use std::io;
use std::path::PathBuf;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair, SanType};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::testing::TestPki;
use crate::{generate_csr, Bundle, Ca, Identity, PeerId};

fn sock(name: &str) -> (tempdir::Guard, PathBuf) {
    let g = tempdir::Guard::new();
    let p = g.0.join(name);
    (g, p)
}

/// A dir removed on drop — no `tempfile` dependency for one directory.
mod tempdir {
    use std::path::PathBuf;
    pub struct Guard(pub PathBuf);
    impl Guard {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "nos-pki-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Serves one connection: echoes what it reads, returns who the peer was.
async fn echo_once(l: crate::Listener) -> io::Result<Option<PeerId>> {
    let (mut s, peer) = l.accept().await?.handshake().await?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await?;
    s.write_all(&buf).await?;
    s.flush().await?;
    Ok(peer)
}

async fn ping(mut s: crate::Stream) -> io::Result<()> {
    s.write_all(b"hello").await?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hello");
    Ok(())
}

#[tokio::test]
async fn mutual_auth_and_identity_on_both_ends() {
    let pki = TestPki::new();
    let (_g, path) = sock("a.sock");
    let server = tokio::spawn(echo_once(
        pki.identity("ribd", "rt1").listen(&path).unwrap(),
    ));
    let client = pki.identity("bgpd", "r1");
    let stream = client
        .connect(&path, &PeerId::new("ribd", "rt1"))
        .await
        .unwrap();
    ping(stream).await.unwrap();
    assert_eq!(
        server.await.unwrap().unwrap(),
        Some(PeerId::new("bgpd", "r1"))
    );
}

#[tokio::test]
async fn client_refuses_a_server_that_is_not_who_it_expected() {
    let pki = TestPki::new();
    let (_g, path) = sock("b.sock");
    let _server = tokio::spawn(echo_once(
        pki.identity("ribd", "rt2").listen(&path).unwrap(),
    ));
    let e = pki
        .identity("bgpd", "r1")
        .connect(&path, &PeerId::new("ribd", "rt1"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn a_peer_certified_by_another_ca_is_rejected() {
    let (ours, theirs) = (TestPki::new(), TestPki::new());
    let (_g, path) = sock("c.sock");
    let server = tokio::spawn(echo_once(
        ours.identity("ribd", "rt1").listen(&path).unwrap(),
    ));
    let outcome = async {
        let s = theirs
            .identity("bgpd", "r1")
            .connect(&path, &PeerId::new("ribd", "rt1"))
            .await?;
        ping(s).await
    }
    .await;
    assert!(outcome.is_err());
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn an_expired_certificate_is_rejected() {
    let ca = Ca::new().unwrap();
    let now = OffsetDateTime::now_utc();
    let expired = ca
        .issue_between(
            &PeerId::new("bgpd", "r1"),
            now - time::Duration::hours(2),
            now - time::Duration::hours(1),
        )
        .unwrap();
    let live = ca
        .issue(&PeerId::new("ribd", "rt1"), Duration::from_secs(60))
        .unwrap();
    let (_g, path) = sock("d.sock");
    let server = tokio::spawn(echo_once(
        Identity::from_bundle(&live).unwrap().listen(&path).unwrap(),
    ));
    let outcome = async {
        let s = Identity::from_bundle(&expired)
            .unwrap()
            .connect(&path, &PeerId::new("ribd", "rt1"))
            .await?;
        ping(s).await
    }
    .await;
    assert!(outcome.is_err());
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn anonymous_clients_only_reach_the_optional_auth_socket() {
    let pki = TestPki::new();
    let (_g, strict) = sock("strict.sock");
    let (_g2, open) = sock("open.sock");
    let server = pki.identity("watchdog", "");
    let strict_l = server.listen(&strict).unwrap();
    let open_l = server.listen_optional_client_auth(&open).unwrap();
    let strict_task = tokio::spawn(echo_once(strict_l));
    let open_task = tokio::spawn(echo_once(open_l));

    let anon = pki.anonymous();
    let want = PeerId::new("watchdog", "");
    let refused = async {
        let s = anon.connect(&strict, &want).await?;
        ping(s).await
    }
    .await;
    assert!(refused.is_err());
    assert!(strict_task.await.unwrap().is_err());

    ping(anon.connect(&open, &want).await.unwrap())
        .await
        .unwrap();
    assert_eq!(open_task.await.unwrap().unwrap(), None);
}

#[test]
fn an_anonymous_identity_cannot_serve() {
    let (_g, path) = sock("e.sock");
    assert!(TestPki::new().anonymous().listen(&path).is_err());
}

#[test]
fn csr_signing_takes_the_key_but_never_the_identity() {
    let ca = Ca::new().unwrap();
    // A hostile client asks for someone else's identity in its CSR.
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names
        .push(SanType::URI("nos://configd/".try_into().unwrap()));
    let csr = p.serialize_request(&key).unwrap();

    let cert = ca
        .sign_csr(
            csr.der(),
            &PeerId::new("user", "alice"),
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(
        PeerId::from_cert_der(&cert),
        Some(PeerId::new("user", "alice"))
    );

    // …and the result is a usable identity on the client's own key.
    let (csr, key) = generate_csr().unwrap();
    let cert = ca
        .sign_csr(&csr, &PeerId::new("user", "bob"), Duration::from_secs(60))
        .unwrap();
    let id = Identity::from_bundle(&Bundle {
        ca: ca.cert_der().to_vec(),
        cert,
        key,
    })
    .unwrap();
    assert_eq!(id.peer(), Some(PeerId::new("user", "bob")));
}

#[test]
fn a_garbage_csr_is_an_error_not_a_panic() {
    let ca = Ca::new().unwrap();
    assert!(ca
        .sign_csr(
            b"not a csr",
            &PeerId::new("user", "x"),
            Duration::from_secs(1)
        )
        .is_err());
}

#[tokio::test]
async fn rotation_reaches_new_connections_and_spares_old_ones() {
    let pki = TestPki::new();
    let (_g, path) = sock("f.sock");
    let l = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let client = pki.identity("bgpd", "r1");
    let expect = PeerId::new("ribd", "rt1");

    let (old, srv) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let (mut old, (mut old_srv, peer)) = (old.unwrap(), srv);
    assert_eq!(peer, Some(PeerId::new("bgpd", "r1")));

    client
        .update(
            &pki.ca()
                .issue(&PeerId::new("bgpd", "r2"), Duration::from_secs(60))
                .unwrap(),
        )
        .unwrap();

    let (new, srv) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let (_new, (_new_srv, peer)) = (new.unwrap(), srv);
    assert_eq!(peer, Some(PeerId::new("bgpd", "r2")));

    // The connection opened before the rotation still works.
    old.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    old_srv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[test]
fn update_refuses_a_bundle_from_another_ca() {
    let (a, b) = (TestPki::new(), TestPki::new());
    let id = a.identity("bgpd", "r1");
    let foreign = b
        .ca()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    assert!(id.update(&foreign).is_err());
}

#[test]
fn bundle_frames_round_trip_and_reject_garbage() {
    let ca = Ca::new().unwrap();
    let b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let mut wire = b.encode();
    wire.extend(b.encode());
    let mut r = wire.as_slice();
    assert_eq!(Bundle::read_from(&mut r).unwrap(), Some(b.clone()));
    assert_eq!(Bundle::read_from(&mut r).unwrap(), Some(b));
    assert_eq!(Bundle::read_from(&mut r).unwrap(), None);

    assert!(Bundle::read_from(&mut &u32::MAX.to_le_bytes()[..]).is_err());
    // A frame whose inner lengths overrun it.
    let mut bad = 8u32.to_le_bytes().to_vec();
    bad.extend(1000u32.to_le_bytes());
    bad.extend([0u8; 4]);
    assert!(Bundle::read_from(&mut bad.as_slice()).is_err());
}

#[test]
fn debug_output_never_shows_key_material() {
    let ca = Ca::new().unwrap();
    let b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    assert!(!format!("{b:?}").contains(&format!("{:?}", &b.key[..8])));
}

/// One-shot clients just drop their connection. That must read as a plain EOF
/// on the server, not as an error every server would log.
#[tokio::test]
async fn a_peer_that_hangs_up_without_close_notify_reads_as_clean_eof() {
    let pki = TestPki::new();
    let (_g, path) = sock("g.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let client = pki.identity("bgpd", "r1");

    let expect = PeerId::new("ribd", "rt1");
    let (stream, server) = tokio::join!(client.connect(&path, &expect), async {
        listener.accept().await.unwrap().handshake().await.unwrap()
    });
    let mut stream = stream.unwrap();
    let (mut server_stream, _) = server;
    stream.write_all(b"hi").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream); // no shutdown, no close_notify

    let mut got = Vec::new();
    server_stream
        .read_to_end(&mut got)
        .await
        .expect("a hang-up is EOF, not an error");
    assert_eq!(got, b"hi");
}
