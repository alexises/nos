use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, RsaKeySize, SanType,
    PKCS_RSA_SHA256,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

struct Pki {
    ca_pem: String,
    leaf: CertificateDer<'static>,
    key: Vec<u8>,
}

fn pki(rsa: bool) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = if rsa {
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap()
    } else {
        KeyPair::generate().unwrap()
    };
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.subject_alt_names = vec![SanType::IpAddress(LOOPBACK)];
    let leaf = p.signed_by(&key, &issuer).unwrap();
    Pki {
        ca_pem: ca.pem(),
        leaf: leaf.der().clone(),
        key: key.serialize_der(),
    }
}

fn fp(pki: &Pki) -> Trust<'static> {
    Trust::Fingerprint(Sha256::digest(pki.leaf.as_ref()).into())
}

fn acceptor(
    pki: &Pki,
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsAcceptor {
    let cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.leaf.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(cfg))
}

/// A one-shot collector on loopback; the client's handshake result.
async fn dial_as(
    acc: TlsAcceptor,
    trust: Trust<'_>,
    address: IpAddr,
    allow_tls12: bool,
) -> io::Result<Negotiated> {
    let l = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        if let Ok(mut s) = acc.accept(tcp).await {
            let _ = tokio::io::AsyncReadExt::read(&mut s, &mut [0u8; 1]).await;
        }
    });
    let c = Connector::new(&trust, None, address, allow_tls12)?;
    let tcp = TcpStream::connect((LOOPBACK, port)).await?;
    c.connect(tcp).await.map(|(_, n)| n)
}

async fn dial(
    pki: &Pki,
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
    trust: Trust<'_>,
    allow_tls12: bool,
) -> io::Result<Negotiated> {
    dial_as(
        acceptor(pki, provider, versions),
        trust,
        LOOPBACK,
        allow_tls12,
    )
    .await
}

fn base() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

fn pq13() -> CryptoProvider {
    let mut p = base();
    p.kx_groups = vec![kx_group::X25519MLKEM768];
    p
}

fn classical13() -> CryptoProvider {
    let mut p = base();
    p.kx_groups = vec![kx_group::X25519];
    p
}

const T13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const T12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
const BOTH: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

#[tokio::test]
async fn pq_tls13_by_anchor_and_by_fingerprint() {
    let p = pki(false);
    for allow in [false, true] {
        let n = dial(&p, pq13(), T13, Trust::AnchorPem(&p.ca_pem), allow)
            .await
            .unwrap();
        assert_eq!(n.version, "TLSv1_3");
        assert_eq!(n.kx, "X25519MLKEM768");
        assert_eq!(n.suite, "TLS13_AES_256_GCM_SHA384");
        assert!(!n.is_tls12());
        let n = dial(&p, pq13(), T13, fp(&p), allow).await.unwrap();
        assert_eq!(n.kx, "X25519MLKEM768");
    }
}

#[tokio::test]
async fn wrong_ca_wrong_fingerprint_and_wrong_san_are_refused() {
    let p = pki(false);
    let other = pki(false);
    assert!(
        dial(&p, pq13(), T13, Trust::AnchorPem(&other.ca_pem), false)
            .await
            .is_err()
    );
    assert!(dial(&p, pq13(), T13, fp(&other), false).await.is_err());
    // The certificate names 127.0.0.1; the client expects another address.
    let wrong = dial_as(
        acceptor(&p, pq13(), T13),
        Trust::AnchorPem(&p.ca_pem),
        "192.0.2.1".parse().unwrap(),
        false,
    )
    .await;
    assert!(wrong.is_err());
}

#[tokio::test]
async fn default_refuses_tls12_and_classical_tls13() {
    let p = pki(false);
    let t = || Trust::AnchorPem(&p.ca_pem);
    assert!(dial(&p, base(), T12, t(), false).await.is_err());
    assert!(dial(&p, classical13(), T13, t(), false).await.is_err());
}

#[tokio::test]
async fn allow_tls12_connects_over_tls12_rsa_and_ecdsa() {
    for rsa in [true, false] {
        let p = pki(rsa);
        for trust in [Trust::AnchorPem(&p.ca_pem), fp(&p)] {
            let n = dial(&p, base(), T12, trust, true).await.unwrap();
            assert!(n.is_tls12(), "{n:?}");
            assert!(n.suite.contains("ECDHE_"), "{n:?}");
            assert!(n.suite.contains("GCM"), "{n:?}");
        }
    }
}

#[tokio::test]
async fn allow_tls12_never_gives_classical_tls13() {
    let p = pki(false);
    // A TLS 1.3 server with only X25519 asks for it in a HelloRetryRequest.
    assert!(
        dial(&p, classical13(), T13, Trust::AnchorPem(&p.ca_pem), true)
            .await
            .is_err()
    );
    // One that lists X25519 first still ends up on the hybrid: no classical
    // key share was sent.
    let mut both = base();
    both.kx_groups = vec![kx_group::X25519, kx_group::X25519MLKEM768];
    let n = dial(&p, both, BOTH, Trust::AnchorPem(&p.ca_pem), true)
        .await
        .unwrap();
    assert_eq!(
        (n.version.as_str(), n.kx.as_str()),
        ("TLSv1_3", "X25519MLKEM768")
    );
}

#[test]
fn allow_tls12_groups_are_tls12_only() {
    let p = allow_tls12_provider();
    assert_eq!(p.kx_groups[0].name(), kx_group::X25519MLKEM768.name());
    for g in &p.kx_groups[1..] {
        assert!(
            !g.usable_for_version(ProtocolVersion::TLSv1_3),
            "{:?}",
            g.name()
        );
        assert!(g.usable_for_version(ProtocolVersion::TLSv1_2));
    }
    let tls13 = p
        .cipher_suites
        .iter()
        .filter(|s| matches!(s, rustls::SupportedCipherSuite::Tls13(_)))
        .count();
    assert_eq!(tls13, 1);
}

#[test]
fn never_sends_early_data_and_requires_ems() {
    let t = Trust::Fingerprint([0; 32]);
    for allow in [false, true] {
        let cfg = client_config(&t, allow).unwrap();
        assert!(!cfg.enable_early_data);
        assert!(cfg.require_ems);
    }
}

#[test]
fn trust_anchor_parsing() {
    let p = pki(false);
    assert_eq!(parse_trust_anchor(&p.ca_pem).unwrap().len(), 1);
    assert!(parse_trust_anchor("").is_err());
    assert!(
        parse_trust_anchor("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            .is_err()
    );
    assert!(parse_trust_anchor("hello").is_err());
}
