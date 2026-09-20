//! The certificate authority (lives in `nos-watchdogd`'s memory only) and the
//! `Bundle` it hands out.

use std::fmt::Display;
use std::io::{self, Read};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;

use crate::PeerId;

/// Every leaf carries this DNS SAN so rustls's stock verifiers have a
/// `ServerName` to check; the *real* identity is the URI SAN, checked after
/// the handshake (see `identity.rs`).
pub(crate) const SERVER_NAME: &str = "nos.internal";

/// Backdating absorbs clock skew between the watchdog and a client container.
const SKEW: time::Duration = time::Duration::seconds(60);
const CA_LIFETIME: time::Duration = time::Duration::days(3650);

pub(crate) fn err(e: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    /// A fresh CA with a fresh key. Ephemeral by design: nothing persists it,
    /// so a watchdog restart (which restarts every child anyway) re-keys all.
    pub fn new() -> io::Result<Self> {
        let now = OffsetDateTime::now_utc();
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, "nos ipc ca");
        p.not_before = now - SKEW;
        p.not_after = now + CA_LIFETIME;
        let key = KeyPair::generate().map_err(err)?;
        let cert = p.self_signed(&key).map_err(err)?;
        Ok(Self { cert, key })
    }

    pub fn cert_der(&self) -> &[u8] {
        self.cert.der()
    }

    /// PEM for `ca.crt`, the public trust anchor clients bootstrap from.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// A fresh keypair and a leaf for `peer`, valid for `lifetime`.
    pub fn issue(&self, peer: &PeerId, lifetime: Duration) -> io::Result<Bundle> {
        let now = OffsetDateTime::now_utc();
        self.issue_between(peer, now - SKEW, now + lifetime)
    }

    pub(crate) fn issue_between(
        &self,
        peer: &PeerId,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> io::Result<Bundle> {
        let key = KeyPair::generate().map_err(err)?;
        let cert = leaf_params(peer, not_before, not_after)?
            .signed_by(&key, &self.cert, &self.key)
            .map_err(err)?;
        Ok(Bundle {
            ca: self.cert_der().to_vec(),
            cert: cert.der().to_vec(),
            key: key.serialize_der(),
        })
    }

    /// Signs the public key of a client-made CSR as `peer`. **Only the key is
    /// taken from the CSR** — the subject/SANs it asks for are discarded, so a
    /// client can never claim an identity the CA didn't authenticate. (rcgen
    /// checks the CSR's own signature, i.e. proof of possession of the key.)
    /// Returns the leaf certificate DER.
    pub fn sign_csr(
        &self,
        csr_der: &[u8],
        peer: &PeerId,
        lifetime: Duration,
    ) -> io::Result<Vec<u8>> {
        let now = OffsetDateTime::now_utc();
        let mut csr = CertificateSigningRequestParams::from_der(&csr_der.into()).map_err(err)?;
        csr.params = leaf_params(peer, now - SKEW, now + lifetime)?;
        let cert = csr.signed_by(&self.cert, &self.key).map_err(err)?;
        Ok(cert.der().to_vec())
    }
}

fn leaf_params(
    peer: &PeerId,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> io::Result<CertificateParams> {
    let mut p = CertificateParams::new(vec![SERVER_NAME.to_string()]).map_err(err)?;
    p.subject_alt_names
        .push(SanType::URI(peer.uri().try_into().map_err(err)?));
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name
        .push(DnType::CommonName, peer.to_string());
    p.not_before = not_before;
    p.not_after = not_after;
    Ok(p)
}

/// A `(key, cert)` pair generated on the client, to be certified by the CA
/// (`Ca::sign_csr`). Returns `(csr_der, pkcs8_key_der)`; the key never leaves
/// the caller.
pub fn generate_csr() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let key = KeyPair::generate().map_err(err)?;
    let csr = CertificateParams::new(Vec::<String>::new())
        .map_err(err)?
        .serialize_request(&key)
        .map_err(err)?;
    Ok((csr.der().to_vec(), key.serialize_der()))
}

/// Everything an identity is made of, as DER: the CA's certificate (trust
/// anchor), this peer's leaf, and the leaf's PKCS#8 private key.
#[derive(Clone, PartialEq, Eq)]
pub struct Bundle {
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bundle { .. }") // holds a private key
    }
}

/// A bundle is a few KB; anything near this is a corrupt or hostile stream.
const MAX_FRAME: usize = 1 << 20;

/// Bundles are a few KB; a part that overflows `u32` is a bug, not an input.
fn len_u32(n: usize) -> [u8; 4] {
    u32::try_from(n)
        .expect("identity part fits u32")
        .to_le_bytes()
}

impl Bundle {
    /// One frame: `u32le total_len`, then `ca`, `cert`, `key`, each as
    /// `u32le len` + bytes. The watchdog writes one per child spawn and one
    /// per rotation down the child's stdin.
    pub fn encode(&self) -> Vec<u8> {
        let parts = [&self.ca, &self.cert, &self.key];
        let body: usize = parts.iter().map(|p| 4 + p.len()).sum();
        let mut out = Vec::with_capacity(4 + body);
        out.extend_from_slice(&len_u32(body));
        for p in parts {
            out.extend_from_slice(&len_u32(p.len()));
            out.extend_from_slice(p);
        }
        out
    }

    /// The next frame from `r`; `Ok(None)` on a clean EOF at a frame boundary.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let total = u32::from_le_bytes(len) as usize;
        if total > MAX_FRAME {
            return Err(err("identity frame too large"));
        }
        let mut body = vec![0u8; total];
        r.read_exact(&mut body)?;
        let mut rest = body.as_slice();
        let mut part = || -> io::Result<Vec<u8>> {
            let (n, tail) = rest
                .split_first_chunk::<4>()
                .ok_or_else(|| err("short frame"))?;
            let n = u32::from_le_bytes(*n) as usize;
            if tail.len() < n {
                return Err(err("short frame"));
            }
            let (p, tail) = tail.split_at(n);
            rest = tail;
            Ok(p.to_vec())
        };
        Ok(Some(Self {
            ca: part()?,
            cert: part()?,
            key: part()?,
        }))
    }
}
