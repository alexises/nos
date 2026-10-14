//! TLS for `nos-logd`'s syslog export (RFC 5425, updated by RFC 9662): a
//! client of a collector `nos` does not control, so no NOS CA is involved —
//! the collector is trusted by a configured CA certificate (RFC 5425 §4.2.1
//! path validation, name checked against the SAN) or by the SHA-256
//! fingerprint of its certificate (§4.2.2). Server authentication only.
//!
//! Default (`Policy::Syslog`): hybrid `X25519MLKEM768`, TLS 1.3, classical
//! collector certificates. That cannot reach a collector that only speaks the
//! TLS 1.2 RFC 9662 requires, so `allow_tls12` adds exactly that: TLS 1.2 with
//! ECDHE + AES-GCM suites and the classical groups — **for TLS 1.2 only**.
//! Every classical group is wrapped in [`Tls12Only`], so rustls can neither
//! offer a classical TLS 1.3 key share nor accept a `HelloRetryRequest` for one:
//! TLS 1.3 stays post-quantum with the opt-in on. This is the one classical
//! path in the crate, and it lives here, never in `policy.rs`, so IPC and REST
//! cannot pick it up. Not implemented: RFC 9662's `TLS_RSA_WITH_AES_128_CBC_SHA`
//! (rustls has neither RSA key transport nor CBC).
//!
//! Resumption and early data (RFC 9662 §6) are off in both modes.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, ActiveKeyExchange, CryptoProvider,
    SupportedKxGroup,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, NamedGroup, ProtocolVersion,
    RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::ca::err;
use crate::policy::{key_alg_name, provider, Policy};

/// The client side of a TLS connection to a syslog collector.
pub type Stream = tokio_rustls::client::TlsStream<TcpStream>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How the collector is authenticated.
pub enum Trust<'a> {
    /// RFC 5425 §4.2.1: PEM CA certificate(s) the collector's chain must reach.
    AnchorPem(&'a str),
    /// RFC 5425 §4.2.2: SHA-256 of the collector's end-entity certificate.
    Fingerprint([u8; 32]),
}

/// The parsed trust anchors of `pem`; an error if it holds no certificate or
/// one that does not parse. Also the commit-time check of the configured PEM.
pub fn parse_trust_anchor(pem: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    if certs.is_empty() {
        return Err(err("no PEM certificate found"));
    }
    let mut roots = RootCertStore::empty();
    for c in &certs {
        roots.add(c.clone()).map_err(err)?;
    }
    Ok(certs)
}

/// What a finished handshake settled on, for the sink's connect log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// `TLSv1_3` or `TLSv1_2`.
    pub version: String,
    /// The key-exchange group, e.g. `X25519MLKEM768`.
    pub kx: String,
    /// The cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub suite: String,
    /// Algorithm of the peer's certificate key (e.g. `ML-DSA-65`).
    pub peer_key: &'static str,
}

impl Negotiated {
    /// A TLS 1.2 session is always classical key exchange.
    pub fn is_tls12(&self) -> bool {
        self.version == format!("{:?}", ProtocolVersion::TLSv1_2)
    }
}

/// Dials a collector over an already-connected TCP stream.
#[derive(Clone)]
pub struct Connector {
    tls: TlsConnector,
    name: ServerName<'static>,
}

impl Connector {
    /// `dns_name` is the name the certificate must carry; `None` matches the
    /// iPAddress SAN against `address` (RFC 5425 §5.2).
    pub fn new(
        trust: &Trust<'_>,
        dns_name: Option<&str>,
        address: IpAddr,
        allow_tls12: bool,
    ) -> io::Result<Self> {
        let name = match dns_name {
            Some(n) => ServerName::DnsName(DnsName::try_from(n.to_string()).map_err(err)?),
            None => ServerName::IpAddress(address.into()),
        };
        Ok(Self {
            tls: TlsConnector::from(Arc::new(client_config(trust, allow_tls12)?)),
            name,
        })
    }

    /// TLS handshake on `tcp`; the stream and what was negotiated.
    pub async fn connect(&self, tcp: TcpStream) -> io::Result<(Stream, Negotiated)> {
        let stream =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.tls.connect(self.name.clone(), tcp))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out")
                })??;
        let n = negotiated(&stream);
        Ok((stream, n))
    }
}

fn negotiated(stream: &Stream) -> Negotiated {
    let (_, conn) = stream.get_ref();
    Negotiated {
        version: conn
            .protocol_version()
            .map_or_else(|| "none".into(), |v| format!("{v:?}")),
        kx: conn
            .negotiated_key_exchange_group()
            .map_or_else(|| "none".into(), |g| format!("{:?}", g.name())),
        suite: conn
            .negotiated_cipher_suite()
            .map_or_else(|| "none".into(), |s| format!("{:?}", s.suite())),
        peer_key: conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map_or("none", |c| key_alg_name(c)),
    }
}

pub(crate) fn client_config(trust: &Trust<'_>, allow_tls12: bool) -> io::Result<ClientConfig> {
    let provider = if allow_tls12 {
        allow_tls12_provider()
    } else {
        provider(Policy::Syslog)
    };
    let verifier: Arc<dyn ServerCertVerifier> = match trust {
        Trust::AnchorPem(pem) => {
            let mut roots = RootCertStore::empty();
            for c in parse_trust_anchor(pem)? {
                roots.add(c).map_err(err)?;
            }
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(err)?
        }
        Trust::Fingerprint(fp) => Arc::new(Fingerprint {
            expected: *fp,
            provider: provider.clone(),
        }),
    };
    let versions: &[&rustls::SupportedProtocolVersion] = if allow_tls12 {
        // TLS 1.3 first: RFC 9662 says to prefer it.
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(err)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    // RFC 7627 against triple-handshake attacks; only matters on TLS 1.2.
    cfg.require_ems = true;
    Ok(cfg)
}

/// A classical group usable for TLS 1.2 only.
#[derive(Debug)]
struct Tls12Only(&'static dyn SupportedKxGroup);

impl SupportedKxGroup for Tls12Only {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        self.0.start()
    }
    fn name(&self) -> NamedGroup {
        self.0.name()
    }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_2
    }
}

static CLASSICAL_TLS12_GROUPS: LazyLock<[&'static dyn SupportedKxGroup; 3]> = LazyLock::new(|| {
    [kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1]
        .map(|g| &*Box::leak(Box::new(Tls12Only(g))) as &'static dyn SupportedKxGroup)
});

/// `Policy::Syslog` plus TLS 1.2: `X25519MLKEM768` stays first and the only
/// TLS 1.3 group; the classical groups and the four ECDHE-GCM suites are
/// appended (no RSA key transport, no CBC, no `ChaCha`).
pub(crate) fn allow_tls12_provider() -> Arc<CryptoProvider> {
    let mut p = (*provider(Policy::Syslog)).clone();
    p.kx_groups.extend(CLASSICAL_TLS12_GROUPS.iter().copied());
    p.cipher_suites.extend([
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ]);
    Arc::new(p)
}

/// RFC 5425 §4.2.2: accepts the one end-entity certificate with this SHA-256.
/// The handshake signature is still verified, so the peer proves it holds the
/// key. No chain, expiry or name check — the fingerprint *is* the identity.
struct Fingerprint {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprint")
    }
}

impl ServerCertVerifier for Fingerprint {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

#[cfg(test)]
mod tests;
