//! The algorithms `nos-pki` speaks — and nothing else. There is no classical
//! fallback: a peer that cannot do post-quantum key exchange fails the
//! handshake instead of quietly downgrading.
//!
//! - **Key exchange**: hybrid `X25519MLKEM768` only (a break of either half alone
//!   does not expose the session; pure ML-KEM would be `kx_group::MLKEM768`).
//! - **Cipher**: `TLS13_AES_256_GCM_SHA384` only (a 256-bit key keeps its margin
//!   against Grover).
//! - **Certificates**: `Ipc` accepts only ML-DSA-65 signatures. `Rest` accepts
//!   only ECDSA P-256, so a browser or stock client can still hold and present
//!   a REST certificate — its *key exchange* is still post-quantum.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{self, cipher_suite, kx_group};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::SignatureScheme;
use webpki::aws_lc_rs::{ECDSA_P256_SHA256, ML_DSA_65};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Ipc,
    Rest,
    /// `nos-logd` as a client of a syslog collector (RFC 5425/9662, #71):
    /// post-quantum key exchange, TLS 1.3 only, but the collector's certificate
    /// may use any classical signature webpki supports — no deployed collector
    /// holds an ML-DSA one. A deliberate deviation from RFC 9662, which wants
    /// TLS 1.2 with classical suites; `syslog::Connector`'s `allow_tls12` opt-in
    /// is the only way back to those, and is built there, not here.
    Syslog,
}

static IPC_SIGNATURES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ML_DSA_65],
    mapping: &[(SignatureScheme::ML_DSA_65, &[ML_DSA_65])],
};

static REST_SIGNATURES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ECDSA_P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256])],
};

pub(crate) fn provider(policy: Policy) -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.cipher_suites = vec![cipher_suite::TLS13_AES_256_GCM_SHA384];
    p.kx_groups = vec![kx_group::X25519MLKEM768];
    p.signature_verification_algorithms = match policy {
        Policy::Ipc => IPC_SIGNATURES,
        Policy::Rest => REST_SIGNATURES,
        Policy::Syslog => p.signature_verification_algorithms,
    };
    Arc::new(p)
}

/// The public-key algorithm of a certificate, for logs and tests.
pub(crate) fn key_alg_name(cert_der: &[u8]) -> &'static str {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
        return "unparsable";
    };
    match cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string()
        .as_str()
    {
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        "1.2.840.10045.2.1" => "ECDSA",
        _ => "other",
    }
}
