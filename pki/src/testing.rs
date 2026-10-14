//! An in-process CA, so other crates' tests exercise the real TLS transport
//! instead of a plaintext hole.

use std::time::Duration;

use crate::{Ca, Identity, KeyAlg, PeerId};

/// One CA for the whole test process, so a fake server and the code under
/// test (dialing as the fallback identity `global()` provides) always agree.
pub fn shared() -> &'static TestPki {
    static SHARED: std::sync::LazyLock<TestPki> = std::sync::LazyLock::new(TestPki::new);
    &SHARED
}

/// A test CA that mints identities for fake servers and clients.
pub struct TestPki {
    ca: Ca,
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPki {
    /// A fresh ML-DSA-65 test CA.
    pub fn new() -> Self {
        Self {
            ca: Ca::new(KeyAlg::MlDsa65).expect("test CA"),
        }
    }

    /// The underlying CA.
    pub fn ca(&self) -> &Ca {
        &self.ca
    }

    /// An identity for `role`/`name`, valid for an hour.
    pub fn identity(&self, role: &str, name: &str) -> Identity {
        let bundle = self
            .ca
            .issue(&PeerId::new(role, name), Duration::from_secs(3600))
            .expect("issue test identity");
        Identity::from_bundle(&bundle).expect("test identity")
    }

    /// Makes an identity from this CA the test process's own for outbound
    /// `nos_pki::connect` calls. Once per test binary — the first wins.
    pub fn install(&self, role: &str, name: &str) {
        crate::install(self.identity(role, name));
    }

    /// Trusts this CA but has no certificate — a not-yet-logged-in client.
    pub fn anonymous(&self) -> Identity {
        Identity::anonymous(self.ca.cert_der()).expect("anonymous identity")
    }
}
