//! An op that carries a secret must not reach the log (#507). Its own test
//! binary with one test and a global subscriber: a thread-local subscriber
//! races other tests over tracing's cached callsite interest.

use std::sync::{Arc, Mutex};

use nos_config::{Config, ConfigStore};
use nos_proto::{AdminOp, ConfigOp, TransactionBase};

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn applying_a_secret_op_logs_only_its_kind() {
    let buf = LogBuf::default();
    let writer = buf.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let store = ConfigStore::new(Config::default(), None);
    store
        .open_transaction("t", TransactionBase::Blank)
        .await
        .unwrap();
    store
        .apply_op(
            "t",
            ConfigOp::Admin(AdminOp::SetKey {
                label: "k".into(),
                secret: "needle-secret".into(),
            }),
        )
        .await
        .unwrap();
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("applying op") && log.contains("Admin"),
        "{log}"
    );
    assert!(!log.contains("needle-secret"), "{log}");
}
