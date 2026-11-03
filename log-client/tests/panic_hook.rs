//! Acceptance test for #419: a panic in a spawned task takes the process down.

use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn child_role() {
    if std::env::var("NOS_PANIC_CHILD").is_err() {
        return;
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    nos_log_client::install_panic_hook();
    tokio::spawn(async { panic!("boom-419") });
    tokio::time::sleep(Duration::from_secs(30)).await;
}

#[test]
#[allow(clippy::disallowed_types, reason = "re-executes the built test binary")]
fn spawned_task_panic_aborts_process() {
    let start = Instant::now();
    // nosemgrep: rust.lang.security.current-exe.current-exe -- test re-execs its own binary
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["child_role", "--exact", "--nocapture"])
        .env("NOS_PANIC_CHILD", "1")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(start.elapsed() < Duration::from_secs(20));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("panic at ") && err.contains("boom-419"),
        "{err}"
    );
}
