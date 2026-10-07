#![allow(
    clippy::disallowed_types,
    reason = "test code spawns the built binaries (#228)"
)]
//! Builds and runs the `nos-logd` binary itself: its `--help` parses, and
//! having an integration test is what makes `cargo test --workspace` build
//! the binary next to `nos-watchdogd`, where `watchdog/tests/system.rs`
//! runs the whole stack from (#131).

#[test]
fn help_lists_its_flags() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nos-logd"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--"));
}
