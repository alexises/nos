//! Bakes the build revision (`NOS_BUILD_REV`, set by the Docker build) into `nos_proto::version`.
fn main() {
    let rev = std::env::var("NOS_BUILD_REV").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=NOS_BUILD_REV={rev}");
    println!("cargo:rerun-if-env-changed=NOS_BUILD_REV");
}
