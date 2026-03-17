use std::process::Command;

use optee_utee_build::{Error, RustEdition, TaConfig};

fn main() -> Result<(), Error> {
    let mut config = TaConfig::new_default_with_cargo_env(
        orb_camera_hmac_proto::CameraHmacDomain::as_uuid(),
    )?;
    config.ta_version = format!("git-{}", &git_rev_parse()[..16]);
    config.trace_level = 1;
    // 2 MB heap: the HMAC src_data (≈37 KB) and crypto operation buffers are
    // small, but give generous headroom for serde_json allocations.
    config.ta_data_size = 2 * 1024 * 1024;

    optee_utee_build::build(RustEdition::Edition2024, config)
}

fn git_rev_parse() -> String {
    let stdout = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git should be installed")
        .stdout;
    std::str::from_utf8(&stdout)
        .expect("git command should be valid utf8")
        .trim()
        .to_owned()
}
