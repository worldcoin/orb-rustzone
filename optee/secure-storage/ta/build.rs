use std::process::Command;

use optee_utee_build::{Error, RustEdition, TaConfig};

fn main() -> Result<(), Error> {
    let mut config = TaConfig::new_default_with_cargo_env(
        orb_secure_storage_proto::StorageDomain::WifiProfiles.as_uuid(),
    )?;
    config.ta_version = format!("git-{}", &git_rev_parse()[..16]);
    config.trace_level = 3;

    optee_utee_build::build(RustEdition::Edition2024, config)
}

fn git_rev_parse() -> String {
    let stdout = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git should be installed")
        .stdout;
    let cleaned_stdout = std::str::from_utf8(&stdout)
        .expect("git command should be valid utf8")
        .trim();

    cleaned_stdout.to_owned()
}
