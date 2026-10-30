//! CLI-facing behavior: `cya`'s command surface — usage, policy reporting
//! and exit codes — exercised the way a user or hook invokes it.

use std::process::Command;

fn cya(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cya"))
        .args(args)
        .output()
        .expect("spawn cya");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn bare_invocation_prints_usage_and_exits_zero() {
    let (code, stdout, _stderr) = cya(&[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("cya scan"), "usage output: {stdout}");
}

#[test]
fn unknown_command_exits_two_with_usage() {
    let (code, stdout, _stderr) = cya(&["wat"]);
    assert_eq!(code, 2);
    assert!(stdout.contains("cya scan"), "usage output: {stdout}");
}

#[test]
fn policy_reports_the_compiled_in_policy() {
    // given no --policy-url override, `cya policy` prints the compiled-in
    // policy the enforcement surfaces apply
    let (code, stdout, stderr) = cya(&["policy"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(!stdout.trim().is_empty());
}
