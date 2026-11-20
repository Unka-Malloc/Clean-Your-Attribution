//! CLI-facing behavior: `cya`'s command surface — usage, policy reporting,
//! hook installation, identity-guarded stripping, and history cleaning —
//! exercised the way a user or hook invokes it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRepo {
    dir: PathBuf,
}

impl TempRepo {
    fn new(tag: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("cya-cli-test-{tag}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let repo = Self { dir };
        repo.git(&["init", "-b", "main"]);
        repo.git(&["config", "commit.gpgsign", "false"]);
        repo.git(&["config", "core.hooksPath", ".git/hooks"]);
        repo
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(&self.dir)
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn cya(&self, args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cya"));
        cmd.current_dir(&self.dir).args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn cya");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

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
    assert!(
        stdout.contains("--merge-strategy"),
        "usage mentions --merge-strategy: {stdout}"
    );
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

#[test]
fn strip_file_check_identity_strips_trailers_and_blocks_agent_author() {
    let repo = TempRepo::new("strip-check-id");
    repo.git(&["config", "user.name", "Alice Contributor"]);
    repo.git(&["config", "user.email", "alice@example.com"]);
    let msg_path = repo.path().join("COMMIT_EDITMSG");
    let raw = "feat: add parser\n\nCo-authored-by: Jane Doe <jane@example.com>\nCo-authored-by: Claude <noreply@anthropic.com>\n";
    fs::write(&msg_path, raw).unwrap();

    // Human author passes while agent trailer is stripped and human co-author stays.
    let (code, _out, stderr) = repo.cya(
        &["strip-file", "--check-identity", msg_path.to_str().unwrap()],
        &[
            ("GIT_AUTHOR_NAME", "Alice Contributor"),
            ("GIT_AUTHOR_EMAIL", "alice@example.com"),
            ("GIT_COMMITTER_NAME", "Alice Contributor"),
            ("GIT_COMMITTER_EMAIL", "alice@example.com"),
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let cleaned = fs::read_to_string(&msg_path).unwrap();
    assert!(!cleaned.contains("noreply@anthropic.com"));
    assert!(cleaned.contains("Jane Doe <jane@example.com>"));

    // Denied agent author fails closed with an actionable message.
    let (code, _out, stderr) = repo.cya(
        &["strip-file", "--check-identity", msg_path.to_str().unwrap()],
        &[
            ("GIT_AUTHOR_NAME", "Claude"),
            ("GIT_AUTHOR_EMAIL", "noreply@anthropic.com"),
            ("GIT_COMMITTER_NAME", "Alice Contributor"),
            ("GIT_COMMITTER_EMAIL", "alice@example.com"),
        ],
    );
    assert_eq!(code, 1, "expected denied author exit 1, stderr: {stderr}");
    assert!(stderr.contains("denied agent author"), "stderr: {stderr}");
}

#[test]
fn clean_rewrites_agent_author_to_committer_identity_and_preserves_worktree() {
    let repo = TempRepo::new("clean-committer");
    repo.git(&["config", "user.name", "Bob Maintainer"]);
    repo.git(&["config", "user.email", "bob@example.com"]);

    fs::write(repo.path().join("a.txt"), "base\n").unwrap();
    repo.git(&["add", "a.txt"]);
    repo.git(&["commit", "-m", "chore: initial"]);
    let base_sha = repo.git(&["rev-parse", "HEAD"]).trim().to_string();

    fs::write(repo.path().join("a.txt"), "changed\n").unwrap();
    repo.git(&["add", "a.txt"]);
    let out = Command::new("git")
        .current_dir(repo.path())
        .env("GIT_AUTHOR_NAME", "Claude")
        .env("GIT_AUTHOR_EMAIL", "noreply@anthropic.com")
        .env("GIT_COMMITTER_NAME", "Bob Maintainer")
        .env("GIT_COMMITTER_EMAIL", "bob@example.com")
        .args([
            "commit",
            "-m",
            "feat: work\n\nCo-authored-by: Jane Doe <jane@example.com>\nCo-authored-by: codex <267193182+codex@users.noreply.github.com>",
        ])
        .output()
        .expect("git commit");
    assert!(out.status.success());

    // Leave an unstaged working-tree edit to confirm `cya clean` never clobbers it.
    fs::write(repo.path().join("a.txt"), "unstaged-wip\n").unwrap();

    let (code, stdout, stderr) = repo.cya(&["clean", "--range", &format!("{base_sha}..HEAD")], &[]);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");

    let log = repo.git(&["log", "-1", "--format=%an|%ae|%cn|%ce|%B"]);
    assert!(
        log.starts_with("Bob Maintainer|bob@example.com|Bob Maintainer|bob@example.com|"),
        "log: {log}"
    );
    assert!(log.contains("Jane Doe <jane@example.com>"), "log: {log}");
    assert!(!log.contains("codex"), "log: {log}");
    assert_eq!(
        fs::read_to_string(repo.path().join("a.txt")).unwrap(),
        "unstaged-wip\n"
    );

    let (scan_code, scan_out, scan_err) =
        repo.cya(&["scan", "--range", &format!("{base_sha}..HEAD")], &[]);
    assert_eq!(scan_code, 0, "stdout: {scan_out}\nstderr: {scan_err}");
}

#[test]
fn clean_head_rewrites_only_head_and_refuses_agent_git_config() {
    let repo = TempRepo::new("clean-head");
    repo.git(&["config", "user.name", "Carol Dev"]);
    repo.git(&["config", "user.email", "carol@example.com"]);

    fs::write(repo.path().join("f.txt"), "1\n").unwrap();
    repo.git(&["add", "f.txt"]);
    let out1 = Command::new("git")
        .current_dir(repo.path())
        .env("GIT_AUTHOR_NAME", "Claude")
        .env("GIT_AUTHOR_EMAIL", "noreply@anthropic.com")
        .args(["commit", "-m", "feat: first"])
        .output()
        .unwrap();
    assert!(out1.status.success());
    let first_sha = repo.git(&["rev-parse", "HEAD"]).trim().to_string();

    fs::write(repo.path().join("f.txt"), "2\n").unwrap();
    repo.git(&["add", "f.txt"]);
    let out2 = Command::new("git")
        .current_dir(repo.path())
        .env("GIT_AUTHOR_NAME", "Claude")
        .env("GIT_AUTHOR_EMAIL", "noreply@anthropic.com")
        .args(["commit", "-m", "feat: second"])
        .output()
        .unwrap();
    assert!(out2.status.success());

    // Refuses if configured git user is itself a denied agent identity.
    repo.git(&["config", "user.name", "Claude Code"]);
    repo.git(&["config", "user.email", "noreply@anthropic.com"]);
    let (bad_code, _out, bad_err) = repo.cya(&["clean", "--head"], &[]);
    assert_eq!(bad_code, 2, "expected config refusal, stderr: {bad_err}");
    assert!(
        bad_err.contains("itself a denied agent identity"),
        "stderr: {bad_err}"
    );

    // Restoring Carol's human identity rewrites only HEAD, leaving parent intact.
    repo.git(&["config", "user.name", "Carol Dev"]);
    repo.git(&["config", "user.email", "carol@example.com"]);
    let (ok_code, _out, ok_err) = repo.cya(&["clean", "--head"], &[]);
    assert_eq!(ok_code, 0, "stderr: {ok_err}");
    assert_eq!(repo.git(&["rev-parse", "HEAD~1"]).trim(), first_sha);
    let head_ident = repo.git(&["log", "-1", "--format=%an <%ae>"]);
    assert_eq!(head_ident.trim(), "Carol Dev <carol@example.com>");
}

#[test]
fn hook_installs_commit_msg_with_check_identity_and_blocks_agent_commit() {
    let repo = TempRepo::new("hook-install");
    repo.git(&["config", "user.name", "Dana Dev"]);
    repo.git(&["config", "user.email", "dana@example.com"]);
    let hooks_dir = repo.path().join(".git/hooks");

    let (code, stdout, stderr) = repo.cya(&["hook", "--dir", hooks_dir.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    let commit_msg = fs::read_to_string(hooks_dir.join("commit-msg")).unwrap();
    assert!(
        commit_msg.contains("strip-file --check-identity"),
        "commit-msg hook: {commit_msg}"
    );

    // Committing as an agent author is blocked by the installed hook.
    fs::write(repo.path().join("x.txt"), "hello\n").unwrap();
    repo.git(&["add", "x.txt"]);
    let denied = Command::new("git")
        .current_dir(repo.path())
        .env("GIT_AUTHOR_NAME", "Claude")
        .env("GIT_AUTHOR_EMAIL", "noreply@anthropic.com")
        .args(["commit", "-m", "feat: blocked"])
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "agent-authored commit must be blocked by commit-msg hook"
    );

    // Committing as the human user with an agent trailer succeeds with trailer stripped.
    let allowed = Command::new("git")
        .current_dir(repo.path())
        .args([
            "commit",
            "-m",
            "feat: clean\n\nCo-authored-by: Claude <noreply@anthropic.com>",
        ])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let log = repo.git(&["log", "-1", "--format=%an|%ae|%B"]);
    assert!(log.starts_with("Dana Dev|dana@example.com|"), "log: {log}");
    assert!(!log.contains("noreply@anthropic.com"), "log: {log}");
}
