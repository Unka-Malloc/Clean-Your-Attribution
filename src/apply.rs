//! cya apply — rollout for clean-your-attribution: install the check
//! workflow, the repo rulesets, and squash-only merge settings on every
//! targeted repository, remote or local.
//!
//!   cya apply --orgs ORG1,ORG2 --users OWNER \
//!     [--enforcement evaluate|active|disabled] [--include-private] \
//!     [--repos o/r,...] [--install-refs o/r:BRANCH,..] \
//!     [--protect-refs o/r:BRANCH,..] [--local PATH:BRANCH,..] \
//!     [--prune] [--dry-run]
//!
//! Ruleset reconciliation is tiered by what the run can prove. A
//! stale `-default` name duplicates the always-desired deny ruleset —
//! removed under `--prune`, or without it only while this run installs
//! an `active` deny successor, so a report-only rerun can never strip
//! a live gate. A stale gate that can provably never fire — a `check`
//! ruleset whose scoped branches all lost the workflow (a deadlock),
//! or a `-protected` whose scoped branches no longer exist — is PUT
//! `disabled` unconditionally, never deleted without `--prune`.
//! Everything else stale — a `-protected` gate the operator stopped
//! naming, a `-check` some branch still produces — keeps enforcing,
//! is warned about and counted, and is deleted only under `--prune`,
//! so a partial rerun can never silently strip gates it did not
//! restate. A stale `-check`/`-protected` found already `disabled`
//! is reported and counted the same way, but costs no probes and no
//! write.
//!
//! Exit: 0 declared state landed; 1 repo failure(s); 3 stale tool-owned
//! rulesets left (rerun with --prune); 2 usage/pre-flight error.
//!
//! The tool never opens branches or pull requests and never guesses where
//! anything belongs: `--install-refs` names (repo, branch) pairs that get
//! the workflow file as a direct commit; `--protect-refs` names (repo,
//! branch) pairs whose merges require a pull request and — once the file
//! exists on that branch — the scan check; `--local` names a checkout and
//! the branch it must be on, then writes the file into the worktree for
//! the operator to commit and promote. A ref that refuses the write or a
//! checkout on the wrong branch fails the run — promotion through
//! protected branches is the operator's own pipeline, not this tool's
//! behavior.
//!
//! Credentials: `GITHUB_TOKEN` if set — piped to curl's stdin config,
//! never in argv or a file — else ambient `gh` auth via `gh api` (the
//! GitHub CLI or a compatible shim).

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clean_your_attribution::load_policy;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::process::Command;

const WORKFLOW_PATH: &str = ".github/workflows/clean-your-attribution.yml";
const CHECK_CONTEXT: &str = "clean-your-attribution / attribution scan";
const ACTIONS_INTEGRATION_ID: i64 = 15368;

const RS_DENY: &str = "clean-your-attribution";
const RS_TAGS: &str = "clean-your-attribution-tags";
const RS_PROTECTED: &str = "clean-your-attribution-protected";
const RS_CHECK: &str = "clean-your-attribution-check";
/// The superseded pre-0.2.0 `~DEFAULT_BRANCH` ruleset — never desired.
/// Removed under `--prune`, or without it only while this run installs
/// an `active` deny successor (otherwise it is a live gate the run
/// must not strip); see `stale_action`.
const RS_LEGACY_DEFAULT: &str = "clean-your-attribution-default";

struct Args {
    orgs: Vec<String>,
    users: Vec<String>,
    repos: Vec<String>,
    enforcement: String,
    install_refs: Vec<(String, String)>,
    protect_refs: Vec<(String, String)>,
    local_refs: Vec<(String, String)>,
    include_private: bool,
    prune: bool,
    dry_run: bool,
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let list = |name: &str| -> Vec<String> {
        argv.iter()
            .position(|a| a == name)
            .and_then(|i| argv.get(i + 1))
            .map(|v| {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    let enforcement = argv
        .iter()
        .position(|a| a == "--enforcement")
        .and_then(|i| argv.get(i + 1).cloned())
        .unwrap_or_else(|| "evaluate".into());
    anyhow::ensure!(
        matches!(enforcement.as_str(), "evaluate" | "active" | "disabled"),
        "--enforcement must be evaluate|active|disabled"
    );
    if argv.is_empty() || argv.iter().any(|a| a == "--help") {
        bail!("usage: cya apply --orgs o[,o..] --users u[,u..] [--repos o/r,..] [--enforcement evaluate|active|disabled] [--install-refs o/r:BRANCH,..] [--protect-refs o/r:BRANCH,..] [--local PATH:BRANCH,..] [--include-private] [--prune] [--dry-run]");
    }
    let combos = |flag: &str, require_slash: bool| -> Result<Vec<(String, String)>> {
        let mut pairs = Vec::new();
        for entry in list(flag) {
            let (repo, branch) = entry
                .split_once(':')
                .with_context(|| format!("{flag} entry {entry:?} must be TARGET:branch"))?;
            anyhow::ensure!(
                (!require_slash || repo.contains('/')) && !branch.is_empty(),
                "{flag} entry {entry:?} must be TARGET:branch"
            );
            pairs.push((repo.to_string(), branch.to_string()));
        }
        Ok(pairs)
    };
    let args = Args {
        orgs: list("--orgs"),
        users: list("--users"),
        repos: list("--repos"),
        enforcement,
        install_refs: combos("--install-refs", true)?,
        protect_refs: combos("--protect-refs", true)?,
        local_refs: combos("--local", false)?,
        include_private: argv.iter().any(|a| a == "--include-private"),
        prune: argv.iter().any(|a| a == "--prune"),
        dry_run: argv.iter().any(|a| a == "--dry-run"),
    };
    // The protected object must not carry its own protection controls:
    // naming this tool's publishing repository as a rollout target is a
    // usage error — its rulesets, check workflow and merge settings are
    // administered by the operator outside the checkout the tool ships
    // from.
    anyhow::ensure!(
        !args.repos.iter().any(|repo| is_self_repo(repo))
            && !args
                .install_refs
                .iter()
                .chain(args.protect_refs.iter())
                .any(|(repo, _)| is_self_repo(repo)),
        "cya apply must not target {} — its protection surface is \
         administered outside the protected checkout",
        self_repo_slug().unwrap_or_default(),
    );
    Ok(args)
}

/// The repository this build publishes. `CARGO_PKG_REPOSITORY` names the
/// origin, so a downstream build of this source guards its own publishing
/// repo rather than borrowing this one's identity.
fn self_repo_slug() -> Option<String> {
    let rest = env!("CARGO_PKG_REPOSITORY").strip_prefix("https://github.com/")?;
    let slug = rest.trim_end_matches(".git").trim_end_matches('/');
    (!slug.is_empty()).then(|| slug.to_string())
}

/// A repo target naming this tool's own publishing repository, matched
/// case-insensitively the way GitHub resolves slugs.
fn is_self_repo(slug: &str) -> bool {
    self_repo_slug().is_some_and(|own| slug.eq_ignore_ascii_case(&own))
}

/// The server's canonical `full_name` for a spelled target decides
/// identity — whatever normalization the transport or server applied.
fn canonical_self(meta: &Value) -> bool {
    meta.get("full_name")
        .and_then(Value::as_str)
        .is_some_and(is_self_repo)
}

/// GitHub's character set for one `owner/repo` segment: names, `.`, `-`
/// and `_`, never `.`/`..` alone. Shared by spelled-target validation
/// and remote-URL identity resolution.
fn slug_segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Split an `owner/repo` target into the two URL-bound segments. Anything
/// beyond GitHub's own character set — a second `/`, a `.`/`..` segment,
/// a percent escape, a `.git` suffix the server folds — is refused: the
/// spelled name is exactly the target or the run stops, so normalization
/// can never redirect a write past the self-protection guard.
fn repo_slug_parts(slug: &str) -> Result<(&str, &str)> {
    let msg = format!("bad repo name {slug} — targets resolve as spelled or not at all");
    let (owner, repo) = slug.split_once('/').context(msg.clone())?;
    anyhow::ensure!(
        slug_segment_ok(owner)
            && slug_segment_ok(repo)
            && !repo.to_ascii_lowercase().ends_with(".git"),
        "{msg}"
    );
    Ok((owner, repo))
}

/// Parse a git remote URL into its `owner/repo` slug — the https, ssh and
/// scp-like spellings of github.com, with the conventional `.git` suffix
/// stripped. Anything else — another host, a local path, a foldable or
/// extra segment — yields `None`: it cannot establish repository
/// identity, so it satisfies neither the self check nor a declared
/// target match.
fn github_slug(url: &str) -> Option<String> {
    let path = url.strip_prefix("git@github.com:").or_else(|| {
        url.strip_prefix("https://github.com/")
            .or_else(|| url.strip_prefix("http://github.com/"))
            .or_else(|| url.strip_prefix("ssh://git@github.com/"))
    })?;
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    (slug_segment_ok(owner) && slug_segment_ok(repo)).then(|| format!("{owner}/{repo}"))
}

/// The repository slugs a checkout's `origin` names — every configured
/// fetch/push URL parsed as a GitHub `owner/repo`. A checkout with no
/// origin remote, or whose origin is not a clean github.com spelling,
/// returns an empty list: its identity cannot be established, so it
/// cannot pass a self check or match a declared repository target.
fn remote_slugs(dir: &str) -> Result<Vec<String>> {
    let out = Command::new("git")
        .args(["-C", dir, "remote", "get-url", "--all", "origin"])
        .output()
        .with_context(|| format!("{dir}: cannot inspect the checkout"))?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    let stdout = String::from_utf8(out.stdout)?;
    Ok(stdout.lines().filter_map(github_slug).collect())
}

// ------------------------------------------------------------------ api --

fn api(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    if env::var("GITHUB_TOKEN").is_ok() {
        api_curl(method, path, body)
    } else {
        api_gh(method, path, body)
    }
}

/// RAII guard: removes the temp dir on every return path.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn private(tag: &str) -> Result<Self> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = env::temp_dir().join(format!("ag-{tag}-{}-{unique}", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The API answered "this object does not exist" — the only absence
/// signal the safety probes may trust, carried as a typed error so
/// `is_not_found` never has to substring-match prose (a repo named
/// `404-archive` or a 403 message can contain the same digits).
#[derive(Debug)]
struct ApiNotFound {
    context: String,
}

impl std::fmt::Display for ApiNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API error {}: 404 Not Found", self.context)
    }
}

impl std::error::Error for ApiNotFound {}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ApiNotFound>().is_some()
}

/// The verdict an HTTP status carries: only 2xx is data, only 404/410 is
/// a provable absence, and everything else — redirects, 4xx/5xx, a lost
/// `-w` marker — is a transport failure. Pure so the boundary a dead-gate
/// proof depends on is pinned by tests.
enum HttpOutcome {
    Data,
    NotFound,
    Transport,
}

fn http_outcome(status: u16) -> HttpOutcome {
    match status {
        200..=299 => HttpOutcome::Data,
        404 | 410 => HttpOutcome::NotFound,
        _ => HttpOutcome::Transport,
    }
}

/// Splits curl's `-w "\n%{http_code}"` framing into (status, body) —
/// the trailer line is always the last one. An absent or unparseable
/// marker yields status 0, which classifies as a generic failure, never
/// as NotFound.
fn split_http_status(stdout: &str) -> (u16, &str) {
    let (body, code) = stdout.rsplit_once('\n').unwrap_or((stdout, ""));
    (code.trim().parse().unwrap_or(0), body)
}

/// Extracts the status from gh's `gh: <msg> (HTTP <code>)` stderr shape.
/// `None` on any other shape — the caller then degrades to a plain
/// transport error, never a NotFound verdict.
fn gh_http_status(stderr: &str) -> Option<u16> {
    let (_, rest) = stderr.split_once("(HTTP ")?;
    rest.get(..3)?.parse().ok()
}

fn api_curl(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let token = env::var("GITHUB_TOKEN").unwrap();
    // The credential never enters argv and never touches a file: curl
    // --config - reads the Authorization header from the child's stdin,
    // so there is no token-bearing path on any platform.
    use std::io::Write;
    use std::process::Stdio;
    let mut argv = vec![
        "-sS".into(),
        "--config".into(),
        "-".into(),
        "-X".into(),
        method.into(),
        "-H".into(),
        "Accept: application/vnd.github+json".into(),
    ];
    let mut body_dir = None;
    if let Some(body) = body {
        let dir = TempDir::private("body")?;
        let file = dir.path("body.json");
        fs::write(&file, body.to_string())?;
        argv.push("--data".into());
        argv.push(format!("@{}", file.display()));
        body_dir = Some(dir);
    }
    argv.push("-H".into());
    argv.push("X-GitHub-Api-Version: 2022-11-28".into());
    argv.push("-w".into());
    argv.push("\n%{http_code}".into());
    argv.push(format!("https://api.github.com{path}"));
    let mut child = Command::new("curl")
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("curl failed")?;
    child
        .stdin
        .take()
        .context("curl stdin")?
        .write_all(format!("header = \"Authorization: Bearer {token}\"\n").as_bytes())?;
    let out = child.wait_with_output().context("curl failed")?;
    drop(body_dir);
    let text = String::from_utf8(out.stdout)?;
    anyhow::ensure!(out.status.success(), "curl failed: {text}");
    // curl success ≠ API success — classify on the real status line, not
    // on prose. Only 2xx is data: 404/410 is the provable "object is
    // gone" answer, and anything else — redirects included, curl runs
    // without -L — fails closed as a transport error.
    let (status, body_text) = split_http_status(&text);
    match http_outcome(status) {
        HttpOutcome::NotFound => {
            return Err(ApiNotFound {
                context: format!("{method} {path}"),
            }
            .into());
        }
        HttpOutcome::Data => {}
        HttpOutcome::Transport => {
            let msg = serde_json::from_str::<Value>(body_text)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            bail!("API error {method} {path}: HTTP {status} {msg}");
        }
    }
    if body_text.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(body_text).unwrap_or(Value::Null))
}

fn api_gh(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let mut argv = vec!["api".to_string(), path.to_string()];
    if method != "GET" {
        argv.extend(["-X".into(), method.into()]);
    }
    let mut body_dir = None;
    if let Some(body) = body {
        let dir = TempDir::private("body")?;
        let file = dir.path("body.json");
        fs::write(&file, body.to_string())?;
        argv.extend(["--input".into(), file.display().to_string()]);
        body_dir = Some(dir);
    }
    let out = Command::new("gh").args(&argv).output();
    drop(body_dir);
    let out = out.context("gh failed to run")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // gh reports errors as `gh: <msg> (HTTP <code>)` — the "(HTTP nnn)"
        // token is the transport's own status, safe to classify on.
        let status = gh_http_status(&stderr);
        if matches!(status, Some(404 | 410)) {
            return Err(ApiNotFound {
                context: format!("{method} {path}"),
            }
            .into());
        }
        bail!("gh api {method} {path}: {}", stderr.trim());
    }
    let text = String::from_utf8(out.stdout)?;
    Ok(if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).context("gh returned non-JSON")?
    })
}

// ------------------------------------------------------------- payloads --

fn ruleset_deny_trailers(enforcement: &str, policy: &clean_your_attribution::Policy) -> Value {
    let rules: Vec<Value> = policy
        .ruleset_patterns()
        .iter()
        .map(|r| {
            json!({
                "type": r.rule_type,
                "parameters": {
                    "name": r.name,
                    "negate": true,
                    "operator": "regex",
                    "pattern": r.pattern,
                },
            })
        })
        .collect();
    json!({
        "name": RS_DENY,
        "target": "branch",
        "enforcement": enforcement,
        "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
        "rules": rules,
        "bypass_actors": [],
    })
}

/// Tags cannot carry commit-metadata rules (branch-scoped in GitHub's
/// ruleset model) and a tag push would execute whatever workflow definition
/// the tagged commit carries — so the scan workflow never runs on tags and
/// tag writes are instead restricted to repository administrators. Tagging
/// an unscanned commit then requires the same actor who could push to the
/// default branch directly.
///
/// The restriction is fail-closed: `evaluate` stages the other rulesets
/// report-only, but here it would silently leave tag writes open while the
/// workflow skips tag scans — so `evaluate` maps to `active`. An explicit
/// `disabled` is honored as an operator choice.
fn ruleset_tags(enforcement: &str) -> Value {
    let tag_enforcement = if enforcement == "disabled" {
        "disabled"
    } else {
        "active"
    };
    json!({
        "name": RS_TAGS,
        "target": "tag",
        "enforcement": tag_enforcement,
        "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
        "rules": [
            { "type": "creation" },
            { "type": "update" },
            { "type": "deletion" },
        ],
        "bypass_actors": [{
            "actor_id": 5,
            "actor_type": "RepositoryRole",
            "bypass_mode": "always",
        }],
    })
}

/// A ruleset's ref scope is a flat include list — literal branch refs, not
/// the `~DEFAULT_BRANCH` symbol. Protection covers exactly the branches the
/// operator names; nothing is scoped implicitly.
fn literal_refs(branches: &[&str]) -> Vec<Value> {
    branches
        .iter()
        .map(|b| json!(format!("refs/heads/{b}")))
        .collect()
}

/// Merges into a protected branch must come through a pull request. This
/// ruleset needs no workflow file, so it lands on every named branch the
/// moment the operator names it.
fn ruleset_protected(enforcement: &str, branches: &[&str]) -> Value {
    json!({
        "name": RS_PROTECTED,
        "target": "branch",
        "enforcement": enforcement,
        "conditions": { "ref_name": { "include": literal_refs(branches), "exclude": [] } },
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": false,
                    "require_code_owner_review": false,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": false,
                },
            },
        ],
        "bypass_actors": [],
    })
}

/// The scan check may only be required on branches that carry the workflow
/// file: a `pull_request` event runs the base branch's copy, so requiring
/// the check where no file exists deadlocks every merge into that branch —
/// including the promotion that would carry the file in. Branches join this
/// ruleset's include list only once their own copy has landed.
fn ruleset_check(enforcement: &str, branches: &[&str]) -> Value {
    json!({
        "name": RS_CHECK,
        "target": "branch",
        "enforcement": enforcement,
        "conditions": { "ref_name": { "include": literal_refs(branches), "exclude": [] } },
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{
                        "context": CHECK_CONTEXT,
                        "integration_id": ACTIONS_INTEGRATION_ID,
                    }],
                    "strict_required_status_checks_policy": false,
                },
            },
        ],
        "bypass_actors": [],
    })
}

const MERGE_SETTINGS: &str = r#"{
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "allow_squash_merge": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "BLANK"
}"#;

/// Every ruleset name this tool has ever owned, including the superseded
/// pre-0.2.0 `~DEFAULT_BRANCH` ruleset — a name a payload builder no
/// longer writes stays managed, so a rename cannot orphan a live gate.
const MANAGED_RULESETS: [&str; 5] = [RS_DENY, RS_TAGS, RS_PROTECTED, RS_CHECK, RS_LEGACY_DEFAULT];

/// The ruleset set a repo should end with: deny + tags always, and once
/// protected branches are named, the pull_request gate plus the check
/// ruleset — `disabled` is the check's deferred state while no named
/// branch can produce it, so the ruleset itself is always desired and
/// never appears in the stale set.
fn desired_rulesets(protected_named: bool) -> Vec<&'static str> {
    let mut names = vec![RS_DENY, RS_TAGS];
    if protected_named {
        names.push(RS_PROTECTED);
        names.push(RS_CHECK);
    }
    names
}

/// Exit-code mapping, pure so the precedence is testable: real repo
/// failures always dominate (1); a run that left undeclared tool-owned
/// rulesets installed reports 3 (2 is this CLI's usage-error status);
/// 0 means the declared state fully landed.
fn apply_exit(failures: usize, stale_left: usize) -> i32 {
    if failures > 0 {
        1
    } else if stale_left > 0 {
        3
    } else {
        0
    }
}

// ---------------------------------------------------------------- apply --

fn list_paginated(path: &str) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    for page in 1..=100 {
        let items = api("GET", &format!("{path}&page={page}"), None)?;
        let rows = items.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        all.extend_from_slice(rows);
        if rows.len() < 100 {
            return Ok(all);
        }
    }
    anyhow::bail!(
        "pagination exceeded 100 pages for {path} — refusing to claim complete enumeration"
    )
}

fn list_repos(args: &Args) -> Result<Vec<String>> {
    let mut named: Vec<String> = args.repos.clone();
    for (repo, _) in args.install_refs.iter().chain(args.protect_refs.iter()) {
        named.push(repo.clone());
    }
    for org in &args.orgs {
        for r in list_paginated(&format!("/orgs/{org}/repos?per_page=100&type=all"))? {
            if let Some(name) = r.get("full_name").and_then(Value::as_str) {
                named.push(name.into());
            }
        }
    }
    for user in &args.users {
        for r in list_paginated(&format!("/users/{user}/repos?per_page=100&type=owner"))? {
            if let Some(name) = r.get("full_name").and_then(Value::as_str) {
                named.push(name.into());
            }
        }
    }
    named.sort();
    named.dedup();
    Ok(named)
}

/// The API path for a branch's git ref — one place so the existence
/// check and the dead-gate probe can never disagree about escaping.
fn branch_ref_path(owner: &str, repo: &str, branch: &str) -> String {
    format!("/repos/{owner}/{repo}/git/ref/heads/{}", urlencode(branch))
}

/// Minimal percent-encoding for a query value — `/` stays readable
/// (branch names carry it constantly); anything else unusual is
/// escaped so a ref can never break out of the parameter.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Fetches the workflow file as it exists on `git_ref` (None = the repo's
/// default branch). A missing file (a real 404/410, nothing else) is
/// `None`; every other API failure propagates so a transient error can
/// never masquerade as "file absent".
fn workflow_file(owner: &str, repo: &str, git_ref: Option<&str>) -> Result<Option<Value>> {
    let mut path = format!("/repos/{owner}/{repo}/contents/{WORKFLOW_PATH}");
    if let Some(r) = git_ref {
        path = format!("{path}?ref={}", urlencode(r));
    }
    match api("GET", &path, None) {
        Ok(v) if v.get("sha").and_then(Value::as_str).is_some() => Ok(Some(v)),
        Ok(_) => Ok(None),
        Err(e) => {
            if is_not_found(&e) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

fn contents_match(entry: &Value, workflow_content: &str) -> bool {
    entry
        .get("content")
        .and_then(Value::as_str)
        .map(|c| {
            B64.decode(c.replace('\n', ""))
                .map(|b| String::from_utf8_lossy(&b) == workflow_content)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Commits the workflow file onto the explicitly named `target` branch.
/// Nothing else moves: no branch creation, no pull request, no fallback to
/// another ref — a target that refuses the write propagates its error and
/// the repo is reported not fully protected.
fn ensure_workflow_ref(
    owner: &str,
    repo: &str,
    target: &str,
    workflow_content: &str,
    dry_run: bool,
) -> Result<()> {
    let existing = workflow_file(owner, repo, Some(target))?;
    if existing
        .as_ref()
        .map(|v| contents_match(v, workflow_content))
        .unwrap_or(false)
    {
        println!("    workflow@{target}: already installed");
        return Ok(());
    }
    if dry_run {
        println!(
            "    workflow@{target}: would {} {WORKFLOW_PATH}",
            if existing.is_some() {
                "update"
            } else {
                "create"
            }
        );
        return Ok(());
    }
    let mut body = json!({
        "message": "chore(attribution): install clean-your-attribution check workflow",
        "content": B64.encode(workflow_content),
        "branch": target,
    });
    if let Some(sha) = existing.and_then(|v| v.get("sha").and_then(Value::as_str).map(String::from))
    {
        body["sha"] = json!(sha);
    }
    api(
        "PUT",
        &format!("/repos/{owner}/{repo}/contents/{WORKFLOW_PATH}"),
        Some(&body),
    )?;
    println!(
        "    workflow@{target}: {}",
        if body.get("sha").is_some() {
            "updated"
        } else {
            "created"
        }
    );
    Ok(())
}

/// Local target: writes the workflow file into a checkout's worktree. The
/// combo names the branch the checkout must already be on — the tool
/// verifies and refuses on a mismatch rather than switching branches;
/// committing and promoting the file stays with the operator.
///
/// The checkout's repository identity, not its directory name, decides
/// whether the write may land at all: the protected repository's own
/// checkout refuses wherever it lives on disk, and when the run declared
/// `--repos`/`--install-refs`/`--protect-refs` targets the checkout must
/// belong to one of them — a directory that is not a declared target is
/// outside the repository scope the run claimed.
fn ensure_workflow_local(
    dir: &str,
    branch: &str,
    workflow_content: &str,
    declared: &[&str],
    dry_run: bool,
) -> Result<()> {
    let slugs = remote_slugs(dir)?;
    anyhow::ensure!(
        !slugs.iter().any(|slug| is_self_repo(slug)),
        "{dir}: checkout of {} — the protected repository is not a rollout target",
        self_repo_slug().unwrap_or_default(),
    );
    if !declared.is_empty() {
        anyhow::ensure!(
            slugs.iter().any(|slug| declared
                .iter()
                .any(|target| target.eq_ignore_ascii_case(slug))),
            "{dir}: checkout is not one of the declared repository targets"
        );
    }
    let out = Command::new("git")
        .args(["-C", dir, "rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .with_context(|| format!("{dir}: cannot inspect the checkout"))?;
    anyhow::ensure!(out.status.success(), "{dir}: not a git checkout");
    let actual = String::from_utf8(out.stdout)?.trim().to_string();
    anyhow::ensure!(
        actual == branch,
        "{dir}: checkout is on {actual}, not {branch} — switch it yourself"
    );
    let path = std::path::Path::new(dir).join(WORKFLOW_PATH);
    let existing = fs::read_to_string(&path).ok();
    if existing.as_deref() == Some(workflow_content) {
        println!("    workflow@{dir}:{branch}: already installed");
        return Ok(());
    }
    if dry_run {
        println!(
            "    workflow@{dir}:{branch}: would {} {WORKFLOW_PATH}",
            if existing.is_some() {
                "update"
            } else {
                "create"
            }
        );
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, workflow_content)?;
    println!(
        "    workflow@{dir}:{branch}: {} — commit and promote it yourself",
        if existing.is_some() {
            "updated"
        } else {
            "created"
        }
    );
    Ok(())
}

fn ensure_ruleset(
    owner: &str,
    repo: &str,
    list: &[Value],
    desired: &Value,
    dry_run: bool,
) -> Result<()> {
    let base = format!("/repos/{owner}/{repo}/rulesets");
    let name = desired["name"].as_str().unwrap_or_default();
    let existing = list
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|r| r.get("id").and_then(Value::as_i64));
    if dry_run {
        println!(
            "    ruleset {name}: would {} ({})",
            if existing.is_some() {
                "update"
            } else {
                "create"
            },
            desired["enforcement"].as_str().unwrap_or("?")
        );
        return Ok(());
    }
    if let Some(id) = existing {
        api("PUT", &format!("{base}/{id}"), Some(desired))?;
        println!("    ruleset {name}: updated");
    } else {
        api("POST", &base, Some(desired))?;
        println!("    ruleset {name}: created");
    }
    Ok(())
}

/// The managed-but-undesired rows in a ruleset listing: what `--prune`
/// deletes and what a plain run warns about or disarms. Pure — the
/// selection is testable without touching the API. Every row a managed
/// `name` makes admissible is kept for accounting; a row without a
/// usable `id` is reported rather than silently dropped, and can never
/// be turned into a request against a fabricated identifier.
fn stale_rows<'a>(list: &'a [Value], desired: &[&str]) -> Vec<&'a Value> {
    list.iter()
        .filter(|row| {
            let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
            MANAGED_RULESETS.contains(&name) && !desired.contains(&name)
        })
        .collect()
}

/// Rows a repo-scoped run may touch: the listing asks the API for
/// repo-owned objects (`includes_parents=false`), but the field check
/// stays as the contract — an inherited organization ruleset sharing a
/// product name must never be updated or pruned from a repo run. A
/// missing `source_type` is treated as unowned and reported distinctly,
/// never silently dropped.
fn repo_owned(row: &Value) -> bool {
    row.get("source_type").and_then(Value::as_str) == Some("Repository")
}

/// The literal branch refs a branch-scoped ruleset detail declares in
/// its include list. `None` when the scope is not provable from the
/// payload alone — a symbolic pattern (`~ALL`, `~DEFAULT_BRANCH`), an
/// fnmatch glob (`refs/heads/release/**` matches live branches a probe
/// cannot enumerate), an empty include list, or a missing conditions
/// block — so only an all-literal scope can ever be judged dead.
fn literal_branches(detail: &Value) -> Option<Vec<String>> {
    let includes = detail
        .get("conditions")?
        .get("ref_name")?
        .get("include")?
        .as_array()?;
    if includes.is_empty() {
        return None;
    }
    let mut branches = Vec::with_capacity(includes.len());
    for pattern in includes {
        let branch = pattern.as_str()?.strip_prefix("refs/heads/")?;
        if branch.is_empty() || branch.contains(['*', '?', '[', ']']) {
            return None;
        }
        branches.push(branch.to_string());
    }
    Some(branches)
}

/// What a reconcile run may do with one stale tool-owned ruleset — the
/// destructive/disarming decision as a pure function so the tier
/// boundary is executable specification, not folklore.
#[derive(Debug, PartialEq, Eq)]
enum StaleAction {
    /// `--prune` always deletes; the superseded `-default` name may also
    /// be deleted without it, but only when this run installs an
    /// enforcing (`active`) deny successor — otherwise removal would
    /// swap a live gate for a report-only duplicate.
    Remove,
    /// A stale gate that can provably never fire — a `-check` whose
    /// scoped branches lost the workflow everywhere, or a `-protected`
    /// whose scoped branches no longer exist — is disarmed to
    /// `disabled` without waiting for `--prune` (deletion still needs
    /// the opt-in). Disarming a dead gate weakens nothing real.
    Disable,
    /// Everything else keeps enforcing: warned, counted, exit 3.
    Warn,
}

/// The two managed names whose rulesets are scoped to literal branches —
/// the only kinds that can go provably dead. Feeds `probe_needed` and
/// `stale_action`; the proof dispatch in `reconcile_rulesets` must stay
/// in sync — a name admitted here without a proof arm there degrades
/// silently to "never dead".
fn branch_scoped_gate(name: &str) -> bool {
    matches!(name, RS_CHECK | RS_PROTECTED)
}

/// Whether a dead-gate probe is worth its API calls at all: only
/// branch-scoped gates can die, never under `--prune` (they are deleted
/// outright), and never for a gate already `disabled` — reaching a
/// state that is in place would spend requests for nothing.
fn probe_needed(name: &str, prune: bool, already_disabled: bool) -> bool {
    !prune && !already_disabled && branch_scoped_gate(name)
}

fn stale_action(name: &str, prune: bool, deny_enforcing: bool, provably_dead: bool) -> StaleAction {
    if name == RS_LEGACY_DEFAULT {
        return if prune || deny_enforcing {
            StaleAction::Remove
        } else {
            StaleAction::Warn
        };
    }
    if !prune && provably_dead && branch_scoped_gate(name) {
        return StaleAction::Disable;
    }
    if prune {
        StaleAction::Remove
    } else {
        StaleAction::Warn
    }
}

/// What one scoped branch tells a dead-gate proof: Alive defeats the
/// verdict at once, Unknown makes it unprovable — only all-Dead is a
/// proven dead scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchVerdict {
    Alive,
    Dead,
    Unknown,
}

/// Short-circuiting fold over branch verdicts: the first Alive or
/// Unknown stops the proof (the probe iterator is lazy, so no further
/// branch GETs are spent). An empty scope is not provable.
fn all_dead(verdicts: impl Iterator<Item = BranchVerdict>) -> bool {
    let mut saw = false;
    for v in verdicts {
        if v != BranchVerdict::Dead {
            return false;
        }
        saw = true;
    }
    saw
}

/// The shared dead-gate proof: fetch the ruleset detail, require an
/// all-literal scope, and fold every scoped branch's verdict. Returns
/// the scope when the gate provably cannot fire — `None` for anything
/// not provable, including a detail read that fails, which the caller
/// treats as "leave to the declared-set paths" rather than a repo
/// failure.
fn proven_dead<F>(owner: &str, repo: &str, id: i64, probe: F) -> Option<Vec<String>>
where
    F: Fn(&str) -> BranchVerdict,
{
    let detail = api("GET", &format!("/repos/{owner}/{repo}/rulesets/{id}"), None).ok()?;
    let branches = literal_branches(&detail)?;
    all_dead(branches.iter().map(|b| probe(b))).then_some(branches)
}

/// Reconciles a repo's ruleset listing against the declared set, tiered
/// by what the run can prove: a `-default` ruleset is removed only when
/// it is provably redundant (`--prune`, or an `active` deny successor
/// this run installs); a stale gate that can never fire — a `-check`
/// whose scoped branches all lost the workflow, or a `-protected` whose
/// scoped branches no longer exist — is disarmed to `disabled`; every
/// other stale object keeps enforcing and is only deleted under
/// `--prune`. Returns how many undeclared objects are left installed —
/// warned or disarmed — for the footer and exit code.
fn reconcile_rulesets(
    owner: &str,
    repo: &str,
    list: &[Value],
    desired: &[&str],
    dry_run: bool,
    prune: bool,
    deny_enforcing: bool,
) -> Result<usize> {
    let base = format!("/repos/{owner}/{repo}/rulesets");
    let mut left = 0;
    for row in stale_rows(list, desired) {
        let name = row.get("name").and_then(Value::as_str).unwrap_or("?");
        let Some(id) = row.get("id").and_then(Value::as_i64) else {
            // A managed name without a usable id cannot be addressed by
            // the API — report it and count it rather than silently
            // dropping a possibly-still-enforcing gate. `--prune` cannot
            // reach it either; it needs manual removal.
            println!("  ruleset {name}: stale — malformed listing row (no usable id); --prune cannot address it, remove manually");
            left += 1;
            continue;
        };
        // An already-disabled gate needs neither probes nor a PUT: it is
        // still undeclared, so it counts as left — but no requests are
        // spent reaching a state that is already in place.
        let already_disabled = row.get("enforcement").and_then(Value::as_str) == Some("disabled");
        let dead = if !probe_needed(name, prune, already_disabled) {
            None
        } else {
            // One proof arm per name `branch_scoped_gate` admits — keep
            // them in lockstep or a new gate kind silently never disarms.
            match name {
                RS_CHECK => proven_dead(owner, repo, id, |b| {
                    match workflow_file(owner, repo, Some(b)) {
                        Ok(Some(_)) => BranchVerdict::Alive,
                        Ok(None) => BranchVerdict::Dead,
                        Err(_) => BranchVerdict::Unknown,
                    }
                }),
                RS_PROTECTED => proven_dead(owner, repo, id, |b| {
                    match api("GET", &branch_ref_path(owner, repo, b), None) {
                        Ok(_) => BranchVerdict::Alive,
                        Err(e) if is_not_found(&e) => BranchVerdict::Dead,
                        Err(_) => BranchVerdict::Unknown,
                    }
                }),
                _ => None,
            }
        };
        match stale_action(name, prune, deny_enforcing, dead.is_some()) {
            StaleAction::Remove => {
                let why = if name == RS_LEGACY_DEFAULT && !prune {
                    format!("superseded by {RS_DENY}")
                } else {
                    "stale".to_string()
                };
                if dry_run {
                    println!("    ruleset {name}: would remove ({why})");
                } else {
                    api("DELETE", &format!("{base}/{id}"), None)?;
                    println!("    ruleset {name}: removed ({why})");
                }
            }
            StaleAction::Disable => {
                let branches = dead.unwrap_or_default();
                let reason = if name == RS_CHECK {
                    "no scoped branch can produce the check"
                } else {
                    "no scoped branch exists"
                };
                if dry_run {
                    println!(
                        "    ruleset {name}: would disable — {reason} ({})",
                        branches.join(", ")
                    );
                } else {
                    let refs: Vec<&str> = branches.iter().map(String::as_str).collect();
                    let body = if name == RS_CHECK {
                        ruleset_check("disabled", &refs)
                    } else {
                        ruleset_protected("disabled", &refs)
                    };
                    api("PUT", &format!("{base}/{id}"), Some(&body))?;
                    println!(
                        "    ruleset {name}: disabled — {reason} ({}) \
                         (dead gate repaired; rerun with --prune to remove)",
                        branches.join(", ")
                    );
                }
                left += 1;
            }
            StaleAction::Warn => {
                left += 1;
                if already_disabled {
                    println!("    ruleset {name}: stale — already disabled (rerun with --prune to remove)");
                } else {
                    println!("    ruleset {name}: stale — not in the declared set (rerun with --prune to remove)");
                }
            }
        }
    }
    Ok(left)
}

pub fn run(argv: &[String]) -> Result<i32> {
    let args = parse_args(argv)?;
    let policy = load_policy(None)?;
    let workflow_content = include_str!("../.github/workflows/sig-check.yml");
    let merge_settings: Value = serde_json::from_str(MERGE_SETTINGS)?;
    let repos = list_repos(&args)?;
    println!(
        "{} repo(s) targeted, enforcement={}{}",
        repos.len(),
        args.enforcement,
        if args.dry_run { " (dry-run)" } else { "" }
    );
    // A `--local` write must land in a checkout of a repository the run
    // actually declared — `--repos`, `--install-refs` and `--protect-refs`
    // name the repository scope; org/user sweeps enumerate the server side
    // and declare no local target.
    let declared: Vec<&str> = args
        .repos
        .iter()
        .map(String::as_str)
        .chain(
            args.install_refs
                .iter()
                .chain(args.protect_refs.iter())
                .map(|(repo, _)| repo.as_str()),
        )
        .collect();
    let mut failures: Vec<String> = Vec::new();
    for (dir, branch) in &args.local_refs {
        if let Err(e) =
            ensure_workflow_local(dir, branch, workflow_content, &declared, args.dry_run)
        {
            failures.push(format!("{dir}:{branch}"));
            println!("  {dir}:{branch}: FAILED: {e:#}");
        }
    }
    let mut pending = Vec::new();
    let mut stale_left_total = 0usize;
    for full in &repos {
        // An organization or user sweep can enumerate this tool's own
        // repository without ever naming it: the protected object is
        // excluded from its own rollout — reported, never a failure.
        if is_self_repo(full) {
            println!(
                "  {full}: skipped — this tool's own repository is administered \
                 outside the protected checkout"
            );
            continue;
        }
        let (owner, repo) = repo_slug_parts(full)?;
        let meta = api("GET", &format!("/repos/{owner}/{repo}"), None)?;
        // A spelled target can normalize to a different repository than
        // the string guard checked — `unused/../` folded by curl, a
        // `.git` suffix stripped by the server. The response's canonical
        // identity is the authoritative answer: whatever the spelled
        // shape, writes never land on the protected object.
        if canonical_self(&meta) {
            println!(
                "  {full}: skipped — resolves to this tool's own repository \
                 (administered outside the protected checkout)"
            );
            continue;
        }
        if meta["private"].as_bool().unwrap_or(false) && !args.include_private {
            println!("  {full}: skipped (private — server-side enforcement needs a paid plan)");
            continue;
        }
        println!("  {full}:");
        // Returns Ok(true) while a protected branch still waits on the
        // workflow file before its check can activate — pending is not a
        // failure.
        let run = || -> Result<(bool, usize)> {
            // Repo-owned rulesets only: organization-inherited rulesets
            // share neither ownership nor a repo-level DELETE endpoint,
            // and a same-named one must never be updated or pruned by a
            // repo-scoped run. Filtered client-side as well because the
            // listing param is a hint, not a contract.
            let rulesets: Vec<Value> = list_paginated(&format!(
                "/repos/{owner}/{repo}/rulesets?per_page=100&includes_parents=false"
            ))?
            .into_iter()
            .filter(|r| {
                if repo_owned(r) {
                    return true;
                }
                let name = r.get("name").and_then(Value::as_str).unwrap_or("?");
                let why = match r.get("source_type").and_then(Value::as_str) {
                    Some(source) => format!("inherited from {source}"),
                    None => "unknown ownership".to_string(),
                };
                println!("    ruleset {name}: skipped ({why} — not repo-owned)");
                false
            })
            .collect();
            // Tag protection lands before the workflow update. On an upgrade
            // path this preserves any older workflow that still scanned tag
            // pushes; on a first install a failure here simply means nothing
            // is deployed yet — either way the run must report the repo as
            // not fully protected rather than claim a partial success.
            ensure_ruleset(
                owner,
                repo,
                &rulesets,
                &ruleset_tags(&args.enforcement),
                args.dry_run,
            )?;
            // The workflow file is the only object that lives inside a
            // branch, so it only goes where the operator explicitly names
            // it: --install-refs (repo, branch) pairs, each a direct commit.
            // Everything else — promotion into protected branches, pull
            // requests — belongs to the operator's own pipeline, and a
            // refused write fails the repo rather than improvising.
            let repo_refs: Vec<&str> = args
                .install_refs
                .iter()
                .filter(|(r, _)| r == full)
                .map(|(_, b)| b.as_str())
                .collect();
            if repo_refs.is_empty() {
                println!("    workflow: not requested (no --install-refs for this repo)");
            } else {
                for target in &repo_refs {
                    ensure_workflow_ref(owner, repo, target, workflow_content, args.dry_run)?;
                }
            }
            ensure_ruleset(
                owner,
                repo,
                &rulesets,
                &ruleset_deny_trailers(&args.enforcement, &policy),
                args.dry_run,
            )?;
            // Protected branches are named explicitly, same tuple model as
            // install-refs: the pull_request gate lands on every named
            // branch now, while the check ruleset only covers branches that
            // already carry the workflow file — requiring a check nothing
            // produces would deadlock merges into that branch.
            let protect_refs: Vec<&str> = args
                .protect_refs
                .iter()
                .filter(|(r, _)| r == full)
                .map(|(_, b)| b.as_str())
                .collect();
            let mut gated = Vec::new();
            let mut awaiting = Vec::new();
            if protect_refs.is_empty() {
                println!("    protected branches: none named (no --protect-refs for this repo)");
            } else {
                for branch in &protect_refs {
                    api("GET", &branch_ref_path(owner, repo, branch), None)
                        .with_context(|| format!("protected branch {branch} not found"))?;
                    if workflow_file(owner, repo, Some(branch))?.is_some()
                        || (args.dry_run && repo_refs.contains(branch))
                    {
                        gated.push(*branch);
                    } else {
                        awaiting.push(*branch);
                    }
                }
                ensure_ruleset(
                    owner,
                    repo,
                    &rulesets,
                    &ruleset_protected(&args.enforcement, &protect_refs),
                    args.dry_run,
                )?;
                // The check ruleset's desired state is unconditional once
                // protected branches are named: active on the branches
                // that can produce the check, disabled while none can. A
                // live -check scoped at fileless branches would demand a
                // check that cannot run and deadlock the merge meant to
                // carry the file back — repairing that self-inflicted
                // state is not a --prune question.
                let check_state = if gated.is_empty() {
                    ruleset_check("disabled", &protect_refs)
                } else {
                    ruleset_check(&args.enforcement, &gated)
                };
                ensure_ruleset(owner, repo, &rulesets, &check_state, args.dry_run)?;
                if gated.is_empty() {
                    println!(
                        "    ruleset {RS_CHECK}: disabled — no protected \
                         branch carries the workflow yet"
                    );
                }
                for branch in &awaiting {
                    println!("    check@{branch}: deferred until the workflow lands there");
                }
            }
            // Tiered reconcile — see reconcile_rulesets: a stale
            // -default is deleted only when provably redundant, a
            // deadlocked -check is disarmed, and every other stale
            // object keeps enforcing until --prune deletes it.
            let stale_left = reconcile_rulesets(
                owner,
                repo,
                &rulesets,
                &desired_rulesets(!protect_refs.is_empty()),
                args.dry_run,
                args.prune,
                args.enforcement == "active",
            )?;
            if args.dry_run {
                println!("    settings: would enforce squash-only + PR title");
            } else {
                api(
                    "PATCH",
                    &format!("/repos/{owner}/{repo}"),
                    Some(&merge_settings),
                )?;
                println!("    settings: squash-only + PR title");
            }
            Ok((!awaiting.is_empty(), stale_left))
        };
        match run() {
            Err(e) => {
                failures.push(full.clone());
                println!("    FAILED: {e:#}");
                println!(
                    "    repo NOT fully protected — an interrupted rollout can leave it \
                     partly enrolled; rerun cya apply before treating it as covered"
                );
            }
            Ok((is_pending, stale)) => {
                stale_left_total += stale;
                if is_pending {
                    pending.push(full.clone());
                    println!(
                        "    pending: protected branches without the workflow get their check \
                         once the file lands — carry it there through your own path, then rerun"
                    );
                }
            }
        }
    }
    if !pending.is_empty() {
        println!(
            "{} repo(s) awaiting the workflow on protected branches \
             (rerun after it lands): {}",
            pending.len(),
            pending.join(", ")
        );
    }
    if stale_left_total > 0 {
        println!(
            "{stale_left_total} undeclared tool-owned ruleset(s) left installed \
             (some disarmed, none deleted without --prune) — rerun with --prune"
        );
    }
    if !failures.is_empty() {
        println!(
            "done with {} failure(s): {}",
            failures.len(),
            failures.join(", ")
        );
    } else if stale_left_total > 0 {
        println!("done (undeclared rulesets pending removal)");
    } else {
        println!("done");
    }
    Ok(apply_exit(failures.len(), stale_left_total))
}

#[cfg(test)]
mod tests {
    use super::{
        all_dead, apply_exit, canonical_self, desired_rulesets, ensure_workflow_local,
        gh_http_status, github_slug, http_outcome, is_self_repo, literal_branches, parse_args,
        probe_needed, remote_slugs, repo_owned, repo_slug_parts, ruleset_check, ruleset_protected,
        ruleset_tags, self_repo_slug, split_http_status, stale_action, stale_rows, urlencode,
        BranchVerdict, HttpOutcome, StaleAction, TempDir, MANAGED_RULESETS,
    };
    use serde_json::json;
    use std::process::Command;

    /// The protected object must not carry its own protection controls:
    /// an explicit `--repos`, `--install-refs` or `--protect-refs` entry
    /// naming the repository this build publishes is refused as a usage
    /// error, whatever case the slug arrives in — while any other
    /// repository stays admissible.
    #[test]
    fn the_publishing_repo_is_not_a_rollout_target() {
        let own = self_repo_slug().expect("the package names its repository");
        assert!(is_self_repo(&own));
        assert!(
            is_self_repo(&own.to_uppercase()),
            "GitHub resolves slugs case-insensitively"
        );
        assert!(!is_self_repo("other/repo"));
        for argv in [
            vec!["--repos".to_string(), own.clone()],
            vec!["--install-refs".to_string(), format!("{own}:main")],
            vec!["--protect-refs".to_string(), format!("{own}:main")],
            vec![
                "--repos".to_string(),
                format!("other/repo,{}", own.to_lowercase()),
            ],
        ] {
            assert!(
                parse_args(&argv).is_err(),
                "an explicit self-target must refuse: {argv:?}"
            );
        }
        assert!(parse_args(&["--repos".to_string(), "other/repo".to_string()]).is_ok());
    }

    /// A spelled target is exactly the repository it names: segments the
    /// transport or server could fold — `..`, `.`, an extra `/`, percent
    /// escapes, a `.git` suffix — are refused rather than re-spelled, so
    /// normalization cannot redirect a write onto the protected object
    /// the string guard compared.
    #[test]
    fn repo_targets_resolve_as_spelled_or_refuse() {
        for (slug, ok) in [
            ("Unka-Malloc/Clean-Your-Attribution", true),
            ("o/r_1.x-y", true),
            ("Unka-Malloc/unused/../Clean-Your-Attribution", false),
            ("o/./r", false),
            ("o/../r", false),
            ("o/r/s", false),
            ("o/r%2e%2e", false),
            ("o%2f/r", false),
            ("o/r.git", false),
            ("o/r.GIT", false),
            ("o/", false),
            ("/r", false),
            ("o r/r", false),
            ("orr", false),
        ] {
            assert_eq!(repo_slug_parts(slug).is_ok(), ok, "slug {slug:?}");
        }
        let own = self_repo_slug().expect("the package names its repository");
        assert!(
            repo_slug_parts("other/repo").is_ok()
                && repo_slug_parts(&format!("x/../{own}")).is_err(),
            "a folded self-target must refuse before the guard compares"
        );
    }

    /// A remote URL establishes checkout identity only when it is a clean
    /// github.com `owner/repo` spelling — another host, a local path, or a
    /// foldable/extra segment yields no slug, so it can satisfy neither
    /// the self check nor a declared-target match.
    #[test]
    fn remote_urls_resolve_to_clean_slugs_or_none() {
        for (url, slug) in [
            ("https://github.com/o/r", Some("o/r")),
            ("https://github.com/o/r.git", Some("o/r")),
            ("https://github.com/o/r/", Some("o/r")),
            ("git@github.com:o/r.git", Some("o/r")),
            ("ssh://git@github.com/o/r", Some("o/r")),
            ("https://github.com/O/R", Some("O/R")),
            ("https://github.com/o", None),
            ("https://github.com/o/r/s", None),
            ("https://github.com/o/../r", None),
            ("https://github.com/o/r.git/x", None),
            ("https://gitlab.com/o/r", None),
            ("file:///tmp/bare", None),
            ("not-a-url", None),
        ] {
            assert_eq!(github_slug(url).as_deref(), slug, "{url}");
        }
    }

    /// `--local` writes the workflow into a repository the run never named
    /// — unless the checkout's origin proves the target. A checkout of the
    /// protected repository refuses wherever the directory lives, and a
    /// checkout unrelated to the run's declared remote targets is outside
    /// the declared repository scope; both refuse before any write, even
    /// under `--dry-run`.
    #[test]
    fn local_checkout_identity_gates_the_write() {
        let own = self_repo_slug().expect("the package names its repository");
        let checkout = |origin: Option<&str>| {
            let dir = TempDir::private("local-checkout").expect("temp dir");
            let path = dir.0.to_string_lossy().into_owned();
            let init = Command::new("git")
                .args(["init", "-b", "main", &path])
                .output()
                .expect("git init");
            assert!(init.status.success(), "git init failed");
            let commit = Command::new("git")
                .args([
                    "-C",
                    &path,
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "commit",
                    "--allow-empty",
                    "-m",
                    "init",
                ])
                .output()
                .expect("git commit");
            assert!(commit.status.success(), "git commit failed");
            if let Some(origin) = origin {
                let remote = Command::new("git")
                    .args(["-C", &path, "remote", "add", "origin", origin])
                    .output()
                    .expect("git remote add");
                assert!(remote.status.success(), "git remote add failed");
            }
            (dir, path)
        };
        let wf = "content";
        // A checkout of the protected repository refuses — any declared
        // scope, even a dry run.
        let (_self_dir, self_path) = checkout(Some(&format!("https://github.com/{own}.git")));
        assert!(
            ensure_workflow_local(&self_path, "main", wf, &[], true).is_err(),
            "the protected repository's own checkout must refuse"
        );
        // A declared scope binds --local to it: an unrelated checkout refuses.
        let (_dir, path) = checkout(Some("https://github.com/other/repo"));
        assert!(
            ensure_workflow_local(&path, "main", wf, &["declared/repo"], true).is_err(),
            "a checkout outside the declared targets must refuse"
        );
        // The declared target's own checkout proceeds to the dry-run plan.
        assert!(ensure_workflow_local(&path, "main", wf, &["other/repo"], true).is_ok());
        // With no declared targets any non-self checkout may take the write.
        assert!(ensure_workflow_local(&path, "main", wf, &[], true).is_ok());
        // A local-only checkout cannot prove identity: admissible with no
        // declared scope, refused when the run declared one.
        let (_bare_dir, bare_path) = checkout(None);
        assert!(remote_slugs(&bare_path).expect("remote query").is_empty());
        assert!(ensure_workflow_local(&bare_path, "main", wf, &[], true).is_ok());
        assert!(ensure_workflow_local(&bare_path, "main", wf, &["other/repo"], true).is_err());
    }

    /// The server's resolved `full_name` is the identity check that no
    /// spelled shape can pass: whatever normalization produced it, a
    /// target that lands on the publishing repository is skipped before
    /// any mutation.
    #[test]
    fn canonical_identity_decides_self_regardless_of_spelling() {
        let own = self_repo_slug().expect("the package names its repository");
        assert!(canonical_self(&json!({ "full_name": own })));
        assert!(
            canonical_self(&json!({ "full_name": own.to_uppercase() })),
            "GitHub resolves slugs case-insensitively"
        );
        assert!(!canonical_self(&json!({ "full_name": "other/repo" })));
        assert!(!canonical_self(&json!({})));
    }

    #[test]
    fn protection_rulesets_scope_only_named_branches() {
        let branches = ["release", "stable"];
        let prot = ruleset_protected("active", &branches);
        assert_eq!(
            prot["conditions"]["ref_name"]["include"],
            serde_json::json!(["refs/heads/release", "refs/heads/stable"])
        );
        assert_eq!(prot["rules"].as_array().unwrap().len(), 1);
        assert_eq!(prot["rules"][0]["type"], "pull_request");
        let check = ruleset_check("active", &branches[..1]);
        assert_eq!(
            check["conditions"]["ref_name"]["include"],
            serde_json::json!(["refs/heads/release"])
        );
        assert_eq!(check["rules"].as_array().unwrap().len(), 1);
        assert_eq!(check["rules"][0]["type"], "required_status_checks");
        assert_eq!(check["bypass_actors"], serde_json::json!([]));
    }

    #[test]
    fn tag_ruleset_is_fail_closed() {
        for (input, expected) in [
            ("evaluate", "active"),
            ("active", "active"),
            ("disabled", "disabled"),
        ] {
            let rs = ruleset_tags(input);
            assert_eq!(rs["enforcement"], expected, "enforcement {input}");
            assert_eq!(rs["target"], "tag");
        }
        let rs = ruleset_tags("evaluate");
        assert_eq!(rs["rules"].as_array().unwrap().len(), 3);
        let bypass = rs["bypass_actors"].as_array().unwrap();
        assert_eq!(bypass.len(), 1);
        assert_eq!(bypass[0]["actor_type"], "RepositoryRole");
    }

    #[test]
    fn desired_rulesets_drop_stale_enforcement() {
        // No branches named: only the repo-wide pair survives — a stale
        // -protected/-check set or the superseded -default ruleset gets
        // reconciled away rather than left enforcing unnamed scopes.
        assert_eq!(
            desired_rulesets(false),
            ["clean-your-attribution", "clean-your-attribution-tags"]
        );
        // Protected branches named: the check ruleset is desired too —
        // `disabled` is its deferred state while no named branch can
        // produce the check, so it never lands in the stale set.
        assert_eq!(
            desired_rulesets(true),
            [
                "clean-your-attribution",
                "clean-your-attribution-tags",
                "clean-your-attribution-protected",
                "clean-your-attribution-check"
            ]
        );
        // The legacy default-branch name is never desired at all.
        for desired in [desired_rulesets(false), desired_rulesets(true)] {
            assert!(!desired.contains(&"clean-your-attribution-default"));
            for name in &desired {
                assert!(MANAGED_RULESETS.contains(name));
            }
        }
        assert!(MANAGED_RULESETS.contains(&"clean-your-attribution-default"));
    }

    #[test]
    fn apply_exit_precedence() {
        assert_eq!(apply_exit(0, 0), 0);
        // Stale rulesets left enforcing get their own status — 2 is the
        // CLI's usage-error code and must stay unambiguous.
        assert_eq!(apply_exit(0, 1), 3);
        // Failures dominate a stale remainder.
        assert_eq!(apply_exit(2, 4), 1);
        assert_eq!(apply_exit(1, 0), 1);
    }

    #[test]
    fn stale_action_tiers() {
        // -default: removed under --prune always; without it, only while
        // the run installs an enforcing deny successor.
        assert_eq!(
            stale_action("clean-your-attribution-default", true, false, false),
            StaleAction::Remove
        );
        assert_eq!(
            stale_action("clean-your-attribution-default", false, true, false),
            StaleAction::Remove
        );
        assert_eq!(
            stale_action("clean-your-attribution-default", false, false, false),
            StaleAction::Warn
        );
        // -check: --prune deletes; a proven deadlock disarms; anything
        // else keeps enforcing and is warned about.
        assert_eq!(
            stale_action("clean-your-attribution-check", true, false, true),
            StaleAction::Remove
        );
        assert_eq!(
            stale_action("clean-your-attribution-check", false, false, true),
            StaleAction::Disable
        );
        assert_eq!(
            stale_action("clean-your-attribution-check", false, false, false),
            StaleAction::Warn
        );
        // -protected: a provably dead gate (every scoped branch gone)
        // disarms like a deadlocked -check; a live one is never touched.
        assert_eq!(
            stale_action("clean-your-attribution-protected", false, true, true),
            StaleAction::Disable
        );
        assert_eq!(
            stale_action("clean-your-attribution-protected", false, true, false),
            StaleAction::Warn
        );
        assert_eq!(
            stale_action("clean-your-attribution-protected", true, true, true),
            StaleAction::Remove
        );
    }

    #[test]
    fn literal_branches_reads_only_all_literal_scopes() {
        let detail =
            |include: serde_json::Value| json!({"conditions": {"ref_name": {"include": include}}});
        assert_eq!(
            literal_branches(&detail(json!(["refs/heads/a", "refs/heads/b"]))),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        // A symbolic pattern, an empty include, a non-string entry or a
        // missing conditions block are all unprovable — never a deadlock.
        assert_eq!(literal_branches(&detail(json!(["~DEFAULT_BRANCH"]))), None);
        assert_eq!(
            literal_branches(&detail(json!(["refs/heads/a", "~ALL"]))),
            None
        );
        assert_eq!(literal_branches(&detail(json!([]))), None);
        assert_eq!(literal_branches(&detail(json!([42]))), None);
        assert_eq!(literal_branches(&json!({})), None);
        // Glob scopes match live branches a probe cannot enumerate —
        // never a provable dead scope.
        assert_eq!(literal_branches(&detail(json!(["refs/heads/*"]))), None);
        assert_eq!(
            literal_branches(&detail(json!(["refs/heads/release/**"]))),
            None
        );
        assert_eq!(literal_branches(&detail(json!(["refs/heads/a?"]))), None);
        assert_eq!(literal_branches(&detail(json!(["refs/heads/x[y]"]))), None);
        assert_eq!(literal_branches(&detail(json!(["refs/heads/"]))), None);
    }

    #[test]
    fn http_status_parsing() {
        // curl -w framing: status is the trailing line, body untouched.
        assert_eq!(split_http_status("{\"a\":1}\n200"), (200, "{\"a\":1}"));
        assert_eq!(split_http_status("\n204"), (204, ""));
        assert_eq!(split_http_status("{}\n404"), (404, "{}"));
        assert_eq!(split_http_status("{}\n410"), (410, "{}"));
        assert_eq!(split_http_status("{}\n301"), (301, "{}"));
        // Only 2xx is data; only 404/410 is provable absence.
        assert!(matches!(http_outcome(200), HttpOutcome::Data));
        assert!(matches!(http_outcome(204), HttpOutcome::Data));
        assert!(matches!(http_outcome(301), HttpOutcome::Transport));
        assert!(matches!(http_outcome(403), HttpOutcome::Transport));
        assert!(matches!(http_outcome(0), HttpOutcome::Transport));
        assert!(matches!(http_outcome(404), HttpOutcome::NotFound));
        assert!(matches!(http_outcome(410), HttpOutcome::NotFound));
        assert_eq!(split_http_status("{}\n403"), (403, "{}"));
        assert_eq!(split_http_status("{}\n502"), (502, "{}"));
        // Absent or unparseable markers classify as 0 — never NotFound.
        assert_eq!(split_http_status("{\"a\":1}"), (0, "{\"a\":1}"));
        assert_eq!(split_http_status(""), (0, ""));
        // gh stderr: only the "(HTTP nnn)" token counts.
        assert_eq!(
            gh_http_status("gh: Not Found (HTTP 404)\nhttps://api.github.com/x"),
            Some(404)
        );
        assert_eq!(gh_http_status("gh: Forbidden (HTTP 403)"), Some(403));
        assert_eq!(gh_http_status("gh: some other error"), None);
        assert_eq!(gh_http_status(""), None);
    }

    #[test]
    fn probe_only_for_live_branch_scoped_gates() {
        assert!(probe_needed("clean-your-attribution-check", false, false));
        assert!(probe_needed(
            "clean-your-attribution-protected",
            false,
            false
        ));
        assert!(!probe_needed("clean-your-attribution-check", true, false));
        assert!(!probe_needed("clean-your-attribution-check", false, true));
        assert!(!probe_needed(
            "clean-your-attribution-default",
            false,
            false
        ));
        assert!(!probe_needed("clean-your-attribution", false, false));
    }

    #[test]
    fn urlencode_keeps_slashes_and_escapes_everything_else() {
        assert_eq!(urlencode("release/1.0"), "release/1.0");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("a?b"), "a%3Fb");
        assert_eq!(urlencode("a#b"), "a%23b");
        assert_eq!(urlencode("a&b"), "a%26b");
        assert_eq!(urlencode("a%b"), "a%25b");
        assert_eq!(urlencode("a b"), "a%20b");
        // Non-ASCII bytes percent-encode rather than pass through raw.
        assert_eq!(urlencode("brànch"), "br%C3%A0nch");
    }

    #[test]
    fn repo_owned_accepts_repository_rows_only() {
        assert!(repo_owned(
            &json!({"source_type": "Repository", "name": "a"})
        ));
        assert!(!repo_owned(
            &json!({"source_type": "Organization", "name": "a"})
        ));
        // A missing source_type is fail-closed: treated as unowned, and
        // the caller logs it distinctly rather than silently dropping it.
        assert!(!repo_owned(&json!({"name": "a"})));
    }

    #[test]
    fn stale_rows_selects_only_managed_and_undesired() {
        let list = vec![
            json!({"name": "clean-your-attribution", "id": 1}),
            json!({"name": "clean-your-attribution-check", "id": 2}),
            json!({"name": "clean-your-attribution-default", "id": 3}),
            json!({"name": "someone-elses", "id": 4}),
            json!({"id": 5}),
            // A managed name without an id stays in the accounting —
            // the loop reports it rather than silently dropping a
            // possibly-still-enforcing gate.
            json!({"name": "clean-your-attribution-protected"}),
        ];
        let names = |rows: Vec<&serde_json::Value>| -> Vec<String> {
            rows.iter()
                .filter_map(|r| r.get("name").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect()
        };
        let desired = desired_rulesets(false);
        assert_eq!(
            names(stale_rows(&list, &desired)),
            [
                "clean-your-attribution-check",
                "clean-your-attribution-default",
                "clean-your-attribution-protected"
            ]
        );
        // A desired managed name is never stale, even mid-list; a
        // nameless row can never be selected.
        let desired = desired_rulesets(true);
        assert_eq!(
            names(stale_rows(&list, &desired)),
            ["clean-your-attribution-default"]
        );
    }

    #[test]
    fn all_dead_requires_every_verdict_dead() {
        use BranchVerdict::*;
        assert!(all_dead([Dead].into_iter()));
        assert!(all_dead([Dead, Dead, Dead].into_iter()));
        assert!(!all_dead([Dead, Alive, Dead].into_iter()));
        assert!(!all_dead([Dead, Unknown, Dead].into_iter()));
        assert!(!all_dead([Alive].into_iter()));
        assert!(!all_dead(std::iter::empty()));
    }
}
