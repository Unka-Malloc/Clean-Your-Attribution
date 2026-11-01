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
//! a live gate. A `check` ruleset whose scoped branches can no longer
//! produce the check (named protected branches with no workflow yet,
//! or a leftover `-check` whose every literal branch ref lost the
//! file) is a self-installed deadlock — PUT `disabled` unconditionally,
//! never deleted without `--prune`. Everything else stale — a
//! `-protected` gate the operator stopped naming, a `-check` some
//! branch still produces — keeps enforcing, is warned about and
//! counted, and is deleted only under `--prune`, so a partial rerun
//! can never silently strip gates it did not restate.
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
    Ok(Args {
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
    })
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
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    // curl success ≠ API success: surface HTTP-layer errors the API returns.
    if let Some(msg) = value.get("message").and_then(Value::as_str) {
        if value.get("documentation_url").is_some() || msg.contains("Not Found") {
            bail!("API error {method} {path}: {msg}");
        }
    }
    Ok(value)
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
    anyhow::ensure!(
        out.status.success(),
        "gh api {method} {path}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
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

/// Fetches the workflow file as it exists on `git_ref` (None = the repo's
/// default branch). A missing file is `None`; real API failures propagate.
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

fn workflow_file(owner: &str, repo: &str, git_ref: Option<&str>) -> Result<Option<Value>> {
    let mut path = format!("/repos/{owner}/{repo}/contents/{WORKFLOW_PATH}");
    if let Some(r) = git_ref {
        path = format!("{path}?ref={}", urlencode(r));
    }
    match api("GET", &path, None) {
        Ok(v) if v.get("sha").and_then(Value::as_str).is_some() => Ok(Some(v)),
        Ok(_) => Ok(None),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("Not Found") || msg.contains("404") {
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
fn ensure_workflow_local(
    dir: &str,
    branch: &str,
    workflow_content: &str,
    dry_run: bool,
) -> Result<()> {
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

/// The managed-but-undesired entries in a ruleset listing: what
/// `--prune` deletes and what a plain run warns about. Pure — the
/// destructive decision is testable without touching the API.
fn stale_rulesets<'a>(list: &'a [Value], desired: &[&str]) -> Vec<(&'a str, i64)> {
    list.iter()
        .filter_map(|row| {
            let name = row.get("name").and_then(Value::as_str)?;
            let id = row.get("id").and_then(Value::as_i64)?;
            (MANAGED_RULESETS.contains(&name) && !desired.contains(&name)).then_some((name, id))
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

/// Handles tool-owned rulesets the current declaration does not want.
/// Deletion only happens under `--prune`: removal is an explicit
/// operator declaration, so a partial rerun (a policy refresh naming
/// no refs) can never silently strip gates it did not restate.
/// Without `--prune` each stale ruleset is warned about and counted —
/// the run's footer and exit code say enforcement was left behind.
/// The literal branch refs a `-check` ruleset detail declares in its
/// include list. `None` when the scope is not provable from the payload
/// alone — a symbolic pattern (`~ALL`, `~DEFAULT_BRANCH`), an empty
/// include list, or a missing conditions block — so only an
/// all-literal scope can ever be judged a deadlock.
fn deadlock_branches(detail: &Value) -> Option<Vec<String>> {
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
        branches.push(pattern.as_str()?.strip_prefix("refs/heads/")?.to_string());
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
    /// A `-check` whose scope provably cannot produce the check is a
    /// deadlock, not enforcement — PUT it `disabled` without waiting
    /// for `--prune` (deletion still needs the opt-in).
    Disable,
    /// Everything else keeps enforcing: warned, counted, exit 3.
    Warn,
}

fn stale_action(name: &str, prune: bool, deny_enforcing: bool, deadlocked: bool) -> StaleAction {
    if name == RS_LEGACY_DEFAULT {
        return if prune || deny_enforcing {
            StaleAction::Remove
        } else {
            StaleAction::Warn
        };
    }
    if name == RS_CHECK && !prune && deadlocked {
        return StaleAction::Disable;
    }
    if prune {
        StaleAction::Remove
    } else {
        StaleAction::Warn
    }
}

/// Probes whether a live `-check` ruleset is a proven deadlock: its
/// scope is all-literal and no scoped branch carries the workflow file.
/// Returns the scoped branch names when proven — `None` for anything
/// not provable, including a detail or file read that fails, which the
/// caller treats as "leave to the declared-set paths" rather than a
/// repo failure.
fn check_ruleset_deadlocks(owner: &str, repo: &str, id: i64) -> Option<Vec<String>> {
    let detail = api("GET", &format!("/repos/{owner}/{repo}/rulesets/{id}"), None).ok()?;
    let branches = deadlock_branches(&detail)?;
    for branch in &branches {
        match workflow_file(owner, repo, Some(branch)) {
            Ok(Some(_)) => return None,
            Ok(None) => {}
            Err(_) => return None,
        }
    }
    Some(branches)
}

/// Reconciles a repo's ruleset listing against the declared set, tiered
/// by what the run can prove: a `-default` ruleset is removed only when
/// it is provably redundant (`--prune`, or an `active` deny successor
/// this run installs); a `-check` whose scope provably cannot produce
/// the check is disarmed to `disabled`; every other stale object keeps
/// enforcing and is only deleted under `--prune`. Returns how many
/// undeclared objects are left installed — warned or disarmed — for the
/// footer and exit code.
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
    for (name, id) in stale_rulesets(list, desired) {
        let deadlocked = if name == RS_CHECK && !prune {
            check_ruleset_deadlocks(owner, repo, id)
        } else {
            None
        };
        match stale_action(name, prune, deny_enforcing, deadlocked.is_some()) {
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
                let branches = deadlocked.unwrap_or_default();
                if dry_run {
                    println!(
                        "    ruleset {name}: would disable — no scoped branch \
                         can produce the check ({})",
                        branches.join(", ")
                    );
                } else {
                    let refs: Vec<&str> = branches.iter().map(String::as_str).collect();
                    api(
                        "PUT",
                        &format!("{base}/{id}"),
                        Some(&ruleset_check("disabled", &refs)),
                    )?;
                    println!(
                        "    ruleset {name}: disabled — scoped branches {} \
                         cannot produce the check (deadlock repaired; \
                         rerun with --prune to remove)",
                        branches.join(", ")
                    );
                }
                left += 1;
            }
            StaleAction::Warn => {
                left += 1;
                println!("    ruleset {name}: stale — not in the declared set (rerun with --prune to remove)");
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
    let mut failures: Vec<String> = Vec::new();
    for (dir, branch) in &args.local_refs {
        if let Err(e) = ensure_workflow_local(dir, branch, workflow_content, args.dry_run) {
            failures.push(format!("{dir}:{branch}"));
            println!("  {dir}:{branch}: FAILED: {e:#}");
        }
    }
    let mut pending = Vec::new();
    let mut stale_left_total = 0usize;
    for full in &repos {
        let (owner, repo) = full
            .split_once('/')
            .context(format!("bad repo name {full}"))?;
        let meta = api("GET", &format!("/repos/{owner}/{repo}"), None)?;
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
                    api(
                        "GET",
                        &format!("/repos/{owner}/{repo}/git/ref/heads/{branch}"),
                        None,
                    )
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
        apply_exit, deadlock_branches, desired_rulesets, repo_owned, ruleset_check,
        ruleset_protected, ruleset_tags, stale_action, stale_rulesets, StaleAction,
        MANAGED_RULESETS,
    };
    use serde_json::json;

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
        // -protected is never auto-touched.
        assert_eq!(
            stale_action("clean-your-attribution-protected", false, true, true),
            StaleAction::Warn
        );
        assert_eq!(
            stale_action("clean-your-attribution-protected", true, true, true),
            StaleAction::Remove
        );
    }

    #[test]
    fn deadlock_branches_reads_only_all_literal_scopes() {
        let detail =
            |include: serde_json::Value| json!({"conditions": {"ref_name": {"include": include}}});
        assert_eq!(
            deadlock_branches(&detail(json!(["refs/heads/a", "refs/heads/b"]))),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        // A symbolic pattern, an empty include, a non-string entry or a
        // missing conditions block are all unprovable — never a deadlock.
        assert_eq!(deadlock_branches(&detail(json!(["~DEFAULT_BRANCH"]))), None);
        assert_eq!(
            deadlock_branches(&detail(json!(["refs/heads/a", "~ALL"]))),
            None
        );
        assert_eq!(deadlock_branches(&detail(json!([]))), None);
        assert_eq!(deadlock_branches(&detail(json!([42]))), None);
        assert_eq!(deadlock_branches(&json!({})), None);
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
    fn stale_rulesets_selects_only_managed_and_undesired() {
        let list = vec![
            json!({"name": "clean-your-attribution", "id": 1}),
            json!({"name": "clean-your-attribution-check", "id": 2}),
            json!({"name": "clean-your-attribution-default", "id": 3}),
            json!({"name": "someone-elses", "id": 4}),
            json!({"id": 5}),
        ];
        let desired = desired_rulesets(false);
        let stale = stale_rulesets(&list, &desired);
        assert_eq!(
            stale,
            [
                ("clean-your-attribution-check", 2),
                ("clean-your-attribution-default", 3)
            ]
        );
        // A desired managed name is never stale, even mid-list.
        let desired = desired_rulesets(true);
        assert!(stale_rulesets(&list, &desired)
            .iter()
            .all(|(n, _)| *n == "clean-your-attribution-default"));
    }
}
