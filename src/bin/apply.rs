//! ag-apply — fleet rollout for attribution-gate: install the check
//! workflow, two repo rulesets, and squash-only merge settings on every
//! targeted repository.
//!
//!   ag-apply --orgs LicoLand,Meshrix-Platform,SymPolicy --users Unka-Malloc \
//!     [--enforcement evaluate|active|disabled] [--include-private] \
//!     [--repos o/r,...] [--dry-run]
//!
//! Credentials: GITHUB_TOKEN if set (via curl), otherwise `gitvault api`
//! with --identity personal — the credential never leaves the vault
//! process; this binary only receives API responses.

use anyhow::{bail, Context, Result};
use attribution_gate::load_policy;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::process::Command;

const WORKFLOW_PATH: &str = ".github/workflows/attribution-gate.yml";
const CHECK_CONTEXT: &str = "attribution-gate / attribution scan";
const ACTIONS_INTEGRATION_ID: i64 = 15368;

struct Args {
    orgs: Vec<String>,
    users: Vec<String>,
    repos: Vec<String>,
    enforcement: String,
    include_private: bool,
    dry_run: bool,
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = env::args().skip(1).collect();
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
        bail!("usage: ag-apply --orgs o[,o..] --users u[,u..] [--repos o/r,..] [--enforcement evaluate|active|disabled] [--include-private] [--dry-run]");
    }
    Ok(Args {
        orgs: list("--orgs"),
        users: list("--users"),
        repos: list("--repos"),
        enforcement,
        include_private: argv.iter().any(|a| a == "--include-private"),
        dry_run: argv.iter().any(|a| a == "--dry-run"),
    })
}

// ------------------------------------------------------------------ api --

fn api(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    if env::var("GITHUB_TOKEN").is_ok() {
        api_curl(method, path, body)
    } else {
        api_gitvault(method, path, body)
    }
}

fn api_curl(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let token = env::var("GITHUB_TOKEN").unwrap();
    let mut argv = vec![
        "-sS".into(),
        "-X".into(),
        method.into(),
        "-H".into(),
        format!("Authorization: Bearer {token}"),
        "-H".into(),
        "Accept: application/vnd.github+json".into(),
    ];
    let mut tmp = None;
    if let Some(body) = body {
        let dir = env::temp_dir().join(format!("ag-body-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let file = dir.join("body.json");
        fs::write(&file, body.to_string())?;
        argv.push("--data".into());
        argv.push(format!("@{}", file.display()));
        tmp = Some(file);
    }
    argv.push("-H".into());
    argv.push("X-GitHub-Api-Version: 2022-11-28".into());
    argv.push(format!("https://api.github.com{path}"));
    let out = Command::new("curl")
        .args(&argv)
        .output()
        .context("curl failed")?;
    drop(tmp);
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

fn api_gitvault(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let mut argv = vec!["api".to_string(), path.to_string()];
    argv.extend(["--identity".into(), "personal".into()]);
    if method != "GET" {
        argv.extend(["-X".into(), method.into()]);
    }
    let mut tmp = None;
    if let Some(body) = body {
        let dir = env::temp_dir().join(format!("ag-body-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let file = dir.join("body.json");
        fs::write(&file, body.to_string())?;
        argv.extend(["--input".into(), file.display().to_string()]);
        tmp = Some(file);
    }
    let out = Command::new("gitvault").args(&argv).output();
    drop(tmp);
    let out = out.context("gitvault failed to run")?;
    anyhow::ensure!(
        out.status.success(),
        "gitvault {method} {path}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let text = String::from_utf8(out.stdout)?;
    Ok(if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).context("gitvault returned non-JSON")?
    })
}

// ------------------------------------------------------------- payloads --

fn ruleset_deny_trailers(enforcement: &str, policy: &attribution_gate::Policy) -> Value {
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
        "name": "attribution-gate",
        "target": "branch",
        "enforcement": enforcement,
        "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
        "rules": rules,
        "bypass_actors": [],
    })
}

fn ruleset_default_branch(enforcement: &str) -> Value {
    json!({
        "name": "attribution-gate-default",
        "target": "branch",
        "enforcement": enforcement,
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
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

// ---------------------------------------------------------------- apply --

fn list_repos(args: &Args) -> Result<Vec<String>> {
    let mut named: Vec<String> = args.repos.clone();
    for org in &args.orgs {
        let page = api(
            "GET",
            &format!("/orgs/{org}/repos?per_page=100&type=all"),
            None,
        )?;
        for r in page.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            if let Some(name) = r.get("full_name").and_then(Value::as_str) {
                named.push(name.into());
            }
        }
    }
    for user in &args.users {
        let page = api(
            "GET",
            &format!("/users/{user}/repos?per_page=100&type=owner"),
            None,
        )?;
        for r in page.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            if let Some(name) = r.get("full_name").and_then(Value::as_str) {
                named.push(name.into());
            }
        }
    }
    named.sort();
    named.dedup();
    Ok(named)
}

fn ensure_workflow(owner: &str, repo: &str, workflow_content: &str, dry_run: bool) -> Result<()> {
    let path = format!("/repos/{owner}/{repo}/contents/{WORKFLOW_PATH}");
    let existing = api("GET", &path, None).ok();
    let same = existing
        .as_ref()
        .and_then(|v| v.get("content").and_then(Value::as_str))
        .map(|c| {
            B64.decode(c.replace('\n', ""))
                .map(|b| String::from_utf8_lossy(&b) == workflow_content)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if same {
        println!("    workflow: already installed");
        return Ok(());
    }
    if dry_run {
        println!(
            "    workflow: would {} {WORKFLOW_PATH}",
            if existing.is_some() {
                "update"
            } else {
                "create"
            }
        );
        return Ok(());
    }
    let mut body = json!({
        "message": "chore(attribution): install attribution-gate check workflow",
        "content": B64.encode(workflow_content),
    });
    if let Some(sha) = existing.and_then(|v| v.get("sha").and_then(Value::as_str).map(String::from))
    {
        body["sha"] = json!(sha);
    }
    api("PUT", &path, Some(&body))?;
    println!(
        "    workflow: {}",
        if body.get("sha").is_some() {
            "updated"
        } else {
            "created"
        }
    );
    Ok(())
}

fn ensure_ruleset(owner: &str, repo: &str, desired: &Value, dry_run: bool) -> Result<()> {
    let base = format!("/repos/{owner}/{repo}/rulesets");
    let list = api("GET", &base, None)?;
    let name = desired["name"].as_str().unwrap_or_default();
    let existing = list
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
        })
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

fn main() -> Result<()> {
    let args = parse_args()?;
    let policy = load_policy(None)?;
    let workflow_content = include_str!("../../.github/workflows/sig-check.yml");
    let merge_settings: Value = serde_json::from_str(MERGE_SETTINGS)?;
    let repos = list_repos(&args)?;
    println!(
        "{} repo(s) targeted, enforcement={}{}",
        repos.len(),
        args.enforcement,
        if args.dry_run { " (dry-run)" } else { "" }
    );
    let mut failures = Vec::new();
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
        let run = || -> Result<()> {
            ensure_workflow(owner, repo, workflow_content, args.dry_run)?;
            ensure_ruleset(
                owner,
                repo,
                &ruleset_deny_trailers(&args.enforcement, &policy),
                args.dry_run,
            )?;
            ensure_ruleset(
                owner,
                repo,
                &ruleset_default_branch(&args.enforcement),
                args.dry_run,
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
            Ok(())
        };
        if let Err(e) = run() {
            failures.push(full.clone());
            println!("    FAILED: {e:#}");
        }
    }
    if failures.is_empty() {
        println!("done");
    } else {
        println!(
            "done with {} failure(s): {}",
            failures.len(),
            failures.join(", ")
        );
        std::process::exit(1);
    }
    Ok(())
}
