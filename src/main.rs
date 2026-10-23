//! cya — clean your attribution. Local enforcement surface of
//! attribution-gate: scan, strip, rewrite ranges, or install hooks so
//! denied attribution never forms. The server-side surface is
//! `.github/workflows/sig-check.yml`.

use anyhow::{Context, Result};
use attribution_gate::{Findings, Policy, load_policy, message_findings, strip_denied};
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const HOOK_MARKER: &str = "# attribution-gate";
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

fn git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args[0]))?;
    anyhow::ensure!(out.status.success(), "git {} failed", args.join(" "));
    Ok(String::from_utf8(out.stdout).context("git output not utf-8")?)
}

fn try_git(args: &[&str]) -> Option<String> {
    git(args).ok().map(|s| s.trim().to_string())
}

fn current_exe() -> Result<PathBuf> {
    env::current_exe().context("cannot resolve own binary path")
}

// ------------------------------------------------------------ commands --

fn report(label: &str, findings: &Findings) -> usize {
    for t in &findings.trailers {
        eprintln!("  {label} L{}: {}  [{}]", t.line, t.text, t.agent);
    }
    for p in &findings.patterns {
        eprintln!("  {label} L{}: {}  [{}]", p.line, p.text, p.id);
    }
    findings.total()
}

fn default_range() -> String {
    if let Some(up) = try_git(&["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]) {
        return format!("{up}..HEAD");
    }
    if try_git(&["rev-parse", "--verify", "origin/HEAD"]).is_some() {
        return "origin/HEAD..HEAD".into();
    }
    "HEAD".into()
}

fn commits_in_range(range: &str) -> Result<Vec<(String, String)>> {
    let out = git(&["log", "--format=%H%x00%B%x00", range])?;
    let parts: Vec<&str> = out.split('\0').filter(|p| !p.is_empty()).collect();
    let mut commits = Vec::new();
    for pair in parts.chunks(2) {
        if pair.len() == 2 {
            commits.push((pair[0].trim().to_string(), pair[1].to_string()));
        }
    }
    Ok(commits)
}

fn cmd_scan(argv: &[String], policy: &Policy) -> Result<i32> {
    if has_flag(argv, "--stdin") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let hits = report("stdin", &message_findings(&buf, policy));
        println!("{}", if hits > 0 { format!("stdin: {hits} denied attribution entr{}", if hits > 1 { "ies" } else { "y" }) } else { "stdin: clean".into() });
        return Ok(if hits > 0 { 1 } else { 0 });
    }
    if has_flag(argv, "--pre-push") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let mut hits = 0;
        for line in buf.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let (local_ref, local_sha, remote_sha) = (cols[0], cols[1], cols[3]);
            let range = if remote_sha != ZERO_SHA {
                format!("{remote_sha}..{local_sha}")
            } else {
                let base = try_git(&["merge-base", local_sha, "origin/HEAD"]).unwrap_or_else(|| "HEAD".into());
                format!("{base}..{local_sha}")
            };
            let commits = commits_in_range(&range).unwrap_or_else(|_| {
                vec![(local_sha.into(), git(&["log", "-1", "--format=%B", local_sha]).unwrap_or_default())]
            });
            for (sha, message) in commits {
                hits += report(&format!("{local_ref} {}", &sha[..sha.len().min(10)]), &message_findings(&message, policy));
            }
        }
        println!("{}", if hits > 0 { format!("pre-push: {hits} denied entr{} — run `cya clean`", if hits > 1 { "ies" } else { "y" }) } else { "pre-push: clean".into() });
        return Ok(if hits > 0 { 1 } else { 0 });
    }
    let range = flag_value(argv, "--range").unwrap_or_else(default_range);
    let commits = commits_in_range(&range)?;
    let mut hits = 0;
    for (sha, message) in &commits {
        hits += report(&sha[..sha.len().min(10)], &message_findings(message, policy));
    }
    println!(
        "{}",
        if hits > 0 {
            format!("{range}: {hits} denied attribution entr{} in {} commit(s)", if hits > 1 { "ies" } else { "y" }, commits.len())
        } else {
            format!("{range}: clean ({} commit(s))", commits.len())
        }
    );
    Ok(if hits > 0 { 1 } else { 0 })
}

fn cmd_strip(policy: &Policy) -> Result<i32> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let (text, removed) = strip_denied(&buf, policy);
    std::io::stdout().write_all(text.as_bytes())?;
    if !removed.is_empty() {
        let mut dedup = removed;
        dedup.sort();
        dedup.dedup();
        eprintln!("stripped: {}", dedup.join(", "));
    }
    Ok(0)
}

fn cmd_strip_file(argv: &[String], policy: &Policy) -> Result<i32> {
    let file = flag_value(argv, "--file")
        .or_else(|| argv.first().cloned())
        .context("strip-file needs a message file path")?;
    let (text, removed) = strip_denied(&fs::read_to_string(&file)?, policy);
    if !removed.is_empty() {
        fs::write(&file, text)?;
        let mut dedup = removed;
        dedup.sort();
        dedup.dedup();
        eprintln!("cya: stripped {} from {file}", dedup.join(", "));
    }
    Ok(0)
}

// Replay the range natively: for each commit in topo order, strip the
// message and commit-tree it onto rewritten parents. Unchanged commits
// keep their original SHA. This avoids `git filter-branch` entirely —
// no hooks, no deprecation warning, and ~10 cheap git calls per commit.
fn cmd_clean(argv: &[String], policy: &Policy) -> Result<i32> {
    let range = flag_value(argv, "--range").unwrap_or_else(default_range);
    let revs: Vec<String> = git(&["rev-list", "--reverse", "--topo-order", &range])?
        .lines()
        .map(String::from)
        .collect();
    anyhow::ensure!(!revs.is_empty(), "nothing to clean: {range} is empty");
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut touched = 0usize;
    for rev in &revs {
        let line = git(&["rev-list", "--parents", "-n1", rev])?;
        let mut ids = line.split_whitespace();
        ids.next();
        let parents: Vec<String> = ids.map(String::from).collect();
        let new_parents: Vec<String> = parents
            .iter()
            .map(|p| map.get(p).cloned().unwrap_or_else(|| p.clone()))
            .collect();
        let message = git(&["log", "-1", "--format=%B", rev])?;
        let (new_message, _removed) = strip_denied(&message, policy);
        let unchanged = new_parents == parents && new_message == message;
        let new_sha = if unchanged {
            rev.clone()
        } else {
            touched += 1;
            let tree = try_git(&["rev-parse", &format!("{rev}^{{tree}}")]).context("no tree")?;
            let mut args = vec!["commit-tree".to_string(), tree];
            for p in &new_parents {
                args.push("-p".into());
                args.push(p.clone());
            }
            for (k, v) in [
                ("GIT_AUTHOR_NAME", try_git(&["log", "-1", "--format=%an", rev])),
                ("GIT_AUTHOR_EMAIL", try_git(&["log", "-1", "--format=%ae", rev])),
                ("GIT_AUTHOR_DATE", try_git(&["log", "-1", "--format=%aI", rev])),
            ] {
                if let Some(v) = v {
                    std::env::set_var(k, v);
                }
            }
            let mut child = Command::new("git")
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .context("commit-tree spawn failed")?;
            child
                .stdin
                .as_mut()
                .context("no stdin")?
                .write_all(new_message.as_bytes())?;
            let out = child.wait_with_output()?;
            anyhow::ensure!(out.status.success(), "commit-tree failed for {rev}");
            String::from_utf8(out.stdout)?.trim().to_string()
        };
        map.insert(rev.clone(), new_sha);
    }
    if touched == 0 {
        println!("cya: {range} already clean — nothing rewritten");
        return Ok(0);
    }
    let new_head = map[&revs[revs.len() - 1]].clone();
    git(&["update-ref", "HEAD", &new_head])?;
    git(&["reset", "--hard", "HEAD"])?;
    println!("cya: rewrote {touched} commit(s) in {range} — verify with `cya scan --range <new range>`, then push --force-with-lease");
    Ok(0)
}

fn cmd_hook(argv: &[String]) -> Result<i32> {
    // Repo-scoped install. When a global core.hooksPath is in effect (e.g.
    // GitVault's dispatcher), .git/hooks never fires — the convention on
    // such machines is a repo-local `.githooks/` the dispatcher chains to.
    let dir = flag_value(argv, "--dir").map(PathBuf::from).or_else(|| {
        let top = try_git(&["rev-parse", "--show-toplevel"]).map(PathBuf::from)?;
        let custom = try_git(&["config", "--get", "core.hooksPath"]);
        Some(match custom {
            Some(_) => top.join(".githooks"),
            None => top.join(".git/hooks"),
        })
    }).context("not inside a git work tree")?;
    if dir.ends_with(".githooks") {
        eprintln!("cya: global core.hooksPath detected — installing repo-local .githooks/ for dispatcher chaining");
    }
    fs::create_dir_all(&dir)?;
    let exe = current_exe()?;
    let hooks = [
        ("commit-msg", format!("#!/bin/sh\n{HOOK_MARKER}\n'{}' strip-file \"$1\"\n", exe.display())),
        ("pre-push", format!("#!/bin/sh\n{HOOK_MARKER}\nexec '{}' scan --pre-push\n", exe.display())),
    ];
    let mut code = 0;
    for (name, content) in hooks {
        let path = dir.join(name);
        if path.exists()
            && !fs::read_to_string(&path).unwrap_or_default().contains(HOOK_MARKER)
            && !has_flag(argv, "--force")
        {
            eprintln!("cya: {name} hook exists and is not ours — merge manually or pass --force");
            code = 1;
            continue;
        }
        fs::write(&path, content)?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        println!("cya: installed {name} hook → {}", path.display());
    }
    Ok(code)
}

fn cmd_policy(argv: &[String], policy: &Policy) -> Result<i32> {
    if has_flag(argv, "--check") {
        anyhow::ensure!(!policy.agents.is_empty(), "policy lists no agents");
        for a in &policy.agents {
            anyhow::ensure!(
                !a.names.is_empty() || !a.addresses.is_empty(),
                "agent {:?} has neither names nor addresses",
                a.id
            );
            anyhow::ensure!(!a.verify.is_empty(), "agent {:?} lacks a verify reference", a.id);
        }
        for (name, pattern) in policy.ruleset_patterns() {
            anyhow::ensure!(
                regex::Regex::new(&pattern).is_ok(),
                "ruleset pattern {name:?} does not compile"
            );
        }
        println!(
            "policy ok ({} verified agents, source: {})",
            policy.agents.len(),
            policy.source
        );
        return Ok(0);
    }
    println!("source: {}", policy.source);
    println!("trailerKeys: {}", policy.trailer_keys.join(", "));
    for a in &policy.agents {
        println!("agent [{}] ({})", a.id, a.verify);
        for n in &a.names {
            println!("    name: {n}");
        }
        for x in &a.addresses {
            println!("    addr: {x}");
        }
    }
    for (name, pattern) in policy.ruleset_patterns() {
        println!("ruleset [{name}]: {pattern}");
    }
    Ok(0)
}

// --------------------------------------------------------------- args --

fn has_flag(argv: &[String], name: &str) -> bool {
    argv.iter().any(|a| a == name)
}

fn flag_value(argv: &[String], name: &str) -> Option<String> {
    argv.iter().position(|a| a == name).and_then(|i| argv.get(i + 1).cloned())
}

const USAGE: &str = "cya — clean your attribution

  cya scan [--range A..B | --stdin | --pre-push]   find denied attribution
  cya strip                                      stdin → stdout, trailers removed
  cya strip-file PATH                            rewrite a commit message file
  cya clean [--range A..B]                       rewrite the range, stripping trailers
  cya hook [--dir DIR] [--force]                 install commit-msg + pre-push hooks
  cya policy [--check]                           print / verify effective policy

Policy: --policy-url URL or CYA_POLICY_URL, else the compiled-in policy.
";

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    let command = argv.first().map(String::as_str).unwrap_or("");
    let rest = &argv[1..];
    let code = if command == "hook" {
        cmd_hook(rest)
    } else {
        match load_policy(flag_value(&argv, "--policy-url").as_deref()) {
            Ok(policy) => match command {
                "scan" => cmd_scan(rest, &policy),
                "strip" => cmd_strip(&policy),
                "strip-file" => cmd_strip_file(rest, &policy),
                "clean" => cmd_clean(rest, &policy),
                "policy" => cmd_policy(rest, &policy),
                _ => {
                    print!("{USAGE}");
                    Ok(if command.is_empty() { 0 } else { 2 })
                }
            },
            Err(e) => Err(e),
        }
    };
    match code {
        Ok(c) => std::process::exit(c),
        Err(e) => {
            eprintln!("cya: {e:#}");
            std::process::exit(2);
        }
    }
}
