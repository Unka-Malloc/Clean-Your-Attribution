//! cya — clean your attribution. Local enforcement surface of
//! clean-your-attribution: scan, strip, rewrite ranges, install hooks so
//! denied attribution never forms, and switch local agents' own
//! attribution options off. The server-side surface is
//! `.github/workflows/sig-check.yml`.

use anyhow::{Context, Result};
use clean_your_attribution::agents;
use clean_your_attribution::{
    identity_agent, load_policy, message_findings, strip_denied, Findings, IdentityHit, Policy,
};
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const HOOK_MARKER: &str = "# clean-your-attribution";
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

fn git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args[0]))?;
    anyhow::ensure!(out.status.success(), "git {} failed", args.join(" "));
    String::from_utf8(out.stdout).context("git output not utf-8")
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
    for i in &findings.identities {
        eprintln!("  {label} {}: {}  [{}]", i.field, i.text, i.agent);
    }
    findings.total()
}

fn default_range() -> String {
    if let Some(up) = try_git(&[
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
    ]) {
        return format!("{up}..HEAD");
    }
    if try_git(&["rev-parse", "--verify", "origin/HEAD"]).is_some() {
        return "origin/HEAD..HEAD".into();
    }
    "HEAD".into()
}

struct Commit {
    sha: String,
    author_name: String,
    author_email: String,
    author_date: String,
    committer_name: String,
    committer_email: String,
    committer_date: String,
    message: String,
}

fn commits_in_range(range: &str) -> Result<Vec<Commit>> {
    let out = git(&[
        "log",
        "--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B%x00",
        range,
    ])?;
    let parts: Vec<&str> = out.split('\0').collect();
    let mut commits = Vec::new();
    for chunk in parts.chunks(8) {
        if chunk.len() == 8 && !chunk[0].trim().is_empty() {
            commits.push(Commit {
                sha: chunk[0].trim().to_string(),
                author_name: chunk[1].to_string(),
                author_email: chunk[2].to_string(),
                author_date: chunk[3].trim().to_string(),
                committer_name: chunk[4].to_string(),
                committer_email: chunk[5].to_string(),
                committer_date: chunk[6].trim().to_string(),
                message: chunk[7].to_string(),
            });
        }
    }
    Ok(commits)
}

/// Findings for one commit: message lines plus author/committer identity.
fn commit_findings(c: &Commit, policy: &Policy) -> Findings {
    let mut f = message_findings(&c.message, policy);
    for (field, name, email) in [
        ("author", c.author_name.as_str(), c.author_email.as_str()),
        (
            "committer",
            c.committer_name.as_str(),
            c.committer_email.as_str(),
        ),
    ] {
        if let Some(agent) = identity_agent(name, email, policy) {
            f.identities.push(IdentityHit {
                field,
                agent,
                text: format!("{name} <{email}>"),
            });
        }
    }
    f
}

fn cmd_scan(argv: &[String], policy: &Policy) -> Result<i32> {
    if has_flag(argv, "--stdin") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let hits = report("stdin", &message_findings(&buf, policy));
        println!(
            "{}",
            if hits > 0 {
                format!(
                    "stdin: {hits} denied attribution entr{}",
                    if hits > 1 { "ies" } else { "y" }
                )
            } else {
                "stdin: clean".into()
            }
        );
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
                let base = try_git(&["merge-base", local_sha, "origin/HEAD"])
                    .unwrap_or_else(|| "HEAD".into());
                format!("{base}..{local_sha}")
            };
            let commits = commits_in_range(&range)
                .or_else(|_| commits_in_range(local_sha))
                .unwrap_or_default();
            for c in &commits {
                hits += report(
                    &format!("{local_ref} {}", &c.sha[..c.sha.len().min(10)]),
                    &commit_findings(c, policy),
                );
            }
        }
        println!(
            "{}",
            if hits > 0 {
                format!(
                    "pre-push: {hits} denied entr{} — run `cya clean`",
                    if hits > 1 { "ies" } else { "y" }
                )
            } else {
                "pre-push: clean".into()
            }
        );
        return Ok(if hits > 0 { 1 } else { 0 });
    }
    let range = flag_value(argv, "--range").unwrap_or_else(default_range);
    let commits = commits_in_range(&range)?;
    let mut hits = 0;
    for c in &commits {
        hits += report(&c.sha[..c.sha.len().min(10)], &commit_findings(c, policy));
    }
    println!(
        "{}",
        if hits > 0 {
            format!(
                "{range}: {hits} denied attribution entr{} in {} commit(s)",
                if hits > 1 { "ies" } else { "y" },
                commits.len()
            )
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
    // Denied author/committer fields are replaced by the repository's own
    // identity — the human operator takes ownership of the rewritten commits.
    let repo_name = try_git(&["config", "user.name"]).unwrap_or_else(|| "Unknown".into());
    let repo_email =
        try_git(&["config", "user.email"]).unwrap_or_else(|| "unknown@localhost".into());
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
        let mut c = commits_in_range(rev)?.remove(0);
        let (new_message, _removed) = strip_denied(&c.message, policy);
        let author_denied = identity_agent(&c.author_name, &c.author_email, policy).is_some();
        let committer_denied =
            identity_agent(&c.committer_name, &c.committer_email, policy).is_some();
        let unchanged = new_parents == parents
            && new_message == c.message
            && !author_denied
            && !committer_denied;
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
            let envs = [
                (
                    "GIT_AUTHOR_NAME",
                    if author_denied {
                        &repo_name
                    } else {
                        &c.author_name
                    },
                ),
                (
                    "GIT_AUTHOR_EMAIL",
                    if author_denied {
                        &repo_email
                    } else {
                        &c.author_email
                    },
                ),
                ("GIT_AUTHOR_DATE", &c.author_date),
                (
                    "GIT_COMMITTER_NAME",
                    if committer_denied {
                        &repo_name
                    } else {
                        &c.committer_name
                    },
                ),
                (
                    "GIT_COMMITTER_EMAIL",
                    if committer_denied {
                        &repo_email
                    } else {
                        &c.committer_email
                    },
                ),
                ("GIT_COMMITTER_DATE", &c.committer_date),
            ];
            let mut child = Command::new("git")
                .args(&args)
                .envs(envs.iter().map(|(k, v)| (k, v.as_str())))
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
            c.message.clear();
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
    let dir = flag_value(argv, "--dir")
        .map(PathBuf::from)
        .or_else(|| {
            let top = try_git(&["rev-parse", "--show-toplevel"]).map(PathBuf::from)?;
            let custom = try_git(&["config", "--get", "core.hooksPath"]);
            Some(match custom {
                Some(_) => top.join(".githooks"),
                None => top.join(".git/hooks"),
            })
        })
        .context("not inside a git work tree")?;
    if dir.ends_with(".githooks") {
        eprintln!("cya: global core.hooksPath detected — installing repo-local .githooks/ for dispatcher chaining");
        // .githooks/ sits inside the worktree — keep it out of commits so
        // machine-local hook paths never leak into history.
        if let Some(git_dir) = try_git(&["rev-parse", "--git-dir"]) {
            let exclude = PathBuf::from(git_dir).join("info/exclude");
            let current = fs::read_to_string(&exclude).unwrap_or_default();
            if !current.lines().any(|l| l.trim() == ".githooks/") {
                if let Some(parent) = exclude.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut line = String::from(".githooks/\n");
                if !current.is_empty() && !current.ends_with('\n') {
                    line = format!("\n{line}");
                }
                fs::write(&exclude, format!("{current}{line}"))?;
                eprintln!("cya: added .githooks/ to .git/info/exclude");
            }
        }
    }
    fs::create_dir_all(&dir)?;
    let exe = current_exe()?;
    let hooks = [
        (
            "commit-msg",
            format!(
                "#!/bin/sh\n{HOOK_MARKER}\n'{}' strip-file \"$1\"\n",
                exe.display()
            ),
        ),
        (
            "pre-push",
            format!(
                "#!/bin/sh\n{HOOK_MARKER}\nexec '{}' scan --pre-push\n",
                exe.display()
            ),
        ),
    ];
    let mut code = 0;
    for (name, content) in hooks {
        let path = dir.join(name);
        if path.exists()
            && !fs::read_to_string(&path)
                .unwrap_or_default()
                .contains(HOOK_MARKER)
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
            anyhow::ensure!(
                !a.verify.is_empty(),
                "agent {:?} lacks a verify reference",
                a.id
            );
        }
        for r in policy.ruleset_patterns() {
            anyhow::ensure!(
                regex::Regex::new(&r.pattern).is_ok(),
                "ruleset rule {:?} does not compile",
                r.name
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
    println!("shape names: {}", policy.shape_names.join(", "));
    println!(
        "shape addressLocals: {}",
        policy.shape_addr_locals.join(", ")
    );
    for a in &policy.agents {
        println!("agent [{}] ({})", a.id, a.verify);
        for n in &a.names {
            println!("    name: {n}");
        }
        for x in &a.addresses {
            println!("    addr: {x}");
        }
    }
    for r in policy.ruleset_patterns() {
        println!("ruleset [{}:{}]: {}", r.rule_type, r.name, r.pattern);
    }
    Ok(0)
}

// ------------------------------------------------------------ agents --

fn tilde(path: &std::path::Path) -> String {
    match agents::home_dir() {
        Ok(h) if path.starts_with(&h) => format!("~/{}", path.strip_prefix(&h).unwrap().display()),
        _ => path.display().to_string(),
    }
}

fn print_probe(knob_label: &str, p: &agents::Probe, home: &std::path::Path) {
    let file = tilde(&home.join(p.rel));
    let state = match &p.state {
        agents::State::Off => "off".into(),
        agents::State::On(v) => format!("on ({knob_label} = {v})"),
        agents::State::Absent if !p.primary => "absent — inherits".into(),
        agents::State::Absent => "unset — agent default applies".into(),
        agents::State::NoFile if !p.primary => "absent".into(),
        agents::State::NoFile => "missing — would create".into(),
        agents::State::Unparseable => "UNREADABLE — skipped".into(),
    };
    if matches!(p.state, agents::State::NoFile) && !p.primary {
        return; // precedence clones that do not exist are not noise
    }
    println!("    {file}  {knob_label}: {state}");
}

fn cmd_agents(argv: &[String]) -> Result<i32> {
    let home = agents::home_dir()?;
    let off = argv.iter().any(|a| a == "off");
    let id = argv
        .iter()
        .find(|a| a.as_str() != "agents" && a.as_str() != "off" && !a.starts_with('-'));
    let target: Vec<&'static agents::Agent> = match (off, id) {
        (_, Some(id)) => match agents::find(id) {
            Some(a) => vec![a],
            None => {
                let known: Vec<_> = agents::AGENTS.iter().map(|a| a.id).collect();
                anyhow::bail!("unknown agent {id:?} — known: {}", known.join(", "));
            }
        },
        _ => agents::AGENTS.iter().collect(),
    };
    let mut code = 0;
    for agent in target {
        if !off {
            let r = agents::scan(&home, agent);
            if !r.installed {
                if id.is_some() {
                    println!("{}  {}  — not installed", agent.id, agent.display);
                }
                continue;
            }
            if agent.knobs.is_empty() {
                println!(
                    "{}  {}  — no local attribution switch (server-side bots are denied by the policy surfaces)",
                    agent.id, agent.display
                );
                continue;
            }
            let state = if r.is_off() {
                "off"
            } else {
                code = 1;
                "ON"
            };
            println!("{}  {}  {state}", agent.id, agent.display);
            for (label, p) in &r.probes {
                print_probe(label, p, &home);
            }
            continue;
        }
        if agent.knobs.is_empty() {
            if !agents::scan(&home, agent).installed {
                continue;
            }
            println!(
                "{}  {}  — no local switch, nothing to write",
                agent.id, agent.display
            );
            continue;
        }
        let results = agents::apply(&home, agent)?;
        let mut changed = 0usize;
        let mut unreadable = Vec::new();
        for (label, file, applied) in &results {
            match applied {
                agents::Applied::Written(true) => {
                    changed += 1;
                    println!("    {}  {label} → off", tilde(file));
                }
                agents::Applied::Written(false) | agents::Applied::Absent => {}
                agents::Applied::Unparseable => {
                    unreadable.push(format!("{label} in {}", tilde(file)))
                }
            }
        }
        for s in &unreadable {
            eprintln!("    skipped {s}");
        }
        if !unreadable.is_empty() {
            code = 1;
        }
        println!(
            "{}  {}  — {} change(s){}",
            agent.id,
            agent.display,
            changed,
            if unreadable.is_empty() {
                ""
            } else {
                ", see skips"
            }
        );
    }
    if off {
        println!(
            "{}",
            if code == 0 {
                "cya: agent attribution off everywhere it has a switch"
            } else {
                "cya: done with skips — unreadable files need a manual pass"
            }
        );
    }
    Ok(code)
}

// --------------------------------------------------------------- args --

fn has_flag(argv: &[String], name: &str) -> bool {
    argv.iter().any(|a| a == name)
}

fn flag_value(argv: &[String], name: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == name)
        .and_then(|i| argv.get(i + 1).cloned())
}

const USAGE: &str = "cya — clean your attribution

  cya scan [--range A..B | --stdin | --pre-push]   find denied attribution
  cya strip                                      stdin → stdout, trailers removed
  cya strip-file PATH                            rewrite a commit message file
  cya clean [--range A..B]                       rewrite the range, stripping trailers
  cya hook [--dir DIR] [--force]                 install commit-msg + pre-push hooks
  cya policy [--check]                           print / verify effective policy
  cya agents [off [ID]]                          agent attribution switches: report, or off all / one

Policy: --policy-url URL or CYA_POLICY_URL, else the compiled-in policy.
";

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    let command = argv.first().map(String::as_str).unwrap_or("");
    let rest = &argv[1..];
    let code = if command == "hook" {
        cmd_hook(rest)
    } else if command == "agents" {
        cmd_agents(&argv)
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
