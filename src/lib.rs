//! One attribution policy, shared by the `cya` CLI binary and the
//! server-side check workflow. The policy file is embedded at compile
//! time, so the binary always carries the rules the repository publishes.
//!
//! The catalogue is a precise-match list of *verified* official agent
//! identities: a line is denied only when it claims one of those
//! identities by display name or by address. Human co-authors —
//! including names that merely resemble an agent — are preserved.

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Deserialize;
use std::process::Command;
use std::sync::LazyLock;

/// Canonical policy embedded from `policy/trailers.json` — file and binary
/// cannot drift apart because there is one source of bytes.
const POLICY_JSON: &str = include_str!("../policy/trailers.json");

#[derive(Deserialize)]
struct PolicyFile {
    #[serde(rename = "trailerKeys", default)]
    trailer_keys: Vec<String>,
    #[serde(default)]
    agents: Vec<AgentSpec>,
}

#[derive(Deserialize)]
struct AgentSpec {
    id: String,
    #[serde(default)]
    verify: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    addresses: Vec<String>,
}

pub struct Agent {
    /// Stable catalogue id, reported in findings.
    pub id: String,
    /// Evidence pointer for humans auditing the list.
    pub verify: String,
    /// Display names, lowercased. Prefix-matched on a non-alphanumeric
    /// boundary so "Claude Sonnet 5" matches the "claude" family but
    /// "Claude Dubois" does not (the name must be listed to match at all).
    pub names: Vec<String>,
    /// Verified attribution addresses, lowercased.
    pub addresses: Vec<String>,
}

pub struct Policy {
    /// Trailer keys inspected for agent attribution, stored lowercased.
    pub trailer_keys: Vec<String>,
    pub agents: Vec<Agent>,
    pub source: String,
    /// `Key:`-prefixed trailer line matcher built from trailer_keys.
    trailer_line: Regex,
}

fn parse_policy(json: &str, source: &str) -> Result<Policy> {
    let raw: PolicyFile = serde_json::from_str(json).context("policy JSON invalid")?;
    ensure!(!raw.agents.is_empty(), "policy lists no agents");
    let trailer_keys: Vec<String> = raw.trailer_keys.iter().map(|k| k.to_lowercase()).collect();
    let keys_alt = raw
        .trailer_keys
        .iter()
        .map(|k| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");
    let trailer_line =
        Regex::new(&format!("(?i)^({keys_alt}):\\s*(.*?)\\s*$")).context("bad trailerKeys")?;
    let mut agents = Vec::new();
    for spec in &raw.agents {
        ensure!(
            !spec.names.is_empty() || !spec.addresses.is_empty(),
            "agent {:?} has neither names nor addresses",
            spec.id
        );
        agents.push(Agent {
            id: spec.id.clone(),
            verify: spec.verify.clone().unwrap_or_default(),
            names: spec.names.iter().map(|n| n.to_lowercase()).collect(),
            addresses: spec.addresses.iter().map(|a| a.to_lowercase()).collect(),
        });
    }
    Ok(Policy {
        trailer_keys,
        agents,
        source: source.into(),
        trailer_line,
    })
}

/// Policy resolution: `--policy-url` / `CYA_POLICY_URL` first (lets a fleet
/// update rules without reinstalling), else the compile-time-embedded file.
pub fn load_policy(policy_url: Option<&str>) -> Result<Policy> {
    let url = policy_url
        .map(str::to_string)
        .or_else(|| std::env::var("CYA_POLICY_URL").ok());
    if let Some(url) = url {
        let out = Command::new("curl")
            .args(["-fsSL", &url])
            .output()
            .context("failed to launch curl")?;
        ensure!(out.status.success(), "policy fetch failed: {url}");
        let json = String::from_utf8(out.stdout).context("policy fetch not utf-8")?;
        return parse_policy(&json, &url);
    }
    parse_policy(POLICY_JSON, "bundled")
}

// -------------------------------------------------------------- matching

/// Name match is exact or a prefix ending on a non-alphanumeric boundary:
/// "Claude Code:claude-sonnet-4-6" and "Claude Code v2" match the listed
/// "claude code", but "ClaudeCoder" and "Claude Dubois" do not (the latter
/// fails because "claude" alone is not a listed name).
fn name_matches(candidate: &str, agent: &Agent) -> bool {
    let c = candidate.trim().to_lowercase();
    agent.names.iter().any(|n| {
        c == *n || (c.starts_with(n.as_str())
            && c[n.len()..].chars().next().map_or(false, |ch| !ch.is_alphanumeric()))
    })
}

fn addr_matches(addr: &str, agent: &Agent) -> bool {
    let a = addr.trim().to_lowercase();
    if agent.addresses.iter().any(|x| a == *x) {
        return true;
    }
    // A users.noreply.github.com address matches on its local part alone,
    // so any `<id>+<login>` variant of a listed account is covered.
    if let Some(local) = a.strip_suffix("@users.noreply.github.com") {
        let bare = local.split_once('+').map(|(_, l)| l).unwrap_or(local);
        return agent.addresses.iter().any(|x| {
            x.strip_suffix("@users.noreply.github.com").is_some_and(|xl| {
                let xb = xl.split_once('+').map(|(_, l)| l).unwrap_or(xl);
                bare == xb
            })
        });
    }
    false
}

/// `Name <addr>` in a trailer value; a value without angle brackets is a
/// bare name (Generated-by / Assisted-by carry name or name:model forms).
fn split_name_addr(value: &str) -> (&str, Option<&str>) {
    if let Some(open) = value.find('<') {
        if let Some(close) = value.rfind('>') {
            if close > open {
                return (value[..open].trim(), Some(value[open + 1..close].trim()));
            }
        }
    }
    (value.trim(), None)
}

static GENERATED_WITH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[^\w\s]{0,3}\s*generated\s+with\s+").unwrap());

/// The agent id a single line attributes work to, if it is a denied
/// attribution line. Indented lines never match — a body quoting a trailer
/// as an example keeps it. `None` means the line stays.
fn attribution_agent(line: &str, policy: &Policy) -> Option<String> {
    if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    if let Some(caps) = policy.trailer_line.captures(line) {
        let (name, addr) = split_name_addr(&caps[2]);
        return policy
            .agents
            .iter()
            .find(|a| name_matches(name, a) || addr.is_some_and(|x| addr_matches(x, a)))
            .map(|a| a.id.clone());
    }
    if let Some(m) = GENERATED_WITH.find(line) {
        let rest = &line[m.end()..];
        let inner = rest.trim_start_matches('[');
        let name = inner
            .split([']', '('])
            .next()
            .unwrap_or("")
            .trim();
        return policy
            .agents
            .iter()
            .find(|a| name_matches(name, a))
            .map(|a| a.id.clone());
    }
    None
}

// --------------------------------------------------------------- findings

pub struct TrailerHit {
    pub line: usize,
    pub key: String,
    pub agent: String,
    pub text: String,
}

pub struct PatternHit {
    pub line: usize,
    pub id: String,
    pub text: String,
}

#[derive(Default)]
pub struct Findings {
    pub trailers: Vec<TrailerHit>,
    pub patterns: Vec<PatternHit>,
}

impl Findings {
    pub fn total(&self) -> usize {
        self.trailers.len() + self.patterns.len()
    }
}

pub fn message_findings(message: &str, policy: &Policy) -> Findings {
    let normalized = message.replace("\r\n", "\n");
    let mut findings = Findings::default();
    for (i, line) in normalized.split('\n').enumerate() {
        if let Some(agent) = attribution_agent(line, policy) {
            let key = policy
                .trailer_line
                .captures(line)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| "generated-with".into());
            if key.eq_ignore_ascii_case("generated-with") {
                findings.patterns.push(PatternHit {
                    line: i + 1,
                    id: agent,
                    text: line.trim().to_string(),
                });
            } else {
                findings.trailers.push(TrailerHit {
                    line: i + 1,
                    key,
                    agent,
                    text: line.trim().to_string(),
                });
            }
        }
    }
    findings
}

/// Remove attribution lines that claim a verified agent identity, plus the
/// wrapped continuation lines hanging off a denied trailer. Everything else
/// is preserved verbatim — human co-authors, Signed-off-by, prose.
/// Returns the cleaned text and the agent ids that were removed.
pub fn strip_denied(message: &str, policy: &Policy) -> (String, Vec<String>) {
    let normalized = message.replace("\r\n", "\n");
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let mut dropping = false;
    for line in normalized.split('\n') {
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if indented && dropping && !line.trim().is_empty() {
            continue;
        }
        dropping = false;
        match attribution_agent(line, policy) {
            Some(agent) => {
                removed.push(agent);
                // Trailer values wrap onto indented continuation lines.
                dropping = !indented && policy.trailer_line.is_match(line);
            }
            None => kept.push(line),
        }
    }
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    let text = if kept.is_empty() {
        String::new()
    } else {
        let mut t = kept.join("\n");
        t.push('\n');
        t
    };
    (text, removed)
}

// ------------------------------------------------------- ruleset patterns

fn re2_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if "\\.^$|?*+()[]{}".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

impl Policy {
    /// RE2 patterns for GitHub ruleset `commit_message_pattern` (negate)
    /// rules — generated from the catalogue so the JSON stays the single
    /// source and never drifts from what the binaries enforce.
    pub fn ruleset_patterns(&self) -> Vec<(String, String)> {
        let mut names: Vec<String> = self
            .agents
            .iter()
            .flat_map(|a| a.names.iter().map(|n| re2_escape(n)))
            .collect();
        names.sort_by_key(|b| std::cmp::Reverse(b.len()));
        names.dedup();
        let names_alt = names.join("|");
        let keys_alt = self
            .trailer_keys
            .iter()
            .map(|k| re2_escape(k))
            .collect::<Vec<_>>()
            .join("|");

        // users.noreply.github.com local parts get an optional <id>+ prefix;
        // other domains match their exact verified address.
        let mut noreply: Vec<String> = vec![];
        let mut exact: Vec<String> = vec![];
        for a in self.agents.iter().flat_map(|a| &a.addresses) {
            if let Some(local) = a.strip_suffix("@users.noreply.github.com") {
                let bare = local.split_once('+').map(|(_, l)| l).unwrap_or(local);
                noreply.push(re2_escape(bare));
            } else {
                exact.push(re2_escape(a));
            }
        }
        noreply.sort();
        noreply.dedup();
        exact.sort();
        exact.dedup();
        let mut addr_alt = vec![format!(
            "(?:[0-9]+\\+)?(?:{})@users\\.noreply\\.github\\.com",
            noreply.join("|")
        )];
        if !exact.is_empty() {
            addr_alt.push(exact.join("|"));
        }

        let mut rules = vec![];
        rules.push((
            "deny listed agent names in attribution trailers".into(),
            format!("(?im)^(?:{keys_alt}):\\s*(?:{names_alt})(?:$|[^A-Za-z0-9])"),
        ));
        rules.push((
            "deny listed agent addresses in attribution trailers".into(),
            format!(
                "(?im)^(?:{keys_alt}):[^<\\n]*<(?:{})>",
                addr_alt.join("|")
            ),
        ));
        rules.push((
            "deny generated-with badges naming listed agents".into(),
            format!("(?im)^[^\\w\\s]{{0,3}}\\s*generated\\s+with[^\\n]*(?:{names_alt})(?:$|[^A-Za-z0-9])"),
        ));
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        parse_policy(POLICY_JSON, "test").unwrap()
    }

    const CODEX_MSG: &str = "feat: x\n\nBody.\n\nCo-authored-by: codex <267193182+codex@users.noreply.github.com>\n";

    #[test]
    fn strips_verified_agent_coauthor_and_keeps_body() {
        let (text, removed) = strip_denied(CODEX_MSG, &policy());
        assert_eq!(removed, ["openai-codex"]);
        assert!(!text.contains("codex"));
        assert!(text.starts_with("feat: x"));
        assert!(text.contains("Body."));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn human_coauthor_is_preserved() {
        // Lulot is a real human account — not in the catalogue — so the
        // trailer stays even though it is agent-shaped.
        let msg = "fix: thing\n\nBody.\n\nCo-authored-by: Lulot <lulot@users.noreply.github.com>\n";
        let (text, removed) = strip_denied(msg, &policy());
        assert!(removed.is_empty());
        assert!(text.contains("Lulot"));
        // An ordinary human co-author on any address is untouched.
        let (text, removed) =
            strip_denied("fix: t\n\nB.\n\nCo-authored-by: Jane Doe <jane@corp.com>\n", &policy());
        assert!(removed.is_empty());
        assert!(text.contains("Jane Doe"));
    }

    #[test]
    fn human_name_collision_is_not_denied() {
        // "Claude" is not a listed name (real trailers carry the address);
        // a human named Claude survives.
        let msg = "fix: t\n\nCo-authored-by: Claude Dubois <claude.d@corp.com>\n";
        let (_, removed) = strip_denied(msg, &policy());
        assert!(removed.is_empty());
        // Jules is a human first name — only the google.com address is denied.
        let (_, removed) =
            strip_denied("fix: t\n\nCo-authored-by: Jules <jules@example.com>\n", &policy());
        assert!(removed.is_empty());
    }

    #[test]
    fn verified_forms_match_by_name_or_address() {
        for (line, id) in [
            ("Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>", "claude"),
            ("Co-authored-by: Jules <jules@google.com>", "google-jules"),
            ("Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>", "factory-droid"),
            ("Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>", "github-copilot"),
            ("Co-authored-by: CommandCodeBot <whatever@random.example>", "commandcode"),
            ("Co-authored-by: amazon-q-developer[bot] <208079219+amazon-q-developer[bot]@users.noreply.github.com>", "amazon-q"),
            ("Co-authored-by: Cursor Agent <cursoragent@cursor.com>", "cursor"),
            ("Generated-by: Claude Code:claude-sonnet-4-6", "claude"),
            ("Assisted-by: Codex", "openai-codex"),
        ] {
            let msg = format!("fix: t\n\n{line}\n");
            let (_, removed) = strip_denied(&msg, &policy());
            assert_eq!(removed, [id], "line: {line}");
        }
    }

    #[test]
    fn unverified_agent_names_are_preserved() {
        // Not in the catalogue: model ids, squatted human logins and tools
        // without a verified identity stay — only verified official
        // identities are denied.
        for line in [
            "Generated-by: gpt-5",
            "Co-authored-by: unknown-bot[bot] <1+unknown-bot[bot]@users.noreply.github.com>",
            "Co-authored-by: kimi <kimi@users.noreply.github.com>",
        ] {
            let (_, removed) = strip_denied(&format!("fix: t\n\n{line}\n"), &policy());
            assert!(removed.is_empty(), "line: {line}");
        }
        // The verified family name still denies sibling bot spellings:
        // "sweep" is the verified Sweep identity, so sweep-ai[bot] matches
        // by name even though that login did not resolve via the API.
        let (_, removed) = strip_denied(
            "fix: t\n\nCo-authored-by: sweep-ai[bot] <9+sweep-ai[bot]@users.noreply.github.com>\n",
            &policy(),
        );
        assert_eq!(removed, ["sweep"]);
    }

    #[test]
    fn generated_with_badges() {
        let msg = "feat: y\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n";
        let (_, removed) = strip_denied(msg, &policy());
        assert_eq!(removed, ["claude"]);
        let msg = "feat: y\n\nGenerated with [Devin AI](https://devin.ai)\n";
        let (_, removed) = strip_denied(msg, &policy());
        assert_eq!(removed, ["devin"]);
        // A tool outside the catalogue is preserved.
        let (_, removed) = strip_denied("feat: y\n\nGenerated with SomeTool\n", &policy());
        assert!(removed.is_empty());
    }

    #[test]
    fn keeps_non_agent_trailers() {
        let message = "fix: thing\n\nBody.\n\nSigned-off-by: Human <h@example.com>\nReviewed-by: Peer <p@example.com>\n";
        let (text, removed) = strip_denied(message, &policy());
        assert!(removed.is_empty());
        assert_eq!(text, message);
    }

    #[test]
    fn drops_wrapped_continuations_of_denied_trailer() {
        let message = "feat: x\n\nCo-authored-by: Codex\n <267193182+codex@users.noreply.github.com> extra\nReviewed-by: Human <h@example.com>\n";
        let (text, _) = strip_denied(message, &policy());
        assert!(!text.contains("codex@users.noreply.github.com"));
        assert!(text.contains("Reviewed-by: Human"));
    }

    #[test]
    fn prose_mention_is_not_denied() {
        let message = "docs: notes\n\nCo-authored-by: someone wrote this line mid-paragraph,\nbut a following plain sentence keeps it prose.\n  Co-authored-by: Codex <indented example stays>\n";
        let (_, removed) = strip_denied(message, &policy());
        assert!(removed.is_empty());
    }

    #[test]
    fn findings_report_agent_with_line() {
        let findings = message_findings(CODEX_MSG, &policy());
        assert_eq!(findings.trailers.len(), 1);
        assert_eq!(findings.trailers[0].agent, "openai-codex");
        assert_eq!(findings.trailers[0].line, 5);
    }

    #[test]
    fn ruleset_patterns_compile() {
        for (name, pat) in policy().ruleset_patterns() {
            assert!(Regex::new(&pat).is_ok(), "ruleset pattern {name} invalid: {pat}");
        }
    }
}
