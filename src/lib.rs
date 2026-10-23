//! One attribution policy, shared by the `cya` CLI binary and the
//! server-side check workflow. The policy file is embedded at compile
//! time, so the binary always carries the rules the repository publishes.
//!
//! The catalogue is a precise-match list of *verified* official agent
//! identities: a line is denied only when it claims one of those
//! identities by display name or by address. Human co-authors —
//! including names that merely resemble an agent — are preserved.

use anyhow::{Context, Result, bail, ensure};
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
    /// Trailer keys declared in the policy file — the canonical attribution
    /// keys. Matching is broader than this list (any `Key:` line is
    /// inspected); the field remains the preset-floor contract.
    pub trailer_keys: Vec<String>,
    pub agents: Vec<Agent>,
    pub source: String,
}

fn parse_policy(json: &str, source: &str) -> Result<Policy> {
    let raw: PolicyFile = serde_json::from_str(json).context("policy JSON invalid")?;
    ensure!(!raw.agents.is_empty(), "policy lists no agents");
    let trailer_keys: Vec<String> = raw.trailer_keys.iter().map(|k| k.to_lowercase()).collect();
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
    })
}

/// The bundled catalogue is the floor every policy source must cover:
/// a fetched policy may *add* trailer keys, agents, names or addresses,
/// but dropping any preset element rejects the whole policy before a
/// single message is scanned.
pub fn validate_against_preset(effective: &Policy) -> Result<()> {
    let preset = parse_policy(POLICY_JSON, "bundled preset")?;
    for key in &preset.trailer_keys {
        ensure!(
            effective.trailer_keys.contains(key),
            "policy drops trailer key {key:?} (preset floor: additions allowed, removals not)"
        );
    }
    for preset_agent in &preset.agents {
        let Some(actual) = effective.agents.iter().find(|a| a.id == preset_agent.id) else {
            bail!(
                "policy drops agent {:?} (preset floor: additions allowed, removals not)",
                preset_agent.id
            );
        };
        for n in &preset_agent.names {
            ensure!(
                actual.names.contains(n),
                "policy drops name {n:?} from agent {:?} (preset floor)",
                preset_agent.id
            );
        }
        for x in &preset_agent.addresses {
            ensure!(
                actual.addresses.contains(x),
                "policy drops address {x:?} from agent {:?} (preset floor)",
                preset_agent.id
            );
        }
    }
    Ok(())
}

/// Policy resolution: `--policy-url` / `CYA_POLICY_URL` first (lets a fleet
/// update rules without reinstalling), else the compile-time-embedded file.
/// Every source — bundled included — must cover the bundled preset floor.
pub fn load_policy(policy_url: Option<&str>) -> Result<Policy> {
    let url = policy_url
        .map(str::to_string)
        .or_else(|| std::env::var("CYA_POLICY_URL").ok());
    let (json, source) = if let Some(url) = url {
        let out = Command::new("curl")
            .args(["-fsSL", &url])
            .output()
            .context("failed to launch curl")?;
        ensure!(out.status.success(), "policy fetch failed: {url}");
        (String::from_utf8(out.stdout).context("policy fetch not utf-8")?, url)
    } else {
        (POLICY_JSON.to_string(), "bundled".to_string())
    };
    let policy = parse_policy(&json, &source)?;
    validate_against_preset(&policy)?;
    Ok(policy)
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

/// Any `Key: value` line — trailer keys beyond the canonical three carry
/// attribution too (Signed-off-by, Reviewed-by, whatever a tool invents).
static KEY_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*?)[ \t]*$").unwrap());
static GENERATED_WITH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[^\w\s]{0,3}\s*generated\s+with\s+").unwrap());

/// The agent id a `name <addr>` pair or a bare name/addr resolves to.
fn find_agent(name: &str, addr: Option<&str>, policy: &Policy) -> Option<String> {
    policy
        .agents
        .iter()
        .find(|a| name_matches(name, a) || addr.is_some_and(|x| addr_matches(x, a)))
        .map(|a| a.id.clone())
}

/// The agent id a single line attributes work to, if it is a denied
/// attribution line — a `Key: Name <addr>` trailer of ANY key, a bare
/// `Name <addr>` or bare-address full line, or a `Generated with <name>`
/// badge. Indented lines never match: a body quoting a trailer as an
/// example keeps it. `None` means the line stays.
fn attribution_agent(line: &str, policy: &Policy) -> Option<String> {
    if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    if let Some(caps) = KEY_LINE.captures(line) {
        let (name, addr) = split_name_addr(&caps[2]);
        return find_agent(name, addr, policy);
    }
    if let Some(m) = GENERATED_WITH.find(line) {
        let inner = line[m.end()..].trim_start_matches('[');
        let name = inner.split([']', '(']).next().unwrap_or("").trim();
        return find_agent(name, None, policy);
    }
    // Bare `Name <addr>` or bare address as the whole line.
    let (name, addr) = split_name_addr(line.trim_end());
    if addr.is_some() {
        return find_agent(name, addr, policy);
    }
    if !line.contains(char::is_whitespace) && line.contains('@') {
        return find_agent("", Some(line.trim()), policy);
    }
    None
}

/// The agent id a commit's author or committer field resolves to.
/// Agents sign commits directly too — copilot-swe-agent[bot] and
/// factory-droid[bot] author commits with no trailer at all.
pub fn identity_agent(name: &str, email: &str, policy: &Policy) -> Option<String> {
    find_agent(name.trim(), Some(email.trim()), policy)
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

/// A hit in the author/committer fields rather than the message.
pub struct IdentityHit {
    pub field: &'static str,
    pub agent: String,
    pub text: String,
}

#[derive(Default)]
pub struct Findings {
    pub trailers: Vec<TrailerHit>,
    pub patterns: Vec<PatternHit>,
    pub identities: Vec<IdentityHit>,
}

impl Findings {
    pub fn total(&self) -> usize {
        self.trailers.len() + self.patterns.len() + self.identities.len()
    }
}

pub fn message_findings(message: &str, policy: &Policy) -> Findings {
    let normalized = message.replace("\r\n", "\n");
    let mut findings = Findings::default();
    for (i, line) in normalized.split('\n').enumerate() {
        if let Some(agent) = attribution_agent(line, policy) {
            if let Some(caps) = KEY_LINE.captures(line) {
                findings.trailers.push(TrailerHit {
                    line: i + 1,
                    key: caps[1].to_string(),
                    agent,
                    text: line.trim().to_string(),
                });
            } else {
                findings.patterns.push(PatternHit {
                    line: i + 1,
                    id: agent,
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
                dropping = KEY_LINE.is_match(line);
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

/// One ruleset rule: `rule_type` is the GitHub ruleset rule type
/// (`commit_message_pattern`, `commit_author_email_pattern`,
/// `committer_email_pattern`); `pattern` is RE2 with `negate: true`.
pub struct RulesetRule {
    pub rule_type: &'static str,
    pub name: String,
    pub pattern: String,
}

impl Policy {
    /// RE2 rules for the GitHub ruleset — generated from the catalogue so
    /// the JSON stays the single source and never drifts from what the
    /// binaries enforce. Message rules mirror the full-domain matching:
    /// any `Key:` line, bare `Name <addr>` lines, bare addresses and
    /// generated-with badges; author/committer rules deny the verified
    /// addresses in the identity fields themselves.
    pub fn ruleset_patterns(&self) -> Vec<RulesetRule> {
        let mut names: Vec<String> = self
            .agents
            .iter()
            .flat_map(|a| a.names.iter().map(|n| re2_escape(n)))
            .collect();
        names.sort_by_key(|b| std::cmp::Reverse(b.len()));
        names.dedup();
        let names_alt = names.join("|");

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
        let addr_alt = if exact.is_empty() {
            format!("(?:[0-9]+\\+)?(?:{})@users\\.noreply\\.github\\.com", noreply.join("|"))
        } else {
            format!(
                "(?:(?:[0-9]+\\+)?(?:{})@users\\.noreply\\.github\\.com|{})",
                noreply.join("|"),
                exact.join("|")
            )
        };

        vec![
            RulesetRule {
                rule_type: "commit_message_pattern",
                name: "deny listed agent names in attribution lines".into(),
                pattern: format!(
                    "(?im)^[A-Za-z][A-Za-z0-9-]*:[ \\t]*(?:{names_alt})(?:$|[^A-Za-z0-9])"
                ),
            },
            RulesetRule {
                rule_type: "commit_message_pattern",
                name: "deny listed agent addresses in attribution lines".into(),
                pattern: format!(
                    "(?im)^[A-Za-z][A-Za-z0-9-]*:[^<\\n]*<(?:{addr_alt})>"
                ),
            },
            RulesetRule {
                rule_type: "commit_message_pattern",
                name: "deny bare agent name-address lines".into(),
                pattern: format!("(?im)^(?:{names_alt})[ \\t]*<[^>\\n]*>"),
            },
            RulesetRule {
                rule_type: "commit_message_pattern",
                name: "deny bare agent address lines".into(),
                pattern: format!("(?im)^<?(?:{addr_alt})>?[ \\t]*$"),
            },
            RulesetRule {
                rule_type: "commit_message_pattern",
                name: "deny generated-with badges naming listed agents".into(),
                pattern: format!(
                    "(?im)^[^\\w\\s]{{0,3}}\\s*generated\\s+with[^\\n]*(?:{names_alt})(?:$|[^A-Za-z0-9])"
                ),
            },
            RulesetRule {
                rule_type: "commit_author_email_pattern",
                name: "deny listed agent author addresses".into(),
                pattern: format!("(?i)^{addr_alt}$"),
            },
            RulesetRule {
                rule_type: "committer_email_pattern",
                name: "deny listed agent committer addresses".into(),
                pattern: format!("(?i)^{addr_alt}$"),
            },
        ]
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
    fn full_domain_matching() {
        // Any trailer key — not just the canonical three — denies.
        for line in [
            "Signed-off-by: codex <267193182+codex@users.noreply.github.com>",
            "Reviewed-by: copilot-swe-agent[bot] <x@y.example>",
            "X-Custom: Claude Code",
        ] {
            let (_, removed) = strip_denied(&format!("fix: t\n\n{line}\n"), &policy());
            assert_eq!(removed.len(), 1, "line: {line}");
        }
        // Bare `Name <addr>` and bare-address full lines deny too.
        let (_, removed) = strip_denied(
            "fix: t\n\nfactory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>\n",
            &policy(),
        );
        assert_eq!(removed, ["factory-droid"]);
        let (_, removed) = strip_denied("fix: t\n\njules@google.com\n", &policy());
        assert_eq!(removed, ["google-jules"]);
        // Agent identities in author/committer fields deny.
        assert_eq!(
            identity_agent("copilot-swe-agent[bot]", "anything@users.noreply.github.com", &policy()),
            Some("github-copilot".into())
        );
        assert_eq!(
            identity_agent("Whoever", "267193182+codex@users.noreply.github.com", &policy()),
            Some("openai-codex".into())
        );
        assert_eq!(
            identity_agent("Jane Doe", "jane@corp.com", &policy()),
            None
        );
    }

    #[test]
    fn ruleset_patterns_compile() {
        for r in policy().ruleset_patterns() {
            assert!(Regex::new(&r.pattern).is_ok(), "ruleset rule {} invalid: {}", r.name, r.pattern);
        }
    }

    fn policy_json() -> serde_json::Value {
        serde_json::from_str(POLICY_JSON).unwrap()
    }

    #[test]
    fn preset_floor_allows_additions_rejects_removals() {
        // The bundled file is its own superset.
        validate_against_preset(&policy()).unwrap();

        // An extra agent is fine.
        let mut added = policy_json();
        added["agents"].as_array_mut().unwrap().push(serde_json::json!({
            "id": "new-agent", "names": ["New Agent"], "addresses": [], "verify": "x"
        }));
        let p = parse_policy(&added.to_string(), "t").unwrap();
        validate_against_preset(&p).unwrap();

        // Dropping an agent rejects.
        let mut dropped = policy_json();
        dropped["agents"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a["id"] != "claude");
        let p = parse_policy(&dropped.to_string(), "t").unwrap();
        let e = validate_against_preset(&p).unwrap_err().to_string();
        assert!(e.contains("claude"), "{e}");

        // Dropping a single address rejects too.
        let mut trimmed = policy_json();
        let claude = trimmed["agents"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|a| a["id"] == "claude")
            .unwrap();
        claude["addresses"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a != "noreply@anthropic.com");
        let p = parse_policy(&trimmed.to_string(), "t").unwrap();
        let e = validate_against_preset(&p).unwrap_err().to_string();
        assert!(e.contains("noreply@anthropic.com"), "{e}");

        // Dropping a trailer key rejects.
        let mut keyed = policy_json();
        keyed["trailerKeys"]
            .as_array_mut()
            .unwrap()
            .retain(|k| k != "Co-authored-by");
        let p = parse_policy(&keyed.to_string(), "t").unwrap();
        let e = validate_against_preset(&p).unwrap_err().to_string();
        assert!(e.contains("co-authored-by"), "{e}");
    }
}
