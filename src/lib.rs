//! One attribution policy, shared by the `cya` CLI binary and the
//! server-side check workflow. The policy file is embedded at compile
//! time, so the binary always carries the rules the repository publishes.

use anyhow::{Context, Result, ensure};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::process::Command;
use std::sync::LazyLock;

/// Canonical policy embedded from `policy/trailers.json` — file and binary
/// cannot drift apart because there is one source of bytes.
const POLICY_JSON: &str = include_str!("../policy/trailers.json");

#[derive(Deserialize)]
struct PolicyFile {
    #[serde(rename = "denyTrailerKeys", default)]
    deny_trailer_keys: Vec<String>,
    #[serde(rename = "denyMessagePatterns", default)]
    deny_message_patterns: Vec<PatternSpec>,
    #[serde(rename = "rulesetPattern")]
    ruleset_pattern: String,
}

#[derive(Deserialize)]
struct PatternSpec {
    id: Option<String>,
    flags: Option<String>,
    pattern: String,
}

pub struct DenyPattern {
    pub id: String,
    pub regex: Regex,
}

pub struct Policy {
    /// Trailer keys denied in the trailing block, stored lowercased.
    pub deny_trailer_keys: Vec<String>,
    pub deny_patterns: Vec<DenyPattern>,
    /// RE2 pattern for GitHub ruleset metadata restrictions.
    pub ruleset_pattern: String,
    pub source: String,
}

fn build_regex(spec: &PatternSpec) -> Result<Regex> {
    let flags = spec.flags.as_deref().unwrap_or("im");
    RegexBuilder::new(&spec.pattern)
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .ignore_whitespace(flags.contains('x'))
        .build()
        .with_context(|| format!("invalid deny pattern {:?}", spec.pattern))
}

pub fn parse_policy(json: &str, source: &str) -> Result<Policy> {
    let raw: PolicyFile = serde_json::from_str(json).context("policy JSON invalid")?;
    let deny_trailer_keys = raw
        .deny_trailer_keys
        .iter()
        .map(|k| k.to_lowercase())
        .collect();
    let deny_patterns = raw
        .deny_message_patterns
        .iter()
        .map(|spec| {
            Ok(DenyPattern {
                id: spec.id.clone().unwrap_or_else(|| "unnamed".into()),
                regex: build_regex(spec)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Policy {
        deny_trailer_keys,
        deny_patterns,
        ruleset_pattern: raw.ruleset_pattern,
        source: source.into(),
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

// --------------------------------------------------------------- messages

static TRAILER_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z][A-Za-z0-9-]*):\s*").unwrap());
static CONTINUATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+\S").unwrap());

/// The trailing paragraph is a trailer block only when every line in it is
/// a `Key: value` line or a wrapped continuation. Returns `(start, end)`.
pub fn locate_trailer_block(lines: &[&str]) -> Option<(usize, usize)> {
    let mut end = lines.len();
    while end > 0 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let line = lines[start - 1];
        if TRAILER_KEY.is_match(line) || CONTINUATION.is_match(line) {
            start -= 1;
        } else {
            break;
        }
    }
    (start < end).then_some((start, end))
}

pub struct TrailerHit {
    pub line: usize,
    pub key: String,
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
    let lines: Vec<&str> = normalized.split('\n').collect();
    let mut findings = Findings::default();
    if let Some((start, end)) = locate_trailer_block(&lines) {
        for (i, line) in lines.iter().enumerate().take(end).skip(start) {
            if let Some(caps) = TRAILER_KEY.captures(line) {
                let key = &caps[1];
                if policy.deny_trailer_keys.contains(&key.to_lowercase()) {
                    findings.trailers.push(TrailerHit {
                        line: i + 1,
                        key: key.to_string(),
                        text: line.trim().to_string(),
                    });
                }
            }
        }
    }
    for (i, line) in lines.iter().enumerate() {
        for p in &policy.deny_patterns {
            if p.regex.is_match(line) {
                findings.patterns.push(PatternHit {
                    line: i + 1,
                    id: p.id.clone(),
                    text: line.trim().to_string(),
                });
            }
        }
    }
    findings
}

/// Remove denied trailer lines (with their wrapped continuations) and any
/// line matching a deny pattern. Everything else is preserved verbatim.
/// Returns the cleaned text and the keys/ids that were removed.
pub fn strip_denied(message: &str, policy: &Policy) -> (String, Vec<String>) {
    let normalized = message.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let (block_start, block_end) = locate_trailer_block(&lines).unwrap_or((usize::MAX, 0));
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let mut dropping = false;
    for (i, line) in lines.iter().enumerate() {
        let in_block = i >= block_start && i < block_end;
        let key = in_block
            .then(|| TRAILER_KEY.captures(line))
            .flatten()
            .map(|c| c[1].to_string());
        if let Some(key) = &key {
            dropping = policy.deny_trailer_keys.contains(&key.to_lowercase());
            if dropping {
                removed.push(key.clone());
            }
        }
        let is_continuation = in_block && key.is_none() && CONTINUATION.is_match(line);
        let pattern_denied = policy.deny_patterns.iter().any(|p| p.regex.is_match(line));
        if (key.is_some() && dropping)
            || (is_continuation && dropping)
            || (pattern_denied && key.is_none())
        {
            if pattern_denied && key.is_none() && !is_continuation {
                removed.push("pattern".into());
            }
            continue;
        }
        kept.push(*line);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        parse_policy(POLICY_JSON, "test").unwrap()
    }

    const LULOT: &str = "docs: regenerate canonical planning and collection indexes\n\nRegenerate the three indexes reported stale by CI from the complete\ncandidate checkout. Preserve language implementation and tests.\n\nCo-authored-by: Lulot <lulot@users.noreply.github.com>\n";

    #[test]
    fn strips_agent_coauthor_and_keeps_body() {
        let (text, removed) = strip_denied(LULOT, &policy());
        assert_eq!(removed, ["Co-authored-by"]);
        assert!(!text.contains("Lulot"));
        assert!(text.starts_with("docs: regenerate canonical planning"));
        assert!(text.contains("Preserve language implementation and tests."));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn keeps_non_denied_trailers() {
        let message = "fix: thing\n\nBody.\n\nSigned-off-by: Human <h@example.com>\nCo-authored-by: Bot <b@example.com>\n";
        let (text, _) = strip_denied(message, &policy());
        assert!(text.contains("Signed-off-by: Human <h@example.com>"));
        assert!(!text.contains("Bot"));
    }

    #[test]
    fn drops_wrapped_continuations_of_denied_trailer() {
        let message = "feat: x\n\nCo-authored-by: Bot\n <bot@example.com> extra\nReviewed-by: Human <h@example.com>\n";
        let (text, _) = strip_denied(message, &policy());
        assert!(!text.contains("bot@example.com"));
        assert!(text.contains("Reviewed-by: Human"));
    }

    #[test]
    fn trailerless_message_unchanged() {
        let message = "chore: plain commit\n\nA body with no trailers.\n";
        let (text, removed) = strip_denied(message, &policy());
        assert_eq!(text, message);
        assert!(removed.is_empty());
    }

    #[test]
    fn prose_mention_is_not_a_trailer() {
        let message = "docs: notes\n\nCo-authored-by: someone wrote this line mid-paragraph,\nbut a following plain sentence keeps it out of the trailer block.\n";
        let (_, removed) = strip_denied(message, &policy());
        assert!(removed.is_empty());
    }

    #[test]
    fn generated_with_footer_removed() {
        let message = "feat: y\n\n🤖 Generated with ExampleTool\n";
        let (text, _) = strip_denied(message, &policy());
        assert!(!text.contains("Generated with"));
    }

    #[test]
    fn findings_report_trailer_with_line() {
        let findings = message_findings(LULOT, &policy());
        assert_eq!(findings.trailers.len(), 1);
        assert_eq!(findings.trailers[0].key, "Co-authored-by");
        assert!(findings.trailers[0].line > 1);
    }

    #[test]
    fn trailer_block_presence() {
        assert!(locate_trailer_block(&["a", "", "B: c", ""]).is_some());
        assert!(locate_trailer_block(&["a", "", "just a sentence", ""]).is_none());
    }
}
