//! Local agent attribution switches — `cya agents`.
//!
//! Every entry in [`AGENTS`] is one agent the tool knows how to handle.
//! Agents whose config carries a documented attribution knob get [`Knob`]s
//! and `cya agents off` writes the off-values; agents that stamp their
//! identity only server-side (cloud bots authoring as `*[bot]`) have no
//! local switch — the policy surfaces are what denies them, and the scan
//! says so instead of pretending to help.
//!
//! Editing rules: JSON files are parsed and rewritten with key order
//! preserved; a file that fails to parse is reported and never touched.
//! `off` means *every* file the key can live in is clean — precedence
//! clones like `settings.local.json` must not be left asserting `true`.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// The value a knob must hold for attribution to be off.
#[derive(Clone, PartialEq)]
pub enum Off {
    Bool(bool),
    Str(&'static str),
}

impl Off {
    fn value(&self) -> Value {
        match self {
            Off::Bool(b) => Value::Bool(*b),
            Off::Str(s) => Value::String((*s).to_string()),
        }
    }
}

/// One setting that switches an agent's attribution off.
pub enum Knob {
    /// A JSON settings file. `files[0]` is the primary (always written
    /// when needed); later files are precedence clones — touched only
    /// when they exist, so a file asserting the opposite cannot outrank
    /// the primary. `path` is a dotted object path created as needed.
    Json {
        files: &'static [&'static str],
        path: &'static [&'static str],
        off: Off,
    },
    /// A flat YAML config: one top-level `key: value` line per knob —
    /// replaced in place when present, appended when absent.
    Yaml {
        file: &'static str,
        key: &'static str,
        off: bool,
    },
}

impl Knob {
    /// The knob's dotted path / key, for reports.
    pub fn label(&self) -> String {
        match self {
            Knob::Json { path, .. } => path.join("."),
            Knob::Yaml { key, .. } => (*key).to_string(),
        }
    }
}

/// One agent the tool knows: how to tell it is installed and which
/// switches silence its attribution.
pub struct Agent {
    pub id: &'static str,
    pub display: &'static str,
    /// Home-relative paths; the agent counts as installed when any exists.
    pub detect: &'static [&'static str],
    pub knobs: &'static [Knob],
}

macro_rules! json {
    ($files:expr, $($seg:literal).+, $off:expr) => {
        Knob::Json { files: $files, path: &[ $($seg),+ ], off: $off }
    };
}

macro_rules! yaml {
    ($file:expr, $key:literal) => {
        Knob::Yaml {
            file: $file,
            key: $key,
            off: false,
        }
    };
}

const FALSE: Off = Off::Bool(false);
const EMPTY: Off = Off::Str("");

/// Agent-attribution switch registry. Knobbed agents first, then the
/// detected-only entries. Keep `knobs: &[]` entries honest: they are
/// reported, never claimed as switched.
pub const AGENTS: &[Agent] = &[
    Agent {
        id: "claude",
        display: "Claude Code",
        detect: &[".claude"],
        knobs: &[
            json!(
                &[".claude/settings.json", ".claude/settings.local.json"],
                "includeCoAuthoredBy",
                FALSE
            ),
            json!(&[".claude/settings.json", ".claude/settings.local.json"], "attribution"."commit", EMPTY),
            json!(&[".claude/settings.json", ".claude/settings.local.json"], "attribution"."pr", EMPTY),
        ],
    },
    Agent {
        id: "commandcode",
        display: "Command Code",
        detect: &[".commandcode"],
        knobs: &[
            json!(
                &[
                    ".commandcode/settings.json",
                    ".commandcode/settings.local.json"
                ],
                "includeCoAuthoredBy",
                FALSE
            ),
            json!(&[".commandcode/settings.json", ".commandcode/settings.local.json"], "attribution"."commit", EMPTY),
            json!(&[".commandcode/settings.json", ".commandcode/settings.local.json"], "attribution"."pr", EMPTY),
        ],
    },
    Agent {
        id: "cursor",
        display: "Cursor Agent",
        detect: &[".cursor"],
        knobs: &[
            json!(&[".cursor/cli-config.json"], "attribution"."attributeCommitsToAgent", FALSE),
            json!(&[".cursor/cli-config.json"], "attribution"."attributePRsToAgent", FALSE),
        ],
    },
    Agent {
        id: "devin",
        display: "Devin",
        detect: &[".config/devin"],
        knobs: &[json!(&[".config/devin/config.json"], "attribution", FALSE)],
    },
    Agent {
        id: "droid",
        display: "Factory Droid",
        detect: &[".factory"],
        knobs: &[json!(&[".factory/settings.json"], "general"."includeCoAuthoredByDroid", FALSE)],
    },
    Agent {
        id: "aider",
        display: "Aider",
        detect: &[".aider.conf.yml", ".aider-desk"],
        knobs: &[
            yaml!(".aider.conf.yml", "attribute-author"),
            yaml!(".aider.conf.yml", "attribute-committer"),
            yaml!(".aider.conf.yml", "attribute-co-authored-by"),
            yaml!(".aider.conf.yml", "attribute-committer-author"),
            yaml!(".aider.conf.yml", "attribute-committer-committer"),
        ],
    },
    Agent {
        id: "codex",
        display: "OpenAI Codex",
        detect: &[".codex"],
        knobs: &[],
    },
    Agent {
        id: "copilot",
        display: "GitHub Copilot CLI",
        detect: &[".copilot"],
        knobs: &[],
    },
    Agent {
        id: "antigravity",
        display: "Antigravity",
        detect: &[".gemini/antigravity-cli"],
        knobs: &[],
    },
    Agent {
        id: "gemini",
        display: "Gemini CLI",
        detect: &[".gemini"],
        knobs: &[],
    },
    Agent {
        id: "kilo",
        display: "Kilo Code CLI",
        detect: &[".config/kilo"],
        knobs: &[],
    },
    Agent {
        id: "kiro",
        display: "Kiro CLI",
        detect: &[".kiro"],
        knobs: &[],
    },
    Agent {
        id: "opencode",
        display: "OpenCode",
        detect: &[".config/opencode", ".opencode"],
        knobs: &[],
    },
    Agent {
        id: "openclaw",
        display: "OpenClaw",
        detect: &[".openclaw"],
        knobs: &[],
    },
    Agent {
        id: "trae",
        display: "Trae",
        detect: &[".trae"],
        knobs: &[],
    },
    Agent {
        id: "windsurf",
        display: "Windsurf",
        detect: &[".windsurf", ".codeium/windsurf"],
        knobs: &[],
    },
    Agent {
        id: "codebuddy",
        display: "CodeBuddy",
        detect: &[".codebuddy"],
        knobs: &[],
    },
    Agent {
        id: "workbuddy",
        display: "WorkBuddy",
        detect: &[".workbuddy"],
        knobs: &[],
    },
    Agent {
        id: "crush",
        display: "Crush",
        detect: &[".config/crush"],
        knobs: &[],
    },
    Agent {
        id: "goose",
        display: "Goose",
        detect: &[".config/goose"],
        knobs: &[],
    },
    Agent {
        id: "continue",
        display: "Continue",
        detect: &[".continue"],
        knobs: &[],
    },
];

// ------------------------------------------------------------- plumbing --

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(std::env::home_dir)
        .context("cannot resolve home directory")
}

fn at(home: &Path, rel: &str) -> PathBuf {
    home.join(rel)
}

fn installed(home: &Path, agent: &Agent) -> bool {
    agent.detect.iter().any(|p| at(home, p).exists())
}

/// One knob's observed state in one file.
#[derive(Debug)]
pub enum State {
    /// Already carries the off-value.
    Off,
    /// Present with a non-off value (rendered for the report).
    On(String),
    /// File exists and parses, but the key is absent — the agent's
    /// default applies, which for every registered knob is "on".
    Absent,
    /// The settings file itself is missing.
    NoFile,
    /// File exists but does not parse — reported, never written.
    Unparseable,
}

/// A (knob, file) observation.
pub struct Probe {
    /// Home-relative file path, for reports and the primary check.
    pub rel: &'static str,
    /// True for `files[0]` — the file written even when absent.
    pub primary: bool,
    pub state: State,
}

impl Probe {
    pub fn is_off(&self) -> bool {
        matches!(self.state, State::Off)
    }
}

fn render(v: &Value) -> String {
    match v {
        Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

fn json_get<'a>(mut v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for seg in path {
        v = v.get(*seg)?;
    }
    Some(v)
}

fn file_state_json(home: &Path, rel: &str, path: &[&str], off: &Off) -> State {
    let text = match fs::read_to_string(at(home, rel)) {
        Err(_) => return State::NoFile,
        Ok(t) => t,
    };
    match serde_json::from_str::<Value>(&text) {
        Err(_) => State::Unparseable,
        Ok(v) => match json_get(&v, path) {
            None => State::Absent,
            Some(cur) if *cur == off.value() => State::Off,
            Some(cur) => State::On(render(cur)),
        },
    }
}

/// Probe one knob across every file it can live in.
pub fn probe(home: &Path, knob: &Knob) -> Vec<Probe> {
    match knob {
        Knob::Json { files, path, off } => files
            .iter()
            .enumerate()
            .map(|(i, rel)| Probe {
                rel,
                primary: i == 0,
                state: file_state_json(home, rel, path, off),
            })
            .collect(),
        Knob::Yaml { file, key, off } => vec![Probe {
            rel: file,
            primary: true,
            state: match fs::read_to_string(at(home, file)) {
                Err(_) => State::NoFile,
                Ok(text) => match yaml_key(&text, key) {
                    YamlValue::Absent => State::Absent,
                    YamlValue::Scalar(v) if v == off.to_string() => State::Off,
                    YamlValue::Scalar(v) => State::On(v),
                },
            },
        }],
    }
}

/// One agent's scan result.
pub struct Report {
    pub agent: &'static Agent,
    pub installed: bool,
    /// (knob label, probe) pairs — one per file the knob can live in.
    pub probes: Vec<(String, Probe)>,
}

impl Report {
    /// Fully off: installed with knobs, and every knob is off. A knob is
    /// off when no file contradicts the off-value and at least one file
    /// pins it — a precedence clone that simply lacks the key inherits
    /// and does not count against.
    pub fn is_off(&self) -> bool {
        if !self.installed || self.agent.knobs.is_empty() {
            return false;
        }
        let mut all_off = true;
        let mut clean = true;
        let mut pinned = false;
        let mut last: Option<&str> = None;
        for (label, p) in &self.probes {
            if last != Some(label.as_str()) {
                if last.is_some() {
                    all_off &= clean && pinned;
                }
                clean = true;
                pinned = false;
                last = Some(label.as_str());
            }
            match p.state {
                State::On(_) | State::Unparseable => clean = false,
                State::Off => pinned = true,
                _ => {}
            }
        }
        if last.is_some() {
            all_off &= clean && pinned;
        }
        all_off
    }
    /// Exposed: installed, and some knob is on, missing or unreadable.
    pub fn is_exposed(&self) -> bool {
        self.installed && !self.agent.knobs.is_empty() && !self.is_off()
    }
}

pub fn scan(home: &Path, agent: &'static Agent) -> Report {
    let installed = installed(home, agent);
    let probes = if installed {
        agent
            .knobs
            .iter()
            .flat_map(|k| probe(home, k).into_iter().map(move |p| (k.label(), p)))
            .collect()
    } else {
        Vec::new()
    };
    Report {
        agent,
        installed,
        probes,
    }
}

// ------------------------------------------------------------ applying --

/// Per-probe apply outcome.
pub enum Applied {
    /// Off-value written (true = file changed, false = already correct).
    Written(bool),
    /// Secondary file does not exist — nothing to pin, it inherits.
    Absent,
    /// Exists but does not parse — NOT written, needs a manual pass.
    Unparseable,
}

/// Walk the object tree, creating objects along the path and setting the
/// leaf. A non-object in the way is replaced — the only documented case
/// is an invalid scalar standing where a settings object belongs.
fn json_set(v: &mut Value, path: &[&str], off: &Value) -> bool {
    if path.is_empty() {
        if *v == *off {
            return false;
        }
        *v = off.clone();
        return true;
    }
    if !v.is_object() {
        *v = Value::Object(Default::default());
    }
    let obj = v.as_object_mut().unwrap();
    json_set(
        obj.entry(path[0].to_string()).or_insert(Value::Null),
        &path[1..],
        off,
    )
}

fn write_atomic(file: &Path, text: &str) -> Result<()> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = file.with_extension("tmp");
    fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(file) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(
            &tmp,
            std::fs::Permissions::from_mode(meta.permissions().mode()),
        );
    }
    fs::rename(&tmp, file).with_context(|| format!("rename onto {}", file.display()))
}

enum YamlValue {
    Absent,
    Scalar(String),
}

/// A top-level `key:` line's scalar value — the only YAML level aider's
/// flat config uses. Indented keys belong to a section and are ignored.
fn yaml_key(text: &str, key: &str) -> YamlValue {
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.starts_with(char::is_whitespace) || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim() == key {
                let v = v.split(" #").next().unwrap_or("").trim();
                return YamlValue::Scalar(v.to_string());
            }
        }
    }
    YamlValue::Absent
}

fn yaml_set(text: &str, key: &str, off: bool) -> (String, bool) {
    let mut found = false;
    let mut changed = false;
    let mut out = String::with_capacity(text.len() + 32);
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = body.trim_end();
        let nl = if line.ends_with('\n') { "\n" } else { "" };
        if !trimmed.starts_with(char::is_whitespace) && !trimmed.starts_with('#') {
            if let Some((k, _)) = trimmed.split_once(':') {
                if k.trim() == key {
                    found = true;
                    let rep = format!("{key}: {off}");
                    if body != rep {
                        changed = true;
                    }
                    out.push_str(&rep);
                    out.push_str(nl);
                    continue;
                }
            }
        }
        out.push_str(line);
    }
    if !found {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("{key}: {off}\n"));
        changed = true;
    } else if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    (out, changed)
}

/// Apply one agent's knobs. JSON files are read once per file across all
/// that file's knobs, then rewritten once. Returns per-(knob,file)
/// outcomes for reporting.
pub fn apply(home: &Path, agent: &'static Agent) -> Result<Vec<(String, PathBuf, Applied)>> {
    let mut out = Vec::new();
    for knob in agent.knobs {
        match knob {
            Knob::Json { files, path, off } => {
                for (i, rel) in files.iter().enumerate() {
                    let state = file_state_json(home, rel, path, off);
                    let file = at(home, rel);
                    let applied = match state {
                        State::Off => Applied::Written(false),
                        State::Unparseable => Applied::Unparseable,
                        State::NoFile if i > 0 => Applied::Absent,
                        State::On(_) | State::Absent | State::NoFile => {
                            let mut v: Value = match fs::read_to_string(&file) {
                                Ok(text) => serde_json::from_str(&text)
                                    .with_context(|| format!("parse {}", file.display()))?,
                                Err(_) => Value::Object(Default::default()),
                            };
                            if json_set(&mut v, path, &off.value()) {
                                let text = format!("{}\n", serde_json::to_string_pretty(&v)?);
                                write_atomic(&file, &text)?;
                                Applied::Written(true)
                            } else {
                                Applied::Written(false)
                            }
                        }
                    };
                    out.push((knob.label(), file, applied));
                }
            }
            Knob::Yaml { file, key, off } => {
                let path = at(home, file);
                let applied = match fs::read_to_string(&path) {
                    Err(_) => {
                        let (text, _) = yaml_set("", key, *off);
                        write_atomic(&path, &text)?;
                        Applied::Written(true)
                    }
                    Ok(text) => match yaml_key(&text, key) {
                        YamlValue::Scalar(v) if v == off.to_string() => Applied::Written(false),
                        _ => {
                            let (new, changed) = yaml_set(&text, key, *off);
                            if changed {
                                write_atomic(&path, &new)?;
                            }
                            Applied::Written(changed)
                        }
                    },
                };
                out.push((knob.label(), path, applied));
            }
        }
    }
    Ok(out)
}

pub fn find(id: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.id == id)
}

/// The resolved home directory — shared by `cya agents` paths.
pub fn home_dir() -> Result<PathBuf> {
    home()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_set_creates_nested_and_is_idempotent() {
        let mut v: Value = serde_json::from_str(r#"{"a":{"b":1}}"#).unwrap();
        assert!(json_set(
            &mut v,
            &["attribution", "commit"],
            &Value::String(String::new())
        ));
        assert_eq!(v["attribution"]["commit"], "");
        assert!(!json_set(
            &mut v,
            &["attribution", "commit"],
            &Value::String(String::new())
        ));
        assert!(json_set(
            &mut v,
            &["includeCoAuthoredBy"],
            &Value::Bool(false)
        ));
        assert_eq!(v["a"]["b"], 1);
    }

    #[test]
    fn json_set_replaces_scalar_in_the_way() {
        let mut v: Value = serde_json::from_str(r#"{"attribution":false}"#).unwrap();
        json_set(
            &mut v,
            &["attribution", "commit"],
            &Value::String(String::new()),
        );
        assert_eq!(v["attribution"]["commit"], "");
    }

    #[test]
    fn yaml_key_reads_flat_values() {
        let text = "model: x\nattribute-author: false\n  nested: true\n# comment\n";
        assert!(matches!(
            yaml_key(text, "attribute-author"),
            YamlValue::Scalar(v) if v == "false"
        ));
        assert!(matches!(yaml_key(text, "nested"), YamlValue::Absent));
        assert!(matches!(yaml_key(text, "missing"), YamlValue::Absent));
    }

    #[test]
    fn yaml_set_replaces_and_appends() {
        let (out, changed) = yaml_set(
            "attribute-author: true\nother: 1\n",
            "attribute-author",
            false,
        );
        assert!(changed);
        assert!(out.contains("attribute-author: false\n"));
        assert!(out.contains("other: 1"));
        let (out, changed) = yaml_set("other: 1\n", "attribute-committer", false);
        assert!(changed);
        assert!(out.ends_with("attribute-committer: false\n"));
        let (_, changed) = yaml_set("attribute-author: false\n", "attribute-author", false);
        assert!(!changed);
    }

    #[test]
    fn registry_has_unique_ids_and_detect_paths() {
        let mut ids: Vec<_> = AGENTS.iter().map(|a| a.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), AGENTS.len());
        assert!(AGENTS.iter().any(|a| !a.knobs.is_empty()));
        for a in AGENTS {
            assert!(!a.detect.is_empty(), "{}", a.id);
        }
    }
}
