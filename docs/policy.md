# Attribution policy

`policy/trailers.json` is the single source of truth for what counts as
denied attribution. Every surface — the `cya` CLI, the `sig-check.yml`
workflow, and the rollout rulesets — resolves from it.

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `denyTrailerKeys` | string[] | Git trailer keys denied anywhere in the trailing trailer block, matched case-insensitively. Covers any current or future agent name — the key is the mechanism, not the identity. |
| `denyMessagePatterns` | object[] | Whole-line deny patterns applied to the entire message (`{id, flags, pattern, note}`), for signatures that carry no trailer key such as "🤖 Generated with …" footers. |
| `rulesetPattern` | string | RE2 regex embedded verbatim in the GitHub ruleset `commit_message_pattern` rule. Must stay in sync with `denyTrailerKeys`. |

## Resolution order

1. `--policy-url URL` / `CYA_POLICY_URL` (remote override — lets a fleet update rules without reinstalling),
2. `policy/trailers.json` compiled into the binaries via `include_str!` — file and binary cannot drift apart because there is one source of bytes.

`cargo test` and `cya policy --check` verify the file parses and that
`rulesetPattern` covers every denied trailer key.

## Trailer-block semantics

Only the final paragraph is treated as a trailer block, and only when every
line in it looks like `Key: value` or a wrapped continuation. A line like
`Co-authored-by: …` inside prose is body text, not attribution, and is left
alone — except when it also matches a `denyMessagePatterns` entry, which are
whole-line deny rules by design.

## Adding a denial

Prefer adding a trailer *key* over a pattern: keys deny the mechanism
regardless of the agent's display name. Patterns are for signatures that
have no key. Keep patterns conservative — they match whole lines anywhere
in the message and can false-positive on prose.
