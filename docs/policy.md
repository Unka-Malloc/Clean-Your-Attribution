# Attribution policy

`policy/trailers.json` is the single source of truth for what counts as
denied attribution. Every surface — the `cya` CLI, the `sig-check.yml`
workflow, and the rollout rulesets — resolves from it.

The policy is a **precise-match catalogue of verified official agent
identities**, not a shape rule: a line is denied only when it claims one of
the listed identities. Human co-authors are preserved — including people
named Jules, Claude or Devin, and squatted accounts like `github.com/jules`
or `github.com/factory-droid` that merely *look* like the agent's name.

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `trailerKeys` | string[] | Trailer keys inspected for agent attribution (`Co-authored-by`, `Generated-by`, `Assisted-by`), matched case-insensitively. A matching key alone does **not** deny — the trailer's name or address must hit an agent entry. |
| `agents[]` | object[] | Verified identities: `{id, display, verify, names, addresses}`. `verify` points at the evidence (GitHub account/app and id, or documented attribution address) so each entry can be audited. |
| `agents[].names` | string[] | Display names denied in name position. Prefix-matched on a non-alphanumeric boundary and case-insensitive, so `Claude Code:claude-sonnet-4-6` matches `Claude Code`. Single-word human-plausible names (Jules, Claude, Devin) are deliberately **absent** — those identities deny by address instead. |
| `agents[].addresses` | string[] | Verified attribution emails. `users.noreply.github.com` entries match on the login local part, so any `<id>+<login>` variant of the same account is covered. |
| `unverified[]` | object[] | Transparency list of identities seen in the wild but not yet verified — **not** denied. Includes real humans who must never be added. |

## Match semantics

- `Key: Name <addr>` trailer lines deny when `name` or `addr` hits an agent
  entry. `Generated-by:` / `Assisted-by:` values without `<>` match by name.
- `… Generated with <name>` footer lines deny when the badge text names an
  agent entry.
- Indented lines never match: a body quoting a trailer as an example keeps
  it. Wrapped continuation lines of a denied trailer are removed with it.
- Everything else survives verbatim: `Signed-off-by`, `Reviewed-by`, human
  co-authors on any address, model ids that name no verified identity
  (`Generated-by: gpt-5`).

## Ruleset generation

`Policy::ruleset_patterns()` derives the GitHub `commit_message_pattern`
RE2 rules from the catalogue at build time — one name rule, one address
rule (noreply logins with optional `<id>+` prefix plus exact vendor
addresses), one generated-with badge rule. The JSON carries no regex, so
the server-side policy cannot drift from the binaries.

## Resolution order

1. `--policy-url URL` / `CYA_POLICY_URL` (remote override — lets a fleet update rules without reinstalling),
2. `policy/trailers.json` compiled into the binaries via `include_str!` — file and binary cannot drift apart because there is one source of bytes.

`cargo test` covers the match semantics; `cya policy --check` verifies the
file parses, every agent carries a verify reference, and the generated
ruleset patterns compile.

## Adding an identity

Verify the account first (`GET /users/<login>` — check id and type; bare
`User` logins with default avatars are usually squatters, the real agent
is the `[bot]` variant or a documented vendor address). Add names and
addresses plus the `verify` pointer. If in doubt, park it in `unverified`
instead — a missed agent is recoverable, a false denial rewrites a human's
attribution.
