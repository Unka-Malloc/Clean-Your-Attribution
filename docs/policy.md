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

## Match semantics — full domain

A denied identity is matched **wherever it appears in complete form**:

- **Author and committer fields.** Agents sign commits directly —
  `copilot-swe-agent[bot]`, `factory-droid[bot]` and `devin-ai-integration[bot]`
  author commits with no trailer at all. `cya scan` reports them;
  `cya clean` rewrites the field to the repository's own `user.name` /
  `user.email`, so the human operator takes ownership.
- **Canonical `trailerKeys`** (`Co-authored-by`, `Generated-by`,
  `Assisted-by`) match loosely: the whole value may prefix-match a
  catalogue name (`Generated-by: Claude Code:model`).
- **Any other `Key:` line** matches only when its value is
  identity-shaped — `Name <addr>` carrying an email or a bare single-token
  login — or when the value is exactly a catalogue name. Prose values
  (`archive: OpenAI Codex under the bin dir`) are not attribution.
- **Bare `Name <addr>` lines and bare-address lines** in the body, plus
  `… Generated with <name>` badges; the bracket must carry an email so
  code placeholders like `<agent>` stay prose.
- **The subject line** (first non-empty line) is never a trailer: a
  conventional-commit `type: token` subject stays untouched.
- Indented lines never match. Wrapped continuation lines of a denied
  trailer are removed with it.
- Everything else survives verbatim: human co-authors on any address,
  sign-offs by humans, model ids that name no verified identity
  (`Generated-by: gpt-5`).

## Agent shapes — brute force in attribution positions only

Besides the verified catalogue, the `shape` block denies identities that
are *obviously* agent-shaped even when the tool is unlisted:

- `shape.names` (`[bot]`, `agent`) — substring of the display name in an
  attribution position: `dependabot[bot]`, `github-actions[bot]`,
  `Random Agent` as author/committer or in an identity trailer value.
- `shape.addressLocals` (`[bot]`, `agent`) — substring of the address
  local part in the same positions: `copilot-swe-agent`, `cursoragent`.

Shapes never fire in prose, in code, or on the subject line — only where
an identity legitimately stands: the two identity fields and
identity-shaped trailer values. The trade-off is deliberate: a human
literally named "Agent Smith" or an account like `agent.smith@corp.com`
in an attribution position is collateral the operator accepts in exchange
for catching every future unlisted agent.

Server side, the ruleset enforces a **safe subset** of the local
classifier: `commit_author_email_pattern` and `committer_email_pattern`
deny the verified addresses and agent-shaped locals in the identity
fields, and the `commit_message_pattern` rules below deny the same
identities in message lines — but deliberately narrower, so no valid
commit is ever rejected server-side that the CLI would keep.

## Ruleset generation

`Policy::ruleset_patterns()` derives the GitHub `commit_message_pattern`
RE2 rules from the catalogue at build time — the JSON carries no regex,
so the server-side policy cannot drift from the binaries. The generated
message rules encode the classifier's signature-position constraints;
no rule fires on an indented line, and `*-by` rules require a
non-empty line before the key, so a first-non-empty subject can never
match a noncanonical key:

- **`Key:` lines** — only `*-by` keys (the attribution-key shape) are
  denied. The canonical `trailerKeys` keep the local prefix semantics
  (`Co-Authored-By: Claude Sonnet 5 <…>`); any other `-by` key mirrors
  the local noncanonical gate exactly — an exact catalogue-name value
  (`X-Custom-by: Claude Code`) or an identity-shaped value
  (`Reviewed-by: Claude Code <jane@corp.com>`). Prose values never fire:
  `Reviewed-by: Copilot was discussed` and `archive:` lines stay, and
  exotic non-`-by` attribution keys stay a documented server-side gap
  the CLI still catches.
- **Bare identity lines** — `Name <email>` with a denied name or shape,
  or a bare denied address/login token.
- **Generated-with badges** — denied names anchor at the badge-label
  start, agent shapes match inside the label only (`[SomeTool](…/agent)`
  URLs cannot fire the shape rule).

The address-field rules need no position argument — author/committer is
always an identity position.

## Tag enforcement

Commit-metadata rules (`commit_message_pattern`, the two address rules)
are branch-scoped in GitHub's ruleset model, and a tag push would execute
whatever workflow the tagged commit carries — so `sig-check.yml` never
runs on `refs/tags/*`. `cya apply` instead installs
`clean-your-attribution-tags`, a tag-targeted ruleset that restricts tag
creation, update and deletion to repository administrators. Pointing a
tag at an unscanned commit then requires the same actor who could push
to the default branch directly.

The tag ruleset is fail-closed by construction: it always deploys
`active` — the `--enforcement evaluate` staging mode softens the branch
rulesets but must not silently reopen tag writes (only an explicit
`disabled` turns it off). It is also installed before the workflow
update, so an upgrade rollout that fails there preserves whichever older
protection was in place; on a first install a failure means nothing was
deployed, and `cya apply` reports the repo as not fully protected either
way — a partially enrolled target must be re-applied, never treated as
covered.

## Branch rollout: two declarations and reconciliation

`cya apply` installs a repo-wide set plus a branch-scoped set, each
explicitly named — nothing is scoped implicitly:

- **Repo-wide** (`--repos`, `--orgs`, `--users`): the `~ALL` deny
  ruleset, the `~ALL`-tags admin restriction, and squash-only merge
  settings.
- **`--install-refs owner/repo:branch`**: the scan workflow committed
  directly onto each named branch (or `--local PATH:branch` writes it
  into a worktree verified to be on the named branch, for the operator
  to commit and promote).
- **`--protect-refs owner/repo:branch`**: `clean-your-attribution-protected`
  requires a pull request on every named branch immediately, and
  `clean-your-attribution-check` requires the `attribution scan` check
  on each named branch that already carries the workflow file. A named
  branch without the file is *pending* — the check joins it on the next
  apply run once the file lands, never before: requiring a check no
  branch produces would deadlock the merge meant to carry the file in.

Reconciliation is explicit opt-in: a run creates and updates only, and
every tool-owned ruleset outside the declared set is *warned* about
(`stale — rerun with --prune`). With `--prune`, the declared set is the
whole story — each stale managed ruleset is deleted and the removal
printed: a `check` gate whose named branches no longer carry the file,
a `protected` set the operator stopped naming, and the superseded
pre-0.2.0 `clean-your-attribution-default` ruleset. A partial rerun —
a policy refresh naming no refs — can therefore never silently strip
gates it did not restate; only `includes_parents=false` repo-owned
rulesets are ever in scope.

## Resolution order

1. `--policy-url URL` / `CYA_POLICY_URL` (remote override — lets a fleet update rules without reinstalling),
2. `policy/trailers.json` compiled into the binaries via `include_str!` — file and binary cannot drift apart because there is one source of bytes.

**Preset floor.** Every source — remote override included — is validated
against the bundled catalogue before a single message is scanned: it may
add trailer keys, agents, names or addresses, but dropping any preset
element rejects the whole policy (`policy drops agent "claude" (preset
floor: additions allowed, removals not)`). A fleet policy can only ever
widen coverage, never silently shrink it.

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
