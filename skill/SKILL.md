---
name: clean-your-attribution
description: Attribution hygiene for every commit an agent touches — find and switch off each local agent's own attribution option at the source, verify an outgoing range with `cya`, and clean attribution that already landed in history. Use when about to commit or push, when a scan or push reports agent attribution, when auditing a machine's agents, or when a server-side ruleset refuses a push for signature lines.
---

# Clean Your Attribution — agent skill

One policy (`policy/trailers.json`), three enforcement surfaces, and
this skill: the *method* an agent follows even where the `cya` binary
is not installed. The order is fixed — **close the source first,
verify what remains, clean what already escaped.** Cleaning without
closing the source is a treadmill: every new commit re-pollutes.

## 1. Close the option at the source (preferred fix)

Every agent that can sign a commit carries an attribution option
somewhere in its own settings. Turning it off makes the whole cleanup
class disappear — this is always the first move, not a fallback.

```sh
cya agents            # every detected agent: installed? attribution on/off/no-switch?
cya agents off        # write the documented off-value into each one's settings
cya agents off cursor # …or just one
```

`cya agents` knows the per-agent knobs directly (Claude's
`includeCoAuthoredBy` + `attribution.commit`/`attribution.pr`, Command
Code's equivalents, Cursor's `attribution.attributeCommitsToAgent` /
`attributePRsToAgent`, Devin's `attribution`, Droid's
`includeCoAuthoredByDroid`, aider's `attribute-*` flags). Edits are
conservative: JSON parsed, off-keys set, key order preserved, a file
that fails to parse is reported — never clobbered.

**When the agent is not in cya's registry — the discovery method:**

1. Find its settings surface: `~/.<agent>/`, `~/.config/<agent>/`,
   `~/Library/Application Support/<agent>/`, repo-local
   `.<agent>/settings*.json`.
2. Grep settings keys for `attribution|coauthored|co-authored|trailer|
   signature|credit|generated.by|assistant.by` — the knob is always
   spelled in one of those families.
3. Check the agent's docs / changelog for the same vocabulary.
4. Confirm by making a test commit in a scratch repo and inspecting
   `git log -1 --format=full`.
5. **Report the new knob** so it lands in `policy`/the `cya agents`
   registry — a discovered switch is a policy contribution, not a
   private workaround.

**Agents with no local switch** (their bots sign server-side —
`devin-ai-integration[bot]`, `copilot-swe-agent[bot]` and friends):
the option does not exist; do not hunt for it. Their attribution can
only be denied at the scan/ruleset boundary — keep them in the scan
step and rely on the server-side surfaces to refuse them.

## 2. Verify before anything leaves

```sh
cya scan                      # commits you are about to push (@{upstream}..HEAD)
cya scan --range main..HEAD   # an explicit range
echo "$MSG" | cya scan --stdin  # a message before it becomes a commit
```

`cya hook` installs `commit-msg` + `pre-push` into the repo — the
commit-msg hook strips denied trailers while the message is still
being written, which is the cleanest local point of all (the
attribution never enters an object). Prefer hooks over remembering
to scan.

## 3. Clean what already escaped

Attribution can only be removed **before history is public** — a
commit's message is content-addressed, so cleaning rewrites objects
and produces new SHAs. That is safe on an unpublished range, never
on shared history.

```sh
cya clean   # rewrite the outgoing range: denied trailers stripped,
            # bot author/committer fields reassigned to the repo's
            # own user.name/user.email — the human takes ownership
```

Then push again. If the server **refused** your push (the ruleset's
`commit_message_pattern` hit), the remediation is the same: clean
locally, re-push — never force-push a cleaned rewrite over history
others hold.

**Pull requests:** a squash-only merge uses the PR title as the sole
commit-message source — a dirty branch's commit messages never reach
the default branch. The fix is editing the PR title/body, not
rewriting the branch. If the `attribution scan` check is red, clean
the title and re-run; a ruleset refusal at merge time means the
edited merge message itself still carries a denied line.

## 4. When per-time cleaning is the only option

A server-side signer, a shared machine you cannot reconfigure, or an
agent whose knob does not exist leaves one path: scrub each message
by hand, every time. The rules, exactly as the policy applies them:

- Remove only **whole-line** denial forms: `Co-authored-by:` /
  `Generated-by:` / `Assisted-by:` trailers whose name or address hits
  the catalogue, `… Generated with <agent>` badges, bare
  `AgentName <agent@addr>` lines, agent signature blocks, and
  agent-bot `author`/`committer` fields (reassign to the repo's own
  identity).
- **Preserve**: human `Co-authored-by` on any address, `Signed-off-by`,
  prose mentions of an agent, indented quoted lines, the subject line
  (never a trailer), and names that merely resemble an agent — a
  human named Jules, Claude or Devin keeps their credit.
- After rewriting, re-verify with `cya scan` — the policy is a
  precise-match catalogue (`cya policy` shows it); never hand-write a
  broader pattern than it defines.

## Boundaries

- This skill governs **attribution hygiene**, nothing else — it does
  not review code, privacy or cost.
- Server-side surfaces (rulesets + `sig-check.yml`) can only refuse,
  never clean — cleaning always happens here, locally, before push.
- The catalogue denies *verified* agent identities only. When in
  doubt whether an identity is an agent, treat it as human and report
  it for the `unverified` list instead of scrubbing a person.
