# clean-your-attribution

Clean Your Attribution. One attribution policy, three enforcement
surfaces, one local switch. `policy/trailers.json` is a precise-match
catalogue of *verified* official agent identities (display names +
attribution addresses, each with a verification pointer): a commit line
is denied only when it claims one of those identities. Human co-authors —
including names that merely resemble an agent or squatted accounts — are
preserved.

State: **initial development**. CLI and check workflow are implemented and
tested; the rollout tool builds, but the fleet has not been applied yet.

## The three surfaces

| Surface | What it does | Where it runs |
| --- | --- | --- |
| `cya` binary | scans or rewrites commit messages, stripping denied trailers; installs repo hooks; switches local agents' own attribution options off | any machine — yours or a collaborator's, a single static binary |
| `sig-check.yml` workflow | scans the PR/merge-group commit range, default-branch push ranges, plus PR title and body | GitHub Actions, referenced by repo rulesets as a required check |
| `cya apply` | installs the deny + tag rulesets and squash-only merge settings on every named repo; the scan workflow and merge-gate rulesets only on explicitly named `(repo, branch)` pairs — remote or a local checkout | run by an operator locally |

All three resolve from the same source of truth: `policy/trailers.json`,
which is compiled into the binaries at build time.

## Build and use

```sh
cargo build --release --bins          # produces target/release/cya
cargo install --path . --bin cya      # or install it

cya scan                              # scan the commits you are about to push
cya scan --range main..HEAD           # or an explicit range
cya clean                             # rewrite the outgoing range, trailers stripped
cya hook                              # install commit-msg + pre-push hooks
cya strip-file .git/COMMIT_EDITMSG    # what the commit-msg hook runs
cya policy                            # show the effective policy
cya agents                            # which agents are present, attribution on or off
cya agents off                        # switch every agent's own attribution off
cya agents off cursor                 # …or just one
```

`scan` defaults to `@{upstream}..HEAD`, falling back to `origin/HEAD..HEAD`.
`--stdin` checks a message piped in; `--pre-push` parses git's pre-push stdin.

`cya hook` installs into `.git/hooks/` on a vanilla machine. When a global
`core.hooksPath` is in effect (e.g. a dispatcher that chains repo hooks), it
installs the repo-local `.githooks/` hooks instead.

## Agent switches

The cleanest attribution is the one never emitted. `cya agents` scans the
machine for installed agents and reports each one's attribution option;
`cya agents off` writes the documented off-value into every agent's own
settings (Claude's `includeCoAuthoredBy`, Cursor's
`attribution.attributeCommitsToAgent`, Droid's
`includeCoAuthoredByDroid`, Devin's `attribution`, Command Code's
`includeCoAuthoredBy`, aider's `attribute-*` flags, …). Agents with no
local switch — their bots sign server-side — are reported as such; the
policy surfaces above are what denies them.

Edits are conservative: JSON files are parsed, the off-keys set, and the
file rewritten with key order preserved; a file that fails to parse is
reported, never clobbered. Missing config files are created only when
the agent itself is present.

## Server-side enforcement

`.github/workflows/sig-check.yml` has `pull_request`, `merge_group`, `push`
and `workflow_call` triggers. A consumer repository installs it once under
`.github/workflows/clean-your-attribution.yml`; the rulesets then refuse pushes
whose commit messages match the deny pattern and require the workflow's
`attribution scan` check on each protected branch the operator names.
Merges are squash-only with
the PR title as the sole commit-message source, so trailers in a dirty
branch cannot reach the default branch's history.

Tags are enforced differently: a tag push would run whatever workflow the
tagged commit carries, and commit-metadata rules are branch-scoped — so
the scan never runs on `refs/tags/*` and a third ruleset,
`clean-your-attribution-tags`, restricts tag creation, update and deletion to
repository administrators. That restriction always deploys `active` —
an `--enforcement evaluate` staging run must not silently reopen tag
writes while the workflow skips them; only `disabled` turns it off.

The workflow provisions the `cya` binary from the published crates.io
package — the maximum stable (non-yanked) version the sparse index
resolves is pinned and logged per run, the build is `--locked`, and the
compiled binary is cached per version. A failed registry install falls
back to a tag-pinned `cargo install --git`. An unresolvable index
(nothing published yet, or an outage) builds the repository HEAD —
but only in this repository's own pre-publication runs; a consumer
repository's run fails closed rather than float off its pin.

`cya apply` rolls all of that out across organizations and accounts:

```sh
cya apply --orgs ORG1,ORG2 --users OWNER --dry-run
cya apply --orgs ORG1,ORG2 --users OWNER --enforcement evaluate
```

The workflow file is the one object that lives inside a branch, so it
only goes where you explicitly name it — `--install-refs` takes
`owner/repo:branch` pairs and direct-commits the file onto each named
branch, nothing else:

```sh
cya apply --repos owner/repo --install-refs owner/repo:nightly
```

The tool never creates branches or pull requests and never falls back to
a different ref: a target that refuses the write fails the run, and
getting the file into a protected branch — promotion PRs, channel
trains — is the operator's own pipeline.

Which branches merges are gated on is a second explicit declaration —
`--protect-refs` takes the same `owner/repo:branch` pairs:

```sh
cya apply --repos owner/repo \
  --install-refs owner/repo:nightly \
  --protect-refs owner/repo:release,owner/repo:stable
```

For a promotion-model repo the file enters locally instead:
`--local PATH:branch` verifies the checkout is on the named branch (it
never switches branches) and writes the file into the worktree for you to
commit and promote yourself:

```sh
cya apply --repos owner/repo \
  --local path/to/checkout:nightly \
  --protect-refs owner/repo:release,owner/repo:stable
```

Every named branch gets the pull_request gate immediately. The required
`attribution scan` check joins each branch only once the workflow file
exists there — a `pull_request` event runs the base branch's copy, so
requiring it where no file exists would deadlock the very merge meant to
carry the file in. While no named branch carries the file yet, the check
ruleset is installed `disabled` — a live one would be that same
deadlock — and the next apply run activates it once a branch can produce
the check. Branches still waiting are reported pending: land the file
through your normal path and rerun `cya apply`. Repos named by either
flag join the rollout automatically; a repo with neither gets the
deny/tag rulesets and merge settings only.

A run repairs only what it can prove, and never weakens a live gate:
the superseded `clean-your-attribution-default` ruleset is deleted
under `--prune`, or without it only while the run installs an `active`
deny successor; a check ruleset whose scoped branches can no longer
produce the check is a deadlock — PUT `disabled` at once, never
deleted without `--prune`. Everything else stale (a `-protected` or
`-check` gate a run no longer names while it still works) keeps
enforcing, is reported `stale`, counted in the footer and surfaced as
exit code 3 until `--prune` deletes it — so a partial rerun can never
silently strip gates. Exit codes: `0` clean, `1` repo failure(s),
`3` undeclared rulesets left, `2` usage/pre-flight error.

Credentials come from `GITHUB_TOKEN` if set, else `gh api` (any `gh`
with GitHub API access — the GitHub CLI or a compatible shim).

## Verify

```sh
cargo test
```

## Documentation

Entry point: `docs/README.md`.
