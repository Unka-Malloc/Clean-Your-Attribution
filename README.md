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
| `cya-apply` binary | installs the workflow, three rulesets, and squash-only merge settings in every targeted repo | run by an operator locally |

All three resolve from the same source of truth: `policy/trailers.json`,
which is compiled into the binaries at build time.

## Build and use

```sh
cargo build --release --bins          # produces target/release/cya + cya-apply
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
`attribution scan` check on the default branch. Merges are squash-only with
the PR title as the sole commit-message source, so trailers in a dirty
branch cannot reach the default branch's history.

Tags are enforced differently: a tag push would run whatever workflow the
tagged commit carries, and commit-metadata rules are branch-scoped — so
the scan never runs on `refs/tags/*` and a third ruleset,
`clean-your-attribution-tags`, restricts tag creation, update and deletion to
repository administrators. That restriction always deploys `active` —
an `--enforcement evaluate` staging run must not silently reopen tag
writes while the workflow skips them; only `disabled` turns it off.

The workflow provisions the `cya` binary from this repository's release
assets for the runner's OS/arch, falling back to `cargo install --git`
until releases exist.

`cya-apply` applies all of that across organizations and accounts:

```sh
cya-apply --orgs ORG1,ORG2 --users OWNER --dry-run
cya-apply --orgs ORG1,ORG2 --users OWNER --enforcement evaluate
```

Credentials come from `GITHUB_TOKEN` if set, else `gitvault api`.

## Verify

```sh
cargo test
```

## Documentation

Entry point: `docs/README.md`.
