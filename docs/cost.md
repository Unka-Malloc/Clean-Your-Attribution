# Operational cost

This document states the candidate's resource profile so cost review can
verify each billed operation against the provider's official sources.

## GitHub Actions (`sig-check.yml`)

The only metered service this repository introduces is one GitHub-hosted
runner job (`ubuntu-latest`) per attribution-relevant event.

| Quantity | Value | Source |
|---|---|---|
| Billing basis | Public repositories use **zero billed minutes** on GitHub-hosted runners; private repositories would consume the plan's included minutes first | GitHub Docs — *About billing for GitHub Actions*: <https://docs.github.com/en/billing/concepts/product-billing/github-actions> ("GitHub Actions usage is free for standard GitHub-hosted runners in public repositories") |
| Trigger volume | One job per `pull_request` or `merge_group` event, and per `push` event on the repository's default branch (other-branch pushes and tag pushes are skipped in seconds — branches are covered at PR time and tags are gated by a tag ruleset, not a workflow); bounded by human commit activity; no schedules, no matrix, single job | this workflow |
| `workflow_call` volume | Caller-defined — the workflow is also reusable; each calling repo's triggers determine its frequency (same per-run cost) | this workflow `on:` block |
| Per-run wall time | ~5 s when the version-keyed binary cache hits (resolve + scan only); ~60–90 s on a cold run — every version change pays one compile per runner image (`cargo build --release` ≈ 40 s clean locally, plus dependency builds on a cold registry cache). Unresolved-index path (this repository's own pre-publication runs only): no binary cache, one cold HEAD compile per run — consumer runs fail closed in the resolve step instead, before any cache restore | this workflow; local build measured |
| Network per run, cached | One repo fetch (`fetch-depth: 0`, ≈ 1 MB git data at current size) + one sparse-index line for version resolution (bytes) + one binary cache restore (≈ 2 MB) + optional policy fetch only if `CYA_POLICY_URL` is set — exactly one fetch per scan invocation: a single HTTPS GET retried up to 3 times (5 s connect, 20 s per-attempt, 2 s retry delay, 45 s total retry budget — worst case ≈ 65 s including the final attempt) | this workflow |
| Network per run, cold | The cached traffic plus the `.crate` and dependency downloads `cargo install` performs — the `~/.cargo` registry cache makes repeat cold builds near-zero on the same version | this workflow |
| Storage | No artifacts or deployments; two `actions/cache` entries **per (version, OS, arch)** — one `~/.cargo/bin/cya` binary (≈ 2 MB) plus a full `~/.cargo` registry + git snapshot (tens of MB). Cache entries are immutable and live under a **10 GB per-repository limit with 7-day retention**: entries a repository has not touched in 7 days are removed, and writes beyond the limit evict the least-recently-used entries — so the per-version snapshots this change adds cost eviction pressure and at most one extra ~60–90 s cold compile, **not a bill**. A run the scan refuses still saves both entries — saves are skipped only for a failed provision or when no resolved version exists to key an entry under. Branch/PR cache scoping can multiply entries within the repo's quota | this workflow; GitHub Docs — *Dependency caching reference* (10 GB limit, 7-day retention, LRU eviction) |

Known cost trade-offs, all deliberate:

- `fetch-depth: 0` clones full history so `--range` scans can diff
  `before..after` on any push shape (force-push, new branch). The
  alternative — shallow fetch plus per-push deepen negotiation — saves
  kilobytes but adds a failure mode; at this repository's size the
  transfer is trivial.
- Provisioning compiles the crate on the runner: a registry-resolved,
  version-pinned, lockfile-pinned artifact at the cost of ~60–90 s on a
  cold cache — the published-binary alternative would need a build
  matrix this repository deliberately does not operate. The
  version-keyed binary cache bounds the recurring cost to one compile
  per release — restore and save are separate steps so a run the scan
  refuses still banks the binary it built. The registry snapshot is
  keyed the same way: `--locked` pins the dependency set to the resolved
  version, so the version is the content key — and cache entries being
  immutable means a versionless key could never refresh after its first
  save. The trade is a fresh tens-of-MB registry snapshot per release
  (plus the per-version binary), retained until the 7-day/LRU eviction —
  the accepted storage cost of exact per-version dependency caching.

## CI (`ci.yml`)

One `verify` job per push to `main` and per pull request: toolchain
install plus `fmt`/`clippy`/`test`, ~2–4 min on GitHub-hosted
`ubuntu-latest` — **zero billed minutes** while the repository is
public (same billing source as above). A `concurrency` group cancels
superseded runs on the same ref; no schedules, no matrices, no
credentials.

## Release

Releases run through `publish.yml`: bump `Cargo.toml`, tag `v<version>`,
push the tag, and publish the GitHub release — the `release.published`
event is the only trigger. One `ubuntu-latest` job then packages the
crate and uploads it, so a release spends one job's minutes — **zero
billed minutes** while the repository is public (same billing source as
above) — plus the crates.io sparse-index probe and one `.crate` upload
(≈ 45 KiB compressed, `cargo package` measured). The job is queued per
release (`publish-<release id>`), so distinct pending releases never
evict one another, and an upload whose version the index already
carries — a hand-published name claim, a retried run — exits as a green
skip without re-uploading.

The job holds no stored credential: it exchanges a GitHub OIDC token for
a short-lived crates.io token through crates.io Trusted Publishing, and
that exchange is bound to this workflow file, this repository, and the
`release` GitHub environment. The environment must carry a
required-reviewers rule — a documented provisioning precondition —
and GitHub itself enforces it before this job starts. The job's own
token cannot read protection rules, so it instead refuses to run
unless this run's record shows an approved review naming the `release`
environment: a missing or unprotected environment lets the job start
with none on record and it fails closed before any authentication
(the record is run-scoped — a 'Re-run failed jobs' attempt inherits
the earlier attempt's approved review),
as does a release tag that does not equal `v<Cargo.toml version>`.

Trust basis, stated plainly: the `.crate` is packaged by a GitHub-hosted
runner from the tagged commit under an environment-scoped OIDC identity;
the approval decision and the OIDC token exchange are the provenance
record, and there is no additional build attestation beyond the tag
pointing at the same commit. `sig-check.yml` consumers install the
binary through `cargo install clean-your-attribution@<resolved> --locked`:
the crates.io sparse index chooses the release at run time (maximum
stable non-yanked version, pinned and logged per run), the shipped
`Cargo.lock` pins every dependency of what they build, and the binary
cache is keyed on that resolved version so the run output always names
what scanned a commit.

## Local CLI (`cya`)

Single-shot processes: one `git log` read per scan, linear regex
matching per commit, no daemons, no polling. The optional policy fetch
runs at most once per invocation: a single GET with up to 3 retries
(5 s connect, 20 s per-attempt, 2 s delay, 45 s total retry budget —
worst case ≈ 65 s for the one fetch, not a loop); everything else
runs once. `cya apply`
pages GitHub list endpoints at 100/page — the minimum request count the
API allows — and stops on the first empty page. A dead-gate probe costs
one ruleset-detail GET plus one read per literal scoped branch, issued
only for stale `-check`/`-protected` rows that are not already
`disabled` — an already-disarmed gate is reported without any write or
per-branch reads.
