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
| Per-run wall time | ~5 s when the version-keyed binary cache hits (resolve + scan only); ~60–90 s on a cold run — every version change pays one compile per runner image (`cargo build --release` ≈ 40 s clean locally, plus dependency builds on a cold registry cache) | this workflow; local build measured |
| Network per run, cached | One repo fetch (`fetch-depth: 0`, ≈ 1 MB git data at current size) + one sparse-index line for version resolution (bytes) + one binary cache restore (≈ 2 MB) + optional policy fetch only if `CYA_POLICY_URL` is set (single HTTPS GET) | this workflow |
| Network per run, cold | The cached traffic plus the `.crate` and dependency downloads `cargo install` performs — the `~/.cargo` registry cache makes repeat cold builds near-zero on the same version | this workflow |
| Storage | No artifacts or deployments; two `actions/cache` entries — the `~/.cargo` registry and one `~/.cargo/bin/cya` per (version, OS, arch) — tens of MB within the repo's cache quota | this workflow |

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
  per release.

## CI (`ci.yml`)

One `verify` job per push to `main` and per pull request: toolchain
install plus `fmt`/`clippy`/`test`, ~2–4 min on GitHub-hosted
`ubuntu-latest` — **zero billed minutes** while the repository is
public (same billing source as above). A `concurrency` group cancels
superseded runs on the same ref; no schedules, no matrices, no
credentials.

## Release

Releases are manual: bump `Cargo.toml`, `cargo publish` locally, tag
`v<version>` and push the tag. Network is the crates.io sparse-index
check plus one `.crate` upload (≈ 45 KiB compressed, `cargo package`
measured) and a kilobyte-scale tag push; no runner minutes are spent.

Trust basis, stated plainly: the `.crate` is packaged by `cargo publish`
from the operator's local checkout under their crates.io credentials —
there is no build attestation or provenance record beyond the tag
pointing at the same commit. `sig-check.yml` consumers install the
binary through `cargo install clean-your-attribution@<resolved> --locked`:
the crates.io sparse index chooses the release at run time (maximum
stable non-yanked version, pinned and logged per run), the shipped
`Cargo.lock` pins every dependency of what they build, and the binary
cache is keyed on that resolved version so the run output always names
what scanned a commit.

## Local CLI (`cya`)

Single-shot processes: one `git log` read per scan, linear regex
matching per commit, no daemons, no polling, no retry loops. `cya apply`
pages GitHub list endpoints at 100/page — the minimum request count the
API allows — and stops on the first empty page.
