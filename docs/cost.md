# Operational cost

This document states the candidate's resource profile so cost review can
verify each billed operation against the provider's official sources.

## GitHub Actions (`sig-check.yml`)

The only metered service this repository introduces is one GitHub-hosted
runner job (`ubuntu-latest`) per attribution-relevant event.

| Quantity | Value | Source |
|---|---|---|
| Billing basis | Public repositories use **zero billed minutes** on GitHub-hosted runners; private repositories would consume the plan's included minutes first | GitHub Docs — *About billing for GitHub Actions*: <https://docs.github.com/en/billing/concepts/product-billing/github-actions> ("GitHub Actions usage is free for standard GitHub-hosted runners in public repositories") |
| Trigger volume | One job per `pull_request` or `merge_group` event, and per `push` event on the repository's default branch (other-branch pushes are skipped in seconds — their commits are scanned at PR time); bounded by human commit activity; no schedules, no matrix, single job | this workflow |
| `workflow_call` volume | Caller-defined — the workflow is also reusable; each calling repo's triggers determine its frequency (same per-run cost) | this workflow `on:` block |
| Per-run wall time | ~10 s (release asset present) or ~60–90 s (cold `cargo install --git` fallback — unmeasured estimate, until a `cya` release exists) | `cargo build --release` ≈ 40 s clean locally |
| Network per run, release path | One repo fetch (`fetch-depth: 0`, ≈ 1 MB git data at current size) + one release-asset download (≈ 5 MB) + optional policy fetch only if `CYA_POLICY_URL` is set (single HTTPS GET) | this workflow |
| Network per run, source fallback | Same repo fetch, plus the `cargo install --git` source fetch and crates.io index + dependency downloads — reduced to near-zero after the first run by the `~/.cargo` cache; eliminated entirely once a release exists | this workflow |
| Storage | No artifacts or deployments; one `actions/cache` entry for `~/.cargo` (tens of MB within the repo's cache quota) | this workflow |

Known cost trade-offs, all deliberate:

- `fetch-depth: 0` clones full history so `--range` scans can diff
  `before..after` on any push shape (force-push, new branch). The
  alternative — shallow fetch plus per-push deepen negotiation — saves
  kilobytes but adds a failure mode; at this repository's size the
  transfer is trivial.
- The source-build fallback exists only until the first release ships
  a `cya` binary; after that the workflow downloads the asset and the
  ~80 s build disappears.

## Local CLI (`cya`, `ag-apply`)

Single-shot processes: one `git log` read per scan, linear regex
matching per commit, no daemons, no polling, no retry loops. `ag-apply`
pages GitHub list endpoints at 100/page — the minimum request count the
API allows — and stops on the first empty page.
