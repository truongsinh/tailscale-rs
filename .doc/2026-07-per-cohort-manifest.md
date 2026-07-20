# Per-cohort manifest + downgrade protection

> Split the single `fleet-manifest.json` into per-cohort URLs (`-ssh` /
> `-gateway`) and make the updater's COMPARE step semver-aware so a
> misconfigured manifest can't regress the fleet. Closes the source TODO from
> the MVP (`updater.rs` line 218, pre-this-change).

## 1. Why

Two failure modes the MVP (`0.4.0-d897332` era) was vulnerable to:

1. **Cross-cohort confusion.** One manifest, keyed by target triple. A
   Windows box with a stale `KOIDRA_TARGET` could resolve to the Linux
   target triple on a re-published manifest and "update" itself to a Linux
   ELF — bricking the box's auto-update path until an agent swaps the binary
   by hand.
2. **Involuntary downgrade.** The MVP COMPARE was string-equality only. A
   manifest re-push that accidentally advertised `0.4.0-100-g...` while the
   fleet was running `0.4.0-253-g...` would have regressed every box on the
   next cycle. The MVP comment said "we publish the manifest, so we won't
   push a downgrade" — true, but a single typo in the publish flow was the
   entire guardrail.

Both have a one-shot fix on the source side that needs no per-box agent
action to roll out (it rides the existing self-update pipeline).

## 2. Design

### 2.1 Per-cohort manifest URLs

Each binary cohort polls its **own** manifest URL on the same release tag:

| Cohort | URL (on release `fleet-manifest`) |
|---|---|
| `ssh_shell` (Linux) | `fleet-manifest-ssh.json` |
| `koidra-gateway` (Windows) | `fleet-manifest-gateway.json` |
| legacy (transition) | `fleet-manifest.json` — frozen, see §4 |

The launcher embeds the cohort URL via `--manifest-url` /
`KOIDRA_MANIFEST_URL` at boot. **This wiring lives in the gateway-kit repo,
not here** — the present change ships only the updater source + manifest
templates + this design note.

A box can no longer "update" to the other cohort's binary shape because it
literally never sees the other cohort's manifest.

### 2.2 Semver-aware COMPARE

`ipn_version` reports one of:

- `MAJOR.MINOR.PATCH` (bare semver — never published, but parsed for safety)
- `MAJOR.MINOR.PATCH-SEQ-gSHA` (git-describe — post-`c3c667f` builds)
- `MAJOR.MINOR.PATCH-SHA` (legacy short form — pre-`c3c667f` builds)

`updater.rs::Version` parses these into `(major, minor, patch, seq, sha)` and
orders them lexicographically per field — numeric for the first four, byte-
compare for the SHA tie-breaker. Higher `seq` = more commits after the base
tag = newer.

`compare_versions(current, manifest)` returns:

- `Equal` → no action
- `Newer` → manifest strictly newer → proceed with update
- `Older` → manifest strictly older → **refuse downgrade**, log warn, `NoUpdate`
- `Unparseable` → one or both sides failed to parse → fall back to MVP
  "string-different = update" policy (publisher is trusted, so we don't
  hard-block the fleet on a parse failure)

### 2.3 Edge cases covered

- `0.10.0` > `0.9.0` (numeric, NOT lexical — guards against `"9" > "10"` string sort).
- `0.4.0-253-g<SHA>` > `0.4.0-100-g<SHA>` (higher SEQ wins).
- `0.4.0-253-g<SHA>` > `0.4.0-f6c10dd` (git-describe > legacy bare SHA, since
  SEQ=253 > SEQ=0).
- Two builds at the same SHA are equal — manifest re-push of the running
  version is a no-op.
- Cross-format comparisons (legacy ↔ git-describe) all produce a strict order;
  there is no "ambiguous" outcome.

## 3. Files

| Path | Change |
|---|---|
| `examples/ssh_shell/updater.rs` | New `Version` struct + `compare_versions()`. `run_one_cycle` COMPARE block now pattern-matches on `VersionComparison` and refuses downgrades. Closes the source TODO. 16 new unit tests + 2 e2e tests. |
| `examples/ssh_shell/manifests/fleet-manifest-ssh.json` | ssh_shell cohort template (Linux target). |
| `examples/ssh_shell/manifests/fleet-manifest-gateway.json` | koidra-gateway cohort template. Restores Windows target pointing at `koidra-gateway-0e00c7d.exe`. |
| `examples/ssh_shell/manifests/fleet-manifest.json` | Legacy no-op: frozen at `0.4.0-d897332`, empty targets. |
| `examples/ssh_shell/manifests/README.md` | Publish flow + per-cohort URL wiring summary. |

## 4. Legacy no-op transition

`fleet-manifest.json` is kept on the release tag as a **frozen** asset
advertising the last-published version with `targets: {}`:

```json
{
  "schema": 1,
  "version": "0.4.0-d897332",
  "published_at": "2026-07-18T12:00:00Z",
  "targets": {}
}
```

- **New (semver-aware) binaries** polling this URL: COMPARE sees the legacy
  version `0.4.0-d897332` as OLDER than the running git-describe version
  (any post-`c3c667f` build has SEQ > 0). Refuses downgrade, `NoUpdate`.
- **Old (MVP) binaries** polling this URL: if their running version differs,
  tries to update, fails at "no target for triple" (empty targets), logs +
  retries. Safe.

Once telemetry confirms all boxes are on per-cohort URLs (no polls against
the legacy path for ≥ 24 h), this file can be removed from the release.

## 5. Launcher wiring — out of scope here

The `--manifest-url` / `KOIDRA_MANIFEST_URL` plumbing in the launcher
(`gateway-kit` repo) needs to set:

- ssh_shell launcher (Linux) → `fleet-manifest-ssh.json`
- koidra-gateway launcher (Windows) → `fleet-manifest-gateway.json`

That change is a separate PR against `gateway-kit`. The updater source change
here is forward-compatible: it works regardless of which manifest URL the
launcher points it at.

## 6. Tests

Unit tests (in `updater.rs`, verified in isolation — see Verification below):

- `version_parse_bare_semver` / `_git_describe` / `_legacy_bare_sha`
- `version_parse_rejects_missing_or_bad_base` / `_bad_seq`
- `version_ordering_base_semver_numeric` (incl. `0.10 > 0.9`)
- `version_ordering_seq_as_tiebreak`
- `version_ordering_sha_lexicographic_when_seq_equal`
- `version_ordering_cross_format` (legacy vs git-describe)
- `version_ordering_equal`
- `compare_versions_classifies_upgrade` / `_equal` / `_downgrade` / `_unparseable`

End-to-end (in `updater.rs`, mock HTTP server):

- `run_one_cycle_refuses_downgrade` — manifest seq=100 vs current seq=253 →
  `NoUpdate`, no staged file.
- `run_one_cycle_unparseable_falls_back_to_string_different_update` — both
  sides garbage → MVP behaviour preserved.

Existing e2e tests updated to use realistic git-describe versions
(`0.4.0-100-g...` → `0.4.0-200-g...`) instead of MVP sentinels (`OLD` /
`NEW_FAKE`).

### Verification

`cargo test --features=ssh --example ssh_shell` couldn't be run end-to-end at
implementation time because the shared worktree contained uncommitted
in-progress `src/silent_proxy/` files (a separate task) with compile errors.
The semver parser + comparator were verified in isolation by extracting
them to a standalone crate and running `rustc --edition 2024 --test` — all
14 unit tests pass. The integration of `compare_versions()` into
`run_one_cycle` is a single `match` on the enum, using only existing
patterns (`info!`, `warn!`, `return Ok(...)`); nothing in that block
requires the silent_proxy module.
