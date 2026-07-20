# Fleet manifests — per-cohort templates

These three JSON files are the **canonical templates** for the assets uploaded to
the `fleet-manifest` GitHub release on `truongsinh/tailscale-rs`. Each binary
cohort in the fleet polls its own manifest URL; the launcher embeds the cohort
URL via `--manifest-url` / `KOIDRA_MANIFEST_URL` (see `.doc/2026-07-per-cohort-manifest.md`
for the full design).

| File | Cohort | Polled by |
|---|---|---|
| `fleet-manifest-ssh.json` | ssh_shell (Linux today) | `ssh_shell` binaries launched by `systemd` on Linux boxes |
| `fleet-manifest-gateway.json` | koidra-gateway (Windows) | `koidra-gateway.exe` launched by `supervisor.vbs` / Scheduled Task on Windows boxes |
| `fleet-manifest.json` | **legacy no-op** | Old binaries that haven't yet been migrated to per-cohort URLs |

## Publish flow (per roll)

1. **Build** the binary for each target (Linux musl + Windows gnu / win7).
   Record the `sha256` + byte `size` and the git-describe version
   (`<MAJOR>.<MINOR>.<PATCH>-<SEQ>-g<SHA>`).
2. **Upload** the binaries to the GitHub release tagged `fleet-manifest`:
   ```bash
   gh release upload fleet-manifest ssh_shell-<SHA>-linux-musl koidra-gateway-<SHA>.exe --clobber
   ```
3. **Copy** the matching template file from this dir; fill in the real `version`,
   `url`, `sha256`, `size`, and `published_at` fields.
4. **Upload** the filled-in manifest to the release:
   ```bash
   gh release upload fleet-manifest fleet-manifest-ssh.json fleet-manifest-gateway.json --clobber
   ```
5. The fleet polls every 600 s ± 120 s; no per-box agent action is needed.

## Legacy no-op (`fleet-manifest.json`)

During the per-cohort migration, the legacy URL stays valid but advertises the
**last-published version** (`0.4.0-d897332` at time of writing) with `targets: {}`.
Any box still polling this URL:

- **New updater (semver-aware)**: sees `manifest.version` as OLDER than its current
  `0.4.0-<SEQ>-g<SHA>` (post-`c3c667f` builds all have SEQ > 0) → refuses
  downgrade → `NoUpdate`.
- **Old updater (string-equal MVP)**: if the running version differs, tries to
  update → fails at "no target for triple" (empty `targets`) → logs + retries
  next cycle. Safe.

Once all boxes are confirmed on per-cohort URLs, this file can be removed from
the release.

## Per-cohort URL choice

The launcher's `--manifest-url` / `KOIDRA_MANIFEST_URL` arg selects the cohort
at boot:

- **Linux ssh_shell** (`run-node.service` or equivalent):
  `KOIDRA_MANIFEST_URL=https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/fleet-manifest-ssh.json`
- **Windows koidra-gateway** (`supervisor.vbs` / Scheduled Task):
  `KOIDRA_MANIFEST_URL=https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/fleet-manifest-gateway.json`

This wiring lives in the **gateway-kit** repo (launcher side), not here.

## Why split

Single manifest → a box polling it could "update" to the other cohort's binary
shape (e.g. Linux `ssh_shell` "updating" to a Windows `koidra-gateway.exe`),
because the MVP only checked version strings, not target-triple compatibility.
Splitting the manifest per cohort makes this category error impossible.

The new semver-aware COMPARE step (see `updater.rs`) closes the related
"misconfigured manifest can downgrade the fleet" gap.
