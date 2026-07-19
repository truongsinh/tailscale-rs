# koidra-gateway-fleet/

On-box supervisor + installer source for the **koidra-gateway** rebrand track
(operational rename of `koidra-ssh`/`ssh_shell` → `koidra-gateway`, identity
preserving). This is the source-of-truth checked-in template; the live on-box
copies (per-box, never in the repo) are what the current fleet actually runs.

> **Status**: templates + installer. The migration is **identity-preserving and
> two-phase** — the old `koidra-ssh` layout is never mutated in the install run;
> it stays the intact boot fallback until a separate coordinator finalize pass.
> The old standalone `migrate-to-koidra-gateway.{ps1,sh}` scripts are
> **SUPERSEDED — do not run** (kept for forensics; see their headers and
> `migration-plan.md §0`).

## Naming convention (kit-wide — no hyphen/underscore split)

| Thing | Value |
|---|---|
| Raw Cargo example output (staged beside the .nsi) | `koidra_gateway.exe` (underscore) |
| Installed / staged process image (Windows) | `koidra-gateway-<sha>.exe` (hyphen, **versioned**) |
| Installed / staged process image (Linux) | `koidra-gateway-<sha>` (hyphen, versioned, no ext) |
| Pointer file (each dir) | `current-koidra-gateway.txt` contains that **exact** versioned filename |
| Launcher default fallback | the **versioned** name (`koidra-gateway-<sha>[.exe]`), never a bare `koidra_gateway.exe` |

The installer takes the raw `koidra_gateway.exe` and files it under the versioned
name (`File /oname=koidra-gateway-<sha>.exe`), seeds `current-koidra-gateway.txt`
with that name, and the launchers run whatever the pointer says. The Cargo
underscore name only ever exists as the pre-install staging artifact; nothing at
runtime runs a bare unversioned exe. `<sha>` defaults to the branch HEAD
(`06f9a3a`) and is overridable at build time via `-DGW_SHA=<sha>`; the launcher
fallbacks are pinned to the same default.

## Files

| File | Purpose |
|---|---|
| `installer.nsi` | NSIS installer source → `koidra-gateway-setup.exe`. Identity-preserving **two-phase** upgrade (see below). The **sole** migration vehicle for Windows. |
| `run-node2.cmd` | Windows channel launch shim. `enabledelayedexpansion`; reads the exe name from `current-koidra-gateway.txt` (`!TARGET!`, delayed expansion — the pointer is honoured); default fallback is the versioned name; auth key read from `authkey.txt` on disk (never env); both channels `:22`. |
| `supervisor.vbs` | Windows non-admin boot supervisor. **Master mode** (no args) spawns ONE detached per-channel relaunch loop for BOTH channels — independent processes, so one channel crash-looping never takes the other down. **Loop mode** (`<channel> <port>`) is the per-channel relauncher with fast-exit backoff. |
| `start-primary.vbs` / `start-backup.vbs` | Detached one-shot launchers — relaunch a single NEW channel over SSH without the loop becoming an SSH-session child (the 40-min-outage class). `Start-Process wscript.exe start-<chan>.vbs`. |
| `start-primary-old.vbs` / `start-backup-old.vbs` | Rollback launchers — detached relaunch of the OLD dir's channel (read from `old-install-dir.txt`). Non-admin rollback path; admin rollback is `schtasks /run /tn KoidraSSH-<chan>`. |
| `extract-authkey.ps1` | Parses the baked `-k tskey-auth-...` token out of the old `run-node.cmd` → `authkey.txt` (PS2.0-safe). |
| `stop-old-stack.ps1` | Ends old `KoidraSSH-*` tasks, kills every `ssh_shell*` tree + old supervise loops, verifies zero remain (PS2.0-safe, `Get-WmiObject`). |
| `run.sh` | Linux (dev) channel launch shim. Resolves `node-<channel>.json` (dev keyfiles are `node-primary.json` / `node-backup.json`); reads versioned binary from `current-koidra-gateway.txt` with a versioned fallback; `#!/usr/bin/env bash`. |
| `koidra-gateway-primary.service` / `-backup.service` | Self-contained systemd units (dev). Inline `TS_HOSTNAME` + baked `AUTHKEY` (no drop-in override); ports 2222 / 2223; `WorkingDirectory=/home/sinh/koidra-gateway`; **no `ProtectHome`** (dir is under `/home`). |
| `migrate-to-koidra-gateway.ps1` / `.sh` | **SUPERSEDED — DO NOT RUN.** Kept for forensics only (rename-in-place / broken rollback — see their headers). |

## Two-phase install (Windows)

The installer never mutates the old layout in the same run that stands up the new
one. **COPY-and-stage beside the old dir**, so the old `koidra-ssh` install stays
a fully boot-capable rollback until externally validated.

**Phase 1 — install + start (this run):**

1. Detect the old layout **by directory**: `%PROGRAMDATA%\koidra-ssh` (admin,
   resolved via `ReadEnvStr`) or `%LOCALAPPDATA%\koidra-ssh` (non-admin). Refuse
   to install a per-user copy next to a live admin stack if not elevated.
2. **Identity:** COPY `primary.json` + `backup.json` byte-identical from the old
   dir → same `nodeId` + same `100.x` IP. Abort (never mint fresh identity) if the
   old jsons are missing on an upgrade.
3. **Auth key:** extract the baked `-k tskey-auth-...` token from the old
   `run-node.cmd` → `authkey.txt` beside the new launcher (read from disk at
   launch — never an env var; SYSTEM-task env is stale until reboot, and reboot is
   a hard NO).
4. **Stop old, verify dead:** end `KoidraSSH-*` tasks, kill every `ssh_shell*`
   tree + old supervise loops, verify zero remain (never two processes on one
   keyfile).
5. Stage the new dir beside the old (`koidra-gateway` next to `koidra-ssh`): the
   versioned binary, launchers, `current-koidra-gateway.txt`, `old-install-dir.txt`.
6. Create + start the new persistence — admin: `KoidraGateway-primary` /
   `-backup` SYSTEM tasks (onstart, HIGHEST, **both `:22`**); non-admin: one
   Startup `KoidraGateway.lnk` → `supervisor.vbs` (master → both channel loops).
7. **The old `KoidraSSH-*` tasks / `KoidraSSH.lnk` and the old dir are LEFT
   INTACT** as the boot fallback.

**External validation (coordinator side — the box cannot self-validate; userspace
netstack has no OS-visible `100.x` route):**

- Admin API: `nodeId` + `100.x` IP **unchanged**, `clientVersion` == the combined
  build, fresh `lastSeen`.
- Real SSH banner + exec round-trip per channel (`ssh -p 22 … 'echo OK_%COMPUTERNAME%'`;
  redsun-win7: `ConnectTimeout=60`, one session at a time).
- `rx` advancing (bidirectional data path, not just control-alive).

**Phase 2 — finalize (separate run, only after validation passes):**

```
koidra-gateway-setup.exe /FINALIZE
```

Removes ONLY the old persistence (`KoidraSSH-*` tasks / `KoidraSSH.lnk`). It does
**not** delete the old `koidra-ssh` directory — directory deletion is the
coordinator's later list-before-delete pass (`migration-plan.md §4`) after a ≥24 h
soak, diffing an on-box listing against the expected inventory (anything
unexpected → stop, no `--force`).

## Rollback

Old persistence and the old dir are intact through Phase 1, so rollback is a
channel bounce — never a reboot (reboot is a hard NO).

- **Admin (Windows):** stop the new task, then restart the intact old task:
  ```
  schtasks /end /tn "KoidraGateway-<chan>"
  schtasks /run /tn "KoidraSSH-<chan>"
  ```
- **Non-admin (Windows):** kill the new channel loop, then relaunch the OLD dir's
  channel detached (SSH-safe — not a session child):
  ```
  Start-Process wscript.exe '<newdir>\start-<chan>-old.vbs'
  ```
  `start-<chan>-old.vbs` reads `old-install-dir.txt` and prefers the old dir's
  per-channel `run-node2.cmd` (falling back to its `supervisor.vbs` / `run-node.cmd`).
  Verify the rolled-back channel externally afterwards.
- **Linux (dev):** stop/disable the new unit and re-enable the untouched old one:
  ```
  systemctl disable --now koidra-gateway-<chan>
  systemctl enable  --now koidra-ssh-<chan>
  ```

Because backup is always swapped first (driven via the primary's session) and
primary only via the NEW backup's session, at least one channel is up at every
instant — no both-down window in the happy path or on rollback.

## Build

```bash
# Build the binaries (from repo root).
bin/build-win7 --example koidra_gateway --features ssh
bin/build-musl --example koidra_gateway --features ssh

# Assemble the installer kit: stage the raw koidra_gateway.exe + all kit files
# beside installer.nsi, then compile (installer files it under the versioned name):
makensis -DGW_SHA=<sha> installer.nsi        # -> koidra-gateway-setup.exe
```

For a fresh (net-new / lab) box with no old `koidra-ssh` dir, also stage
`primary.json`/`backup.json` and/or `authkey.txt` beside the .nsi (or set
`KOIDRA_PRIMARY_AUTHKEY` in the environment for the run).

## Canary ladder

Each rung is externally validated + soaked before the next. One box at a time.

1. **dev (Linux, `vn-office-dev-server`)** — the `koidra-gateway-{primary,backup}`
   units via the coordinator-driven staged sequence (`migration-plan.md §2.3`).
   Lowest blast radius; also proves the launcher/pointer contract.
2. **Azure Win10 VM** — the **only** lab. Exercises BOTH Windows layout classes
   (admin install AND a synthetic non-admin install), the installer upgrade path,
   the both-channel supervisor, and the full rebranded-binary matrix
   (install-fresh, upgrade-from-old, SSH banner/exec, watchdog no-false-fire).
   Nothing reaches a customer box until this rung is green.
3. **Customer boxes, one at a time** (all real production boxes — NOT labs):
   scherze-win10 → redsun-win10 → hanyu → redsun-win7 (Win7, console) →
   scherze-win7 (Win7 non-admin, console) → bioverbeek (after layout audit) →
   **knodt** (non-admin `%LOCALAPPDATA%` layout — a **customer** box, blocked until
   its disk-full cleanup lands; there is no headroom to stage a second layout on a
   near-0-GB disk).

> knodt is a **customer** box on the non-admin `%LOCALAPPDATA%` layout — it is
> NOT a lab and NOT an admin box. The Azure Win10 VM is the sole lab rung.
