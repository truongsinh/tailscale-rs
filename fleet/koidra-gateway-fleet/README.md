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
name (`File /oname=koidra-gateway-<sha>.exe`), then seeds **two** pointer files
and the launchers run whatever the pointers say:

- `current-koidra-gateway.txt` — the **authoritative** pointer; the in-process
  updater rewrites it (temp+rename) as new builds roll.
- `default-koidra-gateway.txt` — the installer-baked default (from `-DGW_SHA`);
  the updater **never** rewrites it, so it survives an emptied/half-written
  current pointer and always names the sha the installer actually bundled.

Launcher resolution: `override arg` → `current` → `default` → hardcoded literal
(last resort, only if **both** pointer files are missing). The Cargo underscore
name only ever exists as the pre-install staging artifact; nothing at runtime
runs a bare unversioned exe.

`<sha>` is the **binary build sha** (currently `06f9a3a`), overridable at build
time via `-DGW_SHA=<sha>` — it is the sha of the compiled `koidra_gateway` binary,
**not** the git HEAD of this kit (the kit and the binary version independently).
Because the installer bakes `default-koidra-gateway.txt` from `-DGW_SHA`, the
hardcoded literal fallback in `run-node2.cmd` / `run.sh` is a true last resort and
cannot silently drift the running build.

## Files

| File | Purpose |
|---|---|
| `installer.nsi` | NSIS installer source → `koidra-gateway-setup.exe`. Identity-preserving **two-phase** upgrade (see below). The **sole** migration vehicle for Windows. |
| `run-node2.cmd` | Windows channel launch shim **and SINGLE supervise-loop owner** (H1). `enabledelayedexpansion`; owns the crash-relaunch `:loop` + fast-exit backoff (so BOTH admin and non-admin recover from a process exit without a reboot); **guards an empty/whitespace `authkey.txt`** (diag + backoff, never `-k <empty>` crash-loop — H2); resolves the exe via `current-koidra-gateway.txt` → `default-koidra-gateway.txt` → literal; auth key read from `authkey.txt` on disk (never env); both channels `:22`. |
| `supervisor.vbs` | Windows non-admin boot **launcher** (not a loop — run-node2.cmd owns the loop, so there is exactly ONE loop per channel). **Master mode** (no args) spawns ONE detached self-looping `run-node2.cmd` per channel — independent processes, so one channel crash-looping never takes the other down. **Single mode** (`<channel> <port>`) detaches one channel's `run-node2.cmd`. |
| `start-primary.vbs` / `start-backup.vbs` | Detached one-shot launchers — relaunch a single NEW channel (a self-looping `run-node2.cmd`) over SSH without the loop becoming an SSH-session child (the 40-min-outage class). `Start-Process wscript.exe start-<chan>.vbs`. |
| `start-primary-old.vbs` / `start-backup-old.vbs` | Rollback launchers — detached relaunch of the OLD dir's channel (read from `old-install-dir.txt`). Non-admin rollback path; admin rollback is `schtasks /run /tn KoidraSSH-<chan>`. |
| `extract-authkey.ps1` | Parses the baked `-k tskey-auth-...` token out of the old `run-node.cmd` → `authkey.txt` (PS2.0-safe). |
| `stop-old-stack.ps1` | Ends old `KoidraSSH-*` task(s), kills `ssh_shell*` + old supervise loops, verifies zero remain (PS2.0-safe, `Get-WmiObject`). Takes an optional `<channel>` arg to stop **only** one channel — the installer uses it to swap backup-then-primary (H3) so both channels are never both down. |
| `check-console.ps1` | Best-effort over-SSH guard (H3): walks the parent-process chain; exits non-zero if launched under an `ssh_shell*` ancestor. The installer runs it on the UPGRADE path and refuses (unless `/CONSOLE`) — an over-SSH upgrade would kill its own transport mid-stop and brick the box. |
| `run.sh` | Linux (dev) channel launch shim. Resolves `node-<channel>.json` (dev keyfiles are `node-primary.json` / `node-backup.json`); resolves the binary via `current-koidra-gateway.txt` → `default-koidra-gateway.txt` → literal fallback; `AUTHKEY` from the unit env (aborts loudly if unset/empty via `${AUTHKEY:?}`); `#!/usr/bin/env bash`. |
| `koidra-gateway-primary.service` / `-backup.service` | Self-contained systemd units (dev). Inline `TS_HOSTNAME` + baked `AUTHKEY` (no drop-in override); ports 2222 / 2223; `WorkingDirectory=/home/sinh/koidra-gateway`; **no `ProtectHome`** (dir is under `/home`). |
| `migrate-to-koidra-gateway.ps1` / `.sh` | **SUPERSEDED — DO NOT RUN.** Kept for forensics only (rename-in-place / broken rollback — see their headers). |

## Two-phase install (Windows)

> **CONSOLE-ONLY.** Run the installer AT THE CONSOLE (physical / RDP), **never over
> the box's own koidra SSH channel.** The upgrade stops the old stack per-channel;
> if it stops the very channel hosting your session, the installer dies mid-run and
> bricks the box (no reboot allowed). The installer runs a **best-effort guard**
> (`check-console.ps1`): on the upgrade path it refuses to proceed if it detects an
> `ssh_shell*` ancestor. If you are certain it is a console session and the guard
> false-positives, re-run with `/CONSOLE`. The guard is best-effort — treat
> console-only as the real contract; the staged over-SSH runbook
> (`migration-plan.md §2`) is the vehicle for driving a swap from the *other*
> channel's session.

The installer never mutates the old layout in the same run that stands up the new
one. **COPY-and-stage beside the old dir**, so the old `koidra-ssh` install stays
a fully boot-capable rollback until externally validated.

**Phase 1 — install + start (this run):**

1. Detect the old layout **by directory**: `%PROGRAMDATA%\koidra-ssh` (admin,
   resolved via `ReadEnvStr`) or `%LOCALAPPDATA%\koidra-ssh` (non-admin). Refuse
   to install a per-user copy next to a live admin stack if not elevated.
2. **Identity:** COPY `primary.json` + `backup.json` byte-identical from the old
   dir → same `nodeId` + same `100.x` IP. Abort (never mint fresh identity) if the
   old jsons are missing **or 0-byte/corrupt** (a 0-byte identity means the box was
   already broken — refuse rather than propagate the EOF crash-loop).
3. **Auth key:** extract the baked `-k tskey-auth-...` token from the old
   `run-node.cmd` → `authkey.txt` beside the new launcher (read from disk at
   launch — never an env var; SYSTEM-task env is stale until reboot, and reboot is
   a hard NO).
4. Stage the new dir beside the old (`koidra-gateway` next to `koidra-ssh`): the
   versioned binary, launchers, `current-koidra-gateway.txt`,
   `default-koidra-gateway.txt`, `old-install-dir.txt`. (Staging is
   non-destructive — the old stack keeps running.)
5. **Per-channel swap (H3): backup first, then primary — never both down at once.**
   For each channel in turn (backup, then primary): stop **only** that channel's
   old task + loop + `ssh_shell*` and verify zero remain (`stop-old-stack.ps1
   <oldDir> <isAdmin> <channel>`), then start that channel's new persistence — so
   ≥1 channel is up at every instant. If a channel's stop can't confirm the old one
   down, the installer **aborts** (the other channel is untouched → box still
   reachable) rather than doubling up on one keyfile.
   - admin: `KoidraGateway-primary` / `-backup` SYSTEM tasks (onstart, HIGHEST,
     **both `:22`**), started per-channel.
   - non-admin: one Startup `KoidraGateway.lnk` → `supervisor.vbs` (master → both
     self-looping `run-node2.cmd` channels at boot); this run launches each channel
     via `start-<chan>.vbs` (detached).
6. **The old `KoidraSSH-*` tasks / `KoidraSSH.lnk` and the old dir are LEFT
   INTACT** as the boot fallback.

> **Crash recovery (H1/H2):** `run-node2.cmd` is now the single supervise-loop
> owner — it relaunches the binary on any exit with fast-exit backoff, so **both**
> the admin (SYSTEM task) and non-admin (supervisor) layouts recover without a
> reboot. It refuses to launch on an empty/whitespace `authkey.txt` (diag +
> backoff) instead of crash-looping on a bare `-k`.

> **Fresh / lab installs** (no old `koidra-ssh` dir) start both channels together
> (no old stack to protect) and are **not** blocked by the console guard, so the
> Azure Win10 VM lab can be driven over SSH. See **Fresh install & /REPROVISION**.

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

## Fresh install & `/REPROVISION` (net-new / lab boxes)

A box with **no** old `koidra-ssh` dir gets a fresh install (the Azure Win10 lab,
any net-new box). Supply the auth key one of two ways: stage `authkey.txt` beside
the `.nsi`, or set `KOIDRA_PRIMARY_AUTHKEY` in the environment. First launch
registers a new node.

**Re-run detection is CONTENT-based, not bare dir existence (C1/M4).** A genuine
prior install has a **non-empty** `primary.json` (the binary writes real state
once it registers):

| On disk | Mode |
|---|---|
| non-empty `primary.json` | `repair` (keep the registered identity) |
| `primary.json` absent **or 0-byte** | `fresh` (re-key, re-provision) |
| `/REPROVISION` flag | `reprovision` (see below) |

This closes the **reprovision-lockout**: a half-failed fresh install used to leave
a dir + bad `authkey.txt` + an unregistered json, and a bare-dir-existence "repair"
would silently keep all three and no-op the retry — locking the box out. Now a
0-byte/absent json routes to `fresh` (which re-requires + rewrites the key), and an
empty `authkey.txt` is treated as absent in `fresh`/`repair`.

**`/REPROVISION` — the operator escape hatch** for the remaining case: a
koidra-gateway dir with a **non-empty but unregistered** json plus a bad key (auto
mode would enter `repair` and keep the bad key). Re-run:

```
set KOIDRA_PRIMARY_AUTHKEY=tskey-auth-...      &  :: or stage authkey.txt beside the .nsi
koidra-gateway-setup.exe /REPROVISION
```

`/REPROVISION`:
- **overwrites** `authkey.txt` from the operator key (the fix for the ignored-key
  lockout),
- **wipes ONLY 0-byte / unregistered stubs** (`primary.json` / `backup.json`) so
  the binary re-inits — a **non-empty (registered) json is NEVER deleted**, so a
  real identity (100.x IP + node/machine keys) is preserved,
- rewrites the launcher and (re)starts the channels.

`/REPROVISION` applies only when there is no old `koidra-ssh` dir (a net-new/lab
box); if an old dir is present the identity-preserving **upgrade** path is used
instead.

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
# (run-node2.cmd, supervisor.vbs, start-{primary,backup}[-old].vbs,
#  extract-authkey.ps1, stop-old-stack.ps1, check-console.ps1) beside installer.nsi,
# then compile (installer files the exe under the versioned name and bakes the
# default pointer from -DGW_SHA):
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
