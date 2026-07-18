# Fleet self-update pipeline (ssh_shell)

> In-binary rustls HTTP pull of a versioned manifest; atomic self-swap via the
> existing supervisor's 5 s relaunch; health-gated rollback. Zero agent tokens
> per fleet roll after first deploy. Folds with the P1 off-tailnet watchdog on
> a shared self-restart primitive.

## 1. Architecture

```
                       GitHub release tag `fleet-manifest`
                       (force-updated per roll; immutable URL)
                              │
                              │  GET manifest.json (rustls, TLS 1.2+)
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │ ssh_shell (in-process updater task, every 600 s ± 120 s) │
  │                                                          │
  │  fetch → compare ipn_version → download → sha256 →       │
  │  write current-ssh-shell.txt (temp+rename) → exit clean  │
  └──────────────────────────────────────────────────────────┘
                              │
                              ▼  supervisor sees clean exit, relaunches within 5 s
  ┌──────────────────────────────────────────────────────────┐
  │ run-node.cmd / supervisor.vbs / schtasks / systemd       │
  │                                                          │
  │  read current-ssh-shell.txt → launch that exe            │
  │  health-gate: track fast-exits, revert to previous on 2× │
  └──────────────────────────────────────────────────────────┘
```

Why this shape:
- the **TLS 1.2 ceiling on Win7** only blocks .NET (`WebClient`/`Invoke-WebRequest`); ssh_shell uses rustls, which does TLS 1.3 on Win7. The pull that's impossible from PowerShell works from inside the binary.
- the **running-exe lock** is sidestepped by never overwriting the running file: the updater writes a new filename and the supervisor picks it up on next relaunch.
- **`supervisor.vbs` is already a 5 s relauncher**; we add one indirection (read the target filename from `current-ssh-shell.txt`) and one smart check (health-gate). No new always-on process.

## 2. Manifest contract

Endpoint (immutable URL, mutable content — force-update the tag+release per roll):

```
https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/manifest.json
```

Schema (JSON):

```json
{
  "schema": 1,
  "version": "0.4.0-d897332",
  "published_at": "2026-07-18T12:00:00Z",
  "targets": {
    "x86_64-win7-windows-gnu": {
      "url":   "https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/ssh_shell-d897332-win7.exe",
      "sha256": "9c8ddef327a4459b272d125a8c43767d3051cacfae88107de18fdc0233645b3e",
      "size":   9634304
    },
    "x86_64-unknown-linux-musl": {
      "url":   "https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/ssh_shell-d897332-linux-musl",
      "sha256": "8c94b1df08b2e460ebee40e454f515cd17e169ea6b7a1a27667ab2d66a64cb64",
      "size":   12247400
    }
  }
}
```

- `version` is compared against `env!("CARGO_PKG_VERSION")`-`<build-sha>` (already in `ipn_version`).
- `targets` keyed by Rust target triple — updater picks `std::env::consts::ARCH`+OS or a build-time `--cfg` constant.
- `published_at` is informational; lets an operator spot a stale manifest from the admin console.
- `schema` lets us evolve format safely (updater refuses unknown schema).

## 3. Updater state machine

One `tokio::spawn` per process; states:

```
            ┌──────────────────────────────────┐
            │ IDLE (sleep 600 s ± jitter 120 s)│
            └──────────────┬───────────────────┘
                           │ timer
                           ▼
            ┌──────────────────────────────────┐
            │ FETCH  GET manifest.json          │─── error ──> log + IDLE
            └──────────────┬───────────────────┘
                           │ 200 OK
                           ▼
            ┌──────────────────────────────────┐
            │ COMPARE manifest.version vs       │
            │   current ipn_version             │── equal/older -> IDLE
            └──────────────┬───────────────────┘
                           │ newer
                           ▼
            ┌──────────────────────────────────┐
            │ LOCK  acquire per-box lockfile    │── busy ──> IDLE (other
            │   .koidra-ssh-update.lock         │            channel updating)
            └──────────────┬───────────────────┘
                           │ acquired
                           ▼
            ┌──────────────────────────────────┐
            │ DOWNLOAD  target.url -> temp file │── error ──> log + release
            │   (rustls; resume-from not needed │            lock + IDLE
            │    at 10 MB)                      │
            └──────────────┬───────────────────┘
                           │
                           ▼
            ┌──────────────────────────────────┐
            │ VERIFY  sha256(temp) == target.sha│── mismatch -> log + IDLE
            └──────────────┬───────────────────┘
                           │ OK
                           ▼
            ┌──────────────────────────────────┐
            │ STAGE  move temp ->               │
            │   ssh_shell-{version}{exe_suffix} │
            └──────────────┬───────────────────┘
                           │
                           ▼
            ┌──────────────────────────────────┐
            │ COMMIT  write current-ssh-shell.txt│
            │   atomically (temp+rename) with   │
            │   the new filename; append the    │
            │   previous filename to a rollback │
            │   stack file (max 3 entries)      │
            └──────────────┬───────────────────┘
                           │
                           ▼
            ┌──────────────────────────────────┐
            │ EXIT  process::exit(0) — clean.   │
            │   Supervisor relaunches the new   │
            │   binary within 5 s.              │
            └──────────────────────────────────┘
```

- On Linux, no file lock → updater can overwrite `ssh_shell-selfheal` in place, but the same stage-and-swap path is used for consistency. systemd `Restart=on-failure` does the relaunch.
- Health-gate (below) runs on the next launch and may roll back.

## 4. Shared primitive — health-gate (BRAVO owns the implementation; Charlie consumes)

This is the contract Bravo's P1 watchdog and Charlie's updater both depend on. Bravo builds it; Charlie calls it from the new binary on boot.

### State files (in install dir)

| File | Purpose |
|---|---|
| `current-ssh-shell.txt` | The exe filename the supervisor launches. Default `ssh_shell.exe`. Updated only via temp+rename. |
| `.boot-state.json` | Written by the binary on boot: `{booted_at, version, target_ip}`. |
| `.rollback-stack.txt` | Last 3 filenames the supervisor can roll back to (newest-first). |
| `.koidra-ssh-update.lock` | Per-box advisory lockfile (payload: PID + channel). Honored by both channels. |

### Health-gate (supervisor-side, language-agnostic)

```
# run on each supervisor cycle (every 5 s on Windows via supervisor.vbs;
# systemd unit defines Restart=on-failure + StartLimitBurst=2 + StartLimitIntervalSec=30s)

1. read current-ssh-shell.txt -> EXE
2. record start time
3. launch EXE
4. wait up to HEALTH_GATE_SECS (default 60) for a "healthy" signal:
     - Windows: TCP listen port open on the tailnet IP
     - Linux:   systemd's `Restart=on-failure` covers this; gate is a no-op
5. if healthy: clear .boot-state.json, continue normal supervision
6. if not healthy within HEALTH_GATE_SECS AND process already exited:
     a. pop the top of .rollback-stack.txt -> PREV_EXE
     b. write PREV_EXE to current-ssh-shell.txt
     c. relaunch PREV_EXE
     d. log + stop attempting updates for COOLDOWN (default 1 h)
7. if process is still running at 60 s but no listen: leave it alone (could be slow registration). Don't roll back.
```

### Interface the new binary must honor (Charlie's contract to Bravo)

On launch, the binary MUST:

1. Write `.boot-state.json` with `{booted_at: now_iso8601, version: ipn_version, target_ip: local_tailnet_ip}` within 2 s of starting.
2. Open the SSH listen socket as early as possible (before DERP/control registration) — that's what the gate probes.
3. Delete `.boot-state.json` once it has successfully registered with the tailnet AND accepted at least one connection (or after 5 min of healthy operation, whichever is first).
4. Never delete `.koidra-ssh-update.lock` — that's the supervisor's responsibility (after the gate clears).

Bravo's watchdog consumes the same primitives with one difference: it doesn't change `current-ssh-shell.txt`, it just forces a process restart of the same binary. So Bravo's watchdog restart path = steps 1-7 above EXCEPT step 6 (no rollback-stack pop). Both features share: `.boot-state.json` lifecycle, supervisor's gate loop, the listen-socket-early invariant.

## 5. Supervisor changes

### Windows (non-admin: `%LOCALAPPDATA%\koidra-ssh\`)

`run-node.cmd` reads the exe name from `current-ssh-shell.txt` (default `ssh_shell.exe` if missing):

```bat
@echo off
setlocal
set "EXE=%~dp0ssh_shell.exe"
if exist "%~dp0current-ssh-shell.txt" (
    set /p TARGET=<"%~dp0current-ssh-shell.txt"
    if not "%TARGET%"=="" set "EXE=%~dp0%TARGET%"
)
"%EXE%" -c "%~dp0%~1.json" -k %AUTHKEY% --listen-port %~2
```

`supervisor.vbs` adds the health-gate: between launches, check `.boot-state.json` age; if older than 60 s and the new process has exited, pop the rollback stack.

### Windows (admin: `C:\ProgramData\koidra-ssh\`, SYSTEM Scheduled Task)

Same `current-ssh-shell.txt` indirection in the schtasks action path. The schtasks `StartLimitBurst=2 / StartLimitIntervalSec=60` gives us the fast-exit detection.

### Linux (systemd)

`koidra-ssh-primary.service` / `-backup.service`:

```ini
[Service]
ExecStartPre=/bin/sh -c 'cat /home/sinh/koidra-ssh/current-ssh-shell.txt 2>/dev/null || echo ssh_shell-selfheal'
ExecStart=/home/sinh/koidra-ssh/ssh_shell-selfheal  # replaced by an ExecStartPre symlink trick OR a tiny wrapper
Restart=on-failure
StartLimitBurst=2
StartLimitIntervalSec=60
```

(Alternative: a 3-line wrapper `/home/sinh/koidra-ssh/run.sh` that reads `current-ssh-shell.txt` and execs the named binary. Simpler than systemd ExecStartPre acrobatics.)

## 6. Per-box dual-channel coordination

Both channels of a box run the updater. Jitter (±120 s on a 600 s period) means they don't swap simultaneously in practice. Belt-and-braces: per-box advisory lockfile (`.koidra-ssh-update.lock`, payload `{pid, channel, acquired_at}`):

- LOCK acquire: `OpenOptions::new().write(true).create_new(true)` — atomic create.
- LOCK held by other channel that's < 120 s old → skip this cycle (the other channel is mid-update; we'll update next cycle after jitter reschedules).
- LOCK held by other channel that's > 120 s old → assume stale, steal it.
- LOCK released on any exit path (including panic via `Drop`).

This honors "never both channels down at once" by construction: only one channel ever exits for an update at a time.

## 7. CLI + build flag

New `ssh_shell` flag:

```rust
#[arg(long = "manifest-url", env = "KOIDRA_MANIFEST_URL")]
manifest_url: Option<url::Url>,
```

- `None` (default): updater task is NOT spawned. Dev/test boxes stay manual. Backward-compatible.
- `Some(url)`: updater task spawned at boot.

Baked into fleet launchers via `run-node.cmd` / `supervisor.vbs` / `run.sh` adding `--manifest-url https://github.com/truongsinh/tailscale-rs/releases/download/fleet-manifest/manifest.json`.

Build-time constant `TAILSCALE_RS_FLEET_MANIFEST_URL_DEFAULT` (set via `.cargo/config.toml` or `--cfg`) lets a fleet-hardened build fail-closed if the flag is omitted. Off by default; can be enabled once the fleet is comfortable.

## 8. Security

- **Interim integrity gate**: SHA-256 over HTTPS (rustls, cert chain validated). A compromised GitHub release tag = a compromised binary fleet-wide. ACKNOWLEDGED RISK for the autonomous week.
- **Follow-up hardening (tracked, not blocking)**: minisign signature on the manifest. `manifest.json` gains `sig:` field; the binary ships with the public key baked in. Verification cost: ~1 ms, +50 LoC. Defer until first post-week review.
- **No auto-update to a downgrade**: updater refuses manifest.version < current (semver-aware).
- **No concurrent update across channels**: lockfile (§6).
- **No update storm**: jitter ±120 s staggers fleet-wide rolls.

## 9. Canary plan

Sequential; each stage gates the next.

| Stage | Box | Channel order | Pass criterion | Rollback trigger |
|---|---|---|---|---|
| 1 | dev box (Linux musl) | backup first | New version visible in admin API within 60 s; SSH OK; survives 10 min | `.boot-state.json` age > 60 s + exit → supervisor reverts to `ssh_shell-selfheal.prev` |
| 2 | dev box | primary | Same | Same |
| 3 | knodt Win10 lab | backup | Same + Windows-specific: supervisor.vbs health-gate observed working | Same; rollback to `ssh_shell.exe` |
| 4 | knodt Win10 lab | primary | Same | Same |
| 5 | **SOAK 24 h** on knodt | — | No rollback loop, no bricks, both channels reachable | — |
| 6 | scherze-win10 (admin) | backup → primary | Same + admin-ACL validation | Same |
| 7 | **SOAK 24 h** | — | — | — |
| 8 | Remaining customer boxes | dual-channel, staggered | Same | Same |
| 9 | Wedged/off-tailnet boxes | — | N/A — still need TeamViewer for the first updater-enabled build | Park |

A canary FAIL = stop, diagnose, fix, restart canary from stage 1.

## 10. Rollback paths

| Layer | Method |
|---|---|
| Single bad launch | Supervisor health-gate reverts `current-ssh-shell.txt` to top of `.rollback-stack.txt` automatically. |
| Bad binary that survives 60 s but wedges later | Push a new manifest pointing at the previous version. Updater downgrades-via-upgrade: bump version, point urls at the known-good binary. (Note: requires the "bad" build to still be able to fetch + swap — design assumes the bad build is not so bad it can't update. Truly bricked = TeamViewer.) |
| Bad manifest | Push a corrected manifest. Updater is idempotent (same version = no-op). |
| Tag compromised | Revoke + force-push tag with signed manifest (after minisign lands). Today, GitHub 2FA on the tag owner is the only gate. |

## 11. First-deploy bridge (Option B)

The first time we deploy the updater itself, we use the existing validated `koidra-upgrade.ps1` (already in `upgrade-kit-d897332/`). It's a one-shot kit-delivered swap; once landed, all subsequent rolls are pull-based. We do NOT agent-automate the kit delivery to Win7 boxes — that's the TeamViewer path the kit was designed for.

## 12. Out of scope (for the autonomous week)

- minisign signing (tracked §8).
- Channel coordination across multiple boxes (only per-box, not "update box A before box B").
- Rollout dashboards (admin API polling suffices for canary stages).
- Config-file-based manifest URL (env var + CLI flag is enough).
- Update rate-limiting beyond jitter (no "max N updates per day" cap).
- Rollback of identity files (`primary.json`/`backup.json`) — these are NEVER touched (locked architecture).

## 13. Files to add/modify (after Bravo's watchdog lands)

```
examples/ssh_shell/
  main.rs              # +15 LoC: parse --manifest-url, tokio::spawn updater task
  updater.rs           # +200 LoC: state machine §3, lockfile, download, swap
  updater_test.rs      # +100 LoC: manifest parse, version compare, atomic swap
.doc/
  2026-07-fleet-self-update.md  # this file
Cargo.toml             # maybe: add `zip` if we pack targets; else no change
```

On-box (NOT in this repo — live in `koidra-ssh-fleet/` artifacts + the NSIS installer source):

```
koidra-ssh-fleet/
  run-node.cmd                # add current-ssh-shell.txt indirection
  supervisor.vbs              # add health-gate loop (shared with Bravo)
  run.sh                      # Linux wrapper, same indirection
  koidra-ssh-primary.service  # ExecStart points to run.sh
  koidra-ssh-backup.service
```
