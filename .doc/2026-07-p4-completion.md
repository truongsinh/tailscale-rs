# P4 Fleet Self-Update Pipeline — Completion Summary

> Status: **VALIDATED-SUFFICIENT** (Linux proven; Windows supervisor pending first real rollout).
> Date: 2026-07-18. Branch: `koidra/charlie-self-update` (all commits pushed to fork).

## What was delivered

| Component | Commit | Status |
|---|---|---|
| Design doc (`.doc/2026-07-fleet-self-update.md`) | `5ed0beb` (charlie-3) | ✅ Complete |
| Interface spec v2 (`.doc/2026-07-supervisor-restart-interface.md`) | `8ba576e` → `4280db3` | ✅ Complete |
| §11 bootstrap expansion (Win7/PS2 transfer reality) | `c45d68a` | ✅ Complete |
| **updater.rs** — state machine (613 LoC + 11 tests) | `5b8520b` → `c71bffb` | ✅ Complete |
| **koidra_fetch** — standalone HTTPS-to-disk CLI | `22c0e3e` | ✅ Validated on knodt Win10 |
| **main.rs wiring** — `--manifest-url` + `--install-dir` + boot-state + spawn | `e3e0a74` | ✅ Clean on P2 base |
| Poll override (`KOIDRA_UPDATER_POLL_SECS`) | `0e189e2` | ✅ Complete |
| Testability refactor (`CycleOutcome`) + e2e integration tests | `c71bffb` | ✅ 11/11 pass |

## Binaries built (staged in `/home/truongsinh/koidra-ssh-fleet/`)

| Binary | sha256 | Size |
|---|---|---|
| `ssh_shell-p4-selfupdate-c71bffb-linux-musl` | `22473870e753c0480d184e310447138f69db1fcd716e764bd9a06211372de964` | 13.3 MB |
| `ssh_shell-p4-selfupdate-c71bffb-win7.exe` | `77c8a0648521e4f93652dedd61de8ccb6d07b5eacc0879714213476c8452c1a2` | 10.6 MB |
| `koidra_fetch-cac1b1b-win7.exe` | `420854faad037f85885326e1cc42462905e18729d47c5adcc66b5f606792d04b` | 4.1 MB |
| `koidra_fetch-cac1b1b-linux-musl` | `180ee52377aca67c1bf1c3ef08d4a16f029c312a175e891c8234ee3f448c13db` | 5.7 MB |

## What was PROVEN

### 1. Unit + integration tests (11/11 pass)
Full state machine: manifest parse → version compare → lockfile (acquire/stale-steal/release) → download → sha256 verify → stage → atomic swap (current-ssh-shell.txt + rollback stack) → `CycleOutcome::Updated`. Plus the "no update" short-circuit + mock HTTP server e2e test (`run_one_cycle_full_swap_end_to_end`).

### 2. Linux dev-box canary (FULL LOOP on real hardware)
vn-office-dev-server-backup (100.73.219.82, port 2223, systemd):
- P4 binary booted → `.boot-state.json` written → updater spawned.
- Manifest fetched (reqwest, localhost HTTP) → version differs → download (12.5 MB) → sha256 verified → staged → current-ssh-shell.txt swapped → rollback stack pushed → `exit(0)`.
- systemd `Restart=always` + `RestartSec=3` fired → `run.sh` read current-ssh-shell.txt → launched the new binary.
- New binary registered + SSH listening + reachable (port 2223).
- Primary channel (100.120.122.20:2222) untouched — backup-first safety held.
- All state files verified correct.

### 3. koidra_fetch on Windows (knodt Win10)
- `koidra_fetch.exe` downloaded from GitHub + fetched a test file over HTTPS (sha256 verified, atomic write, exit codes 0/2/3). Native-tls/SChannel backend works on Win7/Win10 (bypasses .NET).

### 4. koidra_fetch under disk pressure (knodt)
- Succeeded downloading the 10.6 MB P4 binary with only 25 MB free disk space — where PowerShell's WebClient failed ("not enough space"). The streaming approach is more space-efficient.

## What is PARKED (not P4-blocked)

### Windows supervisor integration (run-node2.cmd reading current-ssh-shell.txt)
**Not yet validated on a live Windows box.** The change is a 5-line batch modification (read current-ssh-shell.txt → override the 3rd arg). Risk is minimal:
- The batch logic is straightforward (`for /f` to read the file, fallback to arg).
- NTFS `MoveFileEx` (Rust's `std::fs::rename`) is atomic — same semantics as POSIX rename.
- The supervisor.vbs 5-second relaunch loop is unchanged; only the launched exe name comes from current-ssh-shell.txt.

**Will validate at the first real Windows fleet rollout** (next on-site, user present to TeamViewer-fix if needed). The `koidra-ssh-fleet/run-node.cmd` + `supervisor.vbs` changes are documented in `.doc/2026-07-fleet-self-update.md` §5.

### knodt canary (blocked by box health)
knodt's C: drive has a **125.8 GB temp directory** consuming nearly all 126 GB. Disk is critically full (14 MB free after P4 download). Both SSH channels intermittent (disk thrashing). Needs cleanup/reboot = **user/maintenance action** (predates P4; not our debris). Park until box is healthy.

## Caveats for fleet rollout

1. **Bootstrap problem** (§11): the FIRST P4-equipped binary on each Win7/PS2 box still needs a non-rustls transfer (TeamViewer at next on-site, or chunked base64 over SSH after Bravo's P2 exec-channel fix). After the first delivery, all subsequent updates are automatic.

2. **No semver-aware no-downgrade check** (MVP): the updater treats ANY different version string as an update. We control the manifest, so accidental downgrades are unlikely, but a misconfigured manifest could regress the fleet. TODO: add semver comparison.

3. **No minisign signing** (tracked §8 of design doc): manifest integrity is SHA-256 over HTTPS. A compromised GitHub release tag = compromised fleet. Acceptable for the autonomous week; minisign is the follow-up hardening.

4. **Windows health-gate not implemented**: the supervisor-side rollback (detecting a failed launch within 60s + popping the rollback stack) is documented in the design but not yet coded for Windows. The `run.sh` wrapper on Linux doesn't implement it either (systemd's `Restart=always` covers crash recovery; full health-gate is a follow-up). For now, rollback is manual (edit current-ssh-shell.txt + restart).

## Dev box state

vn-office-dev-server-backup is running the selfheal binary (`0.4.0-unknown`) via the P4 supervisor config (`run.sh` + `Restart=always` + `KOIDRA_*` env). Stable. The selfheal binary ignores the `KOIDRA_*` env vars (pre-P4). Leave as-is for soak or restore the pre-canary systemd drop-in (backed up at `override.conf.pre-p4`).
