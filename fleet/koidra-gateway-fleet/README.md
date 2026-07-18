# koidra-gateway-fleet/

On-box supervisor + installer source for the **koidra-gateway** rebrand track.
This is the source-of-truth checked-in template; the live on-box copies under
`koidra-ssh-fleet/` (per-box, never in the repo) are what the current fleet
actually runs.

> **Status**: artifacts only — **NOT a migration**. The live fleet keeps running
> under `koidra-ssh` until the functional rollout completes and the user signs
> off on the rename. Migration is canary-safe (backup channel first, 10-min
> soak before cleanup, snapshot-rollback). See
> [`migrate-to-koidra-gateway.ps1`](./migrate-to-koidra-gateway.ps1) /
> [`migrate-to-koidra-gateway.sh`](./migrate-to-koidra-gateway.sh).

## Files

| File | Purpose |
|---|---|
| `run-node2.cmd` | Windows supervisor launch shim. Reads `current-koidra-gateway.txt` for the exe name, launches it. Invoked by the scheduled task. |
| `supervisor.vbs` | Windows 5-second relaunch loop (non-admin path where schtasks can't host SYSTEM tasks). Launched from the Startup group via `KoidraGateway.lnk`. |
| `run.sh` | Linux supervisor launch shim (bash). Mirror of `run-node2.cmd`. Exec'd by the systemd unit so `Restart=on-failure` sees the binary's exit status directly. |
| `koidra-gateway-primary.service` | systemd unit — primary channel (port 2222). |
| `koidra-gateway-backup.service` | systemd unit — backup channel (port 2223). |
| `installer.nsi` | NSIS installer source — produces `koidra-gateway-setup.exe`. Installs to `C:\ProgramData\koidra-gateway\` (admin) or `%LOCALAPPDATA%\koidra-gateway\` (non-admin), creates `KoidraGateway-primary` / `KoidraGateway-backup` scheduled tasks (admin) or `KoidraGateway.lnk` Startup shortcut (non-admin). |
| `migrate-to-koidra-gateway.ps1` | Windows migration script (canary-safe, backup-first, 10-min soak, snapshot rollback). **NOT RUN YET.** |
| `migrate-to-koidra-gateway.sh` | Linux migration script (same discipline). **NOT RUN YET.** |

## Build

The installer + binaries are built from this repo + this template. The
`bin/build-win7` / `bin/build-musl` scripts produce `koidra_gateway.exe` /
`koidra_gateway`; the release script stages them as
`koidra-gateway-<sha>-<target>` and ships them to the
`koidra-gateway-bootstrap` GitHub release alongside the migration scripts.

```bash
# Build the binaries (from repo root).
bin/build-win7 --example koidra_gateway --features ssh
bin/build-musl --example koidra_gateway --features ssh

# Assemble the installer kit (operator step, not automated yet):
cp target/x86_64-win7-windows-gnu/release/examples/koidra_gateway.exe fleet/koidra-gateway-fleet/
cp fleet/koidra-gateway-fleet/{run-node2.cmd,supervisor.vbs,installer.nsi} build-dir/
makensis build-dir/installer.nsi
```

## Migration (later, when the functional rollout is done)

```powershell
# Windows — pull via koidra_fetch (already on-box, already cleanly named):
koidra_fetch.exe `
  https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/migrate-to-koidra-gateway.ps1 `
  $env:TEMP\migrate.ps1

# Dry-run first (prints plan, changes nothing):
powershell -ExecutionPolicy Bypass -File $env:TEMP\migrate.ps1 -DryRun

# Real run (backup-first, 10-min soak before cleanup):
powershell -ExecutionPolicy Bypass -File $env:TEMP\migrate.ps1
```

```bash
# Linux — pull via curl (koidra_fetch works too):
sudo curl -fL \
  https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/migrate-to-koidra-gateway.sh \
  -o /usr/local/sbin/migrate.sh
sudo bash /usr/local/sbin/migrate.sh          # DRY_RUN=1 to dry-run
```

## Canary order

1. dev-box-primary (Linux musl — lowest blast radius)
2. scherze-win10 (Windows admin)
3. redsun-win7 (Windows non-admin, restrictive firewall)
4. scherze-win7 (Windows non-admin)
5. bioverbeek (Windows admin)
6. knodt-win10 (Windows admin, disk-pressured — wait for disk cleanup first)

## Rollback

Each migration snapshots the old layout to `<dir>/.pre-rebrand/` and old
scheduled-task / systemd definitions to `*.xml` / `.service` copies. The
migration script auto-rolls back on a failed health gate. For manual rollback
after a successful migration:

- **Windows**: `Move-Item $newDir $oldDir; Get-Content .pre-rebrand\KoidraSSH-*.xml | schtasks /create /tn KoidraSSH-$ch /xml -; schtasks /run /tn KoidraSSH-$ch`
- **Linux**: `mv $NEW_DIR $OLD_DIR; cp /etc/systemd/system/.pre-rebrand/*.service /etc/systemd/system/; systemctl daemon-reload; systemctl enable --now koidra-ssh-{primary,backup}`

The 24 h soak before `.pre-rebrand/` deletion is the rollback window.
