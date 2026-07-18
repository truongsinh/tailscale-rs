# Supervisor-restart × in-process-recovery interface — Bravo (P1) × Charlie (P4)

> Tight contract for the NARROW shared surface between Bravo's in-process
> watchdog (control-stream reconnect + DERP relay rehome) and Charlie's
> supervisor-level process restart (self-update swap). Bravo's mechanism
> runs ENTIRELY in-process; Charlie's restarts the process via the
> supervisor. The surface they share is small — keep it small, don't
> over-couple.
>
> Source design: [2026-07-fleet-self-update.md](2026-07-fleet-self-update.md).
> Background on Bravo's design (redsun smoking gun: `active; relay "dfw",
> tx 2808 rx 0`): tailscale-rs-autonomous-run board, sections
> "SHARPEST DIAGNOSTIC" + "P1 ROOT-CAUSE REFINED".

## 1. Two mechanisms — distinct, NOT coupled

| Feature | What it does | Trigger | Where the logic lives | Restarts process? |
|---|---|---|---|---|
| **Bravo P1 — off-tailnet watchdog** | Control-stream RECONNECT (re-attach on `StreamMessage::Finished`, 5 s backoff) + rx-stall DERP relay REHOME (self-heal re-selects region after fresh `derp_map`) | No `StateUpdate` for >120 s OR rx stall (`tx > 0, rx ≈ 0`) | `ts_runtime/src/offtailnet_watchdog.rs` (in-process actor); ControlRunner `ForceReconnect` msg | **NO** — preserves live SSH sessions (the whole point) |
| **Charlie P4 — fleet self-update** | Atomic exe swap via supervisor relaunch on clean exit | Manifest version newer than current | `examples/ssh_shell/updater.rs` (in-process) triggers `process::exit(0)`; supervisor relaunches the new filename | **YES** — supervisor (`run-node.cmd` / `supervisor.vbs` / `run.sh` / systemd) picks up `current-ssh-shell.txt` |

**Key boundary:** Bravo never touches the supervisor. Bravo's watchdog
runs inside the ssh_shell process; if it recovers (expected case on
redsun), the supervisor sees nothing. If Bravo's watchdog cannot recover
in-process, the binary stays running (unhealthy) — it does NOT write a
sentinel, does NOT request a process restart. Process restart remains
Charlie's domain (clean exit for swap) or plain crash recovery
(supervisor's default `Restart=on-failure`).

## 2. The truly-shared surface (small)

Two invariants in the binary's boot path. Both features depend on them;
neither feature owns them — `examples/ssh_shell/main.rs` owns them.

### 2.1 `.boot-state.json` (single boot-path write)

On launch, before doing anything that could hang or take >2 s, the binary writes `.boot-state.json` in the install dir:

```json
{"schema":1,"booted_at":"2026-07-18T12:34:56Z","version":"0.4.0-d897332","target_ip":"100.115.1.3"}
```

- temp+rename (atomic), single shot at boot.
- `version` = the same `IPN_VERSION` string already logged by main.rs.
- `target_ip` = `dev.ipv4_addr()` (already computed for `serve_ssh`).
- Deleted by the binary after EITHER first successful SSH accept OR 5 min of healthy operation, whichever is first.

**Who reads it:**
- Charlie's supervisor health-gate (§3) — to detect "fresh launch failed within 60 s".
- Bravo's watchdog MAY read it (informational: "I booted at T, version V"). Bravo does NOT write it, does NOT delete it, does NOT depend on its absence/presence for its in-process logic.

### 2.2 Listen-socket-early invariant

The binary MUST open the SSH listen socket BEFORE DERP/control registration. Today `dev.serve_ssh(...)` already does this — keep that ordering.

- Charlie's supervisor gate probes the TCP port to decide if a freshly-launched exe is healthy.
- Bravo benefits indirectly: a reachable listen socket means SSH sessions survive even while Bravo's watchdog is mid-recovery on the control plane.

That's the whole shared surface. Nothing else is shared.

## 3. Charlie's supervisor health-gate (Bravo-independent)

For completeness — this is Charlie's domain; Bravo doesn't interact with it.

State files in install dir:

| File | Owner (writes) | Purpose |
|---|---|---|
| `current-ssh-shell.txt` | supervisor (under gate) | Exe filename to launch. Default `ssh_shell.exe` (Win) / `ssh_shell-selfheal` (Linux). |
| `.rollback-stack.txt` | supervisor (under gate) | LIFO of up to 3 previous exe filenames; pop = revert. |
| `.koidra-ssh-update.lock` | Charlie's updater only | Per-box advisory lock so both channels don't swap simultaneously. |

Gate algorithm (per supervisor cycle, ~5 s on Windows; systemd `Restart=on-failure`):

```
1. read current-ssh-shell.txt -> EXE  (default if missing)
2. track baseline = {exe launched, boot timestamp from .boot-state.json}
3. on process exit within HEALTH_GATE_SECS (60) of a fresh baseline:
     if baseline.exe was JUST swapped (current-ssh-shell.txt changed last cycle)
        AND .rollback-stack.txt non-empty:
        pop top -> PREV_EXE
        write PREV_EXE to current-ssh-shell.txt
        relaunch PREV_EXE
        enter COOLDOWN (1 h)
     else:
        relaunch same EXE (plain crash recovery, default systemd behavior)
4. on healthy launch (process alive at 60 s + listen socket open):
     clear baseline, stop gating
5. at 60 s if process alive but listen not open: leave alone (slow reg)
```

Single trigger source for Charlie's gate: the binary exits. Two outcomes
depending on whether `current-ssh-shell.txt` just changed (Charlie's
update path → rollback eligible) or not (plain crash → restart same
exe). No Bravo interaction.

## 4. What Bravo must implement (checklist)

- [ ] `ts_runtime/src/offtailnet_watchdog.rs` — in-process actor (30 s tick).
- [ ] ControlRunner `ForceReconnect` msg + `StreamMessage::Finished` handler with 5 s backoff.
- [ ] rx-stall detection (`tx > 0, rx ≈ 0` for T) triggering self-heal DERP rehome via fresh `derp_map`.
- [ ] Honor the listen-socket-early invariant (§2.2) — do not move the listen socket later in the boot path.
- [ ] DO NOT write `current-ssh-shell.txt`, `.rollback-stack.txt`, `.koidra-ssh-update.lock`, `.restart-requested`, or any sentinel file in the install dir. Bravo's recovery is in-process ONLY.
- [ ] DO NOT call `process::exit` from the watchdog. If recovery exhausts, log loudly and keep the process running — Charlie's supervisor handles process-level recovery via plain crash detection if the binary later dies on its own.

## 5. What Charlie must implement (checklist, post-Bravo-merge)

- [ ] `examples/ssh_shell/updater.rs` — manifest fetch + compare + download + sha256 + stage + swap `current-ssh-shell.txt` + `process::exit(0)`.
- [ ] `examples/ssh_shell/main.rs`:
  - parse `--manifest-url`, `tokio::spawn` the updater task after `Device::new`.
  - write `.boot-state.json` before `serve_ssh` (single boot-path write, §2.1).
  - ensure listen-socket-early ordering is preserved when adding updater task (§2.2).
- [ ] Per-box lockfile `.koidra-ssh-update.lock` (create_new atomic).
- [ ] Supervisor updates (live in `koidra-ssh-fleet/`): `run-node.cmd` reads `current-ssh-shell.txt`; `supervisor.vbs` runs the §3 gate loop; same for `run.sh`/systemd on Linux.

## 6. Coordination note (why this is v2)

v1 of this doc (commit 6e35b45) assumed Bravo's watchdog would escalate
to a process restart via a `.restart-requested` sentinel + abnormal
exit. Bravo's design has since evolved (per team-lead 2026-07-18):
recovery is in-process (control-stream reconnect + relay rehome) and
does NOT require a process restart. The sentinel is removed; the shared
surface is just §2 (two boot invariants). This v2 reflects that narrower
boundary. If Bravo later finds a case where in-process recovery is
insufficient and a process restart becomes necessary, propose it as a
new §2.3 entry — don't silently add a sentinel.

## 7. Drift guards

- If `.boot-state.json` schema changes, bump the `schema` field; the supervisor gate refuses unknown values.
- If a future feature needs a process restart from inside the binary (neither Charlie's clean-exit nor a plain crash), add it as a new §2.x invariant with its own sentinel — don't overload Charlie's files.
