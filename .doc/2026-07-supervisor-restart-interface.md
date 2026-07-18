# Supervisor-restart interface — Bravo (P1 watchdog) × Charlie (P4 updater)

> Tight contract for the ONE shared thing both features need: asking the
> supervisor to restart the ssh_shell process safely. Extract from
> [2026-07-fleet-self-update.md](2026-07-fleet-self-update.md) §4, refined
> to cover Bravo's in-process-fallback path. Bravo implements against this;
> Charlie's updater conforms to it.

## 1. Two restart mechanisms — do NOT conflate

| Feature | What restarts | Why | Where the logic lives |
|---|---|---|---|
| **Bravo P1 — off-tailnet watchdog** | The SAME binary, in-process | DERP/control stream stalled; recover without losing SSH sessions | `ts_runtime/src/offtailnet_watchdog.rs` (in-process); falls back to process restart ONLY if in-process recovery exhausts |
| **Charlie P4 — fleet self-update** | A NEW binary file, via supervisor relaunch | A manifest-versioned update is staged; current process exits cleanly so supervisor picks up the new filename | `examples/ssh_shell/updater.rs` (in-process) triggers exit; supervisor (`run-node.cmd`/`supervisor.vbs`/`run.sh`/schtasks/systemd) does the relaunch |

The supervisor-side restart path is **shared**. The trigger + post-restart
decision differ:

- Bravo triggers it as a LAST RESORT (in-process recovery failed).
- Charlie triggers it as the HAPPY PATH (clean exit → relaunch picks up new file).
- After relaunch, the supervisor runs the SAME health-gate loop. The gate decides "rollback to previous file" based on whether the boot record indicates a version change — not based on who triggered the restart.

## 2. State files — single owner per file

| File | Owner (writes) | Readers | Purpose |
|---|---|---|---|
| `current-ssh-shell.txt` | supervisor (under health-gate) | supervisor, both binaries | Exe filename to launch. Default `ssh_shell.exe` (Windows) / `ssh_shell-selfheal` (Linux). |
| `.boot-state.json` | **the launched binary** (Charlie writes; Bravo's binary writes the same on every boot — there is one boot path) | supervisor gate | `{booted_at, version, target_ip}`. The gate's rollback trigger keys off `booted_at` age vs. process-alive. |
| `.rollback-stack.txt` | supervisor (under health-gate) | supervisor | LIFO of up to 3 previous exe filenames. Pop = revert. |
| `.koidra-ssh-update.lock` | Charlie's updater only | Charlie's updater | Per-box advisory lock so both channels don't swap simultaneously. Bravo's watchdog does NOT touch this. |
| `.restart-requested` (sentinel) | Bravo's watchdog ONLY (fallback path) | supervisor gate (next cycle) | Empty file; presence = "watchdog exhausted in-process recovery, please restart the process". Unlink by supervisor after relaunch. |

Bravo's watchdog otherwise NEVER touches `current-ssh-shell.txt`,
`.rollback-stack.txt`, or `.koidra-ssh-update.lock`. It operates on the
in-process control runner; only on fallback does it drop the sentinel.

## 3. Binary boot contract (what `main.rs` MUST do)

On launch, before doing anything that could hang or take >2 s, the binary:

1. Compute `target_ip = dev.ipv4_addr()` (already required for `serve_ssh`).
2. Atomically write `.boot-state.json` in the install dir:
   ```json
   {"booted_at":"2026-07-18T12:34:56Z","version":"0.4.0-d897332","target_ip":"100.115.1.3"}
   ```
   temp+rename, single shot. `version` = the same `IPN_VERSION` string already logged.
3. Open the SSH listen socket **first** (before DERP/control registration) — that's what the gate probes. (`dev.serve_ssh(...)` already does this if invoked before any blocking await; keep that ordering.)
4. Delete `.boot-state.json` after EITHER (a) first successful SSH accept, OR (b) 5 min of healthy operation, whichever first. This is the "I'm alive" signal.
5. NEVER delete `.koidra-ssh-update.lock` — that's the supervisor's responsibility (after the gate clears).
6. NEVER delete `.restart-requested` — that's the supervisor's responsibility (after relaunch).

Steps 1-4 are SHARED — every boot does them, regardless of whether the
trigger was Bravo's watchdog fallback or Charlie's update exit or a manual
restart. This is what makes the gate work uniformly.

## 4. Supervisor health-gate loop (single shared algorithm)

Runs every supervisor cycle (Windows `supervisor.vbs` ≈ 5 s; systemd `Restart=on-failure`).

```
inputs:  current-ssh-shell.txt, .boot-state.json, .rollback-stack.txt, .restart-requested

1. read current-ssh-shell.txt -> EXE  (default if missing)
2. if .boot-state.json does NOT exist from a PRIOR launch with same EXE:
       # fresh launch of this EXE — baseline its health
       record baseline={exe: EXE, started: now}
   else:
       # still working through a prior launch's gate cycle
       prior = read .boot-state.json
       if now - prior.booted_at < HEALTH_GATE_SECS (60):
           continue supervision (process may still be coming up)
       elif process still alive AND listen socket open:
           # late but healthy — clear baseline, stop gating
           clear baseline
       elif process exited:
           # FAILED within the gate window — decide rollback
           if .restart-requested exists:
               # Bravo fallback: restart SAME exe, no rollback-stack pop
               unlink .restart-requested
               relaunch EXE
               baseline = {exe: EXE, started: now}
           elif baseline.exe == EXE AND .rollback-stack.txt non-empty:
               # Charlie update path: new exe failed gate, revert
               pop top of rollback-stack -> PREV_EXE
               write PREV_EXE to current-ssh-shell.txt
               relaunch PREV_EXE
               baseline = {exe: PREV_EXE, started: now}
               enter COOLDOWN (1 h) — stop accepting updater exits
           else:
               # Same exe, no rollback candidate, no explicit request = plain crash loop
               # systemd: give up (StartLimitBurst). Windows: stop supervisor for COOLDOWN.
               enter COOLDOWN
       else:
           # process alive but not healthy at 60s — leave alone (slow reg)
           pass
3. else (normal supervision):
       just relaunch on crash
```

Three trigger sources, one algorithm:

| Trigger | Sentinel | Rollback-stack pop? |
|---|---|---|
| Bravo watchdog fallback | `.restart-requested` present | NO — restart same exe |
| Charlie updater clean exit | none (exit code 0) | supervisor relaunches current-ssh-shell.txt; if that's the NEW exe and it fails the gate → pop (revert). If it's the SAME exe (no update in flight) → no pop. |
| Manual kill / OOM | none | Same as Bravo (no rollback pop, same-exe restart) |

The distinguishing signal is `baseline.exe == EXE AND exe was just swapped
(booted_at within last cycle)`. In practice: the supervisor updates
`baseline.exe` whenever `current-ssh-shell.txt` changes value, so a
mismatch on a fresh boot = "we just swapped into a new exe" = rollback
eligible.

## 5. Bravo watchdog → supervisor fallback (the integration point)

```
offtailnet_watchdog (in-process, 30 s tick):
  if no StateUpdate for > TS_OFFNET_T_DETECT_SECS (120):
      attempt ForceReconnect on ControlRunner
      if ForceReconnect fails OR no StateUpdate within COOLDOWN (60 s):
          # in-process recovery exhausted
          log "watchdog fallback: requesting supervisor restart"
          touch .restart-requested   # empty file, install dir
          process::exit(libc::EXIT_FAILURE)   # supervisor sees abnormal exit
```

Why this shape:
- The watchdog's FIRST job is to recover in-process — preserves live SSH sessions (the whole point of P1).
- Only when in-process recovery provably fails does it escalate. The escalation is a process exit (abnormal) + a sentinel that tells the supervisor "I asked for this, don't roll back".
- Supervisor's gate sees: process exited + sentinel present → relaunch same exe + clear sentinel. No rollback-stack pop.
- If Bravo's in-process fix is sufficient on the real redsun box (it likely is — the smoking-gun diagnostic says the issue is control-stream-drop, recoverable in-process), the fallback path is never taken and the supervisor never even notices.

## 6. What Bravo must implement (checklist)

- [ ] `ts_runtime/src/offtailnet_watchdog.rs` — the in-process actor (main's design).
- [ ] ControlRunner `ForceReconnect` msg + `StreamMessage::Finished` handler with 5 s backoff.
- [ ] Fallback: `touch .restart-requested` in the install dir, then `process::exit(EXIT_FAILURE)`.
- [ ] DO NOT touch `current-ssh-shell.txt`, `.rollback-stack.txt`, `.koidra-ssh-update.lock` — Charlie/supervisor owns those.
- [ ] Honor the binary boot contract §3 — Bravo's in-process watchdog runs AFTER boot-state.json is written (which the binary does once at startup, not Bravo specifically).

## 7. What Charlie must implement (checklist, post-Bravo-merge)

- [ ] `examples/ssh_shell/updater.rs` — manifest fetch + compare + download + sha256 + stage + swap current-ssh-shell.txt + exit 0.
- [ ] `examples/ssh_shell/main.rs` — parse `--manifest-url`, `tokio::spawn` the updater task after `Device::new`, write `.boot-state.json` before `serve_ssh`.
- [ ] Per-box lockfile `.koidra-ssh-update.lock` (create_new atomic).
- [ ] Supervisor updates (live in `koidra-ssh-fleet/`): `run-node.cmd` reads `current-ssh-shell.txt`; `supervisor.vbs` runs the §4 gate loop; same for `run.sh`/systemd on Linux.
- [ ] Canary plan §9 of the main design doc.

## 8. Drift guards

- If `.boot-state.json` schema changes, BOTH `updater.rs` and the supervisor scripts must be updated in lockstep. Bump a `schema` field inside the JSON and refuse to parse unknown values.
- If a new restart-trigger source is added (e.g. a manual `ops restart` CLI), add a row to §4's trigger table + a sentinel convention (don't overload `.restart-requested` — use a new sentinel).
- The supervisor gate algorithm is the canonical source — don't duplicate the logic per platform; `supervisor.vbs` and `run.sh` should be line-for-line translations.
