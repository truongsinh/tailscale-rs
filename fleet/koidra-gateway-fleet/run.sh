#!/usr/bin/env bash
#
# run.sh — koidra-gateway channel launch shim (Linux dev box).
#
# Exec'd by the systemd unit (koidra-gateway-primary.service / -backup.service) as:
#   run.sh <channel> <port> [exe-override]
#     <channel>  = primary | backup
#     <port>     = 2222 (primary) | 2223 (backup)   — dev ports
#     [override] = optional explicit versioned binary name (rollout version pins)
#
# `exec` replaces the shell so systemd's Restart=on-failure sees the binary's
# exit status directly.
#
# Binary resolution order (mirror of run-node2.cmd):
#   1. exe-override arg ($3)
#   2. current-koidra-gateway.txt — the authoritative pointer (versioned name,
#      no .exe on Linux), seeded on deploy and rewritten by the updater
#   3. default-koidra-gateway.txt — the deploy-baked default (from GW_SHA); the
#      updater NEVER rewrites this, so it survives an emptied/half-written current
#      pointer and always names the sha that was actually deployed
#   4. hardcoded literal fallback — last resort ONLY if both pointer files are
#      missing (kept in sync with the installer's GW_SHA default).
#
# Identity file is node-<channel>.json in this dir (dev keyfiles are
# node-primary.json / node-backup.json — NOT <channel>.json).
#
# $AUTHKEY comes from the unit's Environment= (systemd env is process-private, so
# baking it there is safe on Linux — unlike Windows machine env). $KOIDRA_MANIFEST_URL
# is optional (the updater is off on the dev box during the roll).

set -euo pipefail

# REQUIRED runtime gate: the binary aborts with `Error: UnstableEnvVar` at startup
# unless this is set (checked in src/lib.rs init). Export it here, per-process, so a
# launch never depends on a machine-wide/unit env var (belt-and-braces with the unit's
# Environment=). The old koidra-ssh launcher set it; the rebrand must keep it.
export TS_RS_EXPERIMENT=this_is_unstable_software

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="${1:?usage: run.sh <channel> <port> [exe-override]}"
port="${2:?usage: run.sh <channel> <port> [exe-override]}"
override="${3:-}"

# Hardcoded literal fallback (last resort; matches installer GW_SHA default).
exe="$dir/koidra-gateway-06f9a3a"
# Deploy-baked default pointer (from GW_SHA; the updater never rewrites it).
if [[ -f "$dir/default-koidra-gateway.txt" ]]; then
    default="$(head -n1 "$dir/default-koidra-gateway.txt" 2>/dev/null || true)"
    [[ -n "$default" ]] && exe="$dir/$default"
fi
# Authoritative current pointer (updater rewrites this atomically) wins over default.
if [[ -f "$dir/current-koidra-gateway.txt" ]]; then
    target="$(head -n1 "$dir/current-koidra-gateway.txt" 2>/dev/null || true)"
    [[ -n "$target" ]] && exe="$dir/$target"
fi
# Explicit override arg wins over everything.
[[ -n "$override" ]] && exe="$dir/$override"

# Dev keyfiles are node-<channel>.json, not <channel>.json.
conf="$dir/node-$channel.json"

# Fail loudly (not a silent set -u abort) if the unit didn't bake the key.
authkey="${AUTHKEY:?AUTHKEY not set — bake it into the unit Environment=}"

# ---- exe-exists guard (supervision integrity) -------------------------------
# Never `exec` a binary that is not on disk. RCA: a resolved-but-absent exe (a
# pointer naming a file that was never staged / a half-finished update) makes
# `exec` fail and systemd Restart=on-failure tight-spin forever on a missing
# filename. Instead log + back off, then exit so systemd restarts us — which
# re-resolves the pointer above and self-heals once a good exe/pointer lands.
# systemd IS this script's supervise loop (the `exec` hands it the child's exit
# status); backing off before exit gives the same effect as run-node2.cmd's
# in-loop backoff, rather than exec'ing a missing file.
if [[ ! -f "$exe" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] run.sh $channel: resolved binary '$exe' missing on disk — not exec'ing; backing off 60s before letting systemd restart" \
        >> "$dir/koidra-diag.txt" 2>/dev/null || true
    sleep 60
    exit 1
fi

if [[ -n "${KOIDRA_MANIFEST_URL:-}" ]]; then
    exec "$exe" -c "$conf" -k "$authkey" \
        --listen-port "$port" --install-dir "$dir" \
        --manifest-url "$KOIDRA_MANIFEST_URL"
else
    exec "$exe" -c "$conf" -k "$authkey" \
        --listen-port "$port" --install-dir "$dir"
fi
