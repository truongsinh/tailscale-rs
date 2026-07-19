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
#   3. default fallback = the shipped VERSIONED name (never a bare/self-heal
#      name — keeps the running build obvious and rollback identity intact).
#      Kept in sync with the installer's GW_SHA default / branch HEAD.
#
# Identity file is node-<channel>.json in this dir (dev keyfiles are
# node-primary.json / node-backup.json — NOT <channel>.json).
#
# $AUTHKEY comes from the unit's Environment= (systemd env is process-private, so
# baking it there is safe on Linux — unlike Windows machine env). $KOIDRA_MANIFEST_URL
# is optional (the updater is off on the dev box during the roll).

set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="${1:?usage: run.sh <channel> <port> [exe-override]}"
port="${2:?usage: run.sh <channel> <port> [exe-override]}"
override="${3:-}"

# Default = shipped versioned binary (matches installer GW_SHA default / HEAD).
exe="$dir/koidra-gateway-06f9a3a"
if [[ -f "$dir/current-koidra-gateway.txt" ]]; then
    target="$(head -n1 "$dir/current-koidra-gateway.txt" 2>/dev/null || true)"
    [[ -n "$target" ]] && exe="$dir/$target"
fi
[[ -n "$override" ]] && exe="$dir/$override"

# Dev keyfiles are node-<channel>.json, not <channel>.json.
conf="$dir/node-$channel.json"

# Fail loudly (not a silent set -u abort) if the unit didn't bake the key.
authkey="${AUTHKEY:?AUTHKEY not set — bake it into the unit Environment=}"

if [[ -n "${KOIDRA_MANIFEST_URL:-}" ]]; then
    exec "$exe" -c "$conf" -k "$authkey" \
        --listen-port "$port" --install-dir "$dir" \
        --manifest-url "$KOIDRA_MANIFEST_URL"
else
    exec "$exe" -c "$conf" -k "$authkey" \
        --listen-port "$port" --install-dir "$dir"
fi
