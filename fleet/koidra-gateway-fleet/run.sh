#!/usr/bin/env bash
#
# Supervisor launch shim for koidra-gateway (Linux).
#
# Invoked by the systemd unit (koidra-gateway-primary.service / -backup.service)
# as:  run.sh <channel> <port> [exe-override]
#
# Mirror of run-node2.cmd: resolve exe name via override arg →
# current-koidra-gateway.txt → default koidra_gateway-selfheal, then exec it.
# `exec` replaces the shell so systemd's Restart=on-failure sees the binary's
# exit status directly.
#
# $AUTHKEY, $KOIDRA_MANIFEST_URL are expected in the systemd unit's Environment=
# lines. The channel's identity file is <channel>.json in this dir.

set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="${1:?usage: run.sh <channel> <port> [exe-override]}"
port="${2:?usage: run.sh <channel> <port> [exe-override]}"
override="${3:-}"

exe="$dir/koidra_gateway-selfheal"
if [[ -f "$dir/current-koidra-gateway.txt" ]]; then
    target="$(head -n1 "$dir/current-koidra-gateway.txt" 2>/dev/null || true)"
    if [[ -n "$target" ]]; then
        exe="$dir/$target"
    fi
fi
if [[ -n "$override" ]]; then
    exe="$dir/$override"
fi

if [[ -n "${KOIDRA_MANIFEST_URL:-}" ]]; then
    exec "$exe" -c "$dir/$channel.json" -k "$AUTHKEY" \
        --listen-port "$port" --install-dir "$dir" \
        --manifest-url "$KOIDRA_MANIFEST_URL"
else
    exec "$exe" -c "$dir/$channel.json" -k "$AUTHKEY" \
        --listen-port "$port" --install-dir "$dir"
fi
