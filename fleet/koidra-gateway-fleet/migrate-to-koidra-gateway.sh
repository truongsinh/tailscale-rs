#!/usr/bin/env bash
#
# ============================================================================
# SUPERSEDED — DO NOT RUN. Kept for forensics only.
#
# This standalone migration script is retired. Its core design is `mv` of a
# RUNNING install dir: the still-running sibling channel's unit ExecStart path
# then vanishes, so its next restart can never come back (latent both-down —
# the SSH-less-upgrade brick class). See review-persistence.md (H5) and
# migration-plan.md §0.
#
# The dev box now migrates via the coordinator-driven staged sequence in
# migration-plan.md §2.3 (COPY-and-stage beside the old dir, self-contained new
# units, external validation, deferred cleanup) using the checked-in
# koidra-gateway-{primary,backup}.service templates. This file is retained ONLY
# so the old approach and its defects remain auditable.
# ============================================================================
#
# migrate-to-koidra-gateway.sh — one-shot rename of koidra-ssh → koidra-gateway
# (Linux variant).
#
# CANARY-SAFE SEQUENCE: backup channel first, primary untouched until backup
# is confirmed healthy. Per-box. Idempotent on the backup path.
#
# Delivered as a release asset under koidra-gateway-bootstrap. Pull on-box via
# koidra_fetch (or curl) and run as root:
#   sudo ./koidra_fetch \
#     https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/migrate-to-koidra-gateway.sh \
#     /usr/local/sbin/migrate.sh
#   sudo bash /usr/local/sbin/migrate.sh
#
# Safety properties:
#   - Snapshots the old layout to <dir>/.pre-rebrand/ + the old systemd units
#     to /etc/systemd/system/.pre-rebrand/ BEFORE any destructive op.
#   - Backup channel is fully migrated + health-gated before primary is touched.
#   - Stops are surgical: only the matching channel's systemd unit.
#   - Old units are `disable`d but NOT deleted until the 24 h soak clears, so
#     rollback is one `systemctl enable --now` away.
#
# Pre-flight aborts if the box isn't in a clean state.

set -euo pipefail

DIR="${KOIDRA_INSTALL_DIR:-/opt/koidra-ssh}"
NEW_DIR="${NEW_DIR:-/opt/koidra-gateway}"
FIRST_CHANNEL="${FIRST_CHANNEL:-backup}"
SKIP_SOAK="${SKIP_SOAK:-0}"
DRY_RUN="${DRY_RUN:-0}"

[[ $EUID -eq 0 ]] || { echo 'must run as root (sudo)'; exit 1; }
[[ -f "$DIR/run.sh" ]] || { echo "$DIR/run.sh not found — box not on koidra-ssh?"; exit 1; }
[[ ! -d "$NEW_DIR" ]] || { echo "$NEW_DIR already exists — already migrated?"; exit 1; }

echo "migrate: $DIR -> $NEW_DIR (first channel: $FIRST_CHANNEL)"

if [[ "$DRY_RUN" == '1' ]]; then
    echo '[dry-run] would snapshot, stop backup, move dir, rename binaries, install new units, start backup, health-gate, repeat for primary, cleanup'
    exit 0
fi

# --- Snapshot ----------------------------------------------------------------

mkdir -p "$DIR/.pre-rebrand"
cp -a "$DIR/run.sh" "$DIR/.pre-rebrand/"
[[ -f "$DIR/current-ssh-shell.txt" ]] && cp -a "$DIR/current-ssh-shell.txt" "$DIR/.pre-rebrand/"
mkdir -p /etc/systemd/system/.pre-rebrand
for ch in primary backup; do
    if systemctl list-unit-files "koidra-ssh-$ch.service" >/dev/null 2>&1; then
        cp -a "/etc/systemd/system/koidra-ssh-$ch.service" /etc/systemd/system/.pre-rebrand/
    fi
done
echo "snapshot: $DIR/.pre-rebrand + /etc/systemd/system/.pre-rebrand"

# --- Health gate -------------------------------------------------------------

wait_healthy() {
    local channel="$1" timeout="${2:-60}"
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if systemctl is-active --quiet "koidra-gateway-$channel.service" \
           && journalctl -u "koidra-gateway-$channel.service" --since '2 min ago' \
                | grep -q 'gateway listener ready'; then
            echo "  $channel healthy"
            return 0
        fi
        sleep 2
    done
    echo "  $channel did not register 'gateway listener ready' within ${timeout}s" >&2
    return 1
}

# --- Per-channel -------------------------------------------------------------

migrate_channel() {
    local channel="$1"
    echo "== migrating $channel =="

    systemctl stop "koidra-ssh-$channel.service" 2>/dev/null || true
    systemctl disable "koidra-ssh-$channel.service" 2>/dev/null || true

    if [[ "$channel" == "$FIRST_CHANNEL" ]]; then
        echo "  moving $DIR -> $NEW_DIR"
        mv "$DIR" "$NEW_DIR"
        DIR="$NEW_DIR"

        # Rename staged binaries + state file.
        for f in "$NEW_DIR"/ssh_shell-*; do
            [[ -e "$f" ]] || continue
            local base newname
            base=$(basename "$f")
            newname=${base/ssh_shell-/koidra-gateway-}
            mv "$f" "$NEW_DIR/$newname"
            echo "  renamed $base -> $newname"
        done
        if [[ -f "$NEW_DIR/current-ssh-shell.txt" ]]; then
            mv "$NEW_DIR/current-ssh-shell.txt" "$NEW_DIR/current-koidra-gateway.txt"
            sed -i 's/ssh_shell-/koidra-gateway-/g' "$NEW_DIR/current-koidra-gateway.txt"
        fi
        [[ -f "$NEW_DIR/.koidra-ssh-update.lock" ]] \
            && mv "$NEW_DIR/.koidra-ssh-update.lock" "$NEW_DIR/.koidra-gateway-update.lock"

        # Drop the new supervisor in.
        local kit_dir
        kit_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
        cp -f "$kit_dir/run.sh" "$NEW_DIR/run.sh"
        chmod 0755 "$NEW_DIR/run.sh"
    fi

    # Install the new systemd unit (primary → port 2222, backup → 2223).
    local port
    case "$channel" in
        primary) port=2222 ;;
        backup)  port=2223 ;;
    esac
    # The shipped .service files use /opt/koidra-gateway + default ports —
    # if the box uses a different layout, override via env vars.
    cp -f "/etc/systemd/system/.pre-rebrand/koidra-ssh-$channel.service" \
          "/etc/systemd/system/koidra-gateway-$channel.service"
    sed -i \
        -e "s|koidra-ssh-$channel|koidra-gateway-$channel|g" \
        -e "s|/opt/koidra-ssh|/opt/koidra-gateway|g" \
        -e "s|Description=.*|Description=Koidra Gateway — $channel channel|" \
        "/etc/systemd/system/koidra-gateway-$channel.service"
    systemctl daemon-reload
    systemctl enable "koidra-gateway-$channel.service"
    systemctl start "koidra-gateway-$channel.service"

    if ! wait_healthy "$channel" 60; then
        echo "ROLLBACK $channel" >&2
        systemctl stop "koidra-gateway-$channel.service" 2>/dev/null || true
        systemctl disable "koidra-gateway-$channel.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/koidra-gateway-$channel.service"
        systemctl daemon-reload
        if [[ "$channel" == "$FIRST_CHANNEL" && -d "$NEW_DIR" ]]; then
            mv "$NEW_DIR" "${NEW_DIR%/koidra-gateway}/koidra-ssh"
        fi
        cp -f "/etc/systemd/system/.pre-rebrand/koidra-ssh-$channel.service" \
              "/etc/systemd/system/koidra-ssh-$channel.service"
        systemctl daemon-reload
        systemctl enable --now "koidra-ssh-$channel.service"
        return 1
    fi
    return 0
}

second_channel() {
    case "$1" in
        backup)  echo primary ;;
        primary) echo backup ;;
    esac
}

# --- Run --------------------------------------------------------------------

if ! migrate_channel "$FIRST_CHANNEL"; then
    echo "Migration aborted at $FIRST_CHANNEL. Box is on old name. Snapshot at $DIR/.pre-rebrand." >&2
    exit 1
fi

sleep 3

SECOND=$(second_channel "$FIRST_CHANNEL")
if ! migrate_channel "$SECOND"; then
    echo "PARTIAL migration: $FIRST_CHANNEL = koidra-gateway, $SECOND = koidra-ssh. Box reachable but mixed. Manual cleanup needed." >&2
    exit 2
fi

# --- Soak + cleanup ---------------------------------------------------------

if [[ "$SKIP_SOAK" != '1' ]]; then
    echo 'both channels healthy. Soaking 10 min before cleanup...'
    sleep 600
    for ch in primary backup; do
        if ! wait_healthy "$ch" 30; then
            echo "post-soak health check failed for $ch. Old units preserved. Manual intervention required." >&2
            exit 3
        fi
    done
fi

# Remove old units (the disable happened in migrate_channel; now delete files).
for ch in primary backup; do
    if [[ -f "/etc/systemd/system/koidra-ssh-$ch.service" ]]; then
        rm -f "/etc/systemd/system/koidra-ssh-$ch.service"
        echo "removed koidra-ssh-$ch.service"
    fi
done
systemctl daemon-reload
rm -rf "$NEW_DIR/.pre-rebrand"
echo 'migration complete. Box is fully on koidra-gateway.'
