#!/usr/bin/env bash
set -euo pipefail

# Linknesis Probe — Linux uninstall script.
# Usage: curl -fsSL https://linknesis.com/uninstall_probe.sh | sudo bash -s -- [options]
#
# --install-folder DIR removes one additional instance previously installed
# with install_probe.sh --install-folder DIR, instead of the default shared
# installation. It leaves the shared linknesis service account (and any other
# instances) untouched unless this is the last instance on the host.

INSTALL_DIR="${INSTALL_DIR:-/opt/linknesis/probe}"
STATE_DIR="${STATE_DIR:-/var/lib/linknesis}"
SERVICE_NAME="linknesis-probe"
# Separate watchdog unit used by older probe versions
LEGACY_WATCHDOG_SERVICE_NAME="linknesis-probe-watchdog"
SERVICE_USER="linknesis"
SERVICE_GROUP="linknesis"
SKIP_CONFIRM="${SKIP_CONFIRM:-0}"
INSTALL_FOLDER=""

usage() {
    cat <<EOF
Linknesis Probe uninstaller (Linux)

This script stops and removes the Linknesis Probe systemd service,
the probe binary, and its local state.

Options:
  --install-dir DIR        Installation directory (default: /opt/linknesis/probe)
  --state-dir DIR          State directory (default: /var/lib/linknesis)
  --install-folder DIR     Remove one additional instance previously installed with
                           install_probe.sh --install-folder DIR, instead of the
                           default shared installation. Leaves the shared linknesis
                           service account and other instances untouched.
  --yes, -y                Skip confirmation prompts
  -h, --help               Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --install-folder) INSTALL_FOLDER="$2"; shift 2 ;;
        --yes|-y) SKIP_CONFIRM=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This uninstaller must be run as root. Try: curl -fsSL https://linknesis.com/uninstall_probe.sh | sudo bash -s -- --yes" >&2
    exit 1
fi

MULTI_INSTANCE=0
INSTANCE_NAME=""
if [ -n "$INSTALL_FOLDER" ]; then
    INSTALL_FOLDER="${INSTALL_FOLDER%/}"
    MULTI_INSTANCE=1
    INSTALL_DIR="$INSTALL_FOLDER"
    STATE_DIR="$INSTALL_FOLDER"
    INSTANCE_NAME="$(basename "$INSTALL_FOLDER")"
    SERVICE_NAME="linknesis-probe-${INSTANCE_NAME}"
    LEGACY_WATCHDOG_SERVICE_NAME="linknesis-probe-watchdog-${INSTANCE_NAME}"
fi

echo "=== Linknesis Probe Uninstaller ==="
echo "Installation directory: $INSTALL_DIR"
echo "State directory:        $STATE_DIR"
if [ "$MULTI_INSTANCE" -eq 1 ]; then
    echo "Instance:                $INSTANCE_NAME (service $SERVICE_NAME)"
fi
echo ""

if [ "$SKIP_CONFIRM" -ne 1 ]; then
    echo "WARNING: This will permanently stop and remove the Linknesis Probe"
    echo "         service, binary, and local state."
    echo ""
    if [ -t 0 ]; then
        read -rp "Type 'yes' to continue: " confirm
    elif [ -r /dev/tty ]; then
        read -rp "Type 'yes' to continue: " confirm </dev/tty
    else
        echo "ERROR: Cannot prompt for confirmation in non-interactive mode. Use --yes to confirm." >&2
        exit 1
    fi
    if [ "$confirm" != "yes" ]; then
        echo "Uninstall cancelled."
        exit 0
    fi
fi

# Stop the old watchdog unit first (if present) so it can't restart the probe
echo "=== Stopping helper services ==="
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$LEGACY_WATCHDOG_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$LEGACY_WATCHDOG_SERVICE_NAME" 2>/dev/null || true
    if [ "$MULTI_INSTANCE" -eq 0 ]; then
        systemctl stop linknesis-probe-update 2>/dev/null || true
        systemctl disable linknesis-probe-update 2>/dev/null || true
    fi
fi

# Stop and disable the service
echo "=== Stopping $SERVICE_NAME service ==="
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
fi

if [ "$MULTI_INSTANCE" -eq 0 ]; then
    # Wait for the process to exit. Matched by binary path, since other
    # instances share the binary name.
    for i in $(seq 1 10); do
        pids=""
        for pid in $(pgrep -x "linknesis-probe" 2>/dev/null || true); do
            exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
            case "$exe" in
                "$INSTALL_DIR/linknesis-probe"|"$INSTALL_DIR/linknesis-probe (deleted)") pids="$pids $pid" ;;
            esac
        done
        if [ -z "$pids" ]; then
            break
        fi
        kill -KILL $pids 2>/dev/null || true
        sleep 1
    done
fi

# Remove this instance's systemd units
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "/etc/systemd/system/${LEGACY_WATCHDOG_SERVICE_NAME}.service"
if [ "$MULTI_INSTANCE" -eq 0 ]; then
    rm -f /etc/systemd/system/linknesis-probe-update.service
    # Remove stale lock file (default layout only; --install-folder instances
    # keep their lock under their own install folder, removed with it below).
    rm -f /tmp/linknesis-probe.lock
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

# Remove probe binary, licenses, and state
echo "=== Removing probe files ==="
rm -rf "$INSTALL_DIR"
if [ "$INSTALL_DIR" != "$STATE_DIR" ]; then
    rm -rf "$STATE_DIR"
fi
# The default layout's parent (/opt/linknesis) is created by the installer
# but holds nothing else; remove it only if it is now empty.
if [ "$MULTI_INSTANCE" -eq 0 ]; then
    rmdir "$(dirname "$INSTALL_DIR")" 2>/dev/null || true
fi

# Older probe versions added a sudoers rule; remove this instance's line,
# and the file once it is empty
echo "=== Removing old sudoers rule (if present) ==="
SUDOERS_FILE="/etc/sudoers.d/linknesis-probe"
RULE_LINE="$SERVICE_USER ALL=(root) NOPASSWD: /usr/sbin/setcap cap_net_raw+ep $INSTALL_DIR/linknesis-probe"
if [ -f "$SUDOERS_FILE" ]; then
    if grep -qxF "$RULE_LINE" "$SUDOERS_FILE" 2>/dev/null; then
        SUDOERS_TMP="$(mktemp)"
        grep -vxF "$RULE_LINE" "$SUDOERS_FILE" > "$SUDOERS_TMP" || true
        if [ -s "$SUDOERS_TMP" ]; then
            install -m 440 "$SUDOERS_TMP" "$SUDOERS_FILE"
        else
            rm -f "$SUDOERS_FILE"
        fi
        rm -f "$SUDOERS_TMP"
    fi
fi

# Remove the dedicated service account only if no other Linknesis Probe
# instance still references it (the account is shared across instances).
echo "=== Checking for other Linknesis Probe instances ==="
REMAINING_UNITS="$(find /etc/systemd/system -maxdepth 1 -name 'linknesis-probe*.service' 2>/dev/null || true)"
if [ -z "$REMAINING_UNITS" ]; then
    echo "No other instances found; removing service account."
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi
    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupdel "$SERVICE_GROUP" 2>/dev/null || true
    fi
else
    echo "Other Linknesis Probe instance(s) still present; keeping $SERVICE_USER account:"
    echo "$REMAINING_UNITS"
fi

echo ""
echo "=============================================="
echo "  Linknesis Probe uninstall complete"
echo "=============================================="
echo ""
echo "Removed:"
echo "  - systemd service $SERVICE_NAME (and leftovers of older versions, if any)"
echo "  - $INSTALL_DIR"
if [ "$INSTALL_DIR" != "$STATE_DIR" ]; then
    echo "  - $STATE_DIR"
fi
echo ""
