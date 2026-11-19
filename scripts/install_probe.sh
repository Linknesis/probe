#!/usr/bin/env bash
set -euo pipefail

# Linknesis Probe — one-command installer for Linux probes.
# Usage: curl -fsSL https://linknesis.com/install_probe.sh | sudo bash -s -- --core <host>:4443 --hash <psk>
#
# The probe runs as the unprivileged "linknesis" user. systemd grants it the
# raw-socket capability MTR needs (CAP_NET_RAW) and restarts it if it stops
# responding (Type=notify watchdog).

DEFAULT_INSTALL_DIR="/opt/linknesis/probe"
DEFAULT_STATE_DIR="/var/lib/linknesis"
SERVICE_USER="linknesis"
SERVICE_GROUP="linknesis"
BIN_URL="https://linknesis.com/linknesis-probe"
# SHA-256 of every genuine released Linux probe binary (one "sha256  version" per line).
CHECKSUMS_URL="https://linknesis.com/probe-checksums.txt"
IPERF3_URL="https://linknesis.com/iperf3-linux-x86_64"
LICENSE_URL="https://linknesis.com/LICENSE-THIRD-PARTY.txt"
IPERF3_LICENSE_URL="https://linknesis.com/iperf3_license.txt"
UPDATE_SCRIPT_URL="https://linknesis.com/update-probe.sh"
UPDATE_SERVICE_URL="https://linknesis.com/linknesis-probe-update.service"

# Needed for AmbientCapabilities= (the probe itself also needs glibc >= 2.34
# and OpenSSL 3, checked below)
MIN_SYSTEMD_VERSION=229

CORE_ADDRESS=""
PROBE_HASH=""
CORE_API_PORT="4480"
PROBE_DEBUG=""
INSTALL_FOLDER=""
PROBE_LABEL=""

usage() {
    cat <<EOF
Linknesis Probe installer (Linux)

Options:
  --core HOST:PORT       Core WebSocket address (e.g. core.example.com:4443)
  --hash HASH            Probe shared hash (from Core Settings > Probes Configuration)
  --label LABEL          Name shown for this probe in the Core. Used only when the
                         probe first registers; never overwrites a name set in the GUI
  --install-folder DIR   Install an additional, independent probe instance in DIR
                         (service name: linknesis-probe-<name of DIR>)
  --api-port PORT        The Core's API port (default 4480), used to download the
                         probe build that matches the Core
  --debug                Enable debug logging for the probe
  -h, --help             Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --core) CORE_ADDRESS="$2"; shift 2 ;;
        --hash) PROBE_HASH="$2"; shift 2 ;;
        --api-port) CORE_API_PORT="$2"; shift 2 ;;
        --label) PROBE_LABEL="$2"; shift 2 ;;
        --install-folder) INSTALL_FOLDER="$2"; shift 2 ;;
        --debug) PROBE_DEBUG=" --debug"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$CORE_ADDRESS" ] || [ -z "$PROBE_HASH" ]; then
    echo "ERROR: --core and --hash are required." >&2
    usage
    exit 1
fi

# The label goes, quoted, into the systemd unit's ExecStart= line: reject
# newlines and escape backslashes and double quotes.
LABEL_FLAG=""
if [ -n "$PROBE_LABEL" ]; then
    case "$PROBE_LABEL" in
        *$'\n'*|*$'\r'*)
            echo "ERROR: --label must not contain newlines." >&2
            exit 1
            ;;
    esac
    ESCAPED_LABEL=$(printf '%s' "$PROBE_LABEL" | sed 's/\\/\\\\/g; s/"/\\"/g')
    LABEL_FLAG=" --label \"$ESCAPED_LABEL\""
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This installer must be run as root." >&2
    exit 1
fi

# systemd is required (capability and watchdog both come from the unit)
if ! command -v systemctl >/dev/null 2>&1; then
    echo "ERROR: 'systemctl' was not found. This installer requires a systemd-based Linux distribution." >&2
    exit 1
fi
SYSTEMD_VERSION="$(systemctl --version | head -n1 | awk '{print $2}')"
if echo "$SYSTEMD_VERSION" | grep -qE '^[0-9]+$'; then
    if [ "$SYSTEMD_VERSION" -lt "$MIN_SYSTEMD_VERSION" ]; then
        echo "ERROR: systemd $SYSTEMD_VERSION is too old (need >= $MIN_SYSTEMD_VERSION for AmbientCapabilities= support)." >&2
        echo "Upgrade the OS to install the probe." >&2
        exit 1
    fi
else
    echo "WARNING: could not parse systemd version from '$SYSTEMD_VERSION'; continuing without the version check." >&2
fi

# PIDs of the default instance's probe process (never another instance's)
default_instance_pids() {
    local pid exe
    for pid in $(pgrep -x "linknesis-probe" 2>/dev/null || true); do
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        case "$exe" in
            "$DEFAULT_INSTALL_DIR/linknesis-probe"|"$DEFAULT_INSTALL_DIR/linknesis-probe (deleted)") echo "$pid" ;;
        esac
    done
}

MULTI_INSTANCE=0
INSTANCE_NAME=""
DATA_DIR_FLAG=""
SERVICE_NAME="linknesis-probe"
# Separate watchdog unit used by older probe versions; removed on reinstall
LEGACY_WATCHDOG_SERVICE_NAME="linknesis-probe-watchdog"

if [ -n "$INSTALL_FOLDER" ]; then
    case "$INSTALL_FOLDER" in
        /*) ;;
        *) echo "ERROR: --install-folder must be an absolute path." >&2; exit 1 ;;
    esac
    INSTALL_FOLDER="${INSTALL_FOLDER%/}"
    if [ -z "$INSTALL_FOLDER" ] || [ "$INSTALL_FOLDER" = "/opt/linknesis/probe" ] || [ "$INSTALL_FOLDER" = "/var/lib/linknesis" ]; then
        echo "ERROR: --install-folder must not be empty, '/', or the default install/state directory." >&2
        exit 1
    fi
    MULTI_INSTANCE=1
    INSTALL_DIR="$INSTALL_FOLDER"
    STATE_DIR="$INSTALL_FOLDER"
    INSTANCE_NAME="$(basename "$INSTALL_FOLDER")"
    SERVICE_NAME="linknesis-probe-${INSTANCE_NAME}"
    LEGACY_WATCHDOG_SERVICE_NAME="linknesis-probe-watchdog-${INSTANCE_NAME}"
    DATA_DIR_FLAG=" --data-dir $INSTALL_FOLDER"
else
    INSTALL_DIR="$DEFAULT_INSTALL_DIR"
    STATE_DIR="$DEFAULT_STATE_DIR"
fi

# Check required commands before changing anything
MISSING_CMDS=""
for cmd in curl getent groupadd useradd chown mktemp sed awk basename dirname; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS="$MISSING_CMDS $cmd"
done
if [ -n "$MISSING_CMDS" ]; then
    echo "ERROR: required command(s) not found:$MISSING_CMDS" >&2
    echo "Install them first (curl: 'curl' package; groupadd/useradd: 'passwd' on Debian/Ubuntu, 'shadow-utils' on RHEL/Fedora/Amazon Linux)." >&2
    exit 1
fi

# Download the probe and check, before changing anything, that the system can
# run it (the dynamic loader lists its libraries without running it). Staged
# next to the install dir, not in /tmp, which may be noexec or carry the
# wrong SELinux label.
STAGE_PARENT="$(dirname "$INSTALL_DIR")"
STAGE_PARENT_CREATED=0
if [ ! -d "$STAGE_PARENT" ]; then
    mkdir -p "$STAGE_PARENT"
    STAGE_PARENT_CREATED=1
fi
STAGE_DIR="$(mktemp -d "$STAGE_PARENT/.linknesis-install.XXXXXX")"
cleanup_stage() {
    rm -rf "$STAGE_DIR"
    if [ "$STAGE_PARENT_CREATED" -eq 1 ]; then
        rmdir "$STAGE_PARENT" 2>/dev/null || true
    fi
}
trap cleanup_stage EXIT
STAGED_BIN="$STAGE_DIR/linknesis-probe"

echo "=== Downloading probe binary ==="
# Prefer the build bundled with the Core (it matches the Core's version). It is
# served over plain HTTP, so it is used only if its SHA-256 is on the list of
# official releases published over HTTPS; otherwise use linknesis.com.
CORE_HOST="${CORE_ADDRESS%:*}"
CORE_HOST="${CORE_HOST#[}"; CORE_HOST="${CORE_HOST%]}"
case "$CORE_HOST" in *:*) CORE_URL_HOST="[$CORE_HOST]" ;; *) CORE_URL_HOST="$CORE_HOST" ;; esac
FROM_CORE=0
if [[ "$CORE_API_PORT" =~ ^[0-9]{1,5}$ ]] && command -v sha256sum >/dev/null 2>&1 \
   && curl -fsS --connect-timeout 10 --max-time 120 -o "$STAGED_BIN" \
        "http://${CORE_URL_HOST}:${CORE_API_PORT}/api/probe-update/linux/x86_64?hash=${PROBE_HASH}" 2>/dev/null; then
    CORE_BIN_SHA="$(sha256sum "$STAGED_BIN" | awk '{print $1}')"
    if curl -fsSL --max-time 30 "$CHECKSUMS_URL" 2>/dev/null | awk '{print $1}' | grep -qx "$CORE_BIN_SHA"; then
        FROM_CORE=1
        echo "Using the probe build bundled with the Core (checksum verified)."
    else
        echo "WARNING: the Core's probe build is not a known Linknesis release; downloading from linknesis.com instead." >&2
    fi
fi
if [ "$FROM_CORE" -ne 1 ]; then
    curl -fsSL "$BIN_URL" -o "$STAGED_BIN"
fi
chmod 755 "$STAGED_BIN"

echo "=== Checking system compatibility ==="
GLIBC_LOADER="/lib64/ld-linux-x86-64.so.2"
if [ "$(uname -m)" != "x86_64" ]; then
    LOADER_CHECK="unsupported CPU architecture $(uname -m): not found"
elif [ ! -e "$GLIBC_LOADER" ]; then
    LOADER_CHECK="$GLIBC_LOADER (glibc dynamic loader): not found"
else
    LOADER_CHECK="$("$GLIBC_LOADER" --list "$STAGED_BIN" 2>&1 || true)"
fi
if echo "$LOADER_CHECK" | grep -qiE "not found|No such file|cannot execute|Exec format error|Permission denied"; then
    . /etc/os-release 2>/dev/null || true
    echo "ERROR: the Linknesis probe cannot run on this system (${PRETTY_NAME:-unknown OS})." >&2
    echo "$LOADER_CHECK" | grep -iE "not found|No such file|cannot execute|Exec format error|Permission denied" | sed 's/^/  /' >&2
    echo "The probe requires glibc >= 2.34 and OpenSSL 3 (libssl.so.3), on x86_64." >&2
    echo "If only libssl.so.3 is missing on one of these, install the OpenSSL 3 package (e.g. 'apt-get install libssl3')." >&2
    echo "Nothing was changed on this system." >&2
    exit 1
fi

echo "=== Linknesis Probe Installer ==="
echo "Core address: $CORE_ADDRESS"
echo "Install dir:  $INSTALL_DIR"
if [ -n "$PROBE_LABEL" ]; then
    echo "Label:        $PROBE_LABEL"
fi
if [ "$MULTI_INSTANCE" -eq 1 ]; then
    echo "Instance:     $INSTANCE_NAME (service $SERVICE_NAME)"
fi

echo "=== Creating dedicated service account ==="
if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
fi
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$DEFAULT_STATE_DIR" --shell /usr/sbin/nologin -g "$SERVICE_GROUP" "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" "$STATE_DIR"

# Disable first, so Restart=always doesn't bring it straight back
echo "=== Stopping any existing '$SERVICE_NAME' service ==="
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

if systemctl list-unit-files "${LEGACY_WATCHDOG_SERVICE_NAME}.service" --no-legend 2>/dev/null | grep -q .; then
    echo "=== Removing old watchdog unit '$LEGACY_WATCHDOG_SERVICE_NAME' ==="
    systemctl stop "$LEGACY_WATCHDOG_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$LEGACY_WATCHDOG_SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${LEGACY_WATCHDOG_SERVICE_NAME}.service"
    systemctl daemon-reload
fi

if [ "$MULTI_INSTANCE" -eq 1 ]; then
    # Other instances share the binary name, so never kill by name here
    rm -f "$INSTALL_DIR/probe.lock"
else
    # Wait up to 10 seconds for a leftover default-instance process to exit
    for i in $(seq 1 10); do
        pids="$(default_instance_pids)"
        if [ -z "$pids" ]; then
            break
        fi
        kill -KILL $pids 2>/dev/null || true
        sleep 1
    done

    # Remove stale lock file so a crashed previous instance does not block the new one.
    rm -f /tmp/linknesis-probe.lock

    if [ -n "$(default_instance_pids)" ]; then
        echo "WARNING: could not terminate existing linknesis-probe process(es)." >&2
    fi
fi

echo "=== Installing probe binary ==="
mv -f "$STAGED_BIN" "$INSTALL_DIR/linknesis-probe"

# A static iperf3 build is bundled: some distributions ship versions too old
# for the options the probe uses (RHEL 9 and derivatives ship 3.9).
echo "=== Downloading iperf3 ==="
curl -fsSL "$IPERF3_URL" -o "$INSTALL_DIR/iperf3"
chmod +x "$INSTALL_DIR/iperf3"

echo "=== Downloading third-party licenses ==="
curl -fsSL "$LICENSE_URL" -o "$INSTALL_DIR/LICENSE-THIRD-PARTY.txt" 2>/dev/null || {
    echo "WARNING: Could not download LICENSE-THIRD-PARTY.txt; the probe binary is installed." >&2
}
curl -fsSL "$IPERF3_LICENSE_URL" -o "$INSTALL_DIR/iperf3_license.txt" 2>/dev/null || {
    echo "WARNING: Could not download iperf3_license.txt; the probe binary is installed." >&2
}

if [ "$MULTI_INSTANCE" -eq 0 ]; then
    echo "=== Installing update helper ==="
    curl -fsSL "$UPDATE_SCRIPT_URL" -o "$INSTALL_DIR/update-probe.sh" 2>/dev/null || {
        echo "WARNING: Could not download update helper from $UPDATE_SCRIPT_URL" >&2
    }
    chmod +x "$INSTALL_DIR/update-probe.sh" 2>/dev/null || true

    curl -fsSL "$UPDATE_SERVICE_URL" -o "/etc/systemd/system/linknesis-probe-update.service" 2>/dev/null || {
        echo "WARNING: Could not download update service from $UPDATE_SERVICE_URL" >&2
    }
fi
# Extra instances (--install-folder) are updated by re-running this installer.

echo "=== Restricting probe file ownership to $SERVICE_USER ==="
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" "$STATE_DIR"

# Reset SELinux labels (no-op without SELinux)
if command -v restorecon >/dev/null 2>&1 && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    restorecon -R "$INSTALL_DIR" "$STATE_DIR" || echo "WARNING: restorecon failed on $INSTALL_DIR/$STATE_DIR." >&2
fi

echo "=== Installing systemd service ==="
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Linknesis Probe${INSTANCE_NAME:+ (instance: $INSTANCE_NAME)}
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
WatchdogSec=45
User=$SERVICE_USER
Group=$SERVICE_GROUP
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=$INSTALL_DIR/linknesis-probe --core $CORE_ADDRESS --hash $PROBE_HASH$PROBE_DEBUG$DATA_DIR_FLAG$LABEL_FLAG
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
echo "=============================================="
echo "  Linknesis Probe installation complete"
echo "=============================================="
echo ""
echo "Core address:  $CORE_ADDRESS"
echo "Install dir:   $INSTALL_DIR"
echo "Service name:  $SERVICE_NAME"
echo ""
echo "View logs:     journalctl -u $SERVICE_NAME -f"
echo "Status:        systemctl status $SERVICE_NAME"
if [ "$MULTI_INSTANCE" -eq 0 ]; then
    echo "Manual update: $INSTALL_DIR/update-probe.sh"
    echo "               systemctl start linknesis-probe-update"
fi
echo ""
