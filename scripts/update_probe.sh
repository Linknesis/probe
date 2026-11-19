#!/usr/bin/env bash
set -euo pipefail

# Linknesis Probe — manual update helper.
#
# This script triggers a one-time probe update. It is useful when the Core's
# automatic probe updates are disabled and you want to update a probe (or a
# fleet of probes) programmatically without using the GUI.
#
# Usage:
#   sudo /opt/linknesis/probe/update-probe.sh
#
# The script stops the running probe service, runs the probe binary in update
# mode, and starts the service again. The probe downloads the matching binary
# from the Core and replaces itself before exiting.

SERVICE_NAME="linknesis-probe.service"
PROBE_BIN="/opt/linknesis/probe/linknesis-probe"
SERVICE_USER="linknesis"
UPDATE_TIMEOUT_SECS=300

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script must be run as root" >&2
    exit 1
fi

if [ ! -x "$PROBE_BIN" ]; then
    echo "ERROR: probe binary not found or not executable: $PROBE_BIN" >&2
    exit 1
fi

# Always start the probe again on exit, even if the update fails
restart_probe() {
    echo "Starting $SERVICE_NAME ..."
    systemctl start "$SERVICE_NAME" || echo "ERROR: could not start $SERVICE_NAME" >&2
}

echo "Stopping $SERVICE_NAME ..."
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
fi
trap restart_probe EXIT

# Run as the probe's service account, which owns the install directory and
# the lock file (older installs without that account run as root)
RUN_AS=()
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    RUN_AS=(runuser -u "$SERVICE_USER" --)
fi

echo "Triggering probe update ..."
if timeout "$UPDATE_TIMEOUT_SECS" "${RUN_AS[@]}" "$PROBE_BIN" --update; then
    echo "Probe update completed."
else
    echo "ERROR: probe update failed or timed out after ${UPDATE_TIMEOUT_SECS}s; the previous binary is kept." >&2
    exit 1
fi
