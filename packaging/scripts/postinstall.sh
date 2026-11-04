#!/usr/bin/env bash
# Runs after the package files are on disk (deb: "configure", rpm: 1 or 2).
# Installs files and starts the daemon so the first-run wizard can talk to
# it. Protection itself stays off until you agree to it in the wizard or
# with "deadboltctl setup".
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

action="${1:-configure}"

if have systemd-sysusers; then
    systemd-sysusers deadbolt.conf
fi
if have systemd-tmpfiles; then
    systemd-tmpfiles --create deadbolt.conf
fi
if have sysctl; then
    sysctl -q -p /usr/lib/sysctl.d/60-deadbolt.conf >/dev/null 2>&1 || true
fi

# Nothing to start inside a chroot or a container build.
if [ ! -d /run/systemd/system ] || ! have systemctl; then
    exit 0
fi

systemctl daemon-reload
systemctl reload dbus.service >/dev/null 2>&1 \
    || systemctl reload dbus-broker.service >/dev/null 2>&1 \
    || true

systemctl enable --now var-lib-deadbolt-quarantine.mount
systemctl enable deadbolt-worker.service deadboltd.service deadbolt-quarantine-purge.timer

case "$action" in
    configure|1)
        systemctl start deadbolt-worker.service deadboltd.service deadbolt-quarantine-purge.timer || true
        ;;
    *)
        # Upgrade: restart what was running so the new binaries take over.
        systemctl try-restart deadbolt-worker.service deadboltd.service || true
        systemctl try-restart deadbolt-clamd.service deadbolt-clamonacc.service || true
        ;;
esac
exit 0
