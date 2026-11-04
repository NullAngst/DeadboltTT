#!/usr/bin/env bash
# Runs after the package files are gone. "apt purge" asks whether to delete
# the quarantine folder too, then removes Deadbolt's state, config and logs.
# A plain remove leaves everything in /var/lib/deadbolt alone.
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

action="${1:-remove}"

if [ "$action" = "purge" ]; then
    delete_quarantine=false
    if [ -e /usr/share/debconf/confmodule ]; then
        # confmodule reads variables it does not set.
        set +u
        # shellcheck disable=SC1091
        . /usr/share/debconf/confmodule
        db_input high deadbolt/purge-quarantine || true
        db_go || true
        if db_get deadbolt/purge-quarantine; then
            delete_quarantine="$RET"
        fi
        db_purge || true
        set -u
    fi
    if [ -d /var/lib/deadbolt ]; then
        for entry in /var/lib/deadbolt/* /var/lib/deadbolt/.[!.]*; do
            [ -e "$entry" ] || continue
            if [ "${entry##*/}" = "quarantine" ] && [ "$delete_quarantine" != "true" ]; then
                continue
            fi
            rm -rf -- "$entry"
        done
        rmdir -- /var/lib/deadbolt 2>/dev/null || true
    fi
    rm -rf -- /etc/deadbolt /var/log/deadbolt
    for p in quick home full custom; do
        rm -rf -- "/etc/systemd/system/deadbolt-scan@$p.timer.d"
    done
fi

if [ -d /run/systemd/system ] && have systemctl; then
    systemctl daemon-reload || true
fi
exit 0
