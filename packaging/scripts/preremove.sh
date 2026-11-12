#!/usr/bin/env bash
# Runs before the package files are removed. On a real removal (deb
# "remove", rpm 0) it stops Deadbolt, hands ClamAV back to the distro units,
# and removes Deadbolt's OpenSnitch rules and canary files. It never touches
# the quarantine folder.
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

case "${1:-remove}" in
    remove|0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ] && have systemctl; then
    for p in quick home full custom; do
        systemctl disable --now "deadbolt-scan@$p.timer" >/dev/null 2>&1 || true
    done
    systemctl disable --now deadbolt-quarantine-purge.timer >/dev/null 2>&1 || true
    systemctl disable --now deadbolt-clamonacc.service deadbolt-clamd.service >/dev/null 2>&1 || true
    systemctl disable --now deadboltd.service deadbolt-worker.service >/dev/null 2>&1 || true
    systemctl disable --now var-lib-deadbolt-quarantine.mount >/dev/null 2>&1 || true
    for u in clamav-daemon.service clamav-clamonacc.service clamd@scan.service; do
        if [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" = "masked" ]; then
            systemctl unmask "$u" >/dev/null 2>&1 || true
        fi
    done
fi

# Unload Deadbolt's clamd profile. The distro's own profile is not touched.
aa_profile=/etc/apparmor.d/deadbolt-clamd
if have apparmor_parser && [ -d /sys/kernel/security/apparmor ] && [ -f "$aa_profile" ]; then
    apparmor_parser -R "$aa_profile" >/dev/null 2>&1 || true
fi

# Deadbolt's own OpenSnitch rules only.
for f in /etc/opensnitchd/rules/*deadbolt-*.json; do
    [ -e "$f" ] || continue
    rm -f -- "$f"
done

# Canary files: only the four names Deadbolt plants, only paths it recorded.
list=/var/lib/deadbolt/canaries.txt
names=(0000-household-records.docx 0000-budget.xlsx zzzz-scan-0001.jpg zzzz-tax-return.pdf)
if [ -f "$list" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        base="${p##*/}"
        ours=0
        for n in "${names[@]}"; do
            [ "$base" = "$n" ] && ours=1
        done
        [ "$ours" -eq 1 ] || continue
        [ -f "$p" ] && [ ! -L "$p" ] && rm -f -- "$p"
        hidden="${p%/*}/.hidden"
        if [ -f "$hidden" ] && [ ! -L "$hidden" ]; then
            tmp="$(mktemp "${TMPDIR:-/tmp}/deadbolt-hidden.XXXXXX")"
            # grep exits 1 when nothing is left; that is fine.
            grep -v -x -F -e "${names[0]}" -e "${names[1]}" -e "${names[2]}" -e "${names[3]}" -- "$hidden" >"$tmp" || true
            if [ -s "$tmp" ]; then
                # cat keeps the file's owner and mode.
                cat -- "$tmp" >"$hidden"
            else
                rm -f -- "$hidden"
            fi
            rm -f -- "$tmp"
        fi
    done <"$list"
fi
exit 0
