#!/usr/bin/env bash
# Remove a source install of Deadbolt (one made with packaging/install.sh).
#
#   sudo bash packaging/uninstall.sh          # keep settings, history and quarantine
#   sudo bash packaging/uninstall.sh --purge  # remove those too, asks about quarantine
#
# For a .deb or .rpm install, use your package manager instead.
set -euo pipefail

LC_ALL=C
export LC_ALL

die() {
    printf 'uninstall.sh: %s\n' "$*" >&2
    exit 1
}

purge=0
for arg in "$@"; do
    case "$arg" in
        --purge) purge=1 ;;
        -h|--help)
            printf 'usage: sudo bash packaging/uninstall.sh [--purge]\n'
            exit 0
            ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash packaging/uninstall.sh"
for cmd in rm id dirname; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing command: $cmd"
done

root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd -- "$root" || exit 1

bash packaging/scripts/preremove.sh remove

# Fields are split on whitespace; the manifest has no spaces in paths.
while read -r kind _pkg _mode _src dst; do
    case "$kind" in ''|'#'*) continue ;; esac
    rm -rf -- "$dst"
done <packaging/manifest.txt
rmdir -- /usr/libexec/deadbolt /usr/share/deadbolt/tools /usr/share/deadbolt/gui /usr/share/deadbolt /usr/share/doc/deadbolt 2>/dev/null || true

if [ "$purge" -eq 1 ]; then
    answer=n
    if [ -t 0 ]; then
        printf 'Delete the quarantine folder (/var/lib/deadbolt/quarantine) too? [y/N] '
        read -r answer || answer=n
    fi
    for entry in /var/lib/deadbolt/* /var/lib/deadbolt/.[!.]*; do
        [ -e "$entry" ] || continue
        case "${entry##*/}:$answer" in
            quarantine:y|quarantine:Y|quarantine:yes) rm -rf -- "$entry" ;;
            quarantine:*) ;;
            *) rm -rf -- "$entry" ;;
        esac
    done
    rmdir -- /var/lib/deadbolt 2>/dev/null || true
    rm -rf -- /etc/deadbolt /var/log/deadbolt
    for p in quick home full custom; do
        rm -rf -- "/etc/systemd/system/deadbolt-scan@$p.timer.d"
    done
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
printf 'uninstall.sh: removed. The distro ClamAV units are unmasked again.\n'
