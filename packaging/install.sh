#!/usr/bin/env bash
# Install Deadbolt from source, for distros without a .deb or .rpm.
#
#   cargo build --release          # as yourself, in the repo root
#   sudo packaging/install.sh      # full desktop install
#   sudo packaging/install.sh --server   # daemon, TUI and CLI only
#
# It copies the files listed in packaging/manifest.txt and runs the same
# post-install step the packages run. It does not install ClamAV or any
# other backend: those come from your distro so their security fixes
# arrive with normal updates.
set -euo pipefail

LC_ALL=C
export LC_ALL

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

server=0
for arg in "$@"; do
    case "$arg" in
        --server) server=1 ;;
        -h|--help)
            printf 'usage: sudo packaging/install.sh [--server]\n'
            exit 0
            ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo packaging/install.sh"

missing=()
for cmd in systemctl cp mkdir chmod find rm id; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
[ "${#missing[@]}" -eq 0 ] || die "missing commands: ${missing[*]}"

root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd -- "$root" || exit 1
[ -x target/release/deadboltd ] || die "build first, as yourself: cargo build --release"

# Package names for what Deadbolt needs at runtime, per package manager.
pm=""
for p in apt dnf zypper pacman apk emerge; do
    if command -v "$p" >/dev/null 2>&1; then
        pm="$p"
        break
    fi
done
case "$pm" in
    apt) hint="sudo apt install clamav clamav-daemon clamav-freshclam python3-pyqt6 polkitd" ;;
    dnf) hint="sudo dnf install clamav clamd clamav-freshclam python3-pyqt6 polkit" ;;
    zypper) hint="sudo zypper install clamav python3-PyQt6 polkit" ;;
    pacman) hint="sudo pacman -S clamav python-pyqt6 polkit" ;;
    apk) hint="sudo apk add clamav clamav-daemon py3-qt6 polkit" ;;
    emerge) hint="sudo emerge app-antivirus/clamav dev-python/pyqt6 sys-auth/polkit" ;;
    *) hint="install ClamAV (clamd, clamonacc, freshclam), PyQt6 and polkit with your package manager" ;;
esac
need=()
for bin in clamd clamonacc freshclam clamscan; do
    command -v "$bin" >/dev/null 2>&1 || need+=("$bin")
done
if [ "${#need[@]}" -gt 0 ]; then
    printf 'install.sh: not found: %s\n' "${need[*]}" >&2
    printf 'install.sh: install them first. In my case: %s (it depends on your system)\n' "$hint" >&2
    exit 1
fi

copied=0
# Fields are split on whitespace; the manifest has no spaces in paths.
while read -r kind pkg mode src dst; do
    case "$kind" in ''|'#'*) continue ;; esac
    if [ "$pkg" = "gui" ] && [ "$server" -eq 1 ]; then
        continue
    fi
    [ -e "$src" ] || die "missing $src"
    mkdir -p -- "$(dirname -- "$dst")"
    if [ "$kind" = "tree" ]; then
        rm -rf -- "$dst"
        mkdir -p -- "$dst"
        cp -R -- "$src/." "$dst/"
        find "$dst" -name __pycache__ -type d -prune -exec rm -rf -- {} +
        find "$dst" -type d -exec chmod 0755 -- {} +
        find "$dst" -type f -exec chmod "$mode" -- {} +
    else
        cp -- "$src" "$dst"
        chmod "$mode" -- "$dst"
    fi
    copied=$((copied + 1))
done <packaging/manifest.txt

printf 'install.sh: copied %s files\n' "$copied"
packaging/scripts/postinstall.sh configure
printf 'install.sh: done. Open Deadbolt from your app menu, or run "sudo deadboltctl setup" on a server.\n'
