#!/usr/bin/env bash
# Build the deadbolt and deadbolt-server .deb and .rpm packages with nfpm,
# from packaging/manifest.txt. Run from the repo root after
# "cargo build --release". GitHub Actions runs this on every v* tag.
#
#   bash packaging/build-packages.sh 0.1.0            # version
#   ARCH=arm64 bash packaging/build-packages.sh 0.1.0 # other architecture
#
# Called through bash on purpose: GitHub web uploads drop the execute bit.
set -euo pipefail

LC_ALL=C
export LC_ALL

die() {
    printf 'build-packages: %s\n' "$*" >&2
    exit 1
}

missing=()
for cmd in nfpm mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if [ "${#missing[@]}" -gt 0 ]; then
    die "missing commands: ${missing[*]} (nfpm: https://nfpm.goreleaser.com/install/)"
fi

version="${1:-}"
[ -n "$version" ] || die "usage: bash packaging/build-packages.sh VERSION"
version="${version#[vV]}"
case "$version" in
    [0-9]*) ;;
    *) die "version must start with a digit, like 1.2.3 or v1.2.3: $1" ;;
esac
arch="${ARCH:-amd64}"
out="${OUT_DIR:-dist}"
manifest=packaging/manifest.txt
[ -f "$manifest" ] || die "run this from the repo root"
[ -x target/release/deadboltd ] || die "build first: cargo build --release"

mkdir -p -- "$out"
work="$(mktemp -d "${TMPDIR:-/tmp}/deadbolt-nfpm.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# contents_for <all|gui...>: nfpm "contents:" entries for the given package classes.
contents_for() {
    local want=("$@")
    local kind pkg mode src dst w match
    # Fields are split on whitespace; the manifest has no spaces in paths.
    while read -r kind pkg mode src dst; do
        case "$kind" in ''|'#'*) continue ;; esac
        match=0
        for w in "${want[@]}"; do
            [ "$pkg" = "$w" ] && match=1
        done
        [ "$match" -eq 1 ] || continue
        [ -e "$src" ] || die "manifest source missing: $src"
        printf '  - src: %s\n    dst: %s\n' "$src" "$dst"
        if [ "$kind" = "tree" ]; then
            printf '    type: tree\n'
        elif [ "$kind" = "config" ]; then
            # deb conffile, rpm %config(noreplace): local edits survive upgrades.
            printf '    type: config|noreplace\n    file_info:\n      mode: 0%s\n' "${mode#0}"
        else
            printf '    file_info:\n      mode: 0%s\n' "${mode#0}"
        fi
    done <"$manifest"
}

common_header() {
    cat <<EOF
arch: $arch
platform: linux
version: "$version"
section: admin
priority: optional
maintainer: "Zack <zack98@protonmail.com>"
vendor: NullAngst
homepage: https://github.com/NullAngst/DeadboltTT
license: GPL-3.0-or-later
scripts:
  postinstall: packaging/scripts/postinstall.sh
  preremove: packaging/scripts/preremove.sh
  postremove: packaging/scripts/postremove.sh
deb:
  scripts:
    templates: packaging/scripts/templates
    config: packaging/scripts/config
EOF
}

{
    printf 'name: deadbolt\n'
    common_header
    cat <<'EOF'
description: |
  Deadbolt: Track and Terminate. Anti-malware for the Linux desktop.
  A front end for ClamAV real-time and on-demand scanning, a ransomware
  shield that freezes apps that mass-encrypt files, quarantine, and
  per-app network blocking through OpenSnitch. Desktop app, tray icon,
  terminal UI and deadboltctl.
depends:
  - clamav
  - clamav-daemon
  - clamav-freshclam
  - python3-pyqt6
  - polkitd
recommends:
  - opensnitch
  - udisks2
  - upower
  - iproute2
  - openssl
suggests:
  - python3-nautilus
  - lynis
  - rkhunter
  - chkrootkit
  - debsums
conflicts:
  - deadbolt-server
replaces:
  - deadbolt-server
overrides:
  rpm:
    depends:
      - clamav
      - (clamd or clamav-server)
      - (clamav-freshclam or clamav-update)
      - (python3-pyqt6 or python3-PyQt6)
      - polkit
    recommends:
      - opensnitch
      - udisks2
      - upower
      - iproute
      - openssl
contents:
EOF
    contents_for all gui
} >"$work/deadbolt.yaml"

{
    printf 'name: deadbolt-server\n'
    common_header
    cat <<'EOF'
description: |
  Deadbolt: Track and Terminate, for headless servers. The daemon, the
  terminal UI and deadboltctl, with no GUI, file manager menus or autostart.
depends:
  - clamav
  - clamav-daemon
  - clamav-freshclam
  - polkitd
recommends:
  - opensnitch
  - iproute2
  - openssl
conflicts:
  - deadbolt
replaces:
  - deadbolt
overrides:
  rpm:
    depends:
      - clamav
      - (clamd or clamav-server)
      - (clamav-freshclam or clamav-update)
      - polkit
    recommends:
      - opensnitch
      - iproute
      - openssl
contents:
EOF
    contents_for all
} >"$work/deadbolt-server.yaml"

for pkg in deadbolt deadbolt-server; do
    for fmt in deb rpm; do
        nfpm package --config "$work/$pkg.yaml" --packager "$fmt" --target "$out/"
    done
done
printf 'build-packages: packages are in %s/\n' "$out"
