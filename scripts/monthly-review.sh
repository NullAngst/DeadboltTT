#!/usr/bin/env bash
# Monthly security and code review, the automatic half.
# Runs the checks from docs/MONTHLY_REVIEW.md and writes a dated report
# skeleton to docs/reviews/YYYY-MM.md. You fill in the manual parts and
# commit the report.
#
#   cd DeadboltTT
#   ./scripts/monthly-review.sh
set -euo pipefail

LC_ALL=C
export LC_ALL

die() {
    printf 'monthly-review: %s\n' "$*" >&2
    exit 1
}

required=(cargo git date mkdir tee)
missing=()
for cmd in "${required[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
[ "${#missing[@]}" -eq 0 ] || die "missing commands: ${missing[*]}"

root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this inside the DeadboltTT checkout"
cd -- "$root" || exit 1

month="$(date +%Y-%m)"
report="docs/reviews/$month.md"
mkdir -p docs/reviews
if [ -e "$report" ]; then
    die "$report already exists. Move it aside if you want to run the review again."
fi

bold=""
plain=""
if [ -t 1 ]; then
    bold="$(printf '\033[1m')"
    plain="$(printf '\033[0m')"
fi

failures=()
tick='`'

# section TITLE CMD...: run a command, record its output and exit code in the report.
section() {
    local title="$1"
    shift
    printf '%s== %s%s\n' "$bold" "$title" "$plain"
    {
        printf '\n### %s\n\n' "$title"
        printf '%s%s%s\n\n' "$tick" "$*" "$tick"
        printf '```\n'
    } >>"$report"
    local rc=0
    "$@" >>"$report" 2>&1 || rc=$?
    {
        printf '```\n\n'
        printf 'Exit code: %s\n' "$rc"
    } >>"$report"
    if [ "$rc" -ne 0 ]; then
        failures+=("$title (exit $rc)")
    fi
}

# optional TOOL TITLE CMD...: like section, but notes a missing tool instead of failing.
optional() {
    local tool="$1"
    shift
    if command -v "$tool" >/dev/null 2>&1; then
        section "$@"
    else
        printf '\n### %s\n\n%s is not installed here, so this was skipped. Install it and re-run, or do it by hand.\n' \
            "$1" "$tool" >>"$report"
        failures+=("$1 (skipped: no $tool)")
    fi
}

{
    printf '# Monthly review %s\n\n' "$month"
    printf 'Reviewer: \n\n'
    printf 'Started: %s\n\n' "$(date)"
    printf 'Open items from last month: read the previous report'"'"'s Open list first.\n\n'
    printf '## 1. Automatic checks\n'
} >"$report"

section "cargo update" cargo update
section "cargo audit" cargo audit
section "cargo deny check" cargo deny check
optional cargo-outdated "cargo outdated (direct dependencies)" cargo outdated --root-deps-only
optional pip-audit "pip-audit (GUI dependencies)" pip-audit --requirement gui/requirements-audit.txt
section "cargo test" cargo test
optional pytest "pytest gui/" env QT_QPA_PLATFORM=offscreen pytest gui/
optional shellcheck "shellcheck" shellcheck tools/deadbolt-shield-test scripts/monthly-review.sh \
    packaging/build-packages.sh packaging/install.sh packaging/uninstall.sh \
    packaging/scripts/postinstall.sh packaging/scripts/preremove.sh packaging/scripts/postremove.sh
optional clamd "clamd version" clamd --version
optional freshclam "freshclam version and signature date" freshclam --version
optional systemctl "freshclam service status" systemctl --no-pager status clamav-freshclam.service
optional opensnitchd "OpenSnitch version" opensnitchd -version
optional systemd-analyze "systemd-analyze security deadboltd" systemd-analyze security --no-pager deadboltd.service
optional systemd-analyze "systemd-analyze security deadbolt-worker" systemd-analyze security --no-pager deadbolt-worker.service
section "Permissions on /var/lib/deadbolt" ls -ld /var/lib/deadbolt /var/lib/deadbolt/quarantine
optional findmnt "Quarantine mount options" findmnt /var/lib/deadbolt/quarantine
section "Changes this month" git log --since="1 month ago" --stat

{
    printf '\n## 2. Check upstream\n\n'
    printf -- '- [ ] ClamAV: installed vs latest release, security notes, branch end of life\n'
    printf -- '- [ ] OpenSnitch: releases and issue tracker, rule-matching bugs or bypasses\n'
    printf -- '- [ ] Rust toolchain: rustup update, rebuild, rerun tests\n'
    printf -- '- [ ] GitHub Actions: each uses: line, new majors or security notices\n'
    printf -- '- [ ] Kernel: running version, dashboard still says blocking\n'
    printf '\n## 3. Code review pass\n\n'
    printf -- '- [ ] Read every file in the change list above\n'
    printf -- '- [ ] grep -rn unsafe crates/: only deadbolt-shield/src/sys.rs, each with a soundness comment\n'
    printf -- '- [ ] polkit_coverage test ran and passed (it is in cargo test above)\n'
    printf -- '- [ ] Paths: file actions go through descriptors, no std::fs on client-supplied paths\n'
    printf -- '- [ ] Subprocesses: grep -rn "Command::new\\|subprocess" crates/ gui/, argument vectors only\n'
    printf -- '- [ ] Parsers reject oversized or malformed input (settings, clamd replies, virus-event socket, OpenSnitch log)\n'
    printf -- '- [ ] Quarantine move and restore: inode check, no overwrite, execute bit stripped\n'
    printf -- '- [ ] Worker socket still root-only, worker still refuses non-root peers\n'
    printf -- '- [ ] OpenSnitch rules built from structs, regex data escaped\n'
    printf '\n## 4. Running system\n\n'
    printf -- '- [ ] systemd-analyze security still under 4.0 for both services\n'
    printf -- '- [ ] Quarantine folder 0700 root:root, mounted noexec,nosuid,nodev\n'
    printf -- '- [ ] polkit policy unchanged: dpkg -V deadbolt (or rpm -V deadbolt)\n'
    printf -- '- [ ] Canary files present and unchanged: deadboltctl shield canaries\n'
    printf -- '- [ ] Allowlist: nothing stale, all root-owned, no interpreters\n'
    printf -- '- [ ] Exclusions: drop the ones no longer needed\n'
    printf -- '- [ ] ls /etc/opensnitchd/rules/*deadbolt-* matches the Network page\n'
    printf '\n## 5. Logs\n\n'
    printf -- '- [ ] Repeat detections of the same file or signature\n'
    printf -- '- [ ] Shield near misses (scores 50 to 99): deadboltctl history --kind shield\n'
    printf -- '- [ ] Any queue overflow or clamonacc errors\n'
    printf -- '- [ ] Quarantine: purge confirmed bad, report false positives\n'
    printf '\n## 6. Live tests\n\n'
    printf -- '- [ ] deadboltctl test eicar passes\n'
    printf -- '- [ ] deadboltctl test shield passes\n'
    printf -- '- [ ] Block and unblock one app, confirm with curl or the app itself\n'
    printf '\n## 7. Close out\n\n'
    printf 'Updated:\n\nFound:\n\nFixed:\n\nDeferred (and why):\n\nOpen (with dates):\n\n'
    printf 'If anything was fixed, tag a release so the packages rebuild with current dependencies.\n'
} >>"$report"

printf '\nReport skeleton: %s\n' "$report"
if [ "${#failures[@]}" -gt 0 ]; then
    printf 'Needs a look:\n' >&2
    for f in "${failures[@]}"; do
        printf '  %s\n' "$f" >&2
    done
    {
        printf '\n## Automatic checks that need a look\n\n'
        for f in "${failures[@]}"; do
            printf -- '- %s\n' "$f"
        done
    } >>"$report"
fi
