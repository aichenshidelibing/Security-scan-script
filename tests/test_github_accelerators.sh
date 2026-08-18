#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for needle in \
  'raw.githubusercontent.com' \
  'gh-proxy.org' \
  'v4.gh-proxy.org' \
  'v6.gh-proxy.org' \
  'cdn.gh-proxy.org' \
  'axisnow.gh-proxy.org' \
  'gh-proxy.com' \
  'curl "$family"' \
  '--connect-timeout 3' \
  'sec_github_probe_named_endpoint'; do
  grep -q -- "$needle" "$ROOT_DIR/lib/github.sh" || fail "missing GitHub accelerator marker: $needle"
done
for needle in 'GITHUB_ACCELERATOR_BASES' 'accelerators' 'download_runtime_libs' 'v4.sh'; do
  grep -q -- "$needle" "$ROOT_DIR/install.sh" || fail "install.sh missing accelerator integration marker: $needle"
done
# Fetch builds accelerator entries first and appends the official entry explicitly last.
fetch_official=$(grep -n 'entry=$(sec_github_entry_for_name official)' "$ROOT_DIR/lib/github.sh" | tail -n1 | cut -d: -f1)
fetch_loop=$(grep -n 'done < <(sec_github_endpoint_entries)' "$ROOT_DIR/lib/github.sh" | tail -n1 | cut -d: -f1)
[ -n "$fetch_official" ] && [ -n "$fetch_loop" ] && [ "$fetch_loop" -lt "$fetch_official" ] || fail 'official endpoint is not appended as the final fallback'
printf 'PASS: GitHub accelerators are preferred, IPv6-filtered, and official raw is last\n'
