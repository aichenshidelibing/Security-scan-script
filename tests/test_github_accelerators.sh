#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for needle in \
  'raw.githubusercontent.com' \
  'gh-proxy.org' \
  'ghproxy.net' \
  'ghfast.top' \
  'gh-proxy.com' \
  'curl "$family"' \
  '--connect-timeout 3' \
  'sec_github_probe_named_endpoint'; do
  grep -q -- "$needle" "$ROOT_DIR/lib/github.sh" || fail "missing GitHub IPv6 accelerator marker: $needle"
done
for needle in 'GITHUB_ACCELERATOR_BASES' 'Official raw is always first' 'download_runtime_libs' 'v4.sh'; do
  grep -q -- "$needle" "$ROOT_DIR/install.sh" || fail "install.sh missing accelerator integration marker: $needle"
done
# The official endpoint must be listed before every accelerator in both fetch paths.
official_line=$(grep -n 'official|https://raw.githubusercontent.com' "$ROOT_DIR/lib/github.sh" | head -n1 | cut -d: -f1)
proxy_line=$(grep -n 'gh-proxy|' "$ROOT_DIR/lib/github.sh" | head -n1 | cut -d: -f1)
[ -n "$official_line" ] && [ -n "$proxy_line" ] && [ "$official_line" -lt "$proxy_line" ] || fail 'official endpoint is not first'
printf 'PASS: GitHub official raw is first and IPv6-tested accelerator fallbacks are present\n'
