#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for needle in \
  'pkg.cloudflareclient.com' \
  'registration new' \
  'mode warp' \
  'sec_with_package_manager_lock' \
  '--max-time 20' \
  'WARP 全隧道' \
  '不是公网 IPv4 地址'; do
  grep -q -- "$needle" "$ROOT_DIR/v4.sh" || fail "missing WARP hardening marker: $needle"
done
# The executable only calls menu after installing the shared lock; no direct connect call exists at top level.
grep -q '^warp_register_connect$' "$ROOT_DIR/v4.sh" && fail 'WARP connect is called at top level'
printf 'PASS: WARP uses official source, bounded commands, and explicit full-tunnel action\n'
