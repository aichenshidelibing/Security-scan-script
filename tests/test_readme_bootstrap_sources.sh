#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
README="$ROOT_DIR/README.md"
grep -q -- '推荐：多源自动拉取' "$README" || fail 'README does not promote multi-source bootstrap as the default quick start'
grep -q -- 'https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh' "$README" || fail 'README bootstrap missing gh-proxy.org source'
grep -q -- 'https://v6.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh' "$README" || fail 'README bootstrap missing IPv6 accelerator source'
grep -q -- 'https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh' "$README" || fail 'README bootstrap missing official raw final fallback'
printf 'PASS: README quick start documents multi-source bootstrap before official raw fallback\n'
