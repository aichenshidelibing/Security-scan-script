#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  set -u
  cd "$TEST_TMP" || exit 1
  SEC_TOOLBOX_NO_MAIN=1 source "$ROOT_DIR/install.sh"
  printf '<SEC_SCRIPT_MARKER_v2.3>\nold-copy\n' >v0.sh
  curl() { return 28; }
  wget() { return 4; }
  if download_script v0.sh >/tmp/download.out 2>&1; then
    fail 'download unexpectedly succeeded'
  fi
  grep -q 'old-copy' v0.sh || fail 'failed download removed or overwrote existing script'
)
printf 'PASS: failed bootstrap downloads preserve existing local scripts\n'
