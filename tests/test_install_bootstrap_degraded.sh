#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  set -u
  cd "$TEST_TMP" || exit 1
  TERM=dumb
  SEC_TOOLBOX_NO_MAIN=1 source "$ROOT_DIR/install.sh"
  curl() { return 22; }
  wget() { return 4; }
  bootstrap_missing_components >/tmp/bootstrap.out 2>&1 || fail 'bootstrap should not exit or return failure when downloads are unavailable'
  grep -Eq '继续进入主菜单|跳过失败项|下载失败' /tmp/bootstrap.out || fail 'bootstrap did not explain degraded continuation'
)
printf 'PASS: bootstrap download failures do not block the main menu\n'
