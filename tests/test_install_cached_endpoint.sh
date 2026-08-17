#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  set -u
  cd "$TEST_TMP" || exit 1
  source <(sed '/^# --- 前置检查 ---/,$d' "$ROOT_DIR/install.sh")
  SEC_GITHUB_ENDPOINT_FILE="$TEST_TMP/selected"
  printf 'ghfast\n' >"$SEC_GITHUB_ENDPOINT_FILE"
  ip() {
    case "$*" in
      *'-6 addr show'*) printf '2: eth0 inet6 2001:db8::10/64 scope global\n' ;;
      *'-4 addr show'*) printf '' ;;
      *) return 1 ;;
    esac
  }
  CURL_URLS="$TEST_TMP/urls"
  : >"$CURL_URLS"
  curl() {
    local out='' previous='' arg url=''
    for arg in "$@"; do
      [ "$previous" = '-o' ] && out="$arg"
      url="$arg"
      previous="$arg"
    done
    printf '%s\n' "$*" >>"$CURL_URLS"
    case "$url" in
      *ghfast.top*) printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"; return 0 ;;
      *) return 22 ;;
    esac
  }
  download_script v0.sh >/dev/null || fail 'cached fallback bootstrap download failed'
  grep -q -- 'ghfast.top/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main/v0.sh' "$CURL_URLS" || fail 'cached fallback URL was not attempted'  || fail 'cached fallback was not tried before other accelerators'
  grep -q -- '-6' "$CURL_URLS" || fail 'pure IPv6 bootstrap did not force curl -6'
)
printf 'PASS: bootstrap download reuses the validated GitHub fallback on pure IPv6\n'