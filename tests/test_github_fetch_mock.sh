#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  set -u
  . "$ROOT_DIR/lib/network_checks.sh"
  . "$ROOT_DIR/lib/github.sh"
  SEC_GITHUB_ENDPOINT_FILE="$TEST_TMP/selected"
  ip() {
    case "$*" in
      *'-6 addr show'*) printf '2: eth0 inet6 2001:db8::10/64 scope global\n' ;;
      *'-4 addr show'*) printf '' ;;
      *) return 1 ;;
    esac
  }
  curl() {
    local out='' previous='' arg url=''
    for arg in "$@"; do
      [ "$previous" = '-o' ] && out="$arg"
      url="$arg"
      previous="$arg"
    done
    printf '%s\n' "$*" >>"$TEST_TMP/curl.args"
    case "$url" in
      *gh-proxy.org*) printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"; return 0 ;;
      *) return 22 ;;
    esac
  }
  output="$TEST_TMP/out"
  sec_github_fetch 'aichenshidelibing/Security-scan-script/main/install.sh' "$output" '<SEC_SCRIPT_MARKER_v2.3>' || fail 'fallback fetch failed'
  grep -q -- '-6' "$TEST_TMP/curl.args" || fail 'IPv6 family was not forced'
  grep -q -- 'raw.githubusercontent.com' "$TEST_TMP/curl.args" || fail 'official raw was not attempted'
  grep -q -- 'gh-proxy.org' "$TEST_TMP/curl.args" || fail 'accelerator fallback was not attempted'
  grep -q -- '<SEC_SCRIPT_MARKER_v2.3>' "$output" || fail 'download marker missing'
)
printf 'PASS: GitHub fallback retries after official failure and forces IPv6 in pure IPv6 mode\n'
