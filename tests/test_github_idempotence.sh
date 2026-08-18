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
  SEC_GITHUB_CACHE_TTL=600
  sec_detect_ip_mode() { printf 'pure_ipv6\n'; }
  CURL_CALLS="$TEST_TMP/curl.calls"
  STDERR_LOG="$TEST_TMP/stderr"
  : >"$CURL_CALLS"
  curl() {
    local out='' previous='' arg url=''
    for arg in "$@"; do
      [ "$previous" = '-o' ] && out="$arg"
      url="$arg"
      previous="$arg"
    done
    printf '%s\n' "$url" >>"$CURL_CALLS"
    printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"
    return 0
  }

  sec_github_prepare_endpoint gh-proxy 2>"$STDERR_LOG" || fail 'first endpoint preparation failed'
  [ ! -s "$STDERR_LOG" ] || fail 'endpoint preparation emitted an unbound-variable error'
  [ "$(wc -l <"$CURL_CALLS")" -eq 3 ] || fail 'first preparation should probe three rounds'
  [ "$(cat "$SEC_GITHUB_ENDPOINT_FILE")" = 'gh-proxy' ] || fail 'selected endpoint was not persisted'
  sec_github_prepare_endpoint gh-proxy 2>"$STDERR_LOG" || fail 'cached endpoint preparation failed'
  [ ! -s "$STDERR_LOG" ] || fail 'cached endpoint preparation emitted an error'
  [ "$(wc -l <"$CURL_CALLS")" -eq 3 ] || fail 'fresh cached endpoint was probed again'
)
printf 'PASS: GitHub endpoint configuration is validated, cached, and idempotent\n'