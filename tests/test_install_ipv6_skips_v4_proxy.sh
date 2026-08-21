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
      *raw.githubusercontent.com*) printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"; return 0 ;;
      *) return 28 ;;
    esac
  }
  download_script v0.sh >/dev/null || fail 'pure IPv6 download should eventually use official raw fallback'
  grep -q -- '-6' "$CURL_URLS" || fail 'pure IPv6 download did not force curl -6'
  if grep -q -- 'v4.gh-proxy.org' "$CURL_URLS"; then
    fail 'pure IPv6 download attempted IPv4-only proxy'
  fi
) || exit 1
printf 'PASS: pure IPv6 bootstrap skips IPv4-only GitHub proxy\n'