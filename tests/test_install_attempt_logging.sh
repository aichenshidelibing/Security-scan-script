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
      *'-6 addr show'*) printf '' ;;
      *'-4 addr show'*) printf '2: eth0 inet 192.0.2.10/24 scope global\n' ;;
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
    printf '%s\n' "$url" >>"$CURL_URLS"
    case "$url" in
      *gh-proxy.org*) return 28 ;;
      *raw.githubusercontent.com*) printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"; return 0 ;;
      *) return 28 ;;
    esac
  }
  output=$(download_script v0.sh 2>&1) || fail 'fallback download should eventually succeed'
  printf '%s' "$output" | grep -q 'trying gh-proxy.org' || fail 'download output did not show accelerator attempt'
  first_url=$(sed -n '1p' "$CURL_URLS")
  case "$first_url" in
    https://gh-proxy.org/*) : ;;
    *) fail "first attempt was not accelerator: $first_url" ;;
  esac
) || exit 1
printf 'PASS: bootstrap download output shows accelerator attempts before official raw\n'