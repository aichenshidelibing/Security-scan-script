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
  SEC_GITHUB_PROBE_ROUNDS=3
  SEC_GITHUB_PROBE_MIN_SUCCESS=2
  sec_detect_ip_mode() { printf 'pure_ipv6\n'; }
  CURL_CALLS="$TEST_TMP/calls"
  : >"$CURL_CALLS"
  curl() {
    local out='' previous='' arg url=''
    for arg in "$@"; do
      [ "$previous" = '-o' ] && out="$arg"
      url="$arg"
      previous="$arg"
    done
    printf '%s\n' "$url" >>"$CURL_CALLS"
    case "$url" in
      *v6.gh-proxy.org*|*gh-proxy.com*) printf '<SEC_SCRIPT_MARKER_v2.3>\n' >"$out"; return 0 ;;
      *) return 22 ;;
    esac
  }
  sec_github_probe_all >/dev/null || fail 'probe all failed'
  sec_github_auto_select || fail 'auto select failed'
  selected=$(cat "$SEC_GITHUB_ENDPOINT_FILE")
  [ "$(printf '%s\n' "$selected" | sed -n '1p')" = 'gh-proxy-v6' ] || fail "unexpected primary auto selection: $selected"
  [ "$(wc -l <"$CURL_CALLS")" -ge 6 ] || fail 'multi-round probe did not run'
  sec_github_set_endpoints gh-proxy-v6 gh-proxy-com || fail 'multi endpoint save failed'
  [ "$(sed -n '1p' "$SEC_GITHUB_ENDPOINT_FILE")" = 'gh-proxy-v6' ] || fail 'primary endpoint missing'
  [ "$(sed -n '2p' "$SEC_GITHUB_ENDPOINT_FILE")" = 'gh-proxy-com' ] || fail 'secondary endpoint missing'
  sec_github_set_endpoints gh-proxy-v6 gh-proxy-v6 gh-proxy-com || fail 'duplicate endpoint save failed'
  [ "$(wc -l <"$SEC_GITHUB_ENDPOINT_FILE")" -eq 2 ] || fail 'duplicate endpoint was not removed'
  release_url='https://github.com/fatedier/frp/releases/download/v0.54.0/frp_0.54.0_linux_amd64.tar.gz'
  axis_url=$(sec_github_endpoint_url "$(sec_github_entry_for_name axisnow)" "$release_url")
  [ "$axis_url" = "https://axisnow.gh-proxy.org/$release_url" ] || fail "axisnow full URL expansion is wrong: $axis_url"
  official_url=$(sec_github_endpoint_url "$(sec_github_entry_for_name official)" "$release_url")
  [ "$official_url" = "$release_url" ] || fail "official full URL expansion is wrong: $official_url"
)
printf 'PASS: GitHub auto selection uses multiple IPv6-compatible endpoints and preserves priority list\n'
