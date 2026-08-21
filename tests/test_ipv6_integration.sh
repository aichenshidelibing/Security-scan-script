#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for needle in \
  'net.ipv6.icmp.echo_ignore_all' \
  'icmpv6 type echo-request drop' \
  'ip6tables' \
  'before6.rules' \
  'sec_toolbox_acquire_lock'; do
  grep -q -- "$needle" "$ROOT_DIR/v3.sh" "$ROOT_DIR/v1.sh" "$ROOT_DIR/v2.sh" "$ROOT_DIR/lib/runtime.sh" 2>/dev/null || fail "missing IPv6/lock support marker: $needle"
done
printf 'PASS: IPv6 ICMP and shared lock integration markers are present\n'
for needle in 'raw.githubusercontent.com' 'GITHUB_FALLBACK_BASE' 'download_family_args' 'curl "$target_family"' 'wget "$target_family"' 'download_runtime_libs'; do
  grep -q -- "$needle" "$ROOT_DIR/install.sh" 2>/dev/null || fail "missing IPv6 download marker: $needle"
done
grep -q -- 'sec_toolbox_release_lock' "$ROOT_DIR/v0.sh" || fail "v0.sh does not release the shared lock"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  cd "$TEST_TMP" || exit 1
  # Load install.sh function definitions without entering its root-only menu.
  SEC_TOOLBOX_NO_MAIN=1 source "$ROOT_DIR/install.sh"
  ip() {
    case "$*" in
      *"-6 addr show"*) printf '2: eth0    inet6 2001:db8::10/64 scope global\n' ;;
      *"-4 addr show"*) printf '' ;;
      *) return 1 ;;
    esac
  }
  curl() {
    local out='' previous='' arg
    for arg in "$@"; do
      [ "$previous" = '-o' ] && out="$arg"
      previous="$arg"
    done
    printf '%s\n' "$*" > "$TEST_TMP/curl.args"
    printf '%s\n' '<SEC_SCRIPT_MARKER_v2.3>' > "$out"
  }
  [ "$(download_family_args)" = '-6' ] || fail 'pure IPv6 download family was not selected'
  download_script v3.sh >/dev/null || fail 'stubbed pure IPv6 download failed'
  grep -q -- '-6' "$TEST_TMP/curl.args" || fail 'curl was not forced to IPv6'
)
