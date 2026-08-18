#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
(
  set -u
  export PATH="$TEST_TMP/bin:$PATH"
  mkdir -p "$TEST_TMP/bin"
  cat >"$TEST_TMP/bin/warp-cli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${WARP_CALL_LOG:?}"
case "$*" in
  'help'|'tunnel ip help'|'tunnel help') printf 'tunnel ip add <ip>\ntunnel ip list\ntunnel ip delete <ip>\n' ;;
  'status') printf 'Status update: Connected\n' ;;
  'registration show') printf 'Registration: Registered\nAccount type: Free\n' ;;
  'settings') printf 'Mode: Warp\n' ;;
  'tunnel ip list') printf '::/0\n' ;;
esac
exit 0
EOF
  chmod +x "$TEST_TMP/bin/warp-cli"
  cat >"$TEST_TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
out=''
previous=''
for arg in "$@"; do
  [ "$previous" = '-o' ] && out="$arg"
  previous="$arg"
done
printf 'ip=203.0.113.10\nwarp=on\n' >"$out"
exit 0
EOF
  chmod +x "$TEST_TMP/bin/curl"
  export WARP_CALL_LOG="$TEST_TMP/warp.calls"
  : >"$WARP_CALL_LOG"
  source <(sed '/^\[ "\$(id -u)" -eq 0/,$d' "$ROOT_DIR/v4.sh")
  id() { [ "$1" = '-u' ] && printf '0\n'; }
  warp_ipv4_only_supported || fail 'IPv4-only WARP should be detected as supported'
  warp_ipv4_only_configured || fail 'existing IPv6 exclusion was not detected'
  warp_register_connect_ipv4_only >/dev/null 2>&1 || fail 'IPv4-only setup failed'
  ! grep -q -- '^tunnel ip add ::/0$' "$WARP_CALL_LOG" || fail 'existing split route was configured twice'
)
printf 'PASS: WARP IPv4-only mode detects and preserves an existing IPv6 exclusion\n'