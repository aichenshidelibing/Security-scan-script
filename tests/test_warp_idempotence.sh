#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
MOCK_BIN="$TEST_TMP/bin"
mkdir -p "$MOCK_BIN"
cat >"$MOCK_BIN/warp-cli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${WARP_CALL_LOG:?}"
case "$1 $2" in
  'status ') printf 'Status update: Connected\n' ;;
  'registration show') printf 'Registration: Registered\nAccount type: Free\n' ;;
  'settings ') printf 'Mode: Warp\n' ;;
esac
exit 0
EOF
cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
[ "$1" = is-active ] && exit 0
exit 0
EOF
cat >"$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env bash
out=''
previous=''
for arg in "$@"; do
  [ "$previous" = '-o' ] && out="$arg"
  previous="$arg"
done
[ -n "$out" ] && printf 'ip=203.0.113.10\nwarp=on\n' >"$out"
exit 0
EOF
chmod +x "$MOCK_BIN"/*
(
  set -u
  export PATH="$MOCK_BIN:$PATH"
  export WARP_CALL_LOG="$TEST_TMP/warp.calls"
  : >"$WARP_CALL_LOG"
  # Load v4 functions without entering the root-only interactive menu.
  source <(sed '/^\[ "\$(id -u)" -eq 0/,$d' "$ROOT_DIR/v4.sh")
  id() { [ "$1" = '-u' ] && printf '0\n'; }
  state=$(warp_needs_action || true)
  [ "$state" = 'none' ] || fail "healthy WARP state was reported as $state"
  warp_register_connect >/dev/null 2>&1 || fail 'idempotent WARP run failed'
  grep -q -- 'registration show' "$WARP_CALL_LOG" || fail 'registration state was not checked'
  grep -q -- 'settings' "$WARP_CALL_LOG" || fail 'WARP mode was not checked'
  ! grep -Eq 'registration new|^mode warp$|^mode warp\+doh$|^connect$' "$WARP_CALL_LOG" || fail 'healthy WARP was reconfigured'
)
printf 'PASS: healthy WARP state skips registration, mode changes, and reconnect\n'