#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/lib/runtime.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_success() { "$@" || fail "expected success: $*"; }
assert_failure() { "$@" && fail "expected failure: $*"; }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
export SEC_TOOLBOX_LOCK_FILE="$TMP_DIR/toolbox.lock"
export SEC_TOOLBOX_LOCK_META="$TMP_DIR/toolbox.lock.meta"

assert_success sec_toolbox_acquire_lock "test-first"
assert_failure bash -c 'source "$1"; SEC_TOOLBOX_LOCK_FILE="$2"; SEC_TOOLBOX_LOCK_META="$3"; sec_toolbox_acquire_lock second' _ "$ROOT_DIR/lib/runtime.sh" "$SEC_TOOLBOX_LOCK_FILE" "$SEC_TOOLBOX_LOCK_META"
sec_toolbox_release_lock

export SEC_TOOLBOX_PACKAGE_LOCK_FILE="$TMP_DIR/package.lock"
export SEC_TOOLBOX_PACKAGE_WAIT=2
assert_success sec_with_package_manager_lock sh -c 'exit 0'
assert_failure sec_with_package_manager_lock sh -c 'exit 7'

command() {
    if [ "$1" = "-v" ] && [ "${2:-}" = "flock" ]; then return 1; fi
    builtin command "$@"
}
export SEC_TOOLBOX_PACKAGE_LOCK_FILE="$TMP_DIR/package-fallback.lock"
assert_success sec_with_package_manager_lock sh -c 'exit 0'
[ ! -d "${SEC_TOOLBOX_PACKAGE_LOCK_FILE}.d" ] || fail "fallback package lock was not released"
unset -f command
[ ! -d "${SEC_TOOLBOX_PACKAGE_LOCK_FILE}.d" ] || fail "package fallback lock was not released"
assert_success sec_toolbox_acquire_lock "test-after-release"
sec_toolbox_release_lock
printf 'PASS: runtime lock serializes concurrent executions and releases cleanly\n'
