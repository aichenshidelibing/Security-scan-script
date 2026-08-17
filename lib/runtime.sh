#!/usr/bin/env bash
# Shared runtime helpers for the Linux Security Toolbox.
# This file deliberately does not enable set -e: callers decide their error policy.

sec_toolbox_lock_file_default() {
    if [ -d /run/lock ] && [ -w /run/lock ]; then
        printf '%s\n' /run/lock/sec-toolbox.lock
    else
        printf '%s\n' "${TMPDIR:-/tmp}/sec-toolbox.lock"
    fi
}

sec_toolbox_acquire_lock() {
    local owner="${1:-security-toolbox}"
    SEC_TOOLBOX_LOCK_FILE="${SEC_TOOLBOX_LOCK_FILE:-$(sec_toolbox_lock_file_default)}"
    SEC_TOOLBOX_LOCK_META="${SEC_TOOLBOX_LOCK_META:-${SEC_TOOLBOX_LOCK_FILE}.meta}"
    mkdir -p "$(dirname -- "$SEC_TOOLBOX_LOCK_FILE")" 2>/dev/null || return 1

    if command -v flock >/dev/null 2>&1; then
        # Keep the descriptor open for the lifetime of the process. Do not use a
        # lock-file existence check: the file is expected to remain after exit.
        exec {SEC_TOOLBOX_LOCK_FD}>"$SEC_TOOLBOX_LOCK_FILE" || return 1
        if ! flock -n "$SEC_TOOLBOX_LOCK_FD"; then
            local holder=""
            [ -r "$SEC_TOOLBOX_LOCK_META" ] && holder=$(cat "$SEC_TOOLBOX_LOCK_META" 2>/dev/null || true)
            printf '[lock] another toolbox process is already running%s\n' \
                "${holder:+ (owner: $holder)}" >&2
            eval "exec ${SEC_TOOLBOX_LOCK_FD}>&-"
            unset SEC_TOOLBOX_LOCK_FD
            return 1
        fi
        printf '%s pid=%s\n' "$owner" "$$" >"$SEC_TOOLBOX_LOCK_META" 2>/dev/null || true
        SEC_TOOLBOX_LOCK_MODE=flock
        return 0
    fi

    # Fallback for minimal systems without util-linux flock. mkdir is atomic;
    # recover only a lock whose recorded PID is no longer alive.
    SEC_TOOLBOX_LOCK_DIR="${SEC_TOOLBOX_LOCK_FILE}.d"
    if ! mkdir "$SEC_TOOLBOX_LOCK_DIR" 2>/dev/null; then
        local pid=""
        [ -r "$SEC_TOOLBOX_LOCK_DIR/pid" ] && pid=$(cat "$SEC_TOOLBOX_LOCK_DIR/pid" 2>/dev/null || true)
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            rm -f -- "$SEC_TOOLBOX_LOCK_DIR/pid" 2>/dev/null || true
            rmdir -- "$SEC_TOOLBOX_LOCK_DIR" 2>/dev/null || true
        fi
        mkdir "$SEC_TOOLBOX_LOCK_DIR" 2>/dev/null || {
            printf '[lock] another toolbox process is already running%s\n' \
                "${pid:+ (pid: $pid)}" >&2
            return 1
        }
    fi
    printf '%s\n' "$$" >"$SEC_TOOLBOX_LOCK_DIR/pid"
    printf '%s pid=%s\n' "$owner" "$$" >"$SEC_TOOLBOX_LOCK_META" 2>/dev/null || true
    SEC_TOOLBOX_LOCK_MODE=mkdir
    return 0
}

sec_toolbox_release_lock() {
    case "${SEC_TOOLBOX_LOCK_MODE:-}" in
        flock)
            if [ -n "${SEC_TOOLBOX_LOCK_FD:-}" ]; then
                flock -u "$SEC_TOOLBOX_LOCK_FD" 2>/dev/null || true
                eval "exec ${SEC_TOOLBOX_LOCK_FD}>&-" 2>/dev/null || true
            fi
            ;;
        mkdir)
            if [ -n "${SEC_TOOLBOX_LOCK_DIR:-}" ] && [ -r "$SEC_TOOLBOX_LOCK_DIR/pid" ] &&
               [ "$(cat "$SEC_TOOLBOX_LOCK_DIR/pid" 2>/dev/null || true)" = "$$" ]; then
                rm -f -- "$SEC_TOOLBOX_LOCK_DIR/pid" 2>/dev/null || true
                rmdir -- "$SEC_TOOLBOX_LOCK_DIR" 2>/dev/null || true
            fi
            ;;
    esac
    if [ -n "${SEC_TOOLBOX_LOCK_META:-}" ] && [ -r "$SEC_TOOLBOX_LOCK_META" ] &&
       grep -q "pid=$$" "$SEC_TOOLBOX_LOCK_META" 2>/dev/null; then
        rm -f -- "$SEC_TOOLBOX_LOCK_META" 2>/dev/null || true
    fi
    unset SEC_TOOLBOX_LOCK_MODE SEC_TOOLBOX_LOCK_FD SEC_TOOLBOX_LOCK_DIR
}

sec_package_manager_busy() {
    local name pid
    for name in apt apt-get dpkg unattended-upgrade apt.systemd.daily dnf yum rpm; do
        if command -v pgrep >/dev/null 2>&1; then
            pgrep -x "$name" >/dev/null 2>&1 && return 0
        else
            for pid in /proc/[0-9]*; do
                [ -r "$pid/comm" ] || continue
                [ "$(cat "$pid/comm" 2>/dev/null || true)" = "$name" ] && return 0
            done
        fi
    done
    return 1
}

sec_wait_for_package_manager() {
    local wait_seconds="${1:-90}" elapsed=0
    while sec_package_manager_busy; do
        if [ "$elapsed" -ge "$wait_seconds" ]; then
            printf '[lock] package manager is still active after %ss\n' "$wait_seconds" >&2
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 0
}

sec_with_package_manager_lock() {
    [ "$#" -gt 0 ] || return 2
    local lock_file="${SEC_TOOLBOX_PACKAGE_LOCK_FILE:-$(sec_toolbox_lock_file_default | sed 's/\.lock$/-package.lock/')}"
    local lock_fd="" lock_dir="" status pid elapsed=0
    local wait_seconds="${SEC_TOOLBOX_PACKAGE_WAIT:-90}"

    mkdir -p "$(dirname -- "$lock_file")" 2>/dev/null || return 1
    sec_wait_for_package_manager "$wait_seconds" || return 1

    if command -v flock >/dev/null 2>&1; then
        exec {lock_fd}>"$lock_file" || return 1
        if ! flock -w "$wait_seconds" "$lock_fd"; then
            printf '[lock] unable to acquire toolbox package-manager lock\n' >&2
            eval "exec ${lock_fd}>&-"
            return 1
        fi
    else
        # Minimal images may not ship util-linux/flock. Use an atomic mkdir
        # lock and recover only locks whose recorded PID is no longer alive.
        lock_dir="${lock_file}.d"
        while ! mkdir "$lock_dir" 2>/dev/null; do
            pid=""
            [ -r "$lock_dir/pid" ] && pid=$(cat "$lock_dir/pid" 2>/dev/null || true)
            if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
                rm -f -- "$lock_dir/pid" 2>/dev/null || true
                rmdir -- "$lock_dir" 2>/dev/null || true
                continue
            fi
            if [ "$elapsed" -ge "$wait_seconds" ]; then
                printf '[lock] unable to acquire toolbox package-manager lock\n' >&2
                return 1
            fi
            sleep 1
            elapsed=$((elapsed + 1))
        done
        printf '%s\n' "$$" >"$lock_dir/pid"
    fi

    # Re-check after acquiring the toolbox lock to close the check/start race.
    sec_wait_for_package_manager "$wait_seconds"
    if [ "$?" -ne 0 ]; then
        if [ -n "$lock_fd" ]; then
            flock -u "$lock_fd" 2>/dev/null || true
            eval "exec ${lock_fd}>&-"
        fi
        if [ -n "$lock_dir" ] && [ -r "$lock_dir/pid" ] &&
           [ "$(cat "$lock_dir/pid" 2>/dev/null || true)" = "$$" ]; then
            rm -f -- "$lock_dir/pid" 2>/dev/null || true
            rmdir -- "$lock_dir" 2>/dev/null || true
        fi
        return 1
    fi

    "$@"
    status=$?

    if [ -n "$lock_fd" ]; then
        flock -u "$lock_fd" 2>/dev/null || true
        eval "exec ${lock_fd}>&-"
    fi
    if [ -n "$lock_dir" ] && [ -r "$lock_dir/pid" ] &&
       [ "$(cat "$lock_dir/pid" 2>/dev/null || true)" = "$$" ]; then
        rm -f -- "$lock_dir/pid" 2>/dev/null || true
        rmdir -- "$lock_dir" 2>/dev/null || true
    fi
    return "$status"
}
