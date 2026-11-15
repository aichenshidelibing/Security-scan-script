#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# Detect by explicit distribution ID; never treat an arbitrary derivative as Debian.
detect_platform() {
    local release_file="${1:-/etc/os-release}" data major
    [ -r "$release_file" ] || { echo '无法读取 os-release。' >&2; return 1; }
    data=$(
        . "$release_file"
        printf '%s\n' "${ID:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
    ) || return 1
    local -a fields
    mapfile -t fields <<< "$data"
    SEC_OS_ID=${fields[0]:-}
    SEC_OS_VERSION=${fields[1]:-}
    SEC_OS_CODENAME=${fields[2]:-}
    SEC_PLATFORM=""
    major=${SEC_OS_VERSION%%.*}
    case "$SEC_OS_ID:$SEC_OS_VERSION" in
        debian:11|debian:12|debian:13) SEC_PLATFORM=debian ;;
        ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) SEC_PLATFORM=ubuntu ;;
        rocky:*|almalinux:*|rhel:*|centos:9|centos:10)
            case "$major" in 8|9|10) SEC_PLATFORM=rhel;; *) return 1;; esac ;;
        *) echo "尚未适配系统: $SEC_OS_ID $SEC_OS_VERSION；拒绝套用其他发行版的软件源。" >&2; return 1 ;;
    esac
    SEC_ARCH=$(uname -m)
    export SEC_PLATFORM SEC_OS_ID SEC_OS_VERSION SEC_OS_CODENAME SEC_ARCH
}
load_platform_adapter() {
    local base="$1"
    detect_platform || return 1
    [ -f "$base/platforms/$SEC_PLATFORM.sh" ] || {
        echo "缺少 $SEC_PLATFORM 适配文件，请从 install.sh 下载/更新 v1。" >&2; return 1;
    }
    # shellcheck source=/dev/null
    source "$base/platforms/$SEC_PLATFORM.sh"
}
