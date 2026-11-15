#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
PLATFORM_LABEL="Debian"
platform_apt_policy() {
    APT_REPO=debian
    APT_OFFICIAL=https://deb.debian.org/debian
    APT_SECURITY=https://security.debian.org/debian-security
    case "$SEC_OS_VERSION" in
        11) APT_CODENAME=bullseye ;;
        12) APT_CODENAME=bookworm ;;
        13) APT_CODENAME=trixie ;;
        *) return 1 ;;
    esac
    APT_ARCH=$(dpkg --print-architecture) || return 1
    [[ "$APT_ARCH" =~ ^[a-z0-9]+$ ]]
}
