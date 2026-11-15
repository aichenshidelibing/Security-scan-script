#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
PLATFORM_LABEL="Ubuntu LTS"
platform_apt_policy() {
    case "$SEC_OS_VERSION" in
        20.04) APT_CODENAME=focal ;;
        22.04) APT_CODENAME=jammy ;;
        24.04) APT_CODENAME=noble ;;
        26.04) APT_CODENAME=resolute ;;
        *) return 1 ;;
    esac
    APT_ARCH=$(dpkg --print-architecture) || return 1
    case "$APT_ARCH" in
        amd64|i386)
            APT_REPO=ubuntu
            APT_OFFICIAL=https://archive.ubuntu.com/ubuntu
            APT_SECURITY=https://security.ubuntu.com/ubuntu ;;
        arm64|armhf|ppc64el|riscv64|s390x)
            APT_REPO=ubuntu-ports
            APT_OFFICIAL=https://ports.ubuntu.com/ubuntu-ports
            APT_SECURITY=$APT_OFFICIAL ;;
        *) return 1 ;;
    esac
}
