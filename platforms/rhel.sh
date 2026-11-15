#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
PLATFORM_LABEL="RHEL / Rocky / AlmaLinux / CentOS Stream"
# RHEL subscription, Rocky, Alma and Stream have distinct repos and signing keys.
# Preserve their vendor configuration; never substitute CentOS/Debian repositories.
platform_apt_policy() { return 1; }
