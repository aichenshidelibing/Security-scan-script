#!/usr/bin/env bash
# Offline fixtures only: never run real apt, sysctl, modprobe or service changes.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ui_info() { :; }; ui_warn() { :; }; ui_ok() { :; }; ui_fail() { echo "$*" >&2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
eq() { [ "$1" = "$2" ] || fail "$3: [$1] != [$2]"; }
source "$ROOT/lib/platform.sh"
for spec in 'debian 11 debian' 'debian 12 debian' 'debian 13 debian' 'ubuntu 20.04 ubuntu' 'ubuntu 22.04 ubuntu' 'ubuntu 24.04 ubuntu' 'ubuntu 26.04 ubuntu' 'rocky 9.5 rhel' 'almalinux 10.0 rhel' 'rhel 8.10 rhel' 'centos 9 rhel'; do
    read -r id version expected <<< "$spec"
    printf 'ID=%s\nVERSION_ID=%s\n' "$id" "$version" > "$TMP/os-release"
    detect_platform "$TMP/os-release"
    eq "$SEC_PLATFORM" "$expected" 'platform mapping'
done
printf 'ID=kali\nVERSION_ID=2026.1\nID_LIKE=debian\n' > "$TMP/os-release"
if detect_platform "$TMP/os-release" 2>/dev/null; then fail 'derivative accepted'; fi
source "$ROOT/platforms/ubuntu.sh"
SEC_OS_VERSION=24.04
dpkg() { echo arm64; }
platform_apt_policy
eq "$APT_REPO" ubuntu-ports 'ARM ports repository'
eq "$APT_CODENAME" noble 'codename'
dpkg() { echo amd64; }
platform_apt_policy
eq "$APT_REPO" ubuntu 'x86 repository'
echo 'PASS: 11 platform fixtures, derivative rejection, Ubuntu ARM/x86 routing'

source "$ROOT/lib/apt.sh"
V1_DIR=$ROOT
APT_ETC="$TMP/apt"
APT_BACKUP_ROOT="$TMP/backups"
SEC_OS_ID=ubuntu
mkdir -p "$APT_ETC/sources.list.d"
cat > "$APT_ETC/sources.list.d/ubuntu.sources" <<'CONFIG'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
 noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://vendor.example/repo
Suites: stable
Components: main
Signed-By: /opt/vendor.gpg
CONFIG
printf 'deb [signed-by=/opt/vendor.gpg] https://vendor.example/repo stable main\n' > "$APT_ETC/sources.list.d/vendor.list"
cp "$APT_ETC/sources.list.d/ubuntu.sources" "$TMP/original"
cp "$APT_ETC/sources.list.d/vendor.list" "$TMP/vendor"
prepare_apt_candidate "$TMP/stage" https://mirrors.aliyun.com/ubuntu
grep -q '^URIs: https://mirrors.aliyun.com/ubuntu$' "$TMP/stage/etc/sources.list.d/ubuntu.sources"
grep -q '^URIs: https://security.ubuntu.com/ubuntu$' "$TMP/stage/etc/sources.list.d/ubuntu.sources"
grep -q '^Suites: noble-security$' "$TMP/stage/etc/sources.list.d/ubuntu.sources"
grep -q '^Signed-By: /opt/vendor.gpg$' "$TMP/stage/etc/sources.list.d/ubuntu.sources"
cmp "$TMP/vendor" "$TMP/stage/etc/sources.list.d/vendor.list"
cmp "$TMP/original" "$APT_ETC/sources.list.d/ubuntu.sources"
apt-get() { return 1; }
if commit_apt_candidate "$TMP/stage" >/dev/null 2>&1; then fail 'failed live update accepted'; fi
cmp "$TMP/original" "$APT_ETC/sources.list.d/ubuntu.sources"
[ ! -e "$APT_ETC/sources.list" ] || fail 'absent sources.list created'
apt-get() { return 0; }
commit_apt_candidate "$TMP/stage" >/dev/null
cmp "$TMP/stage/etc/sources.list.d/ubuntu.sources" "$APT_ETC/sources.list.d/ubuntu.sources"
prepare_apt_candidate "$TMP/repeat" https://mirrors.aliyun.com/ubuntu
cmp "$TMP/repeat/etc/sources.list.d/ubuntu.sources" "$APT_ETC/sources.list.d/ubuntu.sources"
# Reject incompatible suite before writing live files.
printf 'deb https://archive.ubuntu.com/ubuntu jammy main\n' > "$APT_ETC/sources.list"
if prepare_apt_candidate "$TMP/mixed" https://mirrors.aliyun.com/ubuntu 2>/dev/null; then fail 'mixed suite accepted'; fi
# Legacy format maintains options and security source; no duplicate official entry.
printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main\ndeb http://security.ubuntu.com/ubuntu noble-security main\n' > "$APT_ETC/sources.list"
prepare_apt_candidate "$TMP/legacy" https://mirrors.tuna.tsinghua.edu.cn/ubuntu
grep -q '^deb \[arch=amd64 signed-by=' "$TMP/legacy/etc/sources.list"
eq "$(grep -c '^deb ' "$TMP/legacy/etc/sources.list")" 2 'no duplicated sources'
# Ranked metadata timings: fastest candidate first, no fourth domestic vendor.
mirror_time() {
    case "$1" in *tsinghua*) echo 0.3;; *aliyun*) echo 0.1;; *tencent*) echo 0.2;; *) return 1;; esac
}
mkdir "$TMP/rank"
rank_apt_mirrors "$TMP/rank" > "$TMP/ranked"
eq "$(head -n1 "$TMP/ranked")" https://mirrors.aliyun.com/ubuntu 'ranked mirror'
eq "$(wc -l < "$TMP/ranked" | tr -d ' ')" 3 'candidate count'
# Test actual download result parsing without network or apt execution.
(
    source "$ROOT/lib/apt.sh"
    curl() {
        local out=""
        while [ "$#" -gt 0 ]; do
            if [ "$1" = -o ]; then out="$2"; shift; fi
            shift
        done
        printf '%s\n' '-----BEGIN PGP SIGNED MESSAGE-----' 'Codename: noble' 'Architectures: amd64 arm64' > "$out"
        printf 0.125
    }
    eq "$(mirror_time https://mirror.example/test "$TMP/metadata")" 0.125 'metadata probe'
    curl() { printf 0.01; return 22; }
    if mirror_time https://mirror.example/test "$TMP/metadata" >/dev/null; then fail 'HTTP error accepted'; fi
)
# Validate no original sources.list is required on Debian container images.
(
    source "$ROOT/platforms/debian.sh"
    SEC_OS_ID=debian SEC_OS_VERSION=13
    dpkg() { echo arm64; }
    platform_apt_policy
    APT_ETC="$TMP/debian-apt"
    mkdir -p "$APT_ETC/sources.list.d"
    printf 'Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' > "$APT_ETC/sources.list.d/debian.sources"
    prepare_apt_candidate "$TMP/debian-stage" https://mirrors.cloud.tencent.com/debian
    grep -q '^URIs: https://mirrors.cloud.tencent.com/debian$' "$TMP/debian-stage/etc/sources.list.d/debian.sources"
    grep -q '^Components: main non-free-firmware$' "$TMP/debian-stage/etc/sources.list.d/debian.sources"
)
# All candidates failing must leave live sources unchanged; first failing
# candidate followed by second passing candidate must commit the latter only.
(
    SEC_PLATFORM=ubuntu
    rank_apt_mirrors() { printf '%s\n' https://fast.example/ubuntu https://second.example/ubuntu; }
    validate_apt_candidate() { : > "$1/validate.log"; return 1; }
    cp "$APT_ETC/sources.list" "$TMP/before-reject"
    if apt_mirror_transaction >/dev/null 2>&1; then fail 'all invalid mirrors accepted'; fi
    cmp "$TMP/before-reject" "$APT_ETC/sources.list"
    validate_apt_candidate() {
        : > "$1/validate.log"
        grep -q 'https://second.example/ubuntu' "$1/etc/sources.list"
    }
    commit_apt_candidate() { grep -q 'https://second.example/ubuntu' "$1/etc/sources.list"; }
    apt_mirror_transaction >/dev/null
)
echo 'PASS: DEB822/list, security split, signing options, third-party preservation, rollback, Debian, metadata and candidate fallback'


source "$ROOT/lib/bbr.sh"
BBR_SYSCTL_FILE="$TMP/sysctl/bbr.conf"
BBR_BACKUP_ROOT="$TMP/bbr-backups"
state_algo=cubic state_qdisc=pfifo_fast available='reno cubic' failure=0 conflict=0 container=none
sysctl() {
    case "$*" in
        '-n net.ipv4.tcp_available_congestion_control') echo "$available";;
        '-n net.ipv4.tcp_congestion_control') echo "$state_algo";;
        '-n net.core.default_qdisc') echo "$state_qdisc";;
        '-w net.core.default_qdisc='*) state_qdisc=${2#*=};;
        '-w net.ipv4.tcp_congestion_control='*)
            if [ "$failure" = 1 ] && [[ "$2" == *=bbr* ]]; then return 1; fi
            state_algo=${2#*=};;
        *) fail "unexpected sysctl: $*";;
    esac
}
systemd-detect-virt() { echo "$container"; }
load_installed_bbr_modules() { available='reno cubic bbr bbr2 bbr3'; }
bbr_persistence_conflicts() { [ "$conflict" = 1 ]; }
enable_bbr_auto <<< 'ENABLE BBR'
eq "$state_algo" bbr3 'preferred registered algorithm'
eq "$state_qdisc" fq 'qdisc'
grep -q '= bbr3$' "$BBR_SYSCTL_FILE"
state_algo=bbr
eq "$(choose_bbr_algorithm)" bbr 'preserve current generic bbr which may be v3'
state_algo=cubic state_qdisc=pfifo_fast failure=1
cp "$BBR_SYSCTL_FILE" "$TMP/old-bbr"
if enable_bbr_auto <<< 'ENABLE BBR' >/dev/null 2>&1; then fail 'failed sysctl accepted'; fi
eq "$state_algo" cubic 'runtime algo rollback'
eq "$state_qdisc" pfifo_fast 'runtime qdisc rollback'
cmp "$TMP/old-bbr" "$BBR_SYSCTL_FILE"
failure=0 conflict=1
if enable_bbr_auto <<< 'ENABLE BBR' >/dev/null 2>&1; then fail 'conflict accepted'; fi
eq "$state_algo" cubic 'conflict no change'
conflict=0 container=docker
if enable_bbr_auto <<< 'ENABLE BBR' >/dev/null 2>&1; then fail 'container accepted'; fi
container=none
load_installed_bbr_modules() { available='reno cubic'; }
if enable_bbr_auto <<< 'ENABLE BBR' >/dev/null 2>&1; then fail 'missing BBR accepted'; fi
echo 'PASS: BBR module discovery, selection, persistence, rollback, conflicts, container and unavailable kernel'

# Installer downloads only the adapter chosen by OS detection.
(
    set +e
    source "$ROOT/install.sh"
    set -e
    cd "$ROOT"
    detect_platform() { SEC_PLATFORM=ubuntu; }
    # download_module reloads platform helper; mock source only for that helper.
    source() { if [ "$1" != ./lib/platform.sh ]; then builtin source "$@"; fi; }
    download_script() { printf '%s\n' "$1" >> "$TMP/downloaded"; }
    download_module v1.sh
    grep -qx platforms/ubuntu.sh "$TMP/downloaded"
    if grep -qE 'platforms/(debian|rhel)' "$TMP/downloaded"; then fail 'unneeded adapter downloaded'; fi
)
echo 'PASS: installer downloads the selected adapter only'
for f in "$ROOT"/*.sh "$ROOT"/lib/*.sh "$ROOT"/platforms/*.sh "$ROOT"/tests/*.sh; do bash -n "$f"; done
awk -f "$ROOT/lib/apt-rewrite.awk" /dev/null
echo 'All platform/APT/BBR tests passed.'
