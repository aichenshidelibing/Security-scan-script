#!/usr/bin/env bash
# No package installation, service changes, real swap, or external network.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
source "$ROOT/v5.sh"
ui_info() { :; }; ui_ok() { :; }; ui_warn() { :; }; ui_fail() { echo "$*" >&2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
eq() { [ "$1" = "$2" ] || fail "$3: got [$1], expected [$2]"; }

calculate_swap_plan 1024 0 20000 30000
eq "$SWAP_RECOMMENDED" 2048 'small RAM target'
calculate_swap_plan 4096 1024 20000 30000
eq "$SWAP_RECOMMENDED" 3072 'subtract active swap'
calculate_swap_plan 65536 16384 20000 30000
eq "$SWAP_RECOMMENDED" 0 'already sufficient'
calculate_swap_plan 4096 0 2500 10000
eq "$SWAP_RECOMMENDED" 256 'disk constrained recommendation'
calculate_swap_plan 4096 0 1500 10000
eq "$SWAP_MAX" 0 'reserved free space'
echo 'PASS: Swap sizing, existing swap, low disk and reserve policy'

# Every privileged operation is replaced before the transaction is called.
swap_fixture() {
    SWAP_DIR="$TMP/swap-$1"
    SWAP_FILE="$SWAP_DIR/swapfile"
    SWAP_FSTAB="$TMP/fstab-$1"
    SWAP_BACKUPS="$TMP/backups-$1"
    SWAP_PROC="$TMP/proc-swaps-$1"
    printf '# original\nUUID=example / ext4 defaults 0 1\n' > "$SWAP_FSTAB"
    printf 'Filename Type Size Used Priority\n' > "$SWAP_PROC"
    cp "$SWAP_FSTAB" "$SWAP_FSTAB.original"
}
(
    systemd-detect-virt() { echo none; }
    systemctl() { return 0; }
    swap_reload_systemd() { return 0; }
    findmnt() { echo ext4; }
    read_swap_plan() { SWAP_RAM=1024 SWAP_EXISTING=0 SWAP_FREE=10000; calculate_swap_plan 1024 0 10000 20000; }
    dd() { printf 'test-allocated-bytes\n' >> "$SWAP_FILE"; }
    mkswap() { return 0; }
    swapon() { printf '%s file 262144 0 -2\n' "$SWAP_FILE" >> "$SWAP_PROC"; }
    swapoff() { printf 'Filename Type Size Used Priority\n' > "$SWAP_PROC"; }
    swap_fixture success
    create_swap <<< $'256\nCREATE SWAP'
    swap_file_active || fail 'swap not active'
    eq "$(stat -c %a "$SWAP_FILE")" 600 'private swap file'
    grep -qF "$SWAP_FILE none swap sw 0 0" "$SWAP_FSTAB"
    before=$(sha256sum "$SWAP_FILE")
    if create_swap <<< $'512\nCREATE SWAP' 2>/dev/null; then fail 'existing swap overwritten'; fi
    eq "$(sha256sum "$SWAP_FILE")" "$before" 'existing file unchanged'
    swap_fixture activate-failure
    swapon() { return 1; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'swapon failure accepted'; fi
    [ ! -e "$SWAP_FILE" ] || fail 'failed allocation not cleaned up'
    cmp "$SWAP_FSTAB" "$SWAP_FSTAB.original"
    swap_fixture allocation-failure
    dd() { printf partial >> "$SWAP_FILE"; return 1; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'dd failure accepted'; fi
    [ ! -e "$SWAP_FILE" ] || fail 'partial file not removed'
    swap_fixture post-activation-failure
    dd() { printf 'test-bytes' >> "$SWAP_FILE"; }
    swapon() { printf '%s file 262144 0 -2\n' "$SWAP_FILE" >> "$SWAP_PROC"; }
    swap_reload_systemd() { return 1; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'post activation failure accepted'; fi
    [ ! -e "$SWAP_FILE" ] || fail 'new swap not cleaned up after deactivation'
    if grep -qF "$SWAP_FILE" "$SWAP_FSTAB"; then fail 'failed swap still in fstab'; fi
    grep -q 'UUID=example' "$SWAP_FSTAB"
    swap_fixture cannot-disable
    swapoff() { return 1; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'failed swapoff accepted'; fi
    [ -f "$SWAP_FILE" ] && swap_file_active || fail 'active swap deleted on cleanup failure'
    swap_reload_systemd() { return 0; }
    swap_fixture unsupported-fs
    findmnt() { echo btrfs; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'unsupported filesystem accepted'; fi
    [ ! -e "$SWAP_FILE" ] || fail 'Btrfs file created'
    swap_fixture container
    systemd-detect-virt() { echo lxc; }
    if create_swap <<< $'256\nCREATE SWAP' 2>/dev/null; then fail 'container swap accepted'; fi
    # Unknown active state must not be interpreted as inactive during cleanup.
    SWAP_PROC="$TMP/missing-proc"
    if swap_file_active; then fail 'unreadable status accepted'; else eq "$?" 2 'unreadable swap state'; fi
)
echo 'PASS: Swap transaction, active verification, duplicate protection, rollback, filesystem/container restrictions'

(
    for url in https://mirror.example https://mirror.example:8443/; do validate_registry_url "$url" || fail 'valid URL rejected'; done
    for url in http://mirror.example https://user:pass@host https://mirror.example/path 'https://host/?secret=x' 'https://host;id' https://host:0 https://host:65536; do
        if validate_registry_url "$url"; then fail "invalid URL accepted: $url"; fi
    done
    printf '{"log-driver":"local","registry-mirrors":["https://old.example"]}\n' > "$TMP/daemon.json"
    merge_registry_mirror "$TMP/daemon.json" "$TMP/merged.json" https://new.example
    merge_registry_mirror "$TMP/merged.json" "$TMP/merged2.json" https://new.example
    cmp "$TMP/merged.json" "$TMP/merged2.json"
    eq "$(jq -r '."log-driver"' "$TMP/merged.json")" local 'preserve daemon options'
    eq "$(jq '."registry-mirrors" | length' "$TMP/merged.json")" 2 'idempotent mirror merge'
    printf '{"registry-mirrors":"bad"}' > "$TMP/bad.json"
    if merge_registry_mirror "$TMP/bad.json" "$TMP/bad-result" https://new.example 2>/dev/null; then fail 'bad mirror type accepted'; fi
    curl() { printf 401; }
    docker_hub_reachable || fail 'normal auth challenge reported unreachable'
    curl() { printf 503; }
    if docker_hub_reachable; then fail '503 accepted'; fi
)
echo 'PASS: HTTPS registry URLs, JSON preservation/idempotence, Docker Hub 401 detection'

(
    DOCKER_DAEMON_CONFIG="$TMP/docker/config.json"
    DOCKER_BACKUPS="$TMP/docker/backups"
    mkdir -p "$(dirname "$DOCKER_DAEMON_CONFIG")"
    printf '{"log-driver":"local"}\n' > "$DOCKER_DAEMON_CONFIG"
    cp "$DOCKER_DAEMON_CONFIG" "$TMP/daemon-before"
    curl() { printf 200; }
    dockerd() { return 0; }
    docker() { return 0; }
    systemctl() {
        if [ "$1" = restart ]; then printf 'restart\n' >> "$TMP/restarts"; fi
        return 0
    }
    configure_docker_mirror <<< $'https://mirror.example\nSAVE MIRROR\nno'
    [ ! -e "$TMP/restarts" ] || fail 'unapproved restart'
    jq -e '."registry-mirrors"[0]=="https://mirror.example"' "$DOCKER_DAEMON_CONFIG" >/dev/null
    cp "$TMP/daemon-before" "$DOCKER_DAEMON_CONFIG"
    systemctl() {
        if [ "$1" = restart ]; then printf 'restart\n' >> "$TMP/restarts"; return 1; fi
        return 0
    }
    if configure_docker_mirror <<< $'https://mirror.example\nSAVE MIRROR\nRESTART DOCKER' 2>/dev/null; then fail 'failed restart accepted'; fi
    cmp "$TMP/daemon-before" "$DOCKER_DAEMON_CONFIG"
    eq "$(wc -l < "$TMP/restarts" | tr -d ' ')" 2 'new and restored restart attempts'
    dockerd() { return 1; }
    if configure_docker_mirror <<< $'https://mirror.example\nSAVE MIRROR\nno' 2>/dev/null; then fail 'invalid daemon config accepted'; fi
    cmp "$TMP/daemon-before" "$DOCKER_DAEMON_CONFIG"
)
echo 'PASS: Registry save without restart, failed restart rollback, invalid config refusal'

(
    # Verify platform decisions independently of this host's distribution.
    detect_platform() { SEC_OS_ID=debian; SEC_OS_VERSION=13; }
    dpkg() { echo arm64; }
    docker_platform
    eq "$DOCKER_DISTRO:$DOCKER_SUITE:$DOCKER_ARCH" debian:trixie:arm64 'Debian ARM routing'
    detect_platform() { SEC_OS_ID=ubuntu; SEC_OS_VERSION=24.04; }
    docker_platform
    eq "$DOCKER_SUITE" noble 'Ubuntu routing'
    detect_platform() { SEC_OS_ID=rocky; SEC_OS_VERSION=9.5; }
    uname() { echo x86_64; }
    docker_platform
    eq "$DOCKER_DISTRO:$DOCKER_SUITE" centos:9 'RPM routing'
    # Key parser enforces a single matching primary key; rejects extra primary keys.
    gpg() { printf 'pub:::::::::\nfpr:::::::::TESTFINGERPRINT:\nfpr:::::::::SUBKEY:\n'; }
    verify_docker_key ignored TESTFINGERPRINT "$TMP" || fail 'matching primary rejected'
    if verify_docker_key ignored WRONG "$TMP" 2>/dev/null; then fail 'wrong key accepted'; fi
    gpg() { printf 'pub:::::::::\nfpr:::::::::TESTFINGERPRINT:\npub:::::::::\nfpr:::::::::OTHER:\n'; }
    if verify_docker_key ignored TESTFINGERPRINT "$TMP" 2>/dev/null; then fail 'extra primary key accepted'; fi
)
echo 'PASS: Docker distro/architecture routing and signing-key fingerprint gate'
(
    DOCKER_FAMILY=rpm DOCKER_DISTRO=centos DOCKER_SUITE=9 DOCKER_ARCH=aarch64
    DOCKER_RPM_KEY="$TMP/rpm/docker.asc"
    mkdir -p "$TMP/rpm-stage"
    docker_fetch() {
        case "$1" in */gpg) printf key > "$2";; */repodata/repomd.xml) printf '<repomd/>\n' > "$2";; *) return 1;; esac
    }
    verify_docker_key() { eq "$2" "$DOCKER_RPM_FINGERPRINT" 'RPM fingerprint selected'; }
    prepare_docker_repo https://mirrors.aliyun.com/docker-ce "$TMP/rpm-stage"
    grep -qx 'gpgcheck=1' "$TMP/rpm-stage/source"
    grep -qx 'baseurl=https://mirrors.aliyun.com/docker-ce/linux/centos/9/aarch64/stable' "$TMP/rpm-stage/source"
    grep -qx "gpgkey=file://$DOCKER_RPM_KEY" "$TMP/rpm-stage/source"
)
echo 'PASS: RPM source rendering and package signature enforcement'


(
    # Full install flow, with every package/service/network operation mocked.
    DOCKER_APT_SOURCE="$TMP/apt/docker.sources"
    DOCKER_APT_KEY="$TMP/apt/docker.asc"
    DOCKER_BACKUPS="$TMP/install-records"
    docker_platform() { SEC_OS_ID=debian SEC_OS_VERSION=13 DOCKER_ARCH=amd64 DOCKER_FAMILY=apt; }
    docker_host_ready() { return 0; }
    systemd-detect-virt() { echo none; }
    docker_conflicts() { return 1; }
    docker_existing_repo() { return 1; }
    prepare_docker_repo() {
        printf '%s\n' "$1" >> "$TMP/probed-roots"
        [ "$1" != https://download.docker.com ] || return 1
        printf 'verified-key-fixture\n' > "$2/docker.asc"
        printf 'verified-repo-fixture\n' > "$2/source"
    }
    apt-get() { printf '%s\n' "$*" >> "$TMP/apt-calls"; return 0; }
    systemctl() { return 0; }
    docker() { return 0; }
    docker_hub_reachable() { return 1; }
    install_docker <<< 'INSTALL DOCKER'
    eq "$(head -n1 "$TMP/probed-roots")" https://download.docker.com 'official first'
    eq "$(sed -n '2p' "$TMP/probed-roots")" https://mirrors.aliyun.com/docker-ce 'mirror fallback'
    grep -q 'install -y --no-remove docker-ce' "$TMP/apt-calls"
    [ -f "$DOCKER_APT_SOURCE" ] && [ -f "$DOCKER_APT_KEY" ] || fail 'validated repo not retained'
    DOCKER_APT_SOURCE="$TMP/fail-apt/docker.sources"
    DOCKER_APT_KEY="$TMP/fail-apt/docker.asc"
    prepare_docker_repo() { return 1; }
    if install_docker <<< 'INSTALL DOCKER' 2>/dev/null; then fail 'all invalid repositories accepted'; fi
    [ ! -e "$DOCKER_APT_SOURCE" ] || fail 'failed repo left behind'
    # Existing installs must stop before any package mutation.
    docker_conflicts() { return 0; }
    apt-get() { fail 'existing runtime modified'; }
    if install_docker <<< 'INSTALL DOCKER' 2>/dev/null; then fail 'existing runtime accepted'; fi
)
echo 'PASS: Docker official-first fallback, retained valid repo, complete failure, existing runtime refusal'
(
    source "$ROOT/install.sh"
    download_script() { printf '%s\n' "$1" >> "$TMP/v5-downloads"; }
    download_module v5.sh
    for part in lib/platform.sh lib/docker.sh lib/swap.sh v5.sh; do grep -qx "$part" "$TMP/v5-downloads"; done
    eq "$(wc -l < "$TMP/v5-downloads" | tr -d ' ')" 4 'V5 dependencies'
)
echo 'PASS: V5 installer downloads all required dependencies'
for file in "$ROOT/v5.sh" "$ROOT/lib/docker.sh" "$ROOT/lib/swap.sh" "$ROOT/install.sh"; do bash -n "$file"; done
echo 'All Docker/Swap tests passed.'
