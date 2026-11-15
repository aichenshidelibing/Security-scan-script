#!/usr/bin/env bash
# Isolated regression suite: no root, no network, no live service changes.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
export USE_EMOJI=0
fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() { [ "$1" = "$2" ] || fail "${3:-assertion}: expected [$2], got [$1]"; }

(
    source "$ROOT/v2.sh"
    SSHD_CONFIG="$TMP/sshd_config"
    SSHD_DROPIN_DIR="$TMP/sshd_config.d"
    SSHD_DROPIN_FILE="$SSHD_DROPIN_DIR/99-sec-toolbox.conf"
    KEY_PATH="$TMP/id_ed25519"
    AUTH_KEYS="$TMP/keys/authorized_keys"
    BACKUP_ROOT="$TMP/backups"
    mkdir -p "$SSHD_DROPIN_DIR" "$(dirname "$AUTH_KEYS")"
    ssh-keygen -q -t ed25519 -N '' -f "$TMP/host_key"
    # All commands that could affect the system are replaced before invoking actions.
    reload_ssh_safe() { return 0; }
    systemctl() { return 1; }
    port_is_in_use() { return 1; }
    show_status() { :; }
    if [ -x /usr/sbin/sshd ]; then
        REAL_SSHD=1
    else
        REAL_SSHD=0
        echo 'SKIP: real sshd validation (not installed); structural tests only'
        sshd_test() { ! grep -q '^InvalidOption ' "$SSHD_CONFIG"; }
        sshd_effective_config() {
            awk '!/^#/ && NF>=2 && !seen[tolower($1)]++ { print tolower($1), $2 }' "$SSHD_CONFIG"
        }
    fi
    reset_config() {
        rm -f "$SSHD_DROPIN_FILE" "$KEY_PATH" "${KEY_PATH}.pub"
        printf 'ssh-ed25519 fixture\n' > "$AUTH_KEYS"
        cat > "$SSHD_CONFIG" <<CONFIG
HostKey $TMP/host_key
Port 22
PasswordAuthentication yes
PermitRootLogin yes
PubkeyAuthentication no
Match User regression-user
    X11Forwarding no
CONFIG
        expected_port=22 expected_password=yes expected_root=yes
    }
    assert_policy() {
        local cfg
        cfg=$(sshd_effective_config)
        assert_eq "$(awk '$1=="port" {print $2}' <<< "$cfg")" "$expected_port" "port"
        assert_eq "$(awk '$1=="passwordauthentication" {print $2}' <<< "$cfg")" "$expected_password" "password"
        assert_eq "$(awk '$1=="permitrootlogin" {print $2}' <<< "$cfg")" "$expected_root" "root"
        assert_eq "$(grep -cFx "$MANAGED_BEGIN" "$SSHD_CONFIG")" 1 "managed block count"
        grep -q '^Match User regression-user$' "$SSHD_CONFIG" || fail 'Match block lost'
    }
    action() {
        case "$1" in
            key)
                generate_key >/dev/null
                install_pubkey >/dev/null ;;
            port) configure_ssh_port <<< $'2222\nCHANGE PORT' >/dev/null; expected_port=2222 ;;
            port2) configure_ssh_port <<< $'2200\nCHANGE PORT' >/dev/null; expected_port=2200 ;;
            disable) configure_password_login <<< $'1\nI TESTED SSH LOGIN' >/dev/null; expected_password=no ;;
            enable) configure_password_login <<< '2' >/dev/null; expected_password=yes ;;
            rootno) configure_root_login <<< $'2\nDISABLE ROOT' >/dev/null; expected_root=no ;;
            rootyes) configure_root_login <<< $'3\nALLOW ROOT' >/dev/null; expected_root=yes ;;
            recommended) apply_recommended_policy <<< 'APPLY POLICY' >/dev/null ;;
        esac
        assert_policy
    }
    actions=(port port2 key disable enable rootno rootyes recommended)
    pairs=0
    for first in "${actions[@]}"; do
        for second in "${actions[@]}"; do
            reset_config
            action "$first"
            action "$second"
            pairs=$((pairs+1))
        done
    done
    echo "PASS: $pairs ordered SSH action pairs (including repeated actions)"
    # Every ordering of the five independent policy dimensions.
    operations=(port key disable rootno recommended)
    permutations=0
    for a in "${operations[@]}"; do
      for b in "${operations[@]}"; do [ "$a" != "$b" ] || continue
       for c in "${operations[@]}"; do [[ "$c" != "$a" && "$c" != "$b" ]] || continue
        for d in "${operations[@]}"; do [[ "$d" != "$a" && "$d" != "$b" && "$d" != "$c" ]] || continue
         for e in "${operations[@]}"; do [[ "$e" != "$a" && "$e" != "$b" && "$e" != "$c" && "$e" != "$d" ]] || continue
            reset_config
            for op in "$a" "$b" "$c" "$d" "$e"; do action "$op"; done
            permutations=$((permutations+1))
         done
        done
       done
      done
    done
    assert_eq "$permutations" 120 'permutation count'
    echo 'PASS: 120 five-action SSH permutations'

    reset_config
    generate_key >/dev/null
    b1=$(create_ssh_backup before)
    b2=$(create_ssh_backup after)
    [ "$b1" != "$b2" ] || fail 'backup collision'
    assert_eq "$(stat -c %a "$b1")" 700 'private backup directory'
    cp "$SSHD_CONFIG" "$TMP/original"
    if append_managed_block "$b1" 'InvalidOption yes' >/dev/null; then fail 'invalid config accepted'; fi
    cmp "$SSHD_CONFIG" "$TMP/original" || fail 'validation failure not rolled back'
    append_managed_block "$b1" 'Port 2222' >/dev/null
    reload_count=0
    reload_ssh_safe() { reload_count=$((reload_count+1)); [ "$reload_count" -gt 1 ]; }
    if activate_ssh_policy "$b1" >/dev/null; then fail 'reload failure reported success'; fi
    cmp "$SSHD_CONFIG" "$TMP/original" || fail 'reload failure not rolled back'
    assert_eq "$reload_count" 2 'reload restored config'
    reload_ssh_safe() { return 0; }
    echo 'PASS: unique private backups, validation rollback, reload rollback'

    reset_config
    printf '%s\nPort 2222\n' "$MANAGED_BEGIN" >> "$SSHD_CONFIG"
    cp "$SSHD_CONFIG" "$TMP/broken"
    if append_managed_block unused 'PubkeyAuthentication yes' >/dev/null; then fail 'broken block accepted'; fi
    cmp "$SSHD_CONFIG" "$TMP/broken" || fail 'broken config truncated'
    reset_config
    sed -i '/^Port /d' "$SSHD_CONFIG"
    printf 'Port 2222\nPasswordAuthentication no\n' > "$SSHD_DROPIN_FILE"
    b1=$(create_ssh_backup legacy)
    append_managed_block "$b1" 'PubkeyAuthentication yes' >/dev/null
    expected_port=2222 expected_password=no
    assert_policy
    [ ! -e "$SSHD_DROPIN_FILE" ] || fail 'legacy file not migrated'
    echo 'PASS: malformed block rejected and legacy policy preserved'

    if [ "$REAL_SSHD" = 1 ]; then
        reset_config
        printf 'Port 2201\n' > "$TMP/external.conf"
        sed -i "1i Include $TMP/external.conf" "$SSHD_CONFIG"
        cp "$SSHD_CONFIG" "$TMP/original"
        b1=$(create_ssh_backup include)
        if append_managed_block "$b1" 'Port 2222' >/dev/null; then fail 'extra Include port accepted'; fi
        cmp "$SSHD_CONFIG" "$TMP/original" || fail 'Include conflict not rolled back'
        echo 'PASS: real sshd detects additional Include ports; change rolled back'
    fi
    reset_config
    systemctl() { [ "$*" = 'is-active --quiet ssh.socket' ]; }
    cp "$SSHD_CONFIG" "$TMP/original"
    if configure_ssh_port <<< $'2222\nCHANGE PORT' >/dev/null; then fail 'socket activation accepted'; fi
    cmp "$SSHD_CONFIG" "$TMP/original" || fail 'socket configuration changed'
    echo 'PASS: active SSH socket blocks unsupported port change'
)
(
    # v1 is an interactive script without errexit; its startup reads may return 1.
    set +e
    source "$ROOT/v1.sh"
    trap - EXIT
    set -e
    apply_ssh_setting() { printf '%s\n' "$@" > "$TMP/ssh-routing"; }
    SSHD_CONFIG="$TMP/sshd_config"
    TITLES[1]='开启公钥认证支持'
    apply_fix 1 >/dev/null
    assert_eq "$(cat "$TMP/ssh-routing")" 'PubkeyAuthentication yes' 'v1 transactional SSH routing'
    echo 'PASS: shared SSH policy routing'
)
(
    source "$ROOT/v3.sh"
    add_item test pros risks true
    assert_eq "${SELECTED[1]}" TRUE 'existing block preserved'
    add_item test pros risks false
    assert_eq "${SELECTED[2]}" FALSE 'existing allow preserved'
    cmd_exists() { [[ "$1" == ufw || "$1" == nft ]]; }
    ufw() { echo 'Status: inactive'; }
    nft() { return 0; }
    detect_firewall
    assert_eq "$FW_TYPE" nftables 'inactive UFW skipped'
    UFW_RULES="$TMP/before.rules"
    cat > "$UFW_RULES" <<'RULES'
*filter
:ufw-before-input - [0:0]
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
COMMIT
RULES
    cp "$UFW_RULES" "$TMP/before.original"
    ufw() { return 0; }
    apply_ufw_ping block
    apply_ufw_ping block
    assert_eq "$(grep -c '^# DISABLE_PING$' "$UFW_RULES")" 1 'idempotent UFW rule'
    assert_eq "$(grep '^-A ufw-before-input' "$UFW_RULES" | head -n1)" \
        '-A ufw-before-input -p icmp --icmp-type echo-request -j DROP' 'DROP before ACCEPT'
    apply_ufw_ping allow
    cmp "$UFW_RULES" "$TMP/before.original" || fail 'UFW restore changed unrelated rules'
    ufw() { return 1; }
    if apply_ufw_ping block; then fail 'UFW reload failure ignored'; fi
    cmp "$UFW_RULES" "$TMP/before.original" || fail 'UFW reload rollback failed'
    echo 'PASS: Ping state, inactive firewall, UFW ordering/idempotence/rollback'
)
(
    source "$ROOT/v4.sh"
    SEC_GITHUB_ACCEL_DIR="$TMP/mirrors"
    SEC_GITHUB_ACCEL_FILE="$SEC_GITHUB_ACCEL_DIR/github-mirrors"
    SEC_GITHUB_MIRRORS_DEFAULT=(https://bad.example https://good.example)
    probe_mirror() { [ "$1" = https://good.example ]; }
    auto_pick_mirror >/dev/null
    assert_eq "$(head -n1 "$SEC_GITHUB_ACCEL_FILE")" https://good.example 'usable mirror first'
    ui_line >/dev/null
    echo 'PASS: mirror selection ordering and UI helper'
)
(
    source "$ROOT/install.sh"
    cd "$TMP"
    SEC_LOCAL_MODE=0
    SEC_GITHUB_ACCEL_FILE="$TMP/nonexistent-mirror-list"
    cmd_exists() { [ "$1" = wget ]; }
    printf 'old script\n' > v2.sh
    wget() { printf '<html>failed</html>\n' > "$5"; return 1; }
    if download_script v2.sh >/dev/null; then fail 'failed download accepted'; fi
    assert_eq "$(cat v2.sh)" 'old script' 'failed download preserves local copy'
    wget() { printf '<html>error page</html>\n' > "$5"; }
    if download_script v2.sh >/dev/null; then fail 'HTML accepted'; fi
    assert_eq "$(cat v2.sh)" 'old script' 'HTML preserves local copy'
    wget() { printf '#!/bin/bash\n# <SEC_SCRIPT_MARKER_v2.3>\necho ok\n' > "$5"; }
    download_script v2.sh >/dev/null
    grep -qx 'echo ok' v2.sh || fail 'valid script not installed'
    SEC_GITHUB_ACCEL_FILE="$TMP/preferred-mirrors"
    printf 'https://preferred.example/https://raw.githubusercontent.com\n' > "$SEC_GITHUB_ACCEL_FILE"
    wget() {
        printf '%s\n' "$6" > "$TMP/requested-url"
        printf '#!/bin/bash\n# <SEC_SCRIPT_MARKER_v2.3>\necho ok\n' > "$5"
    }
    download_script v2.sh >/dev/null
    case "$(cat "$TMP/requested-url")" in https://preferred.example/*) ;; *) fail 'saved mirror ignored';; esac
    echo 'PASS: atomic downloads reject failures/HTML and honor selected mirror'
)
[ ! -e "$ROOT/v0.sh" ] || fail 'removed module still exists'
if grep -nE 'v0\.sh|全维审计' "$ROOT/install.sh" "$ROOT/README.md"; then fail 'stale removed-module reference'; fi
for script in "$ROOT"/*.sh "$ROOT"/tests/*.sh; do bash -n "$script"; done
echo 'PASS: removed module references and all Bash syntax checks'
echo 'All regression tests passed.'
