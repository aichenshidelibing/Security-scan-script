#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v4.sh - IPv6 出口 / Cloudflare WARP / GitHub 加速中心
# WARP 和加速站都必须由用户明确选择；本脚本不会在启动时改路由或 DNS。

export LC_ALL=C
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
[ -f "$SCRIPT_DIR/lib/runtime.sh" ] && . "$SCRIPT_DIR/lib/runtime.sh"
# shellcheck source=/dev/null
[ -f "$SCRIPT_DIR/lib/network_checks.sh" ] && . "$SCRIPT_DIR/lib/network_checks.sh"
# shellcheck source=/dev/null
[ -f "$SCRIPT_DIR/lib/github.sh" ] && . "$SCRIPT_DIR/lib/github.sh"

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m')

fail() { printf '%s[失败]%s %s\n' "$RED" "$RESET" "$*"; }
ok() { printf '%s[成功]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[注意]%s %s\n' "$YELLOW" "$RESET" "$*"; }
info() { printf '%s[信息]%s %s\n' "$CYAN" "$RESET" "$*"; }

sec_v4_timeout() {
    # Never wait forever, even when the minimal image lacks coreutils timeout.
    local seconds="$1"; shift
    "$@" &
    local pid=$! elapsed=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$seconds" ]; then
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    wait "$pid"
}

warp_installed() { command -v warp-cli >/dev/null 2>&1; }
warp_status_text() { warp-cli status 2>/dev/null || true; }
warp_connected() { warp_status_text | grep -Eiq '(^|[[:space:]:])connected([[:space:]]|$)|已连接'; }

network_family_args() {
    local mode=""
    command -v sec_detect_ip_mode >/dev/null 2>&1 && mode=$(sec_detect_ip_mode 2>/dev/null || true)
    [ "$mode" = pure_ipv6 ] && printf '%s\n' '-6'
}

curl_family() {
    local family
    family=$(network_family_args)
    [ -n "$family" ] && printf '%s\n' "$family"
}

run_warp_cli() { sec_v4_timeout 25 warp-cli "$@"; }
run_systemctl() { sec_v4_timeout 25 systemctl "$@"; }

warp_install_apt() {
    [ "$(id -u)" -eq 0 ] || { fail '安装 WARP 需要 root 权限。'; return 1; }
    command -v apt-get >/dev/null 2>&1 || { fail '当前系统没有 apt-get；此版本仅自动配置 Debian/Ubuntu 官方源。'; return 1; }
    command -v curl >/dev/null 2>&1 || { fail '安装 WARP 前需要 curl。'; return 1; }
    command -v gpg >/dev/null 2>&1 || { fail '安装 WARP 前需要 gpg；请先安装 gnupg。'; return 1; }

    local codename="" keyring='/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg'
    local source_file='/etc/apt/sources.list.d/cloudflare-client.list'
    if [ -r /etc/os-release ]; then . /etc/os-release; codename="${VERSION_CODENAME:-}"; fi
    if [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1; then codename=$(lsb_release -cs 2>/dev/null || true); fi
    [[ "$codename" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || { fail '无法安全识别发行版代号，拒绝写入 WARP 软件源。'; return 1; }

    local tmp_key="${TMPDIR:-/tmp}/cloudflare-warp-key.$$"
    local family; family=$(curl_family)
    info '正在连接 Cloudflare 官方软件源（仅通过当前可用的 IPv6/IPv4 出口）。'
    rm -f -- "$tmp_key"
    if [ -n "$family" ]; then
        curl "$family" -fsSL --connect-timeout 5 --max-time 20 \
            https://pkg.cloudflareclient.com/pubkey.gpg -o "$tmp_key" || { rm -f -- "$tmp_key"; fail '下载 Cloudflare 公钥失败。'; return 1; }
    else
        curl -fsSL --connect-timeout 5 --max-time 20 \
            https://pkg.cloudflareclient.com/pubkey.gpg -o "$tmp_key" || { rm -f -- "$tmp_key"; fail '下载 Cloudflare 公钥失败。'; return 1; }
    fi
    install -d -m 0755 "$(dirname -- "$keyring")" || { rm -f -- "$tmp_key"; return 1; }
    gpg --dearmor --yes -o "$keyring" "$tmp_key" || { rm -f -- "$tmp_key"; fail '写入 Cloudflare 公钥失败。'; return 1; }
    rm -f -- "$tmp_key"
    printf 'deb [signed-by=%s] https://pkg.cloudflareclient.com/ %s main\n' "$keyring" "$codename" >"$source_file" || return 1

    if ! sec_with_package_manager_lock env DEBIAN_FRONTEND=noninteractive apt-get update; then
        fail 'APT 更新失败；保留现有软件状态，未强行安装。'
        return 1
    fi
    if ! sec_with_package_manager_lock env DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflare-warp; then
        fail 'cloudflare-warp 安装失败。'
        return 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        run_systemctl enable --now warp-svc >/dev/null 2>&1 || warn 'warp-svc 未能立即启动，可稍后执行 systemctl restart warp-svc。'
    fi
    ok 'Cloudflare WARP 软件包安装完成。下一步请单独选择“注册并连接”。'
}

warp_install() {
    if warp_installed; then ok 'warp-cli 已安装。'; return 0; fi
    warp_install_apt
}

warp_register_connect() {
    warp_installed || { fail '尚未安装 warp-cli，请先选择安装。'; return 1; }
    [ "$(id -u)" -eq 0 ] || { fail '注册/连接 WARP 需要 root 权限。'; return 1; }
    if command -v systemctl >/dev/null 2>&1; then
        run_systemctl start warp-svc >/dev/null 2>&1 || true
    fi
    if ! run_warp_cli registration show >/dev/null 2>&1; then
        info '正在创建 WARP 注册（Cloudflare 会生成本机账户）。'
        run_warp_cli registration new || { fail 'WARP 注册失败。'; return 1; }
    fi
    # warp mode is full tunnel. Proxy mode would not provide a system IPv4 exit.
    if ! run_warp_cli mode warp >/dev/null 2>&1; then
        # Newer clients may expose the full-tunnel profile as warp+doh.
        run_warp_cli mode warp+doh >/dev/null 2>&1 || { fail '无法切换到 WARP 全隧道模式。'; return 1; }
    fi
    run_warp_cli connect >/dev/null 2>&1 || { fail 'WARP 连接失败；未继续修改 DNS。'; return 1; }
    local i=0
    while [ "$i" -lt 20 ]; do
        warp_connected && { ok 'WARP 已连接：系统 IPv4 出口应已建立（不是公网 IPv4 地址）。'; return 0; }
        sleep 1; i=$((i + 1))
    done
    fail 'WARP 在 20 秒内未进入 Connected 状态，请执行状态检查后再决定是否重试。'
    return 1
}

warp_disconnect() {
    warp_installed || { info 'warp-cli 未安装。'; return 0; }
    run_warp_cli disconnect >/dev/null 2>&1 && ok 'WARP 已断开。' || fail 'WARP 断开失败，请检查 warp-cli status。'
}

probe_exit() {
    local family="$1" url='https://cloudflare.com/cdn-cgi/trace' label="$2" out="${TMPDIR:-/tmp}/sec-exit.$$"
    if curl "$family" -fsSL --connect-timeout 3 --max-time 8 -o "$out" "$url" >/dev/null 2>&1; then
        if grep -Eq 'ip=|warp=' "$out" 2>/dev/null; then ok "$label 可用。"; rm -f -- "$out"; return 0; fi
    fi
    rm -f -- "$out"
    fail "$label 不可用。"
    return 1
}

show_status() {
    echo ''
    printf '%sIPv4/IPv6 出口状态%s\n' "$WHITE" "$RESET"
    if command -v curl >/dev/null 2>&1; then
        probe_exit -4 'IPv4 出口' || true
        probe_exit -6 'IPv6 出口' || true
    else
        warn '缺少 curl，无法执行出口探测。'
    fi
    if warp_installed; then
        printf 'WARP: %s\n' "$(warp_status_text | tr '\n' ' ' | cut -c1-240)"
    else
        printf 'WARP: 未安装\n'
    fi
    local selected; selected=$(sec_github_selected_endpoint 2>/dev/null || true)
    printf 'GitHub fallback: %s\n' "${selected:-未设置（每次仍优先官方 raw）}"
}

probe_github() {
    command -v sec_github_endpoint_entries >/dev/null 2>&1 || { fail '缺少 lib/github.sh。'; return 1; }
    local entry name result
    echo '按当前网络逐个探测 GitHub raw endpoint（每个最多 8 秒）：'
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        name="${entry%%|*}"
        if sec_github_probe_named_endpoint "$name"; then result='可用'; else result='不可用/未验证'; fi
        printf '  %-14s %s\n' "$(sec_github_endpoint_label "$name")" "$result"
    done < <(sec_github_endpoint_entries)
}

select_github() {
    command -v sec_github_endpoint_entries >/dev/null 2>&1 || { fail '缺少 lib/github.sh。'; return 1; }
    local entries=() entry name i=1 choice selected
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        entries+=("$entry")
        name="${entry%%|*}"
        printf ' [%s] %s\n' "$i" "$(sec_github_endpoint_label "$name")"
        i=$((i + 1))
    done < <(sec_github_endpoint_entries)
    printf ' [q] 取消\n选择要保存的 fallback（官方 raw 仍然第一优先）: '
    read -r choice
    [ "$choice" = q ] || [ "$choice" = Q ] && return 0
    [[ "$choice" =~ ^[0-9]+$ ]] || { fail '输入无效。'; return 1; }
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#entries[@]}" ] || { fail '输入超出范围。'; return 1; }
    selected="${entries[$((choice - 1))]:-}"
    [ -n "$selected" ] || { fail '输入超出范围。'; return 1; }
    name="${selected%%|*}"
    if sec_github_probe_named_endpoint "$name"; then
        sec_github_set_endpoint "$name" && ok "已保存 $(sec_github_endpoint_label "$name") 为 fallback。" || fail '保存失败。'
    else
        warn '该站点当前 IPv6/HTTPS/raw 探测未通过，拒绝保存为默认 fallback。'
    fi
}

menu() {
    while true; do
        echo ''
        echo '========== IPv6 出口 / WARP / GitHub 加速中心 =========='
        echo ' [1] 查看当前 IPv4/IPv6 出口与 WARP 状态'
        echo ' [2] 安装 Cloudflare WARP 官方软件包（不连接）'
        echo ' [3] 注册并连接 WARP 全隧道（提供 IPv4 出口）'
        echo ' [4] 断开 WARP'
        echo ' [5] 探测当前可用的 GitHub raw endpoint'
        echo ' [6] 设置 GitHub fallback（只保存已探测可用站点）'
        echo ' [q] 返回主菜单'
        printf '请选择: '
        read -r choice
        case "$choice" in
            1) show_status; read -r -p '按回车返回...' _ ;;
            2) warp_install; read -r -p '按回车返回...' _ ;;
            3) warp_register_connect; read -r -p '按回车返回...' _ ;;
            4) warp_disconnect; read -r -p '按回车返回...' _ ;;
            5) probe_github; read -r -p '按回车返回...' _ ;;
            6) select_github; read -r -p '按回车返回...' _ ;;
            q|Q) return 0 ;;
        esac
    done
}

[ "$(id -u)" -eq 0 ] || { fail '请使用 root 权限运行 v4.sh。'; exit 1; }
sec_toolbox_acquire_lock 'v4-ipv6-warp' || exit 1
trap 'sec_toolbox_release_lock' EXIT INT TERM
menu
