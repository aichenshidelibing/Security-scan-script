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
    # Never wait forever, but do not impose a full one-second delay on every
    # short-lived warp-cli call in minimal images.
    local seconds="$1"; shift
    "$@" &
    local pid=$! started now
    started=$(date +%s 2>/dev/null || printf '0')
    while kill -0 "$pid" 2>/dev/null; do
        now=$(date +%s 2>/dev/null || printf '%s' "$started")
        if [ "$now" -ge "$started" ] && [ $((now - started)) -ge "$seconds" ]; then
            kill "$pid" 2>/dev/null || true
            sleep 0.1
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
    done
    wait "$pid"
}
warp_installed() { command -v warp-cli >/dev/null 2>&1; }
warp_status_text() { warp-cli status 2>/dev/null || true; }
warp_connected() { warp_status_text | grep -Eiq '(^|[[:space:]:])connected([[:space:]]|$)|已连接'; }

warp_registration_text() { run_warp_cli registration show 2>&1; }

warp_is_registered() {
    local text
    warp_installed || return 1
    text=$(warp_registration_text) || return 1
    [ -n "$text" ] || return 1
    printf '%s\n' "$text" | grep -Eiq 'not[[:space:]-]*registered|未注册|no[[:space:]]+registration' && return 1
    # Different warp-cli versions use different labels, so accept several
    # explicit positive registration fields while rejecting absent states.
    printf '%s\n' "$text" | grep -Eiq 'registered|registration[[:space:]]*:[[:space:]]*[[:alnum:]]|account[[:space:]]+type|device[[:space:]]+id|organization|license|profile|public[[:space:]]+key|id[[:space:]:=]' \
        || return 1
}

warp_settings_text() {
    warp_installed || return 0
    run_warp_cli settings 2>&1
}

warp_current_mode() {
    local text
    text="$(warp_settings_text)"
    if printf '%s\n' "$text" | grep -Eiq 'mode[[:space:]]*:[[:space:]]*warp[+]?doh|warp[+]?doh'; then
        printf 'warp+doh\n'
    elif printf '%s\n' "$text" | grep -Eiq 'mode[[:space:]]*:[[:space:]]*warp([[:space:]]|$)|(^|[[:space:]])warp([[:space:]]|$)'; then
        printf 'warp\n'
    elif printf '%s\n' "$text" | grep -Eiq 'mode[[:space:]]*:[[:space:]]*(proxy|proxy\+doh)|proxy'; then
        printf 'proxy\n'
    else
        printf 'unknown\n'
    fi
}

warp_is_full_tunnel() {
    case "$(warp_current_mode)" in
        warp|warp+doh) return 0 ;;
        *) return 1 ;;
    esac
}

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
warp_cli_help_text() {
    warp_installed || return 1
    run_warp_cli help 2>&1
    run_warp_cli tunnel ip help 2>&1 || true
}

warp_split_route_style() {
    local help
    help=$(warp_cli_help_text 2>/dev/null || true)
    if printf '%s\n' "$help" | grep -Eq 'tunnel[[:space:]]+ip[[:space:]]+add'; then
        printf 'tunnel_ip\n'
    elif printf '%s\n' "$help" | grep -Eq 'add-excluded-route'; then
        printf 'excluded_route\n'
    else
        printf 'unsupported\n'
    fi
}

warp_split_routes_text() {
    case "$(warp_split_route_style)" in
        tunnel_ip) run_warp_cli tunnel ip list 2>&1 || true ;;
        excluded_route) run_warp_cli get-excluded-routes 2>&1 || true ;;
        *) return 1 ;;
    esac
}

warp_ipv4_only_supported() {
    [ "$(warp_split_route_style)" != unsupported ]
}

warp_ipv4_only_configured() {
    local routes normalized
    routes=$(warp_split_routes_text 2>/dev/null || true)
    normalized=$(printf '%s\n' "$routes" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    printf '%s\n' "$normalized" | grep -Eq '(^|[^0-9a-f:])(::/0|0:0:0:0:0:0:0:0/0)([^0-9a-f:]|$)'
}

warp_add_ipv6_exclusion() {
    warp_ipv4_only_supported || { fail '当前 warp-cli 未公开 IPv4-only 分流命令，拒绝猜测写入路由。'; return 1; }
    warp_ipv4_only_configured && { info '检测到已有 IPv6 排除路由 ::/0，跳过重复配置。'; return 0; }
    case "$(warp_split_route_style)" in
        tunnel_ip) run_warp_cli tunnel ip add ::/0 >/dev/null 2>&1 ;;
        excluded_route) run_warp_cli add-excluded-route ::/0 >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

warp_remove_ipv6_exclusion() {
    warp_ipv4_only_configured || return 0
    case "$(warp_split_route_style)" in
        tunnel_ip) run_warp_cli tunnel ip delete ::/0 >/dev/null 2>&1 || run_warp_cli tunnel ip del ::/0 >/dev/null 2>&1 ;;
        excluded_route) run_warp_cli remove-excluded-route ::/0 >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
run_systemctl() { sec_v4_timeout 25 systemctl "$@"; }
warp_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl is-active --quiet warp-svc >/dev/null 2>&1
}

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

probe_exit_ok() {
    local family="$1" url='https://cloudflare.com/cdn-cgi/trace' label="$2" out
    command -v curl >/dev/null 2>&1 || return 1
    out="${TMPDIR:-/tmp}/sec-exit-check.$$.$RANDOM"
    curl "$family" -fsSL --connect-timeout 3 --max-time 8 -o "$out" "$url" >/dev/null 2>&1 || {
        rm -f -- "$out"
        return 1
    }
    grep -Eq '(^|\n)(ip=|warp=)' "$out" 2>/dev/null
    local result=$?
    rm -f -- "$out"
    return "$result"
}

warp_ipv4_exit_ok() { probe_exit_ok -4 'IPv4 出口'; }
warp_ipv6_exit_ok() { probe_exit_ok -6 'IPv6 出口'; }

warp_needs_action() {
    warp_installed || { printf 'install\n'; return 0; }
    warp_is_registered || { printf 'register\n'; return 0; }
    warp_is_full_tunnel || { printf 'mode\n'; return 0; }
    warp_connected || { printf 'connect\n'; return 0; }
    warp_ipv4_exit_ok || { printf 'verify_ipv4\n'; return 0; }
    printf 'none\n'
    return 1
}

warp_register_connect() {
    warp_installed || { fail '尚未安装 warp-cli，请先选择安装。'; return 1; }
    [ "$(id -u)" -eq 0 ] || { fail '注册/连接 WARP 需要 root 权限。'; return 1; }
    if command -v systemctl >/dev/null 2>&1 && ! warp_service_active; then
        run_systemctl start warp-svc >/dev/null 2>&1 || true
    fi
    if ! warp_is_registered; then
        info '正在创建 WARP 注册（Cloudflare 会生成本机账户）。'
        run_warp_cli registration new || { fail 'WARP 注册失败。'; return 1; }
    else
        info '检测到已有 WARP 注册，跳过重复 registration new。'
    fi

    # warp mode is full tunnel. Proxy mode would not provide a system IPv4 exit.
    # Returning to full tunnel removes the IPv6 exclusion used by IPv4-only mode.
    warp_remove_ipv6_exclusion >/dev/null 2>&1 || true
    if warp_is_full_tunnel; then
        info "检测到已有全隧道模式（$(warp_current_mode)），跳过重复设置。"
    elif ! run_warp_cli mode warp >/dev/null 2>&1; then
        # Newer clients may expose the full-tunnel profile as warp+doh.
        run_warp_cli mode warp+doh >/dev/null 2>&1 || { fail '无法切换到 WARP 全隧道模式。'; return 1; }
    else
        info '已切换到 WARP 全隧道模式。'
    fi

    if warp_connected; then
        if warp_ipv4_exit_ok; then
            ok 'WARP 已连接且 IPv4 出口探测正常，无需重复连接。'
            return 0
        fi
        warn 'WARP 显示已连接，但 IPv4 出口探测失败；不会盲目重复连接，请先查看状态或手动断开后重试。'
        return 1
    fi

    run_warp_cli connect >/dev/null 2>&1 || { fail 'WARP 连接失败；未继续修改 DNS。'; return 1; }
    local i=0
    while [ "$i" -lt 20 ]; do
        if warp_connected && warp_ipv4_exit_ok; then
            ok 'WARP 已连接：系统 IPv4 出口已建立（不是公网 IPv4 地址）。'
            return 0
        fi
        sleep 1; i=$((i + 1))
    done
    fail 'WARP 在 20 秒内未建立可用 IPv4 出口，请执行状态检查后再决定是否重试。'
    return 1
}


warp_register_connect_ipv4_only() {
    warp_installed || { fail '尚未安装 warp-cli，请先选择安装。'; return 1; }
    [ "$(id -u)" -eq 0 ] || { fail '注册/连接 WARP 需要 root 权限。'; return 1; }
    if command -v systemctl >/dev/null 2>&1 && ! warp_service_active; then
        run_systemctl start warp-svc >/dev/null 2>&1 || true
    fi
    if ! warp_is_registered; then
        info '正在创建 WARP 注册（Cloudflare 会生成本机账户）。'
        run_warp_cli registration new || { fail 'WARP 注册失败。'; return 1; }
    else
        info '检测到已有 WARP 注册，跳过重复 registration new。'
    fi
    if warp_is_full_tunnel; then
        info "检测到已有全隧道模式（$(warp_current_mode)），跳过重复设置。"
    elif ! run_warp_cli mode warp >/dev/null 2>&1; then
        run_warp_cli mode warp+doh >/dev/null 2>&1 || { fail '无法切换到 WARP 全隧道模式。'; return 1; }
    fi
    warp_add_ipv6_exclusion || { fail 'IPv4-only 分流配置失败；未继续连接。'; return 1; }
    if warp_connected; then
        if warp_ipv4_exit_ok; then
            ok 'WARP IPv4-only 已连接；IPv4 走 WARP，IPv6 保留原 VPS 出口。'
            return 0
        fi
        warn 'WARP 显示已连接，但 IPv4 出口探测失败；不会盲目重复连接。'
        return 1
    fi
    run_warp_cli connect >/dev/null 2>&1 || { fail 'WARP 连接失败；未修改 DNS。'; return 1; }
    local i=0
    while [ "$i" -lt 20 ]; do
        if warp_connected && warp_ipv4_exit_ok; then
            ok 'WARP IPv4-only 已连接；IPv4 走 WARP，IPv6 保留原 VPS 出口。'
            return 0
        fi
        sleep 1; i=$((i + 1))
    done
    fail 'WARP IPv4-only 在 20 秒内未建立可用 IPv4 出口，请执行状态检查后再决定是否重试。'
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
    local github_priority="" name
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        [ -n "$github_priority" ] && github_priority+=" -> "
        github_priority+="$(sec_github_endpoint_label "$name")"
    done < <(sec_github_selected_endpoints 2>/dev/null || true)
    printf 'GitHub fallback: %s\n' "${github_priority:-未设置（中转优先，官方 raw 最后备选）}"
    if warp_installed; then
        if warp_ipv4_only_configured; then
            info 'WARP 部分接管已配置：仅 IPv4 请求走 WARP，IPv6 请求保留 VPS 原生出口。'
        elif warp_ipv4_only_supported; then
            info '当前 warp-cli 支持 IPv4-only 分流；尚未检测到 IPv6 ::/0 排除路由。'
        else
            warn '当前 warp-cli 未公开可验证的 IPv4-only 分流命令；不会猜测修改路由。'
        fi
        local action; action=$(warp_needs_action 2>/dev/null || true)
        case "$action" in
            none)
                if warp_ipv4_only_configured; then
                    ok 'WARP 状态完整：已安装、已注册、IPv4-only 分流、已连接且 IPv4 出口正常；IPv6 保持原生出口，重复执行会跳过。'
                else
                    ok 'WARP 状态完整：已安装、已注册、全隧道、已连接且 IPv4 出口正常；重复执行会跳过。'
                fi
                ;;
            install) info 'WARP 尚未安装。' ;;
            register) info 'WARP 已安装，但尚未注册。' ;;
            mode) info 'WARP 已注册，但还不是全隧道模式。' ;;
            connect) info 'WARP 已配置，但当前未连接。' ;;
            verify_ipv4) warn 'WARP 显示已连接，但 IPv4 出口探测未通过；不会自动重复连接。' ;;
            *) warn 'WARP 状态暂时无法完整确认。' ;;
        esac
    fi
}

probe_github() {
    command -v sec_github_probe_all >/dev/null 2>&1 || { fail '缺少 lib/github.sh。'; return 1; }
    echo "按当前网络逐个探测 GitHub endpoint（默认 3 轮，成功至少 2 轮才算可用）："
    local result name success rounds
    while IFS='|' read -r name success rounds; do
        [ -n "$name" ] || continue
        if [ "${success:-0}" -ge "${SEC_GITHUB_PROBE_MIN_SUCCESS:-2}" ] 2>/dev/null; then
            result='可用'
        else
            result='不可用/未达最低成功次数'
        fi
        printf '  %-28s %s（%s/%s）\n' "$(sec_github_endpoint_label "$name")" "$result" "$success" "$rounds"
    done < <(sec_github_probe_all)
}

auto_select_github() {
    command -v sec_github_auto_select >/dev/null 2>&1 || { fail '缺少 lib/github.sh。'; return 1; }
    if sec_github_auto_select; then
        ok "已自动选择可用 GitHub 中转优先级：$(tr '\n' ' ' <"$SEC_GITHUB_ENDPOINT_FILE")"
    else
        warn '没有任何中转站达到最低成功次数；保留官方 GitHub raw 作为最后备选。'
        return 1
    fi
}

select_github() {
    command -v sec_github_endpoint_entries >/dev/null 2>&1 || { fail '缺少 lib/github.sh。'; return 1; }
    local entries=() entry name i=1 choice selected_names=() item index
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        entries+=("$entry")
        name="${entry%%|*}"
        printf ' [%s] %s\n' "$i" "$(sec_github_endpoint_label "$name")"
        i=$((i + 1))
    done < <(sec_github_endpoint_entries)
    printf ' [a] 自动选择（多轮检测后保存全部可用中转的优先级）\n'
    printf ' [q] 取消\n选择一个或多个中转编号（如 2,4,6；官方 raw 始终最后备选）: '
    read -r choice
    [ "$choice" = q ] || [ "$choice" = Q ] && return 0
    if [ "$choice" = a ] || [ "$choice" = A ]; then auto_select_github; return $?; fi
    [ -n "$choice" ] || { fail '输入无效。'; return 1; }
    IFS=',' read -ra selected_names <<< "$choice"
    local selected_count=0
    local resolved=()
    for item in "${selected_names[@]}"; do
        item=$(printf '%s' "$item" | tr -d '[:space:]')
        [[ "$item" =~ ^[0-9]+$ ]] || { fail '输入无效：请输入逗号分隔的编号。'; return 1; }
        index=$((item - 1))
        [ "$index" -ge 0 ] && [ "$index" -lt "${#entries[@]}" ] || { fail '输入超出范围。'; return 1; }
        name="${entries[$index]%%|*}"
        [ "$name" != official ] || { fail '官方 raw 固定为最后备选，不能加入中转优先级。'; return 1; }
        resolved+=("$name")
        selected_count=$((selected_count + 1))
    done
    [ "$selected_count" -gt 0 ] || { fail '至少选择一个中转站。'; return 1; }
    local valid=()
    for name in "${resolved[@]}"; do
        if sec_github_prepare_endpoint "$name"; then valid+=("$name"); else warn "$(sec_github_endpoint_label "$name") 未通过多轮探测，跳过。"; fi
    done
    [ "${#valid[@]}" -gt 0 ] || { fail '没有选中的中转站通过验证。'; return 1; }
    sec_github_set_endpoints "${valid[@]}" || { fail '保存 GitHub 中转优先级失败。'; return 1; }
    ok "已保存 GitHub 中转优先级：${valid[*]}；官方 raw 保留为最后备选。"
}
menu() {
    while true; do
        echo ''
        echo '========== IPv6 出口 / WARP / GitHub 加速中心 =========='
        echo ' [1] 查看当前 IPv4/IPv6 出口与 WARP 状态'
        echo ' [2] 安装 Cloudflare WARP 官方软件包（不连接）'
        echo ' [3] 注册并连接 WARP 全隧道（IPv4/IPv6 都走 WARP）'
        echo ' [4] 注册并连接 WARP IPv4-only（IPv4 走 WARP，IPv6 保持原出口）'
        echo ' [5] 断开 WARP'
        echo ' [6] 多轮探测 GitHub 中转站'
        echo ' [7] 手动选择多个 GitHub 中转优先级'
        echo ' [8] 自动选择可用 GitHub 中转（多轮）'
        echo ' [q] 返回主菜单'
        printf '请选择: '
        read -r choice
        case "$choice" in
            1) show_status; read -r -p '按回车返回...' _ ;;
            2) warp_install; read -r -p '按回车返回...' _ ;;
            3) warp_register_connect; read -r -p '按回车返回...' _ ;;
            4) warp_register_connect_ipv4_only; read -r -p '按回车返回...' _ ;;
            5) warp_disconnect; read -r -p '按回车返回...' _ ;;
            6) probe_github; read -r -p '按回车返回...' _ ;;
            7) select_github; read -r -p '按回车返回...' _ ;;
            8) auto_select_github; read -r -p '按回车返回...' _ ;;
            q|Q) return 0 ;;
        esac
    done
}

[ "$(id -u)" -eq 0 ] || { fail '请使用 root 权限运行 v4.sh。'; exit 1; }
sec_toolbox_acquire_lock 'v4-ipv6-warp' || exit 1
trap 'sec_toolbox_release_lock' EXIT INT TERM
menu
