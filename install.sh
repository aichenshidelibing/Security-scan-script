#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# install.sh - Linux 安全工具箱主控台 (v3.2 稳定增强版)
# 特性：安全下载校验 | 本地自检 | 系统仪表盘 | 细化下载中心 | 极致兼容

export LC_ALL=C

# --- [手动修正位] 如果标题或状态依然显示方块乱码，请将 0 改为 1 ---
FORCE_TEXT_MODE=0

# --- 配置 ---
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
GITHUB_FALLBACK_BASE="https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
# Bootstrap candidates mirror lib/github.sh. They are tried before official GitHub.
GITHUB_ACCELERATOR_BASES=(
    "$GITHUB_FALLBACK_BASE"
    "https://v6.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://cdn.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://axisnow.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://gh-proxy.com/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://v4.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://ghproxy.net/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
    "https://ghfast.top/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
)
GITHUB_RAW_BASE="https://github.com/aichenshidelibing/Security-scan-script/raw/refs/heads/main"
TAG_MARKER="<SEC_SCRIPT_MARKER_v2.3>" # 唯一特征识别码

# --- [核心] 智能环境检测与配色 ---
detect_env() {
    # 1. Emoji 检测
    if [ "$FORCE_TEXT_MODE" == "1" ]; then export USE_EMOJI="0"; else
        [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]] && export USE_EMOJI="1" || export USE_EMOJI="0"
        [[ "${TERM:-}" == "linux" ]] || [[ "${TERM:-}" == "vt100" ]] && export USE_EMOJI="0"
    fi

    # 2. 颜色定义 [已修复 GREY 缺失问题]
    RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
    PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); GREY=$(printf '\033[90m');
    RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

    # 3. 图标定义
    if [ "$USE_EMOJI" == "1" ]; then
        I_MAIN="🛡️ "; I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "
        I_DL="⬇️ "; I_SET="⚙️ "; I_SYS="🖥️ "; I_EXIT="🚪"; I_CHECK="🧪"
    else
        I_MAIN="[*]"; I_OK="[OK]"; I_WARN="[!]"; I_FAIL="[X]"; I_INFO="[i]"
        I_DL="[DL]"; I_SET="[ST]"; I_SYS="[SYS]"; I_EXIT="[Q]"; I_CHECK="[CK]"
    fi
}
detect_env

# --- 辅助 UI 工具 ---
ui_header() { echo -e "${BLUE}################################################################################${RESET}"; }
ui_line()   { echo -e "${GREY}--------------------------------------------------------------------------------${RESET}"; }
ui_ok()     { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_fail()   { echo -e "${RED}${I_FAIL} $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 顶部仪表盘 (Dashboard) ---
show_dashboard() {
    clear
    local os_info=""; [ -f /etc/os-release ] && os_info=$(grep "^PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"') || os_info=$(cat /etc/issue | head -n 1)
    local ip_addr=$(hostname -I 2>/dev/null | cut -d' ' -f1); [ -z "$ip_addr" ] && ip_addr="127.0.0.1"
    local time_now=$(date "+%Y-%m-%d %H:%M")
    local user_now=$(whoami)

    ui_header
    echo -e "${BOLD}${CYAN}           ${I_MAIN} Linux Security Toolbox v3.2 (稳定增强版) ${RESET}"
    ui_header
    printf "  ${I_SYS} 系统: ${WHITE}%-30s ${GREY} IP: ${WHITE}%-15s${RESET}\n" "${os_info:0:30}" "$ip_addr"
    printf "  ${GREY}⏰ 时间: ${WHITE}%-30s ${GREY} 用户: ${WHITE}%-15s${RESET}\n" "$time_now" "$user_now"
    ui_line
}

# --- 核心函数：下载 ---
github_cached_fallback_base() {
    local file="${SEC_GITHUB_ENDPOINT_FILE:-/etc/sec-toolbox/github-endpoint}" name
    [ -r "$file" ] || return 0
    while IFS= read -r name; do
        name=$(printf '%s' "$name" | tr -d '[:space:]')
        case "$name" in
            gh-proxy-org) printf '%s\n' 'https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            gh-proxy-v4) printf '%s\n' 'https://v4.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            gh-proxy-v6) printf '%s\n' 'https://v6.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            gh-proxy-cdn) printf '%s\n' 'https://cdn.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            axisnow) printf '%s\n' 'https://axisnow.gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            gh-proxy-com) printf '%s\n' 'https://gh-proxy.com/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            gh-proxy) printf '%s\n' 'https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            ghproxy) printf '%s\n' 'https://ghproxy.net/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
            ghfast) printf '%s\n' 'https://ghfast.top/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main' ;;
        esac
    done <"$file"
}
download_ip_mode() {
    if command -v ip >/dev/null 2>&1; then
        if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 ' &&
           ! ip -4 addr show scope global 2>/dev/null | grep -q 'inet '; then
            printf '%s\n' 'pure_ipv6'
            return 0
        fi
        if ip -4 addr show scope global 2>/dev/null | grep -q 'inet ' &&
           ! ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
            printf '%s\n' 'ipv4_only'
            return 0
        fi
    fi
    printf '%s\n' 'dual_stack'
}

download_family_args() {
    [ "$(download_ip_mode)" = pure_ipv6 ] && printf '%s\n' '-6'
}

download_base_supported() {
    local base="$1" mode
    mode=$(download_ip_mode)
    case "$base" in
        *v4.gh-proxy.org*) [ "$mode" != pure_ipv6 ] ;;
        *v6.gh-proxy.org*) [ "$mode" != ipv4_only ] ;;
        *) return 0 ;;
    esac
}

download_base_label() {
    local base="$1"
    case "$base" in
        *v6.gh-proxy.org*) printf '%s\n' 'v6.gh-proxy.org' ;;
        *cdn.gh-proxy.org*) printf '%s\n' 'cdn.gh-proxy.org' ;;
        *axisnow.gh-proxy.org*) printf '%s\n' 'axisnow.gh-proxy.org' ;;
        *v4.gh-proxy.org*) printf '%s\n' 'v4.gh-proxy.org' ;;
        *gh-proxy.org/https://raw.githubusercontent.com*) printf '%s\n' 'gh-proxy.org' ;;
        *gh-proxy.com*) printf '%s\n' 'gh-proxy.com' ;;
        *ghproxy.net*) printf '%s\n' 'ghproxy.net' ;;
        *ghfast.top*) printf '%s\n' 'ghfast.top' ;;
        *raw.githubusercontent.com*) printf '%s\n' 'GitHub official raw' ;;
        *github.com/*/raw/*) printf '%s\n' 'GitHub raw path' ;;
        *) printf '%s\n' "$base" ;;
    esac
}

download_script() {
    local name="$1" target_family url downloaded=0 base candidate duplicate tmp status last_error='' invalid_marker=0
    target_family=$(download_family_args)
    mkdir -p "$(dirname -- "$name")" 2>/dev/null || return 1
    echo -e "${CYAN}${I_DL} fetching ${name}... ${RESET}"

    if ! cmd_exists curl && ! cmd_exists wget; then
        echo -e "${RED}failed (missing curl/wget; please install one downloader first)${RESET}"
        return 127
    fi

    # Prefer validated/configured accelerators; official GitHub is last.
    local bases=()
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        duplicate=0
        for base in "${bases[@]}"; do [ "$base" = "$candidate" ] && duplicate=1 && break; done
        [ "$duplicate" -eq 0 ] && bases+=("$candidate")
    done < <(github_cached_fallback_base)
    for candidate in "${GITHUB_ACCELERATOR_BASES[@]}"; do
        [ -n "$candidate" ] || continue
        duplicate=0
        for base in "${bases[@]}"; do [ "$base" = "$candidate" ] && duplicate=1 && break; done
        [ "$duplicate" -eq 0 ] && bases+=("$candidate")
    done
    bases+=("$GITHUB_BASE" "$GITHUB_RAW_BASE")

    tmp="${name}.tmp.$$.$RANDOM"
    for base in "${bases[@]}"; do
        download_base_supported "$base" || continue
        echo -e "${GREY}     trying $(download_base_label "$base")...${RESET}"
        url="${base}/${name}"
        rm -f -- "$tmp"
        if cmd_exists curl; then
            if [ -n "$target_family" ]; then
                curl "$target_family" -fsSL --connect-timeout "${SEC_DOWNLOAD_CONNECT_TIMEOUT:-4}" --max-time "${SEC_DOWNLOAD_MAX_TIME:-12}" --retry "${SEC_DOWNLOAD_RETRY:-1}" -o "$tmp" "$url" >/dev/null 2>&1
            else
                curl -fsSL --connect-timeout "${SEC_DOWNLOAD_CONNECT_TIMEOUT:-4}" --max-time "${SEC_DOWNLOAD_MAX_TIME:-12}" --retry "${SEC_DOWNLOAD_RETRY:-1}" -o "$tmp" "$url" >/dev/null 2>&1
            fi
            status=$?
            [ "$status" -eq 0 ] || last_error="curl exit $status @ $base"
        elif cmd_exists wget; then
            if [ -n "$target_family" ]; then
                wget "$target_family" -q -O "$tmp" --timeout="${SEC_DOWNLOAD_WGET_TIMEOUT:-8}" --tries="${SEC_DOWNLOAD_WGET_TRIES:-1}" "$url" >/dev/null 2>&1
            else
                wget -q -O "$tmp" --timeout="${SEC_DOWNLOAD_WGET_TIMEOUT:-8}" --tries="${SEC_DOWNLOAD_WGET_TRIES:-1}" "$url" >/dev/null 2>&1
            fi
            status=$?
            [ "$status" -eq 0 ] || last_error="wget exit $status @ $base"
        fi
        if [ -s "$tmp" ]; then
            # Reject an HTML error page from a proxy when downloading scripts.
            if [[ "$name" == *.sh ]] && ! grep -Fq -- "$TAG_MARKER" "$tmp" 2>/dev/null; then
                invalid_marker=$((invalid_marker + 1))
                last_error="downloaded content failed script marker check @ $base"
                rm -f -- "$tmp"
                continue
            fi
            mv -f -- "$tmp" "$name" || { rm -f -- "$tmp"; echo -e "${RED}failed (cannot replace target file)${RESET}"; return 1; }
            downloaded=1
            break
        fi
    done

    rm -f -- "$tmp"
    if [ "$downloaded" -eq 1 ] && [ -s "$name" ]; then
        sed -i 's/\r$//' "$name" 2>/dev/null
        chmod +x "$name"
        echo -e "${GREEN}success${RESET}"
        return 0
    fi
    if [ "$invalid_marker" -gt 0 ]; then
        echo -e "${RED}failed (endpoints returned invalid content; existing local file preserved)${RESET}"
    elif [ -n "$last_error" ]; then
        echo -e "${RED}failed (no endpoint succeeded; ${last_error}; existing local file preserved)${RESET}"
    else
        echo -e "${RED}failed (no IPv4/IPv6-compatible endpoint succeeded; existing local file preserved)${RESET}"
    fi
    return 1
}
download_runtime_libs() {
    download_script "lib/runtime.sh" || return 1
    download_script "lib/network_checks.sh" || return 1
    download_script "lib/github.sh" || return 1
}

# --- 本地自检：语法与基础完整性 ---
self_check() {
    local scripts="install.sh lib/runtime.sh lib/network_checks.sh lib/github.sh v0.sh v1.sh v2.sh v3.sh v4.sh"
    local failed=0

    echo ""
    echo -e "${BOLD}${I_CHECK} 本地自检 / 语法检查${RESET}"
    ui_line
    for script in $scripts; do
        if [ ! -f "$script" ]; then
            echo -e "${YELLOW}${I_WARN} $script 不存在，跳过。${RESET}"
            continue
        fi

        echo -ne "${CYAN}检查 $script ... ${RESET}"
        if bash -n "$script" 2>/tmp/sec_toolbox_check.err; then
            echo -e "${GREEN}通过${RESET}"
        else
            echo -e "${RED}失败${RESET}"
            sed 's/^/    /' /tmp/sec_toolbox_check.err
            failed=1
        fi
    done
    rm -f /tmp/sec_toolbox_check.err
    ui_line

    if [ "$failed" -eq 0 ]; then
        ui_ok "自检完成，未发现 Bash 语法错误。"
    else
        ui_fail "发现语法错误，请先修复后再运行加固功能。"
    fi
    echo -ne "${YELLOW}${I_INFO} 按任意键返回主菜单...${RESET}"
    read -n 1 -s -r
}

# --- 子菜单：下载管理 ---
menu_download() {
    while true; do
        show_dashboard
        echo -e "${BOLD}下载/更新中心${RESET}"
        ui_line
        echo " [0] 下载 v0.sh (全维安全审计)"
        echo " [1] 下载 v1.sh (全能管家/修复)"
        echo " [2] 下载 v2.sh (SSH密钥配置)"
        echo " [3] 下载 v3.sh (网络隐身/禁Ping)"
        echo " [4] 下载 v4.sh (IPv6出口/WARP/GitHub加速)"
        ui_line
        echo " [a] 一键更新所有脚本 (All)"
        echo " [q] 返回主菜单"
        ui_line
        echo -ne "${CYAN}请输入选择: ${RESET}"
        read -r dl_choice
        
        case "$dl_choice" in
            [0-4]) download_runtime_libs || ui_fail "公共库下载失败；将继续尝试下载所选脚本，已有本地文件不会被删除。"; download_script "v${dl_choice}.sh"; sleep 1 ;;
            a|A)
                local sync_failed=0
                download_runtime_libs || sync_failed=1
                for s in v0.sh v1.sh v2.sh v3.sh v4.sh; do download_script "$s" || sync_failed=1; done
                if [ "$sync_failed" -eq 0 ]; then ui_ok "同步完成。"; else ui_fail "部分组件下载失败；已保留现有本地文件，可稍后重试或检查网络/DNS/证书。"; fi
                sleep 1; return ;;
            q|Q) return ;;
        esac
    done
}

# --- 核心功能：清理脚本 ---
cleanup_scripts() {
    echo ""
    echo -e "${YELLOW}${I_WARN} 即将通过特征码扫描并清理本工具箱的所有子脚本...${RESET}"
    local current_script
    current_script=$(basename "$0")
    local files=()
    local f

    for f in *.sh; do
        [ -e "$f" ] || continue
        [ "$f" = "$current_script" ] && continue
        grep -q "$TAG_MARKER" "$f" 2>/dev/null && files+=("$f")
    done

    if [ "${#files[@]}" -gt 0 ]; then
        printf "${WHITE}发现待删文件:${RESET}\n"
        printf "  ${YELLOW}%s${RESET}\n" "${files[@]}"
        read -p "确认清理？(yes/no): " c
        if [ "$c" == "yes" ]; then
            rm -f -- "${files[@]}"
            ui_ok "清理完成。"
        else
            echo "已取消。"
        fi
    else
        echo "未发现可清理脚本。"
    fi
    sleep 1.5
}

# --- 主菜单循环 ---
main_menu() {
    while true; do
        show_dashboard
        st() { [ -f "$1" ] && echo "${GREEN}已就绪${RESET}" || echo "${GREY}未下载${RESET}"; }
        
        echo -e "${BOLD}工具列表${RESET}"
        ui_line
        printf " [0] %-30s [状态: %s]\n" "全维审计 (v0.sh)" "$(st v0.sh)"
        echo -e "     ${GREY}└─ 只查不改 / 硬件仪表盘 / 安全精简审计 / 评分报告${RESET}"
        printf " [1] %-30s [状态: %s]\n" "基础管家 (v1.sh)" "$(st v1.sh)"
        echo -e "     ${GREY}└─ APT源优化 / 基础工具 / SSH低风险项 / 权限与日志修复${RESET}"
        printf " [2] %-30s [状态: %s]\n" "SSH策略中心 (v2.sh)" "$(st v2.sh)"
        echo -e "     ${GREY}└─ 密钥部署 / 改端口 / 密码登录 / Root登录策略 / 回滚${RESET}"
        printf " [3] %-30s [状态: %s]\n" "网络隐身 (v3.sh)" "$(st v3.sh)"
        echo -e "     ${GREY}└─ 开启或关闭禁 Ping / 隐藏服务器存活状态${RESET}"
        printf " [4] %-30s [状态: %s]\n" "IPv6出口中心 (v4.sh)" "$(st v4.sh)"
        echo -e "     ${GREY}└─ WARP IPv4 出口 / GitHub IPv6 加速 fallback${RESET}"
        ui_line
        echo " [7] 本地自检 (检查脚本语法)"
        echo " [8] 智能清理 (清理所有工具脚本)"
        echo " [9] 下载中心 (单独下载或批量更新)"
        echo " [q] 退出主控台"
        ui_line
        echo -ne "${CYAN}请选择操作编号: ${RESET}"
        read -r CHOICE

        case "$CHOICE" in
            [0-4])
                local S="v${CHOICE}.sh"
                if [ -f "$S" ]; then bash ./"$S"
                else ui_fail "$S 缺失，请先选 9 进入下载中心。"; sleep 2; fi ;;
            7) self_check ;;
            8) cleanup_scripts ;;
            9) menu_download ;;
            q|Q) echo -e "${CYAN}感谢使用，再见。${RESET}"; exit 0 ;;
        esac
    done
}

# --- 前置检查 / 启动初始化 ---
bootstrap_missing_components() {
    local missing=0 failed=0 component
    local libs=(lib/runtime.sh lib/network_checks.sh lib/github.sh)
    local scripts=(v0.sh v1.sh v2.sh v3.sh v4.sh)

    for component in "${libs[@]}" "${scripts[@]}"; do
        [ -f "$component" ] || missing=1
    done
    [ "$missing" -eq 1 ] || return 0

    show_dashboard
    echo -e "${YELLOW}${I_WARN} 检测到组件缺失，将进行一次非阻塞初始化下载...${RESET}"
    echo -e "${GREY}     如果 GitHub/中转站/DNS/证书暂时不可用，脚本会跳过失败项并继续进入主菜单。${RESET}"

    for component in "${libs[@]}"; do
        [ -f "$component" ] && continue
        download_script "$component" || failed=1
    done
    for component in "${scripts[@]}"; do
        [ -f "$component" ] && continue
        download_script "$component" || failed=1
    done

    if [ "$failed" -eq 1 ]; then
        echo -e "${YELLOW}${I_WARN} 初始化下载失败（部分组件不可用），已跳过失败项并继续进入主菜单。${RESET}"
        echo -e "${GREY}     可稍后进入 [9] 下载中心重试；已有本地文件不会因下载失败被删除。${RESET}"
    else
        ui_ok "初始化下载完成。"
    fi
    sleep 1
    return 0
}

if [ "${SEC_TOOLBOX_NO_MAIN:-0}" != 1 ]; then
    [ "$(id -u)" -eq 0 ] || { echo -e "${RED}${I_FAIL} 错误: 请使用 root 权限运行。${RESET}"; exit 1; }
    bootstrap_missing_components
    main_menu
fi
