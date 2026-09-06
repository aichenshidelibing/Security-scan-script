#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# SEC_TOOLBOX_VERSION=4.0.0
# install.sh - Linux 安全工具箱主控台 (v4.0 增强版)
# 特性：版本自检 | 本地模式 | BBR 多版本 | v5 出口加速中心 | 统一 emoji

export LC_ALL=C

# --- [手动修正位] 如果标题或状态依然显示方块乱码，请将 0 改为 1 ---
FORCE_TEXT_MODE=0

# --- 启动参数解析 ---
# 支持: --local / -l / --bendi  启用本地模式（不发起任何网络请求）
SEC_LOCAL_MODE=0
for arg in "$@"; do
    case "$arg" in
        --local|-l|--bendi) SEC_LOCAL_MODE=1 ;;
        *) ;;
    esac
done
export SEC_LOCAL_MODE

# --- 配置 ---
GITHUB_BASE="https://gh-proxy.org/raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
GITHUB_RAW_BASE="https://github.com/aichenshidelibing/Security-scan-script/raw/refs/heads/main"
TAG_MARKER="<SEC_SCRIPT_MARKER_v2.3>"
SEC_TOOLBOX_VERSION="${SEC_TOOLBOX_VERSION:-4.0.0}"
SEC_TOOLBOX_VERSION_URL="${SEC_TOOLBOX_VERSION_URL:-$GITHUB_BASE/install.sh}"
SEC_UPDATE_CHECK="${SEC_UPDATE_CHECK:-1}"

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
        # 单一图标集，兼容 SSH 和 VNC 客户端
        I_MAIN="▶"; I_OK="✓"; I_WARN="!"; I_FAIL="✗"; I_INFO="»"
        I_DL="↓"; I_SET="⚙"; I_SYS="●"; I_EXIT="×"; I_CHECK="?"
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
    echo -e "${BOLD}${CYAN}           ${I_MAIN} Linux Security Toolbox v${SEC_TOOLBOX_VERSION}${mode_tag} ${RESET}"
    ui_header
    printf "  ${I_SYS} 系统: ${WHITE}%-30s ${GREY} IP: ${WHITE}%-15s${RESET}\n" "${os_info:0:30}" "$ip_addr"
    printf "  ${GREY}⏰ 时间: ${WHITE}%-30s ${GREY} 用户: ${WHITE}%-15s${RESET}\n" "$time_now" "$user_now"
    ui_line
}

# --- 核心函数：下载 ---
download_script() {
    local name="$1"
    local url="${GITHUB_BASE}/${name}"

    if [ "$SEC_LOCAL_MODE" = 1 ]; then
        if [ -f "$name" ]; then
            echo -e "${GREY}[本地] 已就绪 $name${RESET}"
            return 0
        fi
        echo -e "${RED}失败 (本地模式且 $name 不存在)${RESET}"
        return 1
    fi

    echo -ne "${CYAN}${I_DL} 正在获取 ${name}... ${RESET}"
    if cmd_exists wget; then
        wget -q -O "$name" "$url"
    elif cmd_exists curl; then
        curl -s -o "$name" "$url"
    else
        echo -e "${RED}失败 (缺少工具)${RESET}"
        return 1
    fi

    if [ -s "$name" ]; then
        sed -i 's/\r$//' "$name" 2>/dev/null
        chmod +x "$name"
        echo -e "${GREEN}成功${RESET}"
        return 0
    else
        echo -e "${RED}失败 (文件无效)${RESET}"
        return 1
    fi
}

# --- 启动预检查：检查远端是否有更新版本（可跳过） ---
check_update() {
    [ "$SEC_LOCAL_MODE" = 1 ] && return 0
    [ "$SEC_UPDATE_CHECK" != 1 ] && return 0
    local remote_ver="" tmp
    tmp=$(mktemp 2>/dev/null) || tmp="/tmp/sec_toolbox_check_$$"
    if cmd_exists curl; then
        curl -fsSL --connect-timeout 3 --max-time 8 -o "$tmp" "$SEC_TOOLBOX_VERSION_URL" >/dev/null 2>&1
    elif cmd_exists wget; then
        wget -q -O "$tmp" --timeout=5 --tries=1 "$SEC_TOOLBOX_VERSION_URL" >/dev/null 2>&1
    fi
    if [ -s "$tmp" ]; then
        remote_ver=$(grep -E '^# SEC_TOOLBOX_VERSION=' "$tmp" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')
    fi
    rm -f -- "$tmp" 2>/dev/null
    [ -z "$remote_ver" ] && return 0
    [ "$remote_ver" = "$SEC_TOOLBOX_VERSION" ] && return 0
    echo -e "${YELLOW}${I_WARN} 远端版本: $remote_ver (本地: $SEC_TOOLBOX_VERSION)${RESET}"
    echo -ne "${CYAN}是否进入 [9] 下载中心更新? (y/N/s=永久跳过本次会话): ${RESET}"
    read -r upd
    case "$upd" in
        y|Y|yes|YES) menu_download; return 0 ;;
        s|S|skip)   SEC_UPDATE_CHECK=0; return 0 ;;
        *)          return 0 ;;
    esac
}

# --- 本地自检：语法与基础完整性 ---
self_check() {
    local scripts="install.sh v0.sh v1.sh v2.sh v3.sh v4.sh v5.sh"
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
        ui_line
        echo " [4] 拉取 v4.sh (IPv6 出口/WARP/GitHub加速 - 主动拉取)"
        echo " [5] 拉取 v5.sh (WARP + GitHub加速源自动配置 - 主动拉取)"
        echo " [a] 一键更新所有脚本 (All)"
        echo " [q] 返回主菜单"
        ui_line
        echo -ne "${CYAN}请输入选择: ${RESET}"
        read -r dl_choice

        case "$dl_choice" in
            [0-3]) download_script "v${dl_choice}.sh"; sleep 1 ;;
            4) download_script "v4.sh"; sleep 1 ;;
            5) download_script "v5.sh"; sleep 1 ;;
            a|A) for s in v0.sh v1.sh v2.sh v3.sh v4.sh v5.sh; do download_script "$s"; done
                ui_ok "同步完成。"; sleep 1; return ;;
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
        [ -f "v4.sh" ] && { printf " [4] %-30s [状态: %s]\n" "IPv6出口中心 (v4.sh)" "$(st v4.sh)"; echo -e "     ${GREY}└─ WARP IPv4 出口 / GitHub IPv6 加速 fallback${RESET}"; }
        [ -f "v5.sh" ] && { printf " [5] %-30s [状态: %s]\n" "出口与加速源 (v5.sh)" "$(st v5.sh)"; echo -e "     ${GREY}└─ WARP 安装 / GitHub 镜像源自动配置${RESET}"; }
        ui_line
        echo " [7] 本地自检 (检查脚本语法)"
        echo " [8] 智能清理 (清理所有工具脚本)"
        echo " [9] 下载中心 (单独下载或批量更新)"
        echo " [q] 退出主控台"
        ui_line
        echo -ne "${CYAN}请选择操作编号: ${RESET}"
        read -r CHOICE

        case "$CHOICE" in
            [0-5])
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

# --- 前置检查 ---
[ "$(id -u)" -eq 0 ] || { echo -e "${RED}${I_FAIL} 错误: 请使用 root 权限运行。${RESET}"; exit 1; }

# 启动预检查：检测远端版本
[ "$SEC_LOCAL_MODE" = 1 ] || check_update

# v0/v1 默认需要；v2/v3/v4/v5 仅在已存在时加载（v4/v5 默认不主动拉取）
NEED_INIT=0
[ ! -x "v0.sh" ] && NEED_INIT=1
[ ! -x "v1.sh" ] && NEED_INIT=1

if [ "$NEED_INIT" = 1 ] && [ "$SEC_LOCAL_MODE" != 1 ]; then
    show_dashboard
    echo -e "${YELLOW}${I_WARN} 检测到核心组件缺失，正在进行初始化下载...${RESET}"
    download_script "v0.sh"
    download_script "v1.sh"
    sleep 1
fi

main_menu
