#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# install.sh - Linux 安全工具箱主控台 (v3.1 稳定修复版)
# 特性：修复变量缺失报错 | 系统仪表盘 | 细化下载中心 | 极致兼容

export LC_ALL=C

# --- [手动修正位] 如果标题或状态依然显示方块乱码，请将 0 改为 1 ---
FORCE_TEXT_MODE=0

# --- 配置 ---
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/main"
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
        I_DL="⬇️ "; I_SET="⚙️ "; I_SYS="🖥️ "; I_EXIT="🚪"
    else
        I_MAIN="[*]"; I_OK="[OK]"; I_WARN="[!]"; I_FAIL="[X]"; I_INFO="[i]"
        I_DL="[DL]"; I_SET="[ST]"; I_SYS="[SYS]"; I_EXIT="[Q]"
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
    echo -e "${BOLD}${CYAN}           ${I_MAIN} Linux Security Toolbox v3.1 (终极主控台) ${RESET}"
    ui_header
    printf "  ${I_SYS} 系统: ${WHITE}%-30s ${GREY} IP: ${WHITE}%-15s${RESET}\n" "${os_info:0:30}" "$ip_addr"
    printf "  ${GREY}⏰ 时间: ${WHITE}%-30s ${GREY} 用户: ${WHITE}%-15s${RESET}\n" "$time_now" "$user_now"
    ui_line
}

# --- 核心函数：下载 ---
download_script() {
    local name="$1"
    local url="${GITHUB_BASE}/${name}"
    
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
        echo " [a] 一键更新所有脚本 (All)"
        echo " [q] 返回主菜单"
        ui_line
        echo -ne "${CYAN}请输入选择: ${RESET}"
        read -r dl_choice
        
        case "$dl_choice" in
            [0-3]) download_script "v${dl_choice}.sh"; sleep 1 ;;
            a|A) for s in v0.sh v1.sh v2.sh v3.sh; do download_script "$s"; done
                ui_ok "同步完成。"; sleep 1; return ;;
            q|Q) return ;;
        esac
    done
}

# --- 核心功能：清理脚本 ---
cleanup_scripts() {
    echo ""
    echo -e "${YELLOW}${I_WARN} 即将通过特征码扫描并清理本工具箱的所有子脚本...${RESET}"
    local files=$(grep -l "$TAG_MARKER" *.sh 2>/dev/null | grep -v "$(basename "$0")")
    if [ -n "$files" ]; then
        echo -e "${WHITE}发现待删文件: ${YELLOW}$files${RESET}"
        read -p "确认清理？(yes/no): " c
        [ "$c" == "yes" ] && { rm -f $files; ui_ok "清理完成。"; } || echo "已取消。"
    else
        echo "未发现可清理脚本。"
    fi
    sleep 1.5
}

# --- 主菜单循环 ---
main_menu() {
    while true; do
        show_dashboard
        st() { [ -x "$1" ] && echo "${GREEN}已就绪${RESET}" || echo "${GREY}未下载${RESET}"; }
        
        echo -e "${BOLD}工具列表${RESET}"
        ui_line
        printf " [0] %-30s [状态: %s]\n" "全维审计 (v0.sh)" "$(st v0.sh)"
        echo -e "     ${GREY}└─ 只查不改 / 硬件仪表盘 / 36项深度体检 / 评分报告${RESET}"
        printf " [1] %-30s [状态: %s]\n" "全能管家 (v1.sh)" "$(st v1.sh)"
        echo -e "     ${GREY}└─ BBR加速 / 救砖换源 / 批量安装 / 36项加固 / 补丁修复${RESET}"
        printf " [2] %-30s [状态: %s]\n" "密钥配置 (v2.sh)" "$(st v2.sh)"
        echo -e "     ${GREY}└─ 禁用密码登录 / 自动生成密钥对 / 权限自动修正${RESET}"
        printf " [3] %-30s [状态: %s]\n" "网络隐身 (v3.sh)" "$(st v3.sh)"
        echo -e "     ${GREY}└─ 开启或关闭禁 Ping / 隐藏服务器存活状态${RESET}"
        ui_line
        echo " [8] 智能清理 (清理所有工具脚本)"
        echo " [9] 下载中心 (单独下载或批量更新)"
        echo " [q] 退出主控台"
        ui_line
        echo -ne "${CYAN}请选择操作编号: ${RESET}"
        read -r CHOICE

        case "$CHOICE" in
            [0-3])
                local S="v${CHOICE}.sh"
                if [ -x "$S" ]; then ./"$S"
                else ui_fail "$S 缺失，请先选 9 进入下载中心。"; sleep 2; fi ;;
            8) cleanup_scripts ;;
            9) menu_download ;;
            q|Q) echo -e "${CYAN}感谢使用，再见。${RESET}"; exit 0 ;;
        esac
    done
}

# --- 前置检查 ---
[ "$(id -u)" -eq 0 ] || { echo -e "${RED}${I_FAIL} 错误: 请使用 root 权限运行。${RESET}"; exit 1; }
if [ ! -x "v0.sh" ] && [ ! -x "v1.sh" ]; then
    show_dashboard
    echo -e "${YELLOW}${I_WARN} 检测到核心组件缺失，正在进行初始化下载...${RESET}"
    download_script "v0.sh"
    download_script "v1.sh"
    sleep 1
fi

main_menu
