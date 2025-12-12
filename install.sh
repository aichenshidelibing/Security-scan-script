#!/usr/bin/env bash
# install.sh - 统一安全工具启动主控台 (v1.0)
# 功能：从 GitHub WGET 下载 v0, v1, v2, v3 脚本并提供菜单选择运行。

set -u
export LC_ALL=C

# --- 配置 ---
# 【重要】请将这里的 GITHUB_BASE 替换为你存放 v0-v3 脚本的实际仓库地址
# 示例：假设你将所有脚本放在 https://raw.githubusercontent.com/YourUser/YourRepo/main/
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main" 

# --- 颜色定义 ---
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

# --- 辅助工具 ---
ui_header() { echo -e "\n${BLUE}=====================================================${RESET}"; }
ui_info() { echo -e "${CYAN}ℹ️  $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}✅ $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}⚠️  $*${RESET}"; }
ui_fail() { echo -e "${RED}❌ $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 核心函数：下载与权限检查 ---
download_script() {
    local script_name="$1"
    local url="${GITHUB_BASE}/${script_name}"
    
    ui_info "正在下载 ${script_name}..."
    if cmd_exists wget; then
        wget -q -O "$script_name" "$url"
    elif cmd_exists curl; then
        curl -s -o "$script_name" "$url"
    else
        ui_fail "未找到 wget 或 curl，无法下载脚本！"
        return 1
    fi

    if [ -f "$script_name" ]; then
        # 修复格式问题 (CRLF to LF)
        if cmd_exists sed; then
            sed -i 's/\r$//' "$script_name"
        fi
        chmod +x "$script_name"
        ui_ok "${script_name} 下载完成并已赋予执行权限。"
        return 0
    else
        ui_fail "${script_name} 下载失败，请检查 GitHub 链接是否正确。"
        return 1
    fi
}

# --- 菜单函数 ---
main_menu() {
    clear
    ui_header
    echo "${BOLD}${CYAN}      🛡️  Linux 安全工具箱 1.0 - 主控台      ${RESET}"
    ui_header
    echo "${BOLD}当前已就绪的脚本：${RESET}"
    
    # 动态检查脚本文件是否存在
    local V0_STATUS=$( [ -x "v0.sh" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}未下载${RESET}" )
    local V1_STATUS=$( [ -x "v1.sh" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}未下载${RESET}" )
    local V2_STATUS=$( [ -x "v2.sh" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}未下载${RESET}" )
    local V3_STATUS=$( [ -x "v3.sh" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}未下载${RESET}" )
    
    # 菜单列表
    echo " ${BOLD}0) 安全体检 (v0.sh):${RESET} 全面审计，只检测不修改。  [状态: $V0_STATUS]"
    echo " ${BOLD}1) 基础加固 (v1.sh):${RESET} 修复SSH/端口/权限等。 [状态: $V1_STATUS]"
    echo " ${BOLD}2) 密钥配置 (v2.sh):${RESET} 生成密钥，关闭密码登录。 [状态: $V2_STATUS]"
    echo " ${BOLD}3) 网络隐身 (v3.sh):${RESET} 禁/恢复 ICMP Ping 功能。 [状态: $V3_STATUS]"
    echo ""
    echo " ${BOLD}${YELLOW}9) [重新下载所有脚本]${RESET}"
    echo " ${BOLD}${RED}0) [退出主控台]${RESET}"
    ui_header
    
    echo -ne "${CYAN}请选择操作编号 (0-3 或 9): ${RESET}"
    read -r CHOICE

    case "$CHOICE" in
        0) exec ./v0.sh ;;
        1) exec ./v1.sh ;;
        2) exec ./v2.sh ;;
        3) exec ./v3.sh ;;
        9) 
            ui_info "正在尝试下载或更新所有脚本..."
            download_script v0.sh
            download_script v1.sh
            download_script v2.sh
            download_script v3.sh
            ui_ok "下载/更新流程完成，请重新进入菜单。"
            sleep 3
            main_menu # 重新进入菜单
            ;;
        *)
            ui_fail "无效选择或已退出。";;
    esac
}

# --- 主执行流程 ---

need_root() { [ "$(id -u)" -eq 0 ] || { ui_fail "请以 root 运行本脚本"; exit 1; }; }
need_root

# 首次检查核心脚本是否存在，如果不存在，引导用户下载
if [ ! -x "v1.sh" ] || [ ! -x "v2.sh" ]; then
    ui_warn "首次运行：核心脚本不存在，将自动进行下载。"
    download_script v0.sh
    download_script v1.sh
    download_script v2.sh
    download_script v3.sh
fi

main_menu
