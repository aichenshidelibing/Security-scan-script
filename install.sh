#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# install.sh - Linux 安全工具箱主控台 (v3.0 终极主控版)
# 特性：系统仪表盘 | 细化下载管理 | 界面美化 | 全能管家适配

set -u
export LC_ALL=C

# --- [手动修正位] 如果标题或状态依然显示方块乱码，请将 0 改为 1 ---
FORCE_TEXT_MODE=0

# --- 配置 ---
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main"
TAG_MARKER="<SEC_SCRIPT_MARKER_v2.3>" # 唯一特征识别码

# --- [核心] 智能环境检测与配色 ---
detect_env() {
    # 1. Emoji 检测
    if [ "$FORCE_TEXT_MODE" == "1" ]; then export USE_EMOJI="0"; else
        [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]] && export USE_EMOJI="1" || export USE_EMOJI="0"
        # 排除弱终端
        [[ "${TERM:-}" == "linux" ]] || [[ "${TERM:-}" == "vt100" ]] && export USE_EMOJI="0"
    fi

    # 2. 颜色定义
    RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
    PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); 
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
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }
ui_line()   { echo -e "${GREY}--------------------------------------------------------------------------------${RESET}"; }
ui_info()   { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()     { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn()   { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail()   { echo -e "${RED}${I_FAIL} $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 顶部仪表盘 (美化核心) ---
show_dashboard() {
    clear
    # 获取系统信息
    local os_info=""; [ -f /etc/os-release ] && os_info=$(grep "^PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"') || os_info=$(cat /etc/issue | head -n 1)
    local ip_addr=$(hostname -I 2>/dev/null | cut -d' ' -f1); [ -z "$ip_addr" ] && ip_addr="127.0.0.1"
    local time_now=$(date "+%Y-%m-%d %H:%M")
    local user_now=$(whoami)

    echo -e "${BLUE}################################################################################${RESET}"
    echo -e "${BOLD}${CYAN}           ${I_MAIN} Linux Security Toolbox v3.0 (终极主控台) ${RESET}"
    echo -e "${BLUE}################################################################################${RESET}"
    printf "${GREY}  ${I_SYS} 系统: ${WHITE}%-30s ${GREY} IP: ${WHITE}%-15s${RESET}\n" "${os_info:0:30}" "$ip_addr"
    printf "${GREY}  ⏰ 时间: ${WHITE}%-30s ${GREY} 用户: ${WHITE}%-15s${RESET}\n" "$time_now" "$user_now"
    ui_header
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
        echo -e "${RED}失败${RESET} (缺少 wget/curl)"
        return 1
    fi

    if [ -s "$name" ]; then
        sed -i 's/\r$//' "$name" 2>/dev/null
        chmod +x "$name"
        echo -e "${GREEN}成功${RESET}"
        return 0
    else
        echo -e "${RED}失败${RESET} (网络或源错误)"
        return 1
    fi
}

# --- 子菜单：下载中心 (细化下载需求) ---
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
        ui_header
        echo -ne "${CYAN}请输入下载选项: ${RESET}"
        read -r dl_choice
        
        case "$dl_choice" in
            0|1|2|3)
                download_script "v${dl_choice}.sh"
                read -n 1 -s -r -p "按任意键继续..."
                ;;
            a|A)
                for s in v0.sh v1.sh v2.sh v3.sh; do download_script "$s"; done
                ui_ok "所有脚本更新完毕。"
                read -n 1 -s -r -p "按任意键返回..."
                return
                ;;
            q|Q) return ;;
            *) ;;
        esac
    done
}

# --- 核心功能：清理脚本 ---
cleanup_scripts() {
    echo ""
    ui_warn "即将通过特征码扫描并清理本工具箱的所有子脚本..."
    local files=$(grep -l "$TAG_MARKER" *.sh 2>/dev/null | grep -v "$(basename "$0")")
    
    if [ -n "$files" ]; then
        echo -e "${WHITE}发现文件: ${YELLOW}$files${RESET}"
        read -p "确认清理？(yes/no): " c
        if [ "$c" == "yes" ]; then
            rm -f $files
            ui_ok "清理完成。"
        else
            ui_info "已取消。"
        fi
    else
        ui_info "未发现残留脚本。"
    fi
    sleep 1.5
}

# --- 主菜单循环 ---
main_menu() {
    while true; do
        show_dashboard
        
        # 动态状态检测函数
        st() { [ -x "$1" ] && echo "${GREEN}已就绪${RESET}" || echo "${GREY}未下载${RESET}"; }
        
        echo -e "${BOLD}工具列表${RESET}"
        ui_line
        # [修改点] v1 描述更新，匹配 v32.1 的全能身份
        printf " [0] %-30s [状态: %s]\n" "全维审计 (v0.sh)" "$(st v0.sh)"
        echo -e "     ${GREY}└─ 只查不改 / 硬件仪表盘 / 36项深度体检 / 评分报告${RESET}"
        
        printf " [1] %-30s [状态: %s]\n" "全能管家 (v1.sh)" "$(st v1.sh)"
        echo -e "     ${GREY}└─ ${YELLOW}BBR加速${GREY} / ${YELLOW}救砖换源${GREY} / 软件安装 / 36项加固 / 漏洞修复${RESET}"
        
        printf " [2] %-30s [状态: %s]\n" "密钥配置 (v2.sh)" "$(st v2.sh)"
        echo -e "     ${GREY}└─ 禁用密码登录 / 自动生成密钥对 / 权限修正${RESET}"
        
        printf " [3] %-30s [状态: %s]\n" "网络隐身 (v3.sh)" "$(st v3.sh)"
        echo -e "     ${GREY}└─ 开启或关闭禁 Ping / 隐藏服务器存活状态${RESET}"
        
        ui_line
        echo " [8] 智能清理 (删除上述脚本)"
        echo " [9] 下载中心 (单独/批量更新脚本)"
        echo " [q] 退出程序"
        ui_header
        
        echo -ne "${CYAN}请输入操作编号: ${RESET}"
        read -r CHOICE

        case "$CHOICE" in
            0|1|2|3)
                SCRIPT="v${CHOICE}.sh"
                if [ -x "$SCRIPT" ]; then 
                    ./"$SCRIPT"
                    # 子脚本内部有 read 暂停，这里不需要额外 sleep，直接刷新 dashboard
                else 
                    ui_fail "脚本 $SCRIPT 尚未下载！"
                    echo -e "请先输入 ${BOLD}9${RESET} 进入下载中心获取。"
                    read -n 1 -s -r -p "按任意键继续..."
                fi
                ;;
            8) cleanup_scripts ;;
            9) menu_download ;; # 进入二级菜单
            q|Q)
                ui_info "感谢使用，再见。"
                exit 0 
                ;;
            *) ;;
        esac
    done
}

# --- 运行前置检查 ---
[ "$(id -u)" -eq 0 ] || { echo -e "${RED}请使用 root 权限运行本工具。${RESET}"; exit 1; }

# 首次运行自检
if [ ! -x "v0.sh" ] && [ ! -x "v1.sh" ]; then
    clear
    ui_warn "初次见面，正在初始化下载核心组件..."
    download_script "v0.sh"
    download_script "v1.sh"
    sleep 1
fi

main_menu
