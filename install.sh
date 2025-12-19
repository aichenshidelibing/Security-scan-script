#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# install.sh - 统一安全工具启动主控台 (v2.4 终极完整版)

set -u
export LC_ALL=C

# --- [手动修正位] 如果标题或状态依然显示方块乱码，请将 0 改为 1 ---
FORCE_TEXT_MODE=0

# --- 配置 ---
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main"
TAG_MARKER="<SEC_SCRIPT_MARKER_v2.3>" # 唯一特征识别码

# --- [核心] 智能环境检测重构 ---
detect_emoji() {
    # 如果用户手动开启了强制文本模式
    if [ "$FORCE_TEXT_MODE" == "1" ]; then
        export USE_EMOJI="0"
        return
    fi
    
    # 1. 检查环境变量中是否包含 UTF-8
    local supports_utf8=0
    [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]] && supports_utf8=1
    
    # 2. 排除渲染能力极差的终端类型 (如 putty 默认的 linux/vt100)
    local is_weak_term=0
    [[ "${TERM:-}" == "linux" ]] || [[ "${TERM:-}" == "vt100" ]] && is_weak_term=1

    if [ "$supports_utf8" == "1" ] && [ "$is_weak_term" == "0" ]; then
        export USE_EMOJI="1"
    else
        export USE_EMOJI="0"
    fi
}
detect_emoji

# --- 颜色与图标自适应定义 ---
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_MAIN="🛡️ "
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_MAIN="[*]"
fi

# --- 辅助工具 ---
ui_header() { echo -e "\n${BLUE}=====================================================${RESET}"; }
ui_info()   { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()     { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn()   { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail()   { echo -e "${RED}${I_FAIL} $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 核心函数：下载与权限检查 ---
download_script() {
    local name="$1"
    local url="${GITHUB_BASE}/${name}"
    
    ui_info "正在从 GitHub 获取 ${name}..."
    if cmd_exists wget; then
        wget -q -O "$name" "$url"
    elif cmd_exists curl; then
        curl -s -o "$name" "$url"
    else
        ui_fail "未找到 wget 或 curl，无法下载！"
        return 1
    fi

    if [ -f "$name" ]; then
        # 强制修复格式问题并赋予权限
        sed -i 's/\r$//' "$name" 2>/dev/null
        chmod +x "$name"
        ui_ok "${name} 下载成功并已就绪。"
        return 0
    else
        ui_fail "${name} 下载失败。"
        return 1
    fi
}

# --- 脚本清理函数 (基于特征码识别) ---
cleanup_scripts() {
    echo ""
    ui_warn "注意：此操作将通过特征码搜索并删除所有 v0-v3 工具脚本。"
    # 查找包含特征码的所有脚本，排除本主控台自身
    local files_to_del=$(grep -l "$TAG_MARKER" *.sh 2>/dev/null | grep -v "$(basename "$0")")
    
    if [ -n "$files_to_del" ]; then
        echo -e "${WHITE}发现待清理脚本: ${YELLOW}$files_to_del${RESET}"
        read -p "确认全部删除？(输入 yes 确认): " CONFIRM
        if [ "$CONFIRM" == "yes" ]; then
            rm -f $files_to_del
            ui_ok "所有工具脚本已清理完毕。"
        else
            ui_info "操作已取消。"
        fi
    else
        ui_info "未发现带有特征码的脚本，无需清理。"
    fi
    sleep 2
}

# --- 菜单主循环 ---
main_menu() {
    while true; do
        clear
        ui_header
        echo "${BOLD}${CYAN}      ${I_MAIN} Linux 安全工具箱 2.4 - 主控台      ${RESET}"
        ui_header
        echo "${BOLD}当前本地脚本状态：${RESET}"
        
        status_label() { [ -x "$1" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}缺失${RESET}"; }
        
        # 补全功能描述
        echo " [0] 安全体检 (v0.sh): 全面审计，只查不改。 [状态: $(status_label v0.sh)]"
        echo " [1] 基础加固 (v1.sh): 修复SSH、端口、权限。 [状态: $(status_label v1.sh)]"
        echo " [2] 密钥配置 (v2.sh): 禁用密码，生成密钥。 [状态: $(status_label v2.sh)]"
        echo " [3] 网络隐身 (v3.sh): 开启或关闭禁 Ping。  [状态: $(status_label v3.sh)]"
        echo ""
        echo " [8] 智能清理工具脚本 (特征码识别)"
        echo " [9] 重新下载/更新所有脚本"
        echo " [q] 退出主控台"
        ui_header
        
        echo -ne "${CYAN}请选择操作编号: ${RESET}"
        read -r CHOICE

        case "$CHOICE" in
            0|1|2|3)
                local SCRIPT="v${CHOICE}.sh"
                if [ -x "$SCRIPT" ]; then 
                    ui_info "正在启动 $SCRIPT... (运行结束后请按任意键返回)"
                    sleep 1
                    ./"$SCRIPT" # 启动子脚本
                    # 依靠子脚本末尾的 read 暂停，结束后自动刷新菜单
                else 
                    ui_fail "$SCRIPT 不存在，请先选 9 下载。"
                    sleep 2
                fi
                ;;
            8)
                cleanup_scripts
                ;;
            9) 
                ui_info "开始批量同步下载流程..."
                for s in v0.sh v1.sh v2.sh v3.sh; do
                    download_script "$s"
                done
                ui_ok "下载更新流程结束。"
                sleep 2
                ;;
            q|Q)
                ui_info "感谢使用，再见。"; exit 0 ;;
            *)
                ui_warn "无效选择 '$CHOICE'，请重新输入。"
                sleep 1.5
                ;;
        esac
    done
}

# --- 运行前置检查 ---
[ "$(id -u)" -eq 0 ] || { ui_fail "本工具需要 root 权限运行。"; exit 1; }

# 首次运行自动下载检测
if [ ! -x "v0.sh" ] || [ ! -x "v1.sh" ]; then
    ui_warn "检测到核心脚本缺失，正在进行初始化下载..."
    for s in v0.sh v1.sh v2.sh v3.sh; do download_script "$s"; done
    sleep 2
fi

main_menu
