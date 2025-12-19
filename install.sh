#!/usr/bin/env bash
# install.sh - 统一安全工具启动主控台 (v2.3 智慧感知版)
# 特性：环境自适应UI + 特征码识别清理 + 逻辑闭环交互

set -u
export LC_ALL=C

# --- 配置 ---
GITHUB_BASE="https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main"
TAG_MARKER="<SEC_SCRIPT_MARKER_v2.3>" # 唯一特征识别码

# --- [核心] 环境检测：是否支持 Emoji ---
detect_emoji() {
    # 检查环境变量中是否包含 UTF-8，判断终端渲染能力
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        export USE_EMOJI="1"
        return 0
    else
        export USE_EMOJI="0"
        return 1
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
        ui_fail "未找到 wget/curl，请先安装下载工具。"
        return 1
    fi

    if [ -f "$name" ]; then
        # 强制转换格式 (CRLF to LF) 并赋予权限
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
    ui_warn "正在通过特征码搜索并清理脚本文件..."
    # 查找包含特征码的所有 .sh 文件，并排除本主控台脚本自身
    local files_to_del=$(grep -l "$TAG_MARKER" *.sh 2>/dev/null | grep -v "$(basename "$0")")
    
    if [ -n "$files_to_del" ]; then
        echo -e "${WHITE}发现待清理脚本: ${YELLOW}$files_to_del${RESET}"
        read -p "确认全部删除？(输入 yes 确认): " CONFIRM
        if [ "$confirm" == "yes" ] || [ "$CONFIRM" == "yes" ]; then
            rm -f $files_to_del
            ui_ok "清理完成。"
        else
            ui_info "操作已取消。"
        fi
    else
        ui_info "未发现带有特征码的工具脚本。"
    fi
    sleep 2
}

# --- 菜单函数 ---
main_menu() {
    while true; do
        clear
        ui_header
        echo "${BOLD}${CYAN}      ${I_MAIN} Linux 安全工具箱 2.3 - 主控台      ${RESET}"
        ui_header
        echo "${BOLD}当前本地脚本状态：${RESET}"
        
        status_label() { [ -x "$1" ] && echo "${GREEN}就绪${RESET}" || echo "${RED}缺失${RESET}"; }
        
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
                    ui_info "启动 $SCRIPT... (运行结束后请按任意键返回主控台)"
                    sleep 1
                    ./"$SCRIPT" # 启动子脚本
                    # 此处依靠子脚本末尾的 read 暂停，结束后自动刷新菜单
                else 
                    ui_fail "$SCRIPT 缺失，请先选 9 下载。"
                    sleep 2
                fi ;;
            8) cleanup_scripts ;;
            9) 
                ui_info "开始同步下载流程..."
                for s in v0.sh v1.sh v2.sh v3.sh; do download_script "$s"; done
                ui_ok "下载流程结束。" && sleep 2 ;;
            q|Q)
                ui_info "感谢使用，再见。"; exit 0 ;;
            *)
                ui_warn "无效输入 '$CHOICE'，请重新选择。"
                sleep 1.5 ;;
        esac
    done
}

# --- 运行检查 ---
[ "$(id -u)" -eq 0 ] || { ui_fail "请以 root 权限运行本脚本。"; exit 1; }

# 首次运行自动检测
if [ ! -x "v0.sh" ] || [ ! -x "v1.sh" ]; then
    ui_warn "初次使用：正在获取核心脚本..."
    for s in v0.sh v1.sh v2.sh v3.sh; do download_script "$s"; done
    sleep 2
fi

main_menu
