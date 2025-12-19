#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v2.sh - SSH 密钥配置与登录加固 (v3.2 智慧感知版)
# 特性：ED25519生成 | 自动备份 | 防锁死强制确认 | 环境自适应UI

set -u
export LC_ALL=C

# ---------- 统一自适应 UI 区 ----------
# 优先读取主控台变量，读不到则本地检测
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

# 颜色定义
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

# 根据环境定义图标
if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_DOWN="👇"; I_STOP="🛑"; I_KEY="🔐"
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_DOWN="[ v ]"; I_STOP="[ !!! ]"; I_KEY="[ KEY ]"
fi
# ------------------------------------

# --- 变量与路径 ---
KEY_DIR="/root"
KEY_PATH="${KEY_DIR}/id_ed25519"
AUTH_KEYS="/root/.ssh/authorized_keys"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/root/ssh_key_backup_$(date +'%Y%m%d_%H%M%S')"

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }

need_root() { [ "$(id -u)" -eq 0 ] || { ui_fail "请以 root 运行本脚本"; exit 1; }; }

# --- 1. 环境检测 ---
check_status() {
    # 检测密码登录状态
    if grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+yes" "$SSHD_CONFIG"; then
        PASS_STATUS="${RED}开启 (不安全)${RESET}"
    elif grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" "$SSHD_CONFIG"; then
        PASS_STATUS="${GREEN}已关闭 (安全)${RESET}"
    else
        PASS_STATUS="${YELLOW}默认 (通常开启)${RESET}"
    fi

    # 检测公钥登录状态
    if grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" "$SSHD_CONFIG"; then
        PUB_STATUS="${GREEN}已开启${RESET}"
    else
        PUB_STATUS="${RED}未显式开启${RESET}"
    fi
    
    # 检测是否存在旧密钥
    if [ -f "$KEY_PATH" ]; then
        KEY_STATUS="${YELLOW}已存在旧文件${RESET}"
    else
        KEY_STATUS="${GREY}无${RESET}"
    fi
}

# --- 2. 核心逻辑 ---
generate_key() {
    echo ""
    ui_info "步骤 1/4: 生成高强度 ED25519 密钥..."
    
    # 智能备份逻辑
    if [ -f "$KEY_PATH" ]; then
        mkdir -p "$BACKUP_DIR"
        mv "$KEY_PATH" "$BACKUP_DIR/"
        mv "${KEY_PATH}.pub" "$BACKUP_DIR/" 2>/dev/null
        ui_warn "检测到旧密钥，已自动备份至: $BACKUP_DIR"
    fi

    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q >/dev/null 2>&1
    chmod 600 "$KEY_PATH"
    
    if [ -f "$KEY_PATH" ]; then
        ui_ok "密钥生成成功"
    else
        ui_fail "密钥生成失败"
        exit 1
    fi
}

install_pubkey() {
    echo ""
    ui_info "步骤 2/4: 部署公钥到系统..."
    mkdir -p "/root/.ssh"
    chmod 700 "/root/.ssh"
    
    # 追加模式，不覆盖可能存在的其他密钥
    cat "${KEY_PATH}.pub" >> "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"
    
    # 确保 sshd_config 开启了公钥验证
    if ! grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" "$SSHD_CONFIG"; then
        sed -i '/^PubkeyAuthentication/d' "$SSHD_CONFIG"
        echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
        ui_ok "已强制开启 PubkeyAuthentication"
    fi
    
    ui_ok "公钥部署完成"
}

show_private_key() {
    echo ""
    ui_info "步骤 3/4: 获取私钥 (关键)"
    ui_header
    echo -e "${RED}${BOLD}${I_DOWN} 请立即复制下方【绿字内容】保存为文件 (如 key.pem) ${I_DOWN}${RESET}"
    ui_header
    echo "${GREEN}"
    cat "$KEY_PATH"
    echo "${RESET}"
    ui_header
    echo ""
}

confirm_and_lock() {
    echo ""
    echo -e "${RED}${BOLD}${I_STOP} 防锁死安全拦截 ${I_STOP}${RESET}"
    echo "1. 不要关闭当前窗口！"
    echo "2. 新开一个 SSH 窗口，使用刚才保存的私钥尝试登录。"
    echo "3. 只有登录成功，才输入 yes 禁用密码登录。"
    echo ""
    echo -ne "${YELLOW}我已测试私钥登录成功，确认关闭密码登录？(输入 yes): ${RESET}"
    read -r CONFIRM

    if [ "$CONFIRM" == "yes" ]; then
        ui_info "步骤 4/4: 正在关闭密码登录..."
        
        # 修改配置
        sed -i '/^PasswordAuthentication/d' "$SSHD_CONFIG"
        echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
        
        sed -i '/^PermitRootLogin/d' "$SSHD_CONFIG"
        echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
        
        # 删除服务端私钥副本（安全起见）
        rm -f "$KEY_PATH"
        
        ui_ok "密码登录已关闭！服务器端私钥副本已销毁。"
        return 0
    else
        echo ""
        ui_warn "操作已中止！"
        ui_info "当前状态：公钥已添加，但密码登录【仍保留】。"
        ui_info "私钥文件保留在: $KEY_PATH (请自行下载或删除)"
        return 1
    fi
}

# --- 3. 主界面 ---
clear
need_root
check_status

ui_header
echo -e "${BOLD} ${I_KEY} SSH 密钥配置与加固工具 (v3.2)${RESET}"
ui_header

# 卡片式状态展示
printf "${GREY}当前配置状态：${RESET}\n"
printf "  ├─ 密码登录: %b\n" "$PASS_STATUS"
printf "  ├─ 公钥验证: %b\n" "$PUB_STATUS"
printf "  └─ 本地密钥: %b\n" "$KEY_STATUS"
echo ""
echo "${YELLOW}本脚本将执行：${RESET}"
echo "  1. 生成全新的 ED25519 密钥对"
echo "  2. 将公钥自动写入 authorized_keys"
echo "  3. 显示私钥供您下载保存"
echo "  4. (确认后) 关闭密码登录，仅允许密钥登录"
ui_header

echo -ne "${GREEN}按回车键开始配置 (Ctrl+C 退出)...${RESET}"
read -r

# 执行流程
generate_key
install_pubkey
show_private_key

# 确认锁定
if confirm_and_lock; then
    # 重启服务逻辑
    echo ""
    ui_info "最后一步：重启服务生效"
    echo "1. 重载 SSH (Reload) [推荐]"
    echo "2. 重启 SSH (Restart)"
    echo "0. 暂不重启"
    echo -ne "${YELLOW}请选择 (默认1): ${RESET}"; read -r FINAL
    
    case "${FINAL:-1}" in
        1) systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 服务已重载" ;;
        2) systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; ui_ok "SSH 服务已重启" ;;
        *) ui_warn "已跳过重启 (配置未生效)" ;;
    esac
    
    echo ""
    ui_ok "v2.sh 执行完毕。"
else
    echo ""
    ui_warn "脚本已退出，未执行重启，密码登录未关闭。"
fi

# === 关键：平滑返回主控台 ===
echo -ne "\n${YELLOW}${I_INFO} 按任意键返回主控台菜单...${RESET}"
read -n 1 -s -r
