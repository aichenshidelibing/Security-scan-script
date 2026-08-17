#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v2.sh - SSH 密钥与登录策略中心 (v4.0 安全确认版)
# 特性：ED25519密钥 | SSH端口 | 密码登录 | Root登录策略 | 配置备份 | sshd校验 | 失败回滚

set -u
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$SCRIPT_DIR/lib/runtime.sh" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/lib/runtime.sh"
    sec_toolbox_acquire_lock "v2.sh" || exit 75
    trap 'sec_toolbox_release_lock' EXIT
else
    echo "[error] lib/runtime.sh is required; run install.sh to refresh the toolbox." >&2
    exit 1
fi

trap 'exit 0' INT

# ---------- 统一自适应 UI 区 ----------
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m')
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_DOWN="👇"; I_STOP="🛑"; I_KEY="🔐"; I_BACK="↩️ "
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_DOWN="[ v ]"; I_STOP="[ !!! ]"; I_KEY="[ KEY ]"; I_BACK="[BACK]"
fi

# --- 变量与路径 ---
KEY_DIR="/root"
KEY_PATH="${KEY_DIR}/id_ed25519"
AUTH_KEYS="/root/.ssh/authorized_keys"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_ROOT="/root/sec_toolbox_backup"
MANAGED_BEGIN="# BEGIN SEC_TOOLBOX_SSH_POLICY"
MANAGED_END="# END SEC_TOOLBOX_SSH_POLICY"

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() { [ "$(id -u)" -eq 0 ] || { ui_fail "请以 root 运行本脚本"; exit 1; }; }
need_sshd_config() {
    if [ ! -f "$SSHD_CONFIG" ]; then
        ui_fail "未找到 $SSHD_CONFIG，请先安装 openssh-server 后再运行。"
        exit 1
    fi
}

get_sshd_value() {
    local key="$1"
    awk -v k="$key" 'BEGIN{IGNORECASE=1} $1==k {v=$2} END{print v}' "$SSHD_CONFIG" 2>/dev/null
}

get_ssh_port() {
    local p
    p=$(get_sshd_value Port)
    echo "${p:-22}"
}

detect_ssh_service() {
    if cmd_exists systemctl; then
        if systemctl list-unit-files sshd.service >/dev/null 2>&1; then echo "sshd"; return; fi
        if systemctl list-unit-files ssh.service >/dev/null 2>&1; then echo "ssh"; return; fi
    fi
    echo "sshd"
}

sshd_bin() {
    if [ -x /usr/sbin/sshd ]; then echo "/usr/sbin/sshd"; return 0; fi
    command -v sshd 2>/dev/null && return 0
    return 1
}

sshd_test() {
    local bin err
    bin=$(sshd_bin) || { ui_fail "未找到 sshd 命令，无法校验配置。"; return 1; }
    err=$(mktemp /tmp/sec_toolbox_sshd.XXXXXX)
    if "$bin" -t -f "$SSHD_CONFIG" 2>"$err"; then
        rm -f "$err"
        return 0
    fi
    ui_fail "sshd 配置校验失败："
    sed 's/^/    /' "$err"
    rm -f "$err"
    return 1
}

create_ssh_backup() {
    local reason="${1:-manual}"
    local dir="${BACKUP_ROOT}/ssh_$(date +'%Y%m%d_%H%M%S')"
    mkdir -p "$dir"
    [ -f "$SSHD_CONFIG" ] && cp -a "$SSHD_CONFIG" "$dir/sshd_config"
    [ -f "$AUTH_KEYS" ] && cp -a "$AUTH_KEYS" "$dir/authorized_keys"
    [ -f "$KEY_PATH" ] && cp -a "$KEY_PATH" "$dir/id_ed25519"
    [ -f "${KEY_PATH}.pub" ] && cp -a "${KEY_PATH}.pub" "$dir/id_ed25519.pub"
    {
        echo "reason=$reason"
        echo "time=$(date +'%F %T')"
        echo "port=$(get_ssh_port)"
        echo "password_auth=$(get_sshd_value PasswordAuthentication)"
        echo "root_login=$(get_sshd_value PermitRootLogin)"
    } > "$dir/manifest.txt"
    echo "$dir"
}

restore_ssh_backup() {
    local dir="$1"
    [ -d "$dir" ] || { ui_fail "备份目录不存在: $dir"; return 1; }
    [ -f "$dir/sshd_config" ] && cp -a "$dir/sshd_config" "$SSHD_CONFIG"
    if [ -f "$dir/authorized_keys" ]; then
        mkdir -p /root/.ssh
        cp -a "$dir/authorized_keys" "$AUTH_KEYS"
    fi
    if sshd_test; then
        ui_ok "已恢复备份: $dir"
        return 0
    fi
    ui_fail "备份恢复后 sshd 仍校验失败，请手动检查: $dir"
    return 1
}

auto_rollback_on_failure() {
    local dir="$1"
    ui_warn "正在自动回滚 SSH 配置..."
    restore_ssh_backup "$dir"
}

reload_ssh_safe() {
    local service
    sshd_test || return 1
    service=$(detect_ssh_service)
    if cmd_exists systemctl; then
        if systemctl reload "$service" >/dev/null 2>&1; then
            ui_ok "SSH 服务已重载 ($service)。"
            return 0
        fi
        ui_warn "reload 失败，可选择 restart；restart 风险更高，可能断开当前连接。"
        echo -ne "${YELLOW}确认重启 SSH 服务？(输入 RESTART): ${RESET}"
        read -r c
        if [ "$c" = "RESTART" ]; then
            systemctl restart "$service" >/dev/null 2>&1 && { ui_ok "SSH 服务已重启。"; return 0; }
        fi
    fi
    ui_fail "SSH 服务未重载，请手动执行 systemctl reload ssh/sshd。"
    return 1
}

remove_managed_block() {
    sed -i "/^${MANAGED_BEGIN}$/,/^${MANAGED_END}$/d" "$SSHD_CONFIG"
}

append_managed_block() {
    local backup_dir="$1"
    shift
    remove_managed_block
    {
        echo ""
        echo "$MANAGED_BEGIN"
        for kv in "$@"; do echo "$kv"; done
        echo "$MANAGED_END"
    } >> "$SSHD_CONFIG"
    if ! sshd_test; then
        auto_rollback_on_failure "$backup_dir"
        return 1
    fi
    return 0
}

confirm_phrase() {
    local phrase="$1"
    local prompt="$2"
    echo -ne "${YELLOW}${prompt} 请输入 ${BOLD}${phrase}${RESET}${YELLOW}: ${RESET}"
    local input
    read -r input
    [ "$input" = "$phrase" ]
}

check_status() {
    PASS_VALUE=$(get_sshd_value PasswordAuthentication); PASS_VALUE=${PASS_VALUE:-default}
    PUB_VALUE=$(get_sshd_value PubkeyAuthentication); PUB_VALUE=${PUB_VALUE:-default}
    ROOT_VALUE=$(get_sshd_value PermitRootLogin); ROOT_VALUE=${ROOT_VALUE:-default}
    KBD_VALUE=$(get_sshd_value KbdInteractiveAuthentication); KBD_VALUE=${KBD_VALUE:-default}
    CHAL_VALUE=$(get_sshd_value ChallengeResponseAuthentication); CHAL_VALUE=${CHAL_VALUE:-default}
    PORT_VALUE=$(get_ssh_port)
    if [ -f "$KEY_PATH" ]; then KEY_STATUS="${YELLOW}已存在私钥${RESET}"; else KEY_STATUS="${GREY}无${RESET}"; fi
    if [ -s "$AUTH_KEYS" ]; then AUTH_STATUS="${GREEN}存在${RESET}"; else AUTH_STATUS="${YELLOW}无或为空${RESET}"; fi
}

show_status() {
    check_status
    ui_header
    echo -e "${BOLD} ${I_KEY} SSH 登录策略状态${RESET}"
    ui_header
    printf "  ├─ SSH端口: ${WHITE}%s${RESET}\n" "$PORT_VALUE"
    printf "  ├─ 密码登录 PasswordAuthentication: ${WHITE}%s${RESET}\n" "$PASS_VALUE"
    printf "  ├─ 键盘交互 KbdInteractiveAuthentication: ${WHITE}%s${RESET}\n" "$KBD_VALUE"
    printf "  ├─ ChallengeResponseAuthentication: ${WHITE}%s${RESET}\n" "$CHAL_VALUE"
    printf "  ├─ Root登录 PermitRootLogin: ${WHITE}%s${RESET}\n" "$ROOT_VALUE"
    printf "  ├─ 公钥认证 PubkeyAuthentication: ${WHITE}%s${RESET}\n" "$PUB_VALUE"
    printf "  ├─ authorized_keys: %b\n" "$AUTH_STATUS"
    printf "  └─ 本地私钥: %b\n" "$KEY_STATUS"
    ui_header
}

generate_key() {
    echo ""
    ui_info "生成高强度 ED25519 密钥..."
    local backup_dir
    backup_dir=$(create_ssh_backup "generate-key")
    if [ -f "$KEY_PATH" ]; then
        mv "$KEY_PATH" "$backup_dir/old_id_ed25519" 2>/dev/null
        mv "${KEY_PATH}.pub" "$backup_dir/old_id_ed25519.pub" 2>/dev/null
        ui_warn "检测到旧密钥，已备份至: $backup_dir"
    fi
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q >/dev/null 2>&1
    chmod 600 "$KEY_PATH"
    [ -f "${KEY_PATH}.pub" ] || { ui_fail "密钥生成失败"; return 1; }
    ui_ok "密钥生成成功"
}

install_pubkey() {
    echo ""
    ui_info "部署公钥到 authorized_keys..."
    local backup_dir pub
    backup_dir=$(create_ssh_backup "install-pubkey")
    [ -f "${KEY_PATH}.pub" ] || { ui_fail "未找到 ${KEY_PATH}.pub，请先生成密钥。"; return 1; }
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    pub=$(cat "${KEY_PATH}.pub")
    touch "$AUTH_KEYS"
    if ! grep -qxF "$pub" "$AUTH_KEYS"; then
        echo "$pub" >> "$AUTH_KEYS"
    fi
    chmod 600 "$AUTH_KEYS"
    append_managed_block "$backup_dir" \
        "PubkeyAuthentication yes" \
        "PermitEmptyPasswords no" \
        "PermitUserEnvironment no" || return 1
    ui_ok "公钥部署完成，SSH 低风险策略已写入托管块。"
}

show_private_key() {
    [ -f "$KEY_PATH" ] || { ui_warn "未找到私钥 $KEY_PATH"; return 1; }
    echo ""
    ui_info "请立即复制下方【绿字内容】保存为文件 (如 key.pem)"
    ui_header
    echo "${GREEN}"
    cat "$KEY_PATH"
    echo "${RESET}"
    ui_header
}

configure_ssh_port() {
    show_status
    echo -e "${RED}${BOLD}${I_STOP} 修改 SSH 端口可能导致无法连接，请先放行云安全组和防火墙。${RESET}"
    echo -ne "${YELLOW}请输入新的 SSH 端口 (1-65535，留空取消): ${RESET}"
    local port backup_dir
    read -r port
    [ -z "$port" ] && { ui_warn "已取消。"; return 0; }
    [[ "$port" =~ ^[0-9]+$ ]] || { ui_fail "端口必须是数字。"; return 1; }
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { ui_fail "端口范围必须是 1-65535。"; return 1; }
    if cmd_exists ss && ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
        ui_fail "端口 $port 已被占用。"
        return 1
    fi
    confirm_phrase "CHANGE PORT" "我已确认新端口已在云安全组/防火墙放行，继续修改？" || { ui_warn "已取消。"; return 1; }
    backup_dir=$(create_ssh_backup "change-port")
    append_managed_block "$backup_dir" \
        "Port $port" \
        "PubkeyAuthentication yes" \
        "PermitEmptyPasswords no" \
        "PermitUserEnvironment no" || return 1
    ui_ok "SSH 端口已写入为 $port。请 reload 后新开窗口测试。"
    reload_ssh_safe
}

configure_password_login() {
    show_status
    echo -e "${RED}${BOLD}${I_STOP} 禁用密码登录前，必须确认密钥登录已经在新窗口测试成功。${RESET}"
    echo "1. 禁用密码登录 [推荐但高风险]"
    echo "2. 启用密码登录"
    echo "0. 取消"
    echo -ne "${YELLOW}请选择: ${RESET}"
    local choice backup_dir
    read -r choice
    case "$choice" in
        1)
            [ -s "$AUTH_KEYS" ] || { ui_fail "authorized_keys 为空，禁止关闭密码登录。"; return 1; }
            confirm_phrase "I TESTED SSH LOGIN" "我已新开 SSH 窗口并确认密钥登录成功，继续？" || { ui_warn "已取消。"; return 1; }
            backup_dir=$(create_ssh_backup "disable-password-login")
            append_managed_block "$backup_dir" \
                "PubkeyAuthentication yes" \
                "PasswordAuthentication no" \
                "KbdInteractiveAuthentication no" \
                "ChallengeResponseAuthentication no" \
                "PermitEmptyPasswords no" || return 1
            ui_ok "密码登录已禁用。"
            reload_ssh_safe
            ;;
        2)
            backup_dir=$(create_ssh_backup "enable-password-login")
            append_managed_block "$backup_dir" "PasswordAuthentication yes" || return 1
            ui_ok "密码登录已显式开启。"
            reload_ssh_safe
            ;;
        *) ui_warn "已取消。" ;;
    esac
}

configure_root_login() {
    show_status
    echo -e "${RED}${BOLD}${I_STOP} Root 登录策略错误会导致无法登录。${RESET}"
    echo "1. prohibit-password：禁止 root 密码登录，允许 root 密钥登录 [推荐]"
    echo "2. no：完全禁止 root 登录 [高风险]"
    echo "3. yes：允许 root 登录"
    echo "0. 取消"
    echo -ne "${YELLOW}请选择: ${RESET}"
    local choice value backup_dir
    read -r choice
    case "$choice" in
        1) value="prohibit-password"; confirm_phrase "LIMIT ROOT" "确认限制 root 仅允许密钥登录？" || return 1 ;;
        2) value="no"; confirm_phrase "DISABLE ROOT" "我已确认存在可 sudo 的非 root 用户并已测试登录，继续？" || return 1 ;;
        3) value="yes"; confirm_phrase "ALLOW ROOT" "确认允许 root 登录？" || return 1 ;;
        *) ui_warn "已取消。"; return 0 ;;
    esac
    backup_dir=$(create_ssh_backup "root-login-policy")
    append_managed_block "$backup_dir" "PermitRootLogin $value" || return 1
    ui_ok "Root 登录策略已设置为: $value"
    reload_ssh_safe
}

apply_recommended_policy() {
    show_status
    echo -e "${YELLOW}推荐策略将设置：公钥认证、禁止空密码、禁止用户环境变量、10分钟空闲检测。${RESET}"
    echo "不会自动改端口，不会自动禁止密码登录，不会完全禁止 root 登录。"
    confirm_phrase "APPLY POLICY" "确认应用推荐 SSH 基础策略？" || { ui_warn "已取消。"; return 1; }
    local backup_dir
    backup_dir=$(create_ssh_backup "recommended-policy")
    append_managed_block "$backup_dir" \
        "PubkeyAuthentication yes" \
        "PermitEmptyPasswords no" \
        "PermitUserEnvironment no" \
        "ClientAliveInterval 600" \
        "ClientAliveCountMax 2" || return 1
    ui_ok "推荐 SSH 基础策略已应用。"
    reload_ssh_safe
}

rollback_latest_backup() {
    local latest
    latest=$(find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'ssh_*' 2>/dev/null | sort | tail -n 1)
    [ -n "$latest" ] || { ui_warn "未找到 SSH 备份。"; return 0; }
    echo -e "${YELLOW}${I_BACK} 最近备份: $latest${RESET}"
    confirm_phrase "ROLLBACK SSH" "确认恢复最近一次 SSH 配置备份？" || { ui_warn "已取消。"; return 1; }
    restore_ssh_backup "$latest" && reload_ssh_safe
}

key_setup_flow() {
    echo -ne "${GREEN}按回车键开始生成/部署密钥 (Ctrl+C 退出)...${RESET}"
    read -r
    generate_key || return 1
    install_pubkey || return 1
    show_private_key
    ui_warn "私钥当前保留在 $KEY_PATH。确认可登录后可自行删除服务端私钥副本。"
}

main_menu() {
    while true; do
        clear
        show_status
        echo -e "${BOLD}SSH 登录策略中心${RESET}"
        echo " [1] 生成/部署 ED25519 密钥"
        echo " [2] 修改 SSH 端口"
        echo " [3] 密码登录策略"
        echo " [4] Root 登录策略"
        echo " [5] 应用推荐 SSH 基础策略"
        echo " [6] 回滚最近一次 SSH 配置备份"
        echo " [r] 重载 SSH 服务"
        echo " [q] 返回主控台"
        ui_header
        echo -ne "${CYAN}请选择操作: ${RESET}"
        local choice
        read -r choice
        case "$choice" in
            1) key_setup_flow ;;
            2) configure_ssh_port ;;
            3) configure_password_login ;;
            4) configure_root_login ;;
            5) apply_recommended_policy ;;
            6) rollback_latest_backup ;;
            r|R) reload_ssh_safe ;;
            q|Q) clear; exit 0 ;;
            *) ui_warn "无效选择。" ;;
        esac
        echo -ne "\n${YELLOW}${I_INFO} 按任意键继续...${RESET}"
        read -n 1 -s -r
    done
}

clear
need_root
need_sshd_config
sshd_test || ui_warn "当前 sshd_config 校验失败，请先修复配置或使用备份回滚。"
main_menu
