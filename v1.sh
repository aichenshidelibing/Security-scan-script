#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v17.4 智慧交互终极版)
# 特性：26项全量加固 | 智能安装检测(跳过已安装) | 旋转进度条 | 错误回显 | 优雅返回

set -u
export LC_ALL=C

# ---------- [信号捕获] 确保 Ctrl+C 能正常返回菜单 ----------
trap 'exit 0' INT

# ---------- 统一自适应 UI 区 ----------
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_FIX="🔧"; I_WAIT="⏳"
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_FIX="[ FIX ]"; I_WAIT="[工作]"
fi

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

# 旋转进度条函数
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# 智能安装：检测 -> 进度显示 -> 错误捕获
smart_install() {
    local pkg=$1
    # 检测是否已安装 (支持 binary 检测和 /usr/sbin 路径检测)
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ] || [ -f "/etc/init.d/$pkg" ]; then
        return 0
    fi

    ui_info "正在安装必要组件: $pkg ..."
    local err_log="/tmp/${pkg}_install_err.log"
    
    if command -v apt-get >/dev/null; then
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    else
        ui_fail "未找到受支持的包管理器 (apt/dnf)"
        return 1
    fi
    
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        ui_fail "$pkg 安装失败！报错信息如下："
        cat "$err_log"; rm -f "$err_log"
        return 1
    fi
    rm -f "$err_log"
    return 0
}

# --- 审计数据初始化 (26项全量) ---
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CURRENT_SSH_PORT=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
TARGET_SSH_PORT="$CURRENT_SSH_PORT"

add_item() {
    COUNT=$((COUNT+1)); TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

init_audit() {
    # SSH 基础 (1-4)
    add_item "强制 SSH 协议 V2" "修复古老漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止空密码登录" "防止无密登录" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口 (当前:$CURRENT_SSH_PORT)" "避开全网扫描" "需记新端口" "[ \"$CURRENT_SSH_PORT\" != \"22\" ]" "TRUE"

    # SSH 进阶 (5-8)
    add_item "禁用交互式认证" "防密码爆破尝试" "影响部分特殊工具" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防遗忘会话劫持" "自动断开不活跃连接" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "法律警告合规" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止利用Shell环境绕过安全限制" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"

    # 账户加固 (9-11)
    add_item "强制 10 位混合密码" "极大增加爆破难度" "改密需数字+大小写" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防止账号被盗后频繁改密" "7天内禁连续改密" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "终端离开安全" "闲置自动退出登录" "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # 文件权限 (12-15)
    add_item "修正 /etc/passwd" "设为安全 644" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "设为最高安全 600" "防止被低权限用户读取哈希" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "设为 600" "保护配置文件不被读取" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "设为 600" "符合SSH安全规范" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"

    # 清理与限制 (16-19)
    add_item "锁定异常 UID=0" "清理潜在后门账户" "可能影响自建管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "提高提权门槛" "影响自动化脚本" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "防止利用已知指令漏洞提权" "禁用ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel 组" "禁止普通用户随意切换Root" "需手动加组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"

    # 内核防御 (20-22)
    add_item "网络内核防欺骗" "防止ICMP重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御大规模洪水攻击" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵协议层潜在漏洞" "可能影响罕见应用" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"

    # 服务审计 (23-26)
    add_item "时间同步(Chrony)" "确保审计日志时间准确" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防止系统盘被日志撑爆" "减少历史日志存储" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null" "FALSE"
    add_item "Fail2ban 最佳防护" "自动封禁暴力破解 IP" "输错5次封禁1h" "command -v fail2ban-server >/dev/null && [ -f /etc/fail2ban/jail.local ]" "FALSE"
    add_item "每日系统自动更新" "自动修补系统级漏洞" "可能会产生版本微变" "command -v unattended-upgrades >/dev/null || [ -f /etc/apt/apt.conf.d/20auto-upgrades ]" "FALSE"
}

# --- 执行修复逻辑 ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        *"修改 SSH 默认端口"*)
            read -p "   请输入新端口 (20000-60000): " input_port; TARGET_SSH_PORT=${input_port:-$(shuf -i 20000-60000 -n 1)}
            echo "Port $TARGET_SSH_PORT" >> /etc/ssh/sshd_config; command -v ufw >/dev/null && ufw allow $TARGET_SSH_PORT/tcp >/dev/null ;;
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Restricted Access." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        "强制 10 位混合密码") smart_install "libpam-pwquality" && [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root ;;
        "Shell 自动注销(10m)") echo "export TMOUT=600" >> /etc/profile; echo "readonly TMOUT" >> /etc/profile ;;
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} ;;
        "移除 Sudo 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount 2>/dev/null ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危不常用协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        "时间同步(Chrony)") smart_install "chrony" && systemctl enable --now chronyd >/dev/null 2>&1 ;;
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
        "Fail2ban 最佳防护") smart_install "fail2ban" && { cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
EOF
            systemctl enable --now fail2ban >/dev/null 2>&1; } ;;
        "每日系统自动更新") smart_install "unattended-upgrades" ;;
    esac
}

# --- 交互界面 ---
init_audit
while true; do
    clear; echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID  |  修复开关   |  检测结果   |  名称${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    for ((i=1; i<=COUNT; i++)); do
        S_TXT=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK} 通过${RESET}" || echo -e "${RED}${I_FAIL} 未通过${RESET}" )
        SEL_ICON=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON  ]${RESET}" || echo -e "${GREY}[ OFF ]${RESET}" )
        printf "${GREY}%2d.${RESET}  %b  %b  %-30s\n" "$i" "$SEL_ICON" "$S_TXT" "${TITLES[$i]}"
    done
    
    echo "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -e "指令: ${YELLOW}a${RESET}=全选 | ${RED}r${RESET}=执行加固 | ${CYAN}q${RESET}=返回主菜单"
    echo -ne "请输入编号翻转状态或指令: "
    read -r RawInput; input=$(echo "$RawInput" | tr ',' ' ' | xargs)
    case "$input" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已全部勾选" ;;
        r|R) echo ""; ui_info "正在为您完成全量加固，请稍候..."; for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done; ui_ok "全部加固流程已结束。"; sleep 2; exit 0 ;;
        *) for num in $input; do [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ] && { [ "${SELECTED[$num]}" == "TRUE" ] && SELECTED[$num]="FALSE" || SELECTED[$num]="TRUE"; }; done ;;
    esac
done
