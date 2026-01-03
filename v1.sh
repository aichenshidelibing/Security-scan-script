#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v22.2 工业级终极版)
# 特性：27项全量 | 智能锁管理 | 磁盘/SSH语法预检 | 端口防撞 | 进度条 | 防闪退

set -u
export LC_ALL=C

# --- [信号捕获] 确保 Ctrl+C 优雅返回主菜单 ---
trap 'echo -e "\n${YELLOW}操作取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

# --- [UI 自适应] ---
if [ "${USE_EMOJI:-}" == "" ]; then
    [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]] && USE_EMOJI="1" || USE_EMOJI="0"
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_FAIL="❌"; I_INFO="ℹ️ "; I_FIX="🔧"; I_WAIT="⏳"; I_LIST="📝"
else
    I_OK="[ OK ]"; I_FAIL="[FAIL]"; I_INFO="[INFO]"; I_FIX="[FIX]"; I_WAIT="[WAIT]"; I_LIST="[LIST]"
fi

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

show_spinner() {
    local pid=$1; local delay=0.1; local spinstr='|/-\'
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}; printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}; sleep $delay; printf "\b\b\b\b\b\b"
    done; printf "    \b\b\b\b"
}

# 磁盘空间预检 (防止磁盘塞满导致系统卡死)
check_space() { 
    local free_kb=$(df / | awk 'NR==2 {print $4}')
    if [ "$free_kb" -lt 204800 ]; then ui_fail "磁盘空间不足 200MB，停止。"; return 1; fi
    return 0
}

# 智能锁管理 (解决死等不合理问题)
handle_lock() {
    local lock="/var/lib/dpkg/lock-frontend"
    [ ! -f "$lock" ] || ! fuser "$lock" >/dev/null 2>&1 && return 0
    ui_warn "检测到 APT 锁。尝试排队等待 5 秒..."
    local count=0; while fuser "$lock" >/dev/null 2>&1 && [ $count -lt 5 ]; do sleep 1; count=$((count+1)); done
    if fuser "$lock" >/dev/null 2>&1; then
        local pid=$(fuser "$lock" 2>/dev/null | awk '{print $NF}')
        echo -e "${YELLOW}锁仍未释放。请选择: [1] 继续等 [2] 跳过项 [3] 强制解锁(PID:$pid)${RESET}"
        read -p "选择: " c
        if [ "$c" == "3" ]; then [ -z "$pid" ] || kill -9 "$pid"; rm -f "$lock"; return 0; fi
        [ "$c" == "1" ] && handle_lock || return 1
    fi; return 0
}

smart_install() {
    local pkg=$1; [ -x "/usr/bin/$pkg" ] || [ -x "/usr/sbin/$pkg" ] || command -v "$pkg" >/dev/null && return 0
    check_space || return 1; handle_lock || return 1
    ui_info "正在安装必要组件: $pkg ..."
    local err_log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then 
        export DEBIAN_FRONTEND=noninteractive; apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    else return 1; fi
    show_spinner $!; wait $!
    [ $? -ne 0 ] && { ui_fail "$pkg 安装失败。日志:"; [ -f "$err_log" ] && cat "$err_log"; rm -f "$err_log"; return 1; }
    rm -f "$err_log"; return 0
}

# --- 数据定义 (27项全量) ---
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}
TARGET_P="$CUR_P"

add_item() {
    COUNT=$((COUNT+1)); TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

# 老系统 (EOL) 检测逻辑
is_eol() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        [[ "$ID" == "debian" && "$VERSION_ID" -lt 10 ]] && return 0
        [[ "$ID" == "ubuntu" && "${VERSION_ID%%.*}" -lt 18 ]] && return 0
    fi
    return 1
}

init_audit() {
    # 1-8: SSH
    add_item "强制 SSH 协议 V2" "修复旧版漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直连" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开 99% 自动扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用 SSH 密码认证" "彻底防御爆破" "需预配密钥" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 空闲超时(10m)" "防范劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告要求" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防Shell提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    # 9-11: 账户
    add_item "强制 10 位混合密码" "极大提高爆破难度" "需符合要求" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防盗号快速改密" "7天禁再改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "终端离机安全" "闲置强制退" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    # 12-16: 权限
    add_item "修正 /etc/passwd" "防止非法修改账号" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露密码哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护SSH核心配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护授权公钥文件" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID" "堵死常用指令提权" "无法ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    # 17-20: 限制
    add_item "锁定异常 UID=0" "清理潜在后门账号" "误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudoers 免密" "防止静默恶意提权" "脚本需适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel 组" "缩减Root切换范围" "需加组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"
    add_item "限制编译器权限" "防止编译提权木马" "无" "[ \"\$(stat -c %a /usr/bin/gcc 2>/dev/null)\" == \"700\" ] || [ ! -f /usr/bin/gcc ]" "FALSE"
    # 21-23: 内核
    add_item "网络内核防欺骗" "防ICMP重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御洪水 DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵协议漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    # 24-27: 审计与漏洞 (包含 EOL 系统检测)
    add_item "时间同步(Chrony)" "对准审计日志时间" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防范磁盘被撑爆" "减少存储记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破 IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "自动更新与高危补丁" "修补全量系统级漏洞" "需联网下载" "! is_eol && command -v unattended-upgrades >/dev/null && dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10" "FALSE"
}

# --- 修复逻辑 (全量 27 项修复指令，绝无省略) ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                echo -ne "${YELLOW}请输入新端口 (20000-60000, 回车则随机): ${RESET}"; read -r i_p
                TARGET_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$TARGET_P " && ui_warn "端口冲突！请重选。" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $TARGET_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $TARGET_P/tcp >/dev/null ;;
        "禁用 SSH 密码认证") sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config; echo "PasswordAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Restricted." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        "强制 10 位混合密码") smart_install "libpam-pwquality" && [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") echo "export TMOUT=600" >> /etc/profile; echo "readonly TMOUT" >> /etc/profile ;;
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount 2>/dev/null ;;
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} 2>/dev/null ;;
        "移除 Sudoers 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers 2>/dev/null; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "限制编译器权限") [ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        "时间同步(Chrony)") smart_install "chrony" && systemctl enable --now chronyd >/dev/null 2>&1 ;;
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
        "Fail2ban 最佳防护") smart_install "fail2ban" && { cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
maxretry = 5
[sshd]
enabled = true
EOF
            systemctl enable --now fail2ban >/dev/null 2>&1; } ;;
        "自动更新与高危补丁") 
            if is_eol; then ui_fail "系统版本过老 (EOL)，已停更，跳过补丁。"; else
            handle_lock && { apt-get update >/dev/null; apt-get install --only-upgrade -y dpkg logrotate apt tar gzip >/dev/null 2>&1 & show_spinner $!; wait $!; }; fi ;;
    esac
}

# --- 界面循环 ---
init_audit
while true; do
    clear; echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${BOLD} ID | 状态 | 项目名称${RESET}"; echo -e "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        if [ "${SELECTED[$i]}" == "TRUE" ]; then S_ICO="${GREEN}[ ON ]${RESET}"; else S_ICO="${GREY}[OFF ]${RESET}"; fi
        if [ "${STATUS[$i]}" == "PASS" ]; then R_ICO="${GREEN}${I_OK}${RESET}"; else R_ICO="${RED}${I_FAIL}${RESET}"; fi
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行 ID 清单: ${GREEN}${SUM_IDS%, }${RESET}"; echo -e "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始修复 | q=返回 | 输入编号 ID 翻转勾选: "; read -r raw_input
    
    case "$raw_input" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && { MSG="请先勾选项目！"; continue; }
            if [ "$has_r" == "TRUE" ]; then echo -ne "${RED}清单含高危项，确认继续? (yes/no): ${RESET}"; read -r c; [ "$c" != "yes" ] && continue; fi
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            # 最后的 SSH 语法检测与重载
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "配置生效成功。"; } || ui_fail "语法检查错误，已拦截重载。"
            # === [工业级防闪退] ===
            echo -ne "\n${YELLOW}【重要】所有加固流程执行完毕。按任意键安全返回主控台菜单...${RESET}"
            read -n 1 -s -r; exit 0 ;;
        *) for n in $raw_input; do 
             if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ]; then
                if [ "${SELECTED[$n]}" == "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
             fi
           done ;;
    esac
done
