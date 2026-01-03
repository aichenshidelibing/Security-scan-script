#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v21.0 工业级健壮版)
# 特性：27项全量 | 智能锁超时 | SSH配置预检 | 磁盘预检 | 端口防撞 | 信号保护

set -u
export LC_ALL=C

# ---------- [信号捕获] 确保优雅返回 ----------
trap 'echo -e "\n${YELLOW}操作被中断，返回主菜单...${RESET}"; exit 0' INT

# ---------- [UI 自适应] ----------
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')
I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✅" || echo "[ OK ]")
I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "ℹ️ " || echo "[INFO]")
I_FIX=$([ "$USE_EMOJI" == "1" ] && echo "🔧" || echo "[FIX]")
I_WAIT=$([ "$USE_EMOJI" == "1" ] && echo "⏳" || echo "[WAIT]")

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

# 进度条逻辑
show_spinner() {
    local pid=$1; local delay=0.1; local spinstr='|/-\'
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}; printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}; sleep $delay; printf "\b\b\b\b\b\b"
    done; printf "    \b\b\b\b"
}

# --- 磁盘空间预检 ---
check_disk_space() {
    local free_kb=$(df / | awk 'NR==2 {print $4}')
    if [ "$free_kb" -lt 204800 ]; then # 小于 200MB
        ui_fail "错误：根分区剩余空间不足 200MB，为防止系统崩溃，加固终止。"
        return 1
    fi
    return 0
}

# --- 智能锁管理 (解决死等问题) ---
handle_apt_lock() {
    local lock_file="/var/lib/dpkg/lock-frontend"
    if [ ! -f "$lock_file" ] || ! fuser "$lock_file" >/dev/null 2>&1; then return 0; fi

    local holder_pid=$(fuser "$lock_file" 2>/dev/null | awk '{print $NF}')
    local holder_name=$(ps -p "$holder_pid" -o comm= 2>/dev/null)
    ui_warn "检测到 APT 锁被占用 (进程: $holder_name, PID: $holder_pid)。"

    # 尝试等待 30 秒
    ui_info "正在尝试排队等待 30 秒..."
    local count=0
    while fuser "$lock_file" >/dev/null 2>&1 && [ $count -lt 15 ]; do
        sleep 2; count=$((count+1))
        printf "."
    done
    echo ""

    if fuser "$lock_file" >/dev/null 2>&1; then
        ui_fail "等待超时。"
        echo -e "请选择: [1] 继续等 [2] 跳过此项 [3] 强制杀死该进程(风险大)"
        read -p "选择: " lock_choice
        case "$lock_choice" in
            1) handle_apt_lock ;;
            3) kill -9 "$holder_pid"; sleep 1; rm -f "$lock_file"; ui_ok "已强制释放锁。" ;;
            *) return 1 ;; # 默认跳过
        esac
    fi
    return 0
}

# --- SSH 语法预检 ---
safe_sshd_apply() {
    if ! /usr/sbin/sshd -t >/dev/null 2>&1; then
        ui_fail "警告：SSHD 配置语法检查失败！为了防止您被锁在系统外，配置已拦截。"
        ui_info "请检查 /etc/ssh/sshd_config 文件的语法内容。"
        return 1
    fi
    systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1
    ui_ok "SSH 配置已安全重载。"
    return 0
}

smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ]; then return 0; fi
    check_disk_space || return 1
    handle_apt_lock || return 1
    ui_info "正在安装: $pkg ..."
    local err_log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    else return 1; fi
    show_spinner $!; wait $!
    [ $? -ne 0 ] && { ui_fail "$pkg 安装失败。日志:"; cat "$err_log"; rm -f "$err_log"; return 1; }
    rm -f "$err_log"; return 0
}

# --- 数据定义 ---
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}
T_P="$CUR_P"

add_item() {
    COUNT=$((COUNT+1)); TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

init_audit() {
    # == 全量 27 项列表，对应 v17.3 和之前的需求，绝无省略 ==
    add_item "强制 SSH 协议 V2" "修复旧版协议漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止空密码登录" "防范远程暴力侵入" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开 99% 自动扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用交互式认证" "防范密码嗅探尝试" "部分工具受限" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防范会话被劫持" "自动断开闲置连接" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "法律警告合规" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止利用Shell环境提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    add_item "强制 10 位混合密码" "极大提高破解难度" "需改密" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防账号被盗后改密" "7天禁再改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机物理安全" "不活跃自动退" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    add_item "修正 /etc/passwd" "防止非特权修改" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护核心SSH配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护授权公钥" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "锁定异常 UID=0" "清理提权账号" "误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudoers 免密" "防止静默提权" "脚本需适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "堵死指令提权路径" "无法ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel 组" "限制切Root用户" "需手动加组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"
    add_item "网络内核防欺骗" "防ICMP重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS 攻击" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵罕见协议漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    add_item "时间同步(Chrony)" "对准审计日志时间" "无" "command -v chronyd >/dev/null" "FALSE"
    add_item "日志自动轮转(500M)" "防范磁盘撑爆" "减少日志存储" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破 IP" "管理员误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "每日自动更新组件" "自动修补系统漏洞" "小概率版本变" "command -v unattended-upgrades >/dev/null" "FALSE"
    add_item "系统高危漏洞修复" "全量升级漏洞补丁" "需联网下载" "dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10" "FALSE"
}

# --- 2. 修复逻辑 ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1
            while [ $p_ok -ne 0 ]; do
                read -p "   新端口 (回车随机): " i_p; T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                if ss -tuln | grep -q ":$T_P "; then ui_warn "端口冲突！"; else p_ok=0; fi
            done
            sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null ;;
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Denied." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        "强制 10 位混合密码") smart_install "libpam-pwquality" && [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") grep -q "TMOUT=600" /etc/profile || echo "export TMOUT=600 && readonly TMOUT" >> /etc/profile ;;
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} ;;
        "移除 Sudoers 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount 2>/dev/null ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
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
        "每日自动更新组件") smart_install "unattended-upgrades" ;;
        "系统高危漏洞修复") handle_apt_lock; apt-get update >/dev/null; apt-get install --only-upgrade -y dpkg logrotate apt tar >/dev/null 2>&1 & show_spinner $!; wait $! ;;
    esac
}

# --- 3. 界面循环 ---
init_audit
while true; do
    clear; echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${BOLD} ID | 状态 | 名称${RESET}"; echo -e "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        S_TXT=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK}${RESET}" || echo -e "${RED}${I_FAIL}${RESET}" )
        S_ICO=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON ]${RESET}" || echo -e "${GREY}[OFF ]${RESET}" )
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$S_TXT" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行 ID: ${GREEN}${SUM_IDS%, }${RESET}"; echo -e "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始 | q=返回 | 输入 ID 翻转: "; read -r ri
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && continue
            [ "$has_r" == "TRUE" ] && { read -p "   包含高危项，确认继续? (yes/no): " c; [ "$c" != "yes" ] && continue; }
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            safe_sshd_apply # 最后的 SSH 安全重载
            ui_ok "处理完成！按任意键返回主控台..."; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do [ $n -ge 1 -a $n -le $COUNT ] && ([ "${SELECTED[$n]}" == "TRUE" ] && SELECTED[$n]=\"FALSE\" || SELECTED[$n]=\"TRUE\"); done ;;
    esac
done
