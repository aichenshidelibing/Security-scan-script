#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v23.1 工业全能闭环版)

set -u
export LC_ALL=C

# --- [信号捕获] 确保 Ctrl+C 优雅返回主菜单 ---
trap 'echo -e "\n${YELLOW}操作被取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

# --- [UI 自适应检测] ---
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

# --- 核心辅助工具 ---
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

# 修正 Debian 11 安全源报错 (针对 Snipaste_2026-01-03_13-27-49)
fix_apt_sources() {
    if [ -f /etc/debian_version ] && grep -q "^11" /etc/debian_version; then
        if grep -q "bullseye/updates" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            ui_info "检测到 Debian 11 旧版安全源，正在修正路径..."
            sed -i 's|bullseye/updates|bullseye-security|g' /etc/apt/sources.list
            find /etc/apt/sources.list.d/ -type f -exec sed -i 's|bullseye/updates|bullseye-security|g' {} +
        fi
    fi
}

# 锁管理与自愈 (针对 Snipaste_2026-01-03_13-27-49)
handle_apt_lock() {
    local lock_file="/var/lib/dpkg/lock-frontend"
    if [ -f "$lock_file" ] && fuser "$lock_file" >/dev/null 2>&1; then
        local h_pid=$(fuser "$lock_file" 2>/dev/null | awk '{print $NF}')
        ui_warn "检测到更新锁被占用 (PID: $h_pid)。"
        ui_info "尝试排队等待 5 秒..."
        local count=0; while fuser "$lock_file" >/dev/null 2>&1 && [ $count -lt 5 ]; do sleep 1; count=$((count+1)); done
        if fuser "$lock_file" >/dev/null 2>&1; then
            echo -e "${YELLOW}锁未释放。请选: [1] 接着等 [2] 跳过 [3] 强杀进程并执行自愈修复${RESET}"
            read -p "选择: " lock_choice
            if [ "$lock_choice" == "3" ]; then
                kill -9 "$h_pid" 2>/dev/null; rm -f "$lock_file" /var/lib/apt/lists/lock /var/lib/dpkg/lock 2>/dev/null
                ui_info "执行 dpkg 自愈修复..."
                dpkg --configure -a >/dev/null 2>&1
                ui_ok "自愈完成。"
            elif [ "$lock_choice" == "1" ]; then handle_apt_lock; else return 1; fi
        fi
    fi
    return 0
}

smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ] || [ -x "/usr/bin/$pkg" ]; then return 0; fi
    ui_info "正在安装必要组件: $pkg ..."
    local err_log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then
        handle_apt_lock || return 1; fix_apt_sources
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v yum >/dev/null; then yum install -y "$pkg" >/dev/null 2>"$err_log" &
    else return 1; fi
    show_spinner $!; wait $!
    [ $? -ne 0 ] && { ui_fail "$pkg 安装失败。日志内容:"; [ -f "$err_log" ] && cat "$err_log"; rm -f "$err_log"; return 1; }
    rm -f "$err_log"; return 0
}

# --- 数据定义 (27项全量) ---
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}

add_item() {
    COUNT=$((COUNT+1)); TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

is_eol() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        [[ "$ID" == "debian" && "$VERSION_ID" -lt 10 ]] && return 0
        [[ "$ID" == "ubuntu" && "${VERSION_ID%%.*}" -lt 16 ]] && return 0
        [[ "$ID" == "centos" && "$VERSION_ID" -lt 7 ]] && return 0
    fi
    return 1
}

init_audit() {
    add_item "强制 SSH 协议 V2" "修复旧版协议漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程暴力侵入" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开爆破扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用交互式认证" "防范密码爆破嗅探" "特殊工具受限" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防范会话被他人接管" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告提示" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止利用Shell环境提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    add_item "强制 10 位混合密码" "极大提高爆破难度" "需改密" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防账号被盗后快速改密" "7天内禁再改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机物理安全防护" "不活跃强制退" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    add_item "修正 /etc/passwd" "防止非特权修改账号" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露密码哈希值" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护 SSH 核心配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护已授权公钥" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "锁定异常 UID=0 账户" "彻底清理提权后门" "误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudoers 免密" "防止恶意静默提权" "脚本需适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "堵死常用指令提权路径" "无法ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel 组" "缩减 Root 切换权限范围" "需加组" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth" "FALSE"
    add_item "限制编译器权限" "防止普通用户编译木马" "无" "[ \"\$(stat -c %a /usr/bin/gcc 2>/dev/null)\" == \"700\" ] || [ ! -f /usr/bin/gcc ]" "FALSE"
    add_item "网络内核防欺骗" "防范 ICMP 重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御大规模洪水攻击" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵协议层潜在漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    add_item "时间同步(Chrony)" "确保审计日志时间对准" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防范磁盘被日志撑爆" "减少存储记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破恶意 IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "全量系统漏洞修复" "升级 dpkg/logrotate 等高危补丁" "需联网下载" "! is_eol && { dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10; }" "FALSE"
}

# --- 核心修复逻辑 (27项完整展开，绝不省略) ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$T_P " && ui_warn "端口冲突！" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null ;;
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Restricted Access." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        "强制 10 位混合密码") smart_install "libpam-pwquality" && [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") grep -q "TMOUT=600" /etc/profile || echo "export TMOUT=600 && readonly TMOUT" >> /etc/profile ;;
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount 2>/dev/null ;;
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} ;;
        "移除 Sudoers 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "限制编译器权限") [ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危不常用协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
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
        "全量系统漏洞修复") 
            if is_eol; then ui_fail "老系统停更，跳过补丁。"; else
            handle_lock && { fix_apt_sources; apt-get update >/dev/null; apt-get install --only-upgrade -y dpkg logrotate apt tar gzip 2>/dev/null & show_spinner $!; wait $!; }
            fi ;;
    esac
}

# --- 交互界面 ---
init_audit
while true; do
    clear; echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${BOLD} ID | 状态 | 项目名称${RESET}"; echo -e "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        if [ "${SELECTED[$i]}" == "TRUE" ]; then S_ICO="${GREEN}[ ON ]${RESET}"; else S_ICO="${GREY}[OFF ]${RESET}"; fi
        if [ "${STATUS[$i]}" == "PASS" ]; then R_ICO="${GREEN}${I_OK}${RESET}"; else R_ICO="${RED}${I_FAIL}${RESET}" ; fi
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行 ID 清单: ${GREEN}${SUM_IDS%, }${RESET}"; echo -e "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始修复 | q=返回 | 输入编号 ID 翻转勾选: "; read -r ri
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && continue
            if [ "$has_r" == "TRUE" ]; then echo -ne "${RED}清单含风险项，确认继续? (yes/no): ${RESET}"; read -r c; [ "$c" != "yes" ] && continue; fi
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "配置生效成功。"; } || ui_fail "语法检查错误，已拦截。"
            echo -ne "\n${YELLOW}【终极提示】所有加固流程执行完毕。按任意键返回主控台菜单...${RESET}"
            read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ]; then
                if [ "${SELECTED[$n]}" == "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
             fi; done ;;
    esac
done
