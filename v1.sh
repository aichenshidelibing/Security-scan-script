#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v21.3 工业级健壮终极版)
# 特性：27项全量修复逻辑(不省略) | 交互式开关 | 智能锁管理 | 端口防撞 | 语法/磁盘预检

set -u
export LC_ALL=C

# --- [信号捕获] 确保优雅返回主菜单 ---
trap 'echo -e "\n${YELLOW}操作取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

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

# --- 辅助工具函数 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

# 旋转进度条 (解决“傻等”感)
show_spinner() {
    local pid=$1; local delay=0.1; local spinstr='|/-\'
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}; printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}; sleep $delay; printf "\b\b\b\b\b\b"
    done; printf "    \b\b\b\b"
}

# 磁盘空间预检 (防止安装时写满磁盘)
check_disk_space() {
    [ $(df / | awk 'NR==2 {print $4}') -lt 204800 ] && { ui_fail "错误：磁盘空间不足 200MB，停止加固。"; return 1; }
    return 0
}

# 智能锁管理 (解决死等不合理问题)
handle_apt_lock() {
    local lock_file="/var/lib/dpkg/lock-frontend"
    if [ ! -f "$lock_file" ] || ! fuser "$lock_file" >/dev/null 2>&1; then return 0; fi

    local h_pid=$(fuser "$lock_file" 2>/dev/null | awk '{print $NF}')
    ui_warn "检测到更新锁被占用 (PID: $h_pid)。正在排队等待 5 秒..."
    local count=0; while fuser "$lock_file" >/dev/null 2>&1 && [ $count -lt 5 ]; do sleep 1; count=$((count+1)); done

    if fuser "$lock_file" >/dev/null 2>&1; then
        echo -e "${YELLOW}锁仍未释放。请选择: [1] 继续等 [2] 跳过此项 [3] 强制解锁(风险)${RESET}"
        read -p "您的选择: " lock_choice
        case "$lock_choice" in
            1) handle_apt_lock ;;
            3) kill -9 "$h_pid" 2>/dev/null; rm -f "$lock_file" 2>/dev/null; ui_ok "已强制释放。" ;;
            *) return 1 ;;
        esac
    fi
    return 0
}

# 智能安装：带检测 + 进度条 + 报错回显
smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ]; then return 0; fi
    check_disk_space || return 1
    handle_apt_lock || return 1
    ui_info "正在安装组件: $pkg ..."
    local err_log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    else return 1; fi
    show_spinner $!; wait $!
    [ $? -ne 0 ] && { ui_fail "$pkg 安装失败。日志内容:"; cat "$err_log"; rm -f "$err_log"; return 1; }
    rm -f "$err_log"; return 0
}

# --- 数据初始化 (27项全量) ---
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}
TARGET_P="$CUR_P"

add_item() {
    COUNT=$((COUNT+1)); TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

init_audit() {
    add_item "强制 SSH 协议 V2" "修复古老漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止空密码登录" "防范远程侵入" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开扫描" "需开端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用交互式认证" "防密码爆破" "工具受限" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防会话劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规法律警告" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防Shell提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    add_item "强制 10 位混合密码" "极大提高门槛" "需改密" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防盗号改密" "7天禁改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机安全" "不活跃退" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    add_item "修正 /etc/passwd" "权限 644" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "权限 600" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "权限 600" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "权限 600" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "锁定异常 UID=0" "清理后门" "误锁管理" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudoers 免密" "防静默提权" "脚本受阻" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "堵死提权路径" "无法ping" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel 组" "限制切Root" "需手动加组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"
    add_item "网络内核防欺骗" "防ICMP重定向" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵协议漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    add_item "时间同步(Chrony)" "确保审计准确" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防磁盘爆满" "减少记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "每日自动更新组件" "及时修补漏洞" "版本变" "command -v unattended-upgrades >/dev/null" "FALSE"
    add_item "系统高危漏洞修复" "全量漏洞升级" "联网耗时" "dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10" "FALSE"
}

# --- 修复逻辑 (全量完整展开，绝无省略) ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   请输入新端口 (回车随机): " i_p; TARGET_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$TARGET_P " && ui_warn "端口冲突！" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $TARGET_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $TARGET_P/tcp >/dev/null ;;
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
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
        "系统高危漏洞修复") handle_apt_lock; apt-get update >/dev/null; apt-get install --only-upgrade -y dpkg logrotate apt tar gzip >/dev/null 2>&1 & show_spinner $!; wait $! ;;
    esac
}

# --- 交互界面 ---
init_audit
while true; do
    clear; echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${BOLD} ID | 状态 | 名称${RESET}"; echo -e "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        S_TXT=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON ]${RESET}" || echo -e "${GREY}[OFF ]${RESET}" )
        RES_ICO=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK}${RESET}" || echo -e "${RED}${I_FAIL}${RESET}" )
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_TXT" "$RES_ICO" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行清单: ${GREEN}${SUM_IDS%, }${RESET}"; echo -e "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=修复 | q=返回 | 输入编号: "; read -r ri
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && continue
            [ "$has_r" == "TRUE" ] && { read -p "   含风险，确认执行? (yes/no): " c; [ "$c" != "yes" ] && continue; }
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 配置安全生效。"; } || ui_fail "SSH 语法预检失败，拦截重载。"
            echo -ne "\n${YELLOW}全部加固完成。按任意键返回...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do [[ "$n" =~ ^[0-9]+$ ]] && [ $n -ge 1 -a $n -le $COUNT ] && ([ "${SELECTED[$n]}" == "TRUE" ] && SELECTED[$n]="FALSE" || SELECTED[$n]="TRUE"); done ;;
    esac
done
