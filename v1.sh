#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v22.0 终极完美版)

set -u
export LC_ALL=C

# --- [信号捕获] ---
trap 'echo -e "\n${YELLOW}操作取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

# --- [UI 自适应] ---
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')
I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✅" || echo "[ OK ]"); I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "ℹ️ " || echo "[INFO]"); I_WAIT=$([ "$USE_EMOJI" == "1" ] && echo "⏳" || echo "[WAIT]")

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

check_space() { [ $(df / | awk 'NR==2 {print $4}') -lt 204800 ] && { ui_fail "磁盘空间不足 200MB，停止。"; return 1; }; return 0; }

handle_lock() {
    local lock="/var/lib/dpkg/lock-frontend"
    [ ! -f "$lock" ] || ! fuser "$lock" >/dev/null 2>&1 && return 0
    ui_warn "检测到 APT 锁。尝试等待 5 秒..."
    local count=0; while fuser "$lock" >/dev/null 2>&1 && [ $count -lt 5 ]; do sleep 1; count=$((count+1)); done
    if fuser "$lock" >/dev/null 2>&1; then
        echo -e "${YELLOW}锁未释放。请选: [1] 接着等 [2] 跳过 [3] 强制杀掉进程(PID:$(fuser "$lock" 2>/dev/null))${RESET}"
        read -p "选择: " c
        [ "$c" == "3" ] && { kill -9 $(fuser "$lock" 2>/dev/null); rm -f "$lock"; return 0; }
        [ "$c" == "1" ] && handle_lock || return 1
    fi; return 0
}

smart_install() {
    local pkg=$1; [ -x "/usr/bin/$pkg" ] || command -v "$pkg" >/dev/null && return 0
    check_space || return 1; handle_lock || return 1
    ui_info "安装: $pkg ..."
    local log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get install -y "$pkg" >/dev/null 2>"$log" &
    elif command -v dnf >/dev/null; then dnf install -y "$pkg" >/dev/null 2>"$log" &
    else return 1; fi
    show_spinner $!; wait $!
    [ $? -ne 0 ] && { ui_fail "$pkg 失败。日志:"; cat "$log"; rm -f "$log"; return 1; }
    rm -f "$log"; return 0
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

# 判定 EOL (老系统检测)
is_os_eol() {
    local ver=$(cat /etc/debian_version 2>/dev/null | cut -d. -f1)
    # 示例：Debian 9 及以下判定为 EOL
    if [[ -n "$ver" ]] && [[ "$ver" -lt 10 ]]; then return 0; fi
    return 1
}

init_audit() {
    # 1-8: SSH 核心
    add_item "强制 SSH 协议 V2" "修复旧版漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直连" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开爆破扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用 SSH 密码认证" "彻底防御爆破" "需预配密钥" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 空闲超时(10m)" "防范劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防Shell提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    
    # 9-11: 账户密码
    add_item "强制 10 位混合密码" "极大提高门槛" "需改密" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防盗号快速改密" "7天禁再改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机物理安全" "不活跃退出" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    
    # 12-16: 关键权限
    add_item "修正 /etc/passwd" "防止非法改号" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护核心配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护授权公钥" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID" "堵死提权路径" "无法ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    
    # 17-20: 后门与限制
    add_item "锁定异常 UID=0" "清除后门账号" "误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudoers 免密" "防止静默提权" "脚本需适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel 组" "缩减Root范围" "需手动加组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"
    add_item "限制编译器权限" "防止编译提权包" "管理员不受限" "[ \"\$(stat -c %a /usr/bin/gcc 2>/dev/null)\" == \"700\" ] || [ ! -f /usr/bin/gcc ]" "FALSE"
    
    # 21-23: 内核防御
    add_item "网络内核防欺骗" "防ICMP重定向" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵罕见漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    
    # 24-27: 服务审计与更新 (包含 EOL 检测)
    add_item "时间同步(Chrony)" "审计日志对准" "无" "command -v chronyd >/dev/null" "FALSE"
    add_item "日志自动轮转(500M)" "防磁盘塞满" "减少历史记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破 IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "自动更新与漏洞补丁" "系统级漏洞修补" "联网下载耗时" "! is_os_eol && command -v unattended-upgrades >/dev/null && dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10" "FALSE"
}

# --- 修复逻辑 (绝无省略) ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   输入新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$T_P " && ui_warn "端口冲突！" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null ;;
        "禁用 SSH 密码认证") sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config; echo "PasswordAuthentication no" >> /etc/ssh/sshd_config ;;
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
        "自动更新与漏洞补丁") 
            if is_os_eol; then ui_fail "系统版本过老 (EOL)，仓库已停止维护，跳过此项。"; return 1; fi
            handle_lock && { apt-get update >/dev/null; apt-get install --only-upgrade -y dpkg logrotate apt tar gzip >/dev/null 2>&1 & show_spinner $!; wait $!; } ;;
    esac
}

# --- 交互界面 ---
init_audit
while true; do
    clear; echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${BOLD} ID | 状态 | 名称${RESET}"; echo -e "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        # 核心逻辑修正：不再使用转义符号
        [ "${SELECTED[$i]}" == "TRUE" ] && S_ICO="${GREEN}[ ON ]${RESET}" || S_ICO="${GREY}[OFF ]${RESET}"
        [ "${STATUS[$i]}" == "PASS" ] && R_ICO="${GREEN}${I_OK}${RESET}" || R_ICO="${RED}${I_FAIL}${RESET}"
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo -e "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行 ID 清单: ${GREEN}${SUM_IDS%, }${RESET}"; echo -e "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始 | q=返回 | 输入 ID 编号翻转: "; read -r ri
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && continue
            [ "$has_r" == "TRUE" ] && { read -p "   包含风险项，确认执行? (yes/no): " c; [ "$c" != "yes" ] && continue; }
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 配置生效成功。"; } || ui_fail "语法检查失败，拦截重载。"
            echo -ne "\n${YELLOW}加固流程已完成。按任意键返回主控台...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do [ $n -ge 1 -a $n -le $COUNT ] 2>/dev/null && { [ "${SELECTED[$n]}" == "TRUE" ] && SELECTED[$n]="FALSE" || SELECTED[$n]="TRUE"; }; done ;;
    esac
done
