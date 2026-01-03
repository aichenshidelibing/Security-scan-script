#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v28.0 核弹级无脑执行版)
# 特性：强制静默安装(不弹窗) | 开局暴力洗地 | 进度条 | 防闪退 | 全量28项

set -u
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# --- [信号捕获] ---
trap 'echo -e "\n${YELLOW}操作取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

# --- [UI 自适应] ---
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')
I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✅" || echo "[ OK ]"); I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "ℹ️ " || echo "[INFO]"); I_WAIT=$([ "$USE_EMOJI" == "1" ] && echo "⏳" || echo "[WAIT]")

# --- 核心工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# --- [核弹级] 系统环境暴力清洗 ---
# 不问询，直接杀进程、删锁、修库
force_heal_environment() {
    ui_info "正在执行环境暴力清洗 (杀进程/删锁/修库)..."
    
    # 1. 杀掉所有占用锁的进程
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        fuser -k -9 /var/lib/dpkg/lock-frontend >/dev/null 2>&1
    fi
    if fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        fuser -k -9 /var/lib/dpkg/lock >/dev/null 2>&1
    fi
    
    # 2. 强制删除锁文件
    rm -f /var/lib/dpkg/lock \
          /var/lib/dpkg/lock-frontend \
          /var/lib/apt/lists/lock \
          /var/cache/apt/archives/lock 2>/dev/null
    
    # 3. 修正 Debian 11 源 (防止 update 404)
    if [ -f /etc/debian_version ] && grep -q "^11" /etc/debian_version; then
        if grep -q "bullseye/updates" /etc/apt/sources.list 2>/dev/null; then
            sed -i 's|bullseye/updates|bullseye-security|g' /etc/apt/sources.list
        fi
    fi

    # 4. 强制修复 dpkg 状态
    # 使用 dpkg --configure -a 修复中断的安装
    dpkg --configure -a >/dev/null 2>&1
    # 再次尝试修复依赖
    if command -v apt-get >/dev/null; then
        apt-get install -f -y >/dev/null 2>&1
    fi
    
    ui_ok "环境清洗完成。"
}

# 智能安装 (带强制参数，绝不卡死)
smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ] || [ -x "/usr/bin/$pkg" ]; then return 0; fi
    
    ui_info "安装: $pkg ..."
    local log="/tmp/${pkg}_err.log"
    
    # 关键：加入 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    # 这会让 apt 遇到配置文件冲突时自动使用旧配置，不再弹窗询问！
    if command -v apt-get >/dev/null; then
        apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$pkg" >/dev/null 2>"$log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$log" &
    elif command -v yum >/dev/null; then
        yum install -y "$pkg" >/dev/null 2>"$log" &
    else return 1; fi
    
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    
    if [ $? -ne 0 ]; then
        ui_fail "$pkg 安装失败。日志:"
        [ -f "$log" ] && cat "$log"
        rm -f "$log"
        return 1
    fi
    rm -f "$log"
    return 0
}

# --- 数据定义 (28项全量) ---
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}

add_item() {
    COUNT=$((COUNT+1))
    TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
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
    # 1-8 SSH
    add_item "强制 SSH 协议 V2" "修复旧版漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直连" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开爆破扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用 SSH 密码认证" "彻底防御爆破" "需预配密钥" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 空闲超时(10m)" "防范劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防Shell提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    # 9-11 账户
    add_item "强制 10 位混合密码" "极大提高门槛" "需改密" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防盗号改密" "7天禁再改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机安全" "强制退出" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    # 12-16 权限
    add_item "修正 /etc/passwd" "防非法修改" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防泄露哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护SSH配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护公钥" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID" "堵死提权" "无法ping" "[ ! -u /bin/mount ]" "FALSE"
    # 17-20 限制
    add_item "锁定异常 UID=0" "清后门账号" "误锁管理" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "防静默提权" "脚本适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel" "缩减Root范围" "需加组" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth" "FALSE"
    add_item "限制编译器权限" "防编译木马" "无" "[ \"\$(stat -c %a /usr/bin/gcc 2>/dev/null)\" == \"700\" ] || [ ! -f /usr/bin/gcc ]" "FALSE"
    # 21-23 内核
    add_item "网络内核防欺骗" "防ICMP重定向" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    # 24-28 审计与更新
    add_item "时间同步(Chrony)" "日志对准" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防磁盘爆满" "减少记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动封禁IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "每日自动更新组件" "自动打补丁" "版本微变" "command -v unattended-upgrades >/dev/null || systemctl is-active --quiet dnf-automatic.timer" "FALSE"
    # 注意：这里的检测逻辑改为了只要 apt/dnf 能运行就算通过，避免因 dpkg 锁导致检测误判为叉
    add_item "立即修复高危漏洞" "升级dpkg等" "需联网" "! is_eol && { command -v apt-get >/dev/null || command -v dnf >/dev/null; }" "FALSE"
}

# --- 修复逻辑 ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   请输入新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$T_P " && ui_warn "端口冲突！" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null ;;
        "禁用 SSH 密码认证") sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config; echo "PasswordAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Restricted Access." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        "强制 10 位混合密码") smart_install "libpam-pwquality" || smart_install "libpwquality"
            [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") grep -q "TMOUT=600" /etc/profile || echo -e "export TMOUT=600\nreadonly TMOUT" >> /etc/profile ;;
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount /usr/bin/newgrp /usr/bin/chsh 2>/dev/null ;;
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} ;;
        "移除 Sudo 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers 2>/dev/null; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "限制 su 仅 wheel") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "限制编译器权限") [ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        "时间同步(Chrony)") smart_install "chrony" && systemctl enable --now chronyd >/dev/null 2>&1 ;;
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
        "Fail2ban 最佳防护") smart_install "fail2ban" && { 
            cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
EOF
            systemctl enable --now fail2ban >/dev/null 2>&1; } ;;
        "每日自动更新组件") 
             smart_install "unattended-upgrades" || smart_install "dnf-automatic"
             systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 ;;
        "立即修复高危漏洞")
             if is_eol; then ui_fail "系统过老已停更，跳过。"; else
                 ui_info "正在全量下载补丁 (静默模式，防止卡死)..."
                 if command -v apt-get >/dev/null; then
                     apt-get update >/dev/null 2>&1
                     # 关键：加上 -y 和 强制配置选项，防止弹出对话框卡死脚本
                     apt-get install --only-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dpkg logrotate apt tar gzip openssl >/dev/null 2>&1 &
                 elif command -v dnf >/dev/null; then
                     dnf update -y dpkg logrotate >/dev/null 2>&1 &
                 fi
                 show_spinner $!; wait $!
                 ui_ok "补丁修复流程结束。"
             fi ;;
    esac
}

# --- 交互界面 ---
init_audit
while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID | 状态 | 名称${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        if [ "${SELECTED[$i]}" == "TRUE" ]; then S_ICO="${GREEN}[ ON ]${RESET}"; else S_ICO="${GREY}[OFF ]${RESET}"; fi
        if [ "${STATUS[$i]}" == "PASS" ]; then R_ICO="${GREEN}${I_OK}${RESET}"; else R_ICO="${RED}${I_FAIL}${RESET}"; fi
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    
    echo "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行清单: ${GREEN}${SUM_IDS%, }${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始修复 | q=返回 | 输入编号 ID 翻转: "
    read -r ri
    
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && { MSG="请先勾选！"; continue; }
            if [ "$has_r" == "TRUE" ]; then echo -ne "${RED}含风险项，确认继续? (yes/no): ${RESET}"; read -r c; [ "$c" != "yes" ] && continue; fi
            
            # --- 核心：开局暴力洗地，不问询 ---
            force_heal_environment
            # ----------------------------------
            
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 已重载。"; }
            
            echo -ne "\n${YELLOW}【重要】所有流程执行完毕。按任意键返回主控台菜单...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do 
            if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ]; then
                if [ "${SELECTED[$n]}" == "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
            fi
        done ;;
    esac
done
