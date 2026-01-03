#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v32.0 智能DNS·全量终极版)
# 特性：智能DNS判断(不盲目覆盖) | 36项全量 | 救砖自愈 | 防卡死 | 进度条

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

# =======================================================================
# [核心防闪退] 退出前强制暂停
# =======================================================================
finish_trap() {
    echo -e "\n\033[33m[系统提示] 脚本运行结束。请按回车键关闭窗口...\033[0m"
    read -r
}
trap finish_trap EXIT
# =======================================================================

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

check_space() { [ $(df / | awk 'NR==2 {print $4}') -lt 204800 ] && { ui_fail "磁盘不足 200MB，停止。"; return 1; }; return 0; }

# --- 智能锁管理 ---
handle_lock() {
    local lock="/var/lib/dpkg/lock-frontend"
    [ ! -f "$lock" ] || ! fuser "$lock" >/dev/null 2>&1 && return 0
    ui_warn "检测到包管理器锁，等待 5 秒..."
    local count=0; while fuser "$lock" >/dev/null 2>&1 && [ $count -lt 5 ]; do sleep 1; count=$((count+1)); done
    if fuser "$lock" >/dev/null 2>&1; then
        local pid=$(fuser "$lock" 2>/dev/null | awk '{print $NF}')
        kill -9 "$pid" 2>/dev/null
        rm -f /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend 2>/dev/null
        dpkg --configure -a >/dev/null 2>&1
    fi
    return 0
}

# --- 核心：老旧系统救砖 & 换源 ---
fix_eol_sources() {
    # CentOS 7
    if [ -f /etc/centos-release ]; then
        local ver=$(rpm -q --qf "%{VERSION}" -f /etc/centos-release)
        if [[ "$ver" == "7" ]]; then
            if ! grep -q "vault.centos.org" /etc/yum.repos.d/CentOS-Base.repo 2>/dev/null; then
                ui_info "检测到 CentOS 7 (EOL)，切换至 Vault 源..."
                mkdir -p /etc/yum.repos.d/backup
                mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup/ 2>/dev/null
                curl -o /etc/yum.repos.d/CentOS-Base.repo https://raw.githubusercontent.com/hackyo/source/master/CentOS-7-Vault-Aliyun.repo >/dev/null 2>&1
                yum clean all >/dev/null 2>&1; yum makecache >/dev/null 2>&1
            fi
        fi
    fi
    # Debian/Ubuntu EOL
    if [ -f /etc/debian_version ]; then
        if grep -qE "^(8|9|10)" /etc/debian_version; then
             if ! grep -q "archive.debian.org" /etc/apt/sources.list; then
                 ui_info "检测到 Debian 旧版，切换至 Archive 源..."
                 echo "deb http://archive.debian.org/debian/ $(lsb_release -sc) main contrib non-free" > /etc/apt/sources.list
                 echo "deb http://archive.debian.org/debian-security/ $(lsb_release -sc)/updates main contrib non-free" >> /etc/apt/sources.list
             fi
        fi
        if grep -q "^11" /etc/debian_version; then
            sed -i 's|bullseye/updates|bullseye-security|g' /etc/apt/sources.list 2>/dev/null
        fi
    fi
}

# --- 智能 DNS 修复 (v32.0 新增) ---
smart_dns_fix() {
    # 1. 尝试 ping 权威地址，如果通，说明 DNS 正常，直接跳过
    if ping -c 1 -W 2 google.com >/dev/null 2>&1 || ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
        ui_ok "网络连接正常，保留当前 DNS 设置。"
        return 0
    fi

    # 2. 如果不通，尝试检测是否为国内机器 (ping 百度)
    ui_warn "网络连接异常，正在尝试修复 DNS..."
    if ping -c 1 -W 2 baidu.com >/dev/null 2>&1; then
        ui_info "检测到国内网络环境，使用阿里云 DNS..."
        echo "nameserver 223.5.5.5" > /etc/resolv.conf
        echo "nameserver 119.29.29.29" >> /etc/resolv.conf
    else
        ui_info "检测到国际网络环境，使用 Google/CF DNS..."
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    fi
    ui_ok "DNS 已智能修正。"
}

# --- 全局环境自愈 ---
heal_environment() {
    ui_info "正在进行环境自愈..."
    smart_dns_fix # 只有在网不通时才修 DNS
    handle_lock
    fix_eol_sources
    if command -v apt-get >/dev/null; then
        ( UCF_FORCE_CONFFOLD=1 dpkg --configure -a && apt-get install -f -y ) >/dev/null 2>&1
    elif command -v yum >/dev/null; then
        yum install -y epel-release >/dev/null 2>&1
    fi
    ui_ok "环境准备就绪。"
}

# --- 智能安装 ---
smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1; then return 0; fi
    handle_lock
    ui_info "安装: $pkg ..."
    local log="/tmp/${pkg}_err.log"
    if command -v apt-get >/dev/null; then
        ( UCF_FORCE_CONFFOLD=1 apt-get install -y "$pkg" ) >/dev/null 2>"$log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$log" &
    elif command -v yum >/dev/null; then
        yum install -y "$pkg" >/dev/null 2>"$log" &
    else return 1; fi
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    [ $? -ne 0 ] && { ui_fail "$pkg 安装失败。"; return 1; }
    rm -f "$log"; return 0
}

# --- 数据定义 (36项全量) ---
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
    # 1. 基础优化 (3项)
    add_item "开启 TCP BBR 加速" "显著提升网络吞吐" "需内核支持" "sysctl net.ipv4.tcp_congestion_control | grep -q bbr" "FALSE"
    add_item "安装装机必备软件" "curl/wget/vim/htop/git" "占用少量空间" "command -v vim >/dev/null && command -v htop >/dev/null" "FALSE"
    add_item "智能 DNS 优化" "提升解析速度" "无" "grep -q '8.8.8.8' /etc/resolv.conf || grep -q '223.5.5.5' /etc/resolv.conf" "FALSE"

    # 2. SSH 安全 (9项)
    add_item "强制 SSH 协议 V2" "修复旧版漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直连" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开扫描" "需开新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用 SSH 密码认证" "彻底防爆破" "需预配密钥" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 空闲超时(10m)" "防劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH Root 登录" "最高防护" "需建普通用户" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 登录 Banner" "合规警告" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防Shell提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"

    # 3. 账户安全 (3项)
    add_item "强制 10 位混合密码" "提高爆破难度" "改密麻烦" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防盗号改密" "7天禁改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机安全" "强制退出" "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # 4. 文件权限 (5项)
    add_item "修正 /etc/passwd" "防非法修改" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防泄露哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护配置" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护公钥" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID" "堵死提权" "无法ping" "[ ! -u /bin/mount ]" "FALSE"

    # 5. 限制与加固 (6项)
    add_item "锁定异常 UID=0" "清后门账号" "误锁管理" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "防静默提权" "脚本适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel" "缩减Root范围" "需加组" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth" "FALSE"
    add_item "限制编译器权限" "防编译木马" "无" "local g=\$(command -v gcc); [ -z \"\$g\" ] || [ \"\$(stat -c %a \"\$(readlink -f \"\$g\")\")\" == \"700\" ]" "FALSE"
    add_item "扩展 SUID 清理" "宝塔推荐" "更多限制" "[ ! -u /usr/bin/wall ]" "FALSE"
    add_item "锁定 Bootloader" "防物理篡改" "影响Grub" "[ \"\$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)\" == \"600\" ]" "FALSE"

    # 6. 内核防御 (5项)
    add_item "网络内核防欺骗" "防ICMP重定向" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    add_item "禁用非常用文件系统" "宝塔推荐" "禁JFFS2/UDF" "[ -f /etc/modprobe.d/disable-filesystems.conf ]" "FALSE"
    add_item "记录恶意数据包" "监控Martian" "增加日志" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '= 1'" "FALSE"

    # 7. 审计与更新 (5项)
    add_item "时间同步(Chrony)" "日志对准" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防磁盘爆满" "减少记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动封禁IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "每日自动更新组件" "自动打补丁" "版本微变" "command -v unattended-upgrades >/dev/null || systemctl is-active --quiet dnf-automatic.timer" "FALSE"
    add_item "立即修复高危漏洞" "升级dpkg等" "需联网" "! is_eol && { dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10; }" "FALSE"
}

apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    
    case "$title" in
        "开启 TCP BBR 加速")
            if uname -r | grep -q "^[5-9]"; then
                echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p >/dev/null 2>&1; ui_ok "BBR 已开启。"
            else ui_fail "内核版本过低 (<4.9)，不支持 BBR。"; fi ;;
        "安装装机必备软件")
            smart_install "curl"; smart_install "wget"; smart_install "vim"; smart_install "unzip"; smart_install "htop"; smart_install "git"; smart_install "net-tools" ;;
        "智能 DNS 优化")
            smart_dns_fix ;; # 核心改动：调用智能判断函数
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$T_P " && ui_warn "端口冲突" || p_ok=0
            done; sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null ;;
        "禁用 SSH 密码认证") sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config; echo "PasswordAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "禁止 SSH Root 登录") sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config; echo "PermitRootLogin no" >> /etc/ssh/sshd_config ;;
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
        "移除 Sudo 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "限制 su 仅 wheel") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "限制编译器权限") 
            local gcc_path=$(command -v gcc); if [ -n "$gcc_path" ]; then local real_path=$(readlink -f "$gcc_path"); chmod 700 "$real_path"; ui_ok "编译器 $real_path 限制完成。"; fi ;;
        "扩展 SUID 清理") chmod u-s /usr/bin/wall /usr/bin/chage /usr/bin/gpasswd /usr/bin/chfn /usr/bin/chsh 2>/dev/null ;;
        "锁定 Bootloader") [ -f /boot/grub/grub.cfg ] && chmod 600 /boot/grub/grub.cfg ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        "禁用非常用文件系统") echo -e "install cramfs /bin/true\ninstall freevxfs /bin/true\ninstall jffs2 /bin/true\ninstall hfs /bin/true\ninstall hfsplus /bin/true\ninstall squashfs /bin/true\ninstall udf /bin/true" > /etc/modprobe.d/disable-filesystems.conf ;;
        "记录恶意数据包") sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1 ;;
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
        "每日自动更新组件") smart_install "unattended-upgrades" || smart_install "dnf-automatic"; systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 ;;
        "立即修复高危漏洞")
             if is_eol; then ui_fail "系统过老已停更，跳过。"; else
                 handle_lock
                 ui_info "正在下载补丁..."
                 if command -v apt-get >/dev/null; then
                     apt-get update >/dev/null 2>&1
                     ( UCF_FORCE_CONFFOLD=1 apt-get install --only-upgrade -y dpkg logrotate apt tar gzip openssl ) >/dev/null 2>&1 &
                 elif command -v dnf >/dev/null; then
                     dnf update -y dpkg logrotate >/dev/null 2>&1 &
                 fi
                 show_spinner $!; wait $!
                 ui_ok "补丁修复完成。"
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
            check_space || continue
            heal_environment
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 已重载。"; }
            echo -ne "\n${YELLOW}【重要】流程执行完毕。按任意键返回主菜单...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do 
            if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ]; then
                if [ "${SELECTED[$n]}" == "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
            fi
        done ;;
    esac
done
