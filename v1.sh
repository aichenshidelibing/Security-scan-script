#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v41.0)

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

# =======================================================================
# [核心交互修复] 信号管理
# =======================================================================
# 1. 正常退出时的逻辑 (当脚本自然结束时)
finish_trap() {
    echo -e "\n\033[33m[系统提示] 脚本执行结束。按回车键继续...\033[0m"
    read -r
}
# 默认开启 EXIT 陷阱
trap finish_trap EXIT

# 2. [关键修复] 捕获 Ctrl+C (INT)
# 立即解除 EXIT 陷阱，防止二次暂停，直接退出当前脚本返回 install.sh
trap 'trap - EXIT; echo -e "\n\033[33m[用户强制终止] 正在返回主菜单...\033[0m"; exit 0' INT
# =======================================================================

# --- [UI 自适应] ---
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')
I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✅" || echo "[ OK ]"); I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "ℹ️ " || echo "[INFO]"); I_WAIT=$([ "$USE_EMOJI" == "1" ] && echo "⏳" || echo "[WAIT]")
I_NET=$([ "$USE_EMOJI" == "1" ] && echo "🌐" || echo "[NET]"); I_WALL=$([ "$USE_EMOJI" == "1" ] && echo "🧱" || echo "[FW]")

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

# --- [鹰眼] 网络侦测 (启动预加载) ---
NET_BANNER=""
init_network_insight() {
    echo -ne "${CYAN}${I_WAIT} 正在进行网络与防火墙态势感知 (约需 3 秒)...${RESET}"
    
    # 1. 内部防火墙
    local fw_status="${GREEN}已关闭 (推荐)${RESET}"
    if command -v ufw >/dev/null && ufw status | grep -q "active"; then fw_status="${YELLOW}UFW 运行中${RESET}"; fi
    if command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then fw_status="${YELLOW}Firewalld 运行中${RESET}"; fi
    if [ $(iptables -L INPUT | wc -l) -gt 10 ]; then fw_status="${YELLOW}Iptables 活跃${RESET}"; fi

    # 2. 出站连通性
    local net_status=""
    if ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then 
        net_status="${GREEN}ICMP${RESET}"
    else 
        net_status="${RED}ICMP(阻断)${RESET}"
    fi
    if curl -s --connect-timeout 2 https://www.baidu.com >/dev/null 2>&1 || curl -s --connect-timeout 2 https://www.google.com >/dev/null 2>&1; then
        net_status="$net_status | ${GREEN}TCP${RESET}"
    else
        net_status="$net_status | ${RED}TCP(阻断)${RESET}"
    fi
    if timeout 2 nslookup google.com 8.8.8.8 >/dev/null 2>&1 || timeout 2 nslookup baidu.com 223.5.5.5 >/dev/null 2>&1; then
        net_status="$net_status | ${GREEN}UDP${RESET}"
    else
        net_status="$net_status | ${RED}UDP(阻断)${RESET}"
    fi

    NET_BANNER="${BLUE}================================================================================${RESET}\n"
    NET_BANNER+="${I_WALL} 内部防火墙: [ $fw_status ]   ${I_NET} 出站连通性: [ $net_status ]\n"
    NET_BANNER+="${GREY}   (提示: 若连通性全红，请检查云厂商控制台的安全组规则)${RESET}"
    echo -e "\r                                                               \r"
}

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

# --- 老旧系统换源 ---
fix_eol_sources() {
    if [ -f /etc/centos-release ]; then
        local ver=$(rpm -q --qf "%{VERSION}" -f /etc/centos-release)
        if [[ "$ver" == "7" ]]; then
            if ! grep -q "vault.centos.org" /etc/yum.repos.d/CentOS-Base.repo 2>/dev/null; then
                ui_info "检测到 CentOS 7 (EOL)，切换至 Vault 源..."
                mkdir -p /etc/yum.repos.d/backup; mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup/ 2>/dev/null
                curl -o /etc/yum.repos.d/CentOS-Base.repo https://raw.githubusercontent.com/hackyo/source/master/CentOS-7-Vault-Aliyun.repo >/dev/null 2>&1
                yum clean all >/dev/null 2>&1; yum makecache >/dev/null 2>&1
            fi
        fi
    fi
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

# --- 双引擎 DNS ---
smart_dns_fix() {
    ui_info "正在启动双引擎 DNS 优化 (Engine: CN/Global)..."
    local loc=$(curl -s --max-time 3 https://www.cloudflare.com/cdn-cgi/trace | grep "loc=" | cut -d= -f2)
    if [ -z "$loc" ]; then
        local cn_ping=$(ping -c 1 -W 1 223.5.5.5 | grep time= | cut -d= -f4 | cut -d. -f1); [ -z "$cn_ping" ] && cn_ping=999
        local global_ping=$(ping -c 1 -W 1 8.8.8.8 | grep time= | cut -d= -f4 | cut -d. -f1); [ -z "$global_ping" ] && global_ping=999
        if [ "$cn_ping" -lt "$global_ping" ]; then loc="CN"; else loc="US"; fi
    fi
    local current_dns=$(cat /etc/resolv.conf)
    local has_cn_dns=0; echo "$current_dns" | grep -qE "223\.5\.5\.5|119\.29\.29\.29|114\.114\.114\.114|180\.76\.76\.76" && has_cn_dns=1
    local has_global_dns=0; echo "$current_dns" | grep -qE "8\.8\.8\.8|1\.1\.1\.1" && has_global_dns=1

    if [ "$loc" == "CN" ]; then
        if [ "$has_cn_dns" -eq 0 ] || [ "$has_global_dns" -eq 1 ]; then
             ui_warn "检测到国内机器使用非优化DNS，切换至国内引擎..."
             echo "nameserver 223.5.5.5" > /etc/resolv.conf; echo "nameserver 119.29.29.29" >> /etc/resolv.conf; ui_ok "DNS 已修正 (Ali/Tencent)。"
        else ui_ok "DNS 配置符合中国地域标准。"; fi
    else
        if [ "$has_cn_dns" -eq 1 ]; then
            ui_warn "检测到海外机器混用中国DNS，切换至全球引擎..."
            echo "nameserver 1.1.1.1" > /etc/resolv.conf; echo "nameserver 8.8.8.8" >> /etc/resolv.conf; ui_ok "DNS 已修正 (CF/Google)。"
        elif [ "$has_global_dns" -eq 0 ]; then
             echo "nameserver 1.1.1.1" > /etc/resolv.conf; echo "nameserver 8.8.8.8" >> /etc/resolv.conf; ui_ok "DNS 已初始化。"
        else ui_ok "DNS 配置符合海外地域标准。"; fi
    fi
}

# --- 智能 Swap ---
check_swap() {
    if [ $(free -m | awk '/^Swap:/ {print $2}') -eq 0 ] && [ $(free -m | awk '/^Mem:/ {print $2}') -lt 4000 ]; then return 1; fi
    return 0
}

# --- 毒瘤清理 ---
clean_cloud_quirks() {
    [ -f /etc/yum/pluginconf.d/subscription-manager.conf ] && sed -i 's/enabled=1/enabled=0/' /etc/yum/pluginconf.d/subscription-manager.conf 2>/dev/null
    if command -v netfilter-persistent >/dev/null; then systemctl is-enabled netfilter-persistent >/dev/null 2>&1 && systemctl start netfilter-persistent >/dev/null 2>&1; fi
}

# --- 全局自愈 ---
heal_environment() {
    ui_info "正在执行环境自愈流程..."
    clean_cloud_quirks
    handle_lock
    fix_eol_sources
    smart_dns_fix
    if command -v apt-get >/dev/null; then ( UCF_FORCE_CONFFOLD=1 dpkg --configure -a && apt-get install -f -y ) >/dev/null 2>&1; elif command -v yum >/dev/null; then yum install -y epel-release >/dev/null 2>&1; fi
    ui_ok "环境准备就绪。"
}

# --- 批量安装 ---
smart_install() {
    local pkgs="$*"
    handle_lock
    ui_info "批量安装组件: $pkgs ..."
    local log="/tmp/install_err.log"
    if command -v apt-get >/dev/null; then
        ( UCF_FORCE_CONFFOLD=1 apt-get install -y $pkgs ) >/dev/null 2>"$log" &
    elif command -v dnf >/dev/null; then
        dnf install -y $pkgs >/dev/null 2>"$log" &
    elif command -v yum >/dev/null; then
        yum install -y $pkgs >/dev/null 2>"$log" &
    else return 1; fi
    local pid=$!; show_spinner "$pid"; wait "$pid"
    [ $? -ne 0 ] && { ui_fail "安装失败，日志:"; tail -n 5 "$log" 2>/dev/null; return 1; }
    rm -f "$log"; return 0
}

# --- 数据定义 (39项全量) ---
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}

add_item() {
    COUNT=$((COUNT+1))
    TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else STATUS[$COUNT]="FAIL"; [ "$5" == "TRUE" ] && SELECTED[$COUNT]="FALSE" || SELECTED[$COUNT]="TRUE"; fi
}

is_eol() { if [ -f /etc/os-release ]; then . /etc/os-release; [[ "$ID" == "debian" && "$VERSION_ID" -lt 10 ]] && return 0; [[ "$ID" == "ubuntu" && "${VERSION_ID%%.*}" -lt 16 ]] && return 0; [[ "$ID" == "centos" && "$VERSION_ID" -lt 7 ]] && return 0; fi; return 1; }

# === [关键补全] 所有项目的优点和风险描述全部填满，无省略 ===
init_audit() {
    # 1. 基础优化
    add_item "开启 TCP BBR 加速" "大幅提升网络吞吐量" "需内核支持 (>=4.9)" "sysctl net.ipv4.tcp_congestion_control | grep -q bbr" "FALSE"
    add_item "系统资源限制优化" "提升系统高并发处理能力" "无" "grep -q 'soft nofile 65535' /etc/security/limits.conf" "FALSE"
    add_item "IPv4 优先策略" "解决 IPv6 连接卡顿超时" "IPv6 流量可能减少" "grep -q 'precedence ::ffff:0:0/96 100' /etc/gai.conf" "FALSE"
    add_item "智能 Swap 分区" "防止内存溢出导致死机" "占用约 1GB 磁盘空间" "check_swap" "FALSE"
    add_item "安装装机必备软件" "预装 curl/vim/htop/git" "占用少量磁盘空间" "command -v vim >/dev/null && command -v htop >/dev/null && command -v unzip >/dev/null" "FALSE"
    add_item "双引擎 DNS 优化" "地域感知加速与防劫持" "无" "grep -q '8.8.8.8' /etc/resolv.conf || grep -q '223.5.5.5' /etc/resolv.conf" "FALSE"

    # 2. SSH 安全
    add_item "强制 SSH 协议 V2" "修复旧版协议严重漏洞" "不支持极古老的客户端" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许使用密钥登录系统" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直接入侵系统" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "避开全网 99% 爆破扫描" "需在防火墙放行新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用 SSH 密码认证" "彻底防御暴力破解攻击" "需预先配置好 SSH 密钥" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 空闲超时(10m)" "防范管理员会话被劫持" "长时间不操作会自动断开" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH Root 登录" "最高级别的账户安全防护" "需创建并使用普通用户" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" "TRUE"
    add_item "SSH 登录 Banner" "显示合规性警告标语" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止通过环境变量提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"

    # 3. 账户安全
    add_item "强制 10 位混合密码" "极大提高暴力破解难度" "修改密码变麻烦" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防止盗号者频繁改密锁号" "7天内无法改回原密码" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "保护离机后的终端安全" "长时间挂机需重连" "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # 4. 权限与文件
    add_item "修正 /etc/passwd" "防止非法修改用户信息" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露密码哈希值" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护 SSH 核心配置文件" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护公钥文件不被篡改" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID" "堵死利用系统指令提权" "普通用户无法使用 ping" "[ ! -u /bin/mount ]" "FALSE"

    # 5. 限制与加固
    add_item "锁定异常 UID=0" "清理潜在的后门账号" "可能误锁自建管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "防止恶意脚本静默提权" "自动化脚本需适配密码" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel" "缩减 Root 切换权限范围" "需将用户加入 wheel 组" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth" "FALSE"
    add_item "限制编译器权限" "防止黑客编译木马病毒" "无" "local g=\$(command -v gcc); [ -z \"\$g\" ] || [ \"\$(stat -c %a \"\$(readlink -f \"\$g\")\")\" == \"700\" ]" "FALSE"
    add_item "扩展 SUID 清理" "宝塔面板推荐的高级加固" "更多系统指令受限" "[ ! -u /usr/bin/wall ]" "FALSE"
    add_item "锁定 Bootloader" "防止物理接触篡改引导" "内核/Grub 更新受影响" "[ \"\$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)\" == \"600\" ]" "FALSE"

    # 6. 内核防御
    add_item "网络内核防欺骗" "防止 ICMP 重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS 洪水攻击" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵罕见网络协议漏洞" "特殊应用可能受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    add_item "禁用非常用文件系统" "宝塔推荐加固 (JFFS2/UDF)" "无" "[ -f /etc/modprobe.d/disable-filesystems.conf ]" "FALSE"
    add_item "记录恶意数据包" "监控 Martian 来源包" "增加系统日志量" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '= 1'" "FALSE"

    # 7. 审计与更新
    add_item "时间同步(Chrony)" "确保日志时间准确可追溯" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防止日志爆满占死磁盘" "减少历史日志保留" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动封禁暴力破解 IP" "误输多次密码也会被封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "每日自动更新组件" "自动打补丁修复漏洞" "软件版本会有微变" "command -v unattended-upgrades || command -v dnf-automatic" "FALSE"
    add_item "立即修复高危漏洞" "立即修复已知 CVE 漏洞" "需保持网络连接畅通" "! is_eol && { dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10; }" "FALSE"
}

apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    
    case "$title" in
        "开启 TCP BBR 加速")
            if uname -r | grep -q "^[5-9]"; then
                echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p >/dev/null 2>&1; ui_ok "BBR 已开启。"
            else ui_fail "内核版本过低 (<4.9)，不支持 BBR。"; fi ;;
        "系统资源限制优化")
            echo "* soft nofile 65535" >> /etc/security/limits.conf; echo "* hard nofile 65535" >> /etc/security/limits.conf; ui_ok "资源限制已优化。" ;;
        "IPv4 优先策略")
            sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf 2>/dev/null; echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf; ui_ok "IPv4 优先已配置。" ;;
        "智能 Swap 分区")
            if check_swap; then ui_ok "无需处理。"; else
                dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; echo "/swapfile none swap sw 0 0" >> /etc/fstab; ui_ok "1GB Swap 已创建。"
            fi ;;
        "安装装机必备软件") smart_install "curl wget vim unzip htop git net-tools" ;;
        "双引擎 DNS 优化") smart_dns_fix ;;
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        
        # [关键修复] SSH 端口修改明确回显
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                if ss -tuln | grep -q ":$T_P "; then ui_warn "端口 $T_P 被占用，请重试"; else p_ok=0; fi
            done
            sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null
            ui_ok "SSH 端口已修改为: ${BOLD}${GREEN}$T_P${RESET} (请牢记!)"
            ;;
            
        "禁用 SSH 密码认证") sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config; echo "PasswordAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "禁止 SSH Root 登录") sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config; echo "PermitRootLogin no" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Restricted Access." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        
        # [关键修复] 智能判断 libpam-pwquality 包名 (Debian vs RHEL)
        "强制 10 位混合密码") 
            if command -v apt-get >/dev/null; then smart_install "libpam-pwquality"
            elif command -v dnf >/dev/null || command -v yum >/dev/null; then smart_install "libpwquality"; fi
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
            local gcc_path=$(command -v gcc); if [ -n "$gcc_path" ]; then local real_path=$(readlink -f "$gcc_path"); chmod 700 "$real_path"; ui_ok "编译器限制完成。"; fi ;;
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
            
        # [关键修复] 智能判断自动更新包名 (Debian vs RHEL)
        "每日自动更新组件") 
            if command -v apt-get >/dev/null; then smart_install "unattended-upgrades"
            elif command -v dnf >/dev/null; then smart_install "dnf-automatic"; systemctl enable --now dnf-automatic.timer; fi ;;
            
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

# --- 核心逻辑调整 ---
init_network_insight
init_audit

while true; do
    clear
    echo -e "$NET_BANNER"
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID | 状态 | 名称${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        if [ "${SELECTED[$i]}" == "TRUE" ]; then S_ICO="${GREEN}[ ON ]${RESET}"; else S_ICO="${GREY}[OFF ]${RESET}"; fi
        if [ "${STATUS[$i]}" == "PASS" ]; then R_ICO="${GREEN}${I_OK}${RESET}"; else R_ICO="${RED}${I_FAIL}${RESET}"; fi
        # [关键修复] 完整打印 PROS 和 RISKS，不再省略
        printf "${GREY}%2d.${RESET} %b %b %-25s ${GREY}[优点: %s] [风险: %s]${RESET}\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}" "${PROS[$i]}" "${RISKS[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; fi
    done
    echo "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行清单: ${GREEN}${SUM_IDS%, }${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始修复 | q=返回 | 输入编号 ID 翻转: "
    read -r ri
    case "$ri" in
        q|Q) 
            # [关键修复] 退出前解除 trap，不再暂停，直接返回主菜单
            trap - EXIT
            exit 0 
            ;; 
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && { MSG="请先勾选！"; continue; }
            if [ "$has_r" == "TRUE" ]; then echo -ne "${RED}含风险项，确认继续? (yes/no): ${RESET}"; read -r c; [ "$c" != "yes" ] && continue; fi
            check_space || continue
            heal_environment
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 已重载。"; }
            
            # [关键修复] 修复完成后解除 trap，使用显式暂停逻辑，用户按键后退出
            trap - EXIT
            echo -ne "\n${YELLOW}【重要】流程执行完毕。按任意键返回主菜单...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do 
            if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ]; then
                if [ "${SELECTED[$n]}" == "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
            fi
        done ;;
    esac
done
