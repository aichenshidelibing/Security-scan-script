#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v41.0)

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$SCRIPT_DIR/lib/runtime.sh" ] && [ -f "$SCRIPT_DIR/lib/network_checks.sh" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/lib/runtime.sh"
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/lib/network_checks.sh"
else
    echo "[error] lib/runtime.sh and lib/network_checks.sh are required; run install.sh to refresh the toolbox." >&2
    exit 1
fi
sec_toolbox_acquire_lock "v1.sh" || exit 75

# =======================================================================
# [核心交互修复] 信号管理
# =======================================================================
# 1. 正常退出时的逻辑 (当脚本自然结束时)
finish_trap() {
    sec_toolbox_release_lock
    echo -e "\n\033[33m[system] script finished. press Enter to continue...\033[0m"
    [ -t 0 ] && read -r || true
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
I_FIX=$([ "$USE_EMOJI" == "1" ] && echo "🛠️ " || echo "[FIX]"); I_LIST=$([ "$USE_EMOJI" == "1" ] && echo "📋" || echo "[LIST]")

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

check_space() { [ "$(df / | awk 'NR==2 {print $4}')" -lt 204800 ] && { ui_fail "磁盘不足 200MB，停止。"; return 1; }; return 0; }

# --- 系统与网络辅助 ---
OS_ID=""; OS_VERSION_ID=""; OS_CODENAME=""; OS_ID_LIKE=""; APT_UPDATED=0; YUM_CACHED=0

load_os_release() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_VERSION_ID="${VERSION_ID:-}"
        OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
        OS_ID_LIKE="${ID_LIKE:-}"
    fi
}

is_debian_like() { [[ "$OS_ID $OS_ID_LIKE" =~ debian|ubuntu ]]; }

# --- [network insight] IPv4/IPv6 aware diagnostics ---
NET_BANNER=""
init_network_insight() {
    echo -ne "${CYAN}${I_WAIT} network and firewall insight (about 3 seconds)...${RESET}"
    local fw_status="${GREEN}no active firewall detected${RESET}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then fw_status="${YELLOW}UFW active${RESET}"; fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then fw_status="${YELLOW}Firewalld active${RESET}"; fi
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then fw_status="${YELLOW}nftables active${RESET}"; fi
    if command -v iptables >/dev/null 2>&1 && iptables -S >/dev/null 2>&1; then fw_status="${YELLOW}iptables active${RESET}"; fi

    local ip_mode icmp_raw dns_raw tcp_raw
    ip_mode=$(sec_detect_ip_mode)
    icmp_raw=$(sec_probe_icmp "$ip_mode")
    dns_raw=$(sec_probe_dns)
    tcp_raw=$(sec_probe_tcp "$ip_mode")
    local icmp_status="$(sec_network_label "$icmp_raw")"
    local dns_status="$(sec_network_label "$dns_raw")"
    local tcp_status="$(sec_network_label "$tcp_raw")"

    NET_BANNER="${BLUE}================================================================================${RESET}\n"
    NET_BANNER+="${I_WALL} firewall: [ $fw_status ]   ${I_NET} network stack: [ ${ip_mode} ]\n"
    NET_BANNER+="${GREY}   outbound probes: ICMP=[ $icmp_status ] | TCP=[ $tcp_status ] | DNS=[ $dns_status ]${RESET}\n"
    NET_BANNER+="${GREY}   probe failures may mean upstream policy, no route, an unresponsive target, or missing tools; they are not automatically local blocks.${RESET}"
    echo -e "\r                                                               \r"
}

# --- package-manager lock management ---
lock_busy() { sec_package_manager_busy; }
handle_lock() {
    sec_wait_for_package_manager "${SEC_TOOLBOX_PACKAGE_WAIT:-90}" || {
        ui_fail "apt/dpkg/dnf/yum is still running; retry later and do not delete lock files."
        return 1
    }
    return 0
}

# --- APT 源自动优化 ---
detect_apt_codename() {
    [ -n "$OS_CODENAME" ] && { echo "$OS_CODENAME"; return 0; }
    if command -v lsb_release >/dev/null 2>&1; then lsb_release -cs 2>/dev/null && return 0; fi
    if [ "$OS_ID" = "debian" ] && [ -f /etc/debian_version ]; then
        case "$(cut -d. -f1 /etc/debian_version)" in 13) echo trixie;; 12) echo bookworm;; 11) echo bullseye;; 10) echo buster;; *) return 1;; esac
        return 0
    fi
    return 1
}

is_china_network() {
    command -v curl >/dev/null 2>&1 || return 1
    curl -s --connect-timeout 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q '^loc=CN$'
}

mirror_time() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then curl -L --connect-timeout 2 --max-time 5 -o /dev/null -w '%{time_total}' "$url" 2>/dev/null || echo 999; else echo 999; fi
}

pick_fastest_mirror() {
    local codename="$1" best="" best_time="999" m t rel="dists/${codename}/Release"
    shift
    for m in "$@"; do
        t=$(mirror_time "${m%/}/$rel")
        awk "BEGIN{exit !($t < $best_time)}" && { best_time="$t"; best="$m"; }
    done
    echo "$best"
}

backup_apt_sources() {
    local dir="/etc/apt/sec_toolbox_sources_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$dir"
    [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list "$dir/sources.list"
    echo "$dir"
}

restore_apt_sources() { local dir="$1"; [ -f "$dir/sources.list" ] && cp -a "$dir/sources.list" /etc/apt/sources.list; }

write_debian_sources() {
    local codename="$1" mirror="$2" comps="main contrib non-free"
    case "$codename" in bookworm|trixie) comps="main contrib non-free non-free-firmware" ;; esac
    cat > /etc/apt/sources.list <<EOF
# Generated by Linux Security Toolbox. Backup is stored under /etc/apt/sec_toolbox_sources_backup_*
deb ${mirror} ${codename} ${comps}
deb ${mirror} ${codename}-updates ${comps}
deb https://deb.debian.org/debian ${codename} ${comps}
deb https://security.debian.org/debian-security ${codename}-security ${comps}
EOF
}

write_ubuntu_sources() {
    local codename="$1" mirror="$2" comps="main restricted universe multiverse"
    cat > /etc/apt/sources.list <<EOF
# Generated by Linux Security Toolbox. Backup is stored under /etc/apt/sec_toolbox_sources_backup_*
deb ${mirror} ${codename} ${comps}
deb ${mirror} ${codename}-updates ${comps}
deb ${mirror} ${codename}-backports ${comps}
deb https://archive.ubuntu.com/ubuntu ${codename} ${comps}
deb https://security.ubuntu.com/ubuntu ${codename}-security ${comps}
EOF
}

apply_apt_mirror_auto() {
    command -v apt-get >/dev/null 2>&1 || { ui_warn "非 APT 系统，跳过软件源优化。"; return 0; }
    load_os_release
    is_debian_like || { ui_warn "当前发行版不是 Debian/Ubuntu 系，跳过软件源优化。"; return 0; }
    local codename backup mirror
    codename=$(detect_apt_codename) || { ui_warn "无法识别发行版代号，跳过换源。"; return 1; }
    backup=$(backup_apt_sources)
    if [ "$OS_ID" = "ubuntu" ]; then
        if is_china_network; then mirror=$(pick_fastest_mirror "$codename" "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/" "https://mirrors.ustc.edu.cn/ubuntu/" "https://mirrors.aliyun.com/ubuntu/"); else mirror="https://archive.ubuntu.com/ubuntu/"; fi
        [ -z "$mirror" ] && mirror="https://archive.ubuntu.com/ubuntu/"
        write_ubuntu_sources "$codename" "$mirror"
    else
        if is_china_network; then mirror=$(pick_fastest_mirror "$codename" "https://mirrors.tuna.tsinghua.edu.cn/debian/" "https://mirrors.ustc.edu.cn/debian/" "https://mirrors.aliyun.com/debian/"); else mirror="https://deb.debian.org/debian/"; fi
        [ -z "$mirror" ] && mirror="https://deb.debian.org/debian/"
        write_debian_sources "$codename" "$mirror"
    fi
    ui_info "已选择软件源: $mirror，并保留官方源兜底。备份: $backup"
    if sec_with_package_manager_lock apt-get -o Acquire::Retries=2 update >/tmp/sec_toolbox_apt_update.log 2>&1; then ui_ok "APT 软件源优化完成。"; APT_UPDATED=1; return 0; fi
    ui_fail "新软件源验证失败，正在恢复备份..."
    restore_apt_sources "$backup"
    sec_with_package_manager_lock apt-get -o Acquire::Retries=2 update >/dev/null 2>&1 || true
    return 1
}

apt_update_once() {
    [ "$APT_UPDATED" -eq 1 ] && return 0
    handle_lock || return 1
    ui_info "正在刷新 APT 索引..."
    if sec_with_package_manager_lock apt-get -o Acquire::Retries=2 update >/tmp/sec_toolbox_apt_update.log 2>&1; then APT_UPDATED=1; return 0; fi
    ui_warn "APT 索引刷新失败，尝试自动优化软件源..."
    apply_apt_mirror_auto || { ui_fail "APT 源优化失败。日志:"; tail -n 8 /tmp/sec_toolbox_apt_update.log 2>/dev/null; return 1; }
    return 0
}

# --- 安全环境预检 ---
heal_environment() {
    ui_info "正在执行环境预检..."
    load_os_release
    handle_lock || return 1
    if command -v dpkg >/dev/null 2>&1; then sec_with_package_manager_lock env UCF_FORCE_CONFFOLD=1 dpkg --configure -a >/dev/null 2>&1 || return 1; fi
    ui_ok "环境准备就绪。"
}

map_package() {
    local pkg="$1"
    if command -v apt-get >/dev/null 2>&1; then
        case "$pkg" in fuser) echo psmisc;; ping) echo iputils-ping;; nslookup) echo dnsutils;; ss) echo iproute2;; netstat) echo net-tools;; *) echo "$pkg";; esac
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        case "$pkg" in fuser) echo psmisc;; ping) echo iputils;; nslookup) echo bind-utils;; ss) echo iproute;; netstat) echo net-tools;; *) echo "$pkg";; esac
    else echo "$pkg"; fi
}

map_packages() {
    local out="" p mapped
    for p in "$@"; do mapped=$(map_package "$p"); case " $out " in *" $mapped "*) ;; *) out="$out $mapped";; esac; done
    echo "$out"
}

make_cache_once() {
    [ "$YUM_CACHED" -eq 1 ] && return 0
    command -v dnf >/dev/null 2>&1 && dnf makecache -y >/dev/null 2>&1 || true
    command -v yum >/dev/null 2>&1 && yum makecache -y >/dev/null 2>&1 || true
    YUM_CACHED=1
}

# --- 批量安装 ---
smart_install() {
    load_os_release
    handle_lock || return 1
    local mapped log status
    mapped=$(map_packages "$@")
    ui_info "installing packages:$mapped ..."
    log=$(mktemp /tmp/sec_toolbox_install.XXXXXX)
    if command -v apt-get >/dev/null 2>&1; then
        apt_update_once || { rm -f "$log"; return 1; }
        sec_with_package_manager_lock env UCF_FORCE_CONFFOLD=1 apt-get install -y $mapped >/dev/null 2>"$log"
        status=$?
    elif command -v dnf >/dev/null 2>&1; then
        make_cache_once
        sec_with_package_manager_lock dnf install -y $mapped >/dev/null 2>"$log"
        status=$?
    elif command -v yum >/dev/null 2>&1; then
        make_cache_once
        sec_with_package_manager_lock yum install -y $mapped >/dev/null 2>"$log"
        status=$?
    else
        ui_fail "no supported package manager found."
        rm -f "$log"
        return 1
    fi
    if [ "$status" -ne 0 ] && command -v apt-get >/dev/null 2>&1 && printf '%s\n' "$mapped" | grep -qw dnsutils; then
        ui_warn "dnsutils install failed; trying bind9-dnsutils compatibility package..."
        mapped=$(printf '%s\n' "$mapped" | sed 's/\<dnsutils\>/bind9-dnsutils/g')
        sec_with_package_manager_lock env UCF_FORCE_CONFFOLD=1 apt-get install -y $mapped >/dev/null 2>"$log"
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        ui_fail "package install failed; last log lines:"
        tail -n 8 "$log" 2>/dev/null
        rm -f "$log"
        return 1
    fi
    rm -f "$log"
    return 0
}

# --- 数据定义 (安全精简版) ---
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    CUR_P=$(grep -E "^[[:space:]]*Port" "$SSHD_CONFIG" | awk '{print $2}' | tail -n 1)
else
    CUR_P=22
fi
CUR_P=${CUR_P:-22}

has_sshd_config() { [ -f "$SSHD_CONFIG" ]; }
bbr_available() { modprobe tcp_bbr >/dev/null 2>&1 || sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; }

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
    add_item "自动优化 APT 软件源" "根据网络自动选择镜像并保留官方源" "会备份并改写 /etc/apt/sources.list" "[ ! -f /etc/apt/sources.list ] || grep -q 'sec_toolbox_sources_backup' /etc/apt/sources.list" "FALSE"
    add_item "开启 TCP BBR 加速" "提升部分网络场景吞吐" "需内核支持 tcp_bbr" "sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qw bbr" "FALSE"
    add_item "系统资源限制优化" "提升系统高并发处理能力" "无" "grep -q 'soft nofile 65535' /etc/security/limits.conf" "FALSE"
    add_item "安装装机必备软件" "预装 curl/wget/vim/git/网络诊断工具" "占用少量磁盘空间" "command -v curl >/dev/null && command -v wget >/dev/null && command -v vim >/dev/null && command -v git >/dev/null && command -v ping >/dev/null && command -v nslookup >/dev/null" "FALSE"

    # 2. SSH 安全（仅保留低锁死风险项；关闭密码/Root 登录请使用 v2.sh 手动确认流程）
    add_item "开启公钥认证支持" "允许使用密钥登录系统" "无" "has_sshd_config && grep -q '^PubkeyAuthentication yes' \"$SSHD_CONFIG\"" "FALSE"
    add_item "禁止 SSH 空密码" "防止远程直接入侵系统" "无" "has_sshd_config && grep -q '^PermitEmptyPasswords no' \"$SSHD_CONFIG\"" "FALSE"
    add_item "SSH 空闲超时(10m)" "防范管理员会话被劫持" "长时间不操作会自动断开" "has_sshd_config && grep -q '^ClientAliveInterval 600' \"$SSHD_CONFIG\"" "FALSE"
    add_item "SSH 登录 Banner" "显示合规性警告标语" "无" "has_sshd_config && grep -q '^Banner' \"$SSHD_CONFIG\"" "FALSE"
    add_item "禁止环境篡改" "防止通过环境变量提权" "无" "has_sshd_config && grep -q '^PermitUserEnvironment no' \"$SSHD_CONFIG\"" "FALSE"

    # 3. 账户安全

    # 4. 权限与文件
    add_item "修正 /etc/passwd" "防止非法修改用户信息" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露密码哈希值" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "保护 SSH 核心配置文件" "无" "has_sshd_config && [ \"\$(stat -c %a \"$SSHD_CONFIG\")\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护公钥文件不被篡改" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"

    # 5. 限制与加固

    # 6. 内核防御
    add_item "网络内核防欺骗" "防止 ICMP 重定向攻击" "无" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS 洪水攻击" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "记录恶意数据包" "监控 Martian 来源包" "增加系统日志量" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '= 1'" "FALSE"

    # 7. 审计与更新
    add_item "时间同步(Chrony)" "确保日志时间准确可追溯" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防止日志爆满占死磁盘" "减少历史日志保留" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf" "FALSE"
    add_item "Fail2ban 最佳防护" "自动封禁暴力破解 IP" "误输多次密码也会被封" "command -v fail2ban-server >/dev/null" "FALSE"
}

apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"

    case "$title" in
        "开启公钥认证支持"|"禁止 SSH 空密码"|"SSH 空闲超时(10m)"|"SSH 登录 Banner"|"禁止环境篡改"|"修正 sshd_config")
            if ! has_sshd_config; then
                ui_warn "未找到 $SSHD_CONFIG，已跳过该 SSH 项。"
                return 0
            fi
            ;;
    esac

    case "$title" in
        "自动优化 APT 软件源") apply_apt_mirror_auto ;;
        "开启 TCP BBR 加速")
            if bbr_available; then
                sed -i '/^net.core.default_qdisc=/d;/^net.ipv4.tcp_congestion_control=/d' /etc/sysctl.conf
                echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
                sysctl -p >/dev/null 2>&1
                ui_ok "BBR 已开启。"
            else
                ui_fail "当前内核未提供 tcp_bbr，已跳过。"
            fi ;;
        "系统资源限制优化")
            echo "* soft nofile 65535" >> /etc/security/limits.conf; echo "* hard nofile 65535" >> /etc/security/limits.conf; ui_ok "资源限制已优化。" ;;
        "安装装机必备软件") smart_install curl wget vim unzip htop git netstat fuser ping nslookup ss ca-certificates gnupg ;;
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' "$SSHD_CONFIG"; echo "Protocol 2" >> "$SSHD_CONFIG" ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' "$SSHD_CONFIG"; echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG" ;;
        "禁止 SSH 空密码") sed -i '/^PermitEmptyPasswords/d' "$SSHD_CONFIG"; echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG" ;;
        
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' "$SSHD_CONFIG"; echo "ClientAliveInterval 600" >> "$SSHD_CONFIG" ;;
        "SSH 登录 Banner") echo "Restricted Access." > /etc/ssh/banner_warn; sed -i '/^Banner/d' "$SSHD_CONFIG"; echo "Banner /etc/ssh/banner_warn" >> "$SSHD_CONFIG" ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' "$SSHD_CONFIG"; echo "PermitUserEnvironment no" >> "$SSHD_CONFIG" ;;
        
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 "$SSHD_CONFIG" ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "记录恶意数据包") sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1 ;;
        "时间同步(Chrony)") smart_install chrony && { systemctl enable --now chronyd >/dev/null 2>&1 || systemctl enable --now chrony >/dev/null 2>&1; } ;;
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
            heal_environment || { MSG="环境准备失败，请稍后重试。"; continue; }
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
