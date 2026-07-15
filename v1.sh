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

# --- [鹰眼] 网络侦测 (缺工具时降级为未检测) ---
NET_BANNER=""
init_network_insight() {
    echo -ne "${CYAN}${I_WAIT} 正在进行网络与防火墙态势感知 (约需 3 秒)...${RESET}"
    local fw_status="${GREEN}未检测到活动防火墙${RESET}"
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "active"; then fw_status="${YELLOW}UFW 运行中${RESET}"; fi
    if command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then fw_status="${YELLOW}Firewalld 运行中${RESET}"; fi
    if command -v iptables >/dev/null && [ "$(iptables -L INPUT 2>/dev/null | wc -l)" -gt 10 ]; then fw_status="${YELLOW}Iptables 活跃${RESET}"; fi

    local icmp_status tcp_status dns_status
    if command -v ping >/dev/null 2>&1; then
        if ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then icmp_status="${GREEN}ICMP${RESET}"; else icmp_status="${RED}ICMP(阻断)${RESET}"; fi
    else icmp_status="${GREY}ICMP(未检测: 缺少 ping)${RESET}"; fi

    if command -v curl >/dev/null 2>&1; then
        if curl -s --connect-timeout 2 https://www.baidu.com >/dev/null 2>&1 || curl -s --connect-timeout 2 https://www.google.com >/dev/null 2>&1; then tcp_status="${GREEN}TCP${RESET}"; else tcp_status="${RED}TCP(阻断)${RESET}"; fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --spider --timeout=2 https://www.baidu.com >/dev/null 2>&1 || wget -q --spider --timeout=2 https://www.google.com >/dev/null 2>&1; then tcp_status="${GREEN}TCP${RESET}"; else tcp_status="${RED}TCP(阻断)${RESET}"; fi
    else tcp_status="${GREY}TCP(未检测: 缺少 curl/wget)${RESET}"; fi

    if command -v nslookup >/dev/null 2>&1; then
        if timeout 2 nslookup google.com 8.8.8.8 >/dev/null 2>&1 || timeout 2 nslookup baidu.com 223.5.5.5 >/dev/null 2>&1; then dns_status="${GREEN}DNS${RESET}"; else dns_status="${RED}DNS(阻断)${RESET}"; fi
    else dns_status="${GREY}DNS(未检测: 缺少 nslookup)${RESET}"; fi

    NET_BANNER="${BLUE}================================================================================${RESET}\n"
    NET_BANNER+="${I_WALL} 内部防火墙: [ $fw_status ]   ${I_NET} 出站: [ $icmp_status | $tcp_status | $dns_status ]\n"
    NET_BANNER+="${GREY}   (提示: 未检测不等于失败，可先安装基础工具后重新运行)${RESET}"
    echo -e "\r                                                               \r"
}

# --- 智能锁管理 ---
lock_busy() {
    local lock="$1"
    [ -f "$lock" ] || return 1
    if command -v fuser >/dev/null 2>&1; then fuser "$lock" >/dev/null 2>&1; else return 0; fi
}

handle_lock() {
    local locks=("/var/lib/dpkg/lock-frontend" "/var/lib/dpkg/lock" "/var/lib/apt/lists/lock")
    local locked="" lock
    for lock in "${locks[@]}"; do if lock_busy "$lock"; then locked="$lock"; break; fi; done
    [ -z "$locked" ] && return 0
    ui_warn "检测到包管理器锁: $locked"
    command -v fuser >/dev/null 2>&1 || ui_warn "缺少 fuser(psmisc)，无法识别锁持有进程，将仅等待锁文件状态。"
    local count=0
    while lock_busy "$locked" && [ "$count" -lt 30 ]; do sleep 1; count=$((count+1)); done
    if lock_busy "$locked"; then ui_fail "包管理器仍被占用，请稍后重试或手动检查 apt/dpkg 进程。"; return 1; fi
    command -v dpkg >/dev/null 2>&1 && dpkg --configure -a >/dev/null 2>&1
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
    if apt-get -o Acquire::Retries=2 update >/tmp/sec_toolbox_apt_update.log 2>&1; then ui_ok "APT 软件源优化完成。"; APT_UPDATED=1; return 0; fi
    ui_fail "新软件源验证失败，正在恢复备份..."
    restore_apt_sources "$backup"
    apt-get -o Acquire::Retries=2 update >/dev/null 2>&1 || true
    return 1
}

apt_update_once() {
    [ "$APT_UPDATED" -eq 1 ] && return 0
    handle_lock || return 1
    ui_info "正在刷新 APT 索引..."
    if apt-get -o Acquire::Retries=2 update >/tmp/sec_toolbox_apt_update.log 2>&1; then APT_UPDATED=1; return 0; fi
    ui_warn "APT 索引刷新失败，尝试自动优化软件源..."
    apply_apt_mirror_auto || { ui_fail "APT 源优化失败。日志:"; tail -n 8 /tmp/sec_toolbox_apt_update.log 2>/dev/null; return 1; }
    return 0
}

# --- 安全环境预检 ---
heal_environment() {
    ui_info "正在执行环境预检..."
    load_os_release
    handle_lock || return 1
    if command -v dpkg >/dev/null 2>&1; then UCF_FORCE_CONFFOLD=1 dpkg --configure -a >/dev/null 2>&1 || return 1; fi
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
    local mapped log pid
    mapped=$(map_packages "$@")
    ui_info "批量安装组件:$mapped ..."
    log=$(mktemp /tmp/sec_toolbox_install.XXXXXX)
    if command -v apt-get >/dev/null 2>&1; then
        apt_update_once || { rm -f "$log"; return 1; }
        ( UCF_FORCE_CONFFOLD=1 apt-get install -y $mapped ) >/dev/null 2>"$log" &
    elif command -v dnf >/dev/null 2>&1; then
        make_cache_once; dnf install -y $mapped >/dev/null 2>"$log" &
    elif command -v yum >/dev/null 2>&1; then
        make_cache_once; yum install -y $mapped >/dev/null 2>"$log" &
    else ui_fail "未找到支持的包管理器。"; rm -f "$log"; return 1; fi
    pid=$!; show_spinner "$pid"; wait "$pid"
    if [ $? -ne 0 ]; then
        if command -v apt-get >/dev/null 2>&1 && echo "$mapped" | grep -qw dnsutils; then
            ui_warn "dnsutils 安装失败，尝试 bind9-dnsutils 兼容包..."
            mapped=$(echo "$mapped" | sed 's/\bdnsutils\b/bind9-dnsutils/g')
            ( UCF_FORCE_CONFFOLD=1 apt-get install -y $mapped ) >/dev/null 2>"$log" &
            pid=$!; show_spinner "$pid"; wait "$pid" && { rm -f "$log"; return 0; }
        fi
        ui_fail "安装失败，日志:"
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
