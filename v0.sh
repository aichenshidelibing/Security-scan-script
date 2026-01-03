#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v0.sh - Linux 全维安全审计系统 (v2.1 交互体验完美版)
# 特性：36项全量检测 | 硬件仪表盘 | 可视化评分 | 完美衔接主控台

export LC_ALL=C

# --- [UI 自适应] ---
if [ "${USE_EMOJI:-}" == "" ]; then
    [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]] && USE_EMOJI="1" || USE_EMOJI="0"
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); WHITE=$(printf '\033[37m'); 
RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_PASS="✅"; I_FAIL="❌"; I_WARN="⚠️ "; I_INFO="ℹ️ "; I_SYS="🖥️ "; I_SCAN="🔍"
else
    I_PASS="[PASS]"; I_FAIL="[FAIL]"; I_WARN="[WARN]"; I_INFO="[INFO]"; I_SYS="[SYS]"; I_SCAN="[SCAN]"
fi

# =======================================================================
# [核心防闪退] 仅在异常退出/中断时触发，正常返回不触发
# =======================================================================
trap_triggered=0
finish_trap() {
    [ "$trap_triggered" -eq 1 ] && return # 如果已正常处理，不再触发
    echo -e "\n\033[33m[系统提示] 审计被中断。按回车键返回...\033[0m"
    read -r
}
trap finish_trap EXIT INT
# =======================================================================

# --- 辅助功能 ---
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }
ui_line()   { echo -e "${GREY}--------------------------------------------------------------------------------${RESET}"; }

# 进度条
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

# --- 1. 系统硬件信息仪表盘 ---
get_sys_info() {
    # CPU
    local cpu_model=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^[ \t]*//')
    local cpu_cores=$(grep -c "processor" /proc/cpuinfo)
    # 内存
    local mem_total=$(free -h | awk '/^Mem:/ {print $2}')
    local mem_used=$(free -h | awk '/^Mem:/ {print $3}')
    local mem_type=""
    if command -v dmidecode >/dev/null; then
        mem_type=$(dmidecode -t memory 2>/dev/null | grep "Type:" | head -1 | awk '{print $2}')
        [ -n "$mem_type" ] && mem_type="($mem_type)"
    fi
    # 磁盘
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')
    # 系统
    local os_info=""; [ -f /etc/os-release ] && os_info=$(grep "^PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"') || os_info=$(cat /etc/issue | head -n 1)
    local kernel=$(uname -r)
    local uptime=$(uptime -p | sed 's/up //')

    echo -e "${BOLD}${PURPLE}${I_SYS} 系统基本信息仪表盘${RESET}"
    ui_header
    printf " %-12s: ${WHITE}%s${RESET}\n" "操作系统" "$os_info"
    printf " %-12s: ${WHITE}%s${RESET}\n" "内核版本" "$kernel"
    printf " %-12s: ${WHITE}%s (x%s)${RESET}\n" "CPU型号" "${cpu_model:0:40}..." "$cpu_cores"
    printf " %-12s: ${WHITE}%s / %s %s${RESET}\n" "内存状态" "$mem_used" "$mem_total" "$mem_type"
    printf " %-12s: ${WHITE}%s (共 %s)${RESET}\n" "磁盘占用" "$disk_usage" "$disk_total"
    printf " %-12s: ${WHITE}%s${RESET}\n" "运行时间" "$uptime"
    ui_header
    echo ""
}

# --- 2. 审计规则定义 (36项全量对齐) ---
declare -a CAT TITLES DESC SUGGEST LEVEL STATUS
COUNT=0
SCORE=100

add_audit() {
    COUNT=$((COUNT+1))
    CAT[$COUNT]="$1"; TITLES[$COUNT]="$2"; DESC[$COUNT]="$3"; SUGGEST[$COUNT]="$4"; LEVEL[$COUNT]="$5"
    if eval "$6"; then
        STATUS[$COUNT]="PASS"
    else
        STATUS[$COUNT]="FAIL"
        case "$5" in
            "high") SCORE=$((SCORE-5)) ;; "mid") SCORE=$((SCORE-3)) ;; "low") SCORE=$((SCORE-1)) ;;
        esac
    fi
}

# 辅助检测
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}
check_gcc() { local g=$(command -v gcc); [ -z "$g" ] || [ "$(stat -c %a "$(readlink -f "$g")")" == "700" ]; }
is_eol() { if [ -f /etc/os-release ]; then . /etc/os-release; [[ "$ID" == "debian" && "$VERSION_ID" -lt 10 ]] && return 0; [[ "$ID" == "ubuntu" && "${VERSION_ID%%.*}" -lt 16 ]] && return 0; [[ "$ID" == "centos" && "$VERSION_ID" -lt 7 ]] && return 0; fi; return 1; }

run_audits() {
    # 1. 基础
    add_audit "基础" "TCP BBR" "检测 BBR 加速" "建议开启以提升网速" "low" "sysctl net.ipv4.tcp_congestion_control | grep -q bbr"
    add_audit "基础" "必备软件" "检测常用工具" "建议安装 curl/wget/vim 等" "info" "command -v vim >/dev/null && command -v htop >/dev/null"
    add_audit "基础" "DNS设置" "检测公共 DNS" "建议优化 DNS (8.8.8.8等)" "info" "grep -q '8.8.8.8' /etc/resolv.conf || grep -q '223.5.5.5' /etc/resolv.conf"

    # 2. SSH
    add_audit "SSH" "协议版本" "检测 Protocol 2" "必须强制使用 V2 协议" "high" "grep -q '^Protocol 2' /etc/ssh/sshd_config"
    add_audit "SSH" "公钥认证" "检测 Pubkey" "建议开启密钥登录" "info" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config"
    add_audit "SSH" "空密码" "检测 EmptyPasswords" "必须禁止空密码" "high" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config"
    add_audit "SSH" "默认端口" "检测 Port 22" "建议修改高位端口" "mid" "[ \"$CUR_P\" != \"22\" ]"
    add_audit "SSH" "密码认证" "检测 PasswordAuth" "建议关闭密码认证" "mid" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"
    add_audit "SSH" "连接超时" "检测 ClientAlive" "建议设置 600s 超时" "low" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config"
    add_audit "SSH" "Root登录" "检测 RootLogin" "建议禁止 Root 登录" "high" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
    add_audit "SSH" "登录警告" "检测 Banner" "建议设置警告标语" "info" "grep -q '^Banner' /etc/ssh/sshd_config"
    add_audit "SSH" "环境篡改" "检测 UserEnvironment" "必须禁止环境篡改" "mid" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config"

    # 3. 账户
    add_audit "账户" "密码强度" "检测 minlen=10" "建议强制 10 位混合密码" "mid" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null"
    add_audit "账户" "修改间隔" "检测 PASS_MIN_DAYS" "建议设置 7 天最小间隔" "low" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs"
    add_audit "账户" "自动注销" "检测 Shell TMOUT" "建议设置终端 600s 超时" "low" "grep -q 'TMOUT=600' /etc/profile"

    # 4. 权限
    add_audit "权限" "Passwd" "检测 passwd 644" "权限应为 644" "high" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]"
    add_audit "权限" "Shadow" "检测 shadow 600" "权限应为 600" "high" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]"
    add_audit "权限" "SSH配置" "检测 sshd_config 600" "权限应为 600" "high" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]"
    add_audit "权限" "AuthKeys" "检测 authorized_keys 600" "权限应为 600" "high" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]"
    add_audit "权限" "SUID清理" "检测 ping/mount" "建议移除不必要的 SUID" "low" "[ ! -u /bin/mount ]"

    # 5. 限制
    add_audit "限制" "异常Root" "检测 UID=0 非Root" "必须清理后门账户" "high" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]"
    add_audit "限制" "Sudo免密" "检测 NOPASSWD" "禁止 sudo 免密" "high" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1"
    add_audit "限制" "Su Wheel" "检测 su 组" "建议只允许 wheel 组切 Root" "mid" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth"
    add_audit "限制" "编译器" "检测 gcc 权限" "建议限制 gcc 为 700" "mid" "check_gcc"
    add_audit "限制" "扩展SUID" "检测 wall/chage" "建议移除扩展 SUID" "low" "[ ! -u /usr/bin/wall ]"
    add_audit "限制" "Bootloader" "检测 grub.cfg" "建议权限设为 600" "low" "[ \"\$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)\" == \"600\" ]"

    # 6. 内核
    add_audit "内核" "ICMP重定向" "检测 accept_redirects" "建议禁用防攻击" "mid" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'"
    add_audit "内核" "SYN Cookie" "检测 tcp_syncookies" "建议开启防 DDoS" "mid" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'"
    add_audit "内核" "高危协议" "检测 dccp/sctp" "建议禁用不常用协议" "low" "[ -f /etc/modprobe.d/disable-uncommon.conf ]"
    add_audit "内核" "文件系统" "检测 JFFS2/UDF" "建议禁用生僻文件系统" "low" "[ -f /etc/modprobe.d/disable-filesystems.conf ]"
    add_audit "内核" "恶意包日志" "检测 log_martians" "建议开启恶意包记录" "low" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '= 1'"

    # 7. 审计
    add_audit "审计" "时间同步" "检测 Chrony/NTP" "必须保证日志时间准确" "mid" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd"
    add_audit "审计" "日志轮转" "检测 Journald MaxUse" "建议限制日志大小" "low" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf"
    add_audit "防御" "Fail2ban" "检测 Fail2ban" "强烈建议安装防爆破" "high" "command -v fail2ban-server >/dev/null"
    add_audit "更新" "自动更新" "检测 自动更新服务" "建议开启每日自动补丁" "mid" "command -v unattended-upgrades >/dev/null || systemctl is-active --quiet dnf-automatic.timer"
    add_audit "更新" "漏洞补丁" "检测 dpkg 版本" "建议升级到安全版本" "high" "! is_eol && { dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10; }"
}

# --- 3. 打印报告 ---
print_report() {
    echo -ne "${CYAN}${I_SCAN} 正在进行全维深度扫描... ${RESET}"
    sleep 1 & show_spinner $!
    echo ""
    
    printf "${BOLD}%-4s %-6s %-20s %-8s %-10s${RESET}\n" "ID" "类别" "检测项" "权重" "结果"
    ui_line

    for ((i=1; i<=COUNT; i++)); do
        case "${LEVEL[$i]}" in
            "high") L_TXT="${RED}高危${RESET}";;
            "mid")  L_TXT="${YELLOW}中危${RESET}";;
            "low")  L_TXT="${BLUE}低危${RESET}";;
            "info") L_TXT="${GREY}提示${RESET}";;
        esac
        [ "${STATUS[$i]}" == "PASS" ] && RES_ICON="${GREEN}${I_PASS}${RESET}" || RES_ICON="${RED}${I_FAIL}${RESET}"
        printf "%-4s %-6s %-20s %-16s %b\n" "$i" "${CAT[$i]}" "${TITLES[$i]}" "$L_TXT" "$RES_ICON"
        
        # 失败项详情
        if [ "${STATUS[$i]}" == "FAIL" ] && [ "${LEVEL[$i]}" != "info" ]; then
            echo -e "    ${GREY}└─ 建议: ${SUGGEST[$i]}${RESET}"
        fi
    done
    ui_header
    
    # 评分逻辑
    local bar_len=$((SCORE / 10)); local bar_str=""
    for ((b=0; b<10; b++)); do [ $b -lt $bar_len ] && bar_str="${bar_str}#" || bar_str="${bar_str}-"; done
    if [ $SCORE -ge 90 ]; then S_COLOR="$GREEN"; MSG="系统非常安全 (Excellent)"; 
    elif [ $SCORE -ge 70 ]; then S_COLOR="$YELLOW"; MSG="存在安全风险 (Warning)"; 
    else S_COLOR="$RED"; MSG="存在严重隐患 (Dangerous)"; fi
    
    echo -e "安全评分: [${S_COLOR}${bar_str}${RESET}] ${S_COLOR}${BOLD}$SCORE 分${RESET}"
    echo -e "评估结论: $MSG"
    
    [ $SCORE -lt 100 ] && echo -e "\n${YELLOW}${I_WARN} 发现风险项！请运行 ${CYAN}v1.sh${YELLOW} 进行一键修复。${RESET}"
    
    # === 关键：正常结束标志，防止 Trap 触发 ===
    trap_triggered=1
    echo -ne "\n${YELLOW}${I_INFO} 审计完成。按任意键返回主控台菜单...${RESET}"
    read -n 1 -s -r
}

# --- 主流程 ---
clear
get_sys_info
init_audits
print_report
