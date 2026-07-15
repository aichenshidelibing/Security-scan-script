#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v0.sh - Linux 全维安全审计系统 (v3.0 完美镜像版)
# 特性：安全精简审计 | 硬件仪表盘 | 可视化评分 | 防闪退 | 进度条

export LC_ALL=C

# =======================================================================
# [核心防闪退] 退出前强制暂停
# =======================================================================
finish_trap() {
    echo -e "\n\033[33m[系统提示] 审计结束。请按回车键关闭窗口...\033[0m"
    read -r
}
trap finish_trap EXIT
# =======================================================================

# --- [UI 自适应] ---
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); WHITE=$(printf '\033[37m'); 
RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_PASS="✅"; I_FAIL="❌"; I_WARN="⚠️ "; I_INFO="ℹ️ "; I_SYS="🖥️ "; I_SCAN="🔍"
else
    I_PASS="[PASS]"; I_FAIL="[FAIL]"; I_WARN="[WARN]"; I_INFO="[INFO]"; I_SYS="[SYS]"; I_SCAN="[SCAN]"
fi

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

# --- 1. 系统硬件信息仪表盘 (增强版) ---
get_sys_info() {
    # CPU
    local cpu_model=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^[ \t]*//')
    local cpu_cores=$(grep -c "processor" /proc/cpuinfo)
    # 内存
    local mem_total=$(free -h | awk '/^Mem:/ {print $2}')
    local mem_used=$(free -h | awk '/^Mem:/ {print $3}')
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
    printf " %-12s: ${WHITE}%s / %s${RESET}\n" "内存状态" "$mem_used" "$mem_total"
    printf " %-12s: ${WHITE}%s (共 %s)${RESET}\n" "磁盘占用" "$disk_usage" "$disk_total"
    printf " %-12s: ${WHITE}%s${RESET}\n" "运行时间" "$uptime"
    ui_header
    echo ""
}

# --- 2. 审计规则定义 (安全精简版，对齐 v1.sh) ---
declare -a CAT TITLES DESC SUGGEST LEVEL STATUS
COUNT=0
SCORE=100

add_audit() {
    COUNT=$((COUNT+1))
    CAT[$COUNT]="$1"; TITLES[$COUNT]="$2"; DESC[$COUNT]="$3"; SUGGEST[$COUNT]="$4"; LEVEL[$COUNT]="$5"
    
    # 执行检测命令
    if eval "$6"; then
        STATUS[$COUNT]="PASS"
    else
        STATUS[$COUNT]="FAIL"
        # 扣分逻辑
        case "$5" in
            "high") SCORE=$((SCORE-5)) ;;
            "mid")  SCORE=$((SCORE-3)) ;;
            "low")  SCORE=$((SCORE-1)) ;;
        esac
    fi
}

# 辅助检测函数
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    CUR_P=$(grep -E "^[[:space:]]*Port" "$SSHD_CONFIG" | awk '{print $2}' | tail -n 1)
else
    CUR_P=22
fi
CUR_P=${CUR_P:-22}
has_sshd_config() { [ -f "$SSHD_CONFIG" ]; }
bbr_available() { sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; }

# [核心修复] 函数名统一为 init_audit，确保与调用一致
init_audit() {
    # 1. 基础优化
    add_audit "基础" "TCP BBR" "检测 BBR 加速" "内核支持时可开启以改善部分网络场景" "low" "bbr_available && sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qw bbr"
    add_audit "基础" "必备软件" "检测 curl/wget/vim 等" "建议安装常用工具" "info" "command -v vim >/dev/null && command -v htop >/dev/null"

    # 2. SSH 安全（低锁死风险项）
    add_audit "SSH" "公钥认证" "检测 Pubkey" "建议开启密钥登录" "info" "has_sshd_config && grep -q '^PubkeyAuthentication yes' \"$SSHD_CONFIG\""
    add_audit "SSH" "空密码" "检测 EmptyPasswords" "必须禁止空密码" "high" "has_sshd_config && grep -q '^PermitEmptyPasswords no' \"$SSHD_CONFIG\""
    add_audit "SSH" "连接超时" "检测 ClientAlive" "建议设置 600s 超时" "low" "has_sshd_config && grep -q '^ClientAliveInterval 600' \"$SSHD_CONFIG\""
    add_audit "SSH" "登录警告" "检测 Banner" "建议设置警告标语" "info" "has_sshd_config && grep -q '^Banner' \"$SSHD_CONFIG\""
    add_audit "SSH" "环境篡改" "检测 UserEnvironment" "必须禁止环境篡改" "mid" "has_sshd_config && grep -q '^PermitUserEnvironment no' \"$SSHD_CONFIG\""

    
    # 4. 权限与文件 (5项)
    add_audit "权限" "Passwd" "检测 passwd 644" "权限应为 644" "high" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]"
    add_audit "权限" "Shadow" "检测 shadow 600" "权限应为 600" "high" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]"
    add_audit "权限" "SSH配置" "检测 sshd_config 600" "权限应为 600" "high" "has_sshd_config && [ \"$(stat -c %a \\\"$SSHD_CONFIG\\\")\" == \"600\" ]"
    add_audit "权限" "AuthKeys" "检测 authorized_keys 600" "权限应为 600" "high" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]"

    
    # 6. 内核防御
    add_audit "内核" "ICMP重定向" "检测 accept_redirects" "建议禁用防攻击" "mid" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'"
    add_audit "内核" "SYN Cookie" "检测 tcp_syncookies" "建议开启防 DDoS" "mid" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'"
    add_audit "内核" "恶意包日志" "检测 log_martians" "建议开启恶意包记录" "low" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '= 1'"

    # 7. 审计与更新
    add_audit "审计" "时间同步" "检测 Chrony/NTP" "必须保证日志时间准确" "mid" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd"
    add_audit "审计" "日志轮转" "检测 Journald MaxUse" "建议限制日志大小" "low" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf"
    add_audit "防御" "Fail2ban" "检测 Fail2ban" "强烈建议安装防爆破" "high" "command -v fail2ban-server >/dev/null"
}

# --- 3. 打印报告逻辑 ---
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
        
        if [ "${STATUS[$i]}" == "FAIL" ] && [ "${LEVEL[$i]}" != "info" ]; then
            echo -e "    ${GREY}└─ 建议: ${SUGGEST[$i]}${RESET}"
        fi
    done
    ui_header
    
    # 评分显示
    local bar_len=$((SCORE / 10)); local bar_str=""
    for ((b=0; b<10; b++)); do [ $b -lt $bar_len ] && bar_str="${bar_str}#" || bar_str="${bar_str}-"; done
    if [ $SCORE -ge 90 ]; then S_COLOR="$GREEN"; MSG="系统非常安全 (Excellent)"; 
    elif [ $SCORE -ge 70 ]; then S_COLOR="$YELLOW"; MSG="存在安全风险 (Warning)"; 
    else S_COLOR="$RED"; MSG="存在严重隐患 (Dangerous)"; fi
    
    echo -e "安全评分: [${S_COLOR}${bar_str}${RESET}] ${S_COLOR}${BOLD}$SCORE 分${RESET}"
    echo -e "评估结论: $MSG"
    
    [ $SCORE -lt 100 ] && echo -e "\n${YELLOW}${I_WARN} 发现风险项！请运行 ${CYAN}v1.sh${YELLOW} 进行一键修复。${RESET}"
    
    # 正常结束时不触发 trap，而是手动暂停
    trap - EXIT
    echo -ne "\n${YELLOW}${I_INFO} 审计完成。按任意键返回主控台菜单...${RESET}"
    read -n 1 -s -r
}

# --- 主流程 ---
clear
get_sys_info
init_audit  # 修正后的调用名称
print_report
