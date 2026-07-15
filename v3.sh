#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v3.sh - 服务器禁Ping管理工具 (v5.2 智慧感知完整版)
# 特性：内核+防火墙双重屏蔽 | 默认手动翻转 | 自适应UI | 逻辑返回主菜单

set -u
export LC_ALL=C

# ---------- [关键修复] 信号捕获逻辑 ----------
# 捕获 Ctrl+C (SIGINT) 信号，确保其优雅退出并返回主控台菜单
trap 'exit 0' INT
# --------------------------------------------

# ---------- 统一自适应 UI 区 ----------
# 优先读取主控台变量，读不到则本地检测
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

# 颜色定义
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

# 根据环境定义图标
if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_INFO="ℹ️ "; I_LOCK="🚫"; I_UNLOCK="🟢"
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_LOCK="[禁]"; I_UNLOCK="[放]"
fi
# ------------------------------------

# --- 变量与数据 ---
REPORT="/root/security_audit_report.txt"
declare -a IDS TITLES PROS RISKS STATUS SELECTED
COUNT=0
MSG=""
FW_TYPE="none"

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 1. 防火墙自动检测 ---
detect_firewall() {
    if cmd_exists firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then FW_TYPE="firewalld"; return; fi
    if cmd_exists ufw && ufw status >/dev/null 2>&1; then FW_TYPE="ufw"; return; fi
    if cmd_exists nft && nft list ruleset >/dev/null 2>&1; then FW_TYPE="nftables"; return; fi
    if cmd_exists iptables && iptables -S >/dev/null 2>&1; then FW_TYPE="iptables"; return; fi
    FW_TYPE="none"
}

# --- 2. 注册项目与审计 ---
nft_rule_exists() {
    nft list chain inet sec_toolbox input 2>/dev/null | grep -q 'icmp type echo-request drop' && \
        nft list chain inet sec_toolbox input 2>/dev/null | grep -q 'icmpv6 type echo-request drop'
}

ensure_nft_chain() {
    nft list table inet sec_toolbox >/dev/null 2>&1 || nft add table inet sec_toolbox
    nft list chain inet sec_toolbox input >/dev/null 2>&1 || \
        nft add chain inet sec_toolbox input '{ type filter hook input priority 0; policy accept; }'
}

apply_nft_block() {
    ensure_nft_chain || return 1
    nft list chain inet sec_toolbox input 2>/dev/null | grep -q 'icmp type echo-request drop' || \
        nft add rule inet sec_toolbox input icmp type echo-request drop 2>/dev/null
    nft list chain inet sec_toolbox input 2>/dev/null | grep -q 'icmpv6 type echo-request drop' || \
        nft add rule inet sec_toolbox input icmpv6 type echo-request drop 2>/dev/null
}

apply_nft_allow() {
    nft delete table inet sec_toolbox 2>/dev/null || true
}

add_item() {
    COUNT=$((COUNT+1))
    IDS[$COUNT]=$COUNT
    TITLES[$COUNT]="$1"
    PROS[$COUNT]="$2"
    RISKS[$COUNT]="$3"
    
    # 真实状态检测
    if eval "$4"; then STATUS[$COUNT]="BLOCKED"; else STATUS[$COUNT]="ALLOWED"; fi
    SELECTED[$COUNT]="FALSE" # 默认不选中，由用户手动决定
}

audit_all() {
    COUNT=0
    # [1] 内核层 Sysctl
    add_item "内核层禁 Ping (仅IPv4)" "底层屏蔽，极低资源占用" "无法屏蔽 IPv6" \
        "sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null | grep -q '1'"

    # [2] 防火墙层
    local fw_cmd="false"
    case "$FW_TYPE" in
        firewalld) fw_cmd="firewall-cmd --query-icmp-block=echo-request >/dev/null 2>&1" ;;
        ufw)       fw_cmd="grep -q 'DISABLE_PING' /etc/ufw/before.rules 2>/dev/null" ;;
        iptables)  fw_cmd="iptables -C INPUT -p icmp --icmp-type echo-request -j DROP >/dev/null 2>&1" ;;
        nftables)  fw_cmd="nft_rule_exists" ;;
    esac
    
    add_item "防火墙禁 Ping (IPv4/v6)" "全面隐身，包含 IPv6" "属于防火墙规则变更" "$fw_cmd"
}

# --- 3. 执行应用逻辑 ---
apply_action() {
    local id=$1
    local title="${TITLES[$id]}"
    
    if [ "${SELECTED[$id]}" == "TRUE" ]; then
        # === 执行禁止 (Block) ===
        echo -e "   ${CYAN}>> 执行: ${I_LOCK} 禁用 Ping ($title)...${RESET}"
        case "$title" in
            *"内核层"*)
                echo "net.ipv4.icmp_echo_ignore_all = 1" > /etc/sysctl.d/99-disable-ping.conf
                sysctl --system >/dev/null 2>&1 ;;
            *"防火墙"*)
                case "$FW_TYPE" in
                    firewalld) firewall-cmd --add-icmp-block=echo-request --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1 ;;
                    ufw) 
                        [ -f /etc/ufw/before.rules ] && ! grep -q "DISABLE_PING" /etc/ufw/before.rules && sed -i '/ufw-before-input.*-j DROP/i # DISABLE_PING\n-A ufw-before-input -p icmp --icmp-type echo-request -j DROP' /etc/ufw/before.rules
                        ufw reload >/dev/null 2>&1 ;;
                    nftables) apply_nft_block || ui_fail "nftables 规则应用失败" ;;
                    iptables) iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -I INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null ;;
                esac ;;
        esac
    else
        # === 执行恢复 (Allow) ===
        echo -e "   ${CYAN}>> 执行: ${I_UNLOCK} 恢复 Ping ($title)...${RESET}"
        case "$title" in
            *"内核层"*) rm -f /etc/sysctl.d/99-disable-ping.conf; sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 ;;
            *"防火墙"*)
                case "$FW_TYPE" in
                    firewalld) firewall-cmd --remove-icmp-block=echo-request --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1 ;;
                    ufw) sed -i '/DISABLE_PING/,+1d' /etc/ufw/before.rules 2>/dev/null; ufw reload >/dev/null 2>&1 ;;
                    nftables) apply_nft_allow ;;
                    iptables) while iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null; do :; done ;;
                esac ;;
        esac
    fi
}

# --- 4. 主循环界面 ---
detect_firewall
audit_all

while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID  |  设置目标      |  当前真实状态${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    for ((i=1; i<=COUNT; i++)); do
        # 显示当前状态
        if [ "${STATUS[$i]}" == "BLOCKED" ]; then S_TXT="${GREEN}${I_LOCK} 已隐身${RESET}"; else S_TXT="${RED}${I_UNLOCK} 可探测${RESET}"; fi
        # 显示选择目标
        if [ "${SELECTED[$i]}" == "TRUE" ]; then 
            SEL_ICON="${GREEN}[ ON  ]${RESET}"; ACTION_TXT="将被禁止 (Block)"
        else 
            SEL_ICON="${GREY}[ OFF ]${RESET}"; ACTION_TXT="将被允许 (Allow)"
        fi
        
        printf "${GREY}%2d.${RESET}  %b  %b%s${RESET}\n" "$i" "$SEL_ICON" "$WHITE" "${TITLES[$i]}"
        printf "     ├─ 当前: %b   ${GREY}|${RESET} 优点: ${CYAN}%s${RESET}\n" "$S_TXT" "${PROS[$i]}"
        printf "     └─ 目标: ${YELLOW}%s${RESET}\n" "$ACTION_TXT"
        echo "" 
    done
    
    echo "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} 状态更新: $MSG${RESET}"; MSG=""; }
    echo -e "含义: ${GREEN}[ ON ]${RESET}=我要禁用 | ${GREY}[ OFF ]${RESET}=我要放行"
    echo -e "指令: ${YELLOW}a${RESET}=全禁 | ${YELLOW}n${RESET}=全放 | ${RED}r${RESET}=应用更改 | ${CYAN}q${RESET}=返回主菜单"
    echo -ne "请输入编号翻转或指令: "
    
    read -r RawInput 
    input=$(echo "$RawInput" | tr ',' ' ' | xargs)

    case "$input" in
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已全部设为禁用状态" ;;
        n|N) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="FALSE"; done; MSG="已全部设为放行状态" ;;
        q|Q) clear; exit 0 ;; # 返回主控台
        r|R) 
            echo ""; ui_info "正在应用 ICMP 策略..."
            for ((i=1; i<=COUNT; i++)); do apply_action "$i"; done
            ui_ok "操作完成。"
            audit_all # 刷新状态
            sleep 2 ;;
        *)
            for num in $input; do
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ]; then
                    [ "${SELECTED[$num]}" == "TRUE" ] && SELECTED[$num]="FALSE" || SELECTED[$num]="TRUE"
                fi
            done ;;
    esac
done
