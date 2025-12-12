#!/usr/bin/env bash
# v3.sh - 服务器禁Ping管理工具 (v5.0 佛系手动版)
# 特性：默认全关 + 先看状态后操作 + 完美对齐UI

set -u
export LC_ALL=C

# --- 变量与配置 ---
REPORT="/root/security_audit_report.txt"

# 颜色定义
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

# 数据存储
declare -a IDS TITLES PROS RISKS STATUS SELECTED
COUNT=0
MSG=""
FW_TYPE="none"

# --- 辅助工具 ---
ui_info() { echo -e "${CYAN}ℹ️  $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}✅ $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}⚠️  $*${RESET}"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- 1. 防火墙自动检测 ---
detect_firewall() {
    if cmd_exists firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then FW_TYPE="firewalld"; return; fi
    if cmd_exists ufw && ufw status >/dev/null 2>&1; then FW_TYPE="ufw"; return; fi
    if cmd_exists nft && nft list ruleset >/dev/null 2>&1; then FW_TYPE="nftables"; return; fi
    if cmd_exists iptables && iptables -S >/dev/null 2>&1; then FW_TYPE="iptables"; return; fi
    FW_TYPE="none"
}

# --- 2. 注册显示函数 ---
add_item() {
    COUNT=$((COUNT+1))
    IDS[$COUNT]=$COUNT
    TITLES[$COUNT]="$1"
    PROS[$COUNT]="$2"
    RISKS[$COUNT]="$3"
    
    # 检测状态
    if eval "$4"; then
        STATUS[$COUNT]="BLOCKED" # 当前状态：已禁Ping
    else
        STATUS[$COUNT]="ALLOWED" # 当前状态：允许Ping
    fi
    
    # 【核心修改】默认全是 FALSE (OFF)，绝不自动勾选
    SELECTED[$COUNT]="FALSE"
}

# --- 3. 审计逻辑 ---
audit_all() {
    if [ -z "$MSG" ]; then
        ui_info "正在检测 ICMP 策略 (防火墙: $FW_TYPE)..."
    fi

    # [1] 内核层 Sysctl
    add_item "内核层禁 Ping (仅IPv4)" "底层屏蔽，极低资源占用" "无法屏蔽 IPv6" \
        "sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null | grep -q '1'"

    # [2] 防火墙层
    local fw_check_cmd="false"
    case "$FW_TYPE" in
        firewalld) fw_check_cmd="firewall-cmd --query-icmp-block=echo-request >/dev/null 2>&1" ;;
        ufw)       fw_check_cmd="grep -q 'DISABLE_PING' /etc/ufw/before.rules 2>/dev/null" ;;
        iptables)  fw_check_cmd="iptables -C INPUT -p icmp --icmp-type echo-request -j DROP >/dev/null 2>&1" ;;
        nftables)  fw_check_cmd="nft list ruleset | grep -q 'icmp type echo-request .* drop'" ;;
        *)         fw_check_cmd="false" ;;
    esac
    
    add_item "防火墙禁 Ping (IPv4/v6)" "全面隐身，包含 IPv6" "属于防火墙规则变更" \
        "$fw_check_cmd"
}

# --- 4. 执行修复/恢复 ---
apply_action() {
    local id=$1
    local title="${TITLES[$id]}"
    
    # 逻辑定义：
    # [ ON ]  = 执行禁止操作 (Block)
    # [ OFF ] = 执行允许操作 (Allow)
    
    if [ "${SELECTED[$id]}" == "TRUE" ]; then
        # === 用户选择了开启 (禁Ping) ===
        echo -e "   ${CYAN}>> 执行: 🚫 禁止 Ping ($title)...${RESET}"
        case "$title" in
            *"内核层"*)
                cat > "/etc/sysctl.d/99-disable-ping.conf" <<EOF
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
                sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1
                ;;
            *"防火墙"*)
                case "$FW_TYPE" in
                    firewalld)
                        firewall-cmd --add-icmp-block=echo-request >/dev/null 2>&1
                        firewall-cmd --permanent --add-icmp-block=echo-request >/dev/null 2>&1
                        firewall-cmd --reload >/dev/null 2>&1 ;;
                    ufw)
                        [ -f /etc/ufw/before.rules ] && grep -q "DISABLE_PING" /etc/ufw/before.rules || cat >>/etc/ufw/before.rules <<'EOF'
# DISABLE_PING: drop ICMP echo-request
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
EOF
                        [ -f /etc/ufw/before6.rules ] && grep -q "DISABLE_PING" /etc/ufw/before6.rules || cat >>/etc/ufw/before6.rules <<'EOF'
# DISABLE_PING: drop ICMPv6 echo-request
-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j DROP
EOF
                        ufw reload >/dev/null 2>&1 ;;
                    iptables)
                        iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -I INPUT -p icmp --icmp-type echo-request -j DROP
                        if cmd_exists ip6tables; then
                            ip6tables -C INPUT -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null || ip6tables -I INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
                        fi
                        mkdir -p /etc/iptables 2>/dev/null
                        iptables-save > /etc/iptables/rules.v4 2>/dev/null ;;
                esac
                ;;
        esac
    else
        # === 用户选择了关闭 (允许Ping) ===
        # 这里只有当状态是 BLOCKED 时才需要执行恢复，避免重复操作，但强制执行也没坏处
        echo -e "   ${CYAN}>> 执行: 🟢 允许 Ping ($title)...${RESET}"
        case "$title" in
            *"内核层"*)
                rm -f "/etc/sysctl.d/99-disable-ping.conf"
                sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1
                sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 >/dev/null 2>&1
                ;;
            *"防火墙"*)
                case "$FW_TYPE" in
                    firewalld)
                        firewall-cmd --remove-icmp-block=echo-request >/dev/null 2>&1
                        firewall-cmd --permanent --remove-icmp-block=echo-request >/dev/null 2>&1
                        firewall-cmd --reload >/dev/null 2>&1 ;;
                    ufw)
                        sed -i '/DISABLE_PING/,+2d' /etc/ufw/before.rules 2>/dev/null
                        sed -i '/DISABLE_PING/,+2d' /etc/ufw/before6.rules 2>/dev/null
                        ufw reload >/dev/null 2>&1 ;;
                    iptables)
                        while iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null; do :; done
                        if cmd_exists ip6tables; then
                            while ip6tables -D INPUT -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null; do :; done
                        fi
                        iptables-save > /etc/iptables/rules.v4 2>/dev/null ;;
                esac
                ;;
        esac
    fi
}

# --- 5. 主逻辑 ---
detect_firewall
audit_all

while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID  |  设置目标      |  当前真实状态${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    for ((i=1; i<=COUNT; i++)); do
        # 1. 显示当前真实状态
        if [ "${STATUS[$i]}" == "BLOCKED" ]; then 
            S_TXT="${GREEN}已隐身 (禁Ping)${RESET}"
        else 
            S_TXT="${RED}可探测 (允许Ping)${RESET}"
        fi
        
        # 2. 显示开关状态 (你的选择)
        if [ "${SELECTED[$i]}" == "TRUE" ]; then 
            SEL_ICON="${GREEN}[ ON  ]${RESET}"
            ACTION_TXT="将被禁止 (Block)"
        else 
            SEL_ICON="${GREY}[ OFF ]${RESET}"
            ACTION_TXT="将被允许 (Allow)"
        fi
        
        # 卡片式显示
        printf "${GREY}%2d.${RESET}  %b  %b%s${RESET}\n" "$i" "$SEL_ICON" "$WHITE" "${TITLES[$i]}"
        printf "     ├─ 当前: %b   ${GREY}|${RESET} 优点: ${CYAN}%s${RESET}\n" "$S_TXT" "${PROS[$i]}"
        printf "     └─ 目标: ${YELLOW}%s${RESET}\n" "$ACTION_TXT"
        echo "" 
    done
    
    echo "${BLUE}================================================================================${RESET}"
    if [ -n "$MSG" ]; then
        echo -e "${YELLOW}💬 状态更新: $MSG${RESET}"
        MSG=""
        echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    fi

    echo -e "含义: ${GREEN}[ ON  ]${RESET} = 我要禁止 Ping  |  ${GREY}[ OFF ]${RESET} = 我要允许 Ping"
    echo -e "提示: ${WHITE}默认全为 OFF，请手动选择你要禁止的项目，然后按 r 执行${RESET}"
    echo -e "指令: ${YELLOW}a${RESET}=全禁 | ${YELLOW}n${RESET}=全放 | ${RED}r${RESET}=应用更改 | ${CYAN}q${RESET}=退出"
    echo -ne "请输入: "
    
    read -r RawInput 
    input=$(echo "$RawInput" | tr ',' ' ' | xargs)

    case "$input" in
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已设置：全部禁止 Ping" ;;
        n|N) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="FALSE"; done; MSG="已设置：全部允许 Ping" ;;
        q|Q) clear; exit 0 ;;
        r|R) 
            echo ""; ui_info "正在应用 ICMP 策略..."
            for ((i=1; i<=COUNT; i++)); do apply_action "$i"; done
            echo ""; ui_ok "设置完成。"
            # 刷新状态
            COUNT=0; audit_all
            echo -ne "${YELLOW}按回车键刷新显示...${RESET}"; read -r
            ;;
        *)
            MSG=""
            for num in $input; do
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ]; then
                    title="${TITLES[$num]}"
                    if [ "${SELECTED[$num]}" == "TRUE" ]; then 
                        SELECTED[$num]="FALSE"
                        MSG="${MSG} ${RED}[设为:允许]${RESET} $title;"
                    else 
                        SELECTED[$num]="TRUE"
                        MSG="${MSG} ${GREEN}[设为:禁止]${RESET} $title;"
                    fi
                fi
            done
            if [ -z "$MSG" ]; then MSG="无效输入"; fi
            ;;
    esac
done