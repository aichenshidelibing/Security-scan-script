#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v0.sh - Linux 全维安全审计脚本 (v1.4 终极全维度版)

set -u
export LC_ALL=C

# ---------- [关键修复] 信号捕获逻辑 ----------
# 捕获 Ctrl+C (SIGINT) 信号，确保其优雅退出并返回主控台菜单
trap 'exit 0' INT
# --------------------------------------------

# ---------- 统一自适应 UI 区 ----------
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); WHITE=$(printf '\033[37m'); 
RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_PASS="✅"; I_RISK="❌"; I_HEADER="📊"; I_INFO="ℹ️ "; I_LEVEL="🛡️ "
else
    I_PASS="[安全]"; I_RISK="[风险]"; I_HEADER="[*]"; I_INFO="[ INFO ]"; I_LEVEL="[ LEVEL ]"
fi
# ------------------------------------

declare -a TITLES LEVEL CAT DESC PROS CONS STATUS
COUNT=0
SCORE=100

ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }

add_audit() {
    COUNT=$((COUNT+1))
    CAT[$COUNT]="$1"; LEVEL[$COUNT]="$2"; TITLES[$COUNT]="$3"; DESC[$COUNT]="$4"; PROS[$COUNT]="$5"; CONS[$COUNT]="$6"
    
    if eval "$7"; then
        STATUS[$COUNT]="PASS"
    else
        STATUS[$COUNT]="FAIL"
        case "$2" in
            "危险") SCORE=$((SCORE-15)) ;;
            "高危") SCORE=$((SCORE-10)) ;;
            "中危") SCORE=$((SCORE-5)) ;;
            "低危") SCORE=$((SCORE-2)) ;;
        esac
    fi
}

# --- 1. 定义审计规则库 (全量补全，绝无删减) ---
init_audits() {
    # === [系统状态] ===
    add_audit "系统" "提示" "系统版本" "检测当前操作系统发行版" "确认环境基础" "无" "cat /etc/os-release | grep -q 'PRETTY_NAME'"
    add_audit "系统" "提示" "内核版本" "检测当前 Linux 内核版本" "确认是否存在已知内核漏洞" "无" "uname -r | grep -q '.'"
    add_audit "系统" "中危" "磁盘占用" "检测根分区使用率" "防止系统因日志或临时文件爆满而挂掉" "需定期清理" "[ \$(df / | awk 'NR==2 {print \$5}' | sed 's/%//') -lt 90 ]"
    add_audit "系统" "低危" "内存负载" "检测当前剩余可用内存" "防止 OOM 导致关键服务被系统杀掉" "无" "[ \$(free | grep Mem | awk '{print \$7/\$2 * 100}' | cut -d. -f1) -gt 10 ]"

    # === [账户安全] ===
    add_audit "账户" "危险" "空密码账户" "检测是否存在没有密码的账户" "堵死最基础、风险最高的登录漏洞" "无" "[ -z \"\$(awk -F: '(\$2 == \"\" ) { print \$1 }' /etc/shadow)\" ]"
    add_audit "账户" "危险" "UID=0 非Root账户" "检测是否有非 root 用户拥有最高权限" "防止黑客留下的后门账号窃取权限" "误伤自建管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\") {print \$1}' /etc/passwd)\" ]"
    add_audit "账户" "高危" "Sudo 免密特权" "检测 sudoers 中 NOPASSWD 配置" "防止恶意脚本无需确认即可提权" "自动化脚本需调整" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1"
    add_audit "账户" "中危" "密码修改间隔" "检测 /etc/login.defs 修改频率限制" "防止账号被盗后黑客频繁改密" "输错改回需等待" "grep -qE '^PASS_MIN_DAYS\s+([7-9]|[1-9][0-9])' /etc/login.defs"

    # === [SSH 安全] ===
    add_audit "SSH" "危险" "SSH 允许空密码" "检测是否允许无需密码通过 SSH 登录" "防止远程暴力侵入" "无" "grep -qE '^PermitEmptyPasswords no' /etc/ssh/sshd_config"
    add_audit "SSH" "高危" "Root 密码登录" "检测是否允许 Root 直接用密码远程登录" "防止针对 root 的暴力破解" "丢失普通用户后麻烦" "grep -qE '^PermitRootLogin (no|prohibit-password)' /etc/ssh/sshd_config"
    add_audit "SSH" "高危" "SSH 密码认证" "检测是否开启密码登录 (建议关闭转用密钥)" "密钥登录安全性高于密码数倍" "需预配密钥" "grep -qE '^PasswordAuthentication no' /etc/ssh/sshd_config"
    add_audit "SSH" "中危" "SSH 默认端口" "检测是否还在使用默认 22 端口" "避开全网自动扫描脚本" "连接需记新端口" "[ \"\$(grep -E '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print \$2}' | tail -n 1)\" != \"22\" ]"
    add_audit "SSH" "中危" "SSH 协议版本" "检测是否强制使用 Protocol 2" "防止被降级到有严重漏洞的 V1 协议" "老客户端无法连" "grep -qE '^Protocol 2' /etc/ssh/sshd_config"

    # === [文件权限] ===
    add_audit "文件" "高危" "Shadow 权限" "检测 /etc/shadow 权限是否为 600" "防止普通用户读取密码哈希" "无" "[ \"\$(stat -c %a /etc/shadow)\" -le 600 ]"
    add_audit "文件" "低危" "危险 SUID 程序" "检测 mount/ping 等 SUID 位" "防止利用已知指令漏洞提权" "用户无法ping" "[ ! -u /bin/mount ]"

    # === [内核与网络] ===
    add_audit "内核" "高危" "IP 转发功能" "检测非路由服务器是否开启流量转发" "防止服务器被当作肉机中转流量" "Docker需开启" "sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '= 0'"
    add_audit "内核" "中危" "ICMP 重定向" "检测是否接受重定向包" "防止中间人攻击篡改路由表" "复杂内网或受限" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'"
    add_audit "内核" "中危" "SYN Cookie" "检测抗 SYN Flood 攻击能力" "在遭遇流量攻击时保护服务" "无" "sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q '= 1'"
    add_audit "网络" "高危" "防火墙状态" "检测防火墙(UFW/Firewalld)是否在运行" "服务器的第一道网络防线" "配置错误会锁死" "command -v ufw >/dev/null && ufw status | grep -q 'active' || command -v firewall-cmd >/dev/null && firewall-cmd --state | grep -q 'running' || iptables -L INPUT | grep -q 'DROP'"

    # === [日志与审计] ===
    add_audit "日志" "中危" "日志系统状态" "检测 rsyslog/journald 运行情况" "确保安全事件发生后有据可查" "无" "systemctl is-active --quiet rsyslog || systemctl is-active --quiet systemd-journald"
    add_audit "服务" "提示" "Fail2ban 状态" "检测是否安装了防爆破工具" "自动拉黑暴力尝试登录的恶意 IP" "无" "command -v fail2ban-client >/dev/null"
}

# --- 2. 打印报告逻辑 ---
print_report() {
    clear; ui_header
    echo -e "${BOLD}${PURPLE}      ${I_HEADER} v0.sh 全维安全审计报告 (Detection Only)      ${RESET}"
    echo -e "      主机: $(hostname)  |  内核: $(uname -r)"
    ui_header
    printf "${BOLD}%-4s %-6s %-12s %-30s %-10s${RESET}\n" "ID" "类别" "等级" "检测项名称" "结果"
    ui_header

    for ((i=1; i<=COUNT; i++)); do
        case "${LEVEL[$i]}" in
            "危险"|"高危") L_COLOR="$RED";;
            "中危") L_COLOR="$YELLOW";;
            "低危") L_COLOR="$BLUE";;
            *) L_COLOR="$GREY";;
        esac
        RES_ICON=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_PASS}${RESET}" || echo -e "${RED}${I_RISK}${RESET}" )
        printf "${GREY}%-4s${RESET} %-6s ${L_COLOR}%-12s${RESET} %-30s %b\n" "$i" "${CAT[$i]}" "${LEVEL[$i]}" "${TITLES[$i]}" "$RES_ICON"
        
        # 风险详情：只有 FAIL 时显示
        if [ "${STATUS[$i]}" == "FAIL" ] && [ "${LEVEL[$i]}" != "提示" ]; then
            echo -e "     ${GREY}├─ 问题描述: ${RESET}${DESC[$i]}"
            echo -e "     ${GREY}├─ 修复优点: ${RESET}${GREEN}${PROS[$i]}${RESET}"
            echo -e "     ${GREY}└─ 修复缺点: ${RESET}${YELLOW}${CONS[$i]}${RESET}"; echo ""
        fi
    done
    
    ui_header
    # 评分
    if [ $SCORE -ge 90 ]; then S_COLOR="$GREEN"; MSG="系统非常安全！"; elif [ $SCORE -ge 70 ]; then S_COLOR="$YELLOW"; MSG="存在一定风险。"; else S_COLOR="$RED"; MSG="存在严重隐患！"; fi
    echo -e "审计评分: ${S_COLOR}${BOLD}$SCORE 分${RESET}  ($MSG)"
    echo -e "提示: 修复请返回主控台使用 ${CYAN}v1.sh${RESET} 到 ${CYAN}v3.sh${RESET}。"; ui_header
    
    # === 关键：强制暂停 ===
    echo -ne "${YELLOW}${I_INFO} 审计完成。请查看报告后按任意键返回主控台菜单...${RESET}"
    read -n 1 -s -r
}

init_audits; print_report
