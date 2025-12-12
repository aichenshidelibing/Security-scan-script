#!/usr/bin/env bash
# v0.sh - Linux 全维安全审计脚本 (v1.1 闪屏修复版)
# 修复：报告打印后增加 read -r 暂停，防止屏幕闪退。

set -u
export LC_ALL=C

# --- 颜色定义 ---
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); WHITE=$(printf '\033[37m'); 
RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

# --- 数据存储 ---
declare -a TITLES LEVEL CAT DESC PROS CONS STATUS
COUNT=0
SCORE=100

# --- 辅助函数 ---
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }
ui_title()  { echo -e "${BOLD}${PURPLE}   $1 ${RESET}"; }

# 注册检测项
# 参数: 1.类别 2.等级 3.标题 4.描述 5.修复优点 6.修复缺点 7.检测命令
add_audit() {
    COUNT=$((COUNT+1))
    CAT[$COUNT]="$1"
    LEVEL[$COUNT]="$2"
    TITLES[$COUNT]="$3"
    DESC[$COUNT]="$4"
    PROS[$COUNT]="$5"
    CONS[$COUNT]="$6"
    
    # 执行检测命令
    if eval "$7"; then
        STATUS[$COUNT]="PASS"
    else
        STATUS[$COUNT]="FAIL"
        # 扣分逻辑
        case "$2" in
            "危险") SCORE=$((SCORE-15)) ;;
            "高危") SCORE=$((SCORE-10)) ;;
            "中危") SCORE=$((SCORE-5)) ;;
            "低危") SCORE=$((SCORE-2)) ;;
        esac
    fi
}

# --- 1. 定义审计规则库 ---
init_audits() {
    # === [系统基础] ===
    add_audit "系统" "提示" "系统版本检测" \
        "检查当前操作系统发行版版本" "了解环境基础" "无" \
        "true"

    # === [账户安全] ===
    add_audit "账户" "危险" "空密码账户检测" \
        "检测是否存在没有设置密码的账户，极易被直接登录" \
        "堵死无需密码即可登录的最高风险漏洞" "无副作用" \
        "[ -z \"\$(awk -F: '(\$2 == \"\" ) { print \$1 }' /etc/shadow)\" ]"

    add_audit "账户" "危险" "UID=0 非Root账户" \
        "检测是否有非 root 用户拥有 root 权限 (UID=0)" \
        "防止黑客留下的后门账号窃取最高权限" "误伤自建的管理员账号" \
        "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\") {print \$1}' /etc/passwd)\" ]"

    add_audit "账户" "高危" "Sudo 免密特权" \
        "检测 sudoers 中是否存在 NOPASSWD 免密配置" \
        "防止恶意脚本提权，执行 sudo 必须输密码" "自动化运维脚本可能失效" \
        "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1"

    add_audit "账户" "中危" "密码修改最小间隔" \
        "检测 /etc/login.defs 是否限制了频繁修改密码" \
        "防止账号被盗后黑客频繁改密导致找回困难" "用户输错想立刻改回需等待" \
        "grep -qE '^PASS_MIN_DAYS\s+([7-9]|[1-9][0-9])' /etc/login.defs"

    # === [SSH 安全] ===
    add_audit "SSH" "危险" "SSH 允许空密码" \
        "检测 sshd_config 是否允许空密码登录" \
        "防止无密码直接回车登录" "无" \
        "grep -qE '^PermitEmptyPasswords no' /etc/ssh/sshd_config"

    add_audit "SSH" "高危" "SSH 允许 Root 密码登录" \
        "检测是否允许 root 用户直接通过密码远程登录" \
        "防止针对 root 的暴力破解，强迫使用普通用户su或密钥" "丢失普通用户后管理麻烦" \
        "grep -qE '^PermitRootLogin (no|prohibit-password|without-password)' /etc/ssh/sshd_config"

    add_audit "SSH" "高危" "SSH 开启密码认证" \
        "检测是否开启了 PasswordAuthentication" \
        "密钥登录比密码登录安全数个量级" "必须先配好密钥否则无法登录" \
        "grep -qE '^PasswordAuthentication no' /etc/ssh/sshd_config"

    add_audit "SSH" "中危" "SSH 默认端口 22" \
        "检测 SSH 是否运行在默认的 22 端口" \
        "避开全网 99% 的自动化脚本无脑扫描" "连接时需指定端口" \
        "[ \"\$(grep -E '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print \$2}' | tail -n 1)\" != \"22\" ]"

    add_audit "SSH" "中危" "SSH 协议版本" \
        "检测是否强制使用了 Protocol 2" \
        "防止使用有严重漏洞的 SSH v1 协议" "极古老的客户端无法连接" \
        "grep -qE '^Protocol 2' /etc/ssh/sshd_config"

    # === [文件权限] ===
    add_audit "文件" "高危" "Shadow 文件权限" \
        "检测 /etc/shadow 是否设置为 000 或 600" \
        "防止普通用户读取加密后的密码哈希进行跑包破解" "无" \
        "[ \"\$(stat -c %a /etc/shadow)\" -le 600 ]"

    add_audit "文件" "中危" "危险 SUID 程序" \
        "检测 mount/ping 等程序是否带有 SUID 提权位" \
        "防止利用系统指令提权漏洞" "普通用户无法使用 ping" \
        "[ ! -u /bin/mount ]"

    # === [网络与内核] ===
    add_audit "内核" "高危" "IP 转发 (IP Forwarding)" \
        "检测是否开启了路由转发功能 (非路由器不应开启)" \
        "防止服务器被用作恶意流量跳板" "无法做软路由/Docker网桥需开启" \
        "sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '= 0'"

    add_audit "内核" "中危" "ICMP 重定向" \
        "检测是否允许接收 ICMP 重定向包" \
        "防止中间人攻击修改路由表" "极少数复杂旧内网可能受影响" \
        "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'"

    add_audit "内核" "中危" "SYN Cookie 保护" \
        "检测是否开启了 TCP SYN Cookie" \
        "在遭遇 SYN Flood 攻击时保护服务可用性" "无" \
        "sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q '= 1'"

    add_audit "网络" "高危" "防火墙状态" \
        "检测 UFW/Firewalld/Iptables 是否正在运行" \
        "基础的网络访问控制" "配置不当可能把自己锁外面" \
        "command -v ufw >/dev/null && ufw status | grep -q 'active' || command -v firewall-cmd >/dev/null && firewall-cmd --state | grep -q 'running' || iptables -L INPUT | grep -q 'DROP'"

    # === [日志与服务] ===
    add_audit "日志" "中危" "日志服务状态" \
        "检测 rsyslog 或 systemd-journald 是否运行" \
        "确保安全事件可追溯" "无" \
        "systemctl is-active --quiet rsyslog || systemctl is-active --quiet systemd-journald"

    add_audit "服务" "提示" "Fail2ban 安装状态" \
        "检测是否安装了 Fail2ban 防爆破工具" \
        "自动封禁暴力破解 SSH 的 IP" "无" \
        "command -v fail2ban-client >/dev/null"
}

# --- 2. 打印报告逻辑 ---
print_report() {
    clear
    ui_header
    echo -e "${BOLD}${PURPLE}      v0.sh 全维安全审计报告 (Detection Only)      ${RESET}"
    echo -e "      主机: $(hostname)  |  时间: $(date +'%F %T')"
    echo -e "      内核: $(uname -r)"
    ui_header
    
    # 表头
    printf "${BOLD}%-4s %-6s %-12s %-30s %-10s${RESET}\n" "ID" "类别" "等级" "检测项名称" "结果"
    ui_header

    for ((i=1; i<=COUNT; i++)); do
        # 等级颜色处理
        case "${LEVEL[$i]}" in
            "危险") L_COLOR="$RED";;
            "高危") L_COLOR="$RED";;
            "中危") L_COLOR="$YELLOW";;
            "低危") L_COLOR="$BLUE";;
            "提示") L_COLOR="$GREY";;
        esac

        # 结果显示
        if [ "${STATUS[$i]}" == "PASS" ]; then
            RES_ICON="${GREEN}[安全]${RESET}"
        else
            RES_ICON="${RED}[风险]${RESET}"
        fi

        # 打印摘要行
        printf "${GREY}%-4s${RESET} %-6s ${L_COLOR}%-12s${RESET} %-30s %b\n" \
            "$i" "${CAT[$i]}" "${LEVEL[$i]}" "${TITLES[$i]}" "$RES_ICON"
        
        # 如果未通过，打印详细信息
        if [ "${STATUS[$i]}" == "FAIL" ] && [ "${LEVEL[$i]}" != "提示" ]; then
            echo -e "     ${GREY}├─ 问题描述: ${RESET}${DESC[$i]}"
            echo -e "     ${GREY}├─ 修复优点: ${RESET}${GREEN}${PROS[$i]}${RESET}"
            echo -e "     ${GREY}└─ 修复缺点: ${RESET}${YELLOW}${CONS[$i]}${RESET}"
            echo ""
        fi
    done
    
    ui_header
    # 评分逻辑
    if [ $SCORE -ge 90 ]; then S_COLOR="$GREEN"; MSG="系统非常安全！"; 
    elif [ $SCORE -ge 70 ]; then S_COLOR="$YELLOW"; MSG="存在一些风险，建议加固。";
    else S_COLOR="$RED"; MSG="警告！系统存在严重安全隐患！"; fi
    
    echo -e "审计评分: ${S_COLOR}${BOLD}$SCORE 分${RESET}  ($MSG)"
    echo -e "提示: 本脚本仅做检测，如需修复请使用 ${CYAN}v1.sh${RESET} (基础加固) 和 ${CYAN}v2.sh${RESET} (密钥配置)。"
    ui_header
    
    # === 核心修复：增加暂停命令 ===
    echo -ne "${YELLOW}按任意键返回主菜单...${RESET}"
    read -r 
}

# --- 执行 ---
init_audits
print_report
