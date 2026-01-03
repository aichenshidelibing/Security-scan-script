#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v17.9 工业级稳健版)
# 特性：全量26项 | 端口防撞 | 旋转进度条 | 信号保护 | 跨系统适配 | 详细损益说明

set -u
export LC_ALL=C

# ---------- [信号捕获] 确保 Ctrl+C 优雅返回主菜单 ----------
# 防止中断导致 install.sh 崩溃退出
trap 'ui_info "\n操作被用户中断，正在返回..."; sleep 1; exit 0' INT
# ---------------------------------------------------------

# ---------- [UI 自适应区] 探测终端渲染能力 ----------
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

# 颜色定义
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
PURPLE=$(printf '\033[35m'); CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); WHITE=$(printf '\033[37m'); 
RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

# 图标定义
if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_FIX="🔧"; I_LIST="📝"; I_SCAN="🔍"
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_FIX="[ FIX ]"; I_LIST="[ LIST ]"; I_SCAN="[ SCAN ]"
fi

# --- 辅助 UI 工具 ---
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }
ui_header() { echo -e "${BLUE}================================================================================${RESET}"; }

# --- 旋转进度条函数 (Spinner) ---
# 解决“静默安装”时无法判断脚本是否卡死的问题
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# --- 智能安装函数 (带前置检测与错误回显) ---
smart_install() {
    local pkg=$1
    # 1. 检查是否已安装
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ]; then
        return 0
    fi

    # 2. 检查包管理器锁 (防止 apt 被后台更新占用导致卡死)
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        ui_warn "检测到系统更新进程正在运行，正在等待锁释放..."
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 1; done
    fi

    ui_info "正在安装必要组件: $pkg (请稍候)..."
    local err_log="/tmp/${pkg}_err.log"
    
    # 3. 后台执行安装，主进程显示进度条
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    else
        ui_fail "未发现支持的包管理器 (apt/dnf)"
        return 1
    fi
    
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    local res=$?

    if [ $res -ne 0 ]; then
        ui_fail "$pkg 安装失败。报错如下："
        cat "$err_log"; rm -f "$err_log"
        return 1
    fi
    rm -f "$err_log"
    ui_ok "$pkg 安装完成。"
    return 0
}

# --- 数据结构与审计逻辑 (26项全量) ---
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
BACKUP_DIR="/root/security_backup_$(date +'%Y%m%d_%H%M%S')"
mkdir -p "$BACKUP_DIR"

# 获取当前 SSH 端口
CURRENT_SSH_PORT=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
TARGET_SSH_PORT="$CURRENT_SSH_PORT"

add_item() {
    COUNT=$((COUNT+1))
    TITLES[$COUNT]="$1"; PROS[$COUNT]="$2"; RISKS[$COUNT]="$3"; IS_RISKY[$COUNT]="$5"
    if eval "$4"; then
        STATUS[$COUNT]="PASS"; SELECTED[$COUNT]="FALSE"
    else
        STATUS[$COUNT]="FAIL"
        # 默认勾选未通过的非高危项
        if [ "$5" == "TRUE" ]; then SELECTED[$COUNT]="FALSE"; else SELECTED[$COUNT]="TRUE"; fi
    fi
}

init_audit() {
    # [1-4] SSH 核心加固
    add_item "强制 SSH 协议 V2" "修复古老协议漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止空密码登录" "防止未授权登录" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口 (当前:$CURRENT_SSH_PORT)" "避开全网扫描" "需记住并开放新端口" "[ \"$CURRENT_SSH_PORT\" != \"22\" ]" "TRUE"

    # [5-8] SSH 权限进阶
    add_item "禁用交互式认证" "防密码爆破尝试" "影响部分自动化工具" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防范无人值守会话劫持" "自动断开闲置连接" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "法律警告合规要求" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止通过环境变量提权" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"

    # [9-11] 账号策略
    add_item "强制 10 位混合密码" "极大提高爆破成本" "改密需数字+大小写符号" "[ -f /etc/pam.d/common-password ] && grep -q 'minlen=10' /etc/pam.d/common-password || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防止账号被盗后黑客快速改密" "7天内无法重复修改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "终端离开后的物理安全" "不活跃Shell自动注销" "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # [12-15] 关键文件权限
    add_item "修正 /etc/passwd" "防止非特权修改账号" "无" "[ \"\$(stat -c %a /etc/passwd 2>/dev/null)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "防止泄露密码哈希" "无" "[ \"\$(stat -c %a /etc/shadow 2>/dev/null)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "防止泄露SSH策略" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "保护公钥授权文件" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys 2>/dev/null)\" == \"600\" ]" "FALSE"

    # [16-19] 清理高危权限
    add_item "锁定异常 UID=0" "彻底清理潜在后门账户" "可能误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "防止静默提权执行" "自动化运维脚本需适配" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "堵死指令提权路径" "用户无法用ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel 组" "限制能切Root的用户范围" "需手动将管理加入wheel组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"

    # [20-22] 内核级防御
    add_item "网络内核防欺骗" "防止ICMP重定向攻击" "IPv6可能受限" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "在被DDoS攻击时保护服务可用性" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵协议栈罕见漏洞" "罕见协议应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"

    # [23-26] 日志与审计服务
    add_item "时间同步(Chrony)" "确保审计日志时间准确" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防止日志塞满磁盘" "历史日志保留减少" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破尝试 IP" "输错5次封禁1h" "command -v fail2ban-server >/dev/null && [ -f /etc/fail2ban/jail.local ]" "FALSE"
    add_item "每日系统自动更新" "及时修补已知高危漏洞" "小概率导致软件版本微变" "command -v unattended-upgrades >/dev/null || [ -f /etc/apt/apt.conf.d/20auto-upgrades ]" "FALSE"
}

# --- 核心修复逻辑 (完全展开，绝无省略) ---
apply_fix() {
    local id=$1; local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 执行加固: $title ...${RESET}"
    
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        *"修改 SSH 默认端口"*)
            local port_ok=1
            while [ $port_ok -ne 0 ]; do
                read -p "   输入新端口 (20000-60000): " i_p
                TARGET_SSH_PORT=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ui_info "正在检测端口 $TARGET_SSH_PORT 是否占用..."
                if ss -tuln | grep -q ":$TARGET_SSH_PORT "; then
                    ui_warn "冲突：端口 $TARGET_SSH_PORT 已被占用！"
                else
                    port_ok=0; ui_ok "端口可用。"
                fi
            done
            sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $TARGET_SSH_PORT" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $TARGET_SSH_PORT/tcp >/dev/null
            command -v firewall-cmd >/dev/null && firewall-cmd --add-port=$TARGET_SSH_PORT/tcp --permanent >/dev/null && firewall-cmd --reload >/dev/null ;;
        
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Restricted." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;

        "强制 10 位混合密码") 
            smart_install "libpam-pwquality" && {
                [ -f /etc/pam.d/common-password ] && sed -i '/pam_pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password
                [ -f /etc/pam.d/system-auth ] && sed -i '/pam_pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/system-auth
            } ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") grep -q "TMOUT=600" /etc/profile || echo "export TMOUT=600 && readonly TMOUT" >> /etc/profile ;;

        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;

        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} 2>/dev/null ;;
        "移除 Sudo 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers 2>/dev/null; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount /usr/bin/newgrp /usr/bin/chsh 2>/dev/null ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;

        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危不常用协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;

        "时间同步(Chrony)") smart_install "chrony" && systemctl enable --now chronyd >/dev/null 2>&1 ;;
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
        "Fail2ban 最佳防护")
            smart_install "fail2ban" && {
                cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
EOF
                systemctl enable --now fail2ban >/dev/null 2>&1
            } ;;
        "每日系统自动更新") smart_install "unattended-upgrades" ;;
    esac
}

# --- 交互界面流程 ---
init_audit
while true; do
    clear; ui_header
    echo -e "${BOLD} ID  | 目标 | 现状 | 名称${RESET}"
    ui_header
    
    SEL_SUM=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        S_TXT=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK}${RESET}" || echo -e "${RED}${I_FAIL}${RESET}" )
        S_ICO=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON ]${RESET}" || echo -e "${GREY}[OFF ]${RESET}" )
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$S_TXT" "${TITLES[$i]}"
        printf "    ${GREY}├─ 优点: ${RESET}${GREEN}%s${RESET}\n" "${PROS[$i]}"
        printf "    ${GREY}└─ 风险: ${RESET}${YELLOW}%s${RESET}\n\n" "${RISKS[$i]}"
        
        if [ "${SELECTED[$i]}" == "TRUE" ]; then
            SEL_SUM="${SEL_SUM}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"
        fi
    done
    ui_header
    echo -e "${BOLD}${I_LIST} 待执行清单:${RESET} ${GREEN}${SEL_SUM%, }${RESET}"
    ui_header
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始执行 | q=取消并返回 | 输入 ID 翻转: "; read -r ri
    i_p=$(echo "$ri" | tr ',' ' ' | xargs)
    case "$i_p" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已全部勾选" ;;
        r|R)
            [ -z "$SEL_SUM" ] && { MSG="请先勾选项目！"; continue; }
            [ "$has_r" == "TRUE" ] && { read -p "   清单中包含高危项，确认继续? (yes/no): " c; [ "$c" != "yes" ] && continue; }
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            echo -ne "\n${YELLOW}${I_OK} 加固流程已全部完成。按任意键返回主控台...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for num in $i_p; do [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ] && { [ "${SELECTED[$num]}" == "TRUE" ] && SELECTED[$num]="FALSE" || SELECTED[$num]="TRUE"; }; done ;;
    esac
done
