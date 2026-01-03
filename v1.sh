#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v24.0 工业级终极版)

set -u
export LC_ALL=C

# --- [信号捕获] ---
trap 'echo -e "\n${YELLOW}操作取消，返回主菜单...${RESET}"; sleep 1; exit 0' INT

# --- [UI 自适应] ---
if [ "${USE_EMOJI:-}" == "" ]; then
    if [[ "${LANG:-}" =~ "UTF-8" ]] || [[ "${LANG:-}" =~ "utf8" ]]; then
        USE_EMOJI="1"
    else
        USE_EMOJI="0"
    fi
fi

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

if [ "$USE_EMOJI" == "1" ]; then
    I_OK="✅"; I_FAIL="❌"; I_INFO="ℹ️ "; I_FIX="🔧"; I_WAIT="⏳"; I_LIST="📝"
else
    I_OK="[ OK ]"; I_FAIL="[FAIL]"; I_INFO="[INFO]"; I_FIX="[FIX]"; I_WAIT="[WAIT]"; I_LIST="[LIST]"
fi

# --- 核心辅助工具 (Helper Functions) ---

ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

# 旋转进度条 (Spinner)
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

# 修正 Debian 11 安全源
fix_apt_sources() {
    if [ -f /etc/debian_version ] && grep -q "^11" /etc/debian_version; then
        if grep -q "bullseye/updates" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            ui_info "正在为 Debian 11 修正安全源路径..."
            sed -i 's|bullseye/updates|bullseye-security|g' /etc/apt/sources.list 2>/dev/null
            find /etc/apt/sources.list.d/ -type f -exec sed -i 's|bullseye/updates|bullseye-security|g' {} + 2>/dev/null
        fi
    fi
}

# 锁管理与系统自愈
handle_lock() {
    local lock="/var/lib/dpkg/lock-frontend"
    # 如果锁文件不存在或没有进程占用，直接返回
    if [ ! -f "$lock" ] || ! fuser "$lock" >/dev/null 2>&1; then 
        return 0
    fi

    local h_pid=$(fuser "$lock" 2>/dev/null | awk '{print $NF}')
    ui_warn "检测到更新锁占用 (PID: $h_pid)。正在排队等待 5 秒..."
    local count=0
    while fuser "$lock" >/dev/null 2>&1 && [ $count -lt 5 ]; do
        sleep 1
        count=$((count+1))
    done

    if fuser "$lock" >/dev/null 2>&1; then
        echo -e "${YELLOW}锁未释放。请选: [1] 接着等 [2] 跳过 [3] 强杀进程并执行包管理自愈${RESET}"
        read -p "选择: " lock_choice
        if [ "$lock_choice" == "3" ]; then
            kill -9 "$h_pid" 2>/dev/null
            rm -f "$lock" /var/lib/apt/lists/lock /var/lib/dpkg/lock 2>/dev/null
            ui_info "正在尝试修复中断的包管理状态..."
            dpkg --configure -a >/dev/null 2>&1
            apt-get install -f -y >/dev/null 2>&1
            ui_ok "自愈尝试完成。"
            return 0
        elif [ "$lock_choice" == "1" ]; then
            handle_lock
        else
            return 1
        fi
    fi
    return 0
}

# 智能安装
smart_install() {
    local pkg=$1
    if command -v "$pkg" >/dev/null 2>&1 || [ -x "/usr/sbin/$pkg" ] || [ -x "/usr/bin/$pkg" ]; then
        return 0
    fi
    ui_info "正在安装组件: $pkg ..."
    local err_log="/tmp/${pkg}_err.log"
    
    if command -v apt-get >/dev/null; then
        handle_lock || return 1
        fix_apt_sources
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v dnf >/dev/null; then
        dnf install -y "$pkg" >/dev/null 2>"$err_log" &
    elif command -v yum >/dev/null; then
        yum install -y "$pkg" >/dev/null 2>"$err_log" &
    else
        return 1
    fi
    
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    local res=$?
    
    if [ $res -ne 0 ]; then
        ui_fail "$pkg 安装失败。日志内容:"
        [ -f "$err_log" ] && cat "$err_log"
        rm -f "$err_log"
        return 1
    fi
    rm -f "$err_log"
    return 0
}

# --- 数据定义 (27项全量) ---

declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0; MSG=""
CUR_P=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1); CUR_P=${CUR_P:-22}

add_item() {
    COUNT=$((COUNT+1))
    TITLES[$COUNT]="$1"
    PROS[$COUNT]="$2"
    RISKS[$COUNT]="$3"
    IS_RISKY[$COUNT]="$5"
    if eval "$4"; then
        STATUS[$COUNT]="PASS"
        SELECTED[$COUNT]="FALSE"
    else
        STATUS[$COUNT]="FAIL"
        if [ "$5" == "TRUE" ]; then SELECTED[$COUNT]="FALSE"; else SELECTED[$COUNT]="TRUE"; fi
    fi
}

is_eol_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        [[ "$ID" == "debian" && "$VERSION_ID" -lt 10 ]] && return 0
        [[ "$ID" == "ubuntu" && "${VERSION_ID%%.*}" -lt 16 ]] && return 0
        [[ "$ID" == "centos" && "$VERSION_ID" -lt 7 ]] && return 0
    fi
    return 1
}

init_audit() {
    # 1-8: SSH 加固
    add_item "强制 SSH 协议 V2" "修复旧版协议漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止 SSH 空密码登录" "拒绝远程暴力直连" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口" "大幅降低被全网扫描的概率" "需记新端口" "[ \"$CUR_P\" != \"22\" ]" "TRUE"
    add_item "禁用交互式认证" "防范密码爆破尝试" "部分工具不兼容" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防范会话被他人接管" "自动断开不活跃连接" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告及法律威慑" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防止利用 Shell 环境绕过安全限制" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    
    # 9-11: 账号与密码
    add_item "强制 10 位混合密码" "极大提高爆破成本" "改密需数字大小写符号" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防止账号被盗后快速改密" "7天内禁再次改密" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "离机后的物理安全防护" "闲置终端自动注销" "grep -q 'TMOUT=600' /etc/profile" "FALSE"
    
    # 12-16: 文件权限
    add_item "修正 /etc/passwd 权限" "防止非授权修改账号信息" "无" "[ \"\$(stat -c %a /etc/passwd 2>/dev/null)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow 权限" "防止泄露密码哈希值" "无" "[ \"\$(stat -c %a /etc/shadow 2>/dev/null)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config 权限" "保护 SSH 核心配置安全" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys 权限" "保护已授权的公钥文件" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys 2>/dev/null)\" == \"600\" ]" "FALSE"
    add_item "清理危险 SUID 权限" "堵死利用系统指令提权的路径" "普通用户无法ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    
    # 17-20: 限制与后门清理
    add_item "锁定异常 UID=0 账户" "彻底清理潜在提权后门" "可能误锁管理员" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密配置" "提高特权执行门槛" "影响自动化运维脚本" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "限制 su 仅 wheel 组" "缩减能切换 Root 的用户范围" "必须手动加组" "grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q 'pam_wheel.so' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "限制编译器权限" "防止普通用户编译提权木马" "无" "[ \"\$(stat -c %a /usr/bin/gcc 2>/dev/null)\" == \"700\" ] || [ ! -f /usr/bin/gcc ]" "FALSE"
    
    # 21-23: 内核级防御
    add_item "网络内核防欺骗" "防范 ICMP 重定向攻击" "IPv6 环境可能受限" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "在被 DDoS 攻击时保护服务可用" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危不常用协议" "封堵罕见协议层漏洞" "应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"
    
    # 24-27: 审计与全量补丁
    add_item "时间同步(Chrony)" "确保审计日志时间对准" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防范磁盘被日志撑爆" "减少存储记录" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null" "FALSE"
    add_item "Fail2ban 最佳防护" "自动拉黑爆破恶意 IP" "误输也封" "command -v fail2ban-server >/dev/null" "FALSE"
    add_item "全量系统漏洞修复" "升级核心组件补丁(dpkg等)" "需联网下载" "! is_eol_system && { dpkg --compare-versions \$(dpkg-query -f='\${Version}' -W dpkg 2>/dev/null || echo 0) ge 1.20.10; }" "FALSE"
}

# --- 核心修复逻辑 (27项全部展开) ---

apply_fix() {
    local id=$1
    local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 加固中: $title ...${RESET}"
    
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止 SSH 空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        "修改 SSH 默认端口")
            local p_ok=1; while [ $p_ok -ne 0 ]; do
                read -p "   请输入新端口 (回车随机): " i_p; local T_P=${i_p:-$(shuf -i 20000-60000 -n 1)}
                ss -tuln | grep -q ":$T_P " && ui_warn "端口 $T_P 已占用，请重选。" || p_ok=0
            done
            sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $T_P" >> /etc/ssh/sshd_config
            command -v ufw >/dev/null && ufw allow $T_P/tcp >/dev/null
            command -v firewall-cmd >/dev/null && firewall-cmd --add-port=$T_P/tcp --permanent >/dev/null && firewall-cmd --reload >/dev/null ;;
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Restricted." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        
        "强制 10 位混合密码") smart_install "libpam-pwquality" && { 
            [ -f /etc/pam.d/common-password ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/common-password
            [ -f /etc/pam.d/system-auth ] && sed -i '/pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/system-auth
        } ;;
        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root 2>/dev/null ;;
        "Shell 自动注销(10m)") grep -q "TMOUT=600" /etc/profile || echo -e "export TMOUT=600\nreadonly TMOUT" >> /etc/profile ;;
        
        "修正 /etc/passwd 权限") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow 权限") chmod 600 /etc/shadow ;;
        "修正 sshd_config 权限") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys 权限") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        "清理危险 SUID 权限") chmod u-s /bin/mount /bin/umount /usr/bin/newgrp /usr/bin/chsh 2>/dev/null ;;
        
        "锁定异常 UID=0 账户") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} 2>/dev/null ;;
        "移除 Sudo 免密配置") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers 2>/dev/null; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "限制 su 仅 wheel 组") ! grep -q "pam_wheel.so" /etc/pam.d/su && echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su ;;
        "限制编译器权限") [ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc ;;
        
        "网络内核防欺骗") echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/99-sec.conf; sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 ;;
        "禁用高危不常用协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        
        "时间同步(Chrony)") smart_install "chrony" && systemctl enable --now chronyd >/dev/null 2>&1 ;;
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
        "Fail2ban 最佳防护") smart_install "fail2ban" && { 
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
        "全量系统漏洞修复")
            if is_eol_system; then ui_fail "老系统停止维护，跳过补丁。"; else
                handle_lock && { 
                    fix_apt_sources
                    ui_info "正在修补系统级高危漏洞 (dpkg/logrotate 等)..."
                    apt-get update >/dev/null 2>&1
                    apt-get install --only-upgrade -y dpkg logrotate apt tar gzip >/dev/null 2>&1 &
                    show_spinner $!; wait $!
                }
            fi ;;
    esac
}

# --- 交互界面流程 ---

init_audit
while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID | 勾选 | 状态 | 名称${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    SUM_IDS=""; has_r="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        S_ICO=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON ]${RESET}" || echo -e "${GREY}[OFF ]${RESET}" )
        R_ICO=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK}${RESET}" || echo -e "${RED}${I_FAIL}${RESET}" )
        printf "${GREY}%2d.${RESET} %b %b %-30s\n" "$i" "$S_ICO" "$R_ICO" "${TITLES[$i]}"
        if [ "${SELECTED[$i]}" == "TRUE" ]; then 
            SUM_IDS="${SUM_IDS}${i}, "; [ "${IS_RISKY[$i]}" == "TRUE" ] && has_r="TRUE"; 
        fi
    done
    
    echo "${BLUE}================================================================================${RESET}"
    echo -e "${I_LIST} 待执行清单: ${GREEN}${SUM_IDS%, }${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }
    echo -ne "指令: a=全选 | r=开始修复 | q=返回 | 输入编号 ID 翻转勾选: "
    read -r ri
    
    case "$ri" in
        q|Q) exit 0 ;;
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done ;;
        r|R) [ -z "$SUM_IDS" ] && continue
            if [ "$has_r" == "TRUE" ]; then echo -ne "${RED}清单含高危项，确认继续? (yes/no): ${RESET}"; read -r c; [ "$c" != "yes" ] && continue; fi
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            /usr/sbin/sshd -t >/dev/null 2>&1 && { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 已重载生效。"; } || ui_fail "SSH 语法预检失败，拦截重载。"
            echo -ne "\n${YELLOW}加固流程执行完毕。按任意键返回主控台菜单...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *) for n in $ri; do 
            if [ $n -ge 1 -a $n -le $COUNT ] 2>/dev/null; then
                [ "${SELECTED[$n]}" == "TRUE" ] && SELECTED[$n]="FALSE" || SELECTED[$n]="TRUE"
            fi
        done ;;
    esac
done
