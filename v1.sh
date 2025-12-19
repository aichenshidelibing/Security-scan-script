#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v17.3 智慧感知版)
# 特性：全量 26 项修复 | 环境自适应 UI | 智能端口管理 | 逻辑返回主菜单

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
    I_OK="✅"; I_WARN="⚠️ "; I_FAIL="❌"; I_INFO="ℹ️ "; I_FIX="🔧"
else
    I_OK="[  OK  ]"; I_WARN="[ WARN ]"; I_FAIL="[ FAIL ]"; I_INFO="[ INFO ]"; I_FIX="[ FIX ]"
fi
# ------------------------------------

# --- 变量与配置 ---
REPORT="/root/security_audit_report.txt"
BACKUP_DIR="/root/security_backup_$(date +'%Y%m%d_%H%M%S')"
mkdir -p "$BACKUP_DIR"

# 数据存储
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0
MSG="" 

# --- 辅助工具 ---
log() { echo "[$(date +'%T')] $*" >> "$REPORT"; }
backup_file() { [ -f "$1" ] && cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak" && log "Backup $1"; }
ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}${I_WARN} $*${RESET}"; }

# 获取当前 SSH 端口
CURRENT_SSH_PORT=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
TARGET_SSH_PORT="$CURRENT_SSH_PORT"

# 注册函数
add_item() {
    COUNT=$((COUNT+1))
    IDS[$COUNT]=$COUNT
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

# --- 1. 审计初始化 (Audit - 完整 26 项) ---
init_audit() {
    # SSH 基础
    add_item "强制 SSH 协议 V2" "修复古老漏洞" "无" "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
    add_item "开启公钥认证支持" "允许密钥登录" "无" "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止空密码登录" "防止无密登录" "无" "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"
    add_item "修改 SSH 默认端口 (当前:$CURRENT_SSH_PORT)" "避开扫描" "需记新端口" "[ \"$CURRENT_SSH_PORT\" != \"22\" ]" "TRUE"

    # SSH 进阶
    add_item "禁用交互式认证" "防密码尝试" "影响部分工具" "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防会话劫持" "自动断连" "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "合规警告" "无" "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防 Shell 绕过" "无" "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    
    # 账号与密码
    add_item "强制 10 位混合密码" "防弱口令" "改密需数字+大小写" "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"
    add_item "密码修改最小间隔" "防频繁改密" "7天内禁改" "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "终端安全" "闲置自动退" "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # 文件权限
    add_item "修正 /etc/passwd" "设为 644" "无" "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "设为 600" "无" "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "设为 600" "无" "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    add_item "修正 authorized_keys" "设为 600" "无" "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    
    # 高危清理
    add_item "锁定异常 UID=0" "清后门" "影响自建管理" "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "提权需密" "影响自动化" "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "防提权" "禁ping/mount" "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel" "禁普通切Root" "需加入wheel组" "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"

    # 内核与网络
    add_item "网络内核防欺骗" "防重定向" "IPv6可能受限" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防DDoS" "无" "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '1'" "FALSE"
    add_item "禁用高危协议" "封堵漏洞" "电信应用受限" "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"

    # 服务与日志
    add_item "时间同步(Chrony)" "对准时间" "无" "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防爆盘" "保留历史有限" "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null" "FALSE"
    add_item "Fail2ban 最佳防护" "防暴力破解" "输错5次封1h" "grep -q 'bantime = 1h' /etc/fail2ban/jail.local 2>/dev/null" "FALSE"
    add_item "每日自动更新" "修补漏洞" "版本微变" "systemctl is-active --quiet unattended-upgrades || systemctl is-active --quiet dnf-automatic.timer" "FALSE"
}

# --- 2. 修复逻辑 (Fix) ---
cleanup_specific_ssh_port() {
    local delete_port="$1"
    local cfg="/etc/ssh/sshd_config"
    if [[ -n "$delete_port" ]] && [[ "$delete_port" != "$TARGET_SSH_PORT" ]]; then
        ui_info "清理旧端口配置: Port $delete_port ..."
        backup_file "$cfg"
        sed -i "/^[[:space:]]*Port[[:space:]]\+${delete_port}\b/d" "$cfg"
    fi
}

apply_fix() {
    local id=$1
    local title="${TITLES[$id]}"
    echo -e "   ${CYAN}${I_FIX} 执行修复: $title ...${RESET}"
    
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        
        *"修改 SSH 默认端口"*)
            read -p "   请输入新端口 (回车随机 20000-60000): " input_port
            TARGET_SSH_PORT=${input_port:-$(shuf -i 20000-60000 -n 1)}
            if [[ "$TARGET_SSH_PORT" =~ ^[0-9]+$ ]]; then
                echo "Port $TARGET_SSH_PORT" >> /etc/ssh/sshd_config
                command -v ufw >/dev/null && ufw allow $TARGET_SSH_PORT/tcp >/dev/null
                command -v firewall-cmd >/dev/null && firewall-cmd --add-port=$TARGET_SSH_PORT/tcp --permanent >/dev/null && firewall-cmd --reload >/dev/null
                ui_ok "新端口 $TARGET_SSH_PORT 已部署"
            fi ;;
            
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config; sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config; echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Monitored." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        
        "强制 10 位混合密码") 
            if command -v apt-get >/dev/null; then
                apt-get -qq install -y libpam-pwquality >/dev/null 2>&1
                [ -f /etc/pam.d/common-password ] && sed -ri 's/^password.*pam_pwquality\.so.*/password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0/' /etc/pam.d/common-password
            elif command -v dnf >/dev/null; then dnf install -y libpwquality >/dev/null 2>&1; fi ;;

        "密码修改最小间隔") sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs; chage --mindays 7 root ;;
        "Shell 自动注销(10m)") echo "export TMOUT=600" >> /etc/profile; echo "readonly TMOUT" >> /etc/profile ;;
        
        "修正 /etc/passwd") chmod 644 /etc/passwd ;;
        "修正 /etc/shadow") chmod 600 /etc/shadow ;;
        "修正 sshd_config") chmod 600 /etc/ssh/sshd_config ;;
        "修正 authorized_keys") [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys ;;
        
        "锁定异常 UID=0") awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd | xargs -r -I {} passwd -l {} ;;
        "移除 Sudo 免密") sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers; grep -l "NOPASSWD" /etc/sudoers.d/* 2>/dev/null | xargs -r sed -i 's/^/# /' ;;
        "清理危险 SUID") chmod u-s /bin/mount /bin/umount /usr/bin/newgrp /usr/bin/chsh 2>/dev/null ;;
        "限制 su 仅 wheel") if ! grep -q "pam_wheel.so" /etc/pam.d/su; then echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su; fi ;;
        
        "网络内核防欺骗") cat > /etc/sysctl.d/99-sec.conf <<EOF
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
EOF
            sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >> /etc/sysctl.conf 2>/dev/null ;;
        "禁用高危协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        
        "时间同步(Chrony)") 
            command -v apt-get >/dev/null && apt-get install -y chrony >/dev/null
            command -v dnf >/dev/null && dnf install -y chrony >/dev/null
            systemctl enable --now chronyd >/dev/null 2>&1 ;;
        
        "日志自动轮转(500M)") sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf; echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf; systemctl restart systemd-journald ;;
             
        "Fail2ban 最佳防护")
             command -v apt-get >/dev/null && apt-get install -y fail2ban >/dev/null
             cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
EOF
             systemctl enable --now fail2ban >/dev/null 2>&1 ;;
             
        "每日自动更新")
             command -v apt-get >/dev/null && apt-get install -y unattended-upgrades >/dev/null
             command -v dnf >/dev/null && dnf install -y dnf-automatic >/dev/null && systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 ;;
    esac
}

# --- 3. 交互主流程 ---
ui_info "正在扫描系统配置..."
init_audit

while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID  |  修复开关   |  检测结果${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    has_risky_selected="FALSE"
    for ((i=1; i<=COUNT; i++)); do
        S_TXT=$( [ "${STATUS[$i]}" == "PASS" ] && echo -e "${GREEN}${I_OK} 通过${RESET}" || echo -e "${RED}${I_FAIL} 未通过${RESET}" )
        SEL_ICON=$( [ "${SELECTED[$i]}" == "TRUE" ] && echo -e "${GREEN}[ ON  ]${RESET}" || echo -e "${GREY}[ OFF ]${RESET}" )
        printf "${GREY}%2d.${RESET}  %b  %s %-30s\n" "$i" "$SEL_ICON" "${WHITE}" "${TITLES[$i]}"
        printf "     ├─ 状态: %b   ${GREY}|${RESET} 优点: ${CYAN}%s${RESET}\n" "$S_TXT" "${PROS[$i]}"
        printf "     └─ 风险: ${RED}%s${RESET}\n" "${RISKS[$i]}"
        echo "" 
        [ "${SELECTED[$i]}" == "TRUE" ] && [ "${IS_RISKY[$i]}" == "TRUE" ] && has_risky_selected="TRUE"
    done
    
    echo "${BLUE}================================================================================${RESET}"
    [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} 状态更新: $MSG${RESET}"; MSG=""; }
    echo -e "指令: ${YELLOW}a${RESET}=全选 | ${YELLOW}n${RESET}=全不选 | ${RED}r${RESET}=执行修复 | ${CYAN}q${RESET}=返回"
    echo -ne "请输入编号翻转状态或指令: "
    read -r RawInput 
    input=$(echo "$RawInput" | tr ',' ' ' | xargs)

    case "$input" in
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已全选" ;;
        n|N) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="FALSE"; done; MSG="已清空" ;;
        q|Q) clear; exit 0 ;;
        r|R) 
            if [ "$has_risky_selected" == "TRUE" ]; then
                echo -ne "${RED}${I_WARN} 确认执行 [高危] 项目? (输入 yes 继续): ${RESET}"; read confirm
                [ "$confirm" != "yes" ] && { MSG="操作取消"; continue; }
            fi
            echo ""; ui_info "正在执行加固流程..."
            for ((i=1; i<=COUNT; i++)); do [ "${SELECTED[$i]}" == "TRUE" ] && apply_fix "$i"; done
            
            # 服务重启
            echo -e "\n${YELLOW}应用更改：${RESET} 1.重载SSH(推荐) 2.重启SSH 3.重启系统 0.暂不"
            read -p "选择 (默认1): " FINAL
            if [ "${FINAL:-1}" != "0" ] && [[ "$TARGET_SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
                cleanup_specific_ssh_port "$CURRENT_SSH_PORT"
            fi
            case "${FINAL:-1}" in
                1) systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH已重载" ;;
                2) systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; ui_ok "SSH已重启" ;;
                3) ui_warn "系统重启中..."; reboot ;;
            esac
            echo -ne "\n${YELLOW}${I_INFO} 加固完成。按任意键返回主控台...${RESET}"; read -n 1 -s -r; exit 0 ;;
        *)
            for num in $input; do
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ]; then
                    [ "${SELECTED[$num]}" == "TRUE" ] && SELECTED[$num]="FALSE" || SELECTED[$num]="TRUE"
                fi
            done ;;
    esac
done
