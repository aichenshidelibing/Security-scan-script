#!/usr/bin/env bash
# v1.sh - Linux 基础安全加固 (v17.0 Final)
# 包含：10位密码适配 | 文件权限独立修复 | 端口智能清理 | 完整交互反馈

set -u
export LC_ALL=C

# --- 变量与配置 ---
REPORT="/root/security_audit_report.txt"
BACKUP_DIR="/root/security_backup_$(date +'%Y%m%d_%H%M%S')"
mkdir -p "$BACKUP_DIR"

# 颜色定义
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m'); 
GREY=$(printf '\033[90m'); CYAN=$(printf '\033[36m'); WHITE=$(printf '\033[37m'); RESET=$(printf '\033[0m')
BOLD=$(printf '\033[1m')

# 数据存储
declare -a IDS TITLES PROS RISKS STATUS SELECTED IS_RISKY
COUNT=0
MSG="" 

# --- 0. 预检：获取当前 SSH 端口 ---
CURRENT_SSH_PORT=$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
TARGET_SSH_PORT="$CURRENT_SSH_PORT"

# --- 辅助工具 ---
log() { echo "[$(date +'%T')] $*" >> "$REPORT"; }
backup_file() { [ -f "$1" ] && cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak" && log "Backup $1"; }
ui_info() { echo -e "${CYAN}ℹ️  $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}✅ $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}⚠️  $*${RESET}"; }

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
        # 智能逻辑：非高危项自动勾选，高危项手动勾选
        if [ "$5" == "TRUE" ]; then SELECTED[$COUNT]="FALSE"; else SELECTED[$COUNT]="TRUE"; fi
    fi
}

# --- 1. 审计阶段 (Audit) ---
# 初始化审计列表
init_audit() {
    # === SSH 基础安全 ===
    add_item "强制 SSH 协议 V2" "修复古老漏洞" "无副作用" \
        "grep -q '^Protocol 2' /etc/ssh/sshd_config" "FALSE"
        
    add_item "开启公钥认证支持" "允许使用密钥登录" "无副作用" \
        "grep -q '^PubkeyAuthentication yes' /etc/ssh/sshd_config" "FALSE"

    add_item "禁止空密码登录" "防止无密账户被登录" "无副作用" \
        "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config" "FALSE"

    add_item "修改 SSH 默认端口 (当前:$CURRENT_SSH_PORT)" "避开全网 99% 扫描" "需放行防火墙/记新端口" \
        "[ \"$CURRENT_SSH_PORT\" != \"22\" ]" "TRUE"

    # === SSH 进阶防护 ===
    add_item "禁用交互式认证" "强制密钥或特定密码" "可能影响部分自动化工具" \
        "grep -q '^KbdInteractiveAuthentication no' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 空闲超时(10m)" "防挂机被劫持" "长连接会自动断开" \
        "grep -q '^ClientAliveInterval 600' /etc/ssh/sshd_config" "FALSE"
    add_item "SSH 登录 Banner" "满足合规要求" "无副作用" \
        "grep -q '^Banner' /etc/ssh/sshd_config" "FALSE"
    add_item "禁止环境篡改" "防绕过 Shell 限制" "无副作用" \
        "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config" "FALSE"
    
    # === 账户安全与密码策略 ===
    # [适配] 最小长度10位，去除符号强制，保留大小写数字要求
    add_item "强制复杂密码策略" "防弱口令(长度10+混合)" "改密码必须含大小写+数字" \
        "grep -q 'minlen=10' /etc/pam.d/common-password 2>/dev/null || grep -q 'minlen=10' /etc/pam.d/system-auth 2>/dev/null" "FALSE"

    add_item "密码修改最小间隔" "防止盗号后频繁改密" "7天内无法改密码" \
        "grep -q 'PASS_MIN_DAYS[[:space:]]*7' /etc/login.defs" "FALSE"
    add_item "Shell 自动注销(10m)" "本地终端挂机自动退" "本地操作需注意时间" \
        "grep -q 'TMOUT=600' /etc/profile" "FALSE"

    # === [关键] 文件权限独立检查 ===
    add_item "修正 /etc/passwd" "权限设为 644" "无副作用" \
        "[ \"\$(stat -c %a /etc/passwd)\" == \"644\" ]" "FALSE"
    add_item "修正 /etc/shadow" "权限设为 600" "无副作用" \
        "[ \"\$(stat -c %a /etc/shadow)\" == \"600\" ]" "FALSE"
    add_item "修正 sshd_config" "权限设为 600" "无副作用" \
        "[ \"\$(stat -c %a /etc/ssh/sshd_config)\" == \"600\" ]" "FALSE"
    # 检测 authorized_keys (如果文件不存在算通过，存在且权限对也算通过)
    add_item "修正 authorized_keys" "权限设为 600" "无副作用" \
        "[ ! -f /root/.ssh/authorized_keys ] || [ \"\$(stat -c %a /root/.ssh/authorized_keys)\" == \"600\" ]" "FALSE"
    
    # === 高危权限与提权 ===
    add_item "锁定异常 UID=0" "清除后门账户" "误伤自建管理员" \
        "[ -z \"\$(awk -F: '(\$3 == 0 && \$1 != \"root\"){print \$1}' /etc/passwd)\" ]" "TRUE"
    add_item "移除 Sudo 免密" "执行sudo需输密码" "自动化脚本可能失效" \
        "! grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d >/dev/null 2>&1" "TRUE"
    add_item "清理危险 SUID" "防普通用户提权" "普通用户无法ping/mount" \
        "[ ! -u /bin/mount ]" "FALSE"
    add_item "限制 su 仅 wheel" "禁止普通用户切Root" "管理员需加入wheel组" \
        "grep -q 'pam_wheel.so' /etc/pam.d/su" "FALSE"

    # === 内核与网络 ===
    add_item "网络内核防欺骗" "防中间人/重定向" "IPv6 SLAAC 将失效/部分VPS断网" \
        "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'" "FALSE"
    add_item "开启 SYN Cookie" "防御 DDoS 洪水攻击" "无副作用" \
        "sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q '= 1'" "FALSE"
    add_item "禁用高危协议" "封堵内核漏洞" "特殊电信应用可能报错" \
        "[ -f /etc/modprobe.d/disable-uncommon.conf ]" "FALSE"

    # === 服务与日志 ===
    add_item "时间同步(Chrony)" "防证书/日志错误" "占用微小内存" \
        "command -v chronyd >/dev/null || systemctl is-active --quiet systemd-timesyncd" "FALSE"
    add_item "日志自动轮转(500M)" "防爆盘/自动删旧日志" "最多保留500M历史" \
        "grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null" "FALSE"
    
    add_item "Fail2ban 最佳防护" "自动封禁(1h/5次错误)" "输错5次密码封自己1h" \
        "grep -q 'bantime = 1h' /etc/fail2ban/jail.local 2>/dev/null" "FALSE"
        
    add_item "每日自动更新" "第一时间修补漏洞" "极低概率软件兼容问题" \
        "systemctl is-active --quiet unattended-upgrades || systemctl is-active --quiet dnf-automatic.timer" "FALSE"
}

# --- 2. 修复执行阶段 (Fix) ---
cleanup_specific_ssh_port() {
    local delete_port="$1"
    local cfg="/etc/ssh/sshd_config"
    if [[ -n "$delete_port" ]] && [[ "$delete_port" != "$TARGET_SSH_PORT" ]]; then
        ui_info "正在从配置中移除旧端口: Port $delete_port (保留其他端口)..."
        backup_file "$cfg"
        sed -i "/^[[:space:]]*Port[[:space:]]\+${delete_port}\b/d" "$cfg"
        ui_ok "旧端口 $delete_port 已移除"
    fi
}

apply_fix() {
    local id=$1
    local title="${TITLES[$id]}"
    echo -e "   ${CYAN}>> 执行修复: $title ...${RESET}"
    
    case "$title" in
        "强制 SSH 协议 V2") sed -i '/^Protocol/d' /etc/ssh/sshd_config; echo "Protocol 2" >> /etc/ssh/sshd_config ;;
        "开启公钥认证支持") sed -i '/^PubkeyAuthentication/d' /etc/ssh/sshd_config; echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config ;;
        "禁止空密码登录") sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config; echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;;
        
        *"修改 SSH 默认端口"*)
            echo ""; echo -e "   ${YELLOW}当前端口: $CURRENT_SSH_PORT${RESET}"
            read -p "   请输入新端口 (回车随机生成 20000-60000): " input_port
            if [ -z "$input_port" ]; then TARGET_SSH_PORT=$(shuf -i 20000-60000 -n 1); echo -e "   已生成随机端口: ${GREEN}$TARGET_SSH_PORT${RESET}"; else TARGET_SSH_PORT=$input_port; fi
            if [[ "$TARGET_SSH_PORT" =~ ^[0-9]+$ ]]; then
                echo "Port $TARGET_SSH_PORT" >> /etc/ssh/sshd_config
                command -v ufw >/dev/null && ufw allow $TARGET_SSH_PORT/tcp >/dev/null
                command -v firewall-cmd >/dev/null && firewall-cmd --add-port=$TARGET_SSH_PORT/tcp --permanent >/dev/null && firewall-cmd --reload >/dev/null
                ui_ok "新端口 $TARGET_SSH_PORT 已添加 (旧端口 $CURRENT_SSH_PORT 将在重启时移除)"
            else ui_warn "端口无效，跳过。"; TARGET_SSH_PORT="$CURRENT_SSH_PORT"; fi ;;
            
        "禁用交互式认证") sed -i '/^KbdInteractiveAuthentication/d' /etc/ssh/sshd_config; echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config ;;
        "SSH 空闲超时(10m)") sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config; echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config; sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config; echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config ;;
        "SSH 登录 Banner") echo "Access Monitored." > /etc/ssh/banner_warn; sed -i '/^Banner/d' /etc/ssh/sshd_config; echo "Banner /etc/ssh/banner_warn" >> /etc/ssh/sshd_config ;;
        "禁止环境篡改") sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config; echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;;
        
        "强制复杂密码策略") 
            if command -v apt-get >/dev/null; then
                apt-get -qq install -y libpam-pwquality >/dev/null 2>&1
                if [ -f /etc/pam.d/common-password ]; then
                    # 适配: minlen=10, ocredit=0 (不强制特殊符号), 但保留 ucredit/lcredit/dcredit=-1 (必须有大小写数字)
                    sed -ri 's/^password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so.*/password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0/' /etc/pam.d/common-password
                fi
            elif command -v dnf >/dev/null; then
                dnf install -y libpwquality >/dev/null 2>&1
            fi ;;

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
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_ra = 0
EOF
            sysctl --system >/dev/null 2>&1 ;;
        "开启 SYN Cookie") sysctl -w net.ipv4.tcp_syncookies=1 >> /etc/sysctl.conf 2>/dev/null ;;
        "禁用高危协议") echo -e "install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true" > /etc/modprobe.d/disable-uncommon.conf ;;
        
        "时间同步(Chrony)") 
            command -v apt-get >/dev/null && (apt-get update -qq; apt-get install -y chrony >/dev/null)
            command -v dnf >/dev/null && dnf install -y chrony >/dev/null
            systemctl enable --now chronyd >/dev/null 2>&1 ;;
        
        "日志自动轮转(500M)") 
             sed -i '/^SystemMaxUse/d' /etc/systemd/journald.conf
             echo "SystemMaxUse=500M" >> /etc/systemd/journald.conf
             systemctl restart systemd-journald ;;
             
        "Fail2ban 最佳防护")
             command -v apt-get >/dev/null && apt-get install -y fail2ban >/dev/null
             command -v dnf >/dev/null && dnf install -y epel-release fail2ban >/dev/null
             cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8
[sshd]
enabled = true
backend = systemd
EOF
             systemctl enable --now fail2ban >/dev/null 2>&1 ;;
             
        "每日自动更新")
             command -v apt-get >/dev/null && apt-get install -y unattended-upgrades >/dev/null
             command -v dnf >/dev/null && dnf install -y dnf-automatic >/dev/null && systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 ;;
    esac
}

# --- 3. 交互主流程 ---
# 初始化审计
ui_info "正在扫描系统配置 (当前 SSH 端口: $CURRENT_SSH_PORT)..."
init_audit

while true; do
    clear
    echo "${BLUE}================================================================================${RESET}"
    echo "${BOLD} ID  |  修复开关   |  检测结果${RESET}"
    echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    
    has_risky_selected="FALSE"
    
    for ((i=1; i<=COUNT; i++)); do
        if [ "${STATUS[$i]}" == "PASS" ]; then S_TXT="${GREEN}✅ 通过 (安全)${RESET}"; else S_TXT="${RED}❌ 未通过${RESET}"; fi
        if [ "${SELECTED[$i]}" == "TRUE" ]; then SEL_ICON="${GREEN}[ ON  ]${RESET}"; else SEL_ICON="${GREY}[ OFF ]${RESET}"; fi
        if [ "${IS_RISKY[$i]}" == "TRUE" ]; then T_COLOR="${YELLOW}"; else T_COLOR="${WHITE}"; fi
        
        printf "${GREY}%2d.${RESET}  %b  %b%s${RESET}\n" "$i" "$SEL_ICON" "$T_COLOR" "${TITLES[$i]}"
        printf "     ├─ 状态: %b   ${GREY}|${RESET} 优点: ${CYAN}%s${RESET}\n" "$S_TXT" "${PROS[$i]}"
        printf "     └─ 风险: ${RED}%s${RESET}\n" "${RISKS[$i]}"
        echo "" 
        
        if [ "${SELECTED[$i]}" == "TRUE" ] && [ "${IS_RISKY[$i]}" == "TRUE" ]; then has_risky_selected="TRUE"; fi
    done
    
    echo "${BLUE}================================================================================${RESET}"
    if [ -n "$MSG" ]; then
        echo -e "${YELLOW}💬 状态更新: $MSG${RESET}"
        MSG="" 
        echo "${BLUE}--------------------------------------------------------------------------------${RESET}"
    fi

    echo -e "提示: ${GREEN}[ ON  ]${RESET} 为准备修复 (已智能勾选推荐项)"
    echo -e "示例: 输入 ${GREEN}1 3 5${RESET} 可翻转开关状态 (开 ↔ 关)"
    echo -e "指令: ${YELLOW}a${RESET}=全选 | ${YELLOW}n${RESET}=全不选 | ${RED}r${RESET}=执行修复 | ${CYAN}q${RESET}=退出"
    echo -ne "请输入: "
    
    read -r RawInput 
    input=$(echo "$RawInput" | tr ',' ' ' | xargs)

    case "$input" in
        a|A) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="TRUE"; done; MSG="已【全选】所有项目" ;;
        n|N) for ((i=1; i<=COUNT; i++)); do SELECTED[$i]="FALSE"; done; MSG="已【取消】所有选择" ;;
        q|Q) clear; exit 0 ;;
        r|R) 
            if [ "$has_risky_selected" == "TRUE" ]; then
                echo ""; echo -e "${RED}⚠️  警告：您选中了 [高危] 项目 (如改端口/锁账户/禁免密等) ${RESET}"
                echo -ne "${YELLOW}    确认执行吗? (输入 yes 继续): ${RESET}"
                read confirm
                if [ "$confirm" != "yes" ]; then MSG="操作已取消"; continue; fi
            fi

            echo ""; ui_info "开始修复..."
            for ((i=1; i<=COUNT; i++)); do
                if [ "${SELECTED[$i]}" == "TRUE" ]; then apply_fix "$i"; fi
            done
            
            echo ""; ui_info "四、服务重启 (应用更改)"
            echo "1. 重载 SSH (Reload) [推荐] - 配置生效，不断连"
            echo "2. 重启 SSH (Restart) - 可能断开"
            echo "3. 重启服务器 (Reboot) - 应用内核更新"
            echo "0. 暂不重启"
            echo -ne "${YELLOW}请选择 (默认1): ${RESET}"; read -r FINAL
            
            if [ "${FINAL:-1}" != "0" ] && [[ "$TARGET_SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
                cleanup_specific_ssh_port "$CURRENT_SSH_PORT"
            fi

            case "${FINAL:-1}" in
                1) systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1; ui_ok "SSH 服务已重载" ;;
                2) systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; ui_ok "SSH 服务已重启" ;;
                3) ui_info "正在重启..."; reboot ;;
                *) ui_warn "跳过重启。注意：如修改了端口，旧端口暂未禁用。" ;;
            esac
            
            echo ""
            ui_ok "v1.sh 运行结束。日志: $REPORT"
            ui_info "下一步：运行 ./v2.sh 配置密钥登录，或 ./v3.sh 设置禁Ping。"
            exit 0 ;;
        
        *)
            MSG=""
            for num in $input; do
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$COUNT" ]; then
                    title="${TITLES[$num]}"
                    if [ "${SELECTED[$num]}" == "TRUE" ]; then 
                        SELECTED[$num]="FALSE"
                        MSG="${MSG} ${RED}[已关闭]${RESET} $title;"
                    else 
                        SELECTED[$num]="TRUE"
                        MSG="${MSG} ${GREEN}[已开启]${RESET} $title;"
                    fi
                fi
            done
            if [ -z "$MSG" ]; then MSG="无效输入，请重新输入"; fi
            ;;
    esac
done