#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v1.sh - Linux 基础安全加固 (v42.1)

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

# =========================
# 基础约束
# =========================
if [ "$(id -u)" -ne 0 ]; then
  echo "[FAIL] 请使用 root 运行。"
  exit 1
fi

# =========================
# 信号/退出管理：避免二次暂停
# =========================
finish_trap() {
  echo -e "\n\033[33m[系统提示] 脚本执行结束。按回车键继续...\033[0m"
  read -r
}
trap finish_trap EXIT
trap 'trap - EXIT; echo -e "\n\033[33m[用户强制终止] 正在返回主菜单...\033[0m"; exit 0' INT

# =========================
# UI 自适应
# =========================
[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m')
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✅" || echo "[ OK ]")
I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "ℹ️ " || echo "[INFO]")
I_WAIT=$([ "$USE_EMOJI" == "1" ] && echo "⏳" || echo "[WAIT]")
I_NET=$([ "$USE_EMOJI" == "1" ] && echo "🌐" || echo "[NET]")
I_WALL=$([ "$USE_EMOJI" == "1" ] && echo "🧱" || echo "[FW]")
I_FIX=$([ "$USE_EMOJI" == "1" ] && echo "🛠️ " || echo "[FIX ]")
I_LIST=$([ "$USE_EMOJI" == "1" ] && echo "📋" || echo "[LIST]")

ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

is_tty() { [ -t 1 ]; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# =========================
# 会话模式：远程/本地（用于提示和更严格护栏）
# =========================
REMOTE_SESSION=0
[ -n "${SSH_CONNECTION:-}" ] && REMOTE_SESSION=1
[ -n "${SSH_TTY:-}" ] && REMOTE_SESSION=1

# =========================
# spinner（TTY 才显示）
# =========================
show_spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'
  is_tty || { wait "$pid"; return $?; }
  while kill -0 "$pid" 2>/dev/null; do
    printf " [%c]  " "${spinstr:0:1}"
    spinstr="${spinstr:1}${spinstr:0:1}"
    sleep "$delay"
    printf "\b\b\b\b\b\b"
  done
  printf "    \b\b\b\b"
  wait "$pid"
}

# =========================
# 系统识别/包管理器
# =========================
OS_ID="unknown"; OS_VER="unknown"; OS_LIKE=""
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VER="${VERSION_ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
fi

pm_detect() {
  if has_cmd apt-get; then echo "apt"
  elif has_cmd dnf; then echo "dnf"
  elif has_cmd yum; then echo "yum"
  else echo "none"
  fi
}
PM="$(pm_detect)"

# =========================
# 备份（可回滚 + 自动裁剪 + 自动停用防爆盘）
# =========================
RUN_ID="$(date +%Y%m%d-%H%M%S)"
BACKUP_BASE="/var/backups/sec-script"
BACKUP_DIR="${BACKUP_BASE}/${RUN_ID}"
BACKUP_MAX_RUNS=6
BACKUP_MAX_MB=24
declare -A BACKED_UP=()

disk_free_kb_root() { df -Pk / | awk 'NR==2{print $4}'; }

backup_enabled() {
  # 空间 <300MB 不备份，防止小盘爆炸
  local free_kb
  free_kb="$(disk_free_kb_root)"
  [ -n "$free_kb" ] || return 1
  [ "$free_kb" -ge 307200 ] || return 1
  return 0
}

backup_prune() {
  [ -d "$BACKUP_BASE" ] || return 0
  # 保留最近 N 次
  local runs count
  runs="$(ls -1 "$BACKUP_BASE" 2>/dev/null | sort || true)"
  count="$(printf "%s\n" "$runs" | sed '/^$/d' | wc -l | awk '{print $1}')"
  if [ "${count:-0}" -gt "$BACKUP_MAX_RUNS" ]; then
    local del_n=$((count - BACKUP_MAX_RUNS))
    printf "%s\n" "$runs" | sed '/^$/d' | sort | head -n "$del_n" | while read -r old; do
      rm -rf "${BACKUP_BASE:?}/$old" 2>/dev/null || true
    done
  fi
  # 控制总大小
  local total_kb max_kb oldest
  total_kb="$(du -sk "$BACKUP_BASE" 2>/dev/null | awk '{print $1}')"
  max_kb=$((BACKUP_MAX_MB * 1024))
  while [ -n "${total_kb:-}" ] && [ "$total_kb" -gt "$max_kb" ]; do
    oldest="$(ls -1 "$BACKUP_BASE" 2>/dev/null | sort | head -n 1 || true)"
    [ -n "$oldest" ] || break
    rm -rf "${BACKUP_BASE:?}/$oldest" 2>/dev/null || true
    total_kb="$(du -sk "$BACKUP_BASE" 2>/dev/null | awk '{print $1}')"
  done
}

backup_file() {
  local f="$1"
  [ -e "$f" ] || return 0
  backup_enabled || return 0
  [ "${BACKED_UP[$f]+x}" = "x" ] && return 0
  mkdir -p "$BACKUP_DIR" 2>/dev/null || return 0
  local safe
  safe="$(printf "%s" "$f" | sed 's#/#__#g; s#^__##')"
  cp -a "$f" "${BACKUP_DIR}/${safe}.bak" 2>/dev/null || true
  BACKED_UP["$f"]=1
}

# =========================
# 幂等写配置工具：避免重复追加/膨胀
# =========================
ensure_line() {
  local file="$1" line="$2"
  backup_file "$file"
  touch "$file" 2>/dev/null || return 1
  grep -Fqx "$line" "$file" 2>/dev/null && return 0
  printf "%s\n" "$line" >>"$file"
}

set_kv_space() {
  local file="$1" key="$2" value="$3"
  backup_file "$file"
  touch "$file" 2>/dev/null || return 1
  if grep -qiE "^[[:space:]]*${key}[[:space:]]+" "$file" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*(${key})[[:space:]]+.*#\1 ${value}#I" "$file"
  else
    printf "%s %s\n" "$key" "$value" >>"$file"
  fi
}

set_kv_eq() {
  local file="$1" key="$2" value="$3"
  backup_file "$file"
  touch "$file" 2>/dev/null || return 1
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*(${key})[[:space:]]*=.*#\1 = ${value}#" "$file"
  else
    printf "%s = %s\n" "$key" "$value" >>"$file"
  fi
}

ensure_chmod() {
  local mode="$1" path="$2"
  [ -e "$path" ] || return 0
  local cur
  cur="$(stat -c %a "$path" 2>/dev/null || echo "")"
  [ "$cur" = "$mode" ] && return 0
  backup_file "$path"
  chmod "$mode" "$path" 2>/dev/null || return 1
}

# =========================
# 网络态势感知（仅展示）
# =========================
NET_BANNER=""
init_network_insight() {
  echo -ne "${CYAN}${I_WAIT} 正在进行网络与防火墙态势感知 (约需 2 秒)...${RESET}"

  local fw_status="${GREEN}未发现活跃规则${RESET}"
  if has_cmd ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    fw_status="${YELLOW}UFW 运行中${RESET}"
  fi
  if has_cmd firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q "running"; then
    fw_status="${YELLOW}Firewalld 运行中${RESET}"
  fi
  if has_cmd iptables; then
    local lines
    lines="$(iptables -L INPUT 2>/dev/null | wc -l | awk '{print $1}')"
    [ "${lines:-0}" -gt 10 ] && fw_status="${YELLOW}Iptables 可能活跃${RESET}"
  fi

  local net_status=""
  if has_cmd ping && ( ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 ); then
    net_status="${GREEN}ICMP${RESET}"
  else
    net_status="${RED}ICMP(阻断/不可用)${RESET}"
  fi
  if has_cmd curl && ( curl -fsS --connect-timeout 2 https://www.baidu.com >/dev/null 2>&1 || curl -fsS --connect-timeout 2 https://www.cloudflare.com >/dev/null 2>&1 ); then
    net_status="$net_status | ${GREEN}TCP${RESET}"
  else
    net_status="$net_status | ${RED}TCP(阻断/不可用)${RESET}"
  fi
  if has_cmd timeout && has_cmd nslookup && ( timeout 2 nslookup cloudflare.com 1.1.1.1 >/dev/null 2>&1 || timeout 2 nslookup baidu.com 223.5.5.5 >/dev/null 2>&1 ); then
    net_status="$net_status | ${GREEN}UDP${RESET}"
  else
    net_status="$net_status | ${RED}UDP(阻断/不可用)${RESET}"
  fi

  NET_BANNER="${BLUE}================================================================================${RESET}\n"
  NET_BANNER+="${I_WALL} 内部防火墙: [ $fw_status ]   ${I_NET} 出站连通性: [ $net_status ]\n"
  NET_BANNER+="${GREY}   (提示: 若连通性异常，请同时检查云厂商安全组/ACL/路由策略)${RESET}"
  echo -e "\r                                                               \r"
}

# =========================
# 包管理锁：安全处理（不硬杀，不删锁）
# =========================
wait_pkg_lock() {
  local max_wait="${1:-25}"
  local waited=0

  if [ "$PM" = "apt" ]; then
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
      [ "$waited" -ge "$max_wait" ] && return 1
      sleep 1; waited=$((waited+1))
    done
    return 0
  fi

  if [ "$PM" = "dnf" ] || [ "$PM" = "yum" ]; then
    if pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1; then
      while ( pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 ); do
        [ "$waited" -ge "$max_wait" ] && return 1
        sleep 1; waited=$((waited+1))
      done
    fi
    return 0
  fi

  return 0
}

# =========================
# EOL 判定/提示（不做破坏性换源）
# =========================
is_eol() {
  if [ "$OS_ID" = "debian" ]; then
    local maj="${OS_VER%%.*}"
    [ -n "$maj" ] && [ "$maj" -lt 10 ] && return 0
  fi
  if [ "$OS_ID" = "ubuntu" ]; then
    local maj="${OS_VER%%.*}"
    [ -n "$maj" ] && [ "$maj" -lt 16 ] && return 0
  fi
  if [ "$OS_ID" = "centos" ]; then
    local maj="${OS_VER%%.*}"
    [ -n "$maj" ] && [ "$maj" -lt 7 ] && return 0
  fi
  return 1
}

fix_eol_sources() {
  if [ "$PM" = "apt" ] && [ -f /etc/debian_version ]; then
    local dver
    dver="$(cut -d. -f1 </etc/debian_version 2>/dev/null || true)"
    if [ -n "$dver" ] && [ "$dver" -lt 10 ]; then
      ui_warn "检测到 Debian 旧版(EOL)，apt 可能无法正常更新；必要时建议切 archive 源。"
    fi
  fi
  if [ "$PM" = "yum" ] && [ -f /etc/centos-release ]; then
    local cmaj
    cmaj="$(rpm -q --qf "%{VERSION}" -f /etc/centos-release 2>/dev/null | cut -d. -f1 || true)"
    [ "$cmaj" = "7" ] && ui_warn "检测到 CentOS 7(EOL)，yum 源可能不稳定；必要时建议切 Vault 源。"
  fi
}

# =========================
# DNS 智能检测/自愈：默认不改；坏了才修；修时尽量就近
# =========================
resolv_is_managed() {
  local target
  target="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
  printf "%s" "$target" | grep -qiE "systemd/resolve|systemd-resolved|NetworkManager" && return 0
  return 1
}

dns_sanity_ok() {
  # 解析正常：返回 0；解析异常：返回 1
  # 优先不依赖 DNS 本身（但最终还是要通过“解析某个域名”判断是否恢复）
  if has_cmd timeout && has_cmd getent; then
    timeout 2 getent ahosts cloudflare.com >/dev/null 2>&1 && return 0
    timeout 2 getent ahosts www.baidu.com  >/dev/null 2>&1 && return 0
    return 1
  fi
  if has_cmd timeout && has_cmd nslookup; then
    timeout 2 nslookup cloudflare.com >/dev/null 2>&1 && return 0
    timeout 2 nslookup baidu.com      >/dev/null 2>&1 && return 0
    return 1
  fi
  # 没有解析工具：不强行判坏，避免误触发改 DNS
  return 0
}

ping_ms() {
  # 返回整数 ms；失败返回 9999
  has_cmd ping || { echo 9999; return 0; }
  local ip="$1" out
  out="$(ping -c 1 -W 1 "$ip" 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1}' | cut -d. -f1)"
  [ -n "$out" ] && echo "$out" || echo 9999
}

dns_pick_profile() {
  # 输出：CN / GLOBAL / MIXED
  # DNS 坏掉时，用 RTT 选就近；ping 不可用则 MIXED
  if ! has_cmd ping; then
    echo "MIXED"; return 0
  fi
  local cn global
  cn="$(ping_ms 223.5.5.5)"
  global="$(ping_ms 1.1.1.1)"
  if [ "$cn" -ge 9999 ] && [ "$global" -ge 9999 ]; then
    echo "MIXED"; return 0
  fi
  if [ "$cn" -lt "$global" ]; then echo "CN"; else echo "GLOBAL"; fi
}

dns_repair() {
  ui_info "DNS 自愈：检测到解析异常，尝试修复..."
  backup_prune

  local profile dns
  profile="$(dns_pick_profile)"

  case "$profile" in
    CN)     dns="223.5.5.5 119.29.29.29" ;;
    GLOBAL) dns="1.1.1.1 8.8.8.8" ;;
    *)      dns="1.1.1.1 8.8.8.8 223.5.5.5 119.29.29.29" ;;
  esac

  # 优先 systemd-resolved（更不容易被覆盖）
  if has_cmd systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    local f="/etc/systemd/resolved.conf"
    backup_file "$f"
    touch "$f" 2>/dev/null || true

    if grep -qE '^[[:space:]]*DNS=' "$f" 2>/dev/null; then
      sed -i -E "s#^[[:space:]]*DNS=.*#DNS=${dns}#" "$f"
    else
      printf "\nDNS=%s\n" "$dns" >>"$f"
    fi
    systemctl restart systemd-resolved >/dev/null 2>&1 || true

    dns_sanity_ok && ui_ok "DNS 已恢复（resolved，模式：$profile）。" || ui_warn "已写入 resolved 配置，但解析仍异常（可能是网络/安全组/拦截）。"
    return 0
  fi

  # NetworkManager：不强改（避免把用户企业内网 DNS 直接覆盖）
  if has_cmd nmcli; then
    ui_warn "检测到 NetworkManager：为避免破坏连接配置，本脚本不强写 nmcli DNS。建议手工为对应连接设置 DNS。"
    return 0
  fi

  # 非托管 resolv.conf：可直接写，但先识别被接管则跳过
  if resolv_is_managed; then
    ui_warn "/etc/resolv.conf 可能被系统接管，已避免直接覆盖。"
    return 0
  fi

  local rc="/etc/resolv.conf"
  backup_file "$rc"
  {
    echo "# Generated by sec-script (DNS was broken)"
    for ns in $dns; do
      echo "nameserver $ns"
    done
  } >"$rc"

  dns_sanity_ok && ui_ok "DNS 已恢复（resolv.conf，模式：$profile）。" || ui_warn "已写入 resolv.conf，但解析仍异常（可能是网络层阻断）。"
  return 0
}

# =========================
# 安装/自愈：尽量不破坏系统
# =========================
APT_UPDATED=0
apt_update_once() {
  [ "$PM" = "apt" ] || return 0
  [ "$APT_UPDATED" -eq 1 ] && return 0
  wait_pkg_lock 25 || { ui_fail "包管理器被占用，稍后再试。"; return 1; }
  apt-get update >/dev/null 2>&1 || return 1
  APT_UPDATED=1
  return 0
}

smart_install() {
  local pkgs=("$@")
  [ "${#pkgs[@]}" -gt 0 ] || return 0

  wait_pkg_lock 25 || { ui_fail "包管理器被占用，稍后再试。"; return 1; }
  ui_info "安装组件: ${pkgs[*]} ..."

  local log="/tmp/sec_install_err.log"
  : >"$log" 2>/dev/null || true

  if [ "$PM" = "apt" ]; then
    apt_update_once || { ui_fail "apt update 失败（网络/源/锁）。"; return 1; }
    ( UCF_FORCE_CONFFOLD=1 apt-get install -y "${pkgs[@]}" ) >/dev/null 2>"$log" &
    show_spinner "$!"
    local rc=$?
    [ "$rc" -eq 0 ] || { ui_fail "安装失败：$(tail -n 3 "$log" 2>/dev/null | tr '\n' '; ')"; return 1; }
    return 0
  fi

  if [ "$PM" = "dnf" ]; then
    ( dnf install -y "${pkgs[@]}" ) >/dev/null 2>"$log" &
    show_spinner "$!"
    local rc=$?
    [ "$rc" -eq 0 ] || { ui_fail "安装失败：$(tail -n 3 "$log" 2>/dev/null | tr '\n' '; ')"; return 1; }
    return 0
  fi

  if [ "$PM" = "yum" ]; then
    ( yum install -y "${pkgs[@]}" ) >/dev/null 2>"$log" &
    show_spinner "$!"
    local rc=$?
    [ "$rc" -eq 0 ] || { ui_fail "安装失败：$(tail -n 3 "$log" 2>/dev/null | tr '\n' '; ')"; return 1; }
    return 0
  fi

  ui_fail "未识别到包管理器。"
  return 1
}

check_space() {
  local free_kb
  free_kb="$(disk_free_kb_root)"
  [ -n "$free_kb" ] || return 0
  [ "$free_kb" -lt 204800 ] && { ui_fail "磁盘不足 200MB，停止。"; return 1; }
  return 0
}

heal_environment() {
  ui_info "环境检查中..."
  backup_prune
  fix_eol_sources

  if [ "$PM" = "apt" ]; then
    wait_pkg_lock 25 || { ui_fail "包管理器被占用，稍后再试。"; return 1; }
    dpkg --configure -a >/dev/null 2>&1 || true
    apt-get install -f -y >/dev/null 2>&1 || true
  fi

  ui_ok "环境准备就绪。"
}

# =========================
# SSH：优先 drop-in + 语法检测 + 防锁死护栏
# =========================
SSH_MAIN="/etc/ssh/sshd_config"
SSH_D_DIR="/etc/ssh/sshd_config.d"
SSH_DROPIN="${SSH_D_DIR}/99-sec-script.conf"
SSH_BANNER="/etc/ssh/banner_warn"

ssh_has_dropin() {
  [ -d "$SSH_D_DIR" ] || return 1
  [ -f "$SSH_MAIN" ] || return 1
  grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSH_MAIN" 2>/dev/null && return 0
  return 1
}

ssh_write_setting() {
  local k="$1" v="$2"
  if ssh_has_dropin; then
    backup_file "$SSH_DROPIN"
    mkdir -p "$SSH_D_DIR" 2>/dev/null || true
    touch "$SSH_DROPIN" 2>/dev/null || true
    if grep -qiE "^[[:space:]]*${k}[[:space:]]+" "$SSH_DROPIN" 2>/dev/null; then
      sed -i -E "s#^[[:space:]]*(${k})[[:space:]]+.*#\1 ${v}#I" "$SSH_DROPIN"
    else
      printf "%s %s\n" "$k" "$v" >>"$SSH_DROPIN"
    fi
  else
    backup_file "$SSH_MAIN"
    sed -i -E "/^[[:space:]]*${k}[[:space:]]+/Id" "$SSH_MAIN" 2>/dev/null || true
    printf "%s %s\n" "$k" "$v" >>"$SSH_MAIN"
  fi
}

ssh_test() {
  has_cmd /usr/sbin/sshd || return 1
  /usr/sbin/sshd -t >/dev/null 2>&1
}

ssh_reload_safe() {
  if ssh_test; then
    systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true
    ui_ok "SSH 已重载。"
    return 0
  fi
  ui_fail "SSH 配置语法检测失败，已避免重载。"
  return 1
}

has_any_authorized_keys() {
  [ -s /root/.ssh/authorized_keys ] && return 0
  local u="${SUDO_USER:-}"
  if [ -n "$u" ] && [ -s "/home/$u/.ssh/authorized_keys" ]; then return 0; fi
  for p in /home/*/.ssh/authorized_keys; do
    [ -s "$p" ] && return 0
  done
  return 1
}

# =========================
# Swap
# =========================
check_swap_ok() {
  local s m
  s="$(free -m | awk '/^Swap:/ {print $2}')"
  m="$(free -m | awk '/^Mem:/ {print $2}')"
  [ -n "$s" ] || return 0
  [ -n "$m" ] || return 0
  if [ "$s" -eq 0 ] && [ "$m" -lt 4000 ]; then return 1; fi
  return 0
}

swap_apply() {
  if check_swap_ok; then ui_ok "Swap：无需处理。"; return 0; fi
  [ -e /swapfile ] && { ui_warn "发现 /swapfile 已存在，跳过创建。"; return 0; }
  dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null 2>&1
  swapon /swapfile >/dev/null 2>&1 || true
  grep -qE '^[[:space:]]*/swapfile[[:space:]]+' /etc/fstab 2>/dev/null || ensure_line /etc/fstab "/swapfile none swap sw 0 0"
  ui_ok "已创建 1GB Swap。"
}

# =========================
# sysctl
# =========================
SYSCTL_FILE="/etc/sysctl.d/99-sec-script.conf"
sysctl_apply() { sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1 || true; }

bbr_supported() {
  has_cmd sysctl || return 1
  sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr
}

# =========================
# 选择/审计结构（去 eval）
# =========================
declare -a TITLES PROS RISKS STATUS SELECTED IS_RISKY CHECK_FN APPLY_FN
COUNT=0; MSG=""
CUR_P="$(grep -E "^[[:space:]]*Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n 1)"
CUR_P="${CUR_P:-22}"

add_item() {
  COUNT=$((COUNT+1))
  TITLES[$COUNT]="$1"
  PROS[$COUNT]="$2"
  RISKS[$COUNT]="$3"
  CHECK_FN[$COUNT]="$4"
  APPLY_FN[$COUNT]="$5"
  IS_RISKY[$COUNT]="$6"

  if "${CHECK_FN[$COUNT]}"; then
    STATUS[$COUNT]="PASS"
    SELECTED[$COUNT]="FALSE"
  else
    STATUS[$COUNT]="FAIL"
    if [ "${IS_RISKY[$COUNT]}" = "TRUE" ]; then
      SELECTED[$COUNT]="FALSE"
    else
      SELECTED[$COUNT]="TRUE"
    fi
  fi
}

# =========================
# 检测函数
# =========================
chk_bbr() { sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qw bbr; }
chk_limits() { grep -qE '^[[:space:]]*\*[[:space:]]+soft[[:space:]]+nofile[[:space:]]+65535' /etc/security/limits.conf 2>/dev/null; }
chk_ipv4_pref() { grep -q 'precedence ::ffff:0:0/96 100' /etc/gai.conf 2>/dev/null; }
chk_swap() { check_swap_ok; }
chk_tools() { has_cmd curl && (has_cmd vim || has_cmd vi) && has_cmd unzip; }
chk_dns_ok() { dns_sanity_ok; }

chk_ssh_proto2() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^protocol 2'; }
chk_ssh_pubkey() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^pubkeyauthentication yes'; }
chk_ssh_empty_pw() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^permitemptypasswords no'; }
chk_ssh_port() { [ "$CUR_P" != "22" ]; }
chk_ssh_pw_auth_disabled() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'; }
chk_ssh_idle() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^clientaliveinterval 600'; }
chk_ssh_root_disabled() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^permitrootlogin no'; }
chk_ssh_banner() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^banner '; }
chk_ssh_env() { ssh_test && /usr/sbin/sshd -T 2>/dev/null | grep -qi '^permituserenvironment no'; }

chk_pass_policy() {
  if [ -f /etc/pam.d/common-password ]; then
    grep -qE 'pam_pwquality\.so.*minlen=10' /etc/pam.d/common-password 2>/dev/null && return 0
  fi
  if [ -f /etc/pam.d/system-auth ]; then
    grep -qE 'pam_pwquality\.so.*minlen=10' /etc/pam.d/system-auth 2>/dev/null && return 0
  fi
  if [ -f /etc/pam.d/password-auth ]; then
    grep -qE 'pam_pwquality\.so.*minlen=10' /etc/pam.d/password-auth 2>/dev/null && return 0
  fi
  return 1
}
chk_pass_min_days() { grep -qE '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+7' /etc/login.defs 2>/dev/null; }
chk_tmout() { grep -qE '^[[:space:]]*(export[[:space:]]+)?TMOUT=600' /etc/profile 2>/dev/null; }

chk_mode_passwd() { [ "$(stat -c %a /etc/passwd 2>/dev/null)" = "644" ]; }
chk_mode_shadow() { [ "$(stat -c %a /etc/shadow 2>/dev/null)" = "600" ]; }
chk_mode_sshd() { [ "$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)" = "600" ]; }
chk_mode_authkeys() { [ ! -f /root/.ssh/authorized_keys ] || [ "$(stat -c %a /root/.ssh/authorized_keys 2>/dev/null)" = "600" ]; }

chk_suid_basic() {
  [ ! -u /bin/mount ] && [ ! -u /bin/umount ] && [ ! -u /usr/bin/newgrp ] && [ ! -u /usr/bin/chsh ]
}

chk_uid0_clean() { [ -z "$(awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd 2>/dev/null)" ]; }

chk_sudo_nopasswd() {
  ! (grep -R --line-number -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q .)
}

chk_su_wheel() { grep -q 'pam_wheel.so' /etc/pam.d/su 2>/dev/null || grep -q 'pam_wheel.so' /etc/pam.d/system-auth 2>/dev/null; }

chk_gcc_restrict() {
  local g real
  g="$(command -v gcc 2>/dev/null || true)"
  [ -z "$g" ] && return 0
  real="$(readlink -f "$g" 2>/dev/null || echo "$g")"
  [ "$(stat -c %a "$real" 2>/dev/null)" = "700" ]
}

chk_suid_ext() { [ ! -u /usr/bin/wall ]; }
chk_grub_lock() { [ ! -f /boot/grub/grub.cfg ] || [ "$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)" = "600" ]; }

chk_accept_redirects() { sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '^0$'; }
chk_syncookies() { sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q '^1$'; }
chk_mod_uncommon() { [ -f /etc/modprobe.d/disable-uncommon.conf ]; }
chk_mod_fs() { [ -f /etc/modprobe.d/disable-filesystems.conf ]; }
chk_log_martians() { sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '^1$'; }

chk_time_sync() {
  if has_cmd systemctl; then
    systemctl is-active --quiet chrony 2>/dev/null && return 0
    systemctl is-active --quiet chronyd 2>/dev/null && return 0
    systemctl is-active --quiet systemd-timesyncd 2>/dev/null && return 0
  fi
  return 1
}
chk_journal_limit() { grep -q '^SystemMaxUse=500M' /etc/systemd/journald.conf 2>/dev/null; }
chk_fail2ban() { has_cmd fail2ban-server; }

chk_auto_update() {
  if [ "$PM" = "apt" ]; then
    [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -qE 'Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null && return 0
    return 1
  fi
  if [ "$PM" = "dnf" ]; then
    has_cmd dnf-automatic && has_cmd systemctl && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null && return 0
    return 1
  fi
  return 1
}
chk_hotfix() { is_eol && return 1; return 0; }

# =========================
# 修复函数
# =========================
fix_bbr() {
  if ! bbr_supported; then ui_fail "BBR 不支持（内核/能力不足）。"; return 1; fi
  set_kv_eq "$SYSCTL_FILE" "net.core.default_qdisc" "fq"
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.tcp_congestion_control" "bbr"
  sysctl_apply
  ui_ok "BBR 已配置。"
}

fix_limits() {
  ensure_line /etc/security/limits.conf "* soft nofile 65535"
  ensure_line /etc/security/limits.conf "* hard nofile 65535"
  ui_ok "资源限制已优化。"
}

fix_ipv4_pref() {
  backup_file /etc/gai.conf
  sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf 2>/dev/null || true
  ensure_line /etc/gai.conf "precedence ::ffff:0:0/96 100"
  ui_ok "IPv4 优先已配置。"
}

fix_swap() { swap_apply; }
fix_tools() { smart_install curl wget vim unzip htop git net-tools ca-certificates; }

fix_dns() {
  # 默认不改；只有“解析异常并被选择”时才会执行到这里
  dns_repair
}

fix_ssh_proto2() { ssh_write_setting "Protocol" "2"; }
fix_ssh_pubkey() { ssh_write_setting "PubkeyAuthentication" "yes"; }
fix_ssh_empty_pw() { ssh_write_setting "PermitEmptyPasswords" "no"; }

rand_port() {
  if has_cmd shuf; then
    shuf -i 20000-60000 -n 1
  else
    echo $((20000 + (RANDOM % 40001)))
  fi
}

port_in_use() {
  local p="$1"
  if has_cmd ss; then
    ss -tuln 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"
    return $?
  fi
  if has_cmd netstat; then
    netstat -tuln 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"
    return $?
  fi
  return 1
}

fix_ssh_port() {
  local T_P=""
  while :; do
    read -r -p "   新端口 (回车随机): " T_P
    T_P="${T_P:-$(rand_port)}"
    if port_in_use "$T_P"; then
      ui_warn "端口 $T_P 被占用，请重试"
      continue
    fi
    break
  done

  ssh_write_setting "Port" "$T_P"

  if has_cmd ufw; then ufw allow "${T_P}/tcp" >/dev/null 2>&1 || true; fi
  if has_cmd firewall-cmd; then
    firewall-cmd --add-port="${T_P}/tcp" --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  ui_ok "SSH 端口已修改为: ${BOLD}${GREEN}$T_P${RESET} (请同步云安全组/防火墙)"
}

fix_ssh_pw_auth_off() {
  if ! has_any_authorized_keys; then
    ui_fail "未检测到任何 authorized_keys，跳过“禁用密码认证”（防止锁死）。"
    return 1
  fi
  ssh_write_setting "PasswordAuthentication" "no"
  ssh_write_setting "KbdInteractiveAuthentication" "no"
  ssh_write_setting "ChallengeResponseAuthentication" "no"
  ui_ok "SSH 密码认证已禁用。"
}

fix_ssh_idle() {
  ssh_write_setting "ClientAliveInterval" "600"
  ssh_write_setting "ClientAliveCountMax" "0"
  ui_ok "SSH 空闲超时已配置。"
}

fix_ssh_root_off() {
  if ! has_any_authorized_keys; then
    ui_fail "未检测到任何 authorized_keys，跳过“禁止 Root 登录”（防止锁死）。"
    return 1
  fi
  ssh_write_setting "PermitRootLogin" "no"
  ui_ok "Root SSH 登录已禁止。"
}

fix_ssh_banner() {
  backup_file "$SSH_BANNER"
  printf "Restricted Access.\n" >"$SSH_BANNER"
  ssh_write_setting "Banner" "$SSH_BANNER"
  ui_ok "SSH Banner 已配置。"
}

fix_ssh_env() { ssh_write_setting "PermitUserEnvironment" "no"; ui_ok "SSH 环境篡改已禁止。"; }

fix_pass_policy() {
  if [ "$PM" = "apt" ]; then smart_install libpam-pwquality
  elif [ "$PM" = "dnf" ] || [ "$PM" = "yum" ]; then smart_install libpwquality pam
  fi

  if [ -f /etc/pam.d/common-password ]; then
    backup_file /etc/pam.d/common-password
    if grep -qE 'pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
      sed -i -E 's#^([[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so).*#\1 retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0#' /etc/pam.d/common-password
    else
      sed -i -E '0,/pam_unix\.so/s#^(.*pam_unix\.so.*)$#password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0\n\1#' /etc/pam.d/common-password
    fi
    ui_ok "PAM 密码强度已配置（Debian系）。"
    return 0
  fi

  local changed=0 f
  for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$f" ] || continue
    backup_file "$f"
    if grep -qE 'pam_pwquality\.so' "$f" 2>/dev/null; then
      sed -i -E 's#^([[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so).*#\1 retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0#' "$f"
    else
      sed -i -E '0,/pam_unix\.so/s#^(.*pam_unix\.so.*)$#password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=0\n\1#' "$f"
    fi
    changed=1
  done
  [ "$changed" -eq 1 ] && ui_ok "PAM 密码强度已配置（RHEL系）。"
  return 0
}

fix_pass_min_days() { set_kv_space /etc/login.defs "PASS_MIN_DAYS" "7"; chage --mindays 7 root >/dev/null 2>&1 || true; ui_ok "PASS_MIN_DAYS 已设置。"; }

fix_tmout() {
  if ! grep -qE 'TMOUT=600
