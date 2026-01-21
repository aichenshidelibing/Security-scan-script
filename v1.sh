#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.4>
# v1.sh - Linux 基础安全加固 (v42.2)
# 特性：
# - 风险项永不默认勾选；all 只全选非风险项；all! 才包含风险项
# - 风险项执行：总确认 + 逐项二次确认（必须输入 yes）
# - DNS：默认不改；仅当检测到解析异常且用户选择该项时自愈；修复时尽量选“就近 DNS”
# - SSH：优先 drop-in；语法检测 sshd -t 通过才 reload；关键锁死项额外护栏（无公钥则拒绝执行）

set -u

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
  read -r || true
}
trap finish_trap EXIT
trap 'trap - EXIT; echo -e "\n\033[33m[用户强制终止] 正在返回主菜单...\033[0m"; exit 0' INT

# =========================
# UI 自适应
# =========================
[ "${USE_EMOJI:-}" = "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m')
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')

I_OK=$([ "$USE_EMOJI" = "1" ] && echo "✅" || echo "[ OK ]")
I_FAIL=$([ "$USE_EMOJI" = "1" ] && echo "❌" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" = "1" ] && echo "ℹ️ " || echo "[INFO]")
I_WAIT=$([ "$USE_EMOJI" = "1" ] && echo "⏳" || echo "[WAIT]")
I_NET=$([ "$USE_EMOJI" = "1" ] && echo "🌐" || echo "[NET]")
I_WALL=$([ "$USE_EMOJI" = "1" ] && echo "🧱" || echo "[FW]")
I_FIX=$([ "$USE_EMOJI" = "1" ] && echo "🛠️ " || echo "[FIX ]")
I_LIST=$([ "$USE_EMOJI" = "1" ] && echo "📋" || echo "[LIST]")

ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

is_tty() { [ -t 1 ]; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

do_clear() { has_cmd clear && clear || true; }

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
  local free_kb
  free_kb="$(disk_free_kb_root)"
  [ -n "$free_kb" ] || return 1
  [ "$free_kb" -ge 307200 ] || return 1  # <300MB 不备份
  return 0
}

backup_prune() {
  [ -d "$BACKUP_BASE" ] || return 0
  local runs count
  runs="$(ls -1 "$BACKUP_BASE" 2>/dev/null | sort || true)"
  count="$(printf "%s\n" "$runs" | sed '/^$/d' | wc -l | awk '{print $1}')"
  if [ "${count:-0}" -gt "$BACKUP_MAX_RUNS" ]; then
    local del_n=$((count - BACKUP_MAX_RUNS))
    printf "%s\n" "$runs" | sed '/^$/d' | sort | head -n "$del_n" | while read -r old; do
      rm -rf "${BACKUP_BASE:?}/$old" 2>/dev/null || true
    done
  fi

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
  has_cmd ping || { echo 9999; return 0; }
  local ip="$1" out
  out="$(ping -c 1 -W 1 "$ip" 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1}' | cut -d. -f1)"
  [ -n "$out" ] && echo "$out" || echo 9999
}

dns_pick_profile() {
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

  # NetworkManager：不强改（避免覆盖企业/内网 DNS）
  if has_cmd nmcli; then
    ui_warn "检测到 NetworkManager：为避免破坏连接配置，本脚本不强写 nmcli DNS。建议手工为对应连接设置 DNS。"
    return 0
  fi

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
    if has_cmd systemctl; then
      systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true
    fi
    ui_ok "SSH 已重载。"
    return 0
  fi
  ui_fail "SSH 配置语法检测失败，已避免重载（请检查 sshd_config）。"
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
COUNT=0
MSG=""
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
chk_mode_sshd() { [ ! -f /etc/ssh/sshd_config ] || [ "$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)" = "600" ]; }
chk_mode_authkeys() { [ ! -f /root/.ssh/authorized_keys ] || [ "$(stat -c %a /root/.ssh/authorized_keys 2>/dev/null)" = "600" ]; }

chk_suid_basic() { [ ! -u /bin/mount ] && [ ! -u /bin/umount ] && [ ! -u /usr/bin/newgrp ] && [ ! -u /usr/bin/chsh ]; }
chk_uid0_clean() { [ -z "$(awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd 2>/dev/null)" ]; }

chk_sudo_nopasswd() { ! (grep -R --line-number -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q .); }
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
chk_log_martians() { sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '^1$'; }

chk_mod_uncommon() { [ -f /etc/modprobe.d/disable-uncommon.conf ]; }
chk_mod_fs() { [ -f /etc/modprobe.d/disable-filesystems.conf ]; }

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
  if [ "$PM" = "dnf" ] || [ "$PM" = "yum" ]; then
    has_cmd systemctl && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null && return 0
    return 1
  fi
  return 1
}

# =========================
# 修复函数
# =========================
fix_bbr() {
  if ! bbr_supported; then ui_fail "BBR 不支持（内核/能力不足）。"; return 1; fi
  set_kv_eq "$SYSCTL_FILE" "net.core.default_qdisc" "fq"
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.tcp_congestion_control" "bbr"
  sysctl_apply
  ui_ok "BBR 已配置。"
  return 0
}

fix_limits() {
  ensure_line /etc/security/limits.conf "* soft nofile 65535"
  ensure_line /etc/security/limits.conf "* hard nofile 65535"
  ui_ok "资源限制已优化。"
  return 0
}

fix_ipv4_pref() {
  backup_file /etc/gai.conf
  sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf 2>/dev/null || true
  ensure_line /etc/gai.conf "precedence ::ffff:0:0/96 100"
  ui_ok "IPv4 优先已配置。"
  return 0
}

fix_swap() { swap_apply; return 0; }
fix_tools() { smart_install curl wget vim unzip htop git net-tools ca-certificates; return 0; }

fix_dns() { dns_repair; return 0; }

fix_ssh_proto2() { ssh_write_setting "Protocol" "2"; ui_ok "SSH Protocol 已设置为 2。"; return 0; }
fix_ssh_pubkey() { ssh_write_setting "PubkeyAuthentication" "yes"; ui_ok "SSH 公钥认证已启用。"; return 0; }
fix_ssh_empty_pw() { ssh_write_setting "PermitEmptyPasswords" "no"; ui_ok "SSH 空密码登录已禁用。"; return 0; }

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
    read -r -p "   新端口 (回车随机): " T_P || true
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
  ui_ok "SSH 端口已修改为: ${BOLD}${GREEN}$T_P${RESET}（请同步云安全组/ACL）"
  return 0
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
  return 0
}

fix_ssh_idle() {
  ssh_write_setting "ClientAliveInterval" "600"
  ssh_write_setting "ClientAliveCountMax" "0"
  ui_ok "SSH 空闲超时已配置（600s，无响应即断开）。"
  return 0
}

fix_ssh_root_off() {
  if ! has_any_authorized_keys; then
    ui_fail "未检测到任何 authorized_keys，跳过“禁止 Root 登录”（防止锁死）。"
    return 1
  fi
  ssh_write_setting "PermitRootLogin" "no"
  ui_ok "Root SSH 登录已禁止。"
  return 0
}

fix_ssh_banner() {
  backup_file "$SSH_BANNER"
  printf "Restricted Access.\n" >"$SSH_BANNER"
  ssh_write_setting "Banner" "$SSH_BANNER"
  ui_ok "SSH Banner 已配置。"
  return 0
}

fix_ssh_env() {
  ssh_write_setting "PermitUserEnvironment" "no"
  ui_ok "SSH 环境篡改已禁止。"
  return 0
}

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

fix_pass_min_days() {
  set_kv_space /etc/login.defs "PASS_MIN_DAYS" "7"
  chage --mindays 7 root >/dev/null 2>&1 || true
  ui_ok "PASS_MIN_DAYS 已设置为 7。"
  return 0
}

fix_tmout() {
  backup_file /etc/profile
  # 清理旧的 TMOUT 定义，避免多次追加产生歧义
  sed -i -E '/^[[:space:]]*(export[[:space:]]+)?TMOUT=/d' /etc/profile 2>/dev/null || true
  printf "\n# Auto logout (sec-script)\nTMOUT=600\nexport TMOUT\n" >>/etc/profile
  ui_ok "TMOUT 已设置为 600 秒（适用于交互 shell）。"
  return 0
}

fix_mode_passwd() { ensure_chmod 644 /etc/passwd && ui_ok "/etc/passwd 权限已修正。"; return 0; }
fix_mode_shadow() { ensure_chmod 600 /etc/shadow && ui_ok "/etc/shadow 权限已修正。"; return 0; }
fix_mode_sshd() {
  [ -f /etc/ssh/sshd_config ] || { ui_warn "未找到 /etc/ssh/sshd_config，跳过。"; return 0; }
  ensure_chmod 600 /etc/ssh/sshd_config && ui_ok "/etc/ssh/sshd_config 权限已修正。"
  return 0
}
fix_mode_authkeys() {
  [ -f /root/.ssh/authorized_keys ] || { ui_ok "root authorized_keys 不存在，无需处理。"; return 0; }
  ensure_chmod 600 /root/.ssh/authorized_keys && ui_ok "root authorized_keys 权限已修正。"
  return 0
}

fix_suid_basic() {
  local x
  for x in /bin/mount /bin/umount /usr/bin/newgrp /usr/bin/chsh; do
    [ -e "$x" ] && chmod u-s "$x" 2>/dev/null || true
  done
  ui_ok "已移除部分基础 SUID（mount/umount/newgrp/chsh）。"
  return 0
}

fix_uid0_clean() {
  local bad
  bad="$(awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd 2>/dev/null || true)"
  [ -z "$bad" ] && { ui_ok "未发现异常 UID=0 账户。"; return 0; }
  ui_warn "发现异常 UID=0 账户: $bad"
  # 只做锁定/禁用 shell（不擅自改 UID，避免破坏业务）
  local u
  for u in $bad; do
    usermod -L "$u" >/dev/null 2>&1 || true
    usermod -s /usr/sbin/nologin "$u" >/dev/null 2>&1 || usermod -s /sbin/nologin "$u" >/dev/null 2>&1 || true
  done
  ui_ok "已锁定异常 UID=0 账户并设置 nologin shell（未改 UID）。"
  return 0
}

fix_sudo_nopasswd() {
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -e "$f" ] || continue
    backup_file "$f"
    # 将 NOPASSWD 替换成 PASSWD（不破坏其余规则结构）
    sed -i -E 's/NOPASSWD:/PASSWD:/g' "$f" 2>/dev/null || true
  done
  ui_ok "sudo NOPASSWD 已尝试移除（替换为 PASSWD）。"
  return 0
}

fix_su_wheel() {
  # 统一用 wheel 组；没有则创建
  getent group wheel >/dev/null 2>&1 || groupadd wheel >/dev/null 2>&1 || true

  if [ -f /etc/pam.d/su ]; then
    backup_file /etc/pam.d/su
    grep -q 'pam_wheel.so' /etc/pam.d/su 2>/dev/null || \
      printf "\n# sec-script: restrict su to wheel\nauth           required        pam_wheel.so use_uid group=wheel\n" >>/etc/pam.d/su
    ui_ok "已配置 su 仅 wheel 组可用（/etc/pam.d/su）。"
    return 0
  fi

  # 某些 RHEL 系走 system-auth
  if [ -f /etc/pam.d/system-auth ]; then
    backup_file /etc/pam.d/system-auth
    grep -q 'pam_wheel.so' /etc/pam.d/system-auth 2>/dev/null || \
      printf "\n# sec-script: restrict su to wheel\nauth        required      pam_wheel.so use_uid group=wheel\n" >>/etc/pam.d/system-auth
    ui_ok "已配置 su 仅 wheel 组可用（/etc/pam.d/system-auth）。"
    return 0
  fi

  ui_warn "未找到可配置的 PAM su 文件，跳过。"
  return 0
}

fix_gcc_restrict() {
  local g real
  g="$(command -v gcc 2>/dev/null || true)"
  [ -z "$g" ] && { ui_ok "未安装 gcc，无需处理。"; return 0; }
  real="$(readlink -f "$g" 2>/dev/null || echo "$g")"
  backup_file "$real"
  chmod 700 "$real" 2>/dev/null || { ui_fail "限制 gcc 失败。"; return 1; }
  ui_ok "gcc 已限制为仅 root 可执行（chmod 700）。"
  return 0
}

fix_suid_ext() {
  [ -e /usr/bin/wall ] && chmod u-s /usr/bin/wall 2>/dev/null || true
  ui_ok "已移除 /usr/bin/wall 的 SUID（若存在）。"
  return 0
}

fix_grub_lock() {
  [ -f /boot/grub/grub.cfg ] || { ui_ok "未找到 grub.cfg，无需处理。"; return 0; }
  ensure_chmod 600 /boot/grub/grub.cfg && ui_ok "grub.cfg 权限已加固。"
  return 0
}

fix_accept_redirects() {
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.conf.all.accept_redirects" "0"
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.conf.default.accept_redirects" "0"
  sysctl_apply
  ui_ok "ICMP Redirect 已禁用。"
  return 0
}

fix_syncookies() {
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.tcp_syncookies" "1"
  sysctl_apply
  ui_ok "SYN Cookies 已启用。"
  return 0
}

fix_log_martians() {
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.conf.all.log_martians" "1"
  set_kv_eq "$SYSCTL_FILE" "net.ipv4.conf.default.log_martians" "1"
  sysctl_apply
  ui_ok "log_martians 已启用。"
  return 0
}

fix_mod_uncommon() {
  local f="/etc/modprobe.d/disable-uncommon.conf"
  backup_file "$f"
  cat >"$f" <<'EOF'
# sec-script: disable uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds  /bin/true
install tipc /bin/true
EOF
  ui_ok "已写入 disable-uncommon.conf（需要重启/手动卸载模块才完全生效）。"
  return 0
}

fix_mod_fs() {
  local f="/etc/modprobe.d/disable-filesystems.conf"
  backup_file "$f"
  cat >"$f" <<'EOF'
# sec-script: disable uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
  ui_ok "已写入 disable-filesystems.conf（可能影响挂载某些文件系统）。"
  return 0
}

fix_time_sync() {
  if has_cmd systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd\.service'; then
    systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    systemctl is-active --quiet systemd-timesyncd 2>/dev/null && { ui_ok "已启用 systemd-timesyncd。"; return 0; }
  fi

  smart_install chrony || true
  if has_cmd systemctl; then
    systemctl enable --now chrony  >/dev/null 2>&1 || true
    systemctl enable --now chronyd >/dev/null 2>&1 || true
    (systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null) \
      && ui_ok "已启用 chrony/chronyd。" \
      || ui_warn "已尝试安装/启用时间同步，但服务未处于 active。"
  else
    ui_warn "无 systemctl，跳过自动启用时间同步服务。"
  fi
  return 0
}

fix_journal_limit() {
  local f="/etc/systemd/journald.conf"
  backup_file "$f"
  touch "$f" 2>/dev/null || true
  if grep -qE '^[[:space:]]*SystemMaxUse=' "$f" 2>/dev/null; then
    sed -i -E 's#^[[:space:]]*SystemMaxUse=.*#SystemMaxUse=500M#' "$f"
  else
    printf "\nSystemMaxUse=500M\n" >>"$f"
  fi
  if has_cmd systemctl; then
    systemctl restart systemd-journald >/dev/null 2>&1 || true
  fi
  ui_ok "journald 磁盘上限已设置为 500M。"
  return 0
}

fix_fail2ban() {
  smart_install fail2ban || return 1
  if has_cmd systemctl; then
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
  fi
  ui_ok "fail2ban 已安装/尝试启用（请按业务调整 jail 配置）。"
  return 0
}

fix_auto_update() {
  if [ "$PM" = "apt" ]; then
    smart_install unattended-upgrades apt-listchanges || true
    local f="/etc/apt/apt.conf.d/20auto-upgrades"
    backup_file "$f"
    cat >"$f" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    ui_ok "已启用 unattended-upgrades（自动更新）。"
    return 0
  fi

  if [ "$PM" = "dnf" ] || [ "$PM" = "yum" ]; then
    smart_install dnf-automatic || true
    if has_cmd systemctl; then
      systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
    fi
    ui_ok "已尝试启用 dnf-automatic.timer（自动更新）。"
    return 0
  fi

  ui_warn "未识别到可用的自动更新机制，跳过。"
  return 0
}

# =========================
# 初始化项目列表
# =========================
init_items() {
  add_item "启用 BBR" \
    "提升 TCP 拥塞控制性能" \
    "部分内核不支持/需重启后生效" \
    chk_bbr fix_bbr FALSE

  add_item "提升 nofile 限制" \
    "减少高并发句柄不足导致的崩溃" \
    "过高值可能掩盖应用资源泄漏" \
    chk_limits fix_limits FALSE

  add_item "IPv4 优先（gai.conf）" \
    "避免 IPv6 不通导致的卡顿" \
    "纯 IPv6 环境可能不适合" \
    chk_ipv4_pref fix_ipv4_pref FALSE

  add_item "低内存自动加 Swap(1G)" \
    "降低 OOM 风险" \
    "磁盘 IO 增加；极小盘注意空间" \
    chk_swap fix_swap FALSE

  add_item "安装常用运维工具" \
    "增强排障能力（curl/vim/unzip/htop/git...）" \
    "最小化系统可能不希望安装额外包" \
    chk_tools fix_tools FALSE

  add_item "DNS 自愈（仅解析异常时）" \
    "DNS 坏了自动恢复解析；修复时尽量选就近 DNS" \
    "企业内网 DNS 场景需谨慎（NM 不会强写）" \
    chk_dns_ok fix_dns FALSE

  add_item "SSH: 强制 Protocol 2" \
    "基础安全基线" \
    "极老旧客户端可能不兼容" \
    chk_ssh_proto2 fix_ssh_proto2 FALSE

  add_item "SSH: 启用公钥认证" \
    "支持更安全的登录方式" \
    "需配合用户侧上传公钥" \
    chk_ssh_pubkey fix_ssh_pubkey FALSE

  add_item "SSH: 禁止空密码" \
    "阻断弱口令场景" \
    "无" \
    chk_ssh_empty_pw fix_ssh_empty_pw FALSE

  add_item "SSH: 修改端口" \
    "降低被扫概率" \
    "云安全组/防火墙未放行会断连" \
    chk_ssh_port fix_ssh_port TRUE

  add_item "SSH: 禁用密码登录" \
    "显著降低爆破风险" \
    "未配置公钥会锁死（脚本会拦截）" \
    chk_ssh_pw_auth_disabled fix_ssh_pw_auth_off TRUE

  add_item "SSH: 空闲超时(600s)" \
    "降低被劫持会话风险" \
    "长时间操作可能被断开" \
    chk_ssh_idle fix_ssh_idle TRUE

  add_item "SSH: 禁止 Root 登录" \
    "减少 root 暴露面" \
    "未配置公钥/替代账户会锁死（脚本会拦截）" \
    chk_ssh_root_disabled fix_ssh_root_off TRUE

  add_item "SSH: 配置 Banner" \
    "增加合法使用告知" \
    "无" \
    chk_ssh_banner fix_ssh_banner FALSE

  add_item "SSH: 禁止 PermitUserEnvironment" \
    "减少环境注入风险" \
    "少数依赖环境注入的场景需调整" \
    chk_ssh_env fix_ssh_env FALSE

  add_item "PAM: 密码强度(minlen=10)" \
    "提升口令复杂度基线" \
    "可能影响改密策略/合规要求" \
    chk_pass_policy fix_pass_policy FALSE

  add_item "登录策略: PASS_MIN_DAYS=7" \
    "减少频繁改密绕过" \
    "部分业务账号策略需例外" \
    chk_pass_min_days fix_pass_min_days FALSE

  add_item "会话策略: TMOUT=600" \
    "减少无人值守终端风险" \
    "长时间无输入会自动退出" \
    chk_tmout fix_tmout FALSE

  add_item "权限: /etc/passwd=644" \
    "恢复基线权限" \
    "无" \
    chk_mode_passwd fix_mode_passwd FALSE

  add_item "权限: /etc/shadow=600" \
    "保护口令哈希" \
    "无" \
    chk_mode_shadow fix_mode_shadow FALSE

  add_item "权限: sshd_config=600" \
    "降低配置被非特权读取/篡改风险" \
    "极少数审计工具需读文件" \
    chk_mode_sshd fix_mode_sshd FALSE

  add_item "权限: root authorized_keys=600" \
    "保护 root 公钥文件" \
    "无" \
    chk_mode_authkeys fix_mode_authkeys FALSE

  add_item "移除部分基础 SUID" \
    "降低本地提权面" \
    "可能影响普通用户 mount/换壳等功能" \
    chk_suid_basic fix_suid_basic TRUE

  add_item "锁定异常 UID=0 账户" \
    "消除影子 root 账户风险" \
    "若为业务强依赖账户会影响业务" \
    chk_uid0_clean fix_uid0_clean TRUE

  add_item "移除 sudo NOPASSWD" \
    "提升提权可审计性" \
    "自动化/运维流程可能需要调整" \
    chk_sudo_nopasswd fix_sudo_nopasswd TRUE

  add_item "限制 su 仅 wheel 组可用" \
    "减少横向提权" \
    "可能影响现有运维习惯/流程" \
    chk_su_wheel fix_su_wheel TRUE

  add_item "限制 gcc 仅 root 可执行" \
    "降低编译工具被滥用" \
    "会影响开发/编译环境" \
    chk_gcc_restrict fix_gcc_restrict TRUE

  add_item "移除 wall 的 SUID" \
    "降低提权面" \
    "影响 wall 使用" \
    chk_suid_ext fix_suid_ext TRUE

  add_item "GRUB 配置权限加固" \
    "降低引导配置被篡改风险" \
    "无" \
    chk_grub_lock fix_grub_lock FALSE

  add_item "sysctl: 禁用 ICMP Redirect" \
    "降低被路由注入风险" \
    "特殊路由环境需评估" \
    chk_accept_redirects fix_accept_redirects FALSE

  add_item "sysctl: 启用 SYN Cookies" \
    "缓解 SYN Flood" \
    "无" \
    chk_syncookies fix_syncookies FALSE

  add_item "sysctl: 启用 log_martians" \
    "增强异常包审计" \
    "日志量可能增加" \
    chk_log_martians fix_log_martians FALSE

  add_item "禁用少用网络协议模块" \
    "降低攻击面" \
    "依赖这些协议的业务会受影响" \
    chk_mod_uncommon fix_mod_uncommon TRUE

  add_item "禁用少用文件系统模块" \
    "降低攻击面" \
    "挂载某些 FS 会失败" \
    chk_mod_fs fix_mod_fs TRUE

  add_item "启用时间同步" \
    "减少时间漂移导致的认证/日志问题" \
    "极少数离线环境需自定义" \
    chk_time_sync fix_time_sync FALSE

  add_item "journald 限制磁盘占用(500M)" \
    "防止日志挤爆磁盘" \
    "回溯历史日志范围变小" \
    chk_journal_limit fix_journal_limit FALSE

  add_item "安装 fail2ban" \
    "降低暴力破解风险" \
    "误封风险；需按业务调 jail" \
    chk_fail2ban fix_fail2ban TRUE

  add_item "启用自动更新" \
    "自动修复安全漏洞" \
    "可能引入升级变更/需维护窗口" \
    chk_auto_update fix_auto_update TRUE
}

# =========================
# 菜单选择逻辑：更直观 + 风险项二次确认
# =========================
SHOW_DETAILS=0

emit_range() {
  local a="$1" b="$2"
  if has_cmd seq; then
    if [ "$a" -le "$b" ]; then seq "$a" "$b"; else seq "$b" "$a"; fi
    return 0
  fi
  if [ "$a" -le "$b" ]; then
    while [ "$a" -le "$b" ]; do echo "$a"; a=$((a+1)); done
  else
    while [ "$b" -le "$a" ]; do echo "$b"; b=$((b+1)); done
  fi
}

flip_id() {
  local n="$1"
  [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ] || return 0
  if [ "${SELECTED[$n]}" = "TRUE" ]; then SELECTED[$n]="FALSE"; else SELECTED[$n]="TRUE"; fi
}

set_id() {
  local n="$1" v="$2"
  [ "$n" -ge 1 ] && [ "$n" -le "$COUNT" ] || return 0
  SELECTED[$n]="$v"
}

parse_ids_to_list() {
  local s="$*"
  s="$(printf "%s" "$s" | tr ',' ' ')"
  for tok in $s; do
    if printf "%s" "$tok" | grep -qE '^[0-9]+-[0-9]+$'; then
      local a b
      a="$(printf "%s" "$tok" | cut -d- -f1)"
      b="$(printf "%s" "$tok" | cut -d- -f2)"
      emit_range "$a" "$b"
    elif printf "%s" "$tok" | grep -qE '^[0-9]+$'; then
      echo "$tok"
    fi
  done | awk 'NF{print $1}' | awk '!seen[$0]++'
}

set_defaults() {
  local i
  for ((i=1; i<=COUNT; i++)); do
    if [ "${STATUS[$i]}" = "PASS" ]; then
      SELECTED[$i]="FALSE"
    else
      if [ "${IS_RISKY[$i]}" = "TRUE" ]; then
        SELECTED[$i]="FALSE"
      else
        SELECTED[$i]="TRUE"
      fi
    fi
  done
}

select_all_safe() {
  local i
  for ((i=1; i<=COUNT; i++)); do
    [ "${IS_RISKY[$i]}" = "TRUE" ] && continue
    SELECTED[$i]="TRUE"
  done
}

select_all_including_risky() {
  local i
  for ((i=1; i<=COUNT; i++)); do
    SELECTED[$i]="TRUE"
  done
}

deselect_all() {
  local i
  for ((i=1; i<=COUNT; i++)); do
    SELECTED[$i]="FALSE"
  done
}

selected_summary() {
  local i out=""
  for ((i=1; i<=COUNT; i++)); do
    [ "${SELECTED[$i]}" = "TRUE" ] || continue
    out="${out}${i},"
  done
  printf "%s" "${out%,}"
}

has_selected_risky() {
  local i
  for ((i=1; i<=COUNT; i++)); do
    [ "${SELECTED[$i]}" = "TRUE" ] || continue
    [ "${IS_RISKY[$i]}" = "TRUE" ] && return 0
  done
  return 1
}

confirm_risky_global() {
  has_selected_risky || return 0
  echo -e "${YELLOW}${I_INFO} 你已选择【风险项】。这些操作可能导致：SSH 断连/业务受限/系统行为变化。${RESET}"
  echo -e "${YELLOW}${I_INFO} 风险项列表：${RESET}"
  local i
  for ((i=1; i<=COUNT; i++)); do
    [ "${SELECTED[$i]}" = "TRUE" ] || continue
    [ "${IS_RISKY[$i]}" = "TRUE" ] || continue
    echo -e "  - ${RED}${i}.${RESET} ${TITLES[$i]}  ${GREY}[优点:${PROS[$i]}] [风险:${RISKS[$i]}]${RESET}"
  done
  echo -ne "${RED}继续执行所有已选项目? 输入 yes 继续: ${RESET}"
  local c; read -r c || true
  [ "$c" = "yes" ] || return 1
  return 0
}

confirm_risky_per_item() {
  local idx="$1"
  [ "${IS_RISKY[$idx]}" = "TRUE" ] || return 0
  echo -e "${YELLOW}${I_INFO} 风险项二次确认：${RESET}${BOLD}${TITLES[$idx]}${RESET}"
  echo -e "  优点: ${PROS[$idx]}"
  echo -e "  风险: ${RISKS[$idx]}"
  echo -ne "${RED}执行该风险项? 输入 yes 执行(其他任意输入=跳过): ${RESET}"
  local c; read -r c || true
  [ "$c" = "yes" ] || return 1
  return 0
}

# =========================
# 主流程
# =========================
init_network_insight
init_items
set_defaults

while true; do
  do_clear
  echo -e "$NET_BANNER"
  echo "${BLUE}================================================================================${RESET}"
  if [ "$REMOTE_SESSION" -eq 1 ]; then
    echo -e "${YELLOW}${I_INFO} 当前为远程 SSH 会话：风险项务必谨慎（会触发二次确认）。${RESET}"
  else
    echo -e "${GREY}${I_INFO} 当前为本地会话。${RESET}"
  fi
  echo "${BOLD} ID | 选择 | 状态 | 名称${RESET}"
  echo "${BLUE}--------------------------------------------------------------------------------${RESET}"

  for ((i=1; i<=COUNT; i++)); do
    local_sel="${GREY}[OFF]${RESET}"
    [ "${SELECTED[$i]}" = "TRUE" ] && local_sel="${GREEN}[ ON]${RESET}"

    local_stat="${GREEN}${I_OK}${RESET}"
    [ "${STATUS[$i]}" = "FAIL" ] && local_stat="${RED}${I_FAIL}${RESET}"

    local_risk=""
    [ "${IS_RISKY[$i]}" = "TRUE" ] && local_risk="${YELLOW}(风险)${RESET}"

    if [ "$SHOW_DETAILS" -eq 1 ]; then
      printf "${GREY}%2d.${RESET} %b %b %-28s %b\n" "$i" "$local_sel" "$local_stat" "${TITLES[$i]}" "$local_risk"
      printf "     ${GREY}优点:%s  风险:%s${RESET}\n" "${PROS[$i]}" "${RISKS[$i]}"
    else
      printf "${GREY}%2d.${RESET} %b %b %-35s %b\n" "$i" "$local_sel" "$local_stat" "${TITLES[$i]}" "$local_risk"
    fi
  done

  echo "${BLUE}================================================================================${RESET}"
  SUM_IDS="$(selected_summary)"
  [ -z "$SUM_IDS" ] && SUM_IDS="(空)"
  echo -e "${I_LIST} 待执行清单: ${GREEN}${SUM_IDS}${RESET}"
  [ -n "$MSG" ] && { echo -e "${YELLOW}${I_INFO} $MSG${RESET}"; MSG=""; }

  echo -e "${GREY}指令: r=开始 | q=退出 | d=详情开关 | default | all(仅非风险) | all!(含风险) | none | on/off <id...> | 输入ID/范围翻转${RESET}"
  echo -ne "输入: "
  read -r ri || true

  case "$ri" in
    q|Q)
      trap - EXIT
      exit 0
      ;;
    d|D)
      if [ "$SHOW_DETAILS" -eq 1 ]; then SHOW_DETAILS=0; else SHOW_DETAILS=1; fi
      ;;
    default|DEFAULT)
      set_defaults
      ;;
    all|ALL)
      select_all_safe
      ;;
    all\!|ALL\!)
      select_all_including_risky
      ;;
    none|NONE)
      deselect_all
      ;;
    on\ *|ON\ *)
      ids="${ri#* }"
      while read -r n; do set_id "$n" "TRUE"; done < <(parse_ids_to_list "$ids")
      ;;
    off\ *|OFF\ *)
      ids="${ri#* }"
      while read -r n; do set_id "$n" "FALSE"; done < <(parse_ids_to_list "$ids")
      ;;
    r|R|run|RUN)
      SUM_IDS="$(selected_summary)"
      [ -z "$SUM_IDS" ] && { MSG="请先选择要执行的项。"; continue; }

      check_space || continue
      heal_environment || continue
      backup_prune

      confirm_risky_global || { MSG="已取消执行。"; continue; }

      for ((i=1; i<=COUNT; i++)); do
        [ "${SELECTED[$i]}" = "TRUE" ] || continue

        if [ "${IS_RISKY[$i]}" = "TRUE" ]; then
          confirm_risky_per_item "$i" || { ui_warn "已跳过风险项：${TITLES[$i]}"; continue; }
        fi

        echo -e "   ${CYAN}${I_FIX} 加固中: ${TITLES[$i]} ...${RESET}"
        "${APPLY_FN[$i]}" || true
      done

      # SSH：最后统一 reload（语法不通过则不 reload）
      if [ -f "$SSH_MAIN" ] && has_cmd /usr/sbin/sshd; then
        ssh_reload_safe || true
      fi

      backup_prune
      trap - EXIT
      echo -ne "\n${YELLOW}【重要】流程执行完毕。按任意键退出...${RESET}"
      read -n 1 -s -r || true
      exit 0
      ;;
    *)
      while read -r n; do flip_id "$n"; done < <(parse_ids_to_list "$ri")
      ;;
  esac
done
