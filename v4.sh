#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# v4.sh - WARP 安装 + GitHub 加速源自动配置 (v1.0)

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

trap 'echo -e "\n\033[33m[用户强制终止]\033[0m"; exit 1' INT

[ "${USE_EMOJI:-}" == "" ] && { [[ "${LANG:-}" =~ "UTF-8" ]] && USE_EMOJI="1" || USE_EMOJI="0"; }
RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m')
CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m')
I_OK=$([ "$USE_EMOJI" == "1" ] && echo "✓" || echo "[OK]")
I_FAIL=$([ "$USE_EMOJI" == "1" ] && echo "✗" || echo "[FAIL]")
I_INFO=$([ "$USE_EMOJI" == "1" ] && echo "»" || echo "[i]")
I_FIX=$([ "$USE_EMOJI" == "1" ] && echo "→" || echo "[FIX]")

ui_info() { echo -e "${CYAN}${I_INFO} $*${RESET}"; }
ui_ok()   { echo -e "${GREEN}${I_OK} $*${RESET}"; }
ui_warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
ui_fail() { echo -e "${RED}${I_FAIL} $*${RESET}"; }

SEC_GITHUB_ACCEL_DIR="${SEC_GITHUB_ACCEL_DIR:-/etc/sec-toolbox}"
SEC_GITHUB_ACCEL_FILE="${SEC_GITHUB_ACCEL_FILE:-$SEC_GITHUB_ACCEL_DIR/github-mirrors}"

# 推荐的 GitHub 加速镜像列表（可被覆盖）
SEC_GITHUB_MIRRORS_DEFAULT=(
    "https://gh-proxy.org/https://raw.githubusercontent.com"
    "https://cdn.gh-proxy.org/https://raw.githubusercontent.com"
    "https://gh-proxy.com/https://raw.githubusercontent.com"
    "https://ghproxy.net/https://raw.githubusercontent.com"
    "https://ghfast.top/https://raw.githubusercontent.com"
)

write_mirror_list() {
    mkdir -p "$SEC_GITHUB_ACCEL_DIR" || return 1
    : > "$SEC_GITHUB_ACCEL_FILE"
    local mirror
    for mirror in "${SEC_GITHUB_MIRRORS_DEFAULT[@]}"; do
        echo "$mirror" >> "$SEC_GITHUB_ACCEL_FILE"
    done
    chmod 0644 "$SEC_GITHUB_ACCEL_FILE"
    return 0
}

show_mirrors() {
    ui_info "当前 GitHub 加速源 (${SEC_GITHUB_ACCEL_FILE}):"
    if [ ! -f "$SEC_GITHUB_ACCEL_FILE" ]; then
        ui_warn "未配置；将使用内置默认列表。"
        local m
        for m in "${SEC_GITHUB_MIRRORS_DEFAULT[@]}"; do echo "  - $m"; done
    else
        nl -ba "$SEC_GITHUB_ACCEL_FILE"
    fi
}

probe_mirror() {
    local m="$1" code=0
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 3 --max-time 8 -o /dev/null "$m" >/dev/null 2>&1 || code=$?
    elif command -v wget >/dev/null 2>&1; then
        wget -q --spider --timeout=5 --tries=1 "$m" >/dev/null 2>&1 || code=$?
    else
        return 1
    fi
    [ "$code" = 0 ] && return 0
    return 1
}

auto_pick_mirror() {
    ui_info "正在对候选镜像进行连通性测试..."
    local best="" m
    for m in "${SEC_GITHUB_MIRRORS_DEFAULT[@]}"; do
        if probe_mirror "$m"; then
            best="$m"
            ui_ok "可用: $m"
            break
        else
            ui_warn "不可用: $m"
        fi
    done
    if [ -n "$best" ]; then
        write_mirror_list
        ui_ok "已写入加速源列表 (${SEC_GITHUB_ACCEL_FILE})。"
        return 0
    fi
    ui_fail "所有候选镜像均不可用，请检查网络或稍后重试。"
    return 1
}

add_custom_mirror() {
    local m
    read -rp "请输入镜像 URL (例如 https://gh-proxy.org/https://raw.githubusercontent.com): " m
    [ -z "$m" ] && { ui_warn "已取消。"; return 1; }
    mkdir -p "$SEC_GITHUB_ACCEL_DIR"
    echo "$m" >> "$SEC_GITHUB_ACCEL_FILE"
    ui_ok "已追加: $m"
}

WARP_BIN=""

detect_warp() {
    command -v warp-cli >/dev/null 2>&1 && WARP_BIN="warp-cli" && return 0
    command -v warp-go >/dev/null 2>&1 && WARP_BIN="warp-go" && return 0
    [ -x /usr/bin/warp-cli ] && WARP_BIN="/usr/bin/warp-cli" && return 0
    [ -x /usr/local/bin/warp-cli ] && WARP_BIN="/usr/local/bin/warp-cli" && return 0
    [ -x /usr/local/bin/warp-go ] && WARP_BIN="/usr/local/bin/warp-go" && return 0
    return 1
}

warp_install_official() {
    ui_info "添加 Cloudflare 官方 APT 源..."
    local keyring="/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
    if ! curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg -o "$keyring" 2>/dev/null; then
        ui_warn "无法下载 GPG 密钥，将跳过签名验证继续尝试..."
    fi
    . /etc/os-release
    local distro=""
    case "${ID:-}" in
        debian) distro="debian" ;;
        ubuntu) distro="ubuntu" ;;
        *) ui_fail "当前系统非 Debian/Ubuntu，无法通过 APT 安装官方 WARP。"; return 1 ;;
    esac
    echo "deb [signed-by=$keyring] https://pkg.cloudflareclient.com/ $distro main" > /etc/apt/sources.list.d/cloudflare-client.list
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -o Acquire::Retries=2 >/dev/null 2>&1 && apt-get install -y cloudflare-warp || {
            ui_fail "官方 WARP 安装失败。"
            return 1
        }
    fi
    detect_warp && return 0
    return 1
}

warp_install_go() {
    local arch url
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) ui_fail "不支持的架构: $arch"; return 1 ;;
    esac
    url="https://github.com/bepass-org/warp-go/releases/latest/download/warp-go-linux-${arch}"
    ui_info "正在下载 warp-go (${arch})..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 4 --max-time 60 -o /usr/local/bin/warp-go "$url" || { ui_fail "下载失败。"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O /usr/local/bin/warp-go "$url" || { ui_fail "下载失败。"; return 1; }
    else
        ui_fail "需要 curl 或 wget。"
        return 1
    fi
    chmod +x /usr/local/bin/warp-go
    detect_warp
}

warp_install() {
    if detect_warp; then
        ui_ok "已检测到 WARP 客户端: $WARP_BIN"
        return 0
    fi
    echo "选择 WARP 客户端:"
    echo "  [1] 官方 cloudflare-warp (推荐，需要注册/登录)"
    echo "  [2] warp-go (免注册、命令行流量代理)"
    echo "  [3] 跳过安装"
    read -r wchoice
    case "$wchoice" in
        1) warp_install_official ;;
        2) warp_install_go ;;
        3) ui_warn "已跳过 WARP 安装。"; return 1 ;;
        *) ui_warn "无效选择，已跳过。"; return 1 ;;
    esac
}

warp_status() {
    if detect_warp; then
        ui_info "客户端: $WARP_BIN"
        case "$WARP_BIN" in
            *warp-cli*) warp-cli status 2>/dev/null | head -n 5 || ui_warn "无法读取状态。" ;;
            *warp-go)   ui_info "warp-go 运行后由用户自管。" ;;
        esac
    else
        ui_warn "未安装 WARP 客户端。"
    fi
}

while true; do
    clear
    echo -e "${BOLD}${CYAN}WARP + GitHub 加速源 自动配置中心${RESET}"
    ui_line
    echo " [1] 配置 GitHub 加速源 (默认列表)"
    echo " [2] 自动测速并写入加速源"
    echo " [3] 追加自定义加速源"
    echo " [4] 查看当前加速源"
    echo " [5] 安装 WARP 客户端 (官方 / warp-go 二选一)"
    echo " [6] 查看 WARP 状态"
    ui_line
    echo " [q] 返回主菜单"
    ui_line
    read -r v5_choice
    case "$v5_choice" in
        1) write_mirror_list && ui_ok "已写入默认加速源列表 (${SEC_GITHUB_ACCEL_FILE})。"; sleep 1 ;;
        2) auto_pick_mirror; sleep 1 ;;
        3) add_custom_mirror; sleep 1 ;;
        4) show_mirrors; echo; echo "按任意键返回..."; read -n 1 -s -r ;;
        5) warp_install; sleep 1 ;;
        6) warp_status; sleep 1 ;;
        q|Q) exit 0 ;;
        *) ui_warn "无效选择"; sleep 1 ;;
    esac
done
