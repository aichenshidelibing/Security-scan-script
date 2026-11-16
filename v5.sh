#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# Docker and Swap utility. No action until explicitly selected and confirmed.
V5_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
ui_info() { printf '[INFO] %s\n' "$*"; }
ui_ok() { printf '[ OK ] %s\n' "$*"; }
ui_warn() { printf '[WARN] %s\n' "$*"; }
ui_fail() { printf '[FAIL] %s\n' "$*" >&2; }
confirm_action() { local input; read -rp "请输入 $1 确认（其他输入取消）: " input && [ "$input" = "$1" ]; }
for dependency in lib/platform.sh lib/docker.sh lib/swap.sh; do
    [ -r "$V5_DIR/$dependency" ] || { ui_fail "缺少 $dependency，请从 install.sh 下载 V5。"; return 1 2>/dev/null || exit 1; }
    source "$V5_DIR/$dependency"
done

v5_main() {
    [ "$(id -u)" -eq 0 ] || { ui_fail '请以 root 运行。'; return 1; }
    export LC_ALL=C
    local choice
    while true; do
        printf '\n=== Docker / Swap 管理 ===\n'
        echo ' [1] 安装 Docker Engine + Compose（官方源优先，国内安装源兜底）'
        echo ' [2] 检测 Docker Hub / 配置可信的镜像加速地址'
        echo ' [3] 查看内存与 Swap 建议'
        echo ' [4] 按建议或自定义容量创建 Swap'
        echo ' [q] 返回'
        read -rp '请选择: ' choice || return 0
        case "$choice" in
            1) install_docker ;;
            2) configure_docker_mirror ;;
            3) show_swap_plan ;;
            4) create_swap ;;
            q|Q) return 0 ;;
            *) ui_warn '无效选择。' ;;
        esac
    done
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then v5_main; fi
