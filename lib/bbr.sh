#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# Adaptive BBR enablement only: no third-party kernel download or reboot.
BBR_SYSCTL_FILE="${BBR_SYSCTL_FILE:-/etc/sysctl.d/99-zz-sec-toolbox-bbr.conf}"
BBR_BACKUP_ROOT="${BBR_BACKUP_ROOT:-/var/backups/sec-toolbox/bbr}"

bbr_available_algos() {
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr '[:space:]' '\n' | sed '/^$/d' | sort -u
}
available_bbr_variants() {
    local algos variant
    algos=$(bbr_available_algos) || return 1
    for variant in bbr3 bbr2 bbr; do
        if grep -Fxq "$variant" <<< "$algos"; then printf '%s\n' "$variant"; fi
    done
}
bbr_available() { [ -n "$(available_bbr_variants)" ]; }

show_bbr_status() {
    ui_info "内核: $(uname -r)；当前算法: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 未知)"
    ui_info "已注册的 BBR 算法: $(available_bbr_variants | tr '\n' ' ')"
    ui_warn "算法名 bbr 不能可靠区分 v1/v2/v3；内核版本号也不能单独证明算法代际。"
}

load_installed_bbr_modules() {
    local module
    if command -v modprobe >/dev/null 2>&1; then
        for module in tcp_bbr tcp_bbr2 tcp_bbr3; do modprobe "$module" >/dev/null 2>&1 || true; done
    fi
}

choose_bbr_algorithm() {
    local current variants
    current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || return 1
    variants=$(available_bbr_variants)
    case "$current" in
        bbr|bbr2|bbr3) grep -Fxq "$current" <<< "$variants" && { printf '%s\n' "$current"; return 0; } ;;
    esac
    [ -n "$variants" ] || return 1
    printf '%s\n' "${variants%%$'\n'*}"
}

bbr_persistence_conflicts() {
    local variant="$1" file
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
        [ -f "$file" ] || continue
        [ "$file" = "$BBR_SYSCTL_FILE" ] && continue
        awk -v desired="$variant" '
            /^[ \t]*[#;]/ { next }
            { line=$0; sub(/[ \t]*[#;].*/,"",line); gsub(/\//,".",line); split(line,a,"="); gsub(/[ \t]/,"",a[1]); gsub(/[ \t]/,"",a[2]); sub(/^-/,"",a[1]);
              if ((a[1]=="net.ipv4.tcp_congestion_control" && a[2]!=desired) || (a[1]=="net.core.default_qdisc" && a[2]!="fq")) bad=1 }
            END { exit !bad }
        ' "$file" && return 0
    done
    return 1
}

rollback_bbr() {
    local backup="$1" old_algo="$2" old_qdisc="$3" failed=0
    sysctl -w "net.ipv4.tcp_congestion_control=$old_algo" >/dev/null 2>&1 || failed=1
    sysctl -w "net.core.default_qdisc=$old_qdisc" >/dev/null 2>&1 || failed=1
    if [ -f "$backup/config" ]; then cp -p "$backup/config" "$BBR_SYSCTL_FILE" || failed=1; else rm -f "$BBR_SYSCTL_FILE" || failed=1; fi
    [ "$failed" -eq 0 ] || { ui_fail "BBR 回滚不完整，请检查 $backup。"; return 1; }
}

enable_bbr_auto() {
    local variant old_algo old_qdisc backup tmp virt="" answer
    if command -v systemd-detect-virt >/dev/null 2>&1; then virt=$(systemd-detect-virt --container 2>/dev/null || true); fi
    if [[ -n "$virt" && "$virt" != none ]]; then
        ui_fail "检测到容器 ($virt)，拒绝修改共享内核的 BBR；请在宿主机配置。"; return 1
    fi
    show_bbr_status
    ui_warn "将加载本机已安装 BBR 模块并设置默认算法/fq；不安装新内核、不重启，不保证提速。"
    read -rp '输入 ENABLE BBR 确认: ' answer || return 1
    [ "$answer" = 'ENABLE BBR' ] || return 1
    load_installed_bbr_modules
    variant=$(choose_bbr_algorithm) || { ui_fail "当前内核没有可用 BBR；本工具不会下载第三方内核。"; return 1; }
    [ ! -L "$BBR_SYSCTL_FILE" ] || { ui_fail "BBR 配置为符号链接，请手动处理。"; return 1; }
    if bbr_persistence_conflicts "$variant"; then ui_fail "检测到已有冲突 sysctl 配置，未修改。"; return 1; fi
    old_algo=$(sysctl -n net.ipv4.tcp_congestion_control) || return 1
    old_qdisc=$(sysctl -n net.core.default_qdisc) || return 1
    mkdir -p "$BBR_BACKUP_ROOT" "$(dirname "$BBR_SYSCTL_FILE")" || return 1
    chmod 700 "$BBR_BACKUP_ROOT" || return 1
    backup=$(mktemp -d "$BBR_BACKUP_ROOT/bbr_$(date +%Y%m%d_%H%M%S).XXXXXX") || return 1
    printf 'algorithm=%s\nqdisc=%s\n' "$old_algo" "$old_qdisc" > "$backup/runtime"
    [ ! -e "$BBR_SYSCTL_FILE" ] || cp -p "$BBR_SYSCTL_FILE" "$backup/config" || return 1
    tmp=$(mktemp "${BBR_SYSCTL_FILE}.XXXXXX") || return 1
    if ! printf '# Managed by sec-toolbox; bbr name is not a version guarantee.\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = %s\n' "$variant" > "$tmp" || ! chmod 644 "$tmp" || ! mv -f "$tmp" "$BBR_SYSCTL_FILE"; then rm -f "$tmp"; return 1; fi
    if ! sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || ! sysctl -w "net.ipv4.tcp_congestion_control=$variant" >/dev/null 2>&1 || [ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" != fq ] || [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != "$variant" ]; then
        rollback_bbr "$backup" "$old_algo" "$old_qdisc" || return 1
        ui_fail "BBR 配置失败，已恢复原配置。"; return 1
    fi
    ui_ok "已启用当前内核算法 $variant；备份: $backup"
    ui_warn "default_qdisc 只设置默认值；可用 tc -s qdisc show 检查实际队列。"
}
