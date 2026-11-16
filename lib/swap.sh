#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
SWAP_DIR=/var/lib/sec-toolbox
SWAP_FILE="$SWAP_DIR/swapfile"
SWAP_FSTAB=/etc/fstab
SWAP_BACKUPS=/var/backups/sec-toolbox/swap
SWAP_PROC=/proc/swaps

# MiB; policy is a general server starting point, not a workload guarantee.
calculate_swap_plan() {
    local ram="$1" existing="$2" free="$3" total="$4"
    if [ "$ram" -le 2048 ]; then SWAP_TARGET=$((ram * 2));
    elif [ "$ram" -le 8192 ]; then SWAP_TARGET="$ram";
    else SWAP_TARGET=8192; fi
    [ "$SWAP_TARGET" -ge 1024 ] || SWAP_TARGET=1024
    SWAP_RESERVE=$((total / 10))
    [ "$SWAP_RESERVE" -ge 2048 ] || SWAP_RESERVE=2048
    SWAP_MAX=$((free - SWAP_RESERVE))
    [ "$SWAP_MAX" -ge 0 ] || SWAP_MAX=0
    [ "$SWAP_MAX" -le 32768 ] || SWAP_MAX=32768
    SWAP_RECOMMENDED=$((SWAP_TARGET - existing))
    [ "$SWAP_RECOMMENDED" -ge 0 ] || SWAP_RECOMMENDED=0
    [ "$SWAP_RECOMMENDED" -le "$SWAP_MAX" ] || SWAP_RECOMMENDED="$SWAP_MAX"
    SWAP_RECOMMENDED=$((SWAP_RECOMMENDED / 256 * 256))
}

read_swap_plan() {
    local disk_parent="$SWAP_DIR" total free
    while [ ! -d "$disk_parent" ]; do disk_parent=$(dirname "$disk_parent"); done
    SWAP_RAM=$(awk '/^MemTotal:/ { print int($2/1024) }' /proc/meminfo)
    # Includes active partitions, swapfiles and zram, not just free swap.
    SWAP_EXISTING=$(awk 'NR>1 { n+=$3 } END { print int(n/1024) }' /proc/swaps)
    read -r total free < <(df -Pm -- "$disk_parent" | awk 'NR==2 { print $2, $4 }')
    [[ "$SWAP_RAM:$SWAP_EXISTING:$total:$free" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
    SWAP_FREE="$free"
    calculate_swap_plan "$SWAP_RAM" "$SWAP_EXISTING" "$free" "$total"
}

show_swap_plan() {
    read_swap_plan || { ui_fail '无法读取内存/磁盘状态。'; return 1; }
    ui_info "内存 ${SWAP_RAM} MiB；已启用 Swap ${SWAP_EXISTING} MiB；目标总 Swap ${SWAP_TARGET} MiB。"
    ui_info "磁盘可用 ${SWAP_FREE} MiB；预留 ${SWAP_RESERVE} MiB（至少 2 GiB 或分区总量 10%）。"
    ui_info "建议新增 ${SWAP_RECOMMENDED} MiB；允许上限 ${SWAP_MAX} MiB（单文件不超过 32 GiB）。"
    ui_warn 'Swap 不是内存替代品；高 I/O 服务需按负载调整。本工具不配置休眠，不修改 swappiness，不关闭已有 Swap。'
}

swap_file_active() {
    [ -r "$SWAP_PROC" ] || return 2
    local state
    state=$(awk -v path="$SWAP_FILE" 'NR>1 && $1==path { found=1 } END { print found ? "active" : "inactive" }' "$SWAP_PROC") || return 2
    [ "$state" = active ]
}

swap_reload_systemd() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi
}

create_swap() (
    local size fs virt="" committed=0 created=0 backup="" fstab_written=0
    local cmd
    for cmd in flock findmnt df dd mkswap swapon swapoff; do
        command -v "$cmd" >/dev/null 2>&1 || { ui_fail "缺少 $cmd，请安装 util-linux/coreutils。"; return 1; }
    done
    if command -v systemd-detect-virt >/dev/null 2>&1; then virt=$(systemd-detect-virt --container 2>/dev/null || true); fi
    [[ -z "$virt" || "$virt" = none ]] || { ui_fail "检测到容器 $virt，请在宿主机配置 Swap。"; return 1; }
    [ ! -L "$SWAP_DIR" ] && [ ! -L "$SWAP_FILE" ] && [ ! -L "$SWAP_FSTAB" ] || { ui_fail '路径含符号链接，停止。'; return 1; }
    [ -f "$SWAP_FSTAB" ] || { ui_fail '未找到 fstab。'; return 1; }
    mkdir -p "$SWAP_DIR" || return 1
    exec 9>"$SWAP_DIR/.swap.lock" || return 1
    flock -n 9 || { ui_fail '另一个 Swap 操作正在运行。'; return 1; }
    [ ! -e "$SWAP_FILE" ] || { ui_fail "$SWAP_FILE 已存在，不覆盖、不自动扩容。"; return 1; }
    if awk -v path="$SWAP_FILE" '!/^#/ && $1==path { found=1 } END { exit !found }' "$SWAP_FSTAB"; then
        ui_fail 'fstab 已有此路径，请先核对已有配置。'; return 1
    fi
    fs=$(findmnt -n -o FSTYPE -T "$SWAP_DIR") || return 1
    case "$fs" in ext4|xfs) ;; *) ui_fail "暂不自动创建 $fs 上的交换文件（含 Btrfs/ZFS/NFS/overlay）。"; return 1;; esac
    show_swap_plan || return 1
    [ "$SWAP_MAX" -ge 256 ] || { ui_fail '磁盘空间不足以安全创建 Swap。'; return 1; }
    read -rp "新增容量 MiB（回车采用 $SWAP_RECOMMENDED，0 取消）: " size || return 1
    size=${size:-$SWAP_RECOMMENDED}
    [[ "$size" =~ ^[0-9]{1,5}$ ]] || { ui_fail '请输入整数 MiB。'; return 1; }
    size=$((10#$size))
    [ "$size" -ne 0 ] || return 0
    [ "$size" -ge 256 ] && [ "$size" -le "$SWAP_MAX" ] || { ui_fail "容量需在 256..$SWAP_MAX MiB。"; return 1; }
    ui_warn "将在 $SWAP_FILE 创建 ${size} MiB 文件，启用并追加开机配置；不会删除已有 Swap。"
    confirm_action 'CREATE SWAP' || return 1
    read_swap_plan || return 1
    [ "$size" -le "$SWAP_MAX" ] || { ui_fail '可用空间已变化，操作取消。'; return 1; }
    mkdir -p "$SWAP_BACKUPS" || return 1
    chmod 700 "$SWAP_BACKUPS" || return 1
    backup=$(mktemp "$SWAP_BACKUPS/fstab.XXXXXX") || return 1
    cp -p "$SWAP_FSTAB" "$backup" || return 1
    cleanup_swap() {
        [ "$committed" -eq 0 ] || return 0
        if [ "$created" -eq 1 ]; then
            local active_status=0
            swap_file_active || active_status=$?
            if [ "$active_status" -eq 2 ]; then
                ui_fail "无法读取活动 Swap 状态，保留文件: $SWAP_FILE"; return 1
            fi
            if [ "$active_status" -eq 0 ]; then
                if ! swapoff "$SWAP_FILE"; then
                    ui_fail "Swap 回滚无法关闭（可能内存不足），保留活动文件；fstab 备份: $backup"
                    return 1
                fi
            fi
            if [ "$fstab_written" -eq 1 ]; then
                # Remove only our entry; preserve other contemporaneous fstab edits.
                local tmp
                tmp=$(mktemp) || return 1
                if awk -v path="$SWAP_FILE" '$0!="# sec-toolbox swap" && $1!=path' "$SWAP_FSTAB" > "$tmp"; then
                    cat "$tmp" > "$SWAP_FSTAB" || { rm -f "$tmp"; return 1; }
                else rm -f "$tmp"; return 1; fi
                rm -f "$tmp"
                swap_reload_systemd || ui_warn 'fstab 已回滚，但 systemd 重读失败，请手动 daemon-reload。'
            fi
            rm -f -- "$SWAP_FILE"
        fi
    }
    trap cleanup_swap EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    (umask 077; set -o noclobber; : > "$SWAP_FILE") || return 1
    created=1
    chmod 600 "$SWAP_FILE" || return 1
    # Write actual blocks: no sparse files, no assumption that fallocate is safe.
    dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$size" conv=notrunc status=progress || return 1
    mkswap "$SWAP_FILE" || return 1
    swapon "$SWAP_FILE" || return 1
    swap_file_active || { ui_fail '内核未确认 Swap 启用。'; return 1; }
    fstab_written=1
    printf '\n# sec-toolbox swap\n%s none swap sw 0 0\n' "$SWAP_FILE" >> "$SWAP_FSTAB" || return 1
    swap_reload_systemd || { ui_fail 'systemd 重读配置失败，回滚。'; return 1; }
    committed=1
    ui_ok "已创建并启用 ${size} MiB Swap；fstab 备份: $backup"
)
