#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
# Loaded by v1. It ranks only Tsinghua, Aliyun and Tencent, then validates the
# chosen candidate with apt's signature/index checks before changing /etc/apt.
APT_ETC="${APT_ETC:-/etc/apt}"
APT_BACKUP_ROOT="${APT_BACKUP_ROOT:-/var/backups/sec-toolbox/apt}"
APT_MIRROR_HOSTS=(
    https://mirrors.tuna.tsinghua.edu.cn
    https://mirrors.aliyun.com
    https://mirrors.cloud.tencent.com
)

mirror_time() {
    local url="$1" file="$2" elapsed start end
    if command -v curl >/dev/null 2>&1; then
        elapsed=$(curl -fsSL --connect-timeout 3 --max-time 12 --max-filesize 4194304 \
            -o "$file" -w '%{time_total}' "$url" 2>/dev/null) || return 1
    elif command -v wget >/dev/null 2>&1; then
        start=$(date +%s%N)
        wget -q --timeout=12 --tries=1 -O "$file" "$url" || return 1
        end=$(date +%s%N)
        elapsed=$(awk -v start="$start" -v end="$end" 'BEGIN { printf "%.6f", (end-start)/1000000000 }')
    else
        return 1
    fi
    [[ "$elapsed" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
    grep -q '^-----BEGIN PGP SIGNED MESSAGE-----' "$file" || return 1
    grep -Eq "^Codename: ${APT_CODENAME}$" "$file" || return 1
    awk -v arch="$APT_ARCH" '$1=="Architectures:" { for(i=2;i<=NF;i++) if($i==arch) ok=1 } END { exit !ok }' "$file" || return 1
    printf '%s\n' "$elapsed"
}

rank_apt_mirrors() {
    local work="$1" host m round t median ok
    : > "$work/ranking"
    for host in "${APT_MIRROR_HOSTS[@]}"; do
        m="$host/$APT_REPO"
        : > "$work/times"
        ok=1
        for round in 1 2 3; do
            if t=$(mirror_time "$m/dists/$APT_CODENAME/InRelease" "$work/probe"); then
                printf '%s\n' "$t" >> "$work/times"
            else ok=0; break; fi
        done
        if [ "$ok" -eq 1 ]; then
            median=$(sort -n "$work/times" | sed -n '2p')
            printf '%s %s\n' "$median" "$m" >> "$work/ranking"
            ui_info "$m：三次元数据下载中位耗时 ${median}s" >&2
        else
            ui_warn "$m：不可用、缺少该版本/架构或返回内容无效，跳过。" >&2
        fi
    done
    sort -n "$work/ranking" | awk '{ print $2 }'
}

prepare_apt_candidate() {
    local stage="$1" mirror="$2" source_file dest
    mkdir -p "$stage/etc/sources.list.d" "$stage/lists/partial" || return 1
    # apt drops network workers to _apt; keep the temporary validation tree
    # traversable while source files remain readable and are never live paths.
    chmod 755 "$stage" "$stage/lists" "$stage/lists/partial" || return 1
    chmod 700 "$stage/etc" || return 1
    : > "$stage/etc/sources.list"
    [ ! -f "$APT_ETC/sources.list" ] || cp -p "$APT_ETC/sources.list" "$stage/etc/sources.list" || return 1
    for source_file in "$APT_ETC"/sources.list.d/*.list "$APT_ETC"/sources.list.d/*.sources; do
        [ -e "$source_file" ] || continue
        [ ! -L "$source_file" ] || { ui_fail "源文件为符号链接，需手动处理: $source_file"; return 1; }
        cp -p "$source_file" "$stage/etc/sources.list.d/" || return 1
    done
    for dest in "$stage/etc/sources.list" "$stage"/etc/sources.list.d/*.list "$stage"/etc/sources.list.d/*.sources; do
        [ -f "$dest" ] || continue
        awk -v format="${dest##*.}" -v distro="$SEC_OS_ID" -v codename="$APT_CODENAME" \
            -v mirror="$mirror" -v security="$APT_SECURITY" -v matched_file="$stage/matched" \
            -f "$V1_DIR/lib/apt-rewrite.awk" "$dest" > "$stage/rewrite" || return 1
        cat "$stage/rewrite" > "$dest" || return 1
    done
    [ -f "$stage/matched" ] || { ui_fail "没有识别到可安全修改的发行版源，未修改系统。"; return 1; }
}

validate_apt_candidate() {
    local stage="$1"
    apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=1 \
        -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 \
        -o Dir::Etc::sourcelist="$stage/etc/sources.list" \
        -o Dir::Etc::sourceparts="$stage/etc/sources.list.d" \
        -o Dir::State::lists="$stage/lists" -o APT::Get::List-Cleanup=0 \
        update > "$stage/validate.log" 2>&1
}

restore_apt_sources() {
    local backup="$1" rel failed=0
    [ -f "$backup/changed-files" ] || return 1
    while IFS= read -r rel; do
        case "$rel" in sources.list|sources.list.d/*.list|sources.list.d/*.sources) ;; *) return 1;; esac
        [[ "$rel" != *..* ]] || return 1
        mkdir -p "$APT_ETC/$(dirname "$rel")" || return 1
        cp -p -- "$backup/$rel" "$APT_ETC/$rel" || failed=1
    done < "$backup/changed-files"
    [ "$failed" -eq 0 ]
}

commit_apt_candidate() {
    local stage="$1" backup file rel
    mkdir -p "$APT_BACKUP_ROOT" || return 1
    chmod 700 "$APT_BACKUP_ROOT" || return 1
    backup=$(mktemp -d "$APT_BACKUP_ROOT/sources_$(date +%Y%m%d_%H%M%S).XXXXXX") || return 1
    mkdir -p "$backup/sources.list.d" || return 1
    : > "$backup/changed-files"
    for file in "$stage/etc/sources.list" "$stage"/etc/sources.list.d/*.list "$stage"/etc/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        rel=${file#"$stage/etc/"}
        [ -f "$APT_ETC/$rel" ] || continue
        cmp -s "$file" "$APT_ETC/$rel" && continue
        mkdir -p "$backup/$(dirname "$rel")" || return 1
        cp -p "$APT_ETC/$rel" "$backup/$rel" || return 1
        printf '%s\n' "$rel" >> "$backup/changed-files" || return 1
    done
    while IFS= read -r rel; do
        mkdir -p "$APT_ETC/$(dirname "$rel")" || return 1
        if ! cat "$stage/etc/$rel" > "$APT_ETC/$rel"; then
            restore_apt_sources "$backup" || ui_fail "恢复失败！请使用备份 $backup 手动恢复。"
            return 1
        fi
    done < "$backup/changed-files"
    ui_info "备份: $backup"
    if ! apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=1 \
        -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update > "$stage/live-update.log" 2>&1; then
        tail -n 12 "$stage/live-update.log"
        restore_apt_sources "$backup" || { ui_fail "回滚失败，请手动恢复: $backup"; return 1; }
        ui_fail "实际刷新失败，已恢复原源文件。"
        return 1
    fi
    ui_ok "软件源已应用并通过 APT 签名/索引验证。"
}

apt_mirror_transaction() (
    local work mirror apt_group index=0 chosen=""
    [ "${SEC_PLATFORM:-}" != rhel ] || { ui_warn "RPM 系保留发行版官方仓库，不套用 APT 换源。"; return 1; }
    platform_apt_policy || { ui_fail "无法确定软件源版本/架构。"; return 1; }
    [[ "$APT_ETC" = /* && "$APT_BACKUP_ROOT" = /* ]] || return 1
    [ ! -L "$APT_ETC" ] && [ ! -L "$APT_ETC/sources.list" ] && [ ! -L "$APT_ETC/sources.list.d" ] || { ui_fail "源路径是符号链接，请手动处理。"; return 1; }
    command -v flock >/dev/null 2>&1 || { ui_fail "缺少 flock (util-linux)，无法安全锁定换源操作。"; return 1; }
    exec 9>"$APT_ETC/.sec-toolbox-mirror.lock" || return 1
    flock -n 9 || { ui_fail "已有换源操作正在运行。"; return 1; }
    work=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work"' EXIT
    # Root reads private source configuration; only the _apt group needs to
    # traverse the staging root to download into apt-managed lists/partial.
    if [ "$(id -u)" -eq 0 ]; then
        apt_group=$(id -g _apt) || { ui_fail "缺少 _apt 沙箱用户，停止验证。"; return 1; }
        chgrp "$apt_group" "$work" && chmod 710 "$work" || return 1
    fi
    ui_info "系统: $SEC_OS_ID $APT_CODENAME / $APT_ARCH；候选仅清华、阿里、腾讯。"
    rank_apt_mirrors "$work" > "$work/candidates"
    printf '%s\n' "$APT_OFFICIAL" >> "$work/candidates"
    while IFS= read -r mirror; do
        [ -n "$mirror" ] || continue
        index=$((index+1))
        local stage="$work/candidate-$index"
        ui_info "验证候选源: $mirror（安全更新保留官方源）"
        prepare_apt_candidate "$stage" "$mirror" || return 1
        if validate_apt_candidate "$stage"; then chosen="$stage"; break; fi
        ui_warn "候选源验证失败，尝试下一个；系统源尚未修改。"
        tail -n 5 "$stage/validate.log"
    done < "$work/candidates"
    [ -n "$chosen" ] || { ui_fail "所有候选验证失败，保留原源。"; return 1; }
    commit_apt_candidate "$chosen"
)

apply_apt_mirror_auto() {
    apt_mirror_transaction || return 1
    APT_UPDATED=1
}

apt_update_once() {
    [ "$APT_UPDATED" -eq 1 ] && return 0
    handle_lock || return 1
    local log
    log=$(mktemp) || return 1
    ui_info "正在刷新 APT 索引..."
    if apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=1 \
        -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update > "$log" 2>&1; then
        rm -f "$log"; APT_UPDATED=1; return 0
    fi
    tail -n 8 "$log"; rm -f "$log"
    ui_fail "APT 刷新失败；未擅自换源。请单独选择软件源优化后重试。"
    return 1
}
