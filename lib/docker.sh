#!/usr/bin/env bash
# <SEC_SCRIPT_MARKER_v2.3>
DOCKER_APT_SOURCE=/etc/apt/sources.list.d/sec-toolbox-docker.sources
DOCKER_APT_KEY=/etc/apt/keyrings/sec-toolbox-docker.asc
DOCKER_RPM_SOURCE=/etc/yum.repos.d/sec-toolbox-docker.repo
DOCKER_RPM_KEY=/etc/pki/rpm-gpg/sec-toolbox-docker.asc
DOCKER_DAEMON_CONFIG=/etc/docker/daemon.json
DOCKER_BACKUPS=/var/backups/sec-toolbox/docker
# Verify primary signing keys even when obtained from a mirror. Fail closed on rotation.
DOCKER_APT_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
DOCKER_RPM_FINGERPRINT=060A61C51B558A7F742B77AAC52FEB6B621E9F35
DOCKER_REPO_ROOTS=(https://download.docker.com https://mirrors.aliyun.com/docker-ce https://mirrors.tuna.tsinghua.edu.cn/docker-ce)

docker_fetch() {
    curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 45 --retry 1 -o "$2" "$1"
}

docker_platform() {
    detect_platform || return 1
    case "$SEC_OS_ID:$SEC_OS_VERSION" in
        debian:12|debian:13)
            DOCKER_DISTRO=debian; DOCKER_FAMILY=apt
            case "$SEC_OS_VERSION" in 12) DOCKER_SUITE=bookworm;; 13) DOCKER_SUITE=trixie;; esac ;;
        ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)
            DOCKER_DISTRO=ubuntu; DOCKER_FAMILY=apt
            case "$SEC_OS_VERSION" in 22.04) DOCKER_SUITE=jammy;; 24.04) DOCKER_SUITE=noble;; 26.04) DOCKER_SUITE=resolute;; esac ;;
        rhel:*) DOCKER_DISTRO=rhel; DOCKER_FAMILY=rpm ;;
        rocky:*|almalinux:*|centos:*)
            DOCKER_DISTRO=centos; DOCKER_FAMILY=rpm
            ui_warn 'Rocky/Alma 使用兼容 CentOS 的 Docker 仓库；是否有软件包以实际元数据为准。' ;;
        *) ui_fail '本模块暂不自动安装此发行版的 Docker；旧版系统请先升级。'; return 1 ;;
    esac
    if [ "$DOCKER_FAMILY" = apt ]; then
        DOCKER_ARCH=$(dpkg --print-architecture) || return 1
        case "$DOCKER_ARCH" in amd64|arm64|armhf|s390x|ppc64el) ;; *) return 1;; esac
    else
        DOCKER_SUITE=${SEC_OS_VERSION%%.*}
        DOCKER_ARCH=$(uname -m)
        case "$DOCKER_ARCH" in x86_64|aarch64|s390x) ;; *) return 1;; esac
    fi
}

docker_conflicts() {
    local package found=0 status
    if command -v docker >/dev/null 2>&1 || command -v dockerd >/dev/null 2>&1; then
        ui_warn '检测到已有 Docker/兼容 CLI，本模块不自动重装或升级；可使用菜单 2 配置镜像。'
        return 0
    fi
    for package in docker-ce docker-ce-cli docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd containerd.io runc moby-engine docker docker-client docker-common; do
        if [ "$DOCKER_FAMILY" = apt ]; then
            status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
            [ "$status" = 'install ok installed' ] || continue
        else rpm -q "$package" >/dev/null 2>&1 || continue; fi
        ui_warn "发现现有运行时/冲突包: $package；请自行确认依赖，不自动卸载。"
        found=1
    done
    [ "$found" -eq 1 ]
}

docker_existing_repo() {
    if [ "$DOCKER_FAMILY" = apt ]; then
        grep -Eil 'download\.docker\.com|docker-ce|sec-toolbox-docker' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null
    else
        grep -Eil 'download\.docker\.com|docker-ce|sec-toolbox-docker' /etc/yum.repos.d/*.repo 2>/dev/null
    fi
}

verify_docker_key() {
    local file="$1" expected="$2" work="$3" fingerprints
    fingerprints=$(gpg --homedir "$work" --batch --show-keys --with-colons "$file" 2>/dev/null |
        awk -F: '$1=="pub" { primary=1; next } $1=="fpr" && primary { print $10; primary=0 }') || return 1
    [ "$fingerprints" = "$expected" ] || { ui_fail 'Docker 签名主密钥指纹不匹配，拒绝此下载。'; return 1; }
}

prepare_docker_repo() {
    local root="$1" work="$2" base expected
    base="$root/linux/$DOCKER_DISTRO"
    if [ "$DOCKER_FAMILY" = apt ]; then expected=$DOCKER_APT_FINGERPRINT; else expected=$DOCKER_RPM_FINGERPRINT; fi
    docker_fetch "$base/gpg" "$work/docker.asc" || return 1
    verify_docker_key "$work/docker.asc" "$expected" "$work" || return 1
    if [ "$DOCKER_FAMILY" = apt ]; then
        docker_fetch "$base/dists/$DOCKER_SUITE/InRelease" "$work/InRelease" || return 1
        gpg --homedir "$work" --batch --yes --dearmor -o "$work/docker.gpg" "$work/docker.asc" || return 1
        gpgv --keyring "$work/docker.gpg" "$work/InRelease" >/dev/null 2>&1 || return 1
        grep -Eq "^(Codename|Suite): ${DOCKER_SUITE}$" "$work/InRelease" || return 1
        awk -v arch="$DOCKER_ARCH" '$1=="Architectures:" { for(i=2;i<=NF;i++) if($i==arch) ok=1 } END { exit !ok }' "$work/InRelease" || return 1
        cat > "$work/source" <<CONFIG
Types: deb
URIs: $base
Suites: $DOCKER_SUITE
Components: stable
Architectures: $DOCKER_ARCH
Signed-By: $DOCKER_APT_KEY
CONFIG
    else
        # RPM repos are not necessarily metadata-signed; enforce package signing.
        base="$base/$DOCKER_SUITE/$DOCKER_ARCH/stable"
        docker_fetch "$base/repodata/repomd.xml" "$work/repomd.xml" || return 1
        grep -q '<repomd' "$work/repomd.xml" || return 1
        cat > "$work/source" <<CONFIG
[sec-toolbox-docker-ce-stable]
name=Docker CE Stable ($DOCKER_ARCH)
baseurl=$base
enabled=1
gpgcheck=1
gpgkey=file://$DOCKER_RPM_KEY
CONFIG
    fi
}

docker_host_ready() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

install_docker() (
    local work root repo key keep_repo=0 virt="" cmd
    [ "${SEC_LOCAL_MODE:-0}" != 1 ] || { ui_fail '本地模式不进行联网安装。'; return 1; }
    docker_platform || return 1
    docker_host_ready || { ui_fail '自动安装暂要求 systemd 正常运行。'; return 1; }
    if command -v systemd-detect-virt >/dev/null 2>&1; then virt=$(systemd-detect-virt --container 2>/dev/null || true); fi
    [[ -z "$virt" || "$virt" = none ]] || { ui_fail '不在容器内自动安装 Docker Engine。'; return 1; }
    docker_conflicts && return 1
    if docker_existing_repo; then ui_fail '检测到已有 Docker 仓库，请先核对；不叠加或覆盖。'; return 1; fi
    ui_info "目标: $SEC_OS_ID $SEC_OS_VERSION / $DOCKER_ARCH；安装 Docker Engine、Buildx、Compose 插件。"
    ui_warn '将安装软件并启动 Docker，可能改变网络/防火墙规则；Docker 发布端口可能绕过 UFW。不会添加用户到 docker 组。'
    ui_warn '官方安装仓库失败时尝试阿里、清华；这不是 Docker Hub 镜像加速。'
    confirm_action 'INSTALL DOCKER' || return 1
    command -v flock >/dev/null 2>&1 || { ui_fail '缺少 flock，请安装 util-linux。'; return 1; }
    mkdir -p "$DOCKER_BACKUPS" || return 1
    chmod 700 "$DOCKER_BACKUPS" || return 1
    exec 8>"$DOCKER_BACKUPS/.install.lock" || return 1
    flock -n 8 || { ui_fail '另一个 Docker 操作正在运行。'; return 1; }
    docker_conflicts && return 1
    if [ "$DOCKER_FAMILY" = apt ]; then
        apt-get -o APT::Update::Error-Mode=any -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update || return 1
        apt-get install -y --no-remove ca-certificates curl gnupg gpgv jq || return 1
        repo=$DOCKER_APT_SOURCE; key=$DOCKER_APT_KEY
    else
        command -v dnf >/dev/null 2>&1 || { ui_fail '缺少 dnf。'; return 1; }
        dnf install -y ca-certificates curl gnupg2 jq || return 1
        repo=$DOCKER_RPM_SOURCE; key=$DOCKER_RPM_KEY
    fi
    [ ! -e "$repo" ] && [ ! -L "$repo" ] && [ ! -e "$key" ] && [ ! -L "$key" ] || { ui_fail '托管源/密钥已存在，拒绝覆盖。'; return 1; }
    work=$(mktemp -d "$DOCKER_BACKUPS/install.XXXXXX") || return 1
    # Keep logs and downloaded verified key as an installation record.
    trap 'if [ "$keep_repo" -eq 0 ]; then rm -f -- "$repo" "$key"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for root in "${DOCKER_REPO_ROOTS[@]}"; do
        ui_info "检查安装仓库: $root"
        prepare_docker_repo "$root" "$work" > "$work/probe.log" 2>&1 || { tail -n 5 "$work/probe.log"; continue; }
        mkdir -p "$(dirname "$repo")" "$(dirname "$key")" || return 1
        install -m 0644 "$work/docker.asc" "$key" && install -m 0644 "$work/source" "$repo" || return 1
        if [ "$DOCKER_FAMILY" = apt ]; then
            if ! apt-get -o APT::Update::Error-Mode=any -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update > "$work/update.log" 2>&1; then
                tail -n 8 "$work/update.log"; rm -f "$repo" "$key"; continue
            fi
            # Fetch packages before installing, so a reachable metadata endpoint
            # with blocked package downloads can still fall back safely.
            if ! apt-get -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --download-only --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > "$work/download.log" 2>&1; then
                tail -n 8 "$work/download.log"; rm -f "$repo" "$key"; continue
            fi
            # Once package installation starts, don't pretend partial packages can
            # be rolled back by deleting a repo. Retain it and report failure.
            keep_repo=1
            apt-get install -y --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || {
                ui_fail "安装失败，可能已有部分依赖安装；保留已验证的源，记录: $work"; return 1;
            }
        else
            if ! dnf --disablerepo='*' --enablerepo=sec-toolbox-docker-ce-stable makecache --refresh > "$work/update.log" 2>&1; then
                tail -n 8 "$work/update.log"; rm -f "$repo" "$key"; continue
            fi
            keep_repo=1
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || {
                ui_fail "安装失败，保留已验证的源，记录: $work"; return 1;
            }
        fi
        systemctl enable --now docker || { ui_fail '软件已安装，但 Docker 启动失败，请查看 journalctl -u docker。'; return 1; }
        docker info >/dev/null 2>&1 && docker compose version || { ui_fail '安装后的 Docker/Compose 验证失败。'; return 1; }
        ui_ok "Docker 安装完成。使用仓库: $root；记录: $work"
        if ! docker_hub_reachable; then
            ui_warn 'Docker Hub 探测失败。需要镜像拉取加速时，请使用菜单 2 填写你信任的专属 HTTPS 加速地址。'
        fi
        return 0
    done
    ui_fail "所有安装仓库均无法通过验证，未安装 Docker；记录: $work"
    return 1
)

docker_hub_reachable() {
    local code
    code=$(curl -sS --proto '=https' --connect-timeout 5 --max-time 12 -o /dev/null -w '%{http_code}' https://registry-1.docker.io/v2/) || return 1
    # A 401 challenge from the registry is normal without a token.
    [ "$code" = 200 ] || [ "$code" = 401 ]
}

validate_registry_url() {
    # Restrict to a simple HTTPS host[:port]; no credentials, query, or shell text.
    [[ "$1" =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?/?$ ]] || return 1
    local host="${1#https://}" port
    host=${host%/}
    if [[ "$host" == *:* ]]; then
        port=${host##*:}
        [ "$((10#$port))" -ge 1 ] && [ "$((10#$port))" -le 65535 ] || return 1
    fi
    return 0
}

merge_registry_mirror() {
    local original="$1" target="$2" url="$3"
    validate_registry_url "$url" || return 1
    jq --arg url "${url%/}" '
        if type != "object" then error("daemon.json must be an object") else . end |
        if has("registry-mirrors") and ((.["registry-mirrors"] | type) != "array" or any(.["registry-mirrors"][]; type != "string"))
        then error("registry-mirrors must be a string array") else . end |
        .["registry-mirrors"] = ([$url] + ((.["registry-mirrors"] // []) | map(select(. != $url))))
    ' "$original" > "$target"
}

configure_docker_mirror() (
    local url work existed=0 running=0 code apply_now=0
    [ "${SEC_LOCAL_MODE:-0}" != 1 ] || { ui_fail '本地模式不联网探测或配置加速地址。'; return 1; }
    local cmd
    for cmd in curl jq dockerd docker systemctl flock; do command -v "$cmd" >/dev/null 2>&1 || { ui_fail "缺少 $cmd，请先安装 Docker 与 jq/curl/util-linux。"; return 1; }; done
    [ ! -L "$DOCKER_DAEMON_CONFIG" ] && [ ! -L "$(dirname "$DOCKER_DAEMON_CONFIG")" ] || { ui_fail 'Docker 配置路径为符号链接，拒绝覆盖。'; return 1; }
    if docker_hub_reachable; then ui_info 'Docker Hub API 可达；这不保证所有镜像层下载均可达，无需加速可直接回车取消。'
    else ui_warn 'Docker Hub API 探测失败（可能是网络/DNS/代理问题）。'; fi
    ui_warn '公共加速地址可能失效、记录拉取信息或改变内容。仅填写你信任/自建或云厂商账户提供的专属地址，不设置 insecure-registries。'
    read -rp '可信加速地址（https://主机[:端口]，回车取消）: ' url || return 1
    [ -n "$url" ] || return 0
    validate_registry_url "$url" || { ui_fail '地址必须为不含账号、路径、参数的 HTTPS 主机地址。'; return 1; }
    code=$(curl -sS --proto '=https' --connect-timeout 5 --max-time 12 -o /dev/null -w '%{http_code}' "${url%/}/v2/") || return 1
    [ "$code" = 200 ] || { ui_fail "镜像 API 返回 $code，不能确认可用于匿名镜像加速；未修改。"; return 1; }
    mkdir -p "$DOCKER_BACKUPS" || return 1
    chmod 700 "$DOCKER_BACKUPS" || return 1
    exec 8>"$DOCKER_BACKUPS/.install.lock" || return 1
    flock -n 8 || { ui_fail '另一个 Docker 操作正在运行。'; return 1; }
    work=$(mktemp -d "$DOCKER_BACKUPS/mirror.XXXXXX") || return 1
    if [ -e "$DOCKER_DAEMON_CONFIG" ]; then
        [ -f "$DOCKER_DAEMON_CONFIG" ] || return 1
        cp -p "$DOCKER_DAEMON_CONFIG" "$work/original.json" || return 1; existed=1
    else printf '{}\n' > "$work/original.json"; fi
    merge_registry_mirror "$work/original.json" "$work/candidate.json" "$url" || { ui_fail '原 JSON 无效，未修改。'; return 1; }
    dockerd --validate --config-file "$work/candidate.json" || { ui_fail 'Docker 配置校验失败或版本不支持校验，未修改。'; return 1; }
    if systemctl is-active --quiet docker; then running=1; fi
    ui_warn '更改仅合并 registry-mirrors，保留其他配置。重启 Docker 可能中断已有容器；不会自动重启。'
    confirm_action 'SAVE MIRROR' || return 1
    if [ "$running" -eq 1 ]; then
        if confirm_action 'RESTART DOCKER'; then apply_now=1; fi
    fi
    mkdir -p "$(dirname "$DOCKER_DAEMON_CONFIG")" || return 1
    local tmp
    tmp=$(mktemp "${DOCKER_DAEMON_CONFIG}.XXXXXX") || return 1
    if ! cat "$work/candidate.json" > "$tmp"; then rm -f "$tmp"; return 1; fi
    if [ "$existed" -eq 1 ]; then chmod --reference="$work/original.json" "$tmp" || { rm -f "$tmp"; return 1; }
    else chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }; fi
    # Do not overwrite an administrator edit made while confirmation was open.
    if { [ "$existed" -eq 1 ] && ! cmp -s "$work/original.json" "$DOCKER_DAEMON_CONFIG"; } ||
       { [ "$existed" -eq 0 ] && { [ -e "$DOCKER_DAEMON_CONFIG" ] || [ -L "$DOCKER_DAEMON_CONFIG" ]; }; }; then
        rm -f "$tmp"; ui_fail 'Docker 配置已被其他进程修改，本次取消。'; return 1
    fi
    mv -f "$tmp" "$DOCKER_DAEMON_CONFIG" || { rm -f "$tmp"; return 1; }
    if [ "$apply_now" -eq 1 ]; then
        if ! systemctl restart docker || ! docker info >/dev/null 2>&1; then
            if [ "$existed" -eq 1 ]; then cp -p "$work/original.json" "$DOCKER_DAEMON_CONFIG" || return 1
            else rm -f "$DOCKER_DAEMON_CONFIG" || return 1; fi
            systemctl restart docker || ui_fail '旧配置已恢复，但服务仍失败，请通过控制台检查。'
            ui_fail "新配置启用失败，已回滚；备份: $work"; return 1
        fi
        ui_ok '配置已启用；API 探测不保证所有镜像均可拉取。'
    else ui_ok '配置已保存，服务未重启；将在下次 Docker 启动时生效。'; fi
    ui_info "备份: $work"
)
