#!/usr/bin/env bash
# GitHub/raw download helpers. All endpoints are best-effort and are probed at runtime.
# Official GitHub is always attempted first; accelerators are fallbacks only.

SEC_GITHUB_OFFICIAL_BASE="${SEC_GITHUB_OFFICIAL_BASE:-https://raw.githubusercontent.com}"
SEC_GITHUB_ENDPOINT_FILE="${SEC_GITHUB_ENDPOINT_FILE:-/etc/sec-toolbox/github-endpoint}"
SEC_GITHUB_PROBE_PATH="${SEC_GITHUB_PROBE_PATH:-aichenshidelibing/Security-scan-script/main/install.sh}"
SEC_GITHUB_PROBE_MARKER="${SEC_GITHUB_PROBE_MARKER:-<SEC_SCRIPT_MARKER_v2.3>}"
SEC_GITHUB_CACHE_TTL="${SEC_GITHUB_CACHE_TTL:-600}"

sec_github_family_arg() {
    local mode=""
    if command -v sec_detect_ip_mode >/dev/null 2>&1; then
        mode=$(sec_detect_ip_mode 2>/dev/null || true)
    elif command -v ip >/dev/null 2>&1; then
        if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 ' &&
           ! ip -4 addr show scope global 2>/dev/null | grep -q 'inet '; then
            mode=pure_ipv6
        fi
    fi
    [ "$mode" = pure_ipv6 ] && printf '%s\n' '-6'
}

sec_github_endpoint_entries() {
    cat <<'EOF'
official|https://raw.githubusercontent.com
gh-proxy|https://gh-proxy.org/raw.githubusercontent.com
ghproxy|https://ghproxy.net/https://raw.githubusercontent.com
ghfast|https://ghfast.top/https://raw.githubusercontent.com
gh-proxy-com|https://gh-proxy.com/https://raw.githubusercontent.com
EOF
}

sec_github_endpoint_url() {
    local entry="$1" path="$2" base
    base="${entry#*|}"
    path="${path#/}"
    printf '%s/%s\n' "$base" "$path"
}

sec_github_valid_endpoint_name() {
    local name="${1:-}"
    [ -n "$name" ] || return 1
    sec_github_entry_for_name "$name" | grep -Fq -- '|'
}

sec_github_cache_file() {
    printf '%s.cache\n' "$SEC_GITHUB_ENDPOINT_FILE"
}

sec_github_selected_endpoint() {
    local name=""
    [ -r "$SEC_GITHUB_ENDPOINT_FILE" ] || return 0
    IFS= read -r name <"$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null || true
    name=$(printf '%s' "$name" | tr -d '[:space:]')
    sec_github_valid_endpoint_name "$name" && printf '%s\n' "$name"
}

sec_github_set_endpoint() {
    local name="${1:-}" dir tmp current
    sec_github_valid_endpoint_name "$name" || return 2
    current=$(sec_github_selected_endpoint)
    # Idempotent: do not rewrite a valid, already selected endpoint.
    [ "$current" = "$name" ] && return 0
    dir=$(dirname -- "$SEC_GITHUB_ENDPOINT_FILE")
    mkdir -p "$dir" 2>/dev/null || return 1
    tmp="${SEC_GITHUB_ENDPOINT_FILE}.tmp.$$.$RANDOM"
    (umask 077; printf '%s\n' "$name" >"$tmp") || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$SEC_GITHUB_ENDPOINT_FILE" || { rm -f -- "$tmp"; return 1; }
    chmod 0644 "$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null || true
}

sec_github_mark_endpoint_checked() {
    local name="${1:-}" cache tmp now
    sec_github_valid_endpoint_name "$name" || return 2
    cache=$(sec_github_cache_file)
    mkdir -p "$(dirname -- "$cache")" 2>/dev/null || return 1
    now=$(date +%s 2>/dev/null) || return 1
    tmp="${cache}.tmp.$$.$RANDOM"
    (umask 077; printf '%s|%s\n' "$name" "$now" >"$tmp") || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$cache" || { rm -f -- "$tmp"; return 1; }
    chmod 0644 "$cache" 2>/dev/null || true
}

sec_github_selected_endpoint_fresh() {
    local selected cache cache_name timestamp now age
    selected=$(sec_github_selected_endpoint)
    [ -n "$selected" ] || return 1
    case "$SEC_GITHUB_CACHE_TTL" in
        ''|*[!0-9]*) return 1 ;;
    esac
    cache=$(sec_github_cache_file)
    [ -r "$cache" ] || return 1
    IFS='|' read -r cache_name timestamp <"$cache" 2>/dev/null || return 1
    [ "$cache_name" = "$selected" ] || return 1
    [[ "$timestamp" =~ ^[0-9]+$ ]] || return 1
    now=$(date +%s 2>/dev/null) || return 1
    [ "$now" -ge "$timestamp" ] || return 1
    age=$((now - timestamp))
    [ "$age" -le "$SEC_GITHUB_CACHE_TTL" ]
}

sec_github_entry_for_name() {
    local name="$1"
    sec_github_endpoint_entries | awk -F'|' -v wanted="$name" '$1 == wanted { print; exit }'
}

sec_github_fetch() {
    # sec_github_fetch PATH OUTPUT [EXPECTED_MARKER]
    local path="$1" output="$2" expected="${3:-}" family="" entry name url tmp="" status=1
    [ -n "$path" ] && [ -n "$output" ] || return 2
    family=$(sec_github_family_arg)
    mkdir -p "$(dirname -- "$output")" 2>/dev/null || return 1
    tmp="${output}.tmp.$$.$RANDOM"

    local entries=()
    entries+=("official|$SEC_GITHUB_OFFICIAL_BASE")
    local selected
    selected=$(sec_github_selected_endpoint)
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        name="${entry%%|*}"
        [ "$name" = official ] && continue
        [ -n "$selected" ] && [ "$name" = "$selected" ] && entries+=("$entry")
    done < <(sec_github_endpoint_entries)
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        name="${entry%%|*}"
        [ "$name" = official ] && continue
        if [ "$name" != "$selected" ]; then entries+=("$entry"); fi
    done < <(sec_github_endpoint_entries)

    for entry in "${entries[@]}"; do
        name="${entry%%|*}"
        url=$(sec_github_endpoint_url "$entry" "$path")
        rm -f -- "$tmp"
        if command -v curl >/dev/null 2>&1; then
            if [ -n "$family" ]; then
                curl "$family" -fsSL --connect-timeout 4 --max-time 12 --retry 1 --retry-delay 1 -o "$tmp" "$url" >/dev/null 2>&1
            else
                curl -fsSL --connect-timeout 4 --max-time 12 --retry 1 --retry-delay 1 -o "$tmp" "$url" >/dev/null 2>&1
            fi
        elif command -v wget >/dev/null 2>&1; then
            if [ -n "$family" ]; then
                wget "$family" -q -O "$tmp" --timeout=8 --tries=2 "$url" >/dev/null 2>&1
            else
                wget -q -O "$tmp" --timeout=8 --tries=2 "$url" >/dev/null 2>&1
            fi
        else
            return 127
        fi
        [ -s "$tmp" ] || continue
        if [ -n "$expected" ] && ! grep -Fq -- "$expected" "$tmp" 2>/dev/null; then
            continue
        fi
        mv -f -- "$tmp" "$output"
        if [ "$name" != official ]; then
            # A working fallback becomes the next preferred fallback. Failure to
            # persist it must never turn a successful download into a failure.
            sec_github_set_endpoint "$name" >/dev/null 2>&1 || true
            sec_github_mark_endpoint_checked "$name" >/dev/null 2>&1 || true
        fi
        status=0
        break
    done
    rm -f -- "$tmp"
    return "$status"
}

sec_github_probe_endpoint() {
    sec_github_probe_named_endpoint "${1:-}" "${2:-}" "${3:-}"
}

sec_github_probe_named_endpoint() {
    # Probe one exact endpoint without changing the configured fallback.
    # Keep optional parameters nounset-safe: callers commonly provide only the name.
    local name="${1:-}" path="${2:-}" expected="${3:-}" entry url family tmp
    [ -n "$name" ] || return 2
    entry=$(sec_github_entry_for_name "$name")
    [ -n "$entry" ] || return 2
    path="${path:-$SEC_GITHUB_PROBE_PATH}"
    expected="${expected:-$SEC_GITHUB_PROBE_MARKER}"
    url=$(sec_github_endpoint_url "$entry" "$path")
    family=$(sec_github_family_arg)
    tmp="${TMPDIR:-/tmp}/sec-github-probe.$$.$RANDOM"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$family" ]; then
            curl "$family" -fsSL --connect-timeout 3 --max-time 8 --retry 0 -o "$tmp" "$url" >/dev/null 2>&1
        else
            curl -fsSL --connect-timeout 3 --max-time 8 --retry 0 -o "$tmp" "$url" >/dev/null 2>&1
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget ${family:+$family} -q -O "$tmp" --timeout=6 --tries=1 "$url" >/dev/null 2>&1
    else
        rm -f -- "$tmp"
        return 127
    fi
    [ -s "$tmp" ] && grep -Fq -- "$expected" "$tmp"
    local result=$?
    rm -f -- "$tmp"
    return "$result"
}

sec_github_prepare_endpoint() {
    # Validate and persist a selected endpoint once. A fresh cache avoids a
    # second network probe when the same choice is selected repeatedly.
    local name="$1"
    sec_github_valid_endpoint_name "$name" || return 2
    if [ "$(sec_github_selected_endpoint)" = "$name" ] && sec_github_selected_endpoint_fresh; then
        return 0
    fi
    sec_github_probe_named_endpoint "$name" || return 1
    sec_github_set_endpoint "$name" || return 1
    sec_github_mark_endpoint_checked "$name" || return 1
}

sec_github_endpoint_label() {
    case "$1" in
        official) printf 'GitHub 官方 raw\n' ;;
        gh-proxy) printf 'gh-proxy.org\n' ;;
        ghproxy) printf 'ghproxy.net\n' ;;
        ghfast) printf 'ghfast.top\n' ;;
        gh-proxy-com) printf 'gh-proxy.com\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}
