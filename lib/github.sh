#!/usr/bin/env bash
# GitHub/raw download helpers. All endpoints are best-effort and are probed at runtime.
# Official GitHub is always attempted first; accelerators are fallbacks only.

SEC_GITHUB_OFFICIAL_BASE="${SEC_GITHUB_OFFICIAL_BASE:-https://raw.githubusercontent.com}"
SEC_GITHUB_ENDPOINT_FILE="${SEC_GITHUB_ENDPOINT_FILE:-/etc/sec-toolbox/github-endpoint}"
SEC_GITHUB_PROBE_PATH="${SEC_GITHUB_PROBE_PATH:-aichenshidelibing/Security-scan-script/main/install.sh}"
SEC_GITHUB_PROBE_MARKER="${SEC_GITHUB_PROBE_MARKER:-<SEC_SCRIPT_MARKER_v2.3>}"

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

sec_github_selected_endpoint() {
    [ -r "$SEC_GITHUB_ENDPOINT_FILE" ] || return 0
    tr -d '[:space:]' <"$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null | head -n 1
}

sec_github_set_endpoint() {
    local name="$1" dir
    case "$name" in
        official|gh-proxy|ghproxy|ghfast|gh-proxy-com) ;;
        *) return 2 ;;
    esac
    dir=$(dirname -- "$SEC_GITHUB_ENDPOINT_FILE")
    mkdir -p "$dir" 2>/dev/null || return 1
    printf '%s\n' "$name" >"$SEC_GITHUB_ENDPOINT_FILE" || return 1
    chmod 0644 "$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null || true
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
    tmp="${output}.tmp.$$"

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
        status=0
        break
    done
    rm -f -- "$tmp"
    return "$status"
}

sec_github_probe_endpoint() {
    sec_github_probe_named_endpoint "$1"
}

sec_github_probe_named_endpoint() {
    # Probe one exact endpoint without changing the configured fallback.
    local name="$1" path="$2" expected="${3:-}" entry url family tmp
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
