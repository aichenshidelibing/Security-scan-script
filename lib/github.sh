#!/usr/bin/env bash
# GitHub/raw/release download helpers. Endpoint choices are validated at runtime.
# Configured accelerators are preferred; official GitHub raw is the final fallback.

SEC_GITHUB_OFFICIAL_BASE="${SEC_GITHUB_OFFICIAL_BASE:-https://raw.githubusercontent.com}"
SEC_GITHUB_ENDPOINT_FILE="${SEC_GITHUB_ENDPOINT_FILE:-/etc/sec-toolbox/github-endpoint}"
SEC_GITHUB_PROBE_PATH="${SEC_GITHUB_PROBE_PATH:-aichenshidelibing/Security-scan-script/main/install.sh}"
SEC_GITHUB_PROBE_MARKER="${SEC_GITHUB_PROBE_MARKER:-<SEC_SCRIPT_MARKER_v2.3>}"
SEC_GITHUB_CACHE_TTL="${SEC_GITHUB_CACHE_TTL:-600}"
SEC_GITHUB_PROBE_ROUNDS="${SEC_GITHUB_PROBE_ROUNDS:-3}"
SEC_GITHUB_PROBE_MIN_SUCCESS="${SEC_GITHUB_PROBE_MIN_SUCCESS:-2}"

sec_github_family_mode() {
    local mode=""
    if command -v sec_detect_ip_mode >/dev/null 2>&1; then
        mode=$(sec_detect_ip_mode 2>/dev/null || true)
    elif command -v ip >/dev/null 2>&1; then
        if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 ' &&
           ! ip -4 addr show scope global 2>/dev/null | grep -q 'inet '; then
            mode=pure_ipv6
        elif ip -4 addr show scope global 2>/dev/null | grep -q 'inet ' &&
             ! ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
            mode=ipv4_only
        else
            mode=dual_stack
        fi
    else
        mode=dual_stack
    fi
    printf '%s\n' "${mode:-dual_stack}"
}

sec_github_family_arg() {
    [ "$(sec_github_family_mode)" = pure_ipv6 ] && printf '%s\n' '-6'
}

# name|address-family|URL-template|display-label
# {path} is a raw GitHub path; {url} is the complete source URL. Release URLs
# can therefore be passed directly without assuming every proxy has the same form.
sec_github_endpoint_entries() {
    sec_github_endpoint_entries_raw
}
sec_github_endpoint_entries_raw() {
    cat <<'EOF'
official|any|https://raw.githubusercontent.com/{path}|GitHub 官方 raw
gh-proxy-org|any|https://gh-proxy.org/https://raw.githubusercontent.com/{path}|gh-proxy.org
gh-proxy-v4|ipv4|https://v4.gh-proxy.org/https://raw.githubusercontent.com/{path}|v4.gh-proxy.org（IPv4）
gh-proxy-v6|ipv6|https://v6.gh-proxy.org/https://raw.githubusercontent.com/{path}|v6.gh-proxy.org（IPv6）
gh-proxy-cdn|any|https://cdn.gh-proxy.org/https://raw.githubusercontent.com/{path}|cdn.gh-proxy.org
axisnow|any|https://axisnow.gh-proxy.org/{url}|axisnow.gh-proxy.org
gh-proxy-com|any|https://gh-proxy.com/{url}|gh-proxy.com
gh-proxy|any|https://gh-proxy.org/{url}|gh-proxy.org（兼容别名）
ghproxy|any|https://ghproxy.net/{url}|ghproxy.net
ghfast|any|https://ghfast.top/{url}|ghfast.top
EOF
}

sec_github_entry_for_name() {
    local name="${1:-}"
    sec_github_endpoint_entries | awk -F'|' -v wanted="$name" '$1 == wanted { print; exit }'
}

sec_github_endpoint_family() {
    local entry
    entry=$(sec_github_entry_for_name "${1:-}")
    printf '%s\n' "${entry#*|}" | cut -d'|' -f1
}

sec_github_endpoint_supported() {
    local name="${1:-}" mode family
    family=$(sec_github_endpoint_family "$name")
    mode=$(sec_github_family_mode)
    [ "$name" = official ] && return 0
    case "$mode:$family" in
        pure_ipv6:any|pure_ipv6:ipv6|dual_stack:*) return 0 ;;
        ipv4_only:any|ipv4_only:ipv4) return 0 ;;
        *) return 1 ;;
    esac
}

sec_github_endpoint_url() {
    local entry="$1" path="$2" template source_url path_value
    template=$(printf '%s\n' "$entry" | cut -d'|' -f3- | cut -d'|' -f1)
    path="${path#/}"
    if [[ "$path" =~ ^https?:// ]]; then
        source_url="$path"
    else
        source_url="${SEC_GITHUB_OFFICIAL_BASE%/}/$path"
    fi
    if [ "${entry%%|*}" = official ] && [[ "$path" =~ ^https?:// ]]; then
        printf '%s\n' "$source_url"
        return 0
    fi
    path_value="$path"
    [ "$source_url" != "$path" ] && path_value="$source_url"
    template=${template//\{path\}/$path_value}
    template=${template//\{url\}/$source_url}
    printf '%s\n' "$template"
}

sec_github_valid_endpoint_name() {
    [ -n "${1:-}" ] && sec_github_entry_for_name "$1" | grep -Fq -- '|'
}

sec_github_cache_file() { printf '%s.cache\n' "$SEC_GITHUB_ENDPOINT_FILE"; }

sec_github_selected_endpoints() {
    local name
    [ -r "$SEC_GITHUB_ENDPOINT_FILE" ] || return 0
    while IFS= read -r name; do
        name=$(printf '%s' "$name" | tr -d '[:space:]')
        [ -n "$name" ] || continue
        sec_github_valid_endpoint_name "$name" && sec_github_endpoint_supported "$name" &&
            printf '%s\n' "$name"
    done <"$SEC_GITHUB_ENDPOINT_FILE" | awk '!seen[$0]++'
}

sec_github_selected_endpoint() { sec_github_selected_endpoints | sed -n '1p'; }

sec_github_set_endpoints() {
    local dir tmp name count=0 current new_content="" new_names=() existing duplicate
    dir=$(dirname -- "$SEC_GITHUB_ENDPOINT_FILE")
    mkdir -p "$dir" 2>/dev/null || return 1
    for name in "$@"; do
        duplicate=0
        for existing in "${new_names[@]}"; do
            if [ "$existing" = "$name" ]; then duplicate=1; break; fi
        done
        [ "$duplicate" -eq 0 ] || continue
        new_names+=("$name")
        sec_github_endpoint_supported "$name" || continue
        new_content="${new_content}${name}"$'\n'
        count=$((count + 1))
    done
    [ "$count" -gt 0 ] || return 2
    current=$(cat "$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null || true)
    [ "$current" = "$new_content" ] && return 0
    tmp="${SEC_GITHUB_ENDPOINT_FILE}.tmp.$$.$RANDOM"
    (umask 077; printf '%b' "$new_content" >"$tmp") || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$SEC_GITHUB_ENDPOINT_FILE" || { rm -f -- "$tmp"; return 1; }
    chmod 0644 "$SEC_GITHUB_ENDPOINT_FILE" 2>/dev/null || true
}

sec_github_set_endpoint() { sec_github_set_endpoints "$1"; }

sec_github_mark_endpoint_checked() {
    local name="${1:-}" cache tmp now success="${2:-}" avg="${3:-}"
    sec_github_valid_endpoint_name "$name" || return 2
    cache=$(sec_github_cache_file)
    mkdir -p "$(dirname -- "$cache")" 2>/dev/null || return 1
    now=$(date +%s 2>/dev/null) || return 1
    tmp="${cache}.tmp.$$.$RANDOM"
    (umask 077; printf '%s|%s|%s|%s\n' "$name" "$now" "$success" "$avg" >"$tmp") || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$cache" || { rm -f -- "$tmp"; return 1; }
    chmod 0644 "$cache" 2>/dev/null || true
}

sec_github_selected_endpoint_fresh() {
    local selected cache timestamp now age cache_name
    selected=$(sec_github_selected_endpoint)
    [ -n "$selected" ] || return 1
    case "$SEC_GITHUB_CACHE_TTL" in ''|*[!0-9]*) return 1 ;; esac
    cache=$(sec_github_cache_file)
    [ -r "$cache" ] || return 1
    cache_name=""; timestamp=""
    IFS='|' read -r cache_name timestamp _ <"$cache" 2>/dev/null || return 1
    [ "$cache_name" = "$selected" ] || return 1
    [[ "$timestamp" =~ ^[0-9]+$ ]] || return 1
    now=$(date +%s 2>/dev/null) || return 1
    [ "$now" -ge "$timestamp" ] || return 1
    age=$((now - timestamp))
    [ "$age" -le "$SEC_GITHUB_CACHE_TTL" ]
}

sec_github_probe_once() {
    local name="${1:-}" path="${2:-$SEC_GITHUB_PROBE_PATH}" expected="${3:-$SEC_GITHUB_PROBE_MARKER}" entry url family tmp result
    entry=$(sec_github_entry_for_name "$name")
    [ -n "$entry" ] && sec_github_endpoint_supported "$name" || return 2
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
        return 127
    fi
    [ -s "$tmp" ] && grep -Fq -- "$expected" "$tmp"
    result=$?
    rm -f -- "$tmp"
    return "$result"
}

sec_github_probe_endpoint() { sec_github_probe_named_endpoint "${1:-}" "${2:-}" "${3:-}"; }
sec_github_probe_named_endpoint() { sec_github_probe_once "${1:-}" "${2:-}" "${3:-}"; }

sec_github_probe_named_endpoint_rounds() {
    local name="${1:-}" rounds="${2:-$SEC_GITHUB_PROBE_ROUNDS}" success=0 i=0 min
    case "$rounds" in ''|*[!0-9]*) rounds=3 ;; esac
    while [ "$i" -lt "$rounds" ]; do
        sec_github_probe_once "$name" >/dev/null 2>&1 && success=$((success + 1))
        i=$((i + 1))
    done
    printf '%s|%s|%s\n' "$name" "$success" "$rounds"
    min="$SEC_GITHUB_PROBE_MIN_SUCCESS"
    case "$min" in ''|*[!0-9]*) min=2 ;; esac
    [ "$success" -ge "$min" ]
}

sec_github_probe_all() {
    local entry name probed=0
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        name="${entry%%|*}"
        sec_github_endpoint_supported "$name" || continue
        probed=1
        sec_github_probe_named_endpoint_rounds "$name" || true
    done < <(sec_github_endpoint_entries)
    [ "$probed" -eq 1 ]
}

sec_github_auto_select() {
    local selected tmp line best_success=0 name success rounds
    if [ "${SEC_GITHUB_FORCE_RECHECK:-0}" != 1 ] && sec_github_selected_endpoint_fresh; then
        return 0
    fi
    tmp="${TMPDIR:-/tmp}/sec-github-auto.$$.$RANDOM"
    sec_github_probe_all >"$tmp" || true
    while IFS='|' read -r name success rounds; do
        [ -n "$name" ] && [ "$name" != official ] || continue
        [ "${success:-0}" -ge "${SEC_GITHUB_PROBE_MIN_SUCCESS:-2}" ] 2>/dev/null || continue
        if [ "$success" -gt "$best_success" ]; then best_success="$success"; fi
    done <"$tmp"
    [ "$best_success" -gt 0 ] || { rm -f -- "$tmp"; return 1; }
    # Stable priority: highest success count first, then the built-in endpoint order.
    : >"${tmp}.names"
    while IFS='|' read -r name success rounds; do
        [ -n "$name" ] && [ "$name" != official ] || continue
        [ "${success:-0}" -ge "${SEC_GITHUB_PROBE_MIN_SUCCESS:-2}" ] 2>/dev/null || continue
        printf '%s|%s\n' "$success" "$name" >>"${tmp}.names"
    done <"$tmp"
    sort -t'|' -k1,1nr -s "${tmp}.names" | cut -d'|' -f2 >"${SEC_GITHUB_ENDPOINT_FILE}.auto"
    mkdir -p "$(dirname -- "$SEC_GITHUB_ENDPOINT_FILE")" 2>/dev/null || { rm -f -- "$tmp" "${tmp}.names"; return 1; }
    mv -f -- "${SEC_GITHUB_ENDPOINT_FILE}.auto" "$SEC_GITHUB_ENDPOINT_FILE" || { rm -f -- "$tmp" "${tmp}.names"; return 1; }
    name=$(sed -n '1p' "$SEC_GITHUB_ENDPOINT_FILE")
    while IFS='|' read -r line success rounds; do
        [ "$line" = "$name" ] || continue
        sec_github_mark_endpoint_checked "$line" "$success" "$rounds" >/dev/null 2>&1 || true
        break
    done <"$tmp"
    rm -f -- "$tmp" "${tmp}.names"
}

sec_github_prepare_endpoint() {
    local name="$1"
    sec_github_valid_endpoint_name "$name" || return 2
    sec_github_endpoint_supported "$name" || return 1
    if [ "$(sec_github_selected_endpoint)" = "$name" ] && sec_github_selected_endpoint_fresh; then return 0; fi
    local probe_tmp="${TMPDIR:-/tmp}/sec-github-prepare.$$.$RANDOM"
    sec_github_probe_named_endpoint_rounds "$name" >"$probe_tmp" || { rm -f -- "$probe_tmp"; return 1; }
    IFS='|' read -r _ success rounds <"$probe_tmp" || true
    rm -f -- "$probe_tmp"
    [ "${success:-0}" -ge "${SEC_GITHUB_PROBE_MIN_SUCCESS:-2}" ] 2>/dev/null || return 1
    sec_github_set_endpoint "$name" || return 1
    sec_github_mark_endpoint_checked "$name" "$success" "$rounds" || return 1
}

sec_github_fetch() {
    local path="$1" output="$2" expected="${3:-}" family="" entry name url tmp="" status=1 selected_name
    [ -n "$path" ] && [ -n "$output" ] || return 2
    family=$(sec_github_family_arg)
    mkdir -p "$(dirname -- "$output")" 2>/dev/null || return 1
    tmp="${output}.tmp.$$.$RANDOM"
    local entries=() seen="|"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        entry=$(sec_github_entry_for_name "$name")
        [ -n "$entry" ] || continue
        entries+=("$entry")
        seen="${seen}${name}|"
    done < <(sec_github_selected_endpoints)
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        name="${entry%%|*}"
        [ "$name" = official ] && continue
        case "$seen" in *"|$name|"*) continue ;; esac
        entries+=("$entry"); seen="${seen}${name}|"
    done < <(sec_github_endpoint_entries)
    entry=$(sec_github_entry_for_name official)
    [ -n "$entry" ] && entries+=("$entry")

    for entry in "${entries[@]}"; do
        name="${entry%%|*}"
        url=$(sec_github_endpoint_url "$entry" "$path")
        rm -f -- "$tmp"
        if command -v curl >/dev/null 2>&1; then
            if [ -n "$family" ]; then curl "$family" -fsSL --connect-timeout 4 --max-time 12 --retry 1 --retry-delay 1 -o "$tmp" "$url" >/dev/null 2>&1
            else curl -fsSL --connect-timeout 4 --max-time 12 --retry 1 --retry-delay 1 -o "$tmp" "$url" >/dev/null 2>&1; fi
        elif command -v wget >/dev/null 2>&1; then
            wget ${family:+$family} -q -O "$tmp" --timeout=8 --tries=2 "$url" >/dev/null 2>&1
        else
            return 127
        fi
        [ -s "$tmp" ] || continue
        [ -z "$expected" ] || grep -Fq -- "$expected" "$tmp" 2>/dev/null || continue
        mv -f -- "$tmp" "$output"
        if [ "$name" != official ]; then
            sec_github_set_endpoints "$name" $(sec_github_selected_endpoints | grep -v -F -x "$name") >/dev/null 2>&1 || true
            sec_github_mark_endpoint_checked "$name" >/dev/null 2>&1 || true
        fi
        status=0; break
    done
    rm -f -- "$tmp"
    return "$status"
}

sec_github_endpoint_label() {
    local label
    label=$(sec_github_entry_for_name "${1:-}" | cut -d'|' -f4-)
    [ -n "$label" ] && printf '%s\n' "$label" || printf '%s\n' "${1:-unknown}"
}
