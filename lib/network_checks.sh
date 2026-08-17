#!/usr/bin/env bash
# Network probes that distinguish unavailable/unsupported from actively blocked.

sec_detect_ip_mode() {
    local has_v4=0 has_v6=0
    if command -v ip >/dev/null 2>&1; then
        ip -4 addr show scope global 2>/dev/null | grep -q 'inet ' && has_v4=1
        ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 ' && has_v6=1
    fi
    if [ "$has_v6" -eq 1 ] && [ "$has_v4" -eq 0 ]; then
        printf '%s\n' pure_ipv6
    elif [ "$has_v4" -eq 1 ] && [ "$has_v6" -eq 1 ]; then
        printf '%s\n' dual_stack
    elif [ "$has_v4" -eq 1 ]; then
        printf '%s\n' ipv4_only
    else
        printf '%s\n' unknown
    fi
}

sec_ipv6_default_route() {
    command -v ip >/dev/null 2>&1 || return 1
    ip -6 route show default 2>/dev/null | grep -q '^default '
}

sec_probe_icmp() {
    local mode="${1:-$(sec_detect_ip_mode)}" target
    command -v ping >/dev/null 2>&1 || { printf '%s\n' missing; return 0; }
    if [ "$mode" = pure_ipv6 ]; then
        sec_ipv6_default_route || { printf '%s\n' no_route; return 0; }
        for target in 2606:4700:4700::1111 2001:4860:4860::8888; do
            if ping -6 -c 1 -W 2 "$target" >/dev/null 2>&1; then printf '%s\n' ok_ipv6; return 0; fi
        done
        printf '%s\n' unavailable_ipv6
        return 0
    fi
    if [ "$mode" = dual_stack ] || [ "$mode" = ipv4_only ]; then
        for target in 1.1.1.1 8.8.8.8; do
            if ping -4 -c 1 -W 2 "$target" >/dev/null 2>&1; then printf '%s\n' ok_ipv4; return 0; fi
        done
        if [ "$mode" = dual_stack ]; then
            for target in 2606:4700:4700::1111 2001:4860:4860::8888; do
                if ping -6 -c 1 -W 2 "$target" >/dev/null 2>&1; then printf '%s\n' ok_ipv6; return 0; fi
            done
        fi
        printf '%s\n' unavailable
        return 0
    fi
    printf '%s\n' unknown
}

sec_probe_dns() {
    if command -v getent >/dev/null 2>&1 && getent ahosts example.com >/dev/null 2>&1; then
        printf '%s\n' ok
    elif command -v resolvectl >/dev/null 2>&1 && resolvectl --legend=no --timeout=3s query example.com >/dev/null 2>&1; then
        printf '%s\n' ok
    elif command -v nslookup >/dev/null 2>&1 && nslookup -timeout=3 example.com >/dev/null 2>&1; then
        printf '%s\n' ok
    elif [ -s /etc/resolv.conf ]; then
        printf '%s\n' unavailable
    else
        printf '%s\n' missing
    fi
}

sec_probe_tcp() {
    local mode="${1:-$(sec_detect_ip_mode)}" family="" url
    command -v curl >/dev/null 2>&1 || { printf '%s\n' missing; return 0; }
    [ "$mode" = pure_ipv6 ] && family=-6
    [ "$mode" = ipv4_only ] && family=-4
    for url in https://example.com https://www.cloudflare.com; do
        if curl ${family:+$family} -fsSI --connect-timeout 3 --max-time 6 "$url" >/dev/null 2>&1; then
            printf '%s\n' ok
            return 0
        fi
    done
    printf '%s\n' unavailable
}

sec_network_label() {
    case "$1" in
        ok|ok_ipv4|ok_ipv6) printf '可用\n' ;;
        missing) printf '未检测(缺少工具)\n' ;;
        no_route) printf '未检测(无 IPv6 默认路由)\n' ;;
        unavailable|unavailable_ipv6|unknown) printf '不可用(不等于本机阻断)\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}
