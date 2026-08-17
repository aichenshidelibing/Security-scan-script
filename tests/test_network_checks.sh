#!/usr/bin/env bash
set -u
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/lib/network_checks.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [ "$1" = "$2" ] || fail "expected '$1', got '$2'"; }

# The IPv6-only path must not try IPv4 probes.
ip() {
    case "$*" in
        *"-4 addr show"*) printf ''; return 0 ;;
        *"-6 addr show"*) printf '2: eth0    inet6 2001:db8::10/64 scope global\n'; return 0 ;;
        *"-6 route show default"*) printf 'default via 2001:db8::1 dev eth0\n'; return 0 ;;
        *) return 1 ;;
    esac
}
assert_eq pure_ipv6 "$(sec_detect_ip_mode)"

ping() { case "$*" in *"-6"*) return 0 ;; *) return 1 ;; esac; }
assert_eq ok_ipv6 "$(sec_probe_icmp pure_ipv6)"

getent() { [ "$1" = ahosts ] && return 0; return 1; }
assert_eq ok "$(sec_probe_dns)"

printf 'PASS: IPv6-only mode selects IPv6 ICMP and resolver probes\n'
