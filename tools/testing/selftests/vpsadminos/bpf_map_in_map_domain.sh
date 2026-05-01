#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0
helper="$(dirname "$0")/bpf_map_in_map_domain_smoke"

get_field()
{
	printf '%s\n' "$1" | awk -F= -v key="$2" '$1 == key { print $2; exit }'
}

check_eq()
{
	label="$1"
	a="$2"
	b="$3"
	if [ "$a" != "$b" ]; then
		echo "not ok: $label differ: $a vs $b" >&2
		ret=1
	fi
}

if [ "$(id -u)" -ne 0 ]; then
	echo "skip: must run as root" >&2
	exit $ksft_skip
fi

if [ ! -e /proc/self/ns/tracing ]; then
	echo "skip: tracing namespace support not present" >&2
	exit $ksft_skip
fi

if [ ! -r /proc/sys/kernel/bpf_container_tracing_enabled ]; then
	echo "skip: bpf_container_tracing_enabled sysctl missing" >&2
	exit $ksft_skip
fi

if [ "$(cat /proc/sys/kernel/bpf_container_tracing_enabled)" != "1" ]; then
	echo "skip: bpf_container_tracing_enabled must be 1" >&2
	exit $ksft_skip
fi

if [ ! -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then
	echo "skip: unprivileged_bpf_disabled sysctl missing" >&2
	exit $ksft_skip
fi

if [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled)" = "0" ]; then
	echo "skip: test needs unprivileged_bpf_disabled != 0" >&2
	exit $ksft_skip
fi

out="$($helper)" || {
	echo "not ok: helper failed" >&2
	printf '%s\n' "$out" >&2
	exit 1
}

check_eq producer_recv_fd_errno 0 "$(get_field "$out" producer_recv_fd_errno)"
check_eq consumer_send_fd_errno 0 "$(get_field "$out" consumer_send_fd_errno)"
check_eq same_domain_errno 0 "$(get_field "$out" same_domain_errno)"
check_eq tokenless_inner_errno 13 "$(get_field "$out" tokenless_inner_errno)"
check_eq cross_domain_recv_errno 0 "$(get_field "$out" cross_domain_recv_errno)"
check_eq cross_domain_errno 13 "$(get_field "$out" cross_domain_errno)"

exit $ret
