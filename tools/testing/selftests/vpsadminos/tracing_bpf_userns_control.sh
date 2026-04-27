#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0
helper="$(dirname "$0")/tracing_bpf_userns_smoke"

get_field()
{
	printf '%s\n' "$1" | awk -F= -v key="$2" '$1 == key { print $2; exit }'
}

check_ne()
{
	label="$1"
	a="$2"
	b="$3"
	if [ "$a" = "$b" ]; then
		echo "not ok: $label unexpectedly equal: $a" >&2
		ret=1
	fi
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

symbol="copy_process"
out="$($helper --syslog-name "traceH$$" --symbol "$symbol")" || {
	echo "not ok: helper failed" >&2
	exit 1
}

if [ "$(get_field "$out" parent_kallsyms_has_symbol)" != "1" ]; then
	echo "skip: host kallsyms does not expose $symbol on this kernel" >&2
	exit $ksft_skip
fi

check_ne nested_user_boundary "$(get_field "$out" child_user)" "$(get_field "$out" nested_user)"
check_eq nested_keeps_tracing "$(get_field "$out" child_tracing)" "$(get_field "$out" nested_tracing)"
check_eq child_kallsyms_has_symbol 0 "$(get_field "$out" child_kallsyms_has_symbol)"
check_eq nested_kallsyms_has_symbol 0 "$(get_field "$out" nested_kallsyms_has_symbol)"
check_eq first_level_bpf_errno 0 "$(get_field "$out" first_level_bpf_errno)"
check_eq nested_userns_errno 0 "$(get_field "$out" nested_userns_errno)"
check_eq nested_bpf_errno 1 "$(get_field "$out" nested_bpf_errno)"

exit $ret
