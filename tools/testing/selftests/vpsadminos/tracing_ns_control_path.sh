#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0
helper="$(dirname "$0")/tracing_ns_smoke"

get_field()
{
	printf '%s\n' "$1" | awk -F= -v key="$2" '$1 == key { print $2; exit }'
}

require_root_and_feature()
{
	if [ "$(id -u)" -ne 0 ]; then
		echo "skip: must run as root" >&2
		exit $ksft_skip
	fi

	if [ ! -e /proc/self/ns/tracing ]; then
		echo "skip: tracing namespace support not present" >&2
		exit $ksft_skip
	fi
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

require_root_and_feature

out="$($helper --syslog-name traceA --tracing --nested-attempt \
	--setns-parent-tracing)" || {
	echo "not ok: helper failed in tracing+syslog case" >&2
	exit 1
}

check_ne tracing_boundary "$(get_field "$out" parent_tracing)" "$(get_field "$out" child_tracing)"
check_ne syslog_boundary "$(get_field "$out" parent_syslog)" "$(get_field "$out" child_syslog)"
check_ne user_boundary "$(get_field "$out" parent_user)" "$(get_field "$out" child_user)"
check_ne pid_boundary "$(get_field "$out" parent_pid)" "$(get_field "$out" child_pid)"
check_eq nested_request_errno 1 "$(get_field "$out" child_nested_tracing_errno)"
check_eq setns_parent_tracing_errno 1 "$(get_field "$out" child_setns_parent_tracing_errno)"

out="$($helper --syslog-name traceB)" || {
	echo "not ok: helper failed in syslog-only case" >&2
	exit 1
}
check_eq tracing_unchanged_without_request "$(get_field "$out" parent_tracing)" "$(get_field "$out" child_tracing)"
check_ne syslog_changes_without_tracing_request "$(get_field "$out" parent_syslog)" "$(get_field "$out" child_syslog)"

out="$($helper --tracing)" || {
	echo "not ok: helper failed in tracing-only case" >&2
	exit 1
}
check_eq tracing_only_clone_errno 22 "$(get_field "$out" clone_errno)"

out="$($helper --syslog-name traceC --tracing --nested-syslog-name traceC.child)" || {
	echo "not ok: helper failed in nested-syslog case" >&2
	exit 1
}
check_ne nested_syslog_user_boundary "$(get_field "$out" child_user)" "$(get_field "$out" grandchild_user)"
check_ne nested_syslog_pid_boundary "$(get_field "$out" child_pid)" "$(get_field "$out" grandchild_pid)"
check_ne nested_syslog_boundary "$(get_field "$out" child_syslog)" "$(get_field "$out" grandchild_syslog)"
check_eq nested_syslog_keeps_tracing "$(get_field "$out" child_tracing)" "$(get_field "$out" grandchild_tracing)"

out="$($helper --syslog-name traceD --tracing --parent-setns-child-user)" || {
	echo "not ok: helper failed in parent-userns-setns case" >&2
	exit 1
}
check_eq parent_setns_child_user_errno 1 "$(get_field "$out" parent_setns_child_user_errno)"

out="$($helper --syslog-name traceE --tracing --parent-setns-child-pid)" || {
	echo "not ok: helper failed in parent-pidns-setns case" >&2
	exit 1
}
check_eq parent_setns_child_pid_errno 1 "$(get_field "$out" parent_setns_child_pid_errno)"

out="$($helper --syslog-name traceF --tracing --parent-setns-child-syslog)" || {
	echo "not ok: helper failed in parent-syslogns-setns case" >&2
	exit 1
}
check_eq parent_setns_child_syslog_errno 1 "$(get_field "$out" parent_setns_child_syslog_errno)"

exit $ret
