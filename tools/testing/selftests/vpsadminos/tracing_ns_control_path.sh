#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0
helper="$(dirname "$0")/tracing_ns_smoke"
raw_log="$(mktemp -t tracing-ns-control.XXXXXX)"

cleanup()
{
	rm -f "$raw_log"
}

trap cleanup EXIT

dump_file()
{
	label="$1"
	path="$2"

	if [ -r "$path" ]; then
		printf '%s=' "$label" >&2
		cat "$path" >&2
	fi
}

dump_failure_context()
{
	echo "--- tracing_ns_control_path diagnostics ---" >&2
	dump_file security_lsm /sys/kernel/security/lsm
	dump_file apparmor_enabled /sys/module/apparmor/parameters/enabled
	dump_file apparmor_root_ns_policy /sys/module/apparmor/parameters/root_ns_policy
	dump_file unprivileged_userns_clone /proc/sys/kernel/unprivileged_userns_clone
	dump_file user_max_user_namespaces /proc/sys/user/max_user_namespaces
	grep '^CapEff:' /proc/self/status >&2 || true
	cat "$raw_log" >&2
	echo "--- end diagnostics ---" >&2
}

run_case()
{
	label="$1"
	shift

	out="$("$helper" "$@")"
	rc=$?
	{
		echo "--- $label rc=$rc args: $*"
		printf '%s\n' "$out"
	} >> "$raw_log"
	printf '%s\n' "$out"
	return "$rc"
}

get_field()
{
	printf '%s\n' "$1" | awk -F= -v key="$2" '$1 == key { print $2; exit }'
}

ns_name()
{
	printf 't%02d%s%s' "$(($$ % 100))" "$(date +%S)" "$1"
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

check_one_of()
{
	label="$1"
	actual="$2"
	shift 2

	for expected in "$@"; do
		if [ "$actual" = "$expected" ]; then
			return
		fi
	done

	echo "not ok: $label got $actual, expected one of: $*" >&2
	ret=1
}

require_root_and_feature

out="$(run_case tracing_syslog_nested --syslog-name "$(ns_name a)" \
	--tracing --nested-attempt --setns-parent-tracing)" || {
	echo "not ok: helper failed in tracing+syslog case" >&2
	dump_failure_context
	exit 1
}

check_ne tracing_boundary "$(get_field "$out" parent_tracing)" "$(get_field "$out" child_tracing)"
check_ne syslog_boundary "$(get_field "$out" parent_syslog)" "$(get_field "$out" child_syslog)"
check_ne user_boundary "$(get_field "$out" parent_user)" "$(get_field "$out" child_user)"
check_ne pid_boundary "$(get_field "$out" parent_pid)" "$(get_field "$out" child_pid)"
check_eq nested_request_errno 1 "$(get_field "$out" child_nested_tracing_errno)"
check_one_of setns_parent_tracing_errno \
	"$(get_field "$out" child_setns_parent_tracing_errno)" 1 13

out="$(run_case syslog_only --syslog-name "$(ns_name b)")" || {
	echo "not ok: helper failed in syslog-only case" >&2
	dump_failure_context
	exit 1
}
check_eq tracing_unchanged_without_request "$(get_field "$out" parent_tracing)" "$(get_field "$out" child_tracing)"
check_ne syslog_changes_without_tracing_request "$(get_field "$out" parent_syslog)" "$(get_field "$out" child_syslog)"

out="$(run_case tracing_only --tracing)" || {
	echo "not ok: helper failed in tracing-only case" >&2
	dump_failure_context
	exit 1
}
check_eq tracing_only_clone_errno 22 "$(get_field "$out" clone_errno)"

out="$(run_case nested_syslog --syslog-name "$(ns_name c)" --tracing \
	--nested-syslog-name "$(ns_name x)")" || {
	echo "not ok: helper failed in nested-syslog case" >&2
	dump_failure_context
	exit 1
}
check_ne nested_syslog_user_boundary "$(get_field "$out" child_user)" "$(get_field "$out" grandchild_user)"
check_ne nested_syslog_pid_boundary "$(get_field "$out" child_pid)" "$(get_field "$out" grandchild_pid)"
check_ne nested_syslog_boundary "$(get_field "$out" child_syslog)" "$(get_field "$out" grandchild_syslog)"
check_eq nested_syslog_keeps_tracing "$(get_field "$out" child_tracing)" "$(get_field "$out" grandchild_tracing)"

out="$(run_case parent_userns_setns --syslog-name "$(ns_name d)" \
	--tracing --parent-setns-child-user)" || {
	echo "not ok: helper failed in parent-userns-setns case" >&2
	dump_failure_context
	exit 1
}
check_eq parent_setns_child_user_errno 1 "$(get_field "$out" parent_setns_child_user_errno)"

out="$(run_case parent_pidns_setns --syslog-name "$(ns_name e)" \
	--tracing --parent-setns-child-pid)" || {
	echo "not ok: helper failed in parent-pidns-setns case" >&2
	dump_failure_context
	exit 1
}
check_eq parent_setns_child_pid_errno 1 "$(get_field "$out" parent_setns_child_pid_errno)"

out="$(run_case parent_syslogns_setns --syslog-name "$(ns_name f)" \
	--tracing --parent-setns-child-syslog)" || {
	echo "not ok: helper failed in parent-syslogns-setns case" >&2
	dump_failure_context
	exit 1
}
check_eq parent_setns_child_syslog_errno 1 "$(get_field "$out" parent_setns_child_syslog_errno)"

out="$(run_case parent_pidfd_setns --syslog-name "$(ns_name p)" \
	--tracing --parent-pidfd-setns-child)" || {
	echo "not ok: helper failed in parent-pidfd-setns case" >&2
	dump_failure_context
	exit 1
}
check_eq parent_pidfd_setns_child_errno 0 "$(get_field "$out" parent_pidfd_setns_child_errno)"

out="$(run_case parent_pidfd_setns_without_source_cap \
	--syslog-name "$(ns_name q)" --tracing \
	--parent-pidfd-setns-child-without-source-cap)" || {
	echo "not ok: helper failed in parent-pidfd-setns-without-source-cap case" >&2
	dump_failure_context
	exit 1
}
check_eq parent_pidfd_setns_child_without_source_cap_errno 0 \
	"$(get_field "$out" parent_pidfd_setns_child_without_source_cap_errno)"

out="$(run_case retry_after_failed_first_clone \
	--syslog-name "$(ns_name g)" --tracing \
	--retry-after-failed-first-clone)" || {
	echo "not ok: helper failed in pending-request-retry case" >&2
	dump_failure_context
	exit 1
}
check_eq first_clone_errno 22 "$(get_field "$out" first_clone_errno)"
check_ne retry_preserves_syslog_request \
	"$(get_field "$out" parent_syslog)" \
	"$(get_field "$out" child_syslog)"
check_ne retry_preserves_tracing_request \
	"$(get_field "$out" parent_tracing)" \
	"$(get_field "$out" child_tracing)"

if [ "$ret" -ne 0 ]; then
	dump_failure_context
fi

exit $ret
