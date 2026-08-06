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

check_nonzero()
{
	label="$1"
	value="$2"
	if [ -z "$value" ] || [ "$value" = "0" ]; then
		echo "not ok: $label expected nonzero, got: ${value:-missing}" >&2
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

if [ ! -e /sys/fs/cgroup/cgroup.controllers ]; then
	echo "skip: cgroup v2 is not mounted at /sys/fs/cgroup" >&2
	exit $ksft_skip
fi

symbol="copy_process"
out="$($helper --syslog-name "traceH$$" --symbol "$symbol")"
helper_status=$?
if [ "$helper_status" -ne 0 ]; then
	printf '%s\n' "$out" >&2
	echo "not ok: helper failed" >&2
	exit "$helper_status"
fi

if [ "$(get_field "$out" parent_kallsyms_has_symbol)" != "1" ]; then
	echo "skip: host kallsyms does not expose $symbol on this kernel" >&2
	exit $ksft_skip
fi

check_ne first_level_user_boundary \
	"$(get_field "$out" parent_user)" \
	"$(get_field "$out" child_user)"
check_ne first_level_tracing_boundary \
	"$(get_field "$out" parent_tracing)" \
	"$(get_field "$out" child_tracing)"
check_ne nested_user_boundary \
	"$(get_field "$out" child_user)" \
	"$(get_field "$out" nested_user)"
check_eq nested_keeps_tracing \
	"$(get_field "$out" child_tracing)" \
	"$(get_field "$out" nested_tracing)"
check_ne child_cgroup_boundary \
	"$(get_field "$out" parent_cgroup)" \
	"$(get_field "$out" child_cgroup)"
check_eq nested_keeps_cgroup \
	"$(get_field "$out" child_cgroup)" \
	"$(get_field "$out" nested_cgroup)"
check_eq child_kallsyms_has_symbol 0 "$(get_field "$out" child_kallsyms_has_symbol)"
check_eq nested_kallsyms_has_symbol 0 "$(get_field "$out" nested_kallsyms_has_symbol)"
check_eq host_cgroup_fixture_errno 0 \
	"$(get_field "$out" host_cgroup_fixture_errno)"
check_eq move_child_cgroup_errno 0 \
	"$(get_field "$out" move_child_cgroup_errno)"
check_eq child_cgroupns_errno 0 \
	"$(get_field "$out" child_cgroupns_errno)"
check_eq first_level_cap_drop_errno 0 \
	"$(get_field "$out" first_level_cap_drop_errno)"
check_eq first_level_bpf_errno 0 "$(get_field "$out" first_level_bpf_errno)"
check_eq nested_userns_errno 0 "$(get_field "$out" nested_userns_errno)"
check_eq nested_bpf_errno 1 "$(get_field "$out" nested_bpf_errno)"
check_eq host_sysctl_initialized_errno 0 \
	"$(get_field "$out" host_sysctl_initialized_errno)"
check_eq host_sysctl_uninitialized_errno 0 \
	"$(get_field "$out" host_sysctl_uninitialized_errno)"
check_eq container_sysctl_uninitialized_errno 0 \
	"$(get_field "$out" container_sysctl_uninitialized_errno)"
check_nonzero container_sysctl_set_new_value_errno \
	"$(get_field "$out" container_sysctl_set_new_value_errno)"
check_nonzero container_direct_table_helper_errno \
	"$(get_field "$out" container_direct_table_helper_errno)"
check_eq container_allowed_helper_errno 0 \
	"$(get_field "$out" container_allowed_helper_errno)"
check_eq container_var_stack_reads_errno 0 \
	"$(get_field "$out" container_var_stack_reads_errno)"
check_eq container_var_stack_unpriv_xlated_hidden_errno 0 \
	"$(get_field "$out" container_var_stack_unpriv_xlated_hidden_errno)"
check_eq container_var_stack_xlated_send_errno 0 \
	"$(get_field "$out" container_var_stack_xlated_send_errno)"
check_eq container_var_stack_xlated_errno 0 \
	"$(get_field "$out" container_var_stack_xlated_errno)"
check_eq container_var_stack_nospec 1 \
	"$(get_field "$out" container_var_stack_nospec)"
check_eq container_var_stack_zero_init_count 8 \
	"$(get_field "$out" container_var_stack_zero_init_count)"
check_eq container_loop_callback_errno 0 \
	"$(get_field "$out" container_loop_callback_errno)"
check_eq container_loop_callback_unpriv_xlated_hidden_errno 0 \
	"$(get_field "$out" container_loop_callback_unpriv_xlated_hidden_errno)"
check_eq container_loop_callback_xlated_send_errno 0 \
	"$(get_field "$out" container_loop_callback_xlated_send_errno)"
check_eq container_loop_callback_xlated_errno 0 \
	"$(get_field "$out" container_loop_callback_xlated_errno)"
check_eq container_loop_callback_zero_init_count 4 \
	"$(get_field "$out" container_loop_callback_zero_init_count)"
check_eq container_var_stack_zero_write_errno 0 \
	"$(get_field "$out" container_var_stack_zero_write_errno)"
check_nonzero container_var_stack_nonzero_write_errno \
	"$(get_field "$out" container_var_stack_nonzero_write_errno)"
check_nonzero container_var_stack_out_of_bounds_errno \
	"$(get_field "$out" container_var_stack_out_of_bounds_errno)"
check_eq host_array_map_errno 0 "$(get_field "$out" host_array_map_errno)"
check_eq host_array_key_constant_errno 0 \
	"$(get_field "$out" host_array_key_constant_errno)"
check_nonzero host_array_key_bounded_errno \
	"$(get_field "$out" host_array_key_bounded_errno)"
check_nonzero host_array_key_partial_oob_errno \
	"$(get_field "$out" host_array_key_partial_oob_errno)"
check_eq container_array_map_errno 0 \
	"$(get_field "$out" container_array_map_errno)"
check_eq container_array_key_constant_errno 0 \
	"$(get_field "$out" container_array_key_constant_errno)"
check_eq container_array_key_bounded_errno 0 \
	"$(get_field "$out" container_array_key_bounded_errno)"
check_nonzero container_array_key_partial_oob_errno \
	"$(get_field "$out" container_array_key_partial_oob_errno)"

for width in 1 2 4 8; do
	check_eq "container_var_stack_pos_safe_${width}_errno" 0 \
		"$(get_field "$out" "container_var_stack_pos_safe_${width}_errno")"
	check_nonzero "container_var_stack_pos_unsafe_${width}_errno" \
		"$(get_field "$out" "container_var_stack_pos_unsafe_${width}_errno")"
	check_eq "container_var_stack_neg_safe_${width}_errno" 0 \
		"$(get_field "$out" "container_var_stack_neg_safe_${width}_errno")"
	check_nonzero "container_var_stack_neg_unsafe_${width}_errno" \
		"$(get_field "$out" "container_var_stack_neg_unsafe_${width}_errno")"
	check_eq "container_var_stack_delta_safe_${width}_errno" 0 \
		"$(get_field "$out" "container_var_stack_delta_safe_${width}_errno")"
	check_nonzero "container_var_stack_delta_unsafe_${width}_errno" \
		"$(get_field "$out" "container_var_stack_delta_unsafe_${width}_errno")"
done

check_eq container_var_stack_max_xlated_errno 0 \
	"$(get_field "$out" container_var_stack_max_xlated_errno)"
check_eq container_var_stack_max_unpriv_xlated_hidden_errno 0 \
	"$(get_field "$out" container_var_stack_max_unpriv_xlated_hidden_errno)"
check_eq container_var_stack_max_xlated_send_errno 0 \
	"$(get_field "$out" container_var_stack_max_xlated_send_errno)"
check_eq container_var_stack_max_nospec 1 \
	"$(get_field "$out" container_var_stack_max_nospec)"
check_eq container_var_stack_max_zero_init_count 64 \
	"$(get_field "$out" container_var_stack_max_zero_init_count)"

check_eq container_cgroup_query_disallowed_errno 1 \
	"$(get_field "$out" container_cgroup_query_disallowed_errno)"
check_eq container_cgroup_query_peer_errno 13 \
	"$(get_field "$out" container_cgroup_query_peer_errno)"
check_eq container_cgroup_query_host_errno 13 \
	"$(get_field "$out" container_cgroup_query_host_errno)"
check_eq container_cgroup_prog1_load_errno 0 \
	"$(get_field "$out" container_cgroup_prog1_load_errno)"
check_eq container_cgroup_prog1_id_errno 0 \
	"$(get_field "$out" container_cgroup_prog1_id_errno)"
check_nonzero container_cgroup_prog1_id \
	"$(get_field "$out" container_cgroup_prog1_id)"
check_eq container_cgroup_prog1_attach_errno 0 \
	"$(get_field "$out" container_cgroup_prog1_attach_errno)"
check_eq container_cgroup_prog2_load_errno 0 \
	"$(get_field "$out" container_cgroup_prog2_load_errno)"
check_eq container_cgroup_prog2_id_errno 0 \
	"$(get_field "$out" container_cgroup_prog2_id_errno)"
check_nonzero container_cgroup_prog2_id \
	"$(get_field "$out" container_cgroup_prog2_id)"
check_ne container_cgroup_program_ids \
	"$(get_field "$out" container_cgroup_prog1_id)" \
	"$(get_field "$out" container_cgroup_prog2_id)"
check_eq container_cgroup_prog2_attach_errno 0 \
	"$(get_field "$out" container_cgroup_prog2_attach_errno)"

for query in direct effective; do
	check_eq "container_cgroup_query_${query}_errno" 0 \
		"$(get_field "$out" "container_cgroup_query_${query}_errno")"
	check_eq "container_cgroup_query_${query}_count" 2 \
		"$(get_field "$out" "container_cgroup_query_${query}_count")"
	check_eq "container_cgroup_query_${query}_id0" \
		"$(get_field "$out" container_cgroup_prog1_id)" \
		"$(get_field "$out" "container_cgroup_query_${query}_id0")"
	check_eq "container_cgroup_query_${query}_id1" \
		"$(get_field "$out" container_cgroup_prog2_id)" \
		"$(get_field "$out" "container_cgroup_query_${query}_id1")"
	check_eq "container_cgroup_query_${query}_short_errno" 28 \
		"$(get_field "$out" "container_cgroup_query_${query}_short_errno")"
	check_eq "container_cgroup_query_${query}_short_count" 2 \
		"$(get_field "$out" "container_cgroup_query_${query}_short_count")"
	check_eq "container_cgroup_query_${query}_short_id0" \
		"$(get_field "$out" container_cgroup_prog1_id)" \
		"$(get_field "$out" "container_cgroup_query_${query}_short_id0")"
done

check_eq container_cgroup_ingress_load_errno 0 \
	"$(get_field "$out" container_cgroup_ingress_load_errno)"
check_eq container_cgroup_ingress_attach_errno 0 \
	"$(get_field "$out" container_cgroup_ingress_attach_errno)"
check_eq container_cgroup_detach_fdless_errno 0 \
	"$(get_field "$out" container_cgroup_detach_fdless_errno)"
check_eq container_cgroup_ingress_reattach_errno 0 \
	"$(get_field "$out" container_cgroup_ingress_reattach_errno)"
check_eq container_cgroup_detach_invalid_fd_errno 0 \
	"$(get_field "$out" container_cgroup_detach_invalid_fd_errno)"
check_eq container_cgroup_detach_disallowed_errno 1 \
	"$(get_field "$out" container_cgroup_detach_disallowed_errno)"
check_eq container_cgroup_detach_foreign_fd_errno 13 \
	"$(get_field "$out" container_cgroup_detach_foreign_fd_errno)"
check_eq container_cgroup_detach_peer_fdless_errno 13 \
	"$(get_field "$out" container_cgroup_detach_peer_fdless_errno)"
check_eq container_cgroup_detach_host_fdless_errno 13 \
	"$(get_field "$out" container_cgroup_detach_host_fdless_errno)"
check_eq container_cgroup_cleanup_errno 0 \
	"$(get_field "$out" container_cgroup_cleanup_errno)"
check_eq nested_cgroup_query_errno 1 \
	"$(get_field "$out" nested_cgroup_query_errno)"
check_eq nested_cgroup_detach_errno 1 \
	"$(get_field "$out" nested_cgroup_detach_errno)"
check_eq host_cgroup_cleanup_errno 0 \
	"$(get_field "$out" host_cgroup_cleanup_errno)"
check_eq host_xlated_receive_errno 0 \
	"$(get_field "$out" host_xlated_receive_errno)"

exit $ret
