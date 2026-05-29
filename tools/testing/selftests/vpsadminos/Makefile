# SPDX-License-Identifier: GPL-2.0
TEST_GEN_PROGS := tracing_ns_smoke tracing_bpf_userns_smoke lsm_ns_smoke \
	bpf_map_in_map_domain_smoke mnt_ns_bind_smoke
TEST_PROGS := tracing_ns_control_path.sh tracing_bpf_userns_control.sh \
	 kernfs_filter_reload_visibility.sh bpf_map_in_map_domain.sh
CFLAGS += -Wall -Werror
include ../lib.mk
