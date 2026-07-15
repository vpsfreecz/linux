/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AUTH_GUARD_TYPES_H
#define _LINUX_AUTH_GUARD_TYPES_H

#include <linux/types.h>

struct lsm_ctx;

struct auth_guard_task_syslog_request {
	bool enabled;
	char *name;
	size_t name_len;
};

struct auth_guard_task_lsm_request {
	bool enabled;
	u64 lsmid;
	struct lsm_ctx *ctx;
	size_t ctx_len;
};

struct auth_guard_stamp {
	u64 generation;
	u64 nonce;
	u64 seal;
};

/*
 * A guarded write has three materially different ownership outcomes.  A
 * rejected write did not publish the proposed endpoint, an applied write
 * published it exactly, and a quarantined write may have published all or
 * part of it before an integrity failure.  Callers must retain every endpoint
 * reference on the quarantined path.
 */
enum auth_guard_mutation_result {
	AUTH_GUARD_MUTATION_REJECTED,
	AUTH_GUARD_MUTATION_APPLIED,
	AUTH_GUARD_MUTATION_QUARANTINED,
};

enum auth_guard_transition_anchor {
	AUTH_GUARD_TRANSITION_ANCHOR_NONE,
	AUTH_GUARD_TRANSITION_ANCHOR_CRED,
	AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY,
	AUTH_GUARD_TRANSITION_ANCHOR_COUNT,
};

struct auth_guard_transition_state {
	u32 depth;
	enum auth_guard_transition_anchor anchor;
	u64 nonce;
	u64 restore_state;
	u64 expected_state;
	u64 seal;
};

struct auth_guard_unanchored_transition_state {
	u32 depth;
	u64 nonce;
	u64 seal;
};

struct auth_guard_expectation_transition_state {
	struct auth_guard_unanchored_transition_state base;
	u64 restore_state;
	u64 expected_state;
};

#endif /* _LINUX_AUTH_GUARD_TYPES_H */
