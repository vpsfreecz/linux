/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AUTH_GUARD_TYPES_H
#define _LINUX_AUTH_GUARD_TYPES_H

#include <linux/types.h>

struct auth_guard_task_syslog_request {
	bool enabled;
	char *name;
	size_t name_len;
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
	AUTH_GUARD_MUTATION_BUSY,
	AUTH_GUARD_MUTATION_APPLIED,
	AUTH_GUARD_MUTATION_QUARANTINED,
};

/*
 * Retain-biased precedence for combining two receipt classes: QUARANTINED
 * outranks BUSY outranks REJECTED outranks APPLIED.  A caller that has to
 * decide whether a rejected mutation's object may be released must retain when
 * *any* receipt is uncertain (quarantined or in flight) and release only when
 * every receipt is REJECTED -- that is the release policy for rejected
 * receipts the R108 residual asked for.
 */
static inline enum auth_guard_mutation_result
auth_guard_mutation_worst(enum auth_guard_mutation_result a,
			  enum auth_guard_mutation_result b)
{
	switch (a) {
	case AUTH_GUARD_MUTATION_QUARANTINED:
		return a;
	case AUTH_GUARD_MUTATION_BUSY:
		return b == AUTH_GUARD_MUTATION_QUARANTINED ? b : a;
	case AUTH_GUARD_MUTATION_REJECTED:
		return (b == AUTH_GUARD_MUTATION_QUARANTINED ||
			b == AUTH_GUARD_MUTATION_BUSY) ? b : a;
	case AUTH_GUARD_MUTATION_APPLIED:
	default:
		return b;
	}
}

enum auth_guard_transition_anchor {
	AUTH_GUARD_TRANSITION_ANCHOR_NONE,
	AUTH_GUARD_TRANSITION_ANCHOR_CRED,
	AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY,
	AUTH_GUARD_TRANSITION_ANCHOR_COUNT,
};

enum auth_guard_transition_flags {
	AUTH_GUARD_TRANSITION_ALLOW_SUBJECTIVE_CRED = 1U << 0,
};

struct auth_guard_transition_state {
	u32 depth;
	enum auth_guard_transition_anchor anchor;
	u32 flags;
	u64 opener;
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
