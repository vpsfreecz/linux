/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_AUTH_CONTRACT_H
#define _LINUX_AUTH_CONTRACT_H

#include <linux/errno.h>
#include <linux/types.h>

/*
 * Regions whose measured value the authority-transition contract depends on.
 * The store records at most one expected value per region; a consumer
 * compares a fresh measurement against the recorded value and fails closed
 * when the region was never recorded.
 */
enum auth_expectation_region {
	AUTH_EXPECTATION_REGION_GUARD_TEXT = 0,
	AUTH_EXPECTATION_REGION_GUARD_RODATA,
	AUTH_EXPECTATION_REGION_CONTRACT_TABLE,
	AUTH_EXPECTATION_REGION_POLICY,
	AUTH_EXPECTATION_REGION_COUNT,
};

/*
 * Where a recorded expectation came from.  LEXICAL means it was measured from
 * the running image at first boot (no external root configured, so the
 * "externally measured" claim does not hold); EXTERNAL means it was rooted
 * outside the node (TPM/PCR-sealed policy or a control-plane-signed
 * manifest).
 */
enum auth_expectation_source {
	AUTH_EXPECTATION_SOURCE_NONE = 0,
	AUTH_EXPECTATION_SOURCE_LEXICAL,
	AUTH_EXPECTATION_SOURCE_EXTERNAL,
};

struct auth_expectation {
	u64 hash;
	u32 len;
	u16 region;
	u16 source;
};

/*
 * A store instance.  The live store is a global in .data..ro_after_init; the
 * instance form exists so tests can exercise the semantics without touching
 * the live store.
 */
struct auth_expectation_store {
	struct auth_expectation entries[AUTH_EXPECTATION_REGION_COUNT];
	bool sealed;
};

#ifndef CONFIG_AUTH_EXPECTATION

static inline int auth_expectation_record(enum auth_expectation_region region,
					  u64 hash, u32 len,
					  enum auth_expectation_source source)
{
	return -EOPNOTSUPP;
}

static inline int auth_expectation_lookup(enum auth_expectation_region region,
					  struct auth_expectation *out)
{
	return -ENOENT;
}

static inline bool auth_expectation_sealed(void)
{
	return true;
}

#else

int auth_expectation_record(enum auth_expectation_region region, u64 hash,
			    u32 len, enum auth_expectation_source source);
int auth_expectation_lookup(enum auth_expectation_region region,
			    struct auth_expectation *out);
bool auth_expectation_sealed(void);

#endif /* CONFIG_AUTH_EXPECTATION */

int auth_expectation_store_record(struct auth_expectation_store *store,
				  enum auth_expectation_region region, u64 hash,
				  u32 len, enum auth_expectation_source source);
int auth_expectation_store_lookup(const struct auth_expectation_store *store,
				  enum auth_expectation_region region,
				  struct auth_expectation *out);
bool auth_expectation_store_sealed(const struct auth_expectation_store *store);
void auth_expectation_store_seal(struct auth_expectation_store *store);

#endif /* _LINUX_AUTH_CONTRACT_H */
