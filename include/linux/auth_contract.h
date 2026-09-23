/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_AUTH_CONTRACT_H
#define _LINUX_AUTH_CONTRACT_H

#include <linux/auth_guard_types.h>
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

/*
 * The contract table describes the transitions a template may take.  Rows are
 * authored by the control plane and loaded with the template; the stamp seals
 * the table the kernel actually uses, and the expectations recorded at boot
 * bind that table to the image.
 */
enum auth_contract_leaf {
	AUTH_CONTRACT_LEAF_UNKNOWN = 0,
	AUTH_CONTRACT_LEAF_ALLOWED,
	AUTH_CONTRACT_LEAF_FORBIDDEN,
};

struct auth_transition_row {
	u8 kind;
	u8 subject_class;
	u8 root_class;
	u8 trigger;
	u8 caller;
	u8 leaf;
};

struct auth_transition_table {
	u32 template_id;
	u64 generation;
	u32 row_count;
	u64 row_hash;
	struct auth_guard_stamp stamp;
	struct auth_transition_row rows[];
};

#define AUTH_CONTRACT_MAX_ROWS 4096

int auth_contract_table_seal(struct auth_transition_table *table);
int auth_contract_table_verify(const struct auth_transition_table *table);

#endif /* _LINUX_AUTH_CONTRACT_H */
