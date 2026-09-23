// SPDX-License-Identifier: GPL-2.0-or-later
#define pr_fmt(fmt) "auth_expectation: " fmt

#include <linux/auth_contract.h>
#include <linux/auth_guard.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/overflow.h>

static bool auth_expectation_region_valid(enum auth_expectation_region region)
{
	return (unsigned int)region < AUTH_EXPECTATION_REGION_COUNT;
}

static bool auth_expectation_value_valid(u64 hash, u32 len)
{
	return hash != 0 && len != 0;
}

int auth_expectation_store_record(struct auth_expectation_store *store,
				  enum auth_expectation_region region, u64 hash,
				  u32 len, enum auth_expectation_source source)
{
	if (!auth_expectation_region_valid(region))
		return -EINVAL;
	if (!auth_expectation_value_valid(hash, len))
		return -EINVAL;
	if (store->sealed)
		return -EPERM;
	if (store->entries[region].hash)
		return -EEXIST;

	store->entries[region] = (struct auth_expectation) {
		.hash = hash,
		.len = len,
		.region = region,
		.source = source,
	};

	return 0;
}
EXPORT_SYMBOL_GPL(auth_expectation_store_record);

int auth_expectation_store_lookup(const struct auth_expectation_store *store,
				  enum auth_expectation_region region,
				  struct auth_expectation *out)
{
	if (!auth_expectation_region_valid(region) || !out)
		return -EINVAL;
	if (!store->entries[region].hash)
		return -ENOENT;

	*out = store->entries[region];
	return 0;
}
EXPORT_SYMBOL_GPL(auth_expectation_store_lookup);

bool auth_expectation_store_sealed(const struct auth_expectation_store *store)
{
	return store->sealed;
}
EXPORT_SYMBOL_GPL(auth_expectation_store_sealed);

void auth_expectation_store_seal(struct auth_expectation_store *store)
{
	store->sealed = true;
}
EXPORT_SYMBOL_GPL(auth_expectation_store_seal);

#ifdef CONFIG_AUTH_EXPECTATION

/*
 * The live store.  It lives in .data..ro_after_init: writable while
 * expectations are recorded during boot, read-only for the rest of the
 * system's life.
 */
static struct auth_expectation_store auth_expectation_store __ro_after_init;

int auth_expectation_record(enum auth_expectation_region region, u64 hash,
			    u32 len, enum auth_expectation_source source)
{
	return auth_expectation_store_record(&auth_expectation_store, region,
					     hash, len, source);
}
EXPORT_SYMBOL_GPL(auth_expectation_record);

int auth_expectation_lookup(enum auth_expectation_region region,
			    struct auth_expectation *out)
{
	return auth_expectation_store_lookup(&auth_expectation_store, region,
					     out);
}
EXPORT_SYMBOL_GPL(auth_expectation_lookup);

bool auth_expectation_sealed(void)
{
	return auth_expectation_store_sealed(&auth_expectation_store);
}
EXPORT_SYMBOL_GPL(auth_expectation_sealed);

static int __init auth_expectation_init(void)
{
	unsigned int recorded = 0;
	unsigned int external = 0;
	unsigned int i;

	for (i = 0; i < AUTH_EXPECTATION_REGION_COUNT; i++) {
		if (!auth_expectation_store.entries[i].hash)
			continue;
		recorded++;
		if (auth_expectation_store.entries[i].source ==
		    AUTH_EXPECTATION_SOURCE_EXTERNAL)
			external++;
	}

	auth_expectation_store_seal(&auth_expectation_store);

	/*
	 * Recording happens before this late initcall.  Until a measurement
	 * consumer records a region, lookups fail closed, so an unrecorded
	 * region is a claim limit, never a silent pass.
	 */
	if (recorded)
		pr_info("sealed with %u region(s) recorded (%u externally rooted)\n",
			recorded, external);

	return 0;
}
late_initcall(auth_expectation_init);

#endif /* CONFIG_AUTH_EXPECTATION */

/*
 * Contract table sealing.  A table is authored by the control plane and
 * loaded with a template; the domain key binds the published table to this
 * boot, and the digest covers the head fields plus a keyed digest of the
 * rows.
 */
static struct auth_guard_domain auth_contract_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("auth_contract");

struct auth_contract_head {
	u32 template_id;
	u32 row_count;
	u64 row_hash;
	u64 rows_seal;
};

static int auth_contract_table_check(const struct auth_transition_table *table)
{
	if (!table)
		return -EINVAL;
	if (table->row_count == 0 || table->row_count > AUTH_CONTRACT_MAX_ROWS)
		return -EINVAL;

	return 0;
}

static u64 auth_contract_table_digest(const struct auth_transition_table *table)
{
	struct auth_contract_head head = {
		.template_id = table->template_id,
		.row_count = table->row_count,
		.row_hash = table->row_hash,
	};

	head.rows_seal = auth_guard_seal(&auth_contract_guard, table->rows,
					 array_size(table->row_count,
						    sizeof(table->rows[0])));

	return auth_guard_seal(&auth_contract_guard, &head, sizeof(head));
}

int auth_contract_table_seal(struct auth_transition_table *table)
{
	struct auth_guard_stamp stamp;

	if (auth_contract_table_check(table))
		return -EINVAL;

	table->generation = auth_guard_next_generation(&auth_contract_guard);
	stamp.generation = table->generation;
	stamp.nonce = auth_guard_nonce();
	stamp.seal = auth_contract_table_digest(table);
	auth_guard_stamp_publish_release(&table->stamp, &stamp);

	return 0;
}
EXPORT_SYMBOL_GPL(auth_contract_table_seal);

int auth_contract_table_verify(const struct auth_transition_table *table)
{
	struct auth_guard_stamp stamp;

	if (auth_contract_table_check(table))
		return -EINVAL;

	stamp = auth_guard_stamp_load_acquire(&table->stamp);
	if (!auth_guard_stamp_valid(&stamp))
		return -EKEYREJECTED;
	if (stamp.generation != table->generation)
		return -EKEYREJECTED;
	if (stamp.seal != auth_contract_table_digest(table))
		return -EKEYREJECTED;

	return 0;
}
EXPORT_SYMBOL_GPL(auth_contract_table_verify);

static int __init auth_contract_init(void)
{
	auth_guard_init_domain(&auth_contract_guard);
	return 0;
}
late_initcall(auth_contract_init);
