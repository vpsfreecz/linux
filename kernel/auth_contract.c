// SPDX-License-Identifier: GPL-2.0-or-later
#define pr_fmt(fmt) "auth_expectation: " fmt

#include <linux/auth_contract.h>
#include <linux/auth_guard.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

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
	/*
	 * Provenance is part of the record, not decoration: the claim may only
	 * rest on an externally rooted expectation, and a record with no source
	 * (or an unknown one) would let that distinction be lost silently.
	 */
	if (source != AUTH_EXPECTATION_SOURCE_LEXICAL &&
	    source != AUTH_EXPECTATION_SOURCE_EXTERNAL)
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

/*
 * Load-time invariants.  A row must stay inside the inventoried sets and may
 * not give a tenant subject a host-authority root.  The narrowing rule (a
 * table may narrow the global response policy, never widen it) needs the
 * global-policy artefact that the policy region will carry; until that exists
 * the load path enforces the inventory and class rules and rejects anything
 * undeclared.  Publication to the judge lands with the judge itself.
 */
int auth_contract_row_check(const struct auth_transition_row *row)
{
	if (!row)
		return -EINVAL;

	if (row->kind == AUTH_CONTRACT_KIND_UNKNOWN ||
	    row->kind >= AUTH_CONTRACT_KIND_COUNT)
		return -EINVAL;
	if (row->trigger == AUTH_CONTRACT_TRIGGER_UNKNOWN ||
	    row->trigger >= AUTH_CONTRACT_TRIGGER_COUNT)
		return -EINVAL;
	if (row->subject_class == AUTH_CONTRACT_SUBJECT_UNKNOWN ||
	    row->subject_class >= AUTH_CONTRACT_SUBJECT_CLASS_COUNT)
		return -EINVAL;
	if (row->root_class == AUTH_CONTRACT_ROOT_UNKNOWN ||
	    row->root_class >= AUTH_CONTRACT_ROOT_CLASS_COUNT)
		return -EINVAL;
	if (row->leaf != AUTH_CONTRACT_LEAF_ALLOWED &&
	    row->leaf != AUTH_CONTRACT_LEAF_FORBIDDEN)
		return -EINVAL;

	/* Tenant subjects may not reference host-authority roots. */
	if (auth_contract_is_tenant_class(row->subject_class) &&
	    auth_contract_is_host_root_class(row->root_class))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(auth_contract_row_check);

int auth_contract_load(const struct auth_transition_table *table)
{
	unsigned int i;
	int ret;

	ret = auth_contract_table_verify(table);
	if (ret)
		return ret;

	for (i = 0; i < table->row_count; i++) {
		ret = auth_contract_row_check(&table->rows[i]);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(auth_contract_load);

/*
 * Publication and judging.  One table is published per template per boot in
 * this cut; replacement lands with the manager-signed table work.  The judge
 * is a lock-free scan over the class fields, and the counters are published
 * together with the table.
 */
static struct auth_transition_table __rcu *auth_contract_active;
static atomic_long_t *auth_contract_counters;

int auth_contract_table_publish(struct auth_transition_table *table)
{
	atomic_long_t *counters;
	int ret;

	if (!table)
		return -EINVAL;
	if (rcu_access_pointer(auth_contract_active))
		return -EBUSY;

	ret = auth_contract_load(table);
	if (ret)
		return ret;

	counters = kcalloc(table->row_count, sizeof(*counters), GFP_KERNEL);
	if (!counters)
		return -ENOMEM;

	/* Counters first: a reader that sees the table must see them. */
	smp_store_release(&auth_contract_counters, counters);
	rcu_assign_pointer(auth_contract_active, table);

	return 0;
}
EXPORT_SYMBOL_GPL(auth_contract_table_publish);

const struct auth_transition_table *auth_contract_table_get(void)
{
	return rcu_dereference(auth_contract_active);
}
EXPORT_SYMBOL_GPL(auth_contract_table_get);

unsigned long auth_contract_row_count(unsigned int index)
{
	struct auth_transition_table *table = rcu_dereference(auth_contract_active);
	/* Pairs with the counter publication in the table publish path. */
	atomic_long_t *counters = smp_load_acquire(&auth_contract_counters);

	if (!table || !counters || index >= table->row_count)
		return 0;

	return atomic_long_read(&counters[index]);
}
EXPORT_SYMBOL_GPL(auth_contract_row_count);

enum auth_contract_verdict
auth_contract_judge(const struct auth_transition_tuple *tuple)
{
	struct auth_transition_table *table;
	atomic_long_t *counters;
	unsigned int i;

	if (!tuple)
		return AUTH_VERDICT_UNKNOWN;

	table = rcu_dereference(auth_contract_active);
	if (!table)
		return AUTH_VERDICT_UNKNOWN;
	if (table->template_id != tuple->subject.template_id)
		return AUTH_VERDICT_UNKNOWN;

	/* Pairs with the counter publication in the table publish path. */
	counters = smp_load_acquire(&auth_contract_counters);
	if (!counters)
		return AUTH_VERDICT_UNKNOWN;

	for (i = 0; i < table->row_count; i++) {
		const struct auth_transition_row *row = &table->rows[i];

		if (row->kind != tuple->kind || row->trigger != tuple->trigger ||
		    row->caller != tuple->caller ||
		    row->subject_class != tuple->subject.klass)
			continue;
		if (!(tuple->roots & BIT(row->root_class)))
			continue;

		if (row->leaf == AUTH_CONTRACT_LEAF_FORBIDDEN)
			return AUTH_VERDICT_FORBIDDEN;

		atomic_long_inc(&counters[i]);
		return AUTH_VERDICT_DECLARED;
	}

	return AUTH_VERDICT_UNKNOWN;
}
EXPORT_SYMBOL_GPL(auth_contract_judge);

#define AUTH_CONTRACT_PATTERN_SLOTS 64

static DEFINE_SPINLOCK(auth_contract_pattern_lock);
static u64 auth_contract_patterns[AUTH_CONTRACT_PATTERN_SLOTS];
static unsigned int auth_contract_pattern_count;

enum auth_contract_verdict
auth_contract_note(const struct auth_transition_tuple *tuple, const char *where)
{
	enum auth_contract_verdict verdict;
	unsigned long flags;
	unsigned int i;
	bool first = false;
	u64 pattern;

	if (!tuple)
		return AUTH_VERDICT_UNKNOWN;

	verdict = auth_contract_judge(tuple);
	if (verdict == AUTH_VERDICT_DECLARED)
		return verdict;
	/* Without a table there is nothing to note against yet. */
	if (!auth_contract_table_get())
		return verdict;

	pattern = (u64)tuple->kind << 56 | (u64)tuple->trigger << 48 |
		(u64)tuple->caller << 40 | (u64)tuple->subject.klass << 32 |
		tuple->roots;
	if (!pattern)
		pattern = 1;

	spin_lock_irqsave(&auth_contract_pattern_lock, flags);
	for (i = 0; i < auth_contract_pattern_count; i++) {
		if (auth_contract_patterns[i] == pattern)
			break;
	}
	if (i == auth_contract_pattern_count) {
		if (auth_contract_pattern_count < AUTH_CONTRACT_PATTERN_SLOTS)
			auth_contract_patterns[auth_contract_pattern_count++] =
				pattern;
		first = true;
	}
	spin_unlock_irqrestore(&auth_contract_pattern_lock, flags);

	if (first)
		pr_warn("auth_contract: %s: %s transition kind=%u trigger=%u caller=%u subject=%u roots=%#x template=%llu\n",
			where,
			verdict == AUTH_VERDICT_FORBIDDEN ? "forbidden" :
							   "undeclared",
			tuple->kind, tuple->trigger, tuple->caller,
			tuple->subject.klass, tuple->roots,
			tuple->subject.template_id);

	return verdict;
}
EXPORT_SYMBOL_GPL(auth_contract_note);
