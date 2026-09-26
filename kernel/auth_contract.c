// SPDX-License-Identifier: GPL-2.0-or-later
#define pr_fmt(fmt) "auth_expectation: " fmt

#include <linux/auth_contract.h>
#include <linux/auth_guard.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/xxhash.h>
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

static int auth_expectation_store_put(struct auth_expectation_store *store,
				      enum auth_expectation_region region,
				      u64 hash, u32 len,
				      enum auth_expectation_source source,
				      u64 transcript)
{
	struct auth_expectation *existing;

	if (!store || !auth_expectation_region_valid(region))
		return -EINVAL;
	if (!auth_expectation_value_valid(hash, len))
		return -EINVAL;
	if (source != AUTH_EXPECTATION_SOURCE_LEXICAL &&
	    source != AUTH_EXPECTATION_SOURCE_EXTERNAL)
		return -EINVAL;
	existing = &store->entries[region];
	if (store->sealed)
		return -EPERM;
	/*
	 * Provenance is monotonic (round 11): a lexical measurement may be
	 * upgraded by an externally rooted one — the design's rule is that a claim
	 * may only rest on external evidence, and a first-arriving lexical record
	 * must not pin the weaker provenance for the boot — while the reverse
	 * would silently weaken a record that already rests on external evidence.
	 * Any other rewrite stays refused.
	 */
	if (existing->hash) {
		if (existing->source != AUTH_EXPECTATION_SOURCE_LEXICAL ||
		    source != AUTH_EXPECTATION_SOURCE_EXTERNAL)
			return -EEXIST;
	}

	store->entries[region] = (struct auth_expectation) {
		.hash = hash,
		.len = len,
		.region = region,
		.source = source,
		.transcript = transcript,
	};

	return 0;
}

/**
 * auth_expectation_store_record - record a lexical (in-kernel) expectation
 * @store: the store to write to
 * @region: the measured region
 * @hash: the measured value
 * @len: the measured length
 *
 * The entry point fixes the provenance: a caller cannot declare its own
 * measurement external.  Externality is a claim about where the value came
 * from, not a label, so it may only be produced by the path that actually
 * received the external transcript (see
 * auth_expectation_store_record_external()).
 */
int auth_expectation_store_record(struct auth_expectation_store *store,
				  enum auth_expectation_region region, u64 hash,
				  u32 len)
{
	return auth_expectation_store_put(store, region, hash, len,
					  AUTH_EXPECTATION_SOURCE_LEXICAL, 0);
}
EXPORT_SYMBOL_GPL(auth_expectation_store_record);

/**
 * auth_expectation_store_record_external - record an externally measured
 * expectation
 * @store: the store to write to
 * @region: the measured region
 * @hash: the externally measured value
 * @len: the measured length
 * @transcript: identifying seal of the external transcript the value came
 *              from; zero is refused
 *
 * This is the only producer of AUTH_EXPECTATION_SOURCE_EXTERNAL.  The seal is
 * stored with the record, so the claim carries the evidence it rests on
 * instead of being a bare label; verifying the transcript itself belongs to
 * the external measurement path (P-14S/P-17), which owns this entry point.
 */
int auth_expectation_store_record_external(struct auth_expectation_store *store,
					   enum auth_expectation_region region,
					   u64 hash, u32 len, u64 transcript)
{
	if (!transcript)
		return -EINVAL;

	return auth_expectation_store_put(store, region, hash, len,
					  AUTH_EXPECTATION_SOURCE_EXTERNAL,
					  transcript);
}
EXPORT_SYMBOL_GPL(auth_expectation_store_record_external);

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
			    u32 len)
{
	return auth_expectation_store_record(&auth_expectation_store, region,
					     hash, len);
}
EXPORT_SYMBOL_GPL(auth_expectation_record);

int auth_expectation_record_external(enum auth_expectation_region region,
				     u64 hash, u32 len, u64 transcript)
{
	return auth_expectation_store_record_external(&auth_expectation_store,
						      region, hash, len,
						      transcript);
}
EXPORT_SYMBOL_GPL(auth_expectation_record_external);

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
	/*
	 * The template identity is part of what a table claims.  Zero is an
	 * unset identity, not "any template": the judge compares the table's
	 * template_id against the tuple's subject template, so a table sealed
	 * with zero would declare transitions for callers whose subject was
	 * never identified.
	 */
	if (!table->template_id)
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

/**
 * auth_contract_table_verify_buffer - verify a table that arrived as a buffer
 * @buf: the received table image (head followed by its rows)
 * @len: the received length in bytes
 *
 * Tables that reach the kernel from outside (the manager-signed loader, P-03)
 * arrive as a byte range, and row_count is attacker-supplied like the rest of
 * the wire form.  Verifying such a buffer without checking that it really
 * holds row_count rows would read past its end while iterating and digesting:
 * the keyed seal still prevents forgery, but the read itself is a
 * memory-safety hole bounded only by AUTH_CONTRACT_MAX_ROWS.  The length gate
 * is therefore mandatory and exact here, so a truncated row array and
 * trailing bytes the sender did not sign are both rejected before any row is
 * touched.
 */
int auth_contract_table_verify_buffer(const void *buf, size_t len)
{
	const struct auth_transition_table *table = buf;
	size_t expected;

	if (!buf || len < sizeof(*table))
		return -EINVAL;

	expected = struct_size(table, rows, table->row_count);
	if (len != expected)
		return -EINVAL;

	return auth_contract_table_verify(table);
}
EXPORT_SYMBOL_GPL(auth_contract_table_verify_buffer);

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

/**
 * auth_contract_row_hash - content hash of a table's rows
 * @rows: the row array
 * @count: number of rows
 *
 * The table carries the hash of the rows it ships (P-04's row_hash) and the
 * load path must find it consistent with those rows: the kernel seal covers
 * the field too, so a sealed table whose hash contradicts its rows is a
 * self-contradictory object, and anything that compares tables by that hash
 * (the narrowing rule, the fleet records) would otherwise be comparing claims
 * instead of content.
 *
 * xxh64 with seed 0 is deterministic and available on both sides of the
 * interface (the kernel and the manager-side authoring tooling), which is what
 * makes the field checkable at all; authentication is the seal's job, not this
 * hash's.
 */
u64 auth_contract_row_hash(const struct auth_transition_row *rows,
			   unsigned int count)
{
	return xxh64(rows, array_size(count, sizeof(*rows)), 0);
}
EXPORT_SYMBOL_GPL(auth_contract_row_hash);

static int
auth_contract_table_row_hash_check(const struct auth_transition_table *table)
{
	if (table->row_hash != auth_contract_row_hash(table->rows,
						      table->row_count))
		return -EKEYREJECTED;

	return 0;
}

int auth_contract_load(const struct auth_transition_table *table)
{
	unsigned int i;
	int ret;

	ret = auth_contract_table_verify(table);
	if (ret)
		return ret;

	ret = auth_contract_table_row_hash_check(table);
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

/**
 * auth_contract_table_publish - make a table the one the kernel uses
 * @table: the verified table to publish
 *
 * Publication transfers ownership: the kernel takes a private copy of exactly
 * struct_size(rows, row_count) bytes and publishes that.  Publishing the
 * caller's buffer would leave the live policy caller-owned — mutable after
 * the seal was checked, and freeable while readers still dereference it — so
 * a later edit or reuse of the buffer could change what the kernel enforces
 * without any verification seeing it.
 *
 * At most one table is active per boot, and the copy is never released: that
 * is the lifetime the active table has.
 */
int auth_contract_table_publish(struct auth_transition_table *table)
{
	struct auth_transition_table *copy;
	atomic_long_t *counters;
	size_t len;
	int ret;

	if (!table)
		return -EINVAL;
	if (rcu_access_pointer(auth_contract_active))
		return -EBUSY;

	ret = auth_contract_load(table);
	if (ret)
		return ret;

	len = struct_size(copy, rows, table->row_count);
	copy = kmemdup(table, len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	/* The copy must verify in its own right before it goes live. */
	ret = auth_contract_table_verify(copy);
	if (ret) {
		kfree(copy);
		return ret;
	}

	counters = kcalloc(table->row_count, sizeof(*counters), GFP_KERNEL);
	if (!counters) {
		kfree(copy);
		return -ENOMEM;
	}

	/* Counters first: a reader that sees the table must see them. */
	smp_store_release(&auth_contract_counters, counters);
	rcu_assign_pointer(auth_contract_active, copy);

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
	u32 pending;
	unsigned int i;

	if (!tuple || !tuple->roots)
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

	/*
	 * A tuple may request several roots at once, and the verdict must cover
	 * every one of them: a forbidden row denies the whole transition even
	 * when another requested root has an allowed row (deny wins), and a root
	 * that no row declares keeps the verdict undeclared.  Unknown is never a
	 * silent pass, and table ordering must not decide the outcome.
	 */
	pending = tuple->roots;
	for (i = 0; i < table->row_count; i++) {
		const struct auth_transition_row *row = &table->rows[i];
		u32 root_bit;

		if (row->kind != tuple->kind || row->trigger != tuple->trigger ||
		    row->caller != tuple->caller ||
		    row->subject_class != tuple->subject.klass)
			continue;

		root_bit = BIT(row->root_class);
		if (!(tuple->roots & root_bit))
			continue;

		if (row->leaf == AUTH_CONTRACT_LEAF_FORBIDDEN)
			return AUTH_VERDICT_FORBIDDEN;
		if (!(pending & root_bit))
			continue;

		atomic_long_inc(&counters[i]);
		pending &= ~root_bit;
	}

	if (pending)
		return AUTH_VERDICT_UNKNOWN;

	return AUTH_VERDICT_DECLARED;
}
EXPORT_SYMBOL_GPL(auth_contract_judge);

#define AUTH_CONTRACT_PATTERN_SLOTS 64

static DEFINE_SPINLOCK(auth_contract_pattern_lock);
static struct auth_contract_note_key auth_contract_patterns[AUTH_CONTRACT_PATTERN_SLOTS];
static unsigned int auth_contract_pattern_count;

/**
 * auth_contract_note_key - the de-duplication key of a transition class
 * @tuple: the judged transition
 * @key: filled with the class pattern and the template it belongs to
 *
 * The log-only note reports a class once.  Templates are a dimension of that
 * class — the log line prints the template — so the key carries it: otherwise
 * the first violation of one template would suppress the first violation of
 * another, and a node running several templates would under-report silently.
 */
void auth_contract_note_key(const struct auth_transition_tuple *tuple,
			    struct auth_contract_note_key *key)
{
	key->pattern = (u64)tuple->kind << 56 | (u64)tuple->trigger << 48 |
		       (u64)tuple->caller << 40 |
		       (u64)tuple->subject.klass << 32 | tuple->roots;
	if (!key->pattern)
		key->pattern = 1;
	key->template_id = tuple->subject.template_id;
}
EXPORT_SYMBOL_GPL(auth_contract_note_key);

enum auth_contract_verdict
auth_contract_note(const struct auth_transition_tuple *tuple, const char *where)
{
	enum auth_contract_verdict verdict;
	unsigned long flags;
	unsigned int i;
	bool first = false;
	struct auth_contract_note_key key;

	if (!tuple)
		return AUTH_VERDICT_UNKNOWN;

	verdict = auth_contract_judge(tuple);
	if (verdict == AUTH_VERDICT_DECLARED)
		return verdict;
	/* Without a table there is nothing to note against yet. */
	if (!auth_contract_table_get())
		return verdict;

	auth_contract_note_key(tuple, &key);

	spin_lock_irqsave(&auth_contract_pattern_lock, flags);
	for (i = 0; i < auth_contract_pattern_count; i++) {
		if (auth_contract_patterns[i].pattern == key.pattern &&
		    auth_contract_patterns[i].template_id == key.template_id)
			break;
	}
	if (i == auth_contract_pattern_count) {
		if (auth_contract_pattern_count < AUTH_CONTRACT_PATTERN_SLOTS)
			auth_contract_patterns[auth_contract_pattern_count++] =
				key;
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
