// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KUnit tests for the authority guard: the P-01 CRNG gate.
 *
 * The gate itself is exercised end to end by the cred-guard guest script
 * (`#crng-gate`), which needs a machine boot; these cases pin the decision
 * matrix in the kernel so the refusal logic stays covered by the suite that
 * runs on every contract kernel.
 */

#include <kunit/test.h>

#include <linux/auth_guard.h>
#include <linux/kthread.h>
#include <linux/timekeeping.h>

static void auth_guard_crng_gate_allows_initialized(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, auth_guard_crng_gate_allows(true, false));
}

static void auth_guard_crng_gate_refuses_uninitialized(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, auth_guard_crng_gate_allows(false, false));
}

static void auth_guard_crng_gate_honours_forced_unready(struct kunit *test)
{
	/* The synthetic knob refuses even when the generator is ready. */
	KUNIT_EXPECT_FALSE(test, auth_guard_crng_gate_allows(false, true));
	KUNIT_EXPECT_FALSE(test, auth_guard_crng_gate_allows(true, true));
}

static void auth_guard_crng_refusal_keeps_the_guard_mode(struct kunit *test)
{
	struct auth_guard_crng_refusal refusal;

	refusal = auth_guard_crng_refusal_outcome(AUTH_GUARD_MODE_PANIC);
	KUNIT_EXPECT_TRUE(test, refusal.refused);
	KUNIT_EXPECT_EQ(test, refusal.mode, AUTH_GUARD_MODE_PANIC);

	refusal = auth_guard_crng_refusal_outcome(AUTH_GUARD_MODE_LOG);
	KUNIT_EXPECT_TRUE(test, refusal.refused);
	KUNIT_EXPECT_EQ(test, refusal.mode, AUTH_GUARD_MODE_LOG);

	refusal = auth_guard_crng_refusal_outcome(AUTH_GUARD_MODE_OFF);
	KUNIT_EXPECT_TRUE(test, refusal.refused);
	KUNIT_EXPECT_EQ(test, refusal.mode, AUTH_GUARD_MODE_OFF);
}

static void auth_guard_fail_logs_each_site_once(struct kunit *test)
{
	struct auth_guard_fail_store *store;

	/*
	 * The latch covers the inventoried sites (256 slots ≈ 8 KB), so the case
	 * keeps it off the stack.
	 */
	store = kunit_kzalloc(test, sizeof(*store), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, store);
	struct auth_guard_fail_key key = {
		.domain = test,
		.where = "site-a",
		.what = "reason",
	};
	struct auth_guard_fail_key other = {
		.domain = test,
		.where = "site-b",
		.what = "reason",
	};
	struct auth_guard_fail_key fresh = {
		.domain = test,
		.where = "site-c",
		.what = "reason",
	};
	unsigned long count, fresh_count;
	unsigned int i;

	/* The first failure of a site is the report that must survive. */
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_FIRST);
	KUNIT_EXPECT_EQ(test, count, 1UL);

	/* ...and the volume reappears on powers of two (2, 4, 8, ...). */
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_REPEAT);
	KUNIT_EXPECT_EQ(test, count, 2UL);
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_SKIP);
	KUNIT_EXPECT_EQ(test, count, 3UL);
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_REPEAT);
	KUNIT_EXPECT_EQ(test, count, 4UL);

	/* A different site is a different report. */
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &other, &count),
			AUTH_GUARD_FAIL_LOG_FIRST);
	KUNIT_EXPECT_EQ(test, count, 1UL);

	/* A full store cannot remember new sites: they log every time. */
	for (i = 0; i < AUTH_GUARD_FAIL_SLOTS; i++) {
		struct auth_guard_fail_key filler = {
			.domain = test,
			.where = "filler",
			.what = (const char *)(unsigned long)i,
		};
		unsigned long ignored;

		auth_guard_fail_store_record(store, &filler, &ignored);
	}

	for (i = 0; i < 2; i++)
		KUNIT_EXPECT_EQ(test,
				auth_guard_fail_store_record(store, &fresh, &fresh_count),
				AUTH_GUARD_FAIL_LOG_FIRST);
	KUNIT_EXPECT_EQ(test, fresh_count, 1UL);
}

static int auth_guard_counter_worker(void *data)
{
	unsigned int iters = *(unsigned int *)data;
	unsigned int i;

	for (i = 0; i < iters; i++)
		auth_guard_counter_inc(AUTH_GUARD_CTR_TEST);

	while (!kthread_should_stop())
		cond_resched();

	return 0;
}

static void auth_guard_counters_lose_no_increments(struct kunit *test)
{
	const unsigned int nr_threads = 8;
	const unsigned int iters = 10000;
	struct task_struct *threads[8];
	u64 before, after;

	before = auth_guard_counters_total(AUTH_GUARD_CTR_TEST);
	for (unsigned int i = 0; i < nr_threads; i++) {
		threads[i] = kthread_run(auth_guard_counter_worker, (void *)&iters,
					 "ag_ctr%u", i);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, threads[i]);
	}
	for (unsigned int i = 0; i < nr_threads; i++)
		kthread_stop(threads[i]);

	after = auth_guard_counters_total(AUTH_GUARD_CTR_TEST);
	KUNIT_EXPECT_EQ(test, after - before, (u64)nr_threads * iters);
}

static void auth_guard_counters_snapshot_is_monotonic(struct kunit *test)
{
	u64 a[AUTH_GUARD_CTR_LAST], b[AUTH_GUARD_CTR_LAST];

	auth_guard_counters_snapshot(a, AUTH_GUARD_CTR_LAST);
	auth_guard_counters_snapshot(b, AUTH_GUARD_CTR_LAST);

	for (int i = 0; i < AUTH_GUARD_CTR_LAST; i++)
		KUNIT_EXPECT_GE(test, b[i], a[i]);

	/* Only the suite touches the test class, so it is exactly stable. */
	KUNIT_EXPECT_EQ(test, b[AUTH_GUARD_CTR_TEST], a[AUTH_GUARD_CTR_TEST]);
}

static void auth_guard_boot_id_is_drawn_when_enabled(struct kunit *test)
{
	if (auth_guard_enabled())
		KUNIT_EXPECT_NE(test, auth_guard_boot_id(), 0);
}

static void auth_guard_mutation_worst_is_retain_biased(struct kunit *test)
{
	static const enum auth_guard_mutation_result classes[] = {
		AUTH_GUARD_MUTATION_REJECTED,
		AUTH_GUARD_MUTATION_BUSY,
		AUTH_GUARD_MUTATION_APPLIED,
		AUTH_GUARD_MUTATION_QUARANTINED,
	};
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		for (j = 0; j < ARRAY_SIZE(classes); j++) {
			enum auth_guard_mutation_result worst =
				auth_guard_mutation_worst(classes[i], classes[j]);

			if (classes[i] == AUTH_GUARD_MUTATION_QUARANTINED ||
			    classes[j] == AUTH_GUARD_MUTATION_QUARANTINED)
				KUNIT_EXPECT_EQ(test, worst, AUTH_GUARD_MUTATION_QUARANTINED);
			else if (classes[i] == AUTH_GUARD_MUTATION_BUSY ||
				 classes[j] == AUTH_GUARD_MUTATION_BUSY)
				KUNIT_EXPECT_EQ(test, worst, AUTH_GUARD_MUTATION_BUSY);
			else if (classes[i] == AUTH_GUARD_MUTATION_REJECTED ||
				 classes[j] == AUTH_GUARD_MUTATION_REJECTED)
				KUNIT_EXPECT_EQ(test, worst, AUTH_GUARD_MUTATION_REJECTED);
			else
				KUNIT_EXPECT_EQ(test, worst, AUTH_GUARD_MUTATION_APPLIED);
		}
	}
}

static void auth_guard_quarantine_quota_collapses(struct kunit *test)
{
	atomic_t retained = ATOMIC_INIT(0);
	u64 collapsed_before, collapsed_after;
	unsigned int i;

	for (i = 0; i < AUTH_GUARD_QUARANTINE_QUOTA; i++)
		KUNIT_ASSERT_TRUE(test,
			auth_guard_quarantine_retain_counted(&retained));

	/* Past the quota the object collapses instead of being retained. */
	collapsed_before = auth_guard_counters_total(
		AUTH_GUARD_CTR_QUARANTINE_COLLAPSED);
	KUNIT_EXPECT_FALSE(test, auth_guard_quarantine_retain_counted(&retained));
	KUNIT_EXPECT_FALSE(test, auth_guard_quarantine_retain_counted(&retained));
	collapsed_after = auth_guard_counters_total(
		AUTH_GUARD_CTR_QUARANTINE_COLLAPSED);

	KUNIT_EXPECT_GE(test, collapsed_after - collapsed_before, 2);
	KUNIT_EXPECT_EQ(test, atomic_read(&retained),
			(int)AUTH_GUARD_QUARANTINE_QUOTA);
}

/*
 * W7/P-13 cost record: the seal primitive (siphash over a 64-byte block with
 * the domain-key shape) and the per-CPU counter increment, so every run
 * carries the guard's primitive costs in its log and the ledger.  The bounds
 * are deliberately loose: this catches catastrophic regressions, not the few
 * percent the design budgets.
 */
static void auth_guard_seal_cost_is_recorded(struct kunit *test)
{
	enum { OPS = 20000 };
	siphash_key_t key = { .key = { 0x0123456789abcdefULL, 0xfedcba9876543210ULL } };
	u8 data[64] = { };
	u64 t0, t1, i, acc = 0;
	u64 seal_ns, ctr_ns;

	t0 = ktime_get_ns();
	for (i = 0; i < OPS; i++)
		acc ^= siphash(data, sizeof(data), &key);
	t1 = ktime_get_ns();
	seal_ns = (t1 - t0) / OPS;

	t0 = ktime_get_ns();
	for (i = 0; i < OPS; i++)
		auth_guard_counter_inc(AUTH_GUARD_CTR_TEST);
	t1 = ktime_get_ns();
	ctr_ns = (t1 - t0) / OPS;

	/* Keep the accumulated result observable. */
	KUNIT_EXPECT_NE(test, acc, 0);

	kunit_info(test, "cost: siphash64=%llu ns/op, counter_inc=%llu ns/op (%u ops)",
		   (unsigned long long)seal_ns, (unsigned long long)ctr_ns,
		   (unsigned)OPS);

	KUNIT_EXPECT_LT(test, seal_ns, 5000);
	KUNIT_EXPECT_LT(test, ctr_ns, 1000);
}

static struct kunit_case auth_guard_test_cases[] = {
	KUNIT_CASE(auth_guard_crng_gate_allows_initialized),
	KUNIT_CASE(auth_guard_crng_gate_refuses_uninitialized),
	KUNIT_CASE(auth_guard_crng_gate_honours_forced_unready),
	KUNIT_CASE(auth_guard_crng_refusal_keeps_the_guard_mode),
	KUNIT_CASE(auth_guard_fail_logs_each_site_once),
	KUNIT_CASE(auth_guard_counters_lose_no_increments),
	KUNIT_CASE(auth_guard_counters_snapshot_is_monotonic),
	KUNIT_CASE(auth_guard_boot_id_is_drawn_when_enabled),
	KUNIT_CASE(auth_guard_mutation_worst_is_retain_biased),
	KUNIT_CASE(auth_guard_quarantine_quota_collapses),
	KUNIT_CASE(auth_guard_seal_cost_is_recorded),
	{}
};

static struct kunit_suite auth_guard_test_suite = {
	.name = "auth_guard",
	.test_cases = auth_guard_test_cases,
};
kunit_test_suite(auth_guard_test_suite);

MODULE_DESCRIPTION("KUnit tests for the authority guard CRNG gate");
MODULE_LICENSE("GPL");
