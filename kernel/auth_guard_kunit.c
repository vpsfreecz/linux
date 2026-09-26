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
	unsigned long count;
	unsigned int i;

	/* The first failure of a site is the report that must survive. */
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_FIRST);
	KUNIT_EXPECT_EQ(test, count, 1UL);

	/* Immediate repeats are counted and skipped... */
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_SKIP);
	KUNIT_EXPECT_EQ(test, count, 2UL);
	KUNIT_EXPECT_EQ(test,
			auth_guard_fail_store_record(store, &key, &count),
			AUTH_GUARD_FAIL_LOG_SKIP);
	KUNIT_EXPECT_EQ(test, count, 3UL);

	/* ...and the volume reappears on powers of two. */
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
				auth_guard_fail_store_record(store, &key, &count),
				AUTH_GUARD_FAIL_LOG_FIRST);
}

static struct kunit_case auth_guard_test_cases[] = {
	KUNIT_CASE(auth_guard_crng_gate_allows_initialized),
	KUNIT_CASE(auth_guard_crng_gate_refuses_uninitialized),
	KUNIT_CASE(auth_guard_crng_gate_honours_forced_unready),
	KUNIT_CASE(auth_guard_crng_refusal_keeps_the_guard_mode),
	KUNIT_CASE(auth_guard_fail_logs_each_site_once),
	{}
};

static struct kunit_suite auth_guard_test_suite = {
	.name = "auth_guard",
	.test_cases = auth_guard_test_cases,
};
kunit_test_suite(auth_guard_test_suite);

MODULE_DESCRIPTION("KUnit tests for the authority guard CRNG gate");
MODULE_LICENSE("GPL");
