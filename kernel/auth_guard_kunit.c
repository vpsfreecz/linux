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

static struct kunit_case auth_guard_test_cases[] = {
	KUNIT_CASE(auth_guard_crng_gate_allows_initialized),
	KUNIT_CASE(auth_guard_crng_gate_refuses_uninitialized),
	KUNIT_CASE(auth_guard_crng_gate_honours_forced_unready),
	{}
};

static struct kunit_suite auth_guard_test_suite = {
	.name = "auth_guard",
	.test_cases = auth_guard_test_cases,
};
kunit_test_suite(auth_guard_test_suite);

MODULE_DESCRIPTION("KUnit tests for the authority guard CRNG gate");
MODULE_LICENSE("GPL");
