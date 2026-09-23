// SPDX-License-Identifier: GPL-2.0-or-later

#include <kunit/test.h>
#include <linux/auth_contract.h>

static void auth_expectation_missing_region_fails_closed(struct kunit *test)
{
	struct auth_expectation_store store = { };
	struct auth_expectation out;
	int ret;

	KUNIT_EXPECT_FALSE(test, auth_expectation_store_sealed(&store));

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void auth_expectation_record_lookup_roundtrip(struct kunit *test)
{
	struct auth_expectation_store store = { };
	struct auth_expectation out;
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    0x1234, 64,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, out.hash, 0x1234);
	KUNIT_EXPECT_EQ(test, out.len, 64);
	KUNIT_EXPECT_EQ(test, out.region, AUTH_EXPECTATION_REGION_GUARD_TEXT);
	KUNIT_EXPECT_EQ(test, out.source, AUTH_EXPECTATION_SOURCE_LEXICAL);
}

static void auth_expectation_rejects_invalid_values(struct kunit *test)
{
	struct auth_expectation_store store = { };
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_COUNT, 1, 1,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 0, 1,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 0,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_POLICY,
					    NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void auth_expectation_duplicate_record_rejected(struct kunit *test)
{
	struct auth_expectation_store store = { };
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 1,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 2, 2,
					    AUTH_EXPECTATION_SOURCE_EXTERNAL);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

static void auth_expectation_sealed_store_rejects_records(struct kunit *test)
{
	struct auth_expectation_store store = { };
	struct auth_expectation out;
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    1, 1,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_ASSERT_EQ(test, ret, 0);

	auth_expectation_store_seal(&store);
	KUNIT_EXPECT_TRUE(test, auth_expectation_store_sealed(&store));

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 1,
					    AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case auth_expectation_test_cases[] = {
	KUNIT_CASE(auth_expectation_missing_region_fails_closed),
	KUNIT_CASE(auth_expectation_record_lookup_roundtrip),
	KUNIT_CASE(auth_expectation_rejects_invalid_values),
	KUNIT_CASE(auth_expectation_duplicate_record_rejected),
	KUNIT_CASE(auth_expectation_sealed_store_rejects_records),
	{}
};

static struct kunit_suite auth_expectation_test_suite = {
	.name = "auth_expectation",
	.test_cases = auth_expectation_test_cases,
};

kunit_test_suite(auth_expectation_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for the authority expectation store");
