// SPDX-License-Identifier: GPL-2.0-or-later

#include <kunit/test.h>
#include <linux/auth_contract.h>
#include <linux/auth_guard.h>
#include <linux/overflow.h>

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

static struct auth_transition_table *
auth_contract_test_table(struct kunit *test, unsigned int rows)
{
	struct auth_transition_table *table;

	table = kunit_kzalloc(test, struct_size(table, rows, rows), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, table);

	table->template_id = 7;
	table->row_count = rows;
	table->row_hash = 0x1223344556677889ULL;

	if (rows > 0)
		table->rows[0] = (struct auth_transition_row) {
			.kind = AUTH_CONTRACT_KIND_CRED_COMMIT,
			.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
			.root_class = AUTH_CONTRACT_ROOT_CONTAINER_CRED,
			.trigger = AUTH_CONTRACT_TRIGGER_COMMIT_CREDS,
			.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
			.leaf = AUTH_CONTRACT_LEAF_ALLOWED,
		};
	if (rows > 1)
		table->rows[1] = (struct auth_transition_row) {
			.kind = AUTH_CONTRACT_KIND_NS_JOIN,
			.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
			.root_class = AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY,
			.trigger = AUTH_CONTRACT_TRIGGER_SETNS,
			.caller = AUTH_CONTRACT_SUBJECT_MANAGER,
			.leaf = AUTH_CONTRACT_LEAF_FORBIDDEN,
		};

	return table;
}

static void auth_contract_table_seal_roundtrip(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_EXPECT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_EXPECT_TRUE(test, auth_guard_stamp_valid(&table->stamp));
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), 0);
}

static void auth_contract_table_verify_rejects_tampered_row(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	table->rows[1].leaf = AUTH_CONTRACT_LEAF_ALLOWED;
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EKEYREJECTED);
}

static void auth_contract_table_verify_rejects_tampered_head(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	table->row_hash ^= 1;
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EKEYREJECTED);
}

static void auth_contract_table_verify_rejects_unsealed(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_EXPECT_FALSE(test, auth_guard_stamp_valid(&table->stamp));
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EKEYREJECTED);
}

static void auth_contract_table_rejects_bad_row_count(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 1);

	table->row_count = 0;
	KUNIT_EXPECT_EQ(test, auth_contract_table_seal(table), -EINVAL);
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EINVAL);

	table->row_count = AUTH_CONTRACT_MAX_ROWS + 1;
	KUNIT_EXPECT_EQ(test, auth_contract_table_seal(table), -EINVAL);
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EINVAL);
}

static void auth_contract_row_accepts_inventoried_values(struct kunit *test)
{
	struct auth_transition_row row = {
		.kind = AUTH_CONTRACT_KIND_FD_TRANSFER,
		.subject_class = AUTH_CONTRACT_SUBJECT_GUEST_AGENT,
		.root_class = AUTH_CONTRACT_ROOT_HOST_BPF,
		.trigger = AUTH_CONTRACT_TRIGGER_SCM_RIGHTS,
		.caller = AUTH_CONTRACT_SUBJECT_MANAGER,
		.leaf = AUTH_CONTRACT_LEAF_ALLOWED,
	};

	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);
}

static void auth_contract_row_rejects_unknown_values(struct kunit *test)
{
	struct auth_transition_row row = {
		.kind = AUTH_CONTRACT_KIND_CRED_COMMIT,
		.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
		.root_class = AUTH_CONTRACT_ROOT_CONTAINER_CRED,
		.trigger = AUTH_CONTRACT_TRIGGER_COMMIT_CREDS,
		.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
		.leaf = AUTH_CONTRACT_LEAF_ALLOWED,
	};

	row.kind = AUTH_CONTRACT_KIND_UNKNOWN;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);
	row.kind = AUTH_CONTRACT_KIND_COUNT;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);

	row.kind = AUTH_CONTRACT_KIND_CRED_COMMIT;
	row.trigger = AUTH_CONTRACT_TRIGGER_UNKNOWN;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);
	row.trigger = AUTH_CONTRACT_TRIGGER_COUNT;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);

	row.trigger = AUTH_CONTRACT_TRIGGER_COMMIT_CREDS;
	row.subject_class = AUTH_CONTRACT_SUBJECT_UNKNOWN;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);
	row.subject_class = AUTH_CONTRACT_SUBJECT_CLASS_COUNT;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);

	row.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	row.root_class = AUTH_CONTRACT_ROOT_UNKNOWN;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);
	row.root_class = AUTH_CONTRACT_ROOT_CLASS_COUNT;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);

	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_CRED;
	row.leaf = AUTH_CONTRACT_LEAF_UNKNOWN;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);
}

static void auth_contract_row_rejects_tenant_with_host_root(struct kunit *test)
{
	struct auth_transition_row row = {
		.kind = AUTH_CONTRACT_KIND_CRED_COMMIT,
		.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_CONTAINER,
		.root_class = AUTH_CONTRACT_ROOT_HOST_CRED,
		.trigger = AUTH_CONTRACT_TRIGGER_COMMIT_CREDS,
		.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK,
		.leaf = AUTH_CONTRACT_LEAF_ALLOWED,
	};

	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), -EINVAL);

	row.subject_class = AUTH_CONTRACT_SUBJECT_MANAGER;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);
}

static void auth_contract_load_accepts_sealed_table(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_EXPECT_EQ(test, auth_contract_load(table), 0);
}

static void auth_contract_load_rejects_unsealed_table(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_EXPECT_EQ(test, auth_contract_load(table), -EKEYREJECTED);
}

static void auth_contract_load_rejects_invalid_row(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	table->rows[1].leaf = AUTH_CONTRACT_LEAF_UNKNOWN;
	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_EXPECT_EQ(test, auth_contract_load(table), -EINVAL);
}

static struct auth_transition_tuple *
auth_contract_test_tuple(struct kunit *test, unsigned int roots)
{
	struct auth_transition_tuple *tuple;

	tuple = kunit_kzalloc(test, sizeof(*tuple), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tuple);

	tuple->kind = AUTH_CONTRACT_KIND_CRED_COMMIT;
	tuple->trigger = AUTH_CONTRACT_TRIGGER_COMMIT_CREDS;
	tuple->caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	tuple->roots = roots;
	tuple->subject.template_id = 7;
	tuple->subject.klass = AUTH_CONTRACT_SUBJECT_TENANT_TASK;

	return tuple;
}

static void auth_contract_judge_without_table_is_unknown(struct kunit *test)
{
	struct auth_transition_tuple *tuple;
	unsigned int roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_CRED);

	tuple = auth_contract_test_tuple(test, roots);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_UNKNOWN);
}

static void auth_contract_note_without_table_is_unknown(struct kunit *test)
{
	struct auth_transition_tuple *tuple;
	unsigned int roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_CRED);

	tuple = auth_contract_test_tuple(test, roots);
	KUNIT_EXPECT_EQ(test, auth_contract_note(tuple, "test"),
			AUTH_VERDICT_UNKNOWN);
}

static void auth_contract_table_publish_rejects_unsealed(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_EXPECT_EQ(test, auth_contract_table_publish(table), -EKEYREJECTED);
}

static void auth_contract_table_publish_and_judge(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);
	struct auth_transition_tuple *tuple;

	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_ASSERT_EQ(test, auth_contract_table_publish(table), 0);
	KUNIT_EXPECT_PTR_EQ(test, auth_contract_table_get(), table);

	/* Row 0: allowed credential commit for a tenant task. */
	tuple = auth_contract_test_tuple(test,
					 BIT(AUTH_CONTRACT_ROOT_CONTAINER_CRED));
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_DECLARED);
	KUNIT_EXPECT_EQ(test, auth_contract_row_count(0), 1UL);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_DECLARED);
	KUNIT_EXPECT_EQ(test, auth_contract_row_count(0), 2UL);

	/* Row 1: forbidden namespace join for a tenant task. */
	tuple->kind = AUTH_CONTRACT_KIND_NS_JOIN;
	tuple->trigger = AUTH_CONTRACT_TRIGGER_SETNS;
	tuple->caller = AUTH_CONTRACT_SUBJECT_MANAGER;
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_FORBIDDEN);
	KUNIT_EXPECT_EQ(test, auth_contract_row_count(1), 0UL);

	/* A root class the row does not cover stays undeclared. */
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_HOST_CRED);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_UNKNOWN);

	/* Another template is not this table's business. */
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_CRED);
	tuple->subject.template_id = 8;
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_UNKNOWN);

	/* A second publication is refused. */
	KUNIT_EXPECT_EQ(test, auth_contract_table_publish(table), -EBUSY);
}

static void auth_contract_note_reports_the_verdict(struct kunit *test)
{
	struct auth_transition_tuple *tuple;

	/* The table is published by the previous case. */
	KUNIT_ASSERT_NOT_NULL(test, auth_contract_table_get());

	tuple = auth_contract_test_tuple(test,
					 BIT(AUTH_CONTRACT_ROOT_CONTAINER_CRED));
	KUNIT_EXPECT_EQ(test, auth_contract_note(tuple, "test"),
			AUTH_VERDICT_DECLARED);

	tuple->kind = AUTH_CONTRACT_KIND_NS_JOIN;
	tuple->trigger = AUTH_CONTRACT_TRIGGER_SETNS;
	tuple->caller = AUTH_CONTRACT_SUBJECT_MANAGER;
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY);
	KUNIT_EXPECT_EQ(test, auth_contract_note(tuple, "test"),
			AUTH_VERDICT_FORBIDDEN);

	tuple->roots = BIT(AUTH_CONTRACT_ROOT_HOST_CRED);
	KUNIT_EXPECT_EQ(test, auth_contract_note(tuple, "test"),
			AUTH_VERDICT_UNKNOWN);
}

static struct kunit_case auth_contract_test_cases[] = {
	KUNIT_CASE(auth_expectation_missing_region_fails_closed),
	KUNIT_CASE(auth_expectation_record_lookup_roundtrip),
	KUNIT_CASE(auth_expectation_rejects_invalid_values),
	KUNIT_CASE(auth_expectation_duplicate_record_rejected),
	KUNIT_CASE(auth_expectation_sealed_store_rejects_records),
	KUNIT_CASE(auth_contract_table_seal_roundtrip),
	KUNIT_CASE(auth_contract_table_verify_rejects_tampered_row),
	KUNIT_CASE(auth_contract_table_verify_rejects_tampered_head),
	KUNIT_CASE(auth_contract_table_verify_rejects_unsealed),
	KUNIT_CASE(auth_contract_table_rejects_bad_row_count),
	KUNIT_CASE(auth_contract_row_accepts_inventoried_values),
	KUNIT_CASE(auth_contract_row_rejects_unknown_values),
	KUNIT_CASE(auth_contract_row_rejects_tenant_with_host_root),
	KUNIT_CASE(auth_contract_load_accepts_sealed_table),
	KUNIT_CASE(auth_contract_load_rejects_unsealed_table),
	KUNIT_CASE(auth_contract_load_rejects_invalid_row),
	KUNIT_CASE(auth_contract_judge_without_table_is_unknown),
	KUNIT_CASE(auth_contract_note_without_table_is_unknown),
	KUNIT_CASE(auth_contract_table_publish_rejects_unsealed),
	KUNIT_CASE(auth_contract_table_publish_and_judge),
	KUNIT_CASE(auth_contract_note_reports_the_verdict),
	{}
};

static struct kunit_suite auth_contract_test_suite = {
	.name = "auth_contract",
	.test_cases = auth_contract_test_cases,
};

kunit_test_suite(auth_contract_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for the authority contract");
