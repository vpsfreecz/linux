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
					    0x1234, 64);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, out.hash, 0x1234);
	KUNIT_EXPECT_EQ(test, out.len, 64);
	KUNIT_EXPECT_EQ(test, out.region, AUTH_EXPECTATION_REGION_GUARD_TEXT);
	KUNIT_EXPECT_EQ(test, out.source, AUTH_EXPECTATION_SOURCE_LEXICAL);
	KUNIT_EXPECT_EQ(test, out.transcript, 0);

	/*
	 * An externally rooted record must stay distinguishable from a lexical
	 * one: the "externally measured" claim rests on that difference.
	 */
	ret = auth_expectation_store_record_external(&store,
						     AUTH_EXPECTATION_REGION_POLICY,
						     0x5678, 32, 0xbeefcafe);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_POLICY,
					    &out);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out.source, AUTH_EXPECTATION_SOURCE_EXTERNAL);
	KUNIT_EXPECT_EQ(test, out.transcript, 0xbeefcafe);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out.source, AUTH_EXPECTATION_SOURCE_LEXICAL);
}

static void auth_expectation_rejects_invalid_values(struct kunit *test)
{
	struct auth_expectation_store store = { };
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_COUNT, 1, 1);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 0, 1);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_POLICY,
					    NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	/*
	 * Externality is not a label: the lexical entry point cannot mint it at
	 * all (the source is not a parameter), and the external entry point
	 * refuses a claim that carries no transcript seal.
	 */
	ret = auth_expectation_store_record_external(&store,
						     AUTH_EXPECTATION_REGION_POLICY,
						     1, 1, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void auth_expectation_duplicate_record_rejected(struct kunit *test)
{
	struct auth_expectation_store store = { };
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = auth_expectation_store_record_external(&store,
						     AUTH_EXPECTATION_REGION_POLICY,
						     2, 2, 0x5a5a);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

static void auth_expectation_sealed_store_rejects_records(struct kunit *test)
{
	struct auth_expectation_store store = { };
	struct auth_expectation out;
	int ret;

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    1, 1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	auth_expectation_store_seal(&store);
	KUNIT_EXPECT_TRUE(test, auth_expectation_store_sealed(&store));

	ret = auth_expectation_store_record(&store,
					    AUTH_EXPECTATION_REGION_POLICY, 1, 1);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);

	ret = auth_expectation_store_lookup(&store,
					    AUTH_EXPECTATION_REGION_GUARD_TEXT,
					    &out);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void auth_contract_test_fill_table(struct auth_transition_table *table,
					  unsigned int rows)
{
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
	/*
	 * Rows 2 and 3 share kind, trigger, caller and subject on purpose: they
	 * are the multi-root masking pair.  The trusted manager may join its
	 * container namespace, and the same join against host files is
	 * forbidden; a tuple that asks for both must not be decided by
	 * whichever row happens to come first.
	 */
	if (rows > 2)
		table->rows[2] = (struct auth_transition_row) {
			.kind = AUTH_CONTRACT_KIND_NS_JOIN,
			.subject_class = AUTH_CONTRACT_SUBJECT_MANAGER,
			.root_class = AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY,
			.trigger = AUTH_CONTRACT_TRIGGER_SETNS,
			.caller = AUTH_CONTRACT_SUBJECT_MANAGER,
			.leaf = AUTH_CONTRACT_LEAF_ALLOWED,
		};
	if (rows > 3)
		table->rows[3] = (struct auth_transition_row) {
			.kind = AUTH_CONTRACT_KIND_NS_JOIN,
			.subject_class = AUTH_CONTRACT_SUBJECT_MANAGER,
			.root_class = AUTH_CONTRACT_ROOT_HOST_FILES,
			.trigger = AUTH_CONTRACT_TRIGGER_SETNS,
			.caller = AUTH_CONTRACT_SUBJECT_MANAGER,
			.leaf = AUTH_CONTRACT_LEAF_FORBIDDEN,
		};
}

static struct auth_transition_table *
auth_contract_test_table(struct kunit *test, unsigned int rows)
{
	struct auth_transition_table *table;

	table = kunit_kzalloc(test, struct_size(table, rows, rows), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, table);

	auth_contract_test_fill_table(table, rows);

	return table;
}

/*
 * A table that is handed to the kernel outlives the case that publishes it:
 * kunit_kzalloc() memory is freed when the case ends, which would leave the
 * published pointer dangling for the cases that follow (the note case judges
 * against it).  Publishable tables therefore come from kernel memory and are
 * released when the suite exits.
 */
static struct auth_transition_table *auth_contract_test_published;

static struct auth_transition_table *
auth_contract_test_publishable_table(struct kunit *test, unsigned int rows)
{
	struct auth_transition_table *table;

	table = kzalloc(struct_size(table, rows, rows), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, table);

	auth_contract_test_fill_table(table, rows);
	auth_contract_test_published = table;

	return table;
}

static void auth_contract_test_suite_exit(struct kunit_suite *suite)
{
	kfree(auth_contract_test_published);
	auth_contract_test_published = NULL;
}

static void auth_contract_table_seal_roundtrip(struct kunit *test)
{
	struct auth_transition_table *table = auth_contract_test_table(test, 2);

	KUNIT_EXPECT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_EXPECT_TRUE(test, auth_guard_stamp_valid(&table->stamp));
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), 0);
	KUNIT_EXPECT_EQ(test,
			auth_contract_table_verify_buffer(table,
							      struct_size(table, rows, 2)),
			0);
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

	/* The template identity is validated too: zero is unset, not "any". */
	table->row_count = 1;
	table->template_id = 0;
	KUNIT_EXPECT_EQ(test, auth_contract_table_seal(table), -EINVAL);
	KUNIT_EXPECT_EQ(test, auth_contract_table_verify(table), -EINVAL);
	table->template_id = 7;

	/* The buffer entry point rejects a length that does not match. */
	table->row_count = 1;
	KUNIT_EXPECT_EQ(test,
			auth_contract_table_verify_buffer(table, sizeof(*table)),
			-EINVAL);
	KUNIT_EXPECT_EQ(test,
			auth_contract_table_verify_buffer(table,
							      struct_size(table, rows, 2)),
			-EINVAL);
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

static void auth_contract_row_accepts_extended_inventory(struct kunit *test)
{
	struct auth_transition_row row = {
		.kind = AUTH_CONTRACT_KIND_CHECKPOINT_IMPORT,
		.subject_class = AUTH_CONTRACT_SUBJECT_MANAGER,
		.root_class = AUTH_CONTRACT_ROOT_HOST_FILES,
		.trigger = AUTH_CONTRACT_TRIGGER_PROCFS_AUTHORITY,
		.caller = AUTH_CONTRACT_SUBJECT_MANAGER,
		.leaf = AUTH_CONTRACT_LEAF_FORBIDDEN,
	};

	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	row.kind = AUTH_CONTRACT_KIND_IO_URING_REGISTER;
	row.trigger = AUTH_CONTRACT_TRIGGER_IO_URING_REGISTER;
	row.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_FILES;
	row.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	/*
	 * P-11L: authority-bearing object creation/entry (nsfs namespace fds,
	 * pidfds, procfs-mediated opens, device fds).  These are entries, not
	 * fd transfers.
	 */
	row.kind = AUTH_CONTRACT_KIND_NSFS_ENTRY;
	row.trigger = AUTH_CONTRACT_TRIGGER_NSFS_OPEN;
	row.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY;
	row.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	row.kind = AUTH_CONTRACT_KIND_PIDFD_ENTRY;
	row.trigger = AUTH_CONTRACT_TRIGGER_PIDFD_OPEN;
	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_CRED;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	row.kind = AUTH_CONTRACT_KIND_PROCFS_ENTRY;
	row.trigger = AUTH_CONTRACT_TRIGGER_PROCFS_OPEN;
	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_FILES;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	/* A device entry that reaches host hardware needs a manager subject. */
	row.kind = AUTH_CONTRACT_KIND_DEVICE_ENTRY;
	row.trigger = AUTH_CONTRACT_TRIGGER_DEVICE_OPEN;
	row.subject_class = AUTH_CONTRACT_SUBJECT_MANAGER;
	row.root_class = AUTH_CONTRACT_ROOT_HOST_FILES;
	row.caller = AUTH_CONTRACT_SUBJECT_MANAGER;
	KUNIT_EXPECT_EQ(test, auth_contract_row_check(&row), 0);

	/*
	 * P-12L: registration-time registration that changes authority — io_uring
	 * personalities are registered separately from the file bundles, so they
	 * carry their own inventoried trigger.
	 */
	row.kind = AUTH_CONTRACT_KIND_IO_URING_REGISTER;
	row.trigger = AUTH_CONTRACT_TRIGGER_IO_URING_PERSONALITY;
	row.subject_class = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
	row.root_class = AUTH_CONTRACT_ROOT_CONTAINER_CRED;
	row.caller = AUTH_CONTRACT_SUBJECT_TENANT_TASK;
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
	struct auth_transition_table *table =
		auth_contract_test_publishable_table(test, 4);
	struct auth_transition_tuple *tuple;

	KUNIT_ASSERT_EQ(test, auth_contract_table_seal(table), 0);
	KUNIT_ASSERT_EQ(test, auth_contract_table_publish(table), 0);
	/*
	 * Publication transfers ownership: the kernel publishes its own copy of
	 * the table, so a caller that keeps, mutates or frees its buffer
	 * afterwards cannot change what the kernel enforces.
	 */
	KUNIT_EXPECT_PTR_NE(test, auth_contract_table_get(), table);
	KUNIT_EXPECT_EQ(test, 0,
			memcmp(auth_contract_table_get(), table,
			       struct_size(table, rows, table->row_count)));

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

	/*
	 * Round 5: the judge covers every requested root.  Row 2 allows the
	 * manager's container-namespace join and row 3 forbids the same join
	 * against host files; asking for both must deny, not take row 2.
	 */
	tuple->subject.template_id = 7;
	tuple->subject.klass = AUTH_CONTRACT_SUBJECT_MANAGER;
	tuple->kind = AUTH_CONTRACT_KIND_NS_JOIN;
	tuple->trigger = AUTH_CONTRACT_TRIGGER_SETNS;
	tuple->caller = AUTH_CONTRACT_SUBJECT_MANAGER;
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY) |
		       BIT(AUTH_CONTRACT_ROOT_HOST_FILES);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_FORBIDDEN);

	/* An undeclared root in the same tuple keeps it undeclared. */
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY) |
		       BIT(AUTH_CONTRACT_ROOT_CONTAINER_MOUNT);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_UNKNOWN);

	/* Every requested root declared is the only declared case, and the
	 * declared row is the one that counts.
	 */
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_DECLARED);
	KUNIT_EXPECT_EQ(test, auth_contract_row_count(2), 1UL);

	/* A second publication is refused. */
	KUNIT_EXPECT_EQ(test, auth_contract_table_publish(table), -EBUSY);

	/*
	 * A mutation of the caller's buffer — row 1 turned from forbidden into
	 * allowed — must not reach the live table.
	 */
	table->rows[1].leaf = AUTH_CONTRACT_LEAF_ALLOWED;
	tuple->subject.template_id = 7;
	tuple->roots = BIT(AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY);
	KUNIT_EXPECT_EQ(test, auth_contract_judge(tuple), AUTH_VERDICT_FORBIDDEN);
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

	/*
	 * Round 6: the de-duplication key carries the template, so a violation
	 * on one template is not suppressed by another template's first
	 * occurrence (the log line reports the template, so it is part of the
	 * class).
	 */
	{
		struct auth_contract_note_key a, b, c;

		auth_contract_note_key(tuple, &a);
		auth_contract_note_key(tuple, &b);
		KUNIT_EXPECT_EQ(test, a.pattern, b.pattern);
		KUNIT_EXPECT_EQ(test, a.template_id, b.template_id);

		tuple->subject.template_id += 1;
		auth_contract_note_key(tuple, &c);
		KUNIT_EXPECT_EQ(test, a.pattern, c.pattern);
		KUNIT_EXPECT_NE(test, a.template_id, c.template_id);
		tuple->subject.template_id -= 1;
	}
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
	KUNIT_CASE(auth_contract_row_accepts_extended_inventory),
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
	.suite_exit = auth_contract_test_suite_exit,
	.test_cases = auth_contract_test_cases,
};

kunit_test_suite(auth_contract_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for the authority contract");
