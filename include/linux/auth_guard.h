/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AUTH_GUARD_H
#define _LINUX_AUTH_GUARD_H

#include <linux/atomic.h>
#include <linux/auth_guard_types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/siphash.h>
#include <linux/types.h>

struct task_struct;
struct nsproxy;
struct css_set;
struct files_struct;
struct cgroup_namespace;
struct cred;
struct lsm_ctx;
struct lsm_namespace;
struct seccomp_filter;
struct syslog_namespace;
struct tracing_namespace;
struct user_namespace;

#define AUTH_GUARD_TEST_CONTEXT_PREFIX "auth_guard_test:"
#define AUTH_GUARD_TEST_CONTEXT(_command) \
	(AUTH_GUARD_TEST_CONTEXT_PREFIX _command)

enum auth_guard_check_result {
	AUTH_GUARD_CHECK_VALID,
	AUTH_GUARD_CHECK_BUSY,
	AUTH_GUARD_CHECK_CREDENTIAL_ONLY,
	AUTH_GUARD_CHECK_UNAVAILABLE,
	AUTH_GUARD_CHECK_INVALID,
};

/* Retry only a live writer; every terminal or corrupt result is final. */
#define AUTH_GUARD_RETRY_BUSY(_operation)                         \
({                                                                \
	enum auth_guard_check_result __ag_result;                    \
	do {                                                          \
		__ag_result = (_operation);                             \
		if (__ag_result != AUTH_GUARD_CHECK_BUSY)               \
			break;                                            \
		cpu_relax();                                           \
	} while (1);                                                  \
	__ag_result;                                                   \
})

/* Preserve the warning site before an unavoidable integrity fail-stop. */
#define AUTH_GUARD_FAIL_STOP_IF(_condition) \
	do { \
		if (WARN_ON_ONCE(_condition)) \
			BUG(); \
	} while (0)

#define AUTH_GUARD_FAIL_STOP_UNLESS(_condition) \
	AUTH_GUARD_FAIL_STOP_IF(!(_condition))

#define AUTH_GUARD_FAIL_STOP() \
	AUTH_GUARD_FAIL_STOP_IF(true)

/* A quarantined publication cannot be safely rolled back or returned. */
#define AUTH_GUARD_QUARANTINE_FAIL_STOP(_result)                       \
	AUTH_GUARD_FAIL_STOP_IF((_result) == AUTH_GUARD_MUTATION_QUARANTINED)

#define AUTH_GUARD_MUTATION_FAIL_STOP(_result) \
	AUTH_GUARD_FAIL_STOP_IF((_result) != AUTH_GUARD_MUTATION_APPLIED)

enum auth_guard_task_teardown_status {
	AUTH_GUARD_TASK_TEARDOWN_OPENED,
	AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED,
	AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED,
	AUTH_GUARD_TASK_TEARDOWN_SKIP_UNTRUSTED,
	AUTH_GUARD_TASK_TEARDOWN_FAILED,
};

enum auth_guard_task_seccomp_change {
	AUTH_GUARD_TASK_SECCOMP_DEAD,
	AUTH_GUARD_TASK_SECCOMP_STRICT,
	AUTH_GUARD_TASK_SECCOMP_FILTER,
	AUTH_GUARD_TASK_SECCOMP_SYNC,
	AUTH_GUARD_TASK_SECCOMP_DETACH,
};

struct auth_guard_task_seccomp_state {
	unsigned long mode;
	bool no_new_privs;
	int filter_count;
	struct seccomp_filter *filter;
};

static inline bool
auth_guard_stamp_published_acquire(const struct auth_guard_stamp *stamp)
{
	/* Pair with auth_guard_stamp_publish_release(). */
	return smp_load_acquire(&stamp->seal);
}

static inline struct auth_guard_stamp
auth_guard_stamp_load_acquire(const struct auth_guard_stamp *source)
{
	struct auth_guard_stamp stamp;

	/* Pair with auth_guard_stamp_publish_release(). */
	stamp.seal = smp_load_acquire(&source->seal);
	stamp.generation = READ_ONCE(source->generation);
	stamp.nonce = READ_ONCE(source->nonce);
	return stamp;
}

static inline bool
auth_guard_stamp_equal(const struct auth_guard_stamp *left,
			 const struct auth_guard_stamp *right)
{
	return READ_ONCE(left->generation) == READ_ONCE(right->generation) &&
		READ_ONCE(left->nonce) == READ_ONCE(right->nonce) &&
		READ_ONCE(left->seal) == READ_ONCE(right->seal);
}

static inline bool auth_guard_stamp_empty(const struct auth_guard_stamp *stamp)
{
	return !READ_ONCE(stamp->generation) && !READ_ONCE(stamp->nonce) &&
		!READ_ONCE(stamp->seal);
}

static inline bool auth_guard_stamp_valid(const struct auth_guard_stamp *stamp)
{
	return stamp && READ_ONCE(stamp->generation) && READ_ONCE(stamp->nonce) &&
		READ_ONCE(stamp->seal);
}

static inline void
auth_guard_stamp_publish_release(struct auth_guard_stamp *destination,
				 const struct auth_guard_stamp *stamp)
{
	WRITE_ONCE(destination->generation, stamp->generation);
	WRITE_ONCE(destination->nonce, stamp->nonce);
	/* Publish all metadata before readers acquire the seal. */
	smp_store_release(&destination->seal, stamp->seal);
}

static inline void auth_guard_stamp_clear(struct auth_guard_stamp *stamp)
{
	WRITE_ONCE(stamp->generation, 0);
	WRITE_ONCE(stamp->nonce, 0);
	/* Publish cleared metadata before readers observe an empty seal. */
	smp_store_release(&stamp->seal, 0);
}

struct auth_guard_userns_boundary {
	struct syslog_namespace *syslog_ns;
	struct tracing_namespace *tracing_ns;
	struct lsm_namespace *lsm_ns;
};

#ifdef CONFIG_AUTH_GUARD_CORE
enum auth_guard_mutation_result auth_guard_task_replace_files_where(
	struct task_struct *task, struct files_struct *replacement,
	struct files_struct **authenticated_old, const char *where);
enum auth_guard_mutation_result auth_guard_task_set_no_new_privs_where(
	struct task_struct *task, const char *where);
enum auth_guard_mutation_result auth_guard_task_replace_syslog_request_where(
	struct task_struct *task,
	const struct auth_guard_task_syslog_request *replacement,
	struct auth_guard_task_syslog_request *authenticated_old,
	const char *where);
enum auth_guard_mutation_result auth_guard_task_replace_tracing_request_where(
	struct task_struct *task, bool replacement, bool *authenticated_old,
	const char *where);
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
enum auth_guard_mutation_result auth_guard_task_replace_lsm_request_where(
	struct task_struct *task,
	const struct auth_guard_task_lsm_request *replacement,
	struct auth_guard_task_lsm_request *authenticated_old,
	const char *where);
#endif
#endif

#ifdef CONFIG_AUTH_GUARD_CORE
struct auth_guard_domain {
	const char *name;
	siphash_key_t key;
	bool seeded;
};

#define AUTH_GUARD_DOMAIN(_name)			\
	{						\
		.name = _name,				\
	}

void __init auth_guard_init_domain(struct auth_guard_domain *domain);
bool auth_guard_enabled(void);
u64 auth_guard_next_generation(struct auth_guard_domain *domain);
u64 auth_guard_nonce(void);
u64 auth_guard_ptr(const void *ptr);
u64 auth_guard_seal(struct auth_guard_domain *domain, const void *data,
		    size_t len);
void auth_guard_fail(const struct auth_guard_domain *domain, const char *where,
		     const char *what, const void *object);
#else
struct auth_guard_domain {
};

#define AUTH_GUARD_DOMAIN(...)	{}

static inline void __init auth_guard_init_domain(struct auth_guard_domain *domain)
{
}

static inline bool auth_guard_enabled(void)
{
	return false;
}

static inline u64 auth_guard_next_generation(struct auth_guard_domain *domain)
{
	return 0;
}

static inline u64 auth_guard_nonce(void)
{
	return 0;
}

static inline u64 auth_guard_ptr(const void *ptr)
{
	return (u64)(unsigned long)ptr;
}

static inline u64 auth_guard_seal(struct auth_guard_domain *domain,
				  const void *data, size_t len)
{
	return 0;
}

static inline void auth_guard_fail(const struct auth_guard_domain *domain,
				   const char *where, const char *what,
				   const void *object)
{
}
#endif

static inline bool auth_guard_layer_enabled(bool active)
{
	return active && auth_guard_enabled();
}

/* The caller computes the seal and publishes the completed stamp. */
static inline struct auth_guard_stamp
auth_guard_stamp_fresh(struct auth_guard_domain *domain)
{
	return (struct auth_guard_stamp) {
		.generation = auth_guard_next_generation(domain),
		.nonce = auth_guard_nonce(),
		.seal = 0,
	};
}

#define AUTH_GUARD_STUB_TRUE(_name, _args) \
	static inline bool _name _args { return true; }
#define AUTH_GUARD_STUB_FALSE(_name, _args) \
	static inline bool _name _args { return false; }
#define AUTH_GUARD_STUB_VOID(_name, _args) \
	static inline void _name _args { }
#define AUTH_GUARD_STUB_VALID(_name, _args) \
	static inline enum auth_guard_check_result _name _args \
	{ return AUTH_GUARD_CHECK_VALID; }

#ifdef CONFIG_CRED_GUARD
void __init auth_guard_task_transition_enable(void);
enum auth_guard_check_result
auth_guard_task_transition_reader_begin_where(struct task_struct *task,
					       const char *where);
bool auth_guard_task_transition_reader_stable_where(struct task_struct *task,
						     const char *where);
bool auth_guard_task_transition_reader_end_where(struct task_struct *task,
						  const char *where);
enum auth_guard_check_result
auth_guard_task_transition_reserve_teardown_where(struct task_struct *task,
						  const char *where);
bool auth_guard_task_transition_publish_where(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where);
bool auth_guard_task_transition_verify_where(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where);
bool auth_guard_task_transition_cred_published_where(
	struct task_struct *task, const struct auth_guard_stamp *old_stamp,
	const struct auth_guard_stamp *new_stamp, bool retain,
	bool *coordinator_open, const char *where);
bool auth_guard_task_expect_creds_where(
	struct task_struct *task, const struct cred *new_real,
	const struct cred *new_subj, const struct auth_guard_stamp *new_stamp,
	struct auth_guard_stamp *old_stamp, const struct cred **old_real,
	const struct cred **old_subj,
	const char *where);
void auth_guard_task_transition_quarantine(struct task_struct *task);
bool auth_guard_task_transition_close_where(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where);
bool auth_guard_task_transition_terminal_close_where(struct task_struct *task,
						     const char *where);
bool auth_guard_task_first_seal_begin_where(struct task_struct *task,
					    const char *where);
void auth_guard_task_first_seal_complete(struct task_struct *task, bool valid);
#else
static inline void auth_guard_task_transition_enable(void) { }
AUTH_GUARD_STUB_VALID(auth_guard_task_transition_reader_begin_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_reader_stable_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_reader_end_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_VALID(auth_guard_task_transition_reserve_teardown_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_publish_where,
		(struct task_struct *task,
		 enum auth_guard_transition_anchor anchor,
		 const struct auth_guard_stamp *stamp, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_verify_where,
		(struct task_struct *task,
		 enum auth_guard_transition_anchor anchor,
		 const struct auth_guard_stamp *stamp, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_cred_published_where,
		(struct task_struct *task,
		 const struct auth_guard_stamp *old_stamp,
		 const struct auth_guard_stamp *new_stamp, bool retain,
		 bool *coordinator_open, const char *where))
static inline bool auth_guard_task_expect_creds_where(
	struct task_struct *task, const struct cred *new_real,
	const struct cred *new_subj, const struct auth_guard_stamp *new_stamp,
	struct auth_guard_stamp *old_stamp, const struct cred **old_real,
	const struct cred **old_subj,
	const char *where)
{
	return true;
}

AUTH_GUARD_STUB_VOID(auth_guard_task_transition_quarantine,
	(struct task_struct *task))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_close_where,
		(struct task_struct *task,
		 enum auth_guard_transition_anchor anchor,
		 const struct auth_guard_stamp *stamp, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_terminal_close_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_first_seal_begin_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_VOID(auth_guard_task_first_seal_complete,
	(struct task_struct *task, bool valid))
#endif

#ifdef CONFIG_AUTH_GUARD
void __init auth_guard_enable(void);
bool auth_guard_task_init_check_where(struct task_struct *task,
				      const char *where);
void auth_guard_task_mark_unpublished_where(struct task_struct *task,
					    const char *where);
bool auth_guard_task_unpublished_where(struct task_struct *task,
				       const char *where);
bool auth_guard_task_init_where(struct task_struct *task, const char *where);
bool auth_guard_task_begin_transition_where(struct task_struct *task,
					    const char *where);
bool auth_guard_task_begin_transition_wait_where(struct task_struct *task,
						 const char *where);
enum auth_guard_mutation_result
auth_guard_task_replace_files_in_transition_where(
	struct task_struct *task, struct files_struct *replacement,
	struct files_struct **authenticated_old, const char *where);
enum auth_guard_mutation_result
auth_guard_task_replace_nsproxy_in_transition_where(
	struct task_struct *task, struct nsproxy *replacement,
	struct nsproxy **authenticated_old, const char *where);
enum auth_guard_mutation_result
auth_guard_task_replace_syslog_request_in_transition_where(
	struct task_struct *task,
	const struct auth_guard_task_syslog_request *replacement,
	struct auth_guard_task_syslog_request *authenticated_old,
	const char *where);
enum auth_guard_mutation_result
auth_guard_task_replace_tracing_request_in_transition_where(
	struct task_struct *task, bool replacement, bool *authenticated_old,
	const char *where);
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
enum auth_guard_mutation_result
auth_guard_task_replace_lsm_request_in_transition_where(
	struct task_struct *task,
	const struct auth_guard_task_lsm_request *replacement,
	struct auth_guard_task_lsm_request *authenticated_old,
	const char *where);
#endif
#ifdef CONFIG_CGROUPS
bool auth_guard_task_expect_cgroups_in_transition_where(
	struct task_struct *task, struct css_set *authenticated_current,
	struct css_set *replacement, const char *where);
#endif
#ifdef CONFIG_SECCOMP
bool auth_guard_task_expect_seccomp_in_transition_where(
	struct task_struct *task, enum auth_guard_task_seccomp_change change,
	const struct auth_guard_task_seccomp_state *expected,
	const char *where);
#endif
bool auth_guard_task_expect_cred_detach_in_transition_where(
	struct task_struct *task, const struct cred *expected_real,
	const struct cred *expected_subj, const char *where);
bool auth_guard_task_validate_transition_result_where(
	struct task_struct *task, const char *where);
void auth_guard_task_exit_where(struct task_struct *task, const char *where);
enum auth_guard_task_teardown_status
auth_guard_task_begin_teardown_transition_where(struct task_struct *task,
						const char *where);
bool auth_guard_task_validate_teardown_where(
	struct task_struct *task, enum auth_guard_task_teardown_status status,
	const char *where);
bool auth_guard_task_complete_teardown_where(
	struct task_struct *task, enum auth_guard_task_teardown_status status,
	bool old_valid, bool exact, bool final, const char *where);
bool auth_guard_task_transition_open_where(struct task_struct *task,
					   const char *where);
void auth_guard_task_abort_transition_where(struct task_struct *task,
					    const char *where);
bool auth_guard_task_finish_transition_where(struct task_struct *task,
					     const char *where);
enum auth_guard_check_result
auth_guard_task_check_status_where(struct task_struct *task,
				   const char *where);
enum auth_guard_check_result
auth_guard_task_snapshot_begin_where(struct task_struct *task,
				     const char *where);
bool auth_guard_task_snapshot_end_where(struct task_struct *task,
					const char *where);
bool auth_guard_task_check_where(struct task_struct *task, const char *where);
enum auth_guard_check_result
auth_guard_task_check_real_cred_where(struct task_struct *task,
				      const struct cred *expected,
				      const char *where);
bool auth_guard_task_check_wait_where(struct task_struct *task,
				      const char *where);
bool auth_guard_task_is_sealed(struct task_struct *task);
bool auth_guard_current_where(const char *where);
bool auth_guard_userns_boundary_init_where(struct user_namespace *user_ns,
					   const char *where);
bool auth_guard_userns_boundary_begin_transition_where(
	struct user_namespace *user_ns,
	const struct auth_guard_userns_boundary *expected, const char *where);
bool auth_guard_userns_boundary_finish_transition_where(
	struct user_namespace *user_ns,
	const struct auth_guard_userns_boundary *expected, const char *where);
bool auth_guard_userns_boundary_abort_transition_where(
	struct user_namespace *user_ns,
	const struct auth_guard_userns_boundary *expected, const char *where);
bool auth_guard_userns_boundary_check_where(
	const struct user_namespace *user_ns, const char *where);
enum auth_guard_check_result
auth_guard_userns_boundary_snapshot_begin_where(
	const struct user_namespace *user_ns, const char *where);
bool auth_guard_userns_boundary_snapshot_end_where(
	const struct user_namespace *user_ns, const char *where);
bool auth_guard_userns_boundary_destroy_begin_where(
	struct user_namespace *user_ns,
	const struct auth_guard_userns_boundary *expected, const char *where);
bool auth_guard_userns_boundary_destroy_complete_where(
	struct user_namespace *user_ns, bool old_valid, bool exact,
	const char *where);
bool auth_guard_nsproxy_init_where(struct nsproxy *nsproxy, const char *where);
enum auth_guard_check_result
auth_guard_nsproxy_snapshot_begin_where(const struct nsproxy *nsproxy,
					const char *where);
bool auth_guard_nsproxy_snapshot_end_where(const struct nsproxy *nsproxy,
					   const char *where);
bool auth_guard_nsproxy_destroy_begin_where(const struct nsproxy *nsproxy,
					    const char *where);
bool auth_guard_nsproxy_check_where(const struct nsproxy *nsproxy,
				    const char *where);
#ifdef CONFIG_CGROUPS
void __init auth_guard_cgroup_enable(void);
bool auth_guard_cgroup_ns_root_init_where(struct cgroup_namespace *ns,
					       const char *where);
bool auth_guard_cgroup_ns_root_check_where(const struct cgroup_namespace *ns,
						const char *where);
bool auth_guard_cgroup_ns_root_destroy_complete_where(
	struct cgroup_namespace *ns, const struct css_set *expected,
	bool old_valid, bool exact, const char *where);
bool auth_guard_css_set_init_where(struct css_set *cset, const char *where);
bool auth_guard_css_set_check_where(const struct css_set *cset,
				    const char *where);
#endif
#else
static inline void __init auth_guard_enable(void) { }
AUTH_GUARD_STUB_TRUE(auth_guard_task_init_check_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_VOID(auth_guard_task_mark_unpublished_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_unpublished_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_init_where,
	(struct task_struct *task, const char *where))
#ifdef CONFIG_CGROUPS
AUTH_GUARD_STUB_TRUE(auth_guard_task_expect_cgroups_in_transition_where,
	(struct task_struct *task, struct css_set *authenticated_current,
	 struct css_set *replacement, const char *where))
#endif
#ifdef CONFIG_SECCOMP
AUTH_GUARD_STUB_TRUE(auth_guard_task_expect_seccomp_in_transition_where,
	(struct task_struct *task, enum auth_guard_task_seccomp_change change,
	 const struct auth_guard_task_seccomp_state *expected,
	 const char *where))
#endif
AUTH_GUARD_STUB_TRUE(auth_guard_task_expect_cred_detach_in_transition_where,
	(struct task_struct *task, const struct cred *expected_real,
	 const struct cred *expected_subj, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_validate_transition_result_where,
	(struct task_struct *task, const char *where))
#ifdef CONFIG_CRED_GUARD
bool auth_guard_task_begin_transition_where(struct task_struct *task,
					    const char *where);
bool auth_guard_task_begin_transition_wait_where(struct task_struct *task,
						 const char *where);
bool auth_guard_task_transition_open_where(struct task_struct *task,
					   const char *where);
void auth_guard_task_abort_transition_where(struct task_struct *task,
					    const char *where);
bool auth_guard_task_finish_transition_where(struct task_struct *task,
					     const char *where);
#else
AUTH_GUARD_STUB_TRUE(auth_guard_task_begin_transition_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_begin_transition_wait_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_transition_open_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_VOID(auth_guard_task_abort_transition_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_finish_transition_where,
	(struct task_struct *task, const char *where))
#endif
AUTH_GUARD_STUB_VOID(auth_guard_task_exit_where,
	(struct task_struct *task, const char *where))
static inline enum auth_guard_task_teardown_status
auth_guard_task_begin_teardown_transition_where(struct task_struct *task,
						  const char *where)
{
	return AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED;
}

AUTH_GUARD_STUB_TRUE(auth_guard_task_validate_teardown_where,
	(struct task_struct *task, enum auth_guard_task_teardown_status status,
	 const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_complete_teardown_where,
	(struct task_struct *task, enum auth_guard_task_teardown_status status,
	 bool old_valid, bool exact, bool final, const char *where))
AUTH_GUARD_STUB_VALID(auth_guard_task_check_status_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_VALID(auth_guard_task_snapshot_begin_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_snapshot_end_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_task_check_where,
	(struct task_struct *task, const char *where))
#ifdef CONFIG_CRED_GUARD
enum auth_guard_check_result
auth_guard_task_check_real_cred_where(struct task_struct *task,
				      const struct cred *expected,
				      const char *where);
#else
AUTH_GUARD_STUB_VALID(auth_guard_task_check_real_cred_where,
	(struct task_struct *task, const struct cred *expected,
	 const char *where))
#endif
AUTH_GUARD_STUB_TRUE(auth_guard_task_check_wait_where,
	(struct task_struct *task, const char *where))
AUTH_GUARD_STUB_FALSE(auth_guard_task_is_sealed,
	(struct task_struct *task))
AUTH_GUARD_STUB_TRUE(auth_guard_current_where, (const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_init_where,
	(struct user_namespace *user_ns, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_begin_transition_where,
	(struct user_namespace *user_ns,
	 const struct auth_guard_userns_boundary *expected, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_finish_transition_where,
	(struct user_namespace *user_ns,
	 const struct auth_guard_userns_boundary *expected, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_abort_transition_where,
	(struct user_namespace *user_ns,
	 const struct auth_guard_userns_boundary *expected, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_check_where,
	(const struct user_namespace *user_ns, const char *where))
AUTH_GUARD_STUB_VALID(auth_guard_userns_boundary_snapshot_begin_where,
	(const struct user_namespace *user_ns, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_snapshot_end_where,
	(const struct user_namespace *user_ns, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_userns_boundary_destroy_begin_where,
	(struct user_namespace *user_ns,
	 const struct auth_guard_userns_boundary *expected, const char *where))
static inline bool auth_guard_userns_boundary_destroy_complete_where(
	struct user_namespace *user_ns, bool old_valid, bool exact,
	const char *where)
{
	return old_valid && exact;
}

AUTH_GUARD_STUB_TRUE(auth_guard_nsproxy_init_where,
	(struct nsproxy *nsproxy, const char *where))
AUTH_GUARD_STUB_VALID(auth_guard_nsproxy_snapshot_begin_where,
	(const struct nsproxy *nsproxy, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_nsproxy_snapshot_end_where,
	(const struct nsproxy *nsproxy, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_nsproxy_destroy_begin_where,
	(const struct nsproxy *nsproxy, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_nsproxy_check_where,
	(const struct nsproxy *nsproxy, const char *where))
#endif

#ifndef CONFIG_AUTH_GUARD
#define __AUTH_GUARD_NATIVE_MUTATION(_where, _valid, ...) \
({ \
	const char *__ag_native_where = (_where); \
	enum auth_guard_mutation_result __ag_native_result = \
		AUTH_GUARD_MUTATION_REJECTED; \
	(void)__ag_native_where; \
	if (_valid) { \
		__VA_ARGS__; \
		__ag_native_result = AUTH_GUARD_MUTATION_APPLIED; \
	} \
	__ag_native_result; \
})
#define __AUTH_GUARD_NATIVE_FILES(_task, _new, _old, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	struct files_struct *__ag_new = (_new); \
	struct files_struct **__ag_old = (_old); \
	__AUTH_GUARD_NATIVE_MUTATION((_where), __ag_task && __ag_old, \
		task_lock(__ag_task); \
		*__ag_old = __ag_task->files; \
		__ag_task->files = __ag_new; \
		task_unlock(__ag_task)); \
})
#define __AUTH_GUARD_NATIVE_EDGE(_task, _member, _new, _old, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	__auto_type __ag_new = (_new); \
	__auto_type __ag_old = (_old); \
	__AUTH_GUARD_NATIVE_MUTATION((_where), __ag_task && __ag_old, \
		*__ag_old = __ag_task->_member; \
		__ag_task->_member = __ag_new); \
})
#define __AUTH_GUARD_NATIVE_NO_NEW_PRIVS(_task, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	__AUTH_GUARD_NATIVE_MUTATION((_where), __ag_task, \
		task_set_no_new_privs(__ag_task)); \
})
#define __AUTH_GUARD_NATIVE_SYSLOG_REQUEST(_task, _new, _old, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	const struct auth_guard_task_syslog_request *__ag_new = (_new); \
	struct auth_guard_task_syslog_request *__ag_old = (_old); \
	struct auth_guard_task_syslog_request __ag_replacement; \
	const char *__ag_where = (_where); \
	__AUTH_GUARD_NATIVE_MUTATION( \
		__ag_where, __ag_task && __ag_new && __ag_old, \
		__ag_replacement = *__ag_new; \
		*__ag_old = (struct auth_guard_task_syslog_request) { \
			.enabled = __ag_task->syslog_ns_for_child, \
			.name = __ag_task->syslog_ns_for_child_name, \
			.name_len = __ag_task->syslog_ns_for_child_name_len, \
		}; \
		__ag_task->syslog_ns_for_child = __ag_replacement.enabled; \
		__ag_task->syslog_ns_for_child_name = __ag_replacement.name; \
		__ag_task->syslog_ns_for_child_name_len = __ag_replacement.name_len); \
})
#define __AUTH_GUARD_NATIVE_TRACING_REQUEST(_task, _new, _old, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	bool *__ag_old = (_old); \
	const char *__ag_where = (_where); \
	bool __ag_new = (_new); \
	__AUTH_GUARD_NATIVE_MUTATION(__ag_where, __ag_task && __ag_old, \
		*__ag_old = __ag_task->tracing_ns_for_child; \
		__ag_task->tracing_ns_for_child = __ag_new); \
})
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
#define __AUTH_GUARD_NATIVE_LSM_REQUEST(_task, _new, _old, _where) \
({ \
	struct task_struct *__ag_task = (_task); \
	const struct auth_guard_task_lsm_request *__ag_new = (_new); \
	struct auth_guard_task_lsm_request *__ag_old = (_old); \
	struct auth_guard_task_lsm_request __ag_replacement; \
	const char *__ag_where = (_where); \
	__AUTH_GUARD_NATIVE_MUTATION( \
		__ag_where, __ag_task && __ag_new && __ag_old, \
		__ag_replacement = *__ag_new; \
		*__ag_old = (struct auth_guard_task_lsm_request) { \
			.enabled = __ag_task->lsm_ns_for_child, \
			.lsmid = __ag_task->lsm_ns_for_child_lsmid, \
			.ctx = __ag_task->lsm_ns_for_child_ctx, \
			.ctx_len = __ag_task->lsm_ns_for_child_ctx_len, \
		}; \
		__ag_task->lsm_ns_for_child = __ag_replacement.enabled; \
		__ag_task->lsm_ns_for_child_lsmid = __ag_replacement.lsmid; \
		__ag_task->lsm_ns_for_child_ctx = __ag_replacement.ctx; \
		__ag_task->lsm_ns_for_child_ctx_len = __ag_replacement.ctx_len); \
})
#endif

#define auth_guard_task_replace_files_in_transition_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_EDGE((_task), files, (_new), (_old), (_where))
#define auth_guard_task_replace_nsproxy_in_transition_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_EDGE((_task), nsproxy, (_new), (_old), (_where))
#define auth_guard_task_replace_syslog_request_in_transition_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_SYSLOG_REQUEST((_task), (_new), (_old), (_where))
#define auth_guard_task_replace_tracing_request_in_transition_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_TRACING_REQUEST((_task), (_new), (_old), (_where))
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
#define auth_guard_task_replace_lsm_request_in_transition_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_LSM_REQUEST((_task), (_new), (_old), (_where))
#endif

#ifndef CONFIG_AUTH_GUARD_CORE
#define auth_guard_task_replace_files_where(_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_FILES( \
		(_task), (_new), (_old), (_where))
#define auth_guard_task_set_no_new_privs_where(_task, _where) \
	__AUTH_GUARD_NATIVE_NO_NEW_PRIVS((_task), (_where))
#define auth_guard_task_replace_syslog_request_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_SYSLOG_REQUEST( \
		(_task), (_new), (_old), (_where))
#define auth_guard_task_replace_tracing_request_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_TRACING_REQUEST( \
		(_task), (_new), (_old), (_where))
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
#define auth_guard_task_replace_lsm_request_where( \
		_task, _new, _old, _where) \
	__AUTH_GUARD_NATIVE_LSM_REQUEST( \
		(_task), (_new), (_old), (_where))
#endif
#endif
#endif

#if !defined(CONFIG_AUTH_GUARD) || !defined(CONFIG_CGROUPS)
static inline void __init auth_guard_cgroup_enable(void) { }
AUTH_GUARD_STUB_TRUE(auth_guard_cgroup_ns_root_init_where,
	(struct cgroup_namespace *ns, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_cgroup_ns_root_check_where,
	(const struct cgroup_namespace *ns, const char *where))
static inline bool auth_guard_cgroup_ns_root_destroy_complete_where(
	struct cgroup_namespace *ns, const struct css_set *expected,
	bool old_valid, bool exact, const char *where)
{
	return old_valid && exact;
}

AUTH_GUARD_STUB_TRUE(auth_guard_css_set_init_where,
	(struct css_set *cset, const char *where))
AUTH_GUARD_STUB_TRUE(auth_guard_css_set_check_where,
	(const struct css_set *cset, const char *where))
#endif

#undef AUTH_GUARD_STUB_VALID
#undef AUTH_GUARD_STUB_VOID
#undef AUTH_GUARD_STUB_FALSE
#undef AUTH_GUARD_STUB_TRUE

#define auth_guard_task_init_check(_task) \
	auth_guard_task_init_check_where((_task), __func__)
#define auth_guard_task_mark_unpublished(_task) \
	auth_guard_task_mark_unpublished_where((_task), __func__)
#define auth_guard_task_unpublished(_task) \
	auth_guard_task_unpublished_where((_task), __func__)
#define auth_guard_task_init(_task) \
	auth_guard_task_init_where((_task), __func__)
#define auth_guard_task_begin_transition(_task) \
	auth_guard_task_begin_transition_where((_task), __func__)
#define auth_guard_task_exit(_task) \
	auth_guard_task_exit_where((_task), __func__)
#define auth_guard_task_begin_teardown_transition(_task) \
	auth_guard_task_begin_teardown_transition_where((_task), __func__)
#define auth_guard_task_validate_teardown(_task, _status) \
	auth_guard_task_validate_teardown_where((_task), (_status), __func__)
#define auth_guard_task_complete_teardown(_task, _status, _valid, _exact, _final) \
	auth_guard_task_complete_teardown_where((_task), (_status), (_valid), \
					  (_exact), (_final), __func__)
#define auth_guard_task_transition_open(_task) \
	auth_guard_task_transition_open_where((_task), __func__)
#define auth_guard_task_abort_transition(_task) \
	auth_guard_task_abort_transition_where((_task), __func__)
#define auth_guard_task_finish_transition(_task) \
	auth_guard_task_finish_transition_where((_task), __func__)
#define auth_guard_task_replace_files_in_transition(_task, _new, _old) \
	auth_guard_task_replace_files_in_transition_where( \
		(_task), (_new), (_old), __func__)
#define auth_guard_task_replace_nsproxy_in_transition(_task, _new, _old) \
	auth_guard_task_replace_nsproxy_in_transition_where( \
		(_task), (_new), (_old), __func__)
#define auth_guard_task_replace_syslog_request_in_transition( \
		_task, _new, _old) \
	auth_guard_task_replace_syslog_request_in_transition_where( \
		(_task), (_new), (_old), __func__)
#define auth_guard_task_replace_tracing_request_in_transition( \
		_task, _new, _old) \
	auth_guard_task_replace_tracing_request_in_transition_where( \
		(_task), (_new), (_old), __func__)
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
#define auth_guard_task_replace_lsm_request_in_transition( \
		_task, _new, _old) \
	auth_guard_task_replace_lsm_request_in_transition_where( \
		(_task), (_new), (_old), __func__)
#endif
#ifdef CONFIG_CGROUPS
#define auth_guard_task_expect_cgroups_in_transition(_task, _old, _new) \
	auth_guard_task_expect_cgroups_in_transition_where( \
		(_task), (_old), (_new), __func__)
#endif
#ifdef CONFIG_SECCOMP
#define auth_guard_task_expect_seccomp_in_transition(_task, _change, _new) \
	auth_guard_task_expect_seccomp_in_transition_where( \
		(_task), (_change), (_new), __func__)
#endif
#define auth_guard_task_expect_cred_detach_in_transition( \
		_task, _real, _subj) \
	auth_guard_task_expect_cred_detach_in_transition_where( \
		(_task), (_real), (_subj), __func__)
#define auth_guard_task_validate_transition_result(_task) \
	auth_guard_task_validate_transition_result_where((_task), __func__)
#define auth_guard_task_replace_files(_task, _new, _old) \
	auth_guard_task_replace_files_where((_task), (_new), (_old), __func__)
#define auth_guard_task_set_no_new_privs(_task) \
	auth_guard_task_set_no_new_privs_where((_task), __func__)
#define auth_guard_task_replace_syslog_request(_task, _new, _old) \
	auth_guard_task_replace_syslog_request_where( \
		(_task), (_new), (_old), __func__)
#define auth_guard_task_replace_tracing_request(_task, _new, _old) \
	auth_guard_task_replace_tracing_request_where( \
		(_task), (_new), (_old), __func__)
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
#define auth_guard_task_replace_lsm_request(_task, _new, _old) \
	auth_guard_task_replace_lsm_request_where( \
		(_task), (_new), (_old), __func__)
#endif
#define auth_guard_task_check_status(_task) \
	auth_guard_task_check_status_where((_task), __func__)
#define auth_guard_task_snapshot_begin(_task) \
	auth_guard_task_snapshot_begin_where((_task), __func__)
#define auth_guard_task_snapshot_end(_task) \
	auth_guard_task_snapshot_end_where((_task), __func__)
#define auth_guard_task_check(_task) \
	auth_guard_task_check_where((_task), __func__)
#define auth_guard_task_check_real_cred(_task, _expected) \
	auth_guard_task_check_real_cred_where((_task), (_expected), __func__)
#define auth_guard_task_check_wait(_task) \
	auth_guard_task_check_wait_where((_task), __func__)
#define auth_guard_current() auth_guard_current_where(__func__)
#define auth_guard_userns_boundary_init(_user_ns) \
	auth_guard_userns_boundary_init_where((_user_ns), __func__)
#define auth_guard_userns_boundary_check(_user_ns) \
	auth_guard_userns_boundary_check_where((_user_ns), __func__)
#define auth_guard_userns_boundary_snapshot_begin(_user_ns) \
	auth_guard_userns_boundary_snapshot_begin_where((_user_ns), __func__)
#define auth_guard_userns_boundary_snapshot_end(_user_ns) \
	auth_guard_userns_boundary_snapshot_end_where((_user_ns), __func__)
#define auth_guard_userns_boundary_destroy_begin(_user_ns, _expected) \
	auth_guard_userns_boundary_destroy_begin_where((_user_ns), (_expected), \
						       __func__)
#define auth_guard_userns_boundary_destroy_complete(_user_ns, _valid, _exact) \
	auth_guard_userns_boundary_destroy_complete_where((_user_ns), (_valid), \
							  (_exact), __func__)
#define auth_guard_nsproxy_init(_nsproxy) \
	auth_guard_nsproxy_init_where((_nsproxy), __func__)
#define auth_guard_nsproxy_snapshot_begin(_nsproxy) \
	auth_guard_nsproxy_snapshot_begin_where((_nsproxy), __func__)
#define auth_guard_nsproxy_snapshot_end(_nsproxy) \
	auth_guard_nsproxy_snapshot_end_where((_nsproxy), __func__)
#define auth_guard_nsproxy_destroy_begin(_nsproxy) \
	auth_guard_nsproxy_destroy_begin_where((_nsproxy), __func__)
#define auth_guard_nsproxy_check(_nsproxy) \
	auth_guard_nsproxy_check_where((_nsproxy), __func__)
#define auth_guard_cgroup_ns_root_init(_ns) \
	auth_guard_cgroup_ns_root_init_where((_ns), __func__)
#define auth_guard_cgroup_ns_root_check(_ns) \
	auth_guard_cgroup_ns_root_check_where((_ns), __func__)
#define auth_guard_cgroup_ns_root_destroy_complete(_ns, _expected, _valid, _exact) \
	auth_guard_cgroup_ns_root_destroy_complete_where((_ns), (_expected), \
							(_valid), (_exact), __func__)
#define auth_guard_css_set_init(_cset) \
	auth_guard_css_set_init_where((_cset), __func__)
#define auth_guard_css_set_check(_cset) \
	auth_guard_css_set_check_where((_cset), __func__)

#ifdef CONFIG_AUTH_GUARD_TEST
int cred_guard_test_corrupt_current(const char *what);
int selinux_cred_guard_test_corrupt_current(const char *what);
#endif

#endif /* _LINUX_AUTH_GUARD_H */
