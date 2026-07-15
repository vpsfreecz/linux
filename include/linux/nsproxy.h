/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NSPROXY_H
#define _LINUX_NSPROXY_H

#include <linux/auth_guard.h>
#include <linux/bits.h>
#include <linux/cgroup_namespace.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

struct mnt_namespace;
struct uts_namespace;
struct ipc_namespace;
struct pid_namespace;
struct cgroup_namespace;
struct syslog_namespace;
struct tracing_namespace;
struct lsm_namespace;
struct fs_struct;
struct user_namespace;
struct css_set;

/*
 * A structure to contain pointers to all per-process
 * namespaces - fs (mount), uts, network, sysvipc, etc.
 *
 * The pid namespace is an exception -- it's accessed using
 * task_active_pid_ns.  The pid namespace here is the
 * namespace that children will use.
 *
 * 'count' is the number of tasks holding a reference.
 * The count for each namespace, then, will be the number
 * of nsproxies pointing to it, not the number of tasks.
 *
 * The nsproxy is shared by tasks which share all namespaces.
 * As soon as a single namespace is cloned or unshared, the
 * nsproxy is copied.
 */
struct nsproxy {
	refcount_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
	struct syslog_namespace *syslog_ns;
	struct tracing_namespace *tracing_ns;
#ifdef CONFIG_AUTH_GUARD
	struct auth_guard_stamp auth_guard_stamp;
	struct auth_guard_expectation_transition_state auth_guard_transition;
#endif
};
extern struct nsproxy init_nsproxy;

#ifdef CONFIG_AUTH_GUARD
#define DECLARE_AUTH_GUARD_NSPROXY_REPLACER(_member) \
	enum auth_guard_mutation_result \
	auth_guard_nsproxy_replace_##_member##_where( \
		struct nsproxy *nsproxy, \
		typeof_member(struct nsproxy, _member) replacement, \
		typeof_member(struct nsproxy, _member) *authenticated_old, \
		const char *where)
#else
#define DECLARE_AUTH_GUARD_NSPROXY_REPLACER(_member) \
	static inline enum auth_guard_mutation_result \
	auth_guard_nsproxy_replace_##_member##_where( \
		struct nsproxy *nsproxy, \
		typeof_member(struct nsproxy, _member) replacement, \
		typeof_member(struct nsproxy, _member) *authenticated_old, \
		const char *where) \
	{ \
		if (!nsproxy || !authenticated_old) \
			return AUTH_GUARD_MUTATION_REJECTED; \
		*authenticated_old = READ_ONCE(nsproxy->_member); \
		WRITE_ONCE(nsproxy->_member, replacement); \
		return AUTH_GUARD_MUTATION_APPLIED; \
	}
#endif

DECLARE_AUTH_GUARD_NSPROXY_REPLACER(mnt_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(uts_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(ipc_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(pid_ns_for_children);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(net_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(cgroup_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(syslog_ns);
DECLARE_AUTH_GUARD_NSPROXY_REPLACER(tracing_ns);

#undef DECLARE_AUTH_GUARD_NSPROXY_REPLACER

#ifdef CONFIG_AUTH_GUARD
enum auth_guard_mutation_result
auth_guard_nsproxy_replace_time_where(struct nsproxy *nsproxy,
				      struct time_namespace *replacement,
				      struct time_namespace **authenticated_old,
				      struct time_namespace **authenticated_old_for_children,
				      const char *where);
enum auth_guard_mutation_result
auth_guard_nsproxy_replace_cgroup_root_where(struct nsproxy *nsproxy,
					     struct css_set *replacement,
					     struct css_set **authenticated_old,
					     const char *where);
#else
static inline enum auth_guard_mutation_result
auth_guard_nsproxy_replace_time_where(struct nsproxy *nsproxy,
				      struct time_namespace *replacement,
				      struct time_namespace **authenticated_old,
				      struct time_namespace **authenticated_old_for_children,
				      const char *where)
{
	if (!nsproxy || !authenticated_old || !authenticated_old_for_children)
		return AUTH_GUARD_MUTATION_REJECTED;
	*authenticated_old = READ_ONCE(nsproxy->time_ns);
	*authenticated_old_for_children = READ_ONCE(nsproxy->time_ns_for_children);
	WRITE_ONCE(nsproxy->time_ns, replacement);
	WRITE_ONCE(nsproxy->time_ns_for_children, replacement);
	return AUTH_GUARD_MUTATION_APPLIED;
}

static inline enum auth_guard_mutation_result
auth_guard_nsproxy_replace_cgroup_root_where(struct nsproxy *nsproxy,
					     struct css_set *replacement,
					     struct css_set **authenticated_old,
					     const char *where)
{
	struct cgroup_namespace *cgroup_ns;

	if (!nsproxy || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	cgroup_ns = READ_ONCE(nsproxy->cgroup_ns);
	if (!cgroup_ns)
		return AUTH_GUARD_MUTATION_REJECTED;
	*authenticated_old = READ_ONCE(cgroup_ns->root_cset);
	WRITE_ONCE(cgroup_ns->root_cset, replacement);
	return AUTH_GUARD_MUTATION_APPLIED;
}
#endif

#define __auth_guard_nsproxy_replace_owned(                              \
		_nsproxy, _type, _new, _get, _replace, _put)                 \
({                                                                        \
	struct nsproxy *__ag_nsproxy = (_nsproxy);                            \
	_type __ag_new = (_new);                                              \
	_type __ag_old = NULL;                                                \
	enum auth_guard_mutation_result __ag_result;                          \
	_get(__ag_new);                                                       \
	__ag_result = _replace(__ag_nsproxy, __ag_new, &__ag_old, __func__); \
	if (__ag_result == AUTH_GUARD_MUTATION_APPLIED)                       \
		_put(__ag_old);                                                 \
	else if (__ag_result == AUTH_GUARD_MUTATION_REJECTED)                 \
		_put(__ag_new);                                                 \
	__ag_result;                                                          \
})

#define auth_guard_nsproxy_replace_owned(_nsproxy, _member, _new, _get, _put) \
	__auth_guard_nsproxy_replace_owned(                                    \
		(_nsproxy), typeof_member(struct nsproxy, _member), (_new), _get, \
		auth_guard_nsproxy_replace_##_member##_where, _put)

#define auth_guard_nsproxy_replace_time_owned(_nsproxy, _new, _get, _put)   \
({                                                                           \
	struct nsproxy *__ag_nsproxy = (_nsproxy);                               \
	struct time_namespace *__ag_new = (_new);                               \
	struct time_namespace *__ag_old = NULL;                                 \
	struct time_namespace *__ag_old_for_children = NULL;                    \
	enum auth_guard_mutation_result __ag_result;                            \
	_get(__ag_new);                                                          \
	_get(__ag_new);                                                          \
	__ag_result = auth_guard_nsproxy_replace_time_where(                     \
		__ag_nsproxy, __ag_new, &__ag_old, &__ag_old_for_children,         \
		__func__);                                                         \
	if (__ag_result == AUTH_GUARD_MUTATION_APPLIED) {                        \
		_put(__ag_old);                                                    \
		_put(__ag_old_for_children);                                       \
	} else if (__ag_result == AUTH_GUARD_MUTATION_REJECTED) {                \
		_put(__ag_new);                                                    \
		_put(__ag_new);                                                    \
	}                                                                          \
	__ag_result;                                                              \
})

#define auth_guard_nsproxy_install_owned(_nsproxy, _member, _new, _get, _put) \
	(auth_guard_nsproxy_replace_owned((_nsproxy), _member, (_new), _get, _put) == \
	 AUTH_GUARD_MUTATION_APPLIED ? 0 : -EACCES)

#define auth_guard_nsproxy_install_time_owned(_nsproxy, _new, _get, _put) \
	(auth_guard_nsproxy_replace_time_owned((_nsproxy), (_new), _get, _put) == \
	 AUTH_GUARD_MUTATION_APPLIED ? 0 : -EACCES)

#define auth_guard_nsproxy_replace_cgroup_root_owned(                       \
		_nsproxy, _new, _get, _put)                                      \
	__auth_guard_nsproxy_replace_owned(                                    \
		(_nsproxy), struct css_set *, (_new), _get,                      \
		auth_guard_nsproxy_replace_cgroup_root_where, _put)

/*
 * A checked task namespace capture keeps both guard reader reservations and
 * native task/nsproxy references until task_nsproxy_snapshot_put().  The
 * caller may acquire references to namespace members while the capture is
 * held; a failed final validation requires those member references to be
 * discarded.
 */
struct task_nsproxy_snapshot {
	struct task_struct *task;
	struct nsproxy *nsproxy;
};

/*
 * A referenced snapshot of the current namespace visibility boundary.  The
 * complete tuple is pinned under overlapping task/nsproxy, current-userns, and
 * optional syslog-owner-userns reader reservations and is retained only after
 * every final validation passes.
 */
int
get_current_namespace_boundary_owner_where(struct auth_guard_userns_boundary *boundary,
					   struct lsm_namespace **owner_lsm_ns,
					   const char *where);
int
get_current_namespace_boundary_where(struct auth_guard_userns_boundary *boundary,
				     const char *where);
void put_namespace_boundary(struct auth_guard_userns_boundary *boundary);

#define get_current_namespace_boundary(_boundary) \
	get_current_namespace_boundary_where((_boundary), __func__)
#define get_current_namespace_boundary_owner(_boundary, _owner_lsm_ns) \
	get_current_namespace_boundary_owner_where(                         \
		(_boundary), (_owner_lsm_ns), __func__)

/*
 * A structure to encompass all bits needed to install
 * a partial or complete new set of namespaces.
 *
 * If a new user namespace is requested cred will
 * point to a modifiable set of credentials. If a pointer
 * to a modifiable set is needed nsset_cred() must be
 * used and tested.
 */
struct nsset {
	unsigned flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
	struct lsm_namespace *lsm_ns;
};

struct pending_child_ns_request_payloads {
	struct auth_guard_task_syslog_request syslog;
	bool tracing;
	struct auth_guard_task_lsm_request lsm;
};

static inline struct cred *nsset_cred(struct nsset *set)
{
	if (set->flags & CLONE_NEWUSER)
		return (struct cred *)set->cred;

	return NULL;
}

/*
 * the namespaces access rules are:
 *
 *  1. only current task is allowed to change tsk->nsproxy pointer or
 *     any pointer on the nsproxy itself.  Current must hold the task_lock
 *     when changing tsk->nsproxy.
 *
 *  2. when accessing (i.e. reading) current task's namespaces - no
 *     precautions should be taken - just dereference the pointers
 *
 *  3. the access to other task namespaces is performed like this
 *     task_lock(task);
 *     nsproxy = task->nsproxy;
 *     if (nsproxy != NULL) {
 *             / *
 *               * work with the namespaces here
 *               * e.g. get the reference on one of them
 *               * /
 *     } / *
 *         * NULL task->nsproxy means that this task is
 *         * almost dead (zombie)
 *         * /
 *     task_unlock(task);
 *
 */

int copy_namespaces(u64 flags, struct task_struct *tsk);
void exit_task_namespaces(struct task_struct *tsk);
int task_nsproxy_snapshot_get_where(struct task_struct *task,
				    struct task_nsproxy_snapshot *snapshot,
				    const char *where);
bool task_nsproxy_snapshot_put_where(struct task_nsproxy_snapshot *snapshot,
				     const char *where);

#define task_nsproxy_snapshot_get(_task, _snapshot) \
	task_nsproxy_snapshot_get_where((_task), (_snapshot), __func__)
#define task_nsproxy_snapshot_put(_snapshot) \
	task_nsproxy_snapshot_put_where((_snapshot), __func__)

/*
 * Define a proc-ns getter for a mandatory nsproxy member.  The get and put
 * callbacks stay typed at each expansion, and the member reference is kept
 * only if the complete task/nsproxy snapshot remains valid.
 */
#define DEFINE_TASK_NSPROXY_MEMBER_GETTER(name, type, member, get, put) \
static struct ns_common *name(struct task_struct *task)                  \
{                                                                        \
	struct task_nsproxy_snapshot snapshot;                               \
	type *ns;                                                            \
	if (task_nsproxy_snapshot_get(task, &snapshot))                      \
		return NULL;                                                    \
	ns = READ_ONCE(snapshot.nsproxy->member);                             \
	get(ns);                                                              \
	if (!task_nsproxy_snapshot_put(&snapshot)) {                          \
		put(ns);                                                         \
		return NULL;                                                    \
	}                                                                     \
	return &ns->ns;                                                       \
}

struct nsproxy *get_current_nsproxy_checked_where(const char *where);
bool put_current_nsproxy_checked_where(struct nsproxy *nsproxy,
				       const char *where);

#define __DEFINE_CURRENT_NSPROXY_MEMBER_GETTER(storage, name, type, member,  \
					       get, put)                    \
storage type *name##_where(const char *where)                                \
{                                                                            \
	struct nsproxy *nsproxy;                                                 \
	type *ns;                                                               \
	nsproxy = get_current_nsproxy_checked_where(where);                     \
	if (IS_ERR(nsproxy))                                                    \
		return ERR_CAST(nsproxy);                                         \
	ns = get(READ_ONCE(nsproxy->member));                                   \
	if (!put_current_nsproxy_checked_where(nsproxy, where)) {               \
		put(ns);                                                          \
		return ERR_PTR(-EACCES);                                         \
	}                                                                        \
	return ns ?: ERR_PTR(-EACCES);                                          \
}

#define DEFINE_CURRENT_NSPROXY_MEMBER_GETTER(name, type, member, get, put) \
	__DEFINE_CURRENT_NSPROXY_MEMBER_GETTER(, name, type, member, get, put)

#define DEFINE_STATIC_CURRENT_NSPROXY_MEMBER_GETTER(name, type, member,     \
						    get, put)           \
	__DEFINE_CURRENT_NSPROXY_MEMBER_GETTER(static inline, name, type,       \
						 member, get, put)
void switch_task_namespaces(struct task_struct *tsk, struct nsproxy *new);
int switch_task_namespaces_checked_where(struct task_struct *tsk,
					 struct nsproxy *new,
					 const char *where);
#define switch_task_namespaces_checked(_task, _new) \
	switch_task_namespaces_checked_where((_task), (_new), __func__)
int exec_task_namespaces(void);
bool pending_child_lsm_ns_request_consumable(const struct task_struct *task,
					     const struct user_namespace *user_ns);
int consume_pending_child_ns_request_where(struct task_struct *task,
					    bool consume_lsm,
					    const char *where);
void consume_pending_child_ns_request_in_transition_where(
	struct task_struct *task, bool consume_lsm,
	struct pending_child_ns_request_payloads *payloads, const char *where);
void release_pending_child_ns_request_payloads(
	struct pending_child_ns_request_payloads *payloads);
#define consume_pending_child_ns_request(_task, _consume_lsm) \
	consume_pending_child_ns_request_where(                \
		(_task), (_consume_lsm), __func__)
#define consume_pending_child_ns_request_in_transition( \
		_task, _consume_lsm, _payloads)             \
	consume_pending_child_ns_request_in_transition_where( \
		(_task), (_consume_lsm), (_payloads), __func__)
void free_nsproxy(struct nsproxy *ns);
int unshare_nsproxy_namespaces(unsigned long, struct nsproxy **,
		struct cred *, struct fs_struct *);
int __init nsproxy_cache_init(void);

static inline void put_nsproxy(struct nsproxy *ns)
{
	if (refcount_dec_and_test(&ns->count))
		free_nsproxy(ns);
}

static inline void get_nsproxy(struct nsproxy *ns)
{
	refcount_inc(&ns->count);
}

DEFINE_FREE(put_nsproxy, struct nsproxy *, if (_T) put_nsproxy(_T))

#endif
