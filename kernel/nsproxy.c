// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2006 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 *
 *  Jun 2006 - namespaces support
 *             OpenVZ, SWsoft Inc.
 *             Pavel Emelianov <xemul@openvz.org>
 */

#include <linux/auth_guard.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/mnt_namespace.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/syslog_namespace.h>
#include <linux/tracing_namespace.h>
#include <linux/lsm_namespace.h>
#include <linux/proc_ns.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#include <linux/security.h>

static struct kmem_cache *nsproxy_cachep;

static void free_nsproxy_unpublished(struct nsproxy *ns);
static void free_nsproxy_rejected(struct nsproxy *ns);

static int
namespace_boundary_snapshot_error(enum auth_guard_check_result result)
{
	return result == AUTH_GUARD_CHECK_BUSY ? -EAGAIN : -EACCES;
}

int get_current_namespace_boundary_owner_where(struct auth_guard_userns_boundary *boundary,
					       struct lsm_namespace **owner_lsm_ns,
					       const char *where)
{
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	struct auth_guard_userns_boundary owner_boundary;
	struct auth_guard_userns_boundary user_boundary;
	struct user_namespace *owner_user_ns = NULL;
	bool owner_reserved = false;
#endif
	struct user_namespace *user_ns = NULL;
	const struct cred *cred;
	struct nsproxy *nsproxy;
	enum auth_guard_check_result result;
	int ret;

	if (owner_lsm_ns)
		*owner_lsm_ns = NULL;
	if (!boundary)
		return -EINVAL;
	*boundary = (struct auth_guard_userns_boundary) {};

	nsproxy = get_current_nsproxy_checked_where(where);
	if (IS_ERR(nsproxy))
		return PTR_ERR(nsproxy);

	/* The retained task reservation keeps the credential edge stable. */
	cred = current_cred();
	user_ns = get_user_ns(READ_ONCE(cred->user_ns));
	if (!user_ns) {
		ret = -EACCES;
		goto out_nsproxy;
	}

	/* Keep both guarded objects stable while every endpoint is pinned. */
	result = auth_guard_userns_boundary_snapshot_begin_where(user_ns, where);
	if (result != AUTH_GUARD_CHECK_VALID) {
		ret = namespace_boundary_snapshot_error(result);
		goto out_user_ns;
	}
	boundary->syslog_ns = get_syslog_ns(READ_ONCE(nsproxy->syslog_ns));
	boundary->tracing_ns = get_tracing_ns(READ_ONCE(nsproxy->tracing_ns));
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	auth_guard_userns_boundary_read(user_ns, &user_boundary);
	boundary->lsm_ns = get_lsm_ns(user_boundary.lsm_ns ?: &init_lsm_ns);
#endif

	ret = !boundary->syslog_ns ? -EACCES : 0;
#ifdef CONFIG_TRACING_NS
	if (!boundary->tracing_ns)
		ret = -EACCES;
#endif
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (!boundary->lsm_ns)
		ret = -EACCES;
	if (!ret && owner_lsm_ns &&
	    boundary->syslog_ns != &init_syslog_ns) {
		owner_user_ns = READ_ONCE(boundary->syslog_ns->user_ns);
		if (owner_user_ns == user_ns) {
			*owner_lsm_ns = get_lsm_ns(boundary->lsm_ns);
			owner_user_ns = NULL;
		} else if (owner_user_ns) {
			owner_user_ns = get_user_ns(owner_user_ns);
			if (!owner_user_ns) {
				ret = -EACCES;
			} else {
				result =
					auth_guard_userns_boundary_snapshot_begin_where(
						owner_user_ns, where);
				if (result != AUTH_GUARD_CHECK_VALID) {
					ret = namespace_boundary_snapshot_error(result);
				} else {
					owner_reserved = true;
					auth_guard_userns_boundary_read(
						owner_user_ns, &owner_boundary);
					*owner_lsm_ns = get_lsm_ns(
						owner_boundary.lsm_ns ?: &init_lsm_ns);
					if (!*owner_lsm_ns)
						ret = -EACCES;
				}
			}
		}
	}
	if (owner_reserved &&
	    !auth_guard_userns_boundary_snapshot_end_where(owner_user_ns, where))
		ret = -EACCES;
	put_user_ns(owner_user_ns);
#endif
	if (!auth_guard_userns_boundary_snapshot_end_where(user_ns, where))
		ret = -EACCES;

out_user_ns:
	put_user_ns(user_ns);
out_nsproxy:
	if (!put_current_nsproxy_checked_where(nsproxy, where))
		ret = -EACCES;
	if (ret) {
		if (owner_lsm_ns) {
			put_lsm_ns(*owner_lsm_ns);
			*owner_lsm_ns = NULL;
		}
		put_namespace_boundary(boundary);
	}
	return ret;
}

int get_current_namespace_boundary_where(struct auth_guard_userns_boundary *boundary,
					 const char *where)
{
	return get_current_namespace_boundary_owner_where(boundary, NULL, where);
}
EXPORT_SYMBOL_GPL(get_current_namespace_boundary_where);

void put_namespace_boundary(struct auth_guard_userns_boundary *boundary)
{
	if (!boundary)
		return;
	if (!IS_ERR(boundary->lsm_ns))
		put_lsm_ns(boundary->lsm_ns);
	if (!IS_ERR(boundary->tracing_ns))
		put_tracing_ns(boundary->tracing_ns);
	if (!IS_ERR(boundary->syslog_ns))
		put_syslog_ns(boundary->syslog_ns);
	*boundary = (struct auth_guard_userns_boundary) {};
}
EXPORT_SYMBOL_GPL(put_namespace_boundary);

static int task_nsproxy_snapshot_error(enum auth_guard_check_result result)
{
	switch (result) {
	case AUTH_GUARD_CHECK_BUSY:
		return -EAGAIN;
	case AUTH_GUARD_CHECK_CREDENTIAL_ONLY:
	case AUTH_GUARD_CHECK_UNAVAILABLE:
		return -ESRCH;
	default:
		return -EACCES;
	}
}

/*
 * Capture a referenced task nsproxy while retaining authenticated task and
 * nsproxy reader reservations.  Remote task lookup follows the native
 * task_lock() rule; current cannot race its own namespace edge and may already
 * be called from a task-locked context.  A successful capture owns references
 * to both objects and must be finished with task_nsproxy_snapshot_put().
 */
int task_nsproxy_snapshot_get_where(struct task_struct *task,
				    struct task_nsproxy_snapshot *snapshot,
				    const char *where)
{
	struct nsproxy *nsproxy = NULL;
	enum auth_guard_check_result result;
	bool nsproxy_reserved = false;
	bool remote;
	bool task_reserved = false;

	if (!task || !snapshot)
		return -EINVAL;
	snapshot->task = NULL;
	snapshot->nsproxy = NULL;

	remote = task != current;
	if (remote)
		task_lock(task);

	result = auth_guard_task_snapshot_begin_where(task, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		goto out;
	task_reserved = true;

	nsproxy = READ_ONCE(task->nsproxy);
	if (!nsproxy) {
		result = AUTH_GUARD_CHECK_UNAVAILABLE;
		goto out;
	}
	result = auth_guard_nsproxy_snapshot_begin_where(nsproxy, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		goto out;
	nsproxy_reserved = true;

	get_task_struct(task);
	get_nsproxy(nsproxy);
	snapshot->task = task;
	snapshot->nsproxy = nsproxy;
	if (remote)
		task_unlock(task);

	return 0;

out:
	if (nsproxy_reserved &&
	    !auth_guard_nsproxy_snapshot_end_where(nsproxy, where))
		result = AUTH_GUARD_CHECK_INVALID;
	if (task_reserved &&
	    !auth_guard_task_snapshot_end_where(task, where))
		result = AUTH_GUARD_CHECK_INVALID;
	if (remote)
		task_unlock(task);

	return task_nsproxy_snapshot_error(result);
}
EXPORT_SYMBOL_GPL(task_nsproxy_snapshot_get_where);

bool task_nsproxy_snapshot_put_where(struct task_nsproxy_snapshot *snapshot,
				     const char *where)
{
	struct task_struct *task;
	struct nsproxy *nsproxy;
	bool valid;

	if (WARN_ON_ONCE(!snapshot || !snapshot->task || !snapshot->nsproxy))
		return false;

	task = snapshot->task;
	nsproxy = snapshot->nsproxy;
	snapshot->task = NULL;
	snapshot->nsproxy = NULL;

	valid = auth_guard_nsproxy_snapshot_end_where(nsproxy, where);
	if (!auth_guard_task_snapshot_end_where(task, where))
		valid = false;
	put_nsproxy(nsproxy);
	put_task_struct(task);

	return valid;
}
EXPORT_SYMBOL_GPL(task_nsproxy_snapshot_put_where);

/*
 * Return a referenced current nsproxy with both authenticated reader
 * reservations retained. Callers must finish with
 * put_current_nsproxy_checked_where() before using PTR_ERR() as appropriate.
 */
struct nsproxy *get_current_nsproxy_checked_where(const char *where)
{
	struct task_nsproxy_snapshot snapshot;
	int ret;

	ret = task_nsproxy_snapshot_get_where(current, &snapshot, where);
	if (ret)
		return ERR_PTR(ret == -ESRCH ? -EACCES : ret);

	return snapshot.nsproxy;
}
EXPORT_SYMBOL_GPL(get_current_nsproxy_checked_where);

bool put_current_nsproxy_checked_where(struct nsproxy *nsproxy,
				       const char *where)
{
	struct task_nsproxy_snapshot snapshot = {
		.task = current,
		.nsproxy = nsproxy,
	};

	return task_nsproxy_snapshot_put_where(&snapshot, where);
}
EXPORT_SYMBOL_GPL(put_current_nsproxy_checked_where);

bool pending_child_lsm_ns_request_consumable(const struct task_struct *task,
					     const struct user_namespace *user_ns)
{
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (task && task->lsm_ns_for_child && user_ns && user_ns != current_user_ns())
		return true;
#endif
	return false;
}

static void set_child_namespace_owner_creds(struct nsproxy *nsproxy, u64 flags,
					    bool new_syslog_ns,
					    bool new_tracing_ns,
					    struct user_namespace *user_ns,
					    const struct cred *cred)
{
	if (!cred)
		return;

	if (user_ns && user_ns != current_user_ns())
		ns_common_set_owner_prop(&user_ns->ns, cred);
	if ((flags & CLONE_NEWNS) && nsproxy->mnt_ns)
		ns_common_set_owner_prop(from_mnt_ns(nsproxy->mnt_ns), cred);
	if ((flags & CLONE_NEWUTS) && nsproxy->uts_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->uts_ns), cred);
	if ((flags & CLONE_NEWIPC) && nsproxy->ipc_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->ipc_ns), cred);
	if ((flags & CLONE_NEWPID) && nsproxy->pid_ns_for_children) {
		struct ns_common *ns;

		ns = to_ns_common(nsproxy->pid_ns_for_children);
		ns_common_set_owner_prop(ns, cred);
	}
	if ((flags & CLONE_NEWCGROUP) && nsproxy->cgroup_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->cgroup_ns), cred);
	if ((flags & CLONE_NEWNET) && nsproxy->net_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->net_ns), cred);
	if ((flags & CLONE_NEWTIME) && nsproxy->time_ns_for_children) {
		struct ns_common *ns;

		ns = to_ns_common(nsproxy->time_ns_for_children);
		ns_common_set_owner_prop(ns, cred);
	}
	if (new_syslog_ns && nsproxy->syslog_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->syslog_ns), cred);
#ifdef CONFIG_TRACING_NS
	if (new_tracing_ns && nsproxy->tracing_ns)
		ns_common_set_owner_prop(to_ns_common(nsproxy->tracing_ns), cred);
#else
	(void)new_tracing_ns;
#endif
}

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
static void set_child_lsm_namespace_owner_creds(struct lsm_namespace *lsm_ns,
						const struct cred *cred)
{
	if (!cred)
		return;

	if (lsm_ns && lsm_ns != &init_lsm_ns)
		ns_common_set_owner_prop(&lsm_ns->ns, cred);
}
#endif

static bool has_pending_child_ns_request(const struct task_struct *task,
				 const struct user_namespace *user_ns)
{
	if (!task)
		return false;

	if (task->syslog_ns_for_child || task->tracing_ns_for_child)
		return true;

	return pending_child_lsm_ns_request_consumable(task, user_ns);
}

static void reset_pending_child_ns_request_payloads(
	struct pending_child_ns_request_payloads *payloads)
{
	*payloads = (struct pending_child_ns_request_payloads) {
		.lsm.lsmid = LSM_ID_UNDEF,
	};
}

void release_pending_child_ns_request_payloads(
	struct pending_child_ns_request_payloads *payloads)
{
	if (!payloads)
		return;
	kfree(payloads->syslog.name);
	lsm_ns_release_pending_child_request(&payloads->lsm);
	reset_pending_child_ns_request_payloads(payloads);
}

static void __consume_pending_child_ns_request_where(
	struct task_struct *task, bool consume_lsm,
	struct pending_child_ns_request_payloads *payloads, const char *where)
{
	const struct auth_guard_task_syslog_request empty_syslog = {};
	enum auth_guard_mutation_result mutation;

	mutation = auth_guard_task_replace_syslog_request_in_transition_where(
		task, &empty_syslog, &payloads->syslog, where);
	AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	mutation = auth_guard_task_replace_tracing_request_in_transition_where(
		task, false, &payloads->tracing, where);
	AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	if (consume_lsm) {
		mutation =
			lsm_ns_clear_pending_child_request_in_transition_where(
				task, &payloads->lsm, where);
		AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	}
}

int consume_pending_child_ns_request_where(struct task_struct *task,
					    bool consume_lsm,
					    const char *where)
{
	struct pending_child_ns_request_payloads payloads;
	bool auth_guarded;

	reset_pending_child_ns_request_payloads(&payloads);
	if (!task)
		return 0;

	if (!task->syslog_ns_for_child && !task->tracing_ns_for_child &&
	    !consume_lsm)
		return 0;

	auth_guarded = auth_guard_task_begin_transition_where(task, where);
	if (!auth_guarded)
		return -EACCES;

	__consume_pending_child_ns_request_where(
		task, consume_lsm, &payloads, where);
	AUTH_GUARD_FAIL_STOP_UNLESS(
		auth_guard_task_finish_transition_where(task, where));
	release_pending_child_ns_request_payloads(&payloads);
	return 0;
}

void consume_pending_child_ns_request_in_transition_where(
	struct task_struct *task, bool consume_lsm,
	struct pending_child_ns_request_payloads *payloads, const char *where)
{
	if (!task || !payloads)
		return;

	reset_pending_child_ns_request_payloads(payloads);
	if (!task->syslog_ns_for_child && !task->tracing_ns_for_child &&
	    !consume_lsm)
		return;

	AUTH_GUARD_FAIL_STOP_UNLESS(
		auth_guard_task_transition_open_where(task, where));

	__consume_pending_child_ns_request_where(
		task, consume_lsm, payloads, where);
}

#define DEFINE_CHILD_USERNS_DEFAULT_RESTORER(_name, _type, _replace) \
static enum auth_guard_mutation_result \
restore_child_userns_##_name##_default( \
	struct user_namespace *user_ns, struct _type *installed, \
	struct _type *previous) \
{ \
	if (user_ns && user_ns != current_user_ns()) \
		return _replace(user_ns, installed, previous); \
	return AUTH_GUARD_MUTATION_APPLIED; \
}

DEFINE_CHILD_USERNS_DEFAULT_RESTORER(syslog, syslog_namespace,
				     syslog_ns_replace_userns_default)

#ifdef CONFIG_TRACING_NS
DEFINE_CHILD_USERNS_DEFAULT_RESTORER(tracing, tracing_namespace,
				     tracing_ns_replace_userns_default)
#endif

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
DEFINE_CHILD_USERNS_DEFAULT_RESTORER(lsm, lsm_namespace,
				     lsm_ns_replace_userns_default)

static bool
restore_and_put_child_userns_lsm_default(struct user_namespace *user_ns,
					 struct lsm_namespace *installed,
					 struct lsm_namespace *previous)
{
	/* A failed restore quarantines and deliberately retains both refs. */
	if (installed &&
	    restore_child_userns_lsm_default(user_ns, installed, previous) !=
		    AUTH_GUARD_MUTATION_APPLIED)
		return false;
	put_lsm_ns(installed);
	put_lsm_ns(previous);
	return true;
}
#endif

#undef DEFINE_CHILD_USERNS_DEFAULT_RESTORER

struct nsproxy init_nsproxy = {
	.count			= REFCOUNT_INIT(1),
	.uts_ns			= &init_uts_ns,
#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
	.ipc_ns			= &init_ipc_ns,
#endif
	.mnt_ns			= NULL,
	.pid_ns_for_children	= &init_pid_ns,
#ifdef CONFIG_NET
	.net_ns			= &init_net,
#endif
#ifdef CONFIG_CGROUPS
	.cgroup_ns		= &init_cgroup_ns,
#endif
#ifdef CONFIG_TIME_NS
	.time_ns		= &init_time_ns,
	.time_ns_for_children	= &init_time_ns,
#endif
	.syslog_ns		= &init_syslog_ns,
#ifdef CONFIG_TRACING_NS
	.tracing_ns		= &init_tracing_ns,
#endif
};

static inline struct nsproxy *create_nsproxy(void)
{
	struct nsproxy *nsproxy;

	nsproxy = kmem_cache_alloc(nsproxy_cachep, GFP_KERNEL);
	if (nsproxy) {
		memset(nsproxy, 0, sizeof(*nsproxy));
		refcount_set(&nsproxy->count, 1);
	}
	return nsproxy;
}

/*
 * Create new nsproxy and all of its the associated namespaces.
 * Return the newly created nsproxy.  Do not attach this to the task,
 * leave it to the caller to do proper locking and attach it to task.
 *
 * @syslog_req_task is the task owning any pending child-boundary namespace
 * request to consult while duplicating namespaces. The caller consumes the
 * request only after the clone/unshare commit point; callers that only need a
 * transient nsproxy clone should pass NULL so the request survives.
 */
static struct nsproxy *create_new_namespaces(u64 flags,
	struct task_struct *tsk, struct task_struct *syslog_req_task,
	struct user_namespace *user_ns, struct cred *new_cred,
	struct fs_struct *new_fs, bool seal_nsproxy)
{
	bool new_syslog_ns = false;
	bool new_tracing_ns = false;
	const struct cred *owner_cred;
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	bool new_lsm_ns = false;
	struct lsm_ctx *new_lsm_ctx = NULL;
	struct lsm_namespace *created_lsm_ns = NULL;
	struct lsm_namespace *old_lsm_ns = NULL;
	struct lsm_namespace *mnt_lsm_ns = NULL;
#endif
	char *syslog_name = NULL;
	struct nsproxy *new_nsp;
	int err;

	new_nsp = create_nsproxy();
	if (!new_nsp)
		return ERR_PTR(-ENOMEM);
	new_nsp->tracing_ns = NULL;

	new_nsp->mnt_ns = copy_mnt_ns(flags, tsk->nsproxy->mnt_ns, user_ns, new_fs);
	if (IS_ERR(new_nsp->mnt_ns)) {
		err = PTR_ERR(new_nsp->mnt_ns);
		goto out_ns;
	}

	new_nsp->uts_ns = copy_utsname(flags, user_ns, tsk->nsproxy->uts_ns);
	if (IS_ERR(new_nsp->uts_ns)) {
		err = PTR_ERR(new_nsp->uts_ns);
		goto out_uts;
	}

	new_nsp->ipc_ns = copy_ipcs(flags, user_ns, tsk->nsproxy->ipc_ns);
	if (IS_ERR(new_nsp->ipc_ns)) {
		err = PTR_ERR(new_nsp->ipc_ns);
		goto out_ipc;
	}

	new_nsp->pid_ns_for_children =
		copy_pid_ns(flags, user_ns, tsk->nsproxy->pid_ns_for_children);
	if (IS_ERR(new_nsp->pid_ns_for_children)) {
		err = PTR_ERR(new_nsp->pid_ns_for_children);
		goto out_pid;
	}

	new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns,
					    tsk->nsproxy->cgroup_ns);
	if (IS_ERR(new_nsp->cgroup_ns)) {
		err = PTR_ERR(new_nsp->cgroup_ns);
		goto out_cgroup;
	}

	new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);
	if (IS_ERR(new_nsp->net_ns)) {
		err = PTR_ERR(new_nsp->net_ns);
		goto out_net;
	}

	new_nsp->time_ns_for_children = copy_time_ns(flags, user_ns,
					tsk->nsproxy->time_ns_for_children);
	if (IS_ERR(new_nsp->time_ns_for_children)) {
		err = PTR_ERR(new_nsp->time_ns_for_children);
		goto out_time;
	}
	new_nsp->time_ns = get_time_ns(tsk->nsproxy->time_ns);

	if (syslog_req_task) {
		new_syslog_ns = syslog_req_task->syslog_ns_for_child;
		new_tracing_ns = syslog_req_task->tracing_ns_for_child;
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
		new_lsm_ns = pending_child_lsm_ns_request_consumable(syslog_req_task,
								     user_ns);
		new_lsm_ctx = syslog_req_task->lsm_ns_for_child_ctx;
#endif
		syslog_name = syslog_req_task->syslog_ns_for_child_name;
	}

	new_nsp->syslog_ns = copy_syslog_ns(new_syslog_ns, syslog_name,
					    user_ns, tsk->nsproxy->syslog_ns);
	if (IS_ERR(new_nsp->syslog_ns)) {
		err = PTR_ERR(new_nsp->syslog_ns);
		goto out_syslog;
	}

#ifdef CONFIG_TRACING_NS
	new_nsp->tracing_ns = copy_tracing_ns(new_tracing_ns, user_ns,
				      new_nsp->pid_ns_for_children,
				      new_nsp->syslog_ns,
				      tsk->nsproxy->tracing_ns);
	if (IS_ERR(new_nsp->tracing_ns)) {
		err = PTR_ERR(new_nsp->tracing_ns);
		goto out_tracing;
	}
#endif
	if (!new_cred && tsk != current)
		new_cred = (struct cred *)tsk->cred;
	owner_cred = new_cred ?: current_cred();
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (new_lsm_ns) {
		old_lsm_ns = get_current_lsm_ns_checked();
		if (IS_ERR(old_lsm_ns)) {
			err = PTR_ERR(old_lsm_ns);
			old_lsm_ns = NULL;
			goto out_lsm;
		}
		created_lsm_ns = copy_lsm_ns(true, user_ns, tsk, new_cred,
					     new_lsm_ctx, old_lsm_ns);
		if (IS_ERR(created_lsm_ns)) {
			err = PTR_ERR(created_lsm_ns);
			created_lsm_ns = NULL;
			goto out_lsm;
		}
		set_child_lsm_namespace_owner_creds(created_lsm_ns, owner_cred);
	}
#endif
	if (flags & CLONE_NEWNS) {
	#ifdef CONFIG_SECURITY_LSM_NAMESPACE
		if (user_ns)
			mnt_lsm_ns = get_lsm_ns_from_userns_checked(user_ns);
		else
			mnt_lsm_ns = get_current_lsm_ns_checked();
		if (IS_ERR_OR_NULL(mnt_lsm_ns)) {
			err = mnt_lsm_ns ? PTR_ERR(mnt_lsm_ns) : -EACCES;
			mnt_lsm_ns = NULL;
			goto out_lsm;
		}
		mnt_ns_set_boundary_namespaces(new_nsp->mnt_ns,
					       new_nsp->syslog_ns,
					       new_nsp->tracing_ns,
					       mnt_lsm_ns);
		put_lsm_ns(mnt_lsm_ns);
		mnt_lsm_ns = NULL;
#else
		mnt_ns_set_boundary_namespaces(new_nsp->mnt_ns,
					       new_nsp->syslog_ns,
					       new_nsp->tracing_ns,
					       NULL);
#endif
	}
	set_child_namespace_owner_creds(new_nsp, flags, new_syslog_ns,
					new_tracing_ns, user_ns, owner_cred);
	if (seal_nsproxy && !auth_guard_nsproxy_init(new_nsp)) {
		err = -EACCES;
		goto out_rejected_child_boundary;
	}
	if (seal_nsproxy && (flags & CLONE_NEWCGROUP)) {
		err = cgroup_ns_publish(new_nsp->cgroup_ns);
		if (err)
			goto out_rejected_child_boundary;
		cgroup_ns_activate_loadavg(new_nsp->cgroup_ns);
	}
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	put_lsm_ns(created_lsm_ns);
	put_lsm_ns(old_lsm_ns);
#endif
	return new_nsp;

out_rejected_child_boundary:
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (!restore_and_put_child_userns_lsm_default(user_ns, created_lsm_ns, old_lsm_ns))
		goto out_quarantined_child_boundary;
#endif
#ifdef CONFIG_TRACING_NS
	if (restore_child_userns_tracing_default(
		    user_ns, new_nsp->tracing_ns, tsk->nsproxy->tracing_ns) !=
	    AUTH_GUARD_MUTATION_APPLIED)
		goto out_quarantined_child_boundary;
#endif
	if (restore_child_userns_syslog_default(
		    user_ns, new_nsp->syslog_ns, tsk->nsproxy->syslog_ns) !=
	    AUTH_GUARD_MUTATION_APPLIED)
		goto out_quarantined_child_boundary;
	free_nsproxy_rejected(new_nsp);
	return ERR_PTR(err);

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
out_lsm:
	if (!restore_and_put_child_userns_lsm_default(user_ns, created_lsm_ns, old_lsm_ns))
		goto out_quarantined_child_boundary;
#ifdef CONFIG_TRACING_NS
	if (restore_child_userns_tracing_default(
		    user_ns, new_nsp->tracing_ns, tsk->nsproxy->tracing_ns) !=
	    AUTH_GUARD_MUTATION_APPLIED)
		goto out_quarantined_child_boundary;
	put_tracing_ns(new_nsp->tracing_ns);
#endif
	if (restore_child_userns_syslog_default(
		    user_ns, new_nsp->syslog_ns, tsk->nsproxy->syslog_ns) !=
	    AUTH_GUARD_MUTATION_APPLIED)
		goto out_quarantined_child_boundary;
	put_syslog_ns(new_nsp->syslog_ns);
	goto out_syslog;
#endif

#ifdef CONFIG_TRACING_NS
out_tracing:
	if (restore_child_userns_syslog_default(
		    user_ns, new_nsp->syslog_ns, tsk->nsproxy->syslog_ns) !=
	    AUTH_GUARD_MUTATION_APPLIED)
		goto out_quarantined_child_boundary;
	put_syslog_ns(new_nsp->syslog_ns);
#endif
out_syslog:
	put_time_ns(new_nsp->time_ns);
	if (new_nsp->time_ns_for_children)
		put_time_ns(new_nsp->time_ns_for_children);
out_time:
	put_net(new_nsp->net_ns);
out_net:
	put_cgroup_ns_maybe_unpublished(new_nsp->cgroup_ns);
out_cgroup:
	put_pid_ns(new_nsp->pid_ns_for_children);
out_pid:
	put_ipc_ns(new_nsp->ipc_ns);
out_ipc:
	put_uts_ns(new_nsp->uts_ns);
out_uts:
	put_mnt_ns(new_nsp->mnt_ns);
out_ns:
	kmem_cache_free(nsproxy_cachep, new_nsp);
	return ERR_PTR(err);

out_quarantined_child_boundary:
	return ERR_PTR(err);
}

/*
 * called from clone.  This now handles copy for nsproxy and all
 * namespaces therein.
 */
int copy_namespaces(u64 flags, struct task_struct *tsk)
{
	struct nsproxy *old_ns = tsk->nsproxy;
	struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
	struct nsproxy *new_ns;
	int err;

	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET |
			      CLONE_NEWCGROUP | CLONE_NEWTIME))) &&
		    likely(!has_pending_child_ns_request(current, user_ns))) {
		if ((flags & CLONE_VM) ||
		    likely(old_ns->time_ns_for_children == old_ns->time_ns)) {
			if (!auth_guard_nsproxy_check(old_ns))
				return -EACCES;
			get_nsproxy(old_ns);
			return 0;
		}
	} else if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * CLONE_NEWIPC must detach from the undolist: after switching
	 * to a new ipc namespace, the semaphore arrays from the old
	 * namespace are unreachable.  In clone parlance, CLONE_SYSVSEM
	 * means share undolist with parent, so we must forbid using
	 * it along with CLONE_NEWIPC.
	 */
	if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
		(CLONE_NEWIPC | CLONE_SYSVSEM))
		return -EINVAL;

	if (!auth_guard_nsproxy_check(old_ns))
		return -EACCES;

	new_ns = create_new_namespaces(flags, tsk, current, user_ns, NULL,
				       tsk->fs, false);
	if (IS_ERR(new_ns))
		return  PTR_ERR(new_ns);

	if ((flags & CLONE_VM) == 0) {
		err = timens_on_fork(new_ns, tsk);
		if (err) {
			free_nsproxy_unpublished(new_ns);
			return err;
		}
	}

	if (!auth_guard_nsproxy_init(new_ns)) {
		free_nsproxy_rejected(new_ns);
		return -EACCES;
	}
	tsk->nsproxy = new_ns;
	return 0;
}

struct nsproxy_destroy_snapshot {
	struct mnt_namespace *mnt_ns;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
	struct syslog_namespace *syslog_ns;
#ifdef CONFIG_TRACING_NS
	struct tracing_namespace *tracing_ns;
#endif
};

static void free_nsproxy_snapshot(const struct nsproxy_destroy_snapshot *snapshot)
{
	put_mnt_ns(snapshot->mnt_ns);
	put_uts_ns(snapshot->uts_ns);
	put_ipc_ns(snapshot->ipc_ns);
	put_pid_ns(snapshot->pid_ns_for_children);
	put_time_ns(snapshot->time_ns);
	put_time_ns(snapshot->time_ns_for_children);
	put_syslog_ns(snapshot->syslog_ns);
#ifdef CONFIG_TRACING_NS
	put_tracing_ns(snapshot->tracing_ns);
#endif
	put_cgroup_ns_maybe_unpublished(snapshot->cgroup_ns);
	put_net(snapshot->net_ns);
}

static void free_nsproxy_unpublished(struct nsproxy *ns)
{
	struct nsproxy_destroy_snapshot snapshot = {
		.mnt_ns = ns->mnt_ns,
		.uts_ns = ns->uts_ns,
		.ipc_ns = ns->ipc_ns,
		.pid_ns_for_children = ns->pid_ns_for_children,
		.net_ns = ns->net_ns,
		.time_ns = ns->time_ns,
		.time_ns_for_children = ns->time_ns_for_children,
		.cgroup_ns = ns->cgroup_ns,
		.syslog_ns = ns->syslog_ns,
#ifdef CONFIG_TRACING_NS
		.tracing_ns = ns->tracing_ns,
#endif
	};

	free_nsproxy_snapshot(&snapshot);
	kmem_cache_free(nsproxy_cachep, ns);
}

static void free_nsproxy_rejected(struct nsproxy *ns)
{
	(void)xchg(&ns->mnt_ns, NULL);
	(void)xchg(&ns->uts_ns, NULL);
	(void)xchg(&ns->ipc_ns, NULL);
	(void)xchg(&ns->pid_ns_for_children, NULL);
	(void)xchg(&ns->net_ns, NULL);
	(void)xchg(&ns->time_ns, NULL);
	(void)xchg(&ns->time_ns_for_children, NULL);
	(void)xchg(&ns->cgroup_ns, NULL);
	(void)xchg(&ns->syslog_ns, NULL);
#ifdef CONFIG_TRACING_NS
	(void)xchg(&ns->tracing_ns, NULL);
#endif
	kmem_cache_free(nsproxy_cachep, ns);
}

void free_nsproxy(struct nsproxy *ns)
{
	struct nsproxy_destroy_snapshot snapshot = {};
	bool exact = true;
	bool valid;

	valid = auth_guard_nsproxy_destroy_begin(ns);
	if (valid) {
		snapshot.mnt_ns = READ_ONCE(ns->mnt_ns);
		snapshot.uts_ns = READ_ONCE(ns->uts_ns);
		snapshot.ipc_ns = READ_ONCE(ns->ipc_ns);
		snapshot.pid_ns_for_children =
			READ_ONCE(ns->pid_ns_for_children);
		snapshot.net_ns = READ_ONCE(ns->net_ns);
		snapshot.time_ns = READ_ONCE(ns->time_ns);
		snapshot.time_ns_for_children =
			READ_ONCE(ns->time_ns_for_children);
		snapshot.cgroup_ns = READ_ONCE(ns->cgroup_ns);
		snapshot.syslog_ns = READ_ONCE(ns->syslog_ns);
#ifdef CONFIG_TRACING_NS
		snapshot.tracing_ns = READ_ONCE(ns->tracing_ns);
#endif
		valid = auth_guard_nsproxy_snapshot_end(ns);
	}

	exact &= xchg(&ns->mnt_ns, NULL) == snapshot.mnt_ns;
	exact &= xchg(&ns->uts_ns, NULL) == snapshot.uts_ns;
	exact &= xchg(&ns->ipc_ns, NULL) == snapshot.ipc_ns;
	exact &= xchg(&ns->pid_ns_for_children, NULL) ==
		snapshot.pid_ns_for_children;
	exact &= xchg(&ns->net_ns, NULL) == snapshot.net_ns;
	exact &= xchg(&ns->time_ns, NULL) == snapshot.time_ns;
	exact &= xchg(&ns->time_ns_for_children, NULL) ==
		snapshot.time_ns_for_children;
	exact &= xchg(&ns->cgroup_ns, NULL) == snapshot.cgroup_ns;
	exact &= xchg(&ns->syslog_ns, NULL) == snapshot.syslog_ns;
#ifdef CONFIG_TRACING_NS
	exact &= xchg(&ns->tracing_ns, NULL) == snapshot.tracing_ns;
#endif
	if (valid && !exact) {
		/* The detached tuple no longer matches the authenticated snapshot. */
		(void)auth_guard_nsproxy_check(ns);
		valid = false;
	}
	if (valid)
		free_nsproxy_snapshot(&snapshot);
	kmem_cache_free(nsproxy_cachep, ns);
}

/*
 * Called from unshare. Unshare all the namespaces part of nsproxy.
 * On success, returns the new nsproxy.
 */
int unshare_nsproxy_namespaces(unsigned long unshare_flags,
	struct nsproxy **new_nsp, struct cred *new_cred, struct fs_struct *new_fs)
{
	struct user_namespace *user_ns;
	int err = 0;

	user_ns = new_cred ? new_cred->user_ns : current_user_ns();
	if (!(unshare_flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			       CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP |
			       CLONE_NEWTIME)) &&
	    !has_pending_child_ns_request(current, user_ns))
		return 0;
	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (!auth_guard_nsproxy_check(current->nsproxy))
		return -EACCES;

	*new_nsp = create_new_namespaces(unshare_flags, current, current,
					 user_ns, new_cred,
					 new_fs ? new_fs : current->fs, true);
	if (IS_ERR(*new_nsp)) {
		err = PTR_ERR(*new_nsp);
		goto out;
	}

out:
	return err;
}

int switch_task_namespaces_checked_where(struct task_struct *p,
					 struct nsproxy *new,
					 const char *where)
{
	enum auth_guard_mutation_result mutation;
	struct nsproxy *old;

	might_sleep();

	if (!new)
		return -EINVAL;
	if (!auth_guard_nsproxy_check_where(new, where) ||
	    !auth_guard_task_begin_transition_where(p, where))
		return -EACCES;

	task_lock(p);
	mutation = auth_guard_task_replace_nsproxy_in_transition_where(
		p, new, &old, where);
	AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	AUTH_GUARD_FAIL_STOP_UNLESS(
		auth_guard_task_finish_transition_where(p, where));
	task_unlock(p);

	if (old)
		put_nsproxy(old);
	return 0;
}

void switch_task_namespaces(struct task_struct *p, struct nsproxy *new)
{
	if (WARN_ON_ONCE(switch_task_namespaces_checked(p, new)))
		put_nsproxy(new);
}

void exit_task_namespaces(struct task_struct *p)
{
	struct nsproxy *ns;
	struct nsproxy *expected;
	enum auth_guard_mutation_result mutation;
	enum auth_guard_task_teardown_status auth_guard_status;
	bool exact;
	bool old_valid;
	bool trusted;

	auth_guard_status = auth_guard_task_begin_teardown_transition(p);

	task_lock(p);
	expected = READ_ONCE(p->nsproxy);
	old_valid = auth_guard_task_validate_teardown(p, auth_guard_status);
	if (auth_guard_status == AUTH_GUARD_TASK_TEARDOWN_OPENED &&
	    old_valid) {
		ns = NULL;
		mutation = auth_guard_task_replace_nsproxy_in_transition(
			p, NULL, &ns);
		exact = mutation == AUTH_GUARD_MUTATION_APPLIED &&
			ns == expected &&
			auth_guard_task_validate_transition_result(p);
		if (mutation != AUTH_GUARD_MUTATION_APPLIED)
			(void)xchg(&p->nsproxy, NULL);
	} else {
		ns = xchg(&p->nsproxy, NULL);
		exact = ns == expected;
	}

	/*
	 * Reseal the exiting task over its remaining endpoints.  Release the
	 * detached nsproxy only when the old graph and exact edge were authenticated;
	 * otherwise leave its namespace references quarantined and leaked.
	 */
	trusted = auth_guard_task_complete_teardown(p, auth_guard_status,
						    old_valid, exact,
						    false);
	if (!trusted && auth_guard_status == AUTH_GUARD_TASK_TEARDOWN_FAILED)
		WARN_ON_ONCE(1);
	task_unlock(p);
	if (ns && trusted)
		put_nsproxy(ns);
}

int exec_task_namespaces(void)
{
	struct task_struct *tsk = current;
	struct nsproxy *new;
	int err;

	if (tsk->nsproxy->time_ns_for_children == tsk->nsproxy->time_ns)
		return 0;

	if (!auth_guard_nsproxy_check(tsk->nsproxy))
		return -EACCES;

	/*
	 * exec only syncs the deferred time namespace into the active nsproxy.
	 * It must not consume a pending child-boundary namespace request,
	 * which is meant for the next real clone/unshare namespace duplication.
	 */
	new = create_new_namespaces(0, tsk, NULL, current_user_ns(), NULL,
				    tsk->fs, false);
	if (IS_ERR(new))
		return PTR_ERR(new);

	err = timens_on_exec(new, tsk);
	if (err) {
		free_nsproxy_unpublished(new);
		return err;
	}
	if (!auth_guard_nsproxy_init(new)) {
		free_nsproxy_rejected(new);
		return -EACCES;
	}
	err = switch_task_namespaces_checked(tsk, new);
	if (err) {
		put_nsproxy(new);
		return err;
	}
	return 0;
}

static int check_setns_flags(unsigned long flags)
{
	if (!flags || (flags & ~(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
				 CLONE_NEWNET | CLONE_NEWTIME | CLONE_NEWUSER |
				 CLONE_NEWPID | CLONE_NEWCGROUP)))
		return -EINVAL;

#ifndef CONFIG_USER_NS
	if (flags & CLONE_NEWUSER)
		return -EINVAL;
#endif
#ifndef CONFIG_PID_NS
	if (flags & CLONE_NEWPID)
		return -EINVAL;
#endif
#ifndef CONFIG_UTS_NS
	if (flags & CLONE_NEWUTS)
		return -EINVAL;
#endif
#ifndef CONFIG_IPC_NS
	if (flags & CLONE_NEWIPC)
		return -EINVAL;
#endif
#ifndef CONFIG_CGROUPS
	if (flags & CLONE_NEWCGROUP)
		return -EINVAL;
#endif
#ifndef CONFIG_NET_NS
	if (flags & CLONE_NEWNET)
		return -EINVAL;
#endif
#ifndef CONFIG_TIME_NS
	if (flags & CLONE_NEWTIME)
		return -EINVAL;
#endif

	return 0;
}

static void put_nsset(struct nsset *nsset)
{
	unsigned flags = nsset->flags;
	struct cred *cred = nsset_cred(nsset);

	if (cred) {
		abort_creds(cred);
		nsset->cred = NULL;
	}
	/*
	 * We only created a temporary copy if we attached to more than just
	 * the mount namespace.
	 */
	if (nsset->fs && (flags & CLONE_NEWNS) && (flags & ~CLONE_NEWNS))
		free_fs_struct(nsset->fs);
	if (nsset->nsproxy)
		free_nsproxy(nsset->nsproxy);
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	put_lsm_ns(nsset->lsm_ns);
	nsset->lsm_ns = NULL;
#endif
}

static int prepare_nsset(unsigned flags, struct nsset *nsset)
{
	struct task_struct *me = current;
	int err = -ENOMEM;

	nsset->flags = flags;

	/*
	 * setns() needs a transient duplicate of the caller's namespaces for
	 * validation and commit. Do not consume a pending child-boundary namespace request
	 * here; it belongs to the next real clone/unshare boundary.
	 */
	if (!auth_guard_nsproxy_check(me->nsproxy))
		return -EACCES;

	nsset->nsproxy = create_new_namespaces(0, me, NULL,
			       current_user_ns(), NULL, me->fs, true);
	if (IS_ERR(nsset->nsproxy))
		return PTR_ERR(nsset->nsproxy);

	if (flags & CLONE_NEWUSER)
		nsset->cred = prepare_creds();
	else
		nsset->cred = current_cred();
	if (!nsset->cred)
		goto out;

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	nsset->lsm_ns = get_current_lsm_ns_checked();
	if (IS_ERR(nsset->lsm_ns)) {
		err = PTR_ERR(nsset->lsm_ns);
		nsset->lsm_ns = NULL;
		goto out;
	}
#else
	nsset->lsm_ns = NULL;
#endif

	/* Only create a temporary copy of fs_struct if we really need to. */
	if (flags == CLONE_NEWNS) {
		nsset->fs = me->fs;
	} else if (flags & CLONE_NEWNS) {
		nsset->fs = copy_fs_struct(me->fs);
		if (!nsset->fs)
			goto out;
	}

	return 0;

out:
	put_nsset(nsset);
	return err;
}

static int pidfd_install_vpsadminos_tracing_ns(struct nsset *nsset,
					       struct tracing_namespace *ns,
					       struct user_namespace *user_ns,
					       struct pid_namespace *pid_ns)
{
#ifdef CONFIG_TRACING_NS
	if (!ns)
		ns = &init_tracing_ns;

	if (nsset->nsproxy->tracing_ns == ns)
		return 0;

	if (ns != &init_tracing_ns) {
		if (!user_ns ||
		    (ns->user_ns != user_ns && user_ns != &init_user_ns))
			return -EPERM;
		if (!pid_ns || ns->pid_ns != pid_ns)
			return -EPERM;
	}

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	return auth_guard_nsproxy_install_owned(nsset->nsproxy, tracing_ns, ns,
						get_tracing_ns, put_tracing_ns);
#endif
	return 0;
}

static int pidfd_install_vpsadminos_syslog_ns(struct nsset *nsset,
					      struct syslog_namespace *ns,
					      struct user_namespace *user_ns)
{
#ifdef CONFIG_SYSLOG_NS
	int ret;

	if (!ns)
		ns = &init_syslog_ns;

	if (nsset->nsproxy->syslog_ns == ns)
		return 0;

	if (ns != &init_syslog_ns &&
	    (!user_ns ||
	     (ns->user_ns != user_ns && user_ns != &init_user_ns)))
		return -EPERM;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	ret = tracing_ns_check_syslogns_setns_from(ns,
						   nsset->nsproxy->tracing_ns);
	if (ret)
		return ret;

	return auth_guard_nsproxy_install_owned(nsset->nsproxy, syslog_ns, ns,
						get_syslog_ns, put_syslog_ns);
#endif
	return 0;
}

struct pidfd_nsproxy_snapshot {
	struct mnt_namespace *mnt_ns;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct cgroup_namespace *cgroup_ns;
	struct syslog_namespace *syslog_ns;
	struct tracing_namespace *tracing_ns;
};

static enum auth_guard_check_result
pidfd_nsproxy_snapshot_get(struct nsproxy *nsproxy, unsigned int flags,
			   struct pidfd_nsproxy_snapshot *snapshot)
{
	enum auth_guard_check_result result;

	memset(snapshot, 0, sizeof(*snapshot));
	result = auth_guard_nsproxy_snapshot_begin(nsproxy);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;

	snapshot->mnt_ns = READ_ONCE(nsproxy->mnt_ns);
	snapshot->uts_ns = READ_ONCE(nsproxy->uts_ns);
	snapshot->ipc_ns = READ_ONCE(nsproxy->ipc_ns);
	snapshot->net_ns = READ_ONCE(nsproxy->net_ns);
	snapshot->time_ns = READ_ONCE(nsproxy->time_ns);
	snapshot->cgroup_ns = READ_ONCE(nsproxy->cgroup_ns);
	snapshot->syslog_ns = READ_ONCE(nsproxy->syslog_ns);
	snapshot->tracing_ns = READ_ONCE(nsproxy->tracing_ns);

	if (((flags & CLONE_NEWNS) && !snapshot->mnt_ns) ||
	    ((flags & CLONE_NEWUTS) && !snapshot->uts_ns) ||
	    ((flags & CLONE_NEWIPC) && !snapshot->ipc_ns) ||
	    ((flags & CLONE_NEWNET) && !snapshot->net_ns) ||
	    ((flags & CLONE_NEWTIME) && !snapshot->time_ns) ||
	    ((flags & CLONE_NEWCGROUP) && !snapshot->cgroup_ns))
		result = AUTH_GUARD_CHECK_UNAVAILABLE;

	if (!auth_guard_nsproxy_snapshot_end(nsproxy))
		result = AUTH_GUARD_CHECK_INVALID;
	return result;
}

#if defined(CONFIG_TRACING_NS) || defined(CONFIG_SYSLOG_NS)
static bool pidfd_vpsadminos_user_matches(const struct user_namespace *ns_user,
					  const struct user_namespace *set_user)
{
	return ns_user == set_user || set_user == &init_user_ns;
}
#endif

static bool
pidfd_should_install_hidden(const struct pidfd_nsproxy_snapshot *target,
			    struct user_namespace *user_ns,
			    struct pid_namespace *pid_ns)
{
#ifdef CONFIG_TRACING_NS
	struct tracing_namespace *tracing_ns = target->tracing_ns;

	if (tracing_ns && tracing_ns != &init_tracing_ns) {
		return pid_ns == tracing_ns->pid_ns &&
			pidfd_vpsadminos_user_matches(tracing_ns->user_ns,
						      user_ns);
	}
#endif

#ifdef CONFIG_SYSLOG_NS
	if (target->syslog_ns && target->syslog_ns != &init_syslog_ns)
		return pidfd_vpsadminos_user_matches(target->syslog_ns->user_ns,
						     user_ns);
#endif

	return false;
}

static int pidfd_prepare_vpsadminos_namespaces(struct nsset *nsset,
					       const struct pidfd_nsproxy_snapshot *target,
					       struct user_namespace *user_ns,
					       struct pid_namespace *pid_ns,
					       struct user_namespace *target_user_ns,
					       struct pid_namespace *target_pid_ns)
{
	struct user_namespace *hidden_user_ns = user_ns;
	struct pid_namespace *hidden_pid_ns = pid_ns;
	bool install_hidden;
	int ret;

	if (!hidden_user_ns)
		hidden_user_ns = nsset->cred ? nsset->cred->user_ns : current_user_ns();
	if (!hidden_pid_ns)
		hidden_pid_ns = nsset->nsproxy->pid_ns_for_children;

	install_hidden = pidfd_should_install_hidden(target, hidden_user_ns,
						     hidden_pid_ns);
	if (!(nsset->flags & CLONE_NEWUSER) && !install_hidden)
		return 0;

	ret = pidfd_install_vpsadminos_tracing_ns(nsset, target->tracing_ns,
						  hidden_user_ns, hidden_pid_ns);
	if (ret)
		return ret;

	ret = pidfd_install_vpsadminos_syslog_ns(nsset, target->syslog_ns,
						 hidden_user_ns);
	if (ret)
		return ret;

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (nsset->flags & CLONE_NEWUSER) {
		struct lsm_namespace *lsm_ns;

		lsm_ns = get_lsm_ns_from_userns_checked(user_ns);
		if (IS_ERR(lsm_ns))
			return PTR_ERR(lsm_ns);
		put_lsm_ns(nsset->lsm_ns);
		nsset->lsm_ns = lsm_ns;
	}
#endif

	return 0;
}

static inline int validate_ns(struct nsset *nsset, struct ns_common *ns)
{
	return ns->ops->install(nsset, ns);
}

/*
 * This is the inverse operation to unshare().
 * Ordering is equivalent to the standard ordering used everywhere else
 * during unshare and process creation. The switch to the new set of
 * namespaces occurs at the point of no return after installation of
 * all requested namespaces was successful in commit_nsset().
 */
static int validate_nsset(struct nsset *nsset, struct pid *pid)
{
	int ret = 0;
	unsigned flags = nsset->flags;
	struct user_namespace *user_ns = NULL;
	struct user_namespace *target_user_ns = NULL;
	const struct cred *target_cred;
	enum auth_guard_check_result auth_result;
	struct pidfd_nsproxy_snapshot target_ns;
	struct pid_namespace *pid_ns = NULL;
	struct pid_namespace *target_pid_ns = NULL;
	struct nsproxy *nsp;
	struct task_struct *tsk;

	/* Take a "snapshot" of the target task's namespaces. */
	rcu_read_lock();
	tsk = pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}

	if (!ptrace_may_access(tsk, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		return -EPERM;
	}

retry_snapshot:
	target_cred = get_task_cred_checked(tsk);
	if (IS_ERR(target_cred)) {
		rcu_read_unlock();
		return PTR_ERR(target_cred);
	}

	task_lock(tsk);
	nsp = READ_ONCE(tsk->nsproxy);
	if (nsp)
		get_nsproxy(nsp);
	auth_result = auth_guard_task_check_real_cred(tsk, target_cred);
	if (auth_result == AUTH_GUARD_CHECK_VALID && nsp)
		auth_result = pidfd_nsproxy_snapshot_get(nsp, flags, &target_ns);
	task_unlock(tsk);
	if (auth_result != AUTH_GUARD_CHECK_VALID) {
		if (nsp)
			put_nsproxy(nsp);
		put_cred(target_cred);
		if (auth_result == AUTH_GUARD_CHECK_BUSY) {
			cpu_relax();
			goto retry_snapshot;
		}
		rcu_read_unlock();
		return -EPERM;
	}
	if (!nsp) {
		put_cred(target_cred);
		rcu_read_unlock();
		return -ESRCH;
	}

#ifdef CONFIG_PID_NS
	target_pid_ns = task_active_pid_ns(tsk);
	if (unlikely(!target_pid_ns)) {
		put_cred(target_cred);
		rcu_read_unlock();
		ret = -ESRCH;
		goto out;
	}
	get_pid_ns(target_pid_ns);

	if (flags & CLONE_NEWPID) {
		pid_ns = get_pid_ns(target_pid_ns);
	}
#endif

#ifdef CONFIG_USER_NS
	target_user_ns = get_user_ns(target_cred->user_ns);
	if (flags & CLONE_NEWUSER)
		user_ns = get_user_ns(target_user_ns);
#endif
	put_cred(target_cred);
	rcu_read_unlock();

	ret = pidfd_prepare_vpsadminos_namespaces(nsset, &target_ns, user_ns,
						  pid_ns,
						  target_user_ns,
						  target_pid_ns);
	if (ret)
		goto out;

	/*
	 * Install requested namespaces. The caller will have
	 * verified earlier that the requested namespaces are
	 * supported on this kernel. We don't report errors here
	 * if a namespace is requested that isn't supported.
	 */
#ifdef CONFIG_USER_NS
	if (flags & CLONE_NEWUSER) {
		ret = validate_ns(nsset, &user_ns->ns);
		if (ret)
			goto out;
	}
#endif

	if (flags & CLONE_NEWNS) {
		ret = validate_ns(nsset, from_mnt_ns(target_ns.mnt_ns));
		if (ret)
			goto out;
	}

#ifdef CONFIG_UTS_NS
	if (flags & CLONE_NEWUTS) {
		ret = validate_ns(nsset, &target_ns.uts_ns->ns);
		if (ret)
			goto out;
	}
#endif

#ifdef CONFIG_IPC_NS
	if (flags & CLONE_NEWIPC) {
		ret = validate_ns(nsset, &target_ns.ipc_ns->ns);
		if (ret)
			goto out;
	}
#endif

#ifdef CONFIG_PID_NS
	if (flags & CLONE_NEWPID) {
		ret = validate_ns(nsset, &pid_ns->ns);
		if (ret)
			goto out;
	}
#endif

#ifdef CONFIG_CGROUPS
	if (flags & CLONE_NEWCGROUP) {
		ret = validate_ns(nsset, &target_ns.cgroup_ns->ns);
		if (ret)
			goto out;
	}
#endif

#ifdef CONFIG_NET_NS
	if (flags & CLONE_NEWNET) {
		ret = validate_ns(nsset, &target_ns.net_ns->ns);
		if (ret)
			goto out;
	}
#endif

#ifdef CONFIG_TIME_NS
	if (flags & CLONE_NEWTIME) {
		ret = validate_ns(nsset, &target_ns.time_ns->ns);
		if (ret)
			goto out;
	}
#endif

out:
	if (pid_ns)
		put_pid_ns(pid_ns);
	if (target_pid_ns)
		put_pid_ns(target_pid_ns);
	if (nsp)
		put_nsproxy(nsp);
	put_user_ns(user_ns);
	put_user_ns(target_user_ns);

	return ret;
}

/*
 * This is the point of no return. There are just a few namespaces
 * that do some actual work here and it's sufficiently minimal that
 * a separate ns_common operation seems unnecessary for now.
 * Unshare is doing the same thing. If we'll end up needing to do
 * more in a given namespace or a helper here is ultimately not
 * exported anymore a simple commit handler for each namespace
 * should be added to ns_common.
 */
static int commit_nsset(struct nsset *nsset)
{
	unsigned flags = nsset->flags;
	struct task_struct *me = current;
	struct auth_guard_task_lsm_request detached_lsm = {
		.lsmid = LSM_ID_UNDEF,
	};
	struct nsproxy *old_nsproxy;
	enum auth_guard_mutation_result mutation;
#ifdef CONFIG_USER_NS
	int ret;
#endif

#ifdef CONFIG_USER_NS
	if (flags & CLONE_NEWUSER) {
		struct cred *cred = nsset_cred(nsset);

		ret = cred_guard_preflight_commit_creds(cred);
		if (ret)
			return ret;
	}
#endif

	if (!auth_guard_nsproxy_check(nsset->nsproxy))
		return -EACCES;

	if (!(flags & CLONE_NEWUSER ?
	      cred_guard_task_begin_consuming_transition(me) :
	      auth_guard_task_begin_transition(me)))
		return -EACCES;

#ifdef CONFIG_USER_NS
	if (flags & CLONE_NEWUSER) {
		struct cred *cred = nsset_cred(nsset);

		ret = commit_creds_in_task_transition(cred, &detached_lsm);
		nsset->cred = NULL;
		if (ret) {
			auth_guard_task_abort_transition(me);
			lsm_ns_release_pending_child_request(&detached_lsm);
			return ret;
		}
	}
#endif

	/* We only need to commit if we have used a temporary fs_struct. */
	if ((flags & CLONE_NEWNS) && (flags & ~CLONE_NEWNS)) {
		set_fs_root(me->fs, &nsset->fs->root);
		set_fs_pwd(me->fs, &nsset->fs->pwd);
	}

#ifdef CONFIG_IPC_NS
	if (flags & CLONE_NEWIPC)
		exit_sem(me);
#endif

#ifdef CONFIG_TIME_NS
	if (flags & CLONE_NEWTIME)
		timens_commit(me, nsset->nsproxy->time_ns);
#endif

	/* transfer ownership */
	task_lock(me);
	mutation = auth_guard_task_replace_nsproxy_in_transition(
		me, nsset->nsproxy, &old_nsproxy);
	AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	AUTH_GUARD_FAIL_STOP_UNLESS(auth_guard_task_finish_transition(me));
	task_unlock(me);

	if (old_nsproxy)
		put_nsproxy(old_nsproxy);
	nsset->nsproxy = NULL;
	lsm_ns_release_pending_child_request(&detached_lsm);
	return 0;
}

SYSCALL_DEFINE2(setns, int, fd, int, flags)
{
	CLASS(fd, f)(fd);
	struct ns_common *ns = NULL;
	struct nsset nsset = {};
	int err = 0;

	if (fd_empty(f))
		return -EBADF;

	err = security_file_permission(fd_file(f), MAY_READ);
	if (err)
		goto out;

	if (proc_ns_file(fd_file(f))) {
		ns = get_proc_ns(file_inode(fd_file(f)));
		if (flags && (ns->ns_type != flags))
			err = -EINVAL;
		flags = ns->ns_type;
	} else if (!IS_ERR(pidfd_pid(fd_file(f)))) {
		err = check_setns_flags(flags);
	} else {
		err = -EINVAL;
	}
	if (err)
		goto out;

	err = prepare_nsset(flags, &nsset);
	if (err)
		goto out;

	if (proc_ns_file(fd_file(f)))
		err = validate_ns(&nsset, ns);
	else
		err = validate_nsset(&nsset, pidfd_pid(fd_file(f)));
	if (!err) {
		err = commit_nsset(&nsset);
		if (err)
			goto put_nsset;
		perf_event_namespaces(current);
	}
put_nsset:
	put_nsset(&nsset);
out:
	return err;
}

int __init nsproxy_cache_init(void)
{
	nsproxy_cachep = KMEM_CACHE(nsproxy, SLAB_PANIC|SLAB_ACCOUNT);
	return 0;
}
