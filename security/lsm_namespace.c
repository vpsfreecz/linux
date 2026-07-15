// SPDX-License-Identifier: GPL-2.0
#include <linux/auth_guard.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_namespace.h>
#include <linux/nsproxy.h>
#include <linux/nstree.h>
#include <linux/overflow.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syslog_namespace.h>
#include <linux/user_namespace.h>

static DEFINE_MUTEX(lsm_ns_backend_lock);
static const struct lsm_namespace_backend *lsm_ns_backends[2];

static bool lsm_ns_restricts_visibility(const struct lsm_namespace *ns)
{
	return ns && ns != &init_lsm_ns && ns->lsmid != LSM_ID_UNDEF;
}

static bool lsm_ns_is_managed_major(u64 lsmid)
{
	switch (lsmid) {
	case LSM_ID_APPARMOR:
	case LSM_ID_SELINUX:
		return true;
	default:
		return false;
	}
}

struct lsm_namespace init_lsm_ns = {
	.user_ns = &init_user_ns,
	.parent = NULL,
	.lsmid = LSM_ID_UNDEF,
	.backend_data = NULL,
	.ns = {
		.ns_type = LSM_NS_TYPE,
		.__ns_ref = REFCOUNT_INIT(2),
		.ops = &lsmns_operations,
		.inum = LSM_NS_INIT_INO,
	},
};
EXPORT_SYMBOL_GPL(init_lsm_ns);

static bool lsm_ns_valid_lsmid(u64 lsmid)
{
	switch (lsmid) {
	case LSM_ID_APPARMOR:
	case LSM_ID_SELINUX:
		return true;
	}

	return false;
}

static int lsm_ns_backend_slot(u64 lsmid)
{
	switch (lsmid) {
	case LSM_ID_APPARMOR:
		return 0;
	case LSM_ID_SELINUX:
		return 1;
	default:
		return -EINVAL;
	}
}

static const struct lsm_namespace_backend *lsm_ns_backend_lookup(u64 lsmid)
{
	int slot = lsm_ns_backend_slot(lsmid);

	if (slot < 0)
		return NULL;

	return READ_ONCE(lsm_ns_backends[slot]);
}

int register_lsm_namespace_backend(const struct lsm_namespace_backend *backend)
{
	int slot;

	if (!backend || !backend->create || !backend->destroy)
		return -EINVAL;

	if (!lsm_ns_valid_lsmid(backend->lsmid))
		return -EOPNOTSUPP;

	slot = lsm_ns_backend_slot(backend->lsmid);
	if (slot < 0)
		return slot;

	mutex_lock(&lsm_ns_backend_lock);
	if (lsm_ns_backends[slot]) {
		mutex_unlock(&lsm_ns_backend_lock);
		return -EEXIST;
	}

	WRITE_ONCE(lsm_ns_backends[slot], backend);
	mutex_unlock(&lsm_ns_backend_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(register_lsm_namespace_backend);

DEFINE_USERNS_BOUNDARY_GETTER(get_lsm_ns_from_userns_checked, lsm_namespace,
			      lsm_ns, get_lsm_ns, put_lsm_ns, &init_lsm_ns)

struct lsm_namespace *current_lsm_ns(void)
{
	struct auth_guard_userns_boundary boundary;
	struct user_namespace *user_ns;
	struct lsm_namespace *ns;

	user_ns = get_current_user_ns_checked();
	if (IS_ERR(user_ns))
		return NULL;
	if (auth_guard_userns_boundary_snapshot_begin(user_ns) !=
	    AUTH_GUARD_CHECK_VALID) {
		put_user_ns(user_ns);
		return NULL;
	}
	auth_guard_userns_boundary_read(user_ns, &boundary);
	ns = boundary.lsm_ns ?: &init_lsm_ns;
	if (!auth_guard_userns_boundary_snapshot_end(user_ns))
		ns = NULL;
	put_user_ns(user_ns);
	if (!ns)
		return NULL;

	return ns;
}
EXPORT_SYMBOL_GPL(current_lsm_ns);

struct lsm_namespace *get_current_lsm_ns_checked_where(const char *where)
{
	struct user_namespace *user_ns;
	struct lsm_namespace *ns;

	user_ns = get_current_user_ns_checked_where(where);
	if (IS_ERR(user_ns))
		return ERR_CAST(user_ns);
	ns = get_lsm_ns_from_userns_checked_where(user_ns, where);
	put_user_ns(user_ns);

	return ns;
}
EXPORT_SYMBOL_GPL(get_current_lsm_ns_checked_where);

bool lsm_ns_visible_lsmid(u64 lsmid)
{
	struct lsm_namespace *ns __free(put_lsm_ns) =
		get_current_lsm_ns_checked();
	bool visible;

	if (IS_ERR(ns))
		return false;
	visible = !lsm_ns_restricts_visibility(ns) ||
		!lsm_ns_is_managed_major(lsmid) || ns->lsmid == lsmid;

	return visible;
}
EXPORT_SYMBOL_GPL(lsm_ns_visible_lsmid);

void lsm_ns_release_pending_child_request(struct auth_guard_task_lsm_request *saved)
{
	if (!saved)
		return;

	kfree(saved->ctx);
	*saved = (struct auth_guard_task_lsm_request) {
		.lsmid = LSM_ID_UNDEF,
	};
}

enum auth_guard_mutation_result
lsm_ns_clear_pending_child_request_in_transition_where(
	struct task_struct *task, struct auth_guard_task_lsm_request *saved,
	const char *where)
{
	struct auth_guard_task_lsm_request replacement = {
		.lsmid = LSM_ID_UNDEF,
	};

	if (!task)
		return AUTH_GUARD_MUTATION_REJECTED;

	return auth_guard_task_replace_lsm_request_in_transition_where(
		task, &replacement, saved, where);
}

int lsm_ns_clear_pending_child_request(struct task_struct *task)
{
	struct auth_guard_task_lsm_request replacement = {
		.lsmid = LSM_ID_UNDEF,
	};
	struct auth_guard_task_lsm_request old_request;
	enum auth_guard_mutation_result mutation;

	if (!task)
		return 0;

	mutation = auth_guard_task_replace_lsm_request(task, &replacement,
						       &old_request);
	if (mutation == AUTH_GUARD_MUTATION_REJECTED)
		return -EACCES;
	AUTH_GUARD_QUARANTINE_FAIL_STOP(mutation);
	lsm_ns_release_pending_child_request(&old_request);
	return 0;
}
EXPORT_SYMBOL_GPL(lsm_ns_clear_pending_child_request);

struct syslog_namespace *lsm_ns_get_current_syslog_route_lsm(u64 lsmid)
{
	struct auth_guard_userns_boundary boundary;
	struct lsm_namespace *owner_lsm_ns __free(put_lsm_ns) = NULL;
	struct syslog_namespace *result = NULL;

	if (get_current_namespace_boundary_owner(&boundary, &owner_lsm_ns))
		return NULL;

	if (boundary.lsm_ns == &init_lsm_ns || boundary.lsm_ns->lsmid != lsmid)
		goto out;

	if (boundary.syslog_ns == &init_syslog_ns || !owner_lsm_ns)
		goto out;

	/*
	 * Route guest-visible denials only when the active syslog namespace is
	 * owned by a user namespace bound to the same managed LSM namespace as
	 * the current task. This keeps foreign syslog setns() targets and the
	 * host log stream out of guest-denial mirroring.
	 */
	if (owner_lsm_ns == boundary.lsm_ns) {
		result = boundary.syslog_ns;
		boundary.syslog_ns = NULL;
	}

out:
	put_namespace_boundary(&boundary);
	return result;
}
EXPORT_SYMBOL_GPL(lsm_ns_get_current_syslog_route_lsm);

int lsm_ns_prepare_unshare(const struct lsm_ctx *ctx)
{
	const struct lsm_namespace_backend *backend;
	struct auth_guard_task_lsm_request old_request;
	struct auth_guard_task_lsm_request replacement;
	struct lsm_namespace *current_ns __free(put_lsm_ns) = NULL;
	struct lsm_ctx *copy;
	enum auth_guard_mutation_result mutation;
	u64 lsmid;
	u64 required_len;
	int err;

	if (!ctx || ctx->len < sizeof(*ctx))
		return -EINVAL;
	if (ctx->flags)
		return -EINVAL;
	if (check_add_overflow(sizeof(*ctx), ctx->ctx_len, &required_len) ||
	    ctx->len != required_len)
		return -EINVAL;
	current_ns = get_current_lsm_ns_checked();
	if (IS_ERR(current_ns))
		return PTR_ERR(current_ns);
	if (current_ns != &init_lsm_ns)
		return -EPERM;

	lsmid = ctx->id;
	if (!lsm_ns_valid_lsmid(lsmid))
		return -EOPNOTSUPP;

	backend = lsm_ns_backend_lookup(lsmid);
	if (!backend)
		return -EOPNOTSUPP;

	if (!capable(CAP_SYS_ADMIN)) {
		if (!backend->prepare_unshare)
			return -EPERM;

		err = backend->prepare_unshare(ctx);
		if (err)
			return err;
	}

	copy = kmemdup(ctx, ctx->len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	replacement = (struct auth_guard_task_lsm_request) {
		.enabled = true,
		.lsmid = lsmid,
		.ctx = copy,
		.ctx_len = ctx->len,
	};
	mutation = auth_guard_task_replace_lsm_request(current, &replacement,
						       &old_request);
	if (mutation == AUTH_GUARD_MUTATION_REJECTED) {
		kfree(copy);
		return -EACCES;
	}
	AUTH_GUARD_QUARANTINE_FAIL_STOP(mutation);
	lsm_ns_release_pending_child_request(&old_request);

	pr_notice("lsm_ns: arm child create current=%u lsm=%llu\n",
		  init_lsm_ns.ns.inum,
		  (unsigned long long)lsmid);
	return 0;
}
EXPORT_SYMBOL_GPL(lsm_ns_prepare_unshare);

int lsm_ns_install_userns(struct user_namespace *user_ns,
			  struct task_struct *task, struct cred *new_cred)
{
	const struct lsm_namespace_backend *backend;
	struct lsm_namespace *ns __free(put_lsm_ns) = NULL;

	if (!user_ns || !task || !new_cred)
		return -EINVAL;

	ns = get_lsm_ns_from_userns_checked(user_ns);
	if (IS_ERR(ns))
		return PTR_ERR(ns);
	if (ns == &init_lsm_ns)
		return 0;

	backend = lsm_ns_backend_lookup(ns->lsmid);
	if (!backend)
		return -EOPNOTSUPP;
	if (!backend->install)
		return 0;

	return backend->install(ns, task, new_cred);
}
EXPORT_SYMBOL_GPL(lsm_ns_install_userns);

static void delayed_free_lsm_ns(struct rcu_head *head)
{
	struct ns_common *common = container_of(head, struct ns_common, ns_rcu);
	struct lsm_namespace *ns = to_lsm_ns(common);

	kfree(ns);
}

void free_lsm_ns(struct lsm_namespace *ns)
{
	const struct lsm_namespace_backend *backend;

	if (WARN_ON_ONCE(ns == &init_lsm_ns))
		return;

	backend = lsm_ns_backend_lookup(ns->lsmid);
	if (backend && ns->backend_data)
		backend->destroy(ns);

	if (ns_tree_active(ns))
		ns_tree_remove(ns);

	pr_notice("lsm_ns: destroy ns=%u user=%u lsm=%llu\n",
		  ns->ns.inum,
		  ns->user_ns ? ns->user_ns->ns.inum : 0,
		  (unsigned long long)ns->lsmid);

	put_lsm_ns(ns->parent);
	put_user_ns(ns->user_ns);
	ns_common_free(ns);
	call_rcu(&ns->ns.ns_rcu, delayed_free_lsm_ns);
}
EXPORT_SYMBOL_GPL(free_lsm_ns);

int lsm_ns_check_userns_setns_from(const struct user_namespace *user_ns,
					   const struct lsm_namespace *current_ns)
{
	struct lsm_namespace *target_ns __free(put_lsm_ns) = NULL;

	if (!user_ns)
		return -EINVAL;

	if (!current_ns)
		return -EACCES;
	target_ns = get_lsm_ns_from_userns_checked(user_ns);
	if (IS_ERR(target_ns))
		return PTR_ERR(target_ns);
	if (target_ns == current_ns)
		return 0;

	pr_notice("lsm_ns: reject userns setns current=%u target_user=%u target_lsm=%u\n",
		  current_ns ? current_ns->ns.inum : 0,
		      user_ns->ns.inum,
		      target_ns->ns.inum);
	return -EPERM;
}
EXPORT_SYMBOL_GPL(lsm_ns_check_userns_setns_from);

int lsm_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	struct lsm_namespace *current_ns __free(put_lsm_ns) =
		get_current_lsm_ns_checked();

	if (IS_ERR(current_ns))
		return PTR_ERR(current_ns);
	return lsm_ns_check_userns_setns_from(user_ns, current_ns);
}
EXPORT_SYMBOL_GPL(lsm_ns_check_userns_setns);

static struct lsm_namespace *
clone_lsm_ns(struct user_namespace *user_ns, u64 lsmid,
	     struct lsm_namespace *old_ns)
{
	struct lsm_namespace *ns;
	int err;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	err = __ns_common_init(&ns->ns, LSM_NS_TYPE, &lsmns_operations, 0);
	if (err)
		goto fail_free;

	ns->user_ns = get_user_ns(user_ns);
	ns->parent = get_lsm_ns(old_ns);
	ns->lsmid = lsmid;
	ns->backend_data = NULL;

	return ns;

fail_free:
	kfree(ns);
	return ERR_PTR(err);
}

DEFINE_USERNS_BOUNDARY_REPLACER(lsm_ns_replace_userns_default,
				lsm_namespace, lsm_ns,
				get_lsm_ns, put_lsm_ns)

struct lsm_namespace *copy_lsm_ns(bool new_child, struct user_namespace *user_ns,
				  struct task_struct *task, struct cred *new_cred,
				  const struct lsm_ctx *ctx,
				  struct lsm_namespace *old_ns)
{
	struct lsm_namespace *ns;
	struct lsm_namespace *user_lsm_ns __free(put_lsm_ns) = NULL;
	enum auth_guard_mutation_result mutation;
	u64 lsmid;
	int err;

	if (!old_ns)
		old_ns = &init_lsm_ns;

	if (new_child && !new_cred)
		return ERR_PTR(-EINVAL);

	if (!new_child)
		return get_lsm_ns(old_ns);

	if (!user_ns || !ctx)
		return ERR_PTR(-EINVAL);

	lsmid = ctx->id;
	if (!lsm_ns_valid_lsmid(lsmid))
		return ERR_PTR(-EOPNOTSUPP);

	if (old_ns != &init_lsm_ns) {
		pr_notice("lsm_ns: reject nested create parent=%u user=%u lsm=%llu\n",
			  old_ns->ns.inum,
			  user_ns->ns.inum,
			  (unsigned long long)lsmid);
		return ERR_PTR(-EPERM);
	}

	if (user_ns == current_user_ns()) {
		pr_notice("lsm_ns: reject create without new userns current=%u user=%u lsm=%llu\n",
			  old_ns->ns.inum, user_ns->ns.inum,
			  (unsigned long long)lsmid);
		return ERR_PTR(-EINVAL);
	}

	if (user_ns == &init_user_ns || user_ns->parent != &init_user_ns)
		return ERR_PTR(-EPERM);

	user_lsm_ns = get_lsm_ns_from_userns_checked(user_ns);
	if (IS_ERR(user_lsm_ns))
		return ERR_CAST(user_lsm_ns);
	if (user_lsm_ns != old_ns)
		return ERR_PTR(-EINVAL);

	ns = clone_lsm_ns(user_ns, lsmid, old_ns);
	if (IS_ERR(ns))
		return ns;

	err = setup_lsm_namespace(ns, task, new_cred, ctx);
	if (err) {
		put_lsm_ns(ns);
		return ERR_PTR(err);
	}

	mutation = lsm_ns_replace_userns_default(user_ns, old_ns, ns);
	if (mutation == AUTH_GUARD_MUTATION_QUARANTINED)
		return ERR_PTR(-EACCES);
	if (mutation != AUTH_GUARD_MUTATION_APPLIED) {
		put_lsm_ns(ns);
		return ERR_PTR(-EACCES);
	}
	return ns;
}
EXPORT_SYMBOL_GPL(copy_lsm_ns);

static struct ns_common *lsmns_get(struct task_struct *task)
{
	const struct cred *cred __free(put_cred) = get_task_cred_checked(task);
	struct lsm_namespace *ns = NULL;
	struct user_namespace *user_ns;

	if (IS_ERR(cred))
		return NULL;

	user_ns = cred->user_ns;
	ns = get_lsm_ns_from_userns_checked(user_ns);
	if (IS_ERR(ns))
		return NULL;

	return &ns->ns;
}

static void lsmns_put(struct ns_common *ns)
{
	put_lsm_ns(to_lsm_ns(ns));
}

static int lsmns_install(struct nsset *nsset, struct ns_common *new)
{
	struct lsm_namespace *current_ns __free(put_lsm_ns) =
		get_current_lsm_ns_checked();
	struct lsm_namespace *ns = to_lsm_ns(new);
	unsigned int current_inum = 0;

	(void)nsset;

	if (!IS_ERR(current_ns))
		current_inum = current_ns->ns.inum;
	pr_notice("lsm_ns: reject direct setns current=%u target=%u\n",
		  current_inum, ns->ns.inum);
	return -EPERM;
}

static struct user_namespace *lsmns_owner(struct ns_common *ns)
{
	return to_lsm_ns(ns)->user_ns;
}

static bool lsmns_contains(const struct lsm_namespace *ancestor,
			   const struct lsm_namespace *ns)
{
	while (ns) {
		if (ns == ancestor)
			return true;
		ns = ns->parent;
	}

	return false;
}

static struct ns_common *lsmns_get_parent(struct ns_common *ns)
{
	struct lsm_namespace *parent;
	struct lsm_namespace *caller_ns __free(put_lsm_ns) =
		get_current_lsm_ns_checked();
	struct ns_common *ret;

	if (IS_ERR(caller_ns))
		return ERR_CAST(caller_ns);
	parent = to_lsm_ns(ns)->parent;
	if (!parent)
		ret = ERR_PTR(-EPERM);
	else if (!lsmns_contains(caller_ns, parent))
		ret = ERR_PTR(-EPERM);
	else
		ret = &get_lsm_ns(parent)->ns;

	return ret;
}

const struct proc_ns_operations lsmns_operations = {
	.name		= "lsm",
	.get		= lsmns_get,
	.put		= lsmns_put,
	.install	= lsmns_install,
	.owner		= lsmns_owner,
	.get_parent	= lsmns_get_parent,
};
EXPORT_SYMBOL_GPL(lsmns_operations);

int setup_lsm_namespace(struct lsm_namespace *ns, struct task_struct *task,
			struct cred *new_cred, const struct lsm_ctx *ctx)
{
	const struct lsm_namespace_backend *backend;
	int err;

	if (ns == &init_lsm_ns) {
		__ns_tree_add(&ns->ns, &lsm_ns_tree);
		return 0;
	}

	backend = lsm_ns_backend_lookup(ns->lsmid);
	if (!backend)
		return -EOPNOTSUPP;

	err = backend->create(ns, task, new_cred, ctx);
	if (err)
		return err;

	__ns_tree_add(&ns->ns, &lsm_ns_tree);

	pr_notice("lsm_ns: create ns=%u parent=%u user=%u lsm=%llu\n",
		  ns->ns.inum,
		  ns->parent ? ns->parent->ns.inum : 0,
		  ns->user_ns ? ns->user_ns->ns.inum : 0,
		  (unsigned long long)ns->lsmid);

	return 0;
}
EXPORT_SYMBOL_GPL(setup_lsm_namespace);

static int __init lsm_namespaces_init(void)
{
	return setup_lsm_namespace(&init_lsm_ns, NULL, NULL, NULL);
}
subsys_initcall(lsm_namespaces_init);
