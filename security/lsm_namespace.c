// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_namespace.h>
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

struct lsm_namespace *current_lsm_ns(void)
{
	struct user_namespace *user_ns = current_user_ns();

	if (user_ns && user_ns->lsm_ns)
		return user_ns->lsm_ns;

	return &init_lsm_ns;
}
EXPORT_SYMBOL_GPL(current_lsm_ns);

bool lsm_ns_visible_lsmid(u64 lsmid)
{
	struct lsm_namespace *ns = current_lsm_ns();

	if (!lsm_ns_restricts_visibility(ns))
		return true;

	if (!lsm_ns_is_managed_major(lsmid))
		return true;

	return ns->lsmid == lsmid;
}
EXPORT_SYMBOL_GPL(lsm_ns_visible_lsmid);

void lsm_ns_clear_pending_child_request(struct task_struct *task)
{
	if (!task)
		return;

	task->lsm_ns_for_child = false;
	task->lsm_ns_for_child_lsmid = LSM_ID_UNDEF;
	kfree(task->lsm_ns_for_child_ctx);
	task->lsm_ns_for_child_ctx = NULL;
}
EXPORT_SYMBOL_GPL(lsm_ns_clear_pending_child_request);

bool lsm_ns_current_syslog_routes_lsm(u64 lsmid)
{
	struct lsm_namespace *lsm_ns = current_lsm_ns();
	struct syslog_namespace *syslog_ns = current_syslog_ns();
	struct lsm_namespace *owner_lsm_ns;

	if (!lsm_ns || lsm_ns == &init_lsm_ns || lsm_ns->lsmid != lsmid)
		return false;

	if (!syslog_ns || syslog_ns == &init_syslog_ns || !syslog_ns->user_ns)
		return false;

	owner_lsm_ns = READ_ONCE(syslog_ns->user_ns->lsm_ns);
	if (!owner_lsm_ns)
		owner_lsm_ns = &init_lsm_ns;

	/*
	 * Route guest-visible denials only when the active syslog namespace is
	 * owned by a user namespace bound to the same managed LSM namespace as
	 * the current task. This keeps foreign syslog setns() targets and the
	 * host log stream out of guest-denial mirroring.
	 */
	return owner_lsm_ns == lsm_ns;
}
EXPORT_SYMBOL_GPL(lsm_ns_current_syslog_routes_lsm);

int lsm_ns_prepare_unshare(const struct lsm_ctx *ctx)
{
	const struct lsm_namespace_backend *backend;
	struct lsm_ctx *copy;
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
	if (current_lsm_ns() != &init_lsm_ns)
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

	lsm_ns_clear_pending_child_request(current);
	current->lsm_ns_for_child = true;
	current->lsm_ns_for_child_lsmid = lsmid;
	current->lsm_ns_for_child_ctx = copy;

	pr_notice("lsm_ns: arm child create current=%u lsm=%llu\n",
		  current_lsm_ns()->ns.inum,
		  (unsigned long long)lsmid);
	return 0;
}
EXPORT_SYMBOL_GPL(lsm_ns_prepare_unshare);

int lsm_ns_install_userns(struct user_namespace *user_ns,
			  struct task_struct *task, struct cred *new_cred)
{
	const struct lsm_namespace_backend *backend;
	struct lsm_namespace *ns;

	if (!user_ns || !task || !new_cred)
		return -EINVAL;

	ns = user_ns->lsm_ns ? user_ns->lsm_ns : &init_lsm_ns;
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
	struct lsm_namespace *target_ns;

	if (!user_ns)
		return -EINVAL;

	if (!current_ns)
		current_ns = current_lsm_ns();
	target_ns = user_ns->lsm_ns ? user_ns->lsm_ns : &init_lsm_ns;
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
	return lsm_ns_check_userns_setns_from(user_ns, current_lsm_ns());
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

static void lsm_ns_attach_userns(struct lsm_namespace *ns,
				 struct user_namespace *user_ns,
				 struct lsm_namespace *old_ns)
{
	if (user_ns != current_user_ns() && user_ns->lsm_ns == old_ns) {
		put_lsm_ns(user_ns->lsm_ns);
		user_ns->lsm_ns = get_lsm_ns(ns);
	}
}

struct lsm_namespace *copy_lsm_ns(bool new_child, struct user_namespace *user_ns,
				  struct task_struct *task, struct cred *new_cred,
				  const struct lsm_ctx *ctx,
				  struct lsm_namespace *old_ns)
{
	struct lsm_namespace *ns;
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

	if (user_ns->lsm_ns != old_ns)
		return ERR_PTR(-EINVAL);

	ns = clone_lsm_ns(user_ns, lsmid, old_ns);
	if (IS_ERR(ns))
		return ns;

	err = setup_lsm_namespace(ns, task, new_cred, ctx);
	if (err) {
		put_lsm_ns(ns);
		return ERR_PTR(err);
	}

	lsm_ns_attach_userns(ns, user_ns, old_ns);
	return ns;
}
EXPORT_SYMBOL_GPL(copy_lsm_ns);

static struct ns_common *lsmns_get(struct task_struct *task)
{
	struct lsm_namespace *ns = &init_lsm_ns;
	struct user_namespace *user_ns;

	rcu_read_lock();
	user_ns = __task_cred(task)->user_ns;
	if (user_ns && user_ns->lsm_ns)
		ns = user_ns->lsm_ns;
	get_lsm_ns(ns);
	rcu_read_unlock();

	return &ns->ns;
}

static void lsmns_put(struct ns_common *ns)
{
	put_lsm_ns(to_lsm_ns(ns));
}

static int lsmns_install(struct nsset *nsset, struct ns_common *new)
{
	struct lsm_namespace *ns = to_lsm_ns(new);

	(void)nsset;

	pr_notice("lsm_ns: reject direct setns current=%u target=%u\n",
		  current_lsm_ns()->ns.inum,
		  ns->ns.inum);
	return -EPERM;
}

static struct user_namespace *lsmns_owner(struct ns_common *ns)
{
	return to_lsm_ns(ns)->user_ns;
}

static struct ns_common *lsmns_get_parent(struct ns_common *ns)
{
	struct lsm_namespace *parent = to_lsm_ns(ns)->parent;

	if (!parent)
		return ERR_PTR(-EPERM);

	return &get_lsm_ns(parent)->ns;
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
