// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_namespace.h>
#include <linux/nstree.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

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

struct lsm_namespace *current_lsm_ns(void)
{
	struct user_namespace *user_ns = current_user_ns();

	if (user_ns && user_ns->lsm_ns)
		return user_ns->lsm_ns;

	return &init_lsm_ns;
}
EXPORT_SYMBOL_GPL(current_lsm_ns);

static void delayed_free_lsm_ns(struct rcu_head *head)
{
	struct ns_common *common = container_of(head, struct ns_common, ns_rcu);
	struct lsm_namespace *ns = to_lsm_ns(common);

	kfree(ns);
}

void free_lsm_ns(struct lsm_namespace *ns)
{
	if (WARN_ON_ONCE(ns == &init_lsm_ns))
		return;

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

int lsm_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	struct lsm_namespace *target_ns, *current_ns;

	if (!user_ns)
		return -EINVAL;

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

	if (user_ns != current_user_ns() && user_ns->lsm_ns == old_ns) {
		put_lsm_ns(user_ns->lsm_ns);
		user_ns->lsm_ns = get_lsm_ns(ns);
	}

	__ns_tree_add(&ns->ns, &lsm_ns_tree);

	pr_notice("lsm_ns: create ns=%u parent=%u user=%u lsm=%llu\n",
		  ns->ns.inum,
		  old_ns ? old_ns->ns.inum : 0,
		  user_ns->ns.inum,
		  (unsigned long long)lsmid);

	return ns;

fail_free:
	kfree(ns);
	return ERR_PTR(err);
}

struct lsm_namespace *copy_lsm_ns(bool new_child, struct user_namespace *user_ns,
				  u64 lsmid,
				  struct lsm_namespace *old_ns)
{
	if (!old_ns)
		old_ns = &init_lsm_ns;

	if (!new_child)
		return get_lsm_ns(old_ns);

	if (!user_ns)
		return ERR_PTR(-EINVAL);

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

	return clone_lsm_ns(user_ns, lsmid, old_ns);
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

int setup_lsm_namespace(struct lsm_namespace *ns)
{
	if (ns == &init_lsm_ns)
		__ns_tree_add(&ns->ns, &lsm_ns_tree);

	return 0;
}
EXPORT_SYMBOL_GPL(setup_lsm_namespace);

static int __init lsm_namespaces_init(void)
{
	return setup_lsm_namespace(&init_lsm_ns);
}
subsys_initcall(lsm_namespaces_init);
