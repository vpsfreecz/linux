// SPDX-License-Identifier: GPL-2.0
#include "cgroup-internal.h"

#include <linux/auth_guard.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/nstree.h>

/* cgroup namespaces */

static struct ucounts *inc_cgroup_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_CGROUP_NAMESPACES);
}

static void dec_cgroup_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_CGROUP_NAMESPACES);
}

static struct cgroup_namespace *alloc_cgroup_ns(void)
{
	struct cgroup_namespace *new_ns __free(kfree) = NULL;
	int ret;

	new_ns = kzalloc(sizeof(struct cgroup_namespace), GFP_KERNEL_ACCOUNT);
	if (!new_ns)
		return ERR_PTR(-ENOMEM);
	ret = ns_common_init(new_ns);
	if (ret)
		return ERR_PTR(ret);

	INIT_LIST_HEAD(&new_ns->cgns_avenrun_list);
	atomic_set(&new_ns->nr_uninterruptible, 0);
	new_ns->avenrun[0] = 0;
	new_ns->avenrun[1] = 0;
	new_ns->avenrun[2] = 0;
	mutex_init(&new_ns->cgns_avenrun_lock);

	return no_free_ptr(new_ns);
}

int cgroup_ns_publish(struct cgroup_namespace *ns)
{
	if (!ns)
		return -EINVAL;
	if (WARN_ON_ONCE(ns_tree_active(ns)))
		return -EEXIST;
	if (!auth_guard_cgroup_ns_root_check(ns))
		return -EACCES;

	ns_tree_add(ns);
	return 0;
}

void cgroup_ns_activate_loadavg(struct cgroup_namespace *ns)
{
	if (!ns || WARN_ON_ONCE(!ns_tree_active(ns)))
		return;

	if (ns->user_ns->parent == &init_user_ns &&
	    ns->user_ns != &init_user_ns)
		cgroup_ns_track_loadavg(ns);
}

void put_cgroup_ns_maybe_unpublished(struct cgroup_namespace *ns)
{
	if (!ns)
		return;
	if (!ns_tree_active(ns))
		cgroup_ns_untrack_loadavg(ns);
	put_cgroup_ns(ns);
}

void free_cgroup_ns(struct cgroup_namespace *ns)
{
	struct css_set *expected;
	struct css_set *root_cset;
	bool old_valid;
	bool trusted;

	if (ns_tree_active(ns))
		ns_tree_remove(ns);

	expected = READ_ONCE(ns->root_cset);
	old_valid = auth_guard_cgroup_ns_root_check(ns);
	root_cset = xchg(&ns->root_cset, NULL);
	trusted = auth_guard_cgroup_ns_root_destroy_complete(ns, expected,
							     old_valid,
							     root_cset == expected);

	cgroup_ns_untrack_loadavg(ns);
	if (root_cset && trusted)
		put_css_set(root_cset);
	dec_cgroup_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	put_cgroup_ns(ns->parent);
	ns_common_free(ns);
	/* Concurrent nstree traversal depends on a grace period. */
	kfree_rcu(ns, ns.ns_rcu);
}
EXPORT_SYMBOL(free_cgroup_ns);

struct cgroup_namespace *copy_cgroup_ns(u64 flags,
					struct user_namespace *user_ns,
					struct cgroup_namespace *old_ns)
{
	struct cgroup_namespace *new_ns;
	struct ucounts *ucounts;
	struct css_set *cset;

	BUG_ON(!old_ns);

	if (!(flags & CLONE_NEWCGROUP)) {
		if (!cgroup_ns_root_cset_checked(old_ns))
			return ERR_PTR(-EACCES);
		get_cgroup_ns(old_ns);
		return old_ns;
	}

	/* Allow only sysadmin to create cgroup namespace. */
	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	/* It is not safe to take cgroup_mutex here */
	spin_lock_irq(&css_set_lock);
	if (!auth_guard_current()) {
		spin_unlock_irq(&css_set_lock);
		return ERR_PTR(-EACCES);
	}
	cset = task_css_set(current);
	get_css_set(cset);
	spin_unlock_irq(&css_set_lock);

	ucounts = inc_cgroup_namespaces(user_ns);
	if (!ucounts) {
		put_css_set(cset);
		return ERR_PTR(-ENOSPC);
	}

	if (!auth_guard_css_set_check(cset)) {
		put_css_set(cset);
		dec_cgroup_namespaces(ucounts);
		return ERR_PTR(-EACCES);
	}

	new_ns = alloc_cgroup_ns();
	if (IS_ERR(new_ns)) {
		put_css_set(cset);
		dec_cgroup_namespaces(ucounts);
		return new_ns;
	}

	new_ns->user_ns = get_user_ns(user_ns);
	new_ns->ucounts = ucounts;
	new_ns->root_cset = cset;
	get_cgroup_ns(old_ns);
	new_ns->parent = old_ns;
	if (!auth_guard_cgroup_ns_root_init(new_ns)) {
		put_cgroup_ns(new_ns);
		return ERR_PTR(-EACCES);
	}

	return new_ns;
}

static int cgroupns_install(struct nsset *nsset, struct ns_common *ns)
{
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct cgroup_namespace *cgroup_ns = to_cg_ns(ns);

	if (!ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(cgroup_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (!cgroup_ns_root_cset_checked(cgroup_ns))
		return -EACCES;

	/* Don't need to do anything if we are attaching to our own cgroupns. */
	if (cgroup_ns == nsproxy->cgroup_ns)
		return 0;

	return auth_guard_nsproxy_install_owned(nsproxy, cgroup_ns, cgroup_ns,
						get_cgroup_ns, put_cgroup_ns);
}

DEFINE_TASK_NSPROXY_MEMBER_GETTER(cgroupns_get, struct cgroup_namespace,
				  cgroup_ns, get_cgroup_ns, put_cgroup_ns)

static void cgroupns_put(struct ns_common *ns)
{
	put_cgroup_ns(to_cg_ns(ns));
}

static struct user_namespace *cgroupns_owner(struct ns_common *ns)
{
	return to_cg_ns(ns)->user_ns;
}

const struct proc_ns_operations cgroupns_operations = {
	.name		= "cgroup",
	.get		= cgroupns_get,
	.put		= cgroupns_put,
	.install	= cgroupns_install,
	.owner		= cgroupns_owner,
};
