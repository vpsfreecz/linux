// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/nstree.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syslog_namespace.h>
#include <linux/tracing_namespace.h>
#include <linux/user_namespace.h>

extern struct ns_tree tracing_ns_tree;

struct tracing_namespace init_tracing_ns = {
	.user_ns = &init_user_ns,
	.pid_ns = &init_pid_ns,
	.syslog_ns = &init_syslog_ns,
	.parent = NULL,
	.ns = {
		.ns_type = TRACING_NS_TYPE,
		.__ns_ref = REFCOUNT_INIT(2),
		.ops = &tracingns_operations,
		.inum = TRACING_NS_INIT_INO,
	},
};
EXPORT_SYMBOL_GPL(init_tracing_ns);

static bool tracing_ns_pid_contains(const struct tracing_namespace *ns,
				    const struct pid_namespace *pid_ns)
{
	while (pid_ns) {
		if (pid_ns == ns->pid_ns)
			return true;
		pid_ns = pid_ns->parent;
	}

	return false;
}

bool tracing_ns_matches_task(const struct tracing_namespace *ns,
			    const struct task_struct *task)
{
	struct nsproxy *nsproxy;
	bool match = false;

	if (!ns || !task)
		return false;

	rcu_read_lock();
	nsproxy = task->nsproxy;
	if (nsproxy && nsproxy->tracing_ns == ns)
		match = tracing_ns_pid_contains(ns,
				task_active_pid_ns((struct task_struct *)task));
	rcu_read_unlock();

	return match;
}
EXPORT_SYMBOL_GPL(tracing_ns_matches_task);

static void delayed_free_tracing_ns(struct rcu_head *head)
{
	struct ns_common *common = container_of(head, struct ns_common, ns_rcu);
	struct tracing_namespace *ns = to_tracing_ns(common);

	kfree(ns);
}

void free_tracing_ns(struct tracing_namespace *ns)
{
	if (WARN_ON_ONCE(ns == &init_tracing_ns))
		return;

	if (ns_tree_active(ns))
		ns_tree_remove(ns);

	pr_notice("tracing_ns: destroy ns=%u user=%u pid=%u syslog=%u\n",
		  ns->ns.inum,
		  ns->user_ns ? ns->user_ns->ns.inum : 0,
		  ns->pid_ns ? ns->pid_ns->ns.inum : 0,
		  ns->syslog_ns ? ns->syslog_ns->ns.inum : 0);

	put_tracing_ns(ns->parent);
	put_pid_ns(ns->pid_ns);
	put_syslog_ns(ns->syslog_ns);
	put_user_ns(ns->user_ns);
	ns_common_free(ns);
	call_rcu(&ns->ns.ns_rcu, delayed_free_tracing_ns);
}
EXPORT_SYMBOL_GPL(free_tracing_ns);

static struct tracing_namespace *clone_tracing_ns(struct user_namespace *user_ns,
					  struct pid_namespace *pid_ns,
					  struct syslog_namespace *syslog_ns,
					  struct tracing_namespace *old_ns)
{
	struct tracing_namespace *ns;
	int err;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	err = __ns_common_init(&ns->ns, TRACING_NS_TYPE, &tracingns_operations, 0);
	if (err)
		goto fail_free;

	ns->user_ns = get_user_ns(user_ns);
	ns->pid_ns = get_pid_ns(pid_ns);
	ns->syslog_ns = get_syslog_ns(syslog_ns);
	ns->parent = get_tracing_ns(old_ns);

	__ns_tree_add(&ns->ns, &tracing_ns_tree);

	pr_notice("tracing_ns: create ns=%u parent=%u user=%u pid=%u syslog=%u\n",
		  ns->ns.inum,
		  old_ns ? old_ns->ns.inum : 0,
		  user_ns->ns.inum,
		  pid_ns->ns.inum,
		  syslog_ns->ns.inum);

	return ns;

fail_free:
	kfree(ns);
	return ERR_PTR(err);
}

struct tracing_namespace *copy_tracing_ns(bool new_child,
				 struct user_namespace *user_ns,
				 struct pid_namespace *pid_ns,
				 struct syslog_namespace *syslog_ns,
				 struct tracing_namespace *old_ns)
{
	if (!old_ns)
		old_ns = &init_tracing_ns;

	if (!new_child)
		return get_tracing_ns(old_ns);

	if (!user_ns || !pid_ns || !syslog_ns)
		return ERR_PTR(-EINVAL);

	if (old_ns != &init_tracing_ns) {
		pr_notice("tracing_ns: nested create request reused ns=%u for user=%u pid=%u syslog=%u\n",
		  old_ns->ns.inum, user_ns->ns.inum, pid_ns->ns.inum, syslog_ns->ns.inum);
		return get_tracing_ns(old_ns);
	}

	if (user_ns == &init_user_ns || user_ns->parent != &init_user_ns)
		return get_tracing_ns(old_ns);

	if (syslog_ns == old_ns->syslog_ns)
		return get_tracing_ns(old_ns);

	return clone_tracing_ns(user_ns, pid_ns, syslog_ns, old_ns);
}
EXPORT_SYMBOL_GPL(copy_tracing_ns);

static struct ns_common *tracingns_get(struct task_struct *task)
{
	struct tracing_namespace *ns = &init_tracing_ns;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy && nsproxy->tracing_ns)
		ns = nsproxy->tracing_ns;
	get_tracing_ns(ns);
	task_unlock(task);

	return &ns->ns;
}

static void tracingns_put(struct ns_common *ns)
{
	put_tracing_ns(to_tracing_ns(ns));
}

static int tracingns_install(struct nsset *nsset, struct ns_common *new)
{
	struct tracing_namespace *ns = to_tracing_ns(new);
	struct nsproxy *nsproxy = nsset->nsproxy;

	if (!nsproxy)
		return -EINVAL;
	if (nsproxy->tracing_ns == ns)
		return 0;

	return -EPERM;
}

static struct user_namespace *tracingns_owner(struct ns_common *ns)
{
	return to_tracing_ns(ns)->user_ns;
}

static struct ns_common *tracingns_get_parent(struct ns_common *ns)
{
	struct tracing_namespace *parent = to_tracing_ns(ns)->parent;

	if (!parent)
		return ERR_PTR(-EPERM);

	return &get_tracing_ns(parent)->ns;
}

const struct proc_ns_operations tracingns_operations = {
	.name		= "tracing",
	.get		= tracingns_get,
	.put		= tracingns_put,
	.install	= tracingns_install,
	.owner		= tracingns_owner,
	.get_parent	= tracingns_get_parent,
};
EXPORT_SYMBOL_GPL(tracingns_operations);

int setup_tracing_namespace(struct tracing_namespace *ns)
{
	if (ns == &init_tracing_ns)
		__ns_tree_add(&ns->ns, &tracing_ns_tree);

	return 0;
}
EXPORT_SYMBOL_GPL(setup_tracing_namespace);

static int __init tracing_namespaces_init(void)
{
	return setup_tracing_namespace(&init_tracing_ns);
}
subsys_initcall(tracing_namespaces_init);
