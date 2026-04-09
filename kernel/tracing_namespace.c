// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/cred.h>
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
	.pid_ns_id = 0,
	.syslog_ns_id = 0,
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
		if (pid_ns->ns.ns_id == ns->pid_ns_id)
			return true;
		pid_ns = pid_ns->parent;
	}

	return false;
}

static bool tracing_ns_pid_matches(const struct tracing_namespace *ns,
				   const struct task_struct *task,
				   const struct nsproxy *nsproxy)
{
	if (tracing_ns_pid_contains(ns,
				    task_active_pid_ns((struct task_struct *)task)))
		return true;

	/*
	 * setns(CLONE_NEWPID) changes pid_ns_for_children immediately, while
	 * the caller's active PID namespace changes only after the next fork.
	 * A task that has already entered the container tracing namespace must
	 * still be constrained as a tracing guest during that transition.
	 */
	if (nsproxy && tracing_ns_pid_contains(ns, nsproxy->pid_ns_for_children))
		return true;

	return false;
}

static bool tracing_ns_user_contains(const struct tracing_namespace *ns,
				     const struct user_namespace *user_ns)
{
	while (user_ns) {
		if (user_ns == ns->user_ns)
			return true;
		user_ns = user_ns->parent;
	}

	return false;
}

static bool tracing_ns_user_matches(const struct tracing_namespace *ns,
				    const struct user_namespace *user_ns)
{
	/*
	 * Unmapped/privileged containers can execute tasks in the child
	 * tracing/pid/syslog boundary while their credentials remain anchored
	 * in init_user_ns. They still need to be treated as members of the
	 * tracing guest so BPF/tracing restrictions apply to them.
	 */
	if (user_ns == &init_user_ns && ns != &init_tracing_ns)
		return true;

	return tracing_ns_user_contains(ns, user_ns);
}

static bool tracing_ns_syslog_contains(const struct tracing_namespace *ns,
				       const struct syslog_namespace *syslog_ns)
{
	while (syslog_ns) {
		if (syslog_ns->ns.ns_id == ns->syslog_ns_id)
			return true;
		syslog_ns = syslog_ns->parent;
	}

	return false;
}

static bool tracing_ns_can_bind_child(const struct tracing_namespace *old_ns,
				      const struct user_namespace *user_ns,
				      const struct pid_namespace *pid_ns,
				      const struct syslog_namespace *syslog_ns)
{
	if (!user_ns || !pid_ns || !syslog_ns)
		return false;

	if (user_ns == &init_user_ns || user_ns->parent != &init_user_ns)
		return false;

	if (pid_ns->ns.ns_id == old_ns->pid_ns_id || !pid_ns->parent ||
	    pid_ns->parent->ns.ns_id != old_ns->pid_ns_id)
		return false;

	if (syslog_ns->ns.ns_id == old_ns->syslog_ns_id ||
	    !syslog_ns->parent ||
	    syslog_ns->parent->ns.ns_id != old_ns->syslog_ns_id)
		return false;

	return true;
}

bool tracing_ns_matches_task(const struct tracing_namespace *ns,
			     const struct task_struct *task)
{
	struct nsproxy *nsproxy;
	const struct cred *cred;
	bool match = false;

	if (!ns || !task)
		return false;

	rcu_read_lock();
	nsproxy = task->nsproxy;
	cred = __task_cred(task);
	if (nsproxy && cred && nsproxy->tracing_ns == ns &&
	    tracing_ns_syslog_contains(ns, nsproxy->syslog_ns))
		match = tracing_ns_pid_matches(ns, task, nsproxy) &&
			tracing_ns_user_matches(ns, cred->user_ns);
	rcu_read_unlock();

	return match;
}
EXPORT_SYMBOL_GPL(tracing_ns_matches_task);

/*
 * BPF program dispatch can run from NMI context. Match the current task from
 * its directly reachable namespace and credential state instead of taking the
 * foreign-task RCU path used by tracing_ns_matches_task().
 */
bool tracing_ns_matches_current(const struct tracing_namespace *ns)
{
	const struct nsproxy *nsproxy;
	const struct cred *cred;

	if (!ns)
		return false;

	nsproxy = current->nsproxy;
	cred = current_cred();
	if (!nsproxy || nsproxy->tracing_ns != ns ||
	    !tracing_ns_syslog_contains(ns, nsproxy->syslog_ns))
		return false;

	return tracing_ns_pid_matches(ns, current, nsproxy) &&
	       tracing_ns_user_matches(ns, cred->user_ns);
}
EXPORT_SYMBOL_GPL(tracing_ns_matches_current);

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

	pr_notice("tracing_ns: destroy ns=%u user=%u pid=%llu syslog=%llu\n",
		  ns->ns.inum,
		  ns->user_ns ? ns->user_ns->ns.inum : 0,
		  ns->pid_ns_id,
		  ns->syslog_ns_id);

	put_tracing_ns_structural(ns->parent);
	ns_common_free(ns);
	call_rcu(&ns->ns.ns_rcu, delayed_free_tracing_ns);
}
EXPORT_SYMBOL_GPL(free_tracing_ns);

int tracing_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	struct tracing_namespace *target_ns, *current_ns;

	if (!user_ns)
		return -EINVAL;

	current_ns = current_tracing_ns();
	target_ns = user_ns->tracing_ns ? user_ns->tracing_ns : &init_tracing_ns;

	if (target_ns == current_ns)
		return 0;

	pr_notice("tracing_ns: reject userns setns current=%u target_user=%u target_tracing=%u\n",
		  current_ns ? current_ns->ns.inum : 0,
		  user_ns->ns.inum,
		  target_ns->ns.inum);
	return -EPERM;
}
EXPORT_SYMBOL_GPL(tracing_ns_check_userns_setns);

int tracing_ns_check_pidns_setns(const struct pid_namespace *pid_ns)
{
	struct tracing_namespace *target_ns, *current_ns;

	if (!pid_ns)
		return -EINVAL;

	current_ns = current_tracing_ns();
	target_ns = (pid_ns->user_ns && pid_ns->user_ns->tracing_ns) ?
		pid_ns->user_ns->tracing_ns : &init_tracing_ns;

	if (target_ns == current_ns)
		return 0;

	pr_notice("tracing_ns: reject pidns setns current=%u target_pid=%u target_tracing=%u\n",
		  current_ns ? current_ns->ns.inum : 0,
		  pid_ns->ns.inum,
		  target_ns->ns.inum);
	return -EPERM;
}
EXPORT_SYMBOL_GPL(tracing_ns_check_pidns_setns);

int tracing_ns_check_syslogns_setns(const struct syslog_namespace *syslog_ns)
{
	struct tracing_namespace *target_ns, *current_ns;

	if (!syslog_ns)
		return -EINVAL;

	current_ns = current_tracing_ns();
	target_ns = (syslog_ns->user_ns && syslog_ns->user_ns->tracing_ns) ?
		syslog_ns->user_ns->tracing_ns : &init_tracing_ns;

	if (target_ns == current_ns)
		return 0;

	pr_notice("tracing_ns: reject syslogns setns current=%u target_syslog=%u target_tracing=%u\n",
		  current_ns ? current_ns->ns.inum : 0,
		  syslog_ns->ns.inum,
		  target_ns->ns.inum);
	return -EPERM;
}
EXPORT_SYMBOL_GPL(tracing_ns_check_syslogns_setns);

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
	ns->pid_ns_id = pid_ns->ns.ns_id;
	ns->syslog_ns_id = syslog_ns->ns.ns_id;
	ns->parent = get_tracing_ns_structural(old_ns);

	/*
	 * A freshly created child user namespace inherits its parent's effective
	 * tracing namespace in create_user_ns(). When the same clone/unshare also
	 * creates a child tracing namespace, retarget the new userns default here
	 * so future userns descendants and setns checks resolve to the child
	 * tracing boundary rather than the inherited init one.
	 */
	if (user_ns != current_user_ns() && user_ns->tracing_ns == old_ns) {
		if (WARN_ON_ONCE(user_ns->tracing_ns_is_owner)) {
			err = -EINVAL;
			goto fail_refs;
		}
		put_tracing_ns(user_ns->tracing_ns);
		user_ns->tracing_ns = get_tracing_ns_structural(ns);
		user_ns->tracing_ns_is_owner = true;
	}

	__ns_tree_add(&ns->ns, &tracing_ns_tree);

	pr_notice("tracing_ns: create ns=%u parent=%u user=%u pid=%llu syslog=%llu\n",
		  ns->ns.inum,
		  old_ns ? old_ns->ns.inum : 0,
		  user_ns->ns.inum,
		  ns->pid_ns_id,
		  ns->syslog_ns_id);

	return ns;

fail_refs:
	put_tracing_ns_structural(ns->parent);
	put_user_ns(ns->user_ns);
	ns_common_free(ns);
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
		pr_notice("tracing_ns: reject nested create request ns=%u user=%u pid=%u syslog=%u\n",
			  old_ns->ns.inum, user_ns->ns.inum,
			  pid_ns->ns.inum, syslog_ns->ns.inum);
		return ERR_PTR(-EPERM);
	}

	if (!tracing_ns_can_bind_child(old_ns, user_ns, pid_ns, syslog_ns)) {
		pr_notice("tracing_ns: reject create on incomplete boundary user=%u pid=%u syslog=%u old=%u\n",
			  user_ns->ns.inum, pid_ns->ns.inum,
			  syslog_ns->ns.inum, old_ns->ns.inum);
		return ERR_PTR(-EINVAL);
	}

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
	if (ns == &init_tracing_ns) {
		if (WARN_ON_ONCE(!init_pid_ns.ns.ns_id ||
				 !init_syslog_ns.ns.ns_id))
			return -EINVAL;

		ns->pid_ns_id = init_pid_ns.ns.ns_id;
		ns->syslog_ns_id = init_syslog_ns.ns.ns_id;
		__ns_tree_add(&ns->ns, &tracing_ns_tree);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(setup_tracing_namespace);

static int __init tracing_namespaces_init(void)
{
	return setup_tracing_namespace(&init_tracing_ns);
}
late_initcall(tracing_namespaces_init);
