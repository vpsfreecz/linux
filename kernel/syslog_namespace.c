// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/nstree.h>
#include <linux/printk_ringbuffer.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syslog.h>
#include <linux/syslog_namespace.h>
#include <linux/tracing_namespace.h>
#include <linux/user_namespace.h>

extern struct ns_tree syslog_ns_tree;

struct syslog_ns_name_entry {
	struct list_head	list;
	struct syslog_namespace *ns;
};

static DEFINE_MUTEX(syslog_ns_name_lock);
static LIST_HEAD(syslog_ns_names);

static int register_syslog_ns_name(struct syslog_namespace *ns);
static void unregister_syslog_ns_name(struct syslog_namespace *ns);

static int syslog_ns_setup_log_buf(struct syslog_namespace *ns,
				   unsigned long new_log_buf_len)
{
	struct printk_ringbuffer *ns_prb;
	struct printk_info *infos;
	unsigned int descs_count;
	struct prb_desc *descs;
	size_t descs_size, infos_size;
	char *log_buf;

	descs_count = new_log_buf_len >> PRB_AVGBITS;
	if (descs_count == 0) {
		pr_err("log_buf_len: %lu too small\n", new_log_buf_len);
		return -EINVAL;
	}

	ns_prb = kvzalloc(sizeof(*ns_prb), GFP_KERNEL);
	if (!ns_prb)
		return -ENOMEM;

	log_buf = kvzalloc(new_log_buf_len, GFP_KERNEL);
	if (!log_buf)
		goto fail_free_prb;

	ns->log_buf = log_buf;
	ns->log_buf_len = new_log_buf_len;

	descs_size = descs_count * sizeof(*descs);
	descs = kvzalloc(descs_size, GFP_KERNEL);
	if (!descs)
		goto fail_free_log_buf;

	infos_size = descs_count * sizeof(*infos);
	infos = kvzalloc(infos_size, GFP_KERNEL);
	if (!infos)
		goto fail_free_descs;

	prb_init(ns_prb, log_buf, ilog2(ns->log_buf_len),
		 descs, ilog2(descs_count), infos);

	ns->prb = ns_prb;
	if (ns == &init_syslog_ns)
		prb = ns_prb;
	return 0;

fail_free_descs:
	kvfree(descs);
fail_free_log_buf:
	kvfree(log_buf);
	ns->log_buf = NULL;
fail_free_prb:
	kvfree(ns_prb);
	pr_err("%s: cannot allocate memory\n", __func__);
	return -ENOMEM;
}

static void syslog_ns_log_buf_free(struct syslog_namespace *ns)
{
	if (ns->prb) {
		kvfree(ns->prb->desc_ring.descs);
		kvfree(ns->prb->desc_ring.infos);
		kvfree(ns->prb);
		ns->prb = NULL;
	}
	kvfree(ns->log_buf);
	ns->log_buf = NULL;
}

static struct ucounts *inc_syslog_namespaces(struct user_namespace *user_ns)
{
	return inc_ucount(user_ns, current_euid(), UCOUNT_SYSLOG_NAMESPACES);
}

static void dec_syslog_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_SYSLOG_NAMESPACES);
}

static void delayed_free_syslog_ns(struct rcu_head *head)
{
	struct ns_common *common = container_of(head, struct ns_common, ns_rcu);
	struct syslog_namespace *ns = to_syslog_ns(common);

	syslog_ns_log_buf_free(ns);
	kfree(ns->name);
	kfree(ns);
}

void free_syslog_ns(struct syslog_namespace *ns)
{
	if (WARN_ON_ONCE(ns == &init_syslog_ns))
		return;

	if (!RB_EMPTY_NODE(&ns->ns.ns_tree_node))
		ns_tree_remove(ns);
	unregister_syslog_ns_name(ns);
	put_syslog_ns(ns->parent);
	dec_syslog_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	ns_common_free(ns);
	/* Concurrent nstree traversal depends on a grace period. */
	call_rcu(&ns->ns.ns_rcu, delayed_free_syslog_ns);
}

static struct syslog_namespace *clone_syslog_ns(
				struct user_namespace *user_ns,
				struct syslog_namespace *old_ns,
				char *name)
{
	struct syslog_namespace *ns;
	struct ucounts *ucounts;
	int err;

	ucounts = inc_syslog_namespaces(user_ns);
	if (!ucounts)
		return ERR_PTR(-ENOSPC);

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns) {
		err = -ENOMEM;
		goto fail_dec;
	}

	err = __ns_common_init(&ns->ns, SYSLOG_ACTION_NEW_NS,
			      &syslogns_operations, 0);
	if (err)
		goto fail_free_ns;

	ns->ucounts = ucounts;
	ns->user_ns = get_user_ns(user_ns);
	ns->parent = get_syslog_ns(old_ns);
	ns->name = kstrdup(name, GFP_KERNEL);
	if (!ns->name) {
		err = -ENOMEM;
		goto fail_common;
	}

	err = register_syslog_ns_name(ns);
	if (err)
		goto fail_name;

	mutex_init(&ns->syslog_lock);
	init_waitqueue_head(&ns->log_wait);
	spin_lock_init(&ns->dump_list_lock);
	INIT_LIST_HEAD(&ns->dump_list);
	ns->dmesg_restrict = old_ns->dmesg_restrict;

	err = syslog_ns_setup_log_buf(ns, __LOG_BUF_LEN);
	if (err)
		goto fail_unregister_name;

	/*
	 * A freshly created child user namespace inherits its parent's default
	 * syslog namespace in create_user_ns(). When the same clone/unshare also
	 * creates a new syslog namespace, retarget the new userns default here so
	 * subsystems keyed by user_ns (for example netns logging) use the child
	 * syslog buffer rather than the inherited parent one.
	 */
	if (user_ns != current_user_ns() && user_ns->syslog_ns == old_ns) {
		put_syslog_ns(user_ns->syslog_ns);
		user_ns->syslog_ns = get_syslog_ns(ns);
	}

	__ns_tree_add(&ns->ns, &syslog_ns_tree);
	return ns;

fail_unregister_name:
	unregister_syslog_ns_name(ns);
fail_name:
	kfree(ns->name);
fail_common:
	put_syslog_ns(ns->parent);
	put_user_ns(ns->user_ns);
	ns_common_free(ns);
fail_free_ns:
	kfree(ns);
fail_dec:
	dec_syslog_namespaces(ucounts);
	return ERR_PTR(err);
}

static int register_syslog_ns_name(struct syslog_namespace *ns)
{
	struct syslog_ns_name_entry *entry, *iter;
	int ret = 0;

	if (!ns->name || !ns->name[0])
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->ns = ns;
	INIT_LIST_HEAD(&entry->list);

	mutex_lock(&syslog_ns_name_lock);

	if (init_syslog_ns.name && !strcmp(init_syslog_ns.name, ns->name)) {
		ret = -EEXIST;
		goto out_unlock;
	}

	list_for_each_entry(iter, &syslog_ns_names, list) {
		if (!strcmp(iter->ns->name, ns->name)) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	list_add_tail(&entry->list, &syslog_ns_names);

out_unlock:
	mutex_unlock(&syslog_ns_name_lock);

	if (ret)
		kfree(entry);

	return ret;
}

static void unregister_syslog_ns_name(struct syslog_namespace *ns)
{
	struct syslog_ns_name_entry *entry, *tmp;

	if (!ns->name || !ns->name[0])
		return;

	mutex_lock(&syslog_ns_name_lock);
	list_for_each_entry_safe(entry, tmp, &syslog_ns_names, list) {
		if (entry->ns != ns)
			continue;

		list_del(&entry->list);
		kfree(entry);
		break;
	}
	mutex_unlock(&syslog_ns_name_lock);
}

struct syslog_namespace *copy_syslog_ns(bool new, char *name,
					struct user_namespace *user_ns,
					struct syslog_namespace *old_ns)
{
	if (!new)
		return get_syslog_ns(old_ns);

	return clone_syslog_ns(user_ns, old_ns, name);
}

static struct ns_common *syslogns_get(struct task_struct *task)
{
	struct syslog_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy)
		ns = get_syslog_ns(nsproxy->syslog_ns);
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void syslogns_put(struct ns_common *ns)
{
	put_syslog_ns(to_syslog_ns(ns));
}

static int syslogns_install(struct nsset *nsset, struct ns_common *new)
{
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct syslog_namespace *ns = to_syslog_ns(new);
	int ret;

	if (!nsproxy)
		return -EINVAL;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (ns == nsproxy->syslog_ns)
		return 0;

	ret = tracing_ns_check_syslogns_setns_from(ns, nsproxy->tracing_ns);
	if (ret)
		return ret;

	put_syslog_ns(nsproxy->syslog_ns);
	nsproxy->syslog_ns = get_syslog_ns(ns);
	return 0;
}

static struct user_namespace *syslogns_owner(struct ns_common *ns)
{
	return to_syslog_ns(ns)->user_ns;
}

static struct ns_common *syslogns_get_parent(struct ns_common *ns)
{
	struct syslog_namespace *parent = to_syslog_ns(ns)->parent;

	if (!parent)
		return ERR_PTR(-EPERM);

	return &get_syslog_ns(parent)->ns;
}

const struct proc_ns_operations syslogns_operations = {
	.name		= "syslog",
	.get		= syslogns_get,
	.put		= syslogns_put,
	.install	= syslogns_install,
	.owner		= syslogns_owner,
	.get_parent	= syslogns_get_parent,
};

int setup_syslog_namespace(struct syslog_namespace *ns)
{
	if (ns == &init_syslog_ns)
		__ns_tree_add(&ns->ns, &syslog_ns_tree);

	return 0;
}

static int __init syslog_namespaces_init(void)
{
	return setup_syslog_namespace(&init_syslog_ns);
}
subsys_initcall(syslog_namespaces_init);
