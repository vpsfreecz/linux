// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/syslog.h>
#include <linux/proc_ns.h>
#include <linux/printk_ringbuffer.h>
#include <linux/syslog_namespace.h>
#include <linux/user_namespace.h>

inline struct syslog_namespace *detect_syslog_namespace(void)
{
	return current_user_ns()->syslog_ns;
}

static struct ucounts *inc_syslog_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_SYSLOG_NAMESPACES);
}

static void dec_syslog_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_SYSLOG_NAMESPACES);
}

int syslog_ns_setup_log_buf(struct syslog_namespace *ns,
			     unsigned long new_log_buf_len)
{
	struct printk_ringbuffer *prb;
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

	prb = kvzalloc(sizeof(struct printk_ringbuffer), GFP_KERNEL);
	if (unlikely(!prb))
		goto fail_no_mem;

	log_buf = kvzalloc(new_log_buf_len, GFP_KERNEL);
	if (unlikely(!log_buf))
		goto fail_free_prb;

	ns->log_buf = log_buf;
	ns->log_buf_len = new_log_buf_len;

	descs_size = descs_count * sizeof(struct prb_desc);
	descs = kvmalloc(descs_size, GFP_KERNEL);
	if (unlikely(!descs))
		goto fail_free_log_buf;

	infos_size = descs_count * sizeof(struct printk_info);
	infos = kvmalloc(infos_size, GFP_KERNEL);
	if (unlikely(!infos))
		goto fail_free_descs;

	prb_init(prb,
		 log_buf, ilog2(ns->log_buf_len),
		 descs, ilog2(descs_count),
		 infos);

	ns->prb = prb;
	return 0;

fail_free_descs:
	kvfree(descs);
fail_free_log_buf:
	kvfree(log_buf);
fail_free_prb:
	kvfree(prb);
fail_no_mem:
	pr_err("syslog_ns_setup_log_buf: cannot allocate memory\n");
	return -ENOMEM;
}

void syslog_ns_log_buf_free(struct syslog_namespace *ns)
{
	kvfree(ns->prb->desc_ring.descs);
	kvfree(ns->prb->desc_ring.infos);
	kvfree(ns->prb);
	kvfree(ns->log_buf);
}

void free_syslog_ns(struct kref *kref)
{
	struct syslog_namespace *ns;

	ns = container_of(kref, struct syslog_namespace, kref);

	if (ns == &init_syslog_ns) {
		BUG();
		return;
	}

	dec_syslog_namespaces(ns->ucounts);
	put_syslog_ns(ns->parent);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	syslog_ns_log_buf_free(ns);
	kfree(ns);
}

struct syslog_namespace *clone_syslog_ns(struct user_namespace *user_ns,
						struct syslog_namespace *old_ns)
{
	struct syslog_namespace *ns;
	struct ucounts *ucounts;
	int err;

	if (!ns_capable(user_ns, CAP_SYSLOG)) {
		if (ns_capable(user_ns, CAP_SYS_ADMIN)) {
			pr_warn_once("%s (%d): Attempt to access syslog with "
				"CAP_SYS_ADMIN but no CAP_SYSLOG "
				"(deprecated).\n",
				current->comm, task_pid_nr(current));
		} else
			return ERR_PTR(-EPERM);
	}

	err = -ENOSPC;
	ucounts = inc_syslog_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		goto fail_dec;

	kref_init(&ns->kref);

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto fail_free_ns;

	ns->ucounts = ucounts;
	ns->ns.ops = &syslogns_operations;
	ns->user_ns = get_user_ns(user_ns);
	ns->parent = get_syslog_ns(old_ns);

	init_waitqueue_head(&ns->log_wait);
	raw_spin_lock_init(&(ns->logbuf_lock));
	ns->logbuf_cpu = UINT_MAX;
	spin_lock_init(&ns->dump_list_lock);
	INIT_LIST_HEAD(&ns->dump_list);
	ns->dmesg_restrict = old_ns->dmesg_restrict;

	err = syslog_ns_setup_log_buf(ns, __LOG_BUF_LEN);
	if (err)
		goto fail_free_log_buf;

	return ns;

fail_free_log_buf:
	put_syslog_ns(ns->parent);
	put_user_ns(ns->user_ns);
	syslog_ns_log_buf_free(ns);
fail_free_ns:
	kfree(ns);
fail_dec:
	dec_syslog_namespaces(ucounts);
fail:
	return ERR_PTR(err);

}

struct syslog_namespace *copy_syslog_ns(bool new,
				  struct user_namespace *user_ns,
				  struct syslog_namespace *old_ns)
{
	struct syslog_namespace *new_ns;

	get_syslog_ns(old_ns);
	if (!new)
		return old_ns;

	new_ns = clone_syslog_ns(user_ns, old_ns);
	put_syslog_ns(old_ns);

	return new_ns;
}

static struct ns_common *syslogns_get(struct task_struct *task)
{
	struct syslog_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->syslog_ns;
		get_syslog_ns(ns);
	}
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

	put_syslog_ns(nsproxy->syslog_ns);
	nsproxy->syslog_ns = get_syslog_ns(ns);

	return 0;
}

static struct user_namespace *syslogns_owner(struct ns_common *ns)
{
	return to_syslog_ns(ns)->user_ns;
}

const struct proc_ns_operations syslogns_operations = {
	.name = "syslog",
	.type = SYSLOG_ACTION_NEW_NS,
	.get = syslogns_get,
	.put = syslogns_put,
	.install = syslogns_install,
	.owner = syslogns_owner,
};

int setup_syslog_namespace(struct syslog_namespace *ns)
{
	ns->ns.ops = &syslogns_operations;
	return ns_alloc_inum(&ns->ns);
}
