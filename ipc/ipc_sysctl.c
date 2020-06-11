// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmision.com>
 */

#include <linux/module.h>
#include <linux/ipc.h>
#include <linux/nsproxy.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <linux/uaccess.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include "util.h"

static struct ctl_table ipc_kern_table[];

static void *get_ipc(struct ctl_table *table)
{
	char *which = table->data;
	struct ipc_namespace *ipc_ns = current->nsproxy->ipc_ns;
	which = (which - (char *)&init_ipc_ns) + (char *)ipc_ns;
	return which;
}

#ifdef CONFIG_PROC_SYSCTL
static int proc_ipc_dointvec(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table ipc_table;

	memcpy(&ipc_table, table, sizeof(ipc_table));
	ipc_table.data = get_ipc(table);

	return proc_dointvec(&ipc_table, write, buffer, lenp, ppos);
}

static int proc_ipc_dointvec_minmax(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table ipc_table;

	memcpy(&ipc_table, table, sizeof(ipc_table));
	ipc_table.data = get_ipc(table);

	return proc_dointvec_minmax(&ipc_table, write, buffer, lenp, ppos);
}

static int proc_ipc_dointvec_minmax_orphans(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ipc_namespace *ns = current->nsproxy->ipc_ns;
	int err = proc_ipc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (err < 0)
		return err;
	if (ns->shm_rmid_forced)
		shm_destroy_orphaned(ns);
	return err;
}

static int proc_ipc_doulongvec_minmax(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table ipc_table;
	memcpy(&ipc_table, table, sizeof(ipc_table));
	ipc_table.data = get_ipc(table);

	return proc_doulongvec_minmax(&ipc_table, write, buffer,
					lenp, ppos);
}

static int proc_ipc_auto_msgmni(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table ipc_table;
	int dummy = 0;

	memcpy(&ipc_table, table, sizeof(ipc_table));
	ipc_table.data = &dummy;

	if (write)
		pr_info_once("writing to auto_msgmni has no effect");

	return proc_dointvec_minmax(&ipc_table, write, buffer, lenp, ppos);
}

static int proc_ipc_sem_dointvec(struct ctl_table *table, int write,
	void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, semmni;
	struct ipc_namespace *ns = current->nsproxy->ipc_ns;

	semmni = ns->sem_ctls[3];
	ret = proc_ipc_dointvec(table, write, buffer, lenp, ppos);

	if (!ret)
		ret = sem_check_semmni(current->nsproxy->ipc_ns);

	/*
	 * Reset the semmni value if an error happens.
	 */
	if (ret)
		ns->sem_ctls[3] = semmni;
	return ret;
}

#else
#define proc_ipc_doulongvec_minmax NULL
#define proc_ipc_dointvec	   NULL
#define proc_ipc_dointvec_minmax   NULL
#define proc_ipc_dointvec_minmax_orphans   NULL
#define proc_ipc_auto_msgmni	   NULL
#define proc_ipc_sem_dointvec	   NULL
#endif

int ipc_mni = IPCMNI;
int ipc_mni_shift = IPCMNI_SHIFT;
int ipc_min_cycle = RADIX_TREE_MAP_SIZE;

enum ipc_sysctl_index {
	IPC_SYSCTL_SHMMAX,
	IPC_SYSCTL_SHMALL,
	IPC_SYSCTL_SHMMNI,
	IPC_SYSCTL_SHM_RMID_FORCED,
	IPC_SYSCTL_MSGMAX,
	IPC_SYSCTL_MSGMNI,
	IPC_SYSCTL_AUTO_MSGMNI,
	IPC_SYSCTL_MSGMNB,
	IPC_SYSCTL_SEM,
	IPC_SYSCTL_SEM_NEXT_ID,
	IPC_SYSCTL_MSG_NEXT_ID,
	IPC_SYSCTL_SHM_NEXT_ID,
	IPC_SYSCTL_LAST
};

static struct ctl_table ipc_kern_table[] = {
	[IPC_SYSCTL_SHMMAX] = {
		.procname	= "shmmax",
		.data		= &init_ipc_ns.shm_ctlmax,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlmax),
		.mode		= 0644,
		.proc_handler	= proc_ipc_doulongvec_minmax,
	},
	[IPC_SYSCTL_SHMALL] = {
		.procname	= "shmall",
		.data		= &init_ipc_ns.shm_ctlall,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlall),
		.mode		= 0644,
		.proc_handler	= proc_ipc_doulongvec_minmax,
	},
	[IPC_SYSCTL_SHMMNI] = {
		.procname	= "shmmni",
		.data		= &init_ipc_ns.shm_ctlmni,
		.maxlen		= sizeof(init_ipc_ns.shm_ctlmni),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &ipc_mni,
	},
	[IPC_SYSCTL_SHM_RMID_FORCED] = {
		.procname	= "shm_rmid_forced",
		.data		= &init_ipc_ns.shm_rmid_forced,
		.maxlen		= sizeof(init_ipc_ns.shm_rmid_forced),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax_orphans,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	[IPC_SYSCTL_MSGMAX] = {
		.procname	= "msgmax",
		.data		= &init_ipc_ns.msg_ctlmax,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmax),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	[IPC_SYSCTL_MSGMNI] = {
		.procname	= "msgmni",
		.data		= &init_ipc_ns.msg_ctlmni,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmni),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &ipc_mni,
	},
	[IPC_SYSCTL_AUTO_MSGMNI] = {
		.procname	= "auto_msgmni",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_ipc_auto_msgmni,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	[IPC_SYSCTL_MSGMNB] = {
		.procname	= "msgmnb",
		.data		= &init_ipc_ns.msg_ctlmnb,
		.maxlen		= sizeof(init_ipc_ns.msg_ctlmnb),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	[IPC_SYSCTL_SEM] = {
		.procname	= "sem",
		.data		= &init_ipc_ns.sem_ctls,
		.maxlen		= 4*sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_ipc_sem_dointvec,
	},
#ifdef CONFIG_CHECKPOINT_RESTORE
	[IPC_SYSCTL_SEM_NEXT_ID] = {
		.procname	= "sem_next_id",
		.data		= &init_ipc_ns.ids[IPC_SEM_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_SEM_IDS].next_id),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	[IPC_SYSCTL_MSG_NEXT_ID] = {
		.procname	= "msg_next_id",
		.data		= &init_ipc_ns.ids[IPC_MSG_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_MSG_IDS].next_id),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	[IPC_SYSCTL_SHM_NEXT_ID] = {
		.procname	= "shm_next_id",
		.data		= &init_ipc_ns.ids[IPC_SHM_IDS].next_id,
		.maxlen		= sizeof(init_ipc_ns.ids[IPC_SHM_IDS].next_id),
		.mode		= 0644,
		.proc_handler	= proc_ipc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
#endif
	{}
};

#ifdef CONFIG_NET
static void ipc_sysctl_pernet_exit(struct net *net)
{
	struct ctl_table *table;
	int i = 0;

	table = net->ipc_sysctl_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipc_sysctl_hdr);
	if (net->user_ns != &init_user_ns)
		for (i = IPC_SYSCTL_LAST; i >= 0; --i)
			kfree(table[i].data);
	kfree(table);
}
static void ipc_sysctl_replace_functions_safe(struct ctl_table *t)
{
	if (t->proc_handler == proc_ipc_dointvec)
		t->proc_handler = proc_dointvec;
	else if (t->proc_handler == proc_ipc_dointvec_minmax)
		t->proc_handler = proc_dointvec_minmax;
	else if (t->proc_handler == proc_ipc_dointvec_minmax_orphans)
		t->proc_handler = proc_dointvec_minmax;
	else if (t->proc_handler == proc_ipc_doulongvec_minmax)
		t->proc_handler = proc_doulongvec_minmax;
	else if (t->proc_handler == proc_ipc_auto_msgmni)
		t->proc_handler = proc_dointvec_minmax;
	else if (t->proc_handler == proc_ipc_sem_dointvec)
		t->proc_handler = proc_dointvec;
}
static int ipc_sysctl_pernet_init(struct net *net)
{
	struct ctl_table *table;
	int i;

	if (net_eq(net, &init_net))
		return 0;

	table = kmemdup(&ipc_kern_table, sizeof(ipc_kern_table), GFP_KERNEL);
		if (!table)
			goto out_tbl;

	if (net->user_ns != &init_user_ns) {
		for (i = 0; i < IPC_SYSCTL_LAST; ++i) {
			if (table[i].data)
				table[i].data = kmemdup(&ipc_kern_table[i].data,
						ipc_kern_table[i].maxlen, GFP_KERNEL);
			else
				table[i].data = kzalloc(
						ipc_kern_table[i].maxlen, GFP_KERNEL);
			if (!table[i].data)
				goto out;
			ipc_sysctl_replace_functions_safe(&table[i]);
		}
	}

	net->ipc_sysctl_hdr = register_net_sysctl(net, "kernel", table);

	if (!net->ipc_sysctl_hdr)
		goto out;

	return 0;

out:
	for (; i >= 0; --i)
		kfree(table[i].data);
	kfree(table);
out_tbl:
	return -ENOMEM;
}

static struct pernet_operations ipc_sysctl_net_ops = {
	.init		= ipc_sysctl_pernet_init,
	.exit		= ipc_sysctl_pernet_exit,
};
static int __init ipc_sysctl_init(void)
{
	int ret;

	init_net.ipc_sysctl_hdr = register_net_sysctl(&init_net, "kernel", ipc_kern_table);
	ret = register_pernet_subsys(&ipc_sysctl_net_ops);
	return ret;
}
device_initcall(ipc_sysctl_init);
#else
static struct ctl_table ipc_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= ipc_kern_table,
	},
	{}
};

static int __init ipc_sysctl_init(void)
{
	register_sysctl_table(ipc_root_table);
	return 0;
}

device_initcall(ipc_sysctl_init);
#endif

static int __init ipc_mni_extend(char *str)
{
	ipc_mni = IPCMNI_EXTEND;
	ipc_mni_shift = IPCMNI_EXTEND_SHIFT;
	ipc_min_cycle = IPCMNI_EXTEND_MIN_CYCLE;
	pr_info("IPCMNI extended to %d.\n", ipc_mni);
	return 0;
}
early_param("ipcmni_extend", ipc_mni_extend);
