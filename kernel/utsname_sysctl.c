// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmision.com>
 */

#include <linux/export.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/random.h>
#include <linux/sysctl.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>
#include <linux/rwsem.h>

#ifdef CONFIG_PROC_SYSCTL

static void *get_uts(const struct ctl_table *table)
{
	return table->data;
}

/*
 *	Special case of dostring for the UTS structure. This has locks
 *	to observe. Should this be in kernel/sys.c ????
 */
static int proc_do_uts_string(const struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table uts_table;
	int r;
	char tmp_data[__NEW_UTS_LEN + 1];

	memcpy(&uts_table, table, sizeof(uts_table));
	uts_table.data = tmp_data;

	/*
	 * Buffer the value in tmp_data so that proc_dostring() can be called
	 * without holding any locks.
	 * We also need to read the original value in the write==1 case to
	 * support partial writes.
	 */
	down_read(&uts_sem);
	memcpy(tmp_data, get_uts(table), sizeof(tmp_data));
	up_read(&uts_sem);
	r = proc_dostring(&uts_table, write, buffer, lenp, ppos);

	if (write) {
		/*
		 * Write back the new value.
		 * Note that, since we dropped uts_sem, the result can
		 * theoretically be incorrect if there are two parallel writes
		 * at non-zero offsets to the same sysctl.
		 */
		add_device_randomness(tmp_data, sizeof(tmp_data));
		down_write(&uts_sem);
		memcpy(get_uts(table), tmp_data, sizeof(tmp_data));
		up_write(&uts_sem);
		proc_sys_poll_notify(table->poll);
	}

	return r;
}
#else
#define proc_do_uts_string NULL
#endif

static DEFINE_CTL_TABLE_POLL(hostname_poll);
static DEFINE_CTL_TABLE_POLL(domainname_poll);

// Note: update 'enum uts_proc' to match any changes to this table
static const struct ctl_table uts_kern_table[] = {
	{
		.procname	= "arch",
		.data		= init_uts_ns.name.machine,
		.maxlen		= sizeof(init_uts_ns.name.machine),
		.mode		= 0444,
		.proc_handler	= proc_do_uts_string,
	},
	{
		.procname	= "ostype",
		.data		= init_uts_ns.name.sysname,
		.maxlen		= sizeof(init_uts_ns.name.sysname),
		.mode		= 0444,
		.proc_handler	= proc_do_uts_string,
	},
	{
		.procname	= "osrelease",
		.data		= init_uts_ns.name.release,
		.maxlen		= sizeof(init_uts_ns.name.release),
		.mode		= 0444,
		.proc_handler	= proc_do_uts_string,
	},
	{
		.procname	= "version",
		.data		= init_uts_ns.name.version,
		.maxlen		= sizeof(init_uts_ns.name.version),
		.mode		= 0444,
		.proc_handler	= proc_do_uts_string,
	},
	{
		.procname	= "hostname",
		.data		= init_uts_ns.name.nodename,
		.maxlen		= sizeof(init_uts_ns.name.nodename),
		.mode		= 0644,
		.proc_handler	= proc_do_uts_string,
		.poll		= &hostname_poll,
	},
	{
		.procname	= "domainname",
		.data		= init_uts_ns.name.domainname,
		.maxlen		= sizeof(init_uts_ns.name.domainname),
		.mode		= 0644,
		.proc_handler	= proc_do_uts_string,
		.poll		= &domainname_poll,
	},
};

static struct ctl_table_set *uts_table_root_lookup(struct ctl_table_root *root)
{
	return &current->nsproxy->uts_ns->set;
}

static int set_is_seen(struct ctl_table_set *set)
{
	return &current->nsproxy->uts_ns->set == set;
}

static int uts_table_root_permissions(struct ctl_table_header *head,
				      const struct ctl_table *table)
{
	struct uts_namespace *uts_ns =
		container_of(head->set, struct uts_namespace, set);
	int mode = table->mode;

	if (ns_capable_noaudit(uts_ns->user_ns, CAP_SYS_ADMIN) ||
	    uid_eq(current_euid(), make_kuid(uts_ns->user_ns, 0)))
		mode = (mode & S_IRWXU) >> 6;
	else if (in_egroup_p(make_kgid(uts_ns->user_ns, 0)))
		mode = (mode & S_IRWXG) >> 3;
	else
		mode = mode & S_IROTH;

	return (mode << 6) | (mode << 3) | mode;
}

static void uts_table_root_set_ownership(struct ctl_table_header *head,
					 kuid_t *uid, kgid_t *gid)
{
	struct uts_namespace *uts_ns =
		container_of(head->set, struct uts_namespace, set);
	kuid_t ns_root_uid;
	kgid_t ns_root_gid;

	ns_root_uid = make_kuid(uts_ns->user_ns, 0);
	if (uid_valid(ns_root_uid))
		*uid = ns_root_uid;

	ns_root_gid = make_kgid(uts_ns->user_ns, 0);
	if (gid_valid(ns_root_gid))
		*gid = ns_root_gid;
}

static void uts_table_root_set_security(struct ctl_table_header *head,
					struct inode *inode)
{
	struct uts_namespace *uts_ns =
		container_of(head->set, struct uts_namespace, set);

	if (uts_ns != &init_uts_ns)
		ns_common_owner_to_inode(&uts_ns->ns, inode);
}

static struct ctl_table_root uts_table_root = {
	.lookup		= uts_table_root_lookup,
	.permissions	= uts_table_root_permissions,
	.set_ownership	= uts_table_root_set_ownership,
	.set_security	= uts_table_root_set_security,
};

int setup_uts_sysctls(struct uts_namespace *ns)
{
	struct ctl_table *tbl;

	setup_sysctl_set(&ns->set, &uts_table_root, set_is_seen);

	tbl = kmemdup(uts_kern_table, sizeof(uts_kern_table), GFP_KERNEL);
	if (!tbl)
		goto fail;

	tbl[UTS_PROC_ARCH].data = ns->name.machine;
	tbl[UTS_PROC_OSTYPE].data = ns->name.sysname;
	tbl[UTS_PROC_OSRELEASE].data = ns->name.release;
	tbl[UTS_PROC_VERSION].data = ns->name.version;
	tbl[UTS_PROC_HOSTNAME].data = ns->name.nodename;
	tbl[UTS_PROC_DOMAINNAME].data = ns->name.domainname;

	ns->sysctls = __register_sysctl_table(&ns->set, "kernel", tbl,
					      ARRAY_SIZE(uts_kern_table));
	if (!ns->sysctls) {
		kfree(tbl);
		goto fail;
	}

	return 0;

fail:
	retire_sysctl_set(&ns->set);
	return -ENOMEM;
}

void retire_uts_sysctls(struct uts_namespace *ns)
{
	const struct ctl_table *tbl;

	tbl = ns->sysctls->ctl_table_arg;
	unregister_sysctl_table(ns->sysctls);
	retire_sysctl_set(&ns->set);
	kfree(tbl);
}

#ifdef CONFIG_PROC_SYSCTL
/*
 * Notify userspace about a change in a certain entry of uts_kern_table,
 * identified by the parameter proc.
 */
void uts_proc_notify(enum uts_proc proc)
{
	const struct ctl_table *table = &uts_kern_table[proc];

	proc_sys_poll_notify(table->poll);
}
#endif

static int __init utsname_sysctl_init(void)
{
	return setup_uts_sysctls(&init_uts_ns);
}

device_initcall(utsname_sysctl_init);
