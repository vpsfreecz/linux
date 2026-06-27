// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/init_task.h>
#include <linux/ns_common.h>
#include <linux/proc_ns.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/vfsdebug.h>

#ifdef CONFIG_DEBUG_VFS
static void ns_debug(struct ns_common *ns, const struct proc_ns_operations *ops)
{
	switch (ns->ns_type) {
#ifdef CONFIG_CGROUPS
	case CLONE_NEWCGROUP:
		VFS_WARN_ON_ONCE(ops != &cgroupns_operations);
		break;
#endif
#ifdef CONFIG_IPC_NS
	case CLONE_NEWIPC:
		VFS_WARN_ON_ONCE(ops != &ipcns_operations);
		break;
#endif
	case CLONE_NEWNS:
		VFS_WARN_ON_ONCE(ops != &mntns_operations);
		break;
#ifdef CONFIG_NET_NS
	case CLONE_NEWNET:
		VFS_WARN_ON_ONCE(ops != &netns_operations);
		break;
#endif
#ifdef CONFIG_PID_NS
	case CLONE_NEWPID:
		VFS_WARN_ON_ONCE(ops != &pidns_operations);
		break;
#endif
#ifdef CONFIG_TIME_NS
	case CLONE_NEWTIME:
		VFS_WARN_ON_ONCE(ops != &timens_operations);
		break;
#endif
#ifdef CONFIG_USER_NS
	case CLONE_NEWUSER:
		VFS_WARN_ON_ONCE(ops != &userns_operations);
		break;
#endif
#ifdef CONFIG_UTS_NS
	case CLONE_NEWUTS:
		VFS_WARN_ON_ONCE(ops != &utsns_operations);
		break;
#endif
	}
}
#endif

int __ns_common_init(struct ns_common *ns, u32 ns_type,
		     const struct proc_ns_operations *ops, int inum)
{
	int ret;

	refcount_set(&ns->__ns_ref, 1);
	ns->stashed = NULL;
	ns->ops = ops;
	RCU_INIT_POINTER(ns->owner_cred, get_current_cred());
	ns->owner_prop = kzalloc(sizeof(*ns->owner_prop), GFP_KERNEL);
	if (!ns->owner_prop) {
		put_cred(rcu_access_pointer(ns->owner_cred));
		RCU_INIT_POINTER(ns->owner_cred, NULL);
		return -ENOMEM;
	}
	ns->owner_prop_set = false;
	ns->ns_id = 0;
	ns->ns_type = ns_type;
	RB_CLEAR_NODE(&ns->ns_tree_node);
	INIT_LIST_HEAD(&ns->ns_list_node);

#ifdef CONFIG_DEBUG_VFS
	ns_debug(ns, ops);
#endif

	if (inum) {
		ns->inum = inum;
		return 0;
	}
	ret = proc_alloc_inum(&ns->inum);
	if (ret) {
		put_cred(rcu_access_pointer(ns->owner_cred));
		RCU_INIT_POINTER(ns->owner_cred, NULL);
		kfree(ns->owner_prop);
		ns->owner_prop = NULL;
	}
	return ret;
}

void ns_common_set_owner_prop(struct ns_common *ns, const struct cred *cred)
{
	const struct cred *old_cred;

	if (!ns || !cred)
		return;

	if (!ns->owner_prop)
		return;

	/*
	 * Keep the full credential for inode materialization so LSMs with
	 * nested state can choose the identity that matches the inode's
	 * superblock. The retained prop below is the host/global snapshot used
	 * as a fallback for callers that cannot consume creds.
	 */
	old_cred = rcu_replace_pointer(ns->owner_cred, get_cred(cred), true);
	if (old_cred)
		put_cred(old_cred);

	if (READ_ONCE(ns->owner_prop_set))
		security_release_lsmprop(ns->owner_prop);
	security_cred_getlsmprop_global(cred, ns->owner_prop);
	security_lsmprop_hold(ns->owner_prop);
	WRITE_ONCE(ns->owner_prop_set, true);
}

void ns_common_owner_to_inode(struct ns_common *ns, struct inode *inode)
{
	const struct cred *owner_cred;
	const struct lsm_prop *owner_prop;

	if (!ns || !inode)
		return;

	owner_prop = READ_ONCE(ns->owner_prop);
	rcu_read_lock();
	do {
		owner_cred = rcu_dereference(ns->owner_cred);
	} while (owner_cred && !get_cred_rcu(owner_cred));
	rcu_read_unlock();

	if (owner_cred) {
		/* Selects host/global or child-local identity by inode state. */
		security_cred_to_inode(owner_cred, inode);
		put_cred(owner_cred);
		return;
	}

	if (READ_ONCE(ns->owner_prop_set) && owner_prop) {
		security_lsmprop_to_inode(owner_prop, inode);
		return;
	}

	security_cred_to_inode(&init_cred, inode);
}

void __ns_common_free(struct ns_common *ns)
{
	const struct cred *owner_cred = rcu_access_pointer(ns->owner_cred);

	if (owner_cred)
		put_cred(owner_cred);
	RCU_INIT_POINTER(ns->owner_cred, NULL);
	if (ns->owner_prop) {
		if (ns->owner_prop_set)
			security_release_lsmprop(ns->owner_prop);
		kfree(ns->owner_prop);
	}
	ns->owner_prop = NULL;
	ns->owner_prop_set = false;
	proc_free_inum(ns->inum);
}
