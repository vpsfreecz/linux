/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/cleanup.h>
#include <linux/err.h>

struct mnt_namespace;
struct fs_struct;
struct lsm_namespace;
struct syslog_namespace;
struct tracing_namespace;
struct user_namespace;
struct ns_common;

extern struct mnt_namespace init_mnt_ns;

extern struct mnt_namespace *copy_mnt_ns(u64, struct mnt_namespace *,
			struct user_namespace *, struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);
extern bool mnt_ns_current_boundary_can_see(const struct mnt_namespace *mntns);
extern void mnt_ns_set_boundary_namespaces(struct mnt_namespace *ns,
			struct syslog_namespace *syslog_ns,
			struct tracing_namespace *tracing_ns,
			struct lsm_namespace *lsm_ns);
DEFINE_FREE(put_mnt_ns, struct mnt_namespace *, if (!IS_ERR_OR_NULL(_T)) put_mnt_ns(_T))
extern struct ns_common *from_mnt_ns(struct mnt_namespace *);

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

#endif
#endif
