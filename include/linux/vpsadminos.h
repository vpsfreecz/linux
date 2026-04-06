/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPSADMINOS_H
#define _LINUX_VPSADMINOS_H

#include <linux/memcontrol.h>
#include <linux/user_namespace.h>

struct kernfs_open_file;

static inline struct user_namespace *current_1stlvl_user_ns(void)
{
	struct user_namespace *ns = current_user_ns();

	if (ns == &init_user_ns)
		return ns;

	while (ns->parent != &init_user_ns)
		ns = ns->parent;

	return ns;
}

struct mem_cgroup *get_current_most_limited_memcg(void);

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled);
ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled);
void fake_sysctl_bufs_init(struct user_namespace *ns);
void fake_sysctl_bufs_free(struct user_namespace *ns);

#endif /* _LINUX_VPSADMINOS_H */
