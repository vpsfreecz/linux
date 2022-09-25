#ifndef VPSADMINOS_H
#define VPSADMINOS_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <linux/user_namespace.h>

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
struct mem_cgroup *get_nearest_memcg_running_ksoftlimd(void);

extern ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf);
extern ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
				   size_t count, loff_t pos);
extern void fake_sysctl_bufs_init(struct user_namespace *ns);
extern void fake_sysctl_bufs_free(struct user_namespace *ns);
#endif
