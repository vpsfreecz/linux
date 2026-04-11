/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPSADMINOS_H
#define _LINUX_VPSADMINOS_H

#include <linux/memcontrol.h>
#include <linux/user_namespace.h>

struct kernfs_open_file;
struct cpumask;
struct task_struct;

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

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf);
ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos);
void fake_sysctl_bufs_init(struct user_namespace *ns);
void fake_sysctl_bufs_free(struct user_namespace *ns);

unsigned int online_cpus_in_cpu_cgroup(struct task_struct *p);
void fake_cputime_readout(struct task_struct *p, u64 timestamp, u64 *user,
			 u64 *system, int *cpus);
void fake_cputime_readout_percpu(struct task_struct *p, int cpu, u64 *user,
			       u64 *system);
void set_fake_affinity_cpumask(struct task_struct *p, const struct cpumask *srcmask);
int fake_affinity_cpumask(struct task_struct *p, struct cpumask *dstmask);
int fake_online_cpumask(struct task_struct *p, struct cpumask *dstmask);

#endif /* _LINUX_VPSADMINOS_H */
