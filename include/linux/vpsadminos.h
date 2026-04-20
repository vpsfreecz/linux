/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPSADMINOS_H
#define _LINUX_VPSADMINOS_H

#include <linux/memcontrol.h>
#include <linux/types.h>
#include <linux/user_namespace.h>

struct cpumask;
struct dentry;
struct proc_dir_entry;
struct seq_file;
struct task_struct;

enum vpsa_kernfs_filter_decision {
	VPSA_KERNFS_FILTER_DECISION_ALLOW = 0,
	VPSA_KERNFS_FILTER_DECISION_DENY,
	VPSA_KERNFS_FILTER_DECISION_HIDE,
};

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

unsigned int online_cpus_in_cpu_cgroup(struct task_struct *p);
void fake_cputime_readout(struct task_struct *p, u64 timestamp, u64 *user,
			 u64 *system, int *cpus);
void fake_cputime_readout_percpu(struct task_struct *p, int cpu, u64 *user,
			       u64 *system);
void set_fake_affinity_cpumask(struct task_struct *p, const struct cpumask *srcmask);
int fake_affinity_cpumask(struct task_struct *p, struct cpumask *dstmask);
int fake_online_cpumask(struct task_struct *p, struct cpumask *dstmask);
u64 fake_cputime_readout_idle(u64 timestamp, struct task_struct *p);
extern struct proc_dir_entry *proc_vpsadminos;
int virt_loadavg_proc_show(struct seq_file *m, void *v);

bool vpsa_kernfs_filter_subject_restricted_userns(const struct user_namespace *ns);

static inline bool vpsa_kernfs_filter_subject_restricted_current(void)
{
	return vpsa_kernfs_filter_subject_restricted_userns(current_user_ns());
}

u64 vpsa_kernfs_filter_generation(void);
bool vpsa_kernfs_filter_dentry_visibility_stale(const struct dentry *dentry);
void vpsa_kernfs_filter_dentry_set_visibility_token(struct dentry *dentry);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_proc_path_decide(const char *const *segments, const u16 *segment_lens,
			   u16 depth, unsigned int mask);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_sysfs_path_decide(const char *const *segments, const u16 *segment_lens,
			    u16 depth, unsigned int mask);

#endif /* _LINUX_VPSADMINOS_H */
