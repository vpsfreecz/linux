#ifndef VPSADMINOS_H
#define VPSADMINOS_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <asm/page.h>

struct user_namespace;

struct mem_cgroup *get_current_most_limited_memcg(void);
struct mem_cgroup *get_nearest_memcg_running_ksoftlimd(void);

extern ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf);
extern ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
				   size_t count, loff_t pos);
extern void fake_sysctl_bufs_init(struct user_namespace *ns);
extern void fake_sysctl_bufs_free(struct user_namespace *ns);

extern unsigned int online_cpus_in_cpu_cgroup(struct task_struct *p);
void fake_cputime_readout(struct task_struct *p, u64 timestamp, u64 *user, u64 *system, int *cpus);
u64 fake_cputime_readout_idle(struct timespec64 *uptime, struct task_struct *p);
void fake_cputime_readout_percpu(struct task_struct *p, int cpu, u64 *user, u64 *system);
extern void set_fake_affinity_cpumask(struct task_struct *p, const struct cpumask *srcmask);
extern int fake_affinity_cpumask(struct task_struct *p, struct cpumask *dstmask);
extern int fake_online_cpumask(struct task_struct *p, struct cpumask *dstmask);

struct proc_dir_entry;
extern struct proc_dir_entry *proc_vpsadminos;
extern int virt_loadavg_proc_show(struct seq_file *m, void *v);
#endif
