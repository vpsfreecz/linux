#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <asm/page.h>
#include "sched/sched.h"

#include <linux/vpsadminos-livepatch.h>
#include "kpatch-macros.h"
char old_uname[65];
char new_uname[65];

static int patch(patch_object *obj)
{
	scnprintf(new_uname, 64, "%s.%s", LIVEPATCH_ORIG_KERNEL_VERSION,
	    LIVEPATCH_NAME);
	scnprintf(old_uname, 64, "%s", init_uts_ns.name.release);
	scnprintf(init_uts_ns.name.release, 64, "%s", new_uname);
	return 0;
}
KPATCH_PRE_PATCH_CALLBACK(patch);
static void unpatch(patch_object *obj)
{
	scnprintf(init_uts_ns.name.release, 64, "%s", old_uname);
}
KPATCH_POST_UNPATCH_CALLBACK(unpatch);

int online_cpus_in_cpu_cgroup(struct task_struct *p)
{
	struct cgroup_subsys_state *css = p->nsproxy->cgroup_ns->root_cset->subsys[cpu_cgrp_id];
	long quota, period;
	int cpus = 0;

	quota = cpu_cfs_quota_read_s64(css, NULL);
	period = cpu_cfs_period_read_u64(css, NULL);

	if (quota > 0 && period > 0) {
		cpus = quota / period;

		if ((quota % period) > 0)
			cpus++;
	}

	return cpus;
}

void fake_cpuacct_readout(struct task_struct *p, u64 timestamp, u64 *user, u64 *system, int *cpus)
{
	struct cgroup_subsys_state *css = p->nsproxy->cgroup_ns->root_cset->subsys[cpuacct_cgrp_id];
	int i;
	u64 timestamp_old;
	u64 elapsed, user_time, system_time, run_time;
	u64 usr = 0, sys = 0, sys_old = 0, usr_old = 0;
	u64 tmpusr, tmpusr_old, tmpsys, tmpsys_old;
	u64 usr_frac, sys_frac;

	timestamp_old = cpuacct_cpuusage_fake_set_timestamp(css, timestamp);
	elapsed = timestamp - timestamp_old;
	if (!elapsed)
		return;

	for_each_possible_cpu(i) {
		cpuacct_cpuusage_fake_readout(css, i, &tmpusr, &tmpsys,
						&tmpusr_old, &tmpsys_old);
		usr += tmpusr;
		sys += tmpsys;
		usr_old += tmpusr_old;
		sys_old += tmpsys_old;
	}
	*user = usr;
	*system = sys;
	*cpus = online_cpus_in_cpu_cgroup(p);

	user_time = usr - usr_old;
	system_time = sys - sys_old;
	run_time = user_time + system_time;

	usr_frac = 10000 * user_time / run_time;
	sys_frac = 10000 - usr_frac;

	if (!run_time)
		return;

	for (i = 0; i < *cpus; i++) {
		pr_debug("CPU %d start, run_time %llu left\n", i, run_time);
		if (run_time >= elapsed) {
			usr = elapsed * usr_frac / 10000;
			sys = elapsed - usr;
			run_time -= elapsed;
		} else if (run_time) {
			usr = run_time * usr_frac / 10000;
			sys = run_time - usr;
			run_time = 0;
		} else {
			usr = 0;
			sys = 0;
		}
		pr_debug("CPU %d saving, usr %llu, sys %llu\n", i, usr, sys);
		cpuacct_cpuusage_fake_write(css, i, usr, sys);
	}
}

void fake_cpuacct_readout_percpu(struct task_struct *p, int cpu, u64 *user, u64 *system)
{
	struct cgroup_subsys_state *css = p->nsproxy->cgroup_ns->root_cset->subsys[cpuacct_cgrp_id];

	cpuacct_cpuusage_fake_readout_percpu(css, cpu, user, system);
}

int fake_cpumask(struct task_struct *p, struct cpumask *dstmask, const struct cpumask *srcmask)
{
	int cpus;
	int cpu, enabled;

	if (srcmask != NULL)
		cpumask_copy(dstmask, srcmask);

	if (current->nsproxy->cgroup_ns == &init_cgroup_ns)
		return 0;

	cpus = online_cpus_in_cpu_cgroup(p);

	if (!cpus)
		return 0;

	enabled = 0;
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, dstmask)) {
			if (enabled == cpus)
				cpumask_clear_cpu(cpu, dstmask);
			else
				enabled++;
		}
	}

	return enabled;
}

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct mem_cgroup *root_memcg, *walk_memcg, *res_memcg = NULL;
	unsigned long limit = PAGE_COUNTER_MAX;

	rcu_read_lock();

	root_memcg = walk_memcg = mem_cgroup_from_task(current);
	if (!root_memcg)
		goto not_found;

	while ((walk_memcg != root_mem_cgroup) && (walk_memcg != NULL)) {
		unsigned long max = mem_cgroup_get_max(walk_memcg);

		if (max < limit) {
			limit = max;
			res_memcg = walk_memcg;
		}
		walk_memcg = parent_mem_cgroup(walk_memcg);
	}

	if (limit == PAGE_COUNTER_MAX)
		goto not_found;

	WARN_ON(!css_tryget(&res_memcg->css));
	rcu_read_unlock();
	return res_memcg;

not_found:
	rcu_read_unlock();
	return NULL;
}

struct fake_sysctl_buf {
	ssize_t count;
	char *buf;
};

void fake_sysctl_bufs_init(struct user_namespace *ns)
{
	xa_init(&ns->fake_sysctl_bufs);
}

void fake_sysctl_bufs_free(struct user_namespace *ns)
{
	unsigned long index;
	struct fake_sysctl_buf *fbuf;
	xa_for_each(&ns->fake_sysctl_bufs, index, fbuf) {
		if (fbuf->buf)
			kfree(fbuf->buf);
		kfree(fbuf);
	}
}

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf)
{
	struct kobject *kobj = of->kn->parent->priv;
	struct kobj_type *ktype = get_ktype(kobj);
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = current_user_ns();
	struct fake_sysctl_buf *fbuf;

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		fbuf = xa_find(&ns->fake_sysctl_bufs,
		    &index, ULONG_MAX, XA_PRESENT);
		if (fbuf) {
			memcpy(buf, fbuf->buf, PAGE_SIZE);
			pr_debug("%s:%d: kobj %lu fbuf at %p count %lu\n", __func__, __LINE__, index, (void *)fbuf, fbuf->count);
			return fbuf->count;
		}
	}
	return 0;
}

ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			    size_t count, loff_t pos)
{
	struct kobject *kobj = of->kn->parent->priv;
	struct kobj_type *ktype = get_ktype(kobj);
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = current_user_ns();
	struct fake_sysctl_buf *fbuf;

	if (!ns_capable(ns, CAP_SYS_ADMIN))
		return -EPERM;

	if ((count > PAGE_SIZE) || (pos > PAGE_SIZE))
		return 0;

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		fbuf = xa_find(&ns->fake_sysctl_bufs,
		    &index, ULONG_MAX, XA_PRESENT);
		if (!fbuf) {
			fbuf = kzalloc(sizeof(struct fake_sysctl_buf), GFP_KERNEL);
			if (!fbuf)
				return 0;
			fbuf->buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
			if (!fbuf->buf) {
				kfree(fbuf);
				return 0;
			}
			xa_store(&ns->fake_sysctl_bufs,
			    (unsigned long)of->kn, fbuf, GFP_KERNEL);
		}
		memcpy(fbuf->buf, buf, PAGE_SIZE);
		fbuf->count = count;
		pr_debug("%s:%d: kobj %lu, fbuf at %p, pos %llu, count %lu\n", __func__, __LINE__, index, (void *)fbuf, pos, count);
		return count;
	}
	return 0;
}
