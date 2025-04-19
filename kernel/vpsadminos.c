#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <asm/page.h>
#include <linux/cgroup.h>
#include <linux/sched/cputime.h>
#include "sched/sched.h"

struct proc_dir_entry *proc_vpsadminos;

static int __init vpsadminos_init(void)
{
	int ret;

	ret = sysfs_create_mount_point(fs_kobj, "vpsadminos");

	proc_vpsadminos = proc_mkdir("vpsadminos", NULL);
	return ret;
}
fs_initcall(vpsadminos_init);

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
	const struct kobj_type *ktype = get_ktype(kobj);
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
	const struct kobj_type *ktype = get_ktype(kobj);
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

unsigned int online_cpus_in_cpu_cgroup(struct task_struct *p)
{
	struct cgroup_subsys_state *css, *css_parent;
	long quota, period;
	int cpus = 0, mincpus = INT_MAX;
	struct cgroup_namespace *cgns;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	task_lock(p);
	nsproxy = p->nsproxy;
	if (!nsproxy) {
		task_unlock(p);
		rcu_read_unlock();
		return 0;
	}
	cgns = nsproxy->cgroup_ns;
	get_cgroup_ns(cgns);
	if (!cgns) {
		task_unlock(p);
		rcu_read_unlock();
		return 0;
	}
	if (cgns == &init_cgroup_ns) {
		put_cgroup_ns(cgns);
		task_unlock(p);
		rcu_read_unlock();
		return 0;
	}
	task_unlock(p);

	if (!cgns->root_cset) {
		put_cgroup_ns(cgns);
		rcu_read_unlock();
		return 0;
	}
	css = cgns->root_cset->subsys[cpu_cgrp_id];
	if (!css || !css_tryget_online(css)) {
		put_cgroup_ns(cgns);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

up:
	quota = cpu_cfs_quota_read_s64(css, NULL);
	period = cpu_cfs_period_read_u64(css, NULL);

	if (quota > 0 && period > 0) {
		cpus = quota;
		if (do_div(cpus, period))
			cpus++;
		if (cpus < mincpus && cpus > 0)
			mincpus = cpus;
	}

	rcu_read_lock();
	if (css->parent && css->parent != css) {
		css_parent = css->parent;
		if (css_tryget_online(css_parent)) {
			css_put(css);
			css = css_parent;
			rcu_read_unlock();
			goto up;
		}
	}
	rcu_read_unlock();

	pr_debug("online_cpus_in_cpu_cgroup: debug @ line %d quota = %ld, period = %ld, cpus = %d\n", __LINE__, quota, period, cpus);
	css_put(css);
	put_cgroup_ns(cgns);
	return (mincpus == INT_MAX) ? 0 : mincpus;
}

// Caller's responsibility to make sure p lives throughout
int fake_online_cpumask(struct task_struct *p, struct cpumask *dstmask)
{
	unsigned int cpus, cpu, want;

	cpus = online_cpus_in_cpu_cgroup(p);
	if (!cpus)
		return 0;

	want = cpus;
	for_each_possible_cpu(cpu) {
		if (cpus > 0) {
			cpumask_set_cpu(cpu, dstmask);
			cpus--;
		} else {
			cpumask_clear_cpu(cpu, dstmask);
		}
	}
	return want - cpus;
}


// Caller's responsibility to make sure p lives throughout
void set_fake_affinity_cpumask(struct task_struct *p, const struct cpumask *srcmask)
{
	unsigned int want_cpus = cpumask_weight(srcmask);
	unsigned int online_cpus = online_cpus_in_cpu_cgroup(p);

	p->set_fake_cpu_mask = 1;
	if (want_cpus > online_cpus || want_cpus == online_cpus || want_cpus == 0)
		fake_online_cpumask(p, &p->fake_cpu_mask);
	else
		cpumask_copy(&p->fake_cpu_mask, srcmask);
}

// Caller's responsibility to make sure p lives throughout
int fake_affinity_cpumask(struct task_struct *p, struct cpumask *dstmask)
{
	if (p->set_fake_cpu_mask) {
		cpumask_and(dstmask, &p->fake_cpu_mask, cpu_active_mask);
		return 1;
	}

	int ret = fake_online_cpumask(p, dstmask);
	if (!ret)
		return 0;

	return 1;
}

void fake_cputime_readout_v1(struct task_struct *p, u64 timestamp, u64 *user, u64 *system, int *cpus)
{
	struct nsproxy *nsproxy;
	struct cgroup_subsys_state *css;
	int i;
	u64 timestamp_old;
	u64 elapsed, user_time, system_time, run_time;
	u64 usr = 0, sys = 0, sys_old = 0, usr_old = 0;
	u64 tmpusr, tmpusr_old, tmpsys, tmpsys_old;
	u64 usr_frac, sys_frac;
	struct cpumask cpu_fake_mask;

	rcu_read_lock();
	task_lock(p);
	nsproxy = p->nsproxy;
	if (!nsproxy || !nsproxy->cgroup_ns) {
		task_unlock(p);
		rcu_read_unlock();
		return;
	}
	css = nsproxy->cgroup_ns->root_cset->subsys[cpuacct_cgrp_id];
	if (!css || !css_tryget_online(css)) {
		task_unlock(p);
		rcu_read_unlock();
		return;
	}
	task_unlock(p);
	rcu_read_unlock();

	timestamp_old = cpustat_fake_set_timestamp(css, timestamp);
	elapsed = timestamp - timestamp_old;
	if (!elapsed)
		goto out;

	for_each_possible_cpu(i) {
		cpustat_fake_readout(css, i, &tmpusr, &tmpsys,
						&tmpusr_old, &tmpsys_old);
		usr += tmpusr;
		sys += tmpsys;
		usr_old += tmpusr_old;
		sys_old += tmpsys_old;
	}
	*user = usr;
	*system = sys;
	*cpus = online_cpus_in_cpu_cgroup(p);
	fake_online_cpumask(p, &cpu_fake_mask);

	user_time = usr - usr_old;
	system_time = sys - sys_old;
	run_time = user_time + system_time;

	if (!run_time || !timestamp_old)
		goto out;

	usr_frac = 10000 * user_time;
	do_div(usr_frac, run_time);
	sys_frac = 10000 - usr_frac;

	for_each_cpu(i, &cpu_fake_mask) {
		if (run_time >= elapsed) {
			usr = elapsed * usr_frac;
			do_div(usr, 10000);
			sys = elapsed - usr;
			run_time -= elapsed;
		} else if (run_time) {
			usr = run_time * usr_frac;
			do_div(usr, 10000);
			sys = run_time - usr;
			run_time = 0;
		} else {
			usr = 0;
			sys = 0;
		}
		cpustat_fake_write(css, i, usr, sys);
	}
out:
	css_put(css);
	return;
}

void fake_cputime_readout_v2(struct task_struct *p, u64 timestamp, u64 *user, u64 *system, int *cpus)
{
	struct nsproxy *nsproxy;
	struct cgroup *cgrp;
	int i;
	u64 timestamp_old;
	u64 elapsed, user_time, system_time, run_time;
	u64 usr = 0, sys = 0, sys_old = 0, usr_old = 0;
	u64 usr_frac, sys_frac;
	struct cpumask cpu_fake_mask;

	rcu_read_lock();
	task_lock(p);
	nsproxy = p->nsproxy;
	if (!nsproxy || !nsproxy->cgroup_ns) {
		task_unlock(p);
		rcu_read_unlock();
		return;
	}
	cgrp = nsproxy->cgroup_ns->root_cset->dfl_cgrp;
	if (!cgrp || !cgroup_tryget(cgrp)) {
		pr_debug("fake_cputime_readout_v2: cgrp is NULL\n");
		task_unlock(p);
		rcu_read_unlock();
		return;
	}
	task_unlock(p);
	rcu_read_unlock();

	timestamp_old = cgrp->rstat_cpu_fake_timestamp;
	cgrp->rstat_cpu_fake_timestamp = timestamp;

	elapsed = timestamp - timestamp_old;
	if (!elapsed)
		goto out;

	if (cgroup_parent(cgrp)) {
		cgroup_rstat_flush_hold(cgrp);
		usr_old = cgrp->prev_cputime_real.utime;
		sys_old = cgrp->prev_cputime_real.stime;
		cputime_adjust(&cgrp->bstat.cputime, &cgrp->prev_cputime_real,
			       &usr, &sys);
		cgroup_rstat_flush_release(cgrp);
	} else
		goto out;

	*user = usr;
	*system = sys;
	*cpus = online_cpus_in_cpu_cgroup(p);
	fake_online_cpumask(p, &cpu_fake_mask);

	user_time = usr - usr_old;
	system_time = sys - sys_old;
	run_time = user_time + system_time;

	if (!run_time)
		goto out;

	usr_frac = 10000 * user_time;
	do_div(usr_frac, run_time);
	sys_frac = 10000 - usr_frac;

	for_each_cpu(i, &cpu_fake_mask) {
		struct prev_cputime *cputime_fake = per_cpu_ptr(cgrp->prev_cputime_fake, i);

		if (run_time >= elapsed) {
			usr = elapsed * usr_frac;
			do_div(usr, 10000);
			sys = elapsed - usr;
			run_time -= elapsed;
		} else if (run_time) {
			usr = run_time * usr_frac;
			do_div(usr, 10000);
			sys = run_time - usr;
			run_time = 0;
		} else {
			usr = 0;
			sys = 0;
		}
		cputime_fake->utime += usr;
		cputime_fake->stime += sys;
	}
out:
	cgroup_put(cgrp);
	return;
}

void fake_cputime_readout(struct task_struct *p, u64 timestamp, u64 *user, u64 *system, int *cpus)
{
	if (cgroup_subsys_on_dfl(cpuacct_cgrp_subsys))
		fake_cputime_readout_v2(p, timestamp, user, system, cpus);
	else
		fake_cputime_readout_v1(p, timestamp, user, system, cpus);
}

void fake_cputime_readout_percpu(struct task_struct *p, int cpu, u64 *user, u64 *system)
{
	if (cgroup_subsys_on_dfl(cpuacct_cgrp_subsys)) {
		struct cgroup *cgrp;
		struct nsproxy *nsproxy;
		struct prev_cputime *cputime_fake;

		rcu_read_lock();
		task_lock(p);
		nsproxy = p->nsproxy;
		if (!nsproxy || !nsproxy->cgroup_ns) {
			task_unlock(p);
			rcu_read_unlock();
			return;
		}
		cgrp = nsproxy->cgroup_ns->root_cset->dfl_cgrp;
		if (!cgrp || !cgroup_tryget(cgrp)) {
			task_unlock(p);
			rcu_read_unlock();
			return;
		}
		task_unlock(p);
		rcu_read_unlock();

		cputime_fake = per_cpu_ptr(cgrp->prev_cputime_fake, cpu);
		*user = cputime_fake->utime;
		*system = cputime_fake->stime;

		cgroup_put(cgrp);
	}
	else {
		struct cgroup_subsys_state *css;
		struct nsproxy *nsproxy;

		rcu_read_lock();
		task_lock(p);
		nsproxy = p->nsproxy;
		if (!nsproxy || !nsproxy->cgroup_ns) {
			task_unlock(p);
			rcu_read_unlock();
			return;
		}
		css = nsproxy->cgroup_ns->root_cset->subsys[cpuacct_cgrp_id];
		if (!css || !css_tryget_online(css)) {
			task_unlock(p);
			rcu_read_unlock();
			return;
		}
		task_unlock(p);
		rcu_read_unlock();

		cpustat_fake_readout_percpu(css, cpu, user, system);

		css_put(css);
	}
}

u64 fake_cputime_readout_idle(u64 timestamp, struct task_struct *p)
{
	u64 user = 0, system = 0;
	int cpus;

	task_lock(p);
	if (!p->nsproxy || !p->nsproxy->cgroup_ns->loadavg_virt_enabled) {
		task_unlock(p);
		return 0;
	}
	task_unlock(p);

	fake_cputime_readout(p, timestamp, &user, &system, &cpus);

	return (timestamp * cpus) - user - system;
}

