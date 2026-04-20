// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/ctype.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/glob.h>
#include <linux/sysfs.h>
#include <linux/dcache.h>
#include <linux/memcontrol.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/cgroup.h>
#include <linux/sched/cputime.h>

#include <asm/page.h>

#include <linux/vpsadminos.h>

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

	while ((walk_memcg != root_mem_cgroup) && walk_memcg) {
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
	struct mutex lock;
	size_t count;
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
	xa_destroy(&ns->fake_sysctl_bufs);
}

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled)
{
	struct kernfs_node *parent = kernfs_get_parent(of->kn);
	struct kobject *kobj;
	const struct kobj_type *ktype;
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = of->file->f_cred->user_ns;
	struct fake_sysctl_buf *fbuf;
	size_t len;
	size_t stored;

	*handled = false;

	if (!parent)
		return 0;

	kobj = parent->priv;
	ktype = get_ktype(kobj);
	kernfs_put(parent);

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		fbuf = xa_load(&ns->fake_sysctl_bufs, index);
		if (fbuf) {
			*handled = true;
			if (pos < 0)
				return -EINVAL;
			mutex_lock(&fbuf->lock);
			stored = fbuf->count;
			if ((size_t)pos >= stored) {
				mutex_unlock(&fbuf->lock);
				return 0;
			}
			len = min_t(size_t, count, stored - (size_t)pos);
			if (len)
				memcpy(buf, fbuf->buf + (size_t)pos, len);
			mutex_unlock(&fbuf->lock);
			pr_debug("%s:%d: kobj %lu fbuf at %p, pos %lld, count %zu, read %zu\n",
				 __func__, __LINE__, index, (void *)fbuf,
				 pos, stored, len);
			return (ssize_t)len;
		}
	}
	return 0;
}

ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled)
{
	struct kernfs_node *parent;
	struct kobject *kobj;
	const struct kobj_type *ktype;
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = of->file->f_cred->user_ns;
	struct fake_sysctl_buf *fbuf;

	*handled = false;

	parent = kernfs_get_parent(of->kn);
	if (!parent)
		return 0;

	kobj = parent->priv;
	ktype = get_ktype(kobj);
	kernfs_put(parent);

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		*handled = true;

		if (!ns_capable(ns, CAP_SYS_ADMIN))
			return -EPERM;

		if (pos < 0 || pos > PAGE_SIZE)
			return -EINVAL;

		if (count > PAGE_SIZE - (size_t)pos)
			return -EFBIG;

		fbuf = xa_load(&ns->fake_sysctl_bufs, index);
		if (!fbuf) {
			void *old;

			fbuf = kzalloc(sizeof(*fbuf), GFP_KERNEL);
			if (!fbuf)
				return -ENOMEM;
			fbuf->buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
			if (!fbuf->buf) {
				kfree(fbuf);
				return -ENOMEM;
			}
			mutex_init(&fbuf->lock);
			old = xa_cmpxchg(&ns->fake_sysctl_bufs, index, NULL, fbuf,
					  GFP_KERNEL);
			if (xa_is_err(old)) {
				kfree(fbuf->buf);
				kfree(fbuf);
				return xa_err(old);
			}
			if (old) {
				kfree(fbuf->buf);
				kfree(fbuf);
				fbuf = old;
			}
		}
		mutex_lock(&fbuf->lock);
		if (!pos)
			fbuf->count = 0;
		else if ((size_t)pos > fbuf->count)
			memset(fbuf->buf + fbuf->count, 0,
			       (size_t)pos - fbuf->count);

		memcpy(fbuf->buf + (size_t)pos, buf, count);
		fbuf->count = max(fbuf->count, (size_t)pos + count);
		mutex_unlock(&fbuf->lock);
		pr_debug("%s:%d: kobj %lu, fbuf at %p, pos %lld, count %zu\n",
			 __func__, __LINE__, index, (void *)fbuf, pos, count);
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
	if (!cgns) {
		task_unlock(p);
		rcu_read_unlock();
		return 0;
	}
	get_cgroup_ns(cgns);
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

	pr_debug("%s:%d quota=%ld period=%ld cpus=%d\n",
		 __func__, __LINE__, quota, period, cpus);
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

void fake_cputime_readout_v1(struct task_struct *p, u64 timestamp,
			      u64 *user, u64 *system, int *cpus)
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
}

void fake_cputime_readout_v2(struct task_struct *p, u64 timestamp,
			      u64 *user, u64 *system, int *cpus)
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
		pr_debug("%s: cgrp is NULL\n", __func__);
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
		css_rstat_flush(&cgrp->self);
		usr_old = cgrp->prev_cputime_real.utime;
		sys_old = cgrp->prev_cputime_real.stime;
		cputime_adjust(&cgrp->bstat.cputime, &cgrp->prev_cputime_real,
			       &usr, &sys);
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
	} else {
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
	u64 user = 0, system = 0, total;
	int cpus;

	if (!p->nsproxy || !p->nsproxy->cgroup_ns ||
	    !p->nsproxy->cgroup_ns->loadavg_virt_enabled)
		return 0;

	fake_cputime_readout(p, timestamp, &user, &system, &cpus);
	total = timestamp * (u64)cpus;
	if (user + system >= total)
		return 0;

	return total - user - system;
}

#define VPSA_KERNFS_FILTER_POLICY_VERSION		1
#define VPSA_KERNFS_FILTER_POLICY_MAX_BYTES		(256 * 1024)
#define VPSA_KERNFS_FILTER_POLICY_MAX_RULES		4096
#define VPSA_KERNFS_FILTER_POLICY_MAX_SEGMENTS		128
#define VPSA_KERNFS_FILTER_ERRMSG_LEN			128
#define VPSA_KERNFS_FILTER_SEG_GLOB			BIT(0)
#define VPSA_KERNFS_FILTER_SEG_RECURSIVE			BIT(1)
#define VPSA_KERNFS_FILTER_DEFAULT_POLICY		"version 1\nscope noninit-userns\n"
#define VPSA_KERNFS_FILTER_SEG_TMP_MAX			256
#define VPSA_KERNFS_FILTER_REQ_READ			BIT(0)
#define VPSA_KERNFS_FILTER_REQ_WRITE			BIT(1)

enum vpsa_kernfs_filter_rule_fs {
	VPSA_KERNFS_FILTER_RULE_FS_PROC,
	VPSA_KERNFS_FILTER_RULE_FS_SYSFS,
	__VPSA_KERNFS_FILTER_RULE_FS_MAX,
};

enum vpsa_kernfs_filter_rule_action {
	VPSA_KERNFS_FILTER_RULE_ACTION_ALLOW,
	VPSA_KERNFS_FILTER_RULE_ACTION_DENY,
	VPSA_KERNFS_FILTER_RULE_ACTION_HIDE,
	__VPSA_KERNFS_FILTER_RULE_ACTION_MAX,
};

enum vpsa_kernfs_filter_rule_access {
	VPSA_KERNFS_FILTER_RULE_ACCESS_ANY,
	VPSA_KERNFS_FILTER_RULE_ACCESS_READ,
	VPSA_KERNFS_FILTER_RULE_ACCESS_WRITE,
	VPSA_KERNFS_FILTER_RULE_ACCESS_RW,
	__VPSA_KERNFS_FILTER_RULE_ACCESS_MAX,
};

struct vpsa_kernfs_filter_rule_segment {
	char *pattern;
	u16 len;
	u16 flags;
};

struct vpsa_kernfs_filter_rule {
	enum vpsa_kernfs_filter_rule_fs fs;
	enum vpsa_kernfs_filter_rule_action action;
	enum vpsa_kernfs_filter_rule_access access;
	u16 depth;
	u16 literal_prefix_depth;
	u16 wildcard_segments;
	char *path_storage;
	struct vpsa_kernfs_filter_rule_segment *segments;
};

struct vpsa_kernfs_filter {
	struct rcu_head rcu;
	u64 generation;
	u32 rule_count;
	u32 proc_rule_count;
	u32 sysfs_rule_count;
	u32 hide_rule_count;
	u32 deny_rule_count;
	u32 allow_rule_count;
	u32 literal_rule_count;
	u32 wildcard_rule_count;
	u32 max_depth;
	size_t canonical_len;
	char *canonical;
	struct vpsa_kernfs_filter_rule *rules;
};

struct vpsa_kernfs_filter_parse_error {
	unsigned int line;
	int err;
	char msg[VPSA_KERNFS_FILTER_ERRMSG_LEN];
};

struct vpsa_textbuf {
	char *buf;
	size_t len;
	size_t cap;
};

struct vpsa_kernfs_filter_replace_state {
	char *buf;
	size_t len;
	size_t cap;
	int err;
	bool wrote_any;
};

static DEFINE_MUTEX(vpsa_kernfs_filter_lock);
static struct vpsa_kernfs_filter __rcu *vpsa_kernfs_filter_active_policy;
static u64 vpsa_kernfs_filter_last_generation;
static u64 vpsa_kernfs_filter_replace_successes;
static u64 vpsa_kernfs_filter_replace_failures;
static int vpsa_kernfs_filter_last_errno;
static unsigned int vpsa_kernfs_filter_last_error_line;
static char vpsa_kernfs_filter_last_error[VPSA_KERNFS_FILTER_ERRMSG_LEN] = "ok";

static const char *const vpsa_kernfs_filter_fs_names[] = {
	[VPSA_KERNFS_FILTER_RULE_FS_PROC] = "proc",
	[VPSA_KERNFS_FILTER_RULE_FS_SYSFS] = "sysfs",
};

static const char *const vpsa_kernfs_filter_action_names[] = {
	[VPSA_KERNFS_FILTER_RULE_ACTION_ALLOW] = "allow",
	[VPSA_KERNFS_FILTER_RULE_ACTION_DENY] = "deny",
	[VPSA_KERNFS_FILTER_RULE_ACTION_HIDE] = "hide",
};

static const char *const vpsa_kernfs_filter_access_names[] = {
	[VPSA_KERNFS_FILTER_RULE_ACCESS_ANY] = "any",
	[VPSA_KERNFS_FILTER_RULE_ACCESS_READ] = "read",
	[VPSA_KERNFS_FILTER_RULE_ACCESS_WRITE] = "write",
	[VPSA_KERNFS_FILTER_RULE_ACCESS_RW] = "rw",
};

static void vpsa_kernfs_filter_rule_destroy(struct vpsa_kernfs_filter_rule *rule)
{
	if (!rule)
		return;

	kfree(rule->segments);
	rule->segments = NULL;
	kfree(rule->path_storage);
	rule->path_storage = NULL;
}

static void vpsa_kernfs_filter_destroy(struct vpsa_kernfs_filter *policy)
{
	u32 i;

	if (!policy)
		return;

	for (i = 0; i < policy->rule_count; i++)
		vpsa_kernfs_filter_rule_destroy(&policy->rules[i]);

	kfree(policy->rules);
	kfree(policy->canonical);
	kfree(policy);
}

static void vpsa_kernfs_filter_rcu_free(struct rcu_head *rcu)
{
	struct vpsa_kernfs_filter *policy;

	policy = container_of(rcu, struct vpsa_kernfs_filter, rcu);
	vpsa_kernfs_filter_destroy(policy);
}

static void vpsa_kernfs_filter_parse_error_set(struct vpsa_kernfs_filter_parse_error *perr,
				      unsigned int line,
				      int err,
				      const char *fmt, ...)
{
	va_list args;

	if (!perr)
		return;

	perr->line = line;
	perr->err = err;

	va_start(args, fmt);
	vscnprintf(perr->msg, sizeof(perr->msg), fmt, args);
	va_end(args);
}

static void vpsa_textbuf_free(struct vpsa_textbuf *tb)
{
	kfree(tb->buf);
	tb->buf = NULL;
	tb->len = 0;
	tb->cap = 0;
}

static int vpsa_textbuf_reserve(struct vpsa_textbuf *tb, size_t extra)
{
	size_t need;
	size_t new_cap;
	char *new_buf;

	if (check_add_overflow(tb->len, extra + 1, &need))
		return -EOVERFLOW;

	if (need <= tb->cap)
		return 0;

	new_cap = tb->cap ? tb->cap : 256;
	while (new_cap < need) {
		if (new_cap > SIZE_MAX / 2)
			return -E2BIG;
		new_cap <<= 1;
	}

	new_buf = krealloc(tb->buf, new_cap, GFP_KERNEL);
	if (!new_buf)
		return -ENOMEM;

	tb->buf = new_buf;
	tb->cap = new_cap;
	return 0;
}

static int vpsa_textbuf_append_len(struct vpsa_textbuf *tb,
				  const char *src, size_t len)
{
	int ret;

	ret = vpsa_textbuf_reserve(tb, len);
	if (ret)
		return ret;

	memcpy(tb->buf + tb->len, src, len);
	tb->len += len;
	tb->buf[tb->len] = '\0';
	return 0;
}

static int vpsa_textbuf_append(struct vpsa_textbuf *tb, const char *src)
{
	return vpsa_textbuf_append_len(tb, src, strlen(src));
}

static char *vpsa_next_token(char **cursor)
{
	char *tok;

	if (!cursor || !*cursor)
		return NULL;

	while ((tok = strsep(cursor, " \t")) != NULL) {
		if (*tok)
			return tok;
	}

	return NULL;
}

static bool vpsa_segment_has_glob(const char *segment)
{
	return strpbrk(segment, "*?[\\") != NULL;
}

static int vpsa_validate_segment_glob(const char *segment)
{
	bool escape = false;
	bool in_class = false;
	bool class_has_content = false;
	const char *p;

	for (p = segment; *p; p++) {
		char ch = *p;

		if (escape) {
			escape = false;
			continue;
		}

		switch (ch) {
		case '\\':
			escape = true;
			break;
		case '[':
			if (in_class)
				return -EINVAL;
			in_class = true;
			class_has_content = false;
			break;
		case ']':
			if (!in_class || !class_has_content)
				return -EINVAL;
			in_class = false;
			break;
		default:
			if (in_class)
				class_has_content = true;
			break;
		}
	}

	if (escape || in_class)
		return -EINVAL;

	return 0;
}

static int vpsa_kernfs_filter_rule_compile_path(struct vpsa_kernfs_filter_rule *rule,
				       const char *path,
				       struct vpsa_kernfs_filter_parse_error *perr,
				       unsigned int line)
{
	size_t path_len;
	const char *p;
	u16 depth = 0;
	u16 wildcard_segments = 0;
	u16 literal_prefix_depth = 0;
	bool seen_wild = false;
	char *storage;
	char *walker;
	u16 idx = 0;

	if (!path || path[0] != '/') {
		vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "path must start with '/'");
		return -EINVAL;
	}

	path_len = strlen(path);
	if (path_len == 1) {
		vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "path '/' is not allowed; use '/**' for full subtree rules");
		return -EINVAL;
	}

	for (p = path + 1; *p;) {
		const char *slash = strchr(p, '/');
		size_t seglen = slash ? (size_t)(slash - p) : strlen(p);
		const char *seg = p;
		int ret;

		if (!seglen) {
			vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "empty path segment is not allowed");
			return -EINVAL;
		}

		if (seglen == 1 && seg[0] == '.') {
			vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "'.' path segments are not allowed");
			return -EINVAL;
		}

		if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
			vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "'..' path segments are not allowed");
			return -EINVAL;
		}

		if (seglen == 2 && seg[0] == '*' && seg[1] == '*') {
			if (slash && slash[1]) {
				vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
						 "'**' must be the final path segment");
				return -EINVAL;
			}
			seen_wild = true;
			wildcard_segments++;
		} else {
			char *segment_copy;

			segment_copy = kmemdup_nul(seg, seglen, GFP_KERNEL);
			if (!segment_copy)
				return -ENOMEM;

			ret = vpsa_validate_segment_glob(segment_copy);
			if (ret) {
				kfree(segment_copy);
				vpsa_kernfs_filter_parse_error_set(perr, line, ret,
						 "malformed glob segment '%.*s'",
						 (int)seglen, seg);
				return ret;
			}

			if (strstr(segment_copy, "**")) {
				kfree(segment_copy);
				vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
						 "'**' is only allowed as a full segment");
				return -EINVAL;
			}

			if (vpsa_segment_has_glob(segment_copy)) {
				seen_wild = true;
				wildcard_segments++;
			} else if (!seen_wild) {
				literal_prefix_depth++;
			}
			kfree(segment_copy);
		}

		depth++;
		if (depth > VPSA_KERNFS_FILTER_POLICY_MAX_SEGMENTS) {
			vpsa_kernfs_filter_parse_error_set(perr, line, -E2BIG,
					 "too many path segments");
			return -E2BIG;
		}

		if (!slash)
			break;

		if (!slash[1]) {
			vpsa_kernfs_filter_parse_error_set(perr, line, -EINVAL,
					 "trailing '/' is not allowed");
			return -EINVAL;
		}

		p = slash + 1;
	}

	storage = kstrdup(path + 1, GFP_KERNEL);
	if (!storage)
		return -ENOMEM;

	rule->segments = kcalloc(depth, sizeof(*rule->segments), GFP_KERNEL);
	if (!rule->segments) {
		kfree(storage);
		return -ENOMEM;
	}

	rule->path_storage = storage;
	rule->depth = depth;
	rule->literal_prefix_depth = literal_prefix_depth;
	rule->wildcard_segments = wildcard_segments;

	walker = storage;
	while (walker && *walker && idx < depth) {
		char *slash = strchr(walker, '/');
		u16 flags = 0;
		size_t seglen;

		if (slash)
			*slash = '\0';

		seglen = strlen(walker);
		if (seglen == 2 && walker[0] == '*' && walker[1] == '*')
			flags |= VPSA_KERNFS_FILTER_SEG_RECURSIVE | VPSA_KERNFS_FILTER_SEG_GLOB;
		else if (vpsa_segment_has_glob(walker))
			flags |= VPSA_KERNFS_FILTER_SEG_GLOB;

		rule->segments[idx].pattern = walker;
		rule->segments[idx].len = seglen;
		rule->segments[idx].flags = flags;
		idx++;

		if (!slash)
			break;
		walker = slash + 1;
	}

	return 0;
}

static int vpsa_kernfs_filter_rule_fs_from_token(const char *tok,
				        enum vpsa_kernfs_filter_rule_fs *fs)
{
	if (!strcmp(tok, "proc")) {
		*fs = VPSA_KERNFS_FILTER_RULE_FS_PROC;
		return 0;
	}
	if (!strcmp(tok, "sysfs")) {
		*fs = VPSA_KERNFS_FILTER_RULE_FS_SYSFS;
		return 0;
	}
	return -EINVAL;
}

static int vpsa_kernfs_filter_rule_action_from_token(const char *tok,
					    enum vpsa_kernfs_filter_rule_action *action)
{
	if (!strcmp(tok, "allow")) {
		*action = VPSA_KERNFS_FILTER_RULE_ACTION_ALLOW;
		return 0;
	}
	if (!strcmp(tok, "deny")) {
		*action = VPSA_KERNFS_FILTER_RULE_ACTION_DENY;
		return 0;
	}
	if (!strcmp(tok, "hide")) {
		*action = VPSA_KERNFS_FILTER_RULE_ACTION_HIDE;
		return 0;
	}
	return -EINVAL;
}

static int vpsa_kernfs_filter_rule_access_from_token(const char *tok,
					    enum vpsa_kernfs_filter_rule_access *access)
{
	if (!strcmp(tok, "any")) {
		*access = VPSA_KERNFS_FILTER_RULE_ACCESS_ANY;
		return 0;
	}
	if (!strcmp(tok, "read")) {
		*access = VPSA_KERNFS_FILTER_RULE_ACCESS_READ;
		return 0;
	}
	if (!strcmp(tok, "write")) {
		*access = VPSA_KERNFS_FILTER_RULE_ACCESS_WRITE;
		return 0;
	}
	if (!strcmp(tok, "rw")) {
		*access = VPSA_KERNFS_FILTER_RULE_ACCESS_RW;
		return 0;
	}
	return -EINVAL;
}

static int vpsa_kernfs_filter_append_rule_text(struct vpsa_textbuf *tb,
				     const struct vpsa_kernfs_filter_rule *rule,
				     const char *path)
{
	int ret;

	ret = vpsa_textbuf_append(tb, vpsa_kernfs_filter_fs_names[rule->fs]);
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, " ");
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, vpsa_kernfs_filter_action_names[rule->action]);
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, " ");
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, vpsa_kernfs_filter_access_names[rule->access]);
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, " ");
	if (ret)
		return ret;
	ret = vpsa_textbuf_append(tb, path);
	if (ret)
		return ret;
	return vpsa_textbuf_append(tb, "\n");
}

static int vpsa_kernfs_filter_parse_rule(char *line,
				       struct vpsa_kernfs_filter_rule *rule,
				       struct vpsa_kernfs_filter_parse_error *perr,
				       struct vpsa_textbuf *canonical,
				       unsigned int line_no)
{
	char *cursor = line;
	char *tok_fs;
	char *tok_action;
	char *tok_access;
	char *tok_path;
	char *rest;
	int ret;

	tok_fs = vpsa_next_token(&cursor);
	tok_action = vpsa_next_token(&cursor);
	tok_access = vpsa_next_token(&cursor);
	tok_path = vpsa_next_token(&cursor);

	if (!tok_fs || !tok_action || !tok_access || !tok_path) {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, -EINVAL,
					 "rule must be '<fs> <action> <access> <path>'");
		return -EINVAL;
	}

	rest = skip_spaces(cursor ?: "");
	if (*rest && *rest != '#') {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, -EINVAL,
					 "unexpected trailing tokens after path");
		return -EINVAL;
	}

	ret = vpsa_kernfs_filter_rule_fs_from_token(tok_fs, &rule->fs);
	if (ret) {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, ret,
					 "unknown filesystem '%s'", tok_fs);
		return ret;
	}

	ret = vpsa_kernfs_filter_rule_action_from_token(tok_action, &rule->action);
	if (ret) {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, ret,
					 "unknown action '%s'", tok_action);
		return ret;
	}

	ret = vpsa_kernfs_filter_rule_access_from_token(tok_access, &rule->access);
	if (ret) {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, ret,
					 "unknown access mode '%s'", tok_access);
		return ret;
	}

	if (rule->action != VPSA_KERNFS_FILTER_RULE_ACTION_DENY &&
	    rule->access != VPSA_KERNFS_FILTER_RULE_ACCESS_ANY) {
		vpsa_kernfs_filter_parse_error_set(perr, line_no, -EINVAL,
					 "only 'deny' rules may use read/write/rw access modes");
		return -EINVAL;
	}

	ret = vpsa_kernfs_filter_rule_compile_path(rule, tok_path, perr, line_no);
	if (ret)
		return ret;

	ret = vpsa_kernfs_filter_append_rule_text(canonical, rule, tok_path);
	if (ret)
		vpsa_kernfs_filter_parse_error_set(perr, line_no, ret,
					 "failed to build canonical policy text");

	return ret;
}

static int vpsa_kernfs_filter_parse(struct vpsa_kernfs_filter **ret_policy,
				  const char *text, size_t len,
				  struct vpsa_kernfs_filter_parse_error *perr)
{
	struct vpsa_kernfs_filter *policy = NULL;
	struct vpsa_textbuf canonical = {};
	struct vpsa_kernfs_filter_rule *rules = NULL;
	char *scratch = NULL;
	size_t rules_cap = 0;
	unsigned int line_no = 0;
	bool saw_version = false;
	bool saw_scope = false;
	char *cursor;
	int ret = 0;

	if (!ret_policy)
		return -EINVAL;

	if (!text || !len) {
		vpsa_kernfs_filter_parse_error_set(perr, 0, -EINVAL,
					 "policy text is empty");
		return -EINVAL;
	}

	if (len > VPSA_KERNFS_FILTER_POLICY_MAX_BYTES) {
		vpsa_kernfs_filter_parse_error_set(perr, 0, -E2BIG,
					 "policy exceeds maximum size of %u bytes",
					 VPSA_KERNFS_FILTER_POLICY_MAX_BYTES);
		return -E2BIG;
	}

	policy = kzalloc(sizeof(*policy), GFP_KERNEL);
	if (!policy)
		return -ENOMEM;

	ret = vpsa_textbuf_append(&canonical, "version 1\n");
	if (ret)
		goto out;
	ret = vpsa_textbuf_append(&canonical, "scope noninit-userns\n");
	if (ret)
		goto out;

	scratch = kmemdup_nul(text, len, GFP_KERNEL);
	if (!scratch) {
		ret = -ENOMEM;
		goto out;
	}

	cursor = scratch;
	while (cursor) {
		char *line = strsep(&cursor, "\n");
		char *trimmed;
		char *next;

		line_no++;
		if (!line)
			continue;
		trimmed = strim(line);
		if (!*trimmed || *trimmed == '#')
			continue;

		next = skip_spaces(trimmed);
		if (!saw_version) {
			char *tok0 = vpsa_next_token(&next);
			char *tok1 = vpsa_next_token(&next);
			char *rest = skip_spaces(next ?: "");

			if (!tok0 || !tok1 || strcmp(tok0, "version") ||
			    strcmp(tok1, "1") || (*rest && *rest != '#')) {
				vpsa_kernfs_filter_parse_error_set(perr, line_no, -EINVAL,
						 "first non-comment line must be 'version 1'");
				ret = -EINVAL;
				goto out;
			}
			saw_version = true;
			continue;
		}

		next = skip_spaces(trimmed);
		if (!saw_scope) {
			char *tok0 = vpsa_next_token(&next);
			char *tok1 = vpsa_next_token(&next);
			char *rest = skip_spaces(next ?: "");

			if (!tok0 || !tok1 || strcmp(tok0, "scope") ||
			    strcmp(tok1, "noninit-userns") || (*rest && *rest != '#')) {
				vpsa_kernfs_filter_parse_error_set(perr, line_no, -EINVAL,
						 "second non-comment line must be 'scope noninit-userns'");
				ret = -EINVAL;
				goto out;
			}
			saw_scope = true;
			continue;
		}

		if (policy->rule_count >= VPSA_KERNFS_FILTER_POLICY_MAX_RULES) {
			vpsa_kernfs_filter_parse_error_set(perr, line_no, -E2BIG,
					 "too many policy rules");
			ret = -E2BIG;
			goto out;
		}

		if (policy->rule_count == rules_cap) {
			size_t old_cap = rules_cap;
			size_t new_cap = rules_cap ? rules_cap << 1 : 32;
			struct vpsa_kernfs_filter_rule *new_rules;

			new_rules = krealloc(rules, new_cap * sizeof(*new_rules),
					     GFP_KERNEL);
			if (!new_rules) {
				ret = -ENOMEM;
				goto out;
			}
			memset(new_rules + old_cap, 0,
			       (new_cap - old_cap) * sizeof(*new_rules));
			rules = new_rules;
			rules_cap = new_cap;
		}

		ret = vpsa_kernfs_filter_parse_rule(trimmed,
						 &rules[policy->rule_count],
						 perr,
						 &canonical,
						 line_no);
		if (ret)
			goto out;

		policy->rule_count++;
	}

	if (!saw_version) {
		vpsa_kernfs_filter_parse_error_set(perr, 0, -EINVAL,
					 "missing 'version 1' header");
		ret = -EINVAL;
		goto out;
	}

	if (!saw_scope) {
		vpsa_kernfs_filter_parse_error_set(perr, 0, -EINVAL,
					 "missing 'scope noninit-userns' header");
		ret = -EINVAL;
		goto out;
	}

	policy->rules = rules;
	rules = NULL;
	policy->canonical = canonical.buf;
	policy->canonical_len = canonical.len;
	canonical.buf = NULL;
	canonical.cap = 0;
	canonical.len = 0;

	if (policy->rule_count) {
		u32 i;

		for (i = 0; i < policy->rule_count; i++) {
			const struct vpsa_kernfs_filter_rule *rule = &policy->rules[i];

			if (rule->fs == VPSA_KERNFS_FILTER_RULE_FS_PROC)
				policy->proc_rule_count++;
			else if (rule->fs == VPSA_KERNFS_FILTER_RULE_FS_SYSFS)
				policy->sysfs_rule_count++;

			switch (rule->action) {
			case VPSA_KERNFS_FILTER_RULE_ACTION_ALLOW:
				policy->allow_rule_count++;
				break;
			case VPSA_KERNFS_FILTER_RULE_ACTION_DENY:
				policy->deny_rule_count++;
				break;
			case VPSA_KERNFS_FILTER_RULE_ACTION_HIDE:
				policy->hide_rule_count++;
				break;
			default:
				break;
			}

			if (rule->wildcard_segments)
				policy->wildcard_rule_count++;
			else
				policy->literal_rule_count++;

			if (rule->depth > policy->max_depth)
				policy->max_depth = rule->depth;
		}
	}

	*ret_policy = policy;
	policy = NULL;
	ret = 0;
out:
	kfree(scratch);
	if (rules) {
		size_t i;

		for (i = 0; i < rules_cap; i++)
			vpsa_kernfs_filter_rule_destroy(&rules[i]);
		kfree(rules);
	}
	vpsa_textbuf_free(&canonical);
	vpsa_kernfs_filter_destroy(policy);
	return ret;
}


static unsigned int vpsa_kernfs_filter_mask_to_request(unsigned int mask)
{
	unsigned int req = 0;

	if (mask & MAY_WRITE)
		req |= VPSA_KERNFS_FILTER_REQ_WRITE;
	if (mask & (MAY_READ | MAY_EXEC))
		req |= VPSA_KERNFS_FILTER_REQ_READ;
	if (!req)
		req = VPSA_KERNFS_FILTER_REQ_READ;

	return req;
}

static bool vpsa_kernfs_filter_segment_pattern_matches(
	const struct vpsa_kernfs_filter_rule_segment *segment,
	const char *name, u16 len)
{
	char tmp[VPSA_KERNFS_FILTER_SEG_TMP_MAX];

	if (!(segment->flags & VPSA_KERNFS_FILTER_SEG_GLOB))
		return segment->len == len && !memcmp(segment->pattern, name, len);

	if (len >= sizeof(tmp))
		return false;

	memcpy(tmp, name, len);
	tmp[len] = '\0';
	return glob_match(segment->pattern, tmp);
}

static bool vpsa_kernfs_filter_rule_matches_segments(const struct vpsa_kernfs_filter_rule *rule,
				    const char *const *segments,
				    const u16 *segment_lens,
				    u16 depth)
{
	bool recursive = false;
	u16 i;

	if (!rule || !segments || !segment_lens || !rule->depth)
		return false;

	if (rule->segments[rule->depth - 1].flags & VPSA_KERNFS_FILTER_SEG_RECURSIVE)
		recursive = true;

	if (!recursive && depth != rule->depth)
		return false;
	if (recursive && depth + 1 < rule->depth)
		return false;

	for (i = 0; i < rule->depth; i++) {
		const struct vpsa_kernfs_filter_rule_segment *seg = &rule->segments[i];

		if (seg->flags & VPSA_KERNFS_FILTER_SEG_RECURSIVE)
			return true;
		if (i >= depth)
			return false;
		if (!vpsa_kernfs_filter_segment_pattern_matches(seg, segments[i],
					      segment_lens[i]))
			return false;
	}

	return !recursive ? depth == rule->depth : true;
}

static bool vpsa_kernfs_filter_rule_access_matches(const struct vpsa_kernfs_filter_rule *rule,
				  unsigned int req)
{
	switch (rule->access) {
	case VPSA_KERNFS_FILTER_RULE_ACCESS_ANY:
		return true;
	case VPSA_KERNFS_FILTER_RULE_ACCESS_READ:
		return req & VPSA_KERNFS_FILTER_REQ_READ;
	case VPSA_KERNFS_FILTER_RULE_ACCESS_WRITE:
		return req & VPSA_KERNFS_FILTER_REQ_WRITE;
	case VPSA_KERNFS_FILTER_RULE_ACCESS_RW:
		return req & (VPSA_KERNFS_FILTER_REQ_READ | VPSA_KERNFS_FILTER_REQ_WRITE);
	default:
		return false;
	}
}

static bool vpsa_kernfs_filter_rule_better_match(const struct vpsa_kernfs_filter_rule *rule,
					bool explicit_access,
					const struct vpsa_kernfs_filter_rule *best,
					bool best_explicit_access)
{
	if (!best)
		return true;
	if (rule->depth != best->depth)
		return rule->depth > best->depth;
	if (rule->literal_prefix_depth != best->literal_prefix_depth)
		return rule->literal_prefix_depth > best->literal_prefix_depth;
	if (rule->wildcard_segments != best->wildcard_segments)
		return rule->wildcard_segments < best->wildcard_segments;
	if (explicit_access != best_explicit_access)
		return explicit_access;
	return true;
}

static enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_path_decide(enum vpsa_kernfs_filter_rule_fs fs,
		      const char *const *segments,
		      const u16 *segment_lens,
		      u16 depth,
		      unsigned int mask)
{
	struct vpsa_kernfs_filter *policy;
	const struct vpsa_kernfs_filter_rule *best = NULL;
	bool best_explicit_access = false;
	unsigned int req;
	u32 i;

	if (!depth || !vpsa_kernfs_filter_subject_restricted_current())
		return VPSA_KERNFS_FILTER_DECISION_ALLOW;

	req = vpsa_kernfs_filter_mask_to_request(mask);

	rcu_read_lock();
	policy = rcu_dereference(vpsa_kernfs_filter_active_policy);
	if (!policy)
		goto out_unlock;

	for (i = 0; i < policy->rule_count; i++) {
		const struct vpsa_kernfs_filter_rule *rule = &policy->rules[i];
		bool explicit_access;

		if (rule->fs != fs)
			continue;
		if (!vpsa_kernfs_filter_rule_access_matches(rule, req))
			continue;
		if (!vpsa_kernfs_filter_rule_matches_segments(rule, segments, segment_lens,
					      depth))
			continue;

		explicit_access = rule->access != VPSA_KERNFS_FILTER_RULE_ACCESS_ANY;
		if (vpsa_kernfs_filter_rule_better_match(rule, explicit_access, best,
						best_explicit_access)) {
			best = rule;
			best_explicit_access = explicit_access;
		}
	}

	if (!best)
		goto out_unlock;

	switch (best->action) {
	case VPSA_KERNFS_FILTER_RULE_ACTION_HIDE:
		rcu_read_unlock();
		return VPSA_KERNFS_FILTER_DECISION_HIDE;
	case VPSA_KERNFS_FILTER_RULE_ACTION_DENY:
		rcu_read_unlock();
		return VPSA_KERNFS_FILTER_DECISION_DENY;
	default:
		break;
	}

out_unlock:
	rcu_read_unlock();
	return VPSA_KERNFS_FILTER_DECISION_ALLOW;
}

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_proc_path_decide(const char *const *segments, const u16 *segment_lens,
			   u16 depth, unsigned int mask)
{
	return vpsa_kernfs_filter_path_decide(VPSA_KERNFS_FILTER_RULE_FS_PROC, segments,
				    segment_lens, depth, mask);
}
EXPORT_SYMBOL_GPL(vpsa_kernfs_filter_proc_path_decide);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_sysfs_path_decide(const char *const *segments,
			    const u16 *segment_lens,
			    u16 depth,
			    unsigned int mask)
{
	return vpsa_kernfs_filter_path_decide(VPSA_KERNFS_FILTER_RULE_FS_SYSFS, segments,
				    segment_lens, depth, mask);
}
EXPORT_SYMBOL_GPL(vpsa_kernfs_filter_sysfs_path_decide);

bool vpsa_kernfs_filter_subject_restricted_userns(const struct user_namespace *ns)
{
	return ns && ns != &init_user_ns;
}
EXPORT_SYMBOL_GPL(vpsa_kernfs_filter_subject_restricted_userns);

u64 vpsa_kernfs_filter_generation(void)
{
	struct vpsa_kernfs_filter *policy;
	u64 generation = 0;

	rcu_read_lock();
	policy = rcu_dereference(vpsa_kernfs_filter_active_policy);
	if (policy)
		generation = READ_ONCE(policy->generation);
	rcu_read_unlock();

	return generation;
}
EXPORT_SYMBOL_GPL(vpsa_kernfs_filter_generation);

static unsigned long vpsa_kernfs_filter_visibility_token_current(void)
{
	if (!vpsa_kernfs_filter_subject_restricted_current())
		return 0;

	return (unsigned long)vpsa_kernfs_filter_generation();
}

bool vpsa_kernfs_filter_dentry_visibility_stale(const struct dentry *dentry)
{
	return (unsigned long)READ_ONCE(dentry->d_fsdata) !=
		vpsa_kernfs_filter_visibility_token_current();
}

void vpsa_kernfs_filter_dentry_set_visibility_token(struct dentry *dentry)
{
	WRITE_ONCE(dentry->d_fsdata,
		   (void *)vpsa_kernfs_filter_visibility_token_current());
}

static void vpsa_kernfs_filter_record_replace_result(int ret,
				    const struct vpsa_kernfs_filter_parse_error *perr)
{
	mutex_lock(&vpsa_kernfs_filter_lock);
	if (!ret) {
		vpsa_kernfs_filter_replace_successes++;
		vpsa_kernfs_filter_last_errno = 0;
		vpsa_kernfs_filter_last_error_line = 0;
		strscpy(vpsa_kernfs_filter_last_error, "ok", sizeof(vpsa_kernfs_filter_last_error));
	} else {
		vpsa_kernfs_filter_replace_failures++;
		vpsa_kernfs_filter_last_errno = ret;
		vpsa_kernfs_filter_last_error_line = perr ? perr->line : 0;
		if (perr && perr->msg[0])
			strscpy(vpsa_kernfs_filter_last_error, perr->msg,
				sizeof(vpsa_kernfs_filter_last_error));
		else
			snprintf(vpsa_kernfs_filter_last_error, sizeof(vpsa_kernfs_filter_last_error),
				 "replace failed: %d", ret);
	}
	mutex_unlock(&vpsa_kernfs_filter_lock);
}

static int vpsa_kernfs_filter_install_policy(struct vpsa_kernfs_filter *new_policy)
{
	struct vpsa_kernfs_filter *old_policy;

	if (!new_policy)
		return -EINVAL;

	mutex_lock(&vpsa_kernfs_filter_lock);
	new_policy->generation = ++vpsa_kernfs_filter_last_generation;
	old_policy = rcu_dereference_protected(vpsa_kernfs_filter_active_policy,
					       lockdep_is_held(&vpsa_kernfs_filter_lock));
	rcu_assign_pointer(vpsa_kernfs_filter_active_policy, new_policy);
	mutex_unlock(&vpsa_kernfs_filter_lock);

	if (old_policy)
		call_rcu(&old_policy->rcu, vpsa_kernfs_filter_rcu_free);

	pr_info("vpsAdminOS: kernfs-filter generation=%llu rules=%u proc=%u sysfs=%u\n",
		new_policy->generation, new_policy->rule_count,
		new_policy->proc_rule_count, new_policy->sysfs_rule_count);
	return 0;
}

static int vpsa_kernfs_filter_replace_policy_text(const char *text, size_t len)
{
	struct vpsa_kernfs_filter_parse_error perr = {};
	struct vpsa_kernfs_filter *new_policy = NULL;
	int ret;

	ret = vpsa_kernfs_filter_parse(&new_policy, text, len, &perr);
	if (ret) {
		vpsa_kernfs_filter_record_replace_result(ret, &perr);
		return ret;
	}

	ret = vpsa_kernfs_filter_install_policy(new_policy);
	if (ret) {
		vpsa_kernfs_filter_destroy(new_policy);
		vpsa_kernfs_filter_record_replace_result(ret, NULL);
		return ret;
	}

	vpsa_kernfs_filter_record_replace_result(0, NULL);
	return 0;
}

static int vpsa_kernfs_filter_active_policy_show(struct seq_file *m, void *v)
{
	struct vpsa_kernfs_filter *policy;

	rcu_read_lock();
	policy = rcu_dereference(vpsa_kernfs_filter_active_policy);
	if (policy && policy->canonical_len)
		seq_write(m, policy->canonical, policy->canonical_len);
	rcu_read_unlock();

	return 0;
}

static int vpsa_kernfs_filter_stats_show(struct seq_file *m, void *v)
{
	struct vpsa_kernfs_filter *policy;
	u64 replace_successes;
	u64 replace_failures;
	int last_errno;
	unsigned int last_error_line;
	char last_error[VPSA_KERNFS_FILTER_ERRMSG_LEN];

	mutex_lock(&vpsa_kernfs_filter_lock);
	replace_successes = vpsa_kernfs_filter_replace_successes;
	replace_failures = vpsa_kernfs_filter_replace_failures;
	last_errno = vpsa_kernfs_filter_last_errno;
	last_error_line = vpsa_kernfs_filter_last_error_line;
	strscpy(last_error, vpsa_kernfs_filter_last_error, sizeof(last_error));
	mutex_unlock(&vpsa_kernfs_filter_lock);

	rcu_read_lock();
	policy = rcu_dereference(vpsa_kernfs_filter_active_policy);
	if (!policy) {
		seq_puts(m, "generation 0\nactive 0\n");
		rcu_read_unlock();
		return 0;
	}

	seq_printf(m, "generation %llu\n", policy->generation);
	seq_puts(m, "scope noninit-userns\n");
	seq_printf(m, "rules %u\n", policy->rule_count);
	seq_printf(m, "proc_rules %u\n", policy->proc_rule_count);
	seq_printf(m, "sysfs_rules %u\n", policy->sysfs_rule_count);
	seq_printf(m, "hide_rules %u\n", policy->hide_rule_count);
	seq_printf(m, "deny_rules %u\n", policy->deny_rule_count);
	seq_printf(m, "allow_rules %u\n", policy->allow_rule_count);
	seq_printf(m, "literal_rules %u\n", policy->literal_rule_count);
	seq_printf(m, "wildcard_rules %u\n", policy->wildcard_rule_count);
	seq_printf(m, "max_depth %u\n", policy->max_depth);
	seq_printf(m, "canonical_bytes %zu\n", policy->canonical_len);
	rcu_read_unlock();

	seq_printf(m, "replace_successes %llu\n", replace_successes);
	seq_printf(m, "replace_failures %llu\n", replace_failures);
	seq_printf(m, "last_errno %d\n", last_errno);
	seq_printf(m, "last_error_line %u\n", last_error_line);
	seq_printf(m, "last_error %s\n", last_error);
	return 0;
}

static int vpsa_kernfs_filter_replace_open(struct inode *inode, struct file *file)
{
	struct vpsa_kernfs_filter_replace_state *state;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	file->private_data = state;
	return nonseekable_open(inode, file);
}

static ssize_t vpsa_kernfs_filter_replace_write(struct file *file,
				       const char __user *ubuf,
				       size_t count,
				       loff_t *ppos)
{
	struct vpsa_kernfs_filter_replace_state *state = file->private_data;
	size_t need;
	size_t new_cap;
	char *new_buf;

	if (!state)
		return -EINVAL;
	if (state->err)
		return state->err;
	if (!count)
		return 0;
	if (*ppos != state->len)
		return -EINVAL;
	if (check_add_overflow(state->len, count + 1, &need))
		return -EOVERFLOW;
	if (need > VPSA_KERNFS_FILTER_POLICY_MAX_BYTES + 1)
		return -E2BIG;

	new_cap = state->cap ? state->cap : 4096;
	while (new_cap < need)
		new_cap <<= 1;

	new_buf = krealloc(state->buf, new_cap, GFP_KERNEL);
	if (!new_buf)
		return -ENOMEM;

	state->buf = new_buf;
	state->cap = new_cap;
	if (copy_from_user(state->buf + state->len, ubuf, count))
		return -EFAULT;

	state->len += count;
	state->buf[state->len] = '\0';
	state->wrote_any = true;
	*ppos = state->len;
	return count;
}

static int vpsa_kernfs_filter_replace_release(struct inode *inode, struct file *file)
{
	struct vpsa_kernfs_filter_replace_state *state = file->private_data;
	int ret = 0;

	if (!state)
		return 0;

	if (state->wrote_any)
		ret = vpsa_kernfs_filter_replace_policy_text(state->buf, state->len);

	kfree(state->buf);
	kfree(state);
	file->private_data = NULL;
	return ret;
}

static const struct proc_ops vpsa_kernfs_filter_replace_proc_ops = {
	.proc_open	= vpsa_kernfs_filter_replace_open,
	.proc_write	= vpsa_kernfs_filter_replace_write,
	.proc_lseek	= noop_llseek,
	.proc_release	= vpsa_kernfs_filter_replace_release,
};

static int __init vpsa_kernfs_filter_proc_init(void)
{
	struct vpsa_kernfs_filter *initial_policy = NULL;
	struct proc_dir_entry *root;
	struct proc_dir_entry *dir;
	struct vpsa_kernfs_filter_parse_error perr = {};
	int ret;

	ret = vpsa_kernfs_filter_parse(&initial_policy,
				    VPSA_KERNFS_FILTER_DEFAULT_POLICY,
				    strlen(VPSA_KERNFS_FILTER_DEFAULT_POLICY),
				    &perr);
	if (ret) {
		pr_err("vpsAdminOS: failed to build default kernfs-filter policy: %s\n",
		       perr.msg[0] ? perr.msg : "unknown error");
		return ret;
	}

	ret = vpsa_kernfs_filter_install_policy(initial_policy);
	if (ret) {
		vpsa_kernfs_filter_destroy(initial_policy);
		return ret;
	}

	root = proc_vpsadminos;
	if (!root) {
		pr_err("vpsadminos: kernfs_filter missing /proc/vpsadminos parent\n");
		return -ENOENT;
	}

	dir = proc_mkdir_mode("kernfs_filter", 0500, root);
	if (!dir)
		return -ENOMEM;

	if (!proc_create_single("active", 0400, dir,
				vpsa_kernfs_filter_active_policy_show))
		return -ENOMEM;
	if (!proc_create_single("stats", 0400, dir, vpsa_kernfs_filter_stats_show))
		return -ENOMEM;
	if (!proc_create("replace", 0200, dir, &vpsa_kernfs_filter_replace_proc_ops))
		return -ENOMEM;

	pr_info("vpsAdminOS: /proc/vpsadminos/kernfs_filter control plane ready\n");
	return 0;
}
late_initcall(vpsa_kernfs_filter_proc_init);
