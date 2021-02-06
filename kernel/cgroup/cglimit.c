/*
 * cgroup creation limiting controller for cgroups.
 *
 * Since it is trivial to hit the memcg ID MAX - and while it less trivial
 * to hit the CSS ID too it still possible for longer running systems.
 * Thus cglimit controller is here to help prevent bad actors on a shared
 * machine to exhaust shared ID ranges for cgroups in general and memory
 * cgroups in specific too.
 * There is a 2G limit for max amount of cgroups on a running system and
 * 65k limit for memory cgroups, unless MEMCG_32BIT_IDS patch is appied too -
 * which has its own repercussions.
 *
 *
 * In order to use the `cglimit` controller to set the maximum number of 
 * cgroup IDs in cglimit.all.max (this is not available in the root cgroup).
 *
 * Maximum amount of memory cgroup instances under a cglimit cgroup can be set
 * in cglimit.memory.max.
 *
 * To set a cgroup to have no limit, set cglimit.{all,memory}.max to "max".
 * This is the default for all new cgroups (N.B. that cglimit is hierarchical,
 * so the most stringent limit in the hierarchy is followed).
 *
 * Currently held amount of cgroups or memcgs is visible in
 *   cglimit.{all,memory}.current files.
 *
 * Please note, that each memory cgroup also accounts for one cgroup out of
 * cglimit.all.max limit, thus cglimit.all.max should be equal or higher than
 * cglimit.memory.max.
 *
 * cglimit.{all,memory}.current also track all child cgroup hierarchies, so 
 * parent/cglimit.{all,memory}.current is a superset of
 * parent/child/cglimit.{all,memory}.current.
 *
 * Copyright (C) 2018 Pavel Snajdr <snajpa@snajpa.net>
 *
 * Based on kernel/cgroups/pids.c:
 * Copyright (C) 2015 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This file is subject to the terms and conditions of version 2 of the GNU
 * General Public License.  See the file COPYING in the main directory of the
 * Linux distribution for more details.
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/memcontrol.h>
#include <linux/cgroup_cglimit.h>

#define CGLIMIT_MAX_STR		"max"
#define CGLIMIT_CG_MAX		INT_MAX
#define CGLIMIT_MEMCG_MAX	MEM_CGROUP_ID_MAX

struct cgroup_subsys cglimit_cgrp_subsys __read_mostly;
EXPORT_SYMBOL(cglimit_cgrp_subsys);

static struct cglimit_cgroup *css_cglimit(struct cgroup_subsys_state *css)
{
	return container_of(css, struct cglimit_cgroup, css);
}

static struct cglimit_cgroup *parent_cglimit(struct cglimit_cgroup *cglimit)
{
	return css_cglimit(cglimit->css.parent);
}

static struct cgroup_subsys_state *
cglimit_css_alloc(struct cgroup_subsys_state *parent)
{
	struct cglimit_cgroup *cglimit;

	cglimit = kzalloc(sizeof(struct cglimit_cgroup), GFP_KERNEL);
	if (!cglimit)
		return ERR_PTR(-ENOMEM);

	cglimit->cg_limit = CGLIMIT_CG_MAX;
	cglimit->memcg_limit = CGLIMIT_MEMCG_MAX;
	atomic64_set(&cglimit->cg_counter, 0);
	atomic64_set(&cglimit->memcg_counter, 0);
	atomic64_set(&cglimit->events_cg_limit, 0);
	atomic64_set(&cglimit->events_memcg_limit, 0);
	return &cglimit->css;
}

static void cglimit_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_cglimit(css));
}

/**
 * cglimit_cancel - uncharge the local css_id count
 * @cglimit: the css_id cgroup state
 * @num: the number of cglimit to cancel
 *
 * This function will WARN if any counter goes under 0, because such a case is
 * a bug in the cglimit controller proper.
 */
static void cglimit_cancel(struct cglimit_cgroup *cglimit, int num,
				enum cglimit_type t)
{
	bool neg = false;

	switch (t) {
	case CGLIMIT_CG:
		neg = atomic64_add_negative(-num, &cglimit->cg_counter);
		break;
	case CGLIMIT_MEMCG:
		neg = atomic64_add_negative(-num, &cglimit->memcg_counter);
		break;
	default:
		BUG();
	}

	/*
	 * A negative count (or overflow for that matter) is invalid,
	 * and indicates a bug in the `cglimit` controller proper.
	 */
	WARN_ON_ONCE(neg);
}

/**
 * cglimit_uncharge - hierarchically uncharge the css_id count
 * @cglimit: the css_id cgroup state
 * @num: the number of cglimit to uncharge
 */
extern void cglimit_uncharge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t)
{
	struct cglimit_cgroup *p, *cglimit;

	cglimit = css_cglimit(css);

	if (!cglimit)
		return;

	for (p = cglimit; parent_cglimit(p); p = parent_cglimit(p)) {
		cglimit_cancel(p, num, t);
	}
}

/**
 * cglimit_charge - hierarchically charge the css_id count
 * @cglimit: the css_id cgroup state
 * @num: the number of cglimit to charge
 *
 * This function does *not* follow the limits set. It cannot fail and the new
 * css_id count may exceed the limit.
 * */
extern int64_t cglimit_charge(struct cglimit_cgroup *cglimit, int num,
				enum cglimit_type t)
{
	struct cglimit_cgroup *p;
	int64_t ret = 0, retmp = 0;

	switch (t) {
	case CGLIMIT_CG:
		for (p = cglimit; parent_cglimit(p); p = parent_cglimit(p)) {
			retmp = atomic64_add_return(num, &p->cg_counter);
			if (retmp > ret)
				ret = retmp;
		}
		break;
	case CGLIMIT_MEMCG:
		for (p = cglimit; parent_cglimit(p); p = parent_cglimit(p)) {
			retmp = atomic64_add_return(num, &p->memcg_counter);
			if (retmp > ret)
				ret = retmp;
		}
		break;
	default:
		BUG();
		ret = -EINVAL;
	}

	return ret;
}

/**
 * cglimit_try_charge - hierarchically try to charge the css_id count
 * @cglimit: the css_id cgroup state
 * @num: the number of cglimit to charge
 *
 * This function follows the set limit. It will fail if the charge would cause
 * the new value to exceed the hierarchical limit. Returns true if the charge
 * succeeded, false otherwise.
 */
extern bool cglimit_try_charge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t)
{
	struct cglimit_cgroup *p, *q, *cglimit;
	int64_t new, limit;

	cglimit = css_cglimit(css);

	for (p = cglimit; parent_cglimit(p); p = parent_cglimit(p)) {
		switch (t) {
		case CGLIMIT_CG:
			new = atomic64_add_return(num, &p->cg_counter);
			limit = p->cg_limit;
			break;
		case CGLIMIT_MEMCG:
			new = atomic64_add_return(num, &p->memcg_counter);
			limit = p->memcg_limit;
			break;
		default:
			BUG();
		}

		if (new > limit)
			goto revert;
	}

	return true;

revert:
	for (q = cglimit; q != p; q = parent_cglimit(q))
		cglimit_cancel(q, num, t);
	cglimit_cancel(p, num, t);

	return false;
}

static ssize_t _cglimit_max_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off, enum cglimit_type t)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct cglimit_cgroup *cglimit = css_cglimit(css);
	int64_t *limitptr;
	int64_t limit, max;
	int err;

	switch (t) {
	case CGLIMIT_CG:
		max = CGLIMIT_CG_MAX;
		limitptr = &cglimit->cg_limit;
		break;
	case CGLIMIT_MEMCG:
		max = CGLIMIT_MEMCG_MAX;
		limitptr = &cglimit->memcg_limit;
		break;
	default:
		BUG();
	}

	buf = strstrip(buf);
	if (!strcmp(buf, CGLIMIT_MAX_STR)) {
		limit = max;
		goto set_limit;
	}

	err = kstrtoll(buf, 0, &limit);
	if (err)
		return err;

	if (limit < 0 || limit >= max)
		return -EINVAL;

set_limit:
	/*
	 * Limit updates don't need to be mutex'd, since it isn't
	 * critical that any racing fork()s follow the new limit.
	 */
	*limitptr = limit;
	return nbytes;
}

static ssize_t cglimit_cg_max_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off) {
	return _cglimit_max_write(of, buf, nbytes, off, CGLIMIT_CG);
}

static ssize_t cglimit_memcg_max_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off) {
	return _cglimit_max_write(of, buf, nbytes, off, CGLIMIT_MEMCG);
}

static int _cglimit_max_show(struct seq_file *sf, void *v, enum cglimit_type t)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct cglimit_cgroup *cglimit = css_cglimit(css);
	int64_t limit, max;

	switch (t) {
	case CGLIMIT_CG:
		max = CGLIMIT_CG_MAX;
		limit = cglimit->cg_limit;
		break;
	case CGLIMIT_MEMCG:
		max = CGLIMIT_MEMCG_MAX;
		limit = cglimit->memcg_limit;
		break;
	default:
		BUG();
	}

	if (limit >= max)
		seq_printf(sf, "%s\n", CGLIMIT_MAX_STR);
	else
		seq_printf(sf, "%lld\n", limit);

	return 0;
}

static int cglimit_cg_max_show(struct seq_file *sf, void *v) {
	return _cglimit_max_show(sf, v, CGLIMIT_CG);
}

static int cglimit_memcg_max_show(struct seq_file *sf, void *v) {
	return _cglimit_max_show(sf, v, CGLIMIT_MEMCG);
}

static s64 _cglimit_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft, enum cglimit_type t)
{
	struct cglimit_cgroup *cglimit = css_cglimit(css);
	atomic64_t *counter;

	switch (t) {
	case CGLIMIT_CG:
		counter = &cglimit->cg_counter;
		break;
	case CGLIMIT_MEMCG:
		counter = &cglimit->memcg_counter;
		break;
	default:
		BUG();
	}

	return atomic64_read(counter);
}

static s64 cglimit_cg_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft) {
	return _cglimit_current_read(css, cft, CGLIMIT_CG);
}

static s64 cglimit_memcg_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft) {
	return _cglimit_current_read(css, cft, CGLIMIT_MEMCG);
}

static int _cglimit_events_show(struct seq_file *sf, void *v,
					enum cglimit_type t)
{
	struct cglimit_cgroup *cglimit = css_cglimit(seq_css(sf));
	int64_t limit;

	switch (t) {
	case CGLIMIT_CG:
		limit = atomic64_read(&cglimit->events_cg_limit);
		break;
	case CGLIMIT_MEMCG:
		limit = atomic64_read(&cglimit->events_memcg_limit);
		break;
	default:
		BUG();
	}

	seq_printf(sf, "max %lld\n", (s64)limit);
	return 0;
}

static int cglimit_cg_events_show(struct seq_file *sf, void *v) {
	return _cglimit_events_show(sf, v, CGLIMIT_CG);
}

static int cglimit_memcg_events_show(struct seq_file *sf, void *v) {
	return _cglimit_events_show(sf, v, CGLIMIT_MEMCG);
}

static struct cftype cglimit_files[] = {
	{
		.name = "all.max",
		.write = cglimit_cg_max_write,
		.seq_show = cglimit_cg_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "all.current",
		.read_s64 = cglimit_cg_current_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "all.events",
		.seq_show = cglimit_cg_events_show,
		.file_offset = offsetof(struct cglimit_cgroup, events_cg_file),
		.flags = CFTYPE_NOT_ON_ROOT,
	},
#ifdef CONFIG_MEMCG
	{
		.name = "memory.max",
		.write = cglimit_memcg_max_write,
		.seq_show = cglimit_memcg_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "memory.current",
		.read_s64 = cglimit_memcg_current_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "memory.events",
		.seq_show = cglimit_memcg_events_show,
		.file_offset = offsetof(struct cglimit_cgroup, events_memcg_file),
		.flags = CFTYPE_NOT_ON_ROOT,
	},
#endif /* CONFIG_MEMCG */
	{ }	/* terminate */
};

struct cgroup_subsys cglimit_cgrp_subsys = {
	.css_alloc	= cglimit_css_alloc,
	.css_free	= cglimit_css_free,
	.legacy_cftypes	= cglimit_files,
	.dfl_cftypes	= cglimit_files,
	.threaded	= true,
};

