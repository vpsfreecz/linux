/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CGROUP_NAMESPACE_H
#define _LINUX_CGROUP_NAMESPACE_H

#include <linux/atomic.h>
#include <linux/auth_guard_types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/ns_common.h>

struct cgroup;

struct cgroup_namespace {
	struct ns_common	ns;
	struct cgroup_namespace	*parent;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct css_set          *root_cset;
#ifdef CONFIG_AUTH_GUARD
	struct auth_guard_stamp	auth_guard_root_stamp;
#endif

	bool			loadavg_virt_enabled;
	struct list_head	cgns_avenrun_list;
	unsigned long		nr_threads;
	struct mutex		cgns_avenrun_lock;
	atomic_t		nr_uninterruptible;
	unsigned long		avenrun[3];
};

extern struct cgroup_namespace init_cgroup_ns;

#ifdef CONFIG_CGROUPS

static inline struct cgroup_namespace *to_cg_ns(struct ns_common *ns)
{
	return container_of(ns, struct cgroup_namespace, ns);
}

void free_cgroup_ns(struct cgroup_namespace *ns);

struct cgroup_namespace *copy_cgroup_ns(u64 flags,
					struct user_namespace *user_ns,
					struct cgroup_namespace *old_ns);
int cgroup_ns_publish(struct cgroup_namespace *ns);
void cgroup_ns_activate_loadavg(struct cgroup_namespace *ns);
void put_cgroup_ns_maybe_unpublished(struct cgroup_namespace *ns);

int cgroup_path_ns(struct cgroup *cgrp, char *buf, size_t buflen,
		   struct cgroup_namespace *ns);

static inline void get_cgroup_ns(struct cgroup_namespace *ns)
{
	ns_ref_inc(ns);
}

static inline void put_cgroup_ns(struct cgroup_namespace *ns)
{
	if (ns_ref_put(ns))
		free_cgroup_ns(ns);
}

#else /* !CONFIG_CGROUPS */

static inline void free_cgroup_ns(struct cgroup_namespace *ns) { }
static inline struct cgroup_namespace *
copy_cgroup_ns(u64 flags, struct user_namespace *user_ns,
	       struct cgroup_namespace *old_ns)
{
	return old_ns;
}

static inline int cgroup_ns_publish(struct cgroup_namespace *ns)
{
	return 0;
}

static inline void cgroup_ns_activate_loadavg(struct cgroup_namespace *ns)
{
}

static inline void
put_cgroup_ns_maybe_unpublished(struct cgroup_namespace *ns)
{
}

static inline void get_cgroup_ns(struct cgroup_namespace *ns) { }
static inline void put_cgroup_ns(struct cgroup_namespace *ns) { }

#endif /* !CONFIG_CGROUPS */

#endif /* _LINUX_CGROUP_NAMESPACE_H */
