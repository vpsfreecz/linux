/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CGROUP_CGLIMIT_H
#define _CGROUP_CGLIMIT_H

#include <linux/cgroup.h>

struct cglimit_cgroup {
        struct cgroup_subsys_state      css;

        /*
         * Use 64-bit types so that we can safely represent "max"
         */
        atomic64_t                      cg_counter, memcg_counter;
        int64_t                         cg_limit, memcg_limit;

        /* Handle for "cglimit.events" */
        struct cgroup_file              events_cg_file;
        struct cgroup_file              events_memcg_file;

        /* Number of times cssid failed because limit was hit. */
        atomic64_t                      events_cg_limit;
        atomic64_t                      events_memcg_limit;
};

enum cglimit_type {
	CGLIMIT_CG,
	CGLIMIT_MEMCG,
};

#ifdef CONFIG_CGROUP_CGLIMIT

extern bool cglimit_try_charge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t);
extern void cglimit_uncharge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t);

#else /* CONFIG_CGROUP_CGLIMIT */

static bool cglimit_try_charge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t)
{ return true; }
static void cglimit_uncharge(struct cgroup_subsys_state *css, int num,
				enum cglimit_type t)
{ return; }
#endif /* CONFIG_CGROUP_CGLIMIT */

#endif /* _CGROUP_CGLIMIT_H */
