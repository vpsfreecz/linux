#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <asm/page.h>

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *walk_memcg, *res_memcg = NULL;
	unsigned long limit = PAGE_COUNTER_MAX;

	if (mem_cgroup_disabled())
		return NULL;

	rcu_read_lock();
	while (true) {
		css = task_css(current, memory_cgrp_id);
		if (!css) {
			rcu_read_unlock();
			return NULL;
		}

		if (likely(css_tryget(css)))
			break;
		cpu_relax();
	}
	rcu_read_unlock();

	walk_memcg = mem_cgroup_from_css(css);

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

	css_get(&res_memcg->css);
	css_put(css);
	return res_memcg;

not_found:
	css_put(css);
	return NULL;
}
