#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <asm/page.h>

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
