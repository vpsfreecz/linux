// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/vpsadminos.h>
#include <linux/vmstat.h>

#include <asm/page.h>

#ifdef CONFIG_MEMCG
unsigned long vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg)
{
	unsigned long memory_max;
	unsigned long memsw_max;

	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return READ_ONCE(memcg->swap.max);

	memsw_max = READ_ONCE(memcg->memsw.max);
	if (memsw_max == PAGE_COUNTER_MAX)
		return PAGE_COUNTER_MAX;

	memory_max = READ_ONCE(memcg->memory.max);
	return vpsadminos_saturating_sub(memsw_max, memory_max);
}

unsigned long vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg)
{
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return page_counter_read(&memcg->swap);

	return vpsadminos_saturating_sub(page_counter_read(&memcg->memsw),
					 page_counter_read(&memcg->memory));
}

bool vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memory_memcg = NULL;
	struct mem_cgroup *swap_memcg = NULL;
	struct mem_cgroup *walk_memcg;
	unsigned long memory_limit = PAGE_COUNTER_MAX;
	unsigned long swap_limit = PAGE_COUNTER_MAX;

	memset(view, 0, sizeof(*view));
	if (mem_cgroup_disabled())
		return false;

	rcu_read_lock();
	while (true) {
		css = task_css(current, memory_cgrp_id);
		if (!css) {
			rcu_read_unlock();
			return false;
		}

		if (likely(css_tryget(css)))
			break;
		cpu_relax();
	}
	rcu_read_unlock();

	walk_memcg = mem_cgroup_from_css(css);

	while ((walk_memcg != root_mem_cgroup) && walk_memcg) {
		unsigned long max = READ_ONCE(walk_memcg->memory.max);
		unsigned long swap_max = vpsadminos_memcg_swap_limit(walk_memcg);

		if (max < memory_limit) {
			memory_limit = max;
			memory_memcg = walk_memcg;
		}
		if (swap_max < swap_limit) {
			swap_limit = swap_max;
			swap_memcg = walk_memcg;
		}
		walk_memcg = parent_mem_cgroup(walk_memcg);
	}

	if (!memory_memcg) {
		css_put(css);
		return false;
	}

	/*
	 * An unlimited swap hierarchy still needs an ownership domain for usage
	 * accounting. The memory owner is the least surprising fallback and
	 * preserves the historical finite-memory/unlimited-swap view.
	 */
	if (!swap_memcg)
		swap_memcg = memory_memcg;

	css_get(&memory_memcg->css);
	css_get(&swap_memcg->css);
	css_put(css);

	view->memory = memory_memcg;
	view->swap = swap_memcg;
	return true;
}

void vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view)
{
	if (view->memory)
		mem_cgroup_put(view->memory);
	if (view->swap)
		mem_cgroup_put(view->swap);
	memset(view, 0, sizeof(*view));
}

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct vpsadminos_memcg_view view;

	if (!vpsadminos_get_current_memcg_view(&view))
		return NULL;

	mem_cgroup_put(view.swap);
	return view.memory;
}
#endif
