/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPSADMINOS_H
#define _LINUX_VPSADMINOS_H

#include <linux/stddef.h>
#include <linux/types.h>

struct mem_cgroup;
struct user_namespace;

struct vpsadminos_memcg_view {
	struct mem_cgroup *memory;
	struct mem_cgroup *swap;
};

static inline unsigned long
vpsadminos_saturating_sub(unsigned long minuend, unsigned long subtrahend)
{
	return minuend > subtrahend ? minuend - subtrahend : 0;
}

static inline unsigned long
vpsadminos_saturating_add(unsigned long addend1, unsigned long addend2)
{
	return addend1 > ~0UL - addend2 ? ~0UL : addend1 + addend2;
}

#ifdef CONFIG_MEMCG
bool vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view);
void vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view);
unsigned long vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg);
unsigned long vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg);
struct mem_cgroup *get_current_most_limited_memcg(void);
#else
static inline bool
vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view)
{
	view->memory = NULL;
	view->swap = NULL;
	return false;
}

static inline void
vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view)
{
	view->memory = NULL;
	view->swap = NULL;
}

static inline unsigned long
vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg)
{
	return 0;
}

static inline unsigned long
vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg)
{
	return 0;
}

static inline struct mem_cgroup *get_current_most_limited_memcg(void)
{
	return NULL;
}
#endif

#endif /* _LINUX_VPSADMINOS_H */
