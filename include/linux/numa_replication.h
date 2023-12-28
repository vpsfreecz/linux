/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_NUMA_REPLICATION_H
#define _LINUX_NUMA_REPLICATION_H

#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>

#ifdef CONFIG_KERNEL_REPLICATION

#include <asm/numa_replication.h>

extern int closest_memory_node[MAX_NUMNODES];

#define per_numa_pgd(mm, nid) ((mm)->pgd_numa[nid])
#define for_each_replica(nid) for_each_node_state(nid, N_MEMORY)

static inline bool numa_addr_has_replica(const void *addr)
{
	return ((unsigned long)addr >= PAGE_TABLE_REPLICATION_LEFT) &&
		((unsigned long)addr <= PAGE_TABLE_REPLICATION_RIGHT);
}

bool is_text_replicated(void);
void numa_replicate_kernel_rodata(void);
void numa_setup_pgd(void);
void numa_clear_linear_addresses(void);
void __init numa_reserve_memory(void);
void __init numa_replicate_kernel(void);
void __init_or_module *numa_addr_in_replica(void *vaddr, int nid);
void numa_dump_mm_tables(struct mm_struct *mm, unsigned long start, unsigned long end);
static inline int numa_closest_memory_node(int nid)
{
	return closest_memory_node[nid];
}

#else

#define per_numa_pgd(mm, nid) ((mm)->pgd)
#define for_each_replica(nid) for (nid = 0; nid < 1; nid++)

static inline bool numa_addr_has_replica(const void *addr)
{
	return false;
}

static inline bool is_text_replicated(void)
{
	return false;
}

static inline void numa_replicate_kernel_rodata(void)
{
}

static inline void numa_setup_pgd(void)
{
}

static inline void numa_clear_linear_addresses(void)
{
}

static inline void __init numa_reserve_memory(void)
{
}

static inline void __init numa_replicate_kernel(void)
{
}

static inline void __init_or_module *numa_addr_in_replica(void *vaddr, int nid)
{
	return lm_alias(vaddr);
}

static inline void numa_dump_mm_tables(struct mm_struct *mm, unsigned long start, unsigned long end)
{
}


#endif /*CONFIG_KERNEL_REPLICATION*/
#endif /*_LINUX_NUMA_REPLICATION_H*/
