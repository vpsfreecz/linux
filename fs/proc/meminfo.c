// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/memblock.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#include <linux/vpsadminos.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <linux/zswap.h>
#include <asm/page.h>
#include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

static inline unsigned long
vps_memcg_node_page_state(struct mem_cgroup *memcg, int idx)
{
	if (!memcg)
		return global_node_page_state(idx);

	return memcg_page_state_nowarn(memcg, idx);
}

static inline unsigned long
vps_memcg_zone_page_state(struct mem_cgroup *memcg, int idx)
{
	if (!memcg)
		return global_zone_page_state(idx);

	return 0;
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached, cached_inactive;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	struct mem_cgroup *memcg;
	unsigned long memusage, totalram, swapmax, swapusage, proactive_swap;
	unsigned long normal_swap_usage = 0, swapcache = 0;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);

	memcg = get_current_most_limited_memcg();
	if (memcg) {
		memusage = page_counter_read(&memcg->memory);
		totalram = READ_ONCE(memcg->memory.max);

		for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
			pages[lru] = memcg_page_state(memcg, NR_LRU_BASE + lru);

#ifdef CONFIG_SWAP
		swapcache = memcg_page_state_nowarn(memcg, NR_SWAPCACHE);
#endif
		cached = memcg_page_state(memcg, NR_FILE_PAGES) - swapcache;
		if (cached < 0)
			cached = 0;
		cached_inactive = pages[LRU_INACTIVE_FILE];

		if (mem_cgroup_kmem_disabled()) {
			sreclaimable = 0;
			sunreclaim = 0;
		} else {
			sreclaimable = memcg_page_state(memcg, NR_SLAB_RECLAIMABLE_B) / PAGE_SIZE;
			sunreclaim = memcg_page_state(memcg, NR_SLAB_UNRECLAIMABLE_B) / PAGE_SIZE;
		}

		i.totalram = totalram;
		i.totalhigh = totalram;
		i.freeram = totalram - memusage;
		i.freehigh = totalram - memusage;
		i.bufferram = 0;
		i.sharedram = memcg_page_state(memcg, NR_SHMEM);

		proactive_swap = mem_cgroup_proactive_swap_usage(memcg);

		if (!cgroup_subsys_on_dfl(memory_cgrp_subsys)) {
			swapmax = READ_ONCE(memcg->memsw.max);
			swapusage = page_counter_read(&memcg->memsw);

			if (!swapmax || swapmax == totalram) {
				i.totalswap = 0;
				i.freeswap = 0;
			} else {
				if (swapmax != PAGE_COUNTER_MAX)
					i.totalswap = swapmax - totalram;

				normal_swap_usage = swapusage > memusage + proactive_swap ?
					(swapusage - memusage - proactive_swap) : 0;
				i.freeswap = i.totalswap > normal_swap_usage ?
					(i.totalswap - normal_swap_usage) : 0;
			}
		} else {
			swapmax = READ_ONCE(memcg->swap.max);
			swapusage = page_counter_read(&memcg->swap);

			if (!swapmax) {
				i.totalswap = 0;
				i.freeswap = 0;
			} else {
				if (swapmax != PAGE_COUNTER_MAX)
					i.totalswap = swapmax;

				normal_swap_usage = swapusage > proactive_swap ?
					(swapusage - proactive_swap) : 0;
				i.freeswap = i.totalswap > normal_swap_usage ?
					(i.totalswap - normal_swap_usage) : 0;
			}
		}

		i.totalswap += proactive_swap;

		available = i.freeram + sreclaimable + cached_inactive;
		committed = 0;
	} else {
		committed = vm_memory_committed();

		cached = global_node_page_state(NR_FILE_PAGES) -
				total_swapcache_pages() - i.bufferram;
		if (cached < 0)
			cached = 0;

		for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
			pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

		available = si_mem_available();
		sreclaimable = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
		sunreclaim = global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);
	}

	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", memcg ? swapcache : total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", vps_memcg_zone_page_state(memcg, NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
#ifdef CONFIG_ZSWAP
	show_val_kb(m, "Zswap:          ",
		    memcg ? memcg_page_state(memcg, MEMCG_ZSWAP_B) / PAGE_SIZE :
			    zswap_total_pages());
	seq_printf(m,  "Zswapped:       %8lu kB\n",
		   (memcg ? memcg_page_state(memcg, MEMCG_ZSWAPPED) :
			    (unsigned long)atomic_long_read(&zswap_stored_pages)) <<
		   (PAGE_SHIFT - 10));
#endif
	show_val_kb(m, "Dirty:          ",
		    vps_memcg_node_page_state(memcg, NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    vps_memcg_node_page_state(memcg, NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    vps_memcg_node_page_state(memcg, NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    vps_memcg_node_page_state(memcg, NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "KReclaimable:   ", sreclaimable +
		    vps_memcg_node_page_state(memcg, NR_KERNEL_MISC_RECLAIMABLE));
	show_val_kb(m, "Slab:           ", sreclaimable + sunreclaim);
	show_val_kb(m, "SReclaimable:   ", sreclaimable);
	show_val_kb(m, "SUnreclaim:     ", sunreclaim);
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   vps_memcg_node_page_state(memcg, NR_KERNEL_STACK_KB));
#ifdef CONFIG_SHADOW_CALL_STACK
	seq_printf(m, "ShadowCallStack:%8lu kB\n",
		   vps_memcg_node_page_state(memcg, NR_KERNEL_SCS_KB));
#endif
	show_val_kb(m, "PageTables:     ",
		    vps_memcg_node_page_state(memcg, NR_PAGETABLE));
	show_val_kb(m, "SecPageTables:  ",
		    vps_memcg_node_page_state(memcg, NR_SECONDARY_PAGETABLE));

	show_val_kb(m, "NFS_Unstable:   ", 0);
	show_val_kb(m, "Bounce:         ", 0);
	show_val_kb(m, "WritebackTmp:   ", 0);

	if (!memcg) {
		show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
		show_val_kb(m, "Committed_AS:   ", committed);
		seq_printf(m, "VmallocTotal:   %8lu kB\n",
			   (unsigned long)VMALLOC_TOTAL >> 10);
		show_val_kb(m, "VmallocUsed:    ", vmalloc_nr_pages());
		show_val_kb(m, "VmallocChunk:   ", 0ul);
		show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

		memtest_report_meminfo(m);

#ifdef CONFIG_MEMORY_FAILURE
		seq_printf(m, "HardwareCorrupted: %5lu kB\n",
			   atomic_long_read(&num_poisoned_pages) <<
			   (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_CMA
		show_val_kb(m, "CmaTotal:       ", totalcma_pages);
		show_val_kb(m, "CmaFree:        ",
			    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

#ifdef CONFIG_UNACCEPTED_MEMORY
		show_val_kb(m, "Unaccepted:     ",
			    global_zone_page_state(NR_UNACCEPTED));
#endif
	} else {
#ifdef CONFIG_MEMORY_FAILURE
		seq_printf(m, "HardwareCorrupted: %5u kB\n", 0U);
#endif
#ifdef CONFIG_CMA
		show_val_kb(m, "CmaTotal:       ", 0);
		show_val_kb(m, "CmaFree:        ", 0);
#endif
#ifdef CONFIG_UNACCEPTED_MEMORY
		show_val_kb(m, "Unaccepted:     ", 0);
#endif
	}

	show_val_kb(m, "Balloon:        ",
		    vps_memcg_node_page_state(memcg, NR_BALLOON_PAGES));

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    vps_memcg_node_page_state(memcg, NR_ANON_THPS));
	show_val_kb(m, "ShmemHugePages: ",
		    vps_memcg_node_page_state(memcg, NR_SHMEM_THPS));
	show_val_kb(m, "ShmemPmdMapped: ",
		    vps_memcg_node_page_state(memcg, NR_SHMEM_PMDMAPPED));
	show_val_kb(m, "FileHugePages:  ",
		    vps_memcg_node_page_state(memcg, NR_FILE_THPS));
	show_val_kb(m, "FilePmdMapped:  ",
		    vps_memcg_node_page_state(memcg, NR_FILE_PMDMAPPED));
#endif

	if (!memcg) {
		hugetlb_report_meminfo(m);
		arch_report_meminfo(m);
	}

	if (memcg)
		mem_cgroup_put(memcg);

	return 0;
}

static int __init proc_meminfo_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("meminfo", 0, NULL, meminfo_proc_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_meminfo_init);
