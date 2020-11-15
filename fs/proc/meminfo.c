// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
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

#define virtual_zone_page_state(x) (!memcg) ? \
					global_zone_page_state(x) : 0
#define virtual_node_page_state(x) (!memcg) ? \
					global_node_page_state(x) : \
					memcg_page_state(memcg, x)
static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	int lru;
	struct mem_cgroup *memcg;
	unsigned long totalram;

	si_meminfo(&i);
	si_swapinfo(&i);

	memcg = get_current_most_limited_memcg();
	if (memcg) {
		unsigned long memsw = PAGE_COUNTER_MAX;
		unsigned long memsw_usage = 0;
		unsigned long memusage = page_counter_read(&memcg->memory);

		totalram = (u64)READ_ONCE(memcg->memory.max);

		if (!cgroup_memory_noswap) {
			memsw = READ_ONCE(memcg->memsw.max);
			memsw_usage = page_counter_read(&memcg->memsw);
		}

		i.totalram = i.totalhigh = totalram;
		i.freeram = i.freehigh = totalram - memusage;
		if (memsw < PAGE_COUNTER_MAX) {
			i.totalswap = memsw - totalram;
			i.freeswap = i.totalswap - (memsw_usage - memusage);
		} else {
			i.totalswap = 0;
			i.freeswap = 0;
		}

		for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
			pages[lru] = memcg_page_state(memcg, NR_LRU_BASE + lru);

		if (memcg_kmem_enabled()) {
			sreclaimable = memcg_page_state(memcg, NR_SLAB_RECLAIMABLE_B);
			sunreclaim = memcg_page_state(memcg, NR_SLAB_UNRECLAIMABLE_B);
		} else {
			sreclaimable = 0;
			sunreclaim = 0;
		}
		cached = memcg_page_state(memcg, NR_FILE_PAGES);
		available = i.freeram + sreclaimable;
		committed = 0;
		i.bufferram = sreclaimable;
		i.sharedram = memcg_page_state(memcg, NR_SHMEM);
	} else {
		for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
			pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

		cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
		if (cached < 0)
			cached = 0;
		available = si_mem_available();
		sreclaimable = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
		sunreclaim = global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);
		committed = vm_memory_committed();
	}


	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", virtual_zone_page_state(NR_MLOCK));

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
	show_val_kb(m, "Dirty:          ",
		    virtual_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    virtual_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    virtual_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    virtual_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "KReclaimable:   ", sreclaimable +
		    virtual_node_page_state(NR_KERNEL_MISC_RECLAIMABLE));
	show_val_kb(m, "Slab:           ", sreclaimable + sunreclaim);
	show_val_kb(m, "SReclaimable:   ", sreclaimable);
	show_val_kb(m, "SUnreclaim:     ", sunreclaim);

	seq_printf(m, "KernelStack:    %8lu kB\n",
		   virtual_node_page_state(NR_KERNEL_STACK_KB));
#ifdef CONFIG_SHADOW_CALL_STACK
	seq_printf(m, "ShadowCallStack:%8lu kB\n",
		   virtual_node_page_state(NR_KERNEL_SCS_KB));
#endif
	show_val_kb(m, "PageTables:     ",
		    virtual_node_page_state(NR_PAGETABLE));

	show_val_kb(m, "NFS_Unstable:   ", 0);
	show_val_kb(m, "Bounce:         ",
		    virtual_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    virtual_node_page_state(NR_WRITEBACK_TEMP));

	if (!memcg) {
		show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
		show_val_kb(m, "Committed_AS:   ", committed);
		seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
		show_val_kb(m, "VmallocUsed:    ", vmalloc_nr_pages());
		show_val_kb(m, "VmallocChunk:   ", 0ul);
		show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

#ifdef CONFIG_MEMORY_FAILURE
		seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif
	}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    virtual_node_page_state(NR_ANON_THPS));
	show_val_kb(m, "ShmemHugePages: ",
		    virtual_node_page_state(NR_SHMEM_THPS));
	show_val_kb(m, "ShmemPmdMapped: ",
		    virtual_node_page_state(NR_SHMEM_PMDMAPPED));
	show_val_kb(m, "FileHugePages:  ",
		    virtual_node_page_state(NR_FILE_THPS));
	show_val_kb(m, "FilePmdMapped:  ",
		    virtual_node_page_state(NR_FILE_PMDMAPPED));
#endif

	if (!memcg) {
#ifdef CONFIG_CMA
		show_val_kb(m, "CmaTotal:       ", totalcma_pages);
		show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

		hugetlb_report_meminfo(m);

		arch_report_meminfo(m);
	}

	if (memcg)
		mem_cgroup_put(memcg);
	return 0;
}

static int __init proc_meminfo_init(void)
{
	proc_create_single("meminfo", 0, NULL, meminfo_proc_show);
	return 0;
}
fs_initcall(proc_meminfo_init);
