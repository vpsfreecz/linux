/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_NUMA_REPLICATION_H
#define _ASM_X86_NUMA_REPLICATION_H

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable_64_types.h>

/* Replicated region of kernel space */
#define PAGE_TABLE_REPLICATION_LEFT  (0xffffffffffffffff - (SZ_2G - 1))
#define PAGE_TABLE_REPLICATION_RIGHT (0xffffffffffffffff)

static inline pgd_t *numa_replicate_pgt_pgd(int nid)
{
	pgd_t *new_pgd;

	struct page *pgd_page;

	pgd_page = alloc_pages_node(nid, GFP_PGTABLE_KERNEL, PGD_ALLOCATION_ORDER);
	BUG_ON(pgd_page == NULL);

	new_pgd = (pgd_t *)page_address(pgd_page);
	clone_pgd_range(new_pgd + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	return new_pgd;
}

static inline void load_replicated_pgd(pgd_t *pgd)
{
	load_cr3(pgd);
	flush_tlb_local();
}

static inline ssize_t str_cpu_dump(char *buf)
{
	return sprintf(buf, "NODE: #%02d, CPU: #%04d, cr3: 0x%p\n", numa_node_id(),
			smp_processor_id(), (void *)__native_read_cr3());
}

#endif /* _ASM_X86_NUMA_REPLICATION_H */
