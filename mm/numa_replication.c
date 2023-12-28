// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/pagewalk.h>
#include <linux/numa_replication.h>
#include <linux/memblock.h>
#include <linux/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/kobject.h>

#include <asm/sections.h>
#include <asm/tlbflush.h>

#define KERNEL_TEXT_START	((unsigned long)&_stext)
#define KERNEL_TEXT_END		((unsigned long)&_etext)

#define KERNEL_RODATA_START ((unsigned long)&__start_rodata)
#define KERNEL_RODATA_END ((unsigned long)&__end_rodata)

#define PMD_ALLOC_ORDER		(PMD_SHIFT-PAGE_SHIFT)
#define PAGES_PER_PMD		(1 << PMD_ALLOC_ORDER)

struct numa_node_pgt {
	pgd_t *pgd;
	void *text_vaddr;
	void *rodata_vaddr;
};

static struct numa_node_pgt __initdata_or_module numa_pgt[MAX_NUMNODES];

unsigned int master_node = -1;

int closest_memory_node[MAX_NUMNODES];

struct tt_dump_config {
	int pgd_extra_info:1;
	int p4d_extra_info:1;
	int pud_extra_info:1;
	int pmd_extra_info:1;
	int pte_extra_info:1;
};

static bool text_replicated;

bool is_text_replicated(void)
{
	return text_replicated;
}

static void binary_dump(unsigned long value)
{
	int i;

	for (i = BITS_PER_LONG - 1; i >= 0; i--) {
		if ((BITS_PER_LONG - 1 - i) % BITS_PER_BYTE == 0)
			pr_info("%-9d", i);
	}
	pr_info("%d\n", 0);

	for (i = BITS_PER_LONG - 1; i >= 0; i--) {
		if ((BITS_PER_LONG - 1 - i) % BITS_PER_BYTE == 0)
			pr_info("|");

		pr_info("%d", (1UL << i) & value ? 1 : 0);
	}
	pr_info("|");
}

static int pgd_callback(pgd_t *pgd,
			unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	unsigned long val = pgd_val(*pgd);
	struct tt_dump_config *c = (struct tt_dump_config *)walk->private;

	if (!val)
		return 0;

	addr = addr & PGDIR_MASK;
	next = (addr & PGDIR_MASK) - 1 + PGDIR_SIZE;

	pr_info("PGD ADDR: 0x%p PGD VAL: 0x%016lx [%p --- %p]\n",
		pgd, val, (void *)addr, (void *)next);

	if (c->pgd_extra_info)
		binary_dump(val);

	return 0;
}

static int p4d_callback(p4d_t *p4d,
			unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	unsigned long val = p4d_val(*p4d);
	struct tt_dump_config *c = (struct tt_dump_config *)walk->private;

	if (!val)
		return 0;

	addr = addr & P4D_MASK;
	next = (addr & P4D_MASK) - 1 + P4D_SIZE;

	pr_info("P4D ADDR: 0x%p P4D VAL: 0x%016lx [%p --- %p]\n",
		p4d, val, (void *)addr, (void *)next);

	if (c->p4d_extra_info)
		binary_dump(val);

	return 0;
}

static int pud_callback(pud_t *pud,
			unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	unsigned long val = pud_val(*pud);
	struct tt_dump_config *c = (struct tt_dump_config *)walk->private;

	if (!val)
		return 0;

	addr = addr & PUD_MASK;
	next = (addr & PUD_MASK) - 1 + PUD_SIZE;

	pr_info("PUD ADDR: 0x%p PUD VAL: 0x%016lx huge(%d) [%p --- %p]\n",
		pud, val, pud_huge(*pud), (void *)addr, (void *)next);

	if (c->pud_extra_info)
		binary_dump(val);

	return 0;
}

static int pmd_callback(pmd_t *pmd,
			unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	unsigned long val = pmd_val(*pmd);
	unsigned long paddr = pmd_pfn(*pmd) << PAGE_SHIFT;
	struct tt_dump_config *c = (struct tt_dump_config *)walk->private;

	if (!val)
		return 0;

	addr = addr & PMD_MASK;
	next = (addr & PMD_MASK) - 1 + PMD_SIZE;

	pr_info("PMD ADDR: 0x%p PMD VAL: 0x%016lx huge(%d) [%p --- %p] to %p\n",
		pmd, val, pmd_huge(*pmd), (void *)addr, (void *)next, (void *)paddr);

	if (c->pmd_extra_info)
		binary_dump(val);

	return 0;
}

static int pte_callback(pte_t *pte,
			unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	unsigned long val = pte_val(*pte);
	unsigned long paddr = pte_pfn(*pte) << PAGE_SHIFT;
	struct tt_dump_config *c = (struct tt_dump_config *)walk->private;

	if (!val)
		return 0;

	addr = addr & PAGE_MASK;
	next = (addr & PAGE_MASK) - 1 + PAGE_SIZE;

	pr_info("PTE ADDR: 0x%p PTE VAL: 0x%016lx [%p --- %p] to %p\n",
		pte, val, (void *)addr, (void *)next, (void *)paddr);

	if (c->pte_extra_info)
		binary_dump(val);

	return 0;
}

static int pte_hole_callback(unsigned long addr, unsigned long next,
			     int depth, struct mm_walk *walk)
{
	pr_info("%*chole\n", depth * 2, ' ');

	return 0;
}

void numa_dump_mm_tables(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	int nid = 0;
	struct tt_dump_config conf = {
		.pgd_extra_info = 0,
		.p4d_extra_info = 0,
		.pud_extra_info = 0,
		.pmd_extra_info = 0,
		.pte_extra_info = 0,
	};

	const struct mm_walk_ops ops = {
		.pgd_entry = pgd_callback,
		.p4d_entry = p4d_callback,
		.pud_entry = pud_callback,
		.pmd_entry = pmd_callback,
		.pte_entry = pte_callback,
		.pte_hole  = pte_hole_callback
	};

	start = start & PAGE_MASK;
	end = (end & PAGE_MASK) - 1 + PAGE_SIZE;

	pr_info("----------PER-NUMA NODE KERNEL REPLICATION ENABLED----------\n");
	mmap_read_lock(mm);
	for_each_replica(nid) {
		pr_info("NUMA node id #%d\n", nid);
		pr_info("PGD: %p  PGD phys: %p\n",
			mm->pgd_numa[nid], (void *)virt_to_phys(mm->pgd_numa[nid]));
		walk_page_range_novma(mm, start, end, &ops, mm->pgd_numa[nid], &conf);
	}
	mmap_read_unlock(mm);
	pr_info("----------PER-NUMA NODE KERNEL REPLICATION ENABLED----------\n");
}

static void numa_dump_tt(unsigned long start, unsigned long end)
{
	numa_dump_mm_tables(&init_mm, start, end);
}

DEFINE_SPINLOCK(numa_sysfs_lock);
struct dump_data {
	char *buf;
	ssize_t offset;
};

static void cpu_dump(void *info)
{
	struct dump_data *data = (struct dump_data *) info;
	ssize_t offset;

	spin_lock(&numa_sysfs_lock);

	offset = READ_ONCE(data->offset);

	offset += str_cpu_dump(data->buf + offset);

	WRITE_ONCE(data->offset, offset);

	spin_unlock(&numa_sysfs_lock);
}

static ssize_t sysfs_show(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf)
{
	struct dump_data data = {
		.buf = buf,
		.offset = 0
	};
	numa_dump_tt(KERNEL_TEXT_START, KERNEL_RODATA_END - 1);
	on_each_cpu(cpu_dump, &data, 1);

	return data.offset;
}

static struct kobj_attribute etx_attr = __ATTR(numa_replication_dump, 0440, sysfs_show, NULL);

static void numa_replication_sysfs_init(void)
{
	if (sysfs_create_file(mm_kobj, &etx_attr.attr))
		pr_info("Unable to create sysfs entry for numa replication\n");
}


static void copy_pages_and_flush(struct page *to, struct page *from, size_t nr_pages)
{
	while (nr_pages--) {
		copy_page(page_address(to), page_address(from));
		flush_dcache_page(to);
		to++;
		from++;
	}
}

static void replicate_pages(struct page *pages, int nid,
		unsigned long start, unsigned long end,
		unsigned long nr_pages)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pgprot_t prot;
	unsigned int nr_pmd = 0;

	copy_pages_and_flush(pages, virt_to_page(lm_alias(start)), nr_pages);

	for (unsigned long vaddr = start; vaddr < end; vaddr += PMD_SIZE, nr_pmd++) {

		pgd = pgd_offset_pgd(numa_pgt[nid].pgd, vaddr);
		p4d = p4d_offset(pgd, vaddr);
		pud = pud_offset(p4d, vaddr);
		pmd = pmd_offset(pud, vaddr);

		prot = pmd_pgprot(*pmd);

		set_pmd(pmd, pfn_pmd(page_to_pfn(pages) + nr_pmd * PAGES_PER_PMD, prot));
	}
}

static void __init replicate_kernel_text(int nid)
{
	unsigned long nr_pages = (KERNEL_TEXT_END - KERNEL_TEXT_START) / PAGE_SIZE;

	replicate_pages(virt_to_page(numa_pgt[nid].text_vaddr), nid,
			KERNEL_TEXT_START, KERNEL_TEXT_END, nr_pages);
}

static void replicate_kernel_rodata(int nid)
{
	unsigned long nr_pages = (KERNEL_RODATA_END - KERNEL_RODATA_START) / PAGE_SIZE;

	replicate_pages(virt_to_page(numa_pgt[nid].rodata_vaddr), nid,
			KERNEL_RODATA_START, KERNEL_RODATA_END, nr_pages);
}

//'-1' in next functions have only one purpose - prevent unsgined long overflow
static void replicate_pgt_pmd(p4d_t *dst, p4d_t *src,
			      unsigned long start, unsigned long end,
			      unsigned int nid)
{
	unsigned long left = start & PUD_MASK;
	unsigned long right = (end & PUD_MASK) - 1 + PUD_SIZE;

	pud_t *clone_pud = pud_offset(dst, left);
	pud_t *orig_pud = pud_offset(src, left);

	for (unsigned long addr = left; (addr >= left && addr < right); addr += PUD_SIZE) {
		pmd_t *new_pmd;

		if (pud_none(*orig_pud) || pud_huge(*orig_pud)) {
			clone_pud++;
			orig_pud++;
			continue;
		}

		pud_clear(clone_pud);
		new_pmd = pmd_alloc_node(nid, &init_mm, clone_pud, addr);
		BUG_ON(new_pmd == NULL);

		copy_page(pud_pgtable(*clone_pud), pud_pgtable(*orig_pud));

		clone_pud++;
		orig_pud++;
	}
}

static void replicate_pgt_pud(pgd_t *dst, pgd_t *src,
			      unsigned long start, unsigned long end,
			      unsigned int nid)
{
	unsigned long left = start & P4D_MASK;
	unsigned long right = (end & P4D_MASK) - 1 + P4D_SIZE;

	p4d_t *clone_p4d = p4d_offset(dst, left);
	p4d_t *orig_p4d = p4d_offset(src, left);

	for (unsigned long addr = left; (addr >= left && addr < right); addr += P4D_SIZE) {
		pud_t *new_pud;

		if (p4d_none(*orig_p4d) || p4d_huge(*orig_p4d)) {
			clone_p4d++;
			orig_p4d++;
			continue;
		}

		p4d_clear(clone_p4d);
		new_pud = pud_alloc_node(nid, &init_mm, clone_p4d, addr);
		BUG_ON(new_pud == NULL);

		copy_page(p4d_pgtable(*clone_p4d), p4d_pgtable(*orig_p4d));
		/* start and end passed to the next function must be in range of p4ds,
		 * so min and max are used here
		 */
		replicate_pgt_pmd(clone_p4d, orig_p4d, max(addr, start),
				  min(addr - 1 + P4D_SIZE, end), nid);

		clone_p4d++;
		orig_p4d++;
	}
}

static void replicate_pgt_p4d(pgd_t *dst, pgd_t *src,
			      unsigned long start, unsigned long end,
			      unsigned int nid)
{
	unsigned long left = start & PGDIR_MASK;
	unsigned long right = (end & PGDIR_MASK) - 1 + PGDIR_SIZE;

	pgd_t *clone_pgd = pgd_offset_pgd(dst, left);
	pgd_t *orig_pgd = pgd_offset_pgd(src, left);

	for (unsigned long addr = left; (addr >= left && addr < right); addr += PGDIR_SIZE) {
		p4d_t *new_p4d;

		/* TODO: remove last condition and do something better
		 * In the case of a folded P4D level, pgd_none and pgd_huge
		 * always return 0, so we might start to replicate empty entries.
		 * We obviously want to avoid this, so the last check is performed here.
		 */
		if (pgd_none(*orig_pgd) || pgd_huge(*orig_pgd) ||
				(unsigned long)(orig_pgd->pgd) == 0) {
			clone_pgd++;
			orig_pgd++;
			continue;
		}

		pgd_clear(clone_pgd);
		new_p4d = p4d_alloc_node(nid, &init_mm, clone_pgd, addr);
		BUG_ON(new_p4d == NULL);

		copy_page((void *)pgd_page_vaddr(*clone_pgd), (void *)pgd_page_vaddr(*orig_pgd));
		replicate_pgt_pud(clone_pgd, orig_pgd, max(addr, start),
				  min(addr - 1 + PGDIR_SIZE, end), nid);

		clone_pgd++;
		orig_pgd++;
	}
}

static void replicate_pgt(int nid, unsigned long start, unsigned long end)
{
	replicate_pgt_p4d(numa_pgt[nid].pgd, init_mm.pgd, start, end, nid);
}

static void replicate_pagetables(void)
{
	int nid;

	for_each_replica(nid) {
		numa_pgt[nid].pgd = numa_replicate_pgt_pgd(nid);

		replicate_pgt(nid, PAGE_TABLE_REPLICATION_LEFT,
				   PAGE_TABLE_REPLICATION_RIGHT);

	}

	for_each_online_node(nid) {
		init_mm.pgd_numa[nid] = numa_pgt[closest_memory_node[nid]].pgd;
	}
}

void __init numa_replicate_kernel(void)
{
	int nid;

	replicate_pagetables();

	for_each_replica(nid) {
		if (nid == master_node)
			continue;
		replicate_kernel_text(nid);
	}

	text_replicated = true;
	numa_setup_pgd();
}

void numa_replicate_kernel_rodata(void)
{
	int nid;

	for_each_replica(nid) {
		if (nid == master_node)
			continue;
		replicate_kernel_rodata(nid);
	}

	flush_tlb_all();
	pr_info("Replicated page table : [%p --- %p]\n", (void *)PAGE_TABLE_REPLICATION_LEFT,
							 (void *)PAGE_TABLE_REPLICATION_RIGHT);

	numa_replication_sysfs_init();
	numa_dump_tt(KERNEL_TEXT_START, KERNEL_RODATA_END - 1);
}

void numa_setup_pgd(void)
{
	/* switch away from the initial page table */
	load_replicated_pgd(init_mm.pgd_numa[numa_node_id()]);
}

void __init_or_module *numa_addr_in_replica(void *vaddr, int nid)
{
	unsigned long addr = (unsigned long)vaddr;
	unsigned long offset = addr - KERNEL_TEXT_START;

	BUG_ON(addr < KERNEL_TEXT_START || addr >= KERNEL_TEXT_END);
	BUG_ON(numa_pgt[nid].text_vaddr == NULL);
	BUG_ON(closest_memory_node[nid] != nid);

	return numa_pgt[nid].text_vaddr + offset;
}

void numa_clear_linear_addresses(void)
{
	int nid;

	for_each_replica(nid) {
		numa_pgt[nid].text_vaddr = NULL;
		numa_pgt[nid].rodata_vaddr = NULL;
	}
}

static void numa_find_closest_memory_nodes(void)
{
	int nid;

	for_each_online_node(nid) {
		int new_node;
		int min_dist = INT_MAX;
		int found_node = nid;

		for_each_node_state(new_node, N_MEMORY) {
			int new_dist = node_distance(nid, new_node);

			if (new_dist < min_dist) {
				found_node = new_node;
				min_dist = new_dist;
			}
		}
		closest_memory_node[nid] = found_node;

		pr_info("For node %d  closest - %d\n", nid, found_node);
	}
}

void __init numa_reserve_memory(void)
{
	int nid;

	for_each_replica(nid)
		pr_info("Memory node: %d\n", nid);

	numa_find_closest_memory_nodes();
	master_node = page_to_nid(virt_to_page(lm_alias((void *)KERNEL_TEXT_START)));

	pr_info("Master Node: #%d\n", master_node);
	for_each_replica(nid) {
		if (nid == master_node) {
			numa_pgt[nid].text_vaddr = lm_alias((void *)KERNEL_TEXT_START);
			numa_pgt[nid].rodata_vaddr = lm_alias((void *)KERNEL_RODATA_START);
		} else {
			numa_pgt[nid].text_vaddr = memblock_alloc_try_nid(
						   (KERNEL_TEXT_END - KERNEL_TEXT_START),
						   HPAGE_SIZE, 0, MEMBLOCK_ALLOC_ANYWHERE, nid);

			numa_pgt[nid].rodata_vaddr = memblock_alloc_try_nid(
						   (KERNEL_RODATA_END - KERNEL_RODATA_START),
						   HPAGE_SIZE, 0, MEMBLOCK_ALLOC_ANYWHERE, nid);
		}

		BUG_ON(numa_pgt[nid].text_vaddr == NULL);
		BUG_ON(numa_pgt[nid].rodata_vaddr == NULL);
	}
}

