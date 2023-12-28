/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SET_MEMORY_H
#define __ASM_SET_MEMORY_H

/*
 * Functions to change memory attributes.
 */
int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
int set_memory_x(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);

#ifdef CONFIG_KERNEL_REPLICATION
int numa_set_memory_ro(unsigned long addr, int numpages);
int numa_set_memory_rw(unsigned long addr, int numpages);
int numa_set_memory_x(unsigned long addr, int numpages);
int numa_set_memory_nx(unsigned long addr, int numpages);
#else
#define numa_set_memory_ro set_memory_ro
#define numa_set_memory_rw set_memory_rw
#define numa_set_memory_x  set_memory_x
#define numa_set_memory_nx set_memory_nx
#endif /* CONFIG_KERNEL_REPLICATION */

#endif
