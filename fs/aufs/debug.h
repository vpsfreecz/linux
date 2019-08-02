/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * debug print functions
 */

#ifndef __AUFS_DEBUG_H__
#define __AUFS_DEBUG_H__

#ifdef __KERNEL__

#include <linux/atomic.h>
#include <linux/module.h>

#ifdef CONFIG_AUFS_DEBUG
#define AuDebugOn(a)		BUG_ON(a)

/* module parameter */
extern atomic_t aufs_debug;
static inline void au_debug_on(void)
{
	atomic_inc(&aufs_debug);
}
static inline void au_debug_off(void)
{
	atomic_dec_if_positive(&aufs_debug);
}

static inline int au_debug_test(void)
{
	return atomic_read(&aufs_debug) > 0;
}
#else
#define AuDebugOn(a)		do {} while (0)
AuStubVoid(au_debug_on, void)
AuStubVoid(au_debug_off, void)
AuStubInt0(au_debug_test, void)
#endif /* CONFIG_AUFS_DEBUG */

#define param_check_atomic_t(name, p) __param_check(name, p, atomic_t)

/* ---------------------------------------------------------------------- */

/* debug print */

#define AuDbg(fmt, ...) do { \
	if (au_debug_test()) \
		pr_debug("DEBUG: " fmt, ##__VA_ARGS__); \
} while (0)
#define AuLabel(l)		AuDbg(#l "\n")

/* ---------------------------------------------------------------------- */

struct dentry;
#ifdef CONFIG_AUFS_DEBUG
extern struct mutex au_dbg_mtx;
extern char *au_plevel;
struct inode;
void au_dpri_inode(struct inode *inode);

#define AuDbgInode(i) do { \
	mutex_lock(&au_dbg_mtx); \
	AuDbg(#i "\n"); \
	au_dpri_inode(i); \
	mutex_unlock(&au_dbg_mtx); \
} while (0)
#else
#define AuDbgInode(i)		do {} while (0)
#endif /* CONFIG_AUFS_DEBUG */

#endif /* __KERNEL__ */
#endif /* __AUFS_DEBUG_H__ */
