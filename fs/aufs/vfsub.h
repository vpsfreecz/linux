/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * sub-routines for VFS
 */

#ifndef __AUFS_VFSUB_H__
#define __AUFS_VFSUB_H__

#ifdef __KERNEL__

#include <linux/fs.h>
#include "debug.h"

/* to debug easier, do not make them inlined functions */
#define MtxMustLock(mtx)	AuDebugOn(!mutex_is_locked(mtx))
#define IMustLock(i)		AuDebugOn(!inode_is_locked(i))

int vfsub_kern_path(const char *name, unsigned int flags, struct path *path);

#endif /* __KERNEL__ */
#endif /* __AUFS_VFSUB_H__ */
