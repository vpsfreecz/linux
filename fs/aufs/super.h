/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * super_block operations
 */

#ifndef __AUFS_SUPER_H__
#define __AUFS_SUPER_H__

#ifdef __KERNEL__

/* super.c */
struct super_block;
struct inode *au_iget_locked(struct super_block *sb, ino_t ino);

#endif /* __KERNEL__ */
#endif /* __AUFS_SUPER_H__ */
