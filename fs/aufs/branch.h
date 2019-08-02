/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * branch filesystems and xino for them
 */

#ifndef __AUFS_BRANCH_H__
#define __AUFS_BRANCH_H__

#ifdef __KERNEL__

#include <linux/mount.h>
#include "lcnt.h"
#include "super.h"

/* ---------------------------------------------------------------------- */

/* a xino file */
struct au_xino {
	struct file		**xi_file;
	unsigned int		xi_nfile;

	struct {
		spinlock_t		spin;
		ino_t			*array;
		int			total;
		/* reserved for future use */
		/* unsigned long	*bitmap; */
		wait_queue_head_t	wqh;
	} xi_nondir;

	struct mutex		xi_mtx;	/* protects xi_file array */
	struct hlist_bl_head	xi_writing;

	struct kref		xi_kref;
};

/* protected by superblock rwsem */
struct au_branch {
	struct au_xino		*br_xino;

	aufs_bindex_t		br_id;

	int			br_perm;
	struct path		br_path;
	au_lcnt_t		br_count;	/* in-use for other */
};

/* ---------------------------------------------------------------------- */

static inline struct vfsmount *au_br_mnt(struct au_branch *br)
{
	return br->br_path.mnt;
}

static inline struct dentry *au_br_dentry(struct au_branch *br)
{
	return br->br_path.dentry;
}

static inline struct super_block *au_br_sb(struct au_branch *br)
{
	return au_br_mnt(br)->mnt_sb;
}

static inline void au_xino_get(struct au_branch *br)
{
	struct au_xino *xi;

	xi = br->br_xino;
	if (xi)
		kref_get(&xi->xi_kref);
}

static inline int au_xino_count(struct au_branch *br)
{
	int v;
	struct au_xino *xi;

	v = 0;
	xi = br->br_xino;
	if (xi)
		v = kref_read(&xi->xi_kref);

	return v;
}

/* ---------------------------------------------------------------------- */

/* branch.c */
struct au_sbinfo;
void au_br_free(struct au_sbinfo *sinfo);
int au_br_index(struct super_block *sb, aufs_bindex_t br_id);
struct au_opt_add;
int au_br_add(struct super_block *sb, struct au_opt_add *add);

/* xino.c */
aufs_bindex_t au_xi_root(struct super_block *sb, struct dentry *dentry);
struct file *au_xino_create(struct super_block *sb, char *fpath, int silent);
struct file *au_xino_create2(struct super_block *sb, struct path *base,
			     struct file *copy_src);
struct au_xi_new {
	struct au_xino *xi;	/* switch between xino and xigen */
	int idx;
	struct path *base;
	struct file *copy_src;
};
struct file *au_xi_new(struct super_block *sb, struct au_xi_new *xinew);

int au_xino_read(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		 ino_t *ino);
int au_xino_write(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		  ino_t ino);
ssize_t xino_fread(vfs_readf_t func, struct file *file, void *buf, size_t size,
		   loff_t *pos);
ssize_t xino_fwrite(vfs_writef_t func, struct file *file, void *buf,
		    size_t size, loff_t *pos);

struct au_xino *au_xino_alloc(unsigned int nfile);
int au_xino_put(struct au_branch *br);
struct file *au_xino_file1(struct au_xino *xi);

struct au_opt_xino;
void au_xino_clr(struct super_block *sb);
int au_xino_set(struct super_block *sb, struct au_opt_xino *xiopt);
struct file *au_xino_def(struct super_block *sb);
int au_xino_init_br(struct super_block *sb, struct au_branch *br, ino_t hino,
		    struct path *base);

ino_t au_xino_new_ino(struct super_block *sb);
void au_xino_delete_inode(struct inode *inode, const int unlinked);

/* ---------------------------------------------------------------------- */

/* @idx is signed to accept -1 meaning the first file */
static inline struct file *au_xino_file(struct au_xino *xi, int idx)
{
	struct file *file;

	file = NULL;
	if (!xi)
		goto out;

	if (idx >= 0) {
		if (idx < xi->xi_nfile)
			file = xi->xi_file[idx];
	} else
		file = au_xino_file1(xi);

out:
	return file;
}

/* ---------------------------------------------------------------------- */

/* Superblock to branch */
static inline
aufs_bindex_t au_sbr_id(struct super_block *sb, aufs_bindex_t bindex)
{
	return au_sbr(sb, bindex)->br_id;
}

static inline
struct super_block *au_sbr_sb(struct super_block *sb, aufs_bindex_t bindex)
{
	return au_br_sb(au_sbr(sb, bindex));
}

static inline int au_sbr_perm(struct super_block *sb, aufs_bindex_t bindex)
{
	return au_sbr(sb, bindex)->br_perm;
}

#endif /* __KERNEL__ */
#endif /* __AUFS_BRANCH_H__ */
