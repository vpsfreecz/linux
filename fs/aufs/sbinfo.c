// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * superblock private data
 */

#include <linux/iversion.h>
#include "aufs.h"

/*
 * they are necessary regardless sysfs is disabled.
 */
void au_si_free(struct kobject *kobj)
{
	struct au_sbinfo *sbinfo;

	sbinfo = container_of(kobj, struct au_sbinfo, si_kobj);

	au_rw_write_lock(&sbinfo->si_rwsem);
	au_br_free(sbinfo);
	au_rw_write_unlock(&sbinfo->si_rwsem);

	au_kfree_try_rcu(sbinfo->si_branch);
	AuRwDestroy(&sbinfo->si_rwsem);

	au_kfree_rcu(sbinfo);
}

int au_si_alloc(struct super_block *sb)
{
	int err;
	struct au_sbinfo *sbinfo;

	err = -ENOMEM;
	sbinfo = kzalloc(sizeof(*sbinfo), GFP_NOFS);
	if (unlikely(!sbinfo))
		goto out;

	/* will be reallocated separately */
	sbinfo->si_branch = kzalloc(sizeof(*sbinfo->si_branch), GFP_NOFS);
	if (unlikely(!sbinfo->si_branch))
		goto out_sbinfo;

	au_rw_init_wlock(&sbinfo->si_rwsem);

	sbinfo->si_bbot = -1;
	sbinfo->si_last_br_id = AUFS_BRANCH_MAX / 2;

	/* leave other members for sysaufs and si_mnt. */
	sb->s_fs_info = sbinfo;
	return 0; /* success */

	au_kfree_try_rcu(sbinfo->si_branch);
out_sbinfo:
	au_kfree_rcu(sbinfo);
out:
	return err;
}

int au_sbr_realloc(struct au_sbinfo *sbinfo, int nbr, int may_shrink)
{
	int err, sz;
	struct au_branch **brp;

	AuRwMustWriteLock(&sbinfo->si_rwsem);

	err = -ENOMEM;
	sz = sizeof(*brp) * (sbinfo->si_bbot + 1);
	if (unlikely(!sz))
		sz = sizeof(*brp);
	brp = au_kzrealloc(sbinfo->si_branch, sz, sizeof(*brp) * nbr, GFP_NOFS,
			   may_shrink);
	if (brp) {
		sbinfo->si_branch = brp;
		err = 0;
	}

	return err;
}

/* ---------------------------------------------------------------------- */

unsigned int au_sigen_inc(struct super_block *sb)
{
	unsigned int gen;
	struct inode *inode;

	SiMustWriteLock(sb);

	gen = ++au_sbi(sb)->si_generation;
	au_update_digen(sb->s_root);
	inode = d_inode(sb->s_root);
	au_update_iigen(inode, /*half*/0);
	inode_inc_iversion(inode);
	return gen;
}

aufs_bindex_t au_new_br_id(struct super_block *sb)
{
	aufs_bindex_t br_id;
	int i;
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	for (i = 0; i <= AUFS_BRANCH_MAX; i++) {
		br_id = ++sbinfo->si_last_br_id;
		AuDebugOn(br_id < 0);
		if (br_id && au_br_index(sb, br_id) < 0)
			return br_id;
	}

	return -1;
}
