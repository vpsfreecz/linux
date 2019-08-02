// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * directory operations
 */

#include "aufs.h"

void au_add_nlink(struct inode *dir, struct inode *h_dir)
{
	unsigned int nlink;

	AuDebugOn(!S_ISDIR(dir->i_mode) || !S_ISDIR(h_dir->i_mode));

	nlink = dir->i_nlink;
	nlink += h_dir->i_nlink - 2;
	if (h_dir->i_nlink < 2)
		nlink += 2;
	smp_mb(); /* for i_nlink */
	/* 0 can happen in revaliding */
	set_nlink(dir, nlink);
}

void au_sub_nlink(struct inode *dir, struct inode *h_dir)
{
	unsigned int nlink;

	AuDebugOn(!S_ISDIR(dir->i_mode) || !S_ISDIR(h_dir->i_mode));

	nlink = dir->i_nlink;
	nlink -= h_dir->i_nlink - 2;
	if (h_dir->i_nlink < 2)
		nlink -= 2;
	smp_mb(); /* for i_nlink */
	/* nlink == 0 means the branch-fs is broken */
	set_nlink(dir, nlink);
}

loff_t au_dir_size(struct file *file, struct dentry *dentry)
{
	loff_t sz;
	aufs_bindex_t bindex, bbot;
	struct file *h_file;
	struct dentry *h_dentry;

	sz = 0;
	if (file) {
		AuDebugOn(!d_is_dir(file->f_path.dentry));

		bbot = au_fbbot_dir(file);
		for (bindex = au_fbtop(file);
		     bindex <= bbot && sz < KMALLOC_MAX_SIZE;
		     bindex++) {
			h_file = au_hf_dir(file, bindex);
			if (h_file && file_inode(h_file))
				sz += vfsub_f_size_read(h_file);
		}
	} else {
		AuDebugOn(!dentry);
		AuDebugOn(!d_is_dir(dentry));

		bbot = au_dbtaildir(dentry);
		for (bindex = au_dbtop(dentry);
		     bindex <= bbot && sz < KMALLOC_MAX_SIZE;
		     bindex++) {
			h_dentry = au_h_dptr(dentry, bindex);
			if (h_dentry && d_is_positive(h_dentry))
				sz += i_size_read(d_inode(h_dentry));
		}
	}
	if (sz < KMALLOC_MAX_SIZE)
		sz = roundup_pow_of_two(sz);
	if (sz > KMALLOC_MAX_SIZE)
		sz = KMALLOC_MAX_SIZE;
	else if (sz < NAME_MAX) {
		BUILD_BUG_ON(AUFS_RDBLK_DEF < NAME_MAX);
		sz = AUFS_RDBLK_DEF;
	}
	return sz;
}

struct au_dir_ts_arg {
	struct dentry *dentry;
	aufs_bindex_t brid;
};

static void au_do_dir_ts(void *arg)
{
	struct au_dir_ts_arg *a = arg;
	struct au_dtime dt;
	struct path h_path;
	struct inode *dir, *h_dir;
	struct super_block *sb;
	struct au_branch *br;
	struct au_hinode *hdir;
	int err;
	aufs_bindex_t btop, bindex;

	sb = a->dentry->d_sb;
	if (d_really_is_negative(a->dentry))
		goto out;
	/* no dir->i_mutex lock */
	aufs_read_lock(a->dentry, AuLock_DW); /* noflush */

	dir = d_inode(a->dentry);
	btop = au_ibtop(dir);
	bindex = au_br_index(sb, a->brid);
	if (bindex < btop)
		goto out_unlock;

	br = au_sbr(sb, bindex);
	h_path.dentry = au_h_dptr(a->dentry, bindex);
	if (!h_path.dentry)
		goto out_unlock;
	h_path.mnt = au_br_mnt(br);
	au_dtime_store(&dt, a->dentry, &h_path);

	br = au_sbr(sb, btop);
	if (!au_br_writable(br->br_perm))
		goto out_unlock;
	h_path.dentry = au_h_dptr(a->dentry, btop);
	h_path.mnt = au_br_mnt(br);
	err = vfsub_mnt_want_write(h_path.mnt);
	if (err)
		goto out_unlock;
	hdir = au_hi(dir, btop);
	au_hn_inode_lock_nested(hdir, AuLsc_I_PARENT);
	h_dir = au_h_iptr(dir, btop);
	if (h_dir->i_nlink
	    && timespec64_compare(&h_dir->i_mtime, &dt.dt_mtime) < 0) {
		dt.dt_h_path = h_path;
		au_dtime_revert(&dt);
	}
	au_hn_inode_unlock(hdir);
	vfsub_mnt_drop_write(h_path.mnt);
	au_cpup_attr_timesizes(dir);

out_unlock:
	aufs_read_unlock(a->dentry, AuLock_DW);
out:
	dput(a->dentry);
	au_nwt_done(&au_sbi(sb)->si_nowait);
	au_kfree_try_rcu(arg);
}

void au_dir_ts(struct inode *dir, aufs_bindex_t bindex)
{
	int perm, wkq_err;
	aufs_bindex_t btop;
	struct au_dir_ts_arg *arg;
	struct dentry *dentry;
	struct super_block *sb;

	IMustLock(dir);

	dentry = d_find_any_alias(dir);
	AuDebugOn(!dentry);
	sb = dentry->d_sb;
	btop = au_ibtop(dir);
	if (btop == bindex) {
		au_cpup_attr_timesizes(dir);
		goto out;
	}

	perm = au_sbr_perm(sb, btop);
	if (!au_br_writable(perm))
		goto out;

	arg = kmalloc(sizeof(*arg), GFP_NOFS);
	if (!arg)
		goto out;

	arg->dentry = dget(dentry); /* will be dput-ted by au_do_dir_ts() */
	arg->brid = au_sbr_id(sb, bindex);
	wkq_err = au_wkq_nowait(au_do_dir_ts, arg, sb, /*flags*/0);
	if (unlikely(wkq_err)) {
		pr_err("wkq %d\n", wkq_err);
		dput(dentry);
		au_kfree_try_rcu(arg);
	}

out:
	dput(dentry);
}

/* ---------------------------------------------------------------------- */

#define AuTestEmpty_WHONLY	1
#define AuTestEmpty_CALLED	(1 << 1)
#define au_ftest_testempty(flags, name)	((flags) & AuTestEmpty_##name)
#define au_fset_testempty(flags, name) \
	do { (flags) |= AuTestEmpty_##name; } while (0)
#define au_fclr_testempty(flags, name) \
	do { (flags) &= ~AuTestEmpty_##name; } while (0)

struct test_empty_arg {
	struct dir_context ctx;
	struct au_nhash *whlist;
	unsigned int flags;
	int err;
	aufs_bindex_t bindex;
};

static int test_empty_cb(struct dir_context *ctx, const char *__name,
			 int namelen, loff_t offset __maybe_unused, u64 ino,
			 unsigned int d_type)
{
	struct test_empty_arg *arg = container_of(ctx, struct test_empty_arg,
						  ctx);
	char *name = (void *)__name;

	arg->err = 0;
	au_fset_testempty(arg->flags, CALLED);
	/* smp_mb(); */
	if (name[0] == '.'
	    && (namelen == 1 || (name[1] == '.' && namelen == 2)))
		goto out; /* success */

	if (namelen <= AUFS_WH_PFX_LEN
	    || memcmp(name, AUFS_WH_PFX, AUFS_WH_PFX_LEN)) {
		if (au_ftest_testempty(arg->flags, WHONLY)
		    && !au_nhash_test_known_wh(arg->whlist, name, namelen))
			arg->err = -ENOTEMPTY;
		goto out;
	}

	name += AUFS_WH_PFX_LEN;
	namelen -= AUFS_WH_PFX_LEN;
	if (!au_nhash_test_known_wh(arg->whlist, name, namelen))
		arg->err = au_nhash_append_wh
			(arg->whlist, name, namelen, ino, d_type, arg->bindex);

out:
	/* smp_mb(); */
	AuTraceErr(arg->err);
	return arg->err;
}

static int do_test_empty(struct dentry *dentry, struct test_empty_arg *arg)
{
	int err;
	struct file *h_file;
	struct au_branch *br;

	h_file = au_h_open(dentry, arg->bindex,
			   O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_LARGEFILE,
			   /*file*/NULL);
	err = PTR_ERR(h_file);
	if (IS_ERR(h_file))
		goto out;

	err = 0;
	if (!au_opt_test(au_mntflags(dentry->d_sb), UDBA_NONE)
	    && !file_inode(h_file)->i_nlink)
		goto out_put;

	do {
		arg->err = 0;
		au_fclr_testempty(arg->flags, CALLED);
		/* smp_mb(); */
		err = vfsub_iterate_dir(h_file, &arg->ctx);
		if (err >= 0)
			err = arg->err;
	} while (!err && au_ftest_testempty(arg->flags, CALLED));

out_put:
	fput(h_file);
	br = au_sbr(dentry->d_sb, arg->bindex);
	au_lcnt_dec(&br->br_nfiles);
out:
	return err;
}

struct do_test_empty_args {
	int *errp;
	struct dentry *dentry;
	struct test_empty_arg *arg;
};

static void call_do_test_empty(void *args)
{
	struct do_test_empty_args *a = args;
	*a->errp = do_test_empty(a->dentry, a->arg);
}

static int sio_test_empty(struct dentry *dentry, struct test_empty_arg *arg)
{
	int err, wkq_err;
	struct dentry *h_dentry;
	struct inode *h_inode;

	h_dentry = au_h_dptr(dentry, arg->bindex);
	h_inode = d_inode(h_dentry);
	/* todo: i_mode changes anytime? */
	inode_lock_shared_nested(h_inode, AuLsc_I_CHILD);
	err = au_test_h_perm_sio(h_inode, MAY_EXEC | MAY_READ);
	inode_unlock_shared(h_inode);
	if (!err)
		err = do_test_empty(dentry, arg);
	else {
		struct do_test_empty_args args = {
			.errp	= &err,
			.dentry	= dentry,
			.arg	= arg
		};
		unsigned int flags = arg->flags;

		wkq_err = au_wkq_wait(call_do_test_empty, &args);
		if (unlikely(wkq_err))
			err = wkq_err;
		arg->flags = flags;
	}

	return err;
}

int au_test_empty_lower(struct dentry *dentry)
{
	int err;
	unsigned int rdhash;
	aufs_bindex_t bindex, btop, btail;
	struct au_nhash whlist;
	struct test_empty_arg arg = {
		.ctx = {
			.actor = test_empty_cb
		}
	};
	int (*test_empty)(struct dentry *dentry, struct test_empty_arg *arg);

	SiMustAnyLock(dentry->d_sb);

	rdhash = au_sbi(dentry->d_sb)->si_rdhash;
	if (!rdhash)
		rdhash = au_rdhash_est(au_dir_size(/*file*/NULL, dentry));
	err = au_nhash_alloc(&whlist, rdhash, GFP_NOFS);
	if (unlikely(err))
		goto out;

	arg.flags = 0;
	arg.whlist = &whlist;
	btop = au_dbtop(dentry);
	test_empty = do_test_empty;
	arg.bindex = btop;
	err = test_empty(dentry, &arg);
	if (unlikely(err))
		goto out_whlist;

	au_fset_testempty(arg.flags, WHONLY);
	btail = au_dbtaildir(dentry);
	for (bindex = btop + 1; !err && bindex <= btail; bindex++) {
		struct dentry *h_dentry;

		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry && d_is_positive(h_dentry)) {
			arg.bindex = bindex;
			err = test_empty(dentry, &arg);
		}
	}

out_whlist:
	au_nhash_wh_free(&whlist);
out:
	return err;
}

int au_test_empty(struct dentry *dentry, struct au_nhash *whlist)
{
	int err;
	struct test_empty_arg arg = {
		.ctx = {
			.actor = test_empty_cb
		}
	};
	aufs_bindex_t bindex, btail;

	err = 0;
	arg.whlist = whlist;
	arg.flags = AuTestEmpty_WHONLY;
	btail = au_dbtaildir(dentry);
	for (bindex = au_dbtop(dentry); !err && bindex <= btail; bindex++) {
		struct dentry *h_dentry;

		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry && d_is_positive(h_dentry)) {
			arg.bindex = bindex;
			err = sio_test_empty(dentry, &arg);
		}
	}

	return err;
}
