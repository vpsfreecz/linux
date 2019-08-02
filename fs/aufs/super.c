// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * mount and super_block operations
 */

#include <linux/iversion.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include "aufs.h"

/*
 * super_operations
 */
static struct inode *aufs_alloc_inode(struct super_block *sb __maybe_unused)
{
	struct au_icntnr *c;

	c = au_cache_alloc_icntnr();
	if (c) {
		au_icntnr_init(c);
		inode_set_iversion(&c->vfs_inode, 1); /* sigen(sb); */
		c->iinfo.ii_hinode = NULL;
		return &c->vfs_inode;
	}
	return NULL;
}

static void aufs_destroy_inode_cb(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	au_cache_free_icntnr(container_of(inode, struct au_icntnr, vfs_inode));
}

static void aufs_destroy_inode(struct inode *inode)
{
	if (!au_is_bad_inode(inode))
		au_iinfo_fin(inode);
	call_rcu(&inode->i_rcu, aufs_destroy_inode_cb);
}

struct inode *au_iget_locked(struct super_block *sb, ino_t ino)
{
	struct inode *inode;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode)) {
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	if (!(inode->i_state & I_NEW))
		goto out;

	err = au_xigen_new(inode);
	if (!err)
		err = au_iinfo_init(inode);
	if (!err)
		inode_inc_iversion(inode);
	else {
		iget_failed(inode);
		inode = ERR_PTR(err);
	}

out:
	/* never return NULL */
	AuDebugOn(!inode);
	AuTraceErrPtr(inode);
	return inode;
}

/* lock free root dinfo */
/* re-commit later */ __maybe_unused
static int au_show_brs(struct seq_file *seq, struct super_block *sb)
{
	int err;
	aufs_bindex_t bindex, bbot;
	struct path path;
	struct au_hdentry *hdp;
	struct au_branch *br;
	au_br_perm_str_t perm;

	err = 0;
	bbot = au_sbbot(sb);
	bindex = 0;
	hdp = au_hdentry(au_di(sb->s_root), bindex);
	for (; !err && bindex <= bbot; bindex++, hdp++) {
		br = au_sbr(sb, bindex);
		path.mnt = au_br_mnt(br);
		path.dentry = hdp->hd_dentry;
		err = au_seq_path(seq, &path);
		if (!err) {
			au_optstr_br_perm(&perm, br->br_perm);
			seq_printf(seq, "=%s", perm.a);
			if (bindex != bbot)
				seq_putc(seq, ':');
		}
	}
	if (unlikely(err || seq_has_overflowed(seq)))
		err = -E2BIG;

	return err;
}

static void au_gen_fmt(char *fmt, int len __maybe_unused, const char *pat,
		       const char *append)
{
	char *p;

	p = fmt;
	while (*pat != ':')
		*p++ = *pat++;
	*p++ = *pat++;
	strcpy(p, append);
	AuDebugOn(strlen(fmt) >= len);
}

/* re-commit later */ __maybe_unused
static void au_show_wbr_create(struct seq_file *m, int v,
			       struct au_sbinfo *sbinfo)
{
	const char *pat;
	char fmt[32];
	struct au_wbr_mfs *mfs;

	AuRwMustAnyLock(&sbinfo->si_rwsem);

	seq_puts(m, ",create=");
	pat = au_optstr_wbr_create(v);
	mfs = &sbinfo->si_wbr_mfs;
	switch (v) {
	case AuWbrCreate_TDP:
	case AuWbrCreate_RR:
	case AuWbrCreate_MFS:
	case AuWbrCreate_PMFS:
		seq_puts(m, pat);
		break;
	case AuWbrCreate_MFSRR:
	case AuWbrCreate_TDMFS:
	case AuWbrCreate_PMFSRR:
		au_gen_fmt(fmt, sizeof(fmt), pat, "%llu");
		seq_printf(m, fmt, mfs->mfsrr_watermark);
		break;
	case AuWbrCreate_MFSV:
	case AuWbrCreate_PMFSV:
		au_gen_fmt(fmt, sizeof(fmt), pat, "%lu");
		seq_printf(m, fmt,
			   jiffies_to_msecs(mfs->mfs_expire)
			   / MSEC_PER_SEC);
		break;
	case AuWbrCreate_MFSRRV:
	case AuWbrCreate_TDMFSV:
	case AuWbrCreate_PMFSRRV:
		au_gen_fmt(fmt, sizeof(fmt), pat, "%llu:%lu");
		seq_printf(m, fmt, mfs->mfsrr_watermark,
			   jiffies_to_msecs(mfs->mfs_expire) / MSEC_PER_SEC);
		break;
	default:
		BUG();
	}
}

/* re-commit later */ __maybe_unused
static int au_show_xino(struct seq_file *seq, struct super_block *sb)
{
#ifdef CONFIG_SYSFS
	return 0;
#else
	int err;
	const int len = sizeof(AUFS_XINO_FNAME) - 1;
	aufs_bindex_t bindex, brid;
	struct qstr *name;
	struct file *f;
	struct dentry *d, *h_root;
	struct au_branch *br;

	AuRwMustAnyLock(&sbinfo->si_rwsem);

	err = 0;
	f = au_sbi(sb)->si_xib;
	if (!f)
		goto out;

	/* stop printing the default xino path on the first writable branch */
	h_root = NULL;
	bindex = au_xi_root(sb, f->f_path.dentry);
	if (bindex >= 0) {
		br = au_sbr_sb(sb, bindex);
		h_root = au_br_dentry(br);
	}

	d = f->f_path.dentry;
	name = &d->d_name;
	/* safe ->d_parent because the file is unlinked */
	if (d->d_parent == h_root
	    && name->len == len
	    && !memcmp(name->name, AUFS_XINO_FNAME, len))
		goto out;

	seq_puts(seq, ",xino=");
	err = au_xino_path(seq, f);

out:
	return err;
#endif
}

/* ---------------------------------------------------------------------- */

/* final actions when unmounting a file system */
static void aufs_put_super(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	sbinfo = au_sbi(sb);
	if (sbinfo)
		kobject_put(&sbinfo->si_kobj);
}

/* ---------------------------------------------------------------------- */

void *au_array_alloc(unsigned long long *hint, au_arraycb_t cb,
		     struct super_block *sb, void *arg)
{
	void *array;
	unsigned long long n, sz;

	array = NULL;
	n = 0;
	if (!*hint)
		goto out;

	if (*hint > ULLONG_MAX / sizeof(array)) {
		array = ERR_PTR(-EMFILE);
		pr_err("hint %llu\n", *hint);
		goto out;
	}

	sz = sizeof(array) * *hint;
	array = kzalloc(sz, GFP_NOFS);
	if (unlikely(!array))
		array = vzalloc(sz);
	if (unlikely(!array)) {
		array = ERR_PTR(-ENOMEM);
		goto out;
	}

	n = cb(sb, array, *hint, arg);
	AuDebugOn(n > *hint);

out:
	*hint = n;
	return array;
}

static unsigned long long au_iarray_cb(struct super_block *sb, void *a,
				       unsigned long long max __maybe_unused,
				       void *arg)
{
	unsigned long long n;
	struct inode **p, *inode;
	struct list_head *head;

	n = 0;
	p = a;
	head = arg;
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, head, i_sb_list) {
		if (!au_is_bad_inode(inode)
		    && au_ii(inode)->ii_btop >= 0) {
			spin_lock(&inode->i_lock);
			if (atomic_read(&inode->i_count)) {
				au_igrab(inode);
				*p++ = inode;
				n++;
				AuDebugOn(n > max);
			}
			spin_unlock(&inode->i_lock);
		}
	}
	spin_unlock(&sb->s_inode_list_lock);

	return n;
}

struct inode **au_iarray_alloc(struct super_block *sb, unsigned long long *max)
{
	struct au_sbinfo *sbi;

	sbi = au_sbi(sb);
	*max = au_lcnt_read(&sbi->si_ninodes, /*do_rev*/1);
	return au_array_alloc(max, au_iarray_cb, sb, &sb->s_inodes);
}

void au_iarray_free(struct inode **a, unsigned long long max)
{
	unsigned long long ull;

	for (ull = 0; ull < max; ull++)
		iput(a[ull]);
	kvfree(a);
}

/* ---------------------------------------------------------------------- */

/* stop extra interpretation of errno in mount(8), and strange error messages */
static int cvt_err(int err)
{
	AuTraceErr(err);

	switch (err) {
	case -ENOENT:
	case -ENOTDIR:
	case -EEXIST:
	case -EIO:
		err = -EINVAL;
	}
	return err;
}

static const struct super_operations aufs_sop = {
	.alloc_inode	= aufs_alloc_inode,
	.destroy_inode	= aufs_destroy_inode,
	/* always deleting, no clearing */
	.drop_inode	= generic_delete_inode,
	.put_super	= aufs_put_super
};

/* ---------------------------------------------------------------------- */

static int alloc_root(struct super_block *sb)
{
	int err;
	struct inode *inode;
	struct dentry *root;

	err = -ENOMEM;
	inode = au_iget_locked(sb, AUFS_ROOT_INO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	inode->i_op = &simple_dir_inode_operations; /* replace later */
	inode->i_fop = &simple_dir_operations; /* replace later */
	inode->i_mode = S_IFDIR;
	set_nlink(inode, 2);
	unlock_new_inode(inode);

	root = d_make_root(inode);
	if (unlikely(!root))
		goto out;
	err = PTR_ERR(root);
	if (IS_ERR(root))
		goto out;

	err = au_di_init(root);
	if (!err) {
		sb->s_root = root;
		return 0; /* success */
	}
	dput(root);

out:
	return err;
}

static int aufs_fill_super(struct super_block *sb, void *raw_data,
			   int silent __maybe_unused)
{
	int err;
	struct au_opts opts = {
		.opt = NULL
	};
	struct dentry *root;
	struct inode *inode;
	char *arg = raw_data;

	if (unlikely(!arg || !*arg)) {
		err = -EINVAL;
		pr_err("no arg\n");
		goto out;
	}

	err = -ENOMEM;
	opts.opt = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!opts.opt))
		goto out;
	opts.max_opt = PAGE_SIZE / sizeof(*opts.opt);
	opts.sb_flags = sb->s_flags;

	err = au_si_alloc(sb);
	if (unlikely(err))
		goto out_opts;

	/* all timestamps always follow the ones on the branch */
	sb->s_flags |= SB_NOATIME | SB_NODIRATIME;
	sb->s_flags |= SB_I_VERSION; /* do we really need this? */
	sb->s_op = &aufs_sop;
	sb->s_d_op = &simple_dentry_operations;  /* replace later */
	sb->s_magic = AUFS_SUPER_MAGIC;
	sb->s_maxbytes = 0;
	sb->s_stack_depth = 1;

	err = alloc_root(sb);
	if (unlikely(err)) {
		si_write_unlock(sb);
		goto out_info;
	}
	root = sb->s_root;
	inode = d_inode(root);

	/*
	 * actually we can parse options regardless aufs lock here.
	 * but at remount time, parsing must be done before aufs lock.
	 * so we follow the same rule.
	 */
	ii_write_lock_parent(inode);
	aufs_write_unlock(root);
	err = au_opts_parse(sb, arg, &opts);
	if (unlikely(err))
		goto out_root;

	/* lock vfs_inode first, then aufs. */
	inode_lock(inode);
	aufs_write_lock(root);
	err = au_opts_mount(sb, &opts);
	au_opts_free(&opts);
	aufs_write_unlock(root);
	inode_unlock(inode);
	if (!err)
		goto out_opts; /* success */

out_root:
	dput(root);
	sb->s_root = NULL;
out_info:
	kobject_put(&au_sbi(sb)->si_kobj);
	sb->s_fs_info = NULL;
out_opts:
	free_page((unsigned long)opts.opt);
out:
	AuTraceErr(err);
	err = cvt_err(err);
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

static struct dentry *aufs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name __maybe_unused,
				 void *raw_data)
{
	struct dentry *root;

	/* all timestamps always follow the ones on the branch */
	/* mnt->mnt_flags |= MNT_NOATIME | MNT_NODIRATIME; */
	root = mount_nodev(fs_type, flags, raw_data, aufs_fill_super);
	if (IS_ERR(root))
		goto out;

	au_sbilist_add(root->d_sb);

out:
	return root;
}

static void aufs_kill_sb(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	sbinfo = au_sbi(sb);
	if (sbinfo) {
		au_sbilist_del(sb);
		aufs_write_lock(sb->s_root);
		if (sbinfo->si_wbr_create_ops->fin)
			sbinfo->si_wbr_create_ops->fin(sb);
		if (au_opt_test(sbinfo->si_mntflags, PLINK))
			au_plink_put(sb, /*verbose*/1);
		au_xino_clr(sb);
		sbinfo->si_sb = NULL;
		aufs_write_unlock(sb->s_root);
		au_nwt_flush(&sbinfo->si_nowait);
	}
	kill_anon_super(sb);
}

struct file_system_type aufs_fs_type = {
	.name		= AUFS_FSTYPE,
	.mount		= aufs_mount,
	.kill_sb	= aufs_kill_sb,
	/* no need to __module_get() and module_put(). */
	.owner		= THIS_MODULE,
};
