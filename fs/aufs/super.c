// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * mount and super_block operations
 */

#include <linux/iversion.h>
#include <linux/seq_file.h>
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

static const struct super_operations aufs_sop = {
	.alloc_inode	= aufs_alloc_inode,
	.destroy_inode	= aufs_destroy_inode,
	/* always deleting, no clearing */
	.drop_inode	= generic_delete_inode,
	.put_super	= aufs_put_super
};
