// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * handling file/dir, and address_space operation
 */

#ifdef CONFIG_AUFS_DEBUG
#include <linux/migrate.h>
#endif
#include <linux/pagemap.h>
#include "aufs.h"

/* drop flags for writing */
unsigned int au_file_roflags(unsigned int flags)
{
	flags &= ~(O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC);
	flags |= O_RDONLY | O_NOATIME;
	return flags;
}

/* common functions to regular file and dir */
struct file *au_h_open(struct dentry *dentry, aufs_bindex_t bindex, int flags,
		       struct file *file)
{
	struct file *h_file;
	struct dentry *h_dentry;
	struct inode *h_inode;
	struct super_block *sb;
	struct au_branch *br;
	struct path h_path;
	int err;

	/* a race condition can happen between open and unlink/rmdir */
	h_file = ERR_PTR(-ENOENT);
	h_dentry = au_h_dptr(dentry, bindex);
	if (au_test_nfsd() && (!h_dentry || d_is_negative(h_dentry)))
		goto out;
	h_inode = d_inode(h_dentry);
	spin_lock(&h_dentry->d_lock);
	err = (!d_unhashed(dentry) && d_unlinked(h_dentry))
		/* || !d_inode(dentry)->i_nlink */
		;
	spin_unlock(&h_dentry->d_lock);
	if (unlikely(err))
		goto out;

	sb = dentry->d_sb;
	br = au_sbr(sb, bindex);
	err = au_br_test_oflag(flags, br);
	h_file = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	/* drop flags for writing */
	if (au_test_ro(sb, bindex, d_inode(dentry)))
		flags = au_file_roflags(flags);
	flags &= ~O_CREAT;
	au_lcnt_inc(&br->br_nfiles);
	h_path.dentry = h_dentry;
	h_path.mnt = au_br_mnt(br);
	h_file = vfsub_dentry_open(&h_path, flags);
	if (IS_ERR(h_file))
		goto out_br;

	if (flags & __FMODE_EXEC) {
		err = deny_write_access(h_file);
		if (unlikely(err)) {
			fput(h_file);
			h_file = ERR_PTR(err);
			goto out_br;
		}
	}
	fsnotify_open(h_file);
	goto out; /* success */

out_br:
	au_lcnt_dec(&br->br_nfiles);
out:
	return h_file;
}

int au_do_open(struct file *file, struct au_do_open_args *args)
{
	int err;
	struct dentry *dentry;
	struct au_finfo *finfo;

	err = au_finfo_init(file, args->fidir);
	if (unlikely(err))
		goto out;

	dentry = file->f_path.dentry;
	di_read_lock_child(dentry, AuLock_IR);
	err = args->open(file, vfsub_file_flags(file));
	di_read_unlock(dentry, AuLock_IR);

	finfo = au_fi(file);
	fi_write_unlock(file);
	if (unlikely(err)) {
		finfo->fi_hdir = NULL;
		au_finfo_fin(file);
	}

out:
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

static int au_file_refresh_by_inode(struct file *file, int *need_reopen)
{
	int err;
	struct au_pin pin;
	struct au_finfo *finfo;
	struct dentry *parent;
	struct inode *inode;
	struct super_block *sb;
	struct au_cp_generic cpg = {
		.dentry	= file->f_path.dentry,
		.bdst	= -1,
		.bsrc	= -1,
		.len	= -1,
		.pin	= &pin,
		.flags	= AuCpup_DTIME
	};

	FiMustWriteLock(file);

	err = 0;
	finfo = au_fi(file);
	sb = cpg.dentry->d_sb;
	inode = d_inode(cpg.dentry);
	cpg.bdst = au_ibtop(inode);
	if (cpg.bdst == finfo->fi_btop || IS_ROOT(cpg.dentry))
		goto out;

	parent = dget_parent(cpg.dentry);
	if (au_test_ro(sb, cpg.bdst, inode)) {
		di_read_lock_parent(parent, !AuLock_IR);
		err = AuWbrCopyup(au_sbi(sb), cpg.dentry);
		cpg.bdst = err;
		di_read_unlock(parent, !AuLock_IR);
		if (unlikely(err < 0))
			goto out_parent;
		err = 0;
	}

	di_read_lock_parent(parent, AuLock_IR);
	if (!S_ISDIR(inode->i_mode)
	    && au_opt_test(au_mntflags(sb), PLINK)
	    && au_plink_test(inode)
	    && !d_unhashed(cpg.dentry)
	    && cpg.bdst < au_dbtop(cpg.dentry)) {
		err = au_test_and_cpup_dirs(cpg.dentry, cpg.bdst);
		if (unlikely(err))
			goto out_unlock;

		/* always superio. */
		err = au_pin(&pin, cpg.dentry, cpg.bdst, AuOpt_UDBA_NONE,
			     AuPin_DI_LOCKED | AuPin_MNT_WRITE);
		if (!err) {
			err = au_sio_cpup_simple(&cpg);
			au_unpin(&pin);
		}
	}

out_unlock:
	di_read_unlock(parent, AuLock_IR);
out_parent:
	dput(parent);
out:
	return err;
}

static void au_do_refresh_dir(struct file *file)
{
	aufs_bindex_t bindex, bbot, new_bindex, brid;
	struct au_hfile *p, tmp, *q;
	struct au_finfo *finfo;
	struct super_block *sb;
	struct au_fidir *fidir;

	FiMustWriteLock(file);

	sb = file->f_path.dentry->d_sb;
	finfo = au_fi(file);
	fidir = finfo->fi_hdir;
	AuDebugOn(!fidir);
	p = fidir->fd_hfile + finfo->fi_btop;
	brid = p->hf_br->br_id;
	bbot = fidir->fd_bbot;
	for (bindex = finfo->fi_btop; bindex <= bbot; bindex++, p++) {
		if (!p->hf_file)
			continue;

		new_bindex = au_br_index(sb, p->hf_br->br_id);
		if (new_bindex == bindex)
			continue;
		if (new_bindex < 0) {
			au_set_h_fptr(file, bindex, NULL);
			continue;
		}

		/* swap two lower inode, and loop again */
		q = fidir->fd_hfile + new_bindex;
		tmp = *q;
		*q = *p;
		*p = tmp;
		if (tmp.hf_file) {
			bindex--;
			p--;
		}
	}

	p = fidir->fd_hfile;
	if (!d_unlinked(file->f_path.dentry)) {
		bbot = au_sbbot(sb);
		for (finfo->fi_btop = 0; finfo->fi_btop <= bbot;
		     finfo->fi_btop++, p++)
			if (p->hf_file) {
				if (file_inode(p->hf_file))
					break;
				au_hfput(p, /*execed*/0);
			}
	} else {
		bbot = au_br_index(sb, brid);
		for (finfo->fi_btop = 0; finfo->fi_btop < bbot;
		     finfo->fi_btop++, p++)
			if (p->hf_file)
				au_hfput(p, /*execed*/0);
		bbot = au_sbbot(sb);
	}

	p = fidir->fd_hfile + bbot;
	for (fidir->fd_bbot = bbot; fidir->fd_bbot >= finfo->fi_btop;
	     fidir->fd_bbot--, p--)
		if (p->hf_file) {
			if (file_inode(p->hf_file))
				break;
			au_hfput(p, /*execed*/0);
		}
	AuDebugOn(fidir->fd_bbot < finfo->fi_btop);
}

/*
 * after branch manipulating, refresh the file.
 */
static int refresh_file(struct file *file, int (*reopen)(struct file *file))
{
	int err, need_reopen, nbr;
	aufs_bindex_t bbot, bindex;
	struct dentry *dentry;
	struct super_block *sb;
	struct au_finfo *finfo;
	struct au_hfile *hfile;

	dentry = file->f_path.dentry;
	sb = dentry->d_sb;
	nbr = au_sbbot(sb) + 1;
	finfo = au_fi(file);
	if (!finfo->fi_hdir) {
		hfile = &finfo->fi_htop;
		AuDebugOn(!hfile->hf_file);
		bindex = au_br_index(sb, hfile->hf_br->br_id);
		AuDebugOn(bindex < 0);
		if (bindex != finfo->fi_btop)
			au_set_fbtop(file, bindex);
	} else {
		err = au_fidir_realloc(finfo, nbr, /*may_shrink*/0);
		if (unlikely(err))
			goto out;
		au_do_refresh_dir(file);
	}

	err = 0;
	need_reopen = 1;
	err = au_file_refresh_by_inode(file, &need_reopen);
	if (finfo->fi_hdir)
		/* harmless if err */
		au_fidir_realloc(finfo, nbr, /*may_shrink*/1);
	if (!err && need_reopen && !d_unlinked(dentry))
		err = reopen(file);
	if (!err) {
		au_update_figen(file);
		goto out; /* success */
	}

	/* error, close all lower files */
	if (finfo->fi_hdir) {
		bbot = au_fbbot_dir(file);
		for (bindex = au_fbtop(file); bindex <= bbot; bindex++)
			au_set_h_fptr(file, bindex, NULL);
	}

out:
	return err;
}

/* common function to regular file and dir */
int au_reval_and_lock_fdi(struct file *file, int (*reopen)(struct file *file),
			  int wlock, unsigned int fi_lsc)
{
	int err;
	unsigned int sigen, figen;
	aufs_bindex_t btop;
	unsigned char pseudo_link;
	struct dentry *dentry;
	struct inode *inode;

	err = 0;
	dentry = file->f_path.dentry;
	inode = d_inode(dentry);
	sigen = au_sigen(dentry->d_sb);
	fi_write_lock_nested(file, fi_lsc);
	figen = au_figen(file);
	if (!fi_lsc)
		di_write_lock_child(dentry);
	else
		di_write_lock_child2(dentry);
	btop = au_dbtop(dentry);
	pseudo_link = (btop != au_ibtop(inode));
	if (sigen == figen && !pseudo_link && au_fbtop(file) == btop) {
		if (!wlock) {
			di_downgrade_lock(dentry, AuLock_IR);
			fi_downgrade_lock(file);
		}
		goto out; /* success */
	}

	AuDbg("sigen %d, figen %d\n", sigen, figen);
	if (au_digen_test(dentry, sigen)) {
		err = au_reval_dpath(dentry, sigen);
		AuDebugOn(!err && au_digen_test(dentry, sigen));
	}

	if (!err)
		err = refresh_file(file, reopen);
	if (!err) {
		if (!wlock) {
			di_downgrade_lock(dentry, AuLock_IR);
			fi_downgrade_lock(file);
		}
	} else {
		di_write_unlock(dentry);
		fi_write_unlock(file);
	}

out:
	return err;
}

/* ---------------------------------------------------------------------- */

/* cf. aufs_nopage() */
/* for madvise(2) */
static int aufs_readpage(struct file *file __maybe_unused, struct page *page)
{
	unlock_page(page);
	return 0;
}

/* it will never be called, but necessary to support O_DIRECT */
static ssize_t aufs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{ BUG(); return 0; }

/* they will never be called. */
#ifdef CONFIG_AUFS_DEBUG
static int aufs_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{ AuUnsupport(); return 0; }
static int aufs_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{ AuUnsupport(); return 0; }
static int aufs_writepage(struct page *page, struct writeback_control *wbc)
{ AuUnsupport(); return 0; }

static int aufs_set_page_dirty(struct page *page)
{ AuUnsupport(); return 0; }
static void aufs_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{ AuUnsupport(); }
static int aufs_releasepage(struct page *page, gfp_t gfp)
{ AuUnsupport(); return 0; }
#if 0 /* called by memory compaction regardless file */
static int aufs_migratepage(struct address_space *mapping, struct page *newpage,
			    struct page *page, enum migrate_mode mode)
{ AuUnsupport(); return 0; }
#endif
static bool aufs_isolate_page(struct page *page, isolate_mode_t mode)
{ AuUnsupport(); return true; }
static void aufs_putback_page(struct page *page)
{ AuUnsupport(); }
static int aufs_launder_page(struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_is_partially_uptodate(struct page *page,
				      unsigned long from,
				      unsigned long count)
{ AuUnsupport(); return 0; }
static void aufs_is_dirty_writeback(struct page *page, bool *dirty,
				    bool *writeback)
{ AuUnsupport(); }
static int aufs_error_remove_page(struct address_space *mapping,
				  struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_swap_activate(struct swap_info_struct *sis, struct file *file,
			      sector_t *span)
{ AuUnsupport(); return 0; }
static void aufs_swap_deactivate(struct file *file)
{ AuUnsupport(); }
#endif /* CONFIG_AUFS_DEBUG */

const struct address_space_operations aufs_aop = {
	.readpage		= aufs_readpage,
	.direct_IO		= aufs_direct_IO,
#ifdef CONFIG_AUFS_DEBUG
	.writepage		= aufs_writepage,
	/* no writepages, because of writepage */
	.set_page_dirty		= aufs_set_page_dirty,
	/* no readpages, because of readpage */
	.write_begin		= aufs_write_begin,
	.write_end		= aufs_write_end,
	/* no bmap, no block device */
	.invalidatepage		= aufs_invalidatepage,
	.releasepage		= aufs_releasepage,
	/* is fallback_migrate_page ok? */
	/* .migratepage		= aufs_migratepage, */
	.isolate_page		= aufs_isolate_page,
	.putback_page		= aufs_putback_page,
	.launder_page		= aufs_launder_page,
	.is_partially_uptodate	= aufs_is_partially_uptodate,
	.is_dirty_writeback	= aufs_is_dirty_writeback,
	.error_remove_page	= aufs_error_remove_page,
	.swap_activate		= aufs_swap_activate,
	.swap_deactivate	= aufs_swap_deactivate
#endif /* CONFIG_AUFS_DEBUG */
};
