// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * inode operations (except add/del/rename)
 */

#include <linux/device_cgroup.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/security.h>
#include "aufs.h"

static int h_permission(struct inode *h_inode, int mask,
			struct path *h_path, int brperm)
{
	int err;
	const unsigned char write_mask = !!(mask & (MAY_WRITE | MAY_APPEND));

	err = -EPERM;
	if (write_mask && IS_IMMUTABLE(h_inode))
		goto out;

	err = -EACCES;
	if (((mask & MAY_EXEC)
	     && S_ISREG(h_inode->i_mode)
	     && (path_noexec(h_path)
		 || !(h_inode->i_mode & 0111))))
		goto out;

	/*
	 * - skip the lower fs test in the case of write to ro branch.
	 * - nfs dir permission write check is optimized, but a policy for
	 *   link/rename requires a real check.
	 */
	if ((write_mask && !au_br_writable(brperm))
	    || (au_test_nfs(h_inode->i_sb) && S_ISDIR(h_inode->i_mode)
		&& write_mask && !(mask & MAY_READ))
	    || !h_inode->i_op->permission) {
		/* AuLabel(generic_permission); */
		err = generic_permission(h_inode, mask);
	} else {
		/* AuLabel(h_inode->permission); */
		err = h_inode->i_op->permission(h_inode, mask);
		AuTraceErr(err);
	}

	if (!err)
		err = devcgroup_inode_permission(h_inode, mask);
	if (!err)
		err = security_inode_permission(h_inode, mask);

#if 0
	if (!err) {
		/* todo: do we need to call ima_path_check()? */
		struct path h_path = {
			.dentry	=
			.mnt	= h_mnt
		};
		err = ima_path_check(&h_path,
				     mask & (MAY_READ | MAY_WRITE | MAY_EXEC),
				     IMA_COUNT_LEAVE);
	}
#endif

out:
	return err;
}

static int aufs_permission(struct inode *inode, int mask)
{
	int err;
	aufs_bindex_t bindex, bbot;
	const unsigned char isdir = !!S_ISDIR(inode->i_mode),
		write_mask = !!(mask & (MAY_WRITE | MAY_APPEND));
	struct inode *h_inode;
	struct super_block *sb;
	struct au_branch *br;

	/* todo: support rcu-walk? */
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	sb = inode->i_sb;
	si_read_lock(sb, AuLock_FLUSH);
	ii_read_lock_child(inode);
#if 0
	err = au_iigen_test(inode, au_sigen(sb));
	if (unlikely(err))
		goto out;
#endif

	if (!isdir
	    || write_mask) {
		err = au_busy_or_stale();
		h_inode = au_h_iptr(inode, au_ibtop(inode));
		if (unlikely(!h_inode
			     || (h_inode->i_mode & S_IFMT)
			     != (inode->i_mode & S_IFMT)))
			goto out;

		err = 0;
		bindex = au_ibtop(inode);
		br = au_sbr(sb, bindex);
		err = h_permission(h_inode, mask, &br->br_path, br->br_perm);
		if (write_mask
		    && !err
		    && !special_file(h_inode->i_mode)) {
			/* test whether the upper writable branch exists */
			err = -EROFS;
			for (; bindex >= 0; bindex--)
				if (!au_br_rdonly(au_sbr(sb, bindex))) {
					err = 0;
					break;
				}
		}
		goto out;
	}

	/* non-write to dir */
	err = 0;
	bbot = au_ibbot(inode);
	for (bindex = au_ibtop(inode); !err && bindex <= bbot; bindex++) {
		h_inode = au_h_iptr(inode, bindex);
		if (h_inode) {
			err = au_busy_or_stale();
			if (unlikely(!S_ISDIR(h_inode->i_mode)))
				break;

			br = au_sbr(sb, bindex);
			err = h_permission(h_inode, mask, &br->br_path,
					   br->br_perm);
		}
	}

out:
	ii_read_unlock(inode);
	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

static struct dentry *aufs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct dentry *ret, *parent;
	struct inode *inode;
	struct super_block *sb;
	int err, npositive;

	IMustLock(dir);

	/* todo: support rcu-walk? */
	ret = ERR_PTR(-ECHILD);
	if (flags & LOOKUP_RCU)
		goto out;

	ret = ERR_PTR(-ENAMETOOLONG);
	if (unlikely(dentry->d_name.len > AUFS_MAX_NAMELEN))
		goto out;

	sb = dir->i_sb;
	err = si_read_lock(sb, AuLock_FLUSH | AuLock_NOPLM);
	ret = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	err = au_di_init(dentry);
	ret = ERR_PTR(err);
	if (unlikely(err))
		goto out_si;

	inode = NULL;
	npositive = 0; /* suppress a warning */
	parent = dentry->d_parent; /* dir inode is locked */
	di_read_lock_parent(parent, AuLock_IR);
	err = au_alive_dir(parent);
	if (!err)
		err = au_digen_test(parent, au_sigen(sb));
	if (!err) {
		/* regardless LOOKUP_CREATE, always ALLOW_NEG */
		npositive = au_lkup_dentry(dentry, au_dbtop(parent),
					   AuLkup_ALLOW_NEG);
		err = npositive;
	}
	di_read_unlock(parent, AuLock_IR);
	ret = ERR_PTR(err);
	if (unlikely(err < 0))
		goto out_unlock;

	if (npositive) {
		inode = au_new_inode(dentry, /*must_new*/0);
		if (IS_ERR(inode)) {
			ret = (void *)inode;
			inode = NULL;
			goto out_unlock;
		}
	}

	if (inode)
		atomic_inc(&inode->i_count);
	ret = d_splice_alias(inode, dentry);
#if 0
	if (unlikely(d_need_lookup(dentry))) {
		spin_lock(&dentry->d_lock);
		dentry->d_flags &= ~DCACHE_NEED_LOOKUP;
		spin_unlock(&dentry->d_lock);
	} else
#endif
	if (inode) {
		if (!IS_ERR(ret)) {
			iput(inode);
			if (ret && ret != dentry)
				ii_write_unlock(inode);
		} else {
			ii_write_unlock(inode);
			iput(inode);
			inode = NULL;
		}
	}

out_unlock:
	di_write_unlock(dentry);
out_si:
	si_read_unlock(sb);
out:
	return ret;
}

/* ---------------------------------------------------------------------- */

void au_pin_hdir_unlock(struct au_pin *p)
{
	if (p->hdir)
		au_hn_inode_unlock(p->hdir);
}

int au_pin_hdir_lock(struct au_pin *p)
{
	int err;

	err = 0;
	if (!p->hdir)
		goto out;

	/* even if an error happens later, keep this lock */
	au_hn_inode_lock_nested(p->hdir, p->lsc_hi);

	err = -EBUSY;
	if (unlikely(p->hdir->hi_inode != d_inode(p->h_parent)))
		goto out;

	err = 0;
	if (p->h_dentry)
		err = au_h_verify(p->h_dentry, p->udba, p->hdir->hi_inode,
				  p->h_parent, p->br);

out:
	return err;
}

int au_pin_hdir_relock(struct au_pin *p)
{
	int err, i;
	struct inode *h_i;
	struct dentry *h_d[] = {
		p->h_dentry,
		p->h_parent
	};

	err = au_pin_hdir_lock(p);
	if (unlikely(err))
		goto out;

	for (i = 0; !err && i < sizeof(h_d)/sizeof(*h_d); i++) {
		if (!h_d[i])
			continue;
		if (d_is_positive(h_d[i])) {
			h_i = d_inode(h_d[i]);
			err = !h_i->i_nlink;
		}
	}

out:
	return err;
}

static void au_pin_hdir_set_owner(struct au_pin *p, struct task_struct *task)
{
#if !defined(CONFIG_RWSEM_GENERIC_SPINLOCK) && defined(CONFIG_RWSEM_SPIN_ON_OWNER)
	p->hdir->hi_inode->i_rwsem.owner = task;
#endif
}

void au_pin_hdir_acquire_nest(struct au_pin *p)
{
	if (p->hdir) {
		rwsem_acquire_nest(&p->hdir->hi_inode->i_rwsem.dep_map,
				   p->lsc_hi, 0, NULL, _RET_IP_);
		au_pin_hdir_set_owner(p, current);
	}
}

void au_pin_hdir_release(struct au_pin *p)
{
	if (p->hdir) {
		au_pin_hdir_set_owner(p, p->task);
		rwsem_release(&p->hdir->hi_inode->i_rwsem.dep_map, 1, _RET_IP_);
	}
}

struct dentry *au_pinned_h_parent(struct au_pin *pin)
{
	if (pin && pin->parent)
		return au_h_dptr(pin->parent, pin->bindex);
	return NULL;
}

void au_unpin(struct au_pin *p)
{
	if (p->hdir)
		au_pin_hdir_unlock(p);
	if (p->h_mnt && au_ftest_pin(p->flags, MNT_WRITE))
		vfsub_mnt_drop_write(p->h_mnt);
	if (!p->hdir)
		return;

	if (!au_ftest_pin(p->flags, DI_LOCKED))
		di_read_unlock(p->parent, AuLock_IR);
	iput(p->hdir->hi_inode);
	dput(p->parent);
	p->parent = NULL;
	p->hdir = NULL;
	p->h_mnt = NULL;
	/* do not clear p->task */
}

int au_do_pin(struct au_pin *p)
{
	int err;
	struct super_block *sb;
	struct inode *h_dir;

	err = 0;
	sb = p->dentry->d_sb;
	p->br = au_sbr(sb, p->bindex);
	if (IS_ROOT(p->dentry)) {
		if (au_ftest_pin(p->flags, MNT_WRITE)) {
			p->h_mnt = au_br_mnt(p->br);
			err = vfsub_mnt_want_write(p->h_mnt);
			if (unlikely(err)) {
				au_fclr_pin(p->flags, MNT_WRITE);
				goto out_err;
			}
		}
		goto out;
	}

	p->h_dentry = NULL;
	if (p->bindex <= au_dbbot(p->dentry))
		p->h_dentry = au_h_dptr(p->dentry, p->bindex);

	p->parent = dget_parent(p->dentry);
	if (!au_ftest_pin(p->flags, DI_LOCKED))
		di_read_lock(p->parent, AuLock_IR, p->lsc_di);

	h_dir = NULL;
	p->h_parent = au_h_dptr(p->parent, p->bindex);
	p->hdir = au_hi(d_inode(p->parent), p->bindex);
	if (p->hdir)
		h_dir = p->hdir->hi_inode;

	/*
	 * udba case, or
	 * if DI_LOCKED is not set, then p->parent may be different
	 * and h_parent can be NULL.
	 */
	if (unlikely(!p->hdir || !h_dir || !p->h_parent)) {
		err = -EBUSY;
		if (!au_ftest_pin(p->flags, DI_LOCKED))
			di_read_unlock(p->parent, AuLock_IR);
		dput(p->parent);
		p->parent = NULL;
		goto out_err;
	}

	if (au_ftest_pin(p->flags, MNT_WRITE)) {
		p->h_mnt = au_br_mnt(p->br);
		err = vfsub_mnt_want_write(p->h_mnt);
		if (unlikely(err)) {
			au_fclr_pin(p->flags, MNT_WRITE);
			if (!au_ftest_pin(p->flags, DI_LOCKED))
				di_read_unlock(p->parent, AuLock_IR);
			dput(p->parent);
			p->parent = NULL;
			goto out_err;
		}
	}

	au_igrab(h_dir);
	err = au_pin_hdir_lock(p);
	if (!err)
		goto out; /* success */

	au_unpin(p);

out_err:
	pr_err("err %d\n", err);
	err = au_busy_or_stale();
out:
	return err;
}

void au_pin_init(struct au_pin *p, struct dentry *dentry,
		 aufs_bindex_t bindex, int lsc_di, int lsc_hi,
		 unsigned int udba, unsigned char flags)
{
	p->dentry = dentry;
	p->udba = udba;
	p->lsc_di = lsc_di;
	p->lsc_hi = lsc_hi;
	p->flags = flags;
	p->bindex = bindex;

	p->parent = NULL;
	p->hdir = NULL;
	p->h_mnt = NULL;

	p->h_dentry = NULL;
	p->h_parent = NULL;
	p->br = NULL;
	p->task = current;
}

int au_pin(struct au_pin *pin, struct dentry *dentry, aufs_bindex_t bindex,
	   unsigned int udba, unsigned char flags)
{
	au_pin_init(pin, dentry, bindex, AuLsc_DI_PARENT, AuLsc_I_PARENT2,
		    udba, flags);
	return au_do_pin(pin);
}

/* ---------------------------------------------------------------------- */

static const char *aufs_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *done)
{
	const char *ret;
	struct dentry *h_dentry;
	struct inode *h_inode;
	int err;
	aufs_bindex_t bindex;

	ret = NULL; /* suppress a warning */
	err = -ECHILD;
	if (!dentry)
		goto out;

	err = aufs_read_lock(dentry, AuLock_IR | AuLock_GEN);
	if (unlikely(err))
		goto out;

	err = au_d_hashed_positive(dentry);
	if (unlikely(err))
		goto out_unlock;

	err = -EINVAL;
	inode = d_inode(dentry);
	bindex = au_ibtop(inode);
	h_inode = au_h_iptr(inode, bindex);
	if (unlikely(!h_inode->i_op->get_link))
		goto out_unlock;

	err = -EBUSY;
	h_dentry = NULL;
	if (au_dbtop(dentry) <= bindex) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry)
			dget(h_dentry);
	}
	if (!h_dentry) {
		h_dentry = d_find_any_alias(h_inode);
		if (IS_ERR(h_dentry)) {
			err = PTR_ERR(h_dentry);
			goto out_unlock;
		}
	}
	if (unlikely(!h_dentry))
		goto out_unlock;

	err = 0;
	AuDbg("%ps\n", h_inode->i_op->get_link);
	AuDbgDentry(h_dentry);
	ret = vfs_get_link(h_dentry, done);
	dput(h_dentry);
	if (IS_ERR(ret))
		err = PTR_ERR(ret);

out_unlock:
	aufs_read_unlock(dentry, AuLock_IR);
out:
	if (unlikely(err))
		ret = ERR_PTR(err);
	AuTraceErrPtr(ret);
	return ret;
}

/* ---------------------------------------------------------------------- */

struct inode_operations aufs_iop[] = {
	[AuIop_SYMLINK] = {
		.permission	= aufs_permission,

		.get_link	= aufs_get_link
	},
	[AuIop_DIR] = {
		.lookup		= aufs_lookup,

		.permission	= aufs_permission
	},
	[AuIop_OTHER] = {
		.permission	= aufs_permission
	}
};
