#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/parser.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/uidgid.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/uio.h>

struct remapfs_super_info {
	struct vfsmount *mnt;
	const struct cred *creator_cred;
	bool map;
	struct uid_gid_map uid_map, gid_map;
};

struct remapfs_file_info {
	struct path realpath;
	struct file *realfile;
};

struct kmem_cache *remapfs_file_info_cache;

static void remapfs_fill_inode(struct inode *inode, unsigned long ino,
			       umode_t mode, dev_t dev, struct dentry *dentry);

enum {
	OPT_UIDMAP,
	OPT_GIDMAP,
	OPT_LAST,
};

/* global filesystem options */
static const match_table_t tokens = {
	{ OPT_UIDMAP, "uidmap=%u:%u:%u" },
	{ OPT_GIDMAP, "gidmap=%u:%u:%u" },
	{ OPT_LAST, NULL }
};

/*
 * code stolen from user_namespace.c ... except that these functions
 * return the same id back if unmapped ... should probably have a
 * library?
 */
static u32 map_id_down(struct uid_gid_map *map, u32 id)
{
	unsigned idx, extents;
	u32 first = 0, last = 0;

	pr_debug("map_id_down called with %d\n", id);
	/* Find the matching extent */
	extents = map->nr_extents;
	pr_debug("map_id_down got %d extents\n", extents);
	smp_rmb();
	for (idx = 0; idx < extents; idx++) {
		pr_debug("map->extent[idx].first %d\n", map->extent[idx].first);
		pr_debug("map->extent[idx].lower_first %d\n", map->extent[idx].lower_first);
		pr_debug("map->extent[idx].count %d\n", map->extent[idx].count);
		first = map->extent[idx].first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			break;
	}
	/* Map the id or note failure */
	pr_debug("map_id_down idx %d\n", idx);
	if (idx < extents)
		 id = (id - first) + map->extent[idx].lower_first;

	pr_debug("map_id_down returning with %d\n", id);
	return id;
}

static u32 map_id_up(struct uid_gid_map *map, u32 id)
{
	unsigned idx, extents;
	u32 first = 0, last = 0;

	pr_debug("map_id_up called with %d\n", id);
	/* Find the matching extent */
	extents = map->nr_extents;
	pr_debug("map_id_up got %d extents\n", extents);
	smp_rmb();
	for (idx = 0; idx < extents; idx++) {
		pr_debug("map->extent[idx].first %d\n", map->extent[idx].first);
		pr_debug("map->extent[idx].lower_first %d\n", map->extent[idx].lower_first);
		pr_debug("map->extent[idx].count %d\n", map->extent[idx].count);
		first = map->extent[idx].lower_first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			break;
	}
	/* Map the id or note failure */
	pr_debug("map_id_up idx %d\n", idx);
	if (idx < extents)
		 id = (id - first) + map->extent[idx].first;

	pr_debug("map_id_up returning with %d\n", id);
	return id;
}

static bool mappings_overlap(struct uid_gid_map *new_map,
				struct uid_gid_extent *extent)
{
	u32 upper_first, lower_first, upper_last, lower_last;
	unsigned idx;

	upper_first = extent->first;
	lower_first = extent->lower_first;
	upper_last = upper_first + extent->count - 1;
	lower_last = lower_first + extent->count - 1;

	for (idx = 0; idx < new_map->nr_extents; idx++) {
		 u32 prev_upper_first, prev_lower_first;
		 u32 prev_upper_last, prev_lower_last;
		 struct uid_gid_extent *prev;

		 prev = &new_map->extent[idx];

		 prev_upper_first = prev->first;
		 prev_lower_first = prev->lower_first;
		 prev_upper_last = prev_upper_first + prev->count - 1;
		 prev_lower_last = prev_lower_first + prev->count - 1;

		 /* Does the upper range intersect a previous extent? */
		 if ((prev_upper_first <= upper_last) &&
		     (prev_upper_last >= upper_first))
			  return true;

		 /* Does the lower range intersect a previous extent? */
		 if ((prev_lower_first <= lower_last) &&
		     (prev_lower_last >= lower_first))
			  return true;
	}
	return false;
}
/* end code stolen from user_namespace.c */


static const struct cred *remapfs_override_creds(const struct super_block *sb)
{
	struct remapfs_super_info *sbinfo = sb->s_fs_info;

	return override_creds(sbinfo->creator_cred);
}

static inline void remapfs_revert_object_creds(const struct cred *oldcred,
					       struct cred *newcred)
{
	revert_creds(oldcred);
	put_cred(newcred);
}

static int remapfs_override_object_creds(const struct super_block *sb,
					 const struct cred **oldcred,
					 struct cred **newcred,
					 struct dentry *dentry, umode_t mode,
					 bool hardlink)
{
	struct remapfs_super_info *ssi = sb->s_fs_info;
	kuid_t fsuid = current_fsuid();
	kgid_t fsgid = current_fsgid();

	*oldcred = remapfs_override_creds(sb);

	*newcred = prepare_creds();
	if (!*newcred) {
		revert_creds(*oldcred);
		return -ENOMEM;
	}

	(*newcred)->fsuid = KUIDT_INIT(map_id_down(&ssi->uid_map,
				    __kuid_val(fsuid)));
	(*newcred)->fsgid = KGIDT_INIT(map_id_down(&ssi->gid_map,
				    __kgid_val(fsgid)));
	pr_debug("remapfs: %s mapping to uid %d gid %d\n", __FUNCTION__,
					__kuid_val((*newcred)->fsuid),
					__kgid_val((*newcred)->fsgid));

	if (!hardlink) {
		int err = security_dentry_create_files_as(dentry, mode,
							  &dentry->d_name,
							  *oldcred, *newcred);
		if (err) {
			pr_debug("security_dentry_create_files_as failed\n");
			remapfs_revert_object_creds(*oldcred, *newcred);
			return err;
		}
	}

	put_cred(override_creds(*newcred));
	pr_debug("remapfs: %s final newcred uid %d gid %d\n", __FUNCTION__,
					__kuid_val((*newcred)->fsuid),
					__kgid_val((*newcred)->fsgid));
	return 0;
}

static void remapfs_copyattr(struct inode *from, struct inode *to)
{

	struct remapfs_super_info *sbinfo = to->i_sb->s_fs_info;

	if (to->i_sb->s_magic != REMAPFS_MAGIC) {
		BUG();
		return;
	};

	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "called");
	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "mapping");
	to->i_uid = KUIDT_INIT(map_id_up(&sbinfo->uid_map,
					   __kuid_val(from->i_uid)));
	to->i_gid = KGIDT_INIT(map_id_up(&sbinfo->gid_map,
					   __kgid_val(from->i_gid)));
	to->i_mode = from->i_mode;
	to->i_atime = from->i_atime;
	to->i_mtime = from->i_mtime;
	to->i_ctime = from->i_ctime;
	i_size_write(to, i_size_read(from));
	pr_debug("remapfs: %s final to->i_uid %d to->i_gid %d\n", __FUNCTION__,
					__kuid_val(to->i_uid),
					__kgid_val(to->i_gid));
}

static void remapfs_copyflags(struct inode *from, struct inode *to)
{
	unsigned int mask = S_SYNC | S_IMMUTABLE | S_APPEND | S_NOATIME;

	inode_set_flags(to, from->i_flags & mask, mask);
}

static void remapfs_file_accessed(struct file *file)
{
	struct inode *upperi, *loweri;

	if (file->f_flags & O_NOATIME)
		return;

	upperi = file_inode(file);
	loweri = upperi->i_private;

	if (!loweri)
		return;

	upperi->i_mtime = loweri->i_mtime;
	upperi->i_ctime = loweri->i_ctime;

	touch_atime(&file->f_path);
}

static int remapfs_parse_mount_options(struct remapfs_super_info *sbinfo,
				       char *options)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	struct uid_gid_map *map, *maps[2] = {
		[OPT_UIDMAP] = &sbinfo->uid_map,
		[OPT_GIDMAP] = &sbinfo->gid_map,
	};

	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "called");
	while ((p = strsep(&options, ",")) != NULL) {
		int token, from, to, count;
		struct uid_gid_extent ext;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_UIDMAP:
			/* fall through */
		case OPT_GIDMAP:
			pr_debug("%s\n", (token == OPT_UIDMAP) ? "OPT_UIDMAP"
								: "OPT_GIDMAP");
			sbinfo->map = true;
			if (match_int(&args[0], &from) ||
			    match_int(&args[1], &to) ||
			    match_int(&args[2], &count))
				return -EINVAL;
			map = maps[token];
			if (map->nr_extents >= UID_GID_MAP_MAX_EXTENTS)
				return -EINVAL;
			ext.first = to;
			ext.lower_first = from;
			ext.count = count;
			if (mappings_overlap(map, &ext))
				return -EINVAL;
			map->extent[map->nr_extents++] = ext;
			pr_debug("from %d, to %d, count %d\n", from, to, count);
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void remapfs_d_release(struct dentry *dentry)
{
	struct dentry *lowerd = dentry->d_fsdata;

	if (lowerd)
		dput(lowerd);
}

static struct dentry *remapfs_d_real(struct dentry *dentry,
				     const struct inode *inode)
{
	struct dentry *lowerd = dentry->d_fsdata;

	if (inode && d_inode(dentry) == inode)
		return dentry;

	lowerd = d_real(lowerd, inode);
	if (lowerd && (!inode || inode == d_inode(lowerd)))
		return lowerd;

	WARN(1, "remapfs_d_real(%pd4, %s:%lu): real dentry not found\n", dentry,
	     inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);
	return dentry;
}

static int remapfs_d_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	int err = 1;
	struct dentry *lowerd = dentry->d_fsdata;

	if (d_is_negative(lowerd) != d_is_negative(dentry))
		return 0;

	if ((lowerd->d_flags & DCACHE_OP_WEAK_REVALIDATE))
		err = lowerd->d_op->d_weak_revalidate(lowerd, flags);

	if (d_really_is_positive(dentry)) {
		struct inode *inode = d_inode(dentry);
		struct inode *loweri = d_inode(lowerd);

		remapfs_copyattr(loweri, inode);
		if (!inode->i_nlink)
			err = 0;
	}

	return err;
}

static int remapfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	int err = 1;
	struct dentry *lowerd = dentry->d_fsdata;

	if (d_unhashed(lowerd) ||
	    ((d_is_negative(lowerd) != d_is_negative(dentry))))
		return 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if ((lowerd->d_flags & DCACHE_OP_REVALIDATE))
		err = lowerd->d_op->d_revalidate(lowerd, flags);

	if (d_really_is_positive(dentry)) {
		struct inode *inode = d_inode(dentry);
		struct inode *loweri = d_inode(lowerd);

		remapfs_copyattr(loweri, inode);
		if (!inode->i_nlink)
			err = 0;
	}

	return err;
}

static const struct dentry_operations remapfs_dentry_ops = {
	.d_release	   = remapfs_d_release,
	.d_real		   = remapfs_d_real,
	.d_revalidate	   = remapfs_d_revalidate,
	.d_weak_revalidate = remapfs_d_weak_revalidate,
};

static const char *remapfs_get_link(struct dentry *dentry, struct inode *inode,
				    struct delayed_call *done)
{
	const char *p;
	const struct cred *oldcred;
	struct dentry *lowerd;

	/* RCU lookup not supported */
	if (!dentry)
		return ERR_PTR(-ECHILD);

	lowerd = dentry->d_fsdata;
	oldcred = remapfs_override_creds(dentry->d_sb);
	p = vfs_get_link(lowerd, done);
	revert_creds(oldcred);

	return p;
}

static int remapfs_setxattr(struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value,
			    size_t size, int flags)
{
	struct dentry *lowerd = dentry->d_fsdata;
	int err;
	const struct cred *oldcred;

	oldcred = remapfs_override_creds(dentry->d_sb);
	err = vfs_setxattr(lowerd, name, value, size, flags);
	revert_creds(oldcred);

	remapfs_copyattr(lowerd->d_inode, inode);

	return err;
}

static int remapfs_xattr_get(const struct xattr_handler *handler,
			     struct dentry *dentry, struct inode *inode,
			     const char *name, void *value, size_t size)
{
	struct dentry *lowerd = dentry->d_fsdata;
	int err;
	const struct cred *oldcred;

	oldcred = remapfs_override_creds(dentry->d_sb);
	err = vfs_getxattr(lowerd, name, value, size);
	revert_creds(oldcred);

	return err;
}

static ssize_t remapfs_listxattr(struct dentry *dentry, char *list,
				 size_t size)
{
	struct dentry *lowerd = dentry->d_fsdata;
	int err;
	const struct cred *oldcred;

	oldcred = remapfs_override_creds(dentry->d_sb);
	err = vfs_listxattr(lowerd, list, size);
	revert_creds(oldcred);

	return err;
}

static int remapfs_removexattr(struct dentry *dentry, const char *name)
{
	struct dentry *lowerd = dentry->d_fsdata;
	int err;
	const struct cred *oldcred;

	oldcred = remapfs_override_creds(dentry->d_sb);
	err = vfs_removexattr(lowerd, name);
	revert_creds(oldcred);

	/* update c/mtime */
	remapfs_copyattr(lowerd->d_inode, d_inode(dentry));

	return err;
}

static int remapfs_xattr_set(const struct xattr_handler *handler,
			     struct dentry *dentry, struct inode *inode,
			     const char *name, const void *value, size_t size,
			     int flags)
{
	if (!value)
		return remapfs_removexattr(dentry, name);
	return remapfs_setxattr(dentry, inode, name, value, size, flags);
}

static int remapfs_inode_test(struct inode *inode, void *data)
{
	return inode->i_private == data;
}

static int remapfs_inode_set(struct inode *inode, void *data)
{
	inode->i_private = data;
	return 0;
}

static int remapfs_create_object(struct inode *diri, struct dentry *dentry,
				 umode_t mode, const char *symlink,
				 struct dentry *hardlink, bool excl)
{
	int err;
	const struct cred *oldcred;
	struct cred *newcred;
	void *loweri_iop_ptr = NULL;
	umode_t modei = mode;
	struct super_block *dir_sb = diri->i_sb;
	struct dentry *lowerd_new = dentry->d_fsdata;
	struct inode *inode = NULL, *loweri_dir = diri->i_private;
	const struct inode_operations *loweri_dir_iop = loweri_dir->i_op;
	struct dentry *lowerd_link = NULL;

	if (hardlink) {
		loweri_iop_ptr = loweri_dir_iop->link;
	} else {
		switch (mode & S_IFMT) {
		case S_IFDIR:
			loweri_iop_ptr = loweri_dir_iop->mkdir;
			break;
		case S_IFREG:
			loweri_iop_ptr = loweri_dir_iop->create;
			break;
		case S_IFLNK:
			loweri_iop_ptr = loweri_dir_iop->symlink;
			break;
		case S_IFSOCK:
			/* fall through */
		case S_IFIFO:
			loweri_iop_ptr = loweri_dir_iop->mknod;
			break;
		}
	}
	if (!loweri_iop_ptr) {
		err = -EINVAL;
		goto out_iput;
	}

	inode_lock_nested(loweri_dir, I_MUTEX_PARENT);

	if (!hardlink) {
		inode = new_inode(dir_sb);
		if (!inode) {
			err = -ENOMEM;
			goto out_iput;
		}

		/*
		 * new_inode() will have added the new inode to the super
		 * block's list of inodes. Further below we will call
		 * inode_insert5() Which would perform the same operation again
		 * thereby corrupting the list. To avoid this raise I_CREATING
		 * in i_state which will cause inode_insert5() to skip this
		 * step. I_CREATING will be cleared by d_instantiate_new()
		 * below.
		 */
		spin_lock(&inode->i_lock);
		inode->i_state |= I_CREATING;
		spin_unlock(&inode->i_lock);

		inode_init_owner(inode, diri, mode);
		modei = inode->i_mode;
	}

	err = remapfs_override_object_creds(dentry->d_sb, &oldcred, &newcred,
					    dentry, modei, hardlink != NULL);
	if (err)
		goto out_iput;

	if (hardlink) {
		lowerd_link = hardlink->d_fsdata;
		err = vfs_link(lowerd_link, loweri_dir, lowerd_new, NULL);
	} else {
		switch (modei & S_IFMT) {
		case S_IFDIR:
			err = vfs_mkdir(loweri_dir, lowerd_new, modei);
			break;
		case S_IFREG:
			err = vfs_create(loweri_dir, lowerd_new, modei, excl);
			break;
		case S_IFLNK:
			err = vfs_symlink(loweri_dir, lowerd_new, symlink);
			break;
		case S_IFSOCK:
			/* fall through */
		case S_IFIFO:
			err = vfs_mknod(loweri_dir, lowerd_new, modei, 0);
			break;
		default:
			err = -EINVAL;
			break;
		}
	}

	remapfs_revert_object_creds(oldcred, newcred);

	if (!err && WARN_ON(!lowerd_new->d_inode))
		err = -EIO;
	if (err)
		goto out_iput;

	if (hardlink) {
		inode = d_inode(hardlink);
		ihold(inode);

		/* copy up times from lower inode */
		remapfs_copyattr(d_inode(lowerd_link), inode);
		set_nlink(d_inode(hardlink), d_inode(lowerd_link)->i_nlink);
		d_instantiate(dentry, inode);
	} else {
		struct inode *inode_tmp;
		struct inode *loweri_new = d_inode(lowerd_new);

		inode_tmp = inode_insert5(inode, (unsigned long)loweri_new,
					  remapfs_inode_test, remapfs_inode_set,
					  loweri_new);
		if (unlikely(inode_tmp != inode)) {
			pr_err_ratelimited("remapfs: newly created inode found in cache\n");
			iput(inode_tmp);
			err = -EINVAL;
			goto out_iput;
		}

		ihold(loweri_new);
		remapfs_fill_inode(inode, loweri_new->i_ino, loweri_new->i_mode,
				   0, lowerd_new);
		d_instantiate_new(dentry, inode);
	}

	remapfs_copyattr(loweri_dir, diri);
	if (loweri_iop_ptr == loweri_dir_iop->mkdir)
		set_nlink(diri, loweri_dir->i_nlink);

	inode = NULL;

out_iput:
	iput(inode);
	inode_unlock(loweri_dir);

	return err;
}

static int remapfs_create(struct inode *dir, struct dentry *dentry,
			  umode_t mode,  bool excl)
{
	mode |= S_IFREG;

	return remapfs_create_object(dir, dentry, mode, NULL, NULL, excl);
}

static int remapfs_mkdir(struct inode *dir, struct dentry *dentry,
			 umode_t mode)
{
	mode |= S_IFDIR;

	return remapfs_create_object(dir, dentry, mode, NULL, NULL, false);
}

static int remapfs_link(struct dentry *hardlink, struct inode *dir,
			struct dentry *dentry)
{
	return remapfs_create_object(dir, dentry, 0, NULL, hardlink, false);
}

static int remapfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			 dev_t rdev)
{
	if (!S_ISFIFO(mode) && !S_ISSOCK(mode))
		return -EPERM;

	return remapfs_create_object(dir, dentry, mode, NULL, NULL, false);
}

static int remapfs_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symlink)
{
	return remapfs_create_object(dir, dentry, S_IFLNK, symlink, NULL, false);
}

static int remapfs_rm(struct inode *dir, struct dentry *dentry, bool rmdir)
{
	struct dentry *lowerd = dentry->d_fsdata;
	struct inode *loweri = dir->i_private;
	int err;
	const struct cred *oldcred;

	oldcred = remapfs_override_creds(dentry->d_sb);
	inode_lock_nested(loweri, I_MUTEX_PARENT);
	if (rmdir)
		err = vfs_rmdir(loweri, lowerd);
	else
		err = vfs_unlink(loweri, lowerd, NULL);
	inode_unlock(loweri);
	revert_creds(oldcred);

	remapfs_copyattr(loweri, dir);
	set_nlink(d_inode(dentry), loweri->i_nlink);
	if (!err)
		d_drop(dentry);

	set_nlink(dir, loweri->i_nlink);

	return err;
}

static int remapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return remapfs_rm(dir, dentry, false);
}

static int remapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	return remapfs_rm(dir, dentry, true);
}

static int remapfs_rename(struct inode *olddir, struct dentry *old,
			  struct inode *newdir, struct dentry *new,
			  unsigned int flags)
{
	struct dentry *lowerd_dir_old = old->d_parent->d_fsdata,
		      *lowerd_dir_new = new->d_parent->d_fsdata,
		      *lowerd_old = old->d_fsdata, *lowerd_new = new->d_fsdata,
		      *trapd;
	struct inode *loweri_dir_old = lowerd_dir_old->d_inode,
		     *loweri_dir_new = lowerd_dir_new->d_inode;
	int err = -EINVAL;
	const struct cred *oldcred;

	trapd = lock_rename(lowerd_dir_new, lowerd_dir_old);

	if (trapd == lowerd_old || trapd == lowerd_new)
		goto out_unlock;

	oldcred = remapfs_override_creds(old->d_sb);
	err = vfs_rename(loweri_dir_old, lowerd_old, loweri_dir_new, lowerd_new,
			 NULL, flags);
	revert_creds(oldcred);

	remapfs_copyattr(loweri_dir_old, olddir);
	remapfs_copyattr(loweri_dir_new, newdir);

out_unlock:
	unlock_rename(lowerd_dir_new, lowerd_dir_old);

	return err;
}

static struct dentry *remapfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct dentry *new;
	struct inode *newi;
	const struct cred *oldcred;
	struct dentry *lowerd = dentry->d_parent->d_fsdata;
	struct inode *inode = NULL, *loweri = lowerd->d_inode;

	inode_lock(loweri);
	oldcred = remapfs_override_creds(dentry->d_sb);
	new = lookup_one_len(dentry->d_name.name, lowerd, dentry->d_name.len);
	revert_creds(oldcred);
	inode_unlock(loweri);

	if (IS_ERR(new))
		return new;

	dentry->d_fsdata = new;

	newi = new->d_inode;
	if (!newi)
		goto out;

	inode = iget5_locked(dentry->d_sb, (unsigned long)newi,
			     remapfs_inode_test, remapfs_inode_set, newi);
	if (!inode) {
		dput(new);
		return ERR_PTR(-ENOMEM);
	}
	if (inode->i_state & I_NEW) {
		/*
		 * inode->i_private set by remapfs_inode_set(), but we still
		 * need to take a reference
		*/
		ihold(newi);
		remapfs_fill_inode(inode, newi->i_ino, newi->i_mode, 0, new);
		unlock_new_inode(inode);
	}

out:
	return d_splice_alias(inode, dentry);
}

static int remapfs_permission(struct inode *inode, int mask)
{
	int err;
	const struct cred *oldcred;
	struct inode *loweri = inode->i_private;

	if (!loweri) {
		WARN_ON(!(mask & MAY_NOT_BLOCK));
		return -ECHILD;
	}

	err = generic_permission(inode, mask);
	if (err)
		return err;

	oldcred = remapfs_override_creds(inode->i_sb);
	err = inode_permission(loweri, mask);
	revert_creds(oldcred);

	return err;
}

static int remapfs_fiemap(struct inode *inode,
			  struct fiemap_extent_info *fieinfo, u64 start,
			  u64 len)
{
	int err;
	const struct cred *oldcred;
	struct inode *loweri = inode->i_private;

	if (!loweri->i_op->fiemap)
		return -EOPNOTSUPP;

	oldcred = remapfs_override_creds(inode->i_sb);
	if (fieinfo->fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(loweri->i_mapping);
	err = loweri->i_op->fiemap(loweri, fieinfo, start, len);
	revert_creds(oldcred);

	return err;
}

static int remapfs_tmpfile(struct inode *dir, struct dentry *dentry,
			   umode_t mode)
{
	int err;
	const struct cred *oldcred;
	struct dentry *lowerd = dentry->d_fsdata;
	struct inode *loweri = dir->i_private;

	if (!loweri->i_op->tmpfile)
		return -EOPNOTSUPP;

	oldcred = remapfs_override_creds(dir->i_sb);
	err = loweri->i_op->tmpfile(loweri, lowerd, mode);
	revert_creds(oldcred);

	return err;
}

static int remapfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct dentry *lowerd = dentry->d_fsdata;
	struct inode *loweri = lowerd->d_inode;
	struct iattr newattr;
	const struct cred *oldcred;
	struct super_block *sb = dentry->d_sb;
	struct remapfs_super_info *ssi = sb->s_fs_info;
	int err;

	err = setattr_prepare(dentry, attr);
	if (err)
		return err;

	newattr = *attr;
	newattr.ia_uid = KUIDT_INIT(map_id_down(&ssi->uid_map,
				    __kuid_val(attr->ia_uid)));
	newattr.ia_gid = KGIDT_INIT(map_id_down(&ssi->gid_map,
				    __kgid_val(attr->ia_gid)));
	pr_debug("remapfs: %s mapping uid %d gid %d\n", __FUNCTION__,
					__kuid_val(newattr.ia_uid),
					__kgid_val(newattr.ia_gid));

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (newattr.ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID))
		newattr.ia_valid &= ~ATTR_MODE;

	inode_lock(loweri);
	oldcred = remapfs_override_creds(dentry->d_sb);
	err = notify_change(lowerd, &newattr, NULL);
	revert_creds(oldcred);
	inode_unlock(loweri);

	remapfs_copyattr(loweri, d_inode(dentry));

	return err;
}

static int remapfs_getattr(const struct path *path, struct kstat *stat,
			   u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;
	struct dentry *lowerd = path->dentry->d_fsdata;
	struct remapfs_super_info *info = path->dentry->d_sb->s_fs_info;
	struct path newpath = { .mnt = info->mnt, .dentry = lowerd };
	const struct cred *oldcred;
	int err;

	oldcred = remapfs_override_creds(inode->i_sb);
	err = vfs_getattr(&newpath, stat, request_mask, query_flags);
	revert_creds(oldcred);

	if (err)
		return err;

	/* transform the underlying id */
	stat->uid = KUIDT_INIT(map_id_up(&info->uid_map,
				    __kuid_val(stat->uid)));
	stat->gid = KGIDT_INIT(map_id_up(&info->gid_map,
				    __kgid_val(stat->gid)));
	return 0;
}

#ifdef CONFIG_REMAP_FS_POSIX_ACL

static int
shift_acl_ids(struct remapfs_super_info *sbinfo,
	      struct posix_acl *acl, bool up)
{
	int i;

	for (i = 0; i < acl->a_count; i++) {
		struct posix_acl_entry *e = &acl->a_entries[i];
		switch(e->e_tag) {
		case ACL_USER:
			if (up)
			  e->e_uid = KUIDT_INIT(map_id_up(&sbinfo->uid_map,
							__kuid_val(e->e_uid)));
			else
			  e->e_uid = KUIDT_INIT(map_id_down(&sbinfo->uid_map,
							__kuid_val(e->e_uid)));
			if (!uid_valid(e->e_uid))
				return -EOVERFLOW;
			break;
		case ACL_GROUP:
			if (up)
			  e->e_gid = KGIDT_INIT(map_id_up(&sbinfo->gid_map,
							__kgid_val(e->e_gid)));
			else
			  e->e_gid = KGIDT_INIT(map_id_down(&sbinfo->gid_map,
							__kgid_val(e->e_gid)));
			if (!gid_valid(e->e_gid))
				return -EOVERFLOW;
			break;
		}
	}
	return 0;
}

static void
shift_acl_xattr_ids(struct remapfs_super_info *sbinfo,
		    void *value, size_t size, bool up)
{
	struct posix_acl_xattr_header *header = value;
	struct posix_acl_xattr_entry *entry = (void *)(header + 1), *end;
	int count;

	if (!value)
		return;
	if (size < sizeof(struct posix_acl_xattr_header))
		return;
	if (header->a_version != cpu_to_le32(POSIX_ACL_XATTR_VERSION))
		return;

	count = posix_acl_xattr_count(size);
	if (count < 0)
		return;
	if (count == 0)
		return;

	for (end = entry + count; entry != end; entry++) {
		switch(le16_to_cpu(entry->e_tag)) {
		case ACL_USER:
			if (up)
			  entry->e_id = cpu_to_le32(map_id_up(&sbinfo->uid_map,
						  le32_to_cpu(entry->e_id)));
			else
			  entry->e_id = cpu_to_le32(map_id_down(&sbinfo->uid_map,
						  le32_to_cpu(entry->e_id)));
			break;
		case ACL_GROUP:
			if (up)
			  entry->e_id = cpu_to_le32(map_id_up(&sbinfo->gid_map,
						  le32_to_cpu(entry->e_id)));
			else
			  entry->e_id = cpu_to_le32(map_id_down(&sbinfo->gid_map,
						  le32_to_cpu(entry->e_id)));
			break;
		default:
			break;
		}
	}
}

static struct posix_acl *remapfs_get_acl(struct inode *inode, int type)
{
	struct inode *loweri = inode->i_private;
	const struct cred *oldcred;
	struct posix_acl *lower_acl, *acl = NULL;
	int size;
	int err;

	if (!IS_POSIXACL(loweri))
		return NULL;

	oldcred = remapfs_override_creds(inode->i_sb);
	lower_acl = get_acl(loweri, type);
	revert_creds(oldcred);

	if (lower_acl && !IS_ERR(lower_acl)) {
		/* XXX: export posix_acl_clone? */
		size = sizeof(struct posix_acl) +
		       lower_acl->a_count * sizeof(struct posix_acl_entry);
		acl = kmemdup(lower_acl, size, GFP_KERNEL);
		posix_acl_release(lower_acl);

		if (!acl)
			return ERR_PTR(-ENOMEM);

		refcount_set(&acl->a_refcount, 1);

		err = shift_acl_ids(inode->i_sb->s_fs_info, acl, true);
		if (err) {
			kfree(acl);
			return ERR_PTR(err);
		}
	}

	return acl;
}

static int
remapfs_posix_acl_xattr_get(const struct xattr_handler *handler,
			   struct dentry *dentry, struct inode *inode,
			   const char *name, void *buffer, size_t size)
{
	struct inode *loweri = inode->i_private;
	int ret;

	ret = remapfs_xattr_get(NULL, dentry, inode, handler->name,
				buffer, size);
	if (ret < 0)
		return ret;

	inode_lock(loweri);
	shift_acl_xattr_ids(inode->i_sb->s_fs_info,
			    buffer, size, true);
	inode_unlock(loweri);
	return ret;
}

static int
remapfs_posix_acl_xattr_set(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value,
			    size_t size, int flags)
{
	struct inode *loweri = inode->i_private;
	int err;

	if (!IS_POSIXACL(loweri) || !loweri->i_op->set_acl)
		return -EOPNOTSUPP;
	if (handler->flags == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return value ? -EACCES : 0;
	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (value) {
		shift_acl_xattr_ids(inode->i_sb->s_fs_info,
				    (void *)value, size, false);
		err = remapfs_setxattr(dentry, inode, handler->name, value,
				       size, flags);
	} else {
		err = remapfs_removexattr(dentry, handler->name);
	}

	if (!err)
		remapfs_copyattr(loweri, inode);

	return err;
}

static const struct xattr_handler
remapfs_posix_acl_access_xattr_handler = {
	.name = XATTR_NAME_POSIX_ACL_ACCESS,
	.flags = ACL_TYPE_ACCESS,
	.get = remapfs_posix_acl_xattr_get,
	.set = remapfs_posix_acl_xattr_set,
};

static const struct xattr_handler
remapfs_posix_acl_default_xattr_handler = {
	.name = XATTR_NAME_POSIX_ACL_DEFAULT,
	.flags = ACL_TYPE_DEFAULT,
	.get = remapfs_posix_acl_xattr_get,
	.set = remapfs_posix_acl_xattr_set,
};

#else /* !CONFIG_REMAP_FS_POSIX_ACL */

#define remapfs_get_acl NULL

#endif /* CONFIG_REMAP_FS_POSIX_ACL */

static const struct inode_operations remapfs_dir_inode_operations = {
	.lookup		= remapfs_lookup,
	.mkdir		= remapfs_mkdir,
	.symlink	= remapfs_symlink,
	.unlink		= remapfs_unlink,
	.rmdir		= remapfs_rmdir,
	.rename		= remapfs_rename,
	.link		= remapfs_link,
	.setattr	= remapfs_setattr,
	.create		= remapfs_create,
	.mknod		= remapfs_mknod,
	.permission	= remapfs_permission,
	.getattr	= remapfs_getattr,
	.listxattr	= remapfs_listxattr,
	.get_acl	= remapfs_get_acl,
};

static const struct inode_operations remapfs_file_inode_operations = {
	.fiemap		= remapfs_fiemap,
	.getattr	= remapfs_getattr,
	.get_acl	= remapfs_get_acl,
	.listxattr	= remapfs_listxattr,
	.permission	= remapfs_permission,
	.setattr	= remapfs_setattr,
	.tmpfile	= remapfs_tmpfile,
};

static const struct inode_operations remapfs_special_inode_operations = {
	.getattr	= remapfs_getattr,
	.get_acl	= remapfs_get_acl,
	.listxattr	= remapfs_listxattr,
	.permission	= remapfs_permission,
	.setattr	= remapfs_setattr,
};

static const struct inode_operations remapfs_symlink_inode_operations = {
	.getattr	= remapfs_getattr,
	.get_link	= remapfs_get_link,
	.listxattr	= remapfs_listxattr,
	.setattr	= remapfs_setattr,
};

static struct file *remapfs_open_realfile(const struct file *file,
					  struct path *realpath)
{
	struct file *lowerf;
	const struct cred *oldcred;
	struct inode *inode = file_inode(file);
	struct inode *loweri = realpath->dentry->d_inode;
	struct remapfs_super_info *info = inode->i_sb->s_fs_info;

	oldcred = remapfs_override_creds(inode->i_sb);
	/* XXX: open_with_fake_path() not gauranteed to stay around, if
	 * removed use dentry_open() */
	lowerf = open_with_fake_path(realpath, file->f_flags, loweri, info->creator_cred);
	revert_creds(oldcred);

	return lowerf;
}

#define REMAPFS_SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT)

static int remapfs_change_flags(struct file *file, unsigned int flags)
{
	struct inode *inode = file_inode(file);
	int err;

	/* if some flag changed that cannot be changed then something's amiss */
	if (WARN_ON((file->f_flags ^ flags) & ~REMAPFS_SETFL_MASK))
		return -EIO;

	flags &= REMAPFS_SETFL_MASK;

	if (((flags ^ file->f_flags) & O_APPEND) && IS_APPEND(inode))
		return -EPERM;

	if (flags & O_DIRECT) {
		if (!file->f_mapping->a_ops ||
		    !file->f_mapping->a_ops->direct_IO)
			return -EINVAL;
	}

	if (file->f_op->check_flags) {
		err = file->f_op->check_flags(flags);
		if (err)
			return err;
	}

	spin_lock(&file->f_lock);
	file->f_flags = (file->f_flags & ~REMAPFS_SETFL_MASK) | flags;
	spin_unlock(&file->f_lock);

	return 0;
}

static int remapfs_real_fdget(const struct file *file, struct fd *lowerfd)
{
	struct remapfs_file_info *file_info = file->private_data;
	struct file *realfile = file_info->realfile;

	lowerfd->flags = 0;
	lowerfd->file = realfile;

	/* Did the flags change since open? */
	if (unlikely(file->f_flags & ~lowerfd->file->f_flags))
		return remapfs_change_flags(lowerfd->file, file->f_flags);

	return 0;
}

static int remapfs_open(struct inode *inode, struct file *file)
{
	struct remapfs_super_info *ssi = inode->i_sb->s_fs_info;
	struct remapfs_file_info *file_info;
	struct file *realfile;
	struct path *realpath;

	file_info = kmem_cache_zalloc(remapfs_file_info_cache, GFP_KERNEL);
	if (!file_info)
		return -ENOMEM;

	realpath = &file_info->realpath;
	realpath->mnt = ssi->mnt;
	realpath->dentry = file->f_path.dentry->d_fsdata;

	realfile = remapfs_open_realfile(file, realpath);
	if (IS_ERR(realfile)) {
		kmem_cache_free(remapfs_file_info_cache, file_info);
		return PTR_ERR(realfile);
	}

	file->private_data = file_info;
	file_info->realfile = realfile;
	return 0;
}

static int remapfs_release(struct inode *inode, struct file *file)
{
	struct remapfs_file_info *file_info = file->private_data;

	if (file_info) {
		if (file_info->realfile)
			fput(file_info->realfile);

		kmem_cache_free(remapfs_file_info_cache, file_info);
	}

	return 0;
}

static loff_t remapfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct remapfs_file_info *file_info = file->private_data;
	struct file *realfile = file_info->realfile;

	return vfs_llseek(realfile, offset, whence);
}

static loff_t remapfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *realinode = file_inode(file)->i_private;

	return generic_file_llseek_size(file, offset, whence,
					realinode->i_sb->s_maxbytes,
					i_size_read(realinode));
}

/* XXX: Need to figure out what to to about atime updates, maybe other
 * timestamps too ... ref. ovl_file_accessed() */

static rwf_t remapfs_iocb_to_rwf(struct kiocb *iocb)
{
	int ifl = iocb->ki_flags;
	rwf_t flags = 0;

	if (ifl & IOCB_NOWAIT)
		flags |= RWF_NOWAIT;
	if (ifl & IOCB_HIPRI)
		flags |= RWF_HIPRI;
	if (ifl & IOCB_DSYNC)
		flags |= RWF_DSYNC;
	if (ifl & IOCB_SYNC)
		flags |= RWF_SYNC;

	return flags;
}

static ssize_t remapfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fd lowerfd;
	const struct cred *oldcred;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		return ret;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	ret = vfs_iter_read(lowerfd.file, iter, &iocb->ki_pos,
			    remapfs_iocb_to_rwf(iocb));
	revert_creds(oldcred);

	remapfs_file_accessed(file);

	fdput(lowerfd);
	return ret;
}

static ssize_t remapfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fd lowerfd;
	const struct cred *oldcred;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(inode);
	/* Update mode */
	remapfs_copyattr(inode->i_private, inode);
	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		goto out_unlock;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	file_start_write(lowerfd.file);
	ret = vfs_iter_write(lowerfd.file, iter, &iocb->ki_pos,
			     remapfs_iocb_to_rwf(iocb));
	file_end_write(lowerfd.file);
	revert_creds(oldcred);

	/* Update size */
	remapfs_copyattr(inode->i_private, inode);

	fdput(lowerfd);

out_unlock:
	inode_unlock(inode);
	return ret;
}

static int remapfs_fsync(struct file *file, loff_t start, loff_t end,
			 int datasync)
{
	struct fd lowerfd;
	const struct cred *oldcred;
	int ret;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		return ret;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	ret = vfs_fsync_range(lowerfd.file, start, end, datasync);
	revert_creds(oldcred);

	fdput(lowerfd);
	return ret;
}

static int remapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct remapfs_file_info *file_info = file->private_data;
	struct file *realfile = file_info->realfile;
	const struct cred *oldcred;
	int ret;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	vma->vm_file = get_file(realfile);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(oldcred);

	remapfs_file_accessed(file);

	if (ret)
		fput(realfile); /* Drop refcount from new vm_file value */
	else
		fput(file); /* Drop refcount from previous vm_file value */

	return ret;
}

static long remapfs_fallocate(struct file *file, int mode, loff_t offset,
			      loff_t len)
{
	struct inode *inode = file_inode(file);
	struct inode *loweri = inode->i_private;
	struct fd lowerfd;
	const struct cred *oldcred;
	int ret;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		return ret;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	ret = vfs_fallocate(lowerfd.file, mode, offset, len);
	revert_creds(oldcred);

	/* Update size */
	remapfs_copyattr(loweri, inode);

	fdput(lowerfd);
	return ret;
}

static int remapfs_fadvise(struct file *file, loff_t offset, loff_t len,
			   int advice)
{
	struct fd lowerfd;
	const struct cred *oldcred;
	int ret;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		return ret;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	ret = vfs_fadvise(lowerfd.file, offset, len, advice);
	revert_creds(oldcred);

	fdput(lowerfd);
	return ret;
}

static int remapfs_override_ioctl_creds(const struct super_block *sb,
					const struct cred **oldcred,
					struct cred **newcred)
{
	struct remapfs_super_info *ssi = sb->s_fs_info;
	kuid_t fsuid = current_fsuid();
	kgid_t fsgid = current_fsgid();

	*oldcred = remapfs_override_creds(sb);

	*newcred = prepare_creds();
	if (!*newcred) {
		revert_creds(*oldcred);
		return -ENOMEM;
	}

	(*newcred)->fsuid = KUIDT_INIT(map_id_down(&ssi->uid_map,
				    __kuid_val(fsuid)));
	(*newcred)->fsgid = KGIDT_INIT(map_id_down(&ssi->gid_map,
				    __kgid_val(fsgid)));
	pr_debug("remapfs: %s mapping uid %d gid %d\n", __FUNCTION__,
					__kuid_val((*newcred)->fsuid),
					__kgid_val((*newcred)->fsgid));

	/* clear all caps to prevent bypassing capable() checks */
	cap_clear((*newcred)->cap_bset);
	cap_clear((*newcred)->cap_effective);
	cap_clear((*newcred)->cap_inheritable);
	cap_clear((*newcred)->cap_permitted);

	put_cred(override_creds(*newcred));
	return 0;
}

static inline void remapfs_revert_ioctl_creds(const struct cred *oldcred,
					      struct cred *newcred)
{
	return remapfs_revert_object_creds(oldcred, newcred);
}

static long remapfs_real_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct fd lowerfd;
	struct cred *newcred;
	const struct cred *oldcred;
	long ret = 0;
	struct super_block *sb = file->f_path.dentry->d_sb;

	ret = remapfs_real_fdget(file, &lowerfd);
	if (ret)
		goto out;

	ret = remapfs_override_ioctl_creds(sb, &oldcred, &newcred);
	if (ret)
		goto out_fdput;

	ret = vfs_ioctl(lowerfd.file, cmd, arg);

	remapfs_revert_ioctl_creds(oldcred, newcred);

	remapfs_copyattr(file_inode(lowerfd.file), file_inode(file));
	remapfs_copyflags(file_inode(lowerfd.file), file_inode(file));

out_fdput:
	fdput(lowerfd);
out:
	return ret;
}
static long remapfs_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return remapfs_real_ioctl(file, cmd, arg);
}

static long remapfs_compat_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	return remapfs_real_ioctl(file, cmd, arg);
}

enum remapfs_copyop {
	REMAPFS_COPY,
	REMAPFS_CLONE,
	REMAPFS_DEDUPE,
};

static ssize_t remapfs_copyfile(struct file *file_in, loff_t pos_in,
				struct file *file_out, loff_t pos_out, u64 len,
				unsigned int flags, enum remapfs_copyop op)
{
	ssize_t ret;
	struct fd real_in, real_out;
	const struct cred *oldcred;
	struct inode *inode_out = file_inode(file_out);
	struct inode *loweri = inode_out->i_private;

	ret = remapfs_real_fdget(file_out, &real_out);
	if (ret)
		return ret;

	ret = remapfs_real_fdget(file_in, &real_in);
	if (ret) {
		fdput(real_out);
		return ret;
	}

	oldcred = remapfs_override_creds(inode_out->i_sb);
	switch (op) {
	case REMAPFS_COPY:
		ret = vfs_copy_file_range(real_in.file, pos_in, real_out.file,
					  pos_out, len, flags);
		break;

	case REMAPFS_CLONE:
		ret = vfs_clone_file_range(real_in.file, pos_in, real_out.file,
					   pos_out, len, flags);
		break;

	case REMAPFS_DEDUPE:
		ret = vfs_dedupe_file_range_one(real_in.file, pos_in,
						real_out.file, pos_out, len,
						flags);
		break;
	}
	revert_creds(oldcred);

	/* Update size */
	remapfs_copyattr(loweri, inode_out);

	fdput(real_in);
	fdput(real_out);

	return ret;
}

static ssize_t remapfs_copy_file_range(struct file *file_in, loff_t pos_in,
				       struct file *file_out, loff_t pos_out,
				       size_t len, unsigned int flags)
{
	return remapfs_copyfile(file_in, pos_in, file_out, pos_out, len, flags,
				REMAPFS_COPY);
}

static loff_t remapfs_remap_file_range(struct file *file_in, loff_t pos_in,
				       struct file *file_out, loff_t pos_out,
				       loff_t len, unsigned int remap_flags)
{
	enum remapfs_copyop op;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

	if (remap_flags & REMAP_FILE_DEDUP)
		op = REMAPFS_DEDUPE;
	else
		op = REMAPFS_CLONE;

	return remapfs_copyfile(file_in, pos_in, file_out, pos_out, len,
				remap_flags, op);
}

static int remapfs_iterate_shared(struct file *file, struct dir_context *ctx)
{
	const struct cred *oldcred;
	int err = -ENOTDIR;
	struct remapfs_file_info *file_info = file->private_data;
	struct file *realfile = file_info->realfile;

	oldcred = remapfs_override_creds(file->f_path.dentry->d_sb);
	err = iterate_dir(realfile, ctx);
	revert_creds(oldcred);

	return err;
}

const struct file_operations remapfs_file_operations = {
	.open			= remapfs_open,
	.release		= remapfs_release,
	.llseek			= remapfs_file_llseek,
	.read_iter		= remapfs_read_iter,
	.write_iter		= remapfs_write_iter,
	.fsync			= remapfs_fsync,
	.mmap			= remapfs_mmap,
	.fallocate		= remapfs_fallocate,
	.fadvise		= remapfs_fadvise,
	.unlocked_ioctl		= remapfs_ioctl,
	.compat_ioctl		= remapfs_compat_ioctl,
	.copy_file_range	= remapfs_copy_file_range,
	.remap_file_range	= remapfs_remap_file_range,
};

const struct file_operations remapfs_dir_operations = {
	.compat_ioctl		= remapfs_compat_ioctl,
	.fsync			= remapfs_fsync,
	.iterate_shared		= remapfs_iterate_shared,
	.llseek			= remapfs_dir_llseek,
	.open			= remapfs_open,
	.read			= generic_read_dir,
	.release		= remapfs_release,
	.unlocked_ioctl		= remapfs_ioctl,
};

static const struct address_space_operations remapfs_aops = {
	/* For O_DIRECT dentry_open() checks f_mapping->a_ops->direct_IO */
	.direct_IO	= noop_direct_IO,
};

static void remapfs_fill_inode(struct inode *inode, unsigned long ino,
			       umode_t mode, dev_t dev, struct dentry *dentry)
{
	struct inode *loweri;

	inode->i_ino = ino;
	inode->i_flags |= S_NOCMTIME;

	mode &= S_IFMT;
	inode->i_mode = mode;
	switch (mode & S_IFMT) {
	case S_IFDIR:
		inode->i_op = &remapfs_dir_inode_operations;
		inode->i_fop = &remapfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &remapfs_symlink_inode_operations;
		break;
	case S_IFREG:
		inode->i_op = &remapfs_file_inode_operations;
		inode->i_fop = &remapfs_file_operations;
		inode->i_mapping->a_ops = &remapfs_aops;
		break;
	default:
		inode->i_op = &remapfs_special_inode_operations;
		init_special_inode(inode, mode, dev);
		break;
	}

	if (!dentry)
		return;

	loweri = dentry->d_inode;
	if (!loweri->i_op->get_link)
		inode->i_opflags |= IOP_NOFOLLOW;

	remapfs_copyattr(loweri, inode);
	remapfs_copyflags(loweri, inode);
	set_nlink(inode, loweri->i_nlink);
}

static int remapfs_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct remapfs_super_info *sbinfo = sb->s_fs_info;
	static const char *options[] = { "uidmap", "gidmap" };
	const struct uid_gid_map *map[ARRAY_SIZE(options)] =
				{ &sbinfo->uid_map, &sbinfo->gid_map };
	int i, j;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		for (j = 0; j < map[i]->nr_extents; j++) {
			const struct uid_gid_extent *ext = &map[i]->extent[j];

			seq_show_option(m, options[i], NULL);
			seq_printf(m, "=%u:%u:%u", ext->first,
			ext->lower_first, ext->count);
		}
	}
	return 0;
}

static int remapfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct remapfs_super_info *sbinfo = sb->s_fs_info;
	struct dentry *root = sb->s_root;
	struct dentry *realroot = root->d_fsdata;
	struct path realpath = { .mnt = sbinfo->mnt, .dentry = realroot };
	int err;

	err = vfs_statfs(&realpath, buf);
	if (err)
		return err;

	return 0;
}

static void remapfs_evict_inode(struct inode *inode)
{
	struct inode *loweri = inode->i_private;

	clear_inode(inode);

	if (loweri)
		iput(loweri);
}

static void remapfs_put_super(struct super_block *sb)
{
	struct remapfs_super_info *sbinfo = sb->s_fs_info;

	if (sbinfo) {
		mntput(sbinfo->mnt);
		put_cred(sbinfo->creator_cred);
		kfree(sbinfo);
	}
}

static const struct xattr_handler remapfs_xattr_handler = {
	.prefix = "",
	.get    = remapfs_xattr_get,
	.set    = remapfs_xattr_set,
};

const struct xattr_handler *remapfs_xattr_handlers[] = {
#ifdef CONFIG_REMAP_FS_POSIX_ACL
	&remapfs_posix_acl_access_xattr_handler,
	&remapfs_posix_acl_default_xattr_handler,
#endif
	&remapfs_xattr_handler,
	NULL
};

static int remapfs_super_check_flags(unsigned long old_flags,
				     unsigned long new_flags)
{
	if ((old_flags & SB_RDONLY) && !(new_flags & SB_RDONLY))
		return -EPERM;

	if ((old_flags & SB_NOSUID) && !(new_flags & SB_NOSUID))
		return -EPERM;

	if ((old_flags & SB_NODEV) && !(new_flags & SB_NODEV))
		return -EPERM;

	if ((old_flags & SB_NOEXEC) && !(new_flags & SB_NOEXEC))
		return -EPERM;

	if ((old_flags & SB_NOATIME) && !(new_flags & SB_NOATIME))
		return -EPERM;

	if ((old_flags & SB_NODIRATIME) && !(new_flags & SB_NODIRATIME))
		return -EPERM;

	if (!(old_flags & SB_POSIXACL) && (new_flags & SB_POSIXACL))
		return -EPERM;

	return 0;
}

static int remapfs_remount(struct super_block *sb, int *flags, char *data)
{
	int err;
	struct remapfs_super_info new = {};
	struct remapfs_super_info *info = sb->s_fs_info;

	err = remapfs_parse_mount_options(&new, data);
	if (err)
		return err;

	err = remapfs_super_check_flags(sb->s_flags, *flags);
	if (err)
		return err;

	/* Mapping mount option cannot be changed. */
	if (info->map)
		return -EPERM;

	return 0;
}

static const struct super_operations remapfs_super_ops = {
	.put_super	= remapfs_put_super,
	.show_options	= remapfs_show_options,
	.statfs		= remapfs_statfs,
	.remount_fs	= remapfs_remount,
	.evict_inode	= remapfs_evict_inode,
};

struct remapfs_data {
	void *data;
	const char *path;
};

static void remapfs_super_force_flags(struct super_block *sb,
				      unsigned long lower_flags)
{
	sb->s_flags |= lower_flags & (SB_RDONLY | SB_NOSUID | SB_NODEV |
				      SB_NOEXEC | SB_NOATIME | SB_NODIRATIME);

	if (!(lower_flags & SB_POSIXACL))
		sb->s_flags &= ~SB_POSIXACL;
}

static int remapfs_fill_super(struct super_block *sb, void *raw_data,
			      int silent)
{
	int err;
	struct path path = {};
	char *name = NULL;
	struct inode *inode = NULL;
	struct dentry *dentry = NULL;
	struct remapfs_data *data = raw_data;
	struct remapfs_super_info *sbinfo = NULL;
	struct super_block *lower_sb;

	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "called");
	if (!data->path)
		return -EINVAL;

	sb->s_fs_info = kzalloc(sizeof(*sbinfo), GFP_KERNEL);
	if (!sb->s_fs_info)
		return -ENOMEM;
	sbinfo = sb->s_fs_info;

	err = remapfs_parse_mount_options(sbinfo, data->data);
	if (err)
		return err;

	sb->s_magic = REMAPFS_MAGIC;

	name = kstrdup(data->path, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	err = kern_path(name, LOOKUP_FOLLOW, &path);
	if (err)
		goto out_free_name;

	if (!S_ISDIR(path.dentry->d_inode->i_mode)) {
		err = -ENOTDIR;
		goto out_put_path;
	}

	sb->s_flags |= SB_POSIXACL;

	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "mounting MARK1");
	if (!sbinfo->map) {
		err = -EINVAL;
		goto out_put_path;
	}

	/* must be real root */
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		err = -EPERM;
		goto out_put_path;
	}
	
	lower_sb = path.mnt->mnt_sb;
	/*?*/remapfs_super_force_flags(sb, lower_sb->s_flags);

	sbinfo->mnt = mntget(path.mnt);
	dentry = dget(path.dentry);

	sbinfo->creator_cred = prepare_creds();
	if (!sbinfo->creator_cred) {
		err = -ENOMEM;
		goto out_put_path;
	}

	pr_debug("remapfs: %s: %s\n", __FUNCTION__, "mounting MARK2");
	err = -EPERM;

	dentry = dget(path.dentry);
	remapfs_super_force_flags(sb, path.mnt->mnt_sb->s_flags);

	sb->s_stack_depth = dentry->d_sb->s_stack_depth + 1;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		printk(KERN_ERR "remapfs: maximum stacking depth exceeded\n");
		err = -EINVAL;
		goto out_put_path;
	}

	inode = new_inode(sb);
	if (!inode) {
		err = -ENOMEM;
		goto out_put_path;
	}
	remapfs_fill_inode(inode, dentry->d_inode->i_ino, S_IFDIR, 0, dentry);

	ihold(dentry->d_inode);
	inode->i_private = dentry->d_inode;

	sb->s_op = &remapfs_super_ops;
	sb->s_xattr = remapfs_xattr_handlers;
	sb->s_d_op = &remapfs_dentry_ops;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_put_path;
	}

	sb->s_root->d_fsdata = dentry;
	remapfs_copyattr(dentry->d_inode, sb->s_root->d_inode);

	dentry = NULL;
	err = 0;

out_put_path:
	path_put(&path);

out_free_name:
	kfree(name);

	dput(dentry);

	return err;
}

static struct dentry *remapfs_mount(struct file_system_type *fs_type,
				    int flags, const char *dev_name, void *data)
{
	struct remapfs_data d = { data, dev_name };

	return mount_nodev(fs_type, flags, &d, remapfs_fill_super);
}

static struct file_system_type remapfs_type = {
	.owner		= THIS_MODULE,
	.name		= "remapfs",
	.mount		= remapfs_mount,
	.kill_sb	= kill_anon_super,
	.fs_flags	= FS_USERNS_MOUNT,
};

static int __init remapfs_init(void)
{
	remapfs_file_info_cache = kmem_cache_create(
		"remapfs_file_info_cache", sizeof(struct remapfs_file_info), 0,
		SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!remapfs_file_info_cache)
		return -ENOMEM;

	return register_filesystem(&remapfs_type);
}

static void __exit remapfs_exit(void)
{
	unregister_filesystem(&remapfs_type);
	kmem_cache_destroy(remapfs_file_info_cache);
}

MODULE_ALIAS_FS("remapfs");
MODULE_AUTHOR("James Bottomley");
MODULE_AUTHOR("Seth Forshee <seth.forshee@canonical.com>");
MODULE_AUTHOR("Christian Brauner <christian.brauner@ubuntu.com>");
MODULE_AUTHOR("Pavel Snajdr <snajpa@snajpa.net>");
MODULE_DESCRIPTION("id shifting filesystem without namespaces involved");
MODULE_LICENSE("GPL v2");
module_init(remapfs_init)
module_exit(remapfs_exit)
