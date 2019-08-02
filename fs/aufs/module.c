// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * module global variables and operations
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include "aufs.h"

/* shrinkable realloc */
void *au_krealloc(void *p, unsigned int new_sz, gfp_t gfp, int may_shrink)
{
	size_t sz;
	int diff;

	sz = 0;
	diff = -1;
	if (p) {
#if 0 /* unused */
		if (!new_sz) {
			au_kfree_rcu(p);
			p = NULL;
			goto out;
		}
#else
		AuDebugOn(!new_sz);
#endif
		sz = ksize(p);
		diff = au_kmidx_sub(sz, new_sz);
	}
	if (sz && !diff)
		goto out;

	if (sz < new_sz)
		/* expand or SLOB */
		p = krealloc(p, new_sz, gfp);
	else if (new_sz < sz && may_shrink) {
		/* shrink */
		void *q;

		q = kmalloc(new_sz, gfp);
		if (q) {
			if (p) {
				memcpy(q, p, new_sz);
				au_kfree_try_rcu(p);
			}
			p = q;
		} else
			p = NULL;
	}

out:
	return p;
}

void *au_kzrealloc(void *p, unsigned int nused, unsigned int new_sz, gfp_t gfp,
		   int may_shrink)
{
	p = au_krealloc(p, new_sz, gfp, may_shrink);
	if (p && new_sz > nused)
		memset(p + nused, 0, new_sz - nused);
	return p;
}

/* ---------------------------------------------------------------------- */
/*
 * aufs caches
 */
struct kmem_cache *au_cache[AuCache_Last];

static void au_cache_fin(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	for (i = 0; i < AuCache_Last; i++) {
		kmem_cache_destroy(au_cache[i]);
		au_cache[i] = NULL;
	}
}

static int __init au_cache_init(void)
{
	au_cache[AuCache_DINFO] = AuCacheCtor(au_dinfo, au_di_init_once);
	if (au_cache[AuCache_DINFO])
		/* SLAB_DESTROY_BY_RCU */
		au_cache[AuCache_ICNTNR] = AuCacheCtor(au_icntnr,
						       au_icntnr_init_once);
	if (au_cache[AuCache_ICNTNR])
		return 0;

	au_cache_fin();
	return -ENOMEM;
}

/* ---------------------------------------------------------------------- */

#ifdef CONFIG_AUFS_SBILIST
/*
 * iterate_supers_type() doesn't protect us from
 * remounting (branch management)
 */
struct hlist_bl_head au_sbilist;
#endif

/*
 * functions for module interface.
 */
MODULE_LICENSE("GPL");
/* MODULE_LICENSE("GPL v2"); */
MODULE_AUTHOR("Junjiro R. Okajima <aufs-users@lists.sourceforge.net>");
MODULE_DESCRIPTION(AUFS_NAME
	" -- Advanced multi layered unification filesystem");
MODULE_VERSION(AUFS_VERSION);

/* this module parameter has no meaning when SYSFS is disabled */
int sysaufs_brs = 1;
MODULE_PARM_DESC(brs, "use <sysfs>/fs/aufs/si_*/brN");
module_param_named(brs, sysaufs_brs, int, 0444);

/* ---------------------------------------------------------------------- */

static char au_esc_chars[0x20 + 3]; /* 0x01-0x20, backslash, del, and NULL */

int au_seq_path(struct seq_file *seq, struct path *path)
{
	int err;

	err = seq_path(seq, path, au_esc_chars);
	if (err >= 0)
		err = 0;
	else
		err = -ENOMEM;

	return err;
}

/* ---------------------------------------------------------------------- */

static int __init aufs_init(void)
{
	int err, i;
	char *p;

	p = au_esc_chars;
	for (i = 1; i <= ' '; i++)
		*p++ = i;
	*p++ = '\\';
	*p++ = '\x7f';
	*p = 0;

	memset(au_cache, 0, sizeof(au_cache));

	au_sbilist_init();
	sysaufs_brs_init();
	err = sysaufs_init();
	if (unlikely(err))
		goto out;
	err = au_wkq_init();
	if (unlikely(err))
		goto out_sysaufs;
	err = au_cache_init();
	if (unlikely(err))
		goto out_wkq;

	/* since we define pr_fmt, call printk directly */
	printk(KERN_INFO AUFS_NAME " " AUFS_VERSION "\n");
	goto out; /* success */

out_wkq:
	au_wkq_fin();
out_sysaufs:
	sysaufs_fin();
out:
	return err;
}

module_init(aufs_init);
