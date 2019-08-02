/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * mount options/flags
 */

#ifndef __AUFS_OPTS_H__
#define __AUFS_OPTS_H__

#ifdef __KERNEL__

#include <linux/path.h>

/* ---------------------------------------------------------------------- */

/* mount flags */
#define AuOpt_XINO		1		/* external inode number bitmap
						   and translation table */

#define AuOpt_Def	AuOpt_XINO

#define au_opt_test(flags, name)	(flags & AuOpt_##name)
#define au_opt_set(flags, name) do { \
	((flags) |= AuOpt_##name); \
} while (0)
#define au_opt_clr(flags, name) do { \
	((flags) &= ~AuOpt_##name); \
} while (0)

/* ---------------------------------------------------------------------- */

struct au_opt_add {
	aufs_bindex_t	bindex;
	char		*pathname;
	int		perm;
	struct path	path;
};

struct au_opt {
	int type;
	union {
		struct au_opt_add	add;
		/* add more later */
	};
};

struct au_opts {
	struct au_opt	*opt;
	int		max_opt;

	unsigned long	sb_flags;
};

/* ---------------------------------------------------------------------- */

/* opts.c */
void au_optstr_br_perm(au_br_perm_str_t *str, int perm);

void au_opts_free(struct au_opts *opts);
struct super_block;
int au_opts_parse(struct super_block *sb, char *str, struct au_opts *opts);
int au_opts_mount(struct super_block *sb, struct au_opts *opts);

#endif /* __KERNEL__ */
#endif /* __AUFS_OPTS_H__ */
