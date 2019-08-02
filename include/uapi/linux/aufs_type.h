/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

#ifndef __AUFS_TYPE_H__
#define __AUFS_TYPE_H__

#define AUFS_NAME	"aufs"

#ifdef __KERNEL__
/*
 * define it before including all other headers.
 * sched.h may use pr_* macros before defining "current", so define the
 * no-current version first, and re-define later.
 */
#define pr_fmt(fmt)	AUFS_NAME " %s:%d: " fmt, __func__, __LINE__
#include <linux/sched.h>
#undef pr_fmt
#define pr_fmt(fmt) \
		AUFS_NAME " %s:%d:%.*s[%d]: " fmt, __func__, __LINE__, \
		(int)sizeof(current->comm), current->comm, current->pid
#else
#include <stdint.h>
#include <sys/types.h>
#endif /* __KERNEL__ */

#include <linux/limits.h>

#define AUFS_VERSION	"5.x-rcN"

/* todo? move this to linux-2.6.19/include/magic.h */
#define AUFS_SUPER_MAGIC	('a' << 24 | 'u' << 16 | 'f' << 8 | 's')

/* ---------------------------------------------------------------------- */

#ifdef CONFIG_AUFS_BRANCH_MAX_127
typedef int8_t aufs_bindex_t;
#define AUFS_BRANCH_MAX 127
#else
typedef int16_t aufs_bindex_t;
#ifdef CONFIG_AUFS_BRANCH_MAX_511
#define AUFS_BRANCH_MAX 511
#elif defined(CONFIG_AUFS_BRANCH_MAX_1023)
#define AUFS_BRANCH_MAX 1023
#elif defined(CONFIG_AUFS_BRANCH_MAX_32767)
#define AUFS_BRANCH_MAX 32767
#endif
#endif

#ifdef __KERNEL__
#ifndef AUFS_BRANCH_MAX
#error unknown CONFIG_AUFS_BRANCH_MAX value
#endif
#endif /* __KERNEL__ */

/* ---------------------------------------------------------------------- */

#define AUFS_FSTYPE		AUFS_NAME

#define AUFS_ROOT_INO		2
#define AUFS_FIRST_INO		11

#define AUFS_WH_PFX		".wh."
#define AUFS_WH_PFX_LEN		((int)sizeof(AUFS_WH_PFX) - 1)
#define AUFS_WH_TMP_LEN		4
/* a limit for rmdir/rename a dir and copyup */
#define AUFS_MAX_NAMELEN	(NAME_MAX \
				- AUFS_WH_PFX_LEN * 2	/* doubly whiteouted */\
				- 1			/* dot */\
				- AUFS_WH_TMP_LEN)	/* hex */
#define AUFS_XINO_FNAME		"." AUFS_NAME ".xino"
#define AUFS_XINO_DEFPATH	"/tmp/" AUFS_XINO_FNAME
#define AUFS_XINO_DEF_SEC	30 /* seconds */
#define AUFS_XINO_DEF_TRUNC	45 /* percentage */
#define AUFS_RDCACHE_DEF	10 /* seconds */
#define AUFS_RDCACHE_MAX	3600 /* seconds */
#define AUFS_RDBLK_DEF		512 /* bytes */
#define AUFS_RDHASH_DEF		32
#define AUFS_WKQ_NAME		AUFS_NAME "d"
#define AUFS_MFS_DEF_SEC	30 /* seconds */
#define AUFS_MFS_MAX_SEC	3600 /* seconds */
#define AUFS_PLINK_WARN		50 /* number of plinks in a single bucket */

/* pseudo-link maintenace under /proc */
#define AUFS_PLINK_MAINT_NAME	"plink_maint"
#define AUFS_PLINK_MAINT_DIR	"fs/" AUFS_NAME
#define AUFS_PLINK_MAINT_PATH	AUFS_PLINK_MAINT_DIR "/" AUFS_PLINK_MAINT_NAME

#define AUFS_DIROPQ_NAME	AUFS_WH_PFX ".opq" /* whiteouted doubly */
#define AUFS_WH_DIROPQ		AUFS_WH_PFX AUFS_DIROPQ_NAME

#define AUFS_BASE_NAME		AUFS_WH_PFX AUFS_NAME
#define AUFS_PLINKDIR_NAME	AUFS_WH_PFX "plnk"
#define AUFS_ORPHDIR_NAME	AUFS_WH_PFX "orph"

/* doubly whiteouted */
#define AUFS_WH_BASE		AUFS_WH_PFX AUFS_BASE_NAME
#define AUFS_WH_PLINKDIR	AUFS_WH_PFX AUFS_PLINKDIR_NAME
#define AUFS_WH_ORPHDIR		AUFS_WH_PFX AUFS_ORPHDIR_NAME

/* branch permissions and attributes */
#define AUFS_BRPERM_RW		"rw"
#define AUFS_BRPERM_RO		"ro"
#define AUFS_BRPERM_RR		"rr"
#define AUFS_BRATTR_ICEX	"icex"
#define AUFS_BRATTR_ICEX_SEC	"icexsec"
#define AUFS_BRATTR_ICEX_SYS	"icexsys"
#define AUFS_BRATTR_ICEX_TR	"icextr"
#define AUFS_BRATTR_ICEX_USR	"icexusr"
#define AUFS_BRATTR_ICEX_OTH	"icexoth"
#define AUFS_BRRATTR_WH		"wh"
#define AUFS_BRWATTR_NLWH	"nolwh"

#define AuBrPerm_RW		1		/* writable, hardlinkable wh */
#define AuBrPerm_RO		(1 << 1)	/* readonly */
#define AuBrPerm_RR		(1 << 2)	/* natively readonly */
#define AuBrPerm_Mask		(AuBrPerm_RW | AuBrPerm_RO | AuBrPerm_RR)

/* ignore error in copying XATTR */
#define AuBrAttr_ICEX_SEC	(1 << 7)
#define AuBrAttr_ICEX_SYS	(1 << 8)
#define AuBrAttr_ICEX_TR	(1 << 9)
#define AuBrAttr_ICEX_USR	(1 << 10)
#define AuBrAttr_ICEX_OTH	(1 << 11)
#define AuBrAttr_ICEX		(AuBrAttr_ICEX_SEC	\
				 | AuBrAttr_ICEX_SYS	\
				 | AuBrAttr_ICEX_TR	\
				 | AuBrAttr_ICEX_USR	\
				 | AuBrAttr_ICEX_OTH)

#define AuBrRAttr_WH		(1 << 12)	/* whiteout-able */
#define AuBrRAttr_Mask		AuBrRAttr_WH

#define AuBrWAttr_NoLinkWH	(1 << 13)	/* un-hardlinkable whiteouts */
#define AuBrWAttr_Mask		AuBrWAttr_NoLinkWH

/* #warning test userspace */
#ifdef __KERNEL__
#ifndef CONFIG_AUFS_XATTR
#undef	AuBrAttr_ICEX
#define AuBrAttr_ICEX		0
#undef	AuBrAttr_ICEX_SEC
#define AuBrAttr_ICEX_SEC	0
#undef	AuBrAttr_ICEX_SYS
#define AuBrAttr_ICEX_SYS	0
#undef	AuBrAttr_ICEX_TR
#define AuBrAttr_ICEX_TR	0
#undef	AuBrAttr_ICEX_USR
#define AuBrAttr_ICEX_USR	0
#undef	AuBrAttr_ICEX_OTH
#define AuBrAttr_ICEX_OTH	0
#endif
#endif

/* the longest combination */
/* AUFS_BRATTR_ICEX and AUFS_BRATTR_ICEX_TR don't affect here */
#define AuBrPermStrSz	sizeof(AUFS_BRPERM_RW			\
			       "+" AUFS_BRATTR_ICEX_SEC		\
			       "+" AUFS_BRATTR_ICEX_SYS		\
			       "+" AUFS_BRATTR_ICEX_USR		\
			       "+" AUFS_BRATTR_ICEX_OTH		\
			       "+" AUFS_BRWATTR_NLWH)

typedef struct {
	char a[AuBrPermStrSz];
} au_br_perm_str_t;

static inline int au_br_writable(int brperm)
{
	return brperm & AuBrPerm_RW;
}

static inline int au_br_whable(int brperm)
{
	return brperm & (AuBrPerm_RW | AuBrRAttr_WH);
}

static inline int au_br_wh_linkable(int brperm)
{
	return !(brperm & AuBrWAttr_NoLinkWH);
}

#endif /* __AUFS_TYPE_H__ */
