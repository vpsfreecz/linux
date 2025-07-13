/* zfs_config.h.  Generated from zfs_config.h.in by configure.  */
/* zfs_config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* __assign_str() has one arg */
#define HAVE_1ARG_ASSIGN_STR 1

/* lookup_bdev() wants 1 arg */
/* #undef HAVE_1ARG_LOOKUP_BDEV */

/* kernel has access_ok with 'type' parameter */
/* #undef HAVE_ACCESS_OK_TYPE */

/* add_disk() returns int */
#define HAVE_ADD_DISK_RET 1

/* Define if host toolchain supports AES */
#define HAVE_AES 1

/* Define if you have [rt] */
#define HAVE_AIO_H 1

/* Define if host toolchain supports AVX */
#define HAVE_AVX 1

/* Define if host toolchain supports AVX2 */
#define HAVE_AVX2 1

/* Define if host toolchain supports AVX512BW */
#define HAVE_AVX512BW 1

/* Define if host toolchain supports AVX512CD */
#define HAVE_AVX512CD 1

/* Define if host toolchain supports AVX512DQ */
#define HAVE_AVX512DQ 1

/* Define if host toolchain supports AVX512ER */
#define HAVE_AVX512ER 1

/* Define if host toolchain supports AVX512F */
#define HAVE_AVX512F 1

/* Define if host toolchain supports AVX512IFMA */
#define HAVE_AVX512IFMA 1

/* Define if host toolchain supports AVX512PF */
#define HAVE_AVX512PF 1

/* Define if host toolchain supports AVX512VBMI */
#define HAVE_AVX512VBMI 1

/* Define if host toolchain supports AVX512VL */
#define HAVE_AVX512VL 1

/* backtrace() is available */
#define HAVE_BACKTRACE 1

/* bdevname() is available */
/* #undef HAVE_BDEVNAME */

/* bdev_check_media_change() exists */
/* #undef HAVE_BDEV_CHECK_MEDIA_CHANGE */

/* bdev_file_open_by_path() exists */
#define HAVE_BDEV_FILE_OPEN_BY_PATH 1

/* bdev_*_io_acct() available */
#define HAVE_BDEV_IO_ACCT_63 1

/* bdev_*_io_acct() available */
/* #undef HAVE_BDEV_IO_ACCT_OLD */

/* bdev_kobj() exists */
#define HAVE_BDEV_KOBJ 1

/* bdev_max_discard_sectors() is available */
#define HAVE_BDEV_MAX_DISCARD_SECTORS 1

/* bdev_max_secure_erase_sectors() is available */
#define HAVE_BDEV_MAX_SECURE_ERASE_SECTORS 1

/* bdev_nr_bytes() is available */
#define HAVE_BDEV_NR_BYTES 1

/* bdev_open_by_path() exists */
/* #undef HAVE_BDEV_OPEN_BY_PATH */

/* bdev_release() exists */
/* #undef HAVE_BDEV_RELEASE */

/* block_device_operations->submit_bio() returns void */
#define HAVE_BDEV_SUBMIT_BIO_RETURNS_VOID 1

/* bdev_whole() is available */
#define HAVE_BDEV_WHOLE 1

/* bio_alloc() takes 4 arguments */
#define HAVE_BIO_ALLOC_4ARG 1

/* bio->bi_bdev->bd_disk exists */
#define HAVE_BIO_BDEV_DISK 1

/* bio_*_io_acct() available */
/* #undef HAVE_BIO_IO_ACCT */

/* bio_max_segs() is implemented */
#define HAVE_BIO_MAX_SEGS 1

/* bio_set_dev() GPL-only */
/* #undef HAVE_BIO_SET_DEV_GPL_ONLY */

/* bio_set_dev() is a macro */
/* #undef HAVE_BIO_SET_DEV_MACRO */

/* bio_set_op_attrs is available */
/* #undef HAVE_BIO_SET_OP_ATTRS */

/* blkdev_get_by_path() exists and takes 4 args */
/* #undef HAVE_BLKDEV_GET_BY_PATH_4ARG */

/* blkdev_get_by_path() handles ERESTARTSYS */
/* #undef HAVE_BLKDEV_GET_ERESTARTSYS */

/* __blkdev_issue_discard(flags) is available */
/* #undef HAVE_BLKDEV_ISSUE_DISCARD_ASYNC_FLAGS */

/* __blkdev_issue_discard() is available */
#define HAVE_BLKDEV_ISSUE_DISCARD_ASYNC_NOFLAGS 1

/* blkdev_issue_discard(flags) is available */
/* #undef HAVE_BLKDEV_ISSUE_DISCARD_FLAGS */

/* blkdev_issue_discard() is available */
#define HAVE_BLKDEV_ISSUE_DISCARD_NOFLAGS 1

/* blkdev_issue_secure_erase() is available */
#define HAVE_BLKDEV_ISSUE_SECURE_ERASE 1

/* blkdev_put() exists */
/* #undef HAVE_BLKDEV_PUT */

/* blkdev_put() accepts void* as arg 2 */
/* #undef HAVE_BLKDEV_PUT_HOLDER */

/* struct queue_limits has a features field */
#define HAVE_BLKDEV_QUEUE_LIMITS_FEATURES 1

/* blkdev_reread_part() exists */
/* #undef HAVE_BLKDEV_REREAD_PART */

/* blkg_tryget() is available */
/* #undef HAVE_BLKG_TRYGET */

/* blkg_tryget() GPL-only */
/* #undef HAVE_BLKG_TRYGET_GPL_ONLY */

/* blk_alloc_disk() exists */
/* #undef HAVE_BLK_ALLOC_DISK */

/* blk_alloc_disk() exists and takes 2 args */
#define HAVE_BLK_ALLOC_DISK_2ARG 1

/* blk_alloc_queue() expects request function */
/* #undef HAVE_BLK_ALLOC_QUEUE_REQUEST_FN */

/* blk_alloc_queue_rh() expects request function */
/* #undef HAVE_BLK_ALLOC_QUEUE_REQUEST_FN_RH */

/* blk_cleanup_disk() exists */
/* #undef HAVE_BLK_CLEANUP_DISK */

/* blk_mode_t is defined */
#define HAVE_BLK_MODE_T 1

/* block multiqueue hardware context is cached in struct request */
#define HAVE_BLK_MQ_RQ_HCTX 1

/* blk queue backing_dev_info is dynamic */
/* #undef HAVE_BLK_QUEUE_BDI_DYNAMIC */

/* blk_queue_discard() is available */
/* #undef HAVE_BLK_QUEUE_DISCARD */

/* backing_dev_info is available through queue gendisk */
#define HAVE_BLK_QUEUE_DISK_BDI 1

/* blk_queue_secure_erase() is available */
/* #undef HAVE_BLK_QUEUE_SECURE_ERASE */

/* blk_queue_update_readahead() exists */
/* #undef HAVE_BLK_QUEUE_UPDATE_READAHEAD */

/* BLK_STS_RESV_CONFLICT is defined */
#define HAVE_BLK_STS_RESV_CONFLICT 1

/* Define if release() in block_device_operations takes 1 arg */
#define HAVE_BLOCK_DEVICE_OPERATIONS_RELEASE_1ARG 1

/* Define if revalidate_disk() in block_device_operations */
/* #undef HAVE_BLOCK_DEVICE_OPERATIONS_REVALIDATE_DISK */

/* Define to 1 if you have the Mac OS X function
   CFLocaleCopyPreferredLanguages in the CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYPREFERREDLANGUAGES */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* check_disk_change() exists */
/* #undef HAVE_CHECK_DISK_CHANGE */

/* copy_splice_read exists */
#define HAVE_COPY_SPLICE_READ 1

/* cpu_has_feature() is GPL-only */
/* #undef HAVE_CPU_HAS_FEATURE_GPL_ONLY */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* DECLARE_EVENT_CLASS() is available */
#define HAVE_DECLARE_EVENT_CLASS 1

/* 3-arg dequeue_signal() takes a type argument */
#define HAVE_DEQUEUE_SIGNAL_3ARG_TYPE 1

/* dequeue_signal() takes 4 arguments */
/* #undef HAVE_DEQUEUE_SIGNAL_4ARG */

/* lookup_bdev() wants dev_t arg */
#define HAVE_DEVT_LOOKUP_BDEV 1

/* disk_check_media_change() exists */
#define HAVE_DISK_CHECK_MEDIA_CHANGE 1

/* disk_*_io_acct() available */
/* #undef HAVE_DISK_IO_ACCT */

/* disk_update_readahead() exists */
/* #undef HAVE_DISK_UPDATE_READAHEAD */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* dops->d_revalidate() takes 4 args */
/* #undef HAVE_D_REVALIDATE_4ARGS */

/* Define to 1 if you have the 'execvpe' function. */
#define HAVE_EXECVPE 1

/* fault_in_iov_iter_readable() is available */
#define HAVE_FAULT_IN_IOV_ITER_READABLE 1

/* file->f_version exists */
/* #undef HAVE_FILE_F_VERSION */

/* flush_dcache_page() is GPL-only */
/* #undef HAVE_FLUSH_DCACHE_PAGE_GPL_ONLY */

/* Define if compiler supports -Wformat-overflow */
#define HAVE_FORMAT_OVERFLOW 1

/* fsync_bdev() is declared in include/blkdev.h */
/* #undef HAVE_FSYNC_BDEV */

/* yes */
#define HAVE_GENERIC_FADVISE 1

/* generic_fillattr requires struct mnt_idmap* */
/* #undef HAVE_GENERIC_FILLATTR_IDMAP */

/* generic_fillattr requires struct mnt_idmap* and u32 request_mask */
#define HAVE_GENERIC_FILLATTR_IDMAP_REQMASK 1

/* generic_fillattr requires struct user_namespace* */
/* #undef HAVE_GENERIC_FILLATTR_USERNS */

/* generic_*_io_acct() 4 arg available */
/* #undef HAVE_GENERIC_IO_ACCT_4ARG */

/* GENHD_FL_EXT_DEVT flag is available */
/* #undef HAVE_GENHD_FL_EXT_DEVT */

/* GENHD_FL_NO_PART flag is available */
#define HAVE_GENHD_FL_NO_PART 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define to 1 if you have the 'gettid' function. */
#define HAVE_GETTID 1

/* iops->get_acl() exists */
/* #undef HAVE_GET_ACL */

/* iops->get_acl() takes rcu */
/* #undef HAVE_GET_ACL_RCU */

/* has iops->get_inode_acl() */
#define HAVE_GET_INODE_ACL 1

/* iattr->ia_vfsuid and iattr->ia_vfsgid exist */
#define HAVE_IATTR_VFSID 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* iops->getattr() takes struct mnt_idmap* */
#define HAVE_IDMAP_IOPS_GETATTR 1

/* iops->setattr() takes struct mnt_idmap* */
#define HAVE_IDMAP_IOPS_SETATTR 1

/* APIs for idmapped mount are present */
#define HAVE_IDMAP_MNT_API 1

/* mnt_idmap does not have user_namespace */
#define HAVE_IDMAP_NO_USERNS 1

/* Define if compiler supports -Wimplicit-fallthrough */
#define HAVE_IMPLICIT_FALLTHROUGH 1

/* Define if compiler supports -Winfinite-recursion */
#define HAVE_INFINITE_RECURSION 1

/* .inode_free() i_op exists */
#define HAVE_INODE_FREE 1

/* inode_get_atime() exists in linux/fs.h */
#define HAVE_INODE_GET_ATIME 1

/* inode_get_ctime() exists in linux/fs.h */
#define HAVE_INODE_GET_CTIME 1

/* inode_get_mtime() exists in linux/fs.h */
#define HAVE_INODE_GET_MTIME 1

/* inode_owner_or_capable() exists */
/* #undef HAVE_INODE_OWNER_OR_CAPABLE */

/* inode_owner_or_capable() takes mnt_idmap */
#define HAVE_INODE_OWNER_OR_CAPABLE_IDMAP 1

/* inode_owner_or_capable() takes user_ns */
/* #undef HAVE_INODE_OWNER_OR_CAPABLE_USERNS */

/* inode_set_atime_to_ts() exists in linux/fs.h */
#define HAVE_INODE_SET_ATIME_TO_TS 1

/* inode_set_ctime_to_ts() exists in linux/fs.h */
#define HAVE_INODE_SET_CTIME_TO_TS 1

/* inode_set_mtime_to_ts() exists in linux/fs.h */
#define HAVE_INODE_SET_MTIME_TO_TS 1

/* timestamp_truncate() exists */
#define HAVE_INODE_TIMESTAMP_TRUNCATE 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* iops->create() takes struct mnt_idmap* */
#define HAVE_IOPS_CREATE_IDMAP 1

/* iops->create() takes struct user_namespace* */
/* #undef HAVE_IOPS_CREATE_USERNS */

/* iops->mkdir() returns struct dentry* */
/* #undef HAVE_IOPS_MKDIR_DENTRY */

/* iops->mkdir() takes struct mnt_idmap* */
#define HAVE_IOPS_MKDIR_IDMAP 1

/* iops->mkdir() takes struct user_namespace* */
/* #undef HAVE_IOPS_MKDIR_USERNS */

/* iops->mknod() takes struct mnt_idmap* */
#define HAVE_IOPS_MKNOD_IDMAP 1

/* iops->mknod() takes struct user_namespace* */
/* #undef HAVE_IOPS_MKNOD_USERNS */

/* iops->permission() takes struct mnt_idmap* */
#define HAVE_IOPS_PERMISSION_IDMAP 1

/* iops->permission() takes struct user_namespace* */
/* #undef HAVE_IOPS_PERMISSION_USERNS */

/* iops->rename() takes struct mnt_idmap* */
#define HAVE_IOPS_RENAME_IDMAP 1

/* iops->rename() takes struct user_namespace* */
/* #undef HAVE_IOPS_RENAME_USERNS */

/* iops->symlink() takes struct mnt_idmap* */
#define HAVE_IOPS_SYMLINK_IDMAP 1

/* iops->symlink() takes struct user_namespace* */
/* #undef HAVE_IOPS_SYMLINK_USERNS */

/* iov_iter_get_pages2() is available */
#define HAVE_IOV_ITER_GET_PAGES2 1

/* iov_iter_type() is available */
#define HAVE_IOV_ITER_TYPE 1

/* Define to 1 if you have the 'issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* iter_iov() is available */
#define HAVE_ITER_IOV 1

/* iter_is_ubuf() is available */
#define HAVE_ITER_IS_UBUF 1

/* kernel has kernel_fpu_* functions */
#define HAVE_KERNEL_FPU 1

/* kernel has asm/fpu/api.h */
#define HAVE_KERNEL_FPU_API_HEADER 1

/* kernel fpu internal */
/* #undef HAVE_KERNEL_FPU_INTERNAL */

/* kernel has asm/fpu/internal.h */
/* #undef HAVE_KERNEL_FPU_INTERNAL_HEADER */

/* Define if compiler supports -Winfinite-recursion */
#define HAVE_KERNEL_INFINITE_RECURSION 1

/* kernel defines intptr_t */
#define HAVE_KERNEL_INTPTR_T 1

/* kernel has kernel_neon_* functions */
/* #undef HAVE_KERNEL_NEON */

/* kernel does stack verification */
#define HAVE_KERNEL_OBJTOOL 1

/* kernel has linux/objtool.h */
#define HAVE_KERNEL_OBJTOOL_HEADER 1

/* strlcpy() exists */
/* #undef HAVE_KERNEL_STRLCPY */

/* kernel has kmap_local_page */
#define HAVE_KMAP_LOCAL_PAGE 1

/* Define if you have [aio] */
#define HAVE_LIBAIO 1

/* Define if you have [blkid] */
#define HAVE_LIBBLKID 1

/* Define if you have [crypto] */
#define HAVE_LIBCRYPTO 1

/* Define if you have [tirpc] */
#define HAVE_LIBTIRPC 1

/* Define if you have [udev] */
#define HAVE_LIBUDEV 1

/* Define if you have [unwind] */
#define HAVE_LIBUNWIND 1

/* libunwind has unw_get_elf_filename */
/* #undef HAVE_LIBUNWIND_ELF */

/* Define if you have [uuid] */
#define HAVE_LIBUUID 1

/* building against unsupported kernel version */
/* #undef HAVE_LINUX_EXPERIMENTAL */

/* makedev() is declared in sys/mkdev.h */
/* #undef HAVE_MAKEDEV_IN_MKDEV */

/* makedev() is declared in sys/sysmacros.h */
#define HAVE_MAKEDEV_IN_SYSMACROS 1

/* Noting that make_request_fn() returns blk_qc_t */
/* #undef HAVE_MAKE_REQUEST_FN_RET_QC */

/* Define to 1 if you have the 'mlockall' function. */
#define HAVE_MLOCKALL 1

/* PG_error flag is available */
/* #undef HAVE_MM_PAGE_FLAG_ERROR */

/* page_mapping() is available */
/* #undef HAVE_MM_PAGE_MAPPING */

/* page_size() is available */
#define HAVE_MM_PAGE_SIZE 1

/* Define if host toolchain supports MOVBE */
#define HAVE_MOVBE 1

/* folio_wait_bit() exists */
#define HAVE_PAGEMAP_FOLIO_WAIT_BIT 1

/* part_to_dev() exists */
/* #undef HAVE_PART_TO_DEV */

/* iops->getattr() takes a path */
/* #undef HAVE_PATH_IOPS_GETATTR */

/* Define if host toolchain supports PCLMULQDQ */
#define HAVE_PCLMULQDQ 1

/* pin_user_pages_unlocked() is available */
#define HAVE_PIN_USER_PAGES_UNLOCKED 1

/* proc_handler ctl_table arg is const */
#define HAVE_PROC_HANDLER_CTL_TABLE_CONST 1

/* proc_ops structure exists */
#define HAVE_PROC_OPS_STRUCT 1

/* If available, contains the Python version number currently in use. */
#define HAVE_PYTHON "3.13"

/* qat is enabled and existed */
/* #undef HAVE_QAT */

/* struct reclaim_state has reclaimed */
#define HAVE_RECLAIM_STATE_RECLAIMED 1

/* register_shrinker is vararg */
/* #undef HAVE_REGISTER_SHRINKER_VARARG */

/* register_sysctl_sz exists */
#define HAVE_REGISTER_SYSCTL_SZ 1

/* register_sysctl_table exists */
/* #undef HAVE_REGISTER_SYSCTL_TABLE */

/* iops->rename() wants flags */
/* #undef HAVE_RENAME_WANTS_FLAGS */

/* revalidate_disk() is available */
/* #undef HAVE_REVALIDATE_DISK */

/* revalidate_disk_size() is available */
/* #undef HAVE_REVALIDATE_DISK_SIZE */

/* Define to 1 if you have the <security/pam_modules.h> header file. */
#define HAVE_SECURITY_PAM_MODULES_H 1

/* setattr_prepare() accepts mnt_idmap */
#define HAVE_SETATTR_PREPARE_IDMAP 1

/* setattr_prepare() is available, doesn't accept user_namespace */
/* #undef HAVE_SETATTR_PREPARE_NO_USERNS */

/* setattr_prepare() accepts user_namespace */
/* #undef HAVE_SETATTR_PREPARE_USERNS */

/* iops->set_acl() takes 4 args, arg1 is struct mnt_idmap * */
#define HAVE_SET_ACL_IDMAP_DENTRY 1

/* iops->set_acl() takes 4 args */
/* #undef HAVE_SET_ACL_USERNS */

/* iops->set_acl() takes 4 args, arg2 is struct dentry * */
/* #undef HAVE_SET_ACL_USERNS_DENTRY_ARG2 */

/* shrinker_register exists */
#define HAVE_SHRINKER_REGISTER 1

/* kernel_siginfo_t exists */
#define HAVE_SIGINFO 1

/* Define if host toolchain supports SSE */
#define HAVE_SSE 1

/* Define if host toolchain supports SSE2 */
#define HAVE_SSE2 1

/* Define if host toolchain supports SSE3 */
#define HAVE_SSE3 1

/* Define if host toolchain supports SSE4.1 */
#define HAVE_SSE4_1 1

/* Define if host toolchain supports SSE4.2 */
#define HAVE_SSE4_2 1

/* Define if host toolchain supports SSSE3 */
#define HAVE_SSSE3 1

/* STACK_FRAME_NON_STANDARD is defined */
#define HAVE_STACK_FRAME_NON_STANDARD 1

/* STACK_FRAME_NON_STANDARD asm macro is defined */
#define HAVE_STACK_FRAME_NON_STANDARD_ASM 1

/* standalone <linux/stdarg.h> exists */
#define HAVE_STANDALONE_LINUX_STDARG 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the 'strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the 'strlcpy' function. */
#define HAVE_STRLCPY 1

/* submit_bio is member of struct block_device_operations */
#define HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS 1

/* have super_block s_shrink */
/* #undef HAVE_SUPER_BLOCK_S_SHRINK */

/* have super_block s_shrink pointer */
#define HAVE_SUPER_BLOCK_S_SHRINK_PTR 1

/* have super_block s_wb_err */
#define HAVE_SUPER_BLOCK_S_WB_ERR 1

/* sync_blockdev() is declared in include/blkdev.h */
#define HAVE_SYNC_BLOCKDEV 1

/* struct kobj_type has default_groups */
#define HAVE_SYSFS_DEFAULT_GROUPS 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* timer_delete_sync is available */
#define HAVE_TIMER_DELETE_SYNC 1

/* i_op->tmpfile() uses old dentry signature */
/* #undef HAVE_TMPFILE_DENTRY */

/* i_op->tmpfile() has mnt_idmap */
#define HAVE_TMPFILE_IDMAP 1

/* i_op->tmpfile() has userns */
/* #undef HAVE_TMPFILE_USERNS */

/* totalhigh_pages() exists */
#define HAVE_TOTALHIGH_PAGES 1

/* kernel has totalram_pages() */
#define HAVE_TOTALRAM_PAGES_FUNC 1

/* Define to 1 if you have the 'udev_device_get_is_initialized' function. */
#define HAVE_UDEV_DEVICE_GET_IS_INITIALIZED 1

/* kernel has __kernel_fpu_* functions */
/* #undef HAVE_UNDERSCORE_KERNEL_FPU */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* iops->getattr() takes struct user_namespace* */
/* #undef HAVE_USERNS_IOPS_GETATTR */

/* iops->setattr() takes struct user_namespace* */
/* #undef HAVE_USERNS_IOPS_SETATTR */

/* fops->clone_file_range() is available */
/* #undef HAVE_VFS_CLONE_FILE_RANGE */

/* fops->dedupe_file_range() is available */
/* #undef HAVE_VFS_DEDUPE_FILE_RANGE */

/* filemap_dirty_folio exists */
#define HAVE_VFS_FILEMAP_DIRTY_FOLIO 1

/* generic_copy_file_range() is available */
/* #undef HAVE_VFS_GENERIC_COPY_FILE_RANGE */

/* migratepage exists */
/* #undef HAVE_VFS_MIGRATEPAGE */

/* migrate_folio exists */
#define HAVE_VFS_MIGRATE_FOLIO 1

/* address_space_operations->readpages exists */
/* #undef HAVE_VFS_READPAGES */

/* read_folio exists */
#define HAVE_VFS_READ_FOLIO 1

/* fops->remap_file_range() is available */
#define HAVE_VFS_REMAP_FILE_RANGE 1

/* __set_page_dirty_nobuffers exists */
/* #undef HAVE_VFS_SET_PAGE_DIRTY_NOBUFFERS */

/* splice_copy_file_range() is available */
#define HAVE_VFS_SPLICE_COPY_FILE_RANGE 1

/* __vmalloc page flags exists */
/* #undef HAVE_VMALLOC_PAGE_KERNEL */

/* int (*writepage_t)() takes struct folio* */
#define HAVE_WRITEPAGE_T_FOLIO 1

/* xattr_handler->get() wants dentry and inode and flags */
/* #undef HAVE_XATTR_GET_DENTRY_INODE_FLAGS */

/* xattr_handler->set() wants both dentry and inode */
/* #undef HAVE_XATTR_SET_DENTRY_INODE */

/* xattr_handler->set() takes mnt_idmap */
#define HAVE_XATTR_SET_IDMAP 1

/* xattr_handler->set() takes user_namespace */
/* #undef HAVE_XATTR_SET_USERNS */

/* Define if host toolchain supports XSAVE */
#define HAVE_XSAVE 1

/* Define if host toolchain supports XSAVEOPT */
#define HAVE_XSAVEOPT 1

/* Define if host toolchain supports XSAVES */
#define HAVE_XSAVES 1

/* ZERO_PAGE() is GPL-only */
/* #undef HAVE_ZERO_PAGE_GPL_ONLY */

/* Define if you have [z] */
#define HAVE_ZLIB 1

/* libunwind is llvm libunwind */
/* #undef IS_LIBUNWIND_LLVM */

/* kernel exports FPU functions */
#define KERNEL_EXPORTS_X86_FPU 1

/* whether the chosen libfetch is to be loaded at run-time */
#define LIBFETCH_DYNAMIC 1

/* libfetch is fetch(3) */
#define LIBFETCH_IS_FETCH 0

/* libfetch is libcurl */
#define LIBFETCH_IS_LIBCURL 1

/* soname of chosen libfetch */
#define LIBFETCH_SONAME "libcurl.so.4"

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* make_request_fn() return type */
/* #undef MAKE_REQUEST_FN_RET */

/* using complete_and_exit() instead */
#define SPL_KTHREAD_COMPLETE_AND_EXIT kthread_complete_and_exit

/* Defined for legacy compatibility. */
#define SPL_META_ALIAS ZFS_META_ALIAS

/* Defined for legacy compatibility. */
#define SPL_META_RELEASE ZFS_META_RELEASE

/* Defined for legacy compatibility. */
#define SPL_META_VERSION ZFS_META_VERSION

/* pde_data() is PDE_DATA() */
#define SPL_PDE_DATA pde_data

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
/* #undef SYSTEM_FREEBSD */

/* True if ZFS is to be compiled for a Linux system */
#define SYSTEM_LINUX 1

/* Version number of package */
#define ZFS_DEBUG 1

/* /dev/zfs minor */
#define ZFS_DEVICE_MINOR 249

/* Define the project alias string. */
#define ZFS_META_ALIAS "zfs-2.3.3-18_g00d8dc06b"

/* Define the project author. */
#define ZFS_META_AUTHOR "OpenZFS"

/* Define the project release date. */
/* #undef ZFS_META_DATA */

/* Define the maximum compatible kernel version. */
#define ZFS_META_KVER_MAX "6.15"

/* Define the minimum compatible kernel version. */
#define ZFS_META_KVER_MIN "4.18"

/* Define the project license. */
#define ZFS_META_LICENSE "CDDL"

/* Define the libtool library 'age' version information. */
/* #undef ZFS_META_LT_AGE */

/* Define the libtool library 'current' version information. */
/* #undef ZFS_META_LT_CURRENT */

/* Define the libtool library 'revision' version information. */
/* #undef ZFS_META_LT_REVISION */

/* Define the project name. */
#define ZFS_META_NAME "zfs"

/* Define the project release. */
#define ZFS_META_RELEASE "18_g00d8dc06b"

/* Define the project version. */
#define ZFS_META_VERSION "2.3.3"

/* count is located in percpu_ref.data */
#define ZFS_PERCPU_REF_COUNT_IN_DATA 1


