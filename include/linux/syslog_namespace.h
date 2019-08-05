/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSLOG_NS_H
#define _LINUX_SYSLOG_NS_H

#include <linux/slab.h>
#include <linux/syslog.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/err.h>
#include <linux/kref.h>

/*
 * Continuation buffer, must be per syslog namespace or copying
 * to init_syslog_ns will break lines
 */

#ifdef CONFIG_PRINTK

#ifdef CONFIG_PRINTK_CALLER
#define LOG_PREFIX_MAX		48
#else
#define LOG_PREFIX_MAX		32
#endif
#define LOG_LINE_MAX		(1024 - LOG_PREFIX_MAX)

struct cont {
	char buf[LOG_LINE_MAX];
	size_t len;			/* length == 0 means unused buffer */
	u32 caller_id;			/* printk_caller_id() of first print */
	u64 ts_nsec;			/* time of first print */
	u8 level;			/* log level of first message */
	u8 facility;			/* log facility of first message */
	enum log_flags flags;		/* prefix, newline flags */
};

#else /* CONFIG_PRINTK */

#define LOG_LINE_MAX		0
#define LOG_PREFIX_MAX		0
#endif


struct syslog_namespace {
	struct user_namespace		*user_ns;
	struct ucounts			*ucounts;
	struct ns_common		ns;
	struct kref			kref;
	struct syslog_namespace		*parent;
#ifdef CONFIG_PRINTK
	struct cont			cont;
#endif

	/* access conflict locker */
	raw_spinlock_t	logbuf_lock;
	/* cpu currently holding logbuf_lock of ns */
	unsigned int	logbuf_cpu;

	u64 exclusive_console_stop_seq;

	/* index and sequence number of the first record stored in the buffer */
	u64	log_first_seq;
	u32	log_first_idx;

	/* index and sequence number of the next record stored in the buffer */
	u64	log_next_seq;
	u32	log_next_idx;

	/* the next printk record to read after the last 'clear' command */
	u64	clear_seq;
	u32	clear_idx;

	char	*log_buf;
	u32	log_buf_len;

	/* the next printk record to write to the console */
	u64	console_seq;
	u32	console_idx;

	/* the next printk record to read by syslog(READ) or /proc/kmsg */
	u64	syslog_seq;
	u32	syslog_idx;

	enum log_flags	syslog_prev;
	size_t		syslog_partial;
	bool		syslog_time;

	/* per ns dumper */
	spinlock_t	dump_list_lock;
	struct list_head dump_list;

	int	dmesg_restrict;
};

extern struct syslog_namespace init_syslog_ns;

extern inline struct syslog_namespace *detect_syslog_namespace(void);

extern const struct proc_ns_operations syslogns_operations;

static inline struct syslog_namespace *to_syslog_ns(struct ns_common *ns)
{
	return container_of(ns, struct syslog_namespace, ns);
}

#ifdef CONFIG_SYSLOG_NS

extern struct syslog_namespace *clone_syslog_ns(struct user_namespace *user_ns,
					struct syslog_namespace *old_ns);

extern struct syslog_namespace *copy_syslog_ns(bool new,
					struct user_namespace *user_ns,
					struct syslog_namespace *old_ns);

extern int setup_syslog_namespace(struct syslog_namespace *ns);

extern void free_syslog_ns(struct kref *kref);

static inline struct syslog_namespace *get_syslog_ns(
				struct syslog_namespace *ns)
{
	if (ns && (ns != &init_syslog_ns))
		kref_get(&ns->kref);
	return ns;
}

static inline void put_syslog_ns(struct syslog_namespace *ns)
{
	if (ns && (ns != &init_syslog_ns))
		kref_put(&ns->kref, free_syslog_ns);
}

#else /* CONFIG_SYSLOG_NS not defined */

static inline struct syslog_namespace *copy_syslog_ns(bool new,
					struct user_namespace *user_ns,
					struct syslog_namespace *old_ns)
{
	return &init_syslog_ns;
}

static inline void free_syslog_ns(struct kref *kref) {}

static inline struct syslog_namespace *get_syslog_ns(
				struct syslog_namespace *ns)
{
	return ns;
}

static inline void put_syslog_ns(struct syslog_namespace *ns) {}

#endif /* CONFIG_SYSLOG_NS */
#endif /* _LINUX_SYSLOG_NS_H */
