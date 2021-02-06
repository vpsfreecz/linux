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
 * Define the average message size. This only affects the number of
 * descriptors that will be available. Underestimating is better than
 * overestimating (too many available descriptors is better than not enough).
 */
#define PRB_AVGBITS 5	/* 32 character average length */

#ifdef CONFIG_PRINTK

#ifdef CONFIG_PRINTK_CALLER
#define LOG_PREFIX_MAX		48
#else
#define LOG_PREFIX_MAX		32
#endif
#define LOG_LINE_MAX		(1024 - LOG_PREFIX_MAX)

#else /* CONFIG_PRINTK */

#define LOG_LINE_MAX		0
#define LOG_PREFIX_MAX		0
#endif

/*
 * Define the average message size. This only affects the number of
 * descriptors that will be available. Underestimating is better than
 * overestimating (too many available descriptors is better than not enough).
 */
#define PRB_AVGBITS 5	/* 32 character average length */

struct printk_ringbuffer;

struct syslog_namespace {
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct ns_common	ns;
	struct kref		kref;
	struct syslog_namespace	*parent;

	/* access conflict locker */
	raw_spinlock_t		logbuf_lock;
	/* cpu currently holding logbuf_lock of ns */
	unsigned int		logbuf_cpu;

	/* index and sequence number of the first record stored in the buffer */
	u64			log_first_seq;
	/* index and sequence number of the next record stored in the buffer */
	u64			log_next_seq;
	/* the next printk record to read after the last 'clear' command */
	u64			clear_seq;
	/* the next printk record to write to the console */
	u64			console_seq;
	/* the next printk record to read by syslog(READ) or /proc/kmsg */
	u64			syslog_seq;
	/* hackish seq */
	u64			curr_log_seq;

	wait_queue_head_t	log_wait;
	struct printk_ringbuffer *prb;
	char			*log_buf;
	u32			log_buf_len;
	unsigned long		new_log_buf_len;

	enum log_flags		syslog_prev;
	size_t			syslog_partial;
	bool			syslog_time;

	/* per ns dumper */
	spinlock_t		dump_list_lock;
	struct list_head 	dump_list;

	int			dmesg_restrict;
};

extern struct syslog_namespace init_syslog_ns;

extern inline struct syslog_namespace *detect_syslog_namespace(void);

extern const struct proc_ns_operations syslogns_operations;

static inline struct syslog_namespace *to_syslog_ns(struct ns_common *ns)
{
	return container_of(ns, struct syslog_namespace, ns);
}

extern struct printk_ringbuffer *syslog_ns_create_ring_buffer(struct syslog_namespace *ns);

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
