/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSLOG_NS_H
#define _LINUX_SYSLOG_NS_H

#include <linux/slab.h>
#include <linux/syslog.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/user_namespace.h>

#ifdef CONFIG_PRINTK

extern int syslog_ns_print_to_init_ns;

/*
 * Define the average message size. This only affects the number of
 * descriptors that will be available. Underestimating is better than
 * overestimating (too many available descriptors is better than not enough).
 */
#define PRB_AVGBITS 5	/* 32 character average length */

#endif

struct printk_ringbuffer;

struct latched_seq {
	seqcount_latch_t	latch;
	u64			val[2];
};

/* Flags for a single printk record. */
enum printk_info_flags {
	LOG_NEWLINE	= 2,	/* text ended with a newline */
	LOG_CONT	= 8,	/* text is a fragment of a continuation line */
};

#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)

struct syslog_namespace {
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct ns_common	ns;
	struct kref		kref;
	struct syslog_namespace	*parent;

	char			*name;

	/*
	 * The next printk record to read after the last 'clear' command. There are
	 * two copies (updated with seqcount_latch) so that reads can locklessly
	 * access a valid value. Writers are synchronized by @syslog_lock.
	 */
	struct latched_seq	clear_seq;
	/* the next printk record to read by syslog(READ) or /proc/kmsg */
	u64			syslog_seq;

	struct mutex		syslog_lock;
	wait_queue_head_t	log_wait;
	struct printk_ringbuffer *prb;
	char			*log_buf;
	u32			log_buf_len;
	unsigned long		new_log_buf_len;

	enum printk_info_flags	syslog_prev;
	size_t			syslog_partial;
	bool			syslog_time;

	/* per ns dumper */
	spinlock_t		dump_list_lock;
	struct list_head 	dump_list;

	int			dmesg_restrict;
};

extern struct syslog_namespace init_syslog_ns;

static inline struct syslog_namespace *current_syslog_ns(void)
{
	struct user_namespace *user_ns = current_user_ns();

	return user_ns->syslog_ns;
}

extern const struct proc_ns_operations syslogns_operations;

static inline struct syslog_namespace *to_syslog_ns(struct ns_common *ns)
{
	return container_of(ns, struct syslog_namespace, ns);
}

extern struct printk_ringbuffer *syslog_ns_create_ring_buffer(struct syslog_namespace *ns);

#ifdef CONFIG_SYSLOG_NS

extern struct syslog_namespace *copy_syslog_ns(bool new, char *name,
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
