/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSLOG_NS_H
#define _LINUX_SYSLOG_NS_H

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/irq_work.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syslog.h>
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
struct proc_ns_operations;

struct latched_seq {
	seqcount_latch_t	latch;
	u64			val[2];
};

#define __LOG_BUF_LEN BIT(CONFIG_LOG_BUF_SHIFT)

struct syslog_namespace {
	struct user_namespace	*user_ns;
	/* Serializes capability ownership against external reference pins. */
	spinlock_t		owner_lock;
	struct ucounts		*ucounts;
	struct ns_common	ns;
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

	/* Serializes destructive readers and the per-namespace read cursor. */
	struct mutex		syslog_lock;
	wait_queue_head_t	log_wait;
	struct irq_work		wake_up_klogd_work;
	struct printk_ringbuffer *prb;
	char			*log_buf;
	u32			log_buf_len;
	unsigned long		new_log_buf_len;

	u8			syslog_prev;
	size_t			syslog_partial;
	bool			syslog_time;

	/* per ns dumper */
	spinlock_t		dump_list_lock;
	struct list_head	dump_list;

	int			dmesg_restrict;
};

extern struct syslog_namespace init_syslog_ns;
extern struct printk_ringbuffer *prb;
extern struct latched_seq clear_seq;

void syslog_ns_wake_work_init(struct syslog_namespace *ns);
void syslog_ns_wake_work_sync(struct syslog_namespace *ns);

static inline struct syslog_namespace *current_syslog_ns(void)
{
	if (current->nsproxy && current->nsproxy->syslog_ns)
		return current->nsproxy->syslog_ns;

	return current_user_ns()->syslog_ns;
}

extern const struct proc_ns_operations syslogns_operations;

static inline struct syslog_namespace *to_syslog_ns(struct ns_common *ns)
{
	return container_of(ns, struct syslog_namespace, ns);
}

#ifdef CONFIG_SYSLOG_NS
struct syslog_namespace *copy_syslog_ns(bool new, char *name,
					struct user_namespace *user_ns,
					struct syslog_namespace *old_ns);
int setup_syslog_namespace(struct syslog_namespace *ns);
void free_syslog_ns(struct syslog_namespace *ns);
void syslog_ns_wake_all_waiters(void);
void syslog_ns_claim_user_ns(struct user_namespace *user_ns);

static inline struct syslog_namespace *get_syslog_ns(struct syslog_namespace *ns)
{
	unsigned long flags;

	if (ns) {
		spin_lock_irqsave(&ns->owner_lock, flags);
		refcount_inc(&ns->ns.__ns_ref);
		get_user_ns(ns->user_ns);
		spin_unlock_irqrestore(&ns->owner_lock, flags);
	}
	return ns;
}

static inline void put_syslog_ns(struct syslog_namespace *ns)
{
	struct user_namespace *user_ns;
	unsigned long flags;
	bool free_ns;

	if (!ns)
		return;

	spin_lock_irqsave(&ns->owner_lock, flags);
	user_ns = ns->user_ns;
	free_ns = refcount_dec_and_test(&ns->ns.__ns_ref);
	spin_unlock_irqrestore(&ns->owner_lock, flags);
	if (free_ns)
		free_syslog_ns(ns);
	put_user_ns(user_ns);
}

/* The owning user namespace holds this reference without pinning itself. */
static inline struct syslog_namespace *
get_syslog_ns_structural(struct syslog_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->ns.__ns_ref);
	return ns;
}

static inline void put_syslog_ns_structural(struct syslog_namespace *ns)
{
	if (ns && refcount_dec_and_test(&ns->ns.__ns_ref))
		free_syslog_ns(ns);
}
#else /* CONFIG_SYSLOG_NS not defined */
static inline struct syslog_namespace *copy_syslog_ns(bool new, char *name,
						      struct user_namespace *user_ns,
						      struct syslog_namespace *old_ns)
{
	return &init_syslog_ns;
}

static inline int setup_syslog_namespace(struct syslog_namespace *ns)
{
	return 0;
}

static inline void free_syslog_ns(struct syslog_namespace *ns) {}

static inline void syslog_ns_wake_all_waiters(void) {}

static inline void syslog_ns_claim_user_ns(struct user_namespace *user_ns) {}

static inline struct syslog_namespace *get_syslog_ns(struct syslog_namespace *ns)
{
	return ns;
}

static inline void put_syslog_ns(struct syslog_namespace *ns) {}

static inline struct syslog_namespace *
get_syslog_ns_structural(struct syslog_namespace *ns)
{
	return ns;
}

static inline void put_syslog_ns_structural(struct syslog_namespace *ns) {}
#endif /* CONFIG_SYSLOG_NS */
#endif /* _LINUX_SYSLOG_NS_H */
