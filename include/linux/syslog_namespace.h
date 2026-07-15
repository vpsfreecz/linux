/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSLOG_NS_H
#define _LINUX_SYSLOG_NS_H

#include <linux/cred.h>
#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
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

#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)

struct syslog_namespace {
	struct user_namespace	*user_ns;
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

	struct mutex		syslog_lock;
	wait_queue_head_t	log_wait;
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
extern struct syslog_namespace *copy_syslog_ns(bool new, char *name,
						struct user_namespace *user_ns,
						struct syslog_namespace *old_ns);
enum auth_guard_mutation_result
syslog_ns_replace_userns_default_where(struct user_namespace *user_ns,
				       struct syslog_namespace *old_ns,
				       struct syslog_namespace *new_ns,
				       const char *where);
extern int setup_syslog_namespace(struct syslog_namespace *ns);
extern void free_syslog_ns(struct syslog_namespace *ns);

DEFINE_NS_COMMON_REF_HELPERS(struct syslog_namespace, get_syslog_ns,
			     put_syslog_ns, free_syslog_ns)
#else /* CONFIG_SYSLOG_NS not defined */
static inline struct syslog_namespace *copy_syslog_ns(bool new, char *name,
						struct user_namespace *user_ns,
						struct syslog_namespace *old_ns)
{
	return &init_syslog_ns;
}

static inline enum auth_guard_mutation_result
syslog_ns_replace_userns_default_where(struct user_namespace *user_ns,
				       struct syslog_namespace *old_ns,
				       struct syslog_namespace *new_ns,
				       const char *where)
{
	return AUTH_GUARD_MUTATION_APPLIED;
}

static inline int setup_syslog_namespace(struct syslog_namespace *ns)
{
	return 0;
}

static inline void free_syslog_ns(struct syslog_namespace *ns) {}

static inline struct syslog_namespace *get_syslog_ns(struct syslog_namespace *ns)
{
	return ns;
}

static inline void put_syslog_ns(struct syslog_namespace *ns) {}
#endif /* CONFIG_SYSLOG_NS */

DEFINE_NS_COMMON_PUT_CLEANUP(syslog_namespace, put_syslog_ns)

#define syslog_ns_replace_userns_default(_user_ns, _old_ns, _new_ns) \
	syslog_ns_replace_userns_default_where((_user_ns), (_old_ns),     \
						 (_new_ns), __func__)

DEFINE_STATIC_CURRENT_NSPROXY_MEMBER_GETTER(get_current_syslog_ns_checked,
					    struct syslog_namespace, syslog_ns,
					    get_syslog_ns, put_syslog_ns)

#define get_current_syslog_ns_checked() \
	get_current_syslog_ns_checked_where(__func__)

#ifdef CONFIG_AUTH_GUARD
struct syslog_namespace *
get_syslog_ns_from_userns_checked_where(const struct user_namespace *user_ns,
					const char *where);
#else
static inline struct syslog_namespace *
get_syslog_ns_from_userns_checked_where(const struct user_namespace *user_ns,
					const char *where)
{
	if (!user_ns)
		return ERR_PTR(-EINVAL);
	return get_syslog_ns(READ_ONCE(user_ns->syslog_ns) ?: &init_syslog_ns);
}
#endif

#define get_syslog_ns_from_userns_checked(_user_ns) \
	get_syslog_ns_from_userns_checked_where((_user_ns), __func__)
#endif /* _LINUX_SYSLOG_NS_H */
