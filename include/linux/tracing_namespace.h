/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACING_NAMESPACE_H
#define _LINUX_TRACING_NAMESPACE_H

#include <linux/err.h>
#include <uapi/linux/nsfs.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/syslog_namespace.h>
#include <linux/user_namespace.h>

struct proc_ns_operations;
struct task_struct;

#define TRACING_NS_TYPE TRACING_NS_INIT_INO

struct tracing_namespace {
	struct user_namespace		*user_ns;
	u64				 pid_ns_id;
	u64				 syslog_ns_id;
	struct ns_common		 ns;
	struct tracing_namespace	*parent;
};

#ifdef CONFIG_TRACING_NS
extern struct tracing_namespace init_tracing_ns;
extern const struct proc_ns_operations tracingns_operations;

struct tracing_namespace *copy_tracing_ns(bool new_child,
					  struct user_namespace *user_ns,
					  struct pid_namespace *pid_ns,
					  struct syslog_namespace *syslog_ns,
					  struct tracing_namespace *old_ns);
bool tracing_ns_matches_task(const struct tracing_namespace *ns,
			     const struct task_struct *task);
bool tracing_ns_matches_current(const struct tracing_namespace *ns);
int setup_tracing_namespace(struct tracing_namespace *ns);
void free_tracing_ns(struct tracing_namespace *ns);
int tracing_ns_check_userns_setns(const struct user_namespace *user_ns);
int tracing_ns_check_pidns_setns(const struct pid_namespace *pid_ns);
int tracing_ns_check_syslogns_setns(const struct syslog_namespace *syslog_ns);

static inline struct tracing_namespace *current_tracing_ns(void)
{
	if (current->nsproxy && current->nsproxy->tracing_ns)
		return current->nsproxy->tracing_ns;

	return &init_tracing_ns;
}

static inline struct tracing_namespace *to_tracing_ns(struct ns_common *ns)
{
	return container_of(ns, struct tracing_namespace, ns);
}

static inline struct tracing_namespace *get_tracing_ns(struct tracing_namespace *ns)
{
	if (ns) {
		refcount_inc(&ns->ns.__ns_ref);
		get_user_ns(ns->user_ns);
	}
	return ns;
}

static inline void put_tracing_ns(struct tracing_namespace *ns)
{
	struct user_namespace *user_ns;

	if (!ns)
		return;

	user_ns = ns->user_ns;
	if (refcount_dec_and_test(&ns->ns.__ns_ref))
		free_tracing_ns(ns);
	put_user_ns(user_ns);
}

/* The owning user namespace holds this reference without pinning itself. */
static inline struct tracing_namespace *
get_tracing_ns_structural(struct tracing_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->ns.__ns_ref);
	return ns;
}

static inline void put_tracing_ns_structural(struct tracing_namespace *ns)
{
	if (ns && refcount_dec_and_test(&ns->ns.__ns_ref))
		free_tracing_ns(ns);
}
#else
static inline struct tracing_namespace *current_tracing_ns(void)
{
	return NULL;
}

static inline struct tracing_namespace *to_tracing_ns(struct ns_common *ns)
{
	return container_of(ns, struct tracing_namespace, ns);
}

static inline struct tracing_namespace *copy_tracing_ns(bool new_child,
							struct user_namespace *user_ns,
							struct pid_namespace *pid_ns,
							struct syslog_namespace *syslog_ns,
							struct tracing_namespace *old_ns)
{
	return NULL;
}

static inline bool tracing_ns_matches_task(const struct tracing_namespace *ns,
					   const struct task_struct *task)
{
	return false;
}

static inline bool
tracing_ns_matches_current(const struct tracing_namespace *ns)
{
	return false;
}

static inline int setup_tracing_namespace(struct tracing_namespace *ns)
{
	return 0;
}

static inline void free_tracing_ns(struct tracing_namespace *ns) {}

static inline int tracing_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	return 0;
}

static inline int tracing_ns_check_pidns_setns(const struct pid_namespace *pid_ns)
{
	return 0;
}

static inline int tracing_ns_check_syslogns_setns(const struct syslog_namespace *syslog_ns)
{
	return 0;
}

static inline struct tracing_namespace *get_tracing_ns(struct tracing_namespace *ns)
{
	return ns;
}

static inline void put_tracing_ns(struct tracing_namespace *ns) {}

static inline struct tracing_namespace *
get_tracing_ns_structural(struct tracing_namespace *ns)
{
	return ns;
}

static inline void put_tracing_ns_structural(struct tracing_namespace *ns) {}
#endif /* CONFIG_TRACING_NS */

#endif /* _LINUX_TRACING_NAMESPACE_H */
