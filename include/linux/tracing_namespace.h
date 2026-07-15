/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACING_NAMESPACE_H
#define _LINUX_TRACING_NAMESPACE_H

#include <linux/cleanup.h>
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
	struct pid_namespace		*pid_ns;
	struct syslog_namespace		*syslog_ns;
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
enum auth_guard_mutation_result
tracing_ns_replace_userns_default_where(struct user_namespace *user_ns,
					struct tracing_namespace *old_ns,
					struct tracing_namespace *new_ns,
					const char *where);
bool tracing_ns_matches_task_where(const struct tracing_namespace *ns,
				   const struct task_struct *task,
				   const char *where);
struct tracing_namespace *
get_current_tracing_ns_checked_where(const char *where);
bool tracing_ns_current_is_guest(void);
int setup_tracing_namespace(struct tracing_namespace *ns);
void free_tracing_ns(struct tracing_namespace *ns);
int tracing_ns_check_userns_setns_from(const struct user_namespace *user_ns,
				       const struct tracing_namespace *current_ns);
int tracing_ns_check_pidns_setns_from(const struct pid_namespace *pid_ns,
				      const struct tracing_namespace *current_ns);
int tracing_ns_check_syslogns_setns_from(const struct syslog_namespace *syslog_ns,
					 const struct tracing_namespace *current_ns);
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

DEFINE_NS_COMMON_REF_HELPERS(struct tracing_namespace, get_tracing_ns,
			     put_tracing_ns, free_tracing_ns)
#else
static inline struct tracing_namespace *current_tracing_ns(void)
{
	return NULL;
}

static inline bool tracing_ns_current_is_guest(void)
{
	return false;
}

static inline struct tracing_namespace *
get_current_tracing_ns_checked_where(const char *where)
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

static inline enum auth_guard_mutation_result
tracing_ns_replace_userns_default_where(struct user_namespace *user_ns,
					struct tracing_namespace *old_ns,
					struct tracing_namespace *new_ns,
					const char *where)
{
	return AUTH_GUARD_MUTATION_APPLIED;
}

static inline bool
tracing_ns_matches_task_where(const struct tracing_namespace *ns,
			      const struct task_struct *task, const char *where)
{
	return false;
}

static inline int setup_tracing_namespace(struct tracing_namespace *ns)
{
	return 0;
}

static inline void free_tracing_ns(struct tracing_namespace *ns) {}

static inline int tracing_ns_check_userns_setns_from(
	const struct user_namespace *user_ns,
	const struct tracing_namespace *current_ns)
{
	return 0;
}

static inline int tracing_ns_check_pidns_setns_from(
	const struct pid_namespace *pid_ns,
	const struct tracing_namespace *current_ns)
{
	return 0;
}

static inline int tracing_ns_check_syslogns_setns_from(
	const struct syslog_namespace *syslog_ns,
	const struct tracing_namespace *current_ns)
{
	return 0;
}

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
#endif /* CONFIG_TRACING_NS */

DEFINE_NS_COMMON_PUT_CLEANUP(tracing_namespace, put_tracing_ns)

#define tracing_ns_replace_userns_default(_user_ns, _old_ns, _new_ns) \
	tracing_ns_replace_userns_default_where((_user_ns), (_old_ns),     \
						  (_new_ns), __func__)
#define tracing_ns_matches_task(_ns, _task) \
	tracing_ns_matches_task_where((_ns), (_task), __func__)
#define get_current_tracing_ns_checked() \
	get_current_tracing_ns_checked_where(__func__)

#endif /* _LINUX_TRACING_NAMESPACE_H */
