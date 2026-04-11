/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LSM_NAMESPACE_H
#define _LINUX_LSM_NAMESPACE_H

#include <linux/err.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <uapi/linux/lsm.h>

struct proc_ns_operations;
struct task_struct;
struct user_namespace;

#define LSM_NS_TYPE LSM_NS_INIT_INO

struct lsm_namespace {
	struct user_namespace	*user_ns;
	struct ns_common	 ns;
	struct lsm_namespace	*parent;
	u64			 lsmid;
	void			*backend_data;
};

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
extern struct lsm_namespace init_lsm_ns;
extern const struct proc_ns_operations lsmns_operations;

struct lsm_namespace *current_lsm_ns(void);
struct lsm_namespace *copy_lsm_ns(bool new_child, struct user_namespace *user_ns,
				  u64 lsmid,
				  struct lsm_namespace *old_ns);
int setup_lsm_namespace(struct lsm_namespace *ns);
void free_lsm_ns(struct lsm_namespace *ns);
int lsm_ns_check_userns_setns(const struct user_namespace *user_ns);

static inline struct lsm_namespace *to_lsm_ns(struct ns_common *ns)
{
	return container_of(ns, struct lsm_namespace, ns);
}

static inline struct lsm_namespace *get_lsm_ns(struct lsm_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->ns.__ns_ref);
	return ns;
}

static inline void put_lsm_ns(struct lsm_namespace *ns)
{
	if (ns && refcount_dec_and_test(&ns->ns.__ns_ref))
		free_lsm_ns(ns);
}
#else
static inline struct lsm_namespace *current_lsm_ns(void)
{
	return NULL;
}

static inline struct lsm_namespace *copy_lsm_ns(bool new_child,
						struct user_namespace *user_ns,
						u64 lsmid,
						struct lsm_namespace *old_ns)
{
	return NULL;
}

static inline int setup_lsm_namespace(struct lsm_namespace *ns)
{
	return 0;
}

static inline void free_lsm_ns(struct lsm_namespace *ns)
{
}

static inline int lsm_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	return 0;
}

static inline struct lsm_namespace *to_lsm_ns(struct ns_common *ns)
{
	return container_of(ns, struct lsm_namespace, ns);
}

static inline struct lsm_namespace *get_lsm_ns(struct lsm_namespace *ns)
{
	return ns;
}

static inline void put_lsm_ns(struct lsm_namespace *ns)
{
}
#endif /* CONFIG_SECURITY_LSM_NAMESPACE */

#endif /* _LINUX_LSM_NAMESPACE_H */
