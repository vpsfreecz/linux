/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LSM_NAMESPACE_H
#define _LINUX_LSM_NAMESPACE_H

#include <linux/err.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <uapi/linux/lsm.h>

struct proc_ns_operations;
struct cred;
struct lsm_ctx;
struct syslog_namespace;
struct task_struct;
struct user_namespace;

struct lsm_namespace_backend {
	u64 lsmid;
	int (*prepare_unshare)(const struct lsm_ctx *ctx);
	int (*create)(struct lsm_namespace *ns, struct task_struct *task,
		      struct cred *new_cred, const struct lsm_ctx *ctx);
	int (*install)(struct lsm_namespace *ns, struct task_struct *task,
		       struct cred *new_cred);
	void (*destroy)(struct lsm_namespace *ns);
};

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
				  struct task_struct *task, struct cred *new_cred,
				  const struct lsm_ctx *ctx,
				  struct lsm_namespace *old_ns);
int setup_lsm_namespace(struct lsm_namespace *ns, struct task_struct *task,
			struct cred *new_cred, const struct lsm_ctx *ctx);
void free_lsm_ns(struct lsm_namespace *ns);
int lsm_ns_check_userns_setns_from(const struct user_namespace *user_ns,
				   const struct lsm_namespace *current_ns);
int lsm_ns_check_userns_setns(const struct user_namespace *user_ns);
int register_lsm_namespace_backend(const struct lsm_namespace_backend *backend);
int lsm_ns_prepare_unshare(const struct lsm_ctx *ctx);
int lsm_ns_install_userns(struct user_namespace *user_ns,
			  struct task_struct *task, struct cred *new_cred);
void lsm_ns_clear_pending_child_request(struct task_struct *task);
bool lsm_ns_visible_lsmid(u64 lsmid);
bool lsm_ns_current_syslog_routes_lsm(u64 lsmid);

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
						struct task_struct *task,
						struct cred *new_cred,
						const struct lsm_ctx *ctx,
						struct lsm_namespace *old_ns)
{
	return NULL;
}

static inline int setup_lsm_namespace(struct lsm_namespace *ns,
				      struct task_struct *task,
				      struct cred *new_cred,
				      const struct lsm_ctx *ctx)
{
	return 0;
}

static inline void free_lsm_ns(struct lsm_namespace *ns)
{
}

static inline int lsm_ns_check_userns_setns_from(
	const struct user_namespace *user_ns,
	const struct lsm_namespace *current_ns)
{
	return 0;
}

static inline int lsm_ns_check_userns_setns(const struct user_namespace *user_ns)
{
	return 0;
}

static inline int register_lsm_namespace_backend(const struct lsm_namespace_backend *backend)
{
	return -EOPNOTSUPP;
}

static inline int lsm_ns_prepare_unshare(const struct lsm_ctx *ctx)
{
	return -EOPNOTSUPP;
}

static inline int lsm_ns_install_userns(struct user_namespace *user_ns,
					struct task_struct *task,
					struct cred *new_cred)
{
	return 0;
}

static inline void lsm_ns_clear_pending_child_request(struct task_struct *task)
{
}

static inline bool lsm_ns_visible_lsmid(u64 lsmid)
{
	return true;
}

static inline bool lsm_ns_current_syslog_routes_lsm(u64 lsmid)
{
	return false;
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
