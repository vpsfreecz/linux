/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPSADMINOS_H
#define _LINUX_VPSADMINOS_H

#include <linux/cred.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct dentry;
struct kernfs_open_file;
struct mem_cgroup;
struct proc_dir_entry;
struct user_namespace;
struct vpsa_kernfs_filter_view;

enum vpsa_kernfs_filter_decision {
	VPSA_KERNFS_FILTER_DECISION_ALLOW = 0,
	VPSA_KERNFS_FILTER_DECISION_DENY,
	VPSA_KERNFS_FILTER_DECISION_HIDE,
};

struct vpsadminos_memcg_view {
	struct mem_cgroup *memory;
	struct mem_cgroup *swap;
};

static inline unsigned long
vpsadminos_saturating_sub(unsigned long minuend, unsigned long subtrahend)
{
	return minuend > subtrahend ? minuend - subtrahend : 0;
}

static inline unsigned long
vpsadminos_saturating_add(unsigned long addend1, unsigned long addend2)
{
	return addend1 > ~0UL - addend2 ? ~0UL : addend1 + addend2;
}

#ifdef CONFIG_MEMCG
bool vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view);
void vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view);
unsigned long vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg);
unsigned long vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg);
struct mem_cgroup *get_current_most_limited_memcg(void);
#else
static inline bool
vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view)
{
	view->memory = NULL;
	view->swap = NULL;
	return false;
}

static inline void
vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view)
{
	view->memory = NULL;
	view->swap = NULL;
}

static inline unsigned long
vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg)
{
	return 0;
}

static inline unsigned long
vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg)
{
	return 0;
}

static inline struct mem_cgroup *get_current_most_limited_memcg(void)
{
	return NULL;
}
#endif

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled);
ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			    size_t count, loff_t pos, bool *handled);
void fake_sysctl_bufs_init(struct user_namespace *ns);
void fake_sysctl_bufs_free(struct user_namespace *ns);

extern struct proc_dir_entry *proc_vpsadminos;

bool vpsa_kernfs_filter_subject_restricted_userns(const struct user_namespace *ns);

static inline bool vpsa_kernfs_filter_subject_restricted_current(void)
{
	return vpsa_kernfs_filter_subject_restricted_userns(current_user_ns());
}

u64 vpsa_kernfs_filter_generation(void);
bool vpsa_kernfs_filter_dentry_visibility_stale(const struct dentry *dentry);
void vpsa_kernfs_filter_dentry_set_visibility_token(struct dentry *dentry);
void vpsa_kernfs_filter_dentry_set_visibility_token_value(struct dentry *dentry,
							  unsigned long token);

struct vpsa_kernfs_filter_view *vpsa_kernfs_filter_view_open(void);
void vpsa_kernfs_filter_view_close(struct vpsa_kernfs_filter_view *view);
unsigned long vpsa_kernfs_filter_view_visibility_token(const struct vpsa_kernfs_filter_view *view);
enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_path_unavailable(unsigned int mask,
				    const struct vpsa_kernfs_filter_view *view);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_proc_path_decide_view(const char *const *segments,
					 const u16 *segment_lens,
				    u16 depth, unsigned int mask,
				    const struct vpsa_kernfs_filter_view *view);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_proc_path_decide(const char *const *segments, const u16 *segment_lens,
				    u16 depth, unsigned int mask);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_sysfs_path_decide_view(const char *const *segments,
					  const u16 *segment_lens,
				     u16 depth, unsigned int mask,
				     const struct vpsa_kernfs_filter_view *view);

enum vpsa_kernfs_filter_decision
vpsa_kernfs_filter_sysfs_path_decide(const char *const *segments, const u16 *segment_lens,
				     u16 depth, unsigned int mask);

#endif /* _LINUX_VPSADMINOS_H */
