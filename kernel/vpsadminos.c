// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernfs.h>
#include <linux/memcontrol.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <linux/mm.h>
#include <linux/vpsadminos.h>
#include <linux/vmstat.h>

#include <asm/page.h>

#ifdef CONFIG_MEMCG
unsigned long vpsadminos_memcg_swap_limit(struct mem_cgroup *memcg)
{
	unsigned long memory_max;
	unsigned long memsw_max;

	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return READ_ONCE(memcg->swap.max);

	memsw_max = READ_ONCE(memcg->memsw.max);
	if (memsw_max == PAGE_COUNTER_MAX)
		return PAGE_COUNTER_MAX;

	memory_max = READ_ONCE(memcg->memory.max);
	return vpsadminos_saturating_sub(memsw_max, memory_max);
}

unsigned long vpsadminos_memcg_swap_usage(struct mem_cgroup *memcg)
{
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return page_counter_read(&memcg->swap);

	return vpsadminos_saturating_sub(page_counter_read(&memcg->memsw),
					 page_counter_read(&memcg->memory));
}

bool vpsadminos_get_current_memcg_view(struct vpsadminos_memcg_view *view)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memory_memcg = NULL;
	struct mem_cgroup *swap_memcg = NULL;
	struct mem_cgroup *walk_memcg;
	unsigned long memory_limit = PAGE_COUNTER_MAX;
	unsigned long swap_limit = PAGE_COUNTER_MAX;

	memset(view, 0, sizeof(*view));
	if (mem_cgroup_disabled())
		return false;

	rcu_read_lock();
	while (true) {
		css = task_css(current, memory_cgrp_id);
		if (!css) {
			rcu_read_unlock();
			return false;
		}

		if (likely(css_tryget(css)))
			break;
		cpu_relax();
	}
	rcu_read_unlock();

	walk_memcg = mem_cgroup_from_css(css);

	while ((walk_memcg != root_mem_cgroup) && walk_memcg) {
		unsigned long max = READ_ONCE(walk_memcg->memory.max);
		unsigned long swap_max = vpsadminos_memcg_swap_limit(walk_memcg);

		if (max < memory_limit) {
			memory_limit = max;
			memory_memcg = walk_memcg;
		}
		if (swap_max < swap_limit) {
			swap_limit = swap_max;
			swap_memcg = walk_memcg;
		}
		walk_memcg = parent_mem_cgroup(walk_memcg);
	}

	if (!memory_memcg) {
		css_put(css);
		return false;
	}

	/*
	 * An unlimited swap hierarchy still needs an ownership domain for usage
	 * accounting. The memory owner is the least surprising fallback and
	 * preserves the historical finite-memory/unlimited-swap view.
	 */
	if (!swap_memcg)
		swap_memcg = memory_memcg;

	css_get(&memory_memcg->css);
	css_get(&swap_memcg->css);
	css_put(css);

	view->memory = memory_memcg;
	view->swap = swap_memcg;
	return true;
}

void vpsadminos_put_memcg_view(struct vpsadminos_memcg_view *view)
{
	if (view->memory)
		mem_cgroup_put(view->memory);
	if (view->swap)
		mem_cgroup_put(view->swap);
	memset(view, 0, sizeof(*view));
}

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct vpsadminos_memcg_view view;

	if (!vpsadminos_get_current_memcg_view(&view))
		return NULL;

	mem_cgroup_put(view.swap);
	return view.memory;
}
#endif

struct fake_sysctl_buf {
	/* Protects buf and count while readers and writers share this entry. */
	struct mutex lock;
	struct kernfs_node *kn;
	size_t count;
	char *buf;
};

void fake_sysctl_bufs_init(struct user_namespace *ns)
{
	xa_init(&ns->fake_sysctl_bufs);
}

void fake_sysctl_bufs_free(struct user_namespace *ns)
{
	unsigned long index;
	struct fake_sysctl_buf *fbuf;

	xa_for_each(&ns->fake_sysctl_bufs, index, fbuf) {
		kfree(fbuf->buf);
		kernfs_put(fbuf->kn);
		kfree(fbuf);
	}
	xa_destroy(&ns->fake_sysctl_bufs);
}

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf,
			   size_t count, loff_t pos, bool *handled)
{
	struct kernfs_node *parent = kernfs_get_parent(of->kn);
	struct kobject *kobj;
	const struct kobj_type *ktype;
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = of->file->f_cred->user_ns;
	struct fake_sysctl_buf *fbuf;
	size_t len;
	size_t stored;

	*handled = false;

	if (!parent)
		return 0;

	kobj = parent->priv;
	ktype = get_ktype(kobj);
	kernfs_put(parent);

	if (ktype == &module_ktype && ns != &init_user_ns) {
		fbuf = xa_load(&ns->fake_sysctl_bufs, index);
		if (fbuf) {
			*handled = true;
			if (pos < 0)
				return -EINVAL;
			mutex_lock(&fbuf->lock);
			stored = fbuf->count;
			if ((size_t)pos >= stored) {
				mutex_unlock(&fbuf->lock);
				return 0;
			}
			len = min_t(size_t, count, stored - (size_t)pos);
			if (len)
				memcpy(buf, fbuf->buf + (size_t)pos, len);
			mutex_unlock(&fbuf->lock);
			pr_debug("%s:%d: kobj %lu fbuf at %p, pos %lld, count %zu, read %zu\n",
				 __func__, __LINE__, index, (void *)fbuf,
				 pos, stored, len);
			return (ssize_t)len;
		}
	}
	return 0;
}

ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			    size_t count, loff_t pos, bool *handled)
{
	struct kernfs_node *parent;
	struct kobject *kobj;
	const struct kobj_type *ktype;
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = of->file->f_cred->user_ns;
	struct fake_sysctl_buf *fbuf;

	*handled = false;

	parent = kernfs_get_parent(of->kn);
	if (!parent)
		return 0;

	kobj = parent->priv;
	ktype = get_ktype(kobj);
	kernfs_put(parent);

	if (ktype == &module_ktype && ns != &init_user_ns) {
		*handled = true;

		if (!ns_capable(ns, CAP_SYS_ADMIN))
			return -EPERM;

		if (pos < 0 || pos > PAGE_SIZE)
			return -EINVAL;

		if (count > PAGE_SIZE - (size_t)pos)
			return -EFBIG;

		fbuf = xa_load(&ns->fake_sysctl_bufs, index);
		if (!fbuf) {
			void *old;

			fbuf = kzalloc(sizeof(*fbuf), GFP_KERNEL);
			if (!fbuf)
				return -ENOMEM;
			fbuf->buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
			if (!fbuf->buf) {
				kfree(fbuf);
				return -ENOMEM;
			}
			mutex_init(&fbuf->lock);
			fbuf->kn = of->kn;
			kernfs_get(fbuf->kn);
			old = xa_cmpxchg(&ns->fake_sysctl_bufs, index, NULL, fbuf,
					 GFP_KERNEL);
			if (xa_is_err(old)) {
				kernfs_put(fbuf->kn);
				kfree(fbuf->buf);
				kfree(fbuf);
				return xa_err(old);
			}
			if (old) {
				kernfs_put(fbuf->kn);
				kfree(fbuf->buf);
				kfree(fbuf);
				fbuf = old;
			}
		}
		mutex_lock(&fbuf->lock);
		if (!pos)
			fbuf->count = 0;
		else if ((size_t)pos > fbuf->count)
			memset(fbuf->buf + fbuf->count, 0,
			       (size_t)pos - fbuf->count);

		memcpy(fbuf->buf + (size_t)pos, buf, count);
		fbuf->count = max(fbuf->count, (size_t)pos + count);
		mutex_unlock(&fbuf->lock);
		pr_debug("%s:%d: kobj %lu, fbuf at %p, pos %lld, count %zu\n",
			 __func__, __LINE__, index, (void *)fbuf, pos, count);
		return count;
	}
	return 0;
}
