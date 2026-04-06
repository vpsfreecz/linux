// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memcontrol.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <linux/mm.h>
#include <linux/vmstat.h>

#include <asm/page.h>

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct mem_cgroup *root_memcg, *walk_memcg, *res_memcg = NULL;
	unsigned long limit = PAGE_COUNTER_MAX;

	rcu_read_lock();

	root_memcg = walk_memcg = mem_cgroup_from_task(current);
	if (!root_memcg)
		goto not_found;

	while ((walk_memcg != root_mem_cgroup) && walk_memcg) {
		unsigned long max = mem_cgroup_get_max(walk_memcg);

		if (max < limit) {
			limit = max;
			res_memcg = walk_memcg;
		}
		walk_memcg = parent_mem_cgroup(walk_memcg);
	}

	if (limit == PAGE_COUNTER_MAX)
		goto not_found;

	WARN_ON(!css_tryget(&res_memcg->css));
	rcu_read_unlock();
	return res_memcg;

not_found:
	rcu_read_unlock();
	return NULL;
}

struct fake_sysctl_buf {
	struct mutex lock;
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
		if (fbuf->buf)
			kfree(fbuf->buf);
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

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
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

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
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
			old = xa_cmpxchg(&ns->fake_sysctl_bufs, index, NULL, fbuf,
					  GFP_KERNEL);
			if (xa_is_err(old)) {
				kfree(fbuf->buf);
				kfree(fbuf);
				return xa_err(old);
			}
			if (old) {
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
