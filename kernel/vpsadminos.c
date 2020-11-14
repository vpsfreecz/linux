#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/memcontrol.h>
#include <linux/user_namespace.h>
#include <linux/xarray.h>
#include <asm/page.h>

struct mem_cgroup *get_current_most_limited_memcg(void)
{
	struct mem_cgroup *root_memcg, *walk_memcg, *res_memcg = NULL;
	unsigned long limit = PAGE_COUNTER_MAX;

	rcu_read_lock();

	root_memcg = walk_memcg = mem_cgroup_from_task(current);
	if (!root_memcg)
		goto not_found;

	while ((walk_memcg != root_mem_cgroup) && (walk_memcg != NULL)) {
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
	ssize_t count;
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
}

ssize_t fake_sysfs_kf_read(struct kernfs_open_file *of, char *buf)
{
	struct kobject *kobj = of->kn->parent->priv;
	struct kobj_type *ktype = get_ktype(kobj);
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = current_user_ns();
	struct fake_sysctl_buf *fbuf;

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		fbuf = xa_find(&ns->fake_sysctl_bufs,
		    &index, ULONG_MAX, XA_PRESENT);
		if (fbuf) {
			memcpy(buf, fbuf->buf, PAGE_SIZE);
			pr_debug("%s:%d: kobj %lu fbuf at %p count %lu\n", __func__, __LINE__, index, (void *)fbuf, fbuf->count);
			return fbuf->count;
		}
	}
	return 0;
}

ssize_t fake_sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			    size_t count, loff_t pos)
{
	struct kobject *kobj = of->kn->parent->priv;
	struct kobj_type *ktype = get_ktype(kobj);
	unsigned long index = (unsigned long)of->kn;
	struct user_namespace *ns = current_user_ns();
	struct fake_sysctl_buf *fbuf;

	if (!ns_capable(ns, CAP_SYS_ADMIN))
		return -EPERM;

	if ((count > PAGE_SIZE) || (pos > PAGE_SIZE))
		return 0;

	if ((ktype == &module_ktype) && (ns != &init_user_ns)) {
		fbuf = xa_find(&ns->fake_sysctl_bufs,
		    &index, ULONG_MAX, XA_PRESENT);
		if (!fbuf) {
			fbuf = kzalloc(sizeof(struct fake_sysctl_buf), GFP_KERNEL);
			if (!fbuf)
				return 0;
			fbuf->buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
			if (!fbuf->buf) {
				kfree(fbuf);
				return 0;
			}
			xa_store(&ns->fake_sysctl_bufs,
			    (unsigned long)of->kn, fbuf, GFP_KERNEL);
		}
		memcpy(fbuf->buf, buf, PAGE_SIZE);
		fbuf->count = count;
		pr_debug("%s:%d: kobj %lu, fbuf at %p, pos %llu, count %lu\n", __func__, __LINE__, index, (void *)fbuf, pos, count);
		return count;
	}
	return 0;
}
