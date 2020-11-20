// SPDX-License-Identifier: MIT
// Copyright 2019 Advanced Micro Devices, Inc.
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/cgroup_drm.h>
#include <drm/drm_file.h>
#include <drm/drm_drv.h>
#include <drm/drm_device.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_cgroup.h>

#include "cgroup-internal.h"

static struct drmcg *root_drmcg __read_mostly;

/* global mutex for drmcg across all devices */
static DEFINE_MUTEX(drmcg_mutex);

static DECLARE_BITMAP(known_devs, MAX_DRM_DEV);

static struct drm_minor (*(*acquire_drm_minor)(unsigned int minor_id));

static void (*put_drm_dev)(struct drm_device *dev);

#define DRMCG_CTF_PRIV_SIZE 3
#define DRMCG_CTF_PRIV_MASK GENMASK((DRMCG_CTF_PRIV_SIZE - 1), 0)
#define DRMCG_CTF_PRIV(res_type, f_type)  ((res_type) <<\
		DRMCG_CTF_PRIV_SIZE | (f_type))
#define DRMCG_CTF_PRIV2RESTYPE(priv) ((priv) >> DRMCG_CTF_PRIV_SIZE)
#define DRMCG_CTF_PRIV2FTYPE(priv) ((priv) & DRMCG_CTF_PRIV_MASK)


enum drmcg_file_type {
	DRMCG_FTYPE_STATS,
	DRMCG_FTYPE_LIMIT,
	DRMCG_FTYPE_DEFAULT,
};

#define LGPU_LIMITS_NAME_LIST "list"
#define LGPU_LIMITS_NAME_COUNT "count"
#define LGPU_LIMITS_NAME_WEIGHT "weight"

/**
 * drmcg_bind - Bind DRM subsystem to cgroup subsystem
 * @acq_dm: function pointer to the drm_minor_acquire function
 * @put_ddev: function pointer to the drm_dev_put function
 *
 * This function binds some functions from the DRM subsystem and make
 * them available to the drmcg subsystem.
 *
 * drmcg_unbind does the opposite of this function
 */
void drmcg_bind(struct drm_minor (*(*acq_dm)(unsigned int minor_id)),
		void (*put_ddev)(struct drm_device *dev))
{
	mutex_lock(&drmcg_mutex);
	acquire_drm_minor = acq_dm;
	put_drm_dev = put_ddev;
	mutex_unlock(&drmcg_mutex);
}
EXPORT_SYMBOL(drmcg_bind);

/**
 * drmcg_unbind - Unbind DRM subsystem from cgroup subsystem
 *
 * drmcg_bind does the opposite of this function
 */
void drmcg_unbind(void)
{
	mutex_lock(&drmcg_mutex);
	acquire_drm_minor = NULL;
	put_drm_dev = NULL;
	mutex_unlock(&drmcg_mutex);
}
EXPORT_SYMBOL(drmcg_unbind);

/* caller must hold dev->drmcg_mutex */
static inline int init_drmcg_single(struct drmcg *drmcg, struct drm_device *dev)
{
	int minor = dev->primary->index;
	struct drmcg_device_resource *ddr = drmcg->dev_resources[minor];

	if (ddr == NULL) {
		ddr = kzalloc(sizeof(struct drmcg_device_resource),
			GFP_KERNEL);

		if (!ddr)
			return -ENOMEM;
	}

	drmcg->dev_resources[minor] = ddr;

	/* set defaults here */
	ddr->bo_limits_total_allocated =
		dev->drmcg_props.bo_limits_total_allocated_default;

	ddr->bo_limits_peak_allocated =
		dev->drmcg_props.bo_limits_peak_allocated_default;

	bitmap_copy(ddr->lgpu_cfg, dev->drmcg_props.lgpu_slots,
			MAX_DRMCG_LGPU_CAPACITY);
	bitmap_copy(ddr->lgpu_stg, dev->drmcg_props.lgpu_slots,
			MAX_DRMCG_LGPU_CAPACITY);

	ddr->lgpu_weight_cfg = CGROUP_WEIGHT_DFL;

	return 0;
}

static inline void drmcg_update_cg_tree(struct drm_device *dev)
{
	struct cgroup_subsys_state *pos;
	struct drmcg *child;

	if (root_drmcg == NULL)
		return;

	/* init cgroups created before registration (i.e. root cgroup) */

	/* use cgroup_mutex instead of rcu_read_lock because
	 * init_drmcg_single has alloc which may sleep */
	mutex_lock(&cgroup_mutex);
	css_for_each_descendant_pre(pos, &root_drmcg->css) {
		child = css_to_drmcg(pos);
		init_drmcg_single(child, dev);
	}
	mutex_unlock(&cgroup_mutex);
}

static void drmcg_limit_updated(struct drm_device *dev, struct drmcg *drmcg,
		enum drmcg_res_type res_type)
{
	struct drmcg_device_resource *ddr =
		drmcg->dev_resources[dev->primary->index];
	struct css_task_iter it;
	struct task_struct *task;

	if (dev->driver->drmcg_limit_updated == NULL)
		return;

	css_task_iter_start(&drmcg->css.cgroup->self,
			CSS_TASK_ITER_PROCS, &it);
	while ((task = css_task_iter_next(&it))) {
		dev->driver->drmcg_limit_updated(dev, task,
				ddr, res_type);
	}
	css_task_iter_end(&it);
}

static void drmcg_calculate_effective_lgpu(struct drm_device *dev,
		const unsigned long *free_static,
		const unsigned long *free_weighted,
		struct drmcg *parent_drmcg)
{
	int capacity = dev->drmcg_props.lgpu_capacity;
	DECLARE_BITMAP(lgpu_unused, MAX_DRMCG_LGPU_CAPACITY);
	DECLARE_BITMAP(lgpu_by_weight, MAX_DRMCG_LGPU_CAPACITY);
	struct drmcg_device_resource *parent_ddr;
	struct drmcg_device_resource *ddr;
	int minor = dev->primary->index;
	struct cgroup_subsys_state *pos;
	struct drmcg *child;
	s64 weight_sum = 0;
	s64 unused;

	parent_ddr = parent_drmcg->dev_resources[minor];

	if (bitmap_empty(parent_ddr->lgpu_cfg, capacity))
		/* no static cfg, use weight for calculating the effective */
		bitmap_copy(parent_ddr->lgpu_stg, free_weighted, capacity);
	else
		/* lgpu statically configured, use the overlap as effective */
		bitmap_and(parent_ddr->lgpu_stg, free_static,
				parent_ddr->lgpu_cfg, capacity);

	/* calculate lgpu available for distribution by weight for children */
	bitmap_copy(lgpu_unused, parent_ddr->lgpu_stg, capacity);
	css_for_each_child(pos, &parent_drmcg->css) {
		child = css_to_drmcg(pos);
		ddr = child->dev_resources[minor];

		if (bitmap_empty(ddr->lgpu_cfg, capacity))
			/* no static allocation, participate in weight dist */
			weight_sum += ddr->lgpu_weight_cfg;
		else
			/* take out statically allocated lgpu by siblings */
			bitmap_andnot(lgpu_unused, lgpu_unused, ddr->lgpu_cfg,
					capacity);
	}

	unused = bitmap_weight(lgpu_unused, capacity);

	css_for_each_child(pos, &parent_drmcg->css) {
		child = css_to_drmcg(pos);
		ddr = child->dev_resources[minor];

		bitmap_zero(lgpu_by_weight, capacity);
		/* no static allocation, participate in weight distribution */
		if (bitmap_empty(ddr->lgpu_cfg, capacity)) {
			int c;
			int p = 0;

			for (c = ddr->lgpu_weight_cfg * unused / weight_sum;
					c > 0; c--) {
				p = find_next_bit(lgpu_unused, capacity, p);
				if (p < capacity) {
					clear_bit(p, lgpu_unused);
					set_bit(p, lgpu_by_weight);
				}
			}

		}

		drmcg_calculate_effective_lgpu(dev, parent_ddr->lgpu_stg,
				lgpu_by_weight, child);
	}
}

static void drmcg_apply_effective_lgpu(struct drm_device *dev)
{
	int capacity = dev->drmcg_props.lgpu_capacity;
	int minor = dev->primary->index;
	struct drmcg_device_resource *ddr;
	struct cgroup_subsys_state *pos;
	struct drmcg *drmcg;

	if (root_drmcg == NULL) {
		WARN_ON(root_drmcg == NULL);
		return;
	}

	rcu_read_lock();

	/* process the entire cgroup tree from root to simplify the algorithm */
	drmcg_calculate_effective_lgpu(dev, dev->drmcg_props.lgpu_slots,
			dev->drmcg_props.lgpu_slots, root_drmcg);

	/* apply changes to effective only if there is a change */
	css_for_each_descendant_pre(pos, &root_drmcg->css) {
		drmcg = css_to_drmcg(pos);
		ddr = drmcg->dev_resources[minor];

		if (!bitmap_equal(ddr->lgpu_stg, ddr->lgpu_eff, capacity)) {
			bitmap_copy(ddr->lgpu_eff, ddr->lgpu_stg, capacity);
			ddr->lgpu_count_eff =
				bitmap_weight(ddr->lgpu_eff, capacity);

			drmcg_limit_updated(dev, drmcg, DRMCG_TYPE_LGPU);
		}
	}
	rcu_read_unlock();
}

static void drmcg_apply_effective(enum drmcg_res_type type,
		struct drm_device *dev, struct drmcg *changed_drmcg)
{
	switch (type) {
	case DRMCG_TYPE_LGPU:
		drmcg_apply_effective_lgpu(dev);
		break;
	default:
		break;
	}
}

/**
 * drmcg_register_dev - register a DRM device for usage in drm cgroup
 * @dev: DRM device
 *
 * This function make a DRM device visible to the cgroup subsystem.
 * Once the drmcg is aware of the device, drmcg can start tracking and
 * control resource usage for said device.
 *
 * drmcg_unregister_dev reverse the operation of this function
 */
void drmcg_register_dev(struct drm_device *dev)
{
	if (WARN_ON(dev->primary->index >= MAX_DRM_DEV))
		return;

	mutex_lock(&drmcg_mutex);
	set_bit(dev->primary->index, known_devs);

	if (dev->driver->drmcg_custom_init)
	{
		dev->driver->drmcg_custom_init(dev, &dev->drmcg_props);

		WARN_ON(dev->drmcg_props.lgpu_capacity !=
				bitmap_weight(dev->drmcg_props.lgpu_slots,
					MAX_DRMCG_LGPU_CAPACITY));

		drmcg_update_cg_tree(dev);

		drmcg_apply_effective(DRMCG_TYPE_LGPU, dev, root_drmcg);
	}
	mutex_unlock(&drmcg_mutex);
}
EXPORT_SYMBOL(drmcg_register_dev);

/**
 * drmcg_unregister_dev - Iterate through all stored DRM minors
 * @dev: DRM device
 *
 * Unregister @dev so that drmcg no longer control resource usage
 * of @dev.  The @dev was registered to drmcg using
 * drmcg_register_dev function
 */
void drmcg_unregister_dev(struct drm_device *dev)
{
	if (WARN_ON(dev->primary->index >= MAX_DRM_DEV))
		return;

	mutex_lock(&drmcg_mutex);
	clear_bit(dev->primary->index, known_devs);
	mutex_unlock(&drmcg_mutex);
}
EXPORT_SYMBOL(drmcg_unregister_dev);

/**
 * drm_minor_for_each - Iterate through all stored DRM minors
 * @fn: Function to be called for each pointer.
 * @data: Data passed to callback function.
 *
 * The callback function will be called for each registered device, passing
 * the minor, the @drm_minor entry and @data.
 *
 * If @fn returns anything other than %0, the iteration stops and that
 * value is returned from this function.
 */
static int drm_minor_for_each(int (*fn)(int id, void *p, void *data),
		void *data)
{
	int rc = 0;

	mutex_lock(&drmcg_mutex);
	if (acquire_drm_minor) {
		unsigned int minor;
		struct drm_minor *dm;

		minor = find_next_bit(known_devs, MAX_DRM_DEV, 0);
		while (minor < MAX_DRM_DEV) {
			dm = acquire_drm_minor(minor);

			if (IS_ERR(dm))
				continue;

			rc = fn(minor, (void *)dm, data);

			put_drm_dev(dm->dev); /* release from acquire_drm_minor */

			if (rc)
				break;

			minor = find_next_bit(known_devs, MAX_DRM_DEV, minor+1);
		}
	}
	mutex_unlock(&drmcg_mutex);

	return rc;
}

static int drmcg_css_free_fn(int id, void *ptr, void *data)
{
	struct drm_minor *minor = ptr;
	struct drmcg *drmcg = data;

	if (minor->type != DRM_MINOR_PRIMARY)
		return 0;

	kfree(drmcg->dev_resources[minor->index]);

	return 0;
}

static void drmcg_css_free(struct cgroup_subsys_state *css)
{
	struct drmcg *drmcg = css_to_drmcg(css);

	drm_minor_for_each(&drmcg_css_free_fn, drmcg);

	kfree(drmcg);
}

static int init_drmcg_fn(int id, void *ptr, void *data)
{
	struct drm_minor *minor = ptr;
	struct drmcg *drmcg = data;
	int rc;

	if (minor->type != DRM_MINOR_PRIMARY)
		return 0;

	mutex_lock(&minor->dev->drmcg_mutex);
	rc = init_drmcg_single(drmcg, minor->dev);
	mutex_unlock(&minor->dev->drmcg_mutex);

	return rc;
}

static struct cgroup_subsys_state *
drmcg_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct drmcg *parent = css_to_drmcg(parent_css);
	struct drmcg *drmcg;
	int rc;

	drmcg = kzalloc(sizeof(struct drmcg), GFP_KERNEL);
	if (!drmcg)
		return ERR_PTR(-ENOMEM);

	rc = drm_minor_for_each(&init_drmcg_fn, drmcg);
	if (rc) {
		drmcg_css_free(&drmcg->css);
		return ERR_PTR(rc);
	}

	if (!parent)
		root_drmcg = drmcg;

	return &drmcg->css;
}

static void drmcg_print_stats(struct drmcg_device_resource *ddr,
		struct seq_file *sf, enum drmcg_res_type type)
{
	if (ddr == NULL) {
		seq_puts(sf, "\n");
		return;
	}

	switch (type) {
	case DRMCG_TYPE_BO_TOTAL:
		seq_printf(sf, "%lld\n", ddr->bo_stats_total_allocated);
		break;
	case DRMCG_TYPE_BO_PEAK:
		seq_printf(sf, "%lld\n", ddr->bo_stats_peak_allocated);
		break;
	case DRMCG_TYPE_BO_COUNT:
		seq_printf(sf, "%lld\n", ddr->bo_stats_count_allocated);
		break;
	default:
		seq_puts(sf, "\n");
		break;
	}
}

static void drmcg_print_limits(struct drmcg_device_resource *ddr,
		struct seq_file *sf, enum drmcg_res_type type,
		struct drm_device *dev)
{
	if (ddr == NULL) {
		seq_puts(sf, "\n");
		return;
	}

	switch (type) {
	case DRMCG_TYPE_BO_TOTAL:
		seq_printf(sf, "%lld\n", ddr->bo_limits_total_allocated);
		break;
	case DRMCG_TYPE_BO_PEAK:
		seq_printf(sf, "%lld\n", ddr->bo_limits_peak_allocated);
		break;
	case DRMCG_TYPE_LGPU:
		seq_printf(sf, "%s=%lld %s=%d %s=%*pbl\n",
				LGPU_LIMITS_NAME_WEIGHT,
				ddr->lgpu_weight_cfg,
				LGPU_LIMITS_NAME_COUNT,
				bitmap_weight(ddr->lgpu_cfg,
					dev->drmcg_props.lgpu_capacity),
				LGPU_LIMITS_NAME_LIST,
				dev->drmcg_props.lgpu_capacity,
				ddr->lgpu_cfg);
		break;
	case DRMCG_TYPE_LGPU_EFF:
		seq_printf(sf, "%s=%lld %s=%*pbl\n",
				LGPU_LIMITS_NAME_COUNT,
				ddr->lgpu_count_eff,
				LGPU_LIMITS_NAME_LIST,
				dev->drmcg_props.lgpu_capacity,
				ddr->lgpu_eff);
		break;
	default:
		seq_puts(sf, "\n");
		break;
	}
}

static void drmcg_print_default(struct drmcg_props *props,
		struct seq_file *sf, enum drmcg_res_type type)
{
	switch (type) {
	case DRMCG_TYPE_BO_TOTAL:
		seq_printf(sf, "%lld\n",
			props->bo_limits_total_allocated_default);
		break;
	case DRMCG_TYPE_BO_PEAK:
		seq_printf(sf, "%lld\n",
			props->bo_limits_peak_allocated_default);
		break;
	case DRMCG_TYPE_LGPU:
		seq_printf(sf, "%s=%d %s=%d %s=%*pbl\n",
				LGPU_LIMITS_NAME_WEIGHT,
				CGROUP_WEIGHT_DFL,
				LGPU_LIMITS_NAME_COUNT,
				bitmap_weight(props->lgpu_slots,
					props->lgpu_capacity),
				LGPU_LIMITS_NAME_LIST,
				props->lgpu_capacity,
				props->lgpu_slots);
		break;
	default:
		seq_puts(sf, "\n");
		break;
	}
}

static int drmcg_seq_show_fn(int id, void *ptr, void *data)
{
	struct drm_minor *minor = ptr;
	struct seq_file *sf = data;
	struct drmcg *drmcg = css_to_drmcg(seq_css(sf));
	enum drmcg_file_type f_type =
		DRMCG_CTF_PRIV2FTYPE(seq_cft(sf)->private);
	enum drmcg_res_type type =
		DRMCG_CTF_PRIV2RESTYPE(seq_cft(sf)->private);
	struct drmcg_device_resource *ddr;

	if (minor->type != DRM_MINOR_PRIMARY)
		return 0;

	ddr = drmcg->dev_resources[minor->index];

	seq_printf(sf, "%d:%d ", DRM_MAJOR, minor->index);

	switch (f_type) {
	case DRMCG_FTYPE_STATS:
		drmcg_print_stats(ddr, sf, type);
		break;
	case DRMCG_FTYPE_LIMIT:
		drmcg_print_limits(ddr, sf, type, minor->dev);
		break;
	case DRMCG_FTYPE_DEFAULT:
		drmcg_print_default(&minor->dev->drmcg_props, sf, type);
		break;
	default:
		seq_puts(sf, "\n");
		break;
	}

	return 0;
}

int drmcg_seq_show(struct seq_file *sf, void *v)
{
	return drm_minor_for_each(&drmcg_seq_show_fn, sf);
}

static void drmcg_pr_cft_err(const struct drmcg *drmcg,
		int rc, const char *cft_name, int minor)
{
	pr_err("drmcg: error parsing %s, minor %d, rc %d ",
			cft_name, minor, rc);
	pr_cont_cgroup_name(drmcg->css.cgroup);
	pr_cont("\n");
}

static int drmcg_process_limit_s64_val(char *sval, bool is_mem,
			s64 def_val, s64 max_val, s64 *ret_val)
{
	int rc = strcmp("max", sval);


	if (!rc)
		*ret_val = max_val;
	else {
		rc = strcmp("default", sval);

		if (!rc)
			*ret_val = def_val;
	}

	if (rc) {
		if (is_mem) {
			*ret_val = memparse(sval, NULL);
			rc = 0;
		} else {
			rc = kstrtoll(sval, 0, ret_val);
		}
	}

	if (*ret_val > max_val)
		rc = -EINVAL;

	return rc;
}

static void drmcg_nested_limit_parse(struct kernfs_open_file *of,
		struct drm_device *dev, char *attrs)
{
	DECLARE_BITMAP(tmp_bitmap, MAX_DRMCG_LGPU_CAPACITY);
	DECLARE_BITMAP(chk_bitmap, MAX_DRMCG_LGPU_CAPACITY);
	enum drmcg_res_type type =
		DRMCG_CTF_PRIV2RESTYPE(of_cft(of)->private);
	struct drmcg *drmcg = css_to_drmcg(of_css(of));
	struct drmcg_props *props = &dev->drmcg_props;
	char *cft_name = of_cft(of)->name;
	int minor = dev->primary->index;
	char *nested = strstrip(attrs);
	struct drmcg_device_resource *ddr =
		drmcg->dev_resources[minor];
	char *attr;
	char sname[256];
	char sval[256];
	s64 val;
	int rc;

	while (nested != NULL) {
		attr = strsep(&nested, " ");

		if (sscanf(attr, "%255[^=]=%255[^=]", sname, sval) != 2)
			continue;

		switch (type) {
		case DRMCG_TYPE_LGPU:
			if (strncmp(sname, LGPU_LIMITS_NAME_LIST, 256) &&
				strncmp(sname, LGPU_LIMITS_NAME_COUNT, 256) &&
				strncmp(sname, LGPU_LIMITS_NAME_WEIGHT, 256))
				continue;

			if (strncmp(sname, LGPU_LIMITS_NAME_WEIGHT, 256) &&
					(!strcmp("max", sval) ||
					!strcmp("default", sval))) {
				bitmap_copy(ddr->lgpu_cfg, props->lgpu_slots,
						props->lgpu_capacity);

				continue;
			}

			if (strncmp(sname, LGPU_LIMITS_NAME_WEIGHT, 256) == 0) {
				rc = drmcg_process_limit_s64_val(sval,
					false, CGROUP_WEIGHT_DFL,
					CGROUP_WEIGHT_MAX, &val);

				if (rc || val < CGROUP_WEIGHT_MIN ||
						val > CGROUP_WEIGHT_MAX) {
					drmcg_pr_cft_err(drmcg, rc, cft_name,
							minor);
					continue;
				}

				ddr->lgpu_weight_cfg = val;
				continue;
			}

			if (strncmp(sname, LGPU_LIMITS_NAME_COUNT, 256) == 0) {
				rc = drmcg_process_limit_s64_val(sval,
					false, props->lgpu_capacity,
					props->lgpu_capacity, &val);

				if (rc || val < 0) {
					drmcg_pr_cft_err(drmcg, rc, cft_name,
							minor);
					continue;
				}

				bitmap_zero(tmp_bitmap,
						MAX_DRMCG_LGPU_CAPACITY);
				bitmap_set(tmp_bitmap, 0, val);
			}

			if (strncmp(sname, LGPU_LIMITS_NAME_LIST, 256) == 0) {
				rc = bitmap_parselist(sval, tmp_bitmap,
						MAX_DRMCG_LGPU_CAPACITY);

				if (rc) {
					drmcg_pr_cft_err(drmcg, rc, cft_name,
							minor);
					continue;
				}

				bitmap_andnot(chk_bitmap, tmp_bitmap,
					props->lgpu_slots,
					MAX_DRMCG_LGPU_CAPACITY);

				/* user setting does not intersect with
				 * available lgpu */
				if (!bitmap_empty(chk_bitmap,
						MAX_DRMCG_LGPU_CAPACITY)) {
					drmcg_pr_cft_err(drmcg, 0, cft_name,
							minor);
					continue;
				}
			}

			bitmap_copy(ddr->lgpu_cfg, tmp_bitmap,
					props->lgpu_capacity);

			break; /* DRMCG_TYPE_LGPU */
		default:
			break;
		} /* switch (type) */
	}
}

/**
 * drmcg_limit_write - parse cgroup interface files to obtain user config
 *
 * Minimal value check to keep track of user intent.  For example, user
 * can specify limits greater than the values allowed by the parents.
 * This way, the user configuration is kept and comes into effect if and
 * when parents' limits are relaxed.
 */
static ssize_t drmcg_limit_write(struct kernfs_open_file *of, char *buf,
		size_t nbytes, loff_t off)
{
	struct drmcg *drmcg = css_to_drmcg(of_css(of));
	enum drmcg_res_type type =
		DRMCG_CTF_PRIV2RESTYPE(of_cft(of)->private);
	char *cft_name = of_cft(of)->name;
	char *limits = strstrip(buf);
	struct drmcg_device_resource *ddr;
	struct drmcg_props *props;
	struct drm_minor *dm;
	char *line;
	char sattr[256];
	s64 val;
	int rc;
	int minor;

	while (limits != NULL) {
		line =  strsep(&limits, "\n");

		if (sscanf(line,
			__stringify(DRM_MAJOR)":%u %255[^\t\n]",
							&minor, sattr) != 2) {
			pr_err("drmcg: error parsing %s ", cft_name);
			pr_cont_cgroup_name(drmcg->css.cgroup);
			pr_cont("\n");

			continue;
		}

		mutex_lock(&drmcg_mutex);
		if (acquire_drm_minor)
			dm = acquire_drm_minor(minor);
		else
			dm = NULL;
		mutex_unlock(&drmcg_mutex);

		if (IS_ERR_OR_NULL(dm)) {
			pr_err("drmcg: invalid minor %d for %s ",
					minor, cft_name);
			pr_cont_cgroup_name(drmcg->css.cgroup);
			pr_cont("\n");

			continue;
		}

		mutex_lock(&dm->dev->drmcg_mutex);
		ddr = drmcg->dev_resources[minor];
		props = &dm->dev->drmcg_props;
		switch (type) {
		case DRMCG_TYPE_BO_TOTAL:
			rc = drmcg_process_limit_s64_val(sattr, true,
				props->bo_limits_total_allocated_default,
				S64_MAX,
				&val);

			if (rc || val < 0) {
				drmcg_pr_cft_err(drmcg, rc, cft_name, minor);
				break;
			}

			ddr->bo_limits_total_allocated = val;
			break;
		case DRMCG_TYPE_BO_PEAK:
			rc = drmcg_process_limit_s64_val(sattr, true,
				props->bo_limits_peak_allocated_default,
				S64_MAX,
				&val);

			if (rc || val < 0) {
				drmcg_pr_cft_err(drmcg, rc, cft_name, minor);
				break;
			}

			ddr->bo_limits_peak_allocated = val;
			break;
		case DRMCG_TYPE_LGPU:
			drmcg_nested_limit_parse(of, dm->dev, sattr);
			break;
		default:
			break;
		}

		drmcg_apply_effective(type, dm->dev, drmcg);

		mutex_unlock(&dm->dev->drmcg_mutex);

		mutex_lock(&drmcg_mutex);
		if (put_drm_dev)
			put_drm_dev(dm->dev); /* release from acquire */
		mutex_unlock(&drmcg_mutex);
	}

	return nbytes;
}

struct cftype files[] = {
	{
		.name = "buffer.total.stats",
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_TOTAL,
						DRMCG_FTYPE_STATS),
	},
	{
		.name = "buffer.total.default",
		.seq_show = drmcg_seq_show,
		.flags = CFTYPE_ONLY_ON_ROOT,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_TOTAL,
						DRMCG_FTYPE_DEFAULT),
	},
	{
		.name = "buffer.total.max",
		.write = drmcg_limit_write,
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_TOTAL,
						DRMCG_FTYPE_LIMIT),
	},
	{
		.name = "buffer.peak.stats",
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_PEAK,
						DRMCG_FTYPE_STATS),
	},
	{
		.name = "buffer.peak.default",
		.seq_show = drmcg_seq_show,
		.flags = CFTYPE_ONLY_ON_ROOT,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_PEAK,
						DRMCG_FTYPE_DEFAULT),
	},
	{
		.name = "buffer.peak.max",
		.write = drmcg_limit_write,
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_PEAK,
						DRMCG_FTYPE_LIMIT),
	},
	{
		.name = "buffer.count.stats",
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_BO_COUNT,
						DRMCG_FTYPE_STATS),
	},
	{
		.name = "lgpu",
		.seq_show = drmcg_seq_show,
		.write = drmcg_limit_write,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_LGPU,
						DRMCG_FTYPE_LIMIT),
	},
	{
		.name = "lgpu.default",
		.seq_show = drmcg_seq_show,
		.flags = CFTYPE_ONLY_ON_ROOT,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_LGPU,
						DRMCG_FTYPE_DEFAULT),
	},
	{
		.name = "lgpu.effective",
		.seq_show = drmcg_seq_show,
		.private = DRMCG_CTF_PRIV(DRMCG_TYPE_LGPU_EFF,
						DRMCG_FTYPE_LIMIT),
	},
	{ }	/* terminate */
};

static int drmcg_online_fn(int id, void *ptr, void *data)
{
	struct drm_minor *minor = ptr;
	struct drmcg *drmcg = data;

	if (minor->type != DRM_MINOR_PRIMARY)
		return 0;

	drmcg_apply_effective(DRMCG_TYPE_LGPU, minor->dev, drmcg);

	return 0;
}

static int drmcg_css_online(struct cgroup_subsys_state *css)
{
	return drm_minor_for_each(&drmcg_online_fn, css_to_drmcg(css));
}

static int drmcg_attach_fn(int id, void *ptr, void *data)
{
	struct drm_minor *minor = ptr;
	struct task_struct *task = data;
	struct drm_device *dev;

	if (minor->type != DRM_MINOR_PRIMARY)
		return 0;

	dev = minor->dev;

	if (dev->driver->drmcg_limit_updated) {
		struct drmcg *drmcg = drmcg_get(task);
		struct drmcg_device_resource *ddr =
			drmcg->dev_resources[minor->index];
		enum drmcg_res_type type;

		for (type = 0; type < __DRMCG_TYPE_LAST; type++)
			dev->driver->drmcg_limit_updated(dev, task, ddr, type);

		drmcg_put(drmcg);
	}

	return 0;
}

static void drmcg_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *css;

	cgroup_taskset_for_each(task, css, tset)
		drm_minor_for_each(&drmcg_attach_fn, task);
}

struct cgroup_subsys drm_cgrp_subsys = {
	.css_alloc	= drmcg_css_alloc,
	.css_free	= drmcg_css_free,
	.css_online	= drmcg_css_online,
	.attach		= drmcg_attach,
	.early_init	= false,
	.legacy_cftypes	= files,
	.dfl_cftypes	= files,
};

/**
 * drmcg_device_early_init - initialize device specific resources for DRM cgroups
 * @dev: the target DRM device
 *
 * Allocate and initialize device specific resources for existing DRM cgroups.
 * Typically only the root cgroup exists before the initialization of @dev.
 */
void drmcg_device_early_init(struct drm_device *dev)
{
	dev->drmcg_props.limit_enforced = false;

	dev->drmcg_props.bo_limits_total_allocated_default = S64_MAX;
	dev->drmcg_props.bo_limits_peak_allocated_default = S64_MAX;

	dev->drmcg_props.lgpu_capacity = MAX_DRMCG_LGPU_CAPACITY;
	bitmap_fill(dev->drmcg_props.lgpu_slots, MAX_DRMCG_LGPU_CAPACITY);

	drmcg_update_cg_tree(dev);
}
EXPORT_SYMBOL(drmcg_device_early_init);

/**
 * drmcg_try_chg_bo_alloc - charge GEM buffer usage for a device and cgroup
 * @drmcg: the DRM cgroup to be charged to
 * @dev: the device the usage should be charged to
 * @size: size of the GEM buffer to be accounted for
 *
 * This function should be called when a new GEM buffer is allocated to account
 * for the utilization.  This should not be called when the buffer is shared (
 * the GEM buffer's reference count being incremented.)
 */
bool drmcg_try_chg_bo_alloc(struct drmcg *drmcg, struct drm_device *dev,
		size_t size)
{
	struct drmcg_device_resource *ddr;
	int devIdx = dev->primary->index;
	struct drmcg_props *props = &dev->drmcg_props;
	struct drmcg *drmcg_cur = drmcg;
	bool result = true;
	s64 delta = 0;

	if (drmcg == NULL)
		return true;

	mutex_lock(&dev->drmcg_mutex);
	if (props->limit_enforced) {
		for ( ; drmcg != NULL; drmcg = drmcg_parent(drmcg)) {
			ddr = drmcg->dev_resources[devIdx];
			delta = ddr->bo_limits_total_allocated -
					ddr->bo_stats_total_allocated;

			if (delta <= 0 || size > delta) {
				result = false;
				break;
			}

			if (ddr->bo_limits_peak_allocated < size) {
				result = false;
				break;
			}
		}
	}

	drmcg = drmcg_cur;

	if (result || !props->limit_enforced) {
		for ( ; drmcg != NULL; drmcg = drmcg_parent(drmcg)) {
			ddr = drmcg->dev_resources[devIdx];

			ddr->bo_stats_total_allocated += (s64)size;

			if (ddr->bo_stats_peak_allocated < (s64)size)
				ddr->bo_stats_peak_allocated = (s64)size;

			ddr->bo_stats_count_allocated++;
		}
	}
	mutex_unlock(&dev->drmcg_mutex);

	return result;
}
EXPORT_SYMBOL(drmcg_try_chg_bo_alloc);

/**
 * drmcg_unchg_bo_alloc -
 * @drmcg: the DRM cgroup to uncharge from
 * @dev: the device the usage should be removed from
 * @size: size of the GEM buffer to be accounted for
 *
 * This function should be called when the GEM buffer is about to be freed (
 * not simply when the GEM buffer's reference count is being decremented.)
 */
void drmcg_unchg_bo_alloc(struct drmcg *drmcg, struct drm_device *dev,
		size_t size)
{
	struct drmcg_device_resource *ddr;
	int devIdx = dev->primary->index;

	if (drmcg == NULL)
		return;

	mutex_lock(&dev->drmcg_mutex);
	for ( ; drmcg != NULL; drmcg = drmcg_parent(drmcg)) {
		ddr = drmcg->dev_resources[devIdx];

		ddr->bo_stats_total_allocated -= (s64)size;

		ddr->bo_stats_count_allocated--;
	}
	mutex_unlock(&dev->drmcg_mutex);
}
EXPORT_SYMBOL(drmcg_unchg_bo_alloc);
