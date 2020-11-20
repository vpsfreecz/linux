/* SPDX-License-Identifier: MIT
 * Copyright 2019 Advanced Micro Devices, Inc.
 */
#ifndef _CGROUP_DRM_H
#define _CGROUP_DRM_H

#include <linux/mutex.h>
#include <linux/cgroup.h>
#include <drm/drm_file.h>

/* limit defined per the way drm_minor_alloc operates */
#define MAX_DRM_DEV (64 * DRM_MINOR_RENDER)

#define MAX_DRMCG_LGPU_CAPACITY 256

enum drmcg_res_type {
	DRMCG_TYPE_BO_TOTAL,
	DRMCG_TYPE_BO_PEAK,
	DRMCG_TYPE_BO_COUNT,
	DRMCG_TYPE_LGPU,
	DRMCG_TYPE_LGPU_EFF,
	__DRMCG_TYPE_LAST,
};

#ifdef CONFIG_CGROUP_DRM

/**
 * Per DRM cgroup, per device resources (such as statistics and limits)
 */
struct drmcg_device_resource {
	/* for per device stats */
	s64			bo_stats_total_allocated;
	s64			bo_limits_total_allocated;

	s64			bo_stats_peak_allocated;
	s64			bo_limits_peak_allocated;

	s64			bo_stats_count_allocated;

	/**
	 * Logical GPU
	 *
	 * *_cfg are properties configured by users
	 * *_eff are the effective properties being applied to the hardware
         * *_stg is used to calculate _eff before applying to _eff
	 * after considering the entire hierarchy
	 */
	DECLARE_BITMAP(lgpu_stg, MAX_DRMCG_LGPU_CAPACITY);
	/* user configurations */
	s64			lgpu_weight_cfg;
	DECLARE_BITMAP(lgpu_cfg, MAX_DRMCG_LGPU_CAPACITY);
	/* effective lgpu for the cgroup after considering
	 * relationship with other cgroup
	 */
	s64			lgpu_count_eff;
	DECLARE_BITMAP(lgpu_eff, MAX_DRMCG_LGPU_CAPACITY);
};

/**
 * The DRM cgroup controller data structure.
 */
struct drmcg {
	struct cgroup_subsys_state	css;
	struct drmcg_device_resource	*dev_resources[MAX_DRM_DEV];
};

/**
 * css_to_drmcg - get the corresponding drmcg ref from a cgroup_subsys_state
 * @css: the target cgroup_subsys_state
 *
 * Return: DRM cgroup that contains the @css
 */
static inline struct drmcg *css_to_drmcg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct drmcg, css) : NULL;
}

/**
 * drmcg_get - get the drmcg reference that a task belongs to
 * @task: the target task
 *
 * This increase the reference count of the css that the @task belongs to
 *
 * Return: reference to the DRM cgroup the task belongs to
 */
static inline struct drmcg *drmcg_get(struct task_struct *task)
{
	return css_to_drmcg(task_get_css(task, drm_cgrp_id));
}

/**
 * drmcg_put - put a drmcg reference
 * @drmcg: the target drmcg
 *
 * Put a reference obtained via drmcg_get
 */
static inline void drmcg_put(struct drmcg *drmcg)
{
	if (drmcg)
		css_put(&drmcg->css);
}

/**
 * drmcg_parent - find the parent of a drm cgroup
 * @cg: the target drmcg
 *
 * This does not increase the reference count of the parent cgroup
 *
 * Return: parent DRM cgroup of @cg
 */
static inline struct drmcg *drmcg_parent(struct drmcg *cg)
{
	return css_to_drmcg(cg->css.parent);
}

#else /* CONFIG_CGROUP_DRM */

struct drmcg_device_resource {
};

struct drmcg {
};

static inline struct drmcg *css_to_drmcg(struct cgroup_subsys_state *css)
{
	return NULL;
}

static inline struct drmcg *drmcg_get(struct task_struct *task)
{
	return NULL;
}

static inline void drmcg_put(struct drmcg *drmcg)
{
}

static inline struct drmcg *drmcg_parent(struct drmcg *cg)
{
	return NULL;
}

#endif	/* CONFIG_CGROUP_DRM */
#endif	/* _CGROUP_DRM_H */
