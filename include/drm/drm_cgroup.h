/* SPDX-License-Identifier: MIT
 * Copyright 2019 Advanced Micro Devices, Inc.
 */
#ifndef __DRM_CGROUP_H__
#define __DRM_CGROUP_H__

#include <linux/cgroup_drm.h>

#ifdef CONFIG_CGROUP_DRM

/**
 * Per DRM device properties for DRM cgroup controller for the purpose
 * of storing per device defaults
 */
struct drmcg_props {
	bool			limit_enforced;

	s64			bo_limits_total_allocated_default;
	s64			bo_limits_peak_allocated_default;

	int			lgpu_capacity;
	DECLARE_BITMAP(lgpu_slots, MAX_DRMCG_LGPU_CAPACITY);
};

void drmcg_bind(struct drm_minor (*(*acq_dm)(unsigned int minor_id)),
		void (*put_ddev)(struct drm_device *dev));

void drmcg_unbind(void);

void drmcg_register_dev(struct drm_device *dev);

void drmcg_unregister_dev(struct drm_device *dev);

void drmcg_device_early_init(struct drm_device *device);

bool drmcg_try_chg_bo_alloc(struct drmcg *drmcg, struct drm_device *dev,
		size_t size);

void drmcg_unchg_bo_alloc(struct drmcg *drmcg, struct drm_device *dev,
		size_t size);

#else

struct drmcg_props {
};

static inline void drmcg_bind(
		struct drm_minor (*(*acq_dm)(unsigned int minor_id)),
		void (*put_ddev)(struct drm_device *dev))
{
}

static inline void drmcg_unbind(void)
{
}

static inline void drmcg_register_dev(struct drm_device *dev)
{
}

static inline void drmcg_unregister_dev(struct drm_device *dev)
{
}

static inline void drmcg_device_early_init(struct drm_device *device)
{
}

static inline bool drmcg_try_chg_bo_alloc(struct drmcg *drmcg,
		struct drm_device *dev,	size_t size)
{
	return true;
}

static inline void drmcg_unchg_bo_alloc(struct drmcg *drmcg,
		struct drm_device *dev,	size_t size)
{
}

#endif /* CONFIG_CGROUP_DRM */
#endif /* __DRM_CGROUP_H__ */
