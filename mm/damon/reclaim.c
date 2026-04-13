// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON-based page reclamation
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

#define pr_fmt(fmt) "damon-reclaim: " fmt

#include <linux/damon.h>
#include <linux/kstrtox.h>
#include <linux/module.h>

#include "modules-common.h"

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "damon_reclaim."

/*
 * Enable or disable DAMON_RECLAIM.
 *
 * You can enable DAMON_RCLAIM by setting the value of this parameter as ``Y``.
 * Setting it as ``N`` disables DAMON_RECLAIM.  Note that DAMON_RECLAIM could
 * do no real monitoring and reclamation due to the watermarks-based activation
 * condition.  Refer to below descriptions for the watermarks parameter for
 * this.
 */
static bool enabled __read_mostly;

/*
 * Make DAMON_RECLAIM reads the input parameters again, except ``enabled``.
 *
 * Input parameters that updated while DAMON_RECLAIM is running are not applied
 * by default.  Once this parameter is set as ``Y``, DAMON_RECLAIM reads values
 * of parametrs except ``enabled`` again.  Once the re-reading is done, this
 * parameter is set as ``N``.  If invalid parameters are found while the
 * re-reading, DAMON_RECLAIM will be disabled.
 */
static bool commit_inputs __read_mostly;
module_param(commit_inputs, bool, 0600);

/*
 * Reclaim scope.
 *
 * "global" applies a single scheme across the configured global target region.
 * "per-node" applies identical schemes independently on each NUMA node that
 * has matching System RAM.
 */
static char reclaim_scope[16] __read_mostly = "global";
module_param_string(scope, reclaim_scope, sizeof(reclaim_scope), 0600);

/*
 * Time threshold for cold memory regions identification in microseconds.
 *
 * If a memory region is not accessed for this or longer time, DAMON_RECLAIM
 * identifies the region as cold, and reclaims.  120 seconds by default.
 */
static unsigned long min_age __read_mostly = 120000000;
module_param(min_age, ulong, 0600);

static struct damos_quota damon_reclaim_quota = {
	/* use up to 10 ms time, reclaim up to 128 MiB per 1 sec by default */
	.ms = 10,
	.sz = 128 * 1024 * 1024,
	.reset_interval = 1000,
	/* Within the quota, page out older regions first. */
	.weight_sz = 0,
	.weight_nr_accesses = 0,
	.weight_age = 1
};
DEFINE_DAMON_MODULES_DAMOS_QUOTAS(damon_reclaim_quota);

/*
 * Desired level of memory pressure-stall time in microseconds.
 *
 * While keeping the caps that set by other quotas, DAMON_RECLAIM automatically
 * increases and decreases the effective level of the quota aiming this level of
 * memory pressure is incurred.  System-wide ``some`` memory PSI in microseconds
 * per quota reset interval (``quota_reset_interval_ms``) is collected and
 * compared to this value to see if the aim is satisfied.  Value zero means
 * disabling this auto-tuning feature.
 *
 * Disabled by default.
 */
static unsigned long quota_mem_pressure_us __read_mostly;
module_param(quota_mem_pressure_us, ulong, 0600);

/*
 * Desired system free memory rate in [0, 1000].
 *
 * While keeping the caps that set by other quotas, DAMON_RECLAIM automatically
 * increases and decreases the effective level of the quota aiming this free
 * memory rate.  Higher values make DAMON_RECLAIM more aggressive under lower
 * free-memory conditions.  Value zero means disabling this auto-tuning feature.
 *
 * Disabled by default.
 */
static unsigned long quota_free_mem_rate __read_mostly;
module_param(quota_free_mem_rate, ulong, 0600);

/*
 * Desired system free memory in bytes.
 *
 * While keeping the caps that set by other quotas, DAMON_RECLAIM automatically
 * increases and decreases the effective level of the quota aiming this free
 * memory amount.  Higher values make DAMON_RECLAIM try to maintain a larger
 * free-memory tail.  Value zero means disabling this auto-tuning feature.
 *
 * Disabled by default.
 */
static unsigned long quota_free_mem_bytes __read_mostly;
module_param(quota_free_mem_bytes, ulong, 0600);

/*
 * User-specifiable feedback for auto-tuning of the effective quota.
 *
 * While keeping the caps that set by other quotas, DAMON_RECLAIM automatically
 * increases and decreases the effective level of the quota aiming receiving this
 * feedback of value ``10,000`` from the user.  DAMON_RECLAIM assumes the feedback
 * value and the quota are positively proportional.  Value zero means disabling
 * this auto-tuning feature.
 *
 * Disabled by default.
 *
 */
static unsigned long quota_autotune_feedback __read_mostly;
module_param(quota_autotune_feedback, ulong, 0600);

static struct damos_watermarks damon_reclaim_wmarks = {
	.metric = DAMOS_WMARK_FREE_MEM_RATE,
	.metric_nid = NUMA_NO_NODE,
	.interval = 5000000,	/* 5 seconds */
	.high = 500,		/* 50 percent */
	.mid = 400,		/* 40 percent */
	.low = 200,		/* 20 percent */
};
DEFINE_DAMON_MODULES_WMARKS_PARAMS(damon_reclaim_wmarks);

static struct damon_attrs damon_reclaim_mon_attrs = {
	.sample_interval = 5000,	/* 5 ms */
	.aggr_interval = 100000,	/* 100 ms */
	.ops_update_interval = 0,
	.min_nr_regions = 10,
	.max_nr_regions = 1000,
};
DEFINE_DAMON_MODULES_MON_ATTRS_PARAMS(damon_reclaim_mon_attrs);

/*
 * Start of the target memory region in physical address.
 *
 * The start physical address of memory region that DAMON_RECLAIM will do work
 * against.  By default, biggest System RAM is used as the region.
 */
static unsigned long monitor_region_start __read_mostly;
module_param(monitor_region_start, ulong, 0600);

/*
 * End of the target memory region in physical address.
 *
 * The end physical address of memory region that DAMON_RECLAIM will do work
 * against.  By default, biggest System RAM is used as the region.
 */
static unsigned long monitor_region_end __read_mostly;
module_param(monitor_region_end, ulong, 0600);

/*
 * Skip anonymous pages reclamation.
 *
 * If this parameter is set as ``Y``, DAMON_RECLAIM does not reclaim anonymous
 * pages.  By default, ``N``.
 */
static bool skip_anon __read_mostly;
module_param(skip_anon, bool, 0600);

/*
 * PID of the DAMON thread
 *
 * If DAMON_RECLAIM is enabled, this becomes the PID of the worker thread.
 * Else, -1.
 */
static int kdamond_pid __read_mostly = -1;
module_param(kdamond_pid, int, 0400);

static struct damos_stat damon_reclaim_stat;
DEFINE_DAMON_MODULES_DAMOS_STATS_PARAMS(damon_reclaim_stat,
		reclaim_tried_regions, reclaimed_regions, quota_exceeds);

static struct damon_ctx *ctx;

enum damon_reclaim_scope {
	DAMON_RECLAIM_SCOPE_GLOBAL,
	DAMON_RECLAIM_SCOPE_PER_NODE,
};

static int damon_reclaim_get_scope(void)
{
	if (!strcmp(reclaim_scope, "global"))
		return DAMON_RECLAIM_SCOPE_GLOBAL;
	if (!strcmp(reclaim_scope, "per-node"))
		return DAMON_RECLAIM_SCOPE_PER_NODE;
	return -EINVAL;
}

static int damon_reclaim_new_ctx(struct damon_ctx **new_ctx)
{
	struct damon_ctx *ctx;
	int err;

	ctx = damon_new_ctx();
	if (!ctx)
		return -ENOMEM;

	err = damon_select_ops(ctx, DAMON_OPS_PADDR);
	if (err) {
		damon_destroy_ctx(ctx);
		return err;
	}

	*new_ctx = ctx;
	return 0;
}

static struct damos *damon_reclaim_new_scheme(int metric_nid, int target_idx)
{
	struct damos_access_pattern pattern = {
		/* Find regions having PAGE_SIZE or larger size */
		.min_sz_region = PAGE_SIZE,
		.max_sz_region = ULONG_MAX,
		/* and not accessed at all */
		.min_nr_accesses = 0,
		.max_nr_accesses = 0,
		/* for min_age or more micro-seconds */
		.min_age_region = min_age /
			damon_reclaim_mon_attrs.aggr_interval,
		.max_age_region = UINT_MAX,
	};
	struct damos_quota quota = damon_reclaim_quota;
	struct damos_watermarks wmarks = damon_reclaim_wmarks;
	struct damos *scheme;
	struct damos_filter *filter;

	wmarks.metric_nid = metric_nid;

	scheme = damon_new_scheme(
			&pattern,
			/* page out those, as soon as found */
			DAMOS_PAGEOUT,
			/* for each aggregation interval */
			0,
			/* under the quota. */
			&quota,
			/* (De)activate this according to the watermarks. */
			&wmarks,
			NUMA_NO_NODE);
	if (!scheme)
		return NULL;

	if (target_idx >= 0) {
		filter = damos_new_filter(DAMOS_FILTER_TYPE_TARGET, false);
		if (!filter)
			goto out;
		filter->target_idx = target_idx;
		damos_add_filter(scheme, filter);
	}

	if (skip_anon) {
		filter = damos_new_filter(DAMOS_FILTER_TYPE_ANON, true);
		if (!filter)
			goto out;
		damos_add_filter(scheme, filter);
	}

	return scheme;
out:
	damon_destroy_scheme(scheme);
	return NULL;
}

static int damon_reclaim_add_quota_goals(struct damos *scheme, int metric_nid)
{
	struct damos_quota_goal *goal;

	if (quota_mem_pressure_us) {
		goal = damos_new_quota_goal(DAMOS_QUOTA_SOME_MEM_PSI_US,
				quota_mem_pressure_us);
		if (!goal)
			return -ENOMEM;
		damos_add_quota_goal(&scheme->quota, goal);
	}

	if (quota_free_mem_rate) {
		goal = damos_new_quota_goal(DAMOS_QUOTA_FREE_MEM_RATE,
				quota_free_mem_rate);
		if (!goal)
			return -ENOMEM;
		goal->nid = metric_nid;
		damos_add_quota_goal(&scheme->quota, goal);
	}

	if (quota_free_mem_bytes) {
		goal = damos_new_quota_goal(DAMOS_QUOTA_FREE_MEM_BYTES,
				quota_free_mem_bytes);
		if (!goal)
			return -ENOMEM;
		goal->nid = metric_nid;
		damos_add_quota_goal(&scheme->quota, goal);
	}

	if (quota_autotune_feedback) {
		goal = damos_new_quota_goal(DAMOS_QUOTA_USER_INPUT, 10000);
		if (!goal)
			return -ENOMEM;
		goal->current_value = quota_autotune_feedback;
		damos_add_quota_goal(&scheme->quota, goal);
	}

	return 0;
}

static int damon_reclaim_apply_parameters(void)
{
	struct damon_ctx *param_ctx;
	struct damos **schemes = NULL;
	struct damon_target *param_target;
	struct damos *scheme;
	int scope;
	int nr_schemes = 0;
	int err;

	err = damon_reclaim_new_ctx(&param_ctx);
	if (err)
		return err;

	if (!damon_reclaim_mon_attrs.aggr_interval) {
		err = -EINVAL;
		goto out;
	}
	if (quota_free_mem_rate > 1000) {
		err = -EINVAL;
		goto out;
	}
	scope = damon_reclaim_get_scope();
	if (scope < 0) {
		err = scope;
		goto out;
	}

	err = damon_set_attrs(param_ctx, &damon_reclaim_mon_attrs);
	if (err)
		goto out;

	if (scope == DAMON_RECLAIM_SCOPE_PER_NODE) {
		int nid, nr_targets = 0;

		schemes = kcalloc(nr_node_ids, sizeof(*schemes), GFP_KERNEL);
		if (!schemes) {
			err = -ENOMEM;
			goto out;
		}

		for_each_node_state(nid, N_MEMORY) {
			param_target = damon_new_target();
			if (!param_target) {
				err = -ENOMEM;
				goto out;
			}

			err = damon_set_regions_system_ram(param_target,
					monitor_region_start,
					monitor_region_end, nid);
			if (err == -ENOENT) {
				damon_free_target(param_target);
				continue;
			}
			if (err) {
				damon_free_target(param_target);
				goto out;
			}
			damon_add_target(param_ctx, param_target);

			scheme = damon_reclaim_new_scheme(nid, nr_targets);
			if (!scheme) {
				err = -ENOMEM;
				goto out;
			}
			err = damon_reclaim_add_quota_goals(scheme, nid);
			if (err) {
				damon_destroy_scheme(scheme);
				goto out;
			}
			schemes[nr_schemes++] = scheme;
			nr_targets++;
		}
		if (!nr_schemes) {
			err = -EINVAL;
			goto out;
		}
	} else {
		param_target = damon_new_target();
		if (!param_target) {
			err = -ENOMEM;
			goto out;
		}
		damon_add_target(param_ctx, param_target);

		err = damon_set_region_biggest_system_ram_default(param_target,
				&monitor_region_start, &monitor_region_end);
		if (err)
			goto out;

		scheme = damon_reclaim_new_scheme(NUMA_NO_NODE, -1);
		if (!scheme) {
			err = -ENOMEM;
			goto out;
		}
		err = damon_reclaim_add_quota_goals(scheme, NUMA_NO_NODE);
		if (err) {
			damon_destroy_scheme(scheme);
			goto out;
		}
		schemes = kcalloc(1, sizeof(*schemes), GFP_KERNEL);
		if (!schemes) {
			damon_destroy_scheme(scheme);
			err = -ENOMEM;
			goto out;
		}
		schemes[nr_schemes++] = scheme;
	}

	damon_set_schemes(param_ctx, schemes, nr_schemes);
	err = damon_commit_ctx(ctx, param_ctx);
out:
	kfree(schemes);
	damon_destroy_ctx(param_ctx);
	return err;
}

static int damon_reclaim_turn(bool on)
{
	int err;

	if (!on) {
		err = damon_stop(&ctx, 1);
		if (!err)
			kdamond_pid = -1;
		return err;
	}

	err = damon_reclaim_apply_parameters();
	if (err)
		return err;

	err = damon_start(&ctx, 1, true);
	if (err)
		return err;
	kdamond_pid = ctx->kdamond->pid;
	return 0;
}

static int damon_reclaim_enabled_store(const char *val,
		const struct kernel_param *kp)
{
	bool is_enabled = enabled;
	bool enable;
	int err;

	err = kstrtobool(val, &enable);
	if (err)
		return err;

	if (is_enabled == enable)
		return 0;

	/* Called before init function.  The function will handle this. */
	if (!ctx)
		goto set_param_out;

	err = damon_reclaim_turn(enable);
	if (err)
		return err;

set_param_out:
	enabled = enable;
	return err;
}

static const struct kernel_param_ops enabled_param_ops = {
	.set = damon_reclaim_enabled_store,
	.get = param_get_bool,
};

module_param_cb(enabled, &enabled_param_ops, &enabled, 0600);
MODULE_PARM_DESC(enabled,
	"Enable or disable DAMON_RECLAIM (default: disabled)");

static int damon_reclaim_handle_commit_inputs(void)
{
	int err;

	if (!commit_inputs)
		return 0;

	err = damon_reclaim_apply_parameters();
	commit_inputs = false;
	return err;
}

static int damon_reclaim_after_aggregation(struct damon_ctx *c)
{
	struct damos *s;

	/* update the stats parameter */
	damon_reclaim_stat = (struct damos_stat){};
	damon_for_each_scheme(s, c)
	{
		damon_reclaim_stat.nr_tried += s->stat.nr_tried;
		damon_reclaim_stat.sz_tried += s->stat.sz_tried;
		damon_reclaim_stat.nr_applied += s->stat.nr_applied;
		damon_reclaim_stat.sz_applied += s->stat.sz_applied;
		damon_reclaim_stat.qt_exceeds += s->stat.qt_exceeds;
	}

	return damon_reclaim_handle_commit_inputs();
}

static int damon_reclaim_after_wmarks_check(struct damon_ctx *c)
{
	return damon_reclaim_handle_commit_inputs();
}

static int __init damon_reclaim_init(void)
{
	int err = damon_reclaim_new_ctx(&ctx);

	if (err)
		return err;

	ctx->callback.after_wmarks_check = damon_reclaim_after_wmarks_check;
	ctx->callback.after_aggregation = damon_reclaim_after_aggregation;

	/* 'enabled' has set before this function, probably via command line */
	if (enabled)
		err = damon_reclaim_turn(true);

	return err;
}

module_init(damon_reclaim_init);
