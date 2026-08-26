// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * transition.c - Kernel Live Patching transition functions
 *
 * Copyright (C) 2015-2016 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/cpu.h>
#include <linux/overflow.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/sort.h>
#include <linux/stacktrace.h>
#include <linux/static_call.h>
#include <linux/vpsadminos-livepatch-build.h>
#include <linux/vpsadminos-livepatch-foundation.h>
#include "core.h"
#include "patch.h"
#include "transition.h"

#ifdef CONFIG_LIVEPATCH
#include "kpatch-macros.h"
#endif

#define MAX_STACK_ENTRIES  100
static DEFINE_PER_CPU(unsigned long[MAX_STACK_ENTRIES], klp_stack_entries);

#define STACK_ERR_BUF_SIZE 128

#define SIGNALS_TIMEOUT 15

#define KLP_TASK_BATCH_SIZE 256

struct klp_patch *klp_transition_patch;

static int klp_target_state = KLP_TRANSITION_IDLE;

static unsigned int klp_signals_cnt;

enum klp_switch_path {
	KLP_SWITCH_WORKER,
	KLP_SWITCH_SCHED,
	KLP_SWITCH_IDLE,
};

struct klp_transition_range {
	unsigned long start;
	unsigned long end;
	const char *name;
};

struct klp_transition_progress {
	u64 started_ns;
	u64 tasklist_ns;
	u64 batch_ns;
	atomic64_t worker_switches;
	atomic64_t scheduler_switches;
	atomic64_t idle_switches;
	u64 worker_reschedules;
	u64 snapshot_capacity;
	u64 snapshot_tasks;
	u64 snapshot_overflows;
	u64 snapshot_generation;
	u64 snapshot_retries;
	u64 allocation_failures;
	u64 pending_tasks;
	u64 pending_running;
	u64 pending_waking;
	u64 pending_sleeping;
	u64 pending_idle;
	atomic64_t range_lookups;
	atomic64_t range_steps;
	atomic64_t range_max_steps;
	u32 range_count;
	bool complete;
};

static struct klp_transition_range *klp_patching_ranges;
static struct klp_transition_range *klp_unpatching_ranges;
static struct module **klp_transition_modules;
static unsigned int klp_transition_module_count;
static unsigned int klp_transition_range_count;
static struct klp_transition_progress klp_progress;
static atomic64_t klp_task_generation = ATOMIC64_INIT(1);

struct vpsadminos_klp_completion {
	struct list_head node;
	struct module *owner;
	struct vpsadminos_klp_id artifact_id;
	vpsadminos_klp_terminal_fn complete;
	void *data;
	bool active;
};

struct vpsadminos_klp_target_generation {
	struct list_head node;
	struct module *mod;
	u64 generation;
	u32 claims;
};

struct vpsadminos_klp_target_token {
	struct vpsadminos_klp_target_generation *target;
	u64 generation;
};

struct vpsadminos_klp_absorb_target {
	struct list_head node;
	struct module *mod;
};

struct vpsadminos_klp_foundation_absorb {
	struct vpsadminos_klp_foundation_state *predecessor;
	struct vpsadminos_klp_foundation_state *successor;
	struct module *checkpoint;
	struct list_head targets;
};

static LIST_HEAD(vpsadminos_klp_completions);
static LIST_HEAD(vpsadminos_klp_target_generations);
static u64 vpsadminos_klp_next_target_generation = 1;
static struct vpsadminos_klp_foundation_state vpsadminos_foundation;

static int vpsadminos_klp_register_completion(
		struct vpsadminos_klp_foundation_state *state,
		struct module *owner, const struct vpsadminos_klp_id *artifact_id,
		vpsadminos_klp_terminal_fn complete, void *data);
static void vpsadminos_klp_cancel_completion(
		struct vpsadminos_klp_foundation_state *state,
		struct module *owner);
static void vpsadminos_klp_foundation_complete_transition(
		struct vpsadminos_klp_foundation_state *state,
		struct klp_patch *patch);
static void vpsadminos_klp_foundation_deactivate(
		struct vpsadminos_klp_foundation_state *state);
static int vpsadminos_klp_target_claim(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod, const char *object_name,
		struct vpsadminos_klp_target_token **tokenp);
static void vpsadminos_klp_target_release(
		struct vpsadminos_klp_foundation_state *state,
		struct vpsadminos_klp_target_token *token);
static u64 vpsadminos_klp_target_generation(
		struct vpsadminos_klp_foundation_state *state,
		const struct vpsadminos_klp_target_token *token);
static void vpsadminos_klp_target_retire(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod);
static int vpsadminos_klp_target_import(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod, u64 generation);
static int vpsadminos_klp_foundation_prepare_absorb(
		struct vpsadminos_klp_foundation_state *state,
		struct module *checkpoint,
		struct vpsadminos_klp_foundation_state *successor,
		const struct vpsadminos_klp_id *expected, u32 expected_count,
		struct vpsadminos_klp_foundation_absorb **preparedp);
static void vpsadminos_klp_foundation_abort_absorb(
		struct vpsadminos_klp_foundation_absorb *prepared);
static void vpsadminos_klp_foundation_commit_absorb(
		struct vpsadminos_klp_foundation_absorb *prepared);

static struct vpsadminos_klp_foundation_state vpsadminos_foundation = {
	.magic = VPSADMINOS_KLP_FOUNDATION_MAGIC,
	.abi_version = VPSADMINOS_KLP_FOUNDATION_STATE_VERSION,
	.register_completion = vpsadminos_klp_register_completion,
	.cancel_completion = vpsadminos_klp_cancel_completion,
	.prepare_transition = klp_prepare_transition,
	.complete_transition = vpsadminos_klp_foundation_complete_transition,
	.deactivate = vpsadminos_klp_foundation_deactivate,
	.target_claim = vpsadminos_klp_target_claim,
	.target_release = vpsadminos_klp_target_release,
	.target_generation = vpsadminos_klp_target_generation,
	.target_retire = vpsadminos_klp_target_retire,
	.target_import = vpsadminos_klp_target_import,
	.prepare_absorb = vpsadminos_klp_foundation_prepare_absorb,
	.abort_absorb = vpsadminos_klp_foundation_abort_absorb,
	.commit_absorb = vpsadminos_klp_foundation_commit_absorb,
};

#if LIVEPATCH_IS_FOUNDATION || LIVEPATCH_IS_CHECKPOINT
static struct klp_state vpsadminos_foundation_klp_state
__section(".kpatch.system_states") __used
__aligned(__alignof__(struct klp_state)) = {
	.id = VPSADMINOS_KLP_FOUNDATION_STATE_ID,
	.version = VPSADMINOS_KLP_FOUNDATION_STATE_VERSION,
	.data = &vpsadminos_foundation,
};
#endif

static bool vpsadminos_klp_foundation_state_valid(
		struct vpsadminos_klp_foundation_state *state)
{
	return state == &vpsadminos_foundation &&
	       state->magic == VPSADMINOS_KLP_FOUNDATION_MAGIC &&
	       state->abi_version == VPSADMINOS_KLP_FOUNDATION_STATE_VERSION;
}

static const struct vpsadminos_klp_artifact_spec
vpsadminos_klp_foundation_anchor_spec = {
	.module_name = "livepatch_6",
	.artifact_id = VPSADMINOS_KLP_ID(VPSADMINOS_KLP_V6_ANCHOR_ID_HI,
					 VPSADMINOS_KLP_V6_ANCHOR_ID_LO),
	.inventory_id = VPSADMINOS_KLP_ID(LIVEPATCH_ANCHOR_INVENTORY_ID_HI,
					  LIVEPATCH_ANCHOR_INVENTORY_ID_LO),
	.function_count = LIVEPATCH_ANCHOR_FUNCTIONS,
	.order = 0,
	.replace = true,
};

static const struct vpsadminos_klp_artifact_spec
vpsadminos_klp_foundation_guard_spec = {
	.module_name = "livepatch_transition_guard",
	.artifact_id = VPSADMINOS_KLP_ID(VPSADMINOS_KLP_V7_GUARD_ID_HI,
					 VPSADMINOS_KLP_V7_GUARD_ID_LO),
	.inventory_id = VPSADMINOS_KLP_ID(LIVEPATCH_GUARD_INVENTORY_ID_HI,
					  LIVEPATCH_GUARD_INVENTORY_ID_LO),
	.function_count = LIVEPATCH_GUARD_FUNCTIONS,
	.order = 1,
	.replace = false,
};

static const struct vpsadminos_klp_artifact_spec
vpsadminos_klp_foundation_self_spec = {
	.module_name = "lp61295_foundation",
	.artifact_id = VPSADMINOS_KLP_ID(VPSADMINOS_KLP_V7_FOUNDATION_ID_HI,
					 VPSADMINOS_KLP_V7_FOUNDATION_ID_LO),
	.inventory_id = VPSADMINOS_KLP_ID(LIVEPATCH_INVENTORY_ID_HI,
					  LIVEPATCH_INVENTORY_ID_LO),
	.function_count = LIVEPATCH_EXPECTED_FUNCTIONS,
	.order = 2,
	.replace = false,
};

static struct vpsadminos_klp_completion *
vpsadminos_klp_find_completion(struct module *owner)
{
	struct vpsadminos_klp_completion *completion;

	list_for_each_entry(completion, &vpsadminos_klp_completions, node)
		if (completion->owner == owner)
			return completion;
	return NULL;
}

static int vpsadminos_klp_register_completion(
		struct vpsadminos_klp_foundation_state *state,
		struct module *owner, const struct vpsadminos_klp_id *artifact_id,
		vpsadminos_klp_terminal_fn complete, void *data)
{
	struct vpsadminos_klp_completion *registration;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !owner ||
	    !artifact_id || vpsadminos_klp_id_is_zero(artifact_id) || !complete ||
	    state->absorbing || !klp_transition_patch ||
	    klp_transition_patch->mod != owner ||
	    vpsadminos_klp_find_completion(owner))
		return -EINVAL;
	registration = kzalloc(sizeof(*registration), GFP_KERNEL);
	if (!registration)
		return -ENOMEM;
	registration->owner = owner;
	registration->artifact_id = *artifact_id;
	registration->complete = complete;
	registration->data = data;
	list_add_tail(&registration->node, &vpsadminos_klp_completions);
	return 0;
}

static void vpsadminos_klp_cancel_completion(
		struct vpsadminos_klp_foundation_state *state,
		struct module *owner)
{
	struct vpsadminos_klp_completion *registration;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !owner)
		return;
	registration = vpsadminos_klp_find_completion(owner);
	if (!registration || registration->active)
		return;
	list_del(&registration->node);
	kfree(registration);
}

static void vpsadminos_klp_foundation_complete_transition(
		struct vpsadminos_klp_foundation_state *state,
		struct klp_patch *patch)
{
	struct vpsadminos_klp_completion *registration;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !patch)
		return;
	registration = vpsadminos_klp_find_completion(patch->mod);
	if (!registration)
		return;
	if (patch->enabled) {
		if (registration->active)
			return;
		registration->active = true;
		registration->complete(registration->owner, true,
				       registration->data);
		return;
	}
	if (!registration->active)
		return;
	registration->complete(registration->owner, false,
			       registration->data);
	list_del(&registration->node);
	kfree(registration);
}

static void vpsadminos_klp_foundation_deactivate(
		struct vpsadminos_klp_foundation_state *state)
{
	struct vpsadminos_klp_target_generation *target, *tmp;
	struct vpsadminos_klp_dependency_state *dependency;

	lockdep_assert_held(&klp_mutex);
	if (WARN_ON_ONCE(!vpsadminos_klp_foundation_state_valid(state) ||
			 !state->active || !state->dependency || !state->artifact))
		return;
	list_for_each_entry(target, &vpsadminos_klp_target_generations, node)
		if (WARN_ON_ONCE(target->claims))
			return;
	list_for_each_entry_safe(target, tmp,
				 &vpsadminos_klp_target_generations, node) {
		list_del(&target->node);
		kfree(target);
	}
	dependency = state->dependency;
	smp_store_release(&state->active, false);
	WRITE_ONCE(dependency->foundation, NULL);
	dependency->deactivate(dependency, state->artifact);
	WRITE_ONCE(state->artifact, NULL);
	WRITE_ONCE(state->dependency, NULL);
	WRITE_ONCE(state->owner, NULL);
}

static struct vpsadminos_klp_target_generation *
vpsadminos_klp_find_target_generation(struct module *mod)
{
	struct vpsadminos_klp_target_generation *target;

	list_for_each_entry(target, &vpsadminos_klp_target_generations, node)
		if (target->mod == mod)
			return target;
	return NULL;
}

static int vpsadminos_klp_target_claim(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod, const char *object_name,
		struct vpsadminos_klp_target_token **tokenp)
{
	struct vpsadminos_klp_target_generation *target;
	struct vpsadminos_klp_target_token *token;
	bool prepared;
#if LIVEPATCH_IS_CHECKPOINT
	bool provisional;
#endif
	bool available;
	bool created = false;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state))
		return -EINVAL;
	prepared = !state->active && state->owner && state->artifact &&
		   state->dependency && klp_transition_patch &&
		   klp_transition_patch->mod == state->owner &&
		   klp_transition_patch->replace;
#if LIVEPATCH_IS_CHECKPOINT
	/*
	 * The cumulative producer keeps its vmlinux coordinator last so reverse
	 * cleanup is terminal.  Modular callbacks can therefore run before that
	 * coordinator has attached the checkpoint's dependency and artifact
	 * tokens.  Their allocations are provisional, remain inactive, and are
	 * self-unwound if any later pre-patch work rejects the transition.
	 */
	provisional = !state->active && klp_transition_patch &&
		      klp_transition_patch->replace &&
		      klp_transition_patch->mod &&
		      !strcmp(klp_transition_patch->mod->name, "livepatch_7");
#endif
	available = state->active || prepared;
#if LIVEPATCH_IS_CHECKPOINT
	available = available || provisional;
#endif
	if (!available || state->absorbing || !mod || !object_name || !tokenp ||
	    strcmp(mod->name, object_name) ||
	    (mod->state != MODULE_STATE_LIVE &&
	     mod->state != MODULE_STATE_COMING))
		return -EINVAL;
	*tokenp = NULL;
	target = vpsadminos_klp_find_target_generation(mod);
	if (!target) {
		if (!vpsadminos_klp_next_target_generation)
			return -EOVERFLOW;
		target = kzalloc(sizeof(*target), GFP_KERNEL);
		if (!target)
			return -ENOMEM;
		target->mod = mod;
		target->generation = vpsadminos_klp_next_target_generation++;
		list_add_tail(&target->node,
			      &vpsadminos_klp_target_generations);
		created = true;
	}
	if (target->claims == UINT_MAX)
		goto overflow;
	token = kzalloc(sizeof(*token), GFP_KERNEL);
	if (!token)
		goto no_memory;
	target->claims++;
	token->target = target;
	token->generation = target->generation;
	*tokenp = token;
	return 0;

overflow:
	if (created) {
		list_del(&target->node);
		kfree(target);
	}
	return -EOVERFLOW;
no_memory:
	if (created) {
		list_del(&target->node);
		kfree(target);
	}
	return -ENOMEM;
}

static void vpsadminos_klp_target_release(
		struct vpsadminos_klp_foundation_state *state,
		struct vpsadminos_klp_target_token *token)
{
	lockdep_assert_held(&klp_mutex);
	if (!token)
		return;
	if (WARN_ON_ONCE(!vpsadminos_klp_foundation_state_valid(state) ||
			 !token->target || !token->target->claims ||
			 token->generation != token->target->generation))
		return;
	token->target->claims--;
	if (!token->target->claims && !state->active) {
		list_del(&token->target->node);
		kfree(token->target);
	}
	kfree(token);
}

#if LIVEPATCH_IS_CHECKPOINT
int vpsadminos_klp_checkpoint_target_claim(struct klp_object *obj,
					   struct vpsadminos_klp_target_token **tokenp)
{
	struct vpsadminos_klp_foundation_state *foundation;
	struct klp_patch *patch = vpsadminos_klp_object_patch(obj);
	struct klp_state *record;
	int ret;

	if (!patch || !obj->name || !obj->mod || !tokenp || *tokenp)
		return -EINVAL;
	record = vpsadminos_klp_patch_state(
		patch, VPSADMINOS_KLP_FOUNDATION_STATE_ID);
	foundation = record ? record->data : NULL;
	if (!vpsadminos_klp_foundation_state_valid(foundation) ||
	    !foundation->target_claim || !foundation->target_release ||
	    !foundation->target_generation)
		return -EINVAL;
	ret = foundation->target_claim(foundation, obj->mod, obj->name, tokenp);
	if (ret)
		return ret;
	if (!foundation->target_generation(foundation, *tokenp)) {
		foundation->target_release(foundation, *tokenp);
		*tokenp = NULL;
		return -EINVAL;
	}
	return 0;
}

void vpsadminos_klp_checkpoint_target_release(struct klp_object *obj,
					      struct vpsadminos_klp_target_token **tokenp)
{
	struct vpsadminos_klp_foundation_state *foundation;
	struct klp_patch *patch = vpsadminos_klp_object_patch(obj);
	struct klp_state *record;

	if (!patch || !tokenp || !*tokenp)
		return;
	record = vpsadminos_klp_patch_state(
		patch, VPSADMINOS_KLP_FOUNDATION_STATE_ID);
	foundation = record ? record->data : NULL;
	if (WARN_ON_ONCE(!vpsadminos_klp_foundation_state_valid(foundation) ||
			 !foundation->target_release))
		return;
	foundation->target_release(foundation, *tokenp);
	*tokenp = NULL;
}
#endif

static u64 vpsadminos_klp_target_generation(
		struct vpsadminos_klp_foundation_state *state,
		const struct vpsadminos_klp_target_token *token)
{
	if (!vpsadminos_klp_foundation_state_valid(state) || !token ||
	    !token->target || token->generation != token->target->generation)
		return 0;
	return token->generation;
}

static void vpsadminos_klp_target_retire(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod)
{
	struct vpsadminos_klp_target_generation *target;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !mod)
		return;
	target = vpsadminos_klp_find_target_generation(mod);
	if (!target)
		return;
	if (WARN_ON_ONCE(target->claims))
		return;
	list_del(&target->node);
	kfree(target);
}

void vpsadminos_klp_foundation_target_retire(struct module *mod)
{
	if (smp_load_acquire(&vpsadminos_foundation.active) &&
	    vpsadminos_foundation.target_retire)
		vpsadminos_foundation.target_retire(&vpsadminos_foundation, mod);
}

static int vpsadminos_klp_target_import(
		struct vpsadminos_klp_foundation_state *state,
		struct module *mod, u64 generation)
{
	struct vpsadminos_klp_target_generation *target;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !state->absorbing ||
	    !mod || !generation || vpsadminos_klp_find_target_generation(mod))
		return -EINVAL;
	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return -ENOMEM;
	target->mod = mod;
	target->generation = generation;
	list_add_tail(&target->node, &vpsadminos_klp_target_generations);
	if (vpsadminos_klp_next_target_generation <= generation)
		vpsadminos_klp_next_target_generation = generation + 1;
	if (!vpsadminos_klp_next_target_generation) {
		list_del(&target->node);
		kfree(target);
		return -EOVERFLOW;
	}
	return 0;
}

static int vpsadminos_klp_validate_completion_set(
		struct module *checkpoint,
		const struct vpsadminos_klp_id *expected, u32 expected_count)
{
	struct vpsadminos_klp_completion *registration;
	u32 index = 0;
	bool checkpoint_found = false;

	if (!expected || !expected_count)
		return -EINVAL;
	list_for_each_entry(registration, &vpsadminos_klp_completions, node) {
		if (registration->owner == checkpoint) {
			if (checkpoint_found || registration->active)
				return -EINVAL;
			checkpoint_found = true;
			continue;
		}
		if (!registration->active || index == expected_count ||
		    !vpsadminos_klp_id_equal(&registration->artifact_id,
					     &expected[index]))
			return -EINVAL;
		index++;
	}
	return checkpoint_found && index == expected_count ? 0 : -EINVAL;
}

static int vpsadminos_klp_foundation_prepare_absorb(
		struct vpsadminos_klp_foundation_state *state,
		struct module *checkpoint,
		struct vpsadminos_klp_foundation_state *successor,
		const struct vpsadminos_klp_id *expected, u32 expected_count,
		struct vpsadminos_klp_foundation_absorb **preparedp)
{
	struct vpsadminos_klp_foundation_absorb *prepared;
	struct vpsadminos_klp_absorb_target *held;
	struct vpsadminos_klp_target_generation *target;
	int ret;

	lockdep_assert_held(&klp_mutex);
	if (!vpsadminos_klp_foundation_state_valid(state) || !state->active ||
	    state->absorbing || !checkpoint || !successor || !preparedp ||
	    successor->magic != VPSADMINOS_KLP_FOUNDATION_MAGIC ||
	    successor->abi_version != VPSADMINOS_KLP_FOUNDATION_STATE_VERSION ||
	    successor->active || successor->absorbing ||
	    !successor->target_import || !successor->target_retire ||
	    !klp_transition_patch || klp_transition_patch->mod != checkpoint ||
	    !klp_transition_patch->replace)
		return -EINVAL;
	*preparedp = NULL;
	ret = vpsadminos_klp_validate_completion_set(checkpoint, expected,
						     expected_count);
	if (ret)
		return ret;
	prepared = kzalloc(sizeof(*prepared), GFP_KERNEL);
	if (!prepared)
		return -ENOMEM;
	INIT_LIST_HEAD(&prepared->targets);
	prepared->predecessor = state;
	prepared->successor = successor;
	prepared->checkpoint = checkpoint;
	WRITE_ONCE(state->absorbing, true);
	WRITE_ONCE(successor->absorbing, true);
	list_for_each_entry(target, &vpsadminos_klp_target_generations, node) {
		if (target->claims || !try_module_get(target->mod)) {
			ret = -EBUSY;
			goto unwind;
		}
		held = kzalloc(sizeof(*held), GFP_KERNEL);
		if (!held) {
			module_put(target->mod);
			ret = -ENOMEM;
			goto unwind;
		}
		held->mod = target->mod;
		list_add_tail(&held->node, &prepared->targets);
		ret = successor->target_import(successor, target->mod,
					       target->generation);
		if (ret)
			goto unwind;
	}
	*preparedp = prepared;
	return 0;

unwind:
	vpsadminos_klp_foundation_abort_absorb(prepared);
	return ret;
}

static void vpsadminos_klp_foundation_abort_absorb(
		struct vpsadminos_klp_foundation_absorb *prepared)
{
	struct vpsadminos_klp_absorb_target *held, *tmp;

	if (!prepared)
		return;
	lockdep_assert_held(&klp_mutex);
	list_for_each_entry_safe(held, tmp, &prepared->targets, node) {
		prepared->successor->target_retire(prepared->successor,
						   held->mod);
		module_put(held->mod);
		list_del(&held->node);
		kfree(held);
	}
	WRITE_ONCE(prepared->successor->absorbing, false);
	WRITE_ONCE(prepared->predecessor->absorbing, false);
	kfree(prepared);
}

static void vpsadminos_klp_foundation_commit_absorb(
		struct vpsadminos_klp_foundation_absorb *prepared)
{
	struct vpsadminos_klp_target_generation *target, *target_tmp;
	struct vpsadminos_klp_completion *completion, *completion_tmp;
	struct vpsadminos_klp_absorb_target *held, *held_tmp;
	struct vpsadminos_klp_foundation_state *old, *new;

	if (WARN_ON_ONCE(!prepared))
		return;
	lockdep_assert_held(&klp_mutex);
	old = prepared->predecessor;
	new = prepared->successor;
	list_for_each_entry_safe(target, target_tmp,
				 &vpsadminos_klp_target_generations, node) {
		list_del(&target->node);
		kfree(target);
	}
	list_for_each_entry_safe(completion, completion_tmp,
				 &vpsadminos_klp_completions, node) {
		list_del(&completion->node);
		kfree(completion);
	}
	list_for_each_entry_safe(held, held_tmp, &prepared->targets, node) {
		module_put(held->mod);
		list_del(&held->node);
		kfree(held);
	}
	smp_store_release(&old->active, false);
	WRITE_ONCE(old->owner, NULL);
	WRITE_ONCE(old->dependency, NULL);
	WRITE_ONCE(old->artifact, NULL);
	WRITE_ONCE(old->absorbing, false);

	WRITE_ONCE(new->owner, prepared->checkpoint);
	new->owner_id =
		VPSADMINOS_KLP_ID(VPSADMINOS_KLP_V7_CHECKPOINT_ID_HI,
				  VPSADMINOS_KLP_V7_CHECKPOINT_ID_LO);
	WRITE_ONCE(new->absorbing, false);
	smp_store_release(&new->active, true);
	kfree(prepared);
}

static void vpsadminos_klp_foundation_terminal(struct module *owner,
						bool enabled, void *data)
{
	struct vpsadminos_klp_foundation_state *foundation = data;
	struct vpsadminos_klp_dependency_state *dependency;

	if (WARN_ON_ONCE(!vpsadminos_klp_foundation_state_valid(foundation)))
		return;
	dependency = foundation->dependency;
	if (enabled) {
		dependency->activate(dependency, foundation->artifact);
		WRITE_ONCE(foundation->owner, owner);
		foundation->owner_id =
			vpsadminos_klp_foundation_self_spec.artifact_id;
		smp_store_release(&foundation->active, true);
		return;
	}
	foundation->deactivate(foundation);
}

static int __maybe_unused
vpsadminos_klp_foundation_pre_patch(struct klp_object *obj)
{
	struct vpsadminos_klp_dependency_token *dependency_token;
	struct vpsadminos_klp_dependency_state *dependency;
	struct klp_patch *owner_patch;
	struct klp_state *previous, *dependency_record;
	int ret;

	owner_patch = vpsadminos_klp_object_patch(obj);
	if (!owner_patch || owner_patch != klp_transition_patch)
		return -EINVAL;
	previous = klp_get_prev_state(VPSADMINOS_KLP_FOUNDATION_STATE_ID);
	if (previous || READ_ONCE(vpsadminos_foundation.active) ||
	    vpsadminos_foundation.artifact)
		return -EEXIST;
	dependency_record = klp_get_prev_state(
			VPSADMINOS_KLP_DEPENDENCY_STATE_ID);
	if (!dependency_record)
		return -ENODEV;
	dependency = dependency_record->data;
	if (!dependency || dependency->magic != VPSADMINOS_KLP_DEPENDENCY_MAGIC ||
	    dependency->abi_version != VPSADMINOS_KLP_DEPENDENCY_STATE_VERSION ||
	    !smp_load_acquire(&dependency->active) || dependency->absorbing ||
	    dependency->foundation || !dependency->begin || !dependency->acquire ||
	    !dependency->abort || !dependency->activate ||
	    !dependency->deactivate || !dependency->install_foundation ||
	    !dependency->complete_transition)
		return -EINVAL;
	ret = dependency->begin(dependency, owner_patch->mod,
				&vpsadminos_klp_foundation_self_spec,
				&vpsadminos_foundation.artifact);
	if (ret)
		return ret;
	ret = dependency->acquire(dependency, vpsadminos_foundation.artifact,
				  &vpsadminos_klp_foundation_anchor_spec,
				  &dependency_token);
	if (ret)
		goto abort_artifact;
	ret = dependency->acquire(dependency, vpsadminos_foundation.artifact,
				  &vpsadminos_klp_foundation_guard_spec,
				  &dependency_token);
	if (ret)
		goto abort_artifact;
	WRITE_ONCE(vpsadminos_foundation.dependency, dependency);
	ret = vpsadminos_klp_register_completion(&vpsadminos_foundation,
			owner_patch->mod,
			&vpsadminos_klp_foundation_self_spec.artifact_id,
			vpsadminos_klp_foundation_terminal,
			&vpsadminos_foundation);
	if (ret)
		goto abort_artifact;
	ret = dependency->install_foundation(dependency, owner_patch->mod,
					     &vpsadminos_foundation);
	if (ret)
		goto cancel_completion;
	return 0;

cancel_completion:
	vpsadminos_klp_cancel_completion(&vpsadminos_foundation,
					owner_patch->mod);
abort_artifact:
	dependency->abort(dependency, vpsadminos_foundation.artifact);
	WRITE_ONCE(vpsadminos_foundation.artifact, NULL);
	WRITE_ONCE(vpsadminos_foundation.dependency, NULL);
	return ret;
}

static void __maybe_unused
vpsadminos_klp_foundation_post_patch(struct klp_object *obj)
{
	/* Publication is deliberately deferred to the completion aggregator. */
	(void)obj;
}

static void __maybe_unused
vpsadminos_klp_foundation_post_unpatch(struct klp_object *obj)
{
	struct vpsadminos_klp_dependency_state *dependency;
	struct klp_patch *patch = vpsadminos_klp_object_patch(obj);

	if (!patch || vpsadminos_foundation.active)
		return;
	dependency = vpsadminos_foundation.dependency;
	vpsadminos_klp_cancel_completion(&vpsadminos_foundation, patch->mod);
	if (dependency) {
		WRITE_ONCE(dependency->foundation, NULL);
		dependency->abort(dependency, vpsadminos_foundation.artifact);
	}
	WRITE_ONCE(vpsadminos_foundation.artifact, NULL);
	WRITE_ONCE(vpsadminos_foundation.dependency, NULL);
}

#if LIVEPATCH_IS_FOUNDATION
static struct vpsadminos_klp_callback_int vpsadminos_foundation_pre_patch_data
__section(".kpatch.callbacks.pre_patch") __used = {
	.fn = vpsadminos_klp_foundation_pre_patch,
	.objname = NULL,
};

static struct vpsadminos_klp_callback_void
vpsadminos_foundation_post_patch_data
__section(".kpatch.callbacks.post_patch") __used = {
	.fn = vpsadminos_klp_foundation_post_patch,
	.objname = NULL,
};

static struct vpsadminos_klp_callback_void
vpsadminos_foundation_post_unpatch_data
__section(".kpatch.callbacks.post_unpatch") __used = {
	.fn = vpsadminos_klp_foundation_post_unpatch,
	.objname = NULL,
};
#endif

static int klp_transition_progress_get(char *buffer,
				       const struct kernel_param *parameter)
{
	u64 elapsed_ms = 0;
	int len;

	(void)parameter;
	if (READ_ONCE(klp_progress.started_ns))
		elapsed_ms = div_u64(ktime_get_mono_fast_ns() -
				     READ_ONCE(klp_progress.started_ns),
				     NSEC_PER_MSEC);

	len = scnprintf(buffer, PAGE_SIZE,
			"elapsed_ms=%llu complete=%u pending=%llu running=%llu",
			elapsed_ms, READ_ONCE(klp_progress.complete),
			READ_ONCE(klp_progress.pending_tasks),
			READ_ONCE(klp_progress.pending_running));
	len += scnprintf(buffer + len, PAGE_SIZE - len,
			 " waking=%llu sleeping=%llu idle=%llu worker=%llu sched=%llu",
			READ_ONCE(klp_progress.pending_waking),
			READ_ONCE(klp_progress.pending_sleeping),
			READ_ONCE(klp_progress.pending_idle),
			atomic64_read(&klp_progress.worker_switches),
			atomic64_read(&klp_progress.scheduler_switches));
	len += scnprintf(buffer + len, PAGE_SIZE - len,
			 " idle_switched=%llu snapshot=%llu/%llu overflows=%llu",
			atomic64_read(&klp_progress.idle_switches),
			READ_ONCE(klp_progress.snapshot_tasks),
			READ_ONCE(klp_progress.snapshot_capacity),
			READ_ONCE(klp_progress.snapshot_overflows));
	len += scnprintf(buffer + len, PAGE_SIZE - len,
			 " alloc_failures=%llu tasklist_ns=%llu batch_ns=%llu",
			READ_ONCE(klp_progress.allocation_failures),
			READ_ONCE(klp_progress.tasklist_ns),
			READ_ONCE(klp_progress.batch_ns));
	len += scnprintf(buffer + len, PAGE_SIZE - len,
			 " reschedules=%llu ranges=%u lookups=%llu steps=%llu max_steps=%llu",
			READ_ONCE(klp_progress.worker_reschedules),
			READ_ONCE(klp_progress.range_count),
			atomic64_read(&klp_progress.range_lookups),
			atomic64_read(&klp_progress.range_steps),
			atomic64_read(&klp_progress.range_max_steps));
	len += scnprintf(buffer + len, PAGE_SIZE - len,
			 " generation=%llu retries=%llu",
		READ_ONCE(klp_progress.snapshot_generation),
		READ_ONCE(klp_progress.snapshot_retries));
	return len;
}

static const struct kernel_param_ops klp_transition_progress_ops = {
	.get = klp_transition_progress_get,
};
module_param_cb(transition_progress, &klp_transition_progress_ops, NULL, 0444);
MODULE_PARM_DESC(transition_progress, "bounded livepatch transition progress");

static int klp_transition_range_cmp(const void *left, const void *right)
{
	const struct klp_transition_range *a = left;
	const struct klp_transition_range *b = right;

	if (a->start < b->start)
		return -1;
	if (a->start > b->start)
		return 1;
	if (a->end < b->end)
		return -1;
	if (a->end > b->end)
		return 1;
	return 0;
}

static void klp_atomic64_update_max(atomic64_t *value, s64 candidate)
{
	s64 observed = atomic64_read(value);

	while (observed < candidate &&
	       !atomic64_try_cmpxchg(value, &observed, candidate))
		;
}

static int klp_transition_add_range(struct klp_transition_range *range,
				    unsigned long start,
				    unsigned long size,
				    const char *name)
{
	unsigned long end;

	if (!size || check_add_overflow(start, size, &end))
		return -EINVAL;
	range->start = start;
	range->end = end;
	range->name = name;
	return 0;
}

static int klp_transition_validate_ranges(struct klp_transition_range *ranges,
					  unsigned int count)
{
	unsigned int index;

	sort(ranges, count, sizeof(*ranges), klp_transition_range_cmp, NULL);
	for (index = 1; index < count; index++)
		if (ranges[index].start < ranges[index - 1].end)
			return -EINVAL;
	return 0;
}

static void klp_transition_free_resources(void)
{
	unsigned int index;

	for (index = 0; index < klp_transition_module_count; index++)
		module_put(klp_transition_modules[index]);
	kvfree(klp_transition_modules);
	klp_transition_modules = NULL;
	klp_transition_module_count = 0;
	kvfree(klp_patching_ranges);
	kvfree(klp_unpatching_ranges);
	klp_patching_ranges = NULL;
	klp_unpatching_ranges = NULL;
	klp_transition_range_count = 0;
}

static void klp_transition_reset_progress(void)
{
	WRITE_ONCE(klp_progress.started_ns, ktime_get_mono_fast_ns());
	WRITE_ONCE(klp_progress.tasklist_ns, 0);
	WRITE_ONCE(klp_progress.batch_ns, 0);
	atomic64_set(&klp_progress.worker_switches, 0);
	atomic64_set(&klp_progress.scheduler_switches, 0);
	atomic64_set(&klp_progress.idle_switches, 0);
	WRITE_ONCE(klp_progress.worker_reschedules, 0);
	WRITE_ONCE(klp_progress.snapshot_capacity, 0);
	WRITE_ONCE(klp_progress.snapshot_tasks, 0);
	WRITE_ONCE(klp_progress.snapshot_overflows, 0);
	WRITE_ONCE(klp_progress.snapshot_generation,
		   atomic64_read(&klp_task_generation));
	WRITE_ONCE(klp_progress.snapshot_retries, 0);
	WRITE_ONCE(klp_progress.allocation_failures, 0);
	WRITE_ONCE(klp_progress.pending_tasks, 0);
	WRITE_ONCE(klp_progress.pending_running, 0);
	WRITE_ONCE(klp_progress.pending_waking, 0);
	WRITE_ONCE(klp_progress.pending_sleeping, 0);
	WRITE_ONCE(klp_progress.pending_idle, 0);
	atomic64_set(&klp_progress.range_lookups, 0);
	atomic64_set(&klp_progress.range_steps, 0);
	atomic64_set(&klp_progress.range_max_steps, 0);
	WRITE_ONCE(klp_progress.range_count, klp_transition_range_count);
	WRITE_ONCE(klp_progress.complete, false);
}

int klp_prepare_transition(struct klp_patch *patch)
{
	struct klp_transition_range *patching, *unpatching;
	struct module **modules;
	struct klp_object *obj;
	struct klp_func *func;
	struct klp_ops *ops;
	unsigned int function_count = 0;
	unsigned int module_count = 0;
	unsigned int function_index = 0;
	unsigned int module_index = 0;
	int ret;

	if (WARN_ON_ONCE(klp_patching_ranges || klp_unpatching_ranges ||
			 klp_transition_modules))
		return -EBUSY;

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;
		klp_for_each_func(obj, func)
			function_count++;
		if (obj->name)
			module_count++;
	}
	patching = function_count ?
		kvmalloc_array(function_count, sizeof(*patching),
				 GFP_KERNEL | __GFP_ZERO) : NULL;
	unpatching = function_count ?
		kvmalloc_array(function_count, sizeof(*unpatching),
				   GFP_KERNEL | __GFP_ZERO) : NULL;
	modules = kvmalloc_array(module_count, sizeof(*modules),
				 GFP_KERNEL | __GFP_ZERO);
	if ((function_count && (!patching || !unpatching)) ||
	    (module_count && !modules)) {
		ret = -ENOMEM;
		goto free;
	}

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;
		if (obj->name) {
			if (!try_module_get(obj->mod)) {
				ret = -EBUSY;
				goto put_modules;
			}
			modules[module_index++] = obj->mod;
		}
		klp_for_each_func(obj, func) {
			void *previous;
			unsigned long previous_size;

			ops = klp_find_ops(func->old_func);
			if (!patch->enabled &&
			    (!ops || list_empty(&ops->func_stack))) {
				previous = func->old_func;
				previous_size = func->old_size;
			} else if (patch->enabled) {
				struct klp_func *below;

				if (WARN_ON_ONCE(!ops ||
						 list_empty(&ops->func_stack))) {
					ret = -EINVAL;
					goto put_modules;
				}
				if (list_is_last(&func->stack_node,
						 &ops->func_stack)) {
					previous = func->old_func;
					previous_size = func->old_size;
				} else {
					below = list_next_entry(func, stack_node);
					previous = below->new_func;
					previous_size = below->new_size;
				}
			} else {
				struct klp_func *top;

				top = list_first_entry(&ops->func_stack,
						       struct klp_func, stack_node);
				previous = top->new_func;
				previous_size = top->new_size;
			}
			ret = klp_transition_add_range(&patching[function_index],
					(unsigned long)previous, previous_size,
					func->old_name);
			if (ret)
				goto put_modules;
			ret = klp_transition_add_range(&unpatching[function_index],
					(unsigned long)func->new_func,
					func->new_size, func->old_name);
			if (ret)
				goto put_modules;
			function_index++;
		}
	}

	if (function_count) {
		ret = klp_transition_validate_ranges(patching, function_count);
		if (ret)
			goto put_modules;
		ret = klp_transition_validate_ranges(unpatching, function_count);
		if (ret)
			goto put_modules;
	}

	klp_patching_ranges = patching;
	klp_unpatching_ranges = unpatching;
	klp_transition_range_count = function_count;
	klp_transition_modules = modules;
	klp_transition_module_count = module_index;
	return 0;

put_modules:
	while (module_index)
		module_put(modules[--module_index]);
free:
	kvfree(modules);
	kvfree(unpatching);
	kvfree(patching);
	return ret;
}

bool klp_transition_targets_module(const char *name)
{
	struct klp_object *obj;

	if (!klp_transition_patch)
		return false;
	klp_for_each_object(klp_transition_patch, obj)
		if (obj->name && !strcmp(obj->name, name))
			return true;
	return false;
}

/*
 * The exact 6.12.95 anchor starts its first transition through the legacy
 * PREEMPT_DYNAMIC cond_resched override.  Later artifacts add scheduler-entry
 * hooks, but a guard completion must still tear down the same mechanism which
 * the base kernel enabled for that transition.
 */
/*
 * When a livepatch foundation or later artifact is in progress, enable stack
 * checking from scheduler entry paths.  This helps CPU-bound kthreads get
 * patched without relying on runqueue-lock stack walks.
 */
DEFINE_STATIC_KEY_FALSE(klp_sched_try_switch_key);
EXPORT_SYMBOL(klp_sched_try_switch_key);

#ifdef CONFIG_LIVEPATCH
/*
 * Keep the legacy exports for Module.symvers parity with the base kernel, but
 * let the livepatch replace only the transition code and not this object's
 * export metadata.
 */
KPATCH_IGNORE_SECTION(".export_symbol")
#endif

#if defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)
#define klp_anchor_progress_enable() sched_dynamic_klp_enable()
#define klp_anchor_progress_disable() sched_dynamic_klp_disable()
#define klp_extra_sched_enable() static_branch_enable(&klp_sched_try_switch_key)
#define klp_extra_sched_disable() static_branch_disable(&klp_sched_try_switch_key)
#else
#define klp_anchor_progress_enable() static_branch_enable(&klp_sched_try_switch_key)
#define klp_anchor_progress_disable() static_branch_disable(&klp_sched_try_switch_key)
#define klp_extra_sched_enable() do { } while (0)
#define klp_extra_sched_disable() do { } while (0)
#endif

#if LIVEPATCH_IS_GUARD
#define klp_resched_enable() do { } while (0)
#define klp_resched_disable() klp_anchor_progress_disable()
#else
#define klp_resched_enable() \
	do { \
		klp_anchor_progress_enable(); \
		klp_extra_sched_enable(); \
	} while (0)
#define klp_resched_disable() \
	do { \
		klp_extra_sched_disable(); \
		klp_anchor_progress_disable(); \
	} while (0)
#endif

/*
 * This work can be performed periodically to finish patching or unpatching any
 * "straggler" tasks which failed to transition in the first attempt.
 */
static void klp_transition_work_fn(struct work_struct *work)
{
	mutex_lock(&klp_mutex);

	if (klp_transition_patch)
		klp_try_complete_transition();

	mutex_unlock(&klp_mutex);
}
static DECLARE_DELAYED_WORK(klp_transition_work, klp_transition_work_fn);

/*
 * This function is just a stub to implement a hard force
 * of synchronize_rcu(). This requires synchronizing
 * tasks even in userspace and idle.
 */
static void klp_sync(struct work_struct *work)
{
}

/*
 * We allow to patch also functions where RCU is not watching,
 * e.g. before user_exit(). We can not rely on the RCU infrastructure
 * to do the synchronization. Instead hard force the sched synchronization.
 *
 * This approach allows to use RCU functions for manipulating func_stack
 * safely.
 */
static void klp_synchronize_transition(void)
{
	schedule_on_each_cpu(klp_sync);
}

/*
 * The transition to the target patch state is complete.  Clean up the data
 * structures.
 */
static void klp_complete_transition(void)
{
	struct klp_object *obj;
	struct klp_func *func;
	struct task_struct *g, *task;
	unsigned int cpu;

	pr_debug("'%s': completing %s transition\n",
		 klp_transition_patch->mod->name,
		 klp_target_state == KLP_TRANSITION_PATCHED ? "patching" : "unpatching");

	if (klp_transition_patch->replace && klp_target_state == KLP_TRANSITION_PATCHED) {
		klp_unpatch_replaced_patches(klp_transition_patch);
		klp_discard_nops(klp_transition_patch);
	}

	if (klp_target_state == KLP_TRANSITION_UNPATCHED) {
		/*
		 * All tasks have transitioned to KLP_TRANSITION_UNPATCHED so we can now
		 * remove the new functions from the func_stack.
		 */
		klp_unpatch_objects(klp_transition_patch);

		/*
		 * Make sure klp_ftrace_handler() can no longer see functions
		 * from this patch on the ops->func_stack.  Otherwise, after
		 * func->transition gets cleared, the handler may choose a
		 * removed function.
		 */
		klp_synchronize_transition();
	}

	klp_for_each_object(klp_transition_patch, obj)
		klp_for_each_func(obj, func)
			func->transition = false;

	/* Prevent klp_ftrace_handler() from seeing KLP_TRANSITION_IDLE state */
	if (klp_target_state == KLP_TRANSITION_PATCHED)
		klp_synchronize_transition();

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		WARN_ON_ONCE(test_tsk_thread_flag(task, TIF_PATCH_PENDING));
		task->patch_state = KLP_TRANSITION_IDLE;
	}
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		WARN_ON_ONCE(test_tsk_thread_flag(task, TIF_PATCH_PENDING));
		task->patch_state = KLP_TRANSITION_IDLE;
	}

	klp_for_each_object(klp_transition_patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;
		if (klp_target_state == KLP_TRANSITION_PATCHED)
			klp_post_patch_callback(obj);
		else if (klp_target_state == KLP_TRANSITION_UNPATCHED)
			klp_post_unpatch_callback(obj);
	}

	/*
	 * Object callbacks are complete, but sysfs still reports transition=1.
	 * Publish artifact/generation/checkpoint terminal state at this point.
	 */
#if LIVEPATCH_IS_GUARD
	vpsadminos_klp_dependency_complete_transition(klp_transition_patch);
#else
	if (vpsadminos_foundation.dependency &&
	    vpsadminos_foundation.dependency->complete_transition)
		vpsadminos_foundation.dependency->complete_transition(
			vpsadminos_foundation.dependency, klp_transition_patch);
#endif

	pr_notice("'%s': %s complete\n", klp_transition_patch->mod->name,
		  klp_target_state == KLP_TRANSITION_PATCHED ? "patching" : "unpatching");

	WRITE_ONCE(klp_progress.complete, true);
	if (READ_ONCE(klp_progress.started_ns))
		klp_synchronize_transition();
	klp_transition_free_resources();
	klp_target_state = KLP_TRANSITION_IDLE;
	klp_transition_patch = NULL;
}

/*
 * This is called in the error path, to cancel a transition before it has
 * started, i.e. klp_init_transition() has been called but
 * klp_start_transition() hasn't.  If the transition *has* been started,
 * klp_reverse_transition() should be used instead.
 */
void klp_cancel_transition(void)
{
	if (WARN_ON_ONCE(klp_target_state != KLP_TRANSITION_PATCHED))
		return;

	pr_debug("'%s': canceling patching transition, going to unpatch\n",
		 klp_transition_patch->mod->name);

	klp_target_state = KLP_TRANSITION_UNPATCHED;
	klp_complete_transition();
}

/*
 * Switch the patched state of the task to the set of functions in the target
 * patch state.
 *
 * NOTE: If task is not 'current', the caller must ensure the task is inactive.
 * Otherwise klp_ftrace_handler() might read the wrong 'patch_state' value.
 */
void klp_update_patch_state(struct task_struct *task)
{
	/*
	 * A variant of synchronize_rcu() is used to allow patching functions
	 * where RCU is not watching, see klp_synchronize_transition().
	 */
	preempt_disable_notrace();

	/*
	 * This test_and_clear_tsk_thread_flag() call also serves as a read
	 * barrier (smp_rmb) for two cases:
	 *
	 * 1) Enforce the order of the TIF_PATCH_PENDING read and the
	 *    klp_target_state read.  The corresponding write barriers are in
	 *    klp_init_transition() and klp_reverse_transition().
	 *
	 * 2) Enforce the order of the TIF_PATCH_PENDING read and a future read
	 *    of func->transition, if klp_ftrace_handler() is called later on
	 *    the same CPU.  See __klp_disable_patch().
	 */
	if (test_and_clear_tsk_thread_flag(task, TIF_PATCH_PENDING))
		task->patch_state = READ_ONCE(klp_target_state);

	preempt_enable_notrace();
}

/*
 * Determine whether the given stack trace includes any references to a
 * to-be-patched or to-be-unpatched function.
 */
static int klp_check_stack_func(struct klp_func *func, unsigned long *entries,
				unsigned int nr_entries)
{
	unsigned long func_addr, func_size, address;
	struct klp_ops *ops;
	int i;

	if (klp_target_state == KLP_TRANSITION_UNPATCHED) {
		 /*
		  * Check for the to-be-unpatched function
		  * (the func itself).
		  */
		func_addr = (unsigned long)func->new_func;
		func_size = func->new_size;
	} else {
		/*
		 * Check for the to-be-patched function
		 * (the previous func).
		 */
		ops = klp_find_ops(func->old_func);

		if (list_is_singular(&ops->func_stack)) {
			/* original function */
			func_addr = (unsigned long)func->old_func;
			func_size = func->old_size;
		} else {
			/* previously patched function */
			struct klp_func *prev;

			prev = list_next_entry(func, stack_node);
			func_addr = (unsigned long)prev->new_func;
			func_size = prev->new_size;
		}
	}

	for (i = 0; i < nr_entries; i++) {
		address = entries[i];

		if (address >= func_addr && address < func_addr + func_size)
			return -EAGAIN;
	}

	return 0;
}

static int klp_check_stack_ranges(unsigned long *entries,
				  unsigned int nr_entries,
				  const char **oldname)
{
	struct klp_transition_range *ranges;
	u64 maximum_steps;
	unsigned int entry;

	ranges = klp_target_state == KLP_TRANSITION_PATCHED ?
		 klp_patching_ranges : klp_unpatching_ranges;
	if (!ranges || !klp_transition_range_count)
		return -EOPNOTSUPP;

	maximum_steps = atomic64_read(&klp_progress.range_max_steps);
	for (entry = 0; entry < nr_entries; entry++) {
		unsigned int left = 0;
		unsigned int right = klp_transition_range_count;
		u64 steps = 0;

		while (left < right) {
			unsigned int middle = left + (right - left) / 2;
			struct klp_transition_range *range = &ranges[middle];

			steps++;
			if (entries[entry] < range->start) {
				right = middle;
			} else if (entries[entry] >= range->end) {
				left = middle + 1;
			} else {
				*oldname = range->name;
				atomic64_inc(&klp_progress.range_lookups);
				atomic64_add(steps, &klp_progress.range_steps);
				klp_atomic64_update_max(
					&klp_progress.range_max_steps, steps);
				return -EADDRINUSE;
			}
		}
		atomic64_inc(&klp_progress.range_lookups);
		atomic64_add(steps, &klp_progress.range_steps);
		if (steps > maximum_steps)
			maximum_steps = steps;
	}
	klp_atomic64_update_max(&klp_progress.range_max_steps, maximum_steps);
	return 0;
}

/*
 * Determine whether it's safe to transition the task to the target patch state
 * by looking for any to-be-patched or to-be-unpatched functions on its stack.
 */
static int klp_check_stack(struct task_struct *task, const char **oldname)
{
	unsigned long *entries = this_cpu_ptr(klp_stack_entries);
	struct klp_object *obj;
	struct klp_func *func;
	int ret, nr_entries;

	/* Protect 'klp_stack_entries' */
	lockdep_assert_preemption_disabled();

	ret = stack_trace_save_tsk_reliable(task, entries, MAX_STACK_ENTRIES);
	if (ret < 0)
		return -EINVAL;
	nr_entries = ret;
	ret = klp_check_stack_ranges(entries, nr_entries, oldname);
	if (ret != -EOPNOTSUPP)
		return ret;

	klp_for_each_object(klp_transition_patch, obj) {
		if (!obj->patched)
			continue;
		klp_for_each_func(obj, func) {
			ret = klp_check_stack_func(func, entries, nr_entries);
			if (ret) {
				*oldname = func->old_name;
				return -EADDRINUSE;
			}
		}
	}

	return 0;
}

static int klp_check_and_switch_task(struct task_struct *task, void *arg)
{
	int ret;

	if (task_curr(task) && task != current)
		return -EBUSY;

	ret = klp_check_stack(task, arg);
	if (ret)
		return ret;

	clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
	task->patch_state = klp_target_state;
	return 0;
}

/*
 * Try to safely switch a task to the target patch state.  If it's currently
 * running, or it's sleeping on a to-be-patched or to-be-unpatched function, or
 * if the stack is unreliable, return false.
 */
static bool klp_try_switch_task_path(struct task_struct *task,
				     enum klp_switch_path path)
{
	const char *old_name;
	unsigned long flags;
	unsigned int state;
	int ret;

	/* check if this task has already switched over */
	if (task->patch_state == klp_target_state)
		return true;

	/*
	 * For arches which don't have reliable stack traces, we have to rely
	 * on other methods (e.g., switching tasks at kernel exit).
	 */
	if (!klp_have_reliable_stack())
		return false;

	/*
	 * Now try to check the stack for any to-be-patched or to-be-unpatched
	 * functions.  If all goes well, switch the task to the target patch
	 * state.
	 */
	if (task == current) {
		/*
		 * klp_check_stack() uses per-CPU storage.  Also exclude the idle
		 * task IPI callback from reusing that storage on this CPU.
		 */
		local_irq_save(flags);
		ret = klp_check_and_switch_task(current, &old_name);
		local_irq_restore(flags);
	} else {
		/*
		 * task_call_func() can hold the task's rq lock while invoking its
		 * callback.  A cumulative livepatch stack check is not a lightweight
		 * callback: it compares every saved frame against every transition
		 * function.  Pin sleeping tasks with pi_lock instead and leave any
		 * active task for one of the normal self-transition paths.
		 */
		raw_spin_lock_irqsave(&task->pi_lock, flags);

		state = READ_ONCE(task->__state);
		if (state == TASK_RUNNING || state == TASK_WAKING) {
			ret = -EBUSY;
			goto unlock;
		}

		/* Pair the scheduler state and on_rq observations. */
		smp_rmb();
		if (READ_ONCE(task->on_rq)) {
			ret = -EBUSY;
			goto unlock;
		}

#ifdef CONFIG_SMP
		/*
		 * A sleeping task can still be finishing __schedule().  Acquire
		 * from finish_task() before inspecting its stack, but never wait
		 * for it while holding scheduler state locks.
		 */
		smp_rmb();
		/* Pairs with finish_task()'s smp_store_release(). */
		if (smp_load_acquire(&task->on_cpu)) {
			ret = -EBUSY;
			goto unlock;
		}
#endif

		ret = klp_check_and_switch_task(task, &old_name);
unlock:
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
	}

	switch (ret) {
	case 0:		/* success */
		if (path == KLP_SWITCH_WORKER)
			atomic64_inc(&klp_progress.worker_switches);
		else if (path == KLP_SWITCH_SCHED)
			atomic64_inc(&klp_progress.scheduler_switches);
		else
			atomic64_inc(&klp_progress.idle_switches);
		break;

	case -EBUSY:	/* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d is running\n",
			 __func__, task->comm, task->pid);
		break;
	case -EINVAL:	/* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d has an unreliable stack\n",
			 __func__, task->comm, task->pid);
		break;
	case -EADDRINUSE: /* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d is sleeping on function %s\n",
			 __func__, task->comm, task->pid, old_name);
		break;

	default:
		pr_debug("%s: Unknown error code (%d) when trying to switch %s:%d\n",
			 __func__, ret, task->comm, task->pid);
		break;
	}

	return !ret;
}

/*
 * Preserve the exact boot-kernel calling convention.  The active boot
 * __klp_sched_try_switch() calls this private function directly while the
 * guard is being introduced, so adding an argument here would create a
 * cross-version private ABI mismatch during that transition.
 */
static noinline bool klp_try_switch_task(struct task_struct *task)
{
	return klp_try_switch_task_path(task, KLP_SWITCH_SCHED);
}

/*
 * Try to switch this CPU's idle task while execution on the target CPU makes
 * its stack stable.  Idle tasks always have TASK_RUNNING state, even when
 * they are not current, so the ordinary sleeping-task path cannot handle
 * them.  If the idle task is current, this callback runs on its stack.  If a
 * different task is current, local IRQ disablement prevents the idle task
 * from becoming runnable until its inactive stack walk has finished.
 */
static void klp_try_switch_idle_task(void *unused)
{
	struct task_struct *task = idle_task(smp_processor_id());
	const char *old_name;
	int ret;

	if (task->patch_state == klp_target_state ||
	    !klp_have_reliable_stack())
		return;

	ret = klp_check_and_switch_task(task, &old_name);
	if (!ret)
		atomic64_inc(&klp_progress.idle_switches);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		pr_debug("%s: idle task %d has an unreliable stack\n",
			 __func__, smp_processor_id());
		break;
	case -EADDRINUSE:
		pr_debug("%s: idle task %d is sleeping on function %s\n",
			 __func__, smp_processor_id(), old_name);
		break;
	default:
		pr_debug("%s: error %d when trying to switch idle task %d\n",
			 __func__, ret, smp_processor_id());
		break;
	}
}

void __klp_sched_try_switch(void)
{
	if (likely(!klp_patch_pending(current)))
		return;

	/*
	 * This function is called from cond_resched() which is called in many
	 * places throughout the kernel.  Using the klp_mutex here might deadlock.
	 *
	 * Instead, disable preemption to prevent racing with other callers of
	 * klp_try_switch_task().  Its non-current path leaves runnable and on-CPU
	 * tasks pending, so they cannot switch this task while it runs.
	 */
	preempt_disable();

	/* Make sure current didn't get patched before preemption was disabled. */
	if (unlikely(!klp_patch_pending(current)))
		goto out;

	/*
	 * Enforce the order of the TIF_PATCH_PENDING read above and the
	 * klp_target_state read in klp_try_switch_task().  The corresponding
	 * write barriers are in klp_init_transition() and
	 * klp_reverse_transition().
	 */
	smp_rmb();

	klp_try_switch_task(current);

out:
	preempt_enable();
}
EXPORT_SYMBOL(__klp_sched_try_switch);

/*
 * Sends a fake signal to all non-kthread tasks with TIF_PATCH_PENDING set.
 * Kthreads with TIF_PATCH_PENDING set are woken up.
 */
static void klp_send_signals(void)
{
	struct task_struct *g, *task;

	if (klp_signals_cnt == SIGNALS_TIMEOUT)
		pr_notice("signaling remaining tasks\n");

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		if (!klp_patch_pending(task))
			continue;

		/*
		 * There is a small race here. We could see TIF_PATCH_PENDING
		 * set and decide to wake up a kthread or send a fake signal.
		 * Meanwhile the task could migrate itself and the action
		 * would be meaningless. It is not serious though.
		 */
		if (task->flags & PF_KTHREAD) {
			/*
			 * Wake up a kthread which sleeps interruptedly and
			 * still has not been migrated.
			 */
			wake_up_state(task, TASK_INTERRUPTIBLE);
		} else {
			/*
			 * Send fake signal to all non-kthread tasks which are
			 * still not migrated.
			 */
			set_notify_signal(task);
		}
	}
	read_unlock(&tasklist_lock);
}

/*
 * Try to switch all remaining tasks to the target patch state by walking the
 * stacks of sleeping tasks and looking for any to-be-patched or
 * to-be-unpatched functions.  If such functions are found, the task can't be
 * switched yet.
 *
 * If any tasks are still stuck in the initial patch state, schedule a retry.
 */
void klp_try_complete_transition(void)
{
	unsigned int cpu;
	struct task_struct *g, *task;
	struct task_struct **tasks = NULL;
	struct klp_patch *patch;
	size_t capacity = 0, nr_tasks = 0, slack, i;
	u64 task_generation;
	u64 tasklist_started, batch_started;
	u64 pending = 0, pending_running = 0;
	u64 pending_waking = 0, pending_sleeping = 0;
	u64 pending_idle = 0;
	bool complete = true;

	WARN_ON_ONCE(klp_target_state == KLP_TRANSITION_IDLE);

	/*
	 * Try to switch the tasks to the target patch state by walking their
	 * stacks and looking for any to-be-patched or to-be-unpatched
	 * functions.  If such functions are found on a stack, or if the stack
	 * is deemed unreliable, the task can't be switched yet.
	 *
	 * Usually this will transition most (or all) of the tasks on a system
	 * unless the patch includes changes to a very common function.
	 */
	/*
	 * Keep tasklist_lock coverage to pointer collection.  Stack walking and
	 * cumulative function comparison can be expensive on large systems and
	 * must remain preemptible and outside this global lock.
	 */
	task_generation = atomic64_read(&klp_task_generation);
	WRITE_ONCE(klp_progress.snapshot_generation, task_generation);
	tasklist_started = ktime_get_mono_fast_ns();
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		capacity++;
	read_unlock(&tasklist_lock);
	WRITE_ONCE(klp_progress.tasklist_ns,
		   ktime_get_mono_fast_ns() - tasklist_started);
	WRITE_ONCE(klp_progress.snapshot_capacity, capacity);

	if (capacity) {
		/*
		 * Leave room for forks between the count and fill passes.  Requiring
		 * an exact task count here can starve completion under continuous
		 * process churn, especially if this worker is preempted after dropping
		 * tasklist_lock.  The bound remains conservative: an unexpectedly
		 * larger burst still overflows the snapshot and forces a later retry.
		 */
		slack = max_t(size_t, KLP_TASK_BATCH_SIZE, capacity / 8);
		if (check_add_overflow(capacity, slack, &capacity)) {
			WRITE_ONCE(klp_progress.snapshot_overflows,
				   READ_ONCE(klp_progress.snapshot_overflows) + 1);
			complete = false;
			goto idle_tasks;
		}
		WRITE_ONCE(klp_progress.snapshot_capacity, capacity);

		tasks = kvmalloc_array(capacity, sizeof(*tasks), GFP_KERNEL);
		if (!tasks) {
			WRITE_ONCE(klp_progress.allocation_failures,
				   READ_ONCE(klp_progress.allocation_failures) + 1);
			complete = false;
			goto idle_tasks;
		}

		tasklist_started = ktime_get_mono_fast_ns();
		read_lock(&tasklist_lock);
		for_each_process_thread(g, task) {
			/* A larger-than-anticipated fork burst forces a later retry. */
			if (nr_tasks == capacity) {
				WRITE_ONCE(klp_progress.snapshot_overflows,
					   READ_ONCE(klp_progress.snapshot_overflows) + 1);
				complete = false;
				goto snapshot_full;
			}
			get_task_struct(task);
			tasks[nr_tasks++] = task;
		}
snapshot_full:
		read_unlock(&tasklist_lock);
		WRITE_ONCE(klp_progress.tasklist_ns,
			   READ_ONCE(klp_progress.tasklist_ns) +
			   ktime_get_mono_fast_ns() - tasklist_started);
		WRITE_ONCE(klp_progress.snapshot_tasks, nr_tasks);

		batch_started = ktime_get_mono_fast_ns();
		for (i = 0; i < nr_tasks; i++) {
			if (!klp_try_switch_task_path(tasks[i], KLP_SWITCH_WORKER))
				complete = false;
			if (tasks[i]->patch_state != klp_target_state) {
				unsigned int state = READ_ONCE(tasks[i]->__state);

				pending++;
				if (state == TASK_RUNNING)
					pending_running++;
				else if (state == TASK_WAKING)
					pending_waking++;
				else
					pending_sleeping++;
			}
			put_task_struct(tasks[i]);

			if ((i + 1) % KLP_TASK_BATCH_SIZE == 0) {
				WRITE_ONCE(klp_progress.worker_reschedules,
					   READ_ONCE(klp_progress.worker_reschedules) + 1);
				cond_resched();
			}
		}
		WRITE_ONCE(klp_progress.batch_ns,
			   ktime_get_mono_fast_ns() - batch_started);
		kvfree(tasks);
	}

	/*
	 * Ditto for the idle "swapper" tasks.
	 */
idle_tasks:
	cpus_read_lock();
	for_each_online_cpu(cpu) {
		/*
		 * Execute on the idle task's own CPU so it is either current or
		 * cannot become current while the callback walks its stack.  The
		 * callback is synchronous and does not acquire any runqueue lock.
		 */
		if (idle_task(cpu)->patch_state != klp_target_state &&
		    smp_call_function_single(cpu, klp_try_switch_idle_task,
					     NULL, 1))
			complete = false;
	}

	/* Verify every idle task after all target-CPU callbacks have returned. */
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		if (!cpu_online(cpu) && task->patch_state != klp_target_state) {
			/* offline idle tasks can be switched immediately */
			clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
			task->patch_state = klp_target_state;
		}
		if (task->patch_state != klp_target_state) {
			pending_idle++;
			complete = false;
		}
	}
	cpus_read_unlock();
	WRITE_ONCE(klp_progress.pending_tasks, pending + pending_idle);
	WRITE_ONCE(klp_progress.pending_running, pending_running);
	WRITE_ONCE(klp_progress.pending_waking, pending_waking);
	WRITE_ONCE(klp_progress.pending_sleeping, pending_sleeping);
	WRITE_ONCE(klp_progress.pending_idle, pending_idle);

	/*
	 * A child created after the fill pass can inherit an old parent state and
	 * remain absent from this snapshot.  Retry whenever task creation changed
	 * the generation; once every observed parent is new-state, a later child
	 * necessarily inherits that new state.
	 */
	if (atomic64_read(&klp_task_generation) != task_generation) {
		WRITE_ONCE(klp_progress.snapshot_retries,
			   READ_ONCE(klp_progress.snapshot_retries) + 1);
		complete = false;
	}

	if (!complete) {
		if (klp_signals_cnt && !(klp_signals_cnt % SIGNALS_TIMEOUT))
			klp_send_signals();
		klp_signals_cnt++;

		/*
		 * Some tasks weren't able to be switched over.  Try again
		 * later and/or wait for other methods like kernel exit
		 * switching.
		 */
		schedule_delayed_work(&klp_transition_work,
				      round_jiffies_relative(HZ));
		return;
	}

	/* Done!  Now cleanup the data structures. */
	klp_resched_disable();
	patch = klp_transition_patch;
	klp_complete_transition();

	/*
	 * It would make more sense to free the unused patches in
	 * klp_complete_transition() but it is called also
	 * from klp_cancel_transition().
	 */
	if (!patch->enabled)
		klp_free_patch_async(patch);
	else if (patch->replace)
		klp_free_replaced_patches_async(patch);
}

/*
 * Start the transition to the specified target patch state so tasks can begin
 * switching to it.
 */
void klp_start_transition(void)
{
	struct task_struct *g, *task;
	unsigned int cpu;

	WARN_ON_ONCE(klp_target_state == KLP_TRANSITION_IDLE);
	klp_transition_reset_progress();

	pr_notice("'%s': starting %s transition\n",
		  klp_transition_patch->mod->name,
		  klp_target_state == KLP_TRANSITION_PATCHED ? "patching" : "unpatching");

	/*
	 * Mark all normal tasks as needing a patch state update.  They'll
	 * switch either in klp_try_complete_transition() or as they exit the
	 * kernel.
	 */
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		if (task->patch_state != klp_target_state)
			set_tsk_thread_flag(task, TIF_PATCH_PENDING);
	read_unlock(&tasklist_lock);

	/*
	 * Mark all idle tasks as needing a patch state update.  They'll switch
	 * either in klp_try_complete_transition() or at the idle loop switch
	 * point.
	 */
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		if (task->patch_state != klp_target_state)
			set_tsk_thread_flag(task, TIF_PATCH_PENDING);
	}

	klp_resched_enable();

	klp_signals_cnt = 0;
}

/*
 * Initialize the global target patch state and all tasks to the initial patch
 * state, and initialize all function transition states to true in preparation
 * for patching or unpatching.
 */
void klp_init_transition(struct klp_patch *patch, int state)
{
	struct task_struct *g, *task;
	unsigned int cpu;
	struct klp_object *obj;
	struct klp_func *func;
	int initial_state = !state;

	WARN_ON_ONCE(klp_target_state != KLP_TRANSITION_IDLE);

	klp_transition_patch = patch;

	/*
	 * Set the global target patch state which tasks will switch to.  This
	 * has no effect until the TIF_PATCH_PENDING flags get set later.
	 */
	klp_target_state = state;

	pr_debug("'%s': initializing %s transition\n", patch->mod->name,
		 klp_target_state == KLP_TRANSITION_PATCHED ? "patching" : "unpatching");

	/*
	 * Initialize all tasks to the initial patch state to prepare them for
	 * switching to the target state.
	 */
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		WARN_ON_ONCE(task->patch_state != KLP_TRANSITION_IDLE);
		task->patch_state = initial_state;
	}
	read_unlock(&tasklist_lock);

	/*
	 * Ditto for the idle "swapper" tasks.
	 */
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		WARN_ON_ONCE(task->patch_state != KLP_TRANSITION_IDLE);
		task->patch_state = initial_state;
	}

	/*
	 * Enforce the order of the task->patch_state initializations and the
	 * func->transition updates to ensure that klp_ftrace_handler() doesn't
	 * see a func in transition with a task->patch_state of KLP_TRANSITION_IDLE.
	 *
	 * Also enforce the order of the klp_target_state write and future
	 * TIF_PATCH_PENDING writes to ensure klp_update_patch_state() and
	 * __klp_sched_try_switch() don't set a task->patch_state to
	 * KLP_TRANSITION_IDLE.
	 */
	smp_wmb();

	/*
	 * Set the func transition states so klp_ftrace_handler() will know to
	 * switch to the transition logic.
	 *
	 * When patching, the funcs aren't yet in the func_stack and will be
	 * made visible to the ftrace handler shortly by the calls to
	 * klp_patch_object().
	 *
	 * When unpatching, the funcs are already in the func_stack and so are
	 * already visible to the ftrace handler.
	 */
	klp_for_each_object(patch, obj)
		klp_for_each_func(obj, func)
			func->transition = true;
}

/*
 * This function can be called in the middle of an existing transition to
 * reverse the direction of the target patch state.  This can be done to
 * effectively cancel an existing enable or disable operation if there are any
 * tasks which are stuck in the initial patch state.
 */
void klp_reverse_transition(void)
{
	unsigned int cpu;
	struct task_struct *g, *task;

	pr_debug("'%s': reversing transition from %s\n",
		 klp_transition_patch->mod->name,
		 klp_target_state == KLP_TRANSITION_PATCHED ? "patching to unpatching" :
						   "unpatching to patching");

	/*
	 * Clear all TIF_PATCH_PENDING flags to prevent races caused by
	 * klp_update_patch_state() or __klp_sched_try_switch() running in
	 * parallel with the reverse transition.
	 */
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu)
		clear_tsk_thread_flag(idle_task(cpu), TIF_PATCH_PENDING);

	/*
	 * Make sure all existing invocations of klp_update_patch_state() and
	 * __klp_sched_try_switch() see the cleared TIF_PATCH_PENDING before
	 * starting the reverse transition.
	 */
	klp_synchronize_transition();

	/*
	 * All patching has stopped, now re-initialize the global variables to
	 * prepare for the reverse transition.
	 */
	klp_transition_patch->enabled = !klp_transition_patch->enabled;
	klp_target_state = !klp_target_state;

	/*
	 * Enforce the order of the klp_target_state write and the
	 * TIF_PATCH_PENDING writes in klp_start_transition() to ensure
	 * klp_update_patch_state() and __klp_sched_try_switch() don't set
	 * task->patch_state to the wrong value.
	 */
	smp_wmb();

	klp_start_transition();
}

/* Called from copy_process() during fork */
void klp_copy_process(struct task_struct *child)
{

	/*
	 * The parent process may have gone through a KLP transition since
	 * the thread flag was copied in setup_thread_stack earlier. Bring
	 * the task flag up to date with the parent here.
	 *
	 * The operation is serialized against all klp_*_transition()
	 * operations by the tasklist_lock. The only exceptions are
	 * klp_update_patch_state(current) and __klp_sched_try_switch(), but we
	 * cannot race with them because we are current.
	 */
	if (test_tsk_thread_flag(current, TIF_PATCH_PENDING))
		set_tsk_thread_flag(child, TIF_PATCH_PENDING);
	else
		clear_tsk_thread_flag(child, TIF_PATCH_PENDING);

	child->patch_state = current->patch_state;
	if (READ_ONCE(klp_transition_patch) &&
	    child->patch_state != READ_ONCE(klp_target_state))
		atomic64_inc(&klp_task_generation);
}

/*
 * Drop TIF_PATCH_PENDING of all tasks on admin's request. This forces an
 * existing transition to finish.
 *
 * NOTE: klp_update_patch_state(task) requires the task to be inactive or
 * 'current'. This is not the case here and the consistency model could be
 * broken. Administrator, who is the only one to execute the
 * klp_force_transitions(), has to be aware of this.
 */
void klp_force_transition(void)
{
	struct klp_patch *patch;
	struct task_struct *g, *task;
	unsigned int cpu;

	pr_warn("forcing remaining tasks to the patched state\n");

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		klp_update_patch_state(task);
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu)
		klp_update_patch_state(idle_task(cpu));

	/* Set forced flag for patches being removed. */
	if (klp_target_state == KLP_TRANSITION_UNPATCHED)
		klp_transition_patch->forced = true;
	else if (klp_transition_patch->replace) {
		klp_for_each_patch(patch) {
			if (patch != klp_transition_patch)
				patch->forced = true;
		}
	}
}

#if LIVEPATCH_IS_GUARD
KPATCH_IGNORE_FUNCTION(klp_check_stack)
KPATCH_IGNORE_FUNCTION(__klp_sched_try_switch)
KPATCH_IGNORE_FUNCTION(klp_start_transition)
#endif
