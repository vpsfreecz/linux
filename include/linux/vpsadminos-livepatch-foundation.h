/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_VPSADMINOS_LIVEPATCH_FOUNDATION_H
#define _LINUX_VPSADMINOS_LIVEPATCH_FOUNDATION_H

#include <linux/livepatch.h>
#include <linux/types.h>

struct module;
struct vpsadminos_klp_artifact_token;
struct vpsadminos_klp_dependency_token;
struct vpsadminos_klp_dependency_absorb;
struct vpsadminos_klp_foundation_absorb;
struct vpsadminos_klp_target_token;

#define VPSADMINOS_KLP_FOUNDATION_STATE_ID	0x6129500000000001UL
#define VPSADMINOS_KLP_FOUNDATION_STATE_VERSION	1
#define VPSADMINOS_KLP_FOUNDATION_MAGIC		0x4b4c50464f554e44ULL

#define VPSADMINOS_KLP_DEPENDENCY_STATE_ID	0x6129500000000003UL
#define VPSADMINOS_KLP_DEPENDENCY_STATE_VERSION	1
#define VPSADMINOS_KLP_DEPENDENCY_MAGIC		0x4b4c50444550454eULL

#define VPSADMINOS_KLP_COVERAGE_STATE_ID		0x6129500000000002UL
#define VPSADMINOS_KLP_COVERAGE_MAGIC		0x4b4c50434f564552ULL

/* Stable release-record identities, independent of module names and bytes. */
#define VPSADMINOS_KLP_V6_ANCHOR_ID_HI		0x6888161b64a283f7ULL
#define VPSADMINOS_KLP_V6_ANCHOR_ID_LO		0xb0c3d9947c4931a5ULL
#define VPSADMINOS_KLP_V7_GUARD_ID_HI		0x5d48a012baeba5d5ULL
#define VPSADMINOS_KLP_V7_GUARD_ID_LO		0x480b885adc534765ULL
#define VPSADMINOS_KLP_V7_CHECKPOINT_GUARD_ID_HI 0x15aeb9f2788b32c4ULL
#define VPSADMINOS_KLP_V7_CHECKPOINT_GUARD_ID_LO 0x2cddb58d0e673acaULL
#define VPSADMINOS_KLP_V7_REVERSE_GUARD_ID_HI	0x00d2e1060dc19bb0ULL
#define VPSADMINOS_KLP_V7_REVERSE_GUARD_ID_LO	0xbafe296f69d9731cULL
#define VPSADMINOS_KLP_V7_FOUNDATION_ID_HI	0xf8277a7a3a4535f0ULL
#define VPSADMINOS_KLP_V7_FOUNDATION_ID_LO	0x987c13e97754bf85ULL
#define VPSADMINOS_KLP_V7_FINAL_ID_HI		0xbce6746ecd8ec2beULL
#define VPSADMINOS_KLP_V7_FINAL_ID_LO		0xdd5f39796b9a4288ULL
#define VPSADMINOS_KLP_V7_CHECKPOINT_ID_HI	0x6d9f368676415fc9ULL
#define VPSADMINOS_KLP_V7_CHECKPOINT_ID_LO	0x6adff04023728e41ULL

#ifndef VPSADMINOS_KLP_RELEASE_GENERATION
#define VPSADMINOS_KLP_RELEASE_GENERATION	7
#endif

#ifndef VPSADMINOS_KLP_RELEASE_IDENTITY
#define VPSADMINOS_KLP_RELEASE_IDENTITY		"6.12.95.7"
#endif

#ifndef VPSADMINOS_KLP_ONLINE_PREDECESSOR_IDENTITY
#define VPSADMINOS_KLP_ONLINE_PREDECESSOR_IDENTITY "6.12.95.6"
#endif

#ifndef VPSADMINOS_KLP_ONLINE_EXPECT_PREDECESSOR_COVERAGE
#define VPSADMINOS_KLP_ONLINE_EXPECT_PREDECESSOR_COVERAGE 0
#endif

#ifndef VPSADMINOS_KLP_ONLINE_PREDECESSOR_GENERATION
#define VPSADMINOS_KLP_ONLINE_PREDECESSOR_GENERATION 0
#endif

#ifndef VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_IDENTITY
#define VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_IDENTITY ""
#endif

#ifndef VPSADMINOS_KLP_ANCHOR_MODULE_NAME
#define VPSADMINOS_KLP_ANCHOR_MODULE_NAME	"livepatch_6"
#endif

#ifndef VPSADMINOS_KLP_ANCHOR_ID_HI
#define VPSADMINOS_KLP_ANCHOR_ID_HI		VPSADMINOS_KLP_V6_ANCHOR_ID_HI
#endif

#ifndef VPSADMINOS_KLP_ANCHOR_ID_LO
#define VPSADMINOS_KLP_ANCHOR_ID_LO		VPSADMINOS_KLP_V6_ANCHOR_ID_LO
#endif

#ifndef VPSADMINOS_KLP_ONLINE_ANCHOR_CLASS
#define VPSADMINOS_KLP_ONLINE_ANCHOR_CLASS	VPSADMINOS_KLP_ANCHOR_REMEDIATION
#endif

#ifndef VPSADMINOS_KLP_ONLINE_ANCHOR_IDENTITY
#define VPSADMINOS_KLP_ONLINE_ANCHOR_IDENTITY	VPSADMINOS_KLP_ONLINE_PREDECESSOR_IDENTITY
#endif

#ifndef VPSADMINOS_KLP_GUARD_MODULE_NAME
#define VPSADMINOS_KLP_GUARD_MODULE_NAME	"livepatch_transition_guard"
#endif

#ifndef VPSADMINOS_KLP_GUARD_ID_HI
#define VPSADMINOS_KLP_GUARD_ID_HI		VPSADMINOS_KLP_V7_GUARD_ID_HI
#endif

#ifndef VPSADMINOS_KLP_GUARD_ID_LO
#define VPSADMINOS_KLP_GUARD_ID_LO		VPSADMINOS_KLP_V7_GUARD_ID_LO
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_GUARD_MODULE_NAME
#define VPSADMINOS_KLP_CHECKPOINT_GUARD_MODULE_NAME "lp7_checkpoint_guard"
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_GUARD_ID_HI
#define VPSADMINOS_KLP_CHECKPOINT_GUARD_ID_HI VPSADMINOS_KLP_V7_CHECKPOINT_GUARD_ID_HI
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_GUARD_ID_LO
#define VPSADMINOS_KLP_CHECKPOINT_GUARD_ID_LO VPSADMINOS_KLP_V7_CHECKPOINT_GUARD_ID_LO
#endif

#ifndef VPSADMINOS_KLP_REVERSE_GUARD_MODULE_NAME
#define VPSADMINOS_KLP_REVERSE_GUARD_MODULE_NAME "lp7_reverse_guard"
#endif

#ifndef VPSADMINOS_KLP_REVERSE_GUARD_ID_HI
#define VPSADMINOS_KLP_REVERSE_GUARD_ID_HI	VPSADMINOS_KLP_V7_REVERSE_GUARD_ID_HI
#endif

#ifndef VPSADMINOS_KLP_REVERSE_GUARD_ID_LO
#define VPSADMINOS_KLP_REVERSE_GUARD_ID_LO	VPSADMINOS_KLP_V7_REVERSE_GUARD_ID_LO
#endif

#ifndef VPSADMINOS_KLP_FOUNDATION_MODULE_NAME
#define VPSADMINOS_KLP_FOUNDATION_MODULE_NAME	"lp61295_foundation"
#endif

#ifndef VPSADMINOS_KLP_FOUNDATION_ID_HI
#define VPSADMINOS_KLP_FOUNDATION_ID_HI		VPSADMINOS_KLP_V7_FOUNDATION_ID_HI
#endif

#ifndef VPSADMINOS_KLP_FOUNDATION_ID_LO
#define VPSADMINOS_KLP_FOUNDATION_ID_LO		VPSADMINOS_KLP_V7_FOUNDATION_ID_LO
#endif

#ifndef VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_MODULE_NAME
#define VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_MODULE_NAME VPSADMINOS_KLP_FOUNDATION_MODULE_NAME
#endif

#ifndef VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_ID_HI
#define VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_ID_HI VPSADMINOS_KLP_FOUNDATION_ID_HI
#endif

#ifndef VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_ID_LO
#define VPSADMINOS_KLP_PREDECESSOR_FOUNDATION_ID_LO VPSADMINOS_KLP_FOUNDATION_ID_LO
#endif

#ifndef VPSADMINOS_KLP_FINAL_MODULE_NAME
#define VPSADMINOS_KLP_FINAL_MODULE_NAME	"lp7_sctp_correct"
#endif

#ifndef VPSADMINOS_KLP_FINAL_ID_HI
#define VPSADMINOS_KLP_FINAL_ID_HI		VPSADMINOS_KLP_V7_FINAL_ID_HI
#endif

#ifndef VPSADMINOS_KLP_FINAL_ID_LO
#define VPSADMINOS_KLP_FINAL_ID_LO		VPSADMINOS_KLP_V7_FINAL_ID_LO
#endif

#ifndef VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_ID_HI
#define VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_ID_HI 0ULL
#endif

#ifndef VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_ID_LO
#define VPSADMINOS_KLP_ONLINE_PREDECESSOR_FINAL_ID_LO 0ULL
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_MODULE_NAME
#define VPSADMINOS_KLP_CHECKPOINT_MODULE_NAME	"livepatch_7"
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_ID_HI
#define VPSADMINOS_KLP_CHECKPOINT_ID_HI		VPSADMINOS_KLP_V7_CHECKPOINT_ID_HI
#endif

#ifndef VPSADMINOS_KLP_CHECKPOINT_ID_LO
#define VPSADMINOS_KLP_CHECKPOINT_ID_LO		VPSADMINOS_KLP_V7_CHECKPOINT_ID_LO
#endif

struct vpsadminos_klp_id {
	u64 high;
	u64 low;
};

#define VPSADMINOS_KLP_ID(_high, _low) \
	((struct vpsadminos_klp_id) { .high = (_high), .low = (_low) })

static inline bool
vpsadminos_klp_id_equal(const struct vpsadminos_klp_id *left,
			const struct vpsadminos_klp_id *right)
{
	return left->high == right->high && left->low == right->low;
}

static inline bool vpsadminos_klp_id_is_zero(
		const struct vpsadminos_klp_id *id)
{
	return !id->high && !id->low;
}

enum vpsadminos_klp_anchor_class {
	VPSADMINOS_KLP_ANCHOR_NONE,
	VPSADMINOS_KLP_ANCHOR_SUPPORTED,
	VPSADMINOS_KLP_ANCHOR_REMEDIATION,
};

/*
 * The inventory identity is a two-key SipHash transcript over the ordered
 * klp object/function metadata.  It is independent of relocated addresses.
 */
struct vpsadminos_klp_artifact_spec {
	const char *module_name;
	struct vpsadminos_klp_id artifact_id;
	struct vpsadminos_klp_id inventory_id;
	u32 function_count;
	u32 order;
	bool replace;
};

struct vpsadminos_klp_graph_entry {
	struct vpsadminos_klp_id artifact_id;
	u64 required_mask;
};

struct vpsadminos_klp_dependency_state;
struct vpsadminos_klp_foundation_state;

typedef void (*vpsadminos_klp_terminal_fn)(struct module *owner,
					    bool enabled, void *data);

#ifdef __GENKSYMS__
struct vpsadminos_klp_dependency_state {
	u64 magic;
	u32 abi_version;
	bool active;
	bool absorbing;
	struct module *owner;
	struct vpsadminos_klp_id owner_id;
	void *foundation;

	int (*begin)();
	int (*acquire)();
	void (*release)();
	void (*abort)();
	void (*activate)();
	void (*deactivate)();
	int (*install_foundation)();
	void (*complete_transition)();
	int (*prepare_absorb)();
	void (*abort_absorb)();
	void (*commit_absorb)();
};

struct vpsadminos_klp_foundation_state {
	u64 magic;
	u32 abi_version;
	bool active;
	bool absorbing;
	struct module *owner;
	struct vpsadminos_klp_id owner_id;
	void *dependency;
	void *artifact;

	int (*register_completion)();
	void (*cancel_completion)();
	int (*prepare_transition)();
	void (*complete_transition)();
	void (*deactivate)();
	int (*target_claim)();
	void (*target_release)();
	u64 (*target_generation)();
	void (*target_retire)();
	int (*target_import)();
	int (*prepare_absorb)();
	void (*abort_absorb)();
	void (*commit_absorb)();
};

struct vpsadminos_klp_coverage_state {
	u64 magic;
	u32 abi_version;
	u32 generation;
	u32 expected_artifacts;
	u64 completed_artifacts;
	struct vpsadminos_klp_id owner_token;
	struct vpsadminos_klp_id anchor_token;
	struct vpsadminos_klp_id final_token;
	enum vpsadminos_klp_anchor_class anchor_class;
	bool active;
	bool complete;
	bool failed;
	struct module *owner;
	void *lifetime;
	char anchor_identity[32];
	char final_identity[32];
};
#else
struct vpsadminos_klp_dependency_state {
	u64 magic;
	u32 abi_version;
	bool active;
	bool absorbing;
	struct module *owner;
	struct vpsadminos_klp_id owner_id;
	struct vpsadminos_klp_foundation_state *foundation;

	int (*begin)(struct vpsadminos_klp_dependency_state *state,
		     struct module *owner,
		     const struct vpsadminos_klp_artifact_spec *spec,
		     struct vpsadminos_klp_artifact_token **tokenp);
	int (*acquire)(struct vpsadminos_klp_dependency_state *state,
		       struct vpsadminos_klp_artifact_token *dependent,
		       const struct vpsadminos_klp_artifact_spec *required,
		       struct vpsadminos_klp_dependency_token **tokenp);
	void (*release)(struct vpsadminos_klp_dependency_state *state,
			struct vpsadminos_klp_dependency_token *token);
	void (*abort)(struct vpsadminos_klp_dependency_state *state,
		      struct vpsadminos_klp_artifact_token *token);
	void (*activate)(struct vpsadminos_klp_dependency_state *state,
			 struct vpsadminos_klp_artifact_token *token);
	void (*deactivate)(struct vpsadminos_klp_dependency_state *state,
			   struct vpsadminos_klp_artifact_token *token);
	int (*install_foundation)(struct vpsadminos_klp_dependency_state *state,
				  struct module *owner,
				  struct vpsadminos_klp_foundation_state *foundation);
	void (*complete_transition)(struct vpsadminos_klp_dependency_state *state,
				    struct klp_patch *patch);
	int (*prepare_absorb)(struct vpsadminos_klp_dependency_state *state,
			      struct module *checkpoint,
			      const struct vpsadminos_klp_artifact_spec *checkpoint_spec,
			      const struct vpsadminos_klp_graph_entry *graph,
			      u32 graph_count,
			      struct vpsadminos_klp_dependency_state *successor,
			      struct vpsadminos_klp_dependency_absorb **prepared,
			      struct vpsadminos_klp_artifact_token **successor_artifact);
	void (*abort_absorb)(struct vpsadminos_klp_dependency_absorb *prepared);
	void (*commit_absorb)(struct vpsadminos_klp_dependency_absorb *prepared);
};

struct vpsadminos_klp_foundation_state {
	u64 magic;
	u32 abi_version;
	bool active;
	bool absorbing;
	struct module *owner;
	struct vpsadminos_klp_id owner_id;
	struct vpsadminos_klp_dependency_state *dependency;
	struct vpsadminos_klp_artifact_token *artifact;

	int (*register_completion)(struct vpsadminos_klp_foundation_state *state,
				   struct module *owner,
				   const struct vpsadminos_klp_id *artifact_id,
				   vpsadminos_klp_terminal_fn complete,
				   void *data);
	void (*cancel_completion)(struct vpsadminos_klp_foundation_state *state,
				  struct module *owner);
	int (*prepare_transition)(struct klp_patch *patch);
	void (*complete_transition)(struct vpsadminos_klp_foundation_state *state,
				    struct klp_patch *patch);
	void (*deactivate)(struct vpsadminos_klp_foundation_state *state);
	int (*target_claim)(struct vpsadminos_klp_foundation_state *state,
			    struct module *mod, const char *object_name,
			    struct vpsadminos_klp_target_token **tokenp);
	void (*target_release)(struct vpsadminos_klp_foundation_state *state,
			       struct vpsadminos_klp_target_token *token);
	u64 (*target_generation)(struct vpsadminos_klp_foundation_state *state,
				 const struct vpsadminos_klp_target_token *token);
	void (*target_retire)(struct vpsadminos_klp_foundation_state *state,
			      struct module *mod);
	int (*target_import)(struct vpsadminos_klp_foundation_state *state,
			     struct module *mod, u64 generation);
	int (*prepare_absorb)(struct vpsadminos_klp_foundation_state *state,
			      struct module *checkpoint,
			      struct vpsadminos_klp_foundation_state *successor,
			      const struct vpsadminos_klp_id *expected,
			      u32 expected_count,
			      struct vpsadminos_klp_foundation_absorb **prepared);
	void (*abort_absorb)(struct vpsadminos_klp_foundation_absorb *prepared);
	void (*commit_absorb)(struct vpsadminos_klp_foundation_absorb *prepared);
};

struct vpsadminos_klp_coverage_state {
	u64 magic;
	u32 abi_version;
	u32 generation;
	u32 expected_artifacts;
	u64 completed_artifacts;
	struct vpsadminos_klp_id owner_token;
	struct vpsadminos_klp_id anchor_token;
	struct vpsadminos_klp_id final_token;
	enum vpsadminos_klp_anchor_class anchor_class;
	bool active;
	bool complete;
	bool failed;
	struct module *owner;
	struct vpsadminos_klp_artifact_token *lifetime;
	char anchor_identity[32];
	char final_identity[32];
};
#endif

#ifdef __GENKSYMS__
struct klp_patch *vpsadminos_klp_object_patch(struct klp_object *obj);
struct klp_state *vpsadminos_klp_patch_state(struct klp_patch *patch,
					     unsigned long id);
#else
static inline struct klp_patch *
vpsadminos_klp_object_patch(struct klp_object *obj)
{
	if (!obj || !obj->kobj.parent)
		return NULL;
	return container_of(obj->kobj.parent, struct klp_patch, kobj);
}

static inline struct klp_state *
vpsadminos_klp_patch_state(struct klp_patch *patch, unsigned long id)
{
	struct klp_state *state;

	if (!patch)
		return NULL;

	for (state = patch->states; state && state->id; state++)
		if (state->id == id)
			return state;

	return NULL;
}
#endif

struct vpsadminos_klp_callback_int {
	int (*fn)(struct klp_object *obj);
	char *objname;
};

struct vpsadminos_klp_callback_void {
	void (*fn)(struct klp_object *obj);
	char *objname;
};

/* Private cross-translation-unit entry point carried inside a guard build. */
void vpsadminos_klp_dependency_complete_transition(struct klp_patch *patch);
void vpsadminos_klp_foundation_target_retire(struct module *mod);
int vpsadminos_v7_checkpoint_pre_patch(struct klp_object *obj);
void vpsadminos_v7_checkpoint_post_unpatch(struct klp_object *obj);
#if LIVEPATCH_IS_CHECKPOINT
int vpsadminos_klp_checkpoint_target_claim(struct klp_object *obj,
					   struct vpsadminos_klp_target_token **tokenp);
void vpsadminos_klp_checkpoint_target_release(struct klp_object *obj,
					      struct vpsadminos_klp_target_token **tokenp);
#endif

#endif /* _LINUX_VPSADMINOS_LIVEPATCH_FOUNDATION_H */
