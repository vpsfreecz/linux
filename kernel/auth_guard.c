// SPDX-License-Identifier: GPL-2.0-or-later

#define pr_fmt(fmt) "auth_guard: " fmt

#include <linux/auth_guard.h>
#include <linux/cache.h>
#include <linux/cgroup.h>
#include <linux/cgroup_namespace.h>
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <linux/lsm_namespace.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syslog.h>
#include <linux/syslog_namespace.h>
#include <linux/tracing_namespace.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <uapi/linux/lsm.h>

enum auth_guard_mode {
	AUTH_GUARD_MODE_PANIC,
	AUTH_GUARD_MODE_LOG,
	AUTH_GUARD_MODE_OFF,
};

enum auth_guard_task_lifecycle {
	AUTH_GUARD_TASK_LIVE,
	AUTH_GUARD_TASK_EXITING,
	AUTH_GUARD_TASK_UNPUBLISHED,
	AUTH_GUARD_TASK_EXIT_TEARDOWN,
};

static enum auth_guard_mode auth_guard_mode __ro_after_init =
	AUTH_GUARD_MODE_PANIC;
static atomic64_t auth_guard_generation = ATOMIC64_INIT(0);

static int __init auth_guard_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (!strcmp(str, "off"))
		auth_guard_mode = AUTH_GUARD_MODE_OFF;
	else if (!strcmp(str, "log"))
		auth_guard_mode = AUTH_GUARD_MODE_LOG;
	else if (!strcmp(str, "panic"))
		auth_guard_mode = AUTH_GUARD_MODE_PANIC;
	else
		return -EINVAL;

	return 0;
}
early_param("auth_guard", auth_guard_setup);

void __init auth_guard_init_domain(struct auth_guard_domain *domain)
{
	get_random_bytes(&domain->key, sizeof(domain->key));
	domain->seeded = true;
}

bool auth_guard_enabled(void)
{
	return auth_guard_mode != AUTH_GUARD_MODE_OFF;
}

u64 auth_guard_next_generation(struct auth_guard_domain *domain)
{
	u64 generation;

	if (unlikely(!READ_ONCE(domain->seeded)))
		panic("auth_guard: %s: generation: unseeded domain\n",
		      domain->name);

	generation = (u64)atomic64_inc_return(&auth_guard_generation);
	if (unlikely(!generation))
		panic("auth_guard: %s: generation counter wrapped\n", domain->name);

	return generation;
}

u64 auth_guard_nonce(void)
{
	u64 nonce;

	do {
		nonce = get_random_u64();
	} while (!nonce);

	return nonce;
}

u64 auth_guard_ptr(const void *ptr)
{
	return (u64)(unsigned long)ptr;
}

u64 auth_guard_seal(struct auth_guard_domain *domain, const void *data,
		    size_t len)
{
	u64 seal;

	if (!domain->seeded)
		panic("auth_guard: %s: seal: unseeded domain object=%p\n",
		      domain->name, data);

	seal = siphash(data, len, &domain->key);
	return seal ?: 1;
}

void auth_guard_fail(const struct auth_guard_domain *domain, const char *where,
			     const char *what, const void *object)
{
	if (auth_guard_mode == AUTH_GUARD_MODE_OFF)
		return;

	if (auth_guard_mode == AUTH_GUARD_MODE_LOG) {
		pr_emerg("%s: %s: %s object=%p current=%p pid=%d comm=%s\n",
			 domain->name, where, what, object, current,
			 current->pid, current->comm);
		return;
	}

	panic("auth_guard: %s: %s: %s object=%p current=%p pid=%d comm=%s\n",
	      domain->name, where, what, object, current, current->pid,
	      current->comm);
}

#ifdef CONFIG_CRED_GUARD
#define AUTH_GUARD_TRANSITION_PREPARING		U32_MAX
#define AUTH_GUARD_TRANSITION_OPEN		(U32_MAX - 1)
#define AUTH_GUARD_TRANSITION_QUARANTINED	(U32_MAX - 2)
#define AUTH_GUARD_TRANSITION_MAX_READERS	(U32_MAX - 3)

struct auth_guard_transition_digest {
	u64 object;
	u64 anchor;
	u64 anchor_generation;
	u64 anchor_nonce;
	u64 anchor_seal;
	u64 transition_nonce;
	u64 restore_state;
	u64 expected_state;
	u64 depth;
} __aligned(SIPHASH_ALIGNMENT);

struct auth_guard_transition {
	const void *object;
	u32 *depth;
	enum auth_guard_transition_anchor *anchor;
	u64 *nonce;
	u64 *restore_state;
	u64 *expected_state;
	u64 *seal;
};

static struct auth_guard_transition auth_guard_transition_from_state(
	const void *object, struct auth_guard_transition_state *state)
{
	return (struct auth_guard_transition) {
		.object = object,
		.depth = &state->depth,
		.anchor = &state->anchor,
		.nonce = &state->nonce,
		.restore_state = &state->restore_state,
		.expected_state = &state->expected_state,
		.seal = &state->seal,
	};
}

#ifdef CONFIG_AUTH_GUARD
static __always_inline struct auth_guard_transition
auth_guard_transition_from_fields(
	const void *object, u32 *depth, u64 *nonce, u64 *seal)
{
	return (struct auth_guard_transition) {
		.object = object,
		.depth = depth,
		.nonce = nonce,
		.seal = seal,
	};
}

static __always_inline struct auth_guard_transition
auth_guard_transition_from_unanchored_state(
	const void *object, struct auth_guard_unanchored_transition_state *state)
{
	return auth_guard_transition_from_fields(
		object, &state->depth, &state->nonce, &state->seal);
}

static __always_inline struct auth_guard_transition
auth_guard_transition_from_expectation_state(const void *object,
					     struct auth_guard_expectation_transition_state *state)
{
	struct auth_guard_transition transition =
		auth_guard_transition_from_unanchored_state(object, &state->base);

	transition.restore_state = &state->restore_state;
	transition.expected_state = &state->expected_state;
	return transition;
}

#define DEFINE_AUTH_GUARD_STAMP_OBJECT(_name, _struct, _stamp) \
static __always_inline struct auth_guard_stamp \
_name##_stamp_load(const struct _struct *object) \
{ \
	return auth_guard_stamp_load_acquire(&object->_stamp); \
} \
static __always_inline void _name##_stamp_publish( \
	struct _struct *object, const struct auth_guard_stamp *stamp) \
{ \
	auth_guard_stamp_publish_release(&object->_stamp, stamp); \
}

#define DEFINE_AUTH_GUARD_STAMP_CLEAR(_name, _struct, _stamp) \
static __always_inline void _name##_stamp_clear(struct _struct *object) \
{ \
	auth_guard_stamp_clear(&object->_stamp); \
}

#define DEFINE_AUTH_GUARD_TRANSITION_OBJECT(_name, _struct, _stamp, _marker, \
						    _from_state) \
DEFINE_AUTH_GUARD_STAMP_OBJECT(_name, _struct, _stamp) \
static __always_inline struct auth_guard_transition \
_name##_transition(const struct _struct *object) \
{ \
	struct _struct *mutable = (struct _struct *)object; \
\
	return _from_state(object, &mutable->_marker); \
}

#define DEFINE_AUTH_GUARD_OBJECT_SNAPSHOT_API(_name, _struct, _enabled, _guard) \
static enum auth_guard_check_result \
_name##_check_result(const struct _struct *object, const char *where, \
		     bool retain_reservation) \
{ \
	struct auth_guard_transition transition; \
	enum auth_guard_check_result result; \
\
	if (!_enabled()) \
		return AUTH_GUARD_CHECK_VALID; \
	if (!object) { \
		auth_guard_fail(&_guard, where, "missing", object); \
		return AUTH_GUARD_CHECK_INVALID; \
	} \
	transition = _name##_transition(object); \
	result = auth_guard_transition_reader_begin(&_guard, where, &transition); \
	if (result != AUTH_GUARD_CHECK_VALID) \
		return result; \
	result = _name##_check_reserved(object, where, &transition) ? \
		AUTH_GUARD_CHECK_VALID : AUTH_GUARD_CHECK_INVALID; \
	if (result != AUTH_GUARD_CHECK_VALID || !retain_reservation) { \
		if (!auth_guard_transition_reader_end(&_guard, where, &transition)) \
			result = AUTH_GUARD_CHECK_INVALID; \
	} \
	return result; \
} \
bool _name##_check_where(const struct _struct *object, const char *where) \
{ \
	return _name##_check_result(object, where, false) == \
		AUTH_GUARD_CHECK_VALID; \
} \
enum auth_guard_check_result \
_name##_snapshot_begin_where(const struct _struct *object, const char *where) \
{ \
	return _name##_check_result(object, where, true); \
} \
bool _name##_snapshot_end_where(const struct _struct *object, \
					const char *where) \
{ \
	struct auth_guard_transition transition; \
	bool valid; \
\
	if (!_enabled()) \
		return true; \
	if (!object) { \
		auth_guard_fail(&_guard, where, "missing snapshot", object); \
		return false; \
	} \
	transition = _name##_transition(object); \
	valid = _name##_check_reserved(object, where, &transition); \
	return auth_guard_transition_reader_end( \
		&_guard, where, &transition) && valid; \
}
#endif

static enum auth_guard_transition_anchor
auth_guard_transition_anchor_load(const struct auth_guard_transition *transition)
{
	if (!transition->anchor)
		return AUTH_GUARD_TRANSITION_ANCHOR_NONE;
	return READ_ONCE(*transition->anchor);
}

static bool auth_guard_transition_anchor_supported(
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor)
{
	if ((unsigned int)anchor >= AUTH_GUARD_TRANSITION_ANCHOR_COUNT)
		return false;
	return transition->anchor ?
		anchor != AUTH_GUARD_TRANSITION_ANCHOR_NONE :
		anchor == AUTH_GUARD_TRANSITION_ANCHOR_NONE;
}

static u64 auth_guard_transition_hash(
	struct auth_guard_domain *domain,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, u64 transition_nonce,
	u64 restore_state, u64 expected_state, u32 depth)
{
	struct auth_guard_transition_digest digest = {
		.object			= auth_guard_ptr(transition->object),
		.anchor			= anchor,
		.anchor_generation	= stamp->generation,
		.anchor_nonce		= stamp->nonce,
		.anchor_seal		= stamp->seal,
		.transition_nonce	= transition_nonce,
		.restore_state		= restore_state,
		.expected_state		= expected_state,
		.depth			= depth,
	};

	return auth_guard_seal(domain, &digest, sizeof(digest));
}

static bool auth_guard_transition_marker_empty(
	const struct auth_guard_transition *transition)
{
	return auth_guard_transition_anchor_load(transition) ==
			AUTH_GUARD_TRANSITION_ANCHOR_NONE &&
		!READ_ONCE(*transition->nonce) &&
		(!transition->restore_state ||
		 !READ_ONCE(*transition->restore_state)) &&
		(!transition->expected_state ||
		 !READ_ONCE(*transition->expected_state)) &&
		!READ_ONCE(*transition->seal);
}

static void auth_guard_transition_marker_clear(
	const struct auth_guard_transition *transition)
{
	WRITE_ONCE(*transition->seal, 0);
	if (transition->expected_state)
		WRITE_ONCE(*transition->expected_state, 0);
	if (transition->restore_state)
		WRITE_ONCE(*transition->restore_state, 0);
	WRITE_ONCE(*transition->nonce, 0);
	if (transition->anchor)
		WRITE_ONCE(*transition->anchor,
			   AUTH_GUARD_TRANSITION_ANCHOR_NONE);
}

static void auth_guard_transition_clear(
	const struct auth_guard_transition *transition)
{
	auth_guard_transition_marker_clear(transition);
	/* Publish the idle state only after all authenticated metadata is empty. */
	smp_store_release(transition->depth, 0);
}

static void auth_guard_transition_quarantine(
	const struct auth_guard_transition *transition)
{
	/* Preserve the authenticated marker while excluding readers and writers. */
	smp_store_release(transition->depth, AUTH_GUARD_TRANSITION_QUARANTINED);
}

static void auth_guard_transition_initialize(
	const struct auth_guard_transition *transition)
{
	WRITE_ONCE(*transition->depth, AUTH_GUARD_TRANSITION_PREPARING);
	/* Publish exclusion before replacing inherited or constructor metadata. */
	smp_mb();
	auth_guard_transition_marker_clear(transition);
}

static enum auth_guard_check_result auth_guard_transition_reader_begin(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	u32 readers;

	for (;;) {
		readers = READ_ONCE(*transition->depth);
		if (readers == AUTH_GUARD_TRANSITION_PREPARING ||
		    readers == AUTH_GUARD_TRANSITION_OPEN)
			return AUTH_GUARD_CHECK_BUSY;
		if (readers == AUTH_GUARD_TRANSITION_QUARANTINED) {
			auth_guard_fail(domain, where, "quarantined transition",
					transition->object);
			return AUTH_GUARD_CHECK_INVALID;
		}
		if (unlikely(readers == AUTH_GUARD_TRANSITION_MAX_READERS))
			return AUTH_GUARD_CHECK_BUSY;
		if (cmpxchg(transition->depth, readers, readers + 1) == readers)
			return AUTH_GUARD_CHECK_VALID;
		cpu_relax();
	}
}

static bool auth_guard_transition_reader_end(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	u32 readers;

	for (;;) {
		readers = READ_ONCE(*transition->depth);
		if (!readers || readers > AUTH_GUARD_TRANSITION_MAX_READERS) {
			auth_guard_fail(domain, where, "lost reader reservation",
					transition->object);
			return false;
		}
		/* cmpxchg provides release ordering when the last reader leaves. */
		if (cmpxchg(transition->depth, readers, readers - 1) == readers)
			return true;
		cpu_relax();
	}
}

static bool auth_guard_transition_reader_stable(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	const struct auth_guard_stamp *expected_stamp,
	const struct auth_guard_stamp *current_stamp)
{
	u32 readers = READ_ONCE(*transition->depth);

	if (!readers || readers > AUTH_GUARD_TRANSITION_MAX_READERS) {
		auth_guard_fail(domain, where, "lost reader reservation",
				transition->object);
		return false;
	}
	if (expected_stamp &&
	    (!current_stamp ||
	     !auth_guard_stamp_equal(current_stamp, expected_stamp))) {
		auth_guard_fail(domain, where, "changed during reader",
				transition->object);
		return false;
	}
	if (!auth_guard_transition_marker_empty(transition)) {
		auth_guard_fail(domain, where, "corrupt idle transition",
				transition->object);
		return false;
	}

	return true;
}

static enum auth_guard_check_result auth_guard_transition_reserve(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	u32 state;

	state = cmpxchg(transition->depth, 0, AUTH_GUARD_TRANSITION_PREPARING);
	if (state == AUTH_GUARD_TRANSITION_QUARANTINED) {
		auth_guard_fail(domain, where, "quarantined transition",
				transition->object);
		return AUTH_GUARD_CHECK_INVALID;
	}
	if (state)
		return AUTH_GUARD_CHECK_BUSY;
	if (!auth_guard_transition_marker_empty(transition)) {
		auth_guard_fail(domain, where, "corrupt idle transition",
				transition->object);
		auth_guard_transition_quarantine(transition);
		return AUTH_GUARD_CHECK_INVALID;
	}

	return AUTH_GUARD_CHECK_VALID;
}

static enum auth_guard_check_result auth_guard_transition_reserve_teardown(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition, bool local)
{
	u32 state;

	for (;;) {
		state = cmpxchg(transition->depth, 0,
				AUTH_GUARD_TRANSITION_PREPARING);
		if (!state)
			break;
		if (state <= AUTH_GUARD_TRANSITION_MAX_READERS) {
			cpu_relax();
			continue;
		}
		if (state == AUTH_GUARD_TRANSITION_PREPARING ||
		    state == AUTH_GUARD_TRANSITION_OPEN) {
			if (!local) {
				auth_guard_fail(domain, where,
						"remote active teardown transition",
						transition->object);
				return AUTH_GUARD_CHECK_BUSY;
			}
			auth_guard_fail(domain, where,
					"abandoned teardown transition",
					transition->object);
			auth_guard_transition_quarantine(transition);
			return AUTH_GUARD_CHECK_INVALID;
		}
		auth_guard_fail(domain, where, "quarantined teardown transition",
				transition->object);
		return AUTH_GUARD_CHECK_INVALID;
	}

	if (!auth_guard_transition_marker_empty(transition)) {
		auth_guard_fail(domain, where, "corrupt teardown reservation",
				transition->object);
		auth_guard_transition_quarantine(transition);
		return AUTH_GUARD_CHECK_INVALID;
	}

	return AUTH_GUARD_CHECK_VALID;
}

static bool auth_guard_transition_reservation_valid(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	if (READ_ONCE(*transition->depth) == AUTH_GUARD_TRANSITION_PREPARING &&
	    auth_guard_transition_marker_empty(transition))
		return true;

	auth_guard_fail(domain, where, "lost transition reservation",
			transition->object);
	auth_guard_transition_quarantine(transition);
	return false;
}

static bool auth_guard_transition_publish(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, u64 restore_state,
	u64 expected_state)
{
	u64 nonce;
	u64 seal;

	if (!auth_guard_transition_anchor_supported(transition, anchor) ||
	    (!!transition->restore_state != !!restore_state) ||
	    (!!transition->expected_state != !!expected_state) ||
	    !auth_guard_stamp_valid(stamp)) {
		auth_guard_fail(domain, where, "invalid transition anchor",
				transition->object);
		auth_guard_transition_quarantine(transition);
		return false;
	}
	if (!auth_guard_transition_reservation_valid(domain, where, transition))
		return false;

	nonce = auth_guard_nonce();
	seal = auth_guard_transition_hash(domain, transition, anchor, stamp, nonce,
					  restore_state,
					  expected_state,
					  AUTH_GUARD_TRANSITION_OPEN);
	if (transition->anchor)
		WRITE_ONCE(*transition->anchor, anchor);
	WRITE_ONCE(*transition->nonce, nonce);
	if (transition->restore_state)
		WRITE_ONCE(*transition->restore_state, restore_state);
	if (transition->expected_state)
		WRITE_ONCE(*transition->expected_state, expected_state);
	WRITE_ONCE(*transition->seal, seal);
	/* Authority fields may be mutated only after the complete marker is live. */
	smp_store_release(transition->depth, AUTH_GUARD_TRANSITION_OPEN);
	return true;
}

static bool __auth_guard_transition_verify(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, bool allow_quarantined,
	u64 *restore_state, u64 *expected_state)
{
	u64 transition_restore_state;
	u64 transition_expected_state;
	u64 transition_nonce;
	u64 transition_seal;
	u32 depth;

	if (!auth_guard_transition_anchor_supported(transition, anchor) ||
	    !auth_guard_stamp_valid(stamp)) {
		auth_guard_fail(domain, where, "invalid transition anchor",
				transition->object);
		return false;
	}
	/* Acquire the complete marker published by the writer. */
	depth = smp_load_acquire(transition->depth);
	/* Pair with release publication when an open marker is reanchored. */
	transition_seal = smp_load_acquire(transition->seal);
	transition_nonce = READ_ONCE(*transition->nonce);
	transition_restore_state = transition->restore_state ?
		READ_ONCE(*transition->restore_state) : 0;
	transition_expected_state = transition->expected_state ?
		READ_ONCE(*transition->expected_state) : 0;
	if ((depth != AUTH_GUARD_TRANSITION_OPEN &&
	     (!allow_quarantined ||
	      depth != AUTH_GUARD_TRANSITION_QUARANTINED)) ||
	    !transition_nonce || !transition_seal ||
	    auth_guard_transition_anchor_load(transition) != anchor) {
		auth_guard_fail(domain, where, "missing transition",
				transition->object);
		return false;
	}
	if (auth_guard_transition_hash(
		    domain, transition, anchor, stamp, transition_nonce,
		    transition_restore_state,
		    transition_expected_state,
		    AUTH_GUARD_TRANSITION_OPEN) != transition_seal) {
		auth_guard_fail(domain, where, "corrupt transition",
				transition->object);
		return false;
	}
	if (restore_state)
		*restore_state = transition_restore_state;
	if (expected_state)
		*expected_state = transition_expected_state;

	return true;
}

static bool auth_guard_transition_verify(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp)
{
	return __auth_guard_transition_verify(domain, where, transition, anchor,
					      stamp, false, NULL, NULL);
}

static bool auth_guard_transition_can_complete(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, bool allow_quarantined)
{
	if (__auth_guard_transition_verify(domain, where, transition, anchor, stamp,
					  allow_quarantined, NULL, NULL))
		return true;
	auth_guard_transition_quarantine(transition);
	return false;
}

#ifdef CONFIG_AUTH_GUARD
static bool auth_guard_transition_can_finish(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp)
{
	return auth_guard_transition_can_complete(domain, where, transition,
						  anchor, stamp, false);
}

static bool auth_guard_transition_can_abort(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp)
{
	return auth_guard_transition_can_complete(domain, where, transition,
						  anchor, stamp, true);
}
#endif

static bool auth_guard_transition_reanchor(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor old_anchor,
	const struct auth_guard_stamp *old_stamp,
	enum auth_guard_transition_anchor new_anchor,
	const struct auth_guard_stamp *new_stamp)
{
	u64 expected_state;
	u64 nonce;
	u64 seal;

	if (!transition->anchor) {
		auth_guard_fail(domain, where, "unanchored replacement transition",
				transition->object);
		goto quarantine;
	}
	if (!__auth_guard_transition_verify(domain, where, transition, old_anchor,
					    old_stamp, false, NULL,
					    &expected_state))
		goto quarantine;
	if (!auth_guard_transition_anchor_supported(transition, new_anchor) ||
	    !auth_guard_stamp_valid(new_stamp)) {
		auth_guard_fail(domain, where, "invalid replacement anchor",
				transition->object);
		goto quarantine;
	}

	nonce = auth_guard_nonce();
	seal = auth_guard_transition_hash(domain, transition, new_anchor, new_stamp,
					  nonce, expected_state, expected_state,
					  AUTH_GUARD_TRANSITION_OPEN);
	WRITE_ONCE(*transition->anchor, new_anchor);
	WRITE_ONCE(*transition->nonce, nonce);
	WRITE_ONCE(*transition->restore_state, expected_state);
	/* Publish replacement anchor metadata before its authenticating seal. */
	smp_store_release(transition->seal, seal);
	return true;

quarantine:
	auth_guard_transition_quarantine(transition);
	return false;
}

static bool auth_guard_transition_update_expected(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, u64 current_state, u64 expected_state)
{
	u64 authenticated_restore_state;
	u64 authenticated_state;
	u64 nonce;
	u64 seal;

	if (!transition->expected_state || !current_state || !expected_state) {
		auth_guard_fail(domain, where, "invalid transition expectation",
				transition->object);
		goto quarantine;
	}
	if (!__auth_guard_transition_verify(domain, where, transition, anchor,
					    stamp, false,
					    &authenticated_restore_state,
					    &authenticated_state))
		goto quarantine;
	if (authenticated_state != current_state) {
		auth_guard_fail(domain, where, "unexpected transition state",
				transition->object);
		goto quarantine;
	}

	nonce = auth_guard_nonce();
	seal = auth_guard_transition_hash(domain, transition, anchor, stamp, nonce,
					  authenticated_restore_state,
					  expected_state,
					  AUTH_GUARD_TRANSITION_OPEN);
	WRITE_ONCE(*transition->expected_state, expected_state);
	WRITE_ONCE(*transition->nonce, nonce);
	/* Keep readers excluded while publishing the replacement expectation. */
	smp_store_release(transition->seal, seal);
	return true;

quarantine:
	auth_guard_transition_quarantine(transition);
	return false;
}

static bool auth_guard_transition_cancel_reservation(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	if (!auth_guard_transition_reservation_valid(domain, where, transition))
		return false;
	auth_guard_transition_clear(transition);
	return true;
}

static bool auth_guard_transition_complete(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, bool allow_quarantined)
{
	if (!auth_guard_transition_can_complete(domain, where, transition, anchor,
						   stamp, allow_quarantined))
		return false;
	auth_guard_transition_clear(transition);
	return true;
}

static bool auth_guard_transition_close(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp)
{
	return auth_guard_transition_complete(domain, where, transition, anchor,
					      stamp, false);
}

static bool auth_guard_transition_abort_close(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition,
	enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp)
{
	return auth_guard_transition_complete(domain, where, transition, anchor,
					      stamp, true);
}

static bool auth_guard_transition_terminal_close(
	struct auth_guard_domain *domain, const char *where,
	const struct auth_guard_transition *transition)
{
	u32 state;

	/* Acquire the terminal writer exclusion or quarantine publication. */
	state = smp_load_acquire(transition->depth);

	if (state != AUTH_GUARD_TRANSITION_PREPARING &&
	    state != AUTH_GUARD_TRANSITION_OPEN &&
	    state != AUTH_GUARD_TRANSITION_QUARANTINED) {
		auth_guard_fail(domain, where, "missing terminal exclusion",
				transition->object);
		return false;
	}
	auth_guard_transition_clear(transition);
	return true;
}

static struct auth_guard_domain task_transition_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("task_authority");
static bool task_transition_guard_active __ro_after_init;

static bool auth_guard_task_transition_enabled(void)
{
	return auth_guard_layer_enabled(task_transition_guard_active);
}

static struct auth_guard_transition
auth_guard_task_transition(struct task_struct *task)
{
	return auth_guard_transition_from_state(task, &task->auth_guard_transition);
}

static enum auth_guard_check_result auth_guard_task_capture_anchor_state(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where, u64 *state);

void __init auth_guard_task_transition_enable(void)
{
	auth_guard_init_domain(&task_transition_guard);
	task_transition_guard_active = true;
}

#define DEFINE_AUTH_GUARD_TASK_RESULT_ADAPTER(_storage, _name, _operation) \
_storage enum auth_guard_check_result _name(struct task_struct *task,      \
					     const char *where)             \
{                                                                        \
	struct auth_guard_transition transition;                           \
	if (!auth_guard_task_transition_enabled())                         \
		return AUTH_GUARD_CHECK_VALID;                                \
	if (!task) {                                                        \
		auth_guard_fail(&task_transition_guard, where,                \
				"missing", task);                                  \
		return AUTH_GUARD_CHECK_INVALID;                              \
	}                                                                    \
	transition = auth_guard_task_transition(task);                      \
	return _operation(&task_transition_guard, where, &transition);      \
}

#define DEFINE_AUTH_GUARD_TASK_BOOL_ADAPTER(_name, _operation, ...) \
bool _name(struct task_struct *task, const char *where)              \
{                                                                    \
	struct auth_guard_transition transition;                       \
	if (!auth_guard_task_transition_enabled())                     \
		return true;                                              \
	if (!task)                                                     \
		return false;                                             \
	transition = auth_guard_task_transition(task);                  \
	return _operation(&task_transition_guard, where, &transition,   \
			  ##__VA_ARGS__);                                  \
}

#define DEFINE_AUTH_GUARD_TASK_ANCHOR_ADAPTER(                            \
		_name, _operation, _diagnose_missing, _missing)             \
bool _name(struct task_struct *task,                                      \
	   enum auth_guard_transition_anchor anchor,                        \
	   const struct auth_guard_stamp *stamp, const char *where)         \
{                                                                         \
	struct auth_guard_transition transition;                            \
	if (!auth_guard_task_transition_enabled())                          \
		return true;                                                   \
	if (!task) {                                                         \
		if (_diagnose_missing)                                        \
			auth_guard_fail(&task_transition_guard, where,           \
					_missing, task);                            \
		return false;                                                  \
	}                                                                    \
	transition = auth_guard_task_transition(task);                       \
	return _operation(&task_transition_guard, where, &transition,        \
			  anchor, stamp);                                        \
}

DEFINE_AUTH_GUARD_TASK_RESULT_ADAPTER(
	, auth_guard_task_transition_reader_begin_where,
	auth_guard_transition_reader_begin)
DEFINE_AUTH_GUARD_TASK_BOOL_ADAPTER(
	auth_guard_task_transition_reader_stable_where,
	auth_guard_transition_reader_stable, NULL, NULL)
DEFINE_AUTH_GUARD_TASK_BOOL_ADAPTER(
	auth_guard_task_transition_reader_end_where,
	auth_guard_transition_reader_end)
DEFINE_AUTH_GUARD_TASK_RESULT_ADAPTER(
	static, auth_guard_task_transition_reserve_where,
	auth_guard_transition_reserve)
DEFINE_AUTH_GUARD_TASK_BOOL_ADAPTER(
	auth_guard_task_transition_terminal_close_where,
	auth_guard_transition_terminal_close)
DEFINE_AUTH_GUARD_TASK_ANCHOR_ADAPTER(auth_guard_task_transition_verify_where,
				      auth_guard_transition_verify,
				      true, "invalid transition anchor")
DEFINE_AUTH_GUARD_TASK_ANCHOR_ADAPTER(auth_guard_task_transition_close_where,
				      auth_guard_transition_close, false, NULL)

static bool auth_guard_task_transition_publish_exact_where(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, u64 restore_state,
	u64 expected_state, const char *where)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled())
		return true;
	if (!task || !restore_state || !expected_state) {
		auth_guard_fail(&task_transition_guard, where,
				"invalid transition expectation", task);
		return false;
	}
	transition = auth_guard_task_transition(task);
	return auth_guard_transition_publish(
		&task_transition_guard, where, &transition, anchor, stamp,
		restore_state, expected_state);
}

bool auth_guard_task_transition_publish_where(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where)
{
	u64 state;

	if (!auth_guard_task_transition_enabled())
		return true;
	if (auth_guard_task_capture_anchor_state(
		    task, anchor, stamp, where, &state) != AUTH_GUARD_CHECK_VALID) {
		auth_guard_fail(&task_transition_guard, where,
				"invalid transition source", task);
		return false;
	}
	return auth_guard_task_transition_publish_exact_where(
		task, anchor, stamp, state, state, where);
}

static bool auth_guard_task_transition_update_expected_where(
	struct task_struct *task, u64 current_state, u64 expected_state,
	const char *where)
{
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;
	enum auth_guard_transition_anchor anchor;

	if (!auth_guard_task_transition_enabled())
		return true;
	if (!task || !current_state || !expected_state)
		return false;
	transition = auth_guard_task_transition(task);
	anchor = auth_guard_transition_anchor_load(&transition);
	switch (anchor) {
	case AUTH_GUARD_TRANSITION_ANCHOR_CRED:
		stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
		break;
#ifdef CONFIG_AUTH_GUARD
	case AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY:
		stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
		break;
#endif
	default:
		auth_guard_fail(&task_transition_guard, where,
				"invalid expectation anchor", task);
		auth_guard_transition_quarantine(&transition);
		return false;
	}
	return auth_guard_transition_update_expected(
		&task_transition_guard, where, &transition, anchor, &stamp,
		current_state, expected_state);
}

#undef DEFINE_AUTH_GUARD_TASK_ANCHOR_ADAPTER
#undef DEFINE_AUTH_GUARD_TASK_BOOL_ADAPTER
#undef DEFINE_AUTH_GUARD_TASK_RESULT_ADAPTER

enum auth_guard_check_result
auth_guard_task_transition_reserve_teardown_where(struct task_struct *task,
						  const char *where)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled())
		return AUTH_GUARD_CHECK_VALID;
	if (!task) {
		auth_guard_fail(&task_transition_guard, where,
					"missing teardown transition", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	transition = auth_guard_task_transition(task);
	return auth_guard_transition_reserve_teardown(
		&task_transition_guard, where, &transition, task == current);
}

bool auth_guard_task_transition_cred_published_where(
	struct task_struct *task, const struct auth_guard_stamp *old_stamp,
	const struct auth_guard_stamp *new_stamp, bool retain,
	bool *coordinator_open, const char *where)
{
	struct auth_guard_transition transition;
	enum auth_guard_transition_anchor anchor;
#ifdef CONFIG_AUTH_GUARD
	struct auth_guard_stamp authority_stamp;
#endif

	if (!auth_guard_task_transition_enabled())
		return true;
	if (!task || !old_stamp || !new_stamp || !coordinator_open ||
	    !*coordinator_open) {
		auth_guard_fail(&task_transition_guard, where,
				"invalid credential publication", task);
		if (task) {
			transition = auth_guard_task_transition(task);
			auth_guard_transition_quarantine(&transition);
		}
		return false;
	}

	transition = auth_guard_task_transition(task);
	anchor = auth_guard_transition_anchor_load(&transition);
	if (anchor == AUTH_GUARD_TRANSITION_ANCHOR_CRED) {
		if (!auth_guard_transition_reanchor(
			    &task_transition_guard, where, &transition,
			    AUTH_GUARD_TRANSITION_ANCHOR_CRED, old_stamp,
			    AUTH_GUARD_TRANSITION_ANCHOR_CRED, new_stamp))
			return false;
		if (retain)
			return true;
		if (!auth_guard_transition_close(
			    &task_transition_guard, where, &transition,
			    AUTH_GUARD_TRANSITION_ANCHOR_CRED, new_stamp))
			return false;
		*coordinator_open = false;
		return true;
	}

#ifdef CONFIG_AUTH_GUARD
	if (anchor == AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY) {
		authority_stamp =
			auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
		if (auth_guard_transition_verify(
			    &task_transition_guard, where, &transition,
			    AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY,
			    &authority_stamp))
			return true;
		goto quarantine;
	}
#endif

	auth_guard_fail(&task_transition_guard, where,
			"invalid credential publication anchor", task);
#ifdef CONFIG_AUTH_GUARD
quarantine:
#endif
	auth_guard_transition_quarantine(&transition);
	return false;
}

static void auth_guard_task_transition_cancel_reservation(
	struct task_struct *task, const char *where)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled())
		return;
	if (!task)
		return;
	transition = auth_guard_task_transition(task);
	(void)auth_guard_transition_cancel_reservation(
		&task_transition_guard, where, &transition);
}

void auth_guard_task_transition_quarantine(struct task_struct *task)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled() || !task)
		return;
	transition = auth_guard_task_transition(task);
	auth_guard_transition_quarantine(&transition);
}

bool auth_guard_task_first_seal_begin_where(struct task_struct *task,
					    const char *where)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_transition_guard, where,
				"missing first-seal task", task);
		return false;
	}
	transition = auth_guard_task_transition(task);
	auth_guard_transition_initialize(&transition);
	return true;
}

void auth_guard_task_first_seal_complete(struct task_struct *task, bool valid)
{
	struct auth_guard_transition transition;

	if (!auth_guard_task_transition_enabled())
		return;
	transition = auth_guard_task_transition(task);
	if (valid)
		auth_guard_transition_clear(&transition);
	else
		auth_guard_transition_quarantine(&transition);
}

static enum auth_guard_check_result
auth_guard_task_validate_cred_reservation(struct task_struct *task,
					  const char *where,
					  struct auth_guard_stamp *stamp,
					  u64 *state)
{
	*stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	return auth_guard_task_capture_anchor_state(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, stamp, where, state);
}

#ifndef CONFIG_AUTH_GUARD
struct auth_guard_task_cred_semantic_digest {
	u64 purpose;
	u64 task;
	u64 real_cred;
	u64 cred;
	u64 cred_generation;
	u64 cred_nonce;
	u64 cred_seal;
} __aligned(SIPHASH_ALIGNMENT);

static u64 auth_guard_task_cred_semantic_hash(
	const struct task_struct *task, const struct cred *real_cred,
	const struct cred *subj_cred, const struct auth_guard_stamp *stamp)
{
	struct auth_guard_task_cred_semantic_digest digest = {
		.purpose = 0x43524544,
		.task = auth_guard_ptr(task),
		.real_cred = auth_guard_ptr(real_cred),
		.cred = auth_guard_ptr(subj_cred),
		.cred_generation = stamp->generation,
		.cred_nonce = stamp->nonce,
		.cred_seal = stamp->seal,
	};

	return auth_guard_seal(&task_transition_guard, &digest,
			       sizeof(digest));
}

static enum auth_guard_check_result auth_guard_task_capture_anchor_state(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where, u64 *state)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp verified_stamp;
	const struct cred *real_cred;
	const struct cred *subj_cred;

	if (!task || !stamp || !state ||
	    anchor != AUTH_GUARD_TRANSITION_ANCHOR_CRED ||
	    !auth_guard_stamp_valid(stamp))
		return AUTH_GUARD_CHECK_INVALID;
	real_cred = rcu_access_pointer(task->real_cred);
	subj_cred = rcu_access_pointer(task->cred);
	current_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, stamp) ||
	    cred_guard_check_task_cred_reserved_where(task, real_cred, where) !=
		    AUTH_GUARD_CHECK_VALID)
		goto changed;
	verified_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&verified_stamp, stamp) ||
	    rcu_access_pointer(task->real_cred) != real_cred ||
	    rcu_access_pointer(task->cred) != subj_cred)
		goto changed;

	*state = auth_guard_task_cred_semantic_hash(
		task, real_cred, subj_cred, stamp);
	return *state ? AUTH_GUARD_CHECK_VALID : AUTH_GUARD_CHECK_INVALID;

changed:
	auth_guard_fail(&task_transition_guard, where,
			"changed credential expectation", task);
	return AUTH_GUARD_CHECK_INVALID;
}

bool auth_guard_task_expect_creds_where(
	struct task_struct *task, const struct cred *new_real,
	const struct cred *new_subj, const struct auth_guard_stamp *new_stamp,
	struct auth_guard_stamp *old_stamp, const struct cred **old_real,
	const struct cred **old_subj,
	const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stable_stamp;
	const struct cred *real_cred;
	const struct cred *subj_cred;
	u64 current_state;
	u64 expected_state;

	if (!task || !new_real || !new_subj || !new_stamp || !old_stamp ||
	    !old_real || !old_subj || !auth_guard_stamp_valid(new_stamp))
		return false;
	real_cred = rcu_access_pointer(task->real_cred);
	subj_cred = rcu_access_pointer(task->cred);
	current_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (auth_guard_task_capture_anchor_state(
		    task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &current_stamp, where,
		    &current_state) != AUTH_GUARD_CHECK_VALID)
		return false;
	expected_state = auth_guard_task_cred_semantic_hash(
		task, new_real, new_subj, new_stamp);
	if (!auth_guard_task_transition_update_expected_where(
		    task, current_state, expected_state, where))
		return false;
	stable_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, &stable_stamp) ||
	    rcu_access_pointer(task->real_cred) != real_cred ||
	    rcu_access_pointer(task->cred) != subj_cred) {
		auth_guard_task_transition_quarantine(task);
		return false;
	}
	*old_stamp = current_stamp;
	*old_real = real_cred;
	*old_subj = subj_cred;
	return true;
}
#endif

static __always_inline enum auth_guard_check_result
auth_guard_task_begin_transition_reserved(
	struct task_struct *task, const char *where,
	enum auth_guard_check_result (*validate)(
		struct task_struct *task, const char *where,
		struct auth_guard_stamp *stamp, u64 *state),
	enum auth_guard_transition_anchor anchor)
{
	struct auth_guard_stamp stamp;
	enum auth_guard_check_result result;
	u64 state;

	if (unlikely(READ_ONCE(task->flags) & PF_EXITING))
		return AUTH_GUARD_CHECK_UNAVAILABLE;
	result = auth_guard_task_transition_reserve_where(task, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
	if (unlikely(READ_ONCE(task->flags) & PF_EXITING)) {
		auth_guard_task_transition_cancel_reservation(task, where);
		return AUTH_GUARD_CHECK_UNAVAILABLE;
	}

	result = validate(task, where, &stamp, &state);
	if (result != AUTH_GUARD_CHECK_VALID) {
		if (result == AUTH_GUARD_CHECK_BUSY ||
		    result == AUTH_GUARD_CHECK_UNAVAILABLE)
			auth_guard_task_transition_cancel_reservation(task, where);
		else
			auth_guard_task_transition_quarantine(task);
		return result;
	}
	if (!auth_guard_task_transition_publish_exact_where(
		    task, anchor, &stamp, state, state, where))
		return AUTH_GUARD_CHECK_INVALID;
	return AUTH_GUARD_CHECK_VALID;
}

static enum auth_guard_check_result
auth_guard_task_begin_cred_transition_once(struct task_struct *task,
					   const char *where)
{
	if (unlikely(!task))
		return AUTH_GUARD_CHECK_INVALID;
	return auth_guard_task_begin_transition_reserved(
		task, where, auth_guard_task_validate_cred_reservation,
		AUTH_GUARD_TRANSITION_ANCHOR_CRED);
}

static bool auth_guard_task_cred_transition_open_where(struct task_struct *task,
						       const char *where)
{
	struct auth_guard_stamp stamp;

	if (!task)
		return false;
	stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	return auth_guard_task_transition_verify_where(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp, where);
}

static bool auth_guard_task_finish_cred_transition_where(
	struct task_struct *task, const char *where)
{
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;
	enum auth_guard_check_result result;
	u64 expected_state;
	u64 state;

	if (!task)
		goto invalid;
	transition = auth_guard_task_transition(task);
	stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!__auth_guard_transition_verify(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp, false, NULL,
		    &expected_state))
		goto invalid;
	result = auth_guard_task_capture_anchor_state(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp, where, &state);
	if (result != AUTH_GUARD_CHECK_VALID || state != expected_state) {
		auth_guard_fail(&task_transition_guard, where,
				"unexpected credential transition result", task);
		goto invalid;
	}
	return auth_guard_transition_close(
		&task_transition_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp);

invalid:
	auth_guard_task_transition_quarantine(task);
	return false;
}

static bool auth_guard_task_abort_cred_transition_where(
	struct task_struct *task, const char *where)
{
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;
	enum auth_guard_check_result result;
	u64 restore_state;
	u64 state;

	if (!task)
		goto invalid;
	transition = auth_guard_task_transition(task);
	stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!__auth_guard_transition_verify(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp, true,
		    &restore_state, NULL))
		goto invalid;
	result = auth_guard_task_capture_anchor_state(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp, where, &state);
	if (result != AUTH_GUARD_CHECK_VALID || state != restore_state) {
		auth_guard_fail(&task_transition_guard, where,
				"unexpected credential abort state", task);
		goto invalid;
	}
	if (auth_guard_transition_abort_close(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_CRED, &stamp))
		return true;

invalid:
	auth_guard_task_transition_quarantine(task);
	return false;
}

#ifndef CONFIG_AUTH_GUARD
bool auth_guard_task_begin_transition_where(struct task_struct *task,
					    const char *where)
{
	return auth_guard_task_begin_cred_transition_once(task, where) ==
		AUTH_GUARD_CHECK_VALID;
}

bool auth_guard_task_begin_transition_wait_where(struct task_struct *task,
						 const char *where)
{
	return AUTH_GUARD_RETRY_BUSY(
		auth_guard_task_begin_cred_transition_once(task, where)) ==
		AUTH_GUARD_CHECK_VALID;
}

bool auth_guard_task_transition_open_where(struct task_struct *task,
					   const char *where)
{
	return auth_guard_task_cred_transition_open_where(task, where);
}

void auth_guard_task_abort_transition_where(struct task_struct *task,
						    const char *where)
{
	(void)auth_guard_task_abort_cred_transition_where(task, where);
}

bool auth_guard_task_finish_transition_where(struct task_struct *task,
					     const char *where)
{
	return auth_guard_task_finish_cred_transition_where(task, where);
}
#endif
#endif /* CONFIG_CRED_GUARD */

#ifdef CONFIG_AUTH_GUARD
static struct auth_guard_domain task_authority_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("task_authority");
static struct auth_guard_domain userns_boundary_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("userns_boundary");
static struct auth_guard_domain nsproxy_authority_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("nsproxy_authority");
#ifdef CONFIG_CGROUPS
static struct auth_guard_domain css_set_authority_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("css_set_authority");
static struct auth_guard_domain cgroup_ns_root_guard __ro_after_init =
	AUTH_GUARD_DOMAIN("cgroup_ns_root");
#endif
static bool auth_task_guard_active __ro_after_init;
static bool auth_userns_boundary_guard_active __ro_after_init;
static bool auth_nsproxy_guard_active __ro_after_init;
#ifdef CONFIG_CGROUPS
static bool auth_css_set_guard_active __ro_after_init;
static bool auth_cgroup_ns_root_guard_active __ro_after_init;
#endif

struct auth_guard_nsproxy_state {
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
	struct css_set *cgroup_ns_root_cset;
	struct auth_guard_stamp cgroup_ns_root_stamp;
	struct syslog_namespace *syslog_ns;
	struct tracing_namespace *tracing_ns;
};

struct auth_guard_nsproxy_transition {
	struct nsproxy *nsproxy;
	struct auth_guard_nsproxy_state old;
	struct auth_guard_nsproxy_state expected;
	struct auth_guard_stamp old_stamp;
	unsigned long declared;
	unsigned long mutated;
	bool active;
};

enum auth_guard_nsproxy_change {
	AUTH_GUARD_NSPROXY_MNT,
	AUTH_GUARD_NSPROXY_UTS,
	AUTH_GUARD_NSPROXY_IPC,
	AUTH_GUARD_NSPROXY_PID_FOR_CHILDREN,
	AUTH_GUARD_NSPROXY_NET,
	AUTH_GUARD_NSPROXY_TIME,
	AUTH_GUARD_NSPROXY_TIME_FOR_CHILDREN,
	AUTH_GUARD_NSPROXY_CGROUP,
	AUTH_GUARD_NSPROXY_CGROUP_ROOT,
	AUTH_GUARD_NSPROXY_SYSLOG,
	AUTH_GUARD_NSPROXY_TRACING,
};

static bool auth_guard_nsproxy_transition_begin_where(
	struct nsproxy *nsproxy, struct auth_guard_nsproxy_transition *transaction,
	const char *where);

DEFINE_AUTH_GUARD_TRANSITION_OBJECT(
	auth_guard_userns_boundary,
	user_namespace,
	auth_guard_boundary_stamp,
	auth_guard_boundary_transition,
	auth_guard_transition_from_unanchored_state)
DEFINE_AUTH_GUARD_STAMP_CLEAR(
	auth_guard_userns_boundary,
	user_namespace,
	auth_guard_boundary_stamp)
DEFINE_AUTH_GUARD_TRANSITION_OBJECT(
	auth_guard_nsproxy,
	nsproxy,
	auth_guard_stamp,
	auth_guard_transition,
	auth_guard_transition_from_expectation_state)
#ifdef CONFIG_CGROUPS
DEFINE_AUTH_GUARD_STAMP_OBJECT(
	auth_guard_cgroup_ns_root,
	cgroup_namespace,
	auth_guard_root_stamp)
DEFINE_AUTH_GUARD_STAMP_CLEAR(
	auth_guard_cgroup_ns_root,
	cgroup_namespace,
	auth_guard_root_stamp)
DEFINE_AUTH_GUARD_STAMP_OBJECT(
	auth_guard_css_set,
	css_set,
	auth_guard_stamp)
#endif

struct auth_guard_nsproxy_digest {
	u64 purpose;
	u64 nsproxy;
	u64 generation;
	u64 nonce;
	u64 mnt_ns;
	u64 uts_ns;
	u64 ipc_ns;
	u64 pid_ns_for_children;
	u64 net_ns;
	u64 time_ns;
	u64 time_ns_for_children;
	u64 cgroup_ns;
#ifdef CONFIG_CGROUPS
	u64 cgroup_ns_root_cset;
	u64 cgroup_ns_root_generation;
	u64 cgroup_ns_root_nonce;
	u64 cgroup_ns_root_seal;
#endif
	u64 syslog_ns;
	u64 tracing_ns;
} __aligned(SIPHASH_ALIGNMENT);

struct auth_guard_userns_boundary_digest {
	u64 user_ns;
	u64 generation;
	u64 nonce;
	u64 syslog_ns;
	u64 tracing_ns;
	u64 lsm_ns;
} __aligned(SIPHASH_ALIGNMENT);

#ifdef CONFIG_CGROUPS
struct auth_guard_cgroup_ns_root_digest {
	u64 cgroup_ns;
	u64 generation;
	u64 nonce;
	u64 root_cset;
} __aligned(SIPHASH_ALIGNMENT);

struct auth_guard_css_set_digest {
	u64 css_set;
	u64 generation;
	u64 nonce;
	u64 dfl_cgrp;
	u64 dom_cset;
	u64 subsys[CGROUP_SUBSYS_COUNT];
} __aligned(SIPHASH_ALIGNMENT);
#endif

struct auth_guard_task_digest {
	u64 purpose;
	u64 task;
	u64 generation;
	u64 nonce;
	u64 lifecycle;
	u64 real_cred;
	u64 cred;
	u64 cred_generation;
	u64 cred_nonce;
	u64 cred_seal;
	u64 nsproxy;
#ifdef CONFIG_CGROUPS
	u64 cgroups;
#endif
	u64 files;
	u64 tracing_ns_for_child;
	u64 syslog_ns_for_child;
	u64 syslog_ns_for_child_name;
	u64 syslog_ns_for_child_name_len;
	u64 syslog_ns_for_child_name_hash;
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	u64 lsm_ns_for_child;
	u64 lsm_ns_for_child_lsmid;
	u64 lsm_ns_for_child_ctx;
	u64 lsm_ns_for_child_ctx_len;
	u64 lsm_ns_for_child_ctx_hash;
#endif
	u64 no_new_privs;
#ifdef CONFIG_SECCOMP
	u64 seccomp_mode;
#ifdef CONFIG_SECCOMP_FILTER
	u64 seccomp_filter_count;
	u64 seccomp_filter;
#endif
#endif
} __aligned(SIPHASH_ALIGNMENT);

enum auth_guard_semantic_purpose {
	AUTH_GUARD_SEMANTIC_PUBLICATION = 0x5055424c,
	AUTH_GUARD_SEMANTIC_EXPECTATION = 0x45585045,
};

#ifdef CONFIG_AUTH_GUARD_TEST
#define AUTH_GUARD_TEST_COMMAND(where) \
	((where) + sizeof(AUTH_GUARD_TEST_CONTEXT_PREFIX) - 1)

enum auth_guard_test_task_fault {
	AUTH_GUARD_TEST_TASK_NONE,
	AUTH_GUARD_TEST_TASK_CRED,
	AUTH_GUARD_TEST_TASK_REAL_CRED,
	AUTH_GUARD_TEST_TASK_NSPROXY,
	AUTH_GUARD_TEST_TASK_FILES,
#ifdef CONFIG_SECCOMP
	AUTH_GUARD_TEST_TASK_SECCOMP_MODE,
#ifdef CONFIG_SECCOMP_FILTER
	AUTH_GUARD_TEST_TASK_SECCOMP_FILTER_COUNT,
	AUTH_GUARD_TEST_TASK_SECCOMP_FILTER,
#endif
#endif
	AUTH_GUARD_TEST_TASK_COUNT,
};

enum auth_guard_test_nsproxy_fault {
	AUTH_GUARD_TEST_NSPROXY_NONE,
	AUTH_GUARD_TEST_NSPROXY_MNT,
	AUTH_GUARD_TEST_NSPROXY_SYSLOG,
#ifdef CONFIG_TRACING_NS
	AUTH_GUARD_TEST_NSPROXY_TRACING,
#endif
	AUTH_GUARD_TEST_NSPROXY_COUNT,
};

static DEFINE_MUTEX(auth_guard_test_fault_lock);

static const struct task_struct *auth_guard_test_task_fault_target;
static const char *auth_guard_test_task_fault_where;
static enum auth_guard_test_task_fault auth_guard_test_task_fault;

static const struct task_struct *auth_guard_test_nsproxy_fault_task;
static const struct nsproxy *auth_guard_test_nsproxy_fault_target;
static const char *auth_guard_test_nsproxy_fault_where;
static enum auth_guard_test_nsproxy_fault auth_guard_test_nsproxy_fault;

static void
auth_guard_test_adjust_task_digest(const struct task_struct *task,
				   struct auth_guard_task_digest *digest,
				   const char *where)
{
	const char *fault_where;
	enum auth_guard_test_task_fault fault;

	/* Inject only into this task's exact test check, never its live fields. */
	if (likely(task != current))
		return;
	/* Pair with release publication before reading the fault selector. */
	if (likely(smp_load_acquire(&auth_guard_test_task_fault_target) != task))
		return;
	fault = READ_ONCE(auth_guard_test_task_fault);
	fault_where = READ_ONCE(auth_guard_test_task_fault_where);
	if (fault <= AUTH_GUARD_TEST_TASK_NONE ||
	    fault >= AUTH_GUARD_TEST_TASK_COUNT || !fault_where ||
	    strcmp(where, fault_where) ||
	    cmpxchg(&auth_guard_test_task_fault_target, task, NULL) != task)
		return;

	switch (fault) {
	case AUTH_GUARD_TEST_TASK_CRED:
		digest->cred ^= 1;
		break;
	case AUTH_GUARD_TEST_TASK_REAL_CRED:
		digest->real_cred ^= 1;
		break;
	case AUTH_GUARD_TEST_TASK_NSPROXY:
		digest->nsproxy ^= 1;
		break;
	case AUTH_GUARD_TEST_TASK_FILES:
		digest->files ^= 1;
		break;
#ifdef CONFIG_SECCOMP
	case AUTH_GUARD_TEST_TASK_SECCOMP_MODE:
		digest->seccomp_mode ^= 1;
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case AUTH_GUARD_TEST_TASK_SECCOMP_FILTER_COUNT:
		digest->seccomp_filter_count ^= 1;
		break;
	case AUTH_GUARD_TEST_TASK_SECCOMP_FILTER:
		digest->seccomp_filter ^= 1;
		break;
#endif
#endif
	case AUTH_GUARD_TEST_TASK_NONE:
	case AUTH_GUARD_TEST_TASK_COUNT:
		break;
	}
}

static void
auth_guard_test_adjust_nsproxy_digest(const struct nsproxy *nsproxy,
				      struct auth_guard_nsproxy_digest *digest,
				      const char *where)
{
	const char *fault_where;
	enum auth_guard_test_nsproxy_fault fault;

	/* Inject only into current's exact nsproxy check, never published state. */
	/* Pair with release publication before reading the fault selector. */
	if (likely(smp_load_acquire(&auth_guard_test_nsproxy_fault_task) !=
		   current))
		return;
	if (likely(READ_ONCE(auth_guard_test_nsproxy_fault_target) != nsproxy ||
		   READ_ONCE(current->nsproxy) != nsproxy))
		return;
	fault = READ_ONCE(auth_guard_test_nsproxy_fault);
	fault_where = READ_ONCE(auth_guard_test_nsproxy_fault_where);
	if (fault <= AUTH_GUARD_TEST_NSPROXY_NONE ||
	    fault >= AUTH_GUARD_TEST_NSPROXY_COUNT || !fault_where ||
	    strcmp(where, fault_where) ||
	    cmpxchg(&auth_guard_test_nsproxy_fault_task, current, NULL) != current)
		return;

	switch (fault) {
	case AUTH_GUARD_TEST_NSPROXY_MNT:
		digest->mnt_ns ^= 1;
		break;
	case AUTH_GUARD_TEST_NSPROXY_SYSLOG:
		digest->syslog_ns ^= 1;
		break;
#ifdef CONFIG_TRACING_NS
	case AUTH_GUARD_TEST_NSPROXY_TRACING:
		digest->tracing_ns ^= 1;
		break;
#endif
	case AUTH_GUARD_TEST_NSPROXY_NONE:
	case AUTH_GUARD_TEST_NSPROXY_COUNT:
		break;
	}
}
#endif

#if defined(CONFIG_AUTH_GUARD_TEST) && defined(CONFIG_CGROUPS)
#define AUTH_GUARD_TEST_CGROUPS_WHERE AUTH_GUARD_TEST_CONTEXT("cgroups")
#define AUTH_GUARD_TEST_CGROUP_NS_ROOT_WHERE \
	AUTH_GUARD_TEST_CONTEXT("nsproxy_cgroup_root")
#define AUTH_GUARD_TEST_CSS_SET_DFL_WHERE \
	AUTH_GUARD_TEST_CONTEXT("css_set_dfl")
#define AUTH_GUARD_TEST_CSS_SET_DOM_WHERE \
	AUTH_GUARD_TEST_CONTEXT("css_set_dom")
#define AUTH_GUARD_TEST_CSS_SET_SUBSYS_WHERE \
	AUTH_GUARD_TEST_CONTEXT("css_set_subsys")

enum auth_guard_test_css_set_fault {
	AUTH_GUARD_TEST_CSS_SET_NONE,
	AUTH_GUARD_TEST_CSS_SET_DFL,
	AUTH_GUARD_TEST_CSS_SET_DOM,
	AUTH_GUARD_TEST_CSS_SET_SUBSYS,
	AUTH_GUARD_TEST_CSS_SET_COUNT,
};

static const char * const auth_guard_test_css_set_fault_where[] = {
	[AUTH_GUARD_TEST_CSS_SET_DFL] = AUTH_GUARD_TEST_CSS_SET_DFL_WHERE,
	[AUTH_GUARD_TEST_CSS_SET_DOM] = AUTH_GUARD_TEST_CSS_SET_DOM_WHERE,
	[AUTH_GUARD_TEST_CSS_SET_SUBSYS] = AUTH_GUARD_TEST_CSS_SET_SUBSYS_WHERE,
};

static const struct task_struct *auth_guard_test_cgroups_task;
static const struct cgroup_namespace *auth_guard_test_cgroup_ns_root;
static const struct css_set *auth_guard_test_css_set;
static enum auth_guard_test_css_set_fault auth_guard_test_css_set_fault;
static int auth_guard_test_css_set_subsys_id = -1;

static struct css_set *
auth_guard_test_adjust_cgroup_ns_root(const struct cgroup_namespace *ns,
				      struct css_set *root_cset,
				      const char *where)
{
	/* Exercise the missing-endpoint boundary without invalidating live state. */
	if (unlikely(READ_ONCE(auth_guard_test_cgroup_ns_root) == ns &&
		     !strcmp(where, AUTH_GUARD_TEST_CGROUP_NS_ROOT_WHERE) &&
		     cmpxchg(&auth_guard_test_cgroup_ns_root, ns, NULL) == ns))
		return NULL;

	return root_cset;
}

static void
auth_guard_test_adjust_css_set_digest(const struct css_set *cset,
				      struct auth_guard_css_set_digest *digest,
				      const char *where)
{
	enum auth_guard_test_css_set_fault fault;
	int subsys_id = -1;

	/* Published css_set authority fields must remain valid during testing. */
	if (likely(smp_load_acquire(&auth_guard_test_css_set) != cset))
		return;
	fault = READ_ONCE(auth_guard_test_css_set_fault);
	if (fault <= AUTH_GUARD_TEST_CSS_SET_NONE ||
	    fault >= AUTH_GUARD_TEST_CSS_SET_COUNT)
		return;
	if (fault == AUTH_GUARD_TEST_CSS_SET_SUBSYS) {
		subsys_id = READ_ONCE(auth_guard_test_css_set_subsys_id);
		if (subsys_id < 0 || subsys_id >= CGROUP_SUBSYS_COUNT)
			return;
	}
	if (strcmp(where, auth_guard_test_css_set_fault_where[fault]) ||
	    cmpxchg(&auth_guard_test_css_set, cset, NULL) != cset)
		return;

	switch (fault) {
	case AUTH_GUARD_TEST_CSS_SET_DFL:
		digest->dfl_cgrp ^= 1;
		break;
	case AUTH_GUARD_TEST_CSS_SET_DOM:
		digest->dom_cset ^= 1;
		break;
	case AUTH_GUARD_TEST_CSS_SET_SUBSYS:
		digest->subsys[subsys_id] ^= 1;
		break;
	case AUTH_GUARD_TEST_CSS_SET_NONE:
	case AUTH_GUARD_TEST_CSS_SET_COUNT:
		break;
	}
}

static void
auth_guard_test_adjust_task_cgroups_digest(const struct task_struct *task,
					   struct auth_guard_task_digest *digest,
					   const char *where)
{
	/* Keep the live cgroup edge valid while testing its digest coverage. */
	if (unlikely(task == current &&
		     READ_ONCE(auth_guard_test_cgroups_task) == task &&
		     !strcmp(where, AUTH_GUARD_TEST_CGROUPS_WHERE) &&
		     cmpxchg(&auth_guard_test_cgroups_task, task, NULL) == task))
		digest->cgroups ^= 1;
}
#endif

#define AUTH_GUARD_BYTES_CHUNK		64

struct auth_guard_bytes_digest {
	u64 prior;
	u64 offset;
	u64 len;
	u64 chunk_hash;
} __aligned(SIPHASH_ALIGNMENT);

#define auth_task_guard_enabled() \
	auth_guard_layer_enabled(auth_task_guard_active)
#define auth_nsproxy_guard_enabled() \
	auth_guard_layer_enabled(auth_nsproxy_guard_active)
#define auth_userns_boundary_guard_enabled() \
	auth_guard_layer_enabled(auth_userns_boundary_guard_active)

#ifdef CONFIG_CGROUPS
#define auth_css_set_guard_enabled() \
	auth_guard_layer_enabled(auth_css_set_guard_active)
#define auth_cgroup_ns_root_guard_enabled() \
	auth_guard_layer_enabled(auth_cgroup_ns_root_guard_active)
#endif

static bool auth_guard_bytes_hash(const void *data, size_t len, size_t max_len,
				  u64 *hash)
{
	const u8 *ptr = data;
	u8 buf[AUTH_GUARD_BYTES_CHUNK];
	u64 prior = 0;
	size_t offset;

	if (!len) {
		*hash = 0;
		return true;
	}
	if (!ptr)
		return false;
	if (len > max_len)
		return false;

	for (offset = 0; offset < len; offset += sizeof(buf)) {
		size_t chunk_len = min(len - offset, sizeof(buf));
		struct auth_guard_bytes_digest digest;
		u64 chunk_hash;

		if (copy_from_kernel_nofault(buf, ptr + offset, chunk_len))
			return false;

		chunk_hash = auth_guard_seal(&task_authority_guard, buf,
					     chunk_len);
		digest.prior = prior;
		digest.offset = offset;
		digest.len = chunk_len;
		digest.chunk_hash = chunk_hash;
		prior = auth_guard_seal(&task_authority_guard, &digest,
					sizeof(digest));
	}

	*hash = prior;
	return true;
}

static bool auth_guard_snapshot_valid(struct auth_guard_domain *domain,
				      const char *where, const void *object,
				      const struct auth_guard_stamp *stamp,
				      u64 computed)
{
	if (!stamp || !stamp->seal) {
		auth_guard_fail(domain, where, "unsealed", object);
		return false;
	}
	if (!stamp->nonce) {
		auth_guard_fail(domain, where, "missing nonce", object);
		return false;
	}
	if (!auth_guard_stamp_valid(stamp)) {
		auth_guard_fail(domain, where, "missing generation", object);
		return false;
	}
	if (computed != stamp->seal) {
		auth_guard_fail(domain, where, "corrupt", object);
		return false;
	}

	return true;
}

static bool
auth_guard_userns_boundary_equal(const struct auth_guard_userns_boundary *left,
				 const struct auth_guard_userns_boundary *right)
{
	return left->syslog_ns == right->syslog_ns &&
		left->tracing_ns == right->tracing_ns &&
		left->lsm_ns == right->lsm_ns;
}

static bool
auth_guard_userns_boundary_empty(const struct auth_guard_userns_boundary *boundary)
{
	return !boundary->syslog_ns && !boundary->tracing_ns && !boundary->lsm_ns;
}

static bool
auth_guard_userns_boundary_validate_endpoint(const struct user_namespace *user_ns,
					     const struct auth_guard_userns_boundary *boundary,
					     const char *where)
{
	if (!auth_userns_boundary_guard_enabled())
		return true;
	if (!user_ns || !boundary) {
		auth_guard_fail(&userns_boundary_guard, where,
				"missing endpoint", user_ns);
		return false;
	}
	if (!boundary->syslog_ns) {
		auth_guard_fail(&userns_boundary_guard, where,
				"missing syslog namespace", user_ns);
		return false;
	}
#ifdef CONFIG_TRACING_NS
	if (!boundary->tracing_ns) {
		auth_guard_fail(&userns_boundary_guard, where,
				"missing tracing namespace", user_ns);
		return false;
	}
#endif
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (!boundary->lsm_ns) {
		auth_guard_fail(&userns_boundary_guard, where,
				"missing LSM namespace", user_ns);
		return false;
	}
#endif

	return true;
}

static u64
auth_guard_userns_boundary_hash(const struct user_namespace *user_ns,
				u64 generation, u64 nonce,
				const struct auth_guard_userns_boundary *boundary)
{
	struct auth_guard_userns_boundary_digest digest = {
		.user_ns	= auth_guard_ptr(user_ns),
		.generation	= generation,
		.nonce		= nonce,
		.syslog_ns	= auth_guard_ptr(boundary->syslog_ns),
		.tracing_ns	= auth_guard_ptr(boundary->tracing_ns),
		.lsm_ns		= auth_guard_ptr(boundary->lsm_ns),
	};

	return auth_guard_seal(&userns_boundary_guard, &digest, sizeof(digest));
}

static void auth_guard_userns_boundary_seal(struct user_namespace *user_ns)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_transition transition =
		auth_guard_userns_boundary_transition(user_ns);
	struct auth_guard_stamp stamp;

	stamp = auth_guard_stamp_fresh(&userns_boundary_guard);
	auth_guard_userns_boundary_read(user_ns, &boundary);
	auth_guard_transition_initialize(&transition);
	stamp.seal = auth_guard_userns_boundary_hash(
		user_ns, stamp.generation, stamp.nonce, &boundary);
	/* Publish the complete boundary tuple before readers acquire the seal. */
	auth_guard_userns_boundary_stamp_publish(user_ns, &stamp);
	auth_guard_transition_clear(&transition);
}

static bool
auth_guard_userns_boundary_is_sealed(const struct user_namespace *user_ns)
{
	struct auth_guard_stamp stamp;

	if (!user_ns)
		return false;

	/* Pair with release publication of the complete boundary tuple. */
	stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	return auth_guard_stamp_valid(&stamp);
}

bool auth_guard_userns_boundary_init_where(struct user_namespace *user_ns,
				     const char *where)
{
	struct auth_guard_userns_boundary boundary;

	if (!auth_userns_boundary_guard_enabled())
		return true;
	if (!user_ns) {
		auth_guard_fail(&userns_boundary_guard, where, "missing", user_ns);
		return false;
	}

	auth_guard_userns_boundary_read(user_ns, &boundary);
	if (!auth_guard_userns_boundary_validate_endpoint(user_ns, &boundary,
							  where))
		return false;
	auth_guard_userns_boundary_seal(user_ns);
	return true;
}

bool auth_guard_userns_boundary_begin_transition_where(struct user_namespace *user_ns,
						 const struct auth_guard_userns_boundary *expected,
						 const char *where)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;
	u64 computed;

	if (!auth_userns_boundary_guard_enabled())
		return true;
	if (!user_ns || !expected) {
		auth_guard_fail(&userns_boundary_guard, where,
					"missing transition", user_ns);
		return false;
	}
	transition = auth_guard_userns_boundary_transition(user_ns);
	if (auth_guard_transition_reserve(&userns_boundary_guard, where,
					  &transition) != AUTH_GUARD_CHECK_VALID)
		return false;

	/* Pair with release publication of the authenticated old tuple. */
	stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	auth_guard_userns_boundary_read(user_ns, &boundary);
	computed = auth_guard_userns_boundary_hash(
		user_ns, stamp.generation, stamp.nonce, &boundary);
	if (!auth_guard_snapshot_valid(&userns_boundary_guard, where, user_ns,
					       &stamp, computed) ||
	    !auth_guard_userns_boundary_validate_endpoint(user_ns, &boundary,
							    where))
		goto quarantine;
	if (!auth_guard_userns_boundary_equal(&boundary, expected)) {
		auth_guard_fail(&userns_boundary_guard, where,
				"unexpected old boundary", user_ns);
		goto quarantine;
	}

	return auth_guard_transition_publish(
		&userns_boundary_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp, 0, 0);

quarantine:
	auth_guard_transition_quarantine(&transition);
	return false;
}

bool auth_guard_userns_boundary_finish_transition_where(struct user_namespace *user_ns,
						  const struct auth_guard_userns_boundary *expected,
						  const char *where)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_transition transition;
	struct auth_guard_stamp new_stamp;
	struct auth_guard_stamp old_stamp;

	if (!auth_userns_boundary_guard_enabled())
		return true;
	if (!expected || !auth_guard_userns_boundary_is_sealed(user_ns)) {
		auth_guard_fail(&userns_boundary_guard, where,
					"unsealed transition", user_ns);
		return false;
	}

	transition = auth_guard_userns_boundary_transition(user_ns);
	old_stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	if (!auth_guard_transition_can_finish(
		    &userns_boundary_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &old_stamp))
		return false;

	auth_guard_userns_boundary_read(user_ns, &boundary);
	if (!auth_guard_userns_boundary_equal(&boundary, expected)) {
		auth_guard_fail(&userns_boundary_guard, where,
				"unexpected new boundary", user_ns);
		goto quarantine;
	}
	if (!auth_guard_userns_boundary_validate_endpoint(user_ns, &boundary,
							  where))
		goto quarantine;

	new_stamp = auth_guard_stamp_fresh(&userns_boundary_guard);
	new_stamp.seal = auth_guard_userns_boundary_hash(
		user_ns, new_stamp.generation, new_stamp.nonce, &boundary);
	/* Publish the complete replacement tuple before readers acquire it. */
	auth_guard_userns_boundary_stamp_publish(user_ns, &new_stamp);
	return auth_guard_transition_close(
		&userns_boundary_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_NONE, &old_stamp);

quarantine:
	auth_guard_transition_quarantine(&transition);
	return false;
}

bool auth_guard_userns_boundary_abort_transition_where(struct user_namespace *user_ns,
						 const struct auth_guard_userns_boundary *expected,
						 const char *where)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;

	if (!auth_userns_boundary_guard_enabled())
		return true;
	if (!expected || !auth_guard_userns_boundary_is_sealed(user_ns)) {
		auth_guard_fail(&userns_boundary_guard, where, "unsealed abort",
				user_ns);
		return false;
	}

	/* Pair with release publication of the authenticated old tuple. */
	transition = auth_guard_userns_boundary_transition(user_ns);
	stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	if (!auth_guard_transition_can_abort(
		    &userns_boundary_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp))
		goto quarantine;

	auth_guard_userns_boundary_read(user_ns, &boundary);
	computed = auth_guard_userns_boundary_hash(
		user_ns, stamp.generation, stamp.nonce, &boundary);
	if (!auth_guard_userns_boundary_equal(&boundary, expected)) {
		auth_guard_fail(&userns_boundary_guard, where,
				"unexpected restored boundary", user_ns);
		goto quarantine;
	}
	if (!auth_guard_snapshot_valid(&userns_boundary_guard, where, user_ns,
					       &stamp, computed) ||
	    !auth_guard_userns_boundary_validate_endpoint(user_ns, &boundary,
								    where))
		goto quarantine;
	/* Reacquire the old seal before accepting the restored tuple. */
	current_stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp)) {
		auth_guard_fail(&userns_boundary_guard, where,
					"changed abort state", user_ns);
		goto quarantine;
	}
	if (!auth_guard_transition_abort_close(
		    &userns_boundary_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp))
		goto quarantine;
	return true;

quarantine:
	auth_guard_transition_quarantine(&transition);
	return false;
}

static bool auth_guard_userns_boundary_check_reserved(
	const struct user_namespace *user_ns, const char *where,
	const struct auth_guard_transition *transition)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;

	/* Pair with release publication of the complete boundary tuple. */
	stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	auth_guard_userns_boundary_read(user_ns, &boundary);
	computed = auth_guard_userns_boundary_hash(
		user_ns, stamp.generation, stamp.nonce, &boundary);
	current_stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	if (!auth_guard_transition_reader_stable(
		    &userns_boundary_guard, where, transition, &stamp,
		    &current_stamp))
		return false;
	if (!auth_guard_snapshot_valid(&userns_boundary_guard, where, user_ns,
					       &stamp, computed) ||
	    !auth_guard_userns_boundary_validate_endpoint(user_ns, &boundary,
							    where))
		return false;
	current_stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	return auth_guard_transition_reader_stable(
		&userns_boundary_guard, where, transition, &stamp, &current_stamp);
}

DEFINE_AUTH_GUARD_OBJECT_SNAPSHOT_API(
	auth_guard_userns_boundary,
	user_namespace,
	auth_userns_boundary_guard_enabled,
	userns_boundary_guard)

DEFINE_USERNS_BOUNDARY_GETTER(
	get_syslog_ns_from_userns_checked,
	syslog_namespace,
	syslog_ns,
	get_syslog_ns,
	put_syslog_ns,
	&init_syslog_ns)
EXPORT_SYMBOL_GPL(get_syslog_ns_from_userns_checked_where);

bool auth_guard_userns_boundary_destroy_begin_where(struct user_namespace *user_ns,
					      const struct auth_guard_userns_boundary *expected,
					      const char *where)
{
	return auth_guard_userns_boundary_begin_transition_where(user_ns, expected,
							    where);
}

bool auth_guard_userns_boundary_destroy_complete_where(struct user_namespace *user_ns,
							 bool old_valid, bool exact,
							 const char *where)
{
	struct auth_guard_userns_boundary boundary;
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;

	if (!auth_userns_boundary_guard_enabled())
		return old_valid && exact;
	if (!old_valid)
		return false;
	if (!auth_guard_userns_boundary_is_sealed(user_ns)) {
		auth_guard_fail(&userns_boundary_guard, where,
				"unsealed destroy", user_ns);
		return false;
	}

	transition = auth_guard_userns_boundary_transition(user_ns);
	stamp = auth_guard_userns_boundary_stamp_load(user_ns);
	if (!auth_guard_transition_can_finish(
		    &userns_boundary_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp))
		return false;

	auth_guard_userns_boundary_read(user_ns, &boundary);
	if (!exact || !auth_guard_userns_boundary_empty(&boundary)) {
		auth_guard_fail(&userns_boundary_guard, where,
				"inexact destroy detach", user_ns);
		auth_guard_transition_quarantine(&transition);
		return false;
	}

	/* Release the final cleared state before dropping transition exclusion. */
	auth_guard_userns_boundary_stamp_clear(user_ns);
	return auth_guard_transition_close(
		&userns_boundary_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp);
}

#ifdef CONFIG_CGROUPS
static u64 auth_guard_cgroup_ns_root_hash(
	const struct cgroup_namespace *ns, const struct css_set *root_cset,
	u64 generation, u64 nonce);
#endif

static void auth_guard_nsproxy_state_read(
	const struct nsproxy *nsproxy, struct auth_guard_nsproxy_state *state)
{
	*state = (struct auth_guard_nsproxy_state) {
		.mnt_ns = READ_ONCE(nsproxy->mnt_ns),
		.uts_ns = READ_ONCE(nsproxy->uts_ns),
		.ipc_ns = READ_ONCE(nsproxy->ipc_ns),
		.pid_ns_for_children = READ_ONCE(nsproxy->pid_ns_for_children),
		.net_ns = READ_ONCE(nsproxy->net_ns),
		.time_ns = READ_ONCE(nsproxy->time_ns),
		.time_ns_for_children =
			READ_ONCE(nsproxy->time_ns_for_children),
		.cgroup_ns = READ_ONCE(nsproxy->cgroup_ns),
		.syslog_ns = READ_ONCE(nsproxy->syslog_ns),
		.tracing_ns = READ_ONCE(nsproxy->tracing_ns),
	};
#ifdef CONFIG_CGROUPS
	if (state->cgroup_ns) {
		state->cgroup_ns_root_cset =
			READ_ONCE(state->cgroup_ns->root_cset);
		state->cgroup_ns_root_stamp =
			auth_guard_cgroup_ns_root_stamp_load(state->cgroup_ns);
	}
#endif
}

static u64 auth_guard_nsproxy_state_hash(
	const struct nsproxy *nsproxy,
	const struct auth_guard_nsproxy_state *state,
	u64 generation, u64 nonce, enum auth_guard_semantic_purpose purpose,
	const char *where, bool inject_fault)
{
	struct auth_guard_nsproxy_digest digest = {
		.purpose		= purpose,
		.nsproxy		= auth_guard_ptr(nsproxy),
		.generation		= generation,
		.nonce			= nonce,
		.mnt_ns			= auth_guard_ptr(state->mnt_ns),
		.uts_ns			= auth_guard_ptr(state->uts_ns),
		.ipc_ns			= auth_guard_ptr(state->ipc_ns),
		.pid_ns_for_children	=
			auth_guard_ptr(state->pid_ns_for_children),
		.net_ns			= auth_guard_ptr(state->net_ns),
		.time_ns		= auth_guard_ptr(state->time_ns),
		.time_ns_for_children	=
			auth_guard_ptr(state->time_ns_for_children),
		.cgroup_ns		= auth_guard_ptr(state->cgroup_ns),
#ifdef CONFIG_CGROUPS
		.cgroup_ns_root_cset	=
			auth_guard_ptr(state->cgroup_ns_root_cset),
		.cgroup_ns_root_generation =
			purpose == AUTH_GUARD_SEMANTIC_EXPECTATION ?
			state->cgroup_ns_root_stamp.generation : 0,
		.cgroup_ns_root_nonce =
			purpose == AUTH_GUARD_SEMANTIC_EXPECTATION ?
			state->cgroup_ns_root_stamp.nonce : 0,
		.cgroup_ns_root_seal =
			purpose == AUTH_GUARD_SEMANTIC_EXPECTATION ?
			state->cgroup_ns_root_stamp.seal : 0,
#endif
		.syslog_ns		= auth_guard_ptr(state->syslog_ns),
		.tracing_ns		= auth_guard_ptr(state->tracing_ns),
	};

#ifdef CONFIG_AUTH_GUARD_TEST
	if (inject_fault)
		auth_guard_test_adjust_nsproxy_digest(nsproxy, &digest, where);
#endif

	return auth_guard_seal(&nsproxy_authority_guard, &digest,
			       sizeof(digest));
}

static u64 auth_guard_nsproxy_hash(const struct nsproxy *nsproxy,
				   u64 generation, u64 nonce,
				   const char *where)
{
	struct auth_guard_nsproxy_state state;

	auth_guard_nsproxy_state_read(nsproxy, &state);
	return auth_guard_nsproxy_state_hash(
		nsproxy, &state, generation, nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, true);
}

static void auth_guard_nsproxy_seal(struct nsproxy *nsproxy, const char *where)
{
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;

	if (!auth_nsproxy_guard_enabled())
		return;
	if (!nsproxy) {
		auth_guard_fail(&nsproxy_authority_guard, where, "missing", nsproxy);
		return;
	}

	transition = auth_guard_nsproxy_transition(nsproxy);
	stamp = auth_guard_stamp_fresh(&nsproxy_authority_guard);
	auth_guard_transition_initialize(&transition);
	stamp.seal = auth_guard_nsproxy_hash(
		nsproxy, stamp.generation, stamp.nonce, where);
	auth_guard_nsproxy_stamp_publish(nsproxy, &stamp);
	auth_guard_transition_clear(&transition);
}

static bool auth_guard_nsproxy_is_sealed(const struct nsproxy *nsproxy)
{
	struct auth_guard_stamp stamp;

	if (!nsproxy)
		return false;
	stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	return auth_guard_stamp_valid(&stamp);
}

static bool auth_guard_nsproxy_state_validate(
	const struct nsproxy *nsproxy,
	const struct auth_guard_nsproxy_state *state, const char *where)
{
	if (!auth_nsproxy_guard_enabled())
		return true;
	if (!nsproxy || !state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"missing endpoint", nsproxy);
		return false;
	}

#ifdef CONFIG_CGROUPS
	if (state->cgroup_ns &&
	    !auth_guard_cgroup_ns_root_check_where(state->cgroup_ns, where))
		return false;
#endif

	return true;
}

static bool auth_guard_nsproxy_validate_endpoint(const struct nsproxy *nsproxy,
						 const char *where)
{
	struct auth_guard_nsproxy_state state;

	if (!nsproxy)
		return auth_guard_nsproxy_state_validate(nsproxy, NULL, where);
	auth_guard_nsproxy_state_read(nsproxy, &state);
	return auth_guard_nsproxy_state_validate(nsproxy, &state, where);
}

bool auth_guard_nsproxy_init_where(struct nsproxy *nsproxy, const char *where)
{
	if (!auth_guard_nsproxy_validate_endpoint(nsproxy, where))
		return false;

	auth_guard_nsproxy_seal(nsproxy, where);
	return true;
}

static bool auth_guard_nsproxy_transition_begin_where(
	struct nsproxy *nsproxy, struct auth_guard_nsproxy_transition *transaction,
	const char *where)
{
	struct auth_guard_nsproxy_state current_state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 expected_state;
	u64 computed;

	if (!transaction)
		return false;
	*transaction = (struct auth_guard_nsproxy_transition) {
		.nsproxy = nsproxy,
	};
	if (!nsproxy) {
		auth_guard_fail(&nsproxy_authority_guard, where, "missing", nsproxy);
		return false;
	}
	if (!auth_nsproxy_guard_enabled()) {
		auth_guard_nsproxy_state_read(nsproxy, &transaction->old);
		transaction->expected = transaction->old;
		return true;
	}
	transition = auth_guard_nsproxy_transition(nsproxy);
	if (auth_guard_transition_reserve(
		    &nsproxy_authority_guard, where, &transition) !=
	    AUTH_GUARD_CHECK_VALID)
		return false;

	/* Acquire the release-published seal before protected metadata. */
	stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	auth_guard_nsproxy_state_read(nsproxy, &transaction->old);
	computed = auth_guard_nsproxy_state_hash(
		nsproxy, &transaction->old, stamp.generation, stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, true);
	if (!auth_guard_snapshot_valid(&nsproxy_authority_guard, where, nsproxy,
				       &stamp, computed) ||
	    !auth_guard_nsproxy_state_validate(nsproxy, &transaction->old, where)) {
		auth_guard_transition_quarantine(&transition);
		return false;
	}
	expected_state = auth_guard_nsproxy_state_hash(
		nsproxy, &transaction->old, 0, 0,
		AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	auth_guard_nsproxy_state_read(nsproxy, &current_state);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp) ||
	    auth_guard_nsproxy_state_hash(
		    nsproxy, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"changed transition source", nsproxy);
		auth_guard_transition_quarantine(&transition);
		return false;
	}
	transaction->expected = transaction->old;
	transaction->old_stamp = stamp;
	transaction->active = true;

	return auth_guard_transition_publish(
		&nsproxy_authority_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp, expected_state,
		expected_state);
}

static bool auth_guard_nsproxy_finish_transition_where(struct nsproxy *nsproxy,
						 const char *where)
{
	struct auth_guard_nsproxy_state current_state;
	struct auth_guard_nsproxy_state state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp new_stamp;
	struct auth_guard_stamp old_stamp;
	u64 expected_state;
	u64 state_hash;

	if (!auth_nsproxy_guard_enabled())
		return true;
	if (!auth_guard_nsproxy_is_sealed(nsproxy)) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"unsealed transition", nsproxy);
		return false;
	}

	transition = auth_guard_nsproxy_transition(nsproxy);
	old_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	if (!__auth_guard_transition_verify(
		    &nsproxy_authority_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &old_stamp, false,
		    NULL, &expected_state)) {
		auth_guard_transition_quarantine(&transition);
		return false;
	}

	auth_guard_nsproxy_state_read(nsproxy, &state);
	state_hash = auth_guard_nsproxy_state_hash(
		nsproxy, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where,
		false);
	if (state_hash != expected_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"unexpected transition result", nsproxy);
		goto endpoint_failed;
	}
	if (!auth_guard_nsproxy_state_validate(nsproxy, &state, where))
		goto endpoint_failed;
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	auth_guard_nsproxy_state_read(nsproxy, &current_state);
	if (!auth_guard_stamp_equal(&current_stamp, &old_stamp) ||
	    auth_guard_nsproxy_state_hash(
		    nsproxy, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"changed transition result", nsproxy);
		goto endpoint_failed;
	}

	new_stamp = auth_guard_stamp_fresh(&nsproxy_authority_guard);
	new_stamp.seal = auth_guard_nsproxy_state_hash(
		nsproxy, &state, new_stamp.generation, new_stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, false);
	auth_guard_nsproxy_stamp_publish(nsproxy, &new_stamp);
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	auth_guard_nsproxy_state_read(nsproxy, &current_state);
	if (!auth_guard_stamp_equal(&current_stamp, &new_stamp) ||
	    auth_guard_nsproxy_state_hash(
		    nsproxy, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"changed published transition", nsproxy);
		goto endpoint_failed;
	}
	if (auth_guard_transition_close(
		    &nsproxy_authority_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &old_stamp))
		return true;

endpoint_failed:
	/*
	 * Quarantine the transition marker.  The nsproxy now names a rejected
	 * endpoint, so log mode must neither wait on an apparently active writer
	 * nor make the mutated tuple look sealed.
	 */
	auth_guard_transition_quarantine(&transition);
	return false;
}

static bool auth_guard_nsproxy_abort_transition_checked(
	struct nsproxy *nsproxy, const char *where)
{
	struct auth_guard_nsproxy_state current_state;
	struct auth_guard_nsproxy_state state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;
	u64 restore_state;
	u64 state_hash;

	if (!auth_nsproxy_guard_enabled())
		return true;
	if (!auth_guard_nsproxy_is_sealed(nsproxy)) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"unsealed abort", nsproxy);
		return false;
	}

	/* Authenticate the retained marker over the pre-transition publication. */
	transition = auth_guard_nsproxy_transition(nsproxy);
	stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	if (!__auth_guard_transition_verify(
		    &nsproxy_authority_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp, true,
		    &restore_state, NULL))
		goto quarantine;

	/* Clear exclusion only after the caller restored the exact old graph. */
	auth_guard_nsproxy_state_read(nsproxy, &state);
	state_hash = auth_guard_nsproxy_state_hash(
		nsproxy, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where,
		false);
	if (state_hash != restore_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"unexpected abort state", nsproxy);
		goto quarantine;
	}
	computed = auth_guard_nsproxy_state_hash(
		nsproxy, &state, stamp.generation, stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, false);
	if (!auth_guard_snapshot_valid(&nsproxy_authority_guard, where, nsproxy,
				       &stamp, computed) ||
	    !auth_guard_nsproxy_state_validate(nsproxy, &state, where))
		goto quarantine;
	/* Reacquire the publication before accepting restored abort metadata. */
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	auth_guard_nsproxy_state_read(nsproxy, &current_state);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp) ||
	    auth_guard_nsproxy_state_hash(
		    nsproxy, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    restore_state) {
		auth_guard_fail(&nsproxy_authority_guard, where,
				"changed abort state", nsproxy);
		goto quarantine;
	}
	if (!auth_guard_transition_abort_close(
		    &nsproxy_authority_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &stamp))
		goto quarantine;
	return true;

quarantine:
	auth_guard_transition_quarantine(&transition);
	return false;
}

#define AUTH_GUARD_NSPROXY_CHANGE(_change) BIT(AUTH_GUARD_NSPROXY_##_change)

static bool auth_guard_nsproxy_transition_expect_state(
	struct auth_guard_nsproxy_transition *transaction,
	const struct auth_guard_nsproxy_state *current_state,
	const struct auth_guard_nsproxy_state *expected_state,
	unsigned long changes, bool validate_endpoint, const char *where)
{
	struct auth_guard_nsproxy_state stable_state;
	struct auth_guard_transition marker;
	u64 current_hash;
	u64 expected_hash;

	if (!transaction || !transaction->nsproxy || !current_state ||
	    !expected_state || (transaction->declared & changes) ||
	    (transaction->mutated & changes))
		goto invalid;
	if (validate_endpoint &&
	    !auth_guard_nsproxy_state_validate(transaction->nsproxy,
					       expected_state, where))
		goto invalid;
	transaction->expected = *expected_state;
	transaction->declared |= changes;
	if (!auth_nsproxy_guard_enabled())
		return true;
	if (!transaction->active)
		goto invalid;

	marker = auth_guard_nsproxy_transition(transaction->nsproxy);
	current_hash = auth_guard_nsproxy_state_hash(
		transaction->nsproxy, current_state, 0, 0,
		AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	expected_hash = auth_guard_nsproxy_state_hash(
		transaction->nsproxy, expected_state, 0, 0,
		AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (!auth_guard_transition_update_expected(
		    &nsproxy_authority_guard, where, &marker,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &transaction->old_stamp,
		    current_hash, expected_hash))
		return false;

	auth_guard_nsproxy_state_read(transaction->nsproxy, &stable_state);
	if (auth_guard_nsproxy_state_hash(
		    transaction->nsproxy, &stable_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) == current_hash)
		return true;
	auth_guard_fail(&nsproxy_authority_guard, where,
			"changed while declaring transition", transaction->nsproxy);
	auth_guard_transition_quarantine(&marker);
	return false;

invalid:
	if (transaction && transaction->nsproxy) {
		marker = auth_guard_nsproxy_transition(transaction->nsproxy);
		auth_guard_fail(&nsproxy_authority_guard, where,
				"invalid transition declaration",
				transaction->nsproxy);
		if (transaction->active)
			auth_guard_transition_quarantine(&marker);
	}
	return false;
}

static bool auth_guard_nsproxy_transition_state_matches(
	struct auth_guard_nsproxy_transition *transaction, const char *where)
{
	struct auth_guard_nsproxy_state state;
	struct auth_guard_transition marker;
	u64 expected_state;
	u64 state_hash;

	if (!auth_nsproxy_guard_enabled())
		return true;
	if (!transaction || !transaction->active || !transaction->nsproxy)
		return false;
	marker = auth_guard_nsproxy_transition(transaction->nsproxy);
	if (!__auth_guard_transition_verify(
		    &nsproxy_authority_guard, where, &marker,
		    AUTH_GUARD_TRANSITION_ANCHOR_NONE, &transaction->old_stamp, false,
		    NULL, &expected_state))
		goto quarantine;
	auth_guard_nsproxy_state_read(transaction->nsproxy, &state);
	state_hash = auth_guard_nsproxy_state_hash(
		transaction->nsproxy, &state, 0, 0,
		AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (state_hash == expected_state)
		return true;
	auth_guard_fail(&nsproxy_authority_guard, where,
			"unexpected mutated transition", transaction->nsproxy);

quarantine:
	auth_guard_transition_quarantine(&marker);
	return false;
}

static enum auth_guard_mutation_result auth_guard_nsproxy_mutation_fail(
	struct auth_guard_nsproxy_transition *transaction, const char *where,
	const char *what, enum auth_guard_mutation_result result)
{
	struct auth_guard_transition marker;

	if (!transaction || !transaction->nsproxy)
		return AUTH_GUARD_MUTATION_REJECTED;
	if (transaction->active) {
		marker = auth_guard_nsproxy_transition(transaction->nsproxy);
		auth_guard_fail(&nsproxy_authority_guard, where, what,
				transaction->nsproxy);
		auth_guard_transition_quarantine(&marker);
	}
	return result;
}

#define AUTH_GUARD_NSPROXY_NO_AUGMENT(_state, _expected) \
	do { \
		(void)(_state); \
		(void)(_expected); \
	} while (0)

static void auth_guard_nsproxy_augment_cgroup_ns(
	struct auth_guard_nsproxy_state *state,
	struct cgroup_namespace *expected)
{
#ifdef CONFIG_CGROUPS
	state->cgroup_ns_root_cset = expected ? READ_ONCE(expected->root_cset) : NULL;
	state->cgroup_ns_root_stamp = expected ?
		auth_guard_cgroup_ns_root_stamp_load(expected) :
		(struct auth_guard_stamp) {};
#else
	state->cgroup_ns_root_cset = NULL;
	state->cgroup_ns_root_stamp = (struct auth_guard_stamp) {};
#endif
}

#define DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(_name, _change, _augment) \
static bool auth_guard_nsproxy_transition_expect_##_name##_where( \
	struct auth_guard_nsproxy_transition *transaction, \
	typeof_member(struct nsproxy, _name) expected, \
	const char *where) \
{ \
	struct auth_guard_nsproxy_state current_state; \
	struct auth_guard_nsproxy_state expected_state; \
	\
	if (!transaction || !transaction->nsproxy) \
		return false; \
	auth_guard_nsproxy_state_read(transaction->nsproxy, &current_state); \
	expected_state = current_state; \
	expected_state._name = expected; \
	_augment(&expected_state, expected); \
	if (!auth_guard_nsproxy_transition_expect_state( \
		    transaction, &current_state, &expected_state, \
		    AUTH_GUARD_NSPROXY_CHANGE(_change), true, where)) \
		return false; \
	transaction->old._name = current_state._name; \
	return true; \
} \
static enum auth_guard_mutation_result \
auth_guard_nsproxy_transition_mutate_##_name##_where( \
	struct auth_guard_nsproxy_transition *transaction, const char *where) \
{ \
	unsigned long change = AUTH_GUARD_NSPROXY_CHANGE(_change); \
	bool published; \
	\
	if (!transaction || !transaction->nsproxy || \
	    !(transaction->declared & change) || (transaction->mutated & change)) \
		return AUTH_GUARD_MUTATION_REJECTED; \
	if (cmpxchg(&transaction->nsproxy->_name, transaction->old._name, \
		    transaction->expected._name) != transaction->old._name) \
		return auth_guard_nsproxy_mutation_fail( \
			transaction, where, "inexact transition mutation", \
			AUTH_GUARD_MUTATION_REJECTED); \
	published = transaction->old._name != transaction->expected._name; \
	transaction->mutated |= change; \
	if (!auth_guard_nsproxy_transition_state_matches(transaction, where)) \
		return published ? AUTH_GUARD_MUTATION_QUARANTINED : \
			AUTH_GUARD_MUTATION_REJECTED; \
	return AUTH_GUARD_MUTATION_APPLIED; \
}

DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	mnt_ns, MNT, AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	uts_ns, UTS, AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	ipc_ns, IPC, AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	pid_ns_for_children, PID_FOR_CHILDREN,
	AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	net_ns, NET, AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	cgroup_ns, CGROUP, auth_guard_nsproxy_augment_cgroup_ns)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	syslog_ns, SYSLOG, AUTH_GUARD_NSPROXY_NO_AUGMENT)
DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API(
	tracing_ns, TRACING, AUTH_GUARD_NSPROXY_NO_AUGMENT)

#undef DEFINE_AUTH_GUARD_NSPROXY_MEMBER_API

#undef AUTH_GUARD_NSPROXY_NO_AUGMENT

static bool auth_guard_nsproxy_transition_expect_time_where(
	struct auth_guard_nsproxy_transition *transaction,
	struct time_namespace *time_ns,
	struct time_namespace *time_ns_for_children, const char *where)
{
	struct auth_guard_nsproxy_state current_state;
	struct auth_guard_nsproxy_state expected_state;
	unsigned long changes = BIT(AUTH_GUARD_NSPROXY_TIME) |
		BIT(AUTH_GUARD_NSPROXY_TIME_FOR_CHILDREN);

	if (!transaction || !transaction->nsproxy)
		return false;
	auth_guard_nsproxy_state_read(transaction->nsproxy, &current_state);
	expected_state = current_state;
	expected_state.time_ns = time_ns;
	expected_state.time_ns_for_children = time_ns_for_children;
	if (!auth_guard_nsproxy_transition_expect_state(
		    transaction, &current_state, &expected_state, changes, true,
		    where))
		return false;
	transaction->old.time_ns = current_state.time_ns;
	transaction->old.time_ns_for_children =
		current_state.time_ns_for_children;
	return true;
}

static enum auth_guard_mutation_result
auth_guard_nsproxy_transition_mutate_time_where(
	struct auth_guard_nsproxy_transition *transaction, const char *where)
{
	unsigned long changes = BIT(AUTH_GUARD_NSPROXY_TIME) |
		BIT(AUTH_GUARD_NSPROXY_TIME_FOR_CHILDREN);
	bool published = false;

	if (!transaction || !transaction->nsproxy ||
	    (transaction->declared & changes) != changes ||
	    (transaction->mutated & changes))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (cmpxchg(&transaction->nsproxy->time_ns, transaction->old.time_ns,
		    transaction->expected.time_ns) != transaction->old.time_ns)
		goto failed;
	published |= transaction->old.time_ns != transaction->expected.time_ns;
	if (cmpxchg(&transaction->nsproxy->time_ns_for_children,
		    transaction->old.time_ns_for_children,
		    transaction->expected.time_ns_for_children) !=
	    transaction->old.time_ns_for_children) {
		if (cmpxchg(&transaction->nsproxy->time_ns,
			    transaction->expected.time_ns,
			    transaction->old.time_ns) !=
		    transaction->expected.time_ns)
			goto failed;
		goto failed;
	}
	published |= transaction->old.time_ns_for_children !=
		     transaction->expected.time_ns_for_children;
	transaction->mutated |= changes;
	if (!auth_guard_nsproxy_transition_state_matches(transaction, where))
		return published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED;
	return AUTH_GUARD_MUTATION_APPLIED;

failed:
	return auth_guard_nsproxy_mutation_fail(
		transaction, where, "inexact time transition mutation",
		published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED);
}

static bool auth_guard_nsproxy_transition_expect_cgroup_root_where(
	struct auth_guard_nsproxy_transition *transaction,
	struct css_set *root_cset, const char *where)
{
#ifdef CONFIG_CGROUPS
	struct auth_guard_nsproxy_state current_state;
	struct auth_guard_nsproxy_state expected_state;

	if (!transaction || !transaction->nsproxy || !root_cset ||
	    !auth_guard_css_set_check_where(root_cset, where))
		return false;
	auth_guard_nsproxy_state_read(transaction->nsproxy, &current_state);
	if (!current_state.cgroup_ns || !current_state.cgroup_ns_root_cset)
		return false;
	expected_state = current_state;
	expected_state.cgroup_ns_root_cset = root_cset;
	expected_state.cgroup_ns_root_stamp =
		auth_guard_stamp_fresh(&cgroup_ns_root_guard);
	expected_state.cgroup_ns_root_stamp.seal =
		auth_guard_cgroup_ns_root_hash(
			current_state.cgroup_ns, root_cset,
			expected_state.cgroup_ns_root_stamp.generation,
			expected_state.cgroup_ns_root_stamp.nonce);
	if (!auth_guard_nsproxy_transition_expect_state(
		    transaction, &current_state, &expected_state,
		    BIT(AUTH_GUARD_NSPROXY_CGROUP_ROOT), false, where))
		return false;
	transaction->old.cgroup_ns = current_state.cgroup_ns;
	transaction->old.cgroup_ns_root_cset =
		current_state.cgroup_ns_root_cset;
	return true;
#else
	return false;
#endif
}

static enum auth_guard_mutation_result
auth_guard_nsproxy_transition_mutate_cgroup_root_where(
	struct auth_guard_nsproxy_transition *transaction, const char *where)
{
#ifdef CONFIG_CGROUPS
	struct auth_guard_stamp current_stamp;
	unsigned long change = BIT(AUTH_GUARD_NSPROXY_CGROUP_ROOT);

	if (!transaction || !transaction->nsproxy ||
	    !transaction->old.cgroup_ns ||
	    !(transaction->declared & change) || (transaction->mutated & change))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (READ_ONCE(transaction->nsproxy->cgroup_ns) !=
	    transaction->old.cgroup_ns)
		return auth_guard_nsproxy_mutation_fail(
			transaction, where, "changed cgroup-root carrier",
			AUTH_GUARD_MUTATION_REJECTED);
	current_stamp = auth_guard_cgroup_ns_root_stamp_load(
		transaction->old.cgroup_ns);
	if (!auth_guard_stamp_equal(&current_stamp,
				    &transaction->old.cgroup_ns_root_stamp))
		return auth_guard_nsproxy_mutation_fail(
			transaction, where, "changed cgroup-root source",
			AUTH_GUARD_MUTATION_REJECTED);
	if (cmpxchg(&transaction->old.cgroup_ns->root_cset,
		    transaction->old.cgroup_ns_root_cset,
		    transaction->expected.cgroup_ns_root_cset) !=
	    transaction->old.cgroup_ns_root_cset)
		return auth_guard_nsproxy_mutation_fail(
			transaction, where, "inexact cgroup-root mutation",
			AUTH_GUARD_MUTATION_REJECTED);
	transaction->mutated |= change;
	auth_guard_cgroup_ns_root_stamp_publish(
		transaction->old.cgroup_ns,
		&transaction->expected.cgroup_ns_root_stamp);
	current_stamp = auth_guard_cgroup_ns_root_stamp_load(
		transaction->old.cgroup_ns);
	if (READ_ONCE(transaction->old.cgroup_ns->root_cset) !=
		    transaction->expected.cgroup_ns_root_cset ||
	    !auth_guard_stamp_equal(
		    &current_stamp, &transaction->expected.cgroup_ns_root_stamp))
		goto published_inexact;
	if (!auth_guard_nsproxy_transition_state_matches(transaction, where))
		return AUTH_GUARD_MUTATION_QUARANTINED;
	return AUTH_GUARD_MUTATION_APPLIED;

published_inexact:
	return auth_guard_nsproxy_mutation_fail(
		transaction, where, "changed cgroup-root publication",
		AUTH_GUARD_MUTATION_QUARANTINED);
#else
	return AUTH_GUARD_MUTATION_REJECTED;
#endif
}

static bool auth_guard_nsproxy_transition_finish_where(
	struct auth_guard_nsproxy_transition *transaction, const char *where)
{
	if (!transaction || !transaction->nsproxy ||
	    transaction->declared != transaction->mutated)
		return false;
	if (!auth_guard_nsproxy_finish_transition_where(transaction->nsproxy,
							where))
		return false;
	transaction->active = false;
	return true;
}

static bool auth_guard_nsproxy_transition_abort_where(
	struct auth_guard_nsproxy_transition *transaction, const char *where)
{
	if (!transaction || !transaction->nsproxy || transaction->mutated)
		return false;
	if (!auth_guard_nsproxy_abort_transition_checked(transaction->nsproxy,
							where))
		return false;
	transaction->active = false;
	return true;
}

#define AUTH_GUARD_NSPROXY_REPLACE(                                    \
		_nsproxy, _transaction, _expect, _mutate, _where)           \
({                                                                      \
	struct auth_guard_nsproxy_transition *__ag_transaction =             \
		(_transaction);                                                \
	const char *__ag_where = (_where);                                    \
	enum auth_guard_mutation_result __result =                         \
		AUTH_GUARD_MUTATION_REJECTED;                              \
	if (auth_guard_nsproxy_transition_begin_where(                       \
			(_nsproxy), __ag_transaction, __ag_where)) {             \
		if (!(_expect)) {                                              \
			(void)auth_guard_nsproxy_transition_abort_where(          \
				__ag_transaction, __ag_where);                     \
		} else {                                                       \
			__result = (_mutate);                                    \
			if (__result == AUTH_GUARD_MUTATION_REJECTED)            \
				(void)auth_guard_nsproxy_transition_abort_where(  \
					__ag_transaction, __ag_where);          \
			else if (__result == AUTH_GUARD_MUTATION_APPLIED &&      \
				 !auth_guard_nsproxy_transition_finish_where(      \
					 __ag_transaction, __ag_where))             \
				__result = AUTH_GUARD_MUTATION_QUARANTINED;       \
		}                                                              \
	}                                                                      \
	__result;                                                           \
})

#define DEFINE_AUTH_GUARD_NSPROXY_REPLACER(_member)                        \
enum auth_guard_mutation_result                                             \
auth_guard_nsproxy_replace_##_member##_where(                               \
	struct nsproxy *nsproxy,                                                \
	typeof_member(struct nsproxy, _member) replacement,                    \
	typeof_member(struct nsproxy, _member) *authenticated_old,             \
	const char *where)                                                     \
{                                                                           \
	struct auth_guard_nsproxy_transition transaction;                      \
	enum auth_guard_mutation_result result;                                \
	if (!nsproxy || !authenticated_old)                                    \
		return AUTH_GUARD_MUTATION_REJECTED;                             \
	result = AUTH_GUARD_NSPROXY_REPLACE(                                  \
		nsproxy, &transaction,                                           \
		auth_guard_nsproxy_transition_expect_##_member##_where(          \
			&transaction, replacement, where),                         \
		auth_guard_nsproxy_transition_mutate_##_member##_where(          \
			&transaction, where), where);                              \
	if (result == AUTH_GUARD_MUTATION_APPLIED)                            \
		*authenticated_old = transaction.old._member;                   \
	return result;                                                         \
}

DEFINE_AUTH_GUARD_NSPROXY_REPLACER(mnt_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(uts_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(ipc_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(pid_ns_for_children)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(net_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(cgroup_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(syslog_ns)
DEFINE_AUTH_GUARD_NSPROXY_REPLACER(tracing_ns)

#undef DEFINE_AUTH_GUARD_NSPROXY_REPLACER

enum auth_guard_mutation_result auth_guard_nsproxy_replace_time_where(
	struct nsproxy *nsproxy, struct time_namespace *replacement,
	struct time_namespace **authenticated_old,
	struct time_namespace **authenticated_old_for_children,
	const char *where)
{
	struct auth_guard_nsproxy_transition transaction;
	enum auth_guard_mutation_result result;

	if (!nsproxy || !authenticated_old || !authenticated_old_for_children)
		return AUTH_GUARD_MUTATION_REJECTED;
	result = AUTH_GUARD_NSPROXY_REPLACE(
		nsproxy, &transaction,
		auth_guard_nsproxy_transition_expect_time_where(
			&transaction, replacement, replacement, where),
		auth_guard_nsproxy_transition_mutate_time_where(
			&transaction, where), where);
	if (result == AUTH_GUARD_MUTATION_APPLIED) {
		*authenticated_old = transaction.old.time_ns;
		*authenticated_old_for_children =
			transaction.old.time_ns_for_children;
	}
	return result;
}

enum auth_guard_mutation_result auth_guard_nsproxy_replace_cgroup_root_where(
	struct nsproxy *nsproxy, struct css_set *replacement,
	struct css_set **authenticated_old, const char *where)
{
	struct auth_guard_nsproxy_transition transaction;
	enum auth_guard_mutation_result result;

	if (!nsproxy || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	result = AUTH_GUARD_NSPROXY_REPLACE(
		nsproxy, &transaction,
		auth_guard_nsproxy_transition_expect_cgroup_root_where(
			&transaction, replacement, where),
		auth_guard_nsproxy_transition_mutate_cgroup_root_where(
			&transaction, where), where);
	if (result == AUTH_GUARD_MUTATION_APPLIED)
		*authenticated_old = transaction.old.cgroup_ns_root_cset;
	return result;
}

#undef AUTH_GUARD_NSPROXY_REPLACE

#undef AUTH_GUARD_NSPROXY_CHANGE

static bool auth_guard_nsproxy_check_reserved(
	const struct nsproxy *nsproxy, const char *where,
	const struct auth_guard_transition *transition)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;

	/* Acquire the release-published seal before protected metadata. */
	stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	computed = auth_guard_nsproxy_hash(
		nsproxy, stamp.generation, stamp.nonce, where);
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	if (!auth_guard_transition_reader_stable(
		    &nsproxy_authority_guard, where, transition, &stamp,
		    &current_stamp))
		return false;
	if (!auth_guard_snapshot_valid(&nsproxy_authority_guard, where, nsproxy,
					       &stamp, computed))
		return false;
	if (!auth_guard_nsproxy_validate_endpoint(nsproxy, where))
		return false;

	/* The parent snapshot must remain stable across endpoint checks. */
	current_stamp = auth_guard_nsproxy_stamp_load(nsproxy);
	return auth_guard_transition_reader_stable(
		&nsproxy_authority_guard, where, transition, &stamp, &current_stamp);
}

DEFINE_AUTH_GUARD_OBJECT_SNAPSHOT_API(
	auth_guard_nsproxy,
	nsproxy,
	auth_nsproxy_guard_enabled,
	nsproxy_authority_guard)

bool auth_guard_nsproxy_destroy_begin_where(const struct nsproxy *nsproxy,
				      const char *where)
{
	enum auth_guard_check_result result;

	result = auth_guard_nsproxy_snapshot_begin_where(nsproxy, where);
	if (result == AUTH_GUARD_CHECK_BUSY)
		auth_guard_fail(&nsproxy_authority_guard, where, "busy destroy",
				nsproxy);

	return result == AUTH_GUARD_CHECK_VALID;
}

#ifdef CONFIG_CGROUPS
static u64 auth_guard_cgroup_ns_root_hash(
	const struct cgroup_namespace *ns, const struct css_set *root_cset,
	u64 generation, u64 nonce)
{
	struct auth_guard_cgroup_ns_root_digest digest = {
		.cgroup_ns	= auth_guard_ptr(ns),
		.generation	= generation,
		.nonce		= nonce,
		.root_cset	= auth_guard_ptr(root_cset),
	};

	return auth_guard_seal(&cgroup_ns_root_guard, &digest, sizeof(digest));
}

static bool auth_guard_cgroup_ns_root_seal(struct cgroup_namespace *ns,
						    const char *where)
{
	struct auth_guard_stamp stamp;
	struct css_set *root_cset;

	if (!auth_cgroup_ns_root_guard_enabled())
		return true;
	if (!ns) {
		auth_guard_fail(&cgroup_ns_root_guard, where, "missing", ns);
		return false;
	}

	root_cset = READ_ONCE(ns->root_cset);
	if (!root_cset) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"missing endpoint", ns);
		return false;
	}
	if (!auth_guard_css_set_check_where(root_cset, where))
		return false;

	stamp = auth_guard_stamp_fresh(&cgroup_ns_root_guard);
	stamp.seal = auth_guard_cgroup_ns_root_hash(
		ns, root_cset, stamp.generation, stamp.nonce);
	if (READ_ONCE(ns->root_cset) != root_cset) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"changed constructor endpoint", ns);
		return false;
	}
	/* Publish the completed constructor tuple before exposing its seal. */
	auth_guard_cgroup_ns_root_stamp_publish(ns, &stamp);
	return true;
}

bool auth_guard_cgroup_ns_root_init_where(struct cgroup_namespace *ns,
					 const char *where)
{
	struct auth_guard_stamp stamp;

	if (!auth_cgroup_ns_root_guard_enabled())
		return true;
	if (!ns) {
		auth_guard_fail(&cgroup_ns_root_guard, where, "missing init", ns);
		return false;
	}
	stamp = auth_guard_cgroup_ns_root_stamp_load(ns);
	if (!auth_guard_stamp_empty(&stamp)) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"sealed first publication", ns);
		return false;
	}

	return auth_guard_cgroup_ns_root_seal(ns, where);
}

bool auth_guard_cgroup_ns_root_check_where(const struct cgroup_namespace *ns,
					  const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	struct css_set *root_cset;
	u64 computed;

	if (!auth_guard_enabled())
		return true;
	if (!ns) {
		auth_guard_fail(&cgroup_ns_root_guard, where, "missing", ns);
		return false;
	}

	root_cset = READ_ONCE(ns->root_cset);
#if defined(CONFIG_AUTH_GUARD_TEST) && defined(CONFIG_CGROUPS)
	root_cset = auth_guard_test_adjust_cgroup_ns_root(ns, root_cset, where);
#endif
	if (!root_cset) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"missing endpoint", ns);
		return false;
	}
	if (!auth_cgroup_ns_root_guard_enabled())
		return auth_guard_css_set_check_where(root_cset, where);

	/* Authenticate the pointer value before dereferencing its endpoint. */
	stamp = auth_guard_cgroup_ns_root_stamp_load(ns);
	computed = auth_guard_cgroup_ns_root_hash(
		ns, root_cset, stamp.generation, stamp.nonce);
	if (!auth_guard_snapshot_valid(&cgroup_ns_root_guard, where, ns,
				       &stamp, computed))
		return false;
	if (!auth_guard_css_set_check_where(root_cset, where))
		return false;

	/* Reacquire the seal to close the immutable-object snapshot. */
	current_stamp = auth_guard_cgroup_ns_root_stamp_load(ns);
	if (READ_ONCE(ns->root_cset) != root_cset ||
	    !auth_guard_stamp_equal(&current_stamp, &stamp)) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"changed immutable object", ns);
		return false;
	}

	return true;
}

bool auth_guard_cgroup_ns_root_destroy_complete_where(
	struct cgroup_namespace *ns, const struct css_set *expected,
	bool old_valid, bool exact, const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;

	if (!auth_cgroup_ns_root_guard_enabled())
		return old_valid && exact;
	if (!old_valid)
		return false;
	if (!ns || !expected) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"missing destroy endpoint", ns);
		return false;
	}

	/* Acquire the published seal before authenticating the detached endpoint. */
	stamp = auth_guard_cgroup_ns_root_stamp_load(ns);
	computed = auth_guard_cgroup_ns_root_hash(
		ns, expected, stamp.generation, stamp.nonce);
	if (!auth_guard_snapshot_valid(&cgroup_ns_root_guard, where, ns,
				       &stamp, computed))
		return false;
	if (!exact || READ_ONCE(ns->root_cset)) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"inexact destroy detach", ns);
		return false;
	}
	current_stamp = auth_guard_cgroup_ns_root_stamp_load(ns);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp)) {
		auth_guard_fail(&cgroup_ns_root_guard, where,
				"changed during destroy", ns);
		return false;
	}

	/* Publish cleared metadata before removing the final seal. */
	auth_guard_cgroup_ns_root_stamp_clear(ns);
	return true;
}

static u64 auth_guard_css_set_hash(const struct css_set *cset,
				   u64 generation, u64 nonce,
				   const char *where)
{
	struct auth_guard_css_set_digest digest = {
		.css_set	= auth_guard_ptr(cset),
		.generation	= generation,
		.nonce		= nonce,
		.dfl_cgrp	= auth_guard_ptr(READ_ONCE(cset->dfl_cgrp)),
		.dom_cset	= auth_guard_ptr(READ_ONCE(cset->dom_cset)),
	};
	int i;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++)
		digest.subsys[i] =
			auth_guard_ptr(READ_ONCE(cset->subsys[i]));

#if defined(CONFIG_AUTH_GUARD_TEST) && defined(CONFIG_CGROUPS)
	auth_guard_test_adjust_css_set_digest(cset, &digest, where);
#endif

	return auth_guard_seal(&css_set_authority_guard, &digest,
			       sizeof(digest));
}

static void auth_guard_css_set_seal(struct css_set *cset, const char *where)
{
	struct auth_guard_stamp stamp;

	if (!auth_css_set_guard_enabled())
		return;
	if (!cset) {
		auth_guard_fail(&css_set_authority_guard, where, "missing", cset);
		return;
	}

	stamp = auth_guard_stamp_fresh(&css_set_authority_guard);
	stamp.seal = auth_guard_css_set_hash(
		cset, stamp.generation, stamp.nonce, where);
	auth_guard_css_set_stamp_publish(cset, &stamp);
}

static bool auth_guard_css_set_validate_endpoint(const struct css_set *cset,
						 const char *where)
{
	struct css_set *dom_cset;

	if (!auth_css_set_guard_enabled())
		return true;
	if (!cset) {
		auth_guard_fail(&css_set_authority_guard, where,
				"missing endpoint", cset);
		return false;
	}

	dom_cset = READ_ONCE(cset->dom_cset);
	if (dom_cset && dom_cset != cset &&
	    !auth_guard_css_set_check_where(dom_cset, where))
		return false;

	return true;
}

bool auth_guard_css_set_init_where(struct css_set *cset, const char *where)
{
	struct auth_guard_stamp stamp;

	if (!auth_css_set_guard_enabled())
		return true;
	if (!cset) {
		auth_guard_fail(&css_set_authority_guard, where,
				"missing init", cset);
		return false;
	}
	stamp = auth_guard_css_set_stamp_load(cset);
	if (!auth_guard_stamp_empty(&stamp)) {
		auth_guard_fail(&css_set_authority_guard, where,
				"sealed first publication", cset);
		return false;
	}
	if (!auth_guard_css_set_validate_endpoint(cset, where))
		return false;

	auth_guard_css_set_seal(cset, where);
	return true;
}

void __init auth_guard_cgroup_enable(void)
{
	if (!auth_guard_enabled())
		return;

	auth_css_set_guard_active = true;
	auth_cgroup_ns_root_guard_active = true;
	BUG_ON(!auth_guard_css_set_init(&init_css_set));
	BUG_ON(!auth_guard_cgroup_ns_root_init(&init_cgroup_ns));
	BUG_ON(!auth_guard_task_init(current));
}

bool auth_guard_css_set_check_where(const struct css_set *cset, const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;

	if (!auth_css_set_guard_enabled())
		return true;
	if (!cset) {
		auth_guard_fail(&css_set_authority_guard, where, "missing", cset);
		return false;
	}

	/* Acquire the release-published seal before protected metadata. */
	stamp = auth_guard_css_set_stamp_load(cset);
	computed = auth_guard_css_set_hash(
		cset, stamp.generation, stamp.nonce, where);
	if (!auth_guard_snapshot_valid(&css_set_authority_guard, where, cset,
				       &stamp, computed))
		return false;
	if (!auth_guard_css_set_validate_endpoint(cset, where))
		return false;
	/* Reacquire before comparing the protected publication metadata. */
	current_stamp = auth_guard_css_set_stamp_load(cset);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp)) {
		auth_guard_fail(&css_set_authority_guard, where,
				"changed immutable object", cset);
		return false;
	}

	return true;
}
#endif

struct auth_guard_task_state {
	u32 lifecycle;
	const struct cred *real_cred;
	const struct cred *cred;
	struct auth_guard_stamp cred_stamp;
	struct nsproxy *nsproxy;
#ifdef CONFIG_CGROUPS
	struct css_set *cgroups;
#endif
	struct files_struct *files;
	bool no_new_privs;
	bool syslog_ns_for_child;
	const char *syslog_ns_for_child_name;
	size_t syslog_ns_for_child_name_len;
	u64 syslog_ns_for_child_name_hash;
	bool tracing_ns_for_child;
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	bool lsm_ns_for_child;
	u64 lsm_ns_for_child_lsmid;
	const struct lsm_ctx *lsm_ns_for_child_ctx;
	size_t lsm_ns_for_child_ctx_len;
	u64 lsm_ns_for_child_ctx_hash;
#endif
#ifdef CONFIG_SECCOMP
	unsigned long seccomp_mode;
#ifdef CONFIG_SECCOMP_FILTER
	int seccomp_filter_count;
	struct seccomp_filter *seccomp_filter;
#endif
#endif
};

static bool auth_guard_task_syslog_request_valid(
	bool enabled, const char *name, size_t name_len, u64 *name_hash)
{
	u8 terminator;

	if (!enabled)
		return !name && !name_len;
	return name && name_len && name_len <= SYSLOG_NS_NAME_MAX_LENGTH &&
		auth_guard_bytes_hash(name, name_len + 1,
				      SYSLOG_NS_NAME_MAX_LENGTH + 1, name_hash) &&
		!copy_from_kernel_nofault(&terminator, name + name_len,
					  sizeof(terminator)) && !terminator;
}

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
static bool auth_guard_task_lsm_request_valid(
	bool enabled, u64 lsmid, const struct lsm_ctx *ctx, size_t ctx_len,
	u64 *ctx_hash)
{
	struct lsm_ctx header;
	u64 required_len;

	if (!enabled)
		return lsmid == LSM_ID_UNDEF && !ctx && !ctx_len;
	return ctx && ctx_len >= sizeof(header) && ctx_len <= PAGE_SIZE &&
		auth_guard_bytes_hash(ctx, ctx_len, PAGE_SIZE, ctx_hash) &&
		!copy_from_kernel_nofault(&header, ctx, sizeof(header)) &&
		!header.flags && header.id == lsmid && header.len == ctx_len &&
		!check_add_overflow((u64)sizeof(header), header.ctx_len,
				    &required_len) && required_len == ctx_len;
}
#endif

static bool auth_guard_task_state_read(const struct task_struct *task,
				       struct auth_guard_task_state *state,
				       const char *where)
{
	*state = (struct auth_guard_task_state) {
		.lifecycle = READ_ONCE(task->auth_guard_lifecycle),
		.real_cred = rcu_access_pointer(task->real_cred),
		.cred = rcu_access_pointer(task->cred),
		.cred_stamp =
			auth_guard_stamp_load_acquire(&task->cred_guard_stamp),
		.nsproxy = READ_ONCE(task->nsproxy),
#ifdef CONFIG_CGROUPS
		.cgroups = rcu_access_pointer(task->cgroups),
#endif
		.files = READ_ONCE(task->files),
		.no_new_privs =
			test_bit(PFA_NO_NEW_PRIVS, &task->atomic_flags),
		.syslog_ns_for_child = READ_ONCE(task->syslog_ns_for_child),
		.syslog_ns_for_child_name =
			READ_ONCE(task->syslog_ns_for_child_name),
		.syslog_ns_for_child_name_len =
			READ_ONCE(task->syslog_ns_for_child_name_len),
		.tracing_ns_for_child = READ_ONCE(task->tracing_ns_for_child),
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
		.lsm_ns_for_child = READ_ONCE(task->lsm_ns_for_child),
		.lsm_ns_for_child_lsmid =
			READ_ONCE(task->lsm_ns_for_child_lsmid),
		.lsm_ns_for_child_ctx = READ_ONCE(task->lsm_ns_for_child_ctx),
		.lsm_ns_for_child_ctx_len =
			READ_ONCE(task->lsm_ns_for_child_ctx_len),
#endif
#ifdef CONFIG_SECCOMP
		.seccomp_mode = READ_ONCE(task->seccomp.mode),
#ifdef CONFIG_SECCOMP_FILTER
		.seccomp_filter_count = atomic_read(&task->seccomp.filter_count),
		.seccomp_filter = READ_ONCE(task->seccomp.filter),
#endif
#endif
	};

	if (!auth_guard_task_syslog_request_valid(
		    state->syslog_ns_for_child,
		    state->syslog_ns_for_child_name,
		    state->syslog_ns_for_child_name_len,
		    &state->syslog_ns_for_child_name_hash))
		goto invalid_payload;

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (!auth_guard_task_lsm_request_valid(
		    state->lsm_ns_for_child, state->lsm_ns_for_child_lsmid,
		    state->lsm_ns_for_child_ctx, state->lsm_ns_for_child_ctx_len,
		    &state->lsm_ns_for_child_ctx_hash))
		goto invalid_payload;
#endif
	return true;

invalid_payload:
	auth_guard_fail(&task_authority_guard, where,
			"invalid pending child request", task);
	return false;
}

static u64 auth_guard_task_state_hash(
	const struct task_struct *task, const struct auth_guard_task_state *state,
	u64 generation, u64 nonce, enum auth_guard_semantic_purpose purpose,
	const char *where, bool inject_fault)
{
	struct auth_guard_task_digest digest;

	digest = (struct auth_guard_task_digest) {
		.purpose	= purpose,
		.task		= auth_guard_ptr(task),
		.generation	= generation,
		.nonce		= nonce,
		.lifecycle	= state->lifecycle,
		.real_cred	= auth_guard_ptr(state->real_cred),
		.cred		= auth_guard_ptr(state->cred),
		.cred_generation = state->cred_stamp.generation,
		.cred_nonce	= state->cred_stamp.nonce,
		.cred_seal	= state->cred_stamp.seal,
		.nsproxy	= auth_guard_ptr(state->nsproxy),
#ifdef CONFIG_CGROUPS
		.cgroups	= auth_guard_ptr(state->cgroups),
#endif
		.files		= auth_guard_ptr(state->files),
		.no_new_privs	= state->no_new_privs,
		.syslog_ns_for_child = state->syslog_ns_for_child,
		.syslog_ns_for_child_name =
			auth_guard_ptr(state->syslog_ns_for_child_name),
		.syslog_ns_for_child_name_len =
			state->syslog_ns_for_child_name_len,
		.syslog_ns_for_child_name_hash =
			state->syslog_ns_for_child_name_hash,
		.tracing_ns_for_child =
			state->tracing_ns_for_child,
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
		.lsm_ns_for_child = state->lsm_ns_for_child,
		.lsm_ns_for_child_lsmid = state->lsm_ns_for_child_lsmid,
		.lsm_ns_for_child_ctx =
			auth_guard_ptr(state->lsm_ns_for_child_ctx),
		.lsm_ns_for_child_ctx_len =
			state->lsm_ns_for_child_ctx_len,
		.lsm_ns_for_child_ctx_hash =
			state->lsm_ns_for_child_ctx_hash,
#endif
#ifdef CONFIG_SECCOMP
		.seccomp_mode	= state->seccomp_mode,
#ifdef CONFIG_SECCOMP_FILTER
		.seccomp_filter_count = state->seccomp_filter_count,
		.seccomp_filter	= auth_guard_ptr(state->seccomp_filter),
#endif
#endif
	};

#ifdef CONFIG_AUTH_GUARD_TEST
	if (inject_fault)
		auth_guard_test_adjust_task_digest(task, &digest, where);
#ifdef CONFIG_CGROUPS
	if (inject_fault)
		auth_guard_test_adjust_task_cgroups_digest(task, &digest, where);
#endif
#endif

	return auth_guard_seal(&task_authority_guard, &digest, sizeof(digest));
}

static bool
auth_guard_task_hash(const struct task_struct *task, u64 generation, u64 nonce,
		     const char *where, u64 *hash)
{
	struct auth_guard_task_state state;

	if (!auth_guard_task_state_read(task, &state, where))
		return false;
	*hash = auth_guard_task_state_hash(
		task, &state, generation, nonce, AUTH_GUARD_SEMANTIC_PUBLICATION,
		where, true);
	return true;
}

static enum auth_guard_check_result auth_guard_task_check_endpoints(
	struct task_struct *task, const char *where, bool reserved, bool wait);

static enum auth_guard_check_result auth_guard_task_capture_anchor_state(
	struct task_struct *task, enum auth_guard_transition_anchor anchor,
	const struct auth_guard_stamp *stamp, const char *where,
	u64 *expected_state)
{
	struct auth_guard_stamp authority_stamp;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state state;
	enum auth_guard_check_result result;
	u64 publication_hash;
	u64 state_hash;

	if (!task || !stamp || !expected_state ||
	    !auth_guard_stamp_valid(stamp) ||
	    !auth_guard_task_state_read(task, &state, where))
		return AUTH_GUARD_CHECK_INVALID;

	switch (anchor) {
	case AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY:
		if (!auth_task_guard_enabled())
			goto invalid_anchor;
		current_stamp =
			auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
		publication_hash = auth_guard_task_state_hash(
			task, &state, stamp->generation, stamp->nonce,
			AUTH_GUARD_SEMANTIC_PUBLICATION, where, true);
		if (!auth_guard_stamp_equal(&current_stamp, stamp) ||
		    !auth_guard_snapshot_valid(
			    &task_authority_guard, where, task, stamp,
			    publication_hash))
			goto unauthenticated;
		break;
	case AUTH_GUARD_TRANSITION_ANCHOR_CRED:
		/* A credential anchor is valid only before the first task seal. */
		authority_stamp =
			auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
		current_stamp =
			auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
		if (!auth_guard_stamp_empty(&authority_stamp) ||
		    !auth_guard_stamp_equal(&current_stamp, stamp) ||
		    cred_guard_check_task_cred_reserved_where(
			    task, state.real_cred, where) !=
			    AUTH_GUARD_CHECK_VALID)
			goto unauthenticated;
		break;
	default:
		goto invalid_anchor;
	}

	state_hash = auth_guard_task_state_hash(
		task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (!state_hash)
		return AUTH_GUARD_CHECK_INVALID;
	result = auth_guard_task_check_endpoints(task, where, true, false);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
	if (!auth_guard_task_state_read(task, &current_state, where))
		return AUTH_GUARD_CHECK_INVALID;
	current_stamp = anchor == AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY ?
		auth_guard_stamp_load_acquire(&task->auth_guard_stamp) :
		auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, stamp) ||
	    auth_guard_task_state_hash(
		    task, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) != state_hash) {
		auth_guard_fail(&task_authority_guard, where,
				"changed transition expectation", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	*expected_state = state_hash;
	return AUTH_GUARD_CHECK_VALID;

invalid_anchor:
	auth_guard_fail(&task_authority_guard, where,
			"invalid transition anchor", task);
	return AUTH_GUARD_CHECK_INVALID;

unauthenticated:
	auth_guard_fail(&task_authority_guard, where,
			"unauthenticated transition source", task);
	return AUTH_GUARD_CHECK_INVALID;
}

bool auth_guard_task_expect_creds_where(
	struct task_struct *task, const struct cred *new_real,
	const struct cred *new_subj, const struct auth_guard_stamp *new_stamp,
	struct auth_guard_stamp *old_stamp, const struct cred **old_real,
	const struct cred **old_subj,
	const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	struct auth_guard_task_state stable_state;
	struct user_namespace *real_user_ns;
	struct user_namespace *subj_user_ns;
	u64 current_hash;
	u64 expected_hash;

	if (!task || !new_real || !new_subj || !new_stamp || !old_stamp ||
	    !old_real || !old_subj || !auth_guard_stamp_valid(new_stamp) ||
	    !cred_guard_verify_committed_cred_where(new_real, where) ||
	    !cred_guard_verify_committed_cred_where(new_subj, where) ||
	    !auth_guard_task_state_read(task, &current_state, where))
		return false;
	real_user_ns = READ_ONCE(new_real->user_ns);
	subj_user_ns = READ_ONCE(new_subj->user_ns);
	if (!auth_guard_userns_boundary_check_where(real_user_ns, where) ||
	    (subj_user_ns != real_user_ns &&
	     !auth_guard_userns_boundary_check_where(subj_user_ns, where)))
		return false;

	expected_state = current_state;
	expected_state.real_cred = new_real;
	expected_state.cred = new_subj;
	expected_state.cred_stamp = *new_stamp;
	current_hash = auth_guard_task_state_hash(
		task, &current_state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION,
		where, false);
	expected_hash = auth_guard_task_state_hash(
		task, &expected_state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION,
		where, false);
	if (!auth_guard_task_transition_update_expected_where(
		    task, current_hash, expected_hash, where))
		return false;
	if (!auth_guard_task_state_read(task, &stable_state, where) ||
	    auth_guard_task_state_hash(
		    task, &stable_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    current_hash) {
		auth_guard_task_transition_quarantine(task);
		return false;
	}
	*old_stamp = current_state.cred_stamp;
	*old_real = current_state.real_cred;
	*old_subj = current_state.cred;
	return true;
}

static enum auth_guard_check_result auth_guard_task_capture_constructor_states(
	struct task_struct *task, const struct auth_guard_stamp *cred_stamp,
	const char *where, u64 *restore_state, u64 *expected_state,
	u32 *old_lifecycle)
{
	struct auth_guard_task_state state;
	struct auth_guard_task_state expected;
	enum auth_guard_check_result result;
	u64 state_hash;

	if (!restore_state || !expected_state || !old_lifecycle)
		return AUTH_GUARD_CHECK_INVALID;
	result = auth_guard_task_capture_anchor_state(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, cred_stamp, where,
		restore_state);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
	if (!auth_guard_task_state_read(task, &state, where))
		return AUTH_GUARD_CHECK_INVALID;
	state_hash = auth_guard_task_state_hash(
		task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (state_hash != *restore_state ||
	    (state.lifecycle != AUTH_GUARD_TASK_UNPUBLISHED &&
	     state.lifecycle != AUTH_GUARD_TASK_LIVE)) {
		auth_guard_fail(&task_authority_guard, where,
				"invalid constructor state", task);
		return AUTH_GUARD_CHECK_INVALID;
	}

	expected = state;
	expected.lifecycle = AUTH_GUARD_TASK_LIVE;
	*expected_state = auth_guard_task_state_hash(
		task, &expected, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where,
		false);
	*old_lifecycle = state.lifecycle;
	return *expected_state ? AUTH_GUARD_CHECK_VALID :
		AUTH_GUARD_CHECK_INVALID;
}

static bool auth_guard_task_transition_expect_state(
	struct task_struct *task, const struct auth_guard_task_state *current_state,
	const struct auth_guard_task_state *expected_state, const char *where,
	u64 *expected_hash)
{
	struct auth_guard_task_state stable_state;
	u64 current_hash;

	if (!task || !current_state || !expected_state || !expected_hash)
		return false;
	if (!auth_task_guard_enabled()) {
		*expected_hash = 0;
		return true;
	}
	current_hash = auth_guard_task_state_hash(
		task, current_state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION,
		where, false);
	*expected_hash = auth_guard_task_state_hash(
		task, expected_state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION,
		where, false);
	if (!auth_guard_task_transition_update_expected_where(
		    task, current_hash, *expected_hash, where))
		return false;
	if (auth_guard_task_state_read(task, &stable_state, where) &&
	    auth_guard_task_state_hash(
		    task, &stable_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) ==
		    current_hash)
		return true;
	auth_guard_fail(&task_authority_guard, where,
			"changed while declaring task transition", task);
	auth_guard_task_transition_quarantine(task);
	return false;
}

static bool auth_guard_task_transition_state_matches(
	struct task_struct *task, u64 expected_hash, const char *where)
{
	struct auth_guard_task_state state;

	if (!auth_task_guard_enabled())
		return true;
	if (auth_guard_task_state_read(task, &state, where) &&
	    auth_guard_task_state_hash(
		    task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION,
		    where, false) == expected_hash)
		return true;
	auth_guard_fail(&task_authority_guard, where,
			"unexpected mutated task transition", task);
	auth_guard_task_transition_quarantine(task);
	return false;
}

bool auth_guard_task_validate_transition_result_where(
	struct task_struct *task, const char *where)
{
	struct auth_guard_transition transition;
	struct auth_guard_stamp stamp;
	u64 expected_state;

	if (!auth_task_guard_enabled())
		return true;
	if (!task)
		return false;
	transition = auth_guard_task_transition(task);
	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!__auth_guard_transition_verify(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp, false,
		    NULL, &expected_state))
		return false;
	return auth_guard_task_transition_state_matches(
		task, expected_state, where);
}

static enum auth_guard_mutation_result auth_guard_task_mutation_fail(
	struct task_struct *task, const char *where, const char *what,
	enum auth_guard_mutation_result result)
{
	if (task) {
		auth_guard_fail(&task_authority_guard, where, what, task);
		auth_guard_task_transition_quarantine(task);
	}
	return result;
}

static bool auth_guard_task_capture_mutation_states(
	struct task_struct *task, struct auth_guard_task_state *current_state,
	struct auth_guard_task_state *expected_state, const char *where)
{
	if (!auth_guard_task_state_read(task, current_state, where)) {
		auth_guard_task_transition_quarantine(task);
		return false;
	}
	*expected_state = *current_state;
	return true;
}

static bool auth_guard_task_files_replacement_valid(
	const struct auth_guard_task_state *current_state,
	struct files_struct *replacement, const char *where)
{
	(void)where;
	return current_state->lifecycle ==
		(replacement ? AUTH_GUARD_TASK_LIVE :
			       AUTH_GUARD_TASK_EXITING);
}

static bool auth_guard_task_nsproxy_replacement_valid(
	const struct auth_guard_task_state *current_state,
	struct nsproxy *replacement, const char *where)
{
	if (current_state->lifecycle !=
	    (replacement ? AUTH_GUARD_TASK_LIVE : AUTH_GUARD_TASK_EXITING))
		return false;
	return !replacement ||
		auth_guard_nsproxy_check_where(replacement, where);
}

#define DEFINE_AUTH_GUARD_TASK_EDGE_MUTATION(_name, _type, _member, _valid)      \
static bool __auth_guard_task_expect_##_name##_in_transition_where(              \
	struct task_struct *task, struct _type *replacement,                      \
	struct auth_guard_task_state *current_state, u64 *expected_hash,          \
	const char *where)                                                        \
{                                                                               \
	struct auth_guard_task_state expected_state;                             \
\
	if (!task || !current_state || !expected_hash ||                         \
	    !auth_guard_task_capture_mutation_states(                            \
		    task, current_state, &expected_state, where) ||              \
	    !_valid(current_state, replacement, where))                          \
		return false;                                                   \
	expected_state._member = replacement;                                    \
	return auth_guard_task_transition_expect_state(                          \
		task, current_state, &expected_state, where, expected_hash);      \
}                                                                               \
\
enum auth_guard_mutation_result                                                  \
auth_guard_task_replace_##_name##_in_transition_where(                           \
	struct task_struct *task, struct _type *replacement,                      \
	struct _type **authenticated_old, const char *where)                      \
{                                                                               \
	struct auth_guard_task_state current_state;                              \
	struct _type *old;                                                       \
	u64 expected_hash;                                                       \
\
	if (!task || !authenticated_old)                                         \
		return AUTH_GUARD_MUTATION_REJECTED;                            \
	if (!auth_task_guard_enabled()) {                                        \
		*authenticated_old = task->_member;                                \
		task->_member = replacement;                                      \
		return AUTH_GUARD_MUTATION_APPLIED;                               \
	}                                                                       \
	if (!__auth_guard_task_expect_##_name##_in_transition_where(             \
		    task, replacement, &current_state, &expected_hash, where))   \
		return AUTH_GUARD_MUTATION_REJECTED;                            \
	old = current_state._member;                                              \
	if (cmpxchg(&task->_member, old, replacement) != old)                    \
		return auth_guard_task_mutation_fail(                           \
			task, where, "inexact task pointer mutation",           \
			AUTH_GUARD_MUTATION_REJECTED);                          \
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))\
		return AUTH_GUARD_MUTATION_QUARANTINED;                         \
	*authenticated_old = old;                                                 \
	return AUTH_GUARD_MUTATION_APPLIED;                                       \
}

DEFINE_AUTH_GUARD_TASK_EDGE_MUTATION(files, files_struct, files,
				     auth_guard_task_files_replacement_valid)
DEFINE_AUTH_GUARD_TASK_EDGE_MUTATION(nsproxy, nsproxy, nsproxy,
				     auth_guard_task_nsproxy_replacement_valid)

#undef DEFINE_AUTH_GUARD_TASK_EDGE_MUTATION

#ifdef CONFIG_CGROUPS
bool auth_guard_task_expect_cgroups_in_transition_where(
	struct task_struct *task, struct css_set *authenticated_current,
	struct css_set *replacement, const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;

	if (!auth_task_guard_enabled())
		return true;
	if (!task || !authenticated_current ||
	    !auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where) ||
	    current_state.cgroups != authenticated_current ||
	    current_state.lifecycle !=
		    (replacement ? AUTH_GUARD_TASK_LIVE :
				   AUTH_GUARD_TASK_EXITING) ||
	    !auth_guard_css_set_check_where(authenticated_current, where) ||
	    (replacement &&
	     !auth_guard_css_set_check_where(replacement, where)))
		return false;
	expected_state.cgroups = replacement;
	return auth_guard_task_transition_expect_state(
		task, &current_state, &expected_state, where, &expected_hash);
}
#endif

#ifdef CONFIG_SECCOMP
static bool auth_guard_task_seccomp_change_valid(
	const struct auth_guard_task_state *current_state,
	enum auth_guard_task_seccomp_change change,
	const struct auth_guard_task_seccomp_state *expected)
{
	if (expected->filter_count < 0)
		return false;
	if (expected->no_new_privs < current_state->no_new_privs)
		return false;

#ifdef CONFIG_SECCOMP_FILTER
	if (current_state->seccomp_filter_count < 0)
		return false;
	switch (change) {
	case AUTH_GUARD_TASK_SECCOMP_FILTER:
		if (current_state->seccomp_filter_count == S32_MAX ||
		    expected->filter_count !=
			    current_state->seccomp_filter_count + 1 ||
		    !expected->filter ||
		    expected->filter == current_state->seccomp_filter)
			return false;
		break;
	case AUTH_GUARD_TASK_SECCOMP_SYNC:
		if (expected->filter_count < current_state->seccomp_filter_count ||
		    !expected->filter ||
		    (expected->filter == current_state->seccomp_filter) !=
			    (expected->filter_count ==
			     current_state->seccomp_filter_count))
			return false;
		break;
	case AUTH_GUARD_TASK_SECCOMP_DETACH:
		if (!current_state->seccomp_filter || expected->filter ||
		    expected->filter_count != current_state->seccomp_filter_count)
			return false;
		break;
	default:
		if (expected->filter != current_state->seccomp_filter ||
		    expected->filter_count != current_state->seccomp_filter_count)
			return false;
		break;
	}
#else
	if (expected->filter || expected->filter_count ||
	    change == AUTH_GUARD_TASK_SECCOMP_FILTER ||
	    change == AUTH_GUARD_TASK_SECCOMP_SYNC ||
	    change == AUTH_GUARD_TASK_SECCOMP_DETACH)
		return false;
#endif

	switch (change) {
	case AUTH_GUARD_TASK_SECCOMP_DEAD:
		return current_state->lifecycle == AUTH_GUARD_TASK_LIVE &&
			(current_state->seccomp_mode == SECCOMP_MODE_STRICT ||
			 current_state->seccomp_mode == SECCOMP_MODE_FILTER) &&
			expected->mode == SECCOMP_MODE_DEAD &&
			expected->no_new_privs == current_state->no_new_privs;
	case AUTH_GUARD_TASK_SECCOMP_STRICT:
		return current_state->lifecycle == AUTH_GUARD_TASK_LIVE &&
			current_state->seccomp_mode == SECCOMP_MODE_DISABLED &&
			expected->mode == SECCOMP_MODE_STRICT &&
			expected->no_new_privs == current_state->no_new_privs;
	case AUTH_GUARD_TASK_SECCOMP_FILTER:
		return current_state->lifecycle == AUTH_GUARD_TASK_LIVE &&
			(current_state->seccomp_mode == SECCOMP_MODE_DISABLED ||
			 current_state->seccomp_mode == SECCOMP_MODE_FILTER) &&
			expected->mode == SECCOMP_MODE_FILTER &&
			expected->no_new_privs == current_state->no_new_privs;
	case AUTH_GUARD_TASK_SECCOMP_SYNC:
		return current_state->lifecycle == AUTH_GUARD_TASK_LIVE &&
			(current_state->seccomp_mode == SECCOMP_MODE_DISABLED ||
			 current_state->seccomp_mode == SECCOMP_MODE_FILTER) &&
			expected->mode == SECCOMP_MODE_FILTER;
	case AUTH_GUARD_TASK_SECCOMP_DETACH:
		return current_state->lifecycle == AUTH_GUARD_TASK_EXITING &&
			(current_state->seccomp_mode == SECCOMP_MODE_FILTER ||
			 current_state->seccomp_mode == SECCOMP_MODE_DEAD) &&
			expected->mode == current_state->seccomp_mode &&
			expected->no_new_privs == current_state->no_new_privs;
	}
	return false;
}

bool auth_guard_task_expect_seccomp_in_transition_where(
	struct task_struct *task, enum auth_guard_task_seccomp_change change,
	const struct auth_guard_task_seccomp_state *expected, const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;

	if (!auth_task_guard_enabled())
		return true;
	if (!task || !expected ||
	    !auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where) ||
	    !auth_guard_task_seccomp_change_valid(
		    &current_state, change, expected))
		return false;
	expected_state.seccomp_mode = expected->mode;
	expected_state.no_new_privs = expected->no_new_privs;
#ifdef CONFIG_SECCOMP_FILTER
	expected_state.seccomp_filter_count = expected->filter_count;
	expected_state.seccomp_filter = expected->filter;
#endif
	return auth_guard_task_transition_expect_state(
		task, &current_state, &expected_state, where, &expected_hash);
}
#endif

static bool auth_guard_task_cred_detach_source_valid(
	const struct auth_guard_task_state *state,
	const struct cred *expected_real, const struct cred *expected_subj)
{
	if (state->lifecycle != AUTH_GUARD_TASK_EXITING ||
	    state->real_cred != expected_real ||
	    state->cred != expected_subj ||
	    !auth_guard_stamp_valid(&state->cred_stamp) ||
	    state->nsproxy || state->files ||
	    state->syslog_ns_for_child || state->tracing_ns_for_child)
		return false;
#ifdef CONFIG_CGROUPS
	if (state->cgroups)
		return false;
#endif
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	if (state->lsm_ns_for_child)
		return false;
#endif
#ifdef CONFIG_SECCOMP_FILTER
	if (state->seccomp_filter)
		return false;
#endif
	return true;
}

bool auth_guard_task_expect_cred_detach_in_transition_where(
	struct task_struct *task, const struct cred *expected_real,
	const struct cred *expected_subj, const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;

	if (!auth_task_guard_enabled())
		return true;
	if (!task || !expected_real || !expected_subj ||
	    !auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where) ||
	    !auth_guard_task_cred_detach_source_valid(
		    &current_state, expected_real, expected_subj))
		return false;
	expected_state.real_cred = NULL;
	expected_state.cred = NULL;
	expected_state.cred_stamp = (struct auth_guard_stamp) {};
	return auth_guard_task_transition_expect_state(
		task, &current_state, &expected_state, where, &expected_hash);
}

static enum auth_guard_mutation_result
auth_guard_task_set_exiting_in_transition_where(struct task_struct *task,
						const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;

	if (!task ||
	    !auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where) ||
	    current_state.lifecycle != AUTH_GUARD_TASK_LIVE)
		return AUTH_GUARD_MUTATION_REJECTED;
	expected_state.lifecycle = AUTH_GUARD_TASK_EXITING;
	if (!auth_guard_task_transition_expect_state(
		    task, &current_state, &expected_state, where, &expected_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (cmpxchg(&task->auth_guard_lifecycle, AUTH_GUARD_TASK_LIVE,
		    AUTH_GUARD_TASK_EXITING) != AUTH_GUARD_TASK_LIVE)
		return auth_guard_task_mutation_fail(
			task, where, "inexact task lifecycle mutation",
			AUTH_GUARD_MUTATION_REJECTED);
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))
		return AUTH_GUARD_MUTATION_QUARANTINED;
	return AUTH_GUARD_MUTATION_APPLIED;
}

static enum auth_guard_mutation_result
auth_guard_task_transition_set_no_new_privs_where(
	struct task_struct *task, bool *authenticated_old, const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;
	bool old;

	if (!task || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	if (!auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	old = current_state.no_new_privs;
	expected_state.no_new_privs = true;
	if (!auth_guard_task_transition_expect_state(
		    task, &current_state, &expected_state, where, &expected_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (test_and_set_bit(PFA_NO_NEW_PRIVS, &task->atomic_flags) != old) {
		return auth_guard_task_mutation_fail(
			task, where, "inexact no-new-privs mutation",
			AUTH_GUARD_MUTATION_REJECTED);
	}
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))
		return AUTH_GUARD_MUTATION_QUARANTINED;
	*authenticated_old = old;
	return AUTH_GUARD_MUTATION_APPLIED;
}

enum auth_guard_mutation_result
auth_guard_task_replace_syslog_request_in_transition_where(
	struct task_struct *task,
	const struct auth_guard_task_syslog_request *replacement,
	struct auth_guard_task_syslog_request *authenticated_old,
	const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	struct auth_guard_task_syslog_request replacement_state;
	u64 expected_hash;
	u64 name_hash = 0;
	bool enabled_mutated = false;
	bool name_mutated = false;
	bool published = false;

	if (!task || !replacement || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	replacement_state = *replacement;
	replacement = &replacement_state;
	if (!auth_task_guard_enabled()) {
		*authenticated_old = (struct auth_guard_task_syslog_request) {
			.enabled = task->syslog_ns_for_child,
			.name = task->syslog_ns_for_child_name,
			.name_len = task->syslog_ns_for_child_name_len,
		};
		task->syslog_ns_for_child = replacement->enabled;
		task->syslog_ns_for_child_name = replacement->name;
		task->syslog_ns_for_child_name_len = replacement->name_len;
		return AUTH_GUARD_MUTATION_APPLIED;
	}
	if (!auth_guard_task_syslog_request_valid(
		    replacement->enabled, replacement->name,
		    replacement->name_len, &name_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (!auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	expected_state.syslog_ns_for_child = replacement->enabled;
	expected_state.syslog_ns_for_child_name = replacement->name;
	expected_state.syslog_ns_for_child_name_len = replacement->name_len;
	expected_state.syslog_ns_for_child_name_hash = name_hash;
	if (!auth_guard_task_transition_expect_state(
		    task, &current_state, &expected_state, where, &expected_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (cmpxchg(&task->syslog_ns_for_child,
		    current_state.syslog_ns_for_child,
		    replacement->enabled) != current_state.syslog_ns_for_child)
		goto failed;
	enabled_mutated = true;
	published |= current_state.syslog_ns_for_child != replacement->enabled;
	if (cmpxchg(&task->syslog_ns_for_child_name,
		    (char *)current_state.syslog_ns_for_child_name,
		    replacement->name) != current_state.syslog_ns_for_child_name)
		goto rollback;
	name_mutated = true;
	published |= current_state.syslog_ns_for_child_name != replacement->name;
	if (cmpxchg(&task->syslog_ns_for_child_name_len,
		    current_state.syslog_ns_for_child_name_len,
		    replacement->name_len) !=
		    current_state.syslog_ns_for_child_name_len)
		goto rollback;
	published |= current_state.syslog_ns_for_child_name_len !=
		     replacement->name_len;
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))
		return published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED;
	*authenticated_old = (struct auth_guard_task_syslog_request) {
		.enabled = current_state.syslog_ns_for_child,
		.name = (char *)current_state.syslog_ns_for_child_name,
		.name_len = current_state.syslog_ns_for_child_name_len,
	};
	return AUTH_GUARD_MUTATION_APPLIED;

rollback:
	if (name_mutated &&
	    cmpxchg(&task->syslog_ns_for_child_name, replacement->name,
		    (char *)current_state.syslog_ns_for_child_name) !=
		    replacement->name)
		goto failed;
	if (enabled_mutated &&
	    cmpxchg(&task->syslog_ns_for_child, replacement->enabled,
		    current_state.syslog_ns_for_child) != replacement->enabled)
		goto failed;
failed:
	return auth_guard_task_mutation_fail(
		task, where, "inexact syslog-request mutation",
		published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED);
}

enum auth_guard_mutation_result
auth_guard_task_replace_tracing_request_in_transition_where(
	struct task_struct *task, bool replacement, bool *authenticated_old,
	const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	u64 expected_hash;
	bool published;

	if (!task || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	if (!auth_task_guard_enabled()) {
		*authenticated_old = task->tracing_ns_for_child;
		task->tracing_ns_for_child = replacement;
		return AUTH_GUARD_MUTATION_APPLIED;
	}
	if (!auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	expected_state.tracing_ns_for_child = replacement;
	if (!auth_guard_task_transition_expect_state(
		    task, &current_state, &expected_state, where, &expected_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	published = current_state.tracing_ns_for_child != replacement;
	if (cmpxchg(&task->tracing_ns_for_child,
		    current_state.tracing_ns_for_child, replacement) !=
	    current_state.tracing_ns_for_child) {
		return auth_guard_task_mutation_fail(
			task, where, "inexact tracing-request mutation",
			AUTH_GUARD_MUTATION_REJECTED);
	}
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))
		return published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED;
	*authenticated_old = current_state.tracing_ns_for_child;
	return AUTH_GUARD_MUTATION_APPLIED;
}

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
enum auth_guard_mutation_result
auth_guard_task_replace_lsm_request_in_transition_where(
	struct task_struct *task,
	const struct auth_guard_task_lsm_request *replacement,
	struct auth_guard_task_lsm_request *authenticated_old,
	const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state expected_state;
	struct auth_guard_task_lsm_request replacement_state;
	u64 ctx_hash = 0;
	u64 expected_hash;
	bool enabled_mutated = false;
	bool lsmid_mutated = false;
	bool ctx_mutated = false;
	bool published = false;

	if (!task || !replacement || !authenticated_old)
		return AUTH_GUARD_MUTATION_REJECTED;
	replacement_state = *replacement;
	replacement = &replacement_state;
	if (!auth_task_guard_enabled()) {
		*authenticated_old = (struct auth_guard_task_lsm_request) {
			.enabled = task->lsm_ns_for_child,
			.lsmid = task->lsm_ns_for_child_lsmid,
			.ctx = task->lsm_ns_for_child_ctx,
			.ctx_len = task->lsm_ns_for_child_ctx_len,
		};
		task->lsm_ns_for_child = replacement->enabled;
		task->lsm_ns_for_child_lsmid = replacement->lsmid;
		task->lsm_ns_for_child_ctx = replacement->ctx;
		task->lsm_ns_for_child_ctx_len = replacement->ctx_len;
		return AUTH_GUARD_MUTATION_APPLIED;
	}
	if (!auth_guard_task_lsm_request_valid(
		    replacement->enabled, replacement->lsmid, replacement->ctx,
		    replacement->ctx_len, &ctx_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (!auth_guard_task_capture_mutation_states(
		    task, &current_state, &expected_state, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	expected_state.lsm_ns_for_child = replacement->enabled;
	expected_state.lsm_ns_for_child_lsmid = replacement->lsmid;
	expected_state.lsm_ns_for_child_ctx = replacement->ctx;
	expected_state.lsm_ns_for_child_ctx_len = replacement->ctx_len;
	expected_state.lsm_ns_for_child_ctx_hash = ctx_hash;
	if (!auth_guard_task_transition_expect_state(
		    task, &current_state, &expected_state, where, &expected_hash))
		return AUTH_GUARD_MUTATION_REJECTED;
	if (cmpxchg(&task->lsm_ns_for_child,
		    current_state.lsm_ns_for_child, replacement->enabled) !=
		    current_state.lsm_ns_for_child)
		goto failed;
	enabled_mutated = true;
	published |= current_state.lsm_ns_for_child != replacement->enabled;
	if (cmpxchg(&task->lsm_ns_for_child_lsmid,
		    current_state.lsm_ns_for_child_lsmid, replacement->lsmid) !=
		    current_state.lsm_ns_for_child_lsmid)
		goto rollback;
	lsmid_mutated = true;
	published |= current_state.lsm_ns_for_child_lsmid != replacement->lsmid;
	if (cmpxchg(&task->lsm_ns_for_child_ctx,
		    (struct lsm_ctx *)current_state.lsm_ns_for_child_ctx,
		    replacement->ctx) != current_state.lsm_ns_for_child_ctx)
		goto rollback;
	ctx_mutated = true;
	published |= current_state.lsm_ns_for_child_ctx != replacement->ctx;
	if (cmpxchg(&task->lsm_ns_for_child_ctx_len,
		    current_state.lsm_ns_for_child_ctx_len,
		    replacement->ctx_len) != current_state.lsm_ns_for_child_ctx_len) {
		goto rollback;
	}
	published |= current_state.lsm_ns_for_child_ctx_len !=
		     replacement->ctx_len;
	if (!auth_guard_task_transition_state_matches(task, expected_hash, where))
		return published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED;
	*authenticated_old = (struct auth_guard_task_lsm_request) {
		.enabled = current_state.lsm_ns_for_child,
		.lsmid = current_state.lsm_ns_for_child_lsmid,
		.ctx = (struct lsm_ctx *)current_state.lsm_ns_for_child_ctx,
		.ctx_len = current_state.lsm_ns_for_child_ctx_len,
	};
	return AUTH_GUARD_MUTATION_APPLIED;

rollback:
	if (ctx_mutated &&
	    cmpxchg(&task->lsm_ns_for_child_ctx, replacement->ctx,
		    (struct lsm_ctx *)current_state.lsm_ns_for_child_ctx) !=
		    replacement->ctx)
		goto failed;
	if (lsmid_mutated &&
	    cmpxchg(&task->lsm_ns_for_child_lsmid, replacement->lsmid,
		    current_state.lsm_ns_for_child_lsmid) != replacement->lsmid)
		goto failed;
	if (enabled_mutated &&
	    cmpxchg(&task->lsm_ns_for_child, replacement->enabled,
		    current_state.lsm_ns_for_child) != replacement->enabled)
		goto failed;
failed:
	return auth_guard_task_mutation_fail(
		task, where, "inexact LSM-request mutation",
		published ? AUTH_GUARD_MUTATION_QUARANTINED :
			AUTH_GUARD_MUTATION_REJECTED);
}

#endif

static bool auth_guard_task_seal(struct task_struct *task, const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state state;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp auth_stamp;
	struct auth_guard_stamp cred_stamp;
	enum auth_guard_check_result result;
	u64 expected_state;
	u64 restore_state;
	u64 state_hash;
	u32 old_lifecycle;

	if (!auth_task_guard_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return false;
	}

	result = auth_guard_task_transition_reserve_where(task, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		return false;
	auth_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_stamp_empty(&auth_stamp)) {
		auth_guard_fail(&task_authority_guard, where,
				"already sealed first-seal task", task);
		goto invalid;
	}
	cred_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	result = auth_guard_task_capture_constructor_states(
		task, &cred_stamp, where, &restore_state, &expected_state,
		&old_lifecycle);
	if (result != AUTH_GUARD_CHECK_VALID)
		goto invalid;
	if (!auth_guard_task_transition_publish_exact_where(
			task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &cred_stamp,
			restore_state, expected_state, where))
		return false;

	if (cmpxchg(&task->auth_guard_lifecycle, old_lifecycle,
		    AUTH_GUARD_TASK_LIVE) != old_lifecycle) {
		auth_guard_fail(&task_authority_guard, where,
				"inexact constructor mutation", task);
		goto invalid;
	}
	if (!auth_guard_task_state_read(task, &state, where))
		goto invalid;
	state_hash = auth_guard_task_state_hash(
		task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (state_hash != expected_state ||
	    auth_guard_task_check_endpoints(task, where, true, false) !=
		    AUTH_GUARD_CHECK_VALID ||
	    !auth_guard_task_state_read(task, &state, where) ||
	    auth_guard_task_state_hash(
		    task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where,
		    false) != expected_state) {
		auth_guard_fail(&task_authority_guard, where,
				"changed constructor result", task);
		goto invalid;
	}
	auth_stamp = auth_guard_stamp_fresh(&task_authority_guard);
	auth_stamp.seal = auth_guard_task_state_hash(
		task, &state, auth_stamp.generation, auth_stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, false);
	auth_guard_stamp_publish_release(&task->auth_guard_stamp, &auth_stamp);
	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_task_state_read(task, &current_state, where) ||
	    !auth_guard_stamp_equal(&current_stamp, &auth_stamp) ||
	    auth_guard_task_state_hash(
		    task, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&task_authority_guard, where,
				"changed constructor publication", task);
		goto invalid;
	}
	return auth_guard_task_transition_close_where(
		task, AUTH_GUARD_TRANSITION_ANCHOR_CRED, &cred_stamp, where);

invalid:
	auth_guard_task_transition_quarantine(task);
	return false;
}

static bool auth_guard_task_transition_idle(struct task_struct *task)
{
	struct auth_guard_transition transition =
		auth_guard_task_transition(task);

	return !READ_ONCE(*transition.depth) &&
		auth_guard_transition_marker_empty(&transition);
}

static bool auth_guard_task_unsealed_state(struct task_struct *task)
{
	struct auth_guard_stamp stamp =
		auth_guard_stamp_load_acquire(&task->auth_guard_stamp);

	return auth_guard_stamp_empty(&stamp) &&
		auth_guard_task_transition_idle(task);
}

static bool auth_guard_task_terminal_reader_state(struct task_struct *task,
						   const char *where)
{
	struct auth_guard_stamp cred_stamp =
		auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	struct auth_guard_stamp stamp =
		auth_guard_stamp_load_acquire(&task->auth_guard_stamp);

	if (!auth_guard_stamp_empty(&cred_stamp) ||
	    !auth_guard_stamp_empty(&stamp) ||
	    !auth_guard_task_transition_reader_stable_where(task, where)) {
		auth_guard_fail(&task_authority_guard, where,
				"corrupt terminal task state", task);
		return false;
	}

	return true;
}

static bool auth_guard_task_terminal_unsealed_state(struct task_struct *task)
{
	struct auth_guard_stamp cred_stamp =
		auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	struct auth_guard_stamp stamp =
		auth_guard_stamp_load_acquire(&task->auth_guard_stamp);

	return auth_guard_stamp_empty(&cred_stamp) &&
		auth_guard_stamp_empty(&stamp) &&
		auth_guard_task_transition_idle(task);
}

static enum auth_guard_check_result
auth_guard_task_check_creds(struct task_struct *task,
			    const struct cred *expected_real_cred,
			    const char *where, bool reserved)
{
	const struct cred *cred;
	const struct cred *real_cred;
	struct user_namespace *cred_user_ns;
	struct user_namespace *real_user_ns;
	enum auth_guard_check_result result;

	real_cred = rcu_access_pointer(task->real_cred);
	if (!expected_real_cred)
		expected_real_cred = real_cred;

	if (reserved)
		result = cred_guard_check_task_cred_reserved_where(
			task, expected_real_cred, where);
	else
		result = cred_guard_check_task_cred_where(
			task, expected_real_cred, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;

	cred = rcu_access_pointer(task->cred);
	real_user_ns = real_cred ? READ_ONCE(real_cred->user_ns) : NULL;
	cred_user_ns = cred ? READ_ONCE(cred->user_ns) : NULL;
	if (!auth_guard_userns_boundary_check_where(real_user_ns, where))
		return AUTH_GUARD_CHECK_INVALID;
	if (cred_user_ns != real_user_ns &&
	    !auth_guard_userns_boundary_check_where(cred_user_ns, where))
		return AUTH_GUARD_CHECK_INVALID;

	return AUTH_GUARD_CHECK_VALID;
}

static enum auth_guard_check_result
auth_guard_task_check_endpoints(struct task_struct *task, const char *where,
				bool reserved, bool wait)
{
	struct nsproxy *nsproxy;
	enum auth_guard_check_result result;
#ifdef CONFIG_CGROUPS
	struct css_set *cset;
#endif

	result = auth_guard_task_check_creds(task, NULL, where, reserved);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
#ifdef CONFIG_CGROUPS
	cset = rcu_access_pointer(task->cgroups);
	if (cset && !auth_guard_css_set_check_where(cset, where))
		return AUTH_GUARD_CHECK_INVALID;
#endif
	nsproxy = READ_ONCE(task->nsproxy);
	if (!nsproxy)
		return AUTH_GUARD_CHECK_VALID;
	for (;;) {
		result = auth_guard_nsproxy_check_result(nsproxy, where, false);
		if (result != AUTH_GUARD_CHECK_BUSY || !wait)
			return result;
		cpu_relax();
	}
}

bool auth_guard_task_init_check_where(struct task_struct *task, const char *where)
{
	if (!auth_task_guard_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return false;
	}
	return auth_guard_task_check_endpoints(task, where, false, false) ==
		AUTH_GUARD_CHECK_VALID;
}

void auth_guard_task_mark_unpublished_where(struct task_struct *task,
				      const char *where)
{
	if (!auth_task_guard_enabled())
		return;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where,
				"missing unpublished task", task);
		return;
	}

	if (!auth_guard_task_first_seal_begin_where(task, where))
		return;
	auth_guard_stamp_clear(&task->cred_guard_stamp);
	auth_guard_stamp_clear(&task->auth_guard_stamp);
	WRITE_ONCE(task->auth_guard_lifecycle, AUTH_GUARD_TASK_UNPUBLISHED);
	auth_guard_task_first_seal_complete(task, true);
}

bool auth_guard_task_unpublished_where(struct task_struct *task, const char *where)
{
	u32 lifecycle;

	if (!auth_task_guard_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where,
				"missing unpublished task", task);
		return false;
	}

	lifecycle = READ_ONCE(task->auth_guard_lifecycle);
	if (lifecycle != AUTH_GUARD_TASK_UNPUBLISHED) {
		auth_guard_fail(&task_authority_guard, where,
				"not unpublished", task);
		return false;
	}
	if (!auth_guard_task_unsealed_state(task)) {
		auth_guard_fail(&task_authority_guard, where,
				"corrupt unpublished state", task);
		return false;
	}

	return true;
}

bool auth_guard_task_init_where(struct task_struct *task, const char *where)
{
	bool opened;

	if (!auth_guard_task_init_check_where(task, where))
		return false;
	if (auth_guard_task_is_sealed(task)) {
		opened = auth_guard_task_begin_transition_where(task, where);
		return opened && auth_guard_task_finish_transition_where(task, where);
	}
	return auth_guard_task_seal(task, where);
}

bool auth_guard_task_is_sealed(struct task_struct *task)
{
	struct auth_guard_stamp stamp;

	if (!auth_task_guard_enabled())
		return false;
	if (!task)
		return false;

	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	return auth_guard_stamp_valid(&stamp);
}

static enum auth_guard_check_result
auth_guard_task_check_reserved(struct task_struct *task, const char *where,
			       const struct cred *expected_real_cred,
			       bool check_expected_real_cred)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	struct nsproxy *nsproxy;
#ifdef CONFIG_CGROUPS
	struct css_set *cset;
#endif
	u64 computed;
	u32 lifecycle;
	bool exiting;
	enum auth_guard_check_result result;

	if (!auth_task_guard_enabled())
		return AUTH_GUARD_CHECK_VALID;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	result = AUTH_GUARD_CHECK_INVALID;
	lifecycle = READ_ONCE(task->auth_guard_lifecycle);
	if (lifecycle == AUTH_GUARD_TASK_EXIT_TEARDOWN) {
		if (!auth_guard_task_terminal_reader_state(task, where))
			goto out;
		result = AUTH_GUARD_CHECK_UNAVAILABLE;
		goto out;
	}
	exiting = lifecycle == AUTH_GUARD_TASK_EXITING;
	if (!exiting && lifecycle != AUTH_GUARD_TASK_LIVE) {
		auth_guard_fail(&task_authority_guard, where,
				"invalid checked lifecycle", task);
		goto out;
	}

	/* Acquire the release-published seal before protected metadata. */
	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_task_hash(task, stamp.generation, stamp.nonce, where,
				  &computed))
		goto out;
	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp) ||
	    !auth_guard_task_transition_reader_stable_where(task, where))
		goto out;
	if (!auth_guard_snapshot_valid(&task_authority_guard, where, task,
				       &stamp, computed))
		goto out;
	result = auth_guard_task_check_creds(
		task, check_expected_real_cred ? expected_real_cred : NULL, where,
		true);
	if (result != AUTH_GUARD_CHECK_VALID)
		goto out;

#ifdef CONFIG_CGROUPS
	cset = rcu_access_pointer(task->cgroups);
	if (cset && !auth_guard_css_set_check_where(cset, where))
		goto out;
#endif
	nsproxy = READ_ONCE(task->nsproxy);
	if (nsproxy) {
		result = auth_guard_nsproxy_check_result(nsproxy, where, false);
		if (result != AUTH_GUARD_CHECK_VALID)
			goto out;
		result = AUTH_GUARD_CHECK_INVALID;
	}
	/* The task snapshot must remain stable across endpoint checks. */
	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (auth_guard_stamp_equal(&current_stamp, &stamp) &&
	    auth_guard_task_transition_reader_stable_where(task, where)) {
		if (exiting)
			result = check_expected_real_cred ?
				AUTH_GUARD_CHECK_CREDENTIAL_ONLY :
				AUTH_GUARD_CHECK_UNAVAILABLE;
		else
			result = AUTH_GUARD_CHECK_VALID;
	}
out:
	return result;
}

static enum auth_guard_check_result
auth_guard_task_check_result(struct task_struct *task, const char *where,
			     const struct cred *expected_real_cred,
			     bool check_expected_real_cred,
			     bool retain_reservation)
{
	enum auth_guard_check_result result;

	if (!auth_task_guard_enabled())
		return AUTH_GUARD_CHECK_VALID;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	result = auth_guard_task_transition_reader_begin_where(task, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
	result = auth_guard_task_check_reserved(
		task, where, expected_real_cred, check_expected_real_cred);
	if (result != AUTH_GUARD_CHECK_VALID || !retain_reservation) {
		if (!auth_guard_task_transition_reader_end_where(task, where))
			result = AUTH_GUARD_CHECK_INVALID;
	}
	return result;
}

bool auth_guard_task_check_where(struct task_struct *task, const char *where)
{
	return auth_guard_task_check_status_where(task, where) ==
		AUTH_GUARD_CHECK_VALID;
}

enum auth_guard_check_result
auth_guard_task_check_status_where(struct task_struct *task, const char *where)
{
	return auth_guard_task_check_result(task, where, NULL, false, false);
}

enum auth_guard_check_result
auth_guard_task_snapshot_begin_where(struct task_struct *task, const char *where)
{
	return auth_guard_task_check_result(task, where, NULL, false, true);
}

bool auth_guard_task_snapshot_end_where(struct task_struct *task, const char *where)
{
	enum auth_guard_check_result result;

	if (!auth_task_guard_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing snapshot", task);
		return false;
	}

	result = auth_guard_task_check_reserved(task, where, NULL, false);
	return auth_guard_task_transition_reader_end_where(task, where) &&
		result == AUTH_GUARD_CHECK_VALID;
}

enum auth_guard_check_result
auth_guard_task_check_real_cred_where(struct task_struct *task,
				const struct cred *expected, const char *where)
{
	return auth_guard_task_check_result(task, where, expected, true, false);
}

/*
 * Callers without an error path wait only for a legitimate remote writer.
 * Invalid state is distinct from busy state so log mode does not either skip a
 * normal check or spin forever on a quarantined transition.
 *
 * Callers must not own the task transition or a lock needed by its writer.
 */
bool auth_guard_task_check_wait_where(struct task_struct *task, const char *where)
{
	return AUTH_GUARD_RETRY_BUSY(auth_guard_task_check_result(
		task, where, NULL, false, false)) == AUTH_GUARD_CHECK_VALID;
}

static enum auth_guard_check_result
auth_guard_task_validate_reservation(struct task_struct *task,
				     const char *where,
				     struct auth_guard_stamp *stamp, u64 *state)
{
	u32 lifecycle;

	lifecycle = READ_ONCE(task->auth_guard_lifecycle);
	if (lifecycle != AUTH_GUARD_TASK_LIVE &&
	    lifecycle != AUTH_GUARD_TASK_EXITING) {
		auth_guard_fail(&task_authority_guard, where,
				"invalid transition lifecycle", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	*stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	return auth_guard_task_capture_anchor_state(
		task, AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, stamp, where, state);
}

static enum auth_guard_check_result
auth_guard_task_begin_transition_once(struct task_struct *task, const char *where)
{
	if (!auth_task_guard_enabled())
		return auth_guard_task_begin_cred_transition_once(task, where);
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	return auth_guard_task_begin_transition_reserved(
		task, where, auth_guard_task_validate_reservation,
		AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY);
}

bool auth_guard_task_begin_transition_where(struct task_struct *task,
				      const char *where)
{
	return auth_guard_task_begin_transition_once(task, where) ==
		AUTH_GUARD_CHECK_VALID;
}

bool auth_guard_task_begin_transition_wait_where(struct task_struct *task,
					   const char *where)
{
	return AUTH_GUARD_RETRY_BUSY(
		auth_guard_task_begin_transition_once(task, where)) ==
		AUTH_GUARD_CHECK_VALID;
}

enum auth_guard_task_teardown_status
auth_guard_task_begin_teardown_transition_where(struct task_struct *task,
					  const char *where)
{
	struct auth_guard_stamp stamp;
	enum auth_guard_check_result result;
	u64 state;
	u32 lifecycle;

	if (!auth_task_guard_enabled())
		return AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where,
				"missing teardown transition", task);
		return AUTH_GUARD_TASK_TEARDOWN_FAILED;
	}

	lifecycle = READ_ONCE(task->auth_guard_lifecycle);
	/*
	 * Fork failure cleanup can dismantle an unpublished child before the
	 * first task seal.  After a terminal validation failure, normal exit
	 * cleanup must also detach the remaining endpoints without trusting them.
	 * Both cases must be explicit lifecycle states; a zeroed live task guard
	 * is corruption, not an implicit cleanup token.
	 */
	if (!auth_guard_task_is_sealed(task) &&
	    (lifecycle == AUTH_GUARD_TASK_UNPUBLISHED ||
	     lifecycle == AUTH_GUARD_TASK_EXIT_TEARDOWN)) {
		if ((lifecycle == AUTH_GUARD_TASK_UNPUBLISHED &&
		     !auth_guard_task_unsealed_state(task)) ||
		    (lifecycle == AUTH_GUARD_TASK_EXIT_TEARDOWN &&
		     !auth_guard_task_terminal_unsealed_state(task))) {
			auth_guard_fail(&task_authority_guard, where,
					"corrupt teardown state", task);
			return AUTH_GUARD_TASK_TEARDOWN_FAILED;
		}
		return lifecycle == AUTH_GUARD_TASK_UNPUBLISHED ?
			AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED :
			AUTH_GUARD_TASK_TEARDOWN_SKIP_UNTRUSTED;
	}
	if (!(READ_ONCE(task->flags) & PF_EXITING)) {
		auth_guard_fail(&task_authority_guard, where,
				"non-exiting teardown transition", task);
		return AUTH_GUARD_TASK_TEARDOWN_FAILED;
	}

retry_reservation:
	result = auth_guard_task_transition_reserve_teardown_where(task, where);
	if (result == AUTH_GUARD_CHECK_BUSY)
		return AUTH_GUARD_TASK_TEARDOWN_FAILED;
	if (result != AUTH_GUARD_CHECK_VALID)
		return AUTH_GUARD_TASK_TEARDOWN_OPENED;

	result = auth_guard_task_validate_reservation(task, where, &stamp, &state);
	if (result == AUTH_GUARD_CHECK_BUSY) {
		auth_guard_task_transition_cancel_reservation(task, where);
		cpu_relax();
		goto retry_reservation;
	}
	if (result != AUTH_GUARD_CHECK_VALID) {
		auth_guard_task_transition_quarantine(task);
		return AUTH_GUARD_TASK_TEARDOWN_OPENED;
	}
	if (!auth_guard_task_transition_publish_exact_where(
			task, AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp,
			state, state, where))
		return AUTH_GUARD_TASK_TEARDOWN_OPENED;

	return AUTH_GUARD_TASK_TEARDOWN_OPENED;
}

bool auth_guard_task_transition_open_where(struct task_struct *task,
				     const char *where)
{
	struct auth_guard_stamp stamp;

	if (!auth_task_guard_enabled())
		return auth_guard_task_cred_transition_open_where(task, where);
	if (!task) {
		auth_guard_fail(&task_authority_guard, where,
				"missing transition object", task);
		return false;
	}
	if (!auth_guard_task_is_sealed(task)) {
		auth_guard_fail(&task_authority_guard, where,
				"unsealed transition", task);
		return false;
	}

	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	return auth_guard_task_transition_verify_where(
		task, AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp, where);
}

bool auth_guard_task_validate_teardown_where(struct task_struct *task,
				       enum auth_guard_task_teardown_status status,
				       const char *where)
{
	struct auth_guard_stamp stamp;

	if (status == AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED ||
	    status == AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED)
		return true;
	if (status != AUTH_GUARD_TASK_TEARDOWN_OPENED)
		return false;
	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (auth_guard_task_transition_verify_where(
			task, AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp, where))
		return true;
	auth_guard_task_transition_quarantine(task);
	return false;
}

bool auth_guard_task_finish_transition_where(struct task_struct *task,
				       const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp new_stamp;
	struct auth_guard_stamp old_stamp;
	u64 expected_state;
	u64 state_hash;

	if (!auth_task_guard_enabled())
		return auth_guard_task_finish_cred_transition_where(task, where);
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing", task);
		return false;
	}
	if (!auth_guard_task_is_sealed(task)) {
		auth_guard_fail(&task_authority_guard, where,
				"unsealed transition", task);
		return false;
	}

	transition = auth_guard_task_transition(task);
	old_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!__auth_guard_transition_verify(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &old_stamp, false,
		    NULL, &expected_state))
		goto endpoint_failed;

	if (!auth_guard_task_state_read(task, &state, where))
		goto endpoint_failed;
	state_hash = auth_guard_task_state_hash(
		task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (state_hash != expected_state) {
		auth_guard_fail(&task_authority_guard, where,
				"unexpected transition result", task);
		goto endpoint_failed;
	}
	if (auth_guard_task_check_endpoints(task, where, true, true) !=
	    AUTH_GUARD_CHECK_VALID)
		goto endpoint_failed;

	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_task_state_read(task, &current_state, where) ||
	    !auth_guard_stamp_equal(&current_stamp, &old_stamp) ||
	    auth_guard_task_state_hash(
		    task, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&task_authority_guard, where,
				"changed transition authority", task);
		goto endpoint_failed;
	}
	state = current_state;
	new_stamp = auth_guard_stamp_fresh(&task_authority_guard);
	new_stamp.seal = auth_guard_task_state_hash(
		task, &state, new_stamp.generation, new_stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, false);
	auth_guard_stamp_publish_release(&task->auth_guard_stamp, &new_stamp);
	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_task_state_read(task, &current_state, where) ||
	    !auth_guard_stamp_equal(&current_stamp, &new_stamp) ||
	    auth_guard_task_state_hash(
		    task, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    expected_state) {
		auth_guard_fail(&task_authority_guard, where,
				"changed transition publication", task);
		goto endpoint_failed;
	}
	return auth_guard_transition_close(
		&task_transition_guard, where, &transition,
		AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &old_stamp);

endpoint_failed:
	/*
	 * Quarantine the transition marker.  The task now names a rejected
	 * endpoint, so log mode must neither wait on an apparently active writer
	 * nor make the mutated tuple look sealed.
	 */
	auth_guard_task_transition_quarantine(task);
	return false;
}

void auth_guard_task_abort_transition_where(struct task_struct *task,
					      const char *where)
{
	struct auth_guard_task_state current_state;
	struct auth_guard_task_state state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	u64 computed;
	u64 restore_state;
	u64 state_hash;

	if (!auth_task_guard_enabled())
		return (void)auth_guard_task_abort_cred_transition_where(task, where);
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing abort", task);
		return;
	}
	if (!auth_guard_task_is_sealed(task)) {
		auth_guard_fail(&task_authority_guard, where, "unsealed abort",
				task);
		return;
	}

	transition = auth_guard_task_transition(task);
	stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!__auth_guard_transition_verify(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp, true,
		    &restore_state, NULL))
		goto quarantine;

	if (!auth_guard_task_state_read(task, &state, where))
		goto quarantine;
	state_hash = auth_guard_task_state_hash(
		task, &state, 0, 0, AUTH_GUARD_SEMANTIC_EXPECTATION, where, false);
	if (state_hash != restore_state) {
		auth_guard_fail(&task_authority_guard, where,
				"unexpected abort state", task);
		goto quarantine;
	}
	computed = auth_guard_task_state_hash(
		task, &state, stamp.generation, stamp.nonce,
		AUTH_GUARD_SEMANTIC_PUBLICATION, where, true);
	if (!auth_guard_snapshot_valid(&task_authority_guard, where, task,
				       &stamp, computed) ||
	    auth_guard_task_check_endpoints(task, where, true, true) !=
		    AUTH_GUARD_CHECK_VALID)
		goto quarantine;
	current_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	if (!auth_guard_task_state_read(task, &current_state, where) ||
	    !auth_guard_stamp_equal(&current_stamp, &stamp) ||
	    auth_guard_task_state_hash(
		    task, &current_state, 0, 0,
		    AUTH_GUARD_SEMANTIC_EXPECTATION, where, false) !=
		    restore_state) {
		auth_guard_fail(&task_authority_guard, where,
				"changed abort state", task);
		goto quarantine;
	}
	if (!auth_guard_transition_abort_close(
		    &task_transition_guard, where, &transition,
		    AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &stamp))
		goto quarantine;
	return;

quarantine:
	auth_guard_task_transition_quarantine(task);
}

static bool auth_guard_task_detach_transition_where(struct task_struct *task,
					      const char *where)
{
	struct auth_guard_task_state task_state;
	struct auth_guard_transition transition;
	struct auth_guard_stamp cred_stamp;
	struct auth_guard_stamp old_stamp;
	u64 expected_state;
	u64 state_hash;
	u32 state;
	bool valid = true;

	if (!auth_task_guard_enabled())
		return true;
	if (!task) {
		auth_guard_fail(&task_authority_guard, where, "missing detach",
				task);
		return false;
	}
	old_stamp = auth_guard_stamp_load_acquire(&task->auth_guard_stamp);
	/* Pair with release publication of writer exclusion or quarantine. */
	state = smp_load_acquire(&task->auth_guard_transition.depth);
	if (state == AUTH_GUARD_TRANSITION_OPEN) {
		transition = auth_guard_task_transition(task);
		valid = __auth_guard_transition_verify(
			&task_transition_guard, where, &transition,
			AUTH_GUARD_TRANSITION_ANCHOR_AUTHORITY, &old_stamp,
			false, NULL, &expected_state);
		if (valid) {
			valid = auth_guard_task_state_read(task, &task_state, where);
			state_hash = valid ?
				auth_guard_task_state_hash(
					task, &task_state, 0, 0,
					AUTH_GUARD_SEMANTIC_EXPECTATION,
					where, false) :
				0;
			if (state_hash != expected_state) {
				auth_guard_fail(&task_authority_guard, where,
						"unexpected terminal detach state",
						task);
				auth_guard_task_transition_quarantine(task);
				valid = false;
			}
		}
	} else if (state == AUTH_GUARD_TRANSITION_QUARANTINED) {
		/* Log-mode validation failed while terminal exclusion was held. */
		valid = false;
	} else {
		auth_guard_fail(&task_authority_guard, where,
				"invalid detach reservation", task);
		valid = false;
	}

	cred_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (valid && !auth_guard_stamp_empty(&cred_stamp)) {
		auth_guard_fail(&task_authority_guard, where,
				"attached credentials during terminal detach", task);
		valid = false;
	}
	if (!valid)
		cred_guard_task_invalidate_reserved_where(task, where);

	auth_guard_stamp_clear(&task->auth_guard_stamp);
	WRITE_ONCE(task->auth_guard_lifecycle,
		   AUTH_GUARD_TASK_EXIT_TEARDOWN);
	if (!auth_guard_task_transition_terminal_close_where(task, where))
		valid = false;
	return valid;
}

bool auth_guard_task_complete_teardown_where(struct task_struct *task,
				       enum auth_guard_task_teardown_status status,
				       bool old_valid, bool exact, bool final,
				       const char *where)
{
	if (status == AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED ||
	    status == AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED) {
		if (!exact && auth_task_guard_enabled())
			auth_guard_fail(&task_authority_guard, where,
					"changed unpublished endpoint", task);
		return exact;
	}
	if (status != AUTH_GUARD_TASK_TEARDOWN_OPENED)
		return false;

	if (!exact) {
		auth_guard_fail(&task_authority_guard, where,
				"changed teardown endpoint", task);
		auth_guard_task_transition_quarantine(task);
	}

	if (old_valid && exact) {
		if (final)
			return auth_guard_task_detach_transition_where(task, where);
		if (auth_guard_task_finish_transition_where(task, where))
			return true;
	}

	/* Quarantine is terminal: clear the task seal and leak detached endpoints. */
	(void)auth_guard_task_detach_transition_where(task, where);
	return false;
}

static void auth_guard_task_detach_pending_unchecked(
	struct task_struct *task,
	struct pending_child_ns_request_payloads *payloads)
{
	*payloads = (struct pending_child_ns_request_payloads) {
		.syslog = {
			.enabled = READ_ONCE(task->syslog_ns_for_child),
			.name = xchg(&task->syslog_ns_for_child_name, NULL),
			.name_len =
				READ_ONCE(task->syslog_ns_for_child_name_len),
		},
		.tracing = READ_ONCE(task->tracing_ns_for_child),
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
		.lsm = {
			.enabled = READ_ONCE(task->lsm_ns_for_child),
			.lsmid = READ_ONCE(task->lsm_ns_for_child_lsmid),
			.ctx = xchg(&task->lsm_ns_for_child_ctx, NULL),
			.ctx_len = READ_ONCE(task->lsm_ns_for_child_ctx_len),
		},
#else
		.lsm.lsmid = LSM_ID_UNDEF,
#endif
	};
	WRITE_ONCE(task->syslog_ns_for_child, false);
	WRITE_ONCE(task->syslog_ns_for_child_name_len, 0);
	WRITE_ONCE(task->tracing_ns_for_child, false);
#ifdef CONFIG_SECURITY_LSM_NAMESPACE
	WRITE_ONCE(task->lsm_ns_for_child, false);
	WRITE_ONCE(task->lsm_ns_for_child_lsmid, LSM_ID_UNDEF);
	WRITE_ONCE(task->lsm_ns_for_child_ctx_len, 0);
#endif
}

void auth_guard_task_exit_where(struct task_struct *task, const char *where)
{
	struct pending_child_ns_request_payloads payloads;
	enum auth_guard_task_teardown_status status;
	enum auth_guard_mutation_result mutation;
	bool old_valid;
	bool exact;
	bool trusted;

	/*
	 * do_exit() calls this immediately after exit_signals(): PF_EXITING is
	 * visible, cgroup migration has dropped its thread-group exclusion, and
	 * seccomp TSYNC has dropped siglock.  Claim terminal exclusion here, detach
	 * pending payload ownership, and publish a sealed EXITING tuple before the
	 * subsystem endpoint teardown begins.
	 */
	status = auth_guard_task_begin_teardown_transition_where(task, where);
	old_valid = auth_guard_task_validate_teardown_where(task, status, where);
	exact = true;
	if (status == AUTH_GUARD_TASK_TEARDOWN_OPENED && old_valid) {
		consume_pending_child_ns_request_in_transition_where(
			task, true, &payloads, where);
		mutation =
			auth_guard_task_set_exiting_in_transition_where(task, where);
		AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
		exact =
			auth_guard_task_validate_transition_result_where(task, where);
	} else {
		auth_guard_task_detach_pending_unchecked(task, &payloads);
		exact = status == AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED ||
			status == AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED;
	}
	trusted = auth_guard_task_complete_teardown_where(task, status,
						    old_valid, exact, false,
						    where);
	if (!trusted && status == AUTH_GUARD_TASK_TEARDOWN_OPENED)
		WARN_ON_ONCE(1);
	if (trusted)
		release_pending_child_ns_request_payloads(&payloads);
	else if (status == AUTH_GUARD_TASK_TEARDOWN_FAILED)
		WARN_ON_ONCE(1);
}

bool auth_guard_current_where(const char *where)
{
	return auth_guard_task_check_where(current, where);
}

void __init auth_guard_enable(void)
{
	auth_guard_init_domain(&task_authority_guard);
	auth_guard_init_domain(&userns_boundary_guard);
	auth_guard_init_domain(&nsproxy_authority_guard);
#ifdef CONFIG_CGROUPS
	auth_guard_init_domain(&css_set_authority_guard);
	auth_guard_init_domain(&cgroup_ns_root_guard);
#endif
	auth_userns_boundary_guard_active = true;
	BUG_ON(!auth_guard_userns_boundary_init(&init_user_ns));
	auth_nsproxy_guard_active = true;
	BUG_ON(!auth_guard_nsproxy_init(&init_nsproxy));
	auth_task_guard_active = true;
	BUG_ON(!auth_guard_task_init(current));
}
#endif /* CONFIG_AUTH_GUARD */

#ifdef CONFIG_AUTH_GUARD
static enum auth_guard_mutation_result auth_guard_task_complete_mutation(
	struct task_struct *task, enum auth_guard_mutation_result result,
	const char *where)
{
	if (result == AUTH_GUARD_MUTATION_REJECTED)
		auth_guard_task_abort_transition_where(task, where);
	else if (result == AUTH_GUARD_MUTATION_APPLIED &&
		 !auth_guard_task_finish_transition_where(task, where))
		result = AUTH_GUARD_MUTATION_QUARANTINED;
	return result;
}

#define AUTH_GUARD_TASK_REQUEST_REPLACE(                                \
		_task, _replacement, _authenticated_old, _require_replacement, \
		_transition, _where)                                           \
({                                                                       \
	struct task_struct *__ag_task = (_task);                              \
	__auto_type __ag_replacement = (_replacement);                        \
	__auto_type __ag_authenticated_old = (_authenticated_old);            \
	bool __ag_require_replacement = (_require_replacement);               \
	const char *__ag_where = (_where);                                    \
	enum auth_guard_mutation_result __ag_result =                         \
		AUTH_GUARD_MUTATION_REJECTED;                                  \
	if (__ag_task && __ag_authenticated_old &&                            \
	    (!__ag_require_replacement || __ag_replacement) &&                \
	    auth_guard_task_begin_transition_where(__ag_task, __ag_where)) {  \
		__ag_result = (_transition)(__ag_task, __ag_replacement,        \
					    __ag_authenticated_old, __ag_where);       \
		__ag_result = auth_guard_task_complete_mutation(                 \
			__ag_task, __ag_result, __ag_where);                       \
	}                                                                    \
	__ag_result;                                                         \
})
#endif

enum auth_guard_mutation_result auth_guard_task_replace_files_where(
	struct task_struct *task, struct files_struct *replacement,
	struct files_struct **authenticated_old, const char *where)
{
#ifdef CONFIG_AUTH_GUARD
	enum auth_guard_mutation_result result;

	if (!task || !authenticated_old ||
	    !auth_guard_task_begin_transition_where(task, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	task_lock(task);
	result = auth_guard_task_replace_files_in_transition_where(
		task, replacement, authenticated_old, where);
	result = auth_guard_task_complete_mutation(task, result, where);
	task_unlock(task);
	return result;
#else
	return __AUTH_GUARD_NATIVE_FILES(task, replacement, authenticated_old,
					 where);
#endif
}

enum auth_guard_mutation_result auth_guard_task_set_no_new_privs_where(
	struct task_struct *task, const char *where)
{
#ifdef CONFIG_AUTH_GUARD
	enum auth_guard_mutation_result result;
	bool authenticated_old;

	if (!task || !auth_guard_task_begin_transition_where(task, where))
		return AUTH_GUARD_MUTATION_REJECTED;
	result = auth_guard_task_transition_set_no_new_privs_where(
		task, &authenticated_old, where);
	return auth_guard_task_complete_mutation(task, result, where);
#else
	return __AUTH_GUARD_NATIVE_NO_NEW_PRIVS(task, where);
#endif
}

enum auth_guard_mutation_result auth_guard_task_replace_syslog_request_where(
	struct task_struct *task,
	const struct auth_guard_task_syslog_request *replacement,
	struct auth_guard_task_syslog_request *authenticated_old,
	const char *where)
{
#ifdef CONFIG_AUTH_GUARD
	return AUTH_GUARD_TASK_REQUEST_REPLACE(
		task, replacement, authenticated_old, true,
		auth_guard_task_replace_syslog_request_in_transition_where, where);
#else
	return __AUTH_GUARD_NATIVE_SYSLOG_REQUEST(task, replacement,
						  authenticated_old, where);
#endif
}

enum auth_guard_mutation_result auth_guard_task_replace_tracing_request_where(
	struct task_struct *task, bool replacement, bool *authenticated_old,
	const char *where)
{
#ifdef CONFIG_AUTH_GUARD
	return AUTH_GUARD_TASK_REQUEST_REPLACE(
		task, replacement, authenticated_old, false,
		auth_guard_task_replace_tracing_request_in_transition_where, where);
#else
	return __AUTH_GUARD_NATIVE_TRACING_REQUEST(task, replacement,
						   authenticated_old, where);
#endif
}

#ifdef CONFIG_SECURITY_LSM_NAMESPACE
enum auth_guard_mutation_result auth_guard_task_replace_lsm_request_where(
	struct task_struct *task,
	const struct auth_guard_task_lsm_request *replacement,
	struct auth_guard_task_lsm_request *authenticated_old,
	const char *where)
{
#ifdef CONFIG_AUTH_GUARD
	return AUTH_GUARD_TASK_REQUEST_REPLACE(
		task, replacement, authenticated_old, true,
		auth_guard_task_replace_lsm_request_in_transition_where, where);
#else
	return __AUTH_GUARD_NATIVE_LSM_REQUEST(task, replacement,
					      authenticated_old, where);
#endif
}
#endif

#ifdef CONFIG_AUTH_GUARD
#undef AUTH_GUARD_TASK_REQUEST_REPLACE
#endif

#ifdef CONFIG_AUTH_GUARD_TEST
#define AUTH_GUARD_TEST_MAX_CMD	64
#define AUTH_GUARD_TEST_TASK_RECHECK_WHERE \
	AUTH_GUARD_TEST_CONTEXT("task_recheck")
#define AUTH_GUARD_TEST_NSPROXY_RECHECK_WHERE \
	AUTH_GUARD_TEST_CONTEXT("nsproxy_recheck")

struct auth_guard_test_case {
	const char *where;
	int (*run)(const struct auth_guard_test_case *test);
	union {
		enum auth_guard_test_task_fault task;
		enum auth_guard_test_nsproxy_fault nsproxy;
#ifdef CONFIG_CGROUPS
		enum auth_guard_test_css_set_fault css_set;
#endif
	} fault;
};

#ifdef CONFIG_CGROUPS
static int
auth_guard_test_corrupt_cgroups(const struct auth_guard_test_case *test)
{
	const struct task_struct *pending;
	bool detected;
	int ret = 0;

	mutex_lock(&auth_guard_test_fault_lock);
	if (cmpxchg(&auth_guard_test_cgroups_task, NULL, current)) {
		ret = -EBUSY;
		goto out;
	}

	detected = !auth_guard_current_where(test->where);
	pending = xchg(&auth_guard_test_cgroups_task, NULL);
	if (!detected || pending) {
		ret = -EIO;
		goto out;
	}
	if (!auth_guard_current_where(AUTH_GUARD_TEST_CONTEXT("cgroups_recheck")))
		ret = -EIO;

out:
	mutex_unlock(&auth_guard_test_fault_lock);
	return ret;
}

static int
auth_guard_test_corrupt_cgroup_ns_root(const struct auth_guard_test_case *test)
{
	const struct cgroup_namespace *pending;
	const char *recheck_where =
		AUTH_GUARD_TEST_CONTEXT("nsproxy_cgroup_root_recheck");
	struct nsproxy *nsproxy = READ_ONCE(current->nsproxy);
	struct cgroup_namespace *ns;
	bool detected;
	int ret = 0;

	if (!nsproxy)
		return -EINVAL;
	ns = READ_ONCE(nsproxy->cgroup_ns);
	if (!ns)
		return -EINVAL;

	mutex_lock(&auth_guard_test_fault_lock);
	if (cmpxchg(&auth_guard_test_cgroup_ns_root, NULL, ns)) {
		ret = -EBUSY;
		goto out;
	}

	detected = !auth_guard_cgroup_ns_root_check_where(ns, test->where);
	pending = xchg(&auth_guard_test_cgroup_ns_root, NULL);
	if (!detected || pending) {
		ret = -EIO;
		goto out;
	}
	if (!auth_guard_cgroup_ns_root_check_where(ns, recheck_where))
		ret = -EIO;

out:
	mutex_unlock(&auth_guard_test_fault_lock);
	return ret;
}

static int
auth_guard_test_corrupt_css_set(const struct auth_guard_test_case *test)
{
	const struct css_set *pending;
	struct css_set *cset = rcu_access_pointer(current->cgroups);
	enum auth_guard_test_css_set_fault fault = test->fault.css_set;
	bool detected;
	int subsys_id = -1;
	int ret = 0;
	int i;

	if (!cset)
		return -EINVAL;
	switch (fault) {
	case AUTH_GUARD_TEST_CSS_SET_DFL:
	case AUTH_GUARD_TEST_CSS_SET_DOM:
		break;
	case AUTH_GUARD_TEST_CSS_SET_SUBSYS:
		for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
			if (READ_ONCE(cset->subsys[i])) {
				subsys_id = i;
				break;
			}
		}
		if (subsys_id < 0)
			return -EINVAL;
		break;
	case AUTH_GUARD_TEST_CSS_SET_NONE:
	default:
		return -EINVAL;
	}

	mutex_lock(&auth_guard_test_fault_lock);
	/* Acquire the target published after its paired fault selector. */
	if (smp_load_acquire(&auth_guard_test_css_set)) {
		ret = -EBUSY;
		goto out;
	}
	WRITE_ONCE(auth_guard_test_css_set_fault, fault);
	WRITE_ONCE(auth_guard_test_css_set_subsys_id, subsys_id);
	/* Publish the paired fault selector before exposing the target. */
	smp_store_release(&auth_guard_test_css_set, cset);

	detected = !auth_guard_css_set_check_where(cset, test->where);
	pending = xchg(&auth_guard_test_css_set, NULL);
	if (!detected || pending) {
		ret = -EIO;
		goto clear;
	}
	if (!auth_guard_css_set_check_where(cset,
				      AUTH_GUARD_TEST_CONTEXT("css_set_recheck")))
		ret = -EIO;

clear:
	WRITE_ONCE(auth_guard_test_css_set_fault,
		   AUTH_GUARD_TEST_CSS_SET_NONE);
	WRITE_ONCE(auth_guard_test_css_set_subsys_id, -1);
out:
	mutex_unlock(&auth_guard_test_fault_lock);
	return ret;
}
#endif

static int
auth_guard_test_inject_task_fault(const struct auth_guard_test_case *test)
{
	const struct task_struct *pending;
	enum auth_guard_test_task_fault fault = test->fault.task;
	bool detected;
	int ret = 0;

	if (fault <= AUTH_GUARD_TEST_TASK_NONE ||
	    fault >= AUTH_GUARD_TEST_TASK_COUNT)
		return -EINVAL;
#if defined(CONFIG_SECCOMP) && defined(CONFIG_SECCOMP_FILTER)
	if (fault == AUTH_GUARD_TEST_TASK_SECCOMP_FILTER &&
	    !READ_ONCE(current->seccomp.filter))
		return -EINVAL;
#endif

	mutex_lock(&auth_guard_test_fault_lock);
	/* Pair with release publication before inspecting selector state. */
	if (smp_load_acquire(&auth_guard_test_task_fault_target)) {
		ret = -EBUSY;
		goto out;
	}
	WRITE_ONCE(auth_guard_test_task_fault, fault);
	WRITE_ONCE(auth_guard_test_task_fault_where, test->where);
	/* Publish the paired selector and exact boundary before the target. */
	smp_store_release(&auth_guard_test_task_fault_target, current);

	detected = !auth_guard_current_where(test->where);
	pending = xchg(&auth_guard_test_task_fault_target, NULL);
	if (!detected || pending) {
		ret = -EIO;
		goto clear;
	}
	if (!auth_guard_current_where(AUTH_GUARD_TEST_TASK_RECHECK_WHERE))
		ret = -EIO;

clear:
	WRITE_ONCE(auth_guard_test_task_fault_where, NULL);
	WRITE_ONCE(auth_guard_test_task_fault, AUTH_GUARD_TEST_TASK_NONE);
out:
	mutex_unlock(&auth_guard_test_fault_lock);
	return ret;
}

static int
auth_guard_test_inject_nsproxy_fault(const struct auth_guard_test_case *test)
{
	const struct task_struct *pending;
	enum auth_guard_test_nsproxy_fault fault = test->fault.nsproxy;
	struct nsproxy *nsproxy = READ_ONCE(current->nsproxy);
	bool detected;
	int ret = 0;

	if (!nsproxy || fault <= AUTH_GUARD_TEST_NSPROXY_NONE ||
	    fault >= AUTH_GUARD_TEST_NSPROXY_COUNT)
		return -EINVAL;
	if (fault == AUTH_GUARD_TEST_NSPROXY_SYSLOG &&
	    !READ_ONCE(nsproxy->syslog_ns))
		return -EINVAL;
#ifdef CONFIG_TRACING_NS
	if (fault == AUTH_GUARD_TEST_NSPROXY_TRACING &&
	    !READ_ONCE(nsproxy->tracing_ns))
		return -EINVAL;
#endif

	mutex_lock(&auth_guard_test_fault_lock);
	/* Pair with release publication before inspecting selector state. */
	if (smp_load_acquire(&auth_guard_test_nsproxy_fault_task)) {
		ret = -EBUSY;
		goto out;
	}
	WRITE_ONCE(auth_guard_test_nsproxy_fault, fault);
	WRITE_ONCE(auth_guard_test_nsproxy_fault_where, test->where);
	WRITE_ONCE(auth_guard_test_nsproxy_fault_target, nsproxy);
	/* Publish the paired selector, boundary, and nsproxy before current. */
	smp_store_release(&auth_guard_test_nsproxy_fault_task, current);

	detected = !auth_guard_nsproxy_check_where(nsproxy, test->where);
	pending = xchg(&auth_guard_test_nsproxy_fault_task, NULL);
	if (!detected || pending) {
		ret = -EIO;
		goto clear;
	}
	if (!auth_guard_nsproxy_check_where(nsproxy,
				      AUTH_GUARD_TEST_NSPROXY_RECHECK_WHERE))
		ret = -EIO;

clear:
	WRITE_ONCE(auth_guard_test_nsproxy_fault_target, NULL);
	WRITE_ONCE(auth_guard_test_nsproxy_fault_where, NULL);
	WRITE_ONCE(auth_guard_test_nsproxy_fault,
		   AUTH_GUARD_TEST_NSPROXY_NONE);
out:
	mutex_unlock(&auth_guard_test_fault_lock);
	return ret;
}

#define AUTH_GUARD_TEST_CASE(_command, _run) \
	{ .where = AUTH_GUARD_TEST_CONTEXT(#_command), .run = (_run) }
#define AUTH_GUARD_TEST_TASK_CASE(_command, _fault) \
	{ .where = AUTH_GUARD_TEST_CONTEXT(#_command), \
	  .run = auth_guard_test_inject_task_fault, \
	  .fault.task = AUTH_GUARD_TEST_TASK_##_fault }
#define AUTH_GUARD_TEST_NSPROXY_CASE(_command, _fault) \
	{ .where = AUTH_GUARD_TEST_CONTEXT(#_command), \
	  .run = auth_guard_test_inject_nsproxy_fault, \
	  .fault.nsproxy = AUTH_GUARD_TEST_NSPROXY_##_fault }
#ifdef CONFIG_CGROUPS
#define AUTH_GUARD_TEST_CSS_SET_CASE(_command, _fault) \
	{ .where = AUTH_GUARD_TEST_CONTEXT(#_command), \
	  .run = auth_guard_test_corrupt_css_set, \
	  .fault.css_set = AUTH_GUARD_TEST_CSS_SET_##_fault }
#endif

static const struct auth_guard_test_case auth_guard_test_cases[] = {
	AUTH_GUARD_TEST_TASK_CASE(cred_edge, CRED),
	AUTH_GUARD_TEST_TASK_CASE(real_cred_edge, REAL_CRED),
	AUTH_GUARD_TEST_TASK_CASE(nsproxy, NSPROXY),
	AUTH_GUARD_TEST_NSPROXY_CASE(nsproxy_mnt, MNT),
#ifdef CONFIG_CGROUPS
	AUTH_GUARD_TEST_CASE(nsproxy_cgroup_root,
			     auth_guard_test_corrupt_cgroup_ns_root),
#endif
	AUTH_GUARD_TEST_NSPROXY_CASE(nsproxy_syslog, SYSLOG),
#ifdef CONFIG_TRACING_NS
	AUTH_GUARD_TEST_NSPROXY_CASE(nsproxy_tracing, TRACING),
#endif
#ifdef CONFIG_CGROUPS
	AUTH_GUARD_TEST_CASE(cgroups, auth_guard_test_corrupt_cgroups),
	AUTH_GUARD_TEST_CSS_SET_CASE(css_set_dfl, DFL),
	AUTH_GUARD_TEST_CSS_SET_CASE(css_set_dom, DOM),
	AUTH_GUARD_TEST_CSS_SET_CASE(css_set_subsys, SUBSYS),
#endif
#ifdef CONFIG_SECCOMP
	AUTH_GUARD_TEST_TASK_CASE(seccomp, SECCOMP_MODE),
#ifdef CONFIG_SECCOMP_FILTER
	AUTH_GUARD_TEST_TASK_CASE(seccomp_filter_count, SECCOMP_FILTER_COUNT),
	AUTH_GUARD_TEST_TASK_CASE(seccomp_filter, SECCOMP_FILTER),
#endif
#endif
	AUTH_GUARD_TEST_TASK_CASE(files, FILES),
};

#ifdef CONFIG_CGROUPS
#undef AUTH_GUARD_TEST_CSS_SET_CASE
#endif
#undef AUTH_GUARD_TEST_NSPROXY_CASE
#undef AUTH_GUARD_TEST_TASK_CASE
#undef AUTH_GUARD_TEST_CASE

static int auth_guard_test_dispatch(const char *what)
{
	const struct auth_guard_test_case *test;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(auth_guard_test_cases); i++) {
		test = &auth_guard_test_cases[i];
		if (!strcmp(what, AUTH_GUARD_TEST_COMMAND(test->where)))
			return test->run(test);
	}

	return -EINVAL;
}

static int auth_guard_test_corrupt_current(const char *what)
{
	int ret;

	ret = cred_guard_test_corrupt_current(what);
	if (ret != -EINVAL)
		return ret;

	ret = selinux_cred_guard_test_corrupt_current(what);
	if (ret != -EINVAL)
		return ret;

	return auth_guard_test_dispatch(what);
}

static ssize_t auth_guard_test_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char cmd[AUTH_GUARD_TEST_MAX_CMD];
	size_t len;
	int ret;

	if (!count)
		return 0;
	if (count >= sizeof(cmd))
		return -E2BIG;

	len = min(count, sizeof(cmd) - 1);
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';

	ret = auth_guard_test_corrupt_current(strim(cmd));
	if (ret)
		return ret;

	return count;
}

static const struct file_operations auth_guard_test_fops = {
	.write = auth_guard_test_write,
	.llseek = noop_llseek,
};

static int __init auth_guard_test_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("auth_guard", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	debugfs_create_file("corrupt_current", 0200, dir, NULL,
			    &auth_guard_test_fops);
	return 0;
}
late_initcall(auth_guard_test_init);
#endif /* CONFIG_AUTH_GUARD_TEST */
