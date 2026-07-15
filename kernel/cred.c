// SPDX-License-Identifier: GPL-2.0-or-later
/* Task credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "CRED: " fmt

#include <linux/auth_guard.h>
#include <linux/cache.h>
#include <linux/export.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/init_task.h>
#include <linux/security.h>
#include <linux/lsm_namespace.h>
#include <linux/binfmts.h>
#include <linux/cn_proc.h>
#include <linux/uidgid.h>

#if 0
#define kdebug(FMT, ...)						\
	printk("[%-5.5s%5u] " FMT "\n",					\
	       current->comm, current->pid, ##__VA_ARGS__)
#else
#define kdebug(FMT, ...)						\
do {									\
	if (0)								\
		no_printk("[%-5.5s%5u] " FMT "\n",			\
			  current->comm, current->pid, ##__VA_ARGS__);	\
} while (0)
#endif

static struct kmem_cache *cred_jar;
static bool cred_guard_verify_current_task(const char *where);

struct cred_guard_task_transition {
	struct task_struct *task;
	const struct cred *old_real;
	const struct cred *old_subj;
	const struct cred *new_real;
	const struct cred *new_subj;
	struct auth_guard_stamp old_stamp;
	struct auth_guard_stamp new_stamp;
	bool outer_transition;
	bool coordinator_open;
};

struct cred_guard_task_teardown {
	struct task_struct *task;
	const struct cred *old_real;
	const struct cred *old_subj;
	struct auth_guard_stamp stamp;
	bool coordinator_owned;
	bool old_valid;
};

#ifdef CONFIG_CRED_GUARD
static struct auth_guard_domain cred_guard_object_domain __ro_after_init =
	AUTH_GUARD_DOMAIN("cred_object");
static struct auth_guard_domain cred_guard_prepared_domain __ro_after_init =
	AUTH_GUARD_DOMAIN("cred_prepared");
static struct auth_guard_domain cred_guard_task_domain __ro_after_init =
	AUTH_GUARD_DOMAIN("cred_task");
static bool cred_guard_active __ro_after_init;

struct cred_guard_digest {
	u64 cred;
	u64 generation;
	u64 nonce;
	u64 prepared_generation;
	u64 prepared_nonce;
	u64 prepared_source_cred;
	u64 prepared_source_generation;
	u64 prepared_source_nonce;
	u64 prepared_source_seal;
	u64 prepared_seal;
	u64 uid;
	u64 gid;
	u64 suid;
	u64 sgid;
	u64 euid;
	u64 egid;
	u64 fsuid;
	u64 fsgid;
	u64 securebits;
	u64 cap_inheritable;
	u64 cap_permitted;
	u64 cap_effective;
	u64 cap_bset;
	u64 cap_ambient;
	u64 user;
	u64 user_ns;
	u64 ucounts;
	u64 group_info;
#ifdef CONFIG_KEYS
	u64 jit_keyring;
	u64 session_keyring;
	u64 process_keyring;
	u64 thread_keyring;
	u64 request_key_auth;
#endif
#ifdef CONFIG_SECURITY
	u64 security;
#endif
} __aligned(SIPHASH_ALIGNMENT);

struct cred_guard_prepared_digest {
	u64 cred;
	u64 generation;
	u64 nonce;
	u64 source_cred;
	u64 source_generation;
	u64 source_nonce;
	u64 source_seal;
#ifdef CONFIG_SECURITY
	u64 security;
#endif
} __aligned(SIPHASH_ALIGNMENT);

struct cred_guard_task_digest {
	u64 task;
	u64 generation;
	u64 nonce;
	u64 real_cred;
	u64 cred;
	u64 real_generation;
	u64 cred_generation;
	u64 real_nonce;
	u64 cred_nonce;
	u64 real_seal;
	u64 cred_seal;
} __aligned(SIPHASH_ALIGNMENT);

static bool cred_guard_enabled(void)
{
	return auth_guard_layer_enabled(cred_guard_active);
}

static void cred_guard_fail(const char *where, const char *what,
			    const struct cred *cred)
{
	auth_guard_fail(&cred_guard_object_domain, where, what, cred);
}

static void cred_guard_prepared_fail(const char *where, const char *what,
				     const struct cred *cred)
{
	auth_guard_fail(&cred_guard_prepared_domain, where, what, cred);
}

static u64 cred_guard_hash_cred(const struct cred *cred)
{
	struct auth_guard_stamp committed =
		auth_guard_stamp_load_acquire(&cred->guard_stamp);
	struct auth_guard_stamp prepared =
		auth_guard_stamp_load_acquire(&cred->guard_prepared_stamp);
	struct auth_guard_stamp source =
		auth_guard_stamp_load_acquire(&cred->guard_prepared_source_stamp);
	struct cred_guard_digest digest = {
		.cred			= auth_guard_ptr(cred),
		.generation		= committed.generation,
		.nonce			= committed.nonce,
		.prepared_generation	= prepared.generation,
		.prepared_nonce		= prepared.nonce,
		.prepared_source_cred	=
			auth_guard_ptr(READ_ONCE(cred->guard_prepared_source_cred)),
		.prepared_source_generation = source.generation,
		.prepared_source_nonce	= source.nonce,
		.prepared_source_seal	= source.seal,
		.prepared_seal		= prepared.seal,
		.uid			= __kuid_val(cred->uid),
		.gid			= __kgid_val(cred->gid),
		.suid			= __kuid_val(cred->suid),
		.sgid			= __kgid_val(cred->sgid),
		.euid			= __kuid_val(cred->euid),
		.egid			= __kgid_val(cred->egid),
		.fsuid			= __kuid_val(cred->fsuid),
		.fsgid			= __kgid_val(cred->fsgid),
		.securebits		= cred->securebits,
		.cap_inheritable	= cred->cap_inheritable.val,
		.cap_permitted		= cred->cap_permitted.val,
		.cap_effective		= cred->cap_effective.val,
		.cap_bset		= cred->cap_bset.val,
		.cap_ambient		= cred->cap_ambient.val,
		.user			= auth_guard_ptr(cred->user),
		.user_ns		= auth_guard_ptr(cred->user_ns),
		.ucounts		= auth_guard_ptr(cred->ucounts),
		.group_info		= auth_guard_ptr(cred->group_info),
#ifdef CONFIG_KEYS
		.jit_keyring		= cred->jit_keyring,
		.session_keyring	= auth_guard_ptr(cred->session_keyring),
		.process_keyring	= auth_guard_ptr(cred->process_keyring),
		.thread_keyring		= auth_guard_ptr(cred->thread_keyring),
		.request_key_auth	= auth_guard_ptr(cred->request_key_auth),
#endif
#ifdef CONFIG_SECURITY
		.security		= auth_guard_ptr(cred->security),
#endif
	};

	return auth_guard_seal(&cred_guard_object_domain, &digest,
			       sizeof(digest));
}

static u64 cred_guard_hash_prepared_cred(const struct cred *cred)
{
	struct auth_guard_stamp prepared =
		auth_guard_stamp_load_acquire(&cred->guard_prepared_stamp);
	struct auth_guard_stamp source =
		auth_guard_stamp_load_acquire(&cred->guard_prepared_source_stamp);
	const struct cred *source_cred =
		READ_ONCE(cred->guard_prepared_source_cred);
	struct cred_guard_prepared_digest digest = {
		.cred			= auth_guard_ptr(cred),
		.generation		= prepared.generation,
		.nonce			= prepared.nonce,
		.source_cred		= auth_guard_ptr(source_cred),
		.source_generation	= source.generation,
		.source_nonce		= source.nonce,
		.source_seal		= source.seal,
#ifdef CONFIG_SECURITY
		.security		= auth_guard_ptr(cred->security),
#endif
	};

	return auth_guard_seal(&cred_guard_prepared_domain, &digest,
			       sizeof(digest));
}

static bool cred_guard_prepared_metadata_empty(const struct cred *cred)
{
	return auth_guard_stamp_empty(&cred->guard_prepared_stamp) &&
		auth_guard_stamp_empty(&cred->guard_prepared_source_stamp) &&
		!READ_ONCE(cred->guard_prepared_source_cred);
}

static bool cred_guard_metadata_empty(const struct cred *cred)
{
	return cred_guard_prepared_metadata_empty(cred) &&
		auth_guard_stamp_empty(&cred->guard_stamp);
}

static void cred_guard_reset_cred(struct cred *cred)
{
	WRITE_ONCE(cred->guard_prepared_source_cred, NULL);
	auth_guard_stamp_clear(&cred->guard_prepared_source_stamp);
	auth_guard_stamp_clear(&cred->guard_prepared_stamp);
	auth_guard_stamp_clear(&cred->guard_stamp);
}

static bool cred_guard_verify_cred(const struct cred *cred, const char *where)
{
	struct auth_guard_stamp stamp;

	if (!cred_guard_enabled())
		return true;
	if (!cred) {
		cred_guard_fail(where, "missing", cred);
		return false;
	}

	stamp = auth_guard_stamp_load_acquire(&cred->guard_stamp);
	if (!auth_guard_stamp_valid(&stamp)) {
		cred_guard_fail(where, "unsealed", cred);
		return false;
	}
	if (cred_guard_hash_cred(cred) != stamp.seal) {
		cred_guard_fail(where, "corrupt", cred);
		return false;
	}

	return true;
}

bool cred_guard_verify_prepared_cred_where(const struct cred *cred,
					   const char *where)
{
	struct auth_guard_stamp stamp;

	if (!cred_guard_enabled())
		return true;
	if (!cred) {
		cred_guard_prepared_fail(where, "missing", cred);
		return false;
	}

	/* Acquire the release-published seal before authenticating metadata. */
	stamp = auth_guard_stamp_load_acquire(&cred->guard_prepared_stamp);
	if (!auth_guard_stamp_valid(&stamp)) {
		cred_guard_prepared_fail(where, "unprepared", cred);
		return false;
	}
	if (cred_guard_hash_prepared_cred(cred) != stamp.seal) {
		cred_guard_prepared_fail(where, "corrupt", cred);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(cred_guard_verify_prepared_cred_where);

static void cred_guard_seal_cred(struct cred *cred)
{
	struct auth_guard_stamp stamp =
		auth_guard_stamp_fresh(&cred_guard_object_domain);

	WRITE_ONCE(cred->guard_stamp.generation, stamp.generation);
	WRITE_ONCE(cred->guard_stamp.nonce, stamp.nonce);
	stamp.seal = cred_guard_hash_cred(cred);
	auth_guard_stamp_publish_release(&cred->guard_stamp, &stamp);
}

static bool cred_guard_clear_prepared_cred(struct cred *cred,
					   const char *where)
{
	const struct cred *source = NULL;
	struct auth_guard_stamp stamp;
	bool valid = true;

	/* Acquire the release-published seal before authenticating metadata. */
	stamp = auth_guard_stamp_load_acquire(&cred->guard_prepared_stamp);
	if (stamp.seal) {
		if (!auth_guard_stamp_valid(&stamp) ||
		    cred_guard_hash_prepared_cred(cred) != stamp.seal) {
			cred_guard_prepared_fail(where, "unsafe prepared cleanup", cred);
			valid = false;
		} else {
			source = READ_ONCE(cred->guard_prepared_source_cred);
			if (source == cred) {
				cred_guard_prepared_fail(where, "self-sourced credential", cred);
				source = NULL;
				valid = false;
			}
		}
	} else if (!cred_guard_prepared_metadata_empty(cred)) {
		cred_guard_prepared_fail(where, "unsealed prepared cleanup", cred);
		valid = false;
	}

	/* Clear attacker-reachable metadata before dropping an authenticated ref. */
	WRITE_ONCE(cred->guard_prepared_source_cred, NULL);
	auth_guard_stamp_clear(&cred->guard_prepared_source_stamp);
	auth_guard_stamp_clear(&cred->guard_prepared_stamp);
	if (source)
		put_cred(source);
	return valid;
}

static bool cred_guard_stamp_prepared_cred(struct cred *new,
					   const struct cred *old,
					   const char *where)
{
	struct auth_guard_stamp prepared = {};
	struct auth_guard_stamp source;

	if (!cred_guard_enabled())
		return true;

	if (!new) {
		cred_guard_prepared_fail(where, "missing new", new);
		return false;
	}
	if (new == old) {
		cred_guard_prepared_fail(where, "aliased constructor", new);
		return false;
	}

	if (old && !cred_guard_verify_cred(old, where))
		return false;
	if (!cred_guard_metadata_empty(new)) {
		cred_guard_prepared_fail(where, "nonfresh constructor", new);
		return false;
	}

	prepared = auth_guard_stamp_fresh(&cred_guard_prepared_domain);
	WRITE_ONCE(new->guard_prepared_stamp.generation, prepared.generation);
	WRITE_ONCE(new->guard_prepared_stamp.nonce, prepared.nonce);
	if (old) {
		WRITE_ONCE(new->guard_prepared_source_cred, get_cred(old));
		source = auth_guard_stamp_load_acquire(&old->guard_stamp);
		auth_guard_stamp_publish_release(&new->guard_prepared_source_stamp,
						 &source);
	}
	prepared.seal = cred_guard_hash_prepared_cred(new);
	auth_guard_stamp_publish_release(&new->guard_prepared_stamp, &prepared);
	return true;
}

bool cred_guard_prepare_transfer_where(struct cred *new, const struct cred *old,
				       const char *where)
{
	if (!cred_guard_verify_cred(old, where))
		return false;
	return cred_guard_stamp_prepared_cred(new, old, where);
}
EXPORT_SYMBOL(cred_guard_prepare_transfer_where);

static void cred_guard_bootstrap_cred(struct cred *cred, const char *where)
{
	if (!cred_guard_enabled())
		return;

	if (!cred) {
		cred_guard_fail(where, "missing bootstrap", cred);
		return;
	}
	if (auth_guard_stamp_published_acquire(&cred->guard_stamp)) {
		cred_guard_verify_cred(cred, where);
		return;
	}
	if (!cred_guard_metadata_empty(cred)) {
		cred_guard_fail(where, "nonfresh bootstrap", cred);
		return;
	}
	cred_guard_seal_cred(cred);
}

static bool cred_guard_verify_commit_cred(const struct cred *cred,
					  const char *where)
{
	const struct cred *source;
	struct auth_guard_stamp source_stamp;
	struct auth_guard_stamp expected_stamp;

	if (!cred_guard_enabled())
		return true;

	if (!cred) {
		cred_guard_fail(where, "missing commit", cred);
		return false;
	}
	if (!cred_guard_verify_prepared_cred_where(cred, where))
		return false;

	source = READ_ONCE(cred->guard_prepared_source_cred);
	if (!source) {
		cred_guard_prepared_fail(where, "missing source", cred);
		return false;
	}
	/* Acquire the release-published seal before source metadata. */
	source_stamp = auth_guard_stamp_load_acquire(&source->guard_stamp);
	expected_stamp = auth_guard_stamp_load_acquire(&cred->guard_prepared_source_stamp);
	if (!auth_guard_stamp_equal(&source_stamp, &expected_stamp)) {
		cred_guard_prepared_fail(where, "stale source", cred);
		return false;
	}
	if (!cred_guard_verify_cred(source, where)) {
		cred_guard_prepared_fail(where, "corrupt source", cred);
		return false;
	}
	if (!auth_guard_userns_boundary_check_where(READ_ONCE(cred->user_ns), where))
		return false;

	return true;
}

static bool cred_guard_verify_commit_source(const struct cred *cred,
					    const struct cred *expected,
					    const char *where)
{
	if (!cred_guard_enabled())
		return true;
	if (READ_ONCE(cred->guard_prepared_source_cred) != expected) {
		cred_guard_prepared_fail(where, "unexpected source", cred);
		return false;
	}
	return true;
}

static void cred_guard_finalize_commit_cred(struct cred *cred)
{
	if (!cred_guard_enabled())
		return;

	/* A verified prepared object is still private, so consume provenance first. */
	if (!cred_guard_clear_prepared_cred(cred, __func__))
		AUTH_GUARD_FAIL_STOP();
	cred_guard_seal_cred(cred);
}

static bool cred_guard_finalize_prepared_cred(struct cred *cred,
					      const char *where)
{
	if (!cred_guard_verify_commit_cred(cred, where))
		return false;
	cred_guard_finalize_commit_cred(cred);
	return true;
}

bool cred_guard_verify_committed_cred_where(const struct cred *cred,
					    const char *where)
{
	if (!cred_guard_verify_cred(cred, where))
		return false;
	return auth_guard_userns_boundary_check_where(READ_ONCE(cred->user_ns), where);
}
EXPORT_SYMBOL(cred_guard_verify_committed_cred_where);

static bool cred_guard_verify_cred_if_sealed(const struct cred *cred,
					     const char *where)
{
	if (!cred_guard_enabled())
		return true;
	if (!cred)
		return true;
	if (auth_guard_stamp_published_acquire(&cred->guard_stamp))
		return cred_guard_verify_cred(cred, where);
	if (auth_guard_stamp_published_acquire(&cred->guard_prepared_stamp))
		return cred_guard_verify_prepared_cred_where(cred, where);
	if (!cred_guard_prepared_metadata_empty(cred)) {
		cred_guard_prepared_fail(where, "unsealed cleanup", cred);
		return false;
	}
	if (!cred_guard_metadata_empty(cred)) {
		cred_guard_fail(where, "unsealed cleanup", cred);
		return false;
	}
	return true;
}

static u64 cred_guard_hash_task(const struct task_struct *task,
				const struct cred *real_cred,
				const struct cred *cred,
				u64 generation,
				u64 nonce)
{
	struct auth_guard_stamp real_stamp =
		auth_guard_stamp_load_acquire(&real_cred->guard_stamp);
	struct auth_guard_stamp cred_stamp =
		auth_guard_stamp_load_acquire(&cred->guard_stamp);
	struct cred_guard_task_digest digest = {
		.task		= auth_guard_ptr(task),
		.generation	= generation,
		.nonce		= nonce,
		.real_cred	= auth_guard_ptr(real_cred),
		.cred		= auth_guard_ptr(cred),
		.real_generation = real_stamp.generation,
		.cred_generation = cred_stamp.generation,
		.real_nonce	= real_stamp.nonce,
		.cred_nonce	= cred_stamp.nonce,
		.real_seal	= real_stamp.seal,
		.cred_seal	= cred_stamp.seal,
	};

	return auth_guard_seal(&cred_guard_task_domain, &digest,
			       sizeof(digest));
}

static bool cred_guard_build_task_stamp(struct task_struct *task,
					const struct cred *real_cred,
					const struct cred *cred,
					const char *where,
					struct auth_guard_stamp *stamp)
{
	if (!cred_guard_enabled()) {
		*stamp = (struct auth_guard_stamp) {};
		return true;
	}
	if (!task || !real_cred || !cred) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"missing task attachment endpoint", task);
		return false;
	}
	if (!cred_guard_verify_cred(real_cred, where) ||
	    !cred_guard_verify_cred(cred, where))
		return false;

	*stamp = auth_guard_stamp_fresh(&cred_guard_task_domain);
	stamp->seal = cred_guard_hash_task(task, real_cred, cred,
					   stamp->generation, stamp->nonce);
	return true;
}

static bool cred_guard_attach_task(struct task_struct *task,
				   const struct cred *real_cred,
				   const struct cred *cred,
				   const char *where)
{
	struct auth_guard_stamp stamp;

	if (!cred_guard_build_task_stamp(task, real_cred, cred, where, &stamp))
		return false;
	if (cred_guard_enabled())
		auth_guard_stamp_publish_release(&task->cred_guard_stamp, &stamp);
	return true;
}

static enum auth_guard_check_result
cred_guard_task_snapshot(const struct task_struct *task,
			 const struct cred *expected, const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct auth_guard_stamp stamp;
	const struct cred *real_cred;
	const struct cred *cred;

	/* Pair release publication before reading protected attachment metadata. */
	stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_valid(&stamp)) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"unsealed task attachment", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	real_cred = rcu_access_pointer(task->real_cred);
	cred = rcu_access_pointer(task->cred);
	if (real_cred != expected) {
		/* The caller pinned a snapshot from before a completed transition. */
		return AUTH_GUARD_CHECK_BUSY;
	}
	if (!cred_guard_verify_cred(real_cred, where) ||
	    !cred_guard_verify_cred(cred, where))
		return AUTH_GUARD_CHECK_INVALID;
	if (cred_guard_hash_task(task, real_cred, cred, stamp.generation,
				 stamp.nonce) != stamp.seal) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"corrupt task attachment", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	/* A reservation excludes legitimate writers; any change is corruption. */
	current_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, &stamp) ||
	    rcu_access_pointer(task->real_cred) != real_cred ||
	    rcu_access_pointer(task->cred) != cred) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"changed task attachment", task);
		return AUTH_GUARD_CHECK_INVALID;
	}

	return AUTH_GUARD_CHECK_VALID;
}

enum auth_guard_check_result
cred_guard_check_task_cred_reserved_where(const struct task_struct *task,
					  const struct cred *expected,
					  const char *where)
{
	if (!cred_guard_enabled())
		return AUTH_GUARD_CHECK_VALID;
	if (!task) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"missing task attachment", task);
		return AUTH_GUARD_CHECK_INVALID;
	}
	return cred_guard_task_snapshot(task, expected, where);
}

enum auth_guard_check_result
cred_guard_check_task_cred_where(const struct task_struct *task,
				 const struct cred *expected, const char *where)
{
	struct task_struct *mutable_task = (struct task_struct *)task;
	enum auth_guard_check_result result;

	if (!cred_guard_enabled())
		return AUTH_GUARD_CHECK_VALID;
	if (!task) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"missing task attachment", task);
		return AUTH_GUARD_CHECK_INVALID;
	}

	result = auth_guard_task_transition_reader_begin_where(mutable_task, where);
	if (result != AUTH_GUARD_CHECK_VALID)
		return result;
	result = cred_guard_check_task_cred_reserved_where(task, expected, where);
	if (!auth_guard_task_transition_reader_stable_where(mutable_task, where))
		result = AUTH_GUARD_CHECK_INVALID;
	if (!auth_guard_task_transition_reader_end_where(mutable_task, where))
		result = AUTH_GUARD_CHECK_INVALID;
	return result;
}

static bool
cred_guard_task_prepare_transition(struct task_struct *task,
				   const struct cred *new_real,
				   const struct cred *new_subj,
				   bool outer_transition,
				   struct cred_guard_task_transition *transition,
				   const char *where)
{
	struct auth_guard_stamp current_stamp;

	*transition = (struct cred_guard_task_transition) {
		.task = task,
		.new_real = new_real,
		.new_subj = new_subj,
		.outer_transition = outer_transition,
	};
	if (!cred_guard_enabled())
		return true;
	if (!task || !new_real || !new_subj ||
	    !auth_guard_task_transition_open_where(task, where))
		return false;

	if (!cred_guard_build_task_stamp(task, new_real, new_subj, where,
					 &transition->new_stamp))
		return false;
	if (!auth_guard_task_expect_creds_where(task, new_real, new_subj,
						&transition->new_stamp,
						&transition->old_stamp,
						&transition->old_real,
						&transition->old_subj, where))
		return false;

	current_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, &transition->old_stamp) ||
	    rcu_access_pointer(task->real_cred) != transition->old_real ||
	    rcu_access_pointer(task->cred) != transition->old_subj) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"changed prepared task attachment", task);
		return false;
	}
	transition->coordinator_open = true;
	return true;
}

static bool
cred_guard_task_publish_transition(struct cred_guard_task_transition *transition,
				   const char *where)
{
	struct auth_guard_stamp current_stamp;
	struct task_struct *task = transition->task;

	if (!cred_guard_enabled())
		return true;
	if (!transition->coordinator_open ||
	    !auth_guard_task_transition_open_where(task, where))
		goto invalid;
	current_stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (!auth_guard_stamp_equal(&current_stamp, &transition->old_stamp) ||
	    rcu_access_pointer(task->real_cred) != transition->new_real ||
	    rcu_access_pointer(task->cred) != transition->new_subj) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"changed published task attachment", task);
		goto invalid;
	}

	auth_guard_stamp_publish_release(&task->cred_guard_stamp,
					 &transition->new_stamp);
	return auth_guard_task_transition_cred_published_where(task,
		&transition->old_stamp, &transition->new_stamp,
		transition->outer_transition, &transition->coordinator_open, where);

invalid:
	auth_guard_task_transition_quarantine(task);
	return false;
}

static bool cred_guard_task_init_attachment(struct task_struct *task,
					    const char *where)
{
	bool valid;

	if (!cred_guard_enabled())
		return true;
	if (!auth_guard_task_first_seal_begin_where(task, where))
		return false;
	auth_guard_stamp_clear(&task->cred_guard_stamp);
	valid = cred_guard_attach_task(task, rcu_access_pointer(task->real_cred),
				       rcu_access_pointer(task->cred), where);
	auth_guard_task_first_seal_complete(task, valid);
	return valid;
}

void cred_guard_task_invalidate_reserved_where(struct task_struct *task,
					       const char *where)
{
	if (!cred_guard_enabled())
		return;
	if (!task) {
		auth_guard_fail(&cred_guard_task_domain, where,
				"missing reserved invalidation", task);
		return;
	}
	auth_guard_stamp_clear(&task->cred_guard_stamp);
}

static bool
cred_guard_task_begin_teardown(struct task_struct *task,
			       enum auth_guard_task_teardown_status status,
			       const struct cred *expected_real,
			       const struct cred *expected_subj,
			       struct cred_guard_task_teardown *teardown,
			       const char *where)
{
	enum auth_guard_check_result result;

	*teardown = (struct cred_guard_task_teardown) {
		.task = task,
		.old_real = expected_real,
		.old_subj = expected_subj,
	};

	if (!cred_guard_enabled())
		return true;
	if (!task)
		return false;
	teardown->stamp = auth_guard_stamp_load_acquire(&task->cred_guard_stamp);
	if (status == AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED &&
	    auth_guard_stamp_empty(&teardown->stamp)) {
		teardown->old_valid = true;
		return true;
	}

	if (status != AUTH_GUARD_TASK_TEARDOWN_OPENED) {
		if (status != AUTH_GUARD_TASK_TEARDOWN_SKIP_TRUSTED &&
		    status != AUTH_GUARD_TASK_TEARDOWN_SKIP_UNPUBLISHED &&
		    status != AUTH_GUARD_TASK_TEARDOWN_SKIP_UNTRUSTED)
			return false;
		result = auth_guard_task_transition_reserve_teardown_where(task, where);
		if (result == AUTH_GUARD_CHECK_BUSY)
			return false;
		teardown->coordinator_owned = true;
		if (result != AUTH_GUARD_CHECK_VALID)
			return false;
	}
	if (!auth_guard_stamp_valid(&teardown->stamp)) {
		if (status != AUTH_GUARD_TASK_TEARDOWN_SKIP_UNTRUSTED)
			auth_guard_fail(&cred_guard_task_domain, where,
					"unsealed teardown attachment", task);
		auth_guard_task_transition_quarantine(task);
		return false;
	}

	result = cred_guard_check_task_cred_reserved_where(task, expected_real, where);
	if (result != AUTH_GUARD_CHECK_VALID ||
	    rcu_access_pointer(task->real_cred) != expected_real ||
	    rcu_access_pointer(task->cred) != expected_subj) {
		if (result == AUTH_GUARD_CHECK_BUSY)
			auth_guard_fail(&cred_guard_task_domain, where,
					"changed teardown task attachment", task);
		auth_guard_task_transition_quarantine(task);
		return false;
	}
	if (teardown->coordinator_owned &&
	    !auth_guard_task_transition_publish_where(task,
						     AUTH_GUARD_TRANSITION_ANCHOR_CRED,
						     &teardown->stamp, where))
		return false;

	teardown->old_valid = true;
	return true;
}

static bool cred_guard_task_detach(struct cred_guard_task_teardown *teardown,
				   bool exact, const char *where)
{
	struct task_struct *task = teardown->task;
	bool valid = teardown->old_valid && exact;

	if (!cred_guard_enabled())
		return exact;
	if (!task)
		return false;
	if (teardown->coordinator_owned && teardown->old_valid &&
	    !auth_guard_task_transition_verify_where(task,
						    AUTH_GUARD_TRANSITION_ANCHOR_CRED,
						    &teardown->stamp, where))
		valid = false;

	auth_guard_stamp_clear(&task->cred_guard_stamp);
	if (!teardown->coordinator_owned)
		return valid;
	if (valid) {
		if (!auth_guard_task_transition_close_where(task,
							    AUTH_GUARD_TRANSITION_ANCHOR_CRED,
				&teardown->stamp, where))
			valid = false;
	} else if (!auth_guard_task_transition_terminal_close_where(task, where)) {
		valid = false;
	}
	return valid;
}

int cred_guard_preflight_commit_creds_where(const struct cred *new, const char *where)
{
	const struct cred *old = current_real_cred();

	if (!cred_guard_verify_current_task(where))
		return -EACCES;
	if (!cred_guard_verify_commit_cred(new, where))
		return -EINVAL;
	if (!cred_guard_verify_commit_source(new, old, where))
		return -EINVAL;
	if (!auth_guard_task_check_where(current, where))
		return -EACCES;
	return 0;
}
EXPORT_SYMBOL(cred_guard_preflight_commit_creds_where);

void __init cred_guard_enable(void)
{
	auth_guard_task_transition_enable();
	auth_guard_init_domain(&cred_guard_object_domain);
	auth_guard_init_domain(&cred_guard_prepared_domain);
	auth_guard_init_domain(&cred_guard_task_domain);
	cred_guard_active = true;
	cred_guard_bootstrap_cred((struct cred *)current->real_cred,
				  __func__);
	if (!cred_guard_task_init_attachment(current, __func__))
		BUG();
	pr_info("credential guard enabled\n");
}

#ifdef CONFIG_AUTH_GUARD_TEST
int cred_guard_test_corrupt_current(const char *what)
{
	struct cred *cred;

	if (strcmp(what, "cred_uid") && strcmp(what, "cred_cap"))
		return -EINVAL;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	if (!cred_guard_finalize_prepared_cred(cred, __func__)) {
		abort_creds(cred);
		return -EINVAL;
	}

	if (!strcmp(what, "cred_uid")) {
		cred->uid = KUIDT_INIT(__kuid_val(cred->uid) ^ 1);
		cred_guard_verify_cred(cred,
				       AUTH_GUARD_TEST_CONTEXT("cred_uid"));
	} else {
		cred->cap_effective.val ^= BIT_ULL(CAP_SYS_ADMIN);
		cred_guard_verify_cred(cred,
				       AUTH_GUARD_TEST_CONTEXT("cred_cap"));
	}

	cred_guard_reset_cred(cred);
	abort_creds(cred);
	return 0;
}
#endif
#else
#define DEFINE_CRED_GUARD_STUB_TRUE(_name, _args) \
	static inline bool _name _args { return true; }
#define DEFINE_CRED_GUARD_STUB_VOID(_name, _args) \
	static inline void _name _args { }
#define DEFINE_CRED_GUARD_STUB_VALID(_name, _args) \
	enum auth_guard_check_result _name _args { return AUTH_GUARD_CHECK_VALID; }

DEFINE_CRED_GUARD_STUB_VOID(cred_guard_reset_cred,
			    (struct cred *cred))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_clear_prepared_cred,
			    (struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_verify_cred,
			    (const struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_verify_cred_if_sealed,
			    (const struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_verify_commit_cred,
			    (const struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_verify_commit_source,
			    (const struct cred *cred,
			     const struct cred *expected, const char *where))
DEFINE_CRED_GUARD_STUB_VOID(cred_guard_finalize_commit_cred,
			    (struct cred *cred))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_finalize_prepared_cred,
			    (struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_attach_task,
			    (struct task_struct *task,
			     const struct cred *real_cred,
			     const struct cred *cred, const char *where))
DEFINE_CRED_GUARD_STUB_VALID(cred_guard_check_task_cred_where,
			     (const struct task_struct *task,
			      const struct cred *expected, const char *where))
DEFINE_CRED_GUARD_STUB_VALID(cred_guard_check_task_cred_reserved_where,
			     (const struct task_struct *task,
			      const struct cred *expected, const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_task_publish_transition,
			    (struct cred_guard_task_transition *transition,
			     const char *where))
DEFINE_CRED_GUARD_STUB_TRUE(cred_guard_task_init_attachment,
			    (struct task_struct *task, const char *where))

#undef DEFINE_CRED_GUARD_STUB_VALID
#undef DEFINE_CRED_GUARD_STUB_VOID
#undef DEFINE_CRED_GUARD_STUB_TRUE

static inline bool
cred_guard_task_prepare_transition(struct task_struct *task,
				   const struct cred *new_real,
				   const struct cred *new_subj,
				   bool outer_transition,
				   struct cred_guard_task_transition *transition,
				   const char *where)
{
	*transition = (struct cred_guard_task_transition) {
		.task = task,
		.old_real = task ? rcu_access_pointer(task->real_cred) : NULL,
		.old_subj = task ? rcu_access_pointer(task->cred) : NULL,
		.new_real = new_real,
		.new_subj = new_subj,
		.outer_transition = outer_transition,
	};
	return true;
}

static inline bool
cred_guard_task_begin_teardown(struct task_struct *task,
			       enum auth_guard_task_teardown_status status,
			       const struct cred *expected_real,
			       const struct cred *expected_subj,
			       struct cred_guard_task_teardown *teardown,
			       const char *where)
{
	*teardown = (struct cred_guard_task_teardown) {
		.task = task,
		.old_real = expected_real,
		.old_subj = expected_subj,
		.old_valid = true,
	};
	return true;
}

static inline bool
cred_guard_task_detach(struct cred_guard_task_teardown *teardown, bool exact,
		       const char *where)
{
	return exact;
}
#endif

/*
 * A consuming API must not pass rejected caller-supplied memory to the normal
 * credential destructor.  Only authenticated prepared provenance permits the
 * object and its native references to be released; otherwise quarantine it.
 */
static void cred_guard_reject_prepared_cred(struct cred *cred,
					    const char *where)
{
	if (!cred_guard_verify_prepared_cred_where(cred, where))
		return;
	if (!cred_guard_clear_prepared_cred(cred, where))
		return;
	if (WARN_ON_ONCE(atomic_long_read(&cred->usage) < 1))
		return;
	put_cred(cred);
}

/*
 * Consuming credential APIs reject an invalid prepared object themselves.
 * Keep that verification and safe-release contract identical at every such
 * publication site.
 */
static bool cred_guard_validate_prepared_consuming(struct cred *cred,
						   const char *where)
{
	if (cred_guard_verify_commit_cred(cred, where) &&
	    likely(atomic_long_read(&cred->usage) >= 1))
		return true;

	cred_guard_reject_prepared_cred(cred, where);
	return false;
}

#if defined(CONFIG_CRED_GUARD) && !defined(CONFIG_AUTH_GUARD)
enum auth_guard_check_result
auth_guard_task_check_real_cred_where(struct task_struct *task,
				      const struct cred *expected,
				      const char *where)
{
	return cred_guard_check_task_cred_where(task, expected, where);
}
#endif

static bool cred_guard_verify_current_task(const char *where)
{
	return cred_guard_check_task_cred_where(current, current_real_cred(), where) ==
		AUTH_GUARD_CHECK_VALID;
}

static bool
cred_guard_begin_subjective_cred_transition(const struct cred *cred,
					    struct cred_guard_task_transition *transition,
					    const char *where)
{
	if (!cred_guard_verify_committed_cred_where(cred, where))
		return false;
	if (!auth_guard_task_begin_transition_wait_where(current, where))
		return false;
	if (!cred_guard_task_prepare_transition(current, current_real_cred(), cred,
						false, transition, where)) {
		auth_guard_task_abort_transition_where(current, where);
		return false;
	}
	return true;
}

static bool
cred_guard_finish_subjective_cred_transition(struct cred_guard_task_transition *transition,
					     const char *where)
{
	if (!cred_guard_task_publish_transition(transition, where))
		return false;
	if (transition->coordinator_open &&
	    !auth_guard_task_finish_transition_where(current, where))
		return false;
	return cred_guard_verify_current_task(where);
}

/* init to 2 - one for init_task, one to ensure it is never freed */
static struct group_info init_groups = { .usage = REFCOUNT_INIT(2) };

/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
	.ucounts		= &init_ucounts,
};

/*
 * The RCU callback to actually dispose of a set of credentials
 */
static void put_cred_rcu(struct rcu_head *rcu)
{
	struct cred *cred = container_of(rcu, struct cred, rcu);

	kdebug("put_cred_rcu(%p)", cred);

	if (atomic_long_read(&cred->usage) != 0)
		panic("CRED: put_cred_rcu() sees %p with usage %ld\n",
		      cred, atomic_long_read(&cred->usage));

	/* Invalid pointer-bearing credentials are quarantined rather than freed. */
	if (!cred_guard_verify_cred_if_sealed(cred, __func__))
		return;
	if (!cred_guard_clear_prepared_cred(cred, __func__))
		return;
	security_cred_free(cred);
	key_put(cred->session_keyring);
	key_put(cred->process_keyring);
	key_put(cred->thread_keyring);
	key_put(cred->request_key_auth);
	if (cred->group_info)
		put_group_info(cred->group_info);
	free_uid(cred->user);
	if (cred->ucounts)
		put_ucounts(cred->ucounts);
	put_user_ns(cred->user_ns);
	kmem_cache_free(cred_jar, cred);
}

/**
 * __put_cred - Destroy a set of credentials
 * @cred: The record to release
 *
 * Destroy a set of credentials on which no references remain.
 */
void __put_cred(struct cred *cred)
{
	kdebug("__put_cred(%p{%ld})", cred,
	       atomic_long_read(&cred->usage));

	BUG_ON(atomic_long_read(&cred->usage) != 0);
	BUG_ON(cred == current->cred);
	BUG_ON(cred == current->real_cred);

	if (cred->non_rcu)
		put_cred_rcu(&cred->rcu);
	else
		call_rcu(&cred->rcu, put_cred_rcu);
}
EXPORT_SYMBOL(__put_cred);

/*
 * Clean up a task's credentials when it exits
 */
void exit_creds(struct task_struct *tsk)
{
	struct cred_guard_task_teardown cred_teardown;
	const struct cred *expected_real;
	const struct cred *expected_subj;
	const struct cred *real_cred;
	const struct cred *cred;
	enum auth_guard_task_teardown_status status;
	bool auth_old_valid;
	bool cred_old_valid;
	bool auth_detach_declared;
	bool auth_result_valid;
	bool auth_trusted;
	bool cred_detached;
	bool exact;
	bool trusted;

	kdebug("exit_creds(%u,%p,%p)", tsk->pid, tsk->real_cred, tsk->cred);

	status = auth_guard_task_begin_teardown_transition(tsk);
	expected_real = rcu_access_pointer(tsk->real_cred);
	expected_subj = rcu_access_pointer(tsk->cred);
	auth_old_valid = auth_guard_task_validate_teardown(tsk, status);
	cred_old_valid = cred_guard_task_begin_teardown(tsk, status, expected_real,
							expected_subj,
							&cred_teardown, __func__);
	auth_detach_declared = status != AUTH_GUARD_TASK_TEARDOWN_OPENED ||
		(auth_old_valid && cred_old_valid &&
		 auth_guard_task_expect_cred_detach_in_transition(
			 tsk, expected_real, expected_subj));

	real_cred = xchg(&tsk->real_cred, NULL);
	cred = xchg(&tsk->cred, NULL);
	exact = real_cred == expected_real && cred == expected_subj &&
		real_cred && cred;
	/*
	 * This is the final task-authority endpoint detach.  Clear both task seals,
	 * but release credentials only when both old graphs and the exact detached
	 * pointers were authenticated.  Log-mode rejection deliberately leaks the
	 * detached references instead of passing attacker-selected objects to the
	 * credential destructor.
	 */
	cred_detached = cred_guard_task_detach(&cred_teardown, exact, __func__);
	auth_result_valid =
		status != AUTH_GUARD_TASK_TEARDOWN_OPENED ||
		(auth_detach_declared &&
		 auth_guard_task_validate_transition_result(tsk));
	auth_trusted = auth_guard_task_complete_teardown(
		tsk, status, auth_old_valid && auth_detach_declared &&
		auth_result_valid, exact && auth_result_valid, true);
	trusted = auth_trusted && cred_old_valid && cred_detached && exact;
	if (!trusted)
		WARN_ON_ONCE(1);

	if (!trusted) {
		/* Quarantined endpoints retain their references until reboot. */
	} else if (real_cred == cred) {
		put_cred_many(cred, 2);
	} else {
		put_cred(real_cred);
		put_cred(cred);
	}

#ifdef CONFIG_KEYS_REQUEST_CACHE
	key_put(tsk->cached_requested_key);
	tsk->cached_requested_key = NULL;
#endif
}

static const struct cred *
get_task_cred_checked_internal(struct task_struct *task, bool wait,
			       const char *where)
{
	const struct cred *cred;
	enum auth_guard_check_result auth_result;

	for (;;) {
		rcu_read_lock();

		do {
			cred = __task_cred((task));
			BUG_ON(!cred);
		} while (!get_cred_rcu(cred));

		rcu_read_unlock();
		auth_result = auth_guard_task_check_real_cred_where(task, cred, where);
		if (auth_result == AUTH_GUARD_CHECK_VALID ||
		    auth_result == AUTH_GUARD_CHECK_CREDENTIAL_ONLY)
			break;
		put_cred(cred);
		if (auth_result != AUTH_GUARD_CHECK_BUSY)
			return ERR_PTR(-EACCES);
		if (!wait)
			return ERR_PTR(-EAGAIN);
		cpu_relax();
	}
	if (!cred_guard_verify_cred(cred, where)) {
		put_cred(cred);
		return ERR_PTR(-EACCES);
	}
	return cred;
}

/**
 * get_task_cred_checked_where - Get guarded objective credentials
 * @task: The task to query
 * @where: Guard diagnostic label supplied by the outer authority-use boundary
 *
 * Get the objective credentials of a task, pinning them so that they can't go
 * away.  Accessing a task's credentials directly is not permitted.  Return an
 * error pointer when log-mode guard validation rejects the captured task edge.
 * A legitimate in-flight authority writer is retried.
 *
 * The caller must also make sure task doesn't get deleted, either by holding a
 * ref on task or by holding tasklist_lock to prevent it from being unlinked.
 * The caller must not hold a lock needed by an authority writer; use
 * get_task_cred_checked_nowait() in that case.
 */
const struct cred *get_task_cred_checked_where(struct task_struct *task,
					       const char *where)
{
	return get_task_cred_checked_internal(task, true, where);
}
EXPORT_SYMBOL(get_task_cred_checked_where);

/**
 * get_task_cred_checked_nowait_where - Try to get guarded credentials
 * @task: The task to query
 * @where: Guard diagnostic label supplied by the outer authority-use boundary
 *
 * As get_task_cred_checked(), but return %-EAGAIN for a legitimate in-flight
 * authority writer.  This variant is required while holding a lock which a
 * task authority writer may need to complete.
 */
const struct cred *
get_task_cred_checked_nowait_where(struct task_struct *task, const char *where)
{
	return get_task_cred_checked_internal(task, false, where);
}
EXPORT_SYMBOL(get_task_cred_checked_nowait_where);

const struct cred *get_task_cred(struct task_struct *task)
{
	const struct cred *cred = get_task_cred_checked(task);

	if (IS_ERR(cred))
		BUG();
	return cred;
}
EXPORT_SYMBOL(get_task_cred);

/*
 * Allocate blank credentials, such that the credentials can be filled in at a
 * later date without risk of ENOMEM.
 */
struct cred *cred_alloc_blank(void)
{
	struct cred *new;

	new = kmem_cache_zalloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	atomic_long_set(&new->usage, 1);
	cred_guard_reset_cred(new);
	if (security_cred_alloc_blank(new, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	return new;

error:
	abort_creds(new);
	return NULL;
}

/**
 * prepare_creds - Prepare a new set of credentials for modification
 *
 * Prepare a new set of task credentials for modification.  A task's creds
 * shouldn't generally be modified directly, therefore this function is used to
 * prepare a new copy, which the caller then modifies and then commits by
 * calling commit_creds().
 *
 * Preparation involves making a copy of the objective creds for modification.
 *
 * Returns a pointer to the new creds-to-be if successful, NULL otherwise.
 *
 * Call commit_creds() or abort_creds() to clean up.
 */
struct cred *prepare_creds(void)
{
	struct task_struct *task = current;
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_creds() alloc %p", new);

	if (!cred_guard_verify_current_task(__func__)) {
		kmem_cache_free(cred_jar, new);
		return NULL;
	}
	old = task->cred;
	memcpy(new, old, sizeof(struct cred));

	new->non_rcu = 0;
	atomic_long_set(&new->usage, 1);
	cred_guard_reset_cred(new);
	get_group_info(new->group_info);
	get_uid(new->user);
	get_user_ns(new->user_ns);

#ifdef CONFIG_KEYS
	key_get(new->session_keyring);
	key_get(new->process_keyring);
	key_get(new->thread_keyring);
	key_get(new->request_key_auth);
#endif

#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif

	new->ucounts = get_ucounts(new->ucounts);
	if (!new->ucounts)
		goto error;

	if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	if (!cred_guard_prepare_transfer(new, old))
		goto error;
	return new;

error:
	abort_creds(new);
	return NULL;
}
EXPORT_SYMBOL(prepare_creds);

/*
 * Prepare credentials for current to perform an execve()
 * - The caller must hold ->cred_guard_mutex
 */
struct cred *prepare_exec_creds(void)
{
	struct cred *new;

	new = prepare_creds();
	if (!new)
		return new;

#ifdef CONFIG_KEYS
	/* newly exec'd tasks don't get a thread keyring */
	key_put(new->thread_keyring);
	new->thread_keyring = NULL;

	/* inherit the session keyring; new process keyring */
	key_put(new->process_keyring);
	new->process_keyring = NULL;
#endif

	new->suid = new->fsuid = new->euid;
	new->sgid = new->fsgid = new->egid;

	return new;
}

/*
 * Copy credentials for the new process created by fork()
 *
 * We share if we can, but under some circumstances we have to generate a new
 * set.
 *
 * The new process gets the current process's subjective credentials as its
 * objective and subjective credentials
 */
int copy_creds(struct task_struct *p, u64 clone_flags)
{
	struct cred *new;
	int ret;

#ifdef CONFIG_KEYS_REQUEST_CACHE
	p->cached_requested_key = NULL;
#endif

	if (!cred_guard_verify_current_task(__func__))
		return -EACCES;

	if (
#ifdef CONFIG_KEYS
		!p->cred->thread_keyring &&
#endif
		clone_flags & CLONE_THREAD
		    ) {
		p->real_cred = get_cred_many(p->cred, 2);
		if (!cred_guard_task_init_attachment(p, __func__)) {
			const struct cred *shared = p->cred;

			p->real_cred = NULL;
			p->cred = NULL;
			put_cred_many(shared, 2);
			return -EACCES;
		}
		kdebug("share_creds(%p{%ld})",
		       p->cred, atomic_long_read(&p->cred->usage));
		inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
		return 0;
	}

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (clone_flags & CLONE_NEWUSER) {
		ret = create_user_ns(new);
		if (ret < 0)
			goto error_put;
		ret = set_cred_ucounts(new);
		if (ret < 0)
			goto error_put;
	}

#ifdef CONFIG_KEYS
	/* new threads get their own thread keyrings if their parent already
	 * had one */
	if (new->thread_keyring) {
		key_put(new->thread_keyring);
		new->thread_keyring = NULL;
		if (clone_flags & CLONE_THREAD)
			install_thread_keyring_to_cred(new);
	}

	/* The process keyring is only shared between the threads in a process;
	 * anything outside of those threads doesn't inherit.
	 */
	if (!(clone_flags & CLONE_THREAD)) {
		key_put(new->process_keyring);
		new->process_keyring = NULL;
	}
#endif

	if (!cred_guard_finalize_prepared_cred(new, __func__)) {
		ret = -EINVAL;
		goto error_put;
	}
	get_cred(new);
	p->real_cred = new;
	p->cred = new;
	if (!cred_guard_task_init_attachment(p, __func__)) {
		p->real_cred = NULL;
		p->cred = NULL;
		ret = -EACCES;
		goto error_put_committed;
	}
	inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
	return 0;

error_put_committed:
	put_cred_many(new, 2);
	return ret;
error_put:
	abort_creds(new);
	return ret;
}

static bool cred_cap_issubset(const struct cred *set, const struct cred *subset)
{
	const struct user_namespace *set_ns = set->user_ns;
	const struct user_namespace *subset_ns = subset->user_ns;

	/* If the two credentials are in the same user namespace see if
	 * the capabilities of subset are a subset of set.
	 */
	if (set_ns == subset_ns)
		return cap_issubset(subset->cap_permitted, set->cap_permitted);

	/* The credentials are in a different user namespaces
	 * therefore one is a subset of the other only if a set is an
	 * ancestor of subset and set->euid is owner of subset or one
	 * of subsets ancestors.
	 */
	for (;subset_ns != &init_user_ns; subset_ns = subset_ns->parent) {
		if ((set_ns == subset_ns->parent)  &&
		    uid_eq(subset_ns->owner, set->euid))
			return true;
	}

	return false;
}

static int commit_creds_apply_in_task_transition(struct cred *new,
						 struct auth_guard_task_lsm_request *detached_lsm,
						 const char *where,
						 bool finish_task_transition)
{
	struct cred_guard_task_transition cred_transition;
	struct task_struct *task = current;
	const struct cred *old = task->real_cred;
	enum auth_guard_mutation_result mutation;

	if (!where)
		where = __func__;
	if (!new || !detached_lsm)
		return -EINVAL;
	*detached_lsm = (struct auth_guard_task_lsm_request) {
		.lsmid = LSM_ID_UNDEF,
	};

	kdebug("commit_creds(%p{%ld})", new,
	       atomic_long_read(&new->usage));

	if (!auth_guard_task_transition_open_where(task, where)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EACCES;
	}
	if (!cred_guard_validate_prepared_consuming(new, where))
		return -EINVAL;
	if (!cred_guard_verify_commit_source(new, old, where)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EINVAL;
	}
	if (WARN_ON_ONCE(task->cred != old)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EINVAL;
	}
	cred_guard_finalize_commit_cred(new);
	if (old->user_ns != new->user_ns || !uid_eq(old->uid, new->uid) ||
	    !uid_eq(old->euid, new->euid) || !gid_eq(old->gid, new->gid) ||
	    !gid_eq(old->egid, new->egid) || !cred_cap_issubset(old, new) ||
	    !cred_cap_issubset(new, old)) {
		mutation = lsm_ns_clear_pending_child_request_in_transition_where(
			task, detached_lsm, where);
		AUTH_GUARD_MUTATION_FAIL_STOP(mutation);
	}
	if (!cred_guard_task_prepare_transition(task, new, new,
						!finish_task_transition,
						&cred_transition, where) ||
	    cred_transition.old_real != old ||
	    cred_transition.old_subj != old) {
		AUTH_GUARD_FAIL_STOP();
	}

	get_cred(new); /* we will require a ref for the subj creds too */

	/* dumpability changes */
	if (!uid_eq(old->euid, new->euid) ||
	    !gid_eq(old->egid, new->egid) ||
	    !uid_eq(old->fsuid, new->fsuid) ||
	    !gid_eq(old->fsgid, new->fsgid) ||
	    !cred_cap_issubset(old, new)) {
		if (task->mm)
			set_dumpable(task->mm, suid_dumpable);
		task->pdeath_signal = 0;
		/*
		 * If a task drops privileges and becomes nondumpable,
		 * the dumpability change must become visible before
		 * the credential change; otherwise, a __ptrace_may_access()
		 * racing with this change may be able to attach to a task it
		 * shouldn't be able to attach to (as if the task had dropped
		 * privileges without becoming nondumpable).
		 * Pairs with a read barrier in __ptrace_may_access().
		 */
		smp_wmb();
	}

	/* alter the thread keyring */
	if (!uid_eq(new->fsuid, old->fsuid))
		key_fsuid_changed(new);
	if (!gid_eq(new->fsgid, old->fsgid))
		key_fsgid_changed(new);

	/* do it
	 * RLIMIT_NPROC limits on user->processes have already been checked
	 * in set_user().
	 */
	if (new->user != old->user || new->user_ns != old->user_ns)
		inc_rlimit_ucounts(new->ucounts, UCOUNT_RLIMIT_NPROC, 1);
	rcu_assign_pointer(task->real_cred, new);
	rcu_assign_pointer(task->cred, new);
	if (!cred_guard_task_publish_transition(&cred_transition, where))
		AUTH_GUARD_FAIL_STOP();
	/*
	 * From here the transition has observable side effects beyond the
	 * credential pointers (dumpability, pdeath_signal, keyrings, ucounts
	 * and pending LSM child state). A late guard failure is an invariant
	 * violation, not a clean syscall rejection or partial rollback path.
	 */
	if (finish_task_transition && cred_transition.coordinator_open &&
	    !auth_guard_task_finish_transition_where(task, where))
		AUTH_GUARD_FAIL_STOP();
	if (new->user != old->user || new->user_ns != old->user_ns)
		dec_rlimit_ucounts(old->ucounts, UCOUNT_RLIMIT_NPROC, 1);

	/* send notifications */
	if (!uid_eq(new->uid,   old->uid)  ||
	    !uid_eq(new->euid,  old->euid) ||
	    !uid_eq(new->suid,  old->suid) ||
	    !uid_eq(new->fsuid, old->fsuid))
		proc_id_connector(task, PROC_EVENT_UID);

	if (!gid_eq(new->gid,   old->gid)  ||
	    !gid_eq(new->egid,  old->egid) ||
	    !gid_eq(new->sgid,  old->sgid) ||
	    !gid_eq(new->fsgid, old->fsgid))
		proc_id_connector(task, PROC_EVENT_GID);

	/* release the old obj and subj refs both */
	put_cred_many(old, 2);
	return 0;
}

/**
 * commit_creds_in_task_transition_where - Install credentials in a transition
 * @new: The credentials to be assigned
 * @detached_lsm: Receives pending LSM payload ownership for deferred release
 * @where: Guard diagnostic and provenance label for this credential edge
 *
 * Like commit_creds_where(), but requires the caller to have already opened a
 * task authority transition for the current task.  The caller is responsible
 * for publishing any other guarded task edges and then finishing or aborting
 * the transition.
 */
int commit_creds_in_task_transition_where(
	struct cred *new, struct auth_guard_task_lsm_request *detached_lsm,
	const char *where)
{
	if (!where)
		where = __func__;

	return commit_creds_apply_in_task_transition(
		new, detached_lsm, where, false);
}
EXPORT_SYMBOL(commit_creds_in_task_transition_where);

/**
 * commit_creds_where - Install new credentials upon the current task
 * @new: The credentials to be assigned
 * @where: Guard diagnostic and provenance label for this transition
 *
 * Install a new set of credentials to the current task, using RCU to replace
 * the old set.  Both the objective and the subjective credentials pointers are
 * updated.  This function may not be called if the subjective credentials are
 * in an overridden state.
 *
 * This function eats the caller's reference to the new credentials, including
 * when guard verification rejects the transition.
 *
 * Return: 0 on success, -EINVAL if the prepared credential fails credential
 * guard verification, or -EACCES if the current task authority guard rejects
 * the replacement before publication.
 */
int commit_creds_where(struct cred *new, const char *where)
{
	struct auth_guard_task_lsm_request detached_lsm;
	struct task_struct *task = current;
	int ret;

	if (!where)
		where = __func__;
	if (!new)
		return -EINVAL;

	if (!cred_guard_task_begin_consuming_transition_where(task, where)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EACCES;
	}

	ret = commit_creds_apply_in_task_transition(
		new, &detached_lsm, where, true);
	if (ret)
		auth_guard_task_abort_transition_where(task, where);
	else
		lsm_ns_release_pending_child_request(&detached_lsm);
	return ret;
}
EXPORT_SYMBOL(commit_creds_where);

/**
 * commit_creds - Install new credentials upon the current task
 * @new: The credentials to be assigned
 *
 * See commit_creds_where().
 */
#undef commit_creds
int commit_creds(struct cred *new)
{
	return commit_creds_where(new, __func__);
}
EXPORT_SYMBOL(commit_creds);

/**
 * commit_prepared_cred - Finalize prepared credentials for later reuse
 * @new: The prepared credentials to finalize
 *
 * Verify the current task authority and that @new came from a trusted
 * credential constructor, then convert it into an immutable committed
 * credential without attaching it to the current task.  This is for
 * kernel-owned service/cache credentials that are prepared, mutated, stored,
 * and later borrowed with override_creds().
 *
 * This function eats the caller's reference when guard verification rejects the
 * prepared credential.  On success, the caller keeps its original reference and
 * owns a committed credential object.
 *
 * Return: 0 on success, -EINVAL if guard verification rejects @new, or
 * -EACCES if the current task authority guard rejects the finalization.
 */
int commit_prepared_cred(struct cred *new)
{
	const char *where = __func__;

	if (!new)
		return -EINVAL;

	if (!cred_guard_verify_current_task(where)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EACCES;
	}
	if (!cred_guard_validate_prepared_consuming(new, where))
		return -EINVAL;
	if (!auth_guard_task_check_where(current, where)) {
		cred_guard_reject_prepared_cred(new, where);
		return -EACCES;
	}

	cred_guard_finalize_commit_cred(new);
	return 0;
}
EXPORT_SYMBOL(commit_prepared_cred);

/**
 * abort_creds - Discard a set of credentials and unlock the current task
 * @new: The credentials that were going to be applied
 *
 * Discard a set of credentials that were under construction and unlock the
 * current task.
 */
void abort_creds(struct cred *new)
{
	kdebug("abort_creds(%p{%ld})", new,
	       atomic_long_read(&new->usage));

	BUG_ON(atomic_long_read(&new->usage) < 1);
	if (!cred_guard_clear_prepared_cred(new, __func__))
		return;
	put_cred(new);
}
EXPORT_SYMBOL(abort_creds);

/**
 * cred_fscmp - Compare two credentials with respect to filesystem access.
 * @a: The first credential
 * @b: The second credential
 *
 * cred_cmp() will return zero if both credentials have the same
 * fsuid, fsgid, and supplementary groups.  That is, if they will both
 * provide the same access to files based on mode/uid/gid.
 * If the credentials are different, then either -1 or 1 will
 * be returned depending on whether @a comes before or after @b
 * respectively in an arbitrary, but stable, ordering of credentials.
 *
 * Return: -1, 0, or 1 depending on comparison
 */
int cred_fscmp(const struct cred *a, const struct cred *b)
{
	struct group_info *ga, *gb;
	int g;

	if (a == b)
		return 0;
	if (uid_lt(a->fsuid, b->fsuid))
		return -1;
	if (uid_gt(a->fsuid, b->fsuid))
		return 1;

	if (gid_lt(a->fsgid, b->fsgid))
		return -1;
	if (gid_gt(a->fsgid, b->fsgid))
		return 1;

	ga = a->group_info;
	gb = b->group_info;
	if (ga == gb)
		return 0;
	if (ga == NULL)
		return -1;
	if (gb == NULL)
		return 1;
	if (ga->ngroups < gb->ngroups)
		return -1;
	if (ga->ngroups > gb->ngroups)
		return 1;

	for (g = 0; g < ga->ngroups; g++) {
		if (gid_lt(ga->gid[g], gb->gid[g]))
			return -1;
		if (gid_gt(ga->gid[g], gb->gid[g]))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(cred_fscmp);

int set_cred_ucounts(struct cred *new)
{
	struct ucounts *new_ucounts, *old_ucounts;

	if (!cred_guard_verify_prepared_cred(new))
		return -EACCES;
	old_ucounts = new->ucounts;

	/*
	 * This optimization is needed because alloc_ucounts() uses locks
	 * for table lookups.
	 */
	if (old_ucounts->ns == new->user_ns && uid_eq(old_ucounts->uid, new->uid))
		return 0;

	if (!(new_ucounts = alloc_ucounts(new->user_ns, new->uid)))
		return -EAGAIN;

	new->ucounts = new_ucounts;
	put_ucounts(old_ucounts);

	return 0;
}

/*
 * initialise the credentials stuff
 */
void __init cred_init(void)
{
	/* allocate a slab in which we can store credentials */
	cred_jar = KMEM_CACHE(cred,
			      SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT);
}

/**
 * prepare_kernel_cred - Prepare a set of credentials for a kernel service
 * @daemon: A userspace daemon to be used as a reference
 *
 * Prepare a set of credentials for a kernel service.  This can then be used to
 * override a task's own credentials so that work can be done on behalf of that
 * task that requires a different subjective context.
 *
 * @daemon is used to provide a base cred, with the security data derived from
 * that; if this is "&init_task", they'll be set to 0, no groups, full
 * capabilities, and no keys.
 *
 * The caller may change these controls afterwards if desired.
 *
 * Returns the new credentials or NULL if out of memory.
 */
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	if (WARN_ON_ONCE(!daemon))
		return NULL;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	old = get_task_cred(daemon);
	if (!cred_guard_verify_committed_cred(old))
		goto error_old;

	*new = *old;
	new->non_rcu = 0;
	atomic_long_set(&new->usage, 1);
	cred_guard_reset_cred(new);
	get_uid(new->user);
	get_user_ns(new->user_ns);
	get_group_info(new->group_info);

#ifdef CONFIG_KEYS
	new->session_keyring = NULL;
	new->process_keyring = NULL;
	new->thread_keyring = NULL;
	new->request_key_auth = NULL;
	new->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
#endif

#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif
	new->ucounts = get_ucounts(new->ucounts);
	if (!new->ucounts)
		goto error;

	if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	if (!cred_guard_prepare_transfer(new, old))
		goto error;
	put_cred(old);
	return new;

error:
	abort_creds(new);
	put_cred(old);
	return NULL;
error_old:
	put_cred(old);
	kmem_cache_free(cred_jar, new);
	return NULL;
}
EXPORT_SYMBOL(prepare_kernel_cred);

/**
 * override_creds - Override the current process's subjective credentials
 * @override_cred: The credentials to be assigned
 *
 * Install an alternative subjective credential set for the current task.  This
 * function returns the subjective credentials that were active before the
 * override so that revert_creds() can restore them later.
 */
const struct cred *override_creds(const struct cred *override_cred)
{
	struct cred_guard_task_transition transition;
	const struct cred *old;

	if (!cred_guard_begin_subjective_cred_transition(override_cred, &transition,
							 __func__))
		BUG();

	get_cred(override_cred);
	old = rcu_replace_pointer(current->cred, override_cred, 1);
	if (!cred_guard_finish_subjective_cred_transition(&transition, __func__))
		BUG();
	return old;
}
EXPORT_SYMBOL(override_creds);

/**
 * override_creds_from_prepared - Commit and override subjective credentials
 * @override_cred: The prepared credentials to commit and assign
 *
 * This is the narrow helper for prepare-mutate-immediate-override call sites.
 * Long-lived credentials must be finalized with commit_prepared_cred() before
 * storage and later passed through override_creds().
 *
 * This function eats the caller's prepared reference when guard verification
 * rejects the transition before publication.  On success, the caller's
 * prepared reference is consumed by publishing it as the subjective reference.
 * A transient reference is held while finalizing and swapping the credentials.
 * After publication, guard failures are invariant violations and BUG like
 * override_creds().
 *
 * Return: the previously active subjective credentials on success, or %NULL if
 * guard verification rejects @override_cred before publication.
 */
const struct cred *override_creds_from_prepared(struct cred *override_cred)
{
	struct cred_guard_task_transition transition;
	const struct cred *old;
	const char *where = __func__;

	if (!override_cred)
		return NULL;

	if (!cred_guard_validate_prepared_consuming(override_cred, where))
		return NULL;
	if (!cred_guard_task_begin_consuming_transition_where(current, where)) {
		cred_guard_reject_prepared_cred(override_cred, where);
		return NULL;
	}
	/*
	 * Preserve non_rcu for task-synchronous immediate overrides such as
	 * access_override_creds().  get_cred() intentionally clears non_rcu for
	 * external references, but this transient reference never escapes.
	 */
	atomic_long_inc(&override_cred->usage);
	cred_guard_finalize_commit_cred(override_cred);
	if (!cred_guard_task_prepare_transition(current, current_real_cred(),
						override_cred, false, &transition, where)) {
		AUTH_GUARD_FAIL_STOP();
	}
	old = rcu_replace_pointer(current->cred,
				  (const struct cred *)override_cred, 1);
	put_cred(override_cred);
	if (!cred_guard_finish_subjective_cred_transition(&transition, where))
		BUG();
	return old;
}
EXPORT_SYMBOL(override_creds_from_prepared);

/**
 * revert_creds - Revert a subjective credential override
 * @revert_cred: The credentials to restore
 *
 * Restore a subjective credential pointer previously returned by
 * override_creds().  The replaced override credential is returned.
 */
const struct cred *revert_creds(const struct cred *revert_cred)
{
	struct cred_guard_task_transition transition;
	const struct cred *old;

	if (!cred_guard_begin_subjective_cred_transition(revert_cred, &transition,
							 __func__))
		BUG();

	old = rcu_replace_pointer(current->cred, revert_cred, 1);
	if (!cred_guard_finish_subjective_cred_transition(&transition, __func__))
		BUG();
	return old;
}
EXPORT_SYMBOL(revert_creds);

/**
 * set_security_override - Set the security ID in a set of credentials
 * @new: The credentials to alter
 * @secid: The LSM security ID to set
 *
 * Set the LSM security ID in a set of credentials so that the subjective
 * security is overridden when an alternative set of credentials is used.
 */
int set_security_override(struct cred *new, u32 secid)
{
	if (!cred_guard_verify_prepared_cred(new))
		return -EACCES;

	return security_kernel_act_as(new, secid);
}
EXPORT_SYMBOL(set_security_override);

/**
 * set_security_override_from_ctx - Set the security ID in a set of credentials
 * @new: The credentials to alter
 * @secctx: The LSM security context to generate the security ID from.
 *
 * Set the LSM security ID in a set of credentials so that the subjective
 * security is overridden when an alternative set of credentials is used.  The
 * security ID is specified in string form as a security context to be
 * interpreted by the LSM.
 */
int set_security_override_from_ctx(struct cred *new, const char *secctx)
{
	u32 secid;
	int ret;

	ret = security_secctx_to_secid(secctx, strlen(secctx), &secid);
	if (ret < 0)
		return ret;

	return set_security_override(new, secid);
}
EXPORT_SYMBOL(set_security_override_from_ctx);

/**
 * set_create_files_as - Set the LSM file create context in a set of credentials
 * @new: The credentials to alter
 * @inode: The inode to take the context from
 *
 * Change the LSM file creation context in a set of credentials to be the same
 * as the object context of the specified inode, so that the new inodes have
 * the same MAC context as that inode.
 */
int set_create_files_as(struct cred *new, struct inode *inode)
{
	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EINVAL;
	if (!cred_guard_verify_prepared_cred(new))
		return -EACCES;

	new->fsuid = inode->i_uid;
	new->fsgid = inode->i_gid;
	return security_kernel_create_files_as(new, inode);
}
EXPORT_SYMBOL(set_create_files_as);
