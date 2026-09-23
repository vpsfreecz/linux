/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_AUTH_CONTRACT_H
#define _LINUX_AUTH_CONTRACT_H

#include <linux/auth_guard_types.h>
#include <linux/errno.h>
#include <linux/types.h>

/*
 * Regions whose measured value the authority-transition contract depends on.
 * The store records at most one expected value per region; a consumer
 * compares a fresh measurement against the recorded value and fails closed
 * when the region was never recorded.
 */
enum auth_expectation_region {
	AUTH_EXPECTATION_REGION_GUARD_TEXT = 0,
	AUTH_EXPECTATION_REGION_GUARD_RODATA,
	AUTH_EXPECTATION_REGION_CONTRACT_TABLE,
	AUTH_EXPECTATION_REGION_POLICY,
	AUTH_EXPECTATION_REGION_COUNT,
};

/*
 * Where a recorded expectation came from.  LEXICAL means it was measured from
 * the running image at first boot (no external root configured, so the
 * "externally measured" claim does not hold); EXTERNAL means it was rooted
 * outside the node (TPM/PCR-sealed policy or a control-plane-signed
 * manifest).
 */
enum auth_expectation_source {
	AUTH_EXPECTATION_SOURCE_NONE = 0,
	AUTH_EXPECTATION_SOURCE_LEXICAL,
	AUTH_EXPECTATION_SOURCE_EXTERNAL,
};

struct auth_expectation {
	u64 hash;
	u32 len;
	u16 region;
	u16 source;
};

/*
 * A store instance.  The live store is a global in .data..ro_after_init; the
 * instance form exists so tests can exercise the semantics without touching
 * the live store.
 */
struct auth_expectation_store {
	struct auth_expectation entries[AUTH_EXPECTATION_REGION_COUNT];
	bool sealed;
};

#ifndef CONFIG_AUTH_EXPECTATION

static inline int auth_expectation_record(enum auth_expectation_region region,
					  u64 hash, u32 len,
					  enum auth_expectation_source source)
{
	return -EOPNOTSUPP;
}

static inline int auth_expectation_lookup(enum auth_expectation_region region,
					  struct auth_expectation *out)
{
	return -ENOENT;
}

static inline bool auth_expectation_sealed(void)
{
	return true;
}

#else

int auth_expectation_record(enum auth_expectation_region region, u64 hash,
			    u32 len, enum auth_expectation_source source);
int auth_expectation_lookup(enum auth_expectation_region region,
			    struct auth_expectation *out);
bool auth_expectation_sealed(void);

#endif /* CONFIG_AUTH_EXPECTATION */

int auth_expectation_store_record(struct auth_expectation_store *store,
				  enum auth_expectation_region region, u64 hash,
				  u32 len, enum auth_expectation_source source);
int auth_expectation_store_lookup(const struct auth_expectation_store *store,
				  enum auth_expectation_region region,
				  struct auth_expectation *out);
bool auth_expectation_store_sealed(const struct auth_expectation_store *store);
void auth_expectation_store_seal(struct auth_expectation_store *store);

/*
 * The contract table describes the transitions a template may take.  Rows are
 * authored by the control plane and loaded with the template; the stamp seals
 * the table the kernel actually uses, and the expectations recorded at boot
 * bind that table to the image.
 */
enum auth_contract_leaf {
	AUTH_CONTRACT_LEAF_UNKNOWN = 0,
	AUTH_CONTRACT_LEAF_ALLOWED,
	AUTH_CONTRACT_LEAF_FORBIDDEN,
};

struct auth_transition_row {
	u8 kind;
	u8 subject_class;
	u8 root_class;
	u8 trigger;
	u8 caller;
	u8 leaf;
};

struct auth_transition_table {
	u32 template_id;
	u64 generation;
	u32 row_count;
	u64 row_hash;
	struct auth_guard_stamp stamp;
	struct auth_transition_row rows[];
};

#define AUTH_CONTRACT_MAX_ROWS 4096

/*
 * Inventoried classes, kinds and triggers.  A row may only reference values
 * from these sets; anything else is a load error, never a silent rule.  The
 * sets mirror the transition classes in the contract document and grow with
 * the class work; the caller field reuses the subject classes.
 */
enum auth_contract_subject_class {
	AUTH_CONTRACT_SUBJECT_UNKNOWN = 0,
	AUTH_CONTRACT_SUBJECT_TENANT_TASK,
	AUTH_CONTRACT_SUBJECT_TENANT_CONTAINER,
	AUTH_CONTRACT_SUBJECT_GUEST_AGENT,
	AUTH_CONTRACT_SUBJECT_MANAGER,
	AUTH_CONTRACT_SUBJECT_KERNEL_INTERNAL,
	AUTH_CONTRACT_SUBJECT_CLASS_COUNT,
};

enum auth_contract_root_class {
	AUTH_CONTRACT_ROOT_UNKNOWN = 0,
	AUTH_CONTRACT_ROOT_CONTAINER_CRED,
	AUTH_CONTRACT_ROOT_CONTAINER_NSPROXY,
	AUTH_CONTRACT_ROOT_CONTAINER_CGROUP,
	AUTH_CONTRACT_ROOT_CONTAINER_SECCOMP,
	AUTH_CONTRACT_ROOT_CONTAINER_FILES,
	AUTH_CONTRACT_ROOT_CONTAINER_MOUNT,
	AUTH_CONTRACT_ROOT_HOST_CRED,
	AUTH_CONTRACT_ROOT_HOST_NSPROXY,
	AUTH_CONTRACT_ROOT_HOST_CGROUP,
	AUTH_CONTRACT_ROOT_HOST_SECCOMP,
	AUTH_CONTRACT_ROOT_HOST_FILES,
	AUTH_CONTRACT_ROOT_HOST_MODULE,
	AUTH_CONTRACT_ROOT_HOST_LSM_HOOK,
	AUTH_CONTRACT_ROOT_HOST_BPF,
	AUTH_CONTRACT_ROOT_CLASS_COUNT,
};

enum auth_contract_kind {
	AUTH_CONTRACT_KIND_UNKNOWN = 0,
	AUTH_CONTRACT_KIND_CRED_COMMIT,
	AUTH_CONTRACT_KIND_CRED_OVERRIDE,
	AUTH_CONTRACT_KIND_EXEC_FINALIZE,
	AUTH_CONTRACT_KIND_FORK_COPY,
	AUTH_CONTRACT_KIND_TASK_EXIT,
	AUTH_CONTRACT_KIND_NS_CREATE,
	AUTH_CONTRACT_KIND_NS_JOIN,
	AUTH_CONTRACT_KIND_NS_DETACH,
	AUTH_CONTRACT_KIND_MOUNT_ROOT,
	AUTH_CONTRACT_KIND_CGROUP_MEMBERSHIP,
	AUTH_CONTRACT_KIND_CGROUP_NS_ROOT,
	AUTH_CONTRACT_KIND_SECCOMP_INSTALL,
	AUTH_CONTRACT_KIND_SECCOMP_SYNC,
	AUTH_CONTRACT_KIND_SECCOMP_DETACH,
	AUTH_CONTRACT_KIND_FILES_COPY,
	AUTH_CONTRACT_KIND_FILES_REPLACE,
	AUTH_CONTRACT_KIND_SELINUX_BLOB,
	AUTH_CONTRACT_KIND_OUTER_IDENTITY,
	AUTH_CONTRACT_KIND_BOOT_ROOT_PUBLISH,
	AUTH_CONTRACT_KIND_LATE_BINDING,
	AUTH_CONTRACT_KIND_LIFECYCLE_EVENT,
	AUTH_CONTRACT_KIND_FD_TRANSFER,
	AUTH_CONTRACT_KIND_COUNT,
};

enum auth_contract_trigger {
	AUTH_CONTRACT_TRIGGER_UNKNOWN = 0,
	AUTH_CONTRACT_TRIGGER_CLONE,
	AUTH_CONTRACT_TRIGGER_UNSHARE,
	AUTH_CONTRACT_TRIGGER_SETNS,
	AUTH_CONTRACT_TRIGGER_MOUNT,
	AUTH_CONTRACT_TRIGGER_PIVOT_ROOT,
	AUTH_CONTRACT_TRIGGER_EXECVE,
	AUTH_CONTRACT_TRIGGER_FORK,
	AUTH_CONTRACT_TRIGGER_EXIT,
	AUTH_CONTRACT_TRIGGER_SETGROUPS,
	AUTH_CONTRACT_TRIGGER_COMMIT_CREDS,
	AUTH_CONTRACT_TRIGGER_OVERRIDE_CREDS,
	AUTH_CONTRACT_TRIGGER_REVERT_CREDS,
	AUTH_CONTRACT_TRIGGER_CGROUP_ATTACH,
	AUTH_CONTRACT_TRIGGER_SECCOMP_FILTER,
	AUTH_CONTRACT_TRIGGER_SECCOMP_TSYNC,
	AUTH_CONTRACT_TRIGGER_SECCOMP_DETACH,
	AUTH_CONTRACT_TRIGGER_DUP_FD,
	AUTH_CONTRACT_TRIGGER_SCM_RIGHTS,
	AUTH_CONTRACT_TRIGGER_PIDFD_GETFD,
	AUTH_CONTRACT_TRIGGER_BPF_ATTACH,
	AUTH_CONTRACT_TRIGGER_MODULE_LOAD,
	AUTH_CONTRACT_TRIGGER_KERNEL_INTERNAL,
	AUTH_CONTRACT_TRIGGER_COUNT,
};

static inline bool
auth_contract_is_tenant_class(enum auth_contract_subject_class klass)
{
	return klass == AUTH_CONTRACT_SUBJECT_TENANT_TASK ||
		klass == AUTH_CONTRACT_SUBJECT_TENANT_CONTAINER;
}

static inline bool
auth_contract_is_host_root_class(enum auth_contract_root_class klass)
{
	return klass >= AUTH_CONTRACT_ROOT_HOST_CRED &&
		klass < AUTH_CONTRACT_ROOT_CLASS_COUNT;
}

int auth_contract_table_seal(struct auth_transition_table *table);
int auth_contract_table_verify(const struct auth_transition_table *table);
int auth_contract_row_check(const struct auth_transition_row *row);
int auth_contract_load(const struct auth_transition_table *table);

/*
 * A transition instance.  The fields are classes, never identities: the
 * subject carries the sealed template identity, roots is the bitmask of the
 * root classes the transition touches, and the stamps are the authority
 * stamps on both sides of the change.
 */
struct auth_subject {
	u64 container_id;
	u64 template_id;
	u8 userns_level;
	u8 lifecycle;
	u8 klass;
	u64 seal;
};

struct auth_transition_tuple {
	u8 kind;
	u8 trigger;
	u8 caller;
	u32 roots;
	struct auth_subject subject;
	struct auth_guard_stamp old;
	struct auth_guard_stamp new;
};

/*
 * The judge's verdict for one transition instance: declared, forbidden, or
 * undeclared (unknown).  Unknown has a defined, non-fatal path at the call
 * site; it is never a silent pass.
 */
enum auth_contract_verdict {
	AUTH_VERDICT_UNKNOWN = 0,
	AUTH_VERDICT_DECLARED,
	AUTH_VERDICT_FORBIDDEN,
};

int auth_contract_table_publish(struct auth_transition_table *table);
const struct auth_transition_table *auth_contract_table_get(void);
unsigned long auth_contract_row_count(unsigned int index);
enum auth_contract_verdict
auth_contract_judge(const struct auth_transition_tuple *tuple);

#endif /* _LINUX_AUTH_CONTRACT_H */
