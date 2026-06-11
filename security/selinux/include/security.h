/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Security server interface.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 *
 */

#ifndef _SELINUX_SECURITY_H_
#define _SELINUX_SECURITY_H_

#include <linux/compiler.h>
#include <linux/dcache.h>
#include <linux/magic.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include "flask.h"
#include "policycap.h"

#define SECSID_NULL   0x00000000 /* unspecified SID */
#define SECSID_WILD   0xffffffff /* wildcard SID */
#define SECCLASS_NULL 0x0000 /* no class */

/* Identify specific policy version changes */
#define POLICYDB_VERSION_BASE		     15
#define POLICYDB_VERSION_BOOL		     16
#define POLICYDB_VERSION_IPV6		     17
#define POLICYDB_VERSION_NLCLASS	     18
#define POLICYDB_VERSION_VALIDATETRANS	     19
#define POLICYDB_VERSION_MLS		     19
#define POLICYDB_VERSION_AVTAB		     20
#define POLICYDB_VERSION_RANGETRANS	     21
#define POLICYDB_VERSION_POLCAP		     22
#define POLICYDB_VERSION_PERMISSIVE	     23
#define POLICYDB_VERSION_BOUNDARY	     24
#define POLICYDB_VERSION_FILENAME_TRANS	     25
#define POLICYDB_VERSION_ROLETRANS	     26
#define POLICYDB_VERSION_NEW_OBJECT_DEFAULTS 27
#define POLICYDB_VERSION_DEFAULT_TYPE	     28
#define POLICYDB_VERSION_CONSTRAINT_NAMES    29
#define POLICYDB_VERSION_XPERMS_IOCTL	     30
#define POLICYDB_VERSION_INFINIBAND	     31
#define POLICYDB_VERSION_GLBLUB		     32
#define POLICYDB_VERSION_COMP_FTRANS	     33 /* compressed filename transitions */
#define POLICYDB_VERSION_COND_XPERMS	     34 /* extended permissions in conditional policies */
#define POLICYDB_VERSION_NEVERAUDIT	     35 /* neveraudit types */

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX POLICYDB_VERSION_NEVERAUDIT

/* Mask for just the mount related flags */
#define SE_MNTMASK 0x1f
/* Super block security struct flags for mount options */
/* BE CAREFUL, these need to be the low order bits for selinux_get_mnt_opts */
#define CONTEXT_MNT	0x01
#define FSCONTEXT_MNT	0x02
#define ROOTCONTEXT_MNT 0x04
#define DEFCONTEXT_MNT	0x08
#define OUTERCONTEXT_MNT 0x10
#define SBLABEL_MNT	0x20
/* Non-mount related flags */
#define SE_SBINITIALIZED 0x0100
#define SE_SBPROC	 0x0200
#define SE_SBGENFS	 0x0400
#define SE_SBGENFS_XATTR 0x0800
#define SE_SBNATIVE	 0x1000

#define CONTEXT_STR	"context"
#define FSCONTEXT_STR	"fscontext"
#define ROOTCONTEXT_STR "rootcontext"
#define DEFCONTEXT_STR	"defcontext"
#define OUTERCONTEXT_STR "outercontext"
#define SECLABEL_STR	"seclabel"

struct netlbl_lsm_secattr;

extern int selinux_enabled_boot;

/*
 * type_datum properties
 * available at the kernel policy version >= POLICYDB_VERSION_BOUNDARY
 */
#define TYPEDATUM_PROPERTY_PRIMARY   0x0001
#define TYPEDATUM_PROPERTY_ATTRIBUTE 0x0002

/* limitation of boundary depth  */
#define POLICYDB_BOUNDS_MAXDEPTH 4

struct selinux_policy;
struct selinux_state;
struct selinux_avc;

struct selinux_state {
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	bool enforcing;
#endif
	bool initialized;
	bool child_policy_load_allowed;
	bool policycap[__POLICYDB_CAP_MAX];

	struct page *status_page;
	struct mutex status_lock;

	struct selinux_policy __rcu *policy;
	struct selinux_avc *avc;
	struct mutex policy_mutex;
	struct mutex children_lock; /* Protect direct child-state tracking. */
	struct list_head children; /* Direct child SELinux states. */
	struct list_head sibling; /* Node in parent->children. */
	struct selinux_state *parent;
	refcount_t count;
	struct work_struct work;
} __randomize_layout;

void selinux_avc_init(void);

extern struct selinux_state selinux_state;

int selinux_state_create(struct selinux_state *parent,
			 struct selinux_state **state);
void __put_selinux_state(struct selinux_state *state);
void selinux_state_sync_child_enforcing_state(struct selinux_state *parent,
					      bool enforcing);

static inline struct selinux_state *get_selinux_state(struct selinux_state *state)
{
	if (state && state != &selinux_state)
		refcount_inc(&state->count);
	return state;
}

static inline void put_selinux_state(struct selinux_state *state)
{
	if (state && state != &selinux_state &&
	    refcount_dec_and_test(&state->count))
		__put_selinux_state(state);
}

static inline bool selinux_initialized(void)
{
	/* do a synchronized load to avoid race conditions */
	return smp_load_acquire(&selinux_state.initialized);
}

static inline bool selinux_initialized_state(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	return smp_load_acquire(&state->initialized);
}

/*
 * Child SELinux states still interpret the shared host object model through
 * raw SIDs unless an object carries explicit state identity alongside them.
 */
static inline bool selinux_state_shares_object_model(const struct selinux_state *state)
{
	return state && state != &selinux_state;
}

static inline bool selinux_state_freezes_raw_network_sid_carriers(const struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	/*
	 * NetLabel, XFRM packet peer labels, request/flow secids, and datagram
	 * peer secid export still move through raw networking APIs with no attached
	 * SELinux state identity.  Keep those carriers host-global or frozen when a
	 * child SELinux state is active.
	 */
	return selinux_state_shares_object_model(state);
}

static inline u32 selinux_state_raw_network_sid(const struct selinux_state *state,
						      u32 sid)
{
	if (!state)
		state = &selinux_state;

	/*
	 * The remaining packet/secmark/netpeer/XFRM carriers still have no attached
	 * SELinux state identity.  When a child state has to project a socket or
	 * packet subject onto that host-global network plane, pin it to the shared
	 * unlabeled carrier instead of exporting a raw child-state SID.
	 */
	if (selinux_state_freezes_raw_network_sid_carriers(state))
		return SECINITSID_UNLABELED;

	return sid;
}

static inline u32 selinux_state_host_network_object_sid(const struct selinux_state *state,
						      u32 sid)
{
	if (!state)
		state = &selinux_state;

	/*
	 * The netport/netif/netnode policy tables are still host-owned objects with
	 * no explicit SELinux state sidecar.  When a child state hits those checks,
	 * pin the socket subject to the shared unlabeled carrier instead of
	 * comparing raw child-state SIDs against host-global network object labels.
	 */
	return selinux_state_raw_network_sid(state, sid);
}

static inline void selinux_mark_initialized(void)
{
	/* do a synchronized write to avoid race conditions */
	smp_store_release(&selinux_state.initialized, true);
}

static inline void selinux_mark_initialized_state(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	smp_store_release(&state->initialized, true);
}

static inline bool selinux_state_allows_runtime_policy_mutation(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	/*
	 * Child SELinux states currently reuse the host object model.  Allow the
	 * initial parent-policy clone into an uninitialized child state, but block
	 * later policy mutations until per-object state tracking exists.
	 *
	 * Parent-state mutation while pinned children exist is guarded separately in
	 * the security-server helpers.
	 */
	return !state->parent || !selinux_initialized_state(state);
}

static inline bool selinux_state_allows_runtime_policy_load(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	if (!state->parent)
		return true;
	if (!selinux_initialized_state(state))
		return true;

	return READ_ONCE(state->child_policy_load_allowed);
}

static inline void selinux_state_allow_child_policy_load(struct selinux_state *state)
{
	if (state && state->parent)
		WRITE_ONCE(state->child_policy_load_allowed, true);
}

static inline void selinux_state_clear_child_policy_load(struct selinux_state *state)
{
	if (state && state->parent)
		WRITE_ONCE(state->child_policy_load_allowed, false);
}

static inline bool selinux_state_child_policy_load_pending(struct selinux_state *state)
{
	if (!state || !state->parent || !selinux_initialized_state(state))
		return false;

	return READ_ONCE(state->child_policy_load_allowed);
}

static inline bool selinux_state_allows_runtime_enforcing_change(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	/*
	 * Empty child SELinux states still mirror their parent during bootstrap.
	 * After the first policy load, a child state owns its AVC/enforcing view
	 * and can switch between enforcing and permissive without mutating the
	 * policy or boolean tables that remain frozen separately.
	 */
	return !state->parent || selinux_initialized_state(state);
}

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static inline bool enforcing_enabled(void)
{
	return READ_ONCE(selinux_state.enforcing);
}

static inline bool enforcing_enabled_state(struct selinux_state *state)
{
	if (!state)
		state = &selinux_state;

	return READ_ONCE(state->enforcing);
}

static inline void enforcing_set(bool value)
{
	WRITE_ONCE(selinux_state.enforcing, value);
}

static inline void enforcing_set_state(struct selinux_state *state, bool value)
{
	if (!state)
		state = &selinux_state;

	WRITE_ONCE(state->enforcing, value);
}
#else
static inline bool enforcing_enabled(void)
{
	return true;
}

static inline bool enforcing_enabled_state(struct selinux_state *state)
{
	return true;
}

static inline void enforcing_set(bool value)
{
}

static inline void enforcing_set_state(struct selinux_state *state, bool value)
{
}
#endif

static inline bool checkreqprot_get(void)
{
	/* non-zero/true checkreqprot values are no longer supported */
	return 0;
}

static inline bool selinux_policycap_netpeer(void)
{
	return READ_ONCE(selinux_state.policycap[POLICYDB_CAP_NETPEER]);
}

static inline bool selinux_policycap_openperm(void)
{
	return READ_ONCE(selinux_state.policycap[POLICYDB_CAP_OPENPERM]);
}

static inline bool selinux_policycap_extsockclass(void)
{
	return READ_ONCE(selinux_state.policycap[POLICYDB_CAP_EXTSOCKCLASS]);
}

static inline bool selinux_policycap_alwaysnetwork(void)
{
	return READ_ONCE(selinux_state.policycap[POLICYDB_CAP_ALWAYSNETWORK]);
}

static inline bool selinux_policycap_cgroupseclabel(void)
{
	return READ_ONCE(selinux_state.policycap[POLICYDB_CAP_CGROUPSECLABEL]);
}

static inline bool selinux_policycap_nnp_nosuid_transition(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_NNP_NOSUID_TRANSITION]);
}

static inline bool selinux_policycap_genfs_seclabel_symlinks(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS]);
}

static inline bool selinux_policycap_ioctl_skip_cloexec(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_IOCTL_SKIP_CLOEXEC]);
}

static inline bool selinux_policycap_userspace_initial_context(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT]);
}

static inline bool selinux_policycap_netlink_xperm(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_NETLINK_XPERM]);
}

static inline bool selinux_policycap_functionfs_seclabel(void)
{
	return READ_ONCE(
		selinux_state.policycap[POLICYDB_CAP_FUNCTIONFS_SECLABEL]);
}

struct selinux_policy_convert_data;

struct selinux_load_state {
	struct selinux_policy *policy;
	struct selinux_policy_convert_data *convert_data;
};

int security_mls_enabled(void);
int security_mls_enabled_state(struct selinux_state *state);
int security_load_policy(void *data, size_t len,
			 struct selinux_load_state *load_state);
int security_load_policy_state(struct selinux_state *state,
			       void *data, size_t len,
			       struct selinux_load_state *load_state);
void selinux_policy_commit(struct selinux_load_state *load_state);
void selinux_policy_commit_state(struct selinux_state *state,
			       struct selinux_load_state *load_state);
void selinux_policy_cancel(struct selinux_load_state *load_state);
void selinux_policy_cancel_state(struct selinux_state *state,
			       struct selinux_load_state *load_state);
int security_read_policy(void **data, size_t *len);
int security_read_policy_state(struct selinux_state *state,
			      void **data, size_t *len);
int security_read_state_kernel(void **data, size_t *len);
int security_read_state_kernel_state(struct selinux_state *state,
				    void **data, size_t *len);
int security_set_bools_state(struct selinux_state *state,
			     u32 len, const int *values);
int security_get_bool_value_state(struct selinux_state *state, u32 index);
int security_policycap_supported(unsigned int req_cap);
int security_policycap_supported_state(struct selinux_state *state,
			       unsigned int req_cap);

void selinux_policy_free(struct selinux_policy *policy);
void selinux_state_policy_free(struct selinux_state *state);

#define SEL_VEC_MAX 32
struct av_decision {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

#define XPERMS_ALLOWED	  1
#define XPERMS_AUDITALLOW 2
#define XPERMS_DONTAUDIT  4

#define security_xperm_set(perms, x)  ((perms)[(x) >> 5] |= 1 << ((x)&0x1f))
#define security_xperm_test(perms, x) (1 & ((perms)[(x) >> 5] >> ((x)&0x1f)))
struct extended_perms_data {
	u32 p[8];
};

struct extended_perms_decision {
	u8 used;
	u8 driver;
	u8 base_perm;
	struct extended_perms_data *allowed;
	struct extended_perms_data *auditallow;
	struct extended_perms_data *dontaudit;
};

struct extended_perms {
	u16 len; /* length associated decision chain */
	u8 base_perms; /* which base permissions are covered */
	struct extended_perms_data drivers; /* flag drivers that are used */
};

/* definitions of av_decision.flags */
#define AVD_FLAGS_PERMISSIVE 0x0001
#define AVD_FLAGS_NEVERAUDIT  0x0002

void security_compute_av_state(struct selinux_state *state,
			      u32 ssid, u32 tsid, u16 tclass,
			      struct av_decision *avd,
			      struct extended_perms *xperms);

static inline void security_compute_av(u32 ssid, u32 tsid, u16 tclass,
			       struct av_decision *avd,
			       struct extended_perms *xperms)
{
	security_compute_av_state(&selinux_state, ssid, tsid, tclass, avd,
				  xperms);
}

void security_compute_xperms_decision_state(struct selinux_state *state,
				    u32 ssid, u32 tsid, u16 tclass,
				    u8 driver, u8 base_perm,
				    struct extended_perms_decision *xpermd);

static inline void security_compute_xperms_decision(u32 ssid, u32 tsid,
				     u16 tclass, u8 driver, u8 base_perm,
				     struct extended_perms_decision *xpermd)
{
	security_compute_xperms_decision_state(&selinux_state, ssid, tsid,
				       tclass, driver, base_perm, xpermd);
}

void security_compute_av_user_state(struct selinux_state *state,
			   u32 ssid, u32 tsid, u16 tclass,
			   struct av_decision *avd);

static inline void security_compute_av_user(u32 ssid, u32 tsid, u16 tclass,
			       struct av_decision *avd)
{
	security_compute_av_user_state(&selinux_state, ssid, tsid, tclass,
			       avd);
}

int security_transition_sid_state(struct selinux_state *state,
				      u32 ssid, u32 tsid, u16 tclass,
				      const struct qstr *qstr, u32 *out_sid);

static inline int security_transition_sid(u32 ssid, u32 tsid, u16 tclass,
				     const struct qstr *qstr, u32 *out_sid)
{
	return security_transition_sid_state(&selinux_state, ssid, tsid,
					     tclass, qstr, out_sid);
}

int security_transition_sid_user_state(struct selinux_state *state,
					   u32 ssid, u32 tsid, u16 tclass,
					   const char *objname, u32 *out_sid);

static inline int security_transition_sid_user(u32 ssid, u32 tsid, u16 tclass,
					       const char *objname, u32 *out_sid)
{
	return security_transition_sid_user_state(&selinux_state, ssid, tsid,
						   tclass, objname, out_sid);
}

int security_member_sid_state(struct selinux_state *state,
				      u32 ssid, u32 tsid, u16 tclass,
				      u32 *out_sid);

static inline int security_member_sid(u32 ssid, u32 tsid, u16 tclass,
				      u32 *out_sid)
{
	return security_member_sid_state(&selinux_state, ssid, tsid, tclass,
					 out_sid);
}

int security_change_sid_state(struct selinux_state *state,
				      u32 ssid, u32 tsid, u16 tclass,
				      u32 *out_sid);

static inline int security_change_sid(u32 ssid, u32 tsid, u16 tclass,
				      u32 *out_sid)
{
	return security_change_sid_state(&selinux_state, ssid, tsid, tclass,
					 out_sid);
}

int security_sid_to_context_state(struct selinux_state *state,
				  u32 sid, char **scontext,
				  u32 *scontext_len);

static inline int security_sid_to_context(u32 sid, char **scontext,
					 u32 *scontext_len)
{
	return security_sid_to_context_state(&selinux_state, sid, scontext,
				     scontext_len);
}

int security_sid_to_context_force_state(struct selinux_state *state,
					u32 sid, char **scontext,
					u32 *scontext_len);

static inline int security_sid_to_context_force(u32 sid, char **scontext,
				       u32 *scontext_len)
{
	return security_sid_to_context_force_state(&selinux_state, sid,
				   scontext, scontext_len);
}

int security_sid_to_context_inval_state(struct selinux_state *state,
					u32 sid, char **scontext,
					u32 *scontext_len);

static inline int security_sid_to_context_inval(u32 sid, char **scontext,
				       u32 *scontext_len)
{
	return security_sid_to_context_inval_state(&selinux_state, sid,
				   scontext, scontext_len);
}

int security_context_to_sid_state(struct selinux_state *state,
				  const char *scontext,
				  u32 scontext_len,
				  u32 *out_sid, gfp_t gfp);

static inline int security_context_to_sid(const char *scontext,
				  u32 scontext_len,
				  u32 *out_sid, gfp_t gfp)
{
	return security_context_to_sid_state(&selinux_state, scontext,
				     scontext_len, out_sid, gfp);
}

int security_context_str_to_sid_state(struct selinux_state *state,
				      const char *scontext,
				      u32 *out_sid, gfp_t gfp);

static inline int security_context_str_to_sid(const char *scontext,
				      u32 *out_sid, gfp_t gfp)
{
	return security_context_str_to_sid_state(&selinux_state, scontext,
				 out_sid, gfp);
}

int security_context_to_sid_default_state(struct selinux_state *state,
					  const char *scontext,
					  u32 scontext_len,
					  u32 *out_sid,
					  u32 def_sid,
					  gfp_t gfp_flags);

static inline int security_context_to_sid_default(const char *scontext,
				  u32 scontext_len,
				  u32 *out_sid, u32 def_sid,
				  gfp_t gfp_flags)
{
	return security_context_to_sid_default_state(&selinux_state, scontext,
				     scontext_len, out_sid,
				     def_sid, gfp_flags);
}

int security_context_to_sid_force_state(struct selinux_state *state,
					const char *scontext,
					u32 scontext_len,
					u32 *sid);

static inline int security_context_to_sid_force(const char *scontext,
				u32 scontext_len, u32 *sid)
{
	return security_context_to_sid_force_state(&selinux_state, scontext,
				   scontext_len, sid);
}

int security_get_user_sids_state(struct selinux_state *state,
				 u32 fromsid, const char *username,
				 u32 **sids, u32 *nel);

static inline int security_get_user_sids(u32 fromsid, const char *username,
				      u32 **sids, u32 *nel)
{
	return security_get_user_sids_state(&selinux_state, fromsid, username,
					     sids, nel);
}

int security_port_sid(u8 protocol, u16 port, u32 *out_sid);

int security_ib_pkey_sid(u64 subnet_prefix, u16 pkey_num, u32 *out_sid);

int security_ib_endport_sid(const char *dev_name, u8 port_num, u32 *out_sid);

int security_netif_sid(const char *name, u32 *if_sid);

int security_node_sid(u16 domain, const void *addr, u32 addrlen, u32 *out_sid);

int security_validate_transition_state(struct selinux_state *state,
				       u32 oldsid, u32 newsid, u32 tasksid,
				       u16 tclass);

static inline int security_validate_transition(u32 oldsid, u32 newsid,
					      u32 tasksid, u16 tclass)
{
	return security_validate_transition_state(&selinux_state, oldsid,
						 newsid, tasksid, tclass);
}

int security_validate_transition_user_state(struct selinux_state *state,
					    u32 oldsid, u32 newsid,
					    u32 tasksid, u16 tclass);

static inline int security_validate_transition_user(u32 oldsid, u32 newsid,
						   u32 tasksid, u16 tclass)
{
	return security_validate_transition_user_state(&selinux_state, oldsid,
						      newsid, tasksid, tclass);
}

int security_bounded_transition(u32 old_sid, u32 new_sid);
int security_bounded_transition_state(struct selinux_state *state,
			      u32 old_sid, u32 new_sid);

int security_sid_mls_copy_state(struct selinux_state *state, u32 sid,
			       u32 mls_sid, u32 *new_sid);

static inline int security_sid_mls_copy(u32 sid, u32 mls_sid, u32 *new_sid)
{
	return security_sid_mls_copy_state(&selinux_state, sid, mls_sid,
					   new_sid);
}

int security_net_peersid_resolve(u32 nlbl_sid, u32 nlbl_type, u32 xfrm_sid,
				 u32 *peer_sid);

int security_get_classes(struct selinux_policy *policy, char ***classes,
			 u32 *nclasses);
int security_get_permissions(struct selinux_policy *policy, const char *class,
			     char ***perms, u32 *nperms);
int security_get_reject_unknown_state(struct selinux_state *state);
int security_get_allow_unknown_state(struct selinux_state *state);

static inline int security_get_reject_unknown(void)
{
	return security_get_reject_unknown_state(&selinux_state);
}

static inline int security_get_allow_unknown(void)
{
	return security_get_allow_unknown_state(&selinux_state);
}

#define SECURITY_FS_USE_XATTR	 1 /* use xattr */
#define SECURITY_FS_USE_TRANS	 2 /* use transition SIDs, e.g. devpts/tmpfs */
#define SECURITY_FS_USE_TASK	 3 /* use task SIDs, e.g. pipefs/sockfs */
#define SECURITY_FS_USE_GENFS	 4 /* use the genfs support */
#define SECURITY_FS_USE_NONE	 5 /* no labeling support */
#define SECURITY_FS_USE_MNTPOINT 6 /* use mountpoint labeling */
#define SECURITY_FS_USE_NATIVE	 7 /* use native label support */
#define SECURITY_FS_USE_MAX	 7 /* Highest SECURITY_FS_USE_XXX */

int security_fs_use_state(struct selinux_state *state, struct super_block *sb);

int security_genfs_sid(const char *fstype, const char *path, u16 sclass,
		       u32 *sid);

int selinux_policy_genfs_sid(struct selinux_policy *policy, const char *fstype,
			     const char *path, u16 sclass, u32 *sid);

#ifdef CONFIG_NETLABEL
int security_netlbl_secattr_to_sid(struct netlbl_lsm_secattr *secattr,
				   u32 *sid);

int security_netlbl_sid_to_secattr(u32 sid, struct netlbl_lsm_secattr *secattr);
#else
static inline int
security_netlbl_secattr_to_sid(struct netlbl_lsm_secattr *secattr, u32 *sid)
{
	return -EIDRM;
}

static inline int
security_netlbl_sid_to_secattr(u32 sid, struct netlbl_lsm_secattr *secattr)
{
	return -ENOENT;
}
#endif /* CONFIG_NETLABEL */

const char *security_get_initial_sid_context(u32 sid);

/*
 * status notifier using mmap interface
 */
extern struct page *selinux_kernel_status_page(void);
extern struct page *selinux_kernel_status_page_state(struct selinux_state *state);

#define SELINUX_KERNEL_STATUS_VERSION 1
struct selinux_kernel_status {
	u32 version; /* version number of the structure */
	u32 sequence; /* sequence number of seqlock logic */
	u32 enforcing; /* current setting of enforcing mode */
	u32 policyload; /* times of policy reloaded */
	u32 deny_unknown; /* current setting of deny_unknown */
	/*
	 * The version > 0 supports above members.
	 */
} __packed;

extern void selinux_status_update_setenforce(bool enforcing);
extern void selinux_status_update_setenforce_state(struct selinux_state *state,
				   bool enforcing);
extern void selinux_status_update_policyload(u32 seqno);
extern void selinux_status_update_policyload_state(struct selinux_state *state,
				  u32 seqno);
extern void selinux_complete_init(void);
extern struct path selinux_null;
extern void selnl_notify_setenforce(int val);
extern void selnl_notify_policyload(u32 seqno);
extern int selinux_nlmsg_lookup(u16 sclass, u16 nlmsg_type, u32 *perm);

extern void avtab_cache_init(void);
extern void ebitmap_cache_init(void);
extern void hashtab_cache_init(void);
int security_sidtab_hash_stats_state(struct selinux_state *state,
				     char *page);
extern int security_sidtab_hash_stats(char *page);

#endif /* _SELINUX_SECURITY_H_ */
