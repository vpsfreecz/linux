/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#ifndef _SELINUX_AVC_SS_H_
#define _SELINUX_AVC_SS_H_

#include <linux/types.h>
#include "security.h"

int avc_ss_reset_state(struct selinux_state *state, u32 seqno);

static inline int avc_ss_reset(u32 seqno)
{
	return avc_ss_reset_state(&selinux_state, seqno);
}

/* Class/perm mapping support */
struct security_class_mapping {
	const char *name;
	const char *perms[sizeof(u32) * 8 + 1];
};

extern const struct security_class_mapping secclass_map[];

#endif /* _SELINUX_AVC_SS_H_ */
