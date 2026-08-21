/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_VPSADMINOS_LIVEPATCH_H
#define _LINUX_VPSADMINOS_LIVEPATCH_H

#ifdef CONFIG_LIVEPATCH
#define VPSADMINOS_NFS_FREE_STATEID_CONTROL_SHADOW_ID	0xbbddece21d1ee29bUL
#define VPSADMINOS_NFS_FREE_STATEID_DATA_SHADOW_ID	0x32127145199df290UL
#define VPSADMINOS_NFS_FREE_STATEID_STATE_ID		0x95e5fe7fc76a656bUL
#endif

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_XFRM)
int vpsadminos_xfrm_livepatch_pre_patch(void);
void vpsadminos_xfrm_livepatch_post_patch(void);
void vpsadminos_xfrm_livepatch_pre_unpatch(void);
#else
static inline int vpsadminos_xfrm_livepatch_pre_patch(void)
{
	return 0;
}

static inline void vpsadminos_xfrm_livepatch_post_patch(void)
{
}

static inline void vpsadminos_xfrm_livepatch_pre_unpatch(void)
{
}
#endif

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_NETFILTER)
void vpsadminos_nfqueue_livepatch_post_patch(void);
void vpsadminos_nfqueue_livepatch_post_unpatch(void);
#else
static inline void vpsadminos_nfqueue_livepatch_post_patch(void)
{
}

static inline void vpsadminos_nfqueue_livepatch_post_unpatch(void)
{
}
#endif

#ifdef CONFIG_LIVEPATCH
void vpsadminos_pipapo_livepatch_cleanup(void);
#endif

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_X86_64)
struct rhashtable_iter;

int vpsadminos_livepatch_text_poke_cmpxchg64(void *addr, u64 old, u64 new);
int vpsadminos_rhashtable_walk_start_check(struct rhashtable_iter *iter);
int vpsadminos_rhashtable_livepatch_pre_patch(void);
void vpsadminos_rhashtable_livepatch_post_patch(void);
void vpsadminos_rhashtable_livepatch_post_unpatch(void);
#else
static inline int vpsadminos_rhashtable_livepatch_pre_patch(void)
{
	return 0;
}

static inline void vpsadminos_rhashtable_livepatch_post_patch(void)
{
}

static inline void vpsadminos_rhashtable_livepatch_post_unpatch(void)
{
}
#endif

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_X86) && \
	defined(CONFIG_MITIGATION_SRSO)
void error_entry(void);
void paranoid_entry(void);
void vpsadminos_saferet_paranoid_srso(void);
void vpsadminos_saferet_paranoid_alias(void);
void vpsadminos_saferet_error_srso(void);
void vpsadminos_saferet_error_alias(void);
int vpsadminos_saferet_livepatch_pre_patch(void);
void vpsadminos_saferet_livepatch_post_patch(void);
void vpsadminos_saferet_livepatch_post_unpatch(void);
#else
static inline int vpsadminos_saferet_livepatch_pre_patch(void)
{
	return 0;
}

static inline void vpsadminos_saferet_livepatch_post_patch(void)
{
}

static inline void vpsadminos_saferet_livepatch_post_unpatch(void)
{
}
#endif

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_SUNRPC)
int vpsadminos_sunrpc_livepatch_pre_patch(void);
void vpsadminos_sunrpc_livepatch_post_patch(void);
void vpsadminos_sunrpc_livepatch_pre_unpatch(void);
void vpsadminos_sunrpc_livepatch_post_unpatch(void);
#else
static inline int vpsadminos_sunrpc_livepatch_pre_patch(void)
{
	return 0;
}

static inline void vpsadminos_sunrpc_livepatch_post_patch(void)
{
}

static inline void vpsadminos_sunrpc_livepatch_pre_unpatch(void)
{
}

static inline void vpsadminos_sunrpc_livepatch_post_unpatch(void)
{
}
#endif

#endif
