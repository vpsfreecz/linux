/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_VPSADMINOS_LIVEPATCH_H
#define _LINUX_VPSADMINOS_LIVEPATCH_H

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
