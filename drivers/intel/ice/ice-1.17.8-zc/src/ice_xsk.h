/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_XSK_H_
#define _ICE_XSK_H_
#include "ice_txrx.h"
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#include <net/xdp_sock_drv.h>
#endif

struct ice_vsi;

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef CONFIG_XDP_SOCKETS
#ifdef HAVE_NETDEV_BPF_XSK_POOL
int ice_xsk_pool_setup(struct ice_vsi *vsi, struct xsk_buff_pool *pool,
		       u16 qid);
#else
int ice_xsk_umem_setup(struct ice_vsi *vsi, struct xdp_umem *umem,
		       u16 qid);
#endif
#ifndef NO_XDP_QUERY_XSK_UMEM
int ice_xsk_umem_query(struct ice_vsi *vsi, struct xdp_umem **umem, u16 qid);
#endif
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void ice_zca_free(struct zero_copy_allocator *zca, unsigned long handle);
#endif
int ice_clean_rx_irq_zc(struct ice_rx_ring *rx_ring, int budget);
bool ice_clean_tx_irq_zc(struct ice_tx_ring *xdp_ring);
#ifdef HAVE_NDO_XSK_WAKEUP
int ice_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags);
#else
int ice_xsk_async_xmit(struct net_device *netdev, u32 queue_id);
#endif /* HAVE_NDO_XSK_WAKEUP */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
bool ice_alloc_rx_bufs_slow_zc(struct ice_rx_ring *rx_ring, u16 count);
#else
bool ice_alloc_rx_bufs_zc(struct ice_rx_ring *rx_ring, int count);
#endif
bool ice_xsk_any_rx_ring_ena(struct ice_vsi *vsi);
void ice_xsk_clean_rx_ring(struct ice_rx_ring *rx_ring);
void ice_xsk_clean_xdp_ring(struct ice_tx_ring *xdp_ring);
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
int ice_realloc_zc_buf(struct ice_vsi *vsi, bool zc);
#endif
#else
static inline int
#ifdef HAVE_NETDEV_BPF_XSK_POOL
ice_xsk_pool_setup(struct ice_vsi __always_unused *vsi,
		   struct xsk_buff_pool __always_unused *pool,
#else
ice_xsk_umem_setup(struct ice_vsi __always_unused *vsi,
		   struct xdp_umem __always_unused *umem,
#endif
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}

#ifndef NO_XDP_QUERY_XSK_UMEM
static inline int
ice_xsk_umem_query(struct ice_vsi __always_unused *vsi,
		   struct xdp_umem __always_unused **umem,
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}
#endif

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
static inline void
ice_zca_free(struct zero_copy_allocator __always_unused *zca,
	     unsigned long __always_unused handle)
{
}
#endif

static inline int
ice_clean_rx_irq_zc(struct ice_rx_ring __always_unused *rx_ring,
		    int __always_unused budget)
{
	return 0;
}

static inline bool
ice_clean_tx_irq_zc(struct ice_tx_ring __always_unused *xdp_ring)
{
	return false;
}

static inline bool
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
ice_alloc_rx_bufs_slow_zc(struct ice_rx_ring __always_unused *rx_ring,
			  u16 __always_unused count)
#else
ice_alloc_rx_bufs_zc(struct ice_rx_ring __always_unused *rx_ring,
		     u16 __always_unused count)
#endif
{
	return false;
}

static inline bool ice_xsk_any_rx_ring_ena(struct ice_vsi __always_unused *vsi)
{
	return false;
}

#ifdef HAVE_NDO_XSK_WAKEUP
static inline int
ice_xsk_wakeup(struct net_device __always_unused *netdev,
	       u32 __always_unused queue_id, u32 __always_unused flags)
{
	return -EOPNOTSUPP;
}
#else
static inline int
ice_xsk_async_xmit(struct net_device __always_unused *netdev,
		   u32 __always_unused queue_id)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_NDO_XSK_WAKEUP */

static inline void ice_xsk_clean_rx_ring(struct ice_rx_ring *rx_ring) { }
static inline void ice_xsk_clean_xdp_ring(struct ice_tx_ring *xdp_ring) { }

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
static inline int ice_realloc_zc_buf(struct ice_vsi __always_unused *vsi,
				     bool __always_unused zc)
{
	return 0;
}
#endif

#endif /* CONFIG_XDP_SOCKETS */
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* !_ICE_XSK_H_ */
