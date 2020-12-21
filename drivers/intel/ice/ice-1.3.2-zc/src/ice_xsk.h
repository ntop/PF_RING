/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_XSK_H_
#define _ICE_XSK_H_
#include "ice_txrx.h"
#include "ice.h"

struct ice_vsi;

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef CONFIG_XDP_SOCKETS
int ice_xsk_umem_setup(struct ice_vsi *vsi, struct xdp_umem *umem, u16 qid);
int ice_xsk_umem_query(struct ice_vsi *vsi, struct xdp_umem **umem, u16 qid);
void ice_zca_free(struct zero_copy_allocator *zca, unsigned long handle);
int ice_clean_rx_irq_zc(struct ice_ring *rx_ring, int budget);
bool ice_clean_tx_irq_zc(struct ice_ring *xdp_ring);
#ifdef HAVE_NDO_XSK_WAKEUP
int ice_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags);
#else
int ice_xsk_async_xmit(struct net_device *netdev, u32 queue_id);
#endif /* HAVE_NDO_XSK_WAKEUP */
bool ice_alloc_rx_bufs_slow_zc(struct ice_ring *rx_ring, u16 count);
bool ice_xsk_any_rx_ring_ena(struct ice_vsi *vsi);
void ice_xsk_clean_rx_ring(struct ice_ring *rx_ring);
void ice_xsk_clean_xdp_ring(struct ice_ring *xdp_ring);
#else
static inline int
ice_xsk_umem_setup(struct ice_vsi __always_unused *vsi,
		   struct xdp_umem __always_unused *umem,
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}

static inline int
ice_xsk_umem_query(struct ice_vsi __always_unused *vsi,
		   struct xdp_umem __always_unused **umem,
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}

static inline void
ice_zca_free(struct zero_copy_allocator __always_unused *zca,
	     unsigned long __always_unused handle)
{
}

static inline int
ice_clean_rx_irq_zc(struct ice_ring __always_unused *rx_ring,
		    int __always_unused budget)
{
	return 0;
}

static inline bool
ice_clean_tx_irq_zc(struct ice_ring __always_unused *xdp_ring)
{
	return false;
}

static inline bool
ice_alloc_rx_bufs_slow_zc(struct ice_ring __always_unused *rx_ring,
			  u16 __always_unused count)
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

#define ice_xsk_clean_rx_ring(rx_ring) do {} while (0)
#define ice_xsk_clean_xdp_ring(xdp_ring) do {} while (0)
#endif /* CONFIG_XDP_SOCKETS */
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* !_ICE_XSK_H_ */
