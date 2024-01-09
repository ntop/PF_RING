/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#ifndef _I40E_XSK_H_
#define _I40E_XSK_H_

#ifdef HAVE_AF_XDP_ZC_SUPPORT

/* This value should match the pragma in the loop_unrolled_for
 * macro. Why 4? It is strictly empirical. It seems to be a good
 * compromise between the advantage of having simultaneous outstanding
 * reads to the DMA array that can hide each others latency and the
 * disadvantage of having a larger code path.
 */
#define PKTS_PER_BATCH 4

#if __GNUC__ >= 8
#define loop_unrolled_for _Pragma("GCC unroll 4") for
#else
#define loop_unrolled_for for
#endif

struct i40e_vsi;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
struct xsk_buff_pool;
#else
struct xdp_umem;
#endif /*HAVE_NETDEV_BPF_XSK_POOL */
struct zero_copy_allocator;

int i40e_queue_pair_disable(struct i40e_vsi *vsi, int queue_pair);
int i40e_queue_pair_enable(struct i40e_vsi *vsi, int queue_pair);
#ifndef NO_XDP_QUERY_XSK_UMEM
int i40e_xsk_umem_query(struct i40e_vsi *vsi, struct xdp_umem **umem,
			u16 qid);
#endif /* NO_XDP_QUERY_XSK_UMEM */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
int i40e_xsk_pool_setup(struct i40e_vsi *vsi, struct xsk_buff_pool *pool,
			u16 qid);
#else
int i40e_xsk_umem_setup(struct i40e_vsi *vsi, struct xdp_umem *umem,
			u16 qid);
#endif /* HAVE_NETDEV_BFP_XSK_POOL */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void i40e_zca_free(struct zero_copy_allocator *alloc, unsigned long handle);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

bool i40e_alloc_rx_buffers_zc(struct i40e_ring *rx_ring, u16 cleaned_count);
int i40e_clean_rx_irq_zc(struct i40e_ring *rx_ring, int budget);

bool i40e_clean_xdp_tx_irq(struct i40e_vsi *vsi, struct i40e_ring *tx_ring);
#ifdef HAVE_NDO_XSK_WAKEUP
int i40e_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags);
#else
int i40e_xsk_async_xmit(struct net_device *dev, u32 queue_id);
#endif /* HAVE_NDO_XSK_WAKEUP */

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
int i40e_alloc_rx_bi_zc(struct i40e_ring *rx_ring);
void i40e_clear_rx_bi_zc(struct i40e_ring *rx_ring);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

#endif /* HAVE_AF_XDP_SUPPORT */
#endif /* _I40E_XSK_H_ */

