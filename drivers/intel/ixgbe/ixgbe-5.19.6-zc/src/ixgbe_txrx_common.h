/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 1999 - 2023 Intel Corporation */

#ifndef _IXGBE_TXRX_COMMON_H_
#define _IXGBE_TXRX_COMMON_H_

#define IXGBE_TXD_CMD (IXGBE_TXD_CMD_EOP | \
		      IXGBE_TXD_CMD_RS)

#define IXGBE_XDP_PASS		0
#define IXGBE_XDP_CONSUMED	BIT(0)
#define IXGBE_XDP_TX		BIT(1)
#define IXGBE_XDP_REDIR		BIT(2)

#define IXGBE_PKT_HDR_PAD	(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))

void ixgbe_xdp_ring_update_tail(struct ixgbe_ring *ring);
void ixgbe_xdp_ring_update_tail_locked(struct ixgbe_ring *ring);

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_FRAME_STRUCT
int ixgbe_xmit_xdp_ring(struct ixgbe_ring *ring, struct xdp_frame *xdpf);
#else
int ixgbe_xmit_xdp_ring(struct ixgbe_ring *ring, struct xdp_buff *xdp);
#endif
#ifdef HAVE_AF_XDP_ZC_SUPPORT
void ixgbe_txrx_ring_disable(struct ixgbe_adapter *adapter, int ring);
void ixgbe_txrx_ring_enable(struct ixgbe_adapter *adapter, int ring);

#ifndef HAVE_NETDEV_BPF_XSK_POOL
struct xdp_umem *ixgbe_xsk_umem(struct ixgbe_adapter *adapter,
				struct ixgbe_ring *ring);
int ixgbe_xsk_umem_setup(struct ixgbe_adapter *adapter, struct xdp_umem *umem,
			 u16 qid);
#else
struct xsk_buff_pool *ixgbe_xsk_umem(struct ixgbe_adapter *adapter,
				     struct ixgbe_ring *ring);
int ixgbe_xsk_umem_setup(struct ixgbe_adapter *adapter, struct xsk_buff_pool *umem,
			 u16 qid);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 cleaned_count);
void ixgbe_zca_free(struct zero_copy_allocator *alloc, unsigned long handle);
#else
bool ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 cleaned_count);
#endif
int ixgbe_clean_rx_irq_zc(struct ixgbe_q_vector *q_vector,
			  struct ixgbe_ring *rx_ring,
			  const int budget);
void ixgbe_xsk_clean_rx_ring(struct ixgbe_ring *rx_ring);
bool ixgbe_clean_xdp_tx_irq(struct ixgbe_q_vector *q_vector,
			    struct ixgbe_ring *tx_ring);
#ifdef HAVE_NDO_XSK_WAKEUP
int ixgbe_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags);
#else
int ixgbe_xsk_async_xmit(struct net_device *dev, u32 queue_id);
#endif
void ixgbe_xsk_clean_tx_ring(struct ixgbe_ring *tx_ring);
bool ixgbe_xsk_any_rx_ring_enabled(struct ixgbe_adapter *adapter);
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* HAVE_XDP_SUPPORT */

bool ixgbe_cleanup_headers(struct ixgbe_ring __maybe_unused *rx_ring,
			   union ixgbe_adv_rx_desc *rx_desc,
			   struct sk_buff *skb);
void ixgbe_process_skb_fields(struct ixgbe_ring *rx_ring,
			      union ixgbe_adv_rx_desc *rx_desc,
			      struct sk_buff *skb);
void ixgbe_rx_skb(struct ixgbe_q_vector *q_vector,
		  struct ixgbe_ring *rx_ring,
		  union ixgbe_adv_rx_desc *rx_desc,
		  struct sk_buff *skb);

void ixgbe_irq_rearm_queues(struct ixgbe_adapter *adapter, u64 qmask);
#endif /* _IXGBE_TXRX_COMMON_H_ */
