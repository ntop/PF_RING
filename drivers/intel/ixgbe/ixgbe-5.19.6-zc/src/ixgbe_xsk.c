/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 1999 - 2023 Intel Corporation */

#include "ixgbe.h"

#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf_trace.h>
#endif
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#include <net/xdp_sock.h>
#else
#include <net/xdp_sock_drv.h>
#endif
#endif
#ifdef HAVE_XDP_BUFF_RXQ
#include <net/xdp.h>
#endif

#include "ixgbe_txrx_common.h"

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef HAVE_NETDEV_BPF_XSK_POOL
struct xdp_umem *ixgbe_xsk_umem(struct ixgbe_adapter *adapter,
				struct ixgbe_ring *ring)
#else
struct xsk_buff_pool *ixgbe_xsk_umem(struct ixgbe_adapter *adapter,
				     struct ixgbe_ring *ring)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
{
	bool xdp_on = READ_ONCE(adapter->xdp_prog);
	int qid = ring->ring_idx;

	if (!adapter->xsk_pools || !adapter->xsk_pools[qid] ||
	    qid >= adapter->num_xsk_pools || !xdp_on ||
	    !test_bit(qid, adapter->af_xdp_zc_qps))
		return NULL;

	return adapter->xsk_pools[qid];
}

static int ixgbe_alloc_xsk_umems(struct ixgbe_adapter *adapter)
{
	if (adapter->xsk_pools)
		return 0;

	adapter->num_xsk_pools_used = 0;
	adapter->num_xsk_pools = adapter->num_rx_queues;
	adapter->xsk_pools = kcalloc(adapter->num_xsk_pools,
				     sizeof(*adapter->xsk_pools),
				     GFP_KERNEL);
	if (!adapter->xsk_pools) {
		adapter->num_xsk_pools = 0;
		return -ENOMEM;
	}

	return 0;
}

/**
 * ixgbe_xsk_any_rx_ring_enabled - Checks if Rx rings have AF_XDP UMEM attached
 * @adapter: adapter
 *
 * Returns true if any of the Rx rings has an AF_XDP UMEM attached
 **/
bool ixgbe_xsk_any_rx_ring_enabled(struct ixgbe_adapter *adapter)
{
	int i;

	if (!adapter->xsk_pools)
		return false;

	for (i = 0; i < adapter->num_xsk_pools; i++) {
		if (adapter->xsk_pools[i])
			return true;
	}

	return false;
}

#ifndef HAVE_NETDEV_BPF_XSK_POOL
static int ixgbe_add_xsk_umem(struct ixgbe_adapter *adapter,
			      struct xdp_umem *pool,
			      u16 qid)
#else
static int ixgbe_add_xsk_umem(struct ixgbe_adapter *adapter,
			      struct xsk_buff_pool *pool,
			      u16 qid)
#endif
{
	int err;

	err = ixgbe_alloc_xsk_umems(adapter);
	if (err)
		return err;

	adapter->xsk_pools[qid] = pool;
	adapter->num_xsk_pools_used++;

	return 0;
}

static void ixgbe_remove_xsk_umem(struct ixgbe_adapter *adapter, u16 qid)
{
	adapter->xsk_pools[qid] = NULL;
	adapter->num_xsk_pools_used--;

	if (adapter->num_xsk_pools == 0) {
		kfree(adapter->xsk_pools);
		adapter->xsk_pools = NULL;
		adapter->num_xsk_pools = 0;
	}
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
static int ixgbe_xsk_umem_dma_map(struct ixgbe_adapter *adapter,
				  struct xdp_umem *pool)
{
	struct device *dev = &adapter->pdev->dev;
	unsigned int i, j;
	dma_addr_t dma;

	for (i = 0; i < pool->npgs; i++) {
		dma = dma_map_page_attrs(dev, pool->pgs[i], 0, PAGE_SIZE,
					 DMA_BIDIRECTIONAL, IXGBE_RX_DMA_ATTR);
		if (dma_mapping_error(dev, dma))
			goto out_unmap;

		pool->pages[i].dma = dma;
	}

	return 0;

out_unmap:
	for (j = 0; j < i; j++) {
		dma_unmap_page_attrs(dev, pool->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, IXGBE_RX_DMA_ATTR);
		pool->pages[i].dma = 0;
	}

	return -1;
}

static void ixgbe_xsk_umem_dma_unmap(struct ixgbe_adapter *adapter,
				     struct xdp_umem *pool)
{
	struct device *dev = &adapter->pdev->dev;
	unsigned int i;

	for (i = 0; i < pool->npgs; i++) {
		dma_unmap_page_attrs(dev, pool->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, IXGBE_RX_DMA_ATTR);

		pool->pages[i].dma = 0;
	}
}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

#ifndef HAVE_NETDEV_BPF_XSK_POOL
static int ixgbe_xsk_umem_enable(struct ixgbe_adapter *adapter,
				 struct xdp_umem *pool,
				 u16 qid)
#else
static int ixgbe_xsk_umem_enable(struct ixgbe_adapter *adapter,
				 struct xsk_buff_pool *pool,
				 u16 qid)
#endif
{
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_umem_fq_reuse *reuseq;
#endif
	bool if_running;
	int err;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;

	if (adapter->xsk_pools) {
		if (qid >= adapter->num_xsk_pools)
			return -EINVAL;
		if (adapter->xsk_pools[qid])
			return -EBUSY;
	}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	reuseq = xsk_reuseq_prepare(adapter->rx_ring[0]->count);
	if (!reuseq)
		return -ENOMEM;

	xsk_reuseq_free(xsk_reuseq_swap(pool, reuseq));

	err = ixgbe_xsk_umem_dma_map(adapter, pool);
#else
	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, IXGBE_RX_DMA_ATTR);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	if (err)
		return err;

	if_running = netif_running(adapter->netdev) &&
		     READ_ONCE(adapter->xdp_prog);

	if (if_running)
		ixgbe_txrx_ring_disable(adapter, qid);

	set_bit(qid, adapter->af_xdp_zc_qps);
	err = ixgbe_add_xsk_umem(adapter, pool, qid);
	if (err)
		return err;

	if (if_running) {
		ixgbe_txrx_ring_enable(adapter, qid);

		/* Kick start the NAPI context so that receiving will start */
#ifdef HAVE_NDO_XSK_WAKEUP
		err = ixgbe_xsk_wakeup(adapter->netdev, qid, XDP_WAKEUP_RX);
#else
		err = ixgbe_xsk_async_xmit(adapter->netdev, qid);
#endif
		if (err)
			return err;
	}

	return 0;
}

static int ixgbe_xsk_umem_disable(struct ixgbe_adapter *adapter, u16 qid)
{
	bool if_running;

	if (!adapter->xsk_pools || qid >= adapter->num_xsk_pools ||
	    !adapter->xsk_pools[qid])
		return -EINVAL;

	if_running = netif_running(adapter->netdev) &&
		     READ_ONCE(adapter->xdp_prog);

	if (if_running)
		ixgbe_txrx_ring_disable(adapter, qid);

	clear_bit(qid, adapter->af_xdp_zc_qps);

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	ixgbe_xsk_umem_dma_unmap(adapter, adapter->xsk_pools[qid]);
#else
	xsk_pool_dma_unmap(adapter->xsk_pools[qid], IXGBE_RX_DMA_ATTR);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	ixgbe_remove_xsk_umem(adapter, qid);

	if (if_running)
		ixgbe_txrx_ring_enable(adapter, qid);

	return 0;
}

#ifndef HAVE_NETDEV_BPF_XSK_POOL
int ixgbe_xsk_umem_setup(struct ixgbe_adapter *adapter, struct xdp_umem *pool,
			 u16 qid)
#else
int ixgbe_xsk_umem_setup(struct ixgbe_adapter *adapter, struct xsk_buff_pool *pool,
			 u16 qid)
#endif
{
	return pool ? ixgbe_xsk_umem_enable(adapter, pool, qid) :
		ixgbe_xsk_umem_disable(adapter, qid);
}

static int ixgbe_run_xdp_zc(struct ixgbe_adapter *adapter,
			    struct ixgbe_ring *rx_ring,
			    struct xdp_buff *xdp)
{
	int err, result = IXGBE_XDP_PASS;
	struct bpf_prog *xdp_prog;
	struct ixgbe_ring *ring;
	struct xdp_frame *xdpf;
	u32 act;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	act = bpf_prog_run_xdp(xdp_prog, xdp);
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xdp->handle += xdp->data - xdp->data_hard_start;
#endif
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdpf = xdp_convert_buff_to_frame(xdp);
		if (unlikely(!xdpf)) {
			result = IXGBE_XDP_CONSUMED;
			break;
		}
		ring = ixgbe_determine_xdp_ring(adapter);
		if (static_branch_unlikely(&ixgbe_xdp_locking_key))
			spin_lock(&ring->tx_lock);
#ifdef HAVE_XDP_FRAME_STRUCT
		result = ixgbe_xmit_xdp_ring(ring, xdpf);
#else
		result = ixgbe_xmit_xdp_ring(ring, xdp);
#endif /* HAVE_XDP_FRAME_STRUCT */
		if (static_branch_unlikely(&ixgbe_xdp_locking_key))
			spin_unlock(&ring->tx_lock);
		break;
	case XDP_REDIRECT:
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		result = !err ? IXGBE_XDP_REDIR : IXGBE_XDP_CONSUMED;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		/* fallthrough -- handle aborts by dropping packet */
		fallthrough;
	case XDP_DROP:
		result = IXGBE_XDP_CONSUMED;
		break;
	}
	rcu_read_unlock();
	return result;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
static struct
ixgbe_rx_buffer *ixgbe_get_rx_buffer_zc(struct ixgbe_ring *rx_ring,
					unsigned int size)
{
	struct ixgbe_rx_buffer *bi;

	bi = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      bi->dma, 0,
				      size,
				      DMA_BIDIRECTIONAL);

	return bi;
}

static void ixgbe_reuse_rx_buffer_zc(struct ixgbe_ring *rx_ring,
				     struct ixgbe_rx_buffer *obi)
{
	unsigned long mask = (unsigned long)rx_ring->xsk_pool->chunk_mask;
	u64 hr = rx_ring->xsk_pool->headroom + XDP_PACKET_HEADROOM;
	u16 nta = rx_ring->next_to_alloc;
	struct ixgbe_rx_buffer *nbi;

	nbi = &rx_ring->rx_buffer_info[rx_ring->next_to_alloc];
	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	nbi->dma = obi->dma & mask;
	nbi->dma += hr;

	nbi->addr = (void *)((unsigned long)obi->addr & mask);
	nbi->addr += hr;

	nbi->handle = obi->handle & mask;
	nbi->handle += rx_ring->xsk_pool->headroom;

	obi->addr = NULL;
	obi->skb = NULL;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void ixgbe_zca_free(struct zero_copy_allocator *alloc, unsigned long handle)
{
	struct ixgbe_rx_buffer *bi;
	struct ixgbe_ring *rx_ring;
	u64 hr, mask;
	u16 nta;

	rx_ring = container_of(alloc, struct ixgbe_ring, zca);
	hr = rx_ring->xsk_pool->headroom + XDP_PACKET_HEADROOM;
	mask = rx_ring->xsk_pool->chunk_mask;

	nta = rx_ring->next_to_alloc;
	bi = rx_ring->rx_buffer_info;

	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	handle &= mask;

	bi->dma = xdp_umem_get_dma(rx_ring->xsk_pool, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(rx_ring->xsk_pool, handle);
	bi->addr += hr;

	bi->handle = (u64)handle + rx_ring->xsk_pool->headroom;
}
#endif

static bool ixgbe_alloc_buffer_zc(struct ixgbe_ring *rx_ring,
				  struct ixgbe_rx_buffer *bi)
{
#ifndef HAVE_NETDEV_BPF_XSK_POOL
	struct xdp_umem *umem = rx_ring->xsk_pool;
#endif
	void *addr = bi->addr;
	u64 handle, hr;

	if (addr)
		return true;

	if (!xsk_umem_peek_addr(umem, &handle)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	bi->dma = xdp_umem_get_dma(umem, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(umem, handle);
	bi->addr += hr;

	bi->handle = handle + umem->headroom;

	xsk_umem_release_addr(umem);
	return true;
}

static bool ixgbe_alloc_buffer_slow_zc(struct ixgbe_ring *rx_ring,
				       struct ixgbe_rx_buffer *bi)
{
#ifndef HAVE_NETDEV_BPF_XSK_POOL
	struct xdp_umem *pool = rx_ring->xsk_pool;
#else
	struct xsk_buff_pool *pool = rx_ring->xsk_pool;
#endif
	u64 handle, hr;

	if (!xsk_umem_peek_addr_rq(pool, &handle)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	handle &= rx_ring->xsk_pool->chunk_mask;

	hr = pool->headroom + XDP_PACKET_HEADROOM;

	bi->dma = xdp_umem_get_dma(pool, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(pool, handle);
	bi->addr += hr;

	bi->handle = handle + pool->headroom;

	xsk_umem_release_addr_rq(pool);
	return true;
}

static __always_inline bool
__ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 count,
			    bool alloc(struct ixgbe_ring *rx_ring,
				       struct ixgbe_rx_buffer *bi))
#else
bool ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 count)
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
{
	union ixgbe_adv_rx_desc *rx_desc;
	struct ixgbe_rx_buffer *bi;
	u16 i = rx_ring->next_to_use;
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	dma_addr_t dma;
#endif
	bool ok = true;

	/* nothing to do */
	if (!count)
		return true;

	rx_desc = IXGBE_RX_DESC(rx_ring, i);
	bi = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		if (!alloc(rx_ring, bi)) {
#else
		bi->xdp = xsk_buff_alloc(rx_ring->xsk_pool);
		if (!bi->xdp) {
#endif
			ok = false;
			break;
		}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
						 bi->page_offset,
						 rx_ring->rx_buf_len,
						 DMA_BIDIRECTIONAL);
#else
		dma = xsk_buff_xdp_get_dma(bi->xdp);
#endif

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
#else
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
#endif

		rx_desc++;
		bi++;
		i++;
		if (unlikely(!i)) {
			rx_desc = IXGBE_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the length for the next_to_use descriptor */
		rx_desc->wb.upper.length = 0;

		count--;
	} while (count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		/* update next to alloc since we have filled the ring */
		rx_ring->next_to_alloc = i;
#endif

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, rx_ring->tail);
	}

	return ok;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 count)
{
	__ixgbe_alloc_rx_buffers_zc(rx_ring, count,
				    ixgbe_alloc_buffer_slow_zc);
}

static bool ixgbe_alloc_rx_buffers_fast_zc(struct ixgbe_ring *rx_ring,
					   u16 count)
{
	return __ixgbe_alloc_rx_buffers_zc(rx_ring, count,
					   ixgbe_alloc_buffer_zc);
}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

static struct sk_buff *ixgbe_construct_skb_zc(struct ixgbe_ring *rx_ring,
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
					      struct ixgbe_rx_buffer *bi,
					      struct xdp_buff *xdp)
#else
					      struct ixgbe_rx_buffer *bi)
#endif
{
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_buff *xdp_buffer = xdp;
#else
	struct xdp_buff *xdp_buffer = bi->xdp;
#endif
	unsigned int metasize = xdp_buffer->data - xdp_buffer->data_meta;
	unsigned int datasize = xdp_buffer->data_end - xdp_buffer->data;
	struct sk_buff *skb;

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi,
			       xdp_buffer->data_end - xdp_buffer->data_hard_start,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, xdp_buffer->data - xdp_buffer->data_hard_start);
	memcpy(__skb_put(skb, datasize), xdp_buffer->data, datasize);
	if (metasize)
		skb_metadata_set(skb, metasize);
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	ixgbe_reuse_rx_buffer_zc(rx_ring, bi);
#else
	xsk_buff_free(xdp_buffer);
	bi->xdp = NULL;
#endif
	return skb;
}

static void ixgbe_inc_ntc(struct ixgbe_ring *rx_ring)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	prefetch(IXGBE_RX_DESC(rx_ring, ntc));
}

int ixgbe_clean_rx_irq_zc(struct ixgbe_q_vector *q_vector,
			  struct ixgbe_ring *rx_ring,
			  const int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct ixgbe_adapter *adapter = q_vector->adapter;
	u16 cleaned_count = ixgbe_desc_unused(rx_ring);
	unsigned int xdp_res, xdp_xmit = 0;
	bool failure = false;
	struct sk_buff *skb;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_buff xdp;

	xdp.rxq = &rx_ring->xdp_rxq;
#endif

	while (likely(total_rx_packets < budget)) {
		union ixgbe_adv_rx_desc *rx_desc;
		struct ixgbe_rx_buffer *bi;
		unsigned int size;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IXGBE_RX_BUFFER_WRITE) {
			failure = failure ||
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
				  !ixgbe_alloc_rx_buffers_fast_zc(rx_ring,
								  cleaned_count);
#else
				  !ixgbe_alloc_rx_buffers_zc(rx_ring,
							     cleaned_count);
#endif
			cleaned_count = 0;
		}

		rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);
		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (!size)
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		dma_rmb();

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		bi = ixgbe_get_rx_buffer_zc(rx_ring, size);
#else
		bi = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
#endif

		if (unlikely(!ixgbe_test_staterr(rx_desc,
						 IXGBE_RXD_STAT_EOP))) {
			struct ixgbe_rx_buffer *next_bi;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			ixgbe_reuse_rx_buffer_zc(rx_ring, bi);
#else
			xsk_buff_free(bi->xdp);
			bi->xdp = NULL;
#endif
			ixgbe_inc_ntc(rx_ring);
			next_bi =
			       &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			next_bi->skb = ERR_PTR(-EINVAL);
#else
			next_bi->discard = true;
#endif
			continue;
		}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		if (unlikely(bi->skb)) {
			ixgbe_reuse_rx_buffer_zc(rx_ring, bi);
#else
		if (unlikely(bi->discard)) {
			xsk_buff_free(bi->xdp);
			bi->xdp = NULL;
			bi->discard = false;
#endif
			ixgbe_inc_ntc(rx_ring);
			continue;
		}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		xdp.data = bi->addr;
		xdp.data_meta = xdp.data;
		xdp.data_hard_start = xdp.data - XDP_PACKET_HEADROOM;
		xdp.data_end = xdp.data + size;
		xdp.handle = bi->handle;

		xdp_res = ixgbe_run_xdp_zc(adapter, rx_ring, &xdp);
#else
		bi->xdp->data_end = bi->xdp->data + size;
		xsk_buff_dma_sync_for_cpu(bi->xdp, rx_ring->xsk_pool);
		xdp_res = ixgbe_run_xdp_zc(adapter, rx_ring, bi->xdp);
#endif

		if (xdp_res) {
			if (xdp_res & (IXGBE_XDP_TX | IXGBE_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
				bi->addr = NULL;
				bi->skb = NULL;
#endif
			} else {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
				ixgbe_reuse_rx_buffer_zc(rx_ring, bi);
#else
				xsk_buff_free(bi->xdp);
#endif
			}
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
			bi->xdp = NULL;
#endif
			total_rx_packets++;
			total_rx_bytes += size;

			cleaned_count++;
			ixgbe_inc_ntc(rx_ring);
			continue;
		}

		/* XDP_PASS path */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		skb = ixgbe_construct_skb_zc(rx_ring, bi, &xdp);
#else
		skb = ixgbe_construct_skb_zc(rx_ring, bi);
#endif
		if (!skb) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			break;
		}

		cleaned_count++;
		ixgbe_inc_ntc(rx_ring);

		if (eth_skb_pad(skb))
			continue;

		total_rx_bytes += skb->len;
		total_rx_packets++;

		ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
		ixgbe_rx_skb(q_vector, rx_ring, rx_desc, skb);
	}

	if (xdp_xmit & IXGBE_XDP_REDIR)
		xdp_do_flush_map();

	if (xdp_xmit & IXGBE_XDP_TX) {
		struct ixgbe_ring *ring = ixgbe_determine_xdp_ring(adapter);

		ixgbe_xdp_ring_update_tail_locked(ring);
	}

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;

	return failure ? budget : (int)total_rx_packets;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void ixgbe_xsk_clean_rx_ring(struct ixgbe_ring *rx_ring)
{
	u16 i = rx_ring->next_to_clean;
	struct ixgbe_rx_buffer *bi = &rx_ring->rx_buffer_info[i];

	while (i != rx_ring->next_to_alloc) {
		xsk_umem_fq_reuse(rx_ring->xsk_pool, bi->handle);
		i++;
		bi++;
		if (i == rx_ring->count) {
			i = 0;
			bi = rx_ring->rx_buffer_info;
		}
	}
}
#else
void ixgbe_xsk_clean_rx_ring(struct ixgbe_ring *rx_ring)
{
	struct ixgbe_rx_buffer *bi;
	u16 i;

	for (i = 0; i < rx_ring->count; i++) {
		bi = &rx_ring->rx_buffer_info[i];

		if (!bi->xdp)
			continue;

		xsk_buff_free(bi->xdp);
		bi->xdp = NULL;
	}
}
#endif

static bool ixgbe_xmit_zc(struct ixgbe_ring *xdp_ring, unsigned int budget)
{
	unsigned int sent_frames = 0, total_bytes = 0;
	union ixgbe_adv_tx_desc *tx_desc = NULL;
	u16 ntu = xdp_ring->next_to_use;
	struct ixgbe_tx_buffer *tx_bi;
	bool work_done = true;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
	struct xdp_desc desc;
#endif
	dma_addr_t dma;
	u32 cmd_type;
#ifndef XSK_UMEM_RETURNS_XDP_DESC
	u32 len;
#endif

	while (budget-- > 0) {
		if (unlikely(!ixgbe_desc_unused(xdp_ring) ||
			     !netif_carrier_ok(xdp_ring->netdev))) {
			work_done = false;
			break;
		}

#ifdef XSK_UMEM_RETURNS_XDP_DESC
		if (!xsk_tx_peek_desc(xdp_ring->xsk_pool, &desc))
			break;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		dma = xdp_umem_get_dma(xdp_ring->xsk_pool, desc.addr);

		dma_sync_single_for_device(xdp_ring->dev, dma, desc.len,
					   DMA_BIDIRECTIONAL);
#else
		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma,
						 desc.len);
#endif

		tx_bi = &xdp_ring->tx_buffer_info[ntu];
		tx_bi->bytecount = desc.len;
		tx_bi->xdpf = NULL;
#else
		if (!xsk_umem_consume_tx(xdp_ring->xsk_pool, &dma, &len))
			break;

		dma_sync_single_for_device(xdp_ring->dev, dma, len,
					   DMA_BIDIRECTIONAL);

		tx_bi = &xdp_ring->tx_buffer_info[ntu];
		tx_bi->bytecount = len;
		tx_bi->xdpf = NULL;
#endif

		tx_desc = IXGBE_TX_DESC(xdp_ring, ntu);
		tx_desc->read.buffer_addr = cpu_to_le64(dma);

		/* put descriptor type bits */
		cmd_type = IXGBE_ADVTXD_DTYP_DATA |
			   IXGBE_ADVTXD_DCMD_DEXT |
			   IXGBE_ADVTXD_DCMD_IFCS;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
		cmd_type |= desc.len | IXGBE_TXD_CMD_EOP;
		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
		tx_desc->read.olinfo_status =
			cpu_to_le32(desc.len << IXGBE_ADVTXD_PAYLEN_SHIFT);
#else
		cmd_type |= len | IXGBE_TXD_CMD_EOP;
		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
		tx_desc->read.olinfo_status =
			cpu_to_le32(len << IXGBE_ADVTXD_PAYLEN_SHIFT);
#endif

		xdp_ring->next_rs_idx = ntu;
		ntu++;
		if (ntu == xdp_ring->count)
			ntu = 0;
		xdp_ring->next_to_use = ntu;

		sent_frames++;
		total_bytes += tx_bi->bytecount;
	}

	if (tx_desc) {
		/* set RS bit for the last frame and bump tail ptr */
		cmd_type |= IXGBE_TXD_CMD_RS;
		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

		ixgbe_xdp_ring_update_tail(xdp_ring);
		xsk_tx_release(xdp_ring->xsk_pool);

		u64_stats_update_begin(&xdp_ring->syncp);
		xdp_ring->stats.bytes += total_bytes;
		xdp_ring->stats.packets += sent_frames;
		u64_stats_update_end(&xdp_ring->syncp);
		xdp_ring->q_vector->tx.total_bytes += total_bytes;
		xdp_ring->q_vector->tx.total_packets += sent_frames;

	}

	return (budget > 0) && work_done;
}

static void ixgbe_clean_xdp_tx_buffer(struct ixgbe_ring *tx_ring,
				      struct ixgbe_tx_buffer *tx_bi)
{
	xdp_return_frame(tx_bi->xdpf);
	tx_ring->xdp_tx_active--;
	dma_unmap_single(tx_ring->dev,
			 dma_unmap_addr(tx_bi, dma),
			 dma_unmap_len(tx_bi, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_bi, len, 0);
}

bool ixgbe_clean_xdp_tx_irq(struct ixgbe_q_vector *q_vector,
			    struct ixgbe_ring *tx_ring)
{
	u32 next_rs_idx = tx_ring->next_rs_idx;
	union ixgbe_adv_tx_desc *next_rs_desc;
	u32 ntc = tx_ring->next_to_clean;
	struct ixgbe_tx_buffer *tx_bi;
	u16 frames_ready = 0;
	u32 xsk_frames = 0;
	u16 i;

	next_rs_desc = IXGBE_TX_DESC(tx_ring, next_rs_idx);
	if (next_rs_desc->wb.status &
	    cpu_to_le32(IXGBE_TXD_STAT_DD)) {
		if (next_rs_idx >= ntc)
			frames_ready = next_rs_idx - ntc;
		else
			frames_ready = next_rs_idx + tx_ring->count - ntc;
	}

	if (!frames_ready)
		goto out_xmit;

	if (likely(!tx_ring->xdp_tx_active)) {
		xsk_frames = frames_ready;
	} else {
		for (i = 0; i < frames_ready; i++) {
			tx_bi = &tx_ring->tx_buffer_info[ntc];

			if (tx_bi->xdpf)
				ixgbe_clean_xdp_tx_buffer(tx_ring, tx_bi);
			else
				xsk_frames++;

			tx_bi->xdpf = NULL;

			++ntc;
			if (ntc >= tx_ring->count)
				ntc = 0;
		}
	}

	tx_ring->next_to_clean += frames_ready;
	if (unlikely(tx_ring->next_to_clean >= tx_ring->count))
		tx_ring->next_to_clean -= tx_ring->count;

	if (xsk_frames)
		xsk_tx_completed(tx_ring->xsk_pool, xsk_frames);

out_xmit:
	return ixgbe_xmit_zc(tx_ring, q_vector->tx.work_limit);
}

#ifdef HAVE_NDO_XSK_WAKEUP
int ixgbe_xsk_wakeup(struct net_device *dev, u32 qid, u32 __maybe_unused flags)
#else
int ixgbe_xsk_async_xmit(struct net_device *dev, u32 qid)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_ring *ring;

	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return -ENETDOWN;

	if (!READ_ONCE(adapter->xdp_prog))
		return -ENXIO;

	if (qid >= adapter->num_xdp_queues)
		return -ENXIO;

	if (!adapter->xsk_pools || !adapter->xsk_pools[qid])
		return -ENXIO;

	ring = adapter->xdp_ring[qid];
	if (!napi_if_scheduled_mark_missed(&ring->q_vector->napi)) {
		u64 eics = BIT_ULL(ring->q_vector->v_idx);

		ixgbe_irq_rearm_queues(adapter, eics);
	}

	return 0;
}

void ixgbe_xsk_clean_tx_ring(struct ixgbe_ring *tx_ring)
{
	u16 ntc = tx_ring->next_to_clean, ntu = tx_ring->next_to_use;
	struct ixgbe_tx_buffer *tx_bi;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		tx_bi = &tx_ring->tx_buffer_info[ntc];

		if (tx_bi->xdpf)
			ixgbe_clean_xdp_tx_buffer(tx_ring, tx_bi);
		else
			xsk_frames++;

		tx_bi->xdpf = NULL;

		ntc++;
		if (ntc == tx_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(tx_ring->xsk_pool, xsk_frames);
}
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
