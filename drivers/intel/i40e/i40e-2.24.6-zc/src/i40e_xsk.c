/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#include <linux/bpf_trace.h>
#ifdef HAVE_XSK_BATCHED_DESCRIPTOR_INTERFACES
#include <linux/stringify.h>
#endif /* HAVE_XSK_BATCHED_DESCRIPTOR_INTERFACES */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#include <net/xdp_sock.h>
#else
#include <net/xdp_sock_drv.h>
#endif
#include <net/xdp.h>

#include "i40e.h"
#include "i40e_txrx_common.h"
#include "i40e_xsk.h"


#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
int i40e_alloc_rx_bi_zc(struct i40e_ring *rx_ring)
{
	unsigned long sz = sizeof(*rx_ring->rx_bi_zc) * rx_ring->count;

	rx_ring->rx_bi_zc = kzalloc(sz, GFP_KERNEL);
	return rx_ring->rx_bi_zc ? 0 : -ENOMEM;
}

void i40e_clear_rx_bi_zc(struct i40e_ring *rx_ring)
{
	memset(rx_ring->rx_bi_zc, 0,
	       sizeof(*rx_ring->rx_bi_zc) * rx_ring->count);
}

static struct xdp_buff **i40e_rx_bi(struct i40e_ring *rx_ring, u32 idx)
{
	return &rx_ring->rx_bi_zc[idx];
}

#else
static struct i40e_rx_buffer *i40e_rx_bi(struct i40e_ring *rx_ring, u32 idx)
{
	return &rx_ring->rx_bi[idx];
}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

#ifndef HAVE_AF_XDP_NETDEV_UMEM
/**
 * i40e_alloc_xsk_umems - Allocate an array to store per ring UMEMs
 * @vsi: Current VSI
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_alloc_xsk_umems(struct i40e_vsi *vsi)
{
	if (vsi->xsk_umems)
		return 0;

	vsi->num_xsk_umems_used = 0;
	vsi->num_xsk_umems = vsi->alloc_queue_pairs;
	vsi->xsk_umems = kcalloc(vsi->num_xsk_umems, sizeof(*vsi->xsk_umems),
				 GFP_KERNEL);
	if (!vsi->xsk_umems) {
		vsi->num_xsk_umems = 0;
		return -ENOMEM;
	}

	return 0;
}

/**
 * i40e_add_xsk_umem - Store a UMEM for a certain ring/qid
 * @vsi: Current VSI
 * @umem: UMEM to store
 * @qid: Ring/qid to associate with the UMEM
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_add_xsk_umem(struct i40e_vsi *vsi, struct xdp_umem *umem,
			     u16 qid)
{
	int err = 0;

	err = i40e_alloc_xsk_umems(vsi);
	if (err)
		return err;

	vsi->xsk_umems[qid] = umem;
	vsi->num_xsk_umems_used++;

	return 0;
}

/**
 * i40e_remove_xsk_umem - Remove a UMEM for a certain ring/qid
 * @vsi: Current VSI
 * @qid: Ring/qid associated with the UMEM
 **/
static void i40e_remove_xsk_umem(struct i40e_vsi *vsi, u16 qid)
{
	vsi->xsk_umems[qid] = NULL;
	vsi->num_xsk_umems_used--;

	if (vsi->num_xsk_umems == 0) {
		kfree(vsi->xsk_umems);
		vsi->xsk_umems = NULL;
		vsi->num_xsk_umems = 0;
	}
}
#endif /* HAVE_AF_XDP_NETDEV_UMEM */

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * i40e_xsk_umem_dma_map - DMA maps all UMEM memory for the netdev
 * @vsi: Current VSI
 * @umem: UMEM to DMA map
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_umem_dma_map(struct i40e_vsi *vsi, struct xdp_umem *umem)
{
	struct i40e_pf *pf = vsi->back;
	struct device *dev;
	unsigned int i, j;
	dma_addr_t dma;

	dev = &pf->pdev->dev;
	for (i = 0; i < umem->npgs; i++) {
		dma = dma_map_page_attrs(dev, umem->pgs[i], 0, PAGE_SIZE,
					 DMA_BIDIRECTIONAL, I40E_RX_DMA_ATTR);
		if (dma_mapping_error(dev, dma))
			goto out_unmap;

		umem->pages[i].dma = dma;
	}

	return 0;

out_unmap:
	for (j = 0; j < i; j++) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, I40E_RX_DMA_ATTR);
		umem->pages[i].dma = 0;
	}

	return -1;
}

/**
 * i40e_xsk_umem_dma_unmap - DMA unmaps all UMEM memory for the netdev
 * @vsi: Current VSI
 * @umem: UMEM to DMA map
 **/
static void i40e_xsk_umem_dma_unmap(struct i40e_vsi *vsi, struct xdp_umem *umem)
{
	struct i40e_pf *pf = vsi->back;
	struct device *dev;
	unsigned int i;

	dev = &pf->pdev->dev;

	for (i = 0; i < umem->npgs; i++) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, I40E_RX_DMA_ATTR);

		umem->pages[i].dma = 0;
	}
}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

#ifdef HAVE_NETDEV_BPF_XSK_POOL
 /**
 * i40e_xsk_pool_enable - Enable/associate an AF_XDP buffer pool to a
 * certain ring/qid
 * @vsi: Current VSI
 * @pool: buffer pool
 * @qid: Rx ring to associate buffer pool with
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_pool_enable(struct i40e_vsi *vsi,
				struct xsk_buff_pool *pool,
				u16 qid)
#else
/**
 * i40e_xsk_umem_enable - Enable/associate a UMEM to a certain ring/qid
 * @vsi: Current VSI
 * @umem: UMEM
 * @qid: Rx ring to associate UMEM to
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_umem_enable(struct i40e_vsi *vsi, struct xdp_umem *umem,
				u16 qid)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	struct net_device *netdev = vsi->netdev;
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_umem_fq_reuse *reuseq;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	bool if_running;
	int err;

	if (vsi->type != I40E_VSI_MAIN)
		return -EINVAL;

	if (qid >= vsi->num_queue_pairs)
		return -EINVAL;
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	if (qid >= netdev->real_num_rx_queues ||
	    qid >= netdev->real_num_tx_queues)
		return -EINVAL;
#else
	if (vsi->xsk_umems) {
		if (qid >= vsi->num_xsk_umems)
			return -EINVAL;
		if (vsi->xsk_umems[qid])
			return -EBUSY;
	}
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	err = xsk_pool_dma_map(pool, &vsi->back->pdev->dev,
			       I40E_RX_DMA_ATTR);
#else
	err = xsk_pool_dma_map(umem, &vsi->back->pdev->dev,
			       I40E_RX_DMA_ATTR);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#else
	reuseq = xsk_reuseq_prepare(vsi->rx_rings[0]->count);
	if (!reuseq)
		return -ENOMEM;

	xsk_reuseq_free(xsk_reuseq_swap(umem, reuseq));

	err = i40e_xsk_umem_dma_map(vsi, umem);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	if (err)
		return err;
	
	set_bit(qid, vsi->af_xdp_zc_qps);

	if_running = netif_running(vsi->netdev) && i40e_enabled_xdp_vsi(vsi);
	if (if_running) {
		err = i40e_queue_pair_disable(vsi, qid);
		if (err)
			return err;
#ifndef HAVE_AF_XDP_NETDEV_UMEM
	}

	err = i40e_add_xsk_umem(vsi, umem, qid);
	if (err)
		return err;

	if (if_running) {
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
		err = i40e_queue_pair_enable(vsi, qid);
		if (err)
			return err;

		/* Kick start the NAPI context so that receiving will start */
#ifdef HAVE_NDO_XSK_WAKEUP
		err = i40e_xsk_wakeup(vsi->netdev, qid, XDP_WAKEUP_RX);
#else
		err = i40e_xsk_async_xmit(vsi->netdev, qid);
#endif /* HAVE_NDO_XSK_WAKEUP */
		if (err)
			return err;
	}

	return 0;
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
 /**
  * i40e_xsk_pool_disable - Disassociate an AF_XDP buffer pool from a
  * certain ring/qid
  * @vsi: Current VSI
  * @qid: Rx ring to associate buffer pool with
  *
  * Returns 0 on success, <0 on failure
  **/
static int i40e_xsk_pool_disable(struct i40e_vsi *vsi, u16 qid)
#else
/**
 * i40e_xsk_umem_disable - Diassociate a UMEM from a certain ring/qid
 * @vsi: Current VSI
 * @qid: Rx ring to associate UMEM to
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_umem_disable(struct i40e_vsi *vsi, u16 qid)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	struct net_device *netdev = vsi->netdev;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *pool;
#else
	struct xdp_umem *umem;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
	bool if_running;
	int err;

#ifdef HAVE_AF_XDP_NETDEV_UMEM
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	pool = xsk_get_pool_from_qid(netdev, qid);
	if (!pool)
#else
	umem = xsk_get_pool_from_qid(netdev, qid);
	if (!umem)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#else
	if (!vsi->xsk_umems || qid >= vsi->num_xsk_umems ||
	    !vsi->xsk_umems[qid])
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
		return -EINVAL;

	if_running = netif_running(vsi->netdev) && i40e_enabled_xdp_vsi(vsi);
	if (if_running) {
		err = i40e_queue_pair_disable(vsi, qid);
		if (err)
			return err;
	}

	clear_bit(qid, vsi->af_xdp_zc_qps);
#ifdef HAVE_AF_XDP_NETDEV_UMEM
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	xsk_pool_dma_unmap(pool, I40E_RX_DMA_ATTR);
#else
	xsk_pool_dma_unmap(umem, I40E_RX_DMA_ATTR);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#else
	i40e_xsk_umem_dma_unmap(vsi, umem);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
#else
	i40e_xsk_umem_dma_unmap(vsi, vsi->xsk_umems[qid]);
	i40e_remove_xsk_umem(vsi, qid);
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
	if (if_running) {
		err = i40e_queue_pair_enable(vsi, qid);
		if (err)
			return err;
	}

	return 0;
}

#ifndef NO_XDP_QUERY_XSK_UMEM
/**
 * i40e_xsk_umem_query - Queries a certain ring/qid for its UMEM
 * @vsi: Current VSI
 * @umem: UMEM associated to the ring, if any
 * @qid: Rx ring to associate UMEM to
 *
 * This function will store, if any, the UMEM associated to certain ring.
 *
 * Returns 0 on success, <0 on failure
 **/
int i40e_xsk_umem_query(struct i40e_vsi *vsi, struct xdp_umem **umem,
			u16 qid)
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	struct net_device *netdev = vsi->netdev;
	struct xdp_umem *queried_umem;

	queried_umem = xdp_get_umem_from_qid(netdev, qid);

	if (!queried_umem)
		return -EINVAL;
	*umem = queried_umem;
#else
	*umem = NULL;
	if (vsi->type != I40E_VSI_MAIN)
		return -EINVAL;

	if (qid >= vsi->num_queue_pairs)
		return -EINVAL;

	if (vsi->xsk_umems) {
		if (qid >= vsi->num_xsk_umems)
			return -EINVAL;
		*umem = vsi->xsk_umems[qid];
	}
#endif /* HAVE_AF_XDP_NETDEV_UMEM */

	return 0;
}
#endif /* NO_XDP_QUERY_XSK_UMEM */

#ifdef HAVE_NETDEV_BPF_XSK_POOL
/**
 * i40e_xsk_pool_setup - Enable/disassociate an AF_XDP buffer pool to/from
 * a ring/qid
 * @vsi: Current VSI
 * @pool: Buffer pool to enable/associate to a ring, or NULL to disable
 * @qid: Rx ring to (dis)associate buffer pool (from)to
 *
 * This function enables or disables a buffer pool to a certain ring.
 *
 * Returns 0 on success, <0 on failure
 **/
int i40e_xsk_pool_setup(struct i40e_vsi *vsi, struct xsk_buff_pool *pool,
			u16 qid)
{
	return pool ? i40e_xsk_pool_enable(vsi, pool, qid) :
		      i40e_xsk_pool_disable(vsi, qid);
}
#else
/**
 * i40e_xsk_umem_setup - Enable/disassociate a UMEM to/from a ring/qid
 * @vsi: Current VSI
 * @umem: UMEM to enable/associate to a ring, or NULL to disable
 * @qid: Rx ring to (dis)associate UMEM (from)to
 *
 * Returns 0 on success, <0 on failure
 **/
int i40e_xsk_umem_setup(struct i40e_vsi *vsi, struct xdp_umem *umem,
			u16 qid)
{
	return umem ? i40e_xsk_umem_enable(vsi, umem, qid) :
		i40e_xsk_umem_disable(vsi, qid);
}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

/**
 * i40e_run_xdp_zc - Executes an XDP program on an xdp_buff
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 *
 * This function enables or disables a UMEM to a certain ring.
 *
 * Returns any of I40E_XDP_{PASS, CONSUMED, TX, REDIR}
 **/
static int i40e_run_xdp_zc(struct i40e_ring *rx_ring, struct xdp_buff *xdp)
{
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	struct xdp_umem *umem = rx_ring->xsk_umem;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	int err, result = I40E_XDP_PASS;
	struct i40e_ring *xdp_ring;
	struct bpf_prog *xdp_prog;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	u64 offset;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	u32 act;

	rcu_read_lock();
	/* NB! xdp_prog will always be !NULL, due to the fact that
	 * this path is enabled by setting an XDP program.
	 */
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	act = bpf_prog_run_xdp(xdp_prog, xdp);
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	offset = xdp->data - xdp->data_hard_start;

	xdp->handle = xsk_umem_adjust_offset(umem, xdp->handle, offset);
#else
	xdp->handle += xdp->data - xdp->data_hard_start;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

	if (likely(act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		if (err)
			goto out_failure;
		rcu_read_unlock();
		return I40E_XDP_REDIR;
	}

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->queue_index];
		result = i40e_xmit_xdp_tx_ring(xdp, xdp_ring);
		if (result == I40E_XDP_CONSUMED)
			goto out_failure;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* handle invalid actions by packet drop */
	case XDP_ABORTED:
out_failure:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* handle aborts by dropping packet */
	case XDP_DROP:
		result = I40E_XDP_CONSUMED;
		break;
	}
	rcu_read_unlock();
	return result;
}


#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * i40e_alloc_buffer_zc - Allocates an i40e_rx_buffer_zc
 * @rx_ring: Rx ring
 * @bi: Rx buffer to populate
 *
 * This function allocates an Rx buffer. The buffer can come from fill
 * queue, or via the recycle queue (next_to_alloc).
 *
 * Returns true for a successful allocation, false otherwise
 **/
static bool i40e_alloc_buffer_zc(struct i40e_ring *rx_ring,
				 struct i40e_rx_buffer *bi)
{
	struct xdp_umem *umem = rx_ring->xsk_umem;
	void *addr = bi->addr;
	u64 handle, hr;

	if (addr) {
		rx_ring->rx_stats.page_reuse_count++;
		return true;
	}

	if (!xsk_umem_peek_addr(umem, &handle)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	bi->dma = xdp_umem_get_dma(umem, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(umem, handle);
	bi->addr += hr;

#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	bi->handle = xsk_umem_adjust_offset(umem, handle, umem->headroom);
#else
	bi->handle = handle + umem->headroom;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */

	xsk_umem_release_addr(umem);
	return true;
}

/**
 * i40e_alloc_buffer_slow_zc - Allocates an i40e_rx_buffer_zc
 * @rx_ring: Rx ring
 * @bi: Rx buffer to populate
 *
 * This function allocates an Rx buffer. The buffer can come from fill
 * queue, or via the reuse queue.
 *
 * Returns true for a successful allocation, false otherwise
 **/
static bool i40e_alloc_buffer_slow_zc(struct i40e_ring *rx_ring,
				      struct i40e_rx_buffer *bi)
{
	struct xdp_umem *umem = rx_ring->xsk_umem;
	u64 handle, hr;

	if (!xsk_umem_peek_addr_rq(umem, &handle)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	handle &= rx_ring->xsk_umem->chunk_mask;

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	bi->dma = xdp_umem_get_dma(umem, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(umem, handle);
	bi->addr += hr;

#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	bi->handle = xsk_umem_adjust_offset(umem, handle, umem->headroom);
#else
	bi->handle = handle + umem->headroom;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */

	xsk_umem_release_addr_rq(umem);
	return true;
}

#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */


#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
bool i40e_alloc_rx_buffers_zc(struct i40e_ring *rx_ring, u16 count)
#else
static __always_inline bool
__i40e_alloc_rx_buffers_zc(struct i40e_ring *rx_ring, u16 count,
			   bool alloc(struct i40e_ring *rx_ring,
			   struct i40e_rx_buffer *bi))
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
{
	u16 ntu = rx_ring->next_to_use;
	union i40e_rx_desc *rx_desc;
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_buff **bi, *xdp;
	dma_addr_t dma;
#else
	struct i40e_rx_buffer *bi;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	bool ok = true;

	rx_desc = I40E_RX_DESC(rx_ring, ntu);
	bi = i40e_rx_bi(rx_ring, ntu);
	do {
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		xdp = xsk_buff_alloc(rx_ring->xsk_pool);
#else
		xdp = xsk_buff_alloc(rx_ring->xsk_umem);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		if (!xdp) {
			ok = false;
			goto no_buffers;
		}
		*bi = xdp;
		dma = xsk_buff_xdp_get_dma(xdp);
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
		rx_desc->read.hdr_addr = 0;
#else
		if (!alloc(rx_ring, bi)) {
			ok = false;
			goto no_buffers;
		}

		dma_sync_single_range_for_device(rx_ring->dev, bi->dma, 0,
						 rx_ring->rx_buf_len,
						 DMA_BIDIRECTIONAL);

		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
		rx_desc++;
		bi++;
		ntu++;

		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = I40E_RX_DESC(rx_ring, 0);
			bi = i40e_rx_bi(rx_ring, 0);
			ntu = 0;
		}
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		rx_desc->wb.qword1.status_error_len = 0;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	} while (--count);

no_buffers:
	if (rx_ring->next_to_use != ntu) {
		/* clear the status bits for the next_to_use descriptor */
		rx_desc->wb.qword1.status_error_len = 0;
		i40e_release_rx_desc(rx_ring, ntu);
	}

	return ok;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * i40e_alloc_rx_buffers_zc - Allocates a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the reuse queue
 * or fill ring and places them on the Rx ring.
 *
 * Returns true for a successful allocation, false otherwise
 **/
bool i40e_alloc_rx_buffers_zc(struct i40e_ring *rx_ring, u16 count)
{
	return __i40e_alloc_rx_buffers_zc(rx_ring, count,
					  i40e_alloc_buffer_slow_zc);
}

/**
 * i40e_alloc_rx_buffers_fast_zc - Allocates a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the fill ring
 * or the internal recycle mechanism and places them on the Rx ring.
 *
 * Returns true for a successful allocation, false otherwise
 **/
static bool i40e_alloc_rx_buffers_fast_zc(struct i40e_ring *rx_ring, u16 count)
{
	return __i40e_alloc_rx_buffers_zc(rx_ring, count,
					  i40e_alloc_buffer_zc);
}

/**
 * i40e_get_rx_buffer_zc - Return the current Rx buffer
 * @rx_ring: Rx ring
 * @size: The size of the rx buffer (read from descriptor)
 *
 * This function returns the current, received Rx buffer, and also
 * does DMA synchronization.  the Rx ring.
 *
 * Returns the received Rx buffer
 **/
static struct i40e_rx_buffer *i40e_get_rx_buffer_zc(struct i40e_ring *rx_ring,
						    const unsigned int size)
{
	struct i40e_rx_buffer *bi;

	bi = i40e_rx_bi(rx_ring, rx_ring->next_to_clean);

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      bi->dma, 0,
				      size,
				      DMA_BIDIRECTIONAL);

	return bi;
}

/**
 * i40e_reuse_rx_buffer_zc - Recycle an Rx buffer
 * @rx_ring: Rx ring
 * @old_bi: The Rx buffer to recycle
 *
 * This function recycles a finished Rx buffer, and places it on the
 * recycle queue (next_to_alloc).
 **/
static void i40e_reuse_rx_buffer_zc(struct i40e_ring *rx_ring,
				    struct i40e_rx_buffer *old_bi)
{
	struct i40e_rx_buffer *new_bi = i40e_rx_bi(rx_ring,
						   rx_ring->next_to_alloc);
	u16 nta = rx_ring->next_to_alloc;

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_bi->dma = old_bi->dma;
	new_bi->addr = old_bi->addr;
	new_bi->handle = old_bi->handle;

	old_bi->addr = NULL;
}

/**
 * i40e_zca_free - Free callback for MEM_TYPE_ZERO_COPY allocations
 * @alloc: Zero-copy allocator
 * @handle: Buffer handle
 **/
void i40e_zca_free(struct zero_copy_allocator *alloc, unsigned long handle)
{
	struct i40e_rx_buffer *bi;
	struct i40e_ring *rx_ring;
	u64 hr, mask;
	u16 nta;

	rx_ring = container_of(alloc, struct i40e_ring, zca);
	hr = rx_ring->xsk_umem->headroom + XDP_PACKET_HEADROOM;
	mask = rx_ring->xsk_umem->chunk_mask;

	nta = rx_ring->next_to_alloc;
	bi = i40e_rx_bi(rx_ring, nta);

	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	handle &= mask;

	bi->dma = xdp_umem_get_dma(rx_ring->xsk_umem, handle);
	bi->dma += hr;

	bi->addr = xdp_umem_get_data(rx_ring->xsk_umem, handle);
	bi->addr += hr;

#ifdef HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT
	bi->handle = xsk_umem_adjust_offset(rx_ring->xsk_umem, (u64)handle,
					    rx_ring->xsk_umem->headroom);
#else
	bi->handle = (u64)handle + rx_ring->xsk_umem->headroom;
#endif /* HAVE_XSK_UNALIGNED_CHUNK_PLACEMENT */
}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

/*
 * i40e_construct_skb_zc - Create skbuff from zero-copy Rx buffer
 * @rx_ring: Rx ring
 * @bi: Rx buffer
 * @xdp: xdp_buff
 *
 * This functions allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb, or NULL on failure.
 **/
static struct sk_buff *i40e_construct_skb_zc(struct i40e_ring *rx_ring,
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
					     struct i40e_rx_buffer *bi,
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
					     struct xdp_buff *xdp)
{
	unsigned int metasize = xdp->data - xdp->data_meta;
	unsigned int datasize = xdp->data_end - xdp->data;
	struct sk_buff *skb;

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi,
			       xdp->data_end - xdp->data_hard_start,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), xdp->data, datasize);
	if (metasize)
		skb_metadata_set(skb, metasize);
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xsk_buff_free(xdp);
#else
	i40e_reuse_rx_buffer_zc(rx_ring, bi);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	return skb;
}

static void i40e_handle_xdp_result_zc(struct i40e_ring *rx_ring,
				      struct xdp_buff *xdp_buff,
				      union i40e_rx_desc *rx_desc,
				      unsigned int *rx_packets,
				      unsigned int *rx_bytes,
				      unsigned int size,
				      unsigned int xdp_res)
{
	struct sk_buff *skb;

	*rx_packets = 1;
	*rx_bytes = size;

	if (likely(xdp_res == I40E_XDP_REDIR) || xdp_res == I40E_XDP_TX)
		return;

	if (xdp_res == I40E_XDP_CONSUMED) {
		xsk_buff_free(xdp_buff);
		return;
	}

	if (xdp_res == I40E_XDP_PASS) {
		/* NB! We are not checking for errors using
		 * i40e_test_staterr with
		 * BIT(I40E_RXD_QW1_ERROR_SHIFT). This is due to that
		 * SBP is *not* set in PRT_SBPVSI (default not set).
		 */
		skb = i40e_construct_skb_zc(rx_ring, xdp_buff);
		if (!skb) {
			rx_ring->rx_stats.alloc_buff_failed++;
			*rx_packets = 0;
			*rx_bytes = 0;
			return;
		}

		if (eth_skb_pad(skb)) {
			*rx_packets = 0;
			*rx_bytes = 0;
			return;
		}

		*rx_bytes = skb->len;
		i40e_process_skb_fields(rx_ring, rx_desc, skb);
		napi_gro_receive(&rx_ring->q_vector->napi, skb);
		return;
	}

	/* Should never get here, as all valid cases have been handled already.
	 */
	WARN_ON_ONCE(1);
}

/**
 * i40e_clean_rx_irq_zc - Consumes Rx packets from the hardware ring
 * @rx_ring: Rx ring
 * @budget: NAPI budget
 *
 * Returns amount of work completed
 **/
int i40e_clean_rx_irq_zc(struct i40e_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = I40E_DESC_UNUSED(rx_ring);
#ifdef HAVE_XDP_BUFF_FRAME_SZ
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_umem *umem = rx_ring->xsk_umem;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
#endif /* HAVE_XDP_BUFF_FRAME_SZ */
	u16 next_to_clean = rx_ring->next_to_clean;
	u16 count_mask = rx_ring->count - 1;
	unsigned int xdp_res, xdp_xmit = 0;
	bool failure = false;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_buff xdp;

	xdp.rxq = &rx_ring->xdp_rxq;
#ifdef HAVE_XDP_BUFF_FRAME_SZ
	xdp.frame_sz = xsk_umem_xdp_frame_sz(umem);
#endif /* HAVE_XDP_BUFF_FRAME_SZ */
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

	while (likely(total_rx_packets < (unsigned int)budget)) {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		struct i40e_rx_buffer *bi;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
		unsigned int rx_packets;
		unsigned int rx_bytes;
		union i40e_rx_desc *rx_desc;
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		struct xdp_buff *bi;
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
		unsigned int size;
		u64 qword;

		rx_desc = I40E_RX_DESC(rx_ring, next_to_clean);
		qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		  */
		dma_rmb();

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		if (i40e_rx_is_programming_status(qword)) {
			i40e_clean_programming_status(rx_ring,
						      rx_desc->raw.qword[0],
						      qword);
			bi = *i40e_rx_bi(rx_ring, next_to_clean);
			xsk_buff_free(bi);
			next_to_clean = (next_to_clean + 1) & count_mask;
			continue;
		}
#else
		bi = i40e_clean_programming_status(rx_ring, rx_desc,
						   qword);
		if (unlikely(bi)) {
			i40e_reuse_rx_buffer_zc(rx_ring, bi);
			continue;
		}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

		size = (qword & I40E_RXD_QW1_LENGTH_PBUF_MASK) >>
		       I40E_RXD_QW1_LENGTH_PBUF_SHIFT;
		if (!size)
			break;

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		bi = *i40e_rx_bi(rx_ring, next_to_clean);
		bi->data_end = bi->data + size;
		xsk_buff_dma_sync_for_cpu(bi, rx_ring->xsk_pool);

		xdp_res = i40e_run_xdp_zc(rx_ring, bi);
#else
		bi = i40e_get_rx_buffer_zc(rx_ring, size);
		xdp.data = bi->addr;
		xdp.data_meta = xdp.data;
		xdp.data_hard_start = xdp.data - XDP_PACKET_HEADROOM;
		xdp.data_end = xdp.data + size;
		xdp.handle = bi->handle;

		xdp_res = i40e_run_xdp_zc(rx_ring, &xdp);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */

		i40e_handle_xdp_result_zc(rx_ring, bi, rx_desc, &rx_packets,
					  &rx_bytes, size, xdp_res);
		total_rx_packets += rx_packets;
		total_rx_bytes += rx_bytes;
		xdp_xmit |= xdp_res & (I40E_XDP_TX | I40E_XDP_REDIR);

		next_to_clean = (next_to_clean + 1) & count_mask;

	}

	rx_ring->next_to_clean = next_to_clean;
	cleaned_count = (next_to_clean - rx_ring->next_to_use - 1) & count_mask;

	if (cleaned_count >= I40E_RX_BUFFER_WRITE) {
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		failure = !i40e_alloc_rx_buffers_zc(rx_ring, cleaned_count);
#else
		failure = !i40e_alloc_rx_buffers_fast_zc(rx_ring, cleaned_count);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
	}

	i40e_finalize_xdp_rx(rx_ring, xdp_xmit);
	i40e_update_rx_stats(rx_ring, total_rx_bytes, total_rx_packets);

#ifdef HAVE_NDO_XSK_WAKEUP
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);
#else
	if (xsk_uses_need_wakeup(rx_ring->xsk_umem)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_umem);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_umem);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */		
		
		return (int)total_rx_packets;
	}
#endif /* HAVE_NDO_XSK_WAKEUP */

	return failure ? budget : (int)total_rx_packets;
}

#ifdef HAVE_XSK_BATCHED_DESCRIPTOR_INTERFACES

static void i40e_xmit_pkt(struct i40e_ring *xdp_ring, struct xdp_desc *desc,
			  unsigned int *total_bytes)
{
	struct i40e_tx_desc *tx_desc;
	dma_addr_t dma;

	dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc->addr);
	xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, desc->len);

	tx_desc = I40E_TX_DESC(xdp_ring, xdp_ring->next_to_use++);
	tx_desc->buffer_addr = cpu_to_le64(dma);
	tx_desc->cmd_type_offset_bsz = build_ctob(I40E_TX_DESC_CMD_ICRC | I40E_TX_DESC_CMD_EOP,
						  0, desc->len, 0);

	*total_bytes += desc->len;
	}

static void i40e_xmit_pkt_batch(struct i40e_ring *xdp_ring, struct xdp_desc *desc,
				unsigned int *total_bytes)
{
	u16 ntu = xdp_ring->next_to_use;
	struct i40e_tx_desc *tx_desc;
	dma_addr_t dma;
	u32 i;

	loop_unrolled_for(i = 0; i < PKTS_PER_BATCH; i++) {
		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc[i].addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, desc[i].len);

		tx_desc = I40E_TX_DESC(xdp_ring, ntu++);
		tx_desc->buffer_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz = build_ctob(I40E_TX_DESC_CMD_ICRC |
							  I40E_TX_DESC_CMD_EOP,
							  0, desc[i].len, 0);

		*total_bytes += desc[i].len;
	}

	xdp_ring->next_to_use = ntu;

}

static void i40e_fill_tx_hw_ring(struct i40e_ring *xdp_ring, struct xdp_desc *descs, u32 nb_pkts,
				 unsigned int *total_bytes)
{
	u32 batched, leftover, i;

	batched = nb_pkts & ~(PKTS_PER_BATCH - 1);
	leftover = nb_pkts & (PKTS_PER_BATCH - 1);
	for (i = 0; i < batched; i += PKTS_PER_BATCH)
		i40e_xmit_pkt_batch(xdp_ring, &descs[i], total_bytes);
	for (i = batched; i < batched + leftover; i++)
		i40e_xmit_pkt(xdp_ring, &descs[i], total_bytes);
}

static void i40e_set_rs_bit(struct i40e_ring *xdp_ring)
{
	u16 ntu = xdp_ring->next_to_use ? xdp_ring->next_to_use - 1 : xdp_ring->count - 1;
	struct i40e_tx_desc *tx_desc;

	tx_desc = I40E_TX_DESC(xdp_ring, ntu);
	tx_desc->cmd_type_offset_bsz |= cpu_to_le64(I40E_TX_DESC_CMD_RS <<
						    I40E_TXD_QW1_CMD_SHIFT);
}

/**
 * i40e_xmit_zc - Performs zero-copy Tx AF_XDP
 * @xdp_ring: XDP Tx ring
 * @budget: NAPI budget
 *
 * Returns true if the work is finished.
 **/
static bool i40e_xmit_zc(struct i40e_ring *xdp_ring, unsigned int budget)
{
	struct xdp_desc *descs = xdp_ring->xsk_descs;
	u32 nb_pkts, nb_processed = 0;
	unsigned int total_bytes = 0;

#ifdef HAVE_XSK_TX_PEEK_RELEASE_DESC_BATCH_3_PARAMS
	nb_pkts = xsk_tx_peek_release_desc_batch(xdp_ring->xsk_pool, descs, budget);
#else
	nb_pkts = xsk_tx_peek_release_desc_batch(xdp_ring->xsk_pool, budget);
#endif /* HAVE_XSK_TX_PEEK_RELEASE_3_PARAMS */

	if (!nb_pkts)
		return true;

	if (xdp_ring->next_to_use + nb_pkts >= xdp_ring->count) {
		nb_processed = xdp_ring->count - xdp_ring->next_to_use;
		i40e_fill_tx_hw_ring(xdp_ring, descs, nb_processed, &total_bytes);
		xdp_ring->next_to_use = 0;
	}

	i40e_fill_tx_hw_ring(xdp_ring, &descs[nb_processed], nb_pkts - nb_processed,
			     &total_bytes);
	/* Request an interrupt for the last frame and bump tail ptr. */
	i40e_set_rs_bit(xdp_ring);
	i40e_xdp_ring_update_tail(xdp_ring);

	i40e_update_tx_stats(xdp_ring, nb_pkts, total_bytes);

	return nb_pkts < budget;
}

#else
/**
 * i40e_xmit_zc - Performs zero-copy Tx AF_XDP
 * @xdp_ring: XDP Tx ring
 * @budget: NAPI budget
 *
 * Returns true if the work is finished.
 **/
static bool i40e_xmit_zc(struct i40e_ring *xdp_ring, unsigned int budget)
{
	unsigned int sent_frames = 0, total_bytes = 0;
	struct i40e_tx_desc *tx_desc = NULL;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
	struct xdp_desc desc;
#endif /* XSK_UMEM_RETURNS_XDP_DESC */
	dma_addr_t dma;
#ifndef XSK_UMEM_RETURNS_XDP_DESC
	u32 len;
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

	while (budget-- > 0) {
#ifdef XSK_UMEM_RETURNS_XDP_DESC
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (!xsk_umem_consume_tx(xdp_ring->xsk_pool->umem, &desc))
#else
		if (!xsk_umem_consume_tx(xdp_ring->xsk_umem, &desc))
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#else
		if (!xsk_umem_consume_tx(xdp_ring->xsk_umem, &dma, &len))
#endif /* XSK_UMEM_RETURNS_XDP_DESC */
			break;

#ifdef XSK_UMEM_RETURNS_XDP_DESC
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool->umem,
					   desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool->umem, dma,
						 desc.len);
#else
		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_umem, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_umem, dma,
						 desc.len);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#else
		dma = xdp_umem_get_dma(xdp_ring->xsk_umem, desc.addr);

		dma_sync_single_for_device(xdp_ring->dev, dma, desc.len,
					   DMA_BIDIRECTIONAL);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
#else
		dma_sync_single_for_device(xdp_ring->dev, dma, len,
					   DMA_BIDIRECTIONAL);
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

		tx_desc = I40E_TX_DESC(xdp_ring, xdp_ring->next_to_use);
		tx_desc->buffer_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
			build_ctob(I40E_TX_DESC_CMD_ICRC
				   | I40E_TX_DESC_CMD_EOP,
#ifdef XSK_UMEM_RETURNS_XDP_DESC
				   0, desc.len, 0);
#else
				   0, len, 0);
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

		sent_frames++;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
		total_bytes += desc.len;
#else
		total_bytes += len;
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

		xdp_ring->next_to_use++;
		if (xdp_ring->next_to_use == xdp_ring->count)
			xdp_ring->next_to_use = 0;
	}

	if (tx_desc) {
		/* Request an interrupt for the last frame and bump tail ptr. */
		tx_desc->cmd_type_offset_bsz |= (I40E_TX_DESC_CMD_RS <<
						 I40E_TXD_QW1_CMD_SHIFT);
		i40e_xdp_ring_update_tail(xdp_ring);
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		xsk_umem_consume_tx_done(xdp_ring->xsk_pool->umem);
#else
		xsk_umem_consume_tx_done(xdp_ring->xsk_umem);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		i40e_update_tx_stats(xdp_ring, sent_frames, total_bytes);
	}

	return !!budget;
}
#endif /* HAVE_XSK_BATCHED_DESCRIPTOR_INTERFACES */

/**
 * i40e_clean_xdp_tx_buffer - Frees and unmaps an XDP Tx entry
 * @tx_ring: XDP Tx ring
 * @tx_bi: Tx buffer info to clean
 **/
static void i40e_clean_xdp_tx_buffer(struct i40e_ring *tx_ring,
				     struct i40e_tx_buffer *tx_bi)
{
	xdp_return_frame(tx_bi->xdpf);
	tx_ring->xdp_tx_active--;
	dma_unmap_single(tx_ring->dev,
			 dma_unmap_addr(tx_bi, dma),
			 dma_unmap_len(tx_bi, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_bi, len, 0);
}

/**
 * i40e_clean_xdp_tx_irq - Completes AF_XDP entries, and cleans XDP entries
 * @vsi: Current VSI
 * @tx_ring: XDP Tx ring
 *
 * Returns true if cleanup/tranmission is done.
 **/
bool i40e_clean_xdp_tx_irq(struct i40e_vsi *vsi,
			   struct i40e_ring *tx_ring)
{
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *bp = tx_ring->xsk_pool;
#else
	struct xdp_umem *umem = tx_ring->xsk_umem;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	u32 i, completed_frames, xsk_frames = 0;
	u32 head_idx = i40e_get_head(tx_ring);
	struct i40e_tx_buffer *tx_bi;
	unsigned int ntc;

	if (head_idx < tx_ring->next_to_clean)
		head_idx += tx_ring->count;
	completed_frames = head_idx - tx_ring->next_to_clean;

	if (completed_frames == 0)
		goto out_xmit;
	
	if (likely(!tx_ring->xdp_tx_active)) {
		xsk_frames = completed_frames;
		goto skip;
	}

	ntc = tx_ring->next_to_clean;

	for (i = 0; i < completed_frames; i++) {
		tx_bi = &tx_ring->tx_bi[ntc];

		if (tx_bi->xdpf) {
			i40e_clean_xdp_tx_buffer(tx_ring, tx_bi);
			tx_bi->xdpf = NULL;
		} else {
			xsk_frames++;
		}

		if (++ntc >= tx_ring->count)
			ntc = 0;
	}

skip:
	tx_ring->next_to_clean += completed_frames;
	if (unlikely(tx_ring->next_to_clean >= tx_ring->count))
		tx_ring->next_to_clean -= tx_ring->count;

	if (xsk_frames)
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		xsk_tx_completed(bp, xsk_frames);
#else
		xsk_tx_completed(umem, xsk_frames);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	i40e_arm_wb(tx_ring, vsi, completed_frames);

out_xmit:
#ifdef HAVE_NDO_XSK_WAKEUP
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (xsk_uses_need_wakeup(tx_ring->xsk_pool))
		xsk_set_tx_need_wakeup(tx_ring->xsk_pool);
#else
	if (xsk_uses_need_wakeup(tx_ring->xsk_umem))
		xsk_set_tx_need_wakeup(tx_ring->xsk_umem);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_NDO_XSK_WAKEUP */

	return i40e_xmit_zc(tx_ring, I40E_DESC_UNUSED(tx_ring));
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * i40e_xsk_wakeup - Implements the ndo_xsk_wakeup
 * @dev: the netdevice
 * @queue_id: queue id to wake up
 * @flags: ignored in our case since we have Rx and Tx in the same NAPI.
 *
 * Returns <0 for errors, 0 otherwise.
 **/
int i40e_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags)
#else
/*
 * i40e_xsk_async_xmit - Implements the ndo_xsk_async_xmit
 * @dev: the netdevice
 * @queue_id: queue id to wake up
 *
 * Returns <0 for errors, 0 otherwise.
 */
int i40e_xsk_async_xmit(struct net_device *dev, u32 queue_id)
#endif /* HAVE_NDO_XSK_WAKEUP */
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	struct i40e_ring *ring;

	if (test_bit(__I40E_CONFIG_BUSY, pf->state))
		return -EAGAIN;

	if (test_bit(__I40E_VSI_DOWN, vsi->state))
		return -ENETDOWN;

	if (!i40e_enabled_xdp_vsi(vsi))
		return -ENXIO;

	if (queue_id >= vsi->num_queue_pairs)
		return -ENXIO;

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (!vsi->xdp_rings[queue_id]->xsk_pool->umem)
#else
	if (!vsi->xdp_rings[queue_id]->xsk_umem)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		return -ENXIO;

	ring = vsi->xdp_rings[queue_id];

	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	if (!napi_if_scheduled_mark_missed(&ring->q_vector->napi))
		i40e_force_wb(vsi, ring->q_vector);

	return 0;
}

void i40e_xsk_clean_rx_ring(struct i40e_ring *rx_ring)
{
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	u16 count_mask = rx_ring->count - 1;
	u16 ntc = rx_ring->next_to_clean;
	u16 ntu = rx_ring->next_to_use;

	for ( ; ntc != ntu; ntc = (ntc + 1)  & count_mask) {
		struct xdp_buff *rx_bi = *i40e_rx_bi(rx_ring, ntc);
		xsk_buff_free(rx_bi);
	}
#else
	u16 i;

	for (i = 0; i < rx_ring->count; i++) {
		struct i40e_rx_buffer *rx_bi = i40e_rx_bi(rx_ring, i);

		if (!rx_bi->addr)
			continue;
		
		xsk_umem_fq_reuse(rx_ring->xsk_umem, rx_bi->handle);
		rx_bi->addr = NULL;
	}
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
}

/**
 * i40e_xsk_clean_tx_ring - Clean the XDP Tx ring on shutdown
 * @tx_ring: XDP Tx ring
 **/
void i40e_xsk_clean_tx_ring(struct i40e_ring *tx_ring)
{
	u16 ntc = tx_ring->next_to_clean, ntu = tx_ring->next_to_use;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *bp = tx_ring->xsk_pool;
#else
	struct xdp_umem *umem = tx_ring->xsk_umem;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	struct i40e_tx_buffer *tx_bi;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		tx_bi = &tx_ring->tx_bi[ntc];

		if (tx_bi->xdpf)
			i40e_clean_xdp_tx_buffer(tx_ring, tx_bi);
		else
			xsk_frames++;

		tx_bi->xdpf = NULL;

		ntc++;
		if (ntc >= tx_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		xsk_tx_completed(bp, xsk_frames);
#else
		xsk_tx_completed(umem, xsk_frames);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
}

/**
 * i40e_xsk_any_rx_ring_enabled - Checks if Rx rings have AF_XDP UMEM attached
 * @vsi: vsi
 *
 * Returns true if any of the Rx rings has an AF_XDP UMEM attached
 **/
bool i40e_xsk_any_rx_ring_enabled(struct i40e_vsi *vsi)
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	struct net_device *netdev = vsi->netdev;
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
	int i;

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (!vsi->xsk_umems)
		return false;
#endif /* HAVE_AF_XDP_NETDEV_UMEM */

	for (i = 0; i < vsi->num_queue_pairs; i++) {
#ifdef HAVE_AF_XDP_NETDEV_UMEM
		if (xsk_get_pool_from_qid(netdev, i))
#else
		if (vsi->xsk_umems[i])
#endif /* HAVE_AF_XDP_NETDEV_UMEM */
			return true;
	}

	return false;
}

#endif /* HAVE_AF_XDP_ZC_SUPPORT */
