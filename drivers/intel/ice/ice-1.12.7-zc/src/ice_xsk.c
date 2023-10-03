/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#include <linux/bpf_trace.h>
#include <net/xdp_sock.h>
#include <net/xdp.h>
#include <net/busy_poll.h>
#include "ice.h"
#include "ice_lib.h"
#include "ice_base.h"
#include "ice_type.h"
#include "ice_xsk.h"
#include "ice_txrx.h"
#include "ice_txrx_lib.h"
#include "ice_irq.h"
#ifdef HAVE_AF_XDP_ZC_SUPPORT

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
static struct xdp_buff **ice_xdp_buf(struct ice_rx_ring *rx_ring, u32 idx)
{
	return &rx_ring->xdp_buf[idx];
}
#endif /* HAVE_XSK_BATCHED_RX_ALLOC */

/**
 * ice_qp_reset_stats - Resets all stats for rings of given index
 * @vsi: VSI that contains rings of interest
 * @q_idx: ring index in array
 */
static void ice_qp_reset_stats(struct ice_vsi *vsi, u16 q_idx)
{
	struct ice_vsi_stats *vsi_stat;
	struct ice_pf *pf;

	pf = vsi->back;

	if (!pf->vsi_stats)
		return;

	vsi_stat = pf->vsi_stats[vsi->idx];

	if (!vsi_stat)
		return;

	memset(&vsi_stat->rx_ring_stats[q_idx]->rx_stats, 0,
	       sizeof(vsi_stat->rx_ring_stats[q_idx]->rx_stats));
	memset(&vsi_stat->tx_ring_stats[q_idx]->stats, 0,
	       sizeof(vsi_stat->tx_ring_stats[q_idx]->stats));
	if (ice_is_xdp_ena_vsi(vsi))
		memset(&vsi->xdp_rings[q_idx]->ring_stats->stats, 0,
		       sizeof(vsi->xdp_rings[q_idx]->ring_stats->stats));
}

/**
 * ice_qp_clean_rings - Cleans all the rings of a given index
 * @vsi: VSI that contains rings of interest
 * @q_idx: ring index in array
 */
static void ice_qp_clean_rings(struct ice_vsi *vsi, u16 q_idx)
{
	ice_clean_tx_ring(vsi->tx_rings[q_idx]);
	if (ice_is_xdp_ena_vsi(vsi))
		ice_clean_tx_ring(vsi->xdp_rings[q_idx]);

	ice_clean_rx_ring(vsi->rx_rings[q_idx]);
}

/**
 * ice_qvec_toggle_napi - Enables/disables NAPI for a given q_vector
 * @vsi: VSI that has netdev
 * @q_vector: q_vector that has NAPI context
 * @enable: true for enable, false for disable
 */
static void
ice_qvec_toggle_napi(struct ice_vsi *vsi, struct ice_q_vector *q_vector,
		     bool enable)
{
	if (!vsi->netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

/**
 * ice_qvec_dis_irq - Mask off queue interrupt generation on given ring
 * @vsi: the VSI that contains queue vector being un-configured
 * @rx_ring: Rx ring that will have its IRQ disabled
 * @q_vector: queue vector
 */
static void
ice_qvec_dis_irq(struct ice_vsi *vsi, struct ice_rx_ring *rx_ring,
		 struct ice_q_vector *q_vector)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	int base = vsi->base_vector;
	u16 reg;
	u32 val;

	/* QINT_TQCTL is being cleared in ice_vsi_stop_tx_ring, so handle
	 * here only QINT_RQCTL
	 */
	reg = rx_ring->reg_idx;
	val = rd32(hw, QINT_RQCTL(reg));
	val &= ~QINT_RQCTL_CAUSE_ENA_M;
	wr32(hw, QINT_RQCTL(reg), val);

	if (q_vector) {
		u16 v_idx = q_vector->v_idx;

		wr32(hw, GLINT_DYN_CTL(q_vector->reg_idx), 0);

		ice_flush(hw);
		synchronize_irq(ice_get_irq_num(pf, v_idx + base));
	}
}

/**
 * ice_qvec_cfg_msix - Enable IRQ for given queue vector
 * @vsi: the VSI that contains queue vector
 * @q_vector: queue vector
 */
static void
ice_qvec_cfg_msix(struct ice_vsi *vsi, struct ice_q_vector *q_vector)
{
	u16 reg_idx = q_vector->reg_idx;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	struct ice_tx_ring *tx_ring;
	struct ice_rx_ring *rx_ring;

	ice_cfg_itr(hw, q_vector);

	ice_for_each_tx_ring(tx_ring, q_vector->tx)
		ice_cfg_txq_interrupt(vsi, tx_ring->reg_idx, reg_idx,
				      q_vector->tx.itr_idx);

	ice_for_each_rx_ring(rx_ring, q_vector->rx)
		ice_cfg_rxq_interrupt(vsi, rx_ring->reg_idx, reg_idx,
				      q_vector->rx.itr_idx);

	ice_flush(hw);
}

/**
 * ice_qvec_ena_irq - Enable IRQ for given queue vector
 * @vsi: the VSI that contains queue vector
 * @q_vector: queue vector
 */
static void ice_qvec_ena_irq(struct ice_vsi *vsi, struct ice_q_vector *q_vector)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;

	ice_irq_dynamic_ena(hw, vsi, q_vector);

	ice_flush(hw);
}

/**
 * ice_qp_dis - Disables a queue pair
 * @vsi: VSI of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int ice_qp_dis(struct ice_vsi *vsi, u16 q_idx)
{
	struct ice_txq_meta txq_meta = { };
	struct ice_q_vector *q_vector;
	struct ice_tx_ring *tx_ring;
	struct ice_rx_ring *rx_ring;
	int timeout = 50;
	int err;

	if (q_idx >= vsi->num_rxq || q_idx >= vsi->num_txq)
		return -EINVAL;

	tx_ring = vsi->tx_rings[q_idx];
	rx_ring = vsi->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	while (test_and_set_bit(ICE_CFG_BUSY, vsi->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}
	netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

	ice_qvec_dis_irq(vsi, rx_ring, q_vector);

	ice_fill_txq_meta(vsi, tx_ring, &txq_meta);
	err = ice_vsi_stop_tx_ring(vsi, ICE_NO_RESET, 0, tx_ring, &txq_meta);
	if (err)
		return err;
	if (ice_is_xdp_ena_vsi(vsi)) {
		struct ice_tx_ring *xdp_ring = vsi->xdp_rings[q_idx];

		memset(&txq_meta, 0, sizeof(txq_meta));
		ice_fill_txq_meta(vsi, xdp_ring, &txq_meta);
		err = ice_vsi_stop_tx_ring(vsi, ICE_NO_RESET, 0, xdp_ring,
					   &txq_meta);
		if (err)
			return err;
	}
	err = ice_vsi_ctrl_one_rx_ring(vsi, false, q_idx, true);
	if (err)
		return err;
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
	ice_clean_rx_ring(rx_ring);
#endif
	ice_qvec_toggle_napi(vsi, q_vector, false);
	ice_qp_clean_rings(vsi, q_idx);
	ice_qp_reset_stats(vsi, q_idx);

	return 0;
}

/**
 * ice_qp_ena - Enables a queue pair
 * @vsi: VSI of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int ice_qp_ena(struct ice_vsi *vsi, u16 q_idx)
{
	struct ice_aqc_add_tx_qgrp *qg_buf;
	struct ice_q_vector *q_vector;
	struct ice_tx_ring *tx_ring;
	struct ice_rx_ring *rx_ring;
	u16 size;
	int err;

	if (q_idx >= vsi->num_rxq || q_idx >= vsi->num_txq)
		return -EINVAL;

	size = struct_size(qg_buf, txqs, 1);
	qg_buf = kzalloc(size, GFP_KERNEL);
	if (!qg_buf)
		return -ENOMEM;

	qg_buf->num_txqs = 1;

	tx_ring = vsi->tx_rings[q_idx];
	rx_ring = vsi->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	err = ice_vsi_cfg_txq(vsi, tx_ring, qg_buf);
	if (err)
		goto free_buf;

	if (ice_is_xdp_ena_vsi(vsi)) {
		struct ice_tx_ring *xdp_ring = vsi->xdp_rings[q_idx];

		memset(qg_buf, 0, size);
		qg_buf->num_txqs = 1;
		err = ice_vsi_cfg_txq(vsi, xdp_ring, qg_buf);
		if (err)
			goto free_buf;
		ice_set_ring_xdp(xdp_ring);
		xdp_ring->xsk_pool = ice_tx_xsk_pool(xdp_ring);
	}

	err = ice_vsi_cfg_rxq(rx_ring);
	if (err)
		goto free_buf;

	ice_qvec_cfg_msix(vsi, q_vector);

	err = ice_vsi_ctrl_one_rx_ring(vsi, true, q_idx, true);
	if (err)
		goto free_buf;

	clear_bit(ICE_CFG_BUSY, vsi->state);
	ice_qvec_toggle_napi(vsi, q_vector, true);
	ice_qvec_ena_irq(vsi, q_vector);

	netif_tx_start_queue(netdev_get_tx_queue(vsi->netdev, q_idx));
free_buf:
	kfree(qg_buf);
	return err;
}

#ifndef HAVE_AF_XDP_NETDEV_UMEM
/**
 * ice_xsk_alloc_umems - allocate a UMEM region for an XDP socket
 * @vsi: VSI to allocate the UMEM on
 *
 * Returns 0 on success, negative on error
 */
static int ice_xsk_alloc_umems(struct ice_vsi *vsi)
{
	if (vsi->xsk_umems)
		return 0;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	vsi->xsk_umems = kcalloc(vsi->num_xsk_umems, sizeof(*vsi->xsk_umems),
				 GFP_KERNEL);
#else
	vsi->xsk_umems = kcalloc(vsi->num_xsk_umems, sizeof(*vsi->xsk_umems),
				 GFP_KERNEL);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	if (!vsi->xsk_umems) {
		vsi->num_xsk_umems = 0;
		return -ENOMEM;
	}

	return 0;
}

/**
 * ice_xsk_remove_umem - Remove an UMEM for a certain ring/qid
 * @vsi: VSI from which the VSI will be removed
 * @qid: Ring/qid associated with the UMEM
 */
static void ice_xsk_remove_umem(struct ice_vsi *vsi, u16 qid)
{
	vsi->xsk_umems[qid] = NULL;
	vsi->num_xsk_umems_used--;

	if (vsi->num_xsk_umems_used == 0) {
		kfree(vsi->xsk_umems);
		vsi->xsk_umems = NULL;
		vsi->num_xsk_umems = 0;
	}
}
#endif /* !HAVE_AF_XDP_NETDEV_UMEM */

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * ice_xsk_umem_dma_map - DMA map UMEM region for XDP sockets
 * @vsi: VSI to map the UMEM region
 * @umem: UMEM to map
 *
 * Returns 0 on success, negative on error
 */
static int ice_xsk_umem_dma_map(struct ice_vsi *vsi, struct xdp_umem *umem)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	unsigned int i;

	dev = ice_pf_to_dev(pf);
	for (i = 0; i < umem->npgs; i++) {
		dma_addr_t dma = dma_map_page_attrs(dev, umem->pgs[i], 0,
						    PAGE_SIZE,
						    DMA_BIDIRECTIONAL,
						    ICE_RX_DMA_ATTR);
		if (dma_mapping_error(dev, dma)) {
			dev_dbg(dev, "XSK UMEM DMA mapping error on page num %d/n",
				i);
			goto out_unmap;
		}

		umem->pages[i].dma = dma;
	}

	return 0;

out_unmap:
	for (; i > 0; i--) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, ICE_RX_DMA_ATTR);
		umem->pages[i].dma = 0;
	}

	return -EFAULT;
}

/**
 * ice_xsk_umem_dma_unmap - DMA unmap UMEM region for XDP sockets
 * @vsi: VSI from which the UMEM will be unmapped
 * @umem: UMEM to unmap
 */
static void ice_xsk_umem_dma_unmap(struct ice_vsi *vsi, struct xdp_umem *umem)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	unsigned int i;

	dev = ice_pf_to_dev(pf);
	for (i = 0; i < umem->npgs; i++) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL, ICE_RX_DMA_ATTR);

		umem->pages[i].dma = 0;
	}
}
#endif

/**
 * ice_xsk_pool_disable - disable a buffer pool region
 * @vsi: Current VSI
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int ice_xsk_pool_disable(struct ice_vsi *vsi, u16 qid)
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *pool = xsk_get_pool_from_qid(vsi->netdev, qid);
#else
	struct xdp_umem *pool = xsk_get_pool_from_qid(vsi->netdev, qid);
#endif
#else
	struct xdp_umem *pool;

	if (!vsi->xsk_umems || qid >= vsi->num_xsk_umems)
		return -EINVAL;

	pool = vsi->xsk_umems[qid];
#endif

	if (!pool)
		return -EINVAL;

	clear_bit(qid, vsi->af_xdp_zc_qps);
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	ice_xsk_umem_dma_unmap(vsi, pool);
#else
	xsk_pool_dma_unmap(pool, ICE_RX_DMA_ATTR);
#endif

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	ice_xsk_remove_umem(vsi, qid);
#endif

	return 0;
}

/**
 * ice_xsk_pool_enable - enable a buffer pool region
 * @vsi: Current VSI
 * @pool: pointer to a requested buffer pool region
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int
#ifdef HAVE_NETDEV_BPF_XSK_POOL
ice_xsk_pool_enable(struct ice_vsi *vsi, struct xsk_buff_pool *pool, u16 qid)
#else
ice_xsk_pool_enable(struct ice_vsi *vsi, struct xdp_umem *pool, u16 qid)
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
{
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_umem_fq_reuse *reuseq;
#endif
	int err;

	if (vsi->type != ICE_VSI_PF)
		return -EINVAL;

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (!vsi->num_xsk_umems)
		vsi->num_xsk_umems = min_t(u16, vsi->num_rxq, vsi->num_txq);
	if (qid >= vsi->num_xsk_umems)
		return -EINVAL;

	err = ice_xsk_alloc_umems(vsi);
	if (err)
		return err;

	if (vsi->xsk_umems && vsi->xsk_umems[qid])
		return -EBUSY;

	vsi->xsk_umems[qid] = pool;
	vsi->num_xsk_umems_used++;
#else
	if (qid >= vsi->netdev->real_num_rx_queues ||
	    qid >= vsi->netdev->real_num_tx_queues)
		return -EINVAL;
#endif /* !HAVE_AF_XDP_NETDEV_UMEM */

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	reuseq = xsk_reuseq_prepare(vsi->rx_rings[0]->count);
	if (!reuseq)
		return -ENOMEM;

	xsk_reuseq_free(xsk_reuseq_swap(pool, reuseq));

	err = ice_xsk_umem_dma_map(vsi, pool);
#else
	err = xsk_pool_dma_map(pool, ice_pf_to_dev(vsi->back),
			       ICE_RX_DMA_ATTR);
#endif

	if (err)
		return err;

	set_bit(qid, vsi->af_xdp_zc_qps);

	return 0;
}

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
/**
 * ice_realloc_rx_xdp_bufs - reallocate for either XSK or normal buffer
 * @rx_ring: RX ring
 * @pool_present: is pool for XSK present
 *
 * Try allocating memory and return ENOMEM, if failed to allocate.
 * If allocation was successful, substitute buffer with allocated one.
 * Returns 0 on success, negative on failure
 */
static int ice_realloc_rx_xdp_bufs(struct ice_rx_ring *rx_ring,
				   bool pool_present)
{
	size_t elem_size = pool_present ? sizeof(*rx_ring->xdp_buf) :
					  sizeof(*rx_ring->rx_buf);
	void *sw_ring = kcalloc(rx_ring->count, elem_size, GFP_KERNEL);

	if (!sw_ring)
		return -ENOMEM;

	if (pool_present) {
		kfree(rx_ring->rx_buf);
		rx_ring->rx_buf = NULL;
		rx_ring->xdp_buf = sw_ring;
	} else {
		kfree(rx_ring->xdp_buf);
		rx_ring->xdp_buf = NULL;
		rx_ring->rx_buf = sw_ring;
	}

	return 0;
}

/**
 * ice_realloc_zc_buf - reallocate xdp zc queue pairs
 * @vsi: Current VSI
 * @zc: is zero copy set
 *
 * Reallocate buffer for rx_rings that might be used by XSK.
 * XDP requires more memory, than rx_buf provides.
 * Returns 0 on success, negative on failure
 */
int ice_realloc_zc_buf(struct ice_vsi *vsi, bool zc)
{
	unsigned long q;

	for_each_set_bit(q, vsi->af_xdp_zc_qps,
			 max_t(int, vsi->alloc_txq, vsi->alloc_rxq)) {
		struct ice_rx_ring *rx_ring;

		rx_ring = vsi->rx_rings[q];
		if (ice_realloc_rx_xdp_bufs(rx_ring, zc)) {
			unsigned long qid = q;

			for_each_set_bit(q, vsi->af_xdp_zc_qps, qid) {
				rx_ring = vsi->rx_rings[q];
				zc ? kfree(rx_ring->xdp_buf) :
				     kfree(rx_ring->rx_buf);
			}
			return -ENOMEM;
		}
	}

	return 0;
}
#endif /* HAVE_XSK_BATCHED_RX_ALLOC */

/**
 * ice_xsk_pool_setup - enable/disable a buffer pool region depending on its state
 * @vsi: Current VSI
 * @pool: buffer pool to enable/associate to a ring, NULL to disable
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
int ice_xsk_pool_setup(struct ice_vsi *vsi, struct xsk_buff_pool *pool, u16 qid)
#else
int ice_xsk_umem_setup(struct ice_vsi *vsi, struct xdp_umem *pool, u16 qid)
#endif
{
	bool if_running, pool_present = !!pool;
	int ret = 0, pool_failure = 0;

	if (qid >= vsi->num_rxq || qid >= vsi->num_txq) {
		netdev_err(vsi->netdev, "Please use queue id in scope of combined queues count\n");
		pool_failure = -EINVAL;
		goto failure;
	}

	if_running = netif_running(vsi->netdev) && ice_is_xdp_ena_vsi(vsi);

	if (if_running) {
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
		struct ice_rx_ring *rx_ring = vsi->rx_rings[qid];
#endif
		ret = ice_qp_dis(vsi, qid);
		if (ret) {
			netdev_err(vsi->netdev, "ice_qp_dis error = %d\n", ret);
			goto xsk_pool_if_up;
		}

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
		ret = ice_realloc_rx_xdp_bufs(rx_ring, pool_present);
		if (ret)
			goto xsk_pool_if_up;
#endif
	}

	pool_failure = pool_present ? ice_xsk_pool_enable(vsi, pool, qid) :
				      ice_xsk_pool_disable(vsi, qid);

xsk_pool_if_up:
	if (if_running) {
		ret = ice_qp_ena(vsi, qid);
		if (!ret && pool_present)
			napi_schedule(&vsi->xdp_rings[qid]->q_vector->napi);
		else if (ret)
			netdev_err(vsi->netdev, "ice_qp_ena error = %d\n", ret);
	}

failure:
	if (pool_failure) {
		netdev_err(vsi->netdev, "Could not %sable pool, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		return pool_failure;
	}

	return ret;
}

#ifndef NO_XDP_QUERY_XSK_UMEM
/**
 * ice_xsk_umem_query - queries a certain ring/qid for its UMEM
 * @vsi: Current VSI
 * @umem: UMEM associated to the ring, if any
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
int ice_xsk_umem_query(struct ice_vsi *vsi, struct xdp_umem **umem, u16 qid)
{
#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (vsi->type != ICE_VSI_PF)
		return -EINVAL;

	if (qid >= min_t(u16, vsi->num_rxq, vsi->num_txq))
		return -EINVAL;

	if (vsi->xsk_umems) {
		if (qid >= vsi->num_xsk_umems)
			return -EINVAL;
		*umem = vsi->xsk_umems[qid];
		return 0;
	}

	*umem = NULL;
#else
	struct net_device *netdev = vsi->netdev;
	struct xdp_umem *queried_umem;

	if (vsi->type != ICE_VSI_PF)
		return -EINVAL;

	queried_umem = xsk_get_pool_from_qid(netdev, qid);
	if (!queried_umem)
		return -EINVAL;

	*umem = queried_umem;
#endif /* !HAVE_AF_XDP_NETDEV_UMEM */

	return 0;
}
#endif /* NO_XDP_QUERY_XSK_UMEM */

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * ice_zca_free - Callback for MEM_TYPE_ZERO_COPY allocations
 * @zca: zero-cpoy allocator
 * @handle: Buffer handle
 */
void ice_zca_free(struct zero_copy_allocator *zca, unsigned long handle)
{
	struct ice_rx_ring *rx_ring;
	struct ice_rx_buf *rx_buf;
	struct xdp_umem *umem;
	u64 hr, mask;
	u16 nta;

	rx_ring = container_of(zca, struct ice_rx_ring, zca);
	umem = rx_ring->xsk_pool;
	hr = umem->headroom + XDP_PACKET_HEADROOM;

#ifndef HAVE_XDP_UMEM_PROPS
	mask = umem->chunk_mask;
#else
	mask = umem->props.chunk_mask;
#endif

	nta = rx_ring->next_to_alloc;
	rx_buf = &rx_ring->rx_buf[nta];

	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	handle &= mask;

	rx_buf->dma = xdp_umem_get_dma(umem, handle);
	rx_buf->dma += hr;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += hr;

	rx_buf->handle = (u64)handle + umem->headroom;
}

/**
 * ice_alloc_buf_fast_zc - Retrieve buffer address from XDP umem
 * @rx_ring: ring with an xdp_umem bound to it
 * @rx_buf: buffer to which xsk page address will be assigned
 *
 * This function allocates an Rx buffer in the hot path.
 * The buffer can come from fill queue or recycle queue.
 *
 * Returns true if an assignment was successful, false if not.
 */
static __always_inline bool
ice_alloc_buf_fast_zc(struct ice_rx_ring *rx_ring, struct ice_rx_buf *rx_buf)
{
	struct xdp_umem *umem = rx_ring->xsk_pool;
	void *addr = rx_buf->addr;
	u64 handle, hr;

	if (addr) {
#ifdef ICE_ADD_PROBES
		rx_ring->ring_stats->rx_stats.page_reuse++;
#endif /* ICE_ADD_PROBES */
		return true;
	}

	if (!xsk_umem_peek_addr(umem, &handle)) {
		rx_ring->ring_stats->rx_stats.alloc_page_failed++;
		return false;
	}

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	rx_buf->dma = xdp_umem_get_dma(umem, handle);
	rx_buf->dma += hr;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += hr;

	rx_buf->handle = handle + umem->headroom;

	xsk_umem_release_addr(umem);
	return true;
}

/**
 * ice_alloc_buf_slow_zc - Retrieve buffer address from XDP umem
 * @rx_ring: ring with an xdp_umem bound to it
 * @rx_buf: buffer to which xsk page address will be assigned
 *
 * This function allocates an Rx buffer in the slow path.
 * The buffer can come from fill queue or recycle queue.
 *
 * Returns true if an assignment was successful, false if not.
 */
static __always_inline bool
ice_alloc_buf_slow_zc(struct ice_rx_ring *rx_ring, struct ice_rx_buf *rx_buf)
{
	struct xdp_umem *umem = rx_ring->xsk_pool;
	u64 handle, headroom;

	if (!xsk_umem_peek_addr_rq(umem, &handle)) {
		rx_ring->ring_stats->rx_stats.alloc_page_failed++;
		return false;
	}

	handle &= umem->chunk_mask;
	headroom = umem->headroom + XDP_PACKET_HEADROOM;

	rx_buf->dma = xdp_umem_get_dma(umem, handle);
	rx_buf->dma += headroom;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += headroom;

	rx_buf->handle = handle + umem->headroom;

	xsk_umem_release_addr_rq(umem);
	return true;
}
#endif /* !HAVE_MEM_TYPE_XSK_BUFF_POOL */

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * ice_alloc_rx_bufs_zc - allocate a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the fill ring
 * or the internal recycle mechanism and places them on the Rx ring.
 *
 * Returns true if all allocations were successful, false if any fail.
 * NOTE: this function header description doesn't do kdoc style
 *       because of the function pointer creating problems.
 */
bool ice_alloc_rx_bufs_zc(struct ice_rx_ring *rx_ring, int count)
#else
static bool
ice_alloc_rx_bufs_zc(struct ice_rx_ring *rx_ring, int count,
		     bool (*alloc)(struct ice_rx_ring *, struct ice_rx_buf *))
#endif
{
	union ice_32b_rx_flex_desc *rx_desc;
	u16 ntu = rx_ring->next_to_use;
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
	struct ice_rx_buf *rx_buf;
	bool ret = true;
#else
	struct xdp_buff **xdp;
	u32 nb_buffs;
#endif
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	dma_addr_t dma;
#endif
	u32 i;

	if (!count)
		return true;

	rx_desc = ICE_RX_DESC(rx_ring, ntu);
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
	xdp = ice_xdp_buf(rx_ring, ntu);

	nb_buffs = min_t(u16, count, rx_ring->count - ntu);
	nb_buffs = xsk_buff_alloc_batch(rx_ring->xsk_pool, xdp, nb_buffs);
	if (!nb_buffs)
		return false;
	i = nb_buffs;
#else
	rx_buf = &rx_ring->rx_buf[ntu];

	i = count;
#endif

	do {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		if (!alloc(rx_ring, rx_buf)) {
			ret = false;
			break;
		}

		dma_sync_single_range_for_device(rx_ring->dev, rx_buf->dma, 0,
						 rx_ring->rx_buf_len,
						 DMA_BIDIRECTIONAL);

		rx_desc->read.pkt_addr = cpu_to_le64(rx_buf->dma);
#else
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		rx_buf->xdp = xsk_buff_alloc(rx_ring->xsk_pool);
		if (!rx_buf->xdp) {
			ret = false;
			break;
		}
		dma = xsk_buff_xdp_get_dma(rx_buf->xdp);
#else
		dma = xsk_buff_xdp_get_dma(*xdp);
		xdp++;
#endif /* HAVE_XSK_BATCHED_RX_ALLOC */
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
		rx_desc->wb.status_error0 = 0;

		rx_desc++;
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		rx_buf++;
		ntu++;

		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = ICE_RX_DESC(rx_ring, 0);
			rx_buf = rx_ring->rx_buf;
			ntu = 0;
		}
#endif
	} while (--i);

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
	ntu += nb_buffs;
	if (ntu == rx_ring->count)
		ntu = 0;

	ice_release_rx_desc(rx_ring, ntu);

	return count == nb_buffs;
#else
	if (rx_ring->next_to_use != ntu)
		ice_release_rx_desc(rx_ring, ntu);

	return ret;
#endif
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * ice_alloc_rx_bufs_fast_zc - allocate zero copy bufs in the hot path
 * @rx_ring: Rx ring
 * @count: number of bufs to allocate
 *
 * Returns false on success, true on failure.
 */
static bool ice_alloc_rx_bufs_fast_zc(struct ice_rx_ring *rx_ring, u16 count)
{
	return ice_alloc_rx_bufs_zc(rx_ring, count,
				    ice_alloc_buf_fast_zc);
}

/**
 * ice_alloc_rx_bufs_slow_zc - allocate zero copy bufs in the slow path
 * @rx_ring: Rx ring
 * @count: number of bufs to allocate
 *
 * Returns false on success, true on failure.
 */
bool ice_alloc_rx_bufs_slow_zc(struct ice_rx_ring *rx_ring, u16 count)
{
	return ice_alloc_rx_bufs_zc(rx_ring, count,
				    ice_alloc_buf_slow_zc);
}
#endif

/**
 * ice_bump_ntc - Bump the next_to_clean counter of an Rx ring
 * @rx_ring: Rx ring
 */
static void ice_bump_ntc(struct ice_rx_ring *rx_ring)
{
	int ntc = rx_ring->next_to_clean + 1;

	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	prefetch(ICE_RX_DESC(rx_ring, ntc));
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
/**
 * ice_get_rx_buf_zc - Fetch the current Rx buffer
 * @rx_ring: Rx ring
 * @size: size of a buffer
 *
 * This function returns the current, received Rx buffer and does
 * DMA synchronization.
 *
 * Returns a pointer to the received Rx buffer.
 */
static struct ice_rx_buf *
ice_get_rx_buf_zc(struct ice_rx_ring *rx_ring, int size)
{
	struct ice_rx_buf *rx_buf;

	rx_buf = &rx_ring->rx_buf[rx_ring->next_to_clean];

	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma, 0,
				      size, DMA_BIDIRECTIONAL);

	return rx_buf;
}

/**
 * ice_reuse_rx_buf_zc - reuse an Rx buffer
 * @rx_ring: Rx ring
 * @old_buf: The buffer to recycle
 *
 * This function recycles a finished Rx buffer, and places it on the recycle
 * queue (next_to_alloc).
 */
static void
ice_reuse_rx_buf_zc(struct ice_rx_ring *rx_ring, struct ice_rx_buf *old_buf)
{
#ifndef HAVE_XDP_UMEM_PROPS
	unsigned long mask = (unsigned long)rx_ring->xsk_pool->chunk_mask;
#else
	unsigned long mask = (unsigned long)rx_ring->xsk_pool->props.chunk_mask;
#endif /* NO_XDP_UMEM_PROPS */
	u64 hr = rx_ring->xsk_pool->headroom + XDP_PACKET_HEADROOM;
	u16 nta = rx_ring->next_to_alloc;
	struct ice_rx_buf *new_buf;

	new_buf = &rx_ring->rx_buf[nta++];
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	new_buf->dma = old_buf->dma & mask;
	new_buf->dma += hr;

	new_buf->addr = (void *)((unsigned long)old_buf->addr & mask);
	new_buf->addr += hr;

	new_buf->handle = old_buf->handle & mask;
	new_buf->handle += rx_ring->xsk_pool->headroom;

	old_buf->addr = NULL;
}
#endif

#ifdef HAVE_XSK_BATCHED_RX_ALLOC
/**
 * ice_construct_skb_zc - Create an sk_buff from zero-copy buffer
 * @rx_ring: Rx ring
 * @xdp: xdp buffer
 *
 * This function allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb on success, NULL on failure.
 */
static struct sk_buff *
ice_construct_skb_zc(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp)
#else
static struct sk_buff *
ice_construct_skb_zc(struct ice_rx_ring *rx_ring, struct ice_rx_buf *rx_buf,
		     struct xdp_buff *xdp)
#endif
{
	unsigned int metasize = xdp->data - xdp->data_meta;
	unsigned int datasize = xdp->data_end - xdp->data;
	unsigned int datasize_hard = xdp->data_end -
				     xdp->data_hard_start;
	struct sk_buff *skb;

	skb = __napi_alloc_skb(&rx_ring->q_vector->napi, datasize_hard,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), xdp->data, datasize);

	if (metasize)
		skb_metadata_set(skb, metasize);

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	ice_reuse_rx_buf_zc(rx_ring, rx_buf);
#else
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
	xsk_buff_free(xdp);
#else
	xsk_buff_free(rx_buf->xdp);
	rx_buf->xdp = NULL;
#endif
#endif

	return skb;
}

/**
 * ice_run_xdp_zc - Executes an XDP program in zero-copy path
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns any of ICE_XDP_{PASS, CONSUMED, TX, REDIR}
 */
static int
ice_run_xdp_zc(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp)
{
	int err, result = ICE_XDP_PASS;
	struct bpf_prog *xdp_prog;
	struct ice_tx_ring *xdp_ring;
	u32 act;

	rcu_read_lock();
	/* ZC patch is enabled only when XDP program is set,
	 * so here it can not be NULL
	 */
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);

	act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		rcu_read_unlock();
		return !err ? ICE_XDP_REDIR : ICE_XDP_CONSUMED;
	}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xdp->handle += xdp->data - xdp->data_hard_start;
#endif
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->q_index];
		result = ice_xmit_xdp_buff(xdp, xdp_ring);
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* not supported action */
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* handle aborts by dropping frame */
	case XDP_DROP:
		result = ICE_XDP_CONSUMED;
		break;
	}

	rcu_read_unlock();
	return result;
}

/**
 * ice_clean_rx_irq_zc - consumes packets from the hardware ring
 * @rx_ring: AF_XDP Rx ring
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int ice_clean_rx_irq_zc(struct ice_rx_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = ICE_DESC_UNUSED(rx_ring);
	unsigned int xdp_xmit = 0;
	bool failure = false;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_buff xdp;

	xdp.rxq = &rx_ring->xdp_rxq;
#endif

	while (likely(total_rx_packets < (unsigned int)budget)) {
		union ice_32b_rx_flex_desc *rx_desc;
		unsigned int size, xdp_res = 0;
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		struct ice_rx_buf *rx_buf;
#else
		struct xdp_buff *xdp;
#endif
		struct sk_buff *skb;
		u16 stat_err_bits;
		u16 vlan_tag = 0;
		u16 rx_ptype;

		if (cleaned_count >= ICE_RX_BUF_WRITE) {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			failure |= !ice_alloc_rx_bufs_fast_zc(rx_ring,
							      cleaned_count);
#else
			failure |= !ice_alloc_rx_bufs_zc(rx_ring,
							 cleaned_count);
#endif
			cleaned_count = 0;
		}

		rx_desc = ICE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS0_DD_S);
		if (!ice_test_staterr(rx_desc->wb.status_error0, stat_err_bits))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();

		size = le16_to_cpu(rx_desc->wb.pkt_len) &
				   ICE_RX_FLX_DESC_PKT_LEN_M;
		if (!size)
			break;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		rx_buf = ice_get_rx_buf_zc(rx_ring, size);
		if (!rx_buf->addr)
			break;

		xdp.data = rx_buf->addr;
		xdp.data_meta = xdp.data;
		xdp.data_hard_start = (u8 *)xdp.data - XDP_PACKET_HEADROOM;
		xdp.data_end = (u8 *)xdp.data + size;
		xdp.handle = rx_buf->handle;

		xdp_res = ice_run_xdp_zc(rx_ring, &xdp);
#else
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		rx_buf = &rx_ring->rx_buf[rx_ring->next_to_clean];
		if (!rx_buf->xdp)
			break;
		rx_buf->xdp->data_end = rx_buf->xdp->data + size;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp, rx_ring->xsk_pool);

		xdp_res = ice_run_xdp_zc(rx_ring, rx_buf->xdp);
#else
		xdp = *ice_xdp_buf(rx_ring, rx_ring->next_to_clean);
		if (!xdp)
			break;
		xsk_buff_set_size(xdp, size);
		xsk_buff_dma_sync_for_cpu(xdp, rx_ring->xsk_pool);

		xdp_res = ice_run_xdp_zc(rx_ring, xdp);
#endif /* HAVE_XSK_BATCHED_RX_ALLOC */
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
		if (xdp_res) {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			if (xdp_res & (ICE_XDP_TX | ICE_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
				rx_buf->addr = NULL;
			} else {
				ice_reuse_rx_buf_zc(rx_ring, rx_buf);
			}
#else
			if (xdp_res & (ICE_XDP_TX | ICE_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
#ifdef HAVE_XSK_BATCHED_RX_ALLOC
				xsk_buff_free(xdp);
#else
				xsk_buff_free(rx_buf->xdp);

			rx_buf->xdp = NULL;
#endif
#endif
			total_rx_bytes += size;
			total_rx_packets++;
			cleaned_count++;

			ice_bump_ntc(rx_ring);
			continue;
		}

		/* XDP_PASS path */
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		skb = ice_construct_skb_zc(rx_ring, rx_buf, &xdp);
#else
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		skb = ice_construct_skb_zc(rx_ring, rx_buf, rx_buf->xdp);
#else
		skb = ice_construct_skb_zc(rx_ring, xdp);
#endif
#endif
		if (!skb) {
			rx_ring->ring_stats->rx_stats.alloc_buf_failed++;
			break;
		}

		cleaned_count++;
		ice_bump_ntc(rx_ring);

		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		total_rx_bytes += skb->len;
		total_rx_packets++;

		vlan_tag = ice_get_vlan_tag_from_rx_desc(rx_desc);

		rx_ptype = le16_to_cpu(rx_desc->wb.ptype_flex_flags0) &
				       ICE_RX_FLEX_DESC_PTYPE_M;

		ice_process_skb_fields(rx_ring, rx_desc, skb, rx_ptype);
		ice_receive_skb(rx_ring, skb, vlan_tag);
	}

	ice_finalize_xdp_rx(rx_ring, xdp_xmit);
	ice_update_rx_ring_stats(rx_ring, total_rx_packets, total_rx_bytes);

#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use ||
		    (ice_rx_ring_ch_enabled(rx_ring) &&
		     !ice_vsi_pkt_inspect_opt_ena(rx_ring->vsi)))
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);

		return (int)total_rx_packets;
	}

#endif /* HAVE_NDO_XSK_WAKEUP */
	return failure ? budget : (int)total_rx_packets;
}

/**
 * ice_xmit_zc - Completes AF_XDP entries, and cleans XDP entries
 * @xdp_ring: XDP Tx ring
 * @budget: max number of frames to xmit
 *
 * Returns true if cleanup/transmission is done.
 */
static bool ice_xmit_zc(struct ice_tx_ring *xdp_ring, int budget)
{
	unsigned int sent_frames = 0, total_bytes = 0;
	struct ice_tx_desc *tx_desc = NULL;
	u16 ntu = xdp_ring->next_to_use;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
	struct xdp_desc desc;
#endif /* XSK_UMEM_RETURNS_XDP_DESC */
	dma_addr_t dma;
#ifndef XSK_UMEM_RETURNS_XDP_DESC
	u32 len;
#endif /* !XSK_UMEM_RETURNS_XDP_DESC */

	while (likely(budget-- > 0)) {
		struct ice_tx_buf *tx_buf;

		tx_buf = &xdp_ring->tx_buf[ntu];

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
		tx_buf->bytecount = desc.len;
#else
		if (!xsk_tx_peek_desc(xdp_ring->xsk_pool, &dma, &len))
			break;

		dma_sync_single_for_device(xdp_ring->dev, dma, len,
					   DMA_BIDIRECTIONAL);

		tx_buf->bytecount = len;
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

		tx_desc = ICE_TX_DESC(xdp_ring, ntu);
		tx_desc->buf_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
#ifdef XSK_UMEM_RETURNS_XDP_DESC
			ice_build_ctob(ICE_TX_DESC_CMD_EOP, 0, desc.len, 0);
#else
			ice_build_ctob(ICE_TX_DESC_CMD_EOP, 0, len, 0);
#endif /* XSK_UMEM_RETURNS_XDP_DESC */

		xdp_ring->next_rs_idx = ntu;
		ntu++;
		if (ntu == xdp_ring->count)
			ntu = 0;
		sent_frames++;
		total_bytes += tx_buf->bytecount;
	}

	if (tx_desc) {
		xdp_ring->next_to_use = ntu;
		/* Set RS bit for the last frame and bump tail ptr */
		tx_desc->cmd_type_offset_bsz |=
			cpu_to_le64(ICE_TX_DESC_CMD_RS << ICE_TXD_QW1_CMD_S);
		ice_xdp_ring_update_tail(xdp_ring);
		xsk_tx_release(xdp_ring->xsk_pool);
		ice_update_tx_ring_stats(xdp_ring, sent_frames, total_bytes);
	}

	return budget > 0;
}

/**
 * ice_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdp_ring: XDP Tx ring
 * @tx_buf: Tx buffer to clean
 */
static void
ice_clean_xdp_tx_buf(struct ice_tx_ring *xdp_ring, struct ice_tx_buf *tx_buf)
{
	xdp_return_frame((struct xdp_frame *)tx_buf->raw_buf);
	xdp_ring->xdp_tx_active--;
	dma_unmap_single(xdp_ring->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * ice_clean_tx_irq_zc - Completes AF_XDP entries, and cleans XDP entries
 * @xdp_ring: XDP Tx ring
 *
 * Returns true if cleanup/tranmission is done.
 */
bool ice_clean_tx_irq_zc(struct ice_tx_ring *xdp_ring)
{
	u16 next_rs_idx = xdp_ring->next_rs_idx;
	u16 ntc = xdp_ring->next_to_clean;
	u16 frames_ready = 0, send_budget;
	struct ice_tx_desc *next_rs_desc;
	struct ice_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	u16 i;

	next_rs_desc = ICE_TX_DESC(xdp_ring, next_rs_idx);
	if (next_rs_desc->cmd_type_offset_bsz &
	    cpu_to_le64(ICE_TX_DESC_DTYPE_DESC_DONE)) {
		if (next_rs_idx >= ntc)
			frames_ready = next_rs_idx - ntc;
		else
			frames_ready = next_rs_idx + xdp_ring->count - ntc;
	}

	if (!frames_ready)
		goto out_xmit;

	if (likely(!xdp_ring->xdp_tx_active)) {
		xsk_frames = frames_ready;
		goto skip;
	}

	for (i = 0; i < frames_ready; i++) {
		tx_buf = &xdp_ring->tx_buf[ntc];

		if (tx_buf->raw_buf) {
			ice_clean_xdp_tx_buf(xdp_ring, tx_buf);
			tx_buf->raw_buf = NULL;
		} else {
			xsk_frames++;
		}

		++ntc;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

skip:
	xdp_ring->next_to_clean += frames_ready;
	if (unlikely(xdp_ring->next_to_clean >= xdp_ring->count))
		xdp_ring->next_to_clean -= xdp_ring->count;

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);

out_xmit:
#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);
#endif /* HAVE_NDO_XSK_WAKEUP */
	send_budget = ICE_DESC_UNUSED(xdp_ring);
	send_budget = min_t(u16, send_budget, xdp_ring->count >> 2);
	return ice_xmit_zc(xdp_ring, send_budget);
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * ice_xsk_wakeup - Implements ndo_xsk_wakeup
 * @netdev: net_device
 * @queue_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative on error, zero otherwise.
 */
int
ice_xsk_wakeup(struct net_device *netdev, u32 queue_id,
	       u32 __always_unused flags)
#else
int ice_xsk_async_xmit(struct net_device *netdev, u32 queue_id)
#endif /* HAVE_NDO_XSK_WAKEUP */
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_q_vector *q_vector;
	struct ice_vsi *vsi = np->vsi;
	struct ice_tx_ring *ring;

	if (test_bit(ICE_VSI_DOWN, vsi->state))
		return -ENETDOWN;

	if (!ice_is_xdp_ena_vsi(vsi))
		return -ENXIO;

	if (queue_id >= vsi->num_txq)
		return -ENXIO;

	if (!vsi->xdp_rings[queue_id]->xsk_pool)
		return -ENXIO;

	ring = vsi->xdp_rings[queue_id];

	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	q_vector = ring->q_vector;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi)) {
#if IS_ENABLED(CONFIG_NET_RX_BUSY_POLL)
		if (ice_rx_ring_ch_enabled(vsi->rx_rings[queue_id]) &&
		    !ice_vsi_pkt_inspect_opt_ena(vsi))
#define ICE_BUSY_POLL_BUDGET 8
			napi_busy_loop(q_vector->napi.napi_id, NULL, NULL,
				       false, ICE_BUSY_POLL_BUDGET);
		else
#endif
			ice_trigger_sw_intr(&vsi->back->hw, q_vector);
	}

	return 0;
}

/**
 * ice_xsk_any_rx_ring_ena - Checks if Rx rings have AF_XDP UMEM attached
 * @vsi: VSI to be checked
 *
 * Returns true if any of the Rx rings has an AF_XDP UMEM attached
 */
bool ice_xsk_any_rx_ring_ena(struct ice_vsi *vsi)
{
	int i;

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (!vsi->xsk_umems)
		return false;

	for (i = 0; i < vsi->num_xsk_umems; i++) {
		if (vsi->xsk_umems[i])
			return true;
	}
#else
	ice_for_each_rxq(vsi, i) {
		if (xsk_get_pool_from_qid(vsi->netdev, i))
			return true;
	}
#endif /* HAVE_AF_XDP_NETDEV_UMEM */

	return false;
}

/**
 * ice_xsk_clean_rx_ring - clean UMEM queues connected to a given Rx ring
 * @rx_ring: ring to be cleaned
 */
void ice_xsk_clean_rx_ring(struct ice_rx_ring *rx_ring)
{
	u16 ntc = rx_ring->next_to_clean;
	u16 ntu = rx_ring->next_to_use;

	while (ntc != ntu) {
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		struct ice_rx_buf *rx_buf = &rx_ring->rx_buf[ntc];

		if (!rx_buf->addr)
			continue;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		xsk_umem_fq_reuse(rx_ring->xsk_pool, rx_buf->handle);
#endif
		rx_buf->addr = NULL;
#else
		struct xdp_buff *xdp = *ice_xdp_buf(rx_ring, ntc);

		xsk_buff_free(xdp);
#endif
		ntc++;
		if (ntc >= rx_ring->count)
			ntc = 0;
	}
}

/**
 * ice_xsk_clean_xdp_ring - Clean the XDP Tx ring and its UMEM queues
 * @xdp_ring: XDP_Tx ring
 */
void ice_xsk_clean_xdp_ring(struct ice_tx_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean, ntu = xdp_ring->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct ice_tx_buf *tx_buf = &xdp_ring->tx_buf[ntc];

		if (tx_buf->raw_buf)
			ice_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		tx_buf->raw_buf = NULL;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
