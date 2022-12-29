// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_dcb_lib.h"
#include "ice_devlink.h"
#include "ice_vsi_vlan_ops.h"
#include "ice_irq.h"

#ifdef HAVE_PF_RING
extern int RSS[ICE_MAX_NIC];
extern int enable_debug;
#endif

/**
 * ice_vsi_type_str - maps VSI type enum to string equivalents
 * @vsi_type: VSI type enum
 */
const char *ice_vsi_type_str(enum ice_vsi_type vsi_type)
{
	switch (vsi_type) {
	case ICE_VSI_PF:
		return "ICE_VSI_PF";
	case ICE_VSI_VF:
		return "ICE_VSI_VF";
	case ICE_VSI_VMDQ2:
		return "ICE_VSI_VMDQ2";
	case ICE_VSI_CTRL:
		return "ICE_VSI_CTRL";
	case ICE_VSI_CHNL:
		return "ICE_VSI_CHNL";
	case ICE_VSI_OFFLOAD_MACVLAN:
		return "ICE_VSI_OFFLOAD_MACVLAN";
	case ICE_VSI_LB:
		return "ICE_VSI_LB";
	case ICE_VSI_SWITCHDEV_CTRL:
		return "ICE_VSI_SWITCHDEV_CTRL";
	default:
		return "unknown";
	}
}

/**
 * ice_vsi_requires_vf - Does this VSI type always require a VF?
 * @vsi_type: the VSI type
 *
 * Returns true if the VSI type *must* have a VF pointer. Returns false
 * otherwise. In particular, VSI types which may *optionally* have a VF
 * pointer return false.
 *
 * Used to WARN in cases where we always expect a VF pointer to be non-NULL.
 */
static int ice_vsi_requires_vf(enum ice_vsi_type vsi_type)
{
	switch (vsi_type) {
	case ICE_VSI_ADI:
	case ICE_VSI_VF:
		return true;
	default:
		return false;
	}
}

/**
 * ice_vsi_ctrl_all_rx_rings - Start or stop a VSI's Rx rings
 * @vsi: the VSI being configured
 * @ena: start or stop the Rx rings
 *
 * First enable/disable all of the Rx rings, flush any remaining writes, and
 * then verify that they have all been enabled/disabled successfully. This will
 * let all of the register writes complete when enabling/disabling the Rx rings
 * before waiting for the change in hardware to complete.
 */
static int ice_vsi_ctrl_all_rx_rings(struct ice_vsi *vsi, bool ena)
{
	int ret = 0;
	u16 i;

	for (i = 0; i < vsi->num_rxq; i++)
		ice_vsi_ctrl_one_rx_ring(vsi, ena, i, false);

	ice_flush(&vsi->back->hw);

	for (i = 0; i < vsi->num_rxq; i++) {
		ret = ice_vsi_wait_one_rx_ring(vsi, ena, i);
		if (ret)
			break;
	}

	return ret;
}

/**
 * ice_vsi_alloc_arrays - Allocate queue and vector pointer arrays for the VSI
 * @vsi: VSI pointer
 *
 * On error: returns error code (negative)
 * On success: returns 0
 */
static int ice_vsi_alloc_arrays(struct ice_vsi *vsi)
{
	int alloc_txq = vsi->alloc_txq;
	int alloc_rxq = vsi->alloc_rxq;
	struct ice_pf *pf = vsi->back;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (vsi->type == ICE_VSI_CHNL)
		return 0;

	/* allocate memory for both Tx and Rx ring pointers */
	vsi->tx_rings = devm_kcalloc(dev, vsi->alloc_txq,
				     sizeof(*vsi->tx_rings), GFP_KERNEL);
	if (!vsi->tx_rings)
		return -ENOMEM;

	vsi->rx_rings = devm_kcalloc(dev, vsi->alloc_rxq,
				     sizeof(*vsi->rx_rings), GFP_KERNEL);
	if (!vsi->rx_rings)
		goto err_rings;

	if (vsi->type == ICE_VSI_PF && !ice_is_safe_mode(pf)) {
		alloc_txq = pf->max_adq_qps;
		alloc_rxq = pf->max_adq_qps;
	}

#ifdef HAVE_XDP_SUPPORT
	/* XDP will have vsi->alloc_txq Tx queues as well, so double the size */
	vsi->txq_map = devm_kcalloc(dev, (2 * alloc_txq),
				    sizeof(*vsi->txq_map), GFP_KERNEL);
#else
	vsi->txq_map = devm_kcalloc(dev, alloc_txq, sizeof(*vsi->txq_map),
				    GFP_KERNEL);
#endif /* HAVE_XDP_SUPPORT */

	if (!vsi->txq_map)
		goto err_txq_map;

	vsi->rxq_map = devm_kcalloc(dev, alloc_rxq, sizeof(*vsi->rxq_map),
				    GFP_KERNEL);
	if (!vsi->rxq_map)
		goto err_rxq_map;

	/* There is no need to allocate q_vectors for a loopback VSI. */
	if (vsi->type == ICE_VSI_LB)
		return 0;

	/* allocate memory for q_vector pointers */
	vsi->q_vectors = devm_kcalloc(dev, vsi->num_q_vectors,
				      sizeof(*vsi->q_vectors), GFP_KERNEL);
	if (!vsi->q_vectors)
		goto err_vectors;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	vsi->af_xdp_zc_qps = bitmap_zalloc(max_t(int, vsi->alloc_txq, vsi->alloc_rxq), GFP_KERNEL);
	if (!vsi->af_xdp_zc_qps)
		goto err_zc_qps;
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* HAVE_XDP_SUPPORT */

	return 0;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_AF_XDP_ZC_SUPPORT
err_zc_qps:
	devm_kfree(dev, vsi->q_vectors);
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* HAVE_XDP_SUPPORT */
err_vectors:
	devm_kfree(dev, vsi->rxq_map);
err_rxq_map:
	devm_kfree(dev, vsi->txq_map);
err_txq_map:
	devm_kfree(dev, vsi->rx_rings);
err_rings:
	devm_kfree(dev, vsi->tx_rings);
	return -ENOMEM;
}

/**
 * ice_vsi_set_num_desc - Set number of descriptors for queues on this VSI
 * @vsi: the VSI being configured
 */
static void ice_vsi_set_num_desc(struct ice_vsi *vsi)
{
	switch (vsi->type) {
	case ICE_VSI_PF:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_ADI:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_CTRL:
	case ICE_VSI_LB:
		/* a user could change the values of num_[tr]x_desc using
		 * ethtool -G so we should keep those values instead of
		 * overwriting them with the defaults.
		 */
		if (!vsi->num_rx_desc)
			vsi->num_rx_desc = ICE_DFLT_NUM_RX_DESC;
		if (!vsi->num_tx_desc)
			vsi->num_tx_desc = ICE_DFLT_NUM_TX_DESC;
		break;
	default:
		dev_dbg(ice_pf_to_dev(vsi->back), "Not setting number of Tx/Rx descriptors for VSI type %d\n",
			vsi->type);
		break;
	}
}

/**
 * ice_vsi_set_num_qs - Set number of queues, descriptors and vectors for a VSI
 * @vsi: the VSI being configured
 * @vf: the VF associated with this VSI, if any
 *
 * Return 0 on success and a negative value on error
 */
static void ice_vsi_set_num_qs(struct ice_vsi *vsi, struct ice_vf *vf)
{
	enum ice_vsi_type vsi_type = vsi->type;
	struct ice_pf *pf = vsi->back;

	if (WARN_ON(!vf && ice_vsi_requires_vf(vsi_type)))
		return;

	switch (vsi_type) {
	case ICE_VSI_PF:
		/* default to 1 Tx queue per MSI-X to not hurt our performance */
		vsi->alloc_txq = min3(pf->num_lan_msix,
				      ice_get_avail_txq_count(pf),
				      pf->max_qps);
#ifdef HAVE_PF_RING
		if (RSS[pf->instance] != 0)
			vsi->alloc_txq = min_t(int, vsi->alloc_txq, RSS[pf->instance]);
#endif
		if (vsi->req_txq) {
			vsi->alloc_txq = vsi->req_txq;
			vsi->num_txq = vsi->req_txq;
		}

		pf->num_lan_tx = vsi->alloc_txq;

		/* only 1 Rx queue unless RSS is enabled */
		if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			vsi->alloc_rxq = 1;
		} else {
			/* default to 1 Rx queue per MSI-X to not hurt our performance */
			vsi->alloc_rxq = min3(pf->num_lan_msix,
					      ice_get_avail_rxq_count(pf),
					      pf->max_qps);
#ifdef HAVE_PF_RING
			if (RSS[pf->instance] != 0)
				vsi->alloc_rxq = min_t(int, vsi->alloc_rxq, RSS[pf->instance]);
#endif
			if (vsi->req_rxq) {
				vsi->alloc_rxq = vsi->req_rxq;
				vsi->num_rxq = vsi->req_rxq;
			}
		}

		pf->num_lan_rx = vsi->alloc_rxq;

		vsi->num_q_vectors = min_t(int, pf->num_lan_msix,
					   max_t(int, vsi->alloc_rxq, vsi->alloc_txq));
		break;
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
		vsi->alloc_txq = ICE_DFLT_TXQ_VMDQ_VSI;
		vsi->alloc_rxq = ICE_DFLT_RXQ_VMDQ_VSI;
		vsi->num_q_vectors = ICE_DFLT_VEC_VMDQ_VSI;
		break;
	case ICE_VSI_ADI:
		vsi->alloc_txq = pf->vfs.num_qps_per;
		vsi->alloc_rxq = pf->vfs.num_qps_per;

		/* For SIOV VFs, we reserve vectors required for Qs and 1 extra
		 * for OICR.
		 */
		vsi->num_q_vectors = pf->vfs.num_msix_per;
		break;
	case ICE_VSI_SWITCHDEV_CTRL:
		/* The number of queues for ctrl VSI is equal to number of VFs.
		 * Each ring is associated to the corresponding VF_PR netdev.
		 */
		vsi->alloc_txq = ice_get_num_vfs(pf);
		vsi->alloc_rxq = vsi->alloc_txq;
		vsi->num_q_vectors = 1;
		break;
	case ICE_VSI_VF:
		/* pf->vfs.num_msix_per includes (VF miscellaneous vector +
		 * data queue interrupts). Since vsi->num_q_vectors is number
		 * of queues vectors, subtract 1 (ICE_NONQ_VECS_VF) from the
		 * original vector count
		 */
		if (vf->adq_enabled && vf->num_tc) {
			u8 tc = vsi->vf_adq_tc;

			vsi->alloc_txq = vf->ch[tc].num_qps;
			vsi->alloc_rxq = vf->ch[tc].num_qps;
			vsi->num_q_vectors = vf->ch[tc].num_qps;
		} else {
			if (vf->num_req_qs)
				vf->num_vf_qs = vf->num_req_qs;

			vsi->alloc_txq = vf->num_vf_qs;
			vsi->alloc_rxq = vf->num_vf_qs;
			vsi->num_q_vectors = pf->vfs.num_msix_per -
				ICE_NONQ_VECS_VF;
		}
		break;
	case ICE_VSI_CTRL:
		vsi->alloc_txq = 1;
		vsi->alloc_rxq = 1;
		vsi->num_q_vectors = 1;
		break;
	case ICE_VSI_CHNL:
		vsi->alloc_txq = 0;
		vsi->alloc_rxq = 0;
		break;
	case ICE_VSI_LB:
		vsi->alloc_txq = 1;
		vsi->alloc_rxq = 1;
		break;
	default:
		dev_warn(ice_pf_to_dev(pf), "Unknown VSI type %d\n", vsi_type);
		break;
	}

	ice_vsi_set_num_desc(vsi);
}

/**
 * ice_get_free_slot - get the next available free slot in array
 * @array: array to search
 * @size: size of the array
 * @curr: last known occupied index to be used as a search hint
 *
 * void * is being used to keep the functionality generic. This lets us use this
 * function on any array of pointers.
 */
static int ice_get_free_slot(void *array, int size, int curr)
{
	int **tmp_array = (int **)array;
	int next;

	if (curr < (size - 1) && !tmp_array[curr + 1]) {
		next = curr + 1;
	} else {
		int i = 0;

		while ((i < size) && (tmp_array[i]))
			i++;
		if (i == size)
			next = ICE_NO_VSI;
		else
			next = i;
	}
	return next;
}

/**
 * ice_vsi_delete - delete a VSI from the switch
 * @vsi: pointer to VSI being removed
 */
void ice_vsi_delete(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_vsi_ctx *ctxt;
	enum ice_status status;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return;

	if (vsi->type == ICE_VSI_VF)
		ctxt->vf_num = vsi->vf->vf_id;
	ctxt->vsi_num = vsi->vsi_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	status = ice_free_vsi(&pf->hw, vsi->idx, ctxt, false, NULL);
	if (status)
		dev_err(ice_pf_to_dev(pf), "Failed to delete VSI %i in FW - error: %s\n",
			vsi->vsi_num, ice_stat_str(status));

	kfree(ctxt);
}

/**
 * ice_vsi_free_arrays - De-allocate queue and vector pointer arrays for the VSI
 * @vsi: pointer to VSI being cleared
 */
static void ice_vsi_free_arrays(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (vsi->af_xdp_zc_qps) {
		bitmap_free(vsi->af_xdp_zc_qps);
		vsi->af_xdp_zc_qps = NULL;
	}
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* HAVE_XDP_SUPPORT */
	/* free the ring and vector containers */
	if (vsi->q_vectors) {
		devm_kfree(dev, vsi->q_vectors);
		vsi->q_vectors = NULL;
	}
	if (vsi->tx_rings) {
		devm_kfree(dev, vsi->tx_rings);
		vsi->tx_rings = NULL;
	}
	if (vsi->rx_rings) {
		devm_kfree(dev, vsi->rx_rings);
		vsi->rx_rings = NULL;
	}
	if (vsi->txq_map) {
		devm_kfree(dev, vsi->txq_map);
		vsi->txq_map = NULL;
	}
	if (vsi->rxq_map) {
		devm_kfree(dev, vsi->rxq_map);
		vsi->rxq_map = NULL;
	}
}

static void ice_vsi_free_rss_global_lut_memory(struct ice_vsi *vsi)
{
	if (vsi->global_lut_id) {
		devm_kfree(ice_pf_to_dev(vsi->back), vsi->global_lut_id);
		vsi->global_lut_id = NULL;
	}
}

/**
 * ice_vsi_free_rss_global_lut - free the VSI's global RSS LUT
 * @vsi: VSI to free global RSS LUT for
 *
 * If the VSI didn't allocate a global RSS LUT, then there is nothing to do. The vsi->global_lut_id
 * will always be cleared and freed regardless of the result of freeing the global RSS LUT.
 */
static void ice_vsi_free_rss_global_lut(struct ice_vsi *vsi)
{
	enum ice_status status;

	if (!vsi->global_lut_id)
		return;

	status = ice_free_rss_global_lut(&vsi->back->hw, *vsi->global_lut_id);
	if (status)
		dev_dbg(ice_pf_to_dev(vsi->back),
			"Failed to free RSS global LUT ID %d for %s %d, status %d\n",
			*vsi->global_lut_id, ice_vsi_type_str(vsi->type), vsi->idx, status);

	ice_vsi_free_rss_global_lut_memory(vsi);
}

/**
 * ice_vsi_alloc_rss_global_lut - allocate a global RSS LUT for this VSI
 * @vsi: VSI to allocate global RSS LUT for
 *
 * Allocate a global RSS LUT if the VSI supports it. The caller must take care if allocating the
 * global RSS LUT fails since vsi->global_lut_id will be NULL, which means there are no global RSS
 * LUT resources available. There might be other causes of failure, but they can all be treated as
 * the device having no more global RSS LUT resources available.
 */
static void ice_vsi_alloc_rss_global_lut(struct ice_vsi *vsi)
{
	enum ice_status status;
	struct device *dev;

	if (vsi->type != ICE_VSI_VF)
		return;

	/* VSI LUT is wide enough for queue groups up to ICE_MAX_SMALL_RS_QS */
	if (vsi->alloc_rxq <= ICE_MAX_SMALL_RSS_QS)
		return;

	dev = ice_pf_to_dev(vsi->back);
	vsi->global_lut_id = devm_kzalloc(dev, sizeof(vsi->global_lut_id),
					  GFP_KERNEL);
	if (!vsi->global_lut_id)
		return;

	status = ice_alloc_rss_global_lut(&vsi->back->hw, false, vsi->global_lut_id);
	if (status) {
		dev_dbg(dev, "failed to allocate RSS global LUT for %s %d, status %d\n",
			ice_vsi_type_str(vsi->type), vsi->idx, status);
		ice_vsi_free_rss_global_lut_memory(vsi);
	}
}

/**
 * ice_vsi_clear - clean up and deallocate the provided VSI
 * @vsi: pointer to VSI being cleared
 *
 * This deallocates the VSI's queue resources, removes it from the PF's
 * VSI array if necessary, and deallocates the VSI
 *
 * Returns 0 on success, negative on failure
 */
int ice_vsi_clear(struct ice_vsi *vsi)
{
	struct ice_pf *pf = NULL;
	struct device *dev;

	if (!vsi)
		return 0;

	if (!vsi->back)
		return -EINVAL;

	pf = vsi->back;
	dev = ice_pf_to_dev(pf);

	if (!pf->vsi[vsi->idx] || pf->vsi[vsi->idx] != vsi) {
		dev_dbg(dev, "vsi does not exist at pf->vsi[%d]\n", vsi->idx);
		return -EINVAL;
	}

	mutex_lock(&pf->sw_mutex);
	/* updates the PF for this cleared VSI */

	pf->vsi[vsi->idx] = NULL;
	if (vsi->idx < pf->next_vsi && vsi->type != ICE_VSI_CTRL)
		pf->next_vsi = vsi->idx;
	if (vsi->idx < pf->next_vsi && vsi->type == ICE_VSI_CTRL && vsi->vf)
		pf->next_vsi = vsi->idx;

	ice_vsi_free_arrays(vsi);
	ice_vsi_free_rss_global_lut(vsi);
	mutex_unlock(&pf->sw_mutex);
	devm_kfree(dev, vsi);

	return 0;
}

/**
 * ice_msix_clean_ctrl_vsi - MSIX mode interrupt handler for ctrl VSI
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t ice_msix_clean_ctrl_vsi(int __always_unused irq, void *data)
{
	struct ice_q_vector *q_vector = (struct ice_q_vector *)data;

	if (!q_vector->tx.ring)
		return IRQ_HANDLED;

#define FDIR_RX_DESC_CLEAN_BUDGET 64
	ice_clean_rx_irq(q_vector->rx.ring, FDIR_RX_DESC_CLEAN_BUDGET);
	ice_clean_ctrl_tx_irq(q_vector->tx.ring);

	return IRQ_HANDLED;
}

/**
 * ice_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
#ifdef HAVE_NETPOLL_CONTROLLER
irqreturn_t ice_msix_clean_rings(int __always_unused irq, void *data)
#else
static irqreturn_t ice_msix_clean_rings(int __always_unused irq, void *data)
#endif /* HAVE_NETPOLL_CONTROLLER */
{
	struct ice_q_vector *q_vector = (struct ice_q_vector *)data;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;

	q_vector->total_events++;

	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

static irqreturn_t ice_eswitch_msix_clean_rings(int __always_unused irq, void *data)
{
	struct ice_q_vector *q_vector = (struct ice_q_vector *)data;
	struct ice_pf *pf = q_vector->vsi->back;
	struct ice_vf *vf;
	unsigned int bkt;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf)
		napi_schedule(&vf->repr->q_vector->napi);
	rcu_read_unlock();

	return IRQ_HANDLED;
}

/**
 * ice_vsi_alloc - Allocates the next available struct VSI in the PF
 * @pf: board private structure
 * @vsi_type: type of VSI
 * @ch: ptr to channel
 * @tc: traffic class number for VF ADQ
 * @vf: VF for ICE_VSI_VF and ICE_VSI_CTRL
 *
 * The VF pointer is used for ICE_VSI_VF and ICE_VSI_CTRL. For ICE_VSI_CTRL,
 * it may be NULL in the case there is no association with a VF. For
 * ICE_VSI_VF the VF pointer *must not* be NULL.
 *
 * returns a pointer to a VSI on success, NULL on failure.
 */
static struct ice_vsi *
ice_vsi_alloc(struct ice_pf *pf, enum ice_vsi_type vsi_type,
	      struct ice_channel *ch, struct ice_vf *vf, u8 tc)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *vsi = NULL;

	if (WARN_ON(!vf && ice_vsi_requires_vf(vsi_type)))
		return NULL;

	/* Need to protect the allocation of the VSIs at the PF level */
	mutex_lock(&pf->sw_mutex);

	/* If we have already allocated our maximum number of VSIs,
	 * pf->next_vsi will be ICE_NO_VSI. If not, pf->next_vsi index
	 * is available to be populated
	 */
	if (pf->next_vsi == ICE_NO_VSI) {
		dev_dbg(dev, "out of VSI slots!\n");
		goto unlock_pf;
	}

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi)
		goto unlock_pf;

	vsi->type = vsi_type;
	vsi->back = pf;
	/* For VSIs which don't have a connected VF, this will be NULL */
	vsi->vf = vf;
	if (vsi_type == ICE_VSI_VF)
		vsi->vf_adq_tc = tc;
	set_bit(ICE_VSI_DOWN, vsi->state);

	/* Don't set queues for ICE_VSI_CHNL */
	if (vsi_type != ICE_VSI_CHNL)
		ice_vsi_set_num_qs(vsi, vf);

	switch (vsi->type) {
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_ADI:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_PF:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;

		/* Setup default MSIX irq handler for VSI */
		vsi->irq_handler = ice_msix_clean_rings;
		break;
	case ICE_VSI_SWITCHDEV_CTRL:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;

		/* Setup eswitch MSIX irq handler for VSI */
		vsi->irq_handler = ice_eswitch_msix_clean_rings;
		break;
	case ICE_VSI_CTRL:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;

		/* Setup ctrl VSI MSIX irq handler */
		vsi->irq_handler = ice_msix_clean_ctrl_vsi;
		break;
	case ICE_VSI_VF:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;
		break;
	case ICE_VSI_CHNL:
		if (!ch)
			goto err_rings;
		vsi->num_rxq = ch->num_rxq;
		vsi->num_txq = ch->num_txq;
		vsi->next_base_q = ch->base_q;
		break;
	case ICE_VSI_LB:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;
		break;
	default:
		dev_warn(dev, "Unknown VSI type %d\n", vsi->type);
		goto unlock_pf;
	}

	if (vsi->type == ICE_VSI_CTRL && !vf) {
		/* Use the last VSI slot as the index for PF control VSI */
		vsi->idx = pf->num_alloc_vsi - 1;
		pf->ctrl_vsi_idx = vsi->idx;
		pf->vsi[vsi->idx] = vsi;
	} else {
		/* fill slot and make note of the index */
		vsi->idx = pf->next_vsi;
		pf->vsi[pf->next_vsi] = vsi;

		/* prepare pf->next_vsi for next use */
		pf->next_vsi = ice_get_free_slot(pf->vsi, pf->num_alloc_vsi,
						 pf->next_vsi);
	}

	if (vsi->type == ICE_VSI_CTRL && vf)
		vf->ctrl_vsi_idx = vsi->idx;
	goto unlock_pf;

err_rings:
	devm_kfree(dev, vsi);
	vsi = NULL;
unlock_pf:
	mutex_unlock(&pf->sw_mutex);
	return vsi;
}

/**
 * ice_alloc_fd_res - Allocate FD resource for a VSI
 * @vsi: pointer to the ice_vsi
 *
 * This allocates the FD resources
 *
 * Returns 0 on success, -EPERM on no-op or -EIO on failure
 */
static int ice_alloc_fd_res(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	u32 g_val, b_val;

	/* Flow Director filters are only allocated/assigned to the PF VSI or
	 * CHNL VSI which passes the traffic. The CTRL VSI is only used to
	 * add/delete filters so we don't allocate resources to it
	 */

	/* FD filters from guaranteed pool per VSI */
	g_val = pf->hw.func_caps.fd_fltr_guar;
	if (!g_val)
		return -EPERM;

	/* FD filters from best effort pool */
	b_val = pf->hw.func_caps.fd_fltr_best_effort;
	if (!b_val)
		return -EPERM;

	if (!(vsi->type == ICE_VSI_PF || vsi->type == ICE_VSI_CHNL ||
	      vsi->type == ICE_VSI_VF))
		return -EPERM;

	if (!test_bit(ICE_FLAG_FD_ENA, pf->flags))
		return -EPERM;

	/* PF main VSI gets only 64 FD resources from guaranteed pool
	 * when ADQ is configured.
	 */
#define ICE_PF_VSI_GFLTR	64

	/* determine FD filter resources per VSI from shared(best effort) and
	 * dedicated pool
	 */
	if (vsi->type == ICE_VSI_PF) {
		vsi->num_gfltr = g_val;
#ifdef NETIF_F_HW_TC
		/* if MQPRIO is configured, main VSI doesn't get all FD
		 * resources from guaranteed pool. PF VSI gets 64 FD resources
		 */
		if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags)) {
			if (g_val < ICE_PF_VSI_GFLTR)
				return -EPERM;
			/* allow bare minimum entries for PF VSI */
			vsi->num_gfltr = ICE_PF_VSI_GFLTR;
		}
#endif /* NETIF_F_HW_TC */

		/* each VSI gets same "best_effort" quota */
		vsi->num_bfltr = b_val;
	} else if (vsi->type == ICE_VSI_VF) {
		vsi->num_gfltr = 0;

		/* each VSI gets same "best_effort" quota */
		vsi->num_bfltr = b_val;
	} else {
		struct ice_vsi *main_vsi;
		int numtc;

		main_vsi = ice_get_main_vsi(pf);
		if (!main_vsi)
			return -EPERM;

		if (!main_vsi->all_numtc)
			return -EINVAL;

		/* figure out ADQ numtc */
		numtc = main_vsi->all_numtc - ICE_CHNL_START_TC;

		/* only one TC but still asking resources for channels,
		 * invalid config
		 */
		if (numtc < ICE_CHNL_START_TC)
			return -EPERM;

		g_val -= ICE_PF_VSI_GFLTR;
		/* channel VSIs gets equal share from guaranteed pool */
		vsi->num_gfltr = g_val / numtc;

		/* each VSI gets same "best_effort" quota */
		vsi->num_bfltr = b_val;
	}

	return 0;
}

/**
 * ice_vsi_get_qs - Assign queues from PF to VSI
 * @vsi: the VSI to assign queues to
 *
 * Returns 0 on success and a negative value on error
 */
static int ice_vsi_get_qs(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_qs_cfg tx_qs_cfg = {
		.qs_mutex = &pf->avail_q_mutex,
		.pf_map = pf->avail_txqs,
		.pf_map_size = pf->max_pf_txqs,
		.q_count = vsi->alloc_txq,
		.scatter_count = ICE_MAX_SCATTER_TXQS,
		.vsi_map = vsi->txq_map,
		.vsi_map_offset = 0,
		.mapping_mode = ICE_VSI_MAP_CONTIG
	};
	struct ice_qs_cfg rx_qs_cfg = {
		.qs_mutex = &pf->avail_q_mutex,
		.pf_map = pf->avail_rxqs,
		.pf_map_size = pf->max_pf_rxqs,
		.q_count = vsi->alloc_rxq,
		.scatter_count = ICE_MAX_SCATTER_RXQS,
		.vsi_map = vsi->rxq_map,
		.vsi_map_offset = 0,
		.mapping_mode = ICE_VSI_MAP_CONTIG
	};
	int ret;

	if (vsi->type == ICE_VSI_PF && !ice_is_safe_mode(pf)) {
		rx_qs_cfg.q_count = pf->max_adq_qps;
		tx_qs_cfg.q_count = pf->max_adq_qps;
	}

	if (vsi->type == ICE_VSI_CHNL)
		return 0;

	ret = __ice_vsi_get_qs(&tx_qs_cfg);
	if (ret)
		return ret;
	vsi->tx_mapping_mode = tx_qs_cfg.mapping_mode;

	ret = __ice_vsi_get_qs(&rx_qs_cfg);
	if (ret)
		return ret;
	vsi->rx_mapping_mode = rx_qs_cfg.mapping_mode;

	return 0;
}

/**
 * ice_vsi_put_qs - Release queues from VSI to PF
 * @vsi: the VSI that is going to release queues
 */
void ice_vsi_put_qs(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	u16 alloc_txq, alloc_rxq;
	u16 i;

	alloc_txq = vsi->alloc_txq;
	alloc_rxq = vsi->alloc_rxq;
	if (vsi->type == ICE_VSI_PF && !ice_is_safe_mode(pf)) {
		alloc_txq = pf->max_adq_qps;
		alloc_rxq = pf->max_adq_qps;
	}

	mutex_lock(&pf->avail_q_mutex);

	for (i = 0; i < alloc_txq; i++) {
		clear_bit(vsi->txq_map[i], pf->avail_txqs);
		vsi->txq_map[i] = ICE_INVAL_Q_INDEX;
	}

	for (i = 0; i < alloc_rxq; i++) {
		clear_bit(vsi->rxq_map[i], pf->avail_rxqs);
		vsi->rxq_map[i] = ICE_INVAL_Q_INDEX;
	}

	mutex_unlock(&pf->avail_q_mutex);
}

/**
 * ice_is_safe_mode
 * @pf: pointer to the PF struct
 *
 * returns true if driver is in safe mode, false otherwise
 */
bool ice_is_safe_mode(struct ice_pf *pf)
{
	return !test_bit(ICE_FLAG_ADV_FEATURES, pf->flags);
}

/**
 * ice_is_aux_ena
 * @pf: pointer to the PF struct
 *
 * returns true if peer devices/drivers are supported, false otherwise
 */
bool ice_is_aux_ena(struct ice_pf *pf)
{
	return test_bit(ICE_FLAG_AUX_ENA, pf->flags);
}

/**
 * ice_vsi_clean_rss_flow_fld - Delete RSS configuration
 * @vsi: the VSI being cleaned up
 *
 * This function deletes RSS input set for all flows that were configured
 * for this VSI
 */
static void ice_vsi_clean_rss_flow_fld(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;

	if (ice_is_safe_mode(pf))
		return;

	status = ice_rem_vsi_rss_cfg(&pf->hw, vsi->idx);
	if (status)
		dev_dbg(ice_pf_to_dev(pf), "ice_rem_vsi_rss_cfg failed for vsi = %d, error = %s\n",
			vsi->vsi_num, ice_stat_str(status));
}

/**
 * ice_rss_clean - Delete RSS related VSI structures and configuration
 * @vsi: the VSI being removed
 *
 * This function deletes RSS related VSI structures that hold user inputs
 * and removes RSS configuration
 */
static void ice_rss_clean(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	if (vsi->rss_hkey_user)
		devm_kfree(dev, vsi->rss_hkey_user);
	if (vsi->rss_lut_user)
		devm_kfree(dev, vsi->rss_lut_user);

	ice_vsi_clean_rss_flow_fld(vsi);
	/* remove RSS replay list */
	if (!ice_is_safe_mode(pf))
		ice_rem_vsi_rss_list(&pf->hw, vsi->idx);
}

/**
 * ice_vsi_set_rss_params - Setup RSS capabilities per VSI type
 * @vsi: the VSI being configured
 */
static void ice_vsi_set_rss_params(struct ice_vsi *vsi)
{
	struct ice_hw_common_caps *cap;
	struct ice_pf *pf = vsi->back;

	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
		vsi->rss_size = 1;
		return;
	}

	cap = &pf->hw.func_caps.common_cap;
	switch (vsi->type) {
	case ICE_VSI_CHNL:
	case ICE_VSI_PF:
		/* PF VSI will inherit RSS instance of PF */
		vsi->rss_table_size = (u16)cap->rss_table_size;
		if (vsi->type == ICE_VSI_CHNL)
			vsi->rss_size = min_t(u16, vsi->num_rxq,
					      BIT(cap->rss_table_entry_width));
		else
#ifdef HAVE_PF_RING
		{
#endif
			vsi->rss_size = min_t(u16, pf->max_qps,
					      BIT(cap->rss_table_entry_width));
#ifdef HAVE_PF_RING
			if (RSS[pf->instance] != 0)
				vsi->rss_size = min_t(int, vsi->rss_size, RSS[pf->instance]);
		}
#endif
		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF;
		break;
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_ADI:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
		vsi->rss_table_size = ICE_VSIQF_HLUT_ARRAY_SIZE;
		vsi->rss_size = min_t(u16, num_online_cpus(),
				      BIT(cap->rss_table_entry_width));
#ifdef HAVE_PF_RING
		if (RSS[pf->instance] != 0)
			vsi->rss_size = min_t(int, vsi->rss_size, RSS[pf->instance]);
#endif
		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_VSI;
		break;
	case ICE_VSI_VF:
		/* VF VSI will get a small RSS table.
		 * For VSI_LUT, LUT size should be set to 64 bytes.
		 */
		vsi->rss_table_size = ICE_VSIQF_HLUT_ARRAY_SIZE;
		vsi->rss_size = ICE_MAX_RSS_QS_PER_VF;
		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_VSI;
		if (vsi->global_lut_id) {
			vsi->rss_table_size = ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_512;
			vsi->rss_size = ICE_MAX_MEDIUM_RSS_QS;
			vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_GLOBAL;
		}
		break;
	case ICE_VSI_LB:
		break;
	default:
		dev_dbg(ice_pf_to_dev(pf), "Unsupported VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		break;
	}
}

/**
 * ice_set_dflt_vsi_ctx - Set default VSI context before adding a VSI
 * @hw: HW structure used to determine the VLAN mode of the device
 * @ctxt: the VSI context being set
 *
 * This initializes a default VSI context for all sections except the Queues.
 */
static void ice_set_dflt_vsi_ctx(struct ice_hw *hw, struct ice_vsi_ctx *ctxt)
{
	u32 table = 0;

	memset(&ctxt->info, 0, sizeof(ctxt->info));
	/* VSI's should be allocated from shared pool */
	ctxt->alloc_from_pool = true;
	/* Src pruning enabled by default */
	ctxt->info.sw_flags = ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	/* Traffic from VSI can be sent to LAN */
	ctxt->info.sw_flags2 = ICE_AQ_VSI_SW_FLAG_LAN_ENA;
	/* allow all untagged/tagged packets by default on Tx */
	ctxt->info.inner_vlan_flags = ((ICE_AQ_VSI_INNER_VLAN_TX_MODE_ALL &
				  ICE_AQ_VSI_INNER_VLAN_TX_MODE_M) >>
				 ICE_AQ_VSI_INNER_VLAN_TX_MODE_S);
	/* SVM - by default bits 3 and 4 in inner_vlan_flags are 0's which
	 * results in legacy behavior (show VLAN, DEI, and UP) in descriptor.
	 *
	 * DVM - leave inner VLAN in packet by default
	 */
	if (ice_is_dvm_ena(hw)) {
		ctxt->info.inner_vlan_flags |=
			ICE_AQ_VSI_INNER_VLAN_EMODE_NOTHING;
		ctxt->info.outer_vlan_flags =
			(ICE_AQ_VSI_OUTER_VLAN_TX_MODE_ALL <<
			 ICE_AQ_VSI_OUTER_VLAN_TX_MODE_S) &
			ICE_AQ_VSI_OUTER_VLAN_TX_MODE_M;
		ctxt->info.outer_vlan_flags |=
			(ICE_AQ_VSI_OUTER_TAG_VLAN_8100 <<
			 ICE_AQ_VSI_OUTER_TAG_TYPE_S) &
			ICE_AQ_VSI_OUTER_TAG_TYPE_M;
		ctxt->info.outer_vlan_flags |=
			ICE_AQ_VSI_OUTER_VLAN_EMODE_NOTHING <<
			ICE_AQ_VSI_OUTER_VLAN_EMODE_S;
	}
	/* Have 1:1 UP mapping for both ingress/egress tables */
	table |= ICE_UP_TABLE_TRANSLATE(0, 0);
	table |= ICE_UP_TABLE_TRANSLATE(1, 1);
	table |= ICE_UP_TABLE_TRANSLATE(2, 2);
	table |= ICE_UP_TABLE_TRANSLATE(3, 3);
	table |= ICE_UP_TABLE_TRANSLATE(4, 4);
	table |= ICE_UP_TABLE_TRANSLATE(5, 5);
	table |= ICE_UP_TABLE_TRANSLATE(6, 6);
	table |= ICE_UP_TABLE_TRANSLATE(7, 7);
	ctxt->info.ingress_table = cpu_to_le32(table);
	ctxt->info.egress_table = cpu_to_le32(table);
	/* Have 1:1 UP mapping for outer to inner UP table */
	ctxt->info.outer_up_table = cpu_to_le32(table);
	/* No Outer tag support outer_tag_flags remains to zero */
}

/**
 * ice_vsi_setup_q_map - Setup a VSI queue map
 * @vsi: the VSI being configured
 * @ctxt: VSI context structure
 */
static int ice_vsi_setup_q_map(struct ice_vsi *vsi, struct ice_vsi_ctx *ctxt)
{
	u16 offset = 0, qmap = 0, tx_count = 0, pow = 0;
	u16 num_txq_per_tc, num_rxq_per_tc;
	u16 qcount_tx = vsi->alloc_txq;
	u16 qcount_rx = vsi->alloc_rxq;
	u8 netdev_tc = 0;
	int i;

	if (!vsi->tc_cfg.numtc) {
		/* at least TC0 should be enabled by default */
		vsi->tc_cfg.numtc = 1;
		vsi->tc_cfg.ena_tc = 1;
	}

	/* For VF VSI, all queues should be mapped to TC0 and other TCs are
	 * assigned to queue 0 by default
	 */
	if (vsi->type == ICE_VSI_VF) {
		num_rxq_per_tc = qcount_rx;
		num_txq_per_tc = qcount_tx;
	} else {
		num_rxq_per_tc = min_t(u16, qcount_rx / vsi->tc_cfg.numtc,
				       ICE_MAX_RXQS_PER_TC);
		if (!num_rxq_per_tc)
			num_rxq_per_tc = 1;
		num_txq_per_tc = qcount_tx / vsi->tc_cfg.numtc;
		if (!num_txq_per_tc)
			num_txq_per_tc = 1;
	}

	/* find the (rounded up) power-of-2 of qcount */
	pow = (u16)order_base_2(num_rxq_per_tc);

	/* TC mapping is a function of the number of Rx queues assigned to the
	 * VSI for each traffic class and the offset of these queues.
	 * The first 10 bits are for queue offset for TC0, next 4 bits for no:of
	 * queues allocated to TC0. No:of queues is a power-of-2.
	 *
	 * If TC is not enabled, the queue offset is set to 0, and allocate one
	 * queue, this way, traffic for the given TC will be sent to the default
	 * queue.
	 *
	 * Setup number and offset of Rx queues for all TCs for the VSI
	 */
	ice_for_each_traffic_class(i) {
		if (!(vsi->tc_cfg.ena_tc & BIT(i)) ||
		    (i != 0 && vsi->type == ICE_VSI_VF)) {
			vsi->tc_cfg.tc_info[i].qoffset = 0;
			vsi->tc_cfg.tc_info[i].qcount_rx = 1;
			vsi->tc_cfg.tc_info[i].qcount_tx = 1;
			vsi->tc_cfg.tc_info[i].netdev_tc = 0;
			ctxt->info.tc_mapping[i] = 0;
			continue;
		}

		/* TC is enabled */
		vsi->tc_cfg.tc_info[i].qoffset = offset;
		vsi->tc_cfg.tc_info[i].qcount_rx = num_rxq_per_tc;
		vsi->tc_cfg.tc_info[i].qcount_tx = num_txq_per_tc;
		vsi->tc_cfg.tc_info[i].netdev_tc = netdev_tc++;

		qmap = ((offset << ICE_AQ_VSI_TC_Q_OFFSET_S) &
			ICE_AQ_VSI_TC_Q_OFFSET_M) |
			((pow << ICE_AQ_VSI_TC_Q_NUM_S) &
			 ICE_AQ_VSI_TC_Q_NUM_M);
		offset += num_rxq_per_tc;
		tx_count += num_txq_per_tc;
		ctxt->info.tc_mapping[i] = cpu_to_le16(qmap);
	}

	/* if offset is non-zero, means it is calculated correctly based on
	 * enabled TCs for a given VSI otherwise qcount_rx will always
	 * be correct and non-zero because it is based off - VSI's
	 * allocated Rx queues which is at least 1 (hence qcount_tx will be
	 * at least 1)
	 */
	if (offset)
		vsi->num_rxq = offset;
	else
		vsi->num_rxq = num_rxq_per_tc;

	if (vsi->num_rxq > vsi->alloc_rxq) {
		dev_err(ice_pf_to_dev(vsi->back), "Trying to use more Rx queues (%u), than were allocated (%u)!\n",
			vsi->num_rxq, vsi->alloc_rxq);
		return -EINVAL;
	}

	vsi->num_txq = tx_count;
	if (vsi->num_txq > vsi->alloc_txq) {
		dev_err(ice_pf_to_dev(vsi->back), "Trying to use more Tx queues (%u), than were allocated (%u)!\n",
			vsi->num_txq, vsi->alloc_txq);
		return -EINVAL;
	}

	if (vsi->type == ICE_VSI_VF && vsi->num_txq != vsi->num_rxq) {
		dev_dbg(ice_pf_to_dev(vsi->back), "VF VSI should have same number of Tx and Rx queues. Hence making them equal\n");
		/* since there is a chance that num_rxq could have been changed
		 * in the above for loop, make num_txq equal to num_rxq.
		 */
		vsi->num_txq = vsi->num_rxq;
	}

	/* Rx queue mapping */
	ctxt->info.mapping_flags |= cpu_to_le16(ICE_AQ_VSI_Q_MAP_CONTIG);
	/* q_mapping buffer holds the info for the first queue allocated for
	 * this VSI in the PF space and also the number of queues associated
	 * with this VSI.
	 */
	ctxt->info.q_mapping[0] = cpu_to_le16(vsi->rxq_map[0]);
	ctxt->info.q_mapping[1] = cpu_to_le16(vsi->num_rxq);

	return 0;
}

/**
 * ice_set_fd_vsi_ctx - Set FD VSI context before adding a VSI
 * @ctxt: the VSI context being set
 * @vsi: the VSI being configured
 */
static void ice_set_fd_vsi_ctx(struct ice_vsi_ctx *ctxt, struct ice_vsi *vsi)
{
	u8 dflt_q_group, dflt_q_prio;
	u16 dflt_q, report_q, val;

	if (vsi->type != ICE_VSI_PF && vsi->type != ICE_VSI_CTRL &&
	    vsi->type != ICE_VSI_VF && vsi->type != ICE_VSI_CHNL)
		return;

	val = ICE_AQ_VSI_PROP_FLOW_DIR_VALID | ICE_AQ_VSI_PROP_ACL_VALID;
	ctxt->info.valid_sections |= cpu_to_le16(val);
	dflt_q = 0;
	dflt_q_group = 0;
	report_q = 0;
	dflt_q_prio = 0;

	/* enable flow director filtering/programming */
	val = ICE_AQ_VSI_FD_ENABLE | ICE_AQ_VSI_FD_PROG_ENABLE;
	ctxt->info.fd_options = cpu_to_le16(val);
	/* max of allocated flow director filters */
	ctxt->info.max_fd_fltr_dedicated =
			cpu_to_le16(vsi->num_gfltr);
	/* max of shared flow director filters any VSI may program */
	ctxt->info.max_fd_fltr_shared =
			cpu_to_le16(vsi->num_bfltr);
	/* default queue index within the VSI of the default FD */
	val = ((dflt_q << ICE_AQ_VSI_FD_DEF_Q_S) &
	       ICE_AQ_VSI_FD_DEF_Q_M);
	/* target queue or queue group to the FD filter */
	val |= ((dflt_q_group << ICE_AQ_VSI_FD_DEF_GRP_S) &
		ICE_AQ_VSI_FD_DEF_GRP_M);
	ctxt->info.fd_def_q = cpu_to_le16(val);
	/* queue index on which FD filter completion is reported */
	val = ((report_q << ICE_AQ_VSI_FD_REPORT_Q_S) &
	       ICE_AQ_VSI_FD_REPORT_Q_M);
	/* priority of the default qindex action */
	val |= ((dflt_q_prio << ICE_AQ_VSI_FD_DEF_PRIORITY_S) &
		ICE_AQ_VSI_FD_DEF_PRIORITY_M);
	ctxt->info.fd_report_opt = cpu_to_le16(val);

#define ICE_ACL_RX_PROF_MISS_CNTR ((2 << ICE_AQ_VSI_ACL_DEF_RX_PROF_S) & \
				   ICE_AQ_VSI_ACL_DEF_RX_PROF_M)
#define ICE_ACL_RX_TBL_MISS_CNTR ((3 << ICE_AQ_VSI_ACL_DEF_RX_TABLE_S) & \
				  ICE_AQ_VSI_ACL_DEF_RX_TABLE_M)

	val = ICE_ACL_RX_PROF_MISS_CNTR | ICE_ACL_RX_TBL_MISS_CNTR;
	ctxt->info.acl_def_act = cpu_to_le16(val);
}

/**
 * ice_set_rss_vsi_ctx - Set RSS VSI context before adding a VSI
 * @ctxt: the VSI context being set
 * @vsi: the VSI being configured
 */
static void ice_set_rss_vsi_ctx(struct ice_vsi_ctx *ctxt, struct ice_vsi *vsi)
{
	u8 lut_type, hash_type, global_lut_id = 0;
	struct device *dev;
	struct ice_pf *pf;

	pf = vsi->back;
	dev = ice_pf_to_dev(pf);

	switch (vsi->type) {
	case ICE_VSI_CHNL:
	case ICE_VSI_PF:
		/* PF VSI will inherit RSS instance of PF */
		lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_PF;
		hash_type = ICE_AQ_VSI_Q_OPT_RSS_TPLZ;
		break;
	case ICE_VSI_VF:
		lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_VSI;
		if (vsi->global_lut_id) {
			lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_GBL;
			global_lut_id = *vsi->global_lut_id;
		}
		hash_type = ICE_AQ_VSI_Q_OPT_RSS_TPLZ;
		break;
	default:
		dev_dbg(dev, "Unsupported VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		return;
	}

	ctxt->info.q_opt_rss = ((lut_type << ICE_AQ_VSI_Q_OPT_RSS_LUT_S) &
				ICE_AQ_VSI_Q_OPT_RSS_LUT_M) |
				(hash_type & ICE_AQ_VSI_Q_OPT_RSS_HASH_M) |
				((global_lut_id << ICE_AQ_VSI_Q_OPT_RSS_GBL_LUT_S) &
				ICE_AQ_VSI_Q_OPT_RSS_GBL_LUT_M);
}

static void
ice_chnl_vsi_setup_q_map(struct ice_vsi *vsi, struct ice_vsi_ctx *ctxt)
{
	struct ice_pf *pf = vsi->back;
	u16 qcount, qmap;
	u8 offset = 0;
	int pow;

	qcount = min_t(int, vsi->num_rxq, pf->num_lan_msix);

	pow = order_base_2(qcount);
	qmap = ((offset << ICE_AQ_VSI_TC_Q_OFFSET_S) &
		 ICE_AQ_VSI_TC_Q_OFFSET_M) |
		 ((pow << ICE_AQ_VSI_TC_Q_NUM_S) &
		   ICE_AQ_VSI_TC_Q_NUM_M);

	ctxt->info.tc_mapping[0] = cpu_to_le16(qmap);
	ctxt->info.mapping_flags |= cpu_to_le16(ICE_AQ_VSI_Q_MAP_CONTIG);
	ctxt->info.q_mapping[0] = cpu_to_le16(vsi->next_base_q);
	ctxt->info.q_mapping[1] = cpu_to_le16(qcount);
}

/**
 * ice_vsi_init - Create and initialize a VSI
 * @vsi: the VSI being configured
 * @init_vsi: is this call creating a VSI
 *
 * This initializes a VSI context depending on the VSI type to be added and
 * passes it down to the add_vsi aq command to create a new VSI.
 */
static int ice_vsi_init(struct ice_vsi *vsi, bool init_vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi_ctx *ctxt;
	struct device *dev;
	int ret = 0;

	dev = ice_pf_to_dev(pf);
	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ice_set_dflt_vsi_ctx(hw, ctxt);

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_LB:
	case ICE_VSI_PF:
		ctxt->flags = ICE_AQ_VSI_TYPE_PF;
		break;
	case ICE_VSI_CHNL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_ADI:
		ctxt->flags = ICE_AQ_VSI_TYPE_VMDQ2;
		break;
	case ICE_VSI_VF:
		ctxt->flags = ICE_AQ_VSI_TYPE_VF;
		/* VF number here is the absolute VF number (0-255) */
		ctxt->vf_num = vsi->vf->vf_id + hw->func_caps.vf_base_id;
		break;
	default:
		ret = -ENODEV;
		goto out;
	}

	/* Handle VLAN pruning for channel VSI if main VSI has VLAN
	 * prune enabled
	 */
	if (vsi->type == ICE_VSI_CHNL) {
		struct ice_vsi *main_vsi;

		main_vsi = ice_get_main_vsi(pf);
		if (main_vsi && ice_vsi_is_vlan_pruning_ena(main_vsi))
			ctxt->info.sw_flags2 |=
				ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
		else
			ctxt->info.sw_flags2 &=
				~ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
	}

	if (test_bit(ICE_FLAG_FD_ENA, pf->flags))
		ice_set_fd_vsi_ctx(ctxt, vsi);

	/* if the switch is in VEB mode, allow VSI loopback */
	if (vsi->vsw->bridge_mode == BRIDGE_MODE_VEB)
		ctxt->info.sw_flags |= (ICE_AQ_VSI_SW_FLAG_ALLOW_LB |
					ICE_AQ_VSI_SW_FLAG_LOCAL_LB);

	/* Set LUT type and HASH type if RSS is enabled */
	if (test_bit(ICE_FLAG_RSS_ENA, pf->flags) &&
	    vsi->type != ICE_VSI_CTRL) {
		ice_set_rss_vsi_ctx(ctxt, vsi);
		/* if updating VSI context, make sure to set valid_section:
		 * to indicate which section of VSI context being updated
		 */
		if (!init_vsi)
			ctxt->info.valid_sections |=
				cpu_to_le16(ICE_AQ_VSI_PROP_Q_OPT_VALID);
	}

	ctxt->info.sw_id = vsi->port_info->sw_id;

	if (vsi->type == ICE_VSI_CHNL) {
		ice_chnl_vsi_setup_q_map(vsi, ctxt);
	} else {
		ret = ice_vsi_setup_q_map(vsi, ctxt);
		if (ret)
			goto out;

		if (!init_vsi) /* means VSI being updated */
			/* must to indicate which section of VSI context are
			 * being modified
			 */
			ctxt->info.valid_sections |=
				cpu_to_le16(ICE_AQ_VSI_PROP_RXQ_MAP_VALID);
	}

	/* Allow control frames out of main VSI */
	if (vsi->type == ICE_VSI_PF) {
		ctxt->info.sec_flags |= ICE_AQ_VSI_SEC_FLAG_ALLOW_DEST_OVRD;
		ctxt->info.valid_sections |=
			cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
	}

	if (init_vsi) {
		ret = ice_add_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Add VSI failed, err %d\n", ret);
			ret = -EIO;
			goto out;
		}
	} else {
		ret = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Update VSI failed, err %d\n", ret);
			ret = -EIO;
			goto out;
		}
	}

	/* keep context for update VSI operations */
	vsi->info = ctxt->info;

	/* record VSI number returned */
	vsi->vsi_num = ctxt->vsi_num;

out:
	kfree(ctxt);
	return ret;
}

/**
 * ice_free_res - free a block of resources
 * @res: pointer to the resource
 * @index: starting index previously returned by ice_get_res
 * @id: identifier to track owner
 *
 * Returns number of resources freed
 */
int ice_free_res(struct ice_res_tracker *res, u16 index, u16 id)
{
	int count = 0;
	int i;

	if (!res || index >= res->end)
		return -EINVAL;

	id |= ICE_RES_VALID_BIT;
	for (i = index; i < res->end && res->list[i] == id; i++) {
		res->list[i] = 0;
		count++;
	}

	return count;
}

/**
 * ice_search_res - Search the tracker for a block of resources
 * @res: pointer to the resource
 * @needed: size of the block needed
 * @id: identifier to track owner
 *
 * Returns the base item index of the block, or -ENOMEM for error
 */
static int ice_search_res(struct ice_res_tracker *res, u16 needed, u16 id)
{
	u16 start = 0, end = 0;

	if (needed > res->end)
		return -ENOMEM;

	id |= ICE_RES_VALID_BIT;

	do {
		/* skip already allocated entries */
		if (res->list[end++] & ICE_RES_VALID_BIT) {
			start = end;
			if ((start + needed) > res->end)
				break;
		}

		if (end == (start + needed)) {
			int i = start;

			/* there was enough, so assign it to the requestor */
			while (i != end)
				res->list[i++] = id;

			return start;
		}
	} while (end < res->end);

	return -ENOMEM;
}

/**
 * ice_get_free_res_count - Get free count from a resource tracker
 * @res: Resource tracker instance
 */
static u16 ice_get_free_res_count(struct ice_res_tracker *res)
{
	u16 i, count = 0;

	for (i = 0; i < res->end; i++)
		if (!(res->list[i] & ICE_RES_VALID_BIT))
			count++;

	return count;
}

/**
 * ice_get_valid_res_count - Get in-use count from a resource tracker
 * @res: Resource tracker instance
 */
u16 ice_get_valid_res_count(struct ice_res_tracker *res)
{
	return res->end - ice_get_free_res_count(res);
}

/**
 * ice_get_res - get a block of resources
 * @pf: board private structure
 * @res: pointer to the resource
 * @needed: size of the block needed
 * @id: identifier to track owner
 *
 * Returns the base item index of the block, or negative for error
 */
int
ice_get_res(struct ice_pf *pf, struct ice_res_tracker *res, u16 needed, u16 id)
{
	if (!res || !pf)
		return -EINVAL;

	if (!needed || needed > res->num_entries || id >= ICE_RES_VALID_BIT) {
		dev_err(ice_pf_to_dev(pf), "param err: needed=%d, num_entries = %d id=0x%04x\n",
			needed, res->num_entries, id);
		return -EINVAL;
	}

	return ice_search_res(res, needed, id);
}

/**
 * ice_get_vf_ctrl_res - Get VF control VSI resource
 * @pf: pointer to the PF structure
 * @vsi: the VSI to allocate a resource for
 *
 * Look up whether another VF has already allocated the control VSI resource.
 * If so, re-use this resource so that we share it among all VFs.
 *
 * Otherwise, allocate the resource and return it.
 */
static int ice_get_vf_ctrl_res(struct ice_pf *pf, struct ice_vsi *vsi)
{
	struct ice_vf *vf;
	unsigned int bkt;
	int base;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf != vsi->vf && vf->ctrl_vsi_idx != ICE_NO_VSI) {
			base = pf->vsi[vf->ctrl_vsi_idx]->base_vector;
			rcu_read_unlock();
			return base;
		}
	}
	rcu_read_unlock();

	return ice_get_res(pf, pf->irq_tracker, vsi->num_q_vectors,
			   ICE_RES_VF_CTRL_VEC_ID);
}

/**
 * ice_vsi_setup_vector_base - Set up the base vector for the given VSI
 * @vsi: ptr to the VSI
 * @tc: traffic class. Used for VF ADQ
 *
 * This should only be called after ice_vsi_alloc() which allocates the
 * corresponding SW VSI structure and initializes num_queue_pairs for the
 * newly allocated VSI.
 *
 * Returns 0 on success or negative on failure
 */
static int ice_vsi_setup_vector_base(struct ice_vsi *vsi, u8 __maybe_unused tc)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	u16 num_q_vectors;
	int base = 0;

	dev = ice_pf_to_dev(pf);
	/* SRIOV doesn't grab irq_tracker entries for each VSI */
	if (vsi->type == ICE_VSI_VF) {
		/* Assign the base_vector to allow determining the vector
		 * index. Note that VF VSIs MSI-X index is relative to the VF
		 * space and does not get tracked individually in the software
		 * IRQ tracker.
		 */
		vsi->base_vector = ICE_NONQ_VECS_VF;
		/* Adjust base_vector for VSIs corresponding to non-zero TC */
		vsi->base_vector += vsi->vf->ch[tc].offset;
		return 0;
	}
	if (vsi->type == ICE_VSI_CHNL)
		return 0;

	if (vsi->base_vector) {
		dev_dbg(dev, "VSI %d has non-zero base vector %d\n",
			vsi->vsi_num, vsi->base_vector);
		return -EEXIST;
	}

	if (vsi->type == ICE_VSI_PF)
		num_q_vectors = pf->max_adq_qps;
	else
		num_q_vectors = vsi->num_q_vectors;

	/* reserve slots from OS requested IRQs */
	if (vsi->type == ICE_VSI_CTRL && vsi->vf) {
		base = ice_get_vf_ctrl_res(pf, vsi);
	} else {
		base = ice_get_res(pf, pf->irq_tracker, num_q_vectors,
				   vsi->idx);
	}

	if (base < 0) {
		dev_err(dev, "%d MSI-X interrupts available. %s %d failed to get %d MSI-X vectors\n",
			ice_get_free_res_count(pf->irq_tracker),
			ice_vsi_type_str(vsi->type), vsi->idx, num_q_vectors);
		return -ENOENT;
	}
	vsi->base_vector = (u16)base;
	pf->num_avail_sw_msix -= num_q_vectors;

	return 0;
}

/**
 * ice_vsi_clear_rings - Deallocates the Tx and Rx rings for VSI
 * @vsi: the VSI having rings deallocated
 */
static void ice_vsi_clear_rings(struct ice_vsi *vsi)
{
	int i;

	/* Avoid stale references by clearing map from vector to ring */
	if (vsi->q_vectors) {
		ice_for_each_q_vector(vsi, i) {
			struct ice_q_vector *q_vector = vsi->q_vectors[i];

			if (q_vector) {
				q_vector->tx.ring = NULL;
				q_vector->rx.ring = NULL;
			}
		}
	}

	if (vsi->tx_rings) {
		for (i = 0; i < vsi->alloc_txq; i++) {
			if (vsi->tx_rings[i]) {
				kfree_rcu(vsi->tx_rings[i], rcu);
				WRITE_ONCE(vsi->tx_rings[i], NULL);
			}
		}
	}
	if (vsi->rx_rings) {
		for (i = 0; i < vsi->alloc_rxq; i++) {
			if (vsi->rx_rings[i]) {
				kfree_rcu(vsi->rx_rings[i], rcu);
				WRITE_ONCE(vsi->rx_rings[i], NULL);
			}
		}
	}
}

/**
 * ice_vsi_alloc_rings - Allocates Tx and Rx rings for the VSI
 * @vsi: VSI which is having rings allocated
 */
static int ice_vsi_alloc_rings(struct ice_vsi *vsi)
{
	bool dvm_ena = ice_is_dvm_ena(&vsi->back->hw);
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	u16 i;

	dev = ice_pf_to_dev(pf);
	/* Allocate Tx rings */
	for (i = 0; i < vsi->alloc_txq; i++) {
		struct ice_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);

		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->txq_map[i];
		ring->vsi = vsi;
		ring->tx_tstamps = &pf->ptp.port.tx;
		ring->dev = dev;
		ring->count = vsi->num_tx_desc;
		ring->txq_teid = ICE_INVAL_TEID;
		if (dvm_ena)
			ring->flags |= ICE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2;
		else
			ring->flags |= ICE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
		WRITE_ONCE(vsi->tx_rings[i], ring);
	}

	/* Allocate Rx rings */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		struct ice_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);
		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->rxq_map[i];
		ring->vsi = vsi;
		ring->netdev = vsi->netdev;
		ring->dev = dev;
		ring->count = vsi->num_rx_desc;
		WRITE_ONCE(vsi->rx_rings[i], ring);
	}

	return 0;

err_out:
	ice_vsi_clear_rings(vsi);
	return -ENOMEM;
}

/**
 * ice_vsi_reset_stats - Reset all stats of a given VSI
 * @vsi: the VSI whose stats needs to be cleared
 */
static void ice_vsi_reset_stats(struct ice_vsi *vsi)
{
	int i;

	if (!vsi)
		return;

	memset(&vsi->net_stats, 0, sizeof(vsi->net_stats));
	memset(&vsi->eth_stats, 0, sizeof(vsi->eth_stats));
	memset(&vsi->eth_stats_prev, 0, sizeof(vsi->eth_stats_prev));

	if (vsi->tx_rings) {
		ice_for_each_txq(vsi, i) {
			if (vsi->tx_rings[i]) {
				memset(&vsi->tx_rings[i]->stats, 0,
				       sizeof(vsi->tx_rings[i]->stats));
				memset(&vsi->tx_rings[i]->tx_stats, 0,
				       sizeof(vsi->tx_rings[i])->tx_stats);
			}
		}
	}
	if (vsi->rx_rings) {
		ice_for_each_rxq(vsi, i) {
			if (vsi->rx_rings[i]) {
				memset(&vsi->rx_rings[i]->stats, 0,
				       sizeof(vsi->rx_rings[i]->stats));
				memset(&vsi->rx_rings[i]->rx_stats, 0,
				       sizeof(vsi->rx_rings[i])->rx_stats);
			}
		}
	}
	vsi->stat_offsets_loaded = false;
}

/**
 * ice_vsi_manage_rss_lut - disable/enable RSS
 * @vsi: the VSI being changed
 * @ena: boolean value indicating if this is an enable or disable request
 *
 * In the event of disable request for RSS, this function will zero out RSS
 * LUT, while in the event of enable request for RSS, it will reconfigure RSS
 * LUT.
 */
void ice_vsi_manage_rss_lut(struct ice_vsi *vsi, bool ena)
{
	u8 *lut;

	lut = kzalloc(vsi->rss_table_size, GFP_KERNEL);
	if (!lut)
		return;

	if (ena) {
		if (vsi->rss_lut_user)
			memcpy(lut, vsi->rss_lut_user, vsi->rss_table_size);
		else
			ice_fill_rss_lut(lut, vsi->rss_table_size,
					 vsi->rss_size);
	}

	ice_set_rss_lut(vsi, lut, vsi->rss_table_size);
	kfree(lut);
}

/**
 * ice_vsi_cfg_rss_lut_key - Configure RSS params for a VSI
 * @vsi: VSI to be configured
 */
int ice_vsi_cfg_rss_lut_key(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	u8 *lut, *key;
	int err;
#ifdef HAVE_PF_RING
	struct ice_hw *hw = &pf->hw;
	u16 reg;
#endif

	dev = ice_pf_to_dev(pf);
#ifdef NETIF_F_HW_TC
	if (vsi->type == ICE_VSI_PF && vsi->ch_rss_size &&
	    (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))) {
		vsi->rss_size = vsi->ch_rss_size;
	} else {
		vsi->rss_size = min_t(u16, vsi->rss_size, vsi->num_rxq);

		/* If orig_rss_size is valid and it is less than determined
		 * main VSI's rss_size, update main VSI's rss_size to be
		 * orig_rss_size so that when tc-qdisc is deleted, main VSI
		 * RSS table gets programmed to be correct (whatever it was
		 * to begin with (prior to setup-tc for ADQ config)
		 */
		if (vsi->orig_rss_size && vsi->rss_size < vsi->orig_rss_size &&
		    vsi->orig_rss_size <= vsi->num_rxq) {
			vsi->rss_size = vsi->orig_rss_size;
			/* now orig_rss_size is used, reset it to zero */
			vsi->orig_rss_size = 0;
		}
	}
#endif /* NETIF_F_HW_TC */

	lut = kzalloc(vsi->rss_table_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	if (vsi->rss_lut_user)
		memcpy(lut, vsi->rss_lut_user, vsi->rss_table_size);
	else
		ice_fill_rss_lut(lut, vsi->rss_table_size, vsi->rss_size);

	err = ice_set_rss_lut(vsi, lut, vsi->rss_table_size);
	if (err) {
		ice_dev_err_errno(dev, err, "set_rss_lut failed");
		goto ice_vsi_cfg_rss_exit;
	}

	key = kzalloc(ICE_GET_SET_RSS_KEY_EXTEND_KEY_SIZE, GFP_KERNEL);
	if (!key) {
		err = -ENOMEM;
		goto ice_vsi_cfg_rss_exit;
	}

	if (vsi->rss_hkey_user)
		memcpy(key, vsi->rss_hkey_user, ICE_GET_SET_RSS_KEY_EXTEND_KEY_SIZE);
	else
		netdev_rss_key_fill((void *)key, ICE_GET_SET_RSS_KEY_EXTEND_KEY_SIZE);

	err = ice_set_rss_key(vsi, key);
	if (err)
		ice_dev_err_errno(dev, err, "set_rss_key failed");

#ifdef HAVE_PF_RING
	/* Enable registers for symmetric RSS
	 * Bits 7:6 - Hash Scheme
	 * 00b = Toeplitz Hash
	 * 01b = Symmetric Toeplitz
	 * 10b = Simple XOR
	 * 11b = Reserved
	*/
	reg = rd32(hw, VSIQF_HASH_CTL(vsi->vsi_num));
	reg = (reg & (~VSIQF_HASH_CTL_HASH_SCHEME_M)) | (1 << VSIQF_HASH_CTL_HASH_SCHEME_S);
	wr32(hw, VSIQF_HASH_CTL(vsi->vsi_num), reg); 
#endif

	kfree(key);
ice_vsi_cfg_rss_exit:
	kfree(lut);
	return err;
}

/**
 * ice_get_valid_rss_size - return valid number of RSS queues
 * @hw: pointer to the HW structure
 * @new_size: requested RSS queues
 */
int ice_get_valid_rss_size(struct ice_hw *hw, int new_size)
{
	struct ice_hw_common_caps *caps = &hw->func_caps.common_cap;

	return min_t(int, new_size, BIT(caps->rss_table_entry_width));
}

/**
 * ice_vsi_set_dflt_rss_lut - set default RSS LUT with requested RSS size
 * @vsi: VSI to reconfigure RSS LUT on
 * @req_rss_size: requested range of queue numbers for hashing
 *
 * Set the VSI's RSS parameters, configure the RSS LUT based on these.
 */
int ice_vsi_set_dflt_rss_lut(struct ice_vsi *vsi, int req_rss_size)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	struct ice_hw *hw;
	int err;
	u8 *lut;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;

	if (!req_rss_size)
		return -EINVAL;

	lut = kzalloc(vsi->rss_table_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	/* set RSS LUT parameters */
	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags))
		vsi->rss_size = 1;
	else
		vsi->rss_size = ice_get_valid_rss_size(hw, req_rss_size);

	/* create/set RSS LUT */
	ice_fill_rss_lut(lut, vsi->rss_table_size, vsi->rss_size);
	err = ice_set_rss_lut(vsi, lut, vsi->rss_table_size);
	if (err)
		ice_dev_err_errno(dev, err, "Cannot set RSS lut, aq_err %s",
				  ice_aq_str(hw->adminq.sq_last_status));

	kfree(lut);
	return err;
}

/**
 * ice_vsi_set_vf_rss_flow_fld - Sets VF VSI RSS input set for different flows
 * @vsi: VSI to be configured
 *
 * This function will only be called during the VF VSI setup. Upon successful
 * completion of package download, this function will configure default RSS
 * input sets for VF VSI.
 */
static void ice_vsi_set_vf_rss_flow_fld(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		dev_dbg(dev, "Advanced RSS disabled. Package download failed, vsi num = %d\n",
			vsi->vsi_num);
		return;
	}

	status = ice_add_avf_rss_cfg(&pf->hw, vsi->idx, ICE_DEFAULT_RSS_HENA);
	if (status)
		dev_dbg(dev, "ice_add_avf_rss_cfg failed for vsi = %d, error = %s\n",
			vsi->vsi_num, ice_stat_str(status));
}

static const struct ice_rss_hash_cfg default_rss_cfgs[] = {
#ifdef HAVE_PF_RING
	/* configure RSS for IPv4 with input set IP src/dst */
	{ICE_FLOW_SEG_HDR_IPV4, ICE_FLOW_HASH_IPV4, ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for IPv6 with input set IPv6 src/dst */
	{ICE_FLOW_SEG_HDR_IPV6, ICE_FLOW_HASH_IPV6, ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for tcp4 with input set IP src/dst, TCP src/dst */
	{ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_TCP_IPV4,  ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for udp4 with input set IP src/dst, UDP src/dst */
	{ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_UDP_IPV4,  ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for sctp4 with input set IP src/dst */
	{ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_SCTP_IPV4, ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for tcp6 with input set IPv6 src/dst, TCP src/dst */
	{ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_TCP_IPV6,  ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for udp6 with input set IPv6 src/dst, UDP src/dst */
	{ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_UDP_IPV6,  ICE_RSS_ANY_HEADERS, true},
	/* configure RSS for sctp6 with input set IPv6 src/dst */
	{ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_SCTP_IPV6, ICE_RSS_ANY_HEADERS, true},
#else /* HAVE_PF_RING */
	/* configure RSS for IPv4 with input set IP src/dst */
	{ICE_FLOW_SEG_HDR_IPV4, ICE_FLOW_HASH_IPV4, ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for IPv6 with input set IPv6 src/dst */
	{ICE_FLOW_SEG_HDR_IPV6, ICE_FLOW_HASH_IPV6, ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for tcp4 with input set IP src/dst, TCP src/dst */
	{ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_TCP_IPV4,  ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for udp4 with input set IP src/dst, UDP src/dst */
	{ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_UDP_IPV4,  ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for sctp4 with input set IP src/dst */
	{ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV4,
				ICE_HASH_SCTP_IPV4, ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for tcp6 with input set IPv6 src/dst, TCP src/dst */
	{ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_TCP_IPV6,  ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for udp6 with input set IPv6 src/dst, UDP src/dst */
	{ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_UDP_IPV6,  ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for sctp6 with input set IPv6 src/dst */
	{ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV6,
				ICE_HASH_SCTP_IPV6, ICE_RSS_ANY_HEADERS, false},
	/* configure RSS for IPSEC ESP SPI with input set MAC_IPV4_SPI */
	{ ICE_FLOW_SEG_HDR_ESP,
			ICE_FLOW_HASH_ESP_SPI, ICE_RSS_ANY_HEADERS, false },
#endif /* HAVE_PF_RING */
};

/**
 * ice_vsi_set_rss_flow_fld - Sets RSS input set for different flows
 * @vsi: VSI to be configured
 *
 * This function will only be called after successful download package call
 * during initialization of PF. Since the downloaded package will erase the
 * RSS section, this function will configure RSS input sets for different
 * flow types. The last profile added has the highest priority, therefore 2
 * tuple profiles (i.e. IPv4 src/dst) are added before 4 tuple profiles
 * (i.e. IPv4 src/dst TCP src/dst port).
 */
static void ice_vsi_set_rss_flow_fld(struct ice_vsi *vsi)
{
	u16 vsi_handle = vsi->idx, vsi_num = vsi->vsi_num;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	struct device *dev;
	u32 i;

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		dev_dbg(dev, "Advanced RSS disabled. Package download failed, vsi num = %d\n",
			vsi_num);
		return;
	}

	for (i = 0; i < ARRAY_SIZE(default_rss_cfgs); i++) {
		const struct ice_rss_hash_cfg *cfg = &default_rss_cfgs[i];
		enum ice_status status;

		status = ice_add_rss_cfg(hw, vsi_handle, cfg);
		if (status)
			dev_dbg(dev, "ice_add_rss_cfg failed, addl_hdrs = %x, hash_flds = %llx, hdr_type = %d, symm = %d\n",
				cfg->addl_hdrs, cfg->hash_flds, cfg->hdr_type,
				cfg->symm);
	}
}

/**
 * ice_pf_state_is_nominal - checks the PF for nominal state
 * @pf: pointer to PF to check
 *
 * Check the PF's state for a collection of bits that would indicate
 * the PF is in a state that would inhibit normal operation for
 * driver functionality.
 *
 * Returns true if PF is in a nominal state, false otherwise
 */
bool ice_pf_state_is_nominal(struct ice_pf *pf)
{
	DECLARE_BITMAP(check_bits, ICE_STATE_NBITS) = { 0 };

	if (!pf)
		return false;

	bitmap_set(check_bits, 0, ICE_STATE_NOMINAL_CHECK_BITS);
	if (bitmap_intersects(pf->state, check_bits, ICE_STATE_NBITS))
		return false;

	return true;
}

/**
 * ice_update_eth_stats - Update VSI-specific ethernet statistics counters
 * @vsi: the VSI to be updated
 */
void ice_update_eth_stats(struct ice_vsi *vsi)
{
	struct ice_eth_stats *prev_es, *cur_es;
	struct ice_hw *hw = &vsi->back->hw;
	u16 vsi_num = vsi->vsi_num;    /* HW absolute index of a VSI */

	prev_es = &vsi->eth_stats_prev;
	cur_es = &vsi->eth_stats;

	ice_stat_update40(hw, GLV_GORCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->rx_bytes, &cur_es->rx_bytes);

	ice_stat_update40(hw, GLV_UPRCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->rx_unicast, &cur_es->rx_unicast);

	ice_stat_update40(hw, GLV_MPRCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->rx_multicast, &cur_es->rx_multicast);

	ice_stat_update40(hw, GLV_BPRCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->rx_broadcast, &cur_es->rx_broadcast);

	ice_stat_update32(hw, GLV_RDPC(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->rx_discards, &cur_es->rx_discards);

	ice_stat_update40(hw, GLV_GOTCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->tx_bytes, &cur_es->tx_bytes);

	ice_stat_update40(hw, GLV_UPTCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->tx_unicast, &cur_es->tx_unicast);

	ice_stat_update40(hw, GLV_MPTCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->tx_multicast, &cur_es->tx_multicast);

	ice_stat_update40(hw, GLV_BPTCL(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->tx_broadcast, &cur_es->tx_broadcast);

	ice_stat_update32(hw, GLV_TEPC(vsi_num), vsi->stat_offsets_loaded,
			  &prev_es->tx_errors, &cur_es->tx_errors);

	vsi->stat_offsets_loaded = true;
}

/**
 * ice_vsi_cfg_frame_size - setup max frame size and Rx buffer length
 * @vsi: VSI
 */
void ice_vsi_cfg_frame_size(struct ice_vsi *vsi)
{
	if (!vsi->netdev || test_bit(ICE_FLAG_LEGACY_RX, vsi->back->flags)) {
		vsi->max_frame = ICE_AQ_SET_MAC_FRAME_SIZE_MAX;
		vsi->rx_buf_len = ICE_RXBUF_2048;
#if (PAGE_SIZE < 8192)
	} else if (!ICE_2K_TOO_SMALL_WITH_PADDING &&
		   (vsi->netdev->mtu <= ETH_DATA_LEN)) {
		vsi->max_frame = ICE_RXBUF_1536 - NET_IP_ALIGN;
		vsi->rx_buf_len = ICE_RXBUF_1536 - NET_IP_ALIGN;
#endif
	} else {
		vsi->max_frame = ICE_AQ_SET_MAC_FRAME_SIZE_MAX;
#if (PAGE_SIZE < 8192)
		vsi->rx_buf_len = ICE_RXBUF_3072;
#else
		vsi->rx_buf_len = ICE_RXBUF_2048;
#endif
	}
}

/**
 * ice_write_qrxflxp_cntxt - write/configure QRXFLXP_CNTXT register
 * @hw: HW pointer
 * @pf_q: index of the Rx queue in the PF's queue space
 * @rxdid: flexible descriptor RXDID
 * @prio: priority for the RXDID for this queue
 * @ena_ts: true to enable timestamp and false to disable timestamp
 */
void
ice_write_qrxflxp_cntxt(struct ice_hw *hw, u16 pf_q, u32 rxdid, u32 prio,
			bool ena_ts)
{
	int regval = rd32(hw, QRXFLXP_CNTXT(pf_q));

	/* clear any previous values */
	regval &= ~(QRXFLXP_CNTXT_RXDID_IDX_M |
		    QRXFLXP_CNTXT_RXDID_PRIO_M |
		    QRXFLXP_CNTXT_TS_M);

	regval |= (rxdid << QRXFLXP_CNTXT_RXDID_IDX_S) &
		QRXFLXP_CNTXT_RXDID_IDX_M;

	regval |= (prio << QRXFLXP_CNTXT_RXDID_PRIO_S) &
		QRXFLXP_CNTXT_RXDID_PRIO_M;

	if (ena_ts)
		/* Enable TimeSync on this queue */
		regval |= QRXFLXP_CNTXT_TS_M;

	wr32(hw, QRXFLXP_CNTXT(pf_q), regval);
}

int ice_vsi_cfg_single_rxq(struct ice_vsi *vsi, u16 q_idx)
{
	if (q_idx >= vsi->num_rxq)
		return -EINVAL;

	return ice_vsi_cfg_rxq(vsi->rx_rings[q_idx]);
}

int ice_vsi_cfg_single_txq(struct ice_vsi *vsi, struct ice_ring **tx_rings, u16 q_idx)
{
	struct ice_aqc_add_tx_qgrp *qg_buf;
	int err;

	if (q_idx >= vsi->alloc_txq || !tx_rings || !tx_rings[q_idx])
		return -EINVAL;

	qg_buf = kzalloc(struct_size(qg_buf, txqs, 1), GFP_KERNEL);
	if (!qg_buf)
		return -ENOMEM;

	qg_buf->num_txqs = 1;

	err = ice_vsi_cfg_txq(vsi, tx_rings[q_idx], qg_buf);
	kfree(qg_buf);
	return err;
}

/**
 * ice_vsi_cfg_rxqs - Configure the VSI for Rx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Rx VSI for operation.
 */
int ice_vsi_cfg_rxqs(struct ice_vsi *vsi)
{
	u16 i;

	if (vsi->type == ICE_VSI_VF)
		goto setup_rings;

	ice_vsi_cfg_frame_size(vsi);
setup_rings:
	/* set up individual rings */
	ice_for_each_rxq(vsi, i) {
		int err = ice_vsi_cfg_rxq(vsi->rx_rings[i]);

		if (err)
			return err;
	}

	return 0;
}

/**
 * ice_vsi_cfg_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 * @tx_rings: Tx ring array to be configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
static int
ice_vsi_cfg_txqs(struct ice_vsi *vsi, struct ice_ring **tx_rings)
{
	struct ice_aqc_add_tx_qgrp *qg_buf;
	u16 q_idx = 0;
	int err = 0;

	qg_buf = kzalloc(struct_size(qg_buf, txqs, 1), GFP_KERNEL);
	if (!qg_buf)
		return -ENOMEM;

	qg_buf->num_txqs = 1;

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		err = ice_vsi_cfg_txq(vsi, tx_rings[q_idx], qg_buf);
		if (err)
			goto err_cfg_txqs;
	}

err_cfg_txqs:
	kfree(qg_buf);
	return err;
}

/**
 * ice_vsi_cfg_lan_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
int ice_vsi_cfg_lan_txqs(struct ice_vsi *vsi)
{
	return ice_vsi_cfg_txqs(vsi, vsi->tx_rings);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * ice_vsi_cfg_xdp_txqs - Configure Tx queues dedicated for XDP in given VSI
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx queues dedicated for XDP in given VSI for operation.
 */
int ice_vsi_cfg_xdp_txqs(struct ice_vsi *vsi)
{
	int ret;
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	int i;
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

	ret = ice_vsi_cfg_txqs(vsi, vsi->xdp_rings);
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (ret)
		return ret;

	for (i = 0; i < vsi->num_xdp_txq; i++)
		vsi->xdp_rings[i]->xsk_pool = ice_xsk_umem(vsi->xdp_rings[i]);
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

	return ret;
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * ice_intrl_usec_to_reg - convert interrupt rate limit to register value
 * @intrl: interrupt rate limit in usecs
 * @gran: interrupt rate limit granularity in usecs
 *
 * This function converts a decimal interrupt rate limit in usecs to the format
 * expected by firmware.
 */
static u32 ice_intrl_usec_to_reg(u8 intrl, u8 gran)
{
	u32 val = intrl / gran;

	if (val)
		return val | GLINT_RATE_INTRL_ENA_M;
	return 0;
}

/**
 * ice_write_intrl - write throttle rate limit to interrupt specific register
 * @q_vector: pointer to interrupt specific structure
 * @intrl: throttle rate limit in microseconds to write
 */
void ice_write_intrl(struct ice_q_vector *q_vector, u8 intrl)
{
	struct ice_hw *hw = &q_vector->vsi->back->hw;

	wr32(hw, GLINT_RATE(q_vector->reg_idx),
	     ice_intrl_usec_to_reg(intrl, ICE_INTRL_GRAN_ABOVE_25));
}

/**
 * __ice_write_itr - write throttle rate to register
 * @q_vector: pointer to interrupt data structure
 * @rc: pointer to ring container
 * @itr: throttle rate in microseconds to write
 */
static void __ice_write_itr(struct ice_q_vector *q_vector,
			    struct ice_ring_container *rc, u16 itr)
{
	struct ice_hw *hw = &q_vector->vsi->back->hw;

	wr32(hw, GLINT_ITR(rc->itr_idx, q_vector->reg_idx),
	     ITR_REG_ALIGN(itr) >> ICE_ITR_GRAN_S);
}

/**
 * ice_write_itr - write throttle rate to queue specific register
 * @rc: pointer to ring container
 * @itr: throttle rate in microseconds to write
 */
void ice_write_itr(struct ice_ring_container *rc, u16 itr)
{
	struct ice_q_vector *q_vector;

	if (!rc->ring)
		return;

	q_vector = rc->ring->q_vector;

	__ice_write_itr(q_vector, rc, itr);
}

/**
 * ice_set_q_vector_intrl - set up interrupt rate limiting
 * @q_vector: the vector to be configured
 *
 * Interrupt rate limiting is local to the vector, not per-queue so we must
 * detect if either ring container has dynamic enabled to decide what to set
 * the interrupt rate limit to via INTRL settings. In the case of dynamic
 * disabled on both, write the value with the cached setting to make sure
 * INTRL matches user visible value.
 */
void ice_set_q_vector_intrl(struct ice_q_vector *q_vector)
{
	if (ITR_IS_DYNAMIC(&q_vector->tx) || ITR_IS_DYNAMIC(&q_vector->rx)) {
		/* in the case of dynamic enabled, cap each vector to no more
		 * than (4 us) 250,000 ints/sec, which allows low latency
		 * but still less than 500,000 interrupts per second, which
		 * reduces CPU a bit in the case of the lowest latency
		 * setting. The 4 here is a value in microseconds.
		 */
		ice_write_intrl(q_vector, 4);
	} else {
		ice_write_intrl(q_vector, q_vector->intrl);
	}
}

/**
 * ice_vsi_cfg_msix - MSIX mode Interrupt Config in the HW
 * @vsi: the VSI being configured
 *
 * This configures MSIX mode interrupts for the PF VSI, and should not be used
 * for the VF VSI.
 */
void ice_vsi_cfg_msix(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	u16 txq = 0, rxq = 0;
	int i, q;

	for (i = 0; i < vsi->num_q_vectors; i++) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];
		u16 reg_idx = q_vector->reg_idx;

		ice_cfg_itr(hw, q_vector);

		/* Both Transmit Queue Interrupt Cause Control register
		 * and Receive Queue Interrupt Cause control register
		 * expects MSIX_INDX field to be the vector index
		 * within the function space and not the absolute
		 * vector index across PF or across device.
		 * For SR-IOV VF VSIs queue vector index always starts
		 * with 1 since first vector index(0) is used for OICR
		 * in VF space. Since VMDq and other PF VSIs are within
		 * the PF function space, use the vector index that is
		 * tracked for this PF.
		 */
		for (q = 0; q < q_vector->num_ring_tx; q++) {
			ice_cfg_txq_interrupt(vsi, txq, reg_idx,
					      q_vector->tx.itr_idx);
			txq++;
		}

		for (q = 0; q < q_vector->num_ring_rx; q++) {
			ice_cfg_rxq_interrupt(vsi, rxq, reg_idx,
					      q_vector->rx.itr_idx);
			rxq++;
		}
	}
}

/**
 * ice_vsi_start_all_rx_rings - start/enable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be enabled
 *
 * Returns 0 on success and a negative value on error
 */
int ice_vsi_start_all_rx_rings(struct ice_vsi *vsi)
{
	return ice_vsi_ctrl_all_rx_rings(vsi, true);
}

/**
 * ice_vsi_stop_all_rx_rings - stop/disable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be disabled
 *
 * Returns 0 on success and a negative value on error
 */
int ice_vsi_stop_all_rx_rings(struct ice_vsi *vsi)
{
	return ice_vsi_ctrl_all_rx_rings(vsi, false);
}

/**
 * ice_vsi_stop_tx_rings - Disable Tx rings
 * @vsi: the VSI being configured
 * @rst_src: reset source
 * @rel_vmvf_num: Relative ID of VF/VM
 * @rings: Tx ring array to be stopped
 */
static int
ice_vsi_stop_tx_rings(struct ice_vsi *vsi, enum ice_disq_rst_src rst_src,
		      u16 rel_vmvf_num, struct ice_ring **rings)
{
	u16 q_idx;

	if (vsi->num_txq > ICE_LAN_TXQ_MAX_QDIS)
		return -EINVAL;

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		struct ice_txq_meta txq_meta = { };
		int status;

		if (!rings || !rings[q_idx])
			return -EINVAL;

		ice_fill_txq_meta(vsi, rings[q_idx], &txq_meta);
		status = ice_vsi_stop_tx_ring(vsi, rst_src, rel_vmvf_num,
					      rings[q_idx], &txq_meta);

		if (status)
			return status;
	}

	return 0;
}

/**
 * ice_vsi_stop_lan_tx_rings - Disable LAN Tx rings
 * @vsi: the VSI being configured
 * @rst_src: reset source
 * @rel_vmvf_num: Relative ID of VF/VM
 */
int
ice_vsi_stop_lan_tx_rings(struct ice_vsi *vsi, enum ice_disq_rst_src rst_src,
			  u16 rel_vmvf_num)
{
	return ice_vsi_stop_tx_rings(vsi, rst_src, rel_vmvf_num, vsi->tx_rings);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * ice_vsi_stop_xdp_tx_rings - Disable XDP Tx rings
 * @vsi: the VSI being configured
 */
int ice_vsi_stop_xdp_tx_rings(struct ice_vsi *vsi)
{
	return ice_vsi_stop_tx_rings(vsi, ICE_NO_RESET, 0, vsi->xdp_rings);
}

#endif /* HAVE_XDP_SUPPORT */

/**
 * ice_vsi_is_vlan_pruning_ena - check if VLAN pruning is enabled or not
 * @vsi: VSI to check whether or not VLAN pruning is enabled.
 *
 * returns true if Rx VLAN pruning is enabled and false otherwise.
 */
bool ice_vsi_is_vlan_pruning_ena(struct ice_vsi *vsi)
{
	if (!vsi)
		return false;

	return (vsi->info.sw_flags2 & ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA);
}

static void ice_vsi_set_tc_cfg(struct ice_vsi *vsi)
{
	if (!test_bit(ICE_FLAG_DCB_ENA, vsi->back->flags)) {
		vsi->tc_cfg.ena_tc = ICE_DFLT_TRAFFIC_CLASS;
		vsi->tc_cfg.numtc = 1;
		return;
	}

	/* set VSI TC information based on DCB config */
	ice_vsi_set_dcb_tc_cfg(vsi);
}

/**
 * ice_vsi_set_q_vectors_reg_idx - set the HW register index for all q_vectors
 * @vsi: VSI to set the q_vectors register index on
 * @tc: traffic class for VF ADQ
 */
static int ice_vsi_set_q_vectors_reg_idx(struct ice_vsi *vsi,
					 u8 __maybe_unused tc)
{
	u16 i;

	if (!vsi || !vsi->q_vectors)
		return -EINVAL;

	ice_for_each_q_vector(vsi, i) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];

		if (!q_vector) {
			dev_err(ice_pf_to_dev(vsi->back), "Failed to set reg_idx on q_vector %d VSI %d\n",
				i, vsi->vsi_num);
			goto clear_reg_idx;
		}

		if (vsi->type == ICE_VSI_VF) {
			struct ice_vf *vf = vsi->vf;

			q_vector->reg_idx =
					ice_calc_vf_reg_idx(vf, q_vector, tc);
		} else {
			q_vector->reg_idx =
				q_vector->v_idx + vsi->base_vector;
		}
	}

	return 0;

clear_reg_idx:
	ice_for_each_q_vector(vsi, i) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];

		if (q_vector)
			q_vector->reg_idx = 0;
	}

	return -EINVAL;
}

/**
 * ice_cfg_sw_lldp - Config switch rules for LLDP packet handling
 * @vsi: the VSI being configured
 * @tx: bool to determine Tx or Rx rule
 * @create: bool to determine create or remove Rule
 */
void ice_cfg_sw_lldp(struct ice_vsi *vsi, bool tx, bool create)
{
	enum ice_status (*eth_fltr)(struct ice_vsi *v, u16 type, u16 flag,
				    enum ice_sw_fwd_act_type act);
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	eth_fltr = create ? ice_fltr_add_eth : ice_fltr_remove_eth;

	if (tx) {
		status = eth_fltr(vsi, ETH_P_LLDP, ICE_FLTR_TX,
				  ICE_DROP_PACKET);
	} else {
		if (ice_fw_supports_lldp_fltr_ctrl(&pf->hw)) {
			status = ice_lldp_fltr_add_remove(&pf->hw, vsi->vsi_num,
							  create);
		} else {
			status = eth_fltr(vsi, ETH_P_LLDP, ICE_FLTR_RX,
					  ICE_FWD_TO_VSI);
		}
	}

	if (status)
		dev_dbg(dev, "Fail %s %s LLDP rule on VSI %i error: %s\n",
			create ? "adding" : "removing", tx ? "TX" : "RX",
			vsi->vsi_num, ice_stat_str(status));
}

/**
 * ice_set_agg_vsi - sets up scheduler aggregator node and move VSI into it
 * @vsi: pointer to the VSI
 *
 * This function will allocate new scheduler aggregator now if needed and will
 * move specified VSI into it.
 */
static void ice_set_agg_vsi(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct ice_agg_node *agg_node_iter = NULL;
	u32 agg_id = ICE_INVALID_AGG_NODE_ID;
	struct ice_agg_node *agg_node = NULL;
	int node_offset, max_agg_nodes = 0;
	struct ice_port_info *port_info;
	struct ice_pf *pf = vsi->back;
	u32 agg_node_id_start = 0;
	enum ice_status status;

	/* create (as needed) scheduler aggregator node and move VSI into
	 * corresponding aggregator node
	 * - PF aggregator node to contains VSIs of type _PF, _CTRL, _CHNL
	 * - MACVLAN aggregator node to contain MACVLAN VSIs only
	 * - VF aggregator nodes will contain VF VSI including VF ADQ VSIs
	 */
	port_info = pf->hw.port_info;
	if (!port_info)
		return;

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_CHNL:
	case ICE_VSI_LB:
	case ICE_VSI_PF:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
		max_agg_nodes = ICE_MAX_PF_AGG_NODES;
		agg_node_id_start = ICE_PF_AGG_NODE_ID_START;
		agg_node_iter = &pf->pf_agg_node[0];
		break;
	case ICE_VSI_VF:
		/* user can create 'n' VFs on a given PF, but since max children
		 * per aggregator node can be only 64. Following code handles
		 * aggregator(s) for VF VSIs, either selects a agg_node which
		 * was already created provided num_vsis < 64, otherwise
		 * select next available node, which will be created
		 */
		max_agg_nodes = ICE_MAX_VF_AGG_NODES;
		agg_node_id_start = ICE_VF_AGG_NODE_ID_START;
		agg_node_iter = &pf->vf_agg_node[0];
		break;
#ifdef HAVE_NDO_DFWD_OPS
	case ICE_VSI_OFFLOAD_MACVLAN:
		/* there can be 'n' offloaded NACVLAN, hence select the desired
		 * aggregator node for offloaded MACVLAN VSI
		 */
		max_agg_nodes = ICE_MAX_MACVLAN_AGG_NODES;
		agg_node_id_start = ICE_MACVLAN_AGG_NODE_ID_START;
		agg_node_iter = &pf->macvlan_agg_node[0];
		break;
#endif
	default:
		/* other VSI type, handle later if needed */
		dev_dbg(dev, "unexpected VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		return;
	}

	/* find the appropriate aggregator node */
	for (node_offset = 0; node_offset < max_agg_nodes; node_offset++) {
		/* see if we can find space in previously created
		 * node if num_vsis < 64, otherwise skip
		 */
		if (agg_node_iter->num_vsis &&
		    agg_node_iter->num_vsis == ICE_MAX_VSIS_IN_AGG_NODE) {
			agg_node_iter++;
			continue;
		}

		if (agg_node_iter->valid &&
		    agg_node_iter->agg_id != ICE_INVALID_AGG_NODE_ID) {
			agg_id = agg_node_iter->agg_id;
			agg_node = agg_node_iter;
			break;
		}

		/* find unclaimed agg_id */
		if (agg_node_iter->agg_id == ICE_INVALID_AGG_NODE_ID) {
			agg_id = node_offset + agg_node_id_start;
			agg_node = agg_node_iter;
			break;
		}
		/* move to next agg_node */
		agg_node_iter++;
	}

	if (!agg_node)
		return;

	/* if selected aggregator node was not created, create it */
	if (!agg_node->valid) {
		status = ice_cfg_agg(port_info, agg_id, ICE_AGG_TYPE_AGG,
				     (u8)vsi->tc_cfg.ena_tc);
		if (status) {
			dev_err(dev, "unable to create aggregator node with agg_id %u\n",
				agg_id);
			return;
		}
		/* aggregator node is created, store the neeeded info */
		agg_node->valid = true;
		agg_node->agg_id = agg_id;
	}

	/* move VSI to corresponding aggregator node */
	status = ice_move_vsi_to_agg(port_info, agg_id, vsi->idx,
				     (u8)vsi->tc_cfg.ena_tc);
	if (status) {
		dev_err(dev, "unable to move VSI idx %u into aggregator %u node",
			vsi->idx, agg_id);
		return;
	}

	/* keep active children count for aggregator node */
	agg_node->num_vsis++;

	/* cache the 'agg_id' in VSI, so that after reset - VSI will be moved
	 * to aggregator node
	 */
	vsi->agg_node = agg_node;
	dev_dbg(dev, "successfully moved VSI idx %u tc_bitmap 0x%x) into aggregator node %d which has num_vsis %u\n",
		vsi->idx, vsi->tc_cfg.ena_tc, vsi->agg_node->agg_id,
		vsi->agg_node->num_vsis);
}

/**
 * ice_vsi_setup - Set up a VSI by a given type
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 * @vsi_type: VSI type
 * @vf: pointer to the VF associated with this VSI, if any. VSIs not
 *      connected to a VF should pass NULL.
 * @ch: ptr to channel
 * @tc: traffic class for VF ADQ
 *
 * This allocates the sw VSI structure and its queue resources.
 *
 * Returns pointer to the successfully allocated and configured VSI sw struct on
 * success, NULL on failure.
 */
struct ice_vsi *
ice_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi,
	      enum ice_vsi_type vsi_type, struct ice_vf *vf,
	      struct ice_channel *ch, u8 tc)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	struct ice_vsi *vsi;
	int ret, i;

	if (vsi_type == ICE_VSI_CHNL)
		vsi = ice_vsi_alloc(pf, vsi_type, ch, vf, 0);
	else
		vsi = ice_vsi_alloc(pf, vsi_type, NULL, vf, tc);

	if (!vsi) {
		dev_err(dev, "could not allocate VSI\n");
		return NULL;
	}

	vsi->port_info = pi;
	vsi->vsw = pf->first_sw;
	if (vsi->type == ICE_VSI_PF)
		vsi->ethtype = ETH_P_PAUSE;

	ice_alloc_fd_res(vsi);

	if (vsi_type != ICE_VSI_CHNL) {
		if (ice_vsi_get_qs(vsi)) {
			dev_err(dev, "Failed to allocate queues. vsi->idx = %d\n",
				vsi->idx);
			goto unroll_vsi_alloc;
		}
	}

	ice_vsi_alloc_rss_global_lut(vsi);

	/* set RSS capabilities */
	ice_vsi_set_rss_params(vsi);

	/* set TC configuration */
	ice_vsi_set_tc_cfg(vsi);

	/* create the VSI */
	ret = ice_vsi_init(vsi, true);
	if (ret)
		goto unroll_get_qs;

	ice_vsi_init_vlan_ops(vsi);

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_ADI:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_PF:
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_setup_vector_base(vsi, 0);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = ice_vsi_set_q_vectors_reg_idx(vsi, 0);

		if (ret)
			goto unroll_vector_base;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vector_base;

		ice_vsi_map_rings_to_vectors(vsi);
		ice_vsi_reset_stats(vsi);

		/* ICE_VSI_CTRL does not need RSS so skip RSS processing */
		if (vsi->type != ICE_VSI_CTRL)
			/* Do not exit if configuring RSS had an issue, at
			 * least receive traffic on first queue. Hence no
			 * need to capture return value
			 */
			if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
				ice_vsi_cfg_rss_lut_key(vsi);
				ice_vsi_set_rss_flow_fld(vsi);
			}
		ice_init_arfs(vsi);
		break;
	case ICE_VSI_CHNL:
		if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			ice_vsi_cfg_rss_lut_key(vsi);
			ice_vsi_set_rss_flow_fld(vsi);
		}
		break;
	case ICE_VSI_VF:
		/* VF driver will take care of creating netdev for this type and
		 * map queues to vectors through Virtchnl, PF driver only
		 * creates a VSI and corresponding structures for bookkeeping
		 * purpose
		 */
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = ice_vsi_setup_vector_base(vsi, tc);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = ice_vsi_set_q_vectors_reg_idx(vsi, tc);
		if (ret)
			goto unroll_vector_base;

		/* Do not exit if configuring RSS had an issue, at least
		 * receive traffic on first queue. Hence no need to capture
		 * return value
		 */
		if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			ice_vsi_cfg_rss_lut_key(vsi);
			ice_vsi_set_vf_rss_flow_fld(vsi);
		}
		break;
	case ICE_VSI_LB:
		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vsi_init;
		break;
	default:
		/* clean up the resources and exit */
		goto unroll_vsi_init;
	}

	/* configure VSI nodes based on number of queues and TC's */
	ice_for_each_traffic_class(i) {
		if (!(vsi->tc_cfg.ena_tc & BIT(i)))
			continue;

		if (vsi->type == ICE_VSI_CHNL) {
			if (!vsi->alloc_txq && vsi->num_txq)
				max_txqs[i] = vsi->num_txq;
			else
				max_txqs[i] = pf->num_lan_tx;
		} else {
			max_txqs[i] = vsi->alloc_txq;
		}
	}

	dev_dbg(dev, "vsi->tc_cfg.ena_tc = %d\n", vsi->tc_cfg.ena_tc);
	status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				 max_txqs);
	if (status) {
		dev_err(dev, "VSI %d failed lan queue config, error %s\n",
			vsi->vsi_num, ice_stat_str(status));
		goto unroll_clear_rings;
	}

	/* Add switch rule to drop all Tx Flow Control Frames, of look up
	 * type ETHERTYPE from VSIs, and restrict malicious VF from sending
	 * out PAUSE or PFC frames. If enabled, FW can still send FC frames.
	 * The rule is added once for PF VSI in order to create appropriate
	 * recipe, since VSI/VSI list is ignored with drop action...
	 * Also add rules to handle LLDP Tx packets.  Tx LLDP packets need to
	 * be dropped so that VFs cannot send LLDP packets to reconfig DCB
	 * settings in the HW.
	 */
	if (!ice_is_safe_mode(pf))
		if (vsi->type == ICE_VSI_PF) {
			ice_fltr_add_eth(vsi, ETH_P_PAUSE, ICE_FLTR_TX,
					 ICE_DROP_PACKET);
			ice_cfg_sw_lldp(vsi, true, true);
		}

	if (!vsi->agg_node)
		ice_set_agg_vsi(vsi);

	return vsi;

unroll_clear_rings:
	ice_vsi_clear_rings(vsi);
unroll_vector_base:
	/* reclaim SW interrupts back to the common pool */
	ice_free_res(pf->irq_tracker, vsi->base_vector, vsi->idx);
	pf->num_avail_sw_msix += vsi->num_q_vectors;
unroll_alloc_q_vector:
	ice_vsi_free_q_vectors(vsi);
unroll_vsi_init:
	ice_vsi_delete(vsi);
unroll_get_qs:
	ice_vsi_put_qs(vsi);
unroll_vsi_alloc:
	ice_vsi_clear(vsi);

	return NULL;
}

/**
 * ice_vsi_release_msix - Clear the queue to Interrupt mapping in HW
 * @vsi: the VSI being cleaned up
 */
static void ice_vsi_release_msix(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	u32 txq = 0;
	u32 rxq = 0;
	int i, q;

	for (i = 0; i < vsi->num_q_vectors; i++) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];

		ice_write_intrl(q_vector, 0);
		for (q = 0; q < q_vector->num_ring_tx; q++) {
			ice_write_itr(&q_vector->tx, 0);
			wr32(hw, QINT_TQCTL(vsi->txq_map[txq]), 0);
#ifdef HAVE_XDP_SUPPORT
			if (ice_is_xdp_ena_vsi(vsi)) {
				u32 xdp_txq = txq + vsi->num_xdp_txq;

				wr32(hw, QINT_TQCTL(vsi->txq_map[xdp_txq]), 0);
			}
#endif /* HAVE_XDP_SUPPORT */
			txq++;
		}

		for (q = 0; q < q_vector->num_ring_rx; q++) {
			ice_write_itr(&q_vector->rx, 0);
			wr32(hw, QINT_RQCTL(vsi->rxq_map[rxq]), 0);
			rxq++;
		}
	}

	ice_flush(hw);
}

/**
 * ice_vsi_free_irq - Free the IRQ association with the OS
 * @vsi: the VSI being configured
 */
void ice_vsi_free_irq(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	int base = vsi->base_vector;
	int i;

	if (!vsi->q_vectors || !vsi->irqs_ready)
		return;

	ice_vsi_release_msix(vsi);
	if (vsi->type == ICE_VSI_VF)
		return;

	vsi->irqs_ready = false;
	ice_for_each_q_vector(vsi, i) {
		u16 vector = i + base;
		int irq_num;

		irq_num = ice_get_irq_num(pf, vector);

		/* free only the irqs that were actually requested */
		if (!vsi->q_vectors[i] ||
		    !(vsi->q_vectors[i]->num_ring_tx ||
		      vsi->q_vectors[i]->num_ring_rx))
			continue;

		/* clear the affinity notifier in the IRQ descriptor */
		irq_set_affinity_notifier(irq_num, NULL);

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(irq_num, NULL);
		synchronize_irq(irq_num);
		devm_free_irq(ice_pf_to_dev(pf), irq_num, vsi->q_vectors[i]);
	}
}

/**
 * ice_vsi_free_tx_rings - Free Tx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void ice_vsi_free_tx_rings(struct ice_vsi *vsi)
{
	int i;

	if (!vsi->tx_rings)
		return;

	ice_for_each_txq(vsi, i)
		if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc)
			ice_free_tx_ring(vsi->tx_rings[i]);
}

/**
 * ice_vsi_free_rx_rings - Free Rx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void ice_vsi_free_rx_rings(struct ice_vsi *vsi)
{
	int i;

	if (!vsi->rx_rings)
		return;

	ice_for_each_rxq(vsi, i)
		if (vsi->rx_rings[i] && vsi->rx_rings[i]->desc)
			ice_free_rx_ring(vsi->rx_rings[i]);
}

/**
 * ice_vsi_close - Shut down a VSI
 * @vsi: the VSI being shut down
 */
void ice_vsi_close(struct ice_vsi *vsi)
{
	if (!test_and_set_bit(ICE_VSI_DOWN, vsi->state))
#ifdef HAVE_PF_RING
	{
		if (unlikely(enable_debug))
			printk("[PF_RING-ZC] %s -> ice_down\n", __FUNCTION__);
#endif
		ice_down(vsi);
#ifdef HAVE_PF_RING
	}
#endif
	ice_vsi_free_irq(vsi);
	ice_vsi_free_tx_rings(vsi);
	ice_vsi_free_rx_rings(vsi);
}

/**
 * ice_ena_vsi - resume a VSI
 * @vsi: the VSI being resume
 * @locked: is the rtnl_lock already held
 */
int ice_ena_vsi(struct ice_vsi *vsi, bool locked)
{
	int err = 0;

	if (!test_bit(ICE_VSI_NEEDS_RESTART, vsi->state))
		return 0;

	clear_bit(ICE_VSI_NEEDS_RESTART, vsi->state);

	if (vsi->netdev && vsi->type == ICE_VSI_PF) {
		if (netif_running(vsi->netdev)) {
			if (!locked)
				rtnl_lock();

			err = ice_open_internal(vsi->netdev);

			if (!locked)
				rtnl_unlock();
		}
#ifdef HAVE_NDO_DFWD_OPS

		if (err)
			return err;
		if (test_bit(ICE_FLAG_MACVLAN_ENA, vsi->back->flags) &&
		    !ice_is_adq_active(vsi->back))
			err = ice_vsi_cfg_netdev_tc0(vsi);
#endif /* HAVE_NDO_DFWD_OPS */
	} else if (vsi->type == ICE_VSI_CTRL) {
		err = ice_vsi_open_ctrl(vsi);
#ifdef HAVE_NDO_DFWD_OPS
	} else if (vsi->type == ICE_VSI_OFFLOAD_MACVLAN) {
		err = ice_vsi_open(vsi);
#endif /* HAVE_NDO_DFWD_OPS */
	}

	return err;
}

/**
 * ice_dis_vsi - pause a VSI
 * @vsi: the VSI being paused
 * @locked: is the rtnl_lock already held
 */
void ice_dis_vsi(struct ice_vsi *vsi, bool locked)
{
	if (test_bit(ICE_VSI_DOWN, vsi->state))
		return;

	set_bit(ICE_VSI_NEEDS_RESTART, vsi->state);

	if (vsi->type == ICE_VSI_PF && vsi->netdev) {
		if (netif_running(vsi->netdev)) {
			if (!locked)
				rtnl_lock();

			ice_vsi_close(vsi);

			if (!locked)
				rtnl_unlock();
		} else {
			ice_vsi_close(vsi);
		}
	} else if (vsi->type == ICE_VSI_CTRL) {
		ice_vsi_close(vsi);
#ifdef HAVE_NDO_DFWD_OPS
	} else if (vsi->type == ICE_VSI_OFFLOAD_MACVLAN) {
		ice_vsi_close(vsi);
#endif /* HAVE_NDO_DFWD_OPS */
	} else if (vsi->type == ICE_VSI_SWITCHDEV_CTRL) {
		ice_vsi_close(vsi);
	}
}

/**
 * ice_vsi_dis_irq - Mask off queue interrupt generation on the VSI
 * @vsi: the VSI being un-configured
 */
void ice_vsi_dis_irq(struct ice_vsi *vsi)
{
	int base = vsi->base_vector;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	u32 val;
	int i;

	/* disable interrupt causation from each queue */
	if (vsi->tx_rings) {
		ice_for_each_txq(vsi, i) {
			if (vsi->tx_rings[i]) {
				u16 reg;

				reg = vsi->tx_rings[i]->reg_idx;
				val = rd32(hw, QINT_TQCTL(reg));
				val &= ~QINT_TQCTL_CAUSE_ENA_M;
				wr32(hw, QINT_TQCTL(reg), val);
			}
		}
	}

	if (vsi->rx_rings) {
		ice_for_each_rxq(vsi, i) {
			if (vsi->rx_rings[i]) {
				u16 reg;

				reg = vsi->rx_rings[i]->reg_idx;
				val = rd32(hw, QINT_RQCTL(reg));
				val &= ~QINT_RQCTL_CAUSE_ENA_M;
				wr32(hw, QINT_RQCTL(reg), val);
			}
		}
	}

	/* disable each interrupt */
	ice_for_each_q_vector(vsi, i) {
		if (!vsi->q_vectors[i])
			continue;

		wr32(hw, GLINT_DYN_CTL(vsi->q_vectors[i]->reg_idx), 0);
	}

	ice_flush(hw);

	/* don't call synchronize_irq() for VF's from the host */
	if (vsi->type == ICE_VSI_VF)
		return;

	ice_for_each_q_vector(vsi, i)
		synchronize_irq(ice_get_irq_num(pf, i + base));
}

/**
 * ice_napi_del - Remove NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be removed
 */
void ice_napi_del(struct ice_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, v_idx)
		netif_napi_del(&vsi->q_vectors[v_idx]->napi);
}

/**
 * ice_free_vf_ctrl_res - Free the VF control VSI resource
 * @pf: pointer to PF structure
 * @vsi: the VSI to free resources for
 *
 * Check if the VF control VSI resource is still in use. If no VF is using it
 * any more, release the VSI resource. Otherwise, leave it to be cleaned up
 * once no other VF uses it.
 */
static void ice_free_vf_ctrl_res(struct ice_pf *pf,  struct ice_vsi *vsi)
{
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf != vsi->vf && vf->ctrl_vsi_idx != ICE_NO_VSI) {
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();

	/* No other VFs left that have control VSI. It is now safe to reclaim
	 * SW interrupts back to the common pool.
	 */
	ice_free_res(pf->irq_tracker, vsi->base_vector,
		     ICE_RES_VF_CTRL_VEC_ID);
	pf->num_avail_sw_msix += vsi->num_q_vectors;
}

/**
 * ice_vsi_release - Delete a VSI and free its resources
 * @vsi: the VSI being removed
 *
 * Returns 0 on success or < 0 on error
 */
int ice_vsi_release(struct ice_vsi *vsi)
{
	struct ice_pf *pf;
	int err;

	if (!vsi->back)
		return -ENODEV;
	pf = vsi->back;

	/* do not unregister while driver is in the reset recovery pending
	 * state. Since reset/rebuild happens through PF service task workqueue,
	 * it's not a good idea to unregister netdev that is associated to the
	 * PF that is running the work queue items currently. This is done to
	 * avoid check_flush_dependency() warning on this wq
	 */
	if (vsi->netdev && !ice_is_reset_in_progress(pf->state) &&
	    (test_bit(ICE_VSI_NETDEV_REGISTERED, vsi->state))) {
		unregister_netdev(vsi->netdev);
		clear_bit(ICE_VSI_NETDEV_REGISTERED, vsi->state);

		if (vsi->type == ICE_VSI_PF)
			ice_devlink_destroy_pf_port(pf);
	}

	if (test_bit(ICE_FLAG_RSS_ENA, pf->flags))
		ice_rss_clean(vsi);

	/* Disable VSI and free resources */
	if (vsi->type != ICE_VSI_LB)
		ice_vsi_dis_irq(vsi);
	ice_vsi_close(vsi);

	/* SR-IOV determines needed MSIX resources all at once instead of per
	 * VSI since when VFs are spawned we know how many VFs there are and how
	 * many interrupts each VF needs. SR-IOV MSIX resources are also
	 * cleared in the same manner.
	 */
	if (vsi->type == ICE_VSI_CTRL && vsi->vf) {
		ice_free_vf_ctrl_res(pf, vsi);
	} else if (vsi->type != ICE_VSI_VF) {
		/* reclaim SW interrupts back to the common pool */
		ice_free_res(pf->irq_tracker, vsi->base_vector, vsi->idx);
		pf->num_avail_sw_msix += vsi->num_q_vectors;
	}

	if (!ice_is_safe_mode(pf)) {
		if (vsi->type == ICE_VSI_PF) {
			ice_fltr_remove_eth(vsi, ETH_P_PAUSE, ICE_FLTR_TX,
					    ICE_DROP_PACKET);
			ice_cfg_sw_lldp(vsi, true, false);
			/* The Rx rule will only exist to remove if the LLDP FW
			 * engine is currently stopped
			 */
			if (!test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags))
				ice_cfg_sw_lldp(vsi, false, false);
		}
	}

	ice_fltr_remove_all(vsi);
	ice_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	err = ice_rm_vsi_rdma_cfg(vsi->port_info, vsi->idx);
	if (err)
		dev_info(ice_pf_to_dev(vsi->back), "Failed to remove RDMA scheduler config for VSI %u, err %d\n",
			 vsi->vsi_num, err);
	ice_vsi_delete(vsi);
	ice_vsi_free_q_vectors(vsi);

	if (vsi->netdev && !ice_is_reset_in_progress(pf->state)) {
		if (test_bit(ICE_VSI_NETDEV_REGISTERED, vsi->state)) {
			unregister_netdev(vsi->netdev);
			clear_bit(ICE_VSI_NETDEV_REGISTERED, vsi->state);
		}
		if (test_bit(ICE_VSI_NETDEV_ALLOCD, vsi->state)) {
			free_netdev(vsi->netdev);
			vsi->netdev = NULL;
			clear_bit(ICE_VSI_NETDEV_ALLOCD, vsi->state);
		}
	}

	if (vsi->type == ICE_VSI_VF &&
	    vsi->agg_node && vsi->agg_node->valid)
		vsi->agg_node->num_vsis--;
	ice_vsi_clear_rings(vsi);

	ice_vsi_put_qs(vsi);

	/* retain SW VSI data structure since it is needed to unregister and
	 * free VSI netdev when PF is not in reset recovery pending state,\
	 * for ex: during rmmod.
	 */
	if (!ice_is_reset_in_progress(pf->state))
		ice_vsi_clear(vsi);

	return 0;
}

/**
 * ice_vsi_rebuild_get_coalesce - get coalesce from all q_vectors
 * @vsi: VSI connected with q_vectors
 * @coalesce: array of struct with stored coalesce
 *
 * Returns array size.
 */
static int
ice_vsi_rebuild_get_coalesce(struct ice_vsi *vsi,
			     struct ice_coalesce_stored *coalesce)
{
	int i;

	ice_for_each_q_vector(vsi, i) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];

		coalesce[i].itr_tx = q_vector->tx.itr_settings;
		coalesce[i].itr_rx = q_vector->rx.itr_settings;
		coalesce[i].intrl = q_vector->intrl;

		if (i < vsi->num_txq)
			coalesce[i].tx_valid = true;
		if (i < vsi->num_rxq)
			coalesce[i].rx_valid = true;
	}

	return vsi->num_q_vectors;
}

/**
 * ice_vsi_rebuild_set_coalesce - set coalesce from earlier saved arrays
 * @vsi: VSI connected with q_vectors
 * @coalesce: pointer to array of struct with stored coalesce
 * @size: size of coalesce array
 *
 * Before this function, ice_vsi_rebuild_get_coalesce should be called to save
 * ITR params in arrays. If size is 0 or coalesce wasn't stored set coalesce
 * to default value.
 */
static void
ice_vsi_rebuild_set_coalesce(struct ice_vsi *vsi,
			     struct ice_coalesce_stored *coalesce, int size)
{
	struct ice_ring_container *rc;
	int i;

	if ((size && !coalesce) || !vsi)
		return;

	/* There are a couple of cases that have to be handled here:
	 *   1. The case where the number of queue vectors stays the same, but
	 *      the number of Tx or Rx rings changes (the first for loop)
	 *   2. The case where the number of queue vectors increased (the
	 *      second for loop)
	 */
	for (i = 0; i < size && i < vsi->num_q_vectors; i++) {
		/* There are 2 cases to handle here and they are the same for
		 * both Tx and Rx:
		 *   if the entry was valid previously (coalesce[i].[tr]x_valid
		 *   and the loop variable is less than the number of rings
		 *   allocated, then write the previous values
		 *
		 *   if the entry was not valid previously, but the number of
		 *   rings is less than are allocated (this means the number of
		 *   rings increased from previously), then write out the
		 *   values in the first element
		 *
		 *   Also, always write the ITR, even if in ITR_IS_DYNAMIC
		 *   as there is no harm because the dynamic algorithm
		 *   will just overwrite.
		 */
		if (i < vsi->alloc_rxq && coalesce[i].rx_valid) {
			rc = &vsi->q_vectors[i]->rx;
			rc->itr_settings = coalesce[i].itr_rx;
			ice_write_itr(rc, rc->itr_settings);
		} else if (i < vsi->alloc_rxq) {
			rc = &vsi->q_vectors[i]->rx;
			rc->itr_settings = coalesce[0].itr_rx;
			ice_write_itr(rc, rc->itr_settings);
		}

		if (i < vsi->alloc_txq && coalesce[i].tx_valid) {
			rc = &vsi->q_vectors[i]->tx;
			rc->itr_settings = coalesce[i].itr_tx;
			ice_write_itr(rc, rc->itr_settings);
		} else if (i < vsi->alloc_txq) {
			rc = &vsi->q_vectors[i]->tx;
			rc->itr_settings = coalesce[0].itr_tx;
			ice_write_itr(rc, rc->itr_settings);
		}

		vsi->q_vectors[i]->intrl = coalesce[i].intrl;
		ice_set_q_vector_intrl(vsi->q_vectors[i]);
	}

	/* the number of queue vectors increased so write whatever is in
	 * the first element
	 */
	for (; i < vsi->num_q_vectors; i++) {
		/* transmit */
		rc = &vsi->q_vectors[i]->tx;
		rc->itr_settings = coalesce[0].itr_tx;
		ice_write_itr(rc, rc->itr_settings);

		/* receive */
		rc = &vsi->q_vectors[i]->rx;
		rc->itr_settings = coalesce[0].itr_rx;
		ice_write_itr(rc, rc->itr_settings);

		vsi->q_vectors[i]->intrl = coalesce[0].intrl;
		ice_set_q_vector_intrl(vsi->q_vectors[i]);
	}
}

/**
 * ice_vsi_rebuild - Rebuild VSI after reset
 * @vsi: VSI to be rebuild
 * @init_vsi: is this an initialization or a reconfigure of the VSI
 *
 * Returns 0 on success and negative value on failure
 */
int ice_vsi_rebuild(struct ice_vsi *vsi, bool init_vsi)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	struct ice_coalesce_stored *coalesce;
	int prev_num_q_vectors = 0;
	enum ice_vsi_type vtype;
	enum ice_status status;
	struct ice_pf *pf;
	int ret, i;

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;
	vtype = vsi->type;

	if (WARN_ON(!vsi->vf && ice_vsi_requires_vf(vtype)))
		return -EINVAL;

	ice_vsi_init_vlan_ops(vsi);

	coalesce = kcalloc(vsi->num_q_vectors,
			   sizeof(struct ice_coalesce_stored), GFP_KERNEL);
	if (!coalesce)
		return -ENOMEM;

	prev_num_q_vectors = ice_vsi_rebuild_get_coalesce(vsi, coalesce);

	ice_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	ret = ice_rm_vsi_rdma_cfg(vsi->port_info, vsi->idx);
	if (ret)
		dev_info(ice_pf_to_dev(vsi->back), "Failed to remove RDMA scheduler config for VSI %u, err %d\n",
			 vsi->vsi_num, ret);
	ice_vsi_free_q_vectors(vsi);

	/* SR-IOV determines needed MSIX resources all at once instead of per
	 * VSI since when VFs are spawned we know how many VFs there are and how
	 * many interrupts each VF needs. SR-IOV MSIX resources are also
	 * cleared in the same manner.
	 */
	if (vtype != ICE_VSI_VF) {
		/* reclaim SW interrupts back to the common pool */
		ice_free_res(pf->irq_tracker, vsi->base_vector, vsi->idx);
		pf->num_avail_sw_msix += vsi->num_q_vectors;
		vsi->base_vector = 0;
	}

#ifdef HAVE_XDP_SUPPORT
	if (ice_is_xdp_ena_vsi(vsi))
		/* return value check can be skipped here, it always returns
		 * 0 if reset is in progress
		 */
		ice_destroy_xdp_rings(vsi);
#endif /* HAVE_XDP_SUPPORT */
	ice_vsi_put_qs(vsi);
	ice_vsi_clear_rings(vsi);
	ice_vsi_free_arrays(vsi);
	ice_vsi_free_rss_global_lut(vsi);
	ice_vsi_set_num_qs(vsi, vsi->vf);

	ret = ice_vsi_alloc_arrays(vsi);
	if (ret < 0)
		goto err_vsi;

	ice_vsi_get_qs(vsi);
	ice_vsi_alloc_rss_global_lut(vsi);

	ice_alloc_fd_res(vsi);
	ice_vsi_set_tc_cfg(vsi);

	/* Initialize VSI struct elements and create VSI in FW */
	ret = ice_vsi_init(vsi, init_vsi);
	if (ret < 0)
		goto err_vsi;

	switch (vtype) {
	case ICE_VSI_CTRL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_ADI:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_PF:
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto err_rings;

		ret = ice_vsi_setup_vector_base(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = ice_vsi_set_q_vectors_reg_idx(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto err_vectors;

		ice_vsi_map_rings_to_vectors(vsi);
		ice_vsi_reset_stats(vsi);
#ifdef HAVE_XDP_SUPPORT
		if (ice_is_xdp_ena_vsi(vsi)) {
			vsi->num_xdp_txq = vsi->alloc_rxq;
			ret = ice_prepare_xdp_rings(vsi, vsi->xdp_prog);
			if (ret)
				goto err_vectors;
		}
#endif /* HAVE_XDP_SUPPORT */
		/* ICE_VSI_CTRL does not need RSS so skip RSS processing */
		if (vtype != ICE_VSI_CTRL)
			/* Do not exit if configuring RSS had an issue, at
			 * least receive traffic on first queue. Hence no
			 * need to capture return value
			 */
			if (test_bit(ICE_FLAG_RSS_ENA, pf->flags))
				ice_vsi_cfg_rss_lut_key(vsi);
		break;
	case ICE_VSI_VF:
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto err_rings;

		ret = ice_vsi_set_q_vectors_reg_idx(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto err_vectors;

		ice_vsi_reset_stats(vsi);
		break;
	case ICE_VSI_CHNL:
		if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			ice_vsi_cfg_rss_lut_key(vsi);
			ice_vsi_set_rss_flow_fld(vsi);
		}
		break;
	default:
		break;
	}

	for (i = 0; i < vsi->tc_cfg.numtc; i++) {
		/* configure VSI nodes based on number of queues and TC's.
		 * ADQ creates VSIs for each TC/Channel but doesn't
		 * allocate queues instead it reconfigures the PF queues
		 * as per the TC command. So max_txqs should point to the
		 * PF Tx queues.
		 */
		if (vtype == ICE_VSI_CHNL)
			max_txqs[i] = pf->num_lan_tx;
		else
			max_txqs[i] = vsi->alloc_txq;

#ifdef HAVE_XDP_SUPPORT
		if (ice_is_xdp_ena_vsi(vsi))
			max_txqs[i] += vsi->num_xdp_txq;
#endif /* HAVE_XDP_SUPPORT */
	}

#ifdef NETIF_F_HW_TC
	if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		/* If MQPRIO is set, means channel code path, hence for main
		 * VSI's, use TC as 1
		 */
		status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx, 1, max_txqs);
	else
#endif /* NETIF_F_HW_TC */
		status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx,
					 vsi->tc_cfg.ena_tc, max_txqs);

	if (status) {
		dev_err(ice_pf_to_dev(pf), "VSI %d failed lan queue config, error %s\n",
			vsi->vsi_num, ice_stat_str(status));
		if (init_vsi) {
			ret = -EIO;
			goto err_vectors;
		} else {
			return ice_schedule_reset(pf, ICE_RESET_PFR);
		}
	}

	ice_vsi_rebuild_set_coalesce(vsi, coalesce, prev_num_q_vectors);
	kfree(coalesce);

	return 0;

err_vectors:
	ice_vsi_free_q_vectors(vsi);
err_rings:
	ice_vsi_clear_rings(vsi);
err_vsi:
	if (init_vsi)
		ice_vsi_delete(vsi);
	ice_vsi_put_qs(vsi);
	set_bit(ICE_RESET_FAILED, pf->state);
	kfree(coalesce);
	return ret;
}

/**
 * ice_is_reset_in_progress - check for a reset in progress
 * @state: PF state field
 */
bool ice_is_reset_in_progress(unsigned long *state)
{
	return test_bit(ICE_RESET_OICR_RECV, state) ||
	       test_bit(ICE_PFR_REQ, state) ||
	       test_bit(ICE_CORER_REQ, state) ||
	       test_bit(ICE_GLOBR_REQ, state);
}

/**
 * ice_wait_for_reset - Wait for driver to finish reset and rebuild
 * @pf: pointer to the PF structure
 * @timeout: length of time to wait, in jiffies
 *
 * Wait (sleep) for a short time until the driver finishes cleaning up from
 * a device reset. The caller must be able to sleep. Use this to delay
 * operations that could fail while the driver is cleaning up after a device
 * reset.
 *
 * Returns 0 on success, -EBUSY if the reset is not finished within the
 * timeout, and -ERESTARTSYS if the thread was interrupted.
 */
int ice_wait_for_reset(struct ice_pf *pf, unsigned long timeout)
{
	long ret;

#ifdef __CHECKER__
	/* Suppress sparse warning from kernel macro:
	 * warning: symbol '__ret' shadows an earlier one
	 */
	ret = timeout;
#else
	ret = wait_event_interruptible_timeout(pf->reset_wait_queue,
					       !ice_is_reset_in_progress(pf->state),
					       timeout);
#endif
	if (ret < 0)
		return ret;
	else if (!ret)
		return -EBUSY;
	else
		return 0;
}

/**
 * ice_vsi_update_q_map - update our copy of the VSI info with new queue map
 * @vsi: VSI being configured
 * @ctx: the context buffer returned from AQ VSI update command
 */
static void ice_vsi_update_q_map(struct ice_vsi *vsi, struct ice_vsi_ctx *ctx)
{
	vsi->info.mapping_flags = ctx->info.mapping_flags;
	memcpy(&vsi->info.q_mapping, &ctx->info.q_mapping,
	       sizeof(vsi->info.q_mapping));
	memcpy(&vsi->info.tc_mapping, ctx->info.tc_mapping,
	       sizeof(vsi->info.tc_mapping));
}

/**
 * ice_vsi_cfg_netdev_tc - Setup the netdev TC configuration
 * @vsi: the VSI being configured
 * @ena_tc: TC map to be enabled
 */
void ice_vsi_cfg_netdev_tc(struct ice_vsi *vsi, u8 ena_tc)
{
	struct net_device *netdev = vsi->netdev;
	struct ice_pf *pf = vsi->back;
	int numtc = vsi->tc_cfg.numtc;
	struct ice_dcbx_cfg *dcbcfg;
	u8 netdev_tc;
	int i;

	if (!netdev)
		return;

#ifdef NETIF_F_HW_TC
	/* CHNL VSI doesn't have it's own netdev, hence, no netdev_tc */
	if (vsi->type == ICE_VSI_CHNL)
		return;
#endif /* NETIF_F_HW_TC */

	if (!ena_tc) {
		netdev_reset_tc(netdev);
		return;
	}

#ifdef NETIF_F_HW_TC
	if (vsi->type == ICE_VSI_PF && ice_is_adq_active(pf))
		numtc = vsi->all_numtc;
#endif /* NETIF_F_HW_TC */

	if (netdev_set_num_tc(netdev, numtc))
		return;

	dcbcfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	ice_for_each_traffic_class(i)
		if (vsi->tc_cfg.ena_tc & BIT(i))
			netdev_set_tc_queue(netdev,
					    vsi->tc_cfg.tc_info[i].netdev_tc,
					    vsi->tc_cfg.tc_info[i].qcount_tx,
					    vsi->tc_cfg.tc_info[i].qoffset);
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	/* setup TC queue map for CHNL TCs */
	ice_for_each_chnl_tc(i) {
		if (!(vsi->all_enatc & BIT(i)))
			break;
		if (!vsi->mqprio_qopt.qopt.count[i])
			break;
		netdev_set_tc_queue(netdev, i,
				    vsi->mqprio_qopt.qopt.count[i],
				    vsi->mqprio_qopt.qopt.offset[i]);
	}

#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#ifdef NETIF_F_HW_TC
	if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		return;
#endif /* NETIF_F_HW_TC */

	for (i = 0; i < ICE_MAX_USER_PRIORITY; i++) {
		u8 ets_tc = dcbcfg->etscfg.prio_table[i];

		/* Get the mapped netdev TC# for the UP */
		netdev_tc = vsi->tc_cfg.tc_info[ets_tc].netdev_tc;
		netdev_set_prio_tc_map(netdev, i, netdev_tc);
	}
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * ice_vsi_setup_q_map_mqprio - Prepares mqprio based tc_config
 * @vsi: the VSI being configured,
 * @ctxt: VSI context structure
 * @ena_tc: number of traffic classes to enable
 *
 * Prepares VSI tc_config to have queue configurations based on MQPRIO options.
 */
static int
ice_vsi_setup_q_map_mqprio(struct ice_vsi *vsi, struct ice_vsi_ctx *ctxt,
			   u8 ena_tc)
{
	u16 pow, offset = 0, qcount_tx = 0, qcount_rx = 0, qmap;
	u16 tc0_offset = vsi->mqprio_qopt.qopt.offset[0];
	int tc0_qcount = vsi->mqprio_qopt.qopt.count[0];
	u8 netdev_tc = 0;
	int i;

	vsi->tc_cfg.ena_tc = ena_tc ? ena_tc : 1;

	pow = order_base_2(tc0_qcount);
	qmap = ((tc0_offset << ICE_AQ_VSI_TC_Q_OFFSET_S) &
		ICE_AQ_VSI_TC_Q_OFFSET_M) |
		((pow << ICE_AQ_VSI_TC_Q_NUM_S) & ICE_AQ_VSI_TC_Q_NUM_M);

	ice_for_each_traffic_class(i) {
		if (!(vsi->tc_cfg.ena_tc & BIT(i))) {
			/* TC is not enabled */
			vsi->tc_cfg.tc_info[i].qoffset = 0;
			vsi->tc_cfg.tc_info[i].qcount_rx = 1;
			vsi->tc_cfg.tc_info[i].qcount_tx = 1;
			vsi->tc_cfg.tc_info[i].netdev_tc = 0;
			ctxt->info.tc_mapping[i] = 0;
			continue;
		}

		offset = vsi->mqprio_qopt.qopt.offset[i];
		qcount_rx = vsi->mqprio_qopt.qopt.count[i];
		qcount_tx = vsi->mqprio_qopt.qopt.count[i];
		vsi->tc_cfg.tc_info[i].qoffset = offset;
		vsi->tc_cfg.tc_info[i].qcount_rx = qcount_rx;
		vsi->tc_cfg.tc_info[i].qcount_tx = qcount_tx;
		vsi->tc_cfg.tc_info[i].netdev_tc = netdev_tc++;
	}

	if (vsi->all_numtc && vsi->all_numtc != vsi->tc_cfg.numtc) {
		ice_for_each_chnl_tc(i) {
			if (!(vsi->all_enatc & BIT(i)))
				continue;
			offset = vsi->mqprio_qopt.qopt.offset[i];
			qcount_rx = vsi->mqprio_qopt.qopt.count[i];
			qcount_tx = vsi->mqprio_qopt.qopt.count[i];
		}
	}

	/* Set actual Tx/Rx queue pairs */
	vsi->num_txq = offset + qcount_tx;
	if (vsi->num_txq > vsi->alloc_txq) {
		dev_err(ice_pf_to_dev(vsi->back), "Trying to use more Tx queues (%u), than were allocated (%u)!\n",
			vsi->num_txq, vsi->alloc_txq);
		return -EINVAL;
	}

	vsi->num_rxq = offset + qcount_rx;
	if (vsi->num_rxq > vsi->alloc_rxq) {
		dev_err(ice_pf_to_dev(vsi->back), "Trying to use more Rx queues (%u), than were allocated (%u)!\n",
			vsi->num_rxq, vsi->alloc_rxq);
		return -EINVAL;
	}

	/* Setup queue TC[0].qmap for given VSI context */
	ctxt->info.tc_mapping[0] = cpu_to_le16(qmap);
	ctxt->info.q_mapping[0] = cpu_to_le16(vsi->rxq_map[0]);
	ctxt->info.q_mapping[1] = cpu_to_le16(tc0_qcount);

	/* Find queue count available for channel VSIs and starting offset
	 * for channel VSIs
	 */
	if (tc0_qcount && tc0_qcount < vsi->num_rxq) {
		vsi->cnt_q_avail = vsi->num_rxq - tc0_qcount;
		vsi->next_base_q = tc0_qcount;
	}
	dev_dbg(ice_pf_to_dev(vsi->back), "vsi->num_txq = %d\n",  vsi->num_txq);
	dev_dbg(ice_pf_to_dev(vsi->back), "vsi->num_rxq = %d\n",  vsi->num_rxq);
	dev_dbg(ice_pf_to_dev(vsi->back), "%s: all_numtc %u, all_enatc: 0x%04x, tc_cfg.numtc %u\n",
		__func__, vsi->all_numtc, vsi->all_enatc, vsi->tc_cfg.numtc);

	return 0;
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

/**
 * ice_vsi_cfg_tc - Configure VSI Tx Sched for given TC map
 * @vsi: VSI to be configured
 * @ena_tc: TC bitmap
 *
 * VSI queues expected to be quiesced before calling this function
 */
int ice_vsi_cfg_tc(struct ice_vsi *vsi, u8 ena_tc)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	struct ice_pf *pf = vsi->back;
	struct ice_vsi_ctx *ctx;
	enum ice_status status;
	struct device *dev;
	int i, ret = 0;
	u8 num_tc = 0;

	dev = ice_pf_to_dev(pf);
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (vsi->tc_cfg.ena_tc == ena_tc &&
	    vsi->mqprio_qopt.mode != TC_MQPRIO_MODE_CHANNEL)
		return ret;
#else
	if (vsi->tc_cfg.ena_tc == ena_tc)
		return 0;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	ice_for_each_traffic_class(i) {
		/* build bitmap of enabled TCs */
		if (ena_tc & BIT(i))
			num_tc++;
		/* populate max_txqs per TC */
		max_txqs[i] = vsi->alloc_txq;
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
		/* Update max_txqs if it is CHNL VSI, because alloc_t[r]xq are
		 * zero for CHNL VSI, hence use num_txq instead as max_txqs
		 */
		if (vsi->type == ICE_VSI_CHNL &&
		    test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
			max_txqs[i] = vsi->num_txq;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	}

	vsi->tc_cfg.ena_tc = ena_tc;
	vsi->tc_cfg.numtc = num_tc;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->vf_num = 0;
	ctx->info = vsi->info;

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (vsi->type == ICE_VSI_PF &&
	    test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		ret = ice_vsi_setup_q_map_mqprio(vsi, ctx, ena_tc);
	else
		ret = ice_vsi_setup_q_map(vsi, ctx);
#else
	ret = ice_vsi_setup_q_map(vsi, ctx);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	if (ret)
		goto out;

	/* must to indicate which section of VSI context are being modified */
	ctx->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_RXQ_MAP_VALID);
	status = ice_update_vsi(&pf->hw, vsi->idx, ctx, NULL);
	if (status) {
		dev_info(dev, "Failed VSI Update\n");
		ret = -EIO;
		goto out;
	}

#ifdef NETIF_F_HW_TC
	if (vsi->type == ICE_VSI_PF &&
	    test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		status  = ice_cfg_vsi_lan(vsi->port_info, vsi->idx, 1,
					  max_txqs);
	else
#endif /* NETIF_F_HW_TC */
		status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx,
					 vsi->tc_cfg.ena_tc, max_txqs);

	if (status) {
		dev_err(dev, "VSI %d failed TC config, error %s\n",
			vsi->vsi_num, ice_stat_str(status));
		ret = -EIO;
		goto out;
	}
	ice_vsi_update_q_map(vsi, ctx);
	vsi->info.valid_sections = 0;

	ice_vsi_cfg_netdev_tc(vsi, ena_tc);
out:
	kfree(ctx);
	return ret;
}

/**
 * ice_update_ring_stats - Update ring statistics
 * @ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void ice_update_ring_stats(struct ice_ring *ring, u64 pkts, u64 bytes)
{
	ring->stats.bytes += bytes;
	ring->stats.pkts += pkts;
}

#ifdef ADQ_PERF_COUNTERS
/**
 * ice_update_adq_stats - Update channel's counters for busy poll and NAPI
 * @ring: ring to update
 * @pkts: number of processed packets
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void ice_update_adq_stats(struct ice_ring *ring, u64 pkts)
{
	/* separate accounting of packets (eithet from busy_poll or
	 * napi_poll depending upon state of vector specific
	 * flag 'in_bp', 'prev_in_bp'
	 */
	if (ring->q_vector->state_flags & ICE_CHNL_IN_BP) {
		ring->ch_q_stats.poll.bp_packets += pkts;
	} else {
		if (ring->q_vector->state_flags & ICE_CHNL_PREV_IN_BP)
			ring->ch_q_stats.poll.bp_packets += pkts;
		else
			ring->ch_q_stats.poll.np_packets += pkts;
	}
}
#endif /* ADQ_PERF_COUNTERS */

/**
 * ice_update_tx_ring_stats - Update Tx ring specific counters
 * @tx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void ice_update_tx_ring_stats(struct ice_ring *tx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&tx_ring->syncp);
	ice_update_ring_stats(tx_ring, pkts, bytes);
#ifdef ADQ_PERF_COUNTERS
	ice_update_adq_stats(tx_ring, pkts);
#endif /* ADQ_PERF_COUNTERS */
	u64_stats_update_end(&tx_ring->syncp);
}

/**
 * ice_update_rx_ring_stats - Update Rx ring specific counters
 * @rx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void ice_update_rx_ring_stats(struct ice_ring *rx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&rx_ring->syncp);
	ice_update_ring_stats(rx_ring, pkts, bytes);
#ifdef ADQ_PERF_COUNTERS
	ice_update_adq_stats(rx_ring, pkts);
#endif /* ADQ_PERF_COUNTERS */

	/* if vector is transitioning from BP->INT (due to busy_poll_stop()) and
	 * we find no packets, in that case: to avoid entering into INTR mode
	 * (which happens from napi_poll - enabling interrupt if
	 * unlikely_comeback_to_bp getting set), make "prev_data_pkt_recv" to be
	 * non-zero, so that interrupts won't be enabled. This is to address the
	 * issue where num_force_wb on some queues is 2 to 3 times higher than
	 * other queues and those queues also sees lot of interrupts
	 */
	if (ice_ring_ch_enabled(rx_ring) &&
	    ice_vector_busypoll_intr(rx_ring->q_vector)) {
		if (!pkts)
			rx_ring->q_vector->state_flags |=
					ICE_CHNL_PREV_DATA_PKT_RECV;
#ifdef ADQ_PERF_COUNTERS
	} else if (ice_ring_ch_enabled(rx_ring)) {
		struct ice_q_vector *q_vector = rx_ring->q_vector;

		if (pkts &&
		    !(q_vector->state_flags & ICE_CHNL_PREV_DATA_PKT_RECV))
			rx_ring->ch_q_stats.rx.num_only_ctrl_pkts++;
		if (q_vector->state_flags & ICE_CHNL_IN_BP &&
		    !(q_vector->state_flags & ICE_CHNL_PREV_DATA_PKT_RECV))
			rx_ring->ch_q_stats.rx.num_no_data_pkt_bp++;
	}
#else
	}
#endif /* ADQ_PERF_COUNTERS */

	u64_stats_update_end(&rx_ring->syncp);
}

/**
 * ice_status_to_errno - convert from enum ice_status to Linux errno
 * @err: ice_status value to convert
 */
int ice_status_to_errno(enum ice_status err)
{
	switch (err) {
	case ICE_SUCCESS:
		return 0;
	case ICE_ERR_DOES_NOT_EXIST:
		return -ENOENT;
	case ICE_ERR_OUT_OF_RANGE:
		return -ENOTTY;
	case ICE_ERR_PARAM:
		return -EINVAL;
	case ICE_ERR_NO_MEMORY:
		return -ENOMEM;
	case ICE_ERR_MAX_LIMIT:
		return -EAGAIN;
	default:
		return -EINVAL;
	}
}

/**
 * ice_is_dflt_vsi_in_use - check if the default forwarding VSI is being used
 * @pi: port info of the switch with default VSI
 *
 * Return true if the there is a single VSI in default forwarding VSI list
 */
bool ice_is_dflt_vsi_in_use(struct ice_port_info *pi)
{
	bool exists = false;

	ice_check_if_dflt_vsi(pi, 0, &exists);
	return exists;
}

/**
 * ice_is_vsi_dflt_vsi - check if the VSI passed in is the default VSI
 * @vsi: VSI to compare against default forwarding VSI
 *
 * If this VSI passed in is the default forwarding VSI then return true, else
 * return false
 */
bool ice_is_vsi_dflt_vsi(struct ice_vsi *vsi)
{
	return ice_check_if_dflt_vsi(vsi->port_info, vsi->idx, NULL);
}

/**
 * ice_set_dflt_vsi - set the default forwarding VSI
 * @vsi: VSI getting set as the default forwarding VSI on the switch
 *
 * If the VSI passed in is already the default VSI and it's enabled just return
 * success.
 *
 * If there is already a default VSI on the switch and it's enabled then return
 * -EEXIST since there can only be one default VSI per switch.
 *
 *  Otherwise try to set the VSI passed in as the switch's default VSI and
 *  return the result.
 */
int ice_set_dflt_vsi(struct ice_vsi *vsi)
{
	enum ice_status status;
	struct device *dev;

	if (!vsi)
		return -EINVAL;

	dev = ice_pf_to_dev(vsi->back);

	/* the VSI passed in is already the default VSI */
	if (ice_is_vsi_dflt_vsi(vsi)) {
		dev_dbg(dev, "VSI %d passed in is already the default forwarding VSI, nothing to do\n",
			vsi->vsi_num);
		return 0;
	}

	status = ice_cfg_dflt_vsi(vsi->port_info, vsi->idx, true, ICE_FLTR_RX);
	if (status) {
		dev_err(dev, "Failed to set VSI %d as the default forwarding VSI, error %s\n",
			vsi->vsi_num, ice_stat_str(status));
		return -EIO;
	}

	return 0;
}

/**
 * ice_clear_dflt_vsi - clear the default forwarding VSI
 * @vsi: VSI to remove from filter list
 *
 * If the switch has no default VSI or it's not enabled then return error.
 *
 * Otherwise try to clear the default VSI and return the result.
 */
int ice_clear_dflt_vsi(struct ice_vsi *vsi)
{
	enum ice_status status;
	struct device *dev;

	if (!vsi)
		return -EINVAL;

	dev = ice_pf_to_dev(vsi->back);


	/* there is no default VSI configured */
	if (!ice_is_dflt_vsi_in_use(vsi->port_info))
		return -ENODEV;

	status = ice_cfg_dflt_vsi(vsi->port_info, vsi->idx, false,
				  ICE_FLTR_RX);
	if (status) {
		dev_err(dev, "Failed to clear the default forwarding VSI %d, error %s\n",
			vsi->vsi_num, ice_stat_str(status));
		return -EIO;
	}

	return 0;
}

/**
 * ice_get_link_speed_mbps - get link speed in Mbps
 * @vsi: the VSI whose link speed is being queried
 *
 * Return current VSI link speed and 0 if the speed is unknown.
 */
int ice_get_link_speed_mbps(struct ice_vsi *vsi)
{
	switch (vsi->port_info->phy.link_info.link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
		return SPEED_100000;
	case ICE_AQ_LINK_SPEED_50GB:
		return SPEED_50000;
	case ICE_AQ_LINK_SPEED_40GB:
		return SPEED_40000;
	case ICE_AQ_LINK_SPEED_25GB:
		return SPEED_25000;
	case ICE_AQ_LINK_SPEED_20GB:
		return SPEED_20000;
	case ICE_AQ_LINK_SPEED_10GB:
		return SPEED_10000;
	case ICE_AQ_LINK_SPEED_5GB:
		return SPEED_5000;
	case ICE_AQ_LINK_SPEED_2500MB:
		return SPEED_2500;
	case ICE_AQ_LINK_SPEED_1000MB:
		return SPEED_1000;
	case ICE_AQ_LINK_SPEED_100MB:
		return SPEED_100;
	case ICE_AQ_LINK_SPEED_10MB:
		return SPEED_10;
	case ICE_AQ_LINK_SPEED_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * ice_get_link_speed_kbps - get link speed in Kbps
 * @vsi: the VSI whose link speed is being queried
 *
 * Return current VSI link speed and 0 if the speed is unknown.
 */
int ice_get_link_speed_kbps(struct ice_vsi *vsi)
{
	int speed_mbps;

	speed_mbps = ice_get_link_speed_mbps(vsi);

	return speed_mbps * 1000;
}

/**
 * ice_set_min_bw_limit - setup minimum BW limit for Tx based on min_tx_rate
 * @vsi: VSI to be configured
 * @min_tx_rate: min Tx rate in Kbps to be configured as BW limit
 *
 * If the min_tx_rate is specified as 0 that means to clear the minimum BW limit
 * profile, otherwise a non-zero value will force a minimum BW limit for the VSI
 * on TC 0.
 */
int ice_set_min_bw_limit(struct ice_vsi *vsi, u64 min_tx_rate)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;
	int speed;

	dev = ice_pf_to_dev(pf);
	if (!vsi->port_info) {
		dev_dbg(dev, "VSI %d, type %u specified doesn't have valid port_info\n",
			vsi->idx, vsi->type);
		return -EINVAL;
	}

	speed = ice_get_link_speed_kbps(vsi);
	if (min_tx_rate > (u64)speed) {
		dev_err(dev, "invalid min Tx rate %llu Kbps specified for %s %d is greater than current link speed %u Kbps\n",
			min_tx_rate, ice_vsi_type_str(vsi->type), vsi->idx,
			speed);
		return -EINVAL;
	}

	/* Configure min BW for VSI limit */
	if (min_tx_rate) {
		status = ice_cfg_vsi_bw_lmt_per_tc(vsi->port_info, vsi->idx, 0,
						   ICE_MIN_BW, min_tx_rate);
		if (status) {
			dev_err(dev, "failed to set min Tx rate(%llu Kbps) for %s %d\n",
				min_tx_rate, ice_vsi_type_str(vsi->type),
				vsi->idx);
			return -EIO;
		}

		dev_dbg(dev, "set min Tx rate(%llu Kbps) for %s\n",
			min_tx_rate, ice_vsi_type_str(vsi->type));
	} else {
		status = ice_cfg_vsi_bw_dflt_lmt_per_tc(vsi->port_info,
							vsi->idx, 0,
							ICE_MIN_BW);
		if (status) {
			dev_err(dev, "failed to clear min Tx rate configuration for %s %d\n",
				ice_vsi_type_str(vsi->type), vsi->idx);
			return -EIO;
		}

		dev_dbg(dev, "cleared min Tx rate configuration for %s %d\n",
			ice_vsi_type_str(vsi->type), vsi->idx);
	}

	return 0;
}

/**
 * ice_set_max_bw_limit - setup maximum BW limit for Tx based on max_tx_rate
 * @vsi: VSI to be configured
 * @max_tx_rate: max Tx rate in Kbps to be configured as BW limit
 *
 * If the max_tx_rate is specified as 0 that means to clear the maximum BW limit
 * profile, otherwise a non-zero value will force a maximum BW limit for the VSI
 * on TC 0.
 */
int ice_set_max_bw_limit(struct ice_vsi *vsi, u64 max_tx_rate)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;
	int speed;

	dev = ice_pf_to_dev(pf);
	if (!vsi->port_info) {
		dev_dbg(dev, "VSI %d, type %u specified doesn't have valid port_info\n",
			vsi->idx, vsi->type);
		return -EINVAL;
	}

	speed = ice_get_link_speed_kbps(vsi);
	if (max_tx_rate > (u64)speed) {
		dev_err(dev, "invalid max Tx rate %llu Kbps specified for %s %d is greater than current link speed %u Kbps\n",
			max_tx_rate, ice_vsi_type_str(vsi->type), vsi->idx,
			speed);
		return -EINVAL;
	}

	/* Configure max BW for VSI limit */
	if (max_tx_rate) {
		status = ice_cfg_vsi_bw_lmt_per_tc(vsi->port_info, vsi->idx, 0,
						   ICE_MAX_BW, max_tx_rate);
		if (status) {
			dev_err(dev, "failed setting max Tx rate(%llu Kbps) for %s %d\n",
				max_tx_rate, ice_vsi_type_str(vsi->type),
				vsi->idx);
			return -EIO;
		}

		dev_dbg(dev, "set max Tx rate(%llu Kbps) for %s %d\n",
			max_tx_rate, ice_vsi_type_str(vsi->type), vsi->idx);
	} else {
		status = ice_cfg_vsi_bw_dflt_lmt_per_tc(vsi->port_info,
							vsi->idx, 0,
							ICE_MAX_BW);
		if (status) {
			dev_err(dev, "failed clearing max Tx rate configuration for %s %d\n",
				ice_vsi_type_str(vsi->type), vsi->idx);
			return -EIO;
		}

		dev_dbg(dev, "cleared max Tx rate configuration for %s %d\n",
			ice_vsi_type_str(vsi->type), vsi->idx);
	}

	return 0;
}

/**
 * ice_set_link - turn on/off physical link
 * @vsi: VSI to modify physical link on
 * @ena: turn on/off physical link
 */
int ice_set_link(struct ice_vsi *vsi, bool ena)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct ice_port_info *pi = vsi->port_info;
	struct ice_hw *hw = pi->hw;
	enum ice_status status;

	if (vsi->type != ICE_VSI_PF)
		return -EINVAL;

	status = ice_aq_set_link_restart_an(pi, ena, NULL);

	/* if link is owned by manageability, FW will return ICE_AQ_RC_EMODE.
	 * this is not a fatal error, so print a warning message and return
	 * a success code. Return an error if FW returns an error code other
	 * than ICE_AQ_RC_EMODE
	 */
	if (status == ICE_ERR_AQ_ERROR) {
		if (hw->adminq.sq_last_status == ICE_AQ_RC_EMODE)
			dev_warn(dev, "can't set link to %s, err %s aq_err %s. not fatal, continuing\n",
				 (ena ? "ON" : "OFF"), ice_stat_str(status),
				 ice_aq_str(hw->adminq.sq_last_status));
	} else if (status) {
		dev_err(dev, "can't set link to %s, err %s aq_err %s\n",
			(ena ? "ON" : "OFF"), ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * ice_vsi_update_security - update security block in VSI
 * @vsi: pointer to VSI structure
 * @fill: function pointer to fill ctx
 */
int ice_vsi_update_security(struct ice_vsi *vsi,
			    void (*fill)(struct ice_vsi_ctx *))
{
	struct ice_vsi_ctx ctx = { 0 };

	ctx.info = vsi->info;
	ctx.info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
	fill(&ctx);

	if (ice_update_vsi(&vsi->back->hw, vsi->idx, &ctx, NULL))
		return -ENODEV;

	vsi->info = ctx.info;
	return 0;
}

#ifdef HAVE_METADATA_PORT_INFO
/**
 * ice_vsi_ctx_set_antispoof - set antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void ice_vsi_ctx_set_antispoof(struct ice_vsi_ctx *ctx)
{
	ctx->info.sec_flags |= ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
		(ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
		 ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S);
}

/**
 * ice_vsi_ctx_clear_antispoof - clear antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void ice_vsi_ctx_clear_antispoof(struct ice_vsi_ctx *ctx)
{
	ctx->info.sec_flags &= ~ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF &
		~(ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
		  ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S);
}
#endif /* HAVE_METADATA_PORT_INFO */

/**
 * ice_vsi_ctx_set_allow_override - allow destination override on VSI
 * @ctx: pointer to VSI ctx structure
 */
void ice_vsi_ctx_set_allow_override(struct ice_vsi_ctx *ctx)
{
	ctx->info.sec_flags |= ICE_AQ_VSI_SEC_FLAG_ALLOW_DEST_OVRD;
}

/**
 * ice_vsi_ctx_clear_allow_override - turn off destination override on VSI
 * @ctx: pointer to VSI ctx structure
 */
void ice_vsi_ctx_clear_allow_override(struct ice_vsi_ctx *ctx)
{
	ctx->info.sec_flags &= ~ICE_AQ_VSI_SEC_FLAG_ALLOW_DEST_OVRD;
}

/**
 * ice_check_mtu_valid - check if specified MTU can be set for a netdev
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 if MTU is valid, negative otherwise
 */
int ice_check_mtu_valid(struct net_device *netdev, int new_mtu)
{
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	if (new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->extended->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	}
#else /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
	if (new_mtu < (int)netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	} else if (new_mtu > (int)netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	}
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
#else /* HAVE_NETDEVICE_MIN_MAX_MTU */
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		return -EINVAL;
	} else if (new_mtu > ICE_MAX_MTU) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   ICE_MAX_MTU);
		return -EINVAL;
	}
#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */

	return 0;
}

/**
 * ice_vsi_add_vlan_zero - add VLAN 0 filter(s) for this VSI
 * @vsi: VSI used to add VLAN filters
 *
 * In Single VLAN Mode (SVM), single VLAN filters via ICE_SW_LKUP_VLAN are based
 * on the inner VLAN ID, so the VLAN TPID (i.e. 0x8100 or 0x888a8) doesn't
 * matter. In Double VLAN Mode (DVM), outer/single VLAN filters via
 * ICE_SW_LKUP_VLAN are based on the outer/single VLAN ID + VLAN TPID.
 *
 * For both modes add a VLAN 0 + no VLAN TPID filter to handle untagged traffic
 * when VLAN pruning is enabled. Also, this handles VLAN 0 priority tagged
 * traffic in SVM, since the VLAN TPID isn't part of filtering.
 *
 * If DVM is enabled then an explicit VLAN 0 + VLAN TPID filter needs to be
 * added to allow VLAN 0 priority tagged traffic in DVM, since the VLAN TPID is
 * part of filtering.
 */
int ice_vsi_add_vlan_zero(struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	struct ice_vlan vlan;
	int err;

	vlan = ICE_VLAN(0, 0, 0, ICE_FWD_TO_VSI);
	err = vlan_ops->add_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	/* in SVM both VLAN 0 filters are identical */
	if (!ice_is_dvm_ena(&vsi->back->hw))
		return 0;

	vlan = ICE_VLAN(ETH_P_8021Q, 0, 0, ICE_FWD_TO_VSI);
	err = vlan_ops->add_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	return 0;
}

/**
 * ice_vsi_del_vlan_zero - delete VLAN 0 filter(s) for this VSI
 * @vsi: VSI used to add VLAN filters
 *
 * Delete the VLAN 0 filters in the same manner that they were added in
 * ice_vsi_add_vlan_zero.
 */
int ice_vsi_del_vlan_zero(struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	struct ice_vlan vlan;
	int err;

	vlan = ICE_VLAN(0, 0, 0, ICE_FWD_TO_VSI);
	err = vlan_ops->del_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	/* in SVM both VLAN 0 filters are identical */
	if (!ice_is_dvm_ena(&vsi->back->hw))
		return 0;

	vlan = ICE_VLAN(ETH_P_8021Q, 0, 0, ICE_FWD_TO_VSI);
	err = vlan_ops->del_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	/* when deleting the last VLAN filter, make sure to disable the VLAN
	 * promisc mode so the filter isn't left by accident
	 */
	err = ice_clear_vsi_promisc(&vsi->back->hw, vsi->idx,
				    ICE_MCAST_VLAN_PROMISC_BITS, 0);
	if (err)
		return err;

	return 0;
}

/**
 * ice_vsi_num_zero_vlans - get number of VLAN 0 filters based on VLAN mode
 * @vsi: VSI used to get the VLAN mode
 *
 * If DVM is enabled then 2 VLAN 0 filters are added, else if SVM is enabled
 * then 1 VLAN 0 filter is added. See ice_vsi_add_vlan_zero for more details.
 */
static u16 ice_vsi_num_zero_vlans(struct ice_vsi *vsi)
{
#define ICE_DVM_NUM_ZERO_VLAN_FLTRS	2
#define ICE_SVM_NUM_ZERO_VLAN_FLTRS	1
	/* no VLAN 0 filter is created when a port VLAN is active */
	if (vsi->type == ICE_VSI_VF) {
		if (WARN_ON(!vsi->vf))
			return 0;

		if (ice_vf_is_port_vlan_ena(vsi->vf))
			return 0;
	}

	if (ice_is_dvm_ena(&vsi->back->hw))
		return ICE_DVM_NUM_ZERO_VLAN_FLTRS;
	else
		return ICE_SVM_NUM_ZERO_VLAN_FLTRS;
}

/**
 * ice_vsi_has_non_zero_vlans - check if VSI has any non-zero VLANs
 * @vsi: VSI used to determine if any non-zero VLANs have been added
 */
bool ice_vsi_has_non_zero_vlans(struct ice_vsi *vsi)
{
	return (vsi->num_vlan > ice_vsi_num_zero_vlans(vsi));
}

/**
 * ice_vsi_num_non_zero_vlans - get the number of non-zero VLANs for this VSI
 * @vsi: VSI used to get the number of non-zero VLANs added
 */
u16 ice_vsi_num_non_zero_vlans(struct ice_vsi *vsi)
{
	return (vsi->num_vlan - ice_vsi_num_zero_vlans(vsi));
}

/**
 * ice_is_feature_supported
 * @pf: pointer to the struct ice_pf instance
 * @f: feature enum to be checked
 *
 * returns true if feature is supported, false otherwise
 */
bool ice_is_feature_supported(struct ice_pf *pf, enum ice_feature f)
{
	if (f < 0 || f >= ICE_F_MAX)
		return false;

	return test_bit(f, pf->features);
}

/**
 * ice_set_feature_support
 * @pf: pointer to the struct ice_pf instance
 * @f: feature enum to set
 */
static void ice_set_feature_support(struct ice_pf *pf, enum ice_feature f)
{
	if (f < 0 || f >= ICE_F_MAX)
		return;

	set_bit(f, pf->features);
}

/**
 * ice_clear_feature_support
 * @pf: pointer to the struct ice_pf instance
 * @f: feature enum to clear
 */
void ice_clear_feature_support(struct ice_pf *pf, enum ice_feature f)
{
	if (f < 0 || f >= ICE_F_MAX)
		return;

	clear_bit(f, pf->features);
}

/**
 * ice_init_feature_support
 * @pf: pointer to the struct ice_pf instance
 *
 * called during init to setup supported feature
 */
void ice_init_feature_support(struct ice_pf *pf)
{
	switch (pf->hw.device_id) {
	case ICE_DEV_ID_E810C_BACKPLANE:
	case ICE_DEV_ID_E810C_QSFP:
	case ICE_DEV_ID_E810C_SFP:
	case ICE_DEV_ID_E810_XXV_BACKPLANE:
	case ICE_DEV_ID_E810_XXV_QSFP:
	case ICE_DEV_ID_E810_XXV_SFP:
		ice_set_feature_support(pf, ICE_F_DSCP);
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		if (ice_is_phy_rclk_present_e810t(&pf->hw))
			ice_set_feature_support(pf, ICE_F_PHY_RCLK);
		/* If we don't own the timer - don't enable other caps */
		if (!pf->hw.func_caps.ts_func_info.src_tmr_owned)
			break;

		ice_set_feature_support(pf, ICE_F_PTP_EXTTS);
		if (ice_is_clock_mux_present_e810t(&pf->hw))
			ice_set_feature_support(pf, ICE_F_SMA_CTRL);
		if (ice_is_cgu_present(&pf->hw))
			ice_set_feature_support(pf, ICE_F_CGU);
		if (ice_is_gps_present_e810t(&pf->hw) &&
		    ice_gnss_is_gps_present(&pf->hw))
			ice_set_feature_support(pf, ICE_F_GNSS);
#endif /* CONFIG_PTP_1588_CLOCK */
		break;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	case ICE_DEV_ID_E823L_BACKPLANE:
	case ICE_DEV_ID_E823L_SFP:
	case ICE_DEV_ID_E823L_10G_BASE_T:
	case ICE_DEV_ID_E823L_1GBE:
	case ICE_DEV_ID_E823L_QSFP:
	case ICE_DEV_ID_E823C_BACKPLANE:
	case ICE_DEV_ID_E823C_SFP:
	case ICE_DEV_ID_E823C_10G_BASE_T:
	case ICE_DEV_ID_E823C_SGMII:
	case ICE_DEV_ID_E823C_QSFP:
		ice_set_feature_support(pf, ICE_F_PTP_EXTTS);
		break;
#endif /* CONFIG_PTP_1588_CLOCK */
	default:
		break;
	}
}
