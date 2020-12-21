// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_dcb_lib.h"

#ifdef HAVE_PF_RING
extern int RSS[ICE_MAX_NIC];
extern int enable_debug;
#endif

/**
 * ice_vsi_type_str - maps VSI type enum to string equivalents
 * @type: VSI type enum
 */
const char *ice_vsi_type_str(enum ice_vsi_type type)
{
	switch (type) {
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
	default:
		return "unknown";
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
	int i, ret = 0;

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

#ifdef HAVE_XDP_SUPPORT
	/* XDP will have vsi->alloc_txq Tx queues as well, so double the size */
	vsi->txq_map = devm_kcalloc(dev, (2 * vsi->alloc_txq),
				    sizeof(*vsi->txq_map), GFP_KERNEL);
#else
	vsi->txq_map = devm_kcalloc(dev, vsi->alloc_txq,
				    sizeof(*vsi->txq_map), GFP_KERNEL);
#endif /* HAVE_XDP_SUPPORT */

	if (!vsi->txq_map)
		goto err_txq_map;

	vsi->rxq_map = devm_kcalloc(dev, vsi->alloc_rxq,
				    sizeof(*vsi->rxq_map), GFP_KERNEL);
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

	return 0;

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
	case ICE_VSI_VMDQ2:
	case ICE_VSI_CTRL:
	case ICE_VSI_LB:
		vsi->num_rx_desc = ICE_DFLT_NUM_RX_DESC;
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
 * @vf_id: ID of the VF being configured
 *
 * Return 0 on success and a negative value on error
 */
static void ice_vsi_set_num_qs(struct ice_vsi *vsi, u16 vf_id)
{
	struct ice_pf *pf = vsi->back;
	struct ice_vf *vf = NULL;

	if (vsi->type == ICE_VSI_VF)
		vsi->vf_id = vf_id;

	switch (vsi->type) {
	case ICE_VSI_PF:
		vsi->alloc_txq = min_t(int, ice_get_avail_txq_count(pf),
				       num_online_cpus());
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
			vsi->alloc_rxq = min_t(int, ice_get_avail_rxq_count(pf),
					       num_online_cpus());
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

		vsi->num_q_vectors = max_t(int, vsi->alloc_rxq, vsi->alloc_txq);
		break;
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
		vsi->alloc_txq = ICE_DFLT_TXQ_VMDQ_VSI;
		vsi->alloc_rxq = ICE_DFLT_RXQ_VMDQ_VSI;
		vsi->num_q_vectors = ICE_DFLT_VEC_VMDQ_VSI;
		break;
	case ICE_VSI_VF:
		vf = &pf->vf[vsi->vf_id];
		/* pf->num_vf_msix includes (VF miscellaneous vector +
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
			vsi->alloc_txq = vf->num_vf_qs;
			vsi->alloc_rxq = vf->num_vf_qs;
			vsi->num_q_vectors = pf->num_vf_msix - ICE_NONQ_VECS_VF;
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
		dev_warn(ice_pf_to_dev(pf), "Unknown VSI type %d\n", vsi->type);
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
		ctxt->vf_num = vsi->vf_id;
	ctxt->vsi_num = vsi->vsi_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	status = ice_free_vsi(&pf->hw, vsi->idx, ctxt, false, NULL);
	if (status)
		dev_err(ice_pf_to_dev(pf), "Failed to delete VSI %i in FW - error: %d\n",
			vsi->vsi_num, status);

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

	if (vsi->type != ICE_VSI_CTRL) {
		pf->vsi[vsi->idx] = NULL;
		if (vsi->idx < pf->next_vsi)
			pf->next_vsi = vsi->idx;
	} else {
		pf->vsi[vsi->idx] = NULL;
	}

	ice_vsi_free_arrays(vsi);
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

	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * ice_vsi_alloc - Allocates the next available struct VSI in the PF
 * @pf: board private structure
 * @type: type of VSI
 * @ch: ptr to channel
 * @tc: traffic class number for VF ADQ
 * @vf_id: ID of the VF being configured
 *
 * returns a pointer to a VSI on success, NULL on failure.
 */
static struct ice_vsi *
ice_vsi_alloc(struct ice_pf *pf, enum ice_vsi_type type, struct ice_channel *ch,
	      u16 vf_id, u8 tc)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *vsi = NULL;

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

	vsi->type = type;
	vsi->back = pf;
	if (type == ICE_VSI_VF)
		vsi->vf_adq_tc = tc;
	set_bit(__ICE_DOWN, vsi->state);

	if (type == ICE_VSI_VF)
		ice_vsi_set_num_qs(vsi, vf_id);
	else if (type != ICE_VSI_CHNL)
		ice_vsi_set_num_qs(vsi, ICE_INVAL_VFID);

	switch (vsi->type) {
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_PF:
		if (ice_vsi_alloc_arrays(vsi))
			goto err_rings;

		/* Setup default MSIX irq handler for VSI */
		vsi->irq_handler = ice_msix_clean_rings;
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

	if (vsi->type == ICE_VSI_CTRL) {
		/* Use the last VSI slot as the index for the control VSI */
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

	/* flow director filters are only allocated/assigned to the PF VSI,
	 * CHNL VSI which passes traffic. The CTRL VSI is only used to
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

	if (!(vsi->type == ICE_VSI_PF || vsi->type == ICE_VSI_CHNL))
		return -EPERM;

	if (!test_bit(ICE_FLAG_FD_ENA, pf->flags))
		return -EPERM;

	/* PF main VSI gets only 64 FD resources from guaranteed pool
	 * when ADQ is configured. This is current policy, change as needed
	 */
#define ICE_PF_VSI_GFLTR	64

	/* determines FD filter resources per VSI from shared(best effort) and
	 * dedicated pool
	 */
	if (vsi->type == ICE_VSI_PF) {
		vsi->num_gfltr = g_val;
#ifdef NETIF_F_HW_TC
		/* if MQPRIO ic configured, main VSI doesn't get all
		 * FD resources from guaranteed pool. Current policy is,
		 * PF VSI gets 64 FD resources
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
	int i;

	mutex_lock(&pf->avail_q_mutex);

	for (i = 0; i < vsi->alloc_txq; i++) {
		clear_bit(vsi->txq_map[i], pf->avail_txqs);
		vsi->txq_map[i] = ICE_INVAL_Q_INDEX;
	}

	for (i = 0; i < vsi->alloc_rxq; i++) {
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
 * ice_is_peer_ena
 * @pf: pointer to the PF struct
 *
 * returns true if peer devices/drivers are supported, false otherwise
 */
bool ice_is_peer_ena(struct ice_pf *pf)
{
	return test_bit(ICE_FLAG_PEER_ENA, pf->flags);
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
		dev_dbg(ice_pf_to_dev(pf), "ice_rem_vsi_rss_cfg failed for vsi = %d, error = %d\n",
			vsi->vsi_num, status);
}

/**
 * ice_pf_clean_rss_flow_fld - Delete RSS configuration for all VSIs of PF
 * @pf: the PF
 */
void ice_pf_clean_rss_flow_fld(struct ice_pf *pf)
{
	int v;

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v])
			ice_vsi_clean_rss_flow_fld(pf->vsi[v]);
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
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
		vsi->rss_size = 1;
		return;
	}

	cap = &pf->hw.func_caps.common_cap;
	switch (vsi->type) {
	case ICE_VSI_CHNL:
	case ICE_VSI_PF:
		/* PF VSI will inherit RSS instance of PF */
		vsi->rss_table_size = cap->rss_table_size;
		if (vsi->type == ICE_VSI_CHNL)
			vsi->rss_size = min_t(int, vsi->num_rxq,
					      BIT(cap->rss_table_entry_width));
		else
#ifdef HAVE_PF_RING
		{
#endif
			vsi->rss_size = min_t(int, num_online_cpus(),
					      BIT(cap->rss_table_entry_width));
#ifdef HAVE_PF_RING
			if (RSS[pf->instance] != 0)
				vsi->rss_size = min_t(int, vsi->rss_size, RSS[pf->instance]);
		}
#endif

		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF;
		break;
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
		vsi->rss_table_size = ICE_VSIQF_HLUT_ARRAY_SIZE;
		vsi->rss_size = min_t(int, num_online_cpus(),
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
		break;
	case ICE_VSI_CTRL:
		dev_dbg(dev, "Unsupported VSI type %d\n", vsi->type);
		break;
	case ICE_VSI_LB:
		break;
	default:
		dev_warn(dev, "Unknown VSI type %d\n", vsi->type);
		break;
	}
}

/**
 * ice_set_dflt_vsi_ctx - Set default VSI context before adding a VSI
 * @ctxt: the VSI context being set
 *
 * This initializes a default VSI context for all sections except the Queues.
 */
static void ice_set_dflt_vsi_ctx(struct ice_vsi_ctx *ctxt)
{
	u32 table = 0;

	memset(&ctxt->info, 0, sizeof(ctxt->info));
	/* VSI's should be allocated from shared pool */
	ctxt->alloc_from_pool = true;
	/* Src pruning enabled by default */
	ctxt->info.sw_flags = ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	/* Traffic from VSI can be sent to LAN */
	ctxt->info.sw_flags2 = ICE_AQ_VSI_SW_FLAG_LAN_ENA;
	/* By default bits 3 and 4 in vlan_flags are 0's which results in legacy
	 * behavior (show VLAN, DEI, and UP) in descriptor. Also, allow all
	 * packets untagged/tagged.
	 */
	ctxt->info.vlan_flags = ((ICE_AQ_VSI_VLAN_MODE_ALL &
				  ICE_AQ_VSI_VLAN_MODE_M) >>
				 ICE_AQ_VSI_VLAN_MODE_S);
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
static void ice_vsi_setup_q_map(struct ice_vsi *vsi, struct ice_vsi_ctx *ctxt)
{
	u16 offset = 0, qmap = 0, tx_count = 0;
	u16 qcount_tx = vsi->alloc_txq;
	u16 qcount_rx = vsi->alloc_rxq;
	u16 tx_numq_tc, rx_numq_tc;
	u16 pow = 0, max_rss = 0;
	u8 netdev_tc = 0;
	int i;


	if (!vsi->tc_cfg.numtc) {
		/* at least TC0 should be enabled by default */
		vsi->tc_cfg.numtc = 1;
		vsi->tc_cfg.ena_tc = 1;
	}

	rx_numq_tc = qcount_rx / vsi->tc_cfg.numtc;
	if (!rx_numq_tc)
		rx_numq_tc = 1;
	tx_numq_tc = qcount_tx / vsi->tc_cfg.numtc;
	if (!tx_numq_tc)
		tx_numq_tc = 1;

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

	qcount_rx = rx_numq_tc;

	/* qcount will change if RSS is enabled. if numq_tc is 1 then RSS
	 * is not possible so use numq_tc (1) as qcount.
	 */
	if (test_bit(ICE_FLAG_RSS_ENA, vsi->back->flags) && rx_numq_tc != 1) {
		if (vsi->type == ICE_VSI_PF || vsi->type == ICE_VSI_VF) {
			if (vsi->type == ICE_VSI_PF)
				max_rss = ICE_MAX_LG_RSS_QS;
			else
				max_rss = ICE_MAX_SMALL_RSS_QS;
			qcount_rx = min_t(int, rx_numq_tc, max_rss);
			if (!vsi->req_rxq)
				qcount_rx = min_t(int, qcount_rx,
						  vsi->rss_size);
		}
	}

	/* find the (rounded up) power-of-2 of qcount */
	pow = order_base_2(qcount_rx);

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

		/* TC is enabled */
		vsi->tc_cfg.tc_info[i].qoffset = offset;
		vsi->tc_cfg.tc_info[i].qcount_rx = qcount_rx;
		vsi->tc_cfg.tc_info[i].qcount_tx = tx_numq_tc;
		vsi->tc_cfg.tc_info[i].netdev_tc = netdev_tc++;

		qmap = ((offset << ICE_AQ_VSI_TC_Q_OFFSET_S) &
			ICE_AQ_VSI_TC_Q_OFFSET_M) |
			((pow << ICE_AQ_VSI_TC_Q_NUM_S) &
			 ICE_AQ_VSI_TC_Q_NUM_M);
		offset += qcount_rx;
		tx_count += tx_numq_tc;
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
		vsi->num_rxq = qcount_rx;

	vsi->num_txq = tx_count;

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
	    vsi->type != ICE_VSI_CHNL)
		return;

	val = ICE_AQ_VSI_PROP_FLOW_DIR_VALID;
	ctxt->info.valid_sections |= cpu_to_le16(val);
	dflt_q = 0;
	dflt_q_group = 0;
	report_q = 0;
	dflt_q_prio = 0;

	/* enable flow director filtering/programming */
	val = (ICE_AQ_VSI_FD_ENABLE | ICE_AQ_VSI_FD_PROG_ENABLE);
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
}

/**
 * ice_set_rss_vsi_ctx - Set RSS VSI context before adding a VSI
 * @ctxt: the VSI context being set
 * @vsi: the VSI being configured
 */
static void ice_set_rss_vsi_ctx(struct ice_vsi_ctx *ctxt, struct ice_vsi *vsi)
{
	u8 lut_type, hash_type;
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
	case ICE_VSI_CTRL:
		dev_dbg(dev, "Unsupported VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		return;
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
		dev_dbg(dev, "Unsupported VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		return;
	case ICE_VSI_VF:
		/* VF VSI will gets a small RSS table which is a VSI LUT type */
		lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_VSI;
		hash_type = ICE_AQ_VSI_Q_OPT_RSS_TPLZ;
		break;
	case ICE_VSI_LB:
		dev_dbg(dev, "Unsupported VSI type %s\n",
			ice_vsi_type_str(vsi->type));
		return;
	default:
		dev_warn(dev, "Unknown VSI type %d\n", vsi->type);
		return;
	}

	ctxt->info.q_opt_rss = ((lut_type << ICE_AQ_VSI_Q_OPT_RSS_LUT_S) &
				ICE_AQ_VSI_Q_OPT_RSS_LUT_M) |
				((hash_type << ICE_AQ_VSI_Q_OPT_RSS_HASH_S) &
				 ICE_AQ_VSI_Q_OPT_RSS_HASH_M);
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

	ctxt->info = vsi->info;

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_LB:
	case ICE_VSI_PF:
		ctxt->flags = ICE_AQ_VSI_TYPE_PF;
		break;
	case ICE_VSI_CHNL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
		ctxt->flags = ICE_AQ_VSI_TYPE_VMDQ2;
		break;
	case ICE_VSI_VF:
		ctxt->flags = ICE_AQ_VSI_TYPE_VF;
		/* VF number here is the absolute VF number (0-255) */
		ctxt->vf_num = vsi->vf_id + hw->func_caps.vf_base_id;
		break;
	default:
		ret = -ENODEV;
		goto out;
	}

	ice_set_dflt_vsi_ctx(ctxt);
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
		ice_vsi_setup_q_map(vsi, ctxt);
		if (!init_vsi) /* means VSI being updated */
			/* must to indicate which section of VSI context are
			 * being modified
			 */
			ctxt->info.valid_sections |=
				cpu_to_le16(ICE_AQ_VSI_PROP_RXQ_MAP_VALID);
	}

	/* enable/disable MAC and VLAN anti-spoof when spoofchk is on/off
	 * respectively
	 */
	if (vsi->type == ICE_VSI_VF) {
		ctxt->info.valid_sections |=
			cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
		if (pf->vf[vsi->vf_id].spoofchk) {
			ctxt->info.sec_flags |=
				ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
				(ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
				 ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S);
		} else {
			ctxt->info.sec_flags &=
				~(ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
				  (ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
				   ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S));
		}
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
 * ice_vsi_setup_vector_base - Set up the base vector for the given VSI
 * @vsi: ptr to the VSI
 *
 * This should only be called after ice_vsi_alloc() which allocates the
 * corresponding SW VSI structure and initializes num_queue_pairs for the
 * newly allocated VSI.
 *
 * Returns 0 on success or negative on failure
 */
static int ice_vsi_setup_vector_base(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	u16 num_q_vectors;

	dev = ice_pf_to_dev(pf);
	/* SRIOV doesn't grab irq_tracker entries for each VSI */
	if (vsi->type == ICE_VSI_VF)
		return 0;
	if (vsi->type == ICE_VSI_CHNL)
		return 0;

	if (vsi->base_vector) {
		dev_dbg(dev, "VSI %d has non-zero base vector %d\n",
			vsi->vsi_num, vsi->base_vector);
		return -EEXIST;
	}

	num_q_vectors = vsi->num_q_vectors;
	/* reserve slots from OS requested IRQs */
	vsi->base_vector = ice_get_res(pf, pf->irq_tracker, num_q_vectors,
				       vsi->idx);
	if (vsi->base_vector < 0) {
		dev_err(dev, "Failed to get tracking for %d vectors for VSI %d, err=%d\n",
			num_q_vectors, vsi->vsi_num, vsi->base_vector);
		return -ENOENT;
	}
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

	if (vsi->tx_rings) {
		for (i = 0; i < vsi->alloc_txq; i++) {
			if (vsi->tx_rings[i]) {
				kfree_rcu(vsi->tx_rings[i], rcu);
				vsi->tx_rings[i] = NULL;
			}
		}
	}
	if (vsi->rx_rings) {
		for (i = 0; i < vsi->alloc_rxq; i++) {
			if (vsi->rx_rings[i]) {
				kfree_rcu(vsi->rx_rings[i], rcu);
				vsi->rx_rings[i] = NULL;
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
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int i;

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
		ring->ring_active = false;
		ring->vsi = vsi;
		ring->dev = dev;
		ring->count = vsi->num_tx_desc;
		vsi->tx_rings[i] = ring;
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
		ring->ring_active = false;
		ring->vsi = vsi;
		ring->netdev = vsi->netdev;
		ring->dev = dev;
		ring->count = vsi->num_rx_desc;
		vsi->rx_rings[i] = ring;
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
 * ice_vsi_set_dflt_rss_lut - set default RSS LUT with requested RSS size
 * @vsi: VSI to reconfigure RSS LUT on
 * @req_rss_size: requested range of queue numbers for hashing
 *
 * Set the VSI's RSS parameters, configure the RSS LUT based on these, and then
 * clear the previous vsi->rss_lut_user because it is assumed to be invalid at
 * this point.
 */
int ice_vsi_set_dflt_rss_lut(struct ice_vsi *vsi, int req_rss_size)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;
	struct ice_hw *hw;
	int err = 0;
	u8 *lut;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;

	if (!req_rss_size)
		return -EINVAL;

	lut = kzalloc(vsi->rss_table_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	/* set RSS LUT parameters */
	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
		vsi->rss_size = 1;
	} else {
		struct ice_hw_common_caps *caps = &hw->func_caps.common_cap;

		vsi->rss_size = min_t(int, req_rss_size,
				      BIT(caps->rss_table_entry_width));
	}

	/* create/set RSS LUT */
	ice_fill_rss_lut(lut, vsi->rss_table_size, vsi->rss_size);
	status = ice_aq_set_rss_lut(hw, vsi->idx, vsi->rss_lut_type, lut,
				    vsi->rss_table_size);
	if (status) {
		dev_err(dev, "Cannot set RSS lut, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.rq_last_status));
		err = -EIO;
	}

	/* get rid of invalid user configuration */
	if (vsi->rss_lut_user) {
		netdev_info(vsi->netdev, "Rx queue count changed, clearing user modified RSS LUT, re-run ethtool [-x|-X] to [check|set] settings if needed\n");
		devm_kfree(dev, vsi->rss_lut_user);
		vsi->rss_lut_user = NULL;
	}

	kfree(lut);
	return err;
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
int ice_vsi_manage_rss_lut(struct ice_vsi *vsi, bool ena)
{
	int err = 0;
	u8 *lut;

	lut = kzalloc(vsi->rss_table_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	if (ena) {
		if (vsi->rss_lut_user)
			memcpy(lut, vsi->rss_lut_user, vsi->rss_table_size);
		else
			ice_fill_rss_lut(lut, vsi->rss_table_size,
					 vsi->rss_size);
	}

	err = ice_set_rss(vsi, NULL, lut, vsi->rss_table_size);
	kfree(lut);
	return err;
}

/**
 * ice_vsi_cfg_rss_lut_key - Configure RSS params for a VSI
 * @vsi: VSI to be configured
 */
int ice_vsi_cfg_rss_lut_key(struct ice_vsi *vsi)
{
	struct ice_aqc_get_set_rss_keys *key;
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;
	int err = 0;
	u8 *lut;

	dev = ice_pf_to_dev(pf);
#ifdef NETIF_F_HW_TC
	if (vsi->type == ICE_VSI_PF && vsi->ch_rss_size &&
	    (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))) {
		vsi->rss_size = min_t(int, vsi->rss_size, vsi->ch_rss_size);
	} else {
		vsi->rss_size = min_t(int, vsi->rss_size, vsi->num_rxq);

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

	status = ice_aq_set_rss_lut(&pf->hw, vsi->idx, vsi->rss_lut_type, lut,
				    vsi->rss_table_size);

	if (status) {
		dev_err(dev, "set_rss_lut failed, error %d\n", status);
		err = -EIO;
		goto ice_vsi_cfg_rss_exit;
	}

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		err = -ENOMEM;
		goto ice_vsi_cfg_rss_exit;
	}

	if (vsi->rss_hkey_user)
		memcpy(key,
		       (struct ice_aqc_get_set_rss_keys *)vsi->rss_hkey_user,
		       ICE_GET_SET_RSS_KEY_EXTEND_KEY_SIZE);
	else
		netdev_rss_key_fill((void *)key,
				    ICE_GET_SET_RSS_KEY_EXTEND_KEY_SIZE);

	status = ice_aq_set_rss_key(&pf->hw, vsi->idx, key);

	if (status) {
		dev_err(dev, "set_rss_key failed, error %d\n", status);
		err = -EIO;
	}

	kfree(key);
ice_vsi_cfg_rss_exit:
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
void ice_vsi_set_vf_rss_flow_fld(struct ice_vsi *vsi)
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
		dev_dbg(dev, "ice_add_avf_rss_cfg failed for vsi = %d, error = %d\n",
			vsi->vsi_num, status);
}

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
void ice_vsi_set_rss_flow_fld(struct ice_vsi *vsi)
{
	u16 vsi_handle = vsi->idx, vsi_num = vsi->vsi_num;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		dev_dbg(dev, "Advanced RSS disabled. Package download failed, vsi num = %d\n",
			vsi_num);
		return;
	}

	/* configure RSS for IPv4 with input set IP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_FLOW_HASH_IPV4,
				 ICE_FLOW_SEG_HDR_IPV4);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for ipv4 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for IPv6 with input set IPv6 src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_FLOW_HASH_IPV6,
				 ICE_FLOW_SEG_HDR_IPV6);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for ipv6 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for tcp4 with input set IP src/dst, TCP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_HASH_TCP_IPV4,
				 ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV4);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for tcp4 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for udp4 with input set IP src/dst, UDP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_HASH_UDP_IPV4,
				 ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV4);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for udp4 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for sctp4 with input set IP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_FLOW_HASH_IPV4,
				 ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV4);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for sctp4 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for tcp6 with input set IPv6 src/dst, TCP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_HASH_TCP_IPV6,
				 ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV6);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for tcp6 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for udp6 with input set IPv6 src/dst, UDP src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_HASH_UDP_IPV6,
				 ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV6);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for udp6 flow, vsi = %d, error = %d\n",
			vsi_num, status);

	/* configure RSS for sctp6 with input set IPv6 src/dst */
	status = ice_add_rss_cfg(hw, vsi_handle, ICE_FLOW_HASH_IPV6,
				 ICE_FLOW_SEG_HDR_SCTP | ICE_FLOW_SEG_HDR_IPV6);
	if (status)
		dev_dbg(dev, "ice_add_rss_cfg failed for sctp6 flow, vsi = %d, error = %d\n",
			vsi_num, status);
}

/**
 * ice_add_mac_to_list - Add a MAC address filter entry to the list
 * @vsi: the VSI to be forwarded to
 * @add_list: pointer to the list which contains MAC filter entries
 * @macaddr: the MAC address to be added.
 * @action: filter action to be performed on match
 *
 * Adds MAC address filter entry to the temp list
 *
 * Returns 0 on success or ENOMEM on failure.
 */
int
ice_add_mac_to_list(struct ice_vsi *vsi, struct list_head *add_list,
		    const u8 *macaddr, enum ice_sw_fwd_act_type action)
{
	struct ice_fltr_list_entry *tmp;
	struct ice_pf *pf = vsi->back;

	tmp = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*tmp), GFP_ATOMIC);
	if (!tmp)
		return -ENOMEM;

	tmp->fltr_info.flag = ICE_FLTR_TX;
	tmp->fltr_info.src_id = ICE_SRC_ID_VSI;
	tmp->fltr_info.lkup_type = ICE_SW_LKUP_MAC;
	tmp->fltr_info.fltr_act = action;
	tmp->fltr_info.vsi_handle = vsi->idx;
	ether_addr_copy(tmp->fltr_info.l_data.mac.mac_addr, macaddr);

	INIT_LIST_HEAD(&tmp->list_entry);
	list_add(&tmp->list_entry, add_list);

	return 0;
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
	DECLARE_BITMAP(check_bits, __ICE_STATE_NBITS) = { 0 };

	if (!pf)
		return false;

	bitmap_set(check_bits, 0, __ICE_STATE_NOMINAL_CHECK_BITS);
	if (bitmap_intersects(pf->state, check_bits, __ICE_STATE_NBITS))
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
 * ice_free_fltr_list - free filter lists helper
 * @dev: pointer to the device struct
 * @h: pointer to the list head to be freed
 *
 * Helper function to free filter lists previously created using
 * ice_add_mac_to_list
 */
void ice_free_fltr_list(struct device *dev, struct list_head *h)
{
	struct ice_fltr_list_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, h, list_entry) {
		list_del(&e->list_entry);
		devm_kfree(dev, e);
	}
}

/**
 * ice_vsi_add_vlan - Add VSI membership for given VLAN
 * @vsi: the VSI being configured
 * @vid: VLAN ID to be added
 * @action: filter action to be performed on match
 */
int
ice_vsi_add_vlan(struct ice_vsi *vsi, u16 vid, enum ice_sw_fwd_act_type action)
{
	struct ice_fltr_list_entry *tmp;
	struct ice_pf *pf = vsi->back;
	LIST_HEAD(tmp_add_list);
	enum ice_status status;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	tmp = devm_kzalloc(dev, sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp->fltr_info.lkup_type = ICE_SW_LKUP_VLAN;
	tmp->fltr_info.fltr_act = action;
	tmp->fltr_info.flag = ICE_FLTR_TX;
	tmp->fltr_info.src_id = ICE_SRC_ID_VSI;
	tmp->fltr_info.vsi_handle = vsi->idx;
	tmp->fltr_info.l_data.vlan.vlan_id = vid;

	INIT_LIST_HEAD(&tmp->list_entry);
	list_add(&tmp->list_entry, &tmp_add_list);

	status = ice_add_vlan(&pf->hw, &tmp_add_list);
	if (!status) {
		vsi->num_vlan++;
	} else {
		err = -ENODEV;
		dev_err(dev, "Failure Adding VLAN %d on VSI %i\n", vid,
			vsi->vsi_num);
	}

	ice_free_fltr_list(dev, &tmp_add_list);
	return err;
}

/**
 * ice_vsi_kill_vlan - Remove VSI membership for a given VLAN
 * @vsi: the VSI being configured
 * @vid: VLAN ID to be removed
 *
 * Returns 0 on success and negative on failure
 */
int ice_vsi_kill_vlan(struct ice_vsi *vsi, u16 vid)
{
	struct ice_fltr_list_entry *list;
	struct ice_pf *pf = vsi->back;
	LIST_HEAD(tmp_add_list);
	enum ice_status status;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	list = devm_kzalloc(dev, sizeof(*list), GFP_KERNEL);
	if (!list)
		return -ENOMEM;

	list->fltr_info.lkup_type = ICE_SW_LKUP_VLAN;
	list->fltr_info.vsi_handle = vsi->idx;
	list->fltr_info.fltr_act = ICE_FWD_TO_VSI;
	list->fltr_info.l_data.vlan.vlan_id = vid;
	list->fltr_info.flag = ICE_FLTR_TX;
	list->fltr_info.src_id = ICE_SRC_ID_VSI;

	INIT_LIST_HEAD(&list->list_entry);
	list_add(&list->list_entry, &tmp_add_list);

	status = ice_remove_vlan(&pf->hw, &tmp_add_list);
	if (!status) {
		vsi->num_vlan--;
	} else if (status == ICE_ERR_DOES_NOT_EXIST) {
		dev_dbg(dev, "Failed to remove VLAN %d on VSI %i, it does not exist, status: %d\n",
			vid, vsi->vsi_num, status);
	} else {
		dev_err(dev, "Error removing VLAN %d on vsi %i error: %d\n",
			vid, vsi->vsi_num, status);
		err = -EIO;
	}

	ice_free_fltr_list(dev, &tmp_add_list);
	return err;
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
	for (i = 0; i < vsi->num_rxq; i++) {
		int err;

		err = ice_setup_rx_ctx(vsi->rx_rings[i]);
		if (err) {
			dev_err(ice_pf_to_dev(vsi->back), "ice_setup_rx_ctx failed for RxQ %d, err %d\n",
				i, err);
			return err;
		}
	}

	return 0;
}

/**
 * ice_vsi_cfg_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 * @rings: Tx ring array to be configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
static int
ice_vsi_cfg_txqs(struct ice_vsi *vsi, struct ice_ring **rings)
{
	struct ice_aqc_add_tx_qgrp *qg_buf;
	u16 q_idx = 0;
	int err = 0;

	qg_buf = kzalloc(sizeof(*qg_buf), GFP_KERNEL);
	if (!qg_buf)
		return -ENOMEM;

	qg_buf->num_txqs = 1;

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		err = ice_vsi_cfg_txq(vsi, rings[q_idx], qg_buf);
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
		vsi->xdp_rings[i]->xsk_umem = ice_xsk_umem(vsi->xdp_rings[i]);
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
u32 ice_intrl_usec_to_reg(u8 intrl, u8 gran)
{
	u32 val = intrl / gran;

	if (val)
		return val | GLINT_RATE_INTRL_ENA_M;
	return 0;
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
	u32 txq = 0, rxq = 0;
	int i, q;

	for (i = 0; i < vsi->num_q_vectors; i++) {
		struct ice_q_vector *q_vector = vsi->q_vectors[i];
		u16 reg_idx = q_vector->reg_idx;

		ice_cfg_itr(hw, q_vector);

		wr32(hw, GLINT_RATE(reg_idx),
		     ice_intrl_usec_to_reg(q_vector->intrl, hw->intrl_gran));

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
 * ice_vsi_manage_vlan_insertion - Manage VLAN insertion for the VSI for Tx
 * @vsi: the VSI being changed
 */
int ice_vsi_manage_vlan_insertion(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->back->hw;
	struct ice_vsi_ctx *ctxt;
	enum ice_status status;
	int ret = 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;


	/* Here we are configuring the VSI to let the driver add VLAN tags by
	 * setting vlan_flags to ICE_AQ_VSI_VLAN_MODE_ALL. The actual VLAN tag
	 * insertion happens in the Tx hot path, in ice_tx_map.
	 */
	ctxt->info.vlan_flags = ICE_AQ_VSI_VLAN_MODE_ALL;

	/* Preserve existing VLAN strip setting */
	ctxt->info.vlan_flags |= (vsi->info.vlan_flags &
				  ICE_AQ_VSI_VLAN_EMOD_M);

	ctxt->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_VLAN_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(vsi->back), "update VSI for VLAN insert failed, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		ret = -EIO;
		goto out;
	}

	vsi->info.vlan_flags = ctxt->info.vlan_flags;
out:
	kfree(ctxt);
	return ret;
}

/**
 * ice_vsi_manage_vlan_stripping - Manage VLAN stripping for the VSI for Rx
 * @vsi: the VSI being changed
 * @ena: boolean value indicating if this is a enable or disable request
 */
int ice_vsi_manage_vlan_stripping(struct ice_vsi *vsi, bool ena)
{
	struct ice_hw *hw = &vsi->back->hw;
	struct ice_vsi_ctx *ctxt;
	enum ice_status status;
	int ret = 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;


	/* Here we are configuring what the VSI should do with the VLAN tag in
	 * the Rx packet. We can either leave the tag in the packet or put it in
	 * the Rx descriptor.
	 */
	if (ena)
		/* Strip VLAN tag from Rx packet and put it in the desc */
		ctxt->info.vlan_flags = ICE_AQ_VSI_VLAN_EMOD_STR_BOTH;
	else
		/* Disable stripping. Leave tag in packet */
		ctxt->info.vlan_flags = ICE_AQ_VSI_VLAN_EMOD_NOTHING;

	/* Allow all packets untagged/tagged */
	ctxt->info.vlan_flags |= ICE_AQ_VSI_VLAN_MODE_ALL;

	ctxt->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_VLAN_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(vsi->back), "update VSI for VLAN strip failed, ena = %d err %d aq_err %d\n",
			ena, status, hw->adminq.sq_last_status);
		ret = -EIO;
		goto out;
	}

	vsi->info.vlan_flags = ctxt->info.vlan_flags;
out:
	kfree(ctxt);
	return ret;
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

/**
 * ice_cfg_vlan_pruning - enable or disable VLAN pruning on the VSI
 * @vsi: VSI to enable or disable VLAN pruning on
 * @ena: set to true to enable VLAN pruning and false to disable it
 * @vlan_promisc: enable valid security flags if not in VLAN promiscuous mode
 *
 * returns 0 if VSI is updated, negative otherwise
 */
int ice_cfg_vlan_pruning(struct ice_vsi *vsi, bool ena, bool vlan_promisc)
{
	struct ice_vsi_ctx *ctxt;
	struct ice_pf *pf;
	int status;

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;
	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->info = vsi->info;

	if (ena)
		ctxt->info.sw_flags2 |= ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
	else
		ctxt->info.sw_flags2 &= ~ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;

	if (!vlan_promisc)
		ctxt->info.valid_sections =
			cpu_to_le16(ICE_AQ_VSI_PROP_SW_VALID);

	status = ice_update_vsi(&pf->hw, vsi->idx, ctxt, NULL);
	if (status) {
		netdev_err(vsi->netdev, "%sabling VLAN pruning on VSI handle: %d, VSI HW ID: %d failed, err = %d, aq_err = %d\n",
			   ena ? "En" : "Dis", vsi->idx, vsi->vsi_num, status,
			   pf->hw.adminq.sq_last_status);
		goto err_out;
	}

	vsi->info.sw_flags2 = ctxt->info.sw_flags2;

	kfree(ctxt);
	return 0;

err_out:
	kfree(ctxt);
	return -EIO;
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
			struct ice_vf *vf = &vsi->back->vf[vsi->vf_id];

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
 * ice_vsi_add_rem_eth_mac - Program VSI ethertype based filter with rule
 * @vsi: the VSI being configured
 * @add_rule: boolean value to add or remove ethertype filter rule
 */
static void
ice_vsi_add_rem_eth_mac(struct ice_vsi *vsi, bool add_rule)
{
	struct ice_fltr_list_entry *list;
	struct ice_pf *pf = vsi->back;
	LIST_HEAD(tmp_add_list);
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	list = devm_kzalloc(dev, sizeof(*list), GFP_KERNEL);
	if (!list)
		return;

	list->fltr_info.lkup_type = ICE_SW_LKUP_ETHERTYPE;
	list->fltr_info.fltr_act = ICE_DROP_PACKET;
	list->fltr_info.flag = ICE_FLTR_TX;
	list->fltr_info.src_id = ICE_SRC_ID_VSI;
	list->fltr_info.vsi_handle = vsi->idx;
	list->fltr_info.l_data.ethertype_mac.ethertype = vsi->ethtype;

	INIT_LIST_HEAD(&list->list_entry);
	list_add(&list->list_entry, &tmp_add_list);

	if (add_rule)
		status = ice_add_eth_mac(&pf->hw, &tmp_add_list);
	else
		status = ice_remove_eth_mac(&pf->hw, &tmp_add_list);

	if (status)
		dev_err(dev, "Failure Adding or Removing Ethertype on VSI %i error: %d\n",
			vsi->vsi_num, status);

	ice_free_fltr_list(dev, &tmp_add_list);
}

#define ICE_ETHERTYPE_LLDP		0x88CC

/** ice_cfg_sw_lldp - Config switch rules for LLDP packet handling
 * @vsi: the VSI being configured
 * @tx: bool to determine Tx or Rx rule
 * @create: bool to determine create or remove Rule
 */
void ice_cfg_sw_lldp(struct ice_vsi *vsi, bool tx, bool create)
{
	struct ice_fltr_list_entry *list;
	struct ice_pf *pf = vsi->back;
	LIST_HEAD(tmp_add_list);
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	list = devm_kzalloc(dev, sizeof(*list), GFP_KERNEL);
	if (!list)
		return;

	list->fltr_info.lkup_type = ICE_SW_LKUP_ETHERTYPE;
	list->fltr_info.vsi_handle = vsi->idx;
	list->fltr_info.l_data.ethertype_mac.ethertype = ICE_ETHERTYPE_LLDP;

	if (tx) {
		list->fltr_info.fltr_act = ICE_DROP_PACKET;
		list->fltr_info.flag = ICE_FLTR_TX;
		list->fltr_info.src_id = ICE_SRC_ID_VSI;
	} else {
		list->fltr_info.fltr_act = ICE_FWD_TO_VSI;
		list->fltr_info.flag = ICE_FLTR_RX;
		list->fltr_info.src_id = ICE_SRC_ID_LPORT;
	}

	INIT_LIST_HEAD(&list->list_entry);
	list_add(&list->list_entry, &tmp_add_list);

	if (create)
		status = ice_add_eth_mac(&pf->hw, &tmp_add_list);
	else
		status = ice_remove_eth_mac(&pf->hw, &tmp_add_list);

	if (status)
		dev_err(dev, "Fail %s %s LLDP rule on VSI %i error: %d\n",
			create ? "adding" : "removing", tx ? "TX" : "RX",
			vsi->vsi_num, status);

	ice_free_fltr_list(dev, &tmp_add_list);
}

/**
 * ice_vsi_setup - Set up a VSI by a given type
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 * @type: VSI type
 * @vf_id: defines VF ID to which this VSI connects. This field is meant to be
 *         used only for ICE_VSI_VF VSI type. For other VSI types, should
 *         fill-in ICE_INVAL_VFID as input.
 * @ch: ptr to channel
 * @tc: traffic class for VF ADQ
 * This allocates the sw VSI structure and its queue resources.
 *
 * Returns pointer to the successfully allocated and configured VSI sw struct on
 * success, NULL on failure.
 */
struct ice_vsi *
ice_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi,
	      enum ice_vsi_type type, u16 vf_id, struct ice_channel *ch, u8 tc)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	struct ice_vsi *vsi;
	int ret, i;

	if (type == ICE_VSI_CHNL)
		vsi = ice_vsi_alloc(pf, type, ch, ICE_INVAL_VFID, 0);
	else if (type == ICE_VSI_VF)
		vsi = ice_vsi_alloc(pf, type, NULL, vf_id, tc);
	else
		vsi = ice_vsi_alloc(pf, type, NULL, ICE_INVAL_VFID, tc);

	if (!vsi) {
		dev_err(dev, "could not allocate VSI\n");
		return NULL;
	}

	vsi->port_info = pi;
	vsi->vsw = pf->first_sw;
	if (vsi->type == ICE_VSI_PF)
		vsi->ethtype = ETH_P_PAUSE;

	if (vsi->type == ICE_VSI_VF)
		vsi->vf_id = vf_id;

	ice_alloc_fd_res(vsi);

	if (type != ICE_VSI_CHNL) {
		if (ice_vsi_get_qs(vsi)) {
			dev_err(dev, "Failed to allocate queues. vsi->idx = %d\n",
				vsi->idx);
			goto unroll_vsi_alloc;
		}
	}

	/* set RSS capabilities */
	ice_vsi_set_rss_params(vsi);

	/* set TC configuration */
	ice_vsi_set_tc_cfg(vsi);

	/* create the VSI */
	ret = ice_vsi_init(vsi, true);
	if (ret)
		goto unroll_get_qs;

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_PF:
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_setup_vector_base(vsi);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = ice_vsi_set_q_vectors_reg_idx(vsi, 0);

		if (ret)
			goto unroll_vector_base;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vector_base;

		/* Always add VLAN ID 0 switch rule by default. This is needed
		 * in order to allow all untagged and 0 tagged priority traffic
		 * if Rx VLAN pruning is enabled. Also there are cases where we
		 * don't get the call to add VLAN 0 via ice_vlan_rx_add_vid()
		 * so this handles those cases (i.e. adding the PF to a bridge
		 * without the 8021q module loaded).
		 */
		ret = ice_vsi_add_vlan(vsi, 0, ICE_FWD_TO_VSI);
		if (ret)
			goto unroll_clear_rings;

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
		dev_err(dev, "VSI %d failed lan queue config, error %d\n",
			vsi->vsi_num, status);
		goto unroll_vector_base;
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
			ice_vsi_add_rem_eth_mac(vsi, true);

			/* Tx LLDP packets */
			ice_cfg_sw_lldp(vsi, true, true);
		}

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
		u16 reg_idx = q_vector->reg_idx;

		wr32(hw, GLINT_ITR(ICE_IDX_ITR0, reg_idx), 0);
		wr32(hw, GLINT_ITR(ICE_IDX_ITR1, reg_idx), 0);
		for (q = 0; q < q_vector->num_ring_tx; q++) {
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

		irq_num = pf->msix_entries[vector].vector;

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
	enum ice_close_reason reason = ICE_REASON_INTERFACE_DOWN;

	if (test_bit(__ICE_CORER_REQ, vsi->back->state))
		reason = ICE_REASON_CORER_REQ;
	if (test_bit(__ICE_GLOBR_REQ, vsi->back->state))
		reason = ICE_REASON_GLOBR_REQ;
	if (test_bit(__ICE_PFR_REQ, vsi->back->state))
		reason = ICE_REASON_PFR_REQ;
	if (!ice_is_safe_mode(vsi->back) && vsi->type == ICE_VSI_PF) {
		int ret = ice_for_each_peer(vsi->back, &reason, ice_peer_close);

		if (ret)
			dev_dbg(ice_pf_to_dev(vsi->back), "Peer device did not implement close function\n");
	}

	if (!test_and_set_bit(__ICE_DOWN, vsi->state))
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

	if (!test_bit(__ICE_NEEDS_RESTART, vsi->state))
		return 0;

	clear_bit(__ICE_NEEDS_RESTART, vsi->state);

	if (vsi->netdev && vsi->type == ICE_VSI_PF) {
		if (netif_running(vsi->netdev)) {
			if (!locked)
				rtnl_lock();

			err = ice_open(vsi->netdev);

			if (!locked)
				rtnl_unlock();
		}
#ifdef HAVE_NETDEV_SB_DEV

		if (err)
			return err;
		if (test_bit(ICE_FLAG_MACVLAN_ENA, vsi->back->flags) &&
		    !ice_is_adq_active(vsi->back))
			err = ice_vsi_cfg_netdev_tc0(vsi);
#endif /* HAVE_NETDEV_SB_DEV */
	} else if (vsi->type == ICE_VSI_CTRL) {
		err = ice_vsi_open_ctrl(vsi);
#ifdef HAVE_NETDEV_SB_DEV
	} else if (vsi->type == ICE_VSI_OFFLOAD_MACVLAN) {
		err = ice_vsi_open(vsi);
#endif /* HAVE_NETDEV_SB_DEV */
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
	if (test_bit(__ICE_DOWN, vsi->state))
		return;

	set_bit(__ICE_NEEDS_RESTART, vsi->state);

	if (vsi->type == ICE_VSI_PF && vsi->netdev) {
		if (netif_running(vsi->netdev)) {
			if (!locked)
				rtnl_lock();

			ice_stop(vsi->netdev);

			if (!locked)
				rtnl_unlock();
		} else {
			ice_vsi_close(vsi);
		}
	} else if (vsi->type == ICE_VSI_CTRL) {
		ice_vsi_close(vsi);
#ifdef HAVE_NETDEV_SB_DEV
	} else if (vsi->type == ICE_VSI_OFFLOAD_MACVLAN) {
		ice_vsi_close(vsi);
#endif /* HAVE_NETDEV_SB_DEV */
	}
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
	int start = 0, end = 0;

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
 * ice_get_valid_res_count - Get in-use count from a resource tracker
 * @res: Resource tracker instance
 */
u16 ice_get_valid_res_count(struct ice_res_tracker *res)
{
	u16 i, count = 0;

	for (i = 0; i < res->end; i++)
		if (res->list[i] & ICE_RES_VALID_BIT)
			count++;

	return count;
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
		synchronize_irq(pf->msix_entries[i + base].vector);
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
 * ice_vsi_release - Delete a VSI and free its resources
 * @vsi: the VSI being removed
 *
 * Returns 0 on success or < 0 on error
 */
int ice_vsi_release(struct ice_vsi *vsi)
{
	struct ice_pf *pf;

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
	    vsi->type != ICE_VSI_OFFLOAD_MACVLAN) {
		unregister_netdev(vsi->netdev);
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
	if (vsi->type != ICE_VSI_VF) {
		/* reclaim SW interrupts back to the common pool */
		ice_free_res(pf->irq_tracker, vsi->base_vector, vsi->idx);
		pf->num_avail_sw_msix += vsi->num_q_vectors;
	}

	if (!ice_is_safe_mode(pf)) {
		if (vsi->type == ICE_VSI_PF) {
			ice_vsi_add_rem_eth_mac(vsi, false);
			ice_cfg_sw_lldp(vsi, true, false);
			/* The Rx rule will only exist to remove if the LLDP FW
			 * engine is currently stopped
			 */
			if (!test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags))
				ice_cfg_sw_lldp(vsi, false, false);
		}
	}

	ice_remove_vsi_fltr(&pf->hw, vsi->idx);
	ice_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	ice_vsi_delete(vsi);
	ice_vsi_free_q_vectors(vsi);

	/* make sure unregister_netdev() was called by checking __ICE_DOWN */
	if (vsi->netdev && test_bit(__ICE_DOWN, vsi->state)) {
		if (vsi->type != ICE_VSI_OFFLOAD_MACVLAN)
			free_netdev(vsi->netdev);
		vsi->netdev = NULL;
	}

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
 * ice_vsi_rebuild_update_coalesce - set coalesce for a q_vector
 * @q_vector: pointer to q_vector which is being updated
 * @coalesce: pointer to array of struct with stored coalesce
 *
 * Set coalesce param in q_vector and update these parameters in HW.
 */
static void
ice_vsi_rebuild_update_coalesce(struct ice_q_vector *q_vector,
				struct ice_coalesce_stored *coalesce)
{
	struct ice_ring_container *rx_rc = &q_vector->rx;
	struct ice_ring_container *tx_rc = &q_vector->tx;
	struct ice_hw *hw = &q_vector->vsi->back->hw;

	tx_rc->itr_setting = coalesce->itr_tx;
	rx_rc->itr_setting = coalesce->itr_rx;

	/* dynamic ITR values will be updated during Tx/Rx */
	if (!ITR_IS_DYNAMIC(tx_rc->itr_setting))
		wr32(hw, GLINT_ITR(tx_rc->itr_idx, q_vector->reg_idx),
		     ITR_REG_ALIGN(tx_rc->itr_setting) >>
		     ICE_ITR_GRAN_S);
	if (!ITR_IS_DYNAMIC(rx_rc->itr_setting))
		wr32(hw, GLINT_ITR(rx_rc->itr_idx, q_vector->reg_idx),
		     ITR_REG_ALIGN(rx_rc->itr_setting) >>
		     ICE_ITR_GRAN_S);

	q_vector->intrl = coalesce->intrl;
	wr32(hw, GLINT_RATE(q_vector->reg_idx),
	     ice_intrl_usec_to_reg(q_vector->intrl, hw->intrl_gran));
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

		coalesce[i].itr_tx = q_vector->tx.itr_setting;
		coalesce[i].itr_rx = q_vector->rx.itr_setting;
		coalesce[i].intrl = q_vector->intrl;
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
	int i;

	if ((size && !coalesce) || !vsi)
		return;

	for (i = 0; i < size && i < vsi->num_q_vectors; i++)
		ice_vsi_rebuild_update_coalesce(vsi->q_vectors[i],
						&coalesce[i]);

	for (; i < vsi->num_q_vectors; i++) {
		struct ice_coalesce_stored coalesce_dflt = {
			.itr_tx = ICE_DFLT_TX_ITR,
			.itr_rx = ICE_DFLT_RX_ITR,
			.intrl = 0
		};
		ice_vsi_rebuild_update_coalesce(vsi->q_vectors[i],
						&coalesce_dflt);
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
	struct ice_vf *vf = NULL;
	enum ice_status status;
	struct ice_pf *pf;
	int ret, i;

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;
	if (vsi->type == ICE_VSI_VF)
		vf = &pf->vf[vsi->vf_id];

	coalesce = kcalloc(vsi->num_q_vectors,
			   sizeof(struct ice_coalesce_stored), GFP_KERNEL);
	if (coalesce)
		prev_num_q_vectors = ice_vsi_rebuild_get_coalesce(vsi,
								  coalesce);
	ice_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	ice_vsi_free_q_vectors(vsi);

	/* SR-IOV determines needed MSIX resources all at once instead of per
	 * VSI since when VFs are spawned we know how many VFs there are and how
	 * many interrupts each VF needs. SR-IOV MSIX resources are also
	 * cleared in the same manner.
	 */
	if (vsi->type != ICE_VSI_VF) {
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
	ice_dev_onetime_setup(&pf->hw);
	if (vsi->type == ICE_VSI_VF)
		ice_vsi_set_num_qs(vsi, vf->vf_id);
	else
		ice_vsi_set_num_qs(vsi, ICE_INVAL_VFID);

	ret = ice_vsi_alloc_arrays(vsi);
	if (ret < 0)
		goto err_vsi;

	ice_vsi_get_qs(vsi);

	ice_alloc_fd_res(vsi);
	ice_vsi_set_tc_cfg(vsi);

	/* Initialize VSI struct elements and create VSI in FW */
	ret = ice_vsi_init(vsi, init_vsi);
	if (ret < 0)
		goto err_vsi;

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_OFFLOAD_MACVLAN:
	case ICE_VSI_VMDQ2:
	case ICE_VSI_PF:
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto err_rings;

		ret = ice_vsi_setup_vector_base(vsi);
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
			vsi->num_xdp_txq = vsi->alloc_txq;
			ret = ice_prepare_xdp_rings(vsi, vsi->xdp_prog);
			if (ret)
				goto err_vectors;
		}
#endif /* HAVE_XDP_SUPPORT */
		/* ICE_VSI_CTRL does not need RSS so skip RSS processing */
		if (vsi->type != ICE_VSI_CTRL)
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
		if (vsi->type == ICE_VSI_CHNL)
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
		/* If MQPRIO ise set, means channel code path, hence for main
		 * VSI's, use TC as 1
		 */
		status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx, 1, max_txqs);
	else
#endif /* NETIF_F_HW_TC */
		status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx,
					 vsi->tc_cfg.ena_tc, max_txqs);

	if (status) {
		dev_err(ice_pf_to_dev(pf), "VSI %d failed lan queue config, error %d\n",
			vsi->vsi_num, status);
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
	set_bit(__ICE_RESET_FAILED, pf->state);
	kfree(coalesce);
	return ret;
}

/**
 * ice_is_reset_in_progress - check for a reset in progress
 * @state: PF state field
 */
bool ice_is_reset_in_progress(unsigned long *state)
{
	return test_bit(__ICE_RESET_OICR_RECV, state) ||
	       test_bit(__ICE_DCBNL_DEVRESET, state) ||
	       test_bit(__ICE_PFR_REQ, state) ||
	       test_bit(__ICE_CORER_REQ, state) ||
	       test_bit(__ICE_GLOBR_REQ, state);
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

	dcbcfg = &pf->hw.port_info->local_dcbx_cfg;

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
 * ice_vsi_setup_queue_map_mqprio - Prepares mqprio based tc_config
 * @vsi: the VSI being configured,
 * @ctxt: VSI context structure
 * @ena_tc: number of traffic classes to enable
 *
 * Prepares VSI tc_config to have queue configurations based on MQPRIO options.
 */
static void
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
	vsi->num_rxq = offset + qcount_rx;

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
		ice_vsi_setup_q_map_mqprio(vsi, ctx, ena_tc);
	else
		ice_vsi_setup_q_map(vsi, ctx);
#else
	ice_vsi_setup_q_map(vsi, ctx);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

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
		dev_err(dev, "VSI %d failed TC config, error %d\n",
			vsi->vsi_num, status);
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
 * @cont: used to increment per-vector counters
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void ice_update_ring_stats(struct ice_ring *ring,
				  struct ice_ring_container *cont,
				  u64 pkts, u64 bytes)
{
	ring->stats.bytes += bytes;
	ring->stats.pkts += pkts;
	cont->total_bytes += bytes;
	cont->total_pkts += pkts;
}

#ifdef ADQ_PERF
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
#endif /* ADQ_PERF */

/**
 * ice_update_tx_ring_stats - Update Tx ring specific counters
 * @tx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void ice_update_tx_ring_stats(struct ice_ring *tx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&tx_ring->syncp);
	ice_update_ring_stats(tx_ring, &tx_ring->q_vector->tx, pkts, bytes);
#ifdef ADQ_PERF
#ifdef ADQ_PERF_COUNTERS
	ice_update_adq_stats(tx_ring, pkts);
#endif /* ADQ_PERF_COUNTERS */
#endif /* ADQ_PERF */
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
	ice_update_ring_stats(rx_ring, &rx_ring->q_vector->rx, pkts, bytes);
#ifdef ADQ_PERF
	ice_update_adq_stats(rx_ring, pkts);

	/* if vector is transitioning from BP->INT (due to busy_poll_stop()) and
	 * we find no packets, in that case: to avoid entering into INTR mode
	 * (which happens from napi_poll - enabling interrupt if
	 * unlikely_comeback_to_bp getting set), make "prev_data_pkt_recv" to be
	 * non-zero, so that interrupts won't be enabled. This is to address the
	 * issue where num_force_wb on some queues is 2 to 3 times higher than
	 * other queues and those queues also sees lot of interrupts
	 */
	if (ice_vector_ch_enabled(rx_ring->q_vector) &&
	    ice_vector_busypoll_intr(rx_ring->q_vector)) {
		if (!pkts)
			rx_ring->q_vector->state_flags |=
					ICE_CHNL_PREV_DATA_PKT_RECV;
#ifdef ADQ_PERF_COUNTERS
	} else if (ice_vector_ch_enabled(rx_ring->q_vector)) {
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
#endif /* ADQ_PERF */

	u64_stats_update_end(&rx_ring->syncp);
}

/**
 * ice_vsi_cfg_mac_fltr - Add or remove a MAC address filter for a VSI
 * @vsi: the VSI being configured MAC filter
 * @macaddr: the MAC address to be added.
 * @set: Add or delete a MAC filter
 *
 * Adds or removes MAC address filter entry for VF VSI
 */
enum ice_status
ice_vsi_cfg_mac_fltr(struct ice_vsi *vsi, const u8 *macaddr, bool set)
{
	LIST_HEAD(tmp_add_list);
	enum ice_status status;

	 /* Update MAC filter list to be added or removed for a VSI */
	if (ice_add_mac_to_list(vsi, &tmp_add_list, macaddr, ICE_FWD_TO_VSI)) {
		status = ICE_ERR_NO_MEMORY;
		goto cfg_mac_fltr_exit;
	}

	if (set)
		status = ice_add_mac(&vsi->back->hw, &tmp_add_list);
	else
		status = ice_remove_mac(&vsi->back->hw, &tmp_add_list);

cfg_mac_fltr_exit:
	ice_free_fltr_list(ice_pf_to_dev(vsi->back), &tmp_add_list);
	return status;
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
 * @sw: switch to check if its default forwarding VSI is free
 *
 * Return true if the default forwarding VSI is already being used, else returns
 * false signalling that it's available to use.
 */
bool ice_is_dflt_vsi_in_use(struct ice_sw *sw)
{
	return (sw->dflt_vsi && sw->dflt_vsi_ena);
}

/**
 * ice_is_vsi_dflt_vsi - check if the VSI passed in is the default VSI
 * @sw: switch for the default forwarding VSI to compare against
 * @vsi: VSI to compare against default forwarding VSI
 *
 * If this VSI passed in is the default forwarding VSI then return true, else
 * return false
 */
bool ice_is_vsi_dflt_vsi(struct ice_sw *sw, struct ice_vsi *vsi)
{
	return (sw->dflt_vsi == vsi && sw->dflt_vsi_ena);
}

/**
 * ice_set_dflt_vsi - set the default forwarding VSI
 * @sw: switch used to assign the default forwarding VSI
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
int ice_set_dflt_vsi(struct ice_sw *sw, struct ice_vsi *vsi)
{
	enum ice_status status;
	struct device *dev;

	if (!sw || !vsi)
		return -EINVAL;

	dev = ice_pf_to_dev(vsi->back);

	/* the VSI passed in is already the default VSI */
	if (ice_is_vsi_dflt_vsi(sw, vsi)) {
		dev_dbg(dev, "VSI %d passed in is already the default forwarding VSI, nothing to do\n",
			vsi->vsi_num);
		return 0;
	}

	/* another VSI is already the default VSI for this switch */
	if (ice_is_dflt_vsi_in_use(sw)) {
		dev_err(dev, "Default forwarding VSI %d already in use, disable it and try again\n",
			sw->dflt_vsi->vsi_num);
		return -EEXIST;
	}

	status = ice_cfg_dflt_vsi(vsi->port_info, vsi->idx, true, ICE_FLTR_RX);
	if (status) {
		dev_err(dev, "Failed to set VSI %d as the default forwarding VSI, error %d\n",
			vsi->vsi_num, status);
		return -EIO;
	}

	sw->dflt_vsi = vsi;
	sw->dflt_vsi_ena = true;

	return 0;
}

/**
 * ice_clear_dflt_vsi - clear the default forwarding VSI
 * @sw: switch used to clear the default VSI
 *
 * If the switch has no default VSI or it's not enabled then return error.
 *
 * Otherwise try to clear the default VSI and return the result.
 */
int ice_clear_dflt_vsi(struct ice_sw *sw)
{
	struct ice_vsi *dflt_vsi;
	enum ice_status status;
	struct device *dev;

	if (!sw)
		return -EINVAL;

	dev = ice_pf_to_dev(sw->pf);

	dflt_vsi = sw->dflt_vsi;

	/* there is no default VSI configured */
	if (!ice_is_dflt_vsi_in_use(sw))
		return -ENODEV;

	status = ice_cfg_dflt_vsi(dflt_vsi->port_info, dflt_vsi->idx, false,
				  ICE_FLTR_RX);
	if (status) {
		dev_err(dev, "Failed to clear the default forwarding VSI %d, error %d\n",
			dflt_vsi->vsi_num, status);
		return -EIO;
	}

	sw->dflt_vsi = NULL;
	sw->dflt_vsi_ena = false;

	return 0;
}

