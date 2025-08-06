/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* Inter-Driver Communication */
#include "ice.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_dcb_lib.h"
#include "ice_ptp.h"
#include "ice_ieps.h"
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
#include "ice_devlink.h"
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
#include "ice_irq.h"

static DEFINE_IDA(ice_cdev_info_ida);

static struct cdev_info_id ice_cdev_ids[] = ASSIGN_IIDC_INFO;

/**
 * ice_get_auxiliary_drv - retrieve iidc_auxiliary_drv struct
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions for auxiliary
 * driver unload, and the mutex pf->adev_mutex locked to avoid
 * plug/unplug race conditions..
 */
struct iidc_auxiliary_drv
*ice_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;
	struct ice_pf *pf;

	if (!cdev_info)
		return NULL;
	pf = pci_get_drvdata(cdev_info->pdev);

	lockdep_assert_held(&pf->adev_mutex);

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;

	return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
			    adrv.driver);
}

/**
 * ice_for_each_aux - iterate across and call function for each aux driver
 * @pf: pointer to private board struct
 * @data: data to pass to function on each call
 * @fn: pointer to function to call for each aux driver
 */
int
ice_for_each_aux(struct ice_pf *pf, void *data,
		 int (*fn)(struct iidc_core_dev_info *, void *))
{
	unsigned int i;

	if (!pf->cdev_infos)
		return 0;

	for (i = 0; i < ARRAY_SIZE(ice_cdev_ids); i++) {
		struct iidc_core_dev_info *cdev_info;

		cdev_info = pf->cdev_infos[i];
		if (cdev_info) {
			int ret = fn(cdev_info, data);
			if (ret)
				return ret;
		}
	}

	return 0;
}

/**
 * ice_send_event_to_aux - send event to a specific aux driver
 * @cdev_info: pointer to iidc_core_dev_info struct for this aux
 * @data: opaque pointer used to pass event struct
 */
static int
ice_send_event_to_aux(struct iidc_core_dev_info *cdev_info, void *data)
{
	struct iidc_event *event = data;
	struct iidc_auxiliary_drv *iadrv;
	struct ice_pf *pf;

	if (WARN_ON_ONCE(!in_task()))
		return -EINVAL;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!pf)
		return -EINVAL;

	if (test_bit(ICE_SET_CHANNELS, pf->state))
		return 0;

	mutex_lock(&pf->adev_mutex);

	if (!cdev_info->adev || !event) {
		mutex_unlock(&pf->adev_mutex);
		return 0;
	}

	device_lock(&cdev_info->adev->dev);
	iadrv = ice_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev_info, event);
	device_unlock(&cdev_info->adev->dev);
	mutex_unlock(&pf->adev_mutex);

	return 0;
}

/**
 * ice_send_event_to_aux_no_lock - send event to aux dev without taking dev_lock
 * @cdev: pointer to iidc_core_dev_info struct
 * @data: opaque poiner used to pass event struct
 */
void ice_send_event_to_aux_no_lock(struct iidc_core_dev_info *cdev, void *data)
{
	struct iidc_event *event = data;
	struct iidc_auxiliary_drv *iadrv;
	struct ice_pf *pf;

	pf = pci_get_drvdata(cdev->pdev);
	mutex_lock(&pf->adev_mutex);

	iadrv = ice_get_auxiliary_drv(cdev);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev, event);
	mutex_unlock(&pf->adev_mutex);
}

/**
 * ice_send_event_to_auxs - send event to all auxiliary drivers
 * @pf: pointer to PF struct
 * @event: pointer to iidc_event to propagate
 *
 * event struct to be populated by caller
 */
void ice_send_event_to_auxs(struct ice_pf *pf, struct iidc_event *event)
{
	if (!event || !pf)
		return;

	if (bitmap_weight(event->type, IIDC_EVENT_NBITS) != 1) {
		dev_warn(ice_pf_to_dev(pf), "Event with not exactly one type bit set\n");
		return;
	}

	ice_for_each_aux(pf, event, ice_send_event_to_aux);
}

/**
 * ice_unroll_cdev_info - destroy cdev_info resources
 * @cdev_info: ptr to cdev_info struct
 * @data: ptr to opaque data
 *
 * This function releases resources for cdev_info objects.
 * Meant to be called from a ice_for_each_aux invocation, which means it needs
 * to return an int so that it's function signature matches the other
 * functions.
 */
int ice_unroll_cdev_info(struct iidc_core_dev_info *cdev_info,
			 void __always_unused *data)
{
	kfree(cdev_info);
	return 0;
}

/**
 * ice_alloc_rdma_qsets - Allocate Leaf Nodes for RDMA Qset
 * @cdev_info: aux driver that is requesting the Leaf Nodes
 * @qset: Resource to be allocated
 *
 * This function allocates Leaf Nodes for given RDMA Qset resources
 * for the peer object.
 */
static int
ice_alloc_rdma_qsets(struct iidc_core_dev_info *cdev_info,
		     struct iidc_rdma_qset_params *qset)
{
	u16 max_rdmaqs[ICE_MAX_TRAFFIC_CLASS];
#ifdef HAVE_NETDEV_UPPER_INFO
	struct ice_lag *lag;
#endif /* HAVE_NETDEV_UPPER_INFO */
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	u32 qset_teid;
	u16 qs_handle;
	int i, status;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	dev = ice_pf_to_dev(pf);

	if (!ice_is_aux_ena(pf) || !ice_is_rdma_ena(pf))
		return -EINVAL;

	ice_for_each_traffic_class(i)
		max_rdmaqs[i] = 0;

	max_rdmaqs[qset->tc]++;
	qs_handle = qset->qs_handle;

	vsi = ice_find_vsi(pf, qset->vport_id);
	if (!vsi) {
		dev_err(dev, "RDMA QSet invalid VSI\n");
		return -EINVAL;
	}

	status = ice_cfg_vsi_rdma(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				  max_rdmaqs);
	if (status) {
		dev_err(dev, "Failed VSI RDMA qset config\n");
		return status;
	}

	status = ice_ena_vsi_rdma_qset(vsi->port_info, vsi->idx, qset->tc,
				       &qs_handle, 1, &qset_teid);
	if (status) {
		dev_err(dev, "Failed VSI RDMA qset enable\n");
		return status;
	}
	qset->teid = qset_teid;

#ifdef HAVE_NETDEV_UPPER_INFO
	lag = pf->lag;
	if (lag && lag->bonded) {
		mutex_lock(&pf->lag_mutex);
		lag->rdma_qset[qset->tc] = *qset;

		if (cdev_info->rdma_active_port != pf->hw.port_info->lport &&
		    cdev_info->rdma_active_port != IIDC_RDMA_INVALID_PORT) {
			struct net_device *tmp_nd;

			rcu_read_lock();
			for_each_netdev_rcu(&init_net, tmp_nd) {
				struct ice_netdev_priv *tmp_ndp;
				struct ice_lag *tmp_lag;
				struct ice_vsi *tmp_vsi;
				struct ice_hw *tmp_hw;

				if (!netif_is_ice(tmp_nd))
					continue;

				tmp_ndp = netdev_priv(tmp_nd);
				tmp_vsi = tmp_ndp->vsi;
				tmp_lag = tmp_vsi->back->lag;

				if (!tmp_lag->bonded ||
				    tmp_lag->bond_id != lag->bond_id)
					continue;

				tmp_hw = &tmp_vsi->back->hw;

				if (cdev_info->rdma_active_port ==
				    tmp_hw->port_info->lport)
					status = ice_lag_move_node_sync(&pf->hw,
									tmp_hw,
									tmp_vsi,
									qset);
			}
			rcu_read_unlock();
		}
		mutex_unlock(&pf->lag_mutex);
	}

#endif /* HAVE_NETDEV_UPPER_INFO */
	return status;
}

/**
 * ice_alloc_rdma_multi_qsets - Allocate QSets for RDMA Leaf Nodes
 * @cdev_info: struct for aux driver that is allocating qsets
 * @qset: Resource(s) to be allocated
 */
static int
ice_alloc_rdma_multi_qsets(struct iidc_core_dev_info *cdev_info,
			   struct iidc_rdma_multi_qset_params *qset)
{
	u16 max_rdmaqs[ICE_MAX_TRAFFIC_CLASS];
#ifdef HAVE_NETDEV_UPPER_INFO
	struct ice_lag *lag;
#endif /* HAVE_NETDEV_UPPER_INFO */
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	u32 qset_teid[2];
	u16 qs_handle[2];
	int i, status;

	if (!cdev_info || !qset)
		return -EINVAL;

	if (qset->num > 2)
		return -EOPNOTSUPP;

	pf = pci_get_drvdata(cdev_info->pdev);
	dev = ice_pf_to_dev(pf);

	if (!ice_is_aux_ena(pf) || !ice_is_rdma_ena(pf))
		return -EINVAL;

	ice_for_each_traffic_class(i)
		max_rdmaqs[i] = 0;
	max_rdmaqs[qset->tc] = qset->num;

	for (i = 0; i < qset->num; i++)
		qs_handle[i] = qset->qs_handle[i];

	vsi = ice_find_vsi(pf, qset->vport_id);
	if (!vsi) {
		dev_err(dev, "RDMA QSet invalid VSI\n");
		return -EINVAL;
	}

	status = ice_cfg_vsi_rdma(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				  max_rdmaqs);
	if (status) {
		dev_err(dev, "Failed VSI RDMA qset config\n");
		return status;
	}

	for (i = 0; i < qset->num; i++) {
		status = ice_ena_vsi_rdma_qset(vsi->port_info, vsi->idx,
					       qset->tc, &qs_handle[i], 1,
					       &qset_teid[i]);
		if (status) {
			dev_err(dev, "Failed VSI RDMA qset enable\n");
			return status;
		}
	}

	for (i = 0; i < qset->num; i++) {
		qset->teid[i] = qset_teid[i];
		qset->qset_port[i] = IIDC_RDMA_PRIMARY_PORT;
	}

#ifdef HAVE_NETDEV_UPPER_INFO
	lag = pf->lag;
	if (lag && lag->bonded && cdev_info->bond_aa) {
		mutex_lock(&pf->lag_mutex);
		lag->rdma_qsets[qset->tc] = *qset;
		/* ice_lag_aa_failover has the logic that will determine if
		 * some, all or none of the qsets need to move to secondary port
		 */
		ice_lag_aa_failover(lag, cdev_info, IIDC_RDMA_SECONDARY_PORT,
				    true);
		mutex_unlock(&pf->lag_mutex);
	}
#endif /* HAVE_NETDEV_UPPER_INFO */
	return 0;
}

/**
 * ice_free_rdma_qsets - Free leaf nodes for RDMA Qset
 * @cdev_info: aux driver that requested qsets to be freed
 * @qset: Resource to be freed
 */
static int
ice_free_rdma_qsets(struct iidc_core_dev_info *cdev_info,
		    struct iidc_rdma_qset_params *qset)
{
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	u16 vsi_id;
	int status;
	u32 teid;
	u16 q_id;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	dev = ice_pf_to_dev(pf);

	vsi_id = qset->vport_id;
	vsi = ice_find_vsi(pf, vsi_id);
	if (!vsi) {
		dev_err(dev, "RDMA Invalid VSI\n");
		return -EINVAL;
	}

	if (qset->vport_id != vsi_id) {
		dev_err(dev, "RDMA Invalid VSI ID\n");
		return -EINVAL;
	}
	q_id = qset->qs_handle;
	teid = qset->teid;

#ifdef HAVE_NETDEV_UPPER_INFO
	if (pf->lag && pf->lag->bonded) {
		mutex_lock(&pf->lag_mutex);

		if (cdev_info->rdma_active_port != pf->hw.port_info->lport &&
		    cdev_info->rdma_active_port != IIDC_RDMA_INVALID_PORT) {
			struct net_device *tmp_nd;

			rcu_read_lock();
			for_each_netdev_rcu(&init_net, tmp_nd) {
				struct ice_netdev_priv *tmp_ndp;
				struct ice_lag *tmp_lag;
				struct ice_vsi *tmp_vsi;
				struct ice_hw *tmp_hw;

				if (!netif_is_ice(tmp_nd))
					continue;

				tmp_ndp = netdev_priv(tmp_nd);
				tmp_vsi = tmp_ndp->vsi;
				tmp_lag = tmp_vsi->back->lag;
				tmp_hw = &tmp_vsi->back->hw;

				if (!tmp_lag->bonded ||
				    tmp_lag->bond_id != pf->lag->bond_id)
					continue;

				if (cdev_info->rdma_active_port ==
				    tmp_hw->port_info->lport)
					ice_lag_move_node_sync(tmp_hw, &pf->hw,
							       pf->vsi[0],
							       qset);
			}
			rcu_read_unlock();
		}
		mutex_unlock(&pf->lag_mutex);
	}

#endif /* HAVE_NETDEV_UPPER_INFO */
	status = ice_dis_vsi_rdma_qset(vsi->port_info, 1, &teid, &q_id);
	if (status)
		return -EINVAL;

#ifdef HAVE_NETDEV_UPPER_INFO
	if (pf->lag)
		memset(&pf->lag->rdma_qset[qset->tc], 0, sizeof(*qset));
#endif /* HAVE_NETDEV_UPPER_INFO */
	return 0;
}

#ifdef HAVE_NETDEV_UPPER_INFO
/**
 * ice_lag_aa_reclaim_nodes - ensure nodes back on primary for freeing
 * @cdev: aux device struct
 * @qset: resources to be moved
 */
void
ice_lag_aa_reclaim_nodes(struct iidc_core_dev_info *cdev,
			 struct iidc_rdma_multi_qset_params *qset)
{
	struct iidc_rdma_multi_qset_params *r_qsets;
	struct ice_pf *pf;

	if (cdev->rdma_ports[ICE_PRI_IDX] == IIDC_RDMA_INVALID_PORT ||
	    cdev->rdma_ports[ICE_SEC_IDX] == IIDC_RDMA_INVALID_PORT)
		return;

	pf = pci_get_drvdata(cdev->pdev);
	r_qsets = pf->lag->rdma_qsets;

	if (qset->teid[ICE_PRI_IDX] &&
	    r_qsets[qset->tc].qset_port[ICE_PRI_IDX] !=
	    IIDC_RDMA_PRIMARY_PORT &&
	    !ice_lag_move_node(pf->lag, cdev->rdma_ports[ICE_SEC_IDX],
			       cdev->rdma_ports[ICE_PRI_IDX], qset->tc,
			       qset->teid[ICE_PRI_IDX],
			       qset->qs_handle[ICE_PRI_IDX]))
		r_qsets[qset->tc].qset_port[ICE_PRI_IDX] =
			IIDC_RDMA_PRIMARY_PORT;

	if (qset->teid[ICE_SEC_IDX] &&
	    r_qsets[qset->tc].qset_port[ICE_SEC_IDX] !=
	    IIDC_RDMA_PRIMARY_PORT &&
	    !ice_lag_move_node(pf->lag, cdev->rdma_ports[ICE_SEC_IDX],
			       cdev->rdma_ports[ICE_PRI_IDX], qset->tc,
			       qset->teid[ICE_SEC_IDX],
			       qset->qs_handle[ICE_SEC_IDX]))
		r_qsets[qset->tc].qset_port[ICE_SEC_IDX] =
			IIDC_RDMA_PRIMARY_PORT;
}

#endif /* HAVE_NETDEV_UPPER_INFO */
/**
 * ice_free_rdma_multi_qsets - Free leaf nodes for RDMA multi_qsets
 * @cdev_info: struct for aux device freeing resources
 * @qset: resources to be freed
 */
static int
ice_free_rdma_multi_qsets(struct iidc_core_dev_info *cdev_info,
			  struct iidc_rdma_multi_qset_params *qset)
{
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	int status, i;
	u32 teid[2];
	u16 q_id[2];

	if (!cdev_info || !qset)
		return -EINVAL;

	if (qset->num > 2)
		return -EOPNOTSUPP;

	pf = pci_get_drvdata(cdev_info->pdev);
	dev = ice_pf_to_dev(pf);
	vsi = ice_find_vsi(pf, qset->vport_id);
	if (!vsi) {
		dev_err(dev, "RDMA INVALID VSI\n");
		return -EINVAL;
	}

	for (i = 0; i < qset->num; i++) {
		teid[i] = qset->teid[i];
		q_id[i] = qset->qs_handle[i];
	}

#ifdef HAVE_NETDEV_UPPER_INFO
	if (pf->lag && pf->lag->bonded && cdev_info->bond_aa) {
		mutex_lock(&pf->lag_mutex);
		ice_lag_aa_reclaim_nodes(cdev_info, qset);
		mutex_unlock(&pf->lag_mutex);
	}

#endif /* HAVE_NETDEV_UPPER_INFO */
	/* The FW AQ command cannot handle freeing multiple qsets at once,
	 * so break up the call to free qsets into separate calls
	 */
	for (i = 0; i < qset->num; i++) {
		status = ice_dis_vsi_rdma_qset(vsi->port_info, 1, &teid[i],
					       &q_id[i]);
		if (status)
			return status;
	}

#ifdef HAVE_NETDEV_UPPER_INFO
	if (pf->lag)
		memset(&pf->lag->rdma_qsets[qset->tc], 0, sizeof(*qset));

#endif /* HAVE_NETDEV_UPPER_INFO */
	return 0;
}

/**
 * ice_cdev_info_alloc_res - Allocate requested resources for aux driver
 * @cdev_info: struct for aux driver that is requesting resources
 * @qset: Resource to be allocated
 */
static int
ice_cdev_info_alloc_res(struct iidc_core_dev_info *cdev_info,
			struct iidc_rdma_qset_params *qset)
{
	struct ice_pf *pf;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EBUSY;

	return ice_alloc_rdma_qsets(cdev_info, qset);
}

/**
 * ice_cdev_info_alloc_multi_res - Allocate requested resources for aux driver
 * @cdev_info: struct for aux driver that is requesting resources
 * @qset: resource(s) to be allocated
 */
static int
ice_cdev_info_alloc_multi_res(struct iidc_core_dev_info *cdev_info,
			      struct iidc_rdma_multi_qset_params *qset)
{
	struct ice_pf *pf;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EBUSY;

	return ice_alloc_rdma_multi_qsets(cdev_info, qset);
}

/**
 * ice_cdev_info_free_res - Free resources associated with aux driver
 * @cdev_info: struct for aux driver that is requesting freeing of resources
 * @qset: Resource to be freed
 */
static int
ice_cdev_info_free_res(struct iidc_core_dev_info *cdev_info,
		       struct iidc_rdma_qset_params *qset)
{
	if (!cdev_info || !qset)
		return -EINVAL;

	return ice_free_rdma_qsets(cdev_info, qset);
}

/**
 * ice_cdev_info_free_multi_res - Free resources associated with aux driver
 * @cdev_info: struct for aux driver that is freeing resources
 * @qset: resource(s) to be freed
 */
static int
ice_cdev_info_free_multi_res(struct iidc_core_dev_info *cdev_info,
			     struct iidc_rdma_multi_qset_params *qset)
{
	if (!cdev_info || !qset)
		return -EINVAL;

	return ice_free_rdma_multi_qsets(cdev_info, qset);
}

/**
 * ice_cdev_info_request_reset - accept request from aux to perform a reset
 * @cdev_info: struct for aux driver that is requesting a reset
 * @reset_type: type of reset the aux is requesting
 */
static int
ice_cdev_info_request_reset(struct iidc_core_dev_info *cdev_info,
			    enum iidc_reset_type reset_type)
{
	enum ice_reset_req reset;
	struct ice_pf *pf;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);

	switch (reset_type) {
	case IIDC_PFR:
		reset = ICE_RESET_PFR;
		break;
	case IIDC_CORER:
		reset = ICE_RESET_CORER;
		break;
	case IIDC_GLOBR:
		reset = ICE_RESET_GLOBR;
		break;
	default:
		dev_err(ice_pf_to_dev(pf), "incorrect reset request from auxiliary driver\n");
		return -EINVAL;
	}

	return ice_schedule_reset(pf, reset);
}

/**
 * ice_cdev_info_update_vsi_filter - update main VSI filters for RDMA
 * @cdev_info: pointer to struct for aux device updating filters
 * @vsi_id: vsi HW idx to update filter on
 * @enable: bool whether to enable or disable filters
 */
static int
ice_cdev_info_update_vsi_filter(struct iidc_core_dev_info *cdev_info,
				u16 vsi_id, bool enable)
{
	struct ice_vsi *vsi;
	struct ice_pf *pf;
	int ret;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);

	vsi = ice_find_vsi(pf, vsi_id);
	if (!vsi)
		return -EINVAL;

	ret = ice_cfg_iwarp_fltr(&pf->hw, vsi->idx, enable);

	if (ret) {
		dev_err(ice_pf_to_dev(pf), "Failed to  %sable iWARP filtering\n",
			enable ? "en" : "dis");
	} else {
		if (enable)
			vsi->info.q_opt_flags |= ICE_AQ_VSI_Q_OPT_PE_FLTR_EN;
		else
			vsi->info.q_opt_flags &= ~ICE_AQ_VSI_Q_OPT_PE_FLTR_EN;
	}

	return ret;
}

/**
 * ice_cdev_info_vc_send - send a virt channel message from an aux driver
 * @cdev_info: pointer to cdev_info struct for aux driver
 * @vf_id: the VF ID of recipient of message
 * @msg: pointer to message contents
 * @len: len of message
 *
 * Note that the VF ID is absolute for RDMA operations, but a relative ID for
 * IPSEC operations.
 */
static int
ice_cdev_info_vc_send(struct iidc_core_dev_info *cdev_info, u32 vf_id,
		      u8 *msg, u16 len)
{
	struct ice_pf *pf;
	u32 rel_vf_id;
	int status;

	if (!cdev_info)
		return -EINVAL;
	if (!msg || !len)
		return -ENOMEM;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (len > ICE_AQ_MAX_BUF_LEN)
		return -EINVAL;

	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;

	switch (cdev_info->cdev_info_id) {
	case IIDC_RDMA_ID:
		/* The ID is absolute so it must be converted first */
		rel_vf_id = ice_rel_vf_id(&pf->hw, vf_id);

		if (!ice_is_valid_vf_id(pf, rel_vf_id))
			return -ENODEV;

		/* VIRTCHNL_OP_RDMA is being used for RoCEv2 msg also */
		status = ice_aq_send_msg_to_vf(&pf->hw, rel_vf_id,
					       VIRTCHNL_OP_RDMA, 0, msg, len,
					       NULL);
		break;
	default:
		dev_err(ice_pf_to_dev(pf), "Can't send message to VF, Aux not supported, %u\n",
			(u32)cdev_info->cdev_info_id);
		return -ENODEV;
	}

	if (status)
		dev_err(ice_pf_to_dev(pf), "Unable to send msg to VF, error %d\n",
			status);
	return status;
}

/**
 * ice_send_vf_reset_to_aux - send a VF reset notification to the aux driver
 * @cdev_info: pointer to the cdev_info object
 * @vf_id: VF ID to query
 *
 * Tell the RDMA auxiliary driver that a VF is resetting
 */
void ice_send_vf_reset_to_aux(struct iidc_core_dev_info *cdev_info, u16 vf_id)
{
	struct iidc_event *event;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return;
	set_bit(IIDC_EVENT_VF_RESET, event->type);
	event->info.vf_id = (u32)vf_id;
	ice_send_event_to_aux(cdev_info, event);
	kfree(event);
}

/**
 * ice_cdev_info_get_vf_port_info - get a VF's information
 * @cdev_info: pointer to the cdev_info object
 * @abs_vf_id: Absolute VF ID to query
 * @vf_port_info: structure to populate for the caller
 *
 * Allow the RDMA auxiliary driver to query a VF's information
 */
static int
ice_cdev_info_get_vf_port_info(struct iidc_core_dev_info *cdev_info,
			       u16 abs_vf_id,
			       struct iidc_vf_port_info *vf_port_info)
{
	struct ice_pf *pf;

	if (!cdev_info || !vf_port_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);

	return ice_get_vf_port_info(pf, ice_rel_vf_id(&pf->hw, abs_vf_id),
				    vf_port_info);
}

/**
 * ice_find_cdev_info_by_id - find cdev_info instance by its id
 * @pf: pointer to private board struct
 * @cdev_info_id: aux driver ID
 */
struct iidc_core_dev_info
*ice_find_cdev_info_by_id(struct ice_pf *pf, int cdev_info_id)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	unsigned int i;

	if (!pf->cdev_infos)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(ice_cdev_ids); i++) {
		cdev_info = pf->cdev_infos[i];
		if (cdev_info &&
		    cdev_info->cdev_info_id == cdev_info_id)
			break;
		cdev_info = NULL;
	}
	return cdev_info;
}

/**
 * ice_cdev_info_update_vsi - update the pf_vsi info in cdev_info struct
 * @cdev_info: pointer to cdev_info struct
 * @vsi: VSI to be updated
 */
void ice_cdev_info_update_vsi(struct iidc_core_dev_info *cdev_info,
			      struct ice_vsi *vsi)
{
	if (!cdev_info)
		return;

	cdev_info->vport_id = vsi->vsi_num;
}

/* Initialize the ice_ops struct, which is used in 'ice_init_aux_devices' */
static const struct iidc_core_ops iidc_ops = {
	.alloc_res			= ice_cdev_info_alloc_res,
	.free_res			= ice_cdev_info_free_res,
	.alloc_multi_res		= ice_cdev_info_alloc_multi_res,
	.free_multi_res			= ice_cdev_info_free_multi_res,
	.request_reset			= ice_cdev_info_request_reset,
	.update_vport_filter		= ice_cdev_info_update_vsi_filter,
	.get_vf_info			= ice_cdev_info_get_vf_port_info,
	.vc_send			= ice_cdev_info_vc_send,
	.ieps_entry			= ice_ieps_entry,

};

/**
 * ice_cdev_info_adev_release - function to be mapped to aux dev's release op
 * @dev: pointer to device to free
 */
static void ice_cdev_info_adev_release(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
}

/* ice_plug_aux_dev - allocate and register aux dev for cdev_info
 * @cdev_info: pointer to cdev_info struct
 * @name: name of aux dev
 *
 * The cdev_info must be setup before calling this function
 */
int ice_plug_aux_dev(struct iidc_core_dev_info *cdev_info, const char *name)
{
	struct iidc_auxiliary_dev *iadev;
	struct auxiliary_device *adev;
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	struct device *dev;
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
	struct ice_pf *pf;
	int ret;

	if (!cdev_info || !name)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!pf)
		return -EINVAL;
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	dev = &pf->pdev->dev;
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
	if (cdev_info->adev)
		return 0;

	/* if this PF does not support a technology that requires auxiliary
	 * devices, then exit gracefully
	 */
	if (!ice_is_aux_ena(pf))
		return 0;

	if (cdev_info->cdev_info_id == IIDC_RDMA_ID &&
	    !ice_is_rdma_ena(pf))
		return 0;
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE

	if (pf->hw.port_info->is_custom_tx_enabled &&
	    cdev_info->cdev_info_id == IIDC_RDMA_ID) {
		dev_err(dev, "Cannot enable feature RDMA because HQoS HW offload mode is currently enabled\n");
		return -EBUSY;
	}

	ice_tear_down_devlink_rate_tree(pf);
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev)
		return -ENOMEM;

	adev = &iadev->adev;
	mutex_lock(&pf->adev_mutex);
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;
	mutex_unlock(&pf->adev_mutex);

	cdev_info->msix_entries = ice_alloc_aux_vectors(pf,
							cdev_info->msix_count);

	adev->id = pf->aux_idx;
	adev->dev.release = ice_cdev_info_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;
	adev->name = name;

	ret = auxiliary_device_init(adev);
	if (ret) {
		kfree(iadev);
		return ret;
	}

	ret = auxiliary_device_add(adev);
	if (ret) {
		auxiliary_device_uninit(adev);
		return ret;
	}

	return ret;
}

/* ice_unplug_aux_dev - unregister and free aux dev
 * @cdev_info: pointer cdev_info struct
 */
void ice_unplug_aux_dev(struct iidc_core_dev_info *cdev_info)
{
	struct ice_pf *pf;

	if (!cdev_info)
		return;

	pf = pci_get_drvdata(cdev_info->pdev);

	/* if this aux dev has already been unplugged move on */
	mutex_lock(&pf->adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&pf->adev_mutex);
		return;
	}

	auxiliary_device_delete(cdev_info->adev);
	auxiliary_device_uninit(cdev_info->adev);
	cdev_info->adev = NULL;

	ice_free_aux_vectors(pf, cdev_info->msix_entries,
			     cdev_info->msix_count);
	mutex_unlock(&pf->adev_mutex);
}

/* ice_plug_aux_devs - allocate and register aux dev for cdev_info
 * @pf: pointer to pf struct
 */
int ice_plug_aux_devs(struct ice_pf *pf)
{
	int ret;
	u8 i;

	if (!pf->cdev_infos)
		return 0;

	for (i = 0; i < ARRAY_SIZE(ice_cdev_ids); i++) {
		const char *name;

		if (!pf->cdev_infos[i])
			continue;

		if (pf->cdev_infos[i]->cdev_info_id == IIDC_RDMA_ID) {
			if (pf->cdev_infos[i]->rdma_protocol ==
			    IIDC_RDMA_PROTOCOL_IWARP)
				name = IIDC_RDMA_IWARP_NAME;
			else
				name = IIDC_RDMA_ROCE_NAME;
		} else {
			name = ice_cdev_ids[i].name;
		}

		ret = ice_plug_aux_dev(pf->cdev_infos[i], name);
		if (ret)
			return ret;
	}

	return 0;
}

/* ice_unplug_aux_devs - unregister and free aux devs
 * @pf: pointer to pf struct
 */
void ice_unplug_aux_devs(struct ice_pf *pf)
{
	u8 i;

	if (!pf->cdev_infos)
		return;

	for (i = 0; i < ARRAY_SIZE(ice_cdev_ids); i++) {
		ice_unplug_aux_dev(pf->cdev_infos[i]);
	}
}

/**
 * ice_cdev_init_rdma_qos_info - initialize qos_info for RDMA aux
 * @pf: pointer to ice_pf
 * @qos_info: pointer to qos_info struct
 */
static void ice_cdev_init_rdma_qos_info(struct ice_pf *pf,
					struct iidc_qos_params *qos_info)
{
	int j;

	/* setup qos_info fields with defaults */
	qos_info->num_apps = 0;
	qos_info->num_tc = 1;

	for (j = 0; j < IIDC_MAX_USER_PRIORITY; j++)
		qos_info->up2tc[j] = 0;

	qos_info->tc_info[0].rel_bw = 100;
	for (j = 1; j < IEEE_8021QAZ_MAX_TCS; j++)
		qos_info->tc_info[j].rel_bw = 0;
	/* for DCB, override the qos_info defaults. */
	ice_setup_dcb_qos_info(pf, qos_info);

}

/**
 * ice_init_aux_devices - initializes cdev_info objects and aux devices
 * @pf: ptr to ice_pf
 */
int ice_init_aux_devices(struct ice_pf *pf)
{
	struct ice_vsi *vsi = pf->vsi[0];
	struct pci_dev *pdev = pf->pdev;
	struct device *dev = &pdev->dev;
	unsigned int i;

	/* This PFs auxiliary id value */
	pf->aux_idx = ida_alloc(&ice_cdev_info_ida, GFP_KERNEL);
	if (pf->aux_idx < 0) {
		dev_err(dev, "failed to allocate device ID for aux drvs\n");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(ice_cdev_ids); i++) {
		struct iidc_core_dev_info *cdev_info;

		/* structure layout needed for container_of's looks like:
		 * iidc_auxiliary_dev (container_of super-struct for adev)
		 * |--> auxiliary_device
		 * |--> *iidc_core_dev_info (pointer from cdev_info struct)
		 *
		 * The iidc_auxiliary_device has a lifespan as long as it
		 * is on the bus.  Once removed it will be freed and a new
		 * one allocated if needed to re-add.
		 *
		 * The iidc_core_dev_info is tied to the life of the PF, and
		 * will exist as long as the PF driver is loaded.  It will be
		 * freed in the remove flow for the PF driver.
		 */
		if (ice_cdev_ids[i].id == IIDC_RDMA_ID && !ice_is_rdma_ena(pf))
			continue;

		cdev_info = kzalloc(sizeof(*cdev_info), GFP_KERNEL);
		if (!cdev_info) {
			ida_simple_remove(&ice_cdev_info_ida, pf->aux_idx);
			pf->aux_idx = -1;
			return -ENOMEM;
		}

		pf->cdev_infos[i] = cdev_info;

		/* We only pass the lowest memory map here. */
		cdev_info->hw_addr = (u8 __iomem *)ice_get_hw_addr(&pf->hw, 0);
		cdev_info->ver.major = IIDC_MAJOR_VER;
		cdev_info->ver.minor = IIDC_MINOR_VER;
		cdev_info->cdev_info_id = ice_cdev_ids[i].id;
		cdev_info->pdev = pdev;
		/* Initialize ice_ops */
		cdev_info->ops = &iidc_ops;
		/* make sure peer specific resources such as msix_count and
		 * msix_entries are initialized
		 */
		switch (ice_cdev_ids[i].id) {

		case IIDC_RDMA_ID:
			if (!ice_is_rdma_ena(pf)) {
				pf->cdev_infos[i] = NULL;
				kfree(cdev_info);
				continue;
			}
			cdev_info->vport_id = vsi->vsi_num;
			cdev_info->netdev = vsi->netdev;
			cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_ROCEV2;
			cdev_info->rdma_caps.gen = IIDC_RDMA_GEN_2;
			cdev_info->ftype = IIDC_FUNCTION_TYPE_PF;
			cdev_info->cdev_info_id = IIDC_RDMA_ID;
			cdev_info->pf_id = pf->hw.pf_id;
#ifdef HAVE_NETDEV_UPPER_INFO
			cdev_info->rdma_active_port = IIDC_RDMA_INVALID_PORT;
			cdev_info->main_pf_port = pf->hw.port_info->lport;
			cdev_info->rdma_ports[ICE_PRI_IDX] =
				IIDC_RDMA_INVALID_PORT;
			cdev_info->rdma_ports[ICE_SEC_IDX] =
				IIDC_RDMA_INVALID_PORT;
			cdev_info->bond_aa = 0;
			cdev_info->rdma_port_bitmap = 0;
#endif /* HAVE_NETDEV_UPPER_INFO */
			ice_cdev_init_rdma_qos_info(pf, &cdev_info->qos_info);
			/* make sure peer specific resources such as msix_count
			 * and msix_entries are initialized
			 */
			cdev_info->msix_count = pf->msix.rdma;
			break;
		case IIDC_IEPS_ID:
			ice_cdev_init_ieps_info(&pf->hw, &cdev_info->nac_mode);
			break;
		default:
			break;
		}
	}
	set_bit(ICE_FLAG_PLUG_AUX_DEV, pf->flags);

	return 0;
}

/**
 * ice_is_rdma_aux_loaded - check if RDMA auxiliary driver is loaded
 * @pf: ptr to ice_pf
 */
bool ice_is_rdma_aux_loaded(struct ice_pf *pf)
{
	struct iidc_core_dev_info *rcdi;
	struct iidc_auxiliary_drv *iadrv;
	bool loaded = false;

	rcdi = ice_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (!rcdi)
		return false;

	mutex_lock(&pf->adev_mutex);
	if (!rcdi->adev)
		goto err;

	device_lock(&rcdi->adev->dev);
	iadrv = ice_get_auxiliary_drv(rcdi);
	loaded = iadrv ? true : false;
	device_unlock(&rcdi->adev->dev);

err:
	mutex_unlock(&pf->adev_mutex);

	dev_dbg(ice_pf_to_dev(pf), "RDMA Auxiliary Driver status: %s\n",
		loaded ? "loaded" : "not loaded");

	return loaded;
}

