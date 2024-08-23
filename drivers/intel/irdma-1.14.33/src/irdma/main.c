// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2023 Intel Corporation */
#include "main.h"
/* TODO: Adding this here is not ideal. Can we remove this warning now? */
#include "icrdma_hw.h"
#define DRV_VER_MAJOR 1
#define DRV_VER_MINOR 14
#define DRV_VER_BUILD 33
#define DRV_VER	__stringify(DRV_VER_MAJOR) "."		\
	__stringify(DRV_VER_MINOR) "." __stringify(DRV_VER_BUILD)

static u8 resource_profile;
module_param(resource_profile, byte, 0444);
MODULE_PARM_DESC(resource_profile, "Resource Profile: 0=PF only(default), 1=Weighted VF, 2=Even Distribution");

static unsigned short max_rdma_vfs = IRDMA_MAX_PE_ENA_VF_COUNT;
module_param(max_rdma_vfs, ushort, 0444);
MODULE_PARM_DESC(max_rdma_vfs, "Maximum VF count: 0-32, default=32");

bool irdma_upload_context;
module_param(irdma_upload_context, bool, 0644);
MODULE_PARM_DESC(irdma_upload_context, "Upload QP context, default=false");

static unsigned int limits_sel = 3;
module_param(limits_sel, uint, 0444);
MODULE_PARM_DESC(limits_sel, "Resource limits selector, Range: 0-7, default=3");

static unsigned int gen1_limits_sel = 1;
module_param(gen1_limits_sel, uint, 0444);
MODULE_PARM_DESC(gen1_limits_sel, "x722 resource limits selector, Range: 0-5, default=1");

static unsigned int roce_ena;
module_param(roce_ena, uint, 0444);
MODULE_PARM_DESC(roce_ena, "RoCE enable: 1=enable RoCEv2 on all ports (not supported on x722), 0=iWARP(default)");

static ulong roce_port_cfg;
module_param(roce_port_cfg, ulong, 0444);
MODULE_PARM_DESC(roce_port_cfg, "RoCEv2 per port enable: 1=port0 RoCEv2 all others iWARP, 2=port1 RoCEv2 etc. not supported on X722");

static bool en_rem_endpoint_trk;
module_param(en_rem_endpoint_trk, bool, 0444);
MODULE_PARM_DESC(en_rem_endpoint_trk, "Remote Endpoint Tracking: 1=enabled (not supported on x722), 0=disabled(default)");

static u8 fragment_count_limit = 6;
module_param(fragment_count_limit, byte, 0444);
MODULE_PARM_DESC(fragment_count_limit, "adjust maximum values for queue depth and inline data size, default=6, Range: 2-13");

/******************Advanced RoCEv2 congestion knobs***********************************************/
static bool dcqcn_enable;
module_param(dcqcn_enable, bool, 0444);
MODULE_PARM_DESC(dcqcn_enable, "enables DCQCN algorithm for RoCEv2 on all ports, default=false ");

static bool dcqcn_cc_cfg_valid;
module_param(dcqcn_cc_cfg_valid, bool, 0444);
MODULE_PARM_DESC(dcqcn_cc_cfg_valid, "set DCQCN parameters to be valid, default=false");

static u8 dcqcn_min_dec_factor = 1;
module_param(dcqcn_min_dec_factor, byte, 0444);
MODULE_PARM_DESC(dcqcn_min_dec_factor, "set minimum percentage factor by which tx rate can be changed for CNP, Range: 1-100, default=1");

static u8 dcqcn_min_rate_MBps;
module_param(dcqcn_min_rate_MBps, byte, 0444);
MODULE_PARM_DESC(dcqcn_min_rate_MBps, "set minimum rate limit value, in MBits per second, default=0");

static u8 dcqcn_F = 5;
module_param(dcqcn_F, byte, 0444);
MODULE_PARM_DESC(dcqcn_F, "set number of times to stay in each stage of bandwidth recovery, default=5");

static unsigned short dcqcn_T = 0x37;
module_param(dcqcn_T, ushort, 0444);
MODULE_PARM_DESC(dcqcn_T, "set number of usecs that should elapse before increasing the CWND in DCQCN mode, default=0x37");

static unsigned int dcqcn_B = 0x249f0;
module_param(dcqcn_B, uint, 0444);
MODULE_PARM_DESC(dcqcn_B, "The number of bytes to transmit before updating CWND in DCQCN mode. default=0x249f0");

static unsigned short dcqcn_rai_factor = 1;
module_param(dcqcn_rai_factor, ushort, 0444);
MODULE_PARM_DESC(dcqcn_rai_factor, "set number of MSS to add to the congestion window in additive increase mode, default=1");

static unsigned short dcqcn_hai_factor = 5;
module_param(dcqcn_hai_factor, ushort, 0444);
MODULE_PARM_DESC(dcqcn_hai_factor, "set number of MSS to add to the congestion window in hyperactive increase mode, default=5");

static unsigned int dcqcn_rreduce_mperiod = 50;
module_param(dcqcn_rreduce_mperiod, uint, 0444);
MODULE_PARM_DESC(dcqcn_rreduce_mperiod, "set minimum time between 2 consecutive rate reductions for a single flow, default=50");

/**************************************************************************************************/

MODULE_ALIAS("i40iw");
MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) Ethernet Protocol Driver for RDMA");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VER);

/**
 * set_protocol_used - set protocol_used against HW generation and roce_ena flag
 * @rf: RDMA PCI function
 * @roce_ena: RoCE enabled bit flag
 */
static inline void set_protocol_used(struct irdma_pci_f *rf, uint roce_ena)
{
	switch (rf->rdma_ver) {
	case IRDMA_GEN_3:
	case IRDMA_GEN_4:
		rf->protocol_used = IRDMA_ROCE_PROTOCOL_ONLY;
		break;
	case IRDMA_GEN_2:
		rf->protocol_used = roce_ena & BIT(PCI_FUNC(rf->pcidev->devfn)) ?
			IRDMA_ROCE_PROTOCOL_ONLY : IRDMA_IWARP_PROTOCOL_ONLY;

		break;
	case IRDMA_GEN_1:
		rf->protocol_used = IRDMA_IWARP_PROTOCOL_ONLY;
		break;
	}
}

/**
 * irdma_set_rf_user_cfg_params - Setup RF configurations from module parameters
 * @rf: RDMA PCI function
 */
void irdma_set_rf_user_cfg_params(struct irdma_pci_f *rf)
{
	if (limits_sel > 7)
		limits_sel = 7;

	if (gen1_limits_sel > 5)
		gen1_limits_sel = 5;

	rf->limits_sel = (rf->rdma_ver == IRDMA_GEN_1) ? gen1_limits_sel :
							 limits_sel;
	if (roce_ena)
		pr_warn_once("irdma: Because roce_ena is ENABLED, roce_port_cfg will be ignored.");
	set_protocol_used(rf, roce_ena ? 0xFFFFFFFF : roce_port_cfg);
	rf->rsrc_profile = (resource_profile < IRDMA_HMC_PROFILE_EQUAL) ?
			    (u8)resource_profile + IRDMA_HMC_PROFILE_DEFAULT :
			    IRDMA_HMC_PROFILE_DEFAULT;
	if (max_rdma_vfs > IRDMA_MAX_PE_ENA_VF_COUNT) {
		pr_warn_once("irdma: Requested VF count [%d] is above max supported. Setting to %d.",
			     max_rdma_vfs, IRDMA_MAX_PE_ENA_VF_COUNT);
		max_rdma_vfs = IRDMA_MAX_PE_ENA_VF_COUNT;
	}
	rf->max_rdma_vfs = (rf->rsrc_profile != IRDMA_HMC_PROFILE_DEFAULT) ?
				max_rdma_vfs : 0;
	rf->en_rem_endpoint_trk = en_rem_endpoint_trk;
	rf->fragcnt_limit = fragment_count_limit;
	if (rf->fragcnt_limit > 13 || rf->fragcnt_limit < 2) {
		rf->fragcnt_limit = 6;
		pr_warn_once("irdma: Requested [%d] fragment count limit out of range (2-13), setting to default=6.",
			     fragment_count_limit);
	}
	rf->dcqcn_ena = dcqcn_enable;

	/* Skip over all checking if no dcqcn */
	if (!dcqcn_enable)
		return;

	rf->dcqcn_params.cc_cfg_valid = dcqcn_cc_cfg_valid;
	rf->dcqcn_params.dcqcn_b = dcqcn_B;

#define DCQCN_B_MAX GENMASK(25, 0)
	if (rf->dcqcn_params.dcqcn_b > DCQCN_B_MAX) {
		rf->dcqcn_params.dcqcn_b = DCQCN_B_MAX;
		pr_warn_once("irdma: Requested [%d] dcqcn_b value too high, setting to %d.",
			     dcqcn_B, rf->dcqcn_params.dcqcn_b);
	}

#define DCQCN_F_MAX 8
	rf->dcqcn_params.dcqcn_f = dcqcn_F;
	if (dcqcn_F > DCQCN_F_MAX) {
		rf->dcqcn_params.dcqcn_f = DCQCN_F_MAX;
		pr_warn_once("irdma: Requested [%d] dcqcn_f value too high, setting to %d.",
			     dcqcn_F, DCQCN_F_MAX);
	}

	rf->dcqcn_params.dcqcn_t = dcqcn_T;
	rf->dcqcn_params.hai_factor = dcqcn_hai_factor;
	rf->dcqcn_params.min_dec_factor = dcqcn_min_dec_factor;
	if (dcqcn_min_dec_factor < 1 || dcqcn_min_dec_factor > 100) {
		rf->dcqcn_params.dcqcn_b = 1;
		pr_warn_once("irdma: Requested [%d] dcqcn_min_dec_factor out of range (1-100) , setting to default=1",
			     dcqcn_min_dec_factor);
	}

	rf->dcqcn_params.min_rate = dcqcn_min_rate_MBps;
	rf->dcqcn_params.rai_factor = dcqcn_rai_factor;
	rf->dcqcn_params.rreduce_mperiod = dcqcn_rreduce_mperiod;
}

static int irdma_init_dbg_and_configfs(void)
{
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	int ret;

#endif /* CONFIGFS_SUPPORT */
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_init();
#endif
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	ret = irdma_configfs_init();
	if (ret) {
		pr_err("Failed to register irdma to configfs subsystem\n");
#ifdef CONFIG_DEBUG_FS
		irdma_dbg_exit();
#endif
		return ret;
	}
#endif /* CONFIG_CONFIGFS_FS */
	return 0;
}

static inline void irdma_deinit_dbg_and_configfs(void)
{
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	irdma_configfs_exit();
#endif
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_exit();
#endif
}

static int irdma_vchnl_receive(struct iidc_core_dev_info *cdev_info, u32 vf_id,
			       u8 *msg, u16 len)
{
	struct irdma_device *iwdev = dev_get_drvdata(&cdev_info->adev->dev);
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;

	if (WARN_ON(!len || !msg))
		return -EINVAL;

	return dev->vchnl_if->vchnl_recv(dev, (u16)vf_id, msg, len);
}

int irdma_vchnl_send_pf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;

	cdev_info->ops->vc_send(cdev_info, vf_id, msg, len);

	return 0;
}

int irdma_vchnl_send_sync(struct irdma_sc_dev *dev, u8 *msg, u16 len,
			  u8 *recv_msg, u16 *recv_len)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;
	int ret;

	ret = cdev_info->ops->vc_send_sync(cdev_info, msg, len, recv_msg,
					   recv_len);
	if (ret == -ETIMEDOUT) {
		ibdev_err(&(dev_to_rf(dev)->iwdev->ibdev),
			  "Virtual channel Req <-> Resp completion timeout = 0x%x\n", ret);
		dev->vchnl_up = false;
	}

	return ret;
}

static struct irdma_vchnl_if irdma_vchnl_if_pf = {
	.vchnl_recv = irdma_vchnl_recv_pf,
};

static struct irdma_vchnl_if irdma_vchnl_if_req = {
	.vchnl_recv = irdma_vchnl_req_recv,
};

static void irdma_prep_tc_change(struct irdma_device *iwdev)
{
	iwdev->vsi.tc_change_pending = true;
	irdma_sc_suspend_resume_qps(&iwdev->vsi, IRDMA_OP_SUSPEND);

	/* Wait for all qp's to suspend */
	wait_event_timeout(iwdev->suspend_wq,
			   !atomic_read(&iwdev->vsi.qp_suspend_reqs),
			   msecs_to_jiffies(IRDMA_EVENT_TIMEOUT_MS));

	if (iwdev->rf->rdma_ver == IRDMA_GEN_2)
		irdma_ws_reset(&iwdev->vsi);
}

static void irdma_log_invalid_mtu(u16 mtu, struct irdma_sc_dev *dev)
{
	if (mtu < IRDMA_MIN_MTU_IPV4)
		ibdev_warn(to_ibdev(dev),
			   "MTU setting [%d] too low for RDMA traffic. Minimum MTU is 576 for IPv4\n",
			   mtu);
	else if (mtu < IRDMA_MIN_MTU_IPV6)
		ibdev_warn(to_ibdev(dev),
			   "MTU setting [%d] too low for RDMA traffic. Minimum MTU is 1280 for IPv6\\n",
			   mtu);
}

static void irdma_fill_qos_info(struct irdma_l2params *l2params,
				struct iidc_qos_params *qos_info)
{
	int i;

	l2params->num_tc = qos_info->num_tc;
	l2params->vsi_prio_type = qos_info->vport_priority_type;
	l2params->vsi_rel_bw = qos_info->vport_relative_bw;
	for (i = 0; i < l2params->num_tc; i++) {
		l2params->tc_info[i].egress_virt_up =
			qos_info->tc_info[i].egress_virt_up;
		l2params->tc_info[i].ingress_virt_up =
			qos_info->tc_info[i].ingress_virt_up;
		l2params->tc_info[i].prio_type = qos_info->tc_info[i].prio_type;
		l2params->tc_info[i].rel_bw = qos_info->tc_info[i].rel_bw;
		l2params->tc_info[i].tc_ctx = qos_info->tc_info[i].tc_ctx;
	}
	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		l2params->up2tc[i] = qos_info->up2tc[i];

	if (qos_info->pfc_mode == IIDC_DSCP_PFC_MODE) {
		l2params->dscp_mode = true;
		memcpy(l2params->dscp_map, qos_info->dscp_map,
		       sizeof(l2params->dscp_map));
	}
}

static void irdma_free_one_vf(struct irdma_vchnl_dev *vc_dev)
{
	struct irdma_sc_dev *dev = vc_dev->pf_dev;

	irdma_ws_reset(vc_dev->vf_vsi);
	irdma_del_hmc_objects(dev, &vc_dev->hmc_info, true, false,
			      dev->hw_attrs.uk_attrs.hw_rev);
	irdma_pf_put_vf_hmc_fcn(dev, vc_dev);
	irdma_put_vfdev(dev, vc_dev);
}

static void irdma_free_all_vf_rsrc(struct irdma_sc_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (dev->vc_dev[vf_idx])
			irdma_free_one_vf(dev->vc_dev[vf_idx]);
	}
}

/**
 * irdma_failover_start - Handle failover start
 * @iwdev: rdma device
 * @failing_port: Port number failing
 **/
static void irdma_failover_start(struct irdma_device *iwdev, u8 failing_port)
{
	iwdev->vsi.failover_pending = true;
	irdma_ws_failover_cmd(&iwdev->vsi, IRDMA_OP_WS_FAILOVER_START, failing_port, 0);
}

/**
 * irdma_failover_complete - Handle fail over complete
 * @iwdev: rdma device structure
 * @failing_port: Port number failing
 * @active_port: fail_over_port number
 **/
static void irdma_failover_complete(struct irdma_device *iwdev, u8 failing_port, u8 active_port)
{
	if (iwdev->vsi.lag_aa)
		irdma_ws_move_cmd(&iwdev->vsi);
	else
		irdma_ws_failover_cmd(&iwdev->vsi,
				      IRDMA_OP_WS_FAILOVER_COMPLETE,
				      failing_port, active_port);
	iwdev->vsi.failover_pending = false;
}

static void irdma_iidc_event_handler(struct iidc_core_dev_info *cdev_info, struct iidc_event *event)
{
	struct irdma_device *iwdev = dev_get_drvdata(&cdev_info->adev->dev);
	struct irdma_l2params l2params = {};

	if (!iwdev || iwdev->rf->reset)
		return;

	if (*event->type & BIT(IIDC_EVENT_AFTER_MTU_CHANGE)) {
		ibdev_dbg(&iwdev->ibdev, "CLNT: new MTU = %d\n", iwdev->netdev->mtu);
		if (iwdev->vsi.mtu != iwdev->netdev->mtu) {
			l2params.mtu = iwdev->netdev->mtu;
			l2params.mtu_changed = true;
			irdma_log_invalid_mtu(l2params.mtu, &iwdev->rf->sc_dev);
			if (iwdev->vsi.tc_change_pending) {
				iwdev->vsi.mtu_change_pending = true;
				iwdev->vsi.mtu = iwdev->netdev->mtu;
				return;
			}
			irdma_change_l2params(&iwdev->vsi, &l2params);
		}
	} else if (*event->type & BIT(IIDC_EVENT_VF_RESET)) {
		struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
		struct irdma_vchnl_dev *vc_dev =
			irdma_find_vc_dev(dev, event->info.vf_id);

		if (vc_dev)
			irdma_free_one_vf(vc_dev);
	} else if (*event->type & BIT(IIDC_EVENT_BEFORE_TC_CHANGE)) {
		if (iwdev->vsi.tc_change_pending)
			return;

		irdma_prep_tc_change(iwdev);
	} else if (*event->type & BIT(IIDC_EVENT_AFTER_TC_CHANGE)) {

		if (!iwdev->vsi.tc_change_pending)
			return;

		if (iwdev->vsi.mtu_change_pending) {
			iwdev->vsi.mtu_change_pending = false;
			l2params.mtu = iwdev->vsi.mtu;
			l2params.mtu_changed = true;
		}

		l2params.tc_changed = true;
		ibdev_dbg(&iwdev->ibdev, "CLNT: TC Change\n");

		irdma_fill_qos_info(&l2params, &cdev_info->qos_info);
		if (iwdev->rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY)
			iwdev->dcb_vlan_mode = l2params.num_tc > 1 && !l2params.dscp_mode;
		if (iwdev->rf->sc_dev.privileged)
			irdma_check_fc_for_tc_update(&iwdev->vsi, &l2params);
		irdma_change_l2params(&iwdev->vsi, &l2params);
	} else if (*event->type & BIT(IIDC_EVENT_FAILOVER_START) && iwdev->lag_mode) {
		ibdev_dbg(&iwdev->ibdev, "CLNT: IIDC_EVENT_FAILOVER_START: rdma_port = [%d, %d], bitmap = 0x%x, failing_port=%d\n",
			  cdev_info->rdma_ports[0], cdev_info->rdma_ports[1],
			  cdev_info->rdma_port_bitmap,
			  cdev_info->rdma_active_port);
		irdma_failover_start(iwdev, cdev_info->rdma_active_port);
	} else if (*event->type & BIT(IIDC_EVENT_FAILOVER_FINISH)) {
		if (iwdev->lag_mode == IRDMA_LAG_ACTIVE_ACTIVE) {
			ibdev_dbg(&iwdev->ibdev, "CLNT: IIDC_EVENT_FAILOVER_FINISH ports[1][2] = %d %d, bitmap = 0x%x\n",
				  cdev_info->rdma_ports[0],
				  cdev_info->rdma_ports[1],
				  cdev_info->rdma_port_bitmap);
			iwdev->vsi.lag_ports[0] = cdev_info->rdma_ports[0];
			iwdev->vsi.lag_ports[1] = cdev_info->rdma_ports[1];
			iwdev->vsi.lag_port_bitmap = cdev_info->rdma_port_bitmap;
		}
		irdma_failover_complete(iwdev, 0, cdev_info->rdma_active_port);
	} else if (*event->type & BIT(IIDC_EVENT_CRIT_ERR)) {
		ibdev_warn(&iwdev->ibdev, "ICE OICR event notification: oicr = 0x%08x\n",
			   event->info.reg);
		if (event->info.reg & IRDMAPFINT_OICR_PE_CRITERR_M) {
			u32 pe_criterr;

			pe_criterr = readl(iwdev->rf->sc_dev.hw_regs[IRDMA_GLPE_CRITERR]);
#define IRDMA_Q1_RESOURCE_ERR 0x0001024d
			if (pe_criterr != IRDMA_Q1_RESOURCE_ERR) {
				ibdev_err(&iwdev->ibdev, "critical PE Error, GLPE_CRITERR=0x%08x\n",
					  pe_criterr);
				iwdev->rf->reset = true;
			} else {
				ibdev_warn(&iwdev->ibdev, "Q1 Resource Check\n");
			}
		}
		if (event->info.reg & IRDMAPFINT_OICR_HMC_ERR_M) {
			ibdev_err(&iwdev->ibdev, "HMC Error\n");
			iwdev->rf->reset = true;
		}
		if (event->info.reg & IRDMAPFINT_OICR_PE_PUSH_M) {
			ibdev_err(&iwdev->ibdev, "PE Push Error\n");
			iwdev->rf->reset = true;
		}
		if (iwdev->rf->reset)
			iwdev->rf->gen_ops.request_reset(iwdev->rf);
	} else if (*event->type & BIT(IIDC_EVENT_WARN_RESET)) {
		iwdev->rf->reset = true;
	}
}

/**
 * irdma_request_reset - Request a reset
 * @rf: RDMA PCI function
 */
static void irdma_request_reset(struct irdma_pci_f *rf)
{
	struct iidc_core_dev_info *cdev_info = rf->cdev;

	ibdev_warn(&rf->iwdev->ibdev, "Requesting a reset\n");
	rf->sc_dev.vchnl_up = false;
	cdev_info->ops->request_reset(rf->cdev, IIDC_CORER);
}

/*
 * irdma_vchnl_req_aeq_vec_map_gen2 - Virt channel AEQ configuration
 * @dev: device
 * @idx: function relative MSI-X vector
 *
 * Call the IDC to send a AEQ configuration request.
 * Return 0 if successful, otherwise return error
 */
int irdma_vchnl_req_aeq_vec_map_gen2(struct irdma_sc_dev *dev, u32 idx)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;
	struct iidc_qvlist_info qvl_info = {};
	struct iidc_qv_info *qvinfo = &qvl_info.qv_info[0];

	qvl_info.num_vectors = 1;
	qvinfo->ceq_idx = IRDMA_Q_INVALID_IDX;
	qvinfo->v_idx = idx;
	qvinfo->itr_idx = IRDMA_IDX_ITR0;

	return cdev_info->ops->vc_queue_vec_map_unmap(cdev_info, &qvl_info,
						      true);
}

/*
 * irdma_vchnl_req_ceq_vec_map_gen2 - Virt channel CEQ configuration
 * @dev: shared code device
 * @ceq_id: function relative CEQ id
 * @idx: function relative MSI-X vector
 *
 * Call the IDC to send a CEQ configuration request.
 * Return 0 if successful, otherwise return error
 */
int irdma_vchnl_req_ceq_vec_map_gen2(struct irdma_sc_dev *dev, u16 ceq_id, u32 idx)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;
	struct iidc_qvlist_info qvl_info = {};
	struct iidc_qv_info *qvinfo = &qvl_info.qv_info[0];

	qvl_info.num_vectors = 1;
	qvinfo->aeq_idx = IRDMA_Q_INVALID_IDX;
	qvinfo->ceq_idx = ceq_id;
	qvinfo->v_idx = idx;
	qvinfo->itr_idx = IRDMA_IDX_ITR0;

	return cdev_info->ops->vc_queue_vec_map_unmap(cdev_info, &qvl_info,
						      true);
}

/*
 * irdma_lan_register_qset - Register qsets with LAN driver
 * @vsi: vsi structure
 * @tc_node1: List of Traffic class node ponters
 * @tc_node2: List of Traffic class node ponters
 */
static int irdma_lan_register_qset(struct irdma_sc_vsi *vsi,
				   struct irdma_ws_node *tc_node1,
				   struct irdma_ws_node *tc_node2)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;
	int ret;

	if (tc_node2) {
		struct iidc_rdma_multi_qset_params mqset = { };

		mqset.qs_handle[0] = tc_node1->qs_handle;
		mqset.qs_handle[1] = tc_node2->qs_handle;
		mqset.tc = tc_node2->traffic_class;
		mqset.vport_id = vsi->vsi_idx;
		mqset.num = 2;
		ret = cdev_info->ops->alloc_multi_res(cdev_info, &mqset);
		if (ret) {
			ibdev_warn(&iwdev->ibdev, "WS: LAN alloc_multi_res for rdma qset failed.\n");
			/* return ret; Ignore return code since RDMA still works when it fails, until ICE is debugged */
		}
		tc_node1->l2_sched_node_id = mqset.teid[0];
		tc_node2->l2_sched_node_id = mqset.teid[1];
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[0] = mqset.teid[0];
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[1] = mqset.teid[1];
	} else {
		struct iidc_rdma_qset_params qset = { };

		qset.qs_handle = tc_node1->qs_handle;
		qset.tc = tc_node1->traffic_class;
		qset.vport_id = vsi->vsi_idx;
		ret = cdev_info->ops->alloc_res(cdev_info, &qset);
		if (ret) {
			ibdev_warn(&iwdev->ibdev, "WS: LAN alloc_res for rdma qset failed.\n");
			//return ret;
		}

		tc_node1->l2_sched_node_id = qset.teid;
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[0] = qset.teid;
	}
	return 0;
}

/**
 * irdma_lan_unregister_qset - Unregister qsets with LAN driver
 * @vsi: vsi structure
 * @tc_node1: Traffic class node
 * @tc_node2: Traffic class node
 */
static void irdma_lan_unregister_qset(struct irdma_sc_vsi *vsi,
				      struct irdma_ws_node *tc_node1,
				      struct irdma_ws_node *tc_node2)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;

	if (vsi->lag_aa) {
		struct iidc_rdma_multi_qset_params mqset = { };

		mqset.qs_handle[0] = tc_node1->qs_handle;
		mqset.qs_handle[1] = tc_node2->qs_handle;
		mqset.tc = tc_node1->traffic_class; /* TC is the same for both nodes */
		mqset.vport_id = vsi->vsi_idx;
		mqset.num = 2;
		mqset.teid[0] = tc_node1->l2_sched_node_id;
		mqset.teid[1] = tc_node2->l2_sched_node_id;
		if (cdev_info->ops->free_multi_res(cdev_info, &mqset))
			ibdev_warn(&iwdev->ibdev, "WS: LAN free_res for rdma qset failed.\n");

	} else {
		struct iidc_rdma_qset_params qset = { };
		struct irdma_ws_node *tc_node = tc_node1 ? tc_node1 : tc_node2;

		qset.qs_handle = tc_node->qs_handle;
		qset.tc = tc_node->traffic_class;
		qset.vport_id = vsi->vsi_idx;
		qset.teid = tc_node->l2_sched_node_id;

		if (cdev_info->ops->free_res(cdev_info, &qset))
			ibdev_warn(&iwdev->ibdev, "WS: LAN free_res for rdma qset failed.\n");
	}
}

void irdma_cleanup_dead_qps(struct irdma_sc_vsi *vsi)
{
	struct irdma_sc_qp *qp = NULL;
	struct irdma_qp *iwqp;
	struct irdma_pci_f *rf;
	u8 i;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		qp = irdma_get_qp_from_list(&vsi->qos[i].qplist, qp);
		while (qp) {
			if (qp->qp_uk.qp_type == IRDMA_QP_TYPE_UDA) {
				qp = irdma_get_qp_from_list(&vsi->qos[i].qplist, qp);
				continue;
			}
			iwqp = qp->qp_uk.back_qp;
			rf = iwqp->iwdev->rf;
			dma_free_coherent(rf->hw.device,
					  iwqp->q2_ctx_mem.size,
					  iwqp->q2_ctx_mem.va,
					  iwqp->q2_ctx_mem.pa);
			dma_free_coherent(rf->hw.device,
					  iwqp->kqp.dma_mem.size,
					  iwqp->kqp.dma_mem.va,
					  iwqp->kqp.dma_mem.pa);
			kfree(iwqp->kqp.sq_wrid_mem);
			kfree(iwqp->kqp.rq_wrid_mem);
			qp = irdma_get_qp_from_list(&vsi->qos[i].qplist, qp);
			kfree(iwqp);
		}
	}
}

#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
static int irdma_remove(struct auxiliary_device *aux_dev)
#else /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
static void irdma_remove(struct auxiliary_device *aux_dev)
#endif /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct irdma_device *iwdev = auxiliary_get_drvdata(aux_dev);
	u8 rdma_ver = iwdev->rf->rdma_ver;

	if (rdma_ver == IRDMA_GEN_2 && !iwdev->rf->reset) {
		if (iwdev->rf->sc_dev.privileged)
			irdma_free_all_vf_rsrc(&iwdev->rf->sc_dev);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
		if (rdma_ver <= IRDMA_GEN_2 && iwdev->up_map_en) {
			struct irdma_up_info up_map_info = {};

			*((u64 *)up_map_info.map) = IRDMA_DEFAULT_UP_UP_MAP;
			up_map_info.use_cnp_up_override = false;
			up_map_info.cnp_up_override = 0;
			up_map_info.hmc_fcn_idx = iwdev->rf->sc_dev.hmc_fn_id;
			irdma_cqp_up_map_cmd(&iwdev->rf->sc_dev,
					     IRDMA_OP_SET_UP_MAP,
					     &up_map_info);
		}
#endif /* CONFIG_CONFIGFS_FS */
		if (iwdev->vsi.tc_change_pending) {
			iwdev->vsi.tc_change_pending = false;
			irdma_sc_suspend_resume_qps(&iwdev->vsi,
						    IRDMA_OP_RESUME);
		}

	}

	if (rdma_ver == IRDMA_GEN_2) {
		if (iwdev->rf->sc_dev.privileged)
			cdev_info->ops->update_vport_filter(
				cdev_info, iwdev->vsi_num, false);
	}

	irdma_ib_unregister_device(iwdev);
	irdma_unregister_notifiers(iwdev);
	irdma_deinit_device(iwdev);
	ib_dealloc_device(&iwdev->ibdev);
	pr_debug("INIT: Gen[%d] func[%d] device remove success\n",
		 rdma_ver, PCI_FUNC(cdev_info->pdev->devfn));
#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
	return 0;
#endif /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
}

static int irdma_vchnl_init(struct irdma_device *iwdev,
			    struct iidc_core_dev_info *cdev_info, u8 *rdma_ver)
{
	struct irdma_vchnl_init_info virt_info;
	struct irdma_pci_f *rf = iwdev->rf;
	u8 gen = cdev_info->rdma_caps.gen;
	int ret;

	rf->vchnl_wq = alloc_ordered_workqueue("irdma-virtchnl-wq", 0);
	if (!rf->vchnl_wq)
		return -ENOMEM;

	mutex_init(&rf->sc_dev.vchnl_mutex);

	virt_info.hw_rev = !gen ? IRDMA_GEN_2 : gen;
	virt_info.is_pf = !cdev_info->ftype;

	if (cdev_info->ftype) {
		virt_info.privileged = false;
	} else {
		if (cdev_info->ver.major >= 10 && cdev_info->ver.minor >= 2)
			virt_info.privileged = cdev_info->rdma_caps.gen == IRDMA_GEN_2;
		else
			virt_info.privileged = true;
	}
	virt_info.vchnl_if = virt_info.privileged ? &irdma_vchnl_if_pf :
						    &irdma_vchnl_if_req;
	virt_info.vchnl_wq = rf->vchnl_wq;
	ret = irdma_sc_vchnl_init(&rf->sc_dev, &virt_info);
	if (ret) {
		destroy_workqueue(rf->vchnl_wq);
		return ret;
	}

	*rdma_ver = rf->sc_dev.hw_attrs.uk_attrs.hw_rev;
	return 0;
}

static int irdma_fill_device_info(struct irdma_device *iwdev, struct iidc_core_dev_info *cdev_info)
{
	struct irdma_pci_f *rf = iwdev->rf;
	int err;

	rf->sc_dev.hw = &rf->hw;
	rf->iwdev = iwdev;
	rf->cdev = cdev_info;
	rf->hw.hw_addr = cdev_info->hw_addr;
	rf->pcidev = cdev_info->pdev;
	rf->hw.device = &rf->pcidev->dev;
	rf->ftype = cdev_info->ftype;
	rf->msix_count = cdev_info->msix_count;
	rf->msix_entries = cdev_info->msix_entries;

	err = irdma_vchnl_init(iwdev, cdev_info, &rf->rdma_ver);
	if (err)
		return err;

	if (!cdev_info->ftype && cdev_info->ver.major == 10 &&
	    cdev_info->ver.minor == 0 && rf->rdma_ver == IRDMA_GEN_2) {
		u32 val;
#define PF_FUNC_RID 0x0009E880
#define PF_FUNC_RID_FUNCTION_NUMBER GENMASK(2, 0)
		rf->hw.hw_addr = cdev_info->hw_addr;
		val = rd32(&rf->hw, PF_FUNC_RID);
		rf->pf_id = (u8)FIELD_GET(PF_FUNC_RID_FUNCTION_NUMBER, val);
	} else {
		rf->pf_id = cdev_info->pf_id;
	}

	if (!cdev_info->ftype && rf->rdma_ver == IRDMA_GEN_2) {
		rf->gen_ops.register_qset = irdma_lan_register_qset;
		rf->gen_ops.unregister_qset = irdma_lan_unregister_qset;
	}

	rf->default_vsi.vsi_idx = cdev_info->vport_id;
	rf->protocol_used = cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_ROCEV2 ?
			    IRDMA_ROCE_PROTOCOL_ONLY : IRDMA_IWARP_PROTOCOL_ONLY;
	rf->rsrc_profile = IRDMA_HMC_PROFILE_DEFAULT;
	if (rf->rdma_ver == IRDMA_GEN_2)
		rf->check_fc = irdma_check_fc_for_qp;
	rf->gen_ops.request_reset = irdma_request_reset;
	/* Can override limits_sel, protocol_used */
	irdma_set_rf_user_cfg_params(rf);

	mutex_init(&iwdev->ah_tbl_lock);

	rcu_read_lock();
	iwdev->netdev =  netdev_master_upper_dev_get_rcu(cdev_info->netdev);
	rcu_read_unlock();
	if (!iwdev->netdev || cdev_info->rdma_active_port ==
	    IIDC_RDMA_INVALID_PORT) {
		iwdev->netdev = cdev_info->netdev;
	} else {
		if (rf->protocol_used != IRDMA_ROCE_PROTOCOL_ONLY) {
                        dev_err(rf->hw.device, "LAG is only supported in RoCEv2 mode.\n");
                        return -EINVAL;
                }

		if (cdev_info->ver.major >= 10 && cdev_info->ver.minor >= 3)
			iwdev->lag_mode = cdev_info->bond_aa ?
					IRDMA_LAG_ACTIVE_ACTIVE :
					IRDMA_LAG_ACTIVE_PASSIVE;
		else
			iwdev->lag_mode = IRDMA_LAG_ACTIVE_PASSIVE;
	}
	iwdev->vsi_num = cdev_info->vport_id;
	iwdev->init_state = INITIAL_STATE;
	iwdev->roce_cwnd = IRDMA_ROCE_CWND_DEFAULT;
	iwdev->roce_ackcreds = IRDMA_ROCE_ACKCREDS_DEFAULT;
	iwdev->rcv_wnd = IRDMA_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = IRDMA_CM_DEFAULT_RCV_WND_SCALE;
	iwdev->push_mode = iwdev->rf->rdma_ver <= IRDMA_GEN_2 ? false : true;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	iwdev->iwarp_ecn_en = iwdev->rf->rdma_ver == IRDMA_GEN_2 ? true : false;
	iwdev->iwarp_rtomin = 5;
	iwdev->up_up_map = IRDMA_DEFAULT_UP_UP_MAP;
#endif
	if (iwdev->rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY) {
		iwdev->roce_rtomin = 5;
		iwdev->roce_dcqcn_en = iwdev->rf->dcqcn_ena;
		iwdev->roce_mode = true;
	}
	dev_info(rf->hw.device, "%s: iwdev->lag_mode = %d\n", __func__,
		 iwdev->lag_mode);
	return 0;
}

static int irdma_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct irdma_device *iwdev;
	struct irdma_pci_f *rf;
	struct irdma_l2params l2params = {};
	int err;
	struct irdma_handler *hdl;

	if (cdev_info->ver.major != IIDC_MAJOR_VER) {
		pr_err("version mismatch:\n");
		pr_err("expected major ver %d, caller specified major ver %d\n",
		       IIDC_MAJOR_VER, cdev_info->ver.major);
		pr_err("expected minor ver %d, caller specified minor ver %d\n",
		       IIDC_MINOR_VER, cdev_info->ver.minor);
		return -EINVAL;
	}
	if (cdev_info->ver.minor != IIDC_MINOR_VER)
		pr_info("probe: minor version mismatch: expected %0d.%0d caller specified %0d.%0d\n",
			IIDC_MAJOR_VER, IIDC_MINOR_VER,
			cdev_info->ver.major, cdev_info->ver.minor);
	pr_info("probe: cdev_info=%p, cdev_info->dev.aux_dev.bus->number=%d, cdev_info->rdma_active_port=0x%x netdev=%s\n",
		cdev_info, cdev_info->pdev->bus->number, cdev_info->rdma_active_port,
		netdev_name(cdev_info->netdev));
	iwdev = ib_alloc_device(irdma_device, ibdev);
	if (!iwdev)
		return -ENOMEM;
	iwdev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!iwdev->rf) {
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	err = irdma_fill_device_info(iwdev, cdev_info);
	if (err)
		goto err_fill_devinfo;
	rf = iwdev->rf;
	iwdev->aux_dev = aux_dev;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl)
		goto err_hdl;

	hdl->iwdev = iwdev;
	iwdev->hdl = hdl;
	err = irdma_ctrl_init_hw(rf);
	if (err)
		goto err_ctrl_init;

	if (rf->rdma_ver == IRDMA_GEN_2) {
		if (irdma_set_attr_from_fragcnt(&rf->sc_dev, rf->fragcnt_limit))
			dev_warn(rf->hw.device,
				 "device limit update failed for fragment count %d\n",
				 rf->fragcnt_limit);
	}
	l2params.mtu = iwdev->netdev->mtu;
	irdma_fill_qos_info(&l2params, &cdev_info->qos_info);
	if (rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY)
		iwdev->dcb_vlan_mode = l2params.num_tc > 1 && !l2params.dscp_mode;
	err = irdma_rt_init_hw(iwdev, &l2params);
	if (err)
		goto err_rt_init;

	if (iwdev->lag_mode == IRDMA_LAG_ACTIVE_ACTIVE) {
		dev_info(rf->hw.device,
			 "%s: cdev_info->rdma_ports[] = %d %d, rdma_port_bitmap = 0x%x\n",
			 __func__, cdev_info->rdma_ports[0],
			 cdev_info->rdma_ports[1], cdev_info->rdma_port_bitmap);
		iwdev->vsi.lag_ports[0] = cdev_info->rdma_ports[0];
		iwdev->vsi.lag_ports[1] = cdev_info->rdma_ports[1];
		iwdev->vsi.lag_port_bitmap = cdev_info->rdma_port_bitmap;
	}
	err = irdma_register_notifiers(iwdev);
	if (err)
		goto err_notifier_reg;
	irdma_add_handler(hdl);
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_pf_init(hdl);
#endif

	err = irdma_ib_register_device(iwdev);
	if (err)
		goto err_ibreg;

	if (rf->rdma_ver == IRDMA_GEN_2) {
		if (rf->sc_dev.privileged)
			cdev_info->ops->update_vport_filter(
				cdev_info, iwdev->vsi_num, true);
	}

	ibdev_dbg(&iwdev->ibdev, "INIT: Gen[%d] PF[%d] device probe success\n",
		  rf->rdma_ver, PCI_FUNC(rf->pcidev->devfn));

	auxiliary_set_drvdata(aux_dev, iwdev);

	return 0;

err_ibreg:
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_pf_exit(iwdev->hdl);
#endif
	irdma_del_handler(iwdev->hdl);
	irdma_unregister_notifiers(iwdev);
err_notifier_reg:
	irdma_rt_deinit_hw(iwdev);
err_rt_init:
	irdma_ctrl_deinit_hw(rf);
err_ctrl_init:
	kfree(hdl);
err_hdl:
	destroy_workqueue(rf->vchnl_wq);
err_fill_devinfo:
	kfree(iwdev->rf);
	ib_dealloc_device(&iwdev->ibdev);

	return err;
}

static const struct auxiliary_device_id irdma_auxiliary_id_table[] = {
	{.name = "ice.iwarp", },
	{.name = "ice.roce", },
	{.name = "idpf.roce", },
	{.name = "iavf.iwarp", },
	{.name = "iavf.roce", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, irdma_auxiliary_id_table);

static struct iidc_auxiliary_drv irdma_auxiliary_drv = {
	.adrv = {
	    .id_table = irdma_auxiliary_id_table,
	    .probe = irdma_probe,
	    .remove = irdma_remove,
	},
	.event_handler = irdma_iidc_event_handler,
	.vc_receive = irdma_vchnl_receive,
};

static int __init irdma_init_module(void)
{
	int ret;

	pr_info("irdma driver version: %d.%d.%d\n", DRV_VER_MAJOR,
		DRV_VER_MINOR, DRV_VER_BUILD);
	ret = irdma_init_dbg_and_configfs();
	if (ret)
		return ret;

	ret = auxiliary_driver_register(&i40iw_auxiliary_drv);
	if (ret) {
		pr_err("Failed i40iw(gen_1) auxiliary_driver_register() ret=%d\n",
		       ret);
		irdma_deinit_dbg_and_configfs();
		return ret;
	}

	ret = auxiliary_driver_register(&irdma_auxiliary_drv.adrv);
	if (ret) {
		auxiliary_driver_unregister(&i40iw_auxiliary_drv);
		pr_err("Failed irdma auxiliary_driver_register() ret=%d\n",
		       ret);
		irdma_deinit_dbg_and_configfs();
		return ret;
	}

	return 0;
}

static void __exit irdma_exit_module(void)
{
	auxiliary_driver_unregister(&irdma_auxiliary_drv.adrv);
	auxiliary_driver_unregister(&i40iw_auxiliary_drv);
	irdma_deinit_dbg_and_configfs();
}

module_init(irdma_init_module);
module_exit(irdma_exit_module);
