/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#include "iavf.h"
#include "iavf_prototype.h"
#include "iavf_idc.h"

/**
 * iavf_send_pf_msg
 * @adapter: adapter structure
 * @op: virtual channel opcode
 * @msg: pointer to message buffer
 * @len: message length
 *
 * Send message to PF and print status if failure.
 **/
static int iavf_send_pf_msg(struct iavf_adapter *adapter,
			    enum virtchnl_ops op, u8 *msg, u16 len)
{
	struct iavf_hw *hw = &adapter->hw;
	enum iavf_status status;

	if (adapter->flags & IAVF_FLAG_PF_COMMS_FAILED)
		return 0; /* nothing to see here, move along */

	status = iavf_aq_send_msg_to_pf(hw, op, VIRTCHNL_STATUS_SUCCESS, msg, len,
				     NULL);
	if (status)
		dev_dbg(&adapter->pdev->dev, "Unable to send opcode %d to PF, status %s, aq_err %s\n",
			op, iavf_stat_str(hw, status),
			iavf_aq_str(hw, hw->aq.asq_last_status));
	return iavf_status_to_errno(status);
}

/**
 * iavf_send_api_ver
 * @adapter: adapter structure
 *
 * Send API version admin queue message to the PF. The reply is not checked
 * in this function. Returns 0 if the message was successfully
 * sent, or one of the IAVF_ADMIN_QUEUE_ERROR_ statuses if not.
 **/
int iavf_send_api_ver(struct iavf_adapter *adapter)
{
	struct virtchnl_version_info vvi;

	vvi.major = VIRTCHNL_VERSION_MAJOR;
	vvi.minor = VIRTCHNL_VERSION_MINOR;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_VERSION, (u8 *)&vvi,
				sizeof(vvi));
}

/**
 * iavf_poll_virtchnl_msg - poll for virtchnl msg matching the requested_op
 * @hw: HW configuration structure
 * @event: event to populate on success
 * @op_to_poll: requested virtchnl op to poll for
 *
 * Returns 0 if a message of the correct opcode is in the queue. Returns
 * -EALREADY if no message matching the op code is waiting. Returns an error
 *  code for other failures.
 */
static int
iavf_poll_virtchnl_msg(struct iavf_hw *hw, struct iavf_arq_event_info *event,
		       enum virtchnl_ops op_to_poll)
{
	enum virtchnl_ops received_op;
	enum iavf_status status;
	u32 v_retval;

	while (1) {
		/* When the AQ is empty, iavf_clean_arq_element will return
		 * IAVF_ERR_AQ_NO_WORK and this loop will terminate. Callers
		 * which want to wait until a new message is received should
		 * check for -EALREADY and repeat polling attempts.
		 */
		status = iavf_clean_arq_element(hw, event, NULL);
		if (status)
			return iavf_status_to_errno(status);
		received_op =
		    (enum virtchnl_ops)le32_to_cpu(event->desc.cookie_high);
		if (op_to_poll == received_op)
			break;
	}

	v_retval = le32_to_cpu(event->desc.cookie_low);
	return virtchnl_status_to_errno((enum virtchnl_status_code)v_retval);
}

/**
 * iavf_verify_api_ver
 * @adapter: adapter structure
 *
 * Compare API versions with the PF. Must be called after admin queue is
 * initialized. Returns 0 if API versions match, -EIO if they do not,
 * IAVF_ERR_ADMIN_QUEUE_NO_WORK if the admin queue is empty, and any errors
 * from the firmware are propagated.
 **/
int iavf_verify_api_ver(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;

	event.buf_len = IAVF_MAX_AQ_BUF_SIZE;
	event.msg_buf = kzalloc(IAVF_MAX_AQ_BUF_SIZE, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event, VIRTCHNL_OP_VERSION);
	if (!err) {
		struct virtchnl_version_info *pf_vvi =
			(struct virtchnl_version_info *)event.msg_buf;

		adapter->pf_version = *pf_vvi;

		if ((pf_vvi->major > VIRTCHNL_VERSION_MAJOR) ||
		    ((pf_vvi->major == VIRTCHNL_VERSION_MAJOR) &&
		     (pf_vvi->minor > VIRTCHNL_VERSION_MINOR)))
			err = -EIO;
	}

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

/**
 * iavf_send_vf_config_msg
 * @adapter: adapter structure
 *
 * Send VF configuration request admin queue message to the PF. The reply
 * is not checked in this function. Returns 0 if the message was
 * successfully sent, or one of the IAVF_ADMIN_QUEUE_ERROR_ statuses if not.
 **/
int iavf_send_vf_config_msg(struct iavf_adapter *adapter)
{
	u32 caps;

	caps = VIRTCHNL_VF_OFFLOAD_L2 |
	       VIRTCHNL_VF_OFFLOAD_RSS_PF |
	       VIRTCHNL_VF_OFFLOAD_RSS_AQ |
	       VIRTCHNL_VF_OFFLOAD_RSS_REG |
	       VIRTCHNL_VF_OFFLOAD_VLAN |
	       VIRTCHNL_VF_OFFLOAD_WB_ON_ITR |
	       VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2 |
	       VIRTCHNL_VF_OFFLOAD_ENCAP |
	       VIRTCHNL_VF_OFFLOAD_VLAN_V2 |
	       VIRTCHNL_VF_LARGE_NUM_QPAIRS |
	       VIRTCHNL_VF_OFFLOAD_CRC |
	       VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC |
	       VIRTCHNL_VF_OFFLOAD_REQ_QUEUES |
	       VIRTCHNL_VF_CAP_PTP |
#ifdef __TC_MQPRIO_MODE_MAX
	       VIRTCHNL_VF_OFFLOAD_ADQ |
	       VIRTCHNL_VF_OFFLOAD_ADQ_V2 |
#endif /* __TC_MQPRIO_MODE_MAX */
	       VIRTCHNL_VF_OFFLOAD_USO |
	       VIRTCHNL_VF_CAP_RDMA |
#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
	       VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM |
	       VIRTCHNL_VF_CAP_ADV_LINK_SPEED;
#else
	       VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */

	adapter->current_op = VIRTCHNL_OP_GET_VF_RESOURCES;
	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_CONFIG;
	if (PF_IS_V11(adapter))
		return iavf_send_pf_msg(adapter,
					  VIRTCHNL_OP_GET_VF_RESOURCES,
					  (u8 *)&caps, sizeof(caps));
	else
		return iavf_send_pf_msg(adapter,
					  VIRTCHNL_OP_GET_VF_RESOURCES,
					  NULL, 0);
}

int iavf_send_vf_offload_vlan_v2_msg(struct iavf_adapter *adapter)
{
	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS;

	if (!VLAN_V2_ALLOWED(adapter))
		return -EOPNOTSUPP;

	adapter->current_op = VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS,
				NULL, 0);
}

int iavf_send_vf_supported_rxdids_msg(struct iavf_adapter *adapter)
{
	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_SUPPORTED_RXDIDS;

	if (!RXDID_ALLOWED(adapter))
		return -EOPNOTSUPP;

	adapter->current_op = VIRTCHNL_OP_GET_SUPPORTED_RXDIDS;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
				NULL, 0);
}

/**
 * iavf_send_vf_ptp_caps_msg - Send request for PTP capabilities
 * @adapter: private adapter structure
 *
 * Send the VIRTCHNL_OP_1588_PTP_GET_CAPS command to the PF to request the PTP
 * capabilities available to this device. This includes the following
 * potential access:
 *
 * * READ_PHC - access to read the PTP hardware clock time
 * * WRITE_PHC - access to control the PHC time via adjustments
 * * TX_TSTAMP - access to request up to one transmit timestamp at a time
 * * RX_TSTAMP - access to request Rx timestamps on all received packets
 * * PHC_REGS - direct access to the clock time registers for reading PHC
 *
 * The PF will reply with the same opcode a filled out copy of the
 * virtchnl_ptp_caps structure which defines the specifics of which features
 * are accessible to this device.
 */
int iavf_send_vf_ptp_caps_msg(struct iavf_adapter *adapter)
{
	struct virtchnl_ptp_caps hw_caps = {};

	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_PTP_CAPS;

	if (!PTP_ALLOWED(adapter))
		return -EOPNOTSUPP;

	hw_caps.caps = (VIRTCHNL_1588_PTP_CAP_READ_PHC |
			VIRTCHNL_1588_PTP_CAP_WRITE_PHC |
			VIRTCHNL_1588_PTP_CAP_TX_TSTAMP |
			VIRTCHNL_1588_PTP_CAP_RX_TSTAMP |
			VIRTCHNL_1588_PTP_CAP_PHC_REGS |
			VIRTCHNL_1588_PTP_CAP_PIN_CFG);
	hw_caps.caps |=	VIRTCHNL_1588_PTP_CAP_SYNCE;
	hw_caps.caps |= VIRTCHNL_1588_PTP_CAP_GNSS;

	adapter->current_op = VIRTCHNL_OP_1588_PTP_GET_CAPS;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_1588_PTP_GET_CAPS,
				(u8 *)&hw_caps, sizeof(hw_caps));
}

/**
 * iavf_send_vf_ptp_pin_cfgs_msg - Send request for PTP pin configuration
 * @adapter: private adapter structure
 *
 * Send the VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS command to the PF to request
 * extra pin configuration information.
 *
 * The PF will reply with the same opcode a filled out copy of the
 * virtchnl_phc_get_pins structure which defines the specifics of the pin
 * configuration provided to this VF.
 */
int iavf_send_vf_ptp_pin_cfgs_msg(struct iavf_adapter *adapter)
{
	if (!PTP_ALLOWED(adapter) ||
	    !iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PIN_CFG))
		return -EOPNOTSUPP;

	adapter->current_op = VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS,
				NULL, 0);
}

/**
 * iavf_send_max_rss_qregion - send request for the max RSS queue region
 * @adapter: private adapter structure
 *
 * Sends th VIRTCHNL_OP_GET_MAX_RSS_QREGION command to request information
 * about the permissible RSS queues.
 */
int iavf_send_max_rss_qregion(struct iavf_adapter *adapter)
{
	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_MAX_RSS_QREGION;

	if (!LARGE_NUM_QPAIRS_SUPPORT(adapter))
		return -EOPNOTSUPP;

	iavf_send_pf_msg(adapter, VIRTCHNL_OP_GET_MAX_RSS_QREGION, NULL, 0);
	return 0;
}

/**
 * iavf_send_vf_synce_hw_info_msg - Send request for HW Info
 * @adapter: private adapter structure
 *
 * Send the VIRTCHNL_OP_SYNCE_GET_HW_INFO command to the PF to request
 * extra pin configuration information.
 *
 * The PF will reply with the same opcode a filled out copy of the
 * virtchnl_synce_get_hw_info structure which defines the specifics of
 * hw info provided to this VF.
 */
int iavf_send_vf_synce_hw_info_msg(struct iavf_adapter *adapter)
{
	adapter->current_op = VIRTCHNL_OP_SYNCE_GET_HW_INFO;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_SYNCE_GET_HW_INFO,
				NULL, 0);
}

/**
 * iavf_send_vf_synce_cgu_info_msg - Send request for cgu Info
 * @adapter: private adapter structure
 *
 * Send the VIRTCHNL_OP_SYNCE_GET_CGU_INFO command to the PF to request
 * cgu information.
 *
 * The PF will reply with the same opcode a filled out copy of the
 * virtchnl_synce_get_cgu_info structure which defines the specifics of
 * hw info provided to this VF.
 */
int iavf_send_vf_synce_cgu_info_msg(struct iavf_adapter *adapter)
{
	adapter->current_op = VIRTCHNL_OP_SYNCE_GET_CGU_INFO;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_SYNCE_GET_CGU_INFO,
				NULL, 0);
}

/**
 * iavf_send_vf_synce_cgu_abilities_msg - Send request for cgu capabilities
 * @adapter: private adapter structure
 *
 * Send the VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES command to the PF to request
 * cgu capabilities.
 *
 * The PF will reply with the same opcode a filled out copy of the
 * virtchnl_synce_get_cgu_abilities structure which defines the specifics of
 * hw info provided to this VF.
 */
int iavf_send_vf_synce_cgu_abilities_msg(struct iavf_adapter *adapter)
{
	adapter->current_op = VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES;

	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES,
				NULL, 0);
}

/**
 * iavf_validate_num_queues
 * @adapter: adapter structure
 *
 * Validate that the number of queues the PF has sent in
 * VIRTCHNL_OP_GET_VF_RESOURCES is not larger than the VF can handle.
 **/
static void iavf_validate_num_queues(struct iavf_adapter *adapter)
{
	/* When ADQ is enabled PF allocates 16 queues to VF but enables only
	 * the specified number of queues it's been requested for (as per TC
	 * info). So this check should be skipped when ADQ is enabled.
	 */
	if (iavf_is_adq_enabled(adapter))
		return;

	if (adapter->vf_res->num_queue_pairs > IAVF_MAX_REQ_QUEUES) {
		struct virtchnl_vsi_resource *vsi_res;
		int i;

		dev_info(&adapter->pdev->dev, "Received %d queues, but can only have a max of %d\n",
			 adapter->vf_res->num_queue_pairs,
			 IAVF_MAX_REQ_QUEUES);
		dev_info(&adapter->pdev->dev, "Fixing by reducing queues to %d\n",
			 IAVF_MAX_REQ_QUEUES);
		adapter->vf_res->num_queue_pairs = IAVF_MAX_REQ_QUEUES;
		for (i = 0; i < adapter->vf_res->num_vsis; i++) {
			vsi_res = &adapter->vf_res->vsi_res[i];
			vsi_res->num_queue_pairs = IAVF_MAX_REQ_QUEUES;
		}
	}
}

/**
 * iavf_get_vf_config
 * @adapter: private adapter structure
 *
 * Get VF configuration from PF and populate hw structure. Must be called after
 * admin queue is initialized. Busy waits until response is received from PF,
 * with maximum timeout. Response from PF is returned in the buffer for further
 * processing by the caller.
 **/
int iavf_get_vf_config(struct iavf_adapter *adapter)
{
	struct iavf_hw *hw = &adapter->hw;
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	len = sizeof(struct virtchnl_vf_resource) +
		IAVF_MAX_VF_VSI * sizeof(struct virtchnl_vsi_resource);
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(hw, &event, VIRTCHNL_OP_GET_VF_RESOURCES);
	memcpy(adapter->vf_res, event.msg_buf, min(event.msg_len, len));

	/* some PFs send more queues than we should have so validate that
	 * we aren't getting too many queues
	 */
	if (!err)
		iavf_validate_num_queues(adapter);
	iavf_vf_parse_hw_config(hw, adapter->vf_res);

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int iavf_get_vf_vlan_v2_caps(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	len = sizeof(struct virtchnl_vlan_caps);
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS);
	if (!err)
		memcpy(&adapter->vlan_v2_caps, event.msg_buf,
		       min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int iavf_get_vf_supported_rxdids(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	len = sizeof(struct virtchnl_supported_rxdids);
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_GET_SUPPORTED_RXDIDS);
	if (!err)
		memcpy(&adapter->supported_rxdids, event.msg_buf,
		       min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int iavf_get_max_rss_qregion(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	len = sizeof(struct virtchnl_max_rss_qregion);
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_GET_MAX_RSS_QREGION);
	if (!err)
		memcpy(&adapter->max_rss_qregion, event.msg_buf,
		       min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int iavf_get_vf_ptp_caps(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	len = sizeof(struct virtchnl_ptp_caps);
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_1588_PTP_GET_CAPS);
	if (!err)
		memcpy(&adapter->ptp.hw_caps, event.msg_buf,
		       min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)

int iavf_get_vf_ptp_pin_cfgs(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	/* The message from the PF can be variable sized. Use the maximum
	 * expected size of 4Kb to allow the variable size to be received.
	 */
	len = IAVF_MAX_AQ_BUF_SIZE;
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS);
	if (!err)
		iavf_virtchnl_ptp_get_pin_cfgs(adapter, event.msg_buf,
					       min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */

/**
 * iavf_get_synce_hw_info
 * @adapter: adapter structure
 *
 * Get SyncE HW info from PF
 **/
int iavf_get_synce_hw_info(struct iavf_adapter *adapter)
{
	struct iavf_arq_event_info event;
	int err;
	u16 len;

	/* The message from the PF can be variable sized. Use the maximum
	 * expected size of 4Kb to allow the variable size to be received.
	 */
	len = IAVF_MAX_AQ_BUF_SIZE;
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	err = iavf_poll_virtchnl_msg(&adapter->hw, &event,
				     VIRTCHNL_OP_SYNCE_GET_HW_INFO);
	if (!err)
		iavf_virtchnl_synce_get_hw_info(adapter, event.msg_buf,
						min(event.msg_len, len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

/**
 * iavf_configure_queues
 * @adapter: adapter structure
 *
 * Request that the PF set up our (previously allocated) queues.
 **/
void iavf_configure_queues(struct iavf_adapter *adapter)
{
	struct virtchnl_vsi_queue_config_info *vqci;
	struct virtchnl_queue_pair_info *vqpi;
	int i, len, pairs, max_pairs, rem, last;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot configure queues, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_CONFIG_VSI_QUEUES;

	max_pairs = (IAVF_MAX_AQ_BUF_SIZE -
			sizeof(struct virtchnl_vsi_queue_config_info)) /
			sizeof(struct virtchnl_queue_pair_info);

	rem = adapter->num_active_queues;
	last = 0;
	while (rem > 0) {
		pairs = min(max_pairs, rem);
		len = sizeof(struct virtchnl_vsi_queue_config_info) +
			       (sizeof(struct virtchnl_queue_pair_info) * pairs);
		vqci = kzalloc(len, GFP_KERNEL);
		if (!vqci)
			return;

		vqci->vsi_id = adapter->vsi_res->vsi_id;
		vqci->num_queue_pairs = pairs;
		vqpi = vqci->qpair;

		for (i = last; i < last + pairs; i++) {
			vqpi->txq.vsi_id = vqci->vsi_id;
			vqpi->txq.queue_id = i;
			vqpi->txq.ring_len = adapter->tx_rings[i].count;
			vqpi->txq.dma_ring_addr = adapter->tx_rings[i].dma;
			vqpi->rxq.vsi_id = vqci->vsi_id;
			vqpi->rxq.queue_id = i;
			vqpi->rxq.ring_len = adapter->rx_rings[i].count;
			vqpi->rxq.dma_ring_addr = adapter->rx_rings[i].dma;
			vqpi->rxq.max_pkt_size = adapter->netdev->mtu +
						 IAVF_PACKET_HDR_PAD;
			vqpi->rxq.databuffer_size =
				ALIGN(adapter->rx_rings[i].rx_buf_len,
				      BIT_ULL(IAVF_RXQ_CTX_DBUFF_SHIFT));
			if (RXDID_ALLOWED(adapter))
				vqpi->rxq.rxdid = adapter->rxdid;
			if (CRC_OFFLOAD_ALLOWED(adapter))
				vqpi->rxq.crc_disable = !!(adapter->netdev->features &
							   NETIF_F_RXFCS);
			vqpi++;
		}
		last += pairs;
		rem -= pairs;

		adapter->aq_required &= ~IAVF_FLAG_AQ_CONFIGURE_QUEUES;
		iavf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_VSI_QUEUES,
				 (u8 *)vqci, len);
		kfree(vqci);
	}
}

/**
 * iavf_enable_disable_queues_v2 - send V2 messages of ENABLE/DISABLE queues ops
 * @adapter: private adapter structure
 * @enable: true to enable and false to disable the queues
 */
static void iavf_enable_disable_queues_v2(struct iavf_adapter *adapter, bool enable)
{
	struct virtchnl_del_ena_dis_queues *msg;
	struct virtchnl_queue_chunk *chunk;
	enum virtchnl_ops op = VIRTCHNL_OP_ENABLE_QUEUES_V2;
	u64 flag = IAVF_FLAG_AQ_ENABLE_QUEUES;
	int len;

	if (!enable) {
		op = VIRTCHNL_OP_DISABLE_QUEUES_V2;
		flag = IAVF_FLAG_AQ_DISABLE_QUEUES;
	}

	adapter->current_op = op;

	/* We need 2 chunks (one tx and one rx), one chunk is already in
	 * virtchnl_queue_vector_maps strut
	 */
	len = sizeof(struct virtchnl_del_ena_dis_queues) +
		sizeof(struct virtchnl_queue_chunk);
	msg = kzalloc(len, GFP_KERNEL);
	if (!msg)
		return;

	msg->vport_id = adapter->vsi_res->vsi_id;
	msg->chunks.num_chunks = 2;

	chunk = &msg->chunks.chunks[0];
	chunk->type = VIRTCHNL_QUEUE_TYPE_RX;
	chunk->start_queue_id = 0;
	chunk->num_queues = adapter->num_active_queues;

	chunk++;
	chunk->type = VIRTCHNL_QUEUE_TYPE_TX;
	chunk->start_queue_id = 0;
	chunk->num_queues = adapter->num_active_queues;

	adapter->aq_required &= ~flag;
	iavf_send_pf_msg(adapter, op, (u8 *)msg, len);
	kfree(msg);
}

/**
 * iavf_enable_queues
 * @adapter: adapter structure
 *
 * Request that the PF enable all of our queues.
 **/
void iavf_enable_queues(struct iavf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot enable queues, command %d pending\n",
			adapter->current_op);
		return;
	}

	if (LARGE_NUM_QPAIRS_SUPPORT(adapter)) {
		iavf_enable_disable_queues_v2(adapter, true);
		return;
	}

	adapter->current_op = VIRTCHNL_OP_ENABLE_QUEUES;
	vqs.vsi_id = adapter->vsi_res->vsi_id;
	vqs.tx_queues = BIT(adapter->num_active_queues) - 1;
	vqs.rx_queues = vqs.tx_queues;
	adapter->aq_required &= ~IAVF_FLAG_AQ_ENABLE_QUEUES;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_ENABLE_QUEUES,
			 (u8 *)&vqs, sizeof(vqs));
}

/**
 * iavf_disable_queues
 * @adapter: adapter structure
 *
 * Request that the PF disable all of our queues.
 **/
void iavf_disable_queues(struct iavf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot disable queues, command %d pending\n",
			adapter->current_op);
		return;
	}

	if (LARGE_NUM_QPAIRS_SUPPORT(adapter)) {
		iavf_enable_disable_queues_v2(adapter, false);
		return;
	}

	adapter->current_op = VIRTCHNL_OP_DISABLE_QUEUES;
	vqs.vsi_id = adapter->vsi_res->vsi_id;
	vqs.tx_queues = BIT(adapter->num_active_queues) - 1;
	vqs.rx_queues = vqs.tx_queues;
	adapter->aq_required &= ~IAVF_FLAG_AQ_DISABLE_QUEUES;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_DISABLE_QUEUES,
			 (u8 *)&vqs, sizeof(vqs));
}

/**
 * iavf_map_queue_vector
 * @adapter: adapter structure
 *
 * Can only be used if VIRTCHNL_VF_LARGE_NUM_QPAIRS is negotiated with the PF
 **/
static void iavf_map_queue_vector(struct iavf_adapter *adapter)
{
	struct virtchnl_queue_vector_maps *qvmaps;
	struct virtchnl_queue_vector *qv;
	struct iavf_q_vector *q_vector;
	int ret, len, max_qv;
	int i, qv_num, q_next = 0;
	int num_active_queues = adapter->num_active_queues;

	if (!num_active_queues)
		return;

	adapter->current_op = VIRTCHNL_OP_MAP_QUEUE_VECTOR;

	/* Max number of queue vectors maps that we can allocate before reaching
	 * the AQ buffer limit
	 */
	max_qv = (IAVF_MAX_AQ_BUF_SIZE -
			sizeof(struct virtchnl_queue_vector_maps)) /
			sizeof(struct virtchnl_queue_vector);

	while (q_next < num_active_queues) {
		qv_num = min(max_qv + 1,  2 * (num_active_queues - q_next));

		/* We will send even number of maps; 1 tx and 1 rx rings */
		qv_num &= ~1UL;

		len = sizeof(struct virtchnl_queue_vector_maps) +
			((qv_num - 1) * sizeof(struct virtchnl_queue_vector));
		qvmaps = kzalloc(len, GFP_KERNEL);
		if (!qvmaps)
			return;

		qvmaps->vport_id = adapter->vsi_res->vsi_id;
		qvmaps->num_qv_maps = qv_num;
		qv = &qvmaps->qv_maps[0];

		for (i = q_next; i < q_next + qv_num/2; i++) {
			q_vector = adapter->tx_rings[i].q_vector;
			qv->queue_id = i;
			qv->vector_id = NONQ_VECS + q_vector->v_idx;
			qv->itr_idx = IAVF_TX_ITR;
			qv->queue_type = VIRTCHNL_QUEUE_TYPE_TX;
			qv++;

			q_vector = adapter->rx_rings[i].q_vector;
			qv->queue_id = i;
			qv->vector_id = NONQ_VECS + q_vector->v_idx;
			qv->itr_idx = IAVF_RX_ITR;
			qv->queue_type = VIRTCHNL_QUEUE_TYPE_RX;
			qv++;
		}
		q_next += qv_num / 2;

		adapter->aq_required &= ~IAVF_FLAG_AQ_MAP_VECTORS;
		ret = iavf_send_pf_msg(adapter, VIRTCHNL_OP_MAP_QUEUE_VECTOR,
				 (u8 *)qvmaps, len);
		kfree(qvmaps);
		if (ret)
			return;
	}
}

/**
 * iavf_map_queues
 * @adapter: adapter structure
 *
 * Request that the PF map queues to interrupt vectors. Misc causes, including
 * admin queue, are always mapped to vector 0.
 **/
void iavf_map_queues(struct iavf_adapter *adapter)
{
	struct virtchnl_irq_map_info *vimi;
	struct virtchnl_vector_map *vecmap;
	int v_idx, q_vectors, len;
	struct iavf_q_vector *q_vector;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot map queues to vectors, command %d pending\n",
			adapter->current_op);
		return;
	}

	if (LARGE_NUM_QPAIRS_SUPPORT(adapter)) {
		iavf_map_queue_vector(adapter);
		return;
	}

	adapter->current_op = VIRTCHNL_OP_CONFIG_IRQ_MAP;

	q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	len = sizeof(struct virtchnl_irq_map_info) +
	      (adapter->num_msix_vectors *
		sizeof(struct virtchnl_vector_map));
	vimi = kzalloc(len, GFP_KERNEL);
	if (!vimi)
		return;

	vimi->num_vectors = adapter->num_msix_vectors;
	/* Queue vectors first */
	for (v_idx = 0; v_idx < q_vectors; v_idx++) {
		unsigned long map;
		q_vector = &adapter->q_vectors[v_idx];
		vecmap = &vimi->vecmap[v_idx];

		vecmap->vsi_id = adapter->vsi_res->vsi_id;
		vecmap->vector_id = v_idx + NONQ_VECS;
		bitmap_copy(&map, q_vector->ring_mask, BITS_PER_LONG);
		vecmap->txq_map = (u16)map;
		vecmap->rxq_map = (u16)map;
		vecmap->rxitr_idx = IAVF_RX_ITR;
		vecmap->txitr_idx = IAVF_TX_ITR;
	}
	/* Misc vector last - this is only for AdminQ messages */
	vecmap = &vimi->vecmap[v_idx];
	vecmap->vsi_id = adapter->vsi_res->vsi_id;
	vecmap->vector_id = 0;
	vecmap->txq_map = 0;
	vecmap->rxq_map = 0;

	adapter->aq_required &= ~IAVF_FLAG_AQ_MAP_VECTORS;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_IRQ_MAP,
			 (u8 *)vimi, len);
	kfree(vimi);
}

/**
 * iavf_request_queues
 * @adapter: adapter structure
 * @num: number of requested queues
 *
 * We get a default number of queues from the PF.  This enables us to request a
 * different number.  Returns 0 on success, negative on failure
 **/
int iavf_request_queues(struct iavf_adapter *adapter, int num)
{
	struct virtchnl_vf_res_request vfres;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot request queues, command %d pending\n",
			adapter->current_op);
		return -EBUSY;
	}

	vfres.num_queue_pairs = min_t(int, num, num_online_cpus());

	adapter->current_op = VIRTCHNL_OP_REQUEST_QUEUES;
	adapter->flags |= IAVF_FLAG_REINIT_ITR_NEEDED;
	return iavf_send_pf_msg(adapter, VIRTCHNL_OP_REQUEST_QUEUES,
				(u8 *)&vfres, sizeof(vfres));
}

/**
 * iavf_set_mac_addr_type
 * @virtchnl_ether_addr: pointer to request list element
 * @filter: pointer filter being requested
 *
 * Set the correct request type.
 **/
static void
iavf_set_mac_addr_type(struct virtchnl_ether_addr *virtchnl_ether_addr,
		       struct iavf_mac_filter *filter)
{
	virtchnl_ether_addr->type = filter->is_primary ?
		VIRTCHNL_ETHER_ADDR_PRIMARY :
		VIRTCHNL_ETHER_ADDR_EXTRA;
}

/**
 * iavf_add_ether_addrs
 * @adapter: adapter structure
 *
 * Request that the PF add one or more addresses to our filters.
 **/
void iavf_add_ether_addrs(struct iavf_adapter *adapter)
{
	bool is_more = false, is_primary = false;
	struct virtchnl_ether_addr_list *veal;
	int len, i = 0, count = 0;
	struct iavf_mac_filter *f;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot add filters, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->add) {
			if (f->is_primary)
				is_primary = true;

			count++;
		}
	}

	if (is_primary) {
		if (count > 1)
			is_more = true;

		count = 1;
	}

	if (!count) {
		adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_MAC_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_ADD_ETH_ADDR;

	len = sizeof(struct virtchnl_ether_addr_list) +
	      (count * sizeof(struct virtchnl_ether_addr));
	if (len > IAVF_MAX_AQ_BUF_SIZE) {
		dev_warn(&adapter->pdev->dev, "Too many add MAC changes in one request\n");
		count = (IAVF_MAX_AQ_BUF_SIZE -
			 sizeof(struct virtchnl_ether_addr_list)) /
			sizeof(struct virtchnl_ether_addr);
		len = sizeof(struct virtchnl_ether_addr_list) +
		      (count * sizeof(struct virtchnl_ether_addr));
		is_more = true;
	}

	veal = kzalloc(len, GFP_ATOMIC);
	if (!veal) {
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	veal->vsi_id = adapter->vsi_res->vsi_id;
	veal->num_elements = count;
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (is_primary && !(f->is_primary && f->add))
			continue;
		if (!f->add)
			continue;
		ether_addr_copy(veal->list[i].addr,
				f->macaddr);
		iavf_set_mac_addr_type(&veal->list[i], f);
		f->add = false;
		i++;

		if (i == count)
			break;
	}

	if (!is_more)
		adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_MAC_FILTER;

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	iavf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_ETH_ADDR,
			 (u8 *)veal, len);
	kfree(veal);
}

/**
 * iavf_del_ether_addrs
 * @adapter: adapter structure
 *
 * Request that the PF remove one or more addresses from our filters.
 **/
void iavf_del_ether_addrs(struct iavf_adapter *adapter)
{
	struct virtchnl_ether_addr_list *veal;
	struct iavf_mac_filter *f, *ftmp;
	int len, i = 0, count = 0;
	bool more = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot remove filters, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->remove)
			count++;
	}
	if (!count) {
		adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_MAC_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_DEL_ETH_ADDR;

	len = sizeof(struct virtchnl_ether_addr_list) +
	      (count * sizeof(struct virtchnl_ether_addr));
	if (len > IAVF_MAX_AQ_BUF_SIZE) {
		dev_warn(&adapter->pdev->dev, "Too many delete MAC changes in one request\n");
		count = (IAVF_MAX_AQ_BUF_SIZE -
			 sizeof(struct virtchnl_ether_addr_list)) /
			sizeof(struct virtchnl_ether_addr);
		len = sizeof(struct virtchnl_ether_addr_list) +
		      (count * sizeof(struct virtchnl_ether_addr));
		more = true;
	}
	veal = kzalloc(len, GFP_ATOMIC);
	if (!veal) {
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	veal->vsi_id = adapter->vsi_res->vsi_id;
	veal->num_elements = count;
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		if (f->remove) {
			ether_addr_copy(veal->list[i].addr, f->macaddr);
			iavf_set_mac_addr_type(&veal->list[i], f);
			i++;
			list_del(&f->list);
			kfree(f);
			if (i == count)
				break;
		}
	}
	if (!more)
		adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_MAC_FILTER;

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	iavf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_ETH_ADDR,
			 (u8 *)veal, len);
	kfree(veal);
}

/**
 * iavf_mac_add_ok
 * @adapter: adapter structure
 *
 * Submit list of filters based on PF response.
 **/
static void iavf_mac_add_ok(struct iavf_adapter *adapter)
{
	struct iavf_mac_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		f->is_new_mac = false;
		if (!f->add && !f->add_handled) {
			f->add_handled = true;
			if (f->is_primary)
				netdev_info(adapter->netdev,
					    "Setting MAC Address to %pM",
					    adapter->hw.mac.addr);
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * iavf_netdev_mc_mac_add_reject
 * @adapter: adapter structure
 *
 * Remove multicast addresses from netdev list based on PF response.
 **/
static void iavf_netdev_mc_mac_add_reject(struct iavf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct iavf_mac_filter *f, *ftmp, *elem;
	struct list_head tmp_del_list;

	INIT_LIST_HEAD(&tmp_del_list);
	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->is_new_mac && is_multicast_ether_addr(f->macaddr)) {
			elem = kzalloc(sizeof(*elem), GFP_ATOMIC);
			if (!elem)
				goto out;
			ether_addr_copy(elem->macaddr, f->macaddr);
			list_add(&elem->list, &tmp_del_list);
		}
	}
out:
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &tmp_del_list, list) {
		dev_mc_del(netdev, f->macaddr);
		kfree(f);
	}
}

/**
 * iavf_mac_add_reject
 * @adapter: adapter structure
 *
 * Remove filters from list based on PF response.
 **/
static void iavf_mac_add_reject(struct iavf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct iavf_mac_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		if (f->remove && ether_addr_equal(f->macaddr, netdev->dev_addr))
			f->remove = false;

		if (!f->add && !f->add_handled)
			f->add_handled = true;

		if (f->is_new_mac) {
			list_del(&f->list);
			kfree(f);
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * iavf_vlan_add_reject
 * @adapter: adapter structure
 *
 * Remove VLAN filters from list based on PF response.
 **/
static void iavf_vlan_add_reject(struct iavf_adapter *adapter)
{
	struct iavf_vlan_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
		if (f->state == IAVF_VLAN_IS_NEW) {
			list_del(&f->list);
			kfree(f);
			adapter->num_vlan_filters--;
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * iavf_add_vlans
 * @adapter: adapter structure
 *
 * Request that the PF add one or more VLAN filters to our VSI.
 **/
void iavf_add_vlans(struct iavf_adapter *adapter)
{
	int len, i = 0, count = 0;
	struct iavf_vlan_filter *f;
	bool more = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot add VLANs, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry(f, &adapter->vlan_filter_list, list) {
		if (f->state == IAVF_VLAN_ADD)
			count++;
	}
	if (!count || !VLAN_FILTERING_ALLOWED(adapter)) {
		/* prevent endless add VLAN requests */
		adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	if (VLAN_ALLOWED(adapter)) {
		struct virtchnl_vlan_filter_list *vvfl;

		adapter->current_op = VIRTCHNL_OP_ADD_VLAN;

		len = sizeof(*vvfl) + (count * sizeof(u16));
		if (len > IAVF_MAX_AQ_BUF_SIZE) {
			dev_warn(&adapter->pdev->dev, "Too many add VLAN changes in one request\n");
			count = (IAVF_MAX_AQ_BUF_SIZE - sizeof(*vvfl)) /
				sizeof(u16);
			len = sizeof(*vvfl) + (count * sizeof(u16));
			more = true;
		}
		vvfl = kzalloc(len, GFP_ATOMIC);
		if (!vvfl) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl->vsi_id = adapter->vsi_res->vsi_id;
		vvfl->num_elements = count;
		list_for_each_entry(f, &adapter->vlan_filter_list, list) {
			if (f->state == IAVF_VLAN_ADD) {
				vvfl->vlan_id[i] = f->vlan.vid;
				i++;
				f->state = IAVF_VLAN_IS_NEW;
				if (i == count)
					break;
			}
		}
		if (!more)
			adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		iavf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_VLAN, (u8 *)vvfl, len);
		kfree(vvfl);
	} else {
		u16 max_vlans = adapter->vlan_v2_caps.filtering.max_filters;
		u16 current_vlans = iavf_get_num_vlans_added(adapter);
		struct virtchnl_vlan_filter_list_v2 *vvfl_v2;

		adapter->current_op = VIRTCHNL_OP_ADD_VLAN_V2;

		if ((count + current_vlans) > max_vlans &&
		    current_vlans < max_vlans) {
			count = max_vlans - iavf_get_num_vlans_added(adapter);
			more = true;
		}

		len = sizeof(*vvfl_v2) + ((count - 1) *
					  sizeof(struct virtchnl_vlan_filter));
		if (len > IAVF_MAX_AQ_BUF_SIZE) {
			dev_warn(&adapter->pdev->dev, "Too many add VLAN changes in one request\n");
			count = (IAVF_MAX_AQ_BUF_SIZE - sizeof(*vvfl_v2)) /
				sizeof(struct virtchnl_vlan_filter);
			len = sizeof(*vvfl_v2) +
				((count - 1) *
				 sizeof(struct virtchnl_vlan_filter));
			more = true;
		}

		vvfl_v2 = kzalloc(len, GFP_ATOMIC);
		if (!vvfl_v2) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl_v2->vport_id = adapter->vsi_res->vsi_id;
		vvfl_v2->num_elements = count;
		list_for_each_entry(f, &adapter->vlan_filter_list, list) {
			if (f->state == IAVF_VLAN_ADD) {
				struct virtchnl_vlan_supported_caps *filtering_support =
					&adapter->vlan_v2_caps.filtering.filtering_support;
				struct virtchnl_vlan *vlan;

				if (i == count)
					break;
				/* give priority over outer if it's enabled */
				if (filtering_support->outer)
					vlan = &vvfl_v2->filters[i].outer;
				else
					vlan = &vvfl_v2->filters[i].inner;

				vlan->tci = f->vlan.vid;
				vlan->tpid = f->vlan.tpid;

				i++;
				f->state = IAVF_VLAN_IS_NEW;
			}
		}

		if (!more)
			adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		iavf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_VLAN_V2,
				 (u8 *)vvfl_v2, len);
		kfree(vvfl_v2);
	}
}

/**
 * iavf_del_vlans
 * @adapter: adapter structure
 *
 * Request that the PF remove one or more VLAN filters from our VSI.
 **/
void iavf_del_vlans(struct iavf_adapter *adapter)
{
	struct iavf_vlan_filter *f, *ftmp;
	int len, i = 0, count = 0;
	bool more = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot remove VLANs, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
		/* since VLAN capabilities are not allowed, we dont want to send
		 * a VLAN delete request because it will most likely fail and
		 * create unnecessary errors/noise, so just free the VLAN
		 * filters marked for removal to enable bailing out before
		 * sending a virtchnl message
		 */
		if (f->state == IAVF_VLAN_REMOVE &&
		    !VLAN_FILTERING_ALLOWED(adapter)) {
			list_del(&f->list);
			kfree(f);
			adapter->num_vlan_filters--;
		} else if (f->state == IAVF_VLAN_DISABLE &&
		    !VLAN_FILTERING_ALLOWED(adapter)) {
			f->state = IAVF_VLAN_INACTIVE;
		} else if (f->state == IAVF_VLAN_REMOVE ||
			   f->state == IAVF_VLAN_DISABLE) {
			count++;
		}
	}
	if (!count || !VLAN_FILTERING_ALLOWED(adapter)) {
		/* prevent endless del VLAN requests */
		adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	if (VLAN_ALLOWED(adapter)) {
		struct virtchnl_vlan_filter_list *vvfl;

		adapter->current_op = VIRTCHNL_OP_DEL_VLAN;

		len = sizeof(*vvfl) + (count * sizeof(u16));
		if (len > IAVF_MAX_AQ_BUF_SIZE) {
			dev_warn(&adapter->pdev->dev, "Too many delete VLAN changes in one request\n");
			count = (IAVF_MAX_AQ_BUF_SIZE - sizeof(*vvfl)) /
				sizeof(u16);
			len = sizeof(*vvfl) + (count * sizeof(u16));
			more = true;
		}
		vvfl = kzalloc(len, GFP_ATOMIC);
		if (!vvfl) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl->vsi_id = adapter->vsi_res->vsi_id;
		vvfl->num_elements = count;
		list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
			if (f->state == IAVF_VLAN_DISABLE) {
				vvfl->vlan_id[i] = f->vlan.vid;
				f->state = IAVF_VLAN_INACTIVE;
				i++;
				if (i == count)
					break;
			} else if (f->state == IAVF_VLAN_REMOVE) {
				vvfl->vlan_id[i] = f->vlan.vid;
				list_del(&f->list);
				kfree(f);
				adapter->num_vlan_filters--;
				i++;
				if (i == count)
					break;
			}
		}

		if (!more)
			adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		iavf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_VLAN, (u8 *)vvfl, len);
		kfree(vvfl);
	} else {
		struct virtchnl_vlan_filter_list_v2 *vvfl_v2;

		adapter->current_op = VIRTCHNL_OP_DEL_VLAN_V2;

		len = sizeof(*vvfl_v2) +
			((count - 1) * sizeof(struct virtchnl_vlan_filter));
		if (len > IAVF_MAX_AQ_BUF_SIZE) {
			dev_warn(&adapter->pdev->dev, "Too many add VLAN changes in one request\n");
			count = (IAVF_MAX_AQ_BUF_SIZE -
				 sizeof(*vvfl_v2)) /
				sizeof(struct virtchnl_vlan_filter);
			len = sizeof(*vvfl_v2) +
				((count - 1) *
				 sizeof(struct virtchnl_vlan_filter));
			more = true;
		}

		vvfl_v2 = kzalloc(len, GFP_ATOMIC);
		if (!vvfl_v2) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl_v2->vport_id = adapter->vsi_res->vsi_id;
		vvfl_v2->num_elements = count;
		list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
			if (f->state == IAVF_VLAN_DISABLE ||
			    f->state == IAVF_VLAN_REMOVE) {
				struct virtchnl_vlan_supported_caps *filtering_support =
					&adapter->vlan_v2_caps.filtering.filtering_support;
				struct virtchnl_vlan *vlan;

				/* give priority over outer if it's enabled */
				if (filtering_support->outer)
					vlan = &vvfl_v2->filters[i].outer;
				else
					vlan = &vvfl_v2->filters[i].inner;

				vlan->tci = f->vlan.vid;
				vlan->tpid = f->vlan.tpid;

				if (f->state == IAVF_VLAN_DISABLE) {
					f->state = IAVF_VLAN_INACTIVE;
				} else {
					list_del(&f->list);
					kfree(f);
					adapter->num_vlan_filters--;
				}
				i++;
				if (i == count)
					break;
			}
		}

		if (!more)
			adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		iavf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_VLAN_V2,
				 (u8 *)vvfl_v2, len);
		kfree(vvfl_v2);
	}
}

/**
 * iavf_set_promiscuous
 * @adapter: adapter structure
 *
 * Request that the PF enable promiscuous mode for our VSI.
 **/
void iavf_set_promiscuous(struct iavf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct virtchnl_promisc_info vpi;
	unsigned int flags;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set promiscuous mode, command %d pending\n",
			adapter->current_op);
		return;
	}

	/* prevent changes to promiscuous flags */
	spin_lock_bh(&adapter->current_netdev_promisc_flags_lock);

	/* sanity check to prevent duplicate AQ calls */
	if (!iavf_promiscuous_mode_changed(adapter)) {
		adapter->aq_required &= ~IAVF_FLAG_AQ_CONFIGURE_PROMISC_MODE;
		dev_dbg(&adapter->pdev->dev, "No change in promiscuous mode\n");
		/* allow changes to promiscuous flags */
		spin_unlock_bh(&adapter->current_netdev_promisc_flags_lock);
		return;
	}

	/* there are 2 bits, but only 3 states */
	if (!(netdev->flags & IFF_PROMISC) &&
	    netdev->flags & IFF_ALLMULTI) {
		/* State 1  - only multicast promiscuous mode enabled
		 * - !IFF_PROMISC && IFF_ALLMULTI
		 */
		flags = FLAG_VF_MULTICAST_PROMISC;
		adapter->current_netdev_promisc_flags |= IFF_ALLMULTI;
		adapter->current_netdev_promisc_flags &= ~IFF_PROMISC;
		dev_info(&adapter->pdev->dev,
			 "Entering multicast promiscuous mode\n");
	} else if (!(netdev->flags & IFF_PROMISC) &&
		   !(netdev->flags & IFF_ALLMULTI)) {
		/* State 2 - unicast/multicast promiscuous mode disabled
		 * - !IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = 0;
		adapter->current_netdev_promisc_flags &=
			~(IFF_PROMISC | IFF_ALLMULTI);
		dev_info(&adapter->pdev->dev, "Leaving promiscuous mode\n");
	} else {
		/* State 3 - unicast/multicast promiscuous mode enabled
		 * - IFF_PROMISC && IFF_ALLMULTI
		 * - IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = FLAG_VF_UNICAST_PROMISC | FLAG_VF_MULTICAST_PROMISC;
		adapter->current_netdev_promisc_flags |= IFF_PROMISC;
		if (netdev->flags & IFF_ALLMULTI)
			adapter->current_netdev_promisc_flags |= IFF_ALLMULTI;
		else
			adapter->current_netdev_promisc_flags &= ~IFF_ALLMULTI;

		dev_info(&adapter->pdev->dev, "Entering promiscuous mode\n");
	}

	adapter->aq_required &= ~IAVF_FLAG_AQ_CONFIGURE_PROMISC_MODE;

	/* allow changes to promiscuous flags */
	spin_unlock_bh(&adapter->current_netdev_promisc_flags_lock);

	adapter->current_op = VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE;
	vpi.vsi_id = adapter->vsi_res->vsi_id;
	vpi.flags = flags;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
			 (u8 *)&vpi, sizeof(vpi));
}

/**
 * iavf_request_stats
 * @adapter: adapter structure
 *
 * Request VSI statistics from PF.
 **/
void iavf_request_stats(struct iavf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* no error message, this isn't crucial */
		return;
	}

	adapter->aq_required &= ~IAVF_FLAG_AQ_REQUEST_STATS;
	adapter->current_op = VIRTCHNL_OP_GET_STATS;
	vqs.vsi_id = adapter->vsi_res->vsi_id;
	/* queue maps are ignored for this message - only the vsi is used */
	if (iavf_send_pf_msg(adapter, VIRTCHNL_OP_GET_STATS,
			     (u8 *)&vqs, sizeof(vqs)))
		/* if the request failed, don't lock out others */
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	adapter->last_stats_update = ktime_get_ns();
}

/**
 * iavf_get_hena
 * @adapter: adapter structure
 *
 * Request hash enable capabilities from PF
 **/
void iavf_get_hena(struct iavf_adapter *adapter)
{
	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot get RSS hash capabilities, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_GET_RSS_HENA_CAPS;
	adapter->aq_required &= ~IAVF_FLAG_AQ_GET_HENA;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_GET_RSS_HENA_CAPS, NULL, 0);
}

/**
 * iavf_set_hena
 * @adapter: adapter structure
 *
 * Request the PF to set our RSS hash capabilities
 **/
void iavf_set_hena(struct iavf_adapter *adapter)
{
	struct virtchnl_rss_hena vrh;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot set RSS hash enable, command %d pending\n",
			adapter->current_op);
		return;
	}
	vrh.hena = adapter->hena;
	adapter->current_op = VIRTCHNL_OP_SET_RSS_HENA;
	adapter->aq_required &= ~IAVF_FLAG_AQ_SET_HENA;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_SET_RSS_HENA, (u8 *)&vrh,
			 sizeof(vrh));
}

/**
 * iavf_set_rss_key
 * @adapter: adapter structure
 *
 * Request the PF to set our RSS hash key
 **/
void iavf_set_rss_key(struct iavf_adapter *adapter)
{
	struct virtchnl_rss_key *vrk;
	int len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot set RSS key, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_rss_key) +
	      (adapter->rss_key_size * sizeof(u8)) - 1;
	vrk = kzalloc(len, GFP_KERNEL);
	if (!vrk)
		return;
	vrk->vsi_id = adapter->vsi.id;
	vrk->key_len = adapter->rss_key_size;
	memcpy(vrk->key, adapter->rss_key, adapter->rss_key_size);

	adapter->current_op = VIRTCHNL_OP_CONFIG_RSS_KEY;
	adapter->aq_required &= ~IAVF_FLAG_AQ_SET_RSS_KEY;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_RSS_KEY, (u8 *)vrk, len);
	kfree(vrk);
}

/**
 * iavf_set_rss_lut
 * @adapter: adapter structure
 *
 * Request the PF to set our RSS lookup table
 **/
void iavf_set_rss_lut(struct iavf_adapter *adapter)
{
	struct virtchnl_rss_lut *vrl;
	int len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot set RSS LUT, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_rss_lut) +
	      (adapter->rss_lut_size * sizeof(u8)) - 1;
	vrl = kzalloc(len, GFP_KERNEL);
	if (!vrl)
		return;
	vrl->vsi_id = adapter->vsi.id;
	vrl->lut_entries = adapter->rss_lut_size;
	memcpy(vrl->lut, adapter->rss_lut, adapter->rss_lut_size);
	adapter->current_op = VIRTCHNL_OP_CONFIG_RSS_LUT;
	adapter->aq_required &= ~IAVF_FLAG_AQ_SET_RSS_LUT;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_RSS_LUT, (u8 *)vrl, len);
	kfree(vrl);
}

/**
 * iavf_enable_vlan_stripping
 * @adapter: adapter structure
 *
 * Request VLAN header stripping to be enabled
 **/
void iavf_enable_vlan_stripping(struct iavf_adapter *adapter)
{
	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot enable stripping, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_ENABLE_VLAN_STRIPPING;
	adapter->aq_required &= ~IAVF_FLAG_AQ_ENABLE_VLAN_STRIPPING;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING, NULL, 0);
}

/**
 * iavf_disable_vlan_stripping
 * @adapter: adapter structure
 *
 * Request VLAN header stripping to be disabled
 **/
void iavf_disable_vlan_stripping(struct iavf_adapter *adapter)
{
	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot disable stripping, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_DISABLE_VLAN_STRIPPING;
	adapter->aq_required &= ~IAVF_FLAG_AQ_DISABLE_VLAN_STRIPPING;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING, NULL, 0);
}

/**
 * iavf_tpid_to_vc_ethertype - transform from VLAN TPID to virtchnl ethertype
 * @tpid: VLAN TPID (i.e. 0x8100, 0x88a8, etc.)
 */
static u32 iavf_tpid_to_vc_ethertype(u16 tpid)
{
	switch (tpid) {
	case ETH_P_8021Q:
		return VIRTCHNL_VLAN_ETHERTYPE_8100;
	case ETH_P_8021AD:
		return VIRTCHNL_VLAN_ETHERTYPE_88A8;
	}

	return 0;
}

/**
 * iavf_set_vc_offload_ethertype - set virtchnl ethertype for offload message
 * @adapter: adapter structure
 * @msg: message structure used for updating offloads over virtchnl to update
 * @tpid: VLAN TPID (i.e. 0x8100, 0x88a8, etc.)
 * @offload_op: opcode used to determine which support structure to check
 */
static int
iavf_set_vc_offload_ethertype(struct iavf_adapter *adapter,
			      struct virtchnl_vlan_setting *msg, u16 tpid,
			      enum virtchnl_ops offload_op)
{
	struct virtchnl_vlan_supported_caps *offload_support;
	u32 vc_ethertype = iavf_tpid_to_vc_ethertype(tpid);

	/* reference the correct offload support structure */
	switch (offload_op) {
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		fallthrough;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		offload_support =
			&adapter->vlan_v2_caps.offloads.stripping_support;
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		fallthrough;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		offload_support =
			&adapter->vlan_v2_caps.offloads.insertion_support;
		break;
	default:
		dev_err(&adapter->pdev->dev, "Invalid opcode %d for setting virtchnl ethertype to enable/disable VLAN offloads\n",
			offload_op);
		return -EINVAL;
	}

	/* make sure ethertype is supported */
	if ((offload_support->outer & vc_ethertype) &&
	    (offload_support->outer & VIRTCHNL_VLAN_TOGGLE)) {
		msg->outer_ethertype_setting = vc_ethertype;
	} else if ((offload_support->inner & vc_ethertype) &&
		   (offload_support->inner & VIRTCHNL_VLAN_TOGGLE)) {
		msg->inner_ethertype_setting = vc_ethertype;
	} else {
		dev_dbg(&adapter->pdev->dev, "opcode %d unsupported for VLAN TPID 0x%04x\n",
			offload_op, tpid);
		return -EINVAL;
	}

	return 0;
}

/**
 * iavf_clear_offload_v2_aq_required - clear AQ required bit for offload request
 * @adapter: adapter structure
 * @tpid: VLAN TPID
 * @offload_op: opcode used to determine which AQ required bit to clear
 */
static void
iavf_clear_offload_v2_aq_required(struct iavf_adapter *adapter, u16 tpid,
				  enum virtchnl_ops offload_op)
{
	switch (offload_op) {
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING;
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING;
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION;
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~IAVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION;
		break;
	default:
		dev_err(&adapter->pdev->dev, "Unsupported opcode %d specified for clearing aq_required bits for VIRTCHNL_VF_OFFLOAD_VLAN_V2 offload request\n",
			offload_op);
	}
}

/**
 * iavf_send_vlan_offload_v2 - send offload enable/disable over virtchnl
 * @adapter: adapter structure
 * @tpid: VLAN TPID used for the command (i.e. 0x8100 or 0x88a8)
 * @offload_op: offload_op used to make the request over virtchnl
 */
static void
iavf_send_vlan_offload_v2(struct iavf_adapter *adapter, u16 tpid,
			  enum virtchnl_ops offload_op)
{
	struct virtchnl_vlan_setting *msg;
	int len = sizeof(*msg);

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot send %d, command %d pending\n",
			offload_op, adapter->current_op);
		return;
	}

	adapter->current_op = offload_op;

	msg = kzalloc(len, GFP_KERNEL);
	if (!msg)
		return;

	msg->vport_id = adapter->vsi_res->vsi_id;

	/* always clear to prevent unsupported and endless requests */
	iavf_clear_offload_v2_aq_required(adapter, tpid, offload_op);

	/* only send valid offload requests */
	if (!iavf_set_vc_offload_ethertype(adapter, msg, tpid, offload_op))
		iavf_send_pf_msg(adapter, offload_op, (u8 *)msg, len);
	else
		/* since the current_op assigned in this function was never sent
		 * there will never be a completion to clear it, so do that now
		 * to allow other opcodes
		 */
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(msg);
}

/**
 * iavf_enable_vlan_stripping_v2 - enable VLAN stripping
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to enable VLAN stripping
 */
void iavf_enable_vlan_stripping_v2(struct iavf_adapter *adapter, u16 tpid)
{
	iavf_send_vlan_offload_v2(adapter, tpid,
				  VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2);
}

/**
 * iavf_disable_vlan_stripping_v2 - disable VLAN stripping
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to disable VLAN stripping
 */
void iavf_disable_vlan_stripping_v2(struct iavf_adapter *adapter, u16 tpid)
{
	iavf_send_vlan_offload_v2(adapter, tpid,
				  VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2);
}

/**
 * iavf_enable_vlan_insertion_v2 - enable VLAN insertion
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to enable VLAN insertion
 */
void iavf_enable_vlan_insertion_v2(struct iavf_adapter *adapter, u16 tpid)
{
	iavf_send_vlan_offload_v2(adapter, tpid,
				  VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2);
}

/**
 * iavf_disable_vlan_insertion_v2 - disable VLAN insertion
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to disable VLAN insertion
 */
void iavf_disable_vlan_insertion_v2(struct iavf_adapter *adapter, u16 tpid)
{
	iavf_send_vlan_offload_v2(adapter, tpid,
				  VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2);
}

/**
 * iavf_send_vc_msg - Send one queued virtchnl message
 * @adapter: adapter private structure
 *
 * De-queue one command request and send the command message to the PF.
 * Clear IAVF_FLAG_AQ_MSG_QUEUE_PENDING if no more messages are left to send.
 */
void iavf_send_vc_msg(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_vc_msg *vc_msg;
	int err;

	spin_lock(&adapter->vc_msg_queue.lock);
	vc_msg = list_first_entry_or_null(&adapter->vc_msg_queue.msgs,
					  struct iavf_vc_msg, list);
	if (!vc_msg) {
		/* no further messages to send */
		adapter->aq_required &= ~IAVF_FLAG_AQ_MSG_QUEUE_PENDING;
		goto out_unlock;
	}

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(dev, "Cannot send virtchnl command %s-%d, command %s-%d pending\n",
			virtchnl_op_str(vc_msg->v_opcode), vc_msg->v_opcode,
			virtchnl_op_str(adapter->current_op),
			adapter->current_op);
		goto out_unlock;
	}

	err = iavf_send_pf_msg(adapter, vc_msg->v_opcode, vc_msg->msg,
			       vc_msg->msglen);
	if (!err) {
		/* Command was sent without errors, so we can remove it from
		 * the list and discard it.
		 */
		list_del(&vc_msg->list);
		kfree(vc_msg);
	} else {
		/* We failed to send the command, try again next cycle */
		dev_warn(dev, "Failed to send virtchnl command %s-%d\n",
			 virtchnl_op_str(vc_msg->v_opcode), vc_msg->v_opcode);
	}

	if (list_empty(&adapter->vc_msg_queue.msgs))
		/* no further messages to send */
		adapter->aq_required &= ~IAVF_FLAG_AQ_MSG_QUEUE_PENDING;

out_unlock:
	spin_unlock(&adapter->vc_msg_queue.lock);
}

/**
 * iavf_flush_vc_msg_queue - remove and delete any/all matching command(s)
 * @adapter: private adapter structure
 * @op_match: function pointer used for finding ops that match pending_op
 *
 * All commands that match based on the op_match function passed in will be
 * removed from the queue and deleted.
 */
void
iavf_flush_vc_msg_queue(struct iavf_adapter *adapter,
			bool (*op_match)(enum virtchnl_ops pending_op))
{
	struct iavf_vc_msg *vc_msg, *tmp;

	/* Cancel any remaining uncompleted commands that match */
	spin_lock(&adapter->vc_msg_queue.lock);
	list_for_each_entry_safe(vc_msg, tmp, &adapter->vc_msg_queue.msgs,
				 list) {
		if (op_match(vc_msg->v_opcode)) {
			list_del(&vc_msg->list);
			kfree(vc_msg);
		}
	}
	if (list_empty(&adapter->vc_msg_queue.msgs))
		adapter->aq_required &= ~IAVF_FLAG_AQ_MSG_QUEUE_PENDING;
	spin_unlock(&adapter->vc_msg_queue.lock);
}

/**
 * iavf_alloc_vc_msg - Allocate a virtchnl message for the message queue
 * @v_opcode: the virtchnl opcode
 * @msglen: length in bytes of the associated virtchnl structure
 *
 * Allocates a virtchnl message for the message queue and pre-fills it with the
 * provided message length and opcode.
 */
struct iavf_vc_msg *iavf_alloc_vc_msg(enum virtchnl_ops v_opcode, u16 msglen)
{
	struct iavf_vc_msg *vc_msg;

	vc_msg = kzalloc(struct_size(vc_msg, msg, msglen), GFP_KERNEL);
	if (!vc_msg)
		return NULL;

	vc_msg->v_opcode = v_opcode;
	vc_msg->msglen = msglen;

	return vc_msg;
}

/**
 * iavf_queue_vc_msg - Queue message to send over virtchnl
 * @adapter: private adapter structure
 * @vc_msg: the virtchnl message to queue
 *
 * Queue the given command structure into the virtchnl message queue to
 * send to the PF.
 */
void iavf_queue_vc_msg(struct iavf_adapter *adapter, struct iavf_vc_msg *vc_msg)
{
	spin_lock(&adapter->vc_msg_queue.lock);
	list_add_tail(&vc_msg->list, &adapter->vc_msg_queue.msgs);
	spin_unlock(&adapter->vc_msg_queue.lock);

	adapter->aq_required |= IAVF_FLAG_AQ_MSG_QUEUE_PENDING;
	mod_delayed_work(iavf_wq, &adapter->watchdog_task, 0);
}

#define IAVF_MAX_SPEED_STRLEN        13

/**
 * iavf_print_link_message - print link up or down
 * @adapter: adapter structure
 *
 * Log a message telling the world of our wonderous link status
 */
static void iavf_print_link_message(struct iavf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int link_speed_mbps;
	char *speed;

	if (!adapter->link_up) {
		netdev_info(netdev, "NIC Link is Down\n");
		return;
	}

	speed = kcalloc(1, IAVF_MAX_SPEED_STRLEN, GFP_KERNEL);
	if (!speed)
		return;

#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
	if (ADV_LINK_SUPPORT(adapter)) {
		link_speed_mbps = adapter->link_speed_mbps;
		goto print_link_msg;
	}

#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */
	switch (adapter->link_speed) {
	case VIRTCHNL_LINK_SPEED_40GB:
		link_speed_mbps = SPEED_40000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		link_speed_mbps = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		link_speed_mbps = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		link_speed_mbps = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_5GB:
		link_speed_mbps = SPEED_5000;
		break;
	case VIRTCHNL_LINK_SPEED_2_5GB:
		link_speed_mbps = SPEED_2500;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		link_speed_mbps = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_100MB:
		link_speed_mbps = SPEED_100;
		break;
	default:
		link_speed_mbps = SPEED_UNKNOWN;
		break;
	}

#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
print_link_msg:
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */
	if (link_speed_mbps > SPEED_1000) {
		if (link_speed_mbps == SPEED_2500)
			snprintf(speed, IAVF_MAX_SPEED_STRLEN, "2.5 Gbps");
		else
		/* convert to Gbps inline */
			snprintf(speed, IAVF_MAX_SPEED_STRLEN, "%d %s",
				 link_speed_mbps / 1000, "Gbps");
	} else if (link_speed_mbps == SPEED_UNKNOWN)
		snprintf(speed, IAVF_MAX_SPEED_STRLEN, "%s", "Unknown Mbps");
	else
		snprintf(speed, IAVF_MAX_SPEED_STRLEN, "%d %s",
			 link_speed_mbps, "Mbps");

	netdev_info(netdev, "NIC Link is Up Speed is %s Full Duplex\n", speed);
#ifndef SPEED_25000
	netdev_info(netdev, "Ethtool won't report 25 Gbps Link Speed correctly on this Kernel, Time for an Upgrade\n");
#endif
	kfree(speed);
}

#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
/**
 * iavf_get_vpe_link_status
 * @adapter: adapter structure
 * @vpe: virtchnl_pf_event structure
 *
 * Helper function for determining the link status
 **/
static bool
iavf_get_vpe_link_status(struct iavf_adapter *adapter,
			   struct virtchnl_pf_event *vpe)
{
	if (ADV_LINK_SUPPORT(adapter))
		return vpe->event_data.link_event_adv.link_status;
	else
		return vpe->event_data.link_event.link_status;
}

/**
 * iavf_set_adapter_link_speed_from_vpe
 * @adapter: adapter structure for which we are setting the link speed
 * @vpe: virtchnl_pf_event structure that contains the link speed we are setting
 *
 * Helper function for setting iavf_adapter link speed
 **/
static void
iavf_set_adapter_link_speed_from_vpe(struct iavf_adapter *adapter,
				       struct virtchnl_pf_event *vpe)
{
	if (ADV_LINK_SUPPORT(adapter))
		adapter->link_speed_mbps =
			vpe->event_data.link_event_adv.link_speed;
	else
		adapter->link_speed = vpe->event_data.link_event.link_speed;
}

#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */
/**
 * iavf_enable_channels
 * @adapter: adapter structure
 *
 * Request that the PF enable channels as specified by
 * the user via tc tool.
 **/
void iavf_enable_channels(struct iavf_adapter *adapter)
{
	struct virtchnl_tc_info *vti = NULL;
	u16 len;
	int i;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot configure mqprio, command %d pending\n",
			adapter->current_op);
		return;
	}

	len = ((adapter->num_tc - 1) * sizeof(struct virtchnl_channel_info)) +
	       sizeof(struct virtchnl_tc_info);

	vti = kzalloc(len, GFP_KERNEL);
	if (!vti)
		return;
	vti->num_tc = adapter->num_tc;
	for (i = 0; i < vti->num_tc; i++) {
		vti->list[i].count = adapter->ch_config.ch_info[i].count;
		vti->list[i].offset = adapter->ch_config.ch_info[i].offset;
		vti->list[i].pad = 0;
		vti->list[i].max_tx_rate =
				adapter->ch_config.ch_info[i].max_tx_rate;
	}

	adapter->ch_config.state = __IAVF_TC_RUNNING;
	adapter->flags |= IAVF_FLAG_REINIT_ITR_NEEDED;
	adapter->current_op = VIRTCHNL_OP_ENABLE_CHANNELS;
	adapter->aq_required &= ~IAVF_FLAG_AQ_ENABLE_CHANNELS;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_ENABLE_CHANNELS, (u8 *)vti, len);
	kfree(vti);
}

/**
 * iavf_disable_channels
 * @adapter: adapter structure
 *
 * Request that the PF disable channels that are configured
 **/
void iavf_disable_channels(struct iavf_adapter *adapter)
{
	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot configure mqprio, command %d pending\n",
			adapter->current_op);
		return;
	}

	adapter->ch_config.state = __IAVF_TC_INVALID;
	adapter->flags |= IAVF_FLAG_REINIT_ITR_NEEDED;
	adapter->current_op = VIRTCHNL_OP_DISABLE_CHANNELS;
	adapter->aq_required &= ~IAVF_FLAG_AQ_DISABLE_CHANNELS;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_DISABLE_CHANNELS, NULL, 0);
}

/**
 * iavf_print_cloud_filter
 * @adapter: adapter structure
 * @f: cloud filter to print
 *
 * Print the cloud filter
 **/
static void iavf_print_cloud_filter(struct iavf_adapter *adapter,
				    struct virtchnl_filter *f)
{
	switch (f->flow_type) {
	case VIRTCHNL_TCP_V4_FLOW:
		dev_info(&adapter->pdev->dev, "dst_mac: %pM src_mac: %pM vlan_id: %hu dst_ip: %pI4 src_ip %pI4 TCP: dst_port %hu src_port %hu\n",
			 &f->data.tcp_spec.dst_mac,
			 &f->data.tcp_spec.src_mac,
			 ntohs(f->data.tcp_spec.vlan_id),
			 &f->data.tcp_spec.dst_ip[0],
			 &f->data.tcp_spec.src_ip[0],
			 ntohs(f->data.tcp_spec.dst_port),
			 ntohs(f->data.tcp_spec.src_port));
		break;
	case VIRTCHNL_TCP_V6_FLOW:
		dev_info(&adapter->pdev->dev, "dst_mac: %pM src_mac: %pM vlan_id: %hu dst_ip: %pI6 src_ip %pI6 TCP: dst_port %hu tcp_src_port %hu\n",
			 &f->data.tcp_spec.dst_mac,
			 &f->data.tcp_spec.src_mac,
			 ntohs(f->data.tcp_spec.vlan_id),
			 &f->data.tcp_spec.dst_ip,
			 &f->data.tcp_spec.src_ip,
			 ntohs(f->data.tcp_spec.dst_port),
			 ntohs(f->data.tcp_spec.src_port));
		break;
	case VIRTCHNL_UDP_V4_FLOW:
		dev_info(&adapter->pdev->dev, "dst_mac: %pM src_mac: %pM vlan_id: %hu dst_ip: %pI4 src_ip %pI4 UDP: dst_port %hu udp_src_port %hu\n",
			 &f->data.tcp_spec.dst_mac,
			 &f->data.tcp_spec.src_mac,
			 ntohs(f->data.tcp_spec.vlan_id),
			 &f->data.tcp_spec.dst_ip[0],
			 &f->data.tcp_spec.src_ip[0],
			 ntohs(f->data.tcp_spec.dst_port),
			 ntohs(f->data.tcp_spec.src_port));
		break;
	case VIRTCHNL_UDP_V6_FLOW:
		dev_info(&adapter->pdev->dev, "dst_mac: %pM src_mac: %pM vlan_id: %hu dst_ip: %pI6 src_ip %pI6 UDP: dst_port %hu tcp_src_port %hu\n",
			 &f->data.tcp_spec.dst_mac,
			 &f->data.tcp_spec.src_mac,
			 ntohs(f->data.tcp_spec.vlan_id),
			 &f->data.tcp_spec.dst_ip,
			 &f->data.tcp_spec.src_ip,
			 ntohs(f->data.tcp_spec.dst_port),
			 ntohs(f->data.tcp_spec.src_port));
		break;
	}
}

/**
 * iavf_add_cloud_filter
 * @adapter: adapter structure
 *
 * Request that the PF add cloud filters as specified
 * by the user via tc tool.
 **/
void iavf_add_cloud_filter(struct iavf_adapter *adapter)
{
	struct iavf_cloud_filter *cf;
	struct virtchnl_filter *f;
	bool process_fltr = false;
	int len = 0;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot add cloud filter, command %d pending\n",
			adapter->current_op);
		return;
	}

	len = sizeof(struct virtchnl_filter);
	f = kzalloc(len, GFP_KERNEL);
	if (!f)
		return;

	/* Only add a single cloud filter per call to iavf_add_cloud_filter(),
	 * the aq_required IAVF_FLAG_AQ_ADD_CLOUD_FILTER bit will be set until
	 * no filters are left to add
	 */
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	list_for_each_entry(cf, &adapter->cloud_filter_list, list) {
		if (cf->add) {
			process_fltr = true;
			cf->add = false;
			cf->state = __IAVF_CF_ADD_PENDING;
			*f = cf->f;
			/* must to store channel ptr in cloud filter if action
			 * is TC_REDIRECT since it is used later
			 */
			if (f->action == VIRTCHNL_ACTION_TC_REDIRECT) {
				u32 tc = f->action_meta;

				cf->ch = &adapter->ch_config.ch_ex_info[tc];
			}
			break;
		}
	}
	spin_unlock_bh(&adapter->cloud_filter_list_lock);

	if (!process_fltr) {
		/* prevent iavf_add_cloud_filter() from being called when there
		 * are no filters to add
		 */
		adapter->aq_required &= ~IAVF_FLAG_AQ_ADD_CLOUD_FILTER;
		kfree(f);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_ADD_CLOUD_FILTER;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_CLOUD_FILTER, (u8 *)f, len);
	kfree(f);
}

/**
 * iavf_del_cloud_filter
 * @adapter: adapter structure
 *
 * Request that the PF delete cloud filters as specified
 * by the user via tc tool.
 **/
void iavf_del_cloud_filter(struct iavf_adapter *adapter)
{
	struct iavf_cloud_filter *cf;
	struct virtchnl_filter *f;
	bool process_fltr = false;
	int len = 0;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev, "Cannot remove cloud filter, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_filter);
	f = kzalloc(len, GFP_KERNEL);
	if (!f)
		return;

	/* Only delete a single cloud filter per call to iavf_del_cloud_filter()
	 * the aq_required IAVF_FLAG_AQ_DEL_CLOUD_FILTER bit will be set until
	 * no filters are left to delete
	 */
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	list_for_each_entry(cf, &adapter->cloud_filter_list, list) {
		if (cf->del) {
			process_fltr = true;
			*f = cf->f;
			cf->del = false;
			cf->state = __IAVF_CF_DEL_PENDING;
			break;
		}
	}
	spin_unlock_bh(&adapter->cloud_filter_list_lock);

	if (!process_fltr) {
		/* prevent iavf_del_cloud_filter() from being called when there
		 * are no filters to delete
		 */
		adapter->aq_required &= ~IAVF_FLAG_AQ_DEL_CLOUD_FILTER;
		kfree(f);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_DEL_CLOUD_FILTER;
	iavf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_CLOUD_FILTER, (u8 *)f, len);
	kfree(f);
}

/**
 * iavf_request_reset
 * @adapter: adapter structure
 *
 * Request that the PF reset this VF. No response is expected.
 **/
int iavf_request_reset(struct iavf_adapter *adapter)
{
	int err;

	/* Don't check CURRENT_OP - this is always higher priority */
	err = iavf_send_pf_msg(adapter, VIRTCHNL_OP_RESET_VF, NULL, 0);
	adapter->current_op = VIRTCHNL_OP_UNKNOWN;
	return err;
}

/**
 * iavf_clear_chnl_ring_attr - clears  rings attributes specific to channel
 * @adapter: adapter structure
 * @ring: Pointer to ring (Tx/Rx)
 * @tx: TRUE means Tx and FALSE means Rx
 *
 * This function clears up ring attributes such as feature flag (optimization
 * enabled or not, also resets vector feature flags associated with queue)
 **/
static void iavf_clear_chnl_ring_attr(struct iavf_adapter *adapter,
				      struct iavf_ring *ring,
				      bool tx)
{
	struct iavf_q_vector *qv = ring->q_vector;

	ring->ch = NULL;
	ring->chnl_flags &= ~IAVF_RING_CHNL_PERF_ENA;
	dev_dbg(&adapter->pdev->dev,
		"%s_ring %u, ch_ena: %u, perf_ena: %u\n",
		tx ? "Tx" : "Rx", ring->queue_index, ring_ch_ena(ring),
		ring_ch_perf_ena(ring));

	if (!qv)
		return;

	qv->ch = NULL;

	/* revive the vector from ADQ state machine
	 * by triggering SW interrupt
	 */
	iavf_force_wb(&adapter->vsi, qv);
	qv->chnl_flags &= ~IAVF_VECTOR_CHNL_PERF_ENA;
	dev_dbg(&adapter->pdev->dev,
		"vector(idx: %u): ch_ena: %u, perf_ena: %u\n",
		qv->v_idx, vector_ch_ena(qv), vector_ch_perf_ena(qv));
}

/**
 * iavf_clear_ch_info - clears channel specific information and flags_
 * @adapter: adapter structure
 *
 * This function clears channel specific configurations, flags for
 * Tx, Rx queues, related vectors and triggers software interrupt
 * to revive the ADQ specific vectors, so that vector is put back in
 * interrupt state
 **/
static void iavf_clear_ch_info(struct iavf_adapter *adapter)
{
	int tc, q;

	/* to avoid running iAVF on older HW, do not want to support
	 * ADQ related performance bits, hence checking the ADQ_V2 as
	 * run-time type and prevent if ADQ_V2 is not set.
	 */
	if (!iavf_is_adq_v2_enabled(adapter))
		return;

	for (tc = 0; tc < VIRTCHNL_MAX_ADQ_V2_CHANNELS; tc++) {
		struct iavf_channel_ex *ch;
		int num_rxq;

		ch = &adapter->ch_config.ch_ex_info[tc];
		if (!ch)
			continue;

		/* unlikely but make sure to have non-zero "num_rxq" for
		 * channel otherwise skip..
		 */
		num_rxq = ch->num_rxq;
		if (!num_rxq)
			continue;

		/* proceed only when there is no active filter
		 * for given channel
		 */
		if (ch->num_fltr)
			continue;

		/* do not proceed unless we have vectors >= num_active_queues.
		 * In future, this is subject to change if interrupt to queue
		 * assignment policy changesm but for now - expect as many
		 * vectors as data_queues
		 */
		if (adapter->num_msix_vectors <= adapter->num_active_queues)
			continue;

		for (q = 0; q < num_rxq; q++) {
			struct iavf_ring *tx_ring, *rx_ring;

			tx_ring = &adapter->tx_rings[ch->base_q + q];
			rx_ring = &adapter->rx_rings[ch->base_q + q];
			if (tx_ring)
				iavf_clear_chnl_ring_attr(adapter, tx_ring,
							  true);
			if (rx_ring)
				iavf_clear_chnl_ring_attr(adapter, rx_ring,
							  false);
		}
	}
}

/**
 * iavf_set_chnl_ring_attr - sets rings attributes specific to channel
 * @adapter: adapter structure
 * @flags: adapter specific flags (various feature bits)
 * @ring: Pointer to ring (Tx/Rx)
 * @ch: Pointer to channel
 * @tx: TRUE means Tx and FALSE means Rx
 *
 * This function sets up ring attributes such as feature flag (optimization
 * enabled or not, also sets up vector feature flags associated with queue)
 **/
static void iavf_set_chnl_ring_attr(struct iavf_adapter *adapter, u32 flags,
				    struct iavf_ring *ring,
				    struct iavf_channel_ex *ch,
				    bool tx)
{
	struct iavf_q_vector *qv = ring->q_vector;

	ring->ch = ch;
	ring->chnl_flags |= IAVF_RING_CHNL_PERF_ENA;
	dev_dbg(&adapter->pdev->dev, "%s_ring %u, ch_ena: %u, perf_ena: %u\n",
		tx ? "Tx" : "Rx", ring->queue_index, ring_ch_ena(ring),
		ring_ch_perf_ena(ring));

	if (!qv)
		return;

	qv->ch = ch;
	qv->chnl_flags |= IAVF_VECTOR_CHNL_PERF_ENA;
	if (flags & IAVF_FLAG_CHNL_PKT_OPT_ENA)
		qv->chnl_flags |= IAVF_VECTOR_CHNL_PKT_OPT_ENA;
	else
		qv->chnl_flags &= ~IAVF_VECTOR_CHNL_PKT_OPT_ENA;
	dev_dbg(&adapter->pdev->dev,
		"vector(idx %u): ch_ena: %u, perf_ena: %u\n",
		qv->v_idx, vector_ch_ena(qv), vector_ch_perf_ena(qv));
}

/**
 * iavf_setup_ch_info - sets channel specific information and flags
 * @adapter: adapter structure
 * @flags: adapter specific flags (various feature bits)
 *
 * This function sets up queues (Tx and Rx) and vector specific flags
 * as appliable for ADQ. This function is invoked as soon as filters
 * were added successfully, so that queues and vectors are setup to engage
 * for optimized packets processing using ADQ state machine based logic.
 **/
void iavf_setup_ch_info(struct iavf_adapter *adapter, u32 flags)
{
	int tc;

	/* to avoid running iAVF on older HW, do not want to support
	 * ADQ related performance bits, hence checking the ADQ_V2 as
	 * run-time type and prevent if ADQ_V2 is not set.
	 */
	if (!iavf_is_adq_v2_enabled(adapter))
		return;

	for (tc = 0; tc < VIRTCHNL_MAX_ADQ_V2_CHANNELS; tc++) {
		struct iavf_channel_ex *ch;
		int num_rxq, q;

		ch = &adapter->ch_config.ch_ex_info[tc];
		if (!ch)
			continue;

		/* unlikely but make sure to have non-zero "num_rxq" for
		 * channel otherwise skip..
		 */
		num_rxq = ch->num_rxq;
		if (!num_rxq)
			continue;

		/* do not proceed unless there is at least one filter
		 * for given channel
		 */
		if (!ch->num_fltr)
			continue;

		/* do not proceed unless we have vectors >= num_active_queues.
		 * In future, this is subject to change if interrupt to queue
		 * assignment policy changesm but for now - expect as many
		 * vectors as data_queues
		 */
		if (adapter->num_msix_vectors <= adapter->num_active_queues)
			continue;

		for (q = 0; q < num_rxq; q++) {
			struct iavf_ring *tx_ring, *rx_ring;

			tx_ring = &adapter->tx_rings[ch->base_q + q];
			rx_ring = &adapter->rx_rings[ch->base_q + q];
			if (tx_ring)
				iavf_set_chnl_ring_attr(adapter, flags,
							tx_ring, ch, true);
			if (rx_ring)
				iavf_set_chnl_ring_attr(adapter, flags,
							rx_ring, ch, false);
		}
	}
}

/**
 * iavf_netdev_features_vlan_strip_set
 * @netdev: ptr to netdev being adjusted
 * @enable: enable or disable vlan strip
 *
 * Helper function to change vlan strip status in netdev->features.
 **/
static void iavf_netdev_features_vlan_strip_set(struct net_device *netdev,
						const bool enable)
{
	if (enable)
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		netdev->features |= NETIF_F_HW_VLAN_CTAG_RX;
#else
		netdev->features |= NETIF_F_HW_VLAN_RX;
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
	else
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
#else
		netdev->features &= ~NETIF_F_HW_VLAN_RX;
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
}

/**
 * iavf_virtchnl_rdma_irq_map - Handle receive of IRQ mapping message from PF
 * @adapter: private adapter structure
 * @v_retval: result of the received virtchnl message
 *
 * Called when the VF gets a VIRTCHNL_OP_RDMA_CONFIG_IRQ_MAP or
 * VIRTCHNL_OP_RDMA_RELEASE_IRQ_MAP message from the PF.
 */
static void
iavf_virtchnl_rdma_irq_map(struct iavf_adapter *adapter,
			   enum virtchnl_status_code v_retval)
{
	if (adapter->rdma.vc_op_state != IAVF_RDMA_VC_OP_PENDING)
		dev_warn(&adapter->pdev->dev, "Unexpected vc_op_state %u\n",
			 adapter->rdma.vc_op_state);

	if (!v_retval)
		adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_COMPLETE;
	else
		adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_FAILED;

	wake_up(&adapter->rdma.vc_op_waitqueue);
}

/**
 * iavf_virtchnl_completion
 * @adapter: adapter structure
 * @v_opcode: opcode sent by PF
 * @v_retval: virtchnl status code return value sent by PF
 * @msg: message sent by PF
 * @msglen: message length
 *
 * Asynchronous completion function for admin queue messages. Rather than busy
 * wait, we fire off our requests and assume that no errors will be returned.
 * This function handles the reply messages.
 **/
void iavf_virtchnl_completion(struct iavf_adapter *adapter,
			      enum virtchnl_ops v_opcode,
			      enum virtchnl_status_code v_retval,
			      u8 *msg, u16 msglen)
{
	struct net_device *netdev = adapter->netdev;
	struct device *dev = &adapter->pdev->dev;

	if (v_opcode == VIRTCHNL_OP_EVENT) {
		struct virtchnl_pf_event *vpe =
			(struct virtchnl_pf_event *)msg;
#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
		bool link_up = iavf_get_vpe_link_status(adapter, vpe);
#else
		bool link_up = vpe->event_data.link_event.link_status;
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */

		switch (vpe->event) {
		case VIRTCHNL_EVENT_LINK_CHANGE:
#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
			iavf_set_adapter_link_speed_from_vpe(adapter, vpe);
#else
			adapter->link_speed =
				vpe->event_data.link_event.link_speed;
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */

			/* we've already got the right link status, bail */
			if (adapter->link_up == link_up)
				break;

			if (link_up) {
				/* If we get link up message and start queues
				 * before our queues are configured it will
				 * trigger a TX hang. In that case, just ignore
				 * the link status message,we'll get another one
				 * after we enable queues and actually prepared
				 * to send traffic.
				 */
				if (adapter->state != __IAVF_RUNNING)
					break;

				/* For ADQ enabled VF, we reconfigure VSIs and
				 * re-allocate queues. Hence wait till all
				 * queues are enabled.
				 */
				if (adapter->flags &
				    IAVF_FLAG_QUEUES_DISABLED)
					break;
			}

			adapter->link_up = link_up;
			if (link_up) {
				if  (adapter->flags &
				     IAVF_FLAG_QUEUES_ENABLED) {
					netif_tx_start_all_queues(netdev);
					netif_carrier_on(netdev);
				}
			} else {
				netif_tx_stop_all_queues(netdev);
				netif_carrier_off(netdev);
			}
			iavf_print_link_message(adapter);
			break;
		case VIRTCHNL_EVENT_RESET_IMPENDING:
			dev_info(dev, "Reset indication received from the PF\n");
			adapter->flags |= IAVF_FLAG_RESET_PENDING;
			iavf_schedule_reset(adapter);
			break;
		default:
			dev_err(dev, "Unknown event %d from PF\n",
				vpe->event);
			break;
		}
		return;
	}

	/* In earlier versions of ADQ implementation, VF reset was initiated by
	 * PF in response to enable ADQ request from VF. However for performance
	 * of ADQ we need the response back and based on that additional configs
	 * will be done. So don't let the PF reset the VF instead let the VF
	 * reset itself.
	 */
	if (ADQ_V2_ALLOWED(adapter) && !v_retval &&
	    (v_opcode == VIRTCHNL_OP_ENABLE_CHANNELS ||
	     v_opcode == VIRTCHNL_OP_DISABLE_CHANNELS)) {
		adapter->flags |= IAVF_FLAG_REINIT_CHNL_NEEDED;
		dev_info(dev, "Scheduling reset due to %s retval %d\n",
			 v_opcode == VIRTCHNL_OP_ENABLE_CHANNELS ?
			 "VIRTCHNL_OP_ENABLE_CHANNELS" :
			 "VIRTCHNL_OP_DISABLE_CHANNELS", v_retval);
		/* schedule reset always if processing ENABLE/DISABLE_CHANNEL
		 * ops so that as part of reset handling, appropriate steps are
		 * taken such as num_tc, per TC queue_map, etc...
		 */
		iavf_schedule_reset(adapter);
	}

	if (v_retval) {
		switch (v_opcode) {
		case VIRTCHNL_OP_ADD_VLAN:
			dev_err(dev, "Failed to add VLAN filter, error %s\n",
				virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_ADD_ETH_ADDR:
			dev_err(dev, "Failed to add MAC filter, error %s\n",
				virtchnl_stat_str(v_retval));
			iavf_netdev_mc_mac_add_reject(adapter);
			iavf_mac_add_reject(adapter);
			/* restore administratively set mac address */
			ether_addr_copy(adapter->hw.mac.addr, netdev->dev_addr);
			wake_up(&adapter->vc_waitqueue);
			break;
		case VIRTCHNL_OP_DEL_VLAN:
			dev_err(dev, "Failed to delete VLAN filter, error %s\n",
				virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_DEL_ETH_ADDR:
			dev_err(dev, "Failed to delete MAC filter, error %s\n",
				virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_ENABLE_CHANNELS:
			dev_err(dev, "Failed to configure queue channels, error %s\n",
				virtchnl_stat_str(v_retval));
			adapter->flags &= ~IAVF_FLAG_REINIT_ITR_NEEDED;
			adapter->ch_config.state = __IAVF_TC_INVALID;
			netdev_reset_tc(netdev);
			netif_tx_start_all_queues(netdev);
			break;
		case VIRTCHNL_OP_DISABLE_CHANNELS:
			dev_err(dev, "Failed to disable queue channels, error %s\n",
				virtchnl_stat_str(v_retval));
			adapter->flags &= ~IAVF_FLAG_REINIT_ITR_NEEDED;
			adapter->ch_config.state = __IAVF_TC_RUNNING;
			netif_tx_start_all_queues(netdev);
			break;
		case VIRTCHNL_OP_ADD_CLOUD_FILTER: {
			struct iavf_cloud_filter *cf, *cftmp;

			spin_lock_bh(&adapter->cloud_filter_list_lock);
			list_for_each_entry_safe(cf, cftmp,
						 &adapter->cloud_filter_list,
						 list) {
				if (cf->state == __IAVF_CF_ADD_PENDING) {
					cf->state = __IAVF_CF_INVALID;
					dev_info(dev, "Failed to add cloud filter, error %s\n",
						 virtchnl_stat_str(v_retval));
					iavf_print_cloud_filter(adapter,
								&cf->f);
					if (msglen)
						dev_err(dev, "%s\n", msg);
					list_del(&cf->list);
					kfree(cf);
					adapter->num_cloud_filters--;
				}
			}
			spin_unlock_bh(&adapter->cloud_filter_list_lock);
			}
			break;
		case VIRTCHNL_OP_DEL_CLOUD_FILTER: {
			struct iavf_cloud_filter *cf;

			spin_lock_bh(&adapter->cloud_filter_list_lock);
			list_for_each_entry(cf, &adapter->cloud_filter_list,
					    list) {
				if (cf->state == __IAVF_CF_DEL_PENDING) {
					cf->state = __IAVF_CF_ACTIVE;
					dev_info(dev, "Failed to del cloud filter, error %s\n",
						 virtchnl_stat_str(v_retval));
					iavf_print_cloud_filter(adapter,
								&cf->f);
				}
			}
			spin_unlock_bh(&adapter->cloud_filter_list_lock);
			}
			break;
		case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
			dev_warn(dev, "Changing VLAN Stripping is not allowed when Port VLAN is configured\n");
			/*
			 * Vlan stripping could not be enabled by ethtool.
			 * Disable it in netdev->features.
			 */
			iavf_netdev_features_vlan_strip_set(netdev, false);
			break;
		case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
			dev_warn(dev, "Changing VLAN Stripping is not allowed when Port VLAN is configured\n");
			/*
			 * Vlan stripping could not be disabled by ethtool.
			 * Enable it in netdev->features.
			 */
			iavf_netdev_features_vlan_strip_set(netdev, true);
			break;
		case VIRTCHNL_OP_1588_PTP_GET_TIME:
			dev_warn(dev, "Failed to get PHC clock time, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_1588_PTP_SET_TIME:
			dev_warn(dev, "Failed to set PHC clock time, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_1588_PTP_ADJ_TIME:
			dev_warn(dev, "Failed to adjust PHC clock time, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_1588_PTP_ADJ_FREQ:
			dev_warn(dev, "Failed to adjust PHC clock frequency, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_1588_PTP_SET_PIN_CFG:
			dev_warn(dev, "Failed to configure PHC GPIO pin, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS:
			dev_warn(dev, "Failed to get PHC GPIO pin config, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_HW_INFO:
			dev_warn(dev, "Failed to get HW_INFO, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_PHY_REC_CLK_OUT:
			dev_warn(dev, "Failed to get PHY REC CLK OUT config, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS:
			dev_warn(dev, "Failed to get CGU_DPLL_STATUS, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO:
			dev_warn(dev, "Failed to get CGU_REF_PRIO, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_CGU_INFO:
			dev_warn(dev, "Failed to get CGU_INFO, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES:
			dev_warn(dev, "Failed to get CGU_ABILITIES, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_INPUT_PIN_CFG:
			dev_warn(dev, "Failed to get INPUT_PIN_CFG, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG:
			dev_warn(dev, "Failed to get OUTPUT_PIN_CFG, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_GNSS_READ_I2C:
			dev_warn(dev, "Failed to get GNSS READ I2C Response, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_GNSS_WRITE_I2C:
			dev_warn(dev, "Failed to get GNSS WRITE I2C Response, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		case VIRTCHNL_OP_ADD_VLAN_V2:
			iavf_vlan_add_reject(adapter);
			dev_warn(dev, "Failed to add VLAN filter, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		default:
			dev_err(dev, "PF returned error %d (%s) to our request %d\n",
				v_retval, virtchnl_stat_str(v_retval),
				v_opcode);

			/* Assume that the ADQ configuration caused one of the
			 * v_opcodes in this if statement to fail.  Set the
			 * flag so the reset path can return to the pre-ADQ
			 * configuration and traffic can resume
			 */
			if (iavf_is_adq_enabled(adapter) &&
			    (v_opcode == VIRTCHNL_OP_ENABLE_QUEUES ||
			     v_opcode == VIRTCHNL_OP_CONFIG_IRQ_MAP ||
			     v_opcode == VIRTCHNL_OP_CONFIG_VSI_QUEUES)) {
				dev_err(dev, "ADQ is enabled and opcode %d failed (%d)\n",
					v_opcode, v_retval);
				adapter->ch_config.state = __IAVF_TC_INVALID;
				adapter->num_tc = 0;
				netdev_reset_tc(netdev);
				adapter->flags |= IAVF_FLAG_REINIT_ITR_NEEDED;
				iavf_schedule_reset(adapter);
				adapter->current_op = VIRTCHNL_OP_UNKNOWN;
				return;
			}
		}
	}
	switch (v_opcode) {
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		if (!v_retval)
			iavf_mac_add_ok(adapter);
		if (!ether_addr_equal(netdev->dev_addr, adapter->hw.mac.addr)) {
			netif_addr_lock_bh(netdev);
			eth_hw_addr_set(netdev, adapter->hw.mac.addr);
			netif_addr_unlock_bh(netdev);
		}
		wake_up(&adapter->vc_waitqueue);
		break;
	case VIRTCHNL_OP_GET_STATS: {
		struct iavf_eth_stats *stats =
			(struct iavf_eth_stats *)msg;
		adapter->net_stats.rx_packets = stats->rx_unicast +
						 stats->rx_multicast +
						 stats->rx_broadcast;
		adapter->net_stats.tx_packets = stats->tx_unicast +
						 stats->tx_multicast +
						 stats->tx_broadcast;
		adapter->net_stats.rx_bytes = stats->rx_bytes;
		adapter->net_stats.tx_bytes = stats->tx_bytes;
		adapter->net_stats.tx_errors = stats->tx_errors;
		adapter->net_stats.rx_dropped = stats->rx_discards;
		adapter->net_stats.tx_dropped = stats->tx_discards;
		adapter->current_stats = *stats;
		}
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES: {
		u16 len = sizeof(struct virtchnl_vf_resource) +
			  IAVF_MAX_VF_VSI *
			  sizeof(struct virtchnl_vsi_resource);

		memcpy(adapter->vf_res, msg, min(msglen, len));
		iavf_validate_num_queues(adapter);
		iavf_vf_parse_hw_config(&adapter->hw, adapter->vf_res);
		if (is_zero_ether_addr(adapter->hw.mac.addr)) {
			/* restore current mac address */
			ether_addr_copy(adapter->hw.mac.addr, netdev->dev_addr);
		} else {
			netif_addr_lock_bh(netdev);
			/* refresh current mac address if changed */
			ether_addr_copy(netdev->perm_addr,
					adapter->hw.mac.addr);
			netif_addr_unlock_bh(netdev);
		}

		iavf_parse_vf_resource_msg(adapter);

		/* negotiated VIRTCHNL_VF_OFFLOAD_VLAN_V2, so wait for the
		 * response to VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS to finish
		 * configuration
		 */
		if (VLAN_V2_ALLOWED(adapter))
			break;
		/* fall-through and finish config if VIRTCHNL_VF_OFFLOAD_VLAN_V2
		 * wasn't successfully negotiated with the PF
		 */
		}
		fallthrough;
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS: {
		struct iavf_mac_filter *f;
		bool was_mac_changed;
		u64 aq_required = 0;

		if (v_opcode == VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS)
			memcpy(&adapter->vlan_v2_caps, msg,
			       min_t(u16, msglen,
				     sizeof(adapter->vlan_v2_caps)));

		iavf_process_config(adapter);

		adapter->flags |= IAVF_FLAG_UPDATE_NETDEV_FEATURES;

		iavf_set_queue_vlan_tag_loc(adapter);

		was_mac_changed = !ether_addr_equal(netdev->dev_addr,
						    adapter->hw.mac.addr);

		spin_lock_bh(&adapter->mac_vlan_list_lock);

		/* re-add all MAC filters */
		list_for_each_entry(f, &adapter->mac_filter_list, list) {
			if (was_mac_changed &&
			    ether_addr_equal(netdev->dev_addr, f->macaddr))
				ether_addr_copy(f->macaddr,
						adapter->hw.mac.addr);

			f->is_new_mac = true;
			f->add = true;
			f->add_handled = false;
			f->remove = false;
		}

		/* re-add all VLAN filters */
		if (VLAN_FILTERING_ALLOWED(adapter)) {
			struct iavf_vlan_filter *vlf;

			if (!list_empty(&adapter->vlan_filter_list)) {
				list_for_each_entry(vlf,
						    &adapter->vlan_filter_list,
						    list)
					vlf->state = IAVF_VLAN_ADD;

				aq_required |= IAVF_FLAG_AQ_ADD_VLAN_FILTER;
			}
		}

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		/* check if TCs are running and re-add all cloud filters
		 * Set ADD_CLOUD_FILTER only if list is not empty so that
		 * re-add of filters can happen correctly
		 */
		if (iavf_is_adq_enabled(adapter) ||
		    iavf_is_adq_v2_enabled(adapter)) {
			struct iavf_cloud_filter *cf;

			spin_lock_bh(&adapter->cloud_filter_list_lock);
			if (!list_empty(&adapter->cloud_filter_list)) {
				list_for_each_entry(cf,
						    &adapter->cloud_filter_list,
						    list) {
					cf->add = true;
				}
				aq_required |= IAVF_FLAG_AQ_ADD_CLOUD_FILTER;
			}
			spin_unlock_bh(&adapter->cloud_filter_list_lock);
		}

		netif_addr_lock_bh(netdev);
		eth_hw_addr_set(netdev, adapter->hw.mac.addr);
		netif_addr_unlock_bh(netdev);

		adapter->aq_required |= IAVF_FLAG_AQ_ADD_MAC_FILTER |
			aq_required;
		}
		break;
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		memcpy(&adapter->supported_rxdids, msg,
		       min_t(u16, msglen,
			     sizeof(adapter->supported_rxdids)));
		break;
	case VIRTCHNL_OP_1588_PTP_GET_CAPS:
		memcpy(&adapter->ptp.hw_caps, msg,
		       min_t(u16, msglen, sizeof(adapter->ptp.hw_caps)));
		/* process any state change needed due to new capabilities */
		iavf_ptp_process_caps(adapter);
		break;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	case VIRTCHNL_OP_1588_PTP_GET_TIME:
		iavf_virtchnl_ptp_get_time(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_1588_PTP_TX_TIMESTAMP:
		iavf_virtchnl_ptp_tx_timestamp(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_1588_PTP_SET_PIN_CFG:
		iavf_virtchnl_ptp_pin_status(adapter, v_retval);
		break;
	case VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS:
		iavf_virtchnl_ptp_get_pin_cfgs(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP:
		iavf_virtchnl_ptp_ext_timestamp(adapter, msg, msglen);
		break;
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
	case VIRTCHNL_OP_SYNCE_GET_PHY_REC_CLK_OUT:
		iavf_virtchnl_synce_get_phy_rec_clk_out(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS:
		iavf_virtchnl_synce_get_cgu_dpll_status(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO:
		iavf_virtchnl_synce_get_cgu_ref_prio(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_CGU_INFO:
		iavf_virtchnl_synce_get_cgu_info(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES:
		iavf_virtchnl_synce_get_cgu_abilities(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_INPUT_PIN_CFG:
		iavf_virtchnl_synce_get_input_pin_cfg(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG:
		iavf_virtchnl_synce_get_output_pin_cfg(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_GNSS_READ_I2C:
		iavf_virtchnl_gnss_read_i2c(adapter, msg, msglen);
		break;
	case VIRTCHNL_OP_GNSS_WRITE_I2C:
		iavf_virtchnl_gnss_write_i2c(adapter);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
	case VIRTCHNL_OP_ENABLE_QUEUES_V2:
		/* enable transmits */
		if (adapter->state == __IAVF_RUNNING) {
			iavf_irq_enable(adapter, true);

			/* If queues not enabled when handling link event,
			 * then set carrier on now
			 */
			if (adapter->link_up && !netif_carrier_ok(netdev)) {
				netif_tx_start_all_queues(netdev);
				netif_carrier_on(netdev);
			}
			wake_up(&adapter->reset_waitqueue);
		}
		adapter->flags |= IAVF_FLAG_QUEUES_ENABLED;
		adapter->flags &= ~IAVF_FLAG_QUEUES_DISABLED;
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
	case VIRTCHNL_OP_DISABLE_QUEUES_V2:
		iavf_free_all_tx_resources(adapter);
		iavf_free_all_rx_resources(adapter);
		if (adapter->state == __IAVF_DOWN_PENDING) {
			iavf_change_state(adapter, __IAVF_DOWN);
			wake_up(&adapter->down_waitqueue);
		}
		adapter->flags &= ~IAVF_FLAG_QUEUES_ENABLED;
		break;
	case VIRTCHNL_OP_VERSION:
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
	case VIRTCHNL_OP_MAP_QUEUE_VECTOR:
		/* Don't display an error if we get these out of sequence.
		 * If the firmware needed to get kicked, we'll get these and
		 * it's no problem.
		 */
		if (v_opcode != adapter->current_op)
			return;
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS: {
		struct virtchnl_rss_hena *vrh = (struct virtchnl_rss_hena *)msg;
		if (msglen == sizeof(*vrh))
			adapter->hena = vrh->hena;
		else
			dev_warn(dev, "Invalid message %d from PF\n", v_opcode);
		}
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES: {
		struct virtchnl_vf_res_request *vfres =
			(struct virtchnl_vf_res_request *)msg;
		if (vfres->num_queue_pairs != adapter->num_req_queues) {
			dev_info(dev, "Requested %d queues, PF can support %d\n",
				 adapter->num_req_queues,
				 vfres->num_queue_pairs);
			adapter->num_req_queues = 0;
			adapter->flags &= ~IAVF_FLAG_REINIT_ITR_NEEDED;
		}
		}
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER: {
		struct iavf_cloud_filter *cf;

		spin_lock_bh(&adapter->cloud_filter_list_lock);
		list_for_each_entry(cf, &adapter->cloud_filter_list, list) {
			if (cf->state == __IAVF_CF_ADD_PENDING) {
				cf->state = __IAVF_CF_ACTIVE;
				if (cf->ch)
					cf->ch->num_fltr++;
			}
		}
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		if (v_retval == VIRTCHNL_STATUS_SUCCESS)
			dev_dbg(dev, "Cloud filters are added\n");
		/* if not done, set channel specific attribute
		 * such as "is it ADQ enabled", "queues are ADD ena",
		 * "vectors are ADQ ena" or not
		 */
		iavf_setup_ch_info(adapter, adapter->flags);
		}
		break;
	case VIRTCHNL_OP_DEL_CLOUD_FILTER: {
		struct iavf_cloud_filter *cf, *cftmp;

		spin_lock_bh(&adapter->cloud_filter_list_lock);
		list_for_each_entry_safe(cf, cftmp, &adapter->cloud_filter_list,
					 list) {
			if (cf->state == __IAVF_CF_DEL_PENDING) {
				cf->state = __IAVF_CF_INVALID;
				list_del(&cf->list);
				if (cf->ch)
					cf->ch->num_fltr--;
				kfree(cf);
				adapter->num_cloud_filters--;
			}
		}
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		if (v_retval == VIRTCHNL_STATUS_SUCCESS)
			dev_dbg(dev, "Cloud filters are deleted\n");
		/* if active ADQ filters for channels reached zero,
		 * put the rings, vectors back in non-ADQ state
		 */
		iavf_clear_ch_info(adapter);
		}
		break;
	case VIRTCHNL_OP_ADD_VLAN_V2: {
		struct iavf_vlan_filter *f;

		spin_lock_bh(&adapter->mac_vlan_list_lock);
		list_for_each_entry(f, &adapter->vlan_filter_list, list) {
			if (f->state == IAVF_VLAN_IS_NEW)
				f->state = IAVF_VLAN_ACTIVE;
		}
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		}
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
		/*
		 * Got information that PF enabled vlan strip on this VF.
		 * Update netdev->features if needed to be in sync with ethtool.
		 */
		if (!v_retval)
			iavf_netdev_features_vlan_strip_set(netdev, true);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		/*
		 * Got information that PF disabled vlan strip on this VF.
		 * Update netdev->features if needed to be in sync with ethtool.
		 */
		if (!v_retval)
			iavf_netdev_features_vlan_strip_set(netdev, false);
		break;
	case VIRTCHNL_OP_RDMA:
		/* IAVF_RDMA_VC_OP_PENDING is only set for the synchronous
		 * version of vc_send, so make sure we handle both cases
		 */
		if (adapter->rdma.vc_op_state == IAVF_RDMA_VC_OP_PENDING) {
			if (v_retval == VIRTCHNL_STATUS_SUCCESS) {
				memcpy(adapter->rdma.recv_sync_msg, msg,
				       msglen);
				adapter->rdma.recv_sync_msg_size = msglen;
				adapter->rdma.vc_op_state =
					IAVF_RDMA_VC_OP_COMPLETE;
			} else {
				adapter->rdma.vc_op_state =
					IAVF_RDMA_VC_OP_FAILED;
				dev_err(dev, "PF returned error %d to our request %s-%d\n",
					v_retval, virtchnl_op_str(v_opcode),
					v_opcode);
			}

			wake_up(&adapter->rdma.vc_op_waitqueue);
		} else {
			/* asynchronous version of vc_send expects vc_receive to
			 * be called on reception of a VIRTCHNL_OP_RDMA message
			 */
			iavf_idc_vc_receive(adapter, msg, msglen);
		}
		break;
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		iavf_virtchnl_rdma_irq_map(adapter, v_retval);
		break;
	default:
		if (adapter->current_op && (v_opcode != adapter->current_op))
			dev_dbg(dev, "Expected response %d from PF, received %d\n",
				adapter->current_op, v_opcode);
		break;
	} /* switch v_opcode */
	adapter->current_op = VIRTCHNL_OP_UNKNOWN;
}
