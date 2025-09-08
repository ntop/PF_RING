/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"

#if IS_ENABLED(CONFIG_VFIO_PCI_CORE) && defined(HAVE_LMV1_SUPPORT)

#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_base.h"
#include "ice_txrx_lib.h"

struct ice_migration_virtchnl_msg_slot {
	u32 opcode;
	u16 msg_len;
	char msg_buffer[];
};

struct ice_migration_virtchnl_msg_listnode {
	struct list_head node;
	struct ice_migration_virtchnl_msg_slot msg_slot;
};

struct ice_migration_dev_state {
	u16 vsi_id;
	/* next RX desc index to be processed by the device */
	u16 rx_head[IAVF_QRX_TAIL_MAX];
	/* next TX desc index to be processed by the device */
	u16 tx_head[IAVF_QRX_TAIL_MAX];
} __aligned(8);

/**
 * ice_migration_get_vf - Get ice vf structure pointer by pdev
 * @vf_pdev: pointer to ice vfio pci vf pdev structure
 *
 * Return nonzero for success, NULL for failure.
 */
void *ice_migration_get_vf(struct pci_dev *vf_pdev)
{
	struct pci_dev *pf_pdev = vf_pdev->physfn;
	int vf_id = pci_iov_vf_id(vf_pdev);
	struct ice_pf *pf;

	if (!pf_pdev || vf_id < 0)
		return NULL;

	pf = pci_get_drvdata(pf_pdev);
	return ice_get_vf_by_id(pf, vf_id);
}
EXPORT_SYMBOL(ice_migration_get_vf);

/**
 * ice_migration_init_vf - Init ice VF device state data
 * @opaque: pointer to VF handler in ice vdev
 */
void ice_migration_init_vf(void *opaque)
{
	struct ice_vf *vf = opaque;

	vf->migration_active = true;
	INIT_LIST_HEAD(&vf->virtchnl_msg_list);
	vf->virtchnl_msg_num = 0;
}
EXPORT_SYMBOL(ice_migration_init_vf);

/**
 * ice_migration_uninit_vf - uninit VF device state data
 * @opaque: pointer to VF handler in ice vdev
 */
void ice_migration_uninit_vf(void *opaque)
{
	struct ice_migration_virtchnl_msg_listnode *msg_listnode;
	struct ice_migration_virtchnl_msg_listnode *dtmp;
	struct ice_vf *vf = opaque;

	vf->migration_active = false;

	if (list_empty(&vf->virtchnl_msg_list))
		return;
	list_for_each_entry_safe(msg_listnode, dtmp,
				 &vf->virtchnl_msg_list,
				 node) {
		list_del(&msg_listnode->node);
		kfree(msg_listnode);
	}
	vf->virtchnl_msg_num = 0;
}
EXPORT_SYMBOL(ice_migration_uninit_vf);

/**
 * ice_migration_save_vf_msg - Save request message from VF
 * @vf: pointer to the VF structure
 * @event: pointer to the AQ event
 *
 * save VF message for later restore during live migration
 */
void ice_migration_save_vf_msg(struct ice_vf *vf,
			       struct ice_rq_event_info *event)
{
	struct ice_migration_virtchnl_msg_listnode *msg_listnode;
	u32 v_opcode = le32_to_cpu(event->desc.cookie_high);
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	struct device *dev;
	struct ice_pf *pf;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	if (!vf->migration_active)
		return;

	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
	case VIRTCHNL_OP_GET_VF_RESOURCES:
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
	case VIRTCHNL_OP_ADD_ETH_ADDR:
	case VIRTCHNL_OP_DEL_ETH_ADDR:
	case VIRTCHNL_OP_ENABLE_QUEUES:
	case VIRTCHNL_OP_DISABLE_QUEUES:
	case VIRTCHNL_OP_ADD_VLAN:
	case VIRTCHNL_OP_DEL_VLAN:
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		if (vf->virtchnl_msg_num >= VIRTCHNL_MSG_MAX) {
			dev_warn(dev, "VF %d has maximum number virtual channel commands.\n",
				 vf->vf_id);
			return;
		}

		msg_listnode = kzalloc(struct_size(msg_listnode, msg_slot.msg_buffer, msglen),
				       GFP_KERNEL);
		if (!msg_listnode) {
			dev_err(dev, "VF %d failed to allocate memory for msg listnode\n",
				vf->vf_id);
			return;
		}
		dev_dbg(dev, "VF %d save virtual channel command, op code: %d, len: %d\n",
			vf->vf_id, v_opcode, msglen);
		msg_listnode->msg_slot.opcode = v_opcode;
		msg_listnode->msg_slot.msg_len = msglen;
		memcpy(msg_listnode->msg_slot.msg_buffer, msg, msglen);
		list_add_tail(&msg_listnode->node, &vf->virtchnl_msg_list);
		vf->virtchnl_msg_num++;
		break;
	default:
		break;
	}
}

/**
 * ice_migration_suspend_vf - suspend device on src
 * @opaque: pointer to VF handler in ice vdev
 *
 * Return 0 for success, negative for error
 */
int ice_migration_suspend_vf(void *opaque)
{
	struct ice_vf *vf = opaque;
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_pf *pf = vf->pf;
	struct device *dev;
	int ret;

	dev = ice_pf_to_dev(pf);
	if (vf->virtchnl_msg_num >= VIRTCHNL_MSG_MAX) {
		dev_err(dev, "SR-IOV live migration disabled on VF %d. Migration buffer exceeded\n",
			vf->vf_id);
		return -EIO;
	}

	if (!vsi) {
		dev_err(dev, "VF %d VSI is NULL\n", vf->vf_id);
		return -EINVAL;
	}
	/* Prevent VSI from incoming packets by removing all filters before
	 * stop rx ring and draining the traffic. There are possibilities that
	 * rx ring head value jitters when rx ring is stopped with large amount
	 * of packets incoming. In this case, HW mismatches SW on rx ring head
	 * state. As a result, after restoring rx ring head on the destination
	 * VM, the missing rx descriptors will never be written back, causing
	 * packets receiving failure and dropped.
	 */
	ice_fltr_remove_all(vsi);
	/* MAC based filter rule is disabled at this point. Set MAC to zero
	 * to keep consistency when using ip link to display MAC address.
	 */
	eth_zero_addr(vf->hw_lan_addr.addr);
	eth_zero_addr(vf->dev_lan_addr.addr);
	/* For the tx side, there is possibility that some descriptors are
	 * still pending to be transmitted by HW. Since VM is stopped now,
	 * wait a while to make sure all the transmission is completed.
	 * For the rx side, head value jittering may happen in case of high
	 * packet rate. Since all forwarding filters are removed now, wait a
	 * while to make sure all the reception is completed and rx head no
	 * longer moves.
	 */
	usleep_range(1000, 2000);
	ret = ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	if (ret) {
		dev_err(dev, "VF %d failed to stop tx rings\n", vf->vf_id);
		return -EIO;
	}
	ret = ice_vsi_stop_all_rx_rings(vsi);
	if (ret) {
		dev_err(dev, "VF %d failed to stop rx rings\n", vf->vf_id);
		return -EIO;
	}
	return 0;
}
EXPORT_SYMBOL(ice_migration_suspend_vf);

/**
 * ice_migration_save_rx_head - save rx head in migration region
 * @vf: pointer to VF structure
 * @devstate: pointer to migration buffer
 *
 * Return 0 for success, negative for error
 */
static int
ice_migration_save_rx_head(struct ice_vf *vf,
			   struct ice_migration_dev_state *devstate)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	int i;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		dev_err(dev, "VF %d VSI is NULL\n", vf->vf_id);
		return -EINVAL;
	}
	ice_for_each_rxq(vsi, i) {
		struct ice_rx_ring *rx_ring = vsi->rx_rings[i];
		struct ice_rlan_ctx rlan_ctx = {0};
		int status;
		u16 pf_q;

		if (!test_bit(i, vf->rxq_ena))
			continue;

		pf_q = rx_ring->reg_idx;
		status = ice_read_rxq_ctx(hw, &rlan_ctx, pf_q);
		if (status) {
			dev_err(dev, "Failed to read RXQ[%d] context, err=%d\n",
				rx_ring->q_index, status);
			return -EIO;
		}
		devstate->rx_head[i] = rlan_ctx.head;
	}
	return 0;
}

/**
 * ice_migration_save_tx_head - save tx head in migration region
 * @vf: pointer to VF structure
 * @devstate: pointer to migration device state
 *
 */
static int
ice_migration_save_tx_head(struct ice_vf *vf,
			   struct ice_migration_dev_state *devstate)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int i = 0;

	dev = ice_pf_to_dev(pf);
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		dev_err(dev, "VF %d VSI is NULL\n", vf->vf_id);
		return -EINVAL;
	}

	ice_for_each_txq(vsi, i) {
		u16 tx_head;
		u32 reg;

		if (!test_bit(i, vf->txq_ena))
			continue;

		reg = rd32(&pf->hw, QTX_COMM_HEAD(vsi->txq_map[i]));
		tx_head = FIELD_GET(QTX_COMM_HEAD_HEAD_M, reg);

		if (tx_head == QTX_COMM_HEAD_HEAD_M ||
		    tx_head == (vsi->tx_rings[i]->count - 1))
			/* when transmitted packet number is 0 or tx_ring
			 * length, the next packet to be sent is 0.
			 */
			tx_head = 0;
		else
			tx_head++;

		devstate->tx_head[i] = tx_head;
	}
	return 0;
}

/**
 * ice_migration_save_devstate - save VF msg to migration buffer
 * @opaque: pointer to VF handler in ice vdev
 * @buf: pointer to VF msg in migration buffer
 * @buf_sz: size of migration buffer
 *
 * The first two bytes in the buffer is VSI id, followed by
 * virtual channel messages.
 *
 * Return 0 for success, negative for error
 */
int ice_migration_save_devstate(void *opaque, u8 *buf, u64 buf_sz)
{
	struct ice_migration_virtchnl_msg_listnode *msg_listnode;
	struct ice_migration_virtchnl_msg_slot *last_op;
	struct ice_vf *vf = opaque;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_migration_dev_state *devstate;
	u64 total_size = 0;
	int ret;

	/* reserve space to store device state */
	total_size += sizeof(struct ice_migration_dev_state);
	if (total_size > buf_sz) {
		dev_err(dev, "Insufficient buffer to store device state for VF %d\n",
			vf->vf_id);
		return -ENOBUFS;
	}

	devstate = (struct ice_migration_dev_state *)buf;
	devstate->vsi_id = vf->vm_vsi_num;
	ret = ice_migration_save_rx_head(vf, devstate);
	if (ret) {
		dev_err(dev, "VF %d failed to save rxq head\n", vf->vf_id);
		return ret;
	}
	ret = ice_migration_save_tx_head(vf, devstate);
	if (ret) {
		dev_err(dev, "VF %d failed to save txq head\n", vf->vf_id);
		return ret;
	}
	buf += sizeof(*devstate);

	list_for_each_entry(msg_listnode, &vf->virtchnl_msg_list, node) {
		struct ice_migration_virtchnl_msg_slot *msg_slot;
		u64 slot_size;

		msg_slot = &msg_listnode->msg_slot;
		slot_size = struct_size(msg_slot, msg_buffer,
					msg_slot->msg_len);
		total_size += slot_size;
		if (total_size > buf_sz) {
			dev_err(dev, "Insufficient buffer to store virtchnl message for VF %d op: %d, len: %d\n",
				vf->vf_id, msg_slot->opcode, msg_slot->msg_len);
			return -ENOBUFS;
		}
		dev_dbg(dev, "VF %d copy virtchnl message to migration buffer op: %d, len: %d\n",
			vf->vf_id, msg_slot->opcode, msg_slot->msg_len);
		memcpy(buf, msg_slot, slot_size);
		buf += slot_size;
	}
	/* reserve space to mark end of vf messages */
	total_size += sizeof(struct ice_migration_virtchnl_msg_slot);
	if (total_size > buf_sz) {
		dev_err(dev, "Insufficient buffer to store virtchnl message for VF %d\n",
			vf->vf_id);
		return -ENOBUFS;
	}

	/* use op code unknown to mark end of vc messages */
	last_op = (struct ice_migration_virtchnl_msg_slot *)buf;
	last_op->opcode = VIRTCHNL_OP_UNKNOWN;
	return 0;
}
EXPORT_SYMBOL(ice_migration_save_devstate);

/**
 * ice_migration_restore_rx_head - restore rx head at dst
 * @vf: pointer to VF structure
 * @devstate: pointer to migration device state
 *
 * Return 0 for success, negative for error
 */
static int
ice_migration_restore_rx_head(struct ice_vf *vf,
			      struct ice_migration_dev_state *devstate)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int i;

	dev = ice_pf_to_dev(pf);
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		dev_err(dev, "VF %d VSI is NULL\n", vf->vf_id);
		return -EINVAL;
	}
	ice_for_each_rxq(vsi, i) {
		struct ice_rx_ring *rx_ring = vsi->rx_rings[i];
		struct ice_rlan_ctx rlan_ctx = {0};
		int status;
		u16 pf_q;

		if (!rx_ring)
			return -EINVAL;
		pf_q = rx_ring->reg_idx;
		status = ice_read_rxq_ctx(&pf->hw, &rlan_ctx, pf_q);
		if (status) {
			dev_err(dev, "Failed to read RXQ[%d] context, err=%d\n",
				rx_ring->q_index, status);
			return -EIO;
		}

		rlan_ctx.head = devstate->rx_head[i];
		status = ice_write_rxq_ctx(&pf->hw, &rlan_ctx, pf_q);
		if (status) {
			dev_err(dev, "Failed to set LAN RXQ[%d] context, err=%d\n",
				rx_ring->q_index, status);
			return -EIO;
		}
	}
	return 0;
}

/**
 * ice_migration_restore_tx_head - restore tx head at dst
 * @vf: pointer to VF structure
 * @devstate: pointer to migration device state
 * @kvm: pointer to kvm
 *
 * Return 0 for success, negative for error
 */
static int
ice_migration_restore_tx_head(struct ice_vf *vf,
			      struct ice_migration_dev_state *devstate,
			      struct kvm *kvm)
{
	struct ice_tx_desc *tx_desc_dummy, *tx_desc;
	struct ice_pf *pf = vf->pf;
	u16 max_ring_len = 0;
	struct ice_vsi *vsi;
	struct device *dev;
	int ret = 0;
	int i = 0;

	dev = ice_pf_to_dev(vf->pf);
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		dev_err(dev, "VF %d VSI is NULL\n", vf->vf_id);
		return -EINVAL;
	}

	ice_for_each_txq(vsi, i) {
		if (!test_bit(i, vf->txq_ena))
			continue;

		max_ring_len = max(vsi->tx_rings[i]->count, max_ring_len);
	}

	if (max_ring_len == 0)
		return 0;

	tx_desc = kcalloc(max_ring_len, sizeof(struct ice_tx_desc),
			  GFP_KERNEL);
	tx_desc_dummy = kcalloc(max_ring_len, sizeof(struct ice_tx_desc),
				GFP_KERNEL);
	if (!tx_desc || !tx_desc_dummy) {
		dev_err(dev, "VF %d failed to allocate memory for tx descriptors to restore tx head\n",
			vf->vf_id);
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < max_ring_len; i++) {
		u32 td_cmd;

		td_cmd = ICE_TXD_LAST_DESC_CMD | ICE_TX_DESC_CMD_DUMMY;
		tx_desc_dummy[i].cmd_type_offset_bsz =
					ice_build_ctob(td_cmd, 0, SZ_256, 0);
	}

	/* For each tx queue, we restore the tx head following below steps:
	 * 1. backup original tx ring descriptor memory
	 * 2. overwrite the tx ring descriptor with dummy packets
	 * 3. kick doorbell register to trigger descriptor writeback,
	 *    then tx head will move from 0 to tail - 1 and tx head is restored
	 *    to the place we expect.
	 * 4. restore the tx ring with original tx ring descriptor memory in
	 *    order not to corrupt the ring context.
	 */
	ice_for_each_txq(vsi, i) {
		struct ice_tx_ring *tx_ring = vsi->tx_rings[i];
		u16 *tx_heads = devstate->tx_head;
		u32 tx_head;
		int j;

		if (!test_bit(i, vf->txq_ena) || tx_heads[i] == 0)
			continue;

		if (tx_heads[i] >= tx_ring->count) {
			dev_err(dev, "saved tx ring head exceeds tx ring count\n");
			ret = -EINVAL;
			goto err;
		}
		ret = kvm_read_guest(kvm, tx_ring->dma, (void *)tx_desc,
				     tx_ring->count * sizeof(tx_desc[0]));
		if (ret) {
			dev_err(dev, "kvm read guest tx ring error: %d\n",
				ret);
			goto err;
		}
		ret = kvm_write_guest(kvm, tx_ring->dma, (void *)tx_desc_dummy,
				      tx_heads[i] * sizeof(tx_desc_dummy[0]));
		if (ret) {
			dev_err(dev, "kvm write guest return error: %d\n",
				ret);
			goto err;
		}

		/* Force memory writes to complete before letting h/w know there
		 * are new descriptors to fetch.
		 */
		wmb();
		writel(tx_heads[i], tx_ring->tail);
		/* wait until tx_head equals tx_heads[i] - 1 */
		tx_head = rd32(&pf->hw, QTX_COMM_HEAD(vsi->txq_map[i]));
		tx_head = FIELD_GET(QTX_COMM_HEAD_HEAD_M, tx_head);
		for (j = 0; j < 10 && tx_head != (u32)(tx_heads[i] - 1); j++) {
			usleep_range(10, 20);
			tx_head = rd32(&pf->hw, QTX_COMM_HEAD(vsi->txq_map[i]));
			tx_head = FIELD_GET(QTX_COMM_HEAD_HEAD_M, tx_head);
		}
		if (j == 10) {
			ret = -EIO;
			dev_err(dev, "VF %d txq[%d] head restore timeout\n",
				vf->vf_id, i);
			goto err;
		}
		ret = kvm_write_guest(kvm, tx_ring->dma, (void *)tx_desc,
				      tx_ring->count * sizeof(tx_desc[0]));
		if (ret) {
			dev_err(dev, "kvm write guest tx ring error: %d\n",
				ret);
			goto err;
		}
	}

err:
	kfree(tx_desc_dummy);
	kfree(tx_desc);

	return ret;
}

/**
 * ice_migration_restore_devstate - restore device state at dst
 * @opaque: pointer to VF handler in ice vdev
 * @buf: pointer to device state buf in migration buffer
 * @buf_sz: size of migration buffer
 * @kvm: pointer to kvm
 *
 * The first two bytes in the buffer is VSI id, followed by
 * virtual channel messages.
 *
 * Return 0 for success, negative for error
 */
int ice_migration_restore_devstate(void *opaque, const u8 *buf, u64 buf_sz,
				   struct kvm *kvm)
{
	struct ice_migration_virtchnl_msg_slot *msg_slot;
	struct ice_vf *vf = opaque;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_migration_dev_state *devstate;
	struct ice_rq_event_info event;
	u64 total_size = 0;
	u64 op_msglen_sz;
	u64 slot_sz;
	int ret = 0;

	if (!buf || !kvm)
		return -EINVAL;

	total_size += sizeof(struct ice_migration_dev_state);
	if (total_size > buf_sz) {
		dev_err(dev, "VF %d msg size exceeds buffer size\n", vf->vf_id);
		return -ENOBUFS;
	}

	devstate = (struct ice_migration_dev_state *)buf;
	vf->vm_vsi_num = devstate->vsi_id;
	dev_dbg(dev, "VF %d VM VSI num is:%d\n", vf->vf_id, vf->vm_vsi_num);
	buf += sizeof(*devstate);
	msg_slot = (struct ice_migration_virtchnl_msg_slot *)buf;
	op_msglen_sz = sizeof(struct ice_migration_virtchnl_msg_slot);
	/* check whether enough space for opcode and msg_len */
	if (total_size + op_msglen_sz > buf_sz) {
		dev_err(dev, "VF %d msg size exceeds buffer size\n", vf->vf_id);
		return -ENOBUFS;
	}

	set_bit(ICE_VF_STATE_REPLAY_VC, vf->vf_states);

	while (msg_slot->opcode != VIRTCHNL_OP_UNKNOWN) {
		slot_sz = struct_size(msg_slot, msg_buffer, msg_slot->msg_len);
		total_size += slot_sz;
		/* check whether enough space for whole message */
		if (total_size > buf_sz) {
			dev_err(dev, "VF %d msg size exceeds buffer size\n",
				vf->vf_id);
			ret = -ENOBUFS;
			goto err;
		}
		dev_dbg(dev, "VF %d replay virtchnl message op code: %d, msg len: %d\n",
			vf->vf_id, msg_slot->opcode, msg_slot->msg_len);
		event.desc.cookie_high = msg_slot->opcode;
		event.msg_len = msg_slot->msg_len;
		event.desc.retval = vf->vf_id;
		event.msg_buf = (unsigned char *)msg_slot->msg_buffer;
		ret = ice_vc_process_vf_msg(vf->pf, &event, NULL);
		if (ret) {
			dev_err(dev, "failed to replay virtchnl message op code: %d, err %d\n",
				msg_slot->opcode, ret);
			goto err;
		}
		if (msg_slot->opcode == VIRTCHNL_OP_CONFIG_VSI_QUEUES) {
			ret = ice_migration_restore_rx_head(vf, devstate);
			if (ret) {
				dev_err(dev, "VF %d failed to restore rx head\n",
					vf->vf_id);
				break;
			}
		}

		event.msg_buf = NULL;
		msg_slot = (struct ice_migration_virtchnl_msg_slot *)
					((char *)msg_slot + slot_sz);
		/* check whether enough space for opcode and msg_len */
		if (total_size + op_msglen_sz > buf_sz) {
			dev_err(dev, "VF %d msg size exceeds buffer size\n",
				vf->vf_id);
			ret = -ENOBUFS;
			goto err;
		}
	}

	/* Since we can't restore tx head directly due to HW limitation, we
	 * could only restore tx head indirectly by dummy packets injection.
	 * After virtual channel replay completes, tx rings are enabled.
	 * Then restore tx head for tx rings by injecting dummy packets.
	 */
	ret = ice_migration_restore_tx_head(vf, devstate, kvm);
	if (ret) {
		dev_err(dev, "failed to restore tx queue head\n");
		goto err;
	}

err:
	clear_bit(ICE_VF_STATE_REPLAY_VC, vf->vf_states);
	return ret;
}
EXPORT_SYMBOL(ice_migration_restore_devstate);

#define VIRTCHNL_VF_MIGRATION_SUPPORT_FEATURE \
				(VIRTCHNL_VF_OFFLOAD_L2 | \
				 VIRTCHNL_VF_OFFLOAD_RSS_PF | \
				 VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2 | \
				 VIRTCHNL_VF_OFFLOAD_ENCAP | \
				 VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM | \
				 VIRTCHNL_VF_OFFLOAD_RX_POLLING | \
				 VIRTCHNL_VF_OFFLOAD_WB_ON_ITR | \
				 VIRTCHNL_VF_CAP_ADV_LINK_SPEED | \
				 VIRTCHNL_VF_OFFLOAD_VLAN | \
				 VIRTCHNL_VF_OFFLOAD_USO)

/**
 * ice_migration_supported_caps - get migration supported VF capablities
 *
 * When migration is activated, some VF capabilities are not supported.
 * So unmask those capability flags for VF resources.
 */
u32 ice_migration_supported_caps(void)
{
	u32 mig_support_cap = VIRTCHNL_VF_MIGRATION_SUPPORT_FEATURE;

	mig_support_cap |= VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC;

	mig_support_cap |= VIRTCHNL_VF_OFFLOAD_CRC;

	return mig_support_cap;
}

#endif /* CONFIG_VFIO_PCI_CORE && HAVE_LMV1_SUPPORT */
