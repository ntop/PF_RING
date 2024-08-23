// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2023 Intel Corporation */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "virtchnl.h"
#include "ws.h"
#include "i40iw_hw.h"

struct vchnl_reg_map_elem {
	u16 reg_id;
	u16 reg_idx;
	bool pg_rel;
};

struct vchnl_regfld_map_elem {
	u16 regfld_id;
	u16 regfld_idx;
};

static struct vchnl_reg_map_elem vchnl_reg_map[] = {
	{IRDMA_VCHNL_REG_ID_CQPTAIL, IRDMA_CQPTAIL, false},
	{IRDMA_VCHNL_REG_ID_CQPDB, IRDMA_CQPDB, false},
	{IRDMA_VCHNL_REG_ID_CCQPSTATUS, IRDMA_CCQPSTATUS, false},
	{IRDMA_VCHNL_REG_ID_CCQPHIGH, IRDMA_CCQPHIGH, false},
	{IRDMA_VCHNL_REG_ID_CCQPLOW, IRDMA_CCQPLOW, false},
	{IRDMA_VCHNL_REG_ID_CQARM, IRDMA_CQARM, false},
	{IRDMA_VCHNL_REG_ID_CQACK, IRDMA_CQACK, false},
	{IRDMA_VCHNL_REG_ID_AEQALLOC, IRDMA_AEQALLOC, false},
	{IRDMA_VCHNL_REG_ID_CQPERRCODES, IRDMA_CQPERRCODES, false},
	{IRDMA_VCHNL_REG_ID_WQEALLOC, IRDMA_WQEALLOC, false},
	{IRDMA_VCHNL_REG_ID_DB_ADDR_OFFSET, IRDMA_DB_ADDR_OFFSET, false },
	{IRDMA_VCHNL_REG_ID_DYN_CTL, IRDMA_GLINT_DYN_CTL, false },
	{IRDMA_VCHNL_REG_INV_ID, IRDMA_VCHNL_REG_INV_ID, false }
};

static struct vchnl_regfld_map_elem vchnl_regfld_map[] = {
	{IRDMA_VCHNL_REGFLD_ID_CCQPSTATUS_CQP_OP_ERR, IRDMA_CCQPSTATUS_CCQP_ERR_M},
	{IRDMA_VCHNL_REGFLD_ID_CCQPSTATUS_CCQP_DONE, IRDMA_CCQPSTATUS_CCQP_DONE_M},
	{IRDMA_VCHNL_REGFLD_ID_CQPSQ_STAG_PDID, IRDMA_CQPSQ_STAG_PDID_M},
	{IRDMA_VCHNL_REGFLD_ID_CQPSQ_CQ_CEQID, IRDMA_CQPSQ_CQ_CEQID_M},
	{IRDMA_VCHNL_REGFLD_ID_CQPSQ_CQ_CQID, IRDMA_CQPSQ_CQ_CQID_M},
	{IRDMA_VCHNL_REGFLD_ID_COMMIT_FPM_CQCNT, IRDMA_COMMIT_FPM_CQCNT_M},
	{IRDMA_VCHNL_REGFLD_ID_UPESD_HMCN_ID, IRDMA_CQPSQ_UPESD_HMCFNID_M},
	{IRDMA_VCHNL_REGFLD_INV_ID, IRDMA_VCHNL_REGFLD_INV_ID}
};

#define IRDMA_VCHNL_REG_COUNT ARRAY_SIZE(vchnl_reg_map)
#define IRDMA_VCHNL_REGFLD_COUNT ARRAY_SIZE(vchnl_regfld_map)
#define IRDMA_VCHNL_REGFLD_BUF_SIZE \
	(IRDMA_VCHNL_REG_COUNT * sizeof(struct irdma_vchnl_reg_info) + \
	 IRDMA_VCHNL_REGFLD_COUNT * sizeof(struct irdma_vchnl_reg_field_info))
#define IRDMA_REGMAP_RESP_BUF_SIZE (IRDMA_VCHNL_RESP_MIN_SIZE + IRDMA_VCHNL_REGFLD_BUF_SIZE)

static enum irdma_hmc_rsrc_type hmc_rsrc_types_gen2[] = {
	IRDMA_HMC_IW_QP,
	IRDMA_HMC_IW_CQ,
	IRDMA_HMC_IW_HTE,
	IRDMA_HMC_IW_ARP,
	IRDMA_HMC_IW_APBVT_ENTRY,
	IRDMA_HMC_IW_MR,
	IRDMA_HMC_IW_XF,
	IRDMA_HMC_IW_XFFL,
	IRDMA_HMC_IW_Q1,
	IRDMA_HMC_IW_Q1FL,
	IRDMA_HMC_IW_TIMER,
	IRDMA_HMC_IW_FSIMC,
	IRDMA_HMC_IW_FSIAV,
	IRDMA_HMC_IW_PBLE,
	IRDMA_HMC_IW_RRF,
	IRDMA_HMC_IW_RRFFL,
	IRDMA_HMC_IW_HDR,
	IRDMA_HMC_IW_MD,
	IRDMA_HMC_IW_OOISC,
	IRDMA_HMC_IW_OOISCFFL,
};

static enum irdma_hmc_rsrc_type hmc_rsrc_types_gen3[] = {
	IRDMA_HMC_IW_QP,
	IRDMA_HMC_IW_CQ,
	IRDMA_HMC_IW_SRQ,
	IRDMA_HMC_IW_HTE,
	IRDMA_HMC_IW_ARP,
	IRDMA_HMC_IW_APBVT_ENTRY,
	IRDMA_HMC_IW_MR,
	IRDMA_HMC_IW_XF,
	IRDMA_HMC_IW_XFFL,
	IRDMA_HMC_IW_Q1,
	IRDMA_HMC_IW_Q1FL,
	IRDMA_HMC_IW_TIMER,
	IRDMA_HMC_IW_FSIMC,
	IRDMA_HMC_IW_FSIAV,
	IRDMA_HMC_IW_PBLE,
	IRDMA_HMC_IW_RRF,
	IRDMA_HMC_IW_RRFFL,
	IRDMA_HMC_IW_HDR,
	IRDMA_HMC_IW_MD,
	IRDMA_HMC_IW_OOISC,
	IRDMA_HMC_IW_OOISCFFL,
};

/**
 * irdma_sc_vchnl_init - Initialize dev virtchannel and get hw_rev
 * @dev: dev structure to update
 * @info: virtchannel info parameters to fill into the dev structure
 */
int irdma_sc_vchnl_init(struct irdma_sc_dev *dev,
			struct irdma_vchnl_init_info *info)
{
	dev->vchnl_if = info->vchnl_if;
	dev->vchnl_up = dev->vchnl_if ? true : false;
	dev->privileged = info->privileged;
	dev->is_pf = info->is_pf;
	dev->vchnl_wq = info->vchnl_wq;
	dev->hw_attrs.uk_attrs.hw_rev = info->hw_rev;
	dev->hw_attrs.uk_attrs.max_hw_push_len = IRDMA_DEFAULT_MAX_PUSH_LEN;

	if (!dev->privileged) {
		int ret = irdma_vchnl_req_get_ver(dev, IRDMA_VCHNL_CHNL_VER_MAX,
						  &dev->vchnl_ver);
		/* Attempt to negotiate down to V1 as it does not negotaite. */
		if (ret) {
			ret = irdma_vchnl_req_get_ver(dev, IRDMA_VCHNL_CHNL_VER_V1,
						      &dev->vchnl_ver);
		}

		ibdev_dbg(to_ibdev(dev),
			  "DEV: Get Channel version ret = %d, version is %u\n",
			  ret, dev->vchnl_ver);

		if (ret)
			return ret;

		/* IRDMA_VCHNL_OP_GET_RDMA_CAPS not supported in V1. */
		if (dev->vchnl_ver == IRDMA_VCHNL_OP_GET_VER_V1) {
			dev->hw_attrs.uk_attrs.hw_rev = IRDMA_GEN_2;
			return 0;
		}
		ret = irdma_vchnl_req_get_caps(dev);
		if (ret)
			return ret;

		dev->hw_attrs.uk_attrs.hw_rev = dev->vc_caps.hw_rev;
		dev->hw_attrs.uk_attrs.max_hw_push_len = dev->vc_caps.max_hw_push_len;
	}

	return 0;
}

/**
 * irdma_find_vc_dev - get vchnl dev pointer
 * @dev: shared device pointer
 * @vf_id: virtual function id
 */
struct irdma_vchnl_dev *irdma_find_vc_dev(struct irdma_sc_dev *dev, u16 vf_id)
{
	struct irdma_vchnl_dev *vc_dev = NULL;
	unsigned long flags;
	u16 iw_vf_idx;

	spin_lock_irqsave(&dev->vc_dev_lock, flags);
	for (iw_vf_idx = 0; iw_vf_idx < dev->num_vfs; iw_vf_idx++) {
		if (dev->vc_dev[iw_vf_idx] &&
		    dev->vc_dev[iw_vf_idx]->vf_id == vf_id) {
			vc_dev = dev->vc_dev[iw_vf_idx];
			refcount_inc(&vc_dev->refcnt);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->vc_dev_lock, flags);

	return vc_dev;
}

/**
 * irdma_remove_vc_dev - remove vc_dev
 * @dev: shared device pointer
 * @vc_dev: vf dev to be removed
 */
void irdma_remove_vc_dev(struct irdma_sc_dev *dev, struct irdma_vchnl_dev *vc_dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->vc_dev_lock, flags);
	dev->vc_dev[vc_dev->iw_vf_idx] = NULL;
	spin_unlock_irqrestore(&dev->vc_dev_lock, flags);
}

/**
 * irdma_vchnl_pf_send_resp - Send channel version to VF
 * @dev: irdma_vchnl_pf_send_resp device pointer
 * @vf_id: Virtual function ID associated with the message
 * @vchnl_msg: Virtual channel message buffer pointer
 * @param: parameter that is passed back to the VF
 * @param_len: length of parameter that's being passed in
 * @resp_code: response code sent back to VF
 */
static void irdma_vchnl_pf_send_resp(struct irdma_sc_dev *dev, u16 vf_id,
				     struct irdma_vchnl_op_buf *vchnl_msg,
				     void *param, u16 param_len, int resp_code)
{
	u8 resp_buf[IRDMA_VCHNL_MAX_MSG_SIZE] = {};
	struct irdma_vchnl_resp_buf *vchnl_msg_resp;
	int ret;

	vchnl_msg_resp = (struct irdma_vchnl_resp_buf *)resp_buf;
	vchnl_msg_resp->op_ctx = vchnl_msg->op_ctx;
	vchnl_msg_resp->buf_len = IRDMA_VCHNL_RESP_MIN_SIZE + param_len;
	vchnl_msg_resp->op_ret = (s16)resp_code;
	if (param_len)
		memcpy(vchnl_msg_resp->buf, param, param_len);

	ret = irdma_vchnl_send_pf(dev, vf_id, resp_buf,
				  vchnl_msg_resp->buf_len);
	if (ret)
		ibdev_dbg(to_ibdev(dev),
		          "VIRT: virt channel send failed ret = %d\n", ret);
}

/**
 * pf_valid_hmc_rsrc_type - Check obj_type input validation
 * @hw_rev: hw version
 * @obj_type: type of hmc resource
 */
static bool pf_valid_hmc_rsrc_type(u8 hw_rev, u16 obj_type)
{
	enum irdma_hmc_rsrc_type *valid_rsrcs;
	u8 num_rsrcs, i;

	switch (hw_rev) {
	case IRDMA_GEN_2:
		valid_rsrcs = hmc_rsrc_types_gen2;
		num_rsrcs = ARRAY_SIZE(hmc_rsrc_types_gen2);
		break;
	case IRDMA_GEN_3:
		valid_rsrcs = hmc_rsrc_types_gen3;
		num_rsrcs = ARRAY_SIZE(hmc_rsrc_types_gen3);
		break;
	default:
		return false;
	}

	for (i = 0; i < num_rsrcs; i++) {
		if (obj_type == valid_rsrcs[i])
			return true;
	}

	return false;
}

/**
 * irdma_pf_add_hmc_obj - Add HMC Object for VF
 * @vc_dev: pointer to the vc_dev
 * @hmc_obj: hmc_obj to be added
 */
static int irdma_pf_add_hmc_obj(struct irdma_vchnl_dev *vc_dev,
				struct irdma_vchnl_hmc_obj_range *hmc_obj)
{
	struct irdma_sc_dev *dev = vc_dev->pf_dev;
	struct irdma_hmc_info *hmc_info = &vc_dev->hmc_info;
	struct irdma_hmc_create_obj_info info = {};
	int ret;

	if (!vc_dev->pf_hmc_initialized) {
		ret = irdma_pf_init_vfhmc(vc_dev->pf_dev,
					  (u8)vc_dev->pmf_index);
		if (ret)
			return ret;
		vc_dev->pf_hmc_initialized = true;
	}

	if (!pf_valid_hmc_rsrc_type(dev->hw_attrs.uk_attrs.hw_rev,
				    hmc_obj->obj_type)) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: invalid hmc_rsrc type detected. vf_id %d obj_type 0x%x\n",
			  vc_dev->vf_id, hmc_obj->obj_type);
		return -EINVAL;
	}

	info.hmc_info = hmc_info;
	info.privileged = false;
	info.rsrc_type = (u32)hmc_obj->obj_type;
	info.entry_type = (info.rsrc_type == IRDMA_HMC_IW_PBLE) ?
				IRDMA_SD_TYPE_PAGED :
				IRDMA_SD_TYPE_DIRECT;
	info.start_idx = hmc_obj->start_index;
	info.count = hmc_obj->obj_count;
	ibdev_dbg(to_ibdev(vc_dev->pf_dev),
		  "VIRT: IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE.  Add %u type %u objects\n",
		  info.count, info.rsrc_type);

	return irdma_sc_create_hmc_obj(vc_dev->pf_dev, &info);
}

/**
 * irdma_pf_del_hmc_obj - Delete HMC Object for VF
 * @vc_dev: pointer to the vc_dev
 * @hmc_obj: hmc_obj to be deleted
 */
static int irdma_pf_del_hmc_obj(struct irdma_vchnl_dev *vc_dev,
				struct irdma_vchnl_hmc_obj_range *hmc_obj)
{
	struct irdma_sc_dev *dev = vc_dev->pf_dev;
	struct irdma_hmc_info *hmc_info = &vc_dev->hmc_info;
	struct irdma_hmc_del_obj_info info = {};

	if (!vc_dev->pf_hmc_initialized)
		return -EINVAL;

	if (!pf_valid_hmc_rsrc_type(dev->hw_attrs.uk_attrs.hw_rev,
				    hmc_obj->obj_type)) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: invalid hmc_rsrc type detected. vf_id %d obj_type 0x%x\n",
			  vc_dev->vf_id, hmc_obj->obj_type);
		return -EINVAL;
	}

	info.hmc_info = hmc_info;
	info.privileged = false;
	info.rsrc_type = (u32)hmc_obj->obj_type;
	info.start_idx = hmc_obj->start_index;
	info.count = hmc_obj->obj_count;
	ibdev_dbg(to_ibdev(vc_dev->pf_dev),
		  "VIRT: IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE. Delete %u type %u objects\n",
		  info.count, info.rsrc_type);

	return irdma_sc_del_hmc_obj(vc_dev->pf_dev, &info, false);
}

/**
 * irdma_pf_manage_ws_node - managing ws node for VF
 * @vc_dev: pointer to the VF Device
 * @ws_node: work scheduler node to be modified
 * @qs_handle: returned qs_handle provided by cqp
 */
static int
irdma_pf_manage_ws_node(struct irdma_vchnl_dev *vc_dev,
			struct irdma_vchnl_manage_ws_node *ws_node,
			u16 *qs_handle)
{
	struct irdma_sc_vsi *vsi = vc_dev->vf_vsi;
	int ret = 0;

	if (ws_node->user_pri >= IRDMA_MAX_USER_PRIORITY)
		return -EINVAL;

	ibdev_dbg(to_ibdev(vc_dev->pf_dev),
		  "VIRT: IRDMA_VCHNL_OP_MANAGE_WS_NODE. Add %d vf_id %d\n",
		  ws_node->add, vc_dev->vf_id);

	if (ws_node->add) {
		ret = vsi->dev->ws_add(vsi, ws_node->user_pri);
		if (ret)
			ibdev_dbg(to_ibdev(vc_dev->pf_dev),
				  "VIRT: irdma_ws_add failed ret = %d\n", ret);
		else
			*qs_handle = vsi->qos[ws_node->user_pri].qs_handle[0];
	} else {
		vsi->dev->ws_remove(vsi, ws_node->user_pri);
	}

	return ret;
}

/**
 * irdma_pf_get_reg_layout - Format reg layout for AxF
 * @vc_dev: Virtual function device associated with the message
 * @reg_array: register layout array passed back to the AxF
 */
static void irdma_pf_get_reg_layout(struct irdma_vchnl_dev *vc_dev,
				    struct irdma_vchnl_reg_info *reg_array)
{
	struct irdma_vchnl_reg_field_info *regfld_array;
	struct irdma_sc_dev *dev = vc_dev->pf_dev;
	uintptr_t reg_addr, base_addr;
	u16 regfld_idx, reg_idx;
	u64 bitmask;
	u32 idx;

	base_addr = (uintptr_t)dev->hw->hw_addr;

	for (idx = 0; idx < IRDMA_VCHNL_REG_COUNT; idx++) {
		reg_idx = vchnl_reg_map[idx].reg_idx;
		reg_array[idx].reg_id = vchnl_reg_map[idx].reg_id;
		if (reg_array[idx].reg_id == IRDMA_VCHNL_REG_INV_ID)
			break;

		reg_addr = (uintptr_t)dev->hw_regs[reg_idx];
		if (reg_idx != IRDMA_DB_ADDR_OFFSET)
			reg_array[idx].reg_offset = (u32)(reg_addr - base_addr);
		else
			reg_array[idx].reg_offset = (u32)reg_addr;
		if (vchnl_reg_map[idx].pg_rel)
			reg_array[idx].reg_id |= IRDMA_VCHNL_REG_PAGE_REL;
	}

	regfld_array =
		(struct irdma_vchnl_reg_field_info *)&reg_array[idx + 1];
	for (idx = 0; idx < IRDMA_VCHNL_REGFLD_COUNT; idx++) {
		regfld_idx = vchnl_regfld_map[idx].regfld_idx;
		regfld_array[idx].fld_id = vchnl_regfld_map[idx].regfld_id;
		if (regfld_array[idx].fld_id == IRDMA_VCHNL_REGFLD_INV_ID)
			break;

		bitmask = dev->hw_masks[regfld_idx] >>
			  dev->hw_shifts[regfld_idx];
		while (bitmask != 0) {
			regfld_array[idx].fld_bits++;
			bitmask >>= 1;
		}
		regfld_array[idx].fld_shift = dev->hw_shifts[regfld_idx];
	}
}

/**
 * irdma_set_hmc_fcn_info - Populate hmc_fcn_info struct
 * @vc_dev: pointer to VF dev structure
 * @hmc_fcn_info: pointer to HMC fcn info to be filled up
 */
static
void irdma_set_hmc_fcn_info(struct irdma_vchnl_dev *vc_dev,
			    struct irdma_hmc_fcn_info *hmc_fcn_info)
{
	memset(hmc_fcn_info, 0, sizeof(*hmc_fcn_info));

	/* For new HW model vf_id is PCI function  */
	hmc_fcn_info->vf_id = vc_dev->vf_id;
	hmc_fcn_info->protocol_used = vc_dev->protocol_used;
	if (vc_dev->pf_dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		hmc_fcn_info->is_pf = 0;
	}
}

/**
 * irdma_get_protocol_used - returns protocol family to use for HMC FCN
 * @vchnl_msg: inbound vf vchannel message
 *
 * Return: protool family to use in get hmc function cqp operation.
 */
static enum irdma_protocol_used irdma_get_protocol_used(struct irdma_vchnl_op_buf *vchnl_msg)
{
	struct irdma_vchnl_req_hmc_info *req_hmc;

	if (vchnl_msg->op_ver >= IRDMA_VCHNL_OP_GET_HMC_FCN_V1) {
		req_hmc = (struct irdma_vchnl_req_hmc_info *)vchnl_msg->buf;
		return req_hmc->protocol_used;
	}
	return IRDMA_ROCE_PROTOCOL_ONLY;
}

/**
 * irdma_get_next_vf_idx - return the next vf_idx available
 * @dev: pointer to RDMA dev structure
 */
static u16 irdma_get_next_vf_idx(struct irdma_sc_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (!dev->vc_dev[vf_idx])
			break;
	}

	return vf_idx < dev->num_vfs ? vf_idx : IRDMA_VCHNL_INVALID_VF_IDX;
}

/**
 * irdma_put_vfdev - put vfdev and free memory
 * @dev: pointer to RDMA dev structure
 * @vc_dev: pointer to RDMA vf dev structure
 */
void irdma_put_vfdev(struct irdma_sc_dev *dev, struct irdma_vchnl_dev *vc_dev)
{
	if (refcount_dec_and_test(&vc_dev->refcnt)) {
		struct irdma_virt_mem virt_mem;

		if (vc_dev->hmc_info.sd_table.sd_entry) {
			virt_mem.va = vc_dev->hmc_info.sd_table.sd_entry;
			virt_mem.size = sizeof(struct irdma_hmc_sd_entry) *
					(vc_dev->hmc_info.sd_table.sd_cnt +
					 vc_dev->hmc_info.first_sd_index);
			kfree(virt_mem.va);
		}

		virt_mem.va = vc_dev;
		virt_mem.size = sizeof(*vc_dev);
		kfree(virt_mem.va);
	}
}

static int irdma_negotiate_vchnl_rev(u8 hw_rev, u16 op_ver, u32 *vchnl_ver)
{
	if (op_ver < IRDMA_VCHNL_CHNL_VER_MIN)
		return -EOPNOTSUPP;

	switch (hw_rev) {
	case IRDMA_GEN_3:
	default:
		if (op_ver < IRDMA_VCHNL_OP_GET_VER_V2)
			return -EOPNOTSUPP;

		fallthrough;
	case IRDMA_GEN_2:
		*vchnl_ver = min((u16)IRDMA_VCHNL_CHNL_VER_MAX, op_ver);
		break;
	case IRDMA_GEN_1:
		/* GEN_1 does not have VF support */
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * irdma_pf_get_vf_hmc_fcn - Get hmc fcn from CQP for VF
 * @dev: pointer to RDMA dev structure
 * @vf_id: vf id of the hmc fcn requester
 * @protocol_used: protocol family supported for the VF
 */
static struct irdma_vchnl_dev *irdma_pf_get_vf_hmc_fcn(struct irdma_sc_dev *dev,
						       u16 vf_id,
						       enum irdma_protocol_used protocol_used)
{
	struct irdma_hmc_fcn_info hmc_fcn_info;
	struct irdma_virt_mem virt_mem;
	struct irdma_vchnl_dev *vc_dev;
	struct irdma_sc_vsi *vsi;
	u16 iw_vf_idx = 0;
	u32 size;

	iw_vf_idx = irdma_get_next_vf_idx(dev);
	if (iw_vf_idx == IRDMA_VCHNL_INVALID_VF_IDX)
		return NULL;

	size = sizeof(*vc_dev) +
	       sizeof(struct irdma_hmc_obj_info) * IRDMA_HMC_IW_MAX;
	virt_mem.size = size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);

	if (!virt_mem.va) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: VF%u Unable to allocate a VF device structure.\n",
			  vf_id);
		return NULL;
	}

	vc_dev = virt_mem.va;
	vc_dev->pf_dev = dev;
	vc_dev->vf_id = vf_id;
	vc_dev->iw_vf_idx = iw_vf_idx;
	vc_dev->protocol_used = protocol_used;
	vc_dev->pf_hmc_initialized = false;
	vc_dev->hmc_info.hmc_obj = (struct irdma_hmc_obj_info *)(&vc_dev[1]);

	ibdev_dbg(to_ibdev(dev), "VIRT: vc_dev %p, hmc_info %p, hmc_obj %p\n",
		  vc_dev, &vc_dev->hmc_info, vc_dev->hmc_info.hmc_obj);
	vsi = irdma_update_vsi_ctx(dev, vc_dev, true);
	if (!vsi) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: VF%u failed updating vsi ctx .\n", vf_id);
		dev->vc_dev[vc_dev->iw_vf_idx] = NULL;
		kfree(virt_mem.va);
		return NULL;
	}

	refcount_set(&vc_dev->refcnt, 1);
	dev->vc_dev[iw_vf_idx] = vc_dev;
	vc_dev->vf_vsi = vsi;
	vsi->vf_id = (u16)vc_dev->vf_id;
	vsi->vc_dev = vc_dev;

	irdma_set_hmc_fcn_info(vc_dev, &hmc_fcn_info);
	if (irdma_cqp_manage_hmc_fcn_cmd(dev, &hmc_fcn_info,
					 &vc_dev->pmf_index)) {
		irdma_update_vsi_ctx(dev, vc_dev, false);
		dev->vc_dev[vc_dev->iw_vf_idx] = NULL;
		kfree(virt_mem.va);
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: VF%u error CQP Get HMC Function operation.\n",
			  vf_id);
		return NULL;
	}

	ibdev_dbg(to_ibdev(dev), "VIRT: HMC Function allocated = 0x%08x\n",
		  vc_dev->pmf_index);

	/* Caller references vc_dev */
	refcount_inc(&vc_dev->refcnt);
	return vc_dev;
}

/**
 * irdma_pf_put_vf_hmc_fcn - Put hmc fcn from CQP for VF
 * @dev: pointer to RDMA dev structure
 * @vc_dev: vf dev structure
 */
void irdma_pf_put_vf_hmc_fcn(struct irdma_sc_dev *dev,
			     struct irdma_vchnl_dev *vc_dev)
{
	struct irdma_hmc_fcn_info hmc_fcn_info;

	irdma_set_hmc_fcn_info(vc_dev, &hmc_fcn_info);
	hmc_fcn_info.free_fcn = true;
	if (irdma_cqp_manage_hmc_fcn_cmd(dev, &hmc_fcn_info,
					 &vc_dev->pmf_index))
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: VF%u error CQP Free HMC Function operation.\n",
			  vc_dev->vf_id);

	irdma_remove_vc_dev(dev, vc_dev);

	irdma_update_vsi_ctx(dev, vc_dev, false);
	irdma_put_vfdev(dev, vc_dev);
}

/**
 * irdma_recv_pf_worker - PF receive worker processes inbound vchnl request
 * @work: work element for the vchnl request
 */
static void irdma_recv_pf_worker(struct work_struct *work)
{
	struct irdma_vchnl_work *vchnl_work =
		container_of(work, struct irdma_vchnl_work, work);
	struct irdma_vchnl_op_buf *vchnl_msg =
		(struct irdma_vchnl_op_buf *)&vchnl_work->vf_msg_buf;
	u16 vf_id = vchnl_work->vf_id, qs_handle = 0, resp_len = 0;
	void *param = vchnl_msg->buf, *resp_param = NULL;
	int resp_code = 0;
	struct irdma_sc_dev *dev = vchnl_work->dev;
	struct irdma_vchnl_rdma_caps caps = {};
	struct irdma_vchnl_dev *vc_dev = NULL;
	struct irdma_virt_mem virt_mem;
	u8 vlan_parse_en;
	u32 vchnl_ver;

	ibdev_dbg(to_ibdev(dev), "VIRT: opcode %u", vchnl_msg->op_code);
	vc_dev = irdma_find_vc_dev(dev, vf_id);
	if (vc_dev && vc_dev->reset_en)
		goto free_work;

	switch (vchnl_msg->op_code) {
	case IRDMA_VCHNL_OP_GET_VER:
		resp_code = irdma_negotiate_vchnl_rev(
			dev->hw_attrs.uk_attrs.hw_rev, vchnl_msg->op_ver,
			&vchnl_ver);

		resp_param = &vchnl_ver;
		resp_len = sizeof(vchnl_ver);
		break;
	case IRDMA_VCHNL_OP_GET_HMC_FCN:
		if (!vc_dev) {
			vc_dev = irdma_pf_get_vf_hmc_fcn(
				dev, vf_id, irdma_get_protocol_used(vchnl_msg));
			if (!vc_dev) {
				resp_code = -ENODEV;
				break;
			}
		}
		resp_param = &vc_dev->pmf_index;
		resp_len = sizeof(vc_dev->pmf_index);
		break;
	case IRDMA_VCHNL_OP_PUT_HMC_FCN:
		if (!vc_dev)
			goto free_work;

		irdma_pf_put_vf_hmc_fcn(dev, vc_dev);
		break;

	case IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE:
		if (!vc_dev)
			goto free_work;

		resp_code = irdma_pf_add_hmc_obj(vc_dev, param);
		break;
	case IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE:
		if (!vc_dev)
			goto free_work;

		resp_code = irdma_pf_del_hmc_obj(vc_dev, param);
		break;
	case IRDMA_VCHNL_OP_MANAGE_WS_NODE:
		if (!vc_dev)
			goto free_work;

		resp_code = irdma_pf_manage_ws_node(vc_dev, param, &qs_handle);
		resp_param = &qs_handle;
		resp_len = sizeof(qs_handle);
		break;
	case IRDMA_VCHNL_OP_GET_REG_LAYOUT:
		if (!vc_dev)
			goto free_work;

		irdma_pf_get_reg_layout(vc_dev, param);
		resp_param = param;
		resp_len = IRDMA_VCHNL_REGFLD_BUF_SIZE;
		break;
	case IRDMA_VCHNL_OP_VLAN_PARSING:
		if (!vc_dev)
			goto free_work;

		if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2)
			irdma_update_vf_vlan_cfg(dev, vc_dev);
		/* In Linux port_vlan_id != 0 indicates port vlan is enabled.
		 * Linux is always in double VLAN mode.
		 */
		vlan_parse_en = !vc_dev->port_vlan_en;
		ibdev_dbg(to_ibdev(dev), "VIRT: vlan_parse_en = 0x%x\n",
			  vlan_parse_en);

		resp_param = &vlan_parse_en;
		resp_len = sizeof(vlan_parse_en);
		break;

	case IRDMA_VCHNL_OP_GET_RDMA_CAPS:
		caps.hw_rev = dev->hw_attrs.uk_attrs.hw_rev;

		resp_len = sizeof(caps);
		resp_param = &caps;
		break;
	default:
		ibdev_dbg(to_ibdev(dev), "VIRT: Invalid OpCode 0x%x\n",
			  vchnl_msg->op_code);
		resp_code = -EOPNOTSUPP;
	}

	irdma_vchnl_pf_send_resp(dev, vf_id, vchnl_msg, resp_param, resp_len,
				 resp_code);
free_work:
	if (vc_dev)
		irdma_put_vfdev(dev, vc_dev);

	virt_mem.va = work;
	kfree(virt_mem.va);
}

/**
 * irdma_vchnl_pf_verify_msg - validate vf received vchannel message size
 * @vchnl_msg: inbound vf vchannel message
 * @len: length of the virtual channels message
 */
static bool irdma_vchnl_pf_verify_msg(struct irdma_vchnl_op_buf *vchnl_msg,
				      u16 len)
{
	u16 op_code = vchnl_msg->op_code;
	u16 op_size;

	if (len > IRDMA_VCHNL_MAX_MSG_SIZE)
		return false;

	if (len < sizeof(*vchnl_msg))
		return false;

	switch (op_code) {
	case IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE:
	case IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE:
		op_size = sizeof(struct irdma_vchnl_hmc_obj_range);
		if (len < sizeof(*vchnl_msg) + op_size)
			return false;
		break;
	case IRDMA_VCHNL_OP_MANAGE_WS_NODE:
		op_size = sizeof(struct irdma_vchnl_manage_ws_node);
		if (len < sizeof(*vchnl_msg) + op_size)
			return false;
		break;
	case IRDMA_VCHNL_OP_GET_HMC_FCN:
		if (vchnl_msg->op_ver >= IRDMA_VCHNL_OP_GET_HMC_FCN_V1) {
			if (len < sizeof(*vchnl_msg) +
			    sizeof(struct irdma_vchnl_req_hmc_info))
				return false;
		}
		break;
	case IRDMA_VCHNL_OP_GET_VER:
	case IRDMA_VCHNL_OP_PUT_HMC_FCN:
	case IRDMA_VCHNL_OP_GET_REG_LAYOUT:
	case IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP:
	case IRDMA_VCHNL_OP_QUEUE_VECTOR_UNMAP:
	case IRDMA_VCHNL_OP_VLAN_PARSING:
	case IRDMA_VCHNL_OP_GET_RDMA_CAPS:
		if (len < sizeof(*vchnl_msg))
			return false;
		break;

	default:
		return false;
	}

	return true;
}
/**
 * irdma_vchnl_recv_pf - Receive PF virtual channel messages
 * @dev: RDMA device pointer
 * @vf_id: Virtual function ID associated with the message
 * @msg: Virtual channel message buffer pointer
 * @len: Length of the virtual channels message
 */
int irdma_vchnl_recv_pf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	struct irdma_vchnl_work *work;
	struct irdma_virt_mem workmem;

	ibdev_dbg(to_ibdev(dev), "VIRT: VF%u: msg %p len %u chnl up %u",
		  vf_id, msg, len, dev->vchnl_up);

	if (!msg ||
	    !irdma_vchnl_pf_verify_msg((struct irdma_vchnl_op_buf *)msg, len))
		return -EINVAL;

	if (!dev->vchnl_up)
		return -EBUSY;

	workmem.size = sizeof(*work);
	workmem.va = kzalloc(workmem.size, GFP_KERNEL);
	if (!workmem.va)
		return -ENOMEM;

	work = workmem.va;
	memcpy(&work->vf_msg_buf, msg, len);
	work->dev = dev;
	work->vf_id = vf_id;
	work->len = len;
	INIT_WORK(&work->work, irdma_recv_pf_worker);
	queue_work(dev->vchnl_wq, &work->work);

	return 0;
}

/**
 * irdma_vchnl_req_verify_resp - Verify requested response size
 * @vchnl_req: vchnl message requested
 * @resp_len: response length sent from vchnl peer
 */
static int irdma_vchnl_req_verify_resp(struct irdma_vchnl_req *vchnl_req,
				       u16 resp_len)
{
	switch (vchnl_req->vchnl_msg->op_code) {
	case IRDMA_VCHNL_OP_GET_VER:
	case IRDMA_VCHNL_OP_GET_HMC_FCN:
	case IRDMA_VCHNL_OP_PUT_HMC_FCN:
	case IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE:
	case IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE:
	case IRDMA_VCHNL_OP_MANAGE_WS_NODE:
	case IRDMA_VCHNL_OP_VLAN_PARSING:
		if (resp_len != vchnl_req->parm_len)
			return -EBADMSG;
		break;
	case IRDMA_VCHNL_OP_GET_RDMA_CAPS:
		if (resp_len < IRDMA_VCHNL_OP_GET_RDMA_CAPS_MIN_SIZE)
			return -EBADMSG;
		break;
	case IRDMA_VCHNL_OP_MANAGE_PUSH_PAGE:
	case IRDMA_VCHNL_OP_GET_REG_LAYOUT:
	case IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP:
	case IRDMA_VCHNL_OP_QUEUE_VECTOR_UNMAP:
		break;
	default:
		return -EBADMSG;
	}

	return 0;
}

static void irdma_free_vchnl_req_msg(struct irdma_vchnl_req *vchnl_req)
{
	kfree(vchnl_req->vchnl_msg);
}

static int irdma_alloc_vchnl_req_msg(struct irdma_vchnl_req *vchnl_req,
				     struct irdma_vchnl_req_init_info *info)
{
	struct irdma_vchnl_op_buf *vchnl_msg;

	vchnl_msg = kzalloc(IRDMA_VCHNL_MAX_MSG_SIZE, GFP_KERNEL);

	if (!vchnl_msg)
		return -ENOMEM;

	vchnl_msg->op_ctx = (uintptr_t)vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg) + info->req_parm_len;
	if (info->req_parm_len)
		memcpy(vchnl_msg->buf, info->req_parm, info->req_parm_len);
	vchnl_msg->op_code = info->op_code;
	vchnl_msg->op_ver = info->op_ver;

	vchnl_req->vchnl_msg = vchnl_msg;
	vchnl_req->parm = info->resp_parm;
	vchnl_req->parm_len = info->resp_parm_len;

	return 0;
}

static int irdma_vchnl_req_send_sync(struct irdma_sc_dev *dev,
				     struct irdma_vchnl_req_init_info *info)
{
	struct irdma_vchnl_req vchnl_req = {};
	u16 resp_len = sizeof(dev->vc_recv_buf);
	u16 msg_len;
	u8 *msg;
	int ret;

	ret = irdma_alloc_vchnl_req_msg(&vchnl_req, info);
	if (ret)
		return ret;

	msg_len = vchnl_req.vchnl_msg->buf_len;
	msg = (u8 *)vchnl_req.vchnl_msg;

	mutex_lock(&dev->vchnl_mutex);
	ret = irdma_vchnl_send_sync(dev, msg, msg_len, dev->vc_recv_buf,
				    &resp_len);
	if (ret)
		goto exit;

	ret = irdma_vchnl_req_get_resp(dev, &vchnl_req);
exit:
	mutex_unlock(&dev->vchnl_mutex);
	ibdev_dbg(to_ibdev(dev),
		  "VIRT: virtual channel send %s caller: %pS ret=%d op=%u op_ver=%u req_len=%u parm_len=%u resp_len=%u\n",
		  !ret ? "SUCCEEDS" : "FAILS", __builtin_return_address(0),
		  ret, vchnl_req.vchnl_msg->op_code,
		  vchnl_req.vchnl_msg->op_ver, vchnl_req.vchnl_msg->buf_len,
		  vchnl_req.parm_len, vchnl_req.resp_len);
	irdma_free_vchnl_req_msg(&vchnl_req);

	return ret;
}

/**
 * irdma_vchnl_req_manage_push_pg - manage push page
 * @dev: rdma device pointer
 * @add: Add or remove push page
 * @qs_handle: qs_handle of push page for add
 * @pg_idx: index of push page that is added or removed
 */
int irdma_vchnl_req_manage_push_pg(struct irdma_sc_dev *dev, bool add,
				   u32 qs_handle, u32 *pg_idx)
{
	struct irdma_vchnl_manage_push_page add_push_pg = {};
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	add_push_pg.add = add;
	add_push_pg.pg_idx = add ? 0 : *pg_idx;
	add_push_pg.qs_handle = qs_handle;

	info.op_code = IRDMA_VCHNL_OP_MANAGE_PUSH_PAGE;
	info.op_ver = IRDMA_VCHNL_OP_MANAGE_PUSH_PAGE_V0;
	info.req_parm = &add_push_pg;
	info.req_parm_len = sizeof(add_push_pg);
	info.resp_parm = pg_idx;
	info.resp_parm_len = sizeof(*pg_idx);

	ibdev_dbg(to_ibdev(dev),
		  "VIRT: Sending msg: manage_push_pg add = %d, idx %u, qsh %u\n",
		  add_push_pg.add, add_push_pg.pg_idx, add_push_pg.qs_handle);

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_get_reg_layout - Get Register Layout
 * @dev: RDMA device pointer
 */
int irdma_vchnl_req_get_reg_layout(struct irdma_sc_dev *dev)
{
	u16 reg_idx, reg_id, tmp_reg_id, regfld_idx, regfld_id, tmp_regfld_id;
	struct irdma_vchnl_reg_field_info *regfld_array = NULL;
	u8 resp_buffer[IRDMA_REGMAP_RESP_BUF_SIZE] = {};
	struct vchnl_regfld_map_elem *regfld_map_array;
	struct irdma_vchnl_req_init_info info = {};
	struct vchnl_reg_map_elem *reg_map_array;
	struct irdma_vchnl_reg_info *reg_array;
	u8 num_bits, shift_cnt;
	u8 __iomem *hw_addr;
	u16 buf_len = 0;
	u64 bitmask;
	u32 rindex;
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_GET_REG_LAYOUT;
	info.op_ver = IRDMA_VCHNL_OP_GET_REG_LAYOUT_V0;
	info.resp_parm = resp_buffer;
	info.resp_parm_len = sizeof(resp_buffer);

	ret = irdma_vchnl_req_send_sync(dev, &info);

	if (ret)
		return ret;

	/* parse the response buffer and update reg info*/
	/* Parse registers till invalid */
	/* Parse register fields till invalid */
	reg_array = (struct irdma_vchnl_reg_info *)resp_buffer;
	for (rindex = 0; rindex < IRDMA_VCHNL_REG_COUNT; rindex++) {
		buf_len += sizeof(*reg_array);
		if (buf_len >= sizeof(resp_buffer))
			return -ENOMEM;

		regfld_array =
			(struct irdma_vchnl_reg_field_info *)&reg_array[rindex + 1];
		reg_id = reg_array[rindex].reg_id;
		if (reg_id == IRDMA_VCHNL_REG_INV_ID)
			break;

		reg_id &= ~IRDMA_VCHNL_REG_PAGE_REL;
		if (reg_id >= IRDMA_VCHNL_REG_COUNT)
			return -EINVAL;

		/* search regmap for register index in hw_regs.*/
		reg_map_array = vchnl_reg_map;
		do {
			tmp_reg_id = reg_map_array->reg_id;
			if (tmp_reg_id == reg_id)
				break;

			reg_map_array++;
		} while (tmp_reg_id != IRDMA_VCHNL_REG_INV_ID);
		if (tmp_reg_id != reg_id)
			continue;

		reg_idx = reg_map_array->reg_idx;
		hw_addr = dev->hw->hw_addr;

		/* Page relative, DB Offset do not need bar offset */
		if (reg_idx == IRDMA_DB_ADDR_OFFSET ||
		    (reg_array[rindex].reg_id & IRDMA_VCHNL_REG_PAGE_REL))
			hw_addr = NULL;

		/* Update the local HW struct */
		dev->hw_regs[reg_idx] =
			(u32 __iomem *)(hw_addr + reg_array[rindex].reg_offset);
	}

	if (!regfld_array)
		return -ENOMEM;

	/* set up doorbell variables using mapped DB page */
	dev->wqe_alloc_db = dev->hw_regs[IRDMA_WQEALLOC];
	dev->cq_arm_db = dev->hw_regs[IRDMA_CQARM];
	dev->aeq_alloc_db = dev->hw_regs[IRDMA_AEQALLOC];
	dev->cqp_db = dev->hw_regs[IRDMA_CQPDB];
	dev->cq_ack_db = dev->hw_regs[IRDMA_CQACK];

	for (rindex = 0; rindex < IRDMA_VCHNL_REGFLD_COUNT; rindex++) {
		buf_len += sizeof(*regfld_array);
		if ((buf_len - 1) > sizeof(resp_buffer))
			break;

		if (regfld_array[rindex].fld_id == IRDMA_VCHNL_REGFLD_INV_ID)
			break;

		regfld_id = regfld_array[rindex].fld_id;
		regfld_map_array = vchnl_regfld_map;
		do {
			tmp_regfld_id = regfld_map_array->regfld_id;
			if (tmp_regfld_id == regfld_id)
				break;

			regfld_map_array++;
		} while (tmp_regfld_id != IRDMA_VCHNL_REGFLD_INV_ID);

		if (tmp_regfld_id != regfld_id)
			continue;

		regfld_idx = regfld_map_array->regfld_idx;

		num_bits = regfld_array[rindex].fld_bits;
		shift_cnt = regfld_array[rindex].fld_shift;
		if ((num_bits + shift_cnt > 64) || !num_bits) {
			ibdev_dbg(to_ibdev(dev),
				  "ERR: Invalid field mask id %d bits %d shift %d",
				  regfld_id, num_bits, shift_cnt);

			continue;
		}

		bitmask = (1ULL << num_bits) - 1;
		dev->hw_masks[regfld_idx] = bitmask << shift_cnt;
		dev->hw_shifts[regfld_idx] = shift_cnt;
	}

	return 0;
}

/**
 * irdma_vchnl_req_aeq_vec_map - Map AEQ to vector on this function
 * @dev: RDMA device pointer
 * @v_idx: vector index
 */
int irdma_vchnl_req_aeq_vec_map(struct irdma_sc_dev *dev, u32 v_idx)
{
	struct irdma_vchnl_req_init_info info = {};
	struct irdma_vchnl_qvlist_info *qvl;
	struct irdma_vchnl_qv_info *qv;
	u16 qvl_size, num_vectors = 1;
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	qvl_size = struct_size(qvl, qv_info, num_vectors);

	qvl = kzalloc(qvl_size, GFP_KERNEL);
	if (!qvl)
		return -ENOMEM;

	qvl->num_vectors = 1;
	qv = qvl->qv_info;

	qv->ceq_idx = IRDMA_Q_INVALID_IDX;
	qv->v_idx = v_idx;
	qv->itr_idx = IRDMA_IDX_ITR0;

	info.op_code = IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP;
	info.op_ver = IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP_V0;
	info.req_parm = qvl;
	info.req_parm_len = qvl_size;

	ret = irdma_vchnl_req_send_sync(dev, &info);
	kfree(qvl);

	return ret;
}

/**
 * irdma_vchnl_req_ceq_vec_map - Map CEQ to vector on this function
 * @dev: RDMA device pointer
 * @ceq_id: CEQ index
 * @v_idx: vector index
 */
int irdma_vchnl_req_ceq_vec_map(struct irdma_sc_dev *dev, u16 ceq_id, u32 v_idx)
{
	struct irdma_vchnl_req_init_info info = {};
	struct irdma_vchnl_qvlist_info *qvl;
	struct irdma_vchnl_qv_info *qv;
	u16 qvl_size, num_vectors = 1;
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	qvl_size = struct_size(qvl, qv_info, num_vectors);

	qvl = kzalloc(qvl_size, GFP_KERNEL);
	if (!qvl)
		return -ENOMEM;

	qvl->num_vectors = num_vectors;
	qv = qvl->qv_info;

	qv->aeq_idx = IRDMA_Q_INVALID_IDX;
	qv->ceq_idx = ceq_id;
	qv->v_idx = v_idx;
	qv->itr_idx = IRDMA_IDX_ITR0;

	info.op_code = IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP;
	info.op_ver = IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP_V0;
	info.req_parm = qvl;
	info.req_parm_len = qvl_size;

	ret = irdma_vchnl_req_send_sync(dev, &info);
	kfree(qvl);

	return ret;
}

/**
 * irdma_vchnl_req_recv - Receive virtual channel messages on requester function
 * @dev: RDMA device pointer
 * @vf_id: Virtual function ID associated with the message
 * @msg: Virtual channel message buffer pointer
 * @len: Length of the virtual channels message
 */
int irdma_vchnl_req_recv(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	if (len < sizeof(struct irdma_vchnl_resp_buf))
		return -EINVAL;
	if (len > IRDMA_VCHNL_MAX_MSG_SIZE)
		len = IRDMA_VCHNL_MAX_MSG_SIZE;

	memcpy(dev->vc_recv_buf, msg, len);
	dev->vc_recv_len = len;

	return 0;
}

/**
 * irdma_vchnl_req_get_ver - Request Channel version
 * @dev: RDMA device pointer
 * @ver_req: Virtual channel version requested
 * @ver_res: Virtual channel version response
 */
int irdma_vchnl_req_get_ver(struct irdma_sc_dev *dev, u16 ver_req, u32 *ver_res)
{
	struct irdma_vchnl_req_init_info info = {};
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_GET_VER;
	info.op_ver = ver_req;
	info.resp_parm = ver_res;
	info.resp_parm_len = sizeof(*ver_res);

	ret = irdma_vchnl_req_send_sync(dev, &info);
	if (ret)
		return ret;

	if (*ver_res < IRDMA_VCHNL_CHNL_VER_MIN) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: %s unsupported vchnl version 0x%0x\n",
			  __func__, *ver_res);
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * irdma_vchnl_req_get_hmc_fcn - Request VF HMC Function
 * @dev: RDMA device pointer
 */
int irdma_vchnl_req_get_hmc_fcn(struct irdma_sc_dev *dev)
{
	struct irdma_vchnl_req_hmc_info req_hmc = {};
	struct irdma_vchnl_resp_hmc_info resp_hmc = {};
	struct irdma_vchnl_req_init_info info = {};
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_GET_HMC_FCN;
	info.op_ver = IRDMA_VCHNL_OP_GET_HMC_FCN_V0;
	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		info.op_ver = IRDMA_VCHNL_OP_GET_HMC_FCN_V2;
		req_hmc.protocol_used = dev->protocol_used;
		info.req_parm_len = sizeof(req_hmc);
		info.req_parm = &req_hmc;
		info.resp_parm = &resp_hmc;
		info.resp_parm_len = sizeof(resp_hmc);
	}

	ret = irdma_vchnl_req_send_sync(dev, &info);

	if (ret)
		return ret;

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		int i;

		for (i = 0;  i < IRDMA_MAX_USER_PRIORITY; i++) {
			dev->qos[i].qs_handle[0] = resp_hmc.qs_handle[i];
			dev->qos[i].valid = true;
		}
	}
	return 0;
}

/**
 * irdma_vchnl_req_put_hmc_fcn - Free VF HMC Function
 * @dev: RDMA device pointer
 */
int irdma_vchnl_req_put_hmc_fcn(struct irdma_sc_dev *dev)
{
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_PUT_HMC_FCN;
	info.op_ver = IRDMA_VCHNL_OP_PUT_HMC_FCN_V0;

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_manage_ws_node - manage ws node
 * @dev: RDMA device pointer
 * @add: Add or remove ws node
 * @user_pri: user priority of ws node
 * @qs_handle: qs_handle updated from the vchnl response
 */
int irdma_vchnl_req_manage_ws_node(struct irdma_sc_dev *dev, bool add,
				   u8 user_pri, u16 *qs_handle)
{
	struct irdma_vchnl_manage_ws_node ws_node = {};
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	ws_node.add = add;
	ws_node.user_pri = user_pri;

	info.op_code = IRDMA_VCHNL_OP_MANAGE_WS_NODE;
	info.op_ver = IRDMA_VCHNL_OP_MANAGE_WS_NODE_V0;
	info.req_parm = &ws_node;
	info.req_parm_len = sizeof(ws_node);
	if (add) {
		info.resp_parm  = qs_handle;
		info.resp_parm_len = sizeof(*qs_handle);
	}

	ibdev_dbg(to_ibdev(dev),
		  "VIRT: Sending message: manage_ws_node add = %d, user_pri = %d\n",
		  ws_node.add, ws_node.user_pri);

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_add_hmc_objs - Add HMC Object
 * @dev: RDMA device pointer
 * @rsrc_type: HMC Resource type
 * @start_index: Starting index of the objects to be added
 * @rsrc_count: Number of resources to be added
 */
int irdma_vchnl_req_add_hmc_objs(struct irdma_sc_dev *dev,
				 enum irdma_hmc_rsrc_type rsrc_type,
				 u32 start_index, u32 rsrc_count)
{
	struct irdma_vchnl_hmc_obj_range add_hmc_obj = {};
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	add_hmc_obj.obj_type = (u16)rsrc_type;
	add_hmc_obj.start_index = start_index;
	add_hmc_obj.obj_count = rsrc_count;

	info.op_code = IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE;
	info.op_ver = IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE_V0;
	info.req_parm = &add_hmc_obj;
	info.req_parm_len = sizeof(add_hmc_obj);

	ibdev_dbg(to_ibdev(dev),
		  "VIRT: Sending message: obj_type = %d, start_index = %d, obj_count = %d\n",
		  add_hmc_obj.obj_type, add_hmc_obj.start_index,
		  add_hmc_obj.obj_count);

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_del_hmc_obj - del HMC obj
 * @dev: RDMA device pointer
 * @rsrc_type: HMC Resource type
 * @start_index: Starting index of the object to delete
 * @rsrc_count: Number of resources to be delete
 */
int irdma_vchnl_req_del_hmc_obj(struct irdma_sc_dev *dev,
				enum irdma_hmc_rsrc_type rsrc_type,
				u32 start_index, u32 rsrc_count)
{
	struct irdma_vchnl_hmc_obj_range hmc_obj = {};
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	hmc_obj.obj_type = (u16)rsrc_type;
	hmc_obj.start_index = start_index;
	hmc_obj.obj_count = rsrc_count;

	info.op_code = IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE;
	info.op_ver = IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE_V0;
	info.req_parm = &hmc_obj;
	info.req_parm_len = sizeof(hmc_obj);

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_get_vlan_parsing_cfg - Find if vlan should be processed
 * @dev: Dev pointer
 * @vlan_parse_en: vlan parsing enabled
 */
int irdma_vchnl_req_get_vlan_parsing_cfg(struct irdma_sc_dev *dev,
					 u8 *vlan_parse_en)
{
	struct irdma_vchnl_req_init_info info = {};

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_VLAN_PARSING;
	info.op_ver = IRDMA_VCHNL_OP_VLAN_PARSING_V0;
	info.req_parm = vlan_parse_en;
	info.req_parm_len = sizeof(*vlan_parse_en);
	info.resp_parm = vlan_parse_en;
	info.resp_parm_len = sizeof(*vlan_parse_en);

	return irdma_vchnl_req_send_sync(dev, &info);
}

/**
 * irdma_vchnl_req_get_caps - Request RDMA capabilities
 * @dev: RDMA device pointer
 */
int irdma_vchnl_req_get_caps(struct irdma_sc_dev *dev)
{
	struct irdma_vchnl_req_init_info info = {};
	int ret;

	if (!dev->vchnl_up)
		return -EBUSY;

	info.op_code = IRDMA_VCHNL_OP_GET_RDMA_CAPS;
	info.op_ver = IRDMA_VCHNL_OP_GET_RDMA_CAPS_V0;
	info.resp_parm = &dev->vc_caps;
	info.resp_parm_len = sizeof(dev->vc_caps);

	ret = irdma_vchnl_req_send_sync(dev, &info);

	if (ret)
		return ret;

	if (!dev->vc_caps.max_hw_push_len)
		dev->vc_caps.max_hw_push_len = IRDMA_DEFAULT_MAX_PUSH_LEN;

	if (dev->vc_caps.hw_rev > IRDMA_GEN_MAX ||
	    dev->vc_caps.hw_rev < IRDMA_GEN_2) {
		ibdev_dbg(to_ibdev(dev),
			  "ERR: %s unsupported hw_rev version 0x%0x\n",
			  __func__, dev->vc_caps.hw_rev);
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * irdma_vchnl_req_get_resp - Receive the inbound vchnl response.
 * @dev: Dev pointer
 * @vchnl_req: Vchannel request
 */
int irdma_vchnl_req_get_resp(struct irdma_sc_dev *dev,
			     struct irdma_vchnl_req *vchnl_req)
{
	struct irdma_vchnl_resp_buf *vchnl_msg_resp =
		(struct irdma_vchnl_resp_buf *)dev->vc_recv_buf;
	u16 resp_len;
	int ret;

	if ((uintptr_t)vchnl_req != (uintptr_t)vchnl_msg_resp->op_ctx) {
		ibdev_dbg(to_ibdev(dev),
			  "VIRT: error vchnl context value does not match\n");
		return -EBADMSG;
	}

	resp_len = dev->vc_recv_len - sizeof(*vchnl_msg_resp);
	resp_len = min(resp_len, vchnl_req->parm_len);

	if (irdma_vchnl_req_verify_resp(vchnl_req, resp_len))
		return -EBADMSG;

	ret = (int)vchnl_msg_resp->op_ret;
	if (ret)
		return ret;

	vchnl_req->resp_len = 0;
	if (vchnl_req->parm_len && vchnl_req->parm && resp_len) {
		memcpy(vchnl_req->parm, vchnl_msg_resp->buf, resp_len);
		vchnl_req->resp_len = resp_len;
		ibdev_dbg(to_ibdev(dev), "VIRT: Got response, data size %u\n",
			  resp_len);
	}

	return 0;
}
