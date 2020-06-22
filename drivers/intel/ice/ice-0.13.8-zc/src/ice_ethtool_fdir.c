// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

/* flow director ethtool support for ice */

#include "ice.h"
#include "ice_lib.h"
#include "ice_fdir.h"
#include "ice_flow.h"

#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
static const u8 full_ipv6_addr_mask[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static u8 zero_ipv6_addr_mask[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#endif

/* calls to ice_flow_add_prof require the number of segments in the array
 * for segs_cnt. In this code that is one more than the index.
 */
#define TNL_SEG_CNT(_TNL_) ((_TNL_) + 1)

/**
 * ice_fltr_to_ethtool_flow - convert ICE filter type values to ethtool
 * flow type values
 * @flow: ICDE filter type to be converted
 *
 * Returns the corresponding ethtool flow type.
 */
static int ice_fltr_to_ethtool_flow(enum ice_fltr_ptype flow)
{
	switch (flow) {
	case ICE_FLTR_PTYPE_NONF_IPV4_TCP:
		return TCP_V4_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV4_UDP:
		return UDP_V4_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV6_TCP:
		return TCP_V6_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV6_UDP:
		return UDP_V6_FLOW;
	case ICE_FLTR_PTYPE_NONF_IPV6_SCTP:
		return SCTP_V6_FLOW;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case ICE_FLTR_PTYPE_NONF_IPV6_OTHER:
		return IPV6_USER_FLOW;
#endif
	default:
		/* 0 is undefined ethtool flow */
		return 0;
	}
}

/**
 * ice_ethtool_flow_to_fltr - convert ethtool flow type to ICE filter enum
 * @eth: Ethtool flow type to be converted
 *
 * Returns ICE flow enum
 */
static enum ice_fltr_ptype ice_ethtool_flow_to_fltr(int eth)
{
	switch (eth) {
	case TCP_V4_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV4_TCP;
	case UDP_V4_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV4_UDP;
	case SCTP_V4_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV4_SCTP;
	case IPV4_USER_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV4_OTHER;
	case TCP_V6_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV6_TCP;
	case UDP_V6_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV6_UDP;
	case SCTP_V6_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV6_SCTP;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case IPV6_USER_FLOW:
		return ICE_FLTR_PTYPE_NONF_IPV6_OTHER;
#endif
	default:
		return ICE_FLTR_PTYPE_NONF_NONE;
	}
}

/**
 * ice_is_mask_valid - check mask field set
 * @mask: full mask to check
 * @field: field for which mask should be valid
 *
 * If the mask is fully set return 1. If it is not valid for field return 0.
 */
static int ice_is_mask_valid(u64 mask, u64 field)
{
	return (mask & field) == field;
}

/**
 * ice_get_ethtool_fdir_entry - fill ethtool structure with fdir filter data
 * @hw: ICE hardware structure that contains filter list
 * @cmd: ethtool command data structure to receive the filter data
 *
 * Returns 0 on success and -EINVAL on failure
 */
int ice_get_ethtool_fdir_entry(struct ice_hw *hw, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp;
	struct ice_fdir_fltr *rule;
	struct ice_pf *pf;
	int ret = 0;
	u16 idx;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	mutex_lock(&hw->fdir_fltr_lock);
	rule = ice_fdir_find_fltr_by_idx(hw, fsp->location);

	if (!rule || fsp->location != rule->fltr_id) {
		ret = -EINVAL;
		goto release_lock;
	}

	fsp->flow_type = ice_fltr_to_ethtool_flow(rule->flow_type);

	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	switch (fsp->flow_type) {
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = 0;
		fsp->h_u.usr_ip4_spec.ip4src = rule->ip.v4.dst_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = rule->ip.v4.src_ip;
		fsp->h_u.usr_ip4_spec.l4_4_bytes = rule->ip.v4.l4_header;
		fsp->h_u.usr_ip4_spec.tos = rule->ip.v4.tos;
		fsp->m_u.usr_ip4_spec.ip_ver = 0xFF;
		fsp->m_u.usr_ip4_spec.proto = 0;
		fsp->m_u.usr_ip4_spec.ip4src = rule->mask.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = rule->mask.v4.src_ip;
		fsp->m_u.usr_ip4_spec.l4_4_bytes = rule->mask.v4.l4_header;
		fsp->m_u.usr_ip4_spec.tos = rule->mask.v4.tos;
		break;
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		/* Reverse the src and dest notion, since the HW expects
		 * them to be from Tx perspective where as the input from
		 * user is from Rx filter view.
		 */
		fsp->h_u.tcp_ip4_spec.psrc = rule->ip.v4.dst_port;
		fsp->h_u.tcp_ip4_spec.pdst = rule->ip.v4.src_port;
		fsp->h_u.tcp_ip4_spec.ip4src = rule->ip.v4.dst_ip;
		fsp->h_u.tcp_ip4_spec.ip4dst = rule->ip.v4.src_ip;
		fsp->m_u.tcp_ip4_spec.psrc = rule->mask.v4.dst_port;
		fsp->m_u.tcp_ip4_spec.pdst = rule->mask.v4.src_port;
		fsp->m_u.tcp_ip4_spec.ip4src = rule->mask.v4.dst_ip;
		fsp->m_u.tcp_ip4_spec.ip4dst = rule->mask.v4.src_ip;
		break;

#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case IPV6_USER_FLOW:
		fsp->h_u.usr_ip6_spec.l4_4_bytes = rule->ip.v6.l4_header;
		fsp->h_u.usr_ip6_spec.tclass = rule->ip.v6.tc;
		fsp->h_u.usr_ip6_spec.l4_proto = rule->ip.v6.proto;
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src, rule->ip.v6.dst_ip,
		       sizeof(rule->ip.v6.dst_ip));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst, rule->ip.v6.src_ip,
		       sizeof(rule->ip.v6.src_ip));
		fsp->m_u.usr_ip6_spec.l4_4_bytes = rule->mask.v6.l4_header;
		fsp->m_u.usr_ip6_spec.tclass = rule->mask.v6.tc;
		fsp->m_u.usr_ip6_spec.l4_proto = rule->mask.v6.proto;
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src, rule->mask.v6.dst_ip,
		       sizeof(rule->mask.v6.dst_ip));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst, rule->mask.v6.src_ip,
		       sizeof(rule->mask.v6.src_ip));
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		/* Reverse the src and dest notion, since the HW expects
		 * them to be from Tx perspective where as the input from
		 * user is from Rx filter view.
		 */
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src, rule->ip.v6.dst_ip,
		       sizeof(rule->ip.v6.dst_ip));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst, rule->ip.v6.src_ip,
		       sizeof(rule->ip.v6.src_ip));
		fsp->h_u.tcp_ip6_spec.psrc = rule->ip.v6.dst_port;
		fsp->h_u.tcp_ip6_spec.pdst = rule->ip.v6.src_port;
		fsp->h_u.tcp_ip6_spec.tclass = rule->ip.v6.tc;
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src, rule->mask.v6.dst_ip,
		       sizeof(rule->mask.v6.dst_ip));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst, rule->mask.v6.src_ip,
		       sizeof(rule->mask.v6.src_ip));
		fsp->m_u.tcp_ip6_spec.psrc = rule->mask.v6.dst_port;
		fsp->m_u.tcp_ip6_spec.pdst = rule->mask.v6.src_port;
		fsp->m_u.tcp_ip6_spec.tclass = rule->mask.v6.tc;
		break;
#endif /* HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC */

	default:
		break;
	}

	if (rule->dest_ctl == ICE_FLTR_PRGM_DESC_DEST_DROP_PKT)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = rule->orig_q_index;


	idx = ice_ethtool_flow_to_fltr(fsp->flow_type);
	if (idx == ICE_FLTR_PTYPE_NONF_NONE) {
		pf = (struct ice_pf *)hw->back;
		dev_err(ice_pf_to_dev(pf), "Missing input index for flow_type %d\n",
			rule->flow_type);
	}

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
	return ret;
}

/**
 * ice_get_fdir_fltr_ids - fill buffer with filter IDs of active filters
 * @hw: ICE hardware structure containing the filter list
 * @cmd: ethtool command data structure
 * @rule_locs: ethtool array passed in from OS to receive filter IDs
 *
 * Returns 0 as expected for success by ethtool
 */
int
ice_get_fdir_fltr_ids(struct ice_hw *hw, struct ethtool_rxnfc *cmd,
		      u32 *rule_locs)
{
	struct ice_fdir_fltr *f_rule;
	unsigned int cnt = 0;
	int val = 0;

	cmd->data = ice_get_fdir_cnt_all(hw);

	mutex_lock(&hw->fdir_fltr_lock);
	list_for_each_entry(f_rule, &hw->fdir_list_head, fltr_node) {
		if (cnt == cmd->rule_cnt) {
			val = -EMSGSIZE;
			goto release_lock;
		}
		rule_locs[cnt] = f_rule->fltr_id;
		cnt++;
	}

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
	if (!val)
		cmd->rule_cnt = cnt;
	return val;
}

/**
 * ice_fdir_rem_adq_chnl - remove a ADQ channel from HW filter rules
 * @hw: hardware structure containing filter list
 * @vsi_idx: VSI handel
 */
void ice_fdir_rem_adq_chnl(struct ice_hw *hw, u16 vsi_idx)
{
	int flow;

	if (!hw->fdir_prof)
		return;

	for (flow = 0; flow < ICE_FLTR_PTYPE_MAX; flow++) {
		struct ice_fd_hw_prof *prof = hw->fdir_prof[flow];
		int tun, i;

		if (!prof)
			continue;

		for (i = 0; i < prof->cnt; i++) {
			if (prof->vsi_h[i] != vsi_idx)
				continue;
			for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
				enum ice_block blk = ICE_BLK_FD;
				u64 prof_id;
				u16 vsi_num;

				prof_id = flow + tun * ICE_FLTR_PTYPE_MAX;
				vsi_num = ice_get_hw_vsi_num(hw,
							     prof->vsi_h[i]);
				ice_rem_prof_id_flow(hw, blk, vsi_num, prof_id);
				ice_flow_rem_entry(hw, prof->entry_h[i][tun]);
				prof->entry_h[i][tun] = 0;
			}
			prof->vsi_h[i] = 0;
			break;
		}
		if (i != prof->cnt) {
			for ( ; i < (prof->cnt - 1); i++) {
				for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
					u64 old_entry_h;

					old_entry_h = prof->entry_h[i + 1][tun];
					prof->entry_h[i][tun] = old_entry_h;
				}
				prof->vsi_h[i] = prof->vsi_h[i + 1];
			}
			for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++)
				prof->entry_h[i][tun] = 0;
			prof->vsi_h[i] = 0;
		}
		prof->cnt--;
	}
}

/**
 * ice_fdir_erase_flow_from_hw - remove a flow from the HW profile tables
 * @hw: hardware structure containing the filter list
 * @flow: FDir flow type to release
 */
static void
ice_fdir_erase_flow_from_hw(struct ice_hw *hw, int flow)
{
	int tun;

	if (!hw->fdir_prof || !hw->fdir_prof[flow])
		return;
	for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
		struct ice_fd_hw_prof *prof;
		u64 prof_id;
		int j;

		prof = hw->fdir_prof[flow];
		prof_id = flow + tun * ICE_FLTR_PTYPE_MAX;
		for (j = 0; j < prof->cnt; j++) {
			u16 vsi_num;

			if (!prof->entry_h[j][tun] || !prof->vsi_h[j])
				continue;
			vsi_num = ice_get_hw_vsi_num(hw, prof->vsi_h[j]);
			ice_rem_prof_id_flow(hw, ICE_BLK_FD, vsi_num, prof_id);
			ice_flow_rem_entry(hw, prof->entry_h[j][tun]);
			prof->entry_h[j][tun] = 0;
		}
		ice_flow_rem_prof(hw, ICE_BLK_FD, prof_id);
	}
}

/**
 * ice_fdir_rem_flow - release the ice_flow structures for a filter type
 * @hw: hardware structure containing the filter list
 * @flow_type: FDir flow type to release
 */
static void ice_fdir_rem_flow(struct ice_hw *hw, enum ice_fltr_ptype flow_type)
{
	int flow = (int)flow_type & ~FLOW_EXT;
	struct ice_fd_hw_prof *prof;
	int tun, i;

	if (!hw->fdir_prof || !hw->fdir_prof[flow])
		return;

	prof = hw->fdir_prof[flow];

	ice_fdir_erase_flow_from_hw(hw, flow);
	for (i = 0; i < prof->cnt; i++)
		prof->vsi_h[i] = 0;
	for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
		if (!prof->fdir_seg[tun])
			continue;
		devm_kfree(ice_hw_to_dev(hw), prof->fdir_seg[tun]);
		prof->fdir_seg[tun] = NULL;
	}
	prof->cnt = 0;
}

/**
 * ice_fdir_release_flows - release all flows in use for later replay
 * @hw: pointer to HW instance
 */
void ice_fdir_release_flows(struct ice_hw *hw)
{
	int flow;

	/* release Flow Director HW table entries */
	for (flow = 0; flow < (int)ICE_FLTR_PTYPE_MAX; flow++)
		ice_fdir_erase_flow_from_hw(hw, flow);
}

/**
 * ice_fdir_replay_flows - replay HW Flow Director filter info
 * @hw: pointer to HW instance
 */
void ice_fdir_replay_flows(struct ice_hw *hw)
{
	int flow;

	for (flow = 0; flow < ICE_FLTR_PTYPE_MAX; flow++) {
		int tun;

		if (!hw->fdir_prof[flow] || !hw->fdir_prof[flow]->cnt)
			continue;
		for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
			struct ice_fd_hw_prof *prof;
			struct ice_flow_prof *hw_prof;
			u64 entry_h;
			u64 prof_id;
			int j;

			prof = hw->fdir_prof[flow];
			prof_id = flow + tun * ICE_FLTR_PTYPE_MAX;
			ice_flow_add_prof(hw, ICE_BLK_FD, ICE_FLOW_RX, prof_id,
					  prof->fdir_seg[tun], 1, NULL, 0,
					  &hw_prof);
			for (j = 0; j < prof->cnt; j++) {
				enum ice_flow_priority prio;
				int err;

				entry_h = 0;
				prio = ICE_FLOW_PRIO_NORMAL;
				err = ice_flow_add_entry(hw, ICE_BLK_FD,
							 prof_id,
							 prof->vsi_h[0],
							 prof->vsi_h[j],
							 prio, prof->fdir_seg,
							 NULL, 0, &entry_h);
				if (err) {
					dev_err(ice_hw_to_dev(hw), "Could not replay Flow Director, flow type %d\n",
						flow);
					continue;
				}
				prof->entry_h[j][tun] = entry_h;
			}
		}
	}
}

/**
 * ice_parse_rx_flow_user_data - deconstruct user-defined data
 * @fsp: pointer to ethtool Rx flow specification
 * @data: pointer to userdef data structure for storage
 *
 * Returns 0 on success, negative error value on failure
 */
static int
ice_parse_rx_flow_user_data(struct ethtool_rx_flow_spec *fsp,
			    struct ice_rx_flow_userdef *data)
{
	u64 value, mask;

	memset(data, 0, sizeof(*data));
	if (!(fsp->flow_type & FLOW_EXT))
		return 0;

	value = be64_to_cpu(*((__force __be64 *)fsp->h_ext.data));
	mask = be64_to_cpu(*((__force __be64 *)fsp->m_ext.data));
	if (!mask)
		return 0;

#define ICE_USERDEF_FLEX_WORD_M	GENMASK_ULL(15, 0)
#define ICE_USERDEF_FLEX_OFFS_S	16
#define ICE_USERDEF_FLEX_OFFS_M	GENMASK_ULL(31, ICE_USERDEF_FLEX_OFFS_S)
#define ICE_USERDEF_FLEX_FLTR_M	GENMASK_ULL(31, 0)

	/* 0x1fe is the maximum value for offsets stored in the internal
	 * filtering tables.
	 */
#define ICE_USERDEF_FLEX_MAX_OFFS_VAL 0x1fe

	if (!ice_is_mask_valid(mask, ICE_USERDEF_FLEX_FLTR_M) ||
	    value > ICE_USERDEF_FLEX_FLTR_M)
		return -EINVAL;

	data->flex_word = value & ICE_USERDEF_FLEX_WORD_M;
	data->flex_offset = (value & ICE_USERDEF_FLEX_OFFS_M) >>
			     ICE_USERDEF_FLEX_OFFS_S;
	if (data->flex_offset > ICE_USERDEF_FLEX_MAX_OFFS_VAL)
		return -EINVAL;

	data->flex_fltr = true;

	return 0;
}

/**
 * ice_fdir_num_avail_fltr - return the number of unused flow director filters
 * @hw: pointer to hardware structure
 * @vsi: software VSI structure
 *
 * There are 2 filter pools: guaranteed and best effort(shared). Each VSI can
 * use filters from either pool. The guaranteed pool is divided between VSIs.
 * The best effort filter pool is common to all VSIs and is a device shared
 * resource pool. The number of filters available to this VSI is the sum of
 * the VSIs guaranteed filter pool and the global available best effort
 * filter pool.
 *
 * Returns the number of available flow director filters to this VSI
 */
static int ice_fdir_num_avail_fltr(struct ice_hw *hw, struct ice_vsi *vsi)
{
	u16 vsi_num = ice_get_hw_vsi_num(hw, vsi->idx);
	u16 num_guar;
	u16 num_be;

	/* total guaranteed filters assigned to this VSI */
	num_guar = vsi->num_gfltr;

	/* minus the guaranteed filters programed by this VSI */
	num_guar -= (rd32(hw, VSIQF_FD_CNT(vsi_num)) &
		     VSIQF_FD_CNT_FD_GCNT_M) >> VSIQF_FD_CNT_FD_GCNT_S;

	/* total global best effort filters */
	num_be = hw->func_caps.fd_fltr_best_effort;

	/* minus the global best effort filters programmed */
	num_be -= (rd32(hw, GLQF_FD_CNT) & GLQF_FD_CNT_FD_BCNT_M) >>
		   GLQF_FD_CNT_FD_BCNT_S;

	return num_guar + num_be;
}

/**
 * ice_fdir_alloc_flow_prof - allocate FDir flow profile structure(s)
 * @hw: HW structure containing the FDir flow profile structure(s)
 * @flow: flow type to allocate the flow profile for
 *
 * Allocate the fdir_prof and fdir_prof[flow] if not already created. Return 0
 * on success and negative on error.
 */
static int
ice_fdir_alloc_flow_prof(struct ice_hw *hw, enum ice_fltr_ptype flow)
{
	if (!hw)
		return -EINVAL;

	if (!hw->fdir_prof) {
		hw->fdir_prof = devm_kcalloc(ice_hw_to_dev(hw),
					     ICE_FLTR_PTYPE_MAX,
					     sizeof(*hw->fdir_prof),
					     GFP_KERNEL);
		if (!hw->fdir_prof)
			return -ENOMEM;
	}

	if (!hw->fdir_prof[flow]) {
		hw->fdir_prof[flow] = devm_kzalloc(ice_hw_to_dev(hw),
						   sizeof(**hw->fdir_prof),
						   GFP_KERNEL);
		if (!hw->fdir_prof[flow])
			return -ENOMEM;
	}

	return 0;
}

/**
 * ice_fdir_set_hw_fltr_rule - Configure HW tables to generate a FDir rule
 * @pf: pointer to the PF structure
 * @seg: protocol header description pointer
 * @flow: filter enum
 * @tun: index into fdir_seg array
 */
static int
ice_fdir_set_hw_fltr_rule(struct ice_pf *pf, struct ice_flow_seg_info *seg,
			  enum ice_fltr_ptype flow, int tun)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *main_vsi, *ctrl_vsi;
	enum ice_flow_dir dir = ICE_FLOW_RX;
	struct ice_flow_seg_info *old_seg;
	struct ice_flow_prof *prof = NULL;
	enum ice_block blk = ICE_BLK_FD;
	struct ice_fd_hw_prof *hw_prof;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u64 entry1_h = 0;
	u64 entry2_h = 0;
	u64 prof_id;
	int err;

	main_vsi = ice_get_main_vsi(pf);
	if (!main_vsi)
		return -EINVAL;

	ctrl_vsi = ice_get_ctrl_vsi(pf);
	if (!ctrl_vsi)
		return -EINVAL;

	err = ice_fdir_alloc_flow_prof(hw, flow);
	if (err)
		return err;

	hw_prof = hw->fdir_prof[flow];
	old_seg = hw_prof->fdir_seg[tun];
	if (old_seg) {
		/* This flow_type already has a changed input set.
		 * If it matches the requested input set then we are
		 * done. Or, if it's different then it's an error.
		 */
		if (!memcmp(old_seg, seg, sizeof(*seg)))
			return -EAGAIN;
		return -EINVAL;
	}

	/* Adding a profile, but there is only one header supported.
	 * That is the final parameters are 1 header (segment), no
	 * actions (NULL) and zero actions 0.
	 */
	prof_id = flow + tun * ICE_FLTR_PTYPE_MAX;
	status = ice_flow_add_prof(hw, blk, dir, prof_id, seg, TNL_SEG_CNT(tun),
				   NULL, 0, &prof);
	err = ice_status_to_errno(status);
	if (err)
		return err;
	status = ice_flow_add_entry(hw, blk, prof_id, main_vsi->idx,
				    main_vsi->idx, ICE_FLOW_PRIO_NORMAL,
				    seg, NULL, 0, &entry1_h);
	err = ice_status_to_errno(status);
	if (err) {
		dev_err(dev, "Could not add VSI creating perfect flow %d\n",
			flow);
		goto err_prof;
	}
	status = ice_flow_add_entry(hw, blk, prof_id, main_vsi->idx,
				    ctrl_vsi->idx, ICE_FLOW_PRIO_NORMAL,
				    seg, NULL, 0, &entry2_h);
	err = ice_status_to_errno(status);
	if (err) {
		dev_err(dev, "Could not add Control VSI creating perfect flow %d\n",
			flow);
		goto err_entry;
	}

	hw_prof->fdir_seg[tun] = seg;
	hw_prof->entry_h[0][tun] = entry1_h;
	hw_prof->vsi_h[0] = main_vsi->idx;
	hw_prof->entry_h[1][tun] = entry2_h;
	hw_prof->vsi_h[1] = ctrl_vsi->idx;
	hw_prof->cnt = 2;

	return 0;

err_entry:
	ice_rem_prof_id_flow(hw, ICE_BLK_FD,
			     ice_get_hw_vsi_num(hw, main_vsi->idx), prof_id);
	ice_flow_rem_entry(hw, entry1_h);
err_prof:
	ice_flow_rem_prof(hw, ICE_BLK_FD, prof_id);
	return err;
}

/**
 * ice_create_fdir_rule - Create a FDir filter HW table entry.
 * @pf: ICE PF structure
 * @flow: ICE filter enum
 *
 * Return error value or 0 on success.
 */
int ice_create_fdir_rule(struct ice_pf *pf, enum ice_fltr_ptype flow)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_flow_seg_info *seg, *tun_seg;
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi *vsi;
	int ret;

	/* if there is already a filter rule for kind return -EINVAL */
	if (hw->fdir_prof && hw->fdir_prof[flow] &&
	    hw->fdir_prof[flow]->fdir_seg[0])
		return -EINVAL;

	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return -ENOMEM;

	tun_seg = devm_kzalloc(dev, sizeof(*seg) * ICE_FD_HW_SEG_MAX,
			       GFP_KERNEL);
	if (!tun_seg) {
		devm_kfree(dev, seg);
		return -ENOMEM;
	}

	if (flow == ICE_FLTR_PTYPE_NONF_IPV4_TCP) {
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_TCP |
				  ICE_FLOW_SEG_HDR_IPV4);

		/* IP source address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* IP destination address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 source port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

	} else if (flow == ICE_FLTR_PTYPE_NONF_IPV4_UDP) {
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_UDP |
				  ICE_FLOW_SEG_HDR_IPV4);

		/* IP source address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* IP destination address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 source port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

	} else if (flow == ICE_FLTR_PTYPE_NONF_IPV6_TCP) {
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_TCP |
				  ICE_FLOW_SEG_HDR_IPV6);

		/* IP source address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_SA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* IP destination address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_DA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 source port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

	} else if (flow == ICE_FLTR_PTYPE_NONF_IPV6_UDP) {
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_UDP |
				  ICE_FLOW_SEG_HDR_IPV6);

		/* IP source address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_SA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* IP destination address */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_DA,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 source port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL,
				 ICE_FLOW_FLD_OFF_INVAL, false);

	} else {
		return -EOPNOTSUPP;
	}

	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		/* something bad has happened, free memory */
		devm_kfree(dev, seg);
		return -EOPNOTSUPP;
	}

	/* add filter for outer headers */
	ret = ice_fdir_set_hw_fltr_rule(pf, seg, flow, 0);
	if (ret == -EAGAIN) {
		/* seg already exists, free memory */
		devm_kfree(dev, seg);
		return 0;
	}

	/* make tunneled filter HW entries if possible */
	memcpy(&tun_seg[1], seg, sizeof(*seg));
	ret = ice_fdir_set_hw_fltr_rule(pf, tun_seg, flow, 1);
	if (ret == -EAGAIN) {
		/* tun_seg already exists, free memory */
		devm_kfree(dev, tun_seg);
		return 0;
	}

	set_bit(flow, hw->fdir_perfect_fltr);
	return ret;
}

/**
 * ice_check_fdir_input_set - Check that a given Flow Director filter is valid
 * @pf: ice PF structure
 * @vsi: pointer to target VSI
 * @fsp: pointer to ethtool Rx flow specification
 * @user: user defined data from flow specification
 *
 * Returns 0 on success.
 */
static int
ice_check_fdir_input_set(struct ice_pf *pf, struct ice_vsi *vsi,
			 struct ethtool_rx_flow_spec *fsp,
			 struct ice_rx_flow_userdef *user)
{
	struct ethtool_tcpip4_spec *tcp_ip4_spec;
	struct ethtool_usrip4_spec *usr_ip4_spec;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	struct ethtool_tcpip6_spec *tcp_ip6_spec;
	struct ethtool_usrip6_spec *usr_ip6_spec;
#endif
	struct ice_flow_seg_info *seg, *tun_seg;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_fd_hw_prof *hw_prof = NULL;
	enum ice_fltr_ptype fltr_idx;
	struct ice_hw *hw = &pf->hw;
	bool perfect_filter = true;
	struct ice_vsi *ctrl_vsi;
	enum ice_status status;
	u64 entry1_h = 0;
	u64 prof_id;
	int tun;
#ifdef NETIF_F_HW_TC
	int j;
#endif /* NETIF_F_HW_TC */

	ctrl_vsi = ice_get_ctrl_vsi(pf);
	if (!ctrl_vsi)
		return -EINVAL;

	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return -ENOMEM;

	tun_seg = devm_kzalloc(dev, sizeof(*seg) * ICE_FD_HW_SEG_MAX,
			       GFP_KERNEL);
	if (!tun_seg)
		return -ENOMEM;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		/* make sure we don't have any empty rule */
		if (!tcp_ip4_spec->psrc && !tcp_ip4_spec->ip4src &&
		    !tcp_ip4_spec->pdst && !tcp_ip4_spec->ip4dst)
			goto err_exit;

		/* filtering on TOS not supported */
		if (tcp_ip4_spec->tos)
			goto err_exit;

		/* IP source address */
		if (tcp_ip4_spec->ip4src == htonl(0xFFFFFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->ip4src)
			perfect_filter = false;
		else
			goto err_exit;

		/* IP destination address */
		if (tcp_ip4_spec->ip4dst == htonl(0xFFFFFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->ip4dst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case IPV4_USER_FLOW:
		usr_ip4_spec = &fsp->m_u.usr_ip4_spec;

		/* first 4 bytes of Layer 4 header */
		if (usr_ip4_spec->l4_4_bytes)
			goto err_exit;
		if (usr_ip4_spec->tos)
			goto err_exit;
		if (usr_ip4_spec->ip_ver)
			goto err_exit;
		/* Filtering on Layer 4 protocol not supported */
		if (usr_ip4_spec->proto)
			goto err_exit;
		/* empty rules are not valid */
		if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst)
			goto err_exit;

		/* IP source address */
		if (usr_ip4_spec->ip4src == htonl(0xFFFFFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!usr_ip4_spec->ip4src)
			perfect_filter = false;
		else
			goto err_exit;

		/* IP destination address */
		if (usr_ip4_spec->ip4dst == htonl(0xFFFFFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!usr_ip4_spec->ip4dst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		tcp_ip6_spec = &fsp->m_u.tcp_ip6_spec;

		/* make sure we don't have any empty rule */
		if (!memcmp(tcp_ip6_spec->ip6src, zero_ipv6_addr_mask,
			    sizeof(zero_ipv6_addr_mask)) &&
		    !memcmp(tcp_ip6_spec->ip6dst, zero_ipv6_addr_mask,
			    sizeof(zero_ipv6_addr_mask)) &&
		    !tcp_ip6_spec->psrc && !tcp_ip6_spec->pdst)
			goto err_exit;

		/* filtering on TC not supported */
		if (tcp_ip6_spec->tclass)
			goto err_exit;

		if (!memcmp(tcp_ip6_spec->ip6src, full_ipv6_addr_mask,
			    sizeof(full_ipv6_addr_mask)))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_SA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!memcmp(tcp_ip6_spec->ip6src, zero_ipv6_addr_mask,
				 sizeof(zero_ipv6_addr_mask)))
			perfect_filter = false;
		else
			goto err_exit;

		if (!memcmp(tcp_ip6_spec->ip6dst, full_ipv6_addr_mask,
			    sizeof(full_ipv6_addr_mask)))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_DA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!memcmp(tcp_ip6_spec->ip6dst, zero_ipv6_addr_mask,
				 sizeof(zero_ipv6_addr_mask)))
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case IPV6_USER_FLOW:
		usr_ip6_spec = &fsp->m_u.usr_ip6_spec;

		/* filtering on Layer 4 bytes not supported */
		if (usr_ip6_spec->l4_4_bytes)
			goto err_exit;
		/* filtering on TC not supported */
		if (usr_ip6_spec->tclass)
			goto err_exit;
		/* filtering on Layer 4 protocol not supported */
		if (usr_ip6_spec->l4_proto)
			goto err_exit;
		/* empty rules are not valid */
		if (!memcmp(usr_ip6_spec->ip6src, zero_ipv6_addr_mask,
			    sizeof(zero_ipv6_addr_mask)) &&
		    !memcmp(usr_ip6_spec->ip6dst, zero_ipv6_addr_mask,
			    sizeof(zero_ipv6_addr_mask)))
			goto err_exit;

		if (!memcmp(usr_ip6_spec->ip6src, full_ipv6_addr_mask,
			    sizeof(full_ipv6_addr_mask)))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_SA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!memcmp(usr_ip6_spec->ip6src, zero_ipv6_addr_mask,
				 sizeof(zero_ipv6_addr_mask)))
			perfect_filter = false;
		else
			goto err_exit;

		if (!memcmp(usr_ip6_spec->ip6dst, full_ipv6_addr_mask,
			    sizeof(full_ipv6_addr_mask)))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV6_DA,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!memcmp(usr_ip6_spec->ip6dst, zero_ipv6_addr_mask,
				 sizeof(zero_ipv6_addr_mask)))
			perfect_filter = false;
		else
			goto err_exit;

		break;
#endif /* HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC */
	default:
		goto err_exit;
	}

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_TCP |
				  ICE_FLOW_SEG_HDR_IPV4);
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		/* Layer 4 source port */
		if (tcp_ip4_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip4_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case UDP_V4_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_UDP |
				  ICE_FLOW_SEG_HDR_IPV4);
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		/* Layer 4 source port */
		if (tcp_ip4_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip4_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case SCTP_V4_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_SCTP |
				  ICE_FLOW_SEG_HDR_IPV4);
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		/* Layer 4 source port */
		if (tcp_ip4_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg,
					 ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip4_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg,
					 ICE_FLOW_FIELD_IDX_SCTP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip4_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case IPV4_USER_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4);
		break;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case TCP_V6_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV6 |
				  ICE_FLOW_SEG_HDR_TCP);
		tcp_ip6_spec = &fsp->m_u.tcp_ip6_spec;

		/* Layer 4 source port */
		if (tcp_ip6_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip6_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case UDP_V6_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV6 |
				  ICE_FLOW_SEG_HDR_UDP);
		tcp_ip6_spec = &fsp->m_u.tcp_ip6_spec;

		/* Layer 4 source port */
		if (tcp_ip6_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip6_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case SCTP_V6_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV6 |
				  ICE_FLOW_SEG_HDR_SCTP);
		tcp_ip6_spec = &fsp->m_u.tcp_ip6_spec;

		/* Layer 4 source port */
		if (tcp_ip6_spec->psrc == htons(0xFFFF))
			ice_flow_set_fld(seg,
					 ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->psrc)
			perfect_filter = false;
		else
			goto err_exit;

		/* Layer 4 destination port */
		if (tcp_ip6_spec->pdst == htons(0xFFFF))
			ice_flow_set_fld(seg,
					 ICE_FLOW_FIELD_IDX_SCTP_DST_PORT,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		else if (!tcp_ip6_spec->pdst)
			perfect_filter = false;
		else
			goto err_exit;

		break;
	case IPV6_USER_FLOW:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV6);
		break;
#endif /* HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC */
	default:
		goto err_exit;
	}

	/* tunnel segments are shifted up one. */
	memcpy(&tun_seg[1], seg, sizeof(*seg));

	if (user && user->flex_fltr) {
		perfect_filter = false;
		ice_flow_add_fld_raw(seg, user->flex_offset,
				     ICE_FLTR_PRGM_FLEX_WORD_SIZE,
				     ICE_FLOW_FLD_OFF_INVAL,
				     ICE_FLOW_FLD_OFF_INVAL);
		ice_flow_add_fld_raw(&tun_seg[1], user->flex_offset,
				     ICE_FLTR_PRGM_FLEX_WORD_SIZE,
				     ICE_FLOW_FLD_OFF_INVAL,
				     ICE_FLOW_FLD_OFF_INVAL);
	}
	if (ice_is_safe_mode(pf)) {
		goto err_exit;
	} else {
		enum ice_flow_dir dir = ICE_FLOW_RX;
		struct ice_flow_seg_info *old_seg;
		struct ice_flow_prof *prof = NULL;
		enum ice_block blk = ICE_BLK_FD;
		u64 entry2_h = 0;
		int err;
#ifdef NETIF_F_HW_TC
		int idx;
#endif /* NETIF_F_HW_TC */

		fltr_idx = ice_ethtool_flow_to_fltr(fsp->flow_type & ~FLOW_EXT);
		err = ice_fdir_alloc_flow_prof(hw, fltr_idx);
		if (err)
			goto err_exit;

		hw_prof = hw->fdir_prof[fltr_idx];
		old_seg = hw_prof->fdir_seg[0];
		if (old_seg) {
			/* This flow_type already has a changed input set.
			 * If it matches the requested input set then we are
			 * done. Or, if it's different then it's an error.
			 */
			if (!memcmp(old_seg, seg, sizeof(*seg))) {
				devm_kfree(dev, seg);
				devm_kfree(dev, tun_seg);
				return 0;
			}
			/* if there are FDir filters using this flow,
			 * then return error.
			 */
			if (hw->fdir_fltr_cnt[fltr_idx])
				goto err_exit;

			if (ice_is_arfs_using_perfect_flow(hw, fltr_idx)) {
				dev_err(dev, "aRFS using perfect flow type %d, cannot change input set\n",
					fltr_idx);
				goto err_exit;
			}

			/* remove HW filter definition */
			ice_fdir_rem_flow(hw, fltr_idx);
		}
		/* Adding a profile, but there is only one header supported.
		 * That is the final parameters are 1 header (segment), no
		 * actions (NULL) and zero actions 0.
		 */
		for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
			struct ice_flow_seg_info *cur_seg;

			if (tun == 0)
				cur_seg = seg;
			else
				cur_seg = tun_seg;

			prof_id = fltr_idx + tun * ICE_FLTR_PTYPE_MAX;
			status = ice_flow_add_prof(hw, blk, dir, prof_id,
						   cur_seg, TNL_SEG_CNT(tun),
						   NULL, 0, &prof);
			err = ice_status_to_errno(status);
			if (err)
				goto err_exit;
			status = ice_flow_add_entry(hw, blk, prof_id, vsi->idx,
						    vsi->idx,
						    ICE_FLOW_PRIO_NORMAL,
						    cur_seg, NULL, 0,
						    &entry1_h);
			err = ice_status_to_errno(status);
			if (err)
				goto err_prof;
			status = ice_flow_add_entry(hw, blk, prof_id, vsi->idx,
						    ctrl_vsi->idx,
						    ICE_FLOW_PRIO_NORMAL,
						    cur_seg, NULL, 0,
						    &entry2_h);
			err = ice_status_to_errno(status);
			if (err)
				goto err_entry_1;
			hw_prof->fdir_seg[tun] = cur_seg;
			hw_prof->entry_h[hw_prof->cnt][tun] = entry1_h;
			hw_prof->entry_h[hw_prof->cnt + 1][tun] = entry2_h;
		}
		hw_prof->vsi_h[hw_prof->cnt++] = vsi->idx;
		hw_prof->vsi_h[hw_prof->cnt++] = ctrl_vsi->idx;
		if (perfect_filter)
			set_bit(fltr_idx, hw->fdir_perfect_fltr);
		else
			clear_bit(fltr_idx, hw->fdir_perfect_fltr);

#ifdef NETIF_F_HW_TC
		for (idx = 1; idx < ICE_CHNL_MAX_TC; idx++) {
			if (!ice_is_adq_active(pf) || !vsi->tc_map_vsi[idx])
				continue;
			for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
				struct ice_flow_seg_info *cur_seg;
				enum ice_flow_priority prio;
				u16 vsi_h;

				if (tun == 0)
					cur_seg = seg;
				else
					cur_seg = tun_seg;

				prio = ICE_FLOW_PRIO_NORMAL;
				prof_id = fltr_idx + tun * ICE_FLTR_PTYPE_MAX;
				entry1_h = 0;
				vsi_h = vsi->tc_map_vsi[idx]->idx;
				status = ice_flow_add_entry(hw, blk, prof_id,
							    vsi->idx, vsi_h,
							    prio, cur_seg, NULL,
							    0, &entry1_h);
				err = ice_status_to_errno(status);
				if (err) {
					dev_err(dev, "Could not add Channel VSI %d to flow group\n",
						idx);
					goto err_unroll;
				}
				hw_prof->entry_h[hw_prof->cnt][tun] = entry1_h;
			}
			hw_prof->vsi_h[hw_prof->cnt] =
				vsi->tc_map_vsi[idx]->idx;
			hw_prof->cnt++;
		}
#endif /* NETIF_F_HW_TC */
	}
	return 0;

#ifdef NETIF_F_HW_TC
err_unroll:
	entry1_h = 0;
	for (j = 0; j < hw_prof->cnt; j++) {
		for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
			u16 vsi_num = ice_get_hw_vsi_num(hw, hw_prof->vsi_h[j]);

			prof_id = fltr_idx + tun * ICE_FLTR_PTYPE_MAX;
			if (!hw_prof->entry_h[j][tun])
				continue;
			ice_rem_prof_id_flow(hw, ICE_BLK_FD, vsi_num, prof_id);
			ice_flow_rem_entry(hw, hw_prof->entry_h[j][tun]);
			hw_prof->entry_h[j][tun] = 0;
		}
		hw_prof->vsi_h[j] = 0;
	}
	hw_prof->cnt = 0;
	for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++)
		hw_prof->fdir_seg[tun] = NULL;
#endif /* NETIF_F_HW_TC */
err_entry_1:
	if (entry1_h) {
		u16 vsi_num = ice_get_hw_vsi_num(hw, vsi->idx);

		ice_rem_prof_id_flow(hw, ICE_BLK_FD, vsi_num, prof_id);
		ice_flow_rem_entry(hw, entry1_h);
	}
err_prof:
	ice_flow_rem_prof(hw, ICE_BLK_FD, prof_id);
err_exit:
#ifdef NETIF_F_HW_TC
	if (ice_is_adq_active(pf))
		dev_err(ice_pf_to_dev(vsi->back), "Failed to add filter.  Flow director filters must have the same input set as ADQ filters.\n");
	else
		dev_err(ice_pf_to_dev(vsi->back), "Failed to add filter.  Flow director filters on each port must have the same input set.\n");
#else /* !NETIF_F_HW_TC */
	dev_err(ice_pf_to_dev(vsi->back), "Failed to add filter.  Flow director filters on each port must have the same input set.\n");
#endif /* !NETIF_F_HW_TC */
	devm_kfree(dev, seg);
	devm_kfree(dev, tun_seg);
	return -EOPNOTSUPP;
}

/**
 * ice_update_per_q_fltr
 * @vsi: ptr to VSI
 * @q_index: queue index
 * @inc: true to increment or false to decrement per queue filter count
 *
 * This function is used to keep track of per queue sideband filters
 */
static void ice_update_per_q_fltr(struct ice_vsi *vsi, u32 q_index, bool inc)
{
	struct ice_ring *rx_ring;

	if (!vsi->num_rxq || q_index >= vsi->num_rxq)
		return;

	rx_ring = vsi->rx_rings[q_index];
	if (!rx_ring || !rx_ring->ch)
		return;

	if (inc)
		atomic_inc(&rx_ring->ch->num_sb_fltr);
	else
		atomic_dec_if_positive(&rx_ring->ch->num_sb_fltr);
}

/**
 * ice_fdir_write_fltr - send a flow director filter to the hardware
 * @pf: PF data structure
 * @input: filter structure
 * @add: true adds filter and false removed filter
 * @is_tun: true adds inner filter on tunnel and false outer headers
 *
 * returns 0 on success and negative value on error
 */
int
ice_fdir_write_fltr(struct ice_pf *pf, struct ice_fdir_fltr *input, bool add,
		    bool is_tun)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_fltr_desc desc;
	struct ice_vsi *ctrl_vsi;
	enum ice_status status;
	u8 *pkt, *frag_pkt;
	bool has_frag;
	int err;

	ctrl_vsi = ice_get_ctrl_vsi(pf);
	if (!ctrl_vsi)
		return -EINVAL;

	pkt = devm_kzalloc(dev, ICE_FDIR_MAX_RAW_PKT_SIZE, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;
	frag_pkt = devm_kzalloc(dev, ICE_FDIR_MAX_RAW_PKT_SIZE, GFP_KERNEL);
	if (!frag_pkt) {
		err = -ENOMEM;
		goto err_free;
	}

	ice_fdir_get_prgm_desc(hw, input, &desc, add);
	status = ice_fdir_get_gen_prgm_pkt(hw, input, pkt, false, is_tun);
	if (status) {
		err = ice_status_to_errno(status);
		goto err_free_all;
	}
	err = ice_prgm_fdir_fltr(ctrl_vsi, &desc, pkt);
	if (err)
		goto err_free_all;

	/* repeat for fragment packet */
	has_frag = ice_fdir_has_frag(input->flow_type);
	if (has_frag) {
		/* does not return error */
		ice_fdir_get_prgm_desc(hw, input, &desc, add);
		status = ice_fdir_get_gen_prgm_pkt(hw, input, frag_pkt, true,
						   is_tun);
		if (status) {
			err = ice_status_to_errno(status);
			goto err_frag;
		}
		err = ice_prgm_fdir_fltr(ctrl_vsi, &desc, frag_pkt);
		if (err)
			goto err_frag;
	} else {
		devm_kfree(dev, frag_pkt);
	}

	return 0;

err_free_all:
	devm_kfree(dev, frag_pkt);
err_free:
	devm_kfree(dev, pkt);
	return err;

err_frag:
	devm_kfree(dev, frag_pkt);
	return err;
}

/**
 * ice_fdir_write_all_fltr - send a flow director filter to the hardware
 * @pf: PF data structure
 * @input: filter structure
 * @add: true adds filter and false removed filter
 *
 * returns 0 on success and negative value on error
 */
static int
ice_fdir_write_all_fltr(struct ice_pf *pf, struct ice_fdir_fltr *input,
			bool add)
{
	u16 port_num;
	int tun;
	int err;

	for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
		if (tun == ICE_FD_HW_SEG_TUN &&
		    !ice_get_open_tunnel_port(&pf->hw, TNL_ALL, &port_num))
			continue;
		err = ice_fdir_write_fltr(pf, input, add,
					  (tun == ICE_FD_HW_SEG_TUN));
		if (err)
			return err;
	}
	return 0;
}

/**
 * ice_fdir_replay_fltrs - replay filters from the HW filter list
 * @pf: board private structure
 */
void ice_fdir_replay_fltrs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_fdir_fltr *f_rule;
	struct ice_hw *hw = &pf->hw;

	list_for_each_entry(f_rule, &hw->fdir_list_head, fltr_node) {
		int err = ice_fdir_write_all_fltr(pf, f_rule, true);

		if (err)
			dev_dbg(dev, "Flow Director error %d, could not reprogram filter %d\n",
				err, f_rule->fltr_id);
	}
}

/**
 * ice_vsi_manage_fdir - turn on/off flow director
 * @vsi: the VSI being changed
 * @ena: boolean value indicating if this is an enable or disable request
 */
void ice_vsi_manage_fdir(struct ice_vsi *vsi, bool ena)
{
	struct ice_fdir_fltr *f_rule, *tmp;
	struct ice_pf *pf;
	struct ice_hw *hw;

	pf = vsi->back;
	hw = &pf->hw;
	if (ena) {
		set_bit(ICE_FLAG_FD_ENA, pf->flags);
		return;
	}

	mutex_lock(&hw->fdir_fltr_lock);
	if (!test_and_clear_bit(ICE_FLAG_FD_ENA, pf->flags))
		goto release_lock;
	list_for_each_entry_safe(f_rule, tmp, &hw->fdir_list_head, fltr_node) {
		/* ignore return value */
		ice_fdir_write_all_fltr(pf, f_rule, false);
		ice_fdir_update_cntrs(hw, f_rule->flow_type, false);
		list_del(&f_rule->fltr_node);
		devm_kfree(ice_hw_to_dev(hw), f_rule);
	}

	if (hw->fdir_prof) {
		enum ice_fltr_ptype flow;

		for (flow = ICE_FLTR_PTYPE_NONF_NONE; flow < ICE_FLTR_PTYPE_MAX;
		     flow++)
			if (hw->fdir_prof[flow])
				ice_fdir_rem_flow(hw, flow);
	}

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
}

/**
 * ice_fdir_update_list_entry - delete or delete a filter from the filter list
 * @pf: PF structure
 * @input: filter structure
 * @fltr_idx: ethtool index of filter to modify
 *
 * returns 0 on success and negative on errors
 */
static int
ice_fdir_update_list_entry(struct ice_pf *pf, struct ice_fdir_fltr *input,
			   int fltr_idx)
{
	struct ice_fdir_fltr *old_fltr;
	struct ice_vsi *vsi;
	int err = -ENOENT;
	struct ice_hw *hw;

	/* Do not update filters during reset */
	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EINVAL;

	hw = &pf->hw;
	old_fltr = ice_fdir_find_fltr_by_idx(hw, fltr_idx);
	if (old_fltr) {
		err = ice_fdir_write_all_fltr(pf, old_fltr, false);
		if (err)
			return err;
		ice_fdir_update_cntrs(hw, old_fltr->flow_type, false);
		/* update sb-filters count, specific to ring->channel */
		ice_update_per_q_fltr(vsi, old_fltr->orig_q_index, false);
		if (!input && !hw->fdir_fltr_cnt[old_fltr->flow_type])
			/* we just deleted the last filter of flow_type so we
			 * should also delete the HW filter info.
			 */
			ice_fdir_rem_flow(hw, old_fltr->flow_type);
		list_del(&old_fltr->fltr_node);
		devm_kfree(ice_hw_to_dev(hw), old_fltr);
	}
	if (!input)
		return err;
	ice_fdir_list_add_fltr(hw, input);
	/* update sb-filters count, specific to ring->channel */
	ice_update_per_q_fltr(vsi, input->orig_q_index, true);
	ice_fdir_update_cntrs(hw, input->flow_type, true);
	return 0;
}

/**
 * ice_del_fdir_ethtool - delete Flow Director filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete Flow Director filter
 *
 * Returns 0 on success and negative values for failure
 */
int ice_del_fdir_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	int val;

	if (!test_bit(ICE_FLAG_FD_ENA, pf->flags))
		return -EOPNOTSUPP;

	/* Do not delete filters during reset */
	if (ice_is_reset_in_progress(pf->state)) {
		dev_err(ice_pf_to_dev(vsi->back), "Device is resetting - deleting Flow Director filters not supported during reset\n");
		return -EBUSY;
	}

	if (test_bit(__ICE_FD_FLUSH_REQ, pf->state))
		return -EBUSY;

	mutex_lock(&hw->fdir_fltr_lock);
	val = ice_fdir_update_list_entry(pf, NULL, fsp->location);
	mutex_unlock(&hw->fdir_fltr_lock);

	return val;
}

/**
 * ice_update_ring_dest_vsi - update dest ring and dest VSI
 * @vsi: pointer to target VSI
 * @dest_vsi: ptr to dest VSI index
 * @ring: ptr to dest ring
 *
 * This function updates destination VSI and queue if user specifies
 * target queue which falls in channel's (aka ADQ) queue region
 */
static void
ice_update_ring_dest_vsi(struct ice_vsi *vsi, u16 *dest_vsi, u32 *ring)
{
	struct ice_channel *ch;

	if (!ring || !dest_vsi)
		return;

	list_for_each_entry(ch, &vsi->ch_list, list) {
		if (!ch->ch_vsi)
			continue;

		/* make sure to locate corresponding channel based on "queue"
		 * specified
		 */
		if ((*ring < ch->base_q) ||
		    (*ring > (ch->base_q + ch->num_rxq)))
			continue;

		/* update the dest_vsi based on channel */
		*dest_vsi = ch->ch_vsi->idx;

		/* update the "ring" to be correct based on channel */
		*ring -= ch->base_q;
	}
}

/**
 * ice_add_fdir_ethtool - Add/Remove Flow Director filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete Flow Director filter
 *
 * Returns 0 on success and negative values for failure
 */
int ice_add_fdir_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct ice_rx_flow_userdef userdata;
	struct ethtool_rx_flow_spec *fsp;
	struct ice_fdir_fltr *input;
	u16 dest_vsi, q_index = 0;
	u16 orig_q_index = 0;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int fltrs_needed;
	u16 tunnel_port;
	int flow_type;
	u8 dest_ctl;
	bool found;
	int ret;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	int idx;
#endif /* HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC */

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;
	hw = &pf->hw;

	if (!test_bit(ICE_FLAG_FD_ENA, pf->flags))
		return -EOPNOTSUPP;


	/* Do not program filters during reset */
	if (ice_is_reset_in_progress(pf->state)) {
		dev_err(ice_pf_to_dev(vsi->back), "Device is resetting - adding Flow Director filters not supported during reset\n");
		return -EBUSY;
	}

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (ice_parse_rx_flow_user_data(fsp, &userdata))
		return -EINVAL;

	if (fsp->flow_type & FLOW_MAC_EXT)
		return -EINVAL;

	ret = ice_check_fdir_input_set(pf, vsi, fsp, &userdata);
	if (ret)
		return ret;

	if (fsp->location >= (pf->hw.func_caps.fd_fltr_best_effort +
			      pf->hw.func_caps.fd_fltr_guar)) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to add filter.  The maximum number of flow director filters has been reached.\n");
		return -EINVAL;
	}

	dest_vsi = vsi->idx;
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		dest_ctl = ICE_FLTR_PRGM_DESC_DEST_DROP_PKT;
	} else {
		u32 ring = ethtool_get_flow_spec_ring(fsp->ring_cookie);
		u8 vf = ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);

		if (!vf) {
			if (ring >= vsi->num_rxq)
				return -EINVAL;
			orig_q_index = ring;
			ice_update_ring_dest_vsi(vsi, &dest_vsi, &ring);
		} else {
			dev_err(ice_pf_to_dev(pf), "Failed to add filter. Flow director filters are not supported on VF queues.\n");
			return -EINVAL;
		}
		dest_ctl = ICE_FLTR_PRGM_DESC_DEST_DIRECT_PKT_QINDEX;
		q_index = ring;
	}

	/* return error if not an update and no available filters */
	fltrs_needed = (ice_get_open_tunnel_port(hw, TNL_ALL, &tunnel_port)) ?
		2 : 1;
	if (!ice_fdir_find_fltr_by_idx(hw, fsp->location) &&
	    ice_fdir_num_avail_fltr(hw, pf->vsi[dest_vsi]) < fltrs_needed) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to add filter.  The maximum number of flow director filters has been reached.\n");
		return -ENOSPC;
	}

	input = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	input->fltr_id = fsp->location;
	input->q_index = q_index;
	/* Record the original queue as specified by user, because
	 * due to channel, configuration 'q_index' gets adjusted
	 * accordingly, but to keep user experience same - queue of
	 * flow-director filter shall report original queue number
	 * as specified by user, hence record it and use it later
	 */
	input->orig_q_index = orig_q_index;
	input->dest_vsi = dest_vsi;
	input->dest_ctl = dest_ctl;
	input->fltr_status = ICE_FLTR_PRGM_DESC_FD_STATUS_FD_ID;
	input->cnt_index = ICE_FD_SB_STAT_IDX(hw->fd_ctr_base);
	flow_type = fsp->flow_type & ~FLOW_EXT;
	input->flow_type = ice_ethtool_flow_to_fltr(flow_type);

	if (fsp->flow_type & FLOW_EXT) {
		memcpy(input->ext_data.usr_def, fsp->h_ext.data,
		       sizeof(input->ext_data.usr_def));
		input->ext_data.vlan_type = fsp->h_ext.vlan_etype;
		input->ext_data.vlan_tag = fsp->h_ext.vlan_tci;
		memcpy(input->ext_mask.usr_def, fsp->m_ext.data,
		       sizeof(input->ext_mask.usr_def));
		input->ext_mask.vlan_type = fsp->m_ext.vlan_etype;
		input->ext_mask.vlan_tag = fsp->m_ext.vlan_tci;
	}

	switch (flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		/* Reverse the src and dest notion, since the HW expects
		 * them to be from Tx perspective where as the input from
		 * user is from Rx filter view.
		 */
		input->ip.v4.dst_port = fsp->h_u.tcp_ip4_spec.psrc;
		input->ip.v4.src_port = fsp->h_u.tcp_ip4_spec.pdst;
		input->ip.v4.dst_ip = fsp->h_u.tcp_ip4_spec.ip4src;
		input->ip.v4.src_ip = fsp->h_u.tcp_ip4_spec.ip4dst;
		input->mask.v4.dst_port = fsp->m_u.tcp_ip4_spec.psrc;
		input->mask.v4.src_port = fsp->m_u.tcp_ip4_spec.pdst;
		input->mask.v4.dst_ip = fsp->m_u.tcp_ip4_spec.ip4src;
		input->mask.v4.src_ip = fsp->m_u.tcp_ip4_spec.ip4dst;
		break;
	case IPV4_USER_FLOW:
		input->ip.v4.dst_ip = fsp->h_u.usr_ip4_spec.ip4src;
		input->ip.v4.src_ip = fsp->h_u.usr_ip4_spec.ip4dst;
		input->ip.v4.l4_header = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		input->ip.v4.proto = fsp->h_u.usr_ip4_spec.proto;
		input->ip.v4.ip_ver = fsp->h_u.usr_ip4_spec.ip_ver;
		input->ip.v4.tos = fsp->h_u.usr_ip4_spec.tos;
		input->mask.v4.dst_ip = fsp->m_u.usr_ip4_spec.ip4src;
		input->mask.v4.src_ip = fsp->m_u.usr_ip4_spec.ip4dst;
		input->mask.v4.l4_header = fsp->m_u.usr_ip4_spec.l4_4_bytes;
		input->mask.v4.proto = fsp->m_u.usr_ip4_spec.proto;
		input->mask.v4.ip_ver = fsp->m_u.usr_ip4_spec.ip_ver;
		input->mask.v4.tos = fsp->m_u.usr_ip4_spec.tos;
		break;
#ifdef HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		/* Reverse the src and dest notion, since the HW expects
		 * them to be from Tx perspective where as the input from
		 * user is from Rx filter view.
		 */
		for (idx = 0; idx < 4; idx++)
			input->ip.v6.dst_ip[idx] =
				fsp->h_u.tcp_ip6_spec.ip6src[idx];
		for (idx = 0; idx < 4; idx++)
			input->ip.v6.src_ip[idx] =
				fsp->h_u.tcp_ip6_spec.ip6dst[idx];
		input->ip.v6.dst_port = fsp->h_u.tcp_ip6_spec.psrc;
		input->ip.v6.src_port = fsp->h_u.tcp_ip6_spec.pdst;
		input->ip.v6.tc = fsp->h_u.tcp_ip6_spec.tclass;
		memcpy(input->mask.v6.dst_ip, fsp->m_u.tcp_ip6_spec.ip6src,
		       sizeof(input->mask.v6.dst_ip));
		memcpy(input->mask.v6.src_ip, fsp->m_u.tcp_ip6_spec.ip6dst,
		       sizeof(input->mask.v6.src_ip));
		input->mask.v6.dst_port = fsp->m_u.tcp_ip6_spec.psrc;
		input->mask.v6.src_port = fsp->m_u.tcp_ip6_spec.pdst;
		input->mask.v6.tc = fsp->m_u.tcp_ip6_spec.tclass;
		break;
	case IPV6_USER_FLOW:
		memcpy(input->ip.v6.dst_ip, fsp->h_u.usr_ip6_spec.ip6src,
		       sizeof(input->ip.v6.dst_ip));
		memcpy(input->ip.v6.src_ip, fsp->h_u.usr_ip6_spec.ip6dst,
		       sizeof(input->ip.v6.src_ip));
		input->ip.v6.l4_header = fsp->h_u.usr_ip6_spec.l4_4_bytes;
		input->ip.v6.tc = fsp->h_u.usr_ip6_spec.tclass;
		input->ip.v6.proto = fsp->h_u.usr_ip6_spec.l4_proto;
		memcpy(input->mask.v6.dst_ip, fsp->m_u.usr_ip6_spec.ip6src,
		       sizeof(input->mask.v6.dst_ip));
		memcpy(input->mask.v6.src_ip, fsp->m_u.usr_ip6_spec.ip6dst,
		       sizeof(input->mask.v6.src_ip));
		input->mask.v6.l4_header = fsp->m_u.usr_ip6_spec.l4_4_bytes;
		input->mask.v6.tc = fsp->m_u.usr_ip6_spec.tclass;
		input->mask.v6.proto = fsp->m_u.usr_ip6_spec.l4_proto;
		break;
#endif /* HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC */
	default:
		ret = -EINVAL; /* not doing un-parsed flow types */
		goto free_input;
	}

	mutex_lock(&hw->fdir_fltr_lock);
	found = ice_fdir_is_dup_fltr(hw, input);
	if (found) {
		ret = -EINVAL;
		goto release_lock;
	}

	if (userdata.flex_fltr) {
		input->flex_fltr = true;
		input->flex_word = cpu_to_be16(userdata.flex_word);
		input->flex_offset = userdata.flex_offset;
	}

	/* input struct is added to the HW filter list */
	ice_fdir_update_list_entry(pf, input, fsp->location);

	ret = ice_fdir_write_all_fltr(pf, input, true);
	if (ret)
		goto remove_sw_rule;

	goto release_lock;

remove_sw_rule:
	ice_fdir_update_cntrs(hw, input->flow_type, false);
	/* update sb-filters count, specific to ring->channel */
	ice_update_per_q_fltr(vsi, input->orig_q_index, false);
	list_del(&input->fltr_node);
release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
free_input:
	if (ret)
		devm_kfree(ice_hw_to_dev(hw), input);

	return ret;
}
