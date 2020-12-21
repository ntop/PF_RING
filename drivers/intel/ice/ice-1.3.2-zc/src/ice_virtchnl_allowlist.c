// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice_virtchnl_allowlist.h"

/* Purpose of this file is to share functionality to allowlist or denylist
 * opcodes used in PF <-> VF communication. Group of opcodes:
 * - default -> should be always allowed after creating VF,
 *   default_allowlist_opcodes
 * - opcodes needed by VF to work correctly, but not associated with caps ->
 *   should be allowed after successful VF resources allocation,
 *   working_allowlist_opcodes
 * - opcodes needed by VF when caps are activated
 *
 * Caps that don't use new opcodes (no opcodes should be allowed):
 * - VIRTCHNL_VF_OFFLOAD_RSS_AQ
 * - VIRTCHNL_VF_OFFLOAD_RSS_REG
 * - VIRTCHNL_VF_OFFLOAD_WB_ON_ITR
 * - VIRTCHNL_VF_OFFLOAD_CRC
 * - VIRTCHNL_VF_OFFLOAD_RX_POLLING
 * - VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2
 * - VIRTCHNL_VF_OFFLOAD_ENCAP
 * - VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM
 * - VIRTCHNL_VF_OFFLOAD_RX_ENCAP_CSUM
 * - VIRTCHNL_VF_OFFLOAD_USO
 */

/* default opcodes to communicate with VF */
static const u32 default_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_VF_RESOURCES, VIRTCHNL_OP_VERSION, VIRTCHNL_OP_RESET_VF,
};

/* opcodes supported after successful VIRTCHNL_OP_GET_VF_RESOURCES */
static const u32 working_allowlist_opcodes[] = {
	VIRTCHNL_OP_CONFIG_TX_QUEUE, VIRTCHNL_OP_CONFIG_RX_QUEUE,
	VIRTCHNL_OP_CONFIG_VSI_QUEUES, VIRTCHNL_OP_CONFIG_IRQ_MAP,
	VIRTCHNL_OP_ENABLE_QUEUES, VIRTCHNL_OP_DISABLE_QUEUES,
	VIRTCHNL_OP_GET_STATS, VIRTCHNL_OP_EVENT,
};

/* VIRTCHNL_VF_OFFLOAD_L2 */
static const u32 l2_allowlist_opcodes[] = {
	VIRTCHNL_OP_ADD_ETH_ADDR, VIRTCHNL_OP_DEL_ETH_ADDR,
	VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
};

/* VIRTCHNL_VF_OFFLOAD_IWARP */
static const u32 iwarp_allowlist_opcodes[] = {
	VIRTCHNL_OP_IWARP, VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP,
	VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP,
};

/* VIRTCHNL_VF_OFFLOAD_REQ_QUEUES */
static const u32 req_queues_allowlist_opcodes[] = {
	VIRTCHNL_OP_REQUEST_QUEUES,
};

/* VIRTCHNL_VF_OFFLOAD_VLAN */
static const u32 vlan_allowlist_opcodes[] = {
	VIRTCHNL_OP_ADD_VLAN, VIRTCHNL_OP_DEL_VLAN,
	VIRTCHNL_OP_ENABLE_VLAN_STRIPPING, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING,
};

/* VIRTCHNL_VF_OFFLOAD_RSS_PF */
static const u32 rss_pf_allowlist_opcodes[] = {
	VIRTCHNL_OP_CONFIG_RSS_KEY, VIRTCHNL_OP_CONFIG_RSS_LUT,
	VIRTCHNL_OP_GET_RSS_HENA_CAPS, VIRTCHNL_OP_SET_RSS_HENA,
};

/* VIRTCHNL_VF_OFFLOAD_ADQ */
static const u32 adq_allowlist_opcodes[] = {
	VIRTCHNL_OP_ENABLE_CHANNELS, VIRTCHNL_OP_DISABLE_CHANNELS,
	VIRTCHNL_OP_ADD_CLOUD_FILTER, VIRTCHNL_OP_DEL_CLOUD_FILTER,
};

/* VIRTCHNL_VF_OFFLOAD_ADQ_V2 */
static const u32 adq_v2_allowlist_opcodes[] = {
	VIRTCHNL_OP_ENABLE_CHANNELS, VIRTCHNL_OP_DISABLE_CHANNELS,
	VIRTCHNL_OP_ADD_CLOUD_FILTER, VIRTCHNL_OP_DEL_CLOUD_FILTER,
};

/* VIRTCHNL_VF_CAP_DCF */
static const u32 cap_dcf_allowlist_opcodes[] = {
	VIRTCHNL_OP_DCF_CMD_DESC, VIRTCHNL_OP_DCF_CMD_BUFF,
	VIRTCHNL_OP_DCF_DISABLE, VIRTCHNL_OP_DCF_GET_VSI_MAP,
	VIRTCHNL_OP_DCF_GET_PKG_INFO,
};

/* VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC */
static const u32 rx_flex_desc_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
};

/* VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF */
static const u32 adv_rss_pf_allowlist_opcodes[] = {
	VIRTCHNL_OP_ADD_RSS_CFG, VIRTCHNL_OP_DEL_RSS_CFG,
};

/* VIRTCHNL_VF_OFFLOAD_FDIR_PF */
static const u32 fdir_pf_allowlist_opcodes[] = {
	VIRTCHNL_OP_ADD_FDIR_FILTER, VIRTCHNL_OP_DEL_FDIR_FILTER,
	VIRTCHNL_OP_QUERY_FDIR_FILTER,
};


static const u32 large_num_qpairs_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_MAX_RSS_QREGION,
	VIRTCHNL_OP_ENABLE_QUEUES_V2,
	VIRTCHNL_OP_DISABLE_QUEUES_V2,
	VIRTCHNL_OP_MAP_QUEUE_VECTOR,
};

struct allowlist_opcode_info {
	const u32 *opcodes;
	size_t size;
};

#define BIT_INDEX(caps) (HWEIGHT((caps) - 1))
static const struct allowlist_opcode_info allowlist_opcodes[] = {
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_L2)] = {
		.opcodes = l2_allowlist_opcodes,
		.size = ARRAY_SIZE(l2_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_IWARP)] = {
		.opcodes = iwarp_allowlist_opcodes,
		.size = ARRAY_SIZE(iwarp_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_REQ_QUEUES)] = {
		.opcodes = req_queues_allowlist_opcodes,
		.size = ARRAY_SIZE(req_queues_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_VLAN)] = {
		.opcodes = vlan_allowlist_opcodes,
		.size = ARRAY_SIZE(vlan_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_RSS_PF)] = {
		.opcodes = rss_pf_allowlist_opcodes,
		.size = ARRAY_SIZE(rss_pf_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_ADQ)] = {
		.opcodes = adq_allowlist_opcodes,
		.size = ARRAY_SIZE(adq_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_ADQ_V2)] = {
		.opcodes = adq_v2_allowlist_opcodes,
		.size = ARRAY_SIZE(adq_v2_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_CAP_DCF)] = {
		.opcodes = cap_dcf_allowlist_opcodes,
		.size = ARRAY_SIZE(cap_dcf_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)] = {
		.opcodes = rx_flex_desc_allowlist_opcodes,
		.size = ARRAY_SIZE(rx_flex_desc_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF)] = {
		.opcodes = adv_rss_pf_allowlist_opcodes,
		.size = ARRAY_SIZE(adv_rss_pf_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_OFFLOAD_FDIR_PF)] = {
		.opcodes = fdir_pf_allowlist_opcodes,
		.size = ARRAY_SIZE(fdir_pf_allowlist_opcodes)},
	[BIT_INDEX(VIRTCHNL_VF_LARGE_NUM_QPAIRS)] = {
		.opcodes = large_num_qpairs_allowlist_opcodes,
		.size = ARRAY_SIZE(large_num_qpairs_allowlist_opcodes)},
};

/**
 * ice_vc_opcode_is_allowed - check if this opcode is allowed on this VF
 * @vf: pointer to VF structure
 * @opcode: virtchnl opcode
 *
 * Return true if message is allowed on this VF
 */
bool ice_vc_is_opcode_allowed(struct ice_vf *vf, u32 opcode)
{
	if (opcode >= VIRTCHNL_OP_MAX)
		return false;

	return test_bit(opcode, vf->opcodes_allowlist);
}

/**
 * ice_vc_allowlist_opcodes - allowlist selected opcodes
 * @vf: pointer to VF structure
 * @opcodes: array of opocodes to allowlist
 * @size: size of opcodes array
 *
 * Function should be called to allowlist opcodes on VF.
 */
static void
ice_vc_allowlist_opcodes(struct ice_vf *vf, const u32 *opcodes, size_t size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		set_bit(opcodes[i], vf->opcodes_allowlist);
}


/**
 * ice_vc_clear_allowlist - clear all allowlist opcodes
 * @vf: pointer to VF structure
 */
static void ice_vc_clear_allowlist(struct ice_vf *vf)
{
	bitmap_zero(vf->opcodes_allowlist, VIRTCHNL_OP_MAX);
}

/**
 * ice_vc_set_default_allowlist - allowlist default opcodes for VF
 * @vf: pointer to VF structure
 */
void ice_vc_set_default_allowlist(struct ice_vf *vf)
{
	ice_vc_clear_allowlist(vf);
	ice_vc_allowlist_opcodes(vf, default_allowlist_opcodes,
				 ARRAY_SIZE(default_allowlist_opcodes));
}

/**
 * ice_vc_set_working_allowlist - allowlist opcodes needed to by VF to work
 * @vf: pointer to VF structure
 *
 * Whitelist opcodes that aren't associated with specific caps, but
 * are needed by VF to work.
 */
void ice_vc_set_working_allowlist(struct ice_vf *vf)
{
	ice_vc_allowlist_opcodes(vf, working_allowlist_opcodes,
				 ARRAY_SIZE(working_allowlist_opcodes));
}

/**
 * ice_vc_set_allowlist_based_on_caps - allowlist VF opcodes according caps
 * @vf: pointer to VF structure
 */
void ice_vc_set_caps_allowlist(struct ice_vf *vf)
{
	unsigned long caps = vf->driver_caps;
	unsigned int i;

	for_each_set_bit(i, &caps, ARRAY_SIZE(allowlist_opcodes))
		ice_vc_allowlist_opcodes(vf, allowlist_opcodes[i].opcodes,
					 allowlist_opcodes[i].size);
}
