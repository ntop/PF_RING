// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_dcb_lib.h"
#include "ice_virtchnl_allowlist.h"

#define FIELD_SELECTOR(proto_hdr_field) \
		BIT((proto_hdr_field) & PROTO_HDR_FIELD_MASK)

struct ice_vc_hdr_match_type {
	u32 vc_hdr;	/* virtchnl headers (VIRTCHNL_PROTO_HDR_XXX) */
	u32 ice_hdr;	/* ice headers (ICE_FLOW_SEG_HDR_XXX) */
};

static const struct ice_vc_hdr_match_type ice_vc_hdr_list_os[] = {
	{VIRTCHNL_PROTO_HDR_NONE,	ICE_FLOW_SEG_HDR_NONE},
	{VIRTCHNL_PROTO_HDR_IPV4,	ICE_FLOW_SEG_HDR_IPV4 |
					ICE_FLOW_SEG_HDR_IPV_OTHER},
	{VIRTCHNL_PROTO_HDR_IPV6,	ICE_FLOW_SEG_HDR_IPV6 |
					ICE_FLOW_SEG_HDR_IPV_OTHER},
	{VIRTCHNL_PROTO_HDR_TCP,	ICE_FLOW_SEG_HDR_TCP},
	{VIRTCHNL_PROTO_HDR_UDP,	ICE_FLOW_SEG_HDR_UDP},
	{VIRTCHNL_PROTO_HDR_SCTP,	ICE_FLOW_SEG_HDR_SCTP},
};

static const struct ice_vc_hdr_match_type ice_vc_hdr_list_comms[] = {
	{VIRTCHNL_PROTO_HDR_NONE,	ICE_FLOW_SEG_HDR_NONE},
	{VIRTCHNL_PROTO_HDR_ETH,	ICE_FLOW_SEG_HDR_ETH},
	{VIRTCHNL_PROTO_HDR_S_VLAN,	ICE_FLOW_SEG_HDR_VLAN},
	{VIRTCHNL_PROTO_HDR_C_VLAN,	ICE_FLOW_SEG_HDR_VLAN},
	{VIRTCHNL_PROTO_HDR_IPV4,	ICE_FLOW_SEG_HDR_IPV4 |
					ICE_FLOW_SEG_HDR_IPV_OTHER},
	{VIRTCHNL_PROTO_HDR_IPV6,	ICE_FLOW_SEG_HDR_IPV6 |
					ICE_FLOW_SEG_HDR_IPV_OTHER},
	{VIRTCHNL_PROTO_HDR_TCP,	ICE_FLOW_SEG_HDR_TCP},
	{VIRTCHNL_PROTO_HDR_UDP,	ICE_FLOW_SEG_HDR_UDP},
	{VIRTCHNL_PROTO_HDR_SCTP,	ICE_FLOW_SEG_HDR_SCTP},
	{VIRTCHNL_PROTO_HDR_PPPOE,	ICE_FLOW_SEG_HDR_PPPOE},
	{VIRTCHNL_PROTO_HDR_GTPU_IP,	ICE_FLOW_SEG_HDR_GTPU_IP},
	{VIRTCHNL_PROTO_HDR_GTPU_EH,	ICE_FLOW_SEG_HDR_GTPU_EH},
	{VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN,
					ICE_FLOW_SEG_HDR_GTPU_DWN},
	{VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP,
					ICE_FLOW_SEG_HDR_GTPU_UP},
	{VIRTCHNL_PROTO_HDR_L2TPV3,	ICE_FLOW_SEG_HDR_L2TPV3},
	{VIRTCHNL_PROTO_HDR_ESP,	ICE_FLOW_SEG_HDR_ESP},
	{VIRTCHNL_PROTO_HDR_AH,		ICE_FLOW_SEG_HDR_AH},
	{VIRTCHNL_PROTO_HDR_PFCP,	ICE_FLOW_SEG_HDR_PFCP_SESSION},
	{VIRTCHNL_PROTO_HDR_GTPC,	ICE_FLOW_SEG_HDR_GTPC},
};

struct ice_vc_hash_field_match_type {
	u32 vc_hdr;		/* virtchnl headers
				 * (VIRTCHNL_PROTO_HDR_XXX)
				 */
	u32 vc_hash_field;	/* virtchnl hash fields selector
				 * FIELD_SELECTOR((VIRTCHNL_PROTO_HDR_ETH_XXX))
				 */
	u64 ice_hash_field;	/* ice hash fields
				 * (BIT_ULL(ICE_FLOW_FIELD_IDX_XXX))
				 */
};

static const struct
ice_vc_hash_field_match_type ice_vc_hash_field_list_os[] = {
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		ICE_FLOW_HASH_IPV4},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_SA)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_DA)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST),
		ICE_FLOW_HASH_IPV6},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		ICE_FLOW_HASH_IPV6 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT),
		ICE_FLOW_HASH_TCP_PORT},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT),
		ICE_FLOW_HASH_UDP_PORT},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT),
		ICE_FLOW_HASH_SCTP_PORT},
};

static const struct
ice_vc_hash_field_match_type ice_vc_hash_field_list_comms[] = {
	{VIRTCHNL_PROTO_HDR_ETH, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ETH_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_ETH_SA)},
	{VIRTCHNL_PROTO_HDR_ETH, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ETH_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_ETH_DA)},
	{VIRTCHNL_PROTO_HDR_ETH, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ETH_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ETH_DST),
		ICE_FLOW_HASH_ETH},
	{VIRTCHNL_PROTO_HDR_ETH,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ETH_ETHERTYPE),
		BIT_ULL(ICE_FLOW_FIELD_IDX_ETH_TYPE)},
	{VIRTCHNL_PROTO_HDR_S_VLAN,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_S_VLAN_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_S_VLAN)},
	{VIRTCHNL_PROTO_HDR_C_VLAN,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_C_VLAN_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_C_VLAN)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		ICE_FLOW_HASH_IPV4},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_SA)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_DA)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST),
		ICE_FLOW_HASH_IPV6},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		ICE_FLOW_HASH_IPV6 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_DST),
		ICE_FLOW_HASH_IPV6_PRE64},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_SA)},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_DA)},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		ICE_FLOW_HASH_IPV6_PRE64 |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV6,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PROT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT),
		ICE_FLOW_HASH_TCP_PORT},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT),
		ICE_FLOW_HASH_UDP_PORT},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_DST_PORT)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT),
		ICE_FLOW_HASH_SCTP_PORT},
	{VIRTCHNL_PROTO_HDR_PPPOE,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_PPPOE_SESS_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_PPPOE_SESS_ID)},
	{VIRTCHNL_PROTO_HDR_GTPU_IP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_GTPU_IP_TEID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_GTPU_IP_TEID)},
	{VIRTCHNL_PROTO_HDR_L2TPV3,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_L2TPV3_SESS_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV3_SESS_ID)},
	{VIRTCHNL_PROTO_HDR_ESP, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ESP_SPI),
		BIT_ULL(ICE_FLOW_FIELD_IDX_ESP_SPI)},
	{VIRTCHNL_PROTO_HDR_AH, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_AH_SPI),
		BIT_ULL(ICE_FLOW_FIELD_IDX_AH_SPI)},
	{VIRTCHNL_PROTO_HDR_PFCP, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_PFCP_SEID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_PFCP_SEID)},
	{VIRTCHNL_PROTO_HDR_GTPC,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_GTPC_TEID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_GTPC_TEID)},
};

/**
 * ice_get_vf_vsi - get VF's VSI based on the stored index
 * @vf: VF used to get VSI
 */
struct ice_vsi *ice_get_vf_vsi(struct ice_vf *vf)
{
	return vf->pf->vsi[vf->lan_vsi_idx];
}

static struct ice_vsi *ice_get_vf_adq_vsi(struct ice_vf *vf, u8 tc)
{
	return vf->pf->vsi[vf->ch[tc].vsi_idx];
}

/**
 * ice_is_vf_adq_ena - is VF ADQ enabled
 * @vf: pointer to the VF info
 *
 * This function returns true if VF ADQ is enabled. It is must to check
 * VF's num_tc as well, it must be more than ICE_VF_CHNL_START_TC for
 * valid ADQ configuration
 */
static bool ice_is_vf_adq_ena(struct ice_vf *vf)
{
	return vf->adq_enabled && (vf->num_tc > ICE_VF_CHNL_START_TC);
}

/**
 * ice_is_vf_adq_stop_rings - stops the VF ADQ VSI rings
 * @vf: pointer to the VF info
 * @tc: VF ADQ TC number
 *
 * This function stops Tx and Rx ring specific to VF ADQ VSI
 */
static void ice_vf_adq_vsi_stop_rings(struct ice_vf *vf, int tc)
{
	struct ice_vsi *vsi = ice_get_vf_adq_vsi(vf, tc);

	if (!vsi)
		return;
	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);
}

/**
 * ice_is_vf_adq_disable_txqs - disable Tx queues for VF ADQ
 * @vf: pointer to the VF info
 * @tc: VF ADQ TC number
 *
 * This function disabled Tx queues specific to VF ADQ VSI
 */
static void ice_vf_adq_vsi_disable_txqs(struct ice_vf *vf, int tc)
{
	struct ice_vsi *vsi = ice_get_vf_adq_vsi(vf, tc);

	if (!vsi)
		return;
	ice_dis_vsi_txq(vsi->port_info, vf->ch[tc].vsi_idx, 0, 0, NULL, NULL,
			NULL, ICE_VF_RESET, vf->vf_id, NULL);
}

/**
 * ice_validate_vf_id - helper to check if VF ID is valid
 * @pf: pointer to the PF structure
 * @vf_id: the ID of the VF to check
 */
static int ice_validate_vf_id(struct ice_pf *pf, u16 vf_id)
{
	/* vf_id range is only valid for 0-255, and should always be unsigned */
	if (vf_id >= pf->num_alloc_vfs) {
		dev_err(ice_pf_to_dev(pf), "Invalid VF ID: %u\n", vf_id);
		return -EINVAL;
	}
	return 0;
}

/**
 * ice_check_vf_init - helper to check if VF init complete
 * @pf: pointer to the PF structure
 * @vf: the pointer to the VF to check
 */
static int ice_check_vf_init(struct ice_pf *pf, struct ice_vf *vf)
{
	if (!test_bit(ICE_VF_STATE_INIT, vf->vf_states)) {
		dev_err(ice_pf_to_dev(pf), "VF ID: %u in reset. Try again.\n",
			vf->vf_id);
		return -EBUSY;
	}
	return 0;
}

/**
 * ice_err_to_virt_err - translate errors for VF return code
 * @ice_err: error return code
 */
static enum virtchnl_status_code ice_err_to_virt_err(enum ice_status ice_err)
{
	switch (ice_err) {
	case ICE_SUCCESS:
		return VIRTCHNL_STATUS_SUCCESS;
	case ICE_ERR_BAD_PTR:
	case ICE_ERR_INVAL_SIZE:
	case ICE_ERR_DEVICE_NOT_SUPPORTED:
	case ICE_ERR_PARAM:
	case ICE_ERR_CFG:
		return VIRTCHNL_STATUS_ERR_PARAM;
	case ICE_ERR_NO_MEMORY:
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;
	case ICE_ERR_NOT_READY:
	case ICE_ERR_RESET_FAILED:
	case ICE_ERR_FW_API_VER:
	case ICE_ERR_AQ_ERROR:
	case ICE_ERR_AQ_TIMEOUT:
	case ICE_ERR_AQ_FULL:
	case ICE_ERR_AQ_NO_WORK:
	case ICE_ERR_AQ_EMPTY:
		return VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
	default:
		return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
	}
}

/**
 * ice_vc_vf_broadcast - Broadcast a message to all VFs on PF
 * @pf: pointer to the PF structure
 * @v_opcode: operation code
 * @v_retval: return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 */
static void
ice_vc_vf_broadcast(struct ice_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	struct ice_hw *hw = &pf->hw;
	unsigned int i;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		/* Not all vfs are enabled so skip the ones that are not */
		if (!test_bit(ICE_VF_STATE_INIT, vf->vf_states) &&
		    !test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
			continue;

		/* Ignore return value on purpose - a given VF may fail, but
		 * we need to keep going and send to all of them
		 */
		ice_aq_send_msg_to_vf(hw, vf->vf_id, v_opcode, v_retval, msg,
				      msglen, NULL);
	}
}

/**
 * ice_set_pfe_link - Set the link speed/status of the virtchnl_pf_event
 * @vf: pointer to the VF structure
 * @pfe: pointer to the virtchnl_pf_event to set link speed/status for
 * @ice_link_speed: link speed specified by ICE_AQ_LINK_SPEED_*
 * @link_up: whether or not to set the link up/down
 */
static void
ice_set_pfe_link(struct ice_vf *vf, struct virtchnl_pf_event *pfe,
		 int ice_link_speed, bool link_up)
{
	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED) {
		pfe->event_data.link_event_adv.link_status = link_up;
		/* Speed in Mbps */
		pfe->event_data.link_event_adv.link_speed =
			ice_conv_link_speed_to_virtchnl(true, ice_link_speed);
	} else {
		pfe->event_data.link_event.link_status = link_up;
		/* Legacy method for virtchnl link speeds */
		pfe->event_data.link_event.link_speed =
			(enum virtchnl_link_speed)
			ice_conv_link_speed_to_virtchnl(false, ice_link_speed);
	}
}

/**
 * ice_vf_has_no_qs_ena - check if the VF has any Rx or Tx queues enabled
 * @vf: the VF to check
 *
 * Returns true if the VF has no Rx and no Tx queues enabled and returns false
 * otherwise
 */
static bool ice_vf_has_no_qs_ena(struct ice_vf *vf)
{
	return (!bitmap_weight(vf->rxq_ena, ICE_MAX_QS_PER_VF) &&
		!bitmap_weight(vf->txq_ena, ICE_MAX_QS_PER_VF));
}

/**
 * ice_vf_get_port_info - Get the VF's port info structure
 * @vf: VF used to get the port info structure for
 */
static struct ice_port_info *ice_vf_get_port_info(struct ice_vf *vf)
{
	return vf->pf->hw.port_info;
}

/**
 * ice_is_vf_link_up - check if the VF's link is up
 * @vf: VF to check if link is up
 */
static bool ice_is_vf_link_up(struct ice_vf *vf)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	struct ice_pf *pf = vf->pf;

	if (ice_check_vf_init(pf, vf))
		return false;

	if (test_bit(ICE_BAD_EEPROM, pf->state))
		return false;

	if (ice_vf_has_no_qs_ena(vf))
		return false;
	else if (vf->link_forced)
		return vf->link_up;
	else
		return pi->phy.link_info.link_info &
			ICE_AQ_LINK_UP;
}

/**
 * ice_vc_notify_vf_link_state - Inform a VF of link status
 * @vf: pointer to the VF structure
 *
 * send a link status message to a single VF
 */
static void ice_vc_notify_vf_link_state(struct ice_vf *vf)
{
	struct virtchnl_pf_event pfe = { 0 };
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi;

	pi = ice_vf_get_port_info(vf);


	pfe.event = VIRTCHNL_EVENT_LINK_CHANGE;
	pfe.severity = PF_EVENT_SEVERITY_INFO;

	if (ice_is_vf_link_up(vf))
		ice_set_pfe_link(vf, &pfe, pi->phy.link_info.link_speed, true);
	else
		ice_set_pfe_link(vf, &pfe, ICE_AQ_LINK_SPEED_UNKNOWN, false);

	ice_aq_send_msg_to_vf(hw, vf->vf_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe,
			      sizeof(pfe), NULL);
}

/**
 * ice_vf_invalidate_vsi - invalidate vsi_idx/vsi_num to remove VSI access
 * @vf: VF to remove access to VSI for
 */
static void ice_vf_invalidate_vsi(struct ice_vf *vf)
{
	vf->lan_vsi_idx = ICE_NO_VSI;
	vf->lan_vsi_num = ICE_NO_VSI;
}

/**
 * ice_vf_vsi_release - invalidate the VF's VSI after freeing it
 * @vf: invalidate this VF's VSI after freeing it
 */
static void ice_vf_vsi_release(struct ice_vf *vf)
{
	ice_vsi_release(ice_get_vf_vsi(vf));
	ice_vf_invalidate_vsi(vf);
}

/**
 * ice_vf_adq_invalidate_vsi - invalidate vsi_idx/vsi_num to remove VSI access
 * @vf: VF that ADQ VSI is being invalidated on
 * @tc: TC used to access channel specific vsi_idx/vsi_num
 */
static void ice_vf_adq_invalidate_vsi(struct ice_vf *vf, u8 tc)
{
	vf->ch[tc].vsi_idx = ICE_NO_VSI;
	vf->ch[tc].vsi_num = ICE_NO_VSI;
}

/**
 * ice_vf_adq_vsi_valid - is ADQ VSI valid?
 * @vf: VF that ADQ VSI is being validated
 * @tc: TC used to access channel specific vsi_idx/vsi_num
 *
 * vsi_idx must be non-zero, and vsi_idx and vsi_num must not be ICE_NO_VSI
 */
static bool ice_vf_adq_vsi_valid(struct ice_vf *vf, u8 tc)
{
	return (vf->ch[tc].vsi_idx && vf->ch[tc].vsi_idx != ICE_NO_VSI &&
		vf->ch[tc].vsi_num != ICE_NO_VSI);
}

/**
 * ice_vf_adq_vsi_release - release VF ADQ VSI resources
 * @vf: VF that ADQ VSI is being released on
 * @tc: TC used to access channel specific VSI
 *
 * This function stops Tx and Rx queues if specified, disables Tx queues if
 * specified, releases VSI resources, and invalidates it
 *
 */
static void ice_vf_adq_vsi_release(struct ice_vf *vf, u8 tc)
{
	ice_vsi_release(ice_get_vf_adq_vsi(vf, tc));
	ice_vf_adq_invalidate_vsi(vf, tc);
}

/**
 * ice_vf_adq_cfg_cleanup - invalidate the VF's channel software info
 * @vf: VF that ADQ VSI is being released on
 * @tc: TC used to access channel specific VSI
 *
 * This function invalidates software data structures specific to channel
 * such as num_qps, tx_rate, etc... This is called from places like:
 * when ADQ VSI is released either from rebuild path "ice_vf_adq_release"
 * or during rebuild ADQ config if failed to create/setup VF ADQ VSIs
 */
static void ice_vf_adq_cfg_cleanup(struct ice_vf *vf, u8 tc)
{
	vf->ch[tc].num_qps = 0;
	vf->ch[tc].offset = 0;
	vf->ch[tc].max_tx_rate = 0;
	/* since this function is called from places where
	 * VF ADQ VSI are cleanup from HW, it's OK to clear
	 * VF ADQ filter_type to be INVALID.
	 * Remember VF ADQ filter are replayed by VF driver
	 * as needed
	 */
	vf->ch[tc].fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
}

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_del_all_adv_switch_fltr
 * @vf: pointer to the VF info
 *
 * This function deletes all advanced switch filters specific to the VF and
 * releases filter memory and updates all book-keeping. This function to be
 * used when delete channel message is received before deleting channel VSIs
 */
static void ice_del_all_adv_switch_fltr(struct ice_vf *vf)
{
	struct ice_rule_query_data rule;
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct hlist_node *node;
	struct device *dev;
	int err;
	int i;

	dev = ice_pf_to_dev(pf);
	hlist_for_each_entry_safe(f, node, &vf->tc_flower_fltr_list,
				  tc_flower_node) {
		if (!f->dest_vsi)
			continue;

		/* Deleting TC filter */
		rule.rid = f->rid;
		rule.rule_id = f->rule_id;
		rule.vsi_handle = f->dest_id;
		err = ice_rem_adv_rule_by_id(&pf->hw, &rule);
		if (err) {
			if (err == ICE_ERR_DOES_NOT_EXIST)
				dev_dbg(dev, "VF %d: filter (rule_id %u) for dest VSI %u DOES NOT EXIST in hw table\n",
					vf->vf_id, f->rule_id, f->dest_id);
			else
				dev_err(dev, "VF %d: Failed to delete switch filter for VSI handle %u, err %d\n",
					vf->vf_id, f->dest_id, err);
		}

		/* book-keeping and update filter type if filter count
		 * reached zero
		 */
		f->dest_vsi->num_chnl_fltr--;
		hlist_del(&f->tc_flower_node);
		devm_kfree(dev, f);
		vf->num_dmac_chnl_fltrs--;
	}

	/* Reset VF channel filter type to be INVALID */
	for (i = 1; i < vf->num_tc; i++)
		vf->ch[i].fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_vf_adq_release - perform VF ADQ resource cleanup only
 * @vf: pointer to the VF structure
 *
 * Delete all VF ADQ filters, release VF ADQ VSIs, cleanup internal data
 * structues which keeps track of per TC infor including TC0. This function
 * is invoked only when VFLR based VF Reset.
 */
static void ice_vf_adq_release(struct ice_vf *vf)
{
	u8 tc;

	/* no ADQ configured, nothing to do */
	if (!ice_is_vf_adq_ena(vf))
		return;

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* release VF ADQ specific filters and eventually VF driver
	 * will trigger replay of VF ADQ filters as needed, just like
	 * other MAC, VLAN filters
	 */
	ice_del_all_adv_switch_fltr(vf);
#endif

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;
		/* Tx queues are disabled before VF reset is scheduled as part
		 * of VFLR flow. Disabling TX queues again causes error
		 * such as EINVAL from admin command because underlying
		 * scheduler configs are cleared as part of disabling once
		 */
		if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
			ice_vf_adq_vsi_stop_rings(vf, tc);
		ice_vf_adq_vsi_release(vf, tc);
		/* clear per TC info to avoid stale information such as
		 * num_qps, tx_rate, etc...
		 */
		ice_vf_adq_cfg_cleanup(vf, tc);
	}

	/* to avoid rebuilding of VF ADQ VSIs by mistake */
	vf->adq_enabled = false;
	vf->num_tc = 0;

	/* main VF VSI should be built with default, hence clear related
	 * data structures otherwise vf->ch[0].num_qps and tx_rate will
	 * still have stale information as stored from "add channel"
	 * virtchnl message
	 */
	ice_vf_adq_cfg_cleanup(vf, 0);
}

/**
 * ice_vf_ctrl_invalidate_vsi - invalidate ctrl_vsi_idx to remove VSI access
 * @vf: VF that control VSI is being invalidated on
 */
static void ice_vf_ctrl_invalidate_vsi(struct ice_vf *vf)
{
	vf->ctrl_vsi_idx = ICE_NO_VSI;
}

/**
 * ice_vf_ctrl_vsi_release - invalidate the VF's control VSI after freeing it
 * @vf: VF that control VSI is being released on
 */
static void ice_vf_ctrl_vsi_release(struct ice_vf *vf)
{
	ice_vsi_release(vf->pf->vsi[vf->ctrl_vsi_idx]);
	ice_vf_ctrl_invalidate_vsi(vf);
}

/**
 * ice_free_vf_res - Free a VF's resources
 * @vf: pointer to the VF info
 */
static void ice_free_vf_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	int i, last_vector_idx;

	/* First, disable VF's configuration API to prevent OS from
	 * accessing the VF's VSI after it's freed or invalidated.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);
	ice_vf_fdir_exit(vf);
	/* free VF control VSI */
	if (vf->ctrl_vsi_idx != ICE_NO_VSI)
		ice_vf_ctrl_vsi_release(vf);

	/* free VSI and disconnect it from the parent uplink */
	if (vf->lan_vsi_idx != ICE_NO_VSI) {
		ice_vf_vsi_release(vf);
		vf->num_mac = 0;
	}

	last_vector_idx = vf->first_vector_idx + pf->num_msix_per_vf - 1;

	/* clear VF MDD event information */
	memset(&vf->mdd_tx_events, 0, sizeof(vf->mdd_tx_events));
	memset(&vf->mdd_rx_events, 0, sizeof(vf->mdd_rx_events));

	ice_vf_adq_release(vf);

	/* Disable interrupts so that VF starts in a known state */
	for (i = vf->first_vector_idx; i <= last_vector_idx; i++) {
		wr32(&pf->hw, GLINT_DYN_CTL(i), GLINT_DYN_CTL_CLEARPBA_M);
		ice_flush(&pf->hw);
	}
	/* reset some of the state variables keeping track of the resources */
	clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
}

/**
 * ice_dis_vf_mappings
 * @vf: pointer to the VF structure
 */
static void ice_dis_vf_mappings(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int first, last, v;
	struct ice_hw *hw;

	hw = &pf->hw;
	vsi = ice_get_vf_vsi(vf);

	dev = ice_pf_to_dev(pf);
	wr32(hw, VPINT_ALLOC(vf->vf_id), 0);
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), 0);

	first = vf->first_vector_idx;
	last = first + pf->num_msix_per_vf - 1;
	for (v = first; v <= last; v++) {
		u32 reg;

		reg = (((1 << GLINT_VECT2FUNC_IS_PF_S) &
			GLINT_VECT2FUNC_IS_PF_M) |
		       ((hw->pf_id << GLINT_VECT2FUNC_PF_NUM_S) &
			GLINT_VECT2FUNC_PF_NUM_M));
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");

	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
}

/**
 * ice_sriov_free_msix_res - Reset/free any used MSIX resources
 * @pf: pointer to the PF structure
 *
 * Since no MSIX entries are taken from the pf->irq_tracker then just clear
 * the pf->sriov_base_vector.
 *
 * Returns 0 on success, and -EINVAL on error.
 */
static int ice_sriov_free_msix_res(struct ice_pf *pf)
{
	struct ice_res_tracker *res;

	if (!pf)
		return -EINVAL;

	res = pf->irq_tracker;
	if (!res)
		return -EINVAL;

	/* give back irq_tracker resources used */
	WARN_ON(pf->sriov_base_vector < res->num_entries);

	pf->sriov_base_vector = 0;

	return 0;
}

/**
 * ice_set_vf_state_qs_dis - Set VF queues state to disabled
 * @vf: pointer to the VF structure
 */
void ice_set_vf_state_qs_dis(struct ice_vf *vf)
{
	/* Clear Rx/Tx enabled queues flag */
	bitmap_zero(vf->txq_ena, ICE_MAX_QS_PER_VF);
	bitmap_zero(vf->rxq_ena, ICE_MAX_QS_PER_VF);
	clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);
}

/**
 * ice_dis_vf_qs - Disable the VF queues
 * @vf: pointer to the VF structure
 */
static void ice_dis_vf_qs(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);
	/* Likewise if VF ADQ is enabled, stop Tx and Rx rings of VF ADQ VSI */
	if (ice_is_vf_adq_ena(vf)) {
		int tc;

		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			if (!ice_vf_adq_vsi_valid(vf, tc))
				continue;
			vsi = ice_get_vf_adq_vsi(vf, tc);
			ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
			ice_vsi_stop_all_rx_rings(vsi);
		}
	}
	ice_set_vf_state_qs_dis(vf);
}

/**
 * ice_free_vfs - Free all VFs
 * @pf: pointer to the PF structure
 */
void ice_free_vfs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	unsigned int tmp, i;

	if (!pf->vf)
		return;


	while (test_and_set_bit(ICE_VF_DIS, pf->state))
		usleep_range(1000, 2000);


	/* Disable IOV before freeing resources. This lets any VF drivers
	 * running in the host get themselves cleaned up before we yank
	 * the carpet out from underneath their feet.
	 */
	if (!pci_vfs_assigned(pf->pdev))
		pci_disable_sriov(pf->pdev);
	else
		dev_warn(dev, "VFs are assigned - not disabling SR-IOV\n");

	if (ice_dcf_get_state(pf) != ICE_DCF_STATE_OFF) {
		ice_rm_all_dcf_sw_rules(pf);
		ice_dcf_set_state(pf, ICE_DCF_STATE_OFF);
		pf->dcf.vf = NULL;
	}

	/* Avoid wait time by stopping all VFs at the same time */
	ice_for_each_vf(pf, i)
		if (test_bit(ICE_VF_STATE_QS_ENA, pf->vf[i].vf_states))
			ice_dis_vf_qs(&pf->vf[i]);

	tmp = pf->num_alloc_vfs;
	pf->num_qps_per_vf = 0;
	pf->num_alloc_vfs = 0;
	for (i = 0; i < tmp; i++) {
		if (test_bit(ICE_VF_STATE_INIT, pf->vf[i].vf_states)) {
			/* disable VF qp mappings and set VF disable state */
			ice_dis_vf_mappings(&pf->vf[i]);
			set_bit(ICE_VF_STATE_DIS, pf->vf[i].vf_states);
			ice_free_vf_res(&pf->vf[i]);
		}
	}

	if (ice_sriov_free_msix_res(pf))
		dev_err(dev, "Failed to free MSIX resources used by SR-IOV\n");

	devm_kfree(dev, pf->vf);
	pf->vf = NULL;

	/* This check is for when the driver is unloaded while VFs are
	 * assigned. Setting the number of VFs to 0 through sysfs is caught
	 * before this function ever gets called.
	 */
	if (!pci_vfs_assigned(pf->pdev)) {
		unsigned int vf_id;

		/* Acknowledge VFLR for all VFs. Without this, VFs will fail to
		 * work correctly when SR-IOV gets re-enabled.
		 */
		for (vf_id = 0; vf_id < tmp; vf_id++) {
			u32 reg_idx, bit_idx;

			reg_idx = (hw->func_caps.vf_base_id + vf_id) / 32;
			bit_idx = (hw->func_caps.vf_base_id + vf_id) % 32;
			wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
		}
	}

	/* clear malicious info if the VFs are getting released */
	for (i = 0; i < tmp; i++)
		if (ice_mbx_clear_malvf(&hw->mbx_snapshot, pf->malvfs, ICE_MAX_VF_COUNT, i))
			dev_dbg(dev, "failed to clear malicious VF state for VF %u\n", i);

	clear_bit(ICE_VF_DIS, pf->state);
	clear_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
}

/**
 * ice_trigger_vf_reset - Reset a VF on HW
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 * @is_pfr: true if the reset was triggered due to a previous PFR
 *
 * Trigger hardware to start a reset for a particular VF. Expects the caller
 * to wait the proper amount of time to allow hardware to reset the VF before
 * it cleans up and restores VF functionality.
 */
static void ice_trigger_vf_reset(struct ice_vf *vf, bool is_vflr, bool is_pfr)
{
	struct ice_pf *pf = vf->pf;
	u32 reg, reg_idx, bit_idx;
	unsigned int vf_abs_id, i;
	struct device *dev;
	struct ice_hw *hw;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;
	vf_abs_id = vf->vf_id + hw->func_caps.vf_base_id;

	/* Inform VF that it is no longer active, as a warning */
	clear_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);

	/* Disable VF's configuration API during reset. The flag is re-enabled
	 * when it's safe again to access VF's VSI.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);

	/* VF_MBX_ARQLEN and VF_MBX_ATQLEN are cleared by PFR, so the driver
	 * needs to clear them in the case of VFR/VFLR. If this is done for
	 * PFR, it can mess up VF resets because the VF driver may already
	 * have started cleanup by the time we get here.
	 */
	if (!is_pfr) {
		wr32(hw, VF_MBX_ARQLEN(vf->vf_id), 0);
		wr32(hw, VF_MBX_ATQLEN(vf->vf_id), 0);
	}

	/* In the case of a VFLR, the HW has already reset the VF and we
	 * just need to clean up, so don't hit the VFRTRIG register.
	 */
	if (!is_vflr) {
		/* reset VF using VPGEN_VFRTRIG reg */
		reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
		reg |= VPGEN_VFRTRIG_VFSWR_M;
		wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);
	}
	/* clear the VFLR bit in GLGEN_VFLRSTAT */
	reg_idx = (vf_abs_id) / 32;
	bit_idx = (vf_abs_id) % 32;
	wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
	ice_flush(hw);

	wr32(hw, PF_PCI_CIAA,
	     VF_DEVICE_STATUS | (vf_abs_id << PF_PCI_CIAA_VF_NUM_S));
	for (i = 0; i < ICE_PCI_CIAD_WAIT_COUNT; i++) {
		reg = rd32(hw, PF_PCI_CIAD);
		/* no transactions pending so stop polling */
		if ((reg & VF_TRANS_PENDING_M) == 0)
			break;

		dev_err(dev, "VF %u PCI transactions stuck\n", vf->vf_id);
		udelay(ICE_PCI_CIAD_WAIT_DELAY_US);
	}
}

/**
 * ice_vf_vsi_setup - Set up a VF VSI
 * @vf: VF to setup VSI for
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct ice_vsi *ice_vf_vsi_setup(struct ice_vf *vf)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_vsi_setup(pf, pi, ICE_VSI_VF, vf->vf_id, NULL, 0);

	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF VSI\n");
		ice_vf_invalidate_vsi(vf);
		return NULL;
	}

	vf->lan_vsi_idx = vsi->idx;
	vf->lan_vsi_num = vsi->vsi_num;

	return vsi;
}

/**
 * ice_vf_adq_vsi_setup - Set up a VF channel VSI
 * @vf: VF to setup VSI for
 * @tc: TC to setup the channel VSI for
 */
static struct ice_vsi *ice_vf_adq_vsi_setup(struct ice_vf *vf, u8 tc)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_vsi_setup(pf, pi, ICE_VSI_VF, vf->vf_id, NULL, tc);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF ADQ VSI for TC %d\n",
			tc);
		ice_vf_adq_invalidate_vsi(vf, tc);
		return NULL;
	}

	vf->ch[tc].vsi_idx = vsi->idx;
	vf->ch[tc].vsi_num = vsi->vsi_num;

	return vsi;
}

/**
 * ice_vf_ctrl_vsi_setup - Set up a VF control VSI
 * @vf: VF to setup control VSI for
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
struct ice_vsi *ice_vf_ctrl_vsi_setup(struct ice_vf *vf)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_vsi_setup(pf, pi, ICE_VSI_CTRL, vf->vf_id, NULL, 0);

	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF control VSI\n");
		ice_vf_ctrl_invalidate_vsi(vf);
	}

	return vsi;
}

/**
 * ice_calc_vf_first_vector_idx - Calculate MSIX vector index in the PF space
 * @pf: pointer to PF structure
 * @vf: pointer to VF that the first MSIX vector index is being calculated for
 *
 * This returns the first MSIX vector index in PF space that is used by this VF.
 * This index is used when accessing PF relative registers such as
 * GLINT_VECT2FUNC and GLINT_DYN_CTL.
 * This will always be the OICR index in the AVF driver so any functionality
 * using vf->first_vector_idx for queue configuration will have to increment by
 * 1 to avoid meddling with the OICR index.
 */
static int ice_calc_vf_first_vector_idx(struct ice_pf *pf, struct ice_vf *vf)
{
	return pf->sriov_base_vector + vf->vf_id * pf->num_msix_per_vf;
}

/**
 * ice_vf_rebuild_host_tx_rate_cfg - re-apply the Tx rate limiting configuration
 * @vf: VF to re-apply the configuration for
 *
 * Called after a VF VSI has been re-added/rebuild during reset. The PF driver
 * needs to re-apply the host configured Tx rate limiting configuration.
 */
static int ice_vf_rebuild_host_tx_rate_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	int err;

	if (vf->min_tx_rate) {
		err = ice_set_min_bw_limit(vsi, (u64)vf->min_tx_rate * 1000);
		if (err) {
			dev_err(dev, "failed to set min Tx rate to %d Mbps for VF %u, error %d\n",
				vf->min_tx_rate, vf->vf_id, err);
			return err;
		}
	}

	if (vf->max_tx_rate) {
		err = ice_set_max_bw_limit(vsi, (u64)vf->max_tx_rate * 1000);
		if (err) {
			dev_err(dev, "failed to set max Tx rate to %d Mbps for VF %u, error %d\n",
				vf->max_tx_rate, vf->vf_id, err);
			return err;
		}
	}

	return 0;
}

/**
 * ice_vf_rebuild_host_vlan_cfg - add VLAN 0 filter or rebuild the Port VLAN
 * @vf: VF to add MAC filters for
 * @vsi: Pointer to VSI
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds either a VLAN 0 or port VLAN based filter after reset.
 */
static int ice_vf_rebuild_host_vlan_cfg(struct ice_vf *vf, struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	u16 vid = 0;
	u8 prio = 0;
	int err;

	if (vf->port_vlan_info) {
		vid = vf->port_vlan_info & VLAN_VID_MASK;
		prio = (vf->port_vlan_info & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
		err = vsi->vlan_ops.set_port_vlan(vsi,
						  ICE_VLAN(ETH_P_8021Q, vid, prio, ICE_FWD_TO_VSI));
		if (err) {
			dev_err(dev, "failed to configure port VLAN via VSI parameters for VF %u, error %d\n",
				vf->vf_id, err);
			return err;
		}
	}

	/* vlan_id will either be 0 or the port VLAN number */
	err = vsi->vlan_ops.add_vlan(vsi, ICE_VLAN(ETH_P_8021Q, vid, prio, ICE_FWD_TO_VSI));
	if (err) {
		dev_err(dev, "failed to add %s VLAN %u filter for VF %u, error %d\n",
			vf->port_vlan_info ? "port" : "", vid, vf->vf_id, err);
		return err;
	}

	return 0;
}

/**
 * ice_vf_rebuild_adq_port_vlan_cfg - set the port VLAN for VF ADQ VSIs
 * @vf: VF to add MAC filters for
 *
 * Called after a VF ADQ VSI has been re-added/rebuilt during reset.
 */
static int ice_vf_rebuild_adq_port_vlan_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	int err, tc;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		vsi = ice_get_vf_adq_vsi(vf, tc);
		err = ice_vf_rebuild_host_vlan_cfg(vf, vsi);
		if (err) {
			dev_err(dev, "failed to configure port VLAN via VSI parameters for VF %u, ADQ VSI(num %u), error %d\n",
				vf->vf_id, vsi->vsi_num, err);
			return err;
		}
	}
	return 0;
}

/**
 * ice_vf_rebuild_host_mac_cfg - add broadcast and the VF's perm_addr/LAA
 * @vf: VF to add MAC filters for
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds a broadcast filter and the VF's perm_addr/LAA after reset.
 */
static int ice_vf_rebuild_host_mac_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	enum ice_status status;
	u8 broadcast[ETH_ALEN];

	eth_broadcast_addr(broadcast);
	status = ice_fltr_add_mac(vsi, broadcast, ICE_FWD_TO_VSI);
	if (status) {
		dev_err(dev, "failed to add broadcast MAC filter for VF %u, error %s\n",
			vf->vf_id, ice_stat_str(status));
		return ice_status_to_errno(status);
	}

	vf->num_mac++;

	if (is_valid_ether_addr(vf->hw_lan_addr.addr)) {
		status = ice_fltr_add_mac(vsi, vf->hw_lan_addr.addr,
					  ICE_FWD_TO_VSI);
		if (status) {
			dev_err(dev, "failed to add default unicast MAC filter %pM for VF %u, error %s\n",
				&vf->hw_lan_addr.addr[0], vf->vf_id,
				ice_stat_str(status));
			return ice_status_to_errno(status);
		}
		vf->num_mac++;

		ether_addr_copy(vf->dev_lan_addr.addr, vf->hw_lan_addr.addr);
	}

	return 0;
}

/**
 * ice_vf_set_host_trust_cfg - set trust setting based on pre-reset value
 * @vf: VF to configure trust setting for
 */
static void ice_vf_set_host_trust_cfg(struct ice_vf *vf)
{
	if (vf->trusted)
		set_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
	else
		clear_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
}

/**
 * ice_ena_vf_msix_mappings - enable VF MSIX mappings in hardware
 * @vf: VF to enable MSIX mappings for
 *
 * Some of the registers need to be indexed/configured using hardware global
 * device values and other registers need 0-based values, which represent PF
 * based values.
 */
static void ice_ena_vf_msix_mappings(struct ice_vf *vf)
{
	int device_based_first_msix, device_based_last_msix;
	int pf_based_first_msix, pf_based_last_msix, v;
	struct ice_pf *pf = vf->pf;
	int device_based_vf_id;
	struct ice_hw *hw;
	u32 reg;

	hw = &pf->hw;

	pf_based_first_msix = vf->first_vector_idx;
	pf_based_last_msix = (pf_based_first_msix + pf->num_msix_per_vf) - 1;

	device_based_first_msix = pf_based_first_msix +
		pf->hw.func_caps.common_cap.msix_vector_first_id;
	device_based_last_msix =
		(device_based_first_msix + pf->num_msix_per_vf) - 1;
	device_based_vf_id = vf->vf_id + hw->func_caps.vf_base_id;

	reg = (((device_based_first_msix << VPINT_ALLOC_FIRST_S) &
		VPINT_ALLOC_FIRST_M) |
	       ((device_based_last_msix << VPINT_ALLOC_LAST_S) &
		VPINT_ALLOC_LAST_M) | VPINT_ALLOC_VALID_M);
	wr32(hw, VPINT_ALLOC(vf->vf_id), reg);

	reg = (((device_based_first_msix << VPINT_ALLOC_PCI_FIRST_S)
		 & VPINT_ALLOC_PCI_FIRST_M) |
	       ((device_based_last_msix << VPINT_ALLOC_PCI_LAST_S) &
		VPINT_ALLOC_PCI_LAST_M) | VPINT_ALLOC_PCI_VALID_M);
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), reg);

	/* map the interrupts to its functions */
	for (v = pf_based_first_msix; v <= pf_based_last_msix; v++) {
		reg = (((device_based_vf_id << GLINT_VECT2FUNC_VF_NUM_S) &
			GLINT_VECT2FUNC_VF_NUM_M) |
		       ((hw->pf_id << GLINT_VECT2FUNC_PF_NUM_S) &
			GLINT_VECT2FUNC_PF_NUM_M));
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	/* Map mailbox interrupt to VF VSI VF MSI-X vector 0 */
	wr32(hw, VPINT_MBX_CTL(device_based_vf_id), VPINT_MBX_CTL_CAUSE_ENA_M);
}

/**
 * ice_ena_vf_q_mappings - enable Rx/Tx queue mappings for a VF
 * @vf: VF to enable the mappings for
 * @max_txq: max Tx queues allowed on the VF's VSI
 * @max_rxq: max Rx queues allowed on the VF's VSI
 */
static void ice_ena_vf_q_mappings(struct ice_vf *vf, u16 max_txq, u16 max_rxq)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_hw *hw = &vf->pf->hw;
	u32 reg;

	/* set regardless of mapping mode */
	wr32(hw, VPLAN_TXQ_MAPENA(vf->vf_id), VPLAN_TXQ_MAPENA_TX_ENA_M);

	/* VF Tx queues allocation */
	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Tx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = (((vsi->txq_map[0] << VPLAN_TX_QBASE_VFFIRSTQ_S) &
			VPLAN_TX_QBASE_VFFIRSTQ_M) |
		       (((max_txq - 1) << VPLAN_TX_QBASE_VFNUMQ_S) &
			VPLAN_TX_QBASE_VFNUMQ_M));
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");
	}

	/* set regardless of mapping mode */
	wr32(hw, VPLAN_RXQ_MAPENA(vf->vf_id), VPLAN_RXQ_MAPENA_RX_ENA_M);

	/* VF Rx queues allocation */
	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Rx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = (((vsi->rxq_map[0] << VPLAN_RX_QBASE_VFFIRSTQ_S) &
			VPLAN_RX_QBASE_VFFIRSTQ_M) |
		       (((max_rxq - 1) << VPLAN_RX_QBASE_VFNUMQ_S) &
			VPLAN_RX_QBASE_VFNUMQ_M));
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
	}
}

/**
 * ice_ena_vf_mappings - enable VF MSIX and queue mapping
 * @vf: pointer to the VF structure
 */
static void ice_ena_vf_mappings(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	u16 max_txq, max_rxq;

	ice_ena_vf_msix_mappings(vf);

	if (ice_is_vf_adq_ena(vf)) {
		u16 offset, num_qps;

		offset = vf->ch[vf->num_tc - 1].offset;
		num_qps = vf->ch[vf->num_tc - 1].num_qps;
		max_txq = offset + num_qps;
		max_rxq = offset + num_qps;
	} else {
		max_txq = vsi->alloc_txq;
		max_rxq = vsi->alloc_rxq;
	}

	ice_ena_vf_q_mappings(vf, max_txq, max_rxq);
}

/**
 * ice_determine_res
 * @pf: pointer to the PF structure
 * @avail_res: available resources in the PF structure
 * @max_res: maximum resources that can be given per VF
 * @min_res: minimum resources that can be given per VF
 *
 * Returns non-zero value if resources (queues/vectors) are available or
 * returns zero if PF cannot accommodate for all num_alloc_vfs.
 */
static int
ice_determine_res(struct ice_pf *pf, u16 avail_res, u16 max_res, u16 min_res)
{
	bool checked_min_res = false;
	int res;

	/* start by checking if PF can assign max number of resources for
	 * all num_alloc_vfs.
	 * if yes, return number per VF
	 * If no, divide by 2 and roundup, check again
	 * repeat the loop till we reach a point where even minimum resources
	 * are not available, in that case return 0
	 */
	res = max_res;
	while ((res >= min_res) && !checked_min_res) {
		int num_all_res;

		num_all_res = pf->num_alloc_vfs * res;
		if (num_all_res <= avail_res)
			return res;

		if (res == min_res)
			checked_min_res = true;

		res = DIV_ROUND_UP(res, 2);
	}
	return 0;
}

/**
 * ice_calc_vf_reg_idx - Calculate the VF's register index in the PF space
 * @vf: VF to calculate the register index for
 * @q_vector: a q_vector associated to the VF
 * @tc: Traffic class number for VF ADQ
 */
int ice_calc_vf_reg_idx(struct ice_vf *vf, struct ice_q_vector *q_vector,
			u8 __maybe_unused tc)
{
	struct ice_pf *pf;
	u32 reg_idx;

	if (!vf || !q_vector)
		return -EINVAL;

	pf = vf->pf;
	/* always add one to account for the OICR being the first MSIX */
	reg_idx = pf->sriov_base_vector + pf->num_msix_per_vf * vf->vf_id +
		  q_vector->v_idx + 1;

	if (tc && ice_is_vf_adq_ena(vf))
		return reg_idx + vf->ch[tc].offset;
	else
		return reg_idx;
}

/**
 * ice_get_max_valid_res_idx - Get the max valid resource index
 * @res: pointer to the resource to find the max valid index for
 *
 * Start from the end of the ice_res_tracker and return right when we find the
 * first res->list entry with the ICE_RES_VALID_BIT set. This function is only
 * valid for SR-IOV because it is the only consumer that manipulates the
 * res->end and this is always called when res->end is set to res->num_entries.
 */
static int ice_get_max_valid_res_idx(struct ice_res_tracker *res)
{
	int i;

	if (!res)
		return -EINVAL;

	for (i = res->num_entries - 1; i >= 0; i--)
		if (res->list[i] & ICE_RES_VALID_BIT)
			return i;

	return 0;
}

/**
 * ice_sriov_set_msix_res - Set any used MSIX resources
 * @pf: pointer to PF structure
 * @num_msix_needed: number of MSIX vectors needed for all SR-IOV VFs
 *
 * This function allows SR-IOV resources to be taken from the end of the PF's
 * allowed HW MSIX vectors so that the irq_tracker will not be affected. We
 * just set the pf->sriov_base_vector and return success.
 *
 * If there are not enough resources available, return an error. This should
 * always be caught by ice_set_per_vf_res().
 *
 * Return 0 on success, and -EINVAL when there are not enough MSIX vectors
 * in the PF's space available for SR-IOV.
 */
static int ice_sriov_set_msix_res(struct ice_pf *pf, u16 num_msix_needed)
{
	u16 total_vectors = pf->hw.func_caps.common_cap.num_msix_vectors;
	int vectors_used = pf->irq_tracker->num_entries;
	int sriov_base_vector;

	sriov_base_vector = total_vectors - num_msix_needed;

	/* make sure we only grab irq_tracker entries from the list end and
	 * that we have enough available MSIX vectors
	 */
	if (sriov_base_vector < vectors_used)
		return -EINVAL;

	pf->sriov_base_vector = sriov_base_vector;

	return 0;
}

/**
 * ice_set_per_vf_res - check if vectors and queues are available
 * @pf: pointer to the PF structure
 *
 * First, determine HW interrupts from common pool. If we allocate fewer VFs, we
 * get more vectors and can enable more queues per VF. Note that this does not
 * grab any vectors from the SW pool already allocated. Also note, that all
 * vector counts include one for each VF's miscellaneous interrupt vector
 * (i.e. OICR).
 *
 * Minimum VFs - 2 vectors, 1 queue pair
 * Small VFs - 5 vectors, 4 queue pairs
 * Medium VFs - 17 vectors, 16 queue pairs
 *
 * While more vectors can be assigned to a VF, the RSS LUT
 * is only 4 bits wide, so we can only do 16 queues of RSS
 * per VF.
 *
 * ADQ sizes:
 * Small ADQ VFs - 5 vectors, 4 TCs, 16 queue pairs (4 queue pairs/int)
 * Medium ADQ VFs - 17 vectors, 4 TCs, 16 queue pairs (1 queue pairs/int)
 *
 * Second, determine number of queue pairs per VF by starting with a pre-defined
 * maximum each VF supports. If this is not possible, then we adjust based on
 * queue pairs available on the device.
 *
 * Lastly, set queue and MSI-X VF variables tracked by the PF so it can be used
 * by each VF during VF initialization and reset.
 */
static int ice_set_per_vf_res(struct ice_pf *pf)
{
	int max_valid_res_idx = ice_get_max_valid_res_idx(pf->irq_tracker);
	int msix_avail_per_vf, msix_avail_for_sriov;
	struct device *dev = ice_pf_to_dev(pf);
	u16 num_msix_per_vf, num_txq, num_rxq;

	if (!pf->num_alloc_vfs || max_valid_res_idx < 0)
		return -EINVAL;

	/* determine MSI-X resources per VF */
	msix_avail_for_sriov = pf->hw.func_caps.common_cap.num_msix_vectors -
		pf->irq_tracker->num_entries;
	msix_avail_per_vf = msix_avail_for_sriov / pf->num_alloc_vfs;
	if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_MAX) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_MAX;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_LARGE) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_LARGE;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_MED) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_MED;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_SMALL) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_SMALL;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_MULTIQ_MIN) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_MULTIQ_MIN;
	} else if (msix_avail_per_vf >= ICE_MIN_INTR_PER_VF) {
		num_msix_per_vf = ICE_MIN_INTR_PER_VF;
	} else {
		dev_err(dev, "Only %d MSI-X interrupts available for SR-IOV. Not enough to support minimum of %d MSI-X interrupts per VF for %d VFs\n",
			msix_avail_for_sriov, ICE_MIN_INTR_PER_VF,
			pf->num_alloc_vfs);
		return -EIO;
	}

	/* determine queue resources per VF */
	num_txq = ice_determine_res(pf, ice_get_avail_txq_count(pf),
				    min_t(u16,
					  num_msix_per_vf - ICE_NONQ_VECS_VF,
					  ICE_MAX_DFLT_QS_PER_VF),
				    ICE_MIN_QS_PER_VF);

	num_rxq = ice_determine_res(pf, ice_get_avail_rxq_count(pf),
				    min_t(u16,
					  num_msix_per_vf - ICE_NONQ_VECS_VF,
					  ICE_MAX_DFLT_QS_PER_VF),
				    ICE_MIN_QS_PER_VF);

	if (!num_txq || !num_rxq) {
		dev_err(dev, "Not enough queues to support minimum of %d queue pairs per VF for %d VFs\n",
			ICE_MIN_QS_PER_VF, pf->num_alloc_vfs);
		return -EIO;
	}

	if (ice_sriov_set_msix_res(pf, num_msix_per_vf * pf->num_alloc_vfs)) {
		dev_err(dev, "Unable to set MSI-X resources for %d VFs\n",
			pf->num_alloc_vfs);
		return -EINVAL;
	}

	/* only allow equal Tx/Rx queue count (i.e. queue pairs) */
	pf->num_qps_per_vf = min_t(int, num_txq, num_rxq);
	pf->num_msix_per_vf = num_msix_per_vf;
	dev_info(dev, "Enabling %d VFs with %d vectors and %d queues per VF\n",
		 pf->num_alloc_vfs, pf->num_msix_per_vf, pf->num_qps_per_vf);

	return 0;
}

/**
 * ice_clear_vf_reset_trigger - enable VF to access hardware
 * @vf: VF to enabled hardware access for
 */
static void ice_clear_vf_reset_trigger(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;
	u32 reg;

	reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
	reg &= ~VPGEN_VFRTRIG_VFSWR_M;
	wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);
	ice_flush(hw);
}

static int ice_vf_set_vsi_promisc(struct ice_vf *vf, struct ice_vsi *vsi, u8 promisc_m)
{
	struct ice_hw *hw = &vsi->back->hw;
	u8 lport = vsi->port_info->lport;
	enum ice_status status;

	if (vf->port_vlan_info)
		status = ice_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m,
						  vf->port_vlan_info & VLAN_VID_MASK, lport);
	else if (vsi->num_vlan > 1)
		status = ice_fltr_set_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = ice_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, 0, lport);

	if (status && status != ICE_ERR_ALREADY_EXISTS) {
		dev_err(ice_pf_to_dev(vsi->back), "enable Tx/Rx filter promiscuous mode on VF-%u failed, error: %s\n",
			vf->vf_id, ice_stat_str(status));
		return ice_status_to_errno(status);
	}

	return 0;
}

static int ice_vf_clear_vsi_promisc(struct ice_vf *vf, struct ice_vsi *vsi, u8 promisc_m)
{
	struct ice_hw *hw = &vsi->back->hw;
	u8 lport = vsi->port_info->lport;
	enum ice_status status;

	if (vf->port_vlan_info)
		status = ice_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						    vf->port_vlan_info & VLAN_VID_MASK, lport);
	else if (vsi->num_vlan > 1)
		status = ice_fltr_clear_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = ice_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, 0, lport);

	if (status && status != ICE_ERR_DOES_NOT_EXIST) {
		dev_err(ice_pf_to_dev(vsi->back), "disable Tx/Rx filter promiscuous mode on VF-%u failed, error: %s\n",
			vf->vf_id, ice_stat_str(status));
		return ice_status_to_errno(status);
	}

	return 0;
}

static void ice_vf_clear_counters(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	vf->num_mac = 0;
	vsi->num_vlan = 0;
	memset(&vf->mdd_tx_events, 0, sizeof(vf->mdd_tx_events));
	memset(&vf->mdd_rx_events, 0, sizeof(vf->mdd_rx_events));
}

/**
 * ice_vf_pre_vsi_rebuild - tasks to be done prior to VSI rebuild
 * @vf: VF to perfrom pre VSI rebuild tasks
 *
 * These tasks are items that don't need to be amortized since they are most
 * likely called in a for loop with all VF(s) in the reset_all_vfs() case.
 */
static void ice_vf_pre_vsi_rebuild(struct ice_vf *vf)
{
	/* Remove switch rules associated with the reset VF */
	ice_rm_dcf_sw_vsi_rule(vf->pf, vf->lan_vsi_num);

	if (ice_is_vf_dcf(vf))
		ice_dis_dcf_acl_cap(vf->pf);
	ice_vf_clear_counters(vf);
	ice_clear_vf_reset_trigger(vf);
}

/**
 * ice_vf_rebuild_aggregator_node_cfg - rebuild aggregator node config
 * @vsi: Pointer to VSI
 *
 * This function moves VSI into corresponding scheduler aggregator node
 * based on cached value of "aggregator node info" per VSI
 */
static void ice_vf_rebuild_aggregator_node_cfg(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;

	if (!vsi->agg_node)
		return;

	dev = ice_pf_to_dev(pf);
	if (vsi->agg_node->num_vsis == ICE_MAX_VSIS_IN_AGG_NODE) {
		dev_dbg(dev,
			"agg_id %u already has reached max_num_vsis %u\n",
			vsi->agg_node->agg_id, vsi->agg_node->num_vsis);
		return;
	}

	status = ice_move_vsi_to_agg(pf->hw.port_info, vsi->agg_node->agg_id,
				     vsi->idx, (u8)vsi->tc_cfg.ena_tc);
	if (status)
		dev_dbg(dev, "unable to move VSI idx %u into aggregator %u node",
			vsi->idx, vsi->agg_node->agg_id);
	else
		vsi->agg_node->num_vsis++;
}

/**
 * ice_vf_rebuild_host_cfg - host admin configuration is persistent across reset
 * @vf: VF to rebuild host configuration on
 */
static void ice_vf_rebuild_host_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	ice_vf_set_host_trust_cfg(vf);

	if (ice_vf_rebuild_host_mac_cfg(vf))
		dev_err(dev, "failed to rebuild default MAC configuration for VF %d\n",
			vf->vf_id);

	if (ice_vf_rebuild_host_vlan_cfg(vf, vsi))
		dev_err(dev, "failed to rebuild VLAN configuration for VF %u\n",
			vf->vf_id);

	if (ice_vf_rebuild_host_tx_rate_cfg(vf))
		dev_err(dev, "failed to rebuild Tx rate limiting configuration for VF %u\n",
			vf->vf_id);

	/* rebuild aggregator node config for main VF VSI */
	ice_vf_rebuild_aggregator_node_cfg(vsi);
}

/**
 * ice_vf_rebuild_adq_aggregator_node - move ADQ VSIs into aggregator node
 * @vf: VF to rebuild ADQ VSI(s) Tx rate configuration on
 *
 * If VF ADQ is enabled, replay scheduler aggregator node config
 */
static void ice_vf_rebuild_adq_aggregator_node(struct ice_vf *vf)
{
	int tc;

	if (!ice_is_vf_adq_ena(vf))
		return;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;
		vsi = ice_get_vf_adq_vsi(vf, tc);
		ice_vf_rebuild_aggregator_node_cfg(vsi);
	}
}

/**
 * ice_vf_rebuild_adq_tx_rate_cfg - rebuild ADQ VSI(s) Tx rate configuration
 * @vf: VF to rebuild ADQ VSI(s) Tx rate configuration on
 */
static void ice_vf_rebuild_adq_tx_rate_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi;
	u64 max_tx_rate;
	u8 tc;

	if (!ice_is_vf_adq_ena(vf))
		return;

	/* Host may have set Tx rate for VF, but use the TC0's specified
	 * max Tx rate for main VF VSI.
	 * Iterate thru' all VSI (hence for loop starts with zero) shared by
	 * given VF and set the BW limit if specified as part of
	 * VF ADQ TC config
	 */
	for (tc = 0; tc < vf->num_tc; tc++) {
		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		/* TODO: Determine if it's correct for the host/admin
		 * configuration to have priority over VF ADQ Tx rate limiting.
		 */
		max_tx_rate = vf->ch[tc].max_tx_rate;
		if (!max_tx_rate)
			continue;

		if (!tc && vf->max_tx_rate)
			dev_dbg(dev, "Host managed VF rate limit %u for VF %d are being changed to %llu\n",
				vf->max_tx_rate, vf->vf_id, max_tx_rate);

		vsi = ice_get_vf_adq_vsi(vf, tc);
		if (ice_set_max_bw_limit(vsi, max_tx_rate * 1000))
			dev_err(dev, "Unable to set Tx rate %llu in Mbps for VF %u TC %d\n",
				max_tx_rate, vf->vf_id, tc);
	}
}

/**
 * ice_vf_rebuild_adq_vsi_with_release - release and setup each ADQ VSI
 * @vf: VF to re-apply ADQ configuration for
 *
 * This is only called when a single VF is being reset (i.e. VFR, VFLR, host VF
 * configuration change, etc.).
 *
 * This cannot be called for the reset all VFs case as ice_vf_adq_vsi_release()
 * will fail because there are no VF VSI(s) in firmware at this point.
 */
static int ice_vf_rebuild_adq_vsi_with_release(struct ice_vf *vf)
{
	u8 tc;

	if (!ice_is_vf_adq_ena(vf))
		return 0;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (ice_vf_adq_vsi_valid(vf, tc)) {
			ice_vf_adq_vsi_stop_rings(vf, tc);
			ice_vf_adq_vsi_disable_txqs(vf, tc);
			ice_vf_adq_vsi_release(vf, tc);
		}

		if (!ice_vf_adq_vsi_setup(vf, tc)) {
			dev_err(ice_pf_to_dev(vf->pf), "failed to setup ADQ VSI for VF %u, TC %d, disabling VF ADQ VSI\n",
				vf->vf_id, tc);
			goto adq_cfg_failed;
		}
	}

	/* must to store away TC0's info because it is used later */
	vf->ch[0].vsi_idx = vf->lan_vsi_idx;
	vf->ch[0].vsi_num = vf->lan_vsi_num;

	return 0;

adq_cfg_failed:
	/* perform VSI release for ADQ VSI if some of them were
	 * created successfully.
	 */
	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (ice_vf_adq_vsi_valid(vf, tc)) {
			ice_vf_adq_vsi_disable_txqs(vf, tc);
			ice_vf_adq_vsi_release(vf, tc);
		}
		ice_vf_adq_cfg_cleanup(vf, tc);
	}
	vf->adq_enabled = false;
	vf->num_tc = 0;
	/* Upon failure also clean up tc=0 specific info from
	 * software data structs, to avoid having stale info
	 */
	ice_vf_adq_invalidate_vsi(vf, 0);
	ice_vf_adq_cfg_cleanup(vf, 0);
	return -ENOMEM;
}

/**
 * ice_vf_rebuild_adq_vsi - rebuild ADQ VSI(s) on the VF
 * @vf: VF to rebuild ADQ VSI(s) on
 */
static int ice_vf_rebuild_adq_vsi(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	int tc;

	/* no ADQ configured, nothing to do */
	if (!ice_is_vf_adq_ena(vf))
		return 0;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;
		int ret;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		vsi = ice_get_vf_adq_vsi(vf, tc);
		ret = ice_vsi_rebuild(vsi, true);
		if (ret) {
			dev_err(ice_pf_to_dev(pf), "failed to rebuild ADQ VSI for VF %u, disabling VF ADQ VSI\n",
				vf->vf_id);
			vf->adq_enabled = false;
			ice_vf_adq_invalidate_vsi(vf, tc);
			return ret;
		}

		vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);
		vf->ch[tc].vsi_num = vsi->vsi_num;
		vf->ch[tc].vsi_idx = vsi->idx;
	}

	/* must to store away TC0's info because it is use later */
	vf->ch[0].vsi_idx = vf->lan_vsi_idx;
	vf->ch[0].vsi_num = vf->lan_vsi_num;

	return 0;
}

/**
 * ice_vf_rebuild_vsi_with_release - release and setup the VF's VSI
 * @vf: VF to release and setup the VSI for
 *
 * This is only called when a single VF is being reset (i.e. VFR, VFLR, host VF
 * configuration change, etc.).
 */
static int ice_vf_rebuild_vsi_with_release(struct ice_vf *vf)
{
	ice_vf_vsi_release(vf);
	if (!ice_vf_vsi_setup(vf))
		return -ENOMEM;

	ice_vf_rebuild_adq_vsi_with_release(vf);

	return 0;
}

/**
 * ice_vf_rebuild_vsi - rebuild the VF's VSI
 * @vf: VF to rebuild the VSI for
 *
 * This is only called when all VF(s) are being reset (i.e. PCIe Reset on the
 * host, PFR, CORER, etc.).
 */
static int ice_vf_rebuild_vsi(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_pf *pf = vf->pf;

	if (ice_vsi_rebuild(vsi, true)) {
		dev_err(ice_pf_to_dev(pf), "failed to rebuild VF %d VSI\n",
			vf->vf_id);
		return -EIO;
	}
	/* vsi->idx will remain the same in this case so don't update
	 * vf->lan_vsi_idx
	 */
	vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);
	vf->lan_vsi_num = vsi->vsi_num;

	if (ice_vf_rebuild_adq_vsi(vf)) {
		dev_err(ice_pf_to_dev(pf), "failed to rebuild ADQ configuration for VF %d\n",
			vf->vf_id);
		return -EIO;
	}

	return 0;
}

/**
 * ice_vf_set_initialized - VF is ready for VIRTCHNL communication
 * @vf: VF to set in initialized state
 *
 * After this function the VF will be ready to receive/handle the
 * VIRTCHNL_OP_GET_VF_RESOURCES message
 */
static void ice_vf_set_initialized(struct ice_vf *vf)
{
	ice_set_vf_state_qs_dis(vf);
	clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_DIS, vf->vf_states);
	set_bit(ICE_VF_STATE_INIT, vf->vf_states);
}

/**
 * ice_vf_post_vsi_rebuild - tasks to do after the VF's VSI have been rebuilt
 * @vf: VF to perform tasks on
 */
static void ice_vf_post_vsi_rebuild(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_hw *hw;

	hw = &pf->hw;

	ice_vf_rebuild_host_cfg(vf);

	ice_vf_rebuild_adq_aggregator_node(vf);
	ice_vf_rebuild_adq_tx_rate_cfg(vf);
	if (ice_vf_rebuild_adq_port_vlan_cfg(vf))
		dev_err(ice_pf_to_dev(pf), "failed to rebuild port VLAN configuration for ADQ enabled VF %u\n",
			vf->vf_id);

	ice_vf_set_initialized(vf);
	ice_ena_vf_mappings(vf);
	wr32(hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
}

/**
 * ice_reset_all_vfs - reset all allocated VFs in one go
 * @pf: pointer to the PF structure
 * @is_vflr: true if VFLR was issued, false if not
 *
 * First, tell the hardware to reset each VF, then do all the waiting in one
 * chunk, and finally finish restoring each VF after the wait. This is useful
 * during PF routines which need to reset all VFs, as otherwise it must perform
 * these resets in a serialized fashion.
 *
 * Returns true if any VFs were reset, and false otherwise.
 */
bool ice_reset_all_vfs(struct ice_pf *pf, bool is_vflr)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	int v, i;

	/* If we don't have any VFs, then there is nothing to reset */
	if (!pf->num_alloc_vfs)
		return false;

	/* clear all malicious info if the VFs are getting reset */
	ice_for_each_vf(pf, i)
		if (ice_mbx_clear_malvf(&hw->mbx_snapshot, pf->malvfs, ICE_MAX_VF_COUNT, i))
			dev_dbg(dev, "failed to clear malicious VF state for VF %u\n", i);

	/* If VFs have been disabled, there is no need to reset */
	if (test_and_set_bit(ICE_VF_DIS, pf->state))
		return false;

	ice_dis_dcf_acl_cap(pf);

	/* Begin reset on all VFs at once */
	ice_for_each_vf(pf, v)
		ice_trigger_vf_reset(&pf->vf[v], is_vflr, true);

	/* HW requires some time to make sure it can flush the FIFO for a VF
	 * when it resets it. Poll the VPGEN_VFRSTAT register for each VF in
	 * sequence to make sure that it has completed. We'll keep track of
	 * the VFs using a simple iterator that increments once that VF has
	 * finished resetting.
	 */
	for (i = 0, v = 0; i < 10 && v < pf->num_alloc_vfs; i++) {
		/* Check each VF in sequence */
		while (v < pf->num_alloc_vfs) {
			u32 reg;

			vf = &pf->vf[v];
			reg = rd32(hw, VPGEN_VFRSTAT(vf->vf_id));
			if (!(reg & VPGEN_VFRSTAT_VFRD_M)) {
				/* only delay if the check failed */
				usleep_range(10, 20);
				break;
			}

			/* If the current VF has finished resetting, move on
			 * to the next VF in sequence.
			 */
			v++;
		}
	}


	/* Display a warning if at least one VF didn't manage to reset in
	 * time, but continue on with the operation.
	 */
	if (v < pf->num_alloc_vfs)
		dev_warn(dev, "VF reset check timeout\n");


	/* free VF resources to begin resetting the VSI state */
	ice_for_each_vf(pf, v) {
		vf = &pf->vf[v];

		vf->driver_caps = 0;
		ice_vc_set_default_allowlist(vf);

#ifdef HAVE_TC_SETUP_CLSFLOWER
		/* always release VF ADQ filters since those filters will be
		 * replayed by VF driver. This is needed to avoid stale
		 * filters in software internal data structues
		 */
		ice_del_all_adv_switch_fltr(vf);
#endif

		ice_vf_fdir_exit(vf);
		ice_vf_fdir_init(vf);
		/* clean VF control VSI when resetting VFs since it should be
		 * setup only when iAVF creates its first FDIR rule.
		 */
		if (vf->ctrl_vsi_idx != ICE_NO_VSI)
			ice_vf_ctrl_invalidate_vsi(vf);

		ice_vf_pre_vsi_rebuild(vf);
		ice_vf_rebuild_vsi(vf);
		ice_vf_post_vsi_rebuild(vf);
	}

	ice_flush(hw);
	clear_bit(ICE_VF_DIS, pf->state);

	return true;
}

/**
 * ice_is_vf_disabled
 * @vf: pointer to the VF info
 *
 * Returns true if the PF or VF is disabled, false otherwise.
 */
static bool ice_is_vf_disabled(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	/* If the PF has been disabled, there is no need resetting VF until
	 * PF is active again. Similarly, if the VF has been disabled, this
	 * means something else is resetting the VF, so we shouldn't continue.
	 * Otherwise, set disable VF state bit for actual reset, and continue.
	 */
	return (test_bit(ICE_VF_DIS, pf->state) ||
		test_bit(ICE_VF_STATE_DIS, vf->vf_states));
}

/**
 * ice_reset_vf - Reset a particular VF
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 *
 * Returns true if the VF is currently in reset, resets successfully, or resets
 * are disabled and false otherwise.
 */
bool ice_reset_vf(struct ice_vf *vf, bool is_vflr)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	bool rsd = false;
	u8 promisc_m;
	u32 reg;
	int i;

	dev = ice_pf_to_dev(pf);

	if (test_bit(ICE_VF_RESETS_DISABLED, pf->state)) {
		dev_dbg(dev, "Trying to reset VF %d, but all VF resets are disabled\n",
			vf->vf_id);
		return true;
	}

	if (ice_is_vf_disabled(vf)) {
		dev_dbg(dev, "VF is already disabled, there is no need for resetting it, telling VM, all is fine %d\n",
			vf->vf_id);
		return true;
	}

	/* Set VF disable bit state here, before triggering reset */
	set_bit(ICE_VF_STATE_DIS, vf->vf_states);
	ice_trigger_vf_reset(vf, is_vflr, false);

	if (ice_dcf_get_state(pf) == ICE_DCF_STATE_ON)
		ice_dcf_set_state(pf, ICE_DCF_STATE_BUSY);

	vsi = ice_get_vf_vsi(vf);

	if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
		ice_dis_vf_qs(vf);

	/* Call Disable LAN Tx queue AQ whether or not queues are
	 * enabled. This is needed for successful completion of VFR.
	 */
	ice_dis_vsi_txq(vsi->port_info, vsi->idx, 0, 0, NULL, NULL,
			NULL, ICE_VF_RESET, vf->vf_id, NULL);
	/* Likewise Disable LAN Tx queues for VF ADQ VSIs */
	if (ice_is_vf_adq_ena(vf)) {
		int tc;

		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			if (!ice_vf_adq_vsi_valid(vf, tc))
				continue;
			ice_dis_vsi_txq(vsi->port_info, vf->ch[tc].vsi_idx, 0,
					0, NULL, NULL, NULL, ICE_VF_RESET,
					vf->vf_id, NULL);
		}
	}

	hw = &pf->hw;
	/* poll VPGEN_VFRSTAT reg to make sure
	 * that reset is complete
	 */
	for (i = 0; i < 10; i++) {
		/* VF reset requires driver to first reset the VF and then
		 * poll the status register to make sure that the reset
		 * completed successfully.
		 */
		reg = rd32(hw, VPGEN_VFRSTAT(vf->vf_id));
		if (reg & VPGEN_VFRSTAT_VFRD_M) {
			rsd = true;
			break;
		}

		/* only sleep if the reset is not done */
		usleep_range(10, 20);
	}

	vf->driver_caps = 0;
	ice_vc_set_default_allowlist(vf);

	/* Display a warning if VF didn't manage to reset in time, but need to
	 * continue on with the operation.
	 */
	if (!rsd)
		dev_warn(dev, "VF reset check timeout on VF %d\n", vf->vf_id);

	/* disable promiscuous modes in case they were enabled
	 * ignore any error if disabling process failed
	 */
	if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	    test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) {
		if (vf->port_vlan_info || vsi->num_vlan)
			promisc_m = ICE_UCAST_VLAN_PROMISC_BITS;
		else
			promisc_m = ICE_UCAST_PROMISC_BITS;

		vsi = ice_get_vf_vsi(vf);
		if (ice_vf_clear_vsi_promisc(vf, vsi, promisc_m))
			dev_err(dev, "disabling promiscuous mode failed\n");
	}

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* always release VF ADQ filters since those filters will be
	 * replayed by VF driver. This is needed to avoid stale filters in
	 * software internal data structures
	 */
	ice_del_all_adv_switch_fltr(vf);
#endif
	/* VF driver gets reloaded on VFLR, so clear ADQ configuration */
	if (is_vflr)
		ice_vf_adq_release(vf);


	ice_vf_fdir_exit(vf);
	ice_vf_fdir_init(vf);
	/* clean VF control VSI when resetting VF since it should be setup
	 * only when iAVF creates its first FDIR rule.
	 */
	if (vf->ctrl_vsi_idx != ICE_NO_VSI)
		ice_vf_ctrl_vsi_release(vf);

	ice_vf_pre_vsi_rebuild(vf);

	ice_vf_rebuild_vsi_with_release(vf);
	ice_vf_post_vsi_rebuild(vf);

	if (ice_dcf_get_state(pf) == ICE_DCF_STATE_BUSY) {
		struct virtchnl_pf_event pfe = { 0 };

		ice_dcf_set_state(pf, ICE_DCF_STATE_PAUSE);

		pfe.event = VIRTCHNL_EVENT_DCF_VSI_MAP_UPDATE;
		pfe.event_data.vf_vsi_map.vf_id = vf->vf_id;
		pfe.event_data.vf_vsi_map.vsi_id = vf->lan_vsi_num;

		ice_aq_send_msg_to_vf(&pf->hw, ICE_DCF_VFID,
				      VIRTCHNL_OP_EVENT,
				      VIRTCHNL_STATUS_SUCCESS,
				      (u8 *)&pfe, sizeof(pfe), NULL);
	}

	/* if the VF has been reset allow it to come up again */
	if (ice_mbx_clear_malvf(&hw->mbx_snapshot, pf->malvfs, ICE_MAX_VF_COUNT, vf->vf_id))
		dev_dbg(dev, "failed to clear malicious VF state for VF %u\n", i);

	return true;
}

/**
 * ice_vc_notify_link_state - Inform all VFs on a PF of link status
 * @pf: pointer to the PF structure
 */
void ice_vc_notify_link_state(struct ice_pf *pf)
{
	int i;

	ice_for_each_vf(pf, i)
		ice_vc_notify_vf_link_state(&pf->vf[i]);
}

/**
 * ice_vc_notify_reset - Send pending reset message to all VFs
 * @pf: pointer to the PF structure
 *
 * indicate a pending reset to all VFs on a given PF
 */
void ice_vc_notify_reset(struct ice_pf *pf)
{
	struct virtchnl_pf_event pfe;

	if (!pf->num_alloc_vfs)
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_vc_vf_broadcast(pf, VIRTCHNL_OP_EVENT, VIRTCHNL_STATUS_SUCCESS,
			    (u8 *)&pfe, sizeof(struct virtchnl_pf_event));
}

/**
 * ice_vc_notify_vf_reset - Notify VF of a reset event
 * @vf: pointer to the VF structure
 */
static void ice_vc_notify_vf_reset(struct ice_vf *vf)
{
	struct virtchnl_pf_event pfe;
	struct ice_pf *pf;

	if (!vf)
		return;

	pf = vf->pf;
	if (ice_validate_vf_id(pf, vf->vf_id))
		return;

	/* Bail out if VF is in disabled state, neither initialized, nor active
	 * state - otherwise proceed with notifications
	 */
	if ((!test_bit(ICE_VF_STATE_INIT, vf->vf_states) &&
	     !test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) ||
	    test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_aq_send_msg_to_vf(&pf->hw, vf->vf_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe),
			      NULL);
}


/**
 * ice_init_vf_vsi_res - initialize/setup VF VSI resources
 * @vf: VF to initialize/setup the VSI for
 *
 * This function creates a VSI for the VF, adds a VLAN 0 filter, and sets up the
 * VF VSI's broadcast filter and is only used during initial VF creation.
 */
static int ice_init_vf_vsi_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	u8 broadcast[ETH_ALEN];
	enum ice_status status;
	struct ice_vsi *vsi;
	struct device *dev;
	int err;

	vf->first_vector_idx = ice_calc_vf_first_vector_idx(pf, vf);

	dev = ice_pf_to_dev(pf);
	vsi = ice_vf_vsi_setup(vf);
	if (!vsi)
		return -ENOMEM;

	err = vsi->vlan_ops.add_vlan(vsi, ICE_VLAN(ETH_P_8021Q, 0, 0, ICE_FWD_TO_VSI));
	if (err) {
		dev_warn(dev, "Failed to add VLAN 0 filter for VF %d\n",
			 vf->vf_id);
		goto release_vsi;
	}

	eth_broadcast_addr(broadcast);
	status = ice_fltr_add_mac(vsi, broadcast, ICE_FWD_TO_VSI);
	if (status) {
		dev_err(dev, "Failed to add broadcast MAC filter for VF %d, status %s\n",
			vf->vf_id, ice_stat_str(status));
		err = ice_status_to_errno(status);
		goto release_vsi;
	}

	vf->num_mac = 1;

	return 0;

release_vsi:
	ice_vf_vsi_release(vf);
	return err;
}

/**
 * ice_start_vfs - start VFs so they are ready to be used by SR-IOV
 * @pf: PF the VFs are associated with
 */
static int ice_start_vfs(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	int retval, i;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		ice_clear_vf_reset_trigger(vf);

		retval = ice_init_vf_vsi_res(vf);
		if (retval) {
			dev_err(ice_pf_to_dev(pf), "Failed to initialize VSI resources for VF %d, error %d\n",
				vf->vf_id, retval);
			goto teardown;
		}

		set_bit(ICE_VF_STATE_INIT, vf->vf_states);
		ice_ena_vf_mappings(vf);
		wr32(hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
	}

	ice_flush(hw);
	return 0;

teardown:
	for (i = i - 1; i >= 0; i--) {
		struct ice_vf *vf = &pf->vf[i];

		ice_dis_vf_mappings(vf);
		ice_vf_vsi_release(vf);
	}

	return retval;
}

static void
ice_vf_hash_ctx_init(struct ice_vf *vf)
{
	memset(&vf->hash_ctx, 0, sizeof(vf->hash_ctx));
}

/**
 * ice_set_dflt_settings - set VF defaults during initialization/creation
 * @pf: PF holding reference to all VFs for default configuration
 */
static void ice_set_dflt_settings_vfs(struct ice_pf *pf)
{
	int i;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		vf->pf = pf;
		vf->vf_id = i;
		vf->vf_sw_id = pf->first_sw;
		/* assign default capabilities */
		set_bit(ICE_VIRTCHNL_VF_CAP_L2, &vf->vf_caps);
		vf->spoofchk = true;
		vf->num_vf_qs = pf->num_qps_per_vf;
		ice_vc_set_default_allowlist(vf);

		/* ctrl_vsi_idx will be set to a valid value only when iAVF
		 * creates its first fdir rule.
		 */
		ice_vf_ctrl_invalidate_vsi(vf);
		ice_vf_fdir_init(vf);

		ice_vf_hash_ctx_init(vf);
	}
}

/**
 * ice_alloc_vfs - allocate num_vfs in the PF structure
 * @pf: PF to store the allocated VFs in
 * @num_vfs: number of VFs to allocate
 */
static int ice_alloc_vfs(struct ice_pf *pf, int num_vfs)
{
	struct ice_vf *vfs;

	vfs = devm_kcalloc(ice_pf_to_dev(pf), num_vfs, sizeof(*vfs),
			   GFP_KERNEL);
	if (!vfs)
		return -ENOMEM;

	pf->vf = vfs;
	pf->num_alloc_vfs = num_vfs;

	return 0;
}

/**
 * ice_ena_vfs - enable VFs so they are ready to be used
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to enable
 */
static int ice_ena_vfs(struct ice_pf *pf, u16 num_vfs)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int ret;

	/* Disable global interrupt 0 so we don't try to handle the VFLR. */
	wr32(hw, GLINT_DYN_CTL(pf->oicr_idx),
	     ICE_ITR_NONE << GLINT_DYN_CTL_ITR_INDX_S);
	set_bit(ICE_OICR_INTR_DIS, pf->state);
	ice_flush(hw);

	ret = pci_enable_sriov(pf->pdev, num_vfs);
	if (ret) {
		pf->num_alloc_vfs = 0;
		goto err_unroll_intr;
	}

	ret = ice_alloc_vfs(pf, num_vfs);
	if (ret)
		goto err_pci_disable_sriov;

	ice_dcf_init_sw_rule_mgmt(pf);

	if (ice_set_per_vf_res(pf)) {
		dev_err(dev, "Not enough resources for %d VFs, try with fewer number of VFs\n",
			num_vfs);
		ret = -ENOSPC;
		goto err_unroll_sriov;
	}

	ice_set_dflt_settings_vfs(pf);

	if (ice_start_vfs(pf)) {
		dev_err(dev, "Failed to start VF(s)\n");
		ret = -EAGAIN;
		goto err_unroll_sriov;
	}

	clear_bit(ICE_VF_DIS, pf->state);
	return 0;

err_unroll_sriov:
	devm_kfree(dev, pf->vf);
	pf->vf = NULL;
	pf->num_alloc_vfs = 0;
err_pci_disable_sriov:
	pci_disable_sriov(pf->pdev);
err_unroll_intr:
	/* rearm interrupts here */
	ice_irq_dynamic_ena(hw, NULL, NULL);
	clear_bit(ICE_OICR_INTR_DIS, pf->state);
	return ret;
}

/**
 * ice_pci_sriov_ena - Enable or change number of VFs
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to allocate
 *
 * Returns 0 on success and negative on failure
 */
static int ice_pci_sriov_ena(struct ice_pf *pf, int num_vfs)
{
	int pre_existing_vfs = pci_num_vf(pf->pdev);
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	if (pre_existing_vfs && pre_existing_vfs != num_vfs)
		ice_free_vfs(pf);
	else if (pre_existing_vfs && pre_existing_vfs == num_vfs)
		return 0;

	if (num_vfs > pf->num_vfs_supported) {
		dev_err(dev, "Can't enable %d VFs, max VFs supported is %d\n",
			num_vfs, pf->num_vfs_supported);
		return -EOPNOTSUPP;
	}

	dev_info(dev, "Enabling %d VFs\n", num_vfs);
	err = ice_ena_vfs(pf, num_vfs);
	if (err) {
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	set_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
	return 0;
}


/**
 * ice_check_sriov_allowed - check if SR-IOV is allowed based on various checks
 * @pf: PF to enabled SR-IOV on
 */
static int ice_check_sriov_allowed(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(ICE_RECOVERY_MODE, pf->state)) {
		dev_err(dev, "SR-IOV cannot be configured - Device is in Recovery Mode\n");
		return -EOPNOTSUPP;
	}

	if (ice_is_safe_mode(pf)) {
		dev_err(dev, "SR-IOV cannot be configured - Device is in Safe Mode\n");
		return -EOPNOTSUPP;
	}

	if (!ice_pf_state_is_nominal(pf)) {
		dev_err(dev, "Cannot enable SR-IOV, device not ready\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * ice_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate or 0 to free VFs
 *
 * This function is called when the user updates the number of VFs in sysfs. On
 * success return whatever num_vfs was set to by the caller. Return negative on
 * failure.
 */
int ice_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	int err;

	err = ice_check_sriov_allowed(pf);
	if (err)
		return err;

	if (!num_vfs) {
		if (!pci_vfs_assigned(pdev)) {
			ice_mbx_deinit_snapshot(&pf->hw);
			ice_free_vfs(pf);
#ifdef HAVE_NETDEV_UPPER_INFO
			if (pf->lag)
				ice_enable_lag(pf->lag);
#endif /* HAVE_NETDEV_UPPER_INFO */
			return 0;
		}

		dev_err(dev, "can't free VFs because some are assigned to VMs.\n");
		return -EBUSY;
	}

	status = ice_mbx_init_snapshot(&pf->hw, num_vfs);
	if (status)
		return ice_status_to_errno(status);

	err = ice_pci_sriov_ena(pf, num_vfs);
	if (err) {
		ice_mbx_deinit_snapshot(&pf->hw);
		return err;
	}

#ifdef HAVE_NETDEV_UPPER_INFO
	if (pf->lag)
		ice_disable_lag(pf->lag);
#endif /* HAVE_NETDEV_UPPER_INFO */
	return num_vfs;
}

/**
 * ice_process_vflr_event - Free VF resources via IRQ calls
 * @pf: pointer to the PF structure
 *
 * called from the VFLR IRQ handler to
 * free up VF resources and state variables
 */
void ice_process_vflr_event(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	unsigned int vf_id;
	u32 reg;

	if (!test_and_clear_bit(ICE_VFLR_EVENT_PENDING, pf->state) ||
	    !pf->num_alloc_vfs)
		return;

	ice_for_each_vf(pf, vf_id) {
		struct ice_vf *vf = &pf->vf[vf_id];
		u32 reg_idx, bit_idx;

		reg_idx = (hw->func_caps.vf_base_id + vf_id) / 32;
		bit_idx = (hw->func_caps.vf_base_id + vf_id) % 32;
		/* read GLGEN_VFLRSTAT register to find out the flr VFs */
		reg = rd32(hw, GLGEN_VFLRSTAT(reg_idx));
		if (reg & BIT(bit_idx))
			/* GLGEN_VFLRSTAT bit will be cleared in ice_reset_vf */
			ice_reset_vf(vf, true);
	}
}

/**
 * ice_vc_reset_vf - Perform software reset on the VF after informing the AVF
 * @vf: pointer to the VF info
 */
static void ice_vc_reset_vf(struct ice_vf *vf)
{
	ice_vc_notify_vf_reset(vf);
	ice_reset_vf(vf, false);
}

/**
 * ice_get_vf_from_pfq - get the VF who owns the PF space queue passed in
 * @pf: PF used to index all VFs
 * @pfq: queue index relative to the PF's function space
 *
 * If no VF is found who owns the pfq then return NULL, otherwise return a
 * pointer to the VF who owns the pfq
 */
static struct ice_vf *ice_get_vf_from_pfq(struct ice_pf *pf, u16 pfq)
{
	unsigned int vf_id;

	ice_for_each_vf(pf, vf_id) {
		struct ice_vf *vf = &pf->vf[vf_id];
		struct ice_vsi *vsi;
		u16 rxq_idx;

		vsi = ice_get_vf_vsi(vf);

		ice_for_each_rxq(vsi, rxq_idx)
			if (vsi->rxq_map[rxq_idx] == pfq)
				return vf;
	}

	return NULL;
}

/**
 * ice_globalq_to_pfq - convert from global queue index to PF space queue index
 * @pf: PF used for conversion
 * @globalq: global queue index used to convert to PF space queue index
 */
static u32 ice_globalq_to_pfq(struct ice_pf *pf, u32 globalq)
{
	return globalq - pf->hw.func_caps.common_cap.rxq_first_id;
}

/**
 * ice_vf_lan_overflow_event - handle LAN overflow event for a VF
 * @pf: PF that the LAN overflow event happened on
 * @event: structure holding the event information for the LAN overflow event
 *
 * Determine if the LAN overflow event was caused by a VF queue. If it was not
 * caused by a VF, do nothing. If a VF caused this LAN overflow event trigger a
 * reset on the offending VF.
 */
void
ice_vf_lan_overflow_event(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	u32 gldcb_rtctq, queue;
	struct ice_vf *vf;

	gldcb_rtctq = le32_to_cpu(event->desc.params.lan_overflow.prtdcb_ruptq);
	dev_dbg(ice_pf_to_dev(pf), "GLDCB_RTCTQ: 0x%08x\n", gldcb_rtctq);

	/* event returns device global Rx queue number */
	queue = (gldcb_rtctq & GLDCB_RTCTQ_RXQNUM_M) >>
		GLDCB_RTCTQ_RXQNUM_S;

	vf = ice_get_vf_from_pfq(pf, ice_globalq_to_pfq(pf, queue));
	if (!vf)
		return;

	ice_vc_reset_vf(vf);
}

/**
 * ice_vc_send_msg_to_vf - Send message to VF
 * @vf: pointer to the VF info
 * @v_opcode: virtual channel opcode
 * @v_retval: virtual channel return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * send msg to VF
 */
int
ice_vc_send_msg_to_vf(struct ice_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	enum ice_status aq_ret;
	struct device *dev;
	struct ice_pf *pf;

	if (!vf)
		return -EINVAL;

	pf = vf->pf;
	if (ice_validate_vf_id(pf, vf->vf_id))
		return -EINVAL;

	dev = ice_pf_to_dev(pf);

	/* single place to detect unsuccessful return values */
	if (v_retval) {
		vf->num_inval_msgs++;
		dev_info(dev, "VF %d failed opcode %d, retval: %d\n", vf->vf_id,
			 v_opcode, v_retval);
		if (vf->num_inval_msgs > ICE_DFLT_NUM_INVAL_MSGS_ALLOWED) {
			dev_err(dev, "Number of invalid messages exceeded for VF %d\n",
				vf->vf_id);
			dev_err(dev, "Use PF Control I/F to enable the VF\n");
			set_bit(ICE_VF_STATE_DIS, vf->vf_states);
			return -EIO;
		}
	} else {
		vf->num_valid_msgs++;
		/* reset the invalid counter, if a valid message is received. */
		vf->num_inval_msgs = 0;
	}

	aq_ret = ice_aq_send_msg_to_vf(&pf->hw, vf->vf_id, v_opcode, v_retval,
				       msg, msglen, NULL);
	if (aq_ret && pf->hw.mailboxq.sq_last_status != ICE_AQ_RC_ENOSYS) {
		dev_info(dev, "Unable to send the message to VF %d ret %s aq_err %s\n",
			 vf->vf_id, ice_stat_str(aq_ret),
			 ice_aq_str(pf->hw.mailboxq.sq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * ice_vc_get_ver_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request the API version used by the PF
 */
static int ice_vc_get_ver_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_version_info info = {
		VIRTCHNL_VERSION_MAJOR, VIRTCHNL_VERSION_MINOR
	};

	vf->vf_ver = *(struct virtchnl_version_info *)msg;
	/* VFs running the 1.0 API expect to get 1.0 back or they will cry. */
	if (VF_IS_V10(&vf->vf_ver))
		info.minor = VIRTCHNL_VERSION_MINOR_NO_VF_CAPS;

	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_VERSION,
				     VIRTCHNL_STATUS_SUCCESS, (u8 *)&info,
				     sizeof(struct virtchnl_version_info));
}

/**
 * ice_vc_get_max_frame_size - get max frame size allowed for VF
 * @vf: VF used to determine max frame size
 *
 * Max frame size is determined based on the current port's max frame size and
 * whether a port VLAN is configured on this VF. The VF is not aware whether
 * it's in a port VLAN so the PF needs to account for this in max frame size
 * checks and sending the max frame size to the VF.
 */
static u16 ice_vc_get_max_frame_size(struct ice_vf *vf)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	u16 max_frame_size;

	max_frame_size = pi->phy.link_info.max_frame_size;

	if (vf->port_vlan_info)
		max_frame_size -= VLAN_HLEN;

	return max_frame_size;
}

/**
 * ice_vc_get_vf_res_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request its resources
 */
static int ice_vc_get_vf_res_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vf_resource *vfres = NULL;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	int len = 0;
	int ret;

	if (ice_check_vf_init(pf, vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_vf_resource);

	vfres = kzalloc(len, GFP_KERNEL);
	if (!vfres) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}
	if (VF_IS_V11(&vf->vf_ver))
		vf->driver_caps = *(u32 *)msg;
	else
		vf->driver_caps = VIRTCHNL_VF_OFFLOAD_L2 |
				  VIRTCHNL_VF_OFFLOAD_RSS_REG |
				  VIRTCHNL_VF_OFFLOAD_VLAN;

	vfres->vf_cap_flags = VIRTCHNL_VF_OFFLOAD_L2;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!vsi->info.pvid)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_VLAN;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PF) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PF;
	} else {
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_AQ)
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_AQ;
		else
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_REG;
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_FDIR_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_FDIR_PF;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_POLLING)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_POLLING;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_WB_ON_ITR;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_REQ_QUEUES)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_REQ_QUEUES;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_ADV_LINK_SPEED;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF;
#ifdef __TC_MQPRIO_MODE_MAX
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ;
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ_V2;
#endif /* __TC_MQPRIO_MODE_MAX */

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_USO)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_USO;

	if (vf->driver_caps & VIRTCHNL_VF_LARGE_NUM_QPAIRS)
		vfres->vf_cap_flags |= VIRTCHNL_VF_LARGE_NUM_QPAIRS;

	/* Negotiate DCF capability. */
	if (vf->driver_caps & VIRTCHNL_VF_CAP_DCF) {
		if (!ice_check_dcf_allowed(vf)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_DCF;
		pf->dcf.vf = vf;
		ice_dcf_set_state(pf, ICE_DCF_STATE_ON);
		dev_info(ice_pf_to_dev(pf), "Grant request for DCF functionality to VF%d\n",
			 ICE_DCF_VFID);
		if (ice_is_acl_empty(&pf->hw)) {
			ice_acl_destroy_tbl(&pf->hw);
			pf->hw.dcf_acl_enabled = true;
		} else {
			dev_info(ice_pf_to_dev(pf), "Failed to grant ACL capability to VF%d as ACL rules already exist\n",
				 ICE_DCF_VFID);
			pf->hw.dcf_acl_enabled = false;
		}
	} else if (ice_is_vf_dcf(vf) &&
		   ice_dcf_get_state(pf) != ICE_DCF_STATE_OFF) {
		/* If a designated DCF requests AVF functionality from the
		 * same VF without the DCF gracefully relinquishing the DCF
		 * functionality first, remove ALL switch filters that were
		 * added by the DCF.
		 */
		dev_info(ice_pf_to_dev(pf), "DCF is not in the OFF state, removing all filters that were added by the DCF\n");
		ice_rm_all_dcf_sw_rules(pf);
		ice_dis_dcf_acl_cap(pf);
		ice_dcf_set_state(pf, ICE_DCF_STATE_OFF);
		pf->dcf.vf = NULL;
		ice_reset_vf(vf, false);
	}

	vfres->num_vsis = 1;
	/* Tx and Rx queue are equal for VF */
	vfres->num_queue_pairs = vsi->num_txq;
	vfres->max_vectors = pf->num_msix_per_vf;
	vfres->rss_key_size = ICE_VSIQF_HKEY_ARRAY_SIZE;
	vfres->rss_lut_size = vsi->rss_table_size;
	vfres->max_mtu = ice_vc_get_max_frame_size(vf);

	vfres->vsi_res[0].vsi_id = vf->lan_vsi_num;
	vfres->vsi_res[0].vsi_type = VIRTCHNL_VSI_SRIOV;
	vfres->vsi_res[0].num_queue_pairs = vsi->num_txq;
	ether_addr_copy(vfres->vsi_res[0].default_mac_addr,
			vf->hw_lan_addr.addr);

	/* match guest capabilities */
	vf->driver_caps = vfres->vf_cap_flags;

	ice_vc_set_caps_allowlist(vf);
	ice_vc_set_working_allowlist(vf);

	set_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);

err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_VF_RESOURCES, v_ret,
				    (u8 *)vfres, len);

	kfree(vfres);
	return ret;
}

/**
 * ice_vc_reset_vf_msg
 * @vf: pointer to the VF info
 *
 * called from the VF to reset itself,
 * unlike other virtchnl messages, PF driver
 * doesn't send the response back to the VF
 */
static void ice_vc_reset_vf_msg(struct ice_vf *vf)
{
	if (test_bit(ICE_VF_STATE_INIT, vf->vf_states))
		ice_reset_vf(vf, false);
}

/**
 * ice_find_vsi_from_id
 * @pf: the PF structure to search for the VSI
 * @id: ID of the VSI it is searching for
 *
 * searches for the VSI with the given ID
 */
static struct ice_vsi *ice_find_vsi_from_id(struct ice_pf *pf, u16 id)
{
	int i;

	ice_for_each_vsi(pf, i)
		if (pf->vsi[i] && pf->vsi[i]->vsi_num == id)
			return pf->vsi[i];

	return NULL;
}

/**
 * ice_vc_isvalid_vsi_id
 * @vf: pointer to the VF info
 * @vsi_id: VF relative VSI ID
 *
 * check for the valid VSI ID
 */
bool ice_vc_isvalid_vsi_id(struct ice_vf *vf, u16 vsi_id)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_find_vsi_from_id(pf, vsi_id);

	return (vsi && (vsi->vf_id == vf->vf_id));
}

/**
 * ice_vc_isvalid_q_id
 * @vf: pointer to the VF info
 * @vsi_id: VSI ID
 * @qid: VSI relative queue ID
 *
 * check for the valid queue ID
 */
static bool ice_vc_isvalid_q_id(struct ice_vf *vf, u16 vsi_id, u8 qid)
{
	struct ice_vsi *vsi = ice_find_vsi_from_id(vf->pf, vsi_id);
	/* allocated Tx and Rx queues should be always equal for VF VSI */
	return (vsi && (qid < vsi->alloc_txq));
}

/**
 * ice_vc_isvalid_ring_len
 * @ring_len: length of ring
 *
 * check for the valid ring count, should be multiple of ICE_REQ_DESC_MULTIPLE
 * or zero
 */
static bool ice_vc_isvalid_ring_len(u16 ring_len)
{
	return ring_len == 0 ||
	       (ring_len >= ICE_MIN_NUM_DESC &&
		ring_len <= ICE_MAX_NUM_DESC &&
		!(ring_len % ICE_REQ_DESC_MULTIPLE));
}

static enum virtchnl_status_code ice_vc_rss_hash_update(struct ice_hw *hw,
							struct ice_vsi *vsi,
							u8 hash_type)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi_ctx *ctx;
	enum ice_status status;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;


	/* clear previous hash_type */
	ctx->info.q_opt_rss = vsi->info.q_opt_rss &
		~(ICE_AQ_VSI_Q_OPT_RSS_HASH_M);
	/* hash_type is passed in as ICE_AQ_VSI_Q_OPT_RSS_<XOR|TPLZ|SYM_TPLZ */
	ctx->info.q_opt_rss |= hash_type;

	/* Preserve existing queueing option setting */
	ctx->info.q_opt_tc = vsi->info.q_opt_tc;
	ctx->info.q_opt_flags = vsi->info.q_opt_flags;

	ctx->info.valid_sections =
			cpu_to_le16(ICE_AQ_VSI_PROP_Q_OPT_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctx, NULL);
	if (status) {
		dev_err(ice_hw_to_dev(hw),
			"update VSI for rss failed, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	} else {
		vsi->info.q_opt_rss = ctx->info.q_opt_rss;
	}

	kfree(ctx);

	return v_ret;
}

/**
 * ice_vc_parse_rss_cfg - parses hash fields and headers from
 * a specific virtchnl RSS cfg
 * @hw: pointer to the hardware
 * @rss_cfg: pointer to the virtchnl rss cfg
 * @hash_cfg: pointer to the HW hash configuration
 *
 * Return true if all the protocol header and hash fields in the rss cfg could
 * be parsed, else return false
 *
 * This function parses the virtchnl rss cfg to be the intended
 * hash fields and the intended header for RSS configuration
 */
static bool ice_vc_parse_rss_cfg(struct ice_hw *hw,
				 struct virtchnl_rss_cfg *rss_cfg,
				 struct ice_rss_hash_cfg *hash_cfg)
{
	const struct ice_vc_hash_field_match_type *hf_list;
	const struct ice_vc_hdr_match_type *hdr_list;
	int i, hf_list_len, hdr_list_len;
	bool outer_ipv4 = false;
	bool outer_ipv6 = false;
	bool gtpu = false;

	u32 *addl_hdrs = &hash_cfg->addl_hdrs;
	u64 *hash_flds = &hash_cfg->hash_flds;
	/* set outer layer RSS as default */
	hash_cfg->hdr_type = ICE_RSS_OUTER_HEADERS;

	if (!strncmp((const char *)hw->active_pkg_name, "ICE COMMS Package",
		     min(sizeof(hw->active_pkg_name),
			 sizeof("ICE COMMS Package")))) {
		hf_list = ice_vc_hash_field_list_comms;
		hf_list_len = ARRAY_SIZE(ice_vc_hash_field_list_comms);
		hdr_list = ice_vc_hdr_list_comms;
		hdr_list_len = ARRAY_SIZE(ice_vc_hdr_list_comms);
	} else {
		hf_list = ice_vc_hash_field_list_os;
		hf_list_len = ARRAY_SIZE(ice_vc_hash_field_list_os);
		hdr_list = ice_vc_hdr_list_os;
		hdr_list_len = ARRAY_SIZE(ice_vc_hdr_list_os);
	}

	for (i = 0; i < rss_cfg->proto_hdrs.count; i++) {
		struct virtchnl_proto_hdr *proto_hdr =
				&rss_cfg->proto_hdrs.proto_hdr[i];
		u32 hdr_found = 0;
		int j;

		/* find matched ice headers according to virtchnl headers.
		 * Also figure out the outer type of GTPU headers.
		 */
		for (j = 0; j < hdr_list_len; j++) {
			struct ice_vc_hdr_match_type hdr_map =
				hdr_list[j];

			if (proto_hdr->type == hdr_map.vc_hdr)
				hdr_found = hdr_map.ice_hdr;
		}

		if (!hdr_found)
			return false;

		if (proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV4 && !gtpu)
			outer_ipv4 = true;
		else if (proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV6 && !gtpu)
			outer_ipv6 = true;
		/* for GTPU, take inner header as input set if no any field
		 * is selected from outer headers.
		 */
		else if ((proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_IP ||
			  proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_EH ||
			  proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN ||
			  proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP) &&
			 *hash_flds == 0) {
			/* set gtpu flag, and clean up outer header */
			gtpu = true;

			/* clear outer headers */
			*addl_hdrs = 0;

			if (outer_ipv4 && outer_ipv6)
				return false;

			if (outer_ipv4)
				hash_cfg->hdr_type = ICE_RSS_INNER_HEADERS_W_OUTER_IPV4;
			else if (outer_ipv6)
				hash_cfg->hdr_type = ICE_RSS_INNER_HEADERS_W_OUTER_IPV6;
			else
				hash_cfg->hdr_type = ICE_RSS_INNER_HEADERS;
		}

		*addl_hdrs |= hdr_found;

		/* Find matched ice hash fields according to
		 * virtchnl hash fields.
		 */
		for (j = 0; j < hf_list_len; j++) {
			struct ice_vc_hash_field_match_type hf_map =
				hf_list[j];

			if (proto_hdr->type == hf_map.vc_hdr &&
			    proto_hdr->field_selector ==
			     hf_map.vc_hash_field) {
				*hash_flds |= hf_map.ice_hash_field;
				break;
			}
		}
	}

	/* refine gtpu header if we take outer as input set for a no inner
	 * ip gtpu flow.
	 */
	if (hash_cfg->hdr_type == ICE_RSS_OUTER_HEADERS &&
	    *addl_hdrs & ICE_FLOW_SEG_HDR_GTPU_IP) {
		*addl_hdrs &= ~(ICE_FLOW_SEG_HDR_GTPU_IP);
		*addl_hdrs |= ICE_FLOW_SEG_HDR_GTPU_NON_IP;
	}

	/* refine hash field for esp and nat-t-esp. */
	if ((*addl_hdrs & ICE_FLOW_SEG_HDR_UDP) &&
	    (*addl_hdrs & ICE_FLOW_SEG_HDR_ESP)) {
		*addl_hdrs &= ~(ICE_FLOW_SEG_HDR_ESP | ICE_FLOW_SEG_HDR_UDP);
		*addl_hdrs |= ICE_FLOW_SEG_HDR_NAT_T_ESP;
		*hash_flds &= ~(BIT_ULL(ICE_FLOW_FIELD_IDX_ESP_SPI));
		*hash_flds |= BIT_ULL(ICE_FLOW_FIELD_IDX_NAT_T_ESP_SPI);
	}

	/* refine hash hdrs for L4 udp/tcp/sctp. */
	if (*addl_hdrs & (ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_UDP |
			  ICE_FLOW_SEG_HDR_SCTP) &&
	    *addl_hdrs & ICE_FLOW_SEG_HDR_IPV_OTHER)
		*addl_hdrs &= ~ICE_FLOW_SEG_HDR_IPV_OTHER;

	return true;
}

/**
 * ice_vf_adv_rss_offload_ena - determine if capabilities support advanced
 * rss offloads
 * @caps: VF driver negotiated capabilities
 *
 * Return true if VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF capability is set,
 * else return false
 */
static bool ice_vf_adv_rss_offload_ena(u32 caps)
{
	return !!(caps & VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF);
}

/**
 * is_hash_cfg_valid - check if the hash context is valid
 * @cfg: pointer to the RSS hash configuration
 *
 * This function will return true if the hash context is valid, otherwise
 * return false.
 */
static bool is_hash_cfg_valid(struct ice_rss_hash_cfg *cfg)
{
	return (cfg->hash_flds != 0 && cfg->addl_hdrs != 0) ?
		true : false;
}

/**
 * hash_cfg_reset - reset the hash context
 * @cfg: pointer to the RSS hash configuration
 *
 * This function will reset the hash context which stores the valid rule info.
 */
static void hash_cfg_reset(struct ice_rss_hash_cfg *cfg)
{
	cfg->hash_flds = 0;
	cfg->addl_hdrs = 0;
	cfg->hdr_type = ICE_RSS_OUTER_HEADERS;
	cfg->symm = 0;
}

/**
 * hash_cfg_record - record the hash context
 * @ctx: pointer to the global RSS hash configuration
 * @cfg: pointer to the RSS hash configuration to be recorded
 *
 * This function will record the hash context which stores the valid rule info.
 */
static void hash_cfg_record(struct ice_rss_hash_cfg *ctx,
			    struct ice_rss_hash_cfg *cfg)
{
	ctx->hash_flds = cfg->hash_flds;
	ctx->addl_hdrs = cfg->addl_hdrs;
	ctx->hdr_type = cfg->hdr_type;
	ctx->symm = cfg->symm;
}

/**
 * ice_hash_moveout - delete a RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * This function will delete an existing RSS hash configuration but not delete
 * the hash context which stores the rule info.
 */
static int
ice_hash_moveout(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status = 0;
	struct ice_hw *hw = &vf->pf->hw;

	if (!is_hash_cfg_valid(cfg))
		return -ENOENT;

	status = ice_rem_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status && status != ICE_ERR_DOES_NOT_EXIST) {
		dev_err(dev, "ice_rem_rss_cfg failed for VSI:%d, error:%s\n",
			vf->lan_vsi_num, ice_stat_str(status));
		return -EBUSY;
	}

	return 0;
}

/**
 * ice_hash_moveback - add an RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * The function will add a RSS hash configuration if the hash context is valid.
 */
static int
ice_hash_moveback(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status = 0;
	struct ice_hw *hw = &vf->pf->hw;

	if (!is_hash_cfg_valid(cfg))
		return -ENOENT;

	status = ice_add_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status) {
		dev_err(dev, "ice_add_rss_cfg failed for VSI:%d, error:%s\n",
			vf->lan_vsi_num, ice_stat_str(status));
		return -EBUSY;
	}

	return 0;
}

/**
 * ice_hash_remove - remove a RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * This function will delete a RSS hash configuration and also delete the
 * hash context which stores the rule info.
 */
static int
ice_hash_remove(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	int ret;

	ret = ice_hash_moveout(vf, cfg);
	if (ret && (ret != -ENOENT))
		return ret;

	hash_cfg_reset(cfg);

	return 0;
}

/**
 * ice_add_rss_cfg_pre_gtpu - pre-process the GTPU RSS configuration
 * @vf: pointer to the VF info
 * @ctx: pointer to the context of the GTPU hash
 * @ctx_idx: The index of the hash context
 *
 * This function pre-process the GTPU hash configuration before adding a hash
 * config, it will remove or rotate some prior hash configs which will cause
 * conflicts.  For example, if a GTPU_UP/DWN rule be configured after a GTPU_EH
 * rule, the GTPU_EH hash will be hit at first due to TCAM write sequence from
 * top to down, and the hash hit sequence also from top to down. So the
 * GTPU_EH rule need roolback to the later of the GTPU_UP/DWN rule. On the
 * other hand, when a GTPU_EH rule be configured after a GTPU_UP/DWN rule,
 * just need to remove the GTPU_DWN/UP rules.
 */
static int
ice_add_rss_cfg_pre_gtpu(struct ice_vf *vf, struct ice_vf_hash_gtpu_ctx *ctx,
			 u32 ctx_idx)
{
	int ret;

	switch (ctx_idx) {
	case ICE_HASH_GTPU_CTX_EH_IP:
		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_EH_IP_UDP:
		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_EH_IP_TCP:
		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_UP_IP:
		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_UP_IP_UDP:
	case ICE_HASH_GTPU_CTX_UP_IP_TCP:
		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_DW_IP:
		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_remove(vf,
				      &ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_DW_IP_UDP:
	case ICE_HASH_GTPU_CTX_DW_IP_TCP:
		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveout(vf,
				       &ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	default:
		break;
	}

	return 0;
}

/**
 * ice_add_rss_cfg_pre_ip - pre-process the IP RSS configuration
 * @vf: pointer to the VF info
 * @ctx: pointer to the context of the IP L4 hash
 *
 * This function will remove all covered and recorded IP RSS configurations,
 * including IP with ESP/UDP_ESP/AH/L2TPV3/PFCP and UDP/TCP/SCTP.
 */
static int
ice_add_rss_cfg_pre_ip(struct ice_vf *vf, struct ice_vf_hash_ip_ctx *ctx)
{
	int i, ret;

	for (i = 1; i < ICE_HASH_IP_CTX_MAX; i++)
		if (is_hash_cfg_valid(&ctx->ctx[i])) {
			ret = ice_hash_remove(vf, &ctx->ctx[i]);

			if (ret)
				return ret;
		}

	return 0;
}

/**
 * calc_gtpu_ctx_idx - calculate the index of the GTPU hash context
 * @hdrs: the protocol headers prefix with ICE_FLOW_SEG_HDR_XXX.
 *
 * The GTPU hash context use the index to classify for IPV4/IPV6 and
 * GTPU_EH/GTPU_UP/GTPU_DWN, this function used to calculate the index
 * by the protocol headers.
 */
static u32 calc_gtpu_ctx_idx(u32 hdrs)
{
	u32 eh_idx, ip_idx;

	if (hdrs & ICE_FLOW_SEG_HDR_GTPU_EH)
		eh_idx = 0;
	else if (hdrs & ICE_FLOW_SEG_HDR_GTPU_UP)
		eh_idx = 1;
	else if (hdrs & ICE_FLOW_SEG_HDR_GTPU_DWN)
		eh_idx = 2;
	else
		return ICE_HASH_GTPU_CTX_MAX;

	ip_idx = 0;
	if (hdrs & ICE_FLOW_SEG_HDR_UDP)
		ip_idx = 1;
	else if (hdrs & ICE_FLOW_SEG_HDR_TCP)
		ip_idx = 2;

	if (hdrs & (ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV6))
		return eh_idx * 3 + ip_idx;
	else
		return ICE_HASH_GTPU_CTX_MAX;
}

/**
 * ice_map_ip_ctx_idx - map the index of the IP L4 hash context
 * @hdrs: protocol headers prefix with ICE_FLOW_SEG_HDR_XXX.
 *
 * The IP L4 hash context use the index to classify for IPv4/IPv6 with
 * ESP/UDP_ESP/AH/L2TPV3/PFCP and non-tunnel UDP/TCP/SCTP
 * this function map the index based on the protocol headers.
 */
static u8 ice_map_ip_ctx_idx(u32 hdrs)
{
	u8 i;

	static struct {
		u32 hdrs;
		u8 ctx_idx;
	} ip_ctx_idx_map[] = {
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_ESP,
			ICE_HASH_IP_CTX_IP_ESP },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_NAT_T_ESP,
			ICE_HASH_IP_CTX_IP_UDP_ESP },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_AH,
			ICE_HASH_IP_CTX_IP_AH },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_L2TPV3,
			ICE_HASH_IP_CTX_IP_L2TPV3 },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_PFCP_SESSION,
			ICE_HASH_IP_CTX_IP_PFCP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_UDP,
			ICE_HASH_IP_CTX_IP_UDP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_TCP,
			ICE_HASH_IP_CTX_IP_TCP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_SCTP,
			ICE_HASH_IP_CTX_IP_SCTP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER,
			ICE_HASH_IP_CTX_IP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_ESP,
			ICE_HASH_IP_CTX_IP_ESP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_NAT_T_ESP,
			ICE_HASH_IP_CTX_IP_UDP_ESP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_AH,
			ICE_HASH_IP_CTX_IP_AH },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_L2TPV3,
			ICE_HASH_IP_CTX_IP_L2TPV3 },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER |
			ICE_FLOW_SEG_HDR_PFCP_SESSION,
			ICE_HASH_IP_CTX_IP_PFCP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_UDP,
			ICE_HASH_IP_CTX_IP_UDP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_TCP,
			ICE_HASH_IP_CTX_IP_TCP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_SCTP,
			ICE_HASH_IP_CTX_IP_SCTP },
		{ ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN |
			ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER,
			ICE_HASH_IP_CTX_IP },
		/* the remaining mappings are used for default RSS */
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_UDP,
			ICE_HASH_IP_CTX_IP_UDP },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_TCP,
			ICE_HASH_IP_CTX_IP_TCP },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_SCTP,
			ICE_HASH_IP_CTX_IP_SCTP },
		{ ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV_OTHER,
			ICE_HASH_IP_CTX_IP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_UDP,
			ICE_HASH_IP_CTX_IP_UDP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_TCP,
			ICE_HASH_IP_CTX_IP_TCP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_SCTP,
			ICE_HASH_IP_CTX_IP_SCTP },
		{ ICE_FLOW_SEG_HDR_IPV6 | ICE_FLOW_SEG_HDR_IPV_OTHER,
			ICE_HASH_IP_CTX_IP },
	};

	for (i = 0; i < ARRAY_SIZE(ip_ctx_idx_map); i++) {
		if (hdrs == ip_ctx_idx_map[i].hdrs)
			return ip_ctx_idx_map[i].ctx_idx;
	}

	return ICE_HASH_IP_CTX_MAX;
}

static int
ice_add_rss_cfg_pre(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	int ret = 0;

	u32 ice_gtpu_ctx_idx = calc_gtpu_ctx_idx(cfg->addl_hdrs);

	u8 ip_ctx_idx = ice_map_ip_ctx_idx(cfg->addl_hdrs);

	if (ip_ctx_idx == ICE_HASH_IP_CTX_IP) {
		if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4)
			ret = ice_add_rss_cfg_pre_ip(vf, &vf->hash_ctx.v4);
		else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6)
			ret = ice_add_rss_cfg_pre_ip(vf, &vf->hash_ctx.v6);

		if (ret)
			return ret;
	}

	if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4) {
		return ice_add_rss_cfg_pre_gtpu(vf, &vf->hash_ctx.ipv4,
						ice_gtpu_ctx_idx);
	} else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6) {
		return ice_add_rss_cfg_pre_gtpu(vf, &vf->hash_ctx.ipv6,
						ice_gtpu_ctx_idx);
	}

	return 0;
}

/**
 * ice_add_rss_cfg_post_gtpu - A wrap function of deleting an RSS configuration
 * @vf: pointer to the VF info
 * @ctx: pointer to the context of the GTPU hash
 * @cfg: pointer to the rss hash configuration
 * @ctx_idx: The index of the hash context
 *
 * This function post process the hash configuration after the hash config is
 * successfully adding, it will re-configure the prior hash config which was
 * moveout but need to moveback again.
 */
static int
ice_add_rss_cfg_post_gtpu(struct ice_vf *vf, struct ice_vf_hash_gtpu_ctx *ctx,
			  struct ice_rss_hash_cfg *cfg, u32 ctx_idx)
{
	int ret;

	if (ctx_idx < ICE_HASH_GTPU_CTX_MAX) {
		ctx->ctx[ctx_idx].addl_hdrs = cfg->addl_hdrs;
		ctx->ctx[ctx_idx].hash_flds = cfg->hash_flds;
		ctx->ctx[ctx_idx].hdr_type = cfg->hdr_type;
		ctx->ctx[ctx_idx].symm = cfg->symm;
	}

	switch (ctx_idx) {
	case ICE_HASH_GTPU_CTX_EH_IP:
		break;
	case ICE_HASH_GTPU_CTX_EH_IP_UDP:
		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_EH_IP_TCP:
		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_UP_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_DW_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	case ICE_HASH_GTPU_CTX_UP_IP:
	case ICE_HASH_GTPU_CTX_UP_IP_UDP:
	case ICE_HASH_GTPU_CTX_UP_IP_TCP:
	case ICE_HASH_GTPU_CTX_DW_IP:
	case ICE_HASH_GTPU_CTX_DW_IP_UDP:
	case ICE_HASH_GTPU_CTX_DW_IP_TCP:
		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_UDP]);
		if (ret && (ret != -ENOENT))
			return ret;

		ret = ice_hash_moveback(vf,
					&ctx->ctx[ICE_HASH_GTPU_CTX_EH_IP_TCP]);
		if (ret && (ret != -ENOENT))
			return ret;

		break;
	default:
		break;
	}

	return 0;
}

static int
ice_add_rss_cfg_post(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	u32 ice_gtpu_ctx_idx = calc_gtpu_ctx_idx(cfg->addl_hdrs);

	u8 ip_ctx_idx = ice_map_ip_ctx_idx(cfg->addl_hdrs);

	if (ip_ctx_idx && ip_ctx_idx < ICE_HASH_IP_CTX_MAX) {
		if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4)
			hash_cfg_record(&vf->hash_ctx.v4.ctx[ip_ctx_idx], cfg);
		else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6)
			hash_cfg_record(&vf->hash_ctx.v6.ctx[ip_ctx_idx], cfg);
	}

	if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4) {
		return ice_add_rss_cfg_post_gtpu(vf, &vf->hash_ctx.ipv4,
						 cfg, ice_gtpu_ctx_idx);
	} else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6) {
		return ice_add_rss_cfg_post_gtpu(vf, &vf->hash_ctx.ipv6,
						 cfg, ice_gtpu_ctx_idx);
	}

	return 0;
}

/**
 * ice_rem_rss_cfg_post - post-process the RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * This function post-process the RSS hash configuration after deleting a hash
 * config. Such as, it will reset the hash context for the GTPU hash.
 */
static void
ice_rem_rss_cfg_post(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	u32 ice_gtpu_ctx_idx = calc_gtpu_ctx_idx(cfg->addl_hdrs);

	u8 ip_ctx_idx = ice_map_ip_ctx_idx(cfg->addl_hdrs);

	if (ip_ctx_idx && ip_ctx_idx < ICE_HASH_IP_CTX_MAX) {
		if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4)
			hash_cfg_reset(&vf->hash_ctx.v4.ctx[ip_ctx_idx]);
		else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6)
			hash_cfg_reset(&vf->hash_ctx.v6.ctx[ip_ctx_idx]);
	}

	if (ice_gtpu_ctx_idx >= ICE_HASH_GTPU_CTX_MAX)
		return;

	if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV4)
		hash_cfg_reset(&vf->hash_ctx.ipv4.ctx[ice_gtpu_ctx_idx]);
	else if (cfg->addl_hdrs & ICE_FLOW_SEG_HDR_IPV6)
		hash_cfg_reset(&vf->hash_ctx.ipv6.ctx[ice_gtpu_ctx_idx]);
}

/**
 * ice_rem_rss_cfg_wrap - A wrap function of deleting an RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * Wrapper function to delete a flow profile base on an RSS configuration,
 * and also post process the hash context base on the rollback mechanism
 * which handle some rules conflict by ice_add_rss_cfg_wrap.
 */
static enum ice_status
ice_rem_rss_cfg_wrap(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status = 0;
	struct ice_hw *hw = &vf->pf->hw;

	status = ice_rem_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	/* We just ignore ICE_ERR_DOES_NOT_EXIST, because
	 * if two configurations share the same profile remove
	 * one of them actually removes both, since the
	 * profile is deleted.
	 */
	if (status && status != ICE_ERR_DOES_NOT_EXIST) {
		dev_err(dev, "ice_rem_rss_cfg failed for VSI:%d, error:%s\n",
			vf->lan_vsi_num, ice_stat_str(status));
		goto error;
	}

	ice_rem_rss_cfg_post(vf, cfg);

error:
	return status;
}

/**
 * ice_add_rss_cfg_wrap - A wrap function of adding an RSS configuration
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS hash configuration
 *
 * Wapper function to add a flow profile base on a RSS configuration, and
 * also use a rollback mechanism to handle some rules conflict due to TCAM
 * write sequence from top to down.
 */
static enum ice_status
ice_add_rss_cfg_wrap(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status = 0;
	struct ice_hw *hw = &vf->pf->hw;

	if (ice_add_rss_cfg_pre(vf, cfg))
		return ICE_ERR_PARAM;

	status = ice_add_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status) {
		dev_err(dev, "ice_add_rss_cfg failed for VSI:%d, error:%s\n",
			vf->lan_vsi_num, ice_stat_str(status));
		goto error;
	}

	if (ice_add_rss_cfg_post(vf, cfg))
		status = ICE_ERR_PARAM;

error:
	return status;
}

/**
 * ice_vc_handle_rss_cfg
 * @vf: pointer to the VF info
 * @msg: pointer to the message buffer
 * @add: add a RSS config if true, otherwise delete a RSS config
 *
 * This function adds/deletes a RSS config
 */
static int ice_vc_handle_rss_cfg(struct ice_vf *vf, u8 *msg, bool add)
{
	struct virtchnl_rss_cfg *rss_cfg = (struct virtchnl_rss_cfg *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	u32 v_opcode = add ? VIRTCHNL_OP_ADD_RSS_CFG :
			VIRTCHNL_OP_DEL_RSS_CFG;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		dev_dbg(dev, "VF %d attempting to configure RSS, but RSS is not supported by the PF\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto error_param;
	}

	if (!ice_vf_adv_rss_offload_ena(vf->driver_caps)) {
		dev_dbg(dev, "VF %d attempting to configure RSS, but Advanced rss offload is not supported\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (rss_cfg->proto_hdrs.count > VIRTCHNL_MAX_NUM_PROTO_HDRS ||
	    rss_cfg->rss_algorithm < VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC ||
	    rss_cfg->rss_algorithm > VIRTCHNL_RSS_ALG_XOR_SYMMETRIC) {
		dev_dbg(dev, "VF %d attempting to configure RSS, but RSS configuration is not valid\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (rss_cfg->rss_algorithm == VIRTCHNL_RSS_ALG_R_ASYMMETRIC) {
		u8 hash_type = add ? ICE_AQ_VSI_Q_OPT_RSS_XOR : ICE_AQ_VSI_Q_OPT_RSS_TPLZ;

		v_ret = ice_vc_rss_hash_update(hw, vsi, hash_type);
	} else {
		struct ice_rss_hash_cfg cfg;
		u8 hash_type;

		cfg.addl_hdrs = ICE_FLOW_SEG_HDR_NONE;
		cfg.hash_flds = ICE_HASH_INVALID;
		cfg.hdr_type = ICE_RSS_ANY_HEADERS;

		hash_type = add ? ICE_AQ_VSI_Q_OPT_RSS_SYM_TPLZ :
				ICE_AQ_VSI_Q_OPT_RSS_TPLZ;

		v_ret = ice_vc_rss_hash_update(hw, vsi, hash_type);
		if (v_ret)
			goto error_param;

		if (!ice_vc_parse_rss_cfg(hw, rss_cfg, &cfg)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (add) {
			if (rss_cfg->rss_algorithm ==
				     VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC)
				cfg.symm = true;
			else
				cfg.symm = false;

			if (ice_add_rss_cfg_wrap(vf, &cfg))
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		} else {
			if (ice_rem_rss_cfg_wrap(vf, &cfg))
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		}
	}

error_param:
	return ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, NULL, 0);
}

/**
 * ice_vc_config_rss_key
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS key
 */
static int ice_vc_config_rss_key(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_key *vrk =
		(struct virtchnl_rss_key *)msg;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vrk->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrk->key_len != ICE_VSIQF_HKEY_ARRAY_SIZE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_set_rss_key(vsi, vrk->key))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_KEY, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_config_rss_lut
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS LUT
 */
static int ice_vc_config_rss_lut(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_rss_lut *vrl = (struct virtchnl_rss_lut *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vrl->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrl->lut_entries != vsi->rss_table_size) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_set_rss_lut(vsi, vrl->lut, vrl->lut_entries))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_LUT, v_ret,
				     NULL, 0);
}

/**
 * ice_wait_on_vf_reset - poll to make sure a given VF is ready after reset
 * @vf: The VF being resseting
 *
 * The max poll time is about ~800ms, which is about the maximum time it takes
 * for a VF to be reset and/or a VF driver to be removed.
 */
static void ice_wait_on_vf_reset(struct ice_vf *vf)
{
	int i;

	for (i = 0; i < ICE_MAX_VF_RESET_TRIES; i++) {
		if (test_bit(ICE_VF_STATE_INIT, vf->vf_states))
			break;
		msleep(ICE_MAX_VF_RESET_SLEEP_MS);
	}
}

/**
 * ice_check_vf_ready_for_cfg - check if VF is ready to be configured/queried
 * @vf: VF to check if it's ready to be configured/queried
 *
 * The purpose of this function is to make sure the VF is not in reset, not
 * disabled, and initialized so it can be configured and/or queried by a host
 * administrator.
 */
static int ice_check_vf_ready_for_cfg(struct ice_vf *vf)
{
	struct ice_pf *pf;

	ice_wait_on_vf_reset(vf);

	if (ice_is_vf_disabled(vf))
		return -EINVAL;

	pf = vf->pf;
	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	return 0;
}

/**
 * ice_set_vf_spoofchk
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 */
int ice_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_pf *pf = np->vsi->back;
	struct ice_vsi_ctx *ctx;
	struct ice_vsi *vf_vsi;
	enum ice_status status;
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	vf_vsi = ice_get_vf_vsi(vf);
	if (!vf_vsi) {
		netdev_err(netdev, "VSI %d for VF %d is null\n",
			   vf->lan_vsi_idx, vf->vf_id);
		return -EINVAL;
	}

	if (vf_vsi->type != ICE_VSI_VF) {
		netdev_err(netdev, "Type %d of VSI %d for VF %d is no ICE_VSI_VF\n",
			   vf_vsi->type, vf_vsi->vsi_num, vf->vf_id);
		return -ENODEV;
	}

	if (ena == vf->spoofchk) {
		dev_dbg(dev, "VF spoofchk already %s\n", ena ? "ON" : "OFF");
		return 0;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->info.sec_flags = vf_vsi->info.sec_flags;
	ctx->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
	if (ena) {
		ctx->info.sec_flags |=
			ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
			(ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
			 ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S);
	} else {
		ctx->info.sec_flags &=
			~(ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
			  (ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
			   ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S));
	}

	status = ice_update_vsi(&pf->hw, vf_vsi->idx, ctx, NULL);
	if (status) {
		dev_err(dev, "Failed to %sable spoofchk on VF %d VSI %d\n error %s\n",
			ena ? "en" : "dis", vf->vf_id, vf_vsi->vsi_num,
			ice_stat_str(status));
		ret = -EIO;
		goto out;
	}

	/* only update spoofchk state and VSI context on success */
	vf_vsi->info.sec_flags = ctx->info.sec_flags;
	vf->spoofchk = ena;

out:
	kfree(ctx);
	return ret;
}

/**
 * ice_is_any_vf_in_promisc - check if any VF(s) are in promiscuous mode
 * @pf: PF structure for accessing VF(s)
 *
 * Return false if no VF(s) are in unicast and/or multicast promiscuous mode,
 * else return true
 */
bool ice_is_any_vf_in_promisc(struct ice_pf *pf)
{
	int vf_idx;

	ice_for_each_vf(pf, vf_idx) {
		struct ice_vf *vf = &pf->vf[vf_idx];

		/* found a VF that has promiscuous mode configured */
		if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
		    test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
			return true;
	}

	return false;
}

/**
 * ice_vc_cfg_promiscuous_mode_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure VF VSIs promiscuous mode
 */
static int ice_vc_cfg_promiscuous_mode_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	bool rm_promisc, alluni = false, allmulti = false;
	struct virtchnl_promisc_info *info =
	    (struct virtchnl_promisc_info *)msg;
	int mcast_err = 0, ucast_err = 0;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int ret = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, info->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		dev_err(dev, "Unprivileged VF %d is attempting to configure promiscuous mode\n",
			vf->vf_id);
		/* Leave v_ret alone, lie to the VF on purpose. */
		goto error_param;
	}

	if (info->flags & FLAG_VF_UNICAST_PROMISC)
		alluni = true;

	if (info->flags & FLAG_VF_MULTICAST_PROMISC)
		allmulti = true;

	rm_promisc = !allmulti && !alluni;

	if (vsi->num_vlan || vf->port_vlan_info) {
		struct ice_vsi *pf_vsi = ice_get_main_vsi(pf);
		struct net_device *pf_netdev;

		if (!pf_vsi) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		pf_netdev = pf_vsi->netdev;

		ret = ice_set_vf_spoofchk(pf_netdev, vf->vf_id, rm_promisc);
		if (ret) {
			dev_err(dev, "Failed to update spoofchk to %s for VF %d VSI %d when setting promiscuous mode\n",
				rm_promisc ? "ON" : "OFF", vf->vf_id,
				vsi->vsi_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		}

		ret = ice_cfg_vlan_pruning(vsi, true, !rm_promisc);
		if (ret) {
			dev_err(dev, "Failed to configure VLAN pruning in promiscuous mode\n");
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	}

	if (!test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags)) {
		bool set_dflt_vsi = alluni || allmulti;

		if (set_dflt_vsi && !ice_is_dflt_vsi_in_use(vsi->vsw))
			/* only attempt to set the default forwarding VSI if
			 * it's not currently set
			 */
			ret = ice_set_dflt_vsi(vsi->vsw, vsi);
		else if (!set_dflt_vsi &&
			 ice_is_vsi_dflt_vsi(vsi->vsw, vsi))
			/* only attempt to free the default forwarding VSI if we
			 * are the owner
			 */
			ret = ice_clear_dflt_vsi(vsi->vsw);

		if (ret) {
			dev_err(dev, "%sable VF %d as the default VSI failed, error %d\n",
				set_dflt_vsi ? "en" : "dis", vf->vf_id, ret);
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto error_param;
		}
	} else {
		u8 mcast_m, ucast_m;

		if (vf->port_vlan_info || vsi->num_vlan) {
			mcast_m = ICE_MCAST_VLAN_PROMISC_BITS;
			ucast_m = ICE_UCAST_VLAN_PROMISC_BITS;
		} else {
			mcast_m = ICE_MCAST_PROMISC_BITS;
			ucast_m = ICE_UCAST_PROMISC_BITS;
		}

		if (alluni)
			ucast_err = ice_vf_set_vsi_promisc(vf, vsi, ucast_m);
		else
			ucast_err = ice_vf_clear_vsi_promisc(vf, vsi, ucast_m);

		if (allmulti)
			mcast_err = ice_vf_set_vsi_promisc(vf, vsi, mcast_m);
		else
			mcast_err = ice_vf_clear_vsi_promisc(vf, vsi, mcast_m);
	}

	if (!mcast_err) {
		if (allmulti &&
		    !test_and_set_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully set multicast promiscuous mode\n",
				 vf->vf_id);
		else if (!allmulti && test_and_clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully unset multicast promiscuous mode\n",
				 vf->vf_id);
	}

	if (!ucast_err) {
		if (alluni && !test_and_set_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully set unicast promiscuous mode\n",
				 vf->vf_id);
		else if (!alluni && test_and_clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully unset unicast promiscuous mode\n",
				 vf->vf_id);
	}

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_get_stats_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to get VSI stats
 */
static int ice_vc_get_stats_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
		(struct virtchnl_queue_select *)msg;
	struct ice_eth_stats stats = { 0 };
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	ice_update_eth_stats(vsi);

	stats = vsi->eth_stats;

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_STATS, v_ret,
				     (u8 *)&stats, sizeof(stats));
}

/**
 * ice_vf_get_tc_based_qid - get the updated QID based on offset
 * @qid: queue ID
 * @offset : TC specific queue offset
 *
 * This function returns updated queueID based on offset. This is
 * meant to be used only with VF ADQ. Queue ID will always be
 * 0-based from the specified offset
 */
static u16 ice_vf_get_tc_based_qid(u16 qid, u16 offset)
{
	return (qid >= offset) ? (qid - offset) : qid;
}

/**
 * ice_vf_q_id_get_vsi_q_id
 * @vf: pointer to the VF info
 * @vf_q_id: VF relative queue ID
 * @t_tc: traffic class for indexing the VSIs
 * @vqs: the VFs virtual queue selection
 * @vsi_p: pointer to VSI pointer, which changes based on TC for ADQ
 * @vsi_id: VSI ID specific to desired queue ID
 * @q_id: queue ID of the VSI
 *
 * provides ADQ queue enablement support by mapping the VF queue ID and TC to
 * VSI ID and queue ID. call while iterating through VF queue IDs, VF VSIs and
 * TCs.
 */
static void ice_vf_q_id_get_vsi_q_id(struct ice_vf *vf, u16 vf_q_id, u16 *t_tc,
				     struct virtchnl_queue_select *vqs,
				     struct ice_vsi **vsi_p, u16 *vsi_id,
				     u16 *q_id)
{
	struct ice_vsi *vsi = *vsi_p;
	u32 max_chnl_tc;
	u16 tc = *t_tc;

	max_chnl_tc = ice_vc_get_max_chnl_tc_allowed(vf);

	/* Update the VSI and TC based on per TC queue region and offset */
	if (tc + 1U < max_chnl_tc && vf_q_id == vf->ch[tc + 1].offset &&
	    tc < vf->num_tc && ice_is_vf_adq_ena(vf)) {
		vsi = vf->pf->vsi[vf->ch[tc + 1].vsi_idx];
		tc++;
	}

	/* Update vsi_id and queue_id based on TC if TC is VF ADQ TC, then
	 * use VF ADQ VSI otherwise main VF VSI
	 */
	if (tc >= ICE_VF_CHNL_START_TC && ice_is_vf_adq_ena(vf)) {
		*vsi_id = vsi->vsi_num;
		*q_id = ice_vf_get_tc_based_qid(vf_q_id, vf->ch[tc].offset);
	} else {
		*vsi_id = vqs->vsi_id;
		*q_id = vf_q_id;
	}

	*vsi_p = vsi;
	*t_tc = tc;
}

/**
 * ice_vc_validate_vqs_bitmaps - validate Rx/Tx queue bitmaps from VIRTCHNL
 * @vqs: virtchnl_queue_select structure containing bitmaps to validate
 *
 * Return true on successful validation, else false
 */
static bool ice_vc_validate_vqs_bitmaps(struct virtchnl_queue_select *vqs)
{
	if ((!vqs->rx_queues && !vqs->tx_queues) ||
	    vqs->rx_queues >= BIT(ICE_MAX_DFLT_QS_PER_VF) ||
	    vqs->tx_queues >= BIT(ICE_MAX_DFLT_QS_PER_VF))
		return false;

	return true;
}

/**
 * ice_vf_ena_txq_interrupt - enable Tx queue interrupt via QINT_TQCTL
 * @vsi: VSI of the VF to configure
 * @q_idx: VF queue index used to determine the queue in the PF's space
 */
static void ice_vf_ena_txq_interrupt(struct ice_vsi *vsi, u32 q_idx)
{
	struct ice_hw *hw = &vsi->back->hw;
	u32 pfq = vsi->txq_map[q_idx];
	u32 reg;

	reg = rd32(hw, QINT_TQCTL(pfq));

	/* MSI-X index 0 in the VF's space is always for the OICR, which means
	 * this is most likely a poll mode VF driver, so don't enable an
	 * interrupt that was never configured via VIRTCHNL_OP_CONFIG_IRQ_MAP
	 */
	if (!(reg & QINT_TQCTL_MSIX_INDX_M))
		return;

	wr32(hw, QINT_TQCTL(pfq), reg | QINT_TQCTL_CAUSE_ENA_M);
}

/**
 * ice_vf_ena_rxq_interrupt - enable Tx queue interrupt via QINT_RQCTL
 * @vsi: VSI of the VF to configure
 * @q_idx: VF queue index used to determine the queue in the PF's space
 */
static void ice_vf_ena_rxq_interrupt(struct ice_vsi *vsi, u32 q_idx)
{
	struct ice_hw *hw = &vsi->back->hw;
	u32 pfq = vsi->rxq_map[q_idx];
	u32 reg;

	reg = rd32(hw, QINT_RQCTL(pfq));

	/* MSI-X index 0 in the VF's space is always for the OICR, which means
	 * this is most likely a poll mode VF driver, so don't enable an
	 * interrupt that was never configured via VIRTCHNL_OP_CONFIG_IRQ_MAP
	 */
	if (!(reg & QINT_RQCTL_MSIX_INDX_M))
		return;

	wr32(hw, QINT_RQCTL(pfq), reg | QINT_RQCTL_CAUSE_ENA_M);
}

/**
 * ice_vf_vsi_ena_single_rxq - enable single Rx queue based on relative q_id
 * @vf: VF to enable queue for
 * @vsi: VSI for the VF
 * @q_id: VF/VSI relative (0-based) queue ID
 *
 * Attempt to enable the Rx queue passed in. If the Rx queue was successfully enabled then set
 * q_id bit in the enabled queues bitmap and return success. Otherwise return error.
 */
static int ice_vf_vsi_ena_single_rxq(struct ice_vf *vf, struct ice_vsi *vsi, u16 q_id)
{
	int err;

	if (test_bit(q_id, vf->rxq_ena))
		return 0;

	err = ice_vsi_ctrl_one_rx_ring(vsi, true, q_id, true);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to enable Rx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	ice_vf_ena_rxq_interrupt(vsi, q_id);
	set_bit(q_id, vf->rxq_ena);

	return 0;
}

/**
 * ice_vf_vsi_ena_single_txq - enable single Tx queue based on relative q_id
 * @vf: VF to enable queue for
 * @vsi: VSI for the VF
 * @q_id: VF/VSI relative (0-based) queue ID
 *
 * Enable the Tx queue's interrupt then set the q_id bit in the enabled queues bitmap. Note that the
 * Tx queue(s) should have already been configurated/enabled in VIRTCHNL_OP_CONFIG_QUEUES so this
 * function only enables the interrupt associated with the q_id.
 */
static void ice_vf_vsi_ena_single_txq(struct ice_vf *vf, struct ice_vsi *vsi, u16 q_id)
{
	if (test_bit(q_id, vf->txq_ena))
		return;

	ice_vf_ena_txq_interrupt(vsi, q_id);
	set_bit(q_id, vf->txq_ena);
}

/**
 * ice_vc_ena_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to enable all or specific queue(s)
 */
static int ice_vc_ena_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct ice_vsi *vsi;
	unsigned long q_map;
	u16 vf_q_id = 0;
	u16 tc = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_vqs_bitmaps(vqs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* Enable only Rx rings, Tx rings were enabled by the FW when the
	 * Tx queue group list was configured and the context bits were
	 * programmed using ice_vsi_cfg_txqs
	 */
	q_map = vqs->rx_queues;
	for_each_set_bit(vf_q_id, &q_map, ICE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_id, q_id;

		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
					 &vsi_id, &q_id);
		if (ice_is_vf_adq_ena(vf) && tc >= ICE_VF_CHNL_START_TC) {
			if (!ice_vf_adq_vsi_valid(vf, tc)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		if (!ice_vc_isvalid_q_id(vf, vsi_id, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (ice_vf_vsi_ena_single_rxq(vf, vsi, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	}

	tc = 0;
	vsi = ice_get_vf_vsi(vf);
	q_map = vqs->tx_queues;
	for_each_set_bit(vf_q_id, &q_map, ICE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_id, q_id;

		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
					 &vsi_id, &q_id);
		if (ice_is_vf_adq_ena(vf) && tc >= ICE_VF_CHNL_START_TC) {
			if (!ice_vf_adq_vsi_valid(vf, tc)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		if (!ice_vc_isvalid_q_id(vf, vsi_id, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		ice_vf_vsi_ena_single_txq(vf, vsi, q_id);
	}

	/* Set flag to indicate that queues are enabled */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS)
		set_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_vf_vsi_dis_single_txq - disable a single Tx queue for the VF based on relative queue ID
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VF/VSI relative (0-based) queue ID
 *
 * Attempt to disable the Tx queue passed in. If the Tx queue was successfully disabled then clear
 * q_id bit in the enabled queues bitmap and return success. Otherwise return error.
 */
static int ice_vf_vsi_dis_single_txq(struct ice_vf *vf, struct ice_vsi *vsi, u16 q_id)
{
	struct ice_txq_meta txq_meta = { 0 };
	struct ice_ring *ring;
	int err;

	/* Skip queue if not enabled */
	if (!test_bit(q_id, vf->txq_ena))
		return 0;

	ring = vsi->tx_rings[q_id];
	if (!ring)
		return -EINVAL;

	ice_fill_txq_meta(vsi, ring, &txq_meta);

	err = ice_vsi_stop_tx_ring(vsi, ICE_NO_RESET, vf->vf_id, ring, &txq_meta);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Tx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	/* Clear enabled queues flag */
	clear_bit(q_id, vf->txq_ena);

	return 0;
}

/**
 * ice_vf_vsi_dis_single_txq - disable a single Tx queue for the VF based on relative queue ID
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VF/VSI relative (0-based) queue ID
 *
 * Attempt to disable the Rx queue passed in. If the Rx queue was successfully disabled then clear
 * q_id bit in the enabled queues bitmap and return success. Otherwise return error.
 */

static int ice_vf_vsi_dis_single_rxq(struct ice_vf *vf, struct ice_vsi *vsi, u16 q_id)
{
	int err;

	if (!test_bit(q_id, vf->rxq_ena))
		return 0;

	err = ice_vsi_ctrl_one_rx_ring(vsi, false, q_id, true);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Rx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	/* Clear enabled queues flag */
	clear_bit(q_id, vf->rxq_ena);

	return 0;
}

/**
 * ice_vc_dis_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to disable all or specific
 * queue(s)
 */
static int ice_vc_dis_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct ice_vsi *vsi;
	unsigned long q_map;
	u16 vf_q_id = 0;
	u16 tc = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) &&
	    !test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_vqs_bitmaps(vqs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vqs->tx_queues) {
		q_map = vqs->tx_queues;

		for_each_set_bit(vf_q_id, &q_map, ICE_MAX_DFLT_QS_PER_VF) {
			u16 vsi_id, q_id;

			ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
						 &vsi_id, &q_id);
			if (ice_is_vf_adq_ena(vf) &&
			    tc >= ICE_VF_CHNL_START_TC) {
				if (!ice_vf_adq_vsi_valid(vf, tc)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}

			if (!ice_vc_isvalid_q_id(vf, vsi_id, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (ice_vf_vsi_dis_single_txq(vf, vsi, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	q_map = vqs->rx_queues;
	tc = 0;
	/* Reset VSI pointer as it was assigned to ADQ VSIs */
	vsi = ice_get_vf_vsi(vf);
	/* speed up Rx queue disable by batching them if possible */
	if (q_map &&
	    bitmap_equal(&q_map, vf->rxq_ena, ICE_MAX_DFLT_QS_PER_VF)) {
		if (ice_vsi_stop_all_rx_rings(vsi)) {
			dev_err(ice_pf_to_dev(vsi->back), "Failed to stop all Rx rings on VSI %d\n",
				vsi->vsi_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
		if (ice_is_vf_adq_ena(vf)) {
			for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
				vsi = ice_get_vf_adq_vsi(vf, tc);
				if (ice_vsi_stop_all_rx_rings(vsi)) {
					dev_err(ice_pf_to_dev(vsi->back),
						"Failed to stop all Rx rings on VF ADQ VSI %d\n",
						vsi->vsi_num);
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}
		}
		bitmap_zero(vf->rxq_ena, ICE_MAX_DFLT_QS_PER_VF);
	} else if (q_map) {
		for_each_set_bit(vf_q_id, &q_map, ICE_MAX_DFLT_QS_PER_VF) {
			u16 vsi_id, q_id;

			ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
						 &vsi_id, &q_id);
			if (ice_is_vf_adq_ena(vf) &&
			    tc >= ICE_VF_CHNL_START_TC) {
				if (!ice_vf_adq_vsi_valid(vf, tc)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}
			if (!ice_vc_isvalid_q_id(vf, vsi_id, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (ice_vf_vsi_dis_single_rxq(vf, vsi, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	/* Clear enabled queues flag */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS && ice_vf_has_no_qs_ena(vf))
		clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_cfg_interrupt
 * @vf: pointer to the VF info
 * @vsi: the VSI being configured
 * @vector_id: vector ID
 * @tc: traffic class number for ADQ
 * @map: vector map for mapping vectors to queues
 * @q_vector: structure for interrupt vector
 * configure the IRQ to queue map
 */
static int
ice_cfg_interrupt(struct ice_vf *vf, struct ice_vsi *vsi, u16 vector_id,
		  u8 __maybe_unused tc, struct virtchnl_vector_map *map,
		  struct ice_q_vector *q_vector)
{
	unsigned long qmap;
	u16 vsi_q_id_idx;

	q_vector->num_ring_rx = 0;
	q_vector->num_ring_tx = 0;

	qmap = map->rxq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, ICE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_q_id = vsi_q_id_idx;

		if (tc && ice_is_vf_adq_ena(vf))
			vsi_q_id = ice_vf_get_tc_based_qid(vsi_q_id_idx,
							   vf->ch[tc].offset);

		if (!ice_vc_isvalid_q_id(vf, vsi->vsi_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_rx++;
		q_vector->rx.itr_idx = map->rxitr_idx;
		vsi->rx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_rxq_interrupt(vsi, vsi_q_id, vector_id,
				      q_vector->rx.itr_idx);
	}

	qmap = map->txq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, ICE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_q_id = vsi_q_id_idx;

		if (tc && ice_is_vf_adq_ena(vf))
			vsi_q_id = ice_vf_get_tc_based_qid(vsi_q_id_idx,
							   vf->ch[tc].offset);

		if (!ice_vc_isvalid_q_id(vf, vsi->vsi_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_tx++;
		q_vector->tx.itr_idx = map->txitr_idx;
		vsi->tx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_txq_interrupt(vsi, vsi_q_id, vector_id,
				      q_vector->tx.itr_idx);
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_vc_cfg_irq_map_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the IRQ to queue map
 */
static int ice_vc_cfg_irq_map_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_irq_map_info *irqmap_info;
	struct virtchnl_vector_map *map;
	struct ice_pf *pf = vf->pf;
	u16 num_q_vectors_mapped;
	struct ice_vsi *vsi;
	u16 vector_id_ch;
	u16 tc = 0;
	int i;

	irqmap_info = (struct virtchnl_irq_map_info *)msg;
	num_q_vectors_mapped = irqmap_info->num_vectors;

	/* Check to make sure number of VF vectors mapped is not greater than
	 * number of VF vectors originally allocated, and check that
	 * there is actually at least a single VF queue vector mapped
	 */
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    pf->num_msix_per_vf < num_q_vectors_mapped ||
	    !num_q_vectors_mapped) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < num_q_vectors_mapped; i++) {
		struct ice_q_vector *q_vector;
		u16 vsi_id, vector_id;

		map = &irqmap_info->vecmap[i];

		vector_id = map->vector_id;
		vsi_id = map->vsi_id;
		if (ice_is_vf_adq_ena(vf) && tc >= ICE_VF_CHNL_START_TC) {
			if (!ice_vf_adq_vsi_valid(vf, tc)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			vsi_id = vsi->vsi_num;
		}
		/* vector_id is always 0-based for each VF, and can never be
		 * larger than or equal to the max allowed interrupts per VF
		 */
		if (!(vector_id < pf->num_msix_per_vf) ||
		    !ice_vc_isvalid_vsi_id(vf, vsi_id) ||
		    (!vector_id && (map->rxq_map || map->txq_map))) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* No need to map VF miscellaneous or rogue vector */
		if (!vector_id)
			continue;

		/* Subtract non queue vector from vector_id passed by VF
		 * to get actual number of VSI queue vector array index
		 */
		if (tc && ice_is_vf_adq_ena(vf))
			vector_id_ch = vector_id - vf->ch[tc].offset;
		else
			vector_id_ch = vector_id;

		/* if ADQ enablement failed, the main VF VSI could have been
		 * reconfigured (based on TC0 information - means main
		 * VF VSI queues and vectors are equal to TC0.num_qps and
		 * not equal to "num_q_vectors" which is part of
		 * irq_cfg virtchnl message) so prevent using invalid vector ID
		 */
		if ((vector_id_ch - ICE_NONQ_VECS_VF) >= vsi->num_q_vectors) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
		q_vector = vsi->q_vectors[vector_id_ch - ICE_NONQ_VECS_VF];
		if (!q_vector) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* lookout for the invalid queue index */

		v_ret = (enum virtchnl_status_code)
			ice_cfg_interrupt(vf, vsi, vector_id, tc, map,
					  q_vector);
		if (v_ret)
			goto error_param;

		/* Update VSI and TC only when ADQ is configured */
		if (ice_is_vf_adq_ena(vf) &&
		    vector_id == vf->ch[tc + 1].offset) {
			vsi = pf->vsi[vf->ch[tc + 1].vsi_idx];
			tc++;
		}
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_IRQ_MAP, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_get_max_allowed_qpairs - get max allowed queue pairs based on negotiated capabilities
 * @vf: VF used to get max queue pairs allowed
 *
 * The maximum allowed queues is determined based on whether VIRTCHNL_VF_LARGE_NUM_QPAIRS was
 * negotiated.
 */
static int ice_vc_get_max_allowed_qpairs(struct ice_vf *vf)
{
	if (vf->driver_caps & VIRTCHNL_VF_LARGE_NUM_QPAIRS)
		return ICE_MAX_QS_PER_VF;

	return ICE_MAX_DFLT_QS_PER_VF;
}

/**
 * ice_vc_cfg_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the Rx/Tx queues
 */
static int ice_vc_cfg_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vsi_queue_config_info *qci =
	    (struct virtchnl_vsi_queue_config_info *)msg;
	struct virtchnl_queue_pair_info *qpi;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u16 queue_id_tmp, tc;
	int i, q_idx;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, qci->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* check for number of queues is done in ice_alloc_vf_res() function
	 * for ADQ
	 */
	if (ice_is_vf_adq_ena(vf))
		goto skip_num_queues_check;

	if (qci->num_queue_pairs > ice_vc_get_max_allowed_qpairs(vf) ||
	    qci->num_queue_pairs > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(pf), "VF-%d trying to configure more than allocated number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

skip_num_queues_check:
	queue_id_tmp = 0;
	tc = 0;
	for (i = 0; i < qci->num_queue_pairs; i++) {
		qpi = &qci->qpair[i];
		if (ice_is_vf_adq_ena(vf))
			goto skip_non_adq_checks;

		if (qpi->txq.vsi_id != qci->vsi_id ||
		    qpi->rxq.vsi_id != qci->vsi_id ||
		    qpi->rxq.queue_id != qpi->txq.queue_id ||
		    qpi->txq.headwb_enabled ||
		    !ice_vc_isvalid_ring_len(qpi->txq.ring_len) ||
		    !ice_vc_isvalid_ring_len(qpi->rxq.ring_len) ||
		    !ice_vc_isvalid_q_id(vf, qci->vsi_id,
					 qpi->txq.queue_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

skip_non_adq_checks:
		if (ice_is_vf_adq_ena(vf)) {
			q_idx = queue_id_tmp;
			vsi = ice_find_vsi_from_id(vf->pf, vf->ch[tc].vsi_num);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		} else {
			q_idx = qpi->rxq.queue_id;
		}

		/* make sure selected "q_idx" is in valid range of queues
		 * for selected "vsi" (which could be main VF VSI or
		 * VF ADQ VSI
		 */
		if (q_idx >= vsi->alloc_txq || q_idx >= vsi->alloc_rxq) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* copy Tx queue info from VF into VSI */
		if (qpi->txq.ring_len > 0) {
			vsi->tx_rings[q_idx]->dma = qpi->txq.dma_ring_addr;
			vsi->tx_rings[q_idx]->count = qpi->txq.ring_len;
			if (ice_vsi_cfg_single_txq(vsi, vsi->tx_rings, q_idx)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		/* copy Rx queue info from VF into VSI */
		if (qpi->rxq.ring_len > 0) {
			u16 max_frame_size = ice_vc_get_max_frame_size(vf);
			u32 rxdid;

			vsi->rx_rings[q_idx]->dma = qpi->rxq.dma_ring_addr;
			vsi->rx_rings[q_idx]->count = qpi->rxq.ring_len;

			if (qpi->rxq.databuffer_size != 0 &&
			    (qpi->rxq.databuffer_size > ((16 * 1024) - 128) ||
			     qpi->rxq.databuffer_size < 1024)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			vsi->rx_buf_len = qpi->rxq.databuffer_size;
			vsi->rx_rings[q_idx]->rx_buf_len = vsi->rx_buf_len;
			if (qpi->rxq.max_pkt_size > max_frame_size ||
			    qpi->rxq.max_pkt_size < 64) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			vsi->max_frame = qpi->rxq.max_pkt_size;
			/* add space for the port VLAN since the VF driver is not
			 * expected to account for it in the MTU calculation
			 */
			if (vf->port_vlan_info)
				vsi->max_frame += VLAN_HLEN;

			if (ice_vsi_cfg_single_rxq(vsi, q_idx)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* If Rx flex desc is supported, select RXDID for Rx queues.
			 * Otherwise, use legacy 32byte descriptor format.
			 * Legacy 16byte descriptor is not supported. If this RXDID
			 * is selected, return error.
			 */
			if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC) {
				rxdid = qpi->rxq.rxdid;
				if (!(BIT(rxdid) & pf->supported_rxdids)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			} else {
				rxdid = ICE_RXDID_LEGACY_1;
			}

			ice_write_qrxflxp_cntxt(&vsi->back->hw, vsi->rxq_map[q_idx], rxdid, 0x03,
						false);
		}

		/* For ADQ there can be up to 4 VSIs with max 4 queues each.
		 * VF does not know about these additional VSIs and all
		 * it cares is about its own queues. PF configures these queues
		 * to its appropriate VSIs based on TC mapping
		 */
		if (ice_is_vf_adq_ena(vf)) {
			if (queue_id_tmp == (vf->ch[tc].num_qps - 1)) {
				tc++;
				/* reset the queue num */
				queue_id_tmp = 0;
			} else {
				queue_id_tmp++;
			}
		}
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_is_vf_trusted
 * @vf: pointer to the VF info
 */
static bool ice_is_vf_trusted(struct ice_vf *vf)
{
	return test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
}

/**
 * ice_can_vf_change_mac
 * @vf: pointer to the VF info
 *
 * Return true if the VF is allowed to change its MAC filters, false otherwise
 */
static bool ice_can_vf_change_mac(struct ice_vf *vf)
{
	/* If the VF MAC address has been set administratively (via the
	 * ndo_set_vf_mac command), then deny permission to the VF to
	 * add/delete unicast MAC addresses, unless the VF is trusted
	 */
	if (vf->pf_set_mac && !ice_is_vf_trusted(vf))
		return false;

	return true;
}

/**
 * ice_vc_ether_addr_type - get type of virtchnl_ether_addr
 * @vc_ether_addr: used to extract the type
 */
static u8
ice_vc_ether_addr_type(struct virtchnl_ether_addr *vc_ether_addr)
{
	return (vc_ether_addr->type & VIRTCHNL_ETHER_ADDR_TYPE_MASK);
}

/**
 * ice_is_vc_addr_legacy - check if the MAC address is from an older VF
 * @vc_ether_addr: VIRTCHNL structure that contains MAC and type
 */
static bool
ice_is_vc_addr_legacy(struct virtchnl_ether_addr __maybe_unused *vc_ether_addr)
{
	u8 type = ice_vc_ether_addr_type(vc_ether_addr);

	return (type == VIRTCHNL_ETHER_ADDR_LEGACY);
}

/**
 * ice_is_vc_addr_primary - check if the MAC address is the VF's primary MAC
 * @vc_ether_addr: VIRTCHNL structure that contains MAC and type
 *
 * This function should only be called when the MAC address in
 * virtchnl_ether_addr is a valid unicast MAC
 */
static bool
ice_is_vc_addr_primary(struct virtchnl_ether_addr __maybe_unused *vc_ether_addr)
{
	u8 type = ice_vc_ether_addr_type(vc_ether_addr);

	return (type == VIRTCHNL_ETHER_ADDR_PRIMARY);
}

/**
 * ice_vfhw_mac_add - update the VF's cached hardware MAC if allowed
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to add
 */
static void
ice_vfhw_mac_add(struct ice_vf *vf, struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 *mac_addr = vc_ether_addr->addr;

	if (!is_valid_ether_addr(mac_addr))
		return;

	/* only allow legacy VF drivers to set the device and hardware MAC if it
	 * is zero and allow new VF drivers to set the hardware MAC if the type
	 * was correctly specified over VIRTCHNL
	 */
	if ((ice_is_vc_addr_legacy(vc_ether_addr) &&
	     is_zero_ether_addr(vf->hw_lan_addr.addr)) ||
	    ice_is_vc_addr_primary(vc_ether_addr)) {
		ether_addr_copy(vf->dev_lan_addr.addr, mac_addr);
		ether_addr_copy(vf->hw_lan_addr.addr, mac_addr);
	}

	/* hardware and device MACs are already set, but its possible that the
	 * VF driver sent the VIRTCHNL_OP_ADD_ETH_ADDR message before the
	 * VIRTCHNL_OP_DEL_ETH_ADDR when trying to update its MAC, so save it
	 * away for the legacy VF driver case as it will be updated in the
	 * delete flow for this case
	 */
	if (ice_is_vc_addr_legacy(vc_ether_addr)) {
		ether_addr_copy(vf->legacy_last_added_umac.addr,
				mac_addr);
		vf->legacy_last_added_umac.time_modified = jiffies;
	}
}

/**
 * ice_vc_add_mac_addr - attempt to add the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @vc_ether_addr: VIRTCHNL MAC address structure used to add MAC
 */
static int
ice_vc_add_mac_addr(struct ice_vf *vf, struct ice_vsi *vsi,
		    struct virtchnl_ether_addr *vc_ether_addr)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	u8 *mac_addr = vc_ether_addr->addr;
	enum ice_status status;

	/* device MAC already added */
	if (!ether_addr_equal(mac_addr, vf->dev_lan_addr.addr)) {
		if (is_unicast_ether_addr(mac_addr) &&
		    !ice_can_vf_change_mac(vf)) {
			dev_err(dev, "VF attempting to override administratively set MAC address, bring down and up the VF interface to resume normal operation\n");
			return -EPERM;
		}

		status = ice_fltr_add_mac(vsi, mac_addr, ICE_FWD_TO_VSI);
		if (status == ICE_ERR_ALREADY_EXISTS) {
			dev_err(dev, "MAC %pM already exists for VF %d\n", mac_addr, vf->vf_id);
			return -EEXIST;
		} else if (status) {
			dev_err(dev, "Failed to add MAC %pM for VF %d\n, error %s\n", mac_addr,
				vf->vf_id, ice_stat_str(status));
			return -EIO;
		}

		ice_vfhw_mac_add(vf, vc_ether_addr);

		vf->num_mac++;
	}

	return 0;
}

/**
 * ice_is_legacy_umac_expired - check if last added legacy unicast MAC expired
 * @last_added_umac: structure used to check expiration
 */
static bool ice_is_legacy_umac_expired(struct ice_time_mac *last_added_umac)
{
#define ICE_LEGACY_VF_MAC_CHANGE_EXPIRE_TIME	msecs_to_jiffies(3000)
	return time_is_before_jiffies(last_added_umac->time_modified +
				      ICE_LEGACY_VF_MAC_CHANGE_EXPIRE_TIME);
}

/**
 * ice_vfhw_mac_del - update the VF's cached hardware MAC if allowed
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to delete
 */
static void
ice_vfhw_mac_del(struct ice_vf *vf, struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 *mac_addr = vc_ether_addr->addr;

	if (!is_valid_ether_addr(mac_addr) ||
	    !ether_addr_equal(vf->dev_lan_addr.addr, mac_addr))
		return;

	/* allow the device MAC to be repopulated in the add flow and don't
	 * clear the hardware MAC (i.e. hw_lan_addr.addr) here as that is meant
	 * to be persistent on VM reboot and across driver unload/load, which
	 * won't work if we clear the hardware MAC here
	 */
	eth_zero_addr(vf->dev_lan_addr.addr);

	/* only update cached hardware MAC for legacy VF drivers on delete
	 * because we cannot guarantee order/type of MAC from the VF driver
	 */
	if (ice_is_vc_addr_legacy(vc_ether_addr) &&
	    !ice_is_legacy_umac_expired(&vf->legacy_last_added_umac)) {
		ether_addr_copy(vf->dev_lan_addr.addr,
				vf->legacy_last_added_umac.addr);
		ether_addr_copy(vf->hw_lan_addr.addr,
				vf->legacy_last_added_umac.addr);
	}
}

/**
 * ice_vc_del_mac_addr - attempt to delete the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @vc_ether_addr: VIRTCHNL MAC address structure used to delete MAC
 */
static int
ice_vc_del_mac_addr(struct ice_vf *vf, struct ice_vsi *vsi,
		    struct virtchnl_ether_addr *vc_ether_addr)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	u8 *mac_addr = vc_ether_addr->addr;
	enum ice_status status;

	if (!ice_can_vf_change_mac(vf) &&
	    ether_addr_equal(vf->dev_lan_addr.addr, mac_addr))
		return 0;

	status = ice_fltr_remove_mac(vsi, mac_addr, ICE_FWD_TO_VSI);
	if (status == ICE_ERR_DOES_NOT_EXIST) {
		dev_err(dev, "MAC %pM does not exist for VF %d\n", mac_addr,
			vf->vf_id);
		return -ENOENT;
	} else if (status) {
		dev_err(dev, "Failed to delete MAC %pM for VF %d, error %s\n",
			mac_addr, vf->vf_id, ice_stat_str(status));
		return -EIO;
	}


	ice_vfhw_mac_del(vf, vc_ether_addr);

	vf->num_mac--;

	return 0;
}

/**
 * ice_vc_handle_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 * @set: true if MAC filters are being set, false otherwise
 *
 * add guest MAC address filter
 */
static int
ice_vc_handle_mac_addr_msg(struct ice_vf *vf, u8 *msg, bool set)
{
	int (*ice_vc_cfg_mac)
		(struct ice_vf *vf, struct ice_vsi *vsi,
		 struct virtchnl_ether_addr *virtchnl_ether_addr);
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct ice_pf *pf = vf->pf;
	enum virtchnl_ops vc_op;
	struct ice_vsi *vsi;
	int i;

	if (set) {
		vc_op = VIRTCHNL_OP_ADD_ETH_ADDR;
		ice_vc_cfg_mac = ice_vc_add_mac_addr;
	} else {
		vc_op = VIRTCHNL_OP_DEL_ETH_ADDR;
		ice_vc_cfg_mac = ice_vc_del_mac_addr;
	}

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !ice_vc_isvalid_vsi_id(vf, al->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	/* If this VF is not privileged, then we can't add more than a
	 * limited number of addresses. Check to make sure that the
	 * additions do not push us over the limit.
	 */
	if (set && !ice_is_vf_trusted(vf) &&
	    (vf->num_mac + al->num_elements) > ICE_MAX_MACADDR_PER_VF) {
		dev_err(ice_pf_to_dev(pf), "Can't add more MAC addresses, because VF-%d is not trusted, switch the VF to trusted mode in order to add more functionalities\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	for (i = 0; i < al->num_elements; i++) {
		u8 *mac_addr = al->list[i].addr;
		int result;

		if (is_broadcast_ether_addr(mac_addr) ||
		    is_zero_ether_addr(mac_addr))
			continue;

		result = ice_vc_cfg_mac(vf, vsi, &al->list[i]);
		if (result == -EEXIST || result == -ENOENT) {
			continue;
		} else if (result) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto handle_mac_exit;
		}
	}

handle_mac_exit:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, vc_op, v_ret, NULL, 0);
}

/**
 * ice_vc_add_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * add guest MAC address filter
 */
static int ice_vc_add_mac_addr_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_handle_mac_addr_msg(vf, msg, true);
}

/**
 * ice_vc_del_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * remove guest MAC address filter
 */
static int ice_vc_del_mac_addr_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_handle_mac_addr_msg(vf, msg, false);
}

/**
 * ice_vc_request_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * VFs get a default number of queues but can use this message to request a
 * different number. If the request is successful, PF will reset the VF and
 * return 0. If unsuccessful, PF will send message informing VF of number of
 * available queue pairs via virtchnl message response to VF.
 */
static int ice_vc_request_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vf_res_request *vfres =
		(struct virtchnl_vf_res_request *)msg;
	u16 max_avail_vf_qps, max_allowed_vf_qps;
	u16 req_queues = vfres->num_queue_pairs;
	struct ice_pf *pf = vf->pf;
	u16 tx_rx_queue_left;
	struct device *dev;
	u16 cur_queues;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	max_allowed_vf_qps = ice_vc_get_max_allowed_qpairs(vf);

	cur_queues = vf->num_vf_qs;
	tx_rx_queue_left = min_t(u16, ice_get_avail_txq_count(pf),
				 ice_get_avail_rxq_count(pf));
	max_avail_vf_qps = tx_rx_queue_left + cur_queues;
	if (!req_queues) {
		dev_err(dev, "VF %d tried to request 0 queues. Ignoring.\n",
			vf->vf_id);
	} else if (req_queues > max_allowed_vf_qps) {
		dev_err(dev, "VF %d tried to request more than %d queues.\n",
			vf->vf_id, max_allowed_vf_qps);
		vfres->num_queue_pairs = max_allowed_vf_qps;
	} else if (req_queues > cur_queues &&
		   req_queues - cur_queues > tx_rx_queue_left) {
		dev_warn(dev, "VF %d requested %u more queues, but only %u left.\n",
			 vf->vf_id, req_queues - cur_queues, tx_rx_queue_left);
		vfres->num_queue_pairs = min_t(u16, max_avail_vf_qps, max_allowed_vf_qps);
	} else {
		/* request is successful, then reset VF */
		vf->num_req_qs = req_queues;
		ice_vc_reset_vf(vf);
		dev_info(dev, "VF %d granted request of %u queues.\n",
			 vf->vf_id, req_queues);
		return 0;
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_REQUEST_QUEUES,
				     v_ret, (u8 *)vfres, sizeof(*vfres));
}

#ifdef IFLA_VF_VLAN_INFO_MAX
/**
 * ice_set_vf_port_vlan
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 */
int
ice_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto)
#else
int
ice_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos)
#endif /* IFLA_VF_VLAN_INFO_MAX */
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct device *dev;
	struct ice_vf *vf;
	u16 vlanprio;
	int ret;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		dev_err(dev, "Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

#ifdef IFLA_VF_VLAN_INFO_MAX
	if (vlan_proto != htons(ETH_P_8021Q)) {
		dev_err(dev, "VF VLAN protocol is not supported\n");
		return -EPROTONOSUPPORT;
	}
#endif

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	vlanprio = vlan_id | (qos << VLAN_PRIO_SHIFT);

	if (vf->port_vlan_info == vlanprio) {
		/* duplicate request, so just return success */
		dev_dbg(dev, "Duplicate pvid %d request\n", vlanprio);
		return 0;
	}

	vf->port_vlan_info = vlanprio;

	if (vf->port_vlan_info)
		dev_info(dev, "Setting VLAN %d, QoS 0x%x on VF %d\n",
			 vlan_id, qos, vf_id);
	else
		dev_info(dev, "Clearing port VLAN on VF %d\n", vf_id);

	ice_vc_reset_vf(vf);

	return 0;
}

/**
 * ice_vf_vlan_offload_ena - determine if capabilities support VLAN offloads
 * @caps: VF driver negotiated capabilities
 *
 * Return true if VIRTCHNL_VF_OFFLOAD_VLAN capability is set, else return false
 */
static bool ice_vf_vlan_offload_ena(u32 caps)
{
	return !!(caps & VIRTCHNL_VF_OFFLOAD_VLAN);
}

/**
 * ice_vc_process_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 * @add_v: Add VLAN if true, otherwise delete VLAN
 *
 * Process virtchnl op to add or remove programmed guest VLAN ID
 */
static int ice_vc_process_vlan_msg(struct ice_vf *vf, u8 *msg, bool add_v)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_filter_list *vfl =
	    (struct virtchnl_vlan_filter_list *)msg;
	struct ice_pf *pf = vf->pf;
	bool vlan_promisc = false;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	int status = 0;
	u8 promisc_m;
	u8 lport;
	int i;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vfl->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < vfl->num_elements; i++) {
		if (vfl->vlan_id[i] >= VLAN_N_VID) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			dev_err(dev, "invalid VF VLAN id %d\n",
				vfl->vlan_id[i]);
			goto error_param;
		}
	}

	hw = &pf->hw;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (add_v && !ice_is_vf_trusted(vf) &&
	    vsi->num_vlan >= ICE_MAX_VLAN_PER_VF) {
		dev_info(dev, "VF-%d is not trusted, switch the VF to trusted mode, in order to add more VLAN addresses\n",
			 vf->vf_id);
		/* There is no need to let VF know about being not trusted,
		 * so we can just return success message here
		 */
		goto error_param;
	}

	if (vsi->info.pvid) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if ((test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	     test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) &&
	    test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags))
		vlan_promisc = true;

	lport = vsi->port_info->lport;
	if (add_v) {
		for (i = 0; i < vfl->num_elements; i++) {
			u16 vid = vfl->vlan_id[i];

			if (!ice_is_vf_trusted(vf) &&
			    vsi->num_vlan >= ICE_MAX_VLAN_PER_VF) {
				dev_info(dev, "VF-%d is not trusted, switch the VF to trusted mode, in order to add more VLAN addresses\n",
					 vf->vf_id);
				/* There is no need to let VF know about being
				 * not trusted, so we can just return success
				 * message here as well.
				 */
				goto error_param;
			}

			/* we add VLAN 0 by default for each VF so we can enable
			 * Tx VLAN anti-spoof without triggering MDD events so
			 * we don't need to add it again here
			 */
			if (!vid)
				continue;

			status = vsi->vlan_ops.add_vlan(vsi,
							ICE_VLAN(ETH_P_8021Q, vid, 0,
								 ICE_FWD_TO_VSI));
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Enable VLAN pruning when non-zero VLAN is added */
			if (!vlan_promisc && vid &&
			    !ice_vsi_is_vlan_pruning_ena(vsi)) {
				status = ice_cfg_vlan_pruning(vsi, true, false);
				if (status) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					dev_err(dev, "Enable VLAN pruning on VLAN ID: %d failed error-%d\n",
						vid, status);
					goto error_param;
				}
			} else if (vlan_promisc) {
				/* Enable Ucast/Mcast VLAN promiscuous mode */
				promisc_m = ICE_PROMISC_VLAN_TX |
					    ICE_PROMISC_VLAN_RX;

				status = ice_fltr_set_vsi_promisc(hw, vsi->idx,
								  promisc_m,
								  vid, lport);
				if (status) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					dev_err(dev, "Enable Unicast/multicast promiscuous mode on VLAN ID:%d failed error-%d\n",
						vid, status);
				}
			}
		}
	} else {
		/* In case of non_trusted VF, number of VLAN elements passed
		 * to PF for removal might be greater than number of VLANs
		 * filter programmed for that VF - So, use actual number of
		 * VLANS added earlier with add VLAN opcode. In order to avoid
		 * removing VLAN that doesn't exist, which result to sending
		 * erroneous failed message back to the VF
		 */
		int num_vf_vlan;

		num_vf_vlan = vsi->num_vlan;
		for (i = 0; i < vfl->num_elements && i < num_vf_vlan; i++) {
			u16 vid = vfl->vlan_id[i];

			/* we add VLAN 0 by default for each VF so we can enable
			 * Tx VLAN anti-spoof without triggering MDD events so
			 * we don't want a VIRTCHNL request to remove it
			 */
			if (!vid)
				continue;

			status = vsi->vlan_ops.del_vlan(vsi,
							ICE_VLAN(ETH_P_8021Q, vid, 0,
								 ICE_FWD_TO_VSI));
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Disable VLAN pruning when only VLAN 0 is left */
			if (vsi->num_vlan == 1 &&
			    ice_vsi_is_vlan_pruning_ena(vsi))
				ice_cfg_vlan_pruning(vsi, false, false);

			/* Disable Unicast/Multicast VLAN promiscuous mode */
			if (vlan_promisc) {
				promisc_m = ICE_PROMISC_VLAN_TX |
					    ICE_PROMISC_VLAN_RX;

				ice_fltr_clear_vsi_promisc(hw, vsi->idx,
							   promisc_m, vid,
							   lport);
			}
		}
	}

error_param:
	/* send the response to the VF */
	if (add_v)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_VLAN, v_ret,
					     NULL, 0);
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_VLAN, v_ret,
					     NULL, 0);
}

/**
 * ice_vc_add_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Add and program guest VLAN ID
 */
static int ice_vc_add_vlan_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_process_vlan_msg(vf, msg, true);
}

/**
 * ice_vc_remove_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * remove programmed guest VLAN ID
 */
static int ice_vc_remove_vlan_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_process_vlan_msg(vf, msg, false);
}

/**
 * ice_vc_ena_vlan_stripping
 * @vf: pointer to the VF info
 *
 * Enable VLAN header stripping for a given VF
 */
static int ice_vc_ena_vlan_stripping(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (vsi->vlan_ops.ena_stripping(vsi, ETH_P_8021Q))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_dis_vlan_stripping
 * @vf: pointer to the VF info
 *
 * Disable VLAN header stripping for a given VF
 */
static int ice_vc_dis_vlan_stripping(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vsi->vlan_ops.dis_stripping(vsi))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_get_rss_hena - return the RSS HENA bits allowed by the hardware
 * @vf: pointer to the VF info
 */
static int ice_vc_get_rss_hena(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_hena *vrh = NULL;
	int len = 0, ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		dev_err(ice_pf_to_dev(vf->pf), "RSS not supported by PF\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_rss_hena);
	vrh = kzalloc(len, GFP_KERNEL);
	if (!vrh) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	vrh->hena = ICE_DEFAULT_RSS_HENA;
err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_RSS_HENA_CAPS, v_ret,
				    (u8 *)vrh, len);
	kfree(vrh);
	return ret;
}

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_validate_cloud_filter
 * @vf: pointer to the VF info
 * @tc_filter: pointer to virtchnl_filter
 *
 * This function validates cloud filter programmed as TC filter for ADQ
 */
static int
ice_validate_cloud_filter(struct ice_vf *vf, struct virtchnl_filter *tc_filter)
{
	struct virtchnl_l4_spec mask = tc_filter->mask.tcp_spec;
	struct virtchnl_l4_spec data = tc_filter->data.tcp_spec;
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!tc_filter->action) {
		dev_err(dev, "VF %d: Currently ADQ doesn't support Drop Action\n",
			vf->vf_id);
		return -EOPNOTSUPP;
	}

	/* Check filter if it's programmed for advanced mode or basic mode.
	 * There are two ADQ modes (for VF only),
	 * 1. Basic mode: intended to allow as many filter options as possible
	 *		  to be added to a VF in Non-trusted mode. Main goal is
	 *		  to add filters to its own MAC and VLAN ID.
	 * 2. Advanced mode: is for allowing filters to be applied other than
	 *		  its own MAC or VLAN. This mode requires the VF to be
	 *		  Trusted.
	 */
	if (mask.dst_mac[0] && !mask.dst_ip[0]) {
		/* As of now supporting, MAC filter if MAC address is the
		 * default LAN addr for this VF
		 */
		if (!ice_mac_fltr_exist(&pf->hw, data.dst_mac,
					vf->lan_vsi_idx)) {
			dev_err(dev, "Destination MAC %pM doesn't belong to VF %d\n",
				data.dst_mac, vf->vf_id);
			return -EINVAL;
		}
	} else if (!test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		/* Check if VF is trusted */
		dev_err(dev, "VF %d not trusted, make VF trusted to add ADQ filters\n",
			vf->vf_id);
		return -EOPNOTSUPP;
	}

	if (mask.dst_mac[0] & data.dst_mac[0]) {
		if (is_broadcast_ether_addr(data.dst_mac) ||
		    is_zero_ether_addr(data.dst_mac)) {
			dev_err(dev, "VF %d: Invalid Dest MAC addr %pM\n",
				vf->vf_id, data.dst_mac);
			return -EINVAL;
		}
	}

	if (mask.src_mac[0] & data.src_mac[0]) {
		if (is_broadcast_ether_addr(data.src_mac) ||
		    is_zero_ether_addr(data.src_mac)) {
			dev_err(dev, "VF %d: Invalid Source MAC addr %pM\n",
				vf->vf_id, data.src_mac);
			return -EINVAL;
		}
	}

	if (mask.dst_port & data.dst_port) {
		if (!data.dst_port) {
			dev_err(dev, "VF %d: Invalid Dest port\n", vf->vf_id);
			return -EINVAL;
		}
	}

	if (mask.src_port & data.src_port) {
		if (!data.src_port) {
			dev_err(dev, "VF %d: Invalid Source port\n", vf->vf_id);
			return -EINVAL;
		}
	}

	if (mask.vlan_id & data.vlan_id) {
		if (ntohs(data.vlan_id) >= VLAN_N_VID) {
			dev_err(dev, "VF %d: invalid VLAN ID\n", vf->vf_id);
			return -EINVAL;
		}
		/* Validate VLAN for the VF the same way we do for the PF */
		if (!ice_vlan_fltr_exist(&pf->hw, ntohs(data.vlan_id),
					 vf->lan_vsi_idx)) {
			dev_err(dev, "specified VLAN %u doesn't belong to this VF %d\n",
				ntohs(data.vlan_id), vf->vf_id);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * ice_get_tc_flower_fltr - locate the TC flower filter
 * @vf: pointer to the VF info
 * @fltr: pointer to the tc_flower filter
 * @mask: ptr to filter mask (representing filter data specification)
 *
 * This function is used to locate specific filter in filter list. It returns
 * NULL if unable to locate such filter otherwise returns found filter
 */
static struct ice_tc_flower_fltr *
ice_get_tc_flower_fltr(struct ice_vf *vf, struct ice_tc_flower_fltr *fltr,
		       struct virtchnl_l4_spec *mask)
{
	struct ice_tc_flower_lyr_2_4_hdrs *hdrs;
	struct ice_tc_l2_hdr *l2_key;
	struct ice_tc_l3_hdr *l3_key;
	struct ice_tc_l4_hdr *l4_key;
	struct ice_tc_flower_fltr *f;
	struct hlist_node *node;

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return NULL;

	l2_key = &hdrs->l2_key;
	l3_key = &hdrs->l3_key;
	l4_key = &hdrs->l4_key;

	hlist_for_each_entry_safe(f, node,
				  &vf->tc_flower_fltr_list, tc_flower_node) {
		struct ice_tc_flower_lyr_2_4_hdrs *f_hdrs;

		if (!f->dest_vsi || fltr->dest_vsi != f->dest_vsi ||
		    fltr->dest_vsi->idx != f->dest_vsi->idx)
			continue;

		f_hdrs = &f->outer_headers;

		/* handle L2 fields if specified and do not match */
		if ((mask->src_mac[0] &&
		     !ether_addr_equal(l2_key->src_mac,
		     f_hdrs->l2_key.src_mac)) ||
		    (mask->dst_mac[0] &&
		     !ether_addr_equal(l2_key->dst_mac,
		     f_hdrs->l2_key.dst_mac)))
			continue;

		/* handle VLAN if specified and do not match  */
		if (mask->vlan_id && hdrs->vlan_hdr.vlan_id !=
		    f_hdrs->vlan_hdr.vlan_id)
			continue;

		/* handle L3 IPv4 if specified and do not match
		 * for ipv4 data to be valid, check only first dword of mask
		 */
		if (l2_key->n_proto == ETH_P_IP)
			if ((mask->dst_ip[0] &&
			     l3_key->dst_ipv4 != f_hdrs->l3_key.dst_ipv4) ||
			    (mask->src_ip[0] &&
			     l3_key->src_ipv4 != f_hdrs->l3_key.src_ipv4))
				continue;

		/* handle L3 IPv6 if specified and do not match
		 * for ipv6 to be valid, last dword from mask must be valid
		 * hence check only last dword of mask
		 */
		if (l2_key->n_proto == ETH_P_IPV6 && mask->dst_ip[3])
			if (memcmp(&l3_key->ip.v6.dst_ip6,
				   &f_hdrs->l3_key.ip.v6.dst_ip6,
				   sizeof(l3_key->ip.v6.dst_ip6)))
				continue;
		if (l2_key->n_proto == ETH_P_IPV6 && mask->src_ip[3])
			if (memcmp(&l3_key->ip.v6.src_ip6,
				   &f_hdrs->l3_key.ip.v6.src_ip6,
				   sizeof(l3_key->ip.v6.src_ip6)))
				continue;

		/* make sure "ip_proto" is same */
		if (l3_key->ip_proto != f_hdrs->l3_key.ip_proto)
			continue;

		/* handle L4 fields if specified and do not match */
		if ((mask->dst_port &&
		     l4_key->dst_port != f_hdrs->l4_key.dst_port) ||
		    (mask->src_port &&
		     l4_key->src_port != f_hdrs->l4_key.src_port))
			continue;

		/* if reached here, means found matching filter entry */
		return f;
	}

	return NULL;
}

/**
 * ice_vc_chnl_fltr_state_verify - verify general state of VF
 * @vf: pointer to the VF info
 * @vcf: pointer to virtchannel_filter
 *
 * This function performs general validation including validation of filter
 * message and content
 */
static enum virtchnl_status_code
ice_vc_chnl_fltr_state_verify(struct ice_vf *vf, struct virtchnl_filter *vcf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u32 max_tc_allowed;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		return VIRTCHNL_STATUS_ERR_PARAM;

	if (!ice_is_vf_adq_ena(vf)) {
		dev_err(dev, "VF %d: ADQ is not enabled, can't apply switch filter\n",
			vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "VF %d: No corresponding VF VSI\n", vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	max_tc_allowed = ice_vc_get_max_chnl_tc_allowed(vf);
	if (vcf->action == VIRTCHNL_ACTION_TC_REDIRECT &&
	    vcf->action_meta >= max_tc_allowed) {
		dev_err(dev, "VF %d: Err: action(%u)_meta(TC): %u >= max_tc_allowed (%u)\n",
			vf->vf_id, vcf->action, vcf->action_meta,
			max_tc_allowed);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* enforce supported flow_type based on negotiated capability */
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2) {
		if (!(vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_TCP_V6_FLOW ||
		      vcf->flow_type == VIRTCHNL_UDP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_UDP_V6_FLOW)) {
			dev_err(ice_pf_to_dev(pf), "VF %d: Invalid input/s, unsupported flow_type %u\n",
				vf->vf_id, vcf->flow_type);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}
	} else {
		if (!(vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_TCP_V6_FLOW)){
			dev_err(ice_pf_to_dev(pf), "VF %d: Invalid input/s, unsupported flow_type %u\n",
				vf->vf_id, vcf->flow_type);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}
	}

	if (ice_validate_cloud_filter(vf, vcf)) {
		dev_err(dev, "VF %d: Invalid input/s, can't apply switch filter\n",
			vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* filter state fully verified, return SUCCESS */
	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_setup_fltr - populate fields in TC flower filter structure
 * @vf: ptr to VF
 * @vcf: ptr to virt channel message
 * @fltr: pointer to the TC filter structure
 * @dest_vsi: pointer to destination VSI for filter
 * @tc_class: TC number when action type to FWD_TO_VSI, counter index when
 *	      action is count, queue number when action is FWD_TO_QUEUE,
 *	      queue group ID when action is FWD_TO_QGRP
 */
static void
ice_setup_fltr(struct ice_vf *vf, struct ice_tc_flower_fltr *fltr,
	       struct virtchnl_filter *vcf, struct ice_vsi *dest_vsi,
	       int tc_class)
{
	struct virtchnl_l4_spec *mask = &vcf->mask.tcp_spec;
	struct virtchnl_l4_spec *tcf = &vcf->data.tcp_spec;
	struct ice_tc_flower_lyr_2_4_hdrs *hdrs;

	memset(fltr, 0, sizeof(*fltr));

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return;

	/* copy L2 MAC address and MAC mask */
	ether_addr_copy(hdrs->l2_key.dst_mac, tcf->dst_mac);
	ether_addr_copy(hdrs->l2_mask.dst_mac, mask->dst_mac);
	if (!is_zero_ether_addr(hdrs->l2_key.dst_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;

	/* copy L2 source address and MAC mask */
	ether_addr_copy(hdrs->l2_key.src_mac, tcf->src_mac);
	ether_addr_copy(hdrs->l2_mask.src_mac, mask->src_mac);
	if (!is_zero_ether_addr(hdrs->l2_key.src_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_MAC;

	/* copy VLAN info */
	hdrs->vlan_hdr.vlan_id = mask->vlan_id & tcf->vlan_id;
	if (hdrs->vlan_hdr.vlan_id)
		fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;

	/* copy L4 fields */
	hdrs->l4_key.dst_port = mask->dst_port & tcf->dst_port;
	hdrs->l4_mask.dst_port = mask->dst_port;
	if (hdrs->l4_key.dst_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_DEST_L4_PORT;

	hdrs->l4_key.src_port = mask->src_port & tcf->src_port;
	hdrs->l4_mask.src_port = mask->src_port;
	if (hdrs->l4_key.src_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_L4_PORT;

	/* copy L3 fields, IPv4[6] */
	if (vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
	    vcf->flow_type == VIRTCHNL_UDP_V4_FLOW) {
		struct ice_tc_l3_hdr *key, *msk;

		key = &hdrs->l3_key;
		msk = &hdrs->l3_mask;

		/* set n_proto based on flow_type */
		hdrs->l2_key.n_proto = ETH_P_IP;
		if (mask->dst_ip[0] & tcf->dst_ip[0]) {
			key->dst_ipv4 = tcf->dst_ip[0];
			msk->dst_ipv4 = mask->dst_ip[0];
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV4;
		}
		if (mask->src_ip[0] & tcf->src_ip[0]) {
			key->src_ipv4 = tcf->src_ip[0];
			msk->src_ipv4 = mask->src_ip[0];
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV4;
		}
	} else if (vcf->flow_type == VIRTCHNL_TCP_V6_FLOW ||
		   vcf->flow_type == VIRTCHNL_UDP_V6_FLOW) {
		struct ice_tc_l3_hdr *key, *msk;

		key = &hdrs->l3_key;
		msk = &hdrs->l3_mask;

		/* set n_proto based on flow_type */
		hdrs->l2_key.n_proto = ETH_P_IPV6;
		if (mask->dst_ip[3] & tcf->dst_ip[3]) {
			memcpy(&key->ip.v6.dst_ip6, tcf->dst_ip,
			       sizeof(key->ip.v6.dst_ip6));
			memcpy(&msk->ip.v6.dst_ip6, mask->dst_ip,
			       sizeof(msk->ip.v6.dst_ip6));
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV6;
		}
		if (mask->src_ip[3] & tcf->src_ip[3]) {
			memcpy(&key->ip.v6.src_ip6, tcf->src_ip,
			       sizeof(key->ip.v6.src_ip6));
			memcpy(&msk->ip.v6.src_ip6, mask->src_ip,
			       sizeof(msk->ip.v6.src_ip6));
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV6;
		}
	}

	/* get the VSI to which the TC belongs to */
	fltr->dest_vsi = dest_vsi;
	if (vcf->action == VIRTCHNL_ACTION_TC_REDIRECT)
		fltr->action.fltr_act = ICE_FWD_TO_VSI;
	else
		fltr->action.fltr_act = ICE_DROP_PACKET;

	/* make sure to include VF's MAC address when adding ADQ filter */
	if ((!(fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)) &&
	    fltr->action.fltr_act == ICE_FWD_TO_VSI) {
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
		ether_addr_copy(hdrs->l2_key.dst_mac, vf->dev_lan_addr.addr);
		eth_broadcast_addr(hdrs->l2_mask.dst_mac);
	}

	/* 'tc_class' could be TC/QUEUE/QUEUE_GRP number */
	fltr->action.tc_class = tc_class;

	/* must to set the tunnel_type to be INVALID, otherwise if left as zero,
	 * it gets treated as VxLAN tunnel since definition of VxLAN tunnel
	 * type is zero
	 */
	fltr->tunnel_type = TNL_LAST;

	/* set ip_proto in headers based on flow_type which is part of VIRTCHNL
	 * message, "add filter"
	 */
	if (vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
	    vcf->flow_type == VIRTCHNL_TCP_V6_FLOW)
		hdrs->l3_key.ip_proto = IPPROTO_TCP;
	else
		hdrs->l3_key.ip_proto = IPPROTO_UDP;
}

/**
 * ice_vc_del_switch_filter
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * This function deletes a cloud filter programmed as TC filter for ADQ
 */
static int ice_vc_del_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct virtchnl_l4_spec *mask = &vcf->mask.tcp_spec;
	struct ice_rule_query_data rule;
	enum virtchnl_status_code v_ret;
	struct ice_tc_flower_fltr fltr;
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *dest_vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	/* Advanced switch filters and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. Advanced switch filters cannot be deleted.\n");
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	v_ret = ice_vc_chnl_fltr_state_verify(vf, vcf);
	if (v_ret) {
		dev_err(dev, "VF %d: failed to verify ADQ state during filter message processing\n",
			vf->vf_id);
		goto err;
	}

	dest_vsi = pf->vsi[vf->ch[vcf->action_meta].vsi_idx];

	/* prepare the TC flower filter based on input */
	ice_setup_fltr(vf, &fltr, vcf, dest_vsi, vcf->action_meta);

	/* locate the filter in VF tc_flower filter list */
	f = ice_get_tc_flower_fltr(vf, &fltr, mask);
	if (!f) {
		dev_err(dev, "VF %d: Invalid input/s, unable to locate filter due to mismatch\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Deleting TC filter */
	rule.rid = f->rid;
	rule.rule_id = f->rule_id;
	rule.vsi_handle = f->dest_id;
	err = ice_rem_adv_rule_by_id(&pf->hw, &rule);
	if (err) {
		dev_err(dev, "VF %d: Failed to delete switch filter for tc %u, err %d\n",
			vf->vf_id, vcf->action_meta, err);
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		goto err;
	}

	/* book-keeping and update filter type if filter count reached zero */
	dest_vsi->num_chnl_fltr--;

	/* reset filter type for channel if channel filter
	 * count reaches zero
	 */
	if (!dest_vsi->num_chnl_fltr)
		vf->ch[vcf->action_meta].fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;

	hlist_del(&f->tc_flower_node);
	devm_kfree(dev, f);
	if (f->flags & ICE_TC_FLWR_FIELD_DST_MAC)
		vf->num_dmac_chnl_fltrs--;
	v_ret = VIRTCHNL_STATUS_SUCCESS;
err:
	/* send the response back to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_CLOUD_FILTER, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_add_switch_filter
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * This function adds a switch filter programmed as TC filter for ADQ
 *
 * General info about filtering mode:
 * VF ADQ has two different modes when it comes to applying the switch
 * filters
 * 1. basic mode: only dst MAC and dst VLAN filters supported
 * 2. advanced mode: all combination of filters including dst MAC and
 *			dst VLAN ex:
 *	a. dst IP + dst PORT
 *	b. dst MAC + src PORT
 *	c. dst MAC + dst PORT
 * basic mode is for 'untrusted VFs' and advanced mode is only for
 * 'trusted VFs'. When a VF is toggled from being 'trusted' to
 * 'untrusted' we remove all filters irrespective if it's basic or
 * advanced.
 * when ADQ is enabled we need to do ice_down irrespective if VF is
 * 'trusted' or not and delete switch filters only if a 'trusted' VF
 * is made 'untrusted'.
 */
static int ice_vc_add_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct ice_tc_flower_fltr *fltr = NULL;
	enum virtchnl_status_code v_ret;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *dest_vsi;
	struct device *dev;
	int ret;

	dev = ice_pf_to_dev(pf);
	/* Advanced switch filters and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. Advanced switch filters cannot be added\n");
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	v_ret = ice_vc_chnl_fltr_state_verify(vf, vcf);
	if (v_ret) {
		dev_err(dev, "VF %d: failed to verify ADQ state during filter message processing\n",
			vf->vf_id);
		goto err;
	}

	dest_vsi = pf->vsi[vf->ch[vcf->action_meta].vsi_idx];

	fltr = devm_kzalloc(dev, sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	}

	/* prepare the TC flower filter based on input */
	ice_setup_fltr(vf, fltr, vcf, dest_vsi, vcf->action_meta);

	/* call function which adds advanced switch filter */
	ret = ice_add_tc_flower_adv_fltr(ice_get_vf_vsi(vf), fltr);
	if (ret) {
		dev_err(dev, "Failed to add TC Flower filter using advance filter recipe\n");
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		devm_kfree(dev, fltr);
		goto err;
	}

	INIT_HLIST_NODE(&fltr->tc_flower_node);
	hlist_add_head(&fltr->tc_flower_node, &vf->tc_flower_fltr_list);
	if (fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)
		vf->num_dmac_chnl_fltrs++;

	v_ret = VIRTCHNL_STATUS_SUCCESS;
	vf->adq_fltr_ena = true;

err:
	/* send the response back to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_CLOUD_FILTER, v_ret,
				     NULL, 0);
}

/**
 * ice_conv_virtchnl_speed_to_mbps
 * @virt_speed: virt speed that needs to be converted from
 *
 * convert virt channel speeds to mbps, return link speed on success,
 * '0' otherwise
 */
static u32 ice_conv_virtchnl_speed_to_mbps(u16 virt_speed)
{
	u32 speed, link_speed;

	speed = ice_conv_link_speed_to_virtchnl(false, virt_speed);

       /* get link speed in MB to validate rate limit */
	switch (speed) {
	case VIRTCHNL_LINK_SPEED_100MB:
		link_speed = SPEED_100;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		link_speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		link_speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		link_speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		link_speed = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		link_speed = SPEED_40000;
		break;
	default:
		/* on failure to detect link speed the expectation of the caller
		 * to this function is '0'.
		 */
		link_speed = 0;
		break;
	}

	return link_speed;
}

/**
 * ice_vc_add_qch_msg: Add queue channel and enable ADQ
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 */
static int ice_vc_add_qch_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_tc_info *tci =
		(struct virtchnl_tc_info *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	int adq_request_qps = 0;
	struct ice_link_status *ls;
	u16 available_vsis = 0;
	u64 total_max_rate = 0;
	u32 max_tc_allowed;
	struct device *dev;
	u16 total_qs = 0;
	u32 link_speed;
	unsigned int i;

	dev = ice_pf_to_dev(pf);
	ls = &pf->hw.port_info->phy.link_info;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* check if VF has negotiated this capability before anything else */
	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)) {
		dev_dbg(dev, "VF %d attempting to enable ADQ, but hasn't properly negotiated that capability\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Currently ADQ and DCB are mutually exclusive and keeping in sync
	 * with PF, don't allow VF ADQ configuration when DCB Firmware LLDP
	 * agent is already running/enabled.
	 */
	if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags)) {
		dev_err(dev, "FW LLDP is enabled, cannot enable ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* VF ADQ and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. VF ADQ cannot be enabled\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* ADQ cannot be applied if spoof check is ON */
	if (vf->spoofchk) {
		dev_err(dev, "Spoof check is ON, turn it OFF to enable ADQ\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ice_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			++available_vsis;
	}

	if (available_vsis < tci->num_tc - 1) {
		dev_err(dev, "Not enough VSIs left to enable ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	max_tc_allowed = ice_vc_get_max_chnl_tc_allowed(vf);
	/* max number of traffic classes for VF currently capped at 4 for legacy
	 * ADQ and 16 for ADQ V2.
	 */
	if (!tci->num_tc || tci->num_tc > max_tc_allowed) {
		dev_dbg(dev, "VF %d trying to set %u TCs, valid range 1-%u TCs per VF\n",
			vf->vf_id, tci->num_tc, max_tc_allowed);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* validate queues for each TC */
	for (i = 0; i < tci->num_tc; i++) {
		if (!tci->list[i].count) {
			dev_err(dev, "VF %d: TC %d trying to set %u queues, should be > 0 per TC\n",
				vf->vf_id, i, tci->list[i].count);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		total_qs += tci->list[i].count;
	}

	if (total_qs > ICE_MAX_DFLT_QS_PER_VF) {
		dev_err(dev, "VF %d: Total number of queues of all TCs cannot exceed %u\n",
			vf->vf_id, ICE_MAX_DFLT_QS_PER_VF);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Speed in Mbps */
	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		link_speed = ice_conv_link_speed_to_virtchnl(true,
							     ls->link_speed);
	else
		link_speed = ice_conv_virtchnl_speed_to_mbps(ls->link_speed);

	if (!link_speed) {
		dev_err(dev, "Cannot detect link speed on VF %d\n", vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	for (i = 0; i < tci->num_tc; i++)
		if (tci->list[i].max_tx_rate)
			total_max_rate += tci->list[i].max_tx_rate;

	if (total_max_rate > link_speed) {
		dev_err(dev, "Invalid tx rate specified for ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (vf->max_tx_rate && total_max_rate > vf->max_tx_rate) {
		dev_err(dev, "Invalid tx rate specified for ADQ on VF %d, total_max_rate %llu Mpbs > host set max_tx_rate %u Mbps\n",
			vf->vf_id, total_max_rate, vf->max_tx_rate);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* need Max VF queues but already have default number of queues */
	adq_request_qps = ICE_MAX_DFLT_QS_PER_VF - pf->num_qps_per_vf;

	if (ice_get_avail_txq_count(pf) < adq_request_qps) {
		dev_err(dev, "No queues left to allocate to VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	} else {
		/* we need to allocate max VF queues to enable ADQ so as to
		 * make sure ADQ enabled VF always gets back queues when it
		 * goes through a reset.
		 */
		vf->num_vf_qs = ICE_MAX_DFLT_QS_PER_VF;
	}

	/* parse data from the queue channel info */
	vf->num_tc = tci->num_tc;

	for (i = 0; i < vf->num_tc; i++) {
		if (tci->list[i].max_tx_rate)
			vf->ch[i].max_tx_rate = tci->list[i].max_tx_rate;

		vf->ch[i].num_qps = tci->list[i].count;
		vf->ch[i].offset = tci->list[i].offset;
	}

	/* set this flag only after making sure all inputs are sane */
	vf->adq_enabled = true;
	/* initialize filter enable flag, set it only if filters are applied */
	vf->adq_fltr_ena = false;

	/* reset the VF in order to allocate resources. Don't reset if ADQ_V2
	 * capability is negotiated, since in that case AVF driver will request
	 * for a reset.
	 */
	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)) {
		ice_vc_notify_vf_reset(vf);
		ice_reset_vf(vf, false);
	}
	/* send the response to the VF */
err:
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_CHANNELS,
					     v_ret, (u8 *)tci, sizeof(*tci));
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_CHANNELS,
					     v_ret, NULL, 0);
}

/**
 * ice_vc_del_qch_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * delete the additional VSIs which are created as part of ADQ
 */
static int ice_vc_del_qch_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	u8 tc;

	dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* VF ADQ and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. VF ADQ cannot be enabled\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_is_vf_adq_ena(vf)) {
		/* if ADQ_V2 is set, perform inline cleanup of ADQ resources and
		 * return success and eventually VF driver will initiate reset
		 * as per design
		 */
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2) {
			dev_info(ice_pf_to_dev(pf),
				 "Deleting Queue Channels for ADQ on VF %d and ADQ_V2 is set\n",
				 vf->vf_id);

			/* release VF ADQ filters and VSIs inline */
			ice_vf_adq_release(vf);
			v_ret = VIRTCHNL_STATUS_SUCCESS;
			goto err;
		}

#ifdef HAVE_TC_SETUP_CLSFLOWER
		/* delete all ADQ filters for given VF */
		ice_del_all_adv_switch_fltr(vf);
#endif /* HAVE_TC_SETUP_CLSFLOWER */

		/* stop all Tx/Rx rings and clean them before deleting the ADQ
		 * resources, if not it will throw fail to set the LAN Tx queue
		 * context error. This is needed irrespective of ADQ_V2. Channel
		 * related TC starts at 1. Don't down the VSI and related
		 * resources for TC 0 because it is primary VF VSI and downing
		 * that VSI is handled somewhere else.
		 */
		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			vsi = ice_get_vf_adq_vsi(vf, tc);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto err;
			}
			if (vf->ch[tc].vsi_num)
				ice_down(vsi);
		}

		/* this order of code is very important, if num_tc is not
		 * cleared, VF again rebuilds as ADQ enabled clearly contrary
		 * to what we're trying to do. Also clearing num_tc before
		 * deleting ADQ filters leads to the condition where the code
		 * will try to delete filters when none are configured.
		 */
		vf->num_tc = 0;
		dev_info(ice_pf_to_dev(pf), "Deleting Queue Channels for ADQ on VF %d\n",
			 vf->vf_id);

		/* reset needs to happen first, before we clear the adq_enabled
		 * flag, since freeing up of ADQ resources happens based off of
		 * this flag in reset path. Doing a reset after clearing the
		 * flag will leave the ADQ resources in zombie state which in
		 * turn creates undesired problems such as system lock up, stack
		 * trace etc.,
		 * Also we shouldn't be doing a reset if ADQ flag is cleared in
		 * some other place, hence sending the failure response back to
		 * the VF.
		 */
		ice_vc_notify_vf_reset(vf);
		ice_reset_vf(vf, false);
		if (ice_is_vf_link_up(vf)) {
			/* bring the VSI 0 back up again */
			vsi = ice_get_vf_adq_vsi(vf, 0);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto err;
			}
			ice_up(vsi);
		}

		vf->adq_enabled = false;
	} else {
		dev_info(dev, "VF %d trying to delete queue channels but ADQ isn't enabled\n",
			 vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* send the response to the VF */
err:
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_CHANNELS,
					     v_ret, msg,
					     sizeof(struct virtchnl_tc_info));
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_CHANNELS,
					     v_ret, NULL, 0);
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_vc_set_rss_hena - set RSS HENA bits for the VF
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 */
static int ice_vc_set_rss_hena(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_rss_hena *vrh = (struct virtchnl_rss_hena *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
		dev_err(dev, "RSS not supported by PF\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* clear all previously programmed RSS configuration to allow VF drivers
	 * the ability to customize the RSS configuration and/or completely
	 * disable RSS
	 */
	status = ice_rem_vsi_rss_cfg(&pf->hw, vsi->idx);
	if (status && !vrh->hena) {
		/* only report failure to clear the current RSS configuration if
		 * that was clearly the VF's intention (i.e. vrh->hena = 0)
		 */
		v_ret = ice_err_to_virt_err(status);
		goto err;
	} else if (status) {
		/* allow the VF to update the RSS configuration even on failure
		 * to clear the current RSS confguration in an attempt to keep
		 * RSS in a working state
		 */
		dev_warn(dev, "Failed to clear the RSS configuration for VF %u\n",
			 vf->vf_id);
	}

	if (vrh->hena) {
		status = ice_add_avf_rss_cfg(&pf->hw, vsi->idx, vrh->hena);
		v_ret = ice_err_to_virt_err(status);
	}

	/* send the response to the VF */
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_SET_RSS_HENA, v_ret,
				      NULL, 0);
}

/**
 * ice_vc_rdma_msg - send msg to RDMA PF from VF
 * @vf: pointer to VF info
 * @msg: pointer to msg buffer
 * @len: length of the message
 *
 * This function is called indirectly from the AQ clean function.
 */
static int ice_vc_rdma_msg(struct ice_vf *vf, u8 *msg, u16 len)
{
	struct ice_peer_dev *rdma_peer;
	int ret;

	rdma_peer = vf->pf->rdma_peer;
	if (!rdma_peer) {
		pr_err("Invalid RDMA peer attempted to send message to peer\n");
		return -EIO;
	}

	if (!rdma_peer->peer_ops || !rdma_peer->peer_ops->vc_receive) {
		pr_err("Incomplete RMDA peer attempting to send msg\n");
		return -EINVAL;
	}

	ret = rdma_peer->peer_ops->vc_receive(rdma_peer, vf->vf_id, msg, len);
	if (ret)
		pr_err("Failed to send message to RDMA peer, error %d\n", ret);

	return ret;
}

/**
 * ice_vc_query_rxdid - query RXDID supported by DDP package
 * @vf: pointer to VF info
 *
 * Called from VF to query a bitmap of supported flexible
 * descriptor RXDIDs of a DDP package.
 */
static int ice_vc_query_rxdid(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_supported_rxdids *rxdid = NULL;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_pf *pf = vf->pf;
	int len = 0;
	int ret, i;
	u32 regval;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_supported_rxdids);
	rxdid = kzalloc(len, GFP_KERNEL);
	if (!rxdid) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	/* RXDIDs supported by DDP package can be read from the register
	 * to get the supported RXDID bitmap. But the legacy 32byte RXDID
	 * is not listed in DDP package, add it in the bitmap manually.
	 * Legacy 16byte descriptor is not supported.
	 */
	rxdid->supported_rxdids |= BIT(ICE_RXDID_LEGACY_1);

	for (i = ICE_RXDID_FLEX_NIC; i < ICE_FLEX_DESC_RXDID_MAX_NUM; i++) {
		regval = rd32(hw, GLFLXP_RXDID_FLAGS(i, 0));
		if ((regval >> GLFLXP_RXDID_FLAGS_FLEXIFLAG_4N_S)
			& GLFLXP_RXDID_FLAGS_FLEXIFLAG_4N_M)
			rxdid->supported_rxdids |= BIT(i);
	}

	pf->supported_rxdids = rxdid->supported_rxdids;

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
				    v_ret, (u8 *)rxdid, len);
	kfree(rxdid);
	return ret;
}

/**
 * ice_vf_init_vlan_stripping - enable/disable VLAN stripping on initialization
 * @vf: VF to enable/disable VLAN stripping for on initialization
 *
 * If the VIRTCHNL_VF_OFFLOAD_VLAN flag is set enable VLAN stripping, else if
 * the flag is cleared then we want to disable stripping. For example, the flag
 * will be cleared when port VLANs are configured by the administrator before
 * passing the VF to the guest or if the AVF driver doesn't support VLAN
 * offloads.
 */
static int ice_vf_init_vlan_stripping(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (!vsi)
		return -EINVAL;

	/* don't modify stripping if port VLAN is configured */
	if (vsi->info.pvid)
		return 0;

	if (ice_vf_vlan_offload_ena(vf->driver_caps))
		return vsi->vlan_ops.ena_stripping(vsi, ETH_P_8021Q);
	else
		return vsi->vlan_ops.dis_stripping(vsi);
}

/**
 * ice_dcf_handle_aq_cmd - handle the AdminQ command from DCF to FW
 * @vf: pointer to the VF info
 * @aq_desc: the AdminQ command descriptor
 * @aq_buf: the AdminQ command buffer if aq_buf_size is non-zero
 * @aq_buf_size: the AdminQ command buffer size
 *
 * The VF splits the AdminQ command into two parts: one is the descriptor of
 * AdminQ command, the other is the buffer of AdminQ command (the descriptor
 * has BUF flag set). When both of them are received by PF, this function will
 * forward them to firmware once to get the AdminQ's response. And also, the
 * filled descriptor and buffer of the response will be sent back to VF one by
 * one through the virtchnl.
 */
static int
ice_dcf_handle_aq_cmd(struct ice_vf *vf, struct ice_aq_desc *aq_desc,
		      u8 *aq_buf, u16 aq_buf_size)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	enum virtchnl_ops v_op;
	enum ice_status aq_ret;
	u16 v_msg_len = 0;
	u8 *v_msg = NULL;
	int ret;

	pf->dcf.aq_desc_received = false;

	if ((aq_buf && !aq_buf_size) || (!aq_buf && aq_buf_size))
		return -EINVAL;

	if (ice_dcf_is_acl_aq_cmd(aq_desc) && !pf->hw.dcf_acl_enabled)
		return 0;

	if (ice_dcf_pre_aq_send_cmd(vf, aq_desc, aq_buf, aq_buf_size)) {
		ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_CMD_DESC,
					    VIRTCHNL_STATUS_SUCCESS,
					    (u8 *)aq_desc, sizeof(*aq_desc));
		if (ret || !aq_buf_size)
			return ret;

		v_op = VIRTCHNL_OP_DCF_CMD_BUFF;
		v_ret = VIRTCHNL_STATUS_SUCCESS;
		goto err;
	}

	aq_ret = ice_aq_send_cmd(&pf->hw, aq_desc, aq_buf, aq_buf_size, NULL);
	/* It needs to send back the AQ response message if ICE_ERR_AQ_ERROR
	 * returns, some AdminQ handlers will use the error code filled by FW
	 * to do exception handling.
	 */
	if (aq_ret && aq_ret != ICE_ERR_AQ_ERROR) {
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		v_op = VIRTCHNL_OP_DCF_CMD_DESC;
		goto err;
	}

	if (aq_ret != ICE_ERR_AQ_ERROR) {
		v_ret = ice_dcf_post_aq_send_cmd(pf, aq_desc, aq_buf);
		if (v_ret != VIRTCHNL_STATUS_SUCCESS) {
			v_op = VIRTCHNL_OP_DCF_CMD_DESC;
			goto err;
		}

		v_ret = ice_dcf_update_acl_rule_info(pf, aq_desc, aq_buf);
		if (v_ret != VIRTCHNL_STATUS_SUCCESS) {
			v_op = VIRTCHNL_OP_DCF_CMD_DESC;
			goto err;
		}
	}

	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_CMD_DESC, v_ret,
				    (u8 *)aq_desc, sizeof(*aq_desc));
	/* Bail out so we don't send the VIRTCHNL_OP_DCF_CMD_BUFF message
	 * below if failure happens or no AdminQ command buffer.
	 */
	if (ret || !aq_buf_size)
		return ret;

	v_op = VIRTCHNL_OP_DCF_CMD_BUFF;
	v_msg_len = le16_to_cpu(aq_desc->datalen);

	/* buffer is not updated if data length exceeds buffer size */
	if (v_msg_len > aq_buf_size)
		v_msg_len = 0;
	else if (v_msg_len)
		v_msg = aq_buf;

	/* send the response back to the VF */
err:
	return ice_vc_send_msg_to_vf(vf, v_op, v_ret, v_msg, v_msg_len);
}

/**
 * ice_vc_dcf_cmd_desc_msg - handle the DCF AdminQ command descriptor
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command descriptor
 * @len: length of the message
 */
static int ice_vc_dcf_cmd_desc_msg(struct ice_vf *vf, u8 *msg, u16 len)
{
	struct ice_aq_desc *aq_desc = (struct ice_aq_desc *)msg;
	struct ice_pf *pf = vf->pf;

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON)
		goto err;

	if (len != sizeof(*aq_desc) || !ice_dcf_aq_cmd_permitted(aq_desc)) {
		/* In case to avoid the VIRTCHNL_OP_DCF_CMD_DESC message with
		 * the ICE_AQ_FLAG_BUF set followed by another bad message
		 * VIRTCHNL_OP_DCF_CMD_DESC.
		 */
		pf->dcf.aq_desc_received = false;
		goto err;
	}

	/* The AdminQ descriptor needs to be stored for use when the followed
	 * VIRTCHNL_OP_DCF_CMD_BUFF is received.
	 */
	if (aq_desc->flags & cpu_to_le16(ICE_AQ_FLAG_BUF)) {
		pf->dcf.aq_desc = *aq_desc;
		pf->dcf.aq_desc_received = true;
		pf->dcf.aq_desc_expires = jiffies + ICE_DCF_AQ_DESC_TIMEOUT;
		return 0;
	}

	return ice_dcf_handle_aq_cmd(vf, aq_desc, NULL, 0);

	/* send the response back to the VF */
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_CMD_DESC,
				     VIRTCHNL_STATUS_ERR_PARAM, NULL, 0);
}

/**
 * ice_vc_dcf_cmd_buff_msg - handle the DCF AdminQ command buffer
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command buffer
 * @len: length of the message
 */
static int ice_vc_dcf_cmd_buff_msg(struct ice_vf *vf, u8 *msg, u16 len)
{
	struct ice_pf *pf = vf->pf;

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON ||
	    !len || !pf->dcf.aq_desc_received ||
	    time_is_before_jiffies(pf->dcf.aq_desc_expires))
		goto err;

	return ice_dcf_handle_aq_cmd(vf, &pf->dcf.aq_desc, msg, len);

	/* send the response back to the VF */
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_CMD_BUFF,
				     VIRTCHNL_STATUS_ERR_PARAM, NULL, 0);
}

/**
 * ice_vc_dis_dcf_cap - disable DCF capability for the VF
 * @vf: pointer to the VF
 */
static int ice_vc_dis_dcf_cap(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_is_vf_dcf(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (vf->driver_caps & VIRTCHNL_VF_CAP_DCF) {
		vf->driver_caps &= ~VIRTCHNL_VF_CAP_DCF;
		ice_rm_all_dcf_sw_rules(vf->pf);
		ice_dis_dcf_acl_cap(vf->pf);
		ice_dcf_set_state(vf->pf, ICE_DCF_STATE_OFF);
		vf->pf->dcf.vf = NULL;
	}
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_DISABLE,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_dcf_get_vsi_map - get VSI mapping table
 * @vf: pointer to the VF info
 */
static int ice_vc_dcf_get_vsi_map(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_dcf_vsi_map *vsi_map = NULL;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *pf_vsi;
	u16 len = 0;
	int vf_id;
	int ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = struct_size(vsi_map, vf_vsi, pf->num_alloc_vfs - 1);
	vsi_map = kzalloc(len, GFP_KERNEL);
	if (!vsi_map) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	pf_vsi = ice_get_main_vsi(pf);
	if (!pf_vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		len = 0;
		goto err;
	}

	vsi_map->pf_vsi = pf_vsi->vsi_num;
	vsi_map->num_vfs = pf->num_alloc_vfs;

	ice_for_each_vf(pf, vf_id) {
		struct ice_vf *tmp_vf = &pf->vf[vf_id];

		if (!ice_is_vf_disabled(tmp_vf) &&
		    test_bit(ICE_VF_STATE_INIT, tmp_vf->vf_states))
			vsi_map->vf_vsi[vf_id] = tmp_vf->lan_vsi_num |
				VIRTCHNL_DCF_VF_VSI_VALID;
	}

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_GET_VSI_MAP, v_ret,
				    (u8 *)vsi_map, len);
	kfree(vsi_map);
	return ret;
}

/**
 * ice_vc_dcf_query_pkg_info - query DDP package info from PF
 * @vf: pointer to VF info
 *
 * Called from VF to query DDP package information loaded in PF,
 * including track ID, package name, version and device serial
 * number.
 */
static int ice_vc_dcf_query_pkg_info(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_pkg_info *pkg_info = NULL;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_pf *pf = vf->pf;
	int len = 0;
	int ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_pkg_info);
	pkg_info = kzalloc(len, GFP_KERNEL);
	if (!pkg_info) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	pkg_info->track_id = hw->active_track_id;
	memcpy(&pkg_info->pkg_ver, &hw->active_pkg_ver,
	       sizeof(pkg_info->pkg_ver));
	memcpy(pkg_info->pkg_name, hw->active_pkg_name,
	       sizeof(pkg_info->pkg_name));
	memcpy(pkg_info->dsn, pf->dcf.dsn, sizeof(pkg_info->dsn));

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_GET_PKG_INFO,
				    v_ret, (u8 *)pkg_info, len);
	kfree(pkg_info);
	return ret;
}

/**
 * ice_vc_get_max_rss_qregion - message handling for VIRTCHNL_OP_GET_MAX_RSS_QREGION
 * @vf: source of the request
 */
static int ice_vc_get_max_rss_qregion(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_max_rss_qregion *max_rss_qregion = NULL;
	struct ice_vsi *vsi;
	int err, len = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = vf->pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	max_rss_qregion = kzalloc(sizeof(*max_rss_qregion), GFP_KERNEL);
	if (!max_rss_qregion) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto error_param;
	}

	len = sizeof(*max_rss_qregion);

	max_rss_qregion->vport_id = vf->lan_vsi_num;
	max_rss_qregion->qregion_width = ilog2(ICE_MAX_RSS_QS_PER_VF);
	if (vsi->global_lut_id)
		max_rss_qregion->qregion_width = ilog2(ICE_MAX_RSS_QS_PER_LARGE_VF);

error_param:
	err = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_MAX_RSS_QREGION, v_ret,
				    (u8 *)max_rss_qregion, len);
	kfree(max_rss_qregion);
	return err;
}

static bool ice_vc_supported_queue_type(enum virtchnl_queue_type queue_type)
{
	return (queue_type == VIRTCHNL_QUEUE_TYPE_RX || queue_type == VIRTCHNL_QUEUE_TYPE_TX);
}

/**
 * ice_vc_validate_qs_v2_msg - validate all parameters sent in the qs_msg structure
 * @vf: VF the message was received from
 * @qs_msg: contents of the message from the VF
 *
 * Used to validate both the VIRTCHNL_OP_ENABLE_QUEUES_V2 and VIRTCHNL_OP_DISABLE_QUEUES_V2
 * messages. This should always be called before attempting to enable and/or disable queues on
 * behalf of a VF in response to the preivously mentioned opcodes. If all checks succeed, then
 * return success indicating to the caller that the qs_msg is valid. Otherwise return false,
 * indicating to the caller that the qs_msg is invalid.
 */
static bool ice_vc_validate_qs_v2_msg(struct ice_vf *vf, struct virtchnl_del_ena_dis_queues *qs_msg)
{
	struct virtchnl_queue_chunks *chunks = &qs_msg->chunks;
	int i;

	if (qs_msg->vport_id != vf->lan_vsi_num)
		return false;

	if (!chunks->num_chunks)
		return false;

	for (i = 0; i < chunks->num_chunks; i++) {
		if (!ice_vc_supported_queue_type(chunks->chunks[i].type))
			return false;

		if (!chunks->chunks[i].num_queues)
			return false;

		if (chunks->chunks[i].start_queue_id + chunks->chunks[i].num_queues > vf->num_vf_qs)
			return false;
	}

	return true;
}

#define ice_for_each_q_in_chunk(chunk, q_id) \
	for ((q_id) = (chunk)->start_queue_id; \
	     (q_id) < (chunk)->start_queue_id + (chunk)->num_queues; \
	     (q_id)++)

static int ice_vc_ena_rxq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	int q_id;

	if (!vsi)
		return -EINVAL;

	ice_for_each_q_in_chunk(chunk, q_id) {
		int err = ice_vf_vsi_ena_single_rxq(vf, vsi, q_id);

		if (err)
			return err;
	}

	return 0;
}

static int ice_vc_ena_txq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	int q_id;

	if (!vsi)
		return -EINVAL;

	ice_for_each_q_in_chunk(chunk, q_id)
		ice_vf_vsi_ena_single_txq(vf, vsi, q_id);

	return 0;
}

/**
 * ice_vc_ena_qs_v2_msg - message handling for VIRTCHNL_OP_ENABLE_QUEUES_V2
 * @vf: source of the request
 * @msg: message to handle
 */
static int ice_vc_ena_qs_v2_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_del_ena_dis_queues *ena_qs_msg = (struct virtchnl_del_ena_dis_queues *)msg;
	struct virtchnl_queue_chunks *chunks = &ena_qs_msg->chunks;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	int i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, ena_qs_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_qs_v2_msg(vf, ena_qs_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < chunks->num_chunks; i++) {
		struct virtchnl_queue_chunk *chunk = &chunks->chunks[i];

		if (chunk->type == VIRTCHNL_QUEUE_TYPE_RX && ice_vc_ena_rxq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		else if (chunk->type == VIRTCHNL_QUEUE_TYPE_TX && ice_vc_ena_txq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;

		if (v_ret != VIRTCHNL_STATUS_SUCCESS)
			goto error_param;
	}

	set_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES_V2, v_ret, NULL, 0);
}

static int ice_vc_dis_rxq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	u16 q_id;

	if (!vsi)
		return -EINVAL;

	ice_for_each_q_in_chunk(chunk, q_id) {
		int err;

		err = ice_vf_vsi_dis_single_rxq(vf, vsi, q_id);
		if (err)
			return err;
	}

	return 0;
}

static int ice_vc_dis_txq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	u16 q_id;

	if (!vsi)
		return -EINVAL;

	ice_for_each_q_in_chunk(chunk, q_id) {
		int err;

		err = ice_vf_vsi_dis_single_txq(vf, vsi, q_id);
		if (err)
			return err;
	}

	return 0;
}

/**
 * ice_vc_ena_qs_v2_msg - message handling for VIRTCHNL_OP_DISABLE_QUEUES_V2
 * @vf: source of the request
 * @msg: message to handle
 */
static int ice_vc_dis_qs_v2_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_del_ena_dis_queues *dis_qs_msg = (struct virtchnl_del_ena_dis_queues *)msg;
	struct virtchnl_queue_chunks *chunks = &dis_qs_msg->chunks;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	int i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, dis_qs_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_qs_v2_msg(vf, dis_qs_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < chunks->num_chunks; i++) {
		struct virtchnl_queue_chunk *chunk = &chunks->chunks[i];

		if (chunk->type == VIRTCHNL_QUEUE_TYPE_RX && ice_vc_dis_rxq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		else if (chunk->type == VIRTCHNL_QUEUE_TYPE_TX && ice_vc_dis_txq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;

		if (v_ret != VIRTCHNL_STATUS_SUCCESS)
			goto error_param;
	}

	if (ice_vf_has_no_qs_ena(vf))
		clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES_V2, v_ret, NULL, 0);
}

/**
 * ice_vc_validate_qs_v2_msg - validate all parameters sent in the qs_msg structure
 * @vf: VF the message was received from
 * @qv_maps: contents of the message from the VF
 *
 * Used to validate VIRTCHNL_OP_MAP_VECTOR  messages. This should always be called before attempting
 * map interrupts to queues. If all checks succeed, then return success indicating to the caller
 * that the qv_maps are valid. Otherwise return false, indicating to the caller that the qv_maps
 * are invalid.
 */
static bool ice_vc_validate_qv_maps(struct ice_vf *vf, struct virtchnl_queue_vector_maps *qv_maps)
{
	struct ice_vsi *vsi;
	int i;

	vsi = vf->pf->vsi[vf->lan_vsi_idx];
	if (!vsi)
		return false;

	if (!qv_maps->num_qv_maps)
		return false;

	for (i = 0; i < qv_maps->num_qv_maps; i++) {
		if (!ice_vc_supported_queue_type(qv_maps->qv_maps[i].queue_type))
			return false;

		if (qv_maps->qv_maps[i].queue_id >= vf->num_vf_qs)
			return false;

		if (qv_maps->qv_maps[i].vector_id >= (vsi->num_q_vectors + ICE_NONQ_VECS_VF))
			return false;
	}

	return true;
}

/**
 * ice_vc_map_q_vector_msg - message handling for VIRTCHNL_OP_MAP_QUEUE_VECTOR
 * @vf: source of the request
 * @msg: message to handle
 */
static int ice_vc_map_q_vector_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_queue_vector_maps *qv_maps = (struct virtchnl_queue_vector_maps *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi *vsi;
	int i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, qv_maps->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_qv_maps(vf, qv_maps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = vf->pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < qv_maps->num_qv_maps; i++) {
		struct virtchnl_queue_vector *qv_map = &qv_maps->qv_maps[i];

		if (qv_map->queue_type == VIRTCHNL_QUEUE_TYPE_RX)
			ice_cfg_rxq_interrupt(vsi, qv_map->queue_id, qv_map->vector_id,
					      qv_map->itr_idx);
		else if (qv_map->queue_type == VIRTCHNL_QUEUE_TYPE_TX)
			ice_cfg_txq_interrupt(vsi, qv_map->queue_id, qv_map->vector_id,
					      qv_map->itr_idx);
	}

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_MAP_QUEUE_VECTOR, v_ret, NULL, 0);
}

static struct {
	int (*get_ver_msg)(struct ice_vf *vf, u8 *msg);
	int (*get_vf_res_msg)(struct ice_vf *vf, u8 *msg);
	void (*reset_vf)(struct ice_vf *vf);
	int (*add_mac_addr_msg)(struct ice_vf *vf, u8 *msg);
	int (*del_mac_addr_msg)(struct ice_vf *vf, u8 *msg);
	int (*cfg_qs_msg)(struct ice_vf *vf, u8 *msg);
	int (*ena_qs_msg)(struct ice_vf *vf, u8 *msg);
	int (*dis_qs_msg)(struct ice_vf *vf, u8 *msg);
	int (*request_qs_msg)(struct ice_vf *vf, u8 *msg);
	int (*cfg_irq_map_msg)(struct ice_vf *vf, u8 *msg);
	int (*config_rss_key)(struct ice_vf *vf, u8 *msg);
	int (*config_rss_lut)(struct ice_vf *vf, u8 *msg);
	int (*get_stats_msg)(struct ice_vf *vf, u8 *msg);
	int (*cfg_promiscuous_mode_msg)(struct ice_vf *vf, u8 *msg);
	int (*add_vlan_msg)(struct ice_vf *vf, u8 *msg);
	int (*remove_vlan_msg)(struct ice_vf *vf, u8 *msg);
	int (*query_rxdid)(struct ice_vf *vf);
	int (*get_rss_hena)(struct ice_vf *vf);
	int (*set_rss_hena_msg)(struct ice_vf *vf, u8 *msg);
	int (*ena_vlan_stripping)(struct ice_vf *vf);
	int (*dis_vlan_stripping)(struct ice_vf *vf);
#ifdef HAVE_TC_SETUP_CLSFLOWER
	int (*add_qch_msg)(struct ice_vf *vf, u8 *msg);
	int (*add_switch_filter_msg)(struct ice_vf *vf, u8 *msg);
	int (*del_switch_filter_msg)(struct ice_vf *vf, u8 *msg);
	int (*del_qch_msg)(struct ice_vf *vf, u8 *msg);
#endif /* HAVE_TC_SETUP_CLSFLOWER */
	int (*rdma_msg)(struct ice_vf *vf, u8 *msg, u16 msglen);
	int (*dcf_cmd_desc_msg)(struct ice_vf *vf, u8 *msg, u16 msglen);
	int (*dcf_cmd_buff_msg)(struct ice_vf *vf, u8 *msg, u16 msglen);
	int (*dis_dcf_cap)(struct ice_vf *vf);
	int (*dcf_get_vsi_map)(struct ice_vf *vf);
	int (*dcf_query_pkg_info)(struct ice_vf *vf);
	int (*handle_rss_cfg_msg)(struct ice_vf *vf, u8 *msg, bool add);
	int (*add_fdir_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*del_fdir_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*get_max_rss_qregion)(struct ice_vf *vf);
	int (*ena_qs_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*dis_qs_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*map_q_vector_msg)(struct ice_vf *vf, u8 *msg);
} ice_vc_ops = {
	.get_ver_msg = ice_vc_get_ver_msg,
	.get_vf_res_msg = ice_vc_get_vf_res_msg,
	.reset_vf = ice_vc_reset_vf_msg,
	.add_mac_addr_msg = ice_vc_add_mac_addr_msg,
	.del_mac_addr_msg = ice_vc_del_mac_addr_msg,
	.cfg_qs_msg = ice_vc_cfg_qs_msg,
	.ena_qs_msg = ice_vc_ena_qs_msg,
	.dis_qs_msg = ice_vc_dis_qs_msg,
	.request_qs_msg = ice_vc_request_qs_msg,
	.cfg_irq_map_msg = ice_vc_cfg_irq_map_msg,
	.config_rss_key = ice_vc_config_rss_key,
	.config_rss_lut = ice_vc_config_rss_lut,
	.get_stats_msg = ice_vc_get_stats_msg,
	.cfg_promiscuous_mode_msg = ice_vc_cfg_promiscuous_mode_msg,
	.add_vlan_msg = ice_vc_add_vlan_msg,
	.remove_vlan_msg = ice_vc_remove_vlan_msg,
	.query_rxdid = ice_vc_query_rxdid,
	.get_rss_hena = ice_vc_get_rss_hena,
	.set_rss_hena_msg = ice_vc_set_rss_hena,
	.ena_vlan_stripping = ice_vc_ena_vlan_stripping,
	.dis_vlan_stripping = ice_vc_dis_vlan_stripping,
#ifdef HAVE_TC_SETUP_CLSFLOWER
	.add_qch_msg = ice_vc_add_qch_msg,
	.add_switch_filter_msg = ice_vc_add_switch_filter,
	.del_switch_filter_msg = ice_vc_del_switch_filter,
	.del_qch_msg = ice_vc_del_qch_msg,
#endif /* HAVE_TC_SETUP_CLSFLOWER */
	.rdma_msg = ice_vc_rdma_msg,
	.dcf_cmd_desc_msg = ice_vc_dcf_cmd_desc_msg,
	.dcf_cmd_buff_msg = ice_vc_dcf_cmd_buff_msg,
	.dis_dcf_cap = ice_vc_dis_dcf_cap,
	.dcf_get_vsi_map = ice_vc_dcf_get_vsi_map,
	.dcf_query_pkg_info = ice_vc_dcf_query_pkg_info,
	.handle_rss_cfg_msg = ice_vc_handle_rss_cfg,
	.add_fdir_fltr_msg = ice_vc_add_fdir_fltr,
	.del_fdir_fltr_msg = ice_vc_del_fdir_fltr,
	.get_max_rss_qregion = ice_vc_get_max_rss_qregion,
	.ena_qs_v2_msg = ice_vc_ena_qs_v2_msg,
	.dis_qs_v2_msg = ice_vc_dis_qs_v2_msg,
	.map_q_vector_msg = ice_vc_map_q_vector_msg,
};


/**
 * ice_vc_process_vf_msg - Process request from VF
 * @pf: pointer to the PF structure
 * @event: pointer to the AQ event
 *
 * called from the common asq/arq handler to
 * process request from VF
 */
void ice_vc_process_vf_msg(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	u32 v_opcode = le32_to_cpu(event->desc.cookie_high);
	s16 vf_id = le16_to_cpu(event->desc.retval);
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	struct ice_vf *vf = NULL;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id)) {
		err = -EINVAL;
		goto error_handler;
	}

	vf = &pf->vf[vf_id];
	/* Check if VF is disabled. */
	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states)) {
		err = -EPERM;
		goto error_handler;
	}

	/* Perform basic checks on the msg */
	err = virtchnl_vc_validate_vf_msg(&vf->vf_ver, v_opcode, msg, msglen);
	if (err) {
		if (err == VIRTCHNL_STATUS_ERR_PARAM)
			err = -EPERM;
		else
			err = -EINVAL;
	}

	if (!ice_vc_is_opcode_allowed(vf, v_opcode)) {
		ice_vc_send_msg_to_vf(vf, v_opcode,
				      VIRTCHNL_STATUS_ERR_NOT_SUPPORTED, NULL,
				      0);
		return;
	}

error_handler:
	if (err) {
		ice_vc_send_msg_to_vf(vf, v_opcode, VIRTCHNL_STATUS_ERR_PARAM,
				      NULL, 0);
		dev_err(dev, "Invalid message from VF %d, opcode %d, len %d, error %d\n",
			vf_id, v_opcode, msglen, err);
		return;
	}

	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		err = ice_vc_ops.get_ver_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		err = ice_vc_ops.get_vf_res_msg(vf, msg);
		if (ice_vf_init_vlan_stripping(vf))
			dev_err(dev, "Failed to initialize VLAN stripping for VF %d\n",
				vf->vf_id);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_RESET_VF:
		ice_vc_ops.reset_vf(vf);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		err = ice_vc_add_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		err = ice_vc_del_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		err = ice_vc_ops.cfg_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		err = ice_vc_ops.ena_qs_msg(vf, msg);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		err = ice_vc_ops.dis_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES:
		err = ice_vc_ops.request_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		err = ice_vc_ops.cfg_irq_map_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		err = ice_vc_ops.config_rss_key(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		err = ice_vc_ops.config_rss_lut(vf, msg);
		break;
	case VIRTCHNL_OP_GET_STATS:
		err = ice_vc_ops.get_stats_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		err = ice_vc_cfg_promiscuous_mode_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_VLAN:
		err = ice_vc_add_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN:
		err = ice_vc_remove_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		err = ice_vc_ops.query_rxdid(vf);
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		err = ice_vc_ops.get_rss_hena(vf);
		break;
	case VIRTCHNL_OP_SET_RSS_HENA:
		err = ice_vc_ops.set_rss_hena_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
		err = ice_vc_ops.ena_vlan_stripping(vf);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		err = ice_vc_ops.dis_vlan_stripping(vf);
		break;
#ifdef HAVE_TC_SETUP_CLSFLOWER
	case VIRTCHNL_OP_ENABLE_CHANNELS:
		err = ice_vc_ops.add_qch_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER:
		err = ice_vc_ops.add_switch_filter_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_CLOUD_FILTER:
		err = ice_vc_ops.del_switch_filter_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_CHANNELS:
		err = ice_vc_ops.del_qch_msg(vf, msg);
		break;
#endif /* HAVE_TC_SETUP_FLOWER */
	case VIRTCHNL_OP_IWARP:
		err = ice_vc_ops.rdma_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_DCF_CMD_DESC:
		err = ice_vc_ops.dcf_cmd_desc_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_DCF_CMD_BUFF:
		err = ice_vc_ops.dcf_cmd_buff_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_DCF_DISABLE:
		err = ice_vc_ops.dis_dcf_cap(vf);
		break;
	case VIRTCHNL_OP_DCF_GET_VSI_MAP:
		err = ice_vc_ops.dcf_get_vsi_map(vf);
		break;
	case VIRTCHNL_OP_DCF_GET_PKG_INFO:
		err = ice_vc_ops.dcf_query_pkg_info(vf);
		break;
	case VIRTCHNL_OP_ADD_RSS_CFG:
		err = ice_vc_ops.handle_rss_cfg_msg(vf, msg, true);
		break;
	case VIRTCHNL_OP_DEL_RSS_CFG:
		err = ice_vc_ops.handle_rss_cfg_msg(vf, msg, false);
		break;
	case VIRTCHNL_OP_ADD_FDIR_FILTER:
		err = ice_vc_ops.add_fdir_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_FDIR_FILTER:
		err = ice_vc_ops.del_fdir_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_MAX_RSS_QREGION:
		err = ice_vc_ops.get_max_rss_qregion(vf);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES_V2:
		err = ice_vc_ops.ena_qs_v2_msg(vf, msg);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES_V2:
		err = ice_vc_ops.dis_qs_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_MAP_QUEUE_VECTOR:
		err = ice_vc_ops.map_q_vector_msg(vf, msg);
		break;
	case VIRTCHNL_OP_UNKNOWN:
	default:
		dev_err(dev, "Unsupported opcode %d from VF %d\n", v_opcode,
			vf_id);
		err = ice_vc_send_msg_to_vf(vf, v_opcode,
					    VIRTCHNL_STATUS_ERR_NOT_SUPPORTED,
					    NULL, 0);
		break;
	}
	if (err) {
		/* Helper function cares less about error return values here
		 * as it is busy with pending work.
		 */
		dev_info(dev, "PF failed to honor VF %d, opcode %d, error %d\n",
			 vf_id, v_opcode, err);
	}
}

/**
 * ice_get_vf_cfg
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 */
int
ice_get_vf_cfg(struct net_device *netdev, int vf_id, struct ifla_vf_info *ivi)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->hw_lan_addr.addr);

	/* VF configuration for VLAN and applicable QoS */
	ivi->vlan = vf->port_vlan_info & VLAN_VID_MASK;
	ivi->qos = (vf->port_vlan_info & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;

#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = vf->trusted;
#endif /* HAVE_NDO_SET_VF_TRUST */
	ivi->spoofchk = vf->spoofchk;
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	if (!vf->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	ivi->max_tx_rate = vf->max_tx_rate;
	ivi->min_tx_rate = vf->min_tx_rate;
#else
	ivi->tx_rate = vf->max_tx_rate;
#endif
	return 0;
}

/**
 * ice_unicast_mac_exists - check if the unicast MAC exists on the PF's switch
 * @pf: PF used to reference the switch's rules
 * @umac: unicast MAC to compare against existing switch rules
 *
 * Return true on the first/any match, else return false
 */
static bool ice_unicast_mac_exists(struct ice_pf *pf, u8 *umac)
{
	struct ice_sw_recipe *mac_recipe_list =
		&pf->hw.switch_info->recp_list[ICE_SW_LKUP_MAC];
	struct ice_fltr_mgmt_list_entry *list_itr;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* protect MAC filter list access */

	rule_head = &mac_recipe_list->filt_rules;
	rule_lock = &mac_recipe_list->filt_rule_lock;

	mutex_lock(rule_lock);
	list_for_each_entry(list_itr, rule_head, list_entry) {
		u8 *existing_mac = &list_itr->fltr_info.l_data.mac.mac_addr[0];

		if (ether_addr_equal(existing_mac, umac)) {
			mutex_unlock(rule_lock);
			return true;
		}
	}

	mutex_unlock(rule_lock);

	return false;
}

/**
 * ice_set_vf_mac
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 */
int ice_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	if (is_multicast_ether_addr(mac)) {
		netdev_err(netdev, "%pM not a valid unicast address\n", mac);
		return -EINVAL;
	}

	vf = &pf->vf[vf_id];
	/* nothing left to do, unicast MAC already set */
	if (ether_addr_equal(vf->dev_lan_addr.addr, mac) &&
	    ether_addr_equal(vf->hw_lan_addr.addr, mac))
		return 0;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	if (ice_unicast_mac_exists(pf, mac)) {
		netdev_err(netdev, "Unicast MAC %pM already exists on this PF. Preventing setting VF %u unicast MAC address to %pM\n",
			   mac, vf_id, mac);
		return -EINVAL;
	}

	if (ice_vf_chnl_dmac_fltr_cnt(vf)) {
		netdev_err(netdev,
			   "can't set mac %pM. VF %d has tc-flower filters, delete them and try again\n",
			   mac, vf_id);
		return -EAGAIN;
	}

	/* VF is notified of its new MAC via the PF's response to the
	 * VIRTCHNL_OP_GET_VF_RESOURCES message after the VF has been reset
	 */
	ether_addr_copy(vf->dev_lan_addr.addr, mac);
	ether_addr_copy(vf->hw_lan_addr.addr, mac);
	if (is_zero_ether_addr(mac)) {
		/* VF will send VIRTCHNL_OP_ADD_ETH_ADDR message with its MAC */
		vf->pf_set_mac = false;
		netdev_info(netdev, "Removing MAC on VF %d. VF driver will be reinitialized\n",
			    vf->vf_id);
	} else {
		/* PF will add MAC rule for the VF */
		vf->pf_set_mac = true;
		netdev_info(netdev, "Setting MAC %pM on VF %d. VF driver will be reinitialized\n",
			    mac, vf_id);
	}

	ice_vc_reset_vf(vf);
	return 0;
}

#ifdef HAVE_NDO_SET_VF_TRUST
/**
 * ice_set_vf_trust
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @trusted: Boolean value to enable/disable trusted VF
 *
 * Enable or disable a given VF as trusted
 */
int ice_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;


	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	/* Check if already trusted */
	if (trusted == vf->trusted)
		return 0;

	/* If the trust mode of a given DCF is taken away without the DCF
	 * gracefully relinquishing the DCF functionality, remove ALL switch
	 * filters that were added by the DCF and treat this VF as any other
	 * untrusted AVF.
	 */
	if (ice_is_vf_dcf(vf) && !trusted &&
	    ice_dcf_get_state(pf) != ICE_DCF_STATE_OFF) {
		ice_rm_all_dcf_sw_rules(pf);
		ice_dis_dcf_acl_cap(pf);
		ice_dcf_set_state(pf, ICE_DCF_STATE_OFF);
		pf->dcf.vf = NULL;
		vf->driver_caps &= ~VIRTCHNL_VF_CAP_DCF;
	}

	vf->trusted = trusted;
	ice_vc_reset_vf(vf);
	dev_info(ice_pf_to_dev(pf), "VF %u is now %strusted\n", vf_id,
		 trusted ? "" : "un");

	return 0;
}

#endif /* HAVE_NDO_SET_VF_TRUST */
#ifdef HAVE_NDO_SET_VF_LINK_STATE
/**
 * ice_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link_state: required link state
 *
 * Set VF's link state, irrespective of physical link state status
 */
int ice_set_vf_link_state(struct net_device *netdev, int vf_id, int link_state)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	/* disallow link state change if eeprom is corrupted */
	if (test_bit(ICE_BAD_EEPROM, pf->state))
		return -EOPNOTSUPP;

	switch (link_state) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf->link_forced = false;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf->link_forced = true;
		vf->link_up = true;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf->link_forced = true;
		vf->link_up = false;
		break;
	default:
		return -EINVAL;
	}

	ice_vc_notify_vf_link_state(vf);

	return 0;
}
#endif /* HAVE_NDO_SET_VF_LINK_STATE */

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
/**
 * ice_calc_all_vfs_min_tx_rate - calculate cummulative min Tx rate on all VFs
 * @pf: PF associated with VFs
 */
static int ice_calc_all_vfs_min_tx_rate(struct ice_pf *pf)
{
	int rate = 0, i;

	ice_for_each_vf(pf, i)
		rate += pf->vf[i].min_tx_rate;

	return rate;
}

/**
 * ice_min_tx_rate_oversubscribed - check if min Tx rate causes oversubscription
 * @vf: VF trying to configure min_tx_rate
 * @min_tx_rate: min Tx rate in Mbps
 *
 * Check if the min_tx_rate being passed in will cause oversubscription of total
 * min_tx_rate based on the current link speed and all other VFs configured
 * min_tx_rate
 *
 * Return true if the passed min_tx_rate would cause oversubscription, else
 * return false
 */
static bool
ice_min_tx_rate_oversubscribed(struct ice_vf *vf, int min_tx_rate)
{
	int link_speed_mbps = ice_get_link_speed_mbps(ice_get_vf_vsi(vf));
	int all_vfs_min_tx_rate = ice_calc_all_vfs_min_tx_rate(vf->pf);

	/* this VF's previous rate is being overwritten */
	all_vfs_min_tx_rate -= vf->min_tx_rate;

	if (all_vfs_min_tx_rate + min_tx_rate > link_speed_mbps) {
		dev_err(ice_pf_to_dev(vf->pf), "min_tx_rate of %d Mbps on VF %u would cause oversubscription of %d Mbps based on the current link speed %d Mbps\n",
			min_tx_rate, vf->vf_id,
			all_vfs_min_tx_rate + min_tx_rate - link_speed_mbps,
			link_speed_mbps);
		return true;
	}

	return false;
}
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_vf_adq_total_max_tx_rate - cummulative max_tx_rate when VF ADQ is enabled
 * @vf: Pointer to VF
 *
 * This function cummulative max Tx rate of all TCs if VF ADQ is enabled
 */
static u64 ice_vf_adq_total_max_tx_rate(struct ice_vf *vf)
{
	u64 cummulative_max_tx_rate = 0;
	int i;

	if (!ice_is_vf_adq_ena(vf))
		return 0;

	for (i = 0; i < vf->num_tc; i++)
		cummulative_max_tx_rate += vf->ch[i].max_tx_rate;

	return cummulative_max_tx_rate;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_set_vf_bw - set min/max VF bandwidth
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @min_tx_rate: Minimum Tx rate in Mbps
 * @max_tx_rate: Maximum Tx rate in Mbps
 */
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
int
ice_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
	      int max_tx_rate)
#else
int ice_set_vf_bw(struct net_device *netdev, int vf_id, int max_tx_rate)
#endif
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	vsi = ice_get_vf_vsi(vf);

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	/* when max_tx_rate is zero that means no max Tx rate limiting, so only
	 * check if max_tx_rate is non-zero
	 */
	if (max_tx_rate && min_tx_rate > max_tx_rate) {
		dev_err(dev, "Cannot set min Tx rate %d Mbps greater than max Tx rate %d Mbps\n",
			min_tx_rate, max_tx_rate);
		return -EINVAL;
	}

	if (min_tx_rate && ice_is_adq_active(pf)) {
		dev_err(dev, "ADQ on PF is currently enabled. VF min Tx rate limiting not allowed on this PF.\n");
		return -EOPNOTSUPP;
	}

	if (min_tx_rate && ice_is_dcb_active(pf)) {
		dev_err(dev, "DCB on PF is currently enabled. VF min Tx rate limiting not allowed on this PF.\n");
		return -EOPNOTSUPP;
	}

	if (ice_min_tx_rate_oversubscribed(vf, min_tx_rate))
		return -EINVAL;

	if (vf->min_tx_rate != (unsigned int)min_tx_rate) {
		ret = ice_set_min_bw_limit(vsi, (u64)min_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set min-tx-rate for VF %d\n",
				vf->vf_id);
			return ret;
		}

		vf->min_tx_rate = min_tx_rate;
	}

#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */
	if (vf->max_tx_rate != (unsigned int)max_tx_rate) {
#ifdef HAVE_TC_SETUP_CLSFLOWER
		u64 adq_max_tx_rate;
#endif
		ret = ice_set_max_bw_limit(vsi, (u64)max_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set max-tx-rate for VF %d\n",
				vf->vf_id);
			return ret;
		}

		vf->max_tx_rate = max_tx_rate;
#ifdef HAVE_TC_SETUP_CLSFLOWER
		adq_max_tx_rate = ice_vf_adq_total_max_tx_rate(vf);
		if (vf->max_tx_rate < adq_max_tx_rate)
			dev_warn(dev, "Host managed max_tx_rate %u Mpbs for VF %d is less VF ADQ cummulative max_tx_rate %llu Mpbs\n",
				 vf->vf_id, vf->max_tx_rate, adq_max_tx_rate);
#endif
	}

	return 0;
}

#ifdef HAVE_VF_STATS
/**
 * ice_get_vf_stats - populate some stats for the VF
 * @netdev: the netdev of the PF
 * @vf_id: the host OS identifier (0-255)
 * @vf_stats: pointer to the OS memory to be initialized
 */
int ice_get_vf_stats(struct net_device *netdev, int vf_id,
		     struct ifla_vf_stats *vf_stats)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_eth_stats *stats;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	int ret;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		return ret;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	ice_update_eth_stats(vsi);
	stats = &vsi->eth_stats;

	memset(vf_stats, 0, sizeof(*vf_stats));

	vf_stats->rx_packets = stats->rx_unicast + stats->rx_broadcast +
		stats->rx_multicast;
	vf_stats->tx_packets = stats->tx_unicast + stats->tx_broadcast +
		stats->tx_multicast;
	vf_stats->rx_bytes   = stats->rx_bytes;
	vf_stats->tx_bytes   = stats->tx_bytes;
	vf_stats->broadcast  = stats->rx_broadcast;
	vf_stats->multicast  = stats->rx_multicast;
#ifdef HAVE_VF_STATS_DROPPED
	vf_stats->rx_dropped = stats->rx_discards;
	vf_stats->tx_dropped = stats->tx_discards;
#endif

	return 0;
}
#endif /* HAVE_VF_STATS */

/**
 * ice_print_vf_rx_mdd_event - print VF Rx malicious driver detect event
 * @vf: pointer to the VF structure
 */
void ice_print_vf_rx_mdd_event(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	dev_info(dev, "%d Rx Malicious Driver Detection events detected on PF %d VF %d MAC %pM. mdd-auto-reset-vfs=%s\n",
		 vf->mdd_rx_events.count, pf->hw.pf_id, vf->vf_id,
		 vf->dev_lan_addr.addr,
		 test_bit(ICE_FLAG_MDD_AUTO_RESET_VF, pf->flags)
			  ? "on" : "off");
}

/**
 * ice_print_vfs_mdd_event - print VFs malicious driver detect event
 * @pf: pointer to the PF structure
 *
 * Called from ice_handle_mdd_event to rate limit and print VFs MDD events.
 */
void ice_print_vfs_mdd_events(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int i;

	/* check that there are pending MDD events to print */
	if (!test_and_clear_bit(ICE_MDD_VF_PRINT_PENDING, pf->state))
		return;

	/* VF MDD event logs are rate limited to one second intervals */
	if (time_is_after_jiffies(pf->last_printed_mdd_jiffies + HZ * 1))
		return;

	pf->last_printed_mdd_jiffies = jiffies;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		/* only print Rx MDD event message if there are new events */
		if (vf->mdd_rx_events.count != vf->mdd_rx_events.last_printed) {
			vf->mdd_rx_events.last_printed =
							vf->mdd_rx_events.count;
			ice_print_vf_rx_mdd_event(vf);
		}

		/* only print Tx MDD event message if there are new events */
		if (vf->mdd_tx_events.count != vf->mdd_tx_events.last_printed) {
			vf->mdd_tx_events.last_printed =
							vf->mdd_tx_events.count;

			dev_info(dev, "%d Tx Malicious Driver Detection events detected on PF %d VF %d MAC %pM.\n",
				 vf->mdd_tx_events.count, hw->pf_id, i,
				 vf->dev_lan_addr.addr);
		}
	}
}

/**
 * ice_restore_all_vfs_msi_state - restore VF MSI state after PF FLR
 * @pdev: pointer to a pci_dev structure
 *
 * Called when recovering from a PF FLR to restore interrupt capability to
 * the VFs.
 */
void ice_restore_all_vfs_msi_state(struct pci_dev *pdev)
{
	struct pci_dev *vfdev;
	u16 vf_id;
	int pos;

	if (!pci_num_vf(pdev))
		return;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID,
				     &vf_id);
		vfdev = pci_get_device(pdev->vendor, vf_id, NULL);
		while (vfdev) {
			if (vfdev->is_virtfn && vfdev->physfn == pdev)
				pci_restore_msi_state(vfdev);
			vfdev = pci_get_device(pdev->vendor, vf_id,
					       vfdev);
		}
	}
}

/**
 * ice_is_malicious_vf - helper function to detect a malicious VF
 * @pf: ptr to struct ice_pf
 * @event: pointer to the AQ event
 * @num_msg_proc: the number of messages processed so far
 * @num_msg_pending: the number of messages peinding in admin queue
 */
bool
ice_is_malicious_vf(struct ice_pf *pf, struct ice_rq_event_info *event,
		    u16 num_msg_proc, u16 num_msg_pending)
{
	s16 vf_id = le16_to_cpu(event->desc.retval);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_mbx_data mbxdata;
	enum ice_status status;
	bool malvf = false;
	struct ice_vf *vf;

	if (ice_validate_vf_id(pf, vf_id))
		return false;

	vf = &pf->vf[vf_id];
	/* Check if VF is disabled. */
	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return false;

	mbxdata.num_msg_proc = num_msg_proc;
	mbxdata.num_pending_arq = num_msg_pending;
	mbxdata.max_num_msgs_mbx = pf->hw.mailboxq.num_rq_entries;
#define ICE_MBX_OVERFLOW_WATERMARK 64
	mbxdata.async_watermark_val = ICE_MBX_OVERFLOW_WATERMARK;

	/* check to see if we have a malicious VF */
	status = ice_mbx_vf_state_handler(&pf->hw, &mbxdata, vf_id, &malvf);
	if (status)
		return false;

	if (malvf) {
		bool report_vf = false;

		/* if the VF is malicious and we haven't let the user
		 * know about it, then let them know now
		 */
		status = ice_mbx_report_malvf(&pf->hw, pf->malvfs,
					      ICE_MAX_VF_COUNT, vf_id,
					      &report_vf);
		if (status)
			dev_dbg(dev, "Error reporting malicious VF\n");

		if (report_vf) {
			struct ice_vsi *pf_vsi = ice_get_main_vsi(pf);

			if (pf_vsi)
				dev_warn(dev, "VF MAC %pM on PF MAC %pM is generating asynchronous messages and may be overflowing the PF message queue. Please see the Adapter User Guide for more information\n",
					 &vf->dev_lan_addr.addr[0],
					 pf_vsi->netdev->dev_addr);
		}

		return true;
	}

	/* if there was an error in detection or the VF is not malicious then
	 * return false
	 */
	return false;
}

static void ice_dump_vf(struct ice_vf *vf)
{
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;

	if (!vf)
		return;

	pf = vf->pf;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return;

	dev = ice_pf_to_dev(pf);
	dev_info(dev, "VF[%d]:\n", vf->vf_id);
	dev_info(dev, "\tvf_ver.major = %d vf_ver.minor = %d\n",
		 vf->vf_ver.major, vf->vf_ver.minor);
	dev_info(dev, "\tdriver_caps = 0x%08x\n", vf->driver_caps);
	dev_info(dev, "\tvf_caps = 0x%08lx\n", vf->vf_caps);
	dev_info(dev, "\tvf_states:\n");
	if (test_bit(ICE_VF_STATE_INIT, vf->vf_states))
		dev_info(dev, "\t\tICE_VF_STATE_INIT\n");
	if (test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		dev_info(dev, "\t\tICE_VF_STATE_ACTIVE\n");
	if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
		dev_info(dev, "\t\tICE_VF_STATE_QS_ENA\n");
	if (test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
		dev_info(dev, "\t\tICE_VF_STATE_MC_PROMISC\n");
	if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states))
		dev_info(dev, "\t\tICE_VF_STATE_UC_PROMISC\n");
	dev_info(dev, "\tvsi = %pK, vsi->idx = %d, vsi->vsi_num = %d\n",
		 vsi, vsi->idx, vsi->vsi_num);
	dev_info(dev, "\tlan_vsi_idx = %d\n", vf->lan_vsi_idx);
	dev_info(dev, "\tlan_vsi_num = %d\n", vf->lan_vsi_num);
	dev_info(dev, "\tnum_mac = %d\n", vf->num_mac);
	dev_info(dev, "\tdev_lan_addr = %pM\n", &vf->dev_lan_addr.addr[0]);
	dev_info(dev, "\thw_lan_addr = %pM\n", &vf->hw_lan_addr.addr[0]);
	dev_info(dev, "\tnum_req_qs = %d\n", vf->num_req_qs);
	dev_info(dev, "\trxq_ena = 0x%lx\n", *vf->rxq_ena);
	dev_info(dev, "\ttxq_ena = 0x%lx\n", *vf->txq_ena);
	dev_info(dev, "\tport_vlan_info = 0x%x (0 means no port VLAN is configured):\n",
		 vf->port_vlan_info);
	dev_info(dev, "\t\tPort VLAN ID = %d\n",
		 vf->port_vlan_info & VLAN_VID_MASK);
	dev_info(dev, "\t\tQoS = %d\n",
		 (vf->port_vlan_info & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	dev_info(dev, "\tpf_set_mac = %s\n", vf->pf_set_mac ? "true" : "false");
	dev_info(dev, "\ttrusted = %s\n", vf->trusted ? "true" : "false");
	dev_info(dev, "\tspoofchk = %s\n", vf->spoofchk ? "true" : "false");
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	dev_info(dev, "\tlink_forced = %s, link_up (only valid when link_forced is true) = %s\n",
		 vf->link_forced ? "true" : "false",
		 vf->link_up ? "true" : "false");
#endif
	dev_info(dev, "\tmax_tx_rate = %d\n", vf->max_tx_rate);
	dev_info(dev, "\tmin_tx_rate = %d\n", vf->min_tx_rate);
	dev_info(dev, "\tnum_inval_msgs = %lld\n", vf->num_inval_msgs);
	dev_info(dev, "\tnum_valid_msgs = %lld\n", vf->num_valid_msgs);
	dev_info(dev, "\tmdd_rx_events = %u\n", vf->mdd_rx_events.count);
	dev_info(dev, "\tmdd_tx_events = %u\n", vf->mdd_tx_events.count);
	dev_info(dev, "\tfirst_vector_idx = %d\n", vf->first_vector_idx);
	dev_info(dev, "\tvf_sw_id = %pK\n", vf->vf_sw_id);
	dev_info(dev, "\tadq_enabled = %s\n",
		 vf->adq_enabled ? "true" : "false");
	dev_info(dev, "\tadq_fltr_ena = %s\n",
		 vf->adq_fltr_ena ? "true" : "false");
	dev_info(dev, "\tnum_tc = %u\n", vf->num_tc);
	dev_info(dev, "\tnum_dmac_chnl_fltrs = %u\n", vf->num_dmac_chnl_fltrs);
}

void ice_dump_all_vfs(struct ice_pf *pf)
{
	u16 v;

	ice_for_each_vf(pf, v)
		ice_dump_vf(&pf->vf[v]);
}
