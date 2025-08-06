/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_virtchnl.h"
#include "ice_vf_lib_private.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_virtchnl_allowlist.h"
#include "ice_vf_vsi_vlan_ops.h"
#include "ice_vlan.h"
#include "ice_vf_adq.h"
#include "ice_flex_pipe.h"
#include "ice_dcb_lib.h"

#define FIELD_SELECTOR(proto_hdr_field) \
		BIT((proto_hdr_field) & PROTO_HDR_FIELD_MASK)

struct ice_vc_hdr_match_type {
	s32 vc_hdr;	/* virtchnl headers (VIRTCHNL_PROTO_HDR_XXX) */
	u32 ice_hdr;	/* ice headers (ICE_FLOW_SEG_HDR_XXX) */
};

static const struct ice_vc_hdr_match_type ice_vc_hdr_list[] = {
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
	{VIRTCHNL_PROTO_HDR_ECPRI,	ICE_FLOW_SEG_HDR_ECPRI_TP0 |
					ICE_FLOW_SEG_HDR_UDP_ECPRI_TP0},
	{VIRTCHNL_PROTO_HDR_L2TPV2,	ICE_FLOW_SEG_HDR_L2TPV2},
	{VIRTCHNL_PROTO_HDR_PPP,	ICE_FLOW_SEG_HDR_PPP},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,	ICE_FLOW_SEG_HDR_IPV_FRAG},
	{VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG,	ICE_FLOW_SEG_HDR_IPV_FRAG},
	{VIRTCHNL_PROTO_HDR_GRE,        ICE_FLOW_SEG_HDR_GRE},
};

struct ice_vc_hash_field_match_type {
	s32 vc_hdr;		/* virtchnl headers
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
ice_vc_hash_field_match_type ice_vc_hash_field_list[] = {
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
	{VIRTCHNL_PROTO_HDR_IPV4,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_FRAG_PKID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_ID)},
	{VIRTCHNL_PROTO_HDR_IPV4,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4, FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST),
		ICE_FLOW_HASH_IPV4},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_FRAG_PKID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_ID)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_SRC) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_DST) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		ICE_FLOW_HASH_IPV4 | BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_IPV4_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_PROT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV4_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_PROT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_CHKSUM)},
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
	{VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG_PKID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_ID)},
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
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_SRC_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_DST_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_TCP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_TCP_CHKSUM),
		ICE_FLOW_HASH_TCP_PORT |
		BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_CHKSUM)},
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
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_SRC_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_DST_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_UDP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_UDP_CHKSUM),
		ICE_FLOW_HASH_UDP_PORT |
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_CHKSUM)},
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
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_CHKSUM),
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_DST_PORT) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_CHKSUM)},
	{VIRTCHNL_PROTO_HDR_SCTP,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_DST_PORT) |
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_SCTP_CHKSUM),
		ICE_FLOW_HASH_SCTP_PORT |
		BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_CHKSUM)},
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
	{VIRTCHNL_PROTO_HDR_ECPRI,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_ECPRI_PC_RTC_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_ECPRI_TP0_PC_ID) |
		BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_ECPRI_TP0_PC_ID)},
	{VIRTCHNL_PROTO_HDR_L2TPV2,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_L2TPV2_SESS_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV2_SESS_ID)},
	{VIRTCHNL_PROTO_HDR_L2TPV2,
		FIELD_SELECTOR(VIRTCHNL_PROTO_HDR_L2TPV2_LEN_SESS_ID),
		BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV2_LEN_SESS_ID)},
};

/**
 * ice_vc_vf_broadcast - Broadcast a message to all VFs on PF
 * @pf: pointer to the PF structure
 * @v_opcode: operation code
 * @v_retval: return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 */
void
ice_vc_vf_broadcast(struct ice_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	unsigned int bkt;

	mutex_lock(&pf->vfs.table_lock);
	ice_for_each_vf(pf, bkt, vf) {
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
	mutex_unlock(&pf->vfs.table_lock);
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
 * ice_vc_notify_vf_link_state - Inform a VF of link status
 * @vf: pointer to the VF structure
 *
 * send a link status message to a single VF
 */
void ice_vc_notify_vf_link_state(struct ice_vf *vf)
{
	struct virtchnl_pf_event pfe = { 0 };
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi;

	if (test_bit(ICE_VF_STATE_REPLAY_VC, vf->vf_states))
		return;

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
 * ice_vc_notify_link_state - Inform all VFs on a PF of link status
 * @pf: pointer to the PF structure
 */
void ice_vc_notify_link_state(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;

	mutex_lock(&pf->vfs.table_lock);
	ice_for_each_vf(pf, bkt, vf)
		ice_vc_notify_vf_link_state(vf);
	mutex_unlock(&pf->vfs.table_lock);
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

	if (!ice_has_vfs(pf))
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_vc_vf_broadcast(pf, VIRTCHNL_OP_EVENT, VIRTCHNL_STATUS_SUCCESS,
			    (u8 *)&pfe, sizeof(struct virtchnl_pf_event));
}

/**
 * ice_vc_send_msg_to_vf - Send message to VF
 * @vf: pointer to the VF info
 * @v_opcode: virtual channel opcode
 * @v_retval: virtual channel return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * Send a to a VF. Typically called to send a status code indicator to the VF
 * in response to one of its messages.
 *
 * Return: 0 if the response succeeded and v_retval is
 *         VIRTCHNL_STATUS_SUCCESS, -EINVAL if the response succeeded but
 *         v_retval is an error status, or -EIO if the response failed. The
 *         -EINVAL response informs ice_vc_process_vf_msg() whether or not the
 *         specific virtchnl command succeeded or failed.
 */
int
ice_vc_send_msg_to_vf(struct ice_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	struct device *dev;
	struct ice_pf *pf;
	int aq_ret;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	if (test_bit(ICE_VF_STATE_REPLAY_VC, vf->vf_states)) {
		if (v_retval == VIRTCHNL_STATUS_SUCCESS)
			return 0;

		dev_dbg(dev, "Unable to replay virt channel command, VF ID %d, virtchnl status code %d. op code %d, len %d.\n",
			vf->vf_id, v_retval, v_opcode, msglen);
		return -EINVAL;
	}

	aq_ret = ice_aq_send_msg_to_vf(&pf->hw, vf->vf_id, v_opcode, v_retval,
				       msg, msglen, NULL);
	if (aq_ret && pf->hw.mailboxq.sq_last_status != ICE_AQ_RC_ENOSYS) {
		dev_err(dev, "Unable to send the message to VF %d ret %d aq_err %s\n",
			vf->vf_id, aq_ret,
			ice_aq_str(pf->hw.mailboxq.sq_last_status));
		return -EIO;
	}

	if (v_retval != VIRTCHNL_STATUS_SUCCESS)
		return -EINVAL;

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

	if (ice_vf_is_port_vlan_ena(vf))
		max_frame_size -= VLAN_HLEN;

	return max_frame_size;
}

/**
 * ice_vc_get_vlan_caps
 * @hw: pointer to the hw
 * @vf: pointer to the VF info
 * @vsi: pointer to the VSI
 * @driver_caps: current driver caps
 *
 * Return 0 if there is no VLAN caps supported, or VLAN caps value
 */
static u32
ice_vc_get_vlan_caps(struct ice_hw *hw, struct ice_vf *vf, struct ice_vsi *vsi,
		     u32 driver_caps)
{
	if (ice_is_eswitch_mode_switchdev(vf->pf))
		/* In switchdev setting VLAN from VF isn't supported */
		return 0;

	if (driver_caps & VIRTCHNL_VF_OFFLOAD_VLAN_V2) {
		/* VLAN offloads based on current device configuration */
		return VIRTCHNL_VF_OFFLOAD_VLAN_V2;
	} else if (driver_caps & VIRTCHNL_VF_OFFLOAD_VLAN) {
		/* allow VF to negotiate VIRTCHNL_VF_OFFLOAD explicitly for
		 * these two conditions, which amounts to guest VLAN filtering
		 * and offloads being based on the inner VLAN or the
		 * inner/single VLAN respectively and don't allow VF to
		 * negotiate VIRTCHNL_VF_OFFLOAD in any other cases
		 */
		if (ice_is_dvm_ena(hw) && ice_vf_is_port_vlan_ena(vf)) {
			return VIRTCHNL_VF_OFFLOAD_VLAN;
		} else if (!ice_is_dvm_ena(hw) &&
			   !ice_vf_is_port_vlan_ena(vf)) {
			/* configure backward compatible support for VFs that
			 * only support VIRTCHNL_VF_OFFLOAD_VLAN, the PF is
			 * configured in SVM, and no port VLAN is configured
			 */
			ice_vf_vsi_cfg_svm_legacy_vlan_mode(vsi);
			return VIRTCHNL_VF_OFFLOAD_VLAN;
		} else if (ice_is_dvm_ena(hw)) {
			/* configure software offloaded VLAN support when DVM
			 * is enabled, but no port VLAN is enabled
			 */
			ice_vf_vsi_cfg_dvm_legacy_vlan_mode(vsi);
		}
	}
	return 0;
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
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	int len = 0;
	int ret;

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Don't process if GET_VF_RESOURCES is already negotiated */
	if (test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) &&
	    ice_dcf_get_state(pf) != ICE_DCF_STATE_PAUSE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = virtchnl_ss_vf_resource(vfres, vsi_res, 0);

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
				  VIRTCHNL_VF_OFFLOAD_VLAN;

	if (vf->migration_active)
		vf->driver_caps &= ice_migration_supported_caps();
	vfres->vf_cap_flags = VIRTCHNL_VF_OFFLOAD_L2;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vfres->vf_cap_flags |= ice_vc_get_vlan_caps(hw, vf, vsi,
						    vf->driver_caps);

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PF;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_FDIR_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_FDIR_PF;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_FSUB_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_FSUB_PF;

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

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_CRC)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_CRC;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_ADV_LINK_SPEED;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF;
#ifdef __TC_MQPRIO_MODE_MAX
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ &&
	    !ice_is_eswitch_mode_switchdev(pf))
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ;
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2 &&
	    !ice_is_eswitch_mode_switchdev(pf))
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ_V2;
#endif /* __TC_MQPRIO_MODE_MAX */

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_USO)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_USO;

	if (vf->driver_caps & VIRTCHNL_VF_LARGE_NUM_QPAIRS &&
	    vsi->rss_lut_type != ICE_LUT_VSI)
		vfres->vf_cap_flags |= VIRTCHNL_VF_LARGE_NUM_QPAIRS;

	/* Negotiate DCF capability. */
	if (vf->driver_caps & VIRTCHNL_VF_CAP_DCF) {
		if (!ice_is_dcf_enabled(pf)) {
			if (!ice_check_dcf_allowed(vf)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto err;
			}
			pf->dcf.vf = vf;
			dev_info(ice_pf_to_dev(pf), "Grant request for DCF functionality to VF%d\n",
				 ICE_DCF_VFID);
			if (ice_is_acl_empty(hw)) {
				ice_acl_destroy_tbl(hw);
				hw->dcf_caps |= DCF_ACL_CAP;
			} else {
				dev_info(ice_pf_to_dev(pf), "Failed to grant ACL capability to VF%d as ACL rules already exist\n",
					 ICE_DCF_VFID);
				hw->dcf_caps &= ~DCF_ACL_CAP;
			}
			if (!ice_is_tunnel_empty(hw)) {
				dev_info(ice_pf_to_dev(pf), "Failed to grant UDP tunnel capability to VF%d as UDP tunnel rules already exist\n",
					 ICE_DCF_VFID);
				hw->dcf_caps &= ~DCF_UDP_TUNNEL_CAP;
			}
		}

		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_DCF;
		ice_dcf_set_state(pf, ICE_DCF_STATE_ON);
	} else if (ice_is_vf_dcf(vf) &&
		   ice_dcf_get_state(pf) != ICE_DCF_STATE_OFF) {
		/* If a designated DCF requests AVF functionality from the
		 * same VF without the DCF gracefully relinquishing the DCF
		 * functionality first, remove ALL switch filters that were
		 * added by the DCF.
		 */
		dev_info(ice_pf_to_dev(pf), "DCF is not in the OFF state, removing all filters that were added by the DCF\n");
		ice_rm_all_dcf_sw_rules(pf);
		ice_clear_dcf_acl_cfg(pf);
		ice_clear_dcf_udp_tunnel_cfg(pf);
		hw->dcf_caps &= ~(DCF_ACL_CAP | DCF_UDP_TUNNEL_CAP);
		ice_dcf_set_state(pf, ICE_DCF_STATE_OFF);
		pf->dcf.vf = NULL;
		ice_reset_vf(vf, 0);
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_QOS)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_QOS;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_RDMA &&
	    vf->vf_ops->cfg_rdma_irq_map && vf->vf_ops->clear_rdma_irq_map &&
	    ice_is_aux_ena(pf) && ice_is_rdma_ena(pf) &&
	    ice_is_rdma_aux_loaded(pf))
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_RDMA;

	if (ice_is_ptp_supported(pf) &&
	    vf->driver_caps & VIRTCHNL_VF_CAP_PTP)
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_PTP;

	vfres->num_vsis = 1;
	/* Tx and Rx queue are equal for VF */
	vfres->num_queue_pairs = vsi->num_txq;
	vfres->max_vectors = vf->num_msix;
	vfres->rss_key_size = ICE_VSIQF_HKEY_ARRAY_SIZE;
	vfres->rss_lut_size = vsi->rss_table_size;
	vfres->max_mtu = ice_vc_get_max_frame_size(vf);

	vfres->vsi_res[0].vsi_id = vf->vm_vsi_num;
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
		ice_reset_vf(vf, 0);
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
	return vsi_id == vf->vm_vsi_num;
}

/**
 * ice_vc_isvalid_q_id
 * @vsi: VSI to check queue ID against
 * @qid: VSI relative queue ID
 *
 * check for the valid queue ID
 */
static bool ice_vc_isvalid_q_id(struct ice_vsi *vsi, u16 qid)
{
	/* allocated Tx and Rx queues should be always equal for VF VSI */
	return qid < vsi->alloc_txq;
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
		ring_len <= ICE_MAX_NUM_DESC_E810 &&
		!(ring_len % ICE_REQ_DESC_MULTIPLE));
}

static enum virtchnl_status_code
ice_vc_rss_hash_update(struct ice_hw *hw, struct ice_vsi *vsi, u8 hash_type)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi_ctx *ctx;
	int status;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;

	/* clear previous hash_type */
	ctx->info.q_opt_rss = vsi->info.q_opt_rss &
		~(ICE_AQ_VSI_Q_OPT_RSS_HASH_M);
	/* hash_type is passed in as ICE_AQ_VSI_Q_OPT_RSS_<XOR|TPLZ|SYM_TPLZ */
	ctx->info.q_opt_rss |= FIELD_PREP(ICE_AQ_VSI_Q_OPT_RSS_HASH_M,
					  hash_type);

	/* Preserve existing queueing option setting */
	ctx->info.q_opt_tc = vsi->info.q_opt_tc;
	ctx->info.q_opt_flags = vsi->info.q_opt_flags;

	ctx->info.valid_sections =
			cpu_to_le16(ICE_AQ_VSI_PROP_Q_OPT_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctx, NULL);
	if (status) {
		dev_err(ice_hw_to_dev(hw), "update VSI for RSS failed, err %d aq_err %s\n",
			status, ice_aq_str(hw->adminq.sq_last_status));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	} else {
		vsi->info.q_opt_rss = ctx->info.q_opt_rss;
	}

	kfree(ctx);

	return v_ret;
}

/**
 * ice_vc_validate_pattern
 * @vf: pointer to the VF info
 * @proto: virtchnl protocol headers
 *
 * validate the pattern is supported or not.
 *
 * Return: true on success, false on error.
 */
bool
ice_vc_validate_pattern(struct ice_vf *vf, struct virtchnl_proto_hdrs *proto)
{
	bool is_l2tpv2 = false;
	bool is_ipv4 = false;
	bool is_ipv6 = false;
	bool is_udp = false;
	u16 ptype = -1;
	int i = 0;
	int count;
	s32 type;

	if (proto->count > VIRTCHNL_MAX_NUM_PROTO_HDRS +
			   VIRTCHNL_MAX_NUM_PROTO_HDRS_W_MSK)
		return false;

	if (proto->count > VIRTCHNL_MAX_NUM_PROTO_HDRS)
		count = proto->count - VIRTCHNL_MAX_NUM_PROTO_HDRS;
	else
		count = proto->count;

	while (i < count) {
		if (proto->proto_hdr[i].type != VIRTCHNL_PROTO_HDR_NONE)
			type = proto->proto_hdr[i].type;
		else if (i < VIRTCHNL_MAX_NUM_PROTO_HDRS_W_MSK &&
			 proto->proto_hdr_w_msk[i].type !=
				VIRTCHNL_PROTO_HDR_NONE)
			type = proto->proto_hdr_w_msk[i].type;
		else
			break;

		switch (type) {
		case VIRTCHNL_PROTO_HDR_ETH:
			ptype = ICE_PTYPE_MAC_PAY;
			break;
		case VIRTCHNL_PROTO_HDR_IPV4:
			ptype = ICE_PTYPE_IPV4_PAY;
			is_ipv4 = true;
			break;
		case VIRTCHNL_PROTO_HDR_IPV4_FRAG:
			ptype = ICE_PTYPE_IPV4FRAG_PAY;
			is_ipv4 = true;
			break;
		case VIRTCHNL_PROTO_HDR_IPV6:
			ptype = ICE_PTYPE_IPV6_PAY;
			is_ipv6 = true;
			break;
		case VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG:
			ptype = ICE_PTYPE_IPV6FRAG_PAY;
			is_ipv6 = true;
			break;
		case VIRTCHNL_PROTO_HDR_UDP:
			if (is_ipv4)
				ptype = ICE_PTYPE_IPV4_UDP_PAY;
			else if (is_ipv6)
				ptype = ICE_PTYPE_IPV6_UDP_PAY;
			is_udp = true;
			break;
		case VIRTCHNL_PROTO_HDR_TCP:
			if (is_ipv4)
				ptype = ICE_PTYPE_IPV4_TCP_PAY;
			else if (is_ipv6)
				ptype = ICE_PTYPE_IPV6_TCP_PAY;
			break;
		case VIRTCHNL_PROTO_HDR_SCTP:
			if (is_ipv4)
				ptype = ICE_PTYPE_IPV4_SCTP_PAY;
			else if (is_ipv6)
				ptype = ICE_PTYPE_IPV6_SCTP_PAY;
			break;
		case VIRTCHNL_PROTO_HDR_L2TPV2:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_L2TPV2;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_L2TPV2;
			is_l2tpv2 = true;
			break;
		case VIRTCHNL_PROTO_HDR_GTPU_IP:
		case VIRTCHNL_PROTO_HDR_GTPU_EH:
		case VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN:
		case VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_GTPU;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_GTPU;
			goto out;
		case VIRTCHNL_PROTO_HDR_L2TPV3:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_L2TPV3;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_L2TPV3;
			goto out;
		case VIRTCHNL_PROTO_HDR_ESP:
			if (is_ipv4)
				ptype = is_udp ? ICE_MAC_IPV4_NAT_T_ESP :
						ICE_MAC_IPV4_ESP;
			else if (is_ipv6)
				ptype = is_udp ? ICE_MAC_IPV6_NAT_T_ESP :
						ICE_MAC_IPV6_ESP;
			goto out;
		case VIRTCHNL_PROTO_HDR_AH:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_AH;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_AH;
			goto out;
		case VIRTCHNL_PROTO_HDR_PFCP:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_PFCP_SESSION;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_PFCP_SESSION;
			goto out;
		case VIRTCHNL_PROTO_HDR_ECPRI:
			if (is_ipv4)
				ptype = ICE_PTYPE_IPV4_UDP_PAY;
			else if (is_ipv6)
				ptype = ICE_PTYPE_IPV6_UDP_PAY;
			goto out;
		case VIRTCHNL_PROTO_HDR_PPP:
			if (is_ipv4 && is_l2tpv2)
				ptype = ICE_MAC_IPV4_PPPOL2TPV2;
			else if (is_ipv6 && is_l2tpv2)
				ptype = ICE_MAC_IPV6_PPPOL2TPV2;
			goto out;
		case VIRTCHNL_PROTO_HDR_GRE:
			if (is_ipv4)
				ptype = ICE_MAC_IPV4_TUN_PAY;
			else if (is_ipv6)
				ptype = ICE_MAC_IPV6_TUN_PAY;
			goto out;
		default:
			break;
		}
		i++;
	}

out:
	return ice_hw_ptype_ena(&vf->pf->hw, ptype);
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
	bool inner_hdr = false;
	bool has_gre = false;

	u32 *addl_hdrs = &hash_cfg->addl_hdrs;
	u64 *hash_flds = &hash_cfg->hash_flds;
	/* set outer layer RSS as default */
	hash_cfg->hdr_type = ICE_RSS_OUTER_HEADERS;

	hf_list = ice_vc_hash_field_list;
	hf_list_len = ARRAY_SIZE(ice_vc_hash_field_list);
	hdr_list = ice_vc_hdr_list;
	hdr_list_len = ARRAY_SIZE(ice_vc_hdr_list);

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

		if (!hdr_found)
			return false;

		if (proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV4 && !inner_hdr)
			outer_ipv4 = true;
		else if (proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV6 &&
			 !inner_hdr)
			outer_ipv6 = true;
		/* for GRE and L2TPv2, take inner header as input set if no
		 * any field is selected from outer headers.
		 * for GTPU, take inner header and GTPU teid as input set.
		 */
		else if ((proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_IP ||
			  proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_EH ||
			  proto_hdr->type == VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN ||
			  proto_hdr->type ==
				VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP) ||
			 ((proto_hdr->type == VIRTCHNL_PROTO_HDR_L2TPV2 ||
			   proto_hdr->type == VIRTCHNL_PROTO_HDR_GRE) &&
			   *hash_flds == 0)) {
			/* set inner_hdr flag, and clean up outer header */
			inner_hdr = true;

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

			if (has_gre && outer_ipv4)
				hash_cfg->hdr_type =
					ICE_RSS_INNER_HEADERS_W_OUTER_IPV4_GRE;
			if (has_gre && outer_ipv6)
				hash_cfg->hdr_type =
					ICE_RSS_INNER_HEADERS_W_OUTER_IPV6_GRE;

			if (proto_hdr->type == VIRTCHNL_PROTO_HDR_GRE)
				has_gre = true;
		}

		*addl_hdrs |= hdr_found;

		/* refine hash hdrs and fields for IP fragment */
		if (VIRTCHNL_TEST_PROTO_HDR_FIELD(proto_hdr,
		    VIRTCHNL_PROTO_HDR_IPV4_FRAG_PKID) &&
		    proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV4_FRAG) {
			*addl_hdrs |= ICE_FLOW_SEG_HDR_IPV_FRAG;
			*addl_hdrs &= ~(ICE_FLOW_SEG_HDR_IPV_OTHER);
			*hash_flds |= BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_ID);
			VIRTCHNL_DEL_PROTO_HDR_FIELD(proto_hdr,
				VIRTCHNL_PROTO_HDR_IPV4_FRAG_PKID);
		}
		if (VIRTCHNL_TEST_PROTO_HDR_FIELD(proto_hdr,
		    VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG_PKID) &&
		    proto_hdr->type == VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG) {
			*addl_hdrs |= ICE_FLOW_SEG_HDR_IPV_FRAG;
			*addl_hdrs &= ~(ICE_FLOW_SEG_HDR_IPV_OTHER);
			*hash_flds |= BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_ID);
			VIRTCHNL_DEL_PROTO_HDR_FIELD(proto_hdr,
				VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG_PKID);
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

	/* refine hash field for ecpri over mac or udp */
	if ((*addl_hdrs & ICE_FLOW_SEG_HDR_ECPRI_TP0) &&
	    (*addl_hdrs & ICE_FLOW_SEG_HDR_UDP)) {
		*addl_hdrs &= ~ICE_FLOW_SEG_HDR_ECPRI_TP0;
		*hash_flds &= ~(BIT_ULL(ICE_FLOW_FIELD_IDX_ECPRI_TP0_PC_ID));
	} else if (*addl_hdrs & ICE_FLOW_SEG_HDR_ECPRI_TP0) {
		*addl_hdrs &= ~ICE_FLOW_SEG_HDR_UDP_ECPRI_TP0;
		*hash_flds &=
			~(BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_ECPRI_TP0_PC_ID));
	}

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
	struct ice_hw *hw = &vf->pf->hw;
	int status;

	if (!is_hash_cfg_valid(cfg))
		return -ENOENT;

	status = ice_rem_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status && status != -ENOENT) {
		dev_err(dev, "ice_rem_rss_cfg failed for VF %d, VSI %d, error:%d\n",
			vf->vf_id, vf->lan_vsi_idx, status);
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
	struct ice_hw *hw = &vf->pf->hw;
	int status;

	if (!is_hash_cfg_valid(cfg))
		return -ENOENT;

	status = ice_add_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status) {
		dev_err(dev, "ice_add_rss_cfg failed for VF %d, VSI %d, error:%d\n",
			vf->vf_id, vf->lan_vsi_idx, status);
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
	u32 ice_gtpu_ctx_idx = calc_gtpu_ctx_idx(cfg->addl_hdrs);

	u8 ip_ctx_idx = ice_map_ip_ctx_idx(cfg->addl_hdrs);

	if (ip_ctx_idx == ICE_HASH_IP_CTX_IP) {
		int ret = 0;

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
static int
ice_rem_rss_cfg_wrap(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_hw *hw = &vf->pf->hw;
	int status;

	status = ice_rem_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	/* We just ignore -ENOENT, because if two configurations share the same
	 * profile remove one of them actually removes both, since the
	 * profile is deleted.
	 */
	if (status && status != -ENOENT) {
		dev_err(dev, "ice_rem_rss_cfg failed for VF %d, VSI %d, error:%d\n",
			vf->vf_id, vf->lan_vsi_idx, status);
		return status;
	}

	ice_rem_rss_cfg_post(vf, cfg);

	return 0;
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
static int
ice_add_rss_cfg_wrap(struct ice_vf *vf, struct ice_rss_hash_cfg *cfg)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_hw *hw = &vf->pf->hw;
	int status;

	if (ice_add_rss_cfg_pre(vf, cfg))
		return -EINVAL;

	status = ice_add_rss_cfg(hw, vf->lan_vsi_idx, cfg);
	if (status) {
		dev_err(dev, "ice_add_rss_cfg failed for VF %d, VSI %d, error:%d\n",
			vf->vf_id, vf->lan_vsi_idx, status);
		return status;
	}

	if (ice_add_rss_cfg_post(vf, cfg))
		status = -EINVAL;

	return status;
}

/**
 * ice_parse_raw_rss_pattern - Parse raw pattern spec and mask for RSS
 * @vf: pointer to the VF info
 * @proto: pointer to the virtchnl protocol header
 * @raw_cfg: pointer to the RSS raw pattern configuration
 *
 * Parser function to get spec and mask from virtchnl message, and parse
 * them to get the corresponding profile and offset. The profile is used
 * to add RSS configuration.
 */
static int
ice_parse_raw_rss_pattern(struct ice_vf *vf, struct virtchnl_proto_hdrs *proto,
			  struct ice_rss_raw_cfg *raw_cfg)
{
	struct ice_parser_result pkt_parsed;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_parser_profile prof;
	u16 pkt_len, udp_port = 0;
	struct ice_parser *psr;
	u8 *pkt_buf, *msk_buf;
	int status = 0;

	pkt_len = proto->raw.pkt_len;
	if (!pkt_len)
		return -EINVAL;
	if (pkt_len > VIRTCHNL_MAX_SIZE_RAW_PACKET)
		pkt_len = VIRTCHNL_MAX_SIZE_RAW_PACKET;

	pkt_buf = kzalloc(pkt_len, GFP_KERNEL);
	msk_buf = kzalloc(pkt_len, GFP_KERNEL);
	if (!pkt_buf || !msk_buf) {
		status = -ENOMEM;
		goto free_alloc;
	}

	memcpy(pkt_buf, proto->raw.spec, pkt_len);
	memcpy(msk_buf, proto->raw.mask, pkt_len);

	status = ice_parser_create(hw, &psr);
	if (status)
		goto parser_destroy;

	if (ice_get_open_tunnel_port(hw, TNL_VXLAN, &udp_port))
		ice_parser_vxlan_tunnel_set(psr, udp_port, true);

	status = ice_parser_run(psr, pkt_buf, pkt_len, &pkt_parsed);
	if (status)
		goto parser_destroy;

	status = ice_parser_profile_init(&pkt_parsed, pkt_buf, msk_buf,
					 pkt_len, ICE_BLK_RSS,
					 true, &prof);
	if (status)
		goto parser_destroy;

	memcpy(&raw_cfg->prof, &prof, sizeof(prof));

parser_destroy:
	ice_parser_destroy(psr);
free_alloc:
	kfree(pkt_buf);
	kfree(msk_buf);
	return status;
}

/**
 * ice_add_raw_rss_cfg - add RSS configuration for raw pattern
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS raw pattern configuration
 *
 * This function adds the RSS configuration for raw pattern.
 * Check if current profile is matched. If not, remove the old
 * one and add the new profile to HW directly. Update the symmetric
 * hash configuration as well.
 */
static int
ice_add_raw_rss_cfg(struct ice_vf *vf, struct ice_rss_raw_cfg *cfg)
{
	struct ice_parser_profile *prof = &cfg->prof;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_rss_prof_info *rss_prof;
	struct ice_hw *hw = &vf->pf->hw;
	int i, ptg, status = 0;
	u16 vsi_handle;
	u64 id;

	vsi_handle = vf->lan_vsi_idx;
	id = find_first_bit(prof->ptypes, ICE_FLOW_PTYPE_MAX);

	ptg = hw->blk[ICE_BLK_RSS].xlt1.t[id];
	rss_prof = &vf->rss_prof_info[ptg];

	/* check if ptg already has a profile */
	if (rss_prof->prof.fv_num) {
		for (i = 0; i < ICE_MAX_FV_WORDS; i++) {
			if (rss_prof->prof.fv[i].proto_id !=
			    prof->fv[i].proto_id ||
			    rss_prof->prof.fv[i].offset !=
			    prof->fv[i].offset)
				break;
		}

		/* current profile is matched, check symmetric hash */
		if (i == ICE_MAX_FV_WORDS) {
			if (rss_prof->symm != cfg->symm)
				goto update_symm;
			return status;
		}

		/* current profile is not matched, remove it */
		status =
		ice_rem_prof_id_flow(hw, ICE_BLK_RSS,
				     ice_get_hw_vsi_num(hw, vsi_handle),
				     id);
		if (status) {
			dev_err(dev, "remove RSS flow failed\n");
			return status;
		}

		status = ice_rem_prof(hw, ICE_BLK_RSS, id);
		if (status) {
			dev_err(dev, "remove RSS profile failed\n");
			return status;
		}
	}

	/* add new profile */
	status = ice_flow_set_hw_prof(hw, vsi_handle, 0, prof, ICE_BLK_RSS);
	if (status) {
		dev_err(dev, "HW profile add failed\n");
		return status;
	}

	memcpy(&rss_prof->prof, prof, sizeof(struct ice_parser_profile));

update_symm:
	rss_prof->symm = cfg->symm;
	ice_rss_update_raw_symm(hw, cfg, id);
	return status;
}

/**
 * ice_rem_raw_rss_cfg - remove RSS configuration for raw pattern
 * @vf: pointer to the VF info
 * @cfg: pointer to the RSS raw pattern configuration
 *
 * This function removes the RSS configuration for raw pattern.
 * Check if vsi group is already removed first. If not, remove the
 * profile.
 */
static int
ice_rem_raw_rss_cfg(struct ice_vf *vf, struct ice_rss_raw_cfg *cfg)
{
	struct ice_parser_profile *prof = &cfg->prof;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_hw *hw = &vf->pf->hw;
	int ptg, status = 0;
	u16 vsig, vsi;
	u64 id;

	id = find_first_bit(prof->ptypes, ICE_FLOW_PTYPE_MAX);

	ptg = hw->blk[ICE_BLK_RSS].xlt1.t[id];

	memset(&vf->rss_prof_info[ptg], 0,
	       sizeof(struct ice_rss_prof_info));

	/* check if vsig is already removed */
	vsi = ice_get_hw_vsi_num(hw, vf->lan_vsi_idx);
	if (vsi >= ICE_MAX_VSI) {
		status = -EINVAL;
		goto err;
	}

	vsig = hw->blk[ICE_BLK_RSS].xlt2.vsis[vsi].vsig;
	if (vsig) {
		status = ice_rem_prof_id_flow(hw, ICE_BLK_RSS, vsi, id);
		if (status)
			goto err;

		status = ice_rem_prof(hw, ICE_BLK_RSS, id);
		if (status)
			goto err;
	}

	return status;

err:
	dev_err(dev, "HW profile remove failed\n");
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
	u8 hash_type;
	bool symm;

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
		hash_type = add ? ICE_AQ_VSI_Q_OPT_RSS_HASH_XOR :
				  ICE_AQ_VSI_Q_OPT_RSS_HASH_TPLZ;

		v_ret = ice_vc_rss_hash_update(hw, vsi, hash_type);
		goto error_param;
	}

	hash_type = add ? ICE_AQ_VSI_Q_OPT_RSS_HASH_SYM_TPLZ :
			  ICE_AQ_VSI_Q_OPT_RSS_HASH_TPLZ;
	v_ret = ice_vc_rss_hash_update(hw, vsi, hash_type);
	if (v_ret)
		goto error_param;

	symm = rss_cfg->rss_algorithm == VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC;
	/* Configure RSS hash for raw pattern */
	if (rss_cfg->proto_hdrs.tunnel_level == 0 &&
	    rss_cfg->proto_hdrs.count == 0) {
		struct ice_rss_raw_cfg raw_cfg;

		if (ice_parse_raw_rss_pattern(vf, &rss_cfg->proto_hdrs,
					      &raw_cfg)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (add) {
			raw_cfg.symm = symm;
			if (ice_add_raw_rss_cfg(vf, &raw_cfg))
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		} else {
			if (ice_rem_raw_rss_cfg(vf, &raw_cfg))
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		}
	} else {
		struct ice_rss_hash_cfg cfg;

		/* Only check for none raw pattern case */
		if (!ice_vc_validate_pattern(vf, &rss_cfg->proto_hdrs)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		cfg.addl_hdrs = ICE_FLOW_SEG_HDR_NONE;
		cfg.hash_flds = ICE_HASH_INVALID;
		cfg.hdr_type = ICE_RSS_ANY_HEADERS;

		if (!ice_vc_parse_rss_cfg(hw, rss_cfg, &cfg)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (add) {
			cfg.symm = symm;
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
 * ice_vc_get_qos_caps - Get current QoS caps from PF
 * @vf: pointer to the VF info
 *
 * Get VF's QoS capabilities, such as TC number, arbiter and
 * bandwidth from PF.
 */
static int ice_vc_get_qos_caps(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_qos_cap_list *cap_list = NULL;
	u8 tc_prio[ICE_MAX_TRAFFIC_CLASS] = {0};
	struct virtchnl_qos_cap_elem *cfg = NULL;
	struct ice_vsi_ctx *vsi_ctx;
	struct ice_pf *pf = vf->pf;
	struct ice_port_info *pi;
	struct ice_vsi *vsi;
	u8 numtc, tc;
	u16 len = 0;
	int ret, i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	pi = pf->hw.port_info;
	numtc = vsi->tc_cfg.numtc;

	vsi_ctx = ice_get_vsi_ctx(pi->hw, vf->lan_vsi_idx);
	if (!vsi_ctx) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(*cap_list) + sizeof(cap_list->cap[0]) * (numtc - 1);
	cap_list = kzalloc(len, GFP_KERNEL);
	if (!cap_list) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	cap_list->vsi_id = vf->vm_vsi_num;
	cap_list->num_elem = numtc;

	/* Store the UP2TC configuration from DCB to a user priority bitmap
	 * of each TC. Each element of prio_of_tc represents one TC. Each
	 * bitmap indicates the user priorities belong to this TC.
	 */
	for (i = 0; i < ICE_MAX_USER_PRIORITY; i++) {
		tc = pi->qos_cfg.local_dcbx_cfg.etscfg.prio_table[i];
		tc_prio[tc] |= BIT(i);
	}

	for (i = 0; i < numtc; i++) {
		cfg = &cap_list->cap[i];
		cfg->tc_num = i;
		cfg->tc_prio = tc_prio[i];
		cfg->arbiter = pi->qos_cfg.local_dcbx_cfg.etscfg.tsatable[i];
		cfg->weight = VIRTCHNL_STRICT_WEIGHT;
		cfg->type = VIRTCHNL_BW_SHAPER;
		cfg->shaper.committed = vsi_ctx->sched.bw_t_info[i].cir_bw.bw;
		cfg->shaper.peak = vsi_ctx->sched.bw_t_info[i].eir_bw.bw;
	}
err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_QOS_CAPS, v_ret,
				    (u8 *)cap_list, len);
	kfree(cap_list);
	return ret;
}

/**
 * ice_validate_vf_q_tc_map - Validate configurations for queue TC mapping
 * @vf: pointer to the VF info
 * @qtc: pointer to the queue tc mapping info structure
 */
static int
ice_validate_vf_q_tc_map(struct ice_vf *vf,
			 struct virtchnl_queue_tc_mapping *qtc)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u16 offset = 0;
	int i;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "VF-%d has invalid VSI pointer\n",
			vf->vf_id);
		return -EINVAL;
	}

	if (qtc->num_queue_pairs >
	    min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(pf), "VF-%d requesting more than supported number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		return -EINVAL;
	}

	if (qtc->num_tc > vsi->tc_cfg.numtc) {
		dev_err(ice_pf_to_dev(pf), "VF-%d requesting more than supported number of TCs: %d\n",
			vf->vf_id, vsi->tc_cfg.numtc);
		return -EINVAL;
	}

	for (i = 0; i < qtc->num_tc; i++) {
		if ((u32)offset + (u32)qtc->tc[i].req.queue_count >
		    (u32)qtc->num_queue_pairs) {
			dev_err(ice_pf_to_dev(pf), "VF-%d queue count is invalid\n",
				vf->vf_id);
			return -EINVAL;
		}
		offset += qtc->tc[i].req.queue_count;
	}

	if (offset != qtc->num_queue_pairs) {
		dev_err(ice_pf_to_dev(pf), "VF-%d queues to be mapped do not equal to number of VF queue pairs\n",
			vf->vf_id);
		return -EINVAL;
	}

	return 0;
}

/**
 * ice_vc_cfg_q_tc_map - Configure per queue TC mapping
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command descriptor
 *
 * Configure VF queues TC mapping.
 */
static int ice_vc_cfg_q_tc_map(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_tc_mapping *tc_map = NULL;
	struct virtchnl_queue_tc_mapping *qtc =
		(struct virtchnl_queue_tc_mapping *)msg;
	u16 prio_bitmap[ICE_MAX_TRAFFIC_CLASS] = {0};
	u16 qmap = 0, pow = 0, offset = 0, len = 0;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_vsi_ctx *ctx = NULL;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u8 netdev_tc = 0;
	int i, ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_vc_isvalid_vsi_id(vf, qtc->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_validate_vf_q_tc_map(vf, qtc)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	}

	len = sizeof(*tc_map) + sizeof(tc_map->tc[0]) * (qtc->num_tc - 1);
	tc_map = kzalloc(len, GFP_KERNEL);
	if (!tc_map) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	tc_map->vsi_id = vf->vm_vsi_num;
	tc_map->num_tc = qtc->num_tc;
	tc_map->num_queue_pairs = qtc->num_queue_pairs;

	/* Get the corresponding user priority bitmap for each TC */
	for (i = 0; i < ICE_MAX_USER_PRIORITY; i++) {
		int uptc =
		    hw->port_info->qos_cfg.local_dcbx_cfg.etscfg.prio_table[i];

		prio_bitmap[uptc] = BIT(i);
	}
	/* Count queues number per TC, Rx and Tx queues are identical */
	for (i = 0; i < qtc->num_tc; i++) {
		vsi->tc_cfg.tc_info[i].qoffset = offset;
		vsi->tc_cfg.tc_info[i].qcount_tx = qtc->tc[i].req.queue_count;
		vsi->tc_cfg.tc_info[i].qcount_rx = qtc->tc[i].req.queue_count;
		vsi->tc_cfg.tc_info[i].netdev_tc = netdev_tc++;

		pow = (u16)order_base_2(qtc->tc[i].req.queue_count);
		qmap = FIELD_PREP(ICE_AQ_VSI_TC_Q_OFFSET_M, offset) |
		FIELD_PREP(ICE_AQ_VSI_TC_Q_NUM_M, pow);
		ctx->info.tc_mapping[i] = cpu_to_le16(qmap);
		offset += qtc->tc[i].req.queue_count;

		/* Write response message */
		tc_map->tc[i].resp.prio_type = VIRTCHNL_USER_PRIO_TYPE_UP;
		tc_map->tc[i].resp.valid_prio_bitmap = prio_bitmap[i];
	}

	ice_vsi_cfg_dcb_rings(vsi);

	/* Update Rx queue mapping */
	ctx->info.mapping_flags = vsi->info.mapping_flags;
	memcpy(&ctx->info.q_mapping, &vsi->info.q_mapping,
	       sizeof(vsi->info.q_mapping));
	ctx->info.valid_sections |=
		cpu_to_le16(ICE_AQ_VSI_PROP_RXQ_MAP_VALID);

	if (ice_update_vsi(hw, vsi->idx, ctx, NULL)) {
		dev_err(ice_pf_to_dev(pf), "Update VSI failed\n");
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
	} else {
		memcpy(&vsi->info.tc_mapping, ctx->info.tc_mapping,
		       sizeof(vsi->info.tc_mapping));
	}

err:
	/* send the response to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_QUEUE_TC_MAP,
				    v_ret, (u8 *)tc_map, len);
	kfree(ctx);
	kfree(tc_map);
	return ret;
}

/**
 * ice_vf_cfg_qs_bw - Configure per queue bandwidth
 * @vf: pointer to the VF info
 * @num_queues: number of queues to be configured
 *
 * Configure per queue bandwidth.
 */
static int ice_vf_cfg_qs_bw(struct ice_vf *vf, u16 num_queues)
{
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_vsi *vsi;
	u32 p_rate;
	int ret;
	u16 i;
	u8 tc;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return VIRTCHNL_STATUS_ERR_PARAM;

	for (i = 0; i < num_queues; i++) {
		p_rate = vf->qs_bw[i].peak;
		tc = vf->qs_bw[i].tc;
		if (p_rate) {
			ret = ice_cfg_q_bw_lmt(hw->port_info, vsi->idx, tc,
					       vf->qs_bw[i].queue_id,
					       ICE_MAX_BW, p_rate);
		} else {
			ret = ice_cfg_q_bw_dflt_lmt(hw->port_info, vsi->idx, tc,
						    vf->qs_bw[i].queue_id,
						    ICE_MAX_BW);
		}
		if (ret)
			return ret;
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_vf_cfg_q_quanta_profile
 * @vf: pointer to the VF info
 * @quanta_prof_idx: pointer to the quanta profile index
 * @quanta_size: quanta size to be set
 *
 * This function chooses available quanta profile and configures the register.
 * The quanta profile is evenly divided by the number of device ports, and then
 * available to the specific PF and VFs. The first profile for each PF is a
 * reserved default profile. Only quanta size of the rest unused profile can be
 * modified.
 */
static int ice_vf_cfg_q_quanta_profile(struct ice_vf *vf, u16 quanta_size,
				       u16 *quanta_prof_idx)
{
	const u16 n_desc = calc_quanta_desc(quanta_size);
	struct ice_hw *hw = &vf->pf->hw;
	const u16 n_cmd = 2 * n_desc;
	struct ice_pf *pf = vf->pf;
	u16 per_pf, begin_id;
	u8 n_used;
	u32 reg;

	per_pf = (GLCOMM_QUANTA_PROF_MAX_INDEX + 1) / hw->dev_caps.num_funcs;
	begin_id = hw->logical_pf_id * per_pf;
	n_used = pf->n_quanta_prof_used;

	if (quanta_size == ICE_DFLT_QUANTA) {
		*quanta_prof_idx = begin_id;
	} else {
		if (n_used < per_pf) {
			*quanta_prof_idx = begin_id + 1 + n_used;
			pf->n_quanta_prof_used++;
		} else {
			return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		}
	}

	reg = rd32(hw, GLCOMM_QUANTA_PROF(*quanta_prof_idx));
	reg &= ~GLCOMM_QUANTA_PROF_QUANTA_SIZE_M;
	reg |= quanta_size << GLCOMM_QUANTA_PROF_QUANTA_SIZE_S;
	reg &= ~GLCOMM_QUANTA_PROF_MAX_CMD_M;
	reg |= n_cmd << GLCOMM_QUANTA_PROF_MAX_CMD_S;
	reg &= ~GLCOMM_QUANTA_PROF_MAX_DESC_M;
	reg |= n_desc << GLCOMM_QUANTA_PROF_MAX_DESC_S;
	wr32(hw, GLCOMM_QUANTA_PROF(*quanta_prof_idx), reg);

	return VIRTCHNL_STATUS_SUCCESS;
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

	if (ice_set_rss_lut(vsi, vrl->lut, vsi->rss_table_size))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_LUT, v_ret,
				     NULL, 0);
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
	DECLARE_BITMAP(mcast_m, ICE_PROMISC_MAX) = {};
	DECLARE_BITMAP(ucast_m, ICE_PROMISC_MAX) = {};
	struct virtchnl_promisc_info *info =
	    (struct virtchnl_promisc_info *)msg;
	struct ice_vsi_vlan_ops *vlan_ops;
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
	if (!ice_is_vf_trusted(vf)) {
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

	vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	if (rm_promisc)
		ret = vlan_ops->ena_rx_filtering(vsi);
	else
		ret = vlan_ops->dis_rx_filtering(vsi);
	if (ret) {
		dev_err(dev, "Failed to configure VLAN pruning in promiscuous mode\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	ice_vf_get_promisc_masks(vf, vsi, ucast_m, mcast_m);

	if (!test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags)) {
		if (alluni)
			ret = ice_set_dflt_vsi(vsi);
		else
			ret = ice_clear_dflt_vsi(vsi);

		/* in this case we're turning on/off only
		 * allmulticast
		 */
		if (allmulti)
			mcast_err = ice_vf_set_vsi_promisc(vf, vsi, mcast_m);
		else
			mcast_err = ice_vf_clear_vsi_promisc(vf, vsi, mcast_m);

		if (ret) {
			ice_dev_err_errno(dev, ret,
					  "Turning on/off promiscuous mode for VF %d failed",
					  vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto error_param;
		}
	} else {
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
		else if (!allmulti &&
			 test_and_clear_bit(ICE_VF_STATE_MC_PROMISC,
					    vf->vf_states))
			dev_info(dev, "VF %u successfully unset multicast promiscuous mode\n",
				 vf->vf_id);
	} else {
		ice_dev_err_errno(dev, mcast_err,
				  "Error while modifying multicast promiscuous mode for VF %u",
				  vf->vf_id);
	}

	if (!ucast_err) {
		if (alluni &&
		    !test_and_set_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully set unicast promiscuous mode\n",
				 vf->vf_id);
		else if (!alluni &&
			 test_and_clear_bit(ICE_VF_STATE_UC_PROMISC,
					    vf->vf_states))
			dev_info(dev, "VF %u successfully unset unicast promiscuous mode\n",
				 vf->vf_id);
	} else {
		ice_dev_err_errno(dev, ucast_err,
				  "Error while modifying unicast promiscuous mode for VF %u",
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
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to enable the Rx queue passed in. If the Rx queue was successfully
 * enabled then set q_id bit in the enabled queues bitmap and return success.
 * Otherwise return error.
 */
static int
ice_vf_vsi_ena_single_rxq(struct ice_vf *vf, struct ice_vsi *vsi,
			  u16 q_id, u16 vf_q_id)
{
	int err;

	if (test_bit(vf_q_id, vf->rxq_ena))
		return 0;

	err = ice_vsi_ctrl_one_rx_ring(vsi, true, q_id, true);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to enable Rx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	ice_vf_ena_rxq_interrupt(vsi, q_id);
	set_bit(vf_q_id, vf->rxq_ena);

	return 0;
}

/**
 * ice_vf_vsi_ena_single_txq - enable single Tx queue based on relative q_id
 * @vf: VF to enable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Enable the Tx queue's interrupt then set the q_id bit in the enabled queues
 * bitmap. Note that the Tx queue(s) should have already been
 * configurated/enabled in VIRTCHNL_OP_CONFIG_QUEUES so this function only
 * enables the interrupt associated with the q_id.
 */
static void
ice_vf_vsi_ena_single_txq(struct ice_vf *vf, struct ice_vsi *vsi,
			  u16 q_id, u16 vf_q_id)
{
	if (test_bit(vf_q_id, vf->txq_ena))
		return;

	ice_vf_ena_txq_interrupt(vsi, q_id);
	/* set TXQ head value to 0x1FFF to indicate no packet is sent. According
	 * to CPK HAS Transmit Queue Context Structure, the size of descriptor
	 * queue is from 8 descriptores (QLEN=0x8) to 8K-32 descriptors
	 * (QLEN=0x1FE0). So QTX_COMM_HEAD.HEAD rang value from 0x1fe0 to 0x1fff
	 * is reserved and will never be used by HW. So, use 0x1FFF as a marker.
	 * This is used by live migration.
	 */
	if (vf->migration_active)
		wr32(&vsi->back->hw, QTX_COMM_HEAD(vsi->txq_map[q_id]),
		     QTX_COMM_HEAD_HEAD_M);
	set_bit(vf_q_id, vf->txq_ena);
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
		u16 q_id;

		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi, &q_id);
		if (ice_is_vf_adq_ena(vf) && tc >= ICE_VF_CHNL_START_TC) {
			if (!ice_vf_adq_vsi_valid(vf, tc)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		if (!ice_vc_isvalid_q_id(vsi, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (ice_vf_vsi_ena_single_rxq(vf, vsi, q_id, vf_q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	}

	tc = 0;
	/* Grab VSI pointer again since it may have been modified */
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	q_map = vqs->tx_queues;
	for_each_set_bit(vf_q_id, &q_map, ICE_MAX_DFLT_QS_PER_VF) {
		u16 q_id;

		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi, &q_id);
		if (ice_is_vf_adq_ena(vf) && tc >= ICE_VF_CHNL_START_TC) {
			if (!ice_vf_adq_vsi_valid(vf, tc)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		if (!ice_vc_isvalid_q_id(vsi, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		ice_vf_vsi_ena_single_txq(vf, vsi, q_id, vf_q_id);
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
 * ice_vf_vsi_dis_single_txq - disable a single Tx queue
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to disable the Tx queue passed in. If the Tx queue was successfully
 * disabled then clear q_id bit in the enabled queues bitmap and return
 * success. Otherwise return error.
 */
static int
ice_vf_vsi_dis_single_txq(struct ice_vf *vf, struct ice_vsi *vsi,
			  u16 q_id, u16 vf_q_id)
{
	struct ice_txq_meta txq_meta = { 0 };
	struct ice_tx_ring *ring;
	int err;

	if (!test_bit(vf_q_id, vf->txq_ena))
		dev_dbg(ice_pf_to_dev(vsi->back), "Queue %u on VSI %u is not enabled, but stopping it anyway\n",
			q_id, vsi->vsi_num);

	ring = vsi->tx_rings[q_id];
	if (!ring)
		return -EINVAL;

	ice_fill_txq_meta(vsi, ring, &txq_meta);

	err = ice_vsi_stop_tx_ring(vsi, ICE_NO_RESET, vf->vf_id, ring,
				   &txq_meta);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Tx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	/* Clear enabled queues flag */
	clear_bit(vf_q_id, vf->txq_ena);

	return 0;
}

/**
 * ice_vf_vsi_dis_single_rxq - disable a Rx queue for VF on relative queue ID
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to disable the Rx queue passed in. If the Rx queue was successfully
 * disabled then clear q_id bit in the enabled queues bitmap and return success.
 * Otherwise return error.
 */

static int
ice_vf_vsi_dis_single_rxq(struct ice_vf *vf, struct ice_vsi *vsi,
			  u16 q_id, u16 vf_q_id)
{
	int err;

	if (!test_bit(vf_q_id, vf->rxq_ena))
		return 0;

	err = ice_vsi_ctrl_one_rx_ring(vsi, false, q_id, true);
	if (err) {
		dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Rx ring %d on VSI %d\n",
			q_id, vsi->vsi_num);
		return err;
	}

	/* Clear enabled queues flag */
	clear_bit(vf_q_id, vf->rxq_ena);

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
			u16 q_id;

			ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
						 &q_id);
			if (ice_is_vf_adq_ena(vf) &&
			    tc >= ICE_VF_CHNL_START_TC) {
				if (!ice_vf_adq_vsi_valid(vf, tc)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}

			if (!ice_vc_isvalid_q_id(vsi, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (ice_vf_vsi_dis_single_txq(vf, vsi, q_id, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	q_map = vqs->rx_queues;
	tc = 0;
	/* Reset VSI pointer as it was assigned to ADQ VSIs */
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}
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
			u16 q_id;

			ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
						 &q_id);
			if (ice_is_vf_adq_ena(vf) &&
			    tc >= ICE_VF_CHNL_START_TC) {
				if (!ice_vf_adq_vsi_valid(vf, tc)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}
			if (!ice_vc_isvalid_q_id(vsi, q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (ice_vf_vsi_dis_single_rxq(vf, vsi, q_id, vf_q_id)) {
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
 * @tc: traffic class number for ADQ
 * @map: vector map for mapping vectors to queues
 * @q_vector: structure for interrupt vector
 * configure the IRQ to queue map
 */
static enum virtchnl_status_code
ice_cfg_interrupt(struct ice_vf *vf, struct ice_vsi *vsi,
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

		if (!ice_vc_isvalid_q_id(vsi, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_rx++;
		q_vector->rx.itr_idx = map->rxitr_idx;
		vsi->rx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_rxq_interrupt(vsi, vsi_q_id,
				      q_vector->vf_reg_idx,
				      q_vector->rx.itr_idx);
	}

	qmap = map->txq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, ICE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_q_id = vsi_q_id_idx;

		if (tc && ice_is_vf_adq_ena(vf))
			vsi_q_id = ice_vf_get_tc_based_qid(vsi_q_id_idx,
							   vf->ch[tc].offset);

		if (!ice_vc_isvalid_q_id(vsi, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_tx++;
		q_vector->tx.itr_idx = map->txitr_idx;
		vsi->tx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_txq_interrupt(vsi, vsi_q_id,
				      q_vector->vf_reg_idx,
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
	    pf->vfs.num_msix_per < num_q_vectors_mapped ||
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
		}
		/* vector_id is always 0-based for each VF, and can never be
		 * larger than or equal to the max allowed interrupts per VF
		 */
		if (!(vector_id < pf->vfs.num_msix_per) ||
		    !ice_vc_isvalid_vsi_id(vf, vsi_id) ||
		    (!vector_id && (map->rxq_map || map->txq_map))) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* No need to map VF miscellaneous or rogue vector */
		if (!vector_id)
			continue;

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
		q_vector = vf->vf_ops->get_q_vector(vsi, vector_id_ch);

		if (!q_vector) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* lookout for the invalid queue index */
		v_ret = ice_cfg_interrupt(vf, vsi, tc, map, q_vector);
		if (v_ret)
			goto error_param;

		/* Update VSI and TC only when ADQ is configured */
		if (ice_is_vf_adq_ena(vf)) {
			if (tc + 1 >= vf->num_tc)
				goto error_param;
			if (vector_id == vf->ch[tc + 1].offset) {
				vsi = pf->vsi[vf->ch[tc + 1].vsi_idx];
				tc++;
			}
		}
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_IRQ_MAP, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_get_max_allowed_qpairs - get max allowed queue pairs
 * @vf: VF used to get max queue pairs allowed
 *
 * The maximum allowed queues is determined based on whether
 * VIRTCHNL_VF_LARGE_NUM_QPAIRS was negotiated.
 */
static int ice_vc_get_max_allowed_qpairs(struct ice_vf *vf)
{
	if (vf->driver_caps & VIRTCHNL_VF_LARGE_NUM_QPAIRS)
		return ICE_MAX_QS_PER_VF;

	return ICE_MAX_DFLT_QS_PER_VF;
}

/**
 * ice_vc_cfg_q_bw - Configure per queue bandwidth
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command descriptor
 *
 * Configure VF queues bandwidth.
 */
static int ice_vc_cfg_q_bw(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queues_bw_cfg *qbw =
		(struct virtchnl_queues_bw_cfg *)msg;
	struct ice_vf_qs_bw *qs_bw;
	struct ice_vsi *vsi;
	size_t len;
	u16 i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !ice_vc_isvalid_vsi_id(vf, qbw->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (qbw->num_queues > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(vf->pf), "VF-%d trying to configure more than allocated number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	for (i = 0; i < qbw->num_queues; i++) {
		if (qbw->cfg[i].shaper.peak != 0 && vf->max_tx_rate != 0 &&
		    qbw->cfg[i].shaper.peak > vf->max_tx_rate) {
			dev_warn(ice_pf_to_dev(vf->pf), "The maximum queue %d rate limit configuration may not take effect because the maximum TX rate for VF-%d is %d\n",
				 qbw->cfg[i].queue_id, vf->vf_id,
				 vf->max_tx_rate);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		if (qbw->cfg[i].shaper.committed != 0 && vf->min_tx_rate != 0 &&
		    qbw->cfg[i].shaper.committed < vf->min_tx_rate) {
			dev_warn(ice_pf_to_dev(vf->pf), "The minimum queue %d rate limit configuration may not take effect because the minimum TX rate for VF-%d is %d\n",
				 qbw->cfg[i].queue_id, vf->vf_id,
				 vf->min_tx_rate);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		if (qbw->cfg[i].queue_id > vf->num_vf_qs) {
			dev_warn(ice_pf_to_dev(vf->pf), "VF-%d trying to configure invalid queue_id\n",
				 vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		if (qbw->cfg[i].tc >= VIRTCHNL_MAX_ADQ_V2_CHANNELS) {
			dev_warn(ice_pf_to_dev(vf->pf), "VF-%d trying to configure invalid TC\n",
				 vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err_bw;
		}
	}

	len = sizeof(struct ice_vf_qs_bw) * qbw->num_queues;
	qs_bw = kzalloc(len, GFP_KERNEL);
	if (!qs_bw) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err_bw;
	}

	for (i = 0; i < qbw->num_queues; i++) {
		qs_bw[i].queue_id = qbw->cfg[i].queue_id;
		qs_bw[i].peak = qbw->cfg[i].shaper.peak;
		qs_bw[i].committed = qbw->cfg[i].shaper.committed;
		qs_bw[i].tc = qbw->cfg[i].tc;
	}

	memcpy(vf->qs_bw, qs_bw, len);

err_bw:
	kfree(qs_bw);

err:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_QUEUE_BW,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_cfg_q_quanta - Configure per queue quanta
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command descriptor
 *
 * Configure VF queues quanta.
 */
static int ice_vc_cfg_q_quanta(struct ice_vf *vf, u8 *msg)
{
	u16 quanta_prof_id, quanta_size, start_qid, num_queues, end_qid, i;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_quanta_cfg *qquanta =
		(struct virtchnl_quanta_cfg *)msg;
	struct ice_vsi *vsi;
	int ret;

	start_qid = qquanta->queue_select.start_queue_id;
	num_queues = qquanta->queue_select.num_queues;
	quanta_size = qquanta->quanta_size;
	end_qid = start_qid + num_queues;

	if ((u32)start_qid + num_queues > (u32)((u16)-1)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (end_qid > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(vf->pf), "VF-%d trying to configure more than allocated number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (quanta_size > ICE_MAX_QUANTA_SIZE ||
	    quanta_size < ICE_MIN_QUANTA_SIZE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (quanta_size % 64) {
		dev_err(ice_pf_to_dev(vf->pf), "quanta size should be the product of 64\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ret = ice_vf_cfg_q_quanta_profile(vf, quanta_size,
					  &quanta_prof_id);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	for (i = start_qid; i < end_qid; i++)
		vsi->tx_rings[i]->quanta_prof_id = quanta_prof_id;

err:
	/* send the response to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_QUANTA,
				    v_ret, NULL, 0);
	return ret;
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
	struct virtchnl_vsi_queue_config_info *qci =
	    (struct virtchnl_vsi_queue_config_info *)msg;
	struct virtchnl_queue_pair_info *qpi;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi = NULL;
	u16 queue_id_tmp, tc;
	int i = -1, q_idx;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		goto error_param;

	if (!ice_vc_isvalid_vsi_id(vf, qci->vsi_id))
		goto error_param;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		goto error_param;


	if (qci->num_queue_pairs > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(pf), "VF-%d trying to configure more than allocated number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		goto error_param;
	}

	queue_id_tmp = 0;
	tc = 0;
	for (i = 0; i < qci->num_queue_pairs; i++) {
		if (!qci->qpair[i].rxq.crc_disable)
			continue;

		if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_CRC) ||
		    vf->dcf_vlan_info.outer_stripping_ena ||
		    vf->vlan_strip_ena)
			goto error_param;
	}
	for (i = 0; i < qci->num_queue_pairs; i++) {
		qpi = &qci->qpair[i];

		if (qpi->txq.vsi_id != qci->vsi_id ||
		    qpi->rxq.vsi_id != qci->vsi_id ||
		    qpi->rxq.queue_id != qpi->txq.queue_id ||
		    qpi->txq.headwb_enabled ||
		    !ice_vc_isvalid_ring_len(qpi->txq.ring_len) ||
		    !ice_vc_isvalid_ring_len(qpi->rxq.ring_len) ||
		    !ice_vc_isvalid_q_id(vsi, qpi->txq.queue_id))
			goto error_param;

		if (ice_is_vf_adq_ena(vf)) {
			q_idx = queue_id_tmp;
			vsi = ice_find_vsi(vf->pf, vf->ch[tc].vsi_num);
			if (!vsi)
				goto error_param;
		} else {
			q_idx = qpi->rxq.queue_id;
		}

		/* make sure selected "q_idx" is in valid range of queues
		 * for selected "vsi" (which could be main VF VSI or
		 * VF ADQ VSI
		 */
		if (q_idx >= vsi->alloc_txq || q_idx >= vsi->alloc_rxq)
			goto error_param;

		/* copy Tx queue info from VF into VSI */
		if (qpi->txq.ring_len > 0) {
			vsi->tx_rings[q_idx]->dma = qpi->txq.dma_ring_addr;
			vsi->tx_rings[q_idx]->count = qpi->txq.ring_len;

			/* Disable any existing queue first */
			if (ice_vf_vsi_dis_single_txq(vf, vsi, q_idx,
						      qpi->txq.queue_id))
				goto error_param;

			/* Configure a queue with the requested settings */
			if (ice_vsi_cfg_single_txq(vsi, vsi->tx_rings, q_idx)) {
				dev_warn(ice_pf_to_dev(pf), "VF-%d failed to configure TX queue %d\n",
					 vf->vf_id, i);
				goto error_param;
			}
		}

		/* copy Rx queue info from VF into VSI */
		if (qpi->rxq.ring_len > 0) {
			u16 max_frame_size = ice_vc_get_max_frame_size(vf);
			u32 rxdid;

			vsi->rx_rings[q_idx]->dma = qpi->rxq.dma_ring_addr;
			vsi->rx_rings[q_idx]->count = qpi->rxq.ring_len;

			if (qpi->rxq.crc_disable)
				vsi->rx_rings[q_idx]->flags |=
					ICE_RX_FLAGS_CRC_STRIP_DIS;
			else
				vsi->rx_rings[q_idx]->flags &=
					~ICE_RX_FLAGS_CRC_STRIP_DIS;

			if (qpi->rxq.databuffer_size != 0 &&
			    (qpi->rxq.databuffer_size > ((16 * 1024) - 128) ||
			     qpi->rxq.databuffer_size < 1024))
				goto error_param;

			vsi->rx_buf_len = qpi->rxq.databuffer_size;
			vsi->rx_rings[q_idx]->rx_buf_len = vsi->rx_buf_len;
			if (qpi->rxq.max_pkt_size > max_frame_size ||
			    qpi->rxq.max_pkt_size < 64)
				goto error_param;

			vsi->max_frame = qpi->rxq.max_pkt_size;
			/* add space for the port VLAN since the VF driver is
			 * not expected to account for it in the MTU
			 * calculation
			 */
			if (ice_vf_is_port_vlan_ena(vf))
				vsi->max_frame += VLAN_HLEN;

			if (ice_vsi_cfg_single_rxq(vsi, q_idx)) {
				dev_warn(ice_pf_to_dev(pf), "VF-%d failed to configure RX queue %d\n",
					 vf->vf_id, i);
				goto error_param;
			}

			/* If Rx flex desc is supported, select RXDID for Rx
			 * queues. Otherwise, use legacy 32byte descriptor
			 * format. Legacy 16byte descriptor is not supported.
			 * If this RXDID is selected, return error.
			 */
			if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC) {
				rxdid = qpi->rxq.rxdid;
				if (!(BIT(rxdid) & pf->supported_rxdids))
					goto error_param;
			} else {
				rxdid = ICE_RXDID_LEGACY_1;
			}
			if (vf->driver_caps &
			    VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC &&
			    vf->driver_caps & VIRTCHNL_VF_CAP_PTP &&
			    qpi->rxq.flags & VIRTCHNL_PTP_RX_TSTAMP)
				ice_write_qrxflxp_cntxt(&vsi->back->hw,
							vsi->rxq_map[q_idx],
							rxdid, 0x03, true);
			else
				ice_write_qrxflxp_cntxt(&vsi->back->hw,
							vsi->rxq_map[q_idx],
							rxdid, 0x03, false);
		}

		/* For ADQ there can be up to 4 VSIs with max 4 queues each.
		 * VF does not know about these additional VSIs and all
		 * it cares is about its own queues. PF configures these queues
		 * to its appropriate VSIs based on TC mapping
		 */
		if (ice_is_vf_adq_ena(vf) && tc < vf->num_tc - 1) {
			if (queue_id_tmp == (vf->ch[tc].num_qps - 1)) {
				tc++;
				/* reset the queue num */
				queue_id_tmp = 0;
			} else {
				queue_id_tmp++;
			}
		}
	}

	if (ice_vf_cfg_qs_bw(vf, qci->num_queue_pairs))
		goto error_param;

	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES,
				     VIRTCHNL_STATUS_SUCCESS, NULL, 0);
error_param:
	/* disable whatever we can */
	if (vsi) {
		if (i >= qci->num_queue_pairs)
			i = qci->num_queue_pairs - 1;
		for (; i >= 0; i--) {
			qpi = &qci->qpair[i];

			if (ice_vsi_ctrl_one_rx_ring(vsi, false, i, true))
				dev_err(ice_pf_to_dev(pf), "VF-%d could not disable RX queue %d\n",
					vf->vf_id, i);
			if (!ice_vc_isvalid_q_id(vsi, qpi->txq.queue_id))
				continue;
			if (ice_vf_vsi_dis_single_txq(vf, vsi, i,
						      qpi->txq.queue_id))
				dev_err(ice_pf_to_dev(pf), "VF-%d could not disable TX queue %d\n",
					vf->vf_id, i);
		}
	}

	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES,
				     VIRTCHNL_STATUS_ERR_PARAM, NULL, 0);
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
static u8 ice_vc_ether_addr_type(struct virtchnl_ether_addr *vc_ether_addr)
{
	return (vc_ether_addr->type & VIRTCHNL_ETHER_ADDR_TYPE_MASK);
}

/**
 * ice_is_vc_addr_legacy - check if the MAC address is from an older VF
 * @vc_ether_addr: VIRTCHNL structure that contains MAC and type
 */
static bool ice_is_vc_addr_legacy(struct virtchnl_ether_addr *vc_ether_addr)
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
static bool ice_is_vc_addr_primary(struct virtchnl_ether_addr *vc_ether_addr)
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
	int ret = 0;

	/* device MAC already added */
	if (!ether_addr_equal(mac_addr, vf->dev_lan_addr.addr)) {
		if (is_unicast_ether_addr(mac_addr) &&
		    !ice_can_vf_change_mac(vf)) {
			dev_err(dev, "VF attempting to override administratively set MAC address, bring down and up the VF interface to resume normal operation\n");
			return -EPERM;
		}

		ret = ice_fltr_add_mac(vsi, mac_addr, ICE_FWD_TO_VSI);
		if (ret == -EEXIST) {
			dev_dbg(dev, "MAC %pM already exists for VF %d\n",
				mac_addr, vf->vf_id);
			/* don’t return since we might need to update
			 * the primary MAC in ice_vfhw_mac_add() below
			 */
		} else if (ret) {
			dev_err(dev, "Failed to add MAC %pM for VF %d, error %d\n",
				mac_addr, vf->vf_id, ret);
			return ret;
		} else {
			vf->num_mac++;

			if (ice_is_mc_lldp_eth_addr(mac_addr)) {
				vsi->lldp_macs++;
				ice_ena_vf_rx_lldp(vf);
			}
		}

		ice_vfhw_mac_add(vf, vc_ether_addr);
	}

	return ret;
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
 * ice_update_legacy_cached_mac - update cached hardware MAC for legacy VF
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to check
 *
 * only update cached hardware MAC for legacy VF drivers on delete
 * because we cannot guarantee order/type of MAC from the VF driver
 */
static void
ice_update_legacy_cached_mac(struct ice_vf *vf,
			     struct virtchnl_ether_addr *vc_ether_addr)
{
	if (!ice_is_vc_addr_legacy(vc_ether_addr) ||
	    ice_is_legacy_umac_expired(&vf->legacy_last_added_umac))
		return;

	ether_addr_copy(vf->dev_lan_addr.addr, vf->legacy_last_added_umac.addr);
	ether_addr_copy(vf->hw_lan_addr.addr, vf->legacy_last_added_umac.addr);
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

	ice_update_legacy_cached_mac(vf, vc_ether_addr);
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
	int status = 0;

	if (!ice_can_vf_change_mac(vf) &&
	    ether_addr_equal(vf->dev_lan_addr.addr, mac_addr))
		return 0;

	status = ice_fltr_remove_mac(vsi, mac_addr, ICE_FWD_TO_VSI);
	if (status == -ENOENT) {
		dev_err(dev, "MAC %pM does not exist for VF %d\n", mac_addr,
			vf->vf_id);
		return -ENOENT;
	} else if (status) {
		dev_err(dev, "Failed to delete MAC %pM for VF %d, error %d\n",
			mac_addr, vf->vf_id, status);
		return -EIO;
	}

	if (ice_is_mc_lldp_eth_addr(mac_addr))
		vsi->lldp_macs--;

	if (vsi->rx_lldp_ena && !vsi->lldp_macs)
		ice_cfg_sw_lldp(vsi, false, false);

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

		if (is_zero_ether_addr(mac_addr))
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
 * ice_check_avail_qs_contig
 * @pf: pointer to the PF structure
 * @num_queues: number of queues requested
 *
 * check if available queues are contiguous
 */
static bool ice_check_avail_qs_contig(struct ice_pf *pf, u16 num_queues)
{
	u16 txqs_index, rxqs_index;

	mutex_lock(&pf->avail_q_mutex);

	txqs_index = bitmap_find_next_zero_area(pf->avail_txqs, pf->max_pf_txqs,
						0, num_queues, 0);
	rxqs_index = bitmap_find_next_zero_area(pf->avail_rxqs, pf->max_pf_rxqs,
						0, num_queues, 0);
	mutex_unlock(&pf->avail_q_mutex);

	if (txqs_index < pf->max_pf_txqs && rxqs_index < pf->max_pf_rxqs)
		return true;
	else
		return false;
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
	u16 cur_queues, cnt = 0;
	u16 tx_rx_queue_left;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	/* Wait for SR-IOV enablement */
	do {
		if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags))
			break;
		cnt++;
		msleep_interruptible(50);
	} while (cnt < 200);

	if (cnt == 200) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		dev_err(dev, "SR-IOV not enabled\n");
		goto error_param;
	}

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
		vfres->num_queue_pairs = min_t(u16, max_avail_vf_qps,
					       max_allowed_vf_qps);
	} else if (!ice_check_avail_qs_contig(pf, req_queues)) {
		dev_warn(dev, "VF %d requested %u more queues but are not contiguous, falling back to default %u queues.\n",
			 vf->vf_id, req_queues - cur_queues, cur_queues);
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
	} else {
		/* request is successful, then reset VF */
		vf->num_req_qs = req_queues;
		ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);
		dev_info(dev, "VF %d granted request of %u queues.\n",
			 vf->vf_id, req_queues);
		return 0;
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_REQUEST_QUEUES,
				     v_ret, (u8 *)vfres, sizeof(*vfres));
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
 * ice_is_vlan_promisc_allowed - check if VLAN promiscuous config is allowed
 * @vf: VF used to determine if VLAN promiscuous config is allowed
 */
static bool ice_is_vlan_promisc_allowed(struct ice_vf *vf)
{
	if ((test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	     test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) &&
	    test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, vf->pf->flags))
		return true;

	return false;
}

/**
 * ice_vf_ena_vlan_promisc - Enable Tx/Rx VLAN promiscuous for the VLAN
 * @vf: VF to enable VLAN promisc on
 * @vsi: VF's VSI used to enable VLAN promiscuous mode
 * @vlan: VLAN used to enable VLAN promiscuous
 *
 * This function should only be called if VLAN promiscuous mode is allowed,
 * which can be determined via ice_is_vlan_promisc_allowed().
 */
static int
ice_vf_ena_vlan_promisc(struct ice_vf *vf, struct ice_vsi *vsi,
			struct ice_vlan *vlan)
{
	DECLARE_BITMAP(promisc_m, ICE_PROMISC_MAX) = {};
	int status;

	if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states))
		ice_set_vf_ucast_vlan_promisc_bits(promisc_m);
	if (test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
		ice_set_mcast_vlan_promisc_bits(promisc_m);
	if (bitmap_empty(promisc_m, ICE_PROMISC_MAX))
		return 0;

	status = ice_fltr_set_vsi_promisc(&vsi->back->hw, vsi->idx, promisc_m,
					  vlan->vid, vsi->port_info->lport);
	if (status && status != -EEXIST)
		return status;

	return 0;
}

/**
 * ice_vf_dis_vlan_promisc - Disable Tx/Rx VLAN promiscuous for the VLAN
 * @vf: VF to disable VLAN promisc on
 * @vsi: VF's VSI used to disable VLAN promiscuous mode for
 * @vlan: VLAN used to disable VLAN promiscuous
 *
 * This function should only be called if VLAN promiscuous mode is allowed,
 * which can be determined via ice_is_vlan_promisc_allowed().
 */
static int
ice_vf_dis_vlan_promisc(struct ice_vf *vf, struct ice_vsi *vsi,
			struct ice_vlan *vlan)
{
	DECLARE_BITMAP(promisc_m, ICE_PROMISC_MAX) = {};
	int status;

	ice_set_vf_ucast_promisc_bits(promisc_m);
	ice_set_mcast_promisc_bits(promisc_m);

	status = ice_fltr_clear_vsi_promisc(&vsi->back->hw, vsi->idx, promisc_m,
					    vlan->vid, vsi->port_info->lport);
	if (status && status != -ENOENT)
		return status;

	return 0;
}

/**
 * ice_vf_has_max_vlans - check if VF already has the max allowed VLAN filters
 * @vf: VF to check against
 * @vsi: VF's VSI
 *
 * If the VF is trusted then the VF is allowed to add as many VLANs as it
 * wants to, so return false.
 *
 * When the VF is untrusted compare the number of non-zero VLANs + 1 to the max
 * allowed VLANs for an untrusted VF. Return the result of this comparison.
 */
static bool ice_vf_has_max_vlans(struct ice_vf *vf, struct ice_vsi *vsi)
{
	if (ice_is_vf_trusted(vf))
		return false;

#define ICE_VF_ADDED_VLAN_ZERO_FLTRS	1
	return ((ice_vsi_num_non_zero_vlans(vsi) +
		 ICE_VF_ADDED_VLAN_ZERO_FLTRS) >= ICE_MAX_VLAN_PER_VF);
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
	int status = 0;
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

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (add_v && ice_vf_has_max_vlans(vf, vsi)) {
		dev_info(dev, "VF-%d is not trusted, switch the VF to trusted mode, in order to add more VLAN addresses\n",
			 vf->vf_id);
		/* There is no need to let VF know about being not trusted,
		 * so we can just return success message here
		 */
		goto error_param;
	}

	/* in DVM a VF can add/delete inner VLAN filters when
	 * VIRTCHNL_VF_OFFLOAD_VLAN is negotiated, so only reject in SVM
	 */
	if (ice_vf_is_port_vlan_ena(vf) && !ice_is_dvm_ena(&pf->hw)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* in DVM VLAN promiscuous is based on the outer VLAN, which would be
	 * the port VLAN if VIRTCHNL_VF_OFFLOAD_VLAN was negotiated, so only
	 * allow vlan_promisc = true in SVM and if no port VLAN is configured
	 */
	vlan_promisc = ice_is_vlan_promisc_allowed(vf) &&
		!ice_is_dvm_ena(&pf->hw) &&
		!ice_vf_is_port_vlan_ena(vf);

	if (add_v) {
		for (i = 0; i < vfl->num_elements; i++) {
			u16 vid = vfl->vlan_id[i];
			struct ice_vlan vlan;

			if (ice_vf_has_max_vlans(vf, vsi)) {
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

			vlan = ICE_VLAN(ETH_P_8021Q, vid, 0, ICE_FWD_TO_VSI);
			status = vsi->inner_vlan_ops.add_vlan(vsi, &vlan);
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Enable VLAN filtering on first non-zero VLAN */
			if (!vlan_promisc && vid && !ice_is_dvm_ena(&pf->hw)) {
				if (vsi->inner_vlan_ops.ena_rx_filtering(vsi)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					ice_dev_err_errno(dev, status,
							  "Enable VLAN pruning on VLAN ID: %d failed",
							  vid);
					goto error_param;
				}
			} else if (vlan_promisc) {
				status = ice_vf_ena_vlan_promisc(vf, vsi,
								 &vlan);
				if (status) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					ice_dev_err_errno(dev, status,
							  "Enable Unicast/multicast promiscuous mode on VLAN ID:%d failed",
							  vid);
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
			struct ice_vlan vlan;

			/* we add VLAN 0 by default for each VF so we can enable
			 * Tx VLAN anti-spoof without triggering MDD events so
			 * we don't want a VIRTCHNL request to remove it
			 */
			if (!vid)
				continue;

			vlan = ICE_VLAN(ETH_P_8021Q, vid, 0, ICE_FWD_TO_VSI);
			status = vsi->inner_vlan_ops.del_vlan(vsi, &vlan);
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Disable VLAN filtering when only VLAN 0 is left */
			if (!ice_vsi_has_non_zero_vlans(vsi))
				vsi->inner_vlan_ops.dis_rx_filtering(vsi);

			if (vlan_promisc)
				ice_vf_dis_vlan_promisc(vf, vsi, &vlan);
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
 * ice_vsi_is_rxq_crc_strip_dis - check if Rx queue CRC strip is disabled or not
 * @vsi: pointer to the VF VSI info
 */
static bool ice_vsi_is_rxq_crc_strip_dis(struct ice_vsi *vsi)
{
	u16 i;

	for (i = 0; i < vsi->alloc_rxq; i++)
		if (vsi->rx_rings[i]->flags & ICE_RX_FLAGS_CRC_STRIP_DIS)
			return true;

	return false;
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
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_vsi_is_rxq_crc_strip_dis(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto error_param;
	}
	if (vsi->inner_vlan_ops.ena_stripping(vsi, ETH_P_8021Q))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	else
		vf->vlan_strip_ena |= ICE_INNER_VLAN_STRIP_ENA;

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

	if (vsi->inner_vlan_ops.dis_stripping(vsi))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	else
		vf->vlan_strip_ena &= ~ICE_INNER_VLAN_STRIP_ENA;

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
	struct ice_vsi *vsi;
	struct device *dev;
	int status;

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
	struct iidc_core_dev_info *rcdi;
	struct iidc_auxiliary_drv *iadrv;
	int ret = -ENODEV;

	rcdi = ice_find_cdev_info_by_id(vf->pf, IIDC_RDMA_ID);
	if (!rcdi) {
		pr_err("Invalid RDMA peer attempted to send message to peer\n");
		return -EIO;
	}

	mutex_lock(&vf->pf->adev_mutex);
	device_lock(&rcdi->adev->dev);
	iadrv = ice_get_auxiliary_drv(rcdi);
	if (iadrv && iadrv->vc_receive) {
		u16 vf_abs_id = ice_abs_vf_id(&vf->pf->hw, vf->vf_id);

		ret = iadrv->vc_receive(rcdi, vf_abs_id, msg, len);
	}
	device_unlock(&rcdi->adev->dev);
	mutex_unlock(&vf->pf->adev_mutex);
	if (ret)
		ice_dev_err_errno(ice_pf_to_dev(vf->pf), ret,
				  "Failed to send message to RDMA peer");

	return ret;
}

/**
 * ice_vc_cfg_rdma_irq_map_msg - MSIX mapping of RDMA control queue interrupts
 * @vf: VF structure associated to the VF that requested the mapping
 * @msg: Message from the VF used to configure the RDMA mapping
 *
 * Handler for the VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP opcode in virtchnl. This
 * causes the specified control queues to be mapped to the specified MSIX
 * indices and ITR indices. Also, the control queue's interrupt will be
 * enabled.
 */
static int ice_vc_cfg_rdma_irq_map_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rdma_qvlist_info *qvlist =
		(struct virtchnl_rdma_qvlist_info *)msg;
	const struct ice_vf_ops *ops = vf->vf_ops;
	u16 num_msix_per_vf;
	u32 i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	num_msix_per_vf = vf->pf->vfs.num_msix_per;
	if (qvlist->num_vectors > num_msix_per_vf) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	for (i = 0; i < qvlist->num_vectors; i++) {
		struct virtchnl_rdma_qv_info *qv_info = &qvlist->qv_info[i];

		if (qv_info->v_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->ceq_idx == VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->aeq_idx == VIRTCHNL_RDMA_INVALID_QUEUE_IDX) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->ceq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->ceq_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->aeq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->aeq_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
	}

	for (i = 0; i < qvlist->num_vectors; i++) {
		struct virtchnl_rdma_qv_info *qv_info = &qvlist->qv_info[i];

		ops->cfg_rdma_irq_map(vf, qv_info);
	}

err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_clear_rdma_irq_map - clear mapped RDMA control queue interrupts
 * @vf: VF structure associated to the VF that requested to release the mapping
 *
 * Handler for the VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP opcode in virtchnl. This
 * causes all of the MSIX mapping of all the RDMA control queues to be cleared
 * and disabled.
 */
static int ice_vc_clear_rdma_irq_map(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	const struct ice_vf_ops *ops = vf->vf_ops;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ops->clear_rdma_irq_map(vf);

err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP,
				     v_ret, NULL, 0);
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
	struct virtchnl_supported_rxdids rxdid = {};
	struct ice_pf *pf = vf->pf;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	rxdid.supported_rxdids = pf->supported_rxdids;

err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
				     v_ret, (u8 *)&rxdid, sizeof(rxdid));
}

/**
 * ice_vf_init_vlan_stripping - enable/disable VLAN stripping on initialization
 * @vf: VF to enable/disable VLAN stripping for on initialization
 *
 * Set the default for VLAN stripping based on whether a port VLAN is configured
 * and the current VLAN mode of the device.
 */
static int ice_vf_init_vlan_stripping(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	vf->vlan_strip_ena = 0;

	if (!vsi)
		return -EINVAL;

	/* don't modify stripping if port VLAN is configured in SVM since the
	 * port VLAN is based on the inner/single VLAN in SVM
	 */
	if (ice_vf_is_port_vlan_ena(vf) && !ice_is_dvm_ena(&vsi->back->hw))
		return 0;

	if (ice_vf_vlan_offload_ena(vf->driver_caps)) {
		int err = vsi->inner_vlan_ops.ena_stripping(vsi, ETH_P_8021Q);

		if (!err)
			vf->vlan_strip_ena |= ICE_INNER_VLAN_STRIP_ENA;

		return err;
	}

	return vsi->inner_vlan_ops.dis_stripping(vsi);
}

/**
 * ice_validate_tpid - validate the VLAN TPID
 * @tpid: VLAN TPID
 */
static int ice_validate_tpid(u16 tpid)
{
	if (tpid == ETH_P_8021Q ||
	    tpid == ETH_P_8021AD ||
	    tpid == ETH_P_QINQ1)
		return 0;

	return -EINVAL;
}

/**
 * ice_vc_dcf_vlan_offload_msg - send msg to handle VLAN offload from DCF
 * @vf: pointer to VF info
 * @msg: pointer to msg buffer
 */
static int ice_vc_dcf_vlan_offload_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_dcf_vlan_offload *offload;
	struct ice_dcf_vlan_info *dcf_vlan;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *target_vsi;
	struct ice_vf *target_vf;
	u16 insert_mode;
	u16 strip_mode;
	u16 vlan_flags;
	u16 vlan_type;

	offload = (struct virtchnl_dcf_vlan_offload *)msg;

	if (!ice_is_dvm_ena(&pf->hw) ||
	    !(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_VLAN_V2) ||
	    !ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vlan_flags = offload->vlan_flags;
	insert_mode = FIELD_GET(VIRTCHNL_DCF_VLAN_INSERT_MODE_M, vlan_flags);
	strip_mode = FIELD_GET(VIRTCHNL_DCF_VLAN_STRIP_MODE_M, vlan_flags);
	vlan_type = FIELD_GET(VIRTCHNL_DCF_VLAN_TYPE_M, vlan_flags);

	if (ice_validate_tpid(offload->tpid) ||
	    (!insert_mode && !strip_mode) ||
	    vlan_type != VIRTCHNL_DCF_VLAN_TYPE_OUTER ||
	    offload->vlan_id >= VLAN_N_VID) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	target_vf = ice_get_vf_by_id(pf, offload->vf_id);
	if (!target_vf) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_check_vf_ready_for_cfg(target_vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err_put_target_vf;
	}

	target_vsi = ice_get_vf_vsi(target_vf);
	if (!target_vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err_put_target_vf;
	}

	if (ice_vf_is_port_vlan_ena(target_vf) ||
	    ice_vsi_has_non_zero_vlans(target_vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err_put_target_vf;
	}

	dcf_vlan = &target_vf->dcf_vlan_info;

	if (insert_mode == VIRTCHNL_DCF_VLAN_INSERT_DISABLE) {
		if (dcf_vlan->outer_port_vlan.vid) {
			dcf_vlan->outer_port_vlan.vid = 0;
			dcf_vlan->applying = 1;
		}
	} else if (insert_mode == VIRTCHNL_DCF_VLAN_INSERT_PORT_BASED) {
		if (strip_mode) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err_put_target_vf;
		}

		if (dcf_vlan->outer_port_vlan.tpid != offload->tpid ||
		    dcf_vlan->outer_port_vlan.vid != offload->vlan_id) {
			dcf_vlan->outer_port_vlan.tpid = offload->tpid;
			dcf_vlan->outer_port_vlan.vid = offload->vlan_id;
			dcf_vlan->outer_port_vlan.prio = 0;
			dcf_vlan->outer_port_vlan.fwd_act = ICE_FWD_TO_VSI;
			dcf_vlan->applying = 1;
		}
	} else if (insert_mode) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err_put_target_vf;
	}

	if (strip_mode == VIRTCHNL_DCF_VLAN_STRIP_DISABLE) {
		if (dcf_vlan->outer_stripping_ena) {
			dcf_vlan->outer_stripping_ena = 0;
			dcf_vlan->applying = 1;
		}
	} else if (strip_mode == VIRTCHNL_DCF_VLAN_STRIP_INTO_RX_DESC) {
		if (dcf_vlan->outer_stripping_tpid != offload->tpid ||
		    !dcf_vlan->outer_stripping_ena) {
			if (ice_vsi_is_rxq_crc_strip_dis(target_vsi)) {
				v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
				goto err_put_target_vf;
			}
			dcf_vlan->outer_stripping_tpid = offload->tpid;
			dcf_vlan->outer_stripping_ena = 1;
			dcf_vlan->applying = 1;
		}
	} else if (strip_mode) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err_put_target_vf;
	}

	if (dcf_vlan->applying)
		ice_reset_vf(target_vf,
			     ICE_VF_RESET_NOTIFY | ICE_VF_RESET_LOCK);

err_put_target_vf:
	ice_put_vf(target_vf);
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_VLAN_OFFLOAD,
				     v_ret, NULL, 0);
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
	u16 v_msg_len = 0;
	u8 *v_msg = NULL;
	int aq_ret;
	int ret;

	pf->dcf.aq_desc_received = false;

	if ((aq_buf && !aq_buf_size) || (!aq_buf && aq_buf_size))
		return -EINVAL;

	if (ice_dcf_is_acl_aq_cmd(aq_desc) && !ice_dcf_is_acl_capable(&pf->hw))
		return 0;

	if (ice_dcf_is_udp_tunnel_aq_cmd(aq_desc, aq_buf) &&
	    !(pf->hw.dcf_caps & DCF_UDP_TUNNEL_CAP) &&
	    !ice_is_tunnel_empty(&pf->hw))
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
	/* It needs to send back the AQ response message if -EIO returns, some
	 * AdminQ handlers will use the error code filled by FW to do exception
	 * handling.
	 */
	if (aq_ret && aq_ret != -EIO) {
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		v_op = VIRTCHNL_OP_DCF_CMD_DESC;
		goto err;
	}

	if (aq_ret != -EIO) {
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
 * ice_dcf_pre_handle_desc - Pre-handle the DCF AdminQ command descriptor
 * @vf: pointer to the VF info
 * @aq_desc: the AdminQ command descriptor
 *
 * Pre-handle the DCF AdminQ command descriptor before sending it to the
 * firmware. Since DCF does not have some necessary information for specific
 * AdminQ commands, PF needs to complete the descriptor.
 */
static void
ice_dcf_pre_handle_desc(struct ice_vf *vf, struct ice_aq_desc *aq_desc)
{
	struct ice_hw *hw = &vf->pf->hw;

	switch (le16_to_cpu(aq_desc->opcode)) {
	case ice_aqc_opc_query_port_ets:
		aq_desc->params.port_ets.port_teid =
			hw->port_info->root->info.node_teid;
		break;
	default:
		break;
	}
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

	/* Pre-handle the descriptor for specific DCF AdminQ commands */
	ice_dcf_pre_handle_desc(vf, aq_desc);

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
		ice_clear_dcf_acl_cfg(vf->pf);
		ice_clear_dcf_udp_tunnel_cfg(vf->pf);
		vf->pf->hw.dcf_caps &= ~(DCF_ACL_CAP | DCF_UDP_TUNNEL_CAP);
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
	struct ice_vf *tmp_vf;
	unsigned int bkt;
	u16 len = 0;
	u16 num_vfs;
	int ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	num_vfs = ice_get_num_vfs(pf);

	len = struct_size(vsi_map, vf_vsi, num_vfs - 1);
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
	vsi_map->num_vfs = num_vfs;

	mutex_lock(&pf->vfs.table_lock);
	ice_for_each_vf(pf, bkt, tmp_vf) {
		if (!ice_is_vf_disabled(tmp_vf) &&
		    test_bit(ICE_VF_STATE_INIT, tmp_vf->vf_states)) {
			struct ice_vsi *tmp_vsi = ice_get_vf_vsi(tmp_vf);

			if (!tmp_vsi)
				continue;

			vsi_map->vf_vsi[tmp_vf->vf_id] = tmp_vsi->vsi_num |
				VIRTCHNL_DCF_VF_VSI_VALID;
		}
	}
	mutex_unlock(&pf->vfs.table_lock);
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
 * ice_dcf_cfg_vf_tc_bw_lmt - Configure VF bandwidth per TC
 * @vf: pointer to the VF info
 * @cfg_list: pointer to the VF TC bandwidth configuration
 *
 * Configure the bandwidth for VF VSI per enabled TC. If
 * bandwidth is zero, default configuration is applied.
 */
static int
ice_dcf_cfg_vf_tc_bw_lmt(struct ice_vf *vf,
			 struct virtchnl_dcf_bw_cfg_list *cfg_list)
{
	struct ice_port_info *pi = vf->pf->hw.port_info;
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct virtchnl_dcf_bw_cfg *cfg;
	u32 committed_rate;
	u32 peak_rate;
	int i, ret;

	if (!vsi)
		return -EINVAL;

	for (i = 0; i < cfg_list->num_elem; i++) {
		cfg = &cfg_list->cfg[i];
		peak_rate = cfg->shaper.peak;
		committed_rate = cfg->shaper.committed;

		if (cfg->bw_type & VIRTCHNL_DCF_BW_PIR) {
			if (peak_rate) {
				ret =
				ice_cfg_vsi_bw_lmt_per_tc(pi, vsi->idx,
							  cfg->tc_num,
							  ICE_MAX_BW,
							  peak_rate);
				if (ret)
					return ret;
			} else {
				/* If max bandwidth is zero, use default
				 * config
				 */
				ret =
				ice_cfg_vsi_bw_dflt_lmt_per_tc(pi,
							       vsi->idx,
							       cfg->tc_num,
							       ICE_MAX_BW);
				if (ret)
					return ret;
			}
		}

		if (cfg->bw_type & VIRTCHNL_DCF_BW_CIR) {
			if (committed_rate) {
				ret =
				ice_cfg_vsi_bw_lmt_per_tc(pi, vsi->idx,
							  cfg->tc_num,
							  ICE_MIN_BW,
							  committed_rate);
				if (ret)
					return ret;
			} else {
				/* If min bandwidth is zero, use default
				 * config
				 */
				ret =
				ice_cfg_vsi_bw_dflt_lmt_per_tc(pi,
							       vsi->idx,
							       cfg->tc_num,
							       ICE_MIN_BW);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

/**
 * ice_dcf_tc_total_peak - Calculate the total max bandwidth of all TCs
 * @cfg_list: pointer to the VF TC bandwidth configuration
 */
static u32 ice_dcf_tc_total_peak(struct virtchnl_dcf_bw_cfg_list *cfg_list)
{
	u32 total_peak = 0;
	int i;

	for (i = 0; i < cfg_list->num_elem; i++)
		total_peak += cfg_list->cfg[i].shaper.peak;

	return total_peak;
}

/**
 * ice_dcf_cfg_tc_node_bw_lmt - Configure TC node bandwidth
 * @pf: pointer to the PF info
 * @cfg_list: pointer to the VF TC bandwidth configuration
 *
 * Configure the bandwidth for enabled TC nodes. If bandwidth is zero,
 * default configuration is applied.
 */
static int
ice_dcf_cfg_tc_node_bw_lmt(struct ice_pf *pf,
			   struct virtchnl_dcf_bw_cfg_list *cfg_list)
{
	struct ice_port_info *pi = pf->hw.port_info;
	struct device *dev = ice_pf_to_dev(pf);
	struct virtchnl_dcf_bw_cfg *cfg;
	u32 peak_rate;
	int i, ret;

	for (i = 0; i < cfg_list->num_elem; i++) {
		cfg = &cfg_list->cfg[i];
		peak_rate = cfg->shaper.peak;

		if (pi->qos_cfg.local_dcbx_cfg.etscfg.tsatable[cfg->tc_num] !=
			VIRTCHNL_ABITER_STRICT) {
			dev_dbg(dev, "TC %u: TC node max bandwidth can only be configured in Strict Priority mode\n",
				cfg->tc_num);
			continue;
		}

		/* Since TC node CIR configuring is not supported, only
		 * configure PIR to guarantee max and min bandwidth of each TC.
		 * Because PIR and CIR can be both configured in below, any of
		 * the bw_type is allowed.
		 */
		if (cfg->bw_type &
		    (VIRTCHNL_DCF_BW_PIR | VIRTCHNL_DCF_BW_CIR)) {
			if (peak_rate) {
				ret = ice_cfg_tc_node_bw_lmt(pi,
							     cfg->tc_num,
							     ICE_MAX_BW,
							     peak_rate);
				if (ret)
					return ret;
			} else {
				/* If max bandwidth is zero, use default config
				 * (no rate limit)
				 */
				ret = ice_cfg_tc_node_bw_dflt_lmt(pi,
								  cfg->tc_num,
								  ICE_MAX_BW);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

/**
 * ice_dcf_validate_bw - Validate bandwidth for TC and VF VSI
 * @pf: pointer to the PF info
 * @vf: pointer to the VF info
 * @cfg_list: pointer to the VF TC bandwidth configuration
 *
 * Validate the min and max bandwidth for TC and VF VSI in advance before
 * configuring.
 */
static int
ice_dcf_validate_bw(struct ice_pf *pf, struct ice_vf *vf,
		    struct virtchnl_dcf_bw_cfg_list *cfg_list)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct virtchnl_dcf_bw_cfg *cfg;
	u32 committed_rate, peak_rate;
	bool lowest_cir_mark = false;
	struct ice_vsi *vsi;
	u32 total_peak = 0;
	int i, speed;

	if (cfg_list->node_type == VIRTCHNL_DCF_TARGET_TC_BW) {
		total_peak = ice_dcf_tc_total_peak(cfg_list);
		vsi = ice_get_main_vsi(pf);
	} else {
		vsi = ice_get_vf_vsi(vf);
	}

	if (!vsi)
		return -EINVAL;

	speed = ice_get_link_speed_kbps(vsi);

	for (i = 0; i < cfg_list->num_elem; i++) {
		cfg = &cfg_list->cfg[i];
		peak_rate = cfg->shaper.peak;
		committed_rate = cfg->shaper.committed;

		if (!(BIT(cfg->tc_num) & vsi->tc_cfg.ena_tc)) {
			dev_err(dev, "TC %u: TC is not enabled\n",
				cfg->tc_num);
			return -EINVAL;
		}

		if (cfg_list->node_type == VIRTCHNL_DCF_TARGET_TC_BW) {
			u32 rest_peak = total_peak - peak_rate;
			/* For TC larger than the lowest TC with none-zero min
			 * bandwidth, max bandwidth must be set.
			 */
			if (lowest_cir_mark && peak_rate == 0) {
				dev_err(dev, "TC %u: Max bandwidth must be configured\n",
					cfg->tc_num);
				return -EINVAL;
			}

			if (!lowest_cir_mark && committed_rate)
				lowest_cir_mark = true;

			if (committed_rate &&
			    committed_rate + rest_peak > (u32)speed) {
				dev_err(dev, "TC %u: Min bandwidth plus other TCs' max bandwidth %uKbps exceeds port link speed %uKbps\n",
					cfg->tc_num,
					committed_rate + rest_peak, speed);
				return -EINVAL;
			}
		}

		/* If min bandwidth is 0, use default setting. If not 0, min
		 * bandwidth should be larger than 500Kbps.
		 */
		if (committed_rate && committed_rate < ICE_SCHED_MIN_BW) {
			dev_err(dev, "TC %u: If min Tx bandwidth is set for %s %d, it cannot be less than 500Kbps\n",
				cfg->tc_num,
				ice_vsi_type_str(vsi->type),
				vsi->idx);
			return -EINVAL;
		}

		if (peak_rate && committed_rate > peak_rate) {
			dev_err(dev, "TC %u: Cannot set min Tx bandwidth greater than max Tx bandwidth for %s %d\n",
				cfg->tc_num,
				ice_vsi_type_str(vsi->type),
				vsi->idx);
			return -EINVAL;
		}

		if (peak_rate > (u32)speed) {
			dev_err(dev, "TC %u: Invalid max Tx bandwidth %uKbps specified for %s %d is greater than current link speed %uKbps\n",
				cfg->tc_num, peak_rate,
				ice_vsi_type_str(vsi->type),
				vsi->idx, speed);
			return -EINVAL;
		}

		if (committed_rate > (u32)speed) {
			dev_err(dev, "TC %u: Invalid min Tx bandwidth %uKbps specified for %s %d is greater than current link speed %uKbps\n",
				cfg->tc_num, committed_rate,
				ice_vsi_type_str(vsi->type),
				vsi->idx, speed);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * ice_vc_dcf_config_tc - Configure VF and TC bandwidth
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer which holds the command buffer
 *
 * Configure Tx scheduler node's bandwidth per enabled TC
 * for assigned VF, as well as TC nodes.
 */
static int ice_vc_dcf_config_tc(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_dcf_bw_cfg_list *bwcfg_list;
	struct ice_pf *pf = vf->pf;
	struct ice_vf *target_vf;

	bwcfg_list = (struct virtchnl_dcf_bw_cfg_list *)msg;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!ice_is_vf_dcf(vf) || ice_dcf_get_state(pf) != ICE_DCF_STATE_ON) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_dcf_validate_bw(pf, vf, bwcfg_list)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (bwcfg_list->node_type == VIRTCHNL_DCF_TARGET_TC_BW) {
		if (ice_dcf_cfg_tc_node_bw_lmt(pf, bwcfg_list)) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto err;
		}
	} else {
		target_vf = ice_get_vf_by_id(pf, bwcfg_list->vf_id);
		if (!target_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (ice_check_vf_ready_for_cfg(target_vf)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			ice_put_vf(target_vf);
			goto err;
		}

		if (ice_dcf_cfg_vf_tc_bw_lmt(target_vf, bwcfg_list))
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;

		ice_put_vf(target_vf);
	}

err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DCF_CONFIG_BW, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_get_max_rss_qregion - handler for VIRTCHNL_OP_GET_MAX_RSS_QREGION
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

	max_rss_qregion->vport_id = vf->vm_vsi_num;
	max_rss_qregion->qregion_width = ilog2(ICE_MAX_RSS_QS_PER_VF);
	if (vsi->global_lut_id)
		max_rss_qregion->qregion_width = ilog2(ICE_MAX_RSS_QS_PER_LARGE_VF);

error_param:
	err = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_MAX_RSS_QREGION, v_ret,
				    (u8 *)max_rss_qregion, len);
	kfree(max_rss_qregion);
	return err;
}

static bool ice_vc_supported_queue_type(s32 queue_type)
{
	return (queue_type == VIRTCHNL_QUEUE_TYPE_RX ||
		queue_type == VIRTCHNL_QUEUE_TYPE_TX);
}

/**
 * ice_vf_get_tc_of_qid
 * @vf: Pointer to VF
 * @vf_q_id: VF relative qid
 *
 * Finds the TC of VF queue. Returns -1 if queue is not found.
 */
static int
ice_vf_get_tc_of_qid(struct ice_vf *vf, unsigned int vf_q_id)
{
	int tc;

	for (tc = 0; tc < vf->num_tc; tc++) {
		if (vf_q_id < vf->ch[tc].offset + vf->ch[tc].num_qps)
			return tc;
	}
	return -1;
}

/**
 * ice_vf_get_vsi_of_qid
 * @vf : Pointer to VF
 * @vf_qid: VF relative qid
 *
 * Find corresponding VSI for a given VF qid
 */
static struct ice_vsi *ice_vf_get_vsi_of_qid(struct ice_vf *vf, u32 vf_qid)
{
	struct ice_pf *pf = vf->pf;
	int tc;

	if (!ice_is_vf_adq_ena(vf))
		return ice_get_vf_vsi(vf);

	tc = ice_vf_get_tc_of_qid(vf, vf_qid);
	if (tc < 0)
		return NULL;

	return pf->vsi[vf->ch[tc].vsi_idx];
}

/**
 * ice_vf_get_vsi_qid
 * @vf : Pointer to VF
 * @vf_qid: VF relative qid
 *
 * Find corresponding VSI relative qid for a given VF qid
 */
static int ice_vf_get_vsi_qid(struct ice_vf *vf, u32 vf_qid)
{
	int tc;

	if (!ice_is_vf_adq_ena(vf))
		return vf_qid;

	tc = ice_vf_get_tc_of_qid(vf, vf_qid);
	if (tc < 0)
		return -1;
	return (vf_qid - vf->ch[tc].offset);
}

/**
 * ice_vc_validate_qs_v2_msg - validate all qs_msg parameters
 * @vf: VF the message was received from
 * @qs_msg: contents of the message from the VF
 *
 * Used to validate both the VIRTCHNL_OP_ENABLE_QUEUES_V2 and
 * VIRTCHNL_OP_DISABLE_QUEUES_V2 messages. This should always be called before
 * attempting to enable and/or disable queues on behalf of a VF in response to
 * the preivously mentioned opcodes. If all checks succeed, then return
 * success indicating to the caller that the qs_msg is valid. Otherwise return
 * false, indicating to the caller that the qs_msg is invalid.
 */
static bool
ice_vc_validate_qs_v2_msg(struct ice_vf *vf,
			  struct virtchnl_del_ena_dis_queues *qs_msg)
{
	struct virtchnl_queue_chunks *chunks = &qs_msg->chunks;
	int i;

	if (!chunks->num_chunks)
		return false;

	for (i = 0; i < chunks->num_chunks; i++) {
		u32 max_queue_in_chunk;

		if (!ice_vc_supported_queue_type(chunks->chunks[i].type))
			return false;

		if (!chunks->chunks[i].num_queues)
			return false;

		max_queue_in_chunk = chunks->chunks[i].start_queue_id +
				     chunks->chunks[i].num_queues;
		if (max_queue_in_chunk > vf->num_vf_qs)
			return false;
	}

	return true;
}

#define ice_for_each_q_in_chunk(chunk, q_id) \
	for ((q_id) = (chunk)->start_queue_id; \
	     (q_id) < (chunk)->start_queue_id + (chunk)->num_queues; \
	     (q_id)++)

static int
ice_vc_ena_rxq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi;
	int vsi_qid;
	u32 vf_qid;

	ice_for_each_q_in_chunk(chunk, vf_qid) {
		int err;

		vsi = ice_vf_get_vsi_of_qid(vf, vf_qid);
		vsi_qid = ice_vf_get_vsi_qid(vf, vf_qid);
		if (!vsi || vsi_qid < 0)
			return -EINVAL;

		err = ice_vf_vsi_ena_single_rxq(vf, vsi, vsi_qid, vf_qid);
		if (err)
			return err;
	}

	return 0;
}

static int
ice_vc_ena_txq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi;
	int vsi_qid;
	u32 vf_qid;

	ice_for_each_q_in_chunk(chunk, vf_qid) {
		vsi = ice_vf_get_vsi_of_qid(vf, vf_qid);
		vsi_qid = ice_vf_get_vsi_qid(vf, vf_qid);
		if (!vsi || vsi_qid < 0)
			return -EINVAL;

		ice_vf_vsi_ena_single_txq(vf, vsi, vsi_qid, vf_qid);
	}

	return 0;
}

/**
 * ice_vc_ena_qs_v2_msg - message handling for VIRTCHNL_OP_ENABLE_QUEUES_V2
 * @vf: source of the request
 * @msg: message to handle
 */
static int ice_vc_ena_qs_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_del_ena_dis_queues *ena_qs_msg;
	struct virtchnl_queue_chunks *chunks;
	int i;

	ena_qs_msg = (struct virtchnl_del_ena_dis_queues *)msg;
	chunks = &ena_qs_msg->chunks;

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

		if (chunk->type == VIRTCHNL_QUEUE_TYPE_RX &&
		    ice_vc_ena_rxq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		else if (chunk->type == VIRTCHNL_QUEUE_TYPE_TX &&
			 ice_vc_ena_txq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;

		if (v_ret != VIRTCHNL_STATUS_SUCCESS)
			goto error_param;
	}

	set_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES_V2,
				     v_ret, NULL, 0);
}

static int
ice_vc_dis_rxq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi;
	int vsi_qid;
	u32 vf_qid;

	ice_for_each_q_in_chunk(chunk, vf_qid) {
		int err;

		vsi = ice_vf_get_vsi_of_qid(vf, vf_qid);
		vsi_qid = ice_vf_get_vsi_qid(vf, vf_qid);
		if (!vsi || vsi_qid < 0)
			return -EINVAL;

		err = ice_vf_vsi_dis_single_rxq(vf, vsi, vsi_qid, vf_qid);
		if (err)
			return err;
	}

	return 0;
}

static int
ice_vc_dis_txq_chunk(struct ice_vf *vf, struct virtchnl_queue_chunk *chunk)
{
	struct ice_vsi *vsi;
	int vsi_qid;
	u32 vf_qid;

	ice_for_each_q_in_chunk(chunk, vf_qid) {
		int err;

		vsi = ice_vf_get_vsi_of_qid(vf, vf_qid);
		vsi_qid = ice_vf_get_vsi_qid(vf, vf_qid);
		if (!vsi || vsi_qid < 0)
			return -EINVAL;

		err = ice_vf_vsi_dis_single_txq(vf, vsi, vsi_qid, vf_qid);
		if (err)
			return err;
	}

	return 0;
}

/**
 * ice_vc_dis_qs_v2_msg - message handling for VIRTCHNL_OP_DISABLE_QUEUES_V2
 * @vf: source of the request
 * @msg: message to handle
 */
static int ice_vc_dis_qs_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_del_ena_dis_queues *dis_qs_msg;
	struct virtchnl_queue_chunks *chunks;
	int i;

	dis_qs_msg = (struct virtchnl_del_ena_dis_queues *)msg;
	chunks = &dis_qs_msg->chunks;

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

		if (chunk->type == VIRTCHNL_QUEUE_TYPE_RX &&
		    ice_vc_dis_rxq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		else if (chunk->type == VIRTCHNL_QUEUE_TYPE_TX &&
			 ice_vc_dis_txq_chunk(vf, chunk))
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;

		if (v_ret != VIRTCHNL_STATUS_SUCCESS)
			goto error_param;
	}

	if (ice_vf_has_no_qs_ena(vf))
		clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_validate_qv_maps - validate parameters sent in the qs_msg structure
 * @vf: VF the message was received from
 * @qv_maps: contents of the message from the VF
 *
 * Used to validate VIRTCHNL_OP_MAP_VECTOR  messages. This should always be
 * called before attempting map interrupts to queues. If all checks succeed,
 * then return success indicating to the caller that the qv_maps are valid.
 * Otherwise return false, indicating to the caller that the qv_maps are
 * invalid.
 */
static bool
ice_vc_validate_qv_maps(struct ice_vf *vf,
			struct virtchnl_queue_vector_maps *qv_maps)
{
	struct ice_vsi *vsi;
	int i, total_vectors;

	vsi = vf->pf->vsi[vf->lan_vsi_idx];
	if (!vsi)
		return false;

	/* Multiple VSIs exist when ADQ is configured. So, use
	 * total queue count calculated from vf->ch structure
	 * as the limit
	 */
	if (ice_is_vf_adq_ena(vf)) {
		int tc;

		total_vectors = ICE_NONQ_VECS_VF;
		for (tc = 0; tc < vf->num_tc; tc++)
			total_vectors += vf->ch[tc].num_qps;
	} else {
		total_vectors = vsi->num_q_vectors + ICE_NONQ_VECS_VF;
	}

	if (!qv_maps->num_qv_maps)
		return false;

	for (i = 0; i < qv_maps->num_qv_maps; i++) {
		if (!ice_vc_supported_queue_type(qv_maps->qv_maps[i].queue_type))
			return false;

		if (qv_maps->qv_maps[i].queue_id >= vf->num_vf_qs)
			return false;

		if (qv_maps->qv_maps[i].vector_id >= total_vectors ||
		    qv_maps->qv_maps[i].vector_id < ICE_NONQ_VECS_VF)
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
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_vector_maps *qv_maps;
	struct ice_vsi *vsi;
	u16 tc = 0;
	int i;

	qv_maps = (struct virtchnl_queue_vector_maps *)msg;

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

	for (i = 0; i < qv_maps->num_qv_maps; i++) {
		struct virtchnl_queue_vector *qv_map = &qv_maps->qv_maps[i];
		struct ice_q_vector *q_vector;
		u16 vector_id;
		int vsi_q_id;

		vsi = ice_get_vf_vsi(vf);
		vsi_q_id = qv_map->queue_id;
		vector_id = qv_map->vector_id;

		/* qv_maps has 2 entries per queue hence the divide by 2 */
		if (ice_is_vf_adq_ena(vf)) {
			vsi = vf->pf->vsi[vf->ch[tc].vsi_idx];
			vsi_q_id = ice_vf_get_tc_based_qid(i / 2,
							   vf->ch[tc].offset);
			vector_id = qv_map->vector_id - vf->ch[tc].offset;
			if (tc + 1 >= vf->num_tc) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			if ((i + 1) / 2 == vf->ch[tc + 1].offset)
				tc++;
		}

		if (!vsi) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		q_vector = vf->vf_ops->get_q_vector(vsi, vector_id);

		if (!q_vector) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}


		if (!ice_vc_isvalid_q_id(vsi, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		if (qv_map->queue_type == VIRTCHNL_QUEUE_TYPE_RX)
			ice_cfg_rxq_interrupt(vsi, vsi_q_id,
					      q_vector->vf_reg_idx,
					      qv_map->itr_idx);
		else if (qv_map->queue_type == VIRTCHNL_QUEUE_TYPE_TX)
			ice_cfg_txq_interrupt(vsi, vsi_q_id,
					      q_vector->vf_reg_idx,
					      qv_map->itr_idx);
	}

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_MAP_QUEUE_VECTOR,
				     v_ret, NULL, 0);
}

static u16 ice_vc_get_max_vlan_fltrs(struct ice_vf *vf)
{
	if (vf->trusted)
		return VLAN_N_VID;
	else
		return ICE_MAX_VLAN_PER_VF;
}

/**
 * ice_vf_outer_vlan_not_allowed - check if outer VLAN can be used
 * @vf: VF that being checked for
 *
 * When the device is in double VLAN mode, check whether or not the outer VLAN
 * is allowed.
 */
static bool ice_vf_outer_vlan_not_allowed(struct ice_vf *vf)
{
	if (ice_vf_is_port_vlan_ena(vf))
		return true;

	if (vf->dcf_vlan_info.outer_port_vlan.vid ||
	    vf->dcf_vlan_info.outer_stripping_ena)
		return true;

	return false;
}

/**
 * ice_vc_set_dvm_caps - set VLAN capabilities when the device is in DVM
 * @vf: VF that capabilities are being set for
 * @caps: VLAN capabilities to populate
 *
 * Determine VLAN capabilities support based on whether a port VLAN is
 * configured. If a port VLAN is configured then the VF should use the inner
 * filtering/offload capabilities since the port VLAN is using the outer VLAN
 * capabilies.
 */
static void
ice_vc_set_dvm_caps(struct ice_vf *vf, struct virtchnl_vlan_caps *caps)
{
	struct virtchnl_vlan_supported_caps *supported_caps;

	if (ice_vf_outer_vlan_not_allowed(vf)) {
		/* until support for inner VLAN filtering is added when a port
		 * VLAN is configured, only support software offloaded inner
		 * VLANs when a port VLAN is confgured in DVM
		 */
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.insertion_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		caps->offloads.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100;
		caps->offloads.ethertype_match =
			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
	} else {
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
		supported_caps->outer = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_ETHERTYPE_88A8 |
					VIRTCHNL_VLAN_ETHERTYPE_9100 |
					VIRTCHNL_VLAN_ETHERTYPE_AND;
		caps->filtering.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100 |
						 VIRTCHNL_VLAN_ETHERTYPE_88A8 |
						 VIRTCHNL_VLAN_ETHERTYPE_9100;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_ETHERTYPE_88A8 |
					VIRTCHNL_VLAN_ETHERTYPE_9100 |
					VIRTCHNL_VLAN_ETHERTYPE_XOR |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2;

		supported_caps = &caps->offloads.insertion_support;
		supported_caps->inner = VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_ETHERTYPE_88A8 |
					VIRTCHNL_VLAN_ETHERTYPE_9100 |
					VIRTCHNL_VLAN_ETHERTYPE_XOR |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2;

		caps->offloads.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100;

		caps->offloads.ethertype_match =
			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
	}

	caps->filtering.max_filters = ice_vc_get_max_vlan_fltrs(vf);
}

/**
 * ice_vc_set_svm_caps - set VLAN capabilities when the device is in SVM
 * @vf: VF that capabilities are being set for
 * @caps: VLAN capabilities to populate
 *
 * Determine VLAN capabilities support based on whether a port VLAN is
 * configured. If a port VLAN is configured then the VF does not have any VLAN
 * filtering or offload capabilities since the port VLAN is using the inner VLAN
 * capabilities in single VLAN mode (SVM). Otherwise allow the VF to use inner
 * VLAN fitlering and offload capabilities.
 */
static void
ice_vc_set_svm_caps(struct ice_vf *vf, struct virtchnl_vlan_caps *caps)
{
	struct virtchnl_vlan_supported_caps *supported_caps;

	if (ice_vf_is_port_vlan_ena(vf)) {
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.insertion_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		caps->offloads.ethertype_init = VIRTCHNL_VLAN_UNSUPPORTED;
		caps->offloads.ethertype_match = VIRTCHNL_VLAN_UNSUPPORTED;
		caps->filtering.max_filters = 0;
	} else {
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;
		caps->filtering.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.insertion_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		caps->offloads.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100;
		caps->offloads.ethertype_match =
			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
		caps->filtering.max_filters = ice_vc_get_max_vlan_fltrs(vf);
	}
}

/**
 * ice_vc_get_offload_vlan_v2_caps - determine VF's VLAN capabilities
 * @vf: VF to determine VLAN capabilities for
 *
 * This will only be called if the VF and PF successfully negotiated
 * VIRTCHNL_VF_OFFLOAD_VLAN_V2.
 *
 * Set VLAN capabilities based on the current VLAN mode and whether a port VLAN
 * is configured or not.
 */
static int ice_vc_get_offload_vlan_v2_caps(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_caps *caps = NULL;
	int err, len = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	caps = kzalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto out;
	}
	len = sizeof(*caps);

	if (ice_is_dvm_ena(&vf->pf->hw))
		ice_vc_set_dvm_caps(vf, caps);
	else
		ice_vc_set_svm_caps(vf, caps);

	/* store negotiated caps to prevent invalid VF messages */
	memcpy(&vf->vlan_v2_caps, caps, sizeof(*caps));

out:
	err = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS,
				    v_ret, (u8 *)caps, len);
	kfree(caps);
	return err;
}

/**
 * ice_vc_validate_vlan_tpid - validate VLAN TPID
 * @filtering_caps: negotiated/supported VLAN filtering capabilities
 * @tpid: VLAN TPID used for validation
 *
 * Convert the VLAN TPID to a VIRTCHNL_VLAN_ETHERTYPE_* and then compare against
 * the negotiated/supported filtering caps to see if the VLAN TPID is valid.
 */
static bool ice_vc_validate_vlan_tpid(u16 filtering_caps, u16 tpid)
{
	enum virtchnl_vlan_support vlan_ethertype = VIRTCHNL_VLAN_UNSUPPORTED;

	switch (tpid) {
	case ETH_P_8021Q:
		vlan_ethertype = VIRTCHNL_VLAN_ETHERTYPE_8100;
		break;
	case ETH_P_8021AD:
		vlan_ethertype = VIRTCHNL_VLAN_ETHERTYPE_88A8;
		break;
	case ETH_P_QINQ1:
		vlan_ethertype = VIRTCHNL_VLAN_ETHERTYPE_9100;
		break;
	}

	if (!(filtering_caps & vlan_ethertype))
		return false;

	return true;
}

/**
 * ice_vc_is_valid_vlan - validate the virtchnl_vlan
 * @vc_vlan: virtchnl_vlan to validate
 *
 * If the VLAN TCI and VLAN TPID are 0, then this filter is invalid, so return
 * false. Otherwise return true.
 */
static bool ice_vc_is_valid_vlan(struct virtchnl_vlan *vc_vlan)
{
	if (!vc_vlan->tci || !vc_vlan->tpid)
		return false;

	return true;
}

/**
 * ice_vc_validate_vlan_filter_list - validate the filter list from the VF
 * @vfc: negotiated/supported VLAN filtering capabilities
 * @vfl: VLAN filter list from VF to validate
 *
 * Validate all of the filters in the VLAN filter list from the VF. If any of
 * the checks fail then return false. Otherwise return true.
 */
static bool
ice_vc_validate_vlan_filter_list(struct virtchnl_vlan_filtering_caps *vfc,
				 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	u16 i;

	if (!vfl->num_elements)
		return false;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_supported_caps *filtering_support =
			&vfc->filtering_support;
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *outer = &vlan_fltr->outer;
		struct virtchnl_vlan *inner = &vlan_fltr->inner;

		if ((ice_vc_is_valid_vlan(outer) &&
		     filtering_support->outer == VIRTCHNL_VLAN_UNSUPPORTED) ||
		    (ice_vc_is_valid_vlan(inner) &&
		     filtering_support->inner == VIRTCHNL_VLAN_UNSUPPORTED))
			return false;

		if ((outer->tci_mask &&
		     !(filtering_support->outer & VIRTCHNL_VLAN_FILTER_MASK)) ||
		    (inner->tci_mask &&
		     !(filtering_support->inner & VIRTCHNL_VLAN_FILTER_MASK)))
			return false;

		if (((outer->tci & VLAN_PRIO_MASK) &&
		     !(filtering_support->outer & VIRTCHNL_VLAN_PRIO)) ||
		    ((inner->tci & VLAN_PRIO_MASK) &&
		     !(filtering_support->inner & VIRTCHNL_VLAN_PRIO)))
			return false;

		if ((ice_vc_is_valid_vlan(outer) &&
		     !ice_vc_validate_vlan_tpid(filtering_support->outer,
						outer->tpid)) ||
		    (ice_vc_is_valid_vlan(inner) &&
		     !ice_vc_validate_vlan_tpid(filtering_support->inner,
						inner->tpid)))
			return false;
	}

	return true;
}

/**
 * ice_vc_to_vlan - transform from struct virtchnl_vlan to struct ice_vlan
 * @vc_vlan: struct virtchnl_vlan to transform
 */
static struct ice_vlan ice_vc_to_vlan(struct virtchnl_vlan *vc_vlan)
{
	struct ice_vlan vlan = { 0 };

	vlan.prio = FIELD_GET(VLAN_PRIO_MASK, vc_vlan->tci);
	vlan.vid = vc_vlan->tci & VLAN_VID_MASK;
	vlan.tpid = vc_vlan->tpid;

	return vlan;
}

/**
 * ice_vc_vlan_action - action to perform on the virthcnl_vlan
 * @vsi: VF's VSI used to perform the action
 * @vlan_action: function to perform the action with (i.e. add/del)
 * @vlan: VLAN filter to perform the action with
 */
static int
ice_vc_vlan_action(struct ice_vsi *vsi,
		   int (*vlan_action)(struct ice_vsi *, struct ice_vlan *),
		   struct ice_vlan *vlan)
{
	int err;

	err = vlan_action(vsi, vlan);
	if (err)
		return err;

	return 0;
}

/**
 * ice_vc_del_vlans - delete VLAN(s) from the virtchnl filter list
 * @vf: VF used to delete the VLAN(s)
 * @vsi: VF's VSI used to delete the VLAN(s)
 * @vfl: virthchnl filter list used to delete the filters
 */
static int
ice_vc_del_vlans(struct ice_vf *vf, struct ice_vsi *vsi,
		 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	bool vlan_promisc = ice_is_vlan_promisc_allowed(vf);
	int err;
	u16 i;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *vc_vlan;

		vc_vlan = &vlan_fltr->outer;
		if (ice_vc_is_valid_vlan(vc_vlan)) {
			struct ice_vlan vlan = ice_vc_to_vlan(vc_vlan);

			err = ice_vc_vlan_action(vsi,
						 vsi->outer_vlan_ops.del_vlan,
						 &vlan);
			if (err)
				return err;

			if (vlan_promisc)
				ice_vf_dis_vlan_promisc(vf, vsi, &vlan);
		}

		vc_vlan = &vlan_fltr->inner;
		if (ice_vc_is_valid_vlan(vc_vlan)) {
			struct ice_vlan vlan = ice_vc_to_vlan(vc_vlan);

			err = ice_vc_vlan_action(vsi,
						 vsi->inner_vlan_ops.del_vlan,
						 &vlan);
			if (err)
				return err;

			/* no support for VLAN promiscuous on inner VLAN unless
			 * we are in Single VLAN Mode (SVM)
			 */
			if (!ice_is_dvm_ena(&vsi->back->hw) && vlan_promisc)
				ice_vf_dis_vlan_promisc(vf, vsi, &vlan);
		}
	}

	return 0;
}

/**
 * ice_vc_remove_vlan_v2_msg - virtchnl handler for VIRTCHNL_OP_DEL_VLAN_V2
 * @vf: VF the message was received from
 * @msg: message received from the VF
 */
static int ice_vc_remove_vlan_v2_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_vlan_filter_list_v2 *vfl =
		(struct virtchnl_vlan_filter_list_v2 *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_vsi *vsi;

	if (!ice_vc_validate_vlan_filter_list(&vf->vlan_v2_caps.filtering,
					      vfl)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vfl->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ice_vc_del_vlans(vf, vsi, vfl))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_VLAN_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_add_vlans - add VLAN(s) from the virtchnl filter list
 * @vf: VF used to add the VLAN(s)
 * @vsi: VF's VSI used to add the VLAN(s)
 * @vfl: virthchnl filter list used to add the filters
 */
static int
ice_vc_add_vlans(struct ice_vf *vf, struct ice_vsi *vsi,
		 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	bool vlan_promisc = ice_is_vlan_promisc_allowed(vf);
	int err;
	u16 i;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *vc_vlan;

		vc_vlan = &vlan_fltr->outer;
		if (ice_vc_is_valid_vlan(vc_vlan)) {
			struct ice_vlan vlan = ice_vc_to_vlan(vc_vlan);

			err = ice_vc_vlan_action(vsi,
						 vsi->outer_vlan_ops.add_vlan,
						 &vlan);
			if (err)
				return err;

			if (vlan_promisc) {
				err = ice_vf_ena_vlan_promisc(vf, vsi, &vlan);
				if (err)
					return err;
			}
		}

		vc_vlan = &vlan_fltr->inner;
		if (ice_vc_is_valid_vlan(vc_vlan)) {
			struct ice_vlan vlan = ice_vc_to_vlan(vc_vlan);

			err = ice_vc_vlan_action(vsi,
						 vsi->inner_vlan_ops.add_vlan,
						 &vlan);
			if (err)
				return err;

			/* no support for VLAN promiscuous on inner VLAN unless
			 * we are in Single VLAN Mode (SVM)
			 */
			if (!ice_is_dvm_ena(&vsi->back->hw) && vlan_promisc) {
				err = ice_vf_ena_vlan_promisc(vf, vsi, &vlan);
				if (err)
					return err;
			}
		}
	}

	return 0;
}

/**
 * ice_vc_validate_add_vlan_filter_list - validate add filter list from the VF
 * @vsi: VF VSI used to get number of existing VLAN filters
 * @vfc: negotiated/supported VLAN filtering capabilities
 * @vfl: VLAN filter list from VF to validate
 *
 * Validate all of the filters in the VLAN filter list from the VF during the
 * VIRTCHNL_OP_ADD_VLAN_V2 opcode. If any of the checks fail then return false.
 * Otherwise return true.
 */
static bool
ice_vc_validate_add_vlan_filter_list(struct ice_vsi *vsi,
				     struct virtchnl_vlan_filtering_caps *vfc,
				     struct virtchnl_vlan_filter_list_v2 *vfl)
{
	u16 num_requested_filters = ice_vsi_num_non_zero_vlans(vsi) +
		vfl->num_elements;

	if (num_requested_filters > vfc->max_filters)
		return false;

	return ice_vc_validate_vlan_filter_list(vfc, vfl);
}

/**
 * ice_vc_add_vlan_v2_msg - virtchnl handler for VIRTCHNL_OP_ADD_VLAN_V2
 * @vf: VF the message was received from
 * @msg: message received from the VF
 */
static int ice_vc_add_vlan_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_filter_list_v2 *vfl =
		(struct virtchnl_vlan_filter_list_v2 *)msg;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vfl->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_validate_add_vlan_filter_list(vsi,
						  &vf->vlan_v2_caps.filtering,
						  vfl)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ice_vc_add_vlans(vf, vsi, vfl))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_VLAN_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_valid_vlan_setting - validate VLAN setting
 * @negotiated_settings: negotiated VLAN settings during VF init
 * @ethertype_setting: ethertype(s) requested for the VLAN setting
 */
static bool
ice_vc_valid_vlan_setting(u32 negotiated_settings, u32 ethertype_setting)
{
	if (ethertype_setting && !(negotiated_settings & ethertype_setting))
		return false;

	/* only allow a single VIRTCHNL_VLAN_ETHERTYPE if
	 * VIRTHCNL_VLAN_ETHERTYPE_AND is not negotiated/supported
	 */
	if (!(negotiated_settings & VIRTCHNL_VLAN_ETHERTYPE_AND) &&
	    hweight32(ethertype_setting) > 1)
		return false;

	/* ability to modify the VLAN setting was not negotiated */
	if (!(negotiated_settings & VIRTCHNL_VLAN_TOGGLE))
		return false;

	return true;
}

/**
 * ice_vc_valid_vlan_setting_msg - validate the VLAN setting message
 * @caps: negotiated VLAN settings during VF init
 * @msg: message to validate
 *
 * Used to validate any VLAN virtchnl message sent as a
 * virtchnl_vlan_setting structure. Validates the message against the
 * negotiated/supported caps during VF driver init.
 */
static bool
ice_vc_valid_vlan_setting_msg(struct virtchnl_vlan_supported_caps *caps,
			      struct virtchnl_vlan_setting *msg)
{
	if ((!msg->outer_ethertype_setting &&
	     !msg->inner_ethertype_setting) ||
	    (!caps->outer && !caps->inner))
		return false;

	if (msg->outer_ethertype_setting &&
	    !ice_vc_valid_vlan_setting(caps->outer,
				       msg->outer_ethertype_setting))
		return false;

	if (msg->inner_ethertype_setting &&
	    !ice_vc_valid_vlan_setting(caps->inner,
				       msg->inner_ethertype_setting))
		return false;

	return true;
}

/**
 * ice_vc_get_tpid - transform from VIRTCHNL_VLAN_ETHERTYPE_* to VLAN TPID
 * @ethertype_setting: VIRTCHNL_VLAN_ETHERTYPE_* used to get VLAN TPID
 * @tpid: VLAN TPID to populate
 */
static int ice_vc_get_tpid(u32 ethertype_setting, u16 *tpid)
{
	switch (ethertype_setting) {
	case VIRTCHNL_VLAN_ETHERTYPE_8100:
		*tpid = ETH_P_8021Q;
		break;
	case VIRTCHNL_VLAN_ETHERTYPE_88A8:
		*tpid = ETH_P_8021AD;
		break;
	case VIRTCHNL_VLAN_ETHERTYPE_9100:
		*tpid = ETH_P_QINQ1;
		break;
	default:
		*tpid = 0;
		return -EINVAL;
	}

	return 0;
}

/**
 * ice_vc_ena_vlan_offload - enable VLAN offload based on the ethertype_setting
 * @vsi: VF's VSI used to enable the VLAN offload
 * @ena_offload: function used to enable the VLAN offload
 * @ethertype_setting: VIRTCHNL_VLAN_ETHERTYPE_* to enable offloads for
 */
static int
ice_vc_ena_vlan_offload(struct ice_vsi *vsi,
			int (*ena_offload)(struct ice_vsi *vsi, u16 tpid),
			u32 ethertype_setting)
{
	u16 tpid;
	int err;

	err = ice_vc_get_tpid(ethertype_setting, &tpid);
	if (err)
		return err;

	err = ena_offload(vsi, tpid);
	if (err)
		return err;

	return 0;
}

#define ICE_L2TSEL_QRX_CONTEXT_REG_IDX	3
#define ICE_L2TSEL_BIT_OFFSET		23
enum ice_l2tsel {
	ICE_L2TSEL_EXTRACT_FIRST_TAG_L2TAG2_2ND,
	ICE_L2TSEL_EXTRACT_FIRST_TAG_L2TAG1,
};

/**
 * ice_vsi_update_l2tsel - update l2tsel field for all Rx rings on this VSI
 * @vsi: VSI used to update l2tsel on
 * @l2tsel: l2tsel setting requested
 *
 * Use the l2tsel setting to update all of the Rx queue context bits for l2tsel.
 * This will modify which descriptor field the first offloaded VLAN will be
 * stripped into.
 */
static void ice_vsi_update_l2tsel(struct ice_vsi *vsi, enum ice_l2tsel l2tsel)
{
	struct ice_hw *hw = &vsi->back->hw;
	u32 l2tsel_bit;
	int i;

	if (l2tsel == ICE_L2TSEL_EXTRACT_FIRST_TAG_L2TAG2_2ND)
		l2tsel_bit = 0;
	else
		l2tsel_bit = BIT(ICE_L2TSEL_BIT_OFFSET);

	for (i = 0; i < vsi->alloc_rxq; i++) {
		u16 pfq = vsi->rxq_map[i];
		u32 qrx_context_offset;
		u32 regval;

		qrx_context_offset =
			QRX_CONTEXT(ICE_L2TSEL_QRX_CONTEXT_REG_IDX, pfq);

		regval = rd32(hw, qrx_context_offset);
		regval &= ~BIT(ICE_L2TSEL_BIT_OFFSET);
		regval |= l2tsel_bit;
		wr32(hw, qrx_context_offset, regval);
	}
}

/**
 * ice_vc_ena_vlan_stripping_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2
 */
static int ice_vc_ena_vlan_stripping_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *stripping_support;
	struct virtchnl_vlan_setting *strip_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, strip_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	stripping_support = &vf->vlan_v2_caps.offloads.stripping_support;
	if (!ice_vc_valid_vlan_setting_msg(stripping_support, strip_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ice_vsi_is_rxq_crc_strip_dis(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto out;
	}

	ethertype_setting = strip_msg->outer_ethertype_setting;
	if (ethertype_setting) {
		if (ice_vc_ena_vlan_offload(vsi,
					    vsi->outer_vlan_ops.ena_stripping,
					    ethertype_setting)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		} else {
			enum ice_l2tsel l2tsel =
				ICE_L2TSEL_EXTRACT_FIRST_TAG_L2TAG2_2ND;

			/* PF tells the VF that the outer VLAN tag is always
			 * extracted to VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2 and
			 * inner is always extracted to
			 * VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1. This is needed to
			 * support outer stripping so the first tag always ends
			 * up in L2TAG2_2ND and the second/inner tag, if
			 * enabled, is extracted in L2TAG1.
			 */
			ice_vsi_update_l2tsel(vsi, l2tsel);

			vf->vlan_strip_ena |= ICE_OUTER_VLAN_STRIP_ENA;
		}
	}

	ethertype_setting = strip_msg->inner_ethertype_setting;
	if (ethertype_setting &&
	    ice_vc_ena_vlan_offload(vsi, vsi->inner_vlan_ops.ena_stripping,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ethertype_setting)
		vf->vlan_strip_ena |= ICE_INNER_VLAN_STRIP_ENA;

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_dis_vlan_stripping_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2
 */
static int ice_vc_dis_vlan_stripping_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *stripping_support;
	struct virtchnl_vlan_setting *strip_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, strip_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	stripping_support = &vf->vlan_v2_caps.offloads.stripping_support;
	if (!ice_vc_valid_vlan_setting_msg(stripping_support, strip_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = strip_msg->outer_ethertype_setting;
	if (ethertype_setting) {
		if (vsi->outer_vlan_ops.dis_stripping(vsi)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		} else {
			enum ice_l2tsel l2tsel =
				ICE_L2TSEL_EXTRACT_FIRST_TAG_L2TAG1;

			/* PF tells the VF that the outer VLAN tag is always
			 * extracted to VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2 and
			 * inner is always extracted to
			 * VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1. This is needed to
			 * support inner stripping while outer stripping is
			 * disabled so that the first and only tag is extracted
			 * in L2TAG1.
			 */
			ice_vsi_update_l2tsel(vsi, l2tsel);

			vf->vlan_strip_ena &= ~ICE_OUTER_VLAN_STRIP_ENA;
		}
	}

	ethertype_setting = strip_msg->inner_ethertype_setting;
	if (ethertype_setting && vsi->inner_vlan_ops.dis_stripping(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ethertype_setting)
		vf->vlan_strip_ena &= ~ICE_INNER_VLAN_STRIP_ENA;

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_ena_vlan_insertion_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2
 */
static int ice_vc_ena_vlan_insertion_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *insertion_support;
	struct virtchnl_vlan_setting *insertion_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, insertion_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	insertion_support = &vf->vlan_v2_caps.offloads.insertion_support;
	if (!ice_vc_valid_vlan_setting_msg(insertion_support, insertion_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->outer_ethertype_setting;
	if (ethertype_setting &&
	    ice_vc_ena_vlan_offload(vsi, vsi->outer_vlan_ops.ena_insertion,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->inner_ethertype_setting;
	if (ethertype_setting &&
	    ice_vc_ena_vlan_offload(vsi, vsi->inner_vlan_ops.ena_insertion,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_dis_vlan_insertion_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2
 */
static int ice_vc_dis_vlan_insertion_v2_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *insertion_support;
	struct virtchnl_vlan_setting *insertion_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ice_vc_isvalid_vsi_id(vf, insertion_msg->vport_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	insertion_support = &vf->vlan_v2_caps.offloads.insertion_support;
	if (!ice_vc_valid_vlan_setting_msg(insertion_support, insertion_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->outer_ethertype_setting;
	if (ethertype_setting && vsi->outer_vlan_ops.dis_insertion(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->inner_ethertype_setting;
	if (ethertype_setting && vsi->inner_vlan_ops.dis_insertion(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

out:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2,
				     v_ret, NULL, 0);
}

static int ice_vc_get_ptp_cap(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	u32 msg_caps;
	int ret;

	/* PTP is not supported in this PF */
	if (!ice_is_ptp_supported(pf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* VF is not in active state */
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	msg_caps = ((struct virtchnl_ptp_caps *)msg)->caps;

	/* Any VF asking for RX timestamping and reading PHC will get that */
	if (msg_caps & (VIRTCHNL_1588_PTP_CAP_RX_TSTAMP |
	    VIRTCHNL_1588_PTP_CAP_READ_PHC))
		vf->ptp_caps.caps = VIRTCHNL_1588_PTP_CAP_RX_TSTAMP |
				    VIRTCHNL_1588_PTP_CAP_READ_PHC;
#ifdef CONFIG_X86
	if (msg_caps & VIRTCHNL_1588_PTP_CAP_SW_CROSS_TSTAMP &&
	    vf->sw_crosststamp_ena)
		vf->ptp_caps.caps |= VIRTCHNL_1588_PTP_CAP_SW_CROSS_TSTAMP;
#endif /* CONFIG_X86 */

err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_1588_PTP_GET_CAPS, v_ret,
				    (u8 *)&vf->ptp_caps,
				    sizeof(struct virtchnl_ptp_caps));
	return ret;
}

static int ice_vc_get_phc_time(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_phc_time *phc_time = NULL;
	struct ice_pf *pf = vf->pf;
	int len = 0;
	int ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_phc_time);
	phc_time = kzalloc(len, GFP_KERNEL);
	if (!phc_time) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	phc_time->time = ice_ptp_read_src_clk_reg(pf, NULL);

err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_1588_PTP_GET_TIME,
				    v_ret, (u8 *)phc_time, len);
	kfree(phc_time);
	return ret;
}

#ifdef CONFIG_X86
static int ice_vc_get_sw_cross_tstamp(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_sw_cross_timestamp *sw_cts = NULL;
	struct ice_pf *pf = vf->pf;
	size_t len = 0;
	int err;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		return -EBUSY;

	if (!ice_is_ptp_supported(pf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	sw_cts = kzalloc(len, GFP_KERNEL);
	if (!sw_cts) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	}

	err = ice_ptp_get_sw_cross_tstamp(pf, sw_cts);
	if (err == -EOPNOTSUPP) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}
	len = sizeof(*sw_cts);
err:
	err = ice_vc_send_msg_to_vf(vf,
				    VIRTCHNL_OP_1588_PTP_GET_SW_CROSS_TSTAMP,
				    v_ret, (u8 *)sw_cts, len);
	kfree(sw_cts);
	return err;
}

static int ice_vc_get_phc_freq_ratio(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_phc_freq_ratio *ratio = NULL;
	struct ice_pf *pf = vf->pf;
	size_t len = 0;
	int err;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		return -EBUSY;

	if (!ice_is_ptp_supported(pf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ratio = kzalloc(len, GFP_KERNEL);
	if (!ratio) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	}

	err = ice_ptp_get_phc_freq_ratio(pf, ratio);
	if (err == -EOPNOTSUPP) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}
	len = sizeof(*ratio);
err:
	err = ice_vc_send_msg_to_vf(vf,
				    VIRTCHNL_OP_1588_PTP_GET_PHC_TO_CPU_DYNAMIC_RATIO,
				    v_ret, (u8 *)ratio, len);
	kfree(ratio);
	return err;
}
#endif /* CONFIG_X86 */

/**
 * ice_vc_hqos_validate_tree - check new scheduling tree elements for errors
 * @vf: pointer to the VF info
 * @vsi_node: pointer to vsi node in scheduling tree
 * @vhcl: configuration passed in virtchnl maessage
 *
 * Return VIRTCHNL_STATUS_SUCCESS (0) in case no errors found,
 * VIRTCHNL_STATUS_ERR_PARAM in case configuration has errors.
 */
static enum virtchnl_status_code
ice_vc_hqos_validate_tree(struct ice_vf *vf, struct ice_sched_node *vsi_node,
			  struct virtchnl_hqos_cfg_list *vhcl)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_hqos_cfg *cfg_item;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_sched_node *parent;
	int i;

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];

		parent = ice_sched_find_node_by_teid(vsi_node,
						     cfg_item->parent_teid);

		if (!parent) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			break;
		}

		if (parent->tx_sched_layer >= ice_sched_get_qgrp_layer(hw)) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node creation request failed. Element %d exceeds maximum tree Depth: %d",
				vf->vf_id, i, ice_sched_get_qgrp_layer(hw));
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			break;
		}

		if (parent->num_children >=
		    hw->max_children[parent->tx_sched_layer]) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node creation request failed. Element %d parent already has max number of children: %d",
				vf->vf_id, i,
				hw->max_children[parent->tx_sched_layer]);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			break;
		}
	}

	mutex_unlock(&pi->sched_lock);

	return v_ret;
}

/**
 * ice_vc_hqos_validate_cfg - check new scheduling configuration for errors
 * @vf: pointer to the VF info
 * @vsi_node: pointer to vsi node in scheduling tree
 * @vhcl: configuration passed in virtchnl maessage
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors found,
 * VIRTCHNL_STATUS_ERR_PARAM in case configuration has errors.
 */
static enum virtchnl_status_code
ice_vc_hqos_validate_cfg(struct ice_vf *vf, struct ice_sched_node *vsi_node,
			 struct virtchnl_hqos_cfg_list *vhcl)
{
	struct virtchnl_hqos_cfg *cfg_item;
	int i;

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];

		if (cfg_item->tx_share &&
		    (cfg_item->tx_share < ICE_SCHED_MIN_BW ||
		     cfg_item->tx_share > ICE_SCHED_MAX_BW)) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d share is out of bounds",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}

		if (cfg_item->tx_max && (cfg_item->tx_max < ICE_SCHED_MIN_BW ||
					 cfg_item->tx_max > ICE_SCHED_MAX_BW)) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d tx_max is out of bounds",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}

		if (cfg_item->tx_share > cfg_item->tx_max) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d tx_share is greater than tx_max",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}

		if (cfg_item->tx_weight &&
		    (cfg_item->tx_weight < ICE_SCHED_MIN_BW_WT ||
		     cfg_item->tx_weight > ICE_SCHED_MAX_BW_WT)) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d tx_weight is out of bounds",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}

		if (cfg_item->tx_priority > ICE_SCHED_MAX_PRIORITY) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d tx_priority is out of bounds",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}

		if (cfg_item->node_type != VIRTCHNL_HQOS_ELEM_TYPE_NODE &&
		    cfg_item->node_type != VIRTCHNL_HQOS_ELEM_TYPE_LEAF) {
			dev_err(ice_pf_to_dev(vf->pf), "VF %d node configuration incorrect. Element %d has incorrect type",
				vf->vf_id, i);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_vc_hqos_apply_cfg - apply new Tx scheduling configuration
 * @pi: pointer to the port_info instance
 * @vsi_node: pointer to vsi node in scheduling tree
 * @vhcl: configuration passed in virtchnl maessage
 *
 * Respond with 0 in case no errors occurred, VIRTCHNL_STATUS_ERR_PARAM in case
 * configuration has errors.
 */
static enum virtchnl_status_code
ice_vc_hqos_apply_cfg(struct ice_port_info *pi,
		      struct ice_sched_node *vsi_node,
		      struct virtchnl_hqos_cfg_list *vhcl)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_hqos_cfg *cfg_item;
	struct ice_sched_node *node;
	int i, status = 0;

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];

		node = ice_sched_find_node_by_teid(vsi_node, cfg_item->teid);

		if (!node) {
			pr_err("Node not found");
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			break;
		}

		if (cfg_item->tx_share) {
			node->tx_share = cfg_item->tx_share;
			status = ice_sched_set_node_bw_lmt(pi, node,
							   ICE_MIN_BW,
							   node->tx_share);
		}

		if (status) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			break;
		}

		if (cfg_item->tx_max) {
			node->tx_max = cfg_item->tx_max;
			status = ice_sched_set_node_bw_lmt(pi, node,
							   ICE_MAX_BW,
							   node->tx_max);
		}

		if (status) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			break;
		}

		if (cfg_item->tx_priority) {
			node->tx_priority = cfg_item->tx_priority;
			status = ice_sched_set_node_priority(pi, node,
							     node->tx_priority);
		}

		if (status) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			break;
		}

		if (cfg_item->tx_weight) {
			node->tx_weight = cfg_item->tx_weight;
			status = ice_sched_set_node_weight(pi, node,
							   node->tx_weight);
		}

		if (status) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			break;
		}
	}

	mutex_unlock(&pi->sched_lock);

	return v_ret;
}

/**
 * ice_vc_count_subtree_elements - function for getting number of scheduling
 * nodes in the subtree starting from given node.
 *
 * @node: pointer to node in scheduling tree
 *
 * Return size of the subtree from given node (including the node)
 */
static int ice_vc_count_subtree_elements(struct ice_sched_node *node)
{
	int ret = 1;
	int i;

	for (i = 0; i < node->num_children; i++)
		ret += ice_vc_count_subtree_elements(node->children[i]);

	return ret;
}

/**
 * ice_vc_fill_cfg - function for filling hqos_cfg_list with data of all
 * elements in scheduling subtree, starting from the provided node.
 *
 * @node: pointer to node in scheduling tree
 * @list: pointer to pre-allocated variable structure for sending
 *	  scheduling info
 * @idx: index to first free element in elements array
 * @table_size: size of the elements array
 *
 * Return number of scheduling nodes information added to table or -ENOMEM
 * in case of error.
 */
static int
ice_vc_fill_cfg(struct ice_sched_node *node,
		struct virtchnl_hqos_cfg_list *list, int idx, int table_size)
{
	int i;

	if (idx >= table_size)
		return -ENOMEM;

	if (node->info.data.elem_type == ICE_AQC_ELEM_TYPE_LEAF)
		list->cfg[idx].node_type = VIRTCHNL_HQOS_ELEM_TYPE_LEAF;
	else
		list->cfg[idx].node_type = VIRTCHNL_HQOS_ELEM_TYPE_NODE;

	list->cfg[idx].teid = le32_to_cpu(node->info.node_teid);
	list->cfg[idx].parent_teid = le32_to_cpu(node->info.parent_teid);
	list->cfg[idx].tx_max = node->tx_max;
	list->cfg[idx].tx_share = node->tx_share;
	list->cfg[idx].tx_priority = node->tx_priority;
	list->cfg[idx].tx_weight = node->tx_weight;
	idx++;

	for (i = 0; i < node->num_children; i++) {
		idx = ice_vc_fill_cfg(node->children[i], list, idx,
				      table_size);
		if (idx == -ENOMEM)
			return idx;
	}

	return idx;
}

/**
 * ice_vc_hqos_read_tree - return Tx scheduling tree structure
 *
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors occurred,
 * VIRTCHNL_STATUS_ERR_PARAM in case error occurred.
 */
static int ice_vc_hqos_read_tree(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_sched_node *tc_node = hw->port_info->root->children[0];
	struct virtchnl_hqos_cfg_list *cfg_msg = NULL;
	u16 vsi_handle = vf->lan_vsi_idx;
	struct ice_sched_node *vsi_node;
	struct ice_vsi *vsi;
	int count, ret, len = 0;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi_node = ice_sched_get_vsi_node(hw->port_info, tc_node, vsi_handle);
	if (!vsi_node) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	count = ice_vc_count_subtree_elements(vsi_node);
	len = sizeof(struct virtchnl_hqos_cfg_list) +
		     (count - 1) * sizeof(struct virtchnl_hqos_cfg);

	cfg_msg = kzalloc(len, GFP_KERNEL);
	if (!cfg_msg) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	if (count != ice_vc_fill_cfg(vsi_node, cfg_msg, 0, count)) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	cfg_msg->num_elem = count;

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_HQOS_TREE_READ,
				    v_ret, (u8 *)cfg_msg, len);
	kfree(cfg_msg);

	return ret;
}

/**
 * ice_vc_hqos_elems_add - create new scheduling elements in Tx
 * scheduling tree
 *
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors occurred,
 * VIRTCHNL_STATUS_ERR_PARAM in case error occurred.
 */
static int ice_vc_hqos_elems_add(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_sched_node *tc_node = pi->root->children[0];
	struct virtchnl_hqos_cfg_list *vhcl = NULL;
	struct virtchnl_hqos_cfg *cfg_item;
	u16 vsi_handle = vf->lan_vsi_idx;
	struct ice_sched_node *vsi_node;
	struct ice_sched_node *parent;
	struct ice_vsi *vsi;
	u16 num_nodes_added;
	u32 first_node_teid;
	int i, ret;

	vhcl = (struct virtchnl_hqos_cfg_list *)msg;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi_node = ice_sched_get_vsi_node(hw->port_info, tc_node, vsi_handle);
	if (!vsi_node) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	v_ret = ice_vc_hqos_validate_tree(vf, vsi_node, vhcl);
	if (v_ret)
		goto err;

	v_ret = ice_vc_hqos_validate_cfg(vf, vsi_node, vhcl);
	if (v_ret)
		goto err;

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];

		parent = ice_sched_find_node_by_teid(vsi_node,
						     cfg_item->parent_teid);

		if (!parent) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			mutex_unlock(&pi->sched_lock);
			goto err;
		}

		ret = ice_sched_add_elems(pi, tc_node, parent,
					  parent->tx_sched_layer + 1, 1,
					  &num_nodes_added, &first_node_teid,
					  NULL);

		if (ret) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			mutex_unlock(&pi->sched_lock);
			goto err;
		}

		cfg_item->teid = first_node_teid;
	}

	mutex_unlock(&pi->sched_lock);

	v_ret = ice_vc_hqos_apply_cfg(pi, vsi_node, vhcl);
	if (v_ret)
		goto err;

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_HQOS_ELEMS_ADD,
				    v_ret, NULL, 0);

	return ret;
}

/**
 * ice_vc_hqos_elems_del - remove scheduling elements from Tx
 * scheduling tree
 *
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors occurred,
 * VIRTCHNL_STATUS_ERR_PARAM in case error occurred.
 */
static int ice_vc_hqos_elems_del(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_sched_node *tc_node = pi->root->children[0];
	struct virtchnl_hqos_cfg_list *vhcl = NULL;
	struct virtchnl_hqos_cfg *cfg_item;
	u16 vsi_handle = vf->lan_vsi_idx;
	struct ice_sched_node *vsi_node;
	struct ice_sched_node *node;
	struct ice_vsi *vsi;
	int i, ret;

	vhcl = (struct virtchnl_hqos_cfg_list *)msg;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi_node = ice_sched_get_vsi_node(hw->port_info, tc_node, vsi_handle);
	if (!vsi_node) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];

		node = ice_sched_find_node_by_teid(vsi_node, cfg_item->teid);

		if (!node) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			mutex_unlock(&pi->sched_lock);
			goto err;
		}

		if (node->num_children) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			dev_err(ice_pf_to_dev(vf->pf), "VF %d: cannot process delete request, element 0x%x has children",
				vf->vf_id, cfg_item->teid);
			mutex_unlock(&pi->sched_lock);
			goto err;
		}

		ice_free_sched_node(pi, node);
	}

	mutex_unlock(&pi->sched_lock);

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_HQOS_ELEMS_DEL,
				    v_ret, NULL, 0);

	return ret;
}

/**
 * ice_vc_hqos_elems_conf - parse and apply bandwidth changes in Tx
 * scheduling tree
 *
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors occurred,
 * VIRTCHNL_STATUS_ERR_PARAM in case error occurred.
 */
static int ice_vc_hqos_elems_conf(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_sched_node *tc_node = pi->root->children[0];
	struct virtchnl_hqos_cfg_list *vhcl = NULL;
	u16 vsi_handle = vf->lan_vsi_idx;
	struct ice_sched_node *vsi_node;
	struct ice_vsi *vsi;
	int ret;

	vhcl = (struct virtchnl_hqos_cfg_list *)msg;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi_node = ice_sched_get_vsi_node(hw->port_info, tc_node, vsi_handle);
	if (!vsi_node) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	if (ice_vc_hqos_validate_cfg(vf, vsi_node, vhcl)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_vc_hqos_apply_cfg(pi, vsi_node, vhcl)) {
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		goto err;
	}

err:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_HQOS_ELEMS_CONF,
				    v_ret, NULL, 0);

	return ret;
}

/**
 * ice_vc_hqos_elems_move - parse and apply changes to scheduling
 * tree topology.
 *
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Respond with VIRTCHNL_STATUS_SUCCESS in case no errors occurred,
 * VIRTCHNL_STATUS_ERR_PARAM in case error occurred.
 */
static int ice_vc_hqos_elems_move(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_sched_node *tc_node = pi->root->children[0];
	struct virtchnl_hqos_cfg_list *vhcl = NULL;
	struct ice_sched_node *node, *parent;
	struct virtchnl_hqos_cfg *cfg_item;
	u16 vsi_handle = vf->lan_vsi_idx;
	struct ice_sched_node *vsi_node;
	struct ice_vsi *vsi;
	u32 node_teid;
	int ret, i;

	vhcl = (struct virtchnl_hqos_cfg_list *)msg;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto done;
	}

	if (ice_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto done;
	}

	vsi_node = ice_sched_get_vsi_node(hw->port_info, tc_node, vsi_handle);
	if (!vsi_node) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto done;
	}

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < vhcl->num_elem; i++) {
		cfg_item = &vhcl->cfg[i];
		node_teid = cfg_item->teid;

		node = ice_sched_find_node_by_teid(vsi_node, cfg_item->teid);
		parent = ice_sched_find_node_by_teid(vsi_node,
						     cfg_item->parent_teid);

		if (!parent || !node) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			mutex_unlock(&pi->sched_lock);
			goto done;
		}

		if (node->info.data.elem_type == ICE_AQC_ELEM_TYPE_LEAF)
			ret = ice_sched_move_leaves(pi, parent, 1, &node_teid);
		else
			ret = ice_sched_move_nodes(pi, parent, 1, &node_teid);

		if (ret) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			mutex_unlock(&pi->sched_lock);
			goto done;
		}
	}

	mutex_unlock(&pi->sched_lock);

done:
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_HQOS_ELEMS_MOVE,
				    v_ret, NULL, 0);

	return ret;
}

static const struct ice_virtchnl_ops ice_virtchnl_dflt_ops = {
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
	.cfg_rdma_irq_map_msg = ice_vc_cfg_rdma_irq_map_msg,
	.clear_rdma_irq_map = ice_vc_clear_rdma_irq_map,
	.dcf_vlan_offload_msg = ice_vc_dcf_vlan_offload_msg,
	.dcf_cmd_desc_msg = ice_vc_dcf_cmd_desc_msg,
	.dcf_cmd_buff_msg = ice_vc_dcf_cmd_buff_msg,
	.dis_dcf_cap = ice_vc_dis_dcf_cap,
	.dcf_get_vsi_map = ice_vc_dcf_get_vsi_map,
	.dcf_query_pkg_info = ice_vc_dcf_query_pkg_info,
	.dcf_config_vf_tc = ice_vc_dcf_config_tc,
	.handle_rss_cfg_msg = ice_vc_handle_rss_cfg,
	.get_qos_caps = ice_vc_get_qos_caps,
	.cfg_q_tc_map = ice_vc_cfg_q_tc_map,
	.cfg_q_bw = ice_vc_cfg_q_bw,
	.cfg_q_quanta = ice_vc_cfg_q_quanta,
	.add_fdir_fltr_msg = ice_vc_add_fdir_fltr,
	.del_fdir_fltr_msg = ice_vc_del_fdir_fltr,
	.flow_sub_fltr_msg = ice_vc_flow_sub_fltr,
	.flow_unsub_fltr_msg = ice_vc_flow_unsub_fltr,
	.get_max_rss_qregion = ice_vc_get_max_rss_qregion,
	.ena_qs_v2_msg = ice_vc_ena_qs_v2_msg,
	.dis_qs_v2_msg = ice_vc_dis_qs_v2_msg,
	.map_q_vector_msg = ice_vc_map_q_vector_msg,
	.get_offload_vlan_v2_caps = ice_vc_get_offload_vlan_v2_caps,
	.add_vlan_v2_msg = ice_vc_add_vlan_v2_msg,
	.remove_vlan_v2_msg = ice_vc_remove_vlan_v2_msg,
	.ena_vlan_stripping_v2_msg = ice_vc_ena_vlan_stripping_v2_msg,
	.dis_vlan_stripping_v2_msg = ice_vc_dis_vlan_stripping_v2_msg,
	.ena_vlan_insertion_v2_msg = ice_vc_ena_vlan_insertion_v2_msg,
	.dis_vlan_insertion_v2_msg = ice_vc_dis_vlan_insertion_v2_msg,
	.get_ptp_cap = ice_vc_get_ptp_cap,
	.get_phc_time = ice_vc_get_phc_time,
#ifdef CONFIG_X86
	.get_sw_cross_tstamp = ice_vc_get_sw_cross_tstamp,
	.get_phc_freq_ratio = ice_vc_get_phc_freq_ratio,
#endif /* CONFIG_X86 */
};

/**
 * ice_virtchnl_set_dflt_ops - Switch to default virtchnl ops
 * @vf: the VF to switch ops
 */
void ice_virtchnl_set_dflt_ops(struct ice_vf *vf)
{
	vf->virtchnl_ops = &ice_virtchnl_dflt_ops;
}

/**
 * ice_vc_repr_add_mac
 * @vf: pointer to VF
 * @msg: virtchannel message
 *
 * When port representors are created, we do not add MAC rule
 * to firmware, we store it so that PF could report same
 * MAC as VF.
 */
static int ice_vc_repr_add_mac(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct ice_vsi *vsi;
	struct ice_pf *pf;
	int i;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !ice_vc_isvalid_vsi_id(vf, al->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	pf = vf->pf;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	for (i = 0; i < al->num_elements; i++) {
		u8 *mac_addr = al->list[i].addr;

		if (!is_unicast_ether_addr(mac_addr) ||
		    ether_addr_equal(mac_addr, vf->hw_lan_addr.addr))
			continue;

		if (vf->pf_set_mac) {
			dev_err(ice_pf_to_dev(pf), "VF attempting to override administratively set MAC address\n");
			v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
			goto handle_mac_exit;
		}

		ice_vfhw_mac_add(vf, &al->list[i]);
		vf->num_mac++;
		break;
	}

handle_mac_exit:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_ETH_ADDR,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_repr_del_mac - response with success for deleting MAC
 * @vf: pointer to VF
 * @msg: virtchannel message
 *
 * Respond with success to not break normal VF flow.
 * For legacy VF driver try to update cached MAC address.
 */
static int
ice_vc_repr_del_mac(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_ether_addr_list *al =
		(struct virtchnl_ether_addr_list *)msg;

	ice_update_legacy_cached_mac(vf, &al->list[0]);

	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_ETH_ADDR,
				     VIRTCHNL_STATUS_SUCCESS, NULL, 0);
}

static int
ice_vc_repr_cfg_promiscuous_mode(struct ice_vf *vf, u8 __always_unused *msg)
{
	dev_dbg(ice_pf_to_dev(vf->pf),
		"Can't config promiscuous mode in switchdev mode for VF %d\n",
		vf->vf_id);
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				     VIRTCHNL_STATUS_ERR_NOT_SUPPORTED,
				     NULL, 0);
}

static const struct ice_virtchnl_ops ice_virtchnl_repr_ops = {
	.get_ver_msg = ice_vc_get_ver_msg,
	.get_vf_res_msg = ice_vc_get_vf_res_msg,
	.reset_vf = ice_vc_reset_vf_msg,
	.add_mac_addr_msg = ice_vc_repr_add_mac,
	.del_mac_addr_msg = ice_vc_repr_del_mac,
	.cfg_qs_msg = ice_vc_cfg_qs_msg,
	.ena_qs_msg = ice_vc_ena_qs_msg,
	.dis_qs_msg = ice_vc_dis_qs_msg,
	.request_qs_msg = ice_vc_request_qs_msg,
	.cfg_irq_map_msg = ice_vc_cfg_irq_map_msg,
	.config_rss_key = ice_vc_config_rss_key,
	.config_rss_lut = ice_vc_config_rss_lut,
	.get_stats_msg = ice_vc_get_stats_msg,
	.cfg_promiscuous_mode_msg = ice_vc_repr_cfg_promiscuous_mode,
	.add_vlan_msg = ice_vc_add_vlan_msg,
	.remove_vlan_msg = ice_vc_remove_vlan_msg,
	.hqos_read_tree = ice_vc_hqos_read_tree,
	.hqos_elems_add = ice_vc_hqos_elems_add,
	.hqos_elems_del = ice_vc_hqos_elems_del,
	.hqos_elems_move = ice_vc_hqos_elems_move,
	.hqos_elems_conf = ice_vc_hqos_elems_conf,
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
	.cfg_rdma_irq_map_msg = ice_vc_cfg_rdma_irq_map_msg,
	.clear_rdma_irq_map = ice_vc_clear_rdma_irq_map,
	.dcf_vlan_offload_msg = ice_vc_dcf_vlan_offload_msg,
	.dcf_cmd_desc_msg = ice_vc_dcf_cmd_desc_msg,
	.dcf_cmd_buff_msg = ice_vc_dcf_cmd_buff_msg,
	.dis_dcf_cap = ice_vc_dis_dcf_cap,
	.dcf_get_vsi_map = ice_vc_dcf_get_vsi_map,
	.dcf_query_pkg_info = ice_vc_dcf_query_pkg_info,
	.dcf_config_vf_tc = ice_vc_dcf_config_tc,
	.handle_rss_cfg_msg = ice_vc_handle_rss_cfg,
	.get_qos_caps = ice_vc_get_qos_caps,
	.cfg_q_tc_map = ice_vc_cfg_q_tc_map,
	.cfg_q_bw = ice_vc_cfg_q_bw,
	.cfg_q_quanta = ice_vc_cfg_q_quanta,
	.add_fdir_fltr_msg = ice_vc_add_fdir_fltr,
	.del_fdir_fltr_msg = ice_vc_del_fdir_fltr,
	.flow_sub_fltr_msg = ice_vc_flow_sub_fltr,
	.flow_unsub_fltr_msg = ice_vc_flow_unsub_fltr,
	.get_max_rss_qregion = ice_vc_get_max_rss_qregion,
	.ena_qs_v2_msg = ice_vc_ena_qs_v2_msg,
	.dis_qs_v2_msg = ice_vc_dis_qs_v2_msg,
	.map_q_vector_msg = ice_vc_map_q_vector_msg,
	.get_offload_vlan_v2_caps = ice_vc_get_offload_vlan_v2_caps,
	.add_vlan_v2_msg = ice_vc_add_vlan_v2_msg,
	.remove_vlan_v2_msg = ice_vc_remove_vlan_v2_msg,
	.ena_vlan_stripping_v2_msg = ice_vc_ena_vlan_stripping_v2_msg,
	.dis_vlan_stripping_v2_msg = ice_vc_dis_vlan_stripping_v2_msg,
	.ena_vlan_insertion_v2_msg = ice_vc_ena_vlan_insertion_v2_msg,
	.dis_vlan_insertion_v2_msg = ice_vc_dis_vlan_insertion_v2_msg,
	.get_ptp_cap = ice_vc_get_ptp_cap,
	.get_phc_time = ice_vc_get_phc_time,
#ifdef CONFIG_X86
	.get_sw_cross_tstamp = ice_vc_get_sw_cross_tstamp,
	.get_phc_freq_ratio = ice_vc_get_phc_freq_ratio,
#endif /* CONFIG_X86 */
};

/**
 * ice_virtchnl_set_repr_ops - Switch to representor virtchnl ops
 * @vf: the VF to switch ops
 */
void ice_virtchnl_set_repr_ops(struct ice_vf *vf)
{
	vf->virtchnl_ops = &ice_virtchnl_repr_ops;
}

/**
 * ice_is_malicious_vf - check if this vf might be overflowing mailbox
 * @vf: the VF to check
 * @mbxdata: data about the state of the mailbox
 *
 * Detect if a given VF might be malicious and attempting to overflow the PF
 * mailbox. If so, log a warning message and ignore this event.
 */
static bool
ice_is_malicious_vf(struct ice_vf *vf, struct ice_mbx_data *mbxdata)
{
	bool report_malvf = false;
	struct device *dev;
	struct ice_pf *pf;
	int status;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return vf->mbx_info.malicious;

	/* check to see if we have a newly malicious VF */
	status = ice_mbx_vf_state_handler(&pf->hw, mbxdata, &vf->mbx_info,
					  &report_malvf);
	if (status)
		dev_warn_ratelimited(dev, "Unable to check status of mailbox overflow for VF %u MAC %pM, status %d\n",
				     vf->vf_id, vf->dev_lan_addr.addr, status);

	if (report_malvf) {
		struct ice_vsi *pf_vsi = ice_get_main_vsi(pf);
		u8 zero_addr[ETH_ALEN] = {};

		dev_warn(dev, "VF MAC %pM on PF MAC %pM is generating asynchronous messages and may be overflowing the PF message queue. Please see the Adapter User Guide for more information\n",
			 vf->dev_lan_addr.addr,
			 pf_vsi ? pf_vsi->netdev->dev_addr : zero_addr);
	}

	return vf->mbx_info.malicious;
}

/**
 * ice_vc_process_vf_msg - Process request from VF
 * @pf: pointer to the PF structure
 * @event: pointer to the AQ event
 * @mbxdata: information used to detect VF attempting mailbox overflow
 *
 * This function will be called from:
 * 1. the common asq/arq handler to process request from VF
 *
 *    The return value is ignored, as the command will send the status of the
 *    request as a response to the VF. When this flow is used for devices with
 *    hardware VF to PF message queue overflow support (ICE_F_MBX_LIMIT)
 *    mbxdata is set to NULL and skips the ice_is_malicious_vf check, else
 *    mbxdata is set to a non-NULL value and must call ice_is_malicious_vf to
 *    determine if this VF might be attempting to overflow the PF message queue.
 *
 * 2. replay virtual channel commamds during live migration
 *
 *    The return value is used to indicate failure to replay vc commands and
 *    that the migration failed. This flow sets mbxdata to NULL and skips the
 *    ice_is_malicious_vf checks which are unnecessary during replay.
 *
 * Return 0 if success, negative for failure.
 */
int ice_vc_process_vf_msg(struct ice_pf *pf, struct ice_rq_event_info *event,
			  struct ice_mbx_data *mbxdata)
{
	u32 v_opcode = le32_to_cpu(event->desc.cookie_high);
	s16 vf_id = le16_to_cpu(event->desc.retval);
	const struct ice_virtchnl_ops *ops;
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	struct ice_vf *vf = NULL;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(dev, "Unable to locate VF for message from VF ID %d, opcode %d, len %d\n",
			vf_id, v_opcode, msglen);
		return -EINVAL;
	}

	mutex_lock(&vf->cfg_lock);

	/* Check if the VF is trying to overflow the mailbox */
	if (mbxdata && ice_is_malicious_vf(vf, mbxdata))
		goto finish;

	/* Check if VF is disabled. */
	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states)) {
		err = -EPERM;
		goto error_handler;
	}

	ops = vf->virtchnl_ops;

	/* Perform basic checks on the msg */
	err = virtchnl_vc_validate_vf_msg(&vf->vf_ver, v_opcode, msg, msglen);
	if (err) {
		if (err == VIRTCHNL_STATUS_ERR_PARAM)
			err = -EPERM;
		else
			err = -EINVAL;
	}

error_handler:
	if (err) {
		ice_vc_send_msg_to_vf(vf, v_opcode, VIRTCHNL_STATUS_ERR_PARAM,
				      NULL, 0);
		ice_dev_err_errno(dev, err,
				  "Invalid message from VF %d, opcode %d, len %d",
				  vf_id, v_opcode, msglen);
		goto finish;
	}

	if (!ice_vc_is_opcode_allowed(vf, v_opcode)) {
		ice_vc_send_msg_to_vf(vf, v_opcode,
				      VIRTCHNL_STATUS_ERR_NOT_SUPPORTED, NULL,
				      0);
		goto finish;
	}

	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		err = ops->get_ver_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		err = ops->get_vf_res_msg(vf, msg);
		if (ice_vf_init_vlan_stripping(vf))
			dev_dbg(dev, "Failed to initialize VLAN stripping for VF %d\n",
				vf->vf_id);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_RESET_VF:
		ops->reset_vf(vf);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		err = ops->add_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		err = ops->del_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		err = ops->cfg_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		err = ops->ena_qs_msg(vf, msg);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		err = ops->dis_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES:
		err = ops->request_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		err = ops->cfg_irq_map_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		err = ops->config_rss_key(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		err = ops->config_rss_lut(vf, msg);
		break;
	case VIRTCHNL_OP_GET_STATS:
		err = ops->get_stats_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		err = ops->cfg_promiscuous_mode_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_VLAN:
		err = ops->add_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN:
		err = ops->remove_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_HQOS_ELEMS_ADD:
		err = ops->hqos_elems_add(vf, msg);
		break;
	case VIRTCHNL_OP_HQOS_ELEMS_DEL:
		err = ops->hqos_elems_del(vf, msg);
		break;
	case VIRTCHNL_OP_HQOS_ELEMS_MOVE:
		err = ops->hqos_elems_move(vf, msg);
		break;
	case VIRTCHNL_OP_HQOS_ELEMS_CONF:
		err = ops->hqos_elems_conf(vf, msg);
		break;
	case VIRTCHNL_OP_HQOS_TREE_READ:
		err = ops->hqos_read_tree(vf, msg);
		break;
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		err = ops->query_rxdid(vf);
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		err = ops->get_rss_hena(vf);
		break;
	case VIRTCHNL_OP_SET_RSS_HENA:
		err = ops->set_rss_hena_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
		err = ops->ena_vlan_stripping(vf);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		err = ops->dis_vlan_stripping(vf);
		break;
#ifdef HAVE_TC_SETUP_CLSFLOWER
	case VIRTCHNL_OP_ENABLE_CHANNELS:
		err = ops->add_qch_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER:
		err = ops->add_switch_filter_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_CLOUD_FILTER:
		err = ops->del_switch_filter_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_CHANNELS:
		err = ops->del_qch_msg(vf, msg);
		break;
#endif /* HAVE_TC_SETUP_FLOWER */
	case VIRTCHNL_OP_RDMA:
		err = ops->rdma_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
		err = ops->cfg_rdma_irq_map_msg(vf, msg);
		break;
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		err = ops->clear_rdma_irq_map(vf);
		break;
	case VIRTCHNL_OP_DCF_VLAN_OFFLOAD:
		err = ops->dcf_vlan_offload_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DCF_CMD_DESC:
		err = ops->dcf_cmd_desc_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_DCF_CMD_BUFF:
		err = ops->dcf_cmd_buff_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_DCF_DISABLE:
		err = ops->dis_dcf_cap(vf);
		break;
	case VIRTCHNL_OP_DCF_GET_VSI_MAP:
		err = ops->dcf_get_vsi_map(vf);
		break;
	case VIRTCHNL_OP_DCF_GET_PKG_INFO:
		err = ops->dcf_query_pkg_info(vf);
		break;
	case VIRTCHNL_OP_DCF_CONFIG_BW:
		err = ops->dcf_config_vf_tc(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_RSS_CFG:
		err = ops->handle_rss_cfg_msg(vf, msg, true);
		break;
	case VIRTCHNL_OP_DEL_RSS_CFG:
		err = ops->handle_rss_cfg_msg(vf, msg, false);
		break;
	case VIRTCHNL_OP_GET_QOS_CAPS:
		err = ops->get_qos_caps(vf);
		break;
	case VIRTCHNL_OP_CONFIG_QUEUE_TC_MAP:
		err = ops->cfg_q_tc_map(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_QUEUE_BW:
		err = ops->cfg_q_bw(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_QUANTA:
		err = ops->cfg_q_quanta(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_FDIR_FILTER:
		err = ops->add_fdir_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_FDIR_FILTER:
		err = ops->del_fdir_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_FLOW_SUBSCRIBE:
		err = ops->flow_sub_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_FLOW_UNSUBSCRIBE:
		err = ops->flow_unsub_fltr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_MAX_RSS_QREGION:
		err = ops->get_max_rss_qregion(vf);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES_V2:
		err = ops->ena_qs_v2_msg(vf, msg);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES_V2:
		err = ops->dis_qs_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_MAP_QUEUE_VECTOR:
		err = ops->map_q_vector_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
		err = ops->get_offload_vlan_v2_caps(vf);
		break;
	case VIRTCHNL_OP_ADD_VLAN_V2:
		err = ops->add_vlan_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN_V2:
		err = ops->remove_vlan_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		err = ops->ena_vlan_stripping_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		err = ops->dis_vlan_stripping_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		err = ops->ena_vlan_insertion_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		err = ops->dis_vlan_insertion_v2_msg(vf, msg);
		break;
	case VIRTCHNL_OP_1588_PTP_GET_CAPS:
		err = ops->get_ptp_cap(vf, msg);
		break;
	case VIRTCHNL_OP_1588_PTP_GET_TIME:
		err = ops->get_phc_time(vf);
		break;
#ifdef CONFIG_X86
	case VIRTCHNL_OP_1588_PTP_GET_SW_CROSS_TSTAMP:
		if (vf->ptp_caps.caps & VIRTCHNL_1588_PTP_CAP_SW_CROSS_TSTAMP)
			err = ops->get_sw_cross_tstamp(vf);
		break;
	case VIRTCHNL_OP_1588_PTP_GET_PHC_TO_CPU_DYNAMIC_RATIO:
		err = ops->get_phc_freq_ratio(vf);
		break;
#endif /* CONFIG_X86 */
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

	if (!err && vf->migration_active)
		ice_migration_save_vf_msg(vf, event);

finish:
	mutex_unlock(&vf->cfg_lock);
	ice_put_vf(vf);
	return err;
}
