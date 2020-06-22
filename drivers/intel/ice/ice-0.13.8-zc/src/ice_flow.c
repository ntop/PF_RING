// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice_common.h"
#include "ice_flow.h"


/* Size of known protocol header fields */
#define ICE_FLOW_FLD_SZ_ETH_TYPE	2
#define ICE_FLOW_FLD_SZ_VLAN		2
#define ICE_FLOW_FLD_SZ_IPV4_ADDR	4
#define ICE_FLOW_FLD_SZ_IPV6_ADDR	16
#define ICE_FLOW_FLD_SZ_IP_DSCP		1
#define ICE_FLOW_FLD_SZ_IP_TTL		1
#define ICE_FLOW_FLD_SZ_IP_PROT		1
#define ICE_FLOW_FLD_SZ_PORT		2
#define ICE_FLOW_FLD_SZ_TCP_FLAGS	1
#define ICE_FLOW_FLD_SZ_ICMP_TYPE	1
#define ICE_FLOW_FLD_SZ_ICMP_CODE	1
#define ICE_FLOW_FLD_SZ_ARP_OPER	2
#define ICE_FLOW_FLD_SZ_GRE_KEYID	4

/* Describe properties of a protocol header field */
struct ice_flow_field_info {
	enum ice_flow_seg_hdr hdr;
	s16 off;	/* Offset from start of a protocol header, in bits */
	u16 size;	/* Size of fields in bits */
};

#define ICE_FLOW_FLD_INFO(_hdr, _offset_bytes, _size_bytes) { \
	.hdr = _hdr, \
	.off = (_offset_bytes) * BITS_PER_BYTE, \
	.size = (_size_bytes) * BITS_PER_BYTE, \
}

/* Table containing properties of supported protocol header fields */
static const
struct ice_flow_field_info ice_flds_info[ICE_FLOW_FIELD_IDX_MAX] = {
	/* Ether */
	/* ICE_FLOW_FIELD_IDX_ETH_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, 0, ETH_ALEN),
	/* ICE_FLOW_FIELD_IDX_ETH_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, ETH_ALEN, ETH_ALEN),
	/* ICE_FLOW_FIELD_IDX_S_VLAN */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_VLAN, 12, ICE_FLOW_FLD_SZ_VLAN),
	/* ICE_FLOW_FIELD_IDX_C_VLAN */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_VLAN, 14, ICE_FLOW_FLD_SZ_VLAN),
	/* ICE_FLOW_FIELD_IDX_ETH_TYPE */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, 12, ICE_FLOW_FLD_SZ_ETH_TYPE),
	/* IPv4 / IPv6 */
	/* ICE_FLOW_FIELD_IDX_IPV4_DSCP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 1, ICE_FLOW_FLD_SZ_IP_DSCP),
	/* ICE_FLOW_FIELD_IDX_IPV6_DSCP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 0, ICE_FLOW_FLD_SZ_IP_DSCP),
	/* ICE_FLOW_FIELD_IDX_IPV4_TTL */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 8, ICE_FLOW_FLD_SZ_IP_TTL),
	/* ICE_FLOW_FIELD_IDX_IPV4_PROT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 9, ICE_FLOW_FLD_SZ_IP_PROT),
	/* ICE_FLOW_FIELD_IDX_IPV6_TTL */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 7, ICE_FLOW_FLD_SZ_IP_TTL),
	/* ICE_FLOW_FIELD_IDX_IPV4_PROT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 6, ICE_FLOW_FLD_SZ_IP_PROT),
	/* ICE_FLOW_FIELD_IDX_IPV4_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 12, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV4_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 16, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV6_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 8, ICE_FLOW_FLD_SZ_IPV6_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV6_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 24, ICE_FLOW_FLD_SZ_IPV6_ADDR),
	/* Transport */
	/* ICE_FLOW_FIELD_IDX_TCP_SRC_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 0, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_TCP_DST_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 2, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_UDP_SRC_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_UDP, 0, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_UDP_DST_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_UDP, 2, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_SCTP, 0, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_SCTP_DST_PORT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_SCTP, 2, ICE_FLOW_FLD_SZ_PORT),
	/* ICE_FLOW_FIELD_IDX_TCP_FLAGS */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 13, ICE_FLOW_FLD_SZ_TCP_FLAGS),
	/* ARP */
	/* ICE_FLOW_FIELD_IDX_ARP_SIP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 14, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_ARP_DIP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 24, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_ARP_SHA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 8, ETH_ALEN),
	/* ICE_FLOW_FIELD_IDX_ARP_DHA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 18, ETH_ALEN),
	/* ICE_FLOW_FIELD_IDX_ARP_OP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 6, ICE_FLOW_FLD_SZ_ARP_OPER),
	/* ICMP */
	/* ICE_FLOW_FIELD_IDX_ICMP_TYPE */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ICMP, 0, ICE_FLOW_FLD_SZ_ICMP_TYPE),
	/* ICE_FLOW_FIELD_IDX_ICMP_CODE */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ICMP, 1, ICE_FLOW_FLD_SZ_ICMP_CODE),
	/* GRE */
	/* ICE_FLOW_FIELD_IDX_GRE_KEYID */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_GRE, 12, ICE_FLOW_FLD_SZ_GRE_KEYID),
};

/* Bitmaps indicating relevant packet types for a particular protocol header
 *
 * Packet types for packets with an Outer/First/Single MAC header
 */
static const u32 ice_ptypes_mac_ofos[] = {
	0xFDC00846, 0xBFBF7F7E, 0xF70001DF, 0xFEFDFDFB,
	0x0000077E, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last MAC VLAN header */
static const u32 ice_ptypes_macvlan_il[] = {
	0x00000000, 0xBC000000, 0x000001DF, 0xF0000000,
	0x0000077E, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outer/First/Single IPv4 header */
static const u32 ice_ptypes_ipv4_ofos[] = {
	0x1DC00000, 0x04000800, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv4 header */
static const u32 ice_ptypes_ipv4_il[] = {
	0xE0000000, 0xB807700E, 0x80000003, 0xE01DC03B,
	0x0000000E, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outer/First/Single IPv6 header */
static const u32 ice_ptypes_ipv6_ofos[] = {
	0x00000000, 0x00000000, 0x77000000, 0x10002000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv6 header */
static const u32 ice_ptypes_ipv6_il[] = {
	0x00000000, 0x03B80770, 0x000001DC, 0x0EE00000,
	0x00000770, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First ARP header */
static const u32 ice_ptypes_arp_of[] = {
	0x00000800, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* UDP Packet types for non-tunneled packets or tunneled
 * packets with inner UDP.
 */
static const u32 ice_ptypes_udp_il[] = {
	0x81000000, 0x20204040, 0x04000010, 0x80810102,
	0x00000040, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last TCP header */
static const u32 ice_ptypes_tcp_il[] = {
	0x04000000, 0x80810102, 0x10000040, 0x02040408,
	0x00000102, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last SCTP header */
static const u32 ice_ptypes_sctp_il[] = {
	0x08000000, 0x01020204, 0x20000081, 0x04080810,
	0x00000204, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First ICMP header */
static const u32 ice_ptypes_icmp_of[] = {
	0x10000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last ICMP header */
static const u32 ice_ptypes_icmp_il[] = {
	0x00000000, 0x02040408, 0x40000102, 0x08101020,
	0x00000408, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First GRE header */
static const u32 ice_ptypes_gre_of[] = {
	0x00000000, 0xBFBF7800, 0x000001DF, 0xFEFDE000,
	0x0000017E, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last MAC header */
static const u32 ice_ptypes_mac_il[] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
};


/* Manage parameters and info. used during the creation of a flow profile */
struct ice_flow_prof_params {
	enum ice_block blk;
	u16 entry_length; /* # of bytes formatted entry will require */
	u8 es_cnt;
	struct ice_flow_prof *prof;

	/* For ACL, the es[0] will have the data of ICE_RX_MDID_PKT_FLAGS_15_0
	 * This will give us the direction flags.
	 */
	struct ice_fv_word es[ICE_MAX_FV_WORDS];
	DECLARE_BITMAP(ptypes, ICE_FLOW_PTYPE_MAX);
};


#define ICE_FLOW_SEG_HDRS_L2_MASK	\
	(ICE_FLOW_SEG_HDR_ETH | ICE_FLOW_SEG_HDR_VLAN)
#define ICE_FLOW_SEG_HDRS_L3_MASK	\
	(ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV6 | \
	 ICE_FLOW_SEG_HDR_ARP)
#define ICE_FLOW_SEG_HDRS_L4_MASK	\
	(ICE_FLOW_SEG_HDR_ICMP | ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_UDP | \
	 ICE_FLOW_SEG_HDR_SCTP)

/**
 * ice_flow_val_hdrs - validates packet segments for valid protocol headers
 * @segs: array of one or more packet segments that describe the flow
 * @segs_cnt: number of packet segments provided
 */
static enum ice_status
ice_flow_val_hdrs(struct ice_flow_seg_info *segs, u8 segs_cnt)
{
	u8 i;

	for (i = 0; i < segs_cnt; i++) {
		/* Multiple L3 headers */
		if (segs[i].hdrs & ICE_FLOW_SEG_HDRS_L3_MASK &&
		    !is_power_of_2(segs[i].hdrs & ICE_FLOW_SEG_HDRS_L3_MASK))
			return ICE_ERR_PARAM;

		/* Multiple L4 headers */
		if (segs[i].hdrs & ICE_FLOW_SEG_HDRS_L4_MASK &&
		    !is_power_of_2(segs[i].hdrs & ICE_FLOW_SEG_HDRS_L4_MASK))
			return ICE_ERR_PARAM;
	}

	return 0;
}

/* Sizes of fixed known protocol headers without header options */
#define ICE_FLOW_PROT_HDR_SZ_MAC	14
#define ICE_FLOW_PROT_HDR_SZ_MAC_VLAN	(ICE_FLOW_PROT_HDR_SZ_MAC + 2)
#define ICE_FLOW_PROT_HDR_SZ_IPV4	20
#define ICE_FLOW_PROT_HDR_SZ_IPV6	40
#define ICE_FLOW_PROT_HDR_SZ_ARP	28
#define ICE_FLOW_PROT_HDR_SZ_ICMP	8
#define ICE_FLOW_PROT_HDR_SZ_TCP	20
#define ICE_FLOW_PROT_HDR_SZ_UDP	8
#define ICE_FLOW_PROT_HDR_SZ_SCTP	12

/**
 * ice_flow_calc_seg_sz - calculates size of a packet segment based on headers
 * @params: information about the flow to be processed
 * @seg: index of packet segment whose header size is to be determined
 */
static u16 ice_flow_calc_seg_sz(struct ice_flow_prof_params *params, u8 seg)
{
	u16 sz;

	/* L2 headers */
	sz = (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_VLAN) ?
		ICE_FLOW_PROT_HDR_SZ_MAC_VLAN : ICE_FLOW_PROT_HDR_SZ_MAC;

	/* L3 headers */
	if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_IPV4)
		sz += ICE_FLOW_PROT_HDR_SZ_IPV4;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_IPV6)
		sz += ICE_FLOW_PROT_HDR_SZ_IPV6;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_ARP)
		sz += ICE_FLOW_PROT_HDR_SZ_ARP;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDRS_L4_MASK)
		/* A L3 header is required if L4 is specified */
		return 0;

	/* L4 headers */
	if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_ICMP)
		sz += ICE_FLOW_PROT_HDR_SZ_ICMP;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_TCP)
		sz += ICE_FLOW_PROT_HDR_SZ_TCP;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_UDP)
		sz += ICE_FLOW_PROT_HDR_SZ_UDP;
	else if (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_SCTP)
		sz += ICE_FLOW_PROT_HDR_SZ_SCTP;

	return sz;
}

/**
 * ice_flow_proc_seg_hdrs - process protocol headers present in pkt segments
 * @params: information about the flow to be processed
 *
 * This function identifies the packet types associated with the protocol
 * headers being present in packet segments of the specified flow profile.
 */
static enum ice_status
ice_flow_proc_seg_hdrs(struct ice_flow_prof_params *params)
{
	struct ice_flow_prof *prof;
	u8 i;

	memset(params->ptypes, 0xff, sizeof(params->ptypes));

	prof = params->prof;

	for (i = 0; i < params->prof->segs_cnt; i++) {
		const unsigned long *src;
		u32 hdrs;

		hdrs = prof->segs[i].hdrs;

		if (hdrs & ICE_FLOW_SEG_HDR_ETH) {
			src = !i ? (const unsigned long *)ice_ptypes_mac_ofos :
				(const unsigned long *)ice_ptypes_mac_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		}

		if (i && hdrs & ICE_FLOW_SEG_HDR_VLAN) {
			src = (const unsigned long *)ice_ptypes_macvlan_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		}

		if (!i && hdrs & ICE_FLOW_SEG_HDR_ARP) {
			bitmap_and(params->ptypes, params->ptypes,
				   (const unsigned long *)ice_ptypes_arp_of,
				   ICE_FLOW_PTYPE_MAX);
		}


		if (hdrs & ICE_FLOW_SEG_HDR_IPV4) {
			src = !i ? (const unsigned long *)ice_ptypes_ipv4_ofos :
				(const unsigned long *)ice_ptypes_ipv4_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		} else if (hdrs & ICE_FLOW_SEG_HDR_IPV6) {
			src = !i ? (const unsigned long *)ice_ptypes_ipv6_ofos :
				(const unsigned long *)ice_ptypes_ipv6_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		}

		if (hdrs & ICE_FLOW_SEG_HDR_ICMP) {
			src = !i ? (const unsigned long *)ice_ptypes_icmp_of :
				(const unsigned long *)ice_ptypes_icmp_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		} else if (hdrs & ICE_FLOW_SEG_HDR_UDP) {
			src = (const unsigned long *)ice_ptypes_udp_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		} else if (hdrs & ICE_FLOW_SEG_HDR_TCP) {
			bitmap_and(params->ptypes, params->ptypes,
				   (const unsigned long *)ice_ptypes_tcp_il,
				   ICE_FLOW_PTYPE_MAX);
		} else if (hdrs & ICE_FLOW_SEG_HDR_SCTP) {
			src = (const unsigned long *)ice_ptypes_sctp_il;
			bitmap_and(params->ptypes, params->ptypes, src,
				   ICE_FLOW_PTYPE_MAX);
		} else if (hdrs & ICE_FLOW_SEG_HDR_GRE) {
			if (!i) {
				src = (const unsigned long *)ice_ptypes_gre_of;
				bitmap_and(params->ptypes, params->ptypes,
					   src, ICE_FLOW_PTYPE_MAX);
			}
		}
	}

	return 0;
}

/**
 * ice_flow_xtract_pkt_flags - Create an extr sequence entry for packet flags
 * @hw: pointer to the HW struct
 * @params: information about the flow to be processed
 * @flags: The value of pkt_flags[x:x] in Rx/Tx MDID metadata.
 *
 * This function will allocate an extraction sequence entries for a DWORD size
 * chunk of the packet flags.
 */
static enum ice_status
ice_flow_xtract_pkt_flags(struct ice_hw *hw,
			  struct ice_flow_prof_params *params,
			  enum ice_flex_mdid_pkt_flags flags)
{
	u8 fv_words = hw->blk[params->blk].es.fvw;
	u8 idx;

	/* Make sure the number of extraction sequence entries required does not
	 * exceed the block's capacity.
	 */
	if (params->es_cnt >= fv_words)
		return ICE_ERR_MAX_LIMIT;

	/* some blocks require a reversed field vector layout */
	if (hw->blk[params->blk].es.reverse)
		idx = fv_words - params->es_cnt - 1;
	else
		idx = params->es_cnt;

	params->es[idx].prot_id = ICE_PROT_META_ID;
	params->es[idx].off = flags;
	params->es_cnt++;

	return 0;
}

/**
 * ice_flow_xtract_fld - Create an extraction sequence entry for the given field
 * @hw: pointer to the HW struct
 * @params: information about the flow to be processed
 * @seg: packet segment index of the field to be extracted
 * @fld: ID of field to be extracted
 *
 * This function determines the protocol ID, offset, and size of the given
 * field. It then allocates one or more extraction sequence entries for the
 * given field, and fill the entries with protocol ID and offset information.
 */
static enum ice_status
ice_flow_xtract_fld(struct ice_hw *hw, struct ice_flow_prof_params *params,
		    u8 seg, enum ice_flow_field fld)
{
	enum ice_flow_field sib = ICE_FLOW_FIELD_IDX_MAX;
	enum ice_prot_id prot_id = ICE_PROT_ID_INVAL;
	u8 fv_words = hw->blk[params->blk].es.fvw;
	struct ice_flow_fld_info *flds;
	u16 cnt, ese_bits, i;
	s16 adj = 0;
	u16 off;

	flds = params->prof->segs[seg].fields;

	switch (fld) {
	case ICE_FLOW_FIELD_IDX_ETH_DA:
	case ICE_FLOW_FIELD_IDX_ETH_SA:
	case ICE_FLOW_FIELD_IDX_S_VLAN:
	case ICE_FLOW_FIELD_IDX_C_VLAN:
		prot_id = seg == 0 ? ICE_PROT_MAC_OF_OR_S : ICE_PROT_MAC_IL;
		break;
	case ICE_FLOW_FIELD_IDX_ETH_TYPE:
		prot_id = seg == 0 ? ICE_PROT_ETYPE_OL : ICE_PROT_ETYPE_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_DSCP:
		prot_id = seg == 0 ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_DSCP:
		prot_id = seg == 0 ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_TTL:
	case ICE_FLOW_FIELD_IDX_IPV4_PROT:
		prot_id = seg == 0 ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;

		/* TTL and PROT share the same extraction seq. entry.
		 * Each is considered a sibling to the other in terms of sharing
		 * the same extraction sequence entry.
		 */
		if (fld == ICE_FLOW_FIELD_IDX_IPV4_TTL)
			sib = ICE_FLOW_FIELD_IDX_IPV4_PROT;
		else if (fld == ICE_FLOW_FIELD_IDX_IPV4_PROT)
			sib = ICE_FLOW_FIELD_IDX_IPV4_TTL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_TTL:
	case ICE_FLOW_FIELD_IDX_IPV6_PROT:
		prot_id = seg == 0 ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;

		/* TTL and PROT share the same extraction seq. entry.
		 * Each is considered a sibling to the other in terms of sharing
		 * the same extraction sequence entry.
		 */
		if (fld == ICE_FLOW_FIELD_IDX_IPV6_TTL)
			sib = ICE_FLOW_FIELD_IDX_IPV6_PROT;
		else if (fld == ICE_FLOW_FIELD_IDX_IPV6_PROT)
			sib = ICE_FLOW_FIELD_IDX_IPV6_TTL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_SA:
	case ICE_FLOW_FIELD_IDX_IPV4_DA:
		prot_id = seg == 0 ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_SA:
	case ICE_FLOW_FIELD_IDX_IPV6_DA:
		prot_id = seg == 0 ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;
		break;
	case ICE_FLOW_FIELD_IDX_TCP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_TCP_DST_PORT:
	case ICE_FLOW_FIELD_IDX_TCP_FLAGS:
		prot_id = ICE_PROT_TCP_IL;
		break;
	case ICE_FLOW_FIELD_IDX_UDP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_UDP_DST_PORT:
		prot_id = ICE_PROT_UDP_IL_OR_S;
		break;
	case ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_SCTP_DST_PORT:
		prot_id = ICE_PROT_SCTP_IL;
		break;
	case ICE_FLOW_FIELD_IDX_ARP_SIP:
	case ICE_FLOW_FIELD_IDX_ARP_DIP:
	case ICE_FLOW_FIELD_IDX_ARP_SHA:
	case ICE_FLOW_FIELD_IDX_ARP_DHA:
	case ICE_FLOW_FIELD_IDX_ARP_OP:
		prot_id = ICE_PROT_ARP_OF;
		break;
	case ICE_FLOW_FIELD_IDX_ICMP_TYPE:
	case ICE_FLOW_FIELD_IDX_ICMP_CODE:
		/* ICMP type and code share the same extraction seq. entry */
		prot_id = (params->prof->segs[seg].hdrs &
			   ICE_FLOW_SEG_HDR_IPV4) ?
			ICE_PROT_ICMP_IL : ICE_PROT_ICMPV6_IL;
		sib = fld == ICE_FLOW_FIELD_IDX_ICMP_TYPE ?
			ICE_FLOW_FIELD_IDX_ICMP_CODE :
			ICE_FLOW_FIELD_IDX_ICMP_TYPE;
		break;
	case ICE_FLOW_FIELD_IDX_GRE_KEYID:
		prot_id = ICE_PROT_GRE_OF;
		break;
	default:
		return ICE_ERR_NOT_IMPL;
	}

	/* Each extraction sequence entry is a word in size, and extracts a
	 * word-aligned offset from a protocol header.
	 */
	ese_bits = ICE_FLOW_FV_EXTRACT_SZ * BITS_PER_BYTE;

	flds[fld].xtrct.prot_id = prot_id;
	flds[fld].xtrct.off = (ice_flds_info[fld].off / ese_bits) *
		ICE_FLOW_FV_EXTRACT_SZ;
	flds[fld].xtrct.disp = (u8)((ice_flds_info[fld].off + adj) % ese_bits);
	flds[fld].xtrct.idx = params->es_cnt;

	/* Adjust the next field-entry index after accommodating the number of
	 * entries this field consumes
	 */
	cnt = DIV_ROUND_UP(flds[fld].xtrct.disp + ice_flds_info[fld].size,
			   ese_bits);

	/* Fill in the extraction sequence entries needed for this field */
	off = flds[fld].xtrct.off;
	for (i = 0; i < cnt; i++) {
		/* Only consume an extraction sequence entry if there is no
		 * sibling field associated with this field or the sibling entry
		 * already extracts the word shared with this field.
		 */
		if (sib == ICE_FLOW_FIELD_IDX_MAX ||
		    flds[sib].xtrct.prot_id == ICE_PROT_ID_INVAL ||
		    flds[sib].xtrct.off != off) {
			u8 idx;

			/* Make sure the number of extraction sequence required
			 * does not exceed the block's capability
			 */
			if (params->es_cnt >= fv_words)
				return ICE_ERR_MAX_LIMIT;

			/* some blocks require a reversed field vector layout */
			if (hw->blk[params->blk].es.reverse)
				idx = fv_words - params->es_cnt - 1;
			else
				idx = params->es_cnt;

			params->es[idx].prot_id = prot_id;
			params->es[idx].off = off;
			params->es_cnt++;
		}

		off += ICE_FLOW_FV_EXTRACT_SZ;
	}

	return 0;
}

/**
 * ice_flow_xtract_raws - Create extract sequence entries for raw bytes
 * @hw: pointer to the HW struct
 * @params: information about the flow to be processed
 * @seg: index of packet segment whose raw fields are to be be extracted
 */
static enum ice_status
ice_flow_xtract_raws(struct ice_hw *hw, struct ice_flow_prof_params *params,
		     u8 seg)
{
	u16 fv_words;
	u16 hdrs_sz;
	u8 i;

	if (!params->prof->segs[seg].raws_cnt)
		return 0;

	if (params->prof->segs[seg].raws_cnt >
	    ARRAY_SIZE(params->prof->segs[seg].raws))
		return ICE_ERR_MAX_LIMIT;

	/* Offsets within the segment headers are not supported */
	hdrs_sz = ice_flow_calc_seg_sz(params, seg);
	if (!hdrs_sz)
		return ICE_ERR_PARAM;

	fv_words = hw->blk[params->blk].es.fvw;

	for (i = 0; i < params->prof->segs[seg].raws_cnt; i++) {
		struct ice_flow_seg_fld_raw *raw;
		u16 off, cnt, j;

		raw = &params->prof->segs[seg].raws[i];

		/* Storing extraction information */
		raw->info.xtrct.prot_id = ICE_PROT_MAC_OF_OR_S;
		raw->info.xtrct.off = (raw->off / ICE_FLOW_FV_EXTRACT_SZ) *
			ICE_FLOW_FV_EXTRACT_SZ;
		raw->info.xtrct.disp = (raw->off % ICE_FLOW_FV_EXTRACT_SZ) *
			BITS_PER_BYTE;
		raw->info.xtrct.idx = params->es_cnt;

		/* Determine the number of field vector entries this raw field
		 * consumes.
		 */
		cnt = DIV_ROUND_UP(raw->info.xtrct.disp + (raw->info.src.last * BITS_PER_BYTE),
				   (ICE_FLOW_FV_EXTRACT_SZ * BITS_PER_BYTE));
		off = raw->info.xtrct.off;
		for (j = 0; j < cnt; j++) {
			u16 idx;

			/* Make sure the number of extraction sequence required
			 * does not exceed the block's capability
			 */
			if (params->es_cnt >= hw->blk[params->blk].es.count ||
			    params->es_cnt >= ICE_MAX_FV_WORDS)
				return ICE_ERR_MAX_LIMIT;

			/* some blocks require a reversed field vector layout */
			if (hw->blk[params->blk].es.reverse)
				idx = fv_words - params->es_cnt - 1;
			else
				idx = params->es_cnt;

			params->es[idx].prot_id = raw->info.xtrct.prot_id;
			params->es[idx].off = off;
			params->es_cnt++;
			off += ICE_FLOW_FV_EXTRACT_SZ;
		}
	}

	return 0;
}

/**
 * ice_flow_create_xtrct_seq - Create an extraction sequence for given segments
 * @hw: pointer to the HW struct
 * @params: information about the flow to be processed
 *
 * This function iterates through all matched fields in the given segments, and
 * creates an extraction sequence for the fields.
 */
static enum ice_status
ice_flow_create_xtrct_seq(struct ice_hw *hw,
			  struct ice_flow_prof_params *params)
{
	enum ice_status status = 0;
	u8 i;

	/* For ACL, we also need to extract the direction bit (Rx,Tx) data from
	 * packet flags
	 */
	if (params->blk == ICE_BLK_ACL) {
		status = ice_flow_xtract_pkt_flags(hw, params,
						   ICE_RX_MDID_PKT_FLAGS_15_0);
		if (status)
			return status;
	}

	for (i = 0; i < params->prof->segs_cnt; i++) {
		u64 match = params->prof->segs[i].match;
		u16 j;

		for (j = 0; j < ICE_FLOW_FIELD_IDX_MAX && match; j++) {
			const u64 bit = BIT_ULL(j);

			if (match & bit) {
				status = ice_flow_xtract_fld
				(hw, params, i, (enum ice_flow_field)j);
				if (status)
					return status;
				match &= ~bit;
			}
		}

		/* Process raw matching bytes */
		status = ice_flow_xtract_raws(hw, params, i);
		if (status)
			return status;
	}

	return status;
}

/**
 * ice_flow_sel_acl_scen - returns the specific scenario
 * @hw: pointer to the hardware structure
 * @params: information about the flow to be processed
 *
 * This function will return the specific scenario based on the
 * params passed to it
 */
static enum ice_status
ice_flow_sel_acl_scen(struct ice_hw *hw, struct ice_flow_prof_params *params)
{
	/* Find the best-fit scenario for the provided match width */
	struct ice_acl_scen *cand_scen = NULL, *scen;

	if (!hw->acl_tbl)
		return ICE_ERR_DOES_NOT_EXIST;

	/* Loop through each scenario and match against the scenario width
	 * to select the specific scenario
	 */
	list_for_each_entry(scen, &hw->acl_tbl->scens, list_entry)
		if (scen->eff_width >= params->entry_length &&
		    (!cand_scen || cand_scen->eff_width > scen->eff_width))
			cand_scen = scen;
	if (!cand_scen)
		return ICE_ERR_DOES_NOT_EXIST;

	params->prof->cfg.scen = cand_scen;

	return 0;
}

/**
 * ice_flow_acl_def_entry_frmt - Determine the layout of flow entries
 * @params: information about the flow to be processed
 */
static enum ice_status
ice_flow_acl_def_entry_frmt(struct ice_flow_prof_params *params)
{
	u16 index, i, range_idx = 0;

	index = ICE_AQC_ACL_PROF_BYTE_SEL_START_IDX;

	for (i = 0; i < params->prof->segs_cnt; i++) {
		struct ice_flow_seg_info *seg = &params->prof->segs[i];
		u64 match = seg->match;
		u8 j;

		for (j = 0; j < ICE_FLOW_FIELD_IDX_MAX && match; j++) {
			struct ice_flow_fld_info *fld;
			const u64 bit = BIT_ULL(j);

			if (!(match & bit))
				continue;

			fld = &seg->fields[j];
			fld->entry.mask = ICE_FLOW_FLD_OFF_INVAL;

			if (fld->type == ICE_FLOW_FLD_TYPE_RANGE) {
				fld->entry.last = ICE_FLOW_FLD_OFF_INVAL;

				/* Range checking only supported for single
				 * words
				 */
				if (DIV_ROUND_UP(ice_flds_info[j].size + fld->xtrct.disp, BITS_PER_BYTE * 2) > 1)
					return ICE_ERR_PARAM;

				/* Ranges must define low and high values */
				if (fld->src.val == ICE_FLOW_FLD_OFF_INVAL ||
				    fld->src.last == ICE_FLOW_FLD_OFF_INVAL)
					return ICE_ERR_PARAM;

				fld->entry.val = range_idx++;
			} else {
				/* Store adjusted byte-length of field for later
				 * use, taking into account potential
				 * non-byte-aligned displacement
				 */
				fld->entry.last = DIV_ROUND_UP(ice_flds_info[j].size + (fld->xtrct.disp % BITS_PER_BYTE),
							       BITS_PER_BYTE);
				fld->entry.val = index;
				index += fld->entry.last;
			}

			match &= ~bit;
		}

		for (j = 0; j < seg->raws_cnt; j++) {
			struct ice_flow_seg_fld_raw *raw = &seg->raws[j];

			raw->info.entry.mask = ICE_FLOW_FLD_OFF_INVAL;
			raw->info.entry.val = index;
			raw->info.entry.last = raw->info.src.last;
			index += raw->info.entry.last;
		}
	}

	/* Currently only support using the byte selection base, which only
	 * allows for an effective entry size of 30 bytes. Reject anything
	 * larger.
	 */
	if (index > ICE_AQC_ACL_PROF_BYTE_SEL_ELEMS)
		return ICE_ERR_PARAM;

	/* Only 8 range checkers per profile, reject anything trying to use
	 * more
	 */
	if (range_idx > ICE_AQC_ACL_PROF_RANGES_NUM_CFG)
		return ICE_ERR_PARAM;

	/* Store # bytes required for entry for later use */
	params->entry_length = index;

	return 0;
}

/**
 * ice_flow_proc_segs - process all packet segments associated with a profile
 * @hw: pointer to the HW struct
 * @params: information about the flow to be processed
 */
static enum ice_status
ice_flow_proc_segs(struct ice_hw *hw, struct ice_flow_prof_params *params)
{
	enum ice_status status;

	status = ice_flow_proc_seg_hdrs(params);
	if (status)
		return status;

	status = ice_flow_create_xtrct_seq(hw, params);
	if (status)
		return status;

	switch (params->blk) {
	case ICE_BLK_RSS:
		/* Only header information is provided for RSS configuration.
		 * No further processing is needed.
		 */
		status = 0;
		break;
	case ICE_BLK_ACL:
		status = ice_flow_acl_def_entry_frmt(params);
		if (status)
			return status;
		status = ice_flow_sel_acl_scen(hw, params);
		if (status)
			return status;
		break;
	case ICE_BLK_FD:
		status = 0;
		break;
	case ICE_BLK_SW:
	default:
		return ICE_ERR_NOT_IMPL;
	}

	return status;
}

#define ICE_FLOW_FIND_PROF_CHK_FLDS	0x00000001
#define ICE_FLOW_FIND_PROF_CHK_VSI	0x00000002
#define ICE_FLOW_FIND_PROF_NOT_CHK_DIR	0x00000004

/**
 * ice_flow_find_prof_conds - Find a profile matching headers and conditions
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @dir: flow direction
 * @segs: array of one or more packet segments that describe the flow
 * @segs_cnt: number of packet segments provided
 * @vsi_handle: software VSI handle to check VSI (ICE_FLOW_FIND_PROF_CHK_VSI)
 * @conds: additional conditions to be checked (ICE_FLOW_FIND_PROF_CHK_*)
 */
static struct ice_flow_prof *
ice_flow_find_prof_conds(struct ice_hw *hw, enum ice_block blk,
			 enum ice_flow_dir dir, struct ice_flow_seg_info *segs,
			 u8 segs_cnt, u16 vsi_handle, u32 conds)
{
	struct ice_flow_prof *p, *prof = NULL;

	mutex_lock(&hw->fl_profs_locks[blk]);
	list_for_each_entry(p, &hw->fl_profs[blk], l_entry) {
		if ((p->dir == dir || conds & ICE_FLOW_FIND_PROF_NOT_CHK_DIR) &&
		    segs_cnt && segs_cnt == p->segs_cnt) {
			u8 i;

			/* Check for profile-VSI association if specified */
			if ((conds & ICE_FLOW_FIND_PROF_CHK_VSI) &&
			    ice_is_vsi_valid(hw, vsi_handle) &&
			    !test_bit(vsi_handle, p->vsis))
				continue;

			/* Protocol headers must be checked. Matched fields are
			 * checked if specified.
			 */
			for (i = 0; i < segs_cnt; i++)
				if (segs[i].hdrs != p->segs[i].hdrs ||
				    ((conds & ICE_FLOW_FIND_PROF_CHK_FLDS) &&
				     segs[i].match != p->segs[i].match))
					break;

			/* A match is found if all segments are matched */
			if (i == segs_cnt) {
				prof = p;
				break;
			}
		}
	}
	mutex_unlock(&hw->fl_profs_locks[blk]);

	return prof;
}

/**
 * ice_flow_find_prof - Look up a profile matching headers and matched fields
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @dir: flow direction
 * @segs: array of one or more packet segments that describe the flow
 * @segs_cnt: number of packet segments provided
 */
u64
ice_flow_find_prof(struct ice_hw *hw, enum ice_block blk, enum ice_flow_dir dir,
		   struct ice_flow_seg_info *segs, u8 segs_cnt)
{
	struct ice_flow_prof *p;

	p = ice_flow_find_prof_conds(hw, blk, dir, segs, segs_cnt,
				     ICE_MAX_VSI, ICE_FLOW_FIND_PROF_CHK_FLDS);

	return p ? p->id : ICE_FLOW_PROF_ID_INVAL;
}

/**
 * ice_flow_find_prof_id - Look up a profile with given profile ID
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @prof_id: unique ID to identify this flow profile
 */
static struct ice_flow_prof *
ice_flow_find_prof_id(struct ice_hw *hw, enum ice_block blk, u64 prof_id)
{
	struct ice_flow_prof *p;

	list_for_each_entry(p, &hw->fl_profs[blk], l_entry) {
		if (p->id == prof_id)
			return p;
	}

	return NULL;
}

/**
 * ice_dealloc_flow_entry - Deallocate flow entry memory
 * @hw: pointer to the HW struct
 * @entry: flow entry to be removed
 */
static void
ice_dealloc_flow_entry(struct ice_hw *hw, struct ice_flow_entry *entry)
{
	if (!entry)
		return;

	if (entry->entry)
		devm_kfree(ice_hw_to_dev(hw), entry->entry);

	if (entry->range_buf) {
		devm_kfree(ice_hw_to_dev(hw), entry->range_buf);
		entry->range_buf = NULL;
	}

	if (entry->acts) {
		devm_kfree(ice_hw_to_dev(hw), entry->acts);
		entry->acts = NULL;
		entry->acts_cnt = 0;
	}

	devm_kfree(ice_hw_to_dev(hw), entry);
}

/**
 * ice_flow_rem_entry_sync - Remove a flow entry
 * @hw: pointer to the HW struct
 * @entry: flow entry to be removed
 */
static enum ice_status
ice_flow_rem_entry_sync(struct ice_hw *hw, struct ice_flow_entry *entry)
{
	if (!entry)
		return ICE_ERR_BAD_PTR;

	list_del(&entry->l_entry);

	ice_dealloc_flow_entry(hw, entry);

	return 0;
}

/**
 * ice_flow_add_prof_sync - Add a flow profile for packet segments and fields
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @dir: flow direction
 * @prof_id: unique ID to identify this flow profile
 * @segs: array of one or more packet segments that describe the flow
 * @segs_cnt: number of packet segments provided
 * @acts: array of default actions
 * @acts_cnt: number of default actions
 * @prof: stores the returned flow profile added
 *
 * Assumption: the caller has acquired the lock to the profile list
 */
static enum ice_status
ice_flow_add_prof_sync(struct ice_hw *hw, enum ice_block blk,
		       enum ice_flow_dir dir, u64 prof_id,
		       struct ice_flow_seg_info *segs, u8 segs_cnt,
		       struct ice_flow_action *acts, u8 acts_cnt,
		       struct ice_flow_prof **prof)
{
	struct ice_flow_prof_params params;
	enum ice_status status = 0;
	u8 i;

	if (!prof || (acts_cnt && !acts))
		return ICE_ERR_BAD_PTR;

	memset(&params, 0, sizeof(params));
	params.prof = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*params.prof),
				   GFP_KERNEL);
	if (!params.prof)
		return ICE_ERR_NO_MEMORY;

	/* initialize extraction sequence to all invalid (0xff) */
	for (i = 0; i < ICE_MAX_FV_WORDS; i++) {
		params.es[i].prot_id = ICE_PROT_INVALID;
		params.es[i].off = ICE_FV_OFFSET_INVAL;
	}

	params.blk = blk;
	params.prof->id = prof_id;
	params.prof->dir = dir;
	params.prof->segs_cnt = segs_cnt;

	/* Make a copy of the segments that need to be persistent in the flow
	 * profile instance
	 */
	for (i = 0; i < segs_cnt; i++)
		memcpy(&params.prof->segs[i], &segs[i], sizeof(*segs));

	/* Make a copy of the actions that need to be persistent in the flow
	 * profile instance.
	 */
	if (acts_cnt) {
		params.prof->acts = devm_kmemdup(ice_hw_to_dev(hw), acts,
						 acts_cnt * sizeof(*acts),
						 GFP_KERNEL);

		if (!params.prof->acts) {
			status = ICE_ERR_NO_MEMORY;
			goto out;
		}
	}


	status = ice_flow_proc_segs(hw, &params);
	if (status) {
		ice_debug(hw, ICE_DBG_FLOW,
			  "Error processing a flow's packet segments\n");
		goto out;
	}

	/* Add a HW profile for this flow profile */
	status = ice_add_prof(hw, blk, prof_id, (u8 *)params.ptypes, params.es);
	if (status) {
		ice_debug(hw, ICE_DBG_FLOW, "Error adding a HW flow profile\n");
		goto out;
	}

	INIT_LIST_HEAD(&params.prof->entries);
	mutex_init(&params.prof->entries_lock);
	*prof = params.prof;

out:
	if (status) {
		if (params.prof->acts)
			devm_kfree(ice_hw_to_dev(hw), params.prof->acts);
		devm_kfree(ice_hw_to_dev(hw), params.prof);
	}

	return status;
}

/**
 * ice_flow_rem_prof_sync - remove a flow profile
 * @hw: pointer to the hardware structure
 * @blk: classification stage
 * @prof: pointer to flow profile to remove
 *
 * Assumption: the caller has acquired the lock to the profile list
 */
static enum ice_status
ice_flow_rem_prof_sync(struct ice_hw *hw, enum ice_block blk,
		       struct ice_flow_prof *prof)
{
	enum ice_status status = 0;

	/* Remove all remaining flow entries before removing the flow profile */
	if (!list_empty(&prof->entries)) {
		struct ice_flow_entry *e, *t;

		mutex_lock(&prof->entries_lock);

		list_for_each_entry_safe(e, t, &prof->entries, l_entry) {
			status = ice_flow_rem_entry_sync(hw, e);
			if (status)
				break;
		}

		mutex_unlock(&prof->entries_lock);
	}

	/* Remove all hardware profiles associated with this flow profile */
	status = ice_rem_prof(hw, blk, prof->id);
	if (!status) {
		list_del(&prof->l_entry);
		mutex_destroy(&prof->entries_lock);
		if (prof->acts)
			devm_kfree(ice_hw_to_dev(hw), prof->acts);
		devm_kfree(ice_hw_to_dev(hw), prof);
	}

	return status;
}

/**
 * ice_flow_acl_set_xtrct_seq_fld - Populate xtrct seq for single field
 * @buf: Destination buffer function writes partial xtrct sequence to
 * @info: Info about field
 */
static void
ice_flow_acl_set_xtrct_seq_fld(struct ice_aqc_acl_prof_generic_frmt *buf,
			       struct ice_flow_fld_info *info)
{
	u16 dst, i;
	u8 src;

	src = info->xtrct.idx * ICE_FLOW_FV_EXTRACT_SZ +
		info->xtrct.disp / BITS_PER_BYTE;
	dst = info->entry.val;
	for (i = 0; i < info->entry.last; i++)
		/* HW stores field vector words in LE, convert words back to BE
		 * so constructed entries will end up in network order
		 */
		buf->byte_selection[dst++] = src++ ^ 1;
}

/**
 * ice_flow_acl_set_xtrct_seq - Program ACL extraction sequence
 * @hw: pointer to the hardware structure
 * @prof: pointer to flow profile
 */
static enum ice_status
ice_flow_acl_set_xtrct_seq(struct ice_hw *hw, struct ice_flow_prof *prof)
{
	struct ice_aqc_acl_prof_generic_frmt buf;
	enum ice_status status = 0;
	u16 i;

	memset(&buf, 0, sizeof(buf));

	for (i = 0; i < prof->segs_cnt; i++) {
		struct ice_flow_seg_info *seg = &prof->segs[i];
		u64 match = seg->match;
		u16 j;

		for (j = 0; j < ICE_FLOW_FIELD_IDX_MAX && match; j++) {
			struct ice_flow_fld_info *info;
			const u64 bit = BIT_ULL(j);

			if (!(match & bit))
				continue;

			info = &seg->fields[j];

			if (info->type == ICE_FLOW_FLD_TYPE_RANGE)
				buf.word_selection[info->entry.val] =
					info->xtrct.idx;
			else
				ice_flow_acl_set_xtrct_seq_fld(&buf, info);

			match &= ~bit;
		}

		for (j = 0; j < seg->raws_cnt; j++)
			ice_flow_acl_set_xtrct_seq_fld(&buf,
						       &seg->raws[j].info);
	}

	buf.pf_scenario_num[0] = (u8)prof->cfg.scen->id;
	memset(&buf.pf_scenario_num[1], 0xff,
	       ICE_AQC_ACL_PROF_PF_SCEN_NUM_ELEMS - 1);

	status = ice_prgm_acl_prof_extrt(hw, prof->id, &buf, NULL);
	return status;
}

/**
 * ice_flow_assoc_vsig_vsi - associate a VSI with VSIG
 * @hw: pointer to the hardware structure
 * @blk: classification stage
 * @vsi_handle: software VSI handle
 * @vsig: target VSI group
 *
 * Assumption: the caller has already verified that the VSI to
 * be added has the same characteristics as the VSIG and will
 * thereby have access to all resources added to that VSIG.
 */
enum ice_status
ice_flow_assoc_vsig_vsi(struct ice_hw *hw, enum ice_block blk, u16 vsi_handle,
			u16 vsig)
{
	enum ice_status status;

	if (!ice_is_vsi_valid(hw, vsi_handle) || blk >= ICE_BLK_COUNT)
		return ICE_ERR_PARAM;

	mutex_lock(&hw->fl_profs_locks[blk]);
	status = ice_add_vsi_flow(hw, blk, ice_get_hw_vsi_num(hw, vsi_handle),
				  vsig);
	mutex_unlock(&hw->fl_profs_locks[blk]);

	return status;
}

/**
 * ice_flow_assoc_prof - associate a VSI with a flow profile
 * @hw: pointer to the hardware structure
 * @blk: classification stage
 * @prof: pointer to flow profile
 * @vsi_handle: software VSI handle
 *
 * Assumption: the caller has acquired the lock to the profile list
 * and the software VSI handle has been validated
 */
static enum ice_status
ice_flow_assoc_prof(struct ice_hw *hw, enum ice_block blk,
		    struct ice_flow_prof *prof, u16 vsi_handle)
{
	enum ice_status status = 0;

	if (!test_bit(vsi_handle, prof->vsis)) {
		if (blk == ICE_BLK_ACL) {
			status = ice_flow_acl_set_xtrct_seq(hw, prof);
			if (status)
				return status;
		}
		status = ice_add_prof_id_flow(hw, blk,
					      ice_get_hw_vsi_num(hw,
								 vsi_handle),
					      prof->id);
		if (!status)
			set_bit(vsi_handle, prof->vsis);
		else
			ice_debug(hw, ICE_DBG_FLOW,
				  "HW profile add failed, %d\n",
				  status);
	}

	return status;
}

/**
 * ice_flow_disassoc_prof - disassociate a VSI from a flow profile
 * @hw: pointer to the hardware structure
 * @blk: classification stage
 * @prof: pointer to flow profile
 * @vsi_handle: software VSI handle
 *
 * Assumption: the caller has acquired the lock to the profile list
 * and the software VSI handle has been validated
 */
static enum ice_status
ice_flow_disassoc_prof(struct ice_hw *hw, enum ice_block blk,
		       struct ice_flow_prof *prof, u16 vsi_handle)
{
	enum ice_status status = 0;

	if (test_bit(vsi_handle, prof->vsis)) {
		status = ice_rem_prof_id_flow(hw, blk,
					      ice_get_hw_vsi_num(hw,
								 vsi_handle),
					      prof->id);
		if (!status)
			clear_bit(vsi_handle, prof->vsis);
		else
			ice_debug(hw, ICE_DBG_FLOW,
				  "HW profile remove failed, %d\n",
				  status);
	}

	return status;
}

/**
 * ice_flow_add_prof - Add a flow profile for packet segments and matched fields
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @dir: flow direction
 * @prof_id: unique ID to identify this flow profile
 * @segs: array of one or more packet segments that describe the flow
 * @segs_cnt: number of packet segments provided
 * @acts: array of default actions
 * @acts_cnt: number of default actions
 * @prof: stores the returned flow profile added
 */
enum ice_status
ice_flow_add_prof(struct ice_hw *hw, enum ice_block blk, enum ice_flow_dir dir,
		  u64 prof_id, struct ice_flow_seg_info *segs, u8 segs_cnt,
		  struct ice_flow_action *acts, u8 acts_cnt,
		  struct ice_flow_prof **prof)
{
	enum ice_status status;

	if (segs_cnt > ICE_FLOW_SEG_MAX)
		return ICE_ERR_MAX_LIMIT;

	if (!segs_cnt)
		return ICE_ERR_PARAM;

	if (!segs)
		return ICE_ERR_BAD_PTR;

	status = ice_flow_val_hdrs(segs, segs_cnt);
	if (status)
		return status;

	mutex_lock(&hw->fl_profs_locks[blk]);

	status = ice_flow_add_prof_sync(hw, blk, dir, prof_id, segs, segs_cnt,
					acts, acts_cnt, prof);
	if (!status)
		list_add(&(*prof)->l_entry, &hw->fl_profs[blk]);

	mutex_unlock(&hw->fl_profs_locks[blk]);

	return status;
}

/**
 * ice_flow_rem_prof - Remove a flow profile and all entries associated with it
 * @hw: pointer to the HW struct
 * @blk: the block for which the flow profile is to be removed
 * @prof_id: unique ID of the flow profile to be removed
 */
enum ice_status
ice_flow_rem_prof(struct ice_hw *hw, enum ice_block blk, u64 prof_id)
{
	struct ice_flow_prof *prof;
	enum ice_status status;

	mutex_lock(&hw->fl_profs_locks[blk]);

	prof = ice_flow_find_prof_id(hw, blk, prof_id);
	if (!prof) {
		status = ICE_ERR_DOES_NOT_EXIST;
		goto out;
	}

	/* prof becomes invalid after the call */
	status = ice_flow_rem_prof_sync(hw, blk, prof);

out:
	mutex_unlock(&hw->fl_profs_locks[blk]);

	return status;
}

/**
 * ice_flow_get_hw_prof - return the HW profile for a specific profile ID handle
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @prof_id: the profile ID handle
 * @hw_prof_id: pointer to variable to receive the HW profile ID
 */
enum ice_status
ice_flow_get_hw_prof(struct ice_hw *hw, enum ice_block blk, u64 prof_id,
		     u8 *hw_prof_id)
{
	struct ice_prof_map *map;

	map = ice_search_prof_id(hw, blk, prof_id);
	if (map) {
		*hw_prof_id = map->prof_id;
		return 0;
	}

	return ICE_ERR_DOES_NOT_EXIST;
}

/**
 * ice_flow_find_entry - look for a flow entry using its unique ID
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @entry_id: unique ID to identify this flow entry
 *
 * This function looks for the flow entry with the specified unique ID in all
 * flow profiles of the specified classification stage. If the entry is found,
 * and it returns the handle to the flow entry. Otherwise, it returns
 * ICE_FLOW_ENTRY_ID_INVAL.
 */
u64 ice_flow_find_entry(struct ice_hw *hw, enum ice_block blk, u64 entry_id)
{
	struct ice_flow_entry *found = NULL;
	struct ice_flow_prof *p;

	mutex_lock(&hw->fl_profs_locks[blk]);

	list_for_each_entry(p, &hw->fl_profs[blk], l_entry) {
		struct ice_flow_entry *e;

		mutex_lock(&p->entries_lock);
		list_for_each_entry(e, &p->entries, l_entry)
			if (e->id == entry_id) {
				found = e;
				break;
			}
		mutex_unlock(&p->entries_lock);

		if (found)
			break;
	}

	mutex_unlock(&hw->fl_profs_locks[blk]);

	return found ? ICE_FLOW_ENTRY_HNDL(found) : ICE_FLOW_ENTRY_HANDLE_INVAL;
}

/**
 * ice_flow_acl_frmt_entry_range - Format an acl range checker for a given field
 * @fld: number of the given field
 * @info: info about field
 * @range_buf: range checker configuration buffer
 * @data: pointer to a data buffer containing flow entry's match values/masks
 * @range: Input/output param indicating which range checkers are being used
 */
static void
ice_flow_acl_frmt_entry_range(u16 fld, struct ice_flow_fld_info *info,
			      struct ice_aqc_acl_profile_ranges *range_buf,
			      u8 *data, u8 *range)
{
	u16 new_mask;

	/* If not specified, default mask is all bits in field */
	new_mask = (info->src.mask == ICE_FLOW_FLD_OFF_INVAL ?
		    BIT(ice_flds_info[fld].size) - 1 :
		    (*(u16 *)(data + info->src.mask))) << info->xtrct.disp;

	/* If the mask is 0, then we don't need to worry about this input
	 * range checker value.
	 */
	if (new_mask) {
		u16 new_high =
			(*(u16 *)(data + info->src.last)) << info->xtrct.disp;
		u16 new_low =
			(*(u16 *)(data + info->src.val)) << info->xtrct.disp;
		u8 range_idx = info->entry.val;

		range_buf->checker_cfg[range_idx].low_boundary =
			cpu_to_le16(new_low);
		range_buf->checker_cfg[range_idx].high_boundary =
			cpu_to_le16(new_high);
		range_buf->checker_cfg[range_idx].mask = cpu_to_le16(new_mask);

		/* Indicate which range checker is being used */
		*range |= BIT(range_idx);
	}
}

/**
 * ice_flow_acl_frmt_entry_fld - Partially format acl entry for a given field
 * @fld: number of the given field
 * @info: info about the field
 * @buf: buffer containing the entry
 * @dontcare: buffer containing don't care mask for entry
 * @data: pointer to a data buffer containing flow entry's match values/masks
 */
static void
ice_flow_acl_frmt_entry_fld(u16 fld, struct ice_flow_fld_info *info, u8 *buf,
			    u8 *dontcare, u8 *data)
{
	u16 dst, src, mask, k, end_disp, tmp_s = 0, tmp_m = 0;
	bool use_mask = false;
	u8 disp;

	src = info->src.val;
	mask = info->src.mask;
	dst = info->entry.val;
	disp = info->xtrct.disp % BITS_PER_BYTE;

	if (mask != ICE_FLOW_FLD_OFF_INVAL)
		use_mask = true;

	for (k = 0; k < info->entry.last; k++, dst++) {
		/* Add overflow bits from previous byte */
		buf[dst] = (tmp_s & 0xff00) >> 8;

		/* If mask is not valid, tmp_m is always zero, so just setting
		 * dontcare to 0 (no masked bits). If mask is valid, pulls in
		 * overflow bits of mask from prev byte
		 */
		dontcare[dst] = (tmp_m & 0xff00) >> 8;

		/* If there is displacement, last byte will only contain
		 * displaced data, but there is no more data to read from user
		 * buffer, so skip so as not to potentially read beyond end of
		 * user buffer
		 */
		if (!disp || k < info->entry.last - 1) {
			/* Store shifted data to use in next byte */
			tmp_s = data[src++] << disp;

			/* Add current (shifted) byte */
			buf[dst] |= tmp_s & 0xff;

			/* Handle mask if valid */
			if (use_mask) {
				tmp_m = (~data[mask++] & 0xff) << disp;
				dontcare[dst] |= tmp_m & 0xff;
			}
		}
	}

	/* Fill in don't care bits at beginning of field */
	if (disp) {
		dst = info->entry.val;
		for (k = 0; k < disp; k++)
			dontcare[dst] |= BIT(k);
	}

	end_disp = (disp + ice_flds_info[fld].size) % BITS_PER_BYTE;

	/* Fill in don't care bits at end of field */
	if (end_disp) {
		dst = info->entry.val + info->entry.last - 1;
		for (k = end_disp; k < BITS_PER_BYTE; k++)
			dontcare[dst] |= BIT(k);
	}
}

/**
 * ice_flow_acl_frmt_entry - Format acl entry
 * @hw: pointer to the hardware structure
 * @prof: pointer to flow profile
 * @e: pointer to the flow entry
 * @data: pointer to a data buffer containing flow entry's match values/masks
 * @acts: array of actions to be performed on a match
 * @acts_cnt: number of actions
 *
 * Formats the key (and key_inverse) to be matched from the data passed in,
 * along with data from the flow profile. This key/key_inverse pair makes up
 * the 'entry' for an acl flow entry.
 */
static enum ice_status
ice_flow_acl_frmt_entry(struct ice_hw *hw, struct ice_flow_prof *prof,
			struct ice_flow_entry *e, u8 *data,
			struct ice_flow_action *acts, u8 acts_cnt)
{
	u8 *buf = NULL, *dontcare = NULL, *key = NULL, range = 0, dir_flag_msk;
	struct ice_aqc_acl_profile_ranges *range_buf = NULL;
	enum ice_status status = ICE_ERR_NO_MEMORY;
	u64 dup_check = 0;
	u16 i, buf_sz;

	/* Format the result action */
	if (acts_cnt > ICE_FLOW_ACL_MAX_NUM_ACT)
		return ICE_ERR_OUT_OF_RANGE;

	for (i = 0; i < acts_cnt; i++) {
		if (acts[i].type != ICE_FLOW_ACT_NOP &&
		    acts[i].type != ICE_FLOW_ACT_DROP &&
		    acts[i].type != ICE_FLOW_ACT_FWD_QUEUE)
			return ICE_ERR_CFG;

		/* If the caller want to add two actions of the same type, then
		 * it is considered invalid configuration.
		 */
		if (dup_check & BIT_ULL(acts[i].type))
			return ICE_ERR_PARAM;
		dup_check |= BIT_ULL(acts[i].type);
	}

	e->acts = devm_kmemdup(ice_hw_to_dev(hw), acts,
			       acts_cnt * sizeof(*acts), GFP_KERNEL);

	if (!e->acts)
		goto out;

	e->acts_cnt = acts_cnt;

	/* Format the matching data */
	buf_sz = prof->cfg.scen->width;
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_sz, GFP_KERNEL);
	if (!buf)
		goto out;

	dontcare = devm_kzalloc(ice_hw_to_dev(hw), buf_sz, GFP_KERNEL);
	if (!dontcare)
		goto out;

	/* 'key' buffer will store both key and key_inverse, so must be twice
	 * size of buf
	 */
	key = devm_kzalloc(ice_hw_to_dev(hw), buf_sz * 2, GFP_KERNEL);
	if (!key)
		goto out;

	range_buf = devm_kzalloc(ice_hw_to_dev(hw),
				 sizeof(struct ice_aqc_acl_profile_ranges),
				 GFP_KERNEL);
	if (!range_buf)
		goto out;

	/* Set don't care mask to all 1's to start, will zero out used bytes */
	memset(dontcare, 0xff, buf_sz);

	for (i = 0; i < prof->segs_cnt; i++) {
		struct ice_flow_seg_info *seg = &prof->segs[i];
		u64 match = seg->match;
		u16 j;

		for (j = 0; j < ICE_FLOW_FIELD_IDX_MAX && match; j++) {
			struct ice_flow_fld_info *info;
			const u64 bit = BIT_ULL(j);

			if (!(match & bit))
				continue;

			info = &seg->fields[j];

			if (info->type == ICE_FLOW_FLD_TYPE_RANGE)
				ice_flow_acl_frmt_entry_range
					(j, info, range_buf, data, &range);
			else
				ice_flow_acl_frmt_entry_fld(j, info, buf,
							    dontcare, data);

			match &= ~bit;
		}

		for (j = 0; j < seg->raws_cnt; j++) {
			struct ice_flow_fld_info *info = &seg->raws[j].info;
			u16 dst, src, mask, k;
			bool use_mask = false;

			src = info->src.val;
			dst = info->entry.val;
			mask = info->src.mask;

			if (mask != ICE_FLOW_FLD_OFF_INVAL)
				use_mask = true;

			for (k = 0; k < info->entry.last; k++, dst++) {
				buf[dst] = data[src++];
				if (use_mask)
					dontcare[dst] = ~data[mask++];
				else
					dontcare[dst] = 0;
			}
		}
	}

	buf[prof->cfg.scen->pid_idx] = (u8)prof->id;
	dontcare[prof->cfg.scen->pid_idx] = 0;

	/* Format the buffer for direction flags */
	dir_flag_msk = BIT(ICE_FLG_PKT_DIR);
	dontcare[prof->cfg.scen->pkt_dir_idx] = ~dir_flag_msk;
	if (prof->dir == ICE_FLOW_RX)
		buf[prof->cfg.scen->pkt_dir_idx] = dir_flag_msk;

	if (range) {
		buf[prof->cfg.scen->rng_chk_idx] = range;
		/* Mark any unused range checkers as don't care */
		dontcare[prof->cfg.scen->rng_chk_idx] = ~range;
		e->range_buf = range_buf;
	} else {
		devm_kfree(ice_hw_to_dev(hw), range_buf);
	}

	status = ice_set_key(key, buf_sz * 2, buf, NULL, dontcare, NULL, 0,
			     buf_sz);
	if (status)
		goto out;

	e->entry = key;
	e->entry_sz = buf_sz * 2;

out:
	if (buf)
		devm_kfree(ice_hw_to_dev(hw), buf);

	if (dontcare)
		devm_kfree(ice_hw_to_dev(hw), dontcare);

	if (status && key)
		devm_kfree(ice_hw_to_dev(hw), key);

	if (status && range_buf) {
		devm_kfree(ice_hw_to_dev(hw), range_buf);
		e->range_buf = NULL;
	}

	if (status && e->acts) {
		devm_kfree(ice_hw_to_dev(hw), e->acts);
		e->acts = NULL;
		e->acts_cnt = 0;
	}

	return status;
}

/**
 * ice_flow_acl_find_scen_entry_cond - Find an ACL scenario entry that matches
 *				       the compared data.
 * @prof: pointer to flow profile
 * @e: pointer to the comparing flow entry
 * @do_chg_action: decide if we want to change the ACL action
 * @do_add_entry: decide if we want to add the new ACL entry
 * @do_rem_entry: decide if we want to remove the current ACL entry
 *
 * Find an ACL scenario entry that matches the compared data. In the same time,
 * this function also figure out:
 * a/ If we want to change the ACL action
 * b/ If we want to add the new ACL entry
 * c/ If we want to remove the current ACL entry
 */
static struct ice_flow_entry *
ice_flow_acl_find_scen_entry_cond(struct ice_flow_prof *prof,
				  struct ice_flow_entry *e, bool *do_chg_action,
				  bool *do_add_entry, bool *do_rem_entry)
{
	struct ice_flow_entry *p, *return_entry = NULL;
	u8 i, j;

	/* Check if:
	 * a/ There exists an entry with same matching data, but different
	 *    priority, then we remove this existing ACL entry. Then, we
	 *    will add the new entry to the ACL scenario.
	 * b/ There exists an entry with same matching data, priority, and
	 *    result action, then we do nothing
	 * c/ There exists an entry with same matching data, priority, but
	 *    different, action, then do only change the action's entry.
	 * d/ Else, we add this new entry to the ACL scenario.
	 */
	*do_chg_action = false;
	*do_add_entry = true;
	*do_rem_entry = false;
	list_for_each_entry(p, &prof->entries, l_entry) {
		if (memcmp(p->entry, e->entry, p->entry_sz))
			continue;

		/* From this point, we have the same matching_data. */
		*do_add_entry = false;
		return_entry = p;

		if (p->priority != e->priority) {
			/* matching data && !priority */
			*do_add_entry = true;
			*do_rem_entry = true;
			break;
		}

		/* From this point, we will have matching_data && priority */
		if (p->acts_cnt != e->acts_cnt)
			*do_chg_action = true;
		for (i = 0; i < p->acts_cnt; i++) {
			bool found_not_match = false;

			for (j = 0; j < e->acts_cnt; j++)
				if (memcmp(&p->acts[i], &e->acts[j],
					   sizeof(struct ice_flow_action))) {
					found_not_match = true;
					break;
				}

			if (found_not_match) {
				*do_chg_action = true;
				break;
			}
		}

		/* (do_chg_action = true) means :
		 *    matching_data && priority && !result_action
		 * (do_chg_action = false) means :
		 *    matching_data && priority && result_action
		 */
		break;
	}

	return return_entry;
}

/**
 * ice_flow_acl_convert_to_acl_prior - Convert to ACL priority
 * @p: flow priority
 */
static enum ice_acl_entry_prior
ice_flow_acl_convert_to_acl_prior(enum ice_flow_priority p)
{
	enum ice_acl_entry_prior acl_prior;

	switch (p) {
	case ICE_FLOW_PRIO_LOW:
		acl_prior = ICE_LOW;
		break;
	case ICE_FLOW_PRIO_NORMAL:
		acl_prior = ICE_NORMAL;
		break;
	case ICE_FLOW_PRIO_HIGH:
		acl_prior = ICE_HIGH;
		break;
	default:
		acl_prior = ICE_NORMAL;
		break;
	}

	return acl_prior;
}

/**
 * ice_flow_acl_union_rng_chk - Perform union operation between two
 *                              range-range checker buffers
 * @dst_buf: pointer to destination range checker buffer
 * @src_buf: pointer to source range checker buffer
 *
 * For this function, we do the union between dst_buf and src_buf
 * range checker buffer, and we will save the result back to dst_buf
 */
static enum ice_status
ice_flow_acl_union_rng_chk(struct ice_aqc_acl_profile_ranges *dst_buf,
			   struct ice_aqc_acl_profile_ranges *src_buf)
{
	u8 i, j;

	if (!dst_buf || !src_buf)
		return ICE_ERR_BAD_PTR;

	for (i = 0; i < ICE_AQC_ACL_PROF_RANGES_NUM_CFG; i++) {
		struct ice_acl_rng_data *cfg_data = NULL, *in_data;
		bool will_populate = false;

		in_data = &src_buf->checker_cfg[i];

		if (!in_data->mask)
			break;

		for (j = 0; j < ICE_AQC_ACL_PROF_RANGES_NUM_CFG; j++) {
			cfg_data = &dst_buf->checker_cfg[j];

			if (!cfg_data->mask ||
			    !memcmp(cfg_data, in_data,
				    sizeof(struct ice_acl_rng_data))) {
				will_populate = true;
				break;
			}
		}

		if (will_populate) {
			memcpy(cfg_data, in_data,
			       sizeof(struct ice_acl_rng_data));
		} else {
			/* No available slot left to program range checker */
			return ICE_ERR_MAX_LIMIT;
		}
	}

	return 0;
}

/**
 * ice_flow_acl_add_scen_entry_sync - Add entry to ACL scenario sync
 * @hw: pointer to the hardware structure
 * @prof: pointer to flow profile
 * @entry: double pointer to the flow entry
 *
 * For this function, we will look at the current added entries in the
 * corresponding ACL scenario. Then, we will perform matching logic to
 * see if we want to add/modify/do nothing with this new entry.
 */
static enum ice_status
ice_flow_acl_add_scen_entry_sync(struct ice_hw *hw, struct ice_flow_prof *prof,
				 struct ice_flow_entry **entry)
{
	bool do_add_entry, do_rem_entry, do_chg_action, do_chg_rng_chk;
	struct ice_aqc_acl_profile_ranges query_rng_buf, cfg_rng_buf;
	struct ice_acl_act_entry *acts = NULL;
	struct ice_flow_entry *exist_entry;
	struct ice_flow_entry *e;
	enum ice_status status;
	u8 i;

	if (!entry || !(*entry) || !prof)
		return ICE_ERR_BAD_PTR;

	e = *(entry);

	/* Query the current range-checker value in FW with this profile ID */
	status = ice_query_acl_prof_ranges(hw, prof->id, &query_rng_buf, NULL);
	if (status)
		return status;
	memcpy(&cfg_rng_buf, &query_rng_buf,
	       sizeof(struct ice_aqc_acl_profile_ranges));

	/* Generate the new range-checker value */
	status = ice_flow_acl_union_rng_chk(&cfg_rng_buf, e->range_buf);
	if (status)
		return status;

	/* Reconfigure the range check if the buffer is changed. */
	do_chg_rng_chk = false;
	if (memcmp(&query_rng_buf, &cfg_rng_buf,
		   sizeof(struct ice_aqc_acl_profile_ranges))) {
		status = ice_prog_acl_prof_ranges(hw, prof->id, &cfg_rng_buf,
						  NULL);
		if (status)
			return status;

		do_chg_rng_chk = true;
	}

	/* Figure out if we want to (change the ACL action) and/or
	 * (Add the new ACL entry) and/or (Remove the current ACL entry)
	 */
	exist_entry = ice_flow_acl_find_scen_entry_cond
		(prof, e, &do_chg_action, &do_add_entry, &do_rem_entry);

	if (do_rem_entry) {
		status = ice_acl_rem_entry(hw, prof->cfg.scen,
					   exist_entry->scen_entry_idx);
		if (status)
			return status;

		status = ice_flow_rem_entry_sync(hw, exist_entry);
		if (status)
			return status;
	}

	/* Prepare the result action buffer */
	acts = devm_kcalloc(ice_hw_to_dev(hw), e->entry_sz,
			    sizeof(struct ice_acl_act_entry), GFP_KERNEL);
	for (i = 0; i < e->acts_cnt; i++)
		memcpy(&acts[i], &e->acts[i].data.acl_act,
		       sizeof(struct ice_acl_act_entry));

	if (do_add_entry) {
		enum ice_acl_entry_prior prior;
		u8 *keys, *inverts;
		u16 entry_idx;

		keys = (u8 *)e->entry;
		inverts = keys + (e->entry_sz / 2);
		prior = ice_flow_acl_convert_to_acl_prior(e->priority);

		status = ice_acl_add_entry
			(hw, prof->cfg.scen, prior, keys, inverts,
			 acts, e->acts_cnt, &entry_idx);
		if (status)
			goto out;

		e->scen_entry_idx = entry_idx;
		list_add(&e->l_entry, &prof->entries);
	} else {
		if (do_chg_action) {
			/* For the action memory info, update the SW's copy of
			 * exist_entry with e's action memory info
			 */
			devm_kfree(ice_hw_to_dev(hw), exist_entry->acts);
			exist_entry->acts_cnt = e->acts_cnt;
			exist_entry->acts = devm_kcalloc(ice_hw_to_dev(hw),
							 exist_entry->acts_cnt,
							 sizeof(struct ice_flow_action),
							 GFP_KERNEL);

			if (!exist_entry->acts) {
				status = ICE_ERR_NO_MEMORY;
				goto out;
			}

			memcpy(exist_entry->acts, e->acts,
			       sizeof(struct ice_flow_action) * e->acts_cnt);

			status = ice_acl_prog_act(hw, prof->cfg.scen, acts,
						  e->acts_cnt,
						  exist_entry->scen_entry_idx);
			if (status)
				goto out;
		}

		if (do_chg_rng_chk) {
			/* In this case, we want to update the range checker
			 * information of the exist_entry
			 */
			status = ice_flow_acl_union_rng_chk
				(exist_entry->range_buf, e->range_buf);
			if (status)
				goto out;
		}

		/* As we don't add the new entry to our SW DB, deallocate its
		 * memories, and return the exist_entry to the caller
		 */
		ice_dealloc_flow_entry(hw, e);
		*(entry) = exist_entry;
	}
out:
	if (acts)
		devm_kfree(ice_hw_to_dev(hw), acts);

	return status;
}

/**
 * ice_flow_acl_add_scen_entry - Add entry to ACL scenario
 * @hw: pointer to the hardware structure
 * @prof: pointer to flow profile
 * @e: double pointer to the flow entry
 */
static enum ice_status
ice_flow_acl_add_scen_entry(struct ice_hw *hw, struct ice_flow_prof *prof,
			    struct ice_flow_entry **e)
{
	enum ice_status status;

	mutex_lock(&prof->entries_lock);
	status = ice_flow_acl_add_scen_entry_sync(hw, prof, e);
	mutex_unlock(&prof->entries_lock);

	return status;
}

/**
 * ice_flow_add_entry - Add a flow entry
 * @hw: pointer to the HW struct
 * @blk: classification stage
 * @prof_id: ID of the profile to add a new flow entry to
 * @entry_id: unique ID to identify this flow entry
 * @vsi_handle: software VSI handle for the flow entry
 * @prio: priority of the flow entry
 * @data: pointer to a data buffer containing flow entry's match values/masks
 * @acts: arrays of actions to be performed on a match
 * @acts_cnt: number of actions
 * @entry_h: pointer to buffer that receives the new flow entry's handle
 */
enum ice_status
ice_flow_add_entry(struct ice_hw *hw, enum ice_block blk, u64 prof_id,
		   u64 entry_id, u16 vsi_handle, enum ice_flow_priority prio,
		   void *data, struct ice_flow_action *acts, u8 acts_cnt,
		   u64 *entry_h)
{
	struct ice_flow_prof *prof = NULL;
	struct ice_flow_entry *e = NULL;
	enum ice_status status = 0;

	if (acts_cnt && !acts)
		return ICE_ERR_PARAM;


	/* No flow entry data is expected for RSS */
	if (!entry_h || (!data && blk != ICE_BLK_RSS))
		return ICE_ERR_BAD_PTR;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&hw->fl_profs_locks[blk]);

	prof = ice_flow_find_prof_id(hw, blk, prof_id);
	if (!prof) {
		status = ICE_ERR_DOES_NOT_EXIST;
	} else {
		/* Allocate memory for the entry being added and associate
		 * the VSI to the found flow profile
		 */
		e = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*e), GFP_KERNEL);
		if (!e)
			status = ICE_ERR_NO_MEMORY;
		else
			status = ice_flow_assoc_prof(hw, blk, prof, vsi_handle);
	}

	mutex_unlock(&hw->fl_profs_locks[blk]);
	if (status)
		goto out;

	e->id = entry_id;
	e->vsi_handle = vsi_handle;
	e->prof = prof;
	e->priority = prio;

	switch (blk) {
	case ICE_BLK_RSS:
		/* RSS will add only one entry per VSI per profile */
		break;
	case ICE_BLK_ACL:
		/* ACL will handle the entry management */
		status = ice_flow_acl_frmt_entry(hw, prof, e, (u8 *)data, acts,
						 acts_cnt);
		if (status)
			goto out;

		status = ice_flow_acl_add_scen_entry(hw, prof, &e);
		if (status)
			goto out;

		break;
	case ICE_BLK_FD:
		break;
	case ICE_BLK_SW:
	case ICE_BLK_PE:
	default:
		status = ICE_ERR_NOT_IMPL;
		goto out;
	}

	if (blk != ICE_BLK_ACL) {
		/* ACL will handle the entry management */
		mutex_lock(&prof->entries_lock);
		list_add(&e->l_entry, &prof->entries);
		mutex_unlock(&prof->entries_lock);
	}

	*entry_h = ICE_FLOW_ENTRY_HNDL(e);

out:
	if (status && e) {
		if (e->entry)
			devm_kfree(ice_hw_to_dev(hw), e->entry);
		devm_kfree(ice_hw_to_dev(hw), e);
	}

	return status;
}

/**
 * ice_flow_rem_entry - Remove a flow entry
 * @hw: pointer to the HW struct
 * @entry_h: handle to the flow entry to be removed
 */
enum ice_status ice_flow_rem_entry(struct ice_hw *hw, u64 entry_h)
{
	struct ice_flow_entry *entry;
	struct ice_flow_prof *prof;
	enum ice_status status;

	if (entry_h == ICE_FLOW_ENTRY_HANDLE_INVAL)
		return ICE_ERR_PARAM;

	entry = ICE_FLOW_ENTRY_PTR(entry_h);

	/* Retain the pointer to the flow profile as the entry will be freed */
	prof = entry->prof;

	mutex_lock(&prof->entries_lock);
	status = ice_flow_rem_entry_sync(hw, entry);
	mutex_unlock(&prof->entries_lock);

	return status;
}

/**
 * ice_flow_set_fld_ext - specifies locations of field from entry's input buffer
 * @seg: packet segment the field being set belongs to
 * @fld: field to be set
 * @type: type of the field
 * @val_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of the value to match from
 *           entry's input buffer
 * @mask_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of mask value from entry's
 *            input buffer
 * @last_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of last/upper value from
 *            entry's input buffer
 *
 * This helper function stores information of a field being matched, including
 * the type of the field and the locations of the value to match, the mask, and
 * and the upper-bound value in the start of the input buffer for a flow entry.
 * This function should only be used for fixed-size data structures.
 *
 * This function also opportunistically determines the protocol headers to be
 * present based on the fields being set. Some fields cannot be used alone to
 * determine the protocol headers present. Sometimes, fields for particular
 * protocol headers are not matched. In those cases, the protocol headers
 * must be explicitly set.
 */
static void
ice_flow_set_fld_ext(struct ice_flow_seg_info *seg, enum ice_flow_field fld,
		     enum ice_flow_fld_match_type type, u16 val_loc,
		     u16 mask_loc, u16 last_loc)
{
	u64 bit = BIT_ULL(fld);

	seg->match |= bit;
	if (type == ICE_FLOW_FLD_TYPE_RANGE)
		seg->range |= bit;

	seg->fields[fld].type = type;
	seg->fields[fld].src.val = val_loc;
	seg->fields[fld].src.mask = mask_loc;
	seg->fields[fld].src.last = last_loc;

	ICE_FLOW_SET_HDRS(seg, ice_flds_info[fld].hdr);
}

/**
 * ice_flow_set_fld - specifies locations of field from entry's input buffer
 * @seg: packet segment the field being set belongs to
 * @fld: field to be set
 * @val_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of the value to match from
 *           entry's input buffer
 * @mask_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of mask value from entry's
 *            input buffer
 * @last_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of last/upper value from
 *            entry's input buffer
 * @range: indicate if field being matched is to be in a range
 *
 * This function specifies the locations, in the form of byte offsets from the
 * start of the input buffer for a flow entry, from where the value to match,
 * the mask value, and upper value can be extracted. These locations are then
 * stored in the flow profile. When adding a flow entry associated with the
 * flow profile, these locations will be used to quickly extract the values and
 * create the content of a match entry. This function should only be used for
 * fixed-size data structures.
 */
void
ice_flow_set_fld(struct ice_flow_seg_info *seg, enum ice_flow_field fld,
		 u16 val_loc, u16 mask_loc, u16 last_loc, bool range)
{
	enum ice_flow_fld_match_type t = range ?
		ICE_FLOW_FLD_TYPE_RANGE : ICE_FLOW_FLD_TYPE_REG;

	ice_flow_set_fld_ext(seg, fld, t, val_loc, mask_loc, last_loc);
}

/**
 * ice_flow_set_fld_prefix - sets locations of prefix field from entry's buf
 * @seg: packet segment the field being set belongs to
 * @fld: field to be set
 * @val_loc: if not ICE_FLOW_FLD_OFF_INVAL, location of the value to match from
 *           entry's input buffer
 * @pref_loc: location of prefix value from entry's input buffer
 * @pref_sz: size of the location holding the prefix value
 *
 * This function specifies the locations, in the form of byte offsets from the
 * start of the input buffer for a flow entry, from where the value to match
 * and the IPv4 prefix value can be extracted. These locations are then stored
 * in the flow profile. When adding flow entries to the associated flow profile,
 * these locations can be used to quickly extract the values to create the
 * content of a match entry. This function should only be used for fixed-size
 * data structures.
 */
void
ice_flow_set_fld_prefix(struct ice_flow_seg_info *seg, enum ice_flow_field fld,
			u16 val_loc, u16 pref_loc, u8 pref_sz)
{
	/* For this type of field, the "mask" location is for the prefix value's
	 * location and the "last" location is for the size of the location of
	 * the prefix value.
	 */
	ice_flow_set_fld_ext(seg, fld, ICE_FLOW_FLD_TYPE_PREFIX, val_loc,
			     pref_loc, (u16)pref_sz);
}

/**
 * ice_flow_add_fld_raw - sets locations of a raw field from entry's input buf
 * @seg: packet segment the field being set belongs to
 * @off: offset of the raw field from the beginning of the segment in bytes
 * @len: length of the raw pattern to be matched
 * @val_loc: location of the value to match from entry's input buffer
 * @mask_loc: location of mask value from entry's input buffer
 *
 * This function specifies the offset of the raw field to be match from the
 * beginning of the specified packet segment, and the locations, in the form of
 * byte offsets from the start of the input buffer for a flow entry, from where
 * the value to match and the mask value to be extracted. These locations are
 * then stored in the flow profile. When adding flow entries to the associated
 * flow profile, these locations can be used to quickly extract the values to
 * create the content of a match entry. This function should only be used for
 * fixed-size data structures.
 */
void
ice_flow_add_fld_raw(struct ice_flow_seg_info *seg, u16 off, u8 len,
		     u16 val_loc, u16 mask_loc)
{
	if (seg->raws_cnt < ICE_FLOW_SEG_RAW_FLD_MAX) {
		seg->raws[seg->raws_cnt].off = off;
		seg->raws[seg->raws_cnt].info.type = ICE_FLOW_FLD_TYPE_SIZE;
		seg->raws[seg->raws_cnt].info.src.val = val_loc;
		seg->raws[seg->raws_cnt].info.src.mask = mask_loc;
		/* The "last" field is used to store the length of the field */
		seg->raws[seg->raws_cnt].info.src.last = len;
	}

	/* Overflows of "raws" will be handled as an error condition later in
	 * the flow when this information is processed.
	 */
	seg->raws_cnt++;
}


#define ICE_FLOW_RSS_SEG_HDR_L3_MASKS \
	(ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV6)

#define ICE_FLOW_RSS_SEG_HDR_L4_MASKS \
	(ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_UDP | \
	 ICE_FLOW_SEG_HDR_SCTP)

#define ICE_FLOW_RSS_SEG_HDR_VAL_MASKS \
	(ICE_FLOW_RSS_SEG_HDR_L3_MASKS | \
	 ICE_FLOW_RSS_SEG_HDR_L4_MASKS)

/**
 * ice_flow_set_rss_seg_info - setup packet segments for RSS
 * @segs: pointer to the flow field segment(s)
 * @hash_fields: fields to be hashed on for the segment(s)
 * @flow_hdr: protocol header fields within a packet segment
 *
 * Helper function to extract fields from hash bitmap and use flow
 * header value to set flow field segment for further use in flow
 * profile entry or removal.
 */
static enum ice_status
ice_flow_set_rss_seg_info(struct ice_flow_seg_info *segs, u64 hash_fields,
			  u32 flow_hdr)
{
	u64 val = hash_fields;
	u8 i;

	for (i = 0; val && i < ICE_FLOW_FIELD_IDX_MAX; i++) {
		u64 bit = BIT_ULL(i);

		if (val & bit) {
			ice_flow_set_fld(segs, (enum ice_flow_field)i,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL,
					 ICE_FLOW_FLD_OFF_INVAL, false);
			val &= ~bit;
		}
	}
	ICE_FLOW_SET_HDRS(segs, flow_hdr);

	if (segs->hdrs & ~ICE_FLOW_RSS_SEG_HDR_VAL_MASKS)
		return ICE_ERR_PARAM;

	val = (u64)(segs->hdrs & ICE_FLOW_RSS_SEG_HDR_L3_MASKS);
	if (val && !is_power_of_2(val))
		return ICE_ERR_CFG;

	val = (u64)(segs->hdrs & ICE_FLOW_RSS_SEG_HDR_L4_MASKS);
	if (val && !is_power_of_2(val))
		return ICE_ERR_CFG;

	return 0;
}

/**
 * ice_rem_vsi_rss_list - remove VSI from RSS list
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 *
 * Remove the VSI from all RSS configurations in the list.
 */
void ice_rem_vsi_rss_list(struct ice_hw *hw, u16 vsi_handle)
{
	struct ice_rss_cfg *r, *tmp;

	if (list_empty(&hw->rss_list_head))
		return;

	mutex_lock(&hw->rss_locks);
	list_for_each_entry_safe(r, tmp, &hw->rss_list_head, l_entry) {
		if (test_bit(vsi_handle, r->vsis)) {
			clear_bit(vsi_handle, r->vsis);

			if (bitmap_empty(r->vsis, ICE_MAX_VSI)) {
				list_del(&r->l_entry);
				devm_kfree(ice_hw_to_dev(hw), r);
			}
		}
	}
	mutex_unlock(&hw->rss_locks);
}

/**
 * ice_rem_vsi_rss_cfg - remove RSS configurations associated with VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 *
 * This function will iterate through all flow profiles and disassociate
 * the VSI from that profile. If the flow profile has no VSIs it will
 * be removed.
 */
enum ice_status ice_rem_vsi_rss_cfg(struct ice_hw *hw, u16 vsi_handle)
{
	const enum ice_block blk = ICE_BLK_RSS;
	struct ice_flow_prof *p, *t;
	enum ice_status status = 0;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	if (list_empty(&hw->fl_profs[blk]))
		return 0;

	mutex_lock(&hw->fl_profs_locks[blk]);
	list_for_each_entry_safe(p, t, &hw->fl_profs[blk], l_entry) {
		if (test_bit(vsi_handle, p->vsis)) {
			status = ice_flow_disassoc_prof(hw, blk, p, vsi_handle);
			if (status)
				break;

			if (bitmap_empty(p->vsis, ICE_MAX_VSI)) {
				status = ice_flow_rem_prof_sync(hw, blk, p);
				if (status)
					break;
			}
		}
	}
	mutex_unlock(&hw->fl_profs_locks[blk]);

	return status;
}

/**
 * ice_rem_rss_list - remove RSS configuration from list
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @prof: pointer to flow profile
 *
 * Assumption: lock has already been acquired for RSS list
 */
static void
ice_rem_rss_list(struct ice_hw *hw, u16 vsi_handle, struct ice_flow_prof *prof)
{
	struct ice_rss_cfg *r, *tmp;

	/* Search for RSS hash fields associated to the VSI that match the
	 * hash configurations associated to the flow profile. If found
	 * remove from the RSS entry list of the VSI context and delete entry.
	 */
	list_for_each_entry_safe(r, tmp, &hw->rss_list_head, l_entry) {
		if (r->hashed_flds == prof->segs[prof->segs_cnt - 1].match &&
		    r->packet_hdr == prof->segs[prof->segs_cnt - 1].hdrs) {
			clear_bit(vsi_handle, r->vsis);
			if (bitmap_empty(r->vsis, ICE_MAX_VSI)) {
				list_del(&r->l_entry);
				devm_kfree(ice_hw_to_dev(hw), r);
			}
			return;
		}
	}
}

/**
 * ice_add_rss_list - add RSS configuration to list
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @prof: pointer to flow profile
 *
 * Assumption: lock has already been acquired for RSS list
 */
static enum ice_status
ice_add_rss_list(struct ice_hw *hw, u16 vsi_handle, struct ice_flow_prof *prof)
{
	struct ice_rss_cfg *r, *rss_cfg;

	list_for_each_entry(r, &hw->rss_list_head, l_entry)
		if (r->hashed_flds == prof->segs[prof->segs_cnt - 1].match &&
		    r->packet_hdr == prof->segs[prof->segs_cnt - 1].hdrs) {
			set_bit(vsi_handle, r->vsis);
			return 0;
		}

	rss_cfg = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*rss_cfg),
			       GFP_KERNEL);
	if (!rss_cfg)
		return ICE_ERR_NO_MEMORY;

	rss_cfg->hashed_flds = prof->segs[prof->segs_cnt - 1].match;
	rss_cfg->packet_hdr = prof->segs[prof->segs_cnt - 1].hdrs;
	set_bit(vsi_handle, rss_cfg->vsis);

	list_add_tail(&rss_cfg->l_entry, &hw->rss_list_head);

	return 0;
}

#define ICE_FLOW_PROF_HASH_S	0
#define ICE_FLOW_PROF_HASH_M	(0xFFFFFFFFULL << ICE_FLOW_PROF_HASH_S)
#define ICE_FLOW_PROF_HDR_S	32
#define ICE_FLOW_PROF_HDR_M	(0x3FFFFFFFULL << ICE_FLOW_PROF_HDR_S)
#define ICE_FLOW_PROF_ENCAP_S	63
#define ICE_FLOW_PROF_ENCAP_M	(BIT_ULL(ICE_FLOW_PROF_ENCAP_S))

#define ICE_RSS_OUTER_HEADERS	1
#define ICE_RSS_INNER_HEADERS	2

/* Flow profile ID format:
 * [0:31] - Packet match fields
 * [32:62] - Protocol header
 * [63] - Encapsulation flag, 0 if non-tunneled, 1 if tunneled
 */
#define ICE_FLOW_GEN_PROFID(hash, hdr, segs_cnt) \
	(u64)(((u64)(hash) & ICE_FLOW_PROF_HASH_M) | \
	      (((u64)(hdr) << ICE_FLOW_PROF_HDR_S) & ICE_FLOW_PROF_HDR_M) | \
	      ((u8)((segs_cnt) - 1) ? ICE_FLOW_PROF_ENCAP_M : 0))


/**
 * ice_add_rss_cfg_sync - add an RSS configuration
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @hashed_flds: hash bit fields (ICE_FLOW_HASH_*) to configure
 * @addl_hdrs: protocol header fields
 * @segs_cnt: packet segment count
 *
 * Assumption: lock has already been acquired for RSS list
 */
static enum ice_status
ice_add_rss_cfg_sync(struct ice_hw *hw, u16 vsi_handle, u64 hashed_flds,
		     u32 addl_hdrs, u8 segs_cnt)
{
	const enum ice_block blk = ICE_BLK_RSS;
	struct ice_flow_prof *prof = NULL;
	struct ice_flow_seg_info *segs;
	enum ice_status status = 0;

	if (!segs_cnt || segs_cnt > ICE_FLOW_SEG_MAX)
		return ICE_ERR_PARAM;

	segs = devm_kcalloc(ice_hw_to_dev(hw), segs_cnt, sizeof(*segs),
			    GFP_KERNEL);
	if (!segs)
		return ICE_ERR_NO_MEMORY;

	/* Construct the packet segment info from the hashed fields */
	status = ice_flow_set_rss_seg_info(&segs[segs_cnt - 1], hashed_flds,
					   addl_hdrs);
	if (status)
		goto exit;

	/* Search for a flow profile that has matching headers, hash fields
	 * and has the input VSI associated to it. If found, no further
	 * operations required and exit.
	 */
	prof = ice_flow_find_prof_conds(hw, blk, ICE_FLOW_RX, segs, segs_cnt,
					vsi_handle,
					ICE_FLOW_FIND_PROF_CHK_FLDS |
					ICE_FLOW_FIND_PROF_CHK_VSI);
	if (prof)
		goto exit;

	/* Check if a flow profile exists with the same protocol headers and
	 * associated with the input VSI. If so disasscociate the VSI from
	 * this profile. The VSI will be added to a new profile created with
	 * the protocol header and new hash field configuration.
	 */
	prof = ice_flow_find_prof_conds(hw, blk, ICE_FLOW_RX, segs, segs_cnt,
					vsi_handle, ICE_FLOW_FIND_PROF_CHK_VSI);
	if (prof) {
		status = ice_flow_disassoc_prof(hw, blk, prof, vsi_handle);
		if (!status)
			ice_rem_rss_list(hw, vsi_handle, prof);
		else
			goto exit;

		/* Remove profile if it has no VSIs associated */
		if (bitmap_empty(prof->vsis, ICE_MAX_VSI)) {
			status = ice_flow_rem_prof(hw, blk, prof->id);
			if (status)
				goto exit;
		}
	}

	/* Search for a profile that has same match fields only. If this
	 * exists then associate the VSI to this profile.
	 */
	prof = ice_flow_find_prof_conds(hw, blk, ICE_FLOW_RX, segs, segs_cnt,
					vsi_handle,
					ICE_FLOW_FIND_PROF_CHK_FLDS);
	if (prof) {
		status = ice_flow_assoc_prof(hw, blk, prof, vsi_handle);
		if (!status)
			status = ice_add_rss_list(hw, vsi_handle, prof);
		goto exit;
	}

	/* Create a new flow profile with generated profile and packet
	 * segment information.
	 */
	status = ice_flow_add_prof(hw, blk, ICE_FLOW_RX,
				   ICE_FLOW_GEN_PROFID(hashed_flds,
						       segs[segs_cnt - 1].hdrs,
						       segs_cnt),
				   segs, segs_cnt, NULL, 0, &prof);
	if (status)
		goto exit;

	status = ice_flow_assoc_prof(hw, blk, prof, vsi_handle);
	/* If association to a new flow profile failed then this profile can
	 * be removed.
	 */
	if (status) {
		ice_flow_rem_prof(hw, blk, prof->id);
		goto exit;
	}

	status = ice_add_rss_list(hw, vsi_handle, prof);


exit:
	devm_kfree(ice_hw_to_dev(hw), segs);
	return status;
}

/**
 * ice_add_rss_cfg - add an RSS configuration with specified hashed fields
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @hashed_flds: hash bit fields (ICE_FLOW_HASH_*) to configure
 * @addl_hdrs: protocol header fields
 *
 * This function will generate a flow profile based on fields associated with
 * the input fields to hash on, the flow type and use the VSI number to add
 * a flow entry to the profile.
 */
enum ice_status
ice_add_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u64 hashed_flds,
		u32 addl_hdrs)
{
	enum ice_status status;

	if (hashed_flds == ICE_HASH_INVALID ||
	    !ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&hw->rss_locks);
	status = ice_add_rss_cfg_sync(hw, vsi_handle, hashed_flds, addl_hdrs,
				      ICE_RSS_OUTER_HEADERS);
	if (!status)
		status = ice_add_rss_cfg_sync(hw, vsi_handle, hashed_flds,
					      addl_hdrs, ICE_RSS_INNER_HEADERS);
	mutex_unlock(&hw->rss_locks);

	return status;
}

/**
 * ice_rem_rss_cfg_sync - remove an existing RSS configuration
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @hashed_flds: Packet hash types (ICE_FLOW_HASH_*) to remove
 * @addl_hdrs: Protocol header fields within a packet segment
 * @segs_cnt: packet segment count
 *
 * Assumption: lock has already been acquired for RSS list
 */
static enum ice_status
ice_rem_rss_cfg_sync(struct ice_hw *hw, u16 vsi_handle, u64 hashed_flds,
		     u32 addl_hdrs, u8 segs_cnt)
{
	const enum ice_block blk = ICE_BLK_RSS;
	struct ice_flow_seg_info *segs;
	struct ice_flow_prof *prof;
	enum ice_status status;

	segs = devm_kcalloc(ice_hw_to_dev(hw), segs_cnt, sizeof(*segs),
			    GFP_KERNEL);
	if (!segs)
		return ICE_ERR_NO_MEMORY;

	/* Construct the packet segment info from the hashed fields */
	status = ice_flow_set_rss_seg_info(&segs[segs_cnt - 1], hashed_flds,
					   addl_hdrs);
	if (status)
		goto out;

	prof = ice_flow_find_prof_conds(hw, blk, ICE_FLOW_RX, segs, segs_cnt,
					vsi_handle,
					ICE_FLOW_FIND_PROF_CHK_FLDS);
	if (!prof) {
		status = ICE_ERR_DOES_NOT_EXIST;
		goto out;
	}

	status = ice_flow_disassoc_prof(hw, blk, prof, vsi_handle);
	if (status)
		goto out;

	/* Remove RSS configuration from VSI context before deleting
	 * the flow profile.
	 */
	ice_rem_rss_list(hw, vsi_handle, prof);

	if (bitmap_empty(prof->vsis, ICE_MAX_VSI))
		status = ice_flow_rem_prof(hw, blk, prof->id);

out:
	devm_kfree(ice_hw_to_dev(hw), segs);
	return status;
}

/**
 * ice_rem_rss_cfg - remove an existing RSS config with matching hashed fields
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @hashed_flds: Packet hash types (ICE_FLOW_HASH_*) to remove
 * @addl_hdrs: Protocol header fields within a packet segment
 *
 * This function will lookup the flow profile based on the input
 * hash field bitmap, iterate through the profile entry list of
 * that profile and find entry associated with input VSI to be
 * removed. Calls are made to underlying flow apis which will in
 * turn build or update buffers for RSS XLT1 section.
 */
enum ice_status
ice_rem_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u64 hashed_flds,
		u32 addl_hdrs)
{
	enum ice_status status;

	if (hashed_flds == ICE_HASH_INVALID ||
	    !ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&hw->rss_locks);
	status = ice_rem_rss_cfg_sync(hw, vsi_handle, hashed_flds, addl_hdrs,
				      ICE_RSS_OUTER_HEADERS);
	if (!status)
		status = ice_rem_rss_cfg_sync(hw, vsi_handle, hashed_flds,
					      addl_hdrs, ICE_RSS_INNER_HEADERS);
	mutex_unlock(&hw->rss_locks);

	return status;
}

/* Mapping of AVF hash bit fields to an L3-L4 hash combination.
 * As the ice_flow_avf_hdr_field represent individual bit shifts in a hash,
 * convert its values to their appropriate flow L3, L4 values.
 */
#define ICE_FLOW_AVF_RSS_IPV4_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_OTHER) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_FRAG_IPV4))
#define ICE_FLOW_AVF_RSS_TCP_IPV4_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_TCP_SYN_NO_ACK) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_TCP))
#define ICE_FLOW_AVF_RSS_UDP_IPV4_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_UNICAST_IPV4_UDP) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_MULTICAST_IPV4_UDP) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_UDP))
#define ICE_FLOW_AVF_RSS_ALL_IPV4_MASKS \
	(ICE_FLOW_AVF_RSS_TCP_IPV4_MASKS | ICE_FLOW_AVF_RSS_UDP_IPV4_MASKS | \
	 ICE_FLOW_AVF_RSS_IPV4_MASKS | BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_SCTP))

#define ICE_FLOW_AVF_RSS_IPV6_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_OTHER) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_FRAG_IPV6))
#define ICE_FLOW_AVF_RSS_UDP_IPV6_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_UNICAST_IPV6_UDP) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_MULTICAST_IPV6_UDP) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_UDP))
#define ICE_FLOW_AVF_RSS_TCP_IPV6_MASKS \
	(BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_TCP_SYN_NO_ACK) | \
	 BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_TCP))
#define ICE_FLOW_AVF_RSS_ALL_IPV6_MASKS \
	(ICE_FLOW_AVF_RSS_TCP_IPV6_MASKS | ICE_FLOW_AVF_RSS_UDP_IPV6_MASKS | \
	 ICE_FLOW_AVF_RSS_IPV6_MASKS | BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_SCTP))

#define ICE_FLOW_MAX_CFG	10

/**
 * ice_add_avf_rss_cfg - add an RSS configuration for AVF driver
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @avf_hash: hash bit fields (ICE_AVF_FLOW_FIELD_*) to configure
 *
 * This function will take the hash bitmap provided by the AVF driver via a
 * message, convert it to ICE-compatible values, and configure RSS flow
 * profiles.
 */
enum ice_status
ice_add_avf_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u64 avf_hash)
{
	enum ice_status status = 0;
	u64 hash_flds;

	if (avf_hash == ICE_AVF_FLOW_FIELD_INVALID ||
	    !ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	/* Make sure no unsupported bits are specified */
	if (avf_hash & ~(ICE_FLOW_AVF_RSS_ALL_IPV4_MASKS |
			 ICE_FLOW_AVF_RSS_ALL_IPV6_MASKS))
		return ICE_ERR_CFG;

	hash_flds = avf_hash;

	/* Always create an L3 RSS configuration for any L4 RSS configuration */
	if (hash_flds & ICE_FLOW_AVF_RSS_ALL_IPV4_MASKS)
		hash_flds |= ICE_FLOW_AVF_RSS_IPV4_MASKS;

	if (hash_flds & ICE_FLOW_AVF_RSS_ALL_IPV6_MASKS)
		hash_flds |= ICE_FLOW_AVF_RSS_IPV6_MASKS;

	/* Create the corresponding RSS configuration for each valid hash bit */
	while (hash_flds) {
		u64 rss_hash = ICE_HASH_INVALID;

		if (hash_flds & ICE_FLOW_AVF_RSS_ALL_IPV4_MASKS) {
			if (hash_flds & ICE_FLOW_AVF_RSS_IPV4_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV4;
				hash_flds &= ~ICE_FLOW_AVF_RSS_IPV4_MASKS;
			} else if (hash_flds &
				   ICE_FLOW_AVF_RSS_TCP_IPV4_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV4 |
					ICE_FLOW_HASH_TCP_PORT;
				hash_flds &= ~ICE_FLOW_AVF_RSS_TCP_IPV4_MASKS;
			} else if (hash_flds &
				   ICE_FLOW_AVF_RSS_UDP_IPV4_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV4 |
					ICE_FLOW_HASH_UDP_PORT;
				hash_flds &= ~ICE_FLOW_AVF_RSS_UDP_IPV4_MASKS;
			} else if (hash_flds &
				   BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_SCTP)) {
				rss_hash = ICE_FLOW_HASH_IPV4 |
					ICE_FLOW_HASH_SCTP_PORT;
				hash_flds &=
					~BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_SCTP);
			}
		} else if (hash_flds & ICE_FLOW_AVF_RSS_ALL_IPV6_MASKS) {
			if (hash_flds & ICE_FLOW_AVF_RSS_IPV6_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV6;
				hash_flds &= ~ICE_FLOW_AVF_RSS_IPV6_MASKS;
			} else if (hash_flds &
				   ICE_FLOW_AVF_RSS_TCP_IPV6_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV6 |
					ICE_FLOW_HASH_TCP_PORT;
				hash_flds &= ~ICE_FLOW_AVF_RSS_TCP_IPV6_MASKS;
			} else if (hash_flds &
				   ICE_FLOW_AVF_RSS_UDP_IPV6_MASKS) {
				rss_hash = ICE_FLOW_HASH_IPV6 |
					ICE_FLOW_HASH_UDP_PORT;
				hash_flds &= ~ICE_FLOW_AVF_RSS_UDP_IPV6_MASKS;
			} else if (hash_flds &
				   BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_SCTP)) {
				rss_hash = ICE_FLOW_HASH_IPV6 |
					ICE_FLOW_HASH_SCTP_PORT;
				hash_flds &=
					~BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_SCTP);
			}
		}

		if (rss_hash == ICE_HASH_INVALID)
			return ICE_ERR_OUT_OF_RANGE;

		status = ice_add_rss_cfg(hw, vsi_handle, rss_hash,
					 ICE_FLOW_SEG_HDR_NONE);
		if (status)
			break;
	}

	return status;
}

/**
 * ice_replay_rss_cfg - replay RSS configurations associated with VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 */
enum ice_status ice_replay_rss_cfg(struct ice_hw *hw, u16 vsi_handle)
{
	enum ice_status status = 0;
	struct ice_rss_cfg *r;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&hw->rss_locks);
	list_for_each_entry(r, &hw->rss_list_head, l_entry) {
		if (test_bit(vsi_handle, r->vsis)) {
			status = ice_add_rss_cfg_sync(hw, vsi_handle,
						      r->hashed_flds,
						      r->packet_hdr,
						      ICE_RSS_OUTER_HEADERS);
			if (status)
				break;
			status = ice_add_rss_cfg_sync(hw, vsi_handle,
						      r->hashed_flds,
						      r->packet_hdr,
						      ICE_RSS_INNER_HEADERS);
			if (status)
				break;
		}
	}
	mutex_unlock(&hw->rss_locks);

	return status;
}

/**
 * ice_get_rss_cfg - returns hashed fields for the given header types
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @hdrs: protocol header type
 *
 * This function will return the match fields of the first instance of flow
 * profile having the given header types and containing input VSI
 */
u64 ice_get_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u32 hdrs)
{
	struct ice_rss_cfg *r, *rss_cfg = NULL;

	/* verify if the protocol header is non zero and VSI is valid */
	if (hdrs == ICE_FLOW_SEG_HDR_NONE || !ice_is_vsi_valid(hw, vsi_handle))
		return ICE_HASH_INVALID;

	mutex_lock(&hw->rss_locks);
	list_for_each_entry(r, &hw->rss_list_head, l_entry)
		if (test_bit(vsi_handle, r->vsis) &&
		    r->packet_hdr == hdrs) {
			rss_cfg = r;
			break;
		}
	mutex_unlock(&hw->rss_locks);

	return rss_cfg ? rss_cfg->hashed_flds : ICE_HASH_INVALID;
}
