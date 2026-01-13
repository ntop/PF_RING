/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_TC_LIB_H_
#define _ICE_TC_LIB_H_

#ifdef HAVE_TC_SETUP_CLSFLOWER
#define ICE_TC_FLWR_FIELD_DST_MAC		BIT(0)
#define ICE_TC_FLWR_FIELD_SRC_MAC		BIT(1)
#define ICE_TC_FLWR_FIELD_VLAN			BIT(2)
#define ICE_TC_FLWR_FIELD_DEST_IPV4		BIT(3)
#define ICE_TC_FLWR_FIELD_SRC_IPV4		BIT(4)
#define ICE_TC_FLWR_FIELD_DEST_IPV6		BIT(5)
#define ICE_TC_FLWR_FIELD_SRC_IPV6		BIT(6)
#define ICE_TC_FLWR_FIELD_DEST_L4_PORT		BIT(7)
#define ICE_TC_FLWR_FIELD_SRC_L4_PORT		BIT(8)
#define ICE_TC_FLWR_FIELD_TENANT_ID		BIT(9)
#define ICE_TC_FLWR_FIELD_ENC_DEST_IPV4		BIT(10)
#define ICE_TC_FLWR_FIELD_ENC_SRC_IPV4		BIT(11)
#define ICE_TC_FLWR_FIELD_ENC_DEST_IPV6		BIT(12)
#define ICE_TC_FLWR_FIELD_ENC_SRC_IPV6		BIT(13)
#define ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT	BIT(14)
#define ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT	BIT(15)
#define ICE_TC_FLWR_FIELD_ENC_DST_MAC		BIT(16)
#define ICE_TC_FLWR_FIELD_ETH_TYPE_ID		BIT(17)
#ifdef HAVE_GTP_SUPPORT
#define ICE_TC_FLWR_FIELD_ENC_OPTS		BIT(18)
#endif /* HAVE_GTP_SUPPORT */
#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
#define ICE_TC_FLWR_FIELD_IP_TOS		BIT(19)
#define ICE_TC_FLWR_FIELD_IP_TTL		BIT(20)
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */
#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
#define ICE_TC_FLWR_FIELD_ENC_IP_TOS		BIT(21)
#define ICE_TC_FLWR_FIELD_ENC_IP_TTL		BIT(22)
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_IP */
#define ICE_TC_FLWR_FIELD_PPPOE_SESSID		BIT(23)
#define ICE_TC_FLWR_FIELD_PPP_PROTO		BIT(24)
#define ICE_TC_FLWR_FIELD_CVLAN			BIT(25)
#ifdef HAVE_FLOW_DISSECTOR_KEY_L2TPV3
#define ICE_TC_FLWR_FIELD_L2TPV3_SESSID		BIT(26)
#endif /* HAVE_FLOW_DISSECTOR_KEY_L2TPV3 */
#define ICE_TC_FLWR_FIELD_VLAN_PRIO		BIT(27)
#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
#define ICE_TC_FLWR_FIELD_CVLAN_PRIO		BIT(28)
#endif /* HAVE_FLOW_DISSECTOR_KEY_CVLAN  */

/* TC flower supported filter match */
#define ICE_TC_FLWR_FLTR_FLAGS_DST_MAC		ICE_TC_FLWR_FIELD_DST_MAC
#define ICE_TC_FLWR_FLTR_FLAGS_VLAN		ICE_TC_FLWR_FIELD_VLAN
#define ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN	(ICE_TC_FLWR_FIELD_DST_MAC | \
						 ICE_TC_FLWR_FIELD_VLAN)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV4_DST_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV4 | \
						 ICE_TC_FLWR_FIELD_DEST_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV4_SRC_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV4 | \
						 ICE_TC_FLWR_FIELD_SRC_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV6_DST_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV6 | \
						 ICE_TC_FLWR_FIELD_DEST_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV6_SRC_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV6 | \
						 ICE_TC_FLWR_FIELD_SRC_L4_PORT)

#define ICE_TC_FLOWER_MASK_32	0xFFFFFFFF
#define ICE_TC_FLOWER_MASK_16	0xFFFF
#define ICE_TC_FLOWER_VNI_MAX	0xFFFFFFU

#if defined(HAVE_FLOW_DISSECTOR_KEY_IP) || defined(HAVE_FLOW_DISSECTOR_KEY_ENC_IP)
#define ICE_IPV6_HDR_TC_OFFSET 20
#define ICE_IPV6_HDR_TC_MASK GENMASK(27, 20)
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP || HAVE_FLOW_DISSECTOR_KEY_ENC_IP */

#ifdef HAVE_TC_INDIR_BLOCK
struct ice_indr_block_priv {
	struct net_device *netdev;
	struct ice_netdev_priv *np;
	struct list_head list;
};
#endif /* HAVE_TC_INDIR_BLOCK */

struct ice_tc_flower_action {
	/* forward action specific params */
	union {
		struct {
			u32 tc_class; /* forward to hw_tc */
			u32 rsvd;
		} tc;
		struct {
			u32 queue; /* forward to queue */
			/* to add filter in HW, it needs absolute queue number
			 * in global space of queues (between 0...N)
			 */
			u32 hw_queue;
		} q;
	} fwd;
	enum ice_sw_fwd_act_type fltr_act;
};

struct ice_tc_vlan_hdr {
	__be16 vlan_id; /* Only last 12 bits valid */
	__be16 vlan_prio; /* Only first 3 bits valid (valid values: 0..7) */
#ifdef HAVE_TCF_VLAN_TPID
	__be16 vlan_tpid;
#endif /* HAVE_TCF_VLAN_TPID */
};

struct ice_tc_pppoe_hdr {
	__be16 session_id;
	__be16 ppp_proto;
};

struct ice_tc_l2_hdr {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 n_proto;    /* Ethernet Protocol */
};

struct ice_tc_l3_hdr {
	u8 ip_proto;    /* IPPROTO value */
	union {
		struct {
			struct in_addr dst_ip;
			struct in_addr src_ip;
		} v4;
		struct {
			struct in6_addr dst_ip6;
			struct in6_addr src_ip6;
		} v6;
	} ip;
#define dst_ipv6	ip.v6.dst_ip6.s6_addr32
#define dst_ipv6_addr	ip.v6.dst_ip6.s6_addr
#define src_ipv6	ip.v6.src_ip6.s6_addr32
#define src_ipv6_addr	ip.v6.src_ip6.s6_addr
#define dst_ipv4	ip.v4.dst_ip.s_addr
#define src_ipv4	ip.v4.src_ip.s_addr

	u8 tos;
	u8 ttl;
};

#ifdef HAVE_FLOW_DISSECTOR_KEY_L2TPV3
struct ice_tc_l2tpv3_hdr {
	__be32 session_id;
};
#endif /* HAVE_FLOW_DISSECTOR_KEY_L2TPV3 */

struct ice_tc_l4_hdr {
	__be16 dst_port;
	__be16 src_port;
};

struct ice_tc_flower_lyr_2_4_hdrs {
	/* L2 layer fields with their mask */
	struct ice_tc_l2_hdr l2_key;
	struct ice_tc_l2_hdr l2_mask;
	struct ice_tc_vlan_hdr vlan_hdr;
	struct ice_tc_vlan_hdr cvlan_hdr;
	struct ice_tc_pppoe_hdr pppoe_hdr;
#ifdef HAVE_FLOW_DISSECTOR_KEY_L2TPV3
	struct ice_tc_l2tpv3_hdr l2tpv3_hdr;
#endif /* HAVE_FLOW_DISSECTOR_KEY_L2TPV3 */
	/* L3 (IPv4[6]) layer fields with their mask */
	struct ice_tc_l3_hdr l3_key;
	struct ice_tc_l3_hdr l3_mask;

	/* L4 layer fields with their mask */
	struct ice_tc_l4_hdr l4_key;
	struct ice_tc_l4_hdr l4_mask;
};

enum ice_eswitch_fltr_direction {
	ICE_ESWITCH_FLTR_INGRESS,
	ICE_ESWITCH_FLTR_EGRESS,
};

struct ice_tc_flower_fltr {
	struct hlist_node tc_flower_node;

	/* cookie becomes filter_rule_id if rule is added successfully */
	unsigned long cookie;

	/* add_adv_rule returns information like recipe ID, rule_id. Store
	 * those values since they are needed to remove advanced rule
	 */
	u16 rid;
	u16 rule_id;
	/* VSI handle of the destination VSI (it could be main PF VSI, CHNL_VSI,
	 * VF VSI)
	 */
	u16 dest_vsi_handle;
	/* ptr to destination VSI */
	struct ice_vsi *dest_vsi;
	/* direction of fltr for eswitch use case */
	enum ice_eswitch_fltr_direction direction;

	/* Parsed TC flower configuration params */
	struct ice_tc_flower_lyr_2_4_hdrs outer_headers;
	struct ice_tc_flower_lyr_2_4_hdrs inner_headers;
	struct ice_vsi *src_vsi;
	__be32 tenant_id;
#ifdef HAVE_GTP_SUPPORT
	struct gtp_pdu_session_info gtp_pdu_info_keys;
	struct gtp_pdu_session_info gtp_pdu_info_masks;
#endif /* HAVE_GTP_SUPPORT */
	u32 flags;
#define ICE_TC_FLWR_TNL_TYPE_NONE        0xff
	u8 tunnel_type;
	struct ice_tc_flower_action	action;

	/* cache ptr which is used wherever needed to communicate netlink
	 * messages
	 */
	struct netlink_ext_ack *extack;
};

/**
 * ice_is_chnl_fltr - is this a valid channel filter
 * @f: Pointer to tc-flower filter
 *
 * Criteria to determine of given filter is valid channel filter
 * or not is based on its "destination".
 * For forward to VSI action, if destination is valid hw_tc (aka tc_class)
 * and in supported range of TCs for ADQ, then return true.
 * For forward to queue, as long as dest_vsi is valid and it is of type
 * VSI_CHNL (PF ADQ VSI is of type VSI_CHNL), return true.
 * NOTE: For forward to queue, correct dest_vsi is still set in tc_fltr based
 * on destination queue specified.
 */
static inline bool ice_is_chnl_fltr(struct ice_tc_flower_fltr *f)
{
	if (f->action.fltr_act == ICE_FWD_TO_VSI)
		return (f->action.fwd.tc.tc_class >= ICE_CHNL_START_TC &&
			f->action.fwd.tc.tc_class < ICE_CHNL_MAX_TC);
	else if (f->action.fltr_act == ICE_FWD_TO_Q)
		return (f->dest_vsi && f->dest_vsi->type == ICE_VSI_CHNL);

	return false;
}

/**
 * ice_chnl_dmac_fltr_cnt - DMAC based CHNL filter count
 * @pf: Pointer to PF
 */
static inline int ice_chnl_dmac_fltr_cnt(struct ice_pf *pf)
{
	return pf->num_dmac_chnl_fltrs;
}
int
ice_add_tc_flower_adv_fltr(struct ice_vsi *vsi,
			   struct ice_tc_flower_fltr *tc_fltr);
struct ice_vsi *
ice_locate_vsi_using_queue(struct ice_vsi *vsi, int queue);
#if defined(HAVE_TCF_MIRRED_DEV) || defined(HAVE_TC_FLOW_RULE_INFRASTRUCTURE)
int
ice_tc_tun_get_type(struct net_device *tunnel_dev,
		    struct flow_rule *rule);
#endif /* HAVE_TCF_MIRRED_DEC || HAVE_TC_FLOW_RULE_INFRASTRUCTURE */
int
#ifdef HAVE_TC_INDIR_BLOCK
ice_add_cls_flower(struct net_device *netdev, struct ice_vsi *vsi,
		   struct flow_cls_offload *cls_flower);
#else
ice_add_cls_flower(struct net_device __always_unused *netdev,
		   struct ice_vsi *vsi,
		   struct tc_cls_flower_offload *cls_flower);
#endif /* HAVE_TC_INDIR_BLOCK */
int
ice_del_cls_flower(struct ice_vsi *vsi, struct flow_cls_offload *cls_flower);
void ice_replay_tc_fltrs(struct ice_pf *pf);
#endif /* HAVE_TC_SETUP_CLSFLOWER */

#endif /* _ICE_TC_LIB_H_ */
