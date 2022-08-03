// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice.h"
#include "ice_tc_lib.h"
#include "ice_lib.h"
#include "ice_fltr.h"

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_determine_gtp_tun_type - determine TUN type based on user params
 * @pf: Pointer to PF
 * @l4_proto : vale of L4 protocol type
 * @flags: TC filter flags
 * @rule_info: Pointer to rule_info structure
 *
 * Determine TUN type based on user input. For VxLAN and Geneve, it is
 * straight forward. But to detect, correct TUN type for GTP is
 * challenging because there is no native support for GTP in kernel
 * and user may want to filter on
 *          Outer UDP + GTP (optional) + Inner L3 + Inner L4
 * Actual API to add advanced switch filter expects caller to detect
 * and specify correct TUN type and based on TUN type, appropriate
 * type of rule is added in HW.
 */
static bool
ice_determine_gtp_tun_type(struct ice_pf *pf, u16 l4_proto, u32 flags,
			   struct ice_adv_rule_info *rule_info)
{
	u8 outer_ipv6 = 0, inner_ipv6 = 0;
	u8 outer_ipv4 = 0, inner_ipv4 = 0;

	/* if user specified enc IPv6 src/dest/src+dest IP */
	if (flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
		     ICE_TC_FLWR_FIELD_ENC_SRC_IPV6))
		outer_ipv6 = 1;
	else if (flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV4))
		outer_ipv4 = 1;

	if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV6 |
		     ICE_TC_FLWR_FIELD_SRC_IPV6))
		inner_ipv6 = 1;
	else if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV4 |
			  ICE_TC_FLWR_FIELD_SRC_IPV4))
		inner_ipv4 = 1;
	else
		/* for GTP encap, specifying inner L3 is must at this point,
		 * inner L4 is optional
		 */
		return false;

	/* following block support various protocol combinations for GTP
	 * (at this pint we know that detected tunnel type is GTP based
	 * on outer UDP port (2152: GTP_U):
	 *     Outer IPv4 + Inner IPv4[6] + Inner TCP/UDP
	 *     Outer IPv4 + Inner IPv4[6]
	 *     Outer IPv6 + Inner IPv4[6] + Inner TCP/UDP
	 *     Outer IPv6 + Inner IPv4[6]
	 */
	if (!outer_ipv6 && !outer_ipv4) {
		if (inner_ipv4 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV4_TCP;
		else if (inner_ipv4 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV4_UDP;
		else if (inner_ipv6 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV6_TCP;
		else if (inner_ipv6 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV6_UDP;
		else if (inner_ipv4)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV4;
		else if (inner_ipv6)
			rule_info->tun_type = ICE_SW_TUN_GTP_IPV6;
		else
			/* no reason to proceed, error condition (must to
			 * specify inner L3 and/or inner L3 + inner L4)
			 */
			return false;
	} else if (outer_ipv4) {
		if (inner_ipv4 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTP_IPV4_TCP;
		else if (inner_ipv4 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTP_IPV4_UDP;
		else if (inner_ipv6 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTP_IPV6_TCP;
		else if (inner_ipv6 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTP_IPV6_UDP;
		else if (inner_ipv4)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTPU_IPV4;
		else if (inner_ipv6)
			rule_info->tun_type = ICE_SW_TUN_IPV4_GTPU_IPV6;
		else
			/* no reason to proceed, error condition (must to
			 * specify inner L3 and/or inner L3 + inner L4)
			 */
			return false;
	} else if (outer_ipv6) {
		if (inner_ipv4 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTP_IPV4_TCP;
		else if (inner_ipv4 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTP_IPV4_UDP;
		else if (inner_ipv6 && l4_proto == IPPROTO_TCP)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTP_IPV6_TCP;
		else if (inner_ipv6 && l4_proto == IPPROTO_UDP)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTP_IPV6_UDP;
		else if (inner_ipv4)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTPU_IPV4;
		else if (inner_ipv6)
			rule_info->tun_type = ICE_SW_TUN_IPV6_GTPU_IPV6;
		else
			/* no reason to proceed, error condition (must to
			 * specify inner L3 and/or inner L3 + inner L4)
			 */
			return false;
	}

	return true;
}

/**
 * ice_is_tunnel_fltr - is this a tunnel filter
 * @f: Pointer to tc-flower filter
 *
 * This function should be called only after tunnel_type
 * of the filter is set by calling ice_tc_tun_parse()
 */
static bool ice_is_tunnel_fltr(struct ice_tc_flower_fltr *f)
{
	return (f->tunnel_type == TNL_VXLAN ||
		f->tunnel_type == TNL_GENEVE ||
		f->tunnel_type == TNL_GTP);
}

/**
 * ice_tc_count_lkups - determine lookup count for switch filter
 * @flags: TC-flower flags
 * @headers: Pointer to TC flower filter header structure
 * @fltr: Pointer to outer TC filter structure
 *
 * Determine lookup count based on TC flower input for switch filter.
 */
static int
ice_tc_count_lkups(u32 flags, struct ice_tc_flower_lyr_2_4_hdrs *headers,
		   struct ice_tc_flower_fltr *fltr)
{
	int lkups_cnt = 0;

	if (ice_is_tunnel_fltr(fltr)) {
		/* For ADQ filter, outer DMAC gets added implicitly */
		if (flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC)
			lkups_cnt++;
		/* Copy outer L4 port for non-GTP tunnel */
		if (fltr->tunnel_type != TNL_GTP) {
			if (flags & ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT)
				if (headers->l3_key.ip_proto == IPPROTO_UDP)
					lkups_cnt++;
		}
		/* due to tunnel */
		if (fltr->tenant_id)
			lkups_cnt++;
	} else if (flags & ICE_TC_FLWR_FIELD_ETH_TYPE_ID) {
		lkups_cnt++;
	}

	/* is MAC fields specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DST_MAC | ICE_TC_FLWR_FIELD_SRC_MAC))
		lkups_cnt++;

	/* is VLAN specified? */
	if (flags & ICE_TC_FLWR_FIELD_VLAN)
		lkups_cnt++;

	/* are IPv[4|6] fields specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV4 | ICE_TC_FLWR_FIELD_SRC_IPV4))
		lkups_cnt++;
	else if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV6 |
			  ICE_TC_FLWR_FIELD_SRC_IPV6))
		lkups_cnt++;

	/* is L4 (TCP/UDP/any other L4 protocol fields) specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_L4_PORT |
		     ICE_TC_FLWR_FIELD_SRC_L4_PORT))
		lkups_cnt++;

	return lkups_cnt;
}

/**
 * ice_tc_fill_rules - fill filter rules based on TC fltr
 * @hw: pointer to HW structure
 * @flags: TC flower field flags
 * @tc_fltr: pointer to TC flower filter
 * @list: list of advance rule elements
 * @rule_info: pointer to information about rule
 * @l4_proto: pointer to information such as L4 proto type
 *
 * Fill ice_adv_lkup_elem list based on TC flower flags and
 * TC flower headers. This list should be used to add
 * advance filter in hardware.
 */
static int
ice_tc_fill_rules(struct ice_hw *hw, u32 flags,
		  struct ice_tc_flower_fltr *tc_fltr,
		  struct ice_adv_lkup_elem *list,
		  struct ice_adv_rule_info *rule_info,
		  u16 *l4_proto)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	int i = 0;

	/* copy L2 (MAC) fields, Outer UDP (in case of tunnel) port info */
	if (ice_is_tunnel_fltr(tc_fltr)) {
		__be32 tenant_id = tc_fltr->tenant_id;

		/* copy L2 (MAC) fields if specified, For tunnel outer DMAC
		 * is needed and supported and is part of outer_headers.dst_mac
		 * For VxLAN tunnel, supported ADQ filter config is:
		 * - Outer dest MAC + VNI + Inner IPv4 + Inner L4 ports
		 */
		if (flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC) {
			list[i].type = ICE_MAC_OFOS;
			ether_addr_copy(list[i].h_u.eth_hdr.dst_addr,
					headers->l2_key.dst_mac);
			ether_addr_copy(list[i].m_u.eth_hdr.dst_addr,
					headers->l2_mask.dst_mac);
			i++;
		}
		/* copy outer UDP (enc_dst_port) only for non-GTP tunnel */
		if (tc_fltr->tunnel_type != TNL_GTP) {
			if ((flags & ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT) &&
			    headers->l3_key.ip_proto == IPPROTO_UDP) {
				list[i].type = ICE_UDP_OF;
				list[i].h_u.l4_hdr.dst_port =
					headers->l4_key.dst_port;
				list[i].m_u.l4_hdr.dst_port =
					headers->l4_mask.dst_port;
				i++;
			}
		}
		if (tenant_id) {
			/* setup encap info in list elements such as
			 * VNI/encap key-id, mask, type of tunnel
			 */
			if (tc_fltr->tunnel_type == TNL_VXLAN)
				list[i].type = ICE_VXLAN;
			else if (tc_fltr->tunnel_type == TNL_GENEVE)
				list[i].type = ICE_GENEVE;
			else if (tc_fltr->tunnel_type == TNL_GTP)
				list[i].type = ICE_GTP;

			if (tc_fltr->tunnel_type == TNL_VXLAN ||
			    tc_fltr->tunnel_type == TNL_GENEVE) {
				u32 vni = be32_to_cpu(tenant_id) << 8;

				list[i].h_u.tnl_hdr.vni = cpu_to_be32(vni);
				/* 24bit tunnel key mask "\xff\xff\xff\x00" */
				memcpy(&list[i].m_u.tnl_hdr.vni,
				       "\xff\xff\xff\x00", 4);
			} else if (tc_fltr->tunnel_type == TNL_GTP) {
				list[i].h_u.gtp_hdr.teid = tenant_id;
				/* 32bit tunnel key mask "\xff\xff\xff\xff" */
				memcpy(&list[i].m_u.gtp_hdr.teid,
				       "\xff\xff\xff\xff", 4);
			}
			/* advance list index */
			i++;
		}

		/* now access values from inner_headers such as inner MAC (if
		 * supported), inner IPv4[6], Inner L4 ports, hence update
		 * "headers" to point to inner_headers
		 */
		headers = &tc_fltr->inner_headers;
	} else {
		rule_info->tun_type = ICE_NON_TUN;

		if (flags & ICE_TC_FLWR_FIELD_ETH_TYPE_ID) {
			list[i].type = ICE_ETYPE_OL;
			list[i].h_u.ethertype.ethtype_id =
					headers->l2_key.n_proto;
			list[i].m_u.ethertype.ethtype_id =
					headers->l2_mask.n_proto;
			i++;
		}

		/* copy L2 (MAC) fields, for non-tunnel case */
		if (flags & (ICE_TC_FLWR_FIELD_DST_MAC |
			     ICE_TC_FLWR_FIELD_SRC_MAC)) {
			struct ice_tc_l2_hdr *l2_key, *l2_mask;

			l2_key = &headers->l2_key;
			l2_mask = &headers->l2_mask;

			list[i].type = ICE_MAC_OFOS;
			if (flags & ICE_TC_FLWR_FIELD_DST_MAC) {
				ether_addr_copy(list[i].h_u.eth_hdr.dst_addr,
						l2_key->dst_mac);
				ether_addr_copy(list[i].m_u.eth_hdr.dst_addr,
						l2_mask->dst_mac);
			}
			if (flags & ICE_TC_FLWR_FIELD_SRC_MAC) {
				ether_addr_copy(list[i].h_u.eth_hdr.src_addr,
						l2_key->src_mac);
				ether_addr_copy(list[i].m_u.eth_hdr.src_addr,
						l2_mask->src_mac);
			}
			i++;
		}
	}

	/* copy VLAN info */
	if (flags & ICE_TC_FLWR_FIELD_VLAN) {
		list[i].type = ICE_VLAN_OFOS;
		list[i].h_u.vlan_hdr.vlan = headers->vlan_hdr.vlan_id;
		list[i].m_u.vlan_hdr.vlan = cpu_to_be16(0xFFFF);
		i++;
	}

	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV4 |
		     ICE_TC_FLWR_FIELD_SRC_IPV4)) {
		struct ice_tc_l3_hdr *l3_key, *l3_mask;

		/* For encap, Outer L3 and L4 based are not supported,
		 * hence if user specified L3, L4 fields, they are treated
		 * as inner L3 and L4 respectively
		 */
		if (ice_is_tunnel_fltr(tc_fltr))
			list[i].type = ICE_IPV4_IL;
		else
			list[i].type = ICE_IPV4_OFOS;

		l3_key = &headers->l3_key;
		l3_mask = &headers->l3_mask;
		list[i].h_u.ipv4_hdr.protocol = l3_key->ip_proto;
		list[i].m_u.ipv4_hdr.protocol = l3_mask->ip_proto;

		if (flags & ICE_TC_FLWR_FIELD_DEST_IPV4) {
			list[i].h_u.ipv4_hdr.dst_addr = l3_key->dst_ipv4;
			list[i].m_u.ipv4_hdr.dst_addr = l3_mask->dst_ipv4;
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_IPV4) {
			list[i].h_u.ipv4_hdr.src_addr = l3_key->src_ipv4;
			list[i].m_u.ipv4_hdr.src_addr = l3_mask->src_ipv4;
		}
		i++;
	} else if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV6 |
			    ICE_TC_FLWR_FIELD_SRC_IPV6)) {
		struct ice_ipv6_hdr *ipv6_hdr, *ipv6_mask;
		struct ice_tc_l3_hdr *l3_key, *l3_mask;

		if (ice_is_tunnel_fltr(tc_fltr))
			list[i].type = ICE_IPV6_IL;
		else
			list[i].type = ICE_IPV6_OFOS;
		ipv6_hdr = &list[i].h_u.ipv6_hdr;
		ipv6_mask = &list[i].m_u.ipv6_hdr;
		l3_key = &headers->l3_key;
		l3_mask = &headers->l3_mask;

		if (flags & ICE_TC_FLWR_FIELD_DEST_IPV6) {
			memcpy(&ipv6_hdr->dst_addr, &l3_key->dst_ipv6_addr,
			       sizeof(l3_key->dst_ipv6_addr));
			memcpy(&ipv6_mask->dst_addr, &l3_mask->dst_ipv6_addr,
			       sizeof(l3_mask->dst_ipv6_addr));
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_IPV6) {
			memcpy(&ipv6_hdr->src_addr, &l3_key->src_ipv6_addr,
			       sizeof(l3_key->src_ipv6_addr));
			memcpy(&ipv6_mask->src_addr, &l3_mask->src_ipv6_addr,
			       sizeof(l3_mask->src_ipv6_addr));
		}
		i++;
	}

	/* copy L4 (src, dest) port */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_L4_PORT |
		     ICE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		struct ice_tc_l4_hdr *l4_key, *l4_mask;
		u16 dst_port;

		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;
		dst_port = be16_to_cpu(l4_key->dst_port);
		if (headers->l3_key.ip_proto == IPPROTO_TCP) {
			list[i].type = ICE_TCP_IL;
			/* detected L4 proto is TCP */
			if (l4_proto)
				*l4_proto = IPPROTO_TCP;
		} else if (headers->l3_key.ip_proto == IPPROTO_UDP) {
			/* Check if UDP dst port is known as a tunnel port */
			if (ice_tunnel_port_in_use(hw, dst_port, NULL))
				list[i].type = ICE_UDP_OF;
			else
				list[i].type = ICE_UDP_ILOS;
			/* detected L4 proto is UDP */
			if (l4_proto)
				*l4_proto = IPPROTO_UDP;
		}
		if (flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT) {
			list[i].h_u.l4_hdr.dst_port = l4_key->dst_port;
			list[i].m_u.l4_hdr.dst_port = l4_mask->dst_port;
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT) {
			list[i].h_u.l4_hdr.src_port = l4_key->src_port;
			list[i].m_u.l4_hdr.src_port = l4_mask->src_port;
		}
		i++;
	}

	return i;
}

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
static int
ice_eswitch_tc_parse_action(struct ice_tc_flower_fltr *fltr,
			    struct flow_action_entry *act)
{
	struct ice_repr *repr;

	switch (act->id) {
	case FLOW_ACTION_DROP:
		fltr->action.fltr_act = ICE_DROP_PACKET;
		break;

	case FLOW_ACTION_REDIRECT:
		fltr->action.fltr_act = ICE_FWD_TO_VSI;

		if (ice_is_port_repr_netdev(act->dev)) {
			repr = ice_netdev_to_repr(act->dev);

			fltr->dest_vsi = repr->src_vsi;
			fltr->direction = ICE_ESWITCH_FLTR_INGRESS;
		} else if (netif_is_ice(act->dev)) {
			struct ice_netdev_priv *np = netdev_priv(act->dev);

			fltr->dest_vsi = np->vsi;
			fltr->direction = ICE_ESWITCH_FLTR_EGRESS;
		} else {
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported netdevice in switchdev mode");
			return -EINVAL;
		}

		break;

	default:
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported action in switchdev mode");
		return -EINVAL;
	}

	return 0;
}
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */

static int
ice_eswitch_add_tc_fltr(struct ice_vsi *vsi, struct ice_tc_flower_fltr *fltr)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &fltr->outer_headers;
	struct ice_adv_rule_info rule_info = { 0 };
	struct ice_rule_query_data rule_added;
	struct ice_hw *hw = &vsi->back->hw;
	struct ice_adv_lkup_elem *list;
	u32 flags = fltr->flags;
	enum ice_status status;
	int lkups_cnt;
	int ret = 0;
	int i;

	if (!flags || (flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT))) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported encap field(s)");
		return -EOPNOTSUPP;
	}

	lkups_cnt = ice_tc_count_lkups(flags, headers, fltr);
	list = kcalloc(lkups_cnt, sizeof(*list), GFP_ATOMIC);
	if (!list)
		return -ENOMEM;

	i = ice_tc_fill_rules(hw, flags, fltr, list, &rule_info, NULL);
	if (i != lkups_cnt) {
		ret = -EINVAL;
		goto exit;
	}

	rule_info.sw_act.fltr_act = fltr->action.fltr_act;
	if (fltr->action.fltr_act != ICE_DROP_PACKET)
		rule_info.sw_act.vsi_handle = fltr->dest_vsi->idx;
	/* For now, making priority to be highest, and it also becomes
	 * the priority for recipe which will get created as a result of
	 * new extraction sequence based on input set.
	 * Priority '7' is max val for switch recipe, higher the number
	 * results into order of switch rule evaluation.
	 */
	rule_info.priority = 7;

	if (fltr->direction == ICE_ESWITCH_FLTR_INGRESS) {
		rule_info.sw_act.flag |= ICE_FLTR_RX;
		rule_info.sw_act.src = hw->pf_id;
		rule_info.rx = true;
	} else {
		rule_info.sw_act.flag |= ICE_FLTR_TX;
		rule_info.sw_act.src = vsi->idx;
		rule_info.rx = false;
		rule_info.flags_info.act = ICE_SINGLE_ACT_LAN_ENABLE;
		rule_info.flags_info.act_valid = true;
	}

	/* specify the cookie as filter_rule_id */
	rule_info.fltr_rule_id = fltr->cookie;

	status = ice_add_adv_rule(hw, list, lkups_cnt, &rule_info, &rule_added);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add filter because it already exist");
		ret = -EINVAL;
		goto exit;
	} else if (status) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add filter due to error");
		ret = -EIO;
		goto exit;
	}

	/* store the output params, which are needed later for removing
	 * advanced switch filter
	 */
	fltr->rid = rule_added.rid;
	fltr->rule_id = rule_added.rule_id;
	fltr->dest_vsi_handle = rule_added.vsi_handle;

exit:
	kfree(list);
	return ret;
}

/**
 * ice_locate_vsi_using_queue - locate VSI using queue (forward to queue)
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to tc_flower_filter
 *
 * Locate the VSI using specified "queue" (which is part of tc_fltr). When ADQ
 * is not enabled, always return input VSI, otherwise locate corresponding
 * VSI based on per channel "offset" and "qcount"
 */
static struct ice_vsi *
ice_locate_vsi_using_queue(struct ice_vsi *vsi,
			   struct ice_tc_flower_fltr *tc_fltr)
{
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	int num_tc, tc;
	int queue;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	/* verify action is forward to queue */
	if (tc_fltr->action.fltr_act != ICE_FWD_TO_Q)
		return NULL;

	/* if ADQ is not active, passed VSI is the candidate VSI */
	if (!ice_is_adq_active(vsi->back))
		return vsi;

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	/* now locate the VSI (it could still be main PF VSI or CHNL_VSI
	 * depending upon "queue number")
	 */
	num_tc = vsi->mqprio_qopt.qopt.num_tc;
	queue = (int)tc_fltr->action.fwd.q.queue;

	for (tc = 0; tc < num_tc; tc++) {
		int qcount = vsi->mqprio_qopt.qopt.count[tc];
		int offset = vsi->mqprio_qopt.qopt.offset[tc];

		if (queue >= offset && (queue < offset + qcount)) {
			/* for non-ADQ TCs, passed VSI is the candidate VSI */
			if (tc < ICE_CHNL_START_TC)
				return vsi;
			else
				return vsi->tc_map_vsi[tc];
		}
	}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	return NULL;
}

static struct ice_ring *
ice_locate_rx_ring_using_queue(struct ice_vsi *vsi,
			       struct ice_tc_flower_fltr *tc_fltr)
{
	u32 queue = tc_fltr->action.fwd.q.queue;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	struct ice_vf *vf;
	int tc;

	dev = ice_pf_to_dev(pf);
	vf = vsi->vf;

	if (vsi->type != ICE_VSI_VF || vf->num_tc <= ICE_VF_CHNL_START_TC)
		return (queue < vsi->num_rxq) ? vsi->rx_rings[queue] : NULL;

	/* now locate the corresponding Rx rings */
	for (tc = 0; tc < vf->num_tc; tc++) {
		u16 num_qps, offset;

		offset = vf->ch[tc].offset;
		num_qps = vf->ch[tc].num_qps;

		if (queue >= offset &&
		    (queue < (offset + num_qps))) {
			struct ice_vsi *tc_vsi;

			tc_vsi = pf->vsi[vf->ch[tc].vsi_idx];
			if (!tc_vsi) {
				dev_err(dev, "VF %d: VF ADQ VSI is not valid\n",
					vf->vf_id);
				return NULL;
			}
			if ((queue - offset) >= vsi->num_rxq) {
				dev_err(dev, "VF %d: forward to queue (%u) not in range, offset:%u, num_qps %u, num_rxq      %u\n",
					vf->vf_id, queue, offset,
					num_qps, tc_vsi->num_rxq);
				return NULL;
			}
			return tc_vsi->rx_rings[queue - offset];
		}
	}
	return NULL;
}

/**
 * ice_tc_forward_action - Determine destination VSI and queue for the action
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 * @rx_ring: Pointer to ring ptr
 * @dest_vsi: Pointer to VSI ptr
 *
 * Validates the tc forward action and determines the destination VSI and queue
 * for the forward action.
 */
static int
ice_tc_forward_action(struct ice_vsi *vsi, struct ice_tc_flower_fltr *tc_fltr,
		      struct ice_ring **rx_ring, struct ice_vsi **dest_vsi)
{
	struct ice_channel_vf *vf_ch = NULL;
	struct ice_vsi *ch_vsi = NULL;
	struct ice_pf *pf = vsi->back;
	struct ice_ring *ring = NULL;
	struct ice_vf *vf = NULL;
	struct device *dev;
	u16 tc_class = 0;

	dev = ice_pf_to_dev(pf);
	*rx_ring = NULL;
	*dest_vsi = NULL;

	/* validate VSI types */
	if (vsi->type == ICE_VSI_VF) {
		vf = vsi->vf;
		if (!vf) {
			dev_err(dev, "VF is NULL for VF VSI, vsi_num %d\n",
				vsi->vsi_num);
			return -EINVAL;
		}
		if (!tc_fltr->dest_vsi) {
			dev_err(dev,
				"Needs valid destination VSI if main VSI type is ICE_VSI_VF\n");
			return -EINVAL;
		}
		if (tc_fltr->dest_vsi->type != ICE_VSI_VF) {
			dev_err(dev,
				"Unexpected destination VSI type when input VSI type is ICE_VSI_VF\n");
			return -EINVAL;
		}
	}

	/* Get the destination VSI and/or destination queue and validate them */
	tc_class = tc_fltr->action.fwd.tc.tc_class;
	if (tc_class && tc_fltr->action.fltr_act == ICE_FWD_TO_VSI) {
		/* Select the destination VSI */
		if (tc_class < ICE_CHNL_START_TC) {
			NL_SET_ERR_MSG_MOD(tc_fltr->extack,
					   "Unable to add filter because of unsupported destination");
			return -EOPNOTSUPP;
		}
		if (vsi->type == ICE_VSI_VF) {
			ch_vsi = tc_fltr->dest_vsi;
			/* For VF ADQ, locate channel based on tc_class */
			vf_ch = &vf->ch[tc_class];
			if (!vf_ch) {
				dev_err(dev, "Unable to add filter because TC specific param are invalid\n");
				return -EINVAL;
			}
		} else {
			/* Locate ADQ VSI depending on hw_tc number */
			ch_vsi = vsi->tc_map_vsi[tc_class];
		}
	} else if (tc_fltr->action.fltr_act == ICE_FWD_TO_Q) {
		/* Locate the Rx queue using "action.fwd.q.queue" */
		ring = ice_locate_rx_ring_using_queue(vsi, tc_fltr);
		if (!ring) {
			dev_err(dev,
				"Unable to locate Rx queue for action fwd_to_queue: %u\n",
				tc_fltr->action.fwd.q.queue);
			return -EINVAL;
		}
		/* Determine destination VSI even though forward action is
		 * FWD_TO_QUEUE, because QUEUE is associated with VSI
		 */
		if (vsi->type == ICE_VSI_VF) {
			ch_vsi = tc_fltr->dest_vsi;
			/* Locate channel which corresponds to TC0 */
			vf_ch = &vf->ch[0];
			if (!vf_ch) {
				dev_err(dev, "Unable to add filter because TC specific param are invalid\n");
				return -EINVAL;
			}
		} else {
			ch_vsi = ice_locate_vsi_using_queue(vsi, tc_fltr);
		}
	} else {
		dev_err(dev,
			"Unable to add filter because of unsupported action %u (supported actions: fwd to tc, fwd to queue)\n",
			tc_fltr->action.fltr_act);
		return -EINVAL;
	}

	/* Must have valid "ch_vsi" (it could be main VSI or ADQ VSI */
	if (!ch_vsi) {
		dev_err(dev,
			"Unable to add filter because specified destination VSI doesn't exist\n");
		return -EINVAL;
	}

	*rx_ring = ring;
	*dest_vsi = ch_vsi;
	return 0;
}

/**
 * ice_add_tc_flower_adv_fltr - add appropriate filter rules
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 *
 * based on filter parameters using Advance recipes supported
 * by OS package.
 */
int
ice_add_tc_flower_adv_fltr(struct ice_vsi *vsi,
			   struct ice_tc_flower_fltr *tc_fltr)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	struct ice_adv_rule_info rule_info = {0};
	struct ice_rule_query_data rule_added;
	struct ice_ring *rx_ring = NULL;
	struct ice_adv_lkup_elem *list;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	u32 flags = tc_fltr->flags;
	enum ice_status status;
	struct ice_vsi *ch_vsi;
	struct device *dev;
	u16 lkups_cnt = 0;
	u16 l4_proto = 0;
	int ret = 0;
	u16 i = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Unable to add filter because driver is in safe mode");
		return -EOPNOTSUPP;
	}

	if (!flags || (flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT))) {
		NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Unsupported encap field(s)");
		return -EOPNOTSUPP;
	}

	/* validate forwarding action VSI and queue */
	ret = ice_tc_forward_action(vsi, tc_fltr, &rx_ring, &ch_vsi);
	if (ret)
		return ret;

	lkups_cnt = ice_tc_count_lkups(flags, headers, tc_fltr);
	list = kcalloc(lkups_cnt, sizeof(*list), GFP_ATOMIC);
	if (!list)
		return -ENOMEM;

	i = ice_tc_fill_rules(hw, flags, tc_fltr, list, &rule_info, &l4_proto);
	if (i != lkups_cnt) {
		ret = -EINVAL;
		goto exit;
	}

	if (tc_fltr->tunnel_type == TNL_VXLAN)
		rule_info.tun_type = ICE_SW_TUN_VXLAN;
	else if (tc_fltr->tunnel_type == TNL_GENEVE)
		rule_info.tun_type = ICE_SW_TUN_GENEVE;

	/* Now determine correct TUN type of based on encap params */
	if ((flags & ICE_TC_FLWR_FIELD_TENANT_ID) &&
	    tc_fltr->tunnel_type == TNL_GTP) {
		if (!ice_determine_gtp_tun_type(pf, l4_proto, tc_fltr->flags,
						&rule_info)) {
			if (vsi->type == ICE_VSI_VF)
				dev_err(dev, "Unable to add filter because could not determine tun type, VSI %u, vf_id:%u\n",
					vsi->vsi_num, vsi->vf->vf_id);
			else
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Unable to add filter because could not determine TUN type. ");
			ret = -EINVAL;
			goto exit;
		}
	}

	rule_info.sw_act.fltr_act = tc_fltr->action.fltr_act;

	if (tc_fltr->action.fltr_act == ICE_FWD_TO_VSI) {
		rule_info.sw_act.fltr_act = ICE_FWD_TO_VSI;
		rule_info.sw_act.vsi_handle = ch_vsi->idx;
		rule_info.priority = ICE_SWITCH_FLTR_PRIO_VSI;

		rule_info.sw_act.src = hw->pf_id;
		rule_info.rx = true;

		dev_dbg(dev, "add switch rule for TC:%u vsi_idx:%u, lkups_cnt:%u\n",
			tc_fltr->action.fwd.tc.tc_class,
			rule_info.sw_act.vsi_handle, lkups_cnt);
	} else if (tc_fltr->action.fltr_act == ICE_FWD_TO_Q) {
		rule_info.sw_act.fltr_act = ICE_FWD_TO_Q;
		/* HW queue number in global space */
		rule_info.sw_act.fwd_id.q_id = tc_fltr->action.fwd.q.hw_queue;
		rule_info.sw_act.vsi_handle = ch_vsi->idx;
		rule_info.priority = ICE_SWITCH_FLTR_PRIO_QUEUE;
		rule_info.sw_act.src = hw->pf_id;
		rule_info.rx = true;
		dev_dbg(dev, "add switch rule action to forward to queue:%u (HW queue %u), lkups_cnt:%u\n",
			tc_fltr->action.fwd.q.queue,
			tc_fltr->action.fwd.q.hw_queue,
			lkups_cnt);
	} else {
		rule_info.sw_act.flag |= ICE_FLTR_TX;
		/* In case of Tx (LOOKUP_TX), src needs to be src VSI */
		rule_info.sw_act.src = ch_vsi->idx;
		/* 'Rx' is false, direction of rule(LOOKUPTRX) */
		rule_info.rx = false;
		rule_info.priority = ICE_SWITCH_FLTR_PRIO_VSI;
	}

	/* specify the cookie as filter_rule_id */
	rule_info.fltr_rule_id = tc_fltr->cookie;

	status = ice_add_adv_rule(hw, list, lkups_cnt, &rule_info, &rule_added);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Unable to add filter because it already exist");
		ret = -EINVAL;
		goto exit;
	} else if (status) {
		NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Unable to add filter due to error");
		ret = -EIO;
		goto exit;
	}

	/* store the output params, which are needed later for removing
	 * advanced switch filter
	 */
	tc_fltr->rid = rule_added.rid;
	tc_fltr->rule_id = rule_added.rule_id;
	if (tc_fltr->action.fltr_act == ICE_FWD_TO_VSI ||
	    tc_fltr->action.fltr_act == ICE_FWD_TO_Q) {
		tc_fltr->dest_vsi_handle = rule_added.vsi_handle;
		tc_fltr->dest_vsi = ch_vsi;
		/* keep track of advanced switch filter for
		 * destination VSI
		 */
		ch_vsi->num_chnl_fltr++;

		/* keeps track of channel filters for PF VSI */
		if (vsi->type == ICE_VSI_PF &&
		    (flags & (ICE_TC_FLWR_FIELD_DST_MAC |
			      ICE_TC_FLWR_FIELD_ENC_DST_MAC)))
			pf->num_dmac_chnl_fltrs++;
	}
	if (tc_fltr->action.fltr_act == ICE_FWD_TO_VSI) {
		dev_dbg(dev, "added switch rule (lkups_cnt %u, flags 0x%x) for TC %u, rid %u, rule_id %u, vsi_idx %u\n",
			lkups_cnt, flags,
			tc_fltr->action.fwd.tc.tc_class, rule_added.rid,
			rule_added.rule_id, rule_added.vsi_handle);
	} else if (tc_fltr->action.fltr_act == ICE_FWD_TO_Q) {
		dev_dbg(dev, "added switch rule (lkups_cnt %u, flags 0x%x), action is forward to queue: %u (HW queue %u)     , rid %u, rule_id %u\n",
			lkups_cnt, flags, tc_fltr->action.fwd.q.queue,
			tc_fltr->action.fwd.q.hw_queue, rule_added.rid,
			rule_added.rule_id);
	}
exit:
	kfree(list);
	return ret;
}

/**
 * ice_tc_set_ipv4 - Parse IPv4 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv4 address
 */
static int
ice_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	if (match->key->dst) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DEST_IPV4;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV4;
		headers->l3_key.dst_ipv4 = match->key->dst;
		headers->l3_mask.dst_ipv4 = match->mask->dst;
	}
	if (match->key->src) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_SRC_IPV4;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV4;
		headers->l3_key.src_ipv4 = match->key->src;
		headers->l3_mask.src_ipv4 = match->mask->src;
	}
	return 0;
}

/**
 * ice_tc_set_ipv6 - Parse IPv6 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv6 address
 */
static int
ice_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	struct ice_tc_l3_hdr *l3_key, *l3_mask;

	/* src and dest IPV6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1), which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match->key->dst) ||
	    ipv6_addr_loopback(&match->key->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Bad IPv6, addr is LOOPBACK");
		return -EINVAL;
	}
	/* if src/dest IPv6 address is *,* error */
	if (ipv6_addr_any(&match->mask->dst) &&
	    ipv6_addr_any(&match->mask->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Bad src/dest IPv6, addr is any");
		return -EINVAL;
	}
	if (!ipv6_addr_any(&match->mask->dst)) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DEST_IPV6;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV6;
	}
	if (!ipv6_addr_any(&match->mask->src)) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_SRC_IPV6;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV6;
	}

	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	if (fltr->flags & (ICE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
			   ICE_TC_FLWR_FIELD_SRC_IPV6)) {
		memcpy(&l3_key->src_ipv6_addr, &match->key->src.s6_addr,
		       sizeof(match->key->src.s6_addr));
		memcpy(&l3_mask->src_ipv6_addr, &match->mask->src.s6_addr,
		       sizeof(match->mask->src.s6_addr));
	}
	if (fltr->flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
			   ICE_TC_FLWR_FIELD_DEST_IPV6)) {
		memcpy(&l3_key->dst_ipv6_addr, &match->key->dst.s6_addr,
		       sizeof(match->key->dst.s6_addr));
		memcpy(&l3_mask->dst_ipv6_addr, &match->mask->dst.s6_addr,
		       sizeof(match->mask->dst.s6_addr));
	}

	return 0;
}

/**
 * ice_tc_set_port - Parse ports from TC flower filter
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel port
 */
static int
ice_tc_set_port(struct flow_match_ports match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	if (match.key->dst) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_L4_PORT;
		headers->l4_key.dst_port = match.key->dst;
		headers->l4_mask.dst_port = match.mask->dst;
	}
	if (match.key->src) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_L4_PORT;
		headers->l4_key.src_port = match.key->src;
		headers->l4_mask.src_port = match.mask->src;
	}
	return 0;
}

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
/**
 * ice_is_tnl_gtp - detect if tunnel type is GTP or not
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * If curr_tnl_type is TNL_LAST and "flow_rule" is non-NULL, then
 * check if enc_dst_port is well known GTP port (2152)
 * if so - return true (indicating that tunnel type is GTP), otherwise false.
 */
static bool
ice_is_tnl_gtp(struct net_device *tunnel_dev,
	       struct flow_rule *rule)
{
	/* if flow_rule is non-NULL, proceed with detecting possibility
	 * of GTP tunnel. Unlike VXLAN and GENEVE, there is no such API
	 * like  netif_is_gtp since GTP is not natively supported in kernel
	 */
	if (rule && (!is_vlan_dev(tunnel_dev))) {
		struct flow_match_ports match;
		u16 enc_dst_port;

		if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
			netdev_err(tunnel_dev,
				   "Tunnel HW offload is not supported, ENC_PORTs are not specified\n");
			return false;
		}

		/* get ENC_PORTS info */
		flow_rule_match_enc_ports(rule, &match);
		enc_dst_port = be16_to_cpu(match.key->dst);

		/* Outer UDP port is GTP well known port,
		 * if 'enc_dst_port' matched with GTP well known port,
		 * return true from this function.
		 */
		if (enc_dst_port != ICE_GTP_TNL_WELLKNOWN_PORT) {
			netdev_err(tunnel_dev,
				   "Tunnel HW offload is not supported for non-GTP tunnel, ENC_DST_PORT is %u\n",
				   enc_dst_port);
			return false;
		}

		/* all checks passed including outer UDP port to be qualified
		 * for GTP tunnel
		 */
		return true;
	}
	return false;
}

/**
 * ice_tc_tun_get_type - get the tunnel type
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * This function detects appropriate tunnel_type if specified device is
 * tunnel device such as vxlan/geneve othertwise it tries to detect
 * tunnel type based on outer GTP port (2152)
 */
int
ice_tc_tun_get_type(struct net_device *tunnel_dev,
		    struct flow_rule *rule)
{
#ifdef HAVE_VXLAN_TYPE
#if IS_ENABLED(CONFIG_VXLAN)
	if (netif_is_vxlan(tunnel_dev))
		return TNL_VXLAN;
#endif
#endif /* HAVE_VXLAN_TYPE */
#ifdef HAVE_GENEVE_TYPE
#if IS_ENABLED(CONFIG_GENEVE)
	if (netif_is_geneve(tunnel_dev))
		return TNL_GENEVE;
#endif
#endif /* HAVE_GENEVE_TYPE */
	/* detect possibility of GTP tunnel type based on input */
	if (ice_is_tnl_gtp(tunnel_dev, rule))
		return TNL_GTP;

	return TNL_LAST;
}

/**
 * ice_tc_tun_info - Parse and store tunnel info
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @tunnel: type of tunnel (e.g. VxLAN, Geneve, GTP)
 *
 * Parse tunnel attributes such as tunnel_id and store them.
 */
static int
ice_tc_tun_info(struct ice_pf *pf, struct flow_cls_offload *f,
		struct ice_tc_flower_fltr *fltr,
		enum ice_tunnel_type tunnel)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);

	/* match on VNI */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct device *dev = ice_pf_to_dev(pf);
		struct flow_match_enc_keyid enc_keyid;
		u32 key_id;

		flow_rule_match_enc_keyid(rule, &enc_keyid);
		if (!enc_keyid.mask->keyid) {
			dev_err(dev, "Bad mask for encap key_id 0x%04x, it must be non-zero\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		if (enc_keyid.mask->keyid !=
				cpu_to_be32(ICE_TC_FLOWER_MASK_32)) {
			dev_err(dev, "Bad mask value for encap key_id 0x%04x\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		key_id = be32_to_cpu(enc_keyid.key->keyid);
		if (tunnel == TNL_VXLAN || tunnel == TNL_GENEVE) {
			/* VNI is only 3 bytes, applicable for VXLAN/GENEVE */
			if (key_id > ICE_TC_FLOWER_VNI_MAX) {
				dev_err(dev, "VNI out of range : 0x%x\n",
					key_id);
				return -EINVAL;
			}
		}
		fltr->flags |= ICE_TC_FLWR_FIELD_TENANT_ID;
		fltr->tenant_id = enc_keyid.key->keyid;
	} else if (tunnel == TNL_GTP) {
		/* User didn't specify tunnel_key but indicated
		 * intention about GTP tunnel.
		 * For GTP tunnel, support for wild-card tunnel-ID
		 */
		fltr->flags |= ICE_TC_FLWR_FIELD_TENANT_ID;
		fltr->tenant_id = 0;
	}

	return 0;
}

/**
 * ice_tc_tun_parse - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
ice_tc_tun_parse(struct net_device *filter_dev, struct ice_vsi *vsi,
		 struct flow_cls_offload *f,
		 struct ice_tc_flower_fltr *fltr,
		 struct ice_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	enum ice_tunnel_type tunnel_type;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	tunnel_type = ice_tc_tun_get_type(filter_dev, rule);

	if (tunnel_type == TNL_VXLAN || tunnel_type == TNL_GTP ||
	    tunnel_type == TNL_GENEVE) {
		err = ice_tc_tun_info(pf, f, fltr, tunnel_type);
		if (err) {
			dev_err(dev, "Failed to parse tunnel (tunnel_type %u) attributes\n",
				tunnel_type);
			return err;
		}
	} else {
		dev_err(dev, "Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	fltr->tunnel_type = tunnel_type;
	headers->l3_key.ip_proto = IPPROTO_UDP;
	return err;
}

/**
 * ice_parse_tunnel_attr - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
ice_parse_tunnel_attr(struct net_device *filter_dev, struct ice_vsi *vsi,
		      struct flow_cls_offload *f,
		      struct ice_tc_flower_fltr *fltr,
		      struct ice_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control enc_control;
	int err;

	err = ice_tc_tun_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "failed to parse tunnel attributes");
		return err;
	}

	flow_rule_match_enc_control(rule, &enc_control);

	if (enc_control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);
		if (ice_tc_set_ipv4(&match, fltr, headers, true))
			return -EINVAL;
	} else if (enc_control.key->addr_type ==
					FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);
		if (ice_tc_set_ipv6(&match, fltr, headers, true))
			return -EINVAL;
	}

#ifdef HAVE_TC_FLOWER_ENC_IP
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_match_ip match;

		flow_rule_match_enc_ip(rule, &match);
		headers->l3_key.tos = match.key->tos;
		headers->l3_key.ttl = match.key->ttl;
		headers->l3_mask.tos = match.mask->tos;
		headers->l3_mask.ttl = match.mask->ttl;
	}
#endif /* HAVE_TC_FLOWER_ENC_IP */

	if (fltr->tunnel_type == TNL_GTP &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_enc_ports(rule, &match);
		/* store away outer L4 port info and mark it for tunnel */
		if (ice_tc_set_port(match, fltr, headers, true))
			return -EINVAL;
	}
	return 0;
}
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

/**
 * ice_parse_cls_flower - Parse TC flower filters provided by kernel
 * @vsi: Pointer to the VSI
 * @filter_dev: Pointer to device on which filter is being added
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
ice_parse_cls_flower(struct net_device *filter_dev, struct ice_vsi *vsi,
		     struct flow_cls_offload *f,
		     struct ice_tc_flower_fltr *fltr)
#else
static int
ice_parse_cls_flower(struct net_device __always_unused *filter_dev,
		     struct ice_vsi __always_unused *vsi,
		     struct tc_cls_flower_offload *f,
		     struct ice_tc_flower_fltr *fltr)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &fltr->outer_headers;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;
	struct flow_dissector *dissector;

	dissector = rule->match.dissector;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	      BIT(FLOW_DISSECTOR_KEY_VLANID) |
#endif
#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
#ifdef HAVE_TC_FLOWER_ENC
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
#ifdef HAVE_TC_FLOWER_ENC_IP
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif /* HAVE_TC_FLOWER_ENC_IP */
#endif /* HAVE_TC_FLOWER_ENC */
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported key used");
		return -EOPNOTSUPP;
	}

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
#ifdef HAVE_VXLAN_TYPE
#if IS_ENABLED(CONFIG_VXLAN)
	    netif_is_vxlan(filter_dev) ||
#endif
#endif /* HAVE_VXLAN_TYPE */
#ifdef HAVE_GENEVE_TYPE
#if IS_ENABLED(CONFIG_GENEVE)
	    netif_is_geneve(filter_dev) ||
#endif
#endif /* HAVE_GENEVE_TYPE */
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)
	  ) {
		int err;

		err = ice_parse_tunnel_attr(filter_dev, vsi, f, fltr, headers);
		if (err) {
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to parse TC flower tunnel attributes");
			return err;
		}

		/* header pointers should point to the inner headers, outer
		 * header were already set by ice_parse_tunnel_attr
		 */
		headers = &fltr->inner_headers;
	} else {
		fltr->tunnel_type = TNL_LAST;
	}
#else /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */
	fltr->tunnel_type = TNL_LAST;
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		if (n_proto_key == ETH_P_ALL || n_proto_key == 0) {
			n_proto_key = 0;
			n_proto_mask = 0;
		} else {
			fltr->flags |= ICE_TC_FLWR_FIELD_ETH_TYPE_ID;
		}

		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(n_proto_mask);
		headers->l3_key.ip_proto = match.key->ip_proto;
		headers->l3_mask.ip_proto = match.mask->ip_proto;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!is_zero_ether_addr(match.key->dst)) {
			ether_addr_copy(headers->l2_key.dst_mac,
					match.key->dst);
			ether_addr_copy(headers->l2_mask.dst_mac,
					match.mask->dst);
			fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
		}

		if (!is_zero_ether_addr(match.key->src)) {
			ether_addr_copy(headers->l2_key.src_mac,
					match.key->src);
			ether_addr_copy(headers->l2_mask.src_mac,
					match.mask->src);
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_MAC;
		}
	}

#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	if (dissector_uses_key(dissector, FLOW_DISSECTOR_KEY_VLANID)) {
		struct flow_dissector_key_tags *key =
			(struct flow_dissector_key_tags *)
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLANID,
						  f->key);
		struct flow_dissector_key_tags *mask =
			(struct flow_dissector_key_tags *)
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLANID,
						  f->mask);

		if (mask->vlan_id) {
			if (mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack, "Bad VLAN mask");
				return -EINVAL;
			}
		}
		headers->vlan_hdr.vlan_id =
				cpu_to_be16(key->vlan_id & VLAN_VID_MASK);
#ifdef HAVE_FLOW_DISSECTOR_VLAN_PRIO
		if (mask->vlan_priority)
			headers->vlan_hdr.vlan_prio = key->vlan_priority;
#endif
	}
#else /* !HAVE_TC_FLOWER_VLAN_IN_TAGS */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan mask;
		struct flow_dissector_key_vlan key;
		struct flow_match_vlan match;

		if (is_vlan_dev(filter_dev)) {
			match.key = &key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
			match.key->vlan_priority = 0;
			match.mask = &mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}

		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack, "Bad VLAN mask");
				return -EINVAL;
			}
		}

		headers->vlan_hdr.vlan_id =
				cpu_to_be16(match.key->vlan_id & VLAN_VID_MASK);
#ifdef HAVE_FLOW_DISSECTOR_VLAN_PRIO
		if (match.mask->vlan_priority)
			headers->vlan_hdr.vlan_prio = match.key->vlan_priority;
#endif
	}
#endif /* HAVE_TC_FLOWER_VLAN_IN_TAGS */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);

		addr_type = match.key->addr_type;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		if (ice_tc_set_ipv4(&match, fltr, headers, false))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		if (ice_tc_set_ipv6(&match, fltr, headers, false))
			return -EINVAL;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		if (ice_tc_set_port(match, fltr, headers, false))
			return -EINVAL;
		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		default:
			NL_SET_ERR_MSG_MOD(fltr->extack, "Only UDP and TCP transport are supported");
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * ice_add_remove_tc_flower_dflt_fltr - add or remove default filter
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 * @add: true if filter is being added.
 *
 * Add or remove default filter using default recipes to add MAC
 * or VLAN or MAC-VLAN filters.
 */
static int
ice_add_remove_tc_flower_dflt_fltr(struct ice_vsi *vsi,
				   struct ice_tc_flower_fltr *tc_fltr, bool add)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	struct ice_vsi_vlan_ops *vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	enum ice_sw_fwd_act_type act = tc_fltr->action.fltr_act;
	u16 vlan_id =  be16_to_cpu(headers->vlan_hdr.vlan_id);
	const u8 *dst_mac = headers->l2_key.dst_mac;
	int err;

	switch (tc_fltr->flags) {
	case ICE_TC_FLWR_FLTR_FLAGS_DST_MAC:
		if (add) {
			err = ice_fltr_add_mac(vsi, dst_mac, act);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not add MAC filters");
		} else {
			err = ice_fltr_remove_mac(vsi, dst_mac, act);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not remove MAC filters");
		}
		break;
	case ICE_TC_FLWR_FLTR_FLAGS_VLAN:
		if (add) {
			struct ice_vlan vlan =
				ICE_VLAN(ETH_P_8021Q, vlan_id, 0, act);
			err = vlan_ops->add_vlan(vsi, &vlan);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not add VLAN filters");
		} else {
			struct ice_vlan vlan =
				ICE_VLAN(ETH_P_8021Q, vlan_id, 0, act);
			err = vlan_ops->del_vlan(vsi, &vlan);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not delete VLAN filters");
		}
		break;
	case ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN:
		if (add) {
			err = ice_fltr_add_mac_vlan(vsi, dst_mac, vlan_id, act);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not add MAC VLAN filters");
		} else {
			err = ice_fltr_remove_mac_vlan(vsi, dst_mac, vlan_id,
						       act);
			if (err)
				NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Could not remove MAC VLAN filters");
		}
		break;
	default:
		NL_SET_ERR_MSG_MOD(tc_fltr->extack, "Not a default filter type");
		err = -EOPNOTSUPP;
		break;
	}
	return err;
}

/**
 * ice_add_switch_fltr - Add TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct ice_tc_flower_fltr
 *
 * Add filter in HW switch block
 */
static int
ice_add_switch_fltr(struct ice_vsi *vsi, struct ice_tc_flower_fltr *fltr)
{
	if (ice_is_eswitch_mode_switchdev(vsi->back))
		return ice_eswitch_add_tc_fltr(vsi, fltr);

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (fltr->action.fltr_act == ICE_FWD_TO_QGRP)
		return -EOPNOTSUPP;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	if (fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_VLAN ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN)
		return ice_add_remove_tc_flower_dflt_fltr(vsi, fltr, true);
#ifdef HAVE_TC_SETUP_CLSFLOWER
	return ice_add_tc_flower_adv_fltr(vsi, fltr);
#else
	return -EOPNOTSUPP;
#endif /* HAVE_TC_SETUP_CLSFLOWER */
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * ice_handle_tclass_action - Support directing to a traffic class or queue
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Support directing traffic to a traffic class or queue
 */
static int
ice_handle_tclass_action(struct ice_vsi *vsi,
			 struct flow_cls_offload *cls_flower,
			 struct ice_tc_flower_fltr *fltr)
{
	unsigned int nrx = TC_H_MIN(cls_flower->classid);
	u32 num_tc;
	int tc;

	num_tc = (u32)netdev_get_num_tc(vsi->netdev);

	/* There are two regions which will have valid "classid" values:
	 * 1. The first region will have a classid value of 1 through
	 * num_tx_queues (i.e forward to queue).
	 * 2. The second region represents the hardware traffic classes. These
	 * are represented by classid values of TC_H_MIN_PRIORITY through
	 * TC_H_MIN_PRIORITY + netdev_get_num_tc - 1. (i.e forward to TC)
	 */
	if (nrx < TC_H_MIN_PRIORITY) {
		struct ice_hw *hw = &vsi->back->hw;
		u32 queue, global_qid;
		/* user specified queue, hence action is forward to queue */
		if (nrx > vsi->num_rxq) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unable to add filter because specified queue is invalid");
			return -ENXIO;
		}
		/* since nrx is 1 based */
		queue = nrx - 1;

		/* forward to queue */
		fltr->action.fltr_act = ICE_FWD_TO_Q;
		fltr->action.fwd.q.queue = queue;

		/* determine corresponding HW queue */
		global_qid = hw->func_caps.common_cap.rxq_first_id + queue;
		fltr->action.fwd.q.hw_queue = global_qid;
	} else if ((nrx - TC_H_MIN_PRIORITY) < num_tc) {
		/* user specified hw_tc (it must be non-zero for ADQ TC, hence
		 * action is forward to "hw_tc (aka ADQ channel number)"
		 */
		tc = nrx - TC_H_MIN_PRIORITY;
		if (tc < ICE_CHNL_START_TC) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unable to add filter because of unsupported destination");
			return -EOPNOTSUPP;
		}

		if (!(vsi->all_enatc & BIT(tc))) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unable to add filter because of non-existence destination");
			return -EINVAL;
		}
		/* forward to hw_tc (aka ADQ VSI) */
		fltr->action.fltr_act = ICE_FWD_TO_VSI;
		fltr->action.fwd.tc.tc_class = tc;
	} else {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unable to add filter because user specified neither queue nor hw_tc as forward action");
		return -EINVAL;
	}

	if ((fltr->flags & ICE_TC_FLWR_FIELD_TENANT_ID) &&
	    (fltr->flags & (ICE_TC_FLWR_FIELD_DST_MAC |
			   ICE_TC_FLWR_FIELD_SRC_MAC))) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add filter because filter using tunnel key and inner MAC is unsupported combination");
		return -EOPNOTSUPP;
	}

	/* For ADQ, filter must include dest MAC address, otherwise unwanted
	 * packets with unrelated MAC address get delivered to ADQ VSIs as long
	 * as remaining filter criteria is satisfied such as dest IP address
	 * and dest/src L4 port. Following code is trying to handle:
	 * 1. For non-tunnel, if user specify MAC addresses, use them (means
	 * this code won't do anything
	 * 2. For non-tunnel, if user didn't specify MAC address, add implicit
	 * dest MAC to be lower netdev's active unicast MAC address
	 * 3. For tunnel,  as of now TC-filter thru flower classifier doesn't
	 * have provision for user to specify outer DMAC, hence driver to
	 * implicitly add outer dest MAC to be lower netdev's active unicast
	 * MAC address.
	 */
	if (ice_is_tunnel_fltr(fltr)) {
		if (!(fltr->flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC)) {
			ether_addr_copy(fltr->outer_headers.l2_key.dst_mac,
					vsi->netdev->dev_addr);
			eth_broadcast_addr(fltr->outer_headers.l2_mask.dst_mac);
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DST_MAC;
		}
	} else if (!(fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)) {
		ether_addr_copy(fltr->outer_headers.l2_key.dst_mac,
				vsi->netdev->dev_addr);
		eth_broadcast_addr(fltr->outer_headers.l2_mask.dst_mac);
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
	}

	/* Make sure VLAN is already added to main VSI, before allowing ADQ to
	 * add a VLAN based filter such as MAC + VLAN + L4 port.
	 */
	if (fltr->flags & ICE_TC_FLWR_FIELD_VLAN) {
		u16 vlan_id = be16_to_cpu(fltr->outer_headers.vlan_hdr.vlan_id);

		if (!ice_vlan_fltr_exist(&vsi->back->hw, vlan_id, vsi->idx)) {
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add filter because legacy VLAN filter for specified destination doesn't exist");
			return -EINVAL;
		}
	}

	return 0;
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

/**
 * ice_parse_tc_flower_actions - Parse the actions for a TC filter
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Parse the actions for a TC filter
 */
static int
ice_parse_tc_flower_actions(struct ice_vsi *vsi,
			    struct flow_cls_offload *cls_flower,
			    struct ice_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	int i;
#else
	struct tcf_exts *exts = cls_flower->exts;
	struct tc_action *tc_act;
#if defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	int i;
#else
	struct tc_action *temp;
	LIST_HEAD(tc_actions);
#endif
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (cls_flower->classid)
		return ice_handle_tclass_action(vsi, cls_flower, fltr);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	if (!flow_action_has_entries(flow_action))
#elif defined(HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV)
	if (!tcf_exts_has_actions(exts))
#else
	if (tc_no_actions(exts))
#endif
		return -EINVAL;

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	flow_action_for_each(i, act, flow_action) {
#elif defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	tcf_exts_for_each_action(i, tc_act, exts) {
#elif defined(HAVE_TCF_EXTS_TO_LIST)
	tcf_exts_to_list(exts, &tc_actions);

	list_for_each_entry_safe(tc_act, temp, &tc_actions, list) {
#else
	list_for_each_entry_safe(tc_act, temp, &(exts)->actions, list) {
#endif /* HAVE_TCF_EXTS_TO_LIST */
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
		if (ice_is_eswitch_mode_switchdev(vsi->back)) {
			int err = ice_eswitch_tc_parse_action(fltr, act);

			if (err)
				return err;
			continue;
		}
#else
		if (ice_is_eswitch_mode_switchdev(vsi->back))
			return -EINVAL;
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */
		/* Allow only one rule per filter */

		/* Drop action */
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
		if (act->id == FLOW_ACTION_DROP) {
#else
		if (is_tcf_gact_shot(tc_act)) {
#endif
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported action DROP");
			return -EINVAL;
		}
		fltr->action.fltr_act = ICE_FWD_TO_VSI;
	}
	return 0;
}

/**
 * ice_del_tc_fltr - deletes a filter from HW table
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct ice_tc_flower_fltr
 *
 * This function deletes a filter from HW table and manages book-keeping
 */
static int ice_del_tc_fltr(struct ice_vsi *vsi, struct ice_tc_flower_fltr *fltr)
{
	struct ice_pf *pf = vsi->back;
	int err;

	if (fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_VLAN ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN) {
		err = ice_add_remove_tc_flower_dflt_fltr(vsi, fltr, false);
	} else {
		struct ice_rule_query_data rule_rem;

		rule_rem.rid = fltr->rid;
		rule_rem.rule_id = fltr->rule_id;
		rule_rem.vsi_handle = fltr->dest_vsi_handle;
		err = ice_rem_adv_rule_by_id(&pf->hw, &rule_rem);
	}

	if (err) {
		if (err == ICE_ERR_DOES_NOT_EXIST) {
			NL_SET_ERR_MSG_MOD(fltr->extack, "Filter does not exist");
			return -ENOENT;
		}
		NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to delete TC flower filter");
		return -EIO;
	}

	/* update advanced switch filter count for destination
	 * VSI if filter destination was VSI
	 */
	if (fltr->dest_vsi) {
		if (fltr->dest_vsi->type == ICE_VSI_CHNL) {
			fltr->dest_vsi->num_chnl_fltr--;

			/* keeps track of channel filters for PF VSI */
			if (vsi->type == ICE_VSI_PF &&
			    (fltr->flags & (ICE_TC_FLWR_FIELD_DST_MAC |
					    ICE_TC_FLWR_FIELD_ENC_DST_MAC)))
				pf->num_dmac_chnl_fltrs--;
		}
	}
	return 0;
}

/**
 * ice_add_tc_fltr - adds a TC flower filter
 * @netdev: Pointer to netdev
 * @vsi: Pointer to VSI
 * @f: Pointer to flower offload structure
 * @__fltr: Pointer to struct ice_tc_flower_fltr
 *
 * This function parses TC-flower input fields, parses action,
 * and adds a filter.
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
ice_add_tc_fltr(struct net_device *netdev, struct ice_vsi *vsi,
		struct flow_cls_offload *f,
		struct ice_tc_flower_fltr **__fltr)
#else
static int
ice_add_tc_fltr(struct net_device *netdev, struct ice_vsi *vsi,
		struct tc_cls_flower_offload *f,
		struct ice_tc_flower_fltr **__fltr)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct ice_tc_flower_fltr *fltr;
	int err;

	/* by default, set output to be INVALID */
	*__fltr = NULL;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	fltr->cookie = f->cookie;
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	fltr->extack = f->common.extack;
#endif
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);

	err = ice_parse_cls_flower(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = ice_parse_tc_flower_actions(vsi, f, fltr);
	if (err < 0)
		goto err;

	err = ice_add_switch_fltr(vsi, fltr);
	if (err < 0)
		goto err;

	/* return the newly created filter */
	*__fltr = fltr;

	return 0;
err:
	kfree(fltr);
	return err;
}

/**
 * ice_find_tc_flower_fltr - Find the TC flower filter in the list
 * @pf: Pointer to PF
 * @cookie: filter specific cookie
 */
static struct ice_tc_flower_fltr *
ice_find_tc_flower_fltr(struct ice_pf *pf, unsigned long cookie)
{
	struct ice_tc_flower_fltr *fltr;

	hlist_for_each_entry(fltr, &pf->tc_flower_fltr_list, tc_flower_node)
		if (cookie == fltr->cookie)
			return fltr;

	return NULL;
}

/**
 * ice_add_cls_flower - add TC flower filters
 * @netdev: Pointer to filter device
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to flower offload structure
 */
int
#ifdef HAVE_TC_INDIR_BLOCK
ice_add_cls_flower(struct net_device *netdev, struct ice_vsi *vsi,
		   struct flow_cls_offload *cls_flower)
#else
ice_add_cls_flower(struct net_device __always_unused *netdev,
		   struct ice_vsi *vsi,
		   struct tc_cls_flower_offload *cls_flower)
#endif /* HAVE_TC_INDIR_BLOCK */
{
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	struct netlink_ext_ack *extack = cls_flower->common.extack;
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
	struct net_device *vsi_netdev = vsi->netdev;
	struct ice_tc_flower_fltr *fltr;
	struct ice_pf *pf = vsi->back;
	int err;

	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;
	if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags))
		return -EINVAL;

#ifdef HAVE_TC_FLOW_INDIR_DEV
	if ((ice_tc_tun_get_type(netdev, NULL) == TNL_LAST) &&
	    ice_is_port_repr_netdev(netdev))
		vsi_netdev = netdev;
#else
	if (ice_is_port_repr_netdev(netdev))
		vsi_netdev = netdev;
#endif /* HAVE_TC_FLOW_INDIR_DEV */

	if (!(vsi_netdev->features & NETIF_F_HW_TC) &&
	    !test_bit(ICE_FLAG_CLS_FLOWER, pf->flags)) {
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
#ifdef HAVE_TC_INDIR_BLOCK
		/* Based on TC indirect notifications from kernel, all ice
		 * devices get an instance of rule from higher level device.
		 * Avoid triggering explicit error in this case.
		 */
		if (netdev == vsi_netdev)
			NL_SET_ERR_MSG_MOD(extack, "can't apply TC flower filters, turn ON hw-tc-offload and try again");
#else
		NL_SET_ERR_MSG_MOD(extack, "can't apply TC flower filters, turn ON hw-tc-offload and try again");
#endif /* HAVE_TC_INDIR_BLOCK */
#else  /* !HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		netdev_err(vsi_netdev, "can't apply TC flower filters, turn ON hw-tc-offload and try again\n");
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		return -EINVAL;
	}

	/* avoid duplicate entries, if exists - return error */
	fltr = ice_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (fltr) {
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "filter cookie already exists, ignoring");
#else
		netdev_warn(vsi_netdev, "filter cookie %lx already exists, ignoring\n",
			    fltr->cookie);
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		return -EEXIST;
	}

	/* prep and add TC-flower filter in HW */
	err = ice_add_tc_fltr(netdev, vsi, cls_flower, &fltr);
	if (err)
		return err;

	/* add filter into an ordered list */
	hlist_add_head(&fltr->tc_flower_node, &pf->tc_flower_fltr_list);
	return 0;
}

/**
 * ice_del_cls_flower - delete TC flower filters
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to struct flow_cls_offload
 */
int
ice_del_cls_flower(struct ice_vsi *vsi, struct flow_cls_offload *cls_flower)
{
	struct ice_tc_flower_fltr *fltr;
	struct ice_pf *pf = vsi->back;
	int err;

	/* find filter */
	fltr = ice_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (!fltr) {
		/* when egress qdisc is deleted, driver deletes all channel
		 * filters so that there are no stale filters left in
		 * HW (as per design) because deleting egress qdisc means,
		 * deleting all channel VSIs, hence no reason to keep filters
		 * destined to those channel VSIs. But software (OS) still
		 * sees those filters being offloaded in HW. In this situation
		 * user can try to delete those filters or OS will try to
		 * delete them one by one when ingress qdisc is deleted from
		 * given interace (ethX) and driver won't find those filters in
		 * its list of filters, hence don't return error. Return the
		 * error only when there are still active channel(s) and can't
		 * find requested filter and/or failed to delet the filter,
		 * otherwise return success
		 */
		/* means no channels are configured or channels are deleted and
		 * channel filter list is empty
		 */
		if (!test_bit(ICE_FLAG_TC_MQPRIO, pf->flags) &&
		    hlist_empty(&pf->tc_flower_fltr_list))
			return 0;

#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "failed to delete TC flower filter because unable to find it");
#else
		dev_err(ice_pf_to_dev(pf),
			"failed to delete TC flower filter because unable to find it\n");
#endif
		return -EINVAL;
	}

#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	fltr->extack = cls_flower->common.extack;
#endif
	/* delete filter from HW */
	err = ice_del_tc_fltr(vsi, fltr);
	if (err)
		return err;

	/* delete filter from an ordered list */
	hlist_del(&fltr->tc_flower_node);

	/* free the filter node */
	kfree(fltr);

	return 0;
}

/**
 * ice_replay_tc_fltrs - replay TC filters
 * @pf: pointer to PF struct
 */
void ice_replay_tc_fltrs(struct ice_pf *pf)
{
	struct ice_tc_flower_fltr *fltr;
	struct hlist_node *node;

	hlist_for_each_entry_safe(fltr, node,
				  &pf->tc_flower_fltr_list,
				  tc_flower_node) {
		fltr->extack = NULL;
		ice_add_switch_fltr(fltr->src_vsi, fltr);
	}
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */
