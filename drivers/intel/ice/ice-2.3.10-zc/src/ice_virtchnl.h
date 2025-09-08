/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_VIRTCHNL_H_
#define _ICE_VIRTCHNL_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/if_ether.h>
#include "virtchnl.h"
#include "ice_switch.h"
#include "ice_vf_lib.h"

/* Restrict number of MAC Addr and VLAN that non-trusted VF can programmed */
#define ICE_MAX_VLAN_PER_VF		8

/* MAC filters: 1 is reserved for the VF's default/perm_addr/LAA MAC, 1 for
 * broadcast, and 16 for additional unicast/multicast filters
 */
#define ICE_MAX_MACADDR_PER_VF		18

#define ICE_MAX_RSS_QS_PER_LARGE_VF	64
#define ICE_MAX_RSS_QS_PER_VF		16

/* Max number of flexible descriptor rxdid */
#define ICE_FLEX_DESC_RXDID_MAX_NUM 64

#define ICE_DFLT_QUANTA 1024
#define ICE_MAX_QUANTA_SIZE 4096
#define ICE_MIN_QUANTA_SIZE 256
#define calc_quanta_desc(x)	\
	max_t(u16, 12, min_t(u16, 63, ((x + 66) / 132) * 2 + 4))

static inline void ice_set_vf_ucast_promisc_bits(unsigned long *mask)
{
	set_bit(ICE_PROMISC_UCAST_RX, mask);
}

static inline void ice_set_vf_ucast_vlan_promisc_bits(unsigned long *mask)
{
	set_bit(ICE_PROMISC_UCAST_RX, mask);
	set_bit(ICE_PROMISC_VLAN_RX, mask);
}

struct ice_virtchnl_ops {
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
	int (*hqos_read_tree)(struct ice_vf *vf, u8 *msg);
	int (*hqos_elems_add)(struct ice_vf *vf, u8 *msg);
	int (*hqos_elems_del)(struct ice_vf *vf, u8 *msg);
	int (*hqos_elems_move)(struct ice_vf *vf, u8 *msg);
	int (*hqos_elems_conf)(struct ice_vf *vf, u8 *msg);
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
	int (*cfg_rdma_irq_map_msg)(struct ice_vf *vf, u8 *msg);
	int (*clear_rdma_irq_map)(struct ice_vf *vf);
	int (*dcf_vlan_offload_msg)(struct ice_vf *vf, u8 *msg);
	int (*dcf_cmd_desc_msg)(struct ice_vf *vf, u8 *msg, u16 msglen);
	int (*dcf_cmd_buff_msg)(struct ice_vf *vf, u8 *msg, u16 msglen);
	int (*dis_dcf_cap)(struct ice_vf *vf);
	int (*dcf_get_vsi_map)(struct ice_vf *vf);
	int (*dcf_query_pkg_info)(struct ice_vf *vf);
	int (*dcf_config_vf_tc)(struct ice_vf *vf, u8 *msg);
	int (*handle_rss_cfg_msg)(struct ice_vf *vf, u8 *msg, bool add);
	int (*get_qos_caps)(struct ice_vf *vf);
	int (*cfg_q_tc_map)(struct ice_vf *vf, u8 *msg);
	int (*cfg_q_bw)(struct ice_vf *vf, u8 *msg);
	int (*cfg_q_quanta)(struct ice_vf *vf, u8 *msg);
	int (*add_fdir_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*del_fdir_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*flow_sub_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*flow_unsub_fltr_msg)(struct ice_vf *vf, u8 *msg);
	int (*get_max_rss_qregion)(struct ice_vf *vf);
	int (*ena_qs_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*dis_qs_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*map_q_vector_msg)(struct ice_vf *vf, u8 *msg);
	int (*get_offload_vlan_v2_caps)(struct ice_vf *vf);
	int (*add_vlan_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*remove_vlan_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*ena_vlan_stripping_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*dis_vlan_stripping_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*ena_vlan_insertion_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*dis_vlan_insertion_v2_msg)(struct ice_vf *vf, u8 *msg);
	int (*get_ptp_cap)(struct ice_vf *vf, u8 *msg);
	int (*get_phc_time)(struct ice_vf *vf);
#ifdef CONFIG_X86
	int (*get_sw_cross_tstamp)(struct ice_vf *vf);
	int (*get_phc_freq_ratio)(struct ice_vf *vf);
#endif /* CONFIG_X86 */
};

/**
 * ice_vc_get_max_chnl_tc_allowed
 * @vf: pointer to the VF info
 *
 * This function returns max channel TC allowed depends upon "driver_caps"
 */
static inline u32 ice_vc_get_max_chnl_tc_allowed(struct ice_vf *vf)
{
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		return VIRTCHNL_MAX_ADQ_V2_CHANNELS;
	else
		return VIRTCHNL_MAX_ADQ_CHANNELS;
}

#ifdef CONFIG_PCI_IOV
void ice_virtchnl_set_dflt_ops(struct ice_vf *vf);
void ice_virtchnl_set_repr_ops(struct ice_vf *vf);
void
ice_vc_vf_broadcast(struct ice_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen);
void ice_vc_notify_vf_link_state(struct ice_vf *vf);
void ice_vc_notify_link_state(struct ice_pf *pf);
void ice_vc_notify_reset(struct ice_pf *pf);
int
ice_vc_send_msg_to_vf(struct ice_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen);
bool ice_vc_isvalid_vsi_id(struct ice_vf *vf, u16 vsi_id);
int ice_vc_process_vf_msg(struct ice_pf *pf, struct ice_rq_event_info *event,
			  struct ice_mbx_data *mbxdata);
#else /* CONFIG_PCI_IOV */
static inline void ice_virtchnl_set_dflt_ops(struct ice_vf *vf) { }
static inline void ice_virtchnl_set_repr_ops(struct ice_vf *vf) { }
static inline void
ice_vc_vf_broadcast(struct ice_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
}

static inline void ice_vc_notify_vf_link_state(struct ice_vf *vf) { }
static inline void ice_vc_notify_link_state(struct ice_pf *pf) { }
static inline void ice_vc_notify_reset(struct ice_pf *pf) { }

static inline int
ice_vc_send_msg_to_vf(struct ice_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	return -EOPNOTSUPP;
}

static inline bool ice_vc_isvalid_vsi_id(struct ice_vf *vf, u16 vsi_id)
{
	return false;
}

static inline int
ice_vc_process_vf_msg(struct ice_pf *pf, struct ice_rq_event_info *event,
		      struct ice_mbx_data *mbxdata)
{
	return -EOPNOTSUPP;
}
#endif /* !CONFIG_PCI_IOV */

#endif /* _ICE_VIRTCHNL_H_ */
