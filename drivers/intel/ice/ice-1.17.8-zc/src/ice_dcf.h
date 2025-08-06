/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_DCF_H_
#define _ICE_DCF_H_

struct ice_vf;
struct ice_pf;
struct ice_hw;

#define ICE_DCF_VFID	0

/* DCF mode states */
enum ice_dcf_state {
	/* DCF mode is fully off */
	ICE_DCF_STATE_OFF = 0,
	/* Process is live, acquired capability to send DCF CMD */
	ICE_DCF_STATE_ON,
	/* Kernel is busy, deny DCF CMD */
	ICE_DCF_STATE_BUSY,
	/* Kernel is ready for Process to Re-establish, deny DCF CMD */
	ICE_DCF_STATE_PAUSE,
};

struct ice_dcf_sw_rule_entry;

#define ICE_HW_VSI_ID_MAX	BIT(10) /* The AQ VSI number uses 10 bits */

struct ice_dcf_vsi_list_info {
	struct list_head list_entry;
	struct ice_dcf_sw_rule_entry *sw_rule;
	u16 list_id;

	u16 vsi_count;
	DECLARE_BITMAP(hw_vsi_map, ICE_HW_VSI_ID_MAX);
};

struct ice_dcf_sw_rule_entry {
	struct list_head list_entry;
	u16 rule_id;

	/* Only support ICE_FWD_TO_VSI and ICE_FWD_TO_VSI_LIST */
	enum ice_sw_fwd_act_type fltr_act;
	/* Depending on filter action */
	union {
		u16 hw_vsi_id:10;
		u16 vsi_list_id:10;
	} fwd_id;

	struct ice_dcf_vsi_list_info *vsi_list_info;
};

struct ice_dcf {
	struct ice_vf *vf;
	enum ice_dcf_state state;

	/* Trace the switch rules added/removed by DCF */
	struct list_head sw_rule_head;
	struct list_head vsi_list_info_head;

	/* Handle the AdminQ command between the DCF (Device Config Function)
	 * and the firmware.
	 */
#define ICE_DCF_AQ_DESC_TIMEOUT	(HZ / 10)
	struct ice_aq_desc aq_desc;
	u8 aq_desc_received;
	unsigned long aq_desc_expires;

	/* Save the current Device Serial Number when searching the package
	 * path for later query.
	 */
#define ICE_DSN_NUM_LEN 8
	u8 dsn[ICE_DSN_NUM_LEN];
};

#ifdef CONFIG_PCI_IOV
bool ice_dcf_aq_cmd_permitted(struct ice_aq_desc *desc);
bool ice_check_dcf_allowed(struct ice_vf *vf);
bool ice_is_dcf_enabled(struct ice_pf *pf);
bool ice_is_vf_dcf(struct ice_vf *vf);
enum ice_dcf_state ice_dcf_get_state(struct ice_pf *pf);
void ice_dcf_set_state(struct ice_pf *pf, enum ice_dcf_state state);
void ice_dcf_init_sw_rule_mgmt(struct ice_pf *pf);
void ice_rm_all_dcf_sw_rules(struct ice_pf *pf);
void ice_rm_dcf_sw_vsi_rule(struct ice_pf *pf, struct ice_vf *vf);
bool
ice_dcf_pre_aq_send_cmd(struct ice_vf *vf, struct ice_aq_desc *aq_desc,
			u8 *aq_buf, u16 aq_buf_size);
enum virtchnl_status_code
ice_dcf_post_aq_send_cmd(struct ice_pf *pf, struct ice_aq_desc *aq_desc,
			 u8 *aq_buf);
bool ice_dcf_is_acl_aq_cmd(struct ice_aq_desc *desc);
bool ice_dcf_is_udp_tunnel_aq_cmd(struct ice_aq_desc *desc, u8 *aq_buf);
void ice_clear_dcf_acl_cfg(struct ice_pf *pf);
bool ice_dcf_is_acl_capable(struct ice_hw *hw);
void ice_clear_dcf_udp_tunnel_cfg(struct ice_pf *pf);
bool ice_dcf_is_udp_tunnel_capable(struct ice_hw *hw);
enum virtchnl_status_code
ice_dcf_update_acl_rule_info(struct ice_pf *pf, struct ice_aq_desc *desc,
			     u8 *aq_buf);
#else
static inline bool ice_is_dcf_enabled(struct ice_pf __always_unused *pf)
{
	return false;
}

static inline bool
ice_dcf_is_udp_tunnel_capable(struct ice_hw __always_unused *hw)
{
	return false;
}

static inline bool ice_dcf_is_acl_capable(struct ice_hw __always_unused *hw)
{
	return false;
}
#endif /* CONFIG_PCI_IOV */
#endif /* _ICE_DCF_H_ */
