// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice_common.h"
#include "ice_sched.h"
#include "ice_adminq_cmd.h"

#include "ice_flow.h"
#include "ice_switch.h"

#define ICE_PF_RESET_WAIT_COUNT	300
#define ICE_SCHED_VALID_SEC_BITS 4


/**
 * ice_set_mac_type - Sets MAC type
 * @hw: pointer to the HW structure
 *
 * This function sets the MAC type of the adapter based on the
 * vendor ID and device ID stored in the HW structure.
 */
static enum ice_status ice_set_mac_type(struct ice_hw *hw)
{
	enum ice_status status = 0;

	if (hw->vendor_id == PCI_VENDOR_ID_INTEL) {
		switch (hw->device_id) {
		default:
			hw->mac_type = ICE_MAC_GENERIC;
			break;
		}
	} else {
		status = ICE_ERR_DEVICE_NOT_SUPPORTED;
	}

	ice_debug(hw, ICE_DBG_INIT, "found mac_type: %d, status: %d\n",
		  hw->mac_type, status);

	return status;
}

void ice_dev_onetime_setup(struct ice_hw *hw)
{
	u32 reg;

#define RDPU_RLAN_ACK_REQ_PM_TH		0x3
#define RDPU_REQ_WB_PM_TH		0x3
	if (hw->device_id == ICE_DEV_ID_C822N_BACKPLANE ||
	    hw->device_id == ICE_DEV_ID_C822N_QSFP ||
	    hw->device_id == ICE_DEV_ID_C822N_SFP) {
		reg = rd32(hw, GL_RDPU_CNTRL);
		reg &= ~(GL_RDPU_CNTRL_RLAN_ACK_REQ_PM_TH_M |
			 GL_RDPU_CNTRL_REQ_WB_PM_TH_M);
		reg |= (RDPU_RLAN_ACK_REQ_PM_TH <<
			GL_RDPU_CNTRL_RLAN_ACK_REQ_PM_TH_S) |
		       (RDPU_REQ_WB_PM_TH << GL_RDPU_CNTRL_REQ_WB_PM_TH_S);
		wr32(hw, GL_RDPU_CNTRL, reg);
	}
}

/**
 * ice_clear_pf_cfg - Clear PF configuration
 * @hw: pointer to the hardware structure
 *
 * Clears any existing PF configuration (VSIs, VSI lists, switch rules, port
 * configuration, flow director filters, etc.).
 */
enum ice_status ice_clear_pf_cfg(struct ice_hw *hw)
{
	struct ice_aq_desc desc;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_clear_pf_cfg);

	return ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

/**
 * ice_aq_manage_mac_read - manage MAC address read command
 * @hw: pointer to the HW struct
 * @buf: a virtual buffer to hold the manage MAC read response
 * @buf_size: Size of the virtual buffer
 * @cd: pointer to command details structure or NULL
 *
 * This function is used to return per PF station MAC address (0x0107).
 * NOTE: Upon successful completion of this command, MAC address information
 * is returned in user specified buffer. Please interpret user specified
 * buffer as "manage_mac_read" response.
 * Response such as various MAC addresses are stored in HW struct (port.mac)
 * ice_aq_discover_caps is expected to be called before this function is called.
 */
static enum ice_status
ice_aq_manage_mac_read(struct ice_hw *hw, void *buf, u16 buf_size,
		       struct ice_sq_cd *cd)
{
	struct ice_aqc_manage_mac_read_resp *resp;
	struct ice_aqc_manage_mac_read *cmd;
	struct ice_aq_desc desc;
	enum ice_status status;
	u16 flags;
	u8 i;

	cmd = &desc.params.mac_read;

	if (buf_size < sizeof(*resp))
		return ICE_ERR_BUF_TOO_SHORT;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_manage_mac_read);

	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (status)
		return status;

	resp = (struct ice_aqc_manage_mac_read_resp *)buf;
	flags = le16_to_cpu(cmd->flags) & ICE_AQC_MAN_MAC_READ_M;

	if (!(flags & ICE_AQC_MAN_MAC_LAN_ADDR_VALID)) {
		ice_debug(hw, ICE_DBG_LAN, "got invalid MAC address\n");
		return ICE_ERR_CFG;
	}

	/* A single port can report up to two (LAN and WoL) addresses */
	for (i = 0; i < cmd->num_addr; i++)
		if (resp[i].addr_type == ICE_AQC_MAN_MAC_ADDR_TYPE_LAN) {
			ether_addr_copy(hw->port_info->mac.lan_addr,
					resp[i].mac_addr);
			ether_addr_copy(hw->port_info->mac.perm_addr,
					resp[i].mac_addr);
			break;
		}
	return 0;
}

/**
 * ice_aq_get_phy_caps - returns PHY capabilities
 * @pi: port information structure
 * @qual_mods: report qualified modules
 * @report_mode: report mode capabilities
 * @pcaps: structure for PHY capabilities to be filled
 * @cd: pointer to command details structure or NULL
 *
 * Returns the various PHY capabilities supported on the Port (0x0600)
 */
enum ice_status
ice_aq_get_phy_caps(struct ice_port_info *pi, bool qual_mods, u8 report_mode,
		    struct ice_aqc_get_phy_caps_data *pcaps,
		    struct ice_sq_cd *cd)
{
	struct ice_aqc_get_phy_caps *cmd;
	u16 pcaps_size = sizeof(*pcaps);
	struct ice_aq_desc desc;
	enum ice_status status;

	cmd = &desc.params.get_phy;

	if (!pcaps || (report_mode & ~ICE_AQC_REPORT_MODE_M) || !pi)
		return ICE_ERR_PARAM;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_phy_caps);

	if (qual_mods)
		cmd->param0 |= cpu_to_le16(ICE_AQC_GET_PHY_RQM);

	cmd->param0 |= cpu_to_le16(report_mode);
	status = ice_aq_send_cmd(pi->hw, &desc, pcaps, pcaps_size, cd);

	if (!status && report_mode == ICE_AQC_REPORT_TOPO_CAP) {
		pi->phy.phy_type_low = le64_to_cpu(pcaps->phy_type_low);
		pi->phy.phy_type_high = le64_to_cpu(pcaps->phy_type_high);
	}

	return status;
}

/**
 * ice_aq_get_link_topo_handle - get link topology node return status
 * @pi: port information structure
 * @node_type: requested node type
 * @cd: pointer to command details structure or NULL
 *
 * Get link topology node return status for specified node type (0x06E0)
 *
 * Node type cage can be used to determine if cage is present. If AQC
 * returns error (ENOENT), then no cage present. If no cage present, then
 * connection type is backplane or BASE-T.
 */
static enum ice_status
ice_aq_get_link_topo_handle(struct ice_port_info *pi, u8 node_type,
			    struct ice_sq_cd *cd)
{
	struct ice_aqc_get_link_topo *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.get_link_topo;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_link_topo);

	cmd->addr.node_type_ctx = (ICE_AQC_LINK_TOPO_NODE_CTX_PORT <<
				   ICE_AQC_LINK_TOPO_NODE_CTX_S);

	/* set node type */
	cmd->addr.node_type_ctx |= (ICE_AQC_LINK_TOPO_NODE_TYPE_M & node_type);

	return ice_aq_send_cmd(pi->hw, &desc, NULL, 0, cd);
}

/*
 * ice_is_media_cage_present
 * @pi: port information structure
 *
 * Returns true if media cage is present, else false. If no cage, then
 * media type is backplane or BASE-T.
 */
static bool ice_is_media_cage_present(struct ice_port_info *pi)
{
	/* Node type cage can be used to determine if cage is present. If AQC
	 * returns error (ENOENT), then no cage present. If no cage present then
	 * connection type is backplane or BASE-T.
	 */
	return !ice_aq_get_link_topo_handle(pi,
					    ICE_AQC_LINK_TOPO_NODE_TYPE_CAGE,
					    NULL);
}

/**
 * ice_get_media_type - Gets media type
 * @pi: port information structure
 */
static enum ice_media_type ice_get_media_type(struct ice_port_info *pi)
{
	struct ice_link_status *hw_link_info;

	if (!pi)
		return ICE_MEDIA_UNKNOWN;

	hw_link_info = &pi->phy.link_info;
	if (hw_link_info->phy_type_low && hw_link_info->phy_type_high)
		/* If more than one media type is selected, report unknown */
		return ICE_MEDIA_UNKNOWN;

	if (hw_link_info->phy_type_low) {
		switch (hw_link_info->phy_type_low) {
		case ICE_PHY_TYPE_LOW_1000BASE_SX:
		case ICE_PHY_TYPE_LOW_1000BASE_LX:
		case ICE_PHY_TYPE_LOW_10GBASE_SR:
		case ICE_PHY_TYPE_LOW_10GBASE_LR:
		case ICE_PHY_TYPE_LOW_10G_SFI_C2C:
		case ICE_PHY_TYPE_LOW_25GBASE_SR:
		case ICE_PHY_TYPE_LOW_25GBASE_LR:
		case ICE_PHY_TYPE_LOW_40GBASE_SR4:
		case ICE_PHY_TYPE_LOW_40GBASE_LR4:
		case ICE_PHY_TYPE_LOW_50GBASE_SR2:
		case ICE_PHY_TYPE_LOW_50GBASE_LR2:
		case ICE_PHY_TYPE_LOW_50GBASE_SR:
		case ICE_PHY_TYPE_LOW_50GBASE_FR:
		case ICE_PHY_TYPE_LOW_50GBASE_LR:
		case ICE_PHY_TYPE_LOW_100GBASE_SR4:
		case ICE_PHY_TYPE_LOW_100GBASE_LR4:
		case ICE_PHY_TYPE_LOW_100GBASE_SR2:
		case ICE_PHY_TYPE_LOW_100GBASE_DR:
			return ICE_MEDIA_FIBER;
		case ICE_PHY_TYPE_LOW_100BASE_TX:
		case ICE_PHY_TYPE_LOW_1000BASE_T:
		case ICE_PHY_TYPE_LOW_2500BASE_T:
		case ICE_PHY_TYPE_LOW_5GBASE_T:
		case ICE_PHY_TYPE_LOW_10GBASE_T:
		case ICE_PHY_TYPE_LOW_25GBASE_T:
			return ICE_MEDIA_BASET;
		case ICE_PHY_TYPE_LOW_10G_SFI_DA:
		case ICE_PHY_TYPE_LOW_25GBASE_CR:
		case ICE_PHY_TYPE_LOW_25GBASE_CR_S:
		case ICE_PHY_TYPE_LOW_25GBASE_CR1:
		case ICE_PHY_TYPE_LOW_40GBASE_CR4:
		case ICE_PHY_TYPE_LOW_50GBASE_CR2:
		case ICE_PHY_TYPE_LOW_50GBASE_CP:
		case ICE_PHY_TYPE_LOW_100GBASE_CR4:
		case ICE_PHY_TYPE_LOW_100GBASE_CR_PAM4:
		case ICE_PHY_TYPE_LOW_100GBASE_CP2:
			return ICE_MEDIA_DA;
		case ICE_PHY_TYPE_LOW_25G_AUI_C2C:
		case ICE_PHY_TYPE_LOW_40G_XLAUI:
		case ICE_PHY_TYPE_LOW_50G_LAUI2:
		case ICE_PHY_TYPE_LOW_50G_AUI2:
		case ICE_PHY_TYPE_LOW_50G_AUI1:
		case ICE_PHY_TYPE_LOW_100G_AUI4:
		case ICE_PHY_TYPE_LOW_100G_CAUI4:
			if (ice_is_media_cage_present(pi))
				return ICE_MEDIA_DA;
			/* fall-through */
		case ICE_PHY_TYPE_LOW_1000BASE_KX:
		case ICE_PHY_TYPE_LOW_2500BASE_KX:
		case ICE_PHY_TYPE_LOW_2500BASE_X:
		case ICE_PHY_TYPE_LOW_5GBASE_KR:
		case ICE_PHY_TYPE_LOW_10GBASE_KR_CR1:
		case ICE_PHY_TYPE_LOW_25GBASE_KR:
		case ICE_PHY_TYPE_LOW_25GBASE_KR1:
		case ICE_PHY_TYPE_LOW_25GBASE_KR_S:
		case ICE_PHY_TYPE_LOW_40GBASE_KR4:
		case ICE_PHY_TYPE_LOW_50GBASE_KR_PAM4:
		case ICE_PHY_TYPE_LOW_50GBASE_KR2:
		case ICE_PHY_TYPE_LOW_100GBASE_KR4:
		case ICE_PHY_TYPE_LOW_100GBASE_KR_PAM4:
			return ICE_MEDIA_BACKPLANE;
		}
	} else {
		switch (hw_link_info->phy_type_high) {
		case ICE_PHY_TYPE_HIGH_100G_AUI2:
			if (ice_is_media_cage_present(pi))
				return ICE_MEDIA_DA;
			/* fall-through */
		case ICE_PHY_TYPE_HIGH_100GBASE_KR2_PAM4:
			return ICE_MEDIA_BACKPLANE;
		}
	}
	return ICE_MEDIA_UNKNOWN;
}

/**
 * ice_aq_get_link_info
 * @pi: port information structure
 * @ena_lse: enable/disable LinkStatusEvent reporting
 * @link: pointer to link status structure - optional
 * @cd: pointer to command details structure or NULL
 *
 * Get Link Status (0x607). Returns the link status of the adapter.
 */
enum ice_status
ice_aq_get_link_info(struct ice_port_info *pi, bool ena_lse,
		     struct ice_link_status *link, struct ice_sq_cd *cd)
{
	struct ice_aqc_get_link_status_data link_data = { 0 };
	struct ice_aqc_get_link_status *resp;
	struct ice_link_status *li_old, *li;
	enum ice_media_type *hw_media_type;
	struct ice_fc_info *hw_fc_info;
	bool tx_pause, rx_pause;
	struct ice_aq_desc desc;
	enum ice_status status;
	struct ice_hw *hw;
	u16 cmd_flags;

	if (!pi)
		return ICE_ERR_PARAM;
	hw = pi->hw;


	li_old = &pi->phy.link_info_old;
	hw_media_type = &pi->phy.media_type;
	li = &pi->phy.link_info;
	hw_fc_info = &pi->fc;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_link_status);
	cmd_flags = (ena_lse) ? ICE_AQ_LSE_ENA : ICE_AQ_LSE_DIS;
	resp = &desc.params.get_link_status;
	resp->cmd_flags = cpu_to_le16(cmd_flags);
	resp->lport_num = pi->lport;

	status = ice_aq_send_cmd(hw, &desc, &link_data, sizeof(link_data), cd);

	if (status)
		return status;

	/* save off old link status information */
	*li_old = *li;

	/* update current link status information */
	li->link_speed = le16_to_cpu(link_data.link_speed);
	li->phy_type_low = le64_to_cpu(link_data.phy_type_low);
	li->phy_type_high = le64_to_cpu(link_data.phy_type_high);
	*hw_media_type = ice_get_media_type(pi);
	li->link_info = link_data.link_info;
	li->an_info = link_data.an_info;
	li->ext_info = link_data.ext_info;
	li->max_frame_size = le16_to_cpu(link_data.max_frame_size);
	li->fec_info = link_data.cfg & ICE_AQ_FEC_MASK;
	li->topo_media_conflict = link_data.topo_media_conflict;
	li->pacing = link_data.cfg & (ICE_AQ_CFG_PACING_M |
				      ICE_AQ_CFG_PACING_TYPE_M);

	/* update fc info */
	tx_pause = !!(link_data.an_info & ICE_AQ_LINK_PAUSE_TX);
	rx_pause = !!(link_data.an_info & ICE_AQ_LINK_PAUSE_RX);
	if (tx_pause && rx_pause)
		hw_fc_info->current_mode = ICE_FC_FULL;
	else if (tx_pause)
		hw_fc_info->current_mode = ICE_FC_TX_PAUSE;
	else if (rx_pause)
		hw_fc_info->current_mode = ICE_FC_RX_PAUSE;
	else
		hw_fc_info->current_mode = ICE_FC_NONE;

	li->lse_ena = !!(resp->cmd_flags & cpu_to_le16(ICE_AQ_LSE_IS_ENABLED));

	ice_debug(hw, ICE_DBG_LINK, "link_speed = 0x%x\n", li->link_speed);
	ice_debug(hw, ICE_DBG_LINK, "phy_type_low = 0x%llx\n",
		  (unsigned long long)li->phy_type_low);
	ice_debug(hw, ICE_DBG_LINK, "phy_type_high = 0x%llx\n",
		  (unsigned long long)li->phy_type_high);
	ice_debug(hw, ICE_DBG_LINK, "media_type = 0x%x\n", *hw_media_type);
	ice_debug(hw, ICE_DBG_LINK, "link_info = 0x%x\n", li->link_info);
	ice_debug(hw, ICE_DBG_LINK, "an_info = 0x%x\n", li->an_info);
	ice_debug(hw, ICE_DBG_LINK, "ext_info = 0x%x\n", li->ext_info);
	ice_debug(hw, ICE_DBG_LINK, "lse_ena = 0x%x\n", li->lse_ena);
	ice_debug(hw, ICE_DBG_LINK, "max_frame = 0x%x\n", li->max_frame_size);
	ice_debug(hw, ICE_DBG_LINK, "pacing = 0x%x\n", li->pacing);

	/* save link status information */
	if (link)
		*link = *li;

	/* flag cleared so calling functions don't call AQ again */
	pi->phy.get_link_info = false;

	return 0;
}


/**
 * ice_init_fltr_mgmt_struct - initializes filter management list and locks
 * @hw: pointer to the HW struct
 */
static enum ice_status ice_init_fltr_mgmt_struct(struct ice_hw *hw)
{
	struct ice_switch_info *sw;
	hw->switch_info = devm_kzalloc(ice_hw_to_dev(hw),
				       sizeof(*hw->switch_info), GFP_KERNEL);

	sw = hw->switch_info;

	if (!sw)
		return ICE_ERR_NO_MEMORY;

	INIT_LIST_HEAD(&sw->vsi_list_map_head);

	return ice_init_def_sw_recp(hw, &hw->switch_info->recp_list);
}

/**
 * ice_cleanup_fltr_mgmt_struct - cleanup filter management list and locks
 * @hw: pointer to the HW struct
 */
static void ice_cleanup_fltr_mgmt_struct(struct ice_hw *hw)
{
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_vsi_list_map_info *v_pos_map;
	struct ice_vsi_list_map_info *v_tmp_map;
	struct ice_sw_recipe *recps;
	u8 i;

	list_for_each_entry_safe(v_pos_map, v_tmp_map, &sw->vsi_list_map_head,
				 list_entry) {
		list_del(&v_pos_map->list_entry);
		devm_kfree(ice_hw_to_dev(hw), v_pos_map);
	}
	recps = hw->switch_info->recp_list;
	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		struct ice_recp_grp_entry *rg_entry, *tmprg_entry;

		recps[i].root_rid = i;
		list_for_each_entry_safe(rg_entry, tmprg_entry,
					 &recps[i].rg_list, l_entry) {
			list_del(&rg_entry->l_entry);
			devm_kfree(ice_hw_to_dev(hw), rg_entry);
		}

		if (recps[i].adv_rule) {
			struct ice_adv_fltr_mgmt_list_entry *tmp_entry;
			struct ice_adv_fltr_mgmt_list_entry *lst_itr;

			mutex_destroy(&recps[i].filt_rule_lock);
			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &recps[i].filt_rules,
						 list_entry) {
				list_del(&lst_itr->list_entry);
				devm_kfree(ice_hw_to_dev(hw), lst_itr->lkups);
				devm_kfree(ice_hw_to_dev(hw), lst_itr);
			}
		} else {
			struct ice_fltr_mgmt_list_entry *lst_itr, *tmp_entry;

			mutex_destroy(&recps[i].filt_rule_lock);
			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &recps[i].filt_rules,
						 list_entry) {
				list_del(&lst_itr->list_entry);
				devm_kfree(ice_hw_to_dev(hw), lst_itr);
			}
		}
		if (recps[i].root_buf)
			devm_kfree(ice_hw_to_dev(hw), recps[i].root_buf);
	}
	ice_rm_all_sw_replay_rule_info(hw);
	devm_kfree(ice_hw_to_dev(hw), sw->recp_list);
	devm_kfree(ice_hw_to_dev(hw), sw);
}



/**
 * ice_get_itr_intrl_gran
 * @hw: pointer to the HW struct
 *
 * Determines the ITR/INTRL granularities based on the maximum aggregate
 * bandwidth according to the device's configuration during power-on.
 */
static void ice_get_itr_intrl_gran(struct ice_hw *hw)
{
	u8 max_agg_bw = (rd32(hw, GL_PWR_MODE_CTL) &
			 GL_PWR_MODE_CTL_CAR_MAX_BW_M) >>
			GL_PWR_MODE_CTL_CAR_MAX_BW_S;

	switch (max_agg_bw) {
	case ICE_MAX_AGG_BW_200G:
	case ICE_MAX_AGG_BW_100G:
	case ICE_MAX_AGG_BW_50G:
		hw->itr_gran = ICE_ITR_GRAN_ABOVE_25;
		hw->intrl_gran = ICE_INTRL_GRAN_ABOVE_25;
		break;
	case ICE_MAX_AGG_BW_25G:
		hw->itr_gran = ICE_ITR_GRAN_MAX_25;
		hw->intrl_gran = ICE_INTRL_GRAN_MAX_25;
		break;
	}
}

/**
 * ice_get_nvm_version - get cached NVM version data
 * @hw: pointer to the hardware structure
 * @oem_ver: 8 bit NVM version
 * @oem_build: 16 bit NVM build number
 * @oem_patch: 8 NVM patch number
 * @ver_hi: high 16 bits of the NVM version
 * @ver_lo: low 16 bits of the NVM version
 */
void
ice_get_nvm_version(struct ice_hw *hw, u8 *oem_ver, u16 *oem_build,
		    u8 *oem_patch, u8 *ver_hi, u8 *ver_lo)
{
	struct ice_nvm_info *nvm = &hw->nvm;

	*oem_ver = (u8)((nvm->oem_ver & ICE_OEM_VER_MASK) >> ICE_OEM_VER_SHIFT);
	*oem_patch = (u8)(nvm->oem_ver & ICE_OEM_VER_PATCH_MASK);
	*oem_build = (u16)((nvm->oem_ver & ICE_OEM_VER_BUILD_MASK) >>
			   ICE_OEM_VER_BUILD_SHIFT);
	*ver_hi = (nvm->ver & ICE_NVM_VER_HI_MASK) >> ICE_NVM_VER_HI_SHIFT;
	*ver_lo = (nvm->ver & ICE_NVM_VER_LO_MASK) >> ICE_NVM_VER_LO_SHIFT;
}

/**
 * ice_print_rollback_msg - print FW rollback message
 * @hw: pointer to the hardware structure
 */
void ice_print_rollback_msg(struct ice_hw *hw)
{
	char nvm_str[ICE_NVM_VER_LEN] = { 0 };
	u8 oem_ver, oem_patch, ver_hi, ver_lo;
	u16 oem_build;

	ice_get_nvm_version(hw, &oem_ver, &oem_build, &oem_patch, &ver_hi,
			    &ver_lo);
	snprintf(nvm_str, sizeof(nvm_str), "%x.%02x 0x%x %d.%d.%d", ver_hi,
		 ver_lo, hw->nvm.eetrack, oem_ver, oem_build, oem_patch);
	dev_warn(ice_hw_to_dev(hw),
		 "Firmware rollback mode detected. Current version is NVM: %s, FW: %d.%d. Device may exhibit limited functionality. Refer to the Intel(R) Ethernet Adapters and Devices User Guide for details on firmware rollback mode\n",
		 nvm_str, hw->fw_maj_ver, hw->fw_min_ver);
}

/**
 * ice_init_hw - main hardware initialization routine
 * @hw: pointer to the hardware structure
 */
enum ice_status ice_init_hw(struct ice_hw *hw)
{
	struct ice_aqc_get_phy_caps_data *pcaps;
	enum ice_status status;
	u16 mac_buf_len;
	void *mac_buf;

	/* Set MAC type based on DeviceID */
	status = ice_set_mac_type(hw);
	if (status)
		return status;

	hw->pf_id = (u8)(rd32(hw, PF_FUNC_RID) &
			 PF_FUNC_RID_FUNCTION_NUMBER_M) >>
		PF_FUNC_RID_FUNCTION_NUMBER_S;


	status = ice_reset(hw, ICE_RESET_PFR);
	if (status)
		return status;

	ice_get_itr_intrl_gran(hw);


	status = ice_create_all_ctrlq(hw);
	if (status)
		goto err_unroll_cqinit;


	status = ice_init_nvm(hw);
	if (status)
		goto err_unroll_cqinit;


	if (ice_get_fw_mode(hw) == ICE_FW_MODE_ROLLBACK)
		ice_print_rollback_msg(hw);

	status = ice_clear_pf_cfg(hw);
	if (status)
		goto err_unroll_cqinit;

	/* Set bit to enable Flow Director filters */
	wr32(hw, PFQF_FD_ENA, PFQF_FD_ENA_FD_ENA_M);
	INIT_LIST_HEAD(&hw->fdir_list_head);

	ice_clear_pxe_mode(hw);

	status = ice_get_caps(hw);
	if (status)
		goto err_unroll_cqinit;

	hw->port_info = devm_kzalloc(ice_hw_to_dev(hw),
				     sizeof(*hw->port_info), GFP_KERNEL);
	if (!hw->port_info) {
		status = ICE_ERR_NO_MEMORY;
		goto err_unroll_cqinit;
	}

	/* set the back pointer to HW */
	hw->port_info->hw = hw;

	/* Initialize port_info struct with switch configuration data */
	status = ice_get_initial_sw_cfg(hw);
	if (status)
		goto err_unroll_alloc;

	hw->evb_veb = true;
	/* Query the allocated resources for Tx scheduler */
	status = ice_sched_query_res_alloc(hw);
	if (status) {
		ice_debug(hw, ICE_DBG_SCHED,
			  "Failed to get scheduler allocated resources\n");
		goto err_unroll_alloc;
	}


	/* Initialize port_info struct with scheduler data */
	status = ice_sched_init_port(hw->port_info);
	if (status)
		goto err_unroll_sched;

	pcaps = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps) {
		status = ICE_ERR_NO_MEMORY;
		goto err_unroll_sched;
	}

	/* Initialize port_info struct with PHY capabilities */
	status = ice_aq_get_phy_caps(hw->port_info, false,
				     ICE_AQC_REPORT_TOPO_CAP, pcaps, NULL);
	devm_kfree(ice_hw_to_dev(hw), pcaps);
	if (status)
		goto err_unroll_sched;

	/* Initialize port_info struct with link information */
	status = ice_aq_get_link_info(hw->port_info, false, NULL, NULL);
	if (status)
		goto err_unroll_sched;
	/* need a valid SW entry point to build a Tx tree */
	if (!hw->sw_entry_point_layer) {
		ice_debug(hw, ICE_DBG_SCHED, "invalid sw entry point\n");
		status = ICE_ERR_CFG;
		goto err_unroll_sched;
	}
	INIT_LIST_HEAD(&hw->agg_list);
	/* Initialize max burst size */
	if (!hw->max_burst_size)
		ice_cfg_rl_burst_size(hw, ICE_SCHED_DFLT_BURST_SIZE);

	status = ice_init_fltr_mgmt_struct(hw);
	if (status)
		goto err_unroll_sched;

	/* some of the register write workarounds to get Rx working */
	ice_dev_onetime_setup(hw);

	/* Get MAC information */
	/* A single port can report up to two (LAN and WoL) addresses */
	mac_buf = devm_kcalloc(ice_hw_to_dev(hw), 2,
			       sizeof(struct ice_aqc_manage_mac_read_resp),
			       GFP_KERNEL);
	mac_buf_len = 2 * sizeof(struct ice_aqc_manage_mac_read_resp);

	if (!mac_buf) {
		status = ICE_ERR_NO_MEMORY;
		goto err_unroll_fltr_mgmt_struct;
	}

	status = ice_aq_manage_mac_read(hw, mac_buf, mac_buf_len, NULL);
	devm_kfree(ice_hw_to_dev(hw), mac_buf);

	if (status)
		goto err_unroll_fltr_mgmt_struct;
	/* Obtain counter base index which would be used by flow director */
	status = ice_alloc_fd_res_cntr(hw, &hw->fd_ctr_base);
	if (status)
		goto err_unroll_fltr_mgmt_struct;
	status = ice_init_hw_tbls(hw);
	if (status)
		goto err_unroll_fltr_mgmt_struct;
	return 0;

err_unroll_fltr_mgmt_struct:
	ice_cleanup_fltr_mgmt_struct(hw);
err_unroll_sched:
	ice_sched_cleanup_all(hw);
err_unroll_alloc:
	devm_kfree(ice_hw_to_dev(hw), hw->port_info);
	hw->port_info = NULL;
err_unroll_cqinit:
	ice_destroy_all_ctrlq(hw);
	return status;
}

/**
 * ice_deinit_hw - unroll initialization operations done by ice_init_hw
 * @hw: pointer to the hardware structure
 *
 * This should be called only during nominal operation, not as a result of
 * ice_init_hw() failing since ice_init_hw() will take care of unrolling
 * applicable initializations if it fails for any reason.
 */
void ice_deinit_hw(struct ice_hw *hw)
{
	ice_free_fd_res_cntr(hw, hw->fd_ctr_base);
	ice_cleanup_fltr_mgmt_struct(hw);

	ice_sched_cleanup_all(hw);
	ice_sched_clear_agg(hw);
	ice_free_seg(hw);
	ice_free_hw_tbls(hw);

	if (hw->port_info) {
		devm_kfree(ice_hw_to_dev(hw), hw->port_info);
		hw->port_info = NULL;
	}

	ice_destroy_all_ctrlq(hw);

	/* Clear VSI contexts if not already cleared */
	ice_clear_all_vsi_ctx(hw);
}

/**
 * ice_check_reset - Check to see if a global reset is complete
 * @hw: pointer to the hardware structure
 */
enum ice_status ice_check_reset(struct ice_hw *hw)
{
	u32 cnt, reg = 0, grst_delay, uld_mask;

	/* Poll for Device Active state in case a recent CORER, GLOBR,
	 * or EMPR has occurred. The grst delay value is in 100ms units.
	 * Add 1sec for outstanding AQ commands that can take a long time.
	 */
	grst_delay = ((rd32(hw, GLGEN_RSTCTL) & GLGEN_RSTCTL_GRSTDEL_M) >>
		      GLGEN_RSTCTL_GRSTDEL_S) + 10;

	for (cnt = 0; cnt < grst_delay; cnt++) {
		msleep(100);
		reg = rd32(hw, GLGEN_RSTAT);
		if (!(reg & GLGEN_RSTAT_DEVSTATE_M))
			break;
	}

	if (cnt == grst_delay) {
		ice_debug(hw, ICE_DBG_INIT,
			  "Global reset polling failed to complete.\n");
		return ICE_ERR_RESET_FAILED;
	}

#define ICE_RESET_DONE_MASK	(GLNVM_ULD_PCIER_DONE_M |\
				 GLNVM_ULD_PCIER_DONE_1_M |\
				 GLNVM_ULD_CORER_DONE_M |\
				 GLNVM_ULD_GLOBR_DONE_M |\
				 GLNVM_ULD_POR_DONE_M |\
				 GLNVM_ULD_POR_DONE_1_M |\
				 GLNVM_ULD_PCIER_DONE_2_M)

	uld_mask = ICE_RESET_DONE_MASK | (hw->func_caps.common_cap.iwarp ?
					  GLNVM_ULD_PE_DONE_M : 0);

	/* Device is Active; check Global Reset processes are done */
	for (cnt = 0; cnt < ICE_PF_RESET_WAIT_COUNT; cnt++) {
		reg = rd32(hw, GLNVM_ULD) & uld_mask;
		if (reg == uld_mask) {
			ice_debug(hw, ICE_DBG_INIT,
				  "Global reset processes done. %d\n", cnt);
			break;
		}
		msleep(10);
	}

	if (cnt == ICE_PF_RESET_WAIT_COUNT) {
		ice_debug(hw, ICE_DBG_INIT,
			  "Wait for Reset Done timed out. GLNVM_ULD = 0x%x\n",
			  reg);
		return ICE_ERR_RESET_FAILED;
	}

	return 0;
}

/**
 * ice_pf_reset - Reset the PF
 * @hw: pointer to the hardware structure
 *
 * If a global reset has been triggered, this function checks
 * for its completion and then issues the PF reset
 */
static enum ice_status ice_pf_reset(struct ice_hw *hw)
{
	u32 cnt, reg;

	/* If at function entry a global reset was already in progress, i.e.
	 * state is not 'device active' or any of the reset done bits are not
	 * set in GLNVM_ULD, there is no need for a PF Reset; poll until the
	 * global reset is done.
	 */
	if ((rd32(hw, GLGEN_RSTAT) & GLGEN_RSTAT_DEVSTATE_M) ||
	    (rd32(hw, GLNVM_ULD) & ICE_RESET_DONE_MASK) ^ ICE_RESET_DONE_MASK) {
		/* poll on global reset currently in progress until done */
		if (ice_check_reset(hw))
			return ICE_ERR_RESET_FAILED;

		return 0;
	}

	/* Reset the PF */
	reg = rd32(hw, PFGEN_CTRL);

	wr32(hw, PFGEN_CTRL, (reg | PFGEN_CTRL_PFSWR_M));

	for (cnt = 0; cnt < ICE_PF_RESET_WAIT_COUNT; cnt++) {
		reg = rd32(hw, PFGEN_CTRL);
		if (!(reg & PFGEN_CTRL_PFSWR_M))
			break;

		msleep(1);
	}

	if (cnt == ICE_PF_RESET_WAIT_COUNT) {
		ice_debug(hw, ICE_DBG_INIT,
			  "PF reset polling failed to complete.\n");
		return ICE_ERR_RESET_FAILED;
	}

	return 0;
}

/**
 * ice_reset - Perform different types of reset
 * @hw: pointer to the hardware structure
 * @req: reset request
 *
 * This function triggers a reset as specified by the req parameter.
 *
 * Note:
 * If anything other than a PF reset is triggered, PXE mode is restored.
 * This has to be cleared using ice_clear_pxe_mode again, once the AQ
 * interface has been restored in the rebuild flow.
 */
enum ice_status ice_reset(struct ice_hw *hw, enum ice_reset_req req)
{
	u32 val = 0;

	switch (req) {
	case ICE_RESET_PFR:
		return ice_pf_reset(hw);
	case ICE_RESET_CORER:
		ice_debug(hw, ICE_DBG_INIT, "CoreR requested\n");
		val = GLGEN_RTRIG_CORER_M;
		break;
	case ICE_RESET_GLOBR:
		ice_debug(hw, ICE_DBG_INIT, "GlobalR requested\n");
		val = GLGEN_RTRIG_GLOBR_M;
		break;
	default:
		return ICE_ERR_PARAM;
	}

	val |= rd32(hw, GLGEN_RTRIG);
	wr32(hw, GLGEN_RTRIG, val);
	ice_flush(hw);


	/* wait for the FW to be ready */
	return ice_check_reset(hw);
}

/**
 * ice_get_pfa_module_tlv - Reads sub module TLV from NVM PFA
 * @hw: pointer to hardware structure
 * @module_tlv: pointer to module TLV to return
 * @module_tlv_len: pointer to module TLV length to return
 * @module_type: module type requested
 *
 * Finds the requested sub module TLV type from the Preserved Field
 * Area (PFA) and returns the TLV pointer and length. The caller can
 * use these to read the variable length TLV value.
 */
enum ice_status
ice_get_pfa_module_tlv(struct ice_hw *hw, u16 *module_tlv, u16 *module_tlv_len,
		       u16 module_type)
{
	enum ice_status status;
	u16 pfa_len, pfa_ptr;
	u16 next_tlv;

	status = ice_read_sr_word(hw, ICE_SR_PFA_PTR, &pfa_ptr);
	if (status) {
		ice_debug(hw, ICE_DBG_INIT, "Preserved Field Array pointer.\n");
		return status;
	}
	status = ice_read_sr_word(hw, pfa_ptr, &pfa_len);
	if (status) {
		ice_debug(hw, ICE_DBG_INIT, "Failed to read PFA length.\n");
		return status;
	}
	/* Starting with first TLV after PFA length, iterate through the list
	 * of TLVs to find the requested one.
	 */
	next_tlv = pfa_ptr + 1;
	while (next_tlv < pfa_ptr + pfa_len) {
		u16 tlv_sub_module_type;
		u16 tlv_len;

		/* Read TLV type */
		status = ice_read_sr_word(hw, next_tlv, &tlv_sub_module_type);
		if (status) {
			ice_debug(hw, ICE_DBG_INIT, "Failed to read TLV type.\n");
			break;
		}
		/* Read TLV length */
		status = ice_read_sr_word(hw, next_tlv + 1, &tlv_len);
		if (status) {
			ice_debug(hw, ICE_DBG_INIT, "Failed to read TLV length.\n");
			break;
		}
		if (tlv_sub_module_type == module_type) {
			if (tlv_len) {
				*module_tlv = next_tlv;
				*module_tlv_len = tlv_len;
				return 0;
			}
			return ICE_ERR_INVAL_SIZE;
		}
		/* Check next TLV, i.e. current TLV pointer + length + 2 words
		 * (for current TLV's type and length)
		 */
		next_tlv = next_tlv + tlv_len + 2;
	}
	/* Module does not exist */
	return ICE_ERR_DOES_NOT_EXIST;
}

/**
 * ice_read_pba_string - Reads part number string from NVM
 * @hw: pointer to hardware structure
 * @pba_num: stores the part number string from the NVM
 * @pba_num_size: part number string buffer length
 *
 * Reads the part number string from the NVM.
 */
enum ice_status
ice_read_pba_string(struct ice_hw *hw, u8 *pba_num, u32 pba_num_size)
{
	u16 pba_tlv, pba_tlv_len;
	enum ice_status status;
	u16 pba_word, pba_size;
	u16 i;

	status = ice_get_pfa_module_tlv(hw, &pba_tlv, &pba_tlv_len,
					ICE_SR_PBA_BLOCK_PTR);
	if (status) {
		ice_debug(hw, ICE_DBG_INIT, "Failed to read PBA Block TLV.\n");
		return status;
	}

	/* pba_size is the next word */
	status = ice_read_sr_word(hw, (pba_tlv + 2), &pba_size);
	if (status) {
		ice_debug(hw, ICE_DBG_INIT, "Failed to read PBA Section size.\n");
		return status;
	}

	if (pba_tlv_len < pba_size) {
		ice_debug(hw, ICE_DBG_INIT, "Invalid PBA Block TLV size.\n");
		return ICE_ERR_INVAL_SIZE;
	}

	/* Subtract one to get PBA word count (PBA Size word is included in
	 * total size)
	 */
	pba_size--;
	if (pba_num_size < (((u32)pba_size * 2) + 1)) {
		ice_debug(hw, ICE_DBG_INIT,
			  "Buffer too small for PBA data.\n");
		return ICE_ERR_PARAM;
	}

	for (i = 0; i < pba_size; i++) {
		status = ice_read_sr_word(hw, (pba_tlv + 2 + 1) + i, &pba_word);
		if (status) {
			ice_debug(hw, ICE_DBG_INIT,
				  "Failed to read PBA Block word %d.\n", i);
			return status;
		}

		pba_num[(i * 2)] = (pba_word >> 8) & 0xFF;
		pba_num[(i * 2) + 1] = pba_word & 0xFF;
	}
	pba_num[(pba_size * 2)] = '\0';

	return status;
}


/**
 * ice_copy_rxq_ctx_to_hw
 * @hw: pointer to the hardware structure
 * @ice_rxq_ctx: pointer to the rxq context
 * @rxq_index: the index of the Rx queue
 *
 * Copies rxq context from dense structure to HW register space
 */
static enum ice_status
ice_copy_rxq_ctx_to_hw(struct ice_hw *hw, u8 *ice_rxq_ctx, u32 rxq_index)
{
	u8 i;

	if (!ice_rxq_ctx)
		return ICE_ERR_BAD_PTR;

	if (rxq_index > QRX_CTRL_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Copy each dword separately to HW */
	for (i = 0; i < ICE_RXQ_CTX_SIZE_DWORDS; i++) {
		wr32(hw, QRX_CONTEXT(i, rxq_index),
		     *((u32 *)(ice_rxq_ctx + (i * sizeof(u32)))));

		ice_debug(hw, ICE_DBG_QCTX, "qrxdata[%d]: %08X\n", i,
			  *((u32 *)(ice_rxq_ctx + (i * sizeof(u32)))));
	}

	return 0;
}

/* LAN Rx Queue Context */
static const struct ice_ctx_ele ice_rlan_ctx_info[] = {
	/* Field		Width	LSB */
	ICE_CTX_STORE(ice_rlan_ctx, head,		13,	0),
	ICE_CTX_STORE(ice_rlan_ctx, cpuid,		8,	13),
	ICE_CTX_STORE(ice_rlan_ctx, base,		57,	32),
	ICE_CTX_STORE(ice_rlan_ctx, qlen,		13,	89),
	ICE_CTX_STORE(ice_rlan_ctx, dbuf,		7,	102),
	ICE_CTX_STORE(ice_rlan_ctx, hbuf,		5,	109),
	ICE_CTX_STORE(ice_rlan_ctx, dtype,		2,	114),
	ICE_CTX_STORE(ice_rlan_ctx, dsize,		1,	116),
	ICE_CTX_STORE(ice_rlan_ctx, crcstrip,		1,	117),
	ICE_CTX_STORE(ice_rlan_ctx, l2tsel,		1,	119),
	ICE_CTX_STORE(ice_rlan_ctx, hsplit_0,		4,	120),
	ICE_CTX_STORE(ice_rlan_ctx, hsplit_1,		2,	124),
	ICE_CTX_STORE(ice_rlan_ctx, showiv,		1,	127),
	ICE_CTX_STORE(ice_rlan_ctx, rxmax,		14,	174),
	ICE_CTX_STORE(ice_rlan_ctx, tphrdesc_ena,	1,	193),
	ICE_CTX_STORE(ice_rlan_ctx, tphwdesc_ena,	1,	194),
	ICE_CTX_STORE(ice_rlan_ctx, tphdata_ena,	1,	195),
	ICE_CTX_STORE(ice_rlan_ctx, tphhead_ena,	1,	196),
	ICE_CTX_STORE(ice_rlan_ctx, lrxqthresh,		3,	198),
	ICE_CTX_STORE(ice_rlan_ctx, prefena,		1,	201),
	{ 0 }
};

/**
 * ice_write_rxq_ctx
 * @hw: pointer to the hardware structure
 * @rlan_ctx: pointer to the rxq context
 * @rxq_index: the index of the Rx queue
 *
 * Converts rxq context from sparse to dense structure and then writes
 * it to HW register space and enables the hardware to prefetch descriptors
 * instead of only fetching them on demand
 */
enum ice_status
ice_write_rxq_ctx(struct ice_hw *hw, struct ice_rlan_ctx *rlan_ctx,
		  u32 rxq_index)
{
	u8 ctx_buf[ICE_RXQ_CTX_SZ] = { 0 };

	if (!rlan_ctx)
		return ICE_ERR_BAD_PTR;

	rlan_ctx->prefena = 1;

	ice_set_ctx((u8 *)rlan_ctx, ctx_buf, ice_rlan_ctx_info);
	return ice_copy_rxq_ctx_to_hw(hw, ctx_buf, rxq_index);
}

/**
 * ice_clear_rxq_ctx
 * @hw: pointer to the hardware structure
 * @rxq_index: the index of the Rx queue to clear
 *
 * Clears rxq context in HW register space
 */
enum ice_status ice_clear_rxq_ctx(struct ice_hw *hw, u32 rxq_index)
{
	u8 i;

	if (rxq_index > QRX_CTRL_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Clear each dword register separately */
	for (i = 0; i < ICE_RXQ_CTX_SIZE_DWORDS; i++)
		wr32(hw, QRX_CONTEXT(i, rxq_index), 0);

	return 0;
}

/* LAN Tx Queue Context */
const struct ice_ctx_ele ice_tlan_ctx_info[] = {
				    /* Field			Width	LSB */
	ICE_CTX_STORE(ice_tlan_ctx, base,			57,	0),
	ICE_CTX_STORE(ice_tlan_ctx, port_num,			3,	57),
	ICE_CTX_STORE(ice_tlan_ctx, cgd_num,			5,	60),
	ICE_CTX_STORE(ice_tlan_ctx, pf_num,			3,	65),
	ICE_CTX_STORE(ice_tlan_ctx, vmvf_num,			10,	68),
	ICE_CTX_STORE(ice_tlan_ctx, vmvf_type,			2,	78),
	ICE_CTX_STORE(ice_tlan_ctx, src_vsi,			10,	80),
	ICE_CTX_STORE(ice_tlan_ctx, tsyn_ena,			1,	90),
	ICE_CTX_STORE(ice_tlan_ctx, internal_usage_flag,	1,	91),
	ICE_CTX_STORE(ice_tlan_ctx, alt_vlan,			1,	92),
	ICE_CTX_STORE(ice_tlan_ctx, cpuid,			8,	93),
	ICE_CTX_STORE(ice_tlan_ctx, wb_mode,			1,	101),
	ICE_CTX_STORE(ice_tlan_ctx, tphrd_desc,			1,	102),
	ICE_CTX_STORE(ice_tlan_ctx, tphrd,			1,	103),
	ICE_CTX_STORE(ice_tlan_ctx, tphwr_desc,			1,	104),
	ICE_CTX_STORE(ice_tlan_ctx, cmpq_id,			9,	105),
	ICE_CTX_STORE(ice_tlan_ctx, qnum_in_func,		14,	114),
	ICE_CTX_STORE(ice_tlan_ctx, itr_notification_mode,	1,	128),
	ICE_CTX_STORE(ice_tlan_ctx, adjust_prof_id,		6,	129),
	ICE_CTX_STORE(ice_tlan_ctx, qlen,			13,	135),
	ICE_CTX_STORE(ice_tlan_ctx, quanta_prof_idx,		4,	148),
	ICE_CTX_STORE(ice_tlan_ctx, tso_ena,			1,	152),
	ICE_CTX_STORE(ice_tlan_ctx, tso_qnum,			11,	153),
	ICE_CTX_STORE(ice_tlan_ctx, legacy_int,			1,	164),
	ICE_CTX_STORE(ice_tlan_ctx, drop_ena,			1,	165),
	ICE_CTX_STORE(ice_tlan_ctx, cache_prof_idx,		2,	166),
	ICE_CTX_STORE(ice_tlan_ctx, pkt_shaper_prof_idx,	3,	168),
	ICE_CTX_STORE(ice_tlan_ctx, int_q_state,		122,	171),
	{ 0 }
};

/**
 * ice_copy_tx_cmpltnq_ctx_to_hw
 * @hw: pointer to the hardware structure
 * @ice_tx_cmpltnq_ctx: pointer to the Tx completion queue context
 * @tx_cmpltnq_index: the index of the completion queue
 *
 * Copies Tx completion queue context from dense structure to HW register space
 */
static enum ice_status
ice_copy_tx_cmpltnq_ctx_to_hw(struct ice_hw *hw, u8 *ice_tx_cmpltnq_ctx,
			      u32 tx_cmpltnq_index)
{
	u8 i;

	if (!ice_tx_cmpltnq_ctx)
		return ICE_ERR_BAD_PTR;

	if (tx_cmpltnq_index > GLTCLAN_CQ_CNTX0_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Copy each dword separately to HW */
	for (i = 0; i < ICE_TX_CMPLTNQ_CTX_SIZE_DWORDS; i++) {
		wr32(hw, GLTCLAN_CQ_CNTX(i, tx_cmpltnq_index),
		     *((u32 *)(ice_tx_cmpltnq_ctx + (i * sizeof(u32)))));

		ice_debug(hw, ICE_DBG_QCTX, "cmpltnqdata[%d]: %08X\n", i,
			  *((u32 *)(ice_tx_cmpltnq_ctx + (i * sizeof(u32)))));
	}

	return 0;
}

/* LAN Tx Completion Queue Context */
static const struct ice_ctx_ele ice_tx_cmpltnq_ctx_info[] = {
				       /* Field			Width   LSB */
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, base,			57,	0),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, q_len,		18,	64),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, generation,		1,	96),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, wrt_ptr,		22,	97),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, pf_num,		3,	128),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, vmvf_num,		10,	131),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, vmvf_type,		2,	141),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, tph_desc_wr,		1,	160),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, cpuid,		8,	161),
	ICE_CTX_STORE(ice_tx_cmpltnq_ctx, cmpltn_cache,		512,	192),
	{ 0 }
};

/**
 * ice_write_tx_cmpltnq_ctx
 * @hw: pointer to the hardware structure
 * @tx_cmpltnq_ctx: pointer to the completion queue context
 * @tx_cmpltnq_index: the index of the completion queue
 *
 * Converts completion queue context from sparse to dense structure and then
 * writes it to HW register space
 */
enum ice_status
ice_write_tx_cmpltnq_ctx(struct ice_hw *hw,
			 struct ice_tx_cmpltnq_ctx *tx_cmpltnq_ctx,
			 u32 tx_cmpltnq_index)
{
	u8 ctx_buf[ICE_TX_CMPLTNQ_CTX_SIZE_DWORDS * sizeof(u32)] = { 0 };

	ice_set_ctx((u8 *)tx_cmpltnq_ctx, ctx_buf, ice_tx_cmpltnq_ctx_info);
	return ice_copy_tx_cmpltnq_ctx_to_hw(hw, ctx_buf, tx_cmpltnq_index);
}

/**
 * ice_clear_tx_cmpltnq_ctx
 * @hw: pointer to the hardware structure
 * @tx_cmpltnq_index: the index of the completion queue to clear
 *
 * Clears Tx completion queue context in HW register space
 */
enum ice_status
ice_clear_tx_cmpltnq_ctx(struct ice_hw *hw, u32 tx_cmpltnq_index)
{
	u8 i;

	if (tx_cmpltnq_index > GLTCLAN_CQ_CNTX0_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Clear each dword register separately */
	for (i = 0; i < ICE_TX_CMPLTNQ_CTX_SIZE_DWORDS; i++)
		wr32(hw, GLTCLAN_CQ_CNTX(i, tx_cmpltnq_index), 0);

	return 0;
}

/**
 * ice_copy_tx_drbell_q_ctx_to_hw
 * @hw: pointer to the hardware structure
 * @ice_tx_drbell_q_ctx: pointer to the doorbell queue context
 * @tx_drbell_q_index: the index of the doorbell queue
 *
 * Copies doorbell queue context from dense structure to HW register space
 */
static enum ice_status
ice_copy_tx_drbell_q_ctx_to_hw(struct ice_hw *hw, u8 *ice_tx_drbell_q_ctx,
			       u32 tx_drbell_q_index)
{
	u8 i;

	if (!ice_tx_drbell_q_ctx)
		return ICE_ERR_BAD_PTR;

	if (tx_drbell_q_index > QTX_COMM_DBLQ_DBELL_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Copy each dword separately to HW */
	for (i = 0; i < ICE_TX_DRBELL_Q_CTX_SIZE_DWORDS; i++) {
		wr32(hw, QTX_COMM_DBLQ_CNTX(i, tx_drbell_q_index),
		     *((u32 *)(ice_tx_drbell_q_ctx + (i * sizeof(u32)))));

		ice_debug(hw, ICE_DBG_QCTX, "tx_drbell_qdata[%d]: %08X\n", i,
			  *((u32 *)(ice_tx_drbell_q_ctx + (i * sizeof(u32)))));
	}

	return 0;
}

/* LAN Tx Doorbell Queue Context info */
static const struct ice_ctx_ele ice_tx_drbell_q_ctx_info[] = {
					/* Field		Width   LSB */
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, base,		57,	0),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, ring_len,		13,	64),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, pf_num,		3,	80),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, vf_num,		8,	84),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, vmvf_type,		2,	94),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, cpuid,		8,	96),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, tph_desc_rd,		1,	104),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, tph_desc_wr,		1,	108),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, db_q_en,		1,	112),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, rd_head,		13,	128),
	ICE_CTX_STORE(ice_tx_drbell_q_ctx, rd_tail,		13,	144),
	{ 0 }
};

/**
 * ice_write_tx_drbell_q_ctx
 * @hw: pointer to the hardware structure
 * @tx_drbell_q_ctx: pointer to the doorbell queue context
 * @tx_drbell_q_index: the index of the doorbell queue
 *
 * Converts doorbell queue context from sparse to dense structure and then
 * writes it to HW register space
 */
enum ice_status
ice_write_tx_drbell_q_ctx(struct ice_hw *hw,
			  struct ice_tx_drbell_q_ctx *tx_drbell_q_ctx,
			  u32 tx_drbell_q_index)
{
	u8 ctx_buf[ICE_TX_DRBELL_Q_CTX_SIZE_DWORDS * sizeof(u32)] = { 0 };

	ice_set_ctx((u8 *)tx_drbell_q_ctx, ctx_buf, ice_tx_drbell_q_ctx_info);
	return ice_copy_tx_drbell_q_ctx_to_hw(hw, ctx_buf, tx_drbell_q_index);
}

/**
 * ice_clear_tx_drbell_q_ctx
 * @hw: pointer to the hardware structure
 * @tx_drbell_q_index: the index of the doorbell queue to clear
 *
 * Clears doorbell queue context in HW register space
 */
enum ice_status
ice_clear_tx_drbell_q_ctx(struct ice_hw *hw, u32 tx_drbell_q_index)
{
	u8 i;

	if (tx_drbell_q_index > QTX_COMM_DBLQ_DBELL_MAX_INDEX)
		return ICE_ERR_PARAM;

	/* Clear each dword register separately */
	for (i = 0; i < ICE_TX_DRBELL_Q_CTX_SIZE_DWORDS; i++)
		wr32(hw, QTX_COMM_DBLQ_CNTX(i, tx_drbell_q_index), 0);

	return 0;
}


/* FW Admin Queue command wrappers */

/* Software lock/mutex that is meant to be held while the Global Config Lock
 * in firmware is acquired by the software to prevent most (but not all) types
 * of AQ commands from being sent to FW
 */
DEFINE_MUTEX(ice_global_cfg_lock_sw);

/**
 * ice_aq_send_cmd - send FW Admin Queue command to FW Admin Queue
 * @hw: pointer to the HW struct
 * @desc: descriptor describing the command
 * @buf: buffer to use for indirect commands (NULL for direct commands)
 * @buf_size: size of buffer for indirect commands (0 for direct commands)
 * @cd: pointer to command details structure
 *
 * Helper function to send FW Admin Queue commands to the FW Admin Queue.
 */
enum ice_status
ice_aq_send_cmd(struct ice_hw *hw, struct ice_aq_desc *desc, void *buf,
		u16 buf_size, struct ice_sq_cd *cd)
{
	struct ice_aqc_req_res *cmd = &desc->params.res_owner;
	bool lock_acquired = false;
	enum ice_status status;

	/* When a package download is in process (i.e. when the firmware's
	 * Global Configuration Lock resource is held), only the Download
	 * Package, Get Version, Get Package Info List and Release Resource
	 * (with resource ID set to Global Config Lock) AdminQ commands are
	 * allowed; all others must block until the package download completes
	 * and the Global Config Lock is released.  See also
	 * ice_acquire_global_cfg_lock().
	 */
	switch (le16_to_cpu(desc->opcode)) {
	case ice_aqc_opc_download_pkg:
	case ice_aqc_opc_get_pkg_info_list:
	case ice_aqc_opc_get_ver:
		break;
	case ice_aqc_opc_release_res:
		if (le16_to_cpu(cmd->res_id) == ICE_AQC_RES_ID_GLBL_LOCK)
			break;
		/* fall-through */
	default:
		mutex_lock(&ice_global_cfg_lock_sw);
		lock_acquired = true;
		break;
	}

	status = ice_sq_send_cmd(hw, &hw->adminq, desc, buf, buf_size, cd);
	if (lock_acquired)
		mutex_unlock(&ice_global_cfg_lock_sw);

	return status;
}

/**
 * ice_aq_get_fw_ver
 * @hw: pointer to the HW struct
 * @cd: pointer to command details structure or NULL
 *
 * Get the firmware version (0x0001) from the admin queue commands
 */
enum ice_status ice_aq_get_fw_ver(struct ice_hw *hw, struct ice_sq_cd *cd)
{
	struct ice_aqc_get_ver *resp;
	struct ice_aq_desc desc;
	enum ice_status status;

	resp = &desc.params.get_ver;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_ver);

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, cd);

	if (!status) {
		hw->fw_branch = resp->fw_branch;
		hw->fw_maj_ver = resp->fw_major;
		hw->fw_min_ver = resp->fw_minor;
		hw->fw_patch = resp->fw_patch;
		hw->fw_build = le32_to_cpu(resp->fw_build);
		hw->api_branch = resp->api_branch;
		hw->api_maj_ver = resp->api_major;
		hw->api_min_ver = resp->api_minor;
		hw->api_patch = resp->api_patch;
	}

	return status;
}

/**
 * ice_aq_send_driver_ver
 * @hw: pointer to the HW struct
 * @dv: driver's major, minor version
 * @cd: pointer to command details structure or NULL
 *
 * Send the driver version (0x0002) to the firmware
 */
enum ice_status
ice_aq_send_driver_ver(struct ice_hw *hw, struct ice_driver_ver *dv,
		       struct ice_sq_cd *cd)
{
	struct ice_aqc_driver_ver *cmd;
	struct ice_aq_desc desc;
	u16 len;

	cmd = &desc.params.driver_ver;

	if (!dv)
		return ICE_ERR_PARAM;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_driver_ver);

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);
	cmd->major_ver = dv->major_ver;
	cmd->minor_ver = dv->minor_ver;
	cmd->build_ver = dv->build_ver;
	cmd->subbuild_ver = dv->subbuild_ver;

	len = 0;
	while (len < sizeof(dv->driver_string) &&
	       isascii(dv->driver_string[len]) && dv->driver_string[len])
		len++;

	return ice_aq_send_cmd(hw, &desc, dv->driver_string, len, cd);
}

/**
 * ice_aq_q_shutdown
 * @hw: pointer to the HW struct
 * @unloading: is the driver unloading itself
 *
 * Tell the Firmware that we're shutting down the AdminQ and whether
 * or not the driver is unloading as well (0x0003).
 */
enum ice_status ice_aq_q_shutdown(struct ice_hw *hw, bool unloading)
{
	struct ice_aqc_q_shutdown *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.q_shutdown;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_q_shutdown);

	if (unloading)
		cmd->driver_unloading = ICE_AQC_DRIVER_UNLOADING;

	return ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

/**
 * ice_aq_req_res
 * @hw: pointer to the HW struct
 * @res: resource ID
 * @access: access type
 * @sdp_number: resource number
 * @timeout: the maximum time in ms that the driver may hold the resource
 * @cd: pointer to command details structure or NULL
 *
 * Requests common resource using the admin queue commands (0x0008).
 * When attempting to acquire the Global Config Lock, the driver can
 * learn of three states:
 *  1) ICE_SUCCESS -        acquired lock, and can perform download package
 *  2) ICE_ERR_AQ_ERROR -   did not get lock, driver should fail to load
 *  3) ICE_ERR_AQ_NO_WORK - did not get lock, but another driver has
 *                          successfully downloaded the package; the driver does
 *                          not have to download the package and can continue
 *                          loading
 *
 * Note that if the caller is in an acquire lock, perform action, release lock
 * phase of operation, it is possible that the FW may detect a timeout and issue
 * a CORER. In this case, the driver will receive a CORER interrupt and will
 * have to determine its cause. The calling thread that is handling this flow
 * will likely get an error propagated back to it indicating the Download
 * Package, Update Package or the Release Resource AQ commands timed out.
 */
static enum ice_status
ice_aq_req_res(struct ice_hw *hw, enum ice_aq_res_ids res,
	       enum ice_aq_res_access_type access, u8 sdp_number, u32 *timeout,
	       struct ice_sq_cd *cd)
{
	struct ice_aqc_req_res *cmd_resp;
	struct ice_aq_desc desc;
	enum ice_status status;

	cmd_resp = &desc.params.res_owner;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_req_res);

	cmd_resp->res_id = cpu_to_le16(res);
	cmd_resp->access_type = cpu_to_le16(access);
	cmd_resp->res_number = cpu_to_le32(sdp_number);
	cmd_resp->timeout = cpu_to_le32(*timeout);
	*timeout = 0;

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, cd);

	/* The completion specifies the maximum time in ms that the driver
	 * may hold the resource in the Timeout field.
	 */

	/* Global config lock response utilizes an additional status field.
	 *
	 * If the Global config lock resource is held by some other driver, the
	 * command completes with ICE_AQ_RES_GLBL_IN_PROG in the status field
	 * and the timeout field indicates the maximum time the current owner
	 * of the resource has to free it.
	 */
	if (res == ICE_GLOBAL_CFG_LOCK_RES_ID) {
		if (le16_to_cpu(cmd_resp->status) == ICE_AQ_RES_GLBL_SUCCESS) {
			*timeout = le32_to_cpu(cmd_resp->timeout);
			return 0;
		} else if (le16_to_cpu(cmd_resp->status) ==
			   ICE_AQ_RES_GLBL_IN_PROG) {
			*timeout = le32_to_cpu(cmd_resp->timeout);
			return ICE_ERR_AQ_ERROR;
		} else if (le16_to_cpu(cmd_resp->status) ==
			   ICE_AQ_RES_GLBL_DONE) {
			return ICE_ERR_AQ_NO_WORK;
		}

		/* invalid FW response, force a timeout immediately */
		*timeout = 0;
		return ICE_ERR_AQ_ERROR;
	}

	/* If the resource is held by some other driver, the command completes
	 * with a busy return value and the timeout field indicates the maximum
	 * time the current owner of the resource has to free it.
	 */
	if (!status || hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY)
		*timeout = le32_to_cpu(cmd_resp->timeout);

	return status;
}

/**
 * ice_aq_release_res
 * @hw: pointer to the HW struct
 * @res: resource ID
 * @sdp_number: resource number
 * @cd: pointer to command details structure or NULL
 *
 * release common resource using the admin queue commands (0x0009)
 */
static enum ice_status
ice_aq_release_res(struct ice_hw *hw, enum ice_aq_res_ids res, u8 sdp_number,
		   struct ice_sq_cd *cd)
{
	struct ice_aqc_req_res *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.res_owner;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_release_res);

	cmd->res_id = cpu_to_le16(res);
	cmd->res_number = cpu_to_le32(sdp_number);

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_acquire_res
 * @hw: pointer to the HW structure
 * @res: resource ID
 * @access: access type (read or write)
 * @timeout: timeout in milliseconds
 *
 * This function will attempt to acquire the ownership of a resource.
 */
enum ice_status
ice_acquire_res(struct ice_hw *hw, enum ice_aq_res_ids res,
		enum ice_aq_res_access_type access, u32 timeout)
{
#define ICE_RES_POLLING_DELAY_MS	10
	u32 delay = ICE_RES_POLLING_DELAY_MS;
	u32 time_left = timeout;
	enum ice_status status;

	status = ice_aq_req_res(hw, res, access, 0, &time_left, NULL);

	/* A return code of ICE_ERR_AQ_NO_WORK means that another driver has
	 * previously acquired the resource and performed any necessary updates;
	 * in this case the caller does not obtain the resource and has no
	 * further work to do.
	 */
	if (status == ICE_ERR_AQ_NO_WORK)
		goto ice_acquire_res_exit;

	if (status)
		ice_debug(hw, ICE_DBG_RES,
			  "resource %d acquire type %d failed.\n", res, access);

	/* If necessary, poll until the current lock owner timeouts */
	timeout = time_left;
	while (status && timeout && time_left) {
		msleep(delay);
		timeout = (timeout > delay) ? timeout - delay : 0;
		status = ice_aq_req_res(hw, res, access, 0, &time_left, NULL);

		if (status == ICE_ERR_AQ_NO_WORK)
			/* lock free, but no work to do */
			break;

		if (!status)
			/* lock acquired */
			break;
	}
	if (status && status != ICE_ERR_AQ_NO_WORK)
		ice_debug(hw, ICE_DBG_RES, "resource acquire timed out.\n");

ice_acquire_res_exit:
	if (status == ICE_ERR_AQ_NO_WORK) {
		if (access == ICE_RES_WRITE)
			ice_debug(hw, ICE_DBG_RES,
				  "resource indicates no work to do.\n");
		else
			ice_debug(hw, ICE_DBG_RES,
				  "Warning: ICE_ERR_AQ_NO_WORK not expected\n");
	}
	return status;
}

/**
 * ice_release_res
 * @hw: pointer to the HW structure
 * @res: resource ID
 *
 * This function will release a resource using the proper Admin Command.
 */
void ice_release_res(struct ice_hw *hw, enum ice_aq_res_ids res)
{
	enum ice_status status;
	u32 total_delay = 0;

	status = ice_aq_release_res(hw, res, 0, NULL);

	/* there are some rare cases when trying to release the resource
	 * results in an admin queue timeout, so handle them correctly
	 */
	while ((status == ICE_ERR_AQ_TIMEOUT) &&
	       (total_delay < hw->adminq.sq_cmd_timeout)) {
		msleep(1);
		status = ice_aq_release_res(hw, res, 0, NULL);
		total_delay++;
	}
}

/**
 * ice_aq_alloc_free_res - command to allocate/free resources
 * @hw: pointer to the HW struct
 * @num_entries: number of resource entries in buffer
 * @buf: Indirect buffer to hold data parameters and response
 * @buf_size: size of buffer for indirect commands
 * @opc: pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 * Helper function to allocate/free resources using the admin queue commands
 */
enum ice_status
ice_aq_alloc_free_res(struct ice_hw *hw, u16 num_entries,
		      struct ice_aqc_alloc_free_res_elem *buf, u16 buf_size,
		      enum ice_adminq_opc opc, struct ice_sq_cd *cd)
{
	struct ice_aqc_alloc_free_res_cmd *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.sw_res_ctrl;

	if (!buf)
		return ICE_ERR_PARAM;

	if (buf_size < (num_entries * sizeof(buf->elem[0])))
		return ICE_ERR_PARAM;

	ice_fill_dflt_direct_cmd_desc(&desc, opc);

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	cmd->num_entries = cpu_to_le16(num_entries);

	return ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);
}

/**
 * ice_alloc_hw_res - allocate resource
 * @hw: pointer to the HW struct
 * @type: type of resource
 * @num: number of resources to allocate
 * @btm: allocate from bottom
 * @res: pointer to array that will receive the resources
 */
enum ice_status
ice_alloc_hw_res(struct ice_hw *hw, u16 type, u16 num, bool btm, u16 *res)
{
	struct ice_aqc_alloc_free_res_elem *buf;
	enum ice_status status;
	u16 buf_len;

	buf_len = sizeof(*buf) + sizeof(buf->elem) * (num - 1);
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!buf)
		return ICE_ERR_NO_MEMORY;

	/* Prepare buffer to allocate resource. */
	buf->num_elems = cpu_to_le16(num);
	buf->res_type = cpu_to_le16(type | ICE_AQC_RES_TYPE_FLAG_DEDICATED |
				    ICE_AQC_RES_TYPE_FLAG_IGNORE_INDEX);
	if (btm)
		buf->res_type |= cpu_to_le16(ICE_AQC_RES_TYPE_FLAG_SCAN_BOTTOM);

	status = ice_aq_alloc_free_res(hw, 1, buf, buf_len,
				       ice_aqc_opc_alloc_res, NULL);
	if (status)
		goto ice_alloc_res_exit;

	memcpy(res, buf->elem, sizeof(buf->elem) * num);

ice_alloc_res_exit:
	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_free_hw_res - free allocated HW resource
 * @hw: pointer to the HW struct
 * @type: type of resource to free
 * @num: number of resources
 * @res: pointer to array that contains the resources to free
 */
enum ice_status
ice_free_hw_res(struct ice_hw *hw, u16 type, u16 num, u16 *res)
{
	struct ice_aqc_alloc_free_res_elem *buf;
	enum ice_status status;
	u16 buf_len;

	buf_len = sizeof(*buf) + sizeof(buf->elem) * (num - 1);
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!buf)
		return ICE_ERR_NO_MEMORY;

	/* Prepare buffer to free resource. */
	buf->num_elems = cpu_to_le16(num);
	buf->res_type = cpu_to_le16(type);
	memcpy(buf->elem, res, sizeof(buf->elem) * num);

	status = ice_aq_alloc_free_res(hw, num, buf, buf_len,
				       ice_aqc_opc_free_res, NULL);
	if (status)
		ice_debug(hw, ICE_DBG_SW, "CQ CMD Buffer:\n");

	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_get_num_per_func - determine number of resources per PF
 * @hw: pointer to the HW structure
 * @max: value to be evenly split between each PF
 *
 * Determine the number of valid functions by going through the bitmap returned
 * from parsing capabilities and use this to calculate the number of resources
 * per PF based on the max value passed in.
 */
static u32 ice_get_num_per_func(struct ice_hw *hw, u32 max)
{
	u8 funcs;

#define ICE_CAPS_VALID_FUNCS_M	0xFF
	funcs = hweight8(hw->dev_caps.common_cap.valid_functions & ICE_CAPS_VALID_FUNCS_M);

	if (!funcs)
		return 0;

	return max / funcs;
}

/**
 * ice_print_led_caps - print LED capabilities
 * @hw: pointer to the ice_hw instance
 * @caps: pointer to common caps instance
 * @prefix: string to prefix when printing
 * @debug: set to indicate debug print
 */
static void
ice_print_led_caps(struct ice_hw *hw, struct ice_hw_common_caps *caps,
		   char const *prefix, bool debug)
{
	u8 i;

	if (debug)
		ice_debug(hw, ICE_DBG_INIT, "%s: led_pin_num = %d\n", prefix,
			  caps->led_pin_num);
	else
		dev_info(ice_hw_to_dev(hw), "%s: led_pin_num = %d\n", prefix,
			 caps->led_pin_num);

	for (i = 0; i < ICE_MAX_SUPPORTED_GPIO_LED; i++) {
		if (!caps->led[i])
			continue;

		if (debug)
			ice_debug(hw, ICE_DBG_INIT, "%s: led[%d] = %d\n",
				  prefix, i, caps->led[i]);
		else
			dev_info(ice_hw_to_dev(hw), "%s: led[%d] = %d\n",
				 prefix, i, caps->led[i]);
	}
}

/**
 * ice_print_sdp_caps - print SDP capabilities
 * @hw: pointer to the ice_hw instance
 * @caps: pointer to common caps instance
 * @prefix: string to prefix when printing
 * @debug: set to indicate debug print
 */
static void
ice_print_sdp_caps(struct ice_hw *hw, struct ice_hw_common_caps *caps,
		   char const *prefix, bool debug)
{
	u8 i;

	if (debug)
		ice_debug(hw, ICE_DBG_INIT, "%s: sdp_pin_num = %d\n", prefix,
			  caps->sdp_pin_num);
	else
		dev_info(ice_hw_to_dev(hw), "%s: sdp_pin_num = %d\n", prefix,
			 caps->sdp_pin_num);

	for (i = 0; i < ICE_MAX_SUPPORTED_GPIO_SDP; i++) {
		if (!caps->sdp[i])
			continue;

		if (debug)
			ice_debug(hw, ICE_DBG_INIT, "%s: sdp[%d] = %d\n",
				  prefix, i, caps->sdp[i]);
		else
			dev_info(ice_hw_to_dev(hw), "%s: sdp[%d] = %d\n",
				 prefix, i, caps->sdp[i]);
	}
}

/**
 * ice_parse_caps - parse function/device capabilities
 * @hw: pointer to the HW struct
 * @buf: pointer to a buffer containing function/device capability records
 * @cap_count: number of capability records in the list
 * @opc: type of capabilities list to parse
 *
 * Helper function to parse function(0x000a)/device(0x000b) capabilities list.
 */
static void
ice_parse_caps(struct ice_hw *hw, void *buf, u32 cap_count,
	       enum ice_adminq_opc opc)
{
	struct ice_aqc_list_caps_elem *cap_resp;
	struct ice_hw_func_caps *func_p = NULL;
	struct ice_hw_dev_caps *dev_p = NULL;
	struct ice_hw_common_caps *caps;
	char const *prefix;
	u32 i;

	if (!buf)
		return;

	cap_resp = (struct ice_aqc_list_caps_elem *)buf;

	if (opc == ice_aqc_opc_list_dev_caps) {
		dev_p = &hw->dev_caps;
		caps = &dev_p->common_cap;
		prefix = "dev cap";
	} else if (opc == ice_aqc_opc_list_func_caps) {
		func_p = &hw->func_caps;
		caps = &func_p->common_cap;
		prefix = "func cap";
	} else {
		ice_debug(hw, ICE_DBG_INIT, "wrong opcode\n");
		return;
	}

	for (i = 0; caps && i < cap_count; i++, cap_resp++) {
		u32 logical_id = le32_to_cpu(cap_resp->logical_id);
		u32 phys_id = le32_to_cpu(cap_resp->phys_id);
		u32 number = le32_to_cpu(cap_resp->number);
		u16 cap = le16_to_cpu(cap_resp->cap);

		switch (cap) {
		case ICE_AQC_CAPS_SWITCHING_MODE:
			caps->switching_mode = number;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: switching_mode = %d\n", prefix,
				  caps->switching_mode);
			break;
		case ICE_AQC_CAPS_MANAGEABILITY_MODE:
			caps->mgmt_mode = number;
			caps->mgmt_protocols_mctp = logical_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: mgmt_mode = %d\n", prefix,
				  caps->mgmt_mode);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: mgmt_protocols_mctp = %d\n", prefix,
				  caps->mgmt_protocols_mctp);
			break;
		case ICE_AQC_CAPS_OS2BMC:
			caps->os2bmc = number;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: os2bmc = %d\n", prefix, caps->os2bmc);
			break;
		case ICE_AQC_CAPS_VALID_FUNCTIONS:
			caps->valid_functions = number;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: valid_functions (bitmap) = %d\n", prefix,
				  caps->valid_functions);

			/* store func count for resource management purposes */
			if (dev_p)
				dev_p->num_funcs = hweight32(number);
			break;
		case ICE_AQC_CAPS_SRIOV:
			caps->sr_iov_1_1 = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: sr_iov_1_1 = %d\n", prefix,
				  caps->sr_iov_1_1);
			break;
		case ICE_AQC_CAPS_VF:
			if (dev_p) {
				dev_p->num_vfs_exposed = number;
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: num_vfs_exposed = %d\n", prefix,
					  dev_p->num_vfs_exposed);
			} else if (func_p) {
				func_p->num_allocd_vfs = number;
				func_p->vf_base_id = logical_id;
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: num_allocd_vfs = %d\n", prefix,
					  func_p->num_allocd_vfs);
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: vf_base_id = %d\n", prefix,
					  func_p->vf_base_id);
			}
			break;
		case ICE_AQC_CAPS_VMDQ:
			caps->vmdq = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: vmdq = %d\n", prefix, caps->vmdq);
			break;
		case ICE_AQC_CAPS_802_1QBG:
			caps->evb_802_1_qbg = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: evb_802_1_qbg = %d\n", prefix, number);
			break;
		case ICE_AQC_CAPS_802_1BR:
			caps->evb_802_1_qbh = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: evb_802_1_qbh = %d\n", prefix, number);
			break;
		case ICE_AQC_CAPS_VSI:
			if (dev_p) {
				dev_p->num_vsi_allocd_to_host = number;
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: num_vsi_allocd_to_host = %d\n",
					  prefix,
					  dev_p->num_vsi_allocd_to_host);
			} else if (func_p) {
				func_p->guar_num_vsi =
					ice_get_num_per_func(hw, ICE_MAX_VSI);
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: guar_num_vsi (fw) = %d\n",
					  prefix, number);
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: guar_num_vsi = %d\n",
					  prefix, func_p->guar_num_vsi);
			}
			break;
		case ICE_AQC_CAPS_DCB:
			caps->dcb = (number == 1);
			caps->active_tc_bitmap = logical_id;
			caps->maxtc = phys_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: dcb = %d\n", prefix, caps->dcb);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: active_tc_bitmap = %d\n", prefix,
				  caps->active_tc_bitmap);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: maxtc = %d\n", prefix, caps->maxtc);
			break;
		case ICE_AQC_CAPS_ISCSI:
			caps->iscsi = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: iscsi = %d\n", prefix, caps->iscsi);
			break;
		case ICE_AQC_CAPS_RSS:
			caps->rss_table_size = number;
			caps->rss_table_entry_width = logical_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: rss_table_size = %d\n", prefix,
				  caps->rss_table_size);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: rss_table_entry_width = %d\n", prefix,
				  caps->rss_table_entry_width);
			break;
		case ICE_AQC_CAPS_RXQS:
			caps->num_rxq = number;
			caps->rxq_first_id = phys_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: num_rxq = %d\n", prefix,
				  caps->num_rxq);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: rxq_first_id = %d\n", prefix,
				  caps->rxq_first_id);
			break;
		case ICE_AQC_CAPS_TXQS:
			caps->num_txq = number;
			caps->txq_first_id = phys_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: num_txq = %d\n", prefix,
				  caps->num_txq);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: txq_first_id = %d\n", prefix,
				  caps->txq_first_id);
			break;
		case ICE_AQC_CAPS_MSIX:
			caps->num_msix_vectors = number;
			caps->msix_vector_first_id = phys_id;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: num_msix_vectors = %d\n", prefix,
				  caps->num_msix_vectors);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: msix_vector_first_id = %d\n", prefix,
				  caps->msix_vector_first_id);
			break;
		case ICE_AQC_CAPS_FD:
		{
			u32 reg_val, val;

			if (dev_p) {
				dev_p->num_flow_director_fltr = number;
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: num_flow_director_fltr = %d\n",
					  prefix,
					  dev_p->num_flow_director_fltr);
			}
			if (func_p) {
				reg_val = rd32(hw, GLQF_FD_SIZE);
				val = (reg_val & GLQF_FD_SIZE_FD_GSIZE_M) >>
				      GLQF_FD_SIZE_FD_GSIZE_S;
				func_p->fd_fltr_guar =
					ice_get_num_per_func(hw, val);
				val = (reg_val & GLQF_FD_SIZE_FD_BSIZE_M) >>
				      GLQF_FD_SIZE_FD_BSIZE_S;
				func_p->fd_fltr_best_effort = val;
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: fd_fltr_guar = %d\n",
					  prefix, func_p->fd_fltr_guar);
				ice_debug(hw, ICE_DBG_INIT,
					  "%s: fd_fltr_best_effort = %d\n",
					  prefix, func_p->fd_fltr_best_effort);
			}
			break;
		}
		case ICE_AQC_CAPS_NVM_VER:
			break;
		case ICE_AQC_CAPS_CEM:
			caps->mgmt_cem = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: mgmt_cem = %d\n", prefix,
				  caps->mgmt_cem);
			break;
		case ICE_AQC_CAPS_IWARP:
			caps->iwarp = (number == 1);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: iwarp = %d\n", prefix, caps->iwarp);
			break;
		case ICE_AQC_CAPS_LED:
			if (phys_id < ICE_MAX_SUPPORTED_GPIO_LED) {
				caps->led[phys_id] = true;
				caps->led_pin_num++;
			}
			break;
		case ICE_AQC_CAPS_SDP:
			if (phys_id < ICE_MAX_SUPPORTED_GPIO_SDP) {
				caps->sdp[phys_id] = true;
				caps->sdp_pin_num++;
			}
			break;
		case ICE_AQC_CAPS_WR_CSR_PROT:
			caps->wr_csr_prot = number;
			caps->wr_csr_prot |= (u64)logical_id << 32;
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: wr_csr_prot = 0x%llX\n", prefix,
				  (unsigned long long)caps->wr_csr_prot);
			break;
		case ICE_AQC_CAPS_WOL_PROXY:
			caps->num_wol_proxy_fltr = number;
			caps->wol_proxy_vsi_seid = logical_id;
			caps->apm_wol_support = !!(phys_id & ICE_WOL_SUPPORT_M);
			caps->acpi_prog_mthd = !!(phys_id &
						  ICE_ACPI_PROG_MTHD_M);
			caps->proxy_support = !!(phys_id & ICE_PROXY_SUPPORT_M);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: num_wol_proxy_fltr = %d\n", prefix,
				  caps->num_wol_proxy_fltr);
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: wol_proxy_vsi_seid = %d\n", prefix,
				  caps->wol_proxy_vsi_seid);
			break;
		case ICE_AQC_CAPS_MAX_MTU:
			caps->max_mtu = number;
			ice_debug(hw, ICE_DBG_INIT, "%s: max_mtu = %d\n",
				  prefix, caps->max_mtu);
			break;
		default:
			ice_debug(hw, ICE_DBG_INIT,
				  "%s: unknown capability[%d]: 0x%x\n", prefix,
				  i, cap);
			break;
		}
	}

	ice_print_led_caps(hw, caps, prefix, true);
	ice_print_sdp_caps(hw, caps, prefix, true);


	/* Re-calculate capabilities that are dependent on the number of
	 * physical ports; i.e. some features are not supported or function
	 * differently on devices with more than 4 ports.
	 */
	if (hw->dev_caps.num_funcs > 4) {
		/* Max 4 TCs per port */
		caps->maxtc = 4;
		ice_debug(hw, ICE_DBG_INIT,
			  "%s: maxtc = %d (based on #ports)\n", prefix,
			  caps->maxtc);
		if (caps->iwarp) {
			ice_debug(hw, ICE_DBG_INIT, "%s: forcing RDMA off\n",
				  prefix);
			caps->iwarp = 0;
		}

		/* print message only when processing device capabilities */
		if (dev_p)
			dev_info(ice_hw_to_dev(hw),
				 "RDMA functionality is not available with the current device configuration.\n");
	}
}

/**
 * ice_aq_discover_caps - query function/device capabilities
 * @hw: pointer to the HW struct
 * @buf: a virtual buffer to hold the capabilities
 * @buf_size: Size of the virtual buffer
 * @cap_count: cap count needed if AQ err==ENOMEM
 * @opc: capabilities type to discover - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 * Get the function(0x000a)/device(0x000b) capabilities description from
 * the firmware.
 */
static enum ice_status
ice_aq_discover_caps(struct ice_hw *hw, void *buf, u16 buf_size, u32 *cap_count,
		     enum ice_adminq_opc opc, struct ice_sq_cd *cd)
{
	struct ice_aqc_list_caps *cmd;
	struct ice_aq_desc desc;
	enum ice_status status;

	cmd = &desc.params.get_cap;

	if (opc != ice_aqc_opc_list_func_caps &&
	    opc != ice_aqc_opc_list_dev_caps)
		return ICE_ERR_PARAM;

	ice_fill_dflt_direct_cmd_desc(&desc, opc);

	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (!status)
		ice_parse_caps(hw, buf, le32_to_cpu(cmd->count), opc);
	else if (hw->adminq.sq_last_status == ICE_AQ_RC_ENOMEM)
		*cap_count = le32_to_cpu(cmd->count);
	return status;
}

/**
 * ice_discover_caps - get info about the HW
 * @hw: pointer to the hardware structure
 * @opc: capabilities type to discover - pass in the command opcode
 */
static enum ice_status
ice_discover_caps(struct ice_hw *hw, enum ice_adminq_opc opc)
{
	enum ice_status status;
	u32 cap_count;
	u16 cbuf_len;
	u8 retries;

	/* The driver doesn't know how many capabilities the device will return
	 * so the buffer size required isn't known ahead of time. The driver
	 * starts with cbuf_len and if this turns out to be insufficient, the
	 * device returns ICE_AQ_RC_ENOMEM and also the cap_count it needs.
	 * The driver then allocates the buffer based on the count and retries
	 * the operation. So it follows that the retry count is 2.
	 */
#define ICE_GET_CAP_BUF_COUNT	40
#define ICE_GET_CAP_RETRY_COUNT	2

	cap_count = ICE_GET_CAP_BUF_COUNT;
	retries = ICE_GET_CAP_RETRY_COUNT;

	do {
		void *cbuf;

		cbuf_len = (u16)(cap_count *
				 sizeof(struct ice_aqc_list_caps_elem));
		cbuf = devm_kzalloc(ice_hw_to_dev(hw), cbuf_len, GFP_KERNEL);
		if (!cbuf)
			return ICE_ERR_NO_MEMORY;

		status = ice_aq_discover_caps(hw, cbuf, cbuf_len, &cap_count,
					      opc, NULL);
		devm_kfree(ice_hw_to_dev(hw), cbuf);

		if (!status || hw->adminq.sq_last_status != ICE_AQ_RC_ENOMEM)
			break;

		/* If ENOMEM is returned, try again with bigger buffer */
	} while (--retries);

	return status;
}

/**
 * ice_set_safe_mode_caps - Override dev/func capabilities when in safe mode
 * @hw: pointer to the hardware structure
 */
void ice_set_safe_mode_caps(struct ice_hw *hw)
{
	struct ice_hw_func_caps *func_caps = &hw->func_caps;
	struct ice_hw_dev_caps *dev_caps = &hw->dev_caps;
	u32 valid_func, rxq_first_id, txq_first_id;
	u32 msix_vector_first_id, max_mtu;
	u32 num_funcs;

	/* cache some func_caps values that should be restored after memset */
	valid_func = func_caps->common_cap.valid_functions;
	txq_first_id = func_caps->common_cap.txq_first_id;
	rxq_first_id = func_caps->common_cap.rxq_first_id;
	msix_vector_first_id = func_caps->common_cap.msix_vector_first_id;
	max_mtu = func_caps->common_cap.max_mtu;

	/* unset func capabilities */
	memset(func_caps, 0, sizeof(*func_caps));

	/* restore cached values */
	func_caps->common_cap.valid_functions = valid_func;
	func_caps->common_cap.txq_first_id = txq_first_id;
	func_caps->common_cap.rxq_first_id = rxq_first_id;
	func_caps->common_cap.msix_vector_first_id = msix_vector_first_id;
	func_caps->common_cap.max_mtu = max_mtu;

	/* one Tx and one Rx queue in safe mode */
	func_caps->common_cap.num_rxq = 1;
	func_caps->common_cap.num_txq = 1;

	/* two MSIX vectors, one for traffic and one for misc causes */
	func_caps->common_cap.num_msix_vectors = 2;
	func_caps->guar_num_vsi = 1;

	/* cache some dev_caps values that should be restored after memset */
	valid_func = dev_caps->common_cap.valid_functions;
	txq_first_id = dev_caps->common_cap.txq_first_id;
	rxq_first_id = dev_caps->common_cap.rxq_first_id;
	msix_vector_first_id = dev_caps->common_cap.msix_vector_first_id;
	max_mtu = dev_caps->common_cap.max_mtu;
	num_funcs = dev_caps->num_funcs;

	/* unset dev capabilities */
	memset(dev_caps, 0, sizeof(*dev_caps));

	/* restore cached values */
	dev_caps->common_cap.valid_functions = valid_func;
	dev_caps->common_cap.txq_first_id = txq_first_id;
	dev_caps->common_cap.rxq_first_id = rxq_first_id;
	dev_caps->common_cap.msix_vector_first_id = msix_vector_first_id;
	dev_caps->common_cap.max_mtu = max_mtu;
	dev_caps->num_funcs = num_funcs;

	/* one Tx and one Rx queue per function in safe mode */
	dev_caps->common_cap.num_rxq = num_funcs;
	dev_caps->common_cap.num_txq = num_funcs;

	/* two MSIX vectors per function */
	dev_caps->common_cap.num_msix_vectors = 2 * num_funcs;
}

/**
 * ice_get_caps - get info about the HW
 * @hw: pointer to the hardware structure
 */
enum ice_status ice_get_caps(struct ice_hw *hw)
{
	enum ice_status status;

	status = ice_discover_caps(hw, ice_aqc_opc_list_dev_caps);
	if (!status)
		status = ice_discover_caps(hw, ice_aqc_opc_list_func_caps);

	return status;
}

/**
 * ice_aq_manage_mac_write - manage MAC address write command
 * @hw: pointer to the HW struct
 * @mac_addr: MAC address to be written as LAA/LAA+WoL/Port address
 * @flags: flags to control write behavior
 * @cd: pointer to command details structure or NULL
 *
 * This function is used to write MAC address to the NVM (0x0108).
 */
enum ice_status
ice_aq_manage_mac_write(struct ice_hw *hw, const u8 *mac_addr, u8 flags,
			struct ice_sq_cd *cd)
{
	struct ice_aqc_manage_mac_write *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.mac_write;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_manage_mac_write);

	cmd->flags = flags;


	/* Prep values for flags, sah, sal */
	cmd->sah = htons(*((const u16 *)mac_addr));
	cmd->sal = htonl(*((const u32 *)(mac_addr + 2)));

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_clear_pxe_mode
 * @hw: pointer to the HW struct
 *
 * Tell the firmware that the driver is taking over from PXE (0x0110).
 */
static enum ice_status ice_aq_clear_pxe_mode(struct ice_hw *hw)
{
	struct ice_aq_desc desc;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_clear_pxe_mode);
	desc.params.clear_pxe.rx_cnt = ICE_AQC_CLEAR_PXE_RX_CNT;

	return ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

/**
 * ice_clear_pxe_mode - clear pxe operations mode
 * @hw: pointer to the HW struct
 *
 * Make sure all PXE mode settings are cleared, including things
 * like descriptor fetch/write-back mode.
 */
void ice_clear_pxe_mode(struct ice_hw *hw)
{
	if (ice_check_sq_alive(hw, &hw->adminq))
		ice_aq_clear_pxe_mode(hw);
}

/**
 * ice_aq_set_port_params - set physical port parameters.
 * @pi: pointer to the port info struct
 * @bad_frame_vsi: defines the VSI to which bad frames are forwarded
 * @save_bad_pac: if set packets with errors are forwarded to the bad frames VSI
 * @pad_short_pac: if set transmit packets smaller than 60 bytes are padded
 * @double_vlan: if set double VLAN is enabled
 * @cd: pointer to command details structure or NULL
 *
 * Set Physical port parameters (0x0203)
 */
enum ice_status
ice_aq_set_port_params(struct ice_port_info *pi, u16 bad_frame_vsi,
		       bool save_bad_pac, bool pad_short_pac, bool double_vlan,
		       struct ice_sq_cd *cd)

{
	struct ice_aqc_set_port_params *cmd;
	struct ice_hw *hw = pi->hw;
	struct ice_aq_desc desc;
	u16 cmd_flags = 0;

	cmd = &desc.params.set_port_params;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_port_params);
	cmd->bad_frame_vsi = cpu_to_le16(bad_frame_vsi);
	if (save_bad_pac)
		cmd_flags |= ICE_AQC_SET_P_PARAMS_SAVE_BAD_PACKETS;
	if (pad_short_pac)
		cmd_flags |= ICE_AQC_SET_P_PARAMS_PAD_SHORT_PACKETS;
	if (double_vlan)
		cmd_flags |= ICE_AQC_SET_P_PARAMS_DOUBLE_VLAN_ENA;
	cmd->cmd_flags = cpu_to_le16(cmd_flags);

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_get_link_speed_based_on_phy_type - returns link speed
 * @phy_type_low: lower part of phy_type
 * @phy_type_high: higher part of phy_type
 *
 * This helper function will convert an entry in PHY type structure
 * [phy_type_low, phy_type_high] to its corresponding link speed.
 * Note: In the structure of [phy_type_low, phy_type_high], there should
 * be one bit set, as this function will convert one PHY type to its
 * speed.
 * If no bit gets set, ICE_LINK_SPEED_UNKNOWN will be returned
 * If more than one bit gets set, ICE_LINK_SPEED_UNKNOWN will be returned
 */
static u16
ice_get_link_speed_based_on_phy_type(u64 phy_type_low, u64 phy_type_high)
{
	u16 speed_phy_type_high = ICE_AQ_LINK_SPEED_UNKNOWN;
	u16 speed_phy_type_low = ICE_AQ_LINK_SPEED_UNKNOWN;

	switch (phy_type_low) {
	case ICE_PHY_TYPE_LOW_100BASE_TX:
	case ICE_PHY_TYPE_LOW_100M_SGMII:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_100MB;
		break;
	case ICE_PHY_TYPE_LOW_1000BASE_T:
	case ICE_PHY_TYPE_LOW_1000BASE_SX:
	case ICE_PHY_TYPE_LOW_1000BASE_LX:
	case ICE_PHY_TYPE_LOW_1000BASE_KX:
	case ICE_PHY_TYPE_LOW_1G_SGMII:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_1000MB;
		break;
	case ICE_PHY_TYPE_LOW_2500BASE_T:
	case ICE_PHY_TYPE_LOW_2500BASE_X:
	case ICE_PHY_TYPE_LOW_2500BASE_KX:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_2500MB;
		break;
	case ICE_PHY_TYPE_LOW_5GBASE_T:
	case ICE_PHY_TYPE_LOW_5GBASE_KR:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_5GB;
		break;
	case ICE_PHY_TYPE_LOW_10GBASE_T:
	case ICE_PHY_TYPE_LOW_10G_SFI_DA:
	case ICE_PHY_TYPE_LOW_10GBASE_SR:
	case ICE_PHY_TYPE_LOW_10GBASE_LR:
	case ICE_PHY_TYPE_LOW_10GBASE_KR_CR1:
	case ICE_PHY_TYPE_LOW_10G_SFI_AOC_ACC:
	case ICE_PHY_TYPE_LOW_10G_SFI_C2C:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_10GB;
		break;
	case ICE_PHY_TYPE_LOW_25GBASE_T:
	case ICE_PHY_TYPE_LOW_25GBASE_CR:
	case ICE_PHY_TYPE_LOW_25GBASE_CR_S:
	case ICE_PHY_TYPE_LOW_25GBASE_CR1:
	case ICE_PHY_TYPE_LOW_25GBASE_SR:
	case ICE_PHY_TYPE_LOW_25GBASE_LR:
	case ICE_PHY_TYPE_LOW_25GBASE_KR:
	case ICE_PHY_TYPE_LOW_25GBASE_KR_S:
	case ICE_PHY_TYPE_LOW_25GBASE_KR1:
	case ICE_PHY_TYPE_LOW_25G_AUI_AOC_ACC:
	case ICE_PHY_TYPE_LOW_25G_AUI_C2C:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_25GB;
		break;
	case ICE_PHY_TYPE_LOW_40GBASE_CR4:
	case ICE_PHY_TYPE_LOW_40GBASE_SR4:
	case ICE_PHY_TYPE_LOW_40GBASE_LR4:
	case ICE_PHY_TYPE_LOW_40GBASE_KR4:
	case ICE_PHY_TYPE_LOW_40G_XLAUI_AOC_ACC:
	case ICE_PHY_TYPE_LOW_40G_XLAUI:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_40GB;
		break;
	case ICE_PHY_TYPE_LOW_50GBASE_CR2:
	case ICE_PHY_TYPE_LOW_50GBASE_SR2:
	case ICE_PHY_TYPE_LOW_50GBASE_LR2:
	case ICE_PHY_TYPE_LOW_50GBASE_KR2:
	case ICE_PHY_TYPE_LOW_50G_LAUI2_AOC_ACC:
	case ICE_PHY_TYPE_LOW_50G_LAUI2:
	case ICE_PHY_TYPE_LOW_50G_AUI2_AOC_ACC:
	case ICE_PHY_TYPE_LOW_50G_AUI2:
	case ICE_PHY_TYPE_LOW_50GBASE_CP:
	case ICE_PHY_TYPE_LOW_50GBASE_SR:
	case ICE_PHY_TYPE_LOW_50GBASE_FR:
	case ICE_PHY_TYPE_LOW_50GBASE_LR:
	case ICE_PHY_TYPE_LOW_50GBASE_KR_PAM4:
	case ICE_PHY_TYPE_LOW_50G_AUI1_AOC_ACC:
	case ICE_PHY_TYPE_LOW_50G_AUI1:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_50GB;
		break;
	case ICE_PHY_TYPE_LOW_100GBASE_CR4:
	case ICE_PHY_TYPE_LOW_100GBASE_SR4:
	case ICE_PHY_TYPE_LOW_100GBASE_LR4:
	case ICE_PHY_TYPE_LOW_100GBASE_KR4:
	case ICE_PHY_TYPE_LOW_100G_CAUI4_AOC_ACC:
	case ICE_PHY_TYPE_LOW_100G_CAUI4:
	case ICE_PHY_TYPE_LOW_100G_AUI4_AOC_ACC:
	case ICE_PHY_TYPE_LOW_100G_AUI4:
	case ICE_PHY_TYPE_LOW_100GBASE_CR_PAM4:
	case ICE_PHY_TYPE_LOW_100GBASE_KR_PAM4:
	case ICE_PHY_TYPE_LOW_100GBASE_CP2:
	case ICE_PHY_TYPE_LOW_100GBASE_SR2:
	case ICE_PHY_TYPE_LOW_100GBASE_DR:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_100GB;
		break;
	default:
		speed_phy_type_low = ICE_AQ_LINK_SPEED_UNKNOWN;
		break;
	}

	switch (phy_type_high) {
	case ICE_PHY_TYPE_HIGH_100GBASE_KR2_PAM4:
	case ICE_PHY_TYPE_HIGH_100G_CAUI2_AOC_ACC:
	case ICE_PHY_TYPE_HIGH_100G_CAUI2:
	case ICE_PHY_TYPE_HIGH_100G_AUI2_AOC_ACC:
	case ICE_PHY_TYPE_HIGH_100G_AUI2:
		speed_phy_type_high = ICE_AQ_LINK_SPEED_100GB;
		break;
	default:
		speed_phy_type_high = ICE_AQ_LINK_SPEED_UNKNOWN;
		break;
	}

	if (speed_phy_type_low == ICE_AQ_LINK_SPEED_UNKNOWN &&
	    speed_phy_type_high == ICE_AQ_LINK_SPEED_UNKNOWN)
		return ICE_AQ_LINK_SPEED_UNKNOWN;
	else if (speed_phy_type_low != ICE_AQ_LINK_SPEED_UNKNOWN &&
		 speed_phy_type_high != ICE_AQ_LINK_SPEED_UNKNOWN)
		return ICE_AQ_LINK_SPEED_UNKNOWN;
	else if (speed_phy_type_low != ICE_AQ_LINK_SPEED_UNKNOWN &&
		 speed_phy_type_high == ICE_AQ_LINK_SPEED_UNKNOWN)
		return speed_phy_type_low;
	else
		return speed_phy_type_high;
}

/**
 * ice_update_phy_type
 * @phy_type_low: pointer to the lower part of phy_type
 * @phy_type_high: pointer to the higher part of phy_type
 * @link_speeds_bitmap: targeted link speeds bitmap
 *
 * Note: For the link_speeds_bitmap structure, you can check it at
 * [ice_aqc_get_link_status->link_speed]. Caller can pass in
 * link_speeds_bitmap include multiple speeds.
 *
 * Each entry in this [phy_type_low, phy_type_high] structure will
 * present a certain link speed. This helper function will turn on bits
 * in [phy_type_low, phy_type_high] structure based on the value of
 * link_speeds_bitmap input parameter.
 */
void
ice_update_phy_type(u64 *phy_type_low, u64 *phy_type_high,
		    u16 link_speeds_bitmap)
{
	u64 pt_high;
	u64 pt_low;
	int index;
	u16 speed;

	/* We first check with low part of phy_type */
	for (index = 0; index <= ICE_PHY_TYPE_LOW_MAX_INDEX; index++) {
		pt_low = BIT_ULL(index);
		speed = ice_get_link_speed_based_on_phy_type(pt_low, 0);

		if (link_speeds_bitmap & speed)
			*phy_type_low |= BIT_ULL(index);
	}

	/* We then check with high part of phy_type */
	for (index = 0; index <= ICE_PHY_TYPE_HIGH_MAX_INDEX; index++) {
		pt_high = BIT_ULL(index);
		speed = ice_get_link_speed_based_on_phy_type(0, pt_high);

		if (link_speeds_bitmap & speed)
			*phy_type_high |= BIT_ULL(index);
	}
}

/**
 * ice_aq_set_phy_cfg
 * @hw: pointer to the HW struct
 * @pi: port info structure of the interested logical port
 * @cfg: structure with PHY configuration data to be set
 * @cd: pointer to command details structure or NULL
 *
 * Set the various PHY configuration parameters supported on the Port.
 * One or more of the Set PHY config parameters may be ignored in an MFP
 * mode as the PF may not have the privilege to set some of the PHY Config
 * parameters. This status will be indicated by the command response (0x0601).
 */
enum ice_status
ice_aq_set_phy_cfg(struct ice_hw *hw, struct ice_port_info *pi,
		   struct ice_aqc_set_phy_cfg_data *cfg, struct ice_sq_cd *cd)
{
	struct ice_aq_desc desc;
	enum ice_status status;

	if (!cfg)
		return ICE_ERR_PARAM;

	/* Ensure that only valid bits of cfg->caps can be turned on. */
	if (cfg->caps & ~ICE_AQ_PHY_ENA_VALID_MASK) {
		ice_debug(hw, ICE_DBG_PHY,
			  "Invalid bit is set in ice_aqc_set_phy_cfg_data->caps : 0x%x\n",
			  cfg->caps);

		cfg->caps &= ICE_AQ_PHY_ENA_VALID_MASK;
	}

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_phy_cfg);
	desc.params.set_phy.lport_num = pi->lport;
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	ice_debug(hw, ICE_DBG_LINK, "phy_type_low = 0x%llx\n",
		  (unsigned long long)le64_to_cpu(cfg->phy_type_low));
	ice_debug(hw, ICE_DBG_LINK, "phy_type_high = 0x%llx\n",
		  (unsigned long long)le64_to_cpu(cfg->phy_type_high));
	ice_debug(hw, ICE_DBG_LINK, "caps = 0x%x\n", cfg->caps);
	ice_debug(hw, ICE_DBG_LINK, "low_power_ctrl = 0x%x\n",
		  cfg->low_power_ctrl);
	ice_debug(hw, ICE_DBG_LINK, "eee_cap = 0x%x\n", cfg->eee_cap);
	ice_debug(hw, ICE_DBG_LINK, "eeer_value = 0x%x\n", cfg->eeer_value);
	ice_debug(hw, ICE_DBG_LINK, "link_fec_opt = 0x%x\n", cfg->link_fec_opt);

	status = ice_aq_send_cmd(hw, &desc, cfg, sizeof(*cfg), cd);

	if (!status)
		pi->phy.curr_user_phy_cfg = *cfg;

	return status;
}

/**
 * ice_update_link_info - update status of the HW network link
 * @pi: port info structure of the interested logical port
 */
enum ice_status ice_update_link_info(struct ice_port_info *pi)
{
	struct ice_link_status *li;
	enum ice_status status;

	if (!pi)
		return ICE_ERR_PARAM;

	li = &pi->phy.link_info;

	status = ice_aq_get_link_info(pi, true, NULL, NULL);
	if (status)
		return status;

	if (li->link_info & ICE_AQ_MEDIA_AVAILABLE) {
		struct ice_aqc_get_phy_caps_data *pcaps;
		struct ice_hw *hw;

		hw = pi->hw;
		pcaps = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*pcaps),
				     GFP_KERNEL);
		if (!pcaps)
			return ICE_ERR_NO_MEMORY;

		status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP,
					     pcaps, NULL);
		if (!status)
			memcpy(li->module_type, &pcaps->module_type,
			       sizeof(li->module_type));

		devm_kfree(ice_hw_to_dev(hw), pcaps);
	}

	return status;
}

/**
 * ice_cache_phy_user_req
 * @pi: port information structure
 * @cache_data: PHY logging data
 * @cache_mode: PHY logging mode
 *
 * Log the user request on (FC, FEC, SPEED) for later user.
 */
static void
ice_cache_phy_user_req(struct ice_port_info *pi,
		       struct ice_phy_cache_mode_data cache_data,
		       enum ice_phy_cache_mode cache_mode)
{
	if (!pi)
		return;

	switch (cache_mode) {
	case ICE_FC_MODE:
		pi->phy.curr_user_fc_req = cache_data.data.curr_user_fc_req;
		break;
	case ICE_SPEED_MODE:
		pi->phy.curr_user_speed_req =
			cache_data.data.curr_user_speed_req;
		break;
	case ICE_FEC_MODE:
		pi->phy.curr_user_fec_req = cache_data.data.curr_user_fec_req;
		break;
	default:
		break;
	}
}

/**
 * ice_caps_to_fc_mode
 * @caps: PHY capabilities
 *
 * Convert PHY FC capabilities to ice FC mode
 */
enum ice_fc_mode ice_caps_to_fc_mode(u8 caps)
{
	if (caps & ICE_AQC_PHY_EN_TX_LINK_PAUSE &&
	    caps & ICE_AQC_PHY_EN_RX_LINK_PAUSE)
		return ICE_FC_FULL;

	if (caps & ICE_AQC_PHY_EN_TX_LINK_PAUSE)
		return ICE_FC_TX_PAUSE;

	if (caps & ICE_AQC_PHY_EN_RX_LINK_PAUSE)
		return ICE_FC_RX_PAUSE;

	return ICE_FC_NONE;
}

/**
 * ice_caps_to_fec_mode
 * @caps: PHY capabilities
 * @fec_options: Link FEC options
 *
 * Convert PHY FEC capabilities to ice FEC mode
 */
enum ice_fec_mode ice_caps_to_fec_mode(u8 caps, u8 fec_options)
{
	if (caps & ICE_AQC_PHY_EN_AUTO_FEC)
		return ICE_FEC_AUTO;

	if (fec_options & (ICE_AQC_PHY_FEC_10G_KR_40G_KR4_EN |
			   ICE_AQC_PHY_FEC_10G_KR_40G_KR4_REQ |
			   ICE_AQC_PHY_FEC_25G_KR_CLAUSE74_EN |
			   ICE_AQC_PHY_FEC_25G_KR_REQ))
		return ICE_FEC_BASER;

	if (fec_options & (ICE_AQC_PHY_FEC_25G_RS_528_REQ |
			   ICE_AQC_PHY_FEC_25G_RS_544_REQ |
			   ICE_AQC_PHY_FEC_25G_RS_CLAUSE91_EN))
		return ICE_FEC_RS;

	return ICE_FEC_NONE;
}

/**
 * ice_set_fc
 * @pi: port information structure
 * @aq_failures: pointer to status code, specific to ice_set_fc routine
 * @ena_auto_link_update: enable automatic link update
 *
 * Set the requested flow control mode.
 */
enum ice_status
ice_set_fc(struct ice_port_info *pi, u8 *aq_failures, bool ena_auto_link_update)
{
	struct ice_aqc_set_phy_cfg_data cfg = { 0 };
	struct ice_phy_cache_mode_data cache_data;
	struct ice_aqc_get_phy_caps_data *pcaps;
	enum ice_status status;
	u8 pause_mask = 0x0;
	struct ice_hw *hw;

	if (!pi)
		return ICE_ERR_PARAM;
	hw = pi->hw;
	*aq_failures = ICE_SET_FC_AQ_FAIL_NONE;

	/* Cache user FC request */
	cache_data.data.curr_user_fc_req = pi->fc.req_mode;
	ice_cache_phy_user_req(pi, cache_data, ICE_FC_MODE);

	switch (pi->fc.req_mode) {
	case ICE_FC_FULL:
		pause_mask |= ICE_AQC_PHY_EN_TX_LINK_PAUSE;
		pause_mask |= ICE_AQC_PHY_EN_RX_LINK_PAUSE;
		break;
	case ICE_FC_RX_PAUSE:
		pause_mask |= ICE_AQC_PHY_EN_RX_LINK_PAUSE;
		break;
	case ICE_FC_TX_PAUSE:
		pause_mask |= ICE_AQC_PHY_EN_TX_LINK_PAUSE;
		break;
	default:
		break;
	}

	pcaps = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return ICE_ERR_NO_MEMORY;

	/* Get the current PHY config */
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG, pcaps,
				     NULL);
	if (status) {
		*aq_failures = ICE_SET_FC_AQ_FAIL_GET;
		goto out;
	}

	/* clear the old pause settings */
	cfg.caps = pcaps->caps & ~(ICE_AQC_PHY_EN_TX_LINK_PAUSE |
				   ICE_AQC_PHY_EN_RX_LINK_PAUSE);

	/* set the new capabilities */
	cfg.caps |= pause_mask;

	/* If the capabilities have changed, then set the new config */
	if (cfg.caps != pcaps->caps) {
		int retry_count, retry_max = 10;

		/* Auto restart link so settings take effect */
		if (ena_auto_link_update)
			cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;
		/* Copy over all the old settings */
		cfg.phy_type_high = pcaps->phy_type_high;
		cfg.phy_type_low = pcaps->phy_type_low;
		cfg.low_power_ctrl = pcaps->low_power_ctrl;
		cfg.eee_cap = pcaps->eee_cap;
		cfg.eeer_value = pcaps->eeer_value;
		cfg.link_fec_opt = pcaps->link_fec_options;

		status = ice_aq_set_phy_cfg(hw, pi, &cfg, NULL);
		if (status) {
			*aq_failures = ICE_SET_FC_AQ_FAIL_SET;
			goto out;
		}

		/* Update the link info
		 * It sometimes takes a really long time for link to
		 * come back from the atomic reset. Thus, we wait a
		 * little bit.
		 */
		for (retry_count = 0; retry_count < retry_max; retry_count++) {
			status = ice_update_link_info(pi);

			if (!status)
				break;

			msleep(100);
		}

		if (status)
			*aq_failures = ICE_SET_FC_AQ_FAIL_UPDATE;
	}

out:
	devm_kfree(ice_hw_to_dev(hw), pcaps);
	return status;
}

/**
 * ice_phy_caps_equals_cfg
 * @phy_caps: PHY capabilities
 * @phy_cfg: PHY configuration
 *
 * Helper function to determine if PHY capabilities matches PHY
 * configuration
 */
bool
ice_phy_caps_equals_cfg(struct ice_aqc_get_phy_caps_data *phy_caps,
			struct ice_aqc_set_phy_cfg_data *phy_cfg)
{
	u8 caps_mask, cfg_mask;

	if (!phy_caps || !phy_cfg)
		return false;

	/* These bits are not common between capabilities and configuration.
	 * Do not use them to determine equality.
	 */
	caps_mask = ICE_AQC_PHY_CAPS_MASK & ~(ICE_AQC_PHY_AN_MODE |
					      ICE_AQC_PHY_EN_MOD_QUAL);
	cfg_mask = ICE_AQ_PHY_ENA_VALID_MASK & ~ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;

	if (phy_caps->phy_type_low != phy_cfg->phy_type_low ||
	    phy_caps->phy_type_high != phy_cfg->phy_type_high ||
	    ((phy_caps->caps & caps_mask) != (phy_cfg->caps & cfg_mask)) ||
	    phy_caps->low_power_ctrl != phy_cfg->low_power_ctrl ||
	    phy_caps->eee_cap != phy_cfg->eee_cap ||
	    phy_caps->eeer_value != phy_cfg->eeer_value ||
	    phy_caps->link_fec_options != phy_cfg->link_fec_opt)
		return false;

	return true;
}

/**
 * ice_copy_phy_caps_to_cfg - Copy PHY ability data to configuration data
 * @caps: PHY ability structure to copy date from
 * @cfg: PHY configuration structure to copy data to
 *
 * Helper function to copy AQC PHY get ability data to PHY set configuration
 * data structure
 */
void
ice_copy_phy_caps_to_cfg(struct ice_aqc_get_phy_caps_data *caps,
			 struct ice_aqc_set_phy_cfg_data *cfg)
{
	if (!caps || !cfg)
		return;

	cfg->phy_type_low = caps->phy_type_low;
	cfg->phy_type_high = caps->phy_type_high;
	cfg->caps = caps->caps;
	cfg->low_power_ctrl = caps->low_power_ctrl;
	cfg->eee_cap = caps->eee_cap;
	cfg->eeer_value = caps->eeer_value;
	cfg->link_fec_opt = caps->link_fec_options;
}

/**
 * ice_cfg_phy_fec - Configure PHY FEC data based on FEC mode
 * @cfg: PHY configuration data to set FEC mode
 * @fec: FEC mode to configure
 *
 * Caller should copy ice_aqc_get_phy_caps_data.caps ICE_AQC_PHY_EN_AUTO_FEC
 * (bit 7) and ice_aqc_get_phy_caps_data.link_fec_options to cfg.caps
 * ICE_AQ_PHY_ENA_AUTO_FEC (bit 7) and cfg.link_fec_options before calling.
 */
void
ice_cfg_phy_fec(struct ice_aqc_set_phy_cfg_data *cfg, enum ice_fec_mode fec)
{
	switch (fec) {
	case ICE_FEC_BASER:
		/* Clear RS bits, and AND BASE-R ability
		 * bits and OR request bits.
		 */
		cfg->link_fec_opt &= ICE_AQC_PHY_FEC_10G_KR_40G_KR4_EN |
				     ICE_AQC_PHY_FEC_25G_KR_CLAUSE74_EN;
		cfg->link_fec_opt |= ICE_AQC_PHY_FEC_10G_KR_40G_KR4_REQ |
				     ICE_AQC_PHY_FEC_25G_KR_REQ;
		break;
	case ICE_FEC_RS:
		/* Clear BASE-R bits, and AND RS ability
		 * bits and OR request bits.
		 */
		cfg->link_fec_opt &= ICE_AQC_PHY_FEC_25G_RS_CLAUSE91_EN;
		cfg->link_fec_opt |= ICE_AQC_PHY_FEC_25G_RS_528_REQ |
				     ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		break;
	case ICE_FEC_NONE:
		/* Clear all FEC option bits. */
		cfg->link_fec_opt &= ~ICE_AQC_PHY_FEC_MASK;
		break;
	case ICE_FEC_AUTO:
		/* AND auto FEC bit, and all caps bits. */
		cfg->caps &= ICE_AQC_PHY_CAPS_MASK;
		break;
	}
}

/**
 * ice_get_link_status - get status of the HW network link
 * @pi: port information structure
 * @link_up: pointer to bool (true/false = linkup/linkdown)
 *
 * Variable link_up is true if link is up, false if link is down.
 * The variable link_up is invalid if status is non zero. As a
 * result of this call, link status reporting becomes enabled
 */
enum ice_status ice_get_link_status(struct ice_port_info *pi, bool *link_up)
{
	struct ice_phy_info *phy_info;
	enum ice_status status = 0;

	if (!pi || !link_up)
		return ICE_ERR_PARAM;

	phy_info = &pi->phy;

	if (phy_info->get_link_info) {
		status = ice_update_link_info(pi);

		if (status)
			ice_debug(pi->hw, ICE_DBG_LINK,
				  "get link status error, status = %d\n",
				  status);
	}

	*link_up = phy_info->link_info.link_info & ICE_AQ_LINK_UP;

	return status;
}

/**
 * ice_aq_set_link_restart_an
 * @pi: pointer to the port information structure
 * @ena_link: if true: enable link, if false: disable link
 * @cd: pointer to command details structure or NULL
 *
 * Sets up the link and restarts the Auto-Negotiation over the link.
 */
enum ice_status
ice_aq_set_link_restart_an(struct ice_port_info *pi, bool ena_link,
			   struct ice_sq_cd *cd)
{
	struct ice_aqc_restart_an *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.restart_an;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_restart_an);

	cmd->cmd_flags = ICE_AQC_RESTART_AN_LINK_RESTART;
	cmd->lport_num = pi->lport;
	if (ena_link)
		cmd->cmd_flags |= ICE_AQC_RESTART_AN_LINK_ENABLE;
	else
		cmd->cmd_flags &= ~ICE_AQC_RESTART_AN_LINK_ENABLE;

	return ice_aq_send_cmd(pi->hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_set_event_mask
 * @hw: pointer to the HW struct
 * @port_num: port number of the physical function
 * @mask: event mask to be set
 * @cd: pointer to command details structure or NULL
 *
 * Set event mask (0x0613)
 */
enum ice_status
ice_aq_set_event_mask(struct ice_hw *hw, u8 port_num, u16 mask,
		      struct ice_sq_cd *cd)
{
	struct ice_aqc_set_event_mask *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.set_event_mask;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_event_mask);

	cmd->lport_num = port_num;

	cmd->event_mask = cpu_to_le16(mask);
	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_set_mac_loopback
 * @hw: pointer to the HW struct
 * @ena_lpbk: Enable or Disable loopback
 * @cd: pointer to command details structure or NULL
 *
 * Enable/disable loopback on a given port
 */
enum ice_status
ice_aq_set_mac_loopback(struct ice_hw *hw, bool ena_lpbk, struct ice_sq_cd *cd)
{
	struct ice_aqc_set_mac_lb *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.set_mac_lb;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_mac_lb);
	if (ena_lpbk)
		cmd->lb_mode = ICE_AQ_MAC_LB_EN;

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}


/**
 * ice_aq_set_port_id_led
 * @pi: pointer to the port information
 * @is_orig_mode: is this LED set to original mode (by the net-list)
 * @cd: pointer to command details structure or NULL
 *
 * Set LED value for the given port (0x06e9)
 */
enum ice_status
ice_aq_set_port_id_led(struct ice_port_info *pi, bool is_orig_mode,
		       struct ice_sq_cd *cd)
{
	struct ice_aqc_set_port_id_led *cmd;
	struct ice_hw *hw = pi->hw;
	struct ice_aq_desc desc;

	cmd = &desc.params.set_port_id_led;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_port_id_led);


	if (is_orig_mode)
		cmd->ident_mode = ICE_AQC_PORT_IDENT_LED_ORIG;
	else
		cmd->ident_mode = ICE_AQC_PORT_IDENT_LED_BLINK;

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_sff_eeprom
 * @hw: pointer to the HW struct
 * @lport: bits [7:0] = logical port, bit [8] = logical port valid
 * @bus_addr: I2C bus address of the eeprom (typically 0xA0, 0=topo default)
 * @mem_addr: I2C offset. lower 8 bits for address, 8 upper bits zero padding.
 * @page: QSFP page
 * @set_page: set or ignore the page
 * @data: pointer to data buffer to be read/written to the I2C device.
 * @length: 1-16 for read, 1 for write.
 * @write: 0 read, 1 for write.
 * @cd: pointer to command details structure or NULL
 *
 * Read/Write SFF EEPROM (0x06EE)
 */
enum ice_status
ice_aq_sff_eeprom(struct ice_hw *hw, u16 lport, u8 bus_addr,
		  u16 mem_addr, u8 page, u8 set_page, u8 *data, u8 length,
		  bool write, struct ice_sq_cd *cd)
{
	struct ice_aqc_sff_eeprom *cmd;
	struct ice_aq_desc desc;
	enum ice_status status;

	if (!data || (mem_addr & 0xff00))
		return ICE_ERR_PARAM;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_sff_eeprom);
	cmd = &desc.params.read_write_sff_param;
	desc.flags = cpu_to_le16(ICE_AQ_FLAG_RD | ICE_AQ_FLAG_BUF);
	cmd->lport_num = (u8)(lport & 0xff);
	cmd->lport_num_valid = (u8)((lport >> 8) & 0x01);
	cmd->i2c_bus_addr = cpu_to_le16(((bus_addr >> 1) &
					 ICE_AQC_SFF_I2CBUS_7BIT_M) |
					((set_page <<
					  ICE_AQC_SFF_SET_EEPROM_PAGE_S) &
					 ICE_AQC_SFF_SET_EEPROM_PAGE_M));
	cmd->i2c_mem_addr = cpu_to_le16(mem_addr & 0xff);
	cmd->eeprom_page = cpu_to_le16((u16)page << ICE_AQC_SFF_EEPROM_PAGE_S);
	if (write)
		cmd->i2c_bus_addr |= cpu_to_le16(ICE_AQC_SFF_IS_WRITE);

	status = ice_aq_send_cmd(hw, &desc, data, length, cd);
	return status;
}

/**
 * __ice_aq_get_set_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_id: VSI FW index
 * @lut_type: LUT table type
 * @lut: pointer to the LUT buffer provided by the caller
 * @lut_size: size of the LUT buffer
 * @glob_lut_idx: global LUT index
 * @set: set true to set the table, false to get the table
 *
 * Internal function to get (0x0B05) or set (0x0B03) RSS look up table
 */
static enum ice_status
__ice_aq_get_set_rss_lut(struct ice_hw *hw, u16 vsi_id, u8 lut_type, u8 *lut,
			 u16 lut_size, u8 glob_lut_idx, bool set)
{
	struct ice_aqc_get_set_rss_lut *cmd_resp;
	struct ice_aq_desc desc;
	enum ice_status status;
	u16 flags = 0;

	cmd_resp = &desc.params.get_set_rss_lut;

	if (set) {
		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_rss_lut);
		desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);
	} else {
		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_rss_lut);
	}

	cmd_resp->vsi_id = cpu_to_le16(((vsi_id <<
					 ICE_AQC_GSET_RSS_LUT_VSI_ID_S) &
					ICE_AQC_GSET_RSS_LUT_VSI_ID_M) |
				       ICE_AQC_GSET_RSS_LUT_VSI_VALID);

	switch (lut_type) {
	case ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_VSI:
	case ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF:
	case ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_GLOBAL:
		flags |= ((lut_type << ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_S) &
			  ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_M);
		break;
	default:
		status = ICE_ERR_PARAM;
		goto ice_aq_get_set_rss_lut_exit;
	}

	if (lut_type == ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_GLOBAL) {
		flags |= ((glob_lut_idx << ICE_AQC_GSET_RSS_LUT_GLOBAL_IDX_S) &
			  ICE_AQC_GSET_RSS_LUT_GLOBAL_IDX_M);

		if (!set)
			goto ice_aq_get_set_rss_lut_send;
	} else if (lut_type == ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF) {
		if (!set)
			goto ice_aq_get_set_rss_lut_send;
	} else {
		goto ice_aq_get_set_rss_lut_send;
	}

	/* LUT size is only valid for Global and PF table types */
	switch (lut_size) {
	case ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_128:
		break;
	case ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_512:
		flags |= (ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_512_FLAG <<
			  ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_S) &
			 ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_M;
		break;
	case ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_2K:
		if (lut_type == ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF) {
			flags |= (ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_2K_FLAG <<
				  ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_S) &
				 ICE_AQC_GSET_RSS_LUT_TABLE_SIZE_M;
			break;
		}
		/* fall-through */
	default:
		status = ICE_ERR_PARAM;
		goto ice_aq_get_set_rss_lut_exit;
	}

ice_aq_get_set_rss_lut_send:
	cmd_resp->flags = cpu_to_le16(flags);
	status = ice_aq_send_cmd(hw, &desc, lut, lut_size, NULL);

ice_aq_get_set_rss_lut_exit:
	return status;
}

/**
 * ice_aq_get_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @lut_type: LUT table type
 * @lut: pointer to the LUT buffer provided by the caller
 * @lut_size: size of the LUT buffer
 *
 * get the RSS lookup table, PF or VSI type
 */
enum ice_status
ice_aq_get_rss_lut(struct ice_hw *hw, u16 vsi_handle, u8 lut_type,
		   u8 *lut, u16 lut_size)
{
	if (!ice_is_vsi_valid(hw, vsi_handle) || !lut)
		return ICE_ERR_PARAM;

	return __ice_aq_get_set_rss_lut(hw, ice_get_hw_vsi_num(hw, vsi_handle),
					lut_type, lut, lut_size, 0, false);
}

/**
 * ice_aq_set_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_handle: software VSI handle
 * @lut_type: LUT table type
 * @lut: pointer to the LUT buffer provided by the caller
 * @lut_size: size of the LUT buffer
 *
 * set the RSS lookup table, PF or VSI type
 */
enum ice_status
ice_aq_set_rss_lut(struct ice_hw *hw, u16 vsi_handle, u8 lut_type,
		   u8 *lut, u16 lut_size)
{
	if (!ice_is_vsi_valid(hw, vsi_handle) || !lut)
		return ICE_ERR_PARAM;

	return __ice_aq_get_set_rss_lut(hw, ice_get_hw_vsi_num(hw, vsi_handle),
					lut_type, lut, lut_size, 0, true);
}

/**
 * __ice_aq_get_set_rss_key
 * @hw: pointer to the HW struct
 * @vsi_id: VSI FW index
 * @key: pointer to key info struct
 * @set: set true to set the key, false to get the key
 *
 * get (0x0B04) or set (0x0B02) the RSS key per VSI
 */
static enum
ice_status __ice_aq_get_set_rss_key(struct ice_hw *hw, u16 vsi_id,
				    struct ice_aqc_get_set_rss_keys *key,
				    bool set)
{
	struct ice_aqc_get_set_rss_key *cmd_resp;
	u16 key_size = sizeof(*key);
	struct ice_aq_desc desc;

	cmd_resp = &desc.params.get_set_rss_key;

	if (set) {
		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_rss_key);
		desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);
	} else {
		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_rss_key);
	}

	cmd_resp->vsi_id = cpu_to_le16(((vsi_id <<
					 ICE_AQC_GSET_RSS_KEY_VSI_ID_S) &
					ICE_AQC_GSET_RSS_KEY_VSI_ID_M) |
				       ICE_AQC_GSET_RSS_KEY_VSI_VALID);

	return ice_aq_send_cmd(hw, &desc, key, key_size, NULL);
}

/**
 * ice_aq_get_rss_key
 * @hw: pointer to the HW struct
 * @vsi_handle: software VSI handle
 * @key: pointer to key info struct
 *
 * get the RSS key per VSI
 */
enum ice_status
ice_aq_get_rss_key(struct ice_hw *hw, u16 vsi_handle,
		   struct ice_aqc_get_set_rss_keys *key)
{
	if (!ice_is_vsi_valid(hw, vsi_handle) || !key)
		return ICE_ERR_PARAM;

	return __ice_aq_get_set_rss_key(hw, ice_get_hw_vsi_num(hw, vsi_handle),
					key, false);
}

/**
 * ice_aq_set_rss_key
 * @hw: pointer to the HW struct
 * @vsi_handle: software VSI handle
 * @keys: pointer to key info struct
 *
 * set the RSS key per VSI
 */
enum ice_status
ice_aq_set_rss_key(struct ice_hw *hw, u16 vsi_handle,
		   struct ice_aqc_get_set_rss_keys *keys)
{
	if (!ice_is_vsi_valid(hw, vsi_handle) || !keys)
		return ICE_ERR_PARAM;

	return __ice_aq_get_set_rss_key(hw, ice_get_hw_vsi_num(hw, vsi_handle),
					keys, true);
}

/**
 * ice_aq_add_lan_txq
 * @hw: pointer to the hardware structure
 * @num_qgrps: Number of added queue groups
 * @qg_list: list of queue groups to be added
 * @buf_size: size of buffer for indirect command
 * @cd: pointer to command details structure or NULL
 *
 * Add Tx LAN queue (0x0C30)
 *
 * NOTE:
 * Prior to calling add Tx LAN queue:
 * Initialize the following as part of the Tx queue context:
 * Completion queue ID if the queue uses Completion queue, Quanta profile,
 * Cache profile and Packet shaper profile.
 *
 * After add Tx LAN queue AQ command is completed:
 * Interrupts should be associated with specific queues,
 * Association of Tx queue to Doorbell queue is not part of Add LAN Tx queue
 * flow.
 */
static enum ice_status
ice_aq_add_lan_txq(struct ice_hw *hw, u8 num_qgrps,
		   struct ice_aqc_add_tx_qgrp *qg_list, u16 buf_size,
		   struct ice_sq_cd *cd)
{
	u16 i, sum_header_size, sum_q_size = 0;
	struct ice_aqc_add_tx_qgrp *list;
	struct ice_aqc_add_txqs *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.add_txqs;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_add_txqs);

	if (!qg_list)
		return ICE_ERR_PARAM;

	if (num_qgrps > ICE_LAN_TXQ_MAX_QGRPS)
		return ICE_ERR_PARAM;

	sum_header_size = num_qgrps *
		(sizeof(*qg_list) - sizeof(*qg_list->txqs));

	list = qg_list;
	for (i = 0; i < num_qgrps; i++) {
		struct ice_aqc_add_txqs_perq *q = list->txqs;

		sum_q_size += list->num_txqs * sizeof(*q);
		list = (struct ice_aqc_add_tx_qgrp *)(q + list->num_txqs);
	}

	if (buf_size != (sum_header_size + sum_q_size))
		return ICE_ERR_PARAM;

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	cmd->num_qgrps = num_qgrps;

	return ice_aq_send_cmd(hw, &desc, qg_list, buf_size, cd);
}

/**
 * ice_aq_dis_lan_txq
 * @hw: pointer to the hardware structure
 * @num_qgrps: number of groups in the list
 * @qg_list: the list of groups to disable
 * @buf_size: the total size of the qg_list buffer in bytes
 * @rst_src: if called due to reset, specifies the reset source
 * @vmvf_num: the relative VM or VF number that is undergoing the reset
 * @cd: pointer to command details structure or NULL
 *
 * Disable LAN Tx queue (0x0C31)
 */
static enum ice_status
ice_aq_dis_lan_txq(struct ice_hw *hw, u8 num_qgrps,
		   struct ice_aqc_dis_txq_item *qg_list, u16 buf_size,
		   enum ice_disq_rst_src rst_src, u16 vmvf_num,
		   struct ice_sq_cd *cd)
{
	struct ice_aqc_dis_txqs *cmd;
	struct ice_aq_desc desc;
	enum ice_status status;
	u16 i, sz = 0;

	cmd = &desc.params.dis_txqs;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_dis_txqs);

	/* qg_list can be NULL only in VM/VF reset flow */
	if (!qg_list && !rst_src)
		return ICE_ERR_PARAM;

	if (num_qgrps > ICE_LAN_TXQ_MAX_QGRPS)
		return ICE_ERR_PARAM;

	cmd->num_entries = num_qgrps;

	cmd->vmvf_and_timeout = cpu_to_le16((5 << ICE_AQC_Q_DIS_TIMEOUT_S) &
					    ICE_AQC_Q_DIS_TIMEOUT_M);

	switch (rst_src) {
	case ICE_VM_RESET:
		cmd->cmd_type = ICE_AQC_Q_DIS_CMD_VM_RESET;
		cmd->vmvf_and_timeout |=
			cpu_to_le16(vmvf_num & ICE_AQC_Q_DIS_VMVF_NUM_M);
		break;
	case ICE_VF_RESET:
		cmd->cmd_type = ICE_AQC_Q_DIS_CMD_VF_RESET;
		/* In this case, FW expects vmvf_num to be absolute VF ID */
		cmd->vmvf_and_timeout |=
			cpu_to_le16((vmvf_num + hw->func_caps.vf_base_id) &
				    ICE_AQC_Q_DIS_VMVF_NUM_M);
		break;
	case ICE_NO_RESET:
	default:
		break;
	}

	/* flush pipe on time out */
	cmd->cmd_type |= ICE_AQC_Q_DIS_CMD_FLUSH_PIPE;
	/* If no queue group info, we are in a reset flow. Issue the AQ */
	if (!qg_list)
		goto do_aq;

	/* set RD bit to indicate that command buffer is provided by the driver
	 * and it needs to be read by the firmware
	 */
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	for (i = 0; i < num_qgrps; ++i) {
		/* Calculate the size taken up by the queue IDs in this group */
		sz += qg_list[i].num_qs * sizeof(qg_list[i].q_id);

		/* Add the size of the group header */
		sz += sizeof(qg_list[i]) - sizeof(qg_list[i].q_id);

		/* If the num of queues is even, add 2 bytes of padding */
		if ((qg_list[i].num_qs % 2) == 0)
			sz += 2;
	}

	if (buf_size != sz)
		return ICE_ERR_PARAM;

do_aq:
	status = ice_aq_send_cmd(hw, &desc, qg_list, buf_size, cd);
	if (status) {
		if (!qg_list)
			ice_debug(hw, ICE_DBG_SCHED, "VM%d disable failed %d\n",
				  vmvf_num, hw->adminq.sq_last_status);
		else
			ice_debug(hw, ICE_DBG_SCHED, "disable queue %d failed %d\n",
				  le16_to_cpu(qg_list[0].q_id[0]),
				  hw->adminq.sq_last_status);
	}
	return status;
}

/**
 * ice_aq_move_recfg_lan_txq
 * @hw: pointer to the hardware structure
 * @num_qs: number of queues to move/reconfigure
 * @is_move: true if this operation involves node movement
 * @is_tc_change: true if this operation involves a TC change
 * @subseq_call: true if this operation is a subsequent call
 * @flush_pipe: on timeout, true to flush pipe, false to return EAGAIN
 * @timeout: timeout in units of 100 usec (valid values 0-50)
 * @blocked_cgds: out param, bitmap of CGDs that timed out if returning EAGAIN
 * @buf: struct containing src/dest TEID and per-queue info
 * @buf_size: size of buffer for indirect command
 * @txqs_moved: out param, number of queues successfully moved
 * @cd: pointer to command details structure or NULL
 *
 * Move / Reconfigure Tx LAN queues (0x0C32)
 */
enum ice_status
ice_aq_move_recfg_lan_txq(struct ice_hw *hw, u8 num_qs, bool is_move,
			  bool is_tc_change, bool subseq_call, bool flush_pipe,
			  u8 timeout, u32 *blocked_cgds,
			  struct ice_aqc_move_txqs_data *buf, u16 buf_size,
			  u8 *txqs_moved, struct ice_sq_cd *cd)
{
	struct ice_aqc_move_txqs *cmd;
	struct ice_aq_desc desc;
	enum ice_status status;

	cmd = &desc.params.move_txqs;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_move_recfg_txqs);

#define ICE_LAN_TXQ_MOVE_TIMEOUT_MAX 50
	if (timeout > ICE_LAN_TXQ_MOVE_TIMEOUT_MAX)
		return ICE_ERR_PARAM;

	if (is_tc_change && !flush_pipe && !blocked_cgds)
		return ICE_ERR_PARAM;

	if (!is_move && !is_tc_change)
		return ICE_ERR_PARAM;

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	if (is_move)
		cmd->cmd_type |= ICE_AQC_Q_CMD_TYPE_MOVE;

	if (is_tc_change)
		cmd->cmd_type |= ICE_AQC_Q_CMD_TYPE_TC_CHANGE;

	if (subseq_call)
		cmd->cmd_type |= ICE_AQC_Q_CMD_SUBSEQ_CALL;

	if (flush_pipe)
		cmd->cmd_type |= ICE_AQC_Q_CMD_FLUSH_PIPE;

	cmd->num_qs = num_qs;
	cmd->timeout = ((timeout << ICE_AQC_Q_CMD_TIMEOUT_S) &
			ICE_AQC_Q_CMD_TIMEOUT_M);

	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);

	if (!status && txqs_moved)
		*txqs_moved = cmd->num_qs;

	if (hw->adminq.sq_last_status == ICE_AQ_RC_EAGAIN &&
	    is_tc_change && !flush_pipe)
		*blocked_cgds = le32_to_cpu(cmd->blocked_cgds);

	return status;
}

/**
 * ice_aq_add_rdma_qsets
 * @hw: pointer to the hardware structure
 * @num_qset_grps: Number of RDMA Qset groups
 * @qset_list: list of qset groups to be added
 * @buf_size: size of buffer for indirect command
 * @cd: pointer to command details structure or NULL
 *
 * Add Tx RDMA Qsets (0x0C33)
 */
static enum ice_status
ice_aq_add_rdma_qsets(struct ice_hw *hw, u8 num_qset_grps,
		      struct ice_aqc_add_rdma_qset_data *qset_list,
		      u16 buf_size, struct ice_sq_cd *cd)
{
	struct ice_aqc_add_rdma_qset_data *list;
	u16 i, sum_header_size, sum_q_size = 0;
	struct ice_aqc_add_rdma_qset *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.add_rdma_qset;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_add_rdma_qset);

	if (!qset_list)
		return ICE_ERR_PARAM;

	if (num_qset_grps > ICE_LAN_TXQ_MAX_QGRPS)
		return ICE_ERR_PARAM;

	sum_header_size = num_qset_grps *
		(sizeof(*qset_list) - sizeof(*qset_list->rdma_qsets));

	list = qset_list;
	for (i = 0; i < num_qset_grps; i++) {
		struct ice_aqc_add_tx_rdma_qset_entry *qset = list->rdma_qsets;
		u16 num_qsets = le16_to_cpu(list->num_qsets);

		sum_q_size += num_qsets * sizeof(*qset);
		list = (struct ice_aqc_add_rdma_qset_data *)
			(qset + num_qsets);
	}

	if (buf_size != (sum_header_size + sum_q_size))
		return ICE_ERR_PARAM;

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	cmd->num_qset_grps = num_qset_grps;

	return ice_aq_send_cmd(hw, &desc, qset_list, buf_size, cd);
}

/* End of FW Admin Queue command wrappers */

/**
 * ice_write_byte - write a byte to a packed context structure
 * @src_ctx:  the context structure to read from
 * @dest_ctx: the context to be written to
 * @ce_info:  a description of the struct to be filled
 */
static void
ice_write_byte(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info)
{
	u8 src_byte, dest_byte, mask;
	u8 *from, *dest;
	u16 shift_width;

	/* copy from the next struct field */
	from = src_ctx + ce_info->offset;

	/* prepare the bits and mask */
	shift_width = ce_info->lsb % 8;
	mask = (u8)(BIT(ce_info->width) - 1);

	src_byte = *from;
	src_byte &= mask;

	/* shift to correct alignment */
	mask <<= shift_width;
	src_byte <<= shift_width;

	/* get the current bits from the target bit string */
	dest = dest_ctx + (ce_info->lsb / 8);

	memcpy(&dest_byte, dest, sizeof(dest_byte));

	dest_byte &= ~mask;	/* get the bits not changing */
	dest_byte |= src_byte;	/* add in the new bits */

	/* put it all back */
	memcpy(dest, &dest_byte, sizeof(dest_byte));
}

/**
 * ice_write_word - write a word to a packed context structure
 * @src_ctx:  the context structure to read from
 * @dest_ctx: the context to be written to
 * @ce_info:  a description of the struct to be filled
 */
static void
ice_write_word(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info)
{
	u16 src_word, mask;
	__le16 dest_word;
	u8 *from, *dest;
	u16 shift_width;

	/* copy from the next struct field */
	from = src_ctx + ce_info->offset;

	/* prepare the bits and mask */
	shift_width = ce_info->lsb % 8;
	mask = BIT(ce_info->width) - 1;

	/* don't swizzle the bits until after the mask because the mask bits
	 * will be in a different bit position on big endian machines
	 */
	src_word = *(u16 *)from;
	src_word &= mask;

	/* shift to correct alignment */
	mask <<= shift_width;
	src_word <<= shift_width;

	/* get the current bits from the target bit string */
	dest = dest_ctx + (ce_info->lsb / 8);

	memcpy(&dest_word, dest, sizeof(dest_word));

	dest_word &= ~(cpu_to_le16(mask));	/* get the bits not changing */
	dest_word |= cpu_to_le16(src_word);	/* add in the new bits */

	/* put it all back */
	memcpy(dest, &dest_word, sizeof(dest_word));
}

/**
 * ice_write_dword - write a dword to a packed context structure
 * @src_ctx:  the context structure to read from
 * @dest_ctx: the context to be written to
 * @ce_info:  a description of the struct to be filled
 */
static void
ice_write_dword(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info)
{
	u32 src_dword, mask;
	__le32 dest_dword;
	u8 *from, *dest;
	u16 shift_width;

	/* copy from the next struct field */
	from = src_ctx + ce_info->offset;

	/* prepare the bits and mask */
	shift_width = ce_info->lsb % 8;

	/* if the field width is exactly 32 on an x86 machine, then the shift
	 * operation will not work because the SHL instructions count is masked
	 * to 5 bits so the shift will do nothing
	 */
	if (ce_info->width < 32)
		mask = BIT(ce_info->width) - 1;
	else
		mask = (u32)~0;

	/* don't swizzle the bits until after the mask because the mask bits
	 * will be in a different bit position on big endian machines
	 */
	src_dword = *(u32 *)from;
	src_dword &= mask;

	/* shift to correct alignment */
	mask <<= shift_width;
	src_dword <<= shift_width;

	/* get the current bits from the target bit string */
	dest = dest_ctx + (ce_info->lsb / 8);

	memcpy(&dest_dword, dest, sizeof(dest_dword));

	dest_dword &= ~(cpu_to_le32(mask));	/* get the bits not changing */
	dest_dword |= cpu_to_le32(src_dword);	/* add in the new bits */

	/* put it all back */
	memcpy(dest, &dest_dword, sizeof(dest_dword));
}

/**
 * ice_write_qword - write a qword to a packed context structure
 * @src_ctx:  the context structure to read from
 * @dest_ctx: the context to be written to
 * @ce_info:  a description of the struct to be filled
 */
static void
ice_write_qword(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info)
{
	u64 src_qword, mask;
	__le64 dest_qword;
	u8 *from, *dest;
	u16 shift_width;

	/* copy from the next struct field */
	from = src_ctx + ce_info->offset;

	/* prepare the bits and mask */
	shift_width = ce_info->lsb % 8;

	/* if the field width is exactly 64 on an x86 machine, then the shift
	 * operation will not work because the SHL instructions count is masked
	 * to 6 bits so the shift will do nothing
	 */
	if (ce_info->width < 64)
		mask = BIT_ULL(ce_info->width) - 1;
	else
		mask = (u64)~0;

	/* don't swizzle the bits until after the mask because the mask bits
	 * will be in a different bit position on big endian machines
	 */
	src_qword = *(u64 *)from;
	src_qword &= mask;

	/* shift to correct alignment */
	mask <<= shift_width;
	src_qword <<= shift_width;

	/* get the current bits from the target bit string */
	dest = dest_ctx + (ce_info->lsb / 8);

	memcpy(&dest_qword, dest, sizeof(dest_qword));

	dest_qword &= ~(cpu_to_le64(mask));	/* get the bits not changing */
	dest_qword |= cpu_to_le64(src_qword);	/* add in the new bits */

	/* put it all back */
	memcpy(dest, &dest_qword, sizeof(dest_qword));
}

/**
 * ice_set_ctx - set context bits in packed structure
 * @src_ctx:  pointer to a generic non-packed context structure
 * @dest_ctx: pointer to memory for the packed structure
 * @ce_info:  a description of the structure to be transformed
 */
enum ice_status
ice_set_ctx(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info)
{
	int f;

	for (f = 0; ce_info[f].width; f++) {
		/* We have to deal with each element of the FW response
		 * using the correct size so that we are correct regardless
		 * of the endianness of the machine.
		 */
		switch (ce_info[f].size_of) {
		case sizeof(u8):
			ice_write_byte(src_ctx, dest_ctx, &ce_info[f]);
			break;
		case sizeof(u16):
			ice_write_word(src_ctx, dest_ctx, &ce_info[f]);
			break;
		case sizeof(u32):
			ice_write_dword(src_ctx, dest_ctx, &ce_info[f]);
			break;
		case sizeof(u64):
			ice_write_qword(src_ctx, dest_ctx, &ce_info[f]);
			break;
		default:
			return ICE_ERR_INVAL_SIZE;
		}
	}

	return 0;
}


/**
 * ice_print_sched_elem - parse through an element struct in a branch
 * @hw: ice hardware struct
 * @elem: element number in a branch
 * @data: corresponding element info struct to extract data from
 */
static void
ice_print_sched_elem(struct ice_hw *hw, int elem,
		     struct ice_aqc_txsched_elem_data *data)
{
	struct ice_aqc_txsched_elem *d = &data->data;
	unsigned long valid_sec = d->valid_sections;
	char str[128];
	int i;

	dev_info(ice_hw_to_dev(hw), "\t\telement %d\n", elem);
	dev_info(ice_hw_to_dev(hw), "\t\t\tparent TEID %d\n",
		 le32_to_cpu(data->parent_teid));
	dev_info(ice_hw_to_dev(hw), "\t\t\tnode TEID %d\n",
		 le32_to_cpu(data->node_teid));

	switch (d->elem_type) {
	case ICE_AQC_ELEM_TYPE_UNDEFINED:
		snprintf(str, sizeof(str), "undefined");
		break;
	case ICE_AQC_ELEM_TYPE_ROOT_PORT:
		snprintf(str, sizeof(str), "root port");
		break;
	case ICE_AQC_ELEM_TYPE_TC:
		snprintf(str, sizeof(str), "tc");
		break;
	case ICE_AQC_ELEM_TYPE_SE_GENERIC:
		snprintf(str, sizeof(str), "se generic");
		break;
	case ICE_AQC_ELEM_TYPE_ENTRY_POINT:
		snprintf(str, sizeof(str), "sw entry point se");
		break;
	case ICE_AQC_ELEM_TYPE_LEAF:
		snprintf(str, sizeof(str), "leaf");
		break;
	case ICE_AQC_ELEM_TYPE_SE_PADDED:
		snprintf(str, sizeof(str), "se padded");
		break;
	default:
		snprintf(str, sizeof(str), "unknown");
		break;
	}
	dev_info(ice_hw_to_dev(hw), "\t\t\telement type %s\n", str);

	dev_info(ice_hw_to_dev(hw), "\t\t\tvalid sections\n");
	/* iterate through valid sections */
	for_each_set_bit(i, &valid_sec, ICE_SCHED_VALID_SEC_BITS) {
		switch (BIT(i)) {
		case ICE_AQC_ELEM_VALID_GENERIC:
			snprintf(str, sizeof(str), "generic section");
			break;
		case ICE_AQC_ELEM_VALID_CIR:
			snprintf(str, sizeof(str),
				 "cir bw:profile id %d, weight %d",
				 le16_to_cpu(d->cir_bw.bw_profile_idx),
				 le16_to_cpu(d->cir_bw.bw_alloc));
			break;
		case ICE_AQC_ELEM_VALID_EIR:
			snprintf(str, sizeof(str),
				 "eir bw:profile id %d, weight %d",
				 le16_to_cpu(d->eir_bw.bw_profile_idx),
				 le16_to_cpu(d->eir_bw.bw_alloc));
			break;
		case ICE_AQC_ELEM_VALID_SHARED:
			snprintf(str, sizeof(str),
				 "shared bw: rl profile id %d",
				 le16_to_cpu(d->srl_id));
			break;
		default:
			snprintf(str, sizeof(str), "unknown");
			break;
		}
		dev_info(ice_hw_to_dev(hw), "\t\t\t\t%s\n", str);
	}

	dev_info(ice_hw_to_dev(hw), "\t\t\tgeneric\n");
	snprintf(str, sizeof(str), "%s",
		 (d->generic & ICE_AQC_ELEM_GENERIC_MODE_M) ?  "pss" : "bps");
	dev_info(ice_hw_to_dev(hw), "\t\t\t\tscheduling mode %s\n", str);

	dev_info(ice_hw_to_dev(hw), "\t\t\t\tpriority %d\n",
		 ((d->generic & ICE_AQC_ELEM_GENERIC_PRIO_M) >> ICE_AQC_ELEM_GENERIC_PRIO_S));

	dev_info(ice_hw_to_dev(hw), "\t\t\t\tadjustment value %d\n",
		 (d->generic & ICE_AQC_ELEM_GENERIC_ADJUST_VAL_M) >> ICE_AQC_ELEM_GENERIC_ADJUST_VAL_S);
}

/**
 * ice_dump_port_dflt_topo - print scheduler tree topology for a port
 * @pi: pointer to the port_info structure
 */
enum ice_status ice_dump_port_dflt_topo(struct ice_port_info *pi)
{
	struct ice_aqc_get_topo_elem *buf;
	struct ice_hw *hw = pi->hw;
	u16 j, buf_size, num_elem;
	enum ice_status ret;
	u8 i, num_branches;

	/* allocate memory for response buffer */
	buf_size = sizeof(*buf) * ICE_TXSCHED_MAX_BRANCHES;
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return ICE_ERR_NO_MEMORY;
	ret = ice_aq_get_dflt_topo(hw, pi->lport, buf, buf_size, &num_branches,
				   NULL);
	if (ret) {
		ret = ICE_ERR_CFG;
		goto err_exit;
	}

	if (num_branches < 2 || num_branches > ICE_TXSCHED_MAX_BRANCHES)
		dev_info(ice_hw_to_dev(hw),
			 "CHECK: num_branches unexpected %d\n", num_branches);

	dev_info(ice_hw_to_dev(hw), "scheduler tree topology for port %d\n",
		 pi->lport);

	/* iterate through all branches */
	for (i = 0; i < num_branches; i++) {
		dev_info(ice_hw_to_dev(hw), "\tbranch %d\n", i);
		num_elem = le16_to_cpu(buf[i].hdr.num_elems);

		if (num_elem < 2 || num_elem > ICE_AQC_TOPO_MAX_LEVEL_NUM)
			dev_info(ice_hw_to_dev(hw),
				 "CHECK: num_elems unexpected %d\n", num_elem);
		/* iterate through all elements in a branch */
		for (j = 0; j < num_elem; j++)
			ice_print_sched_elem(hw, j, &buf[i].generic[j]);
	}

err_exit:
	devm_kfree(ice_hw_to_dev(hw), buf);
	return ret;
}

/**
 * ice_sched_print_tree - prints the node information
 * @hw: pointer to the HW struct
 * @node: pointer to the node
 *
 * This function prints the node and all its children information
 */
static void ice_sched_print_tree(struct ice_hw *hw, struct ice_sched_node *node)
{
	struct ice_aqc_get_elem buf;
	enum ice_status status;
	u8 i;

	if (!node)
		return;
	for (i = 0; i < node->num_children; i++)
		ice_sched_print_tree(hw, node->children[i]);
	ice_debug(hw, ICE_DBG_SCHED, "Node Layer: 0x%x Node TEID: 0x%x Parent TEID: 0x%x num_children: %d tc_num :0x%x\n",
		  node->tx_sched_layer, le32_to_cpu(node->info.node_teid),
		  le32_to_cpu(node->info.parent_teid), node->num_children,
		  node->tc_num);
	/* print the current RL values and suspend state */
	status = ice_sched_query_elem(hw,  le32_to_cpu(node->info.node_teid),
				      &buf);
	if (status)
		return;
	ice_debug(hw, ICE_DBG_SCHED, "elem type 0x%x valid sec 0x%x\n",
		  buf.generic[0].data.elem_type,
		  buf.generic[0].data.valid_sections);
	ice_debug(hw, ICE_DBG_SCHED, "generic 0x%x Flags 0x%x\n",
		  buf.generic[0].data.generic, buf.generic[0].data.flags);
	ice_debug(hw, ICE_DBG_SCHED, "BW Profile: CIR id 0x%x alloc 0x%x EIR id 0x%x alloc 0x%x SRL id alloc 0x%x\n",
		  le16_to_cpu(buf.generic[0].data.cir_bw.bw_profile_idx),
		  le16_to_cpu(buf.generic[0].data.cir_bw.bw_alloc),
		  le16_to_cpu(buf.generic[0].data.eir_bw.bw_profile_idx),
		  le16_to_cpu(buf.generic[0].data.eir_bw.bw_alloc),
		  le16_to_cpu(buf.generic[0].data.srl_id));
}

/**
 * ice_dump_port_topo - prints the tree topology of the port
 * @pi: port information structure
 *
 * This function prints the tree topology of the port
 */
void ice_dump_port_topo(struct ice_port_info *pi)
{
	struct ice_hw *hw;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return;
	hw = pi->hw;
	if (!(hw->debug_mask & ICE_DBG_SCHED))
		return;
	mutex_lock(&pi->sched_lock);
	ice_sched_print_tree(hw, pi->root);
	mutex_unlock(&pi->sched_lock);
}

/**
 * ice_dump_common_caps - print struct ice_hw_common_caps fields
 * @hw: pointer to the ice_hw instance
 * @caps: pointer to common caps instance
 * @prefix: string to prefix when printing
 */
static void
ice_dump_common_caps(struct ice_hw *hw, struct ice_hw_common_caps *caps,
		     char const *prefix)
{
	dev_info(ice_hw_to_dev(hw), "%s: switching_mode = %d\n", prefix,
		 caps->switching_mode);
	dev_info(ice_hw_to_dev(hw), "%s: mgmt_mode = %d\n", prefix,
		 caps->mgmt_mode);
	dev_info(ice_hw_to_dev(hw), "%s: mgmt_protocols_mctp = %d\n", prefix,
		 caps->mgmt_protocols_mctp);
	dev_info(ice_hw_to_dev(hw), "%s: os2bmc = %d\n", prefix, caps->os2bmc);
	dev_info(ice_hw_to_dev(hw), "%s: valid_functions (bitmap) = %d\n",
		 prefix, caps->valid_functions);
	dev_info(ice_hw_to_dev(hw), "%s: sr_iov_1_1 = %d\n", prefix,
		 caps->sr_iov_1_1);
	dev_info(ice_hw_to_dev(hw), "%s: vmdq = %d\n", prefix, caps->vmdq);
	dev_info(ice_hw_to_dev(hw), "%s: evb_802_1_qbg = %d\n", prefix,
		 caps->evb_802_1_qbg);
	dev_info(ice_hw_to_dev(hw), "%s: evb_802_1_qbh = %d\n", prefix,
		 caps->evb_802_1_qbh);
	dev_info(ice_hw_to_dev(hw), "%s: dcb = %d\n", prefix, caps->dcb);
	dev_info(ice_hw_to_dev(hw), "%s: active_tc_bitmap = %d\n", prefix,
		 caps->active_tc_bitmap);
	dev_info(ice_hw_to_dev(hw), "%s: maxtc = %d\n", prefix, caps->maxtc);
	dev_info(ice_hw_to_dev(hw), "%s: iscsi = %d\n", prefix, caps->iscsi);
	dev_info(ice_hw_to_dev(hw), "%s: rss_table_size = %d\n", prefix,
		 caps->rss_table_size);
	dev_info(ice_hw_to_dev(hw), "%s: rss_table_entry_width = %d\n",
		 prefix, caps->rss_table_entry_width);
	dev_info(ice_hw_to_dev(hw), "%s: num_rxq = %d\n", prefix,
		 caps->num_rxq);
	dev_info(ice_hw_to_dev(hw), "%s: rxq_first_id = %d\n", prefix,
		 caps->rxq_first_id);
	dev_info(ice_hw_to_dev(hw), "%s: num_txq = %d\n", prefix,
		 caps->num_txq);
	dev_info(ice_hw_to_dev(hw), "%s: txq_first_id = %d\n", prefix,
		 caps->txq_first_id);
	dev_info(ice_hw_to_dev(hw), "%s: num_msix_vectors = %d\n", prefix,
		 caps->num_msix_vectors);
	dev_info(ice_hw_to_dev(hw), "%s: msix_vector_first_id = %d\n", prefix,
		 caps->msix_vector_first_id);
	dev_info(ice_hw_to_dev(hw), "%s: mgmt_cem = %d\n", prefix,
		 caps->mgmt_cem);
	dev_info(ice_hw_to_dev(hw), "%s: iwarp = %d\n", prefix, caps->iwarp);
	dev_info(ice_hw_to_dev(hw), "%s: wr_csr_prot = 0x%llX\n", prefix,
		 (unsigned long long)caps->wr_csr_prot);
	dev_info(ice_hw_to_dev(hw), "%s: num_wol_proxy_fltr = %d\n", prefix,
		 caps->num_wol_proxy_fltr);
	dev_info(ice_hw_to_dev(hw), "%s: wol_proxy_vsi_seid = %d\n", prefix,
		 caps->wol_proxy_vsi_seid);
	dev_info(ice_hw_to_dev(hw), "%s: max_mtu = %d\n", prefix,
		 caps->max_mtu);
	ice_print_led_caps(hw, caps, prefix, false);
	ice_print_sdp_caps(hw, caps, prefix, false);
}

/**
 * ice_dump_func_caps - Dump function capabilities
 * @hw: pointer to the ice_hw instance
 * @func_caps: pointer to function capabilities struct
 */
static void
ice_dump_func_caps(struct ice_hw *hw, struct ice_hw_func_caps *func_caps)
{
	char const *prefix = "func cap";

	ice_dump_common_caps(hw, &func_caps->common_cap, prefix);
	dev_info(ice_hw_to_dev(hw), "%s: num_allocd_vfs = %d\n", prefix,
		 func_caps->num_allocd_vfs);
	dev_info(ice_hw_to_dev(hw), "%s: vf_base_id = %d\n", prefix,
		 func_caps->vf_base_id);
	dev_info(ice_hw_to_dev(hw), "%s: guar_num_vsi = %d\n", prefix,
		 func_caps->guar_num_vsi);
	dev_info(ice_hw_to_dev(hw), "%s: fd_fltr_guar = %d\n", prefix,
		 func_caps->fd_fltr_guar);
	dev_info(ice_hw_to_dev(hw), "%s: fd_fltr_best_effort = %d\n", prefix,
		 func_caps->fd_fltr_best_effort);
}

/**
 * ice_dump_dev_caps - Dump device capabilities
 * @hw: pointer to the ice_hw instance
 * @dev_caps: pointer to device capabilities struct
 */
static void
ice_dump_dev_caps(struct ice_hw *hw, struct ice_hw_dev_caps *dev_caps)
{
	char const *prefix = "dev cap";

	ice_dump_common_caps(hw, &dev_caps->common_cap, prefix);
	dev_info(ice_hw_to_dev(hw), "%s: num_vfs_exposed = %d\n", prefix,
		 dev_caps->num_vfs_exposed);
	dev_info(ice_hw_to_dev(hw), "%s: num_vsi_allocd_to_host = %d\n",
		 prefix, dev_caps->num_vsi_allocd_to_host);
	dev_info(ice_hw_to_dev(hw), "%s: num_flow_director_fltr = %d\n",
		 prefix, dev_caps->num_flow_director_fltr);
}

/**
 * ice_dump_caps - Dump a list of capabilities
 * @hw: pointer to the ice_hw instance
 */
void ice_dump_caps(struct ice_hw *hw)
{
	ice_dump_dev_caps(hw, &hw->dev_caps);
	ice_dump_func_caps(hw, &hw->func_caps);
}

/**
 * ice_dump_port_info - Dump data from the port_info array
 * @pi: pointer to the port_info structure
 */
void ice_dump_port_info(struct ice_port_info *pi)
{
	dev_info(ice_hw_to_dev(pi->hw), "\tvirt_port = %d\n", pi->lport);

	dev_info(ice_hw_to_dev(pi->hw), "\tswid = %d\n", pi->sw_id);
	dev_info(ice_hw_to_dev(pi->hw), "\tdflt_tx_vsi = %d\n",
		 pi->dflt_tx_vsi_num);
	dev_info(ice_hw_to_dev(pi->hw), "\tdflt_rx_vsi = %d\n",
		 pi->dflt_rx_vsi_num);
	dev_info(ice_hw_to_dev(pi->hw), "\t%s_num = %d\n",
		 (pi->is_vf ? "vf" : "pf"), pi->pf_vf_num);
	dev_info(ice_hw_to_dev(pi->hw), "\tlast_node_teid = %d\n",
		 pi->last_node_teid);
	dev_info(ice_hw_to_dev(pi->hw), "\tmedia_type = %d\n",
		 pi->phy.media_type);

	dev_info(ice_hw_to_dev(pi->hw), "\tmac_addr: %pM\n", pi->mac.lan_addr);
}



/**
 * ice_get_lan_q_ctx - get the LAN queue context for the given VSI and TC
 * @hw: pointer to the HW struct
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @q_handle: software queue handle
 */
struct ice_q_ctx *
ice_get_lan_q_ctx(struct ice_hw *hw, u16 vsi_handle, u8 tc, u16 q_handle)
{
	struct ice_vsi_ctx *vsi;
	struct ice_q_ctx *q_ctx;

	vsi = ice_get_vsi_ctx(hw, vsi_handle);
	if (!vsi)
		return NULL;
	if (q_handle >= vsi->num_lan_q_entries[tc])
		return NULL;
	if (!vsi->lan_q_ctx[tc])
		return NULL;
	q_ctx = vsi->lan_q_ctx[tc];
	return &q_ctx[q_handle];
}

/**
 * ice_ena_vsi_txq
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @q_handle: software queue handle
 * @num_qgrps: Number of added queue groups
 * @buf: list of queue groups to be added
 * @buf_size: size of buffer for indirect command
 * @cd: pointer to command details structure or NULL
 *
 * This function adds one LAN queue
 */
enum ice_status
ice_ena_vsi_txq(struct ice_port_info *pi, u16 vsi_handle, u8 tc, u16 q_handle,
		u8 num_qgrps, struct ice_aqc_add_tx_qgrp *buf, u16 buf_size,
		struct ice_sq_cd *cd)
{
	struct ice_aqc_txsched_elem_data node = { 0 };
	struct ice_sched_node *parent;
	struct ice_q_ctx *q_ctx;
	enum ice_status status;
	struct ice_hw *hw;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return ICE_ERR_CFG;

	if (num_qgrps > 1 || buf->num_txqs > 1)
		return ICE_ERR_MAX_LIMIT;

	hw = pi->hw;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&pi->sched_lock);

	q_ctx = ice_get_lan_q_ctx(hw, vsi_handle, tc, q_handle);
	if (!q_ctx) {
		ice_debug(hw, ICE_DBG_SCHED, "Enaq: invalid queue handle %d\n",
			  q_handle);
		status = ICE_ERR_PARAM;
		goto ena_txq_exit;
	}

	/* find a parent node */
	parent = ice_sched_get_free_qparent(pi, vsi_handle, tc,
					    ICE_SCHED_NODE_OWNER_LAN);
	if (!parent) {
		status = ICE_ERR_PARAM;
		goto ena_txq_exit;
	}

	buf->parent_teid = parent->info.node_teid;
	node.parent_teid = parent->info.node_teid;
	/* Mark that the values in the "generic" section as valid. The default
	 * value in the "generic" section is zero. This means that :
	 * - Scheduling mode is Bytes Per Second (BPS), indicated by Bit 0.
	 * - 0 priority among siblings, indicated by Bit 1-3.
	 * - WFQ, indicated by Bit 4.
	 * - 0 Adjustment value is used in PSM credit update flow, indicated by
	 * Bit 5-6.
	 * - Bit 7 is reserved.
	 * Without setting the generic section as valid in valid_sections, the
	 * Admin queue command will fail with error code ICE_AQ_RC_EINVAL.
	 */
	buf->txqs[0].info.valid_sections = ICE_AQC_ELEM_VALID_GENERIC;

	/* add the LAN queue */
	status = ice_aq_add_lan_txq(hw, num_qgrps, buf, buf_size, cd);
	if (status) {
		ice_debug(hw, ICE_DBG_SCHED, "enable queue %d failed %d\n",
			  le16_to_cpu(buf->txqs[0].txq_id),
			  hw->adminq.sq_last_status);
		goto ena_txq_exit;
	}

	node.node_teid = buf->txqs[0].q_teid;
	node.data.elem_type = ICE_AQC_ELEM_TYPE_LEAF;
	q_ctx->q_handle = q_handle;
	q_ctx->q_teid = le32_to_cpu(node.node_teid);

	/* add a leaf node into scheduler tree queue layer */
	status = ice_sched_add_node(pi, hw->num_tx_sched_layers - 1, &node);
	if (!status)
		status = ice_sched_replay_q_bw(pi, q_ctx);

ena_txq_exit:
	mutex_unlock(&pi->sched_lock);
	return status;
}

/**
 * ice_dis_vsi_txq
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @num_queues: number of queues
 * @q_handles: pointer to software queue handle array
 * @q_ids: pointer to the q_id array
 * @q_teids: pointer to queue node teids
 * @rst_src: if called due to reset, specifies the reset source
 * @vmvf_num: the relative VM or VF number that is undergoing the reset
 * @cd: pointer to command details structure or NULL
 *
 * This function removes queues and their corresponding nodes in SW DB
 */
enum ice_status
ice_dis_vsi_txq(struct ice_port_info *pi, u16 vsi_handle, u8 tc, u8 num_queues,
		u16 *q_handles, u16 *q_ids, u32 *q_teids,
		enum ice_disq_rst_src rst_src, u16 vmvf_num,
		struct ice_sq_cd *cd)
{
	enum ice_status status = ICE_ERR_DOES_NOT_EXIST;
	struct ice_aqc_dis_txq_item qg_list;
	struct ice_q_ctx *q_ctx;
	u16 i;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return ICE_ERR_CFG;

	if (!num_queues) {
		/* if queue is disabled already yet the disable queue command
		 * has to be sent to complete the VF reset, then call
		 * ice_aq_dis_lan_txq without any queue information
		 */
		if (rst_src)
			return ice_aq_dis_lan_txq(pi->hw, 0, NULL, 0, rst_src,
						  vmvf_num, NULL);
		return ICE_ERR_CFG;
	}

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < num_queues; i++) {
		struct ice_sched_node *node;

		node = ice_sched_find_node_by_teid(pi->root, q_teids[i]);
		if (!node)
			continue;
		q_ctx = ice_get_lan_q_ctx(pi->hw, vsi_handle, tc, q_handles[i]);
		if (!q_ctx) {
			ice_debug(pi->hw, ICE_DBG_SCHED, "invalid queue handle%d\n",
				  q_handles[i]);
			continue;
		}
		if (q_ctx->q_handle != q_handles[i]) {
			ice_debug(pi->hw, ICE_DBG_SCHED, "Err:handles %d %d\n",
				  q_ctx->q_handle, q_handles[i]);
			continue;
		}
		qg_list.parent_teid = node->info.parent_teid;
		qg_list.num_qs = 1;
		qg_list.q_id[0] = cpu_to_le16(q_ids[i]);
		status = ice_aq_dis_lan_txq(pi->hw, 1, &qg_list,
					    sizeof(qg_list), rst_src, vmvf_num,
					    cd);

		if (status)
			break;
		ice_free_sched_node(pi, node);
		q_ctx->q_handle = ICE_INVAL_Q_HANDLE;
	}
	mutex_unlock(&pi->sched_lock);
	return status;
}

/**
 * ice_cfg_vsi_qs - configure the new/existing VSI queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @maxqs: max queues array per TC
 * @owner: LAN or RDMA
 *
 * This function adds/updates the VSI queues per TC.
 */
static enum ice_status
ice_cfg_vsi_qs(struct ice_port_info *pi, u16 vsi_handle, u8 tc_bitmap,
	       u16 *maxqs, u8 owner)
{
	enum ice_status status = 0;
	u8 i;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return ICE_ERR_CFG;

	if (!ice_is_vsi_valid(pi->hw, vsi_handle))
		return ICE_ERR_PARAM;

	mutex_lock(&pi->sched_lock);

	ice_for_each_traffic_class(i) {
		/* configuration is possible only if TC node is present */
		if (!ice_sched_get_tc_node(pi, i))
			continue;

		status = ice_sched_cfg_vsi(pi, vsi_handle, i, maxqs[i], owner,
					   ice_is_tc_ena(tc_bitmap, i));
		if (status)
			break;
	}

	mutex_unlock(&pi->sched_lock);
	return status;
}

/**
 * ice_cfg_vsi_lan - configure VSI LAN queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @max_lanqs: max LAN queues array per TC
 *
 * This function adds/updates the VSI LAN queues per TC.
 */
enum ice_status
ice_cfg_vsi_lan(struct ice_port_info *pi, u16 vsi_handle, u8 tc_bitmap,
		u16 *max_lanqs)
{
	return ice_cfg_vsi_qs(pi, vsi_handle, tc_bitmap, max_lanqs,
			      ICE_SCHED_NODE_OWNER_LAN);
}

/**
 * ice_cfg_vsi_rdma - configure the VSI RDMA queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @max_rdmaqs: max RDMA queues array per TC
 *
 * This function adds/updates the VSI RDMA queues per TC.
 */
enum ice_status
ice_cfg_vsi_rdma(struct ice_port_info *pi, u16 vsi_handle, u8 tc_bitmap,
		 u16 *max_rdmaqs)
{
	return ice_cfg_vsi_qs(pi, vsi_handle, tc_bitmap, max_rdmaqs,
			      ICE_SCHED_NODE_OWNER_RDMA);
}

/**
 * ice_ena_vsi_rdma_qset
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @rdma_qset: pointer to RDMA qset
 * @num_qsets: number of RDMA qsets
 * @qset_teid: pointer to qset node teids
 *
 * This function adds RDMA qset
 */
enum ice_status
ice_ena_vsi_rdma_qset(struct ice_port_info *pi, u16 vsi_handle, u8 tc,
		      u16 *rdma_qset, u16 num_qsets, u32 *qset_teid)
{
	struct ice_aqc_txsched_elem_data node = { 0 };
	struct ice_aqc_add_rdma_qset_data *buf;
	struct ice_sched_node *parent;
	enum ice_status status;
	struct ice_hw *hw;
	u16 i, buf_size;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return ICE_ERR_CFG;
	hw = pi->hw;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	buf_size = sizeof(*buf) + sizeof(*buf->rdma_qsets) * (num_qsets - 1);
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return ICE_ERR_NO_MEMORY;
	mutex_lock(&pi->sched_lock);

	parent = ice_sched_get_free_qparent(pi, vsi_handle, tc,
					    ICE_SCHED_NODE_OWNER_RDMA);
	if (!parent) {
		status = ICE_ERR_PARAM;
		goto rdma_error_exit;
	}
	buf->parent_teid = parent->info.node_teid;
	node.parent_teid = parent->info.node_teid;

	buf->num_qsets = cpu_to_le16(num_qsets);
	for (i = 0; i < num_qsets; i++) {
		buf->rdma_qsets[i].tx_qset_id = cpu_to_le16(rdma_qset[i]);
		buf->rdma_qsets[i].info.valid_sections =
						ICE_AQC_ELEM_VALID_GENERIC;
	}
	status = ice_aq_add_rdma_qsets(hw, 1, buf, buf_size, NULL);
	if (status) {
		ice_debug(hw, ICE_DBG_RDMA, "add RDMA qset failed\n");
		goto rdma_error_exit;
	}
	node.data.elem_type = ICE_AQC_ELEM_TYPE_LEAF;
	for (i = 0; i < num_qsets; i++) {
		node.node_teid = buf->rdma_qsets[i].qset_teid;
		status = ice_sched_add_node(pi, hw->num_tx_sched_layers - 1,
					    &node);
		if (status)
			break;
		qset_teid[i] = le32_to_cpu(node.node_teid);
	}
rdma_error_exit:
	mutex_unlock(&pi->sched_lock);
	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_dis_vsi_rdma_qset - free RDMA resources
 * @pi: port_info struct
 * @count: number of RDMA qsets to free
 * @qset_teid: TEID of qset node
 * @q_id: list of queue IDs being disabled
 */
enum ice_status
ice_dis_vsi_rdma_qset(struct ice_port_info *pi, u16 count, u32 *qset_teid,
		      u16 *q_id)
{
	struct ice_aqc_dis_txq_item qg_list;
	enum ice_status status = 0;
	u16 qg_size;
	int i;

	if (!pi || pi->port_state != ICE_SCHED_PORT_STATE_READY)
		return ICE_ERR_CFG;

	qg_size = sizeof(qg_list);

	mutex_lock(&pi->sched_lock);

	for (i = 0; i < count; i++) {
		struct ice_sched_node *node;

		node = ice_sched_find_node_by_teid(pi->root, qset_teid[i]);
		if (!node)
			continue;

		qg_list.parent_teid = node->info.parent_teid;
		qg_list.num_qs = 1;
		qg_list.q_id[0] =
			cpu_to_le16(q_id[i] |
				    ICE_AQC_Q_DIS_BUF_ELEM_TYPE_RDMA_QSET);

		status = ice_aq_dis_lan_txq(pi->hw, 1, &qg_list, qg_size,
					    ICE_NO_RESET, 0, NULL);
		if (status)
			break;

		ice_free_sched_node(pi, node);
	}

	mutex_unlock(&pi->sched_lock);
	return status;
}


/**
 * ice_replay_pre_init - replay pre initialization
 * @hw: pointer to the HW struct
 *
 * Initializes required config data for VSI, FD, ACL, and RSS before replay.
 */
static enum ice_status ice_replay_pre_init(struct ice_hw *hw)
{
	struct ice_switch_info *sw = hw->switch_info;
	u8 i;

	/* Delete old entries from replay filter list head if there is any */
	ice_rm_all_sw_replay_rule_info(hw);
	/* In start of replay, move entries into replay_rules list, it
	 * will allow adding rules entries back to filt_rules list,
	 * which is operational list.
	 */
	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++)
		list_replace_init(&sw->recp_list[i].filt_rules,
				  &sw->recp_list[i].filt_replay_rules);
	ice_sched_replay_agg_vsi_preinit(hw);

	return ice_sched_replay_tc_node_bw(hw->port_info);
}

/**
 * ice_replay_vsi - replay VSI configuration
 * @hw: pointer to the HW struct
 * @vsi_handle: driver VSI handle
 *
 * Restore all VSI configuration after reset. It is required to call this
 * function with main VSI first.
 */
enum ice_status ice_replay_vsi(struct ice_hw *hw, u16 vsi_handle)
{
	enum ice_status status;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return ICE_ERR_PARAM;

	/* Replay pre-initialization if there is any */
	if (vsi_handle == ICE_MAIN_VSI_HANDLE) {
		status = ice_replay_pre_init(hw);
		if (status)
			return status;
	}
	/* Replay per VSI all RSS configurations */
	status = ice_replay_rss_cfg(hw, vsi_handle);
	if (status)
		return status;
	/* Replay per VSI all filters */
	status = ice_replay_vsi_all_fltr(hw, vsi_handle);
	if (!status)
		status = ice_replay_vsi_agg(hw, vsi_handle);
	return status;
}

/**
 * ice_replay_post - post replay configuration cleanup
 * @hw: pointer to the HW struct
 *
 * Post replay cleanup.
 */
void ice_replay_post(struct ice_hw *hw)
{
	/* Delete old entries from replay filter list head */
	ice_rm_all_sw_replay_rule_info(hw);
	ice_sched_replay_agg(hw);
}

/**
 * ice_stat_update40 - read 40 bit stat from the chip and update stat values
 * @hw: ptr to the hardware info
 * @reg: offset of 64 bit HW register to read from
 * @prev_stat_loaded: bool to specify if previous stats are loaded
 * @prev_stat: ptr to previous loaded stat value
 * @cur_stat: ptr to current stat value
 */
void
ice_stat_update40(struct ice_hw *hw, u32 reg, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	u64 new_data = rd64(hw, reg) & (BIT_ULL(40) - 1);

	/* device stats are not reset at PFR, they likely will not be zeroed
	 * when the driver starts. Thus, save the value from the first read
	 * without adding to the statistic value so that we report stats which
	 * count up from zero.
	 */
	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(40)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

/**
 * ice_stat_update32 - read 32 bit stat from the chip and update stat values
 * @hw: ptr to the hardware info
 * @reg: offset of HW register to read from
 * @prev_stat_loaded: bool to specify if previous stats are loaded
 * @prev_stat: ptr to previous loaded stat value
 * @cur_stat: ptr to current stat value
 */
void
ice_stat_update32(struct ice_hw *hw, u32 reg, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	u32 new_data;

	new_data = rd32(hw, reg);

	/* device stats are not reset at PFR, they likely will not be zeroed
	 * when the driver starts. Thus, save the value from the first read
	 * without adding to the statistic value so that we report stats which
	 * count up from zero.
	 */
	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}



/**
 * ice_sched_query_elem - query element information from HW
 * @hw: pointer to the HW struct
 * @node_teid: node TEID to be queried
 * @buf: buffer to element information
 *
 * This function queries HW element information
 */
enum ice_status
ice_sched_query_elem(struct ice_hw *hw, u32 node_teid,
		     struct ice_aqc_get_elem *buf)
{
	u16 buf_size, num_elem_ret = 0;
	enum ice_status status;

	buf_size = sizeof(*buf);
	memset(buf, 0, buf_size);
	buf->generic[0].node_teid = cpu_to_le32(node_teid);
	status = ice_aq_query_sched_elems(hw, 1, buf, buf_size, &num_elem_ret,
					  NULL);
	if (status || num_elem_ret != 1)
		ice_debug(hw, ICE_DBG_SCHED, "query element failed\n");
	return status;
}


/**
 * ice_get_fw_mode - returns FW mode
 * @hw: pointer to the HW struct
 */
enum ice_fw_modes ice_get_fw_mode(struct ice_hw *hw)
{
#define ICE_FW_MODE_DBG_M BIT(0)
#define ICE_FW_MODE_REC_M BIT(1)
#define ICE_FW_MODE_ROLLBACK_M BIT(2)
	u32 fw_mode;

	/* check the current FW mode */
	fw_mode = rd32(hw, GL_MNG_FWSM) & GL_MNG_FWSM_FW_MODES_M;

	if (fw_mode & ICE_FW_MODE_DBG_M)
		return ICE_FW_MODE_DBG;
	else if (fw_mode & ICE_FW_MODE_REC_M)
		return ICE_FW_MODE_REC;
	else if (fw_mode & ICE_FW_MODE_ROLLBACK_M)
		return ICE_FW_MODE_ROLLBACK;
	else
		return ICE_FW_MODE_NORMAL;
}

