/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* Intel(R) Ethernet Connection E800 Series Linux Driver IEPS extensions */

#include "ice.h"
#include "ice_ieps.h"
#include "ice_cpi.h"

struct ice_ieps_cpi_port_cfg {
	u8 port_mode;
	u8 port_width;
	u16 pmd_mode;
	u16 cu_rate;
	u8 cu_rate_opc;
	u8 cu_fec;
};

/**
 * ice_ieps_cpi_get_phy_caps - Get PHY capabilities
 * @pi: port information structure
 * @qual_mods: report qualified modules
 * @report_mode: report mode capabilities
 * @pcaps: structure for PHY capabilities to be filled
 * @cd: pointer to command details structure or NULL
 *
 * Returns various PHY capabilities supported on the Port
 * using PHY MNG CPI on success or negative value on failure.
 */
static int ice_ieps_cpi_get_phy_caps(struct ice_port_info *pi,
				     bool qual_mods, u8 report_mode,
				     struct ice_aqc_get_phy_caps_data *pcaps,
				     struct ice_sq_cd *cd)
{
	if (!pcaps || (report_mode & ~ICE_AQC_REPORT_MODE_M) || !pi)
		return -EINVAL;

	switch (report_mode) {
	case ICE_AQC_REPORT_TOPO_CAP_MEDIA:
	case ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA:
	case ICE_AQC_REPORT_DFLT_CFG:
	case ICE_AQC_REPORT_ACTIVE_CFG:
		memcpy(pcaps, &pi->hw->ieps_pcaps, sizeof(*pcaps));
		break;
	default:
		return -EINVAL;
	}

	if (report_mode == ICE_AQC_REPORT_ACTIVE_CFG) {
		pcaps->phy_type_low = pi->phy.curr_user_phy_cfg.phy_type_low;
		pcaps->phy_type_high = pi->phy.curr_user_phy_cfg.phy_type_high;
		pcaps->caps = pi->phy.curr_user_phy_cfg.caps;
		pcaps->low_power_ctrl_an =
				pi->phy.curr_user_phy_cfg.low_power_ctrl_an;
		pcaps->link_fec_options =
				pi->phy.curr_user_phy_cfg.link_fec_opt;
	}

	return 0;
}

/**
 * ice_ieps_cpi_set_phy_cfg - Set PHY configuration
 * @hw: pointer to the HW struct
 * @pi: port info structure of the interested logical port
 * @cfg: structure with PHY configuration data to be set
 * @cd: pointer to command details structure or NULL
 *
 * Set the various PHY configuration parameters supported
 * on the Port using PHY MNG CPI
 *
 * Return 0 on success, negative value otherwise
 */
static int ice_ieps_cpi_set_phy_cfg(struct ice_hw *hw,
				    struct ice_port_info *pi,
				    struct ice_aqc_set_phy_cfg_data *cfg,
				    struct ice_sq_cd *cd)
{
	int status = 0;
	bool ena_link;

	if (!cfg)
		return -EINVAL;

	/* Ensure that only valid bits of cfg->caps can be turned on. */
	if (cfg->caps & ~ICE_AQ_PHY_ENA_VALID_MASK) {
		dev_dbg(ice_hw_to_dev(pi->hw),
			"ERROR: Invalid bit is set in ice_aqc_set_phy_cfg_data->caps : 0x%x\n",
			cfg->caps);

		cfg->caps &= ICE_AQ_PHY_ENA_VALID_MASK;
	}

	/* Set the phy configuration stores the configuration in memory and
	 * triggers the DNL sequence when port mode is set up - 0x605 AQ is
	 * executed in regular DNL-based LM Flow.
	 *
	 * CPI based LM store cfg in phy.curr_user_phy_cfg structure and link
	 * will be setup when port set mode API is executed
	 */

	pi->phy.curr_user_phy_cfg = *cfg;

	/* Restart Auto-negotiation if AUTO_LINK_UPDT Bit is set */
	if (cfg->caps & ICE_AQ_PHY_ENA_AUTO_LINK_UPDT) {
		ena_link = !!(cfg->caps & ICE_AQC_PHY_EN_LINK);

		status = hw->lm_ops->restart_an(hw->port_info, ena_link, NULL,
						ICE_AQC_RESTART_AN_REFCLK_NOCHANGE);
		if (status)
			dev_dbg(ice_hw_to_dev(hw), "ERROR: restart_an status=%d\n",
				status);
	}

	return status;
}

/**
 * ice_ieps_cpi_get_link_info - Get link information
 * @pi: port information structure
 * @ena_lse: enable/disable LinkStatusEvent reporting
 * @link: pointer to link status structure - optional
 * @cd: pointer to command details structure or NULL
 *
 * Retrieve link information using CPI/MAC register
 *
 * Return 0 on success, negative value otherwise
 */
static int ice_ieps_cpi_get_link_info(struct ice_port_info *pi, bool ena_lse,
				      struct ice_link_status *link,
				      struct ice_sq_cd *cd)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ice_link_status *li = &pi->phy.link_info;
	struct ieps_peer_cpi_cmd_resp cpi = {};
	u16 max_frame_size, link_speed;
	struct ice_hw *hw = pi->hw;
	bool link_up;
	u8 fec_info;
	u32 val;

	/* save off old link status information */
	pi->phy.link_info_old = *li;

	pstatus = ice_ieps_get_link_state_speed(hw, &link_up, &link_speed);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(pi->hw), "ERROR: Failed to get link state_speed: 0x%x\n",
			pstatus);
		return -EFAULT;
	}

	/* Read DCB TPDU control register and max frame size information */
	val = rd32(hw, PRTDCB_TDPUC);
	max_frame_size = FIELD_GET(PRTDCB_TDPUC_MAX_TXFRAME_M, val);

	/* Update link status structure */
	if (link_up)
		li->link_info |= ICE_AQ_LINK_UP;
	else
		li->link_info &= ~ICE_AQ_LINK_UP;

	li->link_speed = link_speed;
	li->max_frame_size = max_frame_size;

	/* Return success if the link is not up. Negotiated FEC is not
	 * applicable when the link is in down state and the CPI
	 * opcode returns an error as port disabled.
	 */
	if (!(li->link_info & ICE_AQ_LINK_UP))
		return 0;

	/* Update FEC info */
	cpi.cmd.opcode = CPI_OPCODE_NEG_MODE;
	cpi.cmd.port = hw->bus.func;
	cpi.cmd.set = false;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi get neg mode failed\n");
		return -EFAULT;
	}

	fec_info = FIELD_GET(CPI_OPCODE_NEG_MODE_FEC_M, cpi.resp.data);
	switch (fec_info) {
	case CPI_OPCODE_NEG_MODE_FEC_BASE_R:
		li->fec_info = ICE_AQ_LINK_25G_KR_FEC_EN;
		break;
	case CPI_OPCODE_NEG_MODE_FEC_RS_528:
		li->fec_info = ICE_AQ_LINK_25G_RS_528_FEC_EN;
		break;
	case CPI_OPCODE_NEG_MODE_FEC_RS_544:
		li->fec_info = ICE_AQ_LINK_25G_RS_544_FEC_EN;
		break;
	default:
		li->fec_info = CPI_OPCODE_NEG_MODE_FEC_NONE;
		break;
	}

	if (li->fec_info)
		li->an_info |= ICE_AQ_FEC_EN;
	else
		li->an_info &= ~ICE_AQ_FEC_EN;

	/* save link status information */
	if (link)
		*link = *li;

	return 0;
}

/**
 * ice_ieps_cpi_set_port_cfg - Configure port parameter
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 * @lane: lane
 * @cmd: config status command
 *
 * Sets config status command on port
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_set_port_cfg(struct ice_hw *hw, u8 pcs_port, u8 lane, u16 cmd)
{
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;

	cpi.cmd.opcode = CPI_OPCODE_COMMAND;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = FIELD_PREP(CPI_OPCODE_COMMAND_CMD_M, cmd) |
		       FIELD_PREP(CPI_OPCODE_COMMAND_LANE_M, lane);
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus)
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi set port cfg failed\n");

	return pstatus;
}

/**
 * ice_ieps_cpi_disable_port - Disable port
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 *
 * Disable and reset port using PHY MNG CPI opcode
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_disable_port(struct ice_hw *hw, u8 pcs_port)
{
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;
	bool port_disable;

	cpi.cmd.opcode = CPI_OPCODE_PORT_STATE;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = false;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi port get state failed\n");
		return pstatus;
	}

	port_disable = FIELD_GET(CPI_OPCODE_PORT_STATE_DISABLE, cpi.resp.data);

	/* Reset Port if port is enabled */
	if (!port_disable) {
		pstatus = ice_ieps_cpi_set_port_cfg(hw, pcs_port, 0,
						    CPI_OPCODE_COMMAND_RESET_PORT);
		if (pstatus) {
			dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi port cfg set failed\n");
			return pstatus;
		}
	}

	/* Disable Port */
	cpi.cmd.opcode = CPI_OPCODE_PORT_STATE;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = CPI_OPCODE_PORT_STATE_DISABLE;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi disable port failed\n");
		return pstatus;
	}

	return pstatus;
}

/**
 * ice_ieps_cpi_reset_port - Reset port
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 *
 * Put eth56g PCS into reset and reset port
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_reset_port(struct ice_hw *hw, u8 pcs_port)
{
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;

#define PORT_DEFAULT_CONFIG	0x0

	/* Put eth56g PCS into reset */
	cpi.cmd.opcode = CPI_OPCODE_PHY_PCS_RESET;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = CPI_OPCODE_PHY_PCS_ONPI_RESET_VAL;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi phy pcs reset failed\n");
		return pstatus;
	}

	/* Enable port with default configuration */
	cpi.cmd.opcode = CPI_OPCODE_PORT_STATE;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = PORT_DEFAULT_CONFIG;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi set default cfg failed\n");
		return pstatus;
	}

	/* Reset port */
	pstatus = ice_ieps_cpi_set_port_cfg(hw, pcs_port, 0,
					    CPI_OPCODE_COMMAND_RESET_PORT);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: ieps cpi reset port failed\n");
		return pstatus;
	}

	return pstatus;
}

/**
 * ice_ieps_cpi_get_port_cfg - Get port configuration parameter
 * @hw: pointer to the hardware structure
 * @phy_type_low: lower part of phy_type
 * @phy_type_high: higher part of phy_type
 * @port_cfg: pointer to CPI port configuration structure
 *
 * Compute CPI port configuration parameter based on phy type
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_get_port_cfg(struct ice_hw *hw,
			  u64 phy_type_low, u64 phy_type_high,
			  struct ice_ieps_cpi_port_cfg *port_cfg)
{
	dev_dbg(ice_hw_to_dev(hw), "port get cfg phy_type_low=0x%llx phy_type_high=0x%llx\n",
		phy_type_low, phy_type_high);

	switch (phy_type_low) {
	case ICE_PHY_TYPE_LOW_100M_SGMII:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_SGMII;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_100M_SGMII;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_1000BASE_SX:
	case ICE_PHY_TYPE_LOW_1000BASE_LX:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_1000_BASE_X;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_1G_SGMII:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_SGMII;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_1G_SGMII;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_1000BASE_KX:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_1000BASE_KX;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_2500BASE_X:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_2500_BASE_X;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_2500BASE_KX:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_2500BASE_KX;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_5GBASE_KR:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_5GBASE_KR;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_10G_SFI_DA:
	case ICE_PHY_TYPE_LOW_10GBASE_SR:
	case ICE_PHY_TYPE_LOW_10GBASE_LR:
	case ICE_PHY_TYPE_LOW_10G_SFI_AOC_ACC:
	case ICE_PHY_TYPE_LOW_10G_SFI_C2C:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_10G_SFI;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_10GBASE_KR:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_10GBASE_KR;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25GBASE_SR:
	case ICE_PHY_TYPE_LOW_25GBASE_LR:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_25G_AUI;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25G_AUI_AOC_ACC:
	case ICE_PHY_TYPE_LOW_25G_AUI_C2C:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_25G_AUI;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25GBASE_KR:
	case ICE_PHY_TYPE_LOW_25GBASE_CR:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_25GBASE_CR_KR;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25GBASE_KR_S:
	case ICE_PHY_TYPE_LOW_25GBASE_CR_S:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_25GBASE_CR_KR_S;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25GBASE_CR1:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_25GBASE_CR1;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_25GBASE_KR1:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_25GBASE_KR1;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_40GBASE_KR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_40GBASE_KR4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_40GBASE_CR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE0;
		port_cfg->cu_rate = CPI_OPCODE_CURATE0_40GBASE_CR4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_50G_LAUI2_AOC_ACC:
	case ICE_PHY_TYPE_LOW_50G_LAUI2:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_TWO_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_50G_LAUI_2;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_50GBASE_CR_PAM4:
	case ICE_PHY_TYPE_LOW_50GBASE_KR_PAM4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_50GBASE_CP4_KP4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_50GBASE_SR:
	case ICE_PHY_TYPE_LOW_50GBASE_LR:
	case ICE_PHY_TYPE_LOW_50G_AUI1_AOC_ACC:
	case ICE_PHY_TYPE_LOW_50G_AUI1:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_SINGLE_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_50G_AUI_1;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_SR2:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_TWO_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_100G_AUI_2;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_CR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_100GBASE_CR4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_528_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_SR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_100G_CAUI_4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_528_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100G_CAUI4_AOC_ACC:
	case ICE_PHY_TYPE_LOW_100G_CAUI4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_100G_CAUI_4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_528_REQ |
				   ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_LR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_100G_CAUI_4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_DIS;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_KR4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_100GBASE_KR4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_528_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_LOW_100GBASE_CR2_PAM4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_100GBASE_CK_R2P4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;
	}

	switch (phy_type_high) {
	case ICE_PHY_TYPE_HIGH_100GBASE_KR2_PAM4:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_FOUR_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_AN73;
		port_cfg->cu_rate_opc = CPI_OPCODE_CURATE1;
		port_cfg->cu_rate = CPI_OPCODE_CURATE1_100GBASE_CK_R2P4;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_TRAINING;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;

	case ICE_PHY_TYPE_HIGH_100G_AUI2_AOC_ACC:
	case ICE_PHY_TYPE_HIGH_100G_AUI2:
		port_cfg->port_width = CPI_OPCODE_PORT_MODE_TWO_LANE;
		port_cfg->port_mode = CPI_OPCODE_PORT_MODE_100G_AUI_2;
		port_cfg->pmd_mode = CPI_OPCODE_PMD_CONTROL_SFI;
		port_cfg->cu_fec = ICE_AQC_PHY_FEC_25G_RS_544_REQ;
		return IEPS_PEER_SUCCESS;
	}

	return IEPS_PEER_PORT_INV_PHY_TYPE;
}

/**
 * ice_ieps_cpi_cfg_port_pmd_mode - Set port an PMD mode
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 * @port_cfg: pointer to the ice_ieps_cpi_port_cfg
 *
 * Configure port mode and PMD mode
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_cfg_port_pmd_mode(struct ice_hw *hw, u8 pcs_port,
			       struct ice_ieps_cpi_port_cfg *port_cfg)
{
	struct ice_port_info *pi = hw->port_info;
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;
	u8 low_power_ctrl_an;

	if (!port_cfg) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: port_cfg is NULL\n");
		return IEPS_PEER_INVALID_ARG;
	}

	/* Configure the port mode to use desired speed */
	cpi.cmd.opcode = CPI_OPCODE_PORT_MODE;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = FIELD_PREP(CPI_OPCODE_PORT_MODE_PORT_WIDTH_M,
				  port_cfg->port_width) |
		       FIELD_PREP(CPI_OPCODE_PORT_MODE_PORT_MODE_M,
				  port_cfg->port_mode);

	low_power_ctrl_an = pi->phy.curr_user_phy_cfg.low_power_ctrl_an;
	if ((port_cfg->port_mode == CPI_OPCODE_PORT_MODE_1000_BASE_X ||
	     port_cfg->port_mode == CPI_OPCODE_PORT_MODE_SGMII) &&
	     low_power_ctrl_an & ICE_AQC_PHY_AN_EN_CLAUSE37)
		cpi.cmd.data |= CPI_OPCODE_PORT_NEG_FORCED |
				CPI_OPCODE_PORT_AN37;

	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi set port mode failed\n");
		return pstatus;
	}

	/* configure training and DSP adaptations */
	cpi.cmd.opcode = CPI_OPCODE_PMD_CONTROL;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = port_cfg->pmd_mode;

	if (port_cfg->port_mode == CPI_OPCODE_PORT_MODE_SGMII ||
	    port_cfg->port_mode == CPI_OPCODE_PORT_MODE_1000_BASE_X ||
	    port_cfg->port_mode == CPI_OPCODE_PORT_MODE_2500_BASE_X)
		cpi.cmd.data |= CPI_OPCODE_PMD_DIS_DSP_ADAPTATION;

	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi set pmd mode failed\n");
		return pstatus;
	}

	return pstatus;
}

/**
 * ice_ieps_cpi_cfg_port_curate_an73 - Set port phy capability CURATE
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 * @port_cfg: pointer to the ice_ieps_cpi_port_cfg
 *
 * Configure curate and AN control
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_cfg_port_curate_an73(struct ice_hw *hw, u8 pcs_port,
				  struct ice_ieps_cpi_port_cfg *port_cfg)
{
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;

	if (!port_cfg) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: port_cfg is NULL\n");
		return IEPS_PEER_INVALID_ARG;
	}

	/**
	 * For AN phy_type configure the CURATE to use desired speed
	 * CPI_OPCODE_CURATE0 / CPI_OPCODE_CURATE1
	 */
	cpi.cmd.opcode = port_cfg->cu_rate_opc;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = port_cfg->cu_rate;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi set cu_rate failed\n");
		return pstatus;
	}

	cpi.cmd.opcode = CPI_OPCODE_AN_CONTROL;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	cpi.cmd.data = CPI_OPCODE_AN_CONTROL_CFG;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi set AN control failed\n");
		return pstatus;
	}

	return pstatus;
}

/**
 * ice_ieps_cpi_cfg_port_cufec - set FEC capabilities CuFEC
 * @hw: pointer to the hardware structure
 * @pcs_port: port
 * @port_cfg: pointer to the ice_ieps_cpi_port_cfg
 *
 * Configure FEC capabilities CuFEC
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_cfg_port_cufec(struct ice_hw *hw, u8 pcs_port,
			    struct ice_ieps_cpi_port_cfg *port_cfg)
{
	struct ice_port_info *pi = hw->port_info;
	struct ieps_peer_cpi_cmd_resp cpi = {};
	enum ieps_peer_status pstatus;
	u8 i = 0, phy_fec_cap;

	if (!port_cfg) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: port_cfg is NULL\n");
		return IEPS_PEER_INVALID_ARG;
	}

	if (!pi) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: port_info is NULL\n");
		return IEPS_PEER_INVALID_ARG;
	}

	/* Configure default FEC setting if only one FEC option is supported
	 * on the phy type. If the PHY type supports multiple FEC options,
	 * the FEC configuration will be set based on the user's input.
	 */
	if (port_cfg->cu_fec)
		phy_fec_cap = port_cfg->cu_fec;
	else
		phy_fec_cap = pi->phy.curr_user_phy_cfg.link_fec_opt;

	for (i = 0; i < CPI_MAX_FEC_OPTIONS; i++) {
		if ((phy_fec_cap >> i) & 1) {
			switch (BIT(i)) {
			case ICE_AQC_PHY_FEC_10G_KR_40G_KR4_EN:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_10GCL74CAP;
				break;
			case ICE_AQC_PHY_FEC_10G_KR_40G_KR4_REQ:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_10GCL74REQ;
				break;
			case ICE_AQC_PHY_FEC_25G_RS_528_REQ:
				cpi.cmd.data |= (port_cfg->port_mode ==
						 CPI_OPCODE_PORT_MODE_25G_AUI) ?
						 CPI_OPCODE_CUFEC0_CL108REQ :
						 CPI_OPCODE_CUFEC0_CL91REQ;
				break;
			case ICE_AQC_PHY_FEC_25G_KR_REQ:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_25GCL74REQ;
				break;
			case ICE_AQC_PHY_FEC_25G_RS_544_REQ:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_CL91REQ;
				break;
			case ICE_AQC_PHY_FEC_DIS:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_DISABLE;
				break;
			case ICE_AQC_PHY_FEC_25G_RS_CLAUSE91_EN:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_CL91CL108CAP;
				break;
			case ICE_AQC_PHY_FEC_25G_KR_CLAUSE74_EN:
				cpi.cmd.data |= CPI_OPCODE_CUFEC0_25GCL74CAP;
				break;
			}
		}
	}

	cpi.cmd.opcode = CPI_OPCODE_CUFEC0;
	cpi.cmd.port = pcs_port;
	cpi.cmd.set = true;
	pstatus = ice_ieps_exec_cpi(hw, &cpi);
	if (pstatus)
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi set FEC option failed\n");

	/* Store active FEC Clause on successful FEC configuration */
	if (phy_fec_cap)
		pi->phy.curr_user_phy_cfg.link_fec_opt = phy_fec_cap;
	else
		pi->phy.curr_user_phy_cfg.link_fec_opt = ICE_AQC_PHY_FEC_DIS;

	return pstatus;
}

/**
 * ice_ieps_cpi_setup_link - Configure link
 * @hw: pointer to the hardware structure
 * @ena_link: if true: enable link, if false: disable link
 *
 * Sets up phy type, FEC Clause and AN 37.
 *
 * Returns: IEPS_PEER_SUCCESS on success, IEPS_PEER_STATUS error otherwise
 */
static enum ieps_peer_status
ice_ieps_cpi_setup_link(struct ice_hw *hw, bool ena_link)
{
	struct ice_ieps_cpi_port_cfg port_cfg = {};
	struct ice_port_info *pi = hw->port_info;
	u64 phy_type_low, phy_type_high;
	enum ieps_peer_status pstatus;
	u8 pcs_port = hw->bus.func;

	if (!ena_link) {
		pstatus = ice_ieps_cpi_disable_port(hw, pcs_port);
		if (pstatus) {
			dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi port disable failed\n");
			return pstatus;
		}

		return IEPS_PEER_SUCCESS;
	}

	pstatus = ice_ieps_cpi_reset_port(hw, pcs_port);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi reset port failed\n");
		return pstatus;
	}

	phy_type_low = le64_to_cpu(pi->phy.curr_user_phy_cfg.phy_type_low);
	phy_type_high = le64_to_cpu(pi->phy.curr_user_phy_cfg.phy_type_high);

	pstatus = ice_ieps_cpi_get_port_cfg(hw, phy_type_low, phy_type_high,
					    &port_cfg);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi get port cfg failed\n");
		return pstatus;
	}

	pstatus = ice_ieps_cpi_cfg_port_pmd_mode(hw, pcs_port, &port_cfg);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi port_pmd mode set failed\n");
		return pstatus;
	}

	/* Configure AN73 control and CURATE */
	if (port_cfg.pmd_mode == CPI_OPCODE_PMD_CONTROL_TRAINING ||
	    port_cfg.port_mode == CPI_OPCODE_PORT_MODE_SGMII) {
		pstatus = ice_ieps_cpi_cfg_port_curate_an73(hw, pcs_port,
							    &port_cfg);
		if (pstatus) {
			dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi port curate an73 set failed\n");
			return pstatus;
		}
	}

	/* configure fec option */
	pstatus = ice_ieps_cpi_cfg_port_cufec(hw, pcs_port, &port_cfg);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi port FEC option set failed\n");
		return pstatus;
	}

	/* Apply configuration */
	pstatus = ice_ieps_cpi_set_port_cfg(hw, pcs_port, 0,
					    CPI_OPCODE_COMMAND_START_RESTART_CFG);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "ERROR: cpi port set cfg failed\n");
		return pstatus;
	}

	return pstatus;
}

/**
 * ice_ieps_cpi_set_link_restart_an - Restart AN and configure port
 * @pi: pointer to the port information structure
 * @ena_link: if true: enable link, if false: disable link
 * @cd: pointer to command details structure or NULL
 * @refclk: the new TX reference clock, 0 if no change
 *
 * Sets up the link and restarts the Auto-Negotiation over the link.
 *
 * Return 0 on success, negative value otherwise
 */
static int
ice_ieps_cpi_set_link_restart_an(struct ice_port_info *pi, bool ena_link,
				 struct ice_sq_cd *cd, u8 refclk)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ice_hw *hw = pi->hw;

	pstatus = ice_ieps_cpi_setup_link(hw, ena_link);
	if (pstatus) {
		dev_dbg(ice_hw_to_dev(hw), "Failed to setup link\n");
		return -EFAULT;
	}

	if (ena_link)
		pi->phy.curr_user_phy_cfg.caps |= ICE_AQC_PHY_EN_LINK;
	else
		pi->phy.curr_user_phy_cfg.caps &= ~ICE_AQC_PHY_EN_LINK;

	return 0;
}

static struct ice_lm_ops ice_ieps_cpi_lm_ops = {
	.get_phy_caps = ice_ieps_cpi_get_phy_caps,
	.set_phy_cfg = ice_ieps_cpi_set_phy_cfg,
	.restart_an = ice_ieps_cpi_set_link_restart_an,
	.get_link_info = ice_ieps_cpi_get_link_info,
};

/**
 * ice_ieps_init_lm_ops
 * @hw: pointer to the hardware structure
 * @en_fw_ops: enable FW based lm ops else enable cpi based ops
 *
 * Initialize lm_ops with AQ if en_fw_ops is set else initialize
 * it with CPI-based LM operations.
 */
void ice_ieps_init_lm_ops(struct ice_hw *hw, bool en_fw_ops)
{
	if (en_fw_ops)
		ice_init_lm_ops(hw);
	else
		hw->lm_ops = &ice_ieps_cpi_lm_ops;
}
