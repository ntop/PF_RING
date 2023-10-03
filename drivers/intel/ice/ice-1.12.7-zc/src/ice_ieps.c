/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

/* Intel(R) Ethernet Connection E800 Series Linux Driver IEPS extensions */

#include "ice_ieps.h"
#include "ice.h"
#include "ice_lib.h"

static struct ieps_peer_api_version ice_ieps_version = {
	.major    = IEPS_VERSION_PEER_MAJOR,
	.minor    = IEPS_VERSION_PEER_MINOR,
};

/**
 * ice_ieps_i2c_fill - Fill I2C read_write AQ command descriptor
 * @pf: ptr to pf
 * @rw: ptr I2C read/write data structure
 * @desc: ptr to AQ descriptor to fill
 */
static void
ice_ieps_i2c_fill(struct ice_pf *pf, struct ieps_peer_i2c *rw,
		  struct ice_aq_desc *desc)
{
	struct ice_aqc_i2c *cmd = &desc->params.read_write_i2c;
	struct ice_aqc_link_topo_params *tparams;
	struct ice_hw *hw = &pf->hw;
	u8 params;

	params = (rw->data_len << ICE_AQC_I2C_DATA_SIZE_S);
	if (unlikely(rw->en_10b_addr))
		params |= ICE_AQC_I2C_ADDR_TYPE_10BIT;
	else
		params |= ICE_AQC_I2C_ADDR_TYPE_7BIT;

	cmd->i2c_params = params;
	cmd->i2c_bus_addr = cpu_to_le16(rw->dev_addr);
	cmd->i2c_addr = cpu_to_le16(rw->reg_addr);

	tparams = &cmd->topo_addr.topo_params;
	tparams->index = rw->bus;
	tparams->lport_num = hw->port_info->lport;
	tparams->lport_num_valid = ICE_AQC_LINK_TOPO_PORT_NUM_VALID;
	tparams->node_type_ctx |= (ICE_AQC_LINK_TOPO_NODE_CTX_OVERRIDE <<
				   ICE_AQC_LINK_TOPO_NODE_CTX_S);
}

/**
 * ice_ieps_i2c_write - Request FW to perform CPK IO widget I2C write
 * @pf: ptr to pf
 * @rw: ptr to I2C read/write data structure
 */
static enum ieps_peer_status
ice_ieps_i2c_write(struct ice_pf *pf, struct ieps_peer_i2c *rw)
{
	struct ice_hw *hw = &pf->hw;
	struct ice_aq_desc desc;
	u8 i, remaining, wrlen;

	if (rw->data_len == 0) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: i2c_wrlen=0\n");
		return IEPS_PEER_INVALID_ARG;
	}

	dev_dbg(ice_pf_to_dev(pf),
		"i2c_wr bus=%d dev=0x%x reg=0x%x len=%d data[0]=0x%x\n",
		rw->bus, rw->dev_addr, rw->reg_addr, rw->data_len, rw->data[0]);

#define ICE_IEPS_I2C_WR_SZ 4
	for (i = 0; i < rw->data_len; i += ICE_IEPS_I2C_WR_SZ) {
		struct ice_aqc_i2c *i2c;
		int status;

		remaining = rw->data_len - i;
		if (remaining > ICE_IEPS_I2C_WR_SZ)
			wrlen = ICE_IEPS_I2C_WR_SZ;
		else
			wrlen = remaining;

		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_write_i2c);
		ice_ieps_i2c_fill(pf, rw, &desc);
		i2c = &desc.params.read_write_i2c;

		/* Copy write values */
		memcpy(i2c->i2c_data, &rw->data[i], wrlen);
		i2c->i2c_params &= ~ICE_AQC_I2C_DATA_SIZE_M;
		i2c->i2c_params |= (wrlen << ICE_AQC_I2C_DATA_SIZE_S);

		i2c->i2c_addr = cpu_to_le16(rw->reg_addr + i);
		status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
		if (status) {
			dev_dbg(ice_pf_to_dev(pf), "ERROR: i2c_wr status=%d\n",
				status);
			return IEPS_PEER_FW_ERROR;
		}
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_i2c_read - Request FW to perform CPK IO widget I2C read
 * @pf: ptr to pf
 * @rw: ptr to I2C read/write data structure
 */
static enum ieps_peer_status
ice_ieps_i2c_read(struct ice_pf *pf, struct ieps_peer_i2c *rw)
{
	struct ice_hw *hw = &pf->hw;
	struct ice_aq_desc desc;
	u8 i, remaining, rdlen;

	if (rw->data_len == 0) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: i2c_rdlen=0\n");
		return IEPS_PEER_INVALID_ARG;
	}
#define ICE_IEPS_I2C_RD_SZ 15
	for (i = 0; i < rw->data_len; i += ICE_IEPS_I2C_RD_SZ) {
		struct ice_aqc_i2c *i2c;
		int status;

		remaining = rw->data_len - i;
		if (remaining > ICE_IEPS_I2C_RD_SZ)
			rdlen = ICE_IEPS_I2C_RD_SZ;
		else
			rdlen = remaining;

		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_read_i2c);
		ice_ieps_i2c_fill(pf, rw, &desc);
		i2c = &desc.params.read_write_i2c;

		i2c->i2c_params &= ~ICE_AQC_I2C_DATA_SIZE_M;
		i2c->i2c_params |= (rdlen << ICE_AQC_I2C_DATA_SIZE_S);

		i2c->i2c_addr = cpu_to_le16(rw->reg_addr + i);
		status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
		if (status) {
			dev_dbg(ice_pf_to_dev(pf), "ERROR: i2c_rd status=%d\n",
				status);
			return IEPS_PEER_FW_ERROR;
		}

		/* Copy back read values */
		memcpy(&rw->data[i], desc.params.read_i2c_resp.i2c_data, rdlen);
	}

	dev_dbg(ice_pf_to_dev(pf),
		"i2c_rd bus=%d dev=0x%x reg=0x%x len=%d data[0]=0x%x\n",
		rw->bus, rw->dev_addr, rw->reg_addr, rw->data_len, rw->data[0]);

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_mdio_fill_desc - Fill MDIO read_write AQ command descriptor
 * @pf: ptr to pf
 * @rw: ptr to MDIO read/write data structure
 * @desc: ptr to AQ descriptor to fill MDIO data
 */
static enum ieps_peer_status
ice_ieps_mdio_fill_desc(struct ice_pf *pf, struct ieps_peer_mdio *rw,
			struct ice_aq_desc *desc)
{
	struct ice_aqc_mdio *mdio_cmd = &desc->params.read_mdio;
	struct ice_aqc_link_topo_params *tparams;
	struct ice_hw *hw = &pf->hw;

	tparams = &mdio_cmd->topo_addr.topo_params;
	tparams->index = rw->bus;
	tparams->lport_num = hw->port_info->lport;
	tparams->lport_num_valid = ICE_AQC_LINK_TOPO_PORT_NUM_VALID;
	tparams->node_type_ctx |= (ICE_AQC_LINK_TOPO_NODE_CTX_OVERRIDE <<
				   ICE_AQC_LINK_TOPO_NODE_CTX_S);

	if (rw->bus & ~(ICE_AQC_MDIO_BUS_ADDR_M >> ICE_AQC_MDIO_BUS_ADDR_S)) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: mdio_bus=%d max=%d\n",
			rw->bus,
			(ICE_AQC_MDIO_BUS_ADDR_M >> ICE_AQC_MDIO_BUS_ADDR_S));
		return IEPS_PEER_INVALID_ARG;
	}

	if (rw->dev_type & ~(ICE_AQC_MDIO_DEV_M >> ICE_AQC_MDIO_DEV_S)) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: mdiodev=%d max=%d\n",
			rw->dev_type,
			(ICE_AQC_MDIO_DEV_M >> ICE_AQC_MDIO_DEV_S));
		return IEPS_PEER_INVALID_ARG;
	}

	mdio_cmd->mdio_bus_address = rw->phy_addr << ICE_AQC_MDIO_BUS_ADDR_S;
	switch (rw->clause) {
	case IEPS_PEER_MDIO_CLAUSE_22:
		mdio_cmd->mdio_device_addr = ICE_AQC_MDIO_CLAUSE_22;
		break;

	case IEPS_PEER_MDIO_CLAUSE_45:
		mdio_cmd->mdio_device_addr = rw->dev_type << ICE_AQC_MDIO_DEV_S;
		mdio_cmd->mdio_device_addr |= ICE_AQC_MDIO_CLAUSE_45;
		break;

	default:
		dev_dbg(ice_pf_to_dev(pf), "ERROR: mdio_cl=%d\n", rw->clause);
		return IEPS_PEER_INVALID_ARG;
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_mdio_read - Request FW to perform MDIO read
 * @pf: ptr to pf
 * @rw: ptr to MDIO read/write data structure
 */
static enum ieps_peer_status
ice_ieps_mdio_read(struct ice_pf *pf, struct ieps_peer_mdio *rw)
{
	enum ieps_peer_status pstatus;
	struct ice_hw *hw = &pf->hw;
	struct ice_aq_desc desc;
	int i;

	for (i = 0; i < rw->data_len; i++) {
		int status;

		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_read_mdio);
		pstatus = ice_ieps_mdio_fill_desc(pf, rw, &desc);
		if (pstatus)
			return pstatus;

		desc.params.read_mdio.offset = cpu_to_le16(rw->reg_addr + i);
		status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
		if (status) {
			dev_dbg(ice_pf_to_dev(pf), "ERROR: mdio_rd status=%d\n",
				status);
			return IEPS_PEER_FW_ERROR;
		}
		rw->data[i] = le16_to_cpu(desc.params.read_mdio.data);
	}

	dev_dbg(ice_pf_to_dev(pf),
		"mdio_rd bus=%d phy=0x%x dev=0x%x reg=0x%x len=%d data=0x%x\n",
		rw->bus, rw->phy_addr, rw->dev_type, rw->reg_addr, rw->data_len,
		rw->data[0]);

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_mdio_write - Request FW to perform MDIO write
 * @pf: ptr to pf
 * @rw: ptr to MDIO read/write data structure
 */
static enum ieps_peer_status
ice_ieps_mdio_write(struct ice_pf *pf, struct ieps_peer_mdio *rw)
{
	int i;

	dev_dbg(ice_pf_to_dev(pf),
		"mdio_rd bus=%d phy=0x%x dev=0x%x reg=0x%x len=%d data=0x%x\n",
		rw->bus, rw->phy_addr, rw->dev_type, rw->reg_addr, rw->data_len,
		rw->data[0]);

	for (i = 0; i < rw->data_len; i++) {
		enum ieps_peer_status pstatus;
		struct ice_hw *hw = &pf->hw;
		struct ice_aq_desc desc;
		int status;

		ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_write_mdio);
		pstatus = ice_ieps_mdio_fill_desc(pf, rw, &desc);
		if (pstatus)
			return pstatus;

		desc.params.read_mdio.offset = cpu_to_le16(rw->reg_addr + i);
		desc.params.read_mdio.data = cpu_to_le16(rw->data[i]);
		status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
		if (status) {
			dev_err(ice_pf_to_dev(pf), "ERROR: mdio_wr status=%d\n",
				status);
			return IEPS_PEER_FW_ERROR;
		}
	}

	return IEPS_PEER_SUCCESS;
}

#define ICE_IEPS_ETH_GPIO_MAX_PIN_COUNT 20

/**
 * ice_ieps_gpio_fill_desc - Fill GPIO set_get AQ command descriptor
 * @pf: ptr to pf
 * @io: ptr to gpio set/get data structure
 * @desc: ptr to AQ descriptor to fill
 */
static enum ieps_peer_status
ice_ieps_gpio_fill_desc(struct ice_pf *pf, struct ieps_peer_gpio *io,
			struct ice_aq_desc *desc)
{
	struct ice_aqc_sw_gpio *sw_gpio_cmd = &desc->params.sw_read_write_gpio;

	if (io->pin_num >= ICE_IEPS_ETH_GPIO_MAX_PIN_COUNT) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: pin=%d max=%d\n",
			io->pin_num, ICE_IEPS_ETH_GPIO_MAX_PIN_COUNT);
		return IEPS_PEER_INVALID_ARG;
	}

	sw_gpio_cmd->gpio_num = io->pin_num;
	if (io->pin_val)
		sw_gpio_cmd->gpio_params |= ICE_AQC_SW_GPIO_PARAMS_VALUE;

	if (io->is_input)
		sw_gpio_cmd->gpio_params |= ICE_AQC_SW_GPIO_PARAMS_DIRECTION;

	sw_gpio_cmd->gpio_ctrl_handle = 0; /* SOC/on-chip GPIO */

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_sw_gpio_set - Request FW to perform GPIO set operations
 * @pf: ptr to pf
 * @io: ptr to gpio set/get data structure
 */
static enum ieps_peer_status
ice_ieps_sw_gpio_set(struct ice_pf *pf, struct ieps_peer_gpio *io)
{
	enum ieps_peer_status pstatus;
	struct ice_hw *hw = &pf->hw;
	struct ice_aq_desc desc;
	int status;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_sw_set_gpio);
	pstatus = ice_ieps_gpio_fill_desc(pf, io, &desc);
	if (pstatus)
		return pstatus;

	dev_dbg(ice_pf_to_dev(pf), "gpio_set pin=%d dir=%s val=%d\n",
		io->pin_num, io->is_input ? "IN" : "OUT", io->pin_val ? 1 : 0);

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "ERROR: sw_gpio_set status=%d\n",
			status);
		return IEPS_PEER_FW_ERROR;
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_sw_gpio_get - Request FW to perform GPIO get operations
 * @pf: ptr to pf
 * @io: ptr to gpio set/get data structure
 */
static enum ieps_peer_status
ice_ieps_sw_gpio_get(struct ice_pf *pf, struct ieps_peer_gpio *io)
{
	enum ieps_peer_status pstatus;
	struct ice_hw *hw = &pf->hw;
	struct ice_aq_desc desc;
	int status;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_sw_get_gpio);
	pstatus = ice_ieps_gpio_fill_desc(pf, io, &desc);
	if (pstatus)
		return pstatus;

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "ERROR: sw_gpio_get status=%d\n",
			status);
		return IEPS_PEER_FW_ERROR;
	}

	io->is_input = desc.params.sw_read_write_gpio.gpio_params &
				ICE_AQC_SW_GPIO_PARAMS_DIRECTION;
	io->pin_val = desc.params.sw_read_write_gpio.gpio_params &
				ICE_AQC_SW_GPIO_PARAMS_VALUE;

	dev_dbg(ice_pf_to_dev(pf), "gpio_get pin=%d dir=%s val=%d\n",
		io->pin_num, io->is_input ? "IN" : "OUT", io->pin_val ? 1 : 0);

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_ver_check - Perform IEPS versicn check
 * @pf: ptr to pf
 * @lib_ver: ptr to IEPS api lib version to check against
 */
static enum ieps_peer_status
ice_ieps_ver_check(struct ice_pf *pf, struct ieps_peer_api_version *lib_ver)
{
	struct ieps_peer_api_version *my_ver = &ice_ieps_version;

	if (lib_ver->major != my_ver->major || lib_ver->minor < my_ver->minor) {
		dev_err(ice_pf_to_dev(pf), "ERROR: version check\t"
			"exp: mj=%d, mn=%d. given: mj=%d, mn=%d\n",
			my_ver->major, my_ver->minor,
			lib_ver->major, lib_ver->minor);

		return IEPS_PEER_VER_INCOMPATIBLE;
	}

	return IEPS_PEER_SUCCESS;
}

#define ICE_MASK_PHY_AN_CAPS 0xF

/**
 * ice_ieps_get_phy_caps - Request FW for PHY capabilities
 * @pf: ptr to pf
 * @report_mode: capability to retrieve like NVM vs ACTIVE
 * @pcaps: ptr to phy caps structre to store result
 */
static enum ieps_peer_status
ice_ieps_get_phy_caps(struct ice_pf *pf, u8 report_mode,
		      struct ieps_peer_phy_caps *pcaps)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ice_aqc_get_phy_caps_data *aq_pcaps;
	struct ice_hw *hw = &pf->hw;
	int status;

	aq_pcaps = kzalloc(sizeof(*aq_pcaps), GFP_KERNEL);
	if (!aq_pcaps)
		return IEPS_PEER_NO_MEMORY;

	dev_dbg(ice_pf_to_dev(pf), "get phy_caps lport=%d\n",
		hw->port_info->lport);
	status = ice_aq_get_phy_caps(hw->port_info, false, report_mode,
				     aq_pcaps, NULL);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: get_phy_caps ret=%d\n",
			status);
		pstatus = IEPS_PEER_FW_ERROR;
		goto err_exit;
	}

	pcaps->phy_type_low = le64_to_cpu(aq_pcaps->phy_type_low);
	pcaps->phy_type_high = le64_to_cpu(aq_pcaps->phy_type_high);

	pcaps->en_tx_pause = !!(aq_pcaps->caps & ICE_AQC_PHY_EN_TX_LINK_PAUSE);
	pcaps->en_rx_pause = !!(aq_pcaps->caps & ICE_AQC_PHY_EN_RX_LINK_PAUSE);
	pcaps->low_power_mode = !!(aq_pcaps->caps & ICE_AQC_PHY_LOW_POWER_MODE);
	pcaps->en_link        = !!(aq_pcaps->caps & ICE_AQC_PHY_EN_LINK);
	pcaps->an_mode        = !!(aq_pcaps->caps & ICE_AQC_PHY_AN_MODE);
	pcaps->en_lesm        = !!(aq_pcaps->caps & ICE_AQC_PHY_EN_LESM);
	pcaps->en_auto_fec    = !!(aq_pcaps->caps & ICE_AQC_PHY_EN_AUTO_FEC);

	pcaps->an_options_bm  = aq_pcaps->low_power_ctrl_an &
					ICE_MASK_PHY_AN_CAPS;
	pcaps->fec_options_bm = aq_pcaps->link_fec_options &
					ICE_AQC_PHY_FEC_MASK;

	if (report_mode == ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA)
		memcpy(pcaps->phy_fw_ver, aq_pcaps->phy_fw_ver,
		       sizeof(pcaps->phy_fw_ver));

err_exit:
	kfree(aq_pcaps);

	return pstatus;
}

/**
 * ice_ieps_get_phy_status - Request FW to perform retrieve link status
 * @pf: ptr to pf
 * @st: ptr to link status data structure to store the results
 */
static enum ieps_peer_status
ice_ieps_get_phy_status(struct ice_pf *pf, struct ieps_peer_phy_link_status *st)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ice_link_status *link;
	struct ice_hw *hw = &pf->hw;
	int status;

	link = kzalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		return IEPS_PEER_NO_MEMORY;

	status = ice_aq_get_link_info(hw->port_info, true, link, NULL);
	if (status) {
		pstatus = IEPS_PEER_FW_ERROR;
		goto err_exit;
	}

	st->link_up           = !!(link->link_info & ICE_AQ_LINK_UP);
	st->link_fault_rx     = !!(link->link_info & ICE_AQ_LINK_FAULT_RX);
	st->link_fault_tx     = !!(link->link_info & ICE_AQ_LINK_FAULT_TX);
	st->link_fault_remote = !!(link->link_info & ICE_AQ_LINK_FAULT_REMOTE);
	st->link_up_ext_port  = !!(link->link_info & ICE_AQ_LINK_UP_PORT);
	st->media_available   = !!(link->link_info & ICE_AQ_MEDIA_AVAILABLE);
	st->an_complete       = !!(link->an_info & ICE_AQ_AN_COMPLETED);
	st->an_capable        = !!(link->an_info & ICE_AQ_LP_AN_ABILITY);
	st->los               = !(link->link_info & ICE_AQ_SIGNAL_DETECT);

	st->phy_type_low      = cpu_to_le64(link->phy_type_low);
	st->phy_type_high     = cpu_to_le64(link->phy_type_high);
	st->lse_on            = link->lse_ena;

err_exit:
	kfree(link);

	return pstatus;
}

/**
 * ice_ieps_set_mode - Request FW to set port mode
 * @pf: ptr to pf
 * @mode: ptr to enumerated port mode
 */
static enum ieps_peer_status
ice_ieps_set_mode(struct ice_pf *pf, enum ieps_peer_port_mode *mode)
{
	struct ice_hw *hw = &pf->hw;
	bool ena_link = false;
	int status;

	if (*mode >= NUM_IEPS_PEER_PORT_MODE)
		return IEPS_PEER_INVALID_PORT_MODE;

	if (*mode == IEPS_PEER_PORT_MODE_UP)
		ena_link = true;

	status = ice_aq_set_link_restart_an(hw->port_info, ena_link, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "ERROR: set_mode status=%d\n",
			status);
		return IEPS_PEER_FW_ERROR;
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_get_mode - Request FW to return port mode
 * @pf: ptr to pf
 * @mode: ptr to store retrieved port mode
 */
static enum ieps_peer_status
ice_ieps_get_mode(struct ice_pf *pf, enum ieps_peer_port_mode *mode)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ieps_peer_phy_caps *pcaps;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return IEPS_PEER_NO_MEMORY;

	pstatus = ice_ieps_get_phy_caps(pf, ICE_AQC_REPORT_ACTIVE_CFG, pcaps);
	if (pstatus)
		goto err_exit;

	if (pcaps->en_link)
		*mode = IEPS_PEER_PORT_MODE_UP;
	else
		*mode = IEPS_PEER_PORT_MODE_DOWN;

err_exit:
	kfree(pcaps);

	return pstatus;
}

/**
 * ice_ieps_phy_type_decode - Decode phy_type bitmap to PHY_TYPE enum
 * @pf: ptr to pf
 * @phy_cfg: ptr to aqc_set_phy_cfg structure
 * @phy_type: ptr to enumerated phy_type
 *
 * With IEPS, there always be single PHY_TYPE active in the PHY.
 * IEPS driver explicitly initializes PHY_TYPE to single value to
 * override possible multi phy-type in default NVM PHY_TYPE config
 */
static enum ieps_peer_status
ice_ieps_phy_type_decode(struct ice_pf *pf,
			 struct ice_aqc_set_phy_cfg_data *phy_cfg,
			 enum ieps_peer_phy_type *phy_type)
{
	bool phy_type_found = false, phy_type_multi = false;
	int i;

	if (phy_cfg->phy_type_low) {
		for (i = 0; i <= ICE_PHY_TYPE_LOW_MAX_INDEX; i++) {
			u64 type_low = le64_to_cpu(phy_cfg->phy_type_low);

			if (type_low & BIT_ULL(i)) {
				*phy_type = i;
				phy_type_found = true;

				if (type_low & ~BIT_ULL(i))
					phy_type_multi = true;

				break;
			}
		}
	}

	if (phy_type_found && phy_cfg->phy_type_high)
		phy_type_multi = true;

	if (!phy_type_multi && phy_cfg->phy_type_high) {
		for (i = 0; i <= ICE_PHY_TYPE_HIGH_MAX_INDEX; i++) {
			u64 type_high = le64_to_cpu(phy_cfg->phy_type_high);

			if (type_high & BIT_ULL(i)) {
				*phy_type = ICE_PHY_TYPE_LOW_MAX_INDEX + 1 + i;
				phy_type_found = true;

				if (type_high & ~BIT_ULL(i))
					phy_type_multi = true;

				break;
			}
		}
	}

	if (!phy_type_found || phy_type_multi) {
		dev_err(ice_pf_to_dev(pf),
			"ERROR: MULTIPLE_PHY_TYPE l=0x%llx h=0x%llx\n",
			phy_cfg->phy_type_low, phy_cfg->phy_type_high);
		return IEPS_PEER_MULTIPLE_PHY_TYPE;
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_phy_type_setget - Helper function to set/get phy-type
 * @pf: ptr to pf
 * @op_set: true for set operation else, get operation
 * @attr_data: ptr to ieps_port_attr obj containing attr and config value
 * @phy_cfg: ptr to aqc_set_phy_cfg structure
 */
static enum ieps_peer_status
ice_ieps_phy_type_setget(struct ice_pf *pf, bool op_set,
			 struct ieps_peer_port_attr_data *attr_data,
			 struct ice_aqc_set_phy_cfg_data *phy_cfg)
{
	struct ieps_peer_phy_caps *pcaps;
	enum ieps_peer_status pstatus;

	if (!op_set)
		return ice_ieps_phy_type_decode(pf, phy_cfg,
						&attr_data->cfg.phy_type);

	if (attr_data->cfg.phy_type >= NUM_IEPS_PEER_PHY_TYPE ||
	    attr_data->cfg.phy_type < 0)
		return IEPS_PEER_PORT_INV_PHY_TYPE;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return IEPS_PEER_NO_MEMORY;

	pstatus = ice_ieps_get_phy_caps(pf, ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA,
					pcaps);
	if (pstatus)
		goto rel_mem_exit;

	if (attr_data->cfg.phy_type >= 64) {
		u64 type_high = 1ULL << (attr_data->cfg.phy_type - 64);

		if (!(type_high & pcaps->phy_type_high))
			pstatus = IEPS_PEER_PHY_TYPE_NOTSUP;

		phy_cfg->phy_type_high = cpu_to_le64(type_high);
	} else {
		u64 type_low = 1ULL << attr_data->cfg.phy_type;

		if (!(type_low & pcaps->phy_type_low))
			pstatus = IEPS_PEER_PHY_TYPE_NOTSUP;

		phy_cfg->phy_type_low = cpu_to_le64(type_low);
	}

rel_mem_exit:
	kfree(pcaps);
	return pstatus;
}

/**
 * ice_ieps_an_setget - Helper function to set/get Autonegotiation options
 * @pf: ptr to pf
 * @op_set: true for set operation else, get operation
 * @attr_data: ptr to ieps_port_attr obj containing attr and config value
 * @phy_cfg: ptr to aqc_set_phy_cfg structure
 */
static enum ieps_peer_status
ice_ieps_an_setget(struct ice_pf *pf, bool op_set,
		   struct ieps_peer_port_attr_data *attr_data,
		   struct ice_aqc_set_phy_cfg_data *phy_cfg)
{
	if (op_set) {
		if (attr_data->cfg.an_cl37_enable)
			phy_cfg->low_power_ctrl_an = ICE_AQC_PHY_AN_EN_CLAUSE37;
		else
			phy_cfg->low_power_ctrl_an = 0;
	} else {
		attr_data->cfg.an_cl37_enable = !!(phy_cfg->low_power_ctrl_an &
						   ICE_AQC_PHY_AN_EN_CLAUSE37);
	}

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_fec_type_setget - Helper function to set/get FEC options
 * @pf: ptr to pf
 * @op_set: true for set operation else, get operation
 * @attr_data: ptr to ieps_port_attr obj containing attr and config value
 * @phy_cfg: ptr to aqc_set_phy_cfg structure
 */
static enum ieps_peer_status
ice_ieps_fec_type_setget(struct ice_pf *pf, bool op_set,
			 struct ieps_peer_port_attr_data *attr_data,
			 struct ice_aqc_set_phy_cfg_data *phy_cfg)
{
	struct ieps_peer_phy_caps *pcaps;
	enum ieps_peer_status pstatus;

	if (!op_set) {
		attr_data->cfg.fec_options_bm = phy_cfg->link_fec_opt &
						ICE_AQC_PHY_FEC_MASK;
		return IEPS_PEER_SUCCESS;
	}

	if (attr_data->cfg.fec_options_bm & ~ICE_AQC_PHY_FEC_MASK)
		return IEPS_PEER_INVALID_FEC_OPT;

	phy_cfg->link_fec_opt = attr_data->cfg.fec_options_bm &
					ICE_AQC_PHY_FEC_MASK;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return IEPS_PEER_NO_MEMORY;

	pstatus = ice_ieps_get_phy_caps(pf, ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA,
					pcaps);
	if (pstatus)
		goto rel_mem_exit;

	if ((phy_cfg->link_fec_opt & pcaps->fec_options_bm) !=
	    phy_cfg->link_fec_opt)
		pstatus = IEPS_PEER_FEC_OPT_NOTSUP;

rel_mem_exit:
	kfree(pcaps);
	return pstatus;
}

/**
 * ice_ieps_set_get_attr_copy_data - Map data between ieps & ice structures
 * @pf: ptr to pf
 * @op_set: true for set operation else, get operation
 * @attr_data: ptr to ieps_port_attr obj containing attr and config value
 * @phy_cfg: ptr to aqc_set_phy_cfg structure
 */
static enum ieps_peer_status
ice_ieps_set_get_attr_copy_data(struct ice_pf *pf, bool op_set,
				struct ieps_peer_port_attr_data *attr_data,
				struct ice_aqc_set_phy_cfg_data *phy_cfg)
{
	switch (attr_data->attr) {
	case IEPS_PEER_PA_PHY_TYPE:
		return ice_ieps_phy_type_setget(pf, op_set, attr_data, phy_cfg);

	case IEPS_PEER_PA_PHY_AN:
		return ice_ieps_an_setget(pf, op_set, attr_data, phy_cfg);

	case IEPS_PEER_PA_PHY_FEC:
		return ice_ieps_fec_type_setget(pf, op_set, attr_data, phy_cfg);

	default:
		return IEPS_PEER_INVALID_PORT_ATTR;
	}
}

/**
 * ice_ieps_set_get_attr - Generic function to request FW to set/get phy config
 * @pf: ptr to pf
 * @op_set: true for set operation else, get operation
 * @attr_data: ptr to ieps_port_attr obj containing attr and config value
 */
static enum ieps_peer_status
ice_ieps_set_get_attr(struct ice_pf *pf, bool op_set,
		      struct ieps_peer_port_attr_data *attr_data)
{
	struct ice_aqc_set_phy_cfg_data *phy_cfg;
	struct ice_aqc_get_phy_caps_data *pcaps;
	enum ieps_peer_status pstatus;
	struct ice_hw *hw = &pf->hw;
	int status;

	phy_cfg = kzalloc(sizeof(*phy_cfg), GFP_KERNEL);
	if (!phy_cfg)
		return IEPS_PEER_NO_MEMORY;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps) {
		kfree(phy_cfg);
		return IEPS_PEER_NO_MEMORY;
	}

	if (op_set)
		dev_dbg(ice_pf_to_dev(pf), "set_attr = %d\n", attr_data->attr);
	else
		dev_dbg(ice_pf_to_dev(pf), "get_attr = %d\n", attr_data->attr);

	status = ice_aq_get_phy_caps(hw->port_info, false,
				     ICE_AQC_REPORT_ACTIVE_CFG, pcaps, NULL);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: set_attr get_phy_caps status=%d\n",
			status);
		pstatus = IEPS_PEER_FW_ERROR;
		goto release_exit;
	}

	phy_cfg->phy_type_low      = pcaps->phy_type_low;
	phy_cfg->phy_type_high     = pcaps->phy_type_high;
	phy_cfg->caps              = pcaps->caps;
	phy_cfg->low_power_ctrl_an = pcaps->low_power_ctrl_an;
	phy_cfg->link_fec_opt      = pcaps->link_fec_options;
	phy_cfg->eee_cap           = pcaps->eee_cap;

	pstatus = ice_ieps_set_get_attr_copy_data(pf, op_set, attr_data,
						  phy_cfg);
	if (pstatus)
		goto release_exit;

	if (!op_set) {
		pstatus = IEPS_PEER_SUCCESS;
		goto release_exit;
	}

	status = ice_aq_set_phy_cfg(hw, hw->port_info, phy_cfg, NULL);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: set_phy_caps status=%d\n",
			status);
		pstatus = IEPS_PEER_FW_ERROR;
	}

release_exit:
	kfree(pcaps);
	kfree(phy_cfg);

	return pstatus;
}

/**
 * ice_ieps_phy_reg_rw - Perform RMN0 reg rd/wr over SBQ
 * @pf: ptr to pf
 * @rw: ptr to PHY reg read/write data structure
 */
static enum ieps_peer_status
ice_ieps_phy_reg_rw(struct ice_pf *pf, struct ieps_peer_intphy_reg_rw *rw)
{
	struct ice_sbq_msg_input sbq_msg = {0};
	struct ice_hw *hw = &pf->hw;
	int status;

#define ICE_IEPS_SBQ_ADDR_HIGH_S 16
#define ICE_IEPS_SBQ_ADDR_HIGH_M 0xFFFFFFFF
#define ICE_IEPS_SBQ_ADDR_LOW_M  0xFFFF

	sbq_msg.dest_dev = rmn_0;
	sbq_msg.msg_addr_low = rw->reg & ICE_IEPS_SBQ_ADDR_LOW_M;
	sbq_msg.msg_addr_high = (rw->reg >> ICE_IEPS_SBQ_ADDR_HIGH_S) &
				ICE_IEPS_SBQ_ADDR_HIGH_M;
	if (rw->is_write) {
		sbq_msg.opcode = ice_sbq_msg_wr;
		sbq_msg.data   = rw->data;
	} else {
		sbq_msg.opcode = ice_sbq_msg_rd;
	}

	status = ice_sbq_rw_reg(hw, &sbq_msg);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR: sbq_rw_reg status=%d\n",
			status);
		return IEPS_PEER_FW_ERROR;
	}

	if (!rw->is_write)
		rw->data = sbq_msg.data;

	return IEPS_PEER_SUCCESS;
}

/**
 * ice_ieps_set_lm_config - request FW to disable LESM
 * @pf: ptr to pf
 * @en_lesm: set true to enable LESM else disable LESM
 */
static enum ieps_peer_status
ice_ieps_set_lm_config(struct ice_pf *pf, bool en_lesm)
{
	enum ieps_peer_status pstatus = IEPS_PEER_SUCCESS;
	struct ice_aqc_set_phy_cfg_data *phy_cfg;
	struct ice_aqc_get_phy_caps_data *pcaps;
	struct ice_hw *hw = &pf->hw;
	int status;

	phy_cfg = kzalloc(sizeof(*phy_cfg), GFP_KERNEL);
	if (!phy_cfg)
		return IEPS_PEER_NO_MEMORY;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps) {
		kfree(phy_cfg);
		return IEPS_PEER_NO_MEMORY;
	}

	status = ice_aq_get_phy_caps(hw->port_info, false,
				     ICE_AQC_REPORT_ACTIVE_CFG, pcaps, NULL);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "ERROR:get_phy_caps status=%d\n",
			status);
		pstatus = IEPS_PEER_FW_ERROR;
		goto release_exit;
	}

	phy_cfg->phy_type_low      = pcaps->phy_type_low;
	phy_cfg->phy_type_high     = pcaps->phy_type_high;
	phy_cfg->low_power_ctrl_an = pcaps->low_power_ctrl_an;
	phy_cfg->link_fec_opt      = pcaps->link_fec_options;
	phy_cfg->eee_cap           = pcaps->eee_cap;
	phy_cfg->caps              = pcaps->caps;

	if (en_lesm)
		phy_cfg->caps |= ICE_AQ_PHY_ENA_LESM;
	else
		phy_cfg->caps &= ~ICE_AQ_PHY_ENA_LESM;

	status = ice_aq_set_phy_cfg(hw, hw->port_info, phy_cfg, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "ERROR: lm port config status=%d\n",
			status);
		pstatus = IEPS_PEER_FW_ERROR;
	}

release_exit:
	kfree(pcaps);
	kfree(phy_cfg);

	return pstatus;
}

/**
 * ice_ieps_entry - Request FW to perform GPIO set operations
 * @obj: ptr to IDC peer device data object
 * @vptr_arg: ptr to peer arg structure containing cmd and cmd specific data
 */
int ice_ieps_entry(struct iidc_core_dev_info *obj, void *vptr_arg)
{
	struct ieps_peer_arg *arg = vptr_arg;
	struct ice_pf *pf;
	void *vptr;

	if (!obj || !obj->pdev)
		return IEPS_PEER_INVALID_PEER_DEV;

	pf = pci_get_drvdata(obj->pdev);
	if (!pf)
		return IEPS_PEER_INVALID_PEER_DEV;

	if (!arg || !arg->data)
		return IEPS_PEER_INVALID_ARG;

	if (arg->cmd >= NUM_IEPS_PEER_CMD)
		return IEPS_PEER_INVALID_CMD;

	vptr = arg->data;
	switch (arg->cmd) {
	case IEPS_PEER_CMD_VERSION_CHECK:
		return ice_ieps_ver_check(pf,
					  (struct ieps_peer_api_version *)vptr);

	case IEPS_PEER_CMD_I2C_READ:
		return ice_ieps_i2c_read(pf, (struct ieps_peer_i2c *)vptr);

	case IEPS_PEER_CMD_I2C_WRITE:
		return ice_ieps_i2c_write(pf, (struct ieps_peer_i2c *)vptr);

	case IEPS_PEER_CMD_MDIO_READ:
		return ice_ieps_mdio_read(pf, (struct ieps_peer_mdio *)vptr);

	case IEPS_PEER_CMD_MDIO_WRITE:
		return ice_ieps_mdio_write(pf, (struct ieps_peer_mdio *)vptr);

	case IEPS_PEER_CMD_GPIO_GET:
		return ice_ieps_sw_gpio_get(pf, (struct ieps_peer_gpio *)vptr);

	case IEPS_PEER_CMD_GPIO_SET:
		return ice_ieps_sw_gpio_set(pf, (struct ieps_peer_gpio *)vptr);

	case IEPS_PEER_CMD_GET_NVM_PHY_CAPS:
		return ice_ieps_get_phy_caps(pf,
					     ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA,
					     (struct ieps_peer_phy_caps *)vptr);

	case IEPS_PEER_CMD_GET_LINK_STATUS:
		return ice_ieps_get_phy_status(pf,
				(struct ieps_peer_phy_link_status *)vptr);

	case IEPS_PEER_CMD_PORT_GET_MODE:
		return ice_ieps_get_mode(pf, (enum ieps_peer_port_mode *)vptr);

	case IEPS_PEER_CMD_PORT_SET_MODE:
		return ice_ieps_set_mode(pf, (enum ieps_peer_port_mode *)vptr);

	case IEPS_PEER_CMD_PORT_SET_ATTR:
		return ice_ieps_set_get_attr(pf, true,
				(struct ieps_peer_port_attr_data *)vptr);

	case IEPS_PEER_CMD_PORT_GET_ATTR:
		return ice_ieps_set_get_attr(pf, false,
				(struct ieps_peer_port_attr_data *)vptr);

	case IEPS_PEER_CMD_INTPHY_REG_RW:
		return ice_ieps_phy_reg_rw(pf,
				(struct ieps_peer_intphy_reg_rw *)vptr);

	case IEPS_PEER_CMD_SET_LM_CONFIG:
		return ice_ieps_set_lm_config(pf, *(bool *)vptr);

	default:
		return IEPS_PEER_INVALID_CMD;
	}

	return IEPS_PEER_SUCCESS;
}
