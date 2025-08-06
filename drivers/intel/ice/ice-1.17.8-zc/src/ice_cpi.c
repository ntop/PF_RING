/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice_type.h"
#include "ice_common.h"
#include "ice_ptp_hw.h"
#include "ice_cpi.h"

/* CPI is per PHY and the LM CMD and Response register
 * are used to control all ports of the same PHY.
 * Lock is required to when multiple PEER driver try to executes
 * CPI command sequence on same PHY
 */
/* PHY 0 Mutex object */
static DEFINE_MUTEX(ice_global_cpi_phy0);
/* PHY 1 Mutex object */
static DEFINE_MUTEX(ice_global_cpi_phy1);

/**
 * ice_cpi_lock_mutex - acquire mutex lock for given phy
 * @hw: pointer to the HW struct
 * @phy: phy index of port
 */
static void ice_cpi_lock_mutex(struct ice_hw *hw, u8 phy)
{
	if (!phy)
		mutex_lock(&ice_global_cpi_phy0);
	else
		mutex_lock(&ice_global_cpi_phy1);
}

/**
 * ice_cpi_unlock_mutex - release mutex lock for given phy
 * @hw: pointer to the HW struct
 * @phy: phy index of port
 */
static void ice_cpi_unlock_mutex(struct ice_hw *hw, u8 phy)
{
	if (!phy)
		mutex_unlock(&ice_global_cpi_phy0);
	else
		mutex_unlock(&ice_global_cpi_phy1);
}

/**
 * ice_cpi_get_dest_dev - get destination PHY for given phy index
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 */
static enum ice_sbq_msg_dev ice_cpi_get_dest_dev(struct ice_hw *hw,
						 u8 phy)
{
	u8 curr_phy;

	if (ice_is_dual(hw)) {
		if (ice_is_primary(hw))
			curr_phy = PHY0;
		else
			curr_phy = PHY1;
	}

	/* In the driver, lanes 4..7 are in fact 0..3 on a second PHY.
	 * On a single complex E825C, PHY 0 is always destination device phy_0
	 * and PHY 1 is phy_0_peer.
	 * On dual complex E825C, device phy_0 points to PHY on a current
	 * complex and phy_0_peer to PHY on a different complex.
	 */
	if ((!ice_is_dual(hw) && phy) ||
	    (ice_is_dual(hw) && phy != curr_phy))
		return phy_0_peer;
	else
		return phy_0;
}

/**
 * ice_cpi_write_phy - Write a PHY port register
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @addr: PHY register address
 * @val: Value to write
 */
static int ice_cpi_write_phy(struct ice_hw *hw, u8 phy, u32 addr, u32 val)
{
	struct ice_sbq_msg_input msg = {
		.dest_dev = ice_cpi_get_dest_dev(hw, phy),
		.opcode = ice_sbq_msg_wr_np,
		.msg_addr_low = lower_16_bits(addr),
		.msg_addr_high = upper_16_bits(addr),
		.data = val
	};
	int err;

	err = ice_sbq_rw_reg(hw, &msg, ICE_AQ_FLAG_RD);
	if (err)
		ice_debug(hw, ICE_DBG_PTP,
			  "Failed to write CPI msg to phy %d, err: %d\n",
			  phy, err);

	return err;
}

/**
 * ice_cpi_read_phy - Read a PHY port register
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @addr: PHY register address
 * @val: Value to write
 */
static int ice_cpi_read_phy(struct ice_hw *hw, u8 phy, u32 addr, u32 *val)
{
	struct ice_sbq_msg_input msg = {
		.dest_dev = ice_cpi_get_dest_dev(hw, phy),
		.opcode = ice_sbq_msg_rd,
		.msg_addr_low = lower_16_bits(addr),
		.msg_addr_high = upper_16_bits(addr)
	};
	int err;

	err = ice_sbq_rw_reg(hw, &msg, ICE_AQ_FLAG_RD);
	if (err) {
		ice_debug(hw, ICE_DBG_PTP,
			  "Failed to read CPI msg from phy %d, err: %d\n",
			  phy, err);
		return err;
	}

	*val = msg.data;

	return 0;
}

/**
 * ice_cpi_wait_req0_ack0 - waits for CPI interface to be available
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 *
 * This function checks if CPI interface is ready to use by CPI client.
 * It's done by assuring LM.CMD.REQ and PHY.CMD.ACK bit in CPI
 * interface registers to be 0.
 *
 * Returns 0 on success.
 */
static int ice_cpi_wait_req0_ack0(struct ice_hw *hw, int phy)
{
	union cpi_reg_phy_cmd_data phy_regs;
	union cpi_reg_lm_cmd_data lm_regs;

	for (int i = 0; i < CPI_RETRIES_COUNT; i++) {
		int err;

		/* check if another CPI Client is also accessing CPI */
		err = ice_cpi_read_phy(hw, phy, CPI0_LM1_CMD_DATA,
				       &lm_regs.val);
		if (err)
			return err;
		if (lm_regs.field.cpi_req)
			return -EBUSY;

		/* check if PHY.ACK is deasserted */
		err = ice_cpi_read_phy(hw, phy, CPI0_PHY1_CMD_DATA,
				       &phy_regs.val);
		if (err)
			return err;
		if (phy_regs.field.error)
			return -EFAULT;
		if (!phy_regs.field.ack)
			/* req0 and ack0 at this point - ready to go */
			return 0;

		msleep(CPI_RETRIES_CADENCE_MS);
	};

	return -ETIMEDOUT;
}

/**
 * ice_cpi_wait_ack - Waits for the PHY.ACK bit to be asserted/deasserted
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @asserted: desired state of PHY.ACK bit
 * @data: pointer to the user data where PHY.data is stored
 *
 * This function checks if PHY.ACK bit is asserted or deasserted, depending
 * on the phase of CPI handshake. If 'asserted' state is required, PHY command
 * data is stored in the 'data' storage.
 *
 * Returns 0 on success.
 */
static int ice_cpi_wait_ack(struct ice_hw *hw, u8 phy, bool asserted,
			    u32 *data)
{
	union cpi_reg_phy_cmd_data phy_regs;

	for (int i = 0; i < CPI_RETRIES_COUNT; i++) {
		int err;

		err = ice_cpi_read_phy(hw, phy, CPI0_PHY1_CMD_DATA,
				       &phy_regs.val);
		if (err)
			return err;
		if (phy_regs.field.error)
			return -EFAULT;
		if (asserted && phy_regs.field.ack) {
			if (data)
				*data = phy_regs.val;
			return 0;
		}
		if (!asserted && !phy_regs.field.ack)
			return 0;

		msleep(CPI_RETRIES_CADENCE_MS);
	};

	return -ETIMEDOUT;
}

#define ice_cpi_wait_ack0(hw, port) \
	ice_cpi_wait_ack(hw, port, false, NULL)

#define ice_cpi_wait_ack1(hw, port, data) \
	ice_cpi_wait_ack(hw, port, true, data)

/**
 * ice_cpi_req0 - deasserts LM.REQ bit
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @data: the command data
 *
 * Returns 0 on success.
 */
static int ice_cpi_req0(struct ice_hw *hw, u8 phy, u32 data)
{
	union cpi_reg_lm_cmd_data *lm_regs;
	int err;

	lm_regs = (union cpi_reg_lm_cmd_data *)&data;
	lm_regs->field.cpi_req = 0;

	err = ice_cpi_write_phy(hw, phy, CPI0_LM1_CMD_DATA, lm_regs->val);
	if (err)
		return err;

	return 0;
}

/**
 * ice_cpi_exec_cmd - writes command data to CPI interface
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @data: the command data
 *
 * Returns 0 on success.
 */
static int ice_cpi_exec_cmd(struct ice_hw *hw, int phy, u32 data)
{
	return ice_cpi_write_phy(hw, phy, CPI0_LM1_CMD_DATA, data);
}

/**
 * ice_cpi_exec - executes CPI command
 * @hw: pointer to the HW struct
 * @phy: phy index of port the CPI action is taken on
 * @cmd: pointer to the command struct to execute
 * @resp: pointer to user allocated CPI response struct
 *
 * This function executes CPI request with respect to CPI handshake
 * mechanism.
 *
 * Returns 0 on success.
 */
int ice_cpi_exec(struct ice_hw *hw, u8 phy,
		 const struct ice_cpi_cmd *cmd,
		 struct ice_cpi_resp *resp)
{
	u8 curr_phy = ICE_GET_QUAD_NUM((u8)hw->lane_num);
	union cpi_reg_phy_cmd_data phy_cmd_data;
	union cpi_reg_lm_cmd_data lm_cmd_data;
	int err, err1 = 0;

	if (!cmd || !resp)
		return -EINVAL;

	memset(&lm_cmd_data, 0, sizeof(lm_cmd_data));

	ice_cpi_lock_mutex(hw, curr_phy);

	lm_cmd_data.field.cpi_req = CPI_LM_CMD_REQ;
	lm_cmd_data.field.get_set = cmd->set;
	lm_cmd_data.field.opcode = cmd->opcode;
	lm_cmd_data.field.portlane = cmd->port;
	lm_cmd_data.field.data = cmd->data;

	/* 1. Try to acquire the bus, PHY ACK should be low before we begin */
	err = ice_cpi_wait_req0_ack0(hw, phy);
	if (err)
		goto rel_mutex_exit;

	/* 2. We start the CPI request */
	err = ice_cpi_exec_cmd(hw, phy, lm_cmd_data.val);
	if (err)
		goto rel_mutex_exit;

	/*
	 * 3. Wait for CPI confirmation, PHY ACK should be asserted and opcode
	 *    echoed in the response
	 */
	err = ice_cpi_wait_ack1(hw, phy, &phy_cmd_data.val);
	if (err)
		goto rel_cpi_exit;

	if (phy_cmd_data.field.ack &&
	    lm_cmd_data.field.opcode != phy_cmd_data.field.opcode) {
		err = -EFAULT;
		goto rel_cpi_exit;
	}

	resp->opcode = phy_cmd_data.field.opcode;
	resp->data = phy_cmd_data.field.data;
	resp->port = phy_cmd_data.field.data;

rel_cpi_exit:
	/* 4. We deassert REQ */
	err1 = ice_cpi_req0(hw, phy, lm_cmd_data.val);
	if (err1)
		goto rel_mutex_exit;

	/* 5. PHY ACK should be deasserted in response */
	err1 = ice_cpi_wait_ack0(hw, phy);

rel_mutex_exit:
	ice_cpi_unlock_mutex(hw, curr_phy);

	if (!err)
		err = err1;

	return err;
}

/**
 * ice_cpi_set_cmd - execute CPI SET command
 * @hw: pointer to the HW struct
 * @opcode: CPI command opcode
 * @phy: phy index CPI command is applied for
 * @port_lane: ephy index CPI command is applied for
 * @data: CPI opcode context specific data
 *
 * Return: 0 on success.
 */
static int ice_cpi_set_cmd(struct ice_hw *hw, u16 opcode, u8 phy, u8 port_lane,
			   u16 data)
{
	struct ice_cpi_resp cpi_resp = {0};
	struct ice_cpi_cmd cpi_cmd = {
		.opcode = opcode,
		.set = true,
		.port = port_lane,
		.data = data,
	};

	return ice_cpi_exec(hw, phy, &cpi_cmd, &cpi_resp);
}

/**
 * ice_cpi_ena_dis_clk_ref - enables/disables Tx reference clock on port
 * @hw: pointer to the HW struct
 * @phy: phy index of port for which Tx reference clock is enabled/disabled
 * @clk: Tx reference clock to enable or disable
 * @enable: bool value to enable or disable Tx reference clock
 *
 * This function executes CPI request to enable or disable specific
 * Tx reference clock on given PHY.
 *
 * Return: 0 on success.
 */
int ice_cpi_ena_dis_clk_ref(struct ice_hw *hw, u8 phy,
			    enum ice_e825c_ref_clk clk, bool enable)
{
	u16 val;

	val = FIELD_PREP(CPI_OPCODE_PHY_CLK_PHY_SEL_M, phy) |
	      FIELD_PREP(CPI_OPCODE_PHY_CLK_REF_CTRL_M,
			 enable ? CPI_OPCODE_PHY_CLK_ENABLE :
			 CPI_OPCODE_PHY_CLK_DISABLE) |
	      FIELD_PREP(CPI_OPCODE_PHY_CLK_REF_SEL_M, clk);

	return ice_cpi_set_cmd(hw, CPI_OPCODE_PHY_CLK, phy, 0, val);
}

