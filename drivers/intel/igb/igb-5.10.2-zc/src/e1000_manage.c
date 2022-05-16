// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2007 - 2022 Intel Corporation. */

#include "e1000_api.h"
#include "e1000_manage.h"

/**
 *  e1000_calculate_checksum - Calculate checksum for buffer
 *  @buffer: pointer to EEPROM
 *  @length: size of EEPROM to calculate a checksum for
 *
 *  Calculates the checksum for some buffer on a specified length.  The
 *  checksum calculated is returned.
 **/
u8 e1000_calculate_checksum(u8 *buffer, u32 length)
{
	u32 i;
	u8 sum = 0;

	DEBUGFUNC("e1000_calculate_checksum");

	if (!buffer)
		return 0;

	for (i = 0; i < length; i++)
		sum += buffer[i];

	return (u8) (0 - sum);
}

/**
 *  e1000_enable_mng_pass_thru - Check if management passthrough is needed
 *  @hw: pointer to the HW structure
 *
 *  Verifies the hardware needs to leave interface enabled so that frames can
 *  be directed to and from the management interface.
 **/
bool e1000_enable_mng_pass_thru(struct e1000_hw *hw)
{
	u32 manc;
	u32 fwsm, factps;

	DEBUGFUNC("e1000_enable_mng_pass_thru");

	if (!hw->mac.asf_firmware_present)
		return false;

	manc = E1000_READ_REG(hw, E1000_MANC);

	if (!(manc & E1000_MANC_RCV_TCO_EN))
		return false;

	if (hw->mac.has_fwsm) {
		fwsm = E1000_READ_REG(hw, E1000_FWSM);
		factps = E1000_READ_REG(hw, E1000_FACTPS);

		if (!(factps & E1000_FACTPS_MNGCG) &&
		    ((fwsm & E1000_FWSM_MODE_MASK) ==
		     (e1000_mng_mode_pt << E1000_FWSM_MODE_SHIFT)))
			return true;
	} else if ((manc & E1000_MANC_SMBUS_EN) &&
		   !(manc & E1000_MANC_ASF_EN)) {
		return true;
	}

	return false;
}

/**
 *  e1000_host_interface_command - Writes buffer to host interface
 *  @hw: pointer to the HW structure
 *  @buffer: contains a command to write
 *  @length: the byte length of the buffer, must be multiple of 4 bytes
 *
 *  Writes a buffer to the Host Interface.  Upon success, returns E1000_SUCCESS
 *  else returns E1000_ERR_HOST_INTERFACE_COMMAND.
 **/
s32 e1000_host_interface_command(struct e1000_hw *hw, u8 *buffer, u32 length)
{
	u32 hicr, i;

	DEBUGFUNC("e1000_host_interface_command");

	if (!(hw->mac.arc_subsystem_valid)) {
		DEBUGOUT("Hardware doesn't support host interface command.\n");
		return E1000_SUCCESS;
	}

	if (!hw->mac.asf_firmware_present) {
		DEBUGOUT("Firmware is not present.\n");
		return E1000_SUCCESS;
	}

	if (length == 0 || length & 0x3 ||
	    length > E1000_HI_MAX_BLOCK_BYTE_LENGTH) {
		DEBUGOUT("Buffer length failure.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	/* Check that the host interface is enabled. */
	hicr = E1000_READ_REG(hw, E1000_HICR);
	if (!(hicr & E1000_HICR_EN)) {
		DEBUGOUT("E1000_HOST_EN bit disabled.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	/* Calculate length in DWORDs */
	length >>= 2;

	/* The device driver writes the relevant command block
	 * into the ram area.
	 */
	for (i = 0; i < length; i++)
		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF, i,
					    *((u32 *)buffer + i));

	/* Setting this bit tells the ARC that a new command is pending. */
	E1000_WRITE_REG(hw, E1000_HICR, hicr | E1000_HICR_C);

	for (i = 0; i < E1000_HI_COMMAND_TIMEOUT; i++) {
		hicr = E1000_READ_REG(hw, E1000_HICR);
		if (!(hicr & E1000_HICR_C))
			break;
		msec_delay(1);
	}

	/* Check command successful completion. */
	if (i == E1000_HI_COMMAND_TIMEOUT ||
	    (!(E1000_READ_REG(hw, E1000_HICR) & E1000_HICR_SV))) {
		DEBUGOUT("Command has failed with no status valid.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	for (i = 0; i < length; i++)
		*((u32 *)buffer + i) = E1000_READ_REG_ARRAY_DWORD(hw,
								  E1000_HOST_IF,
								  i);

	return E1000_SUCCESS;
}

/**
 *  e1000_load_firmware - Writes proxy FW code buffer to host interface
 *                        and execute.
 *  @hw: pointer to the HW structure
 *  @buffer: contains a firmware to write
 *  @length: the byte length of the buffer, must be multiple of 4 bytes
 *
 *  Upon success returns E1000_SUCCESS, returns E1000_ERR_CONFIG if not enabled
 *  in HW else returns E1000_ERR_HOST_INTERFACE_COMMAND.
 **/
s32 e1000_load_firmware(struct e1000_hw *hw, u8 *buffer, u32 length)
{
	u32 hicr, hibba, fwsm, icr, i;

	DEBUGFUNC("e1000_load_firmware");

	if (hw->mac.type < e1000_i210) {
		DEBUGOUT("Hardware doesn't support loading FW by the driver\n");
		return -E1000_ERR_CONFIG;
	}

	/* Check that the host interface is enabled. */
	hicr = E1000_READ_REG(hw, E1000_HICR);
	if (!(hicr & E1000_HICR_EN)) {
		DEBUGOUT("E1000_HOST_EN bit disabled.\n");
		return -E1000_ERR_CONFIG;
	}
	if (!(hicr & E1000_HICR_MEMORY_BASE_EN)) {
		DEBUGOUT("E1000_HICR_MEMORY_BASE_EN bit disabled.\n");
		return -E1000_ERR_CONFIG;
	}

	if (length == 0 || length & 0x3 || length > E1000_HI_FW_MAX_LENGTH) {
		DEBUGOUT("Buffer length failure.\n");
		return -E1000_ERR_INVALID_ARGUMENT;
	}

	/* Clear notification from ROM-FW by reading ICR register */
	icr = E1000_READ_REG(hw, E1000_ICR_V2);

	/* Reset ROM-FW */
	hicr = E1000_READ_REG(hw, E1000_HICR);
	hicr |= E1000_HICR_FW_RESET_ENABLE;
	E1000_WRITE_REG(hw, E1000_HICR, hicr);
	hicr |= E1000_HICR_FW_RESET;
	E1000_WRITE_REG(hw, E1000_HICR, hicr);
	E1000_WRITE_FLUSH(hw);

	/* Wait till MAC notifies about its readiness after ROM-FW reset */
	for (i = 0; i < (E1000_HI_COMMAND_TIMEOUT * 2); i++) {
		icr = E1000_READ_REG(hw, E1000_ICR_V2);
		if (icr & E1000_ICR_MNG)
			break;
		msec_delay(1);
	}

	/* Check for timeout */
	if (i == E1000_HI_COMMAND_TIMEOUT) {
		DEBUGOUT("FW reset failed.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	/* Wait till MAC is ready to accept new FW code */
	for (i = 0; i < E1000_HI_COMMAND_TIMEOUT; i++) {
		fwsm = E1000_READ_REG(hw, E1000_FWSM);
		if ((fwsm & E1000_FWSM_FW_VALID) &&
		    ((fwsm & E1000_FWSM_MODE_MASK) >> E1000_FWSM_MODE_SHIFT ==
		    E1000_FWSM_HI_EN_ONLY_MODE))
			break;
		msec_delay(1);
	}

	/* Check for timeout */
	if (i == E1000_HI_COMMAND_TIMEOUT) {
		DEBUGOUT("FW reset failed.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	/* Calculate length in DWORDs */
	length >>= 2;

	/* The device driver writes the relevant FW code block
	 * into the ram area in DWORDs via 1kB ram addressing window.
	 */
	for (i = 0; i < length; i++) {
		if (!(i % E1000_HI_FW_BLOCK_DWORD_LENGTH)) {
			/* Point to correct 1kB ram window */
			hibba = E1000_HI_FW_BASE_ADDRESS +
				((E1000_HI_FW_BLOCK_DWORD_LENGTH << 2) *
				(i / E1000_HI_FW_BLOCK_DWORD_LENGTH));

			E1000_WRITE_REG(hw, E1000_HIBBA, hibba);
		}

		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF,
					    i % E1000_HI_FW_BLOCK_DWORD_LENGTH,
					    *((u32 *)buffer + i));
	}

	/* Setting this bit tells the ARC that a new FW is ready to execute. */
	hicr = E1000_READ_REG(hw, E1000_HICR);
	E1000_WRITE_REG(hw, E1000_HICR, hicr | E1000_HICR_C);

	for (i = 0; i < E1000_HI_COMMAND_TIMEOUT; i++) {
		hicr = E1000_READ_REG(hw, E1000_HICR);
		if (!(hicr & E1000_HICR_C))
			break;
		msec_delay(1);
	}

	/* Check for successful FW start. */
	if (i == E1000_HI_COMMAND_TIMEOUT) {
		DEBUGOUT("New FW did not start within timeout period.\n");
		return -E1000_ERR_HOST_INTERFACE_COMMAND;
	}

	return E1000_SUCCESS;
}
