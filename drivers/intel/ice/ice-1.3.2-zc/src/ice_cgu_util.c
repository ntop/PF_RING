// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"

/**
 * ice_cgu_reg_read - Read a CGU register
 * @pf: Board private structure
 * @reg: Register to read from
 * @val: Pointer to the value to read (out param)
 */
int ice_cgu_reg_read(struct ice_pf *pf, u32 reg, u32 *val)
{
	struct ice_sbq_msg_input cgu_msg;
	int status;

	cgu_msg.opcode = ice_sbq_msg_rd;
	cgu_msg.dest_dev = cgu;
	cgu_msg.msg_addr_low = reg;
	cgu_msg.msg_addr_high = 0x0;

	status = ice_sbq_rw_reg_lp(&pf->hw, &cgu_msg, true);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "addr 0x%04x, val 0x%08x\n", reg, cgu_msg.data);
		return -EIO;
	}

	*val = cgu_msg.data;

	return 0;
}

/**
 * ice_cgu_reg_write - Write a CGU register with lock parameter
 * @pf: Board private structure
 * @reg: Register to write to
 * @val: Value to write
 */
int ice_cgu_reg_write(struct ice_pf *pf, u32 reg, u32 val)
{
	struct ice_sbq_msg_input cgu_msg;
	int status;

	cgu_msg.opcode = ice_sbq_msg_wr;
	cgu_msg.dest_dev = cgu;
	cgu_msg.msg_addr_low = reg;
	cgu_msg.msg_addr_high = 0x0;
	cgu_msg.data = val;

	dev_dbg(ice_pf_to_dev(pf), "addr 0x%04x, val 0x%08x\n", reg, val);

	status = ice_sbq_rw_reg_lp(&pf->hw, &cgu_msg, true);
	if (status)
		return -EIO;

	return 0;
}

/**
 * ice_cgu_set_gnd - Ground the refclk
 * @pf: Board private structure
 * @enable: True to ground the refclk
 */
int ice_cgu_set_gnd(struct ice_pf *pf, bool enable)
{
	int status = 0;
	union nac_cgu_dword10 dw10;
	int i;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

	if (enable)
		dw10.field.synce_sel_gnd = 1;
	else
		dw10.field.synce_sel_gnd = 0;

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
	if (status)
		goto err;

	for (i = 0; i < 3; i++)
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_set_byp - Set the DPLL bypass
 * @pf: Board private structure
 * @enable: True to enable bypass
 */
int ice_cgu_set_byp(struct ice_pf *pf, bool enable)
{
	union nac_cgu_dword12 dw12;
	int status = 0;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD12, &dw12.val);
	if (status)
		goto err;

	if (enable)
		dw12.field.synce_dpll_byp = 1;
	else
		dw12.field.synce_dpll_byp = 0;

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD12, dw12.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_set_holdover_lock_irq - Set holdover/lock interrupt
 * @pf: Board private structure
 * @enable: True to enable the lock
 */
int ice_cgu_set_holdover_lock_irq(struct ice_pf *pf, bool enable)
{
	union nac_cgu_dword13 dw13;
	int status;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD13, &dw13.val);
	if (status)
		goto err;

	/* the *_int_enb bits are defined opposite of what one would expect.
	 * 0 = enabled, 1 = disabled
	 */
	if (enable) {
		dw13.field.synce_hdov_int_enb = 0;
		dw13.field.synce_lock_int_enb = 0;
	} else {
		dw13.field.synce_hdov_int_enb = 1;
		dw13.field.synce_lock_int_enb = 1;
	}

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD13, dw13.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_mux_sel_set_reg - Write to selected mux register
 * @pf: Board private structure
 * @mux_sel: Target mux
 * @val: Value to write to
 */
int ice_cgu_mux_sel_set_reg(struct ice_pf *pf, enum ice_cgu_mux_sel mux_sel, u32 val)
{
	union nac_cgu_dword10 dw10;
	union nac_cgu_dword11 dw11;
	int status;

	switch (mux_sel) {
	case ICE_CGU_MUX_SEL_REF_CLK:
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
		if (status)
			goto err;
		dw10.field.synce_s_ref_clk = val;
		status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
		if (status)
			goto err;
		break;

	case ICE_CGU_MUX_SEL_BYPASS_CLK:
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD11, &dw11.val);
		if (status)
			goto err;
		dw11.field.synce_s_byp_clk = val;
		status = ice_cgu_reg_write(pf, NAC_CGU_DWORD11, dw11.val);
		if (status)
			goto err;
		break;

	case ICE_CGU_MUX_SEL_ETHCLKO:
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
		if (status)
			goto err;
		dw10.field.synce_ethclko_sel = val;
		status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
		if (status)
			goto err;
		break;

	case ICE_CGU_MUX_SEL_CLKO:
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
		if (status)
			goto err;
		dw10.field.synce_clko_sel = val;
		status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
		if (status)
			goto err;
		break;

	default:
		dev_err(ice_pf_to_dev(pf), "internal error -- invalid mux!\n");
		return -EIO;
	}

err:
	return status;
}

/**
 * ice_cgu_dck_rst_assert_release - Assert the dck reset
 * @pf: Board private structure
 * @assert: True to assert, false to release
 */
int ice_cgu_dck_rst_assert_release(struct ice_pf *pf, bool assert)
{
	union nac_cgu_dword10 dw10;
	int status = 0;
	int i;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

	if (assert)
		dw10.field.synce_dck_rst = 1;
	else
		dw10.field.synce_dck_rst = 0;

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
	if (status)
		goto err;

	for (i = 0; i < 3; i++)
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_dck2_rst_assert_release - Assert the dck2 reset
 * @pf: Board private structure
 * @assert: True to assert, false to release
 */
int ice_cgu_dck2_rst_assert_release(struct ice_pf *pf, bool assert)
{
	union nac_cgu_dword10 dw10;
	int status = 0;
	int i;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

	if (assert)
		dw10.field.synce_dck2_rst = 1;
	else
		dw10.field.synce_dck2_rst = 0;

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD10, dw10.val);
	if (status)
		goto err;

	for (i = 0; i < 3; i++)
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_mck_rst_assert_release - Assert the mck reset
 * @pf: Board private structure
 * @assert: True to assert, false to release
 */
int ice_cgu_mck_rst_assert_release(struct ice_pf *pf, bool assert)
{
	union nac_cgu_dword12 dw12;
	int status = 0;
	int i;

	status = ice_cgu_reg_read(pf, NAC_CGU_DWORD12, &dw12.val);
	if (status)
		goto err;

	if (assert)
		dw12.field.synce_mck_rst = 1;
	else
		dw12.field.synce_mck_rst = 0;

	status = ice_cgu_reg_write(pf, NAC_CGU_DWORD12, dw12.val);
	if (status)
		goto err;

	for (i = 0; i < 3; i++)
		status = ice_cgu_reg_read(pf, NAC_CGU_DWORD12, &dw12.val);
	if (status)
		goto err;

err:
	return status;
}

/**
 * ice_cgu_usleep - Sleep for a specified period of time
 * @usec: Time to sleep in microseconds
 */
void ice_cgu_usleep(u64 usec)
{
	if (usec <= 10) {
		udelay(usec);
	} else if (usec <= 20000) {
		usleep_range(usec, usec + 10);
	} else {
		int msec;

		msec = (usec + 999) / 1000;
		msleep_interruptible(msec);
	}
}

/**
 * ice_cgu_poll - Poll the specified CGU register for the specified value
 * @pf: Board private structure
 * @offset: Offset of the register
 * @mask: Bitmask for testing the value
 * @value: Value to poll for
 * @delay_time: Delay between the register reads
 * @delay_loops: Number of read loops
 */
int ice_cgu_poll(struct ice_pf *pf, u64 offset, u32 mask, u32 value, u32 delay_time,
		 u32 delay_loops)
{
	int status;
	u32 reg, i;

	for (i = 0; i < delay_loops; i++) {
		status = ice_cgu_reg_read(pf, offset, &reg);
		if (status)
			goto err;

		if ((reg & mask) == value)
			return 0;

		/* delay for a bit */
		ice_cgu_usleep(delay_time);
	}

	return -EBUSY;

err:
	return status;
}

/**
 * ice_cgu_npoll - Poll the specified CGU register for the specified value occurring n times
 * @pf: Board private structure
 * @offset: Offset of the register
 * @mask: Bitmask for testing the value
 * @value: Value to poll for
 * @delay_time: Delay between the register reads
 * @delay_loops: Number of read loops
 * @poll_count: Number of the value matches to poll for
 * @count_delay_time: Additional delay after the value match
 */
int ice_cgu_npoll(struct ice_pf *pf, u32 offset, u32 mask, u32 value, u32 delay_time,
		  u32 delay_loops, u32 poll_count, u32 count_delay_time)
{
	u32 reg, i, my_count = 0, complete = 0;
	int status;

	for (i = 0; i < delay_loops; i++) {
		status = ice_cgu_reg_read(pf, offset, &reg);
		if (status)
			goto err;

		dev_dbg(ice_pf_to_dev(pf), "count=%u, reg=%08x\n", my_count, reg);

		if ((reg & mask) == value) {
			my_count++;
			if (my_count < poll_count) {
				ice_cgu_usleep(count_delay_time);
			} else {
				complete = 1;
				break;
			}
		} else {
			my_count = 0;
			ice_cgu_usleep(delay_time);
		}
	}

	if (complete)
		return 0;
	else
		return -EBUSY;

err:
	return status;
}

struct ice_cgu_dpll_params dpll_params_table[ICE_NUM_DPLL_PARAMS] = {
	/* {dpll select, sample rate, mul_rat_m1, scale, gain} */
	{ ICE_CGU_DPLL_SELECT_TRANSPORT, ICE_CGU_SAMPLE_RATE_8K, 3124, 16, 42 },
	{ ICE_CGU_DPLL_SELECT_EEC_RELAXED_BW, ICE_CGU_SAMPLE_RATE_8K, 3124, 7, 3 },
	{ ICE_CGU_DPLL_SELECT_TRANSPORT, ICE_CGU_SAMPLE_RATE_10K, 2499, 20, 66 },
	{ ICE_CGU_DPLL_SELECT_EEC_RELAXED_BW, ICE_CGU_SAMPLE_RATE_10K, 2499, 8, 4 },
	{ ICE_CGU_DPLL_SELECT_TRANSPORT, ICE_CGU_SAMPLE_RATE_12K5, 1999, 25, 103 },
	{ ICE_CGU_DPLL_SELECT_EEC_RELAXED_BW, ICE_CGU_SAMPLE_RATE_12K5, 1999, 10, 6 }
};

struct ice_cgu_dpll_per_rate_params dpll_per_rate_params[NUM_ICE_TIME_REF_FREQ] = {
	/* {rate_hz, sample_rate, div_rat_m1, synce_rat_sel} */
	{ 25000000, ICE_CGU_SAMPLE_RATE_10K, 2499, 0 }, /* 25 MHz */
	{ 122880000, ICE_CGU_SAMPLE_RATE_8K, 3071, 1 }, /* 122.88 MHz */
	{ 125000000, ICE_CGU_SAMPLE_RATE_10K, 2499, 1 }, /* 125 MHz */
	{ 153600000, ICE_CGU_SAMPLE_RATE_10K, 3071, 1 }, /* 153.6 MHz */
	{ 156250000, ICE_CGU_SAMPLE_RATE_10K, 3124, 1 }, /* 156.25 MHz */
};

struct ice_cgu_lcpll_per_rate_params tspll_per_rate_params[NUM_ICE_TIME_REF_FREQ] = {
	/* {refclk_pre_div, feedback_div, frac_n_div, post_pll_div} */
	{ 1, 197, 2621440, 6 }, /* 25 MHz */
	{ 5, 223, 524288, 7 }, /* 122.88 MHz */
	{ 5, 223, 524288, 7 }, /* 125 MHz */
	{ 5, 159, 1572864, 6 }, /* 153.6 MHz */
	{ 5, 159, 1572864, 6 }, /* 156.25 MHz */
	{ 10, 223, 524288, 7 }, /* 245.76 MHz */
};

struct ice_cgu_lcpll_per_rate_params japll_per_rate_params[NUM_ICE_CGU_JAPLL_REF_FREQ] = {
	/* {refclk_pre_div, feedback_div, frac_n_div, post_pll_div} */
	{ 1, 150, 0, 6 }, /* 25 MHz */
	{ 1, 120, 0, 6 }, /* 156.25 MHz */
};
