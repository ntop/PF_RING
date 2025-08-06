/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_ptp_hw.h"

static const struct
ice_tspll_params_e82x e82x_tspll_params[NUM_ICE_TSPLL_FREQ] = {
	[ICE_TSPLL_FREQ_25_000] = {
		.refclk_pre_div = 1,
		.feedback_div = 197,
		.frac_n_div = 2621440,
		.post_pll_div = 6
	},
	[ICE_TSPLL_FREQ_122_880] = {
		.refclk_pre_div = 5,
		.feedback_div = 223,
		.frac_n_div = 524288,
		.post_pll_div = 7
	},
	[ICE_TSPLL_FREQ_125_000] = {
		.refclk_pre_div = 5,
		.feedback_div = 223,
		.frac_n_div = 524288,
		.post_pll_div = 7
	},
	[ICE_TSPLL_FREQ_153_600] = {
		.refclk_pre_div = 5,
		.feedback_div = 159,
		.frac_n_div = 1572864,
		.post_pll_div = 6
	},
	[ICE_TSPLL_FREQ_156_250] = {
		.refclk_pre_div = 5,
		.feedback_div = 159,
		.frac_n_div = 1572864,
		.post_pll_div = 6
	},
	[ICE_TSPLL_FREQ_245_760] = {
		.refclk_pre_div = 10,
		.feedback_div = 223,
		.frac_n_div = 524288,
		.post_pll_div = 7
	}
};

static const struct
ice_tspll_params_e825c e825c_tspll_params[NUM_ICE_TSPLL_FREQ] = {
	[ICE_TSPLL_FREQ_25_000] = {
		.ck_refclkfreq = 0x19,
		.ndivratio = 1,
		.fbdiv_intgr = 320,
		.fbdiv_frac = 0
	},
	[ICE_TSPLL_FREQ_122_880] = {
		.ck_refclkfreq = 0x29,
		.ndivratio = 3,
		.fbdiv_intgr = 195,
		.fbdiv_frac = 1342177280
	},
	[ICE_TSPLL_FREQ_125_000] = {
		.ck_refclkfreq = 0x3E,
		.ndivratio = 2,
		.fbdiv_intgr = 128,
		.fbdiv_frac = 0
	},
	[ICE_TSPLL_FREQ_153_600] = {
		.ck_refclkfreq = 0x33,
		.ndivratio = 3,
		.fbdiv_intgr = 156,
		.fbdiv_frac = 1073741824
	},
	[ICE_TSPLL_FREQ_156_250] = {
		.ck_refclkfreq = 0x1F,
		.ndivratio = 5,
		.fbdiv_intgr = 256,
		.fbdiv_frac = 0
	},
	[ICE_TSPLL_FREQ_245_760] = {
		.ck_refclkfreq = 0x52,
		.ndivratio = 3,
		.fbdiv_intgr = 97,
		.fbdiv_frac = 2818572288
	}
};

static ssize_t tspll_cfg_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t len);
static ssize_t tspll_cfg_show(struct device *dev, struct device_attribute *attr,
			      char *buf);

static DEVICE_ATTR_RW(tspll_cfg);

/**
 * ice_tspll_sysfs_init - initialize sysfs for internal TSPLL
 * @hw: Pointer to the HW struct
 */
void ice_tspll_sysfs_init(struct ice_hw *hw)
{
	struct device *dev = ice_hw_to_dev(hw);

	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		if (device_create_file(dev, &dev_attr_tspll_cfg))
			dev_dbg(dev, "Failed to create tspll_cfg kobject\n");
		return;
	default:
		return;
	}
}

/**
 * ice_tspll_sysfs_release - release sysfs for internal TSPLL
 * @hw: Pointer to the HW struct
 */
void ice_tspll_sysfs_release(struct ice_hw *hw)
{
	struct device *dev = ice_hw_to_dev(hw);

	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		device_remove_file(dev, &dev_attr_tspll_cfg);
		return;
	default:
		return;
	}
}

/**
 * ice_tspll_set_params_e82x - set TSPLL params for all PFs
 * @pf: Board private structure
 * @tspll_freq: TSPLL frequency to use
 * @clk_src: source of the clock signal
 * @src_tmr_mode: source timer mode (nanoseconds or locked)
 */
static void ice_tspll_set_params_e82x(struct ice_pf *pf,
				      enum ice_tspll_freq tspll_freq,
				      enum ice_clk_src clk_src,
				      enum ice_src_tmr_mode src_tmr_mode)
{
	struct ice_ptp_port *port;

	mutex_lock(&pf->adapter->ports.lock);
	list_for_each_entry(port, &pf->adapter->ports.ports, list_node) {
		struct ice_pf *target_pf = ptp_port_to_pf(port);

		target_pf->hw.ptp.tspll_freq = tspll_freq;
		target_pf->hw.ptp.src_tmr_mode = src_tmr_mode;
		target_pf->hw.ptp.clk_src = clk_src;
	}
	mutex_unlock(&pf->adapter->ports.lock);
}

/**
 * ice_tspll_clk_freq_str - Convert tspll_freq to string
 * @clk_freq: Clock frequency
 *
 * Convert the specified TSPLL clock frequency to a string.
 */
static const char *ice_tspll_clk_freq_str(enum ice_tspll_freq clk_freq)
{
	switch (clk_freq) {
	case ICE_TSPLL_FREQ_25_000:
		return "25 MHz";
	case ICE_TSPLL_FREQ_122_880:
		return "122.88 MHz";
	case ICE_TSPLL_FREQ_125_000:
		return "125 MHz";
	case ICE_TSPLL_FREQ_153_600:
		return "153.6 MHz";
	case ICE_TSPLL_FREQ_156_250:
		return "156.25 MHz";
	case ICE_TSPLL_FREQ_245_760:
		return "245.76 MHz";
	default:
		return "Unknown";
	}
}

/**
 * ice_tspll_check_params - Check if CGU PLL params are correct
 * @hw: Pointer to the HW struct
 * @clk_freq: Clock frequency to program
 * @clk_src: Clock source to select (TIME_REF, or TCXO)
 * @tmr_mode: source timer mode (nanoseconds or locked)
 */
static bool ice_tspll_check_params(struct ice_hw *hw,
				   enum ice_tspll_freq clk_freq,
				   enum ice_clk_src clk_src,
				   enum ice_src_tmr_mode tmr_mode)
{
	enum ice_tspll_freq tcxo_freq = ICE_TSPLL_FREQ_25_000;

	if (clk_freq >= NUM_ICE_TSPLL_FREQ) {
		dev_warn(ice_hw_to_dev(hw), "Invalid TSPLL frequency %u\n",
			 clk_freq);
		return false;
	}

	if (clk_src >= NUM_ICE_CLK_SRC) {
		dev_warn(ice_hw_to_dev(hw), "Invalid clock source %u\n",
			 clk_src);
		return false;
	}

	if (tmr_mode >= NUM_ICE_SRC_TMR_MODE) {
		dev_warn(ice_hw_to_dev(hw), "Invalid source timer mode %u\n",
			 clk_src);
		return false;
	}

	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825) {
		tcxo_freq = ICE_TSPLL_FREQ_156_250;
		if (clk_freq != tcxo_freq) {
			dev_warn(ice_hw_to_dev(hw), "Only %s frequency is supported on this device\n",
				 ice_tspll_clk_freq_str(tcxo_freq));
			return false;
		}
	}

	if (clk_src == ICE_CLK_SRC_TCXO &&
	    clk_freq != tcxo_freq) {
		dev_warn(ice_hw_to_dev(hw), "TCXO only supports %s frequency\n",
			 ice_tspll_clk_freq_str(tcxo_freq));
		return false;
	}

	if (tmr_mode == ICE_SRC_TMR_MODE_LOCKED &&
	    clk_src != ICE_CLK_SRC_TIME_REF) {
		dev_warn(ice_hw_to_dev(hw), "Locked mode available only with TIME_REF as source\n");
		return false;
	}

	return true;
}

/**
 * ice_tspll_clk_src_str - Convert clk_src to string
 * @clk_src: Clock source
 *
 * Convert the specified clock source to its string name.
 */
static const char *ice_tspll_clk_src_str(enum ice_clk_src clk_src)
{
	switch (clk_src) {
	case ICE_CLK_SRC_TCXO:
		return "TCXO";
	case ICE_CLK_SRC_TIME_REF:
		return "TIME_REF";
	default:
		return "Unknown";
	}
}

/**
 * ice_tspll_src_tmr_mode_str - Convert src_tmr_mode to string
 * @hw: Pointer to the HW struct
 *
 * Convert the specified source timer mode to a string.
 */
static const char *
ice_tspll_src_tmr_mode_str(const struct ice_hw *hw)
{
	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825)
		return "";

	switch (hw->ptp.src_tmr_mode) {
	case ICE_SRC_TMR_MODE_NANOSECONDS:
		return "NS MODE";
	case ICE_SRC_TMR_MODE_LOCKED:
		return "LOCKED MODE";
	default:
		return "Unknown";
	}
}

/**
 * ice_tspll_ticks2ns - Converts system ticks to nanoseconds
 * @hw: Pointer to the HW struct
 * @ticks: Ticks to be converted into ns
 *
 * This function converTSPLL ticks into nanoseconds when the PHC works in
 * locked mode.
 */
u64 ice_tspll_ticks2ns(const struct ice_hw *hw, u64 ticks)
{
	if (hw->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		u64 freq = ice_ptp_get_pll_freq(hw);

		/* Avoid division by zero */
		if (!freq)
			return 0;

		return mul_u64_u64_div_u64(ticks, 1000000000ULL, freq);
	}
	return ticks;
}

/**
 * ice_tspll_ns2ticks - Converts nanoseconds to system ticks
 * @hw: Pointer to the HW struct
 * @ns: Nanoseconds to be converted into ticks
 *
 * This function converts nanoseconds into PLL ticks when PHC works in
 * locked mode.
 */
u64 ice_tspll_ns2ticks(const struct ice_hw *hw, u64 ns)
{
	if (hw->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		u64 freq = ice_ptp_get_pll_freq(hw);

		return mul_u64_u64_div_u64(ns, freq, 1000000000ULL);
	}
	return ns;
}

/**
 * ice_get_dest_cgu - get destination CGU dev for given HW
 * @hw: pointer to the HW struct
 */
static enum ice_sbq_msg_dev ice_get_dest_cgu(struct ice_hw *hw)
{
	/* On dual complex E825 only complex 0 has functional CGU powering all
	 * the PHYs.
	 * SBQ destination device cgu points to CGU on a current complex and to
	 * access primary CGU from the secondary complex, the driver should use
	 * cgu_peer as a destination device.
	 */
	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825 && ice_is_dual(hw) &&
	    !ice_is_primary(hw))
		return cgu_peer;
	else
		return cgu;
}

/**
 * ice_read_cgu_reg - Read a CGU register
 * @hw: Pointer to the HW struct
 * @addr: Register address to read
 * @val: Storage for register value read
 *
 * Read the contents of a register of the Clock Generation Unit. Only
 * applicable to E82X/E825 devices.
 */
static int ice_read_cgu_reg(struct ice_hw *hw, u16 addr, u32 *val)
{
	struct ice_sbq_msg_input cgu_msg = {
		.dest_dev = ice_get_dest_cgu(hw),
		.opcode = ice_sbq_msg_rd,
		.msg_addr_low = addr,
		.msg_addr_high = 0x0
	};
	int err;

	err = ice_sbq_rw_reg(hw, &cgu_msg, ICE_AQ_FLAG_RD);
	if (err) {
		dev_dbg(ice_hw_to_dev(hw), "Failed to read CGU register 0x%04x, err %d\n",
			addr, err);
		return err;
	}

	*val = cgu_msg.data;

	return 0;
}

#define ice_read_cgu_reg_or_die(hw, addr, val)		\
do {							\
	static int __err;				\
							\
	__err = ice_read_cgu_reg((hw), (addr), (val));	\
	if (__err) {					\
		return __err;				\
	}						\
} while (0)

/**
 * ice_write_cgu_reg - Write a CGU register
 * @hw: Pointer to the HW struct
 * @addr: Register address to write
 * @val: Value to write into the register
 *
 * Write the specified value to a register of the Clock Generation Unit. Only
 * applicable to E82X/E825 devices.
 */
static int ice_write_cgu_reg(struct ice_hw *hw, u16 addr, u32 val)
{
	struct ice_sbq_msg_input cgu_msg = {
		.dest_dev = ice_get_dest_cgu(hw),
		.opcode = ice_sbq_msg_wr_np,
		.msg_addr_low = addr,
		.msg_addr_high = 0x0,
		.data = val
	};
	int err;

	err = ice_sbq_rw_reg(hw, &cgu_msg, ICE_AQ_FLAG_RD);
	if (err) {
		dev_dbg(ice_hw_to_dev(hw), "Failed to write CGU register 0x%04x, err %d\n",
			addr, err);
		return err;
	}

	return 0;
}

#define ice_write_cgu_reg_or_die(hw, addr, val)		\
do {							\
	static int __err;				\
							\
	__err = ice_write_cgu_reg((hw), (addr), (val));	\
	if (__err) {					\
		return __err;				\
	}						\
} while (0)

/**
 * ice_tspll_log_cfg - Log current/new TSPLL configuration
 * @hw: Pointer to the HW struct
 * @enable: CGU enabled/disabled
 * @clk_src: Current clock source
 * @tspll_freq: Current clock frequency
 * @lock: CGU lock status
 * @new_cfg: true if this is a new config
 */
static void ice_tspll_log_cfg(struct ice_hw *hw, bool enable, u8 clk_src,
			      u8 tspll_freq, bool lock, bool new_cfg)
{
	dev_dbg(ice_hw_to_dev(hw),
		"%s TSPLL configuration -- %s, src %s, freq %s, PLL %s\n",
		new_cfg ? "New" : "Current", enable ? "enabled" : "disabled",
		ice_tspll_clk_src_str((enum ice_clk_src)clk_src),
		ice_tspll_clk_freq_str((enum ice_tspll_freq)tspll_freq),
		lock ? "locked" : "unlocked");
}

/**
 * ice_tspll_cfg_e82x - Configure the Clock Generation Unit TSPLL
 * @hw: Pointer to the HW struct
 * @clk_freq: Clock frequency to program
 * @clk_src: Clock source to select (TIME_REF, or TCXO)
 *
 * Configure the Clock Generation Unit with the desired clock frequency and
 * time reference, enabling the PLL which drives the PTP hardware clock.
 */
static int ice_tspll_cfg_e82x(struct ice_hw *hw, enum ice_tspll_freq clk_freq,
			      enum ice_clk_src clk_src)
{
	u32 val, r9, r24;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R9, &r9);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R24, &r24);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_RO_BWM_LF, &val);

	ice_tspll_log_cfg(hw, !!FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r24),
			  FIELD_GET(ICE_CGU_R23_R24_TIME_REF_SEL, r24),
			  FIELD_GET(ICE_CGU_R9_TIME_REF_FREQ_SEL, r9),
			  !!FIELD_GET(ICE_CGU_RO_BWM_LF_TRUE_LOCK, val),
			  false);

	/* Disable the PLL before changing the clock source or frequency */
	if (FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r24)) {
		r24 &= ~ICE_CGU_R23_R24_TSPLL_ENABLE;
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R24, r24);
	}

	/* Set the frequency */
	r9 &= ~ICE_CGU_R9_TIME_REF_FREQ_SEL;
	r9 |= FIELD_PREP(ICE_CGU_R9_TIME_REF_FREQ_SEL, clk_freq);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R9, r9);

	/* Configure the TSPLL feedback divisor */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R19, &val);
	val &= ~(ICE_CGU_R19_TSPLL_FBDIV_INTGR | ICE_CGU_R19_TSPLL_NDIVRATIO);
	val |= FIELD_PREP(ICE_CGU_R19_TSPLL_FBDIV_INTGR,
			  e82x_tspll_params[clk_freq].feedback_div);
	val |= FIELD_PREP(ICE_CGU_R19_TSPLL_NDIVRATIO, 1);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R19, val);

	/* Configure the TSPLL post divisor */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R22, &val);
	val &= ~(ICE_CGU_R22_TIME1588CLK_DIV |
		 ICE_CGU_R22_TIME1588CLK_SEL_DIV2);
	val |= FIELD_PREP(ICE_CGU_R22_TIME1588CLK_DIV,
			  e82x_tspll_params[clk_freq].post_pll_div);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R22, val);

	/* Configure the TSPLL pre divisor and clock source */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R24, &r24);
	r24 &= ~(ICE_CGU_R23_R24_REF1588_CK_DIV |
		 ICE_CGU_R24_E82X_TSPLL_FBDIV_FRAC |
		 ICE_CGU_R23_R24_TIME_REF_SEL);
	r24 |= FIELD_PREP(ICE_CGU_R23_R24_REF1588_CK_DIV,
			  e82x_tspll_params[clk_freq].refclk_pre_div);
	r24 |= FIELD_PREP(ICE_CGU_R24_E82X_TSPLL_FBDIV_FRAC,
			  e82x_tspll_params[clk_freq].frac_n_div);
	r24 |= FIELD_PREP(ICE_CGU_R23_R24_TIME_REF_SEL, clk_src);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R24, r24);

	/* Wait to ensure everything is stable */
	usleep_range(10, 20);

	/* Finally, enable the PLL */
	r24 |= ICE_CGU_R23_R24_TSPLL_ENABLE;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R24, r24);

	/* Wait at least 1 ms to verify if the PLL locks */
	usleep_range(USEC_PER_MSEC, 2 * USEC_PER_MSEC);

	ice_read_cgu_reg_or_die(hw, ICE_CGU_RO_BWM_LF, &val);
	if (!(val & ICE_CGU_RO_BWM_LF_TRUE_LOCK)) {
		dev_warn(ice_hw_to_dev(hw), "CGU PLL failed to lock\n");
		return -EBUSY;
	}

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R9, &r9);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R24, &r24);

	ice_tspll_log_cfg(hw, !!FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r24),
			  clk_src, clk_freq, true, true);

	return 0;
}

/**
 * ice_tspll_dis_sticky_bits_e82x - disable TSPLL sticky bits
 * @hw: Pointer to the HW struct
 *
 * Configure the Clock Generation Unit TSPLL sticky bits so they don't latch on
 * losing TSPLL lock, but always show current state.
 */
static int ice_tspll_dis_sticky_bits_e82x(struct ice_hw *hw)
{
	u32 val;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_CNTR_BIST, &val);
	val &= ~(ICE_CGU_CNTR_BIST_PLLLOCK_SEL_0 |
		 ICE_CGU_CNTR_BIST_PLLLOCK_SEL_1);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_CNTR_BIST, val);
	return 0;
}

/**
 * ice_tspll_cfg_e825c - Configure the TSPLL for E825-C
 * @hw: Pointer to the HW struct
 * @clk_freq: Clock frequency to program
 * @clk_src: Clock source to select (TIME_REF, or TCXO)
 *
 * Configure the Clock Generation Unit with the desired clock frequency and
 * time reference, enabling the TSPLL which drives the PTP hardware clock.
 */
static int ice_tspll_cfg_e825c(struct ice_hw *hw, enum ice_tspll_freq clk_freq,
			       enum ice_clk_src clk_src)
{
	u32 val, r9, r23;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R9, &r9);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R23, &r23);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_RO_LOCK, &val);

	ice_tspll_log_cfg(hw, !!FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r23),
			  FIELD_GET(ICE_CGU_R23_R24_TIME_REF_SEL, r23),
			  FIELD_GET(ICE_CGU_R9_TIME_REF_FREQ_SEL, r9),
			  !!FIELD_GET(ICE_CGU_RO_LOCK_TRUE_LOCK, val),
			  false);

	/* Disable the PLL before changing the clock source or frequency */
	if (FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r23)) {
		r23 &= ~ICE_CGU_R23_R24_TSPLL_ENABLE;
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R23, r23);
	}

	if (FIELD_GET(ICE_CGU_R9_TIME_SYNC_EN, r9)) {
		r9 &= ~ICE_CGU_R9_TIME_SYNC_EN;
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R9, r9);
	}

	/* Set the frequency and enable the correct receiver */
	r9 &= ~(ICE_CGU_R9_TIME_REF_FREQ_SEL | ICE_CGU_R9_CLK_EREF0_EN |
		ICE_CGU_R9_TIME_REF_EN);
	r9 |= FIELD_PREP(ICE_CGU_R9_TIME_REF_FREQ_SEL, clk_freq);
	if (clk_src == ICE_CLK_SRC_TCXO)
		r9 |= ICE_CGU_R9_CLK_EREF0_EN;
	else
		r9 |= ICE_CGU_R9_TIME_REF_EN;
	r9 |= ICE_CGU_R9_TIME_SYNC_EN;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R9, r9);

	/* Choose the referenced frequency */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R16, &val);
	val &= ~ICE_CGU_R16_TSPLL_CK_REFCLKFREQ;
	val |= FIELD_PREP(ICE_CGU_R16_TSPLL_CK_REFCLKFREQ,
			  e825c_tspll_params[clk_freq].ck_refclkfreq);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R16, val);

	/* Configure the TSPLL feedback divisor */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R19, &val);
	val &= ~(ICE_CGU_R19_TSPLL_FBDIV_INTGR | ICE_CGU_R19_TSPLL_NDIVRATIO);
	val |= FIELD_PREP(ICE_CGU_R19_TSPLL_FBDIV_INTGR,
			  e825c_tspll_params[clk_freq].fbdiv_intgr);
	val |= FIELD_PREP(ICE_CGU_R19_TSPLL_NDIVRATIO,
			  e825c_tspll_params[clk_freq].ndivratio);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R19, val);

	/* Configure the TSPLL post divisor, these two are constant */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R22, &val);
	val &= ~(ICE_CGU_R22_TIME1588CLK_DIV |
		 ICE_CGU_R22_TIME1588CLK_SEL_DIV2);
	val |= FIELD_PREP(ICE_CGU_R22_TIME1588CLK_DIV, 5);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R22, val);

	/* Configure the TSPLL pre divisor (constant) and clock source */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R23, &r23);
	r23 &= ~(ICE_CGU_R23_R24_REF1588_CK_DIV | ICE_CGU_R23_R24_TIME_REF_SEL);
	r23 |= FIELD_PREP(ICE_CGU_R23_R24_TIME_REF_SEL, clk_src);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R23, r23);

	/* Only one field in here so no need to read first */
	val = FIELD_PREP(ICE_CGU_R24_ETH56G_FBDIV_FRAC,
			 e825c_tspll_params[clk_freq].fbdiv_frac);
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R24, val);

	/* Wait to ensure everything is stable */
	usleep_range(10, 20);

	/* Finally, enable the PLL */
	r23 |= ICE_CGU_R23_R24_TSPLL_ENABLE;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R23, r23);

	/* Wait at least 1 ms to verify if the PLL locks */
	usleep_range(USEC_PER_MSEC, 2 * USEC_PER_MSEC);

	ice_read_cgu_reg_or_die(hw, ICE_CGU_RO_LOCK, &val);
	if (!(val & ICE_CGU_RO_LOCK_TRUE_LOCK)) {
		dev_warn(ice_hw_to_dev(hw), "CGU PLL failed to lock\n");
		return -EBUSY;
	}

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R9, &r9);
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R23, &r23);

	ice_tspll_log_cfg(hw, !!FIELD_GET(ICE_CGU_R23_R24_TSPLL_ENABLE, r23),
			  clk_src, clk_freq, true, true);

	return 0;
}

/**
 * ice_tspll_dis_sticky_bits_e825c - disable TSPLL sticky bits for E825-C
 * @hw: Pointer to the HW struct
 *
 * Configure the Clock Generation Unit TSPLL sticky bits so they don't latch on
 * losing TSPLL lock, but always show current state.
 */
static int ice_tspll_dis_sticky_bits_e825c(struct ice_hw *hw)
{
	u32 val;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_BW_TDC, &val);
	val &= ~ICE_CGU_BW_TDC_PLLLOCK_SEL;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_BW_TDC, val);

	return 0;
}

/**
 * ice_tspll_lost_lock_e825c - check if TSPLL lost lock
 * @hw: Pointer to the HW struct
 * @lost_lock: Output flag for reporting lost lock
 */
static int ice_tspll_lost_lock_e825c(struct ice_hw *hw, bool *lost_lock)
{
	u32 val;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_RO_LOCK, &val);
	if (FIELD_GET(ICE_CGU_RO_LOCK_UNLOCK, val) &&
	    !FIELD_GET(ICE_CGU_RO_LOCK_TRUE_LOCK, val))
		*lost_lock = true;
	else
		*lost_lock = false;

	return 0;
}

/**
 * ice_tspll_restart_e825c - trigger TSPLL restart
 * @hw: Pointer to the HW struct
 */
static int ice_tspll_restart_e825c(struct ice_hw *hw)
{
	u32 val;

	/* Read the initial values of r23 and disable the PLL */
	ice_read_cgu_reg_or_die(hw, ICE_CGU_R23, &val);
	val &= ~ICE_CGU_R23_R24_TSPLL_ENABLE;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R23, val);

	/* Wait at least 1 ms before reenabling PLL */
	usleep_range(USEC_PER_MSEC, 2 * USEC_PER_MSEC);
	val |= ICE_CGU_R23_R24_TSPLL_ENABLE;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R23, val);

	return 0;
}

/**
 * ice_tspll_monitor_lock_e825c - Check if TSPLL lock is lost
 * @hw: Pointer to the HW struct
 */
int ice_tspll_monitor_lock_e825c(struct ice_hw *hw)
{
	bool lock_lost;
	int err;

	err = ice_tspll_lost_lock_e825c(hw, &lock_lost);
	if (err) {
		dev_err(ice_hw_to_dev(hw),
			"Failed reading TimeSync PLL lock status. Retrying.\n");
	} else if (lock_lost) {
		/* Log every two minutes */
		if (hw->ptp.tspll_lock_retries % 120)
			dev_err(ice_hw_to_dev(hw), "TimeSync PLL lock lost. Retrying to acquire lock with current PLL configuration\n");

		err = ice_tspll_restart_e825c(hw);
		if (err) {
			dev_err(ice_hw_to_dev(hw), "Failed reading TimeSync PLL lock status. Retrying.\n");
			return err;
		}

		hw->ptp.tspll_lock_retries++;
	} else {
		if (hw->ptp.tspll_lock_retries)
			dev_err(ice_hw_to_dev(hw), "TimeSync PLL lock is acquired with %s clock source.\n",
				ice_tspll_clk_src_str(hw->ptp.clk_src));

		hw->ptp.tspll_lock_retries = 0;
	}

	return err;
}

#define ICE_CGU_BYPASS_MUX_OFFSET_E825C 3

/**
 * ice_tspll_bypass_mux_active_e825c - check if the given port is set active
 * @hw: Pointer to the HW struct
 * @port: Number of the port
 * @active: Output flag showing if port is active
 * @output: Output pin, we have two in E825C
 */
int ice_tspll_bypass_mux_active_e825c(struct ice_hw *hw, u8 port, bool *active,
				      enum ice_synce_clk output)
{
	u8 active_clk;
	u32 val;

	switch (output) {
	case ICE_SYNCE_CLK0:
		ice_read_cgu_reg_or_die(hw, ICE_CGU_R10, &val);
		active_clk = FIELD_GET(ICE_CGU_R10_SYNCE_S_REF_CLK, val);
		break;
	case ICE_SYNCE_CLK1:
		ice_read_cgu_reg_or_die(hw, ICE_CGU_R11, &val);
		active_clk = FIELD_GET(ICE_CGU_R11_SYNCE_S_BYP_CLK, val);
		break;
	default:
		return -EINVAL;
	}

	if (active_clk == port % hw->ptp.ports_per_phy +
			  ICE_CGU_BYPASS_MUX_OFFSET_E825C)
		*active = true;
	else
		*active = false;

	return 0;
}

#define ICE_CGU_NET_REF_CLK0		0x0
#define ICE_CGU_NCOCLK			0x2
#define ICE_CGU_REF_CLK_BYP0		0x5
#define ICE_CGU_REF_CLK_BYP0_DIV	0x0
#define ICE_CGU_REF_CLK_BYP1		0x4
#define ICE_CGU_REF_CLK_BYP1_DIV	0x1

/**
 * ice_tspll_cfg_bypass_mux_e825c - check if the given port is set active
 * @hw: Pointer to the HW struct
 * @port: Number of the port
 * @output: Output pin, we have two in E825C
 * @clock_1588: true to enable 1588 reference, false to recover from port
 * @ena: true to enable the reference, false if disable
 */
int ice_tspll_cfg_bypass_mux_e825c(struct ice_hw *hw, u8 port,
				   enum ice_synce_clk output, bool clock_1588,
				   unsigned int ena)
{
	u8 first_mux;
	u32 r10;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R10, &r10);

	if (!ena)
		first_mux = ICE_CGU_NET_REF_CLK0;
	else if (clock_1588)
		first_mux = ICE_CGU_NCOCLK;
	else
		first_mux = port + ICE_CGU_BYPASS_MUX_OFFSET_E825C;

	r10 &= ~(ICE_CGU_R10_SYNCE_DCK_RST | ICE_CGU_R10_SYNCE_DCK2_RST);

	switch (output) {
	case ICE_SYNCE_CLK0:
		r10 &= ~(ICE_CGU_R10_SYNCE_ETHCLKO_SEL |
			 ICE_CGU_R10_SYNCE_ETHDIV_LOAD |
			 ICE_CGU_R10_SYNCE_S_REF_CLK);
		r10 |= FIELD_PREP(ICE_CGU_R10_SYNCE_S_REF_CLK, first_mux);
		if (clock_1588)
			r10 |= FIELD_PREP(ICE_CGU_R10_SYNCE_ETHCLKO_SEL,
					  ICE_CGU_REF_CLK_BYP0);
		else
			r10 |= FIELD_PREP(ICE_CGU_R10_SYNCE_ETHCLKO_SEL,
					  ICE_CGU_REF_CLK_BYP0_DIV);
		break;
	case ICE_SYNCE_CLK1:
	{
		u32 val;

		ice_read_cgu_reg_or_die(hw, ICE_CGU_R11, &val);
		val &= ~ICE_CGU_R11_SYNCE_S_BYP_CLK;
		val |= FIELD_PREP(ICE_CGU_R11_SYNCE_S_BYP_CLK, first_mux);
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R11, val);
		r10 &= ~(ICE_CGU_R10_SYNCE_CLKODIV_LOAD |
			 ICE_CGU_R10_SYNCE_CLKO_SEL);
		if (clock_1588)
			r10 |= FIELD_PREP(ICE_CGU_R10_SYNCE_CLKO_SEL,
					  ICE_CGU_REF_CLK_BYP1);
		else
			r10 |= FIELD_PREP(ICE_CGU_R10_SYNCE_CLKO_SEL,
					  ICE_CGU_REF_CLK_BYP1_DIV);
		break;
	}
	default:
		return -EINVAL;
	}

	ice_write_cgu_reg_or_die(hw, ICE_CGU_R10, r10);

	return 0;
}

/**
 * ice_tspll_get_div_e825c - get the divider for the given speed
 * @link_speed: link speed of the port
 * @divider: output value, calculated divider
 */
static int ice_tspll_get_div_e825c(u16 link_speed, u8 *divider)
{
	switch (link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
	case ICE_AQ_LINK_SPEED_50GB:
	case ICE_AQ_LINK_SPEED_25GB:
		*divider = 10;
		break;
	case ICE_AQ_LINK_SPEED_40GB:
	case ICE_AQ_LINK_SPEED_10GB:
		*divider = 4;
		break;
	case ICE_AQ_LINK_SPEED_5GB:
	case ICE_AQ_LINK_SPEED_2500MB:
	case ICE_AQ_LINK_SPEED_1000MB:
		*divider = 2;
		break;
	case ICE_AQ_LINK_SPEED_100MB:
		*divider = 1;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

/**
 * ice_tspll_cfg_synce_ethdiv_e825c - set the divider on the mux
 * @hw: Pointer to the HW struct
 * @divider: Output parameter, returns used divider value
 * @output: Output pin, we have two in E825C
 */
int ice_tspll_cfg_synce_ethdiv_e825c(struct ice_hw *hw, u8 *divider,
				     enum ice_synce_clk output)
{
	u16 link_speed;
	u32 val;
	int err;

	link_speed = hw->port_info->phy.link_info.link_speed;
	if (!link_speed)
		return 0;

	err = ice_tspll_get_div_e825c(link_speed, divider);
	if (err)
		return err;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R10, &val);

	/* programmable divider value (from 2 to 16) minus 1 for ETHCLKOUT */
	switch (output) {
	case ICE_SYNCE_CLK0:
		val &= ~(ICE_CGU_R10_SYNCE_ETHDIV_M1 |
			 ICE_CGU_R10_SYNCE_ETHDIV_LOAD);
		val |= FIELD_PREP(ICE_CGU_R10_SYNCE_ETHDIV_M1, *divider - 1);
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R10, val);
		val |= ICE_CGU_R10_SYNCE_ETHDIV_LOAD;
		break;
	case ICE_SYNCE_CLK1:
		val &= ~(ICE_CGU_R10_SYNCE_CLKODIV_M1 |
			 ICE_CGU_R10_SYNCE_CLKODIV_LOAD);
		val |= FIELD_PREP(ICE_CGU_R10_SYNCE_CLKODIV_M1, *divider - 1);
		ice_write_cgu_reg_or_die(hw, ICE_CGU_R10, val);
		val |= ICE_CGU_R10_SYNCE_CLKODIV_LOAD;
		break;
	default:
		return -EINVAL;
	}

	ice_write_cgu_reg_or_die(hw, ICE_CGU_R10, val);

	return 0;
}

/**
 * ice_tspll_ena_pps_out_e825c - Enable/disable 1PPS output and set amplitude
 * @hw: Pointer to the HW struct
 * @ena: Enable/disable 1PPS output
 */
int ice_tspll_ena_pps_out_e825c(struct ice_hw *hw, bool ena)
{
	u32 val;

	ice_read_cgu_reg_or_die(hw, ICE_CGU_R9, &val);
	val &= ~(ICE_CGU_R9_ONE_PPS_OUT_EN | ICE_CGU_R9_ONE_PPS_OUT_AMP);
	val |= FIELD_PREP(ICE_CGU_R9_ONE_PPS_OUT_EN, ena) |
	       ICE_CGU_R9_ONE_PPS_OUT_AMP;
	ice_write_cgu_reg_or_die(hw, ICE_CGU_R9, val);

	return 0;
}

/**
 * ice_tspll_cfg - Configure the Clock Generation Unit TSPLL
 * @hw: Pointer to the HW struct
 * @clk_freq: Clock frequency to program
 * @clk_src: Clock source to select (TIME_REF, or TCXO)
 *
 * Configure the Clock Generation Unit with the desired clock frequency and
 * time reference, enabling the TSPLL which drives the PTP hardware clock.
 */
static int ice_tspll_cfg(struct ice_hw *hw, enum ice_tspll_freq clk_freq,
			 enum ice_clk_src clk_src)
{
	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
		return ice_tspll_cfg_e82x(hw, clk_freq, clk_src);
	case ICE_MAC_GENERIC_3K_E825:
		return ice_tspll_cfg_e825c(hw, clk_freq, clk_src);
	default:
		return -1;
	}
}

/**
 * ice_tspll_dis_sticky_bits - disable TSPLL sticky bits
 * @hw: Pointer to the HW struct
 *
 * Configure the Clock Generation Unit TSPLL sticky bits so they don't latch on
 * losing TSPLL lock, but always show current state.
 */
static int ice_tspll_dis_sticky_bits(struct ice_hw *hw)
{
	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
		return ice_tspll_dis_sticky_bits_e82x(hw);
	case ICE_MAC_GENERIC_3K_E825:
		return ice_tspll_dis_sticky_bits_e825c(hw);
	default:
		return -1;
	}
}

/**
 * tspll_cfg_store - sysfs interface for setting TSPLL config
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t tspll_cfg_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	u32 tspll_freq, clk_src, src_tmr_mode;
	enum ice_src_tmr_mode tmr_mode;
	enum ice_tspll_freq freq;
	char mode_str[44] = {};
	char arg3_str[16] = {};
	enum ice_clk_src clk;
	struct ice_pf *pf;
	int argc, ret;
	char **argv;

	pf = pci_get_drvdata(pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EAGAIN;

	if (pf->ptp.state != ICE_PTP_READY)
		return -EFAULT;

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;

	if ((pf->hw.mac_type == ICE_MAC_GENERIC && argc != 3) ||
	    (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825 && argc != 2))
		goto command_help;

	ret = kstrtou32(argv[0], 0, &tspll_freq);
	if (ret)
		goto command_help;
	ret = kstrtou32(argv[1], 0, &clk_src);
	if (ret)
		goto command_help;
	if (pf->hw.mac_type == ICE_MAC_GENERIC) {
		ret = kstrtou32(argv[2], 0, &src_tmr_mode);
		if (ret)
			goto command_help;

		tmr_mode = (enum ice_src_tmr_mode)src_tmr_mode;
		strscpy(mode_str,
			"src_tmr_mode: 0 = NS MODE, 1 = LOCKED MODE\n",
			sizeof(mode_str));
		strscpy(arg3_str, " <src_tmr_mode>", sizeof(arg3_str));
	} else {
		tmr_mode = ICE_SRC_TMR_MODE_NANOSECONDS;
	}

	argv_free(argv);
	freq = (enum ice_tspll_freq)tspll_freq;
	clk = (enum ice_clk_src)clk_src;

	if (!ice_tspll_check_params(&pf->hw, freq, clk, tmr_mode))
		return -EINVAL;

	ice_tspll_set_params_e82x(pf, freq, clk, tmr_mode);

	ret = ice_tspll_dis_sticky_bits(&pf->hw);
	if (ret)
		return ret;

	ret = ice_tspll_cfg(&pf->hw, freq, clk);
	if (ret)
		return ret;

	ret = ice_ptp_update_incval(pf, freq, tmr_mode);
	if (ret)
		return ret;

	return len;

command_help:
	argv_free(argv);
	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825)
		dev_info(dev, "Usage: <tspll_freq> <clk_src>%s\ntspll_freq (MHz): 4 = 156.25\nclk_src: 0 = TCXO, 1 = TIME_REF\n%s",
			 arg3_str, mode_str);
	else
		dev_info(dev, "Usage: <tspll_freq> <clk_src>%s\ntspll_freq (MHz): 0 = 25, 1 = 122, 2 = 125, 3 = 153, 4 = 156.25, 5 = 245.76\nclk_src: 0 = TCXO, 1 = TIME_REF\n%s",
			 arg3_str, mode_str);
	return -EIO;
}

#define TSPLL_CFG_BUFF_SIZE 60
/**
 * tspll_cfg_show - sysfs callback for reading tspll_cfg file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t tspll_cfg_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	enum ice_tspll_freq clk_freq;
	enum ice_clk_src clk_src;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	size_t cnt;
	int err;
	u32 val;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	if (!ice_pf_state_is_nominal(pf))
		return -EAGAIN;

	if (pf->ptp.state != ICE_PTP_READY)
		return -EFAULT;

	hw = &pf->hw;

	/* Disable sticky lock detection so lock status reported is accurate */
	err = ice_tspll_dis_sticky_bits(hw);
	if (err)
		return err;

	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825)
		err = ice_read_cgu_reg(hw, ICE_CGU_R23, &val);
	else
		err = ice_read_cgu_reg(hw, ICE_CGU_R24, &val);
	if (err)
		return err;

	clk_src = (enum ice_clk_src)FIELD_GET(ICE_CGU_R23_R24_TIME_REF_SEL,
					      val);

	err = ice_read_cgu_reg(hw, ICE_CGU_R9, &val);
	if (err)
		return err;

	clk_freq = (enum ice_tspll_freq)FIELD_GET(ICE_CGU_R9_TIME_REF_FREQ_SEL,
						  val);

	cnt = snprintf(buf, TSPLL_CFG_BUFF_SIZE, "SW conf: %s %s %s\nTSPLL: %s %s\n",
		       ice_tspll_clk_freq_str(hw->ptp.tspll_freq),
		       ice_tspll_clk_src_str(hw->ptp.clk_src),
		       ice_tspll_src_tmr_mode_str(hw),
		       ice_tspll_clk_freq_str(clk_freq),
		       ice_tspll_clk_src_str(clk_src));

	return cnt;
}

/**
 * ice_tspll_cfg_cgu_err_reporting - Configure CGU error reporting
 * @hw: Pointer to the HW structure
 * @enable: true to enable reporting, false otherwise
 *
 * Enable or disable CGU errors/events to be reported through Admin Queue.
 *
 * Return: 0 on success, negative error code otherwise
 */
int ice_tspll_cfg_cgu_err_reporting(struct ice_hw *hw, bool enable)
{
	int err;

	err = ice_aq_cfg_cgu_err(hw, enable, enable, NULL);
	if (err) {
		ice_debug(hw, ICE_DBG_PTP, "Failed to %s CGU error reporting, err %d\n",
			  enable ? "enable" : "disable", err);
		return err;
	}

	return 0;
}

/**
 * ice_tspll_init - Initialize TSPLL with settings from firmware
 * @hw: Pointer to the HW structure
 *
 * Initialize the Clock Generation Unit of the E82X/E825 device.
 */
int ice_tspll_init(struct ice_hw *hw)
{
	enum ice_tspll_freq tspll_freq = hw->ptp.tspll_freq;
	enum ice_clk_src clk_src = hw->ptp.clk_src;
	int err;

	/* Only E822, E823 and E825 products support TSPLL */
	if (hw->mac_type != ICE_MAC_GENERIC &&
	    hw->mac_type != ICE_MAC_GENERIC_3K_E825)
		return 0;

	/* Disable sticky lock detection so lock status reported is accurate */
	err = ice_tspll_dis_sticky_bits(hw);
	if (err)
		return err;

	/* Configure the TSPLL using the parameters from the function
	 * capabilities.
	 */
	if (!ice_tspll_check_params(hw, tspll_freq, clk_src,
				    ICE_SRC_TMR_MODE_NANOSECONDS))
		return -EINVAL;

	err = ice_tspll_cfg(hw, tspll_freq, clk_src);
	if (err) {
		dev_warn(ice_hw_to_dev(hw), "Failed to lock TSPLL to predefined frequency. Retrying with fallback frequency.\n");

		/* Try to lock to internal TCXO as a fallback */
		if (hw->mac_type == ICE_MAC_GENERIC_3K_E825)
			tspll_freq = ICE_TSPLL_FREQ_156_250;
		else
			tspll_freq = ICE_TSPLL_FREQ_25_000;
		clk_src = ICE_CLK_SRC_TCXO;
		err = ice_tspll_cfg(hw, tspll_freq, clk_src);
		if (err)
			dev_warn(ice_hw_to_dev(hw), "Failed to lock TSPLL to fallback frequency.\n");
	}

	if (!err && hw->mac_type == ICE_MAC_GENERIC)
		ice_tspll_cfg_cgu_err_reporting(hw, true);

	return err;
}

/**
 * ice_tspll_process_cgu_err - Handle reported CGU error
 * @hw: pointer to HW struct
 * @event: reported CGU error descriptor
 */
void ice_tspll_process_cgu_err(struct ice_hw *hw,
			       struct ice_rq_event_info *event)
{
	u8 err_type = event->desc.params.cgu_err.err_type;
	enum ice_tspll_freq tspll_freq = hw->ptp.tspll_freq;
	enum ice_clk_src clk_src = hw->ptp.clk_src;

	if (err_type & ICE_AQC_CGU_ERR_SYNCE_LOCK_LOSS)
		ice_debug(hw, ICE_DBG_PTP, "SyncE lock lost\n");

	if (err_type & ICE_AQC_CGU_ERR_HOLDOVER_CHNG)
		ice_debug(hw, ICE_DBG_PTP, "SyncE holdover change\n");
	if (err_type & ICE_AQC_CGU_ERR_TIMESYNC_LOCK_LOSS) {
		dev_warn(ice_hw_to_dev(hw), "TimeSync PLL lock lost. Retrying to acquire lock with default PLL configuration.\n");
		if (ice_tspll_cfg(hw, tspll_freq, clk_src))
			return;
	}

	/* Re-enable CGU error reporting */
	ice_tspll_cfg_cgu_err_reporting(hw, true);
}
