/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_TSPLL_H_
#define _ICE_TSPLL_H_

/**
 * struct ice_tspll_params_e82x
 * @refclk_pre_div: Reference clock pre-divisor
 * @feedback_div: Feedback divisor
 * @frac_n_div: Fractional divisor
 * @post_pll_div: Post PLL divisor
 *
 * Clock Generation Unit parameters used to program the PLL based on the
 * selected TIME_REF/TCXO frequency.
 */
struct ice_tspll_params_e82x {
	u32 refclk_pre_div;
	u32 feedback_div;
	u32 frac_n_div;
	u32 post_pll_div;
};

/**
 * struct ice_tspll_params_e825c
 * @ck_refclkfreq: TSPLL reference clock frequency selection
 * @ndivratio: ndiv ratio that goes directly to the TSPLL
 * @fbdiv_intgr: TSPLL integer feedback divide
 * @fbdiv_frac: TSPLL fractional feedback divide
 *
 * Clock Generation Unit parameters used to program the PLL based on the
 * selected TIME_REF/TCXO frequency.
 */
struct ice_tspll_params_e825c {
	u32 ck_refclkfreq;
	u32 ndivratio;
	u32 fbdiv_intgr;
	u32 fbdiv_frac;
};

#define ICE_CGU_R9				0x24
#define ICE_CGU_R9_TIME_REF_FREQ_SEL		GENMASK(2, 0)
#define ICE_CGU_R9_CLK_EREF0_EN			BIT(4)
#define ICE_CGU_R9_TIME_REF_EN			BIT(5)
#define ICE_CGU_R9_TIME_SYNC_EN			BIT(6)
#define ICE_CGU_R9_ONE_PPS_OUT_EN		BIT(7)
#define ICE_CGU_R9_ONE_PPS_OUT_AMP		GENMASK(19, 18)

#define ICE_CGU_R10				0x28
#define ICE_CGU_R10_SYNCE_CLKO_SEL		GENMASK(8, 5)
#define ICE_CGU_R10_SYNCE_CLKODIV_M1		GENMASK(13, 9)
#define ICE_CGU_R10_SYNCE_CLKODIV_LOAD		BIT(14)
#define ICE_CGU_R10_SYNCE_DCK_RST		BIT(15)
#define ICE_CGU_R10_SYNCE_ETHCLKO_SEL		GENMASK(18, 16)
#define ICE_CGU_R10_SYNCE_ETHDIV_M1		GENMASK(23, 19)
#define ICE_CGU_R10_SYNCE_ETHDIV_LOAD		BIT(24)
#define ICE_CGU_R10_SYNCE_DCK2_RST		BIT(25)
#define ICE_CGU_R10_SYNCE_S_REF_CLK		GENMASK(31, 27)

#define ICE_CGU_R11				0x2C
#define ICE_CGU_R11_SYNCE_S_BYP_CLK		GENMASK(6, 1)

#define ICE_CGU_R16				0x40
#define ICE_CGU_R16_TSPLL_CK_REFCLKFREQ		GENMASK(31, 24)

#define ICE_CGU_R19				0x4C
#define ICE_CGU_R19_TSPLL_FBDIV_INTGR_E82X	GENMASK(7, 0)
#define ICE_CGU_R19_TSPLL_FBDIV_INTGR_E825	GENMASK(9, 0)
#define ICE_CGU_R19_TSPLL_NDIVRATIO		GENMASK(19, 16)

#define ICE_CGU_R22				0x58
#define ICE_CGU_R22_TIME1588CLK_DIV		GENMASK(23, 20)
#define ICE_CGU_R22_TIME1588CLK_SEL_DIV2	BIT(30)

#define ICE_CGU_R23				0x5C

#define ICE_CGU_R24				0x60
#define ICE_CGU_R24_E82X_TSPLL_FBDIV_FRAC	GENMASK(21, 0)
#define ICE_CGU_R23_R24_TSPLL_ENABLE		BIT(24)
#define ICE_CGU_R23_R24_REF1588_CK_DIV		GENMASK(30, 27)
#define ICE_CGU_R23_R24_TIME_REF_SEL		BIT(31)
#define ICE_CGU_R24_ETH56G_FBDIV_FRAC		GENMASK(31, 0)

#define ICE_CGU_BW_TDC				0x31C
#define ICE_CGU_BW_TDC_PLLLOCK_SEL		GENMASK(30, 29)

#define ICE_CGU_RO_LOCK				0x3F0
#define ICE_CGU_RO_LOCK_TRUE_LOCK		BIT(12)
#define ICE_CGU_RO_LOCK_UNLOCK			BIT(13)

#define ICE_CGU_CNTR_BIST			0x344
#define ICE_CGU_CNTR_BIST_PLLLOCK_SEL_0		BIT(15)
#define ICE_CGU_CNTR_BIST_PLLLOCK_SEL_1		BIT(16)

#define ICE_CGU_RO_BWM_LF			0x370
#define ICE_CGU_RO_BWM_LF_TRUE_LOCK		BIT(12)

void ice_tspll_sysfs_init(struct ice_hw *hw);
void ice_tspll_sysfs_release(struct ice_hw *hw);
u64 ice_tspll_ticks2ns(const struct ice_hw *hw, u64 ticks);
u64 ice_tspll_ns2ticks(const struct ice_hw *hw, u64 ns);
int ice_tspll_monitor_lock_e825c(struct ice_hw *hw);
int ice_tspll_bypass_mux_active_e825c(struct ice_hw *hw, u8 port, bool *active,
				      enum ice_synce_clk output);
int ice_tspll_cfg_bypass_mux_e825c(struct ice_hw *hw, u8 port,
				   enum ice_synce_clk output,
				   bool clock_1588, unsigned int ena);
int ice_tspll_cfg_synce_ethdiv_e825c(struct ice_hw *hw, u8 *divider,
				     enum ice_synce_clk output);
int ice_tspll_ena_pps_out_e825c(struct ice_hw *hw, bool ena);
int ice_tspll_cfg_cgu_err_reporting(struct ice_hw *hw, bool enable);
int ice_tspll_init(struct ice_hw *hw);
void ice_tspll_process_cgu_err(struct ice_hw *hw,
			       struct ice_rq_event_info *event);
#endif /* _ICE_TSPLL_H_ */
