/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_CGU_OPS_H_
#define _ICE_CGU_OPS_H_

#define ICE_CGU_LOCK_CHECK_DELAY_USEC        256000	/* 256 msec */

/* fast mode lock check settings */
#define ICE_CGU_EDPLL_FAST_LOCK_DELAY_LOOPS     239	/* 60 seconds total */
#define ICE_CGU_TDPLL_FAST_LOCK_DELAY_LOOPS      25	/* 5 seconds total */

/* normal mode lock check settings */
#define ICE_CGU_EDPLL_NORMAL_LOCK_DELAY_LOOPS    52	/* 12 seconds total */
#define ICE_CGU_TDPLL_NORMAL_LOCK_DELAY_LOOPS    13	/* 2 seconds total */

/* number of consecutive locks to declare DPLL lock */
#define ICE_CGU_DPLL_LOCK_COUNT 5

#define ICE_CGU_CORE_CLOCK_MHZ 800
#define ICE_CGU_DPLL_FREQ_MHZ 25

/* DPLL lock/unlock threshold */
#define ICE_CGU_TRANSPORT_DPLL_LOCK_THRESHOLD_800MHZ    0x2D8
#define ICE_CGU_TRANSPORT_DPLL_UNLOCK_THRESHOLD_800MHZ  0x3640
#define ICE_CGU_ECC_DPLL_LOCK_THRESHOLD_800MHZ          0x5A
#define ICE_CGU_ECC_DPLL_UNLOCK_THRESHOLD_800MHZ        0x21E8

/* time to hold enable bits low to perform a JAPLL reset */
#define ICE_CGU_JAPLL_RESET_TIME_USEC 1

/* LCPLL lock alone (FDPLL disabled) should take < 10 usec */
#define ICE_CGU_LCPLL_LOCK_CHECK_DELAY_USEC 1
#define ICE_CGU_LCPLL_LOCK_DELAY_LOOPS 10

/* FDPLL lock time in fast mode is around 500 msec;
 * use poll interval of 100ms, max poll time 5 seconds
 * (max poll time was originally 2 seconds, increased
 * to 5 to avoid occasional poll timeouts.)
 */
#define ICE_CGU_FDPLL_LOCK_CHECK_DELAY_USEC 100000
#define ICE_CGU_FDPLL_LOCK_DELAY_LOOPS 50
#define ICE_CGU_FDPLL_ACQ_TOGGLE_LOOPS 2


/* valid values for enum ice_cgu_clko_sel */
#define ICE_CGU_CLKO_SEL_VALID_BITMAP \
	(BIT(ICE_CGU_CLKO_SEL_REF_CLK_BYP0_DIV) | \
	 BIT(ICE_CGU_CLKO_SEL_REF_CLK_BYP1_DIV) | \
	 BIT(ICE_CGU_CLKO_SEL_CLK_SYS_DIV) | \
	 BIT(ICE_CGU_CLKO_SEL_CLK_JAPLL_625000_DIV) | \
	 BIT(ICE_CGU_CLKO_SEL_REF_CLK_BYP0) | \
	 BIT(ICE_CGU_CLKO_SEL_REF_CLK_BYP1) | \
	 BIT(ICE_CGU_CLKO_SEL_CLK_1544) | \
	 BIT(ICE_CGU_CLKO_SEL_CLK_2048))

/* Only FW can read NAC_CGU_DWORD8 where these are defined, so they are exposed
 * to the driver stack via soft straps in the misc24 field of NAC_CGU_DWORD9.
 */
#define MISC24_BIT_TCXO_FREQ_SEL_M	BIT(0)
#define MISC24_BIT_TCXO_SEL_M		BIT(4)

/* internal structure definitions */

enum ice_cgu_sample_rate {
	ICE_CGU_SAMPLE_RATE_8K = 0,	/* 8 KHz sample rate */
	ICE_CGU_SAMPLE_RATE_10K,	/* 10 KHz sample rate */
	ICE_CGU_SAMPLE_RATE_12K5,	/* 12.5 KHz sample rate */

	NUM_ICE_CGU_SAMPLE_RATE
};

struct ice_cgu_div_rat_m1 {
	u32 ref_clk_rate;	/* reference clock rate in kHz */
	u32 div_rat_m1;		/* div_rat_m1 value */
};

struct ice_cgu_dpll_params {
	enum ice_cgu_dpll_select dpll_select;
	enum ice_cgu_sample_rate sample_rate;
	u32 mul_rat_m1;
	u32 scale;
	u32 gain;
};

struct ice_cgu_dpll_per_rate_params {
	u32 rate_hz;
	enum ice_cgu_sample_rate sample_rate;
	u32 div_rat_m1;
	u32 synce_rat_sel;
};

struct ice_cgu_lcpll_per_rate_params {
	u32 refclk_pre_div;
	u32 feedback_div;
	u32 frac_n_div;
	u32 post_pll_div;
};

/* Function to init internal state */
void ice_cgu_init_state(struct ice_pf *pf);

/* Function to configure TS PLL */
int
ice_cgu_cfg_ts_pll(struct ice_pf *pf, bool enable, enum ice_time_ref_freq time_ref_freq,
		   enum ice_cgu_time_ref_sel time_ref_sel, enum ice_mstr_tmr_mode mstr_tmr_mode);
#endif /* _ICE_CGU_OPS_H_ */
