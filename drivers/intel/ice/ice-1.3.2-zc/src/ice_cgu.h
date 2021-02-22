/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_CGU_H_
#define _ICE_CGU_H_

#include <linux/types.h>
#include "ice_cgu_regs.h"

/* CGU mux identifier
 * Specifies a mux within the CGU block.
 */
enum ice_cgu_mux_sel {
	/* CGU reference clock source (DWORD10_SYNCE_S_REF_CLK) */
	ICE_CGU_MUX_SEL_REF_CLK,
	/* CGU bypass clock source (DWORD11_SYNCE_S_BYP_CLK) */
	ICE_CGU_MUX_SEL_BYPASS_CLK,
	/* CGU ETHCLKO pin source (DWORD10_SYNCE_ETHCLKO_SEL) */
	ICE_CGU_MUX_SEL_ETHCLKO,
	/* CGU CLKO pin source (DWORD10_SYNCE_CLKO_SEL) */
	ICE_CGU_MUX_SEL_CLKO,

	NUM_ICE_CGU_MUX_SEL
};

/* CGU reference clock specification
 * Specifies the source for the CGU reference/bypass clock.
 */
enum ice_cgu_clk_src {
	/* network reference clock 0 */
	ICE_CGU_CLK_SRC_NET_REF_CLK0,
	/* network reference clock 1 */
	ICE_CGU_CLK_SRC_NET_REF_CLK1,
	/* 1588 recovered clock */
	ICE_CGU_CLK_SRC_1588_RECOVERED_CLK,
	/* recovered clock from phys port 0 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_0,
	/* recovered clock from phys port 1 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_1,
	/* recovered clock from phys port 2 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_2,
	/* recovered clock from phys port 3 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_3,
	/* recovered clock from phys port 4 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_4,
	/* recovered clock from phys port 5 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_5,
	/* recovered clock from phys port 6 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_6,
	/* recovered clock from phys port 7 */
	ICE_CGU_CLK_SRC_SYNCE_CLK_7,
	NUM_ICE_CGU_CLK_SRC
};

/* Sources for ETHCLKO pin */
enum ice_cgu_ethclko_sel {
	/* DPLL reference clock 0 input divided by ETHDIV */
	ICE_CGU_ETHCLKO_SEL_REF_CLK_BYP0_DIV,
	/* DPLL reference clock 1 input divided by ETHDIV */
	ICE_CGU_ETHCLKO_SEL_REF_CLK_BYP1_DIV,
	/* DPLL output clock divided by ETHDIV */
	ICE_CGU_ETHCLKO_SEL_CLK_PLL_25000_DIV,
	/* JAPLL output clock divided by ETHDIV */
	ICE_CGU_ETHCLKO_SEL_CLK_JAPLL_625000_DIV,
	/* DPLL reference clock 0 input */
	ICE_CGU_ETHCLKO_SEL_REF_CLK_BYP0,
	/* DPLL reference clock 1 input */
	ICE_CGU_ETHCLKO_SEL_REF_CLK_BYP1,
	/* DPLL output clock */
	ICE_CGU_ETHCLKO_SEL_CLK_PLL_25000,
	ICE_CGU_ETHCLKO_SEL_CLK_JAPLL_625000,

	NUM_ICE_CGU_ETHCLKO_SEL
};

#define ICE_CGU_ETHCLKO_SEL_NRCKI ICE_CGU_ETHCLKO_SEL_REF_CLK_BYP1

/* Sources for CLKO pin */
enum ice_cgu_clko_sel {
	/* DPLL reference clock 0 input divided by CLKODIV */
	ICE_CGU_CLKO_SEL_REF_CLK_BYP0_DIV,
	/* DPLL reference clock 1 input divided by CLKODIV */
	ICE_CGU_CLKO_SEL_REF_CLK_BYP1_DIV,
	/* DPLL core clock divided by CLKODIV */
	ICE_CGU_CLKO_SEL_CLK_SYS_DIV,
	/* JAPLL output clock divided by CLKODIV */
	ICE_CGU_CLKO_SEL_CLK_JAPLL_625000_DIV,
	/* DPLL reference clock 0 input */
	ICE_CGU_CLKO_SEL_REF_CLK_BYP0,
	/* DPLL reference clock 1 input */
	ICE_CGU_CLKO_SEL_REF_CLK_BYP1,

	/* 1.544 MHz, NRCP divider output */
	ICE_CGU_CLKO_SEL_CLK_1544 = 8,
	/* 2.048 MHz, NRCP divider output */
	ICE_CGU_CLKO_SEL_CLK_2048 = 9,

	NUM_ICE_CGU_CLKO_SEL
};

#define ICE_CGU_CLKO_SEL_NRCKI ICE_CGU_CLKO_SEL_REF_CLK_BYP1

/* TIME_REF source selection */
enum ice_cgu_time_ref_sel {
	ICE_CGU_TIME_REF_SEL_TCXO, /* Use TCXO source */
	ICE_CGU_TIME_REF_SEL_TIME_REF, /* Use TIME_REF source */

	NUM_ICE_CGU_TIME_REF_SEL
};

/* Macro to convert an enum ice_time_ref_freq to a string for printing */
#define ICE_TIME_REF_FREQ_TO_STR(__trf)                              \
	({                                                           \
		enum ice_time_ref_freq _trf = (__trf);               \
		(_trf) == ICE_TIME_REF_FREQ_25_000 ? "25 MHz" :      \
		(_trf) == ICE_TIME_REF_FREQ_122_880 ? "122.88 MHz" : \
		(_trf) == ICE_TIME_REF_FREQ_125_000 ? "125 MHz" :    \
		(_trf) == ICE_TIME_REF_FREQ_153_600 ? "153.6 MHz" :  \
		(_trf) == ICE_TIME_REF_FREQ_156_250 ? "156.25 MHz" : \
		(_trf) == ICE_TIME_REF_FREQ_245_760 ? "245.76 MHz" : \
		"invalid"; \
	})

/* Macro to convert an enum ice_cgu_time_ref_sel to a string for printing */
#define ICE_TIME_REF_SEL_TO_STR(__trs)                                 \
	({                                                             \
		enum ice_cgu_time_ref_sel _trs = (__trs);              \
		(_trs) == ICE_CGU_TIME_REF_SEL_TCXO ? "TCXO" :         \
		(_trs) == ICE_CGU_TIME_REF_SEL_TIME_REF ? "TIME_REF" : \
		"invalid"; \
	})
/* Macro to convert an enum ice_mstr_tmr_mode to a string for printing */
#define ICE_MSTR_TMR_MODE_TO_STR(__mtm)                                    \
	({                                                                 \
		enum ice_mstr_tmr_mode _mtm = (__mtm);                     \
		(_mtm) == ICE_MSTR_TMR_MODE_NANOSECONDS ? "nanoseconds" :  \
		(_mtm) == ICE_MSTR_TMR_MODE_LOCKED ? "locked" :            \
		"invalid"; \
	})

/* DPLL select */
enum ice_cgu_dpll_select {
	/* DPLL (DPLL1) */
	ICE_CGU_DPLL_SELECT_TRANSPORT,
	/* EEC DPLL (DPLL2), 0x098 Hz BW */
	ICE_CGU_DPLL_SELECT_EEC_RELAXED_BW,

	NUM_ICE_CGU_DPLL_SELECT
};

/* DPLL holdover mode */
enum ice_cgu_dpll_holdover_mode {
	/* previous acquired frequency */
	ICE_CGU_DPLL_HOLDOVER_MODE_ACQUIRED_FREQ,
	/* local frequency (free run) */
	ICE_CGU_DPLL_HOLDOVER_MODE_LOCAL_FREQ,

	NUM_ICE_CGU_DPLL_HOLDOVER_MODE
};

/* DPLL configuration parameters */
struct ice_cgu_dpll_cfg {
	/* CGU reference clock frequency */
	enum ice_time_ref_freq ref_freq;
	/* select DPLL */
	enum ice_cgu_dpll_select dpll_sel;
	/* enable holdover feature support */
	u32 holdover_support;
	/* select holdover mode */
	enum ice_cgu_dpll_holdover_mode holdover_mode;
};

enum ice_japll_ref_freq {
	ICE_CGU_JAPLL_REF_FREQ_25_000, /* 25 MHz */
	ICE_CGU_JAPLL_REF_FREQ_156_250, /* 156.25 MHz */

	NUM_ICE_CGU_JAPLL_REF_FREQ
};

/* Mux configuration parameters */
struct ice_cgu_mux_cfg {
	/* reference clock source select */
	enum ice_cgu_clk_src ref_clk_src;
	/* bypass clock source select */
	enum ice_cgu_clk_src byp_clk_src;
	/* ETHCLKO pin source select */
	enum ice_cgu_ethclko_sel eth_clk_out;
	/* CLKO pin source select */
	enum ice_cgu_clko_sel clk_out;
	/* CLKO programmable divider */
	__u8 clk_out_div;
	/* ETHCLKO programmable divider */
	__u8 eth_clk_out_div;
	/* bypass DPLL */
	u32 bypass;
	/* tie refClk to ground (force holdover mode) */
	u32 ref_clk_gnd_ena;
};

/* CGU event was triggered by SyncE loss of lock */
#define ICE_CGU_EVENT_ERR_SYNCE_LOCK_LOSS 0x1

/* CGU event was triggered by SyncE holdover change */
#define ICE_CGU_EVENT_ERR_HOLDOVER_CHNG 0x2

/* CGU event was triggered by timestamp PLL loss of lock */
#define ICE_CGU_EVENT_ERR_TIMESYNC_LOCK_LOSS 0x4


struct ice_cgu_info {
	struct ice_cgu_dpll_cfg dpll_cfg;
	struct ice_cgu_mux_cfg mux_cfg;
	enum ice_japll_ref_freq japll_ref_freq;
	wait_queue_head_t wq_head;

	/* used to synchronize waiters (only one at a time) */
	struct mutex event_mutex;

	u32 event_occurred;
	u8 err_type;
	u8 unlock_event;

	/* current state of 1588 output to CGU */
	u8 out_1588_enabled;
	enum ice_time_ref_freq out_1588_ref_freq;

	enum ice_time_ref_freq time_ref_freq;
	enum ice_mstr_tmr_mode mstr_tmr_mode;
};

#endif /* _ICE_CGU_H_ */
