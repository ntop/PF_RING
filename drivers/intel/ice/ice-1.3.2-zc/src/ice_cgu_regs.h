/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_CGU_REGS_H_
#define _ICE_CGU_REGS_H_

#include "ice_osdep.h"

#define NAC_CGU_DWORD8 0x20
#define NAC_CGU_DWORD8_TCXO_FREQ_SEL_S 0
#define NAC_CGU_DWORD8_TCXO_FREQ_SEL_M BIT(0)
#define NAC_CGU_DWORD8_MISC8_S 1
#define NAC_CGU_DWORD8_MISC8_M ICE_M(0x7, 1)
#define NAC_CGU_DWORD8_HLP_SWITCH_FREQ_SEL_S 4
#define NAC_CGU_DWORD8_HLP_SWITCH_FREQ_SEL_M ICE_M(0xf, 4)
#define NAC_CGU_DWORD8_CGUPLL_NDIVRATIO_S 8
#define NAC_CGU_DWORD8_CGUPLL_NDIVRATIO_M ICE_M(0xf, 8)
#define NAC_CGU_DWORD8_CGUPLL_IREF_NDIVRATIO_S 12
#define NAC_CGU_DWORD8_CGUPLL_IREF_NDIVRATIO_M ICE_M(0x7, 12)
#define NAC_CGU_DWORD8_MISC28_S 15
#define NAC_CGU_DWORD8_MISC28_M BIT(15)
#define NAC_CGU_DWORD8_HLPPLL_NDIVRATIO_S 16
#define NAC_CGU_DWORD8_HLPPLL_NDIVRATIO_M ICE_M(0xf, 16)
#define NAC_CGU_DWORD8_HLPPLL_IREF_NDIVRATIO_S 20
#define NAC_CGU_DWORD8_HLPPLL_IREF_NDIVRATIO_M ICE_M(0x7, 20)
#define NAC_CGU_DWORD8_MISC29_S 23
#define NAC_CGU_DWORD8_MISC29_M BIT(23)
#define NAC_CGU_DWORD8_CLK_EREF1_EN_SELFBIAS_S 24
#define NAC_CGU_DWORD8_CLK_EREF1_EN_SELFBIAS_M BIT(24)
#define NAC_CGU_DWORD8_CLK_EREF0_EN_SELFBIAS_S 25
#define NAC_CGU_DWORD8_CLK_EREF0_EN_SELFBIAS_M BIT(25)
#define NAC_CGU_DWORD8_TIME_REF_EN_SELFBIAS_S 26
#define NAC_CGU_DWORD8_TIME_REF_EN_SELFBIAS_M BIT(26)
#define NAC_CGU_DWORD8_TIME_SYNC_EN_SELFBIAS_S 27
#define NAC_CGU_DWORD8_TIME_SYNC_EN_SELFBIAS_M BIT(27)
#define NAC_CGU_DWORD8_CLK_REF_SYNC_E_EN_SELFBIAS_S 28
#define NAC_CGU_DWORD8_CLK_REF_SYNC_E_EN_SELFBIAS_M BIT(28)
#define NAC_CGU_DWORD8_NET_CLK_REF1_EN_SELFBIAS_S 29
#define NAC_CGU_DWORD8_NET_CLK_REF1_EN_SELFBIAS_M BIT(29)
#define NAC_CGU_DWORD8_NET_CLK_REF0_EN_SELFBIAS_S 30
#define NAC_CGU_DWORD8_NET_CLK_REF0_EN_SELFBIAS_M BIT(30)
#define NAC_CGU_DWORD8_TCXO_SEL_S 31
#define NAC_CGU_DWORD8_TCXO_SEL_M BIT(31)

union nac_cgu_dword8 {
	struct {
		u32 tcxo_freq_sel : 1;
		u32 misc8 : 3;
		u32 hlp_switch_freq_sel : 4;
		u32 cgupll_ndivratio : 4;
		u32 cgupll_iref_ndivratio : 3;
		u32 misc28 : 1;
		u32 hlppll_ndivratio : 4;
		u32 hlppll_iref_ndivratio : 3;
		u32 misc29 : 1;
		u32 clk_eref1_en_selfbias : 1;
		u32 clk_eref0_en_selfbias : 1;
		u32 time_ref_en_selfbias : 1;
		u32 time_sync_en_selfbias : 1;
		u32 clk_ref_sync_e_en_selfbias : 1;
		u32 net_clk_ref1_en_selfbias : 1;
		u32 net_clk_ref0_en_selfbias : 1;
		u32 tcxo_sel : 1;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD9 0x24
#define NAC_CGU_DWORD9_TIME_REF_FREQ_SEL_S 0
#define NAC_CGU_DWORD9_TIME_REF_FREQ_SEL_M ICE_M(0x7, 0)
#define NAC_CGU_DWORD9_CLK_EREF1_EN_S 3
#define NAC_CGU_DWORD9_CLK_EREF1_EN_M BIT(3)
#define NAC_CGU_DWORD9_CLK_EREF0_EN_S 4
#define NAC_CGU_DWORD9_CLK_EREF0_EN_M BIT(4)
#define NAC_CGU_DWORD9_TIME_REF_EN_S 5
#define NAC_CGU_DWORD9_TIME_REF_EN_M BIT(5)
#define NAC_CGU_DWORD9_TIME_SYNC_EN_S 6
#define NAC_CGU_DWORD9_TIME_SYNC_EN_M BIT(6)
#define NAC_CGU_DWORD9_ONE_PPS_OUT_EN_S 7
#define NAC_CGU_DWORD9_ONE_PPS_OUT_EN_M BIT(7)
#define NAC_CGU_DWORD9_CLK_REF_SYNCE_EN_S 8
#define NAC_CGU_DWORD9_CLK_REF_SYNCE_EN_M BIT(8)
#define NAC_CGU_DWORD9_CLK_SYNCE1_EN_S 9
#define NAC_CGU_DWORD9_CLK_SYNCE1_EN_M BIT(9)
#define NAC_CGU_DWORD9_CLK_SYNCE0_EN_S 10
#define NAC_CGU_DWORD9_CLK_SYNCE0_EN_M BIT(10)
#define NAC_CGU_DWORD9_NET_CLK_REF1_EN_S 11
#define NAC_CGU_DWORD9_NET_CLK_REF1_EN_M BIT(11)
#define NAC_CGU_DWORD9_NET_CLK_REF0_EN_S 12
#define NAC_CGU_DWORD9_NET_CLK_REF0_EN_M BIT(12)
#define NAC_CGU_DWORD9_CLK_SYNCE1_AMP_S 13
#define NAC_CGU_DWORD9_CLK_SYNCE1_AMP_M ICE_M(0x3, 13)
#define NAC_CGU_DWORD9_MISC6_S 15
#define NAC_CGU_DWORD9_MISC6_M BIT(15)
#define NAC_CGU_DWORD9_CLK_SYNCE0_AMP_S 16
#define NAC_CGU_DWORD9_CLK_SYNCE0_AMP_M ICE_M(0x3, 16)
#define NAC_CGU_DWORD9_ONE_PPS_OUT_AMP_S 18
#define NAC_CGU_DWORD9_ONE_PPS_OUT_AMP_M ICE_M(0x3, 18)
#define NAC_CGU_DWORD9_MISC24_S 20
#define NAC_CGU_DWORD9_MISC24_M ICE_M(0xfff, 20)

union nac_cgu_dword9 {
	struct {
		u32 time_ref_freq_sel : 3;
		u32 clk_eref1_en : 1;
		u32 clk_eref0_en : 1;
		u32 time_ref_en : 1;
		u32 time_sync_en : 1;
		u32 one_pps_out_en : 1;
		u32 clk_ref_synce_en : 1;
		u32 clk_synce1_en : 1;
		u32 clk_synce0_en : 1;
		u32 net_clk_ref1_en : 1;
		u32 net_clk_ref0_en : 1;
		u32 clk_synce1_amp : 2;
		u32 misc6 : 1;
		u32 clk_synce0_amp : 2;
		u32 one_pps_out_amp : 2;
		u32 misc24 : 12;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD10 0x28
#define NAC_CGU_DWORD10_JA_PLL_ENABLE_S 0
#define NAC_CGU_DWORD10_JA_PLL_ENABLE_M BIT(0)
#define NAC_CGU_DWORD10_MISC11_S 1
#define NAC_CGU_DWORD10_MISC11_M BIT(1)
#define NAC_CGU_DWORD10_FDPLL_ENABLE_S 2
#define NAC_CGU_DWORD10_FDPLL_ENABLE_M BIT(2)
#define NAC_CGU_DWORD10_FDPLL_SLOW_S 3
#define NAC_CGU_DWORD10_FDPLL_SLOW_M BIT(3)
#define NAC_CGU_DWORD10_FDPLL_LOCK_INT_ENB_S 4
#define NAC_CGU_DWORD10_FDPLL_LOCK_INT_ENB_M BIT(4)
#define NAC_CGU_DWORD10_SYNCE_CLKO_SEL_S 5
#define NAC_CGU_DWORD10_SYNCE_CLKO_SEL_M ICE_M(0xf, 5)
#define NAC_CGU_DWORD10_SYNCE_CLKODIV_M1_S 9
#define NAC_CGU_DWORD10_SYNCE_CLKODIV_M1_M ICE_M(0x1f, 9)
#define NAC_CGU_DWORD10_SYNCE_CLKODIV_LOAD_S 14
#define NAC_CGU_DWORD10_SYNCE_CLKODIV_LOAD_M BIT(14)
#define NAC_CGU_DWORD10_SYNCE_DCK_RST_S 15
#define NAC_CGU_DWORD10_SYNCE_DCK_RST_M BIT(15)
#define NAC_CGU_DWORD10_SYNCE_ETHCLKO_SEL_S 16
#define NAC_CGU_DWORD10_SYNCE_ETHCLKO_SEL_M ICE_M(0x7, 16)
#define NAC_CGU_DWORD10_SYNCE_ETHDIV_M1_S 19
#define NAC_CGU_DWORD10_SYNCE_ETHDIV_M1_M ICE_M(0x1f, 19)
#define NAC_CGU_DWORD10_SYNCE_ETHDIV_LOAD_S 24
#define NAC_CGU_DWORD10_SYNCE_ETHDIV_LOAD_M BIT(24)
#define NAC_CGU_DWORD10_SYNCE_DCK2_RST_S 25
#define NAC_CGU_DWORD10_SYNCE_DCK2_RST_M BIT(25)
#define NAC_CGU_DWORD10_SYNCE_SEL_GND_S 26
#define NAC_CGU_DWORD10_SYNCE_SEL_GND_M BIT(26)
#define NAC_CGU_DWORD10_SYNCE_S_REF_CLK_S 27
#define NAC_CGU_DWORD10_SYNCE_S_REF_CLK_M ICE_M(0x1f, 27)

union nac_cgu_dword10 {
	struct {
		u32 ja_pll_enable : 1;
		u32 misc11 : 1;
		u32 fdpll_enable : 1;
		u32 fdpll_slow : 1;
		u32 fdpll_lock_int_enb : 1;
		u32 synce_clko_sel : 4;
		u32 synce_clkodiv_m1 : 5;
		u32 synce_clkodiv_load : 1;
		u32 synce_dck_rst : 1;
		u32 synce_ethclko_sel : 3;
		u32 synce_ethdiv_m1 : 5;
		u32 synce_ethdiv_load : 1;
		u32 synce_dck2_rst : 1;
		u32 synce_sel_gnd : 1;
		u32 synce_s_ref_clk : 5;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD11 0x2c
#define NAC_CGU_DWORD11_MISC25_S 0
#define NAC_CGU_DWORD11_MISC25_M BIT(0)
#define NAC_CGU_DWORD11_SYNCE_S_BYP_CLK_S 1
#define NAC_CGU_DWORD11_SYNCE_S_BYP_CLK_M ICE_M(0x3f, 1)
#define NAC_CGU_DWORD11_SYNCE_HDOV_MODE_S 7
#define NAC_CGU_DWORD11_SYNCE_HDOV_MODE_M BIT(7)
#define NAC_CGU_DWORD11_SYNCE_RAT_SEL_S 8
#define NAC_CGU_DWORD11_SYNCE_RAT_SEL_M ICE_M(0x3, 8)
#define NAC_CGU_DWORD11_SYNCE_LINK_ENABLE_S 10
#define NAC_CGU_DWORD11_SYNCE_LINK_ENABLE_M ICE_M(0xfffff, 10)
#define NAC_CGU_DWORD11_SYNCE_MISCLK_EN_S 30
#define NAC_CGU_DWORD11_SYNCE_MISCLK_EN_M BIT(30)
#define NAC_CGU_DWORD11_SYNCE_MISCLK_RAT_M1_S 31
#define NAC_CGU_DWORD11_SYNCE_MISCLK_RAT_M1_M BIT(31)

union nac_cgu_dword11 {
	struct {
		u32 misc25 : 1;
		u32 synce_s_byp_clk : 6;
		u32 synce_hdov_mode : 1;
		u32 synce_rat_sel : 2;
		u32 synce_link_enable : 20;
		u32 synce_misclk_en : 1;
		u32 synce_misclk_rat_m1 : 1;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD12 0x30
#define NAC_CGU_DWORD12_SYNCE_MISCLK_RAT_M1_S 0
#define NAC_CGU_DWORD12_SYNCE_MISCLK_RAT_M1_M ICE_M(0x3ff, 0)
#define NAC_CGU_DWORD12_SYNCE_MCK_RST_S 10
#define NAC_CGU_DWORD12_SYNCE_MCK_RST_M BIT(10)
#define NAC_CGU_DWORD12_SYNCE_DPLL_BYP_S 11
#define NAC_CGU_DWORD12_SYNCE_DPLL_BYP_M BIT(11)
#define NAC_CGU_DWORD12_SYNCE_DV_RAT_M1_S 12
#define NAC_CGU_DWORD12_SYNCE_DV_RAT_M1_M ICE_M(0x1fff, 12)
#define NAC_CGU_DWORD12_SYNCE_ML_RAT_M1_S 25
#define NAC_CGU_DWORD12_SYNCE_ML_RAT_M1_M ICE_M(0x7f, 25)

union nac_cgu_dword12 {
	struct {
		u32 synce_misclk_rat_m1 : 10;
		u32 synce_mck_rst : 1;
		u32 synce_dpll_byp : 1;
		u32 synce_dv_rat_m1 : 13;
		u32 synce_ml_rat_m1 : 7;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD13 0x34
#define NAC_CGU_DWORD13_SYNCE_ML_RAT_M1_S 0
#define NAC_CGU_DWORD13_SYNCE_ML_RAT_M1_M ICE_M(0x1f, 0)
#define NAC_CGU_DWORD13_SYNCE_HDOV_CHANGED_S 5
#define NAC_CGU_DWORD13_SYNCE_HDOV_CHANGED_M BIT(5)
#define NAC_CGU_DWORD13_SYNCE_LOCK_CHANGED_S 6
#define NAC_CGU_DWORD13_SYNCE_LOCK_CHANGED_M BIT(6)
#define NAC_CGU_DWORD13_SYNCE_HDOV_S 7
#define NAC_CGU_DWORD13_SYNCE_HDOV_M BIT(7)
#define NAC_CGU_DWORD13_SYNCE_HDOV_INT_ENB_S 8
#define NAC_CGU_DWORD13_SYNCE_HDOV_INT_ENB_M BIT(8)
#define NAC_CGU_DWORD13_SYNCE_LOCK_INT_ENB_S 9
#define NAC_CGU_DWORD13_SYNCE_LOCK_INT_ENB_M BIT(9)
#define NAC_CGU_DWORD13_SYNCE_LOCKED_NC_S 10
#define NAC_CGU_DWORD13_SYNCE_LOCKED_NC_M BIT(10)
#define NAC_CGU_DWORD13_FDPLL_LOCKED_NC_S 11
#define NAC_CGU_DWORD13_FDPLL_LOCKED_NC_M BIT(11)
#define NAC_CGU_DWORD13_SYNCE_LOCKED_CLEAR_S 12
#define NAC_CGU_DWORD13_SYNCE_LOCKED_CLEAR_M BIT(12)
#define NAC_CGU_DWORD13_SYNCE_HDOV_CLEAR_S 13
#define NAC_CGU_DWORD13_SYNCE_HDOV_CLEAR_M BIT(13)
#define NAC_CGU_DWORD13_FDPLL_LOCKED_CLEAR_S 14
#define NAC_CGU_DWORD13_FDPLL_LOCKED_CLEAR_M BIT(14)
#define NAC_CGU_DWORD13_FDPLL_LOCK_CHANGED_S 15
#define NAC_CGU_DWORD13_FDPLL_LOCK_CHANGED_M BIT(15)
#define NAC_CGU_DWORD13_RMNRXCLK_SEL_S 16
#define NAC_CGU_DWORD13_RMNRXCLK_SEL_M ICE_M(0x1f, 16)
#define NAC_CGU_DWORD13_ENABLE_ETH_COUNT_S 21
#define NAC_CGU_DWORD13_ENABLE_ETH_COUNT_M BIT(21)
#define NAC_CGU_DWORD13_ETH_COUNT_FAST_MODE_S 22
#define NAC_CGU_DWORD13_ETH_COUNT_FAST_MODE_M BIT(22)
#define NAC_CGU_DWORD13_MISC12_S 23
#define NAC_CGU_DWORD13_MISC12_M ICE_M(0x1ff, 23)

union nac_cgu_dword13 {
	struct {
		u32 synce_ml_rat_m1 : 5;
		u32 synce_hdov_changed : 1;
		u32 synce_lock_changed : 1;
		u32 synce_hdov : 1;
		u32 synce_hdov_int_enb : 1;
		u32 synce_lock_int_enb : 1;
		u32 synce_locked_nc : 1;
		u32 fdpll_locked_nc : 1;
		u32 synce_locked_clear : 1;
		u32 synce_hdov_clear : 1;
		u32 fdpll_locked_clear : 1;
		u32 fdpll_lock_changed : 1;
		u32 rmnrxclk_sel : 5;
		u32 enable_eth_count : 1;
		u32 eth_count_fast_mode : 1;
		u32 misc12 : 9;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD14 0x38
#define NAC_CGU_DWORD14_SYNCE_LNK_UP_MD_S 0
#define NAC_CGU_DWORD14_SYNCE_LNK_UP_MD_M BIT(0)
#define NAC_CGU_DWORD14_SYNCE_LNK_DN_MD_S 1
#define NAC_CGU_DWORD14_SYNCE_LNK_DN_MD_M BIT(1)
#define NAC_CGU_DWORD14_SYNCE_FAST_MODE_S 2
#define NAC_CGU_DWORD14_SYNCE_FAST_MODE_M BIT(2)
#define NAC_CGU_DWORD14_SYNCE_EEC_MODE_S 3
#define NAC_CGU_DWORD14_SYNCE_EEC_MODE_M BIT(3)
#define NAC_CGU_DWORD14_SYNCE_NGAIN_S 4
#define NAC_CGU_DWORD14_SYNCE_NGAIN_M ICE_M(0xff, 4)
#define NAC_CGU_DWORD14_SYNCE_NSCALE_S 12
#define NAC_CGU_DWORD14_SYNCE_NSCALE_M ICE_M(0x3f, 12)
#define NAC_CGU_DWORD14_SYNCE_UNLCK_THR_S 18
#define NAC_CGU_DWORD14_SYNCE_UNLCK_THR_M ICE_M(0x3fff, 18)

union nac_cgu_dword14 {
	struct {
		u32 synce_lnk_up_md : 1;
		u32 synce_lnk_dn_md : 1;
		u32 synce_fast_mode : 1;
		u32 synce_eec_mode : 1;
		u32 synce_ngain : 8;
		u32 synce_nscale : 6;
		u32 synce_unlck_thr : 14;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD15 0x3c
#define NAC_CGU_DWORD15_SYNCE_UNLCK_THR_S 0
#define NAC_CGU_DWORD15_SYNCE_UNLCK_THR_M ICE_M(0x7, 0)
#define NAC_CGU_DWORD15_SYNCE_LOCK_THR_S 3
#define NAC_CGU_DWORD15_SYNCE_LOCK_THR_M ICE_M(0x1ffff, 3)
#define NAC_CGU_DWORD15_SYNCE_QUO_M1_S 20
#define NAC_CGU_DWORD15_SYNCE_QUO_M1_M ICE_M(0x3f, 20)
#define NAC_CGU_DWORD15_SYNCE_REMNDR_S 26
#define NAC_CGU_DWORD15_SYNCE_REMNDR_M ICE_M(0x3f, 26)

union nac_cgu_dword15 {
	struct {
		u32 synce_unlck_thr : 3;
		u32 synce_lock_thr : 17;
		u32 synce_quo_m1 : 6;
		u32 synce_remndr : 6;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD16 0x40
#define NAC_CGU_DWORD16_SYNCE_REMNDR_S 0
#define NAC_CGU_DWORD16_SYNCE_REMNDR_M ICE_M(0x3f, 0)
#define NAC_CGU_DWORD16_SYNCE_PHLMT_EN_S 6
#define NAC_CGU_DWORD16_SYNCE_PHLMT_EN_M BIT(6)
#define NAC_CGU_DWORD16_MISC13_S 7
#define NAC_CGU_DWORD16_MISC13_M ICE_M(0x1ffffff, 7)

union nac_cgu_dword16 {
	struct {
		u32 synce_remndr : 6;
		u32 synce_phlmt_en : 1;
		u32 misc13 : 25;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD17 0x44
#define NAC_CGU_DWORD17_FDPLL_GAIN_S 0
#define NAC_CGU_DWORD17_FDPLL_GAIN_M ICE_M(0xf, 0)
#define NAC_CGU_DWORD17_FDPLL_SCALE_S 4
#define NAC_CGU_DWORD17_FDPLL_SCALE_M ICE_M(0xf, 4)
#define NAC_CGU_DWORD17_FDPLL_FGAIN_SHIFT_F_S 8
#define NAC_CGU_DWORD17_FDPLL_FGAIN_SHIFT_F_M ICE_M(0x3f, 8)
#define NAC_CGU_DWORD17_FDPLL_CLR_PHERR_S 14
#define NAC_CGU_DWORD17_FDPLL_CLR_PHERR_M BIT(14)
#define NAC_CGU_DWORD17_FDPLL_BB_EN_S 15
#define NAC_CGU_DWORD17_FDPLL_BB_EN_M BIT(15)
#define NAC_CGU_DWORD17_FDPLL_FGAIN_SHIFT_S 16
#define NAC_CGU_DWORD17_FDPLL_FGAIN_SHIFT_M ICE_M(0x3f, 16)
#define NAC_CGU_DWORD17_FDPLL_FSCALE_SHIFT_S 22
#define NAC_CGU_DWORD17_FDPLL_FSCALE_SHIFT_M ICE_M(0x1f, 22)
#define NAC_CGU_DWORD17_FDPLL_FSCALE_SHIFT_F_S 27
#define NAC_CGU_DWORD17_FDPLL_FSCALE_SHIFT_F_M ICE_M(0x1f, 27)

union nac_cgu_dword17 {
	struct {
		u32 fdpll_gain : 4;
		u32 fdpll_scale : 4;
		u32 fdpll_fgain_shift_f : 6;
		u32 fdpll_clr_pherr : 1;
		u32 fdpll_bb_en : 1;
		u32 fdpll_fgain_shift : 6;
		u32 fdpll_fscale_shift : 5;
		u32 fdpll_fscale_shift_f : 5;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD18 0x48
#define NAC_CGU_DWORD18_FDPLL_BYPASS_S 0
#define NAC_CGU_DWORD18_FDPLL_BYPASS_M BIT(0)
#define NAC_CGU_DWORD18_FDPLL_INP_NCO_S 1
#define NAC_CGU_DWORD18_FDPLL_INP_NCO_M ICE_M(0xff, 1)
#define NAC_CGU_DWORD18_FDPLL_AUTO_EN_S 9
#define NAC_CGU_DWORD18_FDPLL_AUTO_EN_M BIT(9)
#define NAC_CGU_DWORD18_FDPLL_SAMP_CNT_S 10
#define NAC_CGU_DWORD18_FDPLL_SAMP_CNT_M ICE_M(0xfff, 10)
#define NAC_CGU_DWORD18_FDPLL_LOCKCNT_S 22
#define NAC_CGU_DWORD18_FDPLL_LOCKCNT_M ICE_M(0x1f, 22)
#define NAC_CGU_DWORD18_FDPLL_LOCK_THR_S 27
#define NAC_CGU_DWORD18_FDPLL_LOCK_THR_M ICE_M(0x1f, 27)

union nac_cgu_dword18 {
	struct {
		u32 fdpll_bypass : 1;
		u32 fdpll_inp_nco : 8;
		u32 fdpll_auto_en : 1;
		u32 fdpll_samp_cnt : 12;
		u32 fdpll_lockcnt : 5;
		u32 fdpll_lock_thr : 5;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD19 0x4c
#define NAC_CGU_DWORD19_TSPLL_FBDIV_INTGR_S 0
#define NAC_CGU_DWORD19_TSPLL_FBDIV_INTGR_M ICE_M(0xff, 0)
#define NAC_CGU_DWORD19_FDPLL_ULCK_THR_S 8
#define NAC_CGU_DWORD19_FDPLL_ULCK_THR_M ICE_M(0x1f, 8)
#define NAC_CGU_DWORD19_MISC15_S 13
#define NAC_CGU_DWORD19_MISC15_M ICE_M(0x7, 13)
#define NAC_CGU_DWORD19_TSPLL_NDIVRATIO_S 16
#define NAC_CGU_DWORD19_TSPLL_NDIVRATIO_M ICE_M(0xf, 16)
#define NAC_CGU_DWORD19_TSPLL_IREF_NDIVRATIO_S 20
#define NAC_CGU_DWORD19_TSPLL_IREF_NDIVRATIO_M ICE_M(0x7, 20)
#define NAC_CGU_DWORD19_MISC19_S 23
#define NAC_CGU_DWORD19_MISC19_M BIT(23)
#define NAC_CGU_DWORD19_JAPLL_NDIVRATIO_S 24
#define NAC_CGU_DWORD19_JAPLL_NDIVRATIO_M ICE_M(0xf, 24)
#define NAC_CGU_DWORD19_JAPLL_IREF_NDIVRATIO_S 28
#define NAC_CGU_DWORD19_JAPLL_IREF_NDIVRATIO_M ICE_M(0x7, 28)
#define NAC_CGU_DWORD19_MISC27_S 31
#define NAC_CGU_DWORD19_MISC27_M BIT(31)

union nac_cgu_dword19 {
	struct {
		u32 tspll_fbdiv_intgr : 8;
		u32 fdpll_ulck_thr : 5;
		u32 misc15 : 3;
		u32 tspll_ndivratio : 4;
		u32 tspll_iref_ndivratio : 3;
		u32 misc19 : 1;
		u32 japll_ndivratio : 4;
		u32 japll_iref_ndivratio : 3;
		u32 misc27 : 1;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD20 0x50
#define NAC_CGU_DWORD20_JAPLL_INT_DIV_S 0
#define NAC_CGU_DWORD20_JAPLL_INT_DIV_M ICE_M(0xff, 0)
#define NAC_CGU_DWORD20_JAPLL_FRAC_DIV_S 8
#define NAC_CGU_DWORD20_JAPLL_FRAC_DIV_M ICE_M(0x3fffff, 8)
#define NAC_CGU_DWORD20_MISC16_S 30
#define NAC_CGU_DWORD20_MISC16_M ICE_M(0x3, 30)

union nac_cgu_dword20 {
	struct {
		u32 japll_int_div : 8;
		u32 japll_frac_div : 22;
		u32 misc16 : 2;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD21 0x54
#define NAC_CGU_DWORD21_MISC17_S 0
#define NAC_CGU_DWORD21_MISC17_M ICE_M(0xf, 0)
#define NAC_CGU_DWORD21_FDPLL_INT_DIV_OUT_NC_S 4
#define NAC_CGU_DWORD21_FDPLL_INT_DIV_OUT_NC_M ICE_M(0xff, 4)
#define NAC_CGU_DWORD21_FDPLL_FRAC_DIV_OUT_NC_S 12
#define NAC_CGU_DWORD21_FDPLL_FRAC_DIV_OUT_NC_M ICE_M(0xfffff, 12)

union nac_cgu_dword21 {
	struct {
		u32 misc17 : 4;
		u32 fdpll_int_div_out_nc : 8;
		u32 fdpll_frac_div_out_nc : 20;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD22 0x58
#define NAC_CGU_DWORD22_FDPLL_FRAC_DIV_OUT_NC_S 0
#define NAC_CGU_DWORD22_FDPLL_FRAC_DIV_OUT_NC_M ICE_M(0x3, 0)
#define NAC_CGU_DWORD22_FDPLL_LOCK_INT_FOR_S 2
#define NAC_CGU_DWORD22_FDPLL_LOCK_INT_FOR_M BIT(2)
#define NAC_CGU_DWORD22_SYNCE_HDOV_INT_FOR_S 3
#define NAC_CGU_DWORD22_SYNCE_HDOV_INT_FOR_M BIT(3)
#define NAC_CGU_DWORD22_SYNCE_LOCK_INT_FOR_S 4
#define NAC_CGU_DWORD22_SYNCE_LOCK_INT_FOR_M BIT(4)
#define NAC_CGU_DWORD22_FDPLL_PHLEAD_SLIP_NC_S 5
#define NAC_CGU_DWORD22_FDPLL_PHLEAD_SLIP_NC_M BIT(5)
#define NAC_CGU_DWORD22_FDPLL_ACC1_OVFL_NC_S 6
#define NAC_CGU_DWORD22_FDPLL_ACC1_OVFL_NC_M BIT(6)
#define NAC_CGU_DWORD22_FDPLL_ACC2_OVFL_NC_S 7
#define NAC_CGU_DWORD22_FDPLL_ACC2_OVFL_NC_M BIT(7)
#define NAC_CGU_DWORD22_SYNCE_STATUS_NC_S 8
#define NAC_CGU_DWORD22_SYNCE_STATUS_NC_M ICE_M(0x3f, 8)
#define NAC_CGU_DWORD22_FDPLL_ACC1F_OVFL_S 14
#define NAC_CGU_DWORD22_FDPLL_ACC1F_OVFL_M BIT(14)
#define NAC_CGU_DWORD22_MISC18_S 15
#define NAC_CGU_DWORD22_MISC18_M BIT(15)
#define NAC_CGU_DWORD22_FDPLLCLK_DIV_S 16
#define NAC_CGU_DWORD22_FDPLLCLK_DIV_M ICE_M(0xf, 16)
#define NAC_CGU_DWORD22_TIME1588CLK_DIV_S 20
#define NAC_CGU_DWORD22_TIME1588CLK_DIV_M ICE_M(0xf, 20)
#define NAC_CGU_DWORD22_SYNCECLK_DIV_S 24
#define NAC_CGU_DWORD22_SYNCECLK_DIV_M ICE_M(0xf, 24)
#define NAC_CGU_DWORD22_SYNCECLK_SEL_DIV2_S 28
#define NAC_CGU_DWORD22_SYNCECLK_SEL_DIV2_M BIT(28)
#define NAC_CGU_DWORD22_FDPLLCLK_SEL_DIV2_S 29
#define NAC_CGU_DWORD22_FDPLLCLK_SEL_DIV2_M BIT(29)
#define NAC_CGU_DWORD22_TIME1588CLK_SEL_DIV2_S 30
#define NAC_CGU_DWORD22_TIME1588CLK_SEL_DIV2_M BIT(30)
#define NAC_CGU_DWORD22_MISC3_S 31
#define NAC_CGU_DWORD22_MISC3_M BIT(31)

union nac_cgu_dword22 {
	struct {
		u32 fdpll_frac_div_out_nc : 2;
		u32 fdpll_lock_int_for : 1;
		u32 synce_hdov_int_for : 1;
		u32 synce_lock_int_for : 1;
		u32 fdpll_phlead_slip_nc : 1;
		u32 fdpll_acc1_ovfl_nc : 1;
		u32 fdpll_acc2_ovfl_nc : 1;
		u32 synce_status_nc : 6;
		u32 fdpll_acc1f_ovfl : 1;
		u32 misc18 : 1;
		u32 fdpllclk_div : 4;
		u32 time1588clk_div : 4;
		u32 synceclk_div : 4;
		u32 synceclk_sel_div2 : 1;
		u32 fdpllclk_sel_div2 : 1;
		u32 time1588clk_sel_div2 : 1;
		u32 misc3 : 1;
	} field;
	u32 val;
};

#define NAC_CGU_DWORD24 0x60
#define NAC_CGU_DWORD24_TSPLL_FBDIV_FRAC_S 0
#define NAC_CGU_DWORD24_TSPLL_FBDIV_FRAC_M ICE_M(0x3fffff, 0)
#define NAC_CGU_DWORD24_MISC20_S 22
#define NAC_CGU_DWORD24_MISC20_M ICE_M(0x3, 22)
#define NAC_CGU_DWORD24_TS_PLL_ENABLE_S 24
#define NAC_CGU_DWORD24_TS_PLL_ENABLE_M BIT(24)
#define NAC_CGU_DWORD24_TIME_SYNC_TSPLL_ALIGN_SEL_S 25
#define NAC_CGU_DWORD24_TIME_SYNC_TSPLL_ALIGN_SEL_M BIT(25)
#define NAC_CGU_DWORD24_EXT_SYNCE_SEL_S 26
#define NAC_CGU_DWORD24_EXT_SYNCE_SEL_M BIT(26)
#define NAC_CGU_DWORD24_REF1588_CK_DIV_S 27
#define NAC_CGU_DWORD24_REF1588_CK_DIV_M ICE_M(0xf, 27)
#define NAC_CGU_DWORD24_TIME_REF_SEL_S 31
#define NAC_CGU_DWORD24_TIME_REF_SEL_M BIT(31)

union nac_cgu_dword24 {
	struct {
		u32 tspll_fbdiv_frac : 22;
		u32 misc20 : 2;
		u32 ts_pll_enable : 1;
		u32 time_sync_tspll_align_sel : 1;
		u32 ext_synce_sel : 1;
		u32 ref1588_ck_div : 4;
		u32 time_ref_sel : 1;
	} field;
	u32 val;
};

#define TSPLL_CNTR_BIST_SETTINGS 0x344
#define TSPLL_CNTR_BIST_SETTINGS_I_IREFGEN_SETTLING_TIME_CNTR_7_0_S 0
#define TSPLL_CNTR_BIST_SETTINGS_I_IREFGEN_SETTLING_TIME_CNTR_7_0_M \
	ICE_M(0xff, 0)
#define TSPLL_CNTR_BIST_SETTINGS_I_IREFGEN_SETTLING_TIME_RO_STANDBY_1_0_S 8
#define TSPLL_CNTR_BIST_SETTINGS_I_IREFGEN_SETTLING_TIME_RO_STANDBY_1_0_M \
	ICE_M(0x3, 8)
#define TSPLL_CNTR_BIST_SETTINGS_RESERVED195_S 10
#define TSPLL_CNTR_BIST_SETTINGS_RESERVED195_M ICE_M(0x1f, 10)
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_SEL_0_S 15
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_SEL_0_M BIT(15)
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_SEL_1_S 16
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_SEL_1_M BIT(16)
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_CNT_6_0_S 17
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_CNT_6_0_M ICE_M(0x7f, 17)
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_CNT_10_7_S 24
#define TSPLL_CNTR_BIST_SETTINGS_I_PLLLOCK_CNT_10_7_M ICE_M(0xf, 24)
#define TSPLL_CNTR_BIST_SETTINGS_RESERVED200_S 28
#define TSPLL_CNTR_BIST_SETTINGS_RESERVED200_M ICE_M(0xf, 28)

union tspll_cntr_bist_settings {
	struct {
		u32 i_irefgen_settling_time_cntr_7_0 : 8;
		u32 i_irefgen_settling_time_ro_standby_1_0 : 2;
		u32 reserved195 : 5;
		u32 i_plllock_sel_0 : 1;
		u32 i_plllock_sel_1 : 1;
		u32 i_plllock_cnt_6_0 : 7;
		u32 i_plllock_cnt_10_7 : 4;
		u32 reserved200 : 4;
	} field;
	u32 val;
};

#define TSPLL_RO_BWM_LF 0x370
#define TSPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_7_0_S 0
#define TSPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_7_0_M ICE_M(0xff, 0)
#define TSPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_9_8_S 8
#define TSPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_9_8_M ICE_M(0x3, 8)
#define TSPLL_RO_BWM_LF_BIASCALDONE_CRI_S 10
#define TSPLL_RO_BWM_LF_BIASCALDONE_CRI_M BIT(10)
#define TSPLL_RO_BWM_LF_PLLLOCK_GAIN_TRAN_CRI_S 11
#define TSPLL_RO_BWM_LF_PLLLOCK_GAIN_TRAN_CRI_M BIT(11)
#define TSPLL_RO_BWM_LF_PLLLOCK_TRUE_LOCK_CRI_S 12
#define TSPLL_RO_BWM_LF_PLLLOCK_TRUE_LOCK_CRI_M BIT(12)
#define TSPLL_RO_BWM_LF_PLLUNLOCK_FLAG_CRI_S 13
#define TSPLL_RO_BWM_LF_PLLUNLOCK_FLAG_CRI_M BIT(13)
#define TSPLL_RO_BWM_LF_AFCERR_CRI_S 14
#define TSPLL_RO_BWM_LF_AFCERR_CRI_M BIT(14)
#define TSPLL_RO_BWM_LF_AFCDONE_CRI_S 15
#define TSPLL_RO_BWM_LF_AFCDONE_CRI_M BIT(15)
#define TSPLL_RO_BWM_LF_FEEDFWRDGAIN_CAL_CRI_7_0_S 16
#define TSPLL_RO_BWM_LF_FEEDFWRDGAIN_CAL_CRI_7_0_M ICE_M(0xff, 16)
#define TSPLL_RO_BWM_LF_M2FBDIVMOD_CRI_7_0_S 24
#define TSPLL_RO_BWM_LF_M2FBDIVMOD_CRI_7_0_M ICE_M(0xff, 24)

union tspll_ro_bwm_lf {
	struct {
		u32 bw_freqov_high_cri_7_0 : 8;
		u32 bw_freqov_high_cri_9_8 : 2;
		u32 biascaldone_cri : 1;
		u32 plllock_gain_tran_cri : 1;
		u32 plllock_true_lock_cri : 1;
		u32 pllunlock_flag_cri : 1;
		u32 afcerr_cri : 1;
		u32 afcdone_cri : 1;
		u32 feedfwrdgain_cal_cri_7_0 : 8;
		u32 m2fbdivmod_cri_7_0 : 8;
	} field;
	u32 val;
};

#define JAPLL_DIV0 0x400
#define JAPLL_DIV0_I_FBDIV_INTGR_7_0_S 0
#define JAPLL_DIV0_I_FBDIV_INTGR_7_0_M ICE_M(0xff, 0)
#define JAPLL_DIV0_I_FBDIV_FRAC_7_0_S 8
#define JAPLL_DIV0_I_FBDIV_FRAC_7_0_M ICE_M(0xff, 8)
#define JAPLL_DIV0_I_FBDIV_FRAC_15_8_S 16
#define JAPLL_DIV0_I_FBDIV_FRAC_15_8_M ICE_M(0xff, 16)
#define JAPLL_DIV0_I_FBDIV_FRAC_21_16_S 24
#define JAPLL_DIV0_I_FBDIV_FRAC_21_16_M ICE_M(0x3f, 24)
#define JAPLL_DIV0_I_FRACNEN_H_S 30
#define JAPLL_DIV0_I_FRACNEN_H_M BIT(30)
#define JAPLL_DIV0_I_DIRECT_PIN_IF_EN_S 31
#define JAPLL_DIV0_I_DIRECT_PIN_IF_EN_M BIT(31)

union japll_div0 {
	struct {
		u32 i_fbdiv_intgr_7_0 : 8;
		u32 i_fbdiv_frac_7_0 : 8;
		u32 i_fbdiv_frac_15_8 : 8;
		u32 i_fbdiv_frac_21_16 : 6;
		u32 i_fracnen_h : 1;
		u32 i_direct_pin_if_en : 1;
	} field;
	u32 val;
};

#define JAPLL_LF 0x408
#define JAPLL_LF_I_PROP_COEFF_3_0_S 0
#define JAPLL_LF_I_PROP_COEFF_3_0_M ICE_M(0xf, 0)
#define JAPLL_LF_I_FLL_INT_COEFF_3_0_S 4
#define JAPLL_LF_I_FLL_INT_COEFF_3_0_M ICE_M(0xf, 4)
#define JAPLL_LF_I_INT_COEFF_4_0_S 8
#define JAPLL_LF_I_INT_COEFF_4_0_M ICE_M(0x1f, 8)
#define JAPLL_LF_I_FLL_EN_H_S 13
#define JAPLL_LF_I_FLL_EN_H_M BIT(13)
#define JAPLL_LF_I_TDC_FINE_RES_S 14
#define JAPLL_LF_I_TDC_FINE_RES_M BIT(14)
#define JAPLL_LF_I_DCOFINE_RESOLUTION_S 15
#define JAPLL_LF_I_DCOFINE_RESOLUTION_M BIT(15)
#define JAPLL_LF_I_GAINCTRL_2_0_S 16
#define JAPLL_LF_I_GAINCTRL_2_0_M ICE_M(0x7, 16)
#define JAPLL_LF_I_AFC_DIVRATIO_S 19
#define JAPLL_LF_I_AFC_DIVRATIO_M BIT(19)
#define JAPLL_LF_I_AFCCNTSEL_S 20
#define JAPLL_LF_I_AFCCNTSEL_M BIT(20)
#define JAPLL_LF_I_AFC_STARTUP_1_0_S 21
#define JAPLL_LF_I_AFC_STARTUP_1_0_M ICE_M(0x3, 21)
#define JAPLL_LF_RESERVED31_S 23
#define JAPLL_LF_RESERVED31_M BIT(23)
#define JAPLL_LF_I_TDCTARGETCNT_7_0_S 24
#define JAPLL_LF_I_TDCTARGETCNT_7_0_M ICE_M(0xff, 24)

union japll_lf {
	struct {
		u32 i_prop_coeff_3_0 : 4;
		u32 i_fll_int_coeff_3_0 : 4;
		u32 i_int_coeff_4_0 : 5;
		u32 i_fll_en_h : 1;
		u32 i_tdc_fine_res : 1;
		u32 i_dcofine_resolution : 1;
		u32 i_gainctrl_2_0 : 3;
		u32 i_afc_divratio : 1;
		u32 i_afccntsel : 1;
		u32 i_afc_startup_1_0 : 2;
		u32 reserved31 : 1;
		u32 i_tdctargetcnt_7_0 : 8;
	} field;
	u32 val;
};

#define JAPLL_FRAC_LOCK 0x40c
#define JAPLL_FRAC_LOCK_I_FEEDFWRDGAIN_7_0_S 0
#define JAPLL_FRAC_LOCK_I_FEEDFWRDGAIN_7_0_M ICE_M(0xff, 0)
#define JAPLL_FRAC_LOCK_I_FEEDFWRDCAL_EN_H_S 8
#define JAPLL_FRAC_LOCK_I_FEEDFWRDCAL_EN_H_M BIT(8)
#define JAPLL_FRAC_LOCK_I_FEEDFWRDCAL_PAUSE_H_S 9
#define JAPLL_FRAC_LOCK_I_FEEDFWRDCAL_PAUSE_H_M BIT(9)
#define JAPLL_FRAC_LOCK_I_DCODITHEREN_H_S 10
#define JAPLL_FRAC_LOCK_I_DCODITHEREN_H_M BIT(10)
#define JAPLL_FRAC_LOCK_I_LOCKTHRESH_3_0_S 11
#define JAPLL_FRAC_LOCK_I_LOCKTHRESH_3_0_M ICE_M(0xf, 11)
#define JAPLL_FRAC_LOCK_I_DCODITHER_CONFIG_S 15
#define JAPLL_FRAC_LOCK_I_DCODITHER_CONFIG_M BIT(15)
#define JAPLL_FRAC_LOCK_I_EARLYLOCK_CRITERIA_1_0_S 16
#define JAPLL_FRAC_LOCK_I_EARLYLOCK_CRITERIA_1_0_M ICE_M(0x3, 16)
#define JAPLL_FRAC_LOCK_I_TRUELOCK_CRITERIA_1_0_S 18
#define JAPLL_FRAC_LOCK_I_TRUELOCK_CRITERIA_1_0_M ICE_M(0x3, 18)
#define JAPLL_FRAC_LOCK_I_LF_HALF_CYC_EN_S 20
#define JAPLL_FRAC_LOCK_I_LF_HALF_CYC_EN_M BIT(20)
#define JAPLL_FRAC_LOCK_I_DITHER_OVRD_S 21
#define JAPLL_FRAC_LOCK_I_DITHER_OVRD_M BIT(21)
#define JAPLL_FRAC_LOCK_I_PLLLC_RESTORE_REG_S 22
#define JAPLL_FRAC_LOCK_I_PLLLC_RESTORE_REG_M BIT(22)
#define JAPLL_FRAC_LOCK_I_PLLLC_RESTORE_MODE_CTRL_S 23
#define JAPLL_FRAC_LOCK_I_PLLLC_RESTORE_MODE_CTRL_M BIT(23)
#define JAPLL_FRAC_LOCK_I_PLLRAMPEN_H_S 24
#define JAPLL_FRAC_LOCK_I_PLLRAMPEN_H_M BIT(24)
#define JAPLL_FRAC_LOCK_I_FBDIV_STROBE_H_S 25
#define JAPLL_FRAC_LOCK_I_FBDIV_STROBE_H_M BIT(25)
#define JAPLL_FRAC_LOCK_I_OVC_SNAPSHOT_H_S 26
#define JAPLL_FRAC_LOCK_I_OVC_SNAPSHOT_H_M BIT(26)
#define JAPLL_FRAC_LOCK_I_DITHER_VALUE_4_0_S 27
#define JAPLL_FRAC_LOCK_I_DITHER_VALUE_4_0_M ICE_M(0x1f, 27)

union japll_frac_lock {
	struct {
		u32 i_feedfwrdgain_7_0 : 8;
		u32 i_feedfwrdcal_en_h : 1;
		u32 i_feedfwrdcal_pause_h : 1;
		u32 i_dcoditheren_h : 1;
		u32 i_lockthresh_3_0 : 4;
		u32 i_dcodither_config : 1;
		u32 i_earlylock_criteria_1_0 : 2;
		u32 i_truelock_criteria_1_0 : 2;
		u32 i_lf_half_cyc_en : 1;
		u32 i_dither_ovrd : 1;
		u32 i_plllc_restore_reg : 1;
		u32 i_plllc_restore_mode_ctrl : 1;
		u32 i_pllrampen_h : 1;
		u32 i_fbdiv_strobe_h : 1;
		u32 i_ovc_snapshot_h : 1;
		u32 i_dither_value_4_0 : 5;
	} field;
	u32 val;
};

#define JAPLL_BIAS 0x414
#define JAPLL_BIAS_I_IREFTRIM_4_0_S 0
#define JAPLL_BIAS_I_IREFTRIM_4_0_M ICE_M(0x1f, 0)
#define JAPLL_BIAS_I_VREF_RDAC_2_0_S 5
#define JAPLL_BIAS_I_VREF_RDAC_2_0_M ICE_M(0x7, 5)
#define JAPLL_BIAS_I_CTRIM_4_0_S 8
#define JAPLL_BIAS_I_CTRIM_4_0_M ICE_M(0x1f, 8)
#define JAPLL_BIAS_I_IREF_REFCLK_MODE_1_0_S 13
#define JAPLL_BIAS_I_IREF_REFCLK_MODE_1_0_M ICE_M(0x3, 13)
#define JAPLL_BIAS_I_BIASCAL_EN_H_S 15
#define JAPLL_BIAS_I_BIASCAL_EN_H_M BIT(15)
#define JAPLL_BIAS_I_BIAS_BONUS_7_0_S 16
#define JAPLL_BIAS_I_BIAS_BONUS_7_0_M ICE_M(0xff, 16)
#define JAPLL_BIAS_I_INIT_DCOAMP_5_0_S 24
#define JAPLL_BIAS_I_INIT_DCOAMP_5_0_M ICE_M(0x3f, 24)
#define JAPLL_BIAS_I_BIAS_GB_SEL_1_0_S 30
#define JAPLL_BIAS_I_BIAS_GB_SEL_1_0_M ICE_M(0x3, 30)

union japll_bias {
	struct {
		u32 i_ireftrim_4_0 : 5;
		u32 i_vref_rdac_2_0 : 3;
		u32 i_ctrim_4_0 : 5;
		u32 i_iref_refclk_mode_1_0 : 2;
		u32 i_biascal_en_h : 1;
		u32 i_bias_bonus_7_0 : 8;
		u32 i_init_dcoamp_5_0 : 6;
		u32 i_bias_gb_sel_1_0 : 2;
	} field;
	u32 val;
};

#define JAPLL_TDC_COLDST_BIAS 0x418
#define JAPLL_TDC_COLDST_BIAS_I_TDCSEL_1_0_S 0
#define JAPLL_TDC_COLDST_BIAS_I_TDCSEL_1_0_M ICE_M(0x3, 0)
#define JAPLL_TDC_COLDST_BIAS_I_TDCOVCCORR_EN_H_S 2
#define JAPLL_TDC_COLDST_BIAS_I_TDCOVCCORR_EN_H_M BIT(2)
#define JAPLL_TDC_COLDST_BIAS_I_TDCDC_EN_H_S 3
#define JAPLL_TDC_COLDST_BIAS_I_TDCDC_EN_H_M BIT(3)
#define JAPLL_TDC_COLDST_BIAS_I_TDC_OFFSET_LOCK_1_0_S 4
#define JAPLL_TDC_COLDST_BIAS_I_TDC_OFFSET_LOCK_1_0_M ICE_M(0x3, 4)
#define JAPLL_TDC_COLDST_BIAS_I_SWCAP_IREFGEN_CLKMODE_1_0_S 6
#define JAPLL_TDC_COLDST_BIAS_I_SWCAP_IREFGEN_CLKMODE_1_0_M ICE_M(0x3, 6)
#define JAPLL_TDC_COLDST_BIAS_I_BB_GAIN_2_0_S 8
#define JAPLL_TDC_COLDST_BIAS_I_BB_GAIN_2_0_M ICE_M(0x7, 8)
#define JAPLL_TDC_COLDST_BIAS_I_BBTHRESH_3_0_S 11
#define JAPLL_TDC_COLDST_BIAS_I_BBTHRESH_3_0_M ICE_M(0xf, 11)
#define JAPLL_TDC_COLDST_BIAS_I_BBINLOCK_H_S 15
#define JAPLL_TDC_COLDST_BIAS_I_BBINLOCK_H_M BIT(15)
#define JAPLL_TDC_COLDST_BIAS_I_COLDSTART_S 16
#define JAPLL_TDC_COLDST_BIAS_I_COLDSTART_M BIT(16)
#define JAPLL_TDC_COLDST_BIAS_I_IREFBIAS_STARTUP_PULSE_WIDTH_1_0_S 17
#define JAPLL_TDC_COLDST_BIAS_I_IREFBIAS_STARTUP_PULSE_WIDTH_1_0_M \
	ICE_M(0x3, 17)
#define JAPLL_TDC_COLDST_BIAS_I_DCO_SETTLING_TIME_CNTR_3_0_S 19
#define JAPLL_TDC_COLDST_BIAS_I_DCO_SETTLING_TIME_CNTR_3_0_M ICE_M(0xf, 19)
#define JAPLL_TDC_COLDST_BIAS_I_IREFBIAS_STARTUP_PULSE_BYPASS_S 23
#define JAPLL_TDC_COLDST_BIAS_I_IREFBIAS_STARTUP_PULSE_BYPASS_M BIT(23)
#define JAPLL_TDC_COLDST_BIAS_I_BIAS_CALIB_STEPSIZE_1_0_S 24
#define JAPLL_TDC_COLDST_BIAS_I_BIAS_CALIB_STEPSIZE_1_0_M ICE_M(0x3, 24)
#define JAPLL_TDC_COLDST_BIAS_RESERVED81_S 26
#define JAPLL_TDC_COLDST_BIAS_RESERVED81_M BIT(26)
#define JAPLL_TDC_COLDST_BIAS_I_IREFINT_EN_S 27
#define JAPLL_TDC_COLDST_BIAS_I_IREFINT_EN_M BIT(27)
#define JAPLL_TDC_COLDST_BIAS_I_VGSBUFEN_S 28
#define JAPLL_TDC_COLDST_BIAS_I_VGSBUFEN_M BIT(28)
#define JAPLL_TDC_COLDST_BIAS_I_DIGDFTSWEP_S 29
#define JAPLL_TDC_COLDST_BIAS_I_DIGDFTSWEP_M BIT(29)
#define JAPLL_TDC_COLDST_BIAS_I_IREFDIGDFTEN_S 30
#define JAPLL_TDC_COLDST_BIAS_I_IREFDIGDFTEN_M BIT(30)
#define JAPLL_TDC_COLDST_BIAS_I_IREF_REFCLK_INV_EN_S 31
#define JAPLL_TDC_COLDST_BIAS_I_IREF_REFCLK_INV_EN_M BIT(31)

union japll_tdc_coldst_bias {
	struct {
		u32 i_tdcsel_1_0 : 2;
		u32 i_tdcovccorr_en_h : 1;
		u32 i_tdcdc_en_h : 1;
		u32 i_tdc_offset_lock_1_0 : 2;
		u32 i_swcap_irefgen_clkmode_1_0 : 2;
		u32 i_bb_gain_2_0 : 3;
		u32 i_bbthresh_3_0 : 4;
		u32 i_bbinlock_h : 1;
		u32 i_coldstart : 1;
		u32 i_irefbias_startup_pulse_width_1_0 : 2;
		u32 i_dco_settling_time_cntr_3_0 : 4;
		u32 i_irefbias_startup_pulse_bypass : 1;
		u32 i_bias_calib_stepsize_1_0 : 2;
		u32 reserved81 : 1;
		u32 i_irefint_en : 1;
		u32 i_vgsbufen : 1;
		u32 i_digdftswep : 1;
		u32 i_irefdigdften : 1;
		u32 i_iref_refclk_inv_en : 1;
	} field;
	u32 val;
};

#define JAPLL_DFX_DCO 0x424
#define JAPLL_DFX_DCO_I_DCOFINEDFTSEL_1_0_S 0
#define JAPLL_DFX_DCO_I_DCOFINEDFTSEL_1_0_M ICE_M(0x3, 0)
#define JAPLL_DFX_DCO_I_DCOCOARSE_OVRD_H_S 2
#define JAPLL_DFX_DCO_I_DCOCOARSE_OVRD_H_M BIT(2)
#define JAPLL_DFX_DCO_I_BIAS_FILTER_EN_S 3
#define JAPLL_DFX_DCO_I_BIAS_FILTER_EN_M BIT(3)
#define JAPLL_DFX_DCO_I_PLLPWRMODE_1_0_S 4
#define JAPLL_DFX_DCO_I_PLLPWRMODE_1_0_M ICE_M(0x3, 4)
#define JAPLL_DFX_DCO_I_DCOAMP_STATICLEG_CFG_1_0_S 6
#define JAPLL_DFX_DCO_I_DCOAMP_STATICLEG_CFG_1_0_M ICE_M(0x3, 6)
#define JAPLL_DFX_DCO_I_DCOFINE_7_0_S 8
#define JAPLL_DFX_DCO_I_DCOFINE_7_0_M ICE_M(0xff, 8)
#define JAPLL_DFX_DCO_I_DCOFINE_9_8_S 16
#define JAPLL_DFX_DCO_I_DCOFINE_9_8_M ICE_M(0x3, 16)
#define JAPLL_DFX_DCO_I_DCOAMPOVRDEN_H_S 18
#define JAPLL_DFX_DCO_I_DCOAMPOVRDEN_H_M BIT(18)
#define JAPLL_DFX_DCO_I_DCOAMP_3_0_S 19
#define JAPLL_DFX_DCO_I_DCOAMP_3_0_M ICE_M(0xf, 19)
#define JAPLL_DFX_DCO_I_BIASFILTER_EN_DELAY_S 23
#define JAPLL_DFX_DCO_I_BIASFILTER_EN_DELAY_M BIT(23)
#define JAPLL_DFX_DCO_I_DCOCOARSE_7_0_S 24
#define JAPLL_DFX_DCO_I_DCOCOARSE_7_0_M ICE_M(0xff, 24)

union japll_dfx_dco {
	struct {
		u32 i_dcofinedftsel_1_0 : 2;
		u32 i_dcocoarse_ovrd_h : 1;
		u32 i_bias_filter_en : 1;
		u32 i_pllpwrmode_1_0 : 2;
		u32 i_dcoamp_staticleg_cfg_1_0 : 2;
		u32 i_dcofine_7_0 : 8;
		u32 i_dcofine_9_8 : 2;
		u32 i_dcoampovrden_h : 1;
		u32 i_dcoamp_3_0 : 4;
		u32 i_biasfilter_en_delay : 1;
		u32 i_dcocoarse_7_0 : 8;
	} field;
	u32 val;
};

#define JAPLL_RO_BWM_LF 0x470
#define JAPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_7_0_S 0
#define JAPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_7_0_M ICE_M(0xff, 0)
#define JAPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_9_8_S 8
#define JAPLL_RO_BWM_LF_BW_FREQOV_HIGH_CRI_9_8_M ICE_M(0x3, 8)
#define JAPLL_RO_BWM_LF_BIASCALDONE_CRI_S 10
#define JAPLL_RO_BWM_LF_BIASCALDONE_CRI_M BIT(10)
#define JAPLL_RO_BWM_LF_PLLLOCK_GAIN_TRAN_CRI_S 11
#define JAPLL_RO_BWM_LF_PLLLOCK_GAIN_TRAN_CRI_M BIT(11)
#define JAPLL_RO_BWM_LF_PLLLOCK_TRUE_LOCK_CRI_S 12
#define JAPLL_RO_BWM_LF_PLLLOCK_TRUE_LOCK_CRI_M BIT(12)
#define JAPLL_RO_BWM_LF_PLLUNLOCK_FLAG_CRI_S 13
#define JAPLL_RO_BWM_LF_PLLUNLOCK_FLAG_CRI_M BIT(13)
#define JAPLL_RO_BWM_LF_AFCERR_CRI_S 14
#define JAPLL_RO_BWM_LF_AFCERR_CRI_M BIT(14)
#define JAPLL_RO_BWM_LF_AFCDONE_CRI_S 15
#define JAPLL_RO_BWM_LF_AFCDONE_CRI_M BIT(15)
#define JAPLL_RO_BWM_LF_FEEDFWRDGAIN_CAL_CRI_7_0_S 16
#define JAPLL_RO_BWM_LF_FEEDFWRDGAIN_CAL_CRI_7_0_M ICE_M(0xff, 16)
#define JAPLL_RO_BWM_LF_M2FBDIVMOD_CRI_7_0_S 24
#define JAPLL_RO_BWM_LF_M2FBDIVMOD_CRI_7_0_M ICE_M(0xff, 24)

union japll_ro_bwm_lf {
	struct {
		u32 bw_freqov_high_cri_7_0 : 8;
		u32 bw_freqov_high_cri_9_8 : 2;
		u32 biascaldone_cri : 1;
		u32 plllock_gain_tran_cri : 1;
		u32 plllock_true_lock_cri : 1;
		u32 pllunlock_flag_cri : 1;
		u32 afcerr_cri : 1;
		u32 afcdone_cri : 1;
		u32 feedfwrdgain_cal_cri_7_0 : 8;
		u32 m2fbdivmod_cri_7_0 : 8;
	} field;
	u32 val;
};

#endif /* _ICE_CGU_REGS_H_ */
