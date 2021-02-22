/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_CGU_UTIL_H_
#define _ICE_CGU_UTIL_H_

/* offset of last valid CGU register */
#define ICE_CGU_MAX_REG_OFFS 0x47c

int ice_cgu_reg_read(struct ice_pf *pf, u32 reg, u32 *val);

int ice_cgu_reg_write(struct ice_pf *pf, u32 reg, u32 val);

int ice_cgu_set_gnd(struct ice_pf *pf, bool enable);

int ice_cgu_set_byp(struct ice_pf *pf, bool enable);

int ice_cgu_set_holdover_lock_irq(struct ice_pf *pf, bool enable);

int ice_cgu_mux_sel_set_reg(struct ice_pf *pf, enum ice_cgu_mux_sel mux_sel, u32 val);

int ice_cgu_dck_rst_assert_release(struct ice_pf *pf, bool assert);

int ice_cgu_dck2_rst_assert_release(struct ice_pf *pf, bool assert);

int ice_cgu_mck_rst_assert_release(struct ice_pf *pf, bool assert);

void ice_cgu_usleep(u64 usec);

int ice_cgu_poll(struct ice_pf *pf, u64 offset, u32 mask, u32 value, u32 delay_time,
		 u32 delay_loops);

int ice_cgu_npoll(struct ice_pf *pf, u32 offset, u32 mask, u32 value, u32 delay_time,
		  u32 delay_loops, u32 poll_count, u32 count_delay_time);

#define ICE_NUM_DPLL_PARAMS (NUM_ICE_CGU_SAMPLE_RATE * NUM_ICE_CGU_DPLL_SELECT)

extern struct ice_cgu_dpll_params dpll_params_table[ICE_NUM_DPLL_PARAMS];

extern struct ice_cgu_dpll_per_rate_params dpll_per_rate_params[NUM_ICE_TIME_REF_FREQ];

extern struct ice_cgu_lcpll_per_rate_params tspll_per_rate_params[NUM_ICE_TIME_REF_FREQ];

extern struct ice_cgu_lcpll_per_rate_params japll_per_rate_params[NUM_ICE_CGU_JAPLL_REF_FREQ];

#endif /* _ICE_CGU_UTIL_H_ */
