// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"

/**
 * ice_cgu_cfg_ts_pll - Configure the TS PLL
 * @pf: Board private structure
 * @enable: True to enable TS PLL
 * @time_ref_freq: Master timer frequency
 * @time_ref_sel: Time source
 * @mstr_tmr_mode: Master timer mode
 */
int ice_cgu_cfg_ts_pll(struct ice_pf *pf, bool enable, enum ice_time_ref_freq time_ref_freq,
		       enum ice_cgu_time_ref_sel time_ref_sel, enum ice_mstr_tmr_mode mstr_tmr_mode)
{
	struct ice_cgu_info *cgu_info = &pf->cgu_info;
	union tspll_ro_bwm_lf bwm_lf;
	union nac_cgu_dword19 dw19;
	union nac_cgu_dword22 dw22;
	union nac_cgu_dword24 dw24;
	union nac_cgu_dword9 dw9;
	int err;

	dev_info(ice_pf_to_dev(pf),
		 "Requested %s, time_ref_freq %s, time_ref_sel %s, mstr_tmr_mode %s\n",
		 enable ? "enable" : "disable", ICE_TIME_REF_FREQ_TO_STR(time_ref_freq),
		 ICE_TIME_REF_SEL_TO_STR(time_ref_sel), ICE_MSTR_TMR_MODE_TO_STR(mstr_tmr_mode));

	if (time_ref_freq >= NUM_ICE_TIME_REF_FREQ) {
		dev_err(ice_pf_to_dev(pf), "Invalid TIME_REF freq %u\n", time_ref_freq);
		return -EIO;
	}

	if (time_ref_sel >= NUM_ICE_CGU_TIME_REF_SEL) {
		dev_err(ice_pf_to_dev(pf), "Invalid TIME_REF sel %u\n", time_ref_sel);
		return -EIO;
	}

	if (mstr_tmr_mode >= NUM_ICE_MSTR_TMR_MODE) {
		dev_err(ice_pf_to_dev(pf), "Invalid mstr_tmr_mode %u\n", mstr_tmr_mode);
		return -EIO;
	}

	if (time_ref_sel == ICE_CGU_TIME_REF_SEL_TCXO &&
	    time_ref_freq != ICE_TIME_REF_FREQ_25_000) {
		dev_err(ice_pf_to_dev(pf),
			"TS PLL source specified as TCXO but specified frequency is not 25 MHz\n");
		return -EIO;
	}

	err = ice_cgu_reg_read(pf, NAC_CGU_DWORD9, &dw9.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD24, &dw24.val);
	if (!err)
		err = ice_cgu_reg_read(pf, TSPLL_RO_BWM_LF, &bwm_lf.val);
	if (err)
		return err;

	dev_info(ice_pf_to_dev(pf),
		 "Before change, %s, time_ref_freq %s, time_ref_sel %s, PLL %s\n",
		 dw24.field.ts_pll_enable ? "enabled" : "disabled",
		 ICE_TIME_REF_FREQ_TO_STR(dw9.field.time_ref_freq_sel),
		 ICE_TIME_REF_SEL_TO_STR(dw24.field.time_ref_sel),
		 bwm_lf.field.plllock_true_lock_cri ? "locked" : "unlocked");

	if (!enable) {
		if (dw24.field.ts_pll_enable) {
			dw24.field.ts_pll_enable = 0;
			err = ice_cgu_reg_write(pf, NAC_CGU_DWORD24, dw24.val);
			if (!err)
				ice_cgu_usleep(1);
		}
		/* don't need to update the freq, sel, or mode; that'll happen
		 * when the PLL is re-enabled
		 */
		return err;
	}

	/* TS PLL must be disabled before changing freq or src */
	if (dw24.field.ts_pll_enable && (dw9.field.time_ref_freq_sel != time_ref_freq ||
					 dw24.field.time_ref_sel != time_ref_sel)) {
		dev_err(ice_pf_to_dev(pf),
			"Can't adjust time_ref_freq or time_ref_sel while TS PLL is enabled\n");
		return -EIO;
	}

	/* set frequency, configure TS PLL params, and enable the TS PLL */
	err = ice_cgu_reg_read(pf, NAC_CGU_DWORD19, &dw19.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD22, &dw22.val);
	if (!err) {
		dw9.field.time_ref_freq_sel = time_ref_freq;
		dw19.field.tspll_fbdiv_intgr = tspll_per_rate_params[time_ref_freq].feedback_div;
		dw19.field.tspll_ndivratio = 1;
		dw22.field.time1588clk_div = tspll_per_rate_params[time_ref_freq].post_pll_div;
		dw22.field.time1588clk_sel_div2 = 0;
		dw24.field.ref1588_ck_div = tspll_per_rate_params[time_ref_freq].refclk_pre_div;
		dw24.field.tspll_fbdiv_frac = tspll_per_rate_params[time_ref_freq].frac_n_div;
		dw24.field.time_ref_sel = time_ref_sel;
		err = ice_cgu_reg_write(pf, NAC_CGU_DWORD9, dw9.val);
	}
	if (!err)
		err = ice_cgu_reg_write(pf, NAC_CGU_DWORD19, dw19.val);
	if (!err)
		err = ice_cgu_reg_write(pf, NAC_CGU_DWORD22, dw22.val);
	/* first write dw24 with updated values but still not enabled */
	if (!err)
		err = ice_cgu_reg_write(pf, NAC_CGU_DWORD24, dw24.val);
	/* now enable the TS_PLL */
	if (!err) {
		dw24.field.ts_pll_enable = 1;
		err = ice_cgu_reg_write(pf, NAC_CGU_DWORD24, dw24.val);
	}

	if (!err) {
		cgu_info->time_ref_freq = time_ref_freq;
		cgu_info->mstr_tmr_mode = mstr_tmr_mode;
		err = ice_ptp_update_incval(pf, time_ref_freq, mstr_tmr_mode);
		if (err) {
			dev_err(ice_pf_to_dev(pf), "Failed to update INCVAL\n");
			return err;
		}
	}

	/* to check for lock, wait 1 ms; if it hasn't locked by then, it's not
	 * going to lock
	 */
	if (!err) {
		ice_cgu_usleep(1000);
		err = ice_cgu_reg_read(pf, TSPLL_RO_BWM_LF, &bwm_lf.val);
	}
	if (!err && bwm_lf.field.plllock_true_lock_cri) {
		dev_info(ice_pf_to_dev(pf),
			 "TS PLL successfully locked, time_ref_freq %s, time_ref_sel %s\n",
			 ICE_TIME_REF_FREQ_TO_STR(time_ref_freq),
			 ICE_TIME_REF_SEL_TO_STR(time_ref_sel));

		/* update state to indicate no unlock event since last lock */
		cgu_info->unlock_event = false;
	} else {
		dev_err(ice_pf_to_dev(pf), "TS PLL failed to lock\n");
		err = -EFAULT;
	}

	return err;
}

/**
 * ice_cgu_init_state - Initialize CGU HW
 * @pf: Board private structure
 *
 * Read CGU registers, initialize internal state, and lock the timestamp PLL using the parameters
 * read from the soft straps.
 */
void ice_cgu_init_state(struct ice_pf *pf)
{
	union tspll_cntr_bist_settings tspll_cntr_bist;
	struct ice_cgu_info *cgu_info = &pf->cgu_info;
	union nac_cgu_dword10 dw10;
	union nac_cgu_dword11 dw11;
	union nac_cgu_dword12 dw12;
	union nac_cgu_dword14 dw14;
	union nac_cgu_dword24 dw24;
	union nac_cgu_dword9 dw9;
	int err;

	init_waitqueue_head(&cgu_info->wq_head);
	mutex_init(&cgu_info->event_mutex);

	err = ice_cgu_reg_read(pf, NAC_CGU_DWORD9, &dw9.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD10, &dw10.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD11, &dw11.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD12, &dw12.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD14, &dw14.val);
	if (!err)
		err = ice_cgu_reg_read(pf, NAC_CGU_DWORD24, &dw24.val);
	if (!err)
		err = ice_cgu_reg_read(pf, TSPLL_CNTR_BIST_SETTINGS, &tspll_cntr_bist.val);
	if (err)
		goto err;

	/* Note that the TIME_SYNC, TIME_REF, and ONE_PPS_OUT pins are enabled
	 * through soft straps.
	 */
	/* Mux config */
	cgu_info->mux_cfg.ref_clk_src = dw10.field.synce_s_ref_clk;
	cgu_info->mux_cfg.byp_clk_src = dw11.field.synce_s_byp_clk;
	cgu_info->mux_cfg.eth_clk_out = dw10.field.synce_ethclko_sel;
	cgu_info->mux_cfg.clk_out = dw10.field.synce_clko_sel;
	cgu_info->mux_cfg.clk_out_div = dw10.field.synce_clkodiv_m1;
	cgu_info->mux_cfg.eth_clk_out_div = dw10.field.synce_ethdiv_m1;
	cgu_info->mux_cfg.bypass = dw12.field.synce_dpll_byp;
	cgu_info->mux_cfg.ref_clk_gnd_ena = dw10.field.synce_sel_gnd;

	/* Timestamp PLL config */
	/* Disable sticky lock detection so lock status reported is accurate */
	tspll_cntr_bist.field.i_plllock_sel_0 = 0;
	tspll_cntr_bist.field.i_plllock_sel_1 = 0;
	err = ice_cgu_reg_write(pf, TSPLL_CNTR_BIST_SETTINGS, tspll_cntr_bist.val);

	/* Assume the 1588 output to CGU isn't configured; require the app to reconfigure it before
	 * using it
	 */
	if (!err)
		cgu_info->out_1588_enabled = false;

	/* first, try to lock the timestamp PLL with the parameters from the soft straps */
	/* disable first, then re-enable with correct parameters */
	err = ice_cgu_cfg_ts_pll(pf, false, dw9.field.time_ref_freq_sel, dw24.field.time_ref_sel,
				 ICE_MSTR_TMR_MODE_NANOSECONDS);
	if (err)
		dev_err(ice_pf_to_dev(pf), "Failed to disable TS PLL\n");
	else
		err = ice_cgu_cfg_ts_pll(pf, true, dw9.field.time_ref_freq_sel,
					 dw24.field.time_ref_sel, ICE_MSTR_TMR_MODE_NANOSECONDS);
	if (err) {
		/* if that fails, try to lock the timestamp PLL with the TCXO
		 */
		dev_info(ice_pf_to_dev(pf),
			 "Unable to lock TS PLL with soft straps settings; trying TCXO\n");

			/* disable first, then re-enable with correct parameters */
			err = ice_cgu_cfg_ts_pll(pf, false, ICE_TIME_REF_FREQ_25_000,
						 ICE_CGU_TIME_REF_SEL_TCXO,
						 ICE_MSTR_TMR_MODE_NANOSECONDS);
		if (err)
			dev_err(ice_pf_to_dev(pf), "Failed to disable TS PLL with TCXO\n");
		else
			err = ice_cgu_cfg_ts_pll(pf, true, ICE_TIME_REF_FREQ_25_000,
						 ICE_CGU_TIME_REF_SEL_TCXO,
						 ICE_MSTR_TMR_MODE_NANOSECONDS);
		if (err) {
			dev_err(ice_pf_to_dev(pf), "Failed to lock TS PLL with TCXO\n");
			goto err;
		}
	}

	dev_info(ice_pf_to_dev(pf), "CGU init successful\n");
	return;
err:
	dev_err(ice_pf_to_dev(pf), "CGU init failed, err=%d\n", err);
}
