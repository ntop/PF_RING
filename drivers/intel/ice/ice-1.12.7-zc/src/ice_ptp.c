/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_irq.h"

static const struct ptp_pin_desc ice_pin_desc_e82x[] = {
	/* name        idx func           chan */
	{ "TIME_SYNC", 0,  PTP_PF_EXTTS,  0, { 0, } },
	{ "1PPS",      1,  PTP_PF_PEROUT, 0, { 0, } },
};

static const struct ptp_pin_desc ice_pin_desc_e810t[] = {
	/* name    idx   func         chan */
	{ "GNSS",  GNSS, PTP_PF_EXTTS, 0, { 0, } },
	{ "SMA1",  SMA1, PTP_PF_NONE, 1, { 0, } },
	{ "U.FL1", UFL1, PTP_PF_NONE, 1, { 0, } },
	{ "SMA2",  SMA2, PTP_PF_NONE, 2, { 0, } },
	{ "U.FL2", UFL2, PTP_PF_NONE, 2, { 0, } },
};

#define MAX_DPLL_NAME_LEN 4
struct ice_dpll_desc {
	char name[MAX_DPLL_NAME_LEN];
	u8 index;
};

static const struct ice_dpll_desc ice_e810t_dplls[] = {
	/* name  idx */
	{ "EEC", ICE_CGU_DPLL_SYNCE },
	{ "PPS", ICE_CGU_DPLL_PTP },
};

struct dpll_attribute {
	struct device_attribute attr;
	u8 dpll_num;
};

static ssize_t synce_store(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t count);

static ssize_t tx_clk_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buf, size_t count);
static ssize_t clock_1588_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len);

static ssize_t pin_cfg_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t len);

static ssize_t ts_pll_cfg_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len);

static ssize_t pin_cfg_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf);

static ssize_t dpll_1_offset_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf);

static ssize_t dpll_name_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf);

static ssize_t dpll_state_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf);

static ssize_t dpll_ref_pin_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf);
static ssize_t ts_pll_cfg_show(struct device *dev,
			       struct device_attribute *attr, char *buf);

static struct kobj_attribute synce_attribute = __ATTR_WO(synce);
static DEVICE_ATTR_RW(pin_cfg);
static struct kobj_attribute tx_clk_attribute = __ATTR_WO(tx_clk);
static DEVICE_ATTR_WO(clock_1588);
static DEVICE_ATTR_RO(dpll_1_offset);
static struct dpll_attribute *dpll_name_attrs;
static struct dpll_attribute *dpll_state_attrs;
static struct dpll_attribute *dpll_ref_pin_attrs;
static DEVICE_ATTR_RW(ts_pll_cfg);

#define DPLL_MAX_INPUT_PIN_PRIO	14
#define DPLL_DISABLE_INPUT_PIN_PRIO	0xFF
/**
 * ice_ptp_parse_and_apply_pin_prio - parse and apply pin prio from the buffer
 * @pf: pointer to a pf structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse pin prio config from the split user buffer and apply it on given pin.
 * Return 0 on success, negative value otherwise
 */
static int
ice_ptp_parse_and_apply_pin_prio(struct ice_pf *pf, int argc, char **argv)
{
	u8 dpll = 0, pin = 0, prio = 0;
	int i, ret;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "prio", sizeof("prio")))
			ret = kstrtou8(argv[++i], 0, &prio);
		else if (!strncmp(argv[i], "dpll", sizeof("dpll")))
			ret = kstrtou8(argv[++i], 0, &dpll);
		else if (!strncmp(argv[i], "pin", sizeof("pin")))
			ret = kstrtou8(argv[++i], 0, &pin);
		else
			ret = -EINVAL;

		if (ret)
			return ret;
	}

	/* priority needs to be in range 0-14 */
	if (prio > DPLL_MAX_INPUT_PIN_PRIO &&
	    prio != DPLL_DISABLE_INPUT_PIN_PRIO)
		return -EINVAL;

	dev_info(ice_pf_to_dev(pf), "%s: dpll: %u, pin:%u, prio:%u\n",
		 __func__, dpll, pin, prio);
	return ice_aq_set_cgu_ref_prio(&pf->hw, dpll, pin, prio);
}

/**
 * ice_ptp_parse_and_apply_output_pin_cfg - parse and apply output pin config
 * @pf: pointer to a pf structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse and apply given configuration items in a split user buffer for the
 * output pin.
 * Return 0 on success, negative value otherwise
 */
static int
ice_ptp_parse_and_apply_output_pin_cfg(struct ice_pf *pf, int argc, char **argv)
{
	u8 output_idx, flags = 0, old_flags, old_src_sel;
	u32 freq = 0, old_freq, old_src_freq;
	struct ice_hw *hw = &pf->hw;
	bool esync_en_valid = false;
	bool pin_en_valid = false;
	bool esync_en = false;
	bool pin_en = false;
	s32 phase_delay = 0;
	int i, ret;

	output_idx = ICE_PTP_PIN_INVALID;
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "pin", sizeof("pin"))) {
			ret = kstrtou8(argv[++i], 0, &output_idx);
		} else if (!strncmp(argv[i], "freq", sizeof("freq"))) {
			ret = kstrtou32(argv[++i], 0, &freq);
			flags |= ICE_AQC_SET_CGU_OUT_CFG_UPDATE_FREQ;
		} else if (!strncmp(argv[i], "phase_delay",
				    sizeof("phase_delay"))) {
			ret = kstrtos32(argv[++i], 0, &phase_delay);
			flags |= ICE_AQC_SET_CGU_OUT_CFG_UPDATE_PHASE;
		} else if (!strncmp(argv[i], "esync", sizeof("esync"))) {
			ret = kstrtobool(argv[++i], &esync_en);
			esync_en_valid = true;
		} else if (!strncmp(argv[i], "enable", sizeof("enable"))) {
			ret = kstrtobool(argv[++i], &pin_en);
			pin_en_valid = true;
		} else {
			ret = -EINVAL;
		}

		if (ret)
			return ret;
	}

	if (!esync_en_valid || !pin_en_valid) {
		ret = ice_aq_get_output_pin_cfg(hw, output_idx,
						&old_flags,
						&old_src_sel,
						&old_freq,
						&old_src_freq);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"Failed to read prev output pin cfg (%u:%s)",
				ret, ice_aq_str(hw->adminq.sq_last_status));
			return ret;
		}
	}

	if (!esync_en_valid)
		if (old_flags & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		else
			flags &= ~ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
	else
		if (esync_en)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		else
			flags &= ~ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;

	if (!pin_en_valid)
		if (old_flags & ICE_AQC_SET_CGU_OUT_CFG_OUT_EN)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
		else
			flags &= ~ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
	else
		if (pin_en)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
		else
			flags &= ~ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;

	dev_info(ice_pf_to_dev(pf),
		 "output pin:%u, enable: %u, freq:%u, phase_delay:%u, esync:%u, flags:%u\n",
		 output_idx, pin_en, freq, phase_delay, esync_en,
		 flags);
	return ice_aq_set_output_pin_cfg(hw, output_idx, flags,
					 0, freq, phase_delay);
}

/**
 * ice_ptp_parse_and_apply_input_pin_cfg - parse and apply input pin config
 * @pf: pointer to a pf structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse and apply given list of configuration items for the input pin.
 * Return 0 on success, negative value otherwise
 */
static int
ice_ptp_parse_and_apply_input_pin_cfg(struct ice_pf *pf, int argc, char **argv)
{
	struct ice_aqc_get_cgu_input_config old_cfg = {0};
	u8 flags1 = 0, flags2 = 0, input_idx;
	struct ice_hw *hw = &pf->hw;
	bool esync_en_valid = false;
	bool pin_en_valid = false;
	u8 esync_refsync_en = 0;
	bool esync_en = false;
	bool pin_en = false;
	s32 phase_delay = 0;
	u32 freq = 0;
	int i, ret;

	input_idx = ICE_PTP_PIN_INVALID;
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "pin", sizeof("pin"))) {
			ret = kstrtou8(argv[++i], 0, &input_idx);
		} else if (!strncmp(argv[i], "freq", sizeof("freq"))) {
			ret = kstrtou32(argv[++i], 0, &freq);
			flags1 |= ICE_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ;
		} else if (!strncmp(argv[i], "phase_delay",
				    sizeof("phase_delay"))) {
			ret = kstrtos32(argv[++i], 0, &phase_delay);
			flags1 |= ICE_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_DELAY;
		} else if (!strncmp(argv[i], "esync", sizeof("esync"))) {
			ret = kstrtobool(argv[++i], &esync_en);
			esync_refsync_en = esync_en ?
					   ICE_AQC_SET_CGU_IN_CFG_ESYNC_EN : 0;
			esync_en_valid = true;
			dev_warn_once(ice_pf_to_dev(pf), "The 'esync' setting has been deprecated, please use 'e_ref_sync.\n");
		} else if (!strncmp(argv[i], "e_ref_sync",
			   sizeof("e_ref_sync"))) {
			ret = kstrtou8(argv[++i], 0, &esync_refsync_en);
			esync_en_valid = true;
		} else if (!strncmp(argv[i], "enable", sizeof("enable"))) {
			ret = kstrtobool(argv[++i], &pin_en);
			pin_en_valid = true;
		} else {
			ret = -EINVAL;
		}

		if (ret)
			return ret;
	}

	/* esync/refsync valid values 0,1,2 */
	if (esync_refsync_en > ICE_AQC_GET_CGU_IN_CFG_REFSYNC_EN)
		return -EINVAL;

	/* refsync is not allowed on any pin */
	if (esync_refsync_en == ICE_AQC_GET_CGU_IN_CFG_REFSYNC_EN &&
	    !refsync_pin_id_valid(hw, input_idx)) {
		dev_warn(ice_pf_to_dev(pf), "Ref-sync is not allowed on pin %d. Use pin 1 or pin 5.\n",
			 input_idx);
		return -EINVAL;
	}

	if (!esync_en_valid || !pin_en_valid) {
		ret = ice_aq_get_input_pin_cfg(hw, &old_cfg, input_idx);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"Failed to read prev intput pin cfg (%u:%s)",
				ret, ice_aq_str(hw->adminq.sq_last_status));
			return ret;
		}
	}

	if (flags1 == ICE_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ &&
	    !(old_cfg.flags1 & ICE_AQC_GET_CGU_IN_CFG_FLG1_ANYFREQ)) {
		if (freq != ICE_PTP_PIN_FREQ_1HZ &&
		    freq != ICE_PTP_PIN_FREQ_10MHZ) {
			dev_err(ice_pf_to_dev(pf),
				"Only %i or %i freq supported\n",
				ICE_PTP_PIN_FREQ_1HZ,
				ICE_PTP_PIN_FREQ_10MHZ);
			return -EINVAL;
		}
	}

	if (!esync_en_valid) {
		flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN;
		flags2 |= old_cfg.flags2 &
		       ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN;
	} else {
		flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN;
		flags2 |= esync_refsync_en <<
			  ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN_SHIFT;
	}

	if (!pin_en_valid)
		if (old_cfg.flags2 & ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN)
			flags2 |= ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		else
			flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
	else
		if (pin_en)
			flags2 |= ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		else
			flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;

	dev_info(ice_pf_to_dev(pf),
		 "input pin:%u, enable: %u, freq:%u, phase_delay:%u, e_ref_sync:%u, flags1:%u, flags2:%u\n",
		  input_idx, pin_en, freq, phase_delay, esync_refsync_en,
		  flags1, flags2);
	return ice_aq_set_input_pin_cfg(&pf->hw, input_idx, flags1, flags2,
					freq, phase_delay);
}

/**
 * synce_store_e825c - setting PHY recovered clock pins in E825-C
 * @pf: pointer to pf structure
 * @ena:  true if enable, false in disable
 * @phy_pin:   pin to be enabled/disabled
 *
 * Return number of bytes written on success or negative value on failure.
 */
static int
synce_store_e825c(struct ice_pf *pf, unsigned int ena, unsigned int phy_pin)
{
	struct ice_ptp_port *ptp_port;
	struct ice_hw *hw;
	int status;
	u8 divider;

	/* TODO: It turned out we also need to set the SYNCE_CLK1, add it!*/
	if (phy_pin > 0)
		return -EINVAL;

	ptp_port = &pf->ptp.port;
	hw = &pf->hw;

	/* configure the mux to deliver proper signal to DPLL from the MUX */
	status = ice_cfg_cgu_bypass_mux_e825c(hw, ptp_port->port_num, false,
					      ena);
	if (status)
		return status;

	/* we need to reconfigure the divider if feature is set */
	if (test_bit(ICE_FLAG_ITU_G8262_FILTER_USED, pf->flags)) {
		status = ice_cfg_synce_ethdiv_e825c(hw, &divider);
		if (status)
			return status;

		dev_dbg(ice_hw_to_dev(&pf->hw),
			"SyncE clock divider set to %u\n", divider);
	}

	dev_info(ice_hw_to_dev(&pf->hw), "CLK_SYNCE0 recovered clock: pin %s\n",
		 !!ena ? "Enabled" : "Disabled");

	return 0;
}

/**
 * synce_store_common - setting PHY recovered clock pins in generic devices
 * @pf: pointer to pf structure
 * @ena:  true if enable, false in disable
 * @phy_pin:   pin to be enabled/disabled
 *
 * Return number of bytes written on success or negative value on failure.
 */
static int
synce_store_common(struct ice_pf *pf, unsigned int ena, unsigned int phy_pin)
{
	const char *pin_name;
	u32 freq = 0;
	u8 pin, phy;
	int status;

	if (phy_pin >= ICE_C827_RCLK_PINS_NUM)
		return -EINVAL;

	status = ice_aq_set_phy_rec_clk_out(&pf->hw, phy_pin, !!ena, &freq);
	if (status)
		return -EIO;

	if (ice_is_e810(&pf->hw)) {
		status = ice_get_pf_c827_idx(&pf->hw, &phy);
		if (status)
			return -EIO;

		pin = E810T_CGU_INPUT_C827(phy, phy_pin);
		pin_name = ice_zl_pin_idx_to_name_e810t(pin);
	} else {
		/* e822-based devices for now have only one phy available
		 *  (from Rimmon) and only one DPLL RCLK input pin
		 */
		pin_name = E822_CGU_RCLK_PIN_NAME;
	}

	dev_info(ice_hw_to_dev(&pf->hw), "%s recovered clock: pin %s\n",
		 !!ena ? "Enabled" : "Disabled", pin_name);

	return 0;
}

/**
 * synce_store - sysfs interface for setting PHY recovered clock pins
 * @kobj:  sysfs node
 * @attr:  sysfs node attributes
 * @buf:   string representing enable and pin number
 * @count: length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t
synce_store(struct kobject *kobj, struct kobj_attribute *attr,
	    const char *buf, size_t count)
{
	unsigned int ena, phy_pin;
	struct ice_pf *pf;
	int status, cnt;

	pf = ice_kobj_to_pf(kobj);
	if (!pf)
		return -EPERM;

	cnt = sscanf(buf, "%u %u", &ena, &phy_pin);
	if (cnt != 2)
		return -EINVAL;

	if (ice_is_e825c(&pf->hw))
		status = synce_store_e825c(pf, ena, phy_pin);
	else
		status = synce_store_common(pf, ena, phy_pin);
	if (status)
		return status;

	return count;
}

/**
 * tx_clk_store - sysfs interface for changing TX clock for a given port
 * @kobj:  sysfs node
 * @attr:  sysfs node attributes
 * @buf:   string representing enable and pin number
 * @count: length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t
tx_clk_store(struct kobject *kobj, struct kobj_attribute *attr,
	     const char *buf, size_t count)
{
	struct ice_pf *pf;
	unsigned int clk;
	int status;
	u8 port;

	pf = ice_kobj_to_pf(kobj);
	if (!pf)
		return -EPERM;

	if (kstrtouint(buf, 0, &clk))
		return -EINVAL;

	if (clk >= ICE_REF_CLK_MAX)
		return -EINVAL;

	port = pf->ptp.port.port_num;
	status = ice_change_tx_clk_eth56g(&pf->hw, port,
					  (enum ice_e825c_ref_clk)clk);
	if (status) {
		dev_err(ice_hw_to_dev(&pf->hw), "Failed setting TX CLK for port %u\n",
			port);
		return status;
	}

	dev_err(ice_hw_to_dev(&pf->hw), "Successfully set TX CLK for port %u\n",
		port);

	return count;
}

/**
 * clock_1588_store - sysfs interface for setting 1588 clock as SyncE source
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 * @len:   length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t clock_1588_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ice_pf *pf;
	struct ice_hw *hw;
	int status, cnt;
	u32 ena, pin;
	u8 divider;

	pf = pci_get_drvdata(pdev);
	hw = &pf->hw;

	if (ice_is_reset_in_progress(pf->state))
		return -EAGAIN;

	cnt = sscanf(buf, "%u %u", &ena, &pin);
	if (cnt != 2)
		return -EINVAL;

	if (pin > 0)
		return -EINVAL;

	/* configure the mux to deliver proper signal to DPLL from the MUX */
	status = ice_cfg_cgu_bypass_mux_e825c(hw, 0, true, ena);
	if (status)
		return status;

	/*
	 * TODO: What is the divider for this 1588 clock?
	 */
	/* we need to reconfigure the divider for 1588 clock */
	status = ice_cfg_synce_ethdiv_e825c(hw, &divider);
	if (status)
		return status;

	dev_dbg(ice_hw_to_dev(&pf->hw), "SyncE clock divider set to %u\n",
		divider);

	dev_info(ice_hw_to_dev(&pf->hw), "CLK_SYNCE0 recovered clock: 1588 ref %s\n",
		 !!ena ? "Enabled" : "Disabled");

	return len;
}

/**
 * pin_cfg_store - sysfs interface callback for configuration of pins
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 * @len:   length of the 'buf' string
 *
 * Allows set new configuration of a pin, given in a user buffer.
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t pin_cfg_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ice_pf *pf;
	int argc, ret;
	char **argv;

	pf = pci_get_drvdata(pdev);
	if (ice_is_reset_in_progress(pf->state))
		return -EAGAIN;

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;

	if (argc == ICE_PTP_PIN_PRIO_ARG_CNT) {
		ret = ice_ptp_parse_and_apply_pin_prio(pf, argc, argv);
	} else if (argc == ICE_PTP_PIN_CFG_1_ARG_CNT ||
		   argc == ICE_PTP_PIN_CFG_2_ARG_CNT ||
		   argc == ICE_PTP_PIN_CFG_3_ARG_CNT ||
		   argc == ICE_PTP_PIN_CFG_4_ARG_CNT) {
		if (!strncmp(argv[0], "in", sizeof("in"))) {
			ret = ice_ptp_parse_and_apply_input_pin_cfg(pf,
								    argc - 1,
								    argv + 1);
		} else if (!strncmp(argv[0], "out", sizeof("out"))) {
			ret = ice_ptp_parse_and_apply_output_pin_cfg(pf,
								     argc - 1,
								     argv + 1);
		} else {
			ret = -EINVAL;
			dev_dbg(ice_pf_to_dev(pf),
				"%s: wrong pin direction argument:%s\n",
				__func__, argv[0]);
		}
	} else {
		ret = -EINVAL;
		dev_dbg(ice_pf_to_dev(pf),
			"%s: wrong number of arguments:%d\n",
			__func__, argc);
	}

	if (!ret)
		ret = len;
	argv_free(argv);

	return ret;
}

/**
 * ice_ptp_load_output_pin_cfg - load formated output pin config into buffer
 * @pf: pointer to pf structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 * @pin_num: number of output pins to be printed
 *
 * Acquires configuration of output pins from FW and load it into
 * provided user buffer.
 * Returns total number of bytes written to the buffer.
 * Negative on failure.
 */
static int
ice_ptp_load_output_pin_cfg(struct ice_pf *pf, char *buf, ssize_t offset,
			    const u8 pin_num)
{
	u8 pin, pin_en, esync_en, dpll, flags;
	struct ice_hw *hw = &pf->hw;
	int count = offset;
	u32 freq, src_freq;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "out");
	count += scnprintf(buf + count, PAGE_SIZE,
			   "|%4s|%8s|%5s|%11s|%6s|\n",
			   "pin", "enabled", "dpll", "freq", "esync");
	for (pin = 0; pin < pin_num; ++pin) {
		int ret = ice_aq_get_output_pin_cfg(hw, pin, &flags,
						    &dpll, &freq, &src_freq);

		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"err:%d %s failed to read output pin cfg on pin:%u\n",
				ret, ice_aq_str(hw->adminq.sq_last_status),
				pin);
			return ret;
		}
		esync_en = !!(flags & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN);
		pin_en = !!(flags & ICE_AQC_GET_CGU_OUT_CFG_OUT_EN);
		dpll &= ICE_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL;
		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%5u|%11u|%6u|\n",
				   pin, pin_en, dpll, freq, esync_en);
	}

	return count;
}

/**
 * ice_ptp_load_input_pin_cfg - load formated input pin config into buffer
 * @pf: pointer to pf structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 * @pin_num: number of input pins to be printed
 *
 * Acquires configuration of input pins from FW and load it into
 * provided user buffer.
 * Returns total number of bytes written to the buffer.
 * Negative on failure.
 */
static int
ice_ptp_load_input_pin_cfg(struct ice_pf *pf, char *buf,
			   ssize_t offset, const u8 pin_num)
{
	u8 pin, pin_en, esync_refsync_en, esync_fail, dpll0_prio, dpll1_prio;
	struct ice_aqc_get_cgu_input_config in_cfg;
	struct ice_hw *hw = &pf->hw;
	const char *pin_state;
	int count = offset;
	s32 phase_delay;
	u32 freq;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "in");
	count += scnprintf(buf + count, PAGE_SIZE,
			  "|%4s|%8s|%8s|%11s|%12s|%15s|%11s|%11s|\n",
			   "pin", "enabled", "state", "freq", "phase_delay",
			   "eSync/Ref-sync", "DPLL0 prio", "DPLL1 prio");
	for (pin = 0; pin < pin_num; ++pin) {
		int ret;

		memset(&in_cfg, 0, sizeof(in_cfg));
		ret = ice_aq_get_input_pin_cfg(hw, &in_cfg, pin);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"err:%d %s failed to read input pin cfg on pin:%u\n",
				ret, ice_aq_str(hw->adminq.sq_last_status),
				pin);
			return ret;
		}

		ret = ice_aq_get_cgu_ref_prio(hw, ICE_CGU_DPLL_SYNCE,
					      pin, &dpll0_prio);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"err:%d %s failed to read DPLL0 pin prio on pin:%u\n",
				ret, ice_aq_str(hw->adminq.sq_last_status),
				pin);
			return ret;
		}

		ret = ice_aq_get_cgu_ref_prio(hw, ICE_CGU_DPLL_PTP,
					      pin, &dpll1_prio);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"err:%d %s failed to read DPLL1 pin prio on pin:%u\n",
				ret, ice_aq_str(hw->adminq.sq_last_status),
				pin);
			return ret;
		}

		esync_refsync_en = (in_cfg.flags2 &
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN) >>
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN_SHIFT;
		esync_fail = !!(in_cfg.status &
				ICE_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_FAIL);
		pin_en = !!(in_cfg.flags2 &
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN);
		phase_delay = le32_to_cpu(in_cfg.phase_delay);
		freq = le32_to_cpu(in_cfg.freq);

		if (in_cfg.status & ICE_CGU_IN_PIN_FAIL_FLAGS)
			pin_state = ICE_DPLL_PIN_STATE_INVALID;
		else if (esync_refsync_en == ICE_AQC_GET_CGU_IN_CFG_ESYNC_EN &&
			 esync_fail)
			pin_state = ICE_DPLL_PIN_STATE_INVALID;
		else
			pin_state = ICE_DPLL_PIN_STATE_VALID;

		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%8s|%11u|%12d|%15u|%11u|%11u|\n",
				   in_cfg.input_idx, pin_en, pin_state, freq,
				   phase_delay, esync_refsync_en, dpll0_prio,
				   dpll1_prio);
	}

	return count;
}

/**
 * ice_ptp_load_pin_cfg - load formated pin config into user buffer
 * @pf: pointer to pf structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 *
 * Acquires configuration from FW and load it into provided buffer.
 * Returns total number of bytes written to the buffer
 */
static ssize_t
ice_ptp_load_pin_cfg(struct ice_pf *pf, char *buf, ssize_t offset)
{
	struct ice_aqc_get_cgu_abilities abilities;
	struct ice_hw *hw = &pf->hw;
	int ret;

	ret = ice_aq_get_cgu_abilities(hw, &abilities);
	if (ret) {
		dev_err(ice_pf_to_dev(pf),
			"err:%d %s failed to read cgu abilities\n",
			ret, ice_aq_str(hw->adminq.sq_last_status));
		return ret;
	}

	ret = ice_ptp_load_input_pin_cfg(pf, buf, offset,
					 abilities.num_inputs);
	if (ret < 0)
		return ret;
	offset += ret;
	ret = ice_ptp_load_output_pin_cfg(pf, buf, offset,
					  abilities.num_outputs);
	if (ret < 0)
		return ret;
	ret += offset;

	return ret;
}

/**
 * pin_cfg_show - sysfs interface callback for reading pin_cfg file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t pin_cfg_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ice_pf *pf;

	pf = pci_get_drvdata(pdev);

	return ice_ptp_load_pin_cfg(pf, buf, 0);
}

/**
 * dpll_name_show - sysfs interface callback for reading dpll_name file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t dpll_name_show(struct device __always_unused *dev,
			      struct device_attribute *attr, char *buf)
{
	struct dpll_attribute *dpll_attr;
	u8 dpll_num;

	dpll_attr = container_of(attr, struct dpll_attribute, attr);
	dpll_num = dpll_attr->dpll_num;

	if (dpll_num < ICE_CGU_DPLL_MAX)
		return snprintf(buf, PAGE_SIZE, "%s\n",
				ice_e810t_dplls[dpll_num].name);

	return -EINVAL;
}

/**
 * dpll_state_show - sysfs interface callback for reading dpll_state file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns number of bytes written to the buffer or negative value on error
 */
static ssize_t dpll_state_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpll_attribute *dpll_attr;
	enum ice_cgu_state *dpll_state;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	ssize_t cnt;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);
	dpll_attr = container_of(attr, struct dpll_attribute, attr);

	switch (dpll_attr->dpll_num) {
	case ICE_CGU_DPLL_SYNCE:
		dpll_state = &pf->synce_dpll_state;
		break;
	case ICE_CGU_DPLL_PTP:
		dpll_state = &pf->ptp_dpll_state;
		break;
	default:
		return -EINVAL;
	}

	cnt = snprintf(buf, PAGE_SIZE, "%d\n", *dpll_state);

	return cnt;
}

/**
 * dpll_ref_pin_show - sysfs callback for reading dpll_ref_pin file
 *
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns number of bytes written to the buffer or negative value on error
 */
static ssize_t dpll_ref_pin_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct dpll_attribute *dpll_attr;
	enum ice_cgu_state *dpll_state;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	ssize_t cnt;
	u8 pin;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);
	dpll_attr = container_of(attr, struct dpll_attribute, attr);

	switch (dpll_attr->dpll_num) {
	case ICE_CGU_DPLL_SYNCE:
		dpll_state = &pf->synce_dpll_state;
		pin = pf->synce_ref_pin;
		break;
	case ICE_CGU_DPLL_PTP:
		dpll_state = &pf->ptp_dpll_state;
		pin = pf->ptp_ref_pin;
		break;
	default:
		return -EINVAL;
	}

	switch (*dpll_state) {
	case ICE_CGU_STATE_LOCKED:
	case ICE_CGU_STATE_LOCKED_HO_ACQ:
	case ICE_CGU_STATE_HOLDOVER:
		cnt = snprintf(buf, PAGE_SIZE, "%d\n", pin);
		break;
	default:
		return -EAGAIN;
	}

	return cnt;
}

/**
 * dpll_1_offset_show - sysfs interface callback for reading dpll_1_offset file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Returns number of bytes written to the buffer or negative value on error
 */
static ssize_t dpll_1_offset_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev;
	struct ice_pf *pf;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	return snprintf(buf, PAGE_SIZE, "%lld\n", pf->ptp_dpll_phase_offset);
}

/**
 * ice_ptp_set_e82x_ts_pll_params - set TS PLL params for all PFs
 * @pf: Board private structure
 * @time_ref_freq: TIME_REF frequency to use
 * @clk_src: source of the clock signal
 * @src_tmr_mode: source timer mode (nanoseconds or locked)
 */
static void ice_ptp_set_e82x_ts_pll_params(struct ice_pf *pf,
					   enum ice_time_ref_freq time_ref_freq,
					   enum ice_clk_src clk_src,
					   enum ice_src_tmr_mode src_tmr_mode)
{
	struct ice_ptp_port *port;

	list_for_each_entry(port, &pf->ptp.ports_owner.ports, list_member) {
		struct ice_pf *target_pf = ptp_port_to_pf(port);

		if (target_pf->hw.phy_model != ICE_PHY_ETH56G)
			ice_set_e822_time_ref(&target_pf->hw, time_ref_freq);
		target_pf->ptp.src_tmr_mode = src_tmr_mode;
		target_pf->ptp.clk_src = clk_src;
	}
}

/**
 * ts_pll_cfg_store - sysfs interface for setting TS PLL config
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 * @len:   length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t
ts_pll_cfg_store(struct device *dev, struct device_attribute *attr,
		 const char *buf, size_t len)
{
	u32 time_ref_freq, clk_src, src_tmr_mode;
	struct pci_dev *pdev = to_pci_dev(dev);
	enum ice_time_ref_freq time_ref;
	enum ice_src_tmr_mode tmr_mode;
	enum ice_clk_src clk;
	struct ice_pf *pf;
	int argc, ret;
	char **argv;

	pf = pci_get_drvdata(pdev);
	if (ice_is_reset_in_progress(pf->state))
		return -EAGAIN;

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;

	if (argc != 3)
		goto command_help;

	ret = kstrtou32(argv[0], 0, &time_ref_freq);
	if (ret)
		goto command_help;
	ret = kstrtou32(argv[1], 0, &clk_src);
	if (ret)
		goto command_help;
	ret = kstrtou32(argv[2], 0, &src_tmr_mode);
	if (ret)
		goto command_help;

	if (src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED &&
	    clk_src != ICE_CLK_SRC_TIME_REF) {
		dev_info(ice_pf_to_dev(pf), "Locked mode available only with TIME_REF as source\n");
		return -EIO;
	}

	time_ref = (enum ice_time_ref_freq)time_ref_freq;
	clk = (enum ice_clk_src)clk_src;
	tmr_mode = (enum ice_src_tmr_mode)src_tmr_mode;

	if (ice_is_e825c(&pf->hw))
		ret = ice_cfg_cgu_pll_e825c(&pf->hw, &time_ref, &clk);
	else
		ret = ice_cfg_cgu_pll_e822(&pf->hw, &time_ref, &clk);
	if (ret)
		return ret;
	ice_ptp_set_e82x_ts_pll_params(pf, time_ref, clk, tmr_mode);
	ret = ice_ptp_update_incval(pf, time_ref, tmr_mode);
	if (ret)
		return ret;

	return len;

command_help:
	dev_info(ice_pf_to_dev(pf), "Usage: <time_ref_freq> <clk_src> <src_tmr_mode>\ntime_ref_freq (MHz): 0 = 25, 1 = 122, 2 = 125, 3 = 153, 4 = 156.25, 5 = 245.76\nclk_src: 0 = TCXO, 1 = TIME_REF\nsrc_tmr_mode: 0 = NS MODE, 1 = LOCKED MODE\n");
	return -EIO;
}

/**
 * ice_src_tmr_mode_str - Convert src_tmr_mode to string
 * @src_tmr_mode: Source clock mode
 *
 * Convert the specified TIME_REF clock frequency to a string.
 */
static const char *ice_src_tmr_mode_str(enum ice_src_tmr_mode src_tmr_mode)
{
	switch (src_tmr_mode) {
	case ICE_SRC_TMR_MODE_NANOSECONDS:
		return "NS MODE";
	case ICE_SRC_TMR_MODE_LOCKED:
		return "LOCKED MODE";
	default:
		return "Unknown";
	}
}

#define TS_PLL_CFG_BUFF_SIZE	30
/**
 * ts_pll_cfg_show - sysfs callback for reading ts_pll_cfg file
 *
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t
ts_pll_cfg_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev;
	struct ice_pf *pf;
	size_t cnt;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	cnt = snprintf(buf, TS_PLL_CFG_BUFF_SIZE, "%s %s %s\n",
		       ice_clk_freq_str(ice_e822_time_ref(&pf->hw)),
		       ice_clk_src_str(pf->ptp.clk_src),
		       ice_src_tmr_mode_str(pf->ptp.src_tmr_mode));
	return cnt;
}

/**
 * ice_phy_sysfs_init - initialize sysfs for DPLL
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling DPLL in HW.
 */
static void ice_phy_sysfs_init(struct ice_pf *pf)
{
	struct kobject *phy_kobj;

	phy_kobj = kobject_create_and_add("phy", &pf->pdev->dev.kobj);
	if (!phy_kobj) {
		dev_warn(ice_pf_to_dev(pf), "Failed to create PHY kobject\n");
		return;
	}

	if (sysfs_create_file(phy_kobj, &synce_attribute.attr)) {
		dev_warn(ice_pf_to_dev(pf), "Failed to create synce sysfs file\n");
		kobject_put(phy_kobj);
		return;
	}

	if (ice_is_e825c(&pf->hw) &&
	    sysfs_create_file(phy_kobj, &tx_clk_attribute.attr)) {
		dev_warn(ice_pf_to_dev(pf), "Failed to create synce tx_clk file\n");
		kobject_put(phy_kobj);
		return;
	}

	pf->ptp.phy_kobj = phy_kobj;
}

/**
 * ice_pin_cfg_sysfs_init - initialize sysfs for pin_cfg
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling pin configuration in DPLL.
 */
static void ice_pin_cfg_sysfs_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_pin_cfg))
		dev_warn(ice_pf_to_dev(pf), "Failed to create pin_cfg sysfs file\n");
}

/**
 * ice_clock_1588_sysfs_init - initialize sysfs for 1588 SyncE clock source
 * @pf: pointer to pf structure
 */
static void ice_clock_1588_sysfs_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_clock_1588))
		dev_warn(ice_pf_to_dev(pf), "Failed to create clock_1588 sysfs file\n");
}

/**
 * ice_dpll_1_offset_init - initialize sysfs for dpll_1_offset
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling dpll_1_offset in DPLL.
 */
static void ice_dpll_1_offset_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_dpll_1_offset))
		dev_warn(ice_pf_to_dev(pf),
			 "Failed to create dpll_1_offset sysfs file\n");
}

/**
 * ice_dpll_attrs_init - initialize sysfs for dpll_attribute
 * @pf: pointer to pf structure
 * @name_suffix: sysfs file name suffix
 * @show: pointer to a show operation handler
 *
 * Helper function to allocate and initialize sysfs for dpll_attribute array
 * Returns pointer to dpll_attribute struct on success, ERR_PTR on error
 */
static struct dpll_attribute *
ice_dpll_attrs_init(struct ice_pf *pf, const char *name_suffix,
		    ssize_t (*show)(struct device *dev,
				    struct device_attribute *attr, char *buf))
{
	struct device *dev = ice_pf_to_dev(pf);
	struct dpll_attribute *dpll_attr;
	int err, i = 0;
	char *name;

	dpll_attr = devm_kcalloc(dev, ICE_CGU_DPLL_MAX, sizeof(*dpll_attr),
				 GFP_KERNEL);

	if (!dpll_attr) {
		err = -ENOMEM;
		goto err;
	}

	for (i = 0; i < ICE_CGU_DPLL_MAX; ++i) {
		name = devm_kasprintf(dev, GFP_KERNEL, "dpll_%u_%s", i,
				      name_suffix);
		if (!name) {
			err = -ENOMEM;
			goto err;
		}

		dpll_attr[i].attr.attr.name = name;
		dpll_attr[i].attr.attr.mode = 0444;
		dpll_attr[i].attr.show = show;
		dpll_attr[i].dpll_num = i;

		sysfs_bin_attr_init(&dpll_attr[i].attr);
		err = device_create_file(dev, &dpll_attr[i].attr);
		if (err) {
			devm_kfree(dev, name);
			goto err;
		}
	}

	return dpll_attr;

err:
	while (--i >= 0) {
		devm_kfree(dev, (char *)dpll_attr[i].attr.attr.name);
		device_remove_file(dev, &dpll_attr[i].attr);
	}

	devm_kfree(dev, dpll_attr);

	dev_warn(dev, "Failed to create %s sysfs files\n", name_suffix);
	return (struct dpll_attribute *)ERR_PTR(err);
}

/**
 * ice_ts_pll_sysfs_init - initialize sysfs for internal TS PLL
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling TS PLL in HW.
 */
static void ice_ts_pll_sysfs_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_ts_pll_cfg))
		dev_dbg(ice_pf_to_dev(pf),
			"Failed to create ts_pll_cfg kobject\n");
}

/**
 * ice_ptp_sysfs_init - initialize sysfs for ptp and synce features
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling configuration of ptp and synce features.
 */
static void ice_ptp_sysfs_init(struct ice_pf *pf)
{
	if (ice_is_feature_supported(pf, ICE_F_PHY_RCLK))
		ice_phy_sysfs_init(pf);

	if (ice_pf_src_tmr_owned(pf) &&
	    ice_is_feature_supported(pf, ICE_F_CGU)) {
		ice_pin_cfg_sysfs_init(pf);
		ice_dpll_1_offset_init(pf);
		dpll_name_attrs = ice_dpll_attrs_init(pf, "name",
						      dpll_name_show);
		dpll_state_attrs = ice_dpll_attrs_init(pf, "state",
						       dpll_state_show);
		dpll_ref_pin_attrs = ice_dpll_attrs_init(pf, "ref_pin",
							 dpll_ref_pin_show);
	}

	if (ice_is_e825c(&pf->hw) && ice_pf_src_tmr_owned(pf))
		ice_clock_1588_sysfs_init(pf);
	if (ice_pf_src_tmr_owned(pf) &&
	    (ice_is_e823(&pf->hw) || ice_is_e825c(&pf->hw)))
		ice_ts_pll_sysfs_init(pf);
}

/**
 * ice_ptp_sysfs_release - release sysfs resources of ptp and synce features
 * @pf: pointer to pf structure
 *
 * Release sysfs interface resources for handling configuration of
 * ptp and synce features.
 */
static void ice_ptp_sysfs_release(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (pf->ptp.phy_kobj) {
		sysfs_remove_file(pf->ptp.phy_kobj, &synce_attribute.attr);
		if (ice_is_e825c(&pf->hw))
			sysfs_remove_file(pf->ptp.phy_kobj,
					  &tx_clk_attribute.attr);
		kobject_put(pf->ptp.phy_kobj);
		pf->ptp.phy_kobj = NULL;
	}

	if (pf->hw.func_caps.ts_func_info.src_tmr_owned &&
	    ice_is_feature_supported(pf, ICE_F_CGU)) {
		int i;

		device_remove_file(dev, &dev_attr_pin_cfg);
		device_remove_file(dev, &dev_attr_dpll_1_offset);

		for (i = 0; i < ICE_CGU_DPLL_MAX; ++i) {
			if (!IS_ERR(dpll_name_attrs))
				device_remove_file(ice_pf_to_dev(pf),
						   &dpll_name_attrs[i].attr);
			if (!IS_ERR(dpll_state_attrs))
				device_remove_file(ice_pf_to_dev(pf),
						   &dpll_state_attrs[i].attr);
			if (!IS_ERR(dpll_ref_pin_attrs))
				device_remove_file(ice_pf_to_dev(pf),
						   &dpll_ref_pin_attrs[i].attr);
		}
	}

	if (ice_is_e825c(&pf->hw) && ice_pf_src_tmr_owned(pf))
		device_remove_file(dev, &dev_attr_clock_1588);
	if (ice_is_e823(&pf->hw) || ice_is_e825c(&pf->hw))
		device_remove_file(ice_pf_to_dev(pf), &dev_attr_ts_pll_cfg);
}

/**
 * ice_get_sma_config_e810t
 * @pf: pointer to pf structure
 * @ptp_pins: pointer to the ptp_pin_desc struture
 *
 * Read the configuration of the SMA control logic and put it into the
 * ptp_pin_desc structure
 */
static int
ice_get_sma_config_e810t(struct ice_pf *pf, struct ptp_pin_desc *ptp_pins)
{
	u8 data, i;
	int status;

	/* Read initial pin state */
	status = ice_read_sma_ctrl_e810t(&pf->hw, &data);
	if (status)
		return status;

	/* initialize with defaults */
	for (i = 0; i < NUM_PTP_PINS_E810T; i++) {
		snprintf(ptp_pins[i].name, sizeof(ptp_pins[i].name),
			 "%s", ice_pin_desc_e810t[i].name);
		ptp_pins[i].index = ice_pin_desc_e810t[i].index;
		ptp_pins[i].func = ice_pin_desc_e810t[i].func;
		ptp_pins[i].chan = ice_pin_desc_e810t[i].chan;
		if (ptp_pins[i].func != PTP_PF_EXTTS) {
			struct ice_perout_channel *chan;

			chan = &pf->ptp.perout_channels[ptp_pins[i].chan];
			chan->present = true;
		}
	}

	/* Parse SMA1/UFL1 */
	switch (data & ICE_SMA1_MASK_E810T) {
	case ICE_SMA1_MASK_E810T:
	default:
		ptp_pins[SMA1].func = PTP_PF_NONE;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case ICE_SMA1_DIR_EN_E810T:
		ptp_pins[SMA1].func = PTP_PF_PEROUT;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case ICE_SMA1_TX_EN_E810T:
		ptp_pins[SMA1].func = PTP_PF_EXTTS;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case 0:
		ptp_pins[SMA1].func = PTP_PF_EXTTS;
		ptp_pins[UFL1].func = PTP_PF_PEROUT;
		break;
	}

	/* Parse SMA2/UFL2 */
	switch (data & ICE_SMA2_MASK_E810T) {
	case ICE_SMA2_MASK_E810T:
	default:
		ptp_pins[SMA2].func = PTP_PF_NONE;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_SMA2_TX_EN_E810T | ICE_SMA2_UFL2_RX_DIS_E810T):
		ptp_pins[SMA2].func = PTP_PF_EXTTS;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_SMA2_DIR_EN_E810T | ICE_SMA2_UFL2_RX_DIS_E810T):
		ptp_pins[SMA2].func = PTP_PF_PEROUT;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_SMA2_DIR_EN_E810T | ICE_SMA2_TX_EN_E810T):
		ptp_pins[SMA2].func = PTP_PF_NONE;
		ptp_pins[UFL2].func = PTP_PF_EXTTS;
		break;
	case ICE_SMA2_DIR_EN_E810T:
		ptp_pins[SMA2].func = PTP_PF_PEROUT;
		ptp_pins[UFL2].func = PTP_PF_EXTTS;
		break;
	}

	return 0;
}

/**
 * ice_ptp_set_sma_config_e810t
 * @hw: pointer to the hw struct
 * @ptp_pins: pointer to the ptp_pin_desc struture
 *
 * Set the configuration of the SMA control logic based on the configuration in
 * num_pins parameter
 */
static int
ice_ptp_set_sma_config_e810t(struct ice_hw *hw,
			     const struct ptp_pin_desc *ptp_pins)
{
	int status;
	u8 data;

	/* SMA1 and UFL1 cannot be set to TX at the same time */
	if (ptp_pins[SMA1].func == PTP_PF_PEROUT &&
	    ptp_pins[UFL1].func == PTP_PF_PEROUT)
		return -EINVAL;

	/* SMA2 and UFL2 cannot be set to RX at the same time */
	if (ptp_pins[SMA2].func == PTP_PF_EXTTS &&
	    ptp_pins[UFL2].func == PTP_PF_EXTTS)
		return -EINVAL;

	/* Read initial pin state value */
	status = ice_read_sma_ctrl_e810t(hw, &data);
	if (status)
		return status;

	/* Set the right sate based on the desired configuration */
	data &= ~ICE_SMA1_MASK_E810T;
	if (ptp_pins[SMA1].func == PTP_PF_NONE &&
	    ptp_pins[UFL1].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA1 + U.FL1 disabled");
		data |= ICE_SMA1_MASK_E810T;
	} else if (ptp_pins[SMA1].func == PTP_PF_EXTTS &&
		   ptp_pins[UFL1].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA1 RX");
		data |= ICE_SMA1_TX_EN_E810T;
	} else if (ptp_pins[SMA1].func == PTP_PF_NONE &&
		   ptp_pins[UFL1].func == PTP_PF_PEROUT) {
		/* U.FL 1 TX will always enable SMA 1 RX */
		dev_info(ice_hw_to_dev(hw), "SMA1 RX + U.FL1 TX");
	} else if (ptp_pins[SMA1].func == PTP_PF_EXTTS &&
		   ptp_pins[UFL1].func == PTP_PF_PEROUT) {
		dev_info(ice_hw_to_dev(hw), "SMA1 RX + U.FL1 TX");
	} else if (ptp_pins[SMA1].func == PTP_PF_PEROUT &&
		   ptp_pins[UFL1].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA1 TX");
		data |= ICE_SMA1_DIR_EN_E810T;
	}

	data &= ~ICE_SMA2_MASK_E810T;
	if (ptp_pins[SMA2].func == PTP_PF_NONE &&
	    ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 + U.FL2 disabled");
		data |= ICE_SMA2_MASK_E810T;
	} else if (ptp_pins[SMA2].func == PTP_PF_EXTTS &&
			ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 RX");
		data |= (ICE_SMA2_TX_EN_E810T |
			 ICE_SMA2_UFL2_RX_DIS_E810T);
	} else if (ptp_pins[SMA2].func == PTP_PF_NONE &&
		   ptp_pins[UFL2].func == PTP_PF_EXTTS) {
		dev_info(ice_hw_to_dev(hw), "UFL2 RX");
		data |= (ICE_SMA2_DIR_EN_E810T | ICE_SMA2_TX_EN_E810T);
	} else if (ptp_pins[SMA2].func == PTP_PF_PEROUT &&
		   ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 TX");
		data |= (ICE_SMA2_DIR_EN_E810T |
			 ICE_SMA2_UFL2_RX_DIS_E810T);
	} else if (ptp_pins[SMA2].func == PTP_PF_PEROUT &&
		   ptp_pins[UFL2].func == PTP_PF_EXTTS) {
		dev_info(ice_hw_to_dev(hw), "SMA2 TX + U.FL2 RX");
		data |= ICE_SMA2_DIR_EN_E810T;
	}

	return ice_write_sma_ctrl_e810t(hw, data);
}

/**
 * ice_ptp_set_sma_e810t
 * @info: the driver's PTP info structure
 * @pin: pin index in kernel structure
 * @func: Pin function to be set (PTP_PF_NONE, PTP_PF_EXTTS or PTP_PF_PEROUT)
 *
 * Set the configuration of a single SMA pin
 */
static int
ice_ptp_set_sma_e810t(struct ptp_clock_info *info, unsigned int pin,
		      enum ptp_pin_function func)
{
	struct ptp_pin_desc ptp_pins[NUM_PTP_PINS_E810T];
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	int err;

	if (pin < SMA1 || func > PTP_PF_PEROUT)
		return -EOPNOTSUPP;

	err = ice_get_sma_config_e810t(pf, ptp_pins);
	if (err)
		return err;

	/* Disable the same function on the other pin sharing the channel */
	if (pin == SMA1 && ptp_pins[UFL1].func == func)
		ptp_pins[UFL1].func = PTP_PF_NONE;
	if (pin == UFL1 && ptp_pins[SMA1].func == func)
		ptp_pins[SMA1].func = PTP_PF_NONE;

	if (pin == SMA2 && ptp_pins[UFL2].func == func)
		ptp_pins[UFL2].func = PTP_PF_NONE;
	if (pin == UFL2 && ptp_pins[SMA2].func == func)
		ptp_pins[SMA2].func = PTP_PF_NONE;

	/* Set up new pin function in the temp table */
	ptp_pins[pin].func = func;

	return ice_ptp_set_sma_config_e810t(hw, ptp_pins);
}

/**
 * ice_ptp_set_gnss_e810t - Set the configuration of a GNSS pin
 * @info: The driver's PTP info structure
 * @func: Assigned function
 */
static int
ice_ptp_set_gnss_e810t(struct ptp_clock_info *info, enum ptp_pin_function func)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	u8 input_idx, flags2;

	input_idx = ice_pin_desc_e810t[GNSS].index;
	flags2 = func == PTP_PF_NONE ? 0 : ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;

	return ice_aq_set_input_pin_cfg(&pf->hw, input_idx, 0, flags2, 0, 0);
}

/**
 * ice_verify_pin_e810t
 * @info: the driver's PTP info structure
 * @pin: Pin index
 * @func: Assigned function
 * @chan: Assigned channel
 *
 * Verify if pin supports requested pin function. If the Check pins consistency.
 * Reconfigure the SMA logic attached to the given pin to enable its
 * desired functionality
 */
static int
ice_verify_pin_e810t(struct ptp_clock_info *info, unsigned int pin,
		     enum ptp_pin_function func, unsigned int chan)
{
	/* Don't allow channel reassignment */
	if (chan != ice_pin_desc_e810t[pin].chan)
		return -EOPNOTSUPP;

	/* Check if functions are properly assigned */
	switch (func) {
	case PTP_PF_NONE:
		break;
	case PTP_PF_EXTTS:
		if (pin == UFL1)
			return -EOPNOTSUPP;
		break;
	case PTP_PF_PEROUT:
		if (pin == UFL2 || pin == GNSS)
			return -EOPNOTSUPP;
		break;
	case PTP_PF_PHYSYNC:
		return -EOPNOTSUPP;
	}

	if (pin == GNSS)
		return ice_ptp_set_gnss_e810t(info, func);
	else
		return ice_ptp_set_sma_e810t(info, pin, func);
}

/**
 * ice_ptp_is_managed_phy - Check if driver manaages PHY
 * @phy_model: Phy model
 */
static bool ice_ptp_is_managed_phy(enum ice_phy_model phy_model)
{
	switch (phy_model) {
	case ICE_PHY_E810:
		return false;
	default:
		return true;
	}
}

/**
 * mul_u128_u64_fac - Multiplies two 64bit factors to the 128b result
 * @a: First factor to multiply
 * @b: Second factor to multiply
 * @hi: Pointer for higher part of 128b result
 * @lo: Pointer for lower part of 128b result
 *
 * This function performs multiplication of two 64 bit factors with 128b
 * output.
 */
static inline void mul_u128_u64_fac(u64 a, u64 b, u64 *hi, u64 *lo)
{
	u64 mask = GENMASK_ULL(31, 0);
	u64 a_lo = a & mask;
	u64 b_lo = b & mask;

	a >>= 32;
	b >>= 32;

	*hi = (a * b) + (((a * b_lo) + ((a_lo * b_lo) >> 32)) >> 32) +
	      (((a_lo * b) + (((a * b_lo) + ((a_lo * b_lo) >> 32)) & mask)) >> 32);
	*lo = (((a_lo * b) + (((a * b_lo) + ((a_lo * b_lo) >> 32)) & mask)) << 32) +
	      ((a_lo * b_lo) & mask);
}

/**
 * div128_u64_rem - Divides 128bit integer by 64bit divisor with reminder
 * @a_hi: Higher part of 128bit dividend
 * @a_lo: Lower part of 128bit dividend
 * @d: 64bit divisor
 * @r: 64bit remainder from division, may be NULL
 *
 * This functions computes and return division of 128bit integer with 64bit
 * divisor. Optionally it could return remainder on output.
 */
static inline u64 div128_u64_rem(u64 a_hi, u64 a_lo, u64 d, u64 *r)
{
	u64 mod_hi = ((U64_MAX % d) + 1) % d;
	u64 cnt_hi = U64_MAX / d;
	u64 res, mod;

	if (mod_hi == 0)
		cnt_hi++;

	mod = ((a_hi * mod_hi) % d) + (a_lo % d);
	res = (a_hi * cnt_hi) + ((a_hi * mod_hi) / d) + (a_lo / d) + (mod / d);
	if (r)
		*r = mod;
	return res;
}

/**
 * ice_ptp_ticks2ns - Converts system ticks to nanoseconds
 * @pf: Board private structure
 * @ticks: Ticks to be converted into ns
 *
 * This function converts PLL ticks into nanoseconds when the PHC works in
 * locked mode.
 */
#ifndef HAVE_PF_RING
static
#endif
u64 ice_ptp_ticks2ns(struct ice_pf *pf, u64 ticks)
{
	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		u64 ns, nsec[2], freq;

		freq = ice_ptp_get_pll_freq(&pf->hw);

		if (!freq)
			return 0;

		mul_u128_u64_fac(ticks, 1000000000ULL, &nsec[0], &nsec[1]);
		ns = div128_u64_rem(nsec[0], nsec[1], freq, NULL);
		return ns;
	}
	return ticks;
}

/**
 * ice_ptp_ns2ticks - Converts nanoseconds to system ticks
 * @pf: Board private structure
 * @ns: Nanoseconds to be converted into ticks
 *
 * This function converts nanoseconds into PLL ticks when PHC works in
 * locked mode.
 */
#ifndef HAVE_PF_RING
static
#endif
u64 ice_ptp_ns2ticks(struct ice_pf *pf, u64 ns)
{
	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		u64 sec, ticks, nsec_ticks[2], freq;
		u32 nsec;

		freq = ice_ptp_get_pll_freq(&pf->hw);

		sec = div_u64_rem(ns, 1000000000ULL, &nsec);
		ticks = sec * freq;
		mul_u128_u64_fac(nsec, freq, &nsec_ticks[0], &nsec_ticks[1]);
		nsec_ticks[1] = div128_u64_rem(nsec_ticks[0], nsec_ticks[1],
					       1000000000ULL, NULL);

		return ticks + nsec_ticks[1];
	}
	return ns;
}

/**
 * ice_ptp_configure_tx_tstamp - Enable or disable Tx timestamp interrupt
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamp interrupt is enabled or disabled
 */
static void ice_ptp_configure_tx_tstamp(struct ice_pf *pf, bool on)
{
	u32 val;

	/* Configure the Tx timestamp interrupt */
	val = rd32(&pf->hw, PFINT_OICR_ENA);
	if (on)
		val |= PFINT_OICR_TSYN_TX_M;
	else
		val &= ~PFINT_OICR_TSYN_TX_M;
	wr32(&pf->hw, PFINT_OICR_ENA, val);
}

/**
 * ice_set_tx_tstamp - Enable or disable Tx timestamping
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamps are enabled or disabled
 */
static void ice_set_tx_tstamp(struct ice_pf *pf, bool on)
{
	struct ice_vsi *vsi;
	u16 i;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;

	/* Set the timestamp enable flag for all the Tx rings */
	ice_for_each_txq(vsi, i) {
		if (!vsi->tx_rings[i])
			continue;
		vsi->tx_rings[i]->ptp_tx = on;
	}

	if (pf->ptp.tx_interrupt_mode == ICE_PTP_TX_INTERRUPT_SELF)
		ice_ptp_configure_tx_tstamp(pf, on);

	pf->ptp.tstamp_config.tx_type = on ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
}

/**
 * ice_set_rx_tstamp - Enable or disable Rx timestamping
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamps are enabled or disabled
 */
static void ice_set_rx_tstamp(struct ice_pf *pf, bool on)
{
	struct ice_vsi *vsi;
	u16 i;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;

	/* Set the timestamp flag for all the Rx rings */
	ice_for_each_rxq(vsi, i) {
		if (!vsi->rx_rings[i])
			continue;
		vsi->rx_rings[i]->ptp_rx = on;
	}

	pf->ptp.tstamp_config.rx_filter = on ? HWTSTAMP_FILTER_ALL :
					       HWTSTAMP_FILTER_NONE;
}

/**
 * ice_ptp_cfg_timestamp - Configure timestamp for init/deinit
 * @pf: Board private structure
 * @ena: bool value to enable or disable time stamp
 *
 * This function will configure timestamping during PTP initialization
 * and deinitialization
 */
void ice_ptp_cfg_timestamp(struct ice_pf *pf, bool ena)
{
	ice_set_tx_tstamp(pf, ena);
	ice_set_rx_tstamp(pf, ena);
}

/**
 * ice_ptp_read_src_clk_reg - Read the source clock register
 * @pf: Board private structure
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 */
u64
ice_ptp_read_src_clk_reg(struct ice_pf *pf, struct ptp_system_timestamp *sts)
{
	struct ice_hw *hw = &pf->hw;
	u32 hi, lo, lo2;
	u8 tmr_idx;

	tmr_idx = ice_get_ptp_src_clock_index(hw);
	/* Read the system timestamp pre PHC read */
	ptp_read_system_prets(sts);

	lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));

	/* Read the system timestamp post PHC read */
	ptp_read_system_postts(sts);

	hi = rd32(hw, GLTSYN_TIME_H(tmr_idx));
	lo2 = rd32(hw, GLTSYN_TIME_L(tmr_idx));

	if (lo2 < lo) {
		/* if TIME_L rolled over read TIME_L again and update
		 * system timestamps
		 */
		ptp_read_system_prets(sts);
		lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));
		ptp_read_system_postts(sts);
		hi = rd32(hw, GLTSYN_TIME_H(tmr_idx));
	}

	return ((u64)hi << 32) | lo;
}

/**
 * ice_ptp_extend_32b_ts - Convert a 32b nanoseconds timestamp to 64b
 * @cached_phc_time: recently cached copy of PHC time
 * @in_tstamp: Ingress/egress 32b nanoseconds timestamp value
 *
 * Hardware captures timestamps which contain only 32 bits of nominal
 * nanoseconds, as opposed to the 64bit timestamps that the stack expects.
 * Note that the captured timestamp values may be 40 bits, but the lower
 * 8 bits are sub-nanoseconds and generally discarded.
 *
 * Extend the 32bit nanosecond timestamp using the following algorithm and
 * assumptions:
 *
 * 1) have a recently cached copy of the PHC time
 * 2) assume that the in_tstamp was captured 2^31 nanoseconds (~2.1
 *    seconds) before or after the PHC time was captured.
 * 3) calculate the delta between the cached time and the timestamp
 * 4) if the delta is smaller than 2^31 nanoseconds, then the timestamp was
 *    captured after the PHC time. In this case, the full timestamp is just
 *    the cached PHC time plus the delta.
 * 5) otherwise, if the delta is larger than 2^31 nanoseconds, then the
 *    timestamp was captured *before* the PHC time, i.e. because the PHC
 *    cache was updated after the timestamp was captured by hardware. In this
 *    case, the full timestamp is the cached time minus the inverse delta.
 *
 * This algorithm works even if the PHC time was updated after a Tx timestamp
 * was requested, but before the Tx timestamp event was reported from
 * hardware.
 *
 * This calculation primarily relies on keeping the cached PHC time up to
 * date. If the timestamp was captured more than 2^31 nanoseconds after the
 * PHC time, it is possible that the lower 32bits of PHC time have
 * overflowed more than once, and we might generate an incorrect timestamp.
 *
 * This is prevented by (a) periodically updating the cached PHC time once
 * a second, and (b) discarding any Tx timestamp packet if it has waited for
 * a timestamp for more than one second.
 */
static u64 ice_ptp_extend_32b_ts(u64 cached_phc_time, u32 in_tstamp)
{
	u32 delta, phc_time_lo;
	u64 ns;

	/* Extract the lower 32 bits of the PHC time */
	phc_time_lo = (u32)cached_phc_time;

	/* Calculate the delta between the lower 32bits of the cached PHC
	 * time and the in_tstamp value
	 */
	delta = (in_tstamp - phc_time_lo);

	/* Do not assume that the in_tstamp is always more recent than the
	 * cached PHC time. If the delta is large, it indicates that the
	 * in_tstamp was taken in the past, and should be converted
	 * forward.
	 */
	if (delta > (U32_MAX / 2)) {
		/* reverse the delta calculation here */
		delta = (phc_time_lo - in_tstamp);
		ns = cached_phc_time - delta;
	} else {
		ns = cached_phc_time + delta;
	}

	return ns;
}

/**
 * ice_ptp_extend_40b_ts - Convert a 40b timestamp to 64b nanoseconds
 * @pf: Board private structure
 * @in_tstamp: Ingress/egress 40b timestamp value
 *
 * The Tx and Rx timestamps are 40 bits wide, including 32 bits of nominal
 * nanoseconds, 7 bits of sub-nanoseconds, and a valid bit.
 *
 *  *--------------------------------------------------------------*
 *  | 32 bits of nanoseconds | 7 high bits of sub ns underflow | v |
 *  *--------------------------------------------------------------*
 *
 * The low bit is an indicator of whether the timestamp is valid. The next
 * 7 bits are a capture of the upper 7 bits of the sub-nanosecond underflow,
 * and the remaining 32 bits are the lower 32 bits of the PHC timer.
 *
 * It is assumed that the caller verifies the timestamp is valid prior to
 * calling this function.
 *
 * Extract the 32bit nominal nanoseconds and extend them. Use the cached PHC
 * time stored in the device private PTP structure as the basis for timestamp
 * extension.
 *
 * See ice_ptp_extend_32b_ts for a detailed explanation of the extension
 * algorithm.
 */
#ifndef HAVE_PF_RING
static
#endif
u64 ice_ptp_extend_40b_ts(struct ice_pf *pf, u64 in_tstamp)
{
	const u64 mask = GENMASK_ULL(31, 0);
	unsigned long discard_time;
	u64 ticks;

	/* Discard the hardware timestamp if the cached PHC time is too old */
	discard_time = pf->ptp.cached_phc_jiffies + msecs_to_jiffies(2000);
	if (time_is_before_jiffies(discard_time)) {
		pf->ptp.tx_hwtstamp_discarded++;
		return 0;
	}

	ticks = ice_ptp_extend_32b_ts(pf->ptp.cached_phc_time,
				      (in_tstamp >> 8) & mask);
	return ice_ptp_ticks2ns(pf, ticks);
}

/**
 * ice_ptp_is_tx_tracker_up - Check if Tx tracker is ready for new timestamps
 * @tx: the PTP Tx timestamp tracker to check
 *
 * Check that a given PTP Tx timestamp tracker is up, i.e. that it is ready
 * to accept new timestamp requests.
 *
 * Assumes the tx->lock spinlock is already held.
 */
static bool
ice_ptp_is_tx_tracker_up(struct ice_ptp_tx *tx)
{
	lockdep_assert_held(&tx->lock);

	return tx->init && !tx->calibrating;
}

/**
 * ice_ptp_req_tx_single_tstamp - Request Tx timestamp for a port from FW
 * @tx: the PTP Tx timestamp tracker
 * @idx: index of the timestamp to request
 */
void ice_ptp_req_tx_single_tstamp(struct ice_ptp_tx *tx, u8 idx)
{
	struct ice_ptp_port *ptp_port;
	struct ice_pf *pf;
	struct sk_buff *skb;

	if (!tx->init)
		return;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);

	/* Drop packets which have waited for more than 2 seconds */
	if (time_is_before_jiffies(tx->tstamps[idx].start + 2 * HZ)) {
		/* Count the number of Tx timestamps that timed out */
		pf->ptp.tx_hwtstamp_timeouts++;

		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);
		clear_bit(idx, tx->stale);

		dev_kfree_skb_any(skb);
		return;
	}

	ice_trace(tx_tstamp_fw_req, tx->tstamps[idx].skb, idx);

	/* Write TS index to read to the PF register so the FW can read it */
	wr32(&pf->hw, PF_SB_ATQBAL,
	     TS_LL_READ_TS_INTR | TS_LL_READ_TS_IDX(idx));
	tx->last_ll_ts_idx_read = idx;
}

/**
 * ice_ptp_complete_tx_single_tstamp - Complete Tx timestamp for a port
 * @tx: the PTP Tx timestamp tracker
 */
void ice_ptp_complete_tx_single_tstamp(struct ice_ptp_tx *tx)
{
	struct skb_shared_hwtstamps shhwtstamps = {};
	u8 idx = tx->last_ll_ts_idx_read;
	struct ice_ptp_port *ptp_port;
	u64 raw_tstamp, tstamp;
	bool drop_ts = false;
	struct sk_buff *skb;
	struct ice_pf *pf;
	u32 val;

	if (!tx->init || tx->last_ll_ts_idx_read < 0)
		return;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);

	ice_trace(tx_tstamp_fw_done, tx->tstamps[idx].skb, idx);

	val = rd32(&pf->hw, PF_SB_ATQBAL);

	/* When the bit is cleared, the TS is ready in the register */
	if (val & TS_LL_READ_TS) {
		dev_dbg(ice_pf_to_dev(pf), "Failed to get the Tx tstamp - FW not ready. Will retry");
		return;
	}

	/* High 8 bit value of the TS is on the bits 16:23 */
	raw_tstamp = ICE_LO_BYTE(val >> TS_LL_READ_TS_HIGH_S);
	raw_tstamp <<= 32;

	/* Read the low 32 bit value */
	raw_tstamp |= (u64)rd32(&pf->hw, PF_SB_ATQBAH);

	/* For PHYs which don't implement a proper timestamp ready bitmap,
	 * verify that the timestamp value is different from the last cached
	 * timestamp. If it is not, skip this for now assuming it hasn't yet
	 * been captured by hardware.
	 */
	if (!drop_ts && tx->verify_cached &&
	    raw_tstamp == tx->tstamps[idx].cached_tstamp)
		return;

	if (tx->verify_cached && raw_tstamp)
		tx->tstamps[idx].cached_tstamp = raw_tstamp;
	clear_bit(idx, tx->in_use);
	skb = tx->tstamps[idx].skb;
	tx->tstamps[idx].skb = NULL;
	if (test_and_clear_bit(idx, tx->stale))
		drop_ts = true;

	if (!skb)
		return;

	if (drop_ts) {
		dev_kfree_skb_any(skb);
		return;
	}

	/* Extend the timestamp using cached PHC time */
	tstamp = ice_ptp_extend_40b_ts(pf, raw_tstamp);
	if (tstamp) {
		shhwtstamps.hwtstamp = ns_to_ktime(tstamp);
		ice_trace(tx_tstamp_complete, skb, idx);
	}

	skb_tstamp_tx(skb, &shhwtstamps);
	dev_kfree_skb_any(skb);
}

/**
 * ice_ptp_process_tx_tstamp - Process Tx timestamps for a port
 * @tx: the PTP Tx timestamp tracker
 *
 * Process timestamps captured by the PHY associated with this port. To do
 * this, loop over each index with a waiting skb.
 *
 * If a given index has a valid timestamp, perform the following steps:
 *
 * 1) check that the timestamp request is not stale
 * 2) check that a timestamp is ready and available in the PHY memory bank
 * 3) read and copy the timestamp out of the PHY register
 * 4) unlock the index by clearing the associated in_use bit
 * 5) check if the timestamp is stale, and discard if so
 * 6) extend the 40 bit timestamp value to get a 64 bit timestamp value
 * 7) send this 64 bit timestamp to the stack
 *
 * Note that we do not hold the tracking lock while reading the Tx timestamp.
 * This is because reading the timestamp requires taking a mutex that might
 * sleep.
 *
 * The only place where we set in_use is when a new timestamp is initiated
 * with a slot index. This is only called in the hard xmit routine where an
 * SKB has a request flag set. The only places where we clear this bit is this
 * function, or during teardown when the Tx timestamp tracker is being
 * removed. A timestamp index will never be re-used until the in_use bit for
 * that index is cleared.
 *
 * If a Tx thread starts a new timestamp, we might not begin processing it
 * right away but we will notice it at the end when we re-queue the task.
 *
 * If a Tx thread starts a new timestamp just after this function exits, the
 * interrupt for that timestamp should re-trigger this function once
 * a timestamp is ready.
 *
 * In cases where the PTP hardware clock was directly adjusted, some
 * timestamps may not be able to safely use the timestamp extension math. In
 * this case, software will set the stale bit for any outstanding Tx
 * timestamps when the clock is adjusted. Then this function will discard
 * those captured timestamps instead of sending them to the stack.
 *
 * If a Tx packet has been waiting for more than 2 seconds, it is not possible
 * to correctly extend the timestamp using the cached PHC time. It is
 * extremely unlikely that a packet will ever take this long to timestamp. If
 * we detect a Tx timestamp request that has waited for this long we assume
 * the packet will never be sent by hardware and discard it without reading
 * the timestamp register.
 */
static void ice_ptp_process_tx_tstamp(struct ice_ptp_tx *tx)
{
	struct ice_pf *pf;
	struct ice_hw *hw;
	u64 tstamp_ready;
	int err;
	u8 idx;

	struct ice_ptp_port *ptp_port;
	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);
	hw = &pf->hw;

	/* Read the Tx ready status first */
	err = ice_get_phy_tx_tstamp_ready(hw, tx->block, &tstamp_ready);
	if (err)
		return;

	for_each_set_bit(idx, tx->in_use, tx->len) {
		struct skb_shared_hwtstamps shhwtstamps = {};
		u8 phy_idx = idx + tx->offset;
		u64 raw_tstamp = 0, tstamp;
		bool drop_ts = false;
		struct sk_buff *skb;

		/* Drop packets which have waited for more than 2 seconds */
		if (time_is_before_jiffies(tx->tstamps[idx].start + 2 * HZ)) {
			drop_ts = true;

			/* Count the number of Tx timestamps that timed out */
			pf->ptp.tx_hwtstamp_timeouts++;
		}

		/* Only read a timestamp from the PHY if its marked as ready
		 * by the tstamp_ready register. This avoids unnecessary
		 * reading of timestamps which are not yet valid. This is
		 * important as we must read all timestamps which are valid
		 * and only timestamps which are valid during each interrupt.
		 * If we do not, the hardware logic for generating a new
		 * interrupt can get stuck on some devices.
		 */
		if (!(tstamp_ready & BIT_ULL(phy_idx))) {
			if (drop_ts)
				goto skip_ts_read;

			continue;
		}

		ice_trace(tx_tstamp_fw_req, tx->tstamps[idx].skb, idx);

		err = ice_read_phy_tstamp(hw, tx->block, phy_idx, &raw_tstamp);
		if (err)
			continue;

		ice_trace(tx_tstamp_fw_done, tx->tstamps[idx].skb, idx);

		/* For PHYs which don't implement a proper timestamp ready
		 * bitmap, verify that the timestamp value is different
		 * from the last cached timestamp. If it is not, skip this for
		 * now assuming it hasn't yet been captured by hardware.
		 */
		if (!drop_ts && tx->verify_cached &&
		    raw_tstamp == tx->tstamps[idx].cached_tstamp)
			continue;

		/* Discard any timestamp value without the valid bit set */
		if (!(raw_tstamp & ICE_PTP_TS_VALID))
			drop_ts = true;

skip_ts_read:
		spin_lock(&tx->lock);
		if (tx->verify_cached && raw_tstamp)
			tx->tstamps[idx].cached_tstamp = raw_tstamp;
		clear_bit(idx, tx->in_use);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		if (test_and_clear_bit(idx, tx->stale))
			drop_ts = true;
		spin_unlock(&tx->lock);

		if (!skb)
			continue;

		if (drop_ts) {
			dev_kfree_skb_any(skb);
			continue;
		}

		/* Extend the timestamp using cached PHC time */
		tstamp = ice_ptp_extend_40b_ts(pf, raw_tstamp);
		if (tstamp) {
			shhwtstamps.hwtstamp = ns_to_ktime(tstamp);
			ice_trace(tx_tstamp_complete, skb, idx);
		}

		skb_tstamp_tx(skb, &shhwtstamps);
		dev_kfree_skb_any(skb);
	}
}

/**
 * ice_ptp_tx_tstamp - Process Tx timestamps for this function.
 * @tx: Tx tracking structure to initialize
 *
 * Returns: ICE_TX_TSTAMP_WORK_PENDING if there are any outstanding incomplete
 * Tx timestamps, or ICE_TX_TSTAMP_WORK_DONE otherwise.
 */
static enum ice_tx_tstamp_work ice_ptp_tx_tstamp(struct ice_ptp_tx *tx)
{
	bool more_timestamps;

	if (!tx->init)
		return ICE_TX_TSTAMP_WORK_DONE;

	/* Process the Tx timestamp tracker */
	ice_ptp_process_tx_tstamp(tx);

	/* Check if there are outstanding Tx timestamps */
	spin_lock(&tx->lock);
	more_timestamps = tx->init && !bitmap_empty(tx->in_use, tx->len);
	spin_unlock(&tx->lock);

	if (more_timestamps)
		return ICE_TX_TSTAMP_WORK_PENDING;

	return ICE_TX_TSTAMP_WORK_DONE;
}

/**
 * ice_ptp_tx_tstamp_owner - Process Tx timestamps for all ports on the device
 * @pf: Board private structure
 *
 * Returns: false if any work remains, true if all work completed.
 */
static enum ice_tx_tstamp_work ice_ptp_tx_tstamp_owner(struct ice_pf *pf)
{
	struct ice_ptp_port *port;
	unsigned int i;

	list_for_each_entry(port, &pf->ptp.ports_owner.ports, list_member) {
		struct ice_ptp_tx *tx = &port->tx;

		if (!tx || !tx->init)
			continue;

		ice_ptp_process_tx_tstamp(tx);
	}

	for (i = 0; i < ICE_MAX_QUAD; i++) {
		u64 tstamp_ready;
		int err;

		/* Check each port to determine if there is any new
		 * outstanding work that came in after we processed. If so,
		 * we must report that work is pending to immediately trigger
		 * another interrupt ensuring that we process this data.
		 */
		err = ice_get_phy_tx_tstamp_ready(&pf->hw, i, &tstamp_ready);
		if (err)
			break;
		else if (tstamp_ready)
			return ICE_TX_TSTAMP_WORK_PENDING;
	}

	return ICE_TX_TSTAMP_WORK_DONE;
}

/**
 * ice_ptp_alloc_tx_tracker - Initialize tracking for Tx timestamps
 * @tx: Tx tracking structure to initialize
 *
 * Assumes that the length has already been initialized. Do not call directly,
 * use the ice_ptp_init_tx_* instead.
 */
static int
ice_ptp_alloc_tx_tracker(struct ice_ptp_tx *tx)
{
	unsigned long *in_use, *stale;
	struct ice_tx_tstamp *tstamps;

	tstamps = kcalloc(tx->len, sizeof(*tstamps), GFP_KERNEL);
	in_use = bitmap_zalloc(tx->len, GFP_KERNEL);
	stale = bitmap_zalloc(tx->len, GFP_KERNEL);

	if (!tstamps || !in_use || !stale) {
		kfree(tstamps);
		bitmap_free(in_use);
		bitmap_free(stale);

		return -ENOMEM;
	}

	tx->tstamps = tstamps;
	tx->in_use = in_use;
	tx->stale = stale;
	tx->init = 1;
	tx->calibrating = 0;
	tx->last_ll_ts_idx_read = -1;

	spin_lock_init(&tx->lock);

	return 0;
}

/**
 * ice_ptp_flush_tx_tracker - Flush any remaining timestamps from the tracker
 * @pf: Board private structure
 * @tx: the tracker to flush
 *
 * Called during teardown when a Tx tracker is being removed.
 */
static void
ice_ptp_flush_tx_tracker(struct ice_pf *pf, struct ice_ptp_tx *tx)
{
	struct ice_hw *hw = &pf->hw;
	u64 tstamp_ready;
	int err;
	u8 idx;

	err = ice_get_phy_tx_tstamp_ready(hw, tx->block, &tstamp_ready);
	if (err) {
		dev_dbg(ice_pf_to_dev(pf), "Failed to get the Tx tstamp ready bitmap for block %u, err %d\n",
			tx->block, err);

		/* If we fail to read the Tx timestamp ready bitmap just
		 * skip clearing the PHY timestamps.
		 */
		tstamp_ready = 0;
	}

	for_each_set_bit(idx, tx->in_use, tx->len) {
		u8 phy_idx = idx + tx->offset;
		struct sk_buff *skb;

		/* In case this timestamp is ready, we need to clear it. */
		if (!hw->reset_ongoing && (tstamp_ready & BIT_ULL(phy_idx)))
			ice_clear_phy_tstamp(hw, tx->block, phy_idx);

		spin_lock(&tx->lock);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);
		clear_bit(idx, tx->stale);
		spin_unlock(&tx->lock);

		/* Count the number of Tx timestamps flushed */
		pf->ptp.tx_hwtstamp_flushed++;

		/* Free the SKB after we've cleared the bit */
		dev_kfree_skb_any(skb);
	}
}

/**
 * ice_ptp_mark_tx_tracker_stale - Mark unfinished timestamps as stale
 * @tx: the tracker to mark
 *
 * Mark currently outstanding Tx timestamps as stale. This prevents sending
 * their timestamp value to the stack. This is required to prevent extending
 * the 40bit hardware timestamp incorrectly.
 *
 * This should be called when the PTP clock is modified such as after a set
 * time request.
 */
static void
ice_ptp_mark_tx_tracker_stale(struct ice_ptp_tx *tx)
{
	spin_lock(&tx->lock);
	bitmap_or(tx->stale, tx->stale, tx->in_use, tx->len);
	spin_unlock(&tx->lock);
}

/**
 * ice_ptp_release_tx_tracker - Release allocated memory for Tx tracker
 * @pf: Board private structure
 * @tx: Tx tracking structure to release
 *
 * Free memory associated with the Tx timestamp tracker.
 */
static void
ice_ptp_release_tx_tracker(struct ice_pf *pf, struct ice_ptp_tx *tx)
{
	spin_lock(&tx->lock);
	tx->init = 0;
	spin_unlock(&tx->lock);

	/* wait for potentially outstanding interrupt to complete */
	synchronize_irq(ice_get_irq_num(pf, pf->oicr_idx));

	ice_ptp_flush_tx_tracker(pf, tx);

	kfree(tx->tstamps);
	tx->tstamps = NULL;

	bitmap_free(tx->in_use);
	tx->in_use = NULL;

	bitmap_free(tx->stale);
	tx->stale = NULL;

	tx->len = 0;
}

/**
 * ice_ptp_init_tx_eth56g - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 * @port: the port this structure tracks
 *
 * Initialize the Tx timestamp tracker for this port. ETH56G PHYs
 * have independent memory blocks for all ports.
 */
static int
ice_ptp_init_tx_eth56g(struct ice_pf *pf, struct ice_ptp_tx *tx, u8 port)
{
	tx->block = port;
	tx->offset = 0;
	tx->len = INDEX_PER_PORT_ETH56G;
	tx->verify_cached = 0;

	return ice_ptp_alloc_tx_tracker(tx);
}
/**
 * ice_ptp_init_tx_e822 - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 * @port: the port this structure tracks
 *
 * Initialize the Tx timestamp tracker for this port. For generic MAC devices,
 * the timestamp block is shared for all ports in the same quad. To avoid
 * ports using the same timestamp index, logically break the block of
 * registers into chunks based on the port number.
 */
static int
ice_ptp_init_tx_e822(struct ice_pf *pf, struct ice_ptp_tx *tx, u8 port)
{
	tx->block = port / ICE_PORTS_PER_QUAD;
	tx->offset = (port % ICE_PORTS_PER_QUAD) * INDEX_PER_PORT_E822;
	tx->len = INDEX_PER_PORT_E822;
	tx->verify_cached = 0;

	return ice_ptp_alloc_tx_tracker(tx);
}

/**
 * ice_ptp_init_tx_e810 - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 *
 * Initialize the Tx timestamp tracker for this PF. For E810 devices, each
 * port has its own block of timestamps, independent of the other ports.
 */
static int
ice_ptp_init_tx_e810(struct ice_pf *pf, struct ice_ptp_tx *tx)
{
	tx->block = pf->hw.port_info->lport;
	tx->offset = 0;
	tx->len = INDEX_PER_PORT_E810;
	/* The E810 PHY does not provide a timestamp ready bitmap. Instead,
	 * verify new timestamps against cached copy of the last read
	 * timestamp.
	 */
	tx->verify_cached = 1;

	return ice_ptp_alloc_tx_tracker(tx);
}

/**
 * ice_get_current_systime - Get current system timer reading
 * @pf: Board private structure
 *
 * Get current system timer reading
 */
static u64
ice_get_current_systime(struct ice_pf *pf)
{
	/* Read the current PHC time */
	if (ice_is_primary(pf)) {
		return ice_ptp_read_src_clk_reg(pf, NULL);
	} else {
		struct ice_pf *peer_pf = ice_get_peer_pf(pf);
		u64 systime;

		systime = !peer_pf ?
			  0 : READ_ONCE(peer_pf->ptp.cached_phc_time);
		return systime;
	}
}

/**
 * ice_ptp_update_cached_phctime - Update the cached PHC time values
 * @pf: Board specific private structure
 *
 * This function updates the system time values which are cached in the PF
 * structure and the Rx rings.
 *
 * This function must be called periodically to ensure that the cached value
 * is never more than 2 seconds old.
 *
 * Note that the cached copy in the PF PTP structure is always updated, even
 * if we can't update the copy in the Rx rings.
 *
 * Return:
 * * 0 - OK, successfully updated
 * * -EAGAIN - PF was busy, need to reschedule the update
 */
static int ice_ptp_update_cached_phctime(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	unsigned long update_before;
	u64 systime;
	int i;

	update_before = pf->ptp.cached_phc_jiffies + msecs_to_jiffies(2000);
	if (pf->ptp.cached_phc_time &&
	    time_is_before_jiffies(update_before)) {
		unsigned long time_taken = jiffies - pf->ptp.cached_phc_jiffies;

		dev_warn(dev, "%u msecs passed between update to cached PHC time\n",
			 jiffies_to_msecs(time_taken));
		pf->ptp.late_cached_phc_updates++;
	}

	systime = ice_get_current_systime(pf);

	/* Update the cached PHC time stored in the PF structure */
	WRITE_ONCE(pf->ptp.cached_phc_time, systime);
	WRITE_ONCE(pf->ptp.cached_phc_jiffies, jiffies);

	if (test_and_set_bit(ICE_CFG_BUSY, pf->state))
		return -EAGAIN;

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];
		int j;

		if (!vsi)
			continue;

		if (vsi->type != ICE_VSI_PF)
			continue;
		if (!vsi->rx_rings)
			continue;

		ice_for_each_rxq(vsi, j) {
			if (!vsi->rx_rings[j])
				continue;
			WRITE_ONCE(vsi->rx_rings[j]->cached_phctime, systime);
		}
	}

	clear_bit(ICE_CFG_BUSY, pf->state);

	return 0;
}

/**
 * ice_ptp_reset_cached_phctime - Reset cached PHC time after an update
 * @pf: Board specific private structure
 *
 * This function must be called when the cached PHC time is no longer valid,
 * such as after a time adjustment. It marks any currently outstanding Tx
 * timestamps as stale and updates the cached PHC time for both the PF and Rx
 * rings.
 *
 * If updating the PHC time cannot be done immediately, a warning message is
 * logged and the work item is scheduled immediately to minimize the window
 * with a wrong cached timestamp.
 */
static void ice_ptp_reset_cached_phctime(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	/* Update the cached PHC time immediately if possible, otherwise
	 * schedule the work item to execute soon.
	 */
	err = ice_ptp_update_cached_phctime(pf);
	if (err) {
		/* If another thread is updating the Rx rings, we won't
		 * properly reset them here. This could lead to reporting of
		 * invalid timestamps, but there isn't much we can do.
		 */
		dev_warn(dev, "%s: ICE_CFG_BUSY, unable to immediately update cached PHC time\n",
			 __func__);

		/* Queue the work item to update the Rx rings when possible */
		kthread_queue_delayed_work(pf->ptp.kworker, &pf->ptp.work,
					   msecs_to_jiffies(10));
	}

	/* Mark any outstanding timestamps as stale, since they might have
	 * been captured in hardware before the time update. This could lead
	 * to us extending them with the wrong cached value resulting in
	 * incorrect timestamp values.
	 */
	ice_ptp_mark_tx_tracker_stale(&pf->ptp.port.tx);
}

/**
 * ice_ptp_write_init - Set PHC time to provided value
 * @pf: Board private structure
 * @ts: timespec structure that holds the new time value
 * @wr_main: whether to program the main timer
 *
 * Set the PHC time to the specified time provided in the timespec.
 */
static int ice_ptp_write_init(struct ice_pf *pf, struct timespec64 *ts,
			      bool wr_main)
{
	u64 ns = timespec64_to_ns(ts);
	struct ice_hw *hw = &pf->hw;
	u64 val;

	val = ice_ptp_ns2ticks(pf, ns);

	return ice_ptp_init_time(hw, val, wr_main);
}

/**
 * ice_ptp_write_adj - Adjust PHC clock time atomically
 * @pf: Board private structure
 * @adj: Adjustment in nanoseconds
 * @lock_sbq: true to lock the sbq sq_lock (the usual case); false if the
 *            sq_lock has already been locked at a higher level
 *
 * Perform an atomic adjustment of the PHC time by the specified number of
 * nanoseconds.
 */
static int
ice_ptp_write_adj(struct ice_pf *pf, s32 adj, bool lock_sbq)
{
	struct ice_hw *hw = &pf->hw;

	if (adj >= 0)
		adj = (s32)ice_ptp_ns2ticks(pf, adj);
	else
		adj = -((s32)ice_ptp_ns2ticks(pf, -adj));

	return ice_ptp_adj_clock(hw, adj, lock_sbq);
}

/**
 * ice_ptp_get_incval - Get clock increment params
 * @pf: Board private structure
 * @time_ref_freq: TIME_REF frequency
 * @src_tmr_mode: Source timer mode (nanoseconds or locked)
 */
int ice_ptp_get_incval(struct ice_pf *pf, enum ice_time_ref_freq *time_ref_freq,
		       enum ice_src_tmr_mode *src_tmr_mode)
{
	struct ice_hw *hw = &pf->hw;

	if (WARN_ON(!hw))
		return -EINVAL;

	*time_ref_freq = ice_time_ref(hw);
	*src_tmr_mode = pf->ptp.src_tmr_mode;

	return 0;
}

/**
 * ice_base_incval - Get base timer increment value
 * @pf: Board private structure
 *
 * Look up the base timer increment value for this device. The base increment
 * value is used to define the nominal clock tick rate. This increment value
 * is programmed during device initialization. It is also used as the basis
 * for calculating adjustments using scaled_ppm.
 */
static u64 ice_base_incval(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u64 incval;

	incval = ice_get_base_incval(hw, pf->ptp.src_tmr_mode);

	dev_dbg(ice_pf_to_dev(pf), "PTP: using base increment value of 0x%016llx\n",
		incval);

	return incval;
}

/**
 * ice_ptp_check_tx_fifo - Check whether Tx FIFO is in an OK state
 * @port: PTP port for which Tx FIFO is checked
 */
static int ice_ptp_check_tx_fifo(struct ice_ptp_port *port)
{
	int quad = port->port_num / ICE_PORTS_PER_QUAD;
	int offs = port->port_num % ICE_PORTS_PER_QUAD;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u32 val, phy_sts;
	int err;

	pf = ptp_port_to_pf(port);
	hw = &pf->hw;

	if (port->tx_fifo_busy_cnt == FIFO_OK)
		return 0;

	/* need to read FIFO state */
	if (offs == 0 || offs == 1)
		err = ice_read_quad_reg_e822(hw, quad, Q_REG_FIFO01_STATUS,
					     &val);
	else
		err = ice_read_quad_reg_e822(hw, quad, Q_REG_FIFO23_STATUS,
					     &val);

	if (err) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to check port %d Tx FIFO, err %d\n",
			port->port_num, err);
		return err;
	}

	if (offs & 0x1)
		phy_sts = (val & Q_REG_FIFO13_M) >> Q_REG_FIFO13_S;
	else
		phy_sts = (val & Q_REG_FIFO02_M) >> Q_REG_FIFO02_S;

	if (phy_sts & FIFO_EMPTY) {
		port->tx_fifo_busy_cnt = FIFO_OK;
		return 0;
	}

	port->tx_fifo_busy_cnt++;

	dev_dbg(ice_pf_to_dev(pf), "Try %d, port %d FIFO not empty\n",
		port->tx_fifo_busy_cnt, port->port_num);

	if (port->tx_fifo_busy_cnt == ICE_PTP_FIFO_NUM_CHECKS) {
		dev_dbg(ice_pf_to_dev(pf),
			"Port %d Tx FIFO still not empty; resetting quad %d\n",
			port->port_num, quad);
		ice_ptp_reset_ts_memory_quad_e822(hw, quad);
		port->tx_fifo_busy_cnt = FIFO_OK;
		return 0;
	}

	return -EAGAIN;
}

/**
 * ice_ptp_wait_for_offsets - Check for valid Tx and Rx offsets
 * @work: Pointer to the kthread_work structure for this task
 *
 * Check whether hardware has completed measuring the Tx and Rx offset values
 * used to configure and enable vernier timestamp calibration.
 *
 * Once the offset in either direction is measured, configure the associated
 * registers with the calibrated offset values and enable timestamping. The Tx
 * and Rx directions are configured independently as soon as their associated
 * offsets are known.
 *
 * This function reschedules itself until both Tx and Rx calibration have
 * completed.
 */
static void ice_ptp_wait_for_offsets(struct kthread_work *work)
{
	struct ice_ptp_port *port;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int tx_err;
	int rx_err;

	port = container_of(work, struct ice_ptp_port, ov_work.work);
	pf = ptp_port_to_pf(port);
	hw = &pf->hw;

	if (ice_is_reset_in_progress(pf->state)) {
		/* wait for device driver to complete reset */
		kthread_queue_delayed_work(pf->ptp.kworker,
					   &port->ov_work,
					   msecs_to_jiffies(100));
		return;
	}

	tx_err = ice_ptp_check_tx_fifo(port);
	if (!tx_err)
		tx_err = ice_phy_cfg_tx_offset_e822(hw, port->port_num);
	rx_err = ice_phy_cfg_rx_offset_e822(hw, port->port_num);
	if (tx_err || rx_err) {
		/* Tx and/or Rx offset not yet configured, try again later */
		kthread_queue_delayed_work(pf->ptp.kworker,
					   &port->ov_work,
					   msecs_to_jiffies(100));
		return;
	}

}

/**
 * ice_ptp_port_phy_stop - Stop timestamping for a PHY port
 * @ptp_port: PTP port to stop
 */
static int ice_ptp_port_phy_stop(struct ice_ptp_port *ptp_port)
{
	struct ice_pf *pf = ptp_port_to_pf(ptp_port);
	struct ice_ptp *ptp = &pf->ptp;
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	int err;

	if (!ptp->managed_phy)
		return 0;

	mutex_lock(&ptp_port->ps_lock);

	switch (hw->phy_model) {
	case ICE_PHY_ETH56G:
		err = ice_stop_phy_timer_eth56g(hw, port, true);
		break;
	case ICE_PHY_E822:
		kthread_cancel_delayed_work_sync(&ptp_port->ov_work);

		err = ice_stop_phy_timer_e822(hw, port, true);
		break;
	default:
		err = -ENODEV;
	}
	if (err && err != -EBUSY)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d down, status=%d\n",
			port, err);

	mutex_unlock(&ptp_port->ps_lock);

	return err;
}

/**
 * ice_ptp_port_phy_restart - (Re)start and calibrate PHY timestamping
 * @ptp_port: PTP port for which the PHY start is set
 *
 * Start the PHY timestamping block, and initiate Vernier timestamping
 * calibration. If timestamping cannot be calibrated (such as if link is down)
 * then disable the timestamping block instead.
 */
static int ice_ptp_port_phy_restart(struct ice_ptp_port *ptp_port)
{
	struct ice_pf *pf = ptp_port_to_pf(ptp_port);
	struct ice_ptp *ptp = &pf->ptp;
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	int err;

	if (!ptp->managed_phy)
		return 0;

	if (!ptp_port->link_up)
		return ice_ptp_port_phy_stop(ptp_port);

	mutex_lock(&ptp_port->ps_lock);

	switch (hw->phy_model) {
	case ICE_PHY_ETH56G:
		err = ice_start_phy_timer_eth56g(hw, port);
		break;
	case ICE_PHY_E822:
		/* Start the PHY timer in Vernier mode */
		kthread_cancel_delayed_work_sync(&ptp_port->ov_work);

		/* temporarily disable Tx timestamps while calibrating
		 * PHY offset
		 */
		spin_lock(&ptp_port->tx.lock);
		ptp_port->tx.calibrating = true;
		spin_unlock(&ptp_port->tx.lock);
		ptp_port->tx_fifo_busy_cnt = 0;

		/* Start the PHY timer in Vernier mode */
		err = ice_start_phy_timer_e822(hw, port);
		if (err)
			break;

		/* Enable Tx timestamps right away */
		spin_lock(&ptp_port->tx.lock);
		ptp_port->tx.calibrating = false;
		spin_unlock(&ptp_port->tx.lock);

		kthread_queue_delayed_work(pf->ptp.kworker, &ptp_port->ov_work,
					   0);
		break;
	default:
		err = -ENODEV;
	}

	if (err)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d up, status=%d\n",
			port, err);

	mutex_unlock(&ptp_port->ps_lock);

	return err;
}

/**
 * ice_ptp_phy_restart - Restart PHY
 * @pf: Board private structure
 */
int ice_ptp_phy_restart(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	err = ice_ptp_port_phy_restart(&pf->ptp.port);

	if (err) {
		dev_err(dev, "Failed to restart PHY, err %d\n", err);
		return err;
	}

	return 0;
}

/**
 * ice_ptp_link_change - Reconfigure PTP after link status change
 * @pf: Board private structure
 * @port: Port for which the PHY start is set
 * @linkup: Link is up or down
 */
void ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup)
{
	struct ice_ptp_port *ptp_port;
	struct ice_hw *hw = &pf->hw;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	if (WARN_ON_ONCE(port >= hw->max_phy_port))
		return;

	ptp_port = &pf->ptp.port;
	if (WARN_ON_ONCE(ptp_port->port_num != port))
		return;

	/* Update cached link status for this port immediately */
	ptp_port->link_up = linkup;

	if (ice_is_e825c(hw)) {
		bool active;
		u8 port_num;
		u8 divider;

		port_num = ptp_port->port_num;
		if (WARN_ON_ONCE(ice_cgu_bypass_mux_port_active_e825c(hw,
								      port_num,
								      &active)))
			return;

		if (active &&
		    test_bit(ICE_FLAG_ITU_G8262_FILTER_USED, pf->flags) &&
		    WARN_ON_ONCE(ice_cfg_synce_ethdiv_e825c(hw, &divider)))
			return;
	}

	switch (hw->phy_model) {
	case ICE_PHY_E810:
		/* Do not reconfigure E810 PHY */
		return;
	case ICE_PHY_ETH56G:
		/* Do not reconfigure ETH56G PHY */
		return;
	case ICE_PHY_E822:

		ice_ptp_port_phy_restart(ptp_port);

		return;
	default:
		dev_warn(ice_pf_to_dev(pf), "%s: Unknown PHY type\n", __func__);
	}
}

/**
 * ice_ptp_tx_cfg_intr - Enable or disable the Tx timestamp interrupt
 * @pf: PF private structure
 * @ena: bool value to enable or disable interrupt
 * @threshold: Minimum number of packets at which intr is triggered
 *
 * Utility function to enable or disable Tx timestamp interrupt and threshold
 */
static int ice_ptp_tx_cfg_intr(struct ice_pf *pf, bool ena, u32 threshold)
{
	struct ice_hw *hw = &pf->hw;
	int err = 0;
	int port;
	int quad;

	ice_ptp_reset_ts_memory(hw);

	switch (hw->phy_model) {
	case ICE_PHY_ETH56G:
		for (port = 0; port < hw->max_phy_port; port++) {
			err = ice_phy_cfg_intr_eth56g(hw, port, ena,
						      threshold);

			if (err)
				break;
		}

		break;
	case ICE_PHY_E810:
	case ICE_PHY_E822:
		for (quad = 0; quad < ICE_MAX_QUAD; quad++) {

			err = ice_phy_cfg_intr_e822(hw, quad, ena,
						    threshold);

			if (err)
				break;
		}

		break;
	default:
		err = -ENODEV;
	}

	if (err)
		dev_err(ice_pf_to_dev(pf), "PTP failed in intr ena, status %d\n",
			err);
	return err;
}

/**
 * ice_ptp_reset_phy_timestamping - Reset PHY timestamping block
 * @pf: Board private structure
 */
static void ice_ptp_reset_phy_timestamping(struct ice_pf *pf)
{
	ice_ptp_port_phy_restart(&pf->ptp.port);
}

/**
 * ice_ptp_restart_all_phy - Restart all PHYs to recalibrate timestamping
 * @pf: Board private structure
 */
static void ice_ptp_restart_all_phy(struct ice_pf *pf)
{
	struct list_head *entry;

	list_for_each(entry, &pf->ptp.ports_owner.ports) {
		struct ice_ptp_port *port = list_entry(entry,
						       struct ice_ptp_port,
						       list_member);

		if (port->link_up)
			ice_ptp_port_phy_restart(port);
	}
}

/**
 * ice_ptp_update_incval - Update clock increment rate
 * @pf: Board private structure
 * @time_ref_freq: TIME_REF frequency to use
 * @src_tmr_mode: Src timer mode (nanoseconds or locked)
 */
int
ice_ptp_update_incval(struct ice_pf *pf, enum ice_time_ref_freq time_ref_freq,
		      enum ice_src_tmr_mode src_tmr_mode)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct timespec64 ts;
	int err;

	if (!test_bit(ICE_FLAG_PTP, pf->flags)) {
		dev_err(dev, "PTP not ready, failed to update incval\n");
		return -EINVAL;
	}

	if (!ice_ptp_lock(hw))
		return -EBUSY;

	err = ice_ptp_write_incval(hw, ice_get_base_incval(hw, src_tmr_mode),
				   ice_is_primary(pf));
	if (err) {
		dev_err(dev, "PTP failed to update incval, status %d\n", err);
		goto err_unlock;
	}

	ts = ktime_to_timespec64(ktime_get_real());
	err = ice_ptp_write_init(pf, &ts, ice_is_primary(pf));
	if (err) {
		ice_dev_err_errno(dev, err,
				  "PTP failed to program time registers");
		goto err_unlock;
	}

	/* unlock PTP semaphore first before resetting PHY timestamping */
	ice_ptp_unlock(hw);
	ice_ptp_reset_ts_memory(hw);
	ice_ptp_restart_all_phy(pf);

	return 0;

err_unlock:
	ice_ptp_unlock(hw);

	return err;
}

/**
 * ice_ptp_adjfine - Adjust clock increment rate
 * @info: the driver's PTP info structure
 * @scaled_ppm: Parts per million with 16-bit fractional field
 *
 * Adjust the frequency of the clock by the indicated scaled ppm from the
 * base frequency.
 */
static int ice_ptp_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	u64 incval, diff;
	int neg_adj = 0;
	int err;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"adjfine not supported on secondary devices\n");
		return -ENODEV;
	}

	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"adjfreq not supported in locked mode\n");
		return -EPERM;
	}

	incval = ice_base_incval(pf);

	if (scaled_ppm < 0) {
		neg_adj = 1;
		scaled_ppm = -scaled_ppm;
	}

	diff = mul_u64_u64_div_u64(incval, (u64)scaled_ppm,
				   1000000ULL << 16);
	if (neg_adj)
		incval -= diff;
	else
		incval += diff;

	err = ice_ptp_write_incval_locked(hw, incval, true);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to set incval, err %d\n",
			err);
		return -EIO;
	}

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_ADJFINE
/**
 * ice_ptp_adjfreq - Adjust the frequency of the clock
 * @info: the driver's PTP info structure
 * @ppb: Parts per billion adjustment from the base
 *
 * Adjust the frequency of the clock by the indicated parts per billion from the
 * base frequency.
 */
static int ice_ptp_adjfreq(struct ptp_clock_info *info, s32 ppb)
{
	long scaled_ppm;

	/*
	 * We want to calculate
	 *
	 *    scaled_ppm = ppb * 2^16 / 1000
	 *
	 * which simplifies to
	 *
	 *    scaled_ppm = ppb * 2^13 / 125
	 */
	scaled_ppm = ((long)ppb << 13) / 125;
	return ice_ptp_adjfine(info, scaled_ppm);
}
#endif

/**
 * ice_ptp_extts_event - Process PTP external clock event
 * @pf: Board private structure
 */
void ice_ptp_extts_event(struct ice_pf *pf)
{
	struct ptp_clock_event event;
	struct ice_hw *hw = &pf->hw;
	u8 chan, tmr_idx;
	u32 hi, lo;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	/* Event time is captured by one of the two matched registers
	 *      GLTSYN_EVNT_L: 32 LSB of sampled time event
	 *      GLTSYN_EVNT_H: 32 MSB of sampled time event
	 * Event is defined in GLTSYN_EVNT_0 register
	 */
	for (chan = 0; chan < GLTSYN_EVNT_H_IDX_MAX; chan++) {
		/* Check if channel is enabled */
		if (pf->ptp.ext_ts_irq & (1 << chan)) {
			lo = rd32(hw, GLTSYN_EVNT_L(chan, tmr_idx));
			hi = rd32(hw, GLTSYN_EVNT_H(chan, tmr_idx));
			event.timestamp = (((u64)hi) << 32) | lo;
			event.type = PTP_CLOCK_EXTTS;
			event.index = chan;

			pf->ptp.ext_ts_irq &= ~(1 << chan);

			/* Fire event if not filtered by CGU state */
			if (ice_is_feature_supported(pf, ICE_F_CGU) &&
			    test_bit(ICE_FLAG_DPLL_MONITOR, pf->flags) &&
			    test_bit(ICE_FLAG_EXTTS_FILTER, pf->flags) &&
			    pf->ptp_dpll_state != ICE_CGU_STATE_LOCKED &&
			    pf->ptp_dpll_state != ICE_CGU_STATE_LOCKED_HO_ACQ)
				continue;

			ptp_clock_event(pf->ptp.clock, &event);
		}
	}
}

/**
 * ice_ptp_cfg_extts - Configure EXTTS pin and channel
 * @pf: Board private structure
 * @ena: true to enable; false to disable
 * @chan: GPIO channel
 * @gpio_pin: GPIO pin
 * @extts_flags: request flags from the ptp_extts_request.flags
 */
static int
ice_ptp_cfg_extts(struct ice_pf *pf, bool ena, unsigned int chan, u32 gpio_pin,
		  unsigned int extts_flags)
{
	u32 func, aux_reg, gpio_reg, irq_reg;
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;

	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf), "Locked mode EXTTS not supported\n");
		return -EOPNOTSUPP;
	}

	if (chan > GLTSYN_TGT_H_IDX_MAX)
		return -EINVAL;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	irq_reg = rd32(hw, PFINT_OICR_ENA);

	if (ena) {
		/* Enable the interrupt */
		irq_reg |= PFINT_OICR_TSYN_EVNT_M;
		aux_reg = GLTSYN_AUX_IN_0_INT_ENA_M;

#define GLTSYN_AUX_IN_0_EVNTLVL_RISING_EDGE	BIT(0)
#define GLTSYN_AUX_IN_0_EVNTLVL_FALLING_EDGE	BIT(1)

		/* set event level to requested edge */
		if (extts_flags & PTP_FALLING_EDGE)
			aux_reg |= GLTSYN_AUX_IN_0_EVNTLVL_FALLING_EDGE;
		if (extts_flags & PTP_RISING_EDGE)
			aux_reg |= GLTSYN_AUX_IN_0_EVNTLVL_RISING_EDGE;

		/* Write GPIO CTL reg.
		 * 0x1 is input sampled by EVENT register(channel)
		 * + num_in_channels * tmr_idx
		 */
		func = 1 + chan + (tmr_idx * 3);
		gpio_reg = ((func << GLGEN_GPIO_CTL_PIN_FUNC_S) &
			    GLGEN_GPIO_CTL_PIN_FUNC_M);
		pf->ptp.ext_ts_chan |= (1 << chan);
	} else {
		/* clear the values we set to reset defaults */
		aux_reg = 0;
		gpio_reg = 0;
		pf->ptp.ext_ts_chan &= ~(1 << chan);
		if (!pf->ptp.ext_ts_chan)
			irq_reg &= ~PFINT_OICR_TSYN_EVNT_M;
	}

	wr32(hw, PFINT_OICR_ENA, irq_reg);
	wr32(hw, GLTSYN_AUX_IN(chan, tmr_idx), aux_reg);
	wr32(hw, GLGEN_GPIO_CTL(gpio_pin), gpio_reg);

	return 0;
}

/**
 * ice_ptp_cfg_clkout - Configure clock to generate periodic wave
 * @pf: Board private structure
 * @chan: GPIO channel (0-3)
 * @config: desired periodic clk configuration. NULL will disable channel
 * @store: If set to true the values will be stored
 *
 * Configure the internal clock generator modules to generate the clock wave of
 * specified period.
 */
int ice_ptp_cfg_clkout(struct ice_pf *pf, unsigned int chan,
		       struct ice_perout_channel *config, bool store)
{
	u64 current_time, period, start_time, phase;
	struct ice_hw *hw = &pf->hw;
	u32 func, val, gpio_pin;
	u8 tmr_idx;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* 0. Reset mode & out_en in AUX_OUT */
	wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), 0);

	/* If we're disabling the output, clear out CLKO and TGT and keep
	 * output level low
	 */
	if (!config || !config->ena || !config->period) {
		wr32(hw, GLTSYN_CLKO(chan, tmr_idx), 0);
		wr32(hw, GLTSYN_TGT_L(chan, tmr_idx), 0);
		wr32(hw, GLTSYN_TGT_H(chan, tmr_idx), 0);

		val = GLGEN_GPIO_CTL_PIN_DIR_M;
		gpio_pin = pf->ptp.perout_channels[chan].gpio_pin;
		wr32(hw, GLGEN_GPIO_CTL(gpio_pin), val);

		/* Store the value if requested */
		if (store)
			memset(&pf->ptp.perout_channels[chan], 0,
			       sizeof(struct ice_perout_channel));

		return 0;
	}
	period = config->period;
	/* 1. Write clkout with half of required period value */
	if (period & 0x1) {
		dev_err(ice_pf_to_dev(pf), "CLK Period must be an even value\n");
		goto err;
	}

	start_time = config->start_time;
	div64_u64_rem(start_time, period, &phase);
	gpio_pin = config->gpio_pin;

	period >>= 1;
	period = ice_ptp_ns2ticks(pf, period);
	start_time = ice_ptp_ns2ticks(pf, start_time);

	/* For proper operation, the GLTSYN_CLKO must be larger than clock tick
	 */
#define MIN_PULSE 3
	if (period <= MIN_PULSE || period > U32_MAX) {
		dev_err(ice_pf_to_dev(pf), "CLK Period must be > %d && < 2^33",
			MIN_PULSE * 2);
		goto err;
	}

	wr32(hw, GLTSYN_CLKO(chan, tmr_idx), lower_32_bits(period));

	/* Allow time for programming before start_time is hit */
	current_time = ice_ptp_read_src_clk_reg(pf, NULL);

	/* if start time is in the past start the timer at the nearest second
	 * maintaining phase
	 */
	if (start_time < current_time)
		start_time = div64_u64(current_time + NSEC_PER_SEC - 1,
				       NSEC_PER_SEC) * NSEC_PER_SEC + phase;

	start_time -= ice_prop_delay(hw);

	/* 2. Write TARGET time */
	wr32(hw, GLTSYN_TGT_L(chan, tmr_idx), lower_32_bits(start_time));
	wr32(hw, GLTSYN_TGT_H(chan, tmr_idx), upper_32_bits(start_time));

	/* 3. Write AUX_OUT register */
	val = GLTSYN_AUX_OUT_0_OUT_ENA_M | GLTSYN_AUX_OUT_0_OUTMOD_M;
	wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), val);

	/* 4. write GPIO CTL reg */
	func = 8 + chan + (tmr_idx * 4);
	val = GLGEN_GPIO_CTL_PIN_DIR_M |
	      ((func << GLGEN_GPIO_CTL_PIN_FUNC_S) & GLGEN_GPIO_CTL_PIN_FUNC_M);
	wr32(hw, GLGEN_GPIO_CTL(gpio_pin), val);

	/* Store the value if requested */
	if (store) {
		memcpy(&pf->ptp.perout_channels[chan], config,
		       sizeof(struct ice_perout_channel));
		pf->ptp.perout_channels[chan].start_time = phase;
	}

	return 0;
err:
	dev_err(ice_pf_to_dev(pf), "PTP failed to cfg per_clk\n");
	return -EFAULT;
}

/**
 * ice_ptp_disable_all_clkout - Disable all currently configured outputs
 * @pf: pointer to the PF structure
 *
 * Disable all currently configured clock outputs. This is necessary before
 * certain changes to the PTP hardware clock. Use ice_ptp_enable_all_clkout to
 * re-enable the clocks again.
 */
static void ice_ptp_disable_all_clkout(struct ice_pf *pf)
{
	uint i;

	for (i = 0; i < GLTSYN_TGT_H_IDX_MAX; i++)
		if (pf->ptp.perout_channels[i].present &&
		    pf->ptp.perout_channels[i].ena)
			ice_ptp_cfg_clkout(pf, i, NULL, false);
}

/**
 * ice_ptp_enable_all_clkout - Enable all configured periodic clock outputs
 * @pf: pointer to the PF structure
 *
 * Enable all currently configured clock outputs. Use this after
 * ice_ptp_disable_all_clkout to reconfigure the output signals according to
 * their configuration.
 */
static void ice_ptp_enable_all_clkout(struct ice_pf *pf)
{
	uint i;

	for (i = 0; i < GLTSYN_TGT_H_IDX_MAX; i++)
		if (pf->ptp.perout_channels[i].present &&
		    pf->ptp.perout_channels[i].ena)
			ice_ptp_cfg_clkout(pf, i, &pf->ptp.perout_channels[i],
					   false);
}

/**
 * ice_verify_pin_e82x - verify if pin supports requested pin function
 * @info: the driver's PTP info structure
 * @pin: Pin index
 * @func: Assigned function
 * @chan: Assigned channel
 */
static int
ice_verify_pin_e82x(struct ptp_clock_info *info, unsigned int pin,
		    enum ptp_pin_function func, unsigned int chan)
{
	/* Don't allow channel and function reassignment */
	if (chan != ice_pin_desc_e82x[pin].chan ||
	    func != ice_pin_desc_e82x[pin].func)
		return -EOPNOTSUPP;

	return 0;
}

/**
 * ice_ptp_gpio_enable_e82x - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int
ice_ptp_gpio_enable_e82x(struct ptp_clock_info *info,
			 struct ptp_clock_request *rq, int on)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_perout_channel clk_cfg = {0};
	int err;

	switch (rq->type) {
	case PTP_CLK_REQ_PEROUT:
		clk_cfg.gpio_pin = _1PPS_OUT;
		clk_cfg.period = NSEC_PER_SEC;
		clk_cfg.start_time = ((rq->perout.start.sec * NSEC_PER_SEC) +
				       rq->perout.start.nsec);
		clk_cfg.ena = !!on;

		err = ice_ptp_cfg_clkout(pf, rq->perout.index, &clk_cfg, true);
		break;
	case PTP_CLK_REQ_EXTTS:
		err = ice_ptp_cfg_extts(pf, !!on, rq->extts.index, TIME_SYNC,
					rq->extts.flags);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return err;
}

/**
 * ice_ptp_gpio_enable_e810 - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int
ice_ptp_gpio_enable_e810(struct ptp_clock_info *info,
			 struct ptp_clock_request *rq, int on)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_perout_channel clk_cfg = {0};
	unsigned int chan;
	u32 gpio_pin;
	int err;

	switch (rq->type) {
	case PTP_CLK_REQ_PEROUT:
		chan = rq->perout.index;
		if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
			if (chan == ice_pin_desc_e810t[SMA1].chan)
				clk_cfg.gpio_pin = GPIO_20;
			else if (chan == ice_pin_desc_e810t[SMA2].chan)
				clk_cfg.gpio_pin = GPIO_22;
			else
				return -1;
		} else if (ice_is_feature_supported(pf,
			   ICE_F_FIXED_TIMING_PINS)) {
			if (chan == 0)
				clk_cfg.gpio_pin = GPIO_20;
			else
				clk_cfg.gpio_pin = GPIO_22;
		} else if (chan == PPS_CLK_GEN_CHAN) {
			clk_cfg.gpio_pin = _1PPS_OUT;
		} else {
			clk_cfg.gpio_pin = chan;
		}

		clk_cfg.period = ((rq->perout.period.sec * NSEC_PER_SEC) +
				   rq->perout.period.nsec);
		clk_cfg.start_time = ((rq->perout.start.sec * NSEC_PER_SEC) +
				       rq->perout.start.nsec);
		clk_cfg.ena = !!on;

		err = ice_ptp_cfg_clkout(pf, chan, &clk_cfg, true);
		break;
	case PTP_CLK_REQ_EXTTS:
		chan = rq->extts.index;

		if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
			if (chan < 2)
				gpio_pin = GPIO_21;
			else
				gpio_pin = GPIO_23;
		} else if (ice_is_feature_supported(pf,
			   ICE_F_FIXED_TIMING_PINS)) {
			if (chan == 0)
				gpio_pin = GPIO_21;
			else
				gpio_pin = GPIO_23;
		} else {
			gpio_pin = chan;
		}

		err = ice_ptp_cfg_extts(pf, !!on, chan, gpio_pin,
					rq->extts.flags);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return err;
}

/**
 * ice_ptp_gettimex64 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure to hold the current time value
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int
ice_ptp_gettimex64(struct ptp_clock_info *info, struct timespec64 *ts,
		   struct ptp_system_timestamp *sts)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	u64 time_ns;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"gettime not supported on secondary devices\n");
		return -ENODEV;
	}

	time_ns = ice_ptp_ticks2ns(pf, ice_ptp_read_src_clk_reg(pf, sts));

	*ts = ns_to_timespec64(time_ns);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIMEX64
/**
 * ice_ptp_gettime64 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int ice_ptp_gettime64(struct ptp_clock_info *info, struct timespec64 *ts)
{
	return ice_ptp_gettimex64(info, ts, NULL);
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * ice_ptp_gettime32 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int ice_ptp_gettime32(struct ptp_clock_info *info, struct timespec *ts)
{
	struct timespec64 ts64;

	if (ice_ptp_gettime64(info, &ts64))
		return -EFAULT;

	*ts = timespec64_to_timespec(ts64);
	return 0;
}

#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIMEX64 */
/**
 * ice_ptp_settime64 - Set the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int
ice_ptp_settime64(struct ptp_clock_info *info, const struct timespec64 *ts)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct timespec64 ts64 = *ts;
	struct ice_hw *hw = &pf->hw;
	int status;
	int err;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"settime not supported on secondary devices\n");
		return -ENODEV;
	}

	/* For Vernier mode, we need to recalibrate after new settime.
	 * Start with marking timestamps as invalid.
	 */
	status = ice_ptp_clear_phy_offset_ready(hw);
	if (status)
		dev_warn(ice_pf_to_dev(pf), "Failed to mark timestamps as invalid before settime\n");

	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		goto exit;
	}

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);

	err = ice_ptp_write_init(pf, &ts64, true);

	/* Reenable periodic outputs */
	ice_ptp_enable_all_clkout(pf);
	ice_ptp_unlock(hw);

	if (!err)
		ice_ptp_reset_cached_phctime(pf);

	/* Recalibrate and re-enable timestamp block */
	if (hw->phy_model == ICE_PHY_E822)
		ice_ptp_restart_all_phy(pf);
exit:
	if (err) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to set time %d\n", err);
		return err;
	}

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * ice_ptp_settime32 - Set the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int
ice_ptp_settime32(struct ptp_clock_info *info, const struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);

	return ice_ptp_settime64(info, &ts64);
}
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */

/**
 * ice_ptp_adjtime_nonatomic - Do a non-atomic clock adjustment
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime_nonatomic(struct ptp_clock_info *info, s64 delta)
{
	struct timespec64 now, then;
	int ret;

	then = ns_to_timespec64(delta);
	ret = ice_ptp_gettimex64(info, &now, NULL);
	if (ret)
		return ret;
	now = timespec64_add(now, then);

	return ice_ptp_settime64(info, (const struct timespec64 *)&now);
}

/**
 * ice_ptp_read_perout_tgt - Read the periodic out target time registers
 * @pf: Board private structure
 * @chan: GPIO channel (0-3)
 */
static u64 ice_ptp_read_perout_tgt(struct ice_pf *pf, unsigned int chan)
{
	struct ice_hw *hw = &pf->hw;
	u32 hi, hi2, lo;
	u8 tmr_idx;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	hi = rd32(hw, GLTSYN_TGT_H(chan, tmr_idx));
	lo = rd32(hw, GLTSYN_TGT_L(chan, tmr_idx));
	hi2 = rd32(hw, GLTSYN_TGT_H(chan, tmr_idx));

	if (hi != hi2) {
		/* Between reads, target was hit and auto-advanced */
		lo = rd32(hw, GLTSYN_TGT_L(chan, tmr_idx));
		hi = hi2;
	}

	return ((u64)hi << 32) | lo;
}

/**
 * ice_ptp_write_neg_adj_fine - Write atomic clock adjustment
 * @pf: Board private structure
 * @adj: atomic adjustment in nanoseconds
 *
 * Write an atomic clock adjustment when perout is enabled, and the adjustment
 * is less than 10 milliseconds, and is negative. For these adjustments, we
 * delay the adjustment until just passing a perout signal edge. Then, we stop
 * the SDP controlling the perout, perform the adjustment, and then re-enable
 * the pin output. This enables a small adjustment while leaving a continuous
 * perout signal output without missing a perout edge trigger.
 *
 * In order to ensure we perform the update within the valid window,
 * preemption must be disabled, and the sideband queue lock must be taken up
 * front.
 */
static int ice_ptp_write_neg_adj_fine(struct ice_pf *pf, s32 adj)
{
	struct ice_hw *hw = &pf->hw;
	unsigned long flags = 0;
	unsigned int chan;
	int err = 0;
	u8 tmr_idx;

	/* Lock the sideband queue's send queue lock in advance, since we can't
	 * do it while atomic
	 */
	ice_sbq_lock(hw);

	/* The whole sequence must be done within the valid window, so make sure
	 * we aren't preempted here
	 */
	local_irq_save(flags);
	preempt_disable();

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* Calculate time to next edge */
	for (chan = 0; chan < GLTSYN_TGT_H_IDX_MAX; chan++) {
		u64 systime, target, ns_to_edge;
		u32 val;

		if (!pf->ptp.perout_channels[chan].present ||
		    !pf->ptp.perout_channels[chan].ena)
			continue;

		systime = ice_ptp_read_src_clk_reg(pf, NULL);
		target = ice_ptp_read_perout_tgt(pf, chan);
		ns_to_edge = target - systime;
		ns_to_edge = ice_ptp_ticks2ns(pf, ns_to_edge);

#define PTP_ADJ_TIME_NS 5000000		/* 5 ms */
		/* If we're close to an edge of the PPS, we need to wait until
		 * the edge has passed.
		 */
		if (ns_to_edge < PTP_ADJ_TIME_NS) {
			unsigned int i;

			/* Wait for the next edge (and a bit extra) */
			udelay(ns_to_edge / NSEC_PER_USEC + 10);

			/* Check if we got past edge; iterate for up to 6 ms */
#define ICE_PTP_ADJ_MAX_DELAY_RETRY 600
			for (i = 0; i < ICE_PTP_ADJ_MAX_DELAY_RETRY; i++) {
				u64 tgt_new;

				tgt_new = ice_ptp_read_perout_tgt(pf, chan);
				if (tgt_new != target)
					break;

				udelay(10);
			}

			if (i == ICE_PTP_ADJ_MAX_DELAY_RETRY)
				continue;
		}

		/* Disabling the output prevents the output from toggling, but
		 * does not change the output state to low, so it may be used to
		 * perform fine adjustments while maintaining a continuous
		 * periodic output
		 */
		/* Clear enabled bit */
		val = rd32(hw, GLTSYN_AUX_OUT(chan, tmr_idx));
		val &= ~GLTSYN_AUX_OUT_0_OUT_ENA_M;
		wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), val);

		err = ice_ptp_write_adj(pf, adj, false);
		if (err)
			break;

		/* Set enabled bit */
		val |= GLTSYN_AUX_OUT_0_OUT_ENA_M;
		wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), val);
	}

	preempt_enable();
	local_irq_restore(flags);
	ice_sbq_unlock(&pf->hw);

	return err;
}

/**
 * ice_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	bool perout_ena = false;
	s64 delta_ns = delta;
	struct device *dev;
	unsigned int i;
	int err;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"adjtime not supported on secondary devices\n");
		return -ENODEV;
	}

	dev = ice_pf_to_dev(pf);

	if (delta >= 0)
		delta = ice_ptp_ns2ticks(pf, delta);
	else
		delta = -ice_ptp_ns2ticks(pf, -delta);

	/* Hardware only supports atomic adjustments using signed 32-bit
	 * integers. For any adjustment outside this range, perform
	 * a non-atomic get->adjust->set flow.
	 */
	if (delta > S32_MAX || delta < S32_MIN) {
		dev_dbg(dev, "delta = %lld, adjtime non-atomic\n", delta);
		return ice_ptp_adjtime_nonatomic(info, delta);
	}

	if (!ice_ptp_lock(hw)) {
		dev_err(dev, "PTP failed to acquire semaphore in adjtime\n");
		return -EBUSY;
	}

	for (i = 0; i < GLTSYN_TGT_H_IDX_MAX; i++)
		if (pf->ptp.perout_channels[i].present &&
		    pf->ptp.perout_channels[i].ena)
			perout_ena = true;

#define COARSE_ADJ_THRESH 10000000	/* 10 ms */
	if (perout_ena) {
		/* If the PPS output is enabled, an adjustment could result in
		 * the clock being skipped forward or past the next PPS target
		 * time trigger. In the negative case, this would result in
		 * the pin output being disabled. In the positive case, this
		 * could result in many PPS edges being lost.
		 *
		 * If the adjustment is larger than 10 ms, disable the PPS
		 * before the adjustment and re-enable it afterwards.
		 * Otherwise, if it is negative, ensure we don't miss an edge
		 * by delaying the adjustment until just after an edge.
		 *
		 * For small positive adjustments, just write the adjustment
		 * immediately.
		 */
		if (delta_ns > COARSE_ADJ_THRESH ||
		    delta_ns < -COARSE_ADJ_THRESH) {
			ice_ptp_disable_all_clkout(pf);
			err = ice_ptp_write_adj(pf, delta, true);
			ice_ptp_enable_all_clkout(pf);
		} else if (delta < 0) {
			err = ice_ptp_write_neg_adj_fine(pf, delta);
		} else {
			err = ice_ptp_write_adj(pf, delta, true);
		}
	} else {
		err = ice_ptp_write_adj(pf, delta, true);
	}
	ice_ptp_unlock(hw);

	if (err) {
		ice_dev_err_errno(dev, err, "PTP failed to adjust time");
		return err;
	}

	ice_ptp_reset_cached_phctime(pf);

	return 0;
}

#ifdef HAVE_PTP_CROSSTIMESTAMP
/**
 * ice_ptp_get_syncdevicetime - Get the cross time stamp info
 * @device: Current device time
 * @system: System counter value read synchronously with device time
 * @ctx: Context provided by timekeeping code
 *
 * Read device and system (ART) clock simultaneously and return the corrected
 * clock values in ns.
 */
static int
ice_ptp_get_syncdevicetime(ktime_t *device,
			   struct system_counterval_t *system,
			   void *ctx)
{
	struct ice_pf *pf = ctx;
	struct ice_hw *hw = &pf->hw;
	u32 hh_lock, hh_art_ctl, tmr_idx, cmd_val;
	int i;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"syncdevicetime not supported on secondary devices\n");
		return -ENODEV;
	}

#define MAX_HH_HW_LOCK_TRIES	5
#define MAX_HH_CTL_LOCK_TRIES	100

	for (i = 0; i < MAX_HH_HW_LOCK_TRIES; i++) {
		/* Get the HW lock */
		hh_lock = rd32(hw, PFHH_SEM + (PFTSYN_SEM_BYTES * hw->pf_id));
		if (hh_lock & PFHH_SEM_BUSY_M) {
			usleep_range(10000, 15000);
			continue;
		}
		break;
	}
	if (hh_lock & PFHH_SEM_BUSY_M) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to get hh lock\n");
		return -EBUSY;
	}

	/* Program cmd to master timer */
	ice_ptp_src_cmd(hw, ICE_PTP_READ_TIME);

	/* Start the ART and device clock sync sequence */
	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	cmd_val = tmr_idx << SEL_CPK_SRC;
	wr32(hw, GLTSYN_CMD, cmd_val);

	hh_art_ctl = rd32(hw, GLHH_ART_CTL);
	hh_art_ctl = hh_art_ctl | GLHH_ART_CTL_ACTIVE_M;
	wr32(hw, GLHH_ART_CTL, hh_art_ctl);

	for (i = 0; i < MAX_HH_CTL_LOCK_TRIES; i++) {
		/* Wait for sync to complete */
		hh_art_ctl = rd32(hw, GLHH_ART_CTL);
		if (hh_art_ctl & GLHH_ART_CTL_ACTIVE_M) {
			udelay(1);
			continue;
		} else {
			u32 hh_ts_lo, hh_ts_hi;
			u64 hh_ts;

			/* Read ART time */
			hh_ts_lo = rd32(hw, GLHH_ART_TIME_L);
			hh_ts_hi = rd32(hw, GLHH_ART_TIME_H);
			hh_ts = ((u64)hh_ts_hi << 32) | hh_ts_lo;
			*system = convert_art_ns_to_tsc(hh_ts);
			/* Read Device source clock time */
			hh_ts_lo = rd32(hw, GLTSYN_HHTIME_L(tmr_idx));
			hh_ts_hi = rd32(hw, GLTSYN_HHTIME_H(tmr_idx));
			hh_ts = ice_ptp_ticks2ns(pf, (((u64)hh_ts_hi << 32) |
						      hh_ts_lo));
			*device = ns_to_ktime(hh_ts);
			break;
		}
	}

	/* Clear the master timer */
	ice_ptp_src_cmd(hw, ICE_PTP_NOP);

	/* Release HW lock */
	hh_lock = rd32(hw, PFHH_SEM + (PFTSYN_SEM_BYTES * hw->pf_id));
	hh_lock = hh_lock & ~PFHH_SEM_BUSY_M;
	wr32(hw, PFHH_SEM + (PFTSYN_SEM_BYTES * hw->pf_id), hh_lock);

	if (i == MAX_HH_CTL_LOCK_TRIES)
		return -ETIMEDOUT;

	return 0;
}

/**
 * ice_ptp_getcrosststamp_generic - Capture a device cross timestamp
 * @info: the driver's PTP info structure
 * @cts: The memory to fill the cross timestamp info
 *
 * Capture a cross timestamp between the ART and the device PTP hardware
 * clock. Fill the cross timestamp information and report it back to the
 * caller.
 *
 * This is only valid for E822 and E823 devices which have support for
 * generating the cross timestamp via PCIe PTM.
 *
 * In order to correctly correlate the ART timestamp back to the TSC time, the
 * CPU must have X86_FEATURE_TSC_KNOWN_FREQ.
 */
static int
ice_ptp_getcrosststamp_generic(struct ptp_clock_info *info,
			       struct system_device_crosststamp *cts)
{
	struct ice_pf *pf = ptp_info_to_pf(info);

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"getcrosststamp not supported on secondary devices\n");
		return -ENODEV;
	}

	return get_device_system_crosststamp(ice_ptp_get_syncdevicetime,
					     pf, NULL, cts);
}
#endif /* HAVE_PTP_CROSSTIMESTAMP */

/**
 * ice_ptp_get_ts_config - ioctl interface to read the timestamping config
 * @pf: Board private structure
 * @ifr: ioctl data
 *
 * Copy the timestamping config to user buffer
 */
int ice_ptp_get_ts_config(struct ice_pf *pf, struct ifreq *ifr)
{
	struct hwtstamp_config *config;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return -EIO;

	config = &pf->ptp.tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ?
		-EFAULT : 0;
}

/**
 * ice_ptp_set_timestamp_mode - Setup driver for requested timestamp mode
 * @pf: Board private structure
 * @config: hwtstamp settings requested or saved
 */
static int
ice_ptp_set_timestamp_mode(struct ice_pf *pf, struct hwtstamp_config *config)
{
	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		ice_set_tx_tstamp(pf, false);
		break;
	case HWTSTAMP_TX_ON:
		ice_set_tx_tstamp(pf, true);
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		ice_set_rx_tstamp(pf, false);
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
#ifdef HAVE_HWTSTAMP_FILTER_NTP_ALL
	case HWTSTAMP_FILTER_NTP_ALL:
#endif /* HAVE_HWTSTAMP_FILTER_NTP_ALL */
	case HWTSTAMP_FILTER_ALL:
		ice_set_rx_tstamp(pf, true);
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

/**
 * ice_ptp_set_ts_config - ioctl interface to control the timestamping
 * @pf: Board private structure
 * @ifr: ioctl data
 *
 * Get the user config and store it
 */
int ice_ptp_set_ts_config(struct ice_pf *pf, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return -EAGAIN;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = ice_ptp_set_timestamp_mode(pf, &config);
	if (err)
		return err;

	/* Return the actual configuration set */
	config = pf->ptp.tstamp_config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

/**
 * ice_ptp_rx_hwtstamp - Check for an Rx timestamp
 * @rx_ring: Ring to get the VSI info
 * @rx_desc: Receive descriptor
 * @skb: Particular skb to send timestamp with
 *
 * The driver receives a notification in the receive descriptor with timestamp.
 * The timestamp is in ns, so we must convert the result first.
 */
void
ice_ptp_rx_hwtstamp(struct ice_rx_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *hwtstamps;
	u64 ts_ns, cached_time;
	u32 ts_high;

	if (!(rx_desc->wb.time_stamp_low & ICE_PTP_TS_VALID))
		return;

	cached_time = READ_ONCE(rx_ring->cached_phctime);

	/* Do not report a timestamp if we don't have a cached PHC time */
	if (!cached_time)
		return;

	/* Use ice_ptp_extend_32b_ts directly, using the ring-specific cached
	 * PHC value, rather than accessing the PF. This also allows us to
	 * simply pass the upper 32bits of nanoseconds directly. Calling
	 * ice_ptp_extend_40b_ts is unnecessary as it would just discard these
	 * bits itself.
	 */
	ts_high = le32_to_cpu(rx_desc->wb.flex_ts.ts_high);
	ts_ns = ice_ptp_extend_32b_ts(cached_time, ts_high);
	ts_ns = ice_ptp_ticks2ns(rx_ring->vsi->back, ts_ns);

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ts_ns);
}

/**
 * ice_ptp_disable_sma_pins_e810t - Disable E810-T SMA pins
 * @pf: pointer to the PF structure
 * @info: PTP clock info structure
 *
 * Disable the OS access to the SMA pins. Called to clear out the OS
 * indications of pin support when we fail to setup the E810-T SMA control
 * register.
 */
static void
ice_ptp_disable_sma_pins_e810t(struct ice_pf *pf, struct ptp_clock_info *info)
{
	struct device *dev = ice_pf_to_dev(pf);

	dev_warn(dev, "Failed to configure E810-T SMA pin control\n");

	info->enable = NULL;
	info->verify = NULL;
	info->n_pins = 0;
	info->n_ext_ts = 0;
	info->n_per_out = 0;
}

/**
 * ice_ptp_setup_sma_pins_e810t - Setup the SMA pins
 * @pf: pointer to the PF structure
 * @info: PTP clock info structure
 *
 * Finish setting up the SMA pins by allocating pin_config, and setting it up
 * according to the current status of the SMA. On failure, disable all of the
 * extended SMA pin support.
 */
static void
ice_ptp_setup_sma_pins_e810t(struct ice_pf *pf, struct ptp_clock_info *info)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	/* Allocate memory for kernel pins interface */
	info->pin_config = devm_kcalloc(dev, info->n_pins,
				        sizeof(*info->pin_config), GFP_KERNEL);
	if (!info->pin_config) {
		dev_err(dev, "Failed to allocate pin_config for E810-T SMA pins\n");
		ice_ptp_disable_sma_pins_e810t(pf, info);
		return;
	}

	/* Read current SMA status */
	err = ice_get_sma_config_e810t(pf, info->pin_config);
	if (err)
		ice_ptp_disable_sma_pins_e810t(pf, info);
}

/**
 * ice_ptp_setup_pins_e810 - Setup PTP pins in sysfs
 * @pf: pointer to the PF instance
 * @info: PTP clock capabilities
 */
static void
ice_ptp_setup_pins_e810(struct ice_pf *pf, struct ptp_clock_info *info)
{
	info->n_per_out = N_PER_OUT_E810;
	info->n_ext_ts = N_EXT_TS_E810;

	if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
		info->n_ext_ts = N_EXT_TS_E810;
		info->n_pins = NUM_PTP_PINS_E810T;
		info->verify = ice_verify_pin_e810t;

		/* Complete setup of the SMA pins */
		ice_ptp_setup_sma_pins_e810t(pf, info);
		return;
	}

	if (ice_is_feature_supported(pf, ICE_F_FIXED_TIMING_PINS)) {
		info->n_ext_ts = N_EXT_TS_NO_SMA_E810T;
		info->n_per_out = N_PER_OUT_NO_SMA_E810T;
		return;
	}
}

/**
 * ice_ptp_setup_pin_desc_e82x - setup ptp_pin_desc structure
 * @pf: Board private structure
 * @info: PTP info to fill
 */
static void
ice_ptp_setup_pin_desc_e82x(struct ice_pf *pf, struct ptp_clock_info *info)
{
	struct ptp_pin_desc *pins;
	int i;

	/* Allocate memory for kernel pins interface */
	info->pin_config = devm_kcalloc(ice_pf_to_dev(pf), info->n_pins,
					sizeof(*info->pin_config), GFP_KERNEL);
	if (!info->pin_config) {
		dev_err(ice_pf_to_dev(pf), "Failed to allocate pin_config for E82X pins\n");
		return;
	}

	pins = info->pin_config;
	for (i = 0; i < info->n_pins; i++) {
		snprintf(pins[i].name, sizeof(pins[i].name), "%s",
			 ice_pin_desc_e82x[i].name);
		pins[i].index = i;
		pins[i].func = ice_pin_desc_e82x[i].func;
		pins[i].chan = ice_pin_desc_e82x[i].chan;
		if (pins[i].func == PTP_PF_PEROUT)
			pf->ptp.perout_channels[pins[i].chan].present = true;
	}
}

/**
 * ice_ptp_set_funcs_e82x - Set specialized functions for E82x support
 * @pf: Board private structure
 * @info: PTP info to fill
 *
 * Assign functions to the PTP capabiltiies structure for E82x devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for E82x
 * devices.
 */
static void
ice_ptp_set_funcs_e82x(struct ice_pf *pf, struct ptp_clock_info *info)
{
#ifdef HAVE_PTP_CROSSTIMESTAMP
	if (boot_cpu_has(X86_FEATURE_ART) &&
	    boot_cpu_has(X86_FEATURE_TSC_KNOWN_FREQ))
		info->getcrosststamp = ice_ptp_getcrosststamp_generic;
#endif /* HAVE_PTP_CROSSTIMESTAMP */
	info->enable = ice_ptp_gpio_enable_e82x;
	info->verify = ice_verify_pin_e82x;
	info->n_per_out = 1;
	info->n_ext_ts = 1;
	info->n_pins = 2;

	ice_ptp_setup_pin_desc_e82x(pf, info);
}

/**
 * ice_ptp_set_funcs_e810 - Set specialized functions for E810 support
 * @pf: Board private structure
 * @info: PTP info to fill
 *
 * Assign functions to the PTP capabiltiies structure for E810 devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for e810
 * devices.
 */
static void
ice_ptp_set_funcs_e810(struct ice_pf *pf, struct ptp_clock_info *info)
{
	info->enable = ice_ptp_gpio_enable_e810;
	ice_ptp_setup_pins_e810(pf, info);
}

/**
 * ice_ptp_set_caps - Set PTP capabilities
 * @pf: Board private structure
 */
static void ice_ptp_set_caps(struct ice_pf *pf)
{
	struct ptp_clock_info *info = &pf->ptp.info;
	struct device *dev = ice_pf_to_dev(pf);

	snprintf(info->name, sizeof(info->name) - 1, "%s-%s-clk",
		 dev_driver_string(dev), dev_name(dev));
	info->owner = THIS_MODULE;
	info->max_adj = 100000000;
	info->adjtime = ice_ptp_adjtime;
#ifdef HAVE_PTP_CLOCK_INFO_ADJFINE
	info->adjfine = ice_ptp_adjfine;
#else
	info->adjfreq = ice_ptp_adjfreq;
#endif
#if defined(HAVE_PTP_CLOCK_INFO_GETTIMEX64)
	info->gettimex64 = ice_ptp_gettimex64;
#elif defined(HAVE_PTP_CLOCK_INFO_GETTIME64)
	info->gettime64 = ice_ptp_gettime64;
#else
	info->gettime = ice_ptp_gettime32;
#endif
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
	info->settime64 = ice_ptp_settime64;
#else
	info->settime = ice_ptp_settime32;
#endif /* HAVE_PTP_CLOCK_INFO_GETTIME64 */

	if (ice_is_e810(&pf->hw))
		ice_ptp_set_funcs_e810(pf, info);
	else
		ice_ptp_set_funcs_e82x(pf, info);
}

/**
 * ice_ptp_create_clock - Create PTP clock device for userspace
 * @pf: Board private structure
 *
 * This function creates a new PTP clock device. It only creates one if we
 * don't already have one. Will return error if it can't create one, but success
 * if we already have a device. Should be used by ice_ptp_init to create clock
 * initially, and prevent global resets from creating new clock devices.
 */
static long ice_ptp_create_clock(struct ice_pf *pf)
{
	struct ptp_clock_info *info;
	struct device *dev;

	if (!ice_is_primary(pf)) {
		dev_err(ice_pf_to_dev(pf),
			"PTP clock is supported only on primary devices\n");
		return -ENODEV;
	}

	/* No need to create a clock device if we already have one */
	if (pf->ptp.clock)
		return 0;

	ice_ptp_set_caps(pf);

	info = &pf->ptp.info;
	dev = ice_pf_to_dev(pf);

	/* Attempt to register the clock before enabling the hardware. */
	pf->ptp.clock = ptp_clock_register(info, dev);
	if (IS_ERR(pf->ptp.clock)) {
		ice_dev_err_errno(dev, PTR_ERR(pf->ptp.clock),
				  "Failed to register PTP clock device");
		return PTR_ERR(pf->ptp.clock);
	}

	return 0;
}

/**
 * ice_ptp_request_ts - Request an available Tx timestamp index
 * @tx: the PTP Tx timestamp tracker to request from
 * @skb: the SKB to associate with this timestamp request
 */
s8 ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb)
{
	u8 idx;

	spin_lock(&tx->lock);

	/* Check that this tracker is accepting new timestamp requests */
	if (!ice_ptp_is_tx_tracker_up(tx)) {
		spin_unlock(&tx->lock);
		return -1;
	}

	/* Find and set the first available index */
	idx = find_next_zero_bit(tx->in_use, tx->len,
				 tx->last_ll_ts_idx_read + 1);
	if (idx == tx->len)
		idx = find_first_zero_bit(tx->in_use, tx->len);
	if (idx < tx->len) {
		/* We got a valid index that no other thread could have set.
		 * Store a reference to the skb and the start time to allow
		 * discarding old requests.
		 */
		set_bit(idx, tx->in_use);
		clear_bit(idx, tx->stale);
		tx->tstamps[idx].start = jiffies;
		tx->tstamps[idx].skb = skb_get(skb);
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		ice_trace(tx_tstamp_request, skb, idx);
	}

	spin_unlock(&tx->lock);

	/* return the appropriate PHY timestamp register index, -1 if no
	 * indexes were available.
	 */
	if (idx >= tx->len)
		return -1;
	else
		return idx + tx->offset;
}

/**
 * ice_ptp_process_ts - Process TX timestamps
 * @pf: Board private structure
 *
 * Returns: ICE_TX_TSTAMP_WORK_PENDING if there are any outstanding Tx
 * timestamps that need processing, and ICE_TX_TSTAMP_WORK_DONE otherwise.
 */
enum ice_tx_tstamp_work ice_ptp_process_ts(struct ice_pf *pf)
{
	switch (pf->ptp.tx_interrupt_mode) {
	case ICE_PTP_TX_INTERRUPT_NONE:
		/* This device has the clock owner handle timestamps for it */
		return ICE_TX_TSTAMP_WORK_DONE;
	case ICE_PTP_TX_INTERRUPT_SELF:
		/* This device handles its own timestamps */
		return ice_ptp_tx_tstamp(&pf->ptp.port.tx);
	case ICE_PTP_TX_INTERRUPT_ALL:
		/* This device handles timestamps for all ports */
		return ice_ptp_tx_tstamp_owner(pf);
	}

	WARN_ONCE(1, "Unexpected Tx timestamp interrupt mode %u\n",
		  pf->ptp.tx_interrupt_mode);
	return ICE_TX_TSTAMP_WORK_DONE;
}

/**
 * ice_dpll_pin_idx_to_name - Return pin name for a corresponding pin
 *
 * @pf: pointer to the PF instance
 * @pin: pin number to get name for
 * @pin_name: pointer to pin name buffer
 *
 * A wrapper for device-specific pin index to name converters that take care
 * of mapping pin indices returned by a netlist to real pin names
 */
void ice_dpll_pin_idx_to_name(struct ice_pf *pf, u8 pin, char *pin_name)
{
	/* if we are on a custom board, print generic descriptions */
	if (!ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
		snprintf(pin_name, MAX_PIN_NAME, "Pin %i", pin);
		return;
	}
	switch (pf->hw.device_id) {
	case ICE_DEV_ID_E810C_SFP:
	/* Skip second PHY recovered clocks as they are not represented
	 * in the netlist
	 */
		if (pin >= ZL_REF2P)
			pin += 2;
		fallthrough;
	case ICE_DEV_ID_E810C_QSFP:
		snprintf(pin_name, MAX_PIN_NAME, "%s",
			 ice_zl_pin_idx_to_name_e810t(pin));
		return;
	case ICE_DEV_ID_E823L_10G_BASE_T:
	case ICE_DEV_ID_E823L_1GBE:
	case ICE_DEV_ID_E823L_BACKPLANE:
	case ICE_DEV_ID_E823L_QSFP:
	case ICE_DEV_ID_E823L_SFP:
	case ICE_DEV_ID_E823C_10G_BASE_T:
	case ICE_DEV_ID_E823C_BACKPLANE:
	case ICE_DEV_ID_E823C_QSFP:
	case ICE_DEV_ID_E823C_SFP:
	case ICE_DEV_ID_E823C_SGMII:
		snprintf(pin_name, MAX_PIN_NAME, "%s",
			 ice_pin_idx_to_name_e823(&pf->hw, pin));
		return;
	default:
		snprintf(pin_name, MAX_PIN_NAME, "Pin %i", pin);
	}
}

static void ice_handle_cgu_state(struct ice_pf *pf)
{
	enum ice_cgu_state cgu_state;
	char pin_name[MAX_PIN_NAME];

	cgu_state = ice_get_cgu_state(&pf->hw, ICE_CGU_DPLL_SYNCE,
				      &pf->synce_ref_pin, NULL,
				      pf->synce_dpll_state);
	ice_dpll_pin_idx_to_name(pf, pf->synce_ref_pin, pin_name);
	if (pf->synce_dpll_state != cgu_state) {
		pf->synce_dpll_state = cgu_state;
		dev_warn(ice_pf_to_dev(pf),
			 "DPLL%i state changed to: %s, pin %s",
			 ICE_CGU_DPLL_SYNCE,
			 ice_cgu_state_to_name(pf->synce_dpll_state), pin_name);
	}

	cgu_state = ice_get_cgu_state(&pf->hw, ICE_CGU_DPLL_PTP,
				      &pf->ptp_ref_pin,
				      &pf->ptp_dpll_phase_offset,
				      pf->ptp_dpll_state);
	ice_dpll_pin_idx_to_name(pf, pf->ptp_ref_pin, pin_name);
	if (pf->ptp_dpll_state != cgu_state) {
		pf->ptp_dpll_state = cgu_state;
		dev_warn(ice_pf_to_dev(pf),
			 "DPLL%i state changed to: %s, pin %s",
			 ICE_CGU_DPLL_PTP,
			 ice_cgu_state_to_name(pf->ptp_dpll_state), pin_name);
	}
}

#define TS_PLL_LOS_LOG_CAD 120	/* log every two minutes */
static void ice_ptp_periodic_work(struct kthread_work *work)
{
	struct ice_ptp *ptp = container_of(work, struct ice_ptp, work.work);
	struct ice_pf *pf = container_of(ptp, struct ice_pf, ptp);
	struct ice_hw *hw = &pf->hw;
	bool lock_lost;

	int err;

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		if (test_bit(ICE_FLAG_DPLL_MONITOR, pf->flags) &&
		    pf->hw.func_caps.ts_func_info.src_tmr_owned) {
			ice_handle_cgu_state(pf);
		}
	}

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	err = ice_ptp_update_cached_phctime(pf);

	/* only E825C and only clock owner should monitor the TS PLL */
	if (ice_is_e825c(hw) && ice_pf_src_tmr_owned(pf)) {
		err = ice_cgu_ts_pll_lost_lock_e825c(hw, &lock_lost);
		if (err) {
			dev_err(ice_pf_to_dev(pf),
				"Failed reading TimeSync PLL lock status. Retrying.\n");
		} else if (lock_lost) {
			if (pf->ptp.ts_pll_lock_retries % TS_PLL_LOS_LOG_CAD)
				dev_err(ice_pf_to_dev(pf),
					"TimeSync PLL lock lost. Retrying to acquire lock with current PLL configuration\n");

			err = ice_cgu_ts_pll_restart_e825c(hw);
			if (err) {
				dev_err(ice_pf_to_dev(pf),
					"Failed reading TimeSync PLL lock status. Retrying.\n");
			}

			pf->ptp.ts_pll_lock_retries++;
		} else {
			if (pf->ptp.ts_pll_lock_retries)
				dev_err(ice_pf_to_dev(pf),
					"TimeSync PLL lock is acquired with %s clock source.\n",
					ice_clk_src_str(pf->ptp.clk_src));

			pf->ptp.ts_pll_lock_retries = 0;
		}
	}

	/* Run twice a second or reschedule if PHC update failed */
	if (!test_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags)) {
		kthread_queue_delayed_work(ptp->kworker, &ptp->work,
					   msecs_to_jiffies(err ? 10 : 500));
	}
}

/**
 * ice_ptp_prepare_for_reset - Prepare PTP for reset
 * @pf: Board private structure
 */
void ice_ptp_prepare_for_reset(struct ice_pf *pf)
{
	struct ice_pf *peer_pf = ice_is_primary(pf) ?
				 NULL : ice_get_peer_pf(pf);
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	u8 src_tmr;

	if (!test_and_clear_bit(ICE_FLAG_PTP, pf->flags))
		return;

	if (ptp->state == ICE_PTP_RESETTING)
		return;

	if (peer_pf)
		ice_ptp_prepare_for_reset(peer_pf);

	ptp->state = ICE_PTP_RESETTING;

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);

	kthread_cancel_delayed_work_sync(&ptp->work);

	if (test_bit(ICE_PFR_REQ, pf->state))
		return;

	kthread_cancel_delayed_work_sync(&pf->ptp.port.ov_work);
	ice_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);

	src_tmr = ice_get_ptp_src_clock_index(hw);

	/* Disable source clock */
	wr32(hw, GLTSYN_ENA(src_tmr), (u32)~GLTSYN_ENA_TSYN_ENA_M);

	/* Acquire PHC and system timer to restore after reset */
	ptp->reset_time = ktime_get_real_ns();
}

/**
 * ice_block_ptp_workthreads
 * @pf: driver's pf structure
 * @block_enable: enable / disable WT block
 *
 * Enable or disable ICE_FLAG_PTP_WT_BLOCKED flag for this pf.
 * Additionally, since Rx/Tx timestamps depend on cached PHC value
 * which will be out of date when we block workthreads, stop timestamping
 */
static void ice_block_ptp_workthreads(struct ice_pf *pf, bool block_enable)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (block_enable && !test_and_set_bit(ICE_FLAG_PTP_WT_BLOCKED,
					      pf->flags)) {
		dev_dbg(dev, "PTP workthreads blocked");
		ice_ptp_cfg_timestamp(pf, false);
	} else if (!block_enable) {
		clear_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags);
		dev_dbg(dev, "PTP workthreads unblocked");
	}
}

/**
 * ice_block_ptp_workthreads_global
 * @pf: driver's pf structure
 * @block_enable: enable / disable global WT block
 *
 * Enable or disable ICE_FLAG_PTP_WT_BLOCKED flag across all PFs.
 * Operation requires PTP Auxbus.
 */
void ice_block_ptp_workthreads_global(struct ice_pf *pf, bool block_enable)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_ptp_port *port;

	if (!test_bit(ICE_FLAG_PTP, pf->flags)) {
		dev_dbg(dev, "PTP not active, skipping unnecessary workthread block");
		return;
	}

	list_for_each_entry(port, &pf->ptp.ports_owner.ports, list_member) {
		ice_block_ptp_workthreads(ptp_port_to_pf(port), block_enable);
	}
}

/**
 * ice_ptp_reset - Initialize PTP hardware clock support after reset
 * @pf: Board private structure
 */
void ice_ptp_reset(struct ice_pf *pf)
{
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	struct timespec64 ts;
	int err, itr = 1;
	unsigned int i;
	u64 time_diff;

	if (ptp->state != ICE_PTP_RESETTING) {
		if (ptp->state == ICE_PTP_READY) {
			ice_ptp_prepare_for_reset(pf);
		} else {
			err = -EINVAL;
			dev_err(ice_pf_to_dev(pf), "PTP was not initialized\n");
			goto err;
		}
	}

	if (test_bit(ICE_PFR_REQ, pf->state) ||
	    !hw->func_caps.ts_func_info.src_tmr_owned)
		goto pfr;

	/* Periodic outputs will have been disabled by device reset */
	for (i = 0; i < GLTSYN_TGT_H_IDX_MAX; i++)
		if (pf->ptp.perout_channels[i].present)
			pf->ptp.perout_channels[i].ena = false;

	err = ice_ptp_init_phc(hw);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "Failed to initialize PHC, status %d\n",
			err);
		goto err;
	}

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(ice_pf_to_dev(pf), "Failed to acquire PTP hardware semaphore\n");
		goto err;
	}

	/* Write the increment time value to PHY and LAN */
	err = ice_ptp_write_incval(hw, ice_base_incval(pf),
				   ice_is_primary(pf));
	if (err) {
		dev_err(ice_pf_to_dev(pf), "Failed to write PHC increment value, status %d\n",
			err);
		ice_ptp_unlock(hw);
		goto err;
	}

	/* Write the initial Time value to PHY and LAN using the cached PHC
	 * time before the reset and time difference between stopping and
	 * starting the clock.
	 */
	if (ptp->cached_phc_time) {
		time_diff = ktime_get_real_ns() - ptp->reset_time;
		ts = ns_to_timespec64(ptp->cached_phc_time + time_diff);
	} else {
		ts = ktime_to_timespec64(ktime_get_real());
	}

	err = ice_ptp_write_init(pf, &ts, ice_is_primary(pf));
	if (err) {
		ice_dev_err_errno(ice_pf_to_dev(pf), err,
				  "Failed to write PHC initial time");
		ice_ptp_unlock(hw);
		goto err;
	}

	/* Release the global hardware lock */
	ice_ptp_unlock(hw);
	ice_block_ptp_workthreads_global(pf, false);

	switch (hw->phy_model) {
	case ICE_PHY_ETH56G:
	case ICE_PHY_E822:
		/* Enable quad interrupts */
		err = ice_ptp_tx_cfg_intr(pf, true, itr);
		if (err) {
			ice_dev_err_errno(ice_pf_to_dev(pf), err,
					  "Failed to enable Tx interrupt");
			goto err;
		}

		break;
	case ICE_PHY_E810:
	default:
		break;
	}
pfr:
	/* Init Tx structures */
	switch (hw->phy_model) {
	case ICE_PHY_E810:
		err = ice_ptp_init_tx_e810(pf, &ptp->port.tx);
		break;
	case ICE_PHY_ETH56G:
		err = ice_ptp_init_tx_eth56g(pf, &ptp->port.tx,
					     ptp->port.port_num);
		break;
	case ICE_PHY_E822:
		kthread_init_delayed_work(&ptp->port.ov_work,
					  ice_ptp_wait_for_offsets);
		err = ice_ptp_init_tx_e822(pf, &ptp->port.tx,
					   ptp->port.port_num);
		break;
	default:
		err = -ENODEV;
	}

	if (err)
		goto err;

	ptp->state = ice_is_primary(pf) ?
		     ICE_PTP_PRI_READY : ICE_PTP_SEC_READY;
	set_bit(ICE_FLAG_PTP, pf->flags);

	/* Restart the PHY timestamping block */
	if (!test_bit(ICE_PFR_REQ, pf->state) &&
	    ice_pf_src_tmr_owned(pf))
		ice_ptp_restart_all_phy(pf);

	if (ptp->tx_interrupt_mode)
		ice_ptp_configure_tx_tstamp(pf, true);

	/* Start periodic work going */
	if (!test_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags))
		kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	dev_info(ice_pf_to_dev(pf), "PTP reset successful\n");
	return;
err:
	ptp->state = ICE_PTP_ERROR;
	ice_dev_err_errno(ice_pf_to_dev(pf), err, "PTP reset failed");
}

#ifndef HAVE_PF_RING_NO_AUX
/**
 * ice_ptp_aux_dev_to_aux_pf - Get auxiliary PF handle for the auxiliary device
 * @aux_dev: auxiliary device to get the auxiliary PF for
 */
static struct ice_pf *
ice_ptp_aux_dev_to_aux_pf(struct auxiliary_device *aux_dev)
{
	struct ice_ptp_port *aux_port;
	struct ice_ptp *aux_ptp;

	aux_port = container_of(aux_dev, struct ice_ptp_port, aux_dev);
	aux_ptp = container_of(aux_port, struct ice_ptp, port);
	return container_of(aux_ptp, struct ice_pf, ptp);
}

/**
 * ice_ptp_aux_dev_to_owner_pf - Get owner PF handle for the auxiliary device
 * @aux_dev: auxiliary device to get the owner PF for
 */
static struct ice_pf *
ice_ptp_aux_dev_to_owner_pf(struct auxiliary_device *aux_dev)
{
	struct ice_ptp_port_owner *ports_owner;
	struct auxiliary_driver *aux_drv;
	struct ice_ptp *owner_ptp;

	if (!aux_dev->dev.driver)
		return NULL;

	aux_drv = to_auxiliary_drv(aux_dev->dev.driver);
	ports_owner = container_of(aux_drv, struct ice_ptp_port_owner,
				   aux_driver);
	owner_ptp = container_of(ports_owner, struct ice_ptp, ports_owner);
	return container_of(owner_ptp, struct ice_pf, ptp);
}

/**
 * ice_ptp_auxbus_probe - Probe auxiliary devices
 * @aux_dev: PF's auxiliary device
 * @id: Auxiliary device ID
 */
static int ice_ptp_auxbus_probe(struct auxiliary_device *aux_dev,
				const struct auxiliary_device_id *id)
{
	struct ice_pf *aux_pf, *owner_pf;

	aux_pf = ice_ptp_aux_dev_to_aux_pf(aux_dev);
	owner_pf = ice_ptp_aux_dev_to_owner_pf(aux_dev);
	if (WARN_ON(!owner_pf))
		return -ENODEV;

	INIT_LIST_HEAD(&aux_pf->ptp.port.list_member);
	list_add(&aux_pf->ptp.port.list_member,
		 &owner_pf->ptp.ports_owner.ports);

	return 0;
}

/**
 * ice_ptp_auxbus_remove - Remove auxiliary devices from the bus
 * @aux_dev: PF's auxiliary device
 */
static void ice_ptp_auxbus_remove(struct auxiliary_device *aux_dev)
{
	struct ice_pf *pf = ice_ptp_aux_dev_to_aux_pf(aux_dev);

	list_del(&pf->ptp.port.list_member);
}

/**
 * ice_ptp_auxbus_shutdown
 * @aux_dev: PF's auxiliary device
 */
static void ice_ptp_auxbus_shutdown(struct auxiliary_device *aux_dev)
{
	/* Doing nothing here, but handle to auxbus driver must be satisfied*/
}

/**
 * ice_ptp_auxbus_suspend
 * @aux_dev: PF's auxiliary device
 * @state: power management state indicator
 */
static int
ice_ptp_auxbus_suspend(struct auxiliary_device *aux_dev, pm_message_t state)
{
	/* Doing nothing here, but handle to auxbus driver must be satisfied*/
	return 0;
}

/**
 * ice_ptp_auxbus_resume
 * @aux_dev: PF's auxiliary device
 */
static int ice_ptp_auxbus_resume(struct auxiliary_device *aux_dev)
{
	/* Doing nothing here, but handle to auxbus driver must be satisfied*/
	return 0;
}

/**
 * ice_ptp_auxbus_create_id_table - Create auxiliary device ID table
 * @pf: Board private structure
 * @name: auxiliary bus driver name
 */
static struct auxiliary_device_id *
ice_ptp_auxbus_create_id_table(struct ice_pf *pf, const char *name)
{
	struct auxiliary_device_id *ids;

	/* Second id left empty to terminate the array */
	ids = devm_kcalloc(ice_pf_to_dev(pf), 2,
			   sizeof(struct auxiliary_device_id), GFP_KERNEL);
	if (!ids)
		return NULL;

	snprintf(ids[0].name, sizeof(ids[0].name), "ice.%s", name);

	return ids;
}
#endif

/**
 * ice_ptp_register_auxbus_driver - Register PTP auxiliary bus driver
 * @pf: Board private structure
 */
static int ice_ptp_register_auxbus_driver(struct ice_pf *pf)
{
#ifndef HAVE_PF_RING_NO_AUX
	struct auxiliary_driver *aux_driver;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	int err;

	ptp = &pf->ptp;
	dev = ice_pf_to_dev(pf);
	aux_driver = &ptp->ports_owner.aux_driver;
	INIT_LIST_HEAD(&ptp->ports_owner.ports);

	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_driver->name = name;
	aux_driver->shutdown = ice_ptp_auxbus_shutdown;
	aux_driver->suspend = ice_ptp_auxbus_suspend;
	aux_driver->remove = ice_ptp_auxbus_remove;
	aux_driver->resume = ice_ptp_auxbus_resume;
	aux_driver->probe = ice_ptp_auxbus_probe;
	aux_driver->id_table = ice_ptp_auxbus_create_id_table(pf, name);
	if (!aux_driver->id_table)
		return -ENOMEM;

	err = auxiliary_driver_register(aux_driver);
	if (err) {
		devm_kfree(dev, (void *)aux_driver->id_table);
		dev_err(dev, "Failed registering aux_driver, name <%s>\n",
			name);
	}

	return err;
#else
	return 0;
#endif
}

/**
 * ice_ptp_unregister_auxbus_driver - Unregister PTP auxiliary bus driver
 * @pf: Board private structure
 */
static void ice_ptp_unregister_auxbus_driver(struct ice_pf *pf)
{
#ifndef HAVE_PF_RING_NO_AUX
	struct auxiliary_driver *aux_driver = &pf->ptp.ports_owner.aux_driver;

	auxiliary_driver_unregister(aux_driver);
	devm_kfree(ice_pf_to_dev(pf), (void *)aux_driver->id_table);
#endif
}

/**
 * ice_ptp_clock_index - Get the PTP clock index for this device
 * @pf: Board private structure
 *
 * Returns: the PTP clock index associated with this PF, or -1 if no PTP clock
 * is associated.
 */
int ice_ptp_clock_index(struct ice_pf *pf)
{
#ifndef HAVE_PF_RING_NO_AUX
	struct auxiliary_device *aux_dev;
#endif
	struct ice_pf *owner_pf;
	struct ptp_clock *clock;

#ifndef HAVE_PF_RING_NO_AUX
	aux_dev = &pf->ptp.port.aux_dev;
	owner_pf = ice_ptp_aux_dev_to_owner_pf(aux_dev);
#else
	owner_pf = pf;
#endif
	if (!owner_pf)
		return -1;
	clock = owner_pf->ptp.clock;

	return clock ? ptp_clock_index(clock) : -1;
}

/**
 * ice_ptp_init_owner - Initialize PTP_1588_CLOCK device
 * @pf: Board private structure
 *
 * Setup and initialize a PTP clock device that represents the device hardware
 * clock. Save the clock index for other functions connected to the same
 * hardware resource.
 */
static int ice_ptp_init_owner(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	struct timespec64 ts;
	int err, itr = 1;
	unsigned int i;

	/* Periodic outputs will have been disabled by device reset */
	for (i = 0; i < GLTSYN_TGT_H_IDX_MAX; i++)
		if (pf->ptp.perout_channels[i].present)
			pf->ptp.perout_channels[i].ena = false;

	err = ice_ptp_init_phc(hw);
	if (err) {
		dev_err(dev, "Failed to initialize PHC, status %d\n", err);
		goto err_exit;
	}

	ptp->src_tmr_mode = ICE_SRC_TMR_MODE_NANOSECONDS;
	pf->ptp.clk_src = (enum ice_clk_src)hw->func_caps.ts_func_info.clk_src;
	pf->ptp.ts_pll_lock_retries = 0;

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(dev, "Failed to acquire PTP hardware semaphore\n");
		goto err_exit;
	}

	/* Write the increment time value to PHY and LAN */
	err = ice_ptp_write_incval(hw, ice_base_incval(pf), ice_is_primary(pf));
	if (err) {
		dev_err(dev, "Failed to write PHC increment value, status %d\n",
			err);
		ice_ptp_unlock(hw);
		goto err_exit;
	}

	ts = ktime_to_timespec64(ktime_get_real());
	/* Write the initial Time value to PHY and LAN */
	err = ice_ptp_write_init(pf, &ts, ice_is_primary(pf));
	if (err) {
		ice_dev_err_errno(dev, err, "Failed to write PHC initial time");
		ice_ptp_unlock(hw);
		goto err_exit;
	}

	/* Release the global hardware lock */
	ice_ptp_unlock(hw);

	if (pf->ptp.tx_interrupt_mode == ICE_PTP_TX_INTERRUPT_ALL) {
		/* The clock owner for this device type handles the timestamp
		 * interrupt for all ports.
		 */
		ice_ptp_configure_tx_tstamp(pf, true);

		/* React on all quads interrupts for E82x */
		wr32(hw, PFINT_TSYN_MSK + (0x4 * hw->pf_id), (u32)0x1f);

		/* Enable quad interrupts */
		err = ice_ptp_tx_cfg_intr(pf, true, itr);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "Failed to enable Tx interrupt");
			goto err_exit;
		}
	}

	if (ice_is_primary(pf)) {
		err = ice_ptp_create_clock(pf);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "Failed to register PTP clock device");
			goto err_clk;
		}
		if (ice_is_e825c(hw)) {
			err = ice_enable_all_clk_refs(hw);
			if (err) {
				ice_dev_err_errno(dev, err,
						  "Failed to enable all CLK REFs");
				goto err_clk;
			}
		}
	}

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		set_bit(ICE_FLAG_DPLL_MONITOR, pf->flags);
		pf->synce_dpll_state = ICE_CGU_STATE_UNKNOWN;
		pf->ptp_dpll_state = ICE_CGU_STATE_UNKNOWN;
	}
	clear_bit(ICE_FLAG_ITU_G8262_FILTER_USED, pf->flags);

	err = ice_ptp_register_auxbus_driver(pf);
	if (err) {
		ice_dev_err_errno(dev, err, "Failed to register PTP auxbus driver");
		goto err_clk;
	}

	return 0;

err_clk:
	ptp->clock = NULL;
err_exit:
	return err;
}

/**
 * ice_ptp_init_work - Initialize PTP work threads
 * @pf: Board private structure
 * @ptp: PF PTP structure
 */
static int ice_ptp_init_work(struct ice_pf *pf, struct ice_ptp *ptp)
{
	struct kthread_worker *kworker;

	/* Initialize work functions */
	kthread_init_delayed_work(&ptp->work, ice_ptp_periodic_work);

	/* Allocate a kworker for handling work required for the ports
	 * connected to the PTP hardware clock.
	 */
	kworker = kthread_create_worker(0, "ice-ptp-%s",
					dev_name(ice_pf_to_dev(pf)));
	if (IS_ERR(kworker))
		return PTR_ERR(kworker);

	ptp->kworker = kworker;

	/* Start periodic work going */
	if (!test_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags))
		kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	return 0;
}

/**
 * ice_ptp_init_port - Initialize PTP port structure
 * @pf: Board private structure
 * @ptp_port: PTP port structure
 */
static int ice_ptp_init_port(struct ice_pf *pf, struct ice_ptp_port *ptp_port)
{
	struct ice_hw *hw = &pf->hw;
	int err;

	mutex_init(&ptp_port->ps_lock);

	switch (hw->phy_model) {
	case ICE_PHY_ETH56G:
		err = ice_ptp_init_tx_eth56g(pf, &ptp_port->tx,
					     ptp_port->port_num);
		break;
	case ICE_PHY_E810:
		return ice_ptp_init_tx_e810(pf, &ptp_port->tx);
		break;
	case ICE_PHY_E822:
		/* Non-owner PFs don't react to any interrupts on E82x,
		 * neither on own quad nor on others
		 */
		if (!ice_ptp_pf_handles_tx_interrupt(pf)) {
			ice_ptp_configure_tx_tstamp(pf, false);
			wr32(hw, PFINT_TSYN_MSK + (0x4 * hw->pf_id), (u32)0x0);
		}
		kthread_init_delayed_work(&ptp_port->ov_work,
					  ice_ptp_wait_for_offsets);
		err = ice_ptp_init_tx_e822(pf, &ptp_port->tx,
					   ptp_port->port_num);
		break;

	default:
		err = -ENODEV;
	}

	return err;
}

#ifndef HAVE_PF_RING_NO_AUX
/**
 * ice_ptp_release_auxbus_device
 * @dev: device that utilizes the auxbus
 */
static void ice_ptp_release_auxbus_device(struct device *dev)
{
	/* Doing nothing here, but handle to auxbux device must be satisfied */
}

/**
 * ice_ptp_create_auxbus_device - Create PTP auxiliary bus device
 * @pf: Board private structure
 */
static int ice_ptp_create_auxbus_device(struct ice_pf *pf)
{
	struct auxiliary_device *aux_dev;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	u32 id;

	ptp = &pf->ptp;
	id = ptp->port.port_num;
	dev = ice_pf_to_dev(pf);

	aux_dev = &ptp->port.aux_dev;

	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_dev->name = name;
	aux_dev->id = id;
	aux_dev->dev.release = ice_ptp_release_auxbus_device;
	aux_dev->dev.parent = ice_pf_to_dev(pf);

	if (auxiliary_device_init(aux_dev))
		goto err;

	if (auxiliary_device_add(aux_dev)) {
		auxiliary_device_uninit(aux_dev);
		goto err;
	}

	return 0;
err:
	dev_err(ice_pf_to_dev(pf), "Failed to create PTP auxiliary bus device <%s>\n",
		name);
	devm_kfree(dev, name);
	return -1;
}

/**
 * ice_ptp_remove_auxbus_device - Remove PTP auxiliary bus device
 * @pf: Board private structure
 */
static void ice_ptp_remove_auxbus_device(struct ice_pf *pf)
{
	struct auxiliary_device *aux_dev;

	aux_dev = &pf->ptp.port.aux_dev;

	auxiliary_device_delete(aux_dev);
	auxiliary_device_uninit(aux_dev);

	memset(aux_dev, 0, sizeof(*aux_dev));
}
#endif

/**
 * ice_ptp_init_tx_interrupt_mode - Initialize device Tx interrupt mode
 * @pf: Board private structure
 *
 * Initialize the Tx timestamp interrupt mode for this device. For most device
 * types, each PF processes the interrupt and manages its own timestamps. For
 * E822-based devices, only the clock owner processes the timestamps. Other
 * PFs disable the interrupt and do not process their own timestamps.
 */
static void ice_ptp_init_tx_interrupt_mode(struct ice_pf *pf)
{
	switch (pf->hw.phy_model) {
	case ICE_PHY_E822:
		/* E822 based PHY has the clock owner process the interrupt
		 * for all ports.
		 */
		if (ice_pf_src_tmr_owned(pf))
			pf->ptp.tx_interrupt_mode = ICE_PTP_TX_INTERRUPT_ALL;
		else
			pf->ptp.tx_interrupt_mode = ICE_PTP_TX_INTERRUPT_NONE;
		break;
	default:
		/* other PHY types handle their own Tx interrupt */
		pf->ptp.tx_interrupt_mode = ICE_PTP_TX_INTERRUPT_SELF;
	}
}

/**
 * ice_ptp_init - Initialize PTP hardware clock support
 * @pf: Board private structure
 *
 * Set up the device for interacting with the PTP hardware clock for all
 * functions, both the function that owns the clock hardware, and the
 * functions connected to the clock hardware.
 *
 * The clock owner will allocate and register a ptp_clock with the
 * PTP_1588_CLOCK infrastructure. All functions allocate a kthread and work
 * items used for asynchronous work such as Tx timestamps and periodic work.
 */
void ice_ptp_init(struct ice_pf *pf)
{
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	int err;

	ptp->state = ICE_PTP_INITIALIZING;
	if (pf->peer_pdev)
		dev_info(ice_pf_to_dev(pf), "%s PTP device\n",
			 ice_is_primary(pf) ? "Primary" : "Secondary");

	ice_ptp_init_phy_model(hw);

	ice_ptp_init_tx_interrupt_mode(pf);

	/* If this function owns the clock hardware, it must allocate and
	 * configure the PTP clock device to represent it.
	 */
	if (ice_pf_src_tmr_owned(pf)) {
		err = ice_ptp_init_owner(pf);
		if (err)
			goto err;
	}

	ptp->port.port_num = hw->pf_id;
#ifndef HAVE_PF_RING_NO_AUX
	err = ice_ptp_create_auxbus_device(pf);
	if (err)
		goto err_auxdrv;
#endif

	err = ice_ptp_init_port(pf, &ptp->port);
	if (err)
		goto err_auxdev;

	ptp->managed_phy = ice_ptp_is_managed_phy(hw->phy_model);

	/* Start the PHY timestamping block */
	ice_ptp_reset_phy_timestamping(pf);

	set_bit(ICE_FLAG_PTP, pf->flags);
	err = ice_ptp_init_work(pf, ptp);
	if (err)
		goto err_auxdev;

	ice_ptp_sysfs_init(pf);

	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825)
		ptp->state = ice_is_primary(pf) ?
			ICE_PTP_PRI_READY : ICE_PTP_SEC_READY;
	else
		ptp->state = ICE_PTP_READY;

	dev_info(ice_pf_to_dev(pf), "PTP init successful\n");
	return;

err_auxdev:
#ifndef HAVE_PF_RING_NO_AUX
	ice_ptp_remove_auxbus_device(pf);
err_auxdrv:
#endif
	if (ice_pf_src_tmr_owned(pf))
		ice_ptp_unregister_auxbus_driver(pf);
err:
	ptp->state = ICE_PTP_ERROR;
	/* If we registered a PTP clock, release it */
	if (pf->ptp.clock) {
		ptp_clock_unregister(ptp->clock);
		pf->ptp.clock = NULL;
	}
	clear_bit(ICE_FLAG_PTP, pf->flags);
	ice_dev_err_errno(ice_pf_to_dev(pf), err, "PTP init failed");
}

/**
 * ice_ptp_release - Disable the driver/HW support and unregister the clock
 * @pf: Board private structure
 *
 * This function handles the cleanup work required from the initialization by
 * clearing out the important information and unregistering the clock
 */
void ice_ptp_release(struct ice_pf *pf)
{

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);

#ifndef HAVE_PF_RING_NO_AUX
	ice_ptp_remove_auxbus_device(pf);
#endif
	ice_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	clear_bit(ICE_FLAG_PTP, pf->flags);

	if (!test_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags))
		kthread_cancel_delayed_work_sync(&pf->ptp.work);

	ice_ptp_port_phy_stop(&pf->ptp.port);
	mutex_destroy(&pf->ptp.port.ps_lock);

	if (pf->ptp.kworker) {
		kthread_destroy_worker(pf->ptp.kworker);
		pf->ptp.kworker = NULL;
	}

	ice_ptp_sysfs_release(pf);

	if (!pf->ptp.clock)
		return;

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);
	ptp_clock_unregister(pf->ptp.clock);
	pf->ptp.clock = NULL;

	/* Free pin config */
	if (pf->ptp.info.pin_config) {
		devm_kfree(ice_pf_to_dev(pf), pf->ptp.info.pin_config);
		pf->ptp.info.pin_config = NULL;
	}

	ice_ptp_unregister_auxbus_driver(pf);

	dev_info(ice_pf_to_dev(pf), "Removed PTP clock\n");
}
