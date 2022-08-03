// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"

#define E810_OUT_PROP_DELAY_NS 1

#define LOCKED_INCVAL_E822 0x100000000ULL

static const struct ptp_pin_desc ice_pin_desc_e810t[] = {
	/* name     idx   func         chan */
	 { "GNSS",  GNSS, PTP_PF_EXTTS, 0, { 0, } },
	 { "SMA1",  SMA1, PTP_PF_NONE, 1, { 0, } },
	 { "U.FL1", UFL1, PTP_PF_NONE, 1, { 0, } },
	 { "SMA2",  SMA2, PTP_PF_NONE, 2, { 0, } },
	 { "U.FL2", UFL2, PTP_PF_NONE, 2, { 0, } },
};

static ssize_t synce_store(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t count);

static ssize_t pin_cfg_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t len);

static ssize_t pin_cfg_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf);

static ssize_t cgu_state_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf);

static ssize_t cgu_ref_pin_show(struct device *dev,
				struct device_attribute *attr,
				char *buf);

static struct kobj_attribute synce_attribute = __ATTR_WO(synce);
static DEVICE_ATTR_RW(pin_cfg);
static DEVICE_ATTR_RO(cgu_state);
static DEVICE_ATTR_RO(cgu_ref_pin);

/**
 * __get_pf_pdev - helper function to get the pdev
 * @kobj:       kobject passed
 * @pdev:       PCI device information struct
 */
static int __get_pf_pdev(struct kobject *kobj, struct pci_dev **pdev)
{
	struct device *dev;

	if (!kobj->parent)
		return -EINVAL;

	/* get pdev */
	dev = kobj_to_dev(kobj->parent);
	*pdev = to_pci_dev(dev);

	return 0;
}

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

	if (!esync_en_valid)
		if (old_cfg.flags2 & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)
			flags2 |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		else
			flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
	else
		if (esync_en)
			flags2 |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		else
			flags2 &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;

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
		 "input pin:%u, enable: %u, freq:%u, phase_delay:%u, esync:%u, flags1:%u, flags2:%u\n",
		 input_idx, pin_en, freq, phase_delay, esync_en,
		 flags1, flags2);
	return ice_aq_set_input_pin_cfg(&pf->hw, input_idx, flags1, flags2,
					freq, phase_delay);
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
	enum ice_status status;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	u32 freq = 0;
	u8 pin, phy;
	int cnt;

	if (__get_pf_pdev(kobj, &pdev))
		return -EPERM;

	pf = pci_get_drvdata(pdev);

	cnt = sscanf(buf, "%u %u", &ena, &phy_pin);
	if (cnt != 2 || phy_pin >= ICE_C827_RCLK_PINS_NUM)
		return -EINVAL;

	status = ice_aq_set_phy_rec_clk_out(&pf->hw, phy_pin, !!ena, &freq);
	if (status)
		return -EIO;

	status = ice_get_pf_c827_idx(&pf->hw, &phy);
	if (status)
		return -EIO;

	pin = E810T_CGU_INPUT_C827(phy, phy_pin);
	dev_info(ice_hw_to_dev(&pf->hw), "%s recovered clock: pin %s\n",
		 !!ena ? "Enabled" : "Disabled",
		 ice_zl_pin_idx_to_name_e810t(pin));

	return count;
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
	u8 pin, pin_en, esync_en, dpll0_prio, dpll1_prio;
	struct ice_aqc_get_cgu_input_config in_cfg;
	struct ice_hw *hw = &pf->hw;
	int count = offset;
	s32 phase_delay;
	u32 freq;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "in");
	count += scnprintf(buf + count, PAGE_SIZE,
			  "|%4s|%8s|%11s|%12s|%6s|%11s|%11s|\n",
			   "pin", "enabled", "freq", "phase_delay", "esync",
			   "DPLL0 prio", "DPLL1 prio");
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
		esync_en = !!(in_cfg.flags2 &
			      ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN);
		pin_en = !!(in_cfg.flags2 &
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN);
		phase_delay = le32_to_cpu(in_cfg.phase_delay);
		freq = le32_to_cpu(in_cfg.freq);
		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%11u|%12d|%6u|%11u|%11u|\n",
				   in_cfg.input_idx, pin_en, freq, phase_delay,
				   esync_en, dpll0_prio, dpll1_prio);
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

#define CGU_STATE_BUFF_SIZE	3
/**
 * cgu_state_show - sysfs interface callback for reading cgu_state file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t cgu_state_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	size_t cnt, buffer_size = CGU_STATE_BUFF_SIZE;
	struct pci_dev *pdev;
	struct ice_pf *pf;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	cnt = snprintf(buf, buffer_size, "%d\n", pf->synce_dpll_state);

	if (cnt >= buffer_size)
		return -1;

	return cnt;
}

#define CGU_LOCKED_BUFF_SIZE	3
/**
 * cgu_ref_pin_show - sysfs callback for reading cgu_ref_pin file
 *
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */
static ssize_t cgu_ref_pin_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct pci_dev *pdev;
	struct ice_pf *pf;
	size_t cnt;
	u8 pin;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);
	pin = pf->synce_ref_pin;

	if (pf->synce_dpll_state == ICE_CGU_STATE_LOCKED ||
	    pf->synce_dpll_state == ICE_CGU_STATE_LOCKED_HO_ACQ ||
	    pf->synce_dpll_state == ICE_CGU_STATE_HOLDOVER)
		cnt = snprintf(buf, CGU_LOCKED_BUFF_SIZE, "%d\n", pin);
	else
		return -EAGAIN;

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
		dev_info(ice_pf_to_dev(pf), "Failed to create PHY kobject\n");
		return;
	}

	if (sysfs_create_file(phy_kobj, &synce_attribute.attr)) {
		dev_info(ice_pf_to_dev(pf), "Failed to create synce kobject\n");
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
		dev_dbg(ice_pf_to_dev(pf), "Failed to create pin_cfg kobject\n");
}

/**
 * ice_cgu_state_init - initialize sysfs for cgu_state
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling cgu_state in DPLL.
 */
static void ice_cgu_state_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_cgu_state))
		dev_dbg(ice_pf_to_dev(pf),
			"Failed to create cgu_state kobject\n");
}

/**
 * ice_cgu_ref_pin_init - initialize sysfs for locked_pin
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling cgu_state in DPLL.
 */
static void ice_cgu_ref_pin_init(struct ice_pf *pf)
{
	if (device_create_file(ice_pf_to_dev(pf), &dev_attr_cgu_ref_pin))
		dev_dbg(ice_pf_to_dev(pf),
			"Failed to create cgu_ref_pin kobject\n");
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

	if (pf->hw.func_caps.ts_func_info.src_tmr_owned &&
	    ice_is_feature_supported(pf, ICE_F_CGU)) {
		ice_pin_cfg_sysfs_init(pf);
		ice_cgu_state_init(pf);
		ice_cgu_ref_pin_init(pf);
	}
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
	if (pf->ptp.phy_kobj) {
		sysfs_remove_file(pf->ptp.phy_kobj, &synce_attribute.attr);
		kobject_del(pf->ptp.phy_kobj);
		kobject_put(pf->ptp.phy_kobj);
		pf->ptp.phy_kobj = NULL;
	}

	if (pf->hw.func_caps.ts_func_info.src_tmr_owned &&
	    ice_is_feature_supported(pf, ICE_F_CGU)) {
		device_remove_file(ice_pf_to_dev(pf), &dev_attr_pin_cfg);
		device_remove_file(ice_pf_to_dev(pf), &dev_attr_cgu_state);
		device_remove_file(ice_pf_to_dev(pf), &dev_attr_cgu_ref_pin);
	}
}

/**
 * ice_get_sma_config_e810t
 * @hw: pointer to the hw struct
 * @ptp_pins: pointer to the ptp_pin_desc struture
 *
 * Read the configuration of the SMA control logic and put it into the
 * ptp_pin_desc structure
 */
static int
ice_get_sma_config_e810t(struct ice_hw *hw, struct ptp_pin_desc *ptp_pins)
{
	enum ice_status status;
	u8 data, i;

	/* Read initial pin state */
	status = ice_read_sma_ctrl_e810t(hw, &data);
	if (status)
		return ice_status_to_errno(status);

	/* initialize with defaults */
	for (i = 0; i < NUM_E810T_PTP_PINS; i++) {
		snprintf(ptp_pins[i].name, sizeof(ptp_pins[i].name),
			 "%s", ice_pin_desc_e810t[i].name);
		ptp_pins[i].index = ice_pin_desc_e810t[i].index;
		ptp_pins[i].func = ice_pin_desc_e810t[i].func;
		ptp_pins[i].chan = ice_pin_desc_e810t[i].chan;
	}

	/* Parse SMA1/UFL1 */
	switch (data & ICE_E810T_SMA1_CTRL_MASK) {
	case ICE_E810T_SMA1_CTRL_MASK:
	default:
		ptp_pins[SMA1].func = PTP_PF_NONE;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case ICE_E810T_P1_SMA1_DIR_EN:
		ptp_pins[SMA1].func = PTP_PF_PEROUT;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case ICE_E810T_P1_SMA1_TX_EN:
		ptp_pins[SMA1].func = PTP_PF_EXTTS;
		ptp_pins[UFL1].func = PTP_PF_NONE;
		break;
	case 0:
		ptp_pins[SMA1].func = PTP_PF_EXTTS;
		ptp_pins[UFL1].func = PTP_PF_PEROUT;
		break;
	}

	/* Parse SMA2/UFL2 */
	switch (data & ICE_E810T_SMA2_CTRL_MASK) {
	case ICE_E810T_SMA2_CTRL_MASK:
	default:
		ptp_pins[SMA2].func = PTP_PF_NONE;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_E810T_P1_SMA2_TX_EN | ICE_E810T_P1_SMA2_UFL2_RX_DIS):
		ptp_pins[SMA2].func = PTP_PF_EXTTS;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_E810T_P1_SMA2_DIR_EN | ICE_E810T_P1_SMA2_UFL2_RX_DIS):
		ptp_pins[SMA2].func = PTP_PF_PEROUT;
		ptp_pins[UFL2].func = PTP_PF_NONE;
		break;
	case (ICE_E810T_P1_SMA2_DIR_EN | ICE_E810T_P1_SMA2_TX_EN):
		ptp_pins[SMA2].func = PTP_PF_NONE;
		ptp_pins[UFL2].func = PTP_PF_EXTTS;
		break;
	case ICE_E810T_P1_SMA2_DIR_EN:
		ptp_pins[SMA2].func = PTP_PF_PEROUT;
		ptp_pins[UFL2].func = PTP_PF_EXTTS;
		break;
	}

	return 0;
}

/**
 * ice_ptp_set_sma_state_e810t
 * @hw: pointer to the hw struct
 * @ptp_pins: pointer to the ptp_pin_desc struture
 *
 * Set the configuration of the SMA control logic based on the configuration in
 * num_pins parameter
 */
static int
ice_ptp_set_sma_state_e810t(struct ice_hw *hw,
			    const struct ptp_pin_desc *ptp_pins)
{
	enum ice_status status;
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
		return ice_status_to_errno(status);

	/* Set the right sate based on the desired configuration */
	data &= ~ICE_E810T_SMA1_CTRL_MASK;
	if (ptp_pins[SMA1].func == PTP_PF_NONE &&
	    ptp_pins[UFL1].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA1 + U.FL1 disabled");
		data |= ICE_E810T_SMA1_CTRL_MASK;
	} else if (ptp_pins[SMA1].func == PTP_PF_EXTTS &&
		   ptp_pins[UFL1].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA1 RX");
		data |= ICE_E810T_P1_SMA1_TX_EN;
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
		data |= ICE_E810T_P1_SMA1_DIR_EN;
	}

	data &= (~ICE_E810T_SMA2_CTRL_MASK);
	if (ptp_pins[SMA2].func == PTP_PF_NONE &&
	    ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 + U.FL2 disabled");
		data |= ICE_E810T_SMA2_CTRL_MASK;
	} else if (ptp_pins[SMA2].func == PTP_PF_EXTTS &&
			ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 RX");
		data |= (ICE_E810T_P1_SMA2_TX_EN |
			 ICE_E810T_P1_SMA2_UFL2_RX_DIS);
	} else if (ptp_pins[SMA2].func == PTP_PF_NONE &&
		   ptp_pins[UFL2].func == PTP_PF_EXTTS) {
		dev_info(ice_hw_to_dev(hw), "UFL2 RX");
		data |= (ICE_E810T_P1_SMA2_DIR_EN | ICE_E810T_P1_SMA2_TX_EN);
	} else if (ptp_pins[SMA2].func == PTP_PF_PEROUT &&
		   ptp_pins[UFL2].func == PTP_PF_NONE) {
		dev_info(ice_hw_to_dev(hw), "SMA2 TX");
		data |= (ICE_E810T_P1_SMA2_DIR_EN |
			 ICE_E810T_P1_SMA2_UFL2_RX_DIS);
	} else if (ptp_pins[SMA2].func == PTP_PF_PEROUT &&
		   ptp_pins[UFL2].func == PTP_PF_EXTTS) {
		dev_info(ice_hw_to_dev(hw), "SMA2 TX + U.FL2 RX");
		data |= ICE_E810T_P1_SMA2_DIR_EN;
	}

	status = ice_write_sma_ctrl_e810t(hw, data);
	if (status)
		return ice_status_to_errno(status);

	return 0;
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
	struct ptp_pin_desc ptp_pins[NUM_E810T_PTP_PINS];
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	int err;

	if (pin < SMA1 || func > PTP_PF_PEROUT)
		return -EOPNOTSUPP;

	err = ice_get_sma_config_e810t(hw, ptp_pins);
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

	return ice_ptp_set_sma_state_e810t(hw, ptp_pins);
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

	return ice_status_to_errno(ice_aq_set_input_pin_cfg(&pf->hw, input_idx,
							    0, flags2, 0, 0));
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
 * ice_set_tx_tstamp - Enable or disable Tx timestamping
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamps are enabled or disabled
 */
static void ice_set_tx_tstamp(struct ice_pf *pf, bool on)
{
	struct ice_vsi *vsi;
	u32 val;
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

	/* Configure the Tx timestamp interrupt */
	val = rd32(&pf->hw, PFINT_OICR_ENA);
	if (on)
		val |= PFINT_OICR_TSYN_TX_M;
	else
		val &= ~PFINT_OICR_TSYN_TX_M;
	wr32(&pf->hw, PFINT_OICR_ENA, val);

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
 * ice_get_ptp_clock_index - Get the PTP clock index
 * @pf: the PF pointer
 *
 * Determine the clock index of the PTP clock associated with this device. If
 * this is the PF controlling the clock, just use the local access to the
 * clock device pointer.
 *
 * Otherwise, read from the driver shared parameters to determine the clock
 * index value.
 *
 * Returns: the index of the PTP clock associated with this device, or -1 if
 * there is no associated clock.
 */
int ice_get_ptp_clock_index(struct ice_pf *pf)
{
	enum ice_aqc_driver_params param_idx;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;
	u32 value;

	/* Use the ptp_clock structure if we're the main PF */
	if (pf->ptp.clock)
		return ptp_clock_index(pf->ptp.clock);

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (!tmr_idx)
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR0;
	else
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR1;

	status = ice_aq_get_driver_param(hw, param_idx, &value, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to read PTP clock index parameter, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
		return -1;
	}

	/* The PTP clock index is an integer, and will be between 0 and
	 * INT_MAX. The highest bit of the driver shared parameter is used to
	 * indicate whether or not the currently stored clock index is valid.
	 */
	if (!(value & PTP_SHARED_CLK_IDX_VALID))
		return -1;

	return value & ~PTP_SHARED_CLK_IDX_VALID;
}

/**
 * ice_set_ptp_clock_index - Set the PTP clock index
 * @pf: the PF pointer
 *
 * Set the PTP clock index for this device into the shared driver parameters,
 * so that other PFs associated with this device can read it.
 *
 * If the PF is unable to store the clock index, it will log an error, but
 * will continue operating PTP.
 */
static void ice_set_ptp_clock_index(struct ice_pf *pf)
{
	enum ice_aqc_driver_params param_idx;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;
	u32 value;

	if (!pf->ptp.clock)
		return;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (!tmr_idx)
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR0;
	else
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR1;

	value = (u32)ptp_clock_index(pf->ptp.clock);
	if (value > INT_MAX) {
		dev_err(ice_pf_to_dev(pf), "PTP Clock index is too large to store\n");
		return;
	}
	value |= PTP_SHARED_CLK_IDX_VALID;

	status = ice_aq_set_driver_param(hw, param_idx, value, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to set PTP clock index parameter, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
	}
}

/**
 * ice_clear_ptp_clock_index - Clear the PTP clock index
 * @pf: the PF pointer
 *
 * Clear the PTP clock index for this device. Must be called when
 * unregistering the PTP clock, in order to ensure other PFs stop reporting
 * a clock object that no longer exists.
 */
static void ice_clear_ptp_clock_index(struct ice_pf *pf)
{
	enum ice_aqc_driver_params param_idx;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;

	/* Do not clear the index if we don't own the timer */
	if (!hw->func_caps.ts_func_info.src_tmr_owned)
		return;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (!tmr_idx)
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR0;
	else
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR1;

	status = ice_aq_set_driver_param(hw, param_idx, 0, NULL);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf),
			"Failed to clear PTP clock index parameter, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
	}
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
 * ice_ptp_update_cached_phctime - Update the cached PHC time values
 * @pf: Board specific private structure
 *
 * This function updates the system time values which are cached in the PF
 * structure and the Rx rings.
 *
 * This function must be called periodically to ensure that the cached value
 * is never more than 2 seconds old. It must also be called whenever the PHC
 * time has been changed.
 *
 * Return:
 * * 0 - OK, successfully updated
 * * -EAGAIN - PF was busy, need to reschedule the update
 */
static int ice_ptp_update_cached_phctime(struct ice_pf *pf)
{
	u64 systime;
	int i;

	if (test_and_set_bit(ICE_CFG_BUSY, pf->state))
		return -EAGAIN;

	/* Read the current PHC time */
	systime = ice_ptp_read_src_clk_reg(pf, NULL);

	/* Update the cached PHC time stored in the PF structure */
	WRITE_ONCE(pf->ptp.cached_phc_time, systime);

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
static u64 ice_ptp_extend_40b_ts(struct ice_pf *pf, u64 in_tstamp)
{
	const u64 mask = GENMASK_ULL(31, 0);

	return ice_ptp_extend_32b_ts(pf->ptp.cached_phc_time,
				     (in_tstamp >> 8) & mask);
}

/**
 * ice_ptp_read_time - Read the time from the device
 * @pf: Board private structure
 * @ts: timespec structure to hold the current time value
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 *
 * This function reads the source clock registers and stores them in a timespec.
 * However, since the registers are 64 bits of nanoseconds, we must convert the
 * result to a timespec before we can return.
 */
static void ice_ptp_read_time(struct ice_pf *pf, struct timespec64 *ts,
			      struct ptp_system_timestamp *sts)
{
	u64 time_ns;

	if (pf->ptp.src_tmr_mode != ICE_SRC_TMR_MODE_NANOSECONDS) {
		dev_err(ice_pf_to_dev(pf),
			"PTP Locked mode is not supported!\n");
		return;
	}
	time_ns = ice_ptp_read_src_clk_reg(pf, sts);

	*ts = ns_to_timespec64(time_ns);
}

/**
 * ice_ptp_write_init - Set PHC time to provided value
 * @pf: Board private structure
 * @ts: timespec structure that holds the new time value
 *
 * Set the PHC time to the specified time provided in the timespec.
 */
static int ice_ptp_write_init(struct ice_pf *pf, struct timespec64 *ts)
{
	u64 ns = timespec64_to_ns(ts);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u64 val;

	if (pf->ptp.src_tmr_mode != ICE_SRC_TMR_MODE_NANOSECONDS) {
		dev_err(ice_pf_to_dev(pf),
			"PTP Locked mode is not supported!\n");
		return -EOPNOTSUPP;
	}
	val = ns;

	status = ice_ptp_init_time(hw, val);
	if (status)
		return ice_status_to_errno(status);

	return 0;
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
	enum ice_status status;

	status = ice_ptp_adj_clock(hw, adj, lock_sbq);
	if (status)
		return ice_status_to_errno(status);

	return 0;
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
	*time_ref_freq = ice_e822_time_ref(&pf->hw);
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

	if (ice_is_e810(hw))
		incval = ICE_PTP_NOMINAL_INCVAL_E810;
	else if (ice_e822_time_ref(hw) < NUM_ICE_TIME_REF_FREQ)
		incval = ice_e822_nominal_incval(ice_e822_time_ref(hw));
	else
		incval = LOCKED_INCVAL_E822;

	dev_dbg(ice_pf_to_dev(pf), "PTP: using base increment value of 0x%016llx\n",
		incval);

	return incval;
}

/**
 * ice_ptp_reset_ts_memory_quad - Reset timestamp memory for one quad
 * @pf: The PF private data structure
 * @quad: The quad (0-4)
 */
static void ice_ptp_reset_ts_memory_quad(struct ice_pf *pf, int quad)
{
	struct ice_hw *hw = &pf->hw;

	ice_write_quad_reg_e822(hw, quad, Q_REG_TS_CTRL, Q_REG_TS_CTRL_M);
	ice_write_quad_reg_e822(hw, quad, Q_REG_TS_CTRL, ~(u32)Q_REG_TS_CTRL_M);
}

/**
 * ice_ptp_check_tx_fifo - Check whether Tx FIFO is in an OK state
 * @port: PTP port for which Tx FIFO is checked
 */
static int ice_ptp_check_tx_fifo(struct ice_ptp_port *port)
{
	int quad = port->port_num / ICE_PORTS_PER_QUAD;
	int offs = port->port_num % ICE_PORTS_PER_QUAD;
	enum ice_status status;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u32 val, phy_sts;

	pf = ptp_port_to_pf(port);
	hw = &pf->hw;

	if (port->tx_fifo_busy_cnt == FIFO_OK)
		return 0;

	/* need to read FIFO state */
	if (offs == 0 || offs == 1)
		status = ice_read_quad_reg_e822(hw, quad, Q_REG_FIFO01_STATUS,
						&val);
	else
		status = ice_read_quad_reg_e822(hw, quad, Q_REG_FIFO23_STATUS,
						&val);

	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to check port %d Tx FIFO, status %s\n",
			port->port_num, ice_stat_str(status));
		return ice_status_to_errno(status);
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
		ice_ptp_reset_ts_memory_quad(pf, quad);
		port->tx_fifo_busy_cnt = FIFO_OK;
		return 0;
	}

	return -EAGAIN;
}

/**
 * ice_ptp_check_tx_offset_valid - Check if the Tx PHY offset is valid
 * @port: the PTP port to check
 *
 * Checks whether the Tx offset for the PHY associated with this port is
 * valid. Returns 0 if the offset is valid, and a non-zero error code if it is
 * not.
 */
static int ice_ptp_check_tx_offset_valid(struct ice_ptp_port *port)
{
	struct ice_pf *pf = ptp_port_to_pf(port);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u32 val;
	int err;

	err = ice_ptp_check_tx_fifo(port);
	if (err)
		return err;

	status = ice_read_phy_reg_e822(hw, port->port_num, P_REG_TX_OV_STATUS,
				       &val);
	if (status) {
		dev_err(dev, "Failed to read TX_OV_STATUS for port %d, status %s\n",
			port->port_num, ice_stat_str(status));
		return -EAGAIN;
	}

	if (!(val & P_REG_TX_OV_STATUS_OV_M))
		return -EAGAIN;

	return 0;
}

/**
 * ice_ptp_check_rx_offset_valid - Check if the Rx PHY offset is valid
 * @port: the PTP port to check
 *
 * Checks whether the Rx offset for the PHY associated with this port is
 * valid. Returns 0 if the offset is valid, and a non-zero error code if it is
 * not.
 */
static int ice_ptp_check_rx_offset_valid(struct ice_ptp_port *port)
{
	struct ice_pf *pf = ptp_port_to_pf(port);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u32 val;

	status = ice_read_phy_reg_e822(hw, port->port_num, P_REG_RX_OV_STATUS,
				       &val);
	if (status) {
		dev_err(dev, "Failed to read RX_OV_STATUS for port %d, status %s\n",
			port->port_num, ice_stat_str(status));
		return ice_status_to_errno(status);
	}

	if (!(val & P_REG_RX_OV_STATUS_OV_M))
		return -EAGAIN;

	return 0;
}

/**
 * ice_ptp_check_offset_valid - Check port offset valid bit
 * @port: Port for which offset valid bit is checked
 *
 * Returns 0 if both Tx and Rx offset are valid, and -EAGAIN if one of the
 * offset is not ready.
 */
static int ice_ptp_check_offset_valid(struct ice_ptp_port *port)
{
	int tx_err, rx_err;

	/* always check both Tx and Rx offset validity */
	tx_err = ice_ptp_check_tx_offset_valid(port);
	rx_err = ice_ptp_check_rx_offset_valid(port);

	if (tx_err || rx_err)
		return -EAGAIN;

	return 0;
}

/**
 * ice_ptp_wait_for_offset_valid - Check for valid Tx and Rx offsets
 * @work: Pointer to the kthread_work structure for this task
 *
 * Check whether both the Tx and Rx offsets are valid for enabling the vernier
 * calibration.
 *
 * Once we have valid offsets from hardware, update the total Tx and Rx
 * offsets, and exit bypass mode. This enables more precise timestamps using
 * the extra data measured during the vernier calibration process.
 */
static void ice_ptp_wait_for_offset_valid(struct kthread_work *work)
{
	struct ice_ptp_port *port;
	enum ice_status status;
	struct device *dev;
	struct ice_pf *pf;
	struct ice_hw *hw;

	port = container_of(work, struct ice_ptp_port, ov_work.work);
	pf = ptp_port_to_pf(port);
	hw = &pf->hw;
	dev = ice_pf_to_dev(pf);

	if (ice_is_reset_in_progress(pf->state))
		return;

	if (ice_ptp_check_offset_valid(port)) {
		/* Offsets not ready yet, try again later */
		kthread_queue_delayed_work(pf->ptp.kworker,
					   &port->ov_work,
					   msecs_to_jiffies(100));
		return;
	}

	/* Offsets are valid, so it is safe to exit bypass mode */
	status = ice_phy_exit_bypass_e822(hw, port->port_num);
	if (status) {
		dev_warn(dev, "Failed to exit bypass mode for PHY port %u, status %s\n",
			 port->port_num, ice_stat_str(status));
		return;
	}

}

/**
 * ice_ptp_port_phy_stop - Stop timestamping for a PHY port
 * @ptp_port: PTP port to stop
 */
static int
ice_ptp_port_phy_stop(struct ice_ptp_port *ptp_port)
{
	struct ice_pf *pf = ptp_port_to_pf(ptp_port);
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;

	if (ice_is_e810(hw))
		return 0;

	mutex_lock(&ptp_port->ps_lock);

	kthread_cancel_delayed_work_sync(&ptp_port->ov_work);

	status = ice_stop_phy_timer_e822(hw, port, true);
	if (status && status != ICE_ERR_RESET_ONGOING)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d down, status=%s\n",
			port, ice_stat_str(status));

	mutex_unlock(&ptp_port->ps_lock);

	return ice_status_to_errno(status);
}

/**
 * ice_ptp_port_phy_restart - (Re)start and calibrate PHY timestamping
 * @ptp_port: PTP port for which the PHY start is set
 *
 * Start the PHY timestamping block, and initiate Vernier timestamping
 * calibration. If timestamping cannot be calibrated (such as if link is down)
 * then disable the timestamping block instead.
 */
static int
ice_ptp_port_phy_restart(struct ice_ptp_port *ptp_port)
{
	struct ice_pf *pf = ptp_port_to_pf(ptp_port);
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;

	if (ice_is_e810(hw))
		return 0;

	if (!ptp_port->link_up)
		return ice_ptp_port_phy_stop(ptp_port);

	mutex_lock(&ptp_port->ps_lock);

	/* Start the PHY timer in bypass mode */
	kthread_cancel_delayed_work_sync(&ptp_port->ov_work);

	/* temporarily disable Tx timestamps while calibrating PHY offset */
	ptp_port->tx.calibrating = true;
	ptp_port->tx_fifo_busy_cnt = 0;

	/* Start the PHY timer in bypass mode */
	status = ice_start_phy_timer_e822(hw, port, true);
	if (status)
		goto out_unlock;

	/* Enable Tx timestamps right away */
	ptp_port->tx.calibrating = false;

	kthread_queue_delayed_work(pf->ptp.kworker, &ptp_port->ov_work, 0);

out_unlock:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d up, status=%s\n",
			port, ice_stat_str(status));

	mutex_unlock(&ptp_port->ps_lock);

	return ice_status_to_errno(status);
}

/**
 * ice_ptp_link_change - Set or clear port registers for timestamping
 * @pf: Board private structure
 * @port: Port for which the PHY start is set
 * @linkup: Link is up or down
 */
int ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup)
{
	struct ice_ptp_port *ptp_port;

	if (!test_bit(ICE_FLAG_PTP_SUPPORTED, pf->flags))
		return 0;

	if (port >= ICE_NUM_EXTERNAL_PORTS)
		return -EINVAL;

	ptp_port = &pf->ptp.port;
	if (ptp_port->port_num != port)
		return -EINVAL;

	/* Update cached link status for this port immediately */
	ptp_port->link_up = linkup;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		/* PTP is not setup */
		return -EAGAIN;

	return ice_ptp_port_phy_restart(ptp_port);
}

/**
 * ice_ptp_reset_ts_memory - Reset timestamp memory for all ports
 * @pf: The PF private data structure
 */
static void ice_ptp_reset_ts_memory(struct ice_pf *pf)
{
	int quad;

	quad = pf->hw.port_info->lport / ICE_PORTS_PER_QUAD;
	ice_ptp_reset_ts_memory_quad(pf, quad);
}

/**
 * ice_ptp_tx_ena_intr - Enable or disable the Tx timestamp interrupt
 * @pf: PF private structure
 * @ena: bool value to enable or disable interrupt
 * @threshold: Minimum number of packets at which intr is triggered
 *
 * Utility function to enable or disable Tx timestamp interrupt and threshold
 */
static int ice_ptp_tx_ena_intr(struct ice_pf *pf, bool ena, u32 threshold)
{
	enum ice_status status = 0;
	struct ice_hw *hw = &pf->hw;
	int quad;
	u32 val;

	ice_ptp_reset_ts_memory(pf);
	for (quad = 0; quad < ICE_MAX_QUAD; quad++) {
		status = ice_read_quad_reg_e822(hw, quad, Q_REG_TX_MEM_GBL_CFG,
						&val);
		if (status)
			break;

		if (ena) {
			val |= Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M;
			val &= ~Q_REG_TX_MEM_GBL_CFG_INTR_THR_M;
			val |= ((threshold << Q_REG_TX_MEM_GBL_CFG_INTR_THR_S) &
				Q_REG_TX_MEM_GBL_CFG_INTR_THR_M);
		} else {
			val &= ~Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M;
		}

		status = ice_write_quad_reg_e822(hw, quad, Q_REG_TX_MEM_GBL_CFG,
						 val);
		if (status)
			break;
	}

	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed in intr ena, status %s\n",
			ice_stat_str(status));
	return ice_status_to_errno(status);
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
	enum ice_status status;
	struct timespec64 ts;
	s64 incval;
	int err;

	if (!test_bit(ICE_FLAG_PTP, pf->flags)) {
		dev_err(dev, "PTP not ready, failed to update incval\n");
		return -EINVAL;
	}

	if ((time_ref_freq >= NUM_ICE_TIME_REF_FREQ ||
	     src_tmr_mode >= NUM_ICE_SRC_TMR_MODE))
		return -EINVAL;

	if (src_tmr_mode == ICE_SRC_TMR_MODE_NANOSECONDS)
		incval = ice_e822_nominal_incval(time_ref_freq);
	else
		incval = LOCKED_INCVAL_E822;

	if (!ice_ptp_lock(hw))
		return -EBUSY;

	status = ice_ptp_write_incval(hw, incval);
	if (status) {
		dev_err(dev, "PTP failed to update incval, status %s\n",
			ice_stat_str(status));
		err = ice_status_to_errno(status);
		goto err_unlock;
	}

	ice_set_e822_time_ref(hw, time_ref_freq);
	pf->ptp.src_tmr_mode = src_tmr_mode;

	ts = ktime_to_timespec64(ktime_get_real());
	err = ice_ptp_write_init(pf, &ts);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "PTP failed to program time registers");
		goto err_unlock;
	}

	/* unlock PTP semaphore first before resetting PHY timestamping */
	ice_ptp_unlock(hw);
	ice_ptp_reset_phy_timestamping(pf);
	ice_ptp_reset_ts_memory(pf);

	return 0;

err_unlock:
	ice_ptp_unlock(hw);

	return err;
}

#ifdef HAVE_PTP_CLOCK_INFO_ADJFINE
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
	u64 freq, divisor = 1000000ULL;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	s64 incval, diff;
	int neg_adj = 0;

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

	while ((u64)scaled_ppm > div64_u64(U64_MAX, incval)) {
		/* handle overflow by scaling down the scaled_ppm and
		 * the divisor, losing some precision
		 */
		scaled_ppm >>= 2;
		divisor >>= 2;
	}

	freq = (incval * (u64)scaled_ppm) >> 16;
	diff = div_u64(freq, divisor);

	if (neg_adj)
		incval -= diff;
	else
		incval += diff;

	status = ice_ptp_write_incval_locked(hw, incval);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to set incval, status %s\n",
			ice_stat_str(status));
		return -EIO;
	}

	return 0;
}

#else
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
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	s64 incval, freq, diff;

	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"adjfreq not supported in locked mode\n");
		return -EPERM;
	}

	incval = ice_base_incval(pf);

	freq = incval * ppb;
	diff = div_s64(freq, 1000000000ULL);
	incval += diff;

	status = ice_ptp_write_incval_locked(hw, incval);
	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to set incval, status %s\n",
			ice_stat_str(status));
		return -EIO;
	}

	return 0;
}

#endif
/**
 * ice_ptp_extts_work - Workqueue task function
 * @work: external timestamp work structure
 *
 * Service for PTP external clock event
 */
static void ice_ptp_extts_work(struct kthread_work *work)
{
	struct ice_ptp *ptp = container_of(work, struct ice_ptp, extts_work);
	struct ice_pf *pf = container_of(ptp, struct ice_pf, ptp);
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
			    pf->ptp_dpll_state != ICE_CGU_STATE_LOCKED)
				continue;

			ptp_clock_event(pf->ptp.clock, &event);
		}
	}
}

/**
 * ice_ptp_cfg_extts - Configure EXTTS pin and channel
 * @pf: Board private structure
 * @ena: true to enable; false to disable
 * @chan: GPIO channel (0-3)
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

	if (chan > (unsigned int)pf->ptp.info.n_ext_ts)
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

	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"locked mode PPS/PEROUT not supported\n");
		return -EIO;
	}

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

	if (ice_is_e810(hw))
		start_time -= E810_OUT_PROP_DELAY_NS;
	else
		start_time -= ice_e822_pps_delay(ice_e822_time_ref(hw));

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
	int i;

	for (i = 0; i < pf->ptp.info.n_per_out; i++)
		if (pf->ptp.perout_channels[i].ena)
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
	int i;

	for (i = 0; i < pf->ptp.info.n_per_out; i++)
		if (pf->ptp.perout_channels[i].ena)
			ice_ptp_cfg_clkout(pf, i, &pf->ptp.perout_channels[i],
					   false);
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
	struct ice_hw *hw = &pf->hw;

	if (!ice_ptp_lock(hw)) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to get time\n");
		return -EBUSY;
	}

	ice_ptp_read_time(pf, ts, sts);
	ice_ptp_unlock(hw);

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
	int err;

	/* For Vernier mode, we need to recalibrate after new settime
	 * Start with disabling timestamp block
	 */
	if (pf->ptp.port.link_up)
		ice_ptp_port_phy_stop(&pf->ptp.port);

	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		goto exit;
	}

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);

	err = ice_ptp_write_init(pf, &ts64);
	ice_ptp_unlock(hw);

	if (!err)
		ice_ptp_update_cached_phctime(pf);

	/* Reenable periodic outputs */
	ice_ptp_enable_all_clkout(pf);

	/* Recalibrate and re-enable timestamp block */
	if (pf->ptp.port.link_up)
		ice_ptp_port_phy_restart(&pf->ptp.port);
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
 * ice_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	if (pf->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(dev, "Locked Mode adjtime not supported\n");
		return -EIO;
	}

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

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);

	err = ice_ptp_write_adj(pf, delta, true);

	/* Reenable periodic outputs */
	ice_ptp_enable_all_clkout(pf);

	ice_ptp_unlock(hw);

	if (err) {
		ice_dev_err_errno(dev, err, "PTP failed to adjust time");
		return err;
	}

	ice_ptp_update_cached_phctime(pf);

	return 0;
}

/**
 * ice_ptp_gpio_enable_generic - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int
ice_ptp_gpio_enable_generic(struct ptp_clock_info *info,
			    struct ptp_clock_request *rq, int on)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_perout_channel clk_cfg = {0};
	int err;

	switch (rq->type) {
	case PTP_CLK_REQ_PEROUT:
		clk_cfg.gpio_pin = PPS_PIN_INDEX;
		clk_cfg.period = ((rq->perout.period.sec * NSEC_PER_SEC) +
				   rq->perout.period.nsec);
		clk_cfg.start_time = ((rq->perout.start.sec * NSEC_PER_SEC) +
				       rq->perout.start.nsec);
		clk_cfg.ena = !!on;

		err = ice_ptp_cfg_clkout(pf, rq->perout.index, &clk_cfg, true);
		break;
	case PTP_CLK_REQ_EXTTS:
		err = ice_ptp_cfg_extts(pf, !!on, rq->extts.index,
					TIME_SYNC_PIN_INDEX, rq->extts.flags);
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
		} else if (ice_is_feature_supported(pf, ICE_F_CGU)) {
			if (chan == 0)
				clk_cfg.gpio_pin = GPIO_20;
			else
				clk_cfg.gpio_pin = GPIO_22;
		} else if (chan == PPS_CLK_GEN_CHAN) {
			clk_cfg.gpio_pin = PPS_PIN_INDEX;
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
		} else if (ice_is_feature_supported(pf, ICE_F_CGU)) {
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
 * ice_ptp_gpio_enable_e823 - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int ice_ptp_gpio_enable_e823(struct ptp_clock_info *info,
				    struct ptp_clock_request *rq, int on)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_perout_channel clk_cfg = {0};
	int err;

	switch (rq->type) {
	case PTP_CLK_REQ_PPS:
		clk_cfg.gpio_pin = PPS_PIN_INDEX;
		clk_cfg.period = NSEC_PER_SEC;
		clk_cfg.ena = !!on;

		err = ice_ptp_cfg_clkout(pf, PPS_CLK_GEN_CHAN, &clk_cfg, true);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return err;
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
	struct ice_pf *pf = (struct ice_pf *)ctx;
	struct ice_hw *hw = &pf->hw;
	u32 hh_lock, hh_art_ctl;
	int i;

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

	/* Start the ART and device clock sync sequence */
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
			u32 hh_ts_lo, hh_ts_hi, tmr_idx;
			u64 hh_ts;

			tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
			/* Read ART time */
			hh_ts_lo = rd32(hw, GLHH_ART_TIME_L);
			hh_ts_hi = rd32(hw, GLHH_ART_TIME_H);
			hh_ts = ((u64)hh_ts_hi << 32) | hh_ts_lo;
			*system = convert_art_ns_to_tsc(hh_ts);
			/* Read Device source clock time */
			hh_ts_lo = rd32(hw, GLTSYN_HHTIME_L(tmr_idx));
			hh_ts_hi = rd32(hw, GLTSYN_HHTIME_H(tmr_idx));
			hh_ts = ((u64)hh_ts_hi << 32) | hh_ts_lo;
			*device = ns_to_ktime(hh_ts);
			break;
		}
	}
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
 * This is only valid for E822 devices which have support for generating the
 * cross timestamp via PCIe PTM.
 *
 * In order to correctly correlate the ART timestamp back to the TSC time, the
 * CPU must have X86_FEATURE_TSC_KNOWN_FREQ.
 */
static int
ice_ptp_getcrosststamp_generic(struct ptp_clock_info *info,
			       struct system_device_crosststamp *cts)
{
	struct ice_pf *pf = ptp_info_to_pf(info);

	return get_device_system_crosststamp(ice_ptp_get_syncdevicetime,
					     pf, NULL, cts);
}
#endif /* HAVE_PTP_CROSSTIMESTAMP */

/**
 * ice_ptp_set_timestamp_mode - Setup driver for requested timestamp mode
 * @pf: Board private structure
 * @config: hwtstamp settings requested or saved
 */
static int
ice_ptp_set_timestamp_mode(struct ice_pf *pf, struct hwtstamp_config *config)
{
	/* Reserved for future extensions. */
	if (config->flags)
		return -EINVAL;

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
ice_ptp_rx_hwtstamp(struct ice_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc, struct sk_buff *skb)
{
	u32 ts_high;
	u64 ts_ns;

	/* Populate timesync data into skb */
	if (rx_desc->wb.time_stamp_low & ICE_PTP_TS_VALID) {
		struct skb_shared_hwtstamps *hwtstamps;

		/* Use ice_ptp_extend_32b_ts directly, using the ring-specific
		 * cached PHC value, rather than accessing the PF. This also
		 * allows us to simply pass the upper 32bits of nanoseconds
		 * directly. Calling ice_ptp_extend_40b_ts is unnecessary as
		 * it would just discard these bits itself.
		 */
		ts_high = le32_to_cpu(rx_desc->wb.flex_ts.ts_high);
		ts_ns = ice_ptp_extend_32b_ts(rx_ring->cached_phctime, ts_high);

		hwtstamps = skb_hwtstamps(skb);
		memset(hwtstamps, 0, sizeof(*hwtstamps));
		hwtstamps->hwtstamp = ns_to_ktime(ts_ns);
	}
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
	err = ice_get_sma_config_e810t(&pf->hw, info->pin_config);
	if (err) {
		ice_ptp_disable_sma_pins_e810t(pf, info);
		return;
	}
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

	if (ice_is_feature_supported(pf, ICE_F_PTP_EXTTS))
		info->n_ext_ts = N_EXT_TS_E810;

	if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
		info->n_ext_ts = N_EXT_TS_E810;
		info->n_pins = NUM_E810T_PTP_PINS;
		info->verify = ice_verify_pin_e810t;

		/* Complete setup of the SMA pins */
		ice_ptp_setup_sma_pins_e810t(pf, info);
		return;
	}

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		info->n_ext_ts = N_EXT_TS_NO_SMA_E810T;
		info->n_per_out = N_PER_OUT_NO_SMA_E810T;
		return;
	}
}

/**
 * ice_ptp_setup_pins_e823 - Setup PTP pins in sysfs
 * @pf: pointer to the PF instance
 * @info: PTP clock capabilities
 */
static void
ice_ptp_setup_pins_e823(struct ice_pf *pf, struct ptp_clock_info *info)
{
	info->pps = 1;
	info->n_per_out = 0;
	info->n_ext_ts = 0;
}

/**
 * ice_ptp_setup_pins_generic - Setup PTP pins in sysfs
 * @pf: pointer to the PF instance
 * @info: PTP clock capabilities
 */
static void
ice_ptp_setup_pins_generic(struct ice_pf *pf, struct ptp_clock_info *info)
{
	info->pps = 1;
	info->n_per_out = 1;
	if (!ice_is_feature_supported(pf, ICE_F_PTP_EXTTS))
		return;
	info->n_ext_ts = 1;
}

/**
 * ice_ptp_set_funcs_generic - Set specialized functions for E822 support
 * @pf: Board private structure
 * @info: PTP info to fill
 *
 * Assign functions to the PTP capabiltiies structure for E822 devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for E822
 * devices.
 */
static void
ice_ptp_set_funcs_generic(struct ice_pf *pf, struct ptp_clock_info *info)
{
#ifdef HAVE_PTP_CROSSTIMESTAMP
	if (boot_cpu_has(X86_FEATURE_ART) &&
	    boot_cpu_has(X86_FEATURE_TSC_KNOWN_FREQ))
		info->getcrosststamp = ice_ptp_getcrosststamp_generic;
#endif /* HAVE_PTP_CROSSTIMESTAMP */
	info->enable = ice_ptp_gpio_enable_generic;

	ice_ptp_setup_pins_generic(pf, info);
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
 * ice_ptp_set_funcs_e823 - Set specialized functions for E823 support
 * @pf: Board private structure
 * @info: PTP info to fill
 *
 * Assign functions to the PTP capabiltiies structure for E823 devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for e823
 * devices.
 */
static void
ice_ptp_set_funcs_e823(struct ice_pf *pf, struct ptp_clock_info *info)
{
	info->enable = ice_ptp_gpio_enable_e823;
	ice_ptp_setup_pins_e823(pf, info);
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
	info->max_adj = 999999999;
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
	else if (ice_is_e823(&pf->hw))
		ice_ptp_set_funcs_e823(pf, info);
	else
		ice_ptp_set_funcs_generic(pf, info);
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
	struct ptp_clock *clock;
	struct device *dev;

	/* No need to create a clock device if we already have one */
	if (pf->ptp.clock)
		return 0;

	ice_ptp_set_caps(pf);

	info = &pf->ptp.info;
	dev = ice_pf_to_dev(pf);

	/* Attempt to register the clock before enabling the hardware. */
	clock = ptp_clock_register(info, dev);
	if (IS_ERR(clock)) {
		ice_dev_err_errno(dev, PTR_ERR(clock),
				  "Failed to register PTP clock device");
		return PTR_ERR(clock);
	}

	pf->ptp.clock = clock;

	return 0;
}

/**
 * ice_ptp_tx_tstamp - Process Tx timestamps for a port
 * @tx: the PTP Tx timestamp tracker
 *
 * Process timestamps captured by the PHY associated with this port. To do
 * this, loop over each index with a waiting skb.
 *
 * If a given index has a valid timestamp, perform the following steps:
 *
 * 1) copy the timestamp out of the PHY register
 * 4) clear the timestamp valid bit in the PHY register
 * 5) unlock the index by clearing the associated in_use bit.
 * 2) extend the 40b timestamp value to get a 64bit timestamp
 * 3) send that timestamp to the stack
 *
 * After looping, if we still have waiting SKBs, then re-queue the work. This
 * may cause us effectively poll even when not strictly necessary. We do this
 * because it's possible a new timestamp was requested around the same time as
 * the interrupt. In some cases hardware might not interrupt us again when the
 * timestamp is captured.
 *
 * Note that we only take the tracking lock when clearing the bit and when
 * checking if we need to re-queue this task. The only place where bits can be
 * set is the hard xmit routine where an SKB has a request flag set. The only
 * places where we clear bits are this work function, or the periodic cleanup
 * thread. If the cleanup thread clears a bit we're processing we catch it
 * when we lock to clear the bit and then grab the SKB pointer. If a Tx thread
 * starts a new timestamp, we might not begin processing it right away but we
 * will notice it at the end when we re-queue the work item. If a Tx thread
 * starts a new timestamp just after this function exits without re-queuing,
 * the interrupt when the timestamp finishes should trigger. Avoiding holding
 * the lock for the entire function is important in order to ensure that Tx
 * threads do not get blocked while waiting for the lock.
 */
static void ice_ptp_tx_tstamp(struct ice_ptp_tx *tx)
{
	struct ice_ptp_port *ptp_port;
	struct ice_pf *pf;
	u8 idx;

	if (!tx->init)
		return;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);

	for_each_set_bit(idx, tx->in_use, tx->len) {
		struct skb_shared_hwtstamps shhwtstamps = {};
		u8 phy_idx = idx + tx->offset;
		enum ice_status status;
		u64 raw_tstamp, tstamp;
		struct sk_buff *skb;

		ice_trace(tx_tstamp_fw_req, tx->tstamps[idx].skb, idx);

		status = ice_read_phy_tstamp(&pf->hw, tx->block, phy_idx,
					     &raw_tstamp);
		if (status)
			continue;

		ice_trace(tx_tstamp_fw_done, tx->tstamps[idx].skb, idx);

		/* Check if the timestamp is invalid or stale */
		if (!(raw_tstamp & ICE_PTP_TS_VALID) ||
		    raw_tstamp == tx->tstamps[idx].cached_tstamp)
			continue;

		/* The timestamp is valid, so we'll go ahead and clear this
		 * index and then send the timestamp up to the stack.
		 */
		spin_lock(&tx->lock);
		tx->tstamps[idx].cached_tstamp = raw_tstamp;
		clear_bit(idx, tx->in_use);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		spin_unlock(&tx->lock);

		/* it's (unlikely but) possible we raced with the cleanup
		 * thread for discarding old timestamp requests.
		 */
		if (!skb)
			continue;

		/* Extend the timestamp using cached PHC time */
		tstamp = ice_ptp_extend_40b_ts(pf, raw_tstamp);
		shhwtstamps.hwtstamp = ns_to_ktime(tstamp);

		ice_trace(tx_tstamp_complete, skb, idx);

		skb_tstamp_tx(skb, &shhwtstamps);
		dev_kfree_skb_any(skb);
	}

	/* Check if we still have work to do. If so, re-queue this task to
	 * poll for remaining timestamps.
	 */
	spin_lock(&tx->lock);
	if (!bitmap_empty(tx->in_use, tx->len)) {
		if (tx->ll_ena)
			tasklet_schedule(&tx->tasklet);
		else
			kthread_queue_work(pf->ptp.kworker, &tx->work);
	}
	spin_unlock(&tx->lock);
}

/**
 * ice_ptp_tx_tstamp_task - Task for processing Tx timestamps for a port
 * @task: tasklet struct for Tx timestamping
 */
#ifdef HAVE_TASKLET_SETUP
static void ice_ptp_tx_tstamp_task(struct tasklet_struct *task)
{
	struct ice_ptp_tx *tx = from_tasklet(tx, task, tasklet);
#else
static void ice_ptp_tx_tstamp_task(unsigned long data)
{
	struct ice_ptp_tx *tx = (struct ice_ptp_tx *)data;
#endif

	ice_ptp_tx_tstamp(tx);
}

/**
 * ice_ptp_tx_tstamp_work - Work for processing Tx timestamps for a port
 * @work: pointer to the kthread_work struct
 */
static void ice_ptp_tx_tstamp_work(struct kthread_work *work)
{
	struct ice_ptp_tx *tx = container_of(work, struct ice_ptp_tx, work);

	ice_ptp_tx_tstamp(tx);
}

/**
 * ice_ptp_request_ts - Request an available Tx timestamp index
 * @tx: the PTP Tx timestamp tracker to request from
 * @skb: the SKB to associate with this timestamp request
 */
s8 ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb)
{
	u8 idx;

	/* Check if this tracker is initialized */
	if (!tx->init || tx->calibrating)
		return -1;

	spin_lock(&tx->lock);
	/* Find and set the first available index */
	idx = find_first_zero_bit(tx->in_use, tx->len);
	if (idx < tx->len) {
		/* We got a valid index that no other thread could have set.
		 * Store a reference to the skb and the start time to allow
		 * discarding old requests.
		 */
		set_bit(idx, tx->in_use);
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
 * ice_ptp_process_ts - Spawn kthread work to handle timestamps
 * @pf: Board private structure
 *
 * Queue work required to process the PTP Tx timestamps outside of interrupt
 * context.
 */
void ice_ptp_process_ts(struct ice_pf *pf)
{
	if (!pf->ptp.port.tx.init)
		return;

	if (pf->ptp.port.tx.ll_ena)
		tasklet_schedule(&pf->ptp.port.tx.tasklet);
	else
		kthread_queue_work(pf->ptp.kworker, &pf->ptp.port.tx.work);
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
	tx->tstamps = (struct ice_tx_tstamp *)kcalloc(tx->len, sizeof(*tx->tstamps), GFP_KERNEL);
	if (!tx->tstamps)
		return -ENOMEM;

	tx->in_use = bitmap_zalloc(tx->len, GFP_KERNEL);
	if (!tx->in_use) {
		kfree(tx->tstamps);
		tx->tstamps = NULL;
		return -ENOMEM;
	}

	spin_lock_init(&tx->lock);

	if (tx->ll_ena)
#ifdef HAVE_TASKLET_SETUP
		tasklet_setup(&tx->tasklet, ice_ptp_tx_tstamp_task);
#else
		tasklet_init(&tx->tasklet, ice_ptp_tx_tstamp_task,
			     (unsigned long)tx);
#endif
	else
		kthread_init_work(&tx->work, ice_ptp_tx_tstamp_work);

	tx->init = 1;

	return 0;
}

/**
 * ice_ptp_flush_tx_tracker - Flush any remaining timestamps from the tracker
 * @pf: Board private structure
 * @tx: the tracker to flush
 */
static void
ice_ptp_flush_tx_tracker(struct ice_pf *pf, struct ice_ptp_tx *tx)
{
	u8 idx;

	for (idx = 0; idx < tx->len; idx++) {
		u8 phy_idx = idx + tx->offset;

		spin_lock(&tx->lock);
		if (tx->tstamps[idx].skb) {
			dev_kfree_skb_any(tx->tstamps[idx].skb);
			tx->tstamps[idx].skb = NULL;
		}
		clear_bit(idx, tx->in_use);
		spin_unlock(&tx->lock);

		/* Clear any potential residual timestamp in the PHY block */
		if (!pf->hw.reset_ongoing)
			ice_clear_phy_tstamp(&pf->hw, tx->block, phy_idx);
	}
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
	tx->init = 0;

	if (tx->ll_ena)
		tasklet_kill(&tx->tasklet);
	else
		kthread_cancel_work_sync(&tx->work);

	ice_ptp_flush_tx_tracker(pf, tx);

	kfree(tx->tstamps);
	tx->tstamps = NULL;

	bitmap_free(tx->in_use);
	tx->in_use = NULL;

	tx->len = 0;
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

	if (pf->hw.dev_caps.ts_dev_info.ts_ll_read)
		tx->ll_ena = 1;

	return ice_ptp_alloc_tx_tracker(tx);
}

/**
 * ice_ptp_tx_tstamp_cleanup - Cleanup old timestamp requests that got dropped
 * @hw: pointer to the hw struct
 * @tx: PTP Tx tracker to clean up
 *
 * Loop through the Tx timestamp requests and see if any of them have been
 * waiting for a long time. Discard any SKBs that have been waiting for more
 * than 2 seconds. This is long enough to be reasonably sure that the
 * timestamp will never be captured. This might happen if the packet gets
 * discarded before it reaches the PHY timestamping block.
 */
static void ice_ptp_tx_tstamp_cleanup(struct ice_hw *hw, struct ice_ptp_tx *tx)
{
	u8 idx;

	if (!tx->init)
		return;

	for_each_set_bit(idx, tx->in_use, tx->len) {
		struct sk_buff *skb;
		u64 raw_tstamp;

		/* Check if this SKB has been waiting for too long */
		if (time_is_after_jiffies(tx->tstamps[idx].start + 2 * HZ))
			continue;

		/* Read tstamp to be able to use this register again */
		ice_read_phy_tstamp(hw, tx->block, idx + tx->offset,
				    &raw_tstamp);

		spin_lock(&tx->lock);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);
		spin_unlock(&tx->lock);

		/* Free the SKB after we've cleared the bit */
		dev_kfree_skb_any(skb);
	}
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
			 "<DPLL%i> state changed to: %s, pin %s",
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
			 "<DPLL%i> state changed to: %s, pin %s",
			 ICE_CGU_DPLL_PTP,
			 ice_cgu_state_to_name(pf->ptp_dpll_state), pin_name);
	}
}

static void ice_ptp_periodic_work(struct kthread_work *work)
{
	struct ice_ptp *ptp = container_of(work, struct ice_ptp, work.work);
	struct ice_pf *pf = container_of(ptp, struct ice_pf, ptp);
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

	ice_ptp_tx_tstamp_cleanup(&pf->hw, &pf->ptp.port.tx);

	/* Run twice a second or reschedule if PHC update failed */
	kthread_queue_delayed_work(ptp->kworker, &ptp->work,
				   msecs_to_jiffies(err ? 10 : 500));
}

/**
 * ice_ptp_reset - Initialize PTP hardware clock support after reset
 * @pf: Board private structure
 */
void ice_ptp_reset(struct ice_pf *pf)
{
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct timespec64 ts;
	int err, itr = 1;
	u64 time_diff;

	if (test_bit(ICE_PFR_REQ, pf->state))
		goto pfr;

	if (!hw->func_caps.ts_func_info.src_tmr_owned)
		goto reset_ts;

	status = ice_ptp_init_phc(hw);
	if (status) {
		err = ice_status_to_errno(status);
		dev_err(ice_pf_to_dev(pf),
			"Failed to initialize PHC, status %s\n",
			ice_stat_str(status));
		goto err;
	}

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(ice_pf_to_dev(pf), "Failed to acquire PTP hardware semaphore\n");
		goto err;
	}

	/* Write the increment time value to PHY and LAN */
	status = ice_ptp_write_incval(hw, ice_base_incval(pf));
	if (status) {
		err = ice_status_to_errno(status);
		dev_err(ice_pf_to_dev(pf),
			"Failed to write PHC increment value, status %s\n",
			ice_stat_str(status));
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
	err = ice_ptp_write_init(pf, &ts);
	if (err) {
		ice_dev_err_errno(ice_pf_to_dev(pf), err,
				  "Failed to write PHC initial time");
		ice_ptp_unlock(hw);
		goto err;
	}

	/* Release the global hardware lock */
	ice_ptp_unlock(hw);

	if (!ice_is_e810(hw)) {
		/* Enable quad interrupts */
		err = ice_ptp_tx_ena_intr(pf, true, itr);
		if (err) {
			ice_dev_err_errno(ice_pf_to_dev(pf), err,
					  "Failed to enable Tx interrupt");
			goto err;
		}
	}

reset_ts:
	/* Restart the PHY timestamping block */
	ice_ptp_reset_phy_timestamping(pf);

pfr:
	/* Init Tx structures */
	if (ice_is_e810(&pf->hw)) {
		err = ice_ptp_init_tx_e810(pf, &ptp->port.tx);
	} else {
		kthread_init_delayed_work(&ptp->port.ov_work,
					  ice_ptp_wait_for_offset_valid);
		err = ice_ptp_init_tx_e822(pf, &ptp->port.tx,
					   ptp->port.port_num);
	}
	if (err)
		goto err;

	set_bit(ICE_FLAG_PTP, pf->flags);

	/* Start periodic work going */
	kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	dev_info(ice_pf_to_dev(pf), "PTP reset successful\n");
	return;

err:
	ice_dev_err_errno(ice_pf_to_dev(pf), err, "PTP reset failed");
}

/**
 * ice_ptp_prepare_for_reset - Prepare PTP for reset
 * @pf: Board private structure
 */
void ice_ptp_prepare_for_reset(struct ice_pf *pf)
{
	struct ice_ptp *ptp = &pf->ptp;
	u8 src_tmr;

	clear_bit(ICE_FLAG_PTP, pf->flags);

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);

	kthread_cancel_delayed_work_sync(&ptp->work);
	kthread_cancel_work_sync(&ptp->extts_work);

	if (test_bit(ICE_PFR_REQ, pf->state))
		return;

	ice_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	/* Disable periodic outputs */
	ice_ptp_disable_all_clkout(pf);

	src_tmr = ice_get_ptp_src_clock_index(&pf->hw);

	/* Disable source clock */
	wr32(&pf->hw, GLTSYN_ENA(src_tmr), (u32)~GLTSYN_ENA_TSYN_ENA_M);

	/* Acquire PHC and system timer to restore after reset */
	ptp->reset_time = ktime_get_real_ns();
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
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct timespec64 ts;
	int err, itr = 1;

	status = ice_ptp_init_phc(hw);
	if (status) {
		dev_err(dev, "Failed to initialize PHC, status %s\n",
			ice_stat_str(status));
		return ice_status_to_errno(status);
	}

	pf->ptp.src_tmr_mode = ICE_SRC_TMR_MODE_NANOSECONDS;

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(dev, "Failed to acquire PTP hardware semaphore\n");
		goto err_exit;
	}

	/* Write the increment time value to PHY and LAN */
	status = ice_ptp_write_incval(hw, ice_base_incval(pf));
	if (status) {
		err = ice_status_to_errno(status);
		dev_err(dev, "Failed to write PHC increment value, status %s\n",
			ice_stat_str(status));
		ice_ptp_unlock(hw);
		goto err_exit;
	}

	ts = ktime_to_timespec64(ktime_get_real());
	/* Write the initial Time value to PHY and LAN */
	err = ice_ptp_write_init(pf, &ts);
	if (err) {
		ice_dev_err_errno(dev, err, "Failed to write PHC initial time");
		ice_ptp_unlock(hw);
		goto err_exit;
	}

	/* Release the global hardware lock */
	ice_ptp_unlock(hw);

	if (!ice_is_e810(hw)) {
		/* Enable quad interrupts */
		err = ice_ptp_tx_ena_intr(pf, true, itr);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "Failed to enable Tx interrupt");
			goto err_exit;
		}
	}

	/* Ensure we have a clock device */
	err = ice_ptp_create_clock(pf);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "Failed to register PTP clock device");
		goto err_clk;
	}

	/* Store the PTP clock index for other PFs */
	ice_set_ptp_clock_index(pf);

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		set_bit(ICE_FLAG_DPLL_MONITOR, pf->flags);
		pf->synce_dpll_state = ICE_CGU_STATE_UNINITIALIZED;
		pf->ptp_dpll_state = ICE_CGU_STATE_UNINITIALIZED;
	}

	return 0;

err_clk:
	pf->ptp.clock = NULL;
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
	kthread_init_work(&ptp->extts_work, ice_ptp_extts_work);

	/* Allocate a kworker for handling work required for the ports
	 * connected to the PTP hardware clock.
	 */
	kworker = kthread_create_worker(0, "ice-ptp-%s",
					dev_name(ice_pf_to_dev(pf)));
	if (IS_ERR(kworker))
		return PTR_ERR(kworker);

	ptp->kworker = kworker;

	/* Start periodic work going */
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
	int err;

	mutex_init(&ptp_port->ps_lock);

	if (ice_is_e810(&pf->hw))
		return ice_ptp_init_tx_e810(pf, &ptp_port->tx);

	kthread_init_delayed_work(&ptp_port->ov_work,
				  ice_ptp_wait_for_offset_valid);
	err = ice_ptp_init_tx_e822(pf, &ptp_port->tx, ptp_port->port_num);
	return err;
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

	ice_ptp_init_phy_cfg(hw);

	/* If this function owns the clock hardware, it must allocate and
	 * configure the PTP clock device to represent it.
	 */
	if (hw->func_caps.ts_func_info.src_tmr_owned) {
		err = ice_ptp_init_owner(pf);
		if (err)
			goto err;
	}

	ptp->port.port_num = hw->pf_id;
	err = ice_ptp_init_port(pf, &ptp->port);
	if (err)
		goto err;

	/* Start the PHY timestamping block */
	ice_ptp_reset_phy_timestamping(pf);

	set_bit(ICE_FLAG_PTP, pf->flags);
	err = ice_ptp_init_work(pf, ptp);
	if (err)
		goto err;

	ice_ptp_sysfs_init(pf);

	dev_info(ice_pf_to_dev(pf), "PTP init successful\n");
	return;

err:
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
	struct ice_vsi *vsi;
	char *dev_name;

	if (!pf)
		return;

	vsi = ice_get_main_vsi(pf);
	if (!vsi || !test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	dev_name = vsi->netdev->name;

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);

	ice_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	clear_bit(ICE_FLAG_PTP, pf->flags);

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

	ice_clear_ptp_clock_index(pf);
	ptp_clock_unregister(pf->ptp.clock);
	pf->ptp.clock = NULL;

	/* Free pin config */
	if (pf->ptp.info.pin_config) {
		devm_kfree(ice_pf_to_dev(pf), pf->ptp.info.pin_config);
		pf->ptp.info.pin_config = NULL;
	}

	dev_info(ice_pf_to_dev(pf), "removed Clock from %s\n", dev_name);
}
