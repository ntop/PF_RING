/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_irq.h"
#include "ice_cpi.h"
#include "ice_tspll.h"
#ifndef NEED_READ_POLL_TIMEOUT
#include <linux/iopoll.h>
#endif
#include "ice_dpll.h"
#if defined(CONFIG_X86)
#include "asm/tsc.h"
#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */

static const char ice_pin_names[][64] = {
	"SDP0",
	"SDP1",
	"SDP2",
	"SDP3",
	"TIME_SYNC",
	"1PPS",
};
static const struct ice_ptp_pin_desc ice_pin_desc_e82x[] = {
	/* name,        gpio,       delay */
	{  TIME_SYNC, {  4, -1 }, { 0,  0 }},
	{  ONE_PPS,   { -1,  5 }, { 0, 11 }},
};

static const struct ice_ptp_pin_desc ice_pin_desc_e825c[] = {
	/* name,        gpio,       delay */
	{  SDP0,      {  0,  0 }, { 15, 14 }},
	{  SDP1,      {  1,  1 }, { 15, 14 }},
	{  SDP2,      {  2,  2 }, { 15, 14 }},
	{  SDP3,      {  3,  3 }, { 15, 14 }},
	{  TIME_SYNC, {  4, -1 }, { 11,  0 }},
	{  ONE_PPS,   { -1,  5 }, {  0,  9 }},
};

static const struct ice_ptp_pin_desc ice_pin_desc_e810[] = {
	/* name,        gpio,       delay */
	{  SDP0,      {  0,  0 }, { 0, 1 }},
	{  SDP1,      {  1,  1 }, { 0, 1 }},
	{  SDP2,      {  2,  2 }, { 0, 1 }},
	{  SDP3,      {  3,  3 }, { 0, 1 }},
	{  ONE_PPS,   { -1,  5 }, { 0, 1 }},
};

static const char ice_pin_names_dpll[][64] = {
	"SDP20",
	"SDP21",
	"SDP22",
	"SDP23",
};

static const struct ice_ptp_pin_desc ice_pin_desc_dpll[] = {
	/* name,   gpio,       delay */
	{  SDP0, { -1,  0 }, { 0, 1 }},
	{  SDP1, {  1, -1 }, { 0, 0 }},
	{  SDP2, { -1,  2 }, { 0, 1 }},
	{  SDP3, {  3, -1 }, { 0, 0 }},
};

static struct ice_pf *ice_get_ctrl_pf(struct ice_pf *pf)
{
	return !pf->adapter ? NULL : pf->adapter->ctrl_pf;
}

static struct ice_ptp *ice_get_ctrl_ptp(struct ice_pf *pf)
{
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);

	return !ctrl_pf ? NULL : &ctrl_pf->ptp;
}

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

#define DPLL_ATTR(_dpll_num, _name)					\
	struct dpll_attribute dev_attr_##dpll_##_dpll_num##_##_name = {	\
		__ATTR(dpll_##_dpll_num##_##_name, 0444, dpll_##_name##_show, \
		       NULL),						\
		_dpll_num						\
	}

#define DPLL_ATTR_RW(_dpll_num, _name)					\
	struct dpll_attribute dev_attr_##dpll_##_dpll_num##_##_name = { \
		__ATTR(dpll_##_dpll_num##_##_name, 0644, dpll_##_name##_show, \
		       dpll_##_name##_store),				\
		_dpll_num						\
	}

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
static ssize_t dpll_ref_sw_show(struct device *dev,
				struct device_attribute *attr,
				char *buf);
static ssize_t dpll_ref_sw_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t len);
static ssize_t pin_cfg_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf);
static ssize_t dpll_offset_show(struct device *dev,
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
static ssize_t ptp_802_3cx_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count);
static ssize_t ptp_802_3cx_show(struct device *dev,
				struct device_attribute *attr,
				char *buf);
static ssize_t SMA1_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len);
static ssize_t SMA1_show(struct device *dev, struct device_attribute *attr,
			 char *buf);
static ssize_t SMA2_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len);
static ssize_t SMA2_show(struct device *dev, struct device_attribute *attr,
			 char *buf);
static ssize_t UFL1_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len);
static ssize_t UFL1_show(struct device *dev, struct device_attribute *attr,
			 char *buf);
static ssize_t UFL2_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len);
static ssize_t UFL2_show(struct device *dev, struct device_attribute *attr,
			 char *buf);
static DEVICE_ATTR_RW(SMA1);
static DEVICE_ATTR_RW(SMA2);
static struct device_attribute dev_attr_UFL1 = {
	.attr = { .name = "U.FL1", .mode = 0644 },
	.show	= UFL1_show,
	.store	= UFL1_store,
};

static struct device_attribute dev_attr_UFL2 = {
	.attr = { .name = "U.FL2", .mode = 0644 },
	.show	= UFL2_show,
	.store	= UFL2_store,
};

static struct kobj_attribute synce_attribute = __ATTR_WO(synce);
static DEVICE_ATTR_RW(pin_cfg);
static struct kobj_attribute tx_clk_attribute = __ATTR_WO(tx_clk);
static DEVICE_ATTR_WO(clock_1588);
static DPLL_ATTR(0, name);
static DPLL_ATTR(0, state);
static DPLL_ATTR(0, ref_pin);
static DPLL_ATTR_RW(0, ref_sw);
static DPLL_ATTR(1, name);
static DPLL_ATTR(1, state);
static DPLL_ATTR(1, ref_pin);
static DPLL_ATTR(1, offset);
static DPLL_ATTR_RW(1, ref_sw);
static DEVICE_ATTR_RW(ptp_802_3cx);

/**
 * ice_ptp_sma_pin_str - Convert ice_sma_pins to string
 * @pin: SMA pin index
 */
static const char *ice_ptp_sma_pin_str(enum ice_sma_pins pin)
{
	switch (pin) {
	case SMA_SMA1:
		return "SMA1";
	case SMA_SMA2:
		return "SMA2";
	case SMA_UFL1:
		return "U.FL1";
	case SMA_UFL2:
		return "U.FL2";
	default:
		return "Unknown";
	}
}

/**
 * ice_ptp_sma_fun_str - Convert ptp_pin_function for SMA to string
 * @fun: target function
 */
static const char *ice_ptp_sma_fun_str(enum ptp_pin_function fun)
{
	switch (fun) {
	case PTP_PF_NONE:
		return "disabled";
	case PTP_PF_EXTTS:
		return "input";
	case PTP_PF_PEROUT:
		return "output";
	default:
		return "Unknown";
	}
}

/**
 * ice_ptp_verify_sma_cfg - verify the configuration of the SMA control logic
 * @hw: pointer to HW struct
 * @pin: changed pin number
 * @fun: target pin function
 *
 * Return: 0 on success, negative error code otherwise.
 */
static int ice_ptp_verify_sma_cfg(struct ice_hw *hw, enum ice_sma_pins pin,
				  enum ptp_pin_function fun)
{
	enum ptp_pin_function *sma_pins = hw->ptp.sma_cfg;

	/* Validate supported pin functions */
	if ((pin == SMA_UFL1 && fun == PTP_PF_EXTTS) ||
	    (pin == SMA_UFL2 && fun == PTP_PF_PEROUT))
		return -EIO;

	dev_dbg(ice_hw_to_dev(hw), "%s %s\n", ice_ptp_sma_pin_str(pin),
		ice_ptp_sma_fun_str(fun));

	switch (pin) {
	case SMA_SMA1:
		if (fun == PTP_PF_EXTTS && sma_pins[SMA_UFL1] == PTP_PF_NONE) {
			dev_warn(ice_hw_to_dev(hw), "SMA1 set to Rx. U.FL1 automatically enabled as Tx.\n");
			sma_pins[SMA_UFL1] = PTP_PF_PEROUT;
		} else if (fun == PTP_PF_PEROUT &&
			   sma_pins[SMA_UFL1] != PTP_PF_NONE) {
			dev_warn(ice_hw_to_dev(hw), "SMA1 set to Tx. U.FL1 automatically disabled.\n");
			sma_pins[SMA_UFL1] = PTP_PF_NONE;
		}
		break;
	case SMA_SMA2:
		if (fun == PTP_PF_PEROUT && sma_pins[SMA_UFL2] == PTP_PF_NONE) {
			dev_warn(ice_hw_to_dev(hw), "SMA2 set to Tx. U.FL2 automatically enabled as Rx.\n");
			sma_pins[SMA_UFL2] = PTP_PF_EXTTS;
		} else if (fun == PTP_PF_EXTTS &&
			   sma_pins[SMA_UFL2] != PTP_PF_NONE) {
			dev_warn(ice_hw_to_dev(hw), "SMA2 set to Rx. U.FL2 automatically disabled.\n");
			sma_pins[SMA_UFL2] = PTP_PF_NONE;
		}
		break;
	case SMA_UFL1:
		if (fun == PTP_PF_PEROUT &&
		    sma_pins[SMA_SMA1] != PTP_PF_EXTTS) {
			dev_warn(ice_hw_to_dev(hw), "U.FL1 set to Tx. SMA1 automatically enabled as Rx.\n");
			sma_pins[SMA_SMA1] = PTP_PF_EXTTS;
		}
		break;
	case SMA_UFL2:
		if (fun == PTP_PF_EXTTS &&
		    sma_pins[SMA_SMA2] != PTP_PF_PEROUT) {
			dev_warn(ice_hw_to_dev(hw), "U.FL2 set to Rx. SMA2 automatically enabled as Tx.\n");
			sma_pins[SMA_SMA2] = PTP_PF_PEROUT;
		}
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

/**
 * ice_ptp_set_sma_cfg - set the configuration of the SMA control logic
 * @hw: pointer to HW struct
 *
 * Return: 0 on success, negative error code otherwise.
 */
static int ice_ptp_set_sma_cfg(struct ice_hw *hw)
{
	enum ptp_pin_function *sma_pins = hw->ptp.sma_cfg;
	int err;
	u8 data;

	/* Read initial pin state value */
	err = ice_read_sma_ctrl(hw, &data);
	if (err)
		return err;

	/* Set the right state based on the desired configuration.
	 * When bit is set, functionality is disabled.
	 */
	data &= ~ICE_ALL_SMA_MASK;
	if (!sma_pins[SMA_UFL1]) {
		if (sma_pins[SMA_SMA1] == PTP_PF_EXTTS)
			data |= ICE_SMA1_TX_EN;
		else if (sma_pins[SMA_SMA1] == PTP_PF_PEROUT)
			data |= ICE_SMA1_DIR_EN;
		else
			data |= ICE_SMA1_MASK;
	}

	if (!sma_pins[SMA_UFL2]) {
		if (sma_pins[SMA_SMA2] == PTP_PF_EXTTS)
			data |= ICE_SMA2_TX_EN | ICE_SMA2_UFL2_RX_DIS;
		else if (sma_pins[SMA_SMA2] == PTP_PF_PEROUT)
			data |= ICE_SMA2_DIR_EN | ICE_SMA2_UFL2_RX_DIS;
		else
			data |= ICE_SMA2_MASK;
	} else {
		if (!sma_pins[SMA_SMA2])
			data |= ICE_SMA2_DIR_EN | ICE_SMA2_TX_EN;
		else
			data |= ICE_SMA2_DIR_EN;
	}

	return ice_write_sma_ctrl(hw, data);
}

/**
 * ice_ptp_sma_cfg_store - sysfs interface for setting SMA config
 * @dev: Device that owns the attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 * @pin: Target pin
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t ice_ptp_sma_cfg_store(struct device *dev, const char *buf,
				     size_t len, enum ice_sma_pins pin)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	enum ptp_pin_function fun;
	struct ice_pf *pf;
	int argc, err;
	char **argv;

	pf = pci_get_drvdata(pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EAGAIN;

	if (pf->ptp.state != ICE_PTP_READY)
		return -EFAULT;

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;

	if (argc != 1)
		goto err;

	err = kstrtou32(argv[0], 0, (u32 *)&fun);
	if (err || fun > PTP_PF_PEROUT)
		goto err;

	argv_free(argv);

	err = ice_ptp_verify_sma_cfg(&pf->hw, pin, fun);
	if (err)
		return err;

	pf->hw.ptp.sma_cfg[pin] = fun;
	ice_ptp_set_sma_cfg(&pf->hw);

	return len;

err:
	argv_free(argv);
	return -EIO;
}

/**
 * SMA1_store - sysfs interface for setting SMA1 config
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t SMA1_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	return ice_ptp_sma_cfg_store(dev, buf, len, SMA_SMA1);
}

/**
 * SMA2_store - sysfs interface for setting SMA2 config
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t SMA2_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	return ice_ptp_sma_cfg_store(dev, buf, len, SMA_SMA2);
}

/**
 * UFL1_store - sysfs interface for setting UFL1 config
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t UFL1_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	return ice_ptp_sma_cfg_store(dev, buf, len, SMA_UFL1);
}

/**
 * UFL2_store - sysfs interface for setting UFL2 config
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t UFL2_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	return ice_ptp_sma_cfg_store(dev, buf, len, SMA_UFL2);
}

/**
 * ice_ptp_sma_cfg_show - sysfs callback for reading SMA config file
 * @dev: pointer to dev structure
 * @buf: user buffer to fill with returned data
 * @pin: SMA pin index
 *
 * Collect data and feed the user buffed.
 *
 * Return: total number of bytes written to the buffer.
 */
static ssize_t ice_ptp_sma_cfg_show(struct device *dev, char *buf,
				    enum ice_sma_pins pin)
{
	struct pci_dev *pdev;
	struct ice_pf *pf;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	if (!ice_pf_state_is_nominal(pf))
		return -EAGAIN;

	if (pf->ptp.state != ICE_PTP_READY)
		return -EFAULT;

	return snprintf(buf, PAGE_SIZE, "%i\n", pf->hw.ptp.sma_cfg[pin]);
}

/**
 * SMA1_show - sysfs callback for reading SMA1 file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 *
 * Return: total number of bytes written to the buffer.
 */
static ssize_t SMA1_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	return ice_ptp_sma_cfg_show(dev, buf, SMA_SMA1);
}

/**
 * SMA2_show - sysfs callback for reading SMA2 file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 *
 * Return: total number of bytes written to the buffer.
 */
static ssize_t SMA2_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	return ice_ptp_sma_cfg_show(dev, buf, SMA_SMA2);
}

/**
 * UFL1_show - sysfs callback for reading UFL1 file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 *
 * Return: total number of bytes written to the buffer.
 */
static ssize_t UFL1_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	return ice_ptp_sma_cfg_show(dev, buf, SMA_UFL1);
}

/**
 * UFL2_show - sysfs callback for reading UFL2 file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 *
 * Return: total number of bytes written to the buffer.
 */
static ssize_t UFL2_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	return ice_ptp_sma_cfg_show(dev, buf, SMA_UFL2);
}

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
	ice_dpll_pin_update_lock(pf);
	ret = ice_aq_set_cgu_ref_prio(&pf->hw, dpll, pin, prio);
	ice_dpll_pin_update_unlock(pf, true, ICE_DPLL_PIN_TYPE_INPUT, pin);

	return ret;
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
	u8 output_idx, flags = 0, old_flags, old_src_sel, src_sel = 0;
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
		} else if (!strncmp(argv[i], "source_sel",
				    sizeof("source_sel"))) {
			ret = kstrtou8(argv[++i], 0, &src_sel);
			flags |= ICE_AQC_SET_CGU_OUT_CFG_UPDATE_SRC_SEL;
		} else {
			ret = -EINVAL;
		}

		if (ret)
			return ret;
	}

	ice_dpll_pin_update_lock(pf);
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
			goto unlock;
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
	ret = ice_aq_set_output_pin_cfg(hw, output_idx, flags, src_sel, freq,
					phase_delay);
unlock:
	ice_dpll_pin_update_unlock(pf, true, ICE_DPLL_PIN_TYPE_OUTPUT,
				   output_idx);

	dev_dbg(ice_pf_to_dev(pf),
		"output pin:%u, enable: %u, freq:%u, phase_delay:%u, esync:%u, source_sel:%u, flags:%u ret:%d\n",
		output_idx, pin_en, freq, phase_delay, esync_en, src_sel,
		flags, ret);
	return ret;
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

	ice_dpll_pin_update_lock(pf);
	if (!esync_en_valid || !pin_en_valid) {
		ret = ice_aq_get_input_pin_cfg(hw, input_idx, NULL, NULL,
					       &old_cfg.flags1, &old_cfg.flags2,
					       NULL, NULL);
		if (ret) {
			dev_err(ice_pf_to_dev(pf),
				"Failed to read prev intput pin cfg (%u:%s)",
				ret, ice_aq_str(hw->adminq.sq_last_status));
			goto unlock;
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

	ret = ice_aq_set_input_pin_cfg(&pf->hw, input_idx, flags1, flags2,
				       freq, phase_delay);
unlock:
	ice_dpll_pin_update_unlock(pf, true, ICE_DPLL_PIN_TYPE_INPUT,
				   input_idx);

	dev_dbg(ice_pf_to_dev(pf),
		"input pin:%u, enable: %u, freq:%u, phase_delay:%u, e_ref_sync:%u, flags1:%u, flags2:%u, ret:%d\n",
		input_idx, pin_en, freq, phase_delay, esync_refsync_en, flags1,
		flags2, ret);
	return ret;
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
	enum ice_synce_clk pin;
	struct ice_hw *hw;
	int status;
	u8 divider;

	if (phy_pin >= ICE_SYNCE_CLK_NUM)
		return -EINVAL;

	ptp_port = &pf->ptp.port;
	hw = &pf->hw;
	pin = (enum ice_synce_clk)phy_pin;

	/* configure the mux to deliver proper signal to DPLL from the MUX */
	status = ice_tspll_cfg_bypass_mux_e825c(hw, ptp_port->port_num, pin,
						false, ena);
	if (status)
		return status;

	status = ice_tspll_cfg_synce_ethdiv_e825c(hw, &divider, pin);
	if (status)
		return status;

	dev_dbg(ice_hw_to_dev(&pf->hw),
		"SyncE clock divider set to %u\n", divider);

	dev_info(ice_hw_to_dev(&pf->hw), "CLK_SYNCE%u recovered clock: pin %s\n",
		 pin, !!ena ? "Enabled" : "Disabled");

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

	if (phy_pin >= ICE_E810_RCLK_PINS_NUM)
		return -EINVAL;

	status = ice_aq_set_phy_rec_clk_out(&pf->hw, phy_pin, !!ena, &freq);
	if (status)
		return -EIO;

	if (pf->hw.mac_type == ICE_MAC_E810) {
		status = ice_get_pf_c827_idx(&pf->hw, &phy);
		if (status)
			return -EIO;

		pin = E810T_CGU_INPUT_C827(phy, phy_pin);
		pin_name = ice_cgu_get_pin_name(&pf->hw, pin, true);
	} else {
		/* E82X-based devices have only one PHY available and only one
		 * DPLL RCLK input pin.
		 */
		pin_name = E82X_CGU_RCLK_PIN_NAME;
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
	if (cnt != 2 || ena > 1)
		return -EINVAL;

	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825)
		status = synce_store_e825c(pf, ena, phy_pin);
	else
		status = synce_store_common(pf, ena, phy_pin);
	if (status)
		return status;

	return count;
}

#define PHY0	0
#define PHY1	1

/**
 * ice_ptp_ena_peer_txclk - Enable Tx reference clock on peer phy
 * @pf: pointer to pf structure
 * @clk: new Tx clock
 *
 * Return 0 on success, negative value otherwise.
 */
static int ice_ptp_ena_peer_txclk(struct ice_pf *pf, enum ice_e825c_ref_clk clk)
{
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);
	u8 port_num, phy;
	int err;

	if (clk == ICE_REF_CLK_ENET)
		return 0;

	port_num = pf->ptp.port.port_num;
	phy = port_num / pf->hw.ptp.ports_per_phy;

	if ((clk == ICE_REF_CLK_SYNCE && phy == PHY0 &&
	     !ctrl_pf->ptp.tx_refclks[PHY1][ICE_REF_CLK_SYNCE]) ||
	    (clk == ICE_REF_CLK_EREF0 && phy == PHY1 &&
	     !ctrl_pf->ptp.tx_refclks[PHY0][ICE_REF_CLK_EREF0])) {
		u8 peer_phy = phy ? PHY0 : PHY1;

		err = ice_cpi_ena_dis_clk_ref(&pf->hw, peer_phy, clk, true);
		if (err) {
			dev_err(ice_hw_to_dev(&pf->hw),
				"Failed to enable the %u TX clock for the %u PHY\n",
				clk, peer_phy);
			return err;
		}
	}

	return 0;
}

/**
 * ice_disable_unused_tx_clk - Disable Tx reference clock if unused
 * @pf: pointer to pf structure
 *
 * Returns: 0 on success, negative error otherwise.
 */
static int ice_disable_unused_tx_clk(struct ice_pf *pf)
{
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);
	enum ice_e825c_ref_clk clk;
	struct ice_hw *hw;
	int err = 0;
	u8 phy;

	if (pf->ptp.port.tx_clk == pf->ptp.port.tx_clk_prev)
		return 0;

	hw = &pf->hw;
	clk = pf->ptp.port.tx_clk_prev;
	phy = pf->ptp.port.port_num / hw->ptp.ports_per_phy;

	switch (clk) {
	case ICE_REF_CLK_ENET:
		break;
	case ICE_REF_CLK_SYNCE:
		/* Don't disable SyncE clock if it's still in use on PHY 0 */
		if (ctrl_pf->ptp.tx_refclks[PHY0][clk])
			return 0;

		/* Check if SyncE clock on PHY 1 can be implicitly disabled
		 * as well, as this clock is not used on PHY 0 anymore.
		 */
		if (phy == PHY0 && !ctrl_pf->ptp.tx_refclks[PHY1][clk]) {
			err = ice_cpi_ena_dis_clk_ref(hw, PHY1, clk, false);
			if (err) {
				phy = PHY1;
				goto err;
			}
		}
		break;
	case ICE_REF_CLK_EREF0:
		/* Don't disable EREF0 clock if it's still in use on PHY 1 */
		if (ctrl_pf->ptp.tx_refclks[PHY1][clk])
			return 0;

		/* Check if EREF0 clock on PHY 0 can be implicitly disabled
		 * as well, as this clock is not used on PHY 1 anymore.
		 */
		if (phy == PHY1 && !ctrl_pf->ptp.tx_refclks[PHY0][clk]) {
			err = ice_cpi_ena_dis_clk_ref(hw, PHY0, clk, false);
			if (err) {
				phy = PHY0;
				goto err;
			}
		}
		break;

	default:
		return 0;
	}

	if (!ctrl_pf->ptp.tx_refclks[phy][clk])
		err = ice_cpi_ena_dis_clk_ref(hw, phy, clk, false);
err:
	if (err)
		dev_warn(ice_pf_to_dev(pf), "Failed to disable the %u TX clock for the %u PHY\n",
			 clk, phy);

	return err;
}

#define ICE_REFCLK_USER_TO_AQ_IDX(x) ((x) + 1)

/**
 * ice_ptp_change_tx_clk - Change Tx reference clock
 * @pf: pointer to pf structure
 * @clk: new Tx clock
 *
 * Return 0 on success, negative value otherwise.
 */
static int ice_ptp_change_tx_clk(struct ice_pf *pf, enum ice_e825c_ref_clk clk)
{
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);
	struct ice_port_info *port_info;
	enum ice_e825c_ref_clk old_clk;
	u8 port_num, phy;
	int err;

	old_clk = pf->ptp.port.tx_clk;

	if (old_clk == clk)
		return 0;

	port_num = pf->ptp.port.port_num;
	phy = port_num / pf->hw.ptp.ports_per_phy;
	port_info = pf->hw.port_info;

	/* Check if the TX clk is enabled for this PHY, if not - enable it */
	if (!ctrl_pf->ptp.tx_refclks[phy][clk]) {
		err = ice_cpi_ena_dis_clk_ref(&pf->hw, phy, clk, true);
		if (err) {
			dev_err(ice_hw_to_dev(&pf->hw), "Failed to enable the %u TX clock for the %u PHY\n",
				clk, phy);
			return err;
		}
		err = ice_ptp_ena_peer_txclk(pf, clk);
		if (err)
			return err;
	}

	clear_bit(port_num, &ctrl_pf->ptp.tx_refclks[phy][old_clk]);
	set_bit(port_num, &ctrl_pf->ptp.tx_refclks[phy][clk]);
	pf->ptp.port.tx_clk = clk;

	/* We are ready to switch to the new TX clk. */
	err = pf->hw.lm_ops->restart_an(port_info, true, NULL,
					ICE_REFCLK_USER_TO_AQ_IDX(clk));
	if (err) {
		dev_err(ice_hw_to_dev(&pf->hw), "Failed to switch to %u TX clock for the %u PHY\n",
			clk, phy);
		clear_bit(port_num, &ctrl_pf->ptp.tx_refclks[phy][clk]);
		set_bit(port_num, &ctrl_pf->ptp.tx_refclks[phy][old_clk]);
		err = ice_cpi_ena_dis_clk_ref(&pf->hw, phy, old_clk, true);
		if (err) {
			dev_err(ice_hw_to_dev(&pf->hw), "Failed to restore the %u TX clock for the %u PHY\n",
				old_clk, phy);
			return err;
		}
	}

	pf->ptp.port.tx_clk_prev = old_clk;

	return 0;
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
	enum ice_e825c_ref_clk new_clk;
	struct ice_pf *pf;
	unsigned int clk;
	int err;

	pf = ice_kobj_to_pf(kobj);
	if (!pf)
		return -EPERM;

	if (kstrtouint(buf, 0, &clk))
		return -EINVAL;

	if (clk >= ICE_REF_CLK_MAX)
		return -EINVAL;

	new_clk = (enum ice_e825c_ref_clk)clk;
	if (new_clk == pf->ptp.port.tx_clk) {
		dev_warn(ice_hw_to_dev(&pf->hw), "TX clock already set to %u\n",
			 clk);
		return count;
	}

	err = ice_ptp_change_tx_clk(pf, new_clk);
	if (err) {
		dev_err(ice_hw_to_dev(&pf->hw), "Failed setting TX clock to %u\n",
			clk);
		return -1;
	}

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

	pf = pci_get_drvdata(pdev);
	hw = &pf->hw;

	if (ice_is_reset_in_progress(pf->state))
		return -EAGAIN;

	cnt = sscanf(buf, "%u %u", &ena, &pin);
	if (cnt != 2 || pin >= ICE_SYNCE_CLK_NUM || ena > 1)
		return -EINVAL;

	/* configure the mux to deliver proper signal to DPLL from the MUX */
	status = ice_tspll_cfg_bypass_mux_e825c(hw, 0, (enum ice_synce_clk)pin,
						true, ena);
	if (status)
		return status;

	dev_info(ice_hw_to_dev(&pf->hw), "CLK_SYNCE%u recovered clock: 1588 ref %s\n",
		 pin, !!ena ? "Enabled" : "Disabled");

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
	ice_dpll_pin_update_lock(pf);
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
	ice_dpll_pin_update_unlock(pf, false, ICE_DPLL_PIN_TYPE_OUTPUT, 0);

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
	struct ice_hw *hw = &pf->hw;
	const char *pin_state;
	int count = offset;
	u8 status, flags;
	s32 phase_delay;
	u32 freq;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "in");
	count += scnprintf(buf + count, PAGE_SIZE,
			  "|%4s|%8s|%8s|%11s|%12s|%15s|%11s|%11s|\n",
			   "pin", "enabled", "state", "freq", "phase_delay",
			   "eSync/Ref-sync", "DPLL0 prio", "DPLL1 prio");
	ice_dpll_pin_update_lock(pf);
	for (pin = 0; pin < pin_num; ++pin) {
		int ret = ice_aq_get_input_pin_cfg(hw, pin, &status, NULL,
						   NULL, &flags,
						   &freq, &phase_delay);
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

		esync_refsync_en = FIELD_GET(ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN,
					     flags);
		esync_fail = !!(status &
				ICE_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_FAIL);
		pin_en = !!(flags & ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN);

		if (status & ICE_CGU_IN_PIN_FAIL_FLAGS)
			pin_state = ICE_DPLL_PIN_STATE_INVALID;
		else if (esync_refsync_en == ICE_AQC_GET_CGU_IN_CFG_ESYNC_EN &&
			 esync_fail)
			pin_state = ICE_DPLL_PIN_STATE_INVALID;
		else
			pin_state = ICE_DPLL_PIN_STATE_VALID;

		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%8s|%11u|%12d|%15u|%11u|%11u|\n",
				   pin, pin_en, pin_state, freq,
				   phase_delay, esync_refsync_en, dpll0_prio,
				   dpll1_prio);
	}
	ice_dpll_pin_update_unlock(pf, false, ICE_DPLL_PIN_TYPE_INPUT, 0);

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
 * dpll_ref_sw_show - sysfs interface callback for reading dpll_ref_sw file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Collect data and feed the user buffed.
 * Returns total number of bytes written to the buffer
 */

static ssize_t dpll_ref_sw_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	u8 los, scm, cfm, gst, pfm, esync;
	struct dpll_attribute *dpll_attr;
	int bytes_left = PAGE_SIZE;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	u8 dpll_num;
	int cnt = 0;
	int status;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	dpll_attr = container_of(attr, struct dpll_attribute, attr);
	dpll_num = dpll_attr->dpll_num;

	if (dpll_num >= ICE_CGU_DPLL_MAX)
		return -EINVAL;

	status = ice_get_dpll_ref_sw_status(&pf->hw, dpll_num,
					    &los, &scm, &cfm,
					    &gst, &pfm, &esync);
	if (status)
		return -EINVAL;
	cnt = snprintf(&buf[cnt], bytes_left - cnt, "los %d\n", los);
	cnt += snprintf(&buf[cnt], bytes_left - cnt, "scm %d\n", scm);
	cnt += snprintf(&buf[cnt], bytes_left - cnt, "cfm %d\n", cfm);
	cnt += snprintf(&buf[cnt], bytes_left - cnt, "gst %d\n", gst);
	cnt += snprintf(&buf[cnt], bytes_left - cnt, "pfm %d\n", pfm);
	cnt += snprintf(&buf[cnt], bytes_left - cnt, "esync %d\n", esync);
	return cnt;
}

/**
 * dpll_ref_sw_store - sysfs interface callback for configuration of dpll_ref_sw
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 * @len:   length of the 'buf' string
 *
 * Return number of bytes written on success or negative value on failure.
 */
static ssize_t dpll_ref_sw_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct dpll_attribute *dpll_attr;
	u32 ret, enable_state;
	u8 dpll_num, monitor;
	struct ice_pf *pf;
	char **argv;
	int argc;

	dpll_attr = container_of(attr, struct dpll_attribute, attr);
	dpll_num = dpll_attr->dpll_num;

	if (dpll_num >= ICE_CGU_DPLL_MAX)
		return -EINVAL;
	pf = pci_get_drvdata(pdev);
	if (!ice_pf_state_is_nominal(pf))
		return -EAGAIN;
	if (pf->ptp.state != ICE_PTP_READY)
		return -EFAULT;
	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;
	if (argc != 2)
		return -EIO;
	ret = kstrtou32(argv[1], 0, &enable_state);
	if (ret)
		return -EIO;
	if (enable_state != ICE_DPLL_REF_SW_DISABLE &&
	    enable_state != ICE_DPLL_REF_SW_ENABLE)
		return -EIO;

	if (!strncmp(argv[0], "los", sizeof("los")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_LOS;
	else if (!strncmp(argv[0], "scm", sizeof("scm")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_SCM;
	else if (!strncmp(argv[0], "cfm", sizeof("cfm")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_CFM;
	else if (!strncmp(argv[0], "gst", sizeof("gst")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_GST;
	else if (!strncmp(argv[0], "pfm", sizeof("pfm")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_PFM;
	else if (!strncmp(argv[0], "esync", sizeof("esync")))
		monitor = ICE_AQC_SET_CGU_DPLL_CONFIG_REF_SW_ESYNC;
	else
		return -EIO;
	ice_set_dpll_ref_sw_status(&pf->hw, dpll_num,
				   monitor, enable_state);
	return len;
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
	enum dpll_lock_status *dpll_state;
	struct dpll_attribute *dpll_attr;
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
	enum dpll_lock_status *dpll_state;
	struct dpll_attribute *dpll_attr;
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
	case DPLL_LOCK_STATUS_LOCKED:
	case DPLL_LOCK_STATUS_LOCKED_HO_ACQ:
	case DPLL_LOCK_STATUS_HOLDOVER:
		cnt = snprintf(buf, PAGE_SIZE, "%d\n", pin);
		break;
	default:
		return -EAGAIN;
	}

	return cnt;
}

/**
 * dpll_offset_show - sysfs interface callback for reading dpll_offset file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Returns number of bytes written to the buffer or negative value on error
 */
static ssize_t
dpll_offset_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev;
	struct ice_pf *pf;

	pdev = to_pci_dev(dev);
	pf = pci_get_drvdata(pdev);

	return snprintf(buf, PAGE_SIZE, "%lld\n", pf->ptp_dpll_phase_offset);
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

	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825 &&
	    sysfs_create_file(phy_kobj, &tx_clk_attribute.attr)) {
		dev_warn(ice_pf_to_dev(pf), "Failed to create synce tx_clk file\n");
		kobject_put(phy_kobj);
		return;
	}

	pf->ptp.phy_kobj = phy_kobj;
}

/**
 * ice_pin_cfg_sysfs_init - initialize sysfs for pin_cfg
 * @dev: pointer to pf device structure
 *
 * Initialize sysfs for handling pin configuration in DPLL.
 */
static void ice_pin_cfg_sysfs_init(struct device *dev)
{
	if (device_create_file(dev, &dev_attr_pin_cfg))
		dev_warn(dev, "Failed to create pin_cfg sysfs file\n");
}

/**
 * ice_clock_1588_sysfs_init - initialize sysfs for 1588 SyncE clock source
 * @dev: pointer to pf device structure
 */
static void ice_clock_1588_sysfs_init(struct device *dev)
{
	if (device_create_file(dev, &dev_attr_clock_1588))
		dev_warn(dev, "Failed to create clock_1588 sysfs file\n");
}

/**
 * ice_dpll_attrs_init - initialize sysfs for DPLL attributes
 * @dev: pointer to pf device structure
 *
 * Helper function to allocate and initialize sysfs for DPLL attributes
 */
static void
ice_dpll_attrs_init(struct device *dev)
{
	if (device_create_file(dev, &dev_attr_dpll_0_name.attr))
		dev_warn(dev, "Failed to create dpll_0_name sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_0_state.attr))
		dev_warn(dev, "Failed to create dpll_0_state sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_0_ref_pin.attr))
		dev_warn(dev, "Failed to create dpll_0_ref_pin sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_0_ref_sw.attr))
		dev_warn(dev, "Failed to create dpll_0_ref_sw sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_1_name.attr))
		dev_warn(dev, "Failed to create dpll_1_name sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_1_state.attr))
		dev_warn(dev, "Failed to create dpll_1_state sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_1_ref_pin.attr))
		dev_warn(dev, "Failed to create dpll_1_ref_pin sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_1_offset.attr))
		dev_warn(dev, "Failed to create dpll_1_offset sysfs file\n");
	if (device_create_file(dev, &dev_attr_dpll_1_ref_sw.attr))
		dev_warn(dev, "Failed to create dpll_1_ref_sw sysfs file\n");
}

/**
 * ptp_802_3cx_store - sysfs callback for storing 802.3cx setting
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 * @count: length of the 'buf' string
 *
 * Return: number of bytes written on success or negative value on failure.
 */
static ssize_t ptp_802_3cx_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ice_eth56g_params *params;
	struct ice_pf *pf;
	bool sfd_ena;
	int cnt;

	pf = pci_get_drvdata(pdev);
	if (!pf)
		return -EPERM;

	cnt = kstrtobool(buf, &sfd_ena);
	if (cnt)
		return -EINVAL;

	if (ice_ptp_config_sfd(&pf->hw, sfd_ena))
		return -EAGAIN;

	params = &pf->hw.ptp.phy.eth56g;

	params->sfd_ena = sfd_ena;

	return count;
}

/**
 * ptp_802_3cx_show - sysfs callback for reading 802.3cx setting
 * @dev:   device that owns the attribute
 * @attr:  sysfs device attribute
 * @buf:   string representing configuration
 *
 *  Read the HW settings output to the buf.
 *
 *  Return: number of bytes written to the buffer or negative value on error
 */
static ssize_t ptp_802_3cx_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	const struct ice_eth56g_params *params;
	const struct ice_pf *pf;

	pf = pci_get_drvdata(pdev);
	if (!pf)
		return -EPERM;

	params = &pf->hw.ptp.phy.eth56g;

	return snprintf(buf, PAGE_SIZE, "%u\n", params->sfd_ena);
}

/**
 * ice_ptp_802_3cx_sysfs_init - initialize sysfs for 802.3cx
 * @dev: pointer to pf device structure
 *
 * Initialize sysfs for handling 802.3cx settings
 */
static void ice_ptp_802_3cx_sysfs_init(struct device *dev)
{
	if (device_create_file(dev, &dev_attr_ptp_802_3cx))
		dev_warn(dev, "Failed to create 802.3cx sysfs file\n");
}

/**
 * ice_ptp_sysfs_init - initialize sysfs for ptp and synce features
 * @pf: pointer to pf structure
 *
 * Initialize sysfs for handling configuration of ptp and synce features.
 */
static void ice_ptp_sysfs_init(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825) {
		ice_ptp_802_3cx_sysfs_init(dev);
		ice_clock_1588_sysfs_init(dev);
	}

	if (ice_is_feature_supported(pf, ICE_F_PHY_RCLK))
		ice_phy_sysfs_init(pf);

	if (!ice_pf_src_tmr_owned(pf))
		return;

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		ice_pin_cfg_sysfs_init(dev);
		ice_dpll_attrs_init(dev);
	}

	ice_tspll_sysfs_init(&pf->hw);
	if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
		if (device_create_file(dev, &dev_attr_SMA1) ||
		    device_create_file(dev, &dev_attr_SMA2) ||
		    device_create_file(dev, &dev_attr_UFL1) ||
		    device_create_file(dev, &dev_attr_UFL2))
			dev_warn(dev, "Failed to create SMA sysfs files\n");
	}
}

/**
 * ice_dpll_attrs_release - release sysfs for dpll_attribute
 * @dev: pointer to pf device structure
 */
static void
ice_dpll_attrs_release(struct device *dev)
{
	device_remove_file(dev, &dev_attr_dpll_0_name.attr);
	device_remove_file(dev, &dev_attr_dpll_0_state.attr);
	device_remove_file(dev, &dev_attr_dpll_0_ref_pin.attr);
	device_remove_file(dev, &dev_attr_dpll_0_ref_sw.attr);
	device_remove_file(dev, &dev_attr_dpll_1_name.attr);
	device_remove_file(dev, &dev_attr_dpll_1_state.attr);
	device_remove_file(dev, &dev_attr_dpll_1_ref_pin.attr);
	device_remove_file(dev, &dev_attr_dpll_1_offset.attr);
	device_remove_file(dev, &dev_attr_dpll_1_ref_sw.attr);
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

	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825) {
		device_remove_file(dev, &dev_attr_ptp_802_3cx);
		device_remove_file(dev, &dev_attr_clock_1588);
	}

	if (pf->ptp.phy_kobj) {
		sysfs_remove_file(pf->ptp.phy_kobj, &synce_attribute.attr);
		if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825)
			sysfs_remove_file(pf->ptp.phy_kobj,
					  &tx_clk_attribute.attr);
		kobject_put(pf->ptp.phy_kobj);
		pf->ptp.phy_kobj = NULL;
	}
	if (!ice_pf_src_tmr_owned(pf))
		return;

	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		device_remove_file(dev, &dev_attr_pin_cfg);
		ice_dpll_attrs_release(dev);
	}
	ice_tspll_sysfs_release(&pf->hw);
	if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
		device_remove_file(dev, &dev_attr_SMA1);
		device_remove_file(dev, &dev_attr_SMA2);
		device_remove_file(dev, &dev_attr_UFL1);
		device_remove_file(dev, &dev_attr_UFL2);
	}
}

/**
 * ice_ptp_find_pin_idx - Find pin index in ptp_pin_desc
 * @pf: Board private structure
 * @func: Pin function
 * @chan: GPIO channel
 *
 * Return: positive pin number when pin is present, -1 otherwise
 */
static int ice_ptp_find_pin_idx(struct ice_pf *pf, enum ptp_pin_function func,
				unsigned int chan)
{
	const struct ptp_clock_info *info = &pf->ptp.info;
	int i;

	for (i = 0; i < info->n_pins; i++) {
		if (info->pin_config[i].func == func &&
		    info->pin_config[i].chan == chan)
			return i;
	}

	return -1;
}

/**
 * ice_ptp_is_managed_phy - Check if driver manages PHY
 * @hw: pointer to HW struct
 */
static bool ice_ptp_is_managed_phy(struct ice_hw *hw)
{
	switch (hw->mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_E830:
		return false;
	default:
		return true;
	}
}

/**
 * ice_ptp_state_str - Convert PTP state to readable string
 * @state: PTP state to convert
 *
 * Returns: the human readable string representation of the provided PTP
 * state, used for printing error messages.
 */
static const char *ice_ptp_state_str(enum ice_ptp_state state)
{
	switch (state) {
	case ICE_PTP_UNINIT:
		return "UNINITIALIZED";
	case ICE_PTP_INITIALIZING:
		return "INITIALIZING";
	case ICE_PTP_READY:
		return "READY";
	case ICE_PTP_RESETTING:
		return "RESETTING";
	case ICE_PTP_ERROR:
		return "ERROR";
	}

	return "UNKNOWN";
}

/**
 * ice_is_ptp_supported - Check if PTP is supported by the device
 * @pf: Board private structure
 *
 * Returns: true if PTP is supported by the device and has not entered an
 * error state. False otherwise.
 */
bool ice_is_ptp_supported(struct ice_pf *pf)
{
	enum ice_ptp_state state = pf->ptp.state;

	/* PTP is not supported on this device */
	if (!test_bit(ICE_FLAG_PTP_SUPPORTED, pf->flags))
		return false;

	/* PTP has been initialized and is not in an error state */
	return state != ICE_PTP_UNINIT && state != ICE_PTP_ERROR;
}

/**
 * ice_ptp_cfg_tx_interrupt - Configure Tx timestamp interrupt for the device
 * @pf: Board private structure
 *
 * Program the device to respond appropriately to the Tx timestamp interrupt
 * cause.
 */
static void ice_ptp_cfg_tx_interrupt(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	bool enable;
	u32 val;

	switch (pf->ptp.tx_interrupt_mode) {
	case ICE_PTP_TX_INTERRUPT_ALL:
		/* React to interrupts across all quads. */
		wr32(hw, PFINT_TSYN_MSK, TX_INTR_QUAD_MASK);
		enable = true;
		break;
	case ICE_PTP_TX_INTERRUPT_NONE:
		/* Do not react to interrupts on any quad. */
		wr32(hw, PFINT_TSYN_MSK, 0x0);
		enable = false;
		break;
	case ICE_PTP_TX_INTERRUPT_SELF:
	default:
		enable = pf->ptp.tstamp_config.tx_type == HWTSTAMP_TX_ON;
		break;
	}

	/* Configure the Tx timestamp interrupt */
	val = rd32(hw, PFINT_OICR_ENA);
	if (enable)
		val |= PFINT_OICR_TSYN_TX_M;
	else
		val &= ~PFINT_OICR_TSYN_TX_M;
	wr32(hw, PFINT_OICR_ENA, val);
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
	if (!vsi || !vsi->rx_rings)
		return;

	/* Set the timestamp flag for all the Rx rings */
	ice_for_each_rxq(vsi, i) {
		if (!vsi->rx_rings[i])
			continue;
		vsi->rx_rings[i]->ptp_rx = on;
	}
}

/**
 * ice_ptp_disable_timestamp_mode - Disable current timestamp mode
 * @pf: Board private structure
 *
 * Called during preparation for reset to temporarily disable timestamping on
 * the device. Called during remove to disable timestamping while cleaning up
 * driver resources.
 */
static void ice_ptp_disable_timestamp_mode(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 val;

	val = rd32(hw, PFINT_OICR_ENA);
	val &= ~PFINT_OICR_TSYN_TX_M;
	wr32(hw, PFINT_OICR_ENA, val);

	ice_set_rx_tstamp(pf, false);
}

/**
 * ice_ptp_restore_timestamp_mode - Restore timestamp configuration
 * @pf: Board private structure
 *
 * Called at the end of rebuild to restore timestamp configuration after
 * a device reset.
 */
void ice_ptp_restore_timestamp_mode(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	bool enable_rx;

	ice_ptp_cfg_tx_interrupt(pf);

	enable_rx = pf->ptp.tstamp_config.rx_filter == HWTSTAMP_FILTER_ALL;
	ice_set_rx_tstamp(pf, enable_rx);

	/* Trigger an immediate software interrupt to ensure that timestamps
	 * which occurred during reset are handled now.
	 */
	wr32(hw, PFINT_OICR, PFINT_OICR_TSYN_TX_M);
	ice_flush(hw);
}

/**
 * ice_ptp_read_src_clk_reg - Read the source clock register
 * @pf: Board private structure
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 */
u64 ice_ptp_read_src_clk_reg(struct ice_pf *pf,
			     struct ptp_system_timestamp *sts)
{
	struct ice_hw *hw = &pf->hw;
	u32 hi, lo, lo2;
	u8 tmr_idx;

	if (!ice_is_primary(hw))
		hw = ice_get_primary_hw(pf);

	tmr_idx = ice_get_ptp_src_clock_index(hw);
	spin_lock(&pf->adapter->ptp_gltsyn_time_lock);
	/* Read the system timestamp pre PHC read */
	ptp_read_system_prets(sts);

	if (hw->mac_type == ICE_MAC_E830) {
		u64 clk_time = rd64(hw, E830_GLTSYN_TIME_L(tmr_idx));

		/* Read the system timestamp post PHC read */
		ptp_read_system_postts(sts);
		spin_unlock(&pf->adapter->ptp_gltsyn_time_lock);

		return clk_time;
	}

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

	spin_unlock(&pf->adapter->ptp_gltsyn_time_lock);

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

	ticks = ice_ptp_extend_32b_ts(READ_ONCE(pf->ptp.cached_phc_time),
				      (in_tstamp >> 8) & mask);
	return ice_tspll_ticks2ns(&pf->hw, ticks);
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
	struct ice_e810_params *params;
	struct ice_ptp_port *ptp_port;
	unsigned long flags;
	struct sk_buff *skb;
	struct ice_pf *pf;

	if (!tx->init)
		return;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);
	params = &pf->hw.ptp.phy.e810;

	/* Drop packets which have waited for more than 2 seconds */
	if (time_is_before_jiffies(tx->tstamps[idx].start + 2 * HZ)) {
		/* Count the number of Tx timestamps that timed out */
		pf->ptp.tx_hwtstamp_timeouts++;

		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);

		dev_kfree_skb_any(skb);
		return;
	}

	if (ice_trace_enabled(tx_tstamp_fw_req)) {
		ice_trace(tx_tstamp_fw_req, ice_pf_to_dev(pf), tx,
			  tx->tstamps[idx].skb, idx);
	}

	spin_lock_irqsave(&params->atqbal_wq.lock, flags);

	params->atqbal_flags |= ATQBAL_FLAGS_INTR_IN_PROGRESS;

	/* Write TS index to read to the PF register so the FW can read it */
	wr32(&pf->hw, PF_SB_ATQBAL,
	     ATQBAL_LL_TS_INTR_ENA | FIELD_PREP(ATQBAL_LL_TS_IDX, idx) |
	     ATQBAL_LL_EXEC);
	tx->last_ll_ts_idx_read = idx;

	spin_unlock_irqrestore(&params->atqbal_wq.lock, flags);
}

/**
 * ice_ptp_complete_tx_single_tstamp - Complete Tx timestamp for a port
 * @tx: the PTP Tx timestamp tracker
 */
void ice_ptp_complete_tx_single_tstamp(struct ice_ptp_tx *tx)
{
	struct skb_shared_hwtstamps shhwtstamps = {};
	u8 idx = tx->last_ll_ts_idx_read;
	struct ice_e810_params *params;
	struct ice_ptp_port *ptp_port;
	u64 raw_tstamp, tstamp;
	struct sk_buff *skb;
	unsigned long flags;
	struct device *dev;
	struct ice_pf *pf;
	u32 lo, hi;

	if (!tx->init || tx->last_ll_ts_idx_read < 0)
		return;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);
	dev = ice_pf_to_dev(pf);
	params = &pf->hw.ptp.phy.e810;

	if (ice_trace_enabled(tx_tstamp_fw_done)) {
		ice_trace(tx_tstamp_fw_done, dev, tx, tx->tstamps[idx].skb,
			  idx);
	}

	spin_lock_irqsave(&params->atqbal_wq.lock, flags);

	if (!(params->atqbal_flags & ATQBAL_FLAGS_INTR_IN_PROGRESS))
		dev_dbg(dev, "%s: low latency interrupt request not in progress?\n",
			__func__);

	lo = rd32(&pf->hw, PF_SB_ATQBAL);
	hi = rd32(&pf->hw, PF_SB_ATQBAH);

	/* Wake up threads waiting on low latency interface */
	params->atqbal_flags &= ~ATQBAL_FLAGS_INTR_IN_PROGRESS;

	wake_up_locked(&params->atqbal_wq);

	spin_unlock_irqrestore(&params->atqbal_wq.lock, flags);

	/* When the bit is cleared, the TS is ready in the register */
	if (lo & ATQBAL_LL_EXEC)
		return;

	/* High 8 bit value of the TS is on the bits 16:23 */
	raw_tstamp = FIELD_GET(ATQBAL_LL_TS_HIGH, lo);
	raw_tstamp <<= 32;

	/* Read the low 32 bit value */
	raw_tstamp |= (u64)hi;

	/* Devices using this interface always verify the timestamp differs
	 * relative to the last cached timestamp value.
	 */
	if (raw_tstamp == tx->tstamps[idx].cached_tstamp)
		return;

	tx->tstamps[idx].cached_tstamp = raw_tstamp;
	clear_bit(idx, tx->in_use);
	skb = tx->tstamps[idx].skb;
	tx->tstamps[idx].skb = NULL;

	if (!skb)
		return;

	/* Discard any timestamp value without the valid bit set */
	if (!(raw_tstamp & ICE_PTP_TS_VALID)) {
		if (ice_trace_enabled(tx_tstamp_invalid)) {
			ice_trace(tx_tstamp_invalid, dev, tx, skb, idx);
		}
		dev_kfree_skb_any(skb);
		return;
	}

	/* Extend the timestamp using cached PHC time */
	tstamp = ice_ptp_extend_40b_ts(pf, raw_tstamp);
	if (tstamp) {
		shhwtstamps.hwtstamp = ns_to_ktime(tstamp);
		if (ice_trace_enabled(tx_tstamp_complete)) {
			ice_trace(tx_tstamp_complete, dev, tx, skb, idx);
		}
	}

	skb_tstamp_tx(skb, &shhwtstamps);
	dev_kfree_skb_any(skb);
}

/**
 * ice_ptp_clear_unexpected_tx_ready - Clear Tx ready bitmap after processing
 * @tx: the PTP Tx timestamp tracker
 * @tstamp_ready: the captured Tx timestamp ready bitmap
 *
 * Process the captured Tx timestamp ready bitmap and compare it with the Tx
 * timestamp tracker status. Detect when the hardware indicates we have
 * a valid Tx timestamp but the Tx tracker had no waiting skb. This is an
 * unexpected case but could potentially leave the device in a state where no
 * Tx timestamp interrupts will be generated.
 */
static void
ice_ptp_clear_unexpected_tx_ready(struct ice_ptp_tx *tx, u64 tstamp_ready)
{
	DECLARE_BITMAP(unexpected_tstamp, 64);
	struct ice_ptp_port *ptp_port;
	unsigned long flags;
	struct device *dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u8 phy_idx, idx;

	bitmap_zero(unexpected_tstamp, 64);
	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);
	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;

	/* Find any bit which is *set* in the relevant section of tstamp_ready
	 * but *not set* in the Tx timestamp tracker. This likely means
	 * a driver bug resulted in the Tx timestamp index being used without
	 * the in_use bit being set properly in the tracker.
	 */
	spin_lock_irqsave(&tx->lock, flags);
	for_each_clear_bit(idx, tx->in_use, tx->len) {
		phy_idx = idx + tx->offset;

		if (tstamp_ready & BIT_ULL(phy_idx))
			set_bit(phy_idx, unexpected_tstamp);
	}
	spin_unlock_irqrestore(&tx->lock, flags);

	for_each_set_bit(phy_idx, unexpected_tstamp, 64) {
		u64 raw_tstamp;
		int err;

		dev_warn_ratelimited(dev, "clearing unexpected Tx timestamp ready indication on PHY index %d\n",
				     phy_idx);

		err = ice_read_phy_tstamp(hw, tx->block, phy_idx, &raw_tstamp);
		if (err) {
			dev_warn_ratelimited(dev, "Failed to clear Tx timestamp state for PHY index %d, err %pe",
					     phy_idx, ERR_PTR(err));
		}
	}
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
 * 5) extend the 40 bit timestamp value to get a 64 bit timestamp value
 * 6) send this 64 bit timestamp to the stack
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
 * If a Tx packet has been waiting for more than 2 seconds, it is not possible
 * to correctly extend the timestamp using the cached PHC time. It is
 * extremely unlikely that a packet will ever take this long to timestamp. If
 * we detect a Tx timestamp request that has waited for this long we assume
 * the packet will never be sent by hardware and discard it without reading
 * the timestamp register.
 */
static void ice_ptp_process_tx_tstamp(struct ice_ptp_tx *tx)
{
	struct ice_ptp_port *ptp_port;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u64 tstamp_ready;
	bool link_up;
	int err;
	u8 idx;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);
	hw = &pf->hw;

	/* Read the Tx ready status first */
	if (tx->has_ready_bitmap) {
		err = ice_get_phy_tx_tstamp_ready(hw, tx->block, &tstamp_ready);
		if (err)
			return;

		/* Check and clear any Tx timestamp ready indication for
		 * a slot that is not currently in use.
		 */
		ice_ptp_clear_unexpected_tx_ready(tx, tstamp_ready);
	}

	/* Drop packets if the link went down */
	link_up = ptp_port->link_up;

	for_each_set_bit(idx, tx->in_use, tx->len) {
		struct skb_shared_hwtstamps shhwtstamps = {};
		u8 phy_idx = idx + tx->offset;
		u64 raw_tstamp = 0, tstamp;
		bool drop_ts = !link_up;
		unsigned long flags;
		struct sk_buff *skb;

		/* Drop packets which have waited for more than 2 seconds */
		if (time_is_before_jiffies(tx->tstamps[idx].start + 2 * HZ)) {
			drop_ts = true;

			if (ice_trace_enabled(tx_tstamp_timeout)) {
				spin_lock_irqsave(&tx->lock, flags);
				ice_trace(tx_tstamp_timeout, ice_pf_to_dev(pf),
					  tx, tx->tstamps[idx].skb, idx);
				spin_unlock_irqrestore(&tx->lock, flags);
			}

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
		if (tx->has_ready_bitmap &&
		    !(tstamp_ready & BIT_ULL(phy_idx))) {
			if (drop_ts)
				goto skip_ts_read;

			continue;
		}

		if (ice_trace_enabled(tx_tstamp_fw_req)) {
			spin_lock_irqsave(&tx->lock, flags);
			ice_trace(tx_tstamp_fw_req, ice_pf_to_dev(pf), tx,
				  tx->tstamps[idx].skb, idx);
			spin_unlock_irqrestore(&tx->lock, flags);
		}

		err = ice_read_phy_tstamp(hw, tx->block, phy_idx, &raw_tstamp);
		if (err && !drop_ts)
			continue;

		if (ice_trace_enabled(tx_tstamp_fw_done)) {
			spin_lock_irqsave(&tx->lock, flags);
			ice_trace(tx_tstamp_fw_done, ice_pf_to_dev(pf), tx,
				  tx->tstamps[idx].skb, idx);
			spin_unlock_irqrestore(&tx->lock, flags);
		}

		/* For PHYs which don't implement a proper timestamp ready
		 * bitmap, verify that the timestamp value is different
		 * from the last cached timestamp. If it is not, skip this for
		 * now assuming it hasn't yet been captured by hardware.
		 */
		if (!drop_ts && !tx->has_ready_bitmap &&
		    raw_tstamp == tx->tstamps[idx].cached_tstamp)
			continue;

		/* Discard any timestamp value without the valid bit set */
		if (!(raw_tstamp & ICE_PTP_TS_VALID)) {
			if (ice_trace_enabled(tx_tstamp_invalid)) {
				spin_lock_irqsave(&tx->lock, flags);
				ice_trace(tx_tstamp_invalid, ice_pf_to_dev(pf),
					  tx, tx->tstamps[idx].skb, idx);
				spin_unlock_irqrestore(&tx->lock, flags);
			}
			drop_ts = true;
		}

skip_ts_read:
		spin_lock_irqsave(&tx->lock, flags);
		if (!tx->has_ready_bitmap && raw_tstamp)
			tx->tstamps[idx].cached_tstamp = raw_tstamp;
		clear_bit(idx, tx->in_use);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		spin_unlock_irqrestore(&tx->lock, flags);

		if (!skb)
			continue;

		if (drop_ts) {
			if (ice_trace_enabled(tx_tstamp_dropped)) {
				spin_lock_irqsave(&tx->lock, flags);
				ice_trace(tx_tstamp_dropped, ice_pf_to_dev(pf),
					  tx, skb, idx);
				spin_unlock_irqrestore(&tx->lock, flags);
			}

			dev_kfree_skb_any(skb);
			continue;
		}

		/* Extend the timestamp using cached PHC time */
		tstamp = ice_ptp_extend_40b_ts(pf, raw_tstamp);
		if (tstamp) {
			shhwtstamps.hwtstamp = ns_to_ktime(tstamp);
			if (ice_trace_enabled(tx_tstamp_complete)) {
				spin_lock_irqsave(&tx->lock, flags);
				ice_trace(tx_tstamp_complete,
					  ice_pf_to_dev(pf), tx, skb, idx);
				spin_unlock_irqrestore(&tx->lock, flags);
			}
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
	unsigned long flags;

	if (!tx->init)
		return ICE_TX_TSTAMP_WORK_DONE;

	/* Process the Tx timestamp tracker */
	ice_ptp_process_tx_tstamp(tx);

	/* Check if there are outstanding Tx timestamps */
	spin_lock_irqsave(&tx->lock, flags);
	more_timestamps = !bitmap_empty(tx->in_use, tx->len);
	spin_unlock_irqrestore(&tx->lock, flags);

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

	mutex_lock(&pf->adapter->ports.lock);
	list_for_each_entry(port, &pf->adapter->ports.ports, list_node) {
		struct ice_ptp_tx *tx = &port->tx;

		if (!tx || !tx->init)
			continue;

		ice_ptp_process_tx_tstamp(tx);
	}
	mutex_unlock(&pf->adapter->ports.lock);

	for (i = 0; i < ICE_GET_QUAD_NUM(pf->hw.ptp.num_lports); i++) {
		u64 tstamp_ready;
		int err;

		/* Read the Tx ready status first */
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
	struct ice_tx_tstamp *tstamps;
	unsigned long *in_use;

	tstamps = kcalloc(tx->len, sizeof(*tstamps), GFP_KERNEL);
	in_use = bitmap_zalloc(tx->len, GFP_KERNEL);

	if (!tstamps || !in_use) {
		kfree(tstamps);
		bitmap_free(in_use);

		return -ENOMEM;
	}

	tx->tstamps = tstamps;
	tx->in_use = in_use;
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
		unsigned long flags;
		struct sk_buff *skb;

		/* In case this timestamp is ready, we need to clear it. */
		if (!hw->reset_ongoing && (tstamp_ready & BIT_ULL(phy_idx)))
			ice_clear_phy_tstamp(hw, tx->block, phy_idx);

		spin_lock_irqsave(&tx->lock, flags);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);
		spin_unlock_irqrestore(&tx->lock, flags);

		/* Count the number of Tx timestamps flushed */
		pf->ptp.tx_hwtstamp_flushed++;

		/* Free the SKB after we've cleared the bit */
		dev_kfree_skb_any(skb);
	}
}

/**
 * ice_ptp_flush_all_tx_tracker - Flush all timestamp trackers on this clock
 * @pf: Board private structure
 *
 * Called by the clock owner to flush all the Tx timestamp trackers associated
 * with the clock.
 */
static void
ice_ptp_flush_all_tx_tracker(struct ice_pf *pf)
{
	struct ice_ptp_port *port;

	list_for_each_entry(port, &pf->adapter->ports.ports, list_node)
		ice_ptp_flush_tx_tracker(ptp_port_to_pf(port), &port->tx);
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
	unsigned long flags;

	spin_lock_irqsave(&tx->lock, flags);
	tx->init = 0;
	spin_unlock_irqrestore(&tx->lock, flags);

	/* wait for potentially outstanding interrupt to complete */
	synchronize_irq(pf->oicr_irq.virq);

	ice_ptp_flush_tx_tracker(pf, tx);

	kfree(tx->tstamps);
	tx->tstamps = NULL;

	bitmap_free(tx->in_use);
	tx->in_use = NULL;

	tx->len = 0;
}

/**
 * ice_ptp_init_tx_e82x - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 * @port: the port this structure tracks
 *
 * Initialize the Tx timestamp tracker for this port. For generic MAC devices,
 * the timestamp block is shared for all ports in the same quad. To avoid
 * ports using the same timestamp index, logically break the block of
 * registers into chunks based on the port number.
 *
 * Return: 0 on success, -ENOMEM when out of memory
 */
static int ice_ptp_init_tx_e82x(struct ice_pf *pf, struct ice_ptp_tx *tx,
				u8 port)
{
	tx->block = ICE_GET_QUAD_NUM(port);
	tx->offset = (port % ICE_PORTS_PER_QUAD) * INDEX_PER_PORT_E82X;
	tx->len = INDEX_PER_PORT_E82X;
	tx->has_ready_bitmap = 1;

	return ice_ptp_alloc_tx_tracker(tx);
}

/**
 * ice_ptp_init_tx - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 * @port: the port this structure tracks
 *
 * Initialize the Tx timestamp tracker for this PF. For all PHYs except E82X,
 * each port has its own block of timestamps, independent of the other ports.
 *
 * Return: 0 on success, -ENOMEM when out of memory
 */
static int ice_ptp_init_tx(struct ice_pf *pf, struct ice_ptp_tx *tx, u8 port)
{
	tx->block = port;
	tx->offset = 0;
	tx->len = INDEX_PER_PORT;

	/* The E810 PHY does not provide a timestamp ready bitmap. Instead,
	 * verify new timestamps against cached copy of the last read
	 * timestamp.
	 */
	tx->has_ready_bitmap = pf->hw.mac_type != ICE_MAC_E810;

	return ice_ptp_alloc_tx_tracker(tx);
}

/**
 * ice_ptp_update_cached_phctime - Update the cached PHC time values
 * @pf: Board specific private structure
 * @systime: Cached PHC time to write
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
 * Returns: 0 on success or -EAGAIN when PF was busy and the update needs to be
 * rescheduled
 */
static int ice_ptp_update_cached_phctime(struct ice_pf *pf, u64 systime)
{
	struct device *dev = ice_pf_to_dev(pf);
	unsigned long update_before;
	int i;

	update_before = pf->ptp.cached_phc_jiffies + msecs_to_jiffies(2000);
	if (pf->ptp.cached_phc_time &&
	    time_is_before_jiffies(update_before)) {
		unsigned long time_taken = jiffies - pf->ptp.cached_phc_jiffies;

		dev_warn_once(dev, "%u msecs passed between update to cached PHC time\n",
			      jiffies_to_msecs(time_taken));
		pf->ptp.late_cached_phc_updates++;
	}

	/* Update the cached PHC time stored in the PF structure */
	WRITE_ONCE(pf->ptp.cached_phc_time, systime);
	WRITE_ONCE(pf->ptp.cached_phc_jiffies, jiffies);

	/* Nothing to do if link is down */
	if (!pf->ptp.port.link_up)
		return 0;

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
 * ice_ptp_update_cached_phctime_all - Update the cached PHC time for all ports
 * @pf: Board specific private structure
 *
 * Return:
 * * 0 - OK, successfully updated
 * * -EAGAIN - PF was busy, need to reschedule the update
 */
static int ice_ptp_update_cached_phctime_all(struct ice_pf *pf)
{
	struct ice_ptp_port *port;
	u64 systime;
	int err = 0;

	mutex_lock(&pf->adapter->ports.lock);
	systime = ice_ptp_read_src_clk_reg(pf, NULL);
	list_for_each_entry(port, &pf->adapter->ports.ports, list_node) {
		struct ice_pf *peer_pf = ptp_port_to_pf(port);

		err = ice_ptp_update_cached_phctime(peer_pf, systime);
		if (err)
			break;
	}
	mutex_unlock(&pf->adapter->ports.lock);

	return err;
}

#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
static int ice_ptp_schedule_worker(struct ice_ptp *ptp, unsigned long delay);

#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
/**
 * ice_ptp_reset_cached_phctime - Reset cached PHC time after an update
 * @pf: Board specific private structure
 *
 * This function is called to immediately update the cached PHC time after
 * a .settime or .adjtime call.
 *
 * If updating the PHC time cannot be done immediately, a warning message is
 * logged and the work item is scheduled without delay to minimize the window
 * where a timestamp is extended using the old cached value.
 */
static void ice_ptp_reset_cached_phctime(struct ice_pf *pf)
{
	/* Update the cached PHC time immediately if possible, otherwise
	 * schedule the work item to execute soon.
	 */
	if (ice_ptp_update_cached_phctime_all(pf)) {
		/* Queue the work item to update the Rx rings when possible */
#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
		ice_ptp_schedule_worker(&pf->ptp, msecs_to_jiffies(10));
#else /* HAVE_PTP_CANCEL_WORKER_SYNC */
		ptp_schedule_worker(pf->ptp.clock, msecs_to_jiffies(10));
#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
	}
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
	u64 val;

	val = ice_tspll_ns2ticks(hw, ns);

	return ice_ptp_init_time(hw, val);
}

/**
 * ice_ptp_write_adj - Adjust PHC clock time atomically
 * @pf: Board private structure
 * @adj: Adjustment in nanoseconds
 *
 * Perform an atomic adjustment of the PHC time by the specified number of
 * nanoseconds.
 */
static int
ice_ptp_write_adj(struct ice_pf *pf, s32 adj)
{
	struct ice_hw *hw = &pf->hw;

	if (adj >= 0)
		adj = (s32)ice_tspll_ns2ticks(hw, adj);
	else
		adj = -((s32)ice_tspll_ns2ticks(hw, -adj));

	return ice_ptp_adj_clock(hw, adj);
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
	const struct ice_hw *hw = &pf->hw;
	u64 incval;

	incval = ice_get_base_incval(hw, hw->ptp.src_tmr_mode);

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
	int quad = ICE_GET_QUAD_NUM(port->port_num);
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
		err = ice_read_quad_reg_e82x(hw, quad, Q_REG_FIFO01_STATUS,
					     &val);
	else
		err = ice_read_quad_reg_e82x(hw, quad, Q_REG_FIFO23_STATUS,
					     &val);

	if (err) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to check port %d Tx FIFO, err %d\n",
			port->port_num, err);
		return err;
	}

	if (offs & 0x1)
		phy_sts = FIELD_GET(Q_REG_FIFO13_M, val);
	else
		phy_sts = FIELD_GET(Q_REG_FIFO02_M, val);

	if (phy_sts & FIFO_EMPTY) {
		port->tx_fifo_busy_cnt = FIFO_OK;
		return 0;
	}

	port->tx_fifo_busy_cnt++;

	dev_dbg(ice_pf_to_dev(pf), "Try %d, port %d FIFO not empty\n",
		port->tx_fifo_busy_cnt, port->port_num);

	if (port->tx_fifo_busy_cnt == ICE_PTP_FIFO_NUM_CHECKS) {
		dev_warn(ice_pf_to_dev(pf),
			 "Port %d Tx FIFO still not empty; resetting quad %d\n",
			 port->port_num, quad);
		ice_ptp_reset_ts_memory_quad_e82x(hw, quad);
		port->tx_fifo_busy_cnt = FIFO_OK;
		return 0;
	}

	return -EAGAIN;
}

/**
 * ice_ptp_wait_for_offsets - Check for valid Tx and Rx offsets
 * @work: Pointer to the delayed_work structure for this task
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
static void ice_ptp_wait_for_offsets(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ice_ptp_port *port;
	struct ice_pf *pf;
	int tx_err = 0;
	int rx_err;

	port = container_of(dwork, struct ice_ptp_port, ov_work);
	pf = ptp_port_to_pf(port);

	if (ice_is_reset_in_progress(pf->state))
		goto err;

	if (port->tx.calibrating) {
		tx_err = ice_ptp_check_tx_fifo(port);
		if (!tx_err)
			tx_err = ice_phy_cfg_tx_offset_e82x(&pf->hw,
							    port->port_num);
		if (!tx_err)
			port->tx.calibrating = false;
	}

	if (port->rx_calibrating) {
		rx_err = ice_phy_cfg_rx_offset_e82x(&pf->hw, port->port_num);
		if (!rx_err)
			port->rx_calibrating = false;
	}

	if (!tx_err && !port->rx_calibrating)
		return;
err:
	/* Tx and/or Rx offset not yet configured, try again later */
	queue_delayed_work(system_unbound_wq, &port->ov_work,
			   msecs_to_jiffies(100));
}

/**
 * ice_ptp_port_phy_stop - Stop timestamping for a PHY port
 * @ptp_port: PTP port to stop
 */
static int ice_ptp_port_phy_stop(struct ice_ptp_port *ptp_port)
{
	struct ice_pf *pf = ptp_port_to_pf(ptp_port);
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	int err;

	if (!ice_ptp_is_managed_phy(hw))
		return 0;

	mutex_lock(&ptp_port->ps_lock);

	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
		cancel_delayed_work_sync(&ptp_port->ov_work);

		err = ice_stop_phy_timer_e82x(hw, port, true);
		break;
	case ICE_MAC_GENERIC_3K_E825:
		err = ice_stop_phy_timer_eth56g(hw, port, true);
		break;
	default:
		err = -ENODEV;
	}
	if (err && err != -EBUSY)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d down, err %d\n",
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
	u8 port = ptp_port->port_num;
	struct ice_hw *hw = &pf->hw;
	int err;

	if (!ice_ptp_is_managed_phy(hw))
		return 0;

	if (!ptp_port->link_up)
		return ice_ptp_port_phy_stop(ptp_port);

	mutex_lock(&ptp_port->ps_lock);

	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
		/* Start the PHY timer in Vernier mode */
		cancel_delayed_work_sync(&ptp_port->ov_work);

		/* temporarily disable Tx timestamps while calibrating
		 * PHY offset
		 */
		spin_lock(&ptp_port->tx.lock);
		ptp_port->tx.calibrating = true;
		spin_unlock(&ptp_port->tx.lock);
		ptp_port->tx_fifo_busy_cnt = 0;
		ptp_port->rx_calibrating = true;

		/* Start the PHY timer in Vernier mode */
		err = ice_start_phy_timer_e82x(hw, port);
		if (err)
			break;

		queue_delayed_work(system_unbound_wq, &ptp_port->ov_work, 0);
		break;
	case ICE_MAC_GENERIC_3K_E825:
		err = ice_start_phy_timer_eth56g(hw, port);
		break;
	default:
		err = -ENODEV;
	}

	if (err)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d up, err %d\n",
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
 * @linkup: Link is up or down
 */
void ice_ptp_link_change(struct ice_pf *pf, bool linkup)
{
	struct ice_ptp_port *ptp_port;
	struct ice_hw *hw = &pf->hw;

	if (pf->ptp.state != ICE_PTP_READY)
		return;

	ptp_port = &pf->ptp.port;

	/* Update cached link status for this port immediately */
	ptp_port->link_up = linkup;

	/* Skip HW writes if reset is in progress */
	if (pf->hw.reset_ongoing)
		return;

	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825) {
		int pin, err;

		for (pin = 0; pin < ICE_SYNCE_CLK_NUM; pin++) {
			enum ice_synce_clk clk_pin;
			bool active;
			u8 port_num;
			u8 divider;

			port_num = ptp_port->port_num;
			clk_pin = (enum ice_synce_clk)pin;
			err = ice_tspll_bypass_mux_active_e825c(hw,
								port_num,
								&active,
								clk_pin);
			if (WARN_ON_ONCE(err))
				return;

			err = ice_tspll_cfg_synce_ethdiv_e825c(hw, &divider,
							       clk_pin);
			if (active && WARN_ON_ONCE(err))
				return;
		}

		if (linkup && !ice_disable_unused_tx_clk(pf))
			pf->ptp.port.tx_clk_prev = pf->ptp.port.tx_clk;
	}

	switch (hw->mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_E830:
		/* Do not reconfigure E810 or E830 PHY */
		return;
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		ice_ptp_port_phy_restart(ptp_port);
		return;
	default:
		dev_warn(ice_pf_to_dev(pf), "%s: Unknown PHY type\n", __func__);
	}
}

/**
 * ice_ptp_cfg_phy_interrupt - Configure PHY interrupt settings
 * @pf: PF private structure
 * @ena: bool value to enable or disable interrupt
 * @threshold: Minimum number of packets at which intr is triggered
 *
 * Utility function to configure all the PHY interrupt settings, including
 * whether the PHY interrupt is enabled, and what threshold to use. Also
 * configures The E82X timestamp owner to react to interrupts from all PHYs.
 */
static int ice_ptp_cfg_phy_interrupt(struct ice_pf *pf, bool ena, u32 threshold)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;

	ice_ptp_reset_ts_memory(hw);

	switch (hw->mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_E830:
		return 0;
	case ICE_MAC_GENERIC: {
		int quad;

		for (quad = 0; quad < ICE_GET_QUAD_NUM(hw->ptp.num_lports);
		     quad++) {
			int err;

			err = ice_phy_cfg_intr_e82x(hw, quad, ena,
						    threshold);
			if (err) {
				dev_err(dev, "Failed to configure PHY interrupt for quad %d, err %d\n",
					quad, err);
				return err;
			}
		}

		return 0;
	}
	case ICE_MAC_GENERIC_3K_E825: {
		int port;

		for (port = 0; port < hw->ptp.num_lports; port++) {
			int err;

			err = ice_phy_cfg_intr_eth56g(hw, port, ena,
						      threshold);
			if (err) {
				dev_err(dev, "Failed to configure PHY interrupt for port %d, err %d\n",
					port, err);
				return err;
			}
		}

		return 0;
	}
	case ICE_MAC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
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

	list_for_each(entry, &pf->adapter->ports.ports) {
		struct ice_ptp_port *port = list_entry(entry,
						       struct ice_ptp_port,
						       list_node);

		if (port->link_up)
			ice_ptp_port_phy_restart(port);
	}
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
	u64 incval;
	int err;

	if (hw->ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"adjfreq not supported in locked mode\n");
		return -EPERM;
	}

	incval = adjust_by_scaled_ppm(ice_base_incval(pf), scaled_ppm);
	err = ice_ptp_write_incval_locked(hw, incval);
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

	/* Don't process timestamp events if PTP is not ready */
	if (pf->ptp.state != ICE_PTP_READY)
		return;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	/* Event time is captured by one of the two matched registers
	 *      GLTSYN_EVNT_L: 32 LSB of sampled time event
	 *      GLTSYN_EVNT_H: 32 MSB of sampled time event
	 * Event is defined in GLTSYN_EVNT_0 register
	 */
	for (chan = 0; chan < GLTSYN_EVNT_H_IDX_MAX; chan++) {
		int pin_desc_idx;

		/* Check if channel is enabled */
		if (!(pf->ptp.ext_ts_irq & (1 << chan)))
			continue;

		lo = rd32(hw, GLTSYN_EVNT_L(chan, tmr_idx));
		hi = rd32(hw, GLTSYN_EVNT_H(chan, tmr_idx));
		event.timestamp = (u64)hi << 32 | lo;

		/* Add delay compensation */
		pin_desc_idx = ice_ptp_find_pin_idx(pf, PTP_PF_EXTTS, chan);
		if (pin_desc_idx >= 0) {
			const struct ice_ptp_pin_desc *desc;

			desc = &pf->ptp.ice_pin_desc[pin_desc_idx];
			event.timestamp -= desc->delay[0];
		}

		event.type = PTP_CLOCK_EXTTS;
		event.index = chan;
		pf->ptp.ext_ts_irq &= ~(1 << chan);
		ptp_clock_event(pf->ptp.clock, &event);
	}
}

/**
 * ice_ptp_cfg_extts - Configure EXTTS pin and channel
 * @pf: Board private structure
 * @rq: External timestamp request
 * @on: Enable/disable flag
 *
 * Configure an external timestamp event on the requested channel.
 *
 * Return: 0 on success, negative error code otherwise
 */
static int ice_ptp_cfg_extts(struct ice_pf *pf, struct ptp_extts_request *rq,
			     int on)
{
	u32 aux_reg, gpio_reg, irq_reg;
	struct ice_hw *hw = &pf->hw;
	unsigned int chan, gpio_pin;
	int pin_desc_idx;
	u8 tmr_idx;

	/* Reject requests with unsupported flags */
	if (rq->flags & ~(PTP_ENABLE_FEATURE |
			  PTP_RISING_EDGE |
			  PTP_FALLING_EDGE |
			  PTP_STRICT_FLAGS))
		return -EOPNOTSUPP;

	if (pf->hw.ptp.src_tmr_mode == ICE_SRC_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf), "Locked mode EXTTS not supported\n");
		return -EOPNOTSUPP;
	}

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	chan = rq->index;

	pin_desc_idx = ice_ptp_find_pin_idx(pf, PTP_PF_EXTTS, chan);
	if (pin_desc_idx < 0)
		return -EIO;

	gpio_pin = pf->ptp.ice_pin_desc[pin_desc_idx].gpio[0];
	irq_reg = rd32(hw, PFINT_OICR_ENA);

	if (on) {
		/* Enable the interrupt */
		irq_reg |= PFINT_OICR_TSYN_EVNT_M;
		aux_reg = GLTSYN_AUX_IN_0_INT_ENA_M;

#define GLTSYN_AUX_IN_0_EVNTLVL_RISING_EDGE	BIT(0)
#define GLTSYN_AUX_IN_0_EVNTLVL_FALLING_EDGE	BIT(1)

		/* set event level to requested edge */
		if (rq->flags & PTP_FALLING_EDGE)
			aux_reg |= GLTSYN_AUX_IN_0_EVNTLVL_FALLING_EDGE;
		if (rq->flags & PTP_RISING_EDGE)
			aux_reg |= GLTSYN_AUX_IN_0_EVNTLVL_RISING_EDGE;

		/* Write GPIO CTL reg.
		 * 0x1 is input sampled by EVENT register(channel)
		 * + num_in_channels * tmr_idx
		 */
		gpio_reg = FIELD_PREP(GLGEN_GPIO_CTL_PIN_FUNC_M,
				      ICE_GPIO_CTL_IN(chan, tmr_idx));
	} else {
		bool last_enabled = true;
		uint i;

		/* clear the values we set to reset defaults */
		aux_reg = 0;
		gpio_reg = 0;

		for (i = 0; i < pf->ptp.info.n_ext_ts; i++)
			if ((pf->ptp.extts_rqs[i].flags &
			     PTP_ENABLE_FEATURE) &&
			    i != chan) {
				last_enabled = false;
			}

		if (last_enabled)
			irq_reg &= ~PFINT_OICR_TSYN_EVNT_M;
	}

	wr32(hw, PFINT_OICR_ENA, irq_reg);
	wr32(hw, GLTSYN_AUX_IN(chan, tmr_idx), aux_reg);
	wr32(hw, GLGEN_GPIO_CTL(gpio_pin), gpio_reg);

	return 0;
}

/**
 * ice_ptp_disable_all_extts - Disable all EXTTS channels
 * @pf: Board private structure
 */
static void ice_ptp_disable_all_extts(struct ice_pf *pf)
{
	for (unsigned int i = 0; i < pf->ptp.info.n_ext_ts ; i++)
		if (pf->ptp.extts_rqs[i].flags & PTP_ENABLE_FEATURE)
			ice_ptp_cfg_extts(pf, &pf->ptp.extts_rqs[i],
					  false);

	synchronize_irq(pf->oicr_irq.virq);
}

/**
 * ice_ptp_enable_all_extts - Enable all EXTTS channels
 * @pf: Board private structure
 *
 * Called during reset to restore user configuration.
 */
static void ice_ptp_enable_all_extts(struct ice_pf *pf)
{
	for (unsigned int i = 0; i < pf->ptp.info.n_ext_ts ; i++)
		if (pf->ptp.extts_rqs[i].flags & PTP_ENABLE_FEATURE)
			ice_ptp_cfg_extts(pf, &pf->ptp.extts_rqs[i],
					  true);
}

/**
 * ice_ptp_write_perout - Write periodic wave parameters to HW
 * @hw: pointer to the HW struct
 * @chan: target channel
 * @gpio_pin: target GPIO pin
 * @start: target time to start periodic output
 * @period: target period
 *
 * Return: 0 on success, negative error code otherwise
 */
static int ice_ptp_write_perout(struct ice_hw *hw, unsigned int chan,
				unsigned int gpio_pin, u64 start, u64 period)
{
	u8 tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	u32 val = 0;
	int err;

	/* 0. Reset mode & out_en in AUX_OUT */
	wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), 0);

	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825) {
		/* 0.1 Enable/disable CGU 1PPS output with max amplitude */
		err = ice_tspll_ena_pps_out_e825c(hw, !!period);
		if (err)
			return err;
	}

	/* 1. Write perout with half of required period value.
	 * HW toggles output when source clock hits the TGT and then adds
	 * GLTSYN_CLKO value to the target, so it ends up with 50% duty cycle.
	 */
	period = ice_tspll_ns2ticks(hw, period);
	period >>= 1;

	/* For proper operation, GLTSYN_CLKO must be larger than clock tick and
	 * period has to fit in 32 bit register.
	 */
#define MIN_PULSE 3
	if (!!period && (period <= MIN_PULSE || period > U32_MAX)) {
		dev_err(ice_hw_to_dev(hw), "CLK period ticks must be >= %d && <= 2^32",
			MIN_PULSE);
		return -EIO;
	}

	wr32(hw, GLTSYN_CLKO(chan, tmr_idx), lower_32_bits(period));

	/* 2. Write TARGET time */
	start = ice_tspll_ns2ticks(hw, start);
	wr32(hw, GLTSYN_TGT_L(chan, tmr_idx), lower_32_bits(start));
	wr32(hw, GLTSYN_TGT_H(chan, tmr_idx), upper_32_bits(start));

	/* 3. Write AUX_OUT register */
	if (!!period)
		val = GLTSYN_AUX_OUT_0_OUT_ENA_M | GLTSYN_AUX_OUT_0_OUTMOD_M;
	wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), val);

	/* 4. Write GPIO CTL reg.
	 * Enable TRI_CTL to improve SDPs rising time. This does not affect
	 * other pins.
	 */
	val = GLGEN_GPIO_CTL_PIN_DIR_M | GLGEN_GPIO_CTL_TRI_CTL_M;
	if (!!period)
		val |= FIELD_PREP(GLGEN_GPIO_CTL_PIN_FUNC_M,
				  ICE_GPIO_CTL_OUT(chan, tmr_idx));

	wr32(hw, GLGEN_GPIO_CTL(gpio_pin), val);
	ice_flush(hw);

	return 0;
}

/**
 * ice_ptp_cfg_perout - Configure clock to generate periodic wave
 * @pf: Board private structure
 * @rq: Periodic output request
 * @on: Enable/disable flag
 *
 * Configure the internal clock generator modules to generate the clock wave of
 * specified period.
 *
 * Return: 0 on success, negative error code otherwise
 */
static int ice_ptp_cfg_perout(struct ice_pf *pf, struct ptp_perout_request *rq,
			      int on)
{
	unsigned int gpio_pin, prop_delay_ns;
	u64 clk, period, start, phase;
	struct ice_hw *hw = &pf->hw;
	int pin_desc_idx;

	if (rq->flags & ~PTP_PEROUT_PHASE)
		return -EOPNOTSUPP;

	pin_desc_idx = ice_ptp_find_pin_idx(pf, PTP_PF_PEROUT, rq->index);
	if (pin_desc_idx < 0)
		return -EIO;

	gpio_pin = pf->ptp.ice_pin_desc[pin_desc_idx].gpio[1];
	prop_delay_ns = pf->ptp.ice_pin_desc[pin_desc_idx].delay[1];
	period = rq->period.sec * NSEC_PER_SEC + rq->period.nsec;

	/* If we're disabling the output or period is 0, clear out CLKO and TGT
	 * and keep output level low.
	 */
	if (!on || !period)
		return ice_ptp_write_perout(hw, rq->index, gpio_pin, 0, 0);

	if (strncmp(pf->ptp.pin_desc[pin_desc_idx].name, "1PPS", 64) == 0 &&
	    period != NSEC_PER_SEC && hw->mac_type == ICE_MAC_GENERIC) {
		dev_err(ice_pf_to_dev(pf), "1PPS pin supports only 1 s period\n");
		return -EOPNOTSUPP;
	}

	if (period > U32_MAX) {
		dev_err(ice_pf_to_dev(pf), "CLK Period larger than 2^32 nanoseconds is not supported\n");
		return -EINVAL;
	}

	if (period & 0x1) {
		dev_err(ice_pf_to_dev(pf), "CLK Period must be an even value\n");
		return -EIO;
	}

	start = rq->start.sec * NSEC_PER_SEC + rq->start.nsec;

	/* If PTP_PEROUT_PHASE is set, rq has phase instead of start time */
	if (rq->flags & PTP_PEROUT_PHASE)
		phase = start;
	else
		div64_u64_rem(start, period, &phase);

	/* If we have only phase or start time is in the past, start the timer
	 * at the next multiple of period, maintaining phase at least 0.5 second
	 * from now, so we have time to write it to HW.
	 */
	clk = ice_ptp_read_src_clk_reg(pf, NULL) + NSEC_PER_MSEC * 500;
	clk = ice_tspll_ticks2ns(hw, clk);
	if (rq->flags & PTP_PEROUT_PHASE || start <= clk - prop_delay_ns)
		start = roundup_u64(clk, period) + phase;

	/* Compensate for propagation delay from the generator to the pin. */
	start -= prop_delay_ns;

	return ice_ptp_write_perout(hw, rq->index, gpio_pin, start, period);
}

/**
 * ice_ptp_disable_all_perout - Disable all currently configured outputs
 * @pf: Board private structure
 *
 * Disable all currently configured clock outputs. This is necessary before
 * certain changes to the PTP hardware clock. Use ice_ptp_enable_all_perout to
 * re-enable the clocks again.
 */
static void ice_ptp_disable_all_perout(struct ice_pf *pf)
{
	for (unsigned int i = 0; i < pf->ptp.info.n_per_out; i++)
		if (pf->ptp.perout_rqs[i].period.sec ||
		    pf->ptp.perout_rqs[i].period.nsec)
			ice_ptp_cfg_perout(pf, &pf->ptp.perout_rqs[i],
					   false);
}

/**
 * ice_ptp_enable_all_perout - Enable all configured periodic clock outputs
 * @pf: Board private structure
 *
 * Enable all currently configured clock outputs. Use this after
 * ice_ptp_disable_all_perout to reconfigure the output signals according to
 * their configuration.
 */
static void ice_ptp_enable_all_perout(struct ice_pf *pf)
{
	for (unsigned int i = 0; i < pf->ptp.info.n_per_out; i++)
		if (pf->ptp.perout_rqs[i].period.sec ||
		    pf->ptp.perout_rqs[i].period.nsec)
			ice_ptp_cfg_perout(pf, &pf->ptp.perout_rqs[i],
					   true);
}

/**
 * ice_ptp_update_incval - Update clock increment rate
 * @pf: Board private structure
 * @tspll_freq: TIME_REF frequency to use
 * @src_tmr_mode: Src timer mode (nanoseconds or locked)
 */
int ice_ptp_update_incval(struct ice_pf *pf,
			  enum ice_tspll_freq tspll_freq,
			  enum ice_src_tmr_mode src_tmr_mode)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct timespec64 ts;
	int err;

	if (pf->ptp.state != ICE_PTP_READY) {
		dev_err(dev, "PTP is currently in %s state, failed to update incval\n",
			ice_ptp_state_str(pf->ptp.state));
		return -EINVAL;
	}

	ice_ptp_disable_all_perout(pf);

	if (!ice_ptp_lock(hw))
		return -EBUSY;

	err = ice_ptp_write_incval(hw, ice_get_base_incval(hw, src_tmr_mode));
	if (err) {
		dev_err(dev, "PTP failed to update incval, status %d\n", err);
		goto err_unlock;
	}

	ts = ktime_to_timespec64(ktime_get_real());
	err = ice_ptp_write_init(pf, &ts);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "PTP failed to program time registers");
		goto err_unlock;
	}

	/* unlock PTP semaphore first before resetting PHY timestamping */
	ice_ptp_unlock(hw);

	ice_ptp_enable_all_perout(pf);
	ice_ptp_reset_ts_memory(hw);
	ice_ptp_restart_all_phy(pf);

	return 0;

err_unlock:
	ice_ptp_unlock(hw);

	return err;
}

/**
 * ice_verify_pin - verify if pin supports requested pin function
 * @info: the driver's PTP info structure
 * @pin: Pin index
 * @func: Assigned function
 * @chan: Assigned channel
 *
 * Return: 0 on success, -EOPNOTSUPP when function is not supported.
 */
static int ice_verify_pin(struct ptp_clock_info *info, unsigned int pin,
			  enum ptp_pin_function func, unsigned int chan)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	const struct ice_ptp_pin_desc *pin_desc;

	pin_desc = &pf->ptp.ice_pin_desc[pin];

	/* Is assigned function allowed? */
	switch (func) {
	case PTP_PF_EXTTS:
		if (pin_desc->gpio[0] < 0)
			return -EOPNOTSUPP;
		break;
	case PTP_PF_PEROUT:
		if (pin_desc->gpio[1] < 0)
			return -EOPNOTSUPP;
		break;
	case PTP_PF_NONE:
		break;
	case PTP_PF_PHYSYNC:
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * ice_ptp_gpio_enable - Enable/disable ancillary features of PHC
 * @info: The driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 *
 * Return: 0 on success, negative error code otherwise
 */
static int ice_ptp_gpio_enable(struct ptp_clock_info *info,
			       struct ptp_clock_request *rq, int on)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	int err;

	switch (rq->type) {
	case PTP_CLK_REQ_PEROUT:
	{
		struct ptp_perout_request *cached =
			&pf->ptp.perout_rqs[rq->perout.index];

		err = ice_ptp_cfg_perout(pf, &rq->perout, on);
		if (!err) {
			*cached = rq->perout;
		} else {
			cached->period.sec = 0;
			cached->period.nsec = 0;
		}
		return err;
	}
	case PTP_CLK_REQ_EXTTS:
	{
		struct ptp_extts_request *cached =
			&pf->ptp.extts_rqs[rq->extts.index];

		err = ice_ptp_cfg_extts(pf, &rq->extts, on);
		if (!err)
			*cached = rq->extts;
		else
			cached->flags &= ~PTP_ENABLE_FEATURE;
		return err;
	}
	default:
		return -EOPNOTSUPP;
	}
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

	time_ns = ice_tspll_ticks2ns(&pf->hw,
				     ice_ptp_read_src_clk_reg(pf, sts));

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
	int err;

	/* For Vernier mode on E82X, we need to recalibrate after new settime.
	 * Start with marking timestamps as invalid.
	 */
	if (hw->mac_type == ICE_MAC_GENERIC) {
		err = ice_ptp_clear_phy_offset_ready_e82x(hw);
		if (err)
			dev_warn(ice_pf_to_dev(pf), "Failed to mark timestamps as invalid before settime\n");
	}

	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		goto exit;
	}

	/* Disable periodic outputs */
	ice_ptp_disable_all_perout(pf);

	err = ice_ptp_write_init(pf, &ts64);

	/* Reenable periodic outputs */
	ice_ptp_enable_all_perout(pf);
	ice_ptp_unlock(hw);

	if (!err)
		ice_ptp_reset_cached_phctime(pf);

	/* Recalibrate and re-enable timestamp block */
	if (hw->mac_type == ICE_MAC_GENERIC)
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
 * ice_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	s64 delta_ns = delta;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	if (delta >= 0)
		delta = ice_tspll_ns2ticks(hw, delta);
	else
		delta = -ice_tspll_ns2ticks(hw, -delta);

	/* Hardware only supports atomic adjustments using signed 32-bit
	 * integers. For any adjustment outside this range, perform
	 * a non-atomic get->adjust->set flow.
	 */
	if (delta > S32_MAX || delta < S32_MIN) {
		dev_dbg(dev, "delta = %lld, adjtime non-atomic\n", delta);
		return ice_ptp_adjtime_nonatomic(info, delta_ns);
	}

	if (!ice_ptp_lock(hw)) {
		dev_err(dev, "PTP failed to acquire semaphore in adjtime\n");
		return -EBUSY;
	}

	/* Disable periodic outputs */
	ice_ptp_disable_all_perout(pf);

	err = ice_ptp_write_adj(pf, delta);

	/* Reenable periodic outputs */
	ice_ptp_enable_all_perout(pf);

	ice_ptp_unlock(hw);

	if (err) {
		ice_dev_err_errno(dev, err, "PTP failed to adjust time");
		return err;
	}

	ice_ptp_reset_cached_phctime(pf);

	return 0;
}

#if defined(CONFIG_X86)
/**
 * ice_ptp_get_phc_and_tsc - get PHC and TSC time
 * @hw: Pointer to HW structure
 * @phc: PHC time
 * @tsc: TSC time
 */
static void ice_ptp_get_phc_and_tsc(struct ice_hw *hw, u64 *phc, u64 *tsc)
{
	u8 tmr_idx = ice_get_ptp_src_clock_index(hw);
	u32 hi, lo, lo2;

	prefetch(tsc);
	smp_rmb();
	*tsc = rdtsc();
	lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));
	hi = rd32(hw, GLTSYN_TIME_H(tmr_idx));
	lo2 = rd32(hw, GLTSYN_TIME_L(tmr_idx));

	if (lo2 < lo) {
		smp_rmb();
		*tsc = rdtsc();
		lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));
		hi = rd32(hw, GLTSYN_TIME_H(tmr_idx));
	}

	*phc = (u64)hi << 32 | lo;
}

/**
 * ice_ptp_get_sw_cross_tstamp - get SW cross timestamp
 * @pf: Board private structure
 * @sw_cts: Software cross timestamp data
 */
int ice_ptp_get_sw_cross_tstamp(struct ice_pf *pf,
				struct virtchnl_sw_cross_timestamp *sw_cts)
{
	struct ice_hw *hw = &pf->hw;

	if (!ice_ptp_lock(hw))
		return -EBUSY;
	ice_ptp_get_phc_and_tsc(hw, &sw_cts->time, &sw_cts->aux_time);
	ice_ptp_unlock(hw);
	return 0;
}

/**
 * ice_ptp_get_phc_freq_ratio - get PHC to TSC freq ratio
 * @pf: Board private structure
 * @ratio: PHC to TSC ratio data
 */
int ice_ptp_get_phc_freq_ratio(struct ice_pf *pf,
			       struct virtchnl_phc_freq_ratio *ratio)
{
	u64 prev_phc_time, prev_cpu_time;
	struct ice_hw *hw = &pf->hw;
	unsigned int i;

#define PHC_FREQ_RATIO_ITER		128
#define	PHC_FREQ_RATIO_SCALE_BITS	32

	if (!ice_ptp_lock(hw))
		return -EBUSY;
	ice_ptp_get_phc_and_tsc(hw, &ratio->phc_time, &ratio->cpu_time);
	prev_phc_time = ratio->phc_time;
	prev_cpu_time = ratio->cpu_time;

	for (i = 0; i < PHC_FREQ_RATIO_ITER; i++) {
		u64 cpu_diff, phc_diff;

		ice_ptp_get_phc_and_tsc(hw, &ratio->phc_time, &ratio->cpu_time);

		phc_diff = ratio->phc_time - prev_phc_time;
		cpu_diff = ratio->cpu_time - prev_cpu_time;
		prev_phc_time = ratio->phc_time;
		prev_cpu_time = ratio->cpu_time;

		ratio->scaled_ratio += phc_diff << PHC_FREQ_RATIO_SCALE_BITS /
				       cpu_diff;
	}
	ice_ptp_unlock(hw);
	return 0;
}

#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
#ifdef HAVE_PTP_CROSSTIMESTAMP
#ifdef CONFIG_X86
/**
 * struct ice_crosststamp_cfg - Device cross timestamp configuration
 * @lock_reg: The hardware semaphore lock to use
 * @lock_busy: Bit in the semaphore lock indicating the lock is busy
 * @ctl_reg: The hardware register to request cross timestamp
 * @ctl_active: Bit in the control register to request cross timestamp
 * @ctl_timeout: Bits in the control register to indicate HW timeout
 * @art_time_l: Lower 32-bits of ART system time
 * @art_time_h: Upper 32-bits of ART system time
 * @dev_time_l: Lower 32-bits of device time (per timer index)
 * @dev_time_h: Upper 32-bits of device time (per timer index)
 */
struct ice_crosststamp_cfg {
	/* HW semaphore lock register */
	u32 lock_reg;
	u32 lock_busy;

	/* Capture control register */
	u32 ctl_reg;
	u32 ctl_active;
	u32 ctl_timeout;

	/* Time storage */
	u32 art_time_l;
	u32 art_time_h;
	u32 dev_time_l[2];
	u32 dev_time_h[2];
};

static const struct ice_crosststamp_cfg ice_crosststamp_cfg_e82x = {
	.lock_reg = PFHH_SEM,
	.lock_busy = PFHH_SEM_BUSY_M,
	.ctl_reg = GLHH_ART_CTL,
	.ctl_active = GLHH_ART_CTL_ACTIVE_M,
	.ctl_timeout = GLHH_ART_CTL_TIME_OUT1_M | GLHH_ART_CTL_TIME_OUT2_M,
	.art_time_l = GLHH_ART_TIME_L,
	.art_time_h = GLHH_ART_TIME_H,
	.dev_time_l[0] = GLTSYN_HHTIME_L(0),
	.dev_time_h[0] = GLTSYN_HHTIME_H(0),
	.dev_time_l[1] = GLTSYN_HHTIME_L(1),
	.dev_time_h[1] = GLTSYN_HHTIME_H(1),
};

static const struct ice_crosststamp_cfg ice_crosststamp_cfg_e830 = {
	.lock_reg = E830_PFPTM_SEM,
	.lock_busy = E830_PFPTM_SEM_BUSY_M,
	.ctl_reg = E830_GLPTM_ART_CTL,
	.ctl_active = E830_GLPTM_ART_CTL_ACTIVE_M,
	.ctl_timeout = E830_GLPTM_ART_CTL_TIME_OUT_M,
	.art_time_l = E830_GLPTM_ART_TIME_L,
	.art_time_h = E830_GLPTM_ART_TIME_H,
	.dev_time_l[0] = E830_GLTSYN_PTMTIME_L(0),
	.dev_time_h[0] = E830_GLTSYN_PTMTIME_H(0),
	.dev_time_l[1] = E830_GLTSYN_PTMTIME_L(1),
	.dev_time_h[1] = E830_GLTSYN_PTMTIME_H(1),
};

/**
 * struct ice_crosststamp_ctx - Device cross timestamp context
 * @snapshot: snapshot of system clocks for historic interpolation
 * @pf: pointer to the PF private structure
 * @cfg: pointer to hardware configuration for cross timestamp
 */
struct ice_crosststamp_ctx {
	struct system_time_snapshot snapshot;
	struct ice_pf *pf;
	const struct ice_crosststamp_cfg *cfg;
};

/**
 * ice_capture_crosststamp - Capture a device/system cross timestamp
 * @device: Current device time
 * @system: System counter value read synchronously with device time
 * @__ctx: Context passed from ice_ptp_getcrosststamp
 *
 * Read device and system (ART) clock simultaneously and return the corrected
 * clock values in ns.
 *
 * Return: zero on success, or a negative error code on failure.
 */
static int ice_capture_crosststamp(ktime_t *device,
				   struct system_counterval_t *system,
				   void *__ctx)
{
	struct ice_crosststamp_ctx *ctx = __ctx;
	const struct ice_crosststamp_cfg *cfg;
	u32 lock, ctl, ts_lo, ts_hi, tmr_idx;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int err;
	u64 ts;

	cfg = ctx->cfg;
	pf = ctx->pf;
	hw = &pf->hw;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (tmr_idx > 1)
		return -EINVAL;

	/* Poll until we obtain the cross-timestamp hardware semaphore */
	err = rd32_poll_timeout(hw, cfg->lock_reg, lock,
				!(lock & cfg->lock_busy),
				10 * USEC_PER_MSEC, 50 * USEC_PER_MSEC);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to get cross timestamp lock\n");
		return -EBUSY;
	}

	/* Snapshot system time for historic interpolation */
	ktime_get_snapshot(&ctx->snapshot);

	/* Program cmd to master timer */
	ice_ptp_src_cmd(hw, ICE_PTP_READ_TIME);

	/* Start the ART and device clock sync sequence */
	ctl = rd32(hw, cfg->ctl_reg);
	ctl |= cfg->ctl_active;
	wr32(hw, cfg->ctl_reg, ctl);

	/* Poll until hardware completes the capture or timeout occurs */
	err = rd32_poll_timeout(hw, cfg->ctl_reg, ctl,
				!(ctl & cfg->ctl_active) ||
				(ctl & cfg->ctl_timeout),
				5, 20 * USEC_PER_MSEC);
	if (ctl & cfg->ctl_timeout)
		err = -ETIMEDOUT;
	if (err)
		goto err_timeout;

	/* Read ART system time */
	ts_lo = rd32(hw, cfg->art_time_l);
	ts_hi = rd32(hw, cfg->art_time_h);
	ts = ((u64)ts_hi << 32) | ts_lo;
#ifdef HAVE_PTP_CSID_X86_ART
	system->cycles = ts;
	system->cs_id = CSID_X86_ART;
	system->use_nsecs = true;
#else /* !HAVE_PTP_CSID_X86_ART */
	*system = convert_art_ns_to_tsc(ts);
#endif /* HAVE_PTP_CSID_X86_ART */

	/* Read Device source clock time */
	ts_lo = rd32(hw, cfg->dev_time_l[tmr_idx]);
	ts_hi = rd32(hw, cfg->dev_time_h[tmr_idx]);
	ts = ice_tspll_ticks2ns(hw, (((u64)ts_hi << 32) | ts_lo));
	*device = ns_to_ktime(ts);

err_timeout:
	/* Clear the master timer */
	ice_ptp_src_cmd(hw, ICE_PTP_NOP);

	/* Release HW lock */
	lock = rd32(hw, cfg->lock_reg);
	lock &= ~cfg->lock_busy;
	wr32(hw, cfg->lock_reg, lock);

	return err;
}

/**
 * ice_ptp_getcrosststamp - Capture a device cross timestamp
 * @info: the driver's PTP info structure
 * @cts: The memory to fill the cross timestamp info
 *
 * Capture a cross timestamp between the ART and the device PTP hardware
 * clock. Fill the cross timestamp information and report it back to the
 * caller.
 *
 * In order to correctly correlate the ART timestamp back to the TSC time, the
 * CPU must have X86_FEATURE_TSC_KNOWN_FREQ.
 *
 * Return: zero on success, or a negative error code on failure.
 */
static int ice_ptp_getcrosststamp(struct ptp_clock_info *info,
				  struct system_device_crosststamp *cts)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_crosststamp_ctx ctx = {
		.pf = pf
	};

	switch (pf->hw.mac_type) {
	case ICE_MAC_E830:
		ctx.cfg = &ice_crosststamp_cfg_e830;
		break;
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		ctx.cfg = &ice_crosststamp_cfg_e82x;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return get_device_system_crosststamp(ice_capture_crosststamp, &ctx,
					     &ctx.snapshot, cts);
}
#endif /* CONFIG_X86 */
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

	if (pf->ptp.state != ICE_PTP_READY)
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
		pf->ptp.tstamp_config.tx_type = HWTSTAMP_TX_OFF;
		break;
	case HWTSTAMP_TX_ON:
		pf->ptp.tstamp_config.tx_type = HWTSTAMP_TX_ON;
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		pf->ptp.tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
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
		pf->ptp.tstamp_config.rx_filter = HWTSTAMP_FILTER_ALL;
		break;
	default:
		return -ERANGE;
	}

	/* Immediately update the device timestamping mode */
	ice_ptp_restore_timestamp_mode(pf);

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

	if (pf->ptp.state != ICE_PTP_READY)
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
	struct ice_hw *hw = &((struct ice_pf *)rx_ring->vsi->back)->hw;
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
	ts_ns = ice_tspll_ticks2ns(hw, ts_ns);

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ts_ns);
}

/**
 * ice_ptp_setup_pin_cfg - setup PTP pin_config structure
 * @pf: Board private structure
 */
static void ice_ptp_setup_pin_cfg(struct ice_pf *pf)
{
	for (unsigned int i = 0; i < pf->ptp.info.n_pins; i++) {
		const struct ice_ptp_pin_desc *desc = &pf->ptp.ice_pin_desc[i];
		struct ptp_pin_desc *pin = &pf->ptp.pin_desc[i];
		const char *name = NULL;

		if (!ice_is_feature_supported(pf, ICE_F_SMA_CTRL))
			name = ice_pin_names[desc->name_idx];
		else
			name = ice_pin_names_dpll[desc->name_idx];
		if (name)
			strscpy(pin->name, name, sizeof(pin->name));

		pin->index = i;
	}

	pf->ptp.info.pin_config = pf->ptp.pin_desc;
}

/**
 * ice_ptp_disable_pins - Disable PTP pins
 * @pf: pointer to the PF structure
 */
static void ice_ptp_disable_pins(struct ice_pf *pf)
{
	struct ptp_clock_info *info = &pf->ptp.info;

	dev_warn(ice_pf_to_dev(pf), "Failed to configure PTP pin control\n");

	info->enable = NULL;
	info->verify = NULL;
	info->n_pins = 0;
	info->n_ext_ts = 0;
	info->n_per_out = 0;
}

/**
 * ice_ptp_parse_sdp_entries - update ice_ptp_pin_desc structure from NVM
 * @pf: pointer to the PF structure
 * @entries: SDP connection section from NVM
 * @num_entries: number of valid entries in sdp_entries
 * @pins: PTP pins array to update
 *
 * Return: 0 on success, negative error code otherwise.
 */
static int ice_ptp_parse_sdp_entries(struct ice_pf *pf, __le16 *entries,
				     unsigned int num_entries,
				     struct ice_ptp_pin_desc *pins)
{
	unsigned int n_pins = 0;
	unsigned int i;

	/* Setup ice_pin_desc array */
	for (i = 0; i < ICE_N_PINS_MAX; i++) {
		pins[i].name_idx = -1;
		pins[i].gpio[0] = -1;
		pins[i].gpio[1] = -1;
	}

	for (i = 0; i < num_entries; i++) {
		u16 entry = le16_to_cpu(entries[i]);
		DECLARE_BITMAP(bitmap, GPIO_NA);
		unsigned int idx;
		bool dir;
		u16 gpio;

		*bitmap = FIELD_GET(ICE_AQC_NVM_SDP_AC_PIN_M, entry);

		/* Check if entry's pin bitmap is valid. */
		if (bitmap_empty(bitmap, GPIO_NA))
			continue;

		dir = !!FIELD_GET(ICE_AQC_NVM_SDP_AC_DIR_M, entry);
		gpio = FIELD_GET(ICE_AQC_NVM_SDP_AC_SDP_NUM_M, entry);

		for (idx = 0; idx < ICE_N_PINS_MAX; idx++) {
			if (pins[idx].name_idx == gpio)
				break;
		}

		if (idx == ICE_N_PINS_MAX) {
			/* Pin not found, setup its entry and name */
			idx = n_pins++;
			pins[idx].name_idx = gpio;
		}
		pins[idx].gpio[dir] = gpio;
	}

	for (i = 0; i < n_pins; i++) {
		dev_dbg(ice_pf_to_dev(pf),
			"NVM pin entry[%d] : name_idx %d gpio_out %d gpio_in %d\n",
			i, pins[i].name_idx, pins[i].gpio[1], pins[i].gpio[0]);
	}

	pf->ptp.info.n_pins = n_pins;
	return 0;
}

/**
 * ice_ptp_set_funcs_e82x - Set specialized functions for E82X support
 * @pf: Board private structure
 *
 * Assign functions to the PTP capabiltiies structure for E82X devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for E82X
 * devices.
 */
static void ice_ptp_set_funcs_e82x(struct ice_pf *pf)
{
#ifdef HAVE_PTP_CROSSTIMESTAMP
	pf->ptp.info.getcrosststamp = ice_ptp_getcrosststamp;
#endif /* HAVE_PTP_CROSSTIMESTAMP */

	if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825) {
		pf->ptp.ice_pin_desc = ice_pin_desc_e825c;
		pf->ptp.info.n_pins = ARRAY_SIZE(ice_pin_desc_e825c);
	} else {
		pf->ptp.ice_pin_desc = ice_pin_desc_e82x;
		pf->ptp.info.n_pins = ARRAY_SIZE(ice_pin_desc_e82x);
	}
	ice_ptp_setup_pin_cfg(pf);
}

/**
 * ice_ptp_set_funcs_e810 - Set specialized functions for E810 support
 * @pf: Board private structure
 *
 * Assign functions to the PTP capabiltiies structure for E810 devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for E810
 * devices.
 */
static void ice_ptp_set_funcs_e810(struct ice_pf *pf)
{
	__le16 entries[ICE_AQC_NVM_SDP_AC_MAX_SIZE];
	struct ice_ptp_pin_desc *desc = NULL;
	struct ice_ptp *ptp = &pf->ptp;
	unsigned int num_entries;
	int err;

	err = ice_ptp_read_sdp_ac(&pf->hw, entries, &num_entries);
	if (err) {
		/* SDP section does not exist in NVM or is corrupted */
		if (ice_is_feature_supported(pf, ICE_F_SMA_CTRL)) {
			ptp->ice_pin_desc = ice_pin_desc_dpll;
			ptp->info.n_pins = ARRAY_SIZE(ice_pin_desc_dpll);
		} else {
			pf->ptp.ice_pin_desc = ice_pin_desc_e810;
			pf->ptp.info.n_pins = ARRAY_SIZE(ice_pin_desc_e810);
		}
		err = 0;
	} else {
		desc = devm_kcalloc(ice_pf_to_dev(pf), ICE_N_PINS_MAX,
				    sizeof(struct ice_ptp_pin_desc),
				    GFP_KERNEL);
		if (!desc)
			goto err;

		err = ice_ptp_parse_sdp_entries(pf, entries, num_entries, desc);
		if (err)
			goto err;

		ptp->ice_pin_desc = (const struct ice_ptp_pin_desc *)desc;
	}

	ptp->info.pin_config = ptp->pin_desc;
	ice_ptp_setup_pin_cfg(pf);

err:
	if (err) {
		devm_kfree(ice_pf_to_dev(pf), desc);
		ice_ptp_disable_pins(pf);
	}
}

/**
 * ice_ptp_set_funcs_e830 - Set specialized functions for E830 support
 * @pf: Board private structure
 *
 * Assign functions to the PTP capabiltiies structure for E830 devices.
 * Functions which operate across all device families should be set directly
 * in ice_ptp_set_caps. Only add functions here which are distinct for E830
 * devices.
 */
static void ice_ptp_set_funcs_e830(struct ice_pf *pf)
{
#ifdef HAVE_PTP_CROSSTIMESTAMP
#if defined(CONFIG_X86) && IS_ENABLED(CONFIG_PCIE_PTM)
	if (pcie_ptm_enabled(pf->pdev) &&
	    boot_cpu_has(X86_FEATURE_ART) &&
	    boot_cpu_has(X86_FEATURE_TSC_KNOWN_FREQ))
		pf->ptp.info.getcrosststamp = ice_ptp_getcrosststamp;
#endif /* CONFIG_X86 && CONFIG_PCIE_PTM */
#endif /* HAVE_PTP_CROSSTIMESTAMP */

	/* Rest of the config is the same as base E810 */
	pf->ptp.ice_pin_desc = ice_pin_desc_e810;
	pf->ptp.info.n_pins = ARRAY_SIZE(ice_pin_desc_e810);
	ice_ptp_setup_pin_cfg(pf);
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
	snprintf(pin_name, MAX_PIN_NAME, "%s",
		 ice_cgu_get_pin_name(&pf->hw, pin, true));
}

static void ice_handle_cgu_state(struct ice_pf *pf)
{
	const s64 HUNDREDTH_PSEC = 100LL;
	enum dpll_lock_status state;
	char pin_name[MAX_PIN_NAME];
	int ret;

	ret = ice_get_cgu_state(&pf->hw, ICE_CGU_DPLL_SYNCE,
				pf->synce_dpll_state, &pf->synce_ref_pin,
				NULL, NULL, NULL, &state);

	if (ret) {
		dev_err(ice_pf_to_dev(pf), "Failed to get cgu state (%u:%s)",
			ret, ice_aq_str(pf->hw.adminq.sq_last_status));
		return;
	}
	ice_dpll_pin_idx_to_name(pf, pf->synce_ref_pin, pin_name);
#if defined(BLOCK_DPLL_FREERUN)
	if (!pf->past_synce_lock && state == DPLL_LOCK_STATUS_LOCKED_HO_ACQ)
		pf->past_synce_lock = true;
	if (test_bit(ICE_FLAG_BLOCK_DPLL_FREERUN, pf->flags) &&
	    pf->past_synce_lock && state == DPLL_LOCK_STATUS_UNLOCKED)
		state = DPLL_LOCK_STATUS_HOLDOVER;
#endif /* NOT_FOR_UPSTREAM && BLOCK_DPLL_FREERUN */
	if (pf->synce_dpll_state != state) {
		pf->synce_dpll_state = state;
		dev_warn(ice_pf_to_dev(pf),
			 "DPLL%i state changed to: %s, pin %s",
			 ICE_CGU_DPLL_SYNCE,
			 ice_cgu_state_to_name(pf->synce_dpll_state), pin_name);
	}

	ret = ice_get_cgu_state(&pf->hw, ICE_CGU_DPLL_PTP, pf->ptp_dpll_state,
				&pf->ptp_ref_pin, NULL, NULL,
				&pf->ptp_dpll_phase_offset, &state);
#if defined(BLOCK_DPLL_FREERUN)
	if (!pf->past_ptp_lock && state == DPLL_LOCK_STATUS_LOCKED_HO_ACQ)
		pf->past_ptp_lock = true;
	if (test_bit(ICE_FLAG_BLOCK_DPLL_FREERUN, pf->flags) &&
	    pf->past_ptp_lock && state == DPLL_LOCK_STATUS_UNLOCKED)
		state = DPLL_LOCK_STATUS_HOLDOVER;
#endif /* NOT_FOR_UPSTREAM && BLOCK_DPLL_FREERUN */
	ice_dpll_pin_idx_to_name(pf, pf->ptp_ref_pin, pin_name);
	/* offset is in 0.01ps, convert to ps */
	pf->ptp_dpll_phase_offset /= HUNDREDTH_PSEC;
	if (pf->ptp_dpll_state != state) {
		pf->ptp_dpll_state = state;
		dev_warn(ice_pf_to_dev(pf),
			 "DPLL%i state changed to: %s, pin %s",
			 ICE_CGU_DPLL_PTP,
			 ice_cgu_state_to_name(pf->ptp_dpll_state), pin_name);
	}
}

/**
 * ice_ptp_maybe_trigger_tx_interrupt - Trigger Tx timestamp interrupt
 * @pf: Board private structure
 *
 * The device PHY issues Tx timestamp interrupts to the driver for processing
 * timestamp data from the PHY. It will not interrupt again until all
 * current timestamp data is read. In rare circumstances, it is possible that
 * the driver fails to read all outstanding data.
 *
 * To avoid getting permanently stuck, periodically check if the PHY has
 * outstanding timestamp data. If so, trigger an interrupt from software to
 * process this data.
 */
static void ice_ptp_maybe_trigger_tx_interrupt(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	unsigned int i;

	for (i = 0; i < ICE_GET_QUAD_NUM(hw->ptp.num_lports); i++) {
		u64 tstamp_ready;
		int err;

		err = ice_get_phy_tx_tstamp_ready(&pf->hw, i, &tstamp_ready);
		if (err || tstamp_ready) {
			/* Trigger a software interrupt, to ensure this data
			 * gets processed.
			 */
			dev_dbg(dev, "PTP periodic task detected waiting timestamps. Triggering Tx timestamp interrupt now.\n");

			wr32(hw, PFINT_OICR, PFINT_OICR_TSYN_TX_M);
			ice_flush(hw);

			return;
		}
	}
}

/**
 * ice_ptp_periodic_work - Do PTP periodic work
 * @info: Driver's PTP info structure
 *
 * Return: delay of the next auxiliary work scheduling time (>=0) or negative
 *         value in case further scheduling is not required.
 */
static long ice_ptp_periodic_work(struct ptp_clock_info *info)
{
	struct ice_pf *pf = ptp_info_to_pf(info);
	struct ice_hw *hw = &pf->hw;
	bool retry = false;
	int err;

	if (test_bit(ICE_FLAG_PTP_WT_BLOCKED, pf->flags))
		return -EBUSY;

	err = ice_ptp_update_cached_phctime_all(pf);
	if (err)
		retry = true;

	ice_ptp_maybe_trigger_tx_interrupt(pf);

	if (ice_is_feature_supported(pf, ICE_F_CGU))
		if (test_bit(ICE_FLAG_DPLL_MONITOR, pf->flags))
			ice_handle_cgu_state(pf);

	/* only E825C should monitor the TS PLL */
	if (hw->mac_type == ICE_MAC_GENERIC_3K_E825)
		err = ice_tspll_monitor_lock_e825c(hw);
	if (err)
		retry = true;

	/* Run twice a second or reschedule soon if we need to retry */
	return msecs_to_jiffies(retry ? 10 : MSEC_PER_SEC / 2);
}

#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
static void ice_ptp_aux_kworker(struct kthread_work *work)
{
	struct ice_ptp *ptp = container_of(work, struct ice_ptp, aux_work.work);
	struct ptp_clock_info *info = &ptp->info;
	long delay;

	delay = ice_ptp_periodic_work(info);

	if (delay >= 0)
		kthread_queue_delayed_work(ptp->kworker, &ptp->aux_work, delay);
}

static int ice_ptp_schedule_worker(struct ice_ptp *ptp, unsigned long delay)
{
	return kthread_mod_delayed_work(ptp->kworker, &ptp->aux_work, delay);
}

#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
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
	info->n_per_out = GLTSYN_TGT_H_IDX_MAX;
	info->n_ext_ts = GLTSYN_EVNT_H_IDX_MAX;
	info->enable = ice_ptp_gpio_enable;
	info->verify = ice_verify_pin;
#ifdef HAVE_PTP_CANCEL_WORKER_SYNC
	info->do_aux_work = ice_ptp_periodic_work;
#endif /* HAVE_PTP_CANCEL_WORKER_SYNC */

	switch (pf->hw.mac_type) {
	case ICE_MAC_E810:
		ice_ptp_set_funcs_e810(pf);
		return;
	case ICE_MAC_E830:
		ice_ptp_set_funcs_e830(pf);
		return;
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		ice_ptp_set_funcs_e82x(pf);
		return;
	default:
		return;
	}
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
	struct device *dev = ice_pf_to_dev(pf);

	/* No need to create a clock device if we already have one */
	if (pf->ptp.clock)
		return 0;

	ice_ptp_set_caps(pf);

	/* Attempt to register the clock before enabling the hardware. */
	pf->ptp.clock = ptp_clock_register(&pf->ptp.info, dev);
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
	struct ice_ptp_port *ptp_port;
	unsigned long flags;
	struct ice_pf *pf;
	s8 phy_idx;
	u8 idx;

	ptp_port = container_of(tx, struct ice_ptp_port, tx);
	pf = ptp_port_to_pf(ptp_port);

	spin_lock_irqsave(&tx->lock, flags);

	/* Check that this tracker is accepting new timestamp requests */
	if (!ice_ptp_is_tx_tracker_up(tx)) {
		ice_trace(tx_tstamp_tracker_down, ice_pf_to_dev(pf), tx,
			  skb, -1);
		spin_unlock_irqrestore(&tx->lock, flags);
		return -1;
	}

	/* Find and set the first available index */
	idx = find_next_zero_bit(tx->in_use, tx->len,
				 tx->last_ll_ts_idx_read + 1);
	if (idx == tx->len)
		idx = find_first_zero_bit(tx->in_use, tx->len);
	if (idx < tx->len) {
		/* We got a valid index that no other thread could have set. Store
		 * a reference to the skb and the start time to allow discarding old
		 * requests.
		 */
		set_bit(idx, tx->in_use);
		tx->tstamps[idx].start = jiffies;
		tx->tstamps[idx].skb = skb_get(skb);
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		phy_idx = idx + tx->offset;

		ice_trace(tx_tstamp_request, ice_pf_to_dev(pf), tx, skb, idx);
	} else {
		/* No indexes were available, so we have to skip this
		 * timestamp.
		 */
		pf->ptp.tx_hwtstamp_skipped++;
		phy_idx = -1;

		ice_trace(tx_tstamp_idx_full, ice_pf_to_dev(pf), tx, skb, -1);
	}

	spin_unlock_irqrestore(&tx->lock, flags);

	return phy_idx;
}

/**
 * ice_ptp_process_ts - Process the PTP Tx timestamps
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
	default:
		WARN_ONCE(1, "Unexpected Tx timestamp interrupt mode %u\n",
			  pf->ptp.tx_interrupt_mode);
		return ICE_TX_TSTAMP_WORK_DONE;
	}
}

/**
 * ice_ptp_ts_irq - Process the PTP Tx timestamps in IRQ context
 * @pf: Board private structure
 *
 * Returns: IRQ_WAKE_THREAD if Tx timestamp read has to be handled in the bottom
 * half of the interrupt and IRQ_HANDLED otherwise.
 */
irqreturn_t ice_ptp_ts_irq(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	switch (hw->mac_type) {
	case ICE_MAC_E830:
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K_E825:
		if (ice_ptp_process_ts(pf) == ICE_TX_TSTAMP_WORK_PENDING) {
			/* Process outstanding Tx timestamps. If there
			 * is more work, re-arm the interrupt to trigger again.
			 */
			wr32(hw, PFINT_OICR, PFINT_OICR_TSYN_TX_M);
			ice_flush(hw);
		}
		return IRQ_HANDLED;
	case ICE_MAC_E810:
	{
		struct ice_ptp_tx *tx = &pf->ptp.port.tx;
		unsigned long flags;
		u8 idx;

		if (!ice_pf_state_is_nominal(pf))
			return IRQ_HANDLED;

		/* E810 capable of low latency timestamping with interrupt can
		 * request a single timestamp in the top half and wait for
		 * a second LL TS interrupt from the FW when it's ready.
		 */
		if (!hw->dev_caps.ts_dev_info.ts_ll_int_read) {
			if (!ice_ptp_pf_handles_tx_interrupt(pf))
				return IRQ_HANDLED;

			set_bit(ICE_MISC_THREAD_TX_TSTAMP, pf->misc_thread);
			return IRQ_WAKE_THREAD;
		}

		spin_lock_irqsave(&tx->lock, flags);
		idx = find_next_bit_wrap(tx->in_use, tx->len,
					 tx->last_ll_ts_idx_read + 1);
		if (idx != tx->len)
			ice_ptp_req_tx_single_tstamp(tx, idx);
		spin_unlock_irqrestore(&tx->lock, flags);

		return IRQ_HANDLED;
	}
	default:
		dev_err(ice_pf_to_dev(pf), "Unknown PHY model, timestamping not supported\n");
		return IRQ_HANDLED;
	}
}

/**
 * ice_ptp_prepare_rebuild_sec - Prepare second NAC for PTP reset or rebuild
 * @pf: Board private structure
 * @rebuild: rebuild if true, prepare if false
 * @reset_type: the reset type being performed
 */
static void ice_ptp_prepare_rebuild_sec(struct ice_pf *pf, bool rebuild,
					enum ice_reset_req reset_type)
{
	struct ice_ptp_port *port;

	mutex_lock(&pf->adapter->ports.lock);
	list_for_each_entry(port, &pf->adapter->ports.ports, list_node) {
		struct ice_pf *peer_pf = ptp_port_to_pf(port);

		if (!ice_is_primary(&peer_pf->hw)) {
			if (rebuild)
				ice_ptp_rebuild(peer_pf, reset_type);
			else
				ice_ptp_prepare_for_reset(peer_pf, reset_type);
		}
	}
	mutex_unlock(&pf->adapter->ports.lock);
}

/**
 * ice_ptp_prepare_for_reset - Prepare PTP for reset
 * @pf: Board private structure
 * @reset_type: the reset type being performed
 */
void ice_ptp_prepare_for_reset(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	u8 src_tmr;

	if (ptp->state != ICE_PTP_READY)
		return;

	ptp->state = ICE_PTP_RESETTING;

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_disable_timestamp_mode(pf);

	if (ice_pf_src_tmr_owned(pf))
#ifdef HAVE_PTP_CANCEL_WORKER_SYNC
		ptp_cancel_worker_sync(ptp->clock);
#else /* !HAVE_PTP_CANCEL_WORKER_SYNC */
		kthread_cancel_delayed_work_sync(&ptp->aux_work);
#endif /* HAVE_PTP_CANCEL_WORKER_SYNC */

	if (reset_type == ICE_RESET_PFR)
		return;

	if (ice_pf_src_tmr_owned(pf) && hw->mac_type == ICE_MAC_GENERIC_3K_E825)
		ice_ptp_prepare_rebuild_sec(pf, false, reset_type);

	if (hw->mac_type == ICE_MAC_GENERIC)
		cancel_delayed_work_sync(&pf->ptp.port.ov_work);

	/* Disable periodic outputs */
	ice_ptp_disable_all_perout(pf);

	src_tmr = ice_get_ptp_src_clock_index(hw);

	/* Disable source clock */
	wr32(hw, GLTSYN_ENA(src_tmr), (u32)~GLTSYN_ENA_TSYN_ENA_M);

	/* Acquire PHC and system timer to restore after reset */
	ptp->reset_time = ktime_get_real_ns();
}

/**
 * ice_ptp_rebuild_owner - Initialize PTP clock owner after reset
 * @pf: Board private structure
 *
 * Companion function for ice_ptp_rebuild() which handles tasks that only the
 * PTP clock owner instance should perform.
 */
static int ice_ptp_rebuild_owner(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_ptp *ptp = &pf->ptp;
	struct ice_hw *hw = &pf->hw;
	struct timespec64 ts;
	u64 time_diff;
	int err;

	err = ice_ptp_init_phc(hw);
	if (err) {
		dev_err(dev, "Failed to initialize PHC, status %d\n",
			err);
		return err;
	}

	err = ice_tspll_init(hw);
	if (err) {
		dev_err(dev, "Failed to initialize CGU, status %d\n", err);
		return err;
	}

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(dev, "Failed to acquire PTP hardware semaphore\n");
		return err;
	}

	/* Write the increment time value to PHY and LAN */
	err = ice_ptp_write_incval(hw, ice_base_incval(pf));
	if (err) {
		dev_err(dev, "Failed to write PHC increment value, status %d\n",
			err);
		ice_ptp_unlock(hw);
		return err;
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
		ice_dev_err_errno(dev, err, "Failed to write PHC initial time");
		ice_ptp_unlock(hw);
		return err;
	}

	/* Release the global hardware lock */
	ice_ptp_unlock(hw);

	/* Flush software tracking of any outstanding timestamps since we're
	 * about to flush the PHY timestamp block.
	 */
	ice_ptp_flush_all_tx_tracker(pf);

	/* Configure PHY interrupt settings, and reset timestamp block */
	err = ice_ptp_cfg_phy_interrupt(pf, true, 1);
	if (err)
		return err;

	ice_ptp_restart_all_phy(pf);

	/* Re-enable all periodic outputs and external timestamp events */
	ice_ptp_enable_all_perout(pf);
	ice_ptp_enable_all_extts(pf);

	return 0;
}

/**
 * ice_ptp_rebuild - Initialize PTP hardware clock support after reset
 * @pf: Board private structure
 * @reset_type: the reset type being performed
 */
void ice_ptp_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	struct ice_ptp *ptp = &pf->ptp;
	int err;
	u32 val;

	val = rd32(&pf->hw, PF_SB_REM_DEV_CTL);
	wr32(&pf->hw, PF_SB_REM_DEV_CTL, val | BIT(phy_0_peer) | BIT(cgu_peer));

	if (ptp->state != ICE_PTP_RESETTING) {
		if (ptp->state == ICE_PTP_READY) {
			ice_ptp_prepare_for_reset(pf, reset_type);
		} else {
			err = -EINVAL;
			dev_err(ice_pf_to_dev(pf), "PTP was not initialized\n");
			goto err;
		}
	}

	if (ice_pf_src_tmr_owned(pf)) {
		if (reset_type != ICE_RESET_PFR) {
			err = ice_ptp_rebuild_owner(pf);
			if (err)
				goto err;

			if (pf->hw.mac_type == ICE_MAC_GENERIC_3K_E825)
				ice_ptp_prepare_rebuild_sec(pf, true,
							    reset_type);

			ice_block_ptp_workthreads_global(pf, false);
		}

#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
		ice_ptp_schedule_worker(ptp, 0);
#else /* HAVE_PTP_CANCEL_WORKER_SYNC */
		ptp_schedule_worker(ptp->clock, 0);
#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
	}

	ptp->state = ICE_PTP_READY;

	dev_info(ice_pf_to_dev(pf), "PTP reset successful\n");
	return;
err:
	ptp->state = ICE_PTP_ERROR;
	ice_dev_err_errno(ice_pf_to_dev(pf), err, "PTP reset failed");
}

static int ice_ptp_setup_adapter(struct ice_pf *pf)
{
	if (!ice_pf_src_tmr_owned(pf) || !ice_is_primary(&pf->hw))
		return -EPERM;

	pf->adapter->ctrl_pf = pf;

	return 0;
}

static int ice_ptp_setup_pf(struct ice_pf *pf)
{
	struct ice_ptp *ctrl_ptp = ice_get_ctrl_ptp(pf);
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);
	struct ice_ptp *ptp = &pf->ptp;
	u8 port_num, phy;

	if (WARN_ON(!ctrl_pf) || pf->hw.mac_type == ICE_MAC_UNKNOWN)
		return -ENODEV;

	INIT_LIST_HEAD(&ptp->port.list_node);
	mutex_lock(&pf->adapter->ports.lock);

	list_add(&ptp->port.list_node,
		 &pf->adapter->ports.ports);
	mutex_unlock(&pf->adapter->ports.lock);

	port_num = ptp->port.port_num;
	phy = port_num / pf->hw.ptp.ports_per_phy;
	/* clock ENET is enabled by default, mark it */
	set_bit(port_num, &ctrl_ptp->tx_refclks[phy][ICE_REF_CLK_ENET]);

	/* propagate TS PLL settings for non-control PFs */
	if (!ice_pf_src_tmr_owned(pf) && ice_is_generic_mac(&pf->hw)) {
		pf->hw.ptp.src_tmr_mode = ctrl_pf->hw.ptp.src_tmr_mode;
		pf->hw.ptp.tspll_freq = ctrl_pf->hw.ptp.tspll_freq;
		pf->hw.ptp.clk_src = ctrl_pf->hw.ptp.clk_src;
	}

	return 0;
}

static void ice_ptp_cleanup_pf(struct ice_pf *pf)
{
	struct ice_ptp *ptp = &pf->ptp;

	if (pf->hw.mac_type != ICE_MAC_UNKNOWN) {
		mutex_lock(&pf->adapter->ports.lock);
		list_del(&ptp->port.list_node);
		mutex_unlock(&pf->adapter->ports.lock);
	}
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
	struct ice_ptp *ctrl_ptp = ice_get_ctrl_ptp(pf);
	struct ptp_clock *clock;

	if (!ctrl_ptp)
		return -1;
	clock = ctrl_ptp->clock;

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

	hw->ptp.src_tmr_mode = ICE_SRC_TMR_MODE_NANOSECONDS;
	hw->ptp.tspll_freq = hw->func_caps.ts_func_info.time_ref;
	hw->ptp.clk_src = (enum ice_clk_src)hw->func_caps.ts_func_info.clk_src;
	hw->ptp.tspll_lock_retries = 0;

	err = ice_ptp_init_phc(hw);
	if (err) {
		dev_err(dev, "Failed to initialize PHC, status %d\n", err);
		goto err_exit;
	}

	err = ice_tspll_init(hw);
	if (err) {
		dev_err(dev, "Failed to initialize CGU, status %d\n", err);
		return err;
	}

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(dev, "Failed to acquire PTP hardware semaphore\n");
		goto err_exit;
	}

	/* Write the increment time value to PHY and LAN */
	err = ice_ptp_write_incval(hw, ice_base_incval(pf));
	if (err) {
		dev_err(dev, "Failed to write PHC increment value, status %d\n",
			err);
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

	/* Configure PHY interrupt settings */
	err = ice_ptp_cfg_phy_interrupt(pf, true, itr);
	if (err)
		goto err_exit;

	/* Ensure we have a clock device */
	err = ice_ptp_create_clock(pf);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "Failed to register PTP clock device");
		goto err_clk;
	}

#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
	ptp->kworker = kthread_create_worker(0, "ice-ptp-%s", dev_name(dev));
	if (IS_ERR(ptp->kworker)) {
		err = PTR_ERR(ptp->kworker);
		dev_err(dev, "Failed to create ptp aux_worker err=%d\n",
			err);
		goto err_kthread;
	}
	kthread_init_delayed_work(&ptp->aux_work, ice_ptp_aux_kworker);

#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		set_bit(ICE_FLAG_DPLL_MONITOR, pf->flags);
		pf->synce_dpll_state = DPLL_LOCK_STATUS_UNLOCKED;
		pf->ptp_dpll_state = DPLL_LOCK_STATUS_UNLOCKED;
#if defined(BLOCK_DPLL_FREERUN)
		pf->past_ptp_lock = false;
		pf->past_synce_lock = false;
#endif /* NOT_FOR_UPSTREAM && BLOCK_DPLL_FREERUN */
	}

	return 0;

#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
err_kthread:
	ptp_clock_unregister(ptp->clock);
#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
err_clk:
	ptp->clock = NULL;
err_exit:
	return err;
}

/**
 * ice_ptp_init_port - Initialize PTP port structure
 * @pf: Board private structure
 * @ptp_port: PTP port structure
 *
 * Return: 0 on success, -ENODEV on invalid MAC type, -ENOMEM on failed alloc.
 */
static int ice_ptp_init_port(struct ice_pf *pf, struct ice_ptp_port *ptp_port)
{
	struct ice_hw *hw = &pf->hw;

	mutex_init(&ptp_port->ps_lock);

	switch (hw->mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_E830:
	case ICE_MAC_GENERIC_3K_E825:
		return ice_ptp_init_tx(pf, &ptp_port->tx, ptp_port->port_num);
	case ICE_MAC_GENERIC:
		ptp_port->rx_calibrating = 0;
		INIT_DELAYED_WORK(&ptp_port->ov_work, ice_ptp_wait_for_offsets);
		return ice_ptp_init_tx_e82x(pf, &ptp_port->tx,
					    ptp_port->port_num);
	default:
		return -ENODEV;
	}
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
		ice_ptp_disable_timestamp_mode(pf);
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
 */
void ice_block_ptp_workthreads_global(struct ice_pf *pf, bool block_enable)
{
	struct ice_pf *ctrl_pf = ice_get_ctrl_pf(pf);
	struct ice_ptp_port *port;

	if (!ctrl_pf)
		return;

	if (!ice_is_ptp_supported(ctrl_pf)) {
		dev_dbg(ice_pf_to_dev(ctrl_pf), "PTP not active, skipping unnecessary workthread block");
		return;
	}

	mutex_lock(&pf->adapter->ports.lock);
	list_for_each_entry(port, &pf->adapter->ports.ports, list_node) {
		ice_block_ptp_workthreads(ptp_port_to_pf(port), block_enable);
	}
	mutex_unlock(&pf->adapter->ports.lock);
}

/**
 * ice_ptp_init_tx_interrupt_mode - Initialize device Tx interrupt mode
 * @pf: Board private structure
 *
 * Initialize the Tx timestamp interrupt mode for this device. For most device
 * types, each PF processes the interrupt and manages its own timestamps. For
 * E82X-based devices, only the clock owner processes the timestamps. Other
 * PFs disable the interrupt and do not process their own timestamps.
 */
static void ice_ptp_init_tx_interrupt_mode(struct ice_pf *pf)
{
	switch (pf->hw.mac_type) {
	case ICE_MAC_GENERIC:
		/* E82X based PHY has the clock owner process the interrupt
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

	if (hw->lane_num < 0) {
		err = hw->lane_num;
		goto err_exit;
	}
	ptp->port.port_num = hw->lane_num;

	ice_ptp_init_hw(hw);

	ice_ptp_init_tx_interrupt_mode(pf);

	/* If this function owns the clock hardware, it must allocate and
	 * configure the PTP clock device to represent it.
	 */
	if (ice_pf_src_tmr_owned(pf) && ice_is_primary(hw)) {
		err = ice_ptp_setup_adapter(pf);
		if (err)
			goto err_exit;
		err = ice_ptp_init_owner(pf);
		if (err)
			goto err_exit;
	}

	ptp->port.tx_clk = ICE_REF_CLK_ENET;
	ptp->port.tx_clk_prev = ICE_REF_CLK_ENET;

	err = ice_ptp_setup_pf(pf);
	if (err)
		goto err_exit;

	err = ice_ptp_init_port(pf, &ptp->port);
	if (err)
		goto err_exit;

	/* Start the PHY timestamping block */
	ice_ptp_reset_phy_timestamping(pf);

	/* Configure initial Tx interrupt settings */
	ice_ptp_cfg_tx_interrupt(pf);

	ice_ptp_sysfs_init(pf);

	ptp->state = ICE_PTP_READY;

	if (ice_pf_src_tmr_owned(pf))
#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
		ice_ptp_schedule_worker(ptp, 0);
#else /* HAVE_PTP_CANCEL_WORKER_SYNC */
		ptp_schedule_worker(ptp->clock, 0);
#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */

	dev_info(ice_pf_to_dev(pf), "PTP init successful\n");
	return;

err_exit:
	/* If we registered a PTP clock, release it */
	if (pf->ptp.clock) {
		ptp_clock_unregister(ptp->clock);
		pf->ptp.clock = NULL;
	}
	ptp->state = ICE_PTP_ERROR;
	dev_err(ice_pf_to_dev(pf), "PTP failed %d\n", err);
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
	struct ice_ptp *ptp = &pf->ptp;
	if (ptp->state != ICE_PTP_READY)
		return;

	ptp->state = ICE_PTP_UNINIT;
	if (ice_pf_src_tmr_owned(pf) && pf->hw.mac_type == ICE_MAC_GENERIC)
		ice_tspll_cfg_cgu_err_reporting(&pf->hw, false);

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_disable_timestamp_mode(pf);

	ice_ptp_cleanup_pf(pf);

	ice_ptp_release_tx_tracker(pf, &ptp->port.tx);

	ice_ptp_disable_all_extts(pf);

	if (pf->hw.mac_type == ICE_MAC_GENERIC)
		cancel_delayed_work_sync(&ptp->port.ov_work);
	ice_ptp_port_phy_stop(&ptp->port);
	mutex_destroy(&ptp->port.ps_lock);
	ice_ptp_sysfs_release(pf);

	if (!ptp->clock)
		return;

	/* Disable periodic outputs */
	ice_ptp_disable_all_perout(pf);
#ifdef HAVE_PTP_CANCEL_WORKER_SYNC
	if (ice_pf_src_tmr_owned(pf))
		ptp_cancel_worker_sync(ptp->clock);
#else /* !HAVE_PTP_CANCEL_WORKER_SYNC */
	if (ice_pf_src_tmr_owned(pf)) {
		kthread_cancel_delayed_work_sync(&ptp->aux_work);
		kthread_destroy_worker(ptp->kworker);
	}
#endif /* HAVE_PTP_CANCEL_WORKER_SYNC */

	ptp_clock_unregister(ptp->clock);
	ptp->clock = NULL;

	dev_info(ice_pf_to_dev(pf), "Removed PTP clock\n");
}
