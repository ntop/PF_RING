/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#include "iavf.h"
#include "iavf_prototype.h"
#include "iavf_synce.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/jiffies.h>

/***************************************************************
 * SyncE Device Data Defines & Functions
 ***************************************************************/
enum iavf_cgu_dpll  {
	IAVF_CGU_DPLL_SYNCE,
	IAVF_CGU_DPLL_PTP,
	IAVF_CGU_DPLL_MAX
};

#define IAVF_MAX_CGU_STATE_NAME_LEN 14
struct iavf_cgu_state_desc {
	char name[IAVF_MAX_CGU_STATE_NAME_LEN];
	enum iavf_cgu_state state;
};

#define IAVF_MAX_CGU_PIN_NAME_LEN 16
struct iavf_cgu_pin_desc {
	char name[IAVF_MAX_CGU_PIN_NAME_LEN];
	u8 index;
};

enum iavf_zl_cgu_pins {
	IAVF_ZL_REF0P = 0,
	IAVF_ZL_REF0N,
	IAVF_ZL_REF1P,
	IAVF_ZL_REF1N,
	IAVF_ZL_REF2P,
	IAVF_ZL_REF2N,
	IAVF_ZL_REF3P,
	IAVF_ZL_REF3N,
	IAVF_ZL_REF4P,
	IAVF_ZL_REF4N,
	IAVF_NUM_ZL_CGU_PINS
};

enum iavf_si_cgu_pins {
	IAVF_SI_REF0P = 0,
	IAVF_SI_REF0N,
	IAVF_SI_REF1P,
	IAVF_SI_REF1N,
	IAVF_SI_REF2P,
	IAVF_SI_REF2N,
	IAVF_SI_REF3,
	IAVF_SI_REF4,
	IAVF_NUM_IAVF_SI_CGU_PINS
};

static const struct iavf_cgu_pin_desc iavf_e810t_cgu_inputs[] = {
	/* name		  idx */
	{ "CVL-SDP22",    IAVF_ZL_REF0P },
	{ "CVL-SDP20",    IAVF_ZL_REF0N },
	{ "C827_0-RCLKA", IAVF_ZL_REF1P },
	{ "C827_0-RCLKB", IAVF_ZL_REF1N },
	{ "C827_1-RCLKA", IAVF_ZL_REF2P },
	{ "C827_1-RCLKB", IAVF_ZL_REF2N },
	{ "SMA1",         IAVF_ZL_REF3P },
	{ "SMA2/U.FL2",   IAVF_ZL_REF3N },
	{ "GNSS-1PPS",    IAVF_ZL_REF4P },
	{ "OCXO",         IAVF_ZL_REF4N },
};

#define IAVF_CGU_INPUT_C827(_phy, _pin) ((_phy) * IAVF_C827_RCLK_PINS_NUM + \
					  (_pin) + IAVF_ZL_REF1P)

#define IAVF_MAX_PIN_NAME_LEN 15

/**
 * iavf_kobj_to_iavf - Retrieve the IAVF struct associated with a kobj
 * @kobj: pointer to the kobject
 *
 * Returns a pointer to IAVF or NULL if there is no association.
 */
static inline struct iavf_adapter *iavf_kobj_to_iavf(struct kobject *kobj)
{
	if (!kobj || !kobj->parent)
		return NULL;

	return iavf_pdev_to_adapter(to_pci_dev(kobj_to_dev(kobj->parent)));
}

/**
 * iavf_kdev_to_iavf - Retrieve the IAVF struct associated with a dev
 * @dev: pointer to the device
 *
 * Returns a pointer to IAVF or NULL if there is no association.
 */
static inline struct iavf_adapter *iavf_kdev_to_iavf(struct device *dev)
{
	if (!dev)
		return NULL;

	return iavf_pdev_to_adapter(to_pci_dev(dev));
}

/**
 * iavf_zl_pin_idx_to_name_e810t - get the name of E810T CGU pin
 * @pin: pin number
 *
 * Return: name of E810T CGU pin
 */
static const char *iavf_zl_pin_idx_to_name_e810t(u8 pin)
{
	if (pin < IAVF_NUM_ZL_CGU_PINS)
		return iavf_e810t_cgu_inputs[pin].name;

	return "invalid";
}

/*
 * iavf_synce_start_cgu_dpll_status_log - Request dpll status polling
 * @adapter: pointer to iavf adapter
 * @dpll_num: DPLL index
 *
 * Get CGU DPLL status (0x0C66)
 */
static int iavf_synce_start_cgu_dpll_status_log(struct iavf_adapter *adapter,
						u8 dpll_num)
{
	struct virtchnl_synce_get_cgu_dpll_status *msg;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS,
				   sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->dpll_num = dpll_num;
	iavf_queue_vc_msg(adapter, vc_msg);

	return status;
}

/**
 * iavf_parse_dpll_state - parse the dpll_state bit fields
 * @dpll_state: pll state from pf response
 * @last_dpll_state: last known state of DPLL
 *
 * parse the dpll_state bit fields to defined cgu_dpll_state enum
 */
static
enum iavf_cgu_state iavf_parse_dpll_state(u16 dpll_state,
					  enum iavf_cgu_state last_dpll_state)
{
	if (dpll_state & VIRTCHNL_GET_CGU_DPLL_STATUS_STATE_LOCK) {
		if (dpll_state & VIRTCHNL_GET_CGU_DPLL_STATUS_STATE_HO_READY)
			return IAVF_CGU_STATE_LOCKED_HO_ACQ;
		else
			return IAVF_CGU_STATE_LOCKED;
	}

	if (last_dpll_state == IAVF_CGU_STATE_LOCKED_HO_ACQ ||
	    last_dpll_state == IAVF_CGU_STATE_HOLDOVER)
		return IAVF_CGU_STATE_HOLDOVER;

	return IAVF_CGU_STATE_FREERUN;
}

/**
 * parse_dpll_ref_pin - parse the dpll_state bit fields for ref pin
 * @dpll_state: pll state from pf response
 *
 * parse the dpll_state bit fields to get dpll ref pin
 */
static u16 parse_dpll_ref_pin(u16 dpll_state)
{
	return ((dpll_state & VIRTCHNL_GET_CGU_DPLL_STATUS_STATE_CLK_REF_SEL)
		>> VIRTCHNL_GET_CGU_DPLL_STATUS_STATE_CLK_REF_SHIFT);
}

static void iavf_dpll_pin_idx_to_name(struct iavf_adapter *adapter, u8 pin,
				      char *pin_name);
static const char *iavf_cgu_state_to_name(int state);

/***************************************************************
 * VIRTCHNL Callbacks with iavf opcodes related to syncE
 ***************************************************************/
/**
 * iavf_virtchnl_synce_get_hw_info - Respond to VIRTCHNL_OP_SYNCE_GET_HW_INFO
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_HW_INFO message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the message from the data and store it in hw_info.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_hw_info(struct iavf_adapter *adapter, void *data,
				     u16 len)
{
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_synce_get_hw_info *msg;

	if (len >= sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid hw info. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	/* retrieve the hw info related to feature support such as CGU and
	 * PHY RCLK Presence
	 */
	synce->hw_info = *msg;

	/* retrieve cgu pins */
	memcpy(&adapter->synce.cgu_pins, msg->pins,
	       msg->len * sizeof(struct virtchnl_cgu_pin));
	synce->hw_info_ready = true;
}

/**
 * iavf_virtchnl_synce_get_phy_rec_clk_out - Respond to opcode
 * VIRTCHNL_OP_SYNCE_GET_PHY_REC_CLK_OUT
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_PHY_REC_CLK_OUT message from the PF.
 * This message is sent by the PF in response to the same op as a request
 * from the VF.
 * Extract the message from the data store it in cached_phy_rec_clk_out.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_phy_rec_clk_out(struct iavf_adapter *adapter,
					     void *data, u16 len)
{
	struct virtchnl_synce_get_phy_rec_clk_out *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid phy rec clk out. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_phy_rec_clk_out, msg, len);
	synce->phy_rec_clk_out_ready = true;
	wake_up(&synce->phy_rec_clk_out_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_cgu_dpll_status - Respond to VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the message from the data store it in cached_cgu_dpll_status.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_cgu_dpll_status(struct iavf_adapter *adapter,
					     void *data, u16 len)
{
	struct virtchnl_synce_get_cgu_dpll_status *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;
	char pin_name[IAVF_MAX_PIN_NAME_LEN];
	enum iavf_cgu_state dpll_state;
	u16 ref_pin;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid cgu dpll status. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_cgu_dpll_status, msg, len);
	synce->cgu_dpll_status_ready = true;

	dev_dbg(dev, "%s: dpll_num: %u ref_state: %u dpll_state: %u phase_offset: %lld eec_mode: %u\n",
		__func__, msg->dpll_num, msg->ref_state, msg->dpll_state,
		msg->phase_offset, msg->eec_mode);

	/* print out the dpll status log if it is the pending one
	 * and the state has been changed
	 */
	if (synce->log_pending == msg->dpll_num) {
		switch (msg->dpll_num) {
		case IAVF_CGU_DPLL_SYNCE:
			dpll_state = iavf_parse_dpll_state(msg->dpll_state,
							   synce->synce_dpll_state);
			if (dpll_state != synce->synce_dpll_state) {
				synce->synce_dpll_state = dpll_state;
				ref_pin = parse_dpll_ref_pin(msg->dpll_state);
				iavf_dpll_pin_idx_to_name(adapter, ref_pin,
							  pin_name);
				dev_info(dev, "DPLL%d state changed to: %s, %s",
					 msg->dpll_num,
					 iavf_cgu_state_to_name(dpll_state),
					 pin_name);
			}
			iavf_synce_start_cgu_dpll_status_log(adapter,
							     IAVF_CGU_DPLL_PTP);
			synce->log_pending = (u8)IAVF_CGU_DPLL_PTP;
			break;
		case IAVF_CGU_DPLL_PTP:
			dpll_state = iavf_parse_dpll_state(msg->dpll_state,
							   synce->ptp_dpll_state);
			if (dpll_state != synce->ptp_dpll_state) {
				synce->ptp_dpll_state = dpll_state;
				ref_pin = parse_dpll_ref_pin(msg->dpll_state);
				iavf_dpll_pin_idx_to_name(adapter, ref_pin,
							  pin_name);
				dev_info(dev, "DPLL%d state changed to: %s, %s",
					 msg->dpll_num,
					 iavf_cgu_state_to_name(dpll_state),
					 pin_name);
			}
			break;
		default:
			break;
		}
	}

	/* wake up any pending sysfs request */
	wake_up(&synce->cgu_dpll_stat_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_cgu_ref_prio - Respond to opcode
 * VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO message from the PF.
 * This message is sent by the PF in response to the same op as a request
 * from the VF.
 * Extract the message from the data store it in cached_cgu_dpll_status.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_cgu_ref_prio(struct iavf_adapter *adapter,
					  void *data, u16 len)
{
	struct virtchnl_synce_get_cgu_ref_prio *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid cgu ref prio. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_cgu_ref_prio, msg, len);
	dev_dbg(dev, "%s: dpll_num: %u ref_idx: %u ref_priority: %u\n",
		__func__, msg->dpll_num, msg->ref_idx, msg->ref_priority);
	synce->cgu_ref_prio_ready = true;
	wake_up(&synce->cgu_ref_prio_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_cgu_info - Respond to VIRTCHNL_OP_SYNCE_GET_CGU_INFO
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_CGU_INFO message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the message from the data store it in cached_cgu_info.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_cgu_info(struct iavf_adapter *adapter,
				      void *data, u16 len)
{
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_synce_get_cgu_info *msg;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev,
			     "Invalid cgu info. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_cgu_info, msg, len);
	dev_dbg(dev, "%s: cgu_id: %u cgu_cfg_ver: %u cgu_fw_ver: %u\n",
		__func__, msg->cgu_id,
		msg->cgu_cfg_ver, msg->cgu_fw_ver);
	synce->cgu_info_ready = true;
	wake_up(&synce->cgu_info_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_cgu_abilities - Respond to opcode
 * VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIE
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIE message from the PF.
 * This message is sent by the PF in response to the same op as a request
 * from the VF.
 * Extract the message from the data store it in cached_cgu_abilities.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_cgu_abilities(struct iavf_adapter *adapter,
					   void *data, u16 len)
{
	struct virtchnl_synce_get_cgu_abilities *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev,
			     "Invalid cgu cap from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_cgu_abilities, msg, len);
	dev_dbg(dev,
		"%s: num_inputs: %u num_outputs: %u\n",
		__func__, msg->num_inputs, msg->num_outputs);
	synce->cgu_abilities_ready = true;
	wake_up(&synce->cgu_abilities_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_input_pin_cfg - Respond to VIRTCHNL_OP_SYNCE_SET_INPUT_PIN_CFG
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_SET_INPUT_PIN_CFG  message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the message from the data store it in cached_input_pin_cfg.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_input_pin_cfg(struct iavf_adapter *adapter,
					   void *data, u16 len)
{
	struct virtchnl_synce_get_input_pin_cfg *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid Input Pin Cfg from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_input_pin_cfg, msg, len);
	dev_dbg(dev,
		"%s: input_idx: %u status: %u type: %u flags1: %u flags2: %u freq: %u phase_delay: %d\n",
		__func__, msg->input_idx, msg->status, msg->type, msg->flags1,
		msg->flags2, msg->freq, msg->phase_delay);
	synce->input_pin_cfg_ready = true;
	wake_up(&synce->input_pin_cfg_waitqueue);
}

/**
 * iavf_virtchnl_synce_get_output_pin_cfg - Respond to VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the message from the data store it in cached_output_pin_cfg.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_synce_get_output_pin_cfg(struct iavf_adapter *adapter,
					    void *data, u16 len)
{
	struct virtchnl_synce_get_output_pin_cfg *msg;
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev, "Invalid output pin cfg  from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&synce->cached_output_pin_cfg, msg, len);
	dev_dbg(dev, "%s: output_idx: %u flags: %u src_sel: %u freq: %u src_freq: %u\n",
		__func__, msg->output_idx, msg->flags, msg->src_sel, msg->freq,
		msg->src_freq);

	synce->output_pin_cfg_ready = true;
	wake_up(&synce->output_pin_cfg_waitqueue);
}

/***************************************************************
 * aq cmd re-implementation with iavf op codes related to syncE
 ***************************************************************/
/**
 * iavf_synce_aq_get_hw_info - Get SyncE HW Info through Virtchnl
 * @adapter: pointer to iavf adapter
 *
 * This function sends VIRTCHNL_OP_SYNCE_GET_HW_INFO op code to PF
 * then Polls Virtchnl on PF Response and save the HW Info & Ref Pin
 * Info
 */
static int iavf_synce_aq_get_hw_info(struct iavf_adapter *adapter)
{
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;
	int status = 0;
	int i;

	/* First send pf the HW Info opcode, then poll for pf response
	 * upto IAVF_SYNCE_HW_INFO_ATTEMPTS tries
	 * cache the response into hw_info for sysfs setup
	 */
	iavf_send_vf_synce_hw_info_msg(adapter);
	synce->hw_info_ready = false;
#define IAVF_SYNCE_HW_INFO_ATTEMPTS 10
	for (i = 0; i < IAVF_SYNCE_HW_INFO_ATTEMPTS; i++) {
		/* Sleep for a few msec to give time for the PF to response */
		usleep_range(5000, 100000);

		status = iavf_get_synce_hw_info(adapter);
		if (status == -EALREADY) {
			/* PF hasn't replied yet. Try again */
			continue;
		} else if (status) {
			dev_dbg(dev,
				"Failed to get hw info response from PF, err %d, aq_err %s\n",
				status, iavf_aq_str(&adapter->hw,
				adapter->hw.aq.asq_last_status));
			return status;
		}
		if (!synce->hw_info_ready) {
			dev_dbg(dev, "HW Info data not complete.\n");
			return -EIO;
		}
		return 0;
	}

	/* PF did not send us the message in time */
	dev_dbg(dev, "Failed to get hw info after %d attempts\n",
		IAVF_SYNCE_HW_INFO_ATTEMPTS);

	return status;
}

/**
 * iavf_synce_aq_set_phy_rec_clk_out - set RCLK phy out
 * @adapter: pointer to iavf adapter
 * @phy_output: PHY reference clock output pin
 * @enable: GPIO state to be applied
 * @freq: PHY output frequency
 *
 * Set CGU reference priority (0x0630)
 * Return 0 on success or negative value on failure.
 */
static int iavf_synce_aq_set_phy_rec_clk_out(struct iavf_adapter *adapter,
					     u8 phy_output, bool enable,
					     u32 *freq)
{
	struct virtchnl_synce_set_phy_rec_clk_out *msg;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_vc_msg *vc_msg;

	dev_dbg(dev, "%s: phy_output: %u enable: %u\n", __func__,
		phy_output, enable);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_SET_PHY_REC_CLK_OUT,
				   sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->phy_output = phy_output;
	msg->enable = enable ? 1 : 0;
	*freq = 0;
	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/*
 * iavf_synce_aq_get_cgu_dpll_status
 * @adapter: pointer to iavf adapter
 * @dpll_num: DPLL index
 * @ref_state: Reference clock state
 * @dpll_state: DPLL state
 * @phase_offset: Phase offset in ns
 * @eec_mode: EEC_mode
 *
 * Get CGU DPLL status (0x0C66)
 */
static int iavf_synce_aq_get_cgu_dpll_status(struct iavf_adapter *adapter,
					     u8 dpll_num, u8 *ref_state,
					     u16 *dpll_state,
					     s64 *phase_offset, u8 *eec_mode)
{
	struct virtchnl_synce_get_cgu_dpll_status *msg;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_synce *se = &adapter->synce;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: dpll_num: %u\n", __func__, dpll_num);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS,
				   sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->dpll_num = dpll_num;
	se->cgu_dpll_status_ready = false;
	iavf_queue_vc_msg(adapter, vc_msg);

	/*Handle the response from PF */
	status = wait_event_interruptible_timeout(se->cgu_dpll_stat_waitqueue,
						  se->cgu_dpll_status_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	msg = &se->cached_cgu_dpll_status;
	*ref_state = msg->ref_state;
	*dpll_state = msg->dpll_state;
	*phase_offset = msg->phase_offset;
	*eec_mode = msg->eec_mode;

	dev_dbg(dev, "%s: dpll_num: %u ref_state: %u dpll_state: %u phase_offset: %lld eec_mode: %u\n",
		__func__, dpll_num, *ref_state, *dpll_state, *phase_offset,
		*eec_mode);

	return 0;
}

/**
 * iavf_synce_aq_set_cgu_ref_prio
 * @adapter: pointer to iavf adapter
 * @dpll_num: DPLL index
 * @ref_idx: Reference pin index
 * @ref_priority: Reference input priority
 *
 * Set CGU reference priority (0x0C68)
 */
static int iavf_synce_aq_set_cgu_ref_prio(struct iavf_adapter *adapter,
					  u8 dpll_num, u8 ref_idx,
					  u8 ref_priority)
{
	struct virtchnl_synce_set_cgu_ref_prio *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: dpll_num: %u ref_idx: %u ref_priority: %u\n",
		__func__, dpll_num, ref_idx, ref_priority);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_SET_CGU_REF_PRIO,
				   sizeof(*cmd));

	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->dpll_num = dpll_num;
	cmd->ref_idx = ref_idx;
	cmd->ref_priority = ref_priority;

	iavf_queue_vc_msg(adapter, vc_msg);

	return status;
}

/**
 * iavf_synce_aq_get_cgu_ref_prio
 * @adapter: pointer to iavf adapter
 * @dpll_num: DPLL index
 * @ref_idx: Reference pin index
 * @ref_prio: Reference input priority
 *
 * Get CGU reference priority (0x0C69)
 */
static int iavf_synce_aq_get_cgu_ref_prio(struct iavf_adapter *adapter,
					  u8 dpll_num, u8 ref_idx,
					  u8 *ref_prio)
{
	struct virtchnl_synce_get_cgu_ref_prio *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_synce *se = &adapter->synce;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: dpll_num: %u ref_idx: %u\n",
		__func__, dpll_num, ref_idx);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO,
				   sizeof(*cmd));
	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->dpll_num = dpll_num;
	cmd->ref_idx = ref_idx;
	se->cgu_ref_prio_ready = false;
	iavf_queue_vc_msg(adapter, vc_msg);

	/*Handle the response from PF */
	status = wait_event_interruptible_timeout(se->cgu_ref_prio_waitqueue,
						  se->cgu_ref_prio_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	cmd = &se->cached_cgu_ref_prio;
	*ref_prio = cmd->ref_priority;

	dev_dbg(dev, "%s: dpll_num: %u ref_idx: %u ref_priority: %u\n",
		__func__, dpll_num, ref_idx, *ref_prio);

	return 0;
}

/**
 * iavf_synce_aq_get_cgu_abilities
 * @adapter: pointer to iavf adapter
 * @caps: CGU abilities
 *
 * Get CGU abilities (0x0C61)
 */
static int
iavf_synce_aq_get_cgu_abilities(struct iavf_adapter *adapter,
				struct virtchnl_synce_get_cgu_abilities *caps)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_synce *se = &adapter->synce;
	int status = 0;

	dev_dbg(dev, "%s: %s\n", __func__,  __func__);

	iavf_send_vf_synce_cgu_abilities_msg(adapter);
	se->cgu_abilities_ready = false;

	/*Handle the response from PF */
	status = wait_event_interruptible_timeout(se->cgu_abilities_waitqueue,
						  se->cgu_abilities_ready,
						  HZ);

	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	/* return the pf response */
	*caps = se->cached_cgu_abilities;

	dev_dbg(dev, "%s: num_inputs: %u num_outputs: %u pps_dpll_idx: %u synce_dpll_idx: %u max_in_freq: %u\n",
		__func__, caps->num_inputs, caps->num_outputs,
		caps->pps_dpll_idx, caps->synce_dpll_idx,
		caps->max_in_freq);

	return 0;
}

/**
 * iavf_synce_aq_set_input_pin_cfg
 * @adapter: pointer to iavf adapter
 * @input_idx: Input index
 * @flags1: Input flags
 * @flags2: Input flags
 * @freq: Frequency in Hz
 * @phase_delay: Delay in ps
 *
 * Set CGU input config (0x0C62)
 */
static int iavf_synce_aq_set_input_pin_cfg(struct iavf_adapter *adapter,
					   u8 input_idx, u8 flags1, u8 flags2,
					   u32 freq, s32 phase_delay)
{
	struct virtchnl_synce_set_input_pin_cfg *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: input_idx: %u flags1: %u flags2: %u freq: %u phase_delay: %d\n",
		__func__, input_idx, flags1, flags2, freq, phase_delay);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_SET_INPUT_PIN_CFG,
				   sizeof(*cmd));
	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->input_idx = input_idx;
	cmd->flags1 = flags1;
	cmd->flags2 = flags2;
	cmd->freq = freq;
	cmd->phase_delay = phase_delay;
	iavf_queue_vc_msg(adapter, vc_msg);

	return status;
}

/**
 * iavf_synce_aq_get_input_pin_cfg
 * @adapter: pointer to iavf adapter
 * @cfg: DPLL config
 * @input_idx: Input index
 *
 * Get CGU input config (0x0C63)
 */
static int
iavf_synce_aq_get_input_pin_cfg(struct iavf_adapter *adapter,
				struct virtchnl_synce_get_input_pin_cfg *cfg,
				u8 input_idx)
{
	struct virtchnl_synce_get_input_pin_cfg *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_synce *se = &adapter->synce;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: input_idx: %u\n", __func__, input_idx);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_GET_INPUT_PIN_CFG,
				   sizeof(*cmd));

	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->input_idx = input_idx;
	se->input_pin_cfg_ready = false;
	iavf_queue_vc_msg(adapter, vc_msg);

	/*Handle the response from PF */
	status = wait_event_interruptible_timeout(se->input_pin_cfg_waitqueue,
						  se->input_pin_cfg_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	cmd = &se->cached_input_pin_cfg;
	*cfg = *cmd;
	dev_dbg(dev,
		"%s: input_idx: %u status: %u type: %u flags1: %u flags2: %u freq: %u phase_delay: %d\n",
		__func__, input_idx, cfg->status, cfg->type, cfg->flags1,
		cfg->flags2, cfg->freq, cfg->phase_delay);

	return 0;
}

/**
 * iavf_synce_aq_set_output_pin_cfg
 * @adapter: pointer to iavf adapter
 * @output_idx: Output index
 * @flags: Output flags
 * @src_sel: Index of DPLL block
 * @freq: Output frequency
 * @phase_delay: Output phase compensation
 *
 * Set CGU output config (0x0C64)
 */
static int iavf_synce_aq_set_output_pin_cfg(struct iavf_adapter *adapter,
					    u8 output_idx, u8 flags,
					    u8 src_sel, u32 freq,
					    s32 phase_delay)
{
	struct virtchnl_synce_set_output_pin_cfg *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: output_idx: %u flags: %u src_sel: %u freq: %u phase_delay: %d\n",
		__func__, output_idx, flags, src_sel, freq, phase_delay);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_SET_OUTPUT_PIN_CFG,
				   sizeof(*cmd));

	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->output_idx = output_idx;
	cmd->flags = flags;
	cmd->src_sel = src_sel;
	cmd->freq = freq;
	cmd->phase_delay = phase_delay;

	iavf_queue_vc_msg(adapter, vc_msg);

	return status;
}

/**
 * iavf_synce_aq_get_output_pin_cfg
 * @adapter: pointer to iavf adapter
 * @output_idx: Output index
 * @flags: Output flags
 * @src_sel: Internal DPLL source
 * @freq: Output frequency
 * @src_freq: Source frequency
 *
 * Get CGU output config (0x0C65)
 */
static int
iavf_synce_aq_get_output_pin_cfg(struct iavf_adapter *adapter, u8 output_idx,
				 u8 *flags, u8 *src_sel, u32 *freq,
				 u32 *src_freq)
{
	struct virtchnl_synce_get_output_pin_cfg *cmd;
	struct device *dev = &adapter->pdev->dev;
	struct iavf_synce *se = &adapter->synce;
	struct iavf_vc_msg *vc_msg;
	int status = 0;

	dev_dbg(dev, "%s: output_idx: %u\n", __func__, output_idx);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG,
				   sizeof(*cmd));
	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->output_idx = output_idx;
	se->output_pin_cfg_ready = false;
	iavf_queue_vc_msg(adapter, vc_msg);

	/*Handle the response from PF */
	status = wait_event_interruptible_timeout(se->output_pin_cfg_waitqueue,
						  se->output_pin_cfg_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	cmd = &se->cached_output_pin_cfg;
	*flags = cmd->flags;
	*src_sel = cmd->src_sel;
	*freq = cmd->freq;
	*src_freq = cmd->src_freq;

	dev_dbg(dev, "%s: output_idx: %u flags: %u src_sel: %u freq: %u src_freq: %u\n",
		__func__, output_idx, *flags, *src_sel, *freq, *src_freq);

	return 0;
}

/**************************************************
 * iavf synce helper functions
 * ************************************************/
#define iavf_synce_to_dev(synce) (&((synce)->pdev->dev))

#define MAKEMASK(m, s) ((m) << (s))

/**
 * iavf_is_feature_supported
 * @synce: pointer to struct iavf_synce instance
 * @f: feature enum to be checked
 *
 * returns true if feature is supported in synce, false otherwise
 */
static bool iavf_is_feature_supported(struct iavf_synce *synce,
				      enum iavf_sync_feature f)
{
	dev_dbg(iavf_synce_to_dev(synce), "%s: allowed features: %x, feature:%u\n",
		 __func__, synce->features, f);

	if (f < 0 || f >= IAVF_F_MAX)
		return false;

	return (synce->features & (1 << f));
}

/***********************************
 * SyncE Support Data Defines
 ***********************************/
#define IAVF_SYNCE_PIN_INVALID		0xFF
/* "dpll <x> pin <y> prio <z>" (always 6 arguments) */
#define IAVF_SYNCE_PIN_PRIO_ARG_CNT	6

/*
 * Examples of possible argument lists and count:
 * "in pin <n> enable <0/1>"
 * "out pin <n> enable <0/1> freq <x>"
 * "in pin <n> freq <x>"
 * "out pin <n> freq <x> esync <z>"
 * "in pin <n> freq <x> phase_delay <y> esync <0/1>"
 * "out pin <n> enable <0/1> freq <x> phase_delay <y> esync <0/1>"
 *
 * count = 3 + x * 2
 * 3 = target pin arguments (<dir> pin <n>)
 * x = int [1-4]  (up to 4: 'param name' + 'value' pairs)
 * 2 = count of args in pair ('param name' + 'value')
 */
#define IAVF_SYNCE_PIN_CFG_1_ARG_CNT	5
#define IAVF_SYNCE_PIN_CFG_2_ARG_CNT	7
#define IAVF_SYNCE_PIN_CFG_3_ARG_CNT	9
#define IAVF_SYNCE_PIN_CFG_4_ARG_CNT	11

#define	IAVF_SYNCE_PIN_FREQ_1HZ		1
#define	IAVF_SYNCE_PIN_FREQ_10MHZ	10000000

enum iavf_phy_rclk_pins {
	IAVF_C827_RCLKA_PIN,		/* SCL pin */
	IAVF_C827_RCLKB_PIN,		/* SDA pin */
	IAVF_C827_RCLK_PINS_NUM		/* number of pins */
};

#define IAVF_E822_CGU_RCLK_PHY_PINS_NUM		1
#define IAVF_PIN_NAME_LEN			20
#define IAVF_PIN_STATE_LEN			12
static char IAVF_DPLL_PIN_STATE_INVALID[IAVF_PIN_STATE_LEN]	= "invalid";
static char IAVF_DPLL_PIN_STATE_VALID[IAVF_PIN_STATE_LEN]	= "valid";

/* Get CGU output config (direct 0x0C65)-flags bit field */
#define IAVF_AQC_GET_CGU_OUT_CFG_OUT_EN			BIT(0)
#define IAVF_AQC_GET_CGU_OUT_CFG_ESYNC_EN		BIT(1)
#define IAVF_AQC_GET_CGU_OUT_CFG_ESYNC_ABILITY		BIT(2)

/* Get CGU output config (direct 0x0C65)-src_sel bit field */
#define IAVF_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL_SHIFT	0
#define IAVF_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL \
	MAKEMASK(0x1F, IAVF_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL_SHIFT)

/* Set CGU output config (direct 0x0C64)-flags bit field*/
#define IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN			BIT(0)
#define IAVF_AQC_SET_CGU_OUT_CFG_ESYNC_EN		BIT(1)
#define IAVF_AQC_SET_CGU_OUT_CFG_UPDATE_FREQ		BIT(2)
#define IAVF_AQC_SET_CGU_OUT_CFG_UPDATE_PHASE		BIT(3)

/* Set CGU input config (direct 0x0C62)-flags bit field*/
#define IAVF_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ	BIT(6)
#define IAVF_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_DELAY	BIT(7)
#define IAVF_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN		BIT(5)
#define IAVF_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN		BIT(6)

/* Get CGU input config response (direct 0x0C63) status bit field*/
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_LOS		BIT(0)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_SCM_FAIL		BIT(1)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_CFM_FAIL		BIT(2)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_GST_FAIL		BIT(3)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_PFM_FAIL		BIT(4)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_FAIL	BIT(6)
#define IAVF_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_CAP	BIT(7)

#define IAVF_CGU_IN_PIN_FAIL_FLAGS (IAVF_AQC_GET_CGU_IN_CFG_STATUS_SCM_FAIL | \
				    IAVF_AQC_GET_CGU_IN_CFG_STATUS_CFM_FAIL | \
				    IAVF_AQC_GET_CGU_IN_CFG_STATUS_GST_FAIL | \
				    IAVF_AQC_GET_CGU_IN_CFG_STATUS_PFM_FAIL)

/* Get CGU input config response (direct 0x0C63) flags bit field*/
#define IAVF_AQC_GET_CGU_IN_CFG_FLG1_PHASE_DELAY_SUPP	BIT(0)
#define IAVF_AQC_GET_CGU_IN_CFG_FLG1_1PPS_SUPP		BIT(2)
#define IAVF_AQC_GET_CGU_IN_CFG_FLG1_10MHZ_SUPP		BIT(3)
#define IAVF_AQC_GET_CGU_IN_CFG_FLG1_ANYFREQ		BIT(7)
#define IAVF_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN		BIT(5)
#define IAVF_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN		BIT(6)

/***********************************
 * sysfs functionality support
 ***********************************/
#define IAVF_MAX_DPLL_NAME_LEN 4
struct iavf_dpll_desc {
	char name[IAVF_MAX_DPLL_NAME_LEN];
	u8 index;
};

static const struct iavf_dpll_desc e810t_dplls[] = {
	/* name  idx */
	{ "EEC", IAVF_CGU_DPLL_SYNCE },
	{ "PPS", IAVF_CGU_DPLL_PTP },
};

struct iavf_dpll_attribute {
	struct device_attribute attr;
	u8 dpll_num;
};

static ssize_t synce_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count);

static ssize_t pin_cfg_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len);

static ssize_t pin_cfg_show(struct device *dev, struct device_attribute *attr,
			    char *buf);

static ssize_t dpll_1_offset_show(struct device *dev,
				  struct device_attribute *attr, char *buf);

static ssize_t dpll_name_show(struct device *dev,
			      struct device_attribute *attr, char *buf);

static ssize_t dpll_state_show(struct device *dev,
			       struct device_attribute *attr, char *buf);

static ssize_t dpll_ref_pin_show(struct device *dev,
				 struct device_attribute *attr, char *buf);

static struct kobj_attribute synce_attribute = __ATTR_WO(synce);
static DEVICE_ATTR_RW(pin_cfg);
static DEVICE_ATTR_RO(dpll_1_offset);
static struct iavf_dpll_attribute *dpll_name_attrs;
static struct iavf_dpll_attribute *dpll_state_attrs;
static struct iavf_dpll_attribute *dpll_ref_pin_attrs;

#define IAVF_DPLL_MAX_INPUT_PIN_PRIO	14

/**
 * iavf_synce_parse_and_apply_pin_prio - parse and apply pin prio from the buffer
 * @synce: pointer to a iavf_synce structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse pin prio config from the split user buffer and apply it on given pin.
 * Return 0 on success, negative value otherwise
 */
static int iavf_synce_parse_and_apply_pin_prio(struct iavf_synce *synce,
					       int argc, char **argv)
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
	if (prio > IAVF_DPLL_MAX_INPUT_PIN_PRIO)
		return -EINVAL;

	dev_dbg(iavf_synce_to_dev(synce), "%s: dpll: %u, pin:%u, prio:%u\n",
		 __func__, dpll, pin, prio);

	return iavf_synce_aq_set_cgu_ref_prio(synce->adapter, dpll, pin, prio);
}

/**
 * iavf_synce_parse_and_apply_output_pin_cfg - parse and apply output pin config
 * @synce: pointer to a iavf_synce structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse and apply given configuration items in a split user buffer for the
 * output pin.
 * Return 0 on success, negative value otherwise
 */
static int iavf_synce_parse_and_apply_output_pin_cfg(struct iavf_synce *synce,
						     int argc, char **argv)
{
	u8 output_idx, flags = 0, old_flags, old_src_sel;
	u32 freq = 0, old_freq, old_src_freq;
	bool esync_en_valid = false;
	bool pin_en_valid = false;
	bool esync_en = false;
	bool pin_en = false;
	s32 phase_delay = 0;
	int i, ret;

	output_idx = IAVF_SYNCE_PIN_INVALID;
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "pin", sizeof("pin"))) {
			ret = kstrtou8(argv[++i], 0, &output_idx);
		} else if (!strncmp(argv[i], "freq", sizeof("freq"))) {
			ret = kstrtou32(argv[++i], 0, &freq);
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_UPDATE_FREQ;
		} else if (!strncmp(argv[i], "phase_delay",
				    sizeof("phase_delay"))) {
			ret = kstrtos32(argv[++i], 0, &phase_delay);
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_UPDATE_PHASE;
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
		ret = iavf_synce_aq_get_output_pin_cfg(synce->adapter,
						       output_idx, &old_flags,
						       &old_src_sel, &old_freq,
						       &old_src_freq);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"Failed to read prev output pin cfg (%u:%s)",
				ret, "SyncE AdminQ Error");
			return ret;
		}
	}

	if (!esync_en_valid)
		if (old_flags & IAVF_AQC_GET_CGU_OUT_CFG_ESYNC_EN)
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		else
			flags &= ~IAVF_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
	else
		if (esync_en)
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		else
			flags &= ~IAVF_AQC_SET_CGU_OUT_CFG_ESYNC_EN;

	if (!pin_en_valid)
		if (old_flags & IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN)
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN;
		else
			flags &= ~IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN;
	else
		if (pin_en)
			flags |= IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN;
		else
			flags &= ~IAVF_AQC_SET_CGU_OUT_CFG_OUT_EN;

	dev_dbg(iavf_synce_to_dev(synce),
		"output pin:%u, enable: %u, freq:%u, phase_delay:%u, esync:%u, flags:%u\n",
		output_idx, pin_en, freq, phase_delay, esync_en, flags);

	return iavf_synce_aq_set_output_pin_cfg(synce->adapter, output_idx,
						flags, 0, freq, phase_delay);
}

/**
 * iavf_synce_parse_and_apply_input_pin_cfg - parse and apply input pin config
 * @synce: pointer to a iavf_synce structure
 * @argc: number of arguments to parse
 * @argv: list of human readable configuration parameters
 *
 * Parse and apply given list of configuration items for the input pin.
 * Return 0 on success, negative value otherwise
 */
static int iavf_synce_parse_and_apply_input_pin_cfg(struct iavf_synce *synce,
						    int argc, char **argv)
{
	struct virtchnl_synce_get_input_pin_cfg old_cfg = {0};
	u8 flags1 = 0, flags2 = 0, input_idx;
	bool esync_en_valid = false;
	bool pin_en_valid = false;
	bool esync_en = false;
	bool pin_en = false;
	s32 phase_delay = 0;
	u32 freq = 0;
	int i, ret;

	input_idx = IAVF_SYNCE_PIN_INVALID;
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "pin", sizeof("pin"))) {
			ret = kstrtou8(argv[++i], 0, &input_idx);
		} else if (!strncmp(argv[i], "freq", sizeof("freq"))) {
			ret = kstrtou32(argv[++i], 0, &freq);
			flags1 |= IAVF_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ;
		} else if (!strncmp(argv[i], "phase_delay",
				    sizeof("phase_delay"))) {
			ret = kstrtos32(argv[++i], 0, &phase_delay);
			flags1 |= IAVF_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_DELAY;
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
		ret = iavf_synce_aq_get_input_pin_cfg(synce->adapter, &old_cfg,
						      input_idx);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"Failed to read prev intput pin cfg (%u:%s)",
				ret, "SyncE AdminQ Error");
			return ret;
		}
	}

	if (flags1 == IAVF_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ &&
	    !(old_cfg.flags1 & IAVF_AQC_GET_CGU_IN_CFG_FLG1_ANYFREQ)) {
		if (freq != IAVF_SYNCE_PIN_FREQ_1HZ &&
		    freq != IAVF_SYNCE_PIN_FREQ_10MHZ) {
			dev_err(iavf_synce_to_dev(synce),
				"Only %i or %i freq supported\n",
				IAVF_SYNCE_PIN_FREQ_1HZ,
				IAVF_SYNCE_PIN_FREQ_10MHZ);
			return -EINVAL;
		}
	}

	if (!esync_en_valid)
		if (old_cfg.flags2 & IAVF_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)
			flags2 |= IAVF_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		else
			flags2 &= ~IAVF_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
	else
		if (esync_en)
			flags2 |= IAVF_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		else
			flags2 &= ~IAVF_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;

	if (!pin_en_valid)
		if (old_cfg.flags2 & IAVF_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN)
			flags2 |= IAVF_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		else
			flags2 &= ~IAVF_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
	else
		if (pin_en)
			flags2 |= IAVF_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		else
			flags2 &= ~IAVF_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;

	dev_dbg(iavf_synce_to_dev(synce),
		 "input pin:%u, enable: %u, freq:%u, phase_delay:%u, esync:%u, flags1:%u, flags2:%u\n",
		 input_idx, pin_en, freq, phase_delay, esync_en,
		 flags1, flags2);

	return iavf_synce_aq_set_input_pin_cfg(synce->adapter, input_idx,
					       flags1, flags2, freq,
					       phase_delay);
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
static ssize_t synce_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct iavf_adapter *adapter;
	unsigned int ena, phy_pin;
	struct iavf_synce *synce;
	const char *pin_name;
	struct device *dev;
	u32 freq = 0;
	u8 pin, phy;
	int status;
	int cnt;

	adapter = iavf_kobj_to_iavf(kobj);
	if (WARN_ON(!adapter || !adapter->pdev))
		return -EINVAL;

	synce = &adapter->synce;
	dev = &adapter->pdev->dev;

	cnt = sscanf(buf, "%u %u", &ena, &phy_pin);
	if (cnt != 2 || phy_pin >= IAVF_C827_RCLK_PINS_NUM)
		return -EINVAL;

	/* set phy rec clk out iavf_synce_aq_set_phy_rec_clk_out */
	status = iavf_synce_aq_set_phy_rec_clk_out(adapter, phy_pin, ena,
						   &freq);

	if (status)
		return -EIO;

	phy = synce->C827_idx;
	pin = IAVF_CGU_INPUT_C827(phy, phy_pin);
	pin_name = iavf_zl_pin_idx_to_name_e810t(pin);

	dev_dbg(dev, "%s recovered clock: pin %s\n",
		 !!ena ? "Enabled" : "Disabled", pin_name);

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
	struct iavf_adapter *adapter;
	struct iavf_synce *synce;
	int argc, ret;
	char **argv;

	adapter = iavf_kdev_to_iavf(dev);
	if (WARN_ON(!adapter))
		return -EINVAL;

	synce = &adapter->synce;

	if (iavf_is_reset_in_progress(adapter))
		return -EAGAIN;

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;

	if (argc == IAVF_SYNCE_PIN_PRIO_ARG_CNT) {
		ret = iavf_synce_parse_and_apply_pin_prio(synce, argc, argv);
	} else if (argc == IAVF_SYNCE_PIN_CFG_1_ARG_CNT ||
		   argc == IAVF_SYNCE_PIN_CFG_2_ARG_CNT ||
		   argc == IAVF_SYNCE_PIN_CFG_3_ARG_CNT ||
		   argc == IAVF_SYNCE_PIN_CFG_4_ARG_CNT) {
		if (!strncmp(argv[0], "in", sizeof("in"))) {
			ret = iavf_synce_parse_and_apply_input_pin_cfg(synce,
								    argc - 1,
								    argv + 1);
		} else if (!strncmp(argv[0], "out", sizeof("out"))) {
			ret = iavf_synce_parse_and_apply_output_pin_cfg(synce,
								     argc - 1,
								     argv + 1);
		} else {
			ret = -EINVAL;
			dev_dbg(dev,
				"%s: wrong pin direction argument:%s\n",
				__func__, argv[0]);
		}
	} else {
		ret = -EINVAL;
		dev_dbg(dev, "%s: wrong number of arguments:%d\n", __func__,
			argc);
		dev_dbg(dev, "%s: Right number of arguments are dpll(6), in/out(5, 7, 9, 11)\n",
			__func__);
	}

	if (!ret)
		ret = len;
	argv_free(argv);

	return ret;
}

/**
 * iavf_synce_load_output_pin_cfg - load formated output pin config into buffer
 * @synce: pointer to iavf_synce structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 * @pin_num: number of output pins to be printed
 *
 * Acquires configuration of output pins from FW and load it into
 * provided user buffer.
 * Returns total number of bytes written to the buffer.
 * Negative on failure.
 */
static int iavf_synce_load_output_pin_cfg(struct iavf_synce *synce, char *buf,
					  ssize_t offset, const u8 pin_num)
{
	u8 pin, pin_en, esync_en, dpll, flags;
	int count = offset;
	u32 freq, src_freq;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "out");
	count += scnprintf(buf + count, PAGE_SIZE,
			   "|%4s|%8s|%5s|%11s|%6s|\n",
			   "pin", "enabled", "dpll", "freq", "esync");
	for (pin = 0; pin < pin_num; ++pin) {
		int ret = iavf_synce_aq_get_output_pin_cfg(synce->adapter, pin,
							   &flags, &dpll,
							   &freq, &src_freq);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"err:%d %s failed to read output pin cfg on pin:%u\n",
				ret, "SyncE AdminQ Error",
				pin);
			return ret;
		}

		esync_en = !!(flags & IAVF_AQC_GET_CGU_OUT_CFG_ESYNC_EN);
		pin_en = !!(flags & IAVF_AQC_GET_CGU_OUT_CFG_OUT_EN);
		dpll &= IAVF_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL;
		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%5u|%11u|%6u|\n",
				   pin, pin_en, dpll, freq, esync_en);
	}

	return count;
}

/**
 * iavf_synce_load_input_pin_cfg - load formated input pin config into buffer
 * @synce: pointer to iavf_synce structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 * @pin_num: number of input pins to be printed
 *
 * Acquires configuration of input pins from FW and load it into
 * provided user buffer.
 * Returns total number of bytes written to the buffer.
 * Negative on failure.
 */
static int iavf_synce_load_input_pin_cfg(struct iavf_synce *synce, char *buf,
					 ssize_t offset, const u8 pin_num)
{
	u8 pin, pin_en, esync_en, esync_fail, dpll0_prio, dpll1_prio;
	struct virtchnl_synce_get_input_pin_cfg in_cfg;
	const char *pin_state;
	int count = offset;
	s32 phase_delay;
	u32 freq;
	int ret;

	count += scnprintf(buf + count, PAGE_SIZE, "%s\n", "in");
	count += scnprintf(buf + count, PAGE_SIZE,
			  "|%4s|%8s|%8s|%11s|%12s|%6s|%11s|%11s|\n",
			   "pin", "enabled", "state", "freq", "phase_delay",
			   "esync", "DPLL0 prio", "DPLL1 prio");

	for (pin = 0; pin < pin_num; ++pin) {
		memset(&in_cfg, 0, sizeof(in_cfg));

		ret = iavf_synce_aq_get_input_pin_cfg(synce->adapter, &in_cfg,
						      pin);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"err:%d %s failed to read input pin cfg on pin:%u\n",
				ret, "SyncE AdminQ Error",
				pin);
			return ret;
		}

		ret = iavf_synce_aq_get_cgu_ref_prio(synce->adapter,
						     IAVF_CGU_DPLL_SYNCE, pin,
						     &dpll0_prio);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"err:%d %s failed to read DPLL0 pin prio on pin:%u\n",
				ret, "SyncE AdminQ Error",
				pin);
			return ret;
		}

		ret = iavf_synce_aq_get_cgu_ref_prio(synce->adapter,
						     IAVF_CGU_DPLL_PTP,
						     pin, &dpll1_prio);
		if (ret) {
			dev_err(iavf_synce_to_dev(synce),
				"err:%d %s failed to read DPLL1 pin prio on pin:%u\n",
				ret, "SyncE AdminQ Error",
				pin);
			return ret;
		}

		esync_en = !!(in_cfg.flags2 &
			      IAVF_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN);
		esync_fail = !!(in_cfg.status &
				IAVF_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_FAIL);
		pin_en = !!(in_cfg.flags2 &
			    IAVF_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN);
		phase_delay = in_cfg.phase_delay;
		freq = in_cfg.freq;

		if (in_cfg.status & IAVF_CGU_IN_PIN_FAIL_FLAGS)
			pin_state = IAVF_DPLL_PIN_STATE_INVALID;
		else if (esync_en && esync_fail)
			pin_state = IAVF_DPLL_PIN_STATE_INVALID;
		else
			pin_state = IAVF_DPLL_PIN_STATE_VALID;

		count += scnprintf(buf + count, PAGE_SIZE,
				   "|%4u|%8u|%8s|%11u|%12d|%6u|%11u|%11u|\n",
				   in_cfg.input_idx, pin_en, pin_state, freq,
				   phase_delay, esync_en, dpll0_prio,
				   dpll1_prio);
	}

	return count;
}

/**
 * iavf_synce_load_pin_cfg - load formated pin config into user buffer
 * @synce: pointer to iavf_synce structure
 * @buf: user buffer to fill with returned data
 * @offset: added to buf pointer before first time writing to it
 *
 * Acquires configuration from FW and load it into provided buffer.
 * Returns total number of bytes written to the buffer
 */
static ssize_t iavf_synce_load_pin_cfg(struct iavf_synce *synce,
				       char *buf, ssize_t offset)
{
	struct virtchnl_synce_get_cgu_abilities abilities;
	int ret;

	memset(&abilities, 0, sizeof(abilities));

	ret = iavf_synce_aq_get_cgu_abilities(synce->adapter, &abilities);
	if (ret) {
		dev_err(iavf_synce_to_dev(synce),
			"err:%d %s failed to read cgu abilities\n",
			ret, "SyncE AdminQ Error");
		return ret;
	}

	ret = iavf_synce_load_input_pin_cfg(synce, buf, offset,
					    abilities.num_inputs);
	if (ret < 0)
		return ret;
	offset += ret;
	ret = iavf_synce_load_output_pin_cfg(synce, buf, offset,
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
static ssize_t pin_cfg_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct iavf_adapter *adapter;
	struct iavf_synce *synce;

	adapter = iavf_kdev_to_iavf(dev);
	if (WARN_ON(!adapter))
		return -EINVAL;

	synce = &adapter->synce;

	dev_dbg(dev, "%s: Device Attribute Name %s\n", __func__,
		attr->attr.name);

	return iavf_synce_load_pin_cfg(synce, buf, 0);
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
	struct iavf_dpll_attribute *dpll_attr;
	u8 dpll_num;

	dpll_attr = container_of(attr, struct iavf_dpll_attribute, attr);
	dpll_num = dpll_attr->dpll_num;

	if (dpll_num < IAVF_CGU_DPLL_MAX)
		return snprintf(buf, PAGE_SIZE, "%s\n",
				e810t_dplls[dpll_num].name);

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
	struct iavf_dpll_attribute *dpll_attr;
	enum iavf_cgu_state dpll_state;
	struct iavf_adapter *adapter;
	struct iavf_synce *synce;
	ssize_t cnt;

	adapter = iavf_kdev_to_iavf(dev);
	if (WARN_ON(!adapter))
		return -EINVAL;

	synce = &adapter->synce;
	dpll_attr = container_of(attr, struct iavf_dpll_attribute, attr);

	switch (dpll_attr->dpll_num) {
	case IAVF_CGU_DPLL_SYNCE:
		/* get virtchnl_synce_get_cgu_dpll_status from pf */
		dpll_state = synce->synce_dpll_state;
		break;
	case IAVF_CGU_DPLL_PTP:
		/* get virtchnl_synce_get_cgu_dpll_status from pf */
		dpll_state = synce->ptp_dpll_state;
		break;
	default:
		return -EINVAL;
	}

	cnt = snprintf(buf, PAGE_SIZE, "%d\n", dpll_state);
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
				 struct device_attribute *attr, char *buf)
{
	struct iavf_dpll_attribute *dpll_attr;
	enum iavf_cgu_state dpll_state;
	struct iavf_adapter *adapter;
	struct iavf_synce *synce;
	u8 ref_state, eec_mode;
	s64 phase_offset;
	ssize_t cnt;
	int status;
	u8 pin;

	adapter = iavf_kdev_to_iavf(dev);
	if (WARN_ON(!adapter))
		return -EINVAL;

	synce = &adapter->synce;
	dpll_attr = container_of(attr, struct iavf_dpll_attribute, attr);

	switch (dpll_attr->dpll_num) {
	case IAVF_CGU_DPLL_SYNCE:
		/* get virtchnl_synce_get_cgu_dpll_status from pf */
		/* get ref pin info from pf */
		status = iavf_synce_aq_get_cgu_dpll_status(adapter,
							   IAVF_CGU_DPLL_SYNCE,
							   &ref_state,
							   (u16 *)&dpll_state,
							   &phase_offset,
							   &eec_mode);
		if (status)
			return -EIO;
		dpll_state = iavf_parse_dpll_state((u16)dpll_state,
						   synce->synce_dpll_state);
		break;
	case IAVF_CGU_DPLL_PTP:
		/* get virtchnl_synce_get_cgu_dpll_status from pf */
		status = iavf_synce_aq_get_cgu_dpll_status(adapter,
							   IAVF_CGU_DPLL_PTP,
							   &ref_state,
							   (u16 *)&dpll_state,
							   &phase_offset,
							   &eec_mode);
		if (status)
			return -EIO;
		dpll_state = iavf_parse_dpll_state((u16)dpll_state,
						   synce->ptp_dpll_state);
		break;
	default:
		return -EINVAL;
	}

	pin = parse_dpll_ref_pin(synce->cached_cgu_dpll_status.dpll_state);
	switch (dpll_state) {
	case IAVF_CGU_STATE_LOCKED:
	case IAVF_CGU_STATE_LOCKED_HO_ACQ:
	case IAVF_CGU_STATE_HOLDOVER:
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
	enum iavf_cgu_state dpll_state;
	struct iavf_adapter *adapter;
	s64 dpll_phase_offset = 0;
	u8 ref_state, eec_mode;
	int status;

	adapter = iavf_kdev_to_iavf(dev);
	if (WARN_ON(!adapter))
		return -EINVAL;
	/* send virtchnl_synce_get_cgu_dpll_status for dpll phase offset */
	status = iavf_synce_aq_get_cgu_dpll_status(adapter, IAVF_CGU_DPLL_PTP,
						   &ref_state,
						   (u16 *)&dpll_state,
						   &dpll_phase_offset,
						   &eec_mode);
	if (status)
		return -EIO;

	return snprintf(buf, PAGE_SIZE, "%lld\n", dpll_phase_offset);
}

/***********************************************************
 *SyncE DPLL & RCLK Status Data Defines & Functions
 ***********************************************************/
#define IAVF_E810T_NEVER_USE_PIN 0xff
#define IAVF_ZL_VER_MAJOR_SHIFT	24
#define IAVF_ZL_VER_MAJOR_MASK	MAKEMASK(0xff, IAVF_ZL_VER_MAJOR_SHIFT)
#define IAVF_ZL_VER_MINOR_SHIFT	16
#define IAVF_ZL_VER_MINOR_MASK	MAKEMASK(0xff, IAVF_ZL_VER_MINOR_SHIFT)
#define IAVF_ZL_VER_REV_SHIFT	8
#define IAVF_ZL_VER_BF_SHIFT	0
#define IAVF_ZL_VER_REV_MASK	MAKEMASK(0xff, IAVF_ZL_VER_REV_SHIFT)
#define IAVF_ZL_VER_BF_MASK	MAKEMASK(0xff, IAVF_ZL_VER_BF_SHIFT)
#define IAVF_ACQ_GET_LINK_TOPO_NODE_NR_ZL30632_80032		0x24
#define IAVF_ACQ_GET_LINK_TOPO_NODE_NR_SI5383_5384		0x25
#define IAVF_ACQ_GET_LINK_TOPO_NODE_NR_E822_PHY			0x30
#define IAVF_ACQ_GET_LINK_TOPO_NODE_NR_C827			0x31
#define IAVF_ACQ_GET_LINK_TOPO_NODE_NR_GEN_CLK_MUX		0x47
#define IAVF_FLAG_DPLL_MONITOR					0x02
#define IAVF_SET_PHY_REC_CLK_OUT_OUT_EN	BIT(0)

enum iavf_e810_c827_idx {
	IAVF_C827_0,
	IAVF_C827_1
};

/**
 * iavf_cgu_state_to_name - get the name of CGU state
 * @state: state of the CGU
 *
 * Return: name of CGU state
 */
static const char *iavf_cgu_state_to_name(int state)
{
	switch (state) {
	case IAVF_CGU_STATE_INVALID:
		return "invalid";
	case IAVF_CGU_STATE_FREERUN:
		return "freerun";
	case IAVF_CGU_STATE_LOCKED:
		return "locked";
	case IAVF_CGU_STATE_LOCKED_HO_ACQ:
		return "locked_ho_acq";
	case IAVF_CGU_STATE_HOLDOVER:
		return "holdover";
	case IAVF_CGU_STATE_UNKNOWN:
	default:
		return "unknown";
	}
}

/**
 * iavf_dpll_pin_idx_to_name - Return pin name for a corresponding pin
 * @adapter: pointer to the iavf adapter instance
 * @pin: pin number to get name for
 * @pin_name: pointer to pin name buffer
 *
 * A wrapper for device-specific pin index to name converters that take care
 * of mapping pin indices returned by a netlist to real pin names
 */
static void
iavf_dpll_pin_idx_to_name(struct iavf_adapter *adapter, u8 pin, char *pin_name)
{
	struct iavf_synce *synce = &adapter->synce;
	int cnt;
	int i;

	for (i = 0; i < synce->hw_info.len; ++i) {
		if (synce->cgu_pins[i].pin_index == pin) {
			cnt = snprintf(pin_name, IAVF_MAX_PIN_NAME_LEN, "%s",
				       synce->cgu_pins[i].name);
			snprintf(pin_name + cnt, IAVF_MAX_PIN_NAME_LEN - cnt,
				       " Pin %i", pin);
			break;
		}
	}
}

/***********************************************************
 *SyncE sysfs Node Init & De-Init
 ***********************************************************/
/**
 * iavf_phy_sysfs_init - initialize sysfs for DPLL
 * @synce: pointer to iavf_synce structure
 *
 * Initialize sysfs for handling DPLL in HW.
 */
static void iavf_phy_sysfs_init(struct iavf_synce *synce)
{
	struct kobject *phy_kobj;

	phy_kobj = kobject_create_and_add("phy", &synce->pdev->dev.kobj);
	if (!phy_kobj) {
		dev_err(iavf_synce_to_dev(synce),
			"Failed to create PHY kobject\n");
		return;
	}

	if (sysfs_create_file(phy_kobj, &synce_attribute.attr)) {
		dev_err(iavf_synce_to_dev(synce),
			"Failed to create synce sysfs file\n");
		kobject_put(phy_kobj);
		return;
	}

	synce->phy_kobj = phy_kobj;
}

/**
 * iavf_pin_cfg_sysfs_init - initialize sysfs for pin_cfg
 * @synce: pointer to iavf_synce structure
 *
 * Initialize sysfs for handling pin configuration in DPLL.
 */
static void iavf_pin_cfg_sysfs_init(struct iavf_synce *synce)
{
	if (device_create_file(iavf_synce_to_dev(synce), &dev_attr_pin_cfg))
		dev_err(iavf_synce_to_dev(synce),
			"Failed to create pin_cfg sysfs file\n");
}

/**
 * iavf_dpll_1_offset_init - initialize sysfs for dpll_1_offset
 * @synce: pointer to iavf_synce structure
 *
 * Initialize sysfs for handling dpll_1_offset in DPLL.
 */
static void iavf_dpll_1_offset_init(struct iavf_synce *synce)
{
	if (device_create_file(iavf_synce_to_dev(synce),
			       &dev_attr_dpll_1_offset))
		dev_err(iavf_synce_to_dev(synce),
			"Failed to create dpll_1_offset sysfs file\n");
}

/**
 * iavf_dpll_attrs_init - initialize sysfs for dpll_attribute
 * @synce: pointer to iavf_synce structure
 * @name_suffix: sysfs file name suffix
 * @show: pointer to a show operation handler
 *
 * Helper function to allocate and initialize sysfs for dpll_attribute array
 * Returns pointer to dpll_attribute struct on success, ERR_PTR on error
 */
static struct iavf_dpll_attribute *
iavf_dpll_attrs_init(struct iavf_synce *synce, const char *name_suffix,
		     ssize_t (*show)(struct device *dev,
		     struct device_attribute *attr, char *buf))
{
	struct device *dev = iavf_synce_to_dev(synce);
	struct iavf_dpll_attribute *dpll_attr;
	int err, i = 0;
	char *name;

	dpll_attr = devm_kcalloc(dev, IAVF_CGU_DPLL_MAX, sizeof(*dpll_attr),
				 GFP_KERNEL);
	if (!dpll_attr) {
		err = -ENOMEM;
		goto err;
	}

	for (i = 0; i < IAVF_CGU_DPLL_MAX; ++i) {
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
		err = device_create_file(dev, &dpll_attr[i].attr);
		if (err)
			goto err;
	}

	return dpll_attr;

err:
	while (--i >= 0) {
		if (dpll_attr[i].attr.attr.name)
			devm_kfree(dev, (char *)dpll_attr[i].attr.attr.name);
		device_remove_file(dev, &dpll_attr[i].attr);
	}

	devm_kfree(dev, dpll_attr);
	dev_err(dev, "Failed to create %s sysfs files\n", name_suffix);

	return (struct iavf_dpll_attribute *)ERR_PTR(err);
}

/**
 * iavf_synce_sysfs_init - initialize sysfs for synce access
 * @synce: pointer to iavf_synce structure
 *
 * Initialize sysfs for querying configuration of synce device.
 */
static void iavf_synce_sysfs_init(struct iavf_synce *synce)
{
	if (iavf_is_feature_supported(synce, IAVF_F_PHY_RCLK))
		iavf_phy_sysfs_init(synce);

	if (iavf_is_feature_supported(synce, IAVF_F_CGU)) {
		iavf_pin_cfg_sysfs_init(synce);
		iavf_dpll_1_offset_init(synce);
		dpll_name_attrs = iavf_dpll_attrs_init(synce, "name",
						       dpll_name_show);
		dpll_state_attrs = iavf_dpll_attrs_init(synce, "state",
							dpll_state_show);
		dpll_ref_pin_attrs = iavf_dpll_attrs_init(synce, "ref_pin",
							  dpll_ref_pin_show);
	}
}

/**
 * iavf_synce_sysfs_release - release sysfs resources of ptp and synce features
 * @synce: pointer to iavf_synce structure
 *
 * Release sysfs interface resources for handling configuration of
 * ptp and synce features.
 */
static void iavf_synce_sysfs_release(struct iavf_synce *synce)
{
	if (synce->phy_kobj) {
		sysfs_remove_file(synce->phy_kobj, &synce_attribute.attr);
		kobject_put(synce->phy_kobj);
		synce->phy_kobj = NULL;
	}

	if (iavf_is_feature_supported(synce, IAVF_F_CGU)) {
		struct device *dev = iavf_synce_to_dev(synce);
		int i;

		device_remove_file(dev, &dev_attr_pin_cfg);
		device_remove_file(dev, &dev_attr_dpll_1_offset);
		for (i = 0; i < IAVF_CGU_DPLL_MAX; ++i) {
			if (!IS_ERR(dpll_name_attrs))
				device_remove_file(dev,
						   &dpll_name_attrs[i].attr);
			if (!IS_ERR(dpll_state_attrs))
				device_remove_file(dev,
						   &dpll_state_attrs[i].attr);
			if (!IS_ERR(dpll_ref_pin_attrs))
				device_remove_file(dev,
						   &dpll_ref_pin_attrs[i].attr);
		}
	}
}

/************************************
 * iavf synce API
 ************************************/
/**
 * iavf_synce_probe - Initialize iavf synce @ iavf driver probe stage
 * @adapter: pointer to iavf adapter
 *
 * Initialize data fields of iavf synce structure
 */
void iavf_synce_probe(struct iavf_adapter *adapter)
{
	if (WARN_ON(!adapter))
		return;

	adapter->synce.adapter = adapter;

	init_waitqueue_head(&adapter->synce.phy_rec_clk_out_waitqueue);
	init_waitqueue_head(&adapter->synce.cgu_dpll_stat_waitqueue);
	init_waitqueue_head(&adapter->synce.cgu_ref_prio_waitqueue);
	init_waitqueue_head(&adapter->synce.cgu_info_waitqueue);
	init_waitqueue_head(&adapter->synce.cgu_abilities_waitqueue);
	init_waitqueue_head(&adapter->synce.input_pin_cfg_waitqueue);
	init_waitqueue_head(&adapter->synce.output_pin_cfg_waitqueue);
}

/**
 * iavf_synce_init - Initialize iavf synce when iavf driver is being
 * configured
 * @adapter: pointer to iavf adapter
 *
 * Initialize iavf synce, and get synce hw info from PF
 */
void iavf_synce_init(struct iavf_adapter *adapter)
{
	struct iavf_synce *synce = &adapter->synce;
	struct device *dev = &adapter->pdev->dev;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_SYNCE))
		return;

	if (WARN_ON(synce->initialized)) {
		dev_err(dev, "SyncE functionality was already initialized!\n");
		return;
	}
	synce->pdev = adapter->pdev;
	if (iavf_synce_aq_get_hw_info(adapter)) {
		dev_err(dev, "HW Info Not Available!\n");
		return;
	}
	/* Parse PF features on CGU and PHY RCLK presence */
	if (synce->hw_info.cgu_present)
		synce->features |= 1 << IAVF_F_CGU;
	if (synce->hw_info.rclk_present)
		synce->features |= 1 << IAVF_F_PHY_RCLK;
	synce->C827_idx = synce->hw_info.c827_idx;
	synce->state = adapter->state;
	iavf_synce_sysfs_init(synce);
	synce->log_pending = (u8)IAVF_CGU_DPLL_SYNCE;
	synce->synce_dpll_state = IAVF_CGU_STATE_FREERUN;
	synce->ptp_dpll_state = IAVF_CGU_STATE_FREERUN;
	synce->scheduled_jiffies = jiffies + 20 * HZ;
	synce->initialized = true;
}

/**
 * iavf_synce_op_match - Check if any pending iavf synce virtchnl opcodes
 * @pending_op: virtchnl opcode
 *
 * Return true if pending opcode is one of iavf synce virtchnl opcodes
 * otherwise return false
 */
static bool iavf_synce_op_match(enum virtchnl_ops pending_op)
{
	if (pending_op == VIRTCHNL_OP_SYNCE_GET_PHY_REC_CLK_OUT ||
	    pending_op == VIRTCHNL_OP_SYNCE_SET_PHY_REC_CLK_OUT ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_CGU_REF_PRIO ||
	    pending_op == VIRTCHNL_OP_SYNCE_SET_CGU_REF_PRIO ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_INPUT_PIN_CFG ||
	    pending_op == VIRTCHNL_OP_SYNCE_SET_INPUT_PIN_CFG ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_OUTPUT_PIN_CFG ||
	    pending_op == VIRTCHNL_OP_SYNCE_SET_OUTPUT_PIN_CFG ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_CGU_ABILITIES ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_CGU_DPLL_STATUS ||
	    pending_op == VIRTCHNL_OP_SYNCE_SET_CGU_DPLL_CONFIG ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_CGU_INFO ||
	    pending_op == VIRTCHNL_OP_SYNCE_GET_HW_INFO)
		return true;

	return false;
}

/**
 * iavf_synce_release - Release  synce proxy resources
 * @adapter: pointer to iavf adapter
 *
 * Clean up any pending iavf synce virtchnl messages
 */
void iavf_synce_release(struct iavf_adapter *adapter)
{
	if (adapter->synce.initialized == false) {
		dev_dbg(&adapter->pdev->dev,
			"SyncE functionality was not initialized!\n");
		return;
	}

	iavf_flush_vc_msg_queue(adapter, iavf_synce_op_match);
	iavf_synce_sysfs_release(&adapter->synce);
	adapter->synce.initialized = false;
}

/**
 * iavf_synce_dpll_update - log dpll status
 * @adapter: pointer to iavf adapter
 *
 * Poll PF for dpll status and log periodically
 */
void iavf_synce_dpll_update(struct iavf_adapter *adapter)
{
	struct iavf_synce *synce = &adapter->synce;
	unsigned long current_jiffies = jiffies;

	/* check if it is time to initiate pf polling
	 * get the jiffies and check it w/ the scheduled jiffies
	 * if it time_after, go ahead, mark it let virtchnl callback to
	 * get dpll status log, if not, unblock watchdog task
	 */
	if (time_after(current_jiffies, synce->scheduled_jiffies)) {
		iavf_synce_start_cgu_dpll_status_log(adapter,
						     IAVF_CGU_DPLL_SYNCE);
		synce->log_pending = (u8)IAVF_CGU_DPLL_SYNCE;
		synce->scheduled_jiffies +=
			msecs_to_jiffies(IAVF_PERIODIC_LOG_INTERVAL_IN_MSEC);
	}
}
