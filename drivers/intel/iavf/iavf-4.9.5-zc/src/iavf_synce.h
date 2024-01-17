/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#ifndef _IAVF_SYNCE_H_
#define _IAVF_SYNCE_H_

#include "iavf.h"

enum iavf_sync_feature {
	IAVF_F_CGU,		/* CGU Presence */
	IAVF_F_PHY_RCLK,	/* PHY RCLK Presence */
	IAVF_F_MAX
};

enum iavf_cgu_state {
	IAVF_CGU_STATE_UNKNOWN = -1,
	IAVF_CGU_STATE_INVALID,		/* State is not valid */
	IAVF_CGU_STATE_FREERUN,		/* Clock is free-running */
	IAVF_CGU_STATE_LOCKED,		/* Clock is locked to the reference,
					 * but the holdover memory is not valid
					 */
	IAVF_CGU_STATE_LOCKED_HO_ACQ,	/* Clock is locked to the reference
					 * and holdover memory is valid
					 */
	IAVF_CGU_STATE_HOLDOVER,	/* Clock is in holdover mode */
	IAVF_CGU_STATE_MAX
};

/* fields used for SyncE Support */
struct iavf_synce {
	u8 features;			/* Features mirrored @ synce proxy */
	u32 state;			/* State of SyncE */
	struct iavf_adapter *adapter;	/* iAVF adapter for VC */
	struct pci_dev *pdev;		/* Point to iAVF pdev to attach sysfs */
	struct kobject *phy_kobj;
	wait_queue_head_t phy_rec_clk_out_waitqueue;
	bool phy_rec_clk_out_ready;
	struct virtchnl_synce_get_phy_rec_clk_out cached_phy_rec_clk_out;
	wait_queue_head_t cgu_dpll_stat_waitqueue;
	bool cgu_dpll_status_ready;
	struct virtchnl_synce_get_cgu_dpll_status cached_cgu_dpll_status;
	wait_queue_head_t cgu_ref_prio_waitqueue;
	bool cgu_ref_prio_ready;
	struct virtchnl_synce_get_cgu_ref_prio cached_cgu_ref_prio;
	wait_queue_head_t cgu_info_waitqueue;
	bool cgu_info_ready;
	struct virtchnl_synce_get_cgu_info cached_cgu_info;
	wait_queue_head_t cgu_abilities_waitqueue;
	bool cgu_abilities_ready;
	struct virtchnl_synce_get_cgu_abilities cached_cgu_abilities;
	wait_queue_head_t input_pin_cfg_waitqueue;
	bool input_pin_cfg_ready;
	struct virtchnl_synce_get_input_pin_cfg cached_input_pin_cfg;
	wait_queue_head_t output_pin_cfg_waitqueue;
	bool output_pin_cfg_ready;
	struct virtchnl_synce_get_output_pin_cfg cached_output_pin_cfg;
	bool hw_info_ready;
	struct virtchnl_synce_get_hw_info hw_info;
#define IAVF_MAX_CGU_PIN_NUM		12
	struct virtchnl_cgu_pin cgu_pins[IAVF_MAX_CGU_PIN_NUM];
	bool initialized;
	u8 C827_idx;
	u8 log_pending;
#define IAVF_PERIODIC_LOG_INTERVAL_IN_MSEC	500
	unsigned long scheduled_jiffies;
	enum iavf_cgu_state synce_dpll_state;
	enum iavf_cgu_state ptp_dpll_state;
};

void iavf_synce_probe(struct iavf_adapter *adapter);
void iavf_synce_init(struct iavf_adapter *adapter);
void iavf_synce_release(struct iavf_adapter *adapter);
void iavf_synce_dpll_update(struct iavf_adapter *adapter);
void iavf_virtchnl_synce_get_phy_rec_clk_out(struct iavf_adapter *adapter,
					     void *data, u16 len);
void iavf_virtchnl_synce_get_cgu_dpll_status(struct iavf_adapter *adapter,
					     void *data, u16 len);
void iavf_virtchnl_synce_get_cgu_ref_prio(struct iavf_adapter *adapter,
					  void *data, u16 len);
void iavf_virtchnl_synce_get_cgu_info(struct iavf_adapter *adapter,
				      void *data, u16 len);
void iavf_virtchnl_synce_get_cgu_abilities(struct iavf_adapter *adapter,
					   void *data, u16 len);
void iavf_virtchnl_synce_get_input_pin_cfg(struct iavf_adapter *adapter,
					   void *data, u16 len);
void iavf_virtchnl_synce_get_output_pin_cfg(struct iavf_adapter *adapter,
					    void *data, u16 len);
void iavf_virtchnl_synce_get_hw_info(struct iavf_adapter *adapter,
				     void *data, u16 len);
#endif /* _IAVF_SYNCE_H_ */
