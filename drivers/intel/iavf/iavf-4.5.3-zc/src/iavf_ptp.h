/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _IAVF_PTP_H_
#define _IAVF_PTP_H_

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#endif /* CONFIG_PTP_1588_CLOCK */

struct iavf_adapter;

/* bit indicating whether a 40bit timestamp is valid */
#define IAVF_PTP_40B_TSTAMP_VALID BIT(0)

/* fields used for PTP support */
struct iavf_ptp {
	wait_queue_head_t phc_time_waitqueue;
	wait_queue_head_t gpio_waitqueue;
	struct virtchnl_ptp_caps hw_caps;
	struct hwtstamp_config hwtstamp_config;
	u64 cached_phc_time;
	unsigned long cached_phc_updated;
	u64 tx_hwtstamp_skipped;
	u64 tx_hwtstamp_timeouts;
	struct sk_buff *tx_skb; /* protected by __IAVF_TX_TSTAMP_IN_PROGRESS */
	unsigned long tx_start; /* protected by __IAVF_TX_TSTAMP_IN_PROGRESS */
	u8 __iomem *phc_addr; /* PHC register mapping */
	bool initialized;
	bool phc_time_ready;
	bool set_pin_ready;
	bool pin_cfg_ready;
	enum virtchnl_status_code set_pin_status;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	struct ptp_clock_info info;
	struct ptp_clock *clock;
#endif
};

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
void iavf_ptp_init(struct iavf_adapter *adapter);
void iavf_ptp_release(struct iavf_adapter *adapter);
void iavf_ptp_process_caps(struct iavf_adapter *adapter);
long iavf_ptp_do_aux_work(struct ptp_clock_info *ptp);
bool iavf_ptp_cap_supported(struct iavf_adapter *adapter, u32 cap);
u64 iavf_ptp_extend_32b_timestamp(u64 cached_phc_time, u32 in_tstamp);
int iavf_ptp_get_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr);
int iavf_ptp_set_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr);
void iavf_virtchnl_ptp_get_time(struct iavf_adapter *adapter, void *data,
				u16 len);
void iavf_virtchnl_ptp_tx_timestamp(struct iavf_adapter *adapter, void *data,
				    u16 len);
void iavf_virtchnl_ptp_pin_status(struct iavf_adapter *adapter,
				  enum virtchnl_status_code v_retval);
void iavf_virtchnl_ptp_get_pin_cfgs(struct iavf_adapter *adapter, void *data,
				    u16 len);
void iavf_virtchnl_ptp_ext_timestamp(struct iavf_adapter *adapter, void *data,
				     u16 len);
#else
static inline void iavf_ptp_init(struct iavf_adapter *adapter) {}
static inline void iavf_ptp_release(struct iavf_adapter *adapter) {}
static inline void iavf_ptp_process_caps(struct iavf_adapter *adapter) {}
static inline bool iavf_ptp_cap_supported(struct iavf_adapter *adapter, u32 cap) { return false; }
static inline u64 iavf_ptp_extend_32b_timestamp(u64 cached_phc_time, u32 in_tstamp) { return 0; }

static inline int iavf_ptp_get_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline int iavf_ptp_set_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _IAVF_PTP_H_ */
