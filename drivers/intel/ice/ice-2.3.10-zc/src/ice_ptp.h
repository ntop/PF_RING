/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_PTP_H_
#define _ICE_PTP_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include <linux/highuid.h>
#include "kcompat_kthread.h"
#include "ice_ptp_hw.h"

/* DPLL REF_SW state */
enum ice_dpll_ref_sw_state {
	ICE_DPLL_REF_SW_DISABLE,
	ICE_DPLL_REF_SW_ENABLE,
	NUM_ICE_DPLL_REF_SW_STATE,
};

#define E82X_CGU_RCLK_PHY_PINS_NUM	1
#define E82X_CGU_RCLK_PIN_NAME		"NAC_CLK_SYNCE0_PN"

#define ICE_CGU_IN_PIN_FAIL_FLAGS (ICE_AQC_GET_CGU_IN_CFG_STATUS_SCM_FAIL | \
				   ICE_AQC_GET_CGU_IN_CFG_STATUS_CFM_FAIL | \
				   ICE_AQC_GET_CGU_IN_CFG_STATUS_GST_FAIL | \
				   ICE_AQC_GET_CGU_IN_CFG_STATUS_PFM_FAIL)

#define ICE_DPLL_PIN_STATE_INVALID	"invalid"
#define ICE_DPLL_PIN_STATE_VALIDATING	"validating"
#define ICE_DPLL_PIN_STATE_VALID	"valid"

/* The ice hardware captures Tx hardware timestamps in the PHY. The timestamp
 * is stored in a buffer of registers. Depending on the specific hardware,
 * this buffer might be shared across multiple PHY ports.
 *
 * On transmit of a packet to be timestamped, software is responsible for
 * selecting an open index. Hardware makes no attempt to lock or prevent
 * re-use of an index for multiple packets.
 *
 * To handle this, timestamp indexes must be tracked by software to ensure
 * that an index is not re-used for multiple transmitted packets. The
 * structures and functions declared in this file track the available Tx
 * register indexes, as well as provide storage for the SKB pointers.
 *
 * To allow multiple ports to access the shared register block independently,
 * the blocks are split up so that indexes are assigned to each port based on
 * hardware logical port number.
 *
 * The timestamp blocks are handled differently for E810- and E82X-based
 * devices. In E810 devices, each port has its own block of timestamps, while in
 * E82X there is a need to logically break the block of registers into smaller
 * chunks based on the port number to avoid collisions.
 *
 * Example for port 5 in E810:
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |register|register|register|register|register|register|register|register|
 *  | block  | block  | block  | block  | block  | block  | block  | block  |
 *  |  for   |  for   |  for   |  for   |  for   |  for   |  for   |  for   |
 *  | port 0 | port 1 | port 2 | port 3 | port 4 | port 5 | port 6 | port 7 |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *                                               ^^
 *                                               ||
 *                                               |---  quad offset is always 0
 *                                               ---- quad number
 *
 * Example for port 5 in E82X:
 * +-----------------------------+-----------------------------+
 * |  register block for quad 0  |  register block for quad 1  |
 * |+------+------+------+------+|+------+------+------+------+|
 * ||port 0|port 1|port 2|port 3|||port 0|port 1|port 2|port 3||
 * |+------+------+------+------+|+------+------+------+------+|
 * +-----------------------------+-------^---------------------+
 *                                ^      |
 *                                |      --- quad offset*
 *                                ---- quad number
 *
 *   * PHY port 5 is port 1 in quad 1
 *
 */

/**
 * struct ice_tx_tstamp - Tracking for a single Tx timestamp
 * @skb: pointer to the SKB for this timestamp request
 * @start: jiffies when the timestamp was first requested
 * @cached_tstamp: last read timestamp
 *
 * This structure tracks a single timestamp request. The SKB pointer is
 * provided when initiating a request. The start time is used to ensure that
 * we discard old requests that were not fulfilled within a 2 second time
 * window.
 * Timestamp values in the PHY are read only and do not get cleared except at
 * hardware reset or when a new timestamp value is captured.
 *
 * Some PHY types do not provide a "ready" bitmap indicating which timestamp
 * indexes are valid. In these cases, we use a cached_tstamp to keep track of
 * the last timestamp we read for a given index. If the current timestamp
 * value is the same as the cached value, we assume a new timestamp hasn't
 * been captured. This avoids reporting stale timestamps to the stack. This is
 * only done if the has_ready_bitmap flag is not set in ice_ptp_tx structure.
 */
struct ice_tx_tstamp {
	struct sk_buff *skb;
	unsigned long start;
	u64 cached_tstamp;
};

/**
 * enum ice_tx_tstamp_work - Status of Tx timestamp work function
 * @ICE_TX_TSTAMP_WORK_DONE: Tx timestamp processing is complete
 * @ICE_TX_TSTAMP_WORK_PENDING: More Tx timestamps are pending
 */
enum ice_tx_tstamp_work {
	ICE_TX_TSTAMP_WORK_DONE = 0,
	ICE_TX_TSTAMP_WORK_PENDING,
};

/**
 * struct ice_ptp_tx - Tracking structure for all Tx timestamp requests on a port
 * @lock: lock to prevent concurrent access to fields of this struct
 * @tstamps: array of len to store outstanding requests
 * @in_use: bitmap of len to indicate which slots are in use
 * @block: which memory block (quad or port) the timestamps are captured in
 * @offset: offset into timestamp block to get the real index
 * @len: length of the tstamps and in_use fields.
 * @init: if true, the tracker is initialized;
 * @calibrating: if true, the PHY is calibrating the Tx offset. During this
 *               window, timestamps are temporarily disabled.
 * @has_ready_bitmap: if true, the hardware has a valid Tx timestamp ready
 *                    bitmap register. If false, fall back to verifying new
 *                    timestamp values against previously cached copy.
 * @last_ll_ts_idx_read: index of the last LL TS read by the FW
 */
struct ice_ptp_tx {
	spinlock_t lock; /* lock protecting in_use bitmap */
	struct ice_tx_tstamp *tstamps;
	unsigned long *in_use;
	u8 block;
	u8 offset;
	u8 len;
	u8 init : 1;
	u8 calibrating : 1;
	u8 has_ready_bitmap : 1;
	s8 last_ll_ts_idx_read;
};

/* Quad and port information for initializing timestamp blocks */
#define INDEX_PER_QUAD		64
#define INDEX_PER_PORT_E82X	16
#define INDEX_PER_PORT		64

/**
 * struct ice_ptp_port - data used to initialize an external port for PTP
 *
 * This structure contains data indicating whether a single external port is
 * ready for PTP functionality. It is used to track the port initialization
 * and determine when the port's PHY offset is valid.
 *
 * @list_node: list member structure
 * @tx: Tx timestamp tracking for this port
 * @aux_dev: auxiliary device associated with this port
 * @ov_work: delayed work for tracking when PHY offset is valid
 * @ps_lock: mutex used to protect the overall PTP PHY start procedure
 * @link_up: indicates whether the link is up
 * @tx_fifo_busy_cnt: number of times the Tx FIFO was busy
 * @port_num: the port number this structure represents
 * @tx_clk: Tx reference clock source
 * @tx_clk_prev: previously set Tx reference clock source
 */
struct ice_ptp_port {
	struct list_head list_node;
	struct ice_ptp_tx tx;
	struct delayed_work ov_work;
	struct mutex ps_lock; /* protects overall PTP PHY start procedure */
	bool link_up;
	u8 tx_fifo_busy_cnt;
	u8 port_num;
	u8 rx_calibrating : 1;
	enum ice_e825c_ref_clk tx_clk;
	enum ice_e825c_ref_clk tx_clk_prev;
};

enum ice_ptp_state {
	ICE_PTP_UNINIT = 0,
	ICE_PTP_INITIALIZING,
	ICE_PTP_READY,
	ICE_PTP_RESETTING,
	ICE_PTP_ERROR,
};

enum ice_ptp_tx_interrupt {
	ICE_PTP_TX_INTERRUPT_NONE = 0,
	ICE_PTP_TX_INTERRUPT_SELF,
	ICE_PTP_TX_INTERRUPT_ALL,
};

enum ice_ptp_pin {
	SDP0 = 0,
	SDP1,
	SDP2,
	SDP3,
	TIME_SYNC,
	ONE_PPS,
};

/* Those enum values are shared with NVM, hence non-contiguous values */
enum ice_ptp_pin_nvm {
	GNSS = 0,
	SMA1,
	UFL1,
	SMA2,
	UFL2,
	NUM_PTP_PINS_NVM,
	GPIO_NA = 9
};

/* Per-channel register definitions */
#define GLTSYN_AUX_OUT(_chan, _idx)	(GLTSYN_AUX_OUT_0(_idx) + ((_chan) * 8))
#define GLTSYN_AUX_IN(_chan, _idx)	(GLTSYN_AUX_IN_0(_idx) + ((_chan) * 8))
#define GLTSYN_CLKO(_chan, _idx)	(GLTSYN_CLKO_0(_idx) + ((_chan) * 8))
#define GLTSYN_TGT_L(_chan, _idx)	(GLTSYN_TGT_L_0(_idx) + ((_chan) * 16))
#define GLTSYN_TGT_H(_chan, _idx)	(GLTSYN_TGT_H_0(_idx) + ((_chan) * 16))
#define GLTSYN_TGT_H_IDX_MAX		4
#define GLTSYN_EVNT_L(_chan, _idx)	(GLTSYN_EVNT_L_0(_idx) + ((_chan) * 16))
#define GLTSYN_EVNT_H(_chan, _idx)	(GLTSYN_EVNT_H_0(_idx) + ((_chan) * 16))
#define GLTSYN_EVNT_H_IDX_MAX		3

#define ICE_GPIO_CTL_IN_START		1
#define ICE_GPIO_CTL_OUT_START		8
#define ICE_GPIO_CTL_IN(_chan, _tmr_idx) \
	(ICE_GPIO_CTL_IN_START + (_chan) + GLTSYN_EVNT_H_IDX_MAX * (_tmr_idx))
#define ICE_GPIO_CTL_OUT(_chan, _tmr_idx) \
	(ICE_GPIO_CTL_OUT_START + (_chan) + GLTSYN_TGT_H_IDX_MAX * (_tmr_idx))

/* Pin definitions for PTP */
#define ICE_N_PINS_MAX			(GLGEN_GPIO_CTL_MAX_INDEX + 1)
#define MAX_PIN_NAME			15
#define	ICE_PTP_PIN_FREQ_1HZ		1
#define	ICE_PTP_PIN_FREQ_10MHZ		10000000

/**
 * struct ice_ptp_pin_desc - hardware pin description data
 * @name_idx: index of the name of pin in ice_pin_names
 * @gpio: the associated GPIO input and output pins
 * @delay: input and output signal delays in nanoseconds
 *
 * Structure describing a PTP-capable GPIO pin that extends ptp_pin_desc array
 * for the device. Device families have separate sets of available pins with
 * varying restrictions.
 */
struct ice_ptp_pin_desc {
	int name_idx;
	int gpio[2];
	unsigned int delay[2];
};

/**
 * struct ice_ptp - data used for integrating with CONFIG_PTP_1588_CLOCK
 * @state: current state of PTP state machine
 * @tx_interrupt_mode: the TX interrupt mode for the PHC device
 * @port: data for the PHY port initialization procedure
 * @cached_phc_time: a cached copy of the PHC time for timestamp extension
 * @cached_phc_jiffies: jiffies when cached_phc_time was last updated
#ifndef HAVE_PTP_CLOCK_DO_AUX_WORK
 * @kworker: kwork thread for handling periodic work
 * @aux_work: delayed work function for periodic tasks
#endif
 * @ext_ts_irq: the external timestamp IRQ in use
 * @pin_desc: structure defining pins
 * @ice_pin_desc: internal structure describing pin relations
 * @perout_rqs: cached periodic output requests
 * @extts_rqs: cached external timestamp requests
 * @info: structure defining PTP hardware capabilities
 * @clock: pointer to registered PTP clock device
 * @tstamp_config: hardware timestamping configuration
 * @phy_kobj: pointer to phy sysfs object
 * @tx_refclks: bitmaps table to store the information about TX reference clocks
 * @reset_time: kernel time after clock stop on reset
 * @tx_hwtstamp_skipped: number of Tx time stamp requests skipped
 * @tx_hwtstamp_timeouts: number of Tx skbs discarded with no time stamp
 * @tx_hwtstamp_flushed: number of Tx skbs flushed due to interface closed
 * @tx_hwtstamp_discarded: number of Tx skbs discarded due to cached PHC time
 *                         being too old to correctly extend timestamp
 * @late_cached_phc_updates: number of times cached PHC update is late
 */
struct ice_ptp {
	enum ice_ptp_state state;
	enum ice_ptp_tx_interrupt tx_interrupt_mode;
	struct ice_ptp_port port;
	u64 cached_phc_time;
	unsigned long cached_phc_jiffies;
#ifndef HAVE_PTP_CANCEL_WORKER_SYNC
	struct kthread_worker *kworker;
	struct kthread_delayed_work aux_work;
#endif /* !HAVE_PTP_CANCEL_WORKER_SYNC */
	u8 ext_ts_irq;
	struct ptp_pin_desc pin_desc[ICE_N_PINS_MAX];
	const struct ice_ptp_pin_desc *ice_pin_desc;
	struct ptp_perout_request perout_rqs[GLTSYN_TGT_H_IDX_MAX];
	struct ptp_extts_request extts_rqs[GLTSYN_EVNT_H_IDX_MAX];
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct hwtstamp_config tstamp_config;
	struct kobject *phy_kobj;
#define ICE_E825_MAX_PHYS 2
	unsigned long tx_refclks[ICE_E825_MAX_PHYS][ICE_REF_CLK_MAX];
	u64 reset_time;
	u32 tx_hwtstamp_skipped;
	u32 tx_hwtstamp_timeouts;
	u32 tx_hwtstamp_flushed;
	u32 tx_hwtstamp_discarded;
	u32 late_cached_phc_updates;
};

static inline struct ice_ptp *__ptp_port_to_ptp(struct ice_ptp_port *p)
{
	return container_of(p, struct ice_ptp, port);
}

#define ptp_port_to_pf(p) \
	container_of(__ptp_port_to_ptp((p)), struct ice_pf, ptp)

static inline struct ice_ptp *__ptp_info_to_ptp(struct ptp_clock_info *i)
{
	return container_of(i, struct ice_ptp, info);
}

#define ptp_info_to_pf(i) \
	container_of(__ptp_info_to_ptp((i)), struct ice_pf, ptp)

static inline int ice_ptp_get_seq_id(struct sk_buff *skb)
{
	struct ptp_header *hdr;
	int type;

	if (!skb)
		return -1;

	type = ptp_classify_raw(skb);

	if (type == PTP_CLASS_NONE)
		return -1;

	hdr = ptp_parse_header(skb, type);
	if (!hdr)
		return -1;

	return be16_to_cpu(hdr->sequence_id);
}

#define SYNC_EXEC_CMD			0x3
#define ICE_PTP_TS_VALID		BIT(0)
#define FIFO_EMPTY			BIT(2)
#define FIFO_OK				0xFF
#define ICE_PTP_FIFO_NUM_CHECKS		5
#define TX_INTR_QUAD_MASK		0x1Fu

#define ICE_PTP_PIN_INVALID		0xFF

/* "dpll <x> pin <y> prio <z>" (always 6 arguments) */
#define ICE_PTP_PIN_PRIO_ARG_CNT	6

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
#define ICE_PTP_PIN_CFG_1_ARG_CNT	5
#define ICE_PTP_PIN_CFG_2_ARG_CNT	7
#define ICE_PTP_PIN_CFG_3_ARG_CNT	9
#define ICE_PTP_PIN_CFG_4_ARG_CNT	11

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
bool ice_is_ptp_supported(struct ice_pf *pf);
struct ice_pf;
int ice_ptp_set_ts_config(struct ice_pf *pf, struct ifreq *ifr);
int ice_ptp_get_ts_config(struct ice_pf *pf, struct ifreq *ifr);
void ice_block_ptp_workthreads_global(struct ice_pf *pf, bool block_enable);
void ice_ptp_restore_timestamp_mode(struct ice_pf *pf);

void ice_ptp_extts_event(struct ice_pf *pf);
s8 ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb);
enum ice_tx_tstamp_work ice_ptp_process_ts(struct ice_pf *pf);
irqreturn_t ice_ptp_ts_irq(struct ice_pf *pf);
void ice_ptp_req_tx_single_tstamp(struct ice_ptp_tx *tx, u8 idx);
void ice_ptp_complete_tx_single_tstamp(struct ice_ptp_tx *tx);

u64
ice_ptp_read_src_clk_reg(struct ice_pf *pf, struct ptp_system_timestamp *sts);
void
ice_ptp_rx_hwtstamp(struct ice_rx_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc, struct sk_buff *skb);
void ice_ptp_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type);
void
ice_ptp_prepare_for_reset(struct ice_pf *pf, enum ice_reset_req reset_type);
void ice_ptp_init(struct ice_pf *pf);
void ice_ptp_release(struct ice_pf *pf);
void ice_ptp_link_change(struct ice_pf *pf, bool linkup);
int ice_ptp_check_rx_fifo(struct ice_pf *pf, u8 port);
int ice_ptp_update_incval(struct ice_pf *pf, enum ice_tspll_freq tspll_freq,
			  enum ice_src_tmr_mode src_tmr_mode);
void ice_dpll_pin_idx_to_name(struct ice_pf *pf, u8 pin, char *pin_name);
int ice_ptp_phy_restart(struct ice_pf *pf);
#if defined(CONFIG_X86)
int ice_ptp_get_sw_cross_tstamp(struct ice_pf *pf,
				struct virtchnl_sw_cross_timestamp *sw_cts);
int ice_ptp_get_phc_freq_ratio(struct ice_pf *pf,
			       struct virtchnl_phc_freq_ratio *ratio);
#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
int ice_ptp_clock_index(struct ice_pf *pf);
#else /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
static inline bool ice_is_ptp_supported(struct ice_pf *pf)
{
	return false;
}
static inline int ice_ptp_set_ts_config(struct ice_pf *pf, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline int ice_ptp_get_ts_config(struct ice_pf *pf, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline void
ice_block_ptp_workthreads_global(struct ice_pf *pf, bool block_enable) { }

static inline void ice_ptp_restore_timestamp_mode(struct ice_pf *pf) { }
static inline void ice_ptp_extts_event(struct ice_pf *pf) { }
static inline s8
ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb)
{
	return -1;
}

static inline bool ice_ptp_process_ts(struct ice_pf *pf)
{
	return true;
}

static inline irqreturn_t ice_ptp_ts_irq(struct ice_pf *pf)
{
	return IRQ_HANDLED;
}

static inline void ice_ptp_req_tx_single_tstamp(struct ice_ptp_tx *tx, u8 idx)
{ }

static inline void ice_ptp_complete_tx_single_tstamp(struct ice_ptp_tx *tx) { }

#if defined(CONFIG_X86)
static inline int
ice_ptp_get_sw_cross_tstamp(struct ice_pf *pf,
			    struct virtchnl_sw_cross_timestamp *sw_cts)
{
	return -EOPNOTSUPP;
}

static inline int
ice_ptp_get_phc_freq_ratio(struct ice_pf *pf,
			   struct virtchnl_phc_freq_ratio *ratio)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
static inline void
ice_ptp_rx_hwtstamp(struct ice_rx_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc, struct sk_buff *skb) { }

static inline void
ice_ptp_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type)
{
}

static inline void ice_ptp_prepare_for_reset(struct ice_pf *pf,
					     enum ice_reset_req reset_type)
{
}

static inline void ice_ptp_init(struct ice_pf *pf) { }
static inline void ice_ptp_release(struct ice_pf *pf) { }
static inline void ice_ptp_link_change(struct ice_pf *pf, bool linkup)
{
}
static inline int ice_ptp_clock_index(struct ice_pf *pf)
{
	return -1;
}
static inline void ice_dpll_pin_idx_to_name(struct ice_pf *pf,
					    u8 pin, char *pin_name)
{
	snprintf(pin_name, MAX_PIN_NAME, "Pin %i", pin);
}
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
#endif /* _ICE_PTP_H_ */
