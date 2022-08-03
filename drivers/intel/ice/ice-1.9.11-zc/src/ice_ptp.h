/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_PTP_H_
#define _ICE_PTP_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include <linux/highuid.h>
#include "kcompat_kthread.h"
#include "ice_ptp_hw.h"

enum ice_ptp_pin {
	GPIO_20 = 0,
	GPIO_21,
	GPIO_22,
	GPIO_23,
	NUM_ICE_PTP_PIN
};

/* Main timer mode */
enum ice_src_tmr_mode {
	ICE_SRC_TMR_MODE_NANOSECONDS,
	ICE_SRC_TMR_MODE_LOCKED,

	NUM_ICE_SRC_TMR_MODE
};

#define ICE_E810T_SMA1_CTRL_MASK	(ICE_E810T_P1_SMA1_DIR_EN | \
						ICE_E810T_P1_SMA1_TX_EN)
#define ICE_E810T_SMA2_CTRL_MASK	(ICE_E810T_P1_SMA2_UFL2_RX_DIS | \
						ICE_E810T_P1_SMA2_DIR_EN | \
						ICE_E810T_P1_SMA2_TX_EN)
#define ICE_E810T_SMA_CTRL_MASK		(ICE_E810T_SMA1_CTRL_MASK | \
						ICE_E810T_SMA2_CTRL_MASK)

enum ice_e810t_ptp_pins {
	GNSS = 0,
	SMA1,
	UFL1,
	SMA2,
	UFL2,
	NUM_E810T_PTP_PINS
};

enum ice_phy_rclk_pins {
	ICE_C827_RCLKA_PIN,		/* SCL pin */
	ICE_C827_RCLKB_PIN,		/* SDA pin */
	ICE_C827_RCLK_PINS_NUM		/* number of pins */
};

#define E810T_CGU_INPUT_C827(_phy, _pin) ((_phy) * ICE_C827_RCLK_PINS_NUM + \
					  (_pin) + ZL_REF1P)

struct ice_perout_channel {
	bool ena;
	u32 gpio_pin;
	u64 period;
	u64 start_time;
};

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
 * hardware reset or when a new timestamp value is captured. The cached_tstamp
 * field is used to detect the case where a new timestamp has not yet been
 * captured, ensuring that we avoid sending stale timestamp data to the stack.
 */
struct ice_tx_tstamp {
	struct sk_buff *skb;
	unsigned long start;
	u64 cached_tstamp;
};

/**
 * struct ice_ptp_tx - Tracking structure for Tx timestamp requests on a port
 * @tasklet: tasklet to handle processing of Tx timestamps
 * @work: work function to handle processing of Tx timestamps
 * @lock: lock to prevent concurrent write to in_use bitmap
 * @tstamps: array of len to store outstanding requests
 * @in_use: bitmap of len to indicate which slots are in use
 * @block: which memory block (quad or port) the timestamps are captured in
 * @offset: offset into timestamp block to get the real index
 * @len: length of the tstamps and in_use fields.
 * @init: if true, the tracker is initialized;
 * @calibrating: if true, the PHY is calibrating the Tx offset. During this
 *               window, timestamps are temporarily disabled.
 * @ll_ena: if true, the low latency timestamping feature is supported
 */
struct ice_ptp_tx {
	struct tasklet_struct tasklet;
	struct kthread_work work;
	spinlock_t lock; /* protects access to in_use bitmap */
	struct ice_tx_tstamp *tstamps;
	unsigned long *in_use;
	u8 block;
	u8 offset;
	u8 len;
	u8 init;
	u8 calibrating;
	u8 ll_ena;
};

/* Quad and port information for initializing timestamp blocks */
#define INDEX_PER_QUAD			64
#define INDEX_PER_PORT_E822		16
#define INDEX_PER_PORT_E810		64
#define INDEX_PER_PORT_ETH56G		64

/**
 * struct ice_ptp_port - data used to initialize an external port for PTP
 *
 * This structure contains data indicating whether a single external port is
 * ready for PTP functionality. It is used to track the port initialization
 * and determine when the port's PHY offset is valid.
 *
 * @tx: Tx timestamp tracking for this port
 * @ov_work: delayed work task for tracking when PHY offset is valid
 * @ps_lock: mutex used to protect the overall PTP PHY start procedure
 * @link_up: indicates whether the link is up
 * @tx_fifo_busy_cnt: number of times the Tx FIFO was busy
 * @port_num: the port number this structure represents
 */
struct ice_ptp_port {
	struct ice_ptp_tx tx;
	struct kthread_delayed_work ov_work;
	struct mutex ps_lock; /* protects overall PTP PHY start procedure */
	bool link_up;
	u8 tx_fifo_busy_cnt;
	u8 port_num;
};

#define GLTSYN_TGT_H_IDX_MAX		4

/**
 * struct ice_ptp - data used for integrating with CONFIG_PTP_1588_CLOCK
 * @port: data for the PHY port initialization procedure
 * @work: delayed work function for periodic tasks
 * @extts_work: work function for handling external Tx timestamps
 * @cached_phc_time: a cached copy of the PHC time for timestamp extension
 * @ext_ts_chan: the external timestamp channel in use
 * @ext_ts_irq: the external timestamp IRQ in use
 * @kworker: kwork thread for handling periodic work
 * @perout_channels: periodic output data
 * @info: structure defining PTP hardware capabilities
 * @clock: pointer to registered PTP clock device
 * @tstamp_config: hardware timestamping configuration
 * @phy_kobj: pointer to phy sysfs object
 * @src_tmr_mode: current device timer mode (locked or nanoseconds)
 * @reset_time: kernel time after clock stop on reset
 */
struct ice_ptp {
	struct ice_ptp_port port;
	struct kthread_delayed_work work;
	struct kthread_work extts_work;
	u64 cached_phc_time;
	u8 ext_ts_chan;
	u8 ext_ts_irq;
	struct kthread_worker *kworker;
	struct ice_perout_channel perout_channels[GLTSYN_TGT_H_IDX_MAX];
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct hwtstamp_config tstamp_config;
	struct kobject *phy_kobj;
	enum ice_src_tmr_mode src_tmr_mode;
	u64 reset_time;
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

#define MAC_RX_LINK_COUNTER(_port)	(0x600090 + 0x1000 * (_port))
#define PFTSYN_SEM_BYTES		4
#define PTP_SHARED_CLK_IDX_VALID	BIT(31)
#define PHY_TIMER_SELECT_VALID_BIT	0
#define PHY_TIMER_SELECT_BIT		1
#define PHY_TIMER_SELECT_MASK		0xFFFFFFFC
#define TS_CMD_MASK_EXT			0xFF
#define TS_CMD_MASK			0xF
#define SYNC_EXEC_CMD			0x3
#define ICE_PTP_TS_VALID		BIT(0)
#define FIFO_EMPTY			BIT(2)
#define FIFO_OK				0xFF
#define ICE_PTP_FIFO_NUM_CHECKS		5
#define TX_INTR_QUAD_MASK		0x03
/* Per-channel register definitions */
#define GLTSYN_AUX_OUT(_chan, _idx)	(GLTSYN_AUX_OUT_0(_idx) + ((_chan) * 8))
#define GLTSYN_AUX_IN(_chan, _idx)	(GLTSYN_AUX_IN_0(_idx) + ((_chan) * 8))
#define GLTSYN_CLKO(_chan, _idx)	(GLTSYN_CLKO_0(_idx) + ((_chan) * 8))
#define GLTSYN_TGT_L(_chan, _idx)	(GLTSYN_TGT_L_0(_idx) + ((_chan) * 16))
#define GLTSYN_TGT_H(_chan, _idx)	(GLTSYN_TGT_H_0(_idx) + ((_chan) * 16))
#define GLTSYN_EVNT_L(_chan, _idx)	(GLTSYN_EVNT_L_0(_idx) + ((_chan) * 16))
#define GLTSYN_EVNT_H(_chan, _idx)	(GLTSYN_EVNT_H_0(_idx) + ((_chan) * 16))
#define GLTSYN_EVNT_H_IDX_MAX		3

/* Pin definitions for PTP PPS out */
#define PPS_CLK_GEN_CHAN		3
#define PPS_CLK_SRC_CHAN		2
#define PPS_PIN_INDEX			5
#define TIME_SYNC_PIN_INDEX		4
#define N_EXT_TS_E810			3
#define N_PER_OUT_E810			4
#define N_PER_OUT_E810T			3
#define N_PER_OUT_NO_SMA_E810T		2
#define N_EXT_TS_NO_SMA_E810T		2
/* Macros to derive the low and high addresses for PHY */
#define LOWER_ADDR_SIZE			16
/* Macros to derive offsets for TimeStampLow and TimeStampHigh */
#define PORT_TIMER_ASSOC(_i)		(0x0300102C + ((_i) * 256))
#define ETH_GLTSYN_ENA(_i)		(0x03000348 + ((_i) * 4))

#define MAX_PIN_NAME			15

#define	ICE_PTP_PIN_FREQ_1HZ		1
#define	ICE_PTP_PIN_FREQ_10MHZ		10000000

/* Time allowed for programming periodic clock output */
#define START_OFFS_NS 100000000

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
struct ice_pf;
int ice_ptp_set_ts_config(struct ice_pf *pf, struct ifreq *ifr);
int ice_ptp_get_ts_config(struct ice_pf *pf, struct ifreq *ifr);
void ice_ptp_cfg_timestamp(struct ice_pf *pf, bool ena);
int ice_get_ptp_clock_index(struct ice_pf *pf);

s8 ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb);
void ice_ptp_process_ts(struct ice_pf *pf);

u64
ice_ptp_read_src_clk_reg(struct ice_pf *pf, struct ptp_system_timestamp *sts);
void ice_ptp_rx_hwtstamp(struct ice_ring *rx_ring, union ice_32b_rx_flex_desc *rx_desc,
			 struct sk_buff *skb);
void ice_ptp_reset(struct ice_pf *pf);
void ice_ptp_prepare_for_reset(struct ice_pf *pf);
void ice_ptp_init(struct ice_pf *pf);
void ice_ptp_release(struct ice_pf *pf);
int ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup);
int ice_ptp_check_rx_fifo(struct ice_pf *pf, u8 port);
int ptp_ts_enable(struct ice_pf *pf, u8 port, bool enable);
int ice_ptp_cfg_clkout(struct ice_pf *pf, unsigned int chan,
		       struct ice_perout_channel *config, bool store);
int ice_ptp_update_incval(struct ice_pf *pf, enum ice_time_ref_freq time_ref_freq,
			  enum ice_src_tmr_mode src_tmr_mode);
int ice_ptp_get_incval(struct ice_pf *pf, enum ice_time_ref_freq *time_ref_freq,
		       enum ice_src_tmr_mode *src_tmr_mode);
void ice_dpll_pin_idx_to_name(struct ice_pf *pf, u8 pin, char *pin_name);
#else /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
static inline int ice_ptp_set_ts_config(struct ice_pf __always_unused *pf,
					struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline int ice_ptp_get_ts_config(struct ice_pf __always_unused *pf,
					struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline void ice_ptp_cfg_timestamp(struct ice_pf *pf, bool ena) { }
static inline int
ice_ptp_check_rx_fifo(struct ice_pf __always_unused *pf,
		      u8 __always_unused port)
{
	return 0;
}

static inline s8 ice_ptp_request_ts(struct ice_ptp_tx *tx, struct sk_buff *skb)
{
	return -1;
}

static inline void ice_ptp_process_ts(struct ice_pf *pf) { }

static inline int ice_get_ptp_clock_index(struct ice_pf __always_unused *pf)
{
	return 0;
}
static inline void ice_clean_ptp_subtask(struct ice_pf *pf) { }
static inline void ice_ptp_rx_hwtstamp(struct ice_ring *rx_ring,
				       union ice_32b_rx_flex_desc *rx_desc,
				       struct sk_buff *skb) { }
static inline void ice_ptp_init(struct ice_pf *pf) { }
static inline void ice_ptp_reset(struct ice_pf *pf) { }
static inline void ice_ptp_release(struct ice_pf *pf) { }
static inline void ice_ptp_prepare_for_reset(struct ice_pf *pf) { }
static inline int ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup)
{ return 0; }
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
#endif /* _ICE_PTP_H_ */
