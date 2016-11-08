/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007-2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

/******************************************************************************
 Copyright(c) 2011 Richard Cochran <richardcochran@gmail.com> for some of the
 82576 and 82580 code
******************************************************************************/

#include "igb.h"

#ifdef HAVE_PTP_1588_CLOCK
#include <linux/clocksource.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/ptp_classify.h>

#define INCVALUE_MASK		0x7fffffff
#define ISGN			0x80000000

/*
 * The 82580 timesync updates the system timer every 8ns by 8ns,
 * and this update value cannot be reprogrammed.
 *
 * Neither the 82576 nor the 82580 offer registers wide enough to hold
 * nanoseconds time values for very long. For the 82580, SYSTIM always
 * counts nanoseconds, but the upper 24 bits are not availible. The
 * frequency is adjusted by changing the 32 bit fractional nanoseconds
 * register, TIMINCA.
 *
 * For the 82576, the SYSTIM register time unit is affect by the
 * choice of the 24 bit TININCA:IV (incvalue) field. Five bits of this
 * field are needed to provide the nominal 16 nanosecond period,
 * leaving 19 bits for fractional nanoseconds.
 *
 * We scale the NIC clock cycle by a large factor so that relatively
 * small clock corrections can be added or subtracted at each clock
 * tick. The drawbacks of a large factor are a) that the clock
 * register overflows more quickly (not such a big deal) and b) that
 * the increment per tick has to fit into 24 bits.  As a result we
 * need to use a shift of 19 so we can fit a value of 16 into the
 * TIMINCA register.
 *
 *
 *             SYSTIMH            SYSTIML
 *        +--------------+   +---+---+------+
 *  82576 |      32      |   | 8 | 5 |  19  |
 *        +--------------+   +---+---+------+
 *         \________ 45 bits _______/  fract
 *
 *        +----------+---+   +--------------+
 *  82580 |    24    | 8 |   |      32      |
 *        +----------+---+   +--------------+
 *          reserved  \______ 40 bits _____/
 *
 *
 * The 45 bit 82576 SYSTIM overflows every
 *   2^45 * 10^-9 / 3600 = 9.77 hours.
 *
 * The 40 bit 82580 SYSTIM overflows every
 *   2^40 * 10^-9 /  60  = 18.3 minutes.
 */

#define IGB_SYSTIM_OVERFLOW_PERIOD	(HZ * 60 * 9)
#define IGB_PTP_TX_TIMEOUT		(HZ * 15)
#define INCPERIOD_82576			(1 << E1000_TIMINCA_16NS_SHIFT)
#define INCVALUE_82576_MASK		((1 << E1000_TIMINCA_16NS_SHIFT) - 1)
#define INCVALUE_82576			(16 << IGB_82576_TSYNC_SHIFT)
#define IGB_NBITS_82580			40

/*
 * SYSTIM read access for the 82576
 */

static cycle_t igb_ptp_read_82576(const struct cyclecounter *cc)
{
	struct igb_adapter *igb = container_of(cc, struct igb_adapter, cc);
	struct e1000_hw *hw = &igb->hw;
	u64 val;
	u32 lo, hi;

	lo = E1000_READ_REG(hw, E1000_SYSTIML);
	hi = E1000_READ_REG(hw, E1000_SYSTIMH);

	val = ((u64) hi) << 32;
	val |= lo;

	return val;
}

/*
 * SYSTIM read access for the 82580
 */

static cycle_t igb_ptp_read_82580(const struct cyclecounter *cc)
{
	struct igb_adapter *igb = container_of(cc, struct igb_adapter, cc);
	struct e1000_hw *hw = &igb->hw;
	u64 val;
	u32 lo, hi;

	/* The timestamp latches on lowest register read. For the 82580
	 * the lowest register is SYSTIMR instead of SYSTIML.  However we only
	 * need to provide nanosecond resolution, so we just ignore it.
	 */
	E1000_READ_REG(hw, E1000_SYSTIMR);
	lo = E1000_READ_REG(hw, E1000_SYSTIML);
	hi = E1000_READ_REG(hw, E1000_SYSTIMH);

	val = ((u64) hi) << 32;
	val |= lo;

	return val;
}

/*
 * SYSTIM read access for I210/I211
 */

static void igb_ptp_read_i210(struct igb_adapter *adapter, struct timespec *ts)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 sec, nsec;

	/* The timestamp latches on lowest register read. For I210/I211, the
	 * lowest register is SYSTIMR. Since we only need to provide nanosecond
	 * resolution, we can ignore it.
	 */
	E1000_READ_REG(hw, E1000_SYSTIMR);
	nsec = E1000_READ_REG(hw, E1000_SYSTIML);
	sec = E1000_READ_REG(hw, E1000_SYSTIMH);

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

static void igb_ptp_write_i210(struct igb_adapter *adapter,
			       const struct timespec *ts)
{
	struct e1000_hw *hw = &adapter->hw;

	/*
	 * Writing the SYSTIMR register is not necessary as it only provides
	 * sub-nanosecond resolution.
	 */
	E1000_WRITE_REG(hw, E1000_SYSTIML, ts->tv_nsec);
	E1000_WRITE_REG(hw, E1000_SYSTIMH, ts->tv_sec);
}

/**
 * igb_ptp_systim_to_hwtstamp - convert system time value to hw timestamp
 * @adapter: board private structure
 * @hwtstamps: timestamp structure to update
 * @systim: unsigned 64bit system time value.
 *
 * We need to convert the system time value stored in the RX/TXSTMP registers
 * into a hwtstamp which can be used by the upper level timestamping functions.
 *
 * The 'tmreg_lock' spinlock is used to protect the consistency of the
 * system time value. This is needed because reading the 64 bit time
 * value involves reading two (or three) 32 bit registers. The first
 * read latches the value. Ditto for writing.
 *
 * In addition, here have extended the system time with an overflow
 * counter in software.
 **/
static void igb_ptp_systim_to_hwtstamp(struct igb_adapter *adapter,
				       struct skb_shared_hwtstamps *hwtstamps,
				       u64 systim)
{
	unsigned long flags;
	u64 ns;

	switch (adapter->hw.mac.type) {
	case e1000_82576:
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
		spin_lock_irqsave(&adapter->tmreg_lock, flags);

		ns = timecounter_cyc2time(&adapter->tc, systim);

		spin_unlock_irqrestore(&adapter->tmreg_lock, flags);

		memset(hwtstamps, 0, sizeof(*hwtstamps));
		hwtstamps->hwtstamp = ns_to_ktime(ns);
		break;
	case e1000_i210:
	case e1000_i211:
		memset(hwtstamps, 0, sizeof(*hwtstamps));
		/* Upper 32 bits contain s, lower 32 bits contain ns. */
		hwtstamps->hwtstamp = ktime_set(systim >> 32,
						systim & 0xFFFFFFFF);
		break;
	default:
		break;
	}
}

/*
 * PTP clock operations
 */

static int igb_ptp_adjfreq_82576(struct ptp_clock_info *ptp, s32 ppb)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	struct e1000_hw *hw = &igb->hw;
	int neg_adj = 0;
	u64 rate;
	u32 incvalue;

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}
	rate = ppb;
	rate <<= 14;
	rate = div_u64(rate, 1953125);

	incvalue = 16 << IGB_82576_TSYNC_SHIFT;

	if (neg_adj)
		incvalue -= rate;
	else
		incvalue += rate;

	E1000_WRITE_REG(hw, E1000_TIMINCA, INCPERIOD_82576
			| (incvalue & INCVALUE_82576_MASK));

	return 0;
}

static int igb_ptp_adjfreq_82580(struct ptp_clock_info *ptp, s32 ppb)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	struct e1000_hw *hw = &igb->hw;
	int neg_adj = 0;
	u64 rate;
	u32 inca;

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}
	rate = ppb;
	rate <<= 26;
	rate = div_u64(rate, 1953125);

	/* At 2.5G speeds, the TIMINCA register on I354 updates the clock 2.5x
	 * as quickly. Account for this by dividing the adjustment by 2.5.
	 */
	if (hw->mac.type == e1000_i354) {
		u32 status = E1000_READ_REG(hw, E1000_STATUS);

		if ((status & E1000_STATUS_2P5_SKU) &&
		    !(status & E1000_STATUS_2P5_SKU_OVER)) {
			rate <<= 1;
			rate = div_u64(rate, 5);
		}
	}

	inca = rate & INCVALUE_MASK;
	if (neg_adj)
		inca |= ISGN;

	E1000_WRITE_REG(hw, E1000_TIMINCA, inca);

	return 0;
}

static int igb_ptp_adjtime_82576(struct ptp_clock_info *ptp, s64 delta)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;
	s64 now;

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	now = timecounter_read(&igb->tc);
	now += delta;
	timecounter_init(&igb->tc, &igb->cc, now);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

static int igb_ptp_adjtime_i210(struct ptp_clock_info *ptp, s64 delta)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;
	struct timespec now, then = ns_to_timespec(delta);

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	igb_ptp_read_i210(igb, &now);
	now = timespec_add(now, then);
	igb_ptp_write_i210(igb, (const struct timespec *)&now);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

static int igb_ptp_gettime64_82576(struct ptp_clock_info *ptp,
				   struct timespec64 *ts64)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;
	u64 ns;

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	ns = timecounter_read(&igb->tc);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	*ts64 = ns_to_timespec64(ns);

	return 0;
}

static int igb_ptp_gettime64_i210(struct ptp_clock_info *ptp,
				  struct timespec64 *ts64)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	struct timespec ts;
	unsigned long flags;

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	igb_ptp_read_i210(igb, &ts);
	*ts64 = timespec_to_timespec64(ts);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
static int igb_ptp_settime64_82576(struct ptp_clock_info *ptp,
				   const struct timespec64 *ts64)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;
	u64 ns;

	ns = timespec64_to_ns(ts64);

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	timecounter_init(&igb->tc, &igb->cc, ns);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

#endif
static int igb_ptp_settime64_i210(struct ptp_clock_info *ptp,
				  const struct timespec64 *ts64)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	struct timespec ts;
	unsigned long flags;

	ts = timespec64_to_timespec(*ts64);
	spin_lock_irqsave(&igb->tmreg_lock, flags);

	igb_ptp_write_i210(igb, &ts);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
static int igb_ptp_gettime_82576(struct ptp_clock_info *ptp,
				 struct timespec *ts)
{
	struct timespec64 ts64;
	int err;

	err = igb_ptp_gettime64_82576(ptp, &ts64);
	if (err)
		return err;

	*ts = timespec64_to_timespec(ts64);

	return 0;
}

static int igb_ptp_gettime_i210(struct ptp_clock_info *ptp,
				struct timespec *ts)
{
	struct timespec64 ts64;
	int err;

	err = igb_ptp_gettime64_i210(ptp, &ts64);
	if (err)
		return err;

	*ts = timespec64_to_timespec(ts64);

	return 0;
}

static int igb_ptp_settime_82576(struct ptp_clock_info *ptp,
				 const struct timespec *ts)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;
	u64 ns;

	ns = ts->tv_sec * 1000000000ULL;
	ns += ts->tv_nsec;

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	timecounter_init(&igb->tc, &igb->cc, ns);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

static int igb_ptp_settime_i210(struct ptp_clock_info *ptp,
				const struct timespec *ts)
{
	struct igb_adapter *igb = container_of(ptp, struct igb_adapter,
					       ptp_caps);
	unsigned long flags;

	spin_lock_irqsave(&igb->tmreg_lock, flags);

	igb_ptp_write_i210(igb, ts);

	spin_unlock_irqrestore(&igb->tmreg_lock, flags);

	return 0;
}

#endif
static int igb_ptp_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

/**
 * igb_ptp_tx_work
 * @work: pointer to work struct
 *
 * This work function polls the TSYNCTXCTL valid bit to determine when a
 * timestamp has been taken for the current stored skb.
 */
void igb_ptp_tx_work(struct work_struct *work)
{
	struct igb_adapter *adapter = container_of(work, struct igb_adapter,
						   ptp_tx_work);
	struct e1000_hw *hw = &adapter->hw;
	u32 tsynctxctl;

	if (!adapter->ptp_tx_skb)
		return;

	if (time_is_before_jiffies(adapter->ptp_tx_start +
				   IGB_PTP_TX_TIMEOUT)) {
		dev_kfree_skb_any(adapter->ptp_tx_skb);
		adapter->ptp_tx_skb = NULL;
		clear_bit_unlock(__IGB_PTP_TX_IN_PROGRESS, &adapter->state);
		adapter->tx_hwtstamp_timeouts++;
		dev_warn(&adapter->pdev->dev, "clearing Tx timestamp hang\n");
		return;
	}

	tsynctxctl = E1000_READ_REG(hw, E1000_TSYNCTXCTL);
	if (tsynctxctl & E1000_TSYNCTXCTL_VALID)
		igb_ptp_tx_hwtstamp(adapter);
	else
		/* reschedule to check later */
		schedule_work(&adapter->ptp_tx_work);
}

static void igb_ptp_overflow_check_82576(struct work_struct *work)
{
	struct igb_adapter *igb =
		container_of(work, struct igb_adapter, ptp_overflow_work.work);
	struct timespec64 ts64;

	igb_ptp_gettime64_82576(&igb->ptp_caps, &ts64);

	pr_debug("igb overflow check at %lld.%09lu\n",
		 (long long)ts64.tv_sec, ts64.tv_nsec);

	schedule_delayed_work(&igb->ptp_overflow_work,
			      IGB_SYSTIM_OVERFLOW_PERIOD);
}

/**
 * igb_ptp_rx_hang - detect error case when Rx timestamp registers latched
 * @adapter: private network adapter structure
 *
 * This watchdog task is scheduled to detect error case where hardware has
 * dropped an Rx packet that was timestamped when the ring is full. The
 * particular error is rare but leaves the device in a state unable to timestamp
 * any future packets.
 */
void igb_ptp_rx_hang(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 tsyncrxctl = E1000_READ_REG(hw, E1000_TSYNCRXCTL);
	unsigned long rx_event;

	if (hw->mac.type != e1000_82576)
		return;

	/* If we don't have a valid timestamp in the registers, just update the
	 * timeout counter and exit
	 */
	if (!(tsyncrxctl & E1000_TSYNCRXCTL_VALID)) {
		adapter->last_rx_ptp_check = jiffies;
		return;
	}

	/* Determine the most recent watchdog or rx_timestamp event */
	rx_event = adapter->last_rx_ptp_check;
	if (time_after(adapter->last_rx_timestamp, rx_event))
		rx_event = adapter->last_rx_timestamp;

	/* Only need to read the high RXSTMP register to clear the lock */
	if (time_is_before_jiffies(rx_event + 5 * HZ)) {
		E1000_READ_REG(hw, E1000_RXSTMPH);
		adapter->last_rx_ptp_check = jiffies;
		adapter->rx_hwtstamp_cleared++;
		dev_warn(&adapter->pdev->dev, "clearing Rx timestamp hang\n");
	}
}

/**
 * igb_ptp_tx_hwtstamp - utility function which checks for TX time stamp
 * @adapter: Board private structure.
 *
 * If we were asked to do hardware stamping and such a time stamp is
 * available, then it must have been for this skb here because we only
 * allow only one such packet into the queue.
 */
void igb_ptp_tx_hwtstamp(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct skb_shared_hwtstamps shhwtstamps;
	u64 regval;

	regval = E1000_READ_REG(hw, E1000_TXSTMPL);
	regval |= (u64)E1000_READ_REG(hw, E1000_TXSTMPH) << 32;

	igb_ptp_systim_to_hwtstamp(adapter, &shhwtstamps, regval);
	skb_tstamp_tx(adapter->ptp_tx_skb, &shhwtstamps);
	dev_kfree_skb_any(adapter->ptp_tx_skb);
	adapter->ptp_tx_skb = NULL;
	clear_bit_unlock(__IGB_PTP_TX_IN_PROGRESS, &adapter->state);
}

/**
 * igb_ptp_rx_pktstamp - retrieve Rx per packet timestamp
 * @q_vector: Pointer to interrupt specific structure
 * @va: Pointer to address containing Rx buffer
 * @skb: Buffer containing timestamp and packet
 *
 * This function is meant to retrieve a timestamp from the first buffer of an
 * incoming frame.  The value is stored in little endian format starting on
 * byte 8.
 */
void igb_ptp_rx_pktstamp(struct igb_q_vector *q_vector,
			 unsigned char *va,
			 struct sk_buff *skb)
{
	__le64 *regval = (__le64 *)va;

	/*
	 * The timestamp is recorded in little endian format.
	 * DWORD: 0        1        2        3
	 * Field: Reserved Reserved SYSTIML  SYSTIMH
	 */
	igb_ptp_systim_to_hwtstamp(q_vector->adapter, skb_hwtstamps(skb),
				   le64_to_cpu(regval[1]));
}

/**
 * igb_ptp_rx_rgtstamp - retrieve Rx timestamp stored in register
 * @q_vector: Pointer to interrupt specific structure
 * @skb: Buffer containing timestamp and packet
 *
 * This function is meant to retrieve a timestamp from the internal registers
 * of the adapter and store it in the skb.
 */
void igb_ptp_rx_rgtstamp(struct igb_q_vector *q_vector,
			 struct sk_buff *skb)
{
	struct igb_adapter *adapter = q_vector->adapter;
	struct e1000_hw *hw = &adapter->hw;
	u64 regval;

	/*
	 * If this bit is set, then the RX registers contain the time stamp. No
	 * other packet will be time stamped until we read these registers, so
	 * read the registers to make them available again. Because only one
	 * packet can be time stamped at a time, we know that the register
	 * values must belong to this one here and therefore we don't need to
	 * compare any of the additional attributes stored for it.
	 *
	 * If nothing went wrong, then it should have a shared tx_flags that we
	 * can turn into a skb_shared_hwtstamps.
	 */
	if (!(E1000_READ_REG(hw, E1000_TSYNCRXCTL) & E1000_TSYNCRXCTL_VALID))
		return;

	regval = E1000_READ_REG(hw, E1000_RXSTMPL);
	regval |= (u64)E1000_READ_REG(hw, E1000_RXSTMPH) << 32;

	igb_ptp_systim_to_hwtstamp(adapter, skb_hwtstamps(skb), regval);

	/* Update the last_rx_timestamp timer in order to enable watchdog check
	 * for error case of latched timestamp on a dropped packet.
	 */
	adapter->last_rx_timestamp = jiffies;
}

/**
 * igb_ptp_get_ts_config - get hardware time stamping config
 * @netdev:
 * @ifreq:
 *
 * Get the hwtstamp_config settings to return to the user. Rather than attempt
 * to deconstruct the settings from the registers, just return a shadow copy
 * of the last known settings.
 **/
int igb_ptp_get_ts_config(struct net_device *netdev, struct ifreq *ifr)
{
	struct igb_adapter *adapter = netdev_priv(netdev);
	struct hwtstamp_config *config = &adapter->tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ?
		-EFAULT : 0;
}

/**
 * igb_ptp_set_timestamp_mode - setup hardware for timestamping
 * @adapter: networking device structure
 * @config: hwtstamp configuration
 *
 * Outgoing time stamping can be enabled and disabled. Play nice and
 * disable it when requested, although it shouldn't case any overhead
 * when no packet needs it. At most one packet in the queue may be
 * marked for time stamping, otherwise it would be impossible to tell
 * for sure to which packet the hardware time stamp belongs.
 *
 * Incoming time stamping has to be configured via the hardware
 * filters. Not all combinations are supported, in particular event
 * type has to be specified. Matching the kind of event packet is
 * not supported, with the exception of "all V2 events regardless of
 * level 2 or 4".
 *
 */
static int igb_ptp_set_timestamp_mode(struct igb_adapter *adapter,
				      struct hwtstamp_config *config)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 tsync_tx_ctl = E1000_TSYNCTXCTL_ENABLED;
	u32 tsync_rx_ctl = E1000_TSYNCRXCTL_ENABLED;
	u32 tsync_rx_cfg = 0;
	bool is_l4 = false;
	bool is_l2 = false;
	u32 regval;

	/* reserved for future extensions */
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		tsync_tx_ctl = 0;
	case HWTSTAMP_TX_ON:
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		tsync_rx_ctl = 0;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
		tsync_rx_ctl |= E1000_TSYNCRXCTL_TYPE_L4_V1;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V1_SYNC_MESSAGE;
		is_l4 = true;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		tsync_rx_ctl |= E1000_TSYNCRXCTL_TYPE_L4_V1;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V1_DELAY_REQ_MESSAGE;
		is_l4 = true;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		tsync_rx_ctl |= E1000_TSYNCRXCTL_TYPE_EVENT_V2;
		config->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		is_l2 = true;
		is_l4 = true;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_ALL:
		/*
		 * 82576 cannot timestamp all packets, which it needs to do to
		 * support both V1 Sync and Delay_Req messages
		 */
		if (hw->mac.type != e1000_82576) {
			tsync_rx_ctl |= E1000_TSYNCRXCTL_TYPE_ALL;
			config->rx_filter = HWTSTAMP_FILTER_ALL;
			break;
		}
		/* fall through */
	default:
		config->rx_filter = HWTSTAMP_FILTER_NONE;
		return -ERANGE;
	}

	if (hw->mac.type == e1000_82575) {
		if (tsync_rx_ctl | tsync_tx_ctl)
			return -EINVAL;
		return 0;
	}

	/*
	 * Per-packet timestamping only works if all packets are
	 * timestamped, so enable timestamping in all packets as
	 * long as one rx filter was configured.
	 */
	if ((hw->mac.type >= e1000_82580) && tsync_rx_ctl) {
		tsync_rx_ctl = E1000_TSYNCRXCTL_ENABLED;
		tsync_rx_ctl |= E1000_TSYNCRXCTL_TYPE_ALL;
		config->rx_filter = HWTSTAMP_FILTER_ALL;
		is_l2 = true;
		is_l4 = true;

		if ((hw->mac.type == e1000_i210) ||
		    (hw->mac.type == e1000_i211)) {
			regval = E1000_READ_REG(hw, E1000_RXPBS);
			regval |= E1000_RXPBS_CFG_TS_EN;
			E1000_WRITE_REG(hw, E1000_RXPBS, regval);
		}
	}

	/* enable/disable TX */
	regval = E1000_READ_REG(hw, E1000_TSYNCTXCTL);
	regval &= ~E1000_TSYNCTXCTL_ENABLED;
	regval |= tsync_tx_ctl;
	E1000_WRITE_REG(hw, E1000_TSYNCTXCTL, regval);

	/* enable/disable RX */
	regval = E1000_READ_REG(hw, E1000_TSYNCRXCTL);
	regval &= ~(E1000_TSYNCRXCTL_ENABLED | E1000_TSYNCRXCTL_TYPE_MASK);
	regval |= tsync_rx_ctl;
	E1000_WRITE_REG(hw, E1000_TSYNCRXCTL, regval);

	/* define which PTP packets are time stamped */
	E1000_WRITE_REG(hw, E1000_TSYNCRXCFG, tsync_rx_cfg);

#ifdef HAVE_PF_RING /* PER PACKET HW TIMESTAMP (ns) */ 
        if (hw->mac.type >= e1000_82580) {
		int i, reg_idx;
		u32 reg;

        	for (i = 0; i < adapter->num_q_vectors; i++) {
			reg_idx = adapter->q_vector[i]->rx.ring->reg_idx;
			reg = E1000_READ_REG(hw, E1000_SRRCTL(reg_idx));

        		/* Enable Timestamp Received packet
			 * Timestamp is placed only in buffers of received packets that meet 
			 * the criteria defined in the TSYNCRXCTL.Type field, 2-tuple filters 
			 * or ETQF registers. A 40 bit timestamp generated from the value in 
			 * SYSTIMH and SYSTIML registers is placed in the receive buffer. */
			if (tsync_rx_ctl != 0) /* enabling rx ts (Timestamp Reserved bit) */
				reg |= 0x40000000;
			else /* disabling rx ts */
				reg &= ~0x40000000;
				  
  			E1000_WRITE_REG(hw, E1000_SRRCTL(reg_idx), reg);
         
#if 0
			printk("[PF_RING] [tsync_tx_ctl=%d][tsync_rx_ctl=%d][rx_queue=%d][TSAUXC=%u][SRRCTL=%08X]\n",
			       tsync_tx_ctl, tsync_rx_ctl, reg_idx,
			       E1000_READ_REG(hw, E1000_TSAUXC),
			       E1000_READ_REG(hw, E1000_SRRCTL(reg_idx)));
#endif
		}
        }
#endif

	/* define ethertype filter for timestamped packets */
	if (is_l2)
		E1000_WRITE_REG(hw, E1000_ETQF(3),
		     (E1000_ETQF_FILTER_ENABLE | /* enable filter */
		      E1000_ETQF_1588 | /* enable timestamping */
		      ETH_P_1588));     /* 1588 eth protocol type */
	else
		E1000_WRITE_REG(hw, E1000_ETQF(3), 0);

	/* L4 Queue Filter[3]: filter by destination port and protocol */
	if (is_l4) {
		u32 ftqf = (IPPROTO_UDP /* UDP */
			    | E1000_FTQF_VF_BP /* VF not compared */
			    | E1000_FTQF_1588_TIME_STAMP /* Enable Timestamp */
			    | E1000_FTQF_MASK); /* mask all inputs */
		ftqf &= ~E1000_FTQF_MASK_PROTO_BP; /* enable protocol check */

		E1000_WRITE_REG(hw, E1000_IMIR(3), htons(PTP_EV_PORT));
		E1000_WRITE_REG(hw, E1000_IMIREXT(3),
		     (E1000_IMIREXT_SIZE_BP | E1000_IMIREXT_CTRL_BP));
		if (hw->mac.type == e1000_82576) {
			/* enable source port check */
			E1000_WRITE_REG(hw, E1000_SPQF(3), htons(PTP_EV_PORT));
			ftqf &= ~E1000_FTQF_MASK_SOURCE_PORT_BP;
		}
		E1000_WRITE_REG(hw, E1000_FTQF(3), ftqf);
	} else {
		E1000_WRITE_REG(hw, E1000_FTQF(3), E1000_FTQF_MASK);
	}
	E1000_WRITE_FLUSH(hw);

	/* clear TX/RX time stamp registers, just to be sure */
	regval = E1000_READ_REG(hw, E1000_TXSTMPL);
	regval = E1000_READ_REG(hw, E1000_TXSTMPH);
	regval = E1000_READ_REG(hw, E1000_RXSTMPL);
	regval = E1000_READ_REG(hw, E1000_RXSTMPH);

	return 0;
}

/**
 * igb_ptp_set_ts_config - set hardware time stamping config
 * @netdev:
 * @ifreq:
 *
 **/
int igb_ptp_set_ts_config(struct net_device *netdev, struct ifreq *ifr)
{
	struct igb_adapter *adapter = netdev_priv(netdev);
	struct hwtstamp_config config;
	int err;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = igb_ptp_set_timestamp_mode(adapter, &config);
	if (err)
		return err;

	/* save these settings for future reference */
	memcpy(&adapter->tstamp_config, &config,
	       sizeof(adapter->tstamp_config));

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

void igb_ptp_init(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;

	switch (hw->mac.type) {
	case e1000_82576:
		snprintf(adapter->ptp_caps.name, 16, "%pm", netdev->dev_addr);
		adapter->ptp_caps.owner = THIS_MODULE;
		adapter->ptp_caps.max_adj = 999999881;
		adapter->ptp_caps.n_ext_ts = 0;
		adapter->ptp_caps.pps = 0;
		adapter->ptp_caps.adjfreq = igb_ptp_adjfreq_82576;
		adapter->ptp_caps.adjtime = igb_ptp_adjtime_82576;
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
		adapter->ptp_caps.gettime64 = igb_ptp_gettime64_82576;
		adapter->ptp_caps.settime64 = igb_ptp_settime64_82576;
#else
		adapter->ptp_caps.gettime = igb_ptp_gettime_82576;
		adapter->ptp_caps.settime = igb_ptp_settime_82576;
#endif
		adapter->ptp_caps.enable = igb_ptp_enable;
		adapter->cc.read = igb_ptp_read_82576;
		adapter->cc.mask = CLOCKSOURCE_MASK(64);
		adapter->cc.mult = 1;
		adapter->cc.shift = IGB_82576_TSYNC_SHIFT;
		/* Dial the nominal frequency. */
		E1000_WRITE_REG(hw, E1000_TIMINCA,
				INCPERIOD_82576 | INCVALUE_82576);
		break;
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
		snprintf(adapter->ptp_caps.name, 16, "%pm", netdev->dev_addr);
		adapter->ptp_caps.owner = THIS_MODULE;
		adapter->ptp_caps.max_adj = 62499999;
		adapter->ptp_caps.n_ext_ts = 0;
		adapter->ptp_caps.pps = 0;
		adapter->ptp_caps.adjfreq = igb_ptp_adjfreq_82580;
		adapter->ptp_caps.adjtime = igb_ptp_adjtime_82576;
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
		adapter->ptp_caps.gettime64 = igb_ptp_gettime64_82576;
		adapter->ptp_caps.settime64 = igb_ptp_settime64_82576;
#else
		adapter->ptp_caps.gettime = igb_ptp_gettime_82576;
		adapter->ptp_caps.settime = igb_ptp_settime_82576;
#endif
		adapter->ptp_caps.enable = igb_ptp_enable;
		adapter->cc.read = igb_ptp_read_82580;
		adapter->cc.mask = CLOCKSOURCE_MASK(IGB_NBITS_82580);
		adapter->cc.mult = 1;
		adapter->cc.shift = 0;
		/* Enable the timer functions by clearing bit 31. */
		E1000_WRITE_REG(hw, E1000_TSAUXC, 0x0);
		break;
	case e1000_i210:
	case e1000_i211:
		snprintf(adapter->ptp_caps.name, 16, "%pm", netdev->dev_addr);
		adapter->ptp_caps.owner = THIS_MODULE;
		adapter->ptp_caps.max_adj = 62499999;
		adapter->ptp_caps.n_ext_ts = 0;
		adapter->ptp_caps.pps = 0;
		adapter->ptp_caps.adjfreq = igb_ptp_adjfreq_82580;
		adapter->ptp_caps.adjtime = igb_ptp_adjtime_i210;
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
		adapter->ptp_caps.gettime64 = igb_ptp_gettime64_i210;
		adapter->ptp_caps.settime64 = igb_ptp_settime64_i210;
#else
		adapter->ptp_caps.gettime = igb_ptp_gettime_i210;
		adapter->ptp_caps.settime = igb_ptp_settime_i210;
#endif
		adapter->ptp_caps.enable = igb_ptp_enable;
		/* Enable the timer functions by clearing bit 31. */
		E1000_WRITE_REG(hw, E1000_TSAUXC, 0x0);
		break;
	default:
		adapter->ptp_clock = NULL;
		return;
	}

	E1000_WRITE_FLUSH(hw);

	spin_lock_init(&adapter->tmreg_lock);
	INIT_WORK(&adapter->ptp_tx_work, igb_ptp_tx_work);

	/* Initialize the clock and overflow work for devices that need it. */
	if ((hw->mac.type == e1000_i210) || (hw->mac.type == e1000_i211)) {
		struct timespec64 ts = ktime_to_timespec64(ktime_get_real());

		igb_ptp_settime64_i210(&adapter->ptp_caps, &ts);
	} else {
		timecounter_init(&adapter->tc, &adapter->cc,
				 ktime_to_ns(ktime_get_real()));

		INIT_DELAYED_WORK(&adapter->ptp_overflow_work,
				  igb_ptp_overflow_check_82576);

		schedule_delayed_work(&adapter->ptp_overflow_work,
				      IGB_SYSTIM_OVERFLOW_PERIOD);
	}

	/* Initialize the time sync interrupts for devices that support it. */
	if (hw->mac.type >= e1000_82580) {
		E1000_WRITE_REG(hw, E1000_TSIM, E1000_TSIM_TXTS);
		E1000_WRITE_REG(hw, E1000_IMS, E1000_IMS_TS);
	}

	adapter->tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	adapter->tstamp_config.tx_type = HWTSTAMP_TX_OFF;

	adapter->ptp_clock = ptp_clock_register(&adapter->ptp_caps,
						&adapter->pdev->dev);
	if (IS_ERR(adapter->ptp_clock)) {
		adapter->ptp_clock = NULL;
		dev_err(&adapter->pdev->dev, "ptp_clock_register failed\n");
	} else {
		dev_info(&adapter->pdev->dev, "added PHC on %s\n",
			 adapter->netdev->name);
		adapter->flags |= IGB_FLAG_PTP;
	}
}

/**
 * igb_ptp_stop - Disable PTP device and stop the overflow check.
 * @adapter: Board private structure.
 *
 * This function stops the PTP support and cancels the delayed work.
 **/
void igb_ptp_stop(struct igb_adapter *adapter)
{
	switch (adapter->hw.mac.type) {
	case e1000_82576:
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
		cancel_delayed_work_sync(&adapter->ptp_overflow_work);
		break;
	case e1000_i210:
	case e1000_i211:
		/* No delayed work to cancel. */
		break;
	default:
		return;
	}

	cancel_work_sync(&adapter->ptp_tx_work);
	if (adapter->ptp_tx_skb) {
		dev_kfree_skb_any(adapter->ptp_tx_skb);
		adapter->ptp_tx_skb = NULL;
		clear_bit_unlock(__IGB_PTP_TX_IN_PROGRESS, &adapter->state);
	}

	if (adapter->ptp_clock) {
		ptp_clock_unregister(adapter->ptp_clock);
		dev_info(&adapter->pdev->dev, "removed PHC on %s\n",
			 adapter->netdev->name);
		adapter->flags &= ~IGB_FLAG_PTP;
	}
}

/**
 * igb_ptp_reset - Re-enable the adapter for PTP following a reset.
 * @adapter: Board private structure.
 *
 * This function handles the reset work required to re-enable the PTP device.
 **/
void igb_ptp_reset(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	if (!(adapter->flags & IGB_FLAG_PTP))
		return;

	/* reset the tstamp_config */
	igb_ptp_set_timestamp_mode(adapter, &adapter->tstamp_config);

	switch (adapter->hw.mac.type) {
	case e1000_82576:
		/* Dial the nominal frequency. */
		E1000_WRITE_REG(hw, E1000_TIMINCA, INCPERIOD_82576 |
						   INCVALUE_82576);
		break;
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
	case e1000_i210:
	case e1000_i211:
		/* Enable the timer functions and interrupts. */
		E1000_WRITE_REG(hw, E1000_TSAUXC, 0x0);
		E1000_WRITE_REG(hw, E1000_TSIM, E1000_TSIM_TXTS);
		E1000_WRITE_REG(hw, E1000_IMS, E1000_IMS_TS);
		break;
	default:
		/* No work to do. */
		return;
	}

	/* Re-initialize the timer. */
	if ((hw->mac.type == e1000_i210) || (hw->mac.type == e1000_i211)) {
		struct timespec64 ts64 = ktime_to_timespec64(ktime_get_real());

		igb_ptp_settime64_i210(&adapter->ptp_caps, &ts64);
	} else {
		timecounter_init(&adapter->tc, &adapter->cc,
				 ktime_to_ns(ktime_get_real()));
	}
}
#endif /* HAVE_PTP_1588_CLOCK */
