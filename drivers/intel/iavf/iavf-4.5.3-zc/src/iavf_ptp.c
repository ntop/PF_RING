// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2013, Intel Corporation. */

#include "iavf.h"
#include "iavf_prototype.h"

/**
 * iavf_virtchnl_to_ptp_func - Convert VIRTCHNL function type to PTP stack
 * @virtchnl_func: virtchnl pin function type specification
 */
static enum ptp_pin_function
iavf_virtchnl_to_ptp_func(u8 virtchnl_func)
{
	switch (virtchnl_func) {
	case VIRTCHNL_PHC_PIN_FUNC_NONE:
		return PTP_PF_NONE;
	case VIRTCHNL_PHC_PIN_FUNC_EXT_TS:
		return PTP_PF_EXTTS;
	case VIRTCHNL_PHC_PIN_FUNC_PER_OUT:
		return PTP_PF_PEROUT;
	default:
		return PTP_PF_NONE;
	}
}

/**
 * iavf_ptp_func_to_virtchnl - Convert PTP pin function to virtchnl enum
 * @ptp_func: PTP pin function enumeration type
 */
static enum virtchnl_phc_pin_func
iavf_ptp_func_to_virtchnl(enum ptp_pin_function ptp_func)
{
	switch (ptp_func) {
	case PTP_PF_NONE:
		return VIRTCHNL_PHC_PIN_FUNC_NONE;
	case PTP_PF_EXTTS:
		return VIRTCHNL_PHC_PIN_FUNC_EXT_TS;
	case PTP_PF_PEROUT:
		return VIRTCHNL_PHC_PIN_FUNC_PER_OUT;
	default:
		return VIRTCHNL_PHC_PIN_FUNC_NONE;
	}
}

/**
 * iavf_ptp_disable_tx_tstamp - Disable timestamping in Tx rings
 * @adapter: private adapter structure
 *
 * Disable timestamp capture for all Tx rings
 */
static void iavf_ptp_disable_tx_tstamp(struct iavf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->num_active_queues; i++)
		adapter->tx_rings[i].flags &= ~IAVF_TXRX_FLAGS_HW_TSTAMP;
}

/**
 * iavf_ptp_enable_tx_tstamp - Enable timestamping in Tx rings
 * @adapter: private adapter structure
 *
 * Enable timestamp capture for all Tx rings
 */
static void iavf_ptp_enable_tx_tstamp(struct iavf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->num_active_queues; i++)
		adapter->tx_rings[i].flags |= IAVF_TXRX_FLAGS_HW_TSTAMP;
}

/**
 * iavf_ptp_disable_rx_tstamp - Disable timestamping in Rx rings
 * @adapter: private adapter structure
 *
 * Disable timestamp reporting for all Rx rings.
 */
static void iavf_ptp_disable_rx_tstamp(struct iavf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->num_active_queues; i++)
		adapter->rx_rings[i].flags &= ~IAVF_TXRX_FLAGS_HW_TSTAMP;
}

/**
 * iavf_ptp_enable_rx_tstamp - Enable timestamping in Rx rings
 * @adapter: private adapter structure
 *
 * Enable timestamp reporting for all Rx rings.
 */
static void iavf_ptp_enable_rx_tstamp(struct iavf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->num_active_queues; i++)
		adapter->rx_rings[i].flags |= IAVF_TXRX_FLAGS_HW_TSTAMP;
}

/**
 * iavf_ptp_set_timestamp_mode - Set device timestamping mode
 * @adapter: private adapter structure
 * @config: timestamping configuration request
 *
 * Set the timestamping mode requested from the SIOCSHWTSTAMP ioctl.
 *
 * Note: this function always translates Rx timestamp requests for any packet
 * category into HWTSTAMP_FILTER_ALL.
 */
static int
iavf_ptp_set_timestamp_mode(struct iavf_adapter *adapter, struct hwtstamp_config *config)
{
	/* Reserved for future extensions. */
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		iavf_ptp_disable_tx_tstamp(adapter);
		break;
	case HWTSTAMP_TX_ON:
		if (!(iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_TX_TSTAMP)))
			return -EOPNOTSUPP;
		iavf_ptp_enable_tx_tstamp(adapter);
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		iavf_ptp_disable_rx_tstamp(adapter);
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
		if (!(iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_RX_TSTAMP)))
			return -EOPNOTSUPP;
		config->rx_filter = HWTSTAMP_FILTER_ALL;
		iavf_ptp_enable_rx_tstamp(adapter);
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

/**
 * iavf_ptp_get_ts_config - Get timestamping configuration for SIOCGHWTSTAMP
 * @adapter: private adapter structure
 * @ifr: the ioctl request structure
 *
 * Copy the current hardware timestamping configuration back to userspace.
 * Called in response to the SIOCGHWTSTAMP ioctl that queries a device's
 * current timestamp settings.
 */
int iavf_ptp_get_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr)
{
	struct hwtstamp_config *config = &adapter->ptp.hwtstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ? -EFAULT : 0;
}

/**
 * iavf_ptp_set_ts_config - Set timestamping configuration from SIOCSHWTSTAMP
 * @adapter: private adapter structure
 * @ifr: the ioctl request structure
 *
 * Program the requested timestamping configuration from SIOCSHWTSTAMP ioctl
 * to the device.
 */
int iavf_ptp_set_ts_config(struct iavf_adapter *adapter, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = iavf_ptp_set_timestamp_mode(adapter, &config);
	if (err)
		return err;

	/* Save successful settings for future reference */
	adapter->ptp.hwtstamp_config = config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

/**
 * clock_to_adapter - Convert clock info pointer to adapter pointer
 * @ptp_info: PTP info structure
 *
 * Use container_of in order to extract a pointer to the iAVF adapter private
 * structure.
 */
static struct iavf_adapter *clock_to_adapter(struct ptp_clock_info *ptp_info)
{
	struct iavf_ptp *ptp_priv;

	ptp_priv = container_of(ptp_info, struct iavf_ptp, info);
	return container_of(ptp_priv, struct iavf_adapter, ptp);
}

/**
 * iavf_ptp_cap_supported - Check if a PTP capability is supported
 * @adapter: private adapter structure
 * @cap: the capability bitmask to check
 *
 * Return true if every capability set in cap is also set in the enabled
 * capabilities reported by the PF.
 */
bool iavf_ptp_cap_supported(struct iavf_adapter *adapter, u32 cap)
{
	if (!PTP_ALLOWED(adapter))
		return false;

	/* Only return true if every bit in cap is set in hw_caps.caps */
	return (adapter->ptp.hw_caps.caps & cap) == cap;
}

/**
 * iavf_send_phc_read - Send request to read PHC time
 * @adapter: private adapter structure
 *
 * Send a request to obtain the PTP hardware clock time. This allocates the
 * VIRTCHNL_OP_1588_PTP_GET_TIME message and queues it up to send to
 * indirectly read the PHC time.
 *
 * This function does not wait for the reply from the PF.
 */
static int iavf_send_phc_read(struct iavf_adapter *adapter)
{
	struct iavf_vc_msg *vc_msg;

	if (!adapter->ptp.initialized)
		return -EOPNOTSUPP;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_GET_TIME,
				   sizeof(struct virtchnl_phc_time));
	if (!vc_msg)
		return -ENOMEM;

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/**
 * iavf_read_phc_indirect - Indirectly read the PHC time via virtchnl
 * @adapter: private adapter structure
 * @ts: storage for the timestamp value
 * @sts: system timestamp values before and after the read
 *
 * Used when the device does not have direct register access to the PHC time.
 * Indirectly reads the time via the VIRTCHNL_OP_1588_PTP_GET_TIME, and waits
 * for the reply from the PF.
 *
 * Based on some simple measurements using ftrace and phc2sys, this clock
 * access method has about a ~110 usec latency even when the system is not
 * under load. In order to achieve acceptable results when using phc2sys with
 * the indirect clock access method, it is recommended to use more
 * conservative proportional and integration constants with the P/I servo.
 */
static int iavf_read_phc_indirect(struct iavf_adapter *adapter, struct timespec64 *ts,
				  struct ptp_system_timestamp *sts)
{
	long ret;
	int err;

	adapter->ptp.phc_time_ready = false;
	ptp_read_system_prets(sts);

	err = iavf_send_phc_read(adapter);
	if (err)
		return err;

	ret = wait_event_interruptible_timeout(adapter->ptp.phc_time_waitqueue,
					       adapter->ptp.phc_time_ready,
					       HZ);
	if (ret < 0)
		return ret;
	else if (!ret)
		return -EBUSY;

	*ts = ns_to_timespec64(adapter->ptp.cached_phc_time);

	ptp_read_system_postts(sts);

	return 0;
}

/**
 * iavf_read_phc_ns - Read PHC time from registers and convert to nanoseconds
 * @adapter: private adapter structure
 * @sts: system timestamp values before and after the read
 *
 * Capture the PHC time from the registers and convert it to nanoseconds.
 * Capture the system time before and after reading the lower clock register,
 * to allow more precise comparison between the PHC time and CLOCK_REALTIME.
 *
 * This requires direct access to the PHC registers, which may not be
 * available on all devices.
 *
 * If this method is available, it has a significantly reduced latency of
 * about 2 microseconds. It is preferred whenever available.
 */
static u64 iavf_read_phc_ns(struct iavf_adapter *adapter, struct ptp_system_timestamp *sts)
{
	u8 __iomem *phc_addr, *clock_lo, *clock_hi;
	u32 hi, hi2, lo;

	phc_addr = READ_ONCE(adapter->ptp.phc_addr);
	if (WARN_ON(!phc_addr))
		return 0;

	clock_lo = phc_addr + adapter->ptp.hw_caps.phc_regs.clock_lo;
	clock_hi = phc_addr + adapter->ptp.hw_caps.phc_regs.clock_hi;

	hi = readl(clock_hi);
	ptp_read_system_prets(sts);
	lo = readl(clock_lo);
	ptp_read_system_postts(sts);
	hi2 = readl(clock_hi);

	if (hi != hi2) {
		/* clock_lo might have rolled over, so recapture it */
		ptp_read_system_prets(sts);
		lo = readl(clock_lo);
		ptp_read_system_postts(sts);
		hi = hi2;
	}

	return ((u64)hi << 32) | lo;
}

/**
 * iavf_read_phc_direct - Directly read PHC time from the registers
 * @adapter: private adapter structure
 * @ts: storage for the PHC time
 * @sts: system timestamp values before and after the read
 *
 * Read the PHC time from the registers, and convert it to a timespec64.
 */
static int iavf_read_phc_direct(struct iavf_adapter *adapter, struct timespec64 *ts,
				struct ptp_system_timestamp *sts)
{
	u64 time = iavf_read_phc_ns(adapter, sts);

	*ts = ns_to_timespec64(time);

	return 0;
}

/**
 * iavf_ptp_gettimex64 - Get current PTP clock time
 * @ptp: PTP clock info structure
 * @ts: storage for the current time
 * @sts: system timestamps before and after time captured
 *
 * Read the current PTP clock time, and return it in the ts structure. Capture
 * the system time before and after the PTP clock time in sts. Note that
 * ptp_read_sytsem_prets and ptp_read_system_postts are NULL-aware and will do
 * nothing if sts is NULL.
 */
static int iavf_ptp_gettimex64(struct ptp_clock_info *ptp, struct timespec64 *ts,
			       struct ptp_system_timestamp *sts)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);

	if (!adapter->ptp.initialized)
		return -ENODEV;

	if (adapter->ptp.phc_addr)
		return iavf_read_phc_direct(adapter, ts, sts);
	else
		return iavf_read_phc_indirect(adapter, ts, sts);
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIMEX64
/**
 * iavf_ptp_gettime64 - wrapper in case ptp_caps doesn't have .gettimex64
 * @ptp: PTP clock info structure
 * @ts: storage for the current time
 *
 * Implement .gettime64 for the PTP clock. Wrapper that just calls
 * iavf_ptp_gettimex64 with a NULL sts pointer.
 */
static int iavf_ptp_gettime64(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	return iavf_ptp_gettimex64(ptp, ts, NULL);
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * iavf_ptp_gettime32 - wrapper in case ptp_caps doesn't have .gettime64
 * @ptp: PTP clock info structure
 * @ts: storage for the current time
 *
 * Implement .gettime for the PTP clock. Wrapper that just calls
 * iavf_ptp_gettime64 and converts the timespec back to a 32bit timespec
 * before returning.
 */
static int iavf_ptp_gettime32(struct ptp_clock_info *ptp, struct timespec *ts)
{
	struct timespec64 ts64;
	int err;

	err = iavf_ptp_gettime64(ptp, &ts64);
	if (err)
		return err;

	*ts = timespec64_to_timespec(ts64);
	return 0;
}
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIMEX64 */

/**
 * iavf_ptp_settime64 - Set PTP clock time
 * @ptp: PTP clock info structure
 * @ts: the time to set the clock to
 *
 * Set the PTP clock time to the requested value.
 */
static int iavf_ptp_settime64(struct ptp_clock_info *ptp, const struct timespec64 *ts)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);
	struct virtchnl_phc_time *msg;
	struct iavf_vc_msg *vc_msg;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_WRITE_PHC))
		return -EACCES;

	if (!adapter->ptp.initialized)
		return -ENODEV;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_SET_TIME, sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->time = timespec64_to_ns(ts);

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * iavf_ptp_settime32 - wrapper in case ptp_caps doesn't have .settime64
 * @ptp: PTP clock info structure
 * @ts: 32bit timespec with requested time
 *
 * Implement .settime for the PTP clock. Wrapper that just calls
 * iavf_ptp_settime64 after converting the 32bit timespec to a 64bit timespec.
 */
static int iavf_ptp_settime32(struct ptp_clock_info *ptp, const struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);

	return iavf_ptp_settime64(ptp, &ts64);
}
#endif

/**
 * iavf_ptp_adjtime - Adjust PTP clock time by requested amount
 * @ptp: PTP clock info structure
 * @delta: Offset in nanoseconds to adjust the clock time by
 *
 * Adjust the PTP clock time by the provided delta.
 */
static int iavf_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);
	struct virtchnl_phc_adj_time *msg;
	struct iavf_vc_msg *vc_msg;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_WRITE_PHC))
		return -EACCES;

	if (!adapter->ptp.initialized)
		return -ENODEV;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_ADJ_TIME, sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->delta = delta;

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/**
 * iavf_ptp_adjfine - Adjust PTP clock time by scaled parts per million
 * @ptp: PTP clock info structure
 * @scaled_ppm: scaled parts per million adjustment
 *
 * Perform a frequency adjustment by the provided scaled parts per million
 * value.
 */
static int iavf_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);
	struct virtchnl_phc_adj_freq *msg;
	struct iavf_vc_msg *vc_msg;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_WRITE_PHC))
		return -EACCES;

	if (!adapter->ptp.initialized)
		return -ENODEV;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_ADJ_FREQ, sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->scaled_ppm = (s64)scaled_ppm;

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_ADJFINE
/**
 * ppb_to_scaled_ppm - Convert parts per billion to scaled parts per million
 * @ppb: parts per billion value
 *
 * Older versions of the kernel stack request frequency adjustments in parts
 * per billion. Newer kernels can request adjustment using the full 'freq'
 * field from the 'struct timex'. This is represented as parts per million,
 * but with a 16 bit binary fractional field, i.e. parts per 1 million * 2^16.
 *
 * In essence, this is adjustments in parts per 65,536,000,000, which we call
 * scaled_ppm.
 *
 * The following equation shows the relationship between ppb and scaled_ppm:
 *
 *   ppb = scaled_ppm * 1000 / 2^16
 *
 * i.e.
 *
 *   scaled_ppm = (ppb / 1000) * 2^16
 *
 * We can further simplify this to:
 *
 *   scaled_ppm = ( ppb / 125 ) * 2^13
 *
 * For reference, here is the approximate conversion between scaled_ppm and ppb:
 *
 *   1 scaled_ppm ~= 0.015 ppb
 *   1 ppb ~= 65.5 scaled_ppm
 */
static long ppb_to_scaled_ppm(s32 ppb)
{
	long scaled_ppm;

	scaled_ppm = (s64)ppb << 13;
	scaled_ppm /= 125;

	return scaled_ppm;
}

/**
 * iavf_ptp_adjfreq - wrapper in case ptp_caps doesn't have .adjfine
 * @ptp: PTP clock info structure
 * @ppb: parts per billion frequency adjustment
 *
 * Implement .adjfreq for the PTP clock. Wrapper that converts ppb to
 * scaled_ppm and then calls iavf_ptp_adjfine.
 */
static int iavf_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	return iavf_ptp_adjfine(ptp, ppb_to_scaled_ppm(ppb));
}
#endif

/**
 * iavf_ptp_tx_hang - Detect when Tx timestamp has taken too long
 * @adapter: private adapter structure
 *
 * Detect when a Tx timestamp event has been outstanding for more than one
 * second. If this occurs, discard the waiting SKB and clear the flag.
 *
 * This is important for two reasons. First, if a timestamp event is missed
 * and we do nothing, the driver could prevent all future timestamp requests
 * indefinitely. Second, if a timestamp event is late, the timestamp extension
 * algorithm might incorrectly calculate the wrong timestamp.
 */
static void iavf_ptp_tx_hang(struct iavf_adapter *adapter)
{
	if (!test_bit(__IAVF_TX_TSTAMP_IN_PROGRESS, &adapter->crit_section))
		return;

	if (time_is_before_jiffies(adapter->ptp.tx_start + HZ)) {
		struct sk_buff *skb = adapter->ptp.tx_skb;

		adapter->ptp.tx_skb = NULL;
		clear_bit_unlock(__IAVF_TX_TSTAMP_IN_PROGRESS, &adapter->crit_section);

		/* Free the SKB after we've cleared the bitlock */
		dev_kfree_skb_any(skb);
		adapter->ptp.tx_hwtstamp_timeouts++;
	}
}

/**
 * iavf_ptp_cache_phc_time - Cache PHC time for performing timestamp extension
 * @adapter: private adapter structure
 *
 * Periodically cache the PHC time in order to allow for timestamp extension.
 * This is required because the Tx and Rx timestamps only contain 32bits of
 * nanoseconds. Timestamp extension allows calculating the corrected 64bit
 * timestamp. This algorithm relies on the cached time being within ~1 second
 * of the timestamp.
 */
static void iavf_ptp_cache_phc_time(struct iavf_adapter *adapter)
{
	if (time_is_before_jiffies(adapter->ptp.cached_phc_updated + HZ)) {
		if (adapter->ptp.phc_addr) {
			adapter->ptp.cached_phc_time = iavf_read_phc_ns(adapter, NULL);
			adapter->ptp.cached_phc_updated = jiffies;
		} else {
			/* The response from virtchnl will store the time into cached_phc_time */
			iavf_send_phc_read(adapter);
		}
	}
}

/**
 * iavf_ptp_do_aux_work - Perform periodic work required for PTP support
 * @ptp: PTP clock info structure
 *
 * Handler to take care of periodic work required for PTP operation. This
 * includes the following tasks:
 *
 *   1) updating cached_phc_time
 *
 *      cached_phc_time is used by the Tx and Rx timestamp flows in order to
 *      perform timestamp extension, by carefully comparing the timestamp
 *      32bit nanosecond timestamps and determining the corrected 64bit
 *      timestamp value to report to userspace. This algorithm only works if
 *      the cached_phc_time is within ~1 second of the Tx or Rx timestamp
 *      event. This task periodically reads the PHC time and stores it, to
 *      ensure that timestamp extension operates correctly.
 *
 *   2) canceling outstanding Tx timestamp events
 *
 *      Tx timestamps require waiting to receive a timestamp event indication
 *      from hardware. In some rare cases, the packet might have been dropped
 *      without a timestamp. If this occurs, the Tx timestamp event will never
 *      complete. To avoid this, we check if a timestamp event has taken too
 *      long, and discard it if so.
 *
 * Returns: time in jiffies until the periodic task should be re-scheduled.
 */
long iavf_ptp_do_aux_work(struct ptp_clock_info *ptp)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);

	iavf_ptp_cache_phc_time(adapter);
	iavf_ptp_tx_hang(adapter);

	/* Check work about twice a second */
	return msecs_to_jiffies(500);
}

/**
 * iavf_ptp_rq_to_pin - Locate the pin associated with a given request
 * @adapter: private adapter structure
 * @rq: the PTP feature request structure
 *
 * Search the pin configuration array to locate which pin a given function is
 * currently assigned to.
 *
 * Returns a pointer to the PTP pin description of the relevant pin, otherwise
 * returns NULL if no pin has been assigned the requested function.
 */
static struct ptp_pin_desc *
iavf_ptp_rq_to_pin(struct iavf_adapter *adapter, struct ptp_clock_request *rq)
{
	struct ptp_clock_info *info = &adapter->ptp.info;
	enum ptp_pin_function func;
	unsigned int chan;
	int pin;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		func = PTP_PF_EXTTS;
		chan = rq->extts.index;
		break;
	case PTP_CLK_REQ_PEROUT:
		func = PTP_PF_PEROUT;
		chan = rq->perout.index;
		break;
	case PTP_CLK_REQ_PPS:
		return NULL;
	}

	pin = ptp_find_pin(adapter->ptp.clock, func, chan);
	if (pin < 0)
		return NULL;

	return &info->pin_config[pin];
}

/**
 * ptp_clock_time_to_ns - Convert ptp_clock_time to u64 nanoseconds
 * @time: the ptp_clock_time to convert
 *
 * Convert the struct ptp_clock_time into u64 of nanoseconds.
 */
static u64 ptp_clock_time_to_ns(struct ptp_clock_time *time)
{
	return (time->sec * NSEC_PER_SEC) + time->nsec;
}

/**
 * iavf_ptp_fill_perout - Fill request for a periodic output signal
 * @adapter: private adapter structure
 * @msg: the virtchnl message to fill out
 * @perout: the periodic output request information
 *
 * Take a kernel request for a periodic output signal and fill out the
 * appropriate request to send over virtchnl. By default a request without
 * a duty cycle specified will use a length of half the period.
 *
 * Returns 0 on success, or an error code on a request which is not supported
 * by the virtchnl interface.
 */
static int
iavf_ptp_fill_perout(struct iavf_adapter *adapter,
		     struct virtchnl_phc_set_pin *msg,
		     struct ptp_perout_request *perout)
{
	/* Reject unsupported flags */
	if (perout->flags & ~(PTP_PEROUT_PHASE | PTP_PEROUT_DUTY_CYCLE))
		return -EOPNOTSUPP;

	msg->func = VIRTCHNL_PHC_PIN_FUNC_PER_OUT;

#if PTP_PEROUT_PHASE
	if (perout->flags & PTP_PEROUT_PHASE) {
		msg->per_out.phase = ptp_clock_time_to_ns(&perout->phase);
		msg->flags |= VIRTCHNL_PHC_PER_OUT_PHASE_START;
	} else {
		msg->per_out.start = ptp_clock_time_to_ns(&perout->start);
	}
#else
	msg->per_out.start = ptp_clock_time_to_ns(&perout->start);
#endif

	msg->per_out.period = ptp_clock_time_to_ns(&perout->period);

#if PTP_PEROUT_DUTY_CYCLE
	if (perout->flags & PTP_PEROUT_DUTY_CYCLE)
		msg->per_out.on = ptp_clock_time_to_ns(&perout->on);
	else
		/* if duty cycle is not set, always use half the period */
		msg->per_out.on = msg->per_out.period / 2;
#else
	/* if duty cycle is not set, always use half the period */
	msg->per_out.on = msg->per_out.period / 2;
#endif

	return 0;
}

/**
 * iavf_ptp_fill_extts - Fill request for an external timestamp pin
 * @adapter: private adapter structure
 * @msg: the virtchnl message to fill out
 * @extts: the PTP external timestamp request information
 *
 * Take a kernel request for an external timestamp event pin and fill out the
 * appropriate request to send over virtchnl.
 *
 * Returns 0. Currently the virtchnl interface supports all known external
 * timestamp requests. In the future, this function may fail with an exit code
 * if new request types are not handled by virtchnl.
 */
static int
iavf_ptp_fill_extts(struct iavf_adapter *adapter,
		    struct virtchnl_phc_set_pin *msg,
		    struct ptp_extts_request *extts)
{
	/* Make sure we reject commands with unknown flags */
	if (extts->flags & ~(PTP_STRICT_FLAGS | PTP_ENABLE_FEATURE |
			     PTP_RISING_EDGE | PTP_FALLING_EDGE))
		return -EOPNOTSUPP;

	msg->func = VIRTCHNL_PHC_PIN_FUNC_EXT_TS;

	/* We don't check PTP_STRICT_FLAGS. This driver is always strict and
	 * will always honor the rising/falling flags sent by the stack.
	 */
	if (extts->flags & PTP_ENABLE_FEATURE) {
		if (extts->flags & PTP_FALLING_EDGE &&
		    extts->flags & PTP_RISING_EDGE)
			msg->ext_ts.mode = VIRTCHNL_PHC_EXT_TS_BOTH_EDGES;
		else if (extts->flags & PTP_FALLING_EDGE)
			msg->ext_ts.mode = VIRTCHNL_PHC_EXT_TS_FALLING_EDGE;
		else if (extts->flags & PTP_RISING_EDGE)
			msg->ext_ts.mode = VIRTCHNL_PHC_EXT_TS_RISING_EDGE;
		else
			msg->ext_ts.mode = VIRTCHNL_PHC_EXT_TS_NONE;
	} else {
		/* If the feature enable flag is not set, always request to
		 * timestamp no edges.
		 */
		msg->ext_ts.mode = VIRTCHNL_PHC_EXT_TS_NONE;
	}

	return 0;
}

/**
 * iavf_ptp_gpio_enable - Enable general purpose IO pin according to request
 * @ptp: the PTP clock structure
 * @rq: PTP pin configuration request
 * @on: true to enable the function, false otherwise
 *
 * Enable a general purpose IO pin according to the provided request
 * structure. When enabling the pin, use the provided configuration in order
 * to fill out a virtchnl message with the appropriate information. When
 * disabling a pin, assign it to the null VIRTCHNL_PHC_PIN_FUNC_NONE function.
 */
static int
iavf_ptp_gpio_enable(struct ptp_clock_info *ptp, struct ptp_clock_request *rq,
		     int on)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_phc_set_pin *msg;
	struct iavf_vc_msg *vc_msg;
	struct ptp_pin_desc *pin;
	long ret;
	int err;

	if (rq->type != PTP_CLK_REQ_PEROUT &&
	    rq->type != PTP_CLK_REQ_EXTTS)
		return -EOPNOTSUPP;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PIN_CFG))
		return -EACCES;

	if (!adapter->ptp.initialized)
		return -ENODEV;

	pin = iavf_ptp_rq_to_pin(adapter, rq);
	if (!pin)
		return -EINVAL;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_SET_PIN_CFG,
				   sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;
	msg->pin_index = pin->index;
	msg->func_index = pin->chan;

	if (on) {
		/* This is a request to enable a feature, so fill in the
		 * appropriate information from the request structure based on
		 * the request type.
		 */
		switch (rq->type) {
		case PTP_CLK_REQ_PEROUT:
			err = iavf_ptp_fill_perout(adapter, msg, &rq->perout);
			break;
		case PTP_CLK_REQ_EXTTS:
			err = iavf_ptp_fill_extts(adapter, msg, &rq->extts);
			break;
		default:
			/* This shouldn't be possible since we check the type above */
			WARN_ONCE(1, "Unexpected request type %d\n", rq->type);
			err = -EOPNOTSUPP;
			goto err_free_vc_msg;
		}
		if (err)
			goto err_free_vc_msg;
	} else {
		/* This is a request to disable a feature. For this, we
		 * request the PF to assign the null function to the pin. This
		 * is important because it also informs the PF that a given
		 * pin is not currently in use and can safely be assigned to
		 * a new function.
		 */
		msg->func = VIRTCHNL_PHC_PIN_FUNC_NONE;
	}

	adapter->ptp.set_pin_status = VIRTCHNL_STATUS_SUCCESS;
	adapter->ptp.set_pin_ready = false;

	/* iavf_queue_vc_msg takes ownership of vc_msg allocation */
	iavf_queue_vc_msg(adapter, vc_msg);

	ret = wait_event_interruptible_timeout(adapter->ptp.gpio_waitqueue,
					       adapter->ptp.set_pin_ready,
					       3 * HZ);
	if (ret < 0)
		return ret;
	else if (!ret)
		return -EBUSY;

	if (adapter->ptp.set_pin_status) {
		dev_warn(dev, "Pin configuration failed, error %s (%d)\n",
			 virtchnl_stat_str(adapter->ptp.set_pin_status),
			 adapter->ptp.set_pin_status);
		return -EINVAL;
	}

	return 0;

err_free_vc_msg:
	kfree(vc_msg);
	return err;
}

/**
 * iavf_ptp_verify_gpio - Verify if a given GPIO pin can be assigned
 * @ptp: the PTP clock structure
 * @pin: the pin to configure
 * @func: the function type to configure it to
 * @chan: the index of the function to configure it to
 *
 * Determine whether or not a given pin can be assigned the requested
 * function. Query the PF over virtchnl to determine whether this function is
 * allowed. Wait for a response and inform the stack.
 *
 * Returns 0 if the pin is allowed to be assigned, or an error code otherwise.
 */
static int
iavf_ptp_verify_gpio(struct ptp_clock_info *ptp, unsigned int pin,
		     enum ptp_pin_function func, unsigned int chan)
{
	struct iavf_adapter *adapter = clock_to_adapter(ptp);
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_phc_set_pin *msg;
	struct iavf_vc_msg *vc_msg;
	long ret;

	if (func != PTP_PF_NONE &&
	    func != PTP_PF_EXTTS &&
	    func != PTP_PF_PEROUT)
		return -EOPNOTSUPP;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PIN_CFG))
		return -EACCES;

	if (!adapter->ptp.initialized)
		return -ENODEV;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_1588_PTP_SET_PIN_CFG,
				   sizeof(*msg));
	if (!vc_msg)
		return -ENOMEM;

	msg = (typeof(msg))vc_msg->msg;

	/* This is a verification request only */
	msg->flags = VIRTCHNL_PHC_PIN_CFG_VERIFY;
	msg->pin_index = pin;
	msg->func = iavf_ptp_func_to_virtchnl(func);
	msg->func_index = chan;

	adapter->ptp.set_pin_status = VIRTCHNL_STATUS_SUCCESS;
	adapter->ptp.set_pin_ready = false;

	iavf_queue_vc_msg(adapter, vc_msg);

	ret = wait_event_interruptible_timeout(adapter->ptp.gpio_waitqueue,
					       adapter->ptp.set_pin_ready,
					       3 * HZ);
	if (ret < 0)
		return ret;
	else if (!ret)
		return -EBUSY;

	if (adapter->ptp.set_pin_status) {
		dev_warn(dev, "Pin assignment is invalid, error %s (%d)\n",
			 virtchnl_stat_str(adapter->ptp.set_pin_status),
			 adapter->ptp.set_pin_status);
		return -EINVAL;
	}

	return 0;
}

/**
 * iavf_ptp_fill_pin_config - Request the pin configuration from PF
 * @adapter: private adapter structure
 *
 * Request current pin configuration from the PF by issuing
 * VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS message to the PF. Wait for a response
 * that indicates the configuration has been filled.
 */
static int iavf_ptp_fill_pin_config(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_hw *hw = &adapter->hw;
	int err, i;

	err = iavf_send_vf_ptp_pin_cfgs_msg(adapter);
	if (err) {
		dev_dbg(dev, "Failed to send VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS command, err %d, aq_err %s\n",
			err, iavf_aq_str(hw, hw->aq.asq_last_status));
		return err;
	}

	/* This message is sent either in context of initialization or within
	 * the context of receiving a new PTP configuration settings from the
	 * PF. Thus, we send and immediately poll for a response here.
	 */

	adapter->ptp.pin_cfg_ready = false;

#define IAVF_PTP_PIN_CFG_ATTEMPTS 10

	for (i = 0; i < IAVF_PTP_PIN_CFG_ATTEMPTS; i++ ) {
		/* Sleep for a few msec to give time for the PF to response */
		usleep_range(5000, 100000);

		err = iavf_get_vf_ptp_pin_cfgs(adapter);
		if (err == -EALREADY) {
			/* PF hasn't replied yet. Try again */
			continue;
		} else if (err) {
			dev_dbg(dev, "Failed to get VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS response, err %d, aq_err %s\n",
				err, iavf_aq_str(hw, hw->aq.asq_last_status));
			return err;
		}

		if (!adapter->ptp.pin_cfg_ready) {
			dev_dbg(dev, "Pin configuration data not complete.\n");
			return -EIO;
		}

		return 0;
	}

	/* PF did not send us the message in time */
	dev_dbg(dev, "Failed to get VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS after %d attempts\n",
		IAVF_PTP_PIN_CFG_ATTEMPTS);
	return err;
}

/**
 * iavf_ptp_init_gpio_pins - Initialize PTP GPIO pin interface
 * @adapter: private adapter structure
 * @ptp_info: the PTP info structure
 *
 * Check if the device has support for controlling GPIO pins. If so, allocate
 * a pin_config array and request the current configuration from the PF. If
 * configuration is available, fill in the appropriate pointers in the info
 * structure to enable the kernel GPIO requests.
 */
static void iavf_ptp_init_gpio_pins(struct iavf_adapter *adapter,
				    struct ptp_clock_info *ptp_info)
{
	struct virtchnl_ptp_caps *hw_caps = &adapter->ptp.hw_caps;
	struct device *dev = &adapter->pdev->dev;
	struct ptp_pin_desc *pin_config;
	int err;

	/* Check if the PF has indicated support for pin configuration */
	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PIN_CFG)) {
		dev_dbg(dev, "Device does not have access to GPIO pin configuration\n");
		return;
	}

	if (!hw_caps->n_pins) {
		dev_dbg(dev, "Device does not have any GPIO pins assigned\n");
		return;
	}

	pin_config = kcalloc(hw_caps->n_pins, sizeof(*pin_config), GFP_KERNEL);
	if (!pin_config) {
		dev_warn(dev, "Failed to allocate pin_config for GPIO pins\n");
		return;
	}

	/* iavf_ptp_fill_pin_config relies on the ptp_info->pin_config array
	 * already being assigned
	 */
	ptp_info->n_pins = hw_caps->n_pins;
	ptp_info->pin_config = pin_config;

	/* Fill the pin configuration by requesting from the PF */
	err = iavf_ptp_fill_pin_config(adapter);
	if (err) {
		dev_warn(dev, "Failed to obtain GPIO pin configuration, err %d\n",
			 err);
		ptp_info->n_pins = 0;
		ptp_info->pin_config = NULL;
		kfree(pin_config);
		return;
	}

	ptp_info->n_ext_ts = hw_caps->n_ext_ts;
	ptp_info->n_per_out = hw_caps->n_per_out;
	ptp_info->verify = iavf_ptp_verify_gpio;
	ptp_info->enable = iavf_ptp_gpio_enable;
}

/**
 * iavf_ptp_register_clock - Register a new PTP for userspace
 * @adapter: private adapter structure
 *
 * Allocate and register a new PTP clock device if necessary.
 */
static int iavf_ptp_register_clock(struct iavf_adapter *adapter)
{
	struct ptp_clock_info *ptp_info = &adapter->ptp.info;
	struct device *dev = &adapter->pdev->dev;

	memset(ptp_info, 0, sizeof(*ptp_info));

	snprintf(ptp_info->name, sizeof(ptp_info->name) - 1, "%s-%s-clk", dev_driver_string(dev),
		 netdev_name(adapter->netdev));
	ptp_info->owner = THIS_MODULE;
	ptp_info->max_adj = adapter->ptp.hw_caps.max_adj;

#if defined(HAVE_PTP_CLOCK_INFO_GETTIMEX64)
	ptp_info->gettimex64 = iavf_ptp_gettimex64;
#elif defined(HAVE_PTP_CLOCK_INFO_GETTIME64)
	ptp_info->gettime64 = iavf_ptp_gettime64;
#else
	ptp_info->gettime = iavf_ptp_gettime32;
#endif
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
	ptp_info->settime64 = iavf_ptp_settime64;
#else
	ptp_info->settime = iavf_ptp_settime32;
#endif
	ptp_info->adjtime = iavf_ptp_adjtime;
#ifdef HAVE_PTP_CLOCK_INFO_ADJFINE
	ptp_info->adjfine = iavf_ptp_adjfine;
#else
	ptp_info->adjfreq = iavf_ptp_adjfreq;
#endif
#ifdef HAVE_PTP_CLOCK_DO_AUX_WORK
	ptp_info->do_aux_work = iavf_ptp_do_aux_work;
#endif

	/* Support configuring any GPIO pins we have been given control of */
	iavf_ptp_init_gpio_pins(adapter, ptp_info);

	dev_info(&adapter->pdev->dev, "registering PTP clock %s\n", adapter->ptp.info.name);

	adapter->ptp.clock = ptp_clock_register(ptp_info, dev);
	if (IS_ERR(adapter->ptp.clock))
		return PTR_ERR(adapter->ptp.clock);

	return 0;
}

/**
 * iavf_ptp_map_phc_addr - Map PHC clock register region
 * @adapter: private adapter structure
 *
 * Map the PCI region that contains the PTP hardware clock registers for
 * directly accessing the device time.
 */
static void iavf_ptp_map_phc_addr(struct iavf_adapter *adapter)
{
	struct virtchnl_ptp_caps *hw_caps = &adapter->ptp.hw_caps;
	struct device *dev = &adapter->pdev->dev;
	resource_size_t region_size;
	void __iomem *phc_addr;

	WARN(adapter->ptp.phc_addr, "PHC clock register address already mapped");

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PHC_REGS)) {
		dev_dbg(dev, "Device does not have direct clock register access. Falling back to indirect clock access\n");
		return;
	}

	region_size = pci_resource_len(adapter->pdev, hw_caps->phc_regs.pcie_region);

	if (hw_caps->phc_regs.clock_lo > region_size) {
		dev_warn(dev, "Low clock register outside of PHC bar area. Falling back to indirect clock access\n");
		return;
	}

	if (hw_caps->phc_regs.clock_hi > region_size) {
		dev_warn(dev, "High clock register outside of PHC bar area. Falling back to indirect clock access\n");
		return;
	}

	phc_addr = pci_ioremap_bar(adapter->pdev, hw_caps->phc_regs.pcie_region);
	if (!phc_addr) {
		dev_warn(dev, "Unable to map PHC registers for clock access. Falling back to indirect clock access\n");
		return;
	}

	adapter->ptp.phc_addr = phc_addr;
}

/**
 * iavf_ptp_unmap_phc_addr - Unmap the PHC clock register region
 * @adapter: private adapter structure
 *
 * Unmap and release the PHC clock register region.
 */
static void iavf_ptp_unmap_phc_addr(struct iavf_adapter *adapter)
{
	if (adapter->ptp.phc_addr) {
		iounmap(adapter->ptp.phc_addr);
		adapter->ptp.phc_addr = NULL;
	}
}

/**
 * iavf_validate_tx_tstamp_format - Check if driver knows timestamp format
 * @adapter: private adapter structure
 *
 * Check that the driver understands the timestamp format that the PF
 * indicated. If we do not understand the format, then we must disable Tx
 * timestamps. Otherwise we might process timestamps from
 * VIRTCHNL_OP_1588_PTP_TX_TSTAMP incorrectly.
 */
static void iavf_validate_tx_tstamp_format(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;

	switch (adapter->ptp.hw_caps.tx_tstamp_format) {
	case VIRTCHNL_1588_PTP_TSTAMP_40BIT:
	case VIRTCHNL_1588_PTP_TSTAMP_64BIT_NS:
		dev_dbg(dev, "%s: got Tx timestamp format %u\n",
			__func__, adapter->ptp.hw_caps.tx_tstamp_format);
		break;
	default:
		dev_warn(dev, "Disabling Tx timestamps due to unexpected Tx timestamp format %u\n",
			 adapter->ptp.hw_caps.tx_tstamp_format);
		adapter->ptp.hw_caps.caps &= ~VIRTCHNL_1588_PTP_CAP_TX_TSTAMP;
		break;
	}
}

/**
 * iavf_ptp_init - Initialize PTP support if capability was negotiated
 * @adapter: private adapter structure
 *
 * Initialize PTP functionality, based on the capabilities that the PF has
 * enabled for this VF.
 */
void iavf_ptp_init(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	int err;

	if (WARN_ON(adapter->ptp.initialized)) {
		dev_err(dev, "PTP functionality was already initialized!\n");
		return;
	}

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_READ_PHC)) {
		dev_dbg(dev, "Device does not have PTP clock support\n");
		return;
	}

	err = iavf_ptp_register_clock(adapter);
	if (err) {
		dev_warn(dev, "Failed to register PTP clock device\n");
		return;
	}

#ifdef HAVE_PTP_CLOCK_DO_AUX_WORK
	ptp_schedule_worker(adapter->ptp.clock, 0);
#endif

	iavf_ptp_map_phc_addr(adapter);

	iavf_validate_tx_tstamp_format(adapter);

	adapter->ptp.initialized = true;
}

static bool iavf_ptp_op_match(enum virtchnl_ops pending_op)
{
	if (pending_op == VIRTCHNL_OP_1588_PTP_GET_TIME ||
	    pending_op == VIRTCHNL_OP_1588_PTP_SET_TIME ||
	    pending_op == VIRTCHNL_OP_1588_PTP_ADJ_TIME ||
	    pending_op == VIRTCHNL_OP_1588_PTP_ADJ_FREQ ||
	    pending_op == VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS ||
	    pending_op == VIRTCHNL_OP_1588_PTP_SET_PIN_CFG)
		return true;

	return false;
}

/**
 * iavf_ptp_release - Disable PTP support
 * @adapter: private adapter structure
 *
 * Release all PTP resources that were previously initialized.
 */
void iavf_ptp_release(struct iavf_adapter *adapter)
{
	if (!IS_ERR_OR_NULL(adapter->ptp.clock)) {
		dev_info(&adapter->pdev->dev, "removing PTP clock %s\n", adapter->ptp.info.name);
		ptp_clock_unregister(adapter->ptp.clock);
		adapter->ptp.clock = NULL;
	}

	iavf_flush_vc_msg_queue(adapter, iavf_ptp_op_match);

	iavf_ptp_unmap_phc_addr(adapter);

	adapter->ptp.hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
	iavf_ptp_disable_tx_tstamp(adapter);

	adapter->ptp.hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	iavf_ptp_disable_rx_tstamp(adapter);

	adapter->ptp.initialized = false;
}

/**
 * iavf_ptp_process_caps - Handle change in PTP capabilities
 * @adapter: private adapter structure
 *
 * Handle any state changes necessary due to change in PTP capabilities, such
 * as after a device reset or change in configuration from the PF.
 */
void iavf_ptp_process_caps(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;

	dev_dbg(dev, "PTP capabilities changed at runtime\n");

	/* Check if we lost PTP capability after loading */
	if (adapter->ptp.initialized &&
	    !iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_READ_PHC)) {
		iavf_ptp_release(adapter);
		return;
	}

	/* Check if we gained PTP capability after loading */
	if (!adapter->ptp.initialized &&
	    iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_READ_PHC)) {
		iavf_ptp_init(adapter);
		return;
	}

	/* The following checks are only necessary if we still have PTP clock
	 * capability. These handle if one of the extended capabilities is
	 * changed.
	 */

	if (adapter->ptp.phc_addr &&
	    !(iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PHC_REGS)))
		iavf_ptp_unmap_phc_addr(adapter);
	else if (!adapter->ptp.phc_addr &&
		 (iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_PHC_REGS)))
		iavf_ptp_map_phc_addr(adapter);

	iavf_validate_tx_tstamp_format(adapter);

	/* Check if the device lost access to Tx timestamp outgoing packets */
	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_TX_TSTAMP)) {
		adapter->ptp.hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
		iavf_ptp_disable_tx_tstamp(adapter);
	}

	/* Check if the device lost access to Rx timestamp incoming packets */
	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_RX_TSTAMP)) {
		adapter->ptp.hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
		iavf_ptp_disable_rx_tstamp(adapter);
	}
}

/**
 * iavf_ptp_extend_32b_timestamp - Convert a 32b nanoseconds timestamp to 64b nanoseconds
 * @cached_phc_time: recently cached copy of PHC time
 * @in_tstamp: Ingress/egress 32b nanoseconds timestamp value
 *
 * Hardware captures timestamps which contain only 32 bits of nominal
 * nanoseconds, as opposed to the 64bit timestamps that the stack expects.
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
u64 iavf_ptp_extend_32b_timestamp(u64 cached_phc_time, u32 in_tstamp)
{
	const u64 mask = GENMASK_ULL(31, 0);
	u32 delta;
	u64 ns;

	/* Calculate the delta between the lower 32bits of the cached PHC
	 * time and the in_tstamp value
	 */
	delta = (in_tstamp - (u32)(cached_phc_time & mask));

	/* Do not assume that the in_tstamp is always more recent than the
	 * cached PHC time. If the delta is large, it indicates that the
	 * in_tstamp was taken in the past, and should be converted
	 * forward.
	 */
	if (delta > (mask / 2)) {
		/* reverse the delta calculation here */
		delta = ((u32)(cached_phc_time & mask) - in_tstamp);
		ns = cached_phc_time - delta;
	} else {
		ns = cached_phc_time + delta;
	}

	return ns;
}

/**
 * iavf_ptp_extend_40b_timestamp - Convert a 40b timestamp to 64b nanoseconds
 * @cached_phc_time: recently cached copy of PHC time
 * @in_tstamp: Ingress/egress 40b timestamp value
 *
 * For some devices, the Tx and Rx timestamps use a 40bit timestamp:
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
 * Extract the 32bit nominal nanoseconds and extend them. See
 * iavf_ptp_extend_32b_timestamp for a detailed explanation of the extension
 * algorithm.
 */
static u64 iavf_ptp_extend_40b_timestamp(u64 cached_phc_time, u64 in_tstamp)
{
	const u64 mask = GENMASK_ULL(31, 0);

	return iavf_ptp_extend_32b_timestamp(cached_phc_time, (in_tstamp >> 8) & mask);
}

/**
 * iavf_virtchnl_ptp_get_time - Respond to VIRTCHNL_OP_1588_PTP_GET_TIME
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_1588_PTP_GET_TIME message from the PF. This message
 * is sent by the PF in response to the same op as a request from the VF.
 * Extract the 64bit nanoseconds time from the message and store it in
 * cached_phc_time. Then, notify any thread that is waiting for the update via
 * the wait queue.
 */
void
iavf_virtchnl_ptp_get_time(struct iavf_adapter *adapter, void *data, u16 len)
{
	struct virtchnl_phc_time *msg;

	if (len == sizeof(*msg)) {
		msg = (struct virtchnl_phc_time *)data;
	} else {
		dev_err_once(&adapter->pdev->dev, "Invalid VIRTCHNL_OP_1588_PTP_GET_TIME from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	adapter->ptp.cached_phc_time = msg->time;
	adapter->ptp.cached_phc_updated = jiffies;
	adapter->ptp.phc_time_ready = true;

	wake_up(&adapter->ptp.phc_time_waitqueue);
}

/**
 * iavf_virtchnl_ptp_tx_timestamp - Handle Tx timestamp events from the PF
 * @adapter: private adapter structure
 * @data: message contents from PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_1588_PTP_TX_TIMESTAMP op from the PF. This is sent
 * whenever the PF has detected a transmit timestamp associated with this VF.
 *
 * First, check if there is a pending skb that needs a transmit timestamp. If
 * so, extract the time value from the message and report it to the stack.
 * Note that 40bit timestamp values must first be extended using
 * iavf_ptp_extend_40b_timestamp().
 */
void iavf_virtchnl_ptp_tx_timestamp(struct iavf_adapter *adapter, void *data,
				    u16 len)
{
	struct skb_shared_hwtstamps skb_tstamps = {};
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_phc_tx_tstamp *msg;
	struct sk_buff *skb;
	u64 ns;

	if (len == sizeof(*msg)) {
		msg = (struct virtchnl_phc_tx_tstamp *)data;
	} else {
		dev_err_once(dev, "Invalid VIRTCHNL_OP_1588_PTP_TX_TIMESTAMP from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	/* No need to process the event if timestamping isn't on */
	if (adapter->ptp.hwtstamp_config.tx_type != HWTSTAMP_TX_ON)
		return;

	/* don't attempt to timestamp if we don't have a pending skb */
	skb = adapter->ptp.tx_skb;
	if (!skb)
		return;

	/* Since we only request one outstanding timestamp at once, we assume
	 * this event must belong to the saved SKB. Clear the bit lock and the
	 * skb now prior to notifying the stack via skb_tstamp_tx().
	 */
	adapter->ptp.tx_skb = NULL;
	clear_bit_unlock(__IAVF_TX_TSTAMP_IN_PROGRESS, &adapter->crit_section);

	switch (adapter->ptp.hw_caps.tx_tstamp_format) {
	case VIRTCHNL_1588_PTP_TSTAMP_40BIT:
		if (!(msg->tstamp & IAVF_PTP_40B_TSTAMP_VALID)) {
			dev_warn(dev, "Got a VIRTCHNL_OP_1588_PTP_TX_TIMESTAMP message with an invalid timestamp\n");
			goto out_free_skb;
		}
		ns = iavf_ptp_extend_40b_timestamp(adapter->ptp.cached_phc_time, msg->tstamp);
		break;
	case VIRTCHNL_1588_PTP_TSTAMP_64BIT_NS:
		ns = msg->tstamp;
		break;
	default:
		/* This shouldn't happen since we won't enable Tx timestamps
		 * if we don't know the timestamp format.
		 */
		dev_dbg(dev, "Got a VIRTCHNL_OP_1588_PTP_TX_TIMESTAMP event, when timestamp format is unknown\n");
		goto out_free_skb;
	}

	skb_tstamps.hwtstamp = ns_to_ktime(ns);
	skb_tstamp_tx(skb, &skb_tstamps);

out_free_skb:
	dev_kfree_skb_any(skb);
}

/**
 * iavf_virtchnl_ptp_pin_status - Handle completion status of pin config
 * @adapter: private adapter structure
 * @v_retval: the return value of the virtchnl message
 *
 * Called when the VF gets a completion for VIRTCHNL_OP_1588_PTP_SET_PIN_CFG,
 * used to indicate whether or not the GPIO pin configuration was accepted by
 * the PF.
 */
void
iavf_virtchnl_ptp_pin_status(struct iavf_adapter *adapter,
			     enum virtchnl_status_code v_retval)
{
	adapter->ptp.set_pin_status = v_retval;
	adapter->ptp.set_pin_ready = true;

	wake_up(&adapter->ptp.gpio_waitqueue);
}

/**
 * iavf_virtchnl_ptp_get_pin_cfgs - Handle VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Read the pin configuration data from the PF, and fill in the pin_config
 * structure used by the stack to report the current GPIO pin configuration.
 */
void iavf_virtchnl_ptp_get_pin_cfgs(struct iavf_adapter *adapter, void *data,
				     u16 len)
{
	struct ptp_pin_desc *pin_config = adapter->ptp.info.pin_config;
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_phc_get_pins *msg;
	unsigned int i;

	if (!pin_config) {
		dev_warn_once(dev, "Got VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS, but pin_config array not allocated\n");
		return;
	}

	if (len >= sizeof(*msg)) {
		msg = (struct virtchnl_phc_get_pins *)data;
	} else {
		dev_err_once(dev, "Invalid VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS from PF. Got size of %u, expected at least %lu\n",
			     len, sizeof(*msg));
		return;
	}

	if (!msg->len) {
		dev_dbg(dev, "Got VIRTCHNL_OP_1588_PTP_GET_PIN_CFGS with information on 0 pins\n");
		return;
	}

	/* Copy the data from the PF into the pin_config array */
	for (i = 0; i < msg->len; i++) {
		struct virtchnl_phc_pin *pin = &msg->pins[i];
		unsigned int idx = pin->pin_index;

		if (idx >= adapter->ptp.info.n_pins) {
			dev_warn_once(dev, "PF sent information on pin %u but we only know about %u pins\n",
				      idx, adapter->ptp.info.n_pins);
			continue;
		}

		if (pin->func != VIRTCHNL_PHC_PIN_FUNC_NONE &&
		    pin->func != VIRTCHNL_PHC_PIN_FUNC_EXT_TS &&
		    pin->func != VIRTCHNL_PHC_PIN_FUNC_PER_OUT) {
			dev_warn_once(dev, "PF sent unknown function type %u for pin %u\n",
				      pin->func, idx);
			continue;
		}

		pin_config[idx].index = idx;
		pin_config[idx].chan = pin->func_index;
		pin_config[idx].func = iavf_virtchnl_to_ptp_func(pin->func);
		memcpy(pin_config[idx].name, pin->name, sizeof(pin->name));
	}

	adapter->ptp.pin_cfg_ready = true;
}

/**
 * iavf_virtchnl_ptp_ext_timestamp - Handle external timestamp event
 * @adapter: private adapter structure
 * @data: message contents from PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP op from the PF. This is sent
 * whenever the PF has captured a timestamp of a level change from one of the
 * GPIO pins configured as an external timestamp pin.
 *
 * Validate that this message is for a known external timestamp function. If
 * necessary, convert the timestamp to a full 64bit timestamp. Finally, notify
 * the stack of the external timestamp event.
 */
void iavf_virtchnl_ptp_ext_timestamp(struct iavf_adapter *adapter, void *data,
				     u16 len)
{
	struct device *dev = &adapter->pdev->dev;
	struct virtchnl_phc_ext_tstamp *msg;
	struct ptp_clock_event event = {};
	u64 ns;

	if (len == sizeof(*msg)) {
		msg = (struct virtchnl_phc_ext_tstamp *)data;
	} else {
		dev_err_once(dev, "Invalid VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP from PF. Got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	if (msg->func_index >= adapter->ptp.info.n_ext_ts) {
		dev_err_once(dev, "Got a VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP message with func_index %u, larger than expected bound of %u\n",
			     msg->func_index, adapter->ptp.info.n_ext_ts);
		return;
	}

	switch (msg->tstamp_format) {
	case VIRTCHNL_1588_PTP_TSTAMP_40BIT:
		if (!(msg->tstamp & IAVF_PTP_40B_TSTAMP_VALID)) {
			dev_warn(dev, "Got a VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP message with an invalid timestamp\n");
			return;
		}
		ns = iavf_ptp_extend_40b_timestamp(adapter->ptp.cached_phc_time,
						   msg->tstamp);
		break;
	case VIRTCHNL_1588_PTP_TSTAMP_64BIT_NS:
		ns = msg->tstamp;
		break;
	default:
		dev_err_once(dev, "Got a VIRTCHNL_OP_1588_PTP_EXT_TIMESTAMP message with an unknown format\n");
		return;
	}

	event.type = PTP_CLOCK_EXTTS;
	event.index = msg->func_index;
	event.timestamp = ns;

	/* Notify stack of the event */
	ptp_clock_event(adapter->ptp.clock, &event);
}
