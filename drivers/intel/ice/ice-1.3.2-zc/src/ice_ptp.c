// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"

#define MASTER_IDX_INVALID 0xFF
static u8 master_idx = MASTER_IDX_INVALID;

static const u8 pps_out_prop_delay_ns[NUM_ICE_TIME_REF_FREQ] = {
	11, /* 25 MHz */
	12, /* 122.88 MHz */
	12, /* 125 MHz */
	12, /* 153.6 MHz */
	11, /* 156.25 MHz */
	12  /* 245.76 MHz */
};


#define DEFAULT_INCVAL 0x100000000ULL
#define DEFAULT_INCVAL_EXT 0x13b13b13bULL

static const s64 incval_values[NUM_ICE_TIME_REF_FREQ] = {
	0x136e44fabULL, /* 25 MHz */
	0x146cc2177ULL, /* 122.88 MHz */
	0x141414141ULL, /* 125 MHz */
	0x139b9b9baULL, /* 153.6 MHz */
	0x134679aceULL, /* 156.25 MHz */
	0x146cc2177ULL, /* 245.76 MHz */
};

static const u64 phy_clock_freq[NUM_ICE_TIME_REF_FREQ] = {
	823437500, /* 25 MHz */
	783360000, /* 122.88 MHz */
	796875000, /* 125 MHz */
	816000000, /* 153.6 MHz */
	830078125, /* 156.25 MHz */
	783360000, /* 245.76 MHz */
};


static enum ice_status ice_ptp_set_increment(struct ice_pf *pf, s32 ppb);

/**
 * ice_ptp_lock - acquire PTP global lock
 * @pf: Board private structure
 *
 * Acquire the hardware time sync global lock
 */
static bool ice_ptp_lock(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 hw_lock;
	int i;

#define MAX_TRIES 5

	for (i = 0; i < MAX_TRIES; i++) {
		hw_lock = rd32(hw, PFTSYN_SEM + (PFTSYN_SEM_BYTES * hw->pf_id));
		hw_lock = hw_lock & PFTSYN_SEM_BUSY_M;
		if (hw_lock) {
			/* Somebody is holding the lock */
			usleep_range(10000, 20000);
			continue;
		} else {
			break;
		}
	}

	return !hw_lock;
}

/**
 * ice_ptp_unlock - Release PTP global lock
 * @pf: Board private structure
 *
 * Release the hardware time sync global lock
 */
static void ice_ptp_unlock(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 hw_lock;

	hw_lock = rd32(hw, PFTSYN_SEM + (PFTSYN_SEM_BYTES * hw->pf_id));
	hw_lock = hw_lock & ~PFTSYN_SEM_BUSY_M;
	wr32(hw, PFTSYN_SEM + (PFTSYN_SEM_BYTES * hw->pf_id), hw_lock);
}



/**
 * ice_ena_timestamp - Enable timestamp on packets on all the VSI
 * @pf: The PF pointer to search in
 * @prt_type: Type of port Rx or Tx
 * @ena: bool value to enable or disable timestamp
 */
static void
ice_ena_timestamp(struct ice_pf *pf, enum port_type prt_type, bool ena)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);

	if (!vsi)
		return;
	if (prt_type == TX) {
		vsi->ptp_tx = ena;
	} else {
		u16 i;

		ice_for_each_rxq(vsi, i) {
			if (!vsi->rx_rings[i])
				continue;
			vsi->rx_rings[i]->ptp_rx = ena;
		}
	}
}

/**
 * ice_ptp_cfg_timestamp - Configure timestamp for init/deinit
 * @pf: Board private structure
 * @ena: bool value to enable or disable time stamp
 *
 * This function will configure timestamping during PTP initialization
 * and deinitialization
 */
static void ice_ptp_cfg_timestamp(struct ice_pf *pf, bool ena)
{
	struct ice_vsi *vsi;

	ice_ena_timestamp(pf, TX, ena);
	ice_ena_timestamp(pf, RX, ena);

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;

	vsi->tstamp_config.rx_filter =
		ena ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;
	vsi->tstamp_config.tx_type = ena ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
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
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	enum ice_aqc_driver_params param_idx;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;
	u32 value;

	/* Use the ptp_clock structure if we're the main PF */
	if (vsi && vsi->netdev && !IS_ERR_OR_NULL(vsi->ptp_clock))
		return ptp_clock_index(vsi->ptp_clock);

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (!tmr_idx)
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR0;
	else
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR1;

	status = ice_aq_get_driver_param(hw, param_idx, &value, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to read PTP clock index parameter, err %s aq_err %s\n",
			ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));
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
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	enum ice_aqc_driver_params param_idx;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;
	u32 value;

	if (!vsi || !vsi->netdev || IS_ERR_OR_NULL(vsi->ptp_clock))
		return;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_assoc;
	if (!tmr_idx)
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR0;
	else
		param_idx = ICE_AQC_DRIVER_PARAM_CLK_IDX_TMR1;

	value = (u32)ptp_clock_index(vsi->ptp_clock);
	if (value > INT_MAX) {
		dev_err(ice_pf_to_dev(pf),
			"PTP Clock index is too large to store\n");
		return;
	}
	value |= PTP_SHARED_CLK_IDX_VALID;

	status = ice_aq_set_driver_param(hw, param_idx, value, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to set PTP clock index parameter, err %s aq_err %s\n",
			ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));
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
	if (!hw->func_caps.ts_func_info.master_tmr_owned)
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
			ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
}

/**
 * ice_ptp_read_master_clk_reg - Read the master clock register
 * @pf: Board private structure
 */
u64 ice_ptp_read_master_clk_reg(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 hi, hi2, lo;
	u8 tmr_idx;

	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID)
		return 0;
	hi = rd32(hw, GLTSYN_TIME_H(tmr_idx));
	lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));
	hi2 = rd32(hw, GLTSYN_TIME_H(tmr_idx));

	if (hi != hi2) {
		/* TIME_L rolled over */
		lo = rd32(hw, GLTSYN_TIME_L(tmr_idx));
		hi = hi2;
	}

	return ((u64)hi << 32) | lo;
}

/**
 * ice_ptp_read_incval - Read the master clock increment value
 * @pf: Board private structure
 */
static u64 ice_ptp_read_incval(struct ice_pf *pf)
{
	u64 mstr_incval;
	u8 tmr_idx;
	u32 val;

	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID) {
		struct ice_vsi *vsi = ice_get_main_vsi(pf);

		if (!vsi)
			return 0;
		return incval_values[vsi->time_ref_freq];
	}
	val = rd32(&pf->hw, GLTSYN_INCVAL_L(tmr_idx));
	mstr_incval = val;
	val = rd32(&pf->hw, GLTSYN_INCVAL_H(tmr_idx));
	mstr_incval |= ((u64)(val & TS_HIGH_MASK) << 32);

	return mstr_incval;
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

	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID)
		return 0;

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
 * ice_ptp_update_cached_systime - Update the cached system time values
 * @pf: Board specific private structure
 *
 * This function updates the system time values which are cached in the PF
 * structure and the Rx rings.
 *
 * This should be called periodically at least once a second, and whenever the
 * system time has been adjusted.
 */
static void ice_ptp_update_cached_systime(struct ice_pf *pf)
{
	u64 systime;
	int i;

	/* Read the current system time */
	systime = ice_ptp_read_master_clk_reg(pf);

	/* Update the cached system time stored in the PF structure */
	WRITE_ONCE(pf->cached_systime, systime);

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];
		int j;

		if (!vsi)
			continue;

#ifdef HAVE_NETDEV_SB_DEV
		if (vsi->type != ICE_VSI_PF &&
		    vsi->type != ICE_VSI_OFFLOAD_MACVLAN)
			continue;
#else
		if (vsi->type != ICE_VSI_PF)
			continue;
#endif /* HAVE_NETDEV_SB_DEV */

		ice_for_each_rxq(vsi, j) {
			if (!vsi->rx_rings[j])
				continue;
			WRITE_ONCE(vsi->rx_rings[j]->cached_systime, systime);
		}
	}
}

/**
 * ice_ptp_convert_40b_64b - Convert 40b Tx/Rx timestamp value to 64b
 * @cached_systime: The cached system time
 * @in_timestamp: Ingress/egress 40b timestamp value
 * @vsi: PF or Rx ring corresponding VSI
 *
 * The Tx and Rx timestamps are 40bits wide. The lower 8 bits contains a valid
 * bit, along with 7 bits of sub-nanosecond precision. The remaining 32bits
 * correspond to the lower 32 bits of the system time.
 *
 * In order to report full 64bit timestamps back to the upper stack, compare
 * the 32bit value to the cached time stored in the ring structure.
 *
 * In order to convert the value correctly, it is assumed that the 40bit Tx or
 * Rx timestamp is within ~2 seconds of the value cached in the ring.
 * Otherwise, it's possible that the lower 32bits of the system time have
 * overflowed more than once since the timestamp was taken.
 *
 * For this assumption to hold, the cached ring value must be updated at least
 * once every 2 seconds. Additionally, Tx timestamps should not be held longer
 * than 2 seconds.
 *
 * The system time value used may be cached as long as it has been updated
 * within 2 seconds. For Rx packets, use the system time that is cached in the
 * ring. For Tx packets, use the value cached in the PF structure.
 */
static u64
ice_ptp_convert_40b_64b(u64 cached_systime, u64 in_timestamp,
			struct ice_vsi __always_unused *vsi)
{
	const u64 mask = GENMASK_ULL(31, 0);
	u64 delta;

	/* Drop the sub-nanosecond bits and the valid bit */
	in_timestamp = (in_timestamp >> 8) & mask;

	/* Calculate the delta between the lower 32bits of the cached system
	 * time and the in_timestamp value
	 */
	delta = (in_timestamp - (cached_systime & mask)) & mask;

	/* Do not assume that the in_timestamp is always more recent than the
	 * cached system time. If the delta is large, it indicates that the
	 * in_timestamp was taken in the past, and should be converted
	 * forward.
	 */
	if (delta > (mask / 2)) {
		delta = ((cached_systime & mask) - in_timestamp) & mask;
		cached_systime -= delta;
	} else {
		cached_systime += delta;
	}

	return cached_systime;
}

/**
 * ice_ptp_get_ts_idx - Find the free Tx index based on current logical port
 * @vsi: lport corresponding VSI
 */
int ice_ptp_get_ts_idx(struct ice_vsi *vsi)
{
	u8 quad_lport, own_idx_start, own_idx_end, lport;
	int i;

	lport = vsi->port_info->lport;
	quad_lport = lport % ICE_PORTS_PER_QUAD;

	/* Check on own idx window */
	if (ice_is_generic_mac(&vsi->back->hw)) {
		own_idx_start = quad_lport * INDEX_PER_PORT;
		own_idx_end = own_idx_start + INDEX_PER_PORT;
	} else {
		own_idx_start = 0;
		own_idx_end = INDEX_PER_PORT_EXT;
	}

	for (i = own_idx_start; i < own_idx_end; i++) {
		if (!test_and_set_bit(i, vsi->ptp_tx_idx))
			return i;
	}

	return -1;
}

/**
 * ice_ptp_convert_to_hwtstamp - Convert device clock to system time
 * @hwtstamps: Timestamp structure to update
 * @timestamp: Timestamp from the hardware
 *
 * We need to convert the NIC clock value into a hwtstamp which can be used by
 * the upper level timestamping functions. Since the timestamp is simply
 * a 64-bit nanosecond value, we can call ns_to_ktime directly to handle this.
 */
static void
ice_ptp_convert_to_hwtstamp(struct skb_shared_hwtstamps *hwtstamps,
			    u64 timestamp)
{
	memset(hwtstamps, 0, sizeof(*hwtstamps));

	hwtstamps->hwtstamp = ns_to_ktime(timestamp);
}

/**
 * ice_ptp_send_msg_to_phy - Send a message to PHY using sbq command
 * @pf: Board private structure
 * @port: Port associated with the msg
 * @phy_msg: Message to be sent to PHY
 * @lock_sbq: true to lock the sideband queue
 */
static enum ice_status
ice_ptp_send_msg_to_phy(struct ice_pf *pf, int port,
			struct ice_sbq_msg_input *phy_msg, bool lock_sbq)
{
	enum ice_status status = 0;
	int phy = port / ICE_PORTS_PER_PHY;
	struct ice_hw *hw = &pf->hw;

	if (phy == 0)
		phy_msg->dest_dev = rmn_0;
	else if (phy == 1)
		phy_msg->dest_dev = rmn_1;
	else
		phy_msg->dest_dev = rmn_2;

	status = ice_sbq_rw_reg_lp(hw, phy_msg, lock_sbq);
	if (status)
		dev_dbg(ice_pf_to_dev(pf), "PTP failed to send msg to phy %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_send_msg_to_phy_ext - Send sbq message to external PHY
 * @pf: Board private structure
 * @phy_msg: Message to be sent to PHY
 *
 * Send a message to external PHY using sbq command
 */
static enum ice_status
ice_ptp_send_msg_to_phy_ext(struct ice_pf *pf,
			    struct ice_sbq_msg_input *phy_msg)

{
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;

	phy_msg->dest_dev = rmn_0;
	status = ice_sbq_rw_reg(hw, phy_msg);
	if (status)
		dev_dbg(ice_pf_to_dev(pf), "PTP failed to send msg to phy %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_rel_all_skb - Free all pending skb waiting for timestamp
 * @pf: The PF private structure
 */
static void ice_ptp_rel_all_skb(struct ice_pf *pf)
{
	struct ice_vsi *vsi;
	int idx;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;
	for (idx = 0; idx < INDEX_PER_QUAD; idx++) {
		if (vsi->ptp_tx_skb[idx]) {
			dev_kfree_skb_any(vsi->ptp_tx_skb[idx]);
			vsi->ptp_tx_skb[idx] = NULL;
		}
	}
}


/**
 * ice_phy_port_reg_write_ext - Write an external PHY port register
 * @pf: The PF private structure
 * @addr: Address of the register
 * @val: Value to write
 */
static enum ice_status
ice_phy_port_reg_write_ext(struct ice_pf *pf, u32 addr, u32 val)

{
	struct ice_sbq_msg_input phy_msg;

	phy_msg.msg_addr_low = ICE_LO_WORD(addr);
	phy_msg.msg_addr_high = ICE_HI_WORD(addr);
	phy_msg.opcode = ice_sbq_msg_wr;
	phy_msg.data = val;

	return ice_ptp_send_msg_to_phy_ext(pf, &phy_msg);
}

/**
 * ice_phy_port_reg_write_lp - Write a PHY port register with lock parameter
 * @pf: The PF private structure
 * @port: Port number to be written
 * @offset: Offset from PHY port register base
 * @val: Value to write
 * @lock_sbq: true to lock the sideband queue
 */
static enum ice_status
ice_phy_port_reg_write_lp(struct ice_pf *pf, int port, u16 offset, u32 val,
			  bool lock_sbq)
{
	struct ice_sbq_msg_input phy_msg;
	int phy_port = port % ICE_PORTS_PER_PHY;
	int quadtype;


	phy_msg.opcode = ice_sbq_msg_wr;

	quadtype = (port / ICE_PORTS_PER_QUAD) % ICE_NUM_QUAD_TYPE;

	if (quadtype == 0) {
		phy_msg.msg_addr_low = P_Q0_L(P_0_BASE + offset, phy_port);
		phy_msg.msg_addr_high = P_Q0_H(P_0_BASE + offset, phy_port);
	} else {
		phy_msg.msg_addr_low = P_Q1_L(P_4_BASE + offset, phy_port);
		phy_msg.msg_addr_high = P_Q1_H(P_4_BASE + offset, phy_port);
	}

	phy_msg.data = val;

	return ice_ptp_send_msg_to_phy(pf, port, &phy_msg, lock_sbq);
}

/**
 * ice_phy_port_reg_write - Write a PHY port register with sbq locked
 * @pf: The PF private structure
 * @port: Port number to be written
 * @offset: Offset from PHY port register base
 * @val: Value to write
 */
static enum ice_status
ice_phy_port_reg_write(struct ice_pf *pf, int port, u16 offset, u32 val)
{
	return ice_phy_port_reg_write_lp(pf, port, offset, val, true);
}

/**
 * ice_phy_port_reg_read_ext - Read an external PHY port register
 * @pf: The PF private structure
 * @addr: Address of the register
 * @val: Pointer to the value to read (out param)
 */
static enum ice_status
ice_phy_port_reg_read_ext(struct ice_pf *pf, u32 addr, u32 *val)
{
	struct ice_sbq_msg_input phy_msg;
	enum ice_status status;

	phy_msg.msg_addr_low = ICE_LO_WORD(addr);
	phy_msg.msg_addr_high = ICE_HI_WORD(addr);
	phy_msg.opcode = ice_sbq_msg_rd;

	status = ice_ptp_send_msg_to_phy_ext(pf, &phy_msg);

	if (status)
		return status;

	*val = phy_msg.data;

	return 0;
}

/**
 * ice_phy_port_reg_read_lp - Read a PHY port register with lock parameter
 * @pf: The PF private structure
 * @port: Port number to be read
 * @offset: Offset from PHY port register base
 * @val: Pointer to the value to read (out param)
 * @lock_sbq: true to lock the sideband queue
 */
static enum ice_status
ice_phy_port_reg_read_lp(struct ice_pf *pf, int port, u16 offset, u32 *val,
			 bool lock_sbq)
{
	struct ice_sbq_msg_input phy_msg;
	int phy_port = port % ICE_PORTS_PER_PHY;
	enum ice_status status;
	int quadtype;


	phy_msg.opcode = ice_sbq_msg_rd;

	quadtype = (port / ICE_PORTS_PER_QUAD) % ICE_NUM_QUAD_TYPE;

	if (quadtype == 0) {
		phy_msg.msg_addr_low = P_Q0_L(P_0_BASE + offset, phy_port);
		phy_msg.msg_addr_high = P_Q0_H(P_0_BASE + offset, phy_port);
	} else {
		phy_msg.msg_addr_low = P_Q1_L(P_4_BASE + offset, phy_port);
		phy_msg.msg_addr_high = P_Q1_H(P_4_BASE + offset, phy_port);
	}

	status = ice_ptp_send_msg_to_phy(pf, port, &phy_msg, lock_sbq);
	if (status)
		return status;

	*val = phy_msg.data;

	return 0;
}

/**
 * ice_phy_port_reg_read - Read a PHY port register with sbq locked
 * @pf: The PF private structure
 * @port: Port number to be read
 * @offset: Offset from PHY port register base
 * @val: Pointer to the value to read (out param)
 */
static enum ice_status
ice_phy_port_reg_read(struct ice_pf *pf, int port, u16 offset, u32 *val)
{
	return ice_phy_port_reg_read_lp(pf, port, offset, val, true);
}

/**
 * ice_phy_quad_reg_write_lp - Write a PHY quad register with lock parameter
 * @pf: The PF private structure
 * @quad: Quad number to be written
 * @offset: Offset from PHY quad register base
 * @val: Value to write
 * @lock_sbq: true to lock the sideband queue
 */
static enum ice_status
ice_phy_quad_reg_write_lp(struct ice_pf *pf, int quad, u16 offset, u32 val,
			  bool lock_sbq)
{
	struct ice_sbq_msg_input phy_msg;
	enum ice_status status;

	if (quad >= ICE_MAX_QUAD)
		return ICE_ERR_PARAM;

	phy_msg.opcode = ice_sbq_msg_wr;
	phy_msg.data = val;
	phy_msg.dest_dev = rmn_0;

	if (!(quad % ICE_NUM_QUAD_TYPE)) {
		phy_msg.msg_addr_low = ICE_LO_WORD(Q_0_BASE + offset);
		phy_msg.msg_addr_high = ICE_HI_WORD(Q_0_BASE + offset);
	} else {
		phy_msg.msg_addr_low = ICE_LO_WORD(Q_1_BASE + offset);
		phy_msg.msg_addr_high = ICE_HI_WORD(Q_1_BASE + offset);
	}

	status = ice_sbq_rw_reg_lp(&pf->hw, &phy_msg, lock_sbq);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "QUAD reg write failed for quad %u\n",
			quad);
		return status;
	}

	return status;
}

/**
 * ice_phy_quad_reg_write - Write a PHY quad register with sbq locked
 * @pf: The PF private structure
 * @quad: Quad number to be written
 * @offset: Offset from PHY quad register base
 * @val: Value to write
 */
static enum ice_status
ice_phy_quad_reg_write(struct ice_pf *pf, int quad, u16 offset, u32 val)
{
	return ice_phy_quad_reg_write_lp(pf, quad, offset, val, true);
}

/**
 * ice_phy_quad_reg_read_ext - Read an external PHY quad register
 * @pf: The PF private structure
 * @addr: Address of the register
 * @val: Pointer to the value to read (out param)
 */
static enum ice_status
ice_phy_quad_reg_read_ext(struct ice_pf *pf, u32 addr, u32 *val)
{
	struct ice_sbq_msg_input phy_msg;
	enum ice_status status;

	phy_msg.msg_addr_low = ICE_LO_WORD(addr);
	phy_msg.msg_addr_high = ICE_HI_WORD(addr);
	phy_msg.opcode = ice_sbq_msg_rd;

	status = ice_ptp_send_msg_to_phy_ext(pf, &phy_msg);
	if (!status)
		*val = phy_msg.data;

	return status;
}

/**
 * ice_phy_quad_reg_read_lp - Read a PHY quad register with lock parameter
 * @pf: The PF private structure
 * @quad: Quad number to be read
 * @offset: Offset from PHY quad register base
 * @val: Pointer to the value to read (out param)
 * @lock_sbq: true to lock the sideband queue
 */
static enum ice_status
ice_phy_quad_reg_read_lp(struct ice_pf *pf, int quad, u16 offset, u32 *val,
			 bool lock_sbq)
{
	struct ice_sbq_msg_input phy_msg;
	enum ice_status status;

	if (quad >= ICE_MAX_QUAD)
		return ICE_ERR_PARAM;

	phy_msg.opcode = ice_sbq_msg_rd;
	phy_msg.dest_dev = rmn_0;

	if (!(quad % ICE_NUM_QUAD_TYPE)) {
		phy_msg.msg_addr_low = ICE_LO_WORD(Q_0_BASE + offset);
		phy_msg.msg_addr_high = ICE_HI_WORD(Q_0_BASE + offset);
	} else {
		phy_msg.msg_addr_low = ICE_LO_WORD(Q_1_BASE + offset);
		phy_msg.msg_addr_high = ICE_HI_WORD(Q_1_BASE + offset);
	}

	status = ice_sbq_rw_reg_lp(&pf->hw, &phy_msg, lock_sbq);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "QUAD reg read failed for quad %u\n",
			quad);
		return status;
	}

	*val = phy_msg.data;

	return 0;
}

/**
 * ice_phy_quad_reg_read - Read a PHY quad register with sbq locked
 * @pf: The PF private structure
 * @quad: Quad number to be read
 * @offset: Offset from PHY quad register base
 * @val: Pointer to the value to read (out param)
 */
static enum ice_status
ice_phy_quad_reg_read(struct ice_pf *pf, int quad, u16 offset, u32 *val)
{
	return ice_phy_quad_reg_read_lp(pf, quad, offset, val, true);
}

/**
 * ice_ptp_ena_phy_time_syn_ext - Enable time sync for ports
 * @pf: The PF private structure
 *
 * Utility function for enabling time sync for PHY ports of external PHY
 */
static enum ice_status ice_ptp_ena_phy_time_syn_ext(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	u8 tmr_idx;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_ENA(tmr_idx),
					    GLTSYN_ENA_TSYN_ENA_M);
	if (status)
		dev_err(ice_pf_to_dev(pf),
			"PTP failed in ena_phy_time_syn %s\n",
			ice_stat_str(status));
	return status;
}

/**
 * ice_ptp_port_timer_inc_pre_write_ext - Fill all timer_inc_pre PHY registers
 * @pf: The PF private structure
 * @ns: Time with which the clock is initialized
 *
 * Utility function for filling the external PHY init shadow registers
 */
static enum ice_status
ice_ptp_port_timer_inc_pre_write_ext(struct ice_pf *pf, u64 ns)
{
	enum ice_status status;
	u8 tmr_idx;

	tmr_idx = pf->hw.func_caps.ts_func_info.tmr_index_owned;
	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_SHTIME_0(tmr_idx),
					    0);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_SHTIME_L(tmr_idx),
					    (u32)(ns & TS_LOW_MASK));

exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed to init port %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_time_inc_pre_wr_subns - Fill PHY registers for sub ns cmd
 * @pf: The PF private structure
 * @port: Port number to be initialized
 * @tx_time: Time with which the port Tx clock is initialized
 * @rx_time: Time with which the port Rx clock is initialized
 *
 * Utility function for filling the port init shadow registers.  This version
 * supports sub-nanosecond values for accurate sync of port and master timers.
 */
static enum ice_status
ice_ptp_port_time_inc_pre_wr_subns(struct ice_pf *pf, int port, u64 tx_time,
				   u64 rx_time)
{
	enum ice_status status;
	u32 l_time, u_time;

	if (tx_time != rx_time)
		return ICE_ERR_PARAM;

	l_time = (u32)(tx_time & TS_LOW_MASK);
	u_time = (u32)((tx_time >> 32) & TS_LOW_MASK);

	/* Tx case */
	status = ice_phy_port_reg_write(pf, port, P_REG_TX_TIMER_INC_PRE_L,
					l_time);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write(pf, port, P_REG_TX_TIMER_INC_PRE_U,
					u_time);
	if (status)
		goto exit;

	/* Rx case */
	status = ice_phy_port_reg_write(pf, port, P_REG_RX_TIMER_INC_PRE_L,
					l_time);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write(pf, port, P_REG_RX_TIMER_INC_PRE_U,
					u_time);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed to init port %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_timer_inc_pre_write_lp - Fill all timer_inc_pre PHY registers
 * @pf: The PF private structure
 * @port: Port number to be initialized
 * @tx_ns: Time with which the port Tx clock is initialized
 * @rx_ns: Time with which the port Rx clock is initialized
 * @lock_sbq: true to lock the sideband queue
 *
 * Utility function for filling the port init shadow registers
 */
static enum ice_status
ice_ptp_port_timer_inc_pre_write_lp(struct ice_pf *pf, int port, u64 tx_ns,
				    u64 rx_ns, bool lock_sbq)
{
	enum ice_status status;

	/* Tx case */
	/* No sub nano seconds data */
	status = ice_phy_port_reg_write_lp(pf, port, P_REG_TX_TIMER_INC_PRE_L,
					   0, lock_sbq);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write_lp(pf, port, P_REG_TX_TIMER_INC_PRE_U,
					   (u32)(tx_ns & TS_LOW_MASK),
					   lock_sbq);
	if (status)
		goto exit;

	/* Rx case */
	/* No sub nano seconds data */
	status = ice_phy_port_reg_write_lp(pf, port, P_REG_RX_TIMER_INC_PRE_L,
					   0, lock_sbq);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write_lp(pf, port, P_REG_RX_TIMER_INC_PRE_U,
					   (u32)(rx_ns & TS_LOW_MASK),
					   lock_sbq);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed to init port %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_timer_inc_pre_write - Fill all timer_inc_pre PHY registers
 * @pf: The PF private structure
 * @port: Port number to be initialized
 * @tx_ns: Time with which the port Tx clock is initialized
 * @rx_ns: Time with which the port Rx clock is initialized
 *
 * Utility function for filling the port init shadow registers
 */
static enum ice_status
ice_ptp_port_timer_inc_pre_write(struct ice_pf *pf, int port, u64 tx_ns,
				 u64 rx_ns)
{
	return ice_ptp_port_timer_inc_pre_write_lp(pf, port, tx_ns, rx_ns,
						   true);
}

/**
 * ice_ptp_rd_port_capture - Read a port's local time capture
 * @pf: The PF private structure
 * @port: Port number to read
 * @tx_ts: Where to put the read value from Tx capture register
 * @rx_ts: Where to put the read value from Rx capture register
 */
static enum ice_status
ice_ptp_rd_port_capture(struct ice_pf *pf, int port, u64 *tx_ts, u64 *rx_ts)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	u32 high, low;
	u64 ns;

	/* Tx case */
	status = ice_phy_port_reg_read(pf, port, P_REG_TX_CAPTURE_L, &low);
	if (status)
		goto exit;
	status = ice_phy_port_reg_read(pf, port, P_REG_TX_CAPTURE_U, &high);
	if (status)
		goto exit;

	ns = high;
	*tx_ts = ns << 32 | low;
	dev_dbg(dev, "tx_init = 0x%016llx\n", *tx_ts);

	/* Rx case */
	status = ice_phy_port_reg_read(pf, port, P_REG_RX_CAPTURE_L, &low);
	if (status)
		goto exit;
	status = ice_phy_port_reg_read(pf, port, P_REG_RX_CAPTURE_U, &high);
	if (status)
		goto exit;

	ns = high;
	*rx_ts = ns << 32 | low;
	dev_dbg(dev, "rx_init = 0x%016llx\n", *rx_ts);

exit:
	if (status)
		dev_err(dev, "PTP failed to read port capture %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_time_clk_cyc_write - Utility function to fill port time_clk_cyc
 * @pf: The PF private structure
 * @time_clk_cyc: number of clock cycles for one PHY timer tick
 *
 * Utility function for filling port time_clk_cyc (equivalent to shadow INCVAL
 * on the master timer)
 */
static enum ice_status
ice_ptp_port_time_clk_cyc_write_ext(struct ice_pf *pf, u64 time_clk_cyc)
{
	enum ice_status status;
	u32 high, low;
	u8 tmr_idx;

	tmr_idx = pf->hw.func_caps.ts_func_info.tmr_index_owned;
	low = (u32)(time_clk_cyc & TS_LOW_MASK);
	high = (u32)(time_clk_cyc >> 32);

	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_SHADJ_L(tmr_idx),
					    low);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_SHADJ_H(tmr_idx),
					    high);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf),
			"PTP failed in port time clk cyc write %s\n",
			ice_stat_str(status));
	return status;
}

/**
 * ice_ptp_port_time_clk_cyc_write - Utility function to fill port time_clk_cyc
 * @pf: The PF private structure
 * @port: Port number to be initialized
 * @time_clk_cyc: Number of clock cycles for one PHY timer tick
 *
 * Utility function for filling port time_clk_cyc (equivalent to shadow INCVAL
 * on the master timer)
 */
static enum ice_status
ice_ptp_port_time_clk_cyc_write(struct ice_pf *pf, int port, u64 time_clk_cyc)
{
	enum ice_status status;
	u32 high, low;

	low = (u32)(time_clk_cyc & TS_PHY_LOW_MASK);
	high = (u32)(time_clk_cyc >> 8);

	status = ice_phy_port_reg_write(pf, port, P_REG_TIMETUS_L, low);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write(pf, port, P_REG_TIMETUS_U, high);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf),
			"PTP failed in port time clk cyc write %s\n",
			ice_stat_str(status));
	return status;
}

/**
 * ice_ptp_port_cmd_ext - Utility function to fill port command registers
 * @pf: The PF private structure
 * @cmd: Command to be sent to the port
 *
 * Utility function for filling external PHY command registers
 */
static enum ice_status ice_ptp_port_cmd_ext(struct ice_pf *pf, enum tmr_cmd cmd)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	u32 cmd_val, val;

	switch (cmd) {
	case INIT_TIME:
		cmd_val = GLTSYN_CMD_INIT_TIME;
		break;
	case INIT_INCVAL:
		cmd_val = GLTSYN_CMD_INIT_INCVAL;
		break;
	case ADJ_TIME:
		cmd_val = GLTSYN_CMD_ADJ_TIME;
		break;
	case READ_TIME:
		cmd_val = GLTSYN_CMD_READ_TIME;
		break;
	default:
		dev_warn(dev, "unknown tmr cmd\n");
		status = ICE_ERR_NOT_IMPL;
		goto exit;
	}

	/* Read, modify, write */
	status = ice_phy_port_reg_read_ext(pf, ETH_GLTSYN_CMD, &val);
	if (status)
		goto exit;

	/* Modify necessary bits only and perform write */
	val &= ~TS_CMD_MASK_EXT;
	val |= cmd_val;
	status = ice_phy_port_reg_write_ext(pf, ETH_GLTSYN_CMD, val);

exit:
	if (status)
		dev_err(dev, "PTP failed in port cmd %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_cmd_lp - Utility function to fill port command registers
 * @pf: The PF private structure
 * @port: Port to which cmd has to be sent
 * @cmd: Command to be sent to the port
 * @lock_sbq: true to lock the sideband queue
 *
 * Utility function for filling port command registers, with lock parameter
 */
static enum ice_status
ice_ptp_port_cmd_lp(struct ice_pf *pf, int port, enum tmr_cmd cmd,
		    bool lock_sbq)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	u32 cmd_val, val;
	u8 tmr_idx;

#define SEL_PHY_MASTER 3
	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID)
		return ICE_ERR_NOT_READY;
	cmd_val = tmr_idx << SEL_PHY_MASTER;
	/* Coverity warns the default case is deadcode but removing it causes
	 * other static analysis tools (and compilers) to warn that not all
	 * cases of the tmr_cmd enumerated type are handled by this switch
	 * statement. Suppress the coverity warning with the following...
	 */
	/* Coverity[dead_error_condition] */
	switch (cmd) {
	case INIT_TIME:
		cmd_val |= 0x1;
		break;
	case INIT_INCVAL:
		cmd_val |= 0x2;
		break;
	case ADJ_TIME:
		cmd_val |= 0x3;
		break;
	case ADJ_TIME_AT_TIME:
		cmd_val |= 0x5;
		break;
	case READ_TIME:
		cmd_val |= 0x7;
		break;
	default:
		dev_warn(dev, "unknown tmr cmd\n");
		status = ICE_ERR_NOT_IMPL;
		goto exit;
	}

	/* Tx case */

	/* Read, modify, write */
	status = ice_phy_port_reg_read_lp(pf, port, P_REG_TX_TMR_CMD, &val,
					  lock_sbq);
	if (status)
		goto exit;

	/* Modify necessary bits only and perform write */
	val &= ~TS_CMD_MASK;
	val |= cmd_val;
	status = ice_phy_port_reg_write_lp(pf, port, P_REG_TX_TMR_CMD, val,
					   lock_sbq);
	if (status)
		goto exit;

	/* Rx case */

	/* Read, modify, write */
	status = ice_phy_port_reg_read_lp(pf, port, P_REG_RX_TMR_CMD, &val,
					  lock_sbq);
	if (status)
		goto exit;

	/* Modify necessary bits only and perform write */
	val &= ~TS_CMD_MASK;
	val |= cmd_val;
	status = ice_phy_port_reg_write_lp(pf, port, P_REG_RX_TMR_CMD, val,
					   lock_sbq);
exit:
	if (status)
		dev_err(dev, "PTP failed in port cmd %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_port_cmd - Utility function to fill port command registers
 * @pf: The PF private structure
 * @port: Port to which cmd has to be sent
 * @cmd: Command to be sent to the port
 */
static enum ice_status ice_ptp_port_cmd(struct ice_pf *pf, int port,
					enum tmr_cmd cmd)
{
	return ice_ptp_port_cmd_lp(pf, port, cmd, true);
}

/**
 * ice_ptp_port_set_wl - Set window length for port timestamping
 * @pf: Board private structure
 * @port: Port for which the wl is set
 * @wl: Window length to be set
 */
static enum ice_status ice_ptp_port_set_wl(struct ice_pf *pf, int port, u32 wl)
{
	enum ice_status status;

	status = ice_phy_port_reg_write(pf, port, P_REG_WL, wl);
	if (status)
		dev_err(ice_pf_to_dev(pf),
			"PTP failed to set window length %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_phy_get_link_speed - Get link speed based on serdes mode and FEC
 * @link_spd: Link speed to be determined
 * @serdes: serdes mode of PHY
 * @fec_algo: FEC algorithm
 */
static enum ice_status
ice_ptp_phy_get_link_speed(enum ice_ptp_link_spd *link_spd, u32 serdes,
			   enum ice_ptp_fec_algo fec_algo)
{
	serdes &= P_REG_LINK_SPEED_SERDES_M;

	if (fec_algo == ICE_PTP_FEC_ALGO_RS_FEC) {
		switch (serdes) {
		case ICE_PTP_SERDES_25G:
			*link_spd = ICE_PTP_LNK_SPD_25G_RS;
			break;
		case ICE_PTP_SERDES_50G:
			*link_spd = ICE_PTP_LNK_SPD_50G_RS;
			break;
		case ICE_PTP_SERDES_100G:
			*link_spd = ICE_PTP_LNK_SPD_100G_RS;
			break;
		default:
			return ICE_ERR_OUT_OF_RANGE;
		}
	} else {
		switch (serdes) {
		case ICE_PTP_SERDES_1G:
			*link_spd = ICE_PTP_LNK_SPD_1G;
			break;
		case ICE_PTP_SERDES_10G:
			*link_spd = ICE_PTP_LNK_SPD_10G;
			break;
		case ICE_PTP_SERDES_25G:
			*link_spd = ICE_PTP_LNK_SPD_25G;
			break;
		case ICE_PTP_SERDES_40G:
			*link_spd = ICE_PTP_LNK_SPD_40G;
			break;
		case ICE_PTP_SERDES_50G:
			*link_spd = ICE_PTP_LNK_SPD_50G;
			break;
		default:
			return ICE_ERR_OUT_OF_RANGE;
		}
	}

	return 0;
}

/**
 * ice_ptp_port_phy_set_parpcs_incval - Set PAR/PCS PHY cycle count
 * @pf: Board private struct
 * @port: Port we are configuring PHY for
 *
 * Note that this function is only expected to be called during port up and
 * during a link event.
 */
static void ice_ptp_port_phy_set_parpcs_incval(struct ice_pf *pf, int port)
{
	u64 rxtx_lane_par_clk[NUM_ICE_PTP_LNK_SPD] = { 31250000,  257812500,
						       644531250, 161132812,
						       257812500, 644531250,
						       644531250, 644531250 };
	u64 rxtx_lane_pcs_clk[NUM_ICE_PTP_LNK_SPD] = { 125000000, 156250000,
						       390625000, 97656250,
						       156250000, 390625000,
						       644531250, 644531250 };
	u64 rxtx_rsgb_par_clk[NUM_ICE_PTP_LNK_SPD] = {
		0, 0, 0, 322265625, 0, 0, 644531250, 1289062500 };
	u64 rxtx_rsgb_pcs_clk[NUM_ICE_PTP_LNK_SPD] = {
		0, 0, 0, 97656250, 0, 0, 195312500, 390625000 };
	u64 rx_desk_par_pcs_clk[NUM_ICE_PTP_LNK_SPD] = {
		0, 0, 0, 0, 156250000, 19531250, 644531250, 644531250
	};
	u64 cur_freq, mstr_incval, uix, phy_tus;
	enum ice_ptp_link_spd link_spd;
	enum ice_ptp_fec_algo fec_algo;
	enum ice_status status = 0;
	struct ice_vsi *vsi;
	u32 val, serdes;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;

	cur_freq = phy_clock_freq[vsi->time_ref_freq];
	mstr_incval = ice_ptp_read_incval(pf);

	status = ice_phy_port_reg_read(pf, port, P_REG_LINK_SPEED, &serdes);
	if (status)
		goto exit;
	fec_algo = (serdes & P_REG_LINK_SPEED_FEC_ALGO_M) >>
		   P_REG_LINK_SPEED_FEC_ALGO_S;
	status = ice_ptp_phy_get_link_speed(&link_spd, serdes, fec_algo);
	if (status)
		goto exit;

	/* UIX programming */
	/* We split a 'divide by 1e11' operation into a 'divide by 256' and a
	 * 'divide by 390625000' operation to be able to do the calculation
	 * using fixed-point math.
	 */
	if (link_spd == ICE_PTP_LNK_SPD_10G ||
	    link_spd == ICE_PTP_LNK_SPD_40G) {
#define LINE_UI_10G_40G 640 /* 6600 UI at 10Gb line rate */
		uix = (cur_freq * LINE_UI_10G_40G) >> 8;
		uix *= mstr_incval;
		uix /= 390625000;

		val = TS_LOW_MASK & uix;
		status = ice_phy_port_reg_write(pf, port, P_REG_UIX66_10G_40G_L,
						val);
		if (status)
			goto exit;
		val = (uix >> 32) & TS_LOW_MASK;
		status = ice_phy_port_reg_write(pf, port, P_REG_UIX66_10G_40G_U,
						val);
		if (status)
			goto exit;
	} else if (link_spd == ICE_PTP_LNK_SPD_25G ||
		   link_spd == ICE_PTP_LNK_SPD_100G_RS) {
#define LINE_UI_25G_100G 256 /* 6600 UI at 25Gb line rate */
		uix = (cur_freq * LINE_UI_25G_100G) >> 8;
		uix *= mstr_incval;
		uix /= 390625000;

		val = TS_LOW_MASK & uix;
		status = ice_phy_port_reg_write(pf, port,
						P_REG_UIX66_25G_100G_L, val);
		if (status)
			goto exit;
		val = (uix >> 32) & TS_LOW_MASK;
		status = ice_phy_port_reg_write(pf, port,
						P_REG_UIX66_25G_100G_U, val);
		if (status)
			goto exit;
	}

	if (link_spd == ICE_PTP_LNK_SPD_25G_RS) {
		phy_tus = (cur_freq * mstr_incval * 2) /
			  rxtx_rsgb_par_clk[link_spd];
		val = phy_tus & TS_PHY_LOW_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PAR_RX_TUS_L, val);
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PAR_TX_TUS_L, val);
		val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PAR_RX_TUS_U, val);
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PAR_TX_TUS_U, val);

		phy_tus = (cur_freq * mstr_incval) /
			  rxtx_rsgb_pcs_clk[link_spd];
		val = phy_tus & TS_PHY_LOW_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PCS_RX_TUS_L, val);
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PCS_TX_TUS_L, val);
		val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PCS_RX_TUS_U, val);
		ice_phy_port_reg_write(pf, port, P_REG_DESK_PCS_TX_TUS_U, val);
	} else {
		phy_tus = (cur_freq * mstr_incval) /
			  rxtx_lane_par_clk[link_spd];
		val = phy_tus & TS_PHY_LOW_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_PAR_RX_TUS_L, val);
		val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_PAR_RX_TUS_U, val);

		if (link_spd != ICE_PTP_LNK_SPD_50G_RS &&
		    link_spd != ICE_PTP_LNK_SPD_100G_RS) {
			val = phy_tus & TS_PHY_LOW_MASK;
			ice_phy_port_reg_write(pf, port, P_REG_PAR_TX_TUS_L,
					       val);
			val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
			ice_phy_port_reg_write(pf, port, P_REG_PAR_TX_TUS_U,
					       val);
		} else {
			phy_tus = (cur_freq * mstr_incval * 2) /
				  rxtx_rsgb_par_clk[link_spd];
			val = phy_tus & TS_PHY_LOW_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_RX_TUS_L, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_TX_TUS_L, val);
			val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_RX_TUS_U, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_TX_TUS_U, val);
		}

		phy_tus = (cur_freq * mstr_incval) /
			  rxtx_lane_pcs_clk[link_spd];
		val = phy_tus & TS_PHY_LOW_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_PCS_RX_TUS_L, val);
		val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
		ice_phy_port_reg_write(pf, port, P_REG_PCS_RX_TUS_U, val);

		if (link_spd != ICE_PTP_LNK_SPD_50G_RS &&
		    link_spd != ICE_PTP_LNK_SPD_100G_RS) {
			val = phy_tus & TS_PHY_LOW_MASK;
			ice_phy_port_reg_write(pf, port, P_REG_PCS_TX_TUS_L,
					       val);
			val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
			ice_phy_port_reg_write(pf, port, P_REG_PCS_TX_TUS_U,
					       val);
		} else {
			phy_tus = (cur_freq * mstr_incval) /
				  rxtx_rsgb_pcs_clk[link_spd];
			val = phy_tus & TS_PHY_LOW_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_RX_TUS_L, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_TX_TUS_L, val);
			val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_RX_TUS_U, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_TX_TUS_U, val);
		}

		if (link_spd == ICE_PTP_LNK_SPD_40G ||
		    link_spd == ICE_PTP_LNK_SPD_50G) {
			phy_tus = (cur_freq * mstr_incval) /
				  rx_desk_par_pcs_clk[link_spd];
			val = phy_tus & TS_PHY_LOW_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_RX_TUS_L, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_RX_TUS_L, val);
			val = (phy_tus >> 8) & TS_PHY_HIGH_MASK;
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PAR_RX_TUS_U, val);
			ice_phy_port_reg_write(pf, port,
					       P_REG_DESK_PCS_RX_TUS_U, val);
		}
	}

exit:
	if (status)
		dev_err(ice_pf_to_dev(pf),
			"PTP Vernier configuration failed on port %d\n", port);
}

/**
 * ice_ptp_tx_cfg_lane - Configure PHY quad for single/multi-lane timestamp
 * @pf: PF private structure
 * @port: Port to find quad to configure
 */
static void ice_ptp_tx_cfg_lane(struct ice_pf *pf, u8 port)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_ptp_link_spd link_spd;
	enum ice_ptp_fec_algo fec_algo;
	enum ice_status status;
	u32 serdes, val;
	int quad;

	quad = port / ICE_PORTS_PER_QUAD;

	status = ice_phy_port_reg_read(pf, port, P_REG_LINK_SPEED, &serdes);
	if (status)
		goto exit;

	fec_algo = (serdes & P_REG_LINK_SPEED_FEC_ALGO_M) >>
		   P_REG_LINK_SPEED_FEC_ALGO_S;
	status = ice_ptp_phy_get_link_speed(&link_spd, serdes, fec_algo);
	if (status)
		goto exit;

	status = ice_phy_quad_reg_read(pf, quad, Q_REG_TX_MEM_GBL_CFG, &val);
	if (status)
		goto exit;

	if (link_spd >= ICE_PTP_LNK_SPD_40G)
		val &= ~Q_REG_TX_MEM_GBL_CFG_LANE_TYPE_M;
	else
		val |= Q_REG_TX_MEM_GBL_CFG_LANE_TYPE_M;

	status = ice_phy_quad_reg_write(pf, quad, Q_REG_TX_MEM_GBL_CFG, val);

exit:
	if (status)
		dev_dbg(dev, "PTP failed multi-lane config %s\n",
			ice_stat_str(status));
}

/**
 * ice_ptp_master_cmd - Run timer command on master clock
 * @pf: Board private structure
 * @cmd: Timer command
 */
static void ice_ptp_master_cmd(struct ice_pf *pf, enum tmr_cmd cmd)
{
	struct ice_hw *hw = &pf->hw;
	u32 cmd_val;
	u8 tmr_idx;

#define SEL_CPK_MASTER 8
	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID)
		return;
	cmd_val = tmr_idx << SEL_CPK_MASTER;

	switch (cmd) {
	case INIT_TIME:
		cmd_val |= GLTSYN_CMD_INIT_TIME;
		break;
	case INIT_INCVAL:
		cmd_val |= GLTSYN_CMD_INIT_INCVAL;
		break;
	case ADJ_TIME:
		cmd_val |= GLTSYN_CMD_ADJ_TIME;
		break;
	case ADJ_TIME_AT_TIME:
		cmd_val |= GLTSYN_CMD_ADJ_INIT_TIME;
		break;
	case READ_TIME:
		cmd_val |= GLTSYN_CMD_READ_TIME;
		break;
	}

	wr32(hw, GLTSYN_CMD, cmd_val);
}

/**
 * ice_ptp_port_sync_master_timer - Sync PHY timer with Master timer
 * @pf: Board private structure
 * @port: Port for which the PHY start is set
 *
 * Sync PHY timer with Master timer after calculating and setting Tx/Rx Vernier
 * offset.
 */
static enum ice_status
ice_ptp_port_sync_master_timer(struct ice_pf *pf, int port)
{
	u64 mstr_time = 0x0, tx_time, rx_time, temp_adj;
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	s64 time_adj;
	u32 zo, lo;
	u8 tmr_idx;

	/* Get the PTP HW lock */
	if (!ice_ptp_lock(pf)) {
		status = ICE_ERR_IN_USE;
		goto exit;
	}

	/* Program cmd to master timer */
	ice_ptp_master_cmd(pf, READ_TIME);

	/* Program cmd to PHY port */
	status = ice_ptp_port_cmd(pf, port, READ_TIME);
	if (status)
		goto unlock;

	/* Issue sync to activate commands */
	wr32(&pf->hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);

	tmr_idx = master_idx;
	if (tmr_idx == MASTER_IDX_INVALID)
		return ICE_ERR_NOT_READY;

	/* Read master timer SHTIME_0 and SHTIME_L */
	zo = rd32(&pf->hw, GLTSYN_SHTIME_0(tmr_idx));
	lo = rd32(&pf->hw, GLTSYN_SHTIME_L(tmr_idx));
	mstr_time |= (u64)lo;
	mstr_time = (mstr_time << 32) | (u64)zo;

	/* Read Tx and Rx capture from PHY */
	status = ice_ptp_rd_port_capture(pf, port, &tx_time, &rx_time);
	if (status)
		goto unlock;

	if (tx_time != rx_time)
		dev_info(dev, "Port %d Rx and Tx times do not match\n", port);

	/* Calculate amount to adjust port timer and account for case where
	 * delta is larger/smaller than S64_MAX/S64_MIN
	 */
	if (mstr_time > tx_time) {
		temp_adj = mstr_time - tx_time;
		if (temp_adj & BIT_ULL(63)) {
			time_adj = temp_adj >> 1;
		} else {
			time_adj = temp_adj;
			/* Set to zero to indicate adjustment done */
			temp_adj = 0x0;
		}
	} else {
		temp_adj = tx_time - mstr_time;
		if (temp_adj & BIT_ULL(63)) {
			time_adj = -(temp_adj >> 1);
		} else {
			time_adj = -temp_adj;
			/* Set to zero to indicate adjustment done */
			temp_adj = 0x0;
		}
	}

	status = ice_ptp_port_time_inc_pre_wr_subns(pf, port, time_adj,
						    time_adj);
	if (status)
		goto unlock;

	status = ice_ptp_port_cmd(pf, port, ADJ_TIME);
	if (status)
		goto unlock;

	/* Issue sync to activate commands */
	wr32(&pf->hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);

	/* Do a second adjustment if original was too large/small to fit into
	 * a S64
	 */
	if (temp_adj) {
		status = ice_ptp_port_time_inc_pre_wr_subns(pf, port, time_adj,
							    time_adj);
		if (status)
			goto unlock;

		status = ice_ptp_port_cmd(pf, port, ADJ_TIME);
		if (!status)
			/* Issue sync to activate commands */
			wr32(&pf->hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);
	}

	/* This second register read is to flush out the port and master command
	 * registers. Multiple successive calls to this function require this
	 */

	/* Program cmd to master timer */
	ice_ptp_master_cmd(pf, READ_TIME);

	/* Program cmd to PHY port */
	status = ice_ptp_port_cmd(pf, port, READ_TIME);
	if (status)
		goto unlock;

	/* Issue sync to activate commands */
	wr32(&pf->hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);

	/* Read master timer SHTIME_0 and SHTIME_L */
	zo = rd32(&pf->hw, GLTSYN_SHTIME_0(tmr_idx));
	lo = rd32(&pf->hw, GLTSYN_SHTIME_L(tmr_idx));
	mstr_time = (u64)lo;
	mstr_time = (mstr_time << 32) | (u64)zo;

	/* Read Tx and Rx capture from PHY */
	status = ice_ptp_rd_port_capture(pf, port, &tx_time, &rx_time);
	if (status)
		goto unlock;
	dev_info(dev, "Port %d PTP synced to master 0x%016llX, 0x%016llX\n",
		 port, mstr_time, tx_time);
unlock:
	ice_ptp_unlock(pf);
exit:
	if (status)
		dev_err(dev,
			"PTP failed to sync port %d PHY time, status %d\n",
			port, status);

	return status;
}

/**
 * ice_ptp_port_phy_start - Set or clear PHY start for port timestamping
 * @pf: Board private structure
 * @port: Port for which the PHY start is set
 * @phy_start: Value to be set
 */
static enum ice_status
ice_ptp_port_phy_start(struct ice_pf *pf, u8 port, bool phy_start)
{
	enum ice_status status;
	u32 val;

	mutex_lock(&pf->ptp_ps_lock);

	/* Clear offset_ready registers to avoid marking invalid timestamps as
	 * valid and providing incorrect TS values
	 */

	status = ice_phy_port_reg_write(pf, port, P_REG_TX_OR, 0);
	if (status)
		goto exit;

	status = ice_phy_port_reg_write(pf, port, P_REG_RX_OR, 0);
	if (status)
		goto exit;


	status = ice_phy_port_reg_read(pf, port, P_REG_PS, &val);
	if (status)
		goto exit;

	val &= ~P_REG_PS_START_M;
	status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
	if (status)
		goto exit;

	val &= ~P_REG_PS_ENA_CLK_M;
	status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
	if (status)
		goto exit;

	if (phy_start && pf->ptp_link_up) {
		ice_ptp_tx_cfg_lane(pf, port);
		ice_ptp_port_phy_set_parpcs_incval(pf, port);

		status = ice_ptp_set_increment(pf, 0);
		if (status)
			goto exit;

		status = ice_phy_port_reg_read(pf, port, P_REG_PS, &val);
		if (status)
			goto exit;

		val |= P_REG_PS_SFT_RESET_M;
		status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
		if (status)
			goto exit;

		val |= P_REG_PS_START_M;
		status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
		if (status)
			goto exit;

		val &= ~P_REG_PS_SFT_RESET_M;
		status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
		if (status)
			goto exit;

		status = ice_ptp_set_increment(pf, 0);
		if (status)
			goto exit;

		val |= P_REG_PS_ENA_CLK_M;
		status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
		if (status)
			goto exit;

		val |= P_REG_PS_LOAD_OFFSET_M;
		status = ice_phy_port_reg_write(pf, port, P_REG_PS, val);
		if (status)
			goto exit;
		wr32(&pf->hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);
		status = ice_ptp_port_sync_master_timer(pf, port);
	}
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed to set PHY port %d %s, ret=%s\n", port,
			phy_start ? "up" : "down", ice_stat_str(status));

	mutex_unlock(&pf->ptp_ps_lock);

	return status;
}

/**
 * ice_ptp_link_change - Set or clear port registers for timestamping
 * @pf: Board private structure
 * @port: Port for which the PHY start is set
 * @linkup: Link is up or down
 */
enum ice_status ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup)
{
	if (linkup && !test_bit(ICE_FLAG_PTP, pf->flags)) {
		dev_err(ice_pf_to_dev(pf),
			"PTP not ready, failed to prepare port %d\n", port);
		return ICE_ERR_NOT_READY;
	}

	if (port >= ICE_NUM_EXTERNAL_PORTS)
		return ICE_ERR_PARAM;

	pf->ptp_link_up = linkup;

	return ice_ptp_port_phy_start(pf, port, linkup);
}


/**
 * ice_ptp_tx_ena_intr - Enable or disable the Tx timestamp interrupt
 * @pf: PF private structure
 * @ena: bool value to enable or disable interrupt
 * @threshold: Minimum number of packets at which intr is triggered
 *
 * Utility function to enable or disable Tx timestamp interrupt and threshold
 */
static enum ice_status
ice_ptp_tx_ena_intr(struct ice_pf *pf, bool ena, u32 threshold)
{
	enum ice_status status = 0;
	int quad;
	u32 val;


	for (quad = 0; quad < ICE_MAX_QUAD; quad++) {
		status = ice_phy_quad_reg_read(pf, quad, Q_REG_TX_MEM_GBL_CFG,
					       &val);
		if (status)
			goto exit;

		if (ena) {
			val |= Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M;
			val &= ~Q_REG_TX_MEM_GBL_CFG_INTR_THR_M;
			val |= ((threshold << Q_REG_TX_MEM_GBL_CFG_INTR_THR_S) &
				Q_REG_TX_MEM_GBL_CFG_INTR_THR_M);
		} else {
			val &= ~Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M;
		}

		status = ice_phy_quad_reg_write(pf, quad, Q_REG_TX_MEM_GBL_CFG,
						val);
		if (status)
			goto exit;
	}

exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed in intr ena %s\n",
			ice_stat_str(status));
	return status;
}

/**
 * ice_ptp_read_time - Read the time from the device
 * @pf: Board private structure
 * @ts: timespec structure to hold the current time value
 *
 * This function reads the master clock registers and stores them in a timespec.
 * However, since the registers are 64 bits of nanoseconds, we must convert the
 * result to a timespec before we can return.
 */
static void ice_ptp_read_time(struct ice_pf *pf, struct timespec64 *ts)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	u64 time_ns;

	if (!vsi) {
		dev_err(&pf->pdev->dev, "PTP failed to get VSI!\n");
		return;
	}

	if (vsi->mstr_tmr_mode != ICE_MSTR_TMR_MODE_NANOSECONDS) {
		dev_err(ice_pf_to_dev(pf),
			"PTP Locked mode is not supported!\n");
		return;
	}
	time_ns = ice_ptp_read_master_clk_reg(pf);

	*ts = ns_to_timespec64(time_ns);
}

/**
 * ice_ptp_write_init - Write the time to the device init registers
 * @pf: Board private structure
 * @ts: timespec structure that holds the new time value
 *
 * This function writes the clk registers with the user value. Since we receive
 * a timespec from the stack, we must convert that timespec into nanoseconds
 * before programming the registers.
 */
static enum ice_status
ice_ptp_write_init(struct ice_pf *pf, struct timespec64 *ts)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	u64 ns = timespec64_to_ns(ts);
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;
	int port;
	u64 val;

	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to get VSI!\n");
		return ICE_ERR_BAD_PTR;
	}

	if (vsi->mstr_tmr_mode != ICE_MSTR_TMR_MODE_NANOSECONDS) {
		dev_err(ice_pf_to_dev(pf),
			"PTP Locked mode is not supported!\n");
		return ICE_ERR_NOT_SUPPORTED;
	}
	val = ns;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* Master timers */
	wr32(hw, GLTSYN_SHTIME_L(tmr_idx), (u32)(val & TS_LOW_MASK));
	wr32(hw, GLTSYN_SHTIME_H(tmr_idx), (u32)(val >> 32));
	wr32(hw, GLTSYN_SHTIME_0(tmr_idx), 0);

	/* Phy Clks */
	/* Fill Rx and Tx ports and send msg to PHY */
	if (!ice_is_generic_mac(hw))
		return ice_ptp_port_timer_inc_pre_write_ext(pf, val);

	for (port = 0; port < ICE_NUM_EXTERNAL_PORTS; port++) {
		enum ice_status status;

		status = ice_ptp_port_timer_inc_pre_write(pf, port, val, val);
		if (status)
			return status;
	}

	return 0;
}

/**
 * ice_ptp_write_incval - Write the increment value to the device registers
 * @pf: Board private structure
 * @incval: master timer increment value per clock cycle
 *
 * This function writes the registers with the user value.
 */
static enum ice_status ice_ptp_write_incval(struct ice_pf *pf, u64 incval)
{
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;
	int port;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* Shadow Adjust */
	wr32(hw, GLTSYN_SHADJ_L(tmr_idx), (u32)(incval & TS_LOW_MASK));
	wr32(hw, GLTSYN_SHADJ_H(tmr_idx), (u32)(incval >> 32));

	/* Phy Clks */
	/* Fill Rx and Tx ports and send msg to PHY */
	if (!ice_is_generic_mac(hw))
		return ice_ptp_port_time_clk_cyc_write_ext(pf, incval);

	for (port = 0; port < ICE_NUM_EXTERNAL_PORTS; port++) {
		enum ice_status status;

		status = ice_ptp_port_time_clk_cyc_write(pf, port, incval);
		if (status)
			return status;
	}

	return 0;
}

/**
 * ice_ptp_write_adj - Write an adjustment value to the device registers
 * @pf: Board private structure
 * @adj: Adjustment in nanoseconds
 * @lock_sbq: true to lock the sbq sq_lock (the usual case); false if the
 *            sq_lock has already been locked at a higher level
 *
 * This function writes the registers with the user value.
 */
static enum ice_status
ice_ptp_write_adj(struct ice_pf *pf, s64 adj, bool lock_sbq)
{
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;
	int port;


	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* Shadow Adjust */
	wr32(hw, GLTSYN_SHADJ_L(tmr_idx), 0);
	wr32(hw, GLTSYN_SHADJ_H(tmr_idx), (u32)(adj & TS_LOW_MASK));

	/* Phy Clks */
	/* Fill Rx and Tx ports and send msg to PHY */
	if (!ice_is_generic_mac(hw)) {
		/* The PHY has two 32 bit registers, ETH_GLTSYN_SHADJ_H and
		 * ETH_GLTSYN_SHADJ_L. The former is used to write a 32 bit
		 * nanosecond adjustment value and the latter is used to write
		 * and 32 bit residual subnanosecond adjustment value. In this
		 * flow, the value in 'adj' is the adjustment value, not the
		 * residual value.
		 *
		 * ice_ptp_port_time_clk_cyc_write_ext takes a 64 bit value and
		 * then writes the low 32 bits to ETH_GLTSYN_SHADJ_L and the
		 * high 32 bits to ETH_GLTSYN_SHADJ_H. Ensure the right value
		 * goes into the ETH_GLTSYN_SHADJ_H by left shifting 'adj' by
		 * 32 bits. The residual value written to the PHY will be 0.
		 */
		u64 adj_phy_high = (adj & TS_LOW_MASK) << 32;

		return ice_ptp_port_time_clk_cyc_write_ext(pf, adj_phy_high);
	}

	for (port = 0; port < ICE_NUM_EXTERNAL_PORTS; port++) {
		enum ice_status status;

		status = ice_ptp_port_timer_inc_pre_write_lp(pf, port, adj, adj,
							     lock_sbq);
		if (status)
			return status;
	}

	return 0;
}


/**
 * ice_ptp_tmr_cmd_lp - Run timer command, with lock parameter
 * @pf: Board private structure
 * @cmd: Timer command
 * @lock_sbq: true to lock the sideband queue
 *
 * Perform a timer command on master timer and all PHY ports.
 */
static enum ice_status
ice_ptp_tmr_cmd_lp(struct ice_pf *pf, enum tmr_cmd cmd, bool lock_sbq)
{
	enum ice_status status = 0;
	struct ice_hw *hw = &pf->hw;
	int port;

	/* First write to master timer */
	ice_ptp_master_cmd(pf, cmd);

	/* Next write to ports */
	if (ice_is_generic_mac(hw)) {
		for (port = 0; port < ICE_NUM_EXTERNAL_PORTS; port++) {
			status = ice_ptp_port_cmd_lp(pf, port, cmd, lock_sbq);
			if (status)
				goto exit;
		}
	} else {
		status = ice_ptp_port_cmd_ext(pf, cmd);
	}

	/* Sync will drive both master timers and PHY cmds */
	wr32(hw, GLTSYN_CMD_SYNC, SYNC_EXEC_CMD);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed in tmr cmd %s\n",
			ice_stat_str(status));

	return status;
}

/**
 * ice_ptp_tmr_cmd - Run timer command on master timer and all PHY ports.
 * @pf: Board private structure
 * @cmd: Timer command
 */
static enum ice_status ice_ptp_tmr_cmd(struct ice_pf *pf, enum tmr_cmd cmd)
{
	return ice_ptp_tmr_cmd_lp(pf, cmd, true);
}


/**
 * ice_ptp_set_wl - Set window length for PHY timestamping
 * @pf: Board private structure
 */
static enum ice_status ice_ptp_set_wl(struct ice_pf *pf)
{
	enum ice_status status = 0;
	u32 wl = 0x111ed; /* Vernier Window Length */
	int port;

	for (port = 0; port < ICE_NUM_EXTERNAL_PORTS; port++) {
		status = ice_ptp_port_set_wl(pf, port, wl);
		if (status) {
			dev_err(ice_pf_to_dev(pf), "PTP failed in set WL %s\n",
				ice_stat_str(status));
			break;
		}
	}

	return status;
}

/**
 * ice_ptp_set_incval - Utility function to set clock increment rate
 * @pf: Board private structure
 * @incval: master timer increment value per clock cycle
 *
 * Utility function for setting clock increment rate
 */
static enum ice_status ice_ptp_set_incval(struct ice_pf *pf, s64 incval)
{
	enum ice_status status;

	if (!ice_ptp_lock(pf))
		return ICE_ERR_IN_USE;

	status = ice_ptp_write_incval(pf, incval);
	if (status)
		goto exit;

	status = ice_ptp_tmr_cmd(pf, INIT_INCVAL);
exit:
	ice_ptp_unlock(pf);
	return status;
}

/**
 * ice_ptp_update_incval - Update clock increment rate
 * @pf: Board private structure
 * @time_ref_freq: TIME_REF frequency to use
 * @mstr_tmr_mode: Master timer mode (nanoseconds or locked)
 */
enum ice_status
ice_ptp_update_incval(struct ice_pf *pf, enum ice_time_ref_freq time_ref_freq,
		      enum ice_mstr_tmr_mode mstr_tmr_mode)
{
	enum ice_status status;
	struct timespec64 ts;
	struct ice_vsi *vsi;
	s64 incval;

	if (!test_bit(ICE_FLAG_PTP, pf->flags)) {
		dev_err(ice_pf_to_dev(pf),
			"PTP not ready, failed to update incval\n");
		return ICE_ERR_NOT_READY;
	}

	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		status = ICE_ERR_NOT_IMPL;
		goto exit;
	}

	if (time_ref_freq >= NUM_ICE_TIME_REF_FREQ ||
	    mstr_tmr_mode >= NUM_ICE_MSTR_TMR_MODE) {
		status = ICE_ERR_PARAM;
		goto exit;
	}

	if (mstr_tmr_mode == ICE_MSTR_TMR_MODE_NANOSECONDS)
		incval = incval_values[time_ref_freq];
	else
		incval = 0x100000000ULL;

	status = ice_ptp_set_incval(pf, incval);
	if (status)
		goto exit;

	/* Acquire the global hardware lock */
	if (!ice_ptp_lock(pf)) {
		status = ICE_ERR_IN_USE;
		goto exit;
	}

	vsi->time_ref_freq = time_ref_freq;
	vsi->mstr_tmr_mode = mstr_tmr_mode;

	ts = ktime_to_timespec64(ktime_get_real());
	status = ice_ptp_write_init(pf, &ts);
	if (status)
		goto exit;

	/* Request HW to load the above shadow reg to the real timers */
	status = ice_ptp_tmr_cmd(pf, INIT_TIME);
	if (status)
		goto exit;

	ice_ptp_unlock(pf);
exit:
	if (status) {
		ice_ptp_unlock(pf);
		dev_err(&pf->pdev->dev, "PTP failed in update incval %s\n",
			ice_stat_str(status));
	}

	return status;
}

/**
 * ice_ptp_get_incval - Get clock increment params
 * @pf: Board private structure
 * @time_ref_freq: TIME_REF frequency
 * @mstr_tmr_mode: Master timer mode (nanoseconds or locked)
 */
enum ice_status
ice_ptp_get_incval(struct ice_pf *pf, enum ice_time_ref_freq *time_ref_freq,
		   enum ice_mstr_tmr_mode *mstr_tmr_mode)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);

	if (!vsi)
		return ICE_ERR_NOT_IMPL;

	*time_ref_freq = vsi->time_ref_freq;
	*mstr_tmr_mode = vsi->mstr_tmr_mode;

	return 0;
}

/**
 * ice_ptp_set_increment - Adjust clock increment rate
 * @pf: Board private structure
 * @ppb: Parts per billion
 */
static enum ice_status ice_ptp_set_increment(struct ice_pf *pf, s32 ppb)
{
	enum ice_status status;
	s64 incval, freq, diff;
	struct ice_vsi *vsi;
	int neg_adj = 0;
	int freq_idx;

	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		status = ICE_ERR_NOT_IMPL;
		goto exit;
	}

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}
	if (ice_is_generic_mac(&pf->hw)) {
		freq_idx = vsi->time_ref_freq;
		if (freq_idx < NUM_ICE_TIME_REF_FREQ)
			incval = incval_values[freq_idx];
		else
			incval = DEFAULT_INCVAL;
	} else {
		incval = DEFAULT_INCVAL_EXT;
	}

	freq = incval * ppb;
	diff = div_u64(freq, 1000000000ULL);

	if (neg_adj)
		incval -= diff;
	else
		incval += diff;

	status = ice_ptp_set_incval(pf, incval);
exit:
	if (status)
		dev_err(ice_pf_to_dev(pf), "PTP failed in set incr %s\n",
			ice_stat_str(status));
	return status;
}

/**
 * ice_ptp_adjfreq - Adjust the frequency of the clock
 * @ptp: The PTP clock structure
 * @ppb: Parts per billion adjustment from the base
 *
 * Adjust the frequency of the clock by the indicated parts per billion from the
 * base frequency.
 */
static int ice_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	struct ice_vsi *vsi = container_of(ptp, struct ice_vsi, ptp_caps);
	struct ice_pf *pf = vsi->back;
	enum ice_status status;

	if (vsi->mstr_tmr_mode == ICE_MSTR_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"adjfreq not supported in locked mode\n");
		return -EOPNOTSUPP;
	}

	status = ice_ptp_set_increment(pf, ppb);

	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed in adj freq %s\n",
			ice_stat_str(status));
		return -EFAULT;
	}

	return 0;
}

/**
 * ice_ptp_cfg_periodic_clkout - Configure CPK to generate periodic clk
 * @pf: Board private structure
 * @ena: true to enable; false to disable
 * @chan: GPIO channel (0-3)
 * @gpio_pin: GPIO pin
 * @period: Clock period in nanoseconds
 * @start_time: Start time in nanoseconds
 *
 * Configure the internal clock generator modules to generate the clock wave of
 * specified period.
 */
int
ice_ptp_cfg_periodic_clkout(struct ice_pf *pf, bool ena, unsigned int chan,
			    u32 gpio_pin, u64 period, u64 start_time)
{
	struct ice_hw *hw = &pf->hw;
	u32 func, val, inc_h;
	struct ice_vsi *vsi;
	int status = 0;
	u8 tmr_idx;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EINVAL;

	if (vsi->mstr_tmr_mode == ICE_MSTR_TMR_MODE_LOCKED) {
		dev_err(ice_pf_to_dev(pf),
			"locked mode PPS/PEROUT not supported\n");
		return -EOPNOTSUPP;
	}

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	/* 0. Reset mode & out_en in AUX_OUT */
	wr32(hw, GLTSYN_AUX_OUT(chan, tmr_idx), 0);

	/* If we're disabling the output, clear out CLKO and TGT and keep
	 * output level low
	 */
	if (!ena) {
		wr32(hw, GLTSYN_CLKO(chan, tmr_idx), 0);
		wr32(hw, GLTSYN_TGT_L(chan, tmr_idx), 0);
		wr32(hw, GLTSYN_TGT_H(chan, tmr_idx), 0);

		val = GLGEN_GPIO_CTL_PIN_DIR_M;
		wr32(hw, GLGEN_GPIO_CTL(gpio_pin), val);

		return 0;
	}

	/* 1. Write clkout with half of required period value */
	if (period & 0x1) {
		dev_err(ice_pf_to_dev(pf),
			"CLK Period must be an even value\n");
		status = -EINVAL;
		goto out;
	}

	period >>= 1;

	/* For proper operation, the GLTSYN_CLKO must be larger than twice the
	 * GLTSYN_INC and for reasonable accuracy the GLTSYN_CLKO should be
	 * significantly larger than GLTSYN_INC.
	 * We usually keep inc_h = 1 to get nano-second increment.
	 * Just to simplify our math, let's discard inc_l (sub_ns)
	 * and round it off to 1ns (or 1 increment to inc_h)
	 */
	inc_h = rd32(hw, GLTSYN_INCVAL_H(tmr_idx)) + 1;
	if (period <= inc_h || period > U32_MAX) {
		dev_err(ice_pf_to_dev(pf),
			"CLK Period must be > (2 * INCVAL) && < 2^33\n");
		status = -EINVAL;
		goto out;
	}

	wr32(hw, GLTSYN_CLKO(chan, tmr_idx), lower_32_bits(period));

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

out:
	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to cfg per_clk %d\n",
			status);
		return -EFAULT;
	}

	return 0;
}

/**
 * ice_ptp_stop_pps - Stop the 1588 one pulse per second output
 * @pf: Board private structure
 *
 * This function stops the 1588 one pulse per second output in preparation for
 * making a large adjustment to the 1588 master timer.  The 1 PPS output must
 * be restarted with ice_ptp_restart_pps() after the adjustment is complete.
 * This operation will cause the 1 PPS output signal to transition to low.
 */
static void ice_ptp_stop_pps(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;
	wr32(hw, GLTSYN_AUX_OUT(PPS_CLK_GEN_CHAN, tmr_idx), 0);
}

/* Time allowed for programming periodic clock output */
#define START_OFFS_NS 100000000

/**
 * ice_ptp_restart_pps - Restart the 1588 one pulse per second output
 * @pf: Board private structure
 *
 * This function restarts the 1588 1 PPS output after it has been stopped.
 */
static int ice_ptp_restart_pps(struct ice_pf *pf)
{
	struct ice_vsi *vsi;
	u64 start_time;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EINVAL;

	/* At this point, the 1 PPS output has already been stopped in
	 * GLTSYN_AUX_OUT
	 */

	/* Allow time for programming before start_time is hit */
	start_time = ice_ptp_read_master_clk_reg(pf) + START_OFFS_NS;

	/* Round up to nearest second boundary */
	start_time = roundup(start_time, NSEC_PER_SEC);
	start_time -= pps_out_prop_delay_ns[vsi->time_ref_freq];

	return ice_ptp_cfg_periodic_clkout(pf, true, PPS_CLK_GEN_CHAN,
					   PPS_PIN_INDEX, NSEC_PER_SEC,
					   start_time);
}

/**
 * ice_ptp_dis_pps - Disable the 1588 one pulse per second output
 * @pf: Board private structure
 *
 * This function disables the 1588 one pulse per second output in preparation
 * for making a small adjustment to the 1588 master timer.  The 1 PPS output
 * must be re-enabled with ice_ptp_reena_pps() after the adjustment is
 * complete.  Disabling the 1 PPS output prevents the output from toggling, but
 * does not change the output state to low, so it may be used to perform fine
 * adjustments while maintaining a continuous 1 PPS out.
 */
static void ice_ptp_dis_pps(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;
	u32 val;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	val = rd32(hw, GLTSYN_AUX_OUT(PPS_CLK_GEN_CHAN, tmr_idx));

	/* Clear enabled bit */
	val &= ~GLTSYN_AUX_OUT_0_OUT_ENA_M;

	wr32(hw, GLTSYN_AUX_OUT(PPS_CLK_GEN_CHAN, tmr_idx), val);
}

/**
 * ice_ptp_reena_pps - Re-enable the 1588 one pulse per second output
 * @pf: Board private structure
 *
 * This function re-enables the 1588 1 PPS output after it has been disabled.
 */
static void ice_ptp_reena_pps(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u8 tmr_idx;
	u32 val;

	tmr_idx = hw->func_caps.ts_func_info.tmr_index_owned;

	val = rd32(hw, GLTSYN_AUX_OUT(PPS_CLK_GEN_CHAN, tmr_idx));

	/* Set enabled bit */
	val |= GLTSYN_AUX_OUT_0_OUT_ENA_M;

	wr32(hw, GLTSYN_AUX_OUT(PPS_CLK_GEN_CHAN, tmr_idx), val);
}


/**
 * ice_ptp_gettime - Get the time of the clock
 * @ptp: The PTP clock structure
 * @ts: timespec64 structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int ice_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct ice_vsi *vsi = container_of(ptp, struct ice_vsi, ptp_caps);
	enum ice_status status = 0;
	struct ice_pf *pf = vsi->back;

	if (!ice_ptp_lock(pf)) {
		status = ICE_ERR_IN_USE;
		goto exit;
	}

	ice_ptp_read_time(pf, ts);
	ice_ptp_unlock(pf);

exit:
	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to get time %s\n",
			ice_stat_str(status));
		return -EFAULT;
	}

	return 0;
}

/**
 * ice_ptp_settime - Set the time of the clock
 * @ptp: The PTP clock structure
 * @ts: timespec64 structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int
ice_ptp_settime(struct ptp_clock_info *ptp, const struct timespec64 *ts)
{
	struct ice_vsi *vsi = container_of(ptp, struct ice_vsi, ptp_caps);
	struct ice_pf *pf = vsi->back;
	struct timespec64 ts64 = *ts;
	enum ice_status status;
	u8 port;

	/* For Vernier mode, we need to recalibrate after new settime
	 * Start with disabling timestamp block
	 */
	port = pf->hw.port_info->lport;

	if (pf->ptp_link_up)
		ice_ptp_port_phy_start(pf, port, false);

	if (!ice_ptp_lock(pf)) {
		status = ICE_ERR_IN_USE;
		goto exit;
	}

	if (pf->ptp_one_pps_out_ena)
		ice_ptp_stop_pps(pf);

	status = ice_ptp_write_init(pf, &ts64);
	if (!status)
		status = ice_ptp_tmr_cmd(pf, INIT_TIME);
	if (pf->ptp_one_pps_out_ena)
		ice_ptp_restart_pps(pf);
	ice_ptp_unlock(pf);

	if (!status)
		ice_ptp_update_cached_systime(pf);

	/* Recalibrate and re-enable timestamp block */
	if (pf->ptp_link_up)
		ice_ptp_port_phy_start(pf, port, true);
exit:
	if (status) {
		dev_err(ice_pf_to_dev(pf), "PTP failed to set time %s\n",
			ice_stat_str(status));
		return -EFAULT;
	}

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * ice_ptp_gettime32 - Get the time of the clock
 * @ptp: The PTP clock structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int ice_ptp_gettime32(struct ptp_clock_info *ptp, struct timespec *ts)
{
	struct timespec64 ts64;

	if (!ice_ptp_gettime(ptp, &ts64)) {
		*ts = timespec64_to_timespec(ts64);
		return 0;
	}

	return -EFAULT;
}

/**
 * ice_ptp_settime32 - Set the time of the clock
 * @ptp: The PTP clock structure
 * @ts: timespec structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int
ice_ptp_settime32(struct ptp_clock_info *ptp, const struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);

	return ice_ptp_settime(ptp, &ts64);
}
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */

/**
 * ice_ptp_adjtime_nonatomic - Do a non-atomic clock adjustment
 * @ptp: The PTP clock structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime_nonatomic(struct ptp_clock_info *ptp, s64 delta)
{
	struct timespec64 now, then;

	then = ns_to_timespec64(delta);
	ice_ptp_gettime(ptp, &now);
	now = timespec64_add(now, then);

	return ice_ptp_settime(ptp, (const struct timespec64 *)&now);
}

/**
 * ice_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @ptp: The PTP clock structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int ice_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct ice_vsi *vsi = container_of(ptp, struct ice_vsi, ptp_caps);
	bool coarse_adj = false, lock_sbq = true;
	struct ice_pf *pf = vsi->back;
	unsigned long flags = 0;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	if (vsi->mstr_tmr_mode == ICE_MSTR_TMR_MODE_LOCKED) {
		dev_err(dev, "Locked Mode adjtime not supported\n");
		return -EOPNOTSUPP;
	}

	if (delta > INT_MAX || delta < INT_MIN) {
		/* outside atomic adjustment capability range. do non-atomic
		 * adjustment
		 */
		dev_dbg(dev, "delta = %lld, adjtime non-atomic\n", delta);
		return ice_ptp_adjtime_nonatomic(ptp, delta);
	}

	if (!ice_ptp_lock(pf)) {
		status = ICE_ERR_IN_USE;
		goto exit;
	}

#define COARSE_ADJ_THRESH_NS 10000000	/* 10 ms */
#define PTP_ADJ_TIME_NS 5000000		/* 5 ms */
	if (pf->ptp_one_pps_out_ena) {
		if (delta > COARSE_ADJ_THRESH_NS ||
		    delta < -COARSE_ADJ_THRESH_NS) {
			ice_ptp_stop_pps(pf);
			coarse_adj = true;
		} else if (delta < 0) {
			/* Special flow for negative fine adjustments only */
			u64 systime, target, ns_to_edge;

			/* Lock the sideband queue's send queue lock in
			 * advance, since we can't do it while atomic
			 */
			ice_sbq_lock(&pf->hw);
			lock_sbq = false;

			/* The whole sequence must be done within the valid
			 * window, so make sure we aren't preempted here
			 */
			local_irq_save(flags);
			preempt_disable();

			/* Calculate time to next edge */
			systime = ice_ptp_read_master_clk_reg(pf);
			target = ice_ptp_read_perout_tgt(pf, PPS_CLK_GEN_CHAN);
			ns_to_edge = target - systime;

			/* For negative adjustments, we can't miss an edge. */
			if (ns_to_edge < PTP_ADJ_TIME_NS) {
				u64 delay_count = 0;

				/* Wait for the next edge (and a bit extra) */
				udelay(ns_to_edge / NSEC_PER_USEC + 10);

				/* Check if we got past edge; iterate for up
				 * to 6 ms
				 */
#define ICE_PTP_ADJ_MAX_DELAY_RETRY 600
				while (1) {
					unsigned int ch = PPS_CLK_GEN_CHAN;
					u64 tgt_new;

					tgt_new = ice_ptp_read_perout_tgt(pf,
									  ch);
					if (tgt_new != target)
						break;

					if (++delay_count >
					    ICE_PTP_ADJ_MAX_DELAY_RETRY) {
						preempt_enable();
						local_irq_restore(flags);
						ice_sbq_unlock(&pf->hw);
						ice_ptp_unlock(pf);

						status = ICE_ERR_MAX_LIMIT;
						goto exit;
					}

					usleep_range(10, 20);
				}
			}

			ice_ptp_dis_pps(pf);
		}
	}

	status = ice_ptp_write_adj(pf, delta, lock_sbq);
	/* If writing to device adj registers succeeds then go ahead
	 * and run timer command
	 */
	if (!status)
		status = ice_ptp_tmr_cmd_lp(pf, ADJ_TIME, lock_sbq);
	if (pf->ptp_one_pps_out_ena) {
		if (coarse_adj) {
			ice_ptp_restart_pps(pf);
		} else if (delta < 0) {
			/* Special flow for negative fine adjustments only */
			ice_ptp_reena_pps(pf);
			preempt_enable();
			local_irq_restore(flags);
			ice_sbq_unlock(&pf->hw);
		}
	}

	ice_ptp_unlock(pf);

	if (!status)
		ice_ptp_update_cached_systime(pf);

exit:
	if (status) {
		dev_err(dev, "PTP failed in adj time %s\n",
			ice_stat_str(status));
		return -EFAULT;
	}

	return 0;
}

/**
 * ice_ptp_feature_ena - Enable/disable ancillary features of PHC subsystem
 * @ptp: The PTP clock structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int
ice_ptp_feature_ena(struct ptp_clock_info *ptp, struct ptp_clock_request *rq,
		    int on)
{
	struct ice_vsi *vsi = container_of(ptp, struct ice_vsi, ptp_caps);
	struct ice_pf *pf = vsi->back;
	u64 period_ns, start_time;
	unsigned int chan;
	u32 gpio_pin;
	int ret;

	switch (rq->type) {
	case PTP_CLK_REQ_PPS:
		chan = PPS_CLK_GEN_CHAN;
		gpio_pin = PPS_PIN_INDEX;
		period_ns = NSEC_PER_SEC;
		/* Allow time for programming before start_time is hit */
		start_time = ice_ptp_read_master_clk_reg(pf) + START_OFFS_NS;

		/* Round up to nearest second boundary */
		start_time = roundup(start_time, NSEC_PER_SEC);

		/* Subtract propagation delay */
		start_time -= pps_out_prop_delay_ns[vsi->time_ref_freq];

		break;
	case PTP_CLK_REQ_PEROUT:
		/* For PPS, we generate the 1Hz clock on dedicated pin PPS_OUT
		 * using TGT_3 and CLK_OUT_3 register combination
		 */
		chan = rq->perout.index;
		gpio_pin = chan;
		period_ns = (((s64)rq->perout.period.sec * NSEC_PER_SEC) +
			     rq->perout.period.nsec);
		start_time = (((s64)rq->perout.start.sec * NSEC_PER_SEC) +
			      rq->perout.start.nsec);
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = ice_ptp_cfg_periodic_clkout(pf, !!on, chan, gpio_pin, period_ns,
					  start_time);

	if (ret)
		return ret;

	if (rq->type == PTP_CLK_REQ_PPS)
		pf->ptp_one_pps_out_ena = !!on;

	return 0;
}

#ifdef HAVE_PTP_CROSSTIMESTAMP
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
		ice_ena_timestamp(pf, TX, false);
		break;
	case HWTSTAMP_TX_ON:
		ice_ena_timestamp(pf, TX, true);
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		ice_ena_timestamp(pf, RX, false);
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
		config->rx_filter = HWTSTAMP_FILTER_ALL;
		ice_ena_timestamp(pf, RX, true);
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
	struct ice_vsi *vsi;
	struct hwtstamp_config *config;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return -EOPNOTSUPP;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EFAULT;

	config = &vsi->tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ? -EFAULT :
								      0;
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
	struct ice_vsi *vsi;
	int err;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return -EOPNOTSUPP;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EFAULT;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = ice_ptp_set_timestamp_mode(pf, &config);
	if (err)
		return err;

	/* Save these settings for future reference */
	vsi->tstamp_config = config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT :
								      0;
}

/**
 * ice_ptp_get_tx_hwtstamp_ver - Returns the Tx timestamp and valid bits
 * @pf: Board specific private structure
 * @tx_idx_req: Bitmap of timestamp indices to read
 * @quad: Quad to read
 * @ts: Timestamps read from PHY
 * @ts_read: Bitmap of successfully read timestamp indices
 * @ts_count: Count of timestamps read
 *
 * Read the value of the Tx timestamp from the registers and build a
 * bitmap of successfully read indices and count of the number successfully
 * read.
 *
 * There are 3 possible return values,
 * 0 = success
 *
 * -EIO = unable to read a register, this could be to a variety of issues but
 *  should be very rare.  Up to caller how to respond to this (retry, abandon,
 *  etc).  But once this situation occurs, stop reading as we cannot
 *  guarantee what state the PHY or Timestamp Unit is in.
 *
 * -EINVAL = (at least) one of the timestamps that was read did not have the
 *  TS_VALID bit set, and is probably zero.  Be aware that not all of the
 *  timestamps that were read (so the TS_READY bit for this timestamp was
 *  cleared but no valid TS was retrieved) are present.  Expect at least one
 *  ts_read index that should be 1 is zero.
 */
static int ice_ptp_get_tx_hwtstamp_ver(struct ice_pf *pf, u64 tx_idx_req,
				       u8 quad, u64 *ts, u64 *ts_read,
				       u8 *ts_count)
{
	struct device *dev = ice_pf_to_dev(pf);
	u32 ts_ns_low, ts_ns_high, val;
	enum ice_status status;
	struct ice_vsi *vsi;
	unsigned long i;
	int ret = 0;
	u16 offset;
	u64 ts_ns;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return ICE_ERR_PARAM;


	for_each_set_bit(i, (unsigned long *)&tx_idx_req, INDEX_PER_QUAD) {
		ts[i] = 0x0;
		*ts_read |= BIT(i);
		(*ts_count)++;

		offset = (u16)TS_L(Q_REG_TX_MEMORY_BANK_START, i);

		status = ice_phy_quad_reg_read(pf, quad, offset, &val);
		if (status) {
			dev_dbg(dev, "PTP Tx read failed %s\n",
				ice_stat_str(status));
			*ts_read &= ~BIT(i);
			(*ts_count)--;
			ret = -EIO;
			break;
		}

		ts_ns_low = val;

		/* Read the high timestamp next */
		offset = (u16)TS_H(Q_REG_TX_MEMORY_BANK_START, i);

		status = ice_phy_quad_reg_read(pf, quad, offset, &val);
		if (status) {
			dev_dbg(dev, "PTP Tx read failed %s\n",
				ice_stat_str(status));
			*ts_read &= ~BIT(i);
			(*ts_count)--;
			ret = -EIO;
			break;
		}

		ts_ns_high = val;

		ts_ns = (((u64)ts_ns_high) << 8) | (ts_ns_low & 0x000000FF);

		if (!(ts_ns & ICE_PTP_TS_VALID)) {
			dev_dbg(dev, "PTP tx invalid\n");
			ret = -EINVAL;
			continue;
		}

		ts_ns = ice_ptp_convert_40b_64b(pf->cached_systime, ts_ns, vsi);
		/* Each timestamp will be offset in the array of
		 * timestamps by the index's value.  So the timestamp
		 * from index n will be in ts[n] position.
		 */
		ts[i] = ts_ns;
	}
	return ret;
}


/**
 * ice_ptp_get_tx_hwtstamp_ready - Get the Tx timestamp ready bitmap
 * @pf: The PF private data structure
 * @quad: Quad to read (0-4)
 * @ts_ready: Bitmap where each bit set indicates that the corresponding
 *            timestamp register is ready to read
 *
 * Read the PHY timestamp ready registers for a particular bank.
 */
static void
ice_ptp_get_tx_hwtstamp_ready(struct ice_pf *pf, u8 quad, u64 *ts_ready)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	u64 bitmap;
	u32 val;

	status = ice_phy_quad_reg_read(pf, quad, Q_REG_TX_MEMORY_STATUS_U,
				       &val);
	if (status) {
		dev_dbg(dev, "TX_MEMORY_STATUS_U read failed for quad %u\n",
			quad);
		return;
	}

	bitmap = val;

	status = ice_phy_quad_reg_read(pf, quad, Q_REG_TX_MEMORY_STATUS_L,
				       &val);
	if (status) {
		dev_dbg(dev, "TX_MEMORY_STATUS_L read failed for quad %u\n",
			quad);
		return;
	}

	bitmap = (bitmap << 32) | val;

	*ts_ready = bitmap;

}

/**
 * ice_ptp_tx_hwtstamp_vsi - Return the Tx timestamp for a specified VSI
 * @vsi: lport corresponding VSI
 * @quad: lport corresponding QUAD
 * @idx: Index of timestamp read from QUAD memory
 * @hwtstamp: Timestamps read from PHY
 *
 * Helper function for ice_ptp_tx_hwtstamp.
 */
static void ice_ptp_tx_hwtstamp_vsi(struct ice_vsi *vsi, u8 quad, int idx, u64 hwtstamp)
{
	struct skb_shared_hwtstamps shhwtstamps;
	struct sk_buff *skb;

	skb = vsi->ptp_tx_skb[idx];
	if (!skb)
		return;

	ice_ptp_convert_to_hwtstamp(&shhwtstamps, hwtstamp);

	vsi->ptp_tx_skb[idx] = NULL;

	/* Notify the stack and free the skb after we've unlocked */
	skb_tstamp_tx(skb, &shhwtstamps);
	dev_kfree_skb_any(skb);
	clear_bit(idx, vsi->ptp_tx_idx);
}

/**
 * ice_ptp_tx_hwtstamp - Return the Tx timestamps
 * @pf: Board private structure
 *
 * Read the tx_memory_status registers of the PHY timestamp module to determine which memory entries
 * contain ready timestamps, and then read out the timestamps from those locations. While we are
 * reading out the timestamps, new timestamps may be captured. No new interrupt will be generated
 * until the intr_threshold is crossed again, so read the status registers in a loop until no more
 * timestamps are ready.
 * Convert read timestamps into a value consumable by the stack, and store that result into the
 * shhwtstamps struct before returning it up the stack.
 */
static void ice_ptp_tx_hwtstamp(struct ice_pf *pf)
{
	u8 quad;

	for (quad = 0; quad < ICE_MAX_QUAD; quad++) {
		while (true) {
			u64 ready_map = 0, valid_map = 0;
			u64 hwtstamps[INDEX_PER_QUAD];
			int i, ret, vsi_idx;
			u8 ts_count;

			ice_ptp_get_tx_hwtstamp_ready(pf, quad, &ready_map);
			if (!ready_map)
				break;

			ret = ice_ptp_get_tx_hwtstamp_ver(pf, ready_map, quad, hwtstamps,
							  &valid_map, &ts_count);
			if (ret == -EIO)
				break;

			for_each_set_bit(i, (unsigned long *)&valid_map, INDEX_PER_QUAD) {
				ice_for_each_vsi(pf, vsi_idx) {
					struct ice_vsi *vsi = pf->vsi[vsi_idx];

					if (!vsi ||
					    vsi->type != ICE_VSI_PF ||
					    (vsi->port_info->lport / ICE_PORTS_PER_QUAD != quad))
						continue;

					if (test_bit(i, vsi->ptp_tx_idx))
						ice_ptp_tx_hwtstamp_vsi(vsi, quad, i, hwtstamps[i]);
				}
			}
		}
	}
}

/**
 * ice_ptp_tx_hwtstamp_ext - Return the Tx timestamp
 * @pf: Board private structure
 *
 * Read the value of the Tx timestamp from the registers, convert it into
 * a value consumable by the stack, and store that result into the shhwtstamps
 * struct before returning it up the stack.
 */
static void ice_ptp_tx_hwtstamp_ext(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi *vsi;
	u32 addr, val;
	u8 lport;
	int idx;

	vsi = ice_get_main_vsi(pf);
	if (!vsi || !vsi->ptp_tx)
		return;
	lport = hw->port_info->lport;

	/* Don't attempt to timestamp if we don't have an skb */
	for (idx = 0; idx < INDEX_PER_QUAD; idx++) {
		struct skb_shared_hwtstamps shhwtstamps;
		u32 ts_ns_low, ts_ns_high;
		enum ice_status status;
		struct sk_buff *skb;
		u64 ts_ns;

		skb = vsi->ptp_tx_skb[idx];
		if (!skb)
			continue;

		addr = TS_EXT(LOW_TX_MEMORY_BANK_START, lport, idx);

		status = ice_phy_quad_reg_read_ext(pf, addr, &val);
		if (status)
			continue;

		ts_ns_low = val;

		/* Read the high timestamp next */
		addr = TS_EXT(HIGH_TX_MEMORY_BANK_START, lport, idx);

		status = ice_phy_quad_reg_read_ext(pf, addr, &val);
		if (status) {
			if (!ts_ns_low)
				continue;
			dev_err(ice_pf_to_dev(pf), "PTP tx rd failed %s\n",
				ice_stat_str(status));
			vsi->ptp_tx_skb[idx] = NULL;
			dev_kfree_skb_any(skb);
			clear_bit(idx, vsi->ptp_tx_idx);
			continue;
		}

		ts_ns_high = val;
		ts_ns = (((u64)ts_ns_high) << 32) | (u64)ts_ns_low;

		ts_ns = ice_ptp_convert_40b_64b(pf->cached_systime, ts_ns, vsi);
		ice_ptp_convert_to_hwtstamp(&shhwtstamps, ts_ns);

		vsi->ptp_tx_skb[idx] = NULL;

		/* Notify the stack and free the skb after
		 * we've unlocked
		 */
		skb_tstamp_tx(skb, &shhwtstamps);
		dev_kfree_skb_any(skb);
		clear_bit(idx, vsi->ptp_tx_idx);
	}
}

/**
 * ice_ptp_rx_hwtstamp - Check for an Rx timestamp
 * @rx_ring: Ring to get the VSI info
 * @skb: Particular skb to send timestamp with
 * @rx_desc: Receive descriptor
 *
 * The driver receives a notification in the receive descriptor with timestamp.
 * The timestamp is in ns, so we must convert the result first.
 */
void
ice_ptp_rx_hwtstamp(struct ice_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc,
		    struct sk_buff __maybe_unused *skb)
{
	u32 ts_high, ts_low;
	u8 ts_avail;
	u64 ts_ns;

	/* Populate timesync data into skb */
	ts_avail = rx_desc->wb.time_stamp_low & ICE_PTP_TS_VALID;
	if (ts_avail) {
		ts_high = le32_to_cpu(rx_desc->wb.flex_ts.ts_high);
		ts_low = rx_desc->wb.time_stamp_low & (~ICE_PTP_TS_VALID);
		ts_ns = (((u64)ts_high) << 8) | (ts_low & 0x000000FF);

		ts_ns = ice_ptp_convert_40b_64b(rx_ring->cached_systime, ts_ns,
						rx_ring->vsi);
		ice_ptp_convert_to_hwtstamp(skb_hwtstamps(skb), ts_ns);
	}
}

/**
 * ice_ptp_set_caps - Set PTP capabilities
 * @vsi: VSI to set PTP capabilities for
 */
static void ice_ptp_set_caps(struct ice_vsi *vsi)
{
	struct ptp_clock_info *ptp_caps = &vsi->ptp_caps;
	struct device *dev = ice_pf_to_dev(vsi->back);

	snprintf(ptp_caps->name, sizeof(ptp_caps->name) - 1, "%s-%s-clk",
		 dev_driver_string(dev), dev_name(dev));
	ptp_caps->owner = THIS_MODULE;
	ptp_caps->max_adj = 999999999;
	ptp_caps->n_ext_ts = 0;
	/* HW has a PPS out */
	ptp_caps->pps = 1;
	/* HW has 2 programmable periodic outs */
	ptp_caps->n_per_out = 2;
	ptp_caps->adjfreq = ice_ptp_adjfreq;
	ptp_caps->adjtime = ice_ptp_adjtime;
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
	ptp_caps->gettime64 = ice_ptp_gettime;
	ptp_caps->settime64 = ice_ptp_settime;
#else
	ptp_caps->gettime = ice_ptp_gettime32;
	ptp_caps->settime = ice_ptp_settime32;
#endif /* HAVE_PTP_CLOCK_INFO_GETTIME64 */
	ptp_caps->enable = ice_ptp_feature_ena;
#ifdef HAVE_PTP_CROSSTIMESTAMP
#endif /* HAVE_PTP_CROSSTIMESTAMP */
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
	struct ice_vsi *vsi = ice_get_main_vsi(pf);

	if (!vsi || !vsi->netdev)
		return -EINVAL;

	/* No need to create a clock device if we already have one */
	if (!IS_ERR_OR_NULL(vsi->ptp_clock))
		return 0;

	ice_ptp_set_caps(vsi);

	/* Attempt to register the clock before enabling the hardware. */
	vsi->ptp_clock = ptp_clock_register(&vsi->ptp_caps, ice_pf_to_dev(pf));
	if (IS_ERR(vsi->ptp_clock))
		return PTR_ERR(vsi->ptp_clock);

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);
	return 0;
}

/**
 * ice_ptp_init - Initialize the PTP support after device probe or reset
 * @pf: Board private structure
 *
 * This function sets device up for PTP support. The first time it is run, it
 * will create a clock device. It does not create a clock device if one
 * already exists. It also reconfigures the device after a reset.
 */
void ice_ptp_init(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct timespec64 ts;
	struct ice_vsi *vsi;
	u32 regval;

	status = 0;
	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		status = ICE_ERR_NOT_IMPL;
		goto err_exit;
	}

	/* Check if this PF owns the master timer */
	if (hw->func_caps.ts_func_info.master_tmr_owned) {
		int itr = 1;
		long err;

		/* 1 PPS output will have been disabled by device reset */
		pf->ptp_one_pps_out_ena = false;

		if (!ice_is_generic_mac(hw))
			wr32(hw, GLTSYN_SYNC_DLAY, 0);

		/* Clear some HW residue and enable master clock */
		master_idx = hw->func_caps.ts_func_info.tmr_index_owned;

		/* Enable master clocks */
		wr32(hw, GLTSYN_ENA(master_idx), GLTSYN_ENA_TSYN_ENA_M);
		if (!ice_is_generic_mac(hw)) {
			/* Enable PHY time sync */
			status = ice_ptp_ena_phy_time_syn_ext(pf);

			if (status)
				goto err_exit;
		}
		regval = rd32(hw, GLTSYN_STAT(master_idx));

		/* Do not touch the reserved bits and set other bits
		 * to zero
		 */
		regval &= 0xFFFFFF08;
		wr32(hw, GLTSYN_STAT(master_idx), regval);

		regval = rd32(hw, GLINT_TSYN_PHY);
		/* Do not touch the reserved bits and set other bits
		 * to zero
		 */
		regval &= 0xFFFFFFE0;
		wr32(hw, GLINT_TSYN_PHY, regval);
#define PF_SB_REM_DEV_CTL_PHY0	BIT(2)
		if (ice_is_generic_mac(hw)) {
			regval = rd32(hw, PF_SB_REM_DEV_CTL);
			regval |= PF_SB_REM_DEV_CTL_PHY0;
			wr32(hw, PF_SB_REM_DEV_CTL, regval);
		}
		/* Write the increment time value to PHY and LAN */
		status = ice_ptp_set_increment(pf, 0);
		if (status)
			goto err_exit;
		/* Acquire the global hardware lock */
		if (!ice_ptp_lock(pf)) {
			status = ICE_ERR_IN_USE;
			goto err_exit;
		}

		ts = ktime_to_timespec64(ktime_get_real());
		/* Write the initial Time value to PHY and LAN */
		status = ice_ptp_write_init(pf, &ts);
		if (status) {
			ice_ptp_unlock(pf);
			goto err_exit;
		}
		/* Request HW to load the above shadow reg to the real timers */
		status = ice_ptp_tmr_cmd(pf, INIT_TIME);
		if (status) {
			ice_ptp_unlock(pf);
			goto err_exit;
		}
		/* Release the global hardware lock */
		ice_ptp_unlock(pf);
		if (ice_is_generic_mac(hw)) {
			/* Set window length for all the ports */
			status = ice_ptp_set_wl(pf);
			if (status)
				goto err_exit;
			/* Enable quad interrupts */
			status = ice_ptp_tx_ena_intr(pf, true, itr);
			if (status)
				goto err_exit;
		}
		/* Ensure we have a clock device */
		err = ice_ptp_create_clock(pf);
		if (err) {
			status = ICE_ERR_NOT_IMPL;
			goto err_clk;
		}
		/* Store the PTP clock index for other PFs */
		ice_set_ptp_clock_index(pf);
	}

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);

	mutex_init(&pf->ptp_ps_lock);
	pf->ptp_link_up = false;

	set_bit(ICE_FLAG_PTP, pf->flags);
	dev_info(dev, "PTP init successful\n");

	if (hw->func_caps.ts_func_info.master_tmr_owned && ice_is_generic_mac(hw))
		ice_cgu_init_state(pf);
	return;

err_clk:
	vsi->ptp_clock = NULL;
err_exit:
	dev_err(dev, "PTP failed %s\n", ice_stat_str(status));
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

	vsi = ice_get_main_vsi(pf);
	if (!vsi || !test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	/* Disable timestamping for both Tx and Rx */
	ice_ptp_cfg_timestamp(pf, false);
	/* Clear PHY bank residues if any */
	if (ice_is_generic_mac(&pf->hw))
		ice_ptp_tx_hwtstamp(pf);
	else
		ice_ptp_tx_hwtstamp_ext(pf);
	/* Release any pending skb */
	ice_ptp_rel_all_skb(pf);

	clear_bit(ICE_FLAG_PTP, pf->flags);

	if (vsi->ptp_clock) {
		char *dev_name = vsi->netdev->name;

		ice_clear_ptp_clock_index(pf);
		ptp_clock_unregister(vsi->ptp_clock);
		vsi->ptp_clock = NULL;
		master_idx = MASTER_IDX_INVALID;
		dev_info(ice_pf_to_dev(pf), "removed Clock from %s\n",
			 dev_name);
	}
}


/**
 * ice_clean_ptp_subtask - Handle the service task events
 * @pf: Board private structure
 */
void ice_clean_ptp_subtask(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	if (!test_bit(ICE_FLAG_PTP, pf->flags))
		return;

	ice_ptp_update_cached_systime(pf);
	if (test_and_clear_bit(ICE_PTP_TX_TS_READY, pf->state)) {
		if (ice_is_generic_mac(hw))
			ice_ptp_tx_hwtstamp(pf);
		else
			ice_ptp_tx_hwtstamp_ext(pf);
	}
}
