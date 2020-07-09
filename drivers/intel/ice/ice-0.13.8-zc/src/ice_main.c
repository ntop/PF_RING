// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

/* Intel(R) Ethernet Connection E800 Series Linux Driver */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_dcb_lib.h"
#include "ice_dcb_nl.h"

#ifdef HAVE_PF_RING
#include "ice_txrx_lib.h"
#include "pf_ring.h"

int RSS[ICE_MAX_NIC] = 
  { [0 ... (ICE_MAX_NIC - 1)] = 0 };
module_param_array_named(RSS, RSS, int, NULL, 0444);
MODULE_PARM_DESC(RSS,
                 "Number of Receive-Side Scaling Descriptor Queues, default 0=number of cpus");

int enable_debug = 0;
module_param(enable_debug, int, 0644);
MODULE_PARM_DESC(debug, "PF_RING debug (0=none, 1=enabled)");
#endif

#define DRV_VERSION_MAJOR 0
#define DRV_VERSION_MINOR 13
#define DRV_VERSION_BUILD 8

#define DRV_VERSION	"0.13.8"
#define DRV_SUMMARY	"Intel(R) Ethernet Connection E800 Series Linux Driver"
const char ice_drv_ver[] = DRV_VERSION;
static const char ice_driver_string[] = DRV_SUMMARY;
static const char ice_copyright[] = "Copyright (C) 2018-2019, Intel Corporation.";

/* DDP Package file located in firmware search paths (e.g. /lib/firmware/) */
#define ICE_DDP_PKG_PATH	"updates/intel/ice/ddp/"
#define ICE_DDP_PKG_FILE	ICE_DDP_PKG_PATH "ice.pkg"

MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_FIRMWARE(ICE_DDP_PKG_FILE);

static int debug = -1;
module_param(debug, int, 0644);
#ifndef CONFIG_DYNAMIC_DEBUG
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all), hw debug_mask (0x8XXXXXXX)");
#else
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");
#endif /* !CONFIG_DYNAMIC_DEBUG */



static struct workqueue_struct *ice_wq;
static const struct net_device_ops ice_netdev_recovery_ops;
static const struct net_device_ops ice_netdev_safe_mode_ops;
static const struct net_device_ops ice_netdev_ops;
static void ice_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type);

static void ice_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type);
static void ice_vsi_release_all(struct ice_pf *pf);

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static int ice_rebuild_channels(struct ice_pf *pf);
static void ice_remove_q_channels(struct ice_vsi *vsi, bool rem_adv_fltr);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */


#ifdef HAVE_NETDEV_SB_DEV
bool netif_is_ice(struct net_device *dev)
{
	return dev && (dev->netdev_ops == &ice_netdev_ops);
}

static void ice_deinit_macvlan(struct ice_vsi *vsi);
#endif /* HAVE_NETDEV_SB_DEV */

#ifdef HAVE_TC_INDIR_BLOCK
static int ice_netdevice_event(struct notifier_block *nb, unsigned long event,
			       void *ptr);
static void ice_indr_clean_block_privs(struct ice_netdev_priv *np);
#endif /* HAVE_TC_INDIR_BLOCK */
#ifdef ADQ_PERF
/**
 * ice_chnl_subtask_handle_interrupt - if needed, trigger SW interrupt on
 * channel enabled vector
 * @pf: pointer to PF struct
 *
 * This function process all channel enabled vectors and based on jiffy
 * and delta between jiffies, decides and triggers software initiated
 * interrupt on each of such vectors. Logic used:
 * if on given vector jiffies delta is greated than 1 second and old
 * snapshot of jiffies is valid, then trigger software interrupt.
 * Jiffies snapshot is stored/updated in vector whenever vector
 * is serviced through busy-poll.
 */
static void ice_chnl_subtask_handle_interrupt(struct ice_pf *pf)
{
	struct ice_vsi *vsi;
	unsigned long end;
	unsigned int i;

	vsi = ice_get_main_vsi(pf);
	if (!vsi || test_bit(__ICE_DOWN, vsi->state))
		return;

	if (!(vsi->netdev && netif_carrier_ok(vsi->netdev)))
		return;

	for (i = 0; i < vsi->num_txq; i++) {
		struct ice_ring *tx_ring = vsi->tx_rings[i];
		struct ice_ring *rx_ring = vsi->rx_rings[i];
		struct ice_q_vector *q_vector;

		if (!(tx_ring && tx_ring->desc && rx_ring))
			continue;
		q_vector = tx_ring->q_vector;
		if (!q_vector || !ice_vector_ch_enabled(q_vector))
			continue;

		end = tx_ring->q_vector->jiffies;
		if (!end)
			continue;

		/* trigger software interrupt (to revive queue processing) if
		 * vector is channel enabled and only if current jiffies is at
		 * least 1 sec (worth of jiffies, hence multiplying by HZ) more
		 * than old_jiffies
		 */
#define ICE_JIFFY_DELTA_IN_SEC	(1 * HZ)
		end += ICE_JIFFY_DELTA_IN_SEC;
		if (time_is_before_jiffies(end) &&
		    (q_vector->state_flags & ICE_CHNL_ONCE_IN_BP)) {
#ifdef ADQ_PERF_COUNTERS
			ice_sw_intr_cntr(q_vector, false);
#endif /* ADQ_PERF_COUNTERS */
			ice_adq_trigger_sw_intr(&pf->hw, q_vector);
		}
	}
}
#endif /* ADQ_PERF */

#ifdef ADQ_PERF
/**
 * ice_flush_vsi_fd_fltrs - flush VSI specific FD entries
 * @vsi: ptr to VSI
 *
 * This function flushes all FD entries specific to VSI from
 * HW FD table
 */
static inline void ice_flush_vsi_fd_fltrs(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	enum ice_status status;

	status = ice_clear_vsi_fd_table(&vsi->back->hw, vsi->vsi_num);
	if (status)
		dev_err(dev, "Failed to clear FD table for %s, vsi_num: %u, status: %d\n",
			ice_vsi_type_str(vsi->type), vsi->vsi_num, status);
}

/**
 * ice_chnl_handle_fd_transition - handle VSI specific FD transition
 * @main_vsi: ptr to main VSI (ICE_VSI_PF)
 * @ch: ptr to channel
 * @hw_fd_cnt: HW FD count specific to VSI
 * @fd_pkt_cnt: packets services thru' inline-FD filter
 * @sw_fd_cnt: SW tracking, number of inline-FD filtere were programmed per VSI
 *
 * This function determines whether given VSI should continue to use inline-FD
 * resources or not and sets bits accordingly. It also flushes the FD entries
 * occupied per VSI if detected table full condition 'n' times and no more
 * packets serviced thru' inline-FD filter
 */
static void
ice_chnl_handle_fd_transition(struct ice_vsi *main_vsi, struct ice_channel *ch,
			      u32 hw_fd_cnt, u64 fd_pkt_cnt, int sw_fd_cnt)
{
	struct ice_vsi *vsi;

	if (!ch || !main_vsi)
		return;

	vsi = ch->ch_vsi;
	if (!vsi)
		return;

	/* did we reach table full condition and no activity w.r.t
	 * inline-FD filter being hit in HW table during last 'n' runs of
	 * service task, then it is safe to "drop HW table entries"
	 */
	/* check to see if given VSI reached max limit of FD entries */
	if (ice_is_vsi_fd_table_full(vsi, hw_fd_cnt)) {
		/* check to see if there are any hits using inline-FD filters,
		 * if not start "table_full" counter
		 */
		if (!ch->fd_pkt_cnt && !fd_pkt_cnt &&
		    ch->fd_pkt_cnt == fd_pkt_cnt) {
			/* HW table is FULL: and no more packets being serviced
			 * thru' inline-FD filters (by looking at the current
			 * and prev packets services).
			 * Logic to see if that current and prev packet count
			 * is changing or not, if not changing means,
			 * it is safe to assume that even though there are
			 * inline-FD filters exist in HW table, but flows
			 * associated with those filters are ended via.
			 * RST code path
			 */
			vsi->cnt_tbl_full++;
			main_vsi->cnt_tbl_full++;
		} else {
			vsi->cnt_tbl_full = 0;
		}

		/* detected that HW table remained full during
		 * last 'n' times, now it is the time to purge
		 * HW table entries.
		 * detected that HW FD table full condition
		 * based on SW counter based hueristics,
		 * give around 4 second to be in same condition
		 * otherwise proceed with purging HW table
		 * entries
		 */
		if (vsi->cnt_tbl_full < ICE_TBL_FULL_TIMES)
			return;

		/* if we are here, then safe to flush HW inline-FD filters */
		ice_flush_vsi_fd_fltrs(vsi);
		/* stats to keep track, how many times HW table is flushed */
		vsi->cnt_table_flushed++;
		main_vsi->cnt_table_flushed++;

		/* reset VSI specific counters */
		atomic_set(&vsi->inline_fd_active_cnt, 0);
		vsi->cnt_tbl_full = 0;
		/* clear the feature flag for inline-FD/RSS */
		clear_bit(ICE_SWITCH_TO_RSS, vsi->adv_state);
	} else if (sw_fd_cnt > hw_fd_cnt) {
		/* HW table (inline-FD filters) is not full and SW count is
		 * higher than actual entries in HW table, time to sync SW
		 * counter with HW counter (tracking inline-FD filter count)
		 * and transition back to using inline-FD filters
		 */
		atomic_set(&vsi->inline_fd_active_cnt, hw_fd_cnt);
		vsi->cnt_tbl_full = 0;
		/* stats to keep track, how many times transitioned into
		 * inline-FD from RSS
		 */
		vsi->cnt_inline_fd_transition++;
		main_vsi->cnt_inline_fd_transition++;
		/* clear the feature flag for inline-FD/RSS */
		clear_bit(ICE_SWITCH_TO_RSS, vsi->adv_state);
	} else {
		net_warn_ratelimited("Service_task, Nothing to be done:sw_cnt:%d, hw_fd_cnt:%u, fd_pkt_cnt: %llu\n",
				     sw_fd_cnt, hw_fd_cnt, fd_pkt_cnt);
	}
}

/**
 * ice_channel_sync_global_cntrs - sync SW and HW FD specific counters
 * @pf: ptr to PF
 *
 * This function iterates thru' all channel VSIs and handles transition of
 * FD (Flow-director) -> RSS and vice versa, if needed also flushes VSI
 * specific FD entries from HW table
 */
static void ice_channel_sync_global_cntrs(struct ice_pf *pf)
{
	struct ice_vsi *main_vsi;
	struct ice_channel *ch;

	main_vsi = ice_get_main_vsi(pf);
	if (!main_vsi)
		return;

	list_for_each_entry(ch, &main_vsi->ch_list, list) {
		struct ice_vsi *ch_vsi;
		u64 fd_pkt_cnt;
		int sw_fd_cnt;
		u32 hw_fd_cnt;

		ch_vsi = ch->ch_vsi;
		if (!ch_vsi)
			continue;
		if (!ice_vsi_fd_ena(ch_vsi))
			continue;
		/* bailout if SWITCH_TO_RSS is not set */
		if (!test_bit(ICE_SWITCH_TO_RSS, ch_vsi->adv_state))
			continue;
		/* first counter index is always taken by sideband flow
		 * director, hence channel specific counter index has
		 * to be non-zero, otherwise skip...
		 */
		if (!ch->fd_cnt_index)
			continue;

		/* read SW count */
		sw_fd_cnt = atomic_read(&ch_vsi->inline_fd_active_cnt);
		/* Read HW count */
		hw_fd_cnt = ice_get_current_fd_cnt(ch_vsi);
		/* Read the HW counter which was associated with inline-FD */
		fd_pkt_cnt = ice_read_cntr(pf, ch->fd_cnt_index);

		/* handle VSI specific transition: inline-FD/RSS
		 * if needed flush FD entries specific to VSI
		 */
		ice_chnl_handle_fd_transition(main_vsi, ch, hw_fd_cnt,
					      fd_pkt_cnt, sw_fd_cnt);
		/* store the value of fd_pkt_cnt per channel */
		ch->fd_pkt_cnt = fd_pkt_cnt;
	}
}
#endif /* ADQ_PERF */

/**
 * ice_get_tx_pending - returns number of Tx descriptors not processed
 * @ring: the ring of descriptors
 */
static u16 ice_get_tx_pending(struct ice_ring *ring)
{
	u16 head, tail;

	head = ring->next_to_clean;
	tail = ring->next_to_use;

	if (head != tail)
		return (head < tail) ?
			tail - head : (tail + ring->count - head);
	return 0;
}

/**
 * ice_check_for_hang_subtask - check for and recover hung queues
 * @pf: pointer to PF struct
 */
static void ice_check_for_hang_subtask(struct ice_pf *pf)
{
	struct ice_vsi *vsi = NULL;
	struct ice_hw *hw;
	unsigned int i;
	int packets;
	u32 v;

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v] && pf->vsi[v]->type == ICE_VSI_PF) {
			vsi = pf->vsi[v];
			break;
		}

	if (!vsi || test_bit(__ICE_DOWN, vsi->state))
		return;

	if (!(vsi->netdev && netif_carrier_ok(vsi->netdev)))
		return;

	hw = &vsi->back->hw;

	for (i = 0; i < vsi->num_txq; i++) {
		struct ice_ring *tx_ring = vsi->tx_rings[i];

		if (!tx_ring)
			continue;
#ifdef ADQ_PERF
		if (ice_vector_ch_enabled(tx_ring->q_vector))
			continue;
#endif /* ADQ_PERF */

		if (tx_ring->desc) {
			/* If packet counter has not changed the queue is
			 * likely stalled, so force an interrupt for this
			 * queue.
			 *
			 * prev_pkt would be negative if there was no
			 * pending work.
			 */
			packets = tx_ring->stats.pkts & INT_MAX;
			if (tx_ring->tx_stats.prev_pkt == packets) {
				/* Trigger sw interrupt to revive the queue */
				ice_trigger_sw_intr(hw, tx_ring->q_vector);
				continue;
			}

			/* Memory barrier between read of packet count and call
			 * to ice_get_tx_pending()
			 */
			smp_rmb();
			tx_ring->tx_stats.prev_pkt =
			    ice_get_tx_pending(tx_ring) ? packets : -1;
		}
	}
}

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_add_mac_vlan_to_list - Add a MAC/VLAN filter entry to the list
 * @pf: board private structure
 * @vsi: the VSI to be forwarded to
 * @add_list: pointer to the list which contains MAC/VLAN filter entries
 * @macaddr: the MAC address to be added.
 * @vlan_id: VLAN that needs to be added.
 * @action: filter action to be performed on match
 *
 * Adds MAC/VLAN filter entry to the temp list
 *
 * Returns 0 on success or ENOMEM/EINVAL on failure.
 */
static int
ice_add_mac_vlan_to_list(struct ice_pf *pf, struct ice_vsi *vsi,
			 struct list_head *add_list, const u8 *macaddr,
			 u16 vlan_id, enum ice_sw_fwd_act_type action)
{
	struct ice_fltr_list_entry *tmp;

	if (!vsi || !is_valid_ether_addr(macaddr) || vlan_id <= 0)
		return -EINVAL;

	if (is_broadcast_ether_addr(macaddr))
		return -EINVAL;
	tmp = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*tmp), GFP_ATOMIC);
	if (!tmp)
		return -ENOMEM;

	tmp->fltr_info.lkup_type = ICE_SW_LKUP_MAC_VLAN;
	tmp->fltr_info.fltr_act = action;
	tmp->fltr_info.flag |= ICE_FLTR_TX_RX;
	tmp->fltr_info.vsi_handle = vsi->idx;
	tmp->fltr_info.src = vsi->vsi_num;
	ether_addr_copy(tmp->fltr_info.l_data.mac_vlan.mac_addr, macaddr);
	tmp->fltr_info.l_data.mac_vlan.vlan_id = vlan_id;

	INIT_LIST_HEAD(&tmp->list_entry);
	list_add(&tmp->list_entry, add_list);

	return 0;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_init_mac_fltr - Set initial MAC filters
 * @pf: board private structure
 *
 * Set initial set of MAC filters for PF VSI; configure filters for permanent
 * address and broadcast address. If an error is encountered, netdevice will be
 * unregistered.
 */
static int ice_init_mac_fltr(struct ice_pf *pf)
{
	enum ice_status status;
	u8 broadcast[ETH_ALEN];
	struct ice_vsi *vsi;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EINVAL;

	/* To add a MAC filter, first add the MAC to a list and then
	 * pass the list to ice_add_mac.
	 */

	 /* Add a unicast MAC filter so the VSI can get its packets */
	status = ice_vsi_cfg_mac_fltr(vsi, vsi->port_info->mac.perm_addr, true);
	if (status)
		goto unregister;

	/* VSI needs to receive broadcast traffic, so add the broadcast
	 * MAC address to the list as well.
	 */
	eth_broadcast_addr(broadcast);
	status = ice_vsi_cfg_mac_fltr(vsi, broadcast, true);
	if (status)
		goto unregister;

	return 0;
unregister:
	/* We aren't useful with no MAC filters, so unregister if we
	 * had an error
	 */
	if (status && vsi->netdev->reg_state == NETREG_REGISTERED) {
		dev_err(ice_pf_to_dev(pf), "Could not add MAC filters error %d. Unregistering device\n",
			status);
		unregister_netdev(vsi->netdev);
		free_netdev(vsi->netdev);
		vsi->netdev = NULL;
	}

	return -EIO;
}

/**
 * ice_add_mac_to_sync_list - creates list of MAC addresses to be synced
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 *
 * This is a callback function which is called by the in kernel device sync
 * functions (like __dev_uc_sync, __dev_mc_sync, etc). This function only
 * populates the tmp_sync_list, which is later used by ice_add_mac to add the
 * MAC filters from the hardware.
 */
static int ice_add_mac_to_sync_list(struct net_device *netdev, const u8 *addr)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;

	if (ice_add_mac_to_list(vsi, &vsi->tmp_sync_list, addr, ICE_FWD_TO_VSI))
		return -EINVAL;

	return 0;
}

/**
 * ice_add_mac_to_unsync_list - creates list of MAC addresses to be unsynced
 * @netdev: the net device on which the unsync is happening
 * @addr: MAC address to unsync
 *
 * This is a callback function which is called by the in kernel device unsync
 * functions (like __dev_uc_unsync, __dev_mc_unsync, etc). This function only
 * populates the tmp_unsync_list, which is later used by ice_remove_mac to
 * delete the MAC filters from the hardware.
 */
static int ice_add_mac_to_unsync_list(struct net_device *netdev, const u8 *addr)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;

	if (ice_add_mac_to_list(vsi, &vsi->tmp_unsync_list, addr,
				ICE_FWD_TO_VSI))
		return -EINVAL;

	return 0;
}

/**
 * ice_vsi_fltr_changed - check if filter state changed
 * @vsi: VSI to be checked
 *
 * returns true if filter state has changed, false otherwise.
 */
static bool ice_vsi_fltr_changed(struct ice_vsi *vsi)
{
	return test_bit(ICE_VSI_FLAG_UMAC_FLTR_CHANGED, vsi->flags) ||
	       test_bit(ICE_VSI_FLAG_MMAC_FLTR_CHANGED, vsi->flags) ||
	       test_bit(ICE_VSI_FLAG_VLAN_FLTR_CHANGED, vsi->flags);
}

/**
 * ice_cfg_promisc - Enable or disable promiscuous mode for a given PF
 * @vsi: the VSI being configured
 * @promisc_m: mask of promiscuous config bits
 * @set_promisc: enable or disable promisc flag request
 *
 */
static int ice_cfg_promisc(struct ice_vsi *vsi, u8 promisc_m, bool set_promisc)
{
	struct ice_hw *hw = &vsi->back->hw;
	enum ice_status status = 0;

	if (vsi->type != ICE_VSI_PF)
		return 0;

	if (vsi->vlan_ena) {
		status = ice_set_vlan_vsi_promisc(hw, vsi->idx, promisc_m,
						  set_promisc);
	} else {
		if (set_promisc)
			status = ice_set_vsi_promisc(hw, vsi->idx, promisc_m,
						     0);
		else
			status = ice_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						       0);
	}

	if (status)
		return -EIO;

	return 0;
}


/**
 * ice_vsi_sync_fltr - Update the VSI filter list to the HW
 * @vsi: ptr to the VSI
 *
 * Push any outstanding VSI filter changes through the AdminQ.
 */
static int ice_vsi_sync_fltr(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct net_device *netdev = vsi->netdev;
	bool promisc_forced_on = false;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status = 0;
	u32 changed_flags = 0;
	u8 promisc_m;
	int err = 0;

	if (!vsi->netdev)
		return -EINVAL;

	while (test_and_set_bit(__ICE_CFG_BUSY, vsi->state))
		usleep_range(1000, 2000);

	changed_flags = vsi->current_netdev_flags ^ vsi->netdev->flags;
	vsi->current_netdev_flags = vsi->netdev->flags;

	INIT_LIST_HEAD(&vsi->tmp_sync_list);
	INIT_LIST_HEAD(&vsi->tmp_unsync_list);

	if (ice_vsi_fltr_changed(vsi)) {
		clear_bit(ICE_VSI_FLAG_UMAC_FLTR_CHANGED, vsi->flags);
		clear_bit(ICE_VSI_FLAG_MMAC_FLTR_CHANGED, vsi->flags);
		clear_bit(ICE_VSI_FLAG_VLAN_FLTR_CHANGED, vsi->flags);

		/* grab the netdev's addr_list_lock */
		netif_addr_lock_bh(netdev);
		__dev_uc_sync(netdev, ice_add_mac_to_sync_list,
			      ice_add_mac_to_unsync_list);
		__dev_mc_sync(netdev, ice_add_mac_to_sync_list,
			      ice_add_mac_to_unsync_list);
		/* our temp lists are populated. release lock */
		netif_addr_unlock_bh(netdev);
	}

	/* Remove MAC addresses in the unsync list */
	status = ice_remove_mac(hw, &vsi->tmp_unsync_list);
	ice_free_fltr_list(dev, &vsi->tmp_unsync_list);
	if (status) {
		netdev_err(netdev, "Failed to delete MAC filters\n");
		/* if we failed because of alloc failures, just bail */
		if (status == ICE_ERR_NO_MEMORY) {
			err = -ENOMEM;
			goto out;
		}
	}

	/* Add MAC addresses in the sync list */
	status = ice_add_mac(hw, &vsi->tmp_sync_list);
	ice_free_fltr_list(dev, &vsi->tmp_sync_list);
	/* If filter is added successfully or already exists, do not go into
	 * 'if' condition and report it as error. Instead continue processing
	 * rest of the function.
	 */
	if (status && status != ICE_ERR_ALREADY_EXISTS) {
		netdev_err(netdev, "Failed to add MAC filters\n");
		/* If there is no more space for new umac filters, VSI
		 * should go into promiscuous mode. There should be some
		 * space reserved for promiscuous filters.
		 */
		if (hw->adminq.sq_last_status == ICE_AQ_RC_ENOSPC &&
		    !test_and_set_bit(__ICE_FLTR_OVERFLOW_PROMISC,
				      vsi->state)) {
			promisc_forced_on = true;
			netdev_warn(netdev, "Reached MAC filter limit, forcing promisc mode on VSI %d\n",
				    vsi->vsi_num);
		} else {
			err = -EIO;
			goto out;
		}
	}
	/* check for changes in promiscuous modes */
	if (changed_flags & IFF_ALLMULTI) {
		if (vsi->current_netdev_flags & IFF_ALLMULTI) {
			if (vsi->vlan_ena)
				promisc_m = ICE_MCAST_VLAN_PROMISC_BITS;
			else
				promisc_m = ICE_MCAST_PROMISC_BITS;

			err = ice_cfg_promisc(vsi, promisc_m, true);
			if (err) {
				netdev_err(netdev, "Error setting Multicast promiscuous mode on VSI %i\n",
					   vsi->vsi_num);
				vsi->current_netdev_flags &= ~IFF_ALLMULTI;
				goto out_promisc;
			}
		} else if (!(vsi->current_netdev_flags & IFF_ALLMULTI)) {
			if (vsi->vlan_ena)
				promisc_m = ICE_MCAST_VLAN_PROMISC_BITS;
			else
				promisc_m = ICE_MCAST_PROMISC_BITS;

			err = ice_cfg_promisc(vsi, promisc_m, false);
			if (err) {
				netdev_err(netdev, "Error clearing Multicast promiscuous mode on VSI %i\n",
					   vsi->vsi_num);
				vsi->current_netdev_flags |= IFF_ALLMULTI;
				goto out_promisc;
			}
		}
	}

	if (((changed_flags & IFF_PROMISC) || promisc_forced_on) ||
	    test_bit(ICE_VSI_FLAG_PROMISC_CHANGED, vsi->flags)) {
		clear_bit(ICE_VSI_FLAG_PROMISC_CHANGED, vsi->flags);
		if (vsi->current_netdev_flags & IFF_PROMISC) {
			/* Apply Rx filter rule to get traffic from wire */
			if (!ice_is_dflt_vsi_in_use(pf->first_sw)) {
				err = ice_set_dflt_vsi(pf->first_sw, vsi);
				if (err && err != -EEXIST) {
					netdev_err(netdev, "Error %d setting default VSI %i Rx rule\n",
						   err, vsi->vsi_num);
					vsi->current_netdev_flags &=
						~IFF_PROMISC;
					goto out_promisc;
				}
			}
		} else {
			/* Clear Rx filter to remove traffic from wire */
			if (ice_is_vsi_dflt_vsi(pf->first_sw, vsi)) {
				err = ice_clear_dflt_vsi(pf->first_sw);
				if (err) {
					netdev_err(netdev, "Error %d clearing default VSI %i Rx rule\n",
						   err, vsi->vsi_num);
					vsi->current_netdev_flags |=
						IFF_PROMISC;
					goto out_promisc;
				}
			}
		}
	}
	goto exit;

out_promisc:
	set_bit(ICE_VSI_FLAG_PROMISC_CHANGED, vsi->flags);
	goto exit;
out:
	/* if something went wrong then set the changed flag so we try again */
	set_bit(ICE_VSI_FLAG_UMAC_FLTR_CHANGED, vsi->flags);
	set_bit(ICE_VSI_FLAG_MMAC_FLTR_CHANGED, vsi->flags);
exit:
	clear_bit(__ICE_CFG_BUSY, vsi->state);
	return err;
}

/**
 * ice_sync_fltr_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void ice_sync_fltr_subtask(struct ice_pf *pf)
{
	int v;

	if (!pf || !(test_bit(ICE_FLAG_FLTR_SYNC, pf->flags)))
		return;

	clear_bit(ICE_FLAG_FLTR_SYNC, pf->flags);

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v] && ice_vsi_fltr_changed(pf->vsi[v]) &&
		    ice_vsi_sync_fltr(pf->vsi[v])) {
			/* come back and try again later */
			set_bit(ICE_FLAG_FLTR_SYNC, pf->flags);
			break;
		}
}

/**
 * ice_pf_dis_all_vsi - Pause all VSIs on a PF
 * @pf: the PF
 * @locked: is the rtnl_lock already held
 */
static void ice_pf_dis_all_vsi(struct ice_pf *pf, bool locked)
{
	int v;

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v])
			ice_dis_vsi(pf->vsi[v], locked);
}

/**
 * ice_prepare_for_reset - prep for reset
 * @pf: board private structure
 * @reset_type: reset type requested
 *
 * Inform or close all dependent features in prep for reset.
 */
static void
ice_prepare_for_reset(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	struct ice_hw *hw = &pf->hw;
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	struct ice_vsi *vsi;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	int i;

	dev_dbg(ice_pf_to_dev(pf), "reset_type=%d\n", reset_type);

	/* already prepared for reset */
	if (test_bit(__ICE_PREPARED_FOR_RESET, pf->state))
		return;

	/* Notify VFs of impending reset */
	if (ice_check_sq_alive(hw, &hw->mailboxq))
		ice_vc_notify_reset(pf);

	/* Disable VFs until reset is completed */
	ice_for_each_vf(pf, i)
		ice_set_vf_state_qs_dis(&pf->vf[i]);


	/* clear SW filtering DB */
	ice_clear_hw_tbls(hw);
	/* disable the VSIs and their queues that are not already DOWN */
	ice_pf_dis_all_vsi(pf, false);

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	/* release ADQ specific HW and SW resources */
	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		goto skip;

	/* to be on safer size, reset orig_rss_size so that normal flow
	 * of deciding rss_size can take precedence
	 */
	vsi->orig_rss_size = 0;

	if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags)) {
		if (reset_type == ICE_RESET_PFR) {
			vsi->old_ena_tc = vsi->all_enatc;
			vsi->old_numtc = vsi->all_numtc;
		} else {
			/* for other reset type, do not support "rebuild
			 * of channel, hence reset needed info
			 */
			vsi->old_ena_tc = 0;
			vsi->all_enatc = 0;
			vsi->old_numtc = 0;
			vsi->all_numtc = 0;
			clear_bit(ICE_FLAG_TC_MQPRIO, pf->flags);
			memset(&vsi->mqprio_qopt, 0, sizeof(vsi->mqprio_qopt));
		}
	}
skip:
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	if (hw->port_info)
		ice_sched_clear_port(hw->port_info);

	ice_shutdown_all_ctrlq(hw);

	set_bit(__ICE_PREPARED_FOR_RESET, pf->state);
}

/**
 * ice_print_recovery_msg - print recovery mode message
 * @dev: pointer to the device instance
 */
static void ice_print_recovery_msg(struct device *dev)
{
	dev_err(dev, "Firmware recovery mode detected. Limiting functionality. Refer to the Intel(R) Ethernet Adapters and Devices User Guide for details on firmware recovery mode\n");
}

/**
 * ice_prepare_for_recovery_mode - prepare the driver for FW recovery mode
 * @pf: pointer to the PF instance
 */
static void ice_prepare_for_recovery_mode(struct ice_pf *pf)
{
	enum ice_close_reason reason;
	struct ice_vsi *vsi;

	ice_print_recovery_msg(ice_pf_to_dev(pf));
	set_bit(__ICE_RECOVERY_MODE, pf->state);

	vsi = ice_get_main_vsi(pf);
	if (vsi && vsi->netdev) {
		ice_set_ethtool_recovery_ops(vsi->netdev);
		netif_carrier_off(vsi->netdev);
		netif_tx_stop_all_queues(vsi->netdev);
	}

	/* close peer devices */
	reason = ICE_REASON_RECOVERY_MODE;
	ice_for_each_peer(pf, &reason, ice_peer_close);

	if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags))
		if (!pci_vfs_assigned(pf->pdev))
			pci_disable_sriov(pf->pdev);

	set_bit(__ICE_PREPPED_RECOVERY_MODE, pf->state);
}

/**
 * ice_remove_recovery_mode - Unload helper when in FW recovery mode
 * @pf: pointer to the PF instance
 */
static void ice_remove_recovery_mode(struct ice_pf *pf)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct device *dev = ice_pf_to_dev(pf);

	if (vsi && vsi->netdev) {
		unregister_netdev(vsi->netdev);
		free_netdev(vsi->netdev);
		devm_kfree(dev, vsi);
	}

	ice_reset(&pf->hw, ICE_RESET_PFR);
	pci_disable_pcie_error_reporting(pf->pdev);
	devm_kfree(dev, pf->vsi);
	devm_kfree(dev, pf);
}

/**
 * ice_probe_recovery_mode - Load helper when in FW recovery mode
 * @pf: pointer to the PF instance
 */
static int ice_probe_recovery_mode(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_netdev_priv *np;
	struct net_device *netdev;
	struct ice_vsi *vsi;
	int err;

	ice_print_recovery_msg(dev);
	set_bit(__ICE_RECOVERY_MODE, pf->state);

	/* create one single VSI instance and netdev to allow for ethtool
	 * recovery ops. This VSI cannot be backed by a VSI in the HW as
	 * the FW is in recovery mode. Thus, no traffic is possible on this
	 * VSI/netdev
	 */
	pf->vsi = devm_kcalloc(dev, 1, sizeof(*pf->vsi), GFP_KERNEL);
	if (!pf->vsi)
		return -ENOMEM;

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi) {
		err = -ENOMEM;
		goto err_vsi;
	}

	pf->vsi[0] = vsi;
	vsi->back = pf;

	/* allocate an etherdev with 1 queue pair */
	netdev = alloc_etherdev(sizeof(*np));
	if (!netdev) {
		err = -ENOMEM;
		goto err_netdev;
	}

	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;
	SET_NETDEV_DEV(netdev, dev);
	eth_hw_addr_random(netdev);

	netdev->netdev_ops = &ice_netdev_recovery_ops;
	ice_set_ethtool_recovery_ops(netdev);

	err = register_netdev(netdev);
	if (err)
		goto err_register;

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return 0;

err_register:
	free_netdev(netdev);
err_netdev:
	devm_kfree(dev, vsi);
err_vsi:
	devm_kfree(dev, pf->vsi);
	return err;
}

/**
 * ice_do_reset - Initiate one of many types of resets
 * @pf: board private structure
 * @reset_type: reset type requested
 * before this function was called.
 */
static void ice_do_reset(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug)) 
		printk("[PF_RING-ZC] %s\n", __FUNCTION__);
#endif

	dev_dbg(dev, "reset_type 0x%x requested\n", reset_type);
	WARN_ON(in_interrupt());

	ice_prepare_for_reset(pf, reset_type);


	/* trigger the reset */
	if (ice_reset(hw, reset_type)) {
		dev_err(dev, "reset %d failed\n", reset_type);
		set_bit(__ICE_RESET_FAILED, pf->state);
		clear_bit(__ICE_RESET_OICR_RECV, pf->state);
		clear_bit(__ICE_PREPARED_FOR_RESET, pf->state);
		clear_bit(__ICE_PFR_REQ, pf->state);
		clear_bit(__ICE_CORER_REQ, pf->state);
		clear_bit(__ICE_GLOBR_REQ, pf->state);
		return;
	}

	/* PFR is a bit of a special case because it doesn't result in an OICR
	 * interrupt. So for PFR, rebuild after the reset and clear the reset-
	 * associated state bits.
	 */
	if (reset_type == ICE_RESET_PFR) {
		pf->pfr_count++;
		ice_rebuild(pf, reset_type);
		clear_bit(__ICE_PREPARED_FOR_RESET, pf->state);
		clear_bit(__ICE_PFR_REQ, pf->state);
		ice_reset_all_vfs(pf, true);
	}
}

/**
 * ice_reset_subtask - Set up for resetting the device and driver
 * @pf: board private structure
 */
static void ice_reset_subtask(struct ice_pf *pf)
{
	enum ice_reset_req reset_type = ICE_RESET_INVAL;

	/* When a CORER/GLOBR/EMPR is about to happen, the hardware triggers an
	 * OICR interrupt. The OICR handler (ice_misc_intr) determines what type
	 * of reset is pending and sets bits in pf->state indicating the reset
	 * type and __ICE_RESET_OICR_RECV. So, if the latter bit is set
	 * prepare for pending reset if not already (for PF software-initiated
	 * global resets the software should already be prepared for it as
	 * indicated by __ICE_PREPARED_FOR_RESET; for global resets initiated
	 * by firmware or software on other PFs, that bit is not set so prepare
	 * for the reset now), poll for reset done, rebuild and return.
	 */
	if (test_bit(__ICE_RESET_OICR_RECV, pf->state)) {
		/* Perform the largest reset requested */
		if (test_and_clear_bit(__ICE_CORER_RECV, pf->state))
			reset_type = ICE_RESET_CORER;
		if (test_and_clear_bit(__ICE_GLOBR_RECV, pf->state))
			reset_type = ICE_RESET_GLOBR;
		if (test_and_clear_bit(__ICE_EMPR_RECV, pf->state))
			reset_type = ICE_RESET_EMPR;
		/* return if no valid reset type requested */
		if (reset_type == ICE_RESET_INVAL)
			return;
		if (ice_is_peer_ena(pf))
			ice_for_each_peer(pf, &reset_type,
					  ice_close_peer_for_reset);
		ice_prepare_for_reset(pf, reset_type);

		/* make sure we are ready to rebuild */
		if (ice_check_reset(&pf->hw)) {
			set_bit(__ICE_RESET_FAILED, pf->state);
			clear_bit(__ICE_RESET_OICR_RECV, pf->state);
			clear_bit(__ICE_PREPARED_FOR_RESET, pf->state);
			clear_bit(__ICE_PFR_REQ, pf->state);
			clear_bit(__ICE_CORER_REQ, pf->state);
			clear_bit(__ICE_GLOBR_REQ, pf->state);
			if (ice_get_fw_mode(&pf->hw) == ICE_FW_MODE_REC)
				ice_prepare_for_recovery_mode(pf);
			return;
		}

		/* came out of reset. check if an NVM rollback happened */
		if (ice_get_fw_mode(&pf->hw) == ICE_FW_MODE_ROLLBACK)
			ice_print_rollback_msg(&pf->hw);

		/* done with reset. start rebuild */
		pf->hw.reset_ongoing = false;
		ice_rebuild(pf, reset_type);
		/* clear bit to resume normal operations, but
		 * ICE_NEEDS_RESTART bit is set in case rebuild failed
		 */
		clear_bit(__ICE_RESET_OICR_RECV, pf->state);
		clear_bit(__ICE_PREPARED_FOR_RESET, pf->state);
		clear_bit(__ICE_PFR_REQ, pf->state);
		clear_bit(__ICE_CORER_REQ, pf->state);
		clear_bit(__ICE_GLOBR_REQ, pf->state);
		ice_reset_all_vfs(pf, true);
		return;
	}

	/* No pending resets to finish processing. Check for new resets */
	if (test_bit(__ICE_PFR_REQ, pf->state))
		reset_type = ICE_RESET_PFR;
	if (test_bit(__ICE_CORER_REQ, pf->state))
		reset_type = ICE_RESET_CORER;
	if (test_bit(__ICE_GLOBR_REQ, pf->state))
		reset_type = ICE_RESET_GLOBR;
	/* If no valid reset type requested just return */
	if (reset_type == ICE_RESET_INVAL)
		return;

	/* reset if not already down or busy */
	if (!test_bit(__ICE_DOWN, pf->state) &&
	    !test_bit(__ICE_CFG_BUSY, pf->state)) {
		ice_do_reset(pf, reset_type);
	}
}


/**
 * ice_sync_udp_fltr_subtask - sync the VSI filter list with HW
 * @pf: board private structure
 */
static void ice_sync_udp_fltr_subtask(struct ice_pf __always_unused *pf)
{
}

/**
 * ice_print_topo_conflict - print topology conflict message
 * @vsi: the VSI whose topology status is being checked
 */
static void ice_print_topo_conflict(struct ice_vsi *vsi)
{
	switch (vsi->port_info->phy.link_info.topo_media_conflict) {
	case ICE_AQ_LINK_TOPO_CONFLICT:
	case ICE_AQ_LINK_MEDIA_CONFLICT:
	case ICE_AQ_LINK_TOPO_UNREACH_PRT:
	case ICE_AQ_LINK_TOPO_UNDRUTIL_PRT:
	case ICE_AQ_LINK_TOPO_UNDRUTIL_MEDIA:
		netdev_info(vsi->netdev, "Possible mis-configuration of the Ethernet port detected, please use the Intel(R) Ethernet Port Configuration Tool application to address the issue.\n");
		break;
	case ICE_AQ_LINK_TOPO_UNSUPP_MEDIA:
		netdev_info(vsi->netdev, "Rx/Tx is disabled on this device because an unsupported module type was detected. Refer to the Intel(R) Ethernet Adapters and Devices User Guide for a list of supported modules.\n");
		break;
	default:
		break;
	}
}

/**
 * ice_print_link_msg - print link up or down message
 * @vsi: the VSI whose link status is being queried
 * @isup: boolean for if the link is now up or down
 */
void ice_print_link_msg(struct ice_vsi *vsi, bool isup)
{
	struct ice_aqc_get_phy_caps_data *caps;
	enum ice_status status;
	const char *fec_req;
	const char *speed;
	const char *fec;
	const char *fc;
	const char *an;

	if (!vsi)
		return;

	if (vsi->current_isup == isup)
		return;

	vsi->current_isup = isup;

	if (!isup) {
		netdev_info(vsi->netdev, "NIC Link is Down\n");
		return;
	}

	switch (vsi->port_info->phy.link_info.link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
		speed = "100 G";
		break;
	case ICE_AQ_LINK_SPEED_50GB:
		speed = "50 G";
		break;
	case ICE_AQ_LINK_SPEED_40GB:
		speed = "40 G";
		break;
	case ICE_AQ_LINK_SPEED_25GB:
		speed = "25 G";
		break;
	case ICE_AQ_LINK_SPEED_20GB:
		speed = "20 G";
		break;
	case ICE_AQ_LINK_SPEED_10GB:
		speed = "10 G";
		break;
	case ICE_AQ_LINK_SPEED_5GB:
		speed = "5 G";
		break;
	case ICE_AQ_LINK_SPEED_2500MB:
		speed = "2.5 G";
		break;
	case ICE_AQ_LINK_SPEED_1000MB:
		speed = "1 G";
		break;
	case ICE_AQ_LINK_SPEED_100MB:
		speed = "100 M";
		break;
	default:
		speed = "Unknown ";
		break;
	}

	switch (vsi->port_info->fc.current_mode) {
	case ICE_FC_FULL:
		fc = "Rx/Tx";
		break;
	case ICE_FC_TX_PAUSE:
		fc = "Tx";
		break;
	case ICE_FC_RX_PAUSE:
		fc = "Rx";
		break;
	case ICE_FC_NONE:
		fc = "None";
		break;
	default:
		fc = "Unknown";
		break;
	}

	/* Get FEC mode based on negotiated link info */
	switch (vsi->port_info->phy.link_info.fec_info) {
	case ICE_AQ_LINK_25G_RS_528_FEC_EN:
	case ICE_AQ_LINK_25G_RS_544_FEC_EN:
		fec = "RS-FEC";
		break;
	case ICE_AQ_LINK_25G_KR_FEC_EN:
		fec = "FC-FEC/BASE-R";
		break;
	default:
		fec = "NONE";
		break;
	}

	/* check if autoneg completed, might be false due to not supported */
	if (vsi->port_info->phy.link_info.an_info & ICE_AQ_AN_COMPLETED)
		an = "True";
	else
		an = "False";

	/* Get FEC mode requested based on PHY caps last SW configuration */
	caps = kzalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps) {
		fec_req = "Unknown";
		goto done;
	}

	status = ice_aq_get_phy_caps(vsi->port_info, false,
				     ICE_AQC_REPORT_SW_CFG, caps, NULL);
	if (status)
		netdev_info(vsi->netdev, "Get phy capability failed.\n");

	if (caps->link_fec_options & ICE_AQC_PHY_FEC_25G_RS_528_REQ ||
	    caps->link_fec_options & ICE_AQC_PHY_FEC_25G_RS_544_REQ)
		fec_req = "RS-FEC";
	else if (caps->link_fec_options & ICE_AQC_PHY_FEC_10G_KR_40G_KR4_REQ ||
		 caps->link_fec_options & ICE_AQC_PHY_FEC_25G_KR_REQ)
		fec_req = "FC-FEC/BASE-R";
	else
		fec_req = "NONE";

	kfree(caps);
done:
	netdev_info(vsi->netdev, "NIC Link is up %sbps Full Duplex, Requested FEC: %s, Negotiated FEC: %s, Autoneg: %s, Flow Control: %s\n",
		    speed, fec_req, fec, an, fc);
	ice_print_topo_conflict(vsi);
}

/**
 * ice_vsi_link_event - update the VSI's netdev
 * @vsi: the VSI on which the link event occurred
 * @link_up: whether or not the VSI needs to be set up or down
 */
static void ice_vsi_link_event(struct ice_vsi *vsi, bool link_up)
{
	if (!vsi)
		return;

	if (test_bit(__ICE_DOWN, vsi->state) || !vsi->netdev)
		return;

	if (vsi->type == ICE_VSI_PF) {
		if (link_up == netif_carrier_ok(vsi->netdev))
			return;

		if (link_up) {
			netif_carrier_on(vsi->netdev);
			netif_tx_wake_all_queues(vsi->netdev);
		} else {
			netif_carrier_off(vsi->netdev);
			netif_tx_stop_all_queues(vsi->netdev);
		}
	}
}


/**
 * ice_link_event - process the link event
 * @pf: PF that the link event is associated with
 * @pi: port_info for the port that the link event is associated with
 * @link_up: true if the physical link is up and false if it is down
 * @link_speed: current link speed received from the link event
 *
 * Returns 0 on success and negative on failure
 */
static int
ice_link_event(struct ice_pf *pf, struct ice_port_info *pi, bool link_up,
	       u16 link_speed)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_phy_info *phy_info;
	struct ice_vsi *vsi;
	u16 old_link_speed;
	bool old_link;
	int result;

	phy_info = &pi->phy;
	phy_info->link_info_old = phy_info->link_info;

	old_link = !!(phy_info->link_info_old.link_info & ICE_AQ_LINK_UP);
	old_link_speed = phy_info->link_info_old.link_speed;

	/* update the link info structures and re-enable link events,
	 * don't bail on failure due to other book keeping needed
	 */
	result = ice_update_link_info(pi);
	if (result)
		dev_dbg(dev, "Failed to update link status and re-enable link events for port %d\n",
			pi->lport);

	vsi = ice_get_main_vsi(pf);
	if (!vsi || !vsi->port_info)
		return -EINVAL;

	/* turn off PHY if media was removed */
	if (!test_bit(ICE_FLAG_NO_MEDIA, pf->flags) &&
	    !(pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE)) {
		set_bit(ICE_FLAG_NO_MEDIA, pf->flags);

		result = ice_aq_set_link_restart_an(pi, false, NULL);
		if (result) {
			dev_dbg(dev, "Failed to set link down, VSI %d error %d\n",
				vsi->vsi_num, result);
			return result;
		}
	}


	/* if the old link up/down and speed is the same as the new */
	if (link_up == old_link && link_speed == old_link_speed)
		return result;


	ice_dcb_rebuild(pf);
	ice_vsi_link_event(vsi, link_up);
	ice_print_link_msg(vsi, link_up);

	ice_vc_notify_link_state(pf);


	return result;
}

/**
 * ice_watchdog_subtask - periodic tasks not using event driven scheduling
 * @pf: board private structure
 */
static void ice_watchdog_subtask(struct ice_pf *pf)
{
	int i;

	/* if interface is down do nothing */
	if (test_bit(__ICE_DOWN, pf->state) ||
	    test_bit(__ICE_CFG_BUSY, pf->state))
		return;

	/* make sure we don't do these things too often */
	if (time_before(jiffies,
			pf->serv_tmr_prev + pf->serv_tmr_period))
		return;

	pf->serv_tmr_prev = jiffies;

	/* Update the stats for active netdevs so the network stack
	 * can look at updated numbers whenever it cares to
	 */
	ice_update_pf_stats(pf);
	ice_for_each_vsi(pf, i) {
		if (pf->vsi[i] && pf->vsi[i]->netdev)
			ice_update_vsi_stats(pf->vsi[i]);
	}
}

/**
 * ice_init_link_events - enable/initialize link events
 * @pi: pointer to the port_info instance
 *
 * Returns -EIO on failure, 0 on success
 */
static int ice_init_link_events(struct ice_port_info *pi)
{
	u16 mask;

	if (test_bit(__ICE_BAD_EEPROM,
		     ((struct ice_pf *)pi->hw->back)->state)) {
		dev_err(ice_hw_to_dev(pi->hw), "Link events disabled due to corrupted eeprom\n");
		return 0;
	}

	mask = ~((u16)(ICE_AQ_LINK_EVENT_UPDOWN | ICE_AQ_LINK_EVENT_MEDIA_NA |
		       ICE_AQ_LINK_EVENT_MODULE_QUAL_FAIL));

	if (ice_aq_set_event_mask(pi->hw, pi->lport, mask, NULL)) {
		dev_dbg(ice_hw_to_dev(pi->hw), "Failed to set link event mask for port %d\n",
			pi->lport);
		return -EIO;
	}

	if (ice_aq_get_link_info(pi, true, NULL, NULL)) {
		dev_dbg(ice_hw_to_dev(pi->hw), "Failed to enable link events for port %d\n",
			pi->lport);
		return -EIO;
	}

	return 0;
}

/**
 * ice_handle_link_event - handle link event via ARQ
 * @pf: PF that the link event is associated with
 * @event: event structure containing link status info
 */
static int
ice_handle_link_event(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	struct ice_aqc_get_link_status_data *link_data;
	struct ice_port_info *port_info;
	int status;

	link_data = (struct ice_aqc_get_link_status_data *)event->msg_buf;
	port_info = pf->hw.port_info;
	if (!port_info)
		return -EINVAL;

	status = ice_link_event(pf, port_info,
				!!(link_data->link_info & ICE_AQ_LINK_UP),
				le16_to_cpu(link_data->link_speed));
	if (status)
		dev_dbg(ice_pf_to_dev(pf), "Could not process link event, error %d\n",
			status);

	return status;
}


/**
 * __ice_clean_ctrlq - helper function to clean controlq rings
 * @pf: ptr to struct ice_pf
 * @q_type: specific Control queue type
 */
static int __ice_clean_ctrlq(struct ice_pf *pf, enum ice_ctl_q q_type)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_rq_event_info event;
	struct ice_hw *hw = &pf->hw;
	struct ice_ctl_q_info *cq;
	u16 pending, i = 0;
	const char *qtype;
	u32 oldval, val;

	/* Do not clean control queue if/when PF reset fails */
	if (test_bit(__ICE_RESET_FAILED, pf->state))
		return 0;

	switch (q_type) {
	case ICE_CTL_Q_ADMIN:
		cq = &hw->adminq;
		qtype = "Admin";
		break;
	case ICE_CTL_Q_MAILBOX:
		cq = &hw->mailboxq;
		qtype = "Mailbox";
		break;
	default:
		dev_warn(dev, "Unknown control queue type 0x%x\n", q_type);
		return 0;
	}

	/* check for error indications - PF_xx_AxQLEN register layout for
	 * FW/MBX/SB are identical so just use defines for PF_FW_AxQLEN.
	 */
	val = rd32(hw, cq->rq.len);
	if (val & (PF_FW_ARQLEN_ARQVFE_M | PF_FW_ARQLEN_ARQOVFL_M |
		   PF_FW_ARQLEN_ARQCRIT_M)) {
		oldval = val;
		if (val & PF_FW_ARQLEN_ARQVFE_M)
			dev_dbg(dev, "%s Receive Queue VF Error detected\n",
				qtype);
		if (val & PF_FW_ARQLEN_ARQOVFL_M) {
			dev_dbg(dev, "%s Receive Queue Overflow Error detected\n",
				qtype);
		}
		if (val & PF_FW_ARQLEN_ARQCRIT_M)
			dev_dbg(dev, "%s Receive Queue Critical Error detected\n",
				qtype);
		val &= ~(PF_FW_ARQLEN_ARQVFE_M | PF_FW_ARQLEN_ARQOVFL_M |
			 PF_FW_ARQLEN_ARQCRIT_M);
		if (oldval != val)
			wr32(hw, cq->rq.len, val);
	}

	val = rd32(hw, cq->sq.len);
	if (val & (PF_FW_ATQLEN_ATQVFE_M | PF_FW_ATQLEN_ATQOVFL_M |
		   PF_FW_ATQLEN_ATQCRIT_M)) {
		oldval = val;
		if (val & PF_FW_ATQLEN_ATQVFE_M)
			dev_dbg(dev, "%s Send Queue VF Error detected\n",
				qtype);
		if (val & PF_FW_ATQLEN_ATQOVFL_M) {
			dev_dbg(dev, "%s Send Queue Overflow Error detected\n",
				qtype);
		}
		if (val & PF_FW_ATQLEN_ATQCRIT_M)
			dev_dbg(dev, "%s Send Queue Critical Error detected\n",
				qtype);
		val &= ~(PF_FW_ATQLEN_ATQVFE_M | PF_FW_ATQLEN_ATQOVFL_M |
			 PF_FW_ATQLEN_ATQCRIT_M);
		if (oldval != val)
			wr32(hw, cq->sq.len, val);
	}

	event.buf_len = cq->rq_buf_size;
	event.msg_buf = kzalloc(event.buf_len, GFP_KERNEL);
	if (!event.msg_buf)
		return 0;

	do {
		enum ice_status ret;
		u16 opcode;

		ret = ice_clean_rq_elem(hw, cq, &event, &pending);
		if (ret == ICE_ERR_AQ_NO_WORK)
			break;
		if (ret) {
			dev_err(dev, "%s Receive Queue event error %d\n", qtype,
				ret);
			break;
		}

		opcode = le16_to_cpu(event.desc.opcode);

		switch (opcode) {
		case ice_aqc_opc_get_link_status:
			if (ice_handle_link_event(pf, &event))
				dev_err(dev, "Could not handle link event\n");
			break;
		case ice_aqc_opc_event_lan_overflow:
		{
			ice_vf_lan_overflow_event(pf, &event);
			break;
		}
		case ice_mbx_opc_send_msg_to_pf:
			ice_vc_process_vf_msg(pf, &event);
			break;
		case ice_aqc_opc_lldp_set_mib_change:
			ice_dcb_process_lldp_set_mib_change(pf, &event);
			break;
		default:
			dev_dbg(dev, "%s Receive Queue unknown event 0x%04x ignored\n",
				qtype, opcode);
			break;
		}
	} while (pending && (i++ < ICE_DFLT_IRQ_WORK));

	kfree(event.msg_buf);

	return pending && (i == ICE_DFLT_IRQ_WORK);
}

/**
 * ice_ctrlq_pending - check if there is a difference between ntc and ntu
 * @hw: pointer to hardware info
 * @cq: control queue information
 *
 * returns true if there are pending messages in a queue, false if there aren't
 */
static bool ice_ctrlq_pending(struct ice_hw *hw, struct ice_ctl_q_info *cq)
{
	u16 ntu;

	ntu = (u16)(rd32(hw, cq->rq.head) & cq->rq.head_mask);
	return cq->rq.next_to_clean != ntu;
}

/**
 * ice_clean_adminq_subtask - clean the AdminQ rings
 * @pf: board private structure
 */
static void ice_clean_adminq_subtask(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	if (!test_bit(__ICE_ADMINQ_EVENT_PENDING, pf->state))
		return;

	if (__ice_clean_ctrlq(pf, ICE_CTL_Q_ADMIN))
		return;

	clear_bit(__ICE_ADMINQ_EVENT_PENDING, pf->state);

	/* There might be a situation where new messages arrive to a control
	 * queue between processing the last message and clearing the
	 * EVENT_PENDING bit. So before exiting, check queue head again (using
	 * ice_ctrlq_pending) and process new messages if any.
	 */
	if (ice_ctrlq_pending(hw, &hw->adminq))
		__ice_clean_ctrlq(pf, ICE_CTL_Q_ADMIN);

	ice_flush(hw);
}

/**
 * ice_clean_mailboxq_subtask - clean the MailboxQ rings
 * @pf: board private structure
 */
static void ice_clean_mailboxq_subtask(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	if (!test_bit(__ICE_MAILBOXQ_EVENT_PENDING, pf->state))
		return;

	if (__ice_clean_ctrlq(pf, ICE_CTL_Q_MAILBOX))
		return;

	clear_bit(__ICE_MAILBOXQ_EVENT_PENDING, pf->state);

	if (ice_ctrlq_pending(hw, &hw->mailboxq))
		__ice_clean_ctrlq(pf, ICE_CTL_Q_MAILBOX);

	ice_flush(hw);
}

/**
 * ice_service_task_schedule - schedule the service task to wake up
 * @pf: board private structure
 *
 * If not already scheduled, this puts the task into the work queue.
 */
void ice_service_task_schedule(struct ice_pf *pf)
{
	if (!test_bit(__ICE_SERVICE_DIS, pf->state) &&
	    !test_and_set_bit(__ICE_SERVICE_SCHED, pf->state) &&
	    !test_bit(__ICE_RECOVERY_MODE, pf->state) &&
	    !test_bit(__ICE_NEEDS_RESTART, pf->state))
		queue_work(ice_wq, &pf->serv_task);
}

/**
 * ice_service_task_complete - finish up the service task
 * @pf: board private structure
 */
static void ice_service_task_complete(struct ice_pf *pf)
{
	WARN_ON(!test_bit(__ICE_SERVICE_SCHED, pf->state));

	/* force memory (pf->state) to sync before next service task */
	smp_mb__before_atomic();
	clear_bit(__ICE_SERVICE_SCHED, pf->state);
}

/**
 * ice_service_task_stop - stop service task and cancel works
 * @pf: board private structure
 *
 * Return 0 if the __ICE_SERVICE_DIS bit was not already set,
 * 1 otherwise.
 */
static int ice_service_task_stop(struct ice_pf *pf)
{
	int ret;

	ret = test_and_set_bit(__ICE_SERVICE_DIS, pf->state);

	if (pf->serv_tmr.function)
		del_timer_sync(&pf->serv_tmr);
	if (pf->serv_task.func)
		cancel_work_sync(&pf->serv_task);

	clear_bit(__ICE_SERVICE_SCHED, pf->state);
	return ret;
}

/**
 * ice_service_task_restart - restart service task and schedule works
 * @pf: board private structure
 *
 * This function is needed for suspend and resume works (e.g WoL scenario)
 */
static void ice_service_task_restart(struct ice_pf *pf)
{
	clear_bit(__ICE_SERVICE_DIS, pf->state);
	ice_service_task_schedule(pf);
}

/**
 * ice_service_timer - timer callback to schedule service task
 * @t: pointer to timer_list
 */
static void ice_service_timer(struct timer_list *t)
{
	struct ice_pf *pf = from_timer(pf, t, serv_tmr);

	mod_timer(&pf->serv_tmr, round_jiffies(pf->serv_tmr_period + jiffies));
	ice_service_task_schedule(pf);
}

/**
 * ice_handle_mdd_event - handle malicious driver detect event
 * @pf: pointer to the PF structure
 *
 * Called from service task. OICR interrupt handler indicates MDD event.
 * VF MDD logging is guarded by net_ratelimit. Additional PF and VF log
 * messages are wrapped by netif_msg_[rx|tx]_err. Since VF Rx MDD events
 * disable the queue, the PF can be configured to reset the VF using ethtool
 * private flag mdd-auto-reset-vf.
 */
static void ice_handle_mdd_event(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u32 reg;
	int i;

	if (!test_and_clear_bit(__ICE_MDD_EVENT_PENDING, pf->state)) {
		/* Since the VF MDD event logging is rate limited, check if
		 * there are pending MDD events.
		 */
		ice_print_vfs_mdd_events(pf);
		return;
	}

	/* find what triggered an MDD event */
	reg = rd32(hw, GL_MDET_TX_PQM);
	if (reg & GL_MDET_TX_PQM_VALID_M) {
		u8 pf_num = (reg & GL_MDET_TX_PQM_PF_NUM_M) >>
				GL_MDET_TX_PQM_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_TX_PQM_VF_NUM_M) >>
				GL_MDET_TX_PQM_VF_NUM_S;
		u8 event = (reg & GL_MDET_TX_PQM_MAL_TYPE_M) >>
				GL_MDET_TX_PQM_MAL_TYPE_S;
		u16 queue = ((reg & GL_MDET_TX_PQM_QNUM_M) >>
				GL_MDET_TX_PQM_QNUM_S);

		if (netif_msg_tx_err(pf))
			dev_info(dev, "Malicious Driver Detection event %d on TX queue %d PF# %d VF# %d\n",
				 event, queue, pf_num, vf_num);
		wr32(hw, GL_MDET_TX_PQM, 0xffffffff);
	}

	reg = rd32(hw, GL_MDET_TX_TCLAN);
	if (reg & GL_MDET_TX_TCLAN_VALID_M) {
		u8 pf_num = (reg & GL_MDET_TX_TCLAN_PF_NUM_M) >>
				GL_MDET_TX_TCLAN_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_TX_TCLAN_VF_NUM_M) >>
				GL_MDET_TX_TCLAN_VF_NUM_S;
		u8 event = (reg & GL_MDET_TX_TCLAN_MAL_TYPE_M) >>
				GL_MDET_TX_TCLAN_MAL_TYPE_S;
		u16 queue = ((reg & GL_MDET_TX_TCLAN_QNUM_M) >>
				GL_MDET_TX_TCLAN_QNUM_S);

		if (netif_msg_tx_err(pf))
			dev_info(dev, "Malicious Driver Detection event %d on TX queue %d PF# %d VF# %d\n",
				 event, queue, pf_num, vf_num);
		wr32(hw, GL_MDET_TX_TCLAN, 0xffffffff);
	}

	reg = rd32(hw, GL_MDET_RX);
	if (reg & GL_MDET_RX_VALID_M) {
		u8 pf_num = (reg & GL_MDET_RX_PF_NUM_M) >>
				GL_MDET_RX_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_RX_VF_NUM_M) >>
				GL_MDET_RX_VF_NUM_S;
		u8 event = (reg & GL_MDET_RX_MAL_TYPE_M) >>
				GL_MDET_RX_MAL_TYPE_S;
		u16 queue = ((reg & GL_MDET_RX_QNUM_M) >>
				GL_MDET_RX_QNUM_S);

		if (netif_msg_rx_err(pf))
			dev_info(dev, "Malicious Driver Detection event %d on RX queue %d PF# %d VF# %d\n",
				 event, queue, pf_num, vf_num);
		wr32(hw, GL_MDET_RX, 0xffffffff);
	}

	/* check to see if this PF caused an MDD event */
	reg = rd32(hw, PF_MDET_TX_PQM);
	if (reg & PF_MDET_TX_PQM_VALID_M) {
		wr32(hw, PF_MDET_TX_PQM, 0xFFFF);
		if (netif_msg_tx_err(pf))
			dev_info(dev, "Malicious Driver Detection event TX_PQM detected on PF\n");
	}

	reg = rd32(hw, PF_MDET_TX_TCLAN);
	if (reg & PF_MDET_TX_TCLAN_VALID_M) {
		wr32(hw, PF_MDET_TX_TCLAN, 0xFFFF);
		if (netif_msg_tx_err(pf))
			dev_info(dev, "Malicious Driver Detection event TX_TCLAN detected on PF\n");
	}

	reg = rd32(hw, PF_MDET_RX);
	if (reg & PF_MDET_RX_VALID_M) {
		wr32(hw, PF_MDET_RX, 0xFFFF);
		if (netif_msg_rx_err(pf))
			dev_info(dev, "Malicious Driver Detection event RX detected on PF\n");
	}

	/* Check to see if one of the VFs caused an MDD event, and then
	 * increment counters and set print pending
	 */
	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		reg = rd32(hw, VP_MDET_TX_PQM(i));
		if (reg & VP_MDET_TX_PQM_VALID_M) {
			wr32(hw, VP_MDET_TX_PQM(i), 0xFFFF);
			vf->mdd_tx_events.count++;
			set_bit(__ICE_MDD_VF_PRINT_PENDING, pf->state);
			if (netif_msg_tx_err(pf))
				dev_info(dev, "Malicious Driver Detection event TX_PQM detected on VF %d\n",
					 i);
		}

		reg = rd32(hw, VP_MDET_TX_TCLAN(i));
		if (reg & VP_MDET_TX_TCLAN_VALID_M) {
			wr32(hw, VP_MDET_TX_TCLAN(i), 0xFFFF);
			vf->mdd_tx_events.count++;
			set_bit(__ICE_MDD_VF_PRINT_PENDING, pf->state);
			if (netif_msg_tx_err(pf))
				dev_info(dev, "Malicious Driver Detection event TX_TCLAN detected on VF %d\n",
					 i);
		}

		reg = rd32(hw, VP_MDET_TX_TDPU(i));
		if (reg & VP_MDET_TX_TDPU_VALID_M) {
			wr32(hw, VP_MDET_TX_TDPU(i), 0xFFFF);
			vf->mdd_tx_events.count++;
			set_bit(__ICE_MDD_VF_PRINT_PENDING, pf->state);
			if (netif_msg_tx_err(pf))
				dev_info(dev, "Malicious Driver Detection event TX_TDPU detected on VF %d\n",
					 i);
		}

		reg = rd32(hw, VP_MDET_RX(i));
		if (reg & VP_MDET_RX_VALID_M) {
			wr32(hw, VP_MDET_RX(i), 0xFFFF);
			vf->mdd_rx_events.count++;
			set_bit(__ICE_MDD_VF_PRINT_PENDING, pf->state);
			if (netif_msg_rx_err(pf))
				dev_info(dev, "Malicious Driver Detection event RX detected on VF %d\n",
					 i);

			/* Since the queue is disabled on VF Rx MDD events, the
			 * PF can be configured to reset the VF through ethtool
			 * private flag mdd-auto-reset-vf.
			 */
			if (test_bit(ICE_FLAG_MDD_AUTO_RESET_VF, pf->flags))
				ice_reset_vf(&pf->vf[i], false);
		}
	}

	ice_print_vfs_mdd_events(pf);
}

/**
 * ice_force_phys_link_state - Force the physical link state
 * @vsi: VSI to force the physical link state to up/down
 * @link_up: true/false indicates to set the physical link to up/down
 *
 * Force the physical link state by getting the current PHY capabilities from
 * hardware and setting the PHY config based on the determined capabilities. If
 * link changes a link event will be triggered because both the Enable Automatic
 * Link Update and LESM Enable bits are set when setting the PHY capabilities.
 *
 * Returns 0 on success, negative on failure
 */
static int ice_force_phys_link_state(struct ice_vsi *vsi, bool link_up)
{
	struct ice_aqc_get_phy_caps_data *pcaps;
	struct ice_aqc_set_phy_cfg_data *cfg;
	struct ice_port_info *pi;
	struct device *dev;
	int retcode;

	if (!vsi || !vsi->port_info || !vsi->back)
		return -EINVAL;
	if (vsi->type != ICE_VSI_PF)
		return 0;

	dev = ice_pf_to_dev(vsi->back);

	pi = vsi->port_info;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return -ENOMEM;

	retcode = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG, pcaps,
				      NULL);
	if (retcode) {
		dev_err(dev, "Failed to get phy capabilities, VSI %d error %d\n",
			vsi->vsi_num, retcode);
		retcode = -EIO;
		goto out;
	}

	/* No change in link */
	if (link_up == !!(pcaps->caps & ICE_AQC_PHY_EN_LINK) &&
	    link_up == !!(pi->phy.link_info.link_info & ICE_AQ_LINK_UP))
		goto out;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg) {
		retcode = -ENOMEM;
		goto out;
	}

	/* Copy the current user PHY configuration. The current user PHY
	 * configuration is initialized during probe from PHY capabilities
	 * software mode, and updated on set PHY configuration.
	 */
	memcpy(cfg, &pi->phy.curr_user_phy_cfg, sizeof(*cfg));

	cfg->caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;
	if (link_up)
		cfg->caps |= ICE_AQ_PHY_ENA_LINK;
	else
		cfg->caps &= ~ICE_AQ_PHY_ENA_LINK;

	retcode = ice_aq_set_phy_cfg(&vsi->back->hw, pi, cfg, NULL);
	if (retcode) {
		dev_err(dev, "Failed to set phy config, VSI %d error %d\n",
			vsi->vsi_num, retcode);
		retcode = -EIO;
	}

	kfree(cfg);
out:
	kfree(pcaps);
	return retcode;
}

/**
 * ice_init_phy_user_cfg - Initialize the PHY user configuration
 * @pi: port info structure
 *
 * Initialize the current user PHY configuration, speed, FEC, and FC requested
 * mode. The initial values are taken from SW configuration. This is done during
 * probe because the user can change PHY configurations once the driver is
 * loaded, and these configurations are needed when setting PHY configuration.
 * The user PHY configuration is updated on set PHY configuration. Returns 0 on
 * success, negative on failure
 */
static int ice_init_phy_user_cfg(struct ice_port_info *pi)
{
	struct ice_aqc_get_phy_caps_data *pcaps;
	struct ice_phy_info *phy = &pi->phy;
	int err;

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);

	if (!pcaps)
		return -ENOMEM;

	err = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG, pcaps,
				  NULL);
	if (err) {
		dev_err(ice_hw_to_dev(pi->hw), "Get PHY capability failed.\n");
		err = -EIO;
		goto out;
	}

	/* Start with support for all speeds */
	phy->curr_user_speed_req = ICE_AQ_LINK_SPEED_M;
	phy->curr_user_fec_req = ice_caps_to_fec_mode(pcaps->caps,
						      pcaps->link_fec_options);
	phy->curr_user_fc_req = ice_caps_to_fc_mode(pcaps->caps);

	ice_copy_phy_caps_to_cfg(pcaps, &pi->phy.curr_user_phy_cfg);
out:
	kfree(pcaps);
	return err;
}

/**
 * ice_configure_phy - configure PHY
 * @vsi: VSI of PHY
 *
 * Set the PHY configuration. If this is the initial call, use values
 * provided by the NVM.  Otherwise, attempt to use any settings the user
 * has requested; if we are unable to do so, use the current PHY
 * capabilities.
 */
static int ice_configure_phy(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct ice_aqc_get_phy_caps_data *pcaps;
	struct ice_aqc_set_phy_cfg_data *cfg;
	u64 phy_low = 0, phy_high = 0;
	struct ice_port_info *pi;
	int status;

	pi = vsi->port_info;
	if (!pi)
		return -EINVAL;

	/* Ensure we have media as we cannot configure a medialess port */
	if (!(pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE))
		return -EPERM;

	ice_print_topo_conflict(vsi);

	if (vsi->port_info->phy.link_info.topo_media_conflict ==
	    ICE_AQ_LINK_TOPO_UNSUPP_MEDIA)
		return -EPERM;

	if (test_bit(ICE_FLAG_LINK_DOWN_ON_CLOSE_ENA, vsi->back->flags))
		return ice_force_phys_link_state(vsi, true);

	pcaps = kzalloc(sizeof(*pcaps), GFP_KERNEL);
	if (!pcaps)
		return -ENOMEM;

	/* Get current PHY config */
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG, pcaps,
				     NULL);
	if (status) {
		dev_err(dev, "Failed to get phy capabilities, VSI %d error %d\n",
			vsi->vsi_num, status);
		status = -EIO;
		goto done;
	}

	/* If configuration has not changed, there's nothing to do */
	if (ice_phy_caps_equals_cfg(pcaps, &pi->phy.curr_user_phy_cfg))
		goto done;

	/* Use PHY topology as baseline for configuration */
	memset(pcaps, 0, sizeof(*pcaps));
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP, pcaps,
				     NULL);
	if (status) {
		dev_err(dev, "Failed to get phy capabilities, VSI %d error %d\n",
			vsi->vsi_num, status);
		status = -EIO;
		goto done;
	}

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg) {
		status = -ENOMEM;
		goto done;
	}

	ice_copy_phy_caps_to_cfg(pcaps, cfg);

	/* Speed  */
	ice_update_phy_type(&phy_low, &phy_high, pi->phy.curr_user_speed_req);
	cfg->phy_type_low = pcaps->phy_type_low & cpu_to_le64(phy_low);
	cfg->phy_type_high = pcaps->phy_type_high & cpu_to_le64(phy_high);

	/* Can't provide what was requested; use PHY capabilities */
	if (!cfg->phy_type_low && !cfg->phy_type_high) {
		cfg->phy_type_low = pcaps->phy_type_low;
		cfg->phy_type_high = pcaps->phy_type_high;
	}

	/* FEC */
	ice_cfg_phy_fec(cfg, pi->phy.curr_user_fec_req);

	/* Can't provide what was requested; use PHY capabilities */
	if (cfg->link_fec_opt !=
	    (cfg->link_fec_opt & pcaps->link_fec_options)) {
		cfg->caps |= pcaps->caps & ICE_AQC_PHY_EN_AUTO_FEC;
		cfg->link_fec_opt = pcaps->link_fec_options;
	}

	/* Flow Control is always supported; no need to check against
	 * capabilities
	 */
	cfg->caps &= ~(ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY |
		       ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY);

	switch (pi->phy.curr_user_fc_req) {
	case ICE_FC_FULL:
		cfg->caps |= ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY |
			    ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY;
		break;
	case ICE_FC_RX_PAUSE:
		cfg->caps |= ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY;
		break;
	case ICE_FC_TX_PAUSE:
		cfg->caps |= ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY;
		break;
	default:
		break;
	}

	/* Enable link and link update */
	cfg->caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT | ICE_AQ_PHY_ENA_LINK;

	status = ice_aq_set_phy_cfg(&vsi->back->hw, pi, cfg, NULL);
	if (status) {
		dev_err(dev, "Failed to set phy config, VSI %d error %d\n",
			vsi->vsi_num, status);
		status = -EIO;
	}

	kfree(cfg);
done:
	kfree(pcaps);
	return status;
}

/**
 * ice_check_media_subtask - Check for media; bring link up if detected.
 * @pf: pointer to PF struct
 */
static void ice_check_media_subtask(struct ice_pf *pf)
{
	struct ice_port_info *pi;
	struct ice_vsi *vsi;
	int err;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return;

	/* No need to check for media if it's already present or the interface
	 * is down
	 */
	if (!test_bit(ICE_FLAG_NO_MEDIA, pf->flags) ||
	    test_bit(__ICE_DOWN, vsi->state))
		return;

	/* Refresh link info and check if media is present */
	pi = vsi->port_info;
	err = ice_update_link_info(pi);
	if (err)
		return;

	if (pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE) {
		/* PHY settings are reset on media insertion, reconfigure
		 * PHY to preserve settings.
		 */
		ice_configure_phy(vsi);
		clear_bit(ICE_FLAG_NO_MEDIA, pf->flags);

		/* A Link Status Event will be generated; the event handler
		 * will complete bringing the interface up
		 */
	}
}

/**
 * ice_service_task - manage and run subtasks
 * @work: pointer to work_struct contained by the PF struct
 */
static void ice_service_task(struct work_struct *work)
{
	struct ice_pf *pf = container_of(work, struct ice_pf, serv_task);
	unsigned long start_time = jiffies;

	/* subtasks */

	/* process reset requests first */
	ice_reset_subtask(pf);

	/* bail if a reset/recovery cycle is pending or rebuild failed */
	if (ice_is_reset_in_progress(pf->state) ||
	    test_bit(__ICE_SUSPENDED, pf->state) ||
	    test_bit(__ICE_NEEDS_RESTART, pf->state)) {
		ice_service_task_complete(pf);
		return;
	}

	ice_clean_adminq_subtask(pf);
	ice_check_media_subtask(pf);
	ice_check_for_hang_subtask(pf);
	ice_sync_fltr_subtask(pf);
	ice_handle_mdd_event(pf);
	ice_watchdog_subtask(pf);

	if (ice_is_safe_mode(pf)) {
		ice_service_task_complete(pf);
		return;
	}

	/* Invoke remaining initialization of peer devices */
	ice_for_each_peer(pf, NULL, ice_finish_init_peer_device);

#ifdef ADQ_PERF
	ice_chnl_subtask_handle_interrupt(pf);
#endif /* ADQ_PERF */
#ifdef ADQ_PERF
	ice_channel_sync_global_cntrs(pf);
#endif /* ADQ_PERF */
	ice_process_vflr_event(pf);
	ice_sync_udp_fltr_subtask(pf);
	ice_clean_mailboxq_subtask(pf);
	ice_sync_arfs_fltrs(pf);
	/* Clear __ICE_SERVICE_SCHED flag to allow scheduling next event */
	ice_service_task_complete(pf);

	/* If the tasks have taken longer than one service timer period
	 * or there is more work to be done, reset the service timer to
	 * schedule the service task now.
	 */
	if (time_after(jiffies, (start_time + pf->serv_tmr_period)) ||
	    test_bit(__ICE_MDD_EVENT_PENDING, pf->state) ||
	    test_bit(__ICE_VFLR_EVENT_PENDING, pf->state) ||
	    test_bit(__ICE_MAILBOXQ_EVENT_PENDING, pf->state) ||
	    test_bit(__ICE_ADMINQ_EVENT_PENDING, pf->state))
		mod_timer(&pf->serv_tmr, jiffies);
}

/**
 * ice_set_ctrlq_len - helper function to set controlq length
 * @hw: pointer to the HW instance
 */
static void ice_set_ctrlq_len(struct ice_hw *hw)
{
	hw->adminq.num_rq_entries = ICE_AQ_LEN;
	hw->adminq.num_sq_entries = ICE_AQ_LEN;
	hw->adminq.rq_buf_size = ICE_AQ_MAX_BUF_LEN;
	hw->adminq.sq_buf_size = ICE_AQ_MAX_BUF_LEN;
	hw->mailboxq.num_rq_entries = ICE_MBXRQ_LEN;
	hw->mailboxq.num_sq_entries = ICE_MBXSQ_LEN;
	hw->mailboxq.rq_buf_size = ICE_MBXQ_MAX_BUF_LEN;
	hw->mailboxq.sq_buf_size = ICE_MBXQ_MAX_BUF_LEN;
}

/**
 * ice_schedule_reset - schedule a reset
 * @pf: board private structure
 * @reset: reset being requested
 */
int ice_schedule_reset(struct ice_pf *pf, enum ice_reset_req reset)
{
	struct device *dev = ice_pf_to_dev(pf);

	/* bail out if earlier reset has failed */
	if (test_bit(__ICE_RESET_FAILED, pf->state)) {
		dev_dbg(dev, "earlier reset has failed\n");
		return -EIO;
	}
	/* bail if reset/recovery already in progress */
	if (ice_is_reset_in_progress(pf->state)) {
		dev_dbg(dev, "Reset already in progress\n");
		return -EBUSY;
	}

	switch (reset) {
	case ICE_RESET_PFR:
		set_bit(__ICE_PFR_REQ, pf->state);
		break;
	case ICE_RESET_CORER:
		set_bit(__ICE_CORER_REQ, pf->state);
		break;
	case ICE_RESET_GLOBR:
		set_bit(__ICE_GLOBR_REQ, pf->state);
		break;
	default:
		return -EINVAL;
	}

	ice_service_task_schedule(pf);
	return 0;
}

/**
 * ice_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * so that we may register to receive changes to the irq affinity masks.
 */
static void
ice_irq_affinity_notify(struct irq_affinity_notify *notify,
			const cpumask_t *mask)
{
	struct ice_q_vector *q_vector =
		container_of(notify, struct ice_q_vector, affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

/**
 * ice_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * to inform the current notification subscriber that they will no longer
 * receive notifications.
 */
static void ice_irq_affinity_release(struct kref __always_unused *ref) {}

/**
 * ice_vsi_ena_irq - Enable IRQ for the given VSI
 * @vsi: the VSI being configured
 */
static int ice_vsi_ena_irq(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->back->hw;
	int i;

	ice_for_each_q_vector(vsi, i)
		ice_irq_dynamic_ena(hw, vsi, vsi->q_vectors[i]);

	ice_flush(hw);
	return 0;
}

/**
 * ice_vsi_req_irq_msix - get MSI-X vectors from the OS for the VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 */
static int ice_vsi_req_irq_msix(struct ice_vsi *vsi, char *basename)
{
	int q_vectors = vsi->num_q_vectors;
	struct ice_pf *pf = vsi->back;
	int base = vsi->base_vector;
	struct device *dev;
	int rx_int_idx = 0;
	int tx_int_idx = 0;
	int vector, err;
	int irq_num;

	dev = ice_pf_to_dev(pf);
	for (vector = 0; vector < q_vectors; vector++) {
		struct ice_q_vector *q_vector = vsi->q_vectors[vector];

		irq_num = pf->msix_entries[base + vector].vector;

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "TxRx", rx_int_idx++);
			tx_int_idx++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "rx", rx_int_idx++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "tx", tx_int_idx++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = devm_request_irq(dev, irq_num, vsi->irq_handler, 0,
				       q_vector->name, q_vector);
		if (err) {
			netdev_err(vsi->netdev, "MSIX request_irq failed, error: %d\n",
				   err);
			goto free_q_irqs;
		}

		/* register for affinity change notifications */
		q_vector->affinity_notify.notify = ice_irq_affinity_notify;
		q_vector->affinity_notify.release = ice_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, &q_vector->affinity_notify);

		/* assign the mask for this irq */
		irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);
	}

	vsi->irqs_ready = true;
	return 0;

free_q_irqs:
	while (vector) {
		vector--;
		irq_num = pf->msix_entries[base + vector].vector,
		irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, &vsi->q_vectors[vector]);
	}
	return err;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * ice_xdp_alloc_setup_rings - Allocate and setup Tx rings for XDP
 * @vsi: VSI to setup Tx rings used by XDP
 *
 * Return 0 on success and negative value on error
 */
static int ice_xdp_alloc_setup_rings(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	int i;

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		u16 xdp_q_idx = vsi->alloc_txq + i;
		struct ice_ring *xdp_ring;

		xdp_ring = kzalloc(sizeof(*xdp_ring), GFP_KERNEL);

		if (!xdp_ring)
			goto free_xdp_rings;

		xdp_ring->q_index = xdp_q_idx;
		xdp_ring->reg_idx = vsi->txq_map[xdp_q_idx];
		xdp_ring->ring_active = false;
		xdp_ring->vsi = vsi;
		xdp_ring->netdev = NULL;
		xdp_ring->dev = dev;
		xdp_ring->count = vsi->num_tx_desc;
		vsi->xdp_rings[i] = xdp_ring;
		if (ice_setup_tx_ring(xdp_ring))
			goto free_xdp_rings;
		ice_set_ring_xdp(xdp_ring);
#ifdef HAVE_AF_XDP_ZC_SUPPORT
		xdp_ring->xsk_umem = ice_xsk_umem(xdp_ring);
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
	}

	return 0;

free_xdp_rings:
	for (; i >= 0; i--)
		if (vsi->xdp_rings[i] && vsi->xdp_rings[i]->desc)
			ice_free_tx_ring(vsi->xdp_rings[i]);
	return -ENOMEM;
}

/**
 * ice_vsi_assign_bpf_prog - set or clear bpf prog pointer on VSI
 * @vsi: VSI to set the bpf prog on
 * @prog: the bpf prog pointer
 */
static void ice_vsi_assign_bpf_prog(struct ice_vsi *vsi, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;
	int i;

	old_prog = xchg(&vsi->xdp_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	ice_for_each_rxq(vsi, i)
		WRITE_ONCE(vsi->rx_rings[i]->xdp_prog, vsi->xdp_prog);
}

/**
 * ice_prepare_xdp_rings - Allocate, configure and setup Tx rings for XDP
 * @vsi: VSI to bring up Tx rings used by XDP
 * @prog: bpf program that will be assigned to VSI
 *
 * Return 0 on success and negative value on error
 */
int ice_prepare_xdp_rings(struct ice_vsi *vsi, struct bpf_prog *prog)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	int xdp_rings_rem = vsi->num_xdp_txq;
	struct ice_pf *pf = vsi->back;
	struct ice_qs_cfg xdp_qs_cfg = {
		.qs_mutex = &pf->avail_q_mutex,
		.pf_map = pf->avail_txqs,
		.pf_map_size = pf->max_pf_txqs,
		.q_count = vsi->num_xdp_txq,
		.scatter_count = ICE_MAX_SCATTER_TXQS,
		.vsi_map = vsi->txq_map,
		.vsi_map_offset = vsi->alloc_txq,
		.mapping_mode = ICE_VSI_MAP_CONTIG
	};
	enum ice_status status;
	struct device *dev;
	int i, v_idx;

	dev = ice_pf_to_dev(pf);
	vsi->xdp_rings = devm_kcalloc(dev, vsi->num_xdp_txq,
				      sizeof(*vsi->xdp_rings), GFP_KERNEL);
	if (!vsi->xdp_rings)
		return -ENOMEM;

	if (__ice_vsi_get_qs(&xdp_qs_cfg))
		goto err_map_xdp;

	vsi->xdp_mapping_mode = xdp_qs_cfg.mapping_mode;
	if (ice_xdp_alloc_setup_rings(vsi))
		goto clear_xdp_rings;

	/* follow the logic from ice_vsi_map_rings_to_vectors */
	ice_for_each_q_vector(vsi, v_idx) {
		struct ice_q_vector *q_vector = vsi->q_vectors[v_idx];
		int xdp_rings_per_v, q_id, q_base;

		xdp_rings_per_v = DIV_ROUND_UP(xdp_rings_rem,
					       vsi->num_q_vectors - v_idx);
		q_base = vsi->num_xdp_txq - xdp_rings_rem;

		for (q_id = q_base; q_id < (q_base + xdp_rings_per_v); q_id++) {
			struct ice_ring *xdp_ring = vsi->xdp_rings[q_id];

			xdp_ring->q_vector = q_vector;
			xdp_ring->next = q_vector->tx.ring;
			q_vector->tx.ring = xdp_ring;
		}
		xdp_rings_rem -= xdp_rings_per_v;
	}

	/* omit the scheduler update if in reset path; XDP queues will be
	 * taken into account at the end of ice_vsi_rebuild, where
	 * ice_cfg_vsi_lan is being called
	 */
	if (ice_is_reset_in_progress(pf->state))
		return 0;

	/* tell the Tx scheduler that right now we have
	 * additional queues
	 */
	for (i = 0; i < vsi->tc_cfg.numtc; i++)
		max_txqs[i] = vsi->num_txq + vsi->num_xdp_txq;

	status = ice_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				 max_txqs);
	if (status) {
		dev_err(dev, "Failed VSI LAN queue config for XDP, error:%d\n",
			status);
		goto clear_xdp_rings;
	}
	ice_vsi_assign_bpf_prog(vsi, prog);

	return 0;
clear_xdp_rings:
	for (i = 0; i < vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings[i]) {
			kfree_rcu(vsi->xdp_rings[i], rcu);
			vsi->xdp_rings[i] = NULL;
		}

err_map_xdp:
	mutex_lock(&pf->avail_q_mutex);
	for (i = 0; i < vsi->num_xdp_txq; i++) {
		clear_bit(vsi->txq_map[i + vsi->alloc_txq], pf->avail_txqs);
		vsi->txq_map[i + vsi->alloc_txq] = ICE_INVAL_Q_INDEX;
	}
	mutex_unlock(&pf->avail_q_mutex);

	devm_kfree(dev, vsi->xdp_rings);
	return -ENOMEM;
}

/**
 * ice_destroy_xdp_rings - undo the configuration made by ice_prepare_xdp_rings
 * @vsi: VSI to remove XDP rings
 *
 * Detach XDP rings from irq vectors, clean up the PF bitmap and free
 * resources
 */
int ice_destroy_xdp_rings(struct ice_vsi *vsi)
{
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	struct ice_pf *pf = vsi->back;
	int i, v_idx;

	/* q_vectors are freed in reset path so there's no point in detaching
	 * rings; in case of rebuild being triggered not from reset (for
	 * example when changing the ring count via ethtool -L) reset bits in
	 * pf->state won't be set, so additionally check first q_vector against
	 * NULL;
	 */
	if (ice_is_reset_in_progress(pf->state) || !vsi->q_vectors[0])
		goto free_qmap;

	ice_for_each_q_vector(vsi, v_idx) {
		struct ice_q_vector *q_vector = vsi->q_vectors[v_idx];
		struct ice_ring *ring;

		ice_for_each_ring(ring, q_vector->tx)
			if (!ring->tx_buf || !ice_ring_is_xdp(ring))
				break;

		/* restore the value of last node prior to XDP setup */
		q_vector->tx.ring = ring;
	}

free_qmap:
	mutex_lock(&pf->avail_q_mutex);
	for (i = 0; i < vsi->num_xdp_txq; i++) {
		clear_bit(vsi->txq_map[i + vsi->alloc_txq], pf->avail_txqs);
		vsi->txq_map[i + vsi->alloc_txq] = ICE_INVAL_Q_INDEX;
	}
	mutex_unlock(&pf->avail_q_mutex);

	for (i = 0; i < vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings[i]) {
			if (vsi->xdp_rings[i]->desc)
				ice_free_tx_ring(vsi->xdp_rings[i]);
			kfree_rcu(vsi->xdp_rings[i], rcu);
			vsi->xdp_rings[i] = NULL;
		}

	devm_kfree(ice_pf_to_dev(pf), vsi->xdp_rings);
	vsi->xdp_rings = NULL;

	if (ice_is_reset_in_progress(pf->state) || !vsi->q_vectors[0])
		return 0;

	ice_vsi_assign_bpf_prog(vsi, NULL);

	/* notify Tx scheduler that we destroyed XDP queues and bring
	 * back the old number of child nodes
	 */
	for (i = 0; i < vsi->tc_cfg.numtc; i++)
		max_txqs[i] = vsi->num_txq;

	return ice_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
			       max_txqs);
}

/**
 * ice_xdp_setup_prog - Add or remove XDP eBPF program
 * @vsi: VSI to setup XDP for
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
ice_xdp_setup_prog(struct ice_vsi *vsi, struct bpf_prog *prog,
		   struct netlink_ext_ack *extack)
{
	int frame_size = vsi->netdev->mtu + ICE_ETH_PKT_HDR_PAD;
	bool if_running = netif_running(vsi->netdev);
	int ret = 0, xdp_ring_err = 0;

	if (frame_size > vsi->rx_buf_len) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
		return -EOPNOTSUPP;
	}

	/* need to stop netdev while setting up the program for Rx rings */
	if (if_running && !test_and_set_bit(__ICE_DOWN, vsi->state)) {
		ret = ice_down(vsi);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack, "Preparing device for XDP attach failed");
			return ret;
		}
	}

	if (!ice_is_xdp_ena_vsi(vsi) && prog) {
		vsi->num_xdp_txq = vsi->alloc_txq;
		xdp_ring_err = ice_prepare_xdp_rings(vsi, prog);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack, "Setting up XDP Tx resources failed");
	} else if (ice_is_xdp_ena_vsi(vsi) && !prog) {
		xdp_ring_err = ice_destroy_xdp_rings(vsi);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack, "Freeing XDP Tx resources failed");
	} else {
		ice_vsi_assign_bpf_prog(vsi, prog);
	}

	if (if_running)
		ret = ice_up(vsi);

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (!ret && prog && vsi->xsk_umems) {
		int i;

		ice_for_each_rxq(vsi, i) {
			struct ice_ring *rx_ring = vsi->rx_rings[i];

			if (rx_ring->xsk_umem)
				napi_schedule(&rx_ring->q_vector->napi);
		}
	}
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

	return (ret || xdp_ring_err) ? -ENOMEM : 0;
}

/**
 * ice_xdp - implements XDP handler
 * @dev: netdevice
 * @xdp: XDP command
 */
#ifdef HAVE_NDO_BPF
static int ice_xdp(struct net_device *dev, struct netdev_bpf *xdp)
#else
static int ice_xdp(struct net_device *dev, struct netdev_xdp *xdp)
#endif
{
	struct ice_netdev_priv *np = netdev_priv(dev);
	struct ice_vsi *vsi = np->vsi;

	if (vsi->type != ICE_VSI_PF) {
		NL_SET_ERR_MSG_MOD(xdp->extack, "XDP can be loaded only on PF VSI");
		return -EINVAL;
	}

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return ice_xdp_setup_prog(vsi, xdp->prog, xdp->extack);
	case XDP_QUERY_PROG:
#ifndef NO_NETDEV_BPF_PROG_ATTACHED
		xdp->prog_attached = ice_is_xdp_ena_vsi(vsi);
#endif /* !NO_NETDEV_BPF_PROG_ATTACHED */
		xdp->prog_id = vsi->xdp_prog ? vsi->xdp_prog->aux->id : 0;
		return 0;
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	case XDP_SETUP_XSK_UMEM:
		return ice_xsk_umem_setup(vsi, xdp->xsk.umem,
					  xdp->xsk.queue_id);
#ifndef NO_XDP_QUERY_XSK_UMEM
	case XDP_QUERY_XSK_UMEM:
		return ice_xsk_umem_query(vsi, &xdp->xsk.umem,
					  xdp->xsk.queue_id);
#endif /* !NO_XDP_QUERY_XSK_UMEM */
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
	default:
		return -EINVAL;
	}
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * ice_ena_misc_vector - enable the non-queue interrupts
 * @pf: board private structure
 */
static void ice_ena_misc_vector(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 val;

	/* Disable anti-spoof detection interrupt to prevent spurious event
	 * interrupts during a function reset. Anti-spoof functionally is
	 * still supported.
	 */
	val = rd32(hw, GL_MDCK_TX_TDPU);
	val |= GL_MDCK_TX_TDPU_RCU_ANTISPOOF_ITR_DIS_M;
	wr32(hw, GL_MDCK_TX_TDPU, val);

	/* clear things first */
	wr32(hw, PFINT_OICR_ENA, 0);	/* disable all */
	rd32(hw, PFINT_OICR);		/* read to clear */

	val = (PFINT_OICR_ECC_ERR_M |
	       PFINT_OICR_MAL_DETECT_M |
	       PFINT_OICR_GRST_M |
	       PFINT_OICR_PCI_EXCEPTION_M |
	       PFINT_OICR_VFLR_M |
	       PFINT_OICR_HMC_ERR_M |
	       PFINT_OICR_PE_CRITERR_M |
	       PFINT_OICR_SWINT_M);

	wr32(hw, PFINT_OICR_ENA, val);

	/* SW_ITR_IDX = 0, but don't change INTENA */
	wr32(hw, GLINT_DYN_CTL(pf->oicr_idx),
	     GLINT_DYN_CTL_SW_ITR_INDX_M | GLINT_DYN_CTL_INTENA_MSK_M);
}

/**
 * ice_misc_intr - misc interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t ice_misc_intr(int __always_unused irq, void *data)
{
	struct ice_pf *pf = (struct ice_pf *)data;
	struct ice_hw *hw = &pf->hw;
	irqreturn_t ret = IRQ_NONE;
	struct device *dev;
	u32 oicr, ena_mask;

	dev = ice_pf_to_dev(pf);
	set_bit(__ICE_ADMINQ_EVENT_PENDING, pf->state);
	set_bit(__ICE_MAILBOXQ_EVENT_PENDING, pf->state);

	oicr = rd32(hw, PFINT_OICR);
	ena_mask = rd32(hw, PFINT_OICR_ENA);

	if (oicr & PFINT_OICR_SWINT_M) {
		ena_mask &= ~PFINT_OICR_SWINT_M;
		pf->sw_int_count++;
	}

	if (oicr & PFINT_OICR_MAL_DETECT_M) {
		ena_mask &= ~PFINT_OICR_MAL_DETECT_M;
		set_bit(__ICE_MDD_EVENT_PENDING, pf->state);
	}
	if (oicr & PFINT_OICR_VFLR_M) {
		ena_mask &= ~PFINT_OICR_VFLR_M;
		set_bit(__ICE_VFLR_EVENT_PENDING, pf->state);
	}

	if (oicr & PFINT_OICR_GRST_M) {
		u32 reset;

		/* we have a reset warning */
		ena_mask &= ~PFINT_OICR_GRST_M;
		reset = (rd32(hw, GLGEN_RSTAT) & GLGEN_RSTAT_RESET_TYPE_M) >>
			GLGEN_RSTAT_RESET_TYPE_S;

		if (reset == ICE_RESET_CORER)
			pf->corer_count++;
		else if (reset == ICE_RESET_GLOBR)
			pf->globr_count++;
		else if (reset == ICE_RESET_EMPR)
			pf->empr_count++;
		else
			dev_dbg(dev, "Invalid reset type %d\n", reset);

		/* If a reset cycle isn't already in progress, we set a bit in
		 * pf->state so that the service task can start a reset/rebuild.
		 * We also make note of which reset happened so that peer
		 * devices/drivers can be informed.
		 */
		if (!test_and_set_bit(__ICE_RESET_OICR_RECV, pf->state)) {
			if (reset == ICE_RESET_CORER)
				set_bit(__ICE_CORER_RECV, pf->state);
			else if (reset == ICE_RESET_GLOBR)
				set_bit(__ICE_GLOBR_RECV, pf->state);
			else
				set_bit(__ICE_EMPR_RECV, pf->state);

			/* There are couple of different bits at play here.
			 * hw->reset_ongoing indicates whether the hardware is
			 * in reset. This is set to true when a reset interrupt
			 * is received and set back to false after the driver
			 * has determined that the hardware is out of reset.
			 *
			 * __ICE_RESET_OICR_RECV in pf->state indicates
			 * that a post reset rebuild is required before the
			 * driver is operational again. This is set above.
			 *
			 * As this is the start of the reset/rebuild cycle, set
			 * both to indicate that.
			 */
			hw->reset_ongoing = true;
		}
	}

	if (oicr & PFINT_OICR_HMC_ERR_M) {
		ena_mask &= ~PFINT_OICR_HMC_ERR_M;
		dev_dbg(dev, "HMC Error interrupt - info 0x%x, data 0x%x\n",
			rd32(hw, PFHMC_ERRORINFO),
			rd32(hw, PFHMC_ERRORDATA));
	}


	/* Report any remaining unexpected interrupts */
	oicr &= ena_mask;
	if (oicr) {
		dev_dbg(dev, "unhandled interrupt oicr=0x%08x\n", oicr);
		/* If a critical error is pending there is no choice but to
		 * reset the device.
		 */
		if (oicr & (PFINT_OICR_PE_CRITERR_M |
			    PFINT_OICR_PCI_EXCEPTION_M |
			    PFINT_OICR_ECC_ERR_M)) {
			set_bit(__ICE_PFR_REQ, pf->state);
			ice_service_task_schedule(pf);
		}
	}
	ret = IRQ_HANDLED;

	if (!test_bit(__ICE_DOWN, pf->state)) {
		ice_service_task_schedule(pf);
		ice_irq_dynamic_ena(hw, NULL, NULL);
	}

	return ret;
}

/**
 * ice_dis_ctrlq_interrupts - disable control queue interrupts
 * @hw: pointer to HW structure
 */
static void ice_dis_ctrlq_interrupts(struct ice_hw *hw)
{
	/* disable Admin queue Interrupt causes */
	wr32(hw, PFINT_FW_CTL,
	     rd32(hw, PFINT_FW_CTL) & ~PFINT_FW_CTL_CAUSE_ENA_M);

	/* disable Mailbox queue Interrupt causes */
	wr32(hw, PFINT_MBX_CTL,
	     rd32(hw, PFINT_MBX_CTL) & ~PFINT_MBX_CTL_CAUSE_ENA_M);


	/* disable Control queue Interrupt causes */
	wr32(hw, PFINT_OICR_CTL,
	     rd32(hw, PFINT_OICR_CTL) & ~PFINT_OICR_CTL_CAUSE_ENA_M);

	ice_flush(hw);
}

/**
 * ice_free_irq_msix_misc - Unroll misc vector setup
 * @pf: board private structure
 */
static void ice_free_irq_msix_misc(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	ice_dis_ctrlq_interrupts(hw);

	/* disable OICR interrupt */
	wr32(hw, PFINT_OICR_ENA, 0);
	ice_flush(hw);

	if (pf->msix_entries) {
		synchronize_irq(pf->msix_entries[pf->oicr_idx].vector);
		devm_free_irq(ice_pf_to_dev(pf),
			      pf->msix_entries[pf->oicr_idx].vector, pf);
	}

	pf->num_avail_sw_msix += 1;
	ice_free_res(pf->irq_tracker, pf->oicr_idx, ICE_RES_MISC_VEC_ID);
}

/**
 * ice_ena_ctrlq_interrupts - enable control queue interrupts
 * @hw: pointer to HW structure
 * @reg_idx: HW vector index to associate the control queue interrupts with
 */
static void ice_ena_ctrlq_interrupts(struct ice_hw *hw, u16 reg_idx)
{
	u32 val;

	val = ((reg_idx & PFINT_OICR_CTL_MSIX_INDX_M) |
	       PFINT_OICR_CTL_CAUSE_ENA_M);
	wr32(hw, PFINT_OICR_CTL, val);

	/* enable Admin queue Interrupt causes */
	val = ((reg_idx & PFINT_FW_CTL_MSIX_INDX_M) |
	       PFINT_FW_CTL_CAUSE_ENA_M);
	wr32(hw, PFINT_FW_CTL, val);

	/* enable Mailbox queue Interrupt causes */
	val = ((reg_idx & PFINT_MBX_CTL_MSIX_INDX_M) |
	       PFINT_MBX_CTL_CAUSE_ENA_M);
	wr32(hw, PFINT_MBX_CTL, val);


	ice_flush(hw);
}

/**
 * ice_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 */
static int ice_req_irq_msix_misc(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int oicr_idx, err = 0;

	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1, "%s-%s:misc",
			 dev_driver_string(dev), dev_name(dev));

	/* Do not request IRQ but do enable OICR interrupt since settings are
	 * lost during reset. Note that this function is called only during
	 * rebuild path and not while reset is in progress.
	 */
	if (ice_is_reset_in_progress(pf->state))
		goto skip_req_irq;

	/* reserve one vector in irq_tracker for misc interrupts */
	oicr_idx = ice_get_res(pf, pf->irq_tracker, 1, ICE_RES_MISC_VEC_ID);
	if (oicr_idx < 0)
		return oicr_idx;

	pf->num_avail_sw_msix -= 1;
	pf->oicr_idx = oicr_idx;

	err = devm_request_irq(dev, pf->msix_entries[pf->oicr_idx].vector,
			       ice_misc_intr, 0, pf->int_name, pf);
	if (err) {
		dev_err(dev, "devm_request_irq for %s failed: %d\n",
			pf->int_name, err);
		ice_free_res(pf->irq_tracker, 1, ICE_RES_MISC_VEC_ID);
		pf->num_avail_sw_msix += 1;
		return err;
	}

skip_req_irq:
	ice_ena_misc_vector(pf);

	ice_ena_ctrlq_interrupts(hw, pf->oicr_idx);
	wr32(hw, GLINT_ITR(ICE_RX_ITR, pf->oicr_idx),
	     ITR_REG_ALIGN(ICE_ITR_8K) >> ICE_ITR_GRAN_S);

	ice_flush(hw);
	ice_irq_dynamic_ena(hw, NULL, NULL);

	return 0;
}

/**
 * ice_napi_add - register NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be registered
 *
 * This function is only called in the driver's load path. Registering the NAPI
 * handler is done in ice_vsi_alloc_q_vector() for all other cases (i.e. resume,
 * reset/rebuild, etc.)
 */
static void ice_napi_add(struct ice_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, v_idx)
		netif_napi_add(vsi->netdev, &vsi->q_vectors[v_idx]->napi,
			       ice_napi_poll, NAPI_POLL_WEIGHT);
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * ice_vsi_cfg_netdev_tcf_qreg - Setup the netdev TCF configuration
 * @vsi: the VSI being configured
 * @ena_tcf: TCF map to be enabled
 *
 * This function configures netdev parameters for traffic classes associated
 * with queue regions.
 */
static void ice_vsi_cfg_netdev_tcf_qreg(struct ice_vsi *vsi, u8 ena_tcf)
{
	struct ice_tcf_qreg_cfg *tcf_qr_cfg = &vsi->tcf_qreg_cfg;
	struct net_device *netdev = vsi->netdev;
	int i;

	if (!netdev)
		return;

	if (!ena_tcf) {
		netdev_reset_tc(netdev);
		return;
	}

	if (netdev_set_num_tc(netdev, tcf_qr_cfg->num_qreg))
		return;

	for (i = 0; i < ICE_MAX_MQPRIO_TCF; i++)
		if (tcf_qr_cfg->ena_tcf & BIT(i))
			netdev_set_tc_queue(netdev,
					    tcf_qr_cfg->qreg_info[i].netdev_tc,
					    tcf_qr_cfg->qreg_info[i].qcount,
					    tcf_qr_cfg->qreg_info[i].qoffset);
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

/**
 * ice_set_ops - set netdev and ethtools ops for the given netdev
 * @netdev: netdev instance
 */
static void ice_set_ops(struct net_device *netdev)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);

	if (ice_is_safe_mode(pf)) {
		netdev->netdev_ops = &ice_netdev_safe_mode_ops;
		ice_set_ethtool_safe_mode_ops(netdev);
		return;
	}
	netdev->netdev_ops = &ice_netdev_ops;
	ice_set_ethtool_ops(netdev);
}

/**
 * ice_set_netdev_features - set features for the given netdev
 * @netdev: netdev instance
 */
static void ice_set_netdev_features(struct net_device *netdev)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	netdev_features_t csumo_features;
	netdev_features_t vlano_features;
	netdev_features_t dflt_features;
	netdev_features_t tso_features;

	if (ice_is_safe_mode(pf)) {
		/* safe mode */
		netdev->features = NETIF_F_SG | NETIF_F_HIGHDMA;
		netdev->hw_features = netdev->features;
		return;
	}

	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA	|
			NETIF_F_NTUPLE	|
			NETIF_F_RXHASH;

	csumo_features = NETIF_F_RXCSUM	  |
			 NETIF_F_IP_CSUM  |
			 NETIF_F_SCTP_CRC |
			 NETIF_F_IPV6_CSUM;

	vlano_features = NETIF_F_HW_VLAN_CTAG_FILTER |
			 NETIF_F_HW_VLAN_CTAG_TX     |
			 NETIF_F_HW_VLAN_CTAG_RX;

	tso_features = NETIF_F_TSO			|
		       NETIF_F_TSO_ECN			|
		       NETIF_F_TSO6			|
		       NETIF_F_GSO_GRE			|
		       NETIF_F_GSO_UDP_TUNNEL		|
#ifdef NETIF_F_GSO_GRE_CSUM
		       NETIF_F_GSO_GRE_CSUM		|
		       NETIF_F_GSO_UDP_TUNNEL_CSUM	|
#endif
#ifdef NETIF_F_GSO_PARTIAL
		       NETIF_F_GSO_PARTIAL		|
#endif
#ifdef NETIF_F_GSO_IPXIP4
		       NETIF_F_GSO_IPXIP4		|
		       NETIF_F_GSO_IPXIP6		|
#else
#ifdef NETIF_F_GSO_IPIP
		       NETIF_F_GSO_IPIP		|
		       NETIF_F_GSO_SIT		|
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
#ifdef NETIF_F_GSO_UDP_L4
		       NETIF_F_GSO_UDP_L4	|
#endif /* NETIF_F_GSO_UDP_L4 */
		       0;

#ifndef NETIF_F_GSO_PARTIAL
	tso_features ^= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#else
	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM |
					NETIF_F_GSO_GRE_CSUM;
#endif
	/* set features that user can change */
	netdev->hw_features = dflt_features | csumo_features |
			      vlano_features | tso_features;

#ifdef HAVE_MPLS_FEATURES
	/* add support for HW_CSUM on packets with MPLS header */
	netdev->mpls_features =  NETIF_F_HW_CSUM;
#endif /* HAVE_MPLS_FEATURES */

	/* enable features */
	netdev->features |= netdev->hw_features;
	/* encap and VLAN devices inherit default, csumo and tso features */
	netdev->hw_enc_features |= dflt_features | csumo_features |
				   tso_features;
	netdev->vlan_features |= dflt_features | csumo_features |
				 tso_features;

#ifdef NETIF_F_HW_TC
	netdev->hw_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */

#ifdef HAVE_NETDEV_SB_DEV
	/* Enable macvlan offloads */
	if (test_bit(ICE_FLAG_VMDQ_ENA, pf->flags))
		netdev->hw_features |= NETIF_F_HW_L2FW_DOFFLOAD;
#endif /* HAVE_NETDEV_SB_DEV */
}

/**
 * ice_cfg_netdev - Allocate, configure and register a netdev
 * @vsi: the VSI associated with the new netdev
 *
 * Returns 0 on success, negative value on failure
 */
static int ice_cfg_netdev(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_netdev_priv *np;
	struct net_device *netdev;
	u8 mac_addr[ETH_ALEN];
	int err;

#ifdef HAVE_NETDEV_SB_DEV
	/* Inform Kernel beforehand about max number of MACVLAN queues
	 * supported.
	 */
	netdev = alloc_etherdev_mqs(sizeof(*np),
				    ICE_MAX_MACVLANS + vsi->alloc_txq,
				    ICE_MAX_MACVLANS + vsi->alloc_rxq);
#else /* !HAVE_NETDEV_SB_DEV */
	netdev = alloc_etherdev_mqs(sizeof(*np), vsi->alloc_txq,
				    vsi->alloc_rxq);
#endif /* !HAVE_NETDEV_SB_DEV */
	if (!netdev)
		return -ENOMEM;

	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;

	ice_set_netdev_features(netdev);

	ice_set_ops(netdev);

	if (vsi->type == ICE_VSI_PF) {
		SET_NETDEV_DEV(netdev, ice_pf_to_dev(pf));
		ether_addr_copy(mac_addr, vsi->port_info->mac.perm_addr);
		ether_addr_copy(netdev->dev_addr, mac_addr);
		ether_addr_copy(netdev->perm_addr, mac_addr);
	}

	netdev->priv_flags |= IFF_UNICAST_FLT;

	/* Setup netdev TC information */
	ice_vsi_cfg_netdev_tc(vsi, vsi->tc_cfg.ena_tc);

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (!test_bit(ICE_FLAG_DCB_ENA, pf->flags))
		ice_vsi_cfg_netdev_tcf_qreg(vsi, vsi->tcf_qreg_cfg.ena_tcf);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = ETH_MIN_MTU;
	netdev->extended->max_mtu = ICE_MAX_MTU;
#else
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ICE_MAX_MTU;
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */

	err = register_netdev(vsi->netdev);
	if (err)
		return err;

	netif_carrier_off(vsi->netdev);

	/* make sure transmit queues start off as stopped */
	netif_tx_stop_all_queues(vsi->netdev);

	return 0;
}

/**
 * ice_fill_rss_lut - Fill the RSS lookup table with default values
 * @lut: Lookup table
 * @rss_table_size: Lookup table size
 * @rss_size: Range of queue number for hashing
 */
void ice_fill_rss_lut(u8 *lut, u16 rss_table_size, u16 rss_size)
{
	u16 i;

	for (i = 0; i < rss_table_size; i++)
		lut[i] = i % rss_size;
}

/**
 * ice_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct ice_vsi *
ice_pf_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi)
{
	return ice_vsi_setup(pf, pi, ICE_VSI_PF, ICE_INVAL_VFID, NULL, 0);
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static struct ice_vsi *
ice_chnl_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi,
		   struct ice_channel *ch)
{
	return ice_vsi_setup(pf, pi, ICE_VSI_CHNL, ICE_INVAL_VFID, ch, 0);
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_NETDEV_SB_DEV
/**
 * ice_macvlan_vsi_setup - Set up a MACVLAN VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct ice_vsi *
ice_macvlan_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi)
{
	return ice_vsi_setup(pf, pi, ICE_VSI_OFFLOAD_MACVLAN, ICE_INVAL_VFID,
			     NULL, 0);
}
#endif /* HAVE_NETDEV_SB_DEV */

/**
 * ice_ctrl_vsi_setup - Set up a control VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct ice_vsi *
ice_ctrl_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi)
{
	return ice_vsi_setup(pf, pi, ICE_VSI_CTRL, ICE_INVAL_VFID, NULL, 0);
}

/**
 * ice_lb_vsi_setup - Set up a loopback VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
struct ice_vsi *
ice_lb_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi)
{
	return ice_vsi_setup(pf, pi, ICE_VSI_LB, ICE_INVAL_VFID, NULL, 0);
}

/**
 * ice_vlan_rx_add_vid - Add a VLAN ID filter to HW offload
 * @netdev: network interface to be adjusted
 * @proto: unused protocol
 * @vid: VLAN ID to be added
 *
 * net_device_ops implementation for adding VLAN IDs
 */
static int
ice_vlan_rx_add_vid(struct net_device *netdev, __always_unused __be16 proto,
		    u16 vid)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	int ret;

	if (vid >= VLAN_N_VID) {
		netdev_err(netdev, "VLAN id requested %d is out of range %d\n",
			   vid, VLAN_N_VID);
		return -EINVAL;
	}

	if (vsi->info.pvid)
		return -EINVAL;

	/* VLAN 0 is added by default during load/reset */
	if (!vid)
		return 0;

	/* Enable VLAN pruning when a VLAN other than 0 is added */
	if (!ice_vsi_is_vlan_pruning_ena(vsi)) {
		ret = ice_cfg_vlan_pruning(vsi, true, false);
		if (ret)
			return ret;
	}

	 /* Add a switch rule for this VLAN ID so its corresponding VLAN tagged
	  * packets aren't pruned by the device's internal switch on Rx
	  */
	ret = ice_vsi_add_vlan(vsi, vid, ICE_FWD_TO_VSI);
	if (!ret) {
		vsi->vlan_ena = true;
		set_bit(ICE_VSI_FLAG_VLAN_FLTR_CHANGED, vsi->flags);
	}

	return ret;
}

/**
 * ice_vlan_rx_kill_vid - Remove a VLAN ID filter from HW offload
 * @netdev: network interface to be adjusted
 * @proto: unused protocol
 * @vid: VLAN ID to be removed
 *
 * net_device_ops implementation for removing VLAN IDs
 */
static int
ice_vlan_rx_kill_vid(struct net_device *netdev, __always_unused __be16 proto,
		     u16 vid)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	int ret;

	if (vsi->info.pvid)
		return -EINVAL;

	/* don't allow removal of VLAN 0 */
	if (!vid)
		return 0;

	/* Make sure ice_vsi_kill_vlan is successful before updating VLAN
	 * information
	 */
	ret = ice_vsi_kill_vlan(vsi, vid);
	if (ret)
		return ret;

	/* Disable pruning when VLAN 0 is the only VLAN rule */
	if (vsi->num_vlan == 1 && ice_vsi_is_vlan_pruning_ena(vsi))
		ret = ice_cfg_vlan_pruning(vsi, false, false);

	vsi->vlan_ena = false;
	set_bit(ICE_VSI_FLAG_VLAN_FLTR_CHANGED, vsi->flags);
	return ret;
}

/**
 * ice_pf_reset_stats - Reset all of the stats for the given PF
 * @pf: board private structure
 */
static void ice_pf_reset_stats(struct ice_pf *pf)
{
	memset(&pf->stats, 0, sizeof(pf->stats));
	memset(&pf->stats_prev, 0, sizeof(pf->stats_prev));
	pf->stat_prev_loaded = false;

	pf->hw_csum_rx_error = 0;
#ifdef ICE_ADD_PROBES
	pf->tcp_segs = 0;
	pf->udp_segs = 0;
	pf->tx_tcp_cso = 0;
	pf->tx_udp_cso = 0;
	pf->tx_sctp_cso = 0;
	pf->tx_ip4_cso = 0;
	pf->tx_l3_cso_err = 0;
	pf->tx_l4_cso_err = 0;
	pf->rx_tcp_cso = 0;
	pf->rx_udp_cso = 0;
	pf->rx_sctp_cso = 0;
	pf->rx_ip4_cso = 0;
	pf->rx_ip4_cso_err = 0;
	pf->rx_tcp_cso_err = 0;
	pf->rx_udp_cso_err = 0;
	pf->rx_sctp_cso_err = 0;
	pf->tx_vlano = 0;
	pf->rx_vlano = 0;
#endif
}


#ifdef HAVE_TC_INDIR_BLOCK
/**
 * ice_tc_indir_block_init - Initialize TC indirect block notifications
 * @vsi: VSI struct which has the netdev
 *
 * Returns 0 on success, negative value on failure
 */
static int ice_tc_indir_block_init(struct ice_vsi *vsi)
{
	struct ice_netdev_priv *np;

	if (!vsi || !vsi->netdev)
		return -EINVAL;

	np = netdev_priv(vsi->netdev);

	INIT_LIST_HEAD(&np->tc_indr_block_priv_list);
	np->netdevice_nb.notifier_call = ice_netdevice_event;
	return register_netdevice_notifier(&np->netdevice_nb);
}
#endif /* HAVE_TC_INDIR_BLOCK */

/**
 * ice_setup_pf_sw - Setup the HW switch on startup or after reset
 * @pf: board private structure
 *
 * Returns 0 on success, negative value on failure
 */
static int ice_setup_pf_sw(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *vsi;
	int status = 0;

	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;

	vsi = ice_pf_vsi_setup(pf, pf->hw.port_info);
	if (!vsi) {
		status = -ENOMEM;
		goto unroll_vsi_setup;
	}

	/* init channel list */
	INIT_LIST_HEAD(&vsi->ch_list);

	status = ice_cfg_netdev(vsi);
	if (status) {
		status = -ENODEV;
		goto unroll_vsi_setup;
	}
	/* netdev has to be configured before setting frame size */
	ice_vsi_cfg_frame_size(vsi);

#ifdef HAVE_TC_INDIR_BLOCK
	/* init indirect block notifications */
	status = ice_tc_indir_block_init(vsi);
	if (status) {
		dev_err(dev, "Failed to register netdev notifier\n");
		goto unroll_vsi_setup;
	}
#endif /* HAVE_TC_INDIR_BLOCK */

	/* Setup DCB netlink interface */
	ice_dcbnl_setup(vsi);

	/* registering the NAPI handler requires both the queues and
	 * netdev to be created, which are done in ice_pf_vsi_setup()
	 * and ice_cfg_netdev() respectively
	 */
	ice_napi_add(vsi);

	status = ice_set_cpu_rx_rmap(vsi);
	if (status) {
		dev_err(dev, "Failed to set CPU Rx map VSI %d error %d\n",
			vsi->vsi_num, status);
		status = -EINVAL;
		goto unroll_napi_add;
	}
	status = ice_init_mac_fltr(pf);
	if (status)
		goto free_cpu_rx_map;

	return status;

free_cpu_rx_map:
	ice_free_cpu_rx_rmap(vsi);

unroll_napi_add:
	if (vsi) {
#ifdef HAVE_TC_INDIR_BLOCK
		struct ice_netdev_priv *np = netdev_priv(vsi->netdev);
#endif /* HAVE_TC_INDIR_BLOCK */
		ice_napi_del(vsi);
#ifdef HAVE_TC_INDIR_BLOCK
		/* clean indirect TC block notifications */
		unregister_netdevice_notifier(&np->netdevice_nb);
#endif /* HAVE_TC_INDIR_BLOCK */
		if (vsi->netdev) {
			if (vsi->netdev->reg_state == NETREG_REGISTERED)
				unregister_netdev(vsi->netdev);
			free_netdev(vsi->netdev);
			vsi->netdev = NULL;
		}
	}

unroll_vsi_setup:
	if (vsi) {
		ice_vsi_free_q_vectors(vsi);
		ice_vsi_delete(vsi);
		ice_vsi_put_qs(vsi);
		ice_vsi_clear(vsi);
	}


	return status;
}

/**
 * ice_get_avail_q_count - Get count of queues in use
 * @pf_qmap: bitmap to get queue use count from
 * @lock: pointer to a mutex that protects access to pf_qmap
 * @size: size of the bitmap
 */
static u16
ice_get_avail_q_count(unsigned long *pf_qmap, struct mutex *lock, u16 size)
{
	u16 count = 0, bit;

	mutex_lock(lock);
	for_each_clear_bit(bit, pf_qmap, size)
		count++;
	mutex_unlock(lock);

	return count;
}

/**
 * ice_get_avail_txq_count - Get count of Tx queues in use
 * @pf: pointer to an ice_pf instance
 */
u16 ice_get_avail_txq_count(struct ice_pf *pf)
{
	return ice_get_avail_q_count(pf->avail_txqs, &pf->avail_q_mutex,
				     pf->max_pf_txqs);
}

/**
 * ice_get_avail_rxq_count - Get count of Rx queues in use
 * @pf: pointer to an ice_pf instance
 */
u16 ice_get_avail_rxq_count(struct ice_pf *pf)
{
	return ice_get_avail_q_count(pf->avail_rxqs, &pf->avail_q_mutex,
				     pf->max_pf_rxqs);
}

/**
 * ice_deinit_pf - Unrolls initialziations done by ice_init_pf
 * @pf: board private structure to initialize
 */
static void ice_deinit_pf(struct ice_pf *pf)
{
	ice_service_task_stop(pf);
	mutex_destroy(&pf->sw_mutex);
	mutex_destroy(&pf->tc_mutex);
	mutex_destroy(&pf->avail_q_mutex);

	if (pf->avail_txqs) {
		bitmap_free(pf->avail_txqs);
		pf->avail_txqs = NULL;
	}

	if (pf->avail_rxqs) {
		bitmap_free(pf->avail_rxqs);
		pf->avail_rxqs = NULL;
	}
}

/**
 * ice_set_pf_caps - set PFs capability flags
 * @pf: pointer to the PF instance
 */
static void ice_set_pf_caps(struct ice_pf *pf)
{
	struct ice_hw_func_caps *func_caps = &pf->hw.func_caps;

	clear_bit(ICE_FLAG_VMDQ_ENA, pf->flags);
	if (func_caps->common_cap.vmdq)
		set_bit(ICE_FLAG_VMDQ_ENA, pf->flags);
	clear_bit(ICE_FLAG_IWARP_ENA, pf->flags);
	clear_bit(ICE_FLAG_PEER_ENA, pf->flags);
	if (func_caps->common_cap.iwarp && IS_ENABLED(CONFIG_MFD_CORE)) {
		set_bit(ICE_FLAG_IWARP_ENA, pf->flags);
		set_bit(ICE_FLAG_PEER_ENA, pf->flags);
	}
	clear_bit(ICE_FLAG_DCB_CAPABLE, pf->flags);
	if (func_caps->common_cap.dcb)
		set_bit(ICE_FLAG_DCB_CAPABLE, pf->flags);
	clear_bit(ICE_FLAG_SRIOV_CAPABLE, pf->flags);
	if (func_caps->common_cap.sr_iov_1_1) {
		set_bit(ICE_FLAG_SRIOV_CAPABLE, pf->flags);
		pf->num_vfs_supported = min_t(int, func_caps->num_allocd_vfs,
					      ICE_MAX_VF_COUNT);
	}
	clear_bit(ICE_FLAG_RSS_ENA, pf->flags);
	if (func_caps->common_cap.rss_table_size)
		set_bit(ICE_FLAG_RSS_ENA, pf->flags);

	clear_bit(ICE_FLAG_FD_ENA, pf->flags);
	if (func_caps->fd_fltr_guar > 0 || func_caps->fd_fltr_best_effort > 0) {
		u16 unused;

		/* ctrl_vsi_idx will be set to a valid value when flow director
		 * is setup by ice_init_fdir
		 */
		pf->ctrl_vsi_idx = ICE_NO_VSI;
		set_bit(ICE_FLAG_FD_ENA, pf->flags);
		/* force guaranteed filter pool for PF */
		ice_alloc_fd_guar_item(&pf->hw, &unused,
				       func_caps->fd_fltr_guar);
		/* force shared filter pool for PF */
		ice_alloc_fd_shrd_item(&pf->hw, &unused,
				       func_caps->fd_fltr_best_effort);
	}

	pf->max_pf_txqs = func_caps->common_cap.num_txq;
	pf->max_pf_rxqs = func_caps->common_cap.num_rxq;
}

/**
 * ice_init_pf - Initialize general software structures (struct ice_pf)
 * @pf: board private structure to initialize
 */
static int ice_init_pf(struct ice_pf *pf)
{
	ice_set_pf_caps(pf);

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->tc_mutex);

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, ice_service_timer, 0);
	pf->serv_tmr_period = HZ;
	INIT_WORK(&pf->serv_task, ice_service_task);
	clear_bit(__ICE_SERVICE_SCHED, pf->state);

	mutex_init(&pf->avail_q_mutex);
	pf->avail_txqs = bitmap_zalloc(pf->max_pf_txqs, GFP_KERNEL);
	if (!pf->avail_txqs)
		return -ENOMEM;

	pf->avail_rxqs = bitmap_zalloc(pf->max_pf_rxqs, GFP_KERNEL);
	if (!pf->avail_rxqs) {
		devm_kfree(ice_pf_to_dev(pf), pf->avail_txqs);
		pf->avail_txqs = NULL;
		return -ENOMEM;
	}

	return 0;
}

/**
 * ice_ena_msix_range - Request a range of MSIX vectors from the OS
 * @pf: board private structure
 *
 * compute the number of MSIX vectors required (v_budget) and request from
 * the OS. Return the number of vectors reserved or negative on failure
 */
static int ice_ena_msix_range(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int v_left, v_actual, v_budget = 0;
	int needed, err, i;

	v_left = pf->hw.func_caps.common_cap.num_msix_vectors;

	/* reserve one vector for miscellaneous handler */
	needed = 1;
	if (v_left < needed)
		goto no_hw_vecs_left_err;
	v_budget += needed;
	v_left -= needed;

	/* reserve vectors for LAN traffic */
	needed = min_t(int, num_online_cpus(), v_left);
	if (v_left < needed)
		goto no_hw_vecs_left_err;
#ifdef HAVE_PF_RING
	if (RSS[pf->instance] != 0)
		needed = min_t(int, needed, RSS[pf->instance]);
#endif
	pf->num_lan_msix = needed;
	v_budget += needed;
	v_left -= needed;

	/* reserve one vector for flow director */
	if (test_bit(ICE_FLAG_FD_ENA, pf->flags)) {
		needed = ICE_FDIR_MSIX;
		if (v_left < needed)
			goto no_hw_vecs_left_err;
		v_budget += needed;
		v_left -= needed;
	}

#ifdef HAVE_NETDEV_SB_DEV
	/* reserve vectors for L2 offloads */
	if (test_bit(ICE_FLAG_VMDQ_ENA, pf->flags)) {
		needed = ICE_MAX_MACVLANS * ICE_DFLT_VEC_VMDQ_VSI;
		if (v_left < needed)
			goto no_hw_vecs_left_err;
		v_budget += needed;
		v_left -= needed;
	}
#endif /* HAVE_NETDEV_SB_DEV */

	/* reserve vectors for RDMA peer driver */
	if (test_bit(ICE_FLAG_IWARP_ENA, pf->flags)) {
		needed = ICE_RDMA_NUM_VECS;
		if (v_left < needed)
			goto no_hw_vecs_left_err;
		pf->num_rdma_msix = needed;
		v_budget += needed;
		v_left -= needed;
	}

	if (v_left < pf->num_vfs_supported * ICE_MIN_INTR_PER_VF) {
		pf->num_vfs_supported = v_left / ICE_MIN_INTR_PER_VF;
		dev_warn(dev, "Not enough MSI-X vectors, max %d VFs allowed\n",
			 pf->num_vfs_supported);
	} else {
		if (v_left < pf->num_vfs_supported * ICE_NUM_VF_MSIX_SMALL)
			dev_warn(dev, "Limited MSI-X vectors, max %d VFs recommended\n",
				 v_left / ICE_NUM_VF_MSIX_SMALL);
	}

	pf->msix_entries = devm_kcalloc(dev, v_budget,
					sizeof(*pf->msix_entries), GFP_KERNEL);

	if (!pf->msix_entries) {
		err = -ENOMEM;
		goto exit_err;
	}

	for (i = 0; i < v_budget; i++)
		pf->msix_entries[i].entry = i;

	/* actually reserve the vectors */
	v_actual = pci_enable_msix_range(pf->pdev, pf->msix_entries,
					 ICE_MIN_MSIX, v_budget);

	if (v_actual < 0) {
		dev_err(dev, "unable to reserve MSI-X vectors\n");
		err = v_actual;
		goto msix_err;
	}

	if (v_actual < v_budget) {
		dev_warn(dev, "not enough OS MSI-X vectors. requested = %d, obtained = %d\n",
			 v_budget, v_actual);
/* 2 vectors each for LAN and RDMA (traffic + OICR), one for flow director */
#define ICE_MIN_LAN_VECS 2
#define ICE_MIN_RDMA_VECS 2
#define ICE_MIN_VECS (ICE_MIN_LAN_VECS + ICE_MIN_RDMA_VECS + 1)

		if (v_actual < ICE_MIN_VECS) {
			/* error if we can't get minimum vectors */
			pci_disable_msix(pf->pdev);
			err = -ERANGE;
			goto msix_err;
		} else {
			pf->num_lan_msix = ICE_MIN_LAN_VECS;
			pf->num_rdma_msix = ICE_MIN_RDMA_VECS;
		}
	}

	return v_actual;

msix_err:
	devm_kfree(dev, pf->msix_entries);
	goto exit_err;

no_hw_vecs_left_err:
	dev_err(dev, "not enough device MSI-X vectors. requested = %d, available = %d\n",
		needed, v_left);
	err = -ERANGE;
exit_err:
	pf->num_lan_msix = 0;
	pf->num_rdma_msix = 0;
	return err;
}

/**
 * ice_dis_msix - Disable MSI-X interrupt setup in OS
 * @pf: board private structure
 */
static void ice_dis_msix(struct ice_pf *pf)
{
	pci_disable_msix(pf->pdev);
	devm_kfree(ice_pf_to_dev(pf), pf->msix_entries);
	pf->msix_entries = NULL;
}

/**
 * ice_clear_interrupt_scheme - Undo things done by ice_init_interrupt_scheme
 * @pf: board private structure
 */
static void ice_clear_interrupt_scheme(struct ice_pf *pf)
{
	ice_dis_msix(pf);

	if (pf->irq_tracker) {
		devm_kfree(ice_pf_to_dev(pf), pf->irq_tracker);
		pf->irq_tracker = NULL;
	}
}

/**
 * ice_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
static int ice_init_interrupt_scheme(struct ice_pf *pf)
{
	int vectors;

	vectors = ice_ena_msix_range(pf);

	if (vectors < 0)
		return vectors;

	/* set up vector assignment tracking */
	pf->irq_tracker =
		devm_kzalloc(ice_pf_to_dev(pf), sizeof(*pf->irq_tracker) +
			     (sizeof(u16) * vectors), GFP_KERNEL);
	if (!pf->irq_tracker) {
		ice_dis_msix(pf);
		return -ENOMEM;
	}

	/* populate SW interrupts pool with number of OS granted IRQs. */
	pf->num_avail_sw_msix = vectors;
	pf->irq_tracker->num_entries = vectors;
	pf->irq_tracker->end = pf->irq_tracker->num_entries;

	return 0;
}

/**
 * ice_is_wol_ena
 * @pf: board private structure
 *
 * Check if WoL is enabled or supported based on the HW configuration, and
 * used by the driver to set up Wake on LAN
 */
bool ice_is_wol_ena(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u16 wol_ctrl;

	/* NVM bit 1 means WoL disabled for the PF or port */
	if (ice_read_sr_word(hw, ICE_SR_NVM_WOL_CFG, &wol_ctrl))
		return false;

	return !(BIT(hw->pf_id) & wol_ctrl);
}

/**
 * ice_vsi_recfg_qs - Change the number of queues on a VSI
 * @vsi: VSI being changed
 * @new_rx: new number of Rx queues
 * @new_tx: new number of Tx queues
 *
 * Only change the number of queues if new_tx, or new_rx is non-0.
 *
 * Returns 0 on success.
 */
int ice_vsi_recfg_qs(struct ice_vsi *vsi, int new_rx, int new_tx)
{
	struct ice_pf *pf = vsi->back;
	int err = 0, timeout = 50;

	if (!new_rx && !new_tx)
		return -EINVAL;

	while (test_and_set_bit(__ICE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	if (new_tx)
		vsi->req_txq = new_tx;
	if (new_rx)
		vsi->req_rxq = new_rx;

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		ice_vsi_rebuild(vsi, false);
		dev_dbg(ice_pf_to_dev(pf), "Link is down, queue count change happens when link is brought up\n");
		goto done;
	}

	ice_vsi_close(vsi);
	ice_vsi_rebuild(vsi, false);
	ice_pf_dcb_recfg(pf);
	ice_vsi_open(vsi);
done:
	clear_bit(__ICE_CFG_BUSY, pf->state);
	return err;
}

/**
 * ice_log_pkg_init - log result of DDP package load
 * @hw: pointer to hardware info
 * @status: status of package load
 */
static void
ice_log_pkg_init(struct ice_hw *hw, enum ice_status *status)
{
	struct ice_pf *pf = (struct ice_pf *)hw->back;
	struct device *dev = ice_pf_to_dev(pf);

	switch (*status) {
	case ICE_SUCCESS:
		/* The package download AdminQ command returned success because
		 * this download succeeded or ICE_ERR_AQ_NO_WORK since there is
		 * already a package loaded on the device.
		 */
		if (hw->pkg_ver.major == hw->active_pkg_ver.major &&
		    hw->pkg_ver.minor == hw->active_pkg_ver.minor &&
		    hw->pkg_ver.update == hw->active_pkg_ver.update &&
		    hw->pkg_ver.draft == hw->active_pkg_ver.draft &&
		    !memcmp(hw->pkg_name, hw->active_pkg_name,
			    sizeof(hw->pkg_name))) {
			if (hw->pkg_dwnld_status == ICE_AQ_RC_EEXIST)
				dev_info(dev, "DDP package already present on device: %s version %d.%d.%d.%d\n",
					 hw->active_pkg_name,
					 hw->active_pkg_ver.major,
					 hw->active_pkg_ver.minor,
					 hw->active_pkg_ver.update,
					 hw->active_pkg_ver.draft);
			else
				dev_info(dev, "The DDP package was successfully loaded: %s version %d.%d.%d.%d\n",
					 hw->active_pkg_name,
					 hw->active_pkg_ver.major,
					 hw->active_pkg_ver.minor,
					 hw->active_pkg_ver.update,
					 hw->active_pkg_ver.draft);
		} else if (hw->active_pkg_ver.major != ICE_PKG_SUPP_VER_MAJ ||
			   hw->active_pkg_ver.minor != ICE_PKG_SUPP_VER_MNR) {
			dev_err(dev, "The device has a DDP package that is not supported by the driver.  The device has package '%s' version %d.%d.x.x.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
				hw->active_pkg_name,
				hw->active_pkg_ver.major,
				hw->active_pkg_ver.minor,
				ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			*status = ICE_ERR_NOT_SUPPORTED;
		} else if (hw->active_pkg_ver.major == ICE_PKG_SUPP_VER_MAJ &&
			   hw->active_pkg_ver.minor == ICE_PKG_SUPP_VER_MNR) {
			dev_info(dev, "The driver could not load the DDP package file because a compatible DDP package is already present on the device.  The device has package '%s' version %d.%d.%d.%d.  The package file found by the driver: '%s' version %d.%d.%d.%d.\n",
				 hw->active_pkg_name,
				 hw->active_pkg_ver.major,
				 hw->active_pkg_ver.minor,
				 hw->active_pkg_ver.update,
				 hw->active_pkg_ver.draft,
				 hw->pkg_name,
				 hw->pkg_ver.major,
				 hw->pkg_ver.minor,
				 hw->pkg_ver.update,
				 hw->pkg_ver.draft);
		} else {
			dev_err(dev, "An unknown error occurred when loading the DDP package, please reboot the system.  If the problem persists, update the NVM.  Entering Safe Mode.\n");
			*status = ICE_ERR_NOT_SUPPORTED;
		}
		break;
	case ICE_ERR_BUF_TOO_SHORT:
	case ICE_ERR_CFG:
		dev_err(dev, "The DDP package file is invalid. Entering Safe Mode.\n");
		break;
	case ICE_ERR_NOT_SUPPORTED:
		/* Package File version not supported */
		if (hw->pkg_ver.major > ICE_PKG_SUPP_VER_MAJ ||
		    (hw->pkg_ver.major == ICE_PKG_SUPP_VER_MAJ &&
		     hw->pkg_ver.minor > ICE_PKG_SUPP_VER_MNR))
			dev_err(dev, "The DDP package file version is higher than the driver supports.  Please use an updated driver.  Entering Safe Mode.\n");
		else if (hw->pkg_ver.major < ICE_PKG_SUPP_VER_MAJ ||
			 (hw->pkg_ver.major == ICE_PKG_SUPP_VER_MAJ &&
			  hw->pkg_ver.minor < ICE_PKG_SUPP_VER_MNR))
			dev_err(dev, "The DDP package file version is lower than the driver supports.  The driver requires version %d.%d.x.x.  Please use an updated DDP Package file.  Entering Safe Mode.\n",
				ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
		break;
	case ICE_ERR_AQ_ERROR:
		switch (hw->pkg_dwnld_status) {
		case ICE_AQ_RC_ENOSEC:
		case ICE_AQ_RC_EBADSIG:
			dev_err(dev, "The DDP package could not be loaded because its signature is not valid.  Please use a valid DDP Package.  Entering Safe Mode.\n");
			return;
		case ICE_AQ_RC_ESVN:
			dev_err(dev, "The DDP Package could not be loaded because its security revision is too low.  Please use an updated DDP Package.  Entering Safe Mode.\n");
			return;
		case ICE_AQ_RC_EBADMAN:
		case ICE_AQ_RC_EBADBUF:
			dev_err(dev, "An error occurred on the device while loading the DDP package.  The device will be reset.\n");
			return;
		default:
			break;
		}
		/* fall-through */
	default:
		dev_err(dev, "An unknown error (%d) occurred when loading the DDP package.  Entering Safe Mode.\n",
			*status);
		break;
	}
}

/**
 * ice_load_pkg - load/reload the DDP Package file
 * @firmware: firmware structure when firmware requested or NULL for reload
 * @pf: pointer to the PF instance
 *
 * Called on probe and post CORER/GLOBR rebuild to load DDP Package and
 * initialize HW tables.
 */
static void
ice_load_pkg(const struct firmware *firmware, struct ice_pf *pf)
{
	enum ice_status status = ICE_ERR_PARAM;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;

	/* Load DDP Package */
	if (firmware && !hw->pkg_copy) {
		status = ice_copy_and_init_pkg(hw, firmware->data,
					       firmware->size);
		ice_log_pkg_init(hw, &status);
	} else if (!firmware && hw->pkg_copy) {
		/* Reload package during rebuild after CORER/GLOBR reset */
		status = ice_init_pkg(hw, hw->pkg_copy, hw->pkg_size);
		ice_log_pkg_init(hw, &status);
	} else {
		dev_err(dev, "The DDP package file failed to load. Entering Safe Mode.\n");
	}

	if (status) {
		/* Safe Mode */
		clear_bit(ICE_FLAG_ADV_FEATURES, pf->flags);
		return;
	}

	/* Successful download package is the precondition for advanced
	 * features, hence setting the ICE_FLAG_ADV_FEATURES flag
	 */
	set_bit(ICE_FLAG_ADV_FEATURES, pf->flags);
}

/**
 * ice_prepare_for_safe_mode - Disable advanced features
 * @pf: board private structure
 *
 * If package download failed during reset, then driver clears
 * ICE_FLAG_ADV_FEATURES PF flag bit, and device is official in safe mode.
 * So, all advance features have to be disabled.
 */
static int ice_prepare_for_safe_mode(struct ice_pf *pf)
{
	struct ice_vsi *pf_vsi;
	u16 val;
	int err;

	/* Device not in Safe Mode, so bail out here */
	if (!ice_is_safe_mode(pf))
		return 0;

	pf_vsi = ice_get_main_vsi(pf);
	if (!pf_vsi)
		return -EINVAL;

	/* only one queue pair in safe mode */
	pf_vsi->req_txq = 1;
	pf_vsi->req_rxq = 1;

	/* remove RSS configuration */
	ice_rem_vsi_rss_list(&pf_vsi->back->hw, pf_vsi->idx);

	/* if the PF VSI was flow director enabled, disable it
	 * in the VSI context as we won't be doing flow director
	 * in safe mode. Not doing this causes the add VSI in
	 * ice_rebuild to fail.
	 */
	val = le16_to_cpu(pf_vsi->info.fd_options);
	val &= ~(ICE_AQ_VSI_FD_ENABLE | ICE_AQ_VSI_FD_PROG_ENABLE);
	pf_vsi->info.fd_options = cpu_to_le16(val);
	if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags))
		ice_free_vfs(pf);

#ifdef HAVE_NETDEV_SB_DEV
	if (test_bit(ICE_FLAG_MACVLAN_ENA, pf->flags)) {
		int v;

		ice_for_each_vsi(pf, v) {
			struct ice_vsi *vsi = pf->vsi[v];

			if (vsi && vsi->type == ICE_VSI_OFFLOAD_MACVLAN)
				ice_deinit_macvlan(vsi);
		}
	}
#endif /* HAVE_NETDEV_SB_DEV */

	/* Need to update netdev features, netdev ops and ethtool ops
	 * for safe mode, so free the PF netdev and setup a new one
	 */
	unregister_netdev(pf_vsi->netdev);
	free_netdev(pf_vsi->netdev);
	pf_vsi->netdev = NULL;

	ice_set_safe_mode_caps(&pf->hw);
	ice_set_pf_caps(pf);
	err = ice_cfg_netdev(pf_vsi);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "could not allocate netdev, err %d\n",
			err);
		return err;
	}

	return 0;
}


/**
 * ice_verify_cacheline_size - verify driver's assumption of 64 Byte cache lines
 * @pf: pointer to the PF structure
 *
 * There is no error returned here because the driver should be able to handle
 * 128 Byte cache lines, so we only print a warning in case issues are seen,
 * specifically with Tx.
 */
static void ice_verify_cacheline_size(struct ice_pf *pf)
{
	if (rd32(&pf->hw, GLPCI_CNF2) & GLPCI_CNF2_CACHELINE_SIZE_M)
		dev_warn(ice_pf_to_dev(pf), "%d Byte cache line assumption is invalid, driver may have Tx timeouts!\n",
			 ICE_CACHE_LINE_BYTES);
}

/**
 * ice_send_version - update firmware with driver version
 * @pf: PF struct
 *
 * Returns ICE_SUCCESS on success, else error code
 */
static enum ice_status ice_send_version(struct ice_pf *pf)
{
	struct ice_driver_ver dv;

	dv.major_ver = DRV_VERSION_MAJOR;
	dv.minor_ver = DRV_VERSION_MINOR;
	dv.build_ver = DRV_VERSION_BUILD;
	dv.subbuild_ver = 0;
	strscpy((char *)dv.driver_string, DRV_VERSION,
		sizeof(dv.driver_string));
	return ice_aq_send_driver_ver(&pf->hw, &dv, NULL);
}

/**
 * ice_init_fdir - Initialize flow director VSI and configuration
 * @pf: pointer to the PF instance
 *
 * returns 0 on success, negative on error
 */
static int ice_init_fdir(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *ctrl_vsi;
	int err;

	/* Side Band Flow Director needs to have a control VSI.
	 * Allocate it and store it in the PF.
	 */
	ctrl_vsi = ice_ctrl_vsi_setup(pf, pf->hw.port_info);
	if (!ctrl_vsi) {
		dev_dbg(dev, "could not create control VSI\n");
		return -ENOMEM;
	}

	err = ice_vsi_open_ctrl(ctrl_vsi);
	if (err) {
		dev_dbg(dev, "could not open control VSI\n");
		goto err_vsi_open;
	}

	mutex_init(&pf->hw.fdir_fltr_lock);

	err = ice_create_fdir_rule(pf, ICE_FLTR_PTYPE_NONF_IPV4_TCP);
	if (err)
		goto err_fdir_rule;

	err = ice_create_fdir_rule(pf, ICE_FLTR_PTYPE_NONF_IPV4_UDP);
	if (err)
		goto err_fdir_rule;

	err = ice_create_fdir_rule(pf, ICE_FLTR_PTYPE_NONF_IPV6_TCP);
	if (err)
		goto err_fdir_rule;

	err = ice_create_fdir_rule(pf, ICE_FLTR_PTYPE_NONF_IPV6_UDP);
	if (err)
		goto err_fdir_rule;

	return 0;

err_fdir_rule:
	ice_fdir_release_flows(&pf->hw);
	ice_vsi_close(ctrl_vsi);
err_vsi_open:
	ice_vsi_release(ctrl_vsi);
	if (pf->ctrl_vsi_idx != ICE_NO_VSI) {
		pf->vsi[pf->ctrl_vsi_idx] = NULL;
		pf->ctrl_vsi_idx = ICE_NO_VSI;
	}
	return err;
}

/**
 * ice_get_opt_fw_name - return optional firmware file name or NULL
 * @pf: pointer to the PF instance
 */
static char *ice_get_opt_fw_name(struct ice_pf *pf)
{
	/* Optional firmware name same as default with additional dash
	 * followed by a EUI-64 identifier (PCIe Device Serial Number)
	 */
	struct pci_dev *pdev = pf->pdev;
	char *opt_fw_filename = NULL;
	u32 dword;
	u8 dsn[8];
	int pos;

	/* Determine the name of the optional file using the DSN (two
	 * dwords following the start of the DSN Capability).
	 */
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DSN);
	if (pos) {
		opt_fw_filename = devm_kzalloc(ice_pf_to_dev(pf), NAME_MAX,
					       GFP_KERNEL);
		if (!opt_fw_filename)
			return NULL;

		pci_read_config_dword(pdev, pos + 4, &dword);
		put_unaligned_le32(dword, &dsn[0]);
		pci_read_config_dword(pdev, pos + 8, &dword);
		put_unaligned_le32(dword, &dsn[4]);
		snprintf(opt_fw_filename, NAME_MAX,
			 "%sice-%02x%02x%02x%02x%02x%02x%02x%02x.pkg",
			 ICE_DDP_PKG_PATH,
			 dsn[7], dsn[6], dsn[5], dsn[4],
			 dsn[3], dsn[2], dsn[1], dsn[0]);
	}

	return opt_fw_filename;
}

/**
 * ice_request_fw - Device initialization routine
 * @pf: pointer to the PF instance
 */
static void ice_request_fw(struct ice_pf *pf)
{
	char *opt_fw_filename = ice_get_opt_fw_name(pf);
	const struct firmware *firmware = NULL;
	struct device *dev = ice_pf_to_dev(pf);
	int err = 0;

	/* optional device-specific DDP (if present) overrides the default DDP
	 * package file. kernel logs a debug message if the file doesn't exist,
	 * and warning messages for other errors.
	 */
	if (opt_fw_filename) {
		err = firmware_request_nowarn(&firmware, opt_fw_filename, dev);
		if (err) {
			devm_kfree(dev, opt_fw_filename);
			goto dflt_pkg_load;
		}

		/* request for firmware was successful. Download to device */
		ice_load_pkg(firmware, pf);
		devm_kfree(dev, opt_fw_filename);
		release_firmware(firmware);
		return;
	}

dflt_pkg_load:
	err = request_firmware(&firmware, ICE_DDP_PKG_FILE, dev);
	if (err) {
		dev_err(dev, "The DDP package file was not found or could not be read. Entering Safe Mode\n");
		return;
	}

	/* request for firmware was successful. Download to device */
	ice_load_pkg(firmware, pf);
	release_firmware(firmware);
}

/**
 * ice_verify_eeprom - make sure eeprom is good to use
 * @pf: board private structure
 */
static void ice_verify_eeprom(struct ice_pf *pf)
{
	int err;

	err = ice_nvm_validate_checksum(&pf->hw);
	if (err) {
		set_bit(__ICE_BAD_EEPROM, pf->state);
		dev_err(ice_pf_to_dev(pf), "Bad EEPROM checksum detected, err %d, please update your NVM.\n",
			err);
	} else {
		clear_bit(__ICE_BAD_EEPROM, pf->state);
	}
}

/**
 * ice_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in ice_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int
ice_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *ent)
{
	struct device *dev = &pdev->dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int err;
#ifdef HAVE_PF_RING
	static u16 pfs_found;
#endif

	/* this driver uses devres, see Documentation/driver-model/devres.txt */
	err = pcim_enable_device(pdev);
	if (err)
		return err;

	err = pcim_iomap_regions(pdev, BIT(ICE_BAR0), pci_name(pdev));
	if (err) {
		dev_err(dev, "BAR0 I/O map error %d\n", err);
		return err;
	}


	pf = devm_kzalloc(dev, sizeof(*pf), GFP_KERNEL);
	if (!pf)
		return -ENOMEM;

	/* set up for high or low DMA */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(dev, "DMA configuration failed: 0x%x\n", err);
		return err;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(__ICE_DOWN, pf->state);
	/* Disable service task until DOWN bit is cleared */
	set_bit(__ICE_SERVICE_DIS, pf->state);

	hw = &pf->hw;
	hw->hw_addr = pcim_iomap_table(pdev)[ICE_BAR0];
	pci_save_state(pdev);

	hw->back = pf;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);
	ice_set_ctrlq_len(hw);

#ifdef HAVE_PF_RING
	pf->instance = pfs_found;
	pfs_found++;
#endif

	pf->msg_enable = netif_msg_init(debug, ICE_DFLT_NETIF_M);

#ifndef CONFIG_DYNAMIC_DEBUG
	if (debug < -1)
		hw->debug_mask = debug;
#endif

	/* check if device FW is in recovery mode */
	if (ice_get_fw_mode(hw) == ICE_FW_MODE_REC) {
		err = ice_probe_recovery_mode(pf);
		if (err)
			goto err_rec_mode;

		return 0;
	}

	ice_debugfs_pf_init(pf);


	err = ice_init_hw(hw);
	if (err) {
		dev_err(dev, "ice_init_hw failed: %d\n", err);
		err = -EIO;
		goto err_exit_unroll;
	}

	ice_request_fw(pf);

	/* if ice_request_fw fails, ICE_FLAG_ADV_FEATURES bit won't be
	 * set in pf->state, which will cause ice_is_safe_mode to return
	 * true
	 */
	if (ice_is_safe_mode(pf)) {
		/* we already got function/device capabilities but these don't
		 * reflect what the driver needs to do in safe mode. Instead of
		 * adding conditional logic everywhere to ignore these
		 * device/function capabilities, override them.
		 */
		ice_set_safe_mode_caps(hw);
	}

	err = ice_init_pf(pf);
	if (err) {
		dev_err(dev, "ice_init_pf failed: %d\n", err);
		goto err_init_pf_unroll;
	}
	ice_verify_eeprom(pf);
#ifndef ETHTOOL_GFECPARAM
	switch (pf->hw.port_info->phy.link_info.fec_info) {
	case (ICE_AQ_LINK_25G_RS_528_FEC_EN | ICE_AQ_LINK_25G_KR_FEC_EN):
	case (ICE_AQ_LINK_25G_RS_544_FEC_EN | ICE_AQ_LINK_25G_KR_FEC_EN):
		set_bit(ICE_FLAG_RS_FEC, pf->flags);
		set_bit(ICE_FLAG_BASE_R_FEC, pf->flags);
		break;
	case ICE_AQ_LINK_25G_RS_528_FEC_EN:
	case ICE_AQ_LINK_25G_RS_544_FEC_EN:
		set_bit(ICE_FLAG_RS_FEC, pf->flags);
		break;
	case ICE_AQ_LINK_25G_KR_FEC_EN:
		set_bit(ICE_FLAG_BASE_R_FEC, pf->flags);
		break;
	default:
		break;
	}
#endif /* ETHTOOL_GFECPARAM */
	if (hw->device_id == ICE_DEV_ID_E810C_BACKPLANE ||
	    hw->device_id == ICE_DEV_ID_E810C_QSFP ||
	    hw->device_id == ICE_DEV_ID_E810C_SFP)
		set_bit(ICE_FLAG_EXTERNAL_PHY, pf->flags);


	pf->num_alloc_vsi = hw->func_caps.guar_num_vsi;
	if (!pf->num_alloc_vsi) {
		err = -EIO;
		goto err_init_pf_unroll;
	}

	pf->vsi = devm_kcalloc(dev, pf->num_alloc_vsi, sizeof(*pf->vsi),
			       GFP_KERNEL);
	if (!pf->vsi) {
		err = -ENOMEM;
		goto err_init_pf_unroll;
	}

	err = ice_init_interrupt_scheme(pf);
	if (err) {
		dev_err(dev, "ice_init_interrupt_scheme failed: %d\n", err);
		err = -EIO;
		goto err_init_interrupt_unroll;
	}

	/* Driver is mostly up */
	clear_bit(__ICE_DOWN, pf->state);

	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
	err = ice_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "setup of misc vector failed: %d\n", err);
		goto err_init_interrupt_unroll;
	}


	/* create switch struct for the switch element created by FW on boot */
	pf->first_sw = devm_kzalloc(dev, sizeof(*pf->first_sw), GFP_KERNEL);
	if (!pf->first_sw) {
		err = -ENOMEM;
		goto err_msix_misc_unroll;
	}

	if (hw->evb_veb)
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEB;
	else
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEPA;

	pf->first_sw->pf = pf;

	/* record the sw_id available for later use */
	pf->first_sw->sw_id = hw->port_info->sw_id;

	err = ice_setup_pf_sw(pf);
	if (err) {
		dev_err(dev, "probe failed due to setup PF switch: %d\n", err);
		goto err_alloc_sw_unroll;
	}

	clear_bit(__ICE_SERVICE_DIS, pf->state);

#ifdef ADQ_PERF
	/* by default, set the PF level feature flags to be ON */
	set_bit(ICE_FLAG_CHNL_PKT_INSPECT_OPT_ENA, pf->flags);
#endif /* ADQ_PERF */

	/* tell the firmware we are up */
	err = ice_send_version(pf);
	if (err) {
		dev_err(dev, "probe failed sending driver version %s. error: %d\n",
			ice_drv_ver, err);
		goto err_alloc_sw_unroll;
	}

	/* since everything is good, start the service timer */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	err = ice_init_link_events(pf->hw.port_info);
	if (err) {
		dev_err(dev, "ice_init_link_events failed: %d\n", err);
		goto err_alloc_sw_unroll;
	}

	err = ice_init_phy_user_cfg(pf->hw.port_info);
	if (err) {
		dev_err(dev, "ice_init_phy_user_cfg failed: %d\n", err);
		goto err_alloc_sw_unroll;
	}
	ice_verify_cacheline_size(pf);

	/* If no DDP driven features have to be setup, return here */
	if (ice_is_safe_mode(pf))
		return 0;

	/* initialize DDP driven features */

	/* Enable WoL based on the HW capability */
	pf->wol_ena = ice_is_wol_ena(pf);
	device_set_wakeup_enable(dev, pf->wol_ena);


	/* Note: Flow director init failure is non-fatal to load */
	if (ice_init_fdir(pf))
		dev_err(dev, "could not initialize flow director\n");

	/* init peers only if supported */
	if (ice_is_peer_ena(pf)) {
		pf->peers = devm_kcalloc(dev, ICE_MAX_NUM_PEERS,
					 sizeof(*pf->peers), GFP_KERNEL);
		if (!pf->peers) {
			err = -ENOMEM;
			goto err_init_peer_unroll;
		}

		err = ice_init_peer_devices(pf);
		if (err) {
			dev_err(dev, "Failed to initialize peer devices: 0x%x\n",
				err);
			err = -EIO;
			goto err_init_peer_unroll;
		}
	} else {
		dev_warn(dev, "RDMA is not supported on this device\n");
	}

	/* Note: DCB init failure is non-fatal to load */
	if (ice_init_pf_dcb(pf, false)) {
		clear_bit(ICE_FLAG_DCB_CAPABLE, pf->flags);
		clear_bit(ICE_FLAG_DCB_ENA, pf->flags);
	} else {
		ice_cfg_lldp_mib_change(&pf->hw, true);
	}

	/* print PCI link speed and width */
	pcie_print_link_status(pf->pdev);

	return 0;

	/* Unwind non-managed device resources, etc. if something failed */
err_init_peer_unroll:
	if (ice_is_peer_ena(pf)) {
		ice_for_each_peer(pf, NULL, ice_unroll_peer);
		if (pf->peers) {
			devm_kfree(dev, pf->peers);
			pf->peers = NULL;
		}
	}
err_alloc_sw_unroll:
	set_bit(__ICE_SERVICE_DIS, pf->state);
	set_bit(__ICE_DOWN, pf->state);
	devm_kfree(dev, pf->first_sw);
err_msix_misc_unroll:
	ice_free_irq_msix_misc(pf);
err_init_interrupt_unroll:
	ice_clear_interrupt_scheme(pf);
	devm_kfree(dev, pf->vsi);
err_init_pf_unroll:
	ice_deinit_pf(pf);
	ice_deinit_hw(hw);
err_exit_unroll:
	ice_debugfs_pf_exit(pf);
err_rec_mode:
	pci_disable_pcie_error_reporting(pdev);
	devm_kfree(dev, pf);
	return err;
}


#ifdef HAVE_TC_INDIR_BLOCK
/**
 * ice_tc_indir_block_remove - clean indirect TC block notifications
 * @pf: PF structure
 */
static void ice_tc_indir_block_remove(struct ice_pf *pf)
{
	struct ice_vsi *pf_vsi = ice_get_main_vsi(pf);
	struct ice_netdev_priv *np;

	if (!pf_vsi)
		return;
	np = netdev_priv(pf_vsi->netdev);
	unregister_netdevice_notifier(&np->netdevice_nb);
	ice_indr_clean_block_privs(np);
}
#endif /* HAVE_TC_INDIR_BLOCK */

/**
 * ice_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void ice_remove(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	enum ice_close_reason reason;
	int i;

	if (!pf)
		return;

	/* __ICE_PREPPED_RECOVERY_MODE is set when the up and running
	 * driver transitions to recovery mode. If this is not set
	 * it means that the driver went into recovery mode on load.
	 * For the former case, go through the usual flow for module
	 * unload. For the latter, call ice_remove_recovery_mode
	 * and return.
	 */
	if (!test_bit(__ICE_PREPPED_RECOVERY_MODE, pf->state) &&
	    test_bit(__ICE_RECOVERY_MODE, pf->state)) {
		ice_remove_recovery_mode(pf);
		return;
	}

	for (i = 0; i < ICE_MAX_RESET_WAIT; i++) {
		if (!ice_is_reset_in_progress(pf->state))
			break;
		msleep(100);
	}
#ifdef HAVE_TC_INDIR_BLOCK
	/* clear indirect block notification before cleaning up of ADQ
	 * resources
	 */
	ice_tc_indir_block_remove(pf);
#endif /* HAVE_TC_INDIR_BLOCK */


	ice_service_task_stop(pf);
	if (ice_is_peer_ena(pf)) {
		reason = ICE_REASON_INTERFACE_DOWN;
		ice_for_each_peer(pf, &reason, ice_peer_close);
	}
	set_bit(__ICE_DOWN, pf->state);

	if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags))
		ice_free_vfs(pf);
	mutex_destroy(&(&pf->hw)->fdir_fltr_lock);
	if (!ice_is_safe_mode(pf))
		ice_remove_arfs(pf);
	ice_vsi_release_all(pf);
	if (ice_is_peer_ena(pf)) {
#if IS_ENABLED(CONFIG_MFD_CORE)
		ida_simple_remove(&ice_peer_index_ida, pf->peer_idx);
#endif
		ice_for_each_peer(pf, NULL, ice_unreg_peer_device);
		devm_kfree(&pdev->dev, pf->peers);
	}
	ice_free_irq_msix_misc(pf);
	ice_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;
		ice_vsi_free_q_vectors(pf->vsi[i]);
	}

	ice_deinit_pf(pf);
	ice_deinit_hw(&pf->hw);
	ice_debugfs_pf_exit(pf);
	/* Issue a PFR as part of the prescribed driver unload flow.  Do not
	 * do it via ice_schedule_reset() since there is no need to rebuild
	 * and the service task is already stopped.
	 */
	ice_reset(&pf->hw, ICE_RESET_PFR);
	pci_wait_for_pending_transaction(pdev);
	ice_clear_interrupt_scheme(pf);
	pci_disable_pcie_error_reporting(pdev);
}

/**
 * ice_prepare_for_shutdown - prep for PCI shutdown
 * @pf: board private structure
 *
 * Inform or close all dependent features in prep for PCI device shutdown
 */
static void ice_prepare_for_shutdown(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	u32 v;

	/* Notify VFs of impending reset */
	if (ice_check_sq_alive(hw, &hw->mailboxq))
		ice_vc_notify_reset(pf);

	dev_dbg(ice_pf_to_dev(pf), "Tearing down internal switch for shutdown\n");

	/* disable the VSIs and their queues that are not already DOWN */
	ice_pf_dis_all_vsi(pf, false);

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v])
			pf->vsi[v]->vsi_num = 0;

	ice_shutdown_all_ctrlq(hw);
}

/**
 * ice_setup_magic_mc_wake - setup device to wake on multicast magic packet
 * @pf: pointer to the PF struct
 *
 * Update the PRTPM_SAH/SAL registers with the MC_MAG_EN bit and
 * bit to preserve MAC and LAA WoL in case of PF reset
 */
static void ice_setup_mc_magic_wake(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi *vsi = NULL;
	enum ice_status status;
	u8 mac_addr[6];
	u8 flags = 0;
	u32 v;

	ice_for_each_vsi(pf, v)
		if (pf->vsi[v] && pf->vsi[v]->type == ICE_VSI_PF) {
			vsi = pf->vsi[v];
			break;
		}

	if (!vsi)
		return;

	/* Get current MAC address in case it's an LAA */
	if (vsi->netdev) {
		ether_addr_copy(mac_addr, vsi->netdev->dev_addr);
	} else {
		dev_err(dev, "Failed to retrieve MAC address; using default\n");
		ether_addr_copy(mac_addr, vsi->port_info->mac.perm_addr);
	}

	flags = ICE_AQC_MAN_MAC_WR_MC_MAG_EN |
		ICE_AQC_MAN_MAC_UPDATE_LAA_WOL |
		ICE_AQC_MAN_MAC_WR_WOL_LAA_PFR_KEEP;

	status = ice_aq_manage_mac_write(hw, mac_addr, flags, NULL);
	if (status)
		dev_err(dev, "Failed to enable Multicast Magic Packet wake up\n");
}

/**
 * ice_shutdown - PCI callback for shutting down device
 * @pdev: PCI device information struct
 */
static void ice_shutdown(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	struct ice_hw *hw = &pf->hw;
	enum ice_close_reason reason;
	int v;

	/* __ICE_PREPPED_RECOVERY_MODE is set when the up and running
	 * driver transitions to recovery mode. If this is not set
	 * it means that the driver went into recovery mode on load.
	 * For the former case, go through the usual flow for module
	 * unload. For the latter, call ice_remove_recovery_mode
	 * and return.
	 */
	if (!test_bit(__ICE_PREPPED_RECOVERY_MODE, pf->state) &&
	    test_bit(__ICE_RECOVERY_MODE, pf->state)) {
		ice_remove_recovery_mode(pf);
		return;
	}

	ice_service_task_stop(pf);

	if (ice_is_peer_ena(pf)) {
		reason = ICE_REASON_INTERFACE_DOWN;
		ice_for_each_peer(pf, &reason, ice_peer_close);
	}

	set_bit(__ICE_SUSPENDED, pf->state);
	set_bit(__ICE_DOWN, pf->state);

	if (!ice_is_safe_mode(pf) && pf->wol_ena)
		ice_setup_mc_magic_wake(pf);

	ice_vsi_release_all(pf);

	ice_prepare_for_shutdown(pf);

	if (ice_is_peer_ena(pf)) {
		int err;

#if IS_ENABLED(CONFIG_MFD_CORE)
		ida_simple_remove(&ice_peer_index_ida, pf->peer_idx);
#endif
		err = ice_for_each_peer(pf, NULL, ice_unreg_peer_device);
		if (err)
			dev_err(&pdev->dev, "Failed to remove peer devices: 0x%x\n",
				err);
	}
	if (!ice_is_safe_mode(pf)) {
		u32 val;

		val = rd32(hw, PFPM_APM);
		if (pf->wol_ena)
			val |= PFPM_APM_APME_M;
		else
			val &= ~PFPM_APM_APME_M;
		wr32(hw, PFPM_APM, val);

		val = rd32(hw, PFPM_WUFC);
		if (pf->wol_ena)
			val |= PFPM_WUFC_MAG_M;
		else
			val &= ~PFPM_WUFC_MAG_M;
		wr32(hw, PFPM_WUFC, val);
	}

	/* Free vectors, clear the interrupt scheme and release IRQs
	 * for proper shutdown, especially with large number of CPUs.
	 */
	ice_free_irq_msix_misc(pf);
	ice_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;
		ice_vsi_free_q_vectors(pf->vsi[v]);
	}
	pci_clear_master(pdev);
	ice_clear_interrupt_scheme(pf);

	if (!ice_is_safe_mode(pf) && system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, pf->wol_ena);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

#ifdef CONFIG_PM
/**
 * ice_reinit_interrupt_scheme - Reinitialize interrupt scheme
 * @pf: board private structure to reinitialize
 *
 * This routine reinitialize interrupt scheme that was cleared during
 * power management suspend callback.
 *
 * This should be called during resume routine to re-allocate the q_vectors
 * and reacquire interrupts.
 */
static int ice_reinit_interrupt_scheme(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int ret, v;

	/* Since we clear MSIX flag during suspend, we need to
	 * set it back during resume...
	 */

	ret = ice_init_interrupt_scheme(pf);
	if (ret) {
		dev_err(dev, "Failed to re-initialize interrupt %d\n", ret);
		return ret;
	}

	/* Remap vectors and rings, after successful re-init interrupts */
	ice_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;

		ret = ice_vsi_alloc_q_vectors(pf->vsi[v]);
		if (ret)
			goto err_reinit;
		ice_vsi_map_rings_to_vectors(pf->vsi[v]);
	}

	ret = ice_req_irq_msix_misc(pf);
	if (ret) {
		dev_err(dev, "Setting up misc vector failed after device suspend %d\n",
			ret);
		goto err_reinit;
	}

	return 0;

err_reinit:
	while (v--) {
		if (pf->vsi[v])
			ice_vsi_free_q_vectors(pf->vsi[v]);
	}

	return ret;
}

/**
 * ice_suspend
 * @dev: the net device pointer
 *
 * Power Management callback to move device into D3
 */
static int ice_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	enum ice_close_reason reason;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int disabled, v;
	u32 val;

	pf = pci_get_drvdata(pdev);

	if (!ice_pf_state_is_nominal(pf)) {
		dev_err(dev, "Device is not ready, no need to suspend it\n");
		return -EBUSY;
	}

	hw = &pf->hw;

	/* Stop watchdog tasks until resume completion.
	 * Even though it is most likely that the service task is
	 * disabled if the device is suspended or down, the service task's
	 * state is controlled by a different state bit, and we should
	 * store and honor whatever state that bit is in at this point.
	 */
	disabled = ice_service_task_stop(pf);

	reason = ICE_REASON_INTERFACE_DOWN;
	ice_for_each_peer(pf, &reason, ice_peer_close);

	/* Already suspended?, then there is nothing to do */
	if (test_and_set_bit(__ICE_SUSPENDED, pf->state)) {
		if (!disabled)
			ice_service_task_restart(pf);
		return 0;
	}

	if (test_bit(__ICE_DOWN, pf->state) ||
	    ice_is_reset_in_progress(pf->state)) {
		dev_err(ice_pf_to_dev(pf), "can't suspend device in reset or already down\n");
		if (!disabled)
			ice_service_task_restart(pf);
		return 0;
	}

	if (pf->wol_ena)
		ice_setup_mc_magic_wake(pf);

	ice_prepare_for_shutdown(pf);

	val = rd32(hw, PFPM_APM);
	if (pf->wol_ena)
		val |= PFPM_APM_APME_M;
	else
		val &= ~PFPM_APM_APME_M;
	wr32(hw, PFPM_APM, val);

	val = rd32(hw, PFPM_WUFC);
	if (pf->wol_ena)
		val |= PFPM_WUFC_MAG_M;
	else
		val &= ~PFPM_WUFC_MAG_M;
	wr32(hw, PFPM_WUFC, val);
	pci_wake_from_d3(pdev, pf->wol_ena);

	/* Free vectors, clear the interrupt scheme and release IRQs
	 * for proper hibernation, especially with large number of CPUs.
	 * Otherwise hibernation might fail when mapping all the vectors back
	 * to CPU0.
	 */
	ice_free_irq_msix_misc(pf);
	ice_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;
		ice_vsi_free_q_vectors(pf->vsi[v]);
	}
	ice_clear_interrupt_scheme(pf);

	return 0;
}

/**
 * ice_resume - PM callback for waking up from D3
 * @dev: generic device information structure
 */
static int ice_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	enum ice_reset_req reset_type;
	struct ice_pf *pf;
	int ret;

	pf = pci_get_drvdata(pdev);
	/* If we're not suspended?, then there is nothing to do */
	if (!test_and_set_bit(__ICE_SUSPENDED, pf->state))
		return 0;

	/* We cleared the interrupt scheme when we suspended, so we need to
	 * restore it now to resume device functionality.
	 */
	ret = ice_reinit_interrupt_scheme(pf);
	if (ret) {
		dev_err(&pdev->dev, "Cannot restore interrupt scheme: %d\n",
			ret);
	}

	ice_peer_refresh_msix(pf);

	clear_bit(__ICE_DOWN, pf->state);
	/* Now perform PF reset and rebuild */
	reset_type = ICE_RESET_PFR;
	/* re-enable service task for reset, but allow reset to schedule it */
	clear_bit(__ICE_SERVICE_DIS, pf->state);

	if (ice_schedule_reset(pf, reset_type))
		dev_err(&pdev->dev, "Reset during resume failed.\n");

	clear_bit(__ICE_SUSPENDED, pf->state);
	ice_service_task_restart(pf);

	/* Restart the service task */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	return 0;
}
#endif /* CONFIG_PM */

/**
 * ice_pci_err_detected - warning that PCI error has been detected
 * @pdev: PCI device information struct
 * @err: the type of PCI error
 *
 * Called to warn that something happened on the PCI bus and the error handling
 * is in progress.  Allows the driver to gracefully prepare/handle PCI errors.
 */
static pci_ers_result_t
ice_pci_err_detected(struct pci_dev *pdev, enum pci_channel_state err)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);

	if (!pf) {
		dev_err(&pdev->dev, "%s: unrecoverable device error %d\n",
			__func__, err);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	if (!test_bit(__ICE_SUSPENDED, pf->state)) {
		ice_service_task_stop(pf);

		if (!test_bit(__ICE_PREPARED_FOR_RESET, pf->state)) {
			set_bit(__ICE_PFR_REQ, pf->state);
			ice_prepare_for_reset(pf, ICE_RESET_PFR);
		}
	}

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * ice_pci_err_slot_reset - a PCI slot reset has just happened
 * @pdev: PCI device information struct
 *
 * Called to determine if the driver can recover from the PCI slot reset by
 * using a register read to determine if the device is recoverable.
 */
static pci_ers_result_t ice_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	pci_ers_result_t result;
	int err;
	u32 reg;

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot re-enable PCI device after reset, error %d\n",
			err);
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);
		pci_wake_from_d3(pdev, false);

		/* Check for life */
		reg = rd32(&pf->hw, GLGEN_RTRIG);
		if (!reg)
			result = PCI_ERS_RESULT_RECOVERED;
		else
			result = PCI_ERS_RESULT_DISCONNECT;
	}

	err = pci_cleanup_aer_uncorrect_error_status(pdev);
	if (err)
		dev_dbg(&pdev->dev, "pci_cleanup_aer_uncorrect_error_status failed, error %d\n",
			err);
		/* non-fatal, continue */

	return result;
}

/**
 * ice_pci_err_resume - restart operations after PCI error recovery
 * @pdev: PCI device information struct
 *
 * Called to allow the driver to bring things back up after PCI error and/or
 * reset recovery have finished
 */
static void ice_pci_err_resume(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);

	if (!pf) {
		dev_err(&pdev->dev, "%s failed, device is unrecoverable\n",
			__func__);
		return;
	}

	if (test_bit(__ICE_SUSPENDED, pf->state)) {
		dev_dbg(&pdev->dev, "%s failed to resume normal operations!\n",
			__func__);
		return;
	}

	ice_do_reset(pf, ICE_RESET_PFR);
	ice_service_task_restart(pf);
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));
}

#if defined(HAVE_PCI_ERROR_HANDLER_RESET_PREPARE) || defined(HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY) || defined(HAVE_RHEL7_PCI_RESET_NOTIFY)
/**
 * ice_pci_err_reset_prepare - prepare device driver for PCI reset
 * @pdev: PCI device information struct
 */
static void ice_pci_err_reset_prepare(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);

	if (!test_bit(__ICE_SUSPENDED, pf->state)) {
		ice_service_task_stop(pf);

		if (!test_bit(__ICE_PREPARED_FOR_RESET, pf->state)) {
			set_bit(__ICE_PFR_REQ, pf->state);
			ice_prepare_for_reset(pf, ICE_RESET_PFR);
		}
	}
}

/**
 * ice_pci_err_reset_done - PCI reset done, device driver reset can begin
 * @pdev: PCI device information struct
 */
static void ice_pci_err_reset_done(struct pci_dev *pdev)
{
	ice_pci_err_resume(pdev);
}
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_PREPARE || HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY || HAVE_RHEL7_PCI_RESET_NOTIFY */

#if defined(HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY) || (defined(HAVE_RHEL7_PCI_RESET_NOTIFY) && defined(HAVE_RHEL7_PCI_DRIVER_RH))
/**
 * ice_pci_err_reset_notify - notify device driver of pci reset
 * @pdev: PCI device information struct
 * @prepare: whether or not to prepare for reset or reset is complete
 *
 * Called to perform PF reset when a PCI function level reset is triggered
 */
static void ice_pci_err_reset_notify(struct pci_dev *pdev, bool prepare)
{
	if (prepare)
		ice_pci_err_reset_prepare(pdev);
	else
		ice_pci_err_reset_done(pdev);
}
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY || (HAVE_RHEL7_PCI_RESET_NOTIFY && HAVE_RHEL7_PCI_DRIVER_RH) */

/* ice_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id ice_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810C_BACKPLANE), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810C_QSFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810C_SFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810_XXV_BACKPLANE), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810_XXV_QSFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_E810_XXV_SFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_C822N_BACKPLANE), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_C822N_QSFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_C822N_SFP), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_C822N_10G_BASE_T), 0 },
	{ PCI_VDEVICE(INTEL, ICE_DEV_ID_C822N_SGMII), 0 },
	/* required last entry */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, ice_pci_tbl);

static __maybe_unused SIMPLE_DEV_PM_OPS(ice_pm_ops, ice_suspend, ice_resume);

#ifdef HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS
static const struct pci_error_handlers ice_pci_err_handler = {
#else
static struct pci_error_handlers ice_pci_err_handler = {
#endif /* HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS */
	.error_detected = ice_pci_err_detected,
	.slot_reset = ice_pci_err_slot_reset,
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY
	.reset_notify = ice_pci_err_reset_notify,
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY */
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
	.reset_prepare = ice_pci_err_reset_prepare,
	.reset_done = ice_pci_err_reset_done,
#endif /* HAVE_PCI_ERROR_HANDLER_RESET_PREPARE */
	.resume = ice_pci_err_resume
};

#ifdef HAVE_RHEL7_PCI_DRIVER_RH
static struct pci_driver_rh ice_driver_rh = {
#ifdef HAVE_RHEL7_PCI_RESET_NOTIFY
	.reset_notify = ice_pci_err_reset_notify,
#endif /* HAVE_RHEL7_PCI_RESET_NOTIFY */
};
#endif /* HAVE_RHEL7_PCI_DRIVER_RH */

static struct pci_driver ice_driver = {
	.name = KBUILD_MODNAME,
	.id_table = ice_pci_tbl,
	.probe = ice_probe,
	.remove = ice_remove,
#ifdef CONFIG_PM
	.driver   = {
		.pm = &ice_pm_ops,
	},
#endif /* CONFIG_PM */
	.shutdown = ice_shutdown,
	.sriov_configure = ice_sriov_configure,
#ifdef HAVE_RHEL7_PCI_DRIVER_RH
	.pci_driver_rh = &ice_driver_rh,
#endif /* HAVE_RHEL7_PCI_DRIVER_RH */
	.err_handler = &ice_pci_err_handler
};

/**
 * ice_module_init - Driver registration routine
 *
 * ice_module_init is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 */
static int __init ice_module_init(void)
{
	int status;

	pr_info("%s - version %s\n", ice_driver_string, ice_drv_ver);
	pr_info("%s\n", ice_copyright);

	ice_wq = alloc_workqueue("%s", WQ_MEM_RECLAIM, 0, KBUILD_MODNAME);
	if (!ice_wq) {
		pr_err("Failed to create workqueue\n");
		return -ENOMEM;
	}

#ifdef HAVE_RHEL7_PCI_DRIVER_RH
	/* The size member must be initialized in the driver via a call to
	 * set_pci_driver_rh_size before pci_register_driver is called
	 */
	set_pci_driver_rh_size(ice_driver_rh);

#endif /* HAVE_RHEL7_PCI_DRIVER_RH */

	ice_debugfs_init();

	status = pci_register_driver(&ice_driver);
	if (status) {
		pr_err("failed to register PCI driver, err %d\n", status);
		destroy_workqueue(ice_wq);
		ice_debugfs_exit();
#if IS_ENABLED(CONFIG_MFD_CORE)
		ida_destroy(&ice_peer_index_ida);
#endif
	}

	return status;
}
module_init(ice_module_init);

/**
 * ice_module_exit - Driver exit cleanup routine
 *
 * ice_module_exit is called just before the driver is removed
 * from memory.
 */
static void __exit ice_module_exit(void)
{
	pci_unregister_driver(&ice_driver);
	destroy_workqueue(ice_wq);
	ice_debugfs_exit();
	/* release all cached layer within ida tree, associated with
	 * ice_peer_index_ida object
	 */
#if IS_ENABLED(CONFIG_MFD_CORE)
	ida_destroy(&ice_peer_index_ida);
#endif
	pr_info("module unloaded\n");
}
module_exit(ice_module_exit);

/**
 * ice_set_mac_address - NDO callback to set MAC address
 * @netdev: network interface device structure
 * @pi: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 */
static int ice_set_mac_address(struct net_device *netdev, void *pi)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	struct sockaddr *addr = pi;
	enum ice_status status;
	u8 flags = 0;
	int err = 0;
	u8 *mac;

	mac = (u8 *)addr->sa_data;

	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac)) {
		netdev_warn(netdev, "already using mac %pM\n", mac);
		return 0;
	}

	if (test_bit(__ICE_DOWN, pf->state) ||
	    ice_is_reset_in_progress(pf->state)) {
		netdev_err(netdev, "can't set mac %pM. device not ready\n",
			   mac);
		return -EBUSY;
	}

	/* When we change the MAC address we also have to change the MAC address
	 * based filter rules that were created previously for the old MAC
	 * address. So first, we remove the old filter rule using ice_remove_mac
	 * and then create a new filter rule using ice_add_mac via
	 * ice_vsi_cfg_mac_fltr function call for both add and/or remove
	 * filters.
	 */
	status = ice_vsi_cfg_mac_fltr(vsi, netdev->dev_addr, false);
	if (status) {
		err = -EADDRNOTAVAIL;
		goto err_update_filters;
	}

	status = ice_vsi_cfg_mac_fltr(vsi, mac, true);
	if (status) {
		err = -EADDRNOTAVAIL;
		goto err_update_filters;
	}

err_update_filters:
	if (err) {
		netdev_err(netdev, "can't set MAC %pM. filter update failed\n",
			   mac);
		return err;
	}

	memcpy(netdev->dev_addr, mac, netdev->addr_len);
	/* change the netdev's MAC address */
	netdev_dbg(vsi->netdev, "updated MAC address to %pM\n",
		   netdev->dev_addr);

	/* write new MAC address to the firmware */
	flags = ICE_AQC_MAN_MAC_UPDATE_LAA_WOL;
	status = ice_aq_manage_mac_write(hw, mac, flags, NULL);
	if (status) {
		netdev_err(netdev, "can't set MAC %pM. write to firmware failed error %d\n",
			   mac, status);
	}
	return 0;
}

/**
 * ice_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 */
static void ice_set_rx_mode(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;

	if (!vsi)
		return;

	/* Set the flags to synchronize filters
	 * ndo_set_rx_mode may be triggered even without a change in netdev
	 * flags
	 */
	set_bit(ICE_VSI_FLAG_UMAC_FLTR_CHANGED, vsi->flags);
	set_bit(ICE_VSI_FLAG_MMAC_FLTR_CHANGED, vsi->flags);
	set_bit(ICE_FLAG_FLTR_SYNC, vsi->back->flags);

	/* schedule our worker thread which will take care of
	 * applying the new filter changes
	 */
	ice_service_task_schedule(vsi->back);
}

#ifdef HAVE_NDO_SET_TX_MAXRATE
/**
 * ice_set_tx_maxrate - NDO callback to set the maximum per-queue bitrate
 * @netdev: network interface device structure
 * @queue_index: Queue ID
 * @maxrate: maximum bandwidth in Mbps
 */
static int
ice_set_tx_maxrate(struct net_device *netdev, int queue_index, u32 maxrate)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	enum ice_status status;
	u16 q_handle;
	u8 tc;

	/* Validate maxrate requested is within permitted range */
	if (maxrate && (maxrate > (ICE_SCHED_MAX_BW / 1000))) {
		netdev_err(netdev, "Invalid max rate %d specified for the queue %d\n",
			   maxrate, queue_index);
		return -EINVAL;
	}

	q_handle = vsi->tx_rings[queue_index]->q_handle;
	tc = ice_dcb_get_tc(vsi, queue_index);

	/* Set BW back to default, when user set maxrate to 0 */
	if (!maxrate)
		status = ice_cfg_q_bw_dflt_lmt(vsi->port_info, vsi->idx, tc,
					       q_handle, ICE_MAX_BW);
	else
		status = ice_cfg_q_bw_lmt(vsi->port_info, vsi->idx, tc,
					  q_handle, ICE_MAX_BW, maxrate * 1000);
	if (status) {
		netdev_err(netdev, "Unable to set Tx max rate, error %d\n",
			   status);
		return -EIO;
	}

	return 0;
}
#endif /* HAVE_NDO_SET_TX_MAXRATE */

#ifdef HAVE_NDO_FDB_ADD_EXTACK
/**
 * ice_fdb_add - add an entry to the hardware database
 * @ndm: the input from the stack
 * @tb: pointer to array of nladdr (unused)
 * @dev: the net device pointer
 * @addr: the MAC address entry being added
 * @vid: VLAN ID
 * @flags: instructions from stack about fdb operation
 * @extack: netlink extended ack
 */
static int
ice_fdb_add(struct ndmsg *ndm, struct nlattr __always_unused *tb[],
	    struct net_device *dev, const unsigned char *addr, u16 vid,
	    u16 flags, struct netlink_ext_ack __always_unused *extack)
#elif defined(HAVE_NDO_FDB_ADD_VID)
static int
ice_fdb_add(struct ndmsg *ndm, struct nlattr __always_unused *tb[],
	    struct net_device *dev, const unsigned char *addr, u16 vid,
	    u16 flags)
#else
static int
ice_fdb_add(struct ndmsg *ndm, struct nlattr __always_unused *tb[],
	    struct net_device *dev, const unsigned char *addr, u16 flags)
#endif /* HAVE_NDO_FDB_ADD_VID */
{
	int err;

#ifdef HAVE_NDO_FDB_ADD_VID
	if (vid) {
		netdev_err(dev, "VLANs aren't supported yet for dev_uc|mc_add()\n");
		return -EINVAL;
	}
#endif
	if (ndm->ndm_state && !(ndm->ndm_state & NUD_PERMANENT)) {
		netdev_err(dev, "FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr))
		err = dev_uc_add_excl(dev, addr);
	else if (is_multicast_ether_addr(addr))
		err = dev_mc_add_excl(dev, addr);
	else
		err = -EINVAL;

	/* Only return duplicate errors if NLM_F_EXCL is set */
	if (err == -EEXIST && !(flags & NLM_F_EXCL))
		err = 0;

	return err;
}

#ifdef HAVE_NDO_FDB_ADD_VID
/**
 * ice_fdb_del - delete an entry from the hardware database
 * @ndm: the input from the stack
 * @tb: pointer to array of nladdr (unused)
 * @dev: the net device pointer
 * @addr: the MAC address entry being added
 * @vid: VLAN ID
 */
static int
ice_fdb_del(struct ndmsg *ndm, __always_unused struct nlattr *tb[],
	    struct net_device *dev, const unsigned char *addr,
	    __always_unused u16 vid)
#else
static int
ice_fdb_del(struct ndmsg *ndm, __always_unused struct nlattr *tb[],
	    struct net_device *dev, const unsigned char *addr)
#endif
{
	int err;

	if (ndm->ndm_state & NUD_PERMANENT) {
		netdev_err(dev, "FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr))
		err = dev_uc_del(dev, addr);
	else if (is_multicast_ether_addr(addr))
		err = dev_mc_del(dev, addr);
	else
		err = -EINVAL;

	return err;
}

#ifdef HAVE_NETDEV_SB_DEV
/**
 * ice_vsi_cfg_netdev_tc0 - Setup the netdev TC 0 configuration
 * @vsi: the VSI being configured
 *
 * This function configures netdev parameters for traffic class 0
 */
int ice_vsi_cfg_netdev_tc0(struct ice_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	int ret;

	if (!netdev)
		return -EINVAL;

	ret = netdev_set_num_tc(netdev, 1);
	if (ret) {
		netdev_err(netdev, "Error setting num TC\n");
		return ret;
	}

	/* Set queue information for lowerdev */
	ret = netdev_set_tc_queue(netdev, 0, vsi->num_txq, 0);
	if (ret) {
		netdev_err(netdev, "Error setting TC queue\n");
		goto set_tc_queue_err;
	}

	return 0;
set_tc_queue_err:
	netdev_set_num_tc(netdev, 0);
	return ret;
}

/**
 * ice_fwd_add_macvlan - Configure MACVLAN interface
 * @netdev: Main net device to configure
 * @vdev: MACVLAN subordinate device
 */
static void *
ice_fwd_add_macvlan(struct net_device *netdev, struct net_device *vdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *parent_vsi = np->vsi, *vsi;
	struct ice_pf *pf = parent_vsi->back;
	struct ice_macvlan *mv = NULL;
	int avail_id, ret, offset, i;
	enum ice_status status;
	struct device *dev;
	u8 mac[ETH_ALEN];

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		netdev_err(netdev, "Can't do MACVLAN offload. Device is in Safe Mode\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (pf->num_macvlan == pf->max_num_macvlan) {
		netdev_err(netdev, "MACVLAN offload limit reached\n");
		return ERR_PTR(-ENOSPC);
	}

	if (vdev->num_rx_queues != 1 || vdev->num_tx_queues != 1) {
		netdev_err(netdev, "Can't do MACVLAN offload. %s has multiple queues\n",
			   vdev->name);
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (ice_get_avail_txq_count(pf) < ICE_DFLT_TXQ_VMDQ_VSI ||
	    ice_get_avail_rxq_count(pf) < ICE_DFLT_RXQ_VMDQ_VSI) {
		netdev_err(netdev, "Can't do MACVLAN offload. Not enough queues\n");
		return ERR_PTR(-ENOSPC);
	}

	avail_id = find_first_zero_bit(pf->avail_macvlan, pf->max_num_macvlan);

	vsi = ice_macvlan_vsi_setup(pf, pf->hw.port_info);
	if (!vsi) {
		netdev_err(netdev, "Failed to create MACVLAN offload (VMDQ) VSI\n");
		return ERR_PTR(-EIO);
	}


	pf->num_macvlan++;
	offset = parent_vsi->alloc_txq + avail_id;

	ret = netdev_set_sb_channel(vdev, avail_id + 1);
	if (ret) {
		netdev_err(netdev, "Error setting netdev_set_sb_channel %d\n",
			   ret);
		goto set_sb_channel_err;
	}

	/* configure sbdev with the number of queues and offset within PF
	 * queues range
	 */
	ret = netdev_bind_sb_channel_queue(netdev, vdev, 0, vsi->num_txq,
					   offset);
	if (ret) {
		netdev_err(netdev, "Error setting netdev_bind_sb_channel_queue %d\n",
			   ret);
		goto bind_sb_channel_err;
	}

	vsi->netdev = vdev;
	/* Set MACVLAN ring in root device Tx rings */
	ice_for_each_txq(vsi, i)
		parent_vsi->tx_rings[offset + i] = vsi->tx_rings[i];

	ice_napi_add(vsi);

	ret = ice_vsi_open(vsi);
	if (ret)
		goto vsi_open_err;

	ether_addr_copy(mac, vdev->dev_addr);
	status = ice_vsi_cfg_mac_fltr(vsi, mac, true);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		dev_info(dev, "can't add MAC filters %pM for VSI %d, error %s\n",
			 mac, vsi->idx, ice_stat_str(status));
	} else if (status) {
		dev_err(dev, "can't add MAC filters %pM for VSI %d, error %s\n",
			mac, vsi->idx, ice_stat_str(status));
		ret = -ENOMEM;
		goto add_mac_err;
	}

	mv = devm_kzalloc(dev, sizeof(*mv), GFP_KERNEL);
	if (!mv) {
		ret = -ENOMEM;
		goto mv_init_err;
	}
	INIT_LIST_HEAD(&mv->list);
	mv->parent_vsi = parent_vsi;
	mv->vsi = vsi;
	mv->id = avail_id;
	mv->vdev = vdev;
	ether_addr_copy(mv->mac, mac);
	list_add(&mv->list, &pf->macvlan_list);

	set_bit(avail_id, pf->avail_macvlan);
	netdev_info(netdev, "MACVLAN offloads for %s are on\n", vdev->name);
	return mv;

mv_init_err:
	ice_remove_vsi_fltr(&pf->hw, vsi->idx);
add_mac_err:
	ice_vsi_close(vsi);
vsi_open_err:
	ice_napi_del(vsi);
	vsi->netdev = NULL;
	netdev_unbind_sb_channel(netdev, vdev);
bind_sb_channel_err:
	netdev_set_sb_channel(vdev, 0);
set_sb_channel_err:
	pf->num_macvlan--;
	ice_vsi_release(vsi);
	return ERR_PTR(ret);
}

/**
 * ice_fwd_del_macvlan - Delete MACVLAN interface resources
 * @netdev: Main net device
 * @accel_priv: MACVLAN sub ordinate device
 */
static void ice_fwd_del_macvlan(struct net_device *netdev, void *accel_priv)
{
	struct ice_macvlan *mv = (struct ice_macvlan *)accel_priv;
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *parent_vsi = np->vsi;
	struct ice_pf *pf = parent_vsi->back;
	struct net_device *vdev = mv->vdev;

	netdev_unbind_sb_channel(netdev, vdev);
	netdev_set_sb_channel(vdev, 0);

	ice_vsi_release(mv->vsi);
	parent_vsi->tx_rings[parent_vsi->num_txq + mv->id] = NULL;

	pf->num_macvlan--;

	clear_bit(mv->id, pf->avail_macvlan);
	list_del(&mv->list);
	devm_kfree(ice_pf_to_dev(pf), mv);

	netdev_info(netdev, "MACVLAN offloads for %s are off\n", vdev->name);
}

/**
 * ice_init_macvlan - Configure PF VSI to be able to offload MACVLAN
 * @vsi: Main VSI pointer where sb_dev is attached to
 * @init: Set to false when called in replay path otherwise true
 */
static int ice_init_macvlan(struct ice_vsi *vsi, bool init)
{
	struct net_device *netdev = vsi->netdev;
	struct ice_pf *pf = vsi->back;
	struct ice_ring **tmp_ring;
	unsigned int total_rings;
	struct device *dev;
	int i, ret;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_FLAG_VMDQ_ENA, pf->flags)) {
		dev_err(dev, "MACVLAN offload cannot be supported - VMDQ is disabled\n");
		return -EPERM;
	}

	if (ice_is_safe_mode(pf)) {
		dev_err(dev, "MACVLAN offload cannot be configured - Device is in Safe Mode\n");
		return -EOPNOTSUPP;
	}

#ifdef NETIF_F_HW_TC
	if (ice_is_adq_active(pf)) {
		dev_err(dev, "MACVLAN offload cannot be configured - ADQ is active. Delete ADQ configs using TC and try again\n");
		return -EOPNOTSUPP;
	}
#endif /* NETIF_F_HW_TC */

	pf->max_num_macvlan = min3(ice_get_avail_txq_count(pf),
				   ice_get_avail_rxq_count(pf),
				   (u16)ICE_MAX_MACVLANS);

	total_rings = vsi->alloc_txq + pf->max_num_macvlan;

	/* Allocate struct capable of holding Tx rings and MACVLAN rings */
	tmp_ring = devm_kcalloc(dev, total_rings, sizeof(**tmp_ring),
				GFP_KERNEL);
	if (!tmp_ring) {
		ret = -ENOMEM;
		goto alloc_ring_err;
	}

	/* Set existing rings to new struct */
	for (i = 0; i < vsi->alloc_txq; i++)
		tmp_ring[i] = vsi->tx_rings[i];
	vsi->base_tx_rings = vsi->tx_rings;
	vsi->tx_rings = tmp_ring;

	if (!init)
		return 0;

	ret = netif_set_real_num_tx_queues(netdev, total_rings);
	if (ret) {
		netdev_err(netdev, "Error setting real num queue\n");
		goto set_num_real_txq_err;
	}

#ifdef NETIF_F_HW_TC
	if (!ice_is_adq_active(pf)) {
		ret = ice_vsi_cfg_netdev_tc0(vsi);
		if (ret)
			goto set_num_tc_err;
	}
#else
	ret = ice_vsi_cfg_netdev_tc0(vsi);
	if (ret)
		goto set_num_tc_err;
#endif /* NETIF_F_HW_TC */

	INIT_LIST_HEAD(&pf->macvlan_list);
	set_bit(ICE_FLAG_MACVLAN_ENA, pf->flags);

	return 0;

set_num_tc_err:
	netif_set_real_num_tx_queues(netdev, vsi->num_txq);
set_num_real_txq_err:
	vsi->tx_rings = vsi->base_tx_rings;
	vsi->base_tx_rings = NULL;
	devm_kfree(dev, tmp_ring);
alloc_ring_err:
	pf->max_num_macvlan = 0;
	return ret;
}

/**
 * ice_deinit_macvlan - Release and cleanup MACVLAN resources
 * @vsi: Main VSI pointer where sb_dev is attached to
 */
static void ice_deinit_macvlan(struct ice_vsi *vsi)
{
	struct ice_macvlan *mv, *mv_tmp;
	struct ice_pf *pf = vsi->back;
	struct ice_ring **tmp_ring;

	clear_bit(ICE_FLAG_MACVLAN_ENA, pf->flags);

	/* Remove offload from existing MACVLANs; clear software book-keeping
	 * structures and reclaim hardware resources
	 */
	list_for_each_entry_safe(mv, mv_tmp, &pf->macvlan_list, list) {
		ice_vsi_cfg_mac_fltr(mv->vsi, mv->mac, false);
		macvlan_release_l2fw_offload(mv->vdev);
		ice_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
	}

#ifdef NETIF_F_HW_TC
	if (!ice_is_adq_active(pf))
		netdev_set_num_tc(vsi->netdev, 0);
#else
	netdev_set_num_tc(vsi->netdev, 0);
#endif /* NETIF_F_HW_TC */
	netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
	pf->max_num_macvlan = 0;

	/* Restore original Tx rings */
	tmp_ring = vsi->tx_rings;
	vsi->tx_rings = vsi->base_tx_rings;
	devm_kfree(ice_pf_to_dev(pf), tmp_ring);
}

/**
 * ice_vsi_replay_macvlan - Configure MACVLAN netdev settings after reset
 * @pf: board private structure
 */
static void ice_vsi_replay_macvlan(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_macvlan *mv, *mv_temp;

	list_for_each_entry_safe(mv, mv_temp, &pf->macvlan_list, list) {
		struct ice_vsi *vsi = mv->parent_vsi;
		int offset = vsi->alloc_txq + mv->id;
		int ret = 0, i;

		ice_for_each_txq(mv->vsi, i)
			vsi->tx_rings[offset + i] = mv->vsi->tx_rings[i];

		ret = netdev_set_sb_channel(mv->vdev, mv->id + 1);
		if (ret) {
			dev_dbg(dev, "Error setting netdev_set_sb_channel %d\n",
				ret);
			/* Do not return error, try to configure as many as
			 * possible
			 */
			ice_vsi_cfg_mac_fltr(mv->vsi, mv->mac, false);
			macvlan_release_l2fw_offload(mv->vdev);
			ice_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
			continue;
		}

		ret = netdev_bind_sb_channel_queue(vsi->netdev, mv->vdev, 0,
						   mv->vsi->num_txq, offset);
		if (ret) {
			dev_dbg(dev, "Error setting netdev_bind_sb_channel_queue %d\n",
				ret);
			/* Do not return error, try to configure as many as
			 * possible
			 */
			ice_vsi_cfg_mac_fltr(mv->vsi, mv->mac, false);
			macvlan_release_l2fw_offload(mv->vdev);
			ice_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
			continue;
		}
	}
}
#endif /* HAVE_NETDEV_SB_DEV */

/**
 * ice_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int
ice_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	int ret = 0;

	/* Don't set any netdev advance features with device in Safe Mode */
	if (ice_is_safe_mode(vsi->back)) {
		dev_err(ice_pf_to_dev(vsi->back), "Device is in Safe Mode - not enabling advance netdev features\n");
		return ret;
	}

	/* Do not change setting during reset */
	if (ice_is_reset_in_progress(pf->state)) {
		dev_err(ice_pf_to_dev(vsi->back), "Device is resetting, changing advanced netdev features temporarily unavailable.\n");
		return -EBUSY;
	}

	/* Multiple features can be changed in one call so keep features in
	 * separate if/else statements to guarantee each feature is checked
	 */
	if (features & NETIF_F_RXHASH && !(netdev->features & NETIF_F_RXHASH))
		ret = ice_vsi_manage_rss_lut(vsi, true);
	else if (!(features & NETIF_F_RXHASH) &&
		 netdev->features & NETIF_F_RXHASH)
		ret = ice_vsi_manage_rss_lut(vsi, false);

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    !(netdev->features & NETIF_F_HW_VLAN_CTAG_RX))
		ret = ice_vsi_manage_vlan_stripping(vsi, true);
	else if (!(features & NETIF_F_HW_VLAN_CTAG_RX) &&
		 (netdev->features & NETIF_F_HW_VLAN_CTAG_RX))
		ret = ice_vsi_manage_vlan_stripping(vsi, false);

	if ((features & NETIF_F_HW_VLAN_CTAG_TX) &&
	    !(netdev->features & NETIF_F_HW_VLAN_CTAG_TX))
		ret = ice_vsi_manage_vlan_insertion(vsi);
	else if (!(features & NETIF_F_HW_VLAN_CTAG_TX) &&
		 (netdev->features & NETIF_F_HW_VLAN_CTAG_TX))
		ret = ice_vsi_manage_vlan_insertion(vsi);

	if ((features & NETIF_F_HW_VLAN_CTAG_FILTER) &&
	    !(netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER))
		ret = ice_cfg_vlan_pruning(vsi, true, false);
	else if (!(features & NETIF_F_HW_VLAN_CTAG_FILTER) &&
		 (netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER))
		ret = ice_cfg_vlan_pruning(vsi, false, false);
#ifdef HAVE_NETDEV_SB_DEV

	if ((features & NETIF_F_HW_L2FW_DOFFLOAD) &&
	    !(netdev->features & NETIF_F_HW_L2FW_DOFFLOAD))
		ret = ice_init_macvlan(vsi, true);
	else if (!(features & NETIF_F_HW_L2FW_DOFFLOAD) &&
		 (netdev->features & NETIF_F_HW_L2FW_DOFFLOAD))
		ice_deinit_macvlan(vsi);
#endif /* HAVE_NETDEV_SB_DEV */

	if ((features & NETIF_F_NTUPLE) &&
	    !(netdev->features & NETIF_F_NTUPLE)) {
		ice_vsi_manage_fdir(vsi, true);
		ice_init_arfs(vsi);
	} else if (!(features & NETIF_F_NTUPLE) &&
		 (netdev->features & NETIF_F_NTUPLE)) {
		ice_vsi_manage_fdir(vsi, false);
		ice_clear_arfs(vsi);
	}

#ifdef NETIF_F_HW_TC
	/* don't turn off hw_tc_offload when ADQ is already enabled */
	if (!(features & NETIF_F_HW_TC) && ice_is_adq_active(pf)) {
		dev_err(ice_pf_to_dev(pf), "ADQ is active, can't turn hw_tc_offload off\n");
		return -EACCES;
	}

	if ((features & NETIF_F_HW_TC) &&
	    !(netdev->features & NETIF_F_HW_TC))
		set_bit(ICE_FLAG_CLS_FLOWER, pf->flags);
	else
		clear_bit(ICE_FLAG_CLS_FLOWER, pf->flags);
#endif /* NETIF_F_HW_TC */

	return ret;
}

/**
 * ice_vsi_vlan_setup - Setup VLAN offload properties on a VSI
 * @vsi: VSI to setup VLAN properties for
 */
static int ice_vsi_vlan_setup(struct ice_vsi *vsi)
{
	int ret = 0;

	if (vsi->netdev->features & NETIF_F_HW_VLAN_CTAG_RX)
		ret = ice_vsi_manage_vlan_stripping(vsi, true);
	if (vsi->netdev->features & NETIF_F_HW_VLAN_CTAG_TX)
		ret = ice_vsi_manage_vlan_insertion(vsi);

	return ret;
}

#ifdef HAVE_PF_RING

void ice_update_ena_itr(struct ice_q_vector *q_vector);

int ring_is_not_empty(struct ice_ring *rx_ring) {
	union ice_32b_rx_flex_desc *rx_desc;
	u16 stat_err_bits;
	int i;

	/* Tail is write-only, checking all descriptors (or we need a shadow tail from userspace) */
	for (i = 0; i < rx_ring->count; i++) {
		rx_desc = ICE_RX_DESC(rx_ring, i);    
		if (rx_desc == NULL) {
			printk("[PF_RING-ZC] %s: RX descriptor #%u NULL, this should not happen\n", 
			       __FUNCTION__, i);
 			break;
		}
		stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS0_DD_S);
		if (ice_test_staterr(rx_desc, stat_err_bits))
			return 1;
	}

	return 0;
}

int wait_packet_function_ptr(void *data, int mode)
{
	struct ice_ring *rx_ring = (struct ice_ring*) data;
	int new_packets;
	int enable_irq_debug = 0; // enable_debug;

	if (unlikely(enable_irq_debug))
		printk("[PF_RING-ZC] %s: enter [mode=%d/%s][queue=%d][NTC=%u][NTU=%d]\n",
		       __FUNCTION__, mode, mode == 1 ? "enable int" : "disable int",
		       rx_ring->q_index, rx_ring->next_to_clean, rx_ring->next_to_use);

	if (mode == 1 /* Enable interrupt */) {

		new_packets = ring_is_not_empty(rx_ring);

		if (!new_packets) {
			rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 0;

			if (!rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled) {
				/* Enabling interrupts on demand, this has been disabled with napi in ZC mode */
				ice_update_ena_itr(rx_ring->q_vector);

				rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled = 1;

				if (unlikely(enable_irq_debug)) 
					printk("[PF_RING-ZC] %s: Enabled interrupts [queue=%d]\n", __FUNCTION__,
						rx_ring->q_vector->v_idx);
      			} else {
				if (unlikely(enable_irq_debug)) 
					printk("[PF_RING-ZC] %s: Interrupts already enabled [queue=%d]\n", __FUNCTION__, 
						rx_ring->q_vector->v_idx);
			}
    		} else {
			rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 1;

			if (unlikely(enable_irq_debug))
				printk("[PF_RING-ZC] %s: Packet received [queue=%d][NTC=%u]\n", __FUNCTION__,
					rx_ring->q_vector->v_idx, rx_ring->next_to_clean); 
		}

		return new_packets;
	} else {
		/* No Need to disable interrupts here, the standard napi mechanism will do it */

		rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled = 0;

		if (unlikely(enable_irq_debug))
			printk("[PF_RING-ZC] %s: Disabled interrupts [queue=%d]\n", __FUNCTION__, rx_ring->q_vector->v_idx);
		
		return 0;
	}
}

int wake_up_pfring_zc_socket(struct ice_ring *rx_ring)
{
	int enable_irq_debug = 0; // enable_debug;

	if (atomic_read(&rx_ring->pfring_zc.queue_in_use)) {
		if (waitqueue_active(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue)) {
			if (ring_is_not_empty(rx_ring)) {
				rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 1;
				rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled = 0; /* napi disables them */
				wake_up_interruptible(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue);
				if (unlikely(enable_irq_debug))
					printk("[PF_RING-ZC] %s: Waking up socket [queue=%d]\n", __FUNCTION__, rx_ring->q_vector->v_idx);
				return 1;
			}
		}
		if (!ring_is_not_empty(rx_ring)) {
			/* Note: in case of multiple sockets (RSS), if ice_clean_*x_irq is called
			 * for some queue, interrupts are disabled, preventing packets from arriving 
			 * on other active queues, in order to avoid this we need to enable interrupts */
					
			struct ice_pf *adapter = ice_netdev_to_pf(rx_ring->netdev);
			adapter->pfring_zc.interrupts_required = 1;

			/* Enabling interrupts in ice_napi_poll()
			 * ice_update_ena_itr(rx_ring->q_vector); */
		}
	}

	return 0;
}

static void ice_control_rxq(struct ice_vsi *vsi, int q_index, bool enable)
{
	ice_vsi_ctrl_one_rx_ring(vsi, enable, q_index, true);

	ice_flush(&vsi->back->hw);

	ice_vsi_wait_one_rx_ring(vsi, enable, q_index);
}

#define TAIL_RESET

int notify_function_ptr(void *rx_data, void *tx_data, u_int8_t device_in_use) 
{
	struct ice_ring  *rx_ring = (struct ice_ring *) rx_data;
	struct ice_ring  *tx_ring = (struct ice_ring *) tx_data;
	struct ice_ring  *xx_ring = (rx_ring != NULL) ? rx_ring : tx_ring;
	struct ice_pf    *adapter;
	int i, n;
 
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s %s\n", __FUNCTION__, device_in_use ? "open" : "close");

	if (xx_ring == NULL) return -1; /* safety check */

	adapter = ice_netdev_to_pf(xx_ring->netdev);

	if (device_in_use) { /* free all memory */

		if ((n = atomic_inc_return(&adapter->pfring_zc.usage_counter)) == 1 /* first user */) {
			try_module_get(THIS_MODULE); /* ++ */

			/* wait for ice_clean_rx_irq to complete the current receive if any */
			usleep_range(100, 200);  
		}

    
		if (rx_ring != NULL && atomic_inc_return(&rx_ring->pfring_zc.queue_in_use) == 1 /* first user */) {
			struct ice_vsi *vsi = rx_ring->vsi;
			u_int32_t *shadow_tail_ptr = (u_int32_t *) ICE_RX_DESC(rx_ring, rx_ring->count);
			u_int32_t curr_tail = rx_ring->next_to_clean;

			if (unlikely(enable_debug))
				printk("[PF_RING-ZC] %s:%d RX Hw-Tail=%u NTU=%u NTC/Sw-Tail=%u\n", __FUNCTION__, __LINE__,
					readl(rx_ring->tail), rx_ring->next_to_use, rx_ring->next_to_clean);

			/* Store tail (see ice_release_rx_desc) */
			//writel(rx_ring->next_to_use, rx_ring->tail);

			ice_control_rxq(vsi, rx_ring->q_index, false /* stop */);

			usleep_range(100, 200);

			ice_clean_rx_ring(rx_ring);

			/* Note: keep this after ice_clean_rx_ring which is calling memset on desc */
			*shadow_tail_ptr = curr_tail;
		}

		if (tx_ring != NULL && atomic_inc_return(&tx_ring->pfring_zc.queue_in_use) == 1 /* first user */) {
			u_int32_t *shadow_tail_ptr = (u_int32_t *) ICE_TX_DESC(tx_ring, tx_ring->count);

			*shadow_tail_ptr = tx_ring->next_to_use;

			if(unlikely(enable_debug))
				printk("[PF_RING-ZC] %s:%d TX Tail=%u NTU=%u NTC=%u\n", __FUNCTION__, __LINE__,
					readl(tx_ring->tail), tx_ring->next_to_use, tx_ring->next_to_clean);
		}

		/* Note: in case of multiple sockets (RX and TX or RSS) ice_clean_*x_irq is called
 		 * and interrupts are disabled, preventing packets from arriving on the active sockets,
 		 * in order to avoid this we need to enable interrupts */
		ice_update_ena_itr(xx_ring->q_vector);

	} else { /* restore card memory */
		if (rx_ring != NULL && atomic_dec_return(&rx_ring->pfring_zc.queue_in_use) == 0 /* last user */) {
			struct ice_vsi *vsi = rx_ring->vsi;
#ifndef TAIL_RESET
			u_int32_t *shadow_tail_ptr = (u_int32_t *) ICE_RX_DESC(rx_ring, rx_ring->count);

			/* Note: keep this before the desc memset */
			rx_ring->next_to_clean = *shadow_tail_ptr;
#endif

			ice_control_rxq(vsi, rx_ring->q_index, false /* stop */);

#ifdef TAIL_RESET
			rx_ring->next_to_alloc = 0;
			rx_ring->next_to_clean = 0;
			rx_ring->next_to_use = 0;

			writel_relaxed(0, rx_ring->tail);
#endif

			/* Zero out the descriptor ring */
			memset(rx_ring->desc, 0, rx_ring->size);

			wmb();

#ifndef TAIL_RESET
			rx_ring->next_to_use = rx_ring->next_to_clean;
#endif

			if (unlikely(enable_debug))
				printk("[PF_RING-ZC] %s:%d Restoring RX Hw-Tail=%u NTU=%u NTC/Sw-Tail=%u\n", __FUNCTION__, __LINE__,
					readl(rx_ring->tail), rx_ring->next_to_use, rx_ring->next_to_clean);

			ice_alloc_rx_bufs(rx_ring, rx_ring->count - 1);

#ifndef TAIL_RESET
			/* Force tail update */
			if (rx_ring->next_to_clean == 0)
				rx_ring->next_to_use = rx_ring->count - 1;
			else
				rx_ring->next_to_use = rx_ring->next_to_clean - 1;
			rx_ring->next_to_alloc = rx_ring->next_to_use;
			//writel_relaxed(rx_ring->next_to_use & ~0x7, rx_ring->tail);
#endif

			if (unlikely(enable_debug))
				printk("[PF_RING-ZC] %s:%d Refilled RX Hw-Tail=%u NTU=%u NTC/Sw-Tail=%u\n", __FUNCTION__, __LINE__,
					readl(rx_ring->tail), rx_ring->next_to_use, rx_ring->next_to_clean);

			ice_control_rxq(vsi, rx_ring->q_index, true /* start */);
		}

		if (tx_ring != NULL && atomic_dec_return(&tx_ring->pfring_zc.queue_in_use) == 0 /* last user */) {
			u_int32_t *shadow_tail_ptr = (u_int32_t *) ICE_TX_DESC(tx_ring, tx_ring->count);

			/* Restore TX */
			tx_ring->next_to_use = tx_ring->next_to_clean = *shadow_tail_ptr;

			if (unlikely(enable_debug))
				printk("[PF_RING-ZC] %s:%d Restoring TX Tail=%u NTU=%u NTC=%u\n", __FUNCTION__, __LINE__,
					readl(tx_ring->tail), tx_ring->next_to_use, tx_ring->next_to_clean);
       
			for (i = 0; i < tx_ring->count; i++) {
				struct ice_tx_buf *tx_buffer = &tx_ring->tx_buf[i];
				tx_buffer->next_to_watch = NULL;
				tx_buffer->skb = NULL;
			}

			wmb();
		}

		if ((n = atomic_dec_return(&adapter->pfring_zc.usage_counter)) == 0 /* last user */) {
			module_put(THIS_MODULE);  /* -- */
		}

		/* Note: in case of multiple sockets (RX and TX or RSS) ice_clean_*x_irq is called
 		 * and interrupts are disabled, preventing packets from arriving on the active sockets,
 		 * in order to avoid this we need to enable interrupts even if this is not the last user */
		//if (n == 0) { /* last user */
			/* Enabling interrupts in case they've been disabled by napi and never enabled in ZC mode */
			ice_update_ena_itr(xx_ring->q_vector);
		//}

	}

#if 0
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s %s@%d is %sIN use (%p counter: %u)\n", __FUNCTION__,
			xx_ring->netdev->name, xx_ring->q_index, device_in_use ? "" : "NOT ", 
			adapter, atomic_read(&adapter->pfring_zc.usage_counter));
#endif

	return 0;
}

#endif

/**
 * ice_vsi_cfg - Setup the VSI
 * @vsi: the VSI being configured
 *
 * Return 0 on success and negative value on error
 */
int ice_vsi_cfg(struct ice_vsi *vsi)
{
	int err;

	if (vsi->netdev && vsi->type == ICE_VSI_PF) {
		ice_set_rx_mode(vsi->netdev);

		err = ice_vsi_vlan_setup(vsi);

		if (err)
			return err;
	}
	ice_vsi_cfg_dcb_rings(vsi);

	err = ice_vsi_cfg_lan_txqs(vsi);
#ifdef HAVE_XDP_SUPPORT
	if (!err && ice_is_xdp_ena_vsi(vsi))
		err = ice_vsi_cfg_xdp_txqs(vsi);
#endif /* HAVE_XDP_SUPPORT */
	if (!err)
		err = ice_vsi_cfg_rxqs(vsi);

	return err;
}

/**
 * ice_napi_enable_all - Enable NAPI for all q_vectors in the VSI
 * @vsi: the VSI being configured
 */
static void ice_napi_enable_all(struct ice_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, q_idx) {
		struct ice_q_vector *q_vector = vsi->q_vectors[q_idx];

#ifdef HAVE_PF_RING
		//TODO Check if this is required
		// if (test_bit(NAPI_STATE_SCHED, &q_vector->napi.state)) /* safety check */
#endif
		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_enable(&q_vector->napi);
	}
}

/**
 * ice_up_complete - Finish the last steps of bringing up a connection
 * @vsi: The VSI being configured
 *
 * Return 0 on success and negative value on error
 */
static int ice_up_complete(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	int err;

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s: called on %s\n", __FUNCTION__, vsi->netdev->name);
#endif

	ice_vsi_cfg_msix(vsi);

	/* Enable only Rx rings, Tx rings were enabled by the FW when the
	 * Tx queue group list was configured and the context bits were
	 * programmed using ice_vsi_cfg_txqs
	 */
	err = ice_vsi_start_all_rx_rings(vsi);
	if (err)
		return err;


	clear_bit(__ICE_DOWN, vsi->state);
	ice_napi_enable_all(vsi);
	ice_vsi_ena_irq(vsi);

	if (vsi->port_info &&
	    (vsi->port_info->phy.link_info.link_info & ICE_AQ_LINK_UP) &&
	    vsi->netdev && vsi->type == ICE_VSI_PF) {
		ice_print_link_msg(vsi, true);
		netif_tx_start_all_queues(vsi->netdev);
		netif_carrier_on(vsi->netdev);
	}



	if (vsi->type == ICE_VSI_PF)
		ice_service_task_schedule(pf);

#ifdef HAVE_PF_RING
	if (vsi->netdev) {
		int i;
		u16 cache_line_size;
		struct ice_pf *pf = vsi->back;

		pci_read_config_word(pf->pdev, PCI_DEVICE_CACHE_LINE_SIZE, &cache_line_size);
		cache_line_size &= 0x00FF;
		cache_line_size *= PCI_DEVICE_CACHE_LINE_SIZE_BYTES;
		if (cache_line_size == 0) cache_line_size = 64;

		if (unlikely(enable_debug))  
			printk("[PF_RING-ZC] %s: attach %s [pf start=%llu len=%llu][cache_line_size=%u]\n", __FUNCTION__,
				vsi->netdev->name, pci_resource_start(pf->pdev, 0), pci_resource_len(pf->pdev, 0), cache_line_size);

		ice_for_each_rxq(vsi, i) {
			struct ice_ring *rx_ring = vsi->rx_rings[i];
			struct ice_ring *tx_ring = vsi->tx_rings[i];
			mem_ring_info rx_info = { 0 };
			mem_ring_info tx_info = { 0 };

			init_waitqueue_head(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue);

			rx_info.num_queues = vsi->num_rxq;
			rx_info.packet_memory_num_slots     = rx_ring->count;
			rx_info.packet_memory_slot_len      = ALIGN(rx_ring->rx_buf_len, cache_line_size);
			rx_info.descr_packet_memory_tot_len = rx_ring->size;
			rx_info.registers_index		    = rx_ring->reg_idx;
			rx_info.stats_index		    = vsi->vsi_num;
			rx_info.vector			    = rx_ring->q_vector->v_idx + vsi->base_vector;
 
			tx_info.num_queues = vsi->num_txq;
			tx_info.packet_memory_num_slots     = tx_ring->count;
			tx_info.packet_memory_slot_len      = rx_info.packet_memory_slot_len;
			tx_info.descr_packet_memory_tot_len = tx_ring->size;
			tx_info.registers_index		    = tx_ring->reg_idx;

			pf_ring_zc_dev_handler(add_device_mapping,
				&rx_info,
				&tx_info,
				rx_ring->desc, /* rx packet descriptors */
				tx_ring->desc, /* tx packet descriptors */
				(void *) pci_resource_start(pf->pdev, ICE_BAR0), /* pcim_iomap_table(pf->pdev)[ICE_BAR0] */
				pci_resource_len(pf->pdev, ICE_BAR0),
				rx_ring->q_index, /* channel id */
				rx_ring->netdev,
				rx_ring->dev, /* for DMA mapping */
				intel_ice,
				rx_ring->netdev->dev_addr,
				&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue,
				&rx_ring->pfring_zc.rx_tx.rx.interrupt_received,
				(void *) rx_ring,
				(void *) tx_ring,
				wait_packet_function_ptr,
				notify_function_ptr);
		}
	}
#endif

	return 0;
}

/**
 * ice_up - Bring the connection back up after being down
 * @vsi: VSI being configured
 */
int ice_up(struct ice_vsi *vsi)
{
	int err;

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s: called on %s\n", __FUNCTION__, vsi->netdev->name);
#endif

	err = ice_vsi_cfg(vsi);
	if (!err)
		err = ice_up_complete(vsi);

	return err;
}

/**
 * ice_fetch_u64_stats_per_ring - get packets and bytes stats per ring
 * @ring: Tx or Rx ring to read stats from
 * @pkts: packets stats counter
 * @bytes: bytes stats counter
 *
 * This function fetches stats from the ring considering the atomic operations
 * that needs to be performed to read u64 values in 32 bit machine.
 */
static void
ice_fetch_u64_stats_per_ring(struct ice_ring *ring, u64 *pkts, u64 *bytes)
{
	unsigned int start;
	*pkts = 0;
	*bytes = 0;

	if (!ring)
		return;
	do {
		start = u64_stats_fetch_begin_irq(&ring->syncp);
		*pkts = ring->stats.pkts;
		*bytes = ring->stats.bytes;
	} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
}

/**
 * ice_update_vsi_ring_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
static void ice_update_vsi_ring_stats(struct ice_vsi *vsi)
{
	struct rtnl_link_stats64 *vsi_stats = &vsi->net_stats;
	struct ice_ring *ring;
	u64 pkts, bytes;
	int i;

	/* reset netdev stats */
	vsi_stats->tx_packets = 0;
	vsi_stats->tx_bytes = 0;
	vsi_stats->rx_packets = 0;
	vsi_stats->rx_bytes = 0;

	/* reset non-netdev (extended) stats */
	vsi->tx_restart = 0;
	vsi->tx_busy = 0;
	vsi->tx_linearize = 0;
	vsi->rx_buf_failed = 0;
	vsi->rx_page_failed = 0;

	rcu_read_lock();

	/* update Tx rings counters */
	ice_for_each_txq(vsi, i) {
		ring = READ_ONCE(vsi->tx_rings[i]);
		ice_fetch_u64_stats_per_ring(ring, &pkts, &bytes);
		vsi_stats->tx_packets += pkts;
		vsi_stats->tx_bytes += bytes;
		vsi->tx_restart += ring->tx_stats.restart_q;
		vsi->tx_busy += ring->tx_stats.tx_busy;
		vsi->tx_linearize += ring->tx_stats.tx_linearize;
	}

	/* update Rx rings counters */
	ice_for_each_rxq(vsi, i) {
		ring = READ_ONCE(vsi->rx_rings[i]);
		ice_fetch_u64_stats_per_ring(ring, &pkts, &bytes);
		vsi_stats->rx_packets += pkts;
		vsi_stats->rx_bytes += bytes;
		vsi->rx_buf_failed += ring->rx_stats.alloc_buf_failed;
		vsi->rx_page_failed += ring->rx_stats.alloc_page_failed;
	}

	rcu_read_unlock();
}

/**
 * ice_update_vsi_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
void ice_update_vsi_stats(struct ice_vsi *vsi)
{
	struct rtnl_link_stats64 *cur_ns = &vsi->net_stats;
	struct ice_eth_stats *cur_es = &vsi->eth_stats;
	struct ice_pf *pf = vsi->back;

	if (test_bit(__ICE_DOWN, vsi->state) ||
	    test_bit(__ICE_CFG_BUSY, pf->state))
		return;

	/* get stats as recorded by Tx/Rx rings */
	ice_update_vsi_ring_stats(vsi);

	/* get VSI stats as recorded by the hardware */
	ice_update_eth_stats(vsi);

#ifdef HAVE_PF_RING
	cur_ns->rx_packets = cur_es->rx_unicast; 
	cur_ns->rx_bytes = cur_es->rx_bytes;
#endif
	cur_ns->tx_errors = cur_es->tx_errors;
	cur_ns->rx_dropped = cur_es->rx_discards;
	cur_ns->tx_dropped = cur_es->tx_discards;
	cur_ns->multicast = cur_es->rx_multicast;

	/* update some more netdev stats if this is main VSI */
	if (vsi->type == ICE_VSI_PF) {
		cur_ns->rx_crc_errors = pf->stats.crc_errors;
		cur_ns->rx_errors = pf->stats.crc_errors +
				    pf->stats.illegal_bytes;
		cur_ns->rx_length_errors = pf->stats.rx_len_errors;
		/* record drops from the port level */
		cur_ns->rx_missed_errors = pf->stats.eth.rx_discards;
	}
}

/**
 * ice_update_pf_stats - Update PF port stats counters
 * @pf: PF whose stats needs to be updated
 */
void ice_update_pf_stats(struct ice_pf *pf)
{
	struct ice_hw_port_stats *prev_ps, *cur_ps;
	struct ice_hw *hw = &pf->hw;
	u16 fd_ctr_base;
	u8 port;

	port = hw->port_info->lport;
	prev_ps = &pf->stats_prev;
	cur_ps = &pf->stats;

	ice_stat_update40(hw, GLPRT_GORCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.rx_bytes,
			  &cur_ps->eth.rx_bytes);

	ice_stat_update40(hw, GLPRT_UPRCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.rx_unicast,
			  &cur_ps->eth.rx_unicast);

	ice_stat_update40(hw, GLPRT_MPRCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.rx_multicast,
			  &cur_ps->eth.rx_multicast);

	ice_stat_update40(hw, GLPRT_BPRCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.rx_broadcast,
			  &cur_ps->eth.rx_broadcast);

	ice_stat_update32(hw, PRTRPB_RDPC, pf->stat_prev_loaded,
			  &prev_ps->eth.rx_discards,
			  &cur_ps->eth.rx_discards);

	ice_stat_update40(hw, GLPRT_GOTCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.tx_bytes,
			  &cur_ps->eth.tx_bytes);

	ice_stat_update40(hw, GLPRT_UPTCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.tx_unicast,
			  &cur_ps->eth.tx_unicast);

	ice_stat_update40(hw, GLPRT_MPTCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.tx_multicast,
			  &cur_ps->eth.tx_multicast);

	ice_stat_update40(hw, GLPRT_BPTCL(port), pf->stat_prev_loaded,
			  &prev_ps->eth.tx_broadcast,
			  &cur_ps->eth.tx_broadcast);

	ice_stat_update32(hw, GLPRT_TDOLD(port), pf->stat_prev_loaded,
			  &prev_ps->tx_dropped_link_down,
			  &cur_ps->tx_dropped_link_down);

	ice_stat_update40(hw, GLPRT_PRC64L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_64, &cur_ps->rx_size_64);

	ice_stat_update40(hw, GLPRT_PRC127L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_127, &cur_ps->rx_size_127);

	ice_stat_update40(hw, GLPRT_PRC255L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_255, &cur_ps->rx_size_255);

	ice_stat_update40(hw, GLPRT_PRC511L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_511, &cur_ps->rx_size_511);

	ice_stat_update40(hw, GLPRT_PRC1023L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_1023, &cur_ps->rx_size_1023);

	ice_stat_update40(hw, GLPRT_PRC1522L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_1522, &cur_ps->rx_size_1522);

	ice_stat_update40(hw, GLPRT_PRC9522L(port), pf->stat_prev_loaded,
			  &prev_ps->rx_size_big, &cur_ps->rx_size_big);

	ice_stat_update40(hw, GLPRT_PTC64L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_64, &cur_ps->tx_size_64);

	ice_stat_update40(hw, GLPRT_PTC127L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_127, &cur_ps->tx_size_127);

	ice_stat_update40(hw, GLPRT_PTC255L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_255, &cur_ps->tx_size_255);

	ice_stat_update40(hw, GLPRT_PTC511L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_511, &cur_ps->tx_size_511);

	ice_stat_update40(hw, GLPRT_PTC1023L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_1023, &cur_ps->tx_size_1023);

	ice_stat_update40(hw, GLPRT_PTC1522L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_1522, &cur_ps->tx_size_1522);

	ice_stat_update40(hw, GLPRT_PTC9522L(port), pf->stat_prev_loaded,
			  &prev_ps->tx_size_big, &cur_ps->tx_size_big);

	fd_ctr_base = hw->fd_ctr_base;

	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_FD_SB_STAT_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->fd_sb_match,
			  &cur_ps->fd_sb_match);
#ifdef ADQ_PERF
	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_FD_CH_STAT_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->ch_atr_match,
			  &cur_ps->ch_atr_match);
#endif /* ADQ_PERF */
#ifdef ICE_ADD_PROBES
	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_ARFS_STAT_TCPV4_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->arfs_tcpv4_match,
			  &cur_ps->arfs_tcpv4_match);
	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_ARFS_STAT_TCPV6_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->arfs_tcpv6_match,
			  &cur_ps->arfs_tcpv6_match);
	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_ARFS_STAT_UDPV4_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->arfs_udpv4_match,
			  &cur_ps->arfs_udpv4_match);
	ice_stat_update40(hw,
			  GLSTAT_FD_CNT0L(ICE_ARFS_STAT_UDPV6_IDX(fd_ctr_base)),
			  pf->stat_prev_loaded, &prev_ps->arfs_udpv6_match,
			  &cur_ps->arfs_udpv6_match);
#endif /* ICE_ADD_PROBES */
	ice_stat_update32(hw, GLPRT_LXONRXC(port), pf->stat_prev_loaded,
			  &prev_ps->link_xon_rx, &cur_ps->link_xon_rx);

	ice_stat_update32(hw, GLPRT_LXOFFRXC(port), pf->stat_prev_loaded,
			  &prev_ps->link_xoff_rx, &cur_ps->link_xoff_rx);

	ice_stat_update32(hw, GLPRT_LXONTXC(port), pf->stat_prev_loaded,
			  &prev_ps->link_xon_tx, &cur_ps->link_xon_tx);

	ice_stat_update32(hw, GLPRT_LXOFFTXC(port), pf->stat_prev_loaded,
			  &prev_ps->link_xoff_tx, &cur_ps->link_xoff_tx);

	ice_update_dcb_stats(pf);

	ice_stat_update32(hw, GLPRT_CRCERRS(port), pf->stat_prev_loaded,
			  &prev_ps->crc_errors, &cur_ps->crc_errors);

	ice_stat_update32(hw, GLPRT_ILLERRC(port), pf->stat_prev_loaded,
			  &prev_ps->illegal_bytes, &cur_ps->illegal_bytes);

	ice_stat_update32(hw, GLPRT_MLFC(port), pf->stat_prev_loaded,
			  &prev_ps->mac_local_faults,
			  &cur_ps->mac_local_faults);

	ice_stat_update32(hw, GLPRT_MRFC(port), pf->stat_prev_loaded,
			  &prev_ps->mac_remote_faults,
			  &cur_ps->mac_remote_faults);

	ice_stat_update32(hw, GLPRT_RLEC(port), pf->stat_prev_loaded,
			  &prev_ps->rx_len_errors, &cur_ps->rx_len_errors);

	ice_stat_update32(hw, GLPRT_RUC(port), pf->stat_prev_loaded,
			  &prev_ps->rx_undersize, &cur_ps->rx_undersize);

	ice_stat_update32(hw, GLPRT_RFC(port), pf->stat_prev_loaded,
			  &prev_ps->rx_fragments, &cur_ps->rx_fragments);

	ice_stat_update32(hw, GLPRT_ROC(port), pf->stat_prev_loaded,
			  &prev_ps->rx_oversize, &cur_ps->rx_oversize);

	ice_stat_update32(hw, GLPRT_RJC(port), pf->stat_prev_loaded,
			  &prev_ps->rx_jabber, &cur_ps->rx_jabber);


	if (test_bit(ICE_FLAG_FD_ENA, pf->flags))
		cur_ps->fd_sb_status = true;
	else
		cur_ps->fd_sb_status = false;

	pf->stat_prev_loaded = true;
}

/**
 * ice_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static
#ifdef HAVE_VOID_NDO_GET_STATS64
void ice_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
#else /* HAVE_VOID_NDO_GET_STATS64 */
struct rtnl_link_stats64 *
ice_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
#endif /* !HAVE_VOID_NDO_GET_STATS64 */
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct rtnl_link_stats64 *vsi_stats;
	struct ice_vsi *vsi = np->vsi;

	vsi_stats = &vsi->net_stats;

	if (!vsi->num_txq || !vsi->num_rxq)
#ifdef HAVE_VOID_NDO_GET_STATS64
		return;
#else
		return stats;
#endif

	/* netdev packet/byte stats come from ring counter. These are obtained
	 * by summing up ring counters (done by ice_update_vsi_ring_stats).
	 * But, only call the update routine and read the registers if VSI is
	 * not down.
	 */
	if (!test_bit(__ICE_DOWN, vsi->state))
		ice_update_vsi_ring_stats(vsi);
	stats->tx_packets = vsi_stats->tx_packets;
	stats->tx_bytes = vsi_stats->tx_bytes;
#ifndef HAVE_PF_RING
	stats->rx_packets = vsi_stats->rx_packets;
	stats->rx_bytes = vsi_stats->rx_bytes;
#endif

	/* The rest of the stats can be read from the hardware but instead we
	 * just return values that the watchdog task has already obtained from
	 * the hardware.
	 */
	stats->multicast = vsi_stats->multicast;
	stats->tx_errors = vsi_stats->tx_errors;
	stats->tx_dropped = vsi_stats->tx_dropped;
	stats->rx_errors = vsi_stats->rx_errors;
	stats->rx_dropped = vsi_stats->rx_dropped;
	stats->rx_crc_errors = vsi_stats->rx_crc_errors;
	stats->rx_length_errors = vsi_stats->rx_length_errors;
#ifndef HAVE_VOID_NDO_GET_STATS64

	return stats;
#endif
}

#ifdef HAVE_NETPOLL_CONTROLLER
#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * ice_netpoll - polling "interrupt" handler
 * @netdev: network interface device structure
 *
 * Used by netconsole to send skbs without having to re-enable interrupts.
 * This is not called in the normal interrupt path.
 */
static void ice_netpoll(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	int i;

	if (test_bit(__ICE_DOWN, vsi->state))
		return;

	ice_for_each_q_vector(vsi, i)
		ice_msix_clean_rings(0, vsi->q_vectors[i]);
}
#endif /* CONFIG_NET_POLL_CONTROLLER */
#endif /* HAVE_NETPOLL_CONTROLLER */

/**
 * ice_napi_disable_all - Disable NAPI for all q_vectors in the VSI
 * @vsi: VSI having NAPI disabled
 */
static void ice_napi_disable_all(struct ice_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, q_idx) {
		struct ice_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_disable(&q_vector->napi);
	}
}

/**
 * ice_down - Shutdown the connection
 * @vsi: The VSI being stopped
 */
int ice_down(struct ice_vsi *vsi)
{
	int i, tx_err, rx_err, link_err = 0;

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s: called on %s\n", __FUNCTION__, vsi->netdev->name);
#endif

	/* Caller of this function is expected to set the
	 * vsi->state __ICE_DOWN bit
	 */
	if (vsi->netdev && vsi->type == ICE_VSI_PF) {
		netif_carrier_off(vsi->netdev);
		netif_tx_disable(vsi->netdev);
	}


	ice_vsi_dis_irq(vsi);

	tx_err = ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, 0);
	if (tx_err)
		netdev_err(vsi->netdev, "Failed stop Tx rings, VSI %d error %d\n",
			   vsi->vsi_num, tx_err);
#ifdef HAVE_XDP_SUPPORT
	if (!tx_err && ice_is_xdp_ena_vsi(vsi)) {
		tx_err = ice_vsi_stop_xdp_tx_rings(vsi);
		if (tx_err)
			netdev_err(vsi->netdev, "Failed stop XDP rings, VSI %d error %d\n",
				   vsi->vsi_num, tx_err);
	}
#endif /* HAVE_XDP_SUPPORT */

	rx_err = ice_vsi_stop_all_rx_rings(vsi);
	if (rx_err)
		netdev_err(vsi->netdev, "Failed stop Rx rings, VSI %d error %d\n",
			   vsi->vsi_num, rx_err);

	ice_napi_disable_all(vsi);

	if (test_bit(ICE_FLAG_LINK_DOWN_ON_CLOSE_ENA, vsi->back->flags)) {
		link_err = ice_force_phys_link_state(vsi, false);
		if (link_err)
			netdev_err(vsi->netdev, "Failed to set physical link down, VSI %d error %d\n",
				   vsi->vsi_num, link_err);
	}

	ice_for_each_txq(vsi, i)
		ice_clean_tx_ring(vsi->tx_rings[i]);

	ice_for_each_rxq(vsi, i)
		ice_clean_rx_ring(vsi->rx_rings[i]);

	if (tx_err || rx_err || link_err) {
		netdev_err(vsi->netdev, "Failed to close VSI 0x%04X on switch 0x%04X\n",
			   vsi->vsi_num, vsi->vsw->sw_id);
		return -EIO;
	}

#ifdef HAVE_PF_RING
	if (vsi->netdev) {
		struct ice_pf *pf = vsi->back;
		struct ice_pf    *adapter = ice_netdev_to_pf(vsi->netdev);
		int i;

		if (unlikely(enable_debug))
	      		printk("[PF_RING-ZC] %s: detach %s\n", __FUNCTION__, vsi->netdev->name);

		if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
			printk("[PF_RING-ZC] %s: detaching %s while in use\n", __FUNCTION__, vsi->netdev->name); 

		ice_for_each_rxq(vsi, i) {
			struct ice_ring *rx_ring = vsi->rx_rings[i];
			struct ice_ring *tx_ring = vsi->tx_rings[i];
			pf_ring_zc_dev_handler(remove_device_mapping,
				NULL, // rx_info,
				NULL, // tx_info,
				NULL, /* Packet descriptors */
				NULL, /* Packet descriptors */
				(void*)pci_resource_start(pf->pdev, ICE_BAR0),
				pci_resource_len(pf->pdev, ICE_BAR0),
				rx_ring->q_index, /* Channel Id */
				rx_ring->netdev,
				rx_ring->dev, /* for DMA mapping */
				intel_ice,
				rx_ring->netdev->dev_addr,
				&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue,
				&rx_ring->pfring_zc.rx_tx.rx.interrupt_received,
				(void*)rx_ring,
				(void*)tx_ring,
				NULL, // wait_packet_function_ptr
				NULL // notify_function_ptr
			);
		}
	}
#endif

	return 0;
}

/**
 * ice_vsi_setup_tx_rings - Allocate VSI Tx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int ice_vsi_setup_tx_rings(struct ice_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_txq) {
		dev_err(ice_pf_to_dev(vsi->back), "VSI %d has 0 Tx queues\n",
			vsi->vsi_num);
		return -EINVAL;
	}

	ice_for_each_txq(vsi, i) {
		struct ice_ring *ring = vsi->tx_rings[i];

		if (!ring)
			return -EINVAL;

		ring->netdev = vsi->netdev;
		err = ice_setup_tx_ring(ring);
		if (err)
			break;
	}

	return err;
}

/**
 * ice_vsi_setup_rx_rings - Allocate VSI Rx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int ice_vsi_setup_rx_rings(struct ice_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_rxq) {
		dev_err(ice_pf_to_dev(vsi->back), "VSI %d has 0 Rx queues\n",
			vsi->vsi_num);
		return -EINVAL;
	}

	ice_for_each_rxq(vsi, i) {
		struct ice_ring *ring = vsi->rx_rings[i];

		if (!ring)
			return -EINVAL;

		ring->netdev = vsi->netdev;
		err = ice_setup_rx_ring(ring);
		if (err)
			break;
	}

	return err;
}

/**
 * ice_vsi_open_ctrl - open control VSI for use
 * @vsi: the VSI to open
 *
 * Initialization of the Control VSI
 *
 * Returns 0 on success, negative value on error
 */
int ice_vsi_open_ctrl(struct ice_vsi *vsi)
{
	char int_name[ICE_INT_NAME_STR_LEN];
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	/* allocate descriptors */
	err = ice_vsi_setup_tx_rings(vsi);
	if (err)
		goto err_setup_tx;

	err = ice_vsi_setup_rx_rings(vsi);
	if (err)
		goto err_setup_rx;

	err = ice_vsi_cfg(vsi);
	if (err)
		goto err_setup_rx;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s:ctrl",
		 dev_driver_string(dev), dev_name(dev));
	err = ice_vsi_req_irq_msix(vsi, int_name);
	if (err)
		goto err_setup_rx;

	ice_vsi_cfg_msix(vsi);

	err = ice_vsi_start_all_rx_rings(vsi);
	if (err)
		goto err_up_complete;

	clear_bit(__ICE_DOWN, vsi->state);
	ice_vsi_ena_irq(vsi);

	return 0;

err_up_complete:
	ice_down(vsi);
err_setup_rx:
	ice_vsi_free_rx_rings(vsi);
err_setup_tx:
	ice_vsi_free_tx_rings(vsi);

	return err;
}

/**
 * ice_vsi_open - Called when a network interface is made active
 * @vsi: the VSI to open
 *
 * Initialization of the VSI
 *
 * Returns 0 on success, negative value on error
 */
int ice_vsi_open(struct ice_vsi *vsi)
{
	char int_name[ICE_INT_NAME_STR_LEN];
	struct ice_pf *pf = vsi->back;
	int err;

	/* allocate descriptors */
	err = ice_vsi_setup_tx_rings(vsi);
	if (err)
		goto err_setup_tx;

	err = ice_vsi_setup_rx_rings(vsi);
	if (err)
		goto err_setup_rx;

	err = ice_vsi_cfg(vsi);
	if (err)
		goto err_setup_rx;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
		 dev_driver_string(ice_pf_to_dev(pf)), vsi->netdev->name);
	err = ice_vsi_req_irq_msix(vsi, int_name);
	if (err)
		goto err_setup_rx;

	if (vsi->type == ICE_VSI_PF) {
#ifdef HAVE_NETDEV_SB_DEV
		unsigned int total_qs = vsi->num_txq;

		if (test_bit(ICE_FLAG_MACVLAN_ENA, pf->flags))
			total_qs = vsi->alloc_txq + pf->max_num_macvlan;

		/* Notify the stack of the actual queue counts. */
		err = netif_set_real_num_tx_queues(vsi->netdev, total_qs);
#else
		/* Notify the stack of the actual queue counts. */
		err = netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
#endif /* HAVE_NETDEV_SB_DEV */
		if (err)
			goto err_set_qs;

		err = netif_set_real_num_rx_queues(vsi->netdev, vsi->num_rxq);
		if (err)
			goto err_set_qs;
	}

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug)) 
		printk("[PF_RING-ZC] %s: called on %s\n", __FUNCTION__, vsi->netdev->name);
#endif

	err = ice_up_complete(vsi);
	if (err)
		goto err_up_complete;
	return 0;

err_up_complete:
	ice_down(vsi);
err_set_qs:
	ice_vsi_free_irq(vsi);
err_setup_rx:
	ice_vsi_free_rx_rings(vsi);
err_setup_tx:
	ice_vsi_free_tx_rings(vsi);

	return err;
}

/**
 * ice_vsi_release_all - Delete all VSIs
 * @pf: PF from which all VSIs are being removed
 */
static void ice_vsi_release_all(struct ice_pf *pf)
{
	int err, i;

	if (!pf->vsi)
		return;

	ice_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;

		if (pf->vsi[i]->type == ICE_VSI_CHNL)
			continue;

		err = ice_vsi_release(pf->vsi[i]);
		if (err)
			dev_dbg(ice_pf_to_dev(pf), "Failed to release pf->vsi[%d], err %d, vsi_num = %d\n",
				i, err, pf->vsi[i]->vsi_num);
	}
}

/**
 * ice_vsi_rebuild_by_type - Rebuild VSI of a given type
 * @pf: pointer to the PF instance
 * @type: VSI type to rebuild
 *
 * Iterates through the pf->vsi array and rebuilds VSIs of the requested type
 */
static int ice_vsi_rebuild_by_type(struct ice_pf *pf, enum ice_vsi_type type)
{
	struct device *dev = ice_pf_to_dev(pf);
	enum ice_status status;
	int i, err;

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];

		if (!vsi || vsi->type != type)
			continue;

		/* rebuild the VSI */
		err = ice_vsi_rebuild(vsi, true);
		if (err) {
			dev_err(dev, "rebuild VSI failed, err %d, VSI index %d, type %s\n",
				err, vsi->idx, ice_vsi_type_str(type));
			return err;
		}

		/* replay filters for the VSI */
		status = ice_replay_vsi(&pf->hw, vsi->idx);
		if (status) {
			dev_err(dev, "replay VSI failed, status %d, VSI index %d, type %s\n",
				status, vsi->idx, ice_vsi_type_str(type));
			return -EIO;
		}

		/* Re-map HW VSI number, using VSI handle that has been
		 * previously validated in ice_replay_vsi() call above
		 */
		vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);

		/* enable the VSI */
		err = ice_ena_vsi(vsi, false);
		if (err) {
			dev_err(dev, "enable VSI failed, err %d, VSI index %d, type %s\n",
				err, vsi->idx, ice_vsi_type_str(type));
			return err;
		}

		dev_info(dev, "VSI rebuilt. VSI index %d, type %s\n", vsi->idx,
			 ice_vsi_type_str(type));
	}

	return 0;
}

/**
 * ice_update_pf_netdev_link - Update PF netdev link status
 * @pf: pointer to the PF instance
 */
static void ice_update_pf_netdev_link(struct ice_pf *pf)
{
	bool link_up;
	int i;

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];

		if (!vsi || vsi->type != ICE_VSI_PF)
			return;

		ice_get_link_status(pf->vsi[i]->port_info, &link_up);
		if (link_up) {
			netif_carrier_on(pf->vsi[i]->netdev);
			netif_tx_wake_all_queues(pf->vsi[i]->netdev);
		} else {
			netif_carrier_off(pf->vsi[i]->netdev);
			netif_tx_stop_all_queues(pf->vsi[i]->netdev);
		}
	}
}

/**
 * ice_rebuild - rebuild after reset
 * @pf: PF to rebuild
 * @reset_type: type of reset
 */
static void ice_rebuild(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	enum ice_status ret;
	int err;

	if (test_bit(__ICE_DOWN, pf->state))
		goto clear_recovery;

	dev_dbg(dev, "rebuilding PF after reset_type=%d\n", reset_type);


	ret = ice_init_all_ctrlq(hw);
	if (ret) {
		dev_err(dev, "control queues init failed %d\n", ret);
		goto err_init_ctrlq;
	}

	/* if DDP was previously loaded successfully */
	if (!ice_is_safe_mode(pf)) {
		/* reload the SW DB of filter tables */
		if (reset_type == ICE_RESET_PFR) {
			ice_fill_blk_tbls(hw);
		} else {
			/* Reload DDP Package after CORER/GLOBR reset */
			ice_load_pkg(NULL, pf);

			/* check if package reloaded */
			if (ice_is_safe_mode(pf)) {
				dev_err(dev, "failed to reload DDP Package\n");
				if (ice_prepare_for_safe_mode(pf)) {
					dev_err(dev, "could not transition to safe mode\n");
					goto err_init_ctrlq;
				}
			}
		}
	}

	ret = ice_clear_pf_cfg(hw);
	if (ret) {
		dev_err(dev, "clear PF configuration failed %d\n", ret);
		goto err_init_ctrlq;
	}

	if (pf->first_sw->dflt_vsi_ena)
		dev_info(dev, "Clearing default VSI, re-enable after reset completes\n");
	/* clear the default VSI configuration if it exists */
	pf->first_sw->dflt_vsi = NULL;
	pf->first_sw->dflt_vsi_ena = false;

	ice_clear_pxe_mode(hw);

	ret = ice_get_caps(hw);
	if (ret) {
		dev_err(dev, "ice_get_caps failed %d\n", ret);
		goto err_init_ctrlq;
	}

	err = ice_sched_init_port(hw->port_info);
	if (err)
		goto err_sched_init_port;

	err = ice_update_link_info(hw->port_info);
	if (err)
		dev_err(dev, "Get link status error %d\n", err);

	ice_pf_reset_stats(pf);

	/* start misc vector */
	err = ice_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "misc vector setup failed: %d\n", err);
		goto err_sched_init_port;
	}

	if (test_bit(ICE_FLAG_FD_ENA, pf->flags)) {
		wr32(hw, PFQF_FD_ENA, PFQF_FD_ENA_FD_ENA_M);
		if (!rd32(hw, PFQF_FD_SIZE)) {
			u16 unused, guar, b_effort;

			guar = hw->func_caps.fd_fltr_guar;
			b_effort = hw->func_caps.fd_fltr_best_effort;

			/* force guaranteed filter pool for PF */
			ice_alloc_fd_guar_item(hw, &unused, guar);
			/* force shared filter pool for PF */
			ice_alloc_fd_shrd_item(hw, &unused, b_effort);
		}
	}

	if (test_bit(ICE_FLAG_DCB_ENA, pf->flags))
		ice_dcb_rebuild(pf);

	/* rebuild PF VSI */
	err = ice_vsi_rebuild_by_type(pf, ICE_VSI_PF);
	if (err) {
		dev_err(dev, "PF VSI rebuild failed: %d\n", err);
		goto err_vsi_rebuild;
	}
	if (ice_is_peer_ena(pf)) {
		struct ice_vsi *vsi = ice_get_main_vsi(pf);

		if (!vsi) {
			dev_err(dev, "No PF_VSI to update peer\n");
			goto err_vsi_rebuild;
		}
		ice_for_each_peer(pf, vsi, ice_peer_update_vsi);
	}
	if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags)) {
		err = ice_vsi_rebuild_by_type(pf, ICE_VSI_VF);
		if (err) {
			dev_err(dev, "VF VSI rebuild failed: %d\n", err);
			goto err_vsi_rebuild;
		}
	}

#ifdef HAVE_NETDEV_SB_DEV
	if (test_bit(ICE_FLAG_MACVLAN_ENA, pf->flags)) {
		struct ice_vsi *vsi;

		err = ice_vsi_rebuild_by_type(pf, ICE_VSI_OFFLOAD_MACVLAN);
		if (err) {
			dev_err(dev, "MACVLAN VSI rebuild failed: %d\n", err);
			goto err_vsi_rebuild;
		}

		vsi = ice_get_main_vsi(pf);
		if (!vsi) {
			dev_err(dev, "main VSI doesn't exist\n");
			goto err_vsi_rebuild;
		}

		err = ice_init_macvlan(vsi, false);
		if (err) {
			dev_err(dev, "Failed to init macvlan\n");
			goto err_vsi_rebuild;
		}

		ice_vsi_replay_macvlan(pf);
	}
#endif /* HAVE_NETDEV_SB_DEV */


#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (reset_type == ICE_RESET_PFR) {
		err = ice_rebuild_channels(pf);
		if (err) {
			dev_err(dev, "failed to rebuild and replay ADQ VSIs, err %d\n",
				err);
			goto err_vsi_rebuild;
		}
	}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	/* If Flow Director is active */
	if (test_bit(ICE_FLAG_FD_ENA, pf->flags)) {
		err = ice_vsi_rebuild_by_type(pf, ICE_VSI_CTRL);
		if (err) {
			dev_err(dev, "control VSI rebuild failed: %d\n", err);
			goto err_vsi_rebuild;
		}

		/* replay HW Flow Director recipes */
		if (hw->fdir_prof)
			ice_fdir_replay_flows(hw);

		/* replay Flow Director filters */
		ice_fdir_replay_fltrs(pf);
	}


	if (!ice_is_safe_mode(pf))
		ice_rebuild_arfs(pf);

	ice_update_pf_netdev_link(pf);

	/* tell the firmware we are up */
	ret = ice_send_version(pf);
	if (ret) {
		dev_err(dev, "Rebuild failed due to error sending driver version:%d\n",
			ret);
		goto err_vsi_rebuild;
	}

	ice_replay_post(hw);

	/* if we get here, reset flow is successful */
	clear_bit(__ICE_RESET_FAILED, pf->state);
	return;

err_vsi_rebuild:
err_sched_init_port:
	ice_sched_cleanup_all(hw);
err_init_ctrlq:
	ice_shutdown_all_ctrlq(hw);
	set_bit(__ICE_RESET_FAILED, pf->state);
clear_recovery:
	/* set this bit in PF state to control service task scheduling */
	set_bit(__ICE_NEEDS_RESTART, pf->state);
	dev_err(dev, "Rebuild failed, unload and reload driver\n");
}

#ifdef HAVE_XDP_SUPPORT
/**
 * ice_max_xdp_frame_size - returns the maximum allowed frame size for XDP
 * @vsi: the VSI
 */
static int ice_max_xdp_frame_size(struct ice_vsi *vsi)
{
	if (PAGE_SIZE >= 8192 || test_bit(ICE_FLAG_LEGACY_RX, vsi->back->flags))
		return ICE_RXBUF_2048 - XDP_PACKET_HEADROOM;
	else
		return ICE_RXBUF_3072;
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * ice_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int ice_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	struct ice_event *event;
	u8 count = 0;
	int err = 0;

	if (new_mtu == netdev->mtu) {
		netdev_warn(netdev, "MTU is already %u\n", netdev->mtu);
		return 0;
	}
#ifdef HAVE_XDP_SUPPORT

	if (ice_is_xdp_ena_vsi(vsi)) {
		int frame_size = ice_max_xdp_frame_size(vsi);

		if (new_mtu + ICE_ETH_PKT_HDR_PAD > frame_size) {
			netdev_err(netdev, "max MTU for XDP usage is %d\n",
				   frame_size - ICE_ETH_PKT_HDR_PAD);
			return -EINVAL;
		}
	}

#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	if (new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->extended->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	}
#else /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
	if (new_mtu < netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	}
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
#else /* HAVE_NETDEVICE_MIN_MAX_MTU */
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		return -EINVAL;
	} else if (new_mtu > ICE_MAX_MTU) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   ICE_MAX_MTU);
		return -EINVAL;
	}
#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */
	/* if a reset is in progress, wait for some time for it to complete */
	do {
		if (ice_is_reset_in_progress(pf->state)) {
			count++;
			usleep_range(1000, 2000);
		} else {
			break;
		}

	} while (count < 100);

	if (count == 100) {
		netdev_err(netdev, "can't change MTU. Device is busy\n");
		return -EBUSY;
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	netdev->mtu = new_mtu;

	/* if VSI is up, bring it down and then back up */
	if (!test_and_set_bit(__ICE_DOWN, vsi->state)) {
		err = ice_down(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_down err %d\n", err);
			goto free_event;
		}

		err = ice_up(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_up err %d\n", err);
			goto free_event;
		}
	}

	if (ice_is_safe_mode(pf))
		goto out;

	set_bit(ICE_EVENT_MTU_CHANGE, event->type);
	event->reporter = NULL;
	event->info.mtu = new_mtu;
	ice_for_each_peer(pf, event, ice_peer_check_for_reg);

out:
	netdev_dbg(netdev, "changed MTU to %d\n", new_mtu);
free_event:
	kfree(event);
	return err;
}

/**
 * ice_aq_str - convert AQ err code to a string
 * @aq_err: the AQ error code to convert
 */
const char *ice_aq_str(enum ice_aq_err aq_err)
{
	switch (aq_err) {
	case ICE_AQ_RC_OK:
		return "OK";
	case ICE_AQ_RC_EPERM:
		return "ICE_AQ_RC_EPERM";
	case ICE_AQ_RC_ENOENT:
		return "ICE_AQ_RC_ENOENT";
	case ICE_AQ_RC_ESRCH:
		return "ICE_AQ_RC_ESRCH";
	case ICE_AQ_RC_EINTR:
		return "ICE_AQ_RC_EINTR";
	case ICE_AQ_RC_EIO:
		return "ICE_AQ_RC_EIO";
	case ICE_AQ_RC_ENXIO:
		return "ICE_AQ_RC_ENXIO";
	case ICE_AQ_RC_E2BIG:
		return "ICE_AQ_RC_E2BIG";
	case ICE_AQ_RC_EAGAIN:
		return "ICE_AQ_RC_EAGAIN";
	case ICE_AQ_RC_ENOMEM:
		return "ICE_AQ_RC_ENOMEM";
	case ICE_AQ_RC_EACCES:
		return "ICE_AQ_RC_EACCES";
	case ICE_AQ_RC_EFAULT:
		return "ICE_AQ_RC_EFAULT";
	case ICE_AQ_RC_EBUSY:
		return "ICE_AQ_RC_EBUSY";
	case ICE_AQ_RC_EEXIST:
		return "ICE_AQ_RC_EEXIST";
	case ICE_AQ_RC_EINVAL:
		return "ICE_AQ_RC_EINVAL";
	case ICE_AQ_RC_ENOTTY:
		return "ICE_AQ_RC_ENOTTY";
	case ICE_AQ_RC_ENOSPC:
		return "ICE_AQ_RC_ENOSPC";
	case ICE_AQ_RC_ENOSYS:
		return "ICE_AQ_RC_ENOSYS";
	case ICE_AQ_RC_ERANGE:
		return "ICE_AQ_RC_ERANGE";
	case ICE_AQ_RC_EFLUSHED:
		return "ICE_AQ_RC_EFLUSHED";
	case ICE_AQ_RC_BAD_ADDR:
		return "ICE_AQ_RC_BAD_ADDR";
	case ICE_AQ_RC_EMODE:
		return "ICE_AQ_RC_EMODE";
	case ICE_AQ_RC_EFBIG:
		return "ICE_AQ_RC_EFBIG";
	case ICE_AQ_RC_ESBCOMP:
		return "ICE_AQ_RC_ESBCOMP";
	case ICE_AQ_RC_ENOSEC:
		return "ICE_AQ_RC_ENOSEC";
	case ICE_AQ_RC_EBADSIG:
		return "ICE_AQ_RC_EBADSIG";
	case ICE_AQ_RC_ESVN:
		return "ICE_AQ_RC_ESVN";
	case ICE_AQ_RC_EBADMAN:
		return "ICE_AQ_RC_EBADMAN";
	case ICE_AQ_RC_EBADBUF:
		return "ICE_AQ_RC_EBADBUF";
	case ICE_AQ_RC_EACCES_BMCU:
		return "ICE_AQ_RC_EACCES_BMCU";
	}

	return "ICE_AQ_RC_UNKNOWN";
}

/**
 * ice_stat_str - convert status err code to a string
 * @stat_err: the status error code to convert
 */
const char *ice_stat_str(enum ice_status stat_err)
{
	switch (stat_err) {
	case ICE_SUCCESS:
		return "OK";
	case ICE_ERR_PARAM:
		return "ICE_ERR_PARAM";
	case ICE_ERR_NOT_IMPL:
		return "ICE_ERR_NOT_IMPL";
	case ICE_ERR_NOT_READY:
		return "ICE_ERR_NOT_READY";
	case ICE_ERR_NOT_SUPPORTED:
		return "ICE_ERR_NOT_SUPPORTED";
	case ICE_ERR_BAD_PTR:
		return "ICE_ERR_BAD_PTR";
	case ICE_ERR_INVAL_SIZE:
		return "ICE_ERR_INVAL_SIZE";
	case ICE_ERR_DEVICE_NOT_SUPPORTED:
		return "ICE_ERR_DEVICE_NOT_SUPPORTED";
	case ICE_ERR_RESET_FAILED:
		return "ICE_ERR_RESET_FAILED";
	case ICE_ERR_FW_API_VER:
		return "ICE_ERR_FW_API_VER";
	case ICE_ERR_NO_MEMORY:
		return "ICE_ERR_NO_MEMORY";
	case ICE_ERR_CFG:
		return "ICE_ERR_CFG";
	case ICE_ERR_OUT_OF_RANGE:
		return "ICE_ERR_OUT_OF_RANGE";
	case ICE_ERR_ALREADY_EXISTS:
		return "ICE_ERR_ALREADY_EXISTS";
	case ICE_ERR_NVM:
		return "ICE_ERR_NVM";
	case ICE_ERR_NVM_CHECKSUM:
		return "ICE_ERR_NVM_CHECKSUM";
	case ICE_ERR_BUF_TOO_SHORT:
		return "ICE_ERR_BUF_TOO_SHORT";
	case ICE_ERR_NVM_BLANK_MODE:
		return "ICE_ERR_NVM_BLANK_MODE";
	case ICE_ERR_IN_USE:
		return "ICE_ERR_IN_USE";
	case ICE_ERR_MAX_LIMIT:
		return "ICE_ERR_MAX_LIMIT";
	case ICE_ERR_RESET_ONGOING:
		return "ICE_ERR_RESET_ONGOING";
	case ICE_ERR_HW_TABLE:
		return "ICE_ERR_HW_TABLE";
	case ICE_ERR_DOES_NOT_EXIST:
		return "ICE_ERR_DOES_NOT_EXIST";
	case ICE_ERR_AQ_ERROR:
		return "ICE_ERR_AQ_ERROR";
	case ICE_ERR_AQ_TIMEOUT:
		return "ICE_ERR_AQ_TIMEOUT";
	case ICE_ERR_AQ_FULL:
		return "ICE_ERR_AQ_FULL";
	case ICE_ERR_AQ_NO_WORK:
		return "ICE_ERR_AQ_NO_WORK";
	case ICE_ERR_AQ_EMPTY:
		return "ICE_ERR_AQ_EMPTY";
	}

	return "ICE_ERR_AQ_UNKNOWN";
}

/**
 * ice_set_rss - Set RSS keys and lut
 * @vsi: Pointer to VSI structure
 * @seed: RSS hash seed
 * @lut: Lookup table
 * @lut_size: Lookup table size
 *
 * Returns 0 on success, negative on failure
 */
int ice_set_rss(struct ice_vsi *vsi, u8 *seed, u8 *lut, u16 lut_size)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (seed) {
		struct ice_aqc_get_set_rss_keys *buf =
				  (struct ice_aqc_get_set_rss_keys *)seed;

		status = ice_aq_set_rss_key(hw, vsi->idx, buf);

		if (status) {
			dev_err(dev, "Cannot set RSS key, err %s aq_err %s\n",
				ice_stat_str(status),
				ice_aq_str(hw->adminq.rq_last_status));
			return -EIO;
		}
	}

	if (lut) {
		status = ice_aq_set_rss_lut(hw, vsi->idx, vsi->rss_lut_type,
					    lut, lut_size);
		if (status) {
			dev_err(dev, "Cannot set RSS lut, err %s aq_err %s\n",
				ice_stat_str(status),
				ice_aq_str(hw->adminq.rq_last_status));
			return -EIO;
		}
	}

	return 0;
}

/**
 * ice_get_rss - Get RSS keys and lut
 * @vsi: Pointer to VSI structure
 * @seed: Buffer to store the keys
 * @lut: Buffer to store the lookup table entries
 * @lut_size: Size of buffer to store the lookup table entries
 *
 * Returns 0 on success, negative on failure
 */
int ice_get_rss(struct ice_vsi *vsi, u8 *seed, u8 *lut, u16 lut_size)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (seed) {
		struct ice_aqc_get_set_rss_keys *buf =
				  (struct ice_aqc_get_set_rss_keys *)seed;

		status = ice_aq_get_rss_key(hw, vsi->idx, buf);
		if (status) {
			dev_err(dev, "Cannot get RSS key, err %s aq_err %s\n",
				ice_stat_str(status),
				ice_aq_str(hw->adminq.rq_last_status));
			return -EIO;
		}
	}

	if (lut) {
		status = ice_aq_get_rss_lut(hw, vsi->idx, vsi->rss_lut_type,
					    lut, lut_size);
		if (status) {
			dev_err(dev, "Cannot get RSS lut, err %s aq_err %s\n",
				ice_stat_str(status),
				ice_aq_str(hw->adminq.rq_last_status));
			return -EIO;
		}
	}

	return 0;
}

/**
 * ice_bridge_getlink - Get the hardware bridge mode
 * @skb: skb buff
 * @pid: process ID
 * @seq: RTNL message seq
 * @dev: the netdev being configured
 * @filter_mask: filter mask passed in
 * @nlflags: netlink flags passed in
 *
 * Return the bridge mode (VEB/VEPA)
 */
static int
#ifdef HAVE_NDO_DFLT_BRIDGE_GETLINK_VLAN_SUPPORT
ice_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
		   struct net_device *dev, u32 filter_mask, int nlflags)
#elif defined(HAVE_NDO_BRIDGE_GETLINK_NLFLAGS)
ice_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
		   struct net_device *dev, u32 __always_unused filter_mask,
		   int nlflags)
#else
ice_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
		   struct net_device *dev, u32 __always_unused filter_mask)
#endif
{
	struct ice_netdev_priv *np = netdev_priv(dev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	u16 bmode;

	bmode = pf->first_sw->bridge_mode;

#ifdef HAVE_NDO_DFLT_BRIDGE_GETLINK_VLAN_SUPPORT
	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode, 0, 0, nlflags,
				       filter_mask, NULL);
#elif defined(HAVE_NDO_BRIDGE_GETLINK_NLFLAGS)
	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode, 0, 0,
				       nlflags);
#elif defined(HAVE_NDO_FDB_ADD_VID) || defined(NDO_DFLT_BRIDGE_GETLINK_HAS_BRFLAGS)
	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode, 0, 0);
#else
	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode);
#endif
}

/**
 * ice_vsi_update_bridge_mode - Update VSI for switching bridge mode (VEB/VEPA)
 * @vsi: Pointer to VSI structure
 * @bmode: Hardware bridge mode (VEB/VEPA)
 *
 * Returns 0 on success, negative on failure
 */
static int ice_vsi_update_bridge_mode(struct ice_vsi *vsi, u16 bmode)
{
	struct ice_aqc_vsi_props *vsi_props;
	struct ice_hw *hw = &vsi->back->hw;
	struct ice_vsi_ctx *ctxt;
	enum ice_status status;
	int ret = 0;

	vsi_props = &vsi->info;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->info = vsi->info;

	if (bmode == BRIDGE_MODE_VEB)
		/* change from VEPA to VEB mode */
		ctxt->info.sw_flags |= (ICE_AQ_VSI_SW_FLAG_ALLOW_LB |
					ICE_AQ_VSI_SW_FLAG_LOCAL_LB);
	else
		/* change from VEB to VEPA mode */
		ctxt->info.sw_flags &= ~(ICE_AQ_VSI_SW_FLAG_ALLOW_LB |
					 ICE_AQ_VSI_SW_FLAG_LOCAL_LB);

	ctxt->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_SW_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(ice_pf_to_dev(vsi->back), "update VSI for bridge mode failed, bmode = %d err %d aq_err %d\n",
			bmode, status, hw->adminq.sq_last_status);
		ret = -EIO;
		goto out;
	}
	/* Update sw flags for book keeping */
	vsi_props->sw_flags = ctxt->info.sw_flags;

out:
	kfree(ctxt);
	return ret;
}

#ifdef HAVE_NDO_BRIDGE_SETLINK_EXTACK
/**
 * ice_bridge_setlink - Set the hardware bridge mode
 * @dev: the netdev being configured
 * @nlh: RTNL message
 * @flags: bridge setlink flags
 * @extack: netlink extended ack
 *
 * Sets the bridge mode (VEB/VEPA) of the switch to which the netdev (VSI) is
 * hooked up to. Iterates through the PF VSI list and sets the loopback mode (if
 * not already set for all VSIs connected to this switch. And also update the
 * unicast switch filter rules for the corresponding switch of the netdev.
 */
static int
ice_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
		   u16 __always_unused flags,
		   struct netlink_ext_ack __always_unused *extack)
#elif defined(HAVE_NDO_BRIDGE_SET_DEL_LINK_FLAGS)
static int
ice_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
		   u16 __always_unused flags)
#else
static int ice_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh)
#endif
{
	struct ice_netdev_priv *np = netdev_priv(dev);
	struct ice_pf *pf = np->vsi->back;
	struct nlattr *attr, *br_spec;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
	struct ice_sw *pf_sw;
	int rem, v, err = 0;

	pf_sw = pf->first_sw;
	/* find the attribute in the netlink message */
	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);

	nla_for_each_nested(attr, br_spec, rem) {
		__u16 mode;

		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;
		mode = nla_get_u16(attr);
		if (mode != BRIDGE_MODE_VEPA && mode != BRIDGE_MODE_VEB)
			return -EINVAL;
		/* Continue  if bridge mode is not being flipped */
		if (mode == pf_sw->bridge_mode)
			continue;
		/* Iterates through the PF VSI list and update the loopback
		 * mode of the VSI
		 */
		ice_for_each_vsi(pf, v) {
			if (!pf->vsi[v])
				continue;
			err = ice_vsi_update_bridge_mode(pf->vsi[v], mode);
			if (err)
				return err;
		}

		hw->evb_veb = (mode == BRIDGE_MODE_VEB);
		/* Update the unicast switch filter rules for the corresponding
		 * switch of the netdev
		 */
		status = ice_update_sw_rule_bridge_mode(hw);
		if (status) {
			netdev_err(dev, "switch rule update failed, mode = %d err %d aq_err %d\n",
				   mode, status, hw->adminq.sq_last_status);
			/* revert hw->evb_veb */
			hw->evb_veb = (pf_sw->bridge_mode == BRIDGE_MODE_VEB);
			return -EIO;
		}

		pf_sw->bridge_mode = mode;
	}

	return 0;
}

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
/**
 * ice_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: Tx queue
 */
static void
ice_tx_timeout(struct net_device *netdev, unsigned int __always_unused txqueue)
#else
static void ice_tx_timeout(struct net_device *netdev)
#endif
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_ring *tx_ring = NULL;
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	int hung_queue = -1;
	u32 i;
#ifdef HAVE_PF_RING
	struct ice_pf *adapter = ice_netdev_to_pf(netdev);
#endif

	pf->tx_timeout_count++;

	/* find the stopped queue the same way dev_watchdog() does */
	for (i = 0; i < netdev->num_tx_queues; i++) {
		unsigned long trans_start;
		struct netdev_queue *q;

		q = netdev_get_tx_queue(netdev, i);
		trans_start = q->trans_start;
		if (netif_xmit_stopped(q) &&
		    time_after(jiffies,
			       trans_start + netdev->watchdog_timeo)) {
			hung_queue = i;
			break;
		}
	}

	if (i == netdev->num_tx_queues) {
		netdev_info(netdev, "tx_timeout: no netdev hung queue found\n");
	} else {
		/* Check if PFC is enabled for the TC to which the queue belongs
		 * to. If yes then Tx timeout is not caused by a hung queue, no
		 * need to reset and rebuild
		 */
		if (hung_queue >= 0 &&
		    ice_is_pfc_causing_hung_q(pf, hung_queue)) {
			dev_info(ice_pf_to_dev(pf), "Fake Tx hang detected on queue %d, timeout caused by PFC storm\n",
				 hung_queue);
			return;
		}

		/* now that we have an index, find the tx_ring struct */
		ice_for_each_txq(vsi, i)
			if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc)
				if (hung_queue == vsi->tx_rings[i]->q_index) {
					tx_ring = vsi->tx_rings[i];
					break;
				}
	}

#ifdef HAVE_PF_RING
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		if (tx_ring && atomic_read(&tx_ring->pfring_zc.queue_in_use))
			printk("[PF_RING-ZC] %s: queue in use\n", __FUNCTION__);
		else
			printk("[PF_RING-ZC] %s: device in use\n", __FUNCTION__);
		return; /* avoid card reset while application is running on top of ZC */
	} else {
		printk("[PF_RING-ZC] %s: device not in use, ignoring reset anyway\n", __FUNCTION__);
		return;
	}
#endif

	/* Reset recovery level if enough time has elapsed after last timeout.
	 * Also ensure no new reset action happens before next timeout period.
	 */
	if (time_after(jiffies, (pf->tx_timeout_last_recovery + HZ * 20)))
		pf->tx_timeout_recovery_level = 1;
	else if (time_before(jiffies, (pf->tx_timeout_last_recovery +
				       netdev->watchdog_timeo)))
		return;

	if (tx_ring) {
		struct ice_hw *hw = &pf->hw;
		u32 head, val = 0;

		head = (rd32(hw, QTX_COMM_HEAD(vsi->txq_map[hung_queue])) &
			QTX_COMM_HEAD_HEAD_M) >> QTX_COMM_HEAD_HEAD_S;
		/* Read interrupt register */
		val = rd32(hw, GLINT_DYN_CTL(tx_ring->q_vector->reg_idx));

		netdev_info(netdev, "tx_timeout: VSI_num: %d, Q %d, NTC: 0x%x, HW_HEAD: 0x%x, NTU: 0x%x, INT: 0x%x\n",
			    vsi->vsi_num, hung_queue, tx_ring->next_to_clean,
			    head, tx_ring->next_to_use, val);
	}

	pf->tx_timeout_last_recovery = jiffies;
	netdev_info(netdev, "tx_timeout recovery level %d, hung_queue %d\n",
		    pf->tx_timeout_recovery_level, hung_queue);

	switch (pf->tx_timeout_recovery_level) {
	case 1:
		set_bit(__ICE_PFR_REQ, pf->state);
		break;
	case 2:
		set_bit(__ICE_CORER_REQ, pf->state);
		break;
	case 3:
		set_bit(__ICE_GLOBR_REQ, pf->state);
		break;
	default:
		netdev_err(netdev, "tx_timeout recovery unsuccessful, device is in unrecoverable state.\n");
		set_bit(__ICE_DOWN, pf->state);
		set_bit(__ICE_NEEDS_RESTART, vsi->state);
		set_bit(__ICE_SERVICE_DIS, pf->state);
		break;
	}

	ice_service_task_schedule(pf);
	pf->tx_timeout_recovery_level++;
}

/**
 * ice_udp_tunnel_add - Get notifications about UDP tunnel ports that come up
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
static void
#else
static void __maybe_unused
#endif
ice_udp_tunnel_add(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	enum ice_tunnel_type tnl_type;
	u16 port = ntohs(ti->port);

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		tnl_type = TNL_VXLAN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		tnl_type = TNL_GENEVE;
		break;
	default:
		netdev_err(netdev, "Unknown tunnel type\n");
		return;
	}

	if (!ice_is_safe_mode(pf)) {
		enum ice_status status;

		status = ice_create_tunnel(&pf->hw, tnl_type, port);
		if (status == ICE_ERR_ALREADY_EXISTS)
			dev_dbg(ice_pf_to_dev(pf), "port %d already exists in UDP tunnels list\n",
				port);
		else if (status == ICE_ERR_OUT_OF_RANGE)
			netdev_err(netdev, "Max tunneled UDP ports reached, port %d not added\n",
				   port);
		else if (status)
			netdev_err(netdev, "Error adding UDP tunnel - %s\n",
				   ice_stat_str(status));
	} else {
		if (tnl_type == TNL_VXLAN && port != ICE_DFLT_PORT_VXLAN)
			netdev_err(netdev, "Only port# %d can be added for VxLAN in basic mode\n",
				   ICE_DFLT_PORT_VXLAN);
		else if (tnl_type == TNL_GENEVE && port != ICE_DFLT_PORT_GENEVE)
			netdev_err(netdev, "Only port# %d can be added for GENEVE in basic mode\n",
				   ICE_DFLT_PORT_GENEVE);
	}
}

/**
 * ice_udp_tunnel_del - Get notifications about UDP tunnel ports that go away
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
static void
#else
static void __maybe_unused
#endif
ice_udp_tunnel_del(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	u16 port = ntohs(ti->port);
	enum ice_status status;
	bool retval;
	u16 index;

	/* In basic mode entries cannot be modified/deleted */
	if (ice_is_safe_mode(pf))
		return;

	retval = ice_tunnel_port_in_use(&pf->hw, port, &index);
	if (!retval) {
		netdev_err(netdev, "port %d not found in UDP tunnels list\n",
			   port);
		return;
	}

	status = ice_destroy_tunnel(&pf->hw, port, false);
	if (status)
		netdev_err(netdev, "error deleting port %d from UDP tunnels list\n",
			   port);
}

#if defined(HAVE_VXLAN_RX_OFFLOAD) && !defined(HAVE_UDP_ENC_RX_OFFLOAD)
#if IS_ENABLED(CONFIG_VXLAN)
/**
 * ice_add_vxlan_port - Get notifications about VxLAN ports that come up
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that VxLAN is notifying us about
 * @port: New UDP port number that VxLAN started listening to
 */
static void
ice_add_vxlan_port(struct net_device *netdev, sa_family_t sa_family,
		   __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_VXLAN,
		.sa_family = sa_family,
		.port = port,
	};

	ice_udp_tunnel_add(netdev, &ti);
}

/**
 * ice_del_vxlan_port - Get notifications about VxLAN ports that go away
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that VxLAN is notifying us about
 * @port: UDP port number that VxLAN stopped listening to
 */
static void
ice_del_vxlan_port(struct net_device *netdev, sa_family_t sa_family,
		   __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_VXLAN,
		.sa_family = sa_family,
		.port = port,
	};

	ice_udp_tunnel_del(netdev, &ti);
}
#endif /* CONFIG_VXLAN */
#endif /* HAVE_VXLAN_RX_OFFLOAD && !HAVE_UDP_ENC_RX_OFFLOAD */

#if defined(HAVE_GENEVE_RX_OFFLOAD) && !defined(HAVE_UDP_ENC_RX_OFFLOAD)
#if IS_ENABLED(CONFIG_GENEVE)
/**
 * ice_add_geneve_port - Get notifications about GENEVE ports that come up
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that GENEVE is notifying us about
 * @port: New UDP port number that GENEVE started listening to
 */
static void
ice_add_geneve_port(struct net_device *netdev, sa_family_t sa_family,
		    __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_GENEVE,
		.sa_family = sa_family,
		.port = port,
	};

	ice_udp_tunnel_add(netdev, &ti);
}

/**
 * ice_del_geneve_port - Get notifications about GENEVE ports that go away
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that GENEVE is notifying us about
 * @port: UDP port number that GENEVE stopped listening to
 */
static void
ice_del_geneve_port(struct net_device *netdev, sa_family_t sa_family,
		    __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_GENEVE,
		.sa_family = sa_family,
		.port = port,
	};

	ice_udp_tunnel_del(netdev, &ti);
}

#endif /* CONFIG_GENEVE */
#endif /* HAVE_GENEVE_RX_OFFLOAD  && !HAVE_UDP_ENC_RX_OFFLOAD */

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_tc_set_ipv4 - Parse IPv4 addresses from TC flower filter
 * @pf: Pointer to PF device
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv4 address
 */
static int
ice_tc_set_ipv4(struct ice_pf *pf, struct flow_match_ipv4_addrs match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (match.mask->dst) {
		if (match.mask->dst == cpu_to_be32(ICE_TC_FLOWER_MASK_32)) {
			if (is_encap)
				fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DEST_IPV4;
			else
				fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV4;
		} else {
			dev_err(dev, "Bad IP dst mask %pI4\n",
				&match.mask->dst);
			return -EINVAL;
		}
	}
	if (match.mask->src) {
		if (match.mask->src == cpu_to_be32(ICE_TC_FLOWER_MASK_32)) {
			if (is_encap)
				fltr->flags |= ICE_TC_FLWR_FIELD_ENC_SRC_IPV4;
			else
				fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV4;
		} else {
			dev_err(dev, "Bad IP src mask %pI4\n",
				&match.mask->src);
			return -EINVAL;
		}
	}
	headers->dst_ipv4 = match.key->dst;
	headers->src_ipv4 = match.key->src;
	return 0;
}

/**
 * ice_tc_set_ipv6 - Parse IPv6 addresses from TC flower filter
 * @pf: ptr to PF device
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv6 address
 */
static int
ice_tc_set_ipv6(struct ice_pf *pf, struct flow_match_ipv6_addrs match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	struct device *dev = ice_pf_to_dev(pf);

	/* src and dest IPV6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1), which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match.key->dst) ||
	    ipv6_addr_loopback(&match.key->src)) {
		dev_err(dev, "Bad ipv6, addr is LOOPBACK\n");
		return -EINVAL;
	}
	/* if src/dest IPv6 address is *,* error */
	if (ipv6_addr_any(&match.mask->dst) &&
	    ipv6_addr_any(&match.mask->src)) {
		dev_err(dev, "Bad src/dest IPv6, addr is any\n");
		return -EINVAL;
	}
	if (!ipv6_addr_any(&match.mask->dst)) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DEST_IPV6;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV6;
	}
	if (!ipv6_addr_any(&match.mask->src)) {
		if (is_encap)
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_SRC_IPV6;
		else
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV6;
	}
	if (fltr->flags & (ICE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
			   ICE_TC_FLWR_FIELD_SRC_IPV6))
		memcpy(&headers->src_ipv6_addr, &match.key->src.s6_addr,
		       sizeof(match.key->src.s6_addr));
	if (fltr->flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
			   ICE_TC_FLWR_FIELD_DEST_IPV6))
		memcpy(&headers->dst_ipv6_addr, &match.key->dst.s6_addr,
		       sizeof(match.key->dst.s6_addr));

	return 0;
}

/**
 * ice_tc_set_port - Parse ports from TC flower filter
 * @pf: ptr to PF device
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel port
 */
static int
ice_tc_set_port(struct ice_pf *pf, struct flow_match_ports match,
		struct ice_tc_flower_fltr *fltr,
		struct ice_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (match.mask->dst) {
		if (match.mask->dst == cpu_to_be16(ICE_TC_FLOWER_MASK_16)) {
			if (is_encap)
				fltr->flags |=
					ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
			else
				fltr->flags |= ICE_TC_FLWR_FIELD_DEST_L4_PORT;
		} else {
			dev_err(dev, "Bad dst port mask 0x%04x\n",
				be16_to_cpu(match.mask->dst));
			return -EINVAL;
		}
	}
	if (match.mask->src) {
		if (match.mask->src == cpu_to_be16(ICE_TC_FLOWER_MASK_16)) {
			if (is_encap)
				fltr->flags |=
					ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT;
			else
				fltr->flags |= ICE_TC_FLWR_FIELD_SRC_L4_PORT;
		} else {
			dev_err(dev, "Bad src port mask 0x%04x\n",
				be16_to_cpu(match.mask->dst));
			return -EINVAL;
		}
	}
	headers->dst_port = match.key->dst;
	headers->src_port = match.key->src;
	return 0;
}

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
/**
 * ice_tc_tun_get_type - Get the tunnel type for the tunnel device
 * @tunnel_dev: ptr to tunnel device
 */
static int
ice_tc_tun_get_type(struct net_device *tunnel_dev)
{
	enum ice_tunnel_type tnl_type = TNL_LAST;
#ifdef HAVE_VXLAN_TYPE
#if IS_ENABLED(CONFIG_VXLAN)
	if (netif_is_vxlan(tunnel_dev))
		tnl_type = TNL_VXLAN;
#endif /* HAVE_VXLAN_TYPE */
#elif defined(HAVE_GENEVE_TYPE)
#if IS_ENABLED(CONFIG_GENEVE)
	if (netif_is_geneve(tunnel_dev))
		tnl_type = TNL_GENEVE;
#endif
#endif /* HAVE_GENEVE_TYPE */
	return tnl_type;
}

/**
 * ice_tc_tun_parse_vxlan- Parse VXLAN tunnel attributes from TC flower filter
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
static int
ice_tc_tun_parse_vxlan(struct ice_pf *pf, struct flow_cls_offload *f,
		       struct ice_tc_flower_fltr *fltr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);

	/* match on VNI */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct device *dev = ice_pf_to_dev(pf);
		struct flow_match_enc_keyid enc_keyid;

		flow_rule_match_enc_keyid(rule, &enc_keyid);
		if (enc_keyid.mask->keyid != 0) {
			if (enc_keyid.mask->keyid ==
					cpu_to_be32(ICE_TC_FLOWER_MASK_32)) {
				fltr->flags |= ICE_TC_FLWR_FIELD_TENANT_ID;
			}  else {
				dev_err(dev, "Bad VNI mask 0x%04x\n",
					be32_to_cpu(enc_keyid.mask->keyid));
				return -EINVAL;
			}
		}
		/* VNI is only 3 bytes */
		if (be32_to_cpu(enc_keyid.key->keyid) > ICE_TC_FLOWER_VNI_MAX) {
			dev_err(dev, "VNI out of range : 0x%x\n",
				be32_to_cpu(enc_keyid.key->keyid));
			return -EINVAL;
		}
		fltr->tenant_id = enc_keyid.key->keyid;
	}
	return 0;
}

/**
 * ice_tc_tun_parse - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
ice_tc_tun_parse(struct net_device *filter_dev, struct ice_vsi *vsi,
		 struct flow_cls_offload *f,
		 struct ice_tc_flower_fltr *fltr,
		 struct ice_tc_flower_lyr_2_4_hdrs *headers)
{
	enum ice_tunnel_type tunnel_type;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	tunnel_type = ice_tc_tun_get_type(filter_dev);

	/* Only VXLAN filters are supported now */
	if (tunnel_type == TNL_VXLAN) {
		err = ice_tc_tun_parse_vxlan(pf, f, fltr);
		if (err) {
			dev_err(dev, "Failed parsing VXLAN tunnel attributes\n");
			return err;
		}
	} else {
		dev_err(dev, "Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	fltr->tunnel_type = tunnel_type;
	headers->ip_proto = IPPROTO_UDP;
	return err;
}

/**
 * ice_parse_tunnel_attr - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
ice_parse_tunnel_attr(struct net_device *filter_dev, struct ice_vsi *vsi,
		      struct flow_cls_offload *f,
		      struct ice_tc_flower_fltr *fltr,
		      struct ice_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control enc_control;
	struct ice_pf *pf = vsi->back;
	int err;

	err = ice_tc_tun_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "failed to parse tunnel attributes\n");
		return err;
	}

	flow_rule_match_enc_control(rule, &enc_control);

	if (enc_control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);
		if (ice_tc_set_ipv4(pf, match, fltr, headers, true))
			return -EINVAL;
	} else if (enc_control.key->addr_type ==
					FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);
		if (ice_tc_set_ipv6(pf, match, fltr, headers, true))
			return -EINVAL;
	}

#ifdef HAVE_TC_FLOWER_ENC_IP
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_match_ip match;

		flow_rule_match_enc_ip(rule, &match);
		headers->tos = match.key->tos;
		headers->ttl = match.key->ttl;
	}
#endif /* HAVE_TC_FLOWER_ENC_IP */
	return 0;
}
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

/**
 * ice_parse_cls_flower - Parse TC flower filters provided by kernel
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
ice_parse_cls_flower(struct net_device *filter_dev, struct ice_vsi *vsi,
		     struct flow_cls_offload *f,
		     struct ice_tc_flower_fltr *fltr)
#else
static int
ice_parse_cls_flower(struct net_device __always_unused *filter_dev,
		     struct ice_vsi *vsi, struct tc_cls_flower_offload *f,
		     struct ice_tc_flower_fltr *fltr)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &fltr->outer_headers;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = rule->match.dissector;
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;
	struct ice_pf *pf = vsi->back;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	      BIT(FLOW_DISSECTOR_KEY_VLANID) |
#else
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
#ifdef HAVE_TC_FLOWER_ENC
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
#ifdef HAVE_TC_FLOWER_ENC_IP
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif /* HAVE_TC_FLOWER_ENC_IP */
#endif /* HAVE_TC_FLOWER_ENC */
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		dev_err(dev, "Unsupported key used: 0x%x\n",
			dissector->used_keys);
		return -EOPNOTSUPP;
	}

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
	if ((flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
	     flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) ||
	     flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
	     flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS))) {
		int err;

		err = ice_parse_tunnel_attr(filter_dev, vsi, f, fltr, headers);
		if (err) {
			dev_err(dev, "Failed to parse TC flower tunnel fields\n");
			return err;
		}

		/* header pointers should point to the inner headers, outer
		 * header were already set by ice_parse_tunnel_attr
		 */
		headers = &fltr->inner_headers;
	} else {
		fltr->tunnel_type = TNL_LAST;
	}
#else /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */
	fltr->tunnel_type = TNL_LAST;
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		if (n_proto_key == ETH_P_ALL) {
			n_proto_key = 0;
			n_proto_mask = 0;
		}
		headers->n_proto = n_proto_key & n_proto_mask;
		headers->ip_proto = match.key->ip_proto;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		/* use is_broadcast and is_zero to check for all 0xf or 0 */
		if (!is_zero_ether_addr(match.mask->dst)) {
			if (is_broadcast_ether_addr(match.mask->dst)) {
				fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
			} else {
				dev_err(dev, "Bad ether dest mask %pM\n",
					match.mask->dst);
				return -EINVAL;
			}
		}

		if (!is_zero_ether_addr(match.mask->src)) {
			if (is_broadcast_ether_addr(match.mask->src)) {
				fltr->flags |= ICE_TC_FLWR_FIELD_SRC_MAC;
			} else {
				dev_err(dev, "Bad ether src mask %pM\n",
					match.mask->dst);
				return -EINVAL;
			}
		}
		ether_addr_copy(headers->dst_mac, match.key->dst);
		ether_addr_copy(headers->src_mac, match.key->src);
	}

#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	if (dissector_uses_key(dissector, FLOW_DISSECTOR_KEY_VLANID)) {
		struct flow_dissector_key_tags *key =
			(struct flow_dissector_key_tags *)
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLANID,
						  f->key);
		struct flow_dissector_key_tags *mask =
			(struct flow_dissector_key_tags *)
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLANID,
						  f->mask);

		if (mask->vlan_id) {
			if (mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;

			} else {
				dev_err(dev, "Bad VLAN mask 0x%04x\n",
					mask->vlan_id);
				return -EINVAL;
			}
		}
		headers->vlan_hdr.vlan_id =
				cpu_to_be16(key->vlan_id & VLAN_VID_MASK);
#ifdef HAVE_FLOW_DISSECTOR_VLAN_PRIO
		if (mask->vlan_priority)
			headers->vlan_hdr.vlan_prio = key->vlan_priority;
#endif
	}
#else /* !HAVE_TC_FLOWER_VLAN_IN_TAGS */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);

		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;

			} else {
				dev_err(dev, "Bad VLAN mask 0x%04x\n",
					match.mask->vlan_id);
				return -EINVAL;
			}
		}

		headers->vlan_hdr.vlan_id =
				cpu_to_be16(match.key->vlan_id & VLAN_VID_MASK);
#ifdef HAVE_FLOW_DISSECTOR_VLAN_PRIO
		if (match.mask->vlan_priority)
			headers->vlan_hdr.vlan_prio = match.key->vlan_priority;
#endif
	}
#endif /* HAVE_TC_FLOWER_VLAN_IN_TAGS */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);

		addr_type = match.key->addr_type;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		if (ice_tc_set_ipv4(pf, match, fltr, headers, false))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		if (ice_tc_set_ipv6(pf, match, fltr, headers, false))
			return -EINVAL;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		if (ice_tc_set_port(pf, match, fltr, headers, false))
			return -EINVAL;
		switch (headers->ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		default:
			dev_err(dev, "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * ice_add_remove_tc_flower_dflt_fltr - add or remove default filter
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 * @add: true if filter is being added.
 *
 * Add or remove default filter using default recipes to add MAC
 * or VLAN or MAC-VLAN filters.
 */
static int
ice_add_remove_tc_flower_dflt_fltr(struct ice_vsi *vsi,
				   struct ice_tc_flower_fltr *tc_fltr, bool add)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	enum ice_status status = 0;
	LIST_HEAD(tmp_add_list);
	struct device *dev;
	int error = 0;
	u16 vlan_id;

	dev = ice_pf_to_dev(pf);
	switch (tc_fltr->flags) {
	case ICE_TC_FLWR_FLTR_FLAGS_DST_MAC:
		error = ice_add_mac_to_list(vsi, &tmp_add_list,
					    headers->dst_mac,
					    tc_fltr->action.fltr_act);
		if (error)
			goto error_exit;

		if (add) {
			/* add MAC filter rule(s) */
			status = ice_add_mac(hw, &tmp_add_list);
			if (status) {
				dev_err(dev, "Could not add MAC filters\n");
				error = -ENOMEM;
				goto error_exit;
			}
		} else {
			/* remove MAC filter rule(s) */
			status = ice_remove_mac(hw, &tmp_add_list);
			if (status) {
				dev_err(dev, "Could not remove MAC filters\n");
				error = -ENOMEM;
				goto error_exit;
			}
		}
		break;
	case ICE_TC_FLWR_FLTR_FLAGS_VLAN:
		vlan_id = be16_to_cpu(headers->vlan_hdr.vlan_id);
		if (add) {
			error = ice_vsi_add_vlan(vsi, vlan_id,
						 tc_fltr->action.fltr_act);
			if (error)
				dev_err(dev, "Could not add VLAN filters\n");
		} else {
			error = ice_vsi_kill_vlan(vsi, vlan_id);
			if (error)
				dev_err(dev, "Could not delete VLAN filters\n");
		}
		return error;
	case ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN:
		vlan_id = be16_to_cpu(headers->vlan_hdr.vlan_id);
		error = ice_add_mac_vlan_to_list(pf, vsi, &tmp_add_list,
						 headers->dst_mac, vlan_id,
						 tc_fltr->action.fltr_act);
		if (error)
			goto error_exit;
		if (add) {
			status = ice_add_mac_vlan(hw, &tmp_add_list);
			if (status) {
				dev_err(dev, "Could not add MAC_VLAN filters\n");
				error = -ENOMEM;
				goto error_exit;
			}
		} else {
			status = ice_remove_mac_vlan(hw, &tmp_add_list);
			if (status) {
				dev_err(dev, "Could not remove MAC_VLAN filters\n");
				error = -ENOMEM;
				goto error_exit;
			}
		}
		break;
	default:
		dev_err(dev, "Not a default filter type\n");
		error = -EOPNOTSUPP;
		break;
	}
error_exit:
	ice_free_fltr_list(dev, &tmp_add_list);
	return error;
}

/**
 * ice_chnl_fltr_type_chk - filter type check
 * @tc_fltr: Pointer to TC flower filter structure
 * @final_fltr_type: Ptr to filter type (dest/src/dest+src port)
 *
 * This function is used to determine if given filter (based on input params)
 * should be allowed or not. For a given channel (aka ADQ VSI), supported
 * filter types are src port, dest port , src+dest port. SO this function
 * checks if any filter exist for specified channel (if so, channel specific
 * filter_type will be set), and see if it matches with the filter being added.
 * It returns 0 (upon success) or POSIX error code
 */
static int
ice_chnl_fltr_type_chk(struct ice_tc_flower_fltr *tc_fltr,
		       enum ice_channel_fltr_type *final_fltr_type)
{
	enum ice_channel_fltr_type fltr_type = *final_fltr_type;

	if (fltr_type == ICE_CHNL_FLTR_TYPE_INVALID) {
		if ((tc_fltr->flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT) &&
		    (tc_fltr->flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT))
			fltr_type = ICE_CHNL_FLTR_TYPE_SRC_DEST_PORT;
		else if (tc_fltr->flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT)
			fltr_type = ICE_CHNL_FLTR_TYPE_DEST_PORT;
		else if (tc_fltr->flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT)
			fltr_type = ICE_CHNL_FLTR_TYPE_SRC_PORT;
		else if (tc_fltr->flags & ICE_TC_FLWR_FIELD_TENANT_ID)
			fltr_type = ICE_CHNL_FLTR_TYPE_TENANT_ID;
		else
			return -EOPNOTSUPP;
	} else if (fltr_type == ICE_CHNL_FLTR_TYPE_SRC_PORT) {
		/* now only allow src port based filters */
		if (tc_fltr->flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT)
			return -EOPNOTSUPP;
		fltr_type = ICE_CHNL_FLTR_TYPE_SRC_PORT;
	} else if (fltr_type == ICE_CHNL_FLTR_TYPE_DEST_PORT) {
		/* now only allow dest port based filters */
		if (tc_fltr->flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT)
			return -EOPNOTSUPP;
		fltr_type = ICE_CHNL_FLTR_TYPE_DEST_PORT;
	} else if (fltr_type == ICE_CHNL_FLTR_TYPE_SRC_DEST_PORT) {
		/* now only allow filters which has both
		 * (src and dest) bits set
		 */
		if (!((tc_fltr->flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT) &&
		      (tc_fltr->flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT)))
			return -EOPNOTSUPP;
	} else if (fltr_type == ICE_CHNL_FLTR_TYPE_TENANT_ID) {
		/* Now only allow filters which has VNI */
		if (!(tc_fltr->flags & ICE_TC_FLWR_FIELD_TENANT_ID))
			return -EOPNOTSUPP;
	} else {
		return -EINVAL; /* unsupported filter type */
	}

	/* return the selected fltr_type */
	*final_fltr_type = fltr_type;

	return 0;
}

/**
 * ice_add_tc_flower_adv_fltr - add appropriate filter rules
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 *
 * based on filter parameters using Advance recipes supported
 * by OS package.
 */
int
ice_add_tc_flower_adv_fltr(struct ice_vsi *vsi,
			   struct ice_tc_flower_fltr *tc_fltr)
{
	struct ice_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	enum ice_channel_fltr_type fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
	struct ice_adv_rule_info rule_info = {0};
	struct ice_rule_query_data rule_added;
	struct ice_adv_lkup_elem *list;
	struct ice_pf *pf = vsi->back;
	struct ice_channel_vf *vf_ch;
	struct ice_hw *hw = &pf->hw;
	u32 flags = tc_fltr->flags;
	enum ice_status status;
	struct ice_vsi *ch_vsi;
	struct device *dev;
	struct ice_vf *vf;
	u16 lkups_cnt = 0;
	int ret = 0;
	u16 i = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_is_safe_mode(pf)) {
		dev_err(dev, "Advanced switch filter support disabled\n");
		return -EOPNOTSUPP;
	}

	if (!flags || (flags & (ICE_TC_FLWR_FIELD_ENC_DEST_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
				ICE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
				ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT)))
		return -EINVAL;

	/* get the channel (aka ADQ VSI) */
	if (tc_fltr->dest_vsi)
		ch_vsi = tc_fltr->dest_vsi;
	else
		ch_vsi = vsi->tc_map_vsi[tc_fltr->action.tc_class];

	/* Is outer dest port specified */
	if (flags & ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT)
		lkups_cnt++;

	/* is Tunnel ID specified */
	if (flags & ICE_TC_FLWR_FIELD_TENANT_ID) {
		lkups_cnt++;
		if (flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC)
			lkups_cnt++;
	}

	/* is MAC fields specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DST_MAC | ICE_TC_FLWR_FIELD_SRC_MAC))
		lkups_cnt++;

	/* is VLAN specified? */
	if (flags & ICE_TC_FLWR_FIELD_VLAN)
		lkups_cnt++;

	/* is IPv[4|6] fields specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV4 | ICE_TC_FLWR_FIELD_SRC_IPV4))
		lkups_cnt++;
	else if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV6 |
			  ICE_TC_FLWR_FIELD_SRC_IPV6))
		lkups_cnt++;
	/* is L4 (TCP/UDP/any other L4 protocol fields specified? */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_L4_PORT |
		     ICE_TC_FLWR_FIELD_SRC_L4_PORT))
		lkups_cnt++;


	list = kcalloc(lkups_cnt, sizeof(*list), GFP_ATOMIC);
	if (!list)
		return -ENOMEM;

	/* copy outer dest port */
	if (flags & ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT) {
		if (headers->ip_proto == IPPROTO_UDP)
			list[i].type = ICE_UDP_OF;

		memcpy(&list[i].h_u.l4_hdr.dst_port, &headers->dst_port,
		       sizeof(headers->dst_port));
		memset(&list[i].m_u.l4_hdr.dst_port, 0xff, 2);
		i++;
	}

	/* copy L2 (MAC) fields */
	if (tc_fltr->tunnel_type == TNL_VXLAN) {
		rule_info.tun_type = ICE_SW_TUN_VXLAN;
		/* copy L2 (MAC) fields if specified, For tunnel outer DMAC
		 * is needed and supported and is part of outer_headers.dst_mac
		 * For VxLAN tunnel, supported ADQ filter config is:
		 * - Outer dest MAC + VNI + Inner IPv4 + Inner L4 ports
		 */
		if (flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC) {
			list[i].type = ICE_MAC_OFOS;
			ether_addr_copy(list[i].h_u.eth_hdr.dst_addr,
					headers->dst_mac);
			memset(list[i].m_u.eth_hdr.dst_addr, 0xff,
			       sizeof(list[i].h_u.eth_hdr.dst_addr));
			i++;
		}
		/* now access values from inner_headers such as inner MAC (if
		 * supported), inner IPv4[6], Inner L4 ports , hence update
		 * "headers" to point to inner_headers
		 */
		headers = &tc_fltr->inner_headers;
	} else {
		rule_info.tun_type = ICE_NON_TUN;
		/* copy L2 (MAC) fields, for non-tunnel case */
		if (flags & (ICE_TC_FLWR_FIELD_DST_MAC |
			     ICE_TC_FLWR_FIELD_SRC_MAC)) {
			list[i].type = ICE_MAC_OFOS;
			if (flags & ICE_TC_FLWR_FIELD_DST_MAC) {
				ether_addr_copy(list[i].h_u.eth_hdr.dst_addr,
						headers->dst_mac);
				memset(list[i].m_u.eth_hdr.dst_addr, 0xff,
				       sizeof(list[i].h_u.eth_hdr.dst_addr));
			}
			if (flags & ICE_TC_FLWR_FIELD_SRC_MAC) {
				ether_addr_copy(list[i].h_u.eth_hdr.src_addr,
						headers->src_mac);
				memset(list[i].m_u.eth_hdr.src_addr, 0xff,
				       sizeof(list[i].m_u.eth_hdr.src_addr));
			}
			i++;
		}
	}

	/* copy VLAN info */
	if (flags & ICE_TC_FLWR_FIELD_VLAN) {
		list[i].type = ICE_VLAN_OFOS;
		memcpy(&list[i].h_u.vlan_hdr.vlan, &headers->vlan_hdr.vlan_id,
		       sizeof(headers->vlan_hdr.vlan_id));
		memset(&list[i].m_u.vlan_hdr.vlan, 0xff,
		       sizeof(headers->vlan_hdr.vlan_id));
		i++;
	}

	/* copy VNI */
	if (flags & ICE_TC_FLWR_FIELD_TENANT_ID) {
		__be32 vni;
		u32 ten_id;

		if (tc_fltr->tunnel_type == TNL_VXLAN)
			list[i].type = ICE_VXLAN;
		else if (tc_fltr->tunnel_type == TNL_GENEVE)
			list[i].type = ICE_GENEVE;

		ten_id = be32_to_cpu(tc_fltr->tenant_id) << 8;
		vni = cpu_to_be32(ten_id);

		memcpy(&list[i].h_u.tnl_hdr.vni, &vni,
		       sizeof(tc_fltr->tenant_id));
		/* Copy "\xff\xff\xff\x00" mask for 24 bit VNI */
		memcpy(&list[i].m_u.tnl_hdr.vni, "\xff\xff\xff\x00", 4);
		i++;
	}


	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV4 |
		     ICE_TC_FLWR_FIELD_SRC_IPV4)) {
		if (rule_info.tun_type == ICE_SW_TUN_VXLAN)
			list[i].type = ICE_IPV4_IL;
		else
			list[i].type = ICE_IPV4_OFOS;

		if (flags & ICE_TC_FLWR_FIELD_DEST_IPV4) {
			memcpy(&list[i].h_u.ipv4_hdr.dst_addr,
			       &headers->dst_ipv4,
			       sizeof(headers->dst_ipv4));
			memset(&list[i].m_u.ipv4_hdr.dst_addr, 0xff,
			       sizeof(headers->dst_ipv4));
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_IPV4) {
			memcpy(&list[i].h_u.ipv4_hdr.src_addr,
			       &headers->src_ipv4,
			       sizeof(headers->src_ipv4));
			memset(&list[i].m_u.ipv4_hdr.src_addr, 0xff,
			       sizeof(headers->src_ipv4));
		}
		i++;
	} else if (flags & (ICE_TC_FLWR_FIELD_DEST_IPV6 |
			    ICE_TC_FLWR_FIELD_SRC_IPV6)) {
		struct ice_ipv6_hdr *ipv6_hdr;

		if (rule_info.tun_type == ICE_SW_TUN_VXLAN)
			list[i].type = ICE_IPV6_IL;
		else
			list[i].type = ICE_IPV6_OFOS;
		ipv6_hdr = &list[i].h_u.ipv6_hdr;

		if (flags & ICE_TC_FLWR_FIELD_DEST_IPV6) {
			memcpy(&ipv6_hdr->dst_addr, &headers->dst_ipv6_addr,
			       sizeof(headers->dst_ipv6_addr));
			memset(&list[i].m_u.ipv6_hdr.dst_addr, 0xff,
			       sizeof(headers->dst_ipv6_addr));
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_IPV6) {
			memcpy(&ipv6_hdr->src_addr, &headers->src_ipv6_addr,
			       sizeof(headers->src_ipv6_addr));
			memset(&list[i].m_u.ipv6_hdr.src_addr, 0xff,
			       sizeof(headers->src_ipv6_addr));
		}
		i++;
	}

	/* copy L4 (src, dest) port */
	if (flags & (ICE_TC_FLWR_FIELD_DEST_L4_PORT |
		     ICE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		u16 dst_port = be16_to_cpu(headers->dst_port);

		if (headers->ip_proto == IPPROTO_TCP) {
			list[i].type = ICE_TCP_IL;
		} else {
			/* Check if UDP dst port is known as a tunnel port */
			if (ice_tunnel_port_in_use(hw, dst_port, NULL)) {
				list[i].type = ICE_UDP_OF;
				rule_info.tun_type = ICE_SW_TUN_VXLAN;
			} else {
				list[i].type = ICE_UDP_ILOS;
			}
		}
		if (flags & ICE_TC_FLWR_FIELD_DEST_L4_PORT) {
			memcpy(&list[i].h_u.l4_hdr.dst_port, &headers->dst_port,
			       sizeof(headers->dst_port));
			memset(&list[i].m_u.l4_hdr.dst_port, 0xff, 2);
		}
		if (flags & ICE_TC_FLWR_FIELD_SRC_L4_PORT) {
			memcpy(&list[i].h_u.l4_hdr.src_port, &headers->src_port,
			       sizeof(headers->src_port));
			memset(&list[i].m_u.l4_hdr.src_port, 0xff, 2);
		}
		i++;
	}

	if (i != lkups_cnt) {
		ret = -EINVAL;
		goto exit;
	}

	rule_info.sw_act.fltr_act = tc_fltr->action.fltr_act;
	if (tc_fltr->action.tc_class >= ICE_CHNL_START_TC) {
		if (!ch_vsi) {
			dev_err(dev, "Can't add switch rule because ADQ VSI doesn't exist but tc_class is %u\n",
				tc_fltr->action.tc_class);
			ret = -EINVAL;
			goto exit;
		}

		/* dest_vsi is preset, means it is from virtchnl message */
		if (tc_fltr->dest_vsi) {
			if (vsi->type != ICE_VSI_VF ||
			    tc_fltr->dest_vsi->type != ICE_VSI_VF) {
				dev_err(dev, "Unexpected VSI(vf_id:%u) type: %u\n",
					vsi->vf_id, vsi->type);
				ret = -EINVAL;
				goto exit;
			}
			vf = &pf->vf[vsi->vf_id];
			if (!vf) {
				dev_err(dev, "VF is NULL for VSI->type: ICE_VF_VSI and vf_id %d\n",
					vsi->vf_id);
				ret = -EINVAL;
				goto exit;
			}
			vf_ch = &vf->ch[tc_fltr->action.tc_class];

			fltr_type = (enum ice_channel_fltr_type)
				    vf_ch->fltr_type;
		} else if (ch_vsi->ch) {
			fltr_type = ch_vsi->ch->fltr_type;
		} else {
			dev_err(dev, "Can't add switch rule, neither dest_vsi is valid now VSI channel but tc_class sepcified is %u\n",
				tc_fltr->action.tc_class);
			ret = -EINVAL;
			goto exit;
		}

		/* perform fltr_type check for channel (aka ADQ) VSI */
		ret = ice_chnl_fltr_type_chk(tc_fltr, &fltr_type);
		if (ret) {
			dev_err(dev, "Filter type (%u) check failed TC:%u vsi_idx:%u, lkups_cnt: %u\n",
				fltr_type, tc_fltr->action.tc_class,
				ch_vsi->idx, lkups_cnt);
			ret = -EINVAL;
			goto exit;
		}

		if (tc_fltr->dest_vsi) {
			if (vf_ch && !fltr_type)
				vf_ch->fltr_type = fltr_type;
		} else if (ch_vsi->ch) {
			ch_vsi->ch->fltr_type = fltr_type;
		}

		rule_info.sw_act.fltr_act = ICE_FWD_TO_VSI;
		rule_info.sw_act.vsi_handle = ch_vsi->idx;
		rule_info.priority = 7;

		rule_info.sw_act.src = hw->pf_id;
		rule_info.rx = true;

		dev_dbg(dev, "add switch rule for TC:%u vsi_idx:%u, lkups_cnt:%u\n",
			tc_fltr->action.tc_class,
			rule_info.sw_act.vsi_handle, lkups_cnt);
	} else {
		rule_info.sw_act.flag |= ICE_FLTR_TX;
		rule_info.sw_act.src = vsi->idx;
		rule_info.rx = false;
	}

	/* specify the cookie as filter_rule_id */
	rule_info.fltr_rule_id = tc_fltr->cookie;

	status = ice_add_adv_rule(hw, list, lkups_cnt, &rule_info, &rule_added);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		dev_err(dev, "failed to add filter because it already exists, status: %d\n",
			status);
		ret = -EINVAL;
		goto exit;
	} else if (status) {
		dev_err(dev, "failed to add switch rule for TC:%u, status %d\n",
			tc_fltr->action.tc_class, status);
		ret = -EIO;
		goto exit;
	}

	/* store the output params, which are needed later for removing
	 * advanced switch filter
	 */
	tc_fltr->rid = rule_added.rid;
	tc_fltr->rule_id = rule_added.rule_id;
	if (tc_fltr->action.tc_class > 0 && ch_vsi) {
		/* For PF ADQ, VSI type is set as ICE_VSI_CHNL, and
		 * for PF ADQ filter, it is not yet set in tc_fltr,
		 * hence store the dest_vsi ptr in tc_fltr
		 */
		if (ch_vsi->type == ICE_VSI_CHNL)
			tc_fltr->dest_vsi = ch_vsi;
		/* keep track of advanced switch filter for
		 * destination VSI (channel VSI)
		 */
		ch_vsi->num_chnl_fltr++;
		/* in this case, dest_id is VSI handle (sw handle) */
		tc_fltr->dest_id = rule_added.vsi_handle;
	}
	dev_dbg(dev, "added switch rule (lkups_cnt %u, flags 0x%x) for TC %u, rid %u, rule_id %u, vsi_idx %u\n",
		lkups_cnt, flags,
		tc_fltr->action.tc_class, rule_added.rid,
		rule_added.rule_id, rule_added.vsi_handle);
exit:
	kfree(list);
	return ret;
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * ice_handle_tclass_action - Support directing to a traffic class
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Support directing traffic to a traffic class
 */
static int
ice_handle_tclass_action(struct ice_vsi *vsi,
			 struct flow_cls_offload *cls_flower,
			 struct ice_tc_flower_fltr *fltr)
{
	int tc = tc_classid_to_hwtc(vsi->netdev, cls_flower->classid);
	struct ice_vsi *main_vsi;

	if (tc < 0) {
		dev_err(ice_pf_to_dev(vsi->back), "Invalid traffic class\n");
		return -EOPNOTSUPP;
	}
	if (!tc) {
		dev_err(ice_pf_to_dev(vsi->back), "cannot apply filter on TC0\n");
		return -EINVAL;
	}

	if (!(vsi->all_enatc & BIT(tc))) {
		dev_err(ice_pf_to_dev(vsi->back), "cannot apply filter on a non-existing TC %d\n",
			tc);
		return -EINVAL;
	}

	/* don't allow unsupported filter combinations */
	if (!(fltr->flags & (ICE_TC_FLWR_FLTR_FLAGS_IPV4_DST_PORT |
			     ICE_TC_FLWR_FLTR_FLAGS_IPV4_SRC_PORT))) {
		dev_err(ice_pf_to_dev(vsi->back), "currently this filter combination unsupported\n");
		return -EINVAL;
	}

	/* Redirect to a TC class or Queue Group */
	main_vsi = ice_get_main_vsi(vsi->back);
	if (!main_vsi || !main_vsi->netdev) {
		dev_err(ice_pf_to_dev(vsi->back), "unable to get to main VSI or main VSI's netdev is NULL\n");
		return -EINVAL;
	}

	if ((fltr->flags & ICE_TC_FLWR_FIELD_TENANT_ID) &&
	    (fltr->flags & (ICE_TC_FLWR_FIELD_DST_MAC |
			   ICE_TC_FLWR_FIELD_SRC_MAC))) {
		dev_err(ice_pf_to_dev(vsi->back), "Tunnel with inner MACs is unsupported ADQ filter configuration\n");
		return -EOPNOTSUPP;
	}

	/* For ADQ, filter must include dest MAC address, otherwise unwanted
	 * packets with unrelated MAC address get delivered to ADQ VSIs as long
	 * as remaining filter criteria is satisfied such as dest IP address
	 * and dest/src L4 port. Following code is trying to handle:
	 * 1. For non-tunnel, if user specify MAC addresses, use them (means
	 * this code won't do anything
	 * 2. For non-tunnel, if user didn't specify MAC address, add implicit
	 * dest MAC to be lower netdev's active unicast MAC address
	 * 3. For tunnel,  as of now tc-filter thru flower classifier doesn't
	 * have provision for user to specify outer DMAC, hence driver to
	 * implicitly add outer dest MAC to be lower netdev's active unicast
	 * MAC address.
	 */
	if (fltr->flags & ICE_TC_FLWR_FIELD_TENANT_ID)  {
		if (!(fltr->flags & ICE_TC_FLWR_FIELD_ENC_DST_MAC)) {
			ether_addr_copy(fltr->outer_headers.dst_mac,
					main_vsi->netdev->dev_addr);
			fltr->flags |= ICE_TC_FLWR_FIELD_ENC_DST_MAC;
		}
	} else if (!(fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)) {
		ether_addr_copy(fltr->outer_headers.dst_mac,
				main_vsi->netdev->dev_addr);
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
	}

	/* validate specified dest MAC address, make sure either it belongs to
	 * lower netdev or any of non-offloaded MACVLAN. Non-offloaded MACVLANs
	 * MAC address are added as unicast MAC filter destined to main VSI.
	 */
	if (!ice_mac_fltr_exist(&main_vsi->back->hw,
				fltr->outer_headers.dst_mac,
				main_vsi->idx)) {
		dev_err(ice_pf_to_dev(vsi->back), "specified dest MAC address %pM doesn't belong to this netdevice\n",
			fltr->outer_headers.dst_mac);
		return -EINVAL;
	}

	/* Make sure VLAN is already added to main VSI, before allowing ADQ to
	 * add a VLAN based filter such as MAC + VLAN + L4 port.
	 */
	if (fltr->flags & ICE_TC_FLWR_FIELD_VLAN) {
		u16 vlan_id = be16_to_cpu(fltr->outer_headers.vlan_hdr.vlan_id);

		if (!ice_vlan_fltr_exist(&main_vsi->back->hw, vlan_id,
					 main_vsi->idx)) {
			dev_err(ice_pf_to_dev(vsi->back), "specified VLAN %u doesn't belong to this netdevice\n",
				vlan_id);
			return -EINVAL;
		}
	}
	fltr->action.fltr_act = ICE_FWD_TO_VSI;
	fltr->action.tc_class = tc;

	return 0;
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

/**
 * ice_parse_tc_flower_actions - Parse the actions for a TC filter
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Parse the actions for a TC filter
 */
static int
ice_parse_tc_flower_actions(struct ice_vsi *vsi,
			    struct flow_cls_offload *cls_flower,
			    struct ice_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
#else
	struct tcf_exts *exts = cls_flower->exts;
	struct tc_action *tc_act;
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */
#if defined(HAVE_TC_FLOW_RULE_INFRASTRUCTURE) || defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	int i;
#else
	struct tc_action *temp;
	LIST_HEAD(tc_actions);
#endif

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (cls_flower->classid)
		return ice_handle_tclass_action(vsi, cls_flower, fltr);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	if (!flow_action_has_entries(flow_action))
#elif defined(HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV)
	if (!tcf_exts_has_actions(exts))
#else
	if (tc_no_actions(exts))
#endif
		return -EINVAL;

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	flow_action_for_each(i, act, flow_action) {
#elif defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	tcf_exts_for_each_action(i, tc_act, exts) {
#elif defined(HAVE_TCF_EXTS_TO_LIST)
	tcf_exts_to_list(exts, &tc_actions);

	list_for_each_entry_safe(tc_act, temp, &tc_actions, list) {
#else
	list_for_each_entry_safe(tc_act, temp, &(exts)->actions, list) {
#endif /* HAVE_TCF_EXTS_TO_LIST */
		/* Allow only one rule per filter */

		/* Drop action */
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
		if (act->id == FLOW_ACTION_DROP) {
#else
		if (is_tcf_gact_shot(tc_act)) {
#endif
			dev_err(ice_pf_to_dev(vsi->back), "Action drop is not supported\n");
			return -EINVAL;
		}
		fltr->action.fltr_act = ICE_FWD_TO_VSI;
	}
	return 0;
}

/**
 * ice_add_clsflower - Add TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct ice_tc_flower_fltr
 */
static int
ice_add_clsflower(struct ice_vsi *vsi, struct ice_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (fltr->action.fltr_act == ICE_FWD_TO_QGRP)
		return -EOPNOTSUPP;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	if (fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_VLAN ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN)
		return ice_add_remove_tc_flower_dflt_fltr(vsi, fltr, true);
#ifdef HAVE_TC_SETUP_CLSFLOWER
	return ice_add_tc_flower_adv_fltr(vsi, fltr);
#else
	return -EOPNOTSUPP;
#endif /* HAVE_TC_SETUP_CLSFLOWER */
}

/**
 * ice_cfg_clsflower - Configure TC flower filters
 * @netdev: Pointer to filter device
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to struct flow_cls_offload
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
ice_cfg_clsflower(struct net_device *netdev, struct ice_vsi *vsi,
		  struct flow_cls_offload *cls_flower)
#else
static int
ice_cfg_clsflower(struct net_device __always_unused *netdev,
		  struct ice_vsi *vsi, struct tc_cls_flower_offload *cls_flower)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct ice_tc_flower_fltr *fltr;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_is_reset_in_progress(pf->state))
		return -EBUSY;
	if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags))
		return -EINVAL;

	if (!(vsi->netdev->features & NETIF_F_HW_TC) &&
	    !test_bit(ICE_FLAG_CLS_FLOWER, pf->flags)) {
#ifdef HAVE_TC_INDIR_BLOCK
		/* Based on TC indirect notifications from kernel, all ice
		 * devices get an instance of rule from higher level device.
		 * Avoid triggering explicit error in this case.
		 */
		if (netdev == vsi->netdev)
#endif /* HAVE_TC_INDIR_BLOCK */
			dev_err(dev, "can't apply TC flower filters, turn ON hw-tc-offload and try again\n");
		return -EINVAL;
	}

	fltr = devm_kzalloc(dev, sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	fltr->cookie = cls_flower->cookie;

	err = ice_parse_cls_flower(netdev, vsi, cls_flower, fltr);
	if (err < 0)
		goto err;

	err = ice_parse_tc_flower_actions(vsi, cls_flower, fltr);
	if (err < 0)
		goto err;

	err = ice_add_clsflower(vsi, fltr);
	if (err < 0)
		goto err;

	/* add filter to the ordered list */
	INIT_HLIST_NODE(&fltr->tc_flower_node);

	hlist_add_head(&fltr->tc_flower_node, &pf->tc_flower_fltr_list);

	pf->num_tc_flower_fltrs++;

	return err;
err:
	devm_kfree(dev, fltr);
	return err;
}

/**
 * ice_find_tc_flower_fltr - Find the TC flower filter in the list
 * @vsi: Pointer to VSI
 * @cookie: filter specific cookie
 */
static struct ice_tc_flower_fltr *
ice_find_tc_flower_fltr(struct ice_vsi *vsi, unsigned long cookie)
{
	struct ice_tc_flower_fltr *fltr = NULL;
	struct hlist_node *node2;

	hlist_for_each_entry_safe(fltr, node2,
				  &vsi->back->tc_flower_fltr_list,
				  tc_flower_node)
		if (!memcmp(&cookie, &fltr->cookie, sizeof(fltr->cookie)))
			return fltr;
	return NULL;
}

/**
 * ice_delete_clsflower - delete TC flower filters
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to struct flow_cls_offload
 */
static int
ice_delete_clsflower(struct ice_vsi *vsi, struct flow_cls_offload *cls_flower)
{
	struct ice_tc_flower_fltr *fltr;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	fltr = ice_find_tc_flower_fltr(vsi, cls_flower->cookie);
	if (!fltr)
		return -EINVAL;

	if (fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_VLAN ||
	    fltr->flags == ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN) {
		err = ice_add_remove_tc_flower_dflt_fltr(vsi, fltr, false);
	} else {
		struct ice_rule_query_data rule_rem;

		rule_rem.rid = fltr->rid;
		rule_rem.rule_id = fltr->rule_id;
		rule_rem.vsi_handle = fltr->dest_id;
		err = ice_rem_adv_rule_by_id(&pf->hw, &rule_rem);
	}

	if (err) {
		dev_err(dev, "Failed to delete TC flower filter\n");
		return -EIO;
	}

	/* update advanced switch filter count for destination
	 * VSI if filter destination was VSI
	 */
	if (fltr->dest_vsi) {
		if (fltr->dest_vsi->type == ICE_VSI_CHNL) {
			struct ice_channel *ch = fltr->dest_vsi->ch;

			fltr->dest_vsi->num_chnl_fltr--;

			/* reset filter type for channel if channel filter
			 * count reaches zero
			 */
			if (!fltr->dest_vsi->num_chnl_fltr && ch)
				ch->fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
		}
	}

	hlist_del(&fltr->tc_flower_node);
	devm_kfree(dev, fltr);
	pf->num_tc_flower_fltrs--;
	return 0;
}

/**
 * ice_setup_tc_cls_flower - flower classifier offloads
 * @np: net device to configure
 * @filter_dev: device on which filter is added
 * @cls_flower: offload data
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
ice_setup_tc_cls_flower(struct ice_netdev_priv *np,
			struct net_device *filter_dev,
			struct flow_cls_offload *cls_flower)
#else
static int
ice_setup_tc_cls_flower(struct ice_netdev_priv *np,
			struct net_device __always_unused *filter_dev,
			struct tc_cls_flower_offload *cls_flower)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct ice_vsi *vsi = np->vsi;

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return ice_cfg_clsflower(filter_dev, vsi, cls_flower);
	case FLOW_CLS_DESTROY:
		return ice_delete_clsflower(vsi, cls_flower);
	default:
		return -EINVAL;
	}
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * ice_setup_tc_block_cb - callback handler registered for TC block
 * @type: TC SETUP type
 * @type_data: TC flower offload data that contains user input
 * @cb_priv: netdev private data
 */
static int
ice_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct ice_netdev_priv *np = (struct ice_netdev_priv *)cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return ice_setup_tc_cls_flower(np, np->vsi->netdev,
					       (struct flow_cls_offload *)
					       type_data);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * ice_get_link_speed_mbps - get link speed in Mbps
 * @vsi: the VSI whose link speed is being queried
 */
static int ice_get_link_speed_mbps(struct ice_vsi *vsi)
{
	switch (vsi->port_info->phy.link_info.link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
		return ICE_LINK_SPEED_100000MBPS;
	case ICE_AQ_LINK_SPEED_50GB:
		return ICE_LINK_SPEED_50000MBPS;
	case ICE_AQ_LINK_SPEED_40GB:
		return ICE_LINK_SPEED_40000MBPS;
	case ICE_AQ_LINK_SPEED_25GB:
		return ICE_LINK_SPEED_25000MBPS;
	case ICE_AQ_LINK_SPEED_20GB:
		return ICE_LINK_SPEED_20000MBPS;
	case ICE_AQ_LINK_SPEED_10GB:
		return ICE_LINK_SPEED_10000MBPS;
	case ICE_AQ_LINK_SPEED_5GB:
		return ICE_LINK_SPEED_5000MBPS;
	case ICE_AQ_LINK_SPEED_2500MB:
		return ICE_LINK_SPEED_2500MBPS;
	case ICE_AQ_LINK_SPEED_1000MB:
		return ICE_LINK_SPEED_1000MBPS;
	case ICE_AQ_LINK_SPEED_100MB:
		return ICE_LINK_SPEED_100MBPS;
	case ICE_AQ_LINK_SPEED_10MB:
		return ICE_LINK_SPEED_10MBPS;
	default:
		return -EINVAL;
	}
}

/**
 * ice_validate_mqprio_qopt - Validate TCF input parameters
 * @vsi: Pointer to VSI
 * @mqprio_qopt: input parameters for mqprio queue configuration
 *
 * This function validates MQPRIO params, such as qcount (power of 2 wherever
 * needed), and make sure user doesn't specify qcount and BW rate limit
 * for TCs, which are more than "num_tc"
 */
static int
ice_validate_mqprio_qopt(struct ice_vsi *vsi,
			 struct tc_mqprio_qopt_offload *mqprio_qopt)
{
	u64 sum_max_rate = 0, sum_min_rate = 0;
	int non_power_of_2_qcount = 0;
	struct ice_pf *pf = vsi->back;
	int max_rss_q_cnt = 0;
	struct device *dev;
	int i, speed;
	u8 num_tc;

	if (vsi->type != ICE_VSI_PF)
		return -EINVAL;

	if (mqprio_qopt->qopt.offset[0] != 0 ||
	    mqprio_qopt->qopt.num_tc < 1 ||
	    mqprio_qopt->qopt.num_tc > ICE_CHNL_MAX_TC)
		return -EINVAL;

	dev = ice_pf_to_dev(pf);
	vsi->ch_rss_size = 0;
	num_tc = mqprio_qopt->qopt.num_tc;

	for (i = 0; num_tc; i++) {
		int qcount = mqprio_qopt->qopt.count[i];
		u64 max_rate, min_rate;

		max_rate = mqprio_qopt->max_rate[i];

		if (!qcount)
			return -EINVAL;

		if (!i && !is_power_of_2(qcount)) {
			dev_err(dev, "TC0:qcount[%d] must be a power of 2\n",
				qcount);
			return -EINVAL;
		} else if (non_power_of_2_qcount) {
			if (qcount > non_power_of_2_qcount) {
				dev_err(dev, "TC%d:qcount[%d] > non_power_of_2_qcount [%d]\n",
					i, qcount, non_power_of_2_qcount);
				return -EINVAL;
			} else if (qcount < non_power_of_2_qcount) {
				/* it must be power of 2, otherwise fail */
				if (!is_power_of_2(qcount)) {
					dev_err(dev, "qcount must be a power of 2, TC%d: qcnt[%d] < non_power_of_2_qcount [%d]\n",
						i, qcount,
						non_power_of_2_qcount);
					return -EINVAL;
				}
			}
		} else if (!is_power_of_2(qcount)) {
			/* after tc0, next TCs qcount can be non-power of 2,
			 * if so, set channel RSS size to be the count of that
			 * TC
			 */
			non_power_of_2_qcount = qcount;
			max_rss_q_cnt = qcount;
			dev_dbg(dev, "TC%d:count[%d] non power of 2\n", i,
				qcount);
		}

		/* figure out max_rss_q_cnt based on TC's qcount */
		if (max_rss_q_cnt) {
			if (qcount > max_rss_q_cnt)
				max_rss_q_cnt = qcount;
		} else {
			max_rss_q_cnt = qcount;
		}

		/* Convert input bandwidth from Bytes/s to Kbps */
		/* TC tool converts the bandwidth rate limit into Bytes/s when
		 * passing it down to the driver whereas the TC command can
		 * take bandwidth inputs in Kbps, Mbps or Gbps
		 */
		do_div(max_rate, ICE_BW_KBPS_DIVISOR);
		sum_max_rate += max_rate;

		/* min_rate is minimum guaranteed rate and it can't be zero */
		min_rate = mqprio_qopt->min_rate[i];
		do_div(min_rate, ICE_BW_KBPS_DIVISOR);
		if (min_rate && min_rate < ICE_MIN_BW_LIMIT) {
			dev_err(dev, "TC%d: min_rate(%llu Kbps) < %u Kbps\n", i,
				min_rate, ICE_MIN_BW_LIMIT);
			return -EINVAL;
		}
		if (min_rate % ICE_MIN_BW_LIMIT != 0) {
			dev_err(dev, "TC%d: Min Rate not in increment of %u Kbps",
				i, ICE_MIN_BW_LIMIT);
			return -EINVAL;
		}
		if (max_rate % ICE_MIN_BW_LIMIT != 0) {
			dev_err(dev, "TC%d: Max Rate not in increment of %u Kbps",
				i, ICE_MIN_BW_LIMIT);
			return -EINVAL;
		}
		sum_min_rate += min_rate;

		/* min_rate can't be more than max_rate, except when max_rate
		 * is zero (which is valid and it means bandwidth is sought for
		 * max line rate). In such a case min_rate can be more than max.
		 */
		if (max_rate && min_rate > max_rate) {
			dev_err(dev, "min_rate %llu Kbps can't be more than max_rate %llu Kbps\n",
				min_rate, max_rate);
			return -EINVAL;
		}

		if (i >= mqprio_qopt->qopt.num_tc - 1)
			break;
		if (mqprio_qopt->qopt.offset[i + 1] !=
		    (mqprio_qopt->qopt.offset[i] + qcount))
			return -EINVAL;
	}
	if (vsi->num_rxq <
	    (mqprio_qopt->qopt.offset[i] + mqprio_qopt->qopt.count[i]))
		return -EINVAL;
	if (vsi->num_txq <
	    (mqprio_qopt->qopt.offset[i] + mqprio_qopt->qopt.count[i]))
		return -EINVAL;

	/* Change speed from Mbps to Kbps, since sum of min and max rate
	 * are in Kbps
	 */
	speed = ice_get_link_speed_mbps(vsi) << 10;
	if (sum_min_rate && sum_min_rate > speed) {
		dev_err(dev, "Invalid min Tx rate(%llu) Kbps > speed (%u) Kbps specified\n",
			sum_min_rate, speed);
		return -EINVAL;
	}
	if (sum_max_rate && sum_max_rate > speed) {
		dev_err(dev, "Invalid max Tx rate(%llu) Kbps > speed(%u) Kbps specified\n",
			sum_max_rate, speed);
		return -EINVAL;
	}

	/* make sure vsi->ch_rss_size is set correctly based on TC's qcount */
	vsi->ch_rss_size = max_rss_q_cnt;

	return 0;
}

/**
 * ice_add_vsi_to_fdir - add a VSI to the flow director group for PF
 * @pf: ptr to PF device
 * @vsi: ptr to VSI
 */
static int ice_add_vsi_to_fdir(struct ice_pf *pf, struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(pf);
	bool added = false;
	struct ice_hw *hw;
	int flow;

	if (!(vsi->num_gfltr || vsi->num_bfltr))
		return -EINVAL;

	hw = &pf->hw;
	for (flow = 0; flow < ICE_FLTR_PTYPE_MAX; flow++) {
		enum ice_block blk = ICE_BLK_FD;
		struct ice_fd_hw_prof *prof;
		enum ice_status status;
		u64 entry_h;
		int tun;

		if (!(hw->fdir_prof && hw->fdir_prof[flow] &&
		      hw->fdir_prof[flow]->cnt))
			continue;

		for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
			enum ice_flow_priority prio;
			u64 prof_id;

			/* add this VSI to FDir profile for this flow */
			prio = ICE_FLOW_PRIO_NORMAL;
			prof = hw->fdir_prof[flow];
			prof_id = flow + tun * ICE_FLTR_PTYPE_MAX;
			status = ice_flow_add_entry(hw, blk, prof_id,
						    prof->vsi_h[0], vsi->idx,
						    prio, prof->fdir_seg[tun],
						    NULL, 0, &entry_h);
			if (status) {
				dev_err(dev, "channel VSI idx %d, not able to add to group %d\n",
					vsi->idx, flow);
				continue;
			}

			prof->entry_h[prof->cnt][tun] = entry_h;
		}

		/* store VSI for filter replay and delete */
		prof->vsi_h[prof->cnt] = vsi->idx;
		prof->cnt++;

		/* loop bookkeeping */
		added = true;
		dev_dbg(dev, "VSI idx %d added to fdir group %d\n", vsi->idx,
			flow);
	}

	if (!added)
		dev_dbg(dev, "VSI idx %d not added to fdir groups\n", vsi->idx);
#ifdef ADQ_PERF
	else
		set_bit(ICE_CHNL_FEATURE_FD_ENA, vsi->features);
#endif /* ADQ_PERF */
	return 0;
}

/**
 * ice_add_channel - add a channel by adding VSI
 * @pf: ptr to PF device
 * @sw_id: underlying HW switching element ID
 * @ch: ptr to channel structure
 *
 * Add a channel (VSI) using add_vsi and queue_map
 */
static int ice_add_channel(struct ice_pf *pf, u16 sw_id, struct ice_channel *ch)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *vsi;

	if (ch->type != ICE_VSI_CHNL) {
		dev_err(dev, "add new VSI failed, ch->type %d\n", ch->type);
		return -EINVAL;
	}

	vsi = ice_chnl_vsi_setup(pf, pf->hw.port_info, ch);
	if (!vsi || vsi->type != ICE_VSI_CHNL) {
		dev_err(dev, "create chnl VSI failure\n");
		return -EINVAL;
	}

#ifdef ADQ_PERF
	/* set/clear VSI level feature flag for packet based optimization
	 * (this is related to SW triggred interrupt from napi_poll - which is
	 * generally based off data packets or not)
	 */
	if (test_bit(ICE_FLAG_CHNL_PKT_INSPECT_OPT_ENA, pf->flags))
		set_bit(ICE_CHNL_FEATURE_PKT_INSPECT_OPT_ENA, vsi->features);
	else
		clear_bit(ICE_CHNL_FEATURE_PKT_INSPECT_OPT_ENA, vsi->features);
#endif /* ADQ_PERF */

#ifdef ADQ_PERF
	/* set/clear inline flow-director bits for newly created VSI based
	 * on PF level private flags
	 */
	if (test_bit(ICE_FLAG_CHNL_INLINE_FD_ENA, pf->flags))
		set_bit(ICE_CHNL_FEATURE_INLINE_FD_ENA, vsi->features);
	else
		clear_bit(ICE_CHNL_FEATURE_INLINE_FD_ENA, vsi->features);

	/* if VSI has some FD resources reserved (either from guaranteed or
	 * best-effort quota), add VSI into VSI group which has FD
	 * input set defined so that, newly created VSI can use FD
	 * resources (side-band flow director type filter and/or
	 * inline flow-director type of filters which are typically
	 * setup during normal transmit path if packet being transmitted
	 * has SYN, SYN+ACK, RST, FIN flags set)
	 */
	clear_bit(ICE_CHNL_FEATURE_FD_ENA, vsi->features);
#endif /* ADQ_PERF */

	ice_add_vsi_to_fdir(pf, vsi);

	ch->sw_id = sw_id;
	ch->vsi_num = vsi->vsi_num;
	ch->info.mapping_flags = vsi->info.mapping_flags;
	ch->ch_vsi = vsi;
	/* initialize filter type to be INVALID */
	ch->fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
	/* set the back pointer of channel for newly created VSI */
	vsi->ch = ch;

	memcpy(&ch->info.q_mapping, &vsi->info.q_mapping,
	       sizeof(vsi->info.q_mapping));
	memcpy(&ch->info.tc_mapping, vsi->info.tc_mapping,
	       sizeof(vsi->info.tc_mapping));

	return 0;
}

/**
 * ice_setup_chnl_itr - setup ITR for specified vector
 * @vsi: ptr to VSI
 * @q_vector: ptr to vector
 * @rc: ptr to ring container
 *
 * Configure ITR setting only if "aim" is off for specified vector as part of
 * configuring channel (aka ADQ).
 */
static void
ice_setup_chnl_itr(struct ice_vsi *vsi, struct ice_q_vector *q_vector,
		   struct ice_ring_container *rc)
{
	/* proceed only if ITR is not dynamic (means, aim is off) */
	if (!ITR_IS_DYNAMIC(rc->itr_setting)) {
		wr32(&vsi->back->hw, GLINT_ITR(rc->itr_idx, q_vector->reg_idx),
		     rc->target_itr >> ICE_ITR_GRAN_S);
	}
}

/**
 * ice_chnl_cfg_res
 * @vsi: the VSI being setup
 * @ch: ptr to channel structure
 *
 * Configure channel specific resources such as rings, vector.
 */
static void ice_chnl_cfg_res(struct ice_vsi *vsi, struct ice_channel *ch)
{
	int i;


	for (i = 0; i < ch->num_txq; i++) {
		struct ice_ring *tx_ring, *rx_ring;

		/* Get to Tx ring ptr */
		tx_ring = vsi->tx_rings[ch->base_q + i];
		/* Get the Rx ring ptr */
		rx_ring = vsi->rx_rings[ch->base_q + i];
		if (!tx_ring || !tx_ring->q_vector || !rx_ring)
			continue; /* unlikely */

		/* setup rings and their vectors as channel capable */
		tx_ring->ch = ch;
		rx_ring->ch = ch;
		tx_ring->q_vector->ch = ch;
		rx_ring->q_vector->ch = ch;

		/* setup Tx and Rx ITR setting if aim is off */
		ice_setup_chnl_itr(vsi, tx_ring->q_vector,
				   &tx_ring->q_vector->tx);
		ice_setup_chnl_itr(vsi, rx_ring->q_vector,
				   &rx_ring->q_vector->rx);

#ifdef ADQ_PERF
		/* Initialize vector states suitable for channel specific perf
		 * optimization. Generally Tx and Rx queues are associated to
		 * same vector, but just in case if not, initialize vector
		 * for Rx and Tx queue separately. This is to avoid further
		 * problem if Tx and Rx queue is associated to different
		 * vector depending on vector association driver policy or
		 * when unequal number of Rx and Tx queues are supported
		 */
		rx_ring->q_vector->state_flags = 0;
		tx_ring->q_vector->state_flags = 0;
#endif /* ADQ_PERF */
#ifdef ADQ_PERF
		tx_ring->ch_inline_fd_cnt_index = ch->fd_cnt_index;
#endif /* ADQ_PERF */
	}

	/* it is safe to assume that, if channel has non-zero num_t[r]xq, then
	 * GLINT_ITR register would have written to perform in-context
	 * update, hence perform flush
	 */
	if (ch->num_txq || ch->num_rxq)
		ice_flush(&vsi->back->hw);
}

/**
 * ice_cfg_chnl_all_res - configure channel resources
 * @vsi: pte to main_vsi
 * @ch: ptr to channel structure
 *
 * This function configures channel specific resources such as flow-director
 * counter index, and other resources such as queues, vectors, ITR settings
 */
static void
ice_cfg_chnl_all_res(struct ice_vsi *vsi, struct ice_channel *ch)
{
#ifdef ADQ_PERF
	struct ice_pf *pf = vsi->back;

	/* setup inline-FD counter index per channel, eventually
	 * used separate counter index per channel, to offer
	 * better granularity and QoS per channel for RSS and FD
	 */
	ch->fd_cnt_index = ICE_FD_CH_STAT_IDX(pf->hw.fd_ctr_base);
	/* reset source for all counters is CORER, typically upon
	 * driver load, those counters may have stale value, hence
	 * initialize counter to zero, access type for counters is RWC
	 */
	ice_clear_cntr(pf, ch->fd_cnt_index);
#endif /* ADQ_PERF */

	/* configure channel (aka ADQ) resources such as queues, vectors,
	 * ITR settings for channel specific vectors and anything else
	 */
	ice_chnl_cfg_res(vsi, ch);
}

/**
 * ice_setup_hw_channel - setup new channel
 * @pf: ptr to PF device
 * @vsi: the VSI being setup
 * @ch: ptr to channel structure
 * @sw_id: underlying HW switching element ID
 * @type: type of channel to be created (VMDq2/VF)
 *
 * Setup new channel (VSI) based on specified type (VMDq2/VF)
 * and configures Tx rings accordingly
 */
static int
ice_setup_hw_channel(struct ice_pf *pf, struct ice_vsi *vsi,
		     struct ice_channel *ch, u16 sw_id, u8 type)
{
	struct device *dev = ice_pf_to_dev(pf);
	int ret;

	ch->base_q = vsi->next_base_q;
	ch->type = type;

	ret = ice_add_channel(pf, sw_id, ch);
	if (ret) {
		dev_err(dev, "failed to add_channel using sw_id %u\n", sw_id);
		return ret;
	}

	/* configure/setup ADQ specific resources */
	ice_cfg_chnl_all_res(vsi, ch);

	/* make sure to update the next_base_q so that subsequent channel's
	 * (aka ADQ) VSI queue map is correct
	 */
	vsi->next_base_q = vsi->next_base_q + ch->num_rxq;
	dev_dbg(dev, "added channel: vsi_num %u, num_rxq %u\n", ch->vsi_num,
		ch->num_rxq);

	return 0;
}

/**
 * ice_setup_channel - setup new channel using uplink element
 * @pf: ptr to PF device
 * @vsi: the VSI being setup
 * @ch: ptr to channel structure
 *
 * Setup new channel (VSI) based on specified type (VMDq2/VF)
 * and uplink switching element
 */
static bool
ice_setup_channel(struct ice_pf *pf, struct ice_vsi *vsi,
		  struct ice_channel *ch)
{
	struct device *dev = ice_pf_to_dev(pf);
	u16 sw_id;
	int ret;

	if (vsi->type != ICE_VSI_PF) {
		dev_err(dev, "unsupported parent VSI type(%d)\n", vsi->type);
		return false;
	}

	sw_id = pf->first_sw->sw_id;

	/* create channel (VSI) */
	ret = ice_setup_hw_channel(pf, vsi, ch, sw_id, ICE_VSI_CHNL);
	if (ret) {
		dev_err(dev, "failed to setup hw_channel\n");
		return false;
	}
	dev_dbg(dev, "successfully created channel()\n");

	return ch->ch_vsi ? true : false;
}

/**
 * ice_set_bw_limit - setup BW limit for Tx traffic based on max_tx_rate
 * @vsi: VSI to be configured
 * @max_tx_rate: max Tx rate to be configured as BW limit
 * @min_tx_rate: min Tx rate to be configured as BW limit
 *
 * Helper function to set BW limit for a given VSI
 */
static int
ice_set_bw_limit(struct ice_vsi *vsi, u64 max_tx_rate, u64 min_tx_rate)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status = 0;
	struct device *dev;
	int speed;

	dev = ice_pf_to_dev(pf);
	if (!vsi->port_info) {
		dev_err(dev, "VSI (%p):type (%u) specified doesn't have valid port_info\n",
			vsi, vsi->type);
		return -EINVAL;
	}

	if (!max_tx_rate && !min_tx_rate)
		return -EINVAL;

	/* convert to Kbps from Mbps */
	speed = ice_get_link_speed_mbps(vsi) << 10;
	if (max_tx_rate && max_tx_rate > speed) {
		dev_err(dev, "invalid max Tx rate %llu specified for VSI %d\n",
			max_tx_rate, vsi->vsi_num);
		return -EINVAL;
	}
	if (min_tx_rate && min_tx_rate > speed) {
		dev_err(dev, "invalid min Tx rate %llu specified for VSI %d\n",
			min_tx_rate, vsi->vsi_num);
		return -EINVAL;
	}

	/* Configure max BW for VSI limit */
	if (max_tx_rate) {
		status = ice_cfg_vsi_bw_lmt_per_tc(vsi->port_info, vsi->idx, 0,
						   ICE_MAX_BW, max_tx_rate);

		if (status)
			dev_err(dev, "failed to set max Tx rate(%llu) for %s\n",
				max_tx_rate, ice_vsi_type_str(vsi->type));
		else
			dev_dbg(dev, "set max Tx rate(%llu) for %s\n",
				max_tx_rate, ice_vsi_type_str(vsi->type));
	}
	/* Configure min BW for VSI limit */
	if (min_tx_rate) {
		status = ice_cfg_vsi_bw_lmt_per_tc(vsi->port_info, vsi->idx, 0,
						   ICE_MIN_BW, min_tx_rate);

		if (status)
			dev_err(dev, "failed to set min Tx rate(%llu) for %s\n",
				min_tx_rate, ice_vsi_type_str(vsi->type));
		else
			dev_dbg(dev, "set min Tx rate(%llu) for %s\n",
				min_tx_rate, ice_vsi_type_str(vsi->type));
	}

	return status;
}

/**
 * ice_create_queue_channel - function to create channel
 * @vsi: VSI to be configured
 * @ch: ptr to channel (it contains channel specific params)
 *
 * This function creates channel (VSI) using num_queues specified by user,
 * reconfigs RSS if needed.
 */
static int ice_create_q_channel(struct ice_vsi *vsi, struct ice_channel *ch)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;

	if (!ch)
		return -EINVAL;

	dev = ice_pf_to_dev(pf);
	if (!ch->num_txq || !ch->num_rxq) {
		dev_err(dev, "Invalid num_queues requested: %d\n", ch->num_rxq);
		return -EINVAL;
	}

	if (!vsi->cnt_q_avail || vsi->cnt_q_avail < ch->num_txq) {
		dev_err(dev, "Error: cnt_q_avail (%u) less than num_queues %d\n",
			vsi->cnt_q_avail, ch->num_txq);
		return -EINVAL;
	}

	if (!ice_setup_channel(pf, vsi, ch)) {
		dev_info(dev, "Failed to setup channel\n");
		return -EINVAL;
	}
	/* configure BW rate limit */
	if (ch->ch_vsi && (ch->max_tx_rate || ch->min_tx_rate)) {
		int ret;

		ret = ice_set_bw_limit(ch->ch_vsi, ch->max_tx_rate,
				       ch->min_tx_rate);
		if (ret)
			dev_err(dev, "failed to set Tx rate of %llu Kbps for VSI(%u)\n",
				ch->max_tx_rate, ch->ch_vsi->vsi_num);
		else
			dev_dbg(dev, "set Tx rate of %llu Kbps for VSI(%u)\n",
				ch->max_tx_rate, ch->ch_vsi->vsi_num);
	}

	vsi->cnt_q_avail -= ch->num_txq;

	return 0;
}

/**
 * ice_rem_adv_fltr - remove advanced switch filter rules
 * @pf: ptr to PF, TC-flower based filter are tracked at PF level
 * @ch_vsi: ptr to destination VSI for switch filter
 *
 * Remove all advanced switch filters for a specified channel (aka ADQ) VSI
 */
static void ice_rem_adv_fltr(struct ice_pf *pf, struct ice_vsi *ch_vsi)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_tc_flower_fltr *fltr;
	struct hlist_node *node2;

	hlist_for_each_entry_safe(fltr, node2,
				  &pf->tc_flower_fltr_list,
				  tc_flower_node) {
		struct ice_rule_query_data rule_rem;
		enum ice_status status;

		/* skip the filter whose destination doesn't match with
		 * specified channel (aka ADQ) VSI
		 */
		if (fltr->dest_id != ch_vsi->idx)
			continue;

		/* process only advanced switch filter based on recipe ID.
		 * Newly created recipe ID  must be >= ICE_SW_LKUP_LAST.
		 * Advanced switch filter results into creating of new recipe
		 * because default recipes doesn't match with extraction
		 * sequence needed for advanced switch filter, hence it is
		 * safe to skip any switch rules which refers to
		 * default recipes (recipe ID < ICE_SW_LKUO_LAST
		 */
		if (fltr->rid < ICE_SW_LKUP_LAST)
			continue;

		rule_rem.rid = fltr->rid;
		rule_rem.rule_id = fltr->rule_id;
		rule_rem.vsi_handle = fltr->dest_id;
		status = ice_rem_adv_rule_by_id(&pf->hw, &rule_rem);
		if (status) {
			dev_err(dev, "Failed to delete TC flower filter\n");
			continue;
		}

		/* update advanced switch filter count if dest VSI is valid */
		if (fltr->dest_vsi)
			if (fltr->dest_vsi->type == ICE_VSI_CHNL)
				fltr->dest_vsi->num_chnl_fltr--;

		/* make sure to clean filter object and update global stats */
		hlist_del(&fltr->tc_flower_node);
		devm_kfree(dev, fltr);
		pf->num_tc_flower_fltrs--;
	}
}


/**
 * ice_remove_q_channels - Remove queue channels for the TCs
 * @vsi: VSI to be configured
 * @rem_adv_fltr: delete advanced switch filter or not
 *
 * Remove queue channels for the TCs
 */
static void ice_remove_q_channels(struct ice_vsi *vsi, bool rem_adv_fltr)
{
	struct ice_channel *ch, *ch_tmp;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int i;

	dev = ice_pf_to_dev(pf);
	/* perform cleanup for channels if they exist */
	if (list_empty(&vsi->ch_list))
		return;

	list_for_each_entry_safe(ch, ch_tmp, &vsi->ch_list, list) {
		struct ice_vsi *ch_vsi;

		list_del(&ch->list);
		ch_vsi = ch->ch_vsi;
		if (!ch_vsi) {
			devm_kfree(dev, ch);
			continue;
		}

		/* Reset queue contexts */
		for (i = 0; i < ch->num_rxq; i++) {
			struct ice_ring *tx_ring, *rx_ring;

			tx_ring = vsi->tx_rings[ch->base_q + i];
			rx_ring = vsi->rx_rings[ch->base_q + i];
			if (!tx_ring || !tx_ring->q_vector || !rx_ring)
				continue;
			tx_ring->ch = NULL;
			rx_ring->ch = NULL;
			tx_ring->q_vector->ch = NULL;
			rx_ring->q_vector->ch = NULL;
		}

		/* remove advanced switch filter associated with channel
		 * (aka ADQ) VSI.
		 */
		if (rem_adv_fltr)
			ice_rem_adv_fltr(pf, ch->ch_vsi);

		/* Release FD resources for the channel VSI */
		ice_fdir_rem_adq_chnl(&pf->hw, ch->ch_vsi->idx);

		/* clear the VSI from schedular tree */
		ice_rm_vsi_lan_cfg(ch->ch_vsi->port_info, ch->ch_vsi->idx);

		/* Delete VSI from FW */
		ice_vsi_delete(ch->ch_vsi);

		/* Delete VSI from PF and HW VSI arrays */
		ice_vsi_clear(ch->ch_vsi);

		/* free the channel */
		devm_kfree(dev, ch);
	}

	/* clear the channel VSI map which is stored in main VSI */
	ice_for_each_chnl_tc(i)
		vsi->tc_map_vsi[i] = NULL;
	/* reset main VSI's all TC information */
	vsi->all_enatc = 0;
	vsi->all_numtc = 0;
}

/**
 * ice_rebuild_channels - rebuild channel
 * @pf: ptr to PF
 *
 * Recreate channel VSIs and replay filters
 */
static int ice_rebuild_channels(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *main_vsi;
	bool rem_adv_fltr = true;
	struct ice_channel *ch;
	struct ice_vsi *vsi;
	int tc_idx = 1;
	int i, err;

	main_vsi = ice_get_main_vsi(pf);
	if (!main_vsi)
		return 0;

	if (!test_bit(ICE_FLAG_TC_MQPRIO, pf->flags) ||
	    main_vsi->old_numtc == 1)
		return 0; /* nothing to be done */


	/* reconfigure main VSI based on old value of TC and cached values
	 * for MQPRIO opts
	 */
	err = ice_vsi_cfg_tc(main_vsi, main_vsi->old_ena_tc);
	if (err) {
		dev_err(dev, "failed configuring TC(ena_tc:0x%02x) for HW VSI=%u\n",
			main_vsi->old_ena_tc, main_vsi->vsi_num);
		return err;
	}

	/* rebuild ADQ VSIs */
	ice_for_each_vsi(pf, i) {
		enum ice_vsi_type type;

		vsi = pf->vsi[i];
		if (!vsi || vsi->type != ICE_VSI_CHNL)
			continue;

		type = vsi->type;

		/* rebuild ADQ VSI */
		err = ice_vsi_rebuild(vsi, true);
		if (err) {
			dev_err(dev, "VSI (type:%s) at index %d rebuild failed, err %d\n",
				ice_vsi_type_str(type), vsi->idx, err);
			goto cleanup;
		}

		/* Re-map HW VSI number, using VSI handle that has been
		 * previously validated in ice_replay_vsi() call above
		 */
		vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);

		/* replay filters for the VSI */
		err = ice_replay_vsi(&pf->hw, vsi->idx);
		if (err) {
			dev_err(dev, "VSI (type:%s) replay failed, err %d, VSI index %d\n",
				ice_vsi_type_str(type), err, vsi->idx);
			rem_adv_fltr = false;
			goto cleanup;
		}
		dev_info(dev, "VSI (type:%s) at index %d rebuilt successfully\n",
			 ice_vsi_type_str(type), vsi->idx);

		/* store ADQ VSI at correct TC index in main VSI's
		 * map of TC to VSI
		 */
		main_vsi->tc_map_vsi[tc_idx++] = vsi;
	}

	/* ADQ VSI(s) has been rebuild successfully, so setup
	 * channel for main VSI's Tx and Rx rings
	 */
	list_for_each_entry(ch, &main_vsi->ch_list, list) {
		struct ice_vsi *ch_vsi;

		ch_vsi = ch->ch_vsi;
		if (!ch_vsi)
			continue;

		/* reconfig channel resources */
		ice_cfg_chnl_all_res(main_vsi, ch);

		/* replay BW rate limit it it is non-zero */
		if (!ch->max_tx_rate && !ch->min_tx_rate)
			continue;

		err = ice_set_bw_limit(ch_vsi, ch->max_tx_rate,
				       ch->min_tx_rate);
		if (err)
			dev_err(dev, "failed (err:%d) to rebuild BW rate limit, max_tx_rate: %llu Kbps, min_tx_rate: %llu Kbps for VSI(%u)\n",
				err, ch->max_tx_rate, ch->min_tx_rate,
				ch_vsi->vsi_num);
		else
			dev_dbg(dev, "successfully rebuild BW rate limit, max_tx_rate: %llu Kbps, min_tx_rate: %llu Kbps for VSI(%u)\n",
				ch->max_tx_rate, ch->min_tx_rate,
				ch_vsi->vsi_num);
	}

	/* reconfig RSS for main VSI */
	if (main_vsi->ch_rss_size)
		ice_vsi_cfg_rss_lut_key(main_vsi);

	return 0;

cleanup:
	ice_remove_q_channels(main_vsi, rem_adv_fltr);
	return err;
}

/**
 * ice_cfg_q_channels - Add queue channel for the given TCs
 * @vsi: VSI to be configured
 *
 * Configures queue channel mapping to the given TCs
 */
static int ice_cfg_q_channels(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_channel *ch;
	struct device *dev;
	int ret = 0, i;

	dev = ice_pf_to_dev(pf);
	ice_for_each_chnl_tc(i) {
		if (!(vsi->all_enatc & BIT(i)))
			continue;

		ch = devm_kzalloc(dev, sizeof(*ch), GFP_KERNEL);
		if (!ch) {
			ret = -ENOMEM;
			goto err_free;
		}
		INIT_LIST_HEAD(&ch->list);
		ch->num_rxq = vsi->mqprio_qopt.qopt.count[i];
		ch->num_txq = vsi->mqprio_qopt.qopt.count[i];
		ch->base_q = vsi->mqprio_qopt.qopt.offset[i];
		ch->max_tx_rate = vsi->mqprio_qopt.max_rate[i];
		ch->min_tx_rate = vsi->mqprio_qopt.min_rate[i];

		/* convert to Kbits/s */
		if (ch->max_tx_rate)
			do_div(ch->max_tx_rate, ICE_BW_KBPS_DIVISOR);
		if (ch->min_tx_rate)
			do_div(ch->min_tx_rate, ICE_BW_KBPS_DIVISOR);

		ret = ice_create_q_channel(vsi, ch);
		if (ret) {
			dev_err(dev, "failed creating channel TC:%d\n", i);
			devm_kfree(dev, ch);
			goto err_free;
		}
		list_add_tail(&ch->list, &vsi->ch_list);
		vsi->tc_map_vsi[i] = ch->ch_vsi;
		dev_dbg(dev, "successfully created channel: VSI %p\n",
			ch->ch_vsi);
	}
	return ret;

err_free:
	ice_remove_q_channels(vsi, false);

	return ret;
}

/**
 * ice_setup_tc_qdisc - configure multiple traffic classes
 * @netdev: net device to configure
 * @type_data: TC offload data
 */
static int ice_setup_tc_qdisc(struct net_device *netdev, void *type_data)
{
	struct tc_mqprio_qopt_offload *mqprio_qopt = type_data;
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	u16 mode, ena_tc_qdisc = 0;
	int cur_txq, cur_rxq;
	u8 hw = 0, num_tcf;
	struct device *dev;
	int ret, i;

	dev = ice_pf_to_dev(pf);
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	num_tcf = mqprio_qopt->qopt.num_tc;
	hw = mqprio_qopt->qopt.hw;
	mode = mqprio_qopt->mode;
	if (!hw) {
		clear_bit(ICE_FLAG_TC_MQPRIO, pf->flags);
		vsi->ch_rss_size = 0;
		memcpy(&vsi->mqprio_qopt, mqprio_qopt, sizeof(*mqprio_qopt));
		goto config_tcf;
	}

	/* Generate queue region map for number of TCF requested */
	for (i = 0; i < num_tcf; i++)
		ena_tc_qdisc |= BIT(i);

	switch (mode) {
	case TC_MQPRIO_MODE_DCB:
		netdev_err(netdev, "TC_MQPRIO_MODE_DCB not supported yet\n");
		return -EINVAL;
	case TC_MQPRIO_MODE_CHANNEL:
		if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags)) {
			netdev_err(netdev, "TC MQPRIO offload not supported,FW LLDP is enabled\n");
			return -EINVAL;
		}

		ret = ice_validate_mqprio_qopt(vsi, mqprio_qopt);
		if (ret) {
			netdev_err(netdev, "failed to validate_mqprio_qopt(), ret %d\n",
				   ret);
			return ret;
		}
		memcpy(&vsi->mqprio_qopt, mqprio_qopt, sizeof(*mqprio_qopt));
		set_bit(ICE_FLAG_TC_MQPRIO, pf->flags);
		/* don't assume state of hw_tc_offload during driver load
		 * and set the flag for TC flower filter if hw_tc_offload
		 * already ON
		 */
		if (vsi->netdev->features & NETIF_F_HW_TC)
			set_bit(ICE_FLAG_CLS_FLOWER, pf->flags);
		break;
	default:
		return -EINVAL;
	}

config_tcf:
#else
	num_tcf =  tc;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	/* Requesting same TCF configuration as already enabled */
	if (ena_tc_qdisc == vsi->tc_cfg.ena_tc &&
	    mode != TC_MQPRIO_MODE_CHANNEL)
		return 0;

	/* Pause VSI queues */
	ice_dis_vsi(vsi, true);

	if (!hw && !test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		ice_remove_q_channels(vsi, true);
#else
	if (ena_tc_qdisc == vsi->tc_cfg.ena_tc)
		return 0;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	if (!hw && !test_bit(ICE_FLAG_TC_MQPRIO, pf->flags)) {
		vsi->req_txq = min_t(int, ice_get_avail_txq_count(pf),
				     num_online_cpus());
		vsi->req_rxq = min_t(int, ice_get_avail_rxq_count(pf),
				     num_online_cpus());
#ifdef HAVE_PF_RING
		if (RSS[pf->instance] != 0) {
			vsi->req_txq = min_t(int, vsi->req_txq, RSS[pf->instance]);
			vsi->req_rxq = min_t(int, vsi->req_rxq, RSS[pf->instance]);
		}
#endif
	} else {
		/* logic to rebuild VSI, same like ethtool -L */
		u16 offset = 0, qcount_tx = 0, qcount_rx = 0;

		for (i = 0; i < num_tcf; i++) {
			if (!(ena_tc_qdisc & BIT(i)))
				continue;

			offset = vsi->mqprio_qopt.qopt.offset[i];
			qcount_rx = vsi->mqprio_qopt.qopt.count[i];
			qcount_tx = vsi->mqprio_qopt.qopt.count[i];
		}
		vsi->req_txq = offset + qcount_tx;
		vsi->req_rxq = offset + qcount_rx;

		/* store away original rss_size info, so that it gets reused
		 * form ice_vsi_rebuild during tc-qdisc delete stage - to
		 * determine, what should be the rss_sizefor main VSI
		 */
		vsi->orig_rss_size = vsi->rss_size;
	}

	/* save current values of Tx and Rx queues before calling VSI rebuild
	 * for fallback option
	 */
	cur_txq = vsi->num_txq;
	cur_rxq = vsi->num_rxq;

	/* proceed with rebuild main VSI using correct number of queues */
	ret = ice_vsi_rebuild(vsi, false);
	if (ret) {
		/* fallback to current number of queues */
		dev_info(dev, "Rebuild failed with new queues, try with current number of queues\n");
		vsi->req_txq = cur_txq;
		vsi->req_rxq = cur_rxq;
		clear_bit(__ICE_RESET_FAILED, pf->state);
		if (ice_vsi_rebuild(vsi, false)) {
			dev_err(dev, "Rebuild of main VSI failed again\n");
			return ret;
		}
	}

	vsi->all_numtc = num_tcf;
	vsi->all_enatc = ena_tc_qdisc;
	ret = ice_vsi_cfg_tc(vsi, ena_tc_qdisc);
	if (ret) {
		netdev_err(netdev, "failed configuring TC for VSI id=%d\n",
			   vsi->vsi_num);
		goto exit;
	}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags)) {
		u64 max_tx_rate = vsi->mqprio_qopt.max_rate[0];
		u64 min_tx_rate = vsi->mqprio_qopt.min_rate[0];

		/* set TC0 rate limit if specified */
		if (max_tx_rate || min_tx_rate) {
			/* convert to Kbits/s */
			if (max_tx_rate)
				do_div(max_tx_rate, ICE_BW_KBPS_DIVISOR);
			if (min_tx_rate)
				do_div(min_tx_rate, ICE_BW_KBPS_DIVISOR);

			ret = ice_set_bw_limit(vsi, max_tx_rate, min_tx_rate);
			if (!ret) {
				dev_dbg(dev, "set Tx rate max %llu min %llu for VSI(%u)\n",
					max_tx_rate, min_tx_rate, vsi->vsi_num);
			} else {
				dev_err(dev, "failed to set Tx rate max %llu min %llu for VSI(%u)\n",
					max_tx_rate, min_tx_rate, vsi->vsi_num);
				goto exit;
			}
		}
		ret = ice_cfg_q_channels(vsi);
		if (ret) {
			netdev_err(netdev, "failed configuring queue channels\n");
			goto exit;
		} else {
			netdev_dbg(netdev, "successfully configured channels\n");
		}
	}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	if (vsi->ch_rss_size)
		ice_vsi_cfg_rss_lut_key(vsi);

exit:
	/* if error, reset the all_numtc and all_enatc */
	if (ret) {
		vsi->all_numtc = 0;
		vsi->all_enatc = 0;
	}
	/* resume VSI */
	ice_ena_vsi(vsi, true);

	return ret;
}

#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static LIST_HEAD(ice_block_cb_list);
#endif

static int
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
ice_setup_tc(struct net_device *netdev, enum tc_setup_type type,
	     void *type_data)
#elif defined(HAVE_NDO_SETUP_TC_CHAIN_INDEX)
ice_setup_tc(struct net_device *netdev, u32 __always_unused handle,
	     u32 __always_unused chain_index, __be16 proto,
	     struct tc_to_netdev *tc)
#else
ice_setup_tc(struct net_device *netdev, u32 __always_unused handle,
	     __be16 __always_unused proto, struct tc_to_netdev *tc)
#endif
{
#ifndef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	struct tc_cls_flower_offload *cls_flower = tc->cls_flower;
	unsigned int type = tc->type;
#elif !defined(HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO)
	struct tc_cls_flower_offload *cls_flower = (struct
						   tc_cls_flower_offload *)
						   type_data;
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */
	struct ice_netdev_priv *np = netdev_priv(netdev);
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	struct ice_pf *pf = np->vsi->back;
	int err;

	switch (type) {
	case TC_SETUP_QDISC_MQPRIO:
		/* setup traffic classifier for receive side */
		mutex_lock(&pf->tc_mutex);
		if (ice_is_dcb_active(pf)) {
			netdev_err(netdev, "TC_SETUP_QDISC_MQPRIO not supported when DCB is active\n");
			mutex_unlock(&pf->tc_mutex);
			return -EOPNOTSUPP;
		}
#ifdef HAVE_NETDEV_SB_DEV
		if (ice_is_offloaded_macvlan_ena(pf)) {
			netdev_err(netdev, "TC_SETUP_QDISC_MQPRIO not supported when MACVLAN offloade support is ON. Turn off MACVLAN offload support thru ethtool and try again\n");
			mutex_unlock(&pf->tc_mutex);
			return -EOPNOTSUPP;
		}
#endif /* HAVE_NETDEV_SB_DEV */
		err = ice_setup_tc_qdisc(netdev, type_data);
		mutex_unlock(&pf->tc_mutex);
		return err;
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data,
						  &ice_block_cb_list,
						  ice_setup_tc_block_cb,
						  np, np, true);
	default:
		return -EOPNOTSUPP;
	}
#elif !defined(HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV) || !defined(HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO)

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return ice_setup_tc_cls_flower(np, np->vsi->netdev, cls_flower);
	default:
		return -EOPNOTSUPP;
	}
#endif
	return -EOPNOTSUPP;
}

#ifdef HAVE_TC_INDIR_BLOCK
static struct ice_indr_block_priv *
ice_indr_block_priv_lookup(struct ice_netdev_priv *np,
			   struct net_device *netdev)
{
	struct ice_indr_block_priv *cb_priv;

	/* All callback list access should be protected by RTNL. */
	ASSERT_RTNL();

	list_for_each_entry(cb_priv, &np->tc_indr_block_priv_list, list) {
		if (!cb_priv->netdev)
			return NULL;
		if (cb_priv->netdev == netdev)
			return cb_priv;
	}
	return NULL;
}

static int
ice_indr_setup_block_cb(enum tc_setup_type type, void *type_data,
			void *indr_priv)
{
	struct ice_indr_block_priv *priv = indr_priv;
	struct ice_netdev_priv *np = priv->np;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return ice_setup_tc_cls_flower(np, priv->netdev,
					       (struct flow_cls_offload *)
					       type_data);
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef HAVE_FLOW_BLOCK_API
static void ice_rep_indr_tc_block_unbind(void *cb_priv)
{
	struct ice_indr_block_priv *indr_priv = cb_priv;

	list_del(&indr_priv->list);
	devm_kfree(&indr_priv->netdev->dev, indr_priv);
}
#endif

static int
ice_indr_setup_tc_block(struct net_device *netdev, struct ice_netdev_priv *np,
			struct flow_block_offload *f)
{
	struct ice_indr_block_priv *indr_priv;
#ifdef HAVE_FLOW_BLOCK_API
	struct flow_block_cb *block_cb;
#else
	int err = 0;
#endif

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		indr_priv = ice_indr_block_priv_lookup(np, netdev);
		if (indr_priv)
			return -EEXIST;

		indr_priv = devm_kzalloc(&netdev->dev, sizeof(*indr_priv),
					 GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->netdev = netdev;
		indr_priv->np = np;
		list_add(&indr_priv->list, &np->tc_indr_block_priv_list);

#ifdef HAVE_FLOW_BLOCK_API
		block_cb = flow_block_cb_alloc(ice_indr_setup_block_cb,
					       indr_priv, indr_priv,
					       ice_rep_indr_tc_block_unbind);
		if (IS_ERR(block_cb)) {
			list_del(&indr_priv->list);
			devm_kfree(&netdev->dev, indr_priv);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &ice_block_cb_list);
		return 0;
#else
		err = tcf_block_cb_register(f->block, ice_indr_setup_block_cb,
					    indr_priv, indr_priv, f->extack);
		if (err) {
			list_del(&indr_priv->list);
			devm_kfree(&netdev->dev, indr_priv);
		}
		return err;
#endif
	case FLOW_BLOCK_UNBIND:
		indr_priv = ice_indr_block_priv_lookup(np, netdev);
		if (!indr_priv)
			return -ENOENT;

#ifdef HAVE_FLOW_BLOCK_API
		block_cb = flow_block_cb_lookup(f->block,
						ice_indr_setup_block_cb,
						indr_priv);
		if (!block_cb)
			return -ENOENT;

		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
#else
		tcf_block_cb_unregister(f->block, ice_indr_setup_block_cb,
					indr_priv);
		list_del(&indr_priv->list);
		devm_kfree(&netdev->dev, indr_priv);
		return 0;
#endif
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int
ice_indr_setup_tc_cb(struct net_device *netdev, void *cb_priv,
		     enum tc_setup_type type, void *type_data)
{
	switch (type) {
	case TC_SETUP_BLOCK:
		return ice_indr_setup_tc_block(netdev, cb_priv, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static int
ice_indr_register_block(struct ice_netdev_priv *np, struct net_device *netdev)
{
	struct ice_vsi *vsi = np->vsi;
	struct ice_pf *pf = vsi->back;
	int err;

	err = __flow_indr_block_cb_register(netdev, np, ice_indr_setup_tc_cb,
					    np);
	if (err) {
		dev_err(ice_pf_to_dev(pf), "Failed to register remote block notifier for %s err=%d\n",
			netdev_name(netdev), err);
	}
	return err;
}

static void
ice_indr_unregister_block(struct ice_netdev_priv *np, struct net_device *netdev)
{
	__flow_indr_block_cb_unregister(netdev, ice_indr_setup_tc_cb, np);
}

static void ice_indr_clean_block_privs(struct ice_netdev_priv *np)
{
	struct ice_indr_block_priv *cb_priv, *temp;
	struct list_head *head = &np->tc_indr_block_priv_list;

	list_for_each_entry_safe(cb_priv, temp, head, list) {
		ice_indr_unregister_block(np, cb_priv->netdev);
		devm_kfree(&cb_priv->netdev->dev, cb_priv);
	}
}

static int
ice_netdevice_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct ice_netdev_priv *np = container_of(nb, struct ice_netdev_priv,
						  netdevice_nb);
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	int tunnel_type = ice_tc_tun_get_type(netdev);

	if (tunnel_type != TNL_VXLAN && tunnel_type != TNL_GENEVE)
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_REGISTER:
		ice_indr_register_block(np, netdev);
		break;
	case NETDEV_UNREGISTER:
		ice_indr_unregister_block(np, netdev);
		break;
	}
	return NOTIFY_OK;
}
#endif /* HAVE_TC_INDIR_BLOCK */
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
int ice_open(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_port_info *pi;
	int err;

#ifdef HAVE_PF_RING
	struct ice_pf *adapter = ice_netdev_to_pf(netdev);

	if (adapter->pfring_zc.zombie) {
		printk("%s() bringing up interface previously brought down while in use by ZC, ignoring\n", __FUNCTION__);
		adapter->pfring_zc.zombie = false;
		return 0;
	}
#endif

	/* disallow open if eeprom is corrupted */
	if (test_bit(__ICE_BAD_EEPROM, vsi->back->state))
		return -EOPNOTSUPP;

	if (test_bit(__ICE_NEEDS_RESTART, vsi->back->state)) {
		netdev_err(netdev, "driver needs to be unloaded and reloaded\n");
		return -EIO;
	}

	netif_carrier_off(netdev);

	pi = vsi->port_info;
	err = ice_update_link_info(pi);
	if (err) {
		netdev_err(netdev, "Failed to get link info, error %d\n",
			   err);
		return err;
	}

	/* Set PHY if there is media, otherwise, turn off PHY */
	if (pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE) {
		clear_bit(ICE_FLAG_NO_MEDIA, vsi->back->flags);
		err = ice_configure_phy(vsi);
		if (err) {
			netdev_err(netdev, "Failed to set physical link up, error %d\n",
				   err);
			return err;
		}
	} else {
		set_bit(ICE_FLAG_NO_MEDIA, vsi->back->flags);
		err = ice_aq_set_link_restart_an(pi, false, NULL);
		if (err) {
			netdev_err(netdev, "Failed to set PHY state, VSI %d error %d\n",
				   vsi->vsi_num, err);
			return err;
		}
	}

	err = ice_vsi_open(vsi);
	if (err)
		netdev_err(netdev, "Failed to open VSI 0x%04X on switch 0x%04X\n",
			   vsi->vsi_num, vsi->vsw->sw_id);

	/* Update existing tunnels information */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
	udp_tunnel_get_rx_info(netdev);
#else /* HAVE_UDP_ENC_RX_OFFLOAD */
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
	vxlan_get_rx_port(netdev);
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
	geneve_get_rx_port(netdev);
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#endif /* HAVE_UDP_ENC_RX_OFFLOAD */

	return err;
}

/**
 * ice_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state. The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
int ice_stop(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
#ifdef HAVE_PF_RING
	struct ice_pf *adapter = ice_netdev_to_pf(netdev);

	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		printk("%s() bringing interface down while in use by ZC, ignoring\n", __FUNCTION__);
		adapter->pfring_zc.zombie = true;
		return 0;
	}
#endif

	ice_vsi_close(vsi);

	return 0;
}

#ifdef HAVE_NDO_FEATURES_CHECK
/**
 * ice_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
ice_features_check(struct sk_buff *skb,
		   struct net_device __always_unused *netdev,
		   netdev_features_t features)
{
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_size < 64))
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_header(skb) - skb->data;
	if (len > ICE_TXD_MACLEN_MAX || len & 0x1)
		goto out_rm_features;

	len = skb_transport_header(skb) - skb_network_header(skb);
	if (len > ICE_TXD_IPLEN_MAX || len & 0x1)
		goto out_rm_features;

	if (skb->encapsulation) {
		len = skb_inner_network_header(skb) - skb_transport_header(skb);
		if (len > ICE_TXD_L4LEN_MAX || len & 0x1)
			goto out_rm_features;

		len = skb_inner_transport_header(skb) -
		      skb_inner_network_header(skb);
		if (len > ICE_TXD_IPLEN_MAX || len & 0x1)
			goto out_rm_features;
	}

	return features;
out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}
#endif /* HAVE_NDO_FEATURES_CHECK */

static const struct net_device_ops ice_netdev_safe_mode_ops = {
	.ndo_open = ice_open,
	.ndo_stop = ice_stop,
	.ndo_start_xmit = ice_start_xmit,
	.ndo_set_mac_address = ice_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = ice_change_mtu,
#else
	.ndo_change_mtu = ice_change_mtu,
#endif
	.ndo_get_stats64 = ice_get_stats64,
	.ndo_tx_timeout = ice_tx_timeout,
};

static const struct net_device_ops ice_netdev_ops = {
	.ndo_open = ice_open,
	.ndo_stop = ice_stop,
	.ndo_start_xmit = ice_start_xmit,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = ice_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
	.ndo_set_rx_mode = ice_set_rx_mode,
	.ndo_set_mac_address = ice_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = ice_change_mtu,
#else
	.ndo_change_mtu = ice_change_mtu,
#endif
	.ndo_get_stats64 = ice_get_stats64,
#ifdef HAVE_NETPOLL_CONTROLLER
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = ice_netpoll,
#endif /* CONFIG_NET_POLL_CONTROLLER */
#endif /* HAVE_NETPOLL_CONTROLLER */
#ifdef HAVE_NDO_SET_TX_MAXRATE
	.ndo_set_tx_maxrate = ice_set_tx_maxrate,
#endif /* HAVE_NDO_SET_TX_MAXRATE */
	.ndo_set_vf_spoofchk = ice_set_vf_spoofchk,
#ifdef HAVE_NDO_SET_VF_TRUST
	.ndo_set_vf_mac = ice_set_vf_mac,
	.ndo_get_vf_config = ice_get_vf_cfg,
#ifdef HAVE_RHEL7_NET_DEVICE_OPS_EXT
	/* RHEL7 requires ndo_size to be defined to enable extended ops */
	.ndo_size = sizeof(const struct net_device_ops),
	.extended.ndo_set_vf_trust = ice_set_vf_trust,
#else
	.ndo_set_vf_trust = ice_set_vf_trust,
#endif /* HAVE_RHEL7_NET_DEVICE_OPS_EXT */
#endif /* HAVE_NDO_SET_VF_TRUST */
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN
	.extended.ndo_set_vf_vlan = ice_set_vf_port_vlan,
#else
	.ndo_set_vf_vlan = ice_set_vf_port_vlan,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN */
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	.ndo_set_vf_link_state = ice_set_vf_link_state,
#endif
#ifdef HAVE_VF_STATS
	.ndo_get_vf_stats = ice_get_vf_stats,
#endif /* HAVE_VF_STATS */
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	.ndo_set_vf_rate = ice_set_vf_bw,
#else
	.ndo_set_vf_tx_rate = ice_set_vf_bw,
#endif
	.ndo_vlan_rx_add_vid = ice_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = ice_vlan_rx_kill_vid,
#ifdef HAVE_TC_SETUP_CLSFLOWER
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = ice_setup_tc,
#else
	.ndo_setup_tc = ice_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#endif /* HAVE_TC_SETUP_CLSFLOWER */
	.ndo_set_features = ice_set_features,
	.ndo_bridge_getlink = ice_bridge_getlink,
	.ndo_bridge_setlink = ice_bridge_setlink,
	.ndo_fdb_add = ice_fdb_add,
	.ndo_fdb_del = ice_fdb_del,
	.ndo_rx_flow_steer = ice_rx_flow_steer,
	.ndo_tx_timeout = ice_tx_timeout,
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NDO_BPF
	.ndo_bpf = ice_xdp,
#else
	.ndo_xdp = ice_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = ice_xdp_xmit,
#ifndef NO_NDO_XDP_FLUSH
	.ndo_xdp_flush = ice_xdp_flush,
#endif /* !NO_NDO_XDP_FLUSH */
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef HAVE_NDO_XSK_WAKEUP
	.ndo_xsk_wakeup = ice_xsk_wakeup,
#else
	.ndo_xsk_async_xmit = ice_xsk_async_xmit,
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_UDP_TUNNEL
	.extended.ndo_udp_tunnel_add = ice_udp_tunnel_add,
	.extended.ndo_udp_tunnel_del = ice_udp_tunnel_del,
#else
	.ndo_udp_tunnel_add = ice_udp_tunnel_add,
	.ndo_udp_tunnel_del = ice_udp_tunnel_del,
#endif
#else /* !HAVE_UDP_ENC_RX_OFFLOAD */
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
	.ndo_add_vxlan_port = ice_add_vxlan_port,
	.ndo_del_vxlan_port = ice_del_vxlan_port,
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
	.ndo_add_geneve_port = ice_add_geneve_port,
	.ndo_del_geneve_port = ice_del_geneve_port,
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#endif /* HAVE_UDP_ENC_RX_OFFLOAD */
#ifdef HAVE_NETDEV_SB_DEV
#ifdef HAVE_RHEL7_NET_DEVICE_OPS_EXT
	.extended.ndo_dfwd_add_station = ice_fwd_add_macvlan,
	.extended.ndo_dfwd_del_station = ice_fwd_del_macvlan,
#else
	.ndo_dfwd_add_station = ice_fwd_add_macvlan,
	.ndo_dfwd_del_station = ice_fwd_del_macvlan,
#endif /* HAVE_RHEL7_NET_DEVICE_OPS_EXT */
#endif /* HAVE_NETDEV_SB_DEV */
};
