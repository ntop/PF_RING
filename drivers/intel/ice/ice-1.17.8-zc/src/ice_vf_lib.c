/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_vf_lib_private.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_vf_vsi_vlan_ops.h"
#include "ice_virtchnl_allowlist.h"
#include "ice_vf_adq.h"

#if defined(CONFIG_X86)
static ssize_t sw_cross_timestamp_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t len);
static ssize_t sw_cross_timestamp_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf);
static DEVICE_ATTR_RW(sw_cross_timestamp);

#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
/* Public functions which may be accessed by all driver files */

/**
 * ice_get_vf_by_id - Get pointer to VF by ID
 * @pf: the PF private structure
 * @vf_id: the VF ID to locate
 *
 * Locate and return a pointer to the VF structure associated with a given ID.
 * Returns NULL if the ID does not have a valid VF structure associated with
 * it.
 *
 * Note that valid vf_id values cannot exceed U16_MAX. However, some code
 * flows receive, store, and report VF IDs using a u32 field. This is done so
 * that those flows can use the upper bits for special values such as the
 * broadcast VF ID. The u32 parameter prevents implicit truncation which would
 * cause the driver to misinterpret these special values.
 *
 * This function takes a reference on the VF which must be released by calling
 * ice_put_vf() when the caller has finished accessing the VF structure.
 */
struct ice_vf *ice_get_vf_by_id(struct ice_pf *pf, u32 vf_id)
{
	struct ice_vf *vf;

	/* All valid VF IDs are 16 bits */
	if (vf_id > U16_MAX) {
		dev_err(ice_pf_to_dev(pf), "Out of range VF ID: %u\n",
			vf_id);
		return NULL;
	}

	rcu_read_lock();
	hash_for_each_possible_rcu(pf->vfs.table, vf, entry, vf_id) {
		if (vf->vf_id == vf_id) {
			struct ice_vf *found;

			if (kref_get_unless_zero(&vf->refcnt))
				found = vf;
			else
				found = NULL;

			rcu_read_unlock();
			return found;
		}
	}
	rcu_read_unlock();

	return NULL;
}

struct ice_vf *ice_get_vf_by_dev(struct device *dev)
{
	struct pci_dev *vfdev;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	struct ice_vf *vf;
	unsigned int bkt;

	vfdev = container_of(dev, struct pci_dev, dev);
	pdev = vfdev->physfn;
	pf = pci_get_drvdata(pdev);

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf->vfdev == vfdev)
			break;
	}
	rcu_read_unlock();

	return vf;
}

/**
 * ice_release_vf - Release VF associated with a refcount
 * @ref: the kref decremented to zero
 *
 * Callback function for kref_put to release a VF once its reference count has
 * hit zero.
 */
static void ice_release_vf(struct kref *ref)
{
	struct ice_vf *vf = container_of(ref, struct ice_vf, refcnt);

	if (vf->migration_active)
		ice_migration_uninit_vf(vf);

	vf->vf_ops->free(vf);
}

/**
 * ice_put_vf - Release a reference to a VF
 * @vf: the VF structure to decrease reference count on
 *
 * Decrease the reference count for a VF, and free the entry if it is no
 * longer in use.
 *
 * This must be called after ice_get_vf_by_id() once the reference to the VF
 * structure is no longer used. Otherwise, the VF structure will never be
 * freed.
 */
void ice_put_vf(struct ice_vf *vf)
{
	kref_put(&vf->refcnt, ice_release_vf);
}

/**
 * ice_is_valid_vf_id - helper to check if VF ID is valid
 * @pf: pointer to the PF structure
 * @vf_id: the ID of the VF to check
 *
 * Note that valid vf_id values cannot exceed U16_MAX. However, some code
 * flows receive, store, and report VF IDs using a u32. This function takes
 * a u32 in order to prevent implicit truncation of such values to a u16.
 *
 * Note that this function only guarantees that the VF ID is valid at the
 * point of calling it. It does not guarantee the VF ID will remain valid
 * after it exits. It is possible that the VF will be released at any time
 * after this function exits.
 */
bool ice_is_valid_vf_id(struct ice_pf *pf, u32 vf_id)
{
	struct ice_vf *vf;

	/* VF IDs are not necessarily contiguous. Validate that the VF ID
	 * exists in the VF hash table.
	 */
	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(ice_pf_to_dev(pf), "Invalid VF ID: %u\n", vf_id);
		return false;
	}

	ice_put_vf(vf);
	return true;
}

/**
 * ice_has_vfs - Return true if the PF has any associated VFs
 * @pf: the PF private structure
 *
 * Return whether or not the PF has any allocated VFs.
 *
 * Note that this function only guarantees that there are no VFs at the point
 * of calling it. It does not guarantee that no more VFs will be added.
 */
bool ice_has_vfs(struct ice_pf *pf)
{
	/* A simple check that the hash table is not empty does not require
	 * the mutex or rcu_read_lock.
	 */
	return !hash_empty(pf->vfs.table);
}

/**
 * ice_get_num_vfs - Get number of allocated VFs
 * @pf: the PF private structure
 *
 * Return the total number of allocated VFs. NOTE: VF IDs are not guaranteed
 * to be contiguous. Do not assume that a VF ID is guaranteed to be less than
 * the output of this function.
 */
u16 ice_get_num_vfs(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;
	u16 num_vfs = 0;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf)
		num_vfs++;
	rcu_read_unlock();

	return num_vfs;
}

/**
 * ice_get_vf_vsi - get VF's VSI based on the stored index
 * @vf: VF used to get VSI
 */
struct ice_vsi *ice_get_vf_vsi(struct ice_vf *vf)
{
	if (vf->lan_vsi_idx == ICE_NO_VSI)
		return NULL;

	return vf->pf->vsi[vf->lan_vsi_idx];
}

/**
 * ice_is_vf_disabled
 * @vf: pointer to the VF info
 *
 * If the PF has been disabled, there is no need resetting VF until PF is
 * active again. Similarly, if the VF has been disabled, this means something
 * else is resetting the VF, so we shouldn't continue.
 *
 * Returns true if the caller should consider the VF as disabled whether
 * because that single VF is explicitly disabled or because the PF is
 * currently disabled.
 */
bool ice_is_vf_disabled(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	return (test_bit(ICE_VF_DIS, pf->state) ||
		test_bit(ICE_VF_STATE_DIS, vf->vf_states));
}

/**
 * ice_wait_on_vf_reset - poll to make sure a given VF is ready after reset
 * @vf: The VF being resseting
 *
 * The max poll time is about ~800ms, which is about the maximum time it takes
 * for a VF to be reset and/or a VF driver to be removed.
 */
static void ice_wait_on_vf_reset(struct ice_vf *vf)
{
	int i;

	for (i = 0; i < ICE_MAX_VF_RESET_TRIES; i++) {
		if (test_bit(ICE_VF_STATE_INIT, vf->vf_states))
			break;
		msleep(ICE_MAX_VF_RESET_SLEEP_MS);
	}
}

/**
 * ice_check_vf_ready_for_cfg - check if VF is ready to be configured/queried
 * @vf: VF to check if it's ready to be configured/queried
 *
 * The purpose of this function is to make sure the VF is not in reset, not
 * disabled, and initialized so it can be configured and/or queried by a host
 * administrator.
 */
int ice_check_vf_ready_for_cfg(struct ice_vf *vf)
{
	ice_wait_on_vf_reset(vf);

	if (ice_is_vf_disabled(vf))
		return -EINVAL;

	if (ice_check_vf_init(vf))
		return -EBUSY;

	return 0;
}

/**
 * ice_trigger_vf_reset - Reset a VF on HW
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 * @is_pfr: true if the reset was triggered due to a previous PFR
 *
 * Trigger hardware to start a reset for a particular VF. Expects the caller
 * to wait the proper amount of time to allow hardware to reset the VF before
 * it cleans up and restores VF functionality.
 */
static void ice_trigger_vf_reset(struct ice_vf *vf, bool is_vflr, bool is_pfr)
{
	/* Inform VF that it is no longer active, as a warning */
	clear_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);

	/* Disable VF's configuration API during reset. The flag is re-enabled
	 * when it's safe again to access VF's VSI.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);

	/* VF_MBX_ARQLEN and VF_MBX_ATQLEN are cleared by PFR, so the driver
	 * needs to clear them in the case of VFR/VFLR. If this is done for
	 * PFR, it can mess up VF resets because the VF driver may already
	 * have started cleanup by the time we get here.
	 */
	if (!is_pfr)
		vf->vf_ops->clear_mbx_register(vf);

	vf->vf_ops->trigger_reset_register(vf, is_vflr);
}

static void ice_vf_clear_counters(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (vsi)
		vsi->num_vlan = 0;

	vf->num_mac = 0;
}

/**
 * ice_vf_pre_vsi_rebuild - tasks to be done prior to VSI rebuild
 * @vf: VF to perform pre VSI rebuild tasks
 *
 * These tasks are items that don't need to be amortized since they are most
 * likely called in a for loop with all VF(s) in the reset_all_vfs() case.
 */
static void ice_vf_pre_vsi_rebuild(struct ice_vf *vf)
{
	/* Close any IRQ mapping now */
	if (vf->vf_ops->irq_close)
		vf->vf_ops->irq_close(vf);

	if (vf->migration_active) {
		ice_migration_uninit_vf(vf);
		ice_migration_init_vf(vf);
	}
	/* Remove switch rules associated with the reset VF */
	ice_rm_dcf_sw_vsi_rule(vf->pf, vf);

	if (ice_is_vf_dcf(vf)) {
		if (vf->pf->hw.dcf_caps & DCF_ACL_CAP)
			ice_acl_destroy_tbl(&vf->pf->hw);
		ice_clear_dcf_udp_tunnel_cfg(vf->pf);
	}

	ice_vf_clear_counters(vf);
	vf->vf_ops->clear_reset_trigger(vf);
}

/**
 * ice_vf_reconfig_vsi - Reconfigure a VF VSI with the device
 * @vf: VF to reconfigure the VSI for
 *
 * This is called when a single VF is being reset (i.e. VVF, VFLR, host VF
 * configuration change, etc).
 *
 * It brings the VSI down and then reconfigures it with the hardware.
 */
int ice_vf_reconfig_vsi(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_pf *pf = vf->pf;
	int err;

	if (WARN_ON(!vsi))
		return -EINVAL;

	vsi->flags &= ~(ICE_VSI_FLAG_INIT);

	ice_vsi_decfg(vsi);
	ice_fltr_remove_all(vsi);

	err = ice_vsi_cfg(vsi);
	if (err) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to reconfigure the VF%u's VSI, error %d\n",
			vf->vf_id, err);
		return err;
	}

	ice_vf_recreate_adq_vsi(vf);

	return 0;
}

/**
 * ice_vf_rebuild_vsi - rebuild the VF's VSI
 * @vf: VF to rebuild the VSI for
 *
 * This is only called when all VF(s) are being reset (i.e. PCIe Reset on the
 * host, PFR, CORER, etc.).
 *
 * It reprograms the VSI configuration back into hardware.
 */
static int ice_vf_rebuild_vsi(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_pf *pf = vf->pf;

	if (WARN_ON(!vsi))
		return -EINVAL;

	if (ice_vsi_rebuild(vsi, ICE_VSI_FLAG_INIT)) {
		dev_err(ice_pf_to_dev(pf), "failed to rebuild VF %d VSI\n",
			vf->vf_id);
		return -EIO;
	}
	/* vsi->idx will remain the same in this case so don't update
	 * vf->lan_vsi_idx
	 */
	vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);

	if (ice_vf_rebuild_adq_vsi(vf)) {
		dev_err(ice_pf_to_dev(pf), "failed to rebuild ADQ configuration for VF %d\n",
			vf->vf_id);
		return -EIO;
	}

	return 0;
}

/**
 * ice_vf_set_host_trust_cfg - set trust setting based on pre-reset value
 * @vf: VF to configure trust setting for
 */
static void ice_vf_set_host_trust_cfg(struct ice_vf *vf)
{
	assign_bit(ICE_VF_CAP_TRUSTED, vf->vf_caps, vf->trusted);
}

/**
 * ice_vf_rebuild_host_mac_cfg - add broadcast and the VF's perm_addr/LAA
 * @vf: VF to add MAC filters for
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds a broadcast filter and the VF's perm_addr/LAA after reset.
 */
static int ice_vf_rebuild_host_mac_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	u8 broadcast[ETH_ALEN];
	int status;

	if (WARN_ON(!vsi))
		return -EINVAL;

	if (ice_is_eswitch_mode_switchdev(vf->pf))
		return 0;

	eth_broadcast_addr(broadcast);
	status = ice_fltr_add_mac(vsi, broadcast, ICE_FWD_TO_VSI);
	if (status) {
		dev_err(dev, "failed to add broadcast MAC filter for VF %u, error %d\n",
			vf->vf_id, status);
		return status;
	}

	vf->num_mac++;

	if (is_valid_ether_addr(vf->hw_lan_addr.addr)) {
		status = ice_fltr_add_mac(vsi, vf->hw_lan_addr.addr,
					  ICE_FWD_TO_VSI);
		if (status) {
			dev_err(dev, "failed to add default unicast MAC filter %pM for VF %u, error %d\n",
				&vf->hw_lan_addr.addr[0], vf->vf_id,
				status);
			return status;
		}
		vf->num_mac++;

		ether_addr_copy(vf->dev_lan_addr.addr, vf->hw_lan_addr.addr);
	}

	return 0;
}

/**
 * ice_vf_rebuild_dcf_vlan_cfg - Config DCF outer VLAN for VF
 * @vf: VF to add outer VLAN for
 * @vsi: Pointer to VSI
 */
static int ice_vf_rebuild_dcf_vlan_cfg(struct ice_vf *vf, struct ice_vsi *vsi)
{
	struct ice_dcf_vlan_info *dcf_vlan = &vf->dcf_vlan_info;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vlan *outer_vlan;
	int err;

	if (!ice_is_dcf_enabled(vf->pf) || !dcf_vlan->applying) {
		memset(dcf_vlan, 0, sizeof(*dcf_vlan));
		return 0;
	}

	dcf_vlan->applying = 0;

	outer_vlan = &dcf_vlan->outer_port_vlan;

	if (outer_vlan->vid) {
		err = ice_vf_vsi_dcf_set_outer_port_vlan(vsi, outer_vlan);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to configure outer port VLAN via DCF for VF %u",
					  vf->vf_id);
			return err;
		}
	}

	if (dcf_vlan->outer_stripping_ena) {
		u16 tpid = dcf_vlan->outer_stripping_tpid;

		err = ice_vf_vsi_dcf_ena_outer_vlan_stripping(vsi, tpid);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to enable outer VLAN stripping via DCF for VF %u",
					  vf->vf_id);
			return err;
		}
	}

	return 0;
}

/**
 * ice_vf_rebuild_host_tx_rate_cfg - re-apply the Tx rate limiting configuration
 * @vf: VF to re-apply the configuration for
 *
 * Called after a VF VSI has been re-added/rebuild during reset. The PF driver
 * needs to re-apply the host configured Tx rate limiting configuration.
 */
static int ice_vf_rebuild_host_tx_rate_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	int err;

	if (WARN_ON(!vsi))
		return -EINVAL;

	if (vf->min_tx_rate) {
		err = ice_set_min_bw_limit(vsi, (u64)vf->min_tx_rate * 1000);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to set min Tx rate to %d Mbps for VF %u",
					  vf->min_tx_rate, vf->vf_id);
			return err;
		}
	}

	if (vf->max_tx_rate) {
		err = ice_set_max_bw_limit(vsi, (u64)vf->max_tx_rate * 1000);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to set max Tx rate to %d Mbps for VF %u",
					  vf->max_tx_rate, vf->vf_id);
			return err;
		}
	}

	return 0;
}

static int ice_vf_apply_tx_lldp(struct ice_vf *vf)
{
	if (!vf->transmit_lldp)
		return 0;

	/* Disable it so it can be applied again. */
	vf->transmit_lldp = false;

	return ice_handle_vf_tx_lldp(vf, true);
}

/**
 * ice_vf_rebuild_host_cfg - host admin configuration is persistent across reset
 * @vf: VF to rebuild host configuration on
 */
static void ice_vf_rebuild_host_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	vf->vm_vsi_num = vsi->vsi_num;

	ice_vf_set_host_trust_cfg(vf);

	if (ice_vf_rebuild_host_mac_cfg(vf))
		dev_err(dev, "failed to rebuild default MAC configuration for VF %d\n",
			vf->vf_id);

	if (ice_vf_rebuild_dcf_vlan_cfg(vf, vsi))
		dev_err(dev, "failed to rebuild DCF VLAN configuration for VF %u\n",
			vf->vf_id);

	if (ice_vf_rebuild_host_vlan_cfg(vf, vsi))
		dev_err(dev, "failed to rebuild VLAN configuration for VF %u\n",
			vf->vf_id);

	if (ice_vf_rebuild_host_tx_rate_cfg(vf))
		dev_err(dev, "failed to rebuild Tx rate limiting configuration for VF %u\n",
			vf->vf_id);

	if (ice_vsi_apply_spoofchk(vsi, vf->spoofchk))
		dev_err(dev, "failed to rebuild spoofchk configuration for VF %d\n",
			vf->vf_id);

	if (ice_vf_apply_tx_lldp(vf))
		dev_err(dev, "failed to rebuild transmit LLDP configuration for VF %d\n",
			vf->vf_id);

	/* rebuild aggregator node config for main VF VSI */
	ice_vf_rebuild_aggregator_node_cfg(vsi);
}

/**
 * ice_vf_set_initialized - VF is ready for VIRTCHNL communication
 * @vf: VF to set in initialized state
 *
 * After this function the VF will be ready to receive/handle the
 * VIRTCHNL_OP_GET_VF_RESOURCES message
 */
static void ice_vf_set_initialized(struct ice_vf *vf)
{
	ice_set_vf_state_qs_dis(vf);
	clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_DIS, vf->vf_states);
	set_bit(ICE_VF_STATE_INIT, vf->vf_states);
	memset(&vf->vlan_v2_caps, 0, sizeof(vf->vlan_v2_caps));
}

/**
 * ice_vf_post_vsi_rebuild - Reset tasks that occur after VSI rebuild
 * @vf: the VF being reset
 *
 * Perform reset tasks which must occur after the VSI has been re-created or
 * rebuilt during a VF reset.
 */
static void ice_vf_post_vsi_rebuild(struct ice_vf *vf)
{
	ice_vf_rebuild_host_cfg(vf);
	ice_vf_set_initialized(vf);

	vf->vf_ops->post_vsi_rebuild(vf);
}

/**
 * ice_is_any_vf_in_unicast_promisc - check if any VF(s)
 * are in unicast promiscuous mode
 * @pf: PF structure for accessing VF(s)
 *
 * Return false if no VF(s) are in unicast promiscuous mode,
 * else return true
 */
bool ice_is_any_vf_in_unicast_promisc(struct ice_pf *pf)
{
	bool is_vf_promisc = false;
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		/* found a VF that has promiscuous mode configured */
		if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states)) {
			is_vf_promisc = true;
			break;
		}
	}
	rcu_read_unlock();

	return is_vf_promisc;
}

/**
 * ice_vf_get_promisc_masks - Calculate masks for promiscuous modes
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 * @ucast_m: promiscuous mask to apply to unicast
 * @mcast_m: promiscuous mask to apply to multicast
 *
 * Decide which mask should be used for unicast and multicast filter,
 * based on presence of VLANs
 */
void ice_vf_get_promisc_masks(struct ice_vf *vf, struct ice_vsi *vsi,
			      unsigned long *ucast_m, unsigned long *mcast_m)
{
	if (ice_vf_is_port_vlan_ena(vf) ||
	    ice_vsi_has_non_zero_vlans(vsi)) {
		ice_set_mcast_vlan_promisc_bits(mcast_m);
		ice_set_vf_ucast_vlan_promisc_bits(ucast_m);
	} else {
		ice_set_mcast_promisc_bits(mcast_m);
		ice_set_vf_ucast_promisc_bits(ucast_m);
	}
}

/**
 * ice_vf_clear_all_promisc_modes - Clear promisc/allmulticast on VF VSI
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 *
 * Clear all promiscuous/allmulticast filters for a VF
 */
static int
ice_vf_clear_all_promisc_modes(struct ice_vf *vf, struct ice_vsi *vsi)
{
	DECLARE_BITMAP(ucast_m, ICE_PROMISC_MAX) = {};
	DECLARE_BITMAP(mcast_m, ICE_PROMISC_MAX) = {};
	struct ice_pf *pf = vf->pf;
	int ret = 0;

	ice_vf_get_promisc_masks(vf, vsi, ucast_m, mcast_m);
	if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states)) {
		if (!test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags))
			ret = ice_clear_dflt_vsi(vsi);
		else
			ret = ice_vf_clear_vsi_promisc(vf, vsi, ucast_m);

		if (ret) {
			dev_err(ice_pf_to_dev(vf->pf), "Disabling promiscuous mode failed\n");
		} else {
			clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
			dev_info(ice_pf_to_dev(vf->pf), "Disabling promiscuous mode succeeded\n");
		}
	}

	if (test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) {
		ret = ice_vf_clear_vsi_promisc(vf, vsi, mcast_m);
		if (ret) {
			dev_err(ice_pf_to_dev(vf->pf), "Disabling allmulticast mode failed\n");
		} else {
			clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
			dev_info(ice_pf_to_dev(vf->pf), "Disabling allmulticast mode succeeded\n");
		}
	}
	return ret;
}

/**
 * ice_vf_set_vsi_promisc - Enable promiscuous mode for a VF VSI
 * @vf: the VF to configure
 * @vsi: the VF's VSI
 * @promisc_m: the promiscuous mode to enable
 */
int
ice_vf_set_vsi_promisc(struct ice_vf *vf, struct ice_vsi *vsi,
		       unsigned long *promisc_m)
{
	struct ice_hw *hw = &vsi->back->hw;
	u8 lport = vsi->port_info->lport;
	int status;

	if (ice_vf_is_port_vlan_ena(vf))
		status = ice_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m,
						  ice_vf_get_port_vlan_id(vf),
						  lport);
	else if (ice_vsi_has_non_zero_vlans(vsi))
		status = ice_fltr_set_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = ice_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, 0,
						  lport);

	if (status && status != -EEXIST) {
		dev_err(ice_pf_to_dev(vsi->back), "enable Tx/Rx filter promiscuous mode on VF-%u failed, error: %d\n",
			vf->vf_id, status);
		return status;
	}

	return 0;
}

/**
 * ice_vf_clear_vsi_promisc - Disable promiscuous mode for a VF VSI
 * @vf: the VF to configure
 * @vsi: the VF's VSI
 * @promisc_m: the promiscuous mode to disable
 */
int
ice_vf_clear_vsi_promisc(struct ice_vf *vf, struct ice_vsi *vsi,
			 unsigned long *promisc_m)
{
	struct ice_hw *hw = &vsi->back->hw;
	u8 lport = vsi->port_info->lport;
	int status;

	if (ice_vf_is_port_vlan_ena(vf))
		status = ice_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						    ice_vf_get_port_vlan_id(vf),
						    lport);
	else if (ice_vsi_has_non_zero_vlans(vsi))
		status = ice_fltr_clear_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = ice_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, 0,
						    lport);

	if (status && status != -ENOENT) {
		dev_err(ice_pf_to_dev(vsi->back), "disable Tx/Rx filter promiscuous mode on VF-%u failed, error: %d\n",
			vf->vf_id, status);
		return status;
	}

	return 0;
}

/**
 * ice_reset_vf_mbx_cnt - reset VF mailbox message count
 * @vf: pointer to the VF structure
 *
 * This function clears the VF mailbox message count, and should be called on
 * VF reset.
 */
static void ice_reset_vf_mbx_cnt(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	if (ice_is_feature_supported(pf, ICE_F_MBX_LIMIT))
		ice_mbx_vf_clear_cnt_e830(&pf->hw, vf->vf_id);
	else
		ice_mbx_clear_malvf(&vf->mbx_info);
}

/**
 * ice_reset_all_vfs - reset all allocated VFs in one go
 * @pf: pointer to the PF structure
 *
 * Reset all VFs at once, in response to a PF or other device reset.
 *
 * First, tell the hardware to reset each VF, then do all the waiting in one
 * chunk, and finally finish restoring each VF after the wait. This is useful
 * during PF routines which need to reset all VFs, as otherwise it must perform
 * these resets in a serialized fashion.
 */
void ice_reset_all_vfs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	unsigned int bkt;

	/* If we don't have any VFs, then there is nothing to reset */
	if (!ice_has_vfs(pf))
		return;

	mutex_lock(&pf->vfs.table_lock);

	/* clear all malicious info if the VFs are getting reset */
	ice_for_each_vf(pf, bkt, vf)
		ice_reset_vf_mbx_cnt(vf);

	/* If VFs have been disabled, there is no need to reset */
	if (test_and_set_bit(ICE_VF_DIS, pf->state)) {
		mutex_unlock(&pf->vfs.table_lock);
		return;
	}

	ice_clear_dcf_acl_cfg(pf);
	ice_clear_dcf_udp_tunnel_cfg(pf);
	pf->hw.dcf_caps &= ~(DCF_ACL_CAP | DCF_UDP_TUNNEL_CAP);

	/* Begin reset on all VFs at once */
	ice_for_each_vf(pf, bkt, vf)
		ice_trigger_vf_reset(vf, true, true);

	/* HW requires some time to make sure it can flush the FIFO for a VF
	 * when it resets it. Now that we've triggered all of the VFs, iterate
	 * the table again and wait for each VF to complete.
	 */
	ice_for_each_vf(pf, bkt, vf) {
		if (!vf->vf_ops->poll_reset_status(vf)) {
			/* Display a warning if at least one VF didn't manage
			 * to reset in time, but continue on with the
			 * operation.
			 */
			dev_warn(dev, "VF %u reset check timeout\n", vf->vf_id);
			break;
		}
	}

	/* free VF resources to begin resetting the VSI state */
	ice_for_each_vf(pf, bkt, vf) {
		mutex_lock(&vf->cfg_lock);

		ice_eswitch_detach(pf, vf);
		vf->driver_caps = 0;
		ice_vc_set_default_allowlist(vf);

#ifdef HAVE_TC_SETUP_CLSFLOWER
		/* always release VF ADQ filters since those filters will be
		 * replayed by VF driver. This is needed to avoid stale
		 * filters in software internal data structues
		 */
		ice_del_all_adv_switch_fltr(vf);
#endif

		ice_vf_fdir_exit(vf);
		ice_vf_fdir_init(vf);
		/* clean VF control VSI when resetting VFs since it should be
		 * setup only when iAVF creates its first FDIR rule.
		 */
		if (vf->ctrl_vsi_idx != ICE_NO_VSI)
			ice_vf_ctrl_invalidate_vsi(vf);

		ice_vf_fsub_exit(vf);
		ice_vf_fsub_init(vf);

		ice_vf_pre_vsi_rebuild(vf);
		ice_vf_rebuild_vsi(vf);
		ice_vf_post_vsi_rebuild(vf);

		ice_eswitch_attach(pf, vf);

		mutex_unlock(&vf->cfg_lock);
	}

	ice_flush(hw);
	clear_bit(ICE_VF_DIS, pf->state);

	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * ice_notify_vf_reset - Notify VF of a reset event
 * @vf: pointer to the VF structure
 */
static void ice_notify_vf_reset(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;
	struct virtchnl_pf_event pfe;

	/* Bail out if VF is in disabled state, neither initialized, nor active
	 * state - otherwise proceed with notifications
	 */
	if ((!test_bit(ICE_VF_STATE_INIT, vf->vf_states) &&
	     !test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) ||
	    test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_aq_send_msg_to_vf(hw, vf->vf_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe),
			      NULL);
}

/**
 * ice_reset_vf - Reset a particular VF
 * @vf: pointer to the VF structure
 * @flags: flags controlling behavior of the reset
 *
 * Flags:
 *   ICE_VF_RESET_VFLR - Indicates a reset is due to VFLR event
 *   ICE_VF_RESET_NOTIFY - Send VF a notification prior to reset
 *   ICE_VF_RESET_LOCK - Acquire VF cfg_lock before resetting
 *
 * Returns 0 if the VF is currently in reset, if resets are disabled, or if
 * the VF resets successfully. Returns an error code if the VF fails to
 * rebuild.
 */
int ice_reset_vf(struct ice_vf *vf, u32 flags)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int err = 0;
	bool rsd;

	dev = ice_pf_to_dev(pf);

	if (flags & ICE_VF_RESET_NOTIFY)
		ice_notify_vf_reset(vf);

	if (test_bit(ICE_VF_RESETS_DISABLED, pf->state)) {
		dev_dbg(dev, "Trying to reset VF %d, but all VF resets are disabled\n",
			vf->vf_id);
		return 0;
	}

	/* Set lock if requested in flags, if lock not requested then assert
	 * lock is already held by current thread using lockdep_assert_held
	 */
	if (flags & ICE_VF_RESET_LOCK)
		mutex_lock(&vf->cfg_lock);
	else
		lockdep_assert_held(&vf->cfg_lock);

	if (ice_is_vf_disabled(vf)) {
		vsi = ice_get_vf_vsi(vf);
		if (!vsi) {
			if (flags & ICE_VF_RESET_LOCK)
				mutex_unlock(&vf->cfg_lock);

			dev_dbg(dev, "VF %d is already removed\n", vf->vf_id);
			return -EINVAL;
		}
		ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);

		if (ice_vsi_is_rx_queue_active(vsi))
			ice_vsi_stop_all_rx_rings(vsi);

		if (flags & ICE_VF_RESET_LOCK)
			mutex_unlock(&vf->cfg_lock);

		dev_dbg(dev, "VF is already disabled, there is no need for resetting it, telling VM, all is fine %d\n",
			vf->vf_id);
		return 0;
	}

	/* Set VF disable bit state here, before triggering reset */
	set_bit(ICE_VF_STATE_DIS, vf->vf_states);
	set_bit(ICE_VF_STATE_IN_RESET, vf->vf_states);
	ice_send_vf_reset_to_aux(ice_find_cdev_info_by_id(pf, IIDC_RDMA_ID),
				 ice_abs_vf_id(&pf->hw, vf->vf_id));
	ice_trigger_vf_reset(vf, flags & ICE_VF_RESET_VFLR, false);

	if (ice_dcf_get_state(pf) == ICE_DCF_STATE_ON)
		ice_dcf_set_state(pf, ICE_DCF_STATE_BUSY);

	vsi = ice_get_vf_vsi(vf);
	if (WARN_ON(!vsi)) {
		err = -EIO;
		goto out_unlock;
	}

	ice_dis_vf_qs(vf);

	/* Call Disable LAN Tx queue AQ whether or not queues are
	 * enabled. This is needed for successful completion of VFR.
	 */
	ice_dis_vsi_txq(vsi->port_info, vsi->idx, 0, 0, NULL, NULL,
			NULL, vf->vf_ops->reset_type, vf->vf_id, NULL);

	/* Likewise Disable LAN Tx queues for VF ADQ VSIs */
	if (ice_is_vf_adq_ena(vf)) {
		int tc;

		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			if (!ice_vf_adq_vsi_valid(vf, tc))
				continue;
			ice_dis_vsi_txq(vsi->port_info, vf->ch[tc].vsi_idx, 0,
					0, NULL, NULL, NULL,
					vf->vf_ops->reset_type,
					vf->vf_id, NULL);
		}
	}

	if (vf->driver_caps & VIRTCHNL_VF_CAP_RDMA)
		vf->vf_ops->clear_rdma_irq_map(vf);

	/* poll VPGEN_VFRSTAT reg to make sure
	 * that reset is complete
	 */
	rsd = vf->vf_ops->poll_reset_status(vf);

	/* Display a warning if VF didn't manage to reset in time, but need to
	 * continue on with the operation.
	 */
	if (!rsd)
		dev_warn(dev, "VF reset check timeout on VF %d\n", vf->vf_id);

	vf->driver_caps = 0;
	ice_vc_set_default_allowlist(vf);

	/* disable promiscuous modes in case they were enabled
	 * ignore any error if disabling process failed
	 */
	ice_vf_clear_all_promisc_modes(vf, vsi);

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* always release VF ADQ filters since those filters will be
	 * replayed by VF driver. This is needed to avoid stale filters in
	 * software internal data structures
	 */
	ice_del_all_adv_switch_fltr(vf);
#endif
	/* VF driver gets reloaded on VFLR, so clear ADQ configuration */
	if (flags & ICE_VF_RESET_VFLR)
		ice_vf_adq_release(vf);

	ice_vf_fdir_exit(vf);
	ice_vf_fdir_init(vf);

	/* clean VF control VSI when resetting VF since it should be setup
	 * only when iAVF creates its first FDIR rule.
	 */
	if (vf->ctrl_vsi_idx != ICE_NO_VSI)
		ice_vf_ctrl_vsi_release(vf);

	ice_vf_fsub_exit(vf);
	ice_vf_fsub_init(vf);

	ice_vf_pre_vsi_rebuild(vf);

	if (ice_vf_reconfig_vsi(vf)) {
		dev_err(dev, "Failed to reconfigure the VF%u's VSI\n",
			vf->vf_id);
		err = -EFAULT;
		goto out_unlock;
	}

	ice_vf_post_vsi_rebuild(vf);
	vsi = ice_get_vf_vsi(vf);
	if (WARN_ON(!vsi)) {
		err = -EINVAL;
		goto out_unlock;
	}

	ice_eswitch_update_repr(vf->repr_id, vsi);

	if (ice_dcf_get_state(pf) == ICE_DCF_STATE_BUSY) {
		struct virtchnl_pf_event pfe = { 0 };

		ice_dcf_set_state(pf, ICE_DCF_STATE_PAUSE);

		pfe.event = VIRTCHNL_EVENT_DCF_VSI_MAP_UPDATE;
		pfe.event_data.vf_vsi_map.vf_id = vf->vf_id;
		pfe.event_data.vf_vsi_map.vsi_id = vsi->vsi_num;

		ice_aq_send_msg_to_vf(&pf->hw, ICE_DCF_VFID,
				      VIRTCHNL_OP_EVENT,
				      VIRTCHNL_STATUS_SUCCESS,
				      (u8 *)&pfe, sizeof(pfe), NULL);
	}

	/* If trust is taken away from VF with RX LLDP enabled,
	 * disable it because untrusted VF should not have access to
	 * trusted resources.
	 */
	if (vsi->rx_lldp_ena)
		ice_cfg_sw_lldp(vsi, false, false);

	/* if the VF has been reset allow it to come up again */
	ice_reset_vf_mbx_cnt(vf);

out_unlock:
	clear_bit(ICE_VF_STATE_IN_RESET, vf->vf_states);

	if (flags & ICE_VF_RESET_LOCK)
		mutex_unlock(&vf->cfg_lock);

	return err;
}

/**
 * ice_set_vf_state_qs_dis - Set VF queues state to disabled
 * @vf: pointer to the VF structure
 */
void ice_set_vf_state_qs_dis(struct ice_vf *vf)
{
	/* Clear Rx/Tx enabled queues flag */
	bitmap_zero(vf->txq_ena, ICE_MAX_QS_PER_VF);
	bitmap_zero(vf->rxq_ena, ICE_MAX_QS_PER_VF);
	clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);
}

/* Private functions only accessed from other virtualization files */

static void
ice_vf_hash_ctx_init(struct ice_vf *vf)
{
	memset(&vf->hash_ctx, 0, sizeof(vf->hash_ctx));
}

static ssize_t
rss_lut_vf_attr_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct ice_vf *vf = ice_get_vf_by_dev(dev);
	struct ice_vsi *vsi;

	if (!vf)
		return -ENOENT;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "%s: VSI for this VF is null!", __func__);
		return -ENOENT;
	}

	return sysfs_emit(buf, "%u\n", vsi->rss_table_size);
}

static ssize_t
rss_lut_vf_attr_store(struct device *dev, struct device_attribute *attr,
		      const char *buf, size_t count)
{
	struct pci_dev *vfdev = container_of(dev, struct pci_dev, dev);
	struct ice_vf *vf = ice_get_vf_by_dev(dev);
	struct pci_dev *pdev = vfdev->physfn;
	struct ice_vsi *vsi;
	struct ice_pf *pf;
	struct ice_hw *hw;

	if (!vf)
		return -ENOENT;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "%s: VSI for this VF is null!", __func__);
		return -ENOENT;
	}

	pf = pci_get_drvdata(pdev);
	hw = &pf->hw;

	return ice_vsi_alloc_rss_lut(hw, dev, vsi, buf, count);
}

static int ice_init_vf_rss_lut_sysfs(struct ice_vf *vf)
{
	struct device_attribute tmp = __ATTR(rss_lut_vf_attr, 0644,
					     rss_lut_vf_attr_show,
					     rss_lut_vf_attr_store);

	vf->rss_lut_attr = tmp;

	return device_create_file(&vf->vfdev->dev, &vf->rss_lut_attr);
}

static bool
ice_is_transmit_lldp_enabled(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;

	ice_for_each_vf(pf, bkt, vf) {
		if (vf->transmit_lldp)
			return true;
	}

	return false;
}

/**
 * ice_ena_vf_rx_lldp
 * @vf: VF to configure Rx LLDP for
 *
 * Configure Rx filters for VF to receive LLDP
 */
int ice_ena_vf_rx_lldp(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags)) {
		dev_dbg(ice_pf_to_dev(pf), "FW LLDP agent is enabled, cannot enable Rx LLDP on VF %d\n",
			vf->vf_id);
		return -EPERM;
	}

	if (!vf->trusted) {
		dev_dbg(ice_pf_to_dev(pf), "VF %d is not trusted - cannot configure Rx LLDP filter.\n",
			vf->vf_id);
		return -EPERM;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -ENOENT;

	if (vsi->rx_lldp_ena)
		return 0;

	ice_cfg_sw_lldp(vsi, false, true);

	return 0;
}

/**
 * ice_ena_all_vfs_rx_lldp - Re-add RX LLDP filter on applicable VFs.
 * @pf: ptr to PF
 *
 * That is in case when fw-lldp-agent is toggled and LLDP multicast addresses
 * are added to the interface.
 * RX LLDP filter will be added for trusted VFs only.
 */
void
ice_ena_all_vfs_rx_lldp(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;

	if (!test_bit(ICE_FLAG_SRIOV_ENA, pf->flags))
		return;

	ice_for_each_vf(pf, bkt, vf) {
		struct ice_vsi *vsi = ice_get_vf_vsi(vf);

		if (vsi && vsi->lldp_macs > 0 && !vsi->rx_lldp_ena)
			ice_ena_vf_rx_lldp(vf);
	}
}

/**
 * ice_handle_vf_tx_lldp
 * @vf: VF to configure Tx LLDP for
 * @ena: Enable or disable Tx LLDP switch rule
 *
 * Configure Tx filters for VF to receive LLDP
 */
int ice_handle_vf_tx_lldp(struct ice_vf *vf, bool ena)
{
	void (*allow_override)(struct ice_vsi_ctx *ctx);
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);
	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -ENOENT;

	if (ena && test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags)) {
		dev_err(dev, "Transmit LLDP VF is only allowed when FW LLDP Agent is disabled");
		return -EPERM;
	}

	if (ena && ice_is_transmit_lldp_enabled(pf)) {
		dev_err(dev, "Only a single VF per port is allowed to transmit LLDP packets, ignoring the settings");
		return -EPERM;
	}

	allow_override = ena ? ice_vsi_ctx_set_allow_override
			     : ice_vsi_ctx_clear_allow_override;

	if (ice_vsi_update_security(vsi, allow_override))
		return -ENOENT;

	vf->transmit_lldp = ena;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -ENOENT;
	/* If VF can transmit LLDP, then PF cannot and vice versa */
	allow_override = ena ? ice_vsi_ctx_clear_allow_override
			     : ice_vsi_ctx_set_allow_override;

	if (ice_vsi_update_security(vsi, allow_override))
		return -ENOENT;

	return 0;
}

static ssize_t
transmit_lldp_vf_attr_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct ice_vf *vf = ice_get_vf_by_dev(dev);

	if (!vf)
		return -ENOENT;

	return sysfs_emit(buf, "%u\n", vf->transmit_lldp);
}

static ssize_t
transmit_lldp_vf_attr_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct pci_dev *vfdev = container_of(dev, struct pci_dev, dev);
	struct ice_vf *vf = ice_get_vf_by_dev(dev);
	struct pci_dev *pdev = vfdev->physfn;
	struct ice_pf *pf;
	bool ena;
	int err;

	if (!vf)
		return -ENOENT;

	pf = pci_get_drvdata(pdev);
	if (!pf)
		return -ENOENT;

	err = kstrtobool(buf, &ena);
	if (err)
		return -EINVAL;

	if (ena == vf->transmit_lldp) {
		dev_dbg(dev, "Transmit LLDP value already set for VF %d",
			vf->vf_id);
		return count;
	}

	err = ice_handle_vf_tx_lldp(vf, ena);
	if (err)
		return err;

	return count;
}

static int ice_init_vf_transmit_lldp_sysfs(struct ice_vf *vf)
{
	struct device_attribute tmp = __ATTR(transmit_lldp, 0644,
					     transmit_lldp_vf_attr_show,
					     transmit_lldp_vf_attr_store);

	vf->transmit_lldp_attr = tmp;

	return device_create_file(&vf->vfdev->dev, &vf->transmit_lldp_attr);
}

#if defined(CONFIG_X86)
/**
 * sw_cross_timestamp_store - sysfs interface for enabling sw_cross_timestamp
 * @dev: Device that owns the attribute
 * @attr: sysfs device attribute
 * @buf: String representing configuration
 * @len: Length of the 'buf' string
 *
 * Return: number of bytes written on success, negative error code otherwise.
 */
static ssize_t sw_cross_timestamp_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t len)
{
	struct ice_vf *vf = ice_get_vf_by_dev(dev);
	bool ena;

	if (!vf)
		return -ENOENT;

	if (kstrtobool(buf, &ena))
		return -EINVAL;

	vf->sw_crosststamp_ena = ena;

	return len;
}

/**
 * sw_cross_timestamp_show - sysfs callback for reading sw_cross_timestamp file
 * @dev: pointer to dev structure
 * @attr: device attribute pointing sysfs file
 * @buf: user buffer to fill with returned data
 *
 * Return: number of bytes written on success, negative error code otherwise.
 */
static ssize_t sw_cross_timestamp_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct ice_vf *vf = ice_get_vf_by_dev(dev);

	if (!vf)
		return -ENOENT;

	return sysfs_emit(buf, "%u\n", vf->sw_crosststamp_ena);
}

#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
int ice_init_vf_sysfs(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	int err = 0;

	if (!vf->vfdev) {
		dev_err(dev, "%s: no vfdev", __func__);
		return -ENOENT;
	}

	err = ice_init_vf_rss_lut_sysfs(vf);
	if (err) {
		dev_err(dev, "could not init rss_lut_vf_attr sysfs entry, err: %d",
			err);
		return err;
	}

	err = ice_init_vf_transmit_lldp_sysfs(vf);
	if (err)
		dev_err(dev, "could not init transmit_lldp sysfs entry, err: %d",
			err);

#if defined(CONFIG_X86)
	if (vf->pf->hw.mac_type == ICE_MAC_E810)
		device_create_file(&vf->vfdev->dev,
				   &dev_attr_sw_cross_timestamp);

#endif /* CONFIG_X86 && VIRTCHNL_PTP_SUPPORT */
	return err;
}

/**
 * ice_initialize_vf_entry - Initialize a VF entry
 * @vf: pointer to the VF structure
 */
void ice_initialize_vf_entry(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vfs *vfs;

	vfs = &pf->vfs;

	/* assign default capabilities */
	vf->spoofchk = true;
	vf->num_vf_qs = vfs->num_qps_per;
	/* set default number of MSI-X */
	vf->num_msix = pf->vfs.num_msix_per;
	ice_vc_set_default_allowlist(vf);
	ice_virtchnl_set_dflt_ops(vf);

	/* ctrl_vsi_idx will be set to a valid value only when iAVF
	 * creates its first fdir rule.
	 */
	ice_vf_ctrl_invalidate_vsi(vf);
	ice_vf_fdir_init(vf);

	ice_vf_hash_ctx_init(vf);

	ice_vf_fsub_init(vf);

	/* Initialize mailbox info for this VF */
	if (ice_is_feature_supported(pf, ICE_F_MBX_LIMIT))
		ice_mbx_vf_clear_cnt_e830(&pf->hw, vf->vf_id);
	else
		ice_mbx_init_vf_info(&pf->hw, &vf->mbx_info);
	mutex_init(&vf->cfg_lock);
}

void ice_deinitialize_vf_entry(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	if (!ice_is_feature_supported(pf, ICE_F_MBX_LIMIT))
		list_del(&vf->mbx_info.list_entry);
}

/**
 * ice_dis_vf_qs - Disable the VF queues
 * @vf: pointer to the VF structure
 */
void ice_dis_vf_qs(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);
	/* Likewise if VF ADQ is enabled, stop Tx and Rx rings of VF ADQ VSI */
	if (ice_is_vf_adq_ena(vf)) {
		int tc;

		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			if (!ice_vf_adq_vsi_valid(vf, tc))
				continue;
			vsi = ice_get_vf_adq_vsi(vf, tc);
			ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
			ice_vsi_stop_all_rx_rings(vsi);
		}
	}
	ice_set_vf_state_qs_dis(vf);
}

/**
 * ice_err_to_virt_err - translate errors for VF return code
 * @err: error return code
 */
enum virtchnl_status_code ice_err_to_virt_err(int err)
{
	switch (err) {
	case 0:
		return VIRTCHNL_STATUS_SUCCESS;
	case -EINVAL:
	case -ENODEV:
		return VIRTCHNL_STATUS_ERR_PARAM;
	case -ENOMEM:
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;
	case -EALREADY:
	case -EBUSY:
	case -EIO:
	case -ENOSPC:
		return VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
	default:
		return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
	}
}

/**
 * ice_check_vf_init - helper to check if VF init complete
 * @vf: the pointer to the VF to check
 */
int ice_check_vf_init(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	if (!test_bit(ICE_VF_STATE_INIT, vf->vf_states)) {
		dev_err(ice_pf_to_dev(pf), "VF ID: %u in reset. Try again.\n",
			vf->vf_id);
		return -EBUSY;
	}
	return 0;
}

/**
 * ice_vf_get_port_info - Get the VF's port info structure
 * @vf: VF used to get the port info structure for
 */
struct ice_port_info *ice_vf_get_port_info(struct ice_vf *vf)
{
	return vf->pf->hw.port_info;
}

/**
 * ice_cfg_mac_antispoof - Configure MAC antispoof checking behavior
 * @vsi: the VSI to configure
 * @enable: whether to enable or disable the spoof checking
 *
 * Configure a VSI to enable (or disable) spoof checking behavior.
 */
static int ice_cfg_mac_antispoof(struct ice_vsi *vsi, bool enable)
{
	struct ice_vsi_ctx *ctx;
	int err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->info.sec_flags = vsi->info.sec_flags;
	ctx->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);

	if (enable)
		ctx->info.sec_flags |= ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF;
	else
		ctx->info.sec_flags &= ~ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF;

	err = ice_update_vsi(&vsi->back->hw, vsi->idx, ctx, NULL);
	if (err)
		dev_err(ice_pf_to_dev(vsi->back), "Failed to configure Tx MAC anti-spoof %s for VSI %d, error %d\n",
			enable ? "ON" : "OFF", vsi->vsi_num, err);
	else
		vsi->info.sec_flags = ctx->info.sec_flags;

	kfree(ctx);

	return err;
}

/**
 * ice_vsi_ena_spoofchk - enable Tx spoof checking for this VSI
 * @vsi: VSI to enable Tx spoof checking for
 */
static int ice_vsi_ena_spoofchk(struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops;
	int err;

	vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);

	err = vlan_ops->ena_tx_filtering(vsi);
	if (err)
		return err;

	return ice_cfg_mac_antispoof(vsi, true);
}

/**
 * ice_vsi_dis_spoofchk - disable Tx spoof checking for this VSI
 * @vsi: VSI to disable Tx spoof checking for
 */
static int ice_vsi_dis_spoofchk(struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops;
	int err;

	vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);

	err = vlan_ops->dis_tx_filtering(vsi);
	if (err)
		return err;

	return ice_cfg_mac_antispoof(vsi, false);
}

/**
 * ice_vsi_apply_spoofchk - Apply Tx spoof checking setting to a VSI
 * @vsi: VSI associated to the VF
 * @enable: whether to enable or disable the spoof checking
 */
int ice_vsi_apply_spoofchk(struct ice_vsi *vsi, bool enable)
{
	int err;

	if (enable)
		err = ice_vsi_ena_spoofchk(vsi);
	else
		err = ice_vsi_dis_spoofchk(vsi);

	return err;
}

/**
 * ice_is_vf_trusted
 * @vf: pointer to the VF info
 */
bool ice_is_vf_trusted(struct ice_vf *vf)
{
	return test_bit(ICE_VF_CAP_TRUSTED, vf->vf_caps);
}

/**
 * ice_vf_has_no_qs_ena - check if the VF has any Rx or Tx queues enabled
 * @vf: the VF to check
 *
 * Returns true if the VF has no Rx and no Tx queues enabled and returns false
 * otherwise
 */
bool ice_vf_has_no_qs_ena(struct ice_vf *vf)
{
	return (!bitmap_weight(vf->rxq_ena, ICE_MAX_QS_PER_VF) &&
		!bitmap_weight(vf->txq_ena, ICE_MAX_QS_PER_VF));
}

/**
 * ice_is_vf_link_up - check if the VF's link is up
 * @vf: VF to check if link is up
 */
bool ice_is_vf_link_up(struct ice_vf *vf)
{
	struct ice_port_info *pi = ice_vf_get_port_info(vf);
	struct ice_pf *pf = vf->pf;

	if (ice_check_vf_init(vf))
		return false;

	if (test_bit(ICE_BAD_EEPROM, pf->state))
		return false;

	if (ice_vf_has_no_qs_ena(vf))
		return false;
	else if (vf->link_forced)
		return vf->link_up;
	else
		return pi->phy.link_info.link_info &
			ICE_AQ_LINK_UP;
}

/**
 * ice_vf_rebuild_host_vlan_cfg - add VLAN 0 filter or rebuild the Port VLAN
 * @vf: VF to add MAC filters for
 * @vsi: Pointer to VSI
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds either a VLAN 0 or port VLAN based filter after reset.
 */
int ice_vf_rebuild_host_vlan_cfg(struct ice_vf *vf, struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	struct device *dev = ice_pf_to_dev(vf->pf);
	int err;

	if (ice_vf_is_port_vlan_ena(vf)) {
		err = vlan_ops->set_port_vlan(vsi, &vf->port_vlan_info);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to configure port VLAN via VSI parameters for VF %u",
					  vf->vf_id);
			return err;
		}

		err = vlan_ops->add_vlan(vsi, &vf->port_vlan_info);
	} else {
		/* clear possible previous port vlan config */
		err = ice_vsi_clear_port_vlan(vsi);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to clear port VLAN via VSI parameters for VF %u",
					  vf->vf_id);
			return err;
		}
		err = ice_vsi_add_vlan_zero(vsi);
	}

	if (err) {
		ice_dev_err_errno(dev, err,
				  "failed to add VLAN %u filter for VF %u during VF rebuild",
				  ice_vf_is_port_vlan_ena(vf) ?
				  ice_vf_get_port_vlan_id(vf) : 0, vf->vf_id);
		return err;
	}

	err = vlan_ops->ena_rx_filtering(vsi);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "failed to enable Rx VLAN filtering for VF %d VSI %d during VF rebuild",
				  vf->vf_id, vsi->idx);
	}

	return 0;
}

/**
 * ice_vf_rebuild_aggregator_node_cfg - rebuild aggregator node config
 * @vsi: Pointer to VSI
 *
 * This function moves VSI into corresponding scheduler aggregator node
 * based on cached value of "aggregator node info" per VSI
 */
void ice_vf_rebuild_aggregator_node_cfg(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int status;

	if (!vsi->agg_node)
		return;

	dev = ice_pf_to_dev(pf);
	if (vsi->agg_node->num_vsis == ICE_MAX_VSIS_IN_AGG_NODE) {
		dev_dbg(dev,
			"agg_id %u already has reached max_num_vsis %u\n",
			vsi->agg_node->agg_id, vsi->agg_node->num_vsis);
		return;
	}

	status = ice_move_vsi_to_agg(pf->hw.port_info, vsi->agg_node->agg_id,
				     vsi->idx, (u8)vsi->tc_cfg.ena_tc);
	if (status)
		dev_dbg(dev, "unable to move VSI idx %u into aggregator %u node",
			vsi->idx, vsi->agg_node->agg_id);
	else
		vsi->agg_node->num_vsis++;
}

/**
 * ice_vf_init_host_cfg - Initialize host admin configuration
 * @vf: VF to initialize
 * @vsi: the VSI created at initialization
 *
 * Initialize the VF host configuration. Called during VF creation to setup
 * VLAN 0, add the VF VSI broadcast filter, and setup spoof checking. It
 * should only be called during VF creation.
 */
int ice_vf_init_host_cfg(struct ice_vf *vf, struct ice_vsi *vsi)
{
	struct ice_vsi_vlan_ops *vlan_ops;
	struct ice_pf *pf = vf->pf;
	u8 broadcast[ETH_ALEN];
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	vf->vm_vsi_num = vsi->vsi_num;

	err = ice_vsi_add_vlan_zero(vsi);
	if (err) {
		dev_warn(dev, "Failed to add VLAN 0 filter for VF %d\n",
			 vf->vf_id);
		return err;
	}

	vlan_ops = ice_get_compat_vsi_vlan_ops(vsi);
	err = vlan_ops->ena_rx_filtering(vsi);
	if (err) {
		dev_warn(dev, "Failed to enable Rx VLAN filtering for VF %d\n",
			 vf->vf_id);
		return err;
	}

	eth_broadcast_addr(broadcast);
	err = ice_fltr_add_mac(vsi, broadcast, ICE_FWD_TO_VSI);
	if (err) {
		dev_err(dev, "Failed to add broadcast MAC filter for VF %d, status %d\n",
			vf->vf_id, err);
		return err;
	}

	vf->num_mac = 1;

	err = ice_vsi_apply_spoofchk(vsi, vf->spoofchk);
	if (err) {
		dev_warn(dev, "Failed to initialize spoofchk setting for VF %d\n",
			 vf->vf_id);
		return err;
	}

	return 0;
}

/**
 * ice_vf_ctrl_invalidate_vsi - invalidate ctrl_vsi_idx to remove VSI access
 * @vf: VF that control VSI is being invalidated on
 */
void ice_vf_ctrl_invalidate_vsi(struct ice_vf *vf)
{
	vf->ctrl_vsi_idx = ICE_NO_VSI;
}

/**
 * ice_vf_ctrl_vsi_release - invalidate the VF's control VSI after freeing it
 * @vf: VF that control VSI is being released on
 */
void ice_vf_ctrl_vsi_release(struct ice_vf *vf)
{
	ice_vsi_release(vf->pf->vsi[vf->ctrl_vsi_idx]);
	ice_vf_ctrl_invalidate_vsi(vf);
}

/**
 * ice_vf_ctrl_vsi_setup - Set up a VF control VSI
 * @vf: VF to setup control VSI for
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
struct ice_vsi *ice_vf_ctrl_vsi_setup(struct ice_vf *vf)
{
	struct ice_vsi_cfg_params params = {};
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	params.type = ICE_VSI_CTRL;
	params.port_info = ice_vf_get_port_info(vf);
	params.vf = vf;
	params.flags = ICE_VSI_FLAG_INIT;

	vsi = ice_vsi_setup(pf, &params);

	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF control VSI\n");
		ice_vf_ctrl_invalidate_vsi(vf);
	}

	return vsi;
}

/**
 * ice_vf_invalidate_vsi - invalidate vsi_idx to remove VSI access
 * @vf: VF to remove access to VSI for
 */
void ice_vf_invalidate_vsi(struct ice_vf *vf)
{
	vf->lan_vsi_idx = ICE_NO_VSI;
}

/**
 * ice_vf_vsi_release - Release the VF VSI and invalidate indexes
 * @vf: pointer to the VF structure
 *
 * Release the VF associated with this VSI and then invalidate the VSI
 * indexes.
 */
void ice_vf_vsi_release(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	ice_vsi_release(vsi);
	ice_vf_invalidate_vsi(vf);
}

/**
 * ice_get_vf_ctrl_vsi - Get first VF control VSI pointer
 * @pf: the PF private structure
 * @vsi: pointer to the VSI
 *
 * Return first found VF control VSI other than the vsi
 * passed by parameter. This function is used to determine
 * whether new resources have to be allocated for control VSI
 * or they can be shared with existing one.
 *
 * Return found VF control VSI pointer other itself. Return
 * NULL Otherwise.
 *
 */
struct ice_vsi *ice_get_vf_ctrl_vsi(struct ice_pf *pf, struct ice_vsi *vsi)
{
	struct ice_vsi *ctrl_vsi = NULL;
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf != vsi->vf && vf->ctrl_vsi_idx != ICE_NO_VSI) {
			ctrl_vsi = pf->vsi[vf->ctrl_vsi_idx];
			break;
		}
	}

	rcu_read_unlock();
	return ctrl_vsi;
}
