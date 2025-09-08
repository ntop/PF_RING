/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_devlink.h"
#include "ice_eswitch.h"
#include "ice_fw_update.h"
#include "ice_common.h"
#include "ice_adminq_cmd.h"
#include "ice_dcb_lib.h"
#include "ice_idc_int.h"
#ifdef CONFIG_PCI_IOV
#include "ice_virtchnl_allowlist.h"
#endif /* CONFIG_PCI_IOV */

#ifdef HAVE_DEVLINK_INFO_GET
/* context for devlink info version reporting */
struct ice_info_ctx {
	char buf[128];
	struct ice_orom_info pending_orom;
	struct ice_nvm_info pending_nvm;
	struct ice_netlist_info pending_netlist;
	struct ice_hw_dev_caps dev_caps;
};

/* The following functions are used to format specific strings for various
 * devlink info versions. The ctx parameter is used to provide the storage
 * buffer, as well as any ancillary information calculated when the info
 * request was made.
 *
 * If a version does not exist, for example when attempting to get the
 * inactive version of flash when there is no pending update, the function
 * should leave the buffer in the ctx structure empty.
 */

static void ice_info_get_dsn(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	u8 dsn[8];

	/* Copy the DSN into an array in Big Endian format */
	put_unaligned_be64(pci_get_dsn(pf->pdev), dsn);

	snprintf(ctx->buf, sizeof(ctx->buf), "%8phD", dsn);
}

static void ice_info_pba(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;
	int status;

	status = ice_read_pba_string(hw, (u8 *)ctx->buf, sizeof(ctx->buf));
	if (status)
		/* We failed to locate the PBA, so just skip this entry */
		dev_dbg(ice_pf_to_dev(pf), "Failed to read Product Board Assembly string, status %d\n",
			status);
}

static void ice_info_fw_mgmt(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
		 hw->fw_maj_ver, hw->fw_min_ver, hw->fw_patch);
}

static void ice_info_fw_api(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u", hw->api_maj_ver,
		 hw->api_min_ver, hw->api_patch);
}

static void ice_info_fw_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", hw->fw_build);
}

static void ice_info_fw_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u", nvm->srev);
}

static void
ice_info_pending_fw_srev(struct ice_pf __always_unused *pf,
			 struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u", nvm->srev);
}

static void ice_info_orom_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &pf->hw.flash.orom;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
		 orom->major, orom->build, orom->patch);
}

static void
ice_info_pending_orom_ver(struct ice_pf __always_unused *pf,
			  struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &ctx->pending_orom;

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
			 orom->major, orom->build, orom->patch);
}

static void ice_info_orom_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &pf->hw.flash.orom;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u", orom->srev);
}

static void
ice_info_pending_orom_srev(struct ice_pf __always_unused *pf,
			   struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &ctx->pending_orom;

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u", orom->srev);
}

static void ice_info_nvm_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x", nvm->major, nvm->minor);
}

static void
ice_info_pending_nvm_ver(struct ice_pf __always_unused *pf,
			 struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x",
			 nvm->major, nvm->minor);
}

static void ice_info_eetrack(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);
}

static void
ice_info_pending_eetrack(struct ice_pf __always_unused *pf,
			 struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);
}

static void ice_info_ddp_pkg_name(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%s", hw->active_pkg_name);
}

static void
ice_info_ddp_pkg_version(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_pkg_ver *pkg = &pf->hw.active_pkg_ver;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u.%u",
		 pkg->major, pkg->minor, pkg->update, pkg->draft);
}

static void
ice_info_ddp_pkg_bundle_id(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", pf->hw.active_track_id);
}

static void ice_info_netlist_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	/* The netlist version fields are BCD formatted */
	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x",
		 netlist->major, netlist->minor,
		 netlist->type >> 16, netlist->type & 0xFFFF,
		 netlist->rev, netlist->cust_ver);
}

static void ice_info_netlist_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);
}

static void
ice_info_pending_netlist_ver(struct ice_pf __always_unused *pf,
			     struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	/* The netlist version fields are BCD formatted */
	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x",
			 netlist->major, netlist->minor,
			 netlist->type >> 16, netlist->type & 0xFFFF,
			 netlist->rev, netlist->cust_ver);
}

static void
ice_info_pending_netlist_build(struct ice_pf __always_unused *pf,
			       struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);
}

#define fixed(key, getter) { ICE_VERSION_FIXED, key, getter, NULL }
#define running(key, getter) { ICE_VERSION_RUNNING, key, getter, NULL }
#define stored(key, getter, fallback) \
	{ ICE_VERSION_STORED, key, getter, fallback }

/* The combined() macro inserts both the running entry as well as a stored
 * entry. The running entry will always report the version from the active
 * handler. The stored entry will first try the pending handler, and fallback
 * to the active handler if the pending function does not report a version.
 * The pending handler should check the status of a pending update for the
 * relevant flash component. It should only fill in the buffer in the case
 * where a valid pending version is available. This ensures that the related
 * stored and running versions remain in sync, and that stored versions are
 * correctly reported as expected.
 */
#define combined(key, active, pending) \
	running(key, active), \
	stored(key, pending, active)

enum ice_version_type {
	ICE_VERSION_FIXED,
	ICE_VERSION_RUNNING,
	ICE_VERSION_STORED,
};

static const struct ice_devlink_version {
	enum ice_version_type type;
	const char *key;
	void (*getter)(struct ice_pf *pf, struct ice_info_ctx *ctx);
	void (*fallback)(struct ice_pf *pf, struct ice_info_ctx *ctx);
} ice_devlink_versions[] = {
	fixed(DEVLINK_INFO_VERSION_GENERIC_BOARD_ID, ice_info_pba),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_MGMT, ice_info_fw_mgmt),
	running("fw.mgmt.api", ice_info_fw_api),
	running("fw.mgmt.build", ice_info_fw_build),
	combined("fw.mgmt.srev", ice_info_fw_srev, ice_info_pending_fw_srev),
	combined(DEVLINK_INFO_VERSION_GENERIC_FW_UNDI,
		 ice_info_orom_ver, ice_info_pending_orom_ver),
	combined("fw.undi.srev", ice_info_orom_srev,
		 ice_info_pending_orom_srev),
	combined("fw.psid.api", ice_info_nvm_ver, ice_info_pending_nvm_ver),
	combined(DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID,
		 ice_info_eetrack, ice_info_pending_eetrack),
	running("fw.app.name", ice_info_ddp_pkg_name),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_APP, ice_info_ddp_pkg_version),
	running("fw.app.bundle_id", ice_info_ddp_pkg_bundle_id),
	combined("fw.netlist", ice_info_netlist_ver,
		 ice_info_pending_netlist_ver),
	combined("fw.netlist.build", ice_info_netlist_build,
		 ice_info_pending_netlist_build),
};

/**
 * ice_devlink_info_get - .info_get devlink handler
 * @devlink: devlink instance structure
 * @req: the devlink info request
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .info_get operation. Reports information about the
 * device.
 *
 * Return: zero on success or an error code on failure.
 */
static int ice_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_info_ctx *ctx;
	size_t i;
	int err;

	if (ice_get_fw_mode(hw) == ICE_FW_MODE_REC) {
		NL_SET_ERR_MSG_MOD(extack, "Device firmware is in recovery mode. Unable to collect version info.");
		return -EOPNOTSUPP;
	}

	err = ice_wait_for_reset(pf, 10 * HZ);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Device is busy resetting");
		return err;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	/* discover capabilities first */
	err = ice_discover_dev_caps(hw, &ctx->dev_caps);
	if (err) {
		dev_dbg(dev, "Failed to discover device capabilities, status %d aq_err %s\n",
			err, ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Unable to discover device capabilities");
		goto out_free_ctx;
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom) {
		err = ice_get_inactive_orom_ver(hw, &ctx->pending_orom);
		if (err) {
			dev_dbg(dev, "Unable to read inactive Option ROM version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_orom = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm) {
		err = ice_get_inactive_nvm_ver(hw, &ctx->pending_nvm);
		if (err) {
			dev_dbg(dev, "Unable to read inactive NVM version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_nvm = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist) {
		err = ice_get_inactive_netlist_ver(hw, &ctx->pending_netlist);
		if (err) {
			dev_dbg(dev, "Unable to read inactive Netlist version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_netlist = false;
		}
	}

#ifdef HAVE_DEVLINK_INFO_DRIVER_NAME_PUT
	err = devlink_info_driver_name_put(req, KBUILD_MODNAME);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set driver name");
		goto out_free_ctx;
	}

#endif /* HAVE_DEVLINK_INFO_DRIVER_NAME_PUT */
	ice_info_get_dsn(pf, ctx);

	err = devlink_info_serial_number_put(req, ctx->buf);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set serial number");
		goto out_free_ctx;
	}

	for (i = 0; i < ARRAY_SIZE(ice_devlink_versions); i++) {
		enum ice_version_type type = ice_devlink_versions[i].type;
		const char *key = ice_devlink_versions[i].key;

		memset(ctx->buf, 0, sizeof(ctx->buf));

		ice_devlink_versions[i].getter(pf, ctx);

		/* If the default getter doesn't report a version, use the
		 * fallback function. This is primarily useful in the case of
		 * "stored" versions that want to report the same value as the
		 * running version in the normal case of no pending update.
		 */
		if (ctx->buf[0] == '\0' && ice_devlink_versions[i].fallback)
			ice_devlink_versions[i].fallback(pf, ctx);

		/* Do not report missing versions */
		if (ctx->buf[0] == '\0')
			continue;

		switch (type) {
		case ICE_VERSION_FIXED:
			err = devlink_info_version_fixed_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set fixed version");
				goto out_free_ctx;
			}
			break;
		case ICE_VERSION_RUNNING:
			err = devlink_info_version_running_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set running version");
				goto out_free_ctx;
			}
			break;
		case ICE_VERSION_STORED:
			err = devlink_info_version_stored_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set stored version");
				goto out_free_ctx;
			}
			break;
		}
	}

out_free_ctx:
	kfree(ctx);
	return err;
}
#endif /* HAVE_DEVLINK_INFO_GET */

#ifdef HAVE_DEVLINK_PARAMS
enum ice_devlink_param_id {
	ICE_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV,
	ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV,
	ICE_DEVLINK_PARAM_ID_TX_LOOPBACK,
	ICE_DEVLINK_PARAM_ID_TX_SCHED_LAYERS,
};

/**
 * ice_devlink_minsrev_get - Get the current minimum security revision
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to get
 * @ctx: context to return the parameter value
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_minsrev_get(struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_minsrev_info minsrevs = {};
	int status;

	if (id != ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV &&
	    id != ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV)
		return -EINVAL;

	status = ice_get_nvm_minsrevs(&pf->hw, &minsrevs);
	if (status) {
		dev_warn(dev, "Failed to read minimum security revision data from flash\n");
		return -EIO;
	}

	/* We report zero if the device has not yet had a valid minimum
	 * security revision programmed for the associated module. This makes
	 * sense because it is not possible to have a security revision of
	 * less than zero. Thus, all images will be able to load if the
	 * minimum security revision is zero, the same as the case where the
	 * minimum value is indicated as invalid.
	 */
	switch (id) {
	case ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV:
		if (minsrevs.nvm_valid)
			ctx->val.vu32 = minsrevs.nvm;
		else
			ctx->val.vu32 = 0;
		break;
	case ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV:
		if (minsrevs.orom_valid)
			ctx->val.vu32 = minsrevs.orom;
		else
			ctx->val.vu32 = 0;
		break;
	}

	return 0;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_minsrev_set - Set the minimum security revision
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 * @extack: netlink extended ACK structure
 *
 * Set the minimum security revision value for fw.mgmt or fw.undi. The kernel
 * calls the validate handler before calling this, so we do not need to
 * duplicate those checks here.
 *
 * Returns: zero on success, or an error code on failure.
 */
static int ice_devlink_minsrev_set(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx,
				   struct netlink_ext_ack *extack)
#else
static int
ice_devlink_minsrev_set(struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_minsrev_info minsrevs = {};
	struct ice_aq_task task = {};
	u16 completion_retval;
	int err;

	switch (id) {
	case ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV:
		minsrevs.nvm_valid = true;
		minsrevs.nvm = ctx->val.vu32;
		break;
	case ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV:
		minsrevs.orom_valid = true;
		minsrevs.orom = ctx->val.vu32;
		break;
	default:
		return -EINVAL;
	}

	ice_aq_prep_for_event(pf, &task, ice_aqc_opc_nvm_write_activate);

	err = ice_update_nvm_minsrevs(&pf->hw, &minsrevs);
	if (err) {
		dev_warn(dev, "Failed to update minimum security revision data\n");
		return -EIO;
	}

	/* Wait for FW to finish Dumping the Shadow RAM */
	err = ice_aq_wait_for_event(pf, &task, 3 * HZ);
	if (err) {
		dev_warn(dev, "Timed out waiting for firmware to dump Shadow RAM\n");
		return -ETIMEDOUT;
	}

	completion_retval = le16_to_cpu(task.event.desc.retval);
	if (completion_retval) {
		dev_warn(dev, "Failed to dump Shadow RAM\n");
		return -EIO;
	}

	return 0;
}

/**
 * ice_devlink_minsrev_validate - Validate a minimum security revision update
 * @devlink: unused pointer to devlink instance
 * @id: the parameter ID to validate
 * @val: value to validate
 * @extack: netlink extended ACK structure
 *
 * Check that a proposed update to a minimum security revision field is valid.
 * Each minimum security revision can only be increased, not decreased.
 * Additionally, we verify that the value is never set higher than the
 * security revision of the active flash component.
 *
 * Returns: zero if the value is valid, -ERANGE if it is out of range, and
 * -EINVAL if this function is called with the wrong ID.
 */
static int
ice_devlink_minsrev_validate(struct devlink *devlink, u32 id, union devlink_param_value val,
			     struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_minsrev_info minsrevs = {};
	int status;

	if (id != ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV &&
	    id != ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV)
		return -EINVAL;

	status = ice_get_nvm_minsrevs(&pf->hw, &minsrevs);
	if (status) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to read minimum security revision data from flash");
		return -EIO;
	}

	switch (id) {
	case ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV:
		if (val.vu32 > pf->hw.flash.nvm.srev) {
			NL_SET_ERR_MSG_MOD(extack, "Cannot update fw.mgmt minimum security revision higher than the currently running firmware");
			dev_dbg(dev, "Attempted to set fw.mgmt.minsrev to %u, but running firmware has srev %u\n",
				val.vu32, pf->hw.flash.nvm.srev);
			return -EPERM;
		}

		if (minsrevs.nvm_valid && val.vu32 < minsrevs.nvm) {
			NL_SET_ERR_MSG_MOD(extack, "Cannot lower the minimum security revision for fw.mgmt flash section");
			dev_dbg(dev, "Attempted  to set fw.mgmt.minsrev to %u, but current minsrev is %u\n",
				val.vu32, minsrevs.nvm);
			return -EPERM;
		}
		break;
	case ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV:
		if (val.vu32 > pf->hw.flash.orom.srev) {
			NL_SET_ERR_MSG_MOD(extack, "Cannot update fw.undi minimum security revision higher than the currently running firmware");
			dev_dbg(dev, "Attempted to set fw.undi.minsrev to %u, but running firmware has srev %u\n",
				val.vu32, pf->hw.flash.orom.srev);
			return -EPERM;
		}

		if (minsrevs.orom_valid && val.vu32 < minsrevs.orom) {
			NL_SET_ERR_MSG_MOD(extack, "Cannot lower the minimum security revision for fw.undi flash section");
			dev_dbg(dev, "Attempted  to set fw.undi.minsrev to %u, but current minsrev is %u\n",
				val.vu32, minsrevs.orom);
			return -EPERM;
		}
		break;
	}

	return 0;
}

/**
 * ice_update_tx_topo_user_sel - Save user's preference in flash
 * @pf: pointer to pf structure
 * @layers: value to be saved in flash
 *
 * Variable "layers" defines user's preference about number of layers in Tx
 * Scheduler Topology Tree. This choice should be stored in PFA TLV field
 * and be picked up by driver, next time during init.
 *
 * Return: zero when save was successful, negative values otherwise.
 */
static int ice_update_tx_topo_user_sel(struct ice_pf *pf, int layers)
{
	struct ice_aqc_nvm_tx_topo_user_sel usr_sel = {};
	struct ice_hw *hw = &pf->hw;
	int err;

	err = ice_acquire_nvm(hw, ICE_RES_WRITE);
	if (err)
		return err;

	err = ice_aq_read_nvm(hw, ICE_AQC_NVM_TX_TOPO_MOD_ID, 0,
			      sizeof(usr_sel), &usr_sel, true, true, NULL);
	if (err)
		goto exit_release_res;

	if (layers == ICE_SCHED_5_LAYERS)
		usr_sel.data |= ICE_AQC_NVM_TX_TOPO_USER_SEL;
	else
		usr_sel.data &= ~ICE_AQC_NVM_TX_TOPO_USER_SEL;

	err = ice_write_one_nvm_block(pf, ICE_AQC_NVM_TX_TOPO_MOD_ID, 2,
				      sizeof(usr_sel.data), &usr_sel.data,
				      true, NULL, NULL);
exit_release_res:
	ice_release_nvm(hw);

	return err;
}

/**
 * ice_devlink_tx_sched_layers_get - Get tx_scheduling_layers parameter
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to store the parameter value
 *
 * Reads user's preference for Tx Scheduler Topology Tree from PFA TLV.
 *
 * Return: zero on success and negative value on failure.
 */
static int ice_devlink_tx_sched_layers_get(struct devlink *devlink,
					   u32 __always_unused id,
					   struct devlink_param_gset_ctx *ctx)
{
	struct ice_aqc_nvm_tx_topo_user_sel usr_sel = {};
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_hw *hw = &pf->hw;
	int err;

	err = ice_acquire_nvm(hw, ICE_RES_READ);
	if (err)
		return err;

	err = ice_aq_read_nvm(hw, ICE_AQC_NVM_TX_TOPO_MOD_ID, 0,
			      sizeof(usr_sel), &usr_sel, true, true, NULL);
	if (err)
		goto exit_release_res;

	if (usr_sel.data & ICE_AQC_NVM_TX_TOPO_USER_SEL)
		ctx->val.vu8 = ICE_SCHED_5_LAYERS;
	else
		ctx->val.vu8 = ICE_SCHED_9_LAYERS;

exit_release_res:
	ice_release_nvm(hw);

	return err;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_tx_sched_layers_set - Set tx_scheduling_layers parameter
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to get the parameter value
 * @extack: netlink extended ACK structure
 *
 * Return: zero on success and negative value on failure.
 */
static int ice_devlink_tx_sched_layers_set(struct devlink *devlink,
					   u32 __always_unused id,
					   struct devlink_param_gset_ctx *ctx,
					   struct netlink_ext_ack *extack)
#else
static int ice_devlink_tx_sched_layers_set(struct devlink *devlink,
					   u32 __always_unused id,
					   struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	struct ice_pf *pf = devlink_priv(devlink);
#ifndef HAVE_DEVLINK_PARAMS_SET_EXTACK
	struct device *dev = ice_pf_to_dev(pf);
#endif /* !HAVE_DEVLINK_PARAMS_SET_EXTACK */
	int err;

	err = ice_update_tx_topo_user_sel(pf, ctx->val.vu8);
	if (err)
		return err;

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
	NL_SET_ERR_MSG_MOD(extack,
			   "Tx scheduling layers have been changed on this device. You must do the PCI slot powercycle for the change to take effect.");
#else
	dev_err(dev,
		"Tx scheduling layers have been changed on this device. You must do the PCI slot powercycle for the change to take effect.");
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */

	return 0;
}

/**
 * ice_devlink_tx_sched_layers_validate - Validate passed txbalance parameter
 *                                        value
 * @devlink: unused pointer to devlink instance
 * @id: the parameter ID to validate
 * @val: value to validate
 * @extack: netlink extended ACK structure
 *
 * Supported values are:
 * true - five layer, false - nine layer Tx Scheduler Topology Tree
 *
 * Returns zero when passed parameter value is supported. Negative value on
 * error.
 */
static int ice_devlink_tx_sched_layers_validate(struct devlink *devlink,
						u32 __always_unused id,
						union devlink_param_value val,
						struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_hw *hw = &pf->hw;

	if (!hw->func_caps.common_cap.tx_sched_topo_comp_mode_en) {
		NL_SET_ERR_MSG_MOD(extack, "Error: Requested feature is not supported by the FW on this device. Update the FW and run this command again.");
		return -EOPNOTSUPP;
	}

	return 0;
}

#define DEVLINK_LPBK_DISABLED "disabled"
#define DEVLINK_LPBK_ENABLED "enabled"
#define DEVLINK_LPBK_PRIORITIZED "prioritized"

/**
 * ice_devlink_loopback_mode_to_str - Get string for lpbk mode
 * @loopback_mode: loopback_mode used in port_info struct
 *
 * Returns mode respective string or "Invalid".
 */
static const char *ice_devlink_loopback_mode_to_str(u32 loopback_mode)
{
	switch (loopback_mode) {
	case ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_NORMAL:
		return DEVLINK_LPBK_ENABLED;
	case ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_HIGH:
		return DEVLINK_LPBK_PRIORITIZED;
	case ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_NO:
		return DEVLINK_LPBK_DISABLED;
	}

	return "Invalid mode";
}

/**
 * ice_devlink_loopback_str_to_mode - Get lpbk mode from string name
 * @mode_str: loopback mode string
 *
 * Returns mode value or -1 if invalid.
 */
static int ice_devlink_loopback_str_to_mode(const char *mode_str)
{
	if (!strcmp(mode_str, DEVLINK_LPBK_ENABLED))
		return ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_NORMAL;
	else if (!strcmp(mode_str, DEVLINK_LPBK_PRIORITIZED))
		return ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_HIGH;
	else if (!strcmp(mode_str, DEVLINK_LPBK_DISABLED))
		return ICE_AQC_SET_P_PARAMS_LOOPBACK_MODE_NO;

	return -EINVAL;
}

/**
 * ice_devlink_loopback_get - Get loopback parameter
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to store the parameter value
 *
 * Returns zero on success.
 */
static int ice_devlink_loopback_get(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_port_info *pi = pf->hw.port_info;
	const char *mode_str;

	mode_str = ice_devlink_loopback_mode_to_str(pi->loopback_mode);
	snprintf(ctx->val.vstr, sizeof(ctx->val.vstr), "%s", mode_str);

	return 0;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_loopback_set - Set loopback parameter
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to get the parameter value
 * @extack: netlink extended ACK structure
 *
 * Returns zero on success.
 */
static int ice_devlink_loopback_set(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx,
				    struct netlink_ext_ack *extack)
#else
static int ice_devlink_loopback_set(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	int new_loopback_mode = ice_devlink_loopback_str_to_mode(ctx->val.vstr);
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_port_info *pi = pf->hw.port_info;
	struct device *dev = ice_pf_to_dev(pf);

	if (pi->loopback_mode != new_loopback_mode) {
		pi->loopback_mode = new_loopback_mode;
		dev_info(dev, "Setting loopback to %s\n", ctx->val.vstr);
		ice_schedule_reset(pf, ICE_RESET_CORER);
	}

	return 0;
}

/**
 * ice_devlink_loopback_validate - Validate passed loopback parameter value
 * @devlink: unused pointer to devlink instance
 * @id: the parameter ID to validate
 * @val: value to validate
 * @extack: netlink extended ACK structure
 *
 * Supported values are:
 * "enabled" - loopback is enabled, "disabled" - loopback is disabled
 * "prioritized" - loopback traffic is prioritized in scheduling
 *
 * Returns zero when passed parameter value is supported. Negative value on
 * error.
 */
static int ice_devlink_loopback_validate(struct devlink *devlink, u32 id,
					 union devlink_param_value val,
					 struct netlink_ext_ack *extack)
{
	if (ice_devlink_loopback_str_to_mode(val.vstr) < 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Error: Requested value is not supported.");
		return -EINVAL;
	}

	return 0;
}

/* devlink parameters for the ice driver */
static const struct devlink_param ice_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV,
			     "fw.mgmt.minsrev",
			     DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     ice_devlink_minsrev_get,
			     ice_devlink_minsrev_set,
			     ice_devlink_minsrev_validate),
	DEVLINK_PARAM_DRIVER(ICE_DEVLINK_PARAM_ID_FW_UNDI_MINSREV,
			     "fw.undi.minsrev",
			     DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     ice_devlink_minsrev_get,
			     ice_devlink_minsrev_set,
			     ice_devlink_minsrev_validate),
	DEVLINK_PARAM_DRIVER(ICE_DEVLINK_PARAM_ID_TX_LOOPBACK,
			     "loopback",
			     DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     ice_devlink_loopback_get,
			     ice_devlink_loopback_set,
			     ice_devlink_loopback_validate),
};

static const struct devlink_param ice_dvl_sched_params[] = {
	DEVLINK_PARAM_DRIVER(ICE_DEVLINK_PARAM_ID_TX_SCHED_LAYERS,
			     "tx_scheduling_layers",
			     DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     ice_devlink_tx_sched_layers_get,
			     ice_devlink_tx_sched_layers_set,
			     ice_devlink_tx_sched_layers_validate),
};
#endif /* HAVE_DEVLINK_PARAMS */

#ifdef HAVE_DEVLINK_FLASH_UPDATE
#ifdef HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY
/**
 * ice_devlink_flash_update_notify_compat - Compatibility for begin/end notify
 * @devlink: pointer to the devlink instance for this device
 * @params: flash update parameters
 * @extack: netlink extended ACK message structure
 *
 * Compatibility wrapper which handles calling
 * devlink_flash_update_begin_notify and devlink_flash_update_end_notify when
 * the kernel does not do this for us.
 */
static int
ice_devlink_flash_update_notify_compat(struct devlink *devlink,
				       struct devlink_flash_update_params *params,
				       struct netlink_ext_ack *extack)
{
	int err;

	devlink_flash_update_begin_notify(devlink);
	err = ice_flash_pldm_image(devlink, params, extack);
	devlink_flash_update_end_notify(devlink);

	return err;
}
#endif /* HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY */

#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
/**
 * ice_devlink_flash_update_params_compat - Compatibility for params argument
 * @devlink: pointer to the devlink instance for this device
 * @file_name: the file name to request the firmware from
 * @component: the flash component to update
 * @extack: netlink extended ACK message structure
 *
 * Compatibility wrapper which handles creating the flash update parameters
 * structure for kernels which do not have this structure defined yet.
 */
static int
ice_devlink_flash_update_params_compat(struct devlink *devlink, const char *file_name,
				       const char *component, struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct devlink_flash_update_params params = {};
	struct device *dev = ice_pf_to_dev(pf);
	int ret = 0;

	/* individual component update is not yet supported, and older kernels
	 * did not check this for us.
	 */
	if (component)
		return -EOPNOTSUPP;

	params.file_name = file_name;

#ifdef HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY
	ret = ice_devlink_flash_update_notify_compat(devlink, &params, extack);

	if (ret)
		dev_dbg(dev, "ice_devlink_flash_update_notify_compat() returned %d\n",
			ret);
#else
	ret = ice_flash_pldm_image(devlink, &params, extack);

	if (ret)
		dev_dbg(dev, "ice_flash_pldm_image() returned %d\n", ret);
#endif
	return ret;
}
#endif /* !HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#endif /* HAVE_DEVLINK_FLASH_UPDATE */

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
enum devlink_msix_resource_id {
	/* generic resource for MSIX */
	ICE_DEVL_RES_ID_MSIX = 1,
	ICE_DEVL_RES_ID_MSIX_MISC,
	ICE_DEVL_RES_ID_MSIX_ETH,
	ICE_DEVL_RES_ID_MSIX_VF,
	ICE_DEVL_RES_ID_MSIX_RDMA,
};

#define ICE_DEVL_RES_NAME_MSIX "msix"
#define ICE_DEVL_RES_NAME_MSIX_MISC "msix_misc"
#define ICE_DEVL_RES_NAME_MSIX_ETH "msix_eth"
#define ICE_DEVL_RES_NAME_MSIX_VF "msix_vf"
#define ICE_DEVL_RES_NAME_MSIX_RDMA "msix_rdma"

static void ice_devlink_read_resources_size(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	u64 size_new;

	devl_resource_size_get(devlink,
			       ICE_DEVL_RES_ID_MSIX_ETH,
			       &size_new);
	pf->req_msix.eth = size_new;

	devl_resource_size_get(devlink,
			       ICE_DEVL_RES_ID_MSIX_VF,
			       &size_new);
	pf->req_msix.vf = size_new;

	devl_resource_size_get(devlink,
			       ICE_DEVL_RES_ID_MSIX_RDMA,
			       &size_new);
	pf->req_msix.rdma = size_new;

	pf->req_msix.all_host = pf->req_msix.eth +
			       pf->req_msix.rdma +
			       pf->req_msix.siov +
			       pf->req_msix.misc;
}

/**
 * ice_devlink_res_msix_pf_occ_get - get occupied MSI-X
 * @priv: void pointer to get PF pointer
 *
 * Return the amount of used MSI-X resources by eth part of the driver.
 */
static u64 ice_devlink_res_msix_pf_occ_get(void *priv)
{
	struct ice_pf *pf = priv;

	return pf->msix.eth;
}

static u64 ice_devlink_res_msix_vf_occ_get(void *priv)
{
	struct ice_pf *pf = priv;

	return ice_sriov_get_vf_used_msix(pf);
}

static u64 ice_devlink_res_msix_rdma_occ_get(void *priv)
{
	struct ice_pf *pf = priv;

	return pf->msix.rdma;
}

static u64 ice_devlink_res_msix_occ_get(void *priv)
{
	struct ice_pf *pf = priv;

	return ice_devlink_res_msix_pf_occ_get(priv) +
	       ice_devlink_res_msix_rdma_occ_get(priv) +
	       ice_devlink_res_msix_vf_occ_get(priv) +
	       pf->msix.misc;
}

int ice_devlink_register_resources(struct ice_pf *pf)
{
	int all = pf->hw.func_caps.common_cap.num_msix_vectors;
	struct devlink *devlink = priv_to_devlink(pf);
	struct devlink_resource_size_params params;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_msix *req = &pf->req_msix;
	int err, max_pf_msix;
	const char *res_name;
	int max_rdma_msix;
	int max_vf_msix;

	max_pf_msix = min_t(int, all, ICE_MAX_LARGE_RSS_QS);
	max_rdma_msix = num_online_cpus() + ICE_RDMA_NUM_AEQ_MSIX;

	devlink_resource_size_params_init(&params, all, all, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);
	res_name = ICE_DEVL_RES_NAME_MSIX;

	err = devl_resource_register(devlink, res_name, all,
				     ICE_DEVL_RES_ID_MSIX,
				     DEVLINK_RESOURCE_ID_PARENT_TOP, &params);
	if (err)
		goto res_create_err;

	devlink_resource_size_params_init(&params, req->misc, req->misc, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);
	res_name = ICE_DEVL_RES_NAME_MSIX_MISC;
	err = devl_resource_register(devlink, res_name, req->misc,
				     ICE_DEVL_RES_ID_MSIX_MISC,
				     ICE_DEVL_RES_ID_MSIX, &params);
	if (err)
		goto res_create_err;

	devlink_resource_size_params_init(&params, ICE_MIN_LAN_MSIX,
					  max_pf_msix, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);
	res_name = ICE_DEVL_RES_NAME_MSIX_ETH;
	err = devl_resource_register(devlink, res_name, req->eth,
				     ICE_DEVL_RES_ID_MSIX_ETH,
				     ICE_DEVL_RES_ID_MSIX, &params);
	if (err)
		goto res_create_err;

	max_vf_msix = all - req->misc - ICE_MIN_LAN_MSIX;
	max_vf_msix -= ICE_MIN_RDMA_MSIX;
	devlink_resource_size_params_init(&params, 0, max_vf_msix, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);

	res_name = ICE_DEVL_RES_NAME_MSIX_VF;
	err = devl_resource_register(devlink, res_name, req->vf,
				     ICE_DEVL_RES_ID_MSIX_VF,
				     ICE_DEVL_RES_ID_MSIX, &params);
	if (err)
		goto res_create_err;

	devlink_resource_size_params_init(&params, ICE_MIN_RDMA_MSIX,
					  max_rdma_msix, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);

	res_name = ICE_DEVL_RES_NAME_MSIX_RDMA;
	err = devl_resource_register(devlink, res_name, req->rdma,
				     ICE_DEVL_RES_ID_MSIX_RDMA,
				     ICE_DEVL_RES_ID_MSIX, &params);
	if (err)
		goto res_create_err;
	devl_resource_occ_get_register(devlink, ICE_DEVL_RES_ID_MSIX,
				       ice_devlink_res_msix_occ_get, pf);

	devl_resource_occ_get_register(devlink, ICE_DEVL_RES_ID_MSIX_ETH,
				       ice_devlink_res_msix_pf_occ_get, pf);

	devl_resource_occ_get_register(devlink, ICE_DEVL_RES_ID_MSIX_VF,
				       ice_devlink_res_msix_vf_occ_get, pf);

	devl_resource_occ_get_register(devlink, ICE_DEVL_RES_ID_MSIX_RDMA,
				       ice_devlink_res_msix_rdma_occ_get, pf);
	return 0;

res_create_err:
	dev_err(dev, "Failed to register devlink resource: %s error: %pe\n",
		res_name, ERR_PTR(err));
	devl_resources_unregister(devlink);

	return err;
}

void ice_devlink_unregister_resources(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devl_resource_occ_get_unregister(devlink, ICE_DEVL_RES_ID_MSIX);
	devl_resource_occ_get_unregister(devlink, ICE_DEVL_RES_ID_MSIX_ETH);
	devl_resource_occ_get_unregister(devlink, ICE_DEVL_RES_ID_MSIX_VF);
	devl_resource_occ_get_unregister(devlink, ICE_DEVL_RES_ID_MSIX_RDMA);
	devl_resources_unregister(devlink);
}

/**
 * ice_devlink_reload_empr_start - Start EMP reset to activate new firmware
 * @pf: pointer to the pf instance
 * @extack: netlink extended ACK structure
 *
 * Allow user to activate new Embedded Management Processor firmware by
 * issuing device specific EMP reset. Called in response to
 * a DEVLINK_CMD_RELOAD with the DEVLINK_RELOAD_ACTION_FW_ACTIVATE.
 *
 * Note that teardown and rebuild of the driver state happens automatically as
 * part of an interrupt and watchdog task. This is because all physical
 * functions on the device must be able to reset when an EMP reset occurs from
 * any source.
 */
static int
ice_devlink_reload_empr_start(struct ice_pf *pf,
			      struct netlink_ext_ack *extack)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 pending;
	int err;

	err = ice_get_pending_updates(pf, &pending, extack);
	if (err)
		return err;

	/* pending is a bitmask of which flash banks have a pending update,
	 * including the main NVM bank, the Option ROM bank, and the netlist
	 * bank. If any of these bits are set, then there is a pending update
	 * waiting to be activated.
	 */
	if (!pending) {
		NL_SET_ERR_MSG_MOD(extack, "No pending firmware update");
		return -ECANCELED;
	}

	if (pf->fw_emp_reset_disabled) {
		NL_SET_ERR_MSG_MOD(extack, "EMP reset is not available. To activate firmware, a reboot or power cycle is needed");
		return -ECANCELED;
	}

	dev_dbg(dev, "Issuing device EMP reset to activate firmware\n");

	err = ice_aq_nvm_update_empr(hw);
	if (err) {
		dev_err(dev, "Failed to trigger EMP device reset to reload firmware, err %d aq_err %s\n",
			err, ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Failed to trigger EMP device reset to reload firmware");
		return err;
	}

	err = wait_event_interruptible_timeout(pf->reset_wait_queue,
					       ice_is_reset_in_progress(pf->state),
					       msecs_to_jiffies(1000));
	if (err <= 0)
		dev_err(dev, "Device has not reached the reset state, err %d\n", err);

	return 0;
}

/**
 * ice_devlink_reload_down - Prepare for reload
 * @devlink: pointer to the devlink instance to reload
 * @netns_change: if true, the network namespace is changing
 * @action: the action to perform. Must be DEVLINK_RELOAD_ACTION_FW_ACTIVATE
 * @limit: limits on what reload should do, such as not resetting
 * @extack: netlink extended ACK structure
 */
static int
ice_devlink_reload_down(struct devlink *devlink, bool netns_change,
			enum devlink_reload_action action,
			enum devlink_reload_limit limit,
			struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *vsi;

	vsi = ice_get_main_vsi(pf);
	vsi->flags |= ICE_VSI_FLAG_RELOAD;

	switch (action) {
	case DEVLINK_RELOAD_ACTION_DRIVER_REINIT:
		if (ice_is_eswitch_mode_switchdev(pf)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Go to legacy mode before doing reinit\n");
			return -EOPNOTSUPP;
		}
		if (ice_is_adq_active(pf)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Turn off ADQ before doing reinit\n");
			return -EOPNOTSUPP;
		}
		if (ice_has_vfs(pf)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Remove all VFs before doing reinit\n");
			return -EOPNOTSUPP;
		}
#ifdef HAVE_NETDEV_UPPER_INFO
		if (pf->lag && pf->lag->bonded) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Remove all associated Bonds before doing reinit\n");
			return -EBUSY;
		}
#endif   /* HAVE_NETDEV_UPPER_INFO */
		ice_unload(pf);
		return 0;
	case DEVLINK_RELOAD_ACTION_FW_ACTIVATE:
		return ice_devlink_reload_empr_start(pf, extack);
	default:
		WARN_ON(1);
		return -EOPNOTSUPP;
	}
}

/**
 * ice_devlink_reload_empr_finish - Wait for EMP reset to finish
 * @pf: pointer to the pf instance
 * @extack: netlink extended ACK structure
 *
 * Wait for driver to finish rebuilding after EMP reset is completed. This
 * includes time to wait for both the actual device reset as well as the time
 * for the driver's rebuild to complete.
 */
static int
ice_devlink_reload_empr_finish(struct ice_pf *pf,
			       struct netlink_ext_ack *extack)
{
	int err;

	err = ice_wait_for_reset(pf, 60 * HZ);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Device still resetting after 1 minute");
		return err;
	}

	return 0;
}

/**
 * ice_devlink_reload_up - do reload up after reinit
 * @devlink: pointer to the devlink instance reloading
 * @action: the action requested
 * @limit: limits imposed by userspace, such as not resetting
 * @actions_performed: on return, indicate what actions actually performed
 * @extack: netlink extended ACK structure
 */
static int
ice_devlink_reload_up(struct devlink *devlink,
		      enum devlink_reload_action action,
		      enum devlink_reload_limit limit,
		      u32 *actions_performed,
		      struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);

	switch (action) {
	case DEVLINK_RELOAD_ACTION_DRIVER_REINIT:
		*actions_performed = BIT(DEVLINK_RELOAD_ACTION_DRIVER_REINIT);
		ice_devlink_read_resources_size(pf);
		return ice_load(pf);
	case DEVLINK_RELOAD_ACTION_FW_ACTIVATE:
		*actions_performed = BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE);
		return ice_devlink_reload_empr_finish(pf, extack);
	default:
		WARN_ON(1);
		return -EOPNOTSUPP;
	}
}
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

#ifdef HAVE_DEVLINK_PORT_SPLIT
static int ice_active_port_option = -1;

/**
 * ice_devlink_port_opt_speed_str - convert speed to a string
 * @speed: speed value
 */
static const char *ice_devlink_port_opt_speed_str(u8 speed)
{
	switch (speed) {
	case ICE_AQC_PORT_OPT_MAX_LANE_100M:
		return "0.1";
	case ICE_AQC_PORT_OPT_MAX_LANE_1G:
		return "1";
	case ICE_AQC_PORT_OPT_MAX_LANE_2500M:
		return "2.5";
	case ICE_AQC_PORT_OPT_MAX_LANE_5G:
		return "5";
	case ICE_AQC_PORT_OPT_MAX_LANE_10G:
		return "10";
	case ICE_AQC_PORT_OPT_MAX_LANE_25G:
		return "25";
	case ICE_AQC_PORT_OPT_MAX_LANE_40G:
		return "40";
	case ICE_AQC_PORT_OPT_MAX_LANE_50G:
		return "50";
	case ICE_AQC_PORT_OPT_MAX_LANE_100G:
		return "100";
	case ICE_AQC_PORT_OPT_MAX_LANE_200G:
		return "200";
	}

	return "-";
}

#define ICE_PORT_OPT_DESC_LEN	50
/**
 * ice_devlink_port_options_print - Print available port split options
 * @pf: the PF to print split port options
 *
 * Prints a table with available port split options and max port speeds
 */
static void ice_devlink_port_options_print(struct ice_pf *pf)
{
	u8 i, j, options_count, cnt, speed, pending_idx, active_idx;
	struct ice_aqc_get_port_options_elem *options, *opt;
	struct device *dev = ice_pf_to_dev(pf);
	bool active_valid, pending_valid;
	char desc[ICE_PORT_OPT_DESC_LEN];
	const char *str;
	int status;

	options = kcalloc(ICE_AQC_PORT_OPT_MAX * ICE_MAX_PORT_PER_PCI_DEV,
			  sizeof(*options), GFP_KERNEL);
	if (!options)
		return;

	for (i = 0; i < ICE_MAX_PORT_PER_PCI_DEV; i++) {
		opt = options + i * ICE_AQC_PORT_OPT_MAX;
		options_count = ICE_AQC_PORT_OPT_MAX;
		active_valid = 0;

		status = ice_aq_get_port_options(&pf->hw, opt, &options_count,
						 i, true, &active_idx,
						 &active_valid, &pending_idx,
						 &pending_valid);
		if (status) {
			dev_dbg(dev, "Couldn't read port option for port %d, err %d\n",
				i, status);
			goto err;
		}
	}

	dev_dbg(dev, "Available port split options and max port speeds (Gbps):\n");
	dev_dbg(dev, "Status  Split      Quad 0          Quad 1\n");
	dev_dbg(dev, "        count  L0  L1  L2  L3  L4  L5  L6  L7\n");

	for (i = 0; i < options_count; i++) {
		cnt = 0;

		if (i == ice_active_port_option)
			str = "Active";
		else if ((i == pending_idx) && pending_valid)
			str = "Pending";
		else
			str = "";

		cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
				"%-8s", str);

		cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
				"%-6u", options[i].pmd);

		for (j = 0; j < ICE_MAX_PORT_PER_PCI_DEV; ++j) {
			speed = options[i + j * ICE_AQC_PORT_OPT_MAX]
					.max_lane_speed;
			str = ice_devlink_port_opt_speed_str(speed);
			cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
					"%3s ", str);
		}

		dev_dbg(dev, "%s\n", desc);
	}

err:
	kfree(options);
}

/**
 * ice_devlink_aq_set_port_option - Send set port option admin queue command
 * @pf: the PF to print split port options
 * @option_idx: selected port option
 * @extack: extended netdev ack structure
 *
 * Sends set port option admin queue command with selected port option and
 * calls NVM write activate.
 */
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
static int
ice_devlink_aq_set_port_option(struct ice_pf *pf, u8 option_idx,
			       struct netlink_ext_ack *extack)
#else
static int
ice_devlink_aq_set_port_option(struct ice_pf *pf, u8 option_idx)
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
{
	struct device *dev = ice_pf_to_dev(pf);
	int status;

	status = ice_aq_set_port_option(&pf->hw, 0, true, option_idx);
	if (status) {
		dev_dbg(dev, "ice_aq_set_port_option, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Port split request failed");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		return -EIO;
	}

	status = ice_acquire_nvm(&pf->hw, ICE_RES_WRITE);
	if (status) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		return -EIO;
	}

	status = ice_nvm_write_activate(&pf->hw, ICE_AQC_NVM_ACTIV_REQ_EMPR,
					NULL);
	if (status) {
		dev_dbg(dev, "ice_nvm_write_activate failed, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Port split request failed to save data");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		ice_release_nvm(&pf->hw);
		return -EIO;
	}

	ice_release_nvm(&pf->hw);

#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
	NL_SET_ERR_MSG_MOD(extack, "Reboot required to finish port split");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
	return 0;
}

/**
 * ice_devlink_port_split - .port_split devlink handler
 * @devlink: devlink instance structure
 * @port: devlink port structure
 * @count: number of ports to split to
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .port_split operation.
 *
 * Unfortunately, the devlink expression of available options is limited
 * to just a number, so search for an FW port option which supports
 * the specified number. As there could be multiple FW port options with
 * the same port split count, allow switching between them. When the same
 * port split count request is issued again, switch to the next FW port
 * option with the same port split count.
 *
 * Return: zero on success or an error code on failure.
 */
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
#ifdef HAVE_DEVLINK_PORT_SPLIT_PORT_STRUCT
static int
ice_devlink_port_split(struct devlink *devlink, struct devlink_port *port,
		       unsigned int count, struct netlink_ext_ack *extack)
#else
static int
ice_devlink_port_split(struct devlink *devlink, unsigned int port_index,
		       unsigned int count, struct netlink_ext_ack *extack)
#endif /* HAVE_DEVLINK_PORT_SPLIT_PORT_STRUCT */
#else
static int
ice_devlink_port_split(struct devlink *devlink, unsigned int port_index,
		       unsigned int count)
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
{
	struct ice_aqc_get_port_options_elem options[ICE_AQC_PORT_OPT_MAX];
	u8 i, j, active_idx, pending_idx, new_option;
	struct ice_pf *pf = devlink_priv(devlink);
	u8 option_count = ICE_AQC_PORT_OPT_MAX;
	struct device *dev = ice_pf_to_dev(pf);
	bool active_valid, pending_valid;
	int status;

	status = ice_aq_get_port_options(&pf->hw, options, &option_count,
					 0, true, &active_idx, &active_valid,
					 &pending_idx, &pending_valid);
	if (status) {
		dev_dbg(dev, "Couldn't read port split options, err = %d\n",
			status);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Failed to get available port split options");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		return -EIO;
	}

	new_option = ICE_AQC_PORT_OPT_MAX;
	active_idx = pending_valid ? pending_idx : active_idx;
	for (i = 1; i <= option_count; i++) {
		/* In order to allow switching between FW port options with
		 * the same port split count, search for a new option starting
		 * from the active/pending option (with array wrap around).
		 */
		j = (active_idx + i) % option_count;

		if (count == options[j].pmd) {
			new_option = j;
			break;
		}
	}

	if (new_option == active_idx) {
		dev_dbg(dev, "request to split: count: %u is already set and there are no other options\n",
			count);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Requested split count is already set");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		ice_devlink_port_options_print(pf);
		return -EINVAL;
	}

	if (new_option == ICE_AQC_PORT_OPT_MAX) {
		dev_dbg(dev, "request to split: count: %u not found\n", count);
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Port split requested unsupported port config");
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
		ice_devlink_port_options_print(pf);
		return -EINVAL;
	}

#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
	status = ice_devlink_aq_set_port_option(pf, new_option, extack);
#else
	status = ice_devlink_aq_set_port_option(pf, new_option);
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */
	if (status)
		return status;

	ice_devlink_port_options_print(pf);

	return 0;
}

/**
 * ice_devlink_port_unsplit - .port_unsplit devlink handler
 * @devlink: devlink instance structure
 * @port: devlink port structure
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .port_unsplit operation.
 * Calls ice_devlink_port_split with split count set to 1.
 * There could be no FW option available with split count 1.
 *
 * Return: zero on success or an error code on failure.
 */
#ifdef HAVE_DEVLINK_PORT_SPLIT_EXTACK
#ifdef HAVE_DEVLINK_PORT_SPLIT_PORT_STRUCT
static int
ice_devlink_port_unsplit(struct devlink *devlink, struct devlink_port *port,
			 struct netlink_ext_ack *extack)
{
	return ice_devlink_port_split(devlink, port, 1, extack);
}
#else
static int
ice_devlink_port_unsplit(struct devlink *devlink, unsigned int port_index,
			 struct netlink_ext_ack *extack)
{
	return ice_devlink_port_split(devlink, port_index, 1, extack);
}
#endif /* HAVE_DEVLINK_PORT_SPLIT_PORT_STRUCT */
#else
static int
ice_devlink_port_unsplit(struct devlink *devlink, unsigned int port_index)
{
	return ice_devlink_port_split(devlink, port_index, 1);
}
#endif /* HAVE_DEVLINK_PORT_SPLIT_EXTACK */

#endif /* HAVE_DEVLINK_PORT_SPLIT */

#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
/**
 * ice_tear_down_devlink_rate_tree - removes devlink-rate exported tree
 * @pf: pf struct
 *
 * This function tears down tree exported during VF's creation.
 */
void ice_tear_down_devlink_rate_tree(struct ice_pf *pf)
{
	struct devlink *devlink;
	struct ice_vf *vf;
	unsigned int bkt;

	devlink = priv_to_devlink(pf);

	mutex_lock(&pf->vfs.table_lock);
	devl_lock(devlink);
	ice_for_each_vf(pf, bkt, vf) {
		if (vf->devlink_port.devlink_rate)
			devl_rate_leaf_destroy(&vf->devlink_port);
	}
	devl_rate_nodes_destroy(devlink);
	devl_unlock(devlink);
	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * ice_enable_custom_tx - try to enable custom Tx feature
 * @pf: pf struct
 *
 * This function tries to enable custom Tx feature,
 * it's not possible to enable it, if DCB or RDMA is active.
 */
static bool ice_enable_custom_tx(struct ice_pf *pf)
{
	struct ice_port_info *pi = ice_get_main_vsi(pf)->port_info;
	struct device *dev = ice_pf_to_dev(pf);
#ifdef CONFIG_PCI_IOV
	struct ice_vf *vf;
	unsigned int bkt;
#endif /* CONFIG_PCI_IOV */

	if (pi->is_custom_tx_enabled)
		/* already enabled, return true */
		return true;

	if (ice_is_dcb_active(pf)) {
		dev_err(dev,
			"Hierarchical QoS configuration is not supported because DCB is configured. Please disable these features and try again\n");
		return false;
	}
	if (ice_is_aux_ena(pf) &&
	    ice_is_rdma_ena(pf) &&
	    ice_is_rdma_aux_loaded(pf)) {
		dev_err(dev,
			"Hierarchical QoS configuration is not supported because RDMA is configured. Please disable these features and try again\n");
		return false;
	}
#ifdef CONFIG_PCI_IOV
	ice_for_each_vf(pf, bkt, vf)
		ice_vc_set_hqos_allowlist(vf);
#endif /* CONFIG_PCI_IOV */

	pi->is_custom_tx_enabled = true;

	return true;
}

/**
 * ice_traverse_tx_tree - traverse Tx scheduler tree
 * @devlink: devlink struct
 * @node: current node, used for recursion
 * @tc_node: tc_node struct, that is treated as a root
 * @pf: pf struct
 *
 * This function traverses Tx scheduler tree and exports
 * entire structure to the devlink-rate.
 */
static void ice_traverse_tx_tree(struct devlink *devlink, struct ice_sched_node *node,
				 struct ice_sched_node *tc_node, struct ice_pf *pf)
{
	struct devlink_rate *rate_node = NULL;
	struct ice_vf *vf;
	int i;

	if (node->rate_node)
		/* already added, skip to the next */
		goto traverse_children;

	if (node->parent == tc_node) {
		/* create root node */
		rate_node = devl_rate_node_create(devlink, node, node->name, NULL);
	} else if (node->vsi_handle &&
		   pf->vsi[node->vsi_handle]->vf) {
		vf = pf->vsi[node->vsi_handle]->vf;
		if (!vf->devlink_port.devlink_rate)
			/* leaf nodes doesn't have children
			 * so we don't set rate_node
			 */
			devl_rate_leaf_create(&vf->devlink_port, node,
					      node->parent->rate_node);
	} else if (node->info.data.elem_type != ICE_AQC_ELEM_TYPE_LEAF &&
		   node->parent->rate_node) {
		rate_node = devl_rate_node_create(devlink, node, node->name,
						  node->parent->rate_node);
	}

	if (rate_node && !IS_ERR(rate_node))
		node->rate_node = rate_node;

traverse_children:
	for (i = 0; i < node->num_children; i++)
		ice_traverse_tx_tree(devlink, node->children[i], tc_node, pf);
}

/**
 * ice_devlink_rate_init_tx_topology - export Tx scheduler tree to devlink rate
 * @devlink: devlink struct
 * @vsi: main vsi struct
 *
 * This function finds a root node, then calls ice_traverse_tx tree, which
 * traverses the tree and exports it's contents to devlink rate.
 */
int ice_devlink_rate_init_tx_topology(struct devlink *devlink, struct ice_vsi *vsi)
{
	struct ice_port_info *pi = vsi->port_info;
	struct ice_sched_node *tc_node;
	struct ice_pf *pf = vsi->back;
	int i;

	tc_node = pi->root->children[0];
	mutex_lock(&pi->sched_lock);
	devl_lock(devlink);
	for (i = 0; i < tc_node->num_children; i++)
		ice_traverse_tx_tree(devlink, tc_node->children[i], tc_node, pf);
	devl_unlock(devlink);
	mutex_unlock(&pi->sched_lock);

	return 0;
}

static void ice_clear_rate_nodes(struct ice_sched_node *node)
{
	node->rate_node = NULL;

	for (int i = 0; i < node->num_children; i++)
		ice_clear_rate_nodes(node->children[i]);
}

/**
 * ice_devlink_rate_clear_tx_topology - clear node->rate_node
 * @vsi: main vsi struct
 *
 * Clear rate_node to cleanup creation of Tx topology.
 */
void ice_devlink_rate_clear_tx_topology(struct ice_vsi *vsi)
{
	struct ice_port_info *pi = vsi->port_info;

	mutex_lock(&pi->sched_lock);
	ice_clear_rate_nodes(pi->root->children[0]);
	mutex_unlock(&pi->sched_lock);
}

/**
 * ice_set_object_tx_share - sets node scheduling parameter
 * @pi: devlink struct instance
 * @node: node struct instance
 * @bw: bandwidth in bytes per second
 * @extack: extended netdev ack structure
 *
 * This function sets ICE_MIN_BW scheduling BW limit.
 */
static int ice_set_object_tx_share(struct ice_port_info *pi, struct ice_sched_node *node,
				   u64 bw, struct netlink_ext_ack *extack)
{
	int status;

	mutex_lock(&pi->sched_lock);
	/* converts bytes per second to kilo bits per second */
	node->tx_share = div_u64(bw, 125);
	status = ice_sched_set_node_bw_lmt(pi, node, ICE_MIN_BW, node->tx_share);
	mutex_unlock(&pi->sched_lock);

	if (status)
		NL_SET_ERR_MSG_MOD(extack, "Can't set scheduling node tx_share");

	return status;
}

/**
 * ice_set_object_tx_max - sets node scheduling parameter
 * @pi: devlink struct instance
 * @node: node struct instance
 * @bw: bandwidth in bytes per second
 * @extack: extended netdev ack structure
 *
 * This function sets ICE_MAX_BW scheduling BW limit.
 */
static int ice_set_object_tx_max(struct ice_port_info *pi, struct ice_sched_node *node,
				 u64 bw, struct netlink_ext_ack *extack)
{
	int status;

	mutex_lock(&pi->sched_lock);
	/* converts bytes per second value to kilo bits per second */
	node->tx_max = div_u64(bw, 125);
	status = ice_sched_set_node_bw_lmt(pi, node, ICE_MAX_BW, node->tx_max);
	mutex_unlock(&pi->sched_lock);

	if (status)
		NL_SET_ERR_MSG_MOD(extack, "Can't set scheduling node tx_max");

	return status;
}

/**
 * ice_set_object_tx_priority - sets node scheduling parameter
 * @pi: devlink struct instance
 * @node: node struct instance
 * @priority: value representing priority for strict priority arbitration
 * @extack: extended netdev ack structure
 *
 * This function sets priority of node among siblings.
 */
static int ice_set_object_tx_priority(struct ice_port_info *pi, struct ice_sched_node *node,
				      u32 priority, struct netlink_ext_ack *extack)
{
	int status;

	if (priority >= 8) {
		NL_SET_ERR_MSG_MOD(extack, "Priority should be less than 8");
		return -EINVAL;
	}

	mutex_lock(&pi->sched_lock);
	node->tx_priority = priority;
	status = ice_sched_set_node_priority(pi, node, node->tx_priority);
	mutex_unlock(&pi->sched_lock);

	if (status)
		NL_SET_ERR_MSG_MOD(extack, "Can't set scheduling node tx_priority");

	return status;
}

/**
 * ice_set_object_tx_weight - sets node scheduling parameter
 * @pi: devlink struct instance
 * @node: node struct instance
 * @weight: value represeting relative weight for WFQ arbitration
 * @extack: extended netdev ack structure
 *
 * This function sets node weight for WFQ algorithm.
 */
static int ice_set_object_tx_weight(struct ice_port_info *pi, struct ice_sched_node *node,
				    u32 weight, struct netlink_ext_ack *extack)
{
	int status;

	if (weight > 200 || weight < 1) {
		NL_SET_ERR_MSG_MOD(extack, "Weight must be between 1 and 200");
		return -EINVAL;
	}

	mutex_lock(&pi->sched_lock);
	node->tx_weight = weight;
	status = ice_sched_set_node_weight(pi, node, node->tx_weight);
	mutex_unlock(&pi->sched_lock);

	if (status)
		NL_SET_ERR_MSG_MOD(extack, "Can't set scheduling node tx_weight");

	return status;
}

/**
 * ice_get_pi_from_dev_rate - get port info from devlink_rate
 * @rate_node: devlink struct instance
 *
 * This function returns corresponding port_info struct of devlink_rate
 */
static struct ice_port_info *ice_get_pi_from_dev_rate(struct devlink_rate *rate_node)
{
	struct ice_pf *pf = devlink_priv(rate_node->devlink);

	return ice_get_main_vsi(pf)->port_info;
}

static int ice_devlink_rate_node_new(struct devlink_rate *rate_node, void **priv,
				     struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node;
	struct ice_port_info *pi;

	pi = ice_get_pi_from_dev_rate(rate_node);

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	/* preallocate memory for ice_sched_node */
	node = devm_kzalloc(ice_hw_to_dev(pi->hw), sizeof(*node), GFP_KERNEL);
	if (!node) {
		NL_SET_ERR_MSG_MOD(extack, "Not enough memory to allocate new node");
		return -ENOMEM;
	}

	*priv = node;

	return 0;
}

static int ice_devlink_rate_node_del(struct devlink_rate *rate_node, void *priv,
				     struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node, *tc_node;
	struct ice_port_info *pi;

	pi = ice_get_pi_from_dev_rate(rate_node);
	tc_node = pi->root->children[0];
	node = priv;

	if (!rate_node->parent || !node || tc_node == node || !extack)
		return 0;

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	/* can't allow to delete a node with children */
	if (node->num_children)
		return -EINVAL;

	mutex_lock(&pi->sched_lock);
	ice_free_sched_node(pi, node);
	mutex_unlock(&pi->sched_lock);

	return 0;
}

static int ice_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_max, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_leaf->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_max(ice_get_pi_from_dev_rate(rate_leaf),
				     node, tx_max, extack);
}

static int ice_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					      u64 tx_share, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_leaf->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_share(ice_get_pi_from_dev_rate(rate_leaf), node,
				       tx_share, extack);
}

static int ice_devlink_rate_leaf_tx_priority_set(struct devlink_rate *rate_leaf, void *priv,
						 u32 tx_priority, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_leaf->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_priority(ice_get_pi_from_dev_rate(rate_leaf), node,
					  tx_priority, extack);
}

static int ice_devlink_rate_leaf_tx_weight_set(struct devlink_rate *rate_leaf, void *priv,
					       u32 tx_weight, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_leaf->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_weight(ice_get_pi_from_dev_rate(rate_leaf), node,
					tx_weight, extack);
}

static int ice_devlink_rate_node_tx_max_set(struct devlink_rate *rate_node, void *priv,
					    u64 tx_max, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_max(ice_get_pi_from_dev_rate(rate_node),
				     node, tx_max, extack);
}

static int ice_devlink_rate_node_tx_share_set(struct devlink_rate *rate_node, void *priv,
					      u64 tx_share, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_share(ice_get_pi_from_dev_rate(rate_node),
				       node, tx_share, extack);
}

static int ice_devlink_rate_node_tx_priority_set(struct devlink_rate *rate_node, void *priv,
						 u32 tx_priority, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_priority(ice_get_pi_from_dev_rate(rate_node),
					  node, tx_priority, extack);
}

static int ice_devlink_rate_node_tx_weight_set(struct devlink_rate *rate_node, void *priv,
					       u32 tx_weight, struct netlink_ext_ack *extack)
{
	struct ice_sched_node *node = priv;

	if (!ice_enable_custom_tx(devlink_priv(rate_node->devlink)))
		return -EBUSY;

	if (!node)
		return 0;

	return ice_set_object_tx_weight(ice_get_pi_from_dev_rate(rate_node),
					node, tx_weight, extack);
}

static int ice_devlink_set_parent(struct devlink_rate *devlink_rate,
				  struct devlink_rate *parent,
				  void *priv, void *parent_priv,
				  struct netlink_ext_ack *extack)
{
	struct ice_port_info *pi = ice_get_pi_from_dev_rate(devlink_rate);
	struct ice_sched_node *tc_node, *node, *parent_node;
	u16 num_nodes_added;
	u32 first_node_teid;
	u32 node_teid;
	int status;

	tc_node = pi->root->children[0];
	node = priv;

	if (!extack)
		return 0;

	if (!ice_enable_custom_tx(devlink_priv(devlink_rate->devlink)))
		return -EBUSY;

	if (!parent) {
		if (!node || tc_node == node || node->num_children)
			return -EINVAL;

		mutex_lock(&pi->sched_lock);
		ice_free_sched_node(pi, node);
		mutex_unlock(&pi->sched_lock);

		return 0;
	}

	parent_node = parent_priv;

	/* if the node doesn't exist, create it */
	if (!node->parent) {
		mutex_lock(&pi->sched_lock);
		status = ice_sched_add_elems(pi, tc_node, parent_node,
					     parent_node->tx_sched_layer + 1,
					     1, &num_nodes_added, &first_node_teid,
					     &node);
		mutex_unlock(&pi->sched_lock);

		if (status) {
			NL_SET_ERR_MSG_MOD(extack, "Can't add a new node");
			return status;
		}

		if (devlink_rate->tx_share)
			ice_set_object_tx_share(pi, node, devlink_rate->tx_share, extack);
		if (devlink_rate->tx_max)
			ice_set_object_tx_max(pi, node, devlink_rate->tx_max, extack);
		if (devlink_rate->tx_priority)
			ice_set_object_tx_priority(pi, node, devlink_rate->tx_priority, extack);
		if (devlink_rate->tx_weight)
			ice_set_object_tx_weight(pi, node, devlink_rate->tx_weight, extack);
	} else {
		node_teid = le32_to_cpu(node->info.node_teid);
		mutex_lock(&pi->sched_lock);
		status = ice_sched_move_nodes(pi, parent_node, 1, &node_teid);
		mutex_unlock(&pi->sched_lock);

		if (status)
			NL_SET_ERR_MSG_MOD(extack, "Can't move existing node to a new parent");
	}

	return status;
}
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */

#ifdef HAVE_DEVLINK_PORT_OPS
static const struct devlink_port_ops ice_devlink_port_ops = {
#ifdef HAVE_DEVLINK_PORT_SPLIT_IN_PORT_OPS
	.port_split = ice_devlink_port_split,
	.port_unsplit = ice_devlink_port_unsplit,
#endif /* HAVE_DEVLINK_PORT_SPLIT_IN_PORT_OPS */
};
#endif /* HAVE_DEVLINK_PORT_OPS */

static const struct devlink_ops ice_devlink_ops = {
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
#endif /* HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
	.reload_actions = BIT(DEVLINK_RELOAD_ACTION_DRIVER_REINIT) |
			  BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE),
	.reload_down = ice_devlink_reload_down,
	.reload_up = ice_devlink_reload_up,
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
#ifdef HAVE_DEVLINK_PORT_SPLIT_IN_OPS
	.port_split = ice_devlink_port_split,
	.port_unsplit = ice_devlink_port_unsplit,
#endif /* HAVE_DEVLINK_PORT_SPLIT_IN_OPS */
	.eswitch_mode_get = ice_eswitch_mode_get,
	.eswitch_mode_set = ice_eswitch_mode_set,
#ifdef HAVE_DEVLINK_INFO_GET
	.info_get = ice_devlink_info_get,
#endif /* HAVE_DEVLINK_INFO_GET */
#ifdef HAVE_DEVLINK_FLASH_UPDATE
#if !defined(HAVE_DEVLINK_FLASH_UPDATE_PARAMS)
	.flash_update = ice_devlink_flash_update_params_compat,
#elif defined(HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY)
	.flash_update = ice_devlink_flash_update_notify_compat,
#else
	.flash_update = ice_flash_pldm_image,
#endif
#endif /* HAVE_DEVLINK_FLASH_UPDATE */
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	.rate_leaf_tx_share_set = ice_devlink_rate_leaf_tx_share_set,
	.rate_leaf_tx_max_set = ice_devlink_rate_leaf_tx_max_set,
	.rate_leaf_tx_priority_set = ice_devlink_rate_leaf_tx_priority_set,
	.rate_leaf_tx_weight_set = ice_devlink_rate_leaf_tx_weight_set,

	.rate_node_tx_share_set = ice_devlink_rate_node_tx_share_set,
	.rate_node_tx_max_set = ice_devlink_rate_node_tx_max_set,
	.rate_node_tx_priority_set = ice_devlink_rate_node_tx_priority_set,
	.rate_node_tx_weight_set = ice_devlink_rate_node_tx_weight_set,

	.rate_node_new = ice_devlink_rate_node_new,
	.rate_node_del = ice_devlink_rate_node_del,

	.rate_leaf_parent_set = ice_devlink_set_parent,
	.rate_node_parent_set = ice_devlink_set_parent,
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
};

static void ice_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

/**
 * ice_allocate_pf - Allocate devlink and return PF structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
struct ice_pf *ice_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink = devlink_alloc(&ice_devlink_ops, sizeof(struct ice_pf), dev);
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action(dev, ice_devlink_free, devlink)) {
		devlink_free(devlink);
		return NULL;
	}

	return (struct ice_pf *)devlink_priv(devlink);
}

/**
 * ice_devlink_register - Register devlink interface for this PF
 * @pf: the PF to register the devlink for.
 *
 * Register the devlink instance associated with this physical function.
 *
 * Return: zero on success or an error code on failure.
 */
void ice_devlink_register(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

#ifdef HAVE_DEVLINK_SET_FEATURES
	devlink_set_features(devlink, DEVLINK_F_RELOAD);
#endif /* HAVE_DEVLINK_SET_FEATURES */
#ifdef HAVE_DEVLINK_REGISTER_SETS_DEV
	devlink_register(devlink, ice_pf_to_dev(pf));
#else
	devl_register(devlink);
#endif /* HAVE_DEVLINK_REGISTER_SETS_DEV */

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifndef HAVE_DEVLINK_SET_FEATURES
#ifdef HAVE_DEVLINK_RELOAD_ENABLE_DISABLE
	devlink_reload_enable(devlink);
#endif /* HAVE_DEVLINK_RELOAD_ENABLE_DISABLE */
#endif /* !HAVE_DEVLINK_SET_FEATURES */
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
}

/**
 * ice_devlink_unregister - Unregister devlink resources for this PF.
 * @pf: the PF structure to cleanup
 *
 * Releases resources used by devlink and cleans up associated memory.
 */
void ice_devlink_unregister(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifndef HAVE_DEVLINK_SET_FEATURES
#ifdef HAVE_DEVLINK_RELOAD_ENABLE_DISABLE
	devlink_reload_disable(devlink);
#endif /* HAVE_DEVLINK_RELOAD_ENABLE_DISABLE */
#endif /* !HAVE_DEVLINK_SET_FEATURES */
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

	devl_unregister(devlink);
}

/**
 * ice_devlink_register_params - Register devlink parameters for this PF
 * @pf: the PF structure to register
 *
 * Registers the parameters associated with this PF.
 */
int ice_devlink_register_params(struct ice_pf *pf)
{
#ifdef HAVE_DEVLINK_PARAMS
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int err;

	err = devl_params_register(devlink, ice_devlink_params,
				   ARRAY_SIZE(ice_devlink_params));
	if (err) {
		ice_dev_err_errno(dev, err,
				  "devlink params registration failed");
		return err;
	}

	if (hw->func_caps.common_cap.tx_sched_topo_comp_mode_en)
		err = devl_params_register(devlink, ice_dvl_sched_params,
					   ARRAY_SIZE(ice_dvl_sched_params));
	if (err)
		return err;

#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_publish(priv_to_devlink(pf));
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */

#endif /* HAVE_DEVLINK_PARAMS */
	return 0;
}

/**
 * ice_devlink_unregister_params - Unregister devlink parameters for this PF
 * @pf: the PF structure to cleanup
 *
 * Removes the main devlink parameters associated with this PF.
 */
void ice_devlink_unregister_params(struct ice_pf *pf)
{
#ifdef HAVE_DEVLINK_PARAMS
	struct devlink *devlink = priv_to_devlink(pf);
	struct ice_hw *hw = &pf->hw;

#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_unpublish(priv_to_devlink(pf));
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */

	devl_params_unregister(devlink, ice_devlink_params,
			       ARRAY_SIZE(ice_devlink_params));

	if (hw->func_caps.common_cap.tx_sched_topo_comp_mode_en)
		devl_params_unregister(devlink, ice_dvl_sched_params,
				       ARRAY_SIZE(ice_dvl_sched_params));
#endif /* HAVE_DEVLINK_PARAMS */
}

#ifdef HAVE_DEVLINK_PORT_SPLIT
/**
 * ice_devlink_set_port_split_options - Set port split options
 * @pf: the PF to set port split options
 * @attrs: devlink attributes
 *
 * Sets devlink port split options based on available FW port options
 */
static void
ice_devlink_set_port_split_options(struct ice_pf *pf,
				   struct devlink_port_attrs *attrs)
{
	struct ice_aqc_get_port_options_elem options[ICE_AQC_PORT_OPT_MAX];
	u8 i, active_idx, pending_idx, option_count = ICE_AQC_PORT_OPT_MAX;
	bool active_valid, pending_valid;
	int status;

	status = ice_aq_get_port_options(&pf->hw, options, &option_count,
					 0, true, &active_idx, &active_valid,
					 &pending_idx, &pending_valid);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "Couldn't read port split options, err = %d\n",
			status);
		return;
	}

	/* find the biggest available port split count */
	for (i = 0; i < option_count; i++)
		attrs->lanes = max_t(int, attrs->lanes, options[i].pmd);

	attrs->splittable = attrs->lanes ? 1 : 0;
	ice_active_port_option = active_idx;
}

#endif /* HAVE_DEVLINK_PORT_SPLIT */
/**
 * ice_devlink_set_switch_id - Set unical switch id based on pci dsn
 * @pf: the PF to create a devlink port for
 * @ppid: struct with switch id information
 */
static void
ice_devlink_set_switch_id(struct ice_pf *pf, struct netdev_phys_item_id *ppid)
{
	struct pci_dev *pdev = pf->pdev;
	u64 id;

	id = pci_get_dsn(pdev);

	ppid->id_len = sizeof(id);
	put_unaligned_be64(id, &ppid->id);
}

/**
 * ice_devlink_create_pf_port - Create a devlink port for this PF
 * @pf: the PF to create a devlink port for
 *
 * Create and register a devlink_port for this PF.
 *
 * Return: zero on success or an error code on failure.
 */
int ice_devlink_create_pf_port(struct ice_pf *pf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct ice_vsi *vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	devlink_port = &pf->devlink_port;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EIO;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	attrs.phys.port_number = pf->hw.bus.func;

#ifdef HAVE_DEVLINK_PORT_SPLIT
	/* As FW supports only port split options for whole device,
	 * set port split options only for first PF.
	 */
	if (pf->hw.pf_id == 0)
		ice_devlink_set_port_split_options(pf, &attrs);

#endif /* HAVE_DEVLINK_PORT_SPLIT */
	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

#ifdef HAVE_DEVLINK_PORT_OPS
	err = devl_port_register_with_ops(devlink, devlink_port, vsi->idx,
					  &ice_devlink_port_ops);
#else
	err = devl_port_register(devlink, devlink_port, vsi->idx);
#endif
	if (err) {
		ice_dev_err_errno(dev, err,
				  "Failed to create devlink port for PF %d",
				  pf->hw.pf_id);
		return err;
	}

	return 0;
}

/**
 * ice_devlink_destroy_pf_port - Destroy the devlink_port for this PF
 * @pf: the PF to cleanup
 *
 * Unregisters the devlink_port structure associated with this PF.
 */
void ice_devlink_destroy_pf_port(struct ice_pf *pf)
{
	struct devlink_port *devlink_port;

	devlink_port = &pf->devlink_port;

	devlink_port_type_clear(devlink_port);
	devl_port_unregister(devlink_port);
}

#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
/**
 * ice_devlink_create_vf_port - Create a devlink port for this VF
 * @vf: the VF to create a port for
 *
 * Create and register a devlink_port for this VF.
 *
 * Return: zero on success or an error code on failure.
 */
int ice_devlink_create_vf_port(struct ice_vf *vf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	int err;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);
	devlink_port = &vf->devlink_port;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	attrs.pci_vf.pf = pf->hw.bus.func;
	attrs.pci_vf.vf = vf->vf_id;

	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devl_port_register(devlink, devlink_port, vsi->idx);
	if (err) {
		ice_dev_err_errno(dev, err,
				  "Failed to create devlink port for VF %d",
				  vf->vf_id);
		return err;
	}

	return 0;
}

/**
 * ice_devlink_destroy_vf_port - Destroy the devlink_port for this VF
 * @vf: the VF to cleanup
 *
 * Unregisters the devlink_port structure associated with this VF.
 */
void ice_devlink_destroy_vf_port(struct ice_vf *vf)
{
	struct devlink_port *devlink_port;

	devlink_port = &vf->devlink_port;

#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	devl_rate_leaf_destroy(devlink_port);
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
	devlink_port_type_clear(devlink_port);
	devl_port_unregister(devlink_port);
#ifndef HAVE_DEVLINK_PORT_REGISTERED
	devlink_port->devlink = NULL;
#endif /* HAVE_DEVLINK_PORT_REGISTERED */
}
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */

#ifdef HAVE_DEVLINK_REGIONS
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
#define ICE_DEVLINK_READ_BLK_SIZE (1024 * 1024)

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS

/**
 * ice_devlink_nvm_snapshot - Capture a snapshot of the NVM flash contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the nvm-flash devlink region. It captures a snapshot of the full NVM flash
 * contents, including both banks of flash. This snapshot can later be viewed
 * via the devlink-region interface.
 *
 * It captures the flash using the FLASH_ONLY bit set when reading via
 * firmware, so it does not read the current Shadow RAM contents. For that,
 * use the shadow-ram region.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int
ice_devlink_nvm_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
			 const struct devlink_region_ops __always_unused *ops,
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
			 struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 *nvm_data, *tmp, i;
	u32 nvm_size, left;
	s8 num_blks;
	int status;

	status = ice_wait_for_reset(pf, msecs_to_jiffies(10000));
	if (status) {
		dev_dbg(dev, "Device is busy resetting");
		NL_SET_ERR_MSG_MOD(extack, "Device is busy resetting");
		return status;
	}

	nvm_size = hw->flash.flash_size;
	nvm_data = vzalloc(nvm_size);
	if (!nvm_data)
		return -ENOMEM;

	num_blks = DIV_ROUND_UP(nvm_size, ICE_DEVLINK_READ_BLK_SIZE);
	tmp = nvm_data;
	left = nvm_size;

	/* some systems take longer to read the nvm than others which causes the
	 * fw to reclaim the nvm lock before the entire nvm has been read. fix
	 * this by breaking the reads of the nvm into smaller chunks that will
	 * probably not take as long. this has some overhead since we are
	 * increasing the number of AQ commands, but it should always work
	 */
	for (i = 0; i < num_blks; i++) {
		u32 read_sz = min_t(u32, ICE_DEVLINK_READ_BLK_SIZE, left);

		status = ice_acquire_nvm(hw, ICE_RES_READ);
		if (status) {
			dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
				status, hw->adminq.sq_last_status);
			NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
			vfree(nvm_data);
			return -EIO;
		}

		status = ice_read_flat_nvm(hw, i * ICE_DEVLINK_READ_BLK_SIZE,
					   &read_sz, tmp, false);
		if (status) {
			dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
				read_sz, status, hw->adminq.sq_last_status);
			NL_SET_ERR_MSG_MOD(extack, "Failed to read NVM contents");
			ice_release_nvm(hw);
			vfree(nvm_data);
			return -EIO;
		}

		ice_release_nvm(hw);

		tmp += read_sz;
		left -= read_sz;
	}

	*data = nvm_data;

	return 0;
}

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
/**
 * ice_devlink_sram_snapshot - Capture a snapshot of the Shadow RAM contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the shadow-ram devlink region. It captures a snapshot of the shadow ram
 * contents. This snapshot can later be viewed via the devlink-region
 * interface.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int
ice_devlink_sram_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
			  const struct devlink_region_ops __always_unused *ops,
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
			  struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 *sram_data;
	u32 sram_size;
	int err;

	sram_size = hw->flash.sr_words * 2u;
	sram_data = vzalloc(sram_size);
	if (!sram_data)
		return -ENOMEM;

	err = ice_acquire_nvm(hw, ICE_RES_READ);
	if (err) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			err, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
		vfree(sram_data);
		return err;
	}

	/* Read from the Shadow RAM, rather than directly from NVM */
	err = ice_read_flat_nvm(hw, 0, &sram_size, sram_data, true);
	if (err) {
		dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
			sram_size, err, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to read Shadow RAM contents");
		ice_release_nvm(hw);
		vfree(sram_data);
		return err;
	}

	ice_release_nvm(hw);

	*data = sram_data;

	return 0;
}

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
/**
 * ice_devlink_devcaps_snapshot - Capture snapshot of device capabilities
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the device-caps devlink region. It captures a snapshot of the device
 * capabilities reported by firmware.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int
ice_devlink_devcaps_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
			     const struct devlink_region_ops __always_unused *ops,
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
			     struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	void *devcaps;
	int status;

	devcaps = vzalloc(ICE_AQ_MAX_BUF_LEN);
	if (!devcaps)
		return -ENOMEM;

	status = ice_aq_list_caps(hw, devcaps, ICE_AQ_MAX_BUF_LEN, NULL,
				  ice_aqc_opc_list_dev_caps, NULL);
	if (status) {
		dev_dbg(dev, "ice_aq_list_caps: failed to read device capabilities, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to read device capabilities");
		vfree(devcaps);
		return status;
	}

	*data = devcaps;

	return 0;
}
#endif /* HAVE_DEVLINK_REGION_OPS_SNAPSHOT */

static const struct devlink_region_ops ice_nvm_region_ops = {
	.name = "nvm-flash",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = ice_devlink_nvm_snapshot,
#endif
};

static const struct devlink_region_ops ice_sram_region_ops = {
	.name = "shadow-ram",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = ice_devlink_sram_snapshot,
#endif
};

static const struct devlink_region_ops ice_devcaps_region_ops = {
	.name = "device-caps",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = ice_devlink_devcaps_snapshot,
#endif
};

/**
 * ice_devlink_init_regions - Initialize devlink regions
 * @pf: the PF device structure
 *
 * Create devlink regions used to enable access to dump the contents of the
 * flash memory on the device.
 */
void ice_devlink_init_regions(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = ice_pf_to_dev(pf);
	u64 nvm_size, sram_size;

	nvm_size = pf->hw.flash.flash_size;
	pf->nvm_region = devl_region_create(devlink, &ice_nvm_region_ops, 1,
					    nvm_size);
	if (IS_ERR(pf->nvm_region)) {
		ice_dev_err_errno(dev, PTR_ERR(pf->nvm_region),
				  "failed to create NVM devlink region");
		pf->nvm_region = NULL;
	}

	sram_size = pf->hw.flash.sr_words * 2u;
	pf->sram_region = devl_region_create(devlink, &ice_sram_region_ops, 1,
					     sram_size);
	if (IS_ERR(pf->sram_region)) {
		dev_err(dev, "failed to create shadow-ram devlink region, err %ld\n",
			PTR_ERR(pf->sram_region));
		pf->sram_region = NULL;
	}

	pf->devcaps_region = devl_region_create(devlink,
						&ice_devcaps_region_ops, 10,
						ICE_AQ_MAX_BUF_LEN);
	if (IS_ERR(pf->devcaps_region)) {
		ice_dev_err_errno(dev, PTR_ERR(pf->devcaps_region),
				  "failed to create device-caps devlink region");
		pf->devcaps_region = NULL;
	}
}

/**
 * ice_devlink_destroy_regions - Destroy devlink regions
 * @pf: the PF device structure
 *
 * Remove previously created regions for this PF.
 */
void ice_devlink_destroy_regions(struct ice_pf *pf)
{
	if (pf->nvm_region)
		devl_region_destroy(pf->nvm_region);

	if (pf->sram_region)
		devl_region_destroy(pf->sram_region);

	if (pf->devcaps_region)
		devl_region_destroy(pf->devcaps_region);
}
#endif /* HAVE_DEVLINK_REGIONS */

#ifdef HAVE_DEVLINK_PARAMS
#define ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD	101
#define ICE_DEVLINK_PARAM_ID_TC2_INLINE_FD	102
#define ICE_DEVLINK_PARAM_ID_TC3_INLINE_FD	103
#define ICE_DEVLINK_PARAM_ID_TC4_INLINE_FD	104
#define ICE_DEVLINK_PARAM_ID_TC5_INLINE_FD	105
#define ICE_DEVLINK_PARAM_ID_TC6_INLINE_FD	106
#define ICE_DEVLINK_PARAM_ID_TC7_INLINE_FD	107
#define ICE_DEVLINK_PARAM_ID_TC8_INLINE_FD	108
#define ICE_DEVLINK_PARAM_ID_TC9_INLINE_FD	109
#define ICE_DEVLINK_PARAM_ID_TC10_INLINE_FD	110
#define ICE_DEVLINK_PARAM_ID_TC11_INLINE_FD	111
#define ICE_DEVLINK_PARAM_ID_TC12_INLINE_FD	112
#define ICE_DEVLINK_PARAM_ID_TC13_INLINE_FD	113
#define ICE_DEVLINK_PARAM_ID_TC14_INLINE_FD	114
#define ICE_DEVLINK_PARAM_ID_TC15_INLINE_FD	115

#define ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(num)	(120 + (num))
#define ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(num)	(140 + (num))

/**
 * ice_validate_tc_params_id - Validate devlink tc param id
 * @id: the parameter ID to validate
 * @start_id: start param id
 * @num_params: number of valid params
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_validate_tc_params_id(u32 id, u32 start_id, u8 num_params)
{
	if (id < start_id || id >= start_id + num_params)
		return -EINVAL;

	return 0;
}

/**
 * ice_get_tc_param_ch_vsi - Return channel vsi associated with
 * tc param id
 * @pf: pointer to PF instance
 * @id: the parameter ID to validate
 * @start_id: start param id
 *
 * Returns: ch_vsi on success, or NULL on failure.
 */
static struct ice_vsi *
ice_get_tc_param_ch_vsi(struct ice_pf *pf, u32 id, u32 start_id)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct ice_vsi *ch_vsi;

	if (ice_validate_tc_params_id(id, start_id, vsi->num_tc_devlink_params))
		return NULL;

	ch_vsi = vsi->tc_map_vsi[id - start_id + 1];
	if (!ch_vsi || !ch_vsi->ch)
		return NULL;

	return ch_vsi;
}

/**
 * ice_devlink_tc_inline_fd_get - Get poller timeout value
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to get
 * @ctx: context to return the parameter value
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_inline_fd_get(struct devlink *devlink, u32 id,
			     struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *vsi = pf->vsi[0];
	struct ice_vsi *ch_vsi;
	int err = 0;

	err = ice_validate_tc_params_id(id, ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD,
					vsi->num_tc_devlink_params);
	if (err)
		return err;

	ch_vsi = vsi->tc_map_vsi[id - ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD + 1];
	if (!ch_vsi || !ch_vsi->ch)
		return -EINVAL;

	ctx->val.vbool = ch_vsi->ch->inline_fd;

	return 0;
}

/**
 * ice_devlink_tc_inline_fd_validate - Validate inline_fd setting
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to validate
 * @val: value to be validated
 * @extack: netlink extended ACK structure
 *
 * Validate inline fd
 * Returns: zero on success, or an error code on failure and extack with a
 * reason for failure.
 */
static int
ice_devlink_tc_inline_fd_validate(struct devlink *devlink, u32 id,
				  union devlink_param_value val,
				  struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *vsi = pf->vsi[0];
	struct ice_vsi *ch_vsi;
	int err = 0;

	err = ice_validate_tc_params_id(id, ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD,
					vsi->num_tc_devlink_params);
	if (err)
		return err;

	ch_vsi = vsi->tc_map_vsi[id - ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD + 1];
	if (!ch_vsi || !ch_vsi->ch)
		return -EINVAL;

	return 0;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_tc_inline_fd_set - Enable/Disable inline flow director
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 * @extack: netlink extended ACK structure
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_inline_fd_set(struct devlink *devlink, u32 id,
			     struct devlink_param_gset_ctx *ctx,
			     struct netlink_ext_ack *extack)
#else
static int
ice_devlink_tc_inline_fd_set(struct devlink *devlink, u32 id,
			     struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *vsi = pf->vsi[0];
	struct ice_vsi *ch_vsi;

	ch_vsi = vsi->tc_map_vsi[id - ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD + 1];
	ch_vsi->ch->inline_fd = ctx->val.vbool;

	return 0;
}

/**
 * ice_devlink_tc_qps_per_poller_get - Get the current number of qps per
 * poller for a tc.
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to get
 * @ctx: context to return the parameter value
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_qps_per_poller_get(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(1));
	if (!ch_vsi)
		return -EINVAL;

	ctx->val.vu8 = ch_vsi->ch->qps_per_poller;

	return 0;
}

/**
 * ice_devlink_tc_qps_per_poller_validate - Validate the number of qps
 * per poller.
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to validate
 * @val: value to be validated
 * @extack: netlink extended ACK structure
 *
 * Check that the value passed is less than the max queues in the TC
 * Returns: zero on success, or an error code on failure and extack with a
 * reason for failure.
 */
static int
ice_devlink_tc_qps_per_poller_validate(struct devlink *devlink, u32 id,
				       union devlink_param_value val,
				       struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(1));
	if (!ch_vsi)
		return -EINVAL;

	if (val.vu8 > ch_vsi->ch->num_rxq) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Value cannot be greater than number of queues in TC");
		return -EINVAL;
	}

#ifdef HAVE_XDP_SUPPORT
	if (ice_is_xdp_ena_vsi(ice_get_main_vsi(pf))) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot change qps_per_poller when xdp is enabled");
		return -EINVAL;
	}
#endif /* HAVE_XDP_SUPPORT */

	return 0;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_tc_qps_per_poller_set - Set the number of qps per poller
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 * @extack: netlink extended ACK structure
 *
 * Returns: zero on success, or an error code on failure.
 */
static int ice_devlink_tc_qps_per_poller_set(struct devlink *devlink, u32 id,
					     struct devlink_param_gset_ctx *ctx,
					     struct netlink_ext_ack *extack)
#else
static int
ice_devlink_tc_qps_per_poller_set(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(1));
	if (!ch_vsi)
		return -EINVAL;

	ch_vsi->ch->qps_per_poller = ctx->val.vu8;

#ifdef HAVE_XDP_SUPPORT
	ice_ch_vsi_update_ring_vecs(ice_get_main_vsi(pf));
#endif /* HAVE_XDP_SUPPORT */
	return 0;
}

/**
 * ice_devlink_tc_poller_timeout_get - Get poller timeout value
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to get
 * @ctx: context to return the parameter value
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_poller_timeout_get(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(1));
	if (!ch_vsi)
		return -EINVAL;

	ctx->val.vu32 = ch_vsi->ch->poller_timeout;

	return 0;
}

#define MAX_POLLER_TIMEOUT 10000

/**
 * ice_devlink_tc_poller_timeout_validate - Validate the poller timeout
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to validate
 * @val: value to be validated
 * @extack: netlink extended ACK structure
 *
 * Validate poller timeout value
 * Returns: zero on success, or an error code on failure and extack with a
 * reason for failure.
 */
static int
ice_devlink_tc_poller_timeout_validate(struct devlink *devlink, u32 id,
				       union devlink_param_value val,
				       struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(1));
	if (!ch_vsi)
		return -EINVAL;

	if (val.vu32 > MAX_POLLER_TIMEOUT) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Value cannot be greater than 10000 jiffies");
		return -EINVAL;
	}

	return 0;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
/**
 * ice_devlink_tc_poller_timeout_set - Set the poller timeout
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 * @extack: netlink extended ACK structure
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_poller_timeout_set(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx,
				  struct netlink_ext_ack *extack)
#else
static int
ice_devlink_tc_poller_timeout_set(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
#endif /* HAVE_DEVLINK_PARAMS_SET_EXTACK */
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *ch_vsi;

	ch_vsi = ice_get_tc_param_ch_vsi(pf, id,
					 ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(1));
	if (!ch_vsi)
		return -EINVAL;

	ch_vsi->ch->poller_timeout = ctx->val.vu32;

	return 0;
}

#define ICE_DEVLINK_TC_INLINE_FD_PARAM(_id, _name)			\
	DEVLINK_PARAM_DRIVER(_id, _name, DEVLINK_PARAM_TYPE_BOOL,	\
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),		\
			     ice_devlink_tc_inline_fd_get,         \
			     ice_devlink_tc_inline_fd_set,         \
			     ice_devlink_tc_inline_fd_validate)    \

#define ICE_DL_TC_QPS_PER_POLLER_PARAM(_id, _name)			\
	DEVLINK_PARAM_DRIVER(_id, _name, DEVLINK_PARAM_TYPE_U8,		\
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),		\
			     ice_devlink_tc_qps_per_poller_get,		\
			     ice_devlink_tc_qps_per_poller_set,		\
			     ice_devlink_tc_qps_per_poller_validate)	\

#define ICE_DL_TC_POLLER_TIMEOUT_PARAM(_id, _name)			\
	DEVLINK_PARAM_DRIVER(_id, _name, DEVLINK_PARAM_TYPE_U32,	\
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),		\
			     ice_devlink_tc_poller_timeout_get,		\
			     ice_devlink_tc_poller_timeout_set,		\
			     ice_devlink_tc_poller_timeout_validate)	\

static const struct devlink_param ice_devlink_inline_fd_params[] = {
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD,
				       "tc1_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC2_INLINE_FD,
				       "tc2_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC3_INLINE_FD,
				       "tc3_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC4_INLINE_FD,
				       "tc4_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC5_INLINE_FD,
				       "tc5_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC6_INLINE_FD,
				       "tc6_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC7_INLINE_FD,
				       "tc7_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC8_INLINE_FD,
				       "tc8_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC9_INLINE_FD,
				       "tc9_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC10_INLINE_FD,
				       "tc10_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC11_INLINE_FD,
				       "tc11_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC12_INLINE_FD,
				       "tc12_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC13_INLINE_FD,
				       "tc13_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC14_INLINE_FD,
				       "tc14_inline_fd"),
	ICE_DEVLINK_TC_INLINE_FD_PARAM(ICE_DEVLINK_PARAM_ID_TC15_INLINE_FD,
				       "tc15_inline_fd"),
};

static const struct devlink_param ice_devlink_qps_per_poller_params[] = {
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(1),
				       "tc1_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(2),
				       "tc2_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(3),
				       "tc3_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(4),
				       "tc4_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(5),
				       "tc5_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(6),
				       "tc6_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(7),
				       "tc7_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(8),
				       "tc8_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(9),
				       "tc9_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(10),
				       "tc10_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(11),
				       "tc11_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(12),
				       "tc12_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(13),
				       "tc13_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(14),
				       "tc14_qps_per_poller"),
	ICE_DL_TC_QPS_PER_POLLER_PARAM(ICE_DL_PARAM_ID_TC_QPS_PER_POLLER(15),
				       "tc15_qps_per_poller"),
};

static const struct devlink_param ice_devlink_poller_timeout_params[] = {
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(1),
				       "tc1_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(2),
				       "tc2_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(3),
				       "tc3_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(4),
				       "tc4_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(5),
				       "tc5_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(6),
				       "tc6_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(7),
				       "tc7_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(8),
				       "tc8_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(9),
				       "tc9_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(10),
				       "tc10_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(11),
				       "tc11_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(12),
				       "tc12_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(13),
				       "tc13_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(14),
				       "tc14_poller_timeout"),
	ICE_DL_TC_POLLER_TIMEOUT_PARAM(ICE_DL_PARAM_ID_TC_POLLER_TIMEOUT(15),
				       "tc15_poller_timeout"),
};

int ice_devlink_tc_params_register(struct ice_vsi *vsi)
{
	struct devlink *devlink = priv_to_devlink(vsi->back);
	struct device *dev = ice_pf_to_dev(vsi->back);
	int err = 0;

	if (vsi->all_numtc > 1) {
		vsi->num_tc_devlink_params = vsi->all_numtc - 1;
		err = devl_params_register(devlink,
					   ice_devlink_inline_fd_params,
					   vsi->num_tc_devlink_params);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "devlink inline_fd params registration failed");
			return err;
		}

		err = devl_params_register(devlink,
					   ice_devlink_qps_per_poller_params,
					   vsi->num_tc_devlink_params);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "devlink qps_per_poller params registration failed");
			return err;
		}

		err = devl_params_register(devlink,
					   ice_devlink_poller_timeout_params,
					   vsi->num_tc_devlink_params);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "devlink poller_timeout params registration failed");
			return err;
		}
#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
		devlink_params_publish(devlink);
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */
	}

	return err;
}

void ice_devlink_tc_params_unregister(struct ice_vsi *vsi)
{
	struct devlink *devlink = priv_to_devlink(vsi->back);

	if (vsi->num_tc_devlink_params) {
		devl_params_unregister(devlink, ice_devlink_inline_fd_params,
				       vsi->num_tc_devlink_params);
		devl_params_unregister(devlink,
				       ice_devlink_qps_per_poller_params,
				       vsi->num_tc_devlink_params);
		devl_params_unregister(devlink,
				       ice_devlink_poller_timeout_params,
				       vsi->num_tc_devlink_params);
		vsi->num_tc_devlink_params = 0;
	}
}
#endif /* HAVE_DEVLINK_PARAMS */
