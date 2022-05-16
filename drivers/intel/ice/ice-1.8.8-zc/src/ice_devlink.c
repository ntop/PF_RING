// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_devlink.h"
#include "ice_eswitch.h"
#include "ice_fw_update.h"

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
	enum ice_status status;

	status = ice_read_pba_string(hw, (u8 *)ctx->buf, sizeof(ctx->buf));
	if (status)
		/* We failed to locate the PBA, so just skip this entry */
		dev_dbg(ice_pf_to_dev(pf), "Failed to read Product Board Assembly string, status %s\n",
			ice_stat_str(status));
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

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
		 hw->api_maj_ver, hw->api_min_ver, hw->api_patch);
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
	enum ice_status status;
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
	status = ice_discover_dev_caps(hw, &ctx->dev_caps);
	if (status) {
		dev_dbg(dev, "Failed to discover device capabilities, status %s aq_err %s\n",
			ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Unable to discover device capabilities");
		err = -EIO;
		goto out_free_ctx;
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom) {
		status = ice_get_inactive_orom_ver(hw, &ctx->pending_orom);
		if (status) {
			dev_dbg(dev, "Unable to read inactive Option ROM version data, status %s aq_err %s\n",
				ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_orom = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm) {
		status = ice_get_inactive_nvm_ver(hw, &ctx->pending_nvm);
		if (status) {
			dev_dbg(dev, "Unable to read inactive NVM version data, status %s aq_err %s\n",
				ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_nvm = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist) {
		status = ice_get_inactive_netlist_ver(hw, &ctx->pending_netlist);
		if (status) {
			dev_dbg(dev, "Unable to read inactive Netlist version data, status %s aq_err %s\n",
				ice_stat_str(status), ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_netlist = false;
		}
	}

	err = devlink_info_driver_name_put(req, KBUILD_MODNAME);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set driver name");
		goto out_free_ctx;
	}

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
	enum ice_status status;

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

/**
 * ice_devlink_minsrev_set - Set the minimum security revision
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 *
 * Set the minimum security revision value for fw.mgmt or fw.undi. The kernel
 * calls the validate handler before calling this, so we do not need to
 * duplicate those checks here.
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_minsrev_set(struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_minsrev_info minsrevs = {};
	enum ice_status status;

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

	status = ice_update_nvm_minsrevs(&pf->hw, &minsrevs);
	if (status) {
		dev_warn(dev, "Failed to update minimum security revision data\n");
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
	enum ice_status status;

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
	ret = ice_flash_pldm_image(devlink, params, extack);

	if (ret)
		dev_dbg(dev, "ice_flash_pldm_image() returned %d\n", ret);
#endif
	return ret;
}
#endif /* !HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#endif /* HAVE_DEVLINK_FLASH_UPDATE */

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
/**
 * ice_devlink_reload_empr_start - Start EMP reset to activate new firmware
 * @devlink: pointer to the devlink instance to reload
 * @netns_change: if true, the network namespace is changing
 * @action: the action to perform. Must be DEVLINK_RELOAD_ACTION_FW_ACTIVATE
 * @limit: limits on what reload should do, such as not resetting
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
ice_devlink_reload_empr_start(struct devlink *devlink, bool netns_change,
			      enum devlink_reload_action action,
			      enum devlink_reload_limit limit,
			      struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;
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
		NL_SET_ERR_MSG_MOD(extack, "EMP reset is not available. To activate firmware, a reboot or power cycle is needed\n");
		return -ECANCELED;
	}

	dev_dbg(dev, "Issuing device EMP reset to activate firmware\n");

	status = ice_aq_nvm_update_empr(hw);
	if (status) {
		dev_err(dev, "Failed to trigger EMP device reset to reload firmware, err %s aq_err %s\n",
			ice_stat_str(status),
			ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Failed to trigger EMP device reset to reload firmware");
		return -EIO;
	}

	return 0;
}

/**
 * ice_devlink_reload_empr_finish - Wait for EMP reset to finish
 * @devlink: pointer to the devlink instance reloading
 * @action: the action requested
 * @limit: limits imposed by userspace, such as not resetting
 * @actions_performed: on return, indicate what actions actually performed
 * @extack: netlink extended ACK structure
 *
 * Wait for driver to finish rebuilding after EMP reset is completed. This
 * includes time to wait for both the actual device reset as well as the time
 * for the driver's rebuild to complete.
 */
static int
ice_devlink_reload_empr_finish(struct devlink *devlink,
			       enum devlink_reload_action action,
			       enum devlink_reload_limit limit,
			       u32 *actions_performed,
			       struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	int err;

	*actions_performed = BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE);

	/* It can take a while for the device and driver to complete the reset
	 * and rebuild process.
	 */
	err = ice_wait_for_reset(pf, 60 * HZ);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Device still resetting after 1 minute");
		return err;
	}

	return 0;
}
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

static const struct devlink_ops ice_devlink_ops = {
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
#endif /* HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
	.reload_actions = BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE),
	/* The ice driver currently does not support driver reinit */
	.reload_down = ice_devlink_reload_empr_start,
	.reload_up = ice_devlink_reload_empr_finish,
#endif
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

	return devlink_priv(devlink);
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
	devlink_register(devlink);
#endif

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifndef HAVE_DEVLINK_SET_FEATURES
	devlink_reload_enable(devlink);
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
	devlink_reload_disable(devlink);
#endif /* !HAVE_DEVLINK_SET_FEATURES */
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

	devlink_unregister(devlink);
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
	int err;

	err = devlink_params_register(devlink, ice_devlink_params,
				      ARRAY_SIZE(ice_devlink_params));
	if (err) {
		ice_dev_err_errno(dev, err,
				  "devlink params registration failed");
		return err;
	}

#ifndef HAVE_DEVLINK_NOTIFY_REGISTER
#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_publish(priv_to_devlink(pf));
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */
#endif /* !HAVE_DEVLINK_NOTIFY_REGISTER */

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

#ifndef HAVE_DEVLINK_NOTIFY_REGISTER
#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_unpublish(priv_to_devlink(pf));
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */
#endif /* !HAVE_DEVLINK_NOTIFY_REGISTER */

	devlink_params_unregister(devlink, ice_devlink_params,
				  ARRAY_SIZE(ice_devlink_params));
#endif /* HAVE_DEVLINK_PARAMS */
}

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

	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
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
	devlink_port_unregister(devlink_port);
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
	vsi = ice_get_vf_vsi(vf);
	devlink_port = &vf->devlink_port;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	attrs.pci_vf.pf = pf->hw.bus.func;
	attrs.pci_vf.vf = vf->vf_id;

	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
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

	devlink_port_type_clear(devlink_port);
	devlink_port_unregister(devlink_port);
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
	enum ice_status status;
	u8 *nvm_data, *tmp, i;
	u32 nvm_size, left;
	s8 num_blks;

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
	enum ice_status status;
	u8 *sram_data;
	u32 sram_size;

	sram_size = hw->flash.sr_words * 2u;
	sram_data = vzalloc(sram_size);
	if (!sram_data)
		return -ENOMEM;

	status = ice_acquire_nvm(hw, ICE_RES_READ);
	if (status) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
		vfree(sram_data);
		return -EIO;
	}

	/* Read from the Shadow RAM, rather than directly from NVM */
	status = ice_read_flat_nvm(hw, 0, &sram_size, sram_data, true);
	if (status) {
		dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
			sram_size, status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to read Shadow RAM contents");
		ice_release_nvm(hw);
		vfree(sram_data);
		return -EIO;
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
	enum ice_status status;
	void *devcaps;

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
		return -EIO;
	}

	*data = (u8 *)devcaps;

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
	pf->nvm_region = devlink_region_create(devlink, &ice_nvm_region_ops, 1,
					       nvm_size);
	if (IS_ERR(pf->nvm_region)) {
		ice_dev_err_errno(dev, PTR_ERR(pf->nvm_region),
				  "failed to create NVM devlink region");
		pf->nvm_region = NULL;
	}

	sram_size = pf->hw.flash.sr_words * 2u;
	pf->sram_region = devlink_region_create(devlink, &ice_sram_region_ops,
						1, sram_size);
	if (IS_ERR(pf->sram_region)) {
		dev_err(dev, "failed to create shadow-ram devlink region, err %ld\n",
			PTR_ERR(pf->sram_region));
		pf->sram_region = NULL;
	}

	pf->devcaps_region = devlink_region_create(devlink,
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
		devlink_region_destroy(pf->nvm_region);

	if (pf->sram_region)
		devlink_region_destroy(pf->sram_region);

	if (pf->devcaps_region)
		devlink_region_destroy(pf->devcaps_region);
}
#endif /* HAVE_DEVLINK_REGIONS */

#ifdef HAVE_DEVLINK_HEALTH

#define ICE_MDD_SRC_TO_STR(_src) \
	((_src) == ICE_MDD_SRC_NONE ? "none"		\
	 : (_src) == ICE_MDD_SRC_TX_PQM ? "tx_pqm"	\
	 : (_src) == ICE_MDD_SRC_TX_TCLAN ? "tx_tclan"	\
	 : (_src) == ICE_MDD_SRC_TX_TDPU ? "tx_tdpu"	\
	 : (_src) == ICE_MDD_SRC_RX ? "rx"		\
	 : "invalid")

static int
#ifndef HAVE_DEVLINK_HEALTH_OPS_EXTACK
ice_mdd_reporter_dump(struct devlink_health_reporter *reporter,
		      struct devlink_fmsg *fmsg, void *priv_ctx)
#else
ice_mdd_reporter_dump(struct devlink_health_reporter *reporter,
		      struct devlink_fmsg *fmsg, void *priv_ctx,
		      struct netlink_ext_ack __always_unused *extack)
#endif /* HAVE_DEVLINK_HEALTH_OPS_EXTACK */
{
	struct ice_pf *pf = devlink_health_reporter_priv(reporter);
	struct ice_mdd_reporter *mdd_reporter = &pf->mdd_reporter;
	struct ice_mdd_event *mdd_event;
	int err;

	err = devlink_fmsg_u32_pair_put(fmsg, "count",
					mdd_reporter->count);
	if (err)
		return err;

	list_for_each_entry(mdd_event, &mdd_reporter->event_list, list) {
		char *src;

		err = devlink_fmsg_obj_nest_start(fmsg);
		if (err)
			return err;

		src = ICE_MDD_SRC_TO_STR(mdd_event->src);

		err = devlink_fmsg_string_pair_put(fmsg, "src", src);
		if (err)
			return err;

		err = devlink_fmsg_u8_pair_put(fmsg, "pf_num",
					       mdd_event->pf_num);
		if (err)
			return err;

		err = devlink_fmsg_u32_pair_put(fmsg, "mdd_vf_num",
						mdd_event->vf_num);
		if (err)
			return err;

		err = devlink_fmsg_u8_pair_put(fmsg, "mdd_event",
					       mdd_event->event);
		if (err)
			return err;

		err = devlink_fmsg_u32_pair_put(fmsg, "mdd_queue",
						mdd_event->queue);
		if (err)
			return err;

		err = devlink_fmsg_obj_nest_end(fmsg);
		if (err)
			return err;
	}

	return 0;
}

static const struct devlink_health_reporter_ops ice_mdd_reporter_ops = {
	.name = "mdd",
	.dump = ice_mdd_reporter_dump,
};

/**
 * ice_devlink_init_mdd_reporter - Initialize MDD devlink health reporter
 * @pf: the PF device structure
 *
 * Create devlink health reporter used to handle MDD events.
 */
void ice_devlink_init_mdd_reporter(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = ice_pf_to_dev(pf);

	INIT_LIST_HEAD(&pf->mdd_reporter.event_list);

	pf->mdd_reporter.reporter =
		devlink_health_reporter_create(devlink,
					       &ice_mdd_reporter_ops,
					       0, /* graceful period */
#ifndef HAVE_DEVLINK_HEALTH_DEFAULT_AUTO_RECOVER
					       false, /* auto recover */
#endif /* HAVE_DEVLINK_HEALTH_DEFAULT_AUTO_RECOVER */
					       pf); /* private data */

	if (IS_ERR(pf->mdd_reporter.reporter)) {
		ice_dev_err_errno(dev, PTR_ERR(pf->mdd_reporter.reporter),
				  "failed to create devlink MDD health reporter");
	}
}

/**
 * ice_devlink_destroy_mdd_reporter - Destroy MDD devlink health reporter
 * @pf: the PF device structure
 *
 * Remove previously created MDD health reporter for this PF.
 */
void ice_devlink_destroy_mdd_reporter(struct ice_pf *pf)
{
	if (pf->mdd_reporter.reporter)
		devlink_health_reporter_destroy(pf->mdd_reporter.reporter);
}

/**
 * ice_devlink_report_mdd_event - Report an MDD event through devlink health
 * @pf: the PF device structure
 * @src: the HW block that was the source of this MDD event
 * @pf_num: the pf_num on which the MDD event occurred
 * @vf_num: the vf_num on which the MDD event occurred
 * @event: the event type of the MDD event
 * @queue: the queue on which the MDD event occurred
 *
 * Report an MDD event that has occurred on this PF.
 */
void
ice_devlink_report_mdd_event(struct ice_pf *pf, enum ice_mdd_src src,
			     u8 pf_num, u16 vf_num, u8 event, u16 queue)
{
	struct ice_mdd_reporter *mdd_reporter = &pf->mdd_reporter;
	struct ice_mdd_event *mdd_event;
	int err;

	if (!mdd_reporter->reporter)
		return;

	mdd_reporter->count++;

	mdd_event = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*mdd_event),
				 GFP_KERNEL);
	if (!mdd_event)
		return;

	mdd_event->src = src;
	mdd_event->pf_num = pf_num;
	mdd_event->vf_num = vf_num;
	mdd_event->event = event;
	mdd_event->queue = queue;

	list_add_tail(&mdd_event->list, &mdd_reporter->event_list);

	err = devlink_health_report(mdd_reporter->reporter,
				    "Malicious Driver Detection event\n",
				    pf);
	if (err)
		dev_err(ice_pf_to_dev(pf),
			"failed to report MDD via devlink health\n");
}

/**
 * ice_devlink_clear_after_reset - clear devlink health issues after a reset
 * @pf: the PF device structure
 *
 * Mark the PF in healthy state again after a reset has completed.
 */
void ice_devlink_clear_after_reset(struct ice_pf *pf)
{
	struct ice_mdd_reporter *mdd_reporter = &pf->mdd_reporter;
	enum devlink_health_reporter_state new_state =
		DEVLINK_HEALTH_REPORTER_STATE_HEALTHY;
	struct ice_mdd_event *mdd_event, *tmp;

	if (!mdd_reporter->reporter)
		return;

	devlink_health_reporter_state_update(mdd_reporter->reporter,
					     new_state);
	pf->mdd_reporter.count = 0;

	list_for_each_entry_safe(mdd_event, tmp, &mdd_reporter->event_list,
				 list) {
		list_del(&mdd_event->list);
	}
}

#endif /* HAVE_DEVLINK_HEALTH */

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

/**
 * ice_devlink_tc_inline_fd_set - Enable/Disable inline flow director
 * @devlink: pointer to the devlink instance
 * @id: the parameter ID to set
 * @ctx: context to return the parameter value
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_tc_inline_fd_set(struct devlink *devlink, u32 id,
			     struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct ice_vsi *vsi = pf->vsi[0];
	struct ice_vsi *ch_vsi;

	ch_vsi = vsi->tc_map_vsi[id - ICE_DEVLINK_PARAM_ID_TC1_INLINE_FD + 1];
	ch_vsi->ch->inline_fd = ctx->val.vbool;

	return 0;
}

#define ICE_DEVLINK_TC_INLINE_FD_PARAM(_id, _name)			\
	DEVLINK_PARAM_DRIVER(_id, _name, DEVLINK_PARAM_TYPE_BOOL,	\
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),		\
			     ice_devlink_tc_inline_fd_get,         \
			     ice_devlink_tc_inline_fd_set,         \
			     ice_devlink_tc_inline_fd_validate)    \

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

int ice_devlink_tc_params_register(struct ice_vsi *vsi)
{
	struct devlink *devlink = priv_to_devlink(vsi->back);
	struct device *dev = ice_pf_to_dev(vsi->back);
	int err = 0;

	if (vsi->all_numtc > 1) {
		vsi->num_tc_devlink_params = vsi->all_numtc - 1;
		err = devlink_params_register(devlink,
					      ice_devlink_inline_fd_params,
					      vsi->num_tc_devlink_params);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "devlink inline_fd params registration failed");
			return err;
		}

#ifndef HAVE_DEVLINK_NOTIFY_REGISTER
#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
		devlink_params_publish(devlink);
#endif /* HAVE_DEVLINK_PARAMS_PUBLISH */
#endif /* !HAVE_DEVLINK_NOTIFY_REGISTER */
	}

	return err;
}

void ice_devlink_tc_params_unregister(struct ice_vsi *vsi)
{
	struct devlink *devlink = priv_to_devlink(vsi->back);

	if (vsi->num_tc_devlink_params) {
		devlink_params_unregister(devlink, ice_devlink_inline_fd_params,
					  vsi->num_tc_devlink_params);
		vsi->num_tc_devlink_params = 0;
	}
}
#endif /* HAVE_DEVLINK_PARAMS */
