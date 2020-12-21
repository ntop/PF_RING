// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_devlink.h"
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

/*
 * The following functions are used to format specific strings for various
 * devlink info versions. The ctx parameter is used to provide the storage
 * buffer, as well as any ancillary information calculated when the info
 * request was made.
 *
 * If a version does not exist, for example a "stored" version that does not
 * exist because no update is pending, the function should leave the buffer in
 * the ctx structure empty and return 0.
 */

static void ice_info_get_dsn(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	u8 dsn[8];

	/* Copy the DSN into an array in Big Endian format */
	put_unaligned_be64(pci_get_dsn(pf->pdev), dsn);

	snprintf(ctx->buf, sizeof(ctx->buf), "%8phD", dsn);
}

static int ice_info_pba(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;
	enum ice_status status;

	status = ice_read_pba_string(hw, (u8 *)ctx->buf, sizeof(ctx->buf));
	if (status)
		return -EIO;

	return 0;
}

static int ice_info_fw_mgmt(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u", hw->fw_maj_ver, hw->fw_min_ver,
		 hw->fw_patch);

	return 0;
}

static int ice_info_fw_api(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u", hw->api_maj_ver, hw->api_min_ver);

	return 0;
}

static int ice_info_fw_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", hw->fw_build);

	return 0;
}

static int ice_info_fw_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u", nvm->srev);

	return 0;
}

static int ice_info_pending_fw_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u", nvm->srev);

	return 0;
}

static int ice_info_orom_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &pf->hw.flash.orom;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u", orom->major, orom->build, orom->patch);

	return 0;
}

static int ice_info_pending_orom_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &ctx->pending_orom;

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
			 orom->major, orom->build, orom->patch);

	return 0;
}

static int ice_info_orom_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &pf->hw.flash.orom;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u", orom->srev);

	return 0;
}

static int ice_info_pending_orom_srev(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &ctx->pending_orom;

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u", orom->srev);

	return 0;
}

static int ice_info_nvm_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x", nvm->major, nvm->minor);

	return 0;
}

static int ice_info_pending_nvm_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x", nvm->major, nvm->minor);

	return 0;
}

static int ice_info_eetrack(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);

	return 0;
}

static int ice_info_pending_eetrack(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);

	return 0;
}

static int ice_info_ddp_pkg_name(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%s", hw->active_pkg_name);

	return 0;
}

static int ice_info_ddp_pkg_version(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_pkg_ver *pkg = &pf->hw.active_pkg_ver;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u.%u", pkg->major, pkg->minor, pkg->update,
		 pkg->draft);

	return 0;
}

static int ice_info_ddp_pkg_bundle_id(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", pf->hw.active_track_id);

	return 0;
}

static int ice_info_netlist_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	/* The netlist versions are BCD formatted */
	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x", netlist->major, netlist->minor,
		 netlist->type >> 16, netlist->type & 0xFFFF, netlist->rev,
		 netlist->cust_ver);

	return 0;
}

static int ice_info_netlist_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);

	return 0;
}

static int ice_info_pending_netlist_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	/* The netlist versions are BCD formatted */
	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x",
			 netlist->major, netlist->minor,
			 netlist->type >> 16, netlist->type & 0xFFFF, netlist->rev,
			 netlist->cust_ver);

	return 0;
}

static int ice_info_pending_netlist_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);

	return 0;
}

#define fixed(key, getter) { ICE_VERSION_FIXED, key, getter }
#define running(key, getter) { ICE_VERSION_RUNNING, key, getter }
#define stored(key, getter) { ICE_VERSION_STORED, key, getter }

enum ice_version_type {
	ICE_VERSION_FIXED,
	ICE_VERSION_RUNNING,
	ICE_VERSION_STORED,
};

static const struct ice_devlink_version {
	enum ice_version_type type;
	const char *key;
	int (*getter)(struct ice_pf *pf, struct ice_info_ctx *ctx);
} ice_devlink_versions[] = {
	fixed(DEVLINK_INFO_VERSION_GENERIC_BOARD_ID, ice_info_pba),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_MGMT, ice_info_fw_mgmt),
	running("fw.mgmt.api", ice_info_fw_api),
	running("fw.mgmt.build", ice_info_fw_build),
	running("fw.mgmt.srev", ice_info_fw_srev),
	stored("fw.mgmt.srev", ice_info_pending_fw_srev),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_UNDI, ice_info_orom_ver),
	stored(DEVLINK_INFO_VERSION_GENERIC_FW_UNDI, ice_info_pending_orom_ver),
	running("fw.undi.srev", ice_info_orom_srev),
	stored("fw.undi.srev", ice_info_pending_orom_srev),
	running("fw.psid.api", ice_info_nvm_ver),
	stored("fw.psid.api", ice_info_pending_nvm_ver),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID, ice_info_eetrack),
	stored(DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID, ice_info_pending_eetrack),
	running("fw.app.name", ice_info_ddp_pkg_name),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_APP, ice_info_ddp_pkg_version),
	running("fw.app.bundle_id", ice_info_ddp_pkg_bundle_id),
	running("fw.netlist", ice_info_netlist_ver),
	stored("fw.netlist", ice_info_pending_netlist_ver),
	running("fw.netlist.build", ice_info_netlist_build),
	stored("fw.netlist.build", ice_info_pending_netlist_build),
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

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	/* discover capabilities first */
	status = ice_discover_dev_caps(hw, &ctx->dev_caps);
	if (status) {
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

		err = ice_devlink_versions[i].getter(pf, ctx);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack, "Unable to obtain version info");
			goto out_free_ctx;
		}

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
/**
 * ice_devlink_flash_update - Update firmware stored in flash on the device
 * @devlink: pointer to devlink associated with device to update
 * @params: flash update parameters
 * @extack: netlink extended ACK structure
 *
 * Perform a device flash update. The bulk of the update logic is contained
 * within the ice_flash_pldm_image function.
 *
 * Returns: zero on success, or an error code on failure.
 */
static int
ice_devlink_flash_update(struct devlink *devlink,
			 struct devlink_flash_update_params *params,
			 struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = &pf->pdev->dev;
	struct ice_hw *hw = &pf->hw;
	const struct firmware *fw;
	u8 preservation;
	int err;

	if (!params->overwrite_mask) {
		/* preserve all settings and identifiers */
		preservation = ICE_AQC_NVM_PRESERVE_ALL;
	} else if (params->overwrite_mask == DEVLINK_FLASH_OVERWRITE_SETTINGS) {
		/* overwrite settings, but preserve the vital device identifiers */
		preservation = ICE_AQC_NVM_PRESERVE_SELECTED;
	} else if (params->overwrite_mask == (DEVLINK_FLASH_OVERWRITE_SETTINGS |
					      DEVLINK_FLASH_OVERWRITE_IDENTIFIERS)) {
		/* overwrite both settings and identifiers, preserve nothing */
		preservation = ICE_AQC_NVM_NO_PRESERVATION;
	} else {
		NL_SET_ERR_MSG_MOD(extack, "Requested overwrite mask is not supported");
		return -EOPNOTSUPP;
	}

	if (!hw->dev_caps.common_cap.nvm_unified_update) {
		NL_SET_ERR_MSG_MOD(extack, "Current firmware does not support unified update");
		return -EOPNOTSUPP;
	}

	err = ice_check_for_pending_update(pf, NULL, extack);
	if (err)
		return err;

	err = request_firmware(&fw, params->file_name, dev);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to read file from disk");
		return err;
	}

	dev_dbg(dev, "Beginning flash update with file '%s'\n", params->file_name);

	devlink_flash_update_begin_notify(devlink);
	devlink_flash_update_status_notify(devlink, "Preparing to flash", NULL, 0, 0);
	err = ice_flash_pldm_image(pf, fw, preservation, extack);
	devlink_flash_update_end_notify(devlink);

	release_firmware(fw);

	return err;
}

#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
static int
ice_devlink_flash_update_compat(struct devlink *devlink, const char *file_name,
				const char *component, struct netlink_ext_ack *extack)
{
	struct devlink_flash_update_params params = {};

	/* individual component update is not yet supported, and older kernels
	 * did not check this for us.
	 */
	if (component)
		return -EOPNOTSUPP;

	params.file_name = file_name;

	return ice_devlink_flash_update(devlink, &params, extack);
}
#endif /* !HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#endif /* HAVE_DEVLINK_FLASH_UPDATE */

static const struct devlink_ops ice_devlink_ops = {
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
#endif /* HAVE_DEVLINK_FLASH_UPDATE_PARAMS */
#ifdef HAVE_DEVLINK_INFO_GET
	.info_get = ice_devlink_info_get,
#endif /* HAVE_DEVLINK_INFO_GET */
#ifdef HAVE_DEVLINK_FLASH_UPDATE
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	.flash_update = ice_devlink_flash_update,
#else
	.flash_update = ice_devlink_flash_update_compat,
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

	devlink = devlink_alloc(&ice_devlink_ops, sizeof(struct ice_pf));
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
int ice_devlink_register(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	err = devlink_register(devlink, dev);
	if (err) {
		dev_err(dev, "devlink registration failed: %d\n", err);
		return err;
	}

#ifdef HAVE_DEVLINK_PARAMS
	err = devlink_params_register(devlink, ice_devlink_params,
				      ARRAY_SIZE(ice_devlink_params));
	if (err) {
		dev_err(dev, "devlink params registration failed: %d\n", err);
		return err;
	}
#endif /* HAVE_DEVLINK_PARAMS */

	return 0;
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

#ifdef HAVE_DEVLINK_PARAMS
	devlink_params_unregister(devlink, ice_devlink_params,
				  ARRAY_SIZE(ice_devlink_params));
#endif /* HAVE_DEVLINK_PARAMS */
	devlink_unregister(devlink);
}

/**
 * ice_devlink_params_publish - Publish parameters to allow user access.
 * @pf: the PF structure pointer
 */
void ice_devlink_params_publish(struct ice_pf __maybe_unused *pf)
{
#ifdef HAVE_DEVLINK_PARAMS
	devlink_params_publish(priv_to_devlink(pf));
#endif
}

/**
 * ice_devlink_params_unpublish - Unpublish parameters to prevent user access.
 * @pf: the PF structure pointer
 */
void ice_devlink_params_unpublish(struct ice_pf __maybe_unused *pf)
{
#ifdef HAVE_DEVLINK_PARAMS
	devlink_params_unpublish(priv_to_devlink(pf));
#endif
}

/**
 * ice_devlink_create_port - Create a devlink port for this VSI
 * @vsi: the VSI to create a port for
 *
 * Create and register a devlink_port for this VSI.
 *
 * Return: zero on success or an error code on failure.
 */
int ice_devlink_create_port(struct ice_vsi *vsi)
{
	struct devlink_port_attrs attrs = {};
	struct devlink *devlink;
	struct device *dev;
	struct ice_pf *pf;
	int err;

	pf = vsi->back;
	dev = ice_pf_to_dev(pf);

	/* Currently we only create devlink_port instances for PF VSIs and
	 * for VF port representors.
	 */
	switch (vsi->type) {
	case ICE_VSI_PF:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		attrs.phys.port_number = vsi->port_info->lport;
		break;
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
	case ICE_VSI_VF:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
		attrs.pci_vf.pf = pf->hw.bus.func;
		attrs.pci_vf.vf = vsi->vf_id;
		break;
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
	default:
		return -EINVAL;
	}
	devlink_port_attrs_set(&vsi->devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, &vsi->devlink_port, vsi->idx);
	if (err) {
		dev_err(dev, "devlink_port_register failed: %d\n", err);
		return err;
	}

	vsi->devlink_port_registered = true;

	return 0;
}

/**
 * ice_devlink_destroy_port - Destroy the devlink_port for this VSI
 * @vsi: the VSI to cleanup
 *
 * Unregisters the devlink_port structure associated with this VSI.
 */
void ice_devlink_destroy_port(struct ice_vsi *vsi)
{
	if (!vsi->devlink_port_registered)
		return;

	devlink_port_type_clear(&vsi->devlink_port);
	devlink_port_unregister(&vsi->devlink_port);

	vsi->devlink_port_registered = false;
}

#ifdef HAVE_DEVLINK_REGIONS
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
/**
 * ice_devlink_nvm_snapshot - Capture a snapshot of the Shadow RAM contents
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
	u8 *nvm_data;
	u32 nvm_size;

	nvm_size = hw->flash.flash_size;
	nvm_data = vzalloc(nvm_size);
	if (!nvm_data)
		return -ENOMEM;

	status = ice_acquire_nvm(hw, ICE_RES_READ);
	if (status) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
		vfree(nvm_data);
		return -EIO;
	}

	status = ice_read_flat_nvm(hw, 0, &nvm_size, nvm_data, false);
	if (status) {
		dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
			nvm_size, status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to read NVM contents");
		ice_release_nvm(hw);
		vfree(nvm_data);
		return -EIO;
	}

	ice_release_nvm(hw);

	*data = nvm_data;

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
	u64 nvm_size;

	nvm_size = pf->hw.flash.flash_size;
	pf->nvm_region = devlink_region_create(devlink, &ice_nvm_region_ops, 1,
					       nvm_size);
	if (IS_ERR(pf->nvm_region)) {
		dev_err(dev, "failed to create NVM devlink region, err %ld\n",
			PTR_ERR(pf->nvm_region));
		pf->nvm_region = NULL;
	}

	pf->devcaps_region = devlink_region_create(devlink,
						   &ice_devcaps_region_ops, 10,
						   ICE_AQ_MAX_BUF_LEN);
	if (IS_ERR(pf->devcaps_region)) {
		dev_err(dev, "failed to create device-caps devlink region, err %ld\n",
			PTR_ERR(pf->devcaps_region));
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

	if (pf->devcaps_region)
		devlink_region_destroy(pf->devcaps_region);
}
#endif /* HAVE_DEVLINK_REGIONS */
