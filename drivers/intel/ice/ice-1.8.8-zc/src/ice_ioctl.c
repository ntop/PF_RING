// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_ioctl.h"
#include "ice_sched.h"
#include "ice_common.h"
#include "ice_sched_cfg.h"
#include "ice_lib.h"

#define ICE_IO_DEVICE_NAME "ice_io"
#define ICE_DEVICE_NAME "ice_dev"
#define ICE_DEVICE_CLASS_NAME "ice_class"

struct ice_cfg_ioctl_table_entry {
	enum ice_ioctl_command cmd;
	ice_ioctl_cb_fn_t cb_fn;
};

static struct class *ice_ioctl_dev_class;
dev_t ice_ioctl_device;

#define ICE_IOCTL_CFG_TEMPLATE(lc_name)					\
static int ice_ioctl_cfg_##lc_name(struct ice_pf *pf,			\
					 unsigned long user_arg,	\
					 u16 size)			\
{									\
	ice_cfg_##lc_name##_data arg;					\
	int ret = 0;							\
									\
	if (size != sizeof(arg)) {					\
		return -EINVAL;						\
	}								\
									\
	if (copy_from_user(&arg,					\
			   (void __user *)user_arg,			\
			   sizeof(arg))) {				\
		return -EFAULT;						\
	}								\
									\
	ret = ice_sched_cfg_##lc_name(pf, &arg);			\
									\
	return ret;							\
}

ICE_IOCTL_CFG_TEMPLATE(set_bw_lmt)
ICE_IOCTL_CFG_TEMPLATE(rm_bw_lmt)
ICE_IOCTL_CFG_TEMPLATE(bw_alloc)
ICE_IOCTL_CFG_TEMPLATE(vf_set_bw_lmt)
ICE_IOCTL_CFG_TEMPLATE(vf_rm_bw_lmt)
ICE_IOCTL_CFG_TEMPLATE(vf_bw_alloc)
ICE_IOCTL_CFG_TEMPLATE(q_set_bw_lmt)
ICE_IOCTL_CFG_TEMPLATE(q_rm_bw_lmt)

static struct ice_cfg_ioctl_table_entry ice_cfg_ioctl_table[] = {
	{.cmd = ICE_QOS_CMD_CFG_TC_BW_LMT,
		.cb_fn = ice_ioctl_cfg_set_bw_lmt},
	{.cmd = ICE_QOS_CMD_CFG_TC_DFLT_LMT,
		.cb_fn = ice_ioctl_cfg_rm_bw_lmt},
	{.cmd = ICE_QOS_CMD_CFG_TC_BW_ALLOC,
		.cb_fn = ice_ioctl_cfg_bw_alloc},
	{.cmd = ICE_QOS_CMD_CFG_VF_BW_LMT,
		.cb_fn = ice_ioctl_cfg_vf_set_bw_lmt},
	{.cmd = ICE_QOS_CMD_CFG_VF_DFLT_LMT,
		.cb_fn = ice_ioctl_cfg_vf_rm_bw_lmt},
	{.cmd = ICE_QOS_CMD_CFG_VF_BW_ALLOC,
		.cb_fn = ice_ioctl_cfg_vf_bw_alloc},
	{.cmd = ICE_QOS_CMD_CFG_Q_BW_LMT,
		.cb_fn = ice_ioctl_cfg_q_set_bw_lmt},
	{.cmd = ICE_QOS_CMD_CFG_Q_DFLT_LMT,
		.cb_fn = ice_ioctl_cfg_q_rm_bw_lmt},
};

/**
 * ice_cdev_ioctl - dispatch IOCTL message
 * @file_hdl: IO file handle
 * @cmd: IOCTL command code to process
 * @arg: argument buffer associated with IOCTL command
 */
static long ice_cdev_ioctl(struct file *file_hdl,
			   unsigned int cmd,
			   unsigned long arg)
{
	struct ice_pf *pf;
	unsigned int cmd_nr = _IOC_NR(cmd);

	if (_IOC_TYPE(cmd) != ICE_SWX_IOC_MAGIC)
		return -ENODEV;

	if (cmd_nr >= NUM_ICE_QOS_CMD)
		return -EINVAL;

	pf = container_of(file_hdl->f_inode->i_cdev, struct ice_pf, ice_cdev);
	if (!pf)
		return -EFAULT;

	if (ice_is_reset_in_progress(pf->state)) {
		dev_dbg(ice_pf_to_dev(pf),
			"IOCTL ignored as reset is in progress");
		return -EBUSY;
	}

	cmd_nr = array_index_nospec(cmd_nr, NUM_ICE_QOS_CMD);

	if (!ice_cfg_ioctl_table[cmd_nr].cb_fn) {
		dev_err(ice_pf_to_dev(pf),
			"IOCTL command %u has no callback\n", cmd_nr);
		return -EINVAL;
	}

	return ice_cfg_ioctl_table[cmd_nr].cb_fn(pf, arg, _IOC_SIZE(cmd));
}

static const struct file_operations ice_cdev_fops = {
	.owner =   THIS_MODULE,
	.unlocked_ioctl = ice_cdev_ioctl,
};

/**
 * init_ioctl - initialization of IOCTL interface
 * @dev: pointer to dev structure
 * @cdev: pointer to char device struct to be initialized
 */
void init_ioctl(struct device *dev, struct cdev *cdev)
{
	struct device *io_dev;

	if ((alloc_chrdev_region(&ice_ioctl_device,
				 0, 1, ICE_DEVICE_NAME)) < 0) {
		dev_err(dev, "Failed to allocate device region\n");
		return;
	}

	cdev_init(cdev, &ice_cdev_fops);
	cdev->owner = THIS_MODULE;

	if ((cdev_add(cdev, ice_ioctl_device, 1) < 0)) {
		dev_err(dev, "Failed to add the device to the system\n");
		goto err_unroll_reg_chrdev_reg;
	}

	ice_ioctl_dev_class = class_create(THIS_MODULE, ICE_DEVICE_CLASS_NAME);
	if (IS_ERR(ice_ioctl_dev_class)) {
		dev_err(dev, "Failed to create device struct class\n");
		goto err_unroll_cdev_add;
	}

	io_dev = device_create(ice_ioctl_dev_class, NULL,
			       ice_ioctl_device, NULL, ICE_IO_DEVICE_NAME);
	if (IS_ERR(io_dev)) {
		dev_err(dev, "Failed to create IO Device\n");
		goto err_unroll_dev_create;
	}

	return;

err_unroll_dev_create:
	class_destroy(ice_ioctl_dev_class);
err_unroll_cdev_add:
	cdev_del(cdev);
err_unroll_reg_chrdev_reg:
	unregister_chrdev_region(ice_ioctl_device, 1);
}

/**
 * deinit_ioctl - deinit all resources associated with IOCTL interface
 * @cdev: pointer to char device struct
 */
void deinit_ioctl(struct cdev *cdev)
{
	device_destroy(ice_ioctl_dev_class, ice_ioctl_device);
	class_destroy(ice_ioctl_dev_class);
	cdev_del(cdev);
	unregister_chrdev_region(ice_ioctl_device, 1);
}
