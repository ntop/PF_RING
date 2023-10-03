/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>

#include <linux/vfio_pci_core.h>
#include "ice_migration.h"

#define DRIVER_DESC     "ICE VFIO PCI - User Level meta-driver for Intel E800 device family"

#define VFIO_DEVICE_MIGRATION_OFFSET(x) \
	(offsetof(struct vfio_device_migration_info, x))
#define ICE_VFIO_MIG_REGION_INFO_SZ (sizeof(struct vfio_device_migration_info))
#define ICE_VFIO_MIG_REGION_DATA_SZ \
	(struct_size((struct ice_vfio_pci_migration_data *)NULL, \
		      dev_state, SZ_128K))

/* IAVF registers description */
#define IAVF_VF_ARQBAH1 0x00006000 /* Reset: EMPR */
#define IAVF_VF_ATQH1 0x00006400 /* Reset: EMPR */
#define IAVF_VF_ATQLEN1 0x00006800 /* Reset: EMPR */
#define IAVF_VF_ARQBAL1 0x00006C00 /* Reset: EMPR */
#define IAVF_VF_ARQT1 0x00007000   /* Reset: EMPR */
#define IAVF_VF_ARQH1 0x00007400   /* Reset: EMPR */
#define IAVF_VF_ATQBAH1 0x00007800 /* Reset: EMPR */
#define IAVF_VF_ATQBAL1 0x00007C00 /* Reset: EMPR */
#define IAVF_VF_ARQLEN1 0x00008000 /* Reset: EMPR */
#define IAVF_VF_ATQT1 0x00008400   /* Reset: EMPR */
#define IAVF_VFINT_DYN_CTL01 0x00005C00 /* Reset: VFR */
#define IAVF_VFINT_DYN_CTLN1(_INTVF) \
	(0x00003800 + ((_INTVF) * 4)) /* _INTVF=0...16 */ /* Reset: VFR */
#define IAVF_VFINT_DYN_CTLN_NUM 16
#define IAVF_VFINT_ITRN0(_i) \
	(0x00004C00 + (_i) * 4) /* _i=0...2 */ /* Reset: VFR */
#define IAVF_VFINT_ITRN0_NUM 3
#define IAVF_VFINT_ITRN1(_i, _INTVF) (0x00002800 + ((_i) * 64 + (_INTVF) * 4))
	/* _i=0...2, _INTVF=0...15 */ /* Reset: VFR */
#define IAVF_VFINT_ITRN_NUM 3
#define IAVF_QRX_TAIL1(_Q) \
	(0x00002000 + ((_Q) * 4)) /* _Q=0...256 */ /* Reset: CORER */

/* Registers for saving and loading during live Migration */
struct ice_vfio_pci_regs {
	/* VF interrupts */
	u32 int_dyn_ctl0;
	u32 int_dyn_ctln[IAVF_VFINT_DYN_CTLN_NUM];
	u32 int_intr0[IAVF_VFINT_ITRN0_NUM];
	u32 int_intrn[IAVF_VFINT_ITRN_NUM][IAVF_VFINT_DYN_CTLN_NUM];

	/* VF Control Queues */
	u32 asq_bal;
	u32 asq_bah;
	u32 asq_len;
	u32 asq_head;
	u32 asq_tail;
	u32 arq_bal;
	u32 arq_bah;
	u32 arq_len;
	u32 arq_head;
	u32 arq_tail;

	/* VF LAN RX */
	u32 rx_tail[IAVF_QRX_TAIL_MAX];
};

struct ice_vfio_pci_migration_data {
	struct ice_vfio_pci_regs regs;

	u8 __aligned(8) dev_state[];
};

struct ice_vfio_pci_core_device {
	struct vfio_pci_core_device core_device;
	struct vfio_device_migration_info mig_info;
	struct ice_vfio_pci_migration_data *mig_data;
	u8 __iomem *io_base;
	void *vf_handle;
	struct kvm *kvm;
	struct notifier_block group_notifier;
};

/**
 * ice_vfio_pci_save_regs - Save migration register data
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @regs: pointer to ice_vfio_pci_regs structure
 *
 */
static void
ice_vfio_pci_save_regs(struct ice_vfio_pci_core_device *ice_vdev,
		       struct ice_vfio_pci_regs *regs)
{
	u8 __iomem *io_base = ice_vdev->io_base;
	int i, j;

	regs->int_dyn_ctl0 = readl(io_base + IAVF_VFINT_DYN_CTL01);

	for (i = 0; i < IAVF_VFINT_DYN_CTLN_NUM; i++)
		regs->int_dyn_ctln[i] =
		    readl(io_base + IAVF_VFINT_DYN_CTLN1(i));

	for (i = 0; i < IAVF_VFINT_ITRN0_NUM; i++)
		regs->int_intr0[i] = readl(io_base + IAVF_VFINT_ITRN0(i));

	for (i = 0; i < IAVF_VFINT_ITRN_NUM; i++)
		for (j = 0; j < IAVF_VFINT_DYN_CTLN_NUM; j++)
			regs->int_intrn[i][j] =
			    readl(io_base + IAVF_VFINT_ITRN1(i, j));

	regs->asq_bal = readl(io_base + IAVF_VF_ATQBAL1);
	regs->asq_bah = readl(io_base + IAVF_VF_ATQBAH1);
	regs->asq_len = readl(io_base + IAVF_VF_ATQLEN1);
	regs->asq_head = readl(io_base + IAVF_VF_ATQH1);
	regs->asq_tail = readl(io_base + IAVF_VF_ATQT1);
	regs->arq_bal = readl(io_base + IAVF_VF_ARQBAL1);
	regs->arq_bah = readl(io_base + IAVF_VF_ARQBAH1);
	regs->arq_len = readl(io_base +  IAVF_VF_ARQLEN1);
	regs->arq_head = readl(io_base + IAVF_VF_ARQH1);
	regs->arq_tail = readl(io_base + IAVF_VF_ARQT1);

	for (i = 0; i < IAVF_QRX_TAIL_MAX; i++)
		regs->rx_tail[i] = readl(io_base + IAVF_QRX_TAIL1(i));
}

/**
 * ice_vfio_pci_load_regs - Load migration register data
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @regs: pointer to ice_vfio_pci_regs structure
 *
 */
static void
ice_vfio_pci_load_regs(struct ice_vfio_pci_core_device *ice_vdev,
		       struct ice_vfio_pci_regs *regs)
{
	u8 __iomem *io_base = ice_vdev->io_base;
	int i, j;

	writel(regs->int_dyn_ctl0, io_base + IAVF_VFINT_DYN_CTL01);

	for (i = 0; i < IAVF_VFINT_DYN_CTLN_NUM; i++)
		writel(regs->int_dyn_ctln[i],
		       io_base + IAVF_VFINT_DYN_CTLN1(i));

	for (i = 0; i < IAVF_VFINT_ITRN0_NUM; i++)
		writel(regs->int_intr0[i], io_base + IAVF_VFINT_ITRN0(i));

	for (i = 0; i < IAVF_VFINT_ITRN_NUM; i++)
		for (j = 0; j < IAVF_VFINT_DYN_CTLN_NUM; j++)
			writel(regs->int_intrn[i][j],
			       io_base + IAVF_VFINT_ITRN1(i, j));

	writel(regs->asq_bal, io_base + IAVF_VF_ATQBAL1);
	writel(regs->asq_bah, io_base + IAVF_VF_ATQBAH1);
	writel(regs->asq_len, io_base + IAVF_VF_ATQLEN1);
	writel(regs->asq_head, io_base + IAVF_VF_ATQH1);
	writel(regs->asq_tail, io_base + IAVF_VF_ATQT1);
	writel(regs->arq_bal, io_base + IAVF_VF_ARQBAL1);
	writel(regs->arq_bah, io_base + IAVF_VF_ARQBAH1);
	writel(regs->arq_len, io_base +  IAVF_VF_ARQLEN1);
	writel(regs->arq_head, io_base + IAVF_VF_ARQH1);
	writel(regs->arq_tail, io_base + IAVF_VF_ARQT1);

	for (i = 0; i < IAVF_QRX_TAIL_MAX; i++)
		writel(regs->rx_tail[i], io_base + IAVF_QRX_TAIL1(i));
}

/**
 * ice_vfio_pci_load_state - VFIO device state reloading
 * @ice_vdev: pointer to ice vfio pci core device structure
 *
 * Load device state and restore it. This function is called when the VFIO uAPI
 * consumer wants to load the device state info from VFIO migration region and
 * restore them into the device. This function should make sure all the device
 * state info is loaded and restored successfully. As a result, return value is
 * mandatory to be checked.
 *
 * Return 0 for success, negative value for failure.
 */
static int __must_check
ice_vfio_pci_load_state(struct ice_vfio_pci_core_device *ice_vdev)
{
	int ret;

	ice_vfio_pci_load_regs(ice_vdev, &ice_vdev->mig_data->regs);
	ret = ice_migration_restore_devstate(ice_vdev->vf_handle,
					     ice_vdev->mig_data->dev_state,
					     ICE_VFIO_MIG_REGION_DATA_SZ,
					     ice_vdev->kvm);

	return ret;
}

/**
 * ice_vfio_pci_save_state - VFIO device state saving
 * @ice_vdev: pointer to ice vfio pci core device structure
 *
 * Snapshot the device state and save it. This function is called when the
 * VFIO uAPI consumer wants to snapshot the current device state and saves
 * it into the VFIO migration region. This function should make sure all
 * of the device state info is collectted and saved successfully. As a
 * result, return value is mandatory to be checked.
 *
 * Return 0 for success, negative value for failure.
 */
static int __must_check
ice_vfio_pci_save_state(struct ice_vfio_pci_core_device *ice_vdev)
{
	int ret = 0;

	ice_vfio_pci_save_regs(ice_vdev, &ice_vdev->mig_data->regs);
	ret = ice_migration_save_devstate(ice_vdev->vf_handle,
					  ice_vdev->mig_data->dev_state,
					  ICE_VFIO_MIG_REGION_DATA_SZ);
	ice_vdev->mig_info.pending_bytes = ICE_VFIO_MIG_REGION_DATA_SZ;
	return ret;
}

/**
 * ice_vfio_pci_reset_mig - Reset migration status
 * @ice_vdev: pointer to ice vfio pci core device structure
 *
 */
static void ice_vfio_pci_reset_mig(struct ice_vfio_pci_core_device *ice_vdev)
{
	ice_vdev->mig_info.pending_bytes = 0;
}

/**
 * ice_vfio_pci_set_device_state - Config device state
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @state: device state
 *
 * Return 0 for success, negative value for failure.
 */
static int
ice_vfio_pci_set_device_state(struct ice_vfio_pci_core_device *ice_vdev,
			      u32 state)
{
	struct vfio_device_migration_info *mig_info = &ice_vdev->mig_info;
	struct device *dev = &ice_vdev->core_device.pdev->dev;
	int ret = 0;

	if (state == mig_info->device_state)
		return 0;

	switch (state) {
	case VFIO_DEVICE_STATE_RUNNING:
		if (mig_info->device_state == VFIO_DEVICE_STATE_RESUMING)
			ret = ice_vfio_pci_load_state(ice_vdev);
		break;
	case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
		dev_info(dev, "Live migration begins\n");
		break;
	case VFIO_DEVICE_STATE_SAVING:
		ret = ice_migration_suspend_vf(ice_vdev->vf_handle);
		if (ret)
			return ret;
		ret = ice_vfio_pci_save_state(ice_vdev);
		dev_info(dev, "Live migration ends\n");
		break;
	case VFIO_DEVICE_STATE_STOP:
		ice_vfio_pci_reset_mig(ice_vdev);
		break;
	case VFIO_DEVICE_STATE_RESUMING:
		break;
	default:
		return -EFAULT;
	}

	if (!ret)
		mig_info->device_state = state;

	return ret;
}

/**
 * ice_vfio_pci_mig_rw_data - Read/write vfio migration data section
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @offset: read/write offset
 * @iswrite: write or not
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw_data(struct ice_vfio_pci_core_device *ice_vdev,
			 char __user *buf, size_t count, u64 offset,
			 bool iswrite)
{
	struct vfio_device_migration_info *mig_info = &ice_vdev->mig_info;
	int ret;

	if (offset + count > ICE_VFIO_MIG_REGION_DATA_SZ)
		return -EINVAL;

	if (iswrite) {
		ret = copy_from_user((u8 *)ice_vdev->mig_data + offset,
				     buf, count);
		if (ret)
			return -EFAULT;
	} else {
		ret = copy_to_user(buf, (u8 *)ice_vdev->mig_data + offset,
				   count);
		if (ret)
			return -EFAULT;

		mig_info->pending_bytes -= count;
	}

	return count;
}

/**
 * ice_vfio_pci_mig_rw_device_state - Read/write vfio migration device_state
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @iswrite: write or not
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw_device_state(struct ice_vfio_pci_core_device *ice_vdev,
				 char __user *buf, size_t count, bool iswrite)
{
	int ret;

	if (count != sizeof(ice_vdev->mig_info.device_state))
		return -EINVAL;

	if (iswrite) {
		u32 device_state;

		ret = copy_from_user(&device_state, buf, count);
		if (ret)
			return -EFAULT;

		ret = ice_vfio_pci_set_device_state(ice_vdev, device_state);
		if (ret)
			return ret;
	} else {
		ret = copy_to_user(buf, &ice_vdev->mig_info.device_state,
				   count);
		if (ret)
			return -EFAULT;
	}

	return count;
}

/**
 * ice_vfio_pci_mig_rw_pending_bytes - read/write vfio migration pending_bytes
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @iswrite: write or not
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw_pending_bytes(struct ice_vfio_pci_core_device *ice_vdev,
				  char __user *buf, size_t count, bool iswrite)
{
	int ret;

	if (count != sizeof(ice_vdev->mig_info.pending_bytes))
		return -EINVAL;

	if (iswrite)
		return -EFAULT;

	ret = copy_to_user(buf, &ice_vdev->mig_info.pending_bytes, count);
	if (ret)
		return -EFAULT;

	return count;
}

/**
 * ice_vfio_pci_mig_rw_data_offset - Read/write vfio migration data_offset
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @iswrite: write or not
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw_data_offset(struct ice_vfio_pci_core_device *ice_vdev,
				char __user *buf, size_t count, bool iswrite)
{
	int ret;

	if (count != sizeof(ice_vdev->mig_info.data_offset))
		return -EINVAL;

	if (iswrite)
		return -EFAULT;

	ret = copy_to_user(buf, &ice_vdev->mig_info.data_offset, count);
	if (ret)
		return -EFAULT;

	return count;
}

/**
 * ice_vfio_pci_mig_rw_data_size - Read/write vfio migration data_size
 * @ice_vdev: pointer to ice vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @iswrite: write or not
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw_data_size(struct ice_vfio_pci_core_device *ice_vdev,
			      char __user *buf, size_t count, bool iswrite)
{
	struct vfio_device_migration_info *mig_info = &ice_vdev->mig_info;
	u64 data_size;
	int ret;

	if (count != sizeof(ice_vdev->mig_info.data_size))
		return -EINVAL;

	if (iswrite) {
		ret = copy_from_user(&data_size, buf, count);
		if (ret)
			return -EFAULT;

		/* The user application should write the size in bytes of the
		 * data copied in the migration region during the _RESUMING
		 * state
		 */
		if (mig_info->device_state != VFIO_DEVICE_STATE_RESUMING)
			return -EINVAL;

		if (data_size != ICE_VFIO_MIG_REGION_DATA_SZ)
			return -EINVAL;
	} else {
		/* The user application should read data_size to get the size
		 * in bytes of the data copied in the migration region during
		 * the _SAVING state
		 */
		if (mig_info->device_state != VFIO_DEVICE_STATE_SAVING)
			return -EINVAL;

		ret = copy_to_user(buf, &mig_info->data_size, count);
		if (ret)
			return -EFAULT;
	}

	return count;
}

/**
 * ice_vfio_pci_mig_rw - Callback for vfio pci region read or write
 * @vdev: pointer to vfio pci core device structure
 * @buf: buffer for data
 * @count: size of buffer
 * @ppos: file position offset
 * @iswrite: write or not
 *
 * This is a callback function used by vfio framework to read or write the
 * vfio region for the live migration.
 *
 * Return the number of read/write bytes for success, negative value for failure
 */
static ssize_t
ice_vfio_pci_mig_rw(struct vfio_pci_core_device *vdev, char __user *buf,
		    size_t count, loff_t *ppos, bool iswrite)
{
	struct ice_vfio_pci_core_device *ice_vdev = container_of(vdev,
				struct ice_vfio_pci_core_device, core_device);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos) -
				VFIO_PCI_NUM_REGIONS;
	struct vfio_pci_region *region = &vdev->region[index];
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	int ret;

	if (region->type != VFIO_REGION_TYPE_MIGRATION ||
	    region->subtype != VFIO_REGION_SUBTYPE_MIGRATION)
		return -EINVAL;

	if (pos >= ice_vdev->mig_info.data_offset)
		return ice_vfio_pci_mig_rw_data(ice_vdev, buf, count,
				pos - ice_vdev->mig_info.data_offset, iswrite);

	switch (pos) {
	case VFIO_DEVICE_MIGRATION_OFFSET(device_state):
		ret = ice_vfio_pci_mig_rw_device_state(ice_vdev, buf,
						       count, iswrite);
		break;
	case VFIO_DEVICE_MIGRATION_OFFSET(pending_bytes):
		ret = ice_vfio_pci_mig_rw_pending_bytes(ice_vdev, buf,
							count, iswrite);
		break;
	case VFIO_DEVICE_MIGRATION_OFFSET(data_offset):
		ret = ice_vfio_pci_mig_rw_data_offset(ice_vdev, buf,
						      count, iswrite);
		break;
	case VFIO_DEVICE_MIGRATION_OFFSET(data_size):
		ret = ice_vfio_pci_mig_rw_data_size(ice_vdev, buf,
						    count, iswrite);
		break;
	default:
		ret = -EFAULT;
		break;
	}

	return ret;
}

/**
 * ice_vfio_pci_mig_release - Callback for vfio pci region release
 * @vdev: pointer to vfio pci core device structure
 * @region: pointer to vfio pci region
 *
 * This is a callback function used by vfio framework to info the driver that
 * they will release the vfio region.
 *
 * Returns 0 on success, negative value on error
 */
static void
ice_vfio_pci_mig_release(struct vfio_pci_core_device *vdev,
			 struct vfio_pci_region *region)
{
}

static struct vfio_pci_regops ice_vfio_pci_regops = {
	.rw = ice_vfio_pci_mig_rw,
	.release = ice_vfio_pci_mig_release,
};

/**
 * ice_vfio_group_notifier - Callback function when set kvm event occur
 * @nb: pointer to notifier_block structure
 * @action: the event used by notifier block
 * @opaque: pointer to kvm structure
 *
 * Returns 0 on success, negative value on error
 */
static int ice_vfio_group_notifier(struct notifier_block *nb,
				   unsigned long action, void *opaque)
{
	struct ice_vfio_pci_core_device *ice_vdev =
	    container_of(nb,
			 struct ice_vfio_pci_core_device,
			 group_notifier);
	struct device *dev = &ice_vdev->core_device.pdev->dev;

	if (action == VFIO_GROUP_NOTIFY_SET_KVM)
		ice_vdev->kvm = opaque;
	else
		return NOTIFY_DONE;

	if (!ice_vdev->kvm) {
		dev_err(dev, "NULL kvm pointer\n");
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

/**
 * ice_vfio_migration_init - Initialization for live migration function
 * @ice_vdev: pointer to ice vfio pci core device structure
 *
 * Returns 0 on success, negative value on error
 */
static int ice_vfio_migration_init(struct ice_vfio_pci_core_device *ice_vdev)
{
	struct vfio_device_migration_info *mig_info = &ice_vdev->mig_info;
	struct device *dev = &ice_vdev->core_device.pdev->dev;
	struct pci_dev *pdev = ice_vdev->core_device.pdev;
	unsigned long events;
	int ret = 0;

	ice_vdev->mig_data = kzalloc(ICE_VFIO_MIG_REGION_DATA_SZ, GFP_KERNEL);
	if (!ice_vdev->mig_data)
		return -ENOMEM;

	mig_info->data_size = ICE_VFIO_MIG_REGION_DATA_SZ;
	mig_info->data_offset = ICE_VFIO_MIG_REGION_INFO_SZ;

	ice_vdev->vf_handle = ice_migration_get_vf(pdev);
	if (!ice_vdev->vf_handle) {
		ret = -EFAULT;
		goto err_get_vf_handle;
	}

	ice_migration_init_vf(ice_vdev->vf_handle);
	ice_vdev->io_base = (u8 __iomem *)pci_iomap(pdev, 0, 0);
	if (!ice_vdev->io_base) {
		ret =  -EFAULT;
		goto err_pci_iomap;
	}

	ice_vdev->group_notifier.notifier_call = ice_vfio_group_notifier;

	events = VFIO_GROUP_NOTIFY_SET_KVM;
	ret = vfio_register_notifier(dev, VFIO_GROUP_NOTIFY, &events,
				     &ice_vdev->group_notifier);
	if (ret) {
		dev_err(dev, "register group notifier failed %d\n", ret);
		ret = -EINVAL;
		goto err_register_notifier;
	}

	ret = vfio_pci_register_dev_region(&ice_vdev->core_device,
					   VFIO_REGION_TYPE_MIGRATION,
					   VFIO_REGION_SUBTYPE_MIGRATION,
					   &ice_vfio_pci_regops,
					   ICE_VFIO_MIG_REGION_INFO_SZ +
					   ICE_VFIO_MIG_REGION_DATA_SZ,
					   VFIO_REGION_INFO_FLAG_READ |
					   VFIO_REGION_INFO_FLAG_WRITE,
					   NULL);
	if (ret)
		goto err_dev_region_register;

	return ret;

err_dev_region_register:
	vfio_unregister_notifier(dev, VFIO_GROUP_NOTIFY,
				 &ice_vdev->group_notifier);
err_register_notifier:
	pci_iounmap(pdev, ice_vdev->io_base);
err_get_vf_handle:
err_pci_iomap:
	kfree(ice_vdev->mig_data);

	return ret;
}

/**
 * ice_vfio_migration_uninit - Cleanup for live migration function
 * @ice_vdev: pointer to ice vfio pci core device structure
 */
static void ice_vfio_migration_uninit(struct ice_vfio_pci_core_device *ice_vdev)
{
	struct device *dev = &ice_vdev->core_device.pdev->dev;

	vfio_unregister_notifier(dev, VFIO_GROUP_NOTIFY,
				 &ice_vdev->group_notifier);
	pci_iounmap(ice_vdev->core_device.pdev, ice_vdev->io_base);
	ice_migration_uninit_vf(ice_vdev->vf_handle);
	kfree(ice_vdev->mig_data);
}

/**
 * ice_vfio_pci_open_device - Called when a vfio device is probed by VFIO UAPI
 * @core_vdev: the vfio device to open
 *
 * Initialization of the vfio device
 *
 * Returns 0 on success, negative value on error
 */
static int ice_vfio_pci_open_device(struct vfio_device *core_vdev)
{
	struct ice_vfio_pci_core_device *ice_vdev = container_of(core_vdev,
			struct ice_vfio_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *vdev = &ice_vdev->core_device;
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	ret = ice_vfio_migration_init(ice_vdev);
	if (ret) {
		vfio_pci_core_disable(vdev);
		return ret;
	}

	vfio_pci_core_finish_enable(vdev);

	return 0;
}

/**
 * ice_vfio_pci_close_device - Called when a vfio device fd is closed
 * @core_vdev: the vfio device to close
 */
static void ice_vfio_pci_close_device(struct vfio_device *core_vdev)
{
	struct ice_vfio_pci_core_device *ice_vdev = container_of(core_vdev,
			struct ice_vfio_pci_core_device, core_device.vdev);

	vfio_pci_core_close_device(core_vdev);
	ice_vfio_migration_uninit(ice_vdev);
}

static const struct vfio_device_ops ice_vfio_pci_ops = {
	.name		= "ice-vfio-pci",
	.open_device	= ice_vfio_pci_open_device,
	.close_device	= ice_vfio_pci_close_device,
	.read		= vfio_pci_core_read,
	.write		= vfio_pci_core_write,
	.ioctl		= vfio_pci_core_ioctl,
	.mmap		= vfio_pci_core_mmap,
	.request	= vfio_pci_core_request,
	.match		= vfio_pci_core_match,
};

/**
 * ice_vfio_pci_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @id: entry in ice_vfio_pci_table
 *
 * Returns 0 on success, negative on failure
 */
static int
ice_vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ice_vfio_pci_core_device *ice_vdev;
	int ret;

	ice_vdev = kzalloc(sizeof(*ice_vdev), GFP_KERNEL);
	if (!ice_vdev)
		return -ENOMEM;

	vfio_pci_core_init_device(&ice_vdev->core_device, pdev,
				  &ice_vfio_pci_ops);

	ret = vfio_pci_core_register_device(&ice_vdev->core_device);
	if (ret)
		goto out_free;

	dev_set_drvdata(&pdev->dev, ice_vdev);

	return 0;

out_free:
	vfio_pci_core_uninit_device(&ice_vdev->core_device);
	kfree(ice_vdev);
	return ret;
}

/**
 * ice_vfio_pci_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void ice_vfio_pci_remove(struct pci_dev *pdev)
{
	struct ice_vfio_pci_core_device *ice_vdev =
		(struct ice_vfio_pci_core_device *)dev_get_drvdata(&pdev->dev);

	vfio_pci_core_unregister_device(&ice_vdev->core_device);
	vfio_pci_core_uninit_device(&ice_vdev->core_device);
	kfree(ice_vdev);
}

/* ice_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id ice_vfio_pci_table[] = {
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x1889) },
	{}
};
MODULE_DEVICE_TABLE(pci, ice_vfio_pci_table);

static struct pci_driver ice_vfio_pci_driver = {
	.name			= "ice-vfio-pci",
	.id_table		= ice_vfio_pci_table,
	.probe			= ice_vfio_pci_probe,
	.remove			= ice_vfio_pci_remove,
	.err_handler		= &vfio_pci_core_err_handlers,
};

/**
 * ice_vfio_pci_init - Driver registration routine
 *
 * ice_vfio_pci_init is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 */
static int __init ice_vfio_pci_init(void)
{
	int ret;

	/* Register and scan for devices */
	ret = pci_register_driver(&ice_vfio_pci_driver);
	if (ret)
		return ret;

	return 0;
}
module_init(ice_vfio_pci_init);

/**
 * ice_vfio_pci_exit - Driver exit cleanup routine
 *
 * ice_vfio_pci_exit is called just before the driver is removed
 * from memory.
 */
static void __exit ice_vfio_pci_exit(void)
{
	pci_unregister_driver(&ice_vfio_pci_driver);
}
module_exit(ice_vfio_pci_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION(DRIVER_DESC);
