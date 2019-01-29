// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 1999 - 2018 Intel Corporation. */

#include "ixgbe.h"
#include "ixgbe_common.h"
#include "ixgbe_type.h"

#ifdef IXGBE_SYSFS

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#ifdef IXGBE_HWMON
#include <linux/hwmon.h>
#endif

#ifdef IXGBE_HWMON
/* hwmon callback functions */
static ssize_t ixgbe_hwmon_show_location(struct device __always_unused *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	return sprintf(buf, "loc%u\n",
		       ixgbe_attr->sensor->location);
}

static ssize_t ixgbe_hwmon_show_temp(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value;

	/* reset the temp field */
	ixgbe_attr->hw->mac.ops.get_thermal_sensor_data(ixgbe_attr->hw);

	value = ixgbe_attr->sensor->temp;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t ixgbe_hwmon_show_cautionthresh(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = ixgbe_attr->sensor->caution_thresh;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t ixgbe_hwmon_show_maxopthresh(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = ixgbe_attr->sensor->max_op_thresh;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

/**
 * ixgbe_add_hwmon_attr - Create hwmon attr table for a hwmon sysfs file.
 * @adapter: pointer to the adapter structure
 * @offset: offset in the eeprom sensor data table
 * @type: type of sensor data to display
 *
 * For each file we want in hwmon's sysfs interface we need a device_attribute
 * This is included in our hwmon_attr struct that contains the references to
 * the data structures we need to get the data to display.
 */
static int ixgbe_add_hwmon_attr(struct ixgbe_adapter *adapter,
				unsigned int offset, int type) {
	unsigned int n_attr;
	struct hwmon_attr *ixgbe_attr;
#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS

	n_attr = adapter->ixgbe_hwmon_buff->n_hwmon;
	ixgbe_attr = &adapter->ixgbe_hwmon_buff->hwmon_list[n_attr];
#else
	int rc;

	n_attr = adapter->ixgbe_hwmon_buff.n_hwmon;
	ixgbe_attr = &adapter->ixgbe_hwmon_buff.hwmon_list[n_attr];
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */

	switch (type) {
	case IXGBE_HWMON_TYPE_LOC:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_location;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_label", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_TEMP:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_temp;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_input", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_CAUTION:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_cautionthresh;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_max", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_MAX:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_maxopthresh;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_crit", offset + 1);
		break;
	default:
		return -EPERM;
	}

	/* These always the same regardless of type */
	ixgbe_attr->sensor =
		&adapter->hw.mac.thermal_sensor_data.sensor[offset];
	ixgbe_attr->hw = &adapter->hw;
	ixgbe_attr->dev_attr.store = NULL;
	ixgbe_attr->dev_attr.attr.mode = 0444;
	ixgbe_attr->dev_attr.attr.name = ixgbe_attr->name;

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	sysfs_attr_init(&ixgbe_attr->dev_attr.attr);

	adapter->ixgbe_hwmon_buff->attrs[n_attr] = &ixgbe_attr->dev_attr.attr;

	++adapter->ixgbe_hwmon_buff->n_hwmon;

	return 0;
#else
	rc = device_create_file(pci_dev_to_dev(adapter->pdev),
				&ixgbe_attr->dev_attr);

	if (rc == 0)
		++adapter->ixgbe_hwmon_buff.n_hwmon;

	return rc;
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
}
#endif /* IXGBE_HWMON */

static void ixgbe_sysfs_del_adapter(struct ixgbe_adapter __maybe_unused *adapter)
{
#ifdef IXGBE_HWMON
#ifndef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	int i;

	if (adapter == NULL)
		return;

	for (i = 0; i < adapter->ixgbe_hwmon_buff.n_hwmon; i++) {
		device_remove_file(pci_dev_to_dev(adapter->pdev),
			   &adapter->ixgbe_hwmon_buff.hwmon_list[i].dev_attr);
	}

	kfree(adapter->ixgbe_hwmon_buff.hwmon_list);

	if (adapter->ixgbe_hwmon_buff.device)
		hwmon_device_unregister(adapter->ixgbe_hwmon_buff.device);
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
#endif /* IXGBE_HWMON */
}

/* called from ixgbe_main.c */
void ixgbe_sysfs_exit(struct ixgbe_adapter *adapter)
{
	ixgbe_sysfs_del_adapter(adapter);
}

/* called from ixgbe_main.c */
int ixgbe_sysfs_init(struct ixgbe_adapter *adapter)
{
	int rc = 0;
#ifdef IXGBE_HWMON
#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	struct hwmon_buff *ixgbe_hwmon;
	struct device *hwmon_dev;
#else
	struct hwmon_buff *ixgbe_hwmon = &adapter->ixgbe_hwmon_buff;
	int n_attrs;
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
	unsigned int i;
#endif /* IXGBE_HWMON */

#ifdef IXGBE_HWMON
	/* If this method isn't defined we don't support thermals */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh == NULL) {
		goto no_thermal;
	}

	/* Don't create thermal hwmon interface if no sensors present */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh(&adapter->hw))
		goto no_thermal;

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	ixgbe_hwmon = devm_kzalloc(&adapter->pdev->dev, sizeof(*ixgbe_hwmon),
				   GFP_KERNEL);

	if (!ixgbe_hwmon) {
		rc = -ENOMEM;
		goto exit;
	}

	adapter->ixgbe_hwmon_buff = ixgbe_hwmon;
#else
	/*
	 * Allocation space for max attributs
	 * max num sensors * values (loc, temp, max, caution)
	 */
	n_attrs = IXGBE_MAX_SENSORS * 4;
	ixgbe_hwmon->hwmon_list = kcalloc(n_attrs, sizeof(struct hwmon_attr),
					  GFP_KERNEL);

	if (!ixgbe_hwmon->hwmon_list) {
		rc = -ENOMEM;
		goto err;
	}
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {
		/*
		 * Only create hwmon sysfs entries for sensors that have
		 * meaningful data for.
		 */
		if (adapter->hw.mac.thermal_sensor_data.sensor[i].location == 0)
			continue;

		/* Bail if any hwmon attr struct fails to initialize */
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_CAUTION);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_LOC);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_TEMP);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_MAX);
		if (rc)
			goto err;
	}

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	ixgbe_hwmon->groups[0] = &ixgbe_hwmon->group;
	ixgbe_hwmon->group.attrs = ixgbe_hwmon->attrs;

	hwmon_dev = devm_hwmon_device_register_with_groups(&adapter->pdev->dev,
							   "ixgbe",
							   ixgbe_hwmon,
							   ixgbe_hwmon->groups);

	if (IS_ERR(hwmon_dev)) {
		rc = PTR_ERR(hwmon_dev);
		goto exit;
	}

#else
	ixgbe_hwmon->device =
		hwmon_device_register(pci_dev_to_dev(adapter->pdev));

	if (IS_ERR(ixgbe_hwmon->device)) {
		rc = PTR_ERR(ixgbe_hwmon->device);
		goto err;
	}

#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
no_thermal:
#endif /* IXGBE_HWMON */
	goto exit;

err:
	ixgbe_sysfs_del_adapter(adapter);
exit:
	return rc;
}
#endif /* IXGBE_SYSFS */
