// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2013, Intel Corporation. */

#include "kcompat.h"
#include "kcompat_vfd.h"

#define to_dev(obj) container_of(obj, struct device, kobj)

const struct vfd_ops *vfd_ops = NULL;

/**
 * __get_pf_pdev - helper function to get the pdev
 * @kobj:	kobject passed
 * @pdev:	PCI device information struct
 */
static int __get_pf_pdev(struct kobject *kobj, struct pci_dev **pdev)
{
	struct device *dev;

	if (!kobj->parent)
		return -EINVAL;

	/* get pdev */
	dev = to_dev(kobj->parent);
	*pdev = to_pci_dev(dev);

	return 0;
}

/**
 * __get_pdev_and_vfid - helper function to get the pdev and the vf id
 * @kobj:	kobject passed
 * @pdev:	PCI device information struct
 * @vf_id:	VF id of the VF under consideration
 */
static int __get_pdev_and_vfid(struct kobject *kobj, struct pci_dev **pdev,
			       int *vf_id)
{
	struct device *dev;

	if (!kobj->parent->parent)
		return -EINVAL;

	/* get pdev */
	dev = to_dev(kobj->parent->parent);
	*pdev = to_pci_dev(dev);

	/* get vf_id */
	if (kstrtoint(kobj->name, 10, vf_id) != 0) {
		dev_err(&(*pdev)->dev, "Failed to convert %s to vf_id\n",
			kobj->name);
		return -EINVAL;
	}

	return 0;
}

/**
 * __get_tc - helper function to get the pdev and the vf id
 * @pdev:	PCI device information struct
 * @tc_kobj:	kobject passed
 * @tc:		number of extracted TC
 */
static int __get_tc(struct pci_dev *pdev, struct kobject *tc_kobj, int *tc)
{
	if (kstrtoint(tc_kobj->name, 10, tc) != 0) {
		dev_err(&pdev->dev, "Failed to convert %s to tc\n",
			tc_kobj->name);
		return -EINVAL;
	}

	return 0;
}

/**
 * __get_vf_tc_pdev - helper function to get the pdev and the vf id
 * @kobj:	kobject passed
 * @pdev:	PCI device information struct
 * @vf_id:	VF id of the VF under consideration
 * @tc:		number of extracted TC
 */
static int __get_vf_tc_pdev(struct kobject *kobj, struct pci_dev **pdev,
			    int *vf_id, int *tc)
{
	int ret;

	if (!kobj->parent->parent)
		return -EINVAL;

	ret = __get_pdev_and_vfid(kobj->parent->parent, pdev, vf_id);
	if (ret)
		goto err;

	ret = __get_tc(*pdev, kobj, tc);
err:
	return ret;
}

/**
 * __get_pdev_tc - helper function to get the pdev and the vf id
 * @kobj:	kobject passed
 * @pdev:	PCI device information struct
 * @tc:		number of extracted TC
 */
static int __get_pdev_tc(struct kobject *kobj, struct pci_dev **pdev, int *tc)
{
	int ret;

	/* check for pci_dev kobject */
	if (!kobj->parent->parent->parent)
		return -EINVAL;

	ret = __get_pf_pdev(kobj->parent->parent, pdev);
	if (ret)
		goto err;

	ret = __get_tc(*pdev, kobj, tc);
err:
	return ret;
}

/**
 * __parse_bool_data - helper function to parse boolean data
 * @pdev:	PCI device information struct
 * @buff:	buffer with input data
 * @attr_name:	name of the attribute
 * @data:	pointer to output data
 */
static int __parse_bool_data(struct pci_dev *pdev, const char *buff,
			     const char *attr_name, bool *data)
{
	if (sysfs_streq("on", buff)) {
		*data = true;
	} else if (sysfs_streq("off", buff)) {
		*data = false;
	} else {
		dev_err(&pdev->dev, "set %s: invalid input string", attr_name);
		return -EINVAL;
	}
	return 0;
}

/**
 * __parse_egress_ingress_input - helper function for ingress/egress_mirror attributes
 * @pdev:	PCI device information struct
 * @buff:	buffer with input data
 * @attr_name:	name of the attribute
 * @data_new:	pointer to input data merged with the old data
 * @data_old:	pointer to old data of the attribute
 *
 * Get the input data for egress_mirror or ingress_mirror attribute in the form
 * "add <number>" or "rem <number>".
 * Set the output data to off if in "rem <number>", <number> matches old data.
 *
 */
static int __parse_egress_ingress_input(struct pci_dev *pdev, const char *buff,
					const char *attr_name, int *data_new,
					int *data_old)
{
	int ret = 0;
	char *p;

	if (strstr(buff, "add")) {
		p = strstr(buff, "add");

		ret = kstrtoint(p + sizeof("add"), 10, data_new);
		if (ret) {
			dev_err(&pdev->dev,
				"add %s: input error %d\n", attr_name, ret);
			return ret;
		}
	} else if (strstr(buff, "rem")) {
		p = strstr(buff, "rem");

		ret = kstrtoint(p + sizeof("rem"), 10, data_new);
		if (ret) {
			dev_err(&pdev->dev,
				"rem %s: input error %d\n", attr_name, ret);
			return ret;
		}

		if (*data_new == *data_old) {
			if (!strcmp(attr_name, "egress_mirror"))
				*data_new = VFD_EGRESS_MIRROR_OFF;
			else if (!strcmp(attr_name, "ingress_mirror"))
				*data_new = VFD_INGRESS_MIRROR_OFF;
		} else {
			dev_err(&pdev->dev,
				"rem %s: input doesn't match current value",
				attr_name);
			return -EINVAL;
		}
	} else {
		dev_err(&pdev->dev, "set %s: invalid input string", attr_name);
		return -EINVAL;
	}

	return ret;
}

/**
 * __parse_add_rem_bitmap - helper function to parse bitmap data
 * @pdev:	PCI device information struct
 * @buff:	buffer with input data
 * @attr_name:	name of the attribute
 * @data_new:	pointer to input data merged with the old data
 * @data_old:	pointer to old data of the attribute
 *
 * If passed add: set data_new to "data_old || data_input"
 * If passed rem: set data_new to "data_old || ~data_input"
 */
static int __parse_add_rem_bitmap(struct pci_dev *pdev, const char *buff,
				  const char *attr_name,
				  unsigned long *data_new,
				  unsigned long *data_old)
{
	int ret = 0;
	char *p;

	if (strstr(buff, "add")) {
		p = strstr(buff, "add");
		bitmap_zero(data_new, VLAN_N_VID);

		ret = bitmap_parselist(p + sizeof("add"), data_new, VLAN_N_VID);
		if (ret) {
			dev_err(&pdev->dev,
				"add %s: input error %d\n", attr_name, ret);
			return ret;
		}

		bitmap_or(data_new, data_new, data_old, VLAN_N_VID);
	} else if (strstr(buff, "rem")) {
		p = strstr(buff, "rem");
		bitmap_zero(data_new, VLAN_N_VID);

		ret = bitmap_parselist(p + sizeof("rem"), data_new, VLAN_N_VID);
		if (ret) {
			dev_err(&pdev->dev,
				"rem %s: input error %d\n", attr_name, ret);
			return ret;
		}

		/* new = old & ~rem */
		bitmap_andnot(data_new, data_old, data_new, VLAN_N_VID);
	} else {
		dev_err(&pdev->dev, "set %s: invalid input string", attr_name);
		return -EINVAL;
	}
	return 0;
}

/**
 * __parse_promisc_input - helper function for promisc attributes
 * @buff:	buffer with input data
 * @count:	size of buff
 * @cmd:	return pointer to cmd into buff
 * @subcmd:	return pointer to subcmd into buff
 *
 * Get the input data for promisc attributes in the form "add/rem mcast/ucast".
 */
static int __parse_promisc_input(const char *buff, size_t count,
				 const char **cmd, const char **subcmd)
{
	size_t idx = 0;

	/* Remove start spaces */
	while (buff[idx] == ' ' && idx < count)
		idx++;

	/* Parse cmd */
	if (strncmp(&buff[idx], "add", strlen("add")) == 0) {
		*cmd = &buff[idx];
		idx += strlen("add");
	} else if (strncmp(&buff[idx], "rem", strlen("rem")) == 0) {
		*cmd = &buff[idx];
		idx += strlen("rem");
	} else {
		return -EINVAL;
	}

	if (buff[idx++] != ' ')
		return -EINVAL;

	/* Remove spaces between cmd */
	while (buff[idx] == ' ' && idx < count)
		idx++;

	/* Parse subcmd */
	if (strncmp(&buff[idx], "ucast", strlen("ucast")) == 0) {
		*subcmd = &buff[idx];
		idx += strlen("ucast");
	} else if (strncmp(&buff[idx], "mcast", strlen("mcast")) == 0) {
		*subcmd = &buff[idx];
		idx += strlen("mcast");
	} else {
		return -EINVAL;
	}

	/* Remove spaces after subcmd */
	while ((buff[idx] == ' ' || buff[idx] == '\n') && idx < count)
		idx++;

	if (idx != count)
		return -EINVAL;

	return 0;
}

/* Handlers for each VFd operation */

/**
 * vfd_trunk_show - handler for trunk show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 *
 * Get current data from driver and copy to buffer
 **/
static ssize_t vfd_trunk_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	DECLARE_BITMAP(data, VLAN_N_VID);
	bitmap_zero(data, VLAN_N_VID);

	if (!vfd_ops->get_trunk)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_trunk(pdev, vf_id, data);
	if (ret)
		ret = bitmap_print_to_pagebuf(1, buff, data, VLAN_N_VID);

	return ret;
}

/**
 * vfd_trunk_store - handler for trunk store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * Get current data from driver, compose new data based on input values
 * depending on "add" or "rem" command, and pass new data to the driver to set.
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_trunk_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buff, size_t count)
{
	unsigned long *data_old, *data_new;
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->set_trunk || !vfd_ops->get_trunk)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	data_old = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
			   GFP_KERNEL);
	if (!data_old)
		return -ENOMEM;
	data_new = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
			   GFP_KERNEL);
	if (!data_new) {
		kfree(data_old);
		return -ENOMEM;
	}

	ret = vfd_ops->get_trunk(pdev, vf_id, data_old);
	if (ret < 0)
		goto err_free;

	ret = __parse_add_rem_bitmap(pdev, buff, "trunk", data_new, data_old);
	if (ret)
		goto err_free;

	if (!bitmap_equal(data_new, data_old, VLAN_N_VID))
		ret = vfd_ops->set_trunk(pdev, vf_id, data_new);

err_free:
	kfree(data_old);
	kfree(data_new);
	return ret ? ret : count;
}

/**
 * vfd_vlan_mirror_show - handler for vlan_mirror show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 *
 * Get current data from driver and copy to buffer
 **/
static ssize_t vfd_vlan_mirror_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	DECLARE_BITMAP(data, VLAN_N_VID);
	bitmap_zero(data, VLAN_N_VID);

	if (!vfd_ops->get_vlan_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vlan_mirror(pdev, vf_id, data);
	if (ret)
		ret = bitmap_print_to_pagebuf(1, buff, data, VLAN_N_VID);

	return ret;
}

/**
 * vfd_vlan_mirror_store - handler for vlan_mirror store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * Get current data from driver, compose new data based on input values
 * depending on "add" or "rem" command, and pass new data to the driver to set.
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_vlan_mirror_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	unsigned long *data_old, *data_new;
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->set_vlan_mirror || !vfd_ops->get_vlan_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	data_old = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
			   GFP_KERNEL);
	if (!data_old)
		return -ENOMEM;
	data_new = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
			   GFP_KERNEL);
	if (!data_new) {
		kfree(data_old);
		return -ENOMEM;
	}

	ret = vfd_ops->get_vlan_mirror(pdev, vf_id, data_old);
	if (ret < 0)
		goto err_free;

	ret = __parse_add_rem_bitmap(pdev, buff, "vlan_mirror",
				     data_new, data_old);
	if (ret)
		goto err_free;

	if (!bitmap_equal(data_new, data_old, VLAN_N_VID))
		ret = vfd_ops->set_vlan_mirror(pdev, vf_id, data_new);

err_free:
	kfree(data_old);
	kfree(data_new);
	return ret ? ret : count;
}

/**
 * vfd_egress_mirror_show - handler for egress_mirror show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_egress_mirror_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	int data;

	if (!vfd_ops->get_egress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_egress_mirror(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data == VFD_EGRESS_MIRROR_OFF)
		ret = scnprintf(buff, PAGE_SIZE, "off\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "%u\n", data);

	return ret;
}

/**
 * vfd_egress_mirror_store - handler for egress_mirror store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_egress_mirror_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buff, size_t count)
{
	int data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->set_egress_mirror || !vfd_ops->get_egress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_egress_mirror(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_egress_ingress_input(pdev, buff, "egress_mirror",
					   &data_new, &data_old);
	if (ret)
		return ret;
	if(data_new == vf_id) {
		dev_err(&pdev->dev, "VF %d: Setting egress_mirror to itself is not allowed\n", vf_id);
		return -EINVAL;
	}

	if (data_new != data_old)
		ret = vfd_ops->set_egress_mirror(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_ingress_mirror_show - handler for ingress_mirror show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_ingress_mirror_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	int data;

	if (!vfd_ops->get_ingress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_ingress_mirror(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data == VFD_INGRESS_MIRROR_OFF)
		ret = scnprintf(buff, PAGE_SIZE, "off\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "%u\n", data);

	return ret;
}

/**
 * vfd_ingress_mirror_store - handler for ingress_mirror store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_ingress_mirror_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buff, size_t count)
{
	int data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->set_ingress_mirror || !vfd_ops->get_ingress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_ingress_mirror(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_egress_ingress_input(pdev, buff, "ingress_mirror",
					   &data_new, &data_old);
	if (ret)
		return ret;
	if(data_new == vf_id) {
		dev_err(&pdev->dev, "VF %d: Setting ingress_mirror to itself is not allowed\n", vf_id);
		return -EINVAL;
	}

	if (data_new != data_old)
		ret = vfd_ops->set_ingress_mirror(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_mac_anti_spoof_show - handler for mac_anti_spoof show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_mac_anti_spoof_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	bool data;

	if (!vfd_ops->get_mac_anti_spoof)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_mac_anti_spoof(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_mac_anti_spoof_store - handler for mac_anti_spoof store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_mac_anti_spoof_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buff, size_t count)
{
	bool data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_mac_anti_spoof || !vfd_ops->get_mac_anti_spoof)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_mac_anti_spoof(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "mac_anti_spoof", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_mac_anti_spoof(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_vlan_anti_spoof_show - handler for vlan_anti_spoof show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_vlan_anti_spoof_show(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	bool data;

	if (!vfd_ops->get_vlan_anti_spoof)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vlan_anti_spoof(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_vlan_anti_spoof_store - handler for vlan_anti_spoof store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_vlan_anti_spoof_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buff, size_t count)
{
	bool data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_vlan_anti_spoof || !vfd_ops->get_vlan_anti_spoof)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vlan_anti_spoof(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "vlan_anti_spoof", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_vlan_anti_spoof(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_allow_untagged_show - handler for allow_untagged show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_allow_untagged_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data;

	if (!vfd_ops->get_allow_untagged)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_allow_untagged(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_allow_untagged_store - handler for allow_untagged store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_allow_untagged_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data_new, data_old;

	if (!vfd_ops->set_allow_untagged || !vfd_ops->get_allow_untagged)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_allow_untagged(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "allow_untagged", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_allow_untagged(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_loopback_show - handler for loopback show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_loopback_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data;

	if (!vfd_ops->get_loopback)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_loopback(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_loopback_store - handler for loopback store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_loopback_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data_new, data_old;

	if (!vfd_ops->set_loopback || !vfd_ops->get_loopback)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_loopback(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "loopback", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_loopback(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_mac_show - handler for mac show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_mac_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buff)
{
	u8 macaddr[ETH_ALEN];
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->get_mac)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_mac(pdev, vf_id, macaddr);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%pM\n", macaddr);

	return ret;
}

/**
 * vfd_mac_store - handler for mac store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_mac_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buff, size_t count)
{
	u8 macaddr[ETH_ALEN];
	u8 macaddr_old[ETH_ALEN];
	struct pci_dev *pdev;
	int vf_id, ret = 0;

	if (!vfd_ops->set_mac || !vfd_ops->get_mac)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_mac(pdev, vf_id, macaddr_old);
	if (ret < 0)
		return ret;

	ret = sscanf(buff, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &macaddr[0], &macaddr[1], &macaddr[2],
		     &macaddr[3], &macaddr[4], &macaddr[5]);

	if (ret != 6)
		return -EINVAL;

	if (!ether_addr_equal(macaddr, macaddr_old))
		ret = vfd_ops->set_mac(pdev, vf_id, macaddr);

	return ret ? ret : count;
}

/**
 * vfd_mac_list_show - handler for mac_list show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 *
 * This function also frees the memory allocated for mac_list in another function.
 *
 **/
static ssize_t vfd_mac_list_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buff)
{
	unsigned int mac_num_allowed, mac_num_list, mac_num_count;
	const char *overflow_msg = "... and more\n";
	unsigned int mac_msg_len = 3*ETH_ALEN;
	struct list_head *pos, *n;
	struct pci_dev *pdev;
	int vf_id, ret;
	char *written;
	LIST_HEAD(mac_list);

	if (!vfd_ops->get_mac_list)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_mac_list(pdev, vf_id, &mac_list);
	if (ret < 0)
		goto err_free;

	mac_num_list = 0;
	mac_num_count = 0;
	list_for_each_safe(pos, n, &mac_list)
		mac_num_list++;

	mac_num_allowed = (PAGE_SIZE - 1) / mac_msg_len;
	if (mac_num_list > mac_num_allowed)
		mac_num_allowed = (PAGE_SIZE - 1 - strlen(overflow_msg)) /
				   mac_msg_len;

	written = buff;
	list_for_each_safe(pos, n, &mac_list) {
		struct vfd_macaddr *mac = NULL;

		mac_num_count++;
		mac = list_entry(pos, struct vfd_macaddr, list);
		if (mac_num_count > mac_num_allowed) {
			ret += scnprintf(written, PAGE_SIZE - ret,
					 "%s", overflow_msg);
			goto err_free;
		} else if (list_is_last(pos, &mac_list)) {
			ret += scnprintf(written, PAGE_SIZE - ret,
					 "%pM\n", mac->mac);
		} else {
			ret += scnprintf(written, PAGE_SIZE - ret,
					 "%pM,", mac->mac);
		}
		written += mac_msg_len;
	}

err_free:
	list_for_each_safe(pos, n, &mac_list) {
		struct vfd_macaddr *mac = NULL;

		mac = list_entry(pos, struct vfd_macaddr, list);
		list_del(pos);
		kfree(mac);
	}
	return ret;
}

/**
 * vfd_mac_list_store - handler for mac_list store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * Get input mac list into the linked list and depending on "add" or "rem" command
 * pass the input mac list to the driver to either add or remove macs to the list.
 *
 * This function also frees the memory allocated for mac_list in another function.
 *
 **/
static ssize_t vfd_mac_list_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	struct list_head *pos, *n;
	struct pci_dev *pdev;
	u8 macaddr[ETH_ALEN];
	int vf_id, ret;
	size_t shift;
	bool add;
	LIST_HEAD(mac_list_inp);

	if (!vfd_ops->add_macs_to_list || !vfd_ops->rem_macs_from_list)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	if (strstr(buff, "add")) {
		shift = sizeof("add");
		add = true;
	} else if (strstr(buff, "rem")) {
		shift = sizeof("rem");
		add = false;
	} else {
		dev_err(&pdev->dev, "Invalid input string");
		ret = -EINVAL;
		goto err_free;
	}

	/* Get input data */
	for (;;) {
		struct vfd_macaddr *mac_new;

		if (*(buff + shift) == ' ' || *(buff + shift) == ',') {
			shift++;
			continue;
		}

		ret = sscanf(buff + shift,
			     "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			     &macaddr[0], &macaddr[1], &macaddr[2],
			     &macaddr[3], &macaddr[4], &macaddr[5]);

		if (ret != 6)
			break;

		if (!is_valid_ether_addr(macaddr)) {
			shift += 3*ETH_ALEN;
			continue;
		}

		mac_new = kmalloc(sizeof(struct vfd_macaddr), GFP_KERNEL);
		if (!mac_new) {
			ret = -ENOMEM;
			goto err_free;
		}

		ether_addr_copy(mac_new->mac, macaddr);
		list_add(&mac_new->list, &mac_list_inp);

		shift += 3*ETH_ALEN;
	}

	if (add)
		ret = vfd_ops->add_macs_to_list(pdev, vf_id, &mac_list_inp);
	else
		ret = vfd_ops->rem_macs_from_list(pdev, vf_id, &mac_list_inp);

err_free:
        list_for_each_safe(pos, n, &mac_list_inp) {
                struct vfd_macaddr *mac = NULL;

                mac = list_entry(pos, struct vfd_macaddr, list);
                list_del(pos);
                kfree(mac);
        }
	return ret ? ret : count;
}

/**
 * vfd_promisc_show - handler for promisc show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_promisc_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u8 data;

	if (!vfd_ops->get_promisc)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_promisc(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data == VFD_PROMISC_UNICAST)
		ret = scnprintf(buff, PAGE_SIZE, "ucast\n");
	else if (data == VFD_PROMISC_MULTICAST)
		ret = scnprintf(buff, PAGE_SIZE, "mcast\n");
	else if (data == (VFD_PROMISC_UNICAST | VFD_PROMISC_MULTICAST))
		ret = scnprintf(buff, PAGE_SIZE, "ucast, mcast\n");
	else if (data == VFD_PROMISC_OFF)
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_promisc_store - handler for promisc store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_promisc_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buff, size_t count)
{
	u8 data_new, data_old;
	struct pci_dev *pdev;
	const char *subcmd;
	const char *cmd;
	int vf_id, ret;

	if (!vfd_ops->get_promisc || !vfd_ops->set_promisc)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_promisc(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_promisc_input(buff, count, &cmd, &subcmd);
	if (ret)
		goto promisc_err;

	if (strncmp(cmd, "add", strlen("add")) == 0) {
		if (strncmp(subcmd, "ucast", strlen("ucast")) == 0)
			data_new = data_old | VFD_PROMISC_UNICAST;
		else if (strncmp(subcmd, "mcast", strlen("mcast")) == 0)
			data_new = data_old | VFD_PROMISC_MULTICAST;
		else
			goto promisc_err;
	} else if (strncmp(cmd, "rem", strlen("rem")) == 0) {
		if (strncmp(subcmd, "ucast", strlen("ucast")) == 0)
			data_new = data_old & ~VFD_PROMISC_UNICAST;
		else if (strncmp(subcmd, "mcast", strlen("mcast")) == 0)
			data_new = data_old & ~VFD_PROMISC_MULTICAST;
		else
			goto promisc_err;
	} else {
		goto promisc_err;
	}

	if (data_new != data_old)
		ret = vfd_ops->set_promisc(pdev, vf_id, data_new);

	return ret ? ret : count;

promisc_err:
	dev_err(&pdev->dev, "Invalid input string");
	return -EINVAL;
}

/**
 * vfd_vlan_strip_show - handler for vlan_strip show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_vlan_strip_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data;

	if (!vfd_ops->get_vlan_strip)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vlan_strip(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_vlan_strip_store - handler for vlan_strip store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_vlan_strip_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool data_new, data_old;

	if (!vfd_ops->set_vlan_strip || !vfd_ops->get_vlan_strip)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vlan_strip(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "vlan_strip", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_vlan_strip(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_link_state_show - handler for link_state show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_link_state_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	enum vfd_link_speed link_speed;
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	bool enabled;

	if (!vfd_ops->get_link_state)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_link_state(pdev, vf_id, &enabled, &link_speed);
	if (ret < 0)
		return ret;

	if (enabled) {
		const char *speed_str;

		switch (link_speed) {
		case VFD_LINK_SPEED_100MB:
			speed_str = "100 Mbps";
			break;
		case VFD_LINK_SPEED_1GB:
			speed_str = "1 Gbps";
			break;
		case VFD_LINK_SPEED_2_5GB:
			speed_str = "2.5 Gbps";
			break;
		case VFD_LINK_SPEED_5GB:
			speed_str = "5 Gbps";
			break;
		case VFD_LINK_SPEED_10GB:
			speed_str = "10 Gbps";
			break;
		case VFD_LINK_SPEED_40GB:
			speed_str = "40 Gbps";
			break;
		case VFD_LINK_SPEED_20GB:
			speed_str = "20 Gbps";
			break;
		case VFD_LINK_SPEED_25GB:
			speed_str = "25 Gbps";
			break;
		case VFD_LINK_SPEED_UNKNOWN:
			speed_str = "unknown speed";
			break;
		default:
			dev_err(&pdev->dev, "Link speed is not supported");
			return -EOPNOTSUPP;
		}

		ret = scnprintf(buff, PAGE_SIZE, "%s, %s\n", "up", speed_str);
	} else {
		ret = scnprintf(buff, PAGE_SIZE, "down\n");
	}

	return ret;
}

/**
 * vfd_link_state_store - handler for link_state store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_link_state_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u8 data;

	if (!vfd_ops->set_link_state)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	if (sysfs_streq("enable", buff)) {
		data = VFD_LINKSTATE_ON;
	} else if (sysfs_streq("disable", buff)) {
		data = VFD_LINKSTATE_OFF;
	} else if (sysfs_streq("auto", buff)) {
		data = VFD_LINKSTATE_AUTO;
	} else {
		dev_err(&pdev->dev, "Invalid input string");
		return -EINVAL;
	}

	ret = vfd_ops->set_link_state(pdev, vf_id, data);

	return ret ? ret : count;
}

/**
 * vfd_enable_show - handler for VF enable/disable show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_enable_show(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	bool data;

	if (!vfd_ops->get_vf_enable)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vf_enable(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_enable_store - handler for VF enable/disable store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_enable_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buff, size_t count)
{
	bool data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_vf_enable || !vfd_ops->get_vf_enable)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vf_enable(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "enable", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_vf_enable(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_max_tx_rate_show - handler for mac_tx_rate show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_max_tx_rate_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buff)
{
	unsigned int max_tx_rate;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->get_max_tx_rate)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_max_tx_rate(pdev, vf_id, &max_tx_rate);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%u\n", max_tx_rate);
	return ret;
}

/**
 * vfd_max_tx_rate_store - handler for max_tx_rate store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_max_tx_rate_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	unsigned int max_tx_rate;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_max_tx_rate)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = kstrtouint(buff, 10, &max_tx_rate);
	if (ret) {
		dev_err(&pdev->dev,
			"Invalid argument, not a decimal number: %s", buff);
		return ret;
	}

	ret = vfd_ops->set_max_tx_rate(pdev, vf_id, &max_tx_rate);

	return ret ? ret : count;
}

/**
 * vfd_min_tx_rate_show - handler for min_tx_rate show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_min_tx_rate_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buff)
{
	if (!vfd_ops->get_min_tx_rate)
		return -EOPNOTSUPP;

	return vfd_ops->get_min_tx_rate(kobj, attr, buff);
}

/**
 * vfd_min_tx_rate_store - handler for min_tx_rate store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_min_tx_rate_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	if (!vfd_ops->set_min_tx_rate)
		return -EOPNOTSUPP;

	return vfd_ops->set_min_tx_rate(kobj, attr, buff, count);
}

/**
 * vfd_trust_show - handler for trust show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_trust_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	bool data;

	if (!vfd_ops->get_trust_state)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_trust_state(pdev, vf_id, &data);
	if (ret)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_trust_store - handler for trust store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_trust_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buff, size_t count)
{
	bool data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_trust_state || !vfd_ops->get_trust_state)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_trust_state(pdev, vf_id, &data_old);
	if (ret)
		return ret;

	ret = __parse_bool_data(pdev, buff, "trust", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_trust_state(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_reset_stats_store - handler for reset stats store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_reset_stats_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	int vf_id, reset, ret;
	struct pci_dev *pdev;

	if (!vfd_ops->reset_stats)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;
	ret = kstrtoint(buff, 10, &reset);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	if (reset != 1)
		return -EINVAL;

	ret = vfd_ops->reset_stats(pdev, vf_id);

	return ret ? ret : count;
}

/**
 * vfd_rx_bytes_show - handler for rx_bytes show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_rx_bytes_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_rx_bytes)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_rx_bytes(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_rx_dropped_show - handler for rx_dropped show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_rx_dropped_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_rx_dropped)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_rx_dropped(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_rx_packets_show - handler for rx_packets show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_rx_packets_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_rx_packets)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_rx_packets(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_tx_bytes_show - handler for tx_bytes show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_tx_bytes_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_tx_bytes)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_tx_bytes(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_tx_dropped_show - handler for tx_dropped show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_tx_dropped_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_tx_dropped)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_tx_dropped(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_tx_packets_show - handler for tx_packets show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_tx_packets_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_tx_packets)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_tx_packets(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_tx_spoofed_show - handler for tx_spoofed show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_tx_spoofed_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_tx_spoofed)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_tx_spoofed(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * vfd_tx_errors_show - handler for tx_errors show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_tx_errors_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u64 data;

	if (!vfd_ops->get_tx_errors)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_tx_errors(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%llu\n", data);

	return ret;
}

/**
 * qos_share_show - handler for the bw_share show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t qos_share_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	u8 data = 0;

	if (!vfd_ops->get_vf_bw_share)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj->parent, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_vf_bw_share(pdev, vf_id, &data);
	if (ret < 0) {
		dev_err(&pdev->dev, "No bw share applied for VF %d\n", vf_id);
		return ret;
	}

	ret = scnprintf(buff, PAGE_SIZE, "%u\n", data);

	return ret;
}

/**
 * qos_share_store - handler for the bw_share store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t qos_share_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	u8 bw_share;

	if (!vfd_ops->set_vf_bw_share)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj->parent, &pdev, &vf_id);
	if (ret)
		return ret;

	/* parse the bw_share */
	ret = kstrtou8(buff, 10, &bw_share);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	/* check that the BW is between 1 and 100 */
	if (bw_share < 1 || bw_share > 100) {
		dev_err(&pdev->dev, "BW share has to be between 1-100\n");
		return -EINVAL;
	}
	ret = vfd_ops->set_vf_bw_share(pdev, vf_id, bw_share);
	return ret ? ret : count;
}

/**
 * pf_qos_apply_store - handler for pf qos apply store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t pf_qos_apply_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	int ret, apply;
	struct pci_dev *pdev;

	if (!vfd_ops->set_pf_qos_apply)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj->parent, &pdev);
	if (ret)
		return ret;

	ret = kstrtoint(buff, 10, &apply);
	if (ret) {
		dev_err(&pdev->dev,
			"Invalid input\n");
		return ret;
	}

	if (apply != 1)
		return -EINVAL;

	ret = vfd_ops->set_pf_qos_apply(pdev);

	return ret ? ret : count;
}

/**
 * pf_ingress_mirror_show - handler for PF ingress mirror show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_ingress_mirror_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int ret, data;

	if (!vfd_ops->get_pf_ingress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_ingress_mirror(pdev, &data);
	if (ret < 0)
		return ret;

	if (data == VFD_INGRESS_MIRROR_OFF)
		ret = scnprintf(buff, PAGE_SIZE, "off\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "%u\n", data);

	return ret;
}

/**
 * pf_ingress_mirror_store - handler for pf ingress mirror store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t pf_ingress_mirror_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buff, size_t count)
{
	int data_new, data_old;
	struct pci_dev *pdev;
	int ret;

	if (!vfd_ops->set_pf_ingress_mirror || !vfd_ops->get_pf_ingress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_ingress_mirror(pdev, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_egress_ingress_input(pdev, buff, "ingress_mirror",
					   &data_new, &data_old);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_pf_ingress_mirror(pdev, data_new);

	return ret ? ret : count;
}

/**
 * pf_egress_mirror_show - handler for PF egress mirror show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_egress_mirror_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int ret, data;

	if (!vfd_ops->get_pf_egress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_egress_mirror(pdev, &data);
	if (ret < 0)
		return ret;

	if (data == VFD_EGRESS_MIRROR_OFF)
		ret = scnprintf(buff, PAGE_SIZE, "off\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "%u\n", data);

	return ret;
}

/**
 * pf_egress_mirror_store - handler for pf egress mirror store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t pf_egress_mirror_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buff, size_t count)
{
	int data_new, data_old;
	struct pci_dev *pdev;
	int ret;

	if (!vfd_ops->set_pf_egress_mirror || !vfd_ops->get_pf_egress_mirror)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_egress_mirror(pdev, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_egress_ingress_input(pdev, buff, "egress_mirror",
					   &data_new, &data_old);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_pf_egress_mirror(pdev, data_new);

	return ret ? ret : count;
}

/**
 * pf_tpid_show - handler for pf tpid show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_tpid_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	u16 data;
	int ret;

	if (!vfd_ops->get_pf_tpid)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_tpid(pdev, &data);
	if (ret < 0)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%x\n", data);

	return ret;
}

/**
 * pf_tpid_store - handler for pf tpid store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t pf_tpid_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buff, size_t count)
{
	struct pci_dev *pdev;
	u16 data;
	int ret;

	if (!vfd_ops->set_pf_tpid)
		return -EOPNOTSUPP;

	ret = __get_pf_pdev(kobj, &pdev);
	if (ret)
		return ret;

	ret = kstrtou16(buff, 16, &data);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	ret = vfd_ops->set_pf_tpid(pdev, data);

	return ret ? ret : count;
}

/**
 * vfd_num_queues_show - handler for num_queues show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_num_queues_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	int data;

	if (!vfd_ops->get_num_queues)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_num_queues(pdev, vf_id, &data);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%d\n", data);

	return ret;
}

/**
 * vfd_num_queues_store - handler for num_queues store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_num_queues_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	int data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_num_queues)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_num_queues(pdev, vf_id, &data_old);
	if (ret)
		return ret;

	ret = kstrtoint(buff, 10, &data_new);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	if (data_new < 1) {
		dev_err(&pdev->dev, "VF queue count must be at least 1\n");
		return -EINVAL;
	}

	if (data_new != data_old)
		ret = vfd_ops->set_num_queues(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * vfd_queue_type_show - handler for queue_type show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_queue_type_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret = 0;
	u8 data;

	if (!vfd_ops->get_queue_type)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_queue_type(pdev, vf_id, &data);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%d\n", data);

	return ret;
}

/**
 * vfd_queue_type_store - handler for queue_type store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 **/
static ssize_t vfd_queue_type_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	// the setting will be updated via different sysfs
	return -EOPNOTSUPP;
}

/**
 * vfd_allow_bcast_show - handler for VF allow broadcast show function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vfd_allow_bcast_show(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    char *buff)
{
	struct pci_dev *pdev;
	int vf_id, ret;
	bool data;

	if (!vfd_ops->get_allow_bcast)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_allow_bcast(pdev, vf_id, &data);
	if (ret < 0)
		return ret;

	if (data)
		ret = scnprintf(buff, PAGE_SIZE, "on\n");
	else
		ret = scnprintf(buff, PAGE_SIZE, "off\n");

	return ret;
}

/**
 * vfd_allow_bcast_store - handler for VF allow broadcast store function
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_allow_bcast_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	bool data_new, data_old;
	struct pci_dev *pdev;
	int vf_id, ret;

	if (!vfd_ops->set_allow_bcast || !vfd_ops->get_allow_bcast)
		return -EOPNOTSUPP;

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
	if (ret)
		return ret;

	ret = vfd_ops->get_allow_bcast(pdev, vf_id, &data_old);
	if (ret < 0)
		return ret;

	ret = __parse_bool_data(pdev, buff, "allow_bcast", &data_new);
	if (ret)
		return ret;

	if (data_new != data_old)
		ret = vfd_ops->set_allow_bcast(pdev, vf_id, data_new);

	return ret ? ret : count;
}

/**
 * round_nearest_quanta - helper function for calculating quanta
 * @num:	Number to be rounded
 *
 * Calculates nearest multiple of 50, which is quanta accepted by FW.
 * For 0 it returns 0, which means unlimitied bandwidth
 **/
static int round_nearest_quanta(int num)
{
	static const int base = 50;

	if (!(num % base) || !num)
		return num;
	else
		return num + base - (num % base);
}

/**
 * pf_qos_tc_priority_show - handler for PF's priority for given TC show
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_qos_tc_priority_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int i, tc, ret;
	char *written;
	u8 prio;

	/* check if option is implemented in vfd_ops*/
	if (!vfd_ops->set_pf_qos_tc_priority ||
	    !vfd_ops->get_pf_qos_tc_priority)
		return -EOPNOTSUPP;

	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_qos_tc_priority(pdev, tc, &prio);

	if (!prio)
		return ret;

	written = buff;
	/* iterate over prio bits */
	for (i = 0; i < 8; i++) {
		if (BIT(i) & prio) {
			ret += scnprintf(written, PAGE_SIZE, "%d,", i);
			written += 2;
		}
	}
	ret += scnprintf(written, PAGE_SIZE, "\n");
	return ret;
}

/**
 * pf_qos_tc_priority_store - handler for PF's priority for given TC store
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t pf_qos_tc_priority_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int tc, tmp, ret;
	char *tok, *str;
	u8 prio = 0;

	/* check if option is implemented in vfd_ops*/
	if (!vfd_ops->set_pf_qos_tc_priority ||
	    !vfd_ops->get_pf_qos_tc_priority)
		return -EOPNOTSUPP;

	str = kzalloc(sizeof(*str) * count + 1, GFP_KERNEL);
	if (!str)
		return -ENOMEM;

	strncpy(str, buff, count);
	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		goto err;

	while ((tok = strsep(&str, ",")) != NULL) {
		tok = strim(tok);

		ret = kstrtoint(tok, 10, &tmp);
		if (ret) {
			dev_err(&pdev->dev, "Invalid input\n");
			goto err;
		}

		if (tmp < 0 || tmp >= VFD_NUM_TC) {
			dev_err(&pdev->dev, "Only numbers 0-7 are allowed.\n");
			ret = -EINVAL;
			goto err;
		}
		prio |= BIT(tmp);
	}
	vfd_ops->set_pf_qos_tc_priority(pdev, tc, prio);

	kfree(str);
	return count;

err:
	kfree(str);
	return ret;
}

/**
 * pf_qos_tc_lsp_show - handler for PF's link strict priority for given TC show
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_qos_tc_lsp_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int tc, ret;
	bool lsp;

	/* check if option is implemented in vfd_ops*/
	if (!vfd_ops->set_pf_qos_tc_lsp || !vfd_ops->get_pf_qos_tc_lsp)
		return -EOPNOTSUPP;

	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_qos_tc_lsp(pdev, tc, &lsp);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, lsp ? "on\n" : "off\n");

	return ret;
}

/**
 * pf_qos_tc_lsp_store - handler for PF link strict priority for given TC store
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t pf_qos_tc_lsp_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int tc, ret;
	bool lsp;

	/* check if option is implemented in vfd_ops*/
	if (!vfd_ops->set_pf_qos_tc_lsp || !vfd_ops->get_pf_qos_tc_lsp)
		return -EOPNOTSUPP;

	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		return ret;

	__parse_bool_data(pdev, buff, "lsp", &lsp);

	ret = vfd_ops->set_pf_qos_tc_lsp(pdev, tc, lsp);
	if (ret) {
		dev_err(&pdev->dev, "Failed to store PF QoS lsp value.\n");
		return ret;
	}

	return count;
}

/**
 * pf_qos_tc_max_bw_show - handler for PF's max bandwidth for given TC show
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t pf_qos_tc_max_bw_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int tc, ret;
	u16 max_bw;

	if (!vfd_ops->set_pf_qos_tc_max_bw || !vfd_ops->get_pf_qos_tc_max_bw)
		return -EOPNOTSUPP;

	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		return ret;

	ret = vfd_ops->get_pf_qos_tc_max_bw(pdev, tc, &max_bw);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%d\n", max_bw);

	return ret;
}

/**
 * pf_qos_tc_max_bw_store - handler for PF's max bandwidth for given TC store
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t pf_qos_tc_max_bw_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int tc, ret;
	u16 bw;

	if (!vfd_ops->set_pf_qos_tc_max_bw || !vfd_ops->get_pf_qos_tc_max_bw)
		return -EOPNOTSUPP;

	ret = __get_pdev_tc(kobj, &pdev, &tc);
	if (ret)
		return ret;

	ret = kstrtou16(buff, 10, &bw);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	ret = vfd_ops->set_pf_qos_tc_max_bw(pdev, tc,
					    round_nearest_quanta(bw));
	if (ret)
		return ret;

	return count;
}

/**
 * vf_max_tc_tx_rate_show - handler for VF's max per TC tx rate show
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vf_max_tc_tx_rate_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buff)
{
	int tc, vf_id, tc_tx_rate, ret;
	struct pci_dev *pdev;

	if (!vfd_ops->set_vf_max_tc_tx_rate || !vfd_ops->get_vf_max_tc_tx_rate)
		return -EOPNOTSUPP;

	ret = __get_vf_tc_pdev(kobj, &pdev, &vf_id, &tc);
	if (ret)
		return ret;

	ret = vfd_ops->get_vf_max_tc_tx_rate(pdev, vf_id, tc, &tc_tx_rate);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%d\n", tc_tx_rate);
	return ret;
}

/**
 * vf_max_tc_tx_rate_store - handler for VF's max per TC tx rate store
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vf_max_tc_tx_rate_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buff, size_t count)
{
	int tc, vf_id, tc_tx_rate, ret;
	struct pci_dev *pdev;

	if (!vfd_ops->set_vf_max_tc_tx_rate || !vfd_ops->get_vf_max_tc_tx_rate)
		return -EOPNOTSUPP;

	ret = __get_vf_tc_pdev(kobj, &pdev, &vf_id, &tc);
	if (ret)
		return ret;
	ret = kstrtoint(buff, 10, &tc_tx_rate);
	if (ret) {
		dev_err(&pdev->dev,
			"Invalid input, provide bandwidth as number.\n");
		return ret;
	}

	ret = vfd_ops->set_vf_max_tc_tx_rate(pdev, vf_id, tc,
					     round_nearest_quanta(tc_tx_rate));
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to assign max TC tx rate.\n");
		return ret;
	}

	return count;
}

/**
 * vf_qos_tc_share_show - handler for VF bandwidth share per TC show
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer for data
 **/
static ssize_t vf_qos_tc_share_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buff)
{
	struct pci_dev *pdev;
	int tc, vf_id, ret;
	u8 share;

	if (!vfd_ops->set_vf_qos_tc_share || !vfd_ops->get_vf_qos_tc_share)
		return -EOPNOTSUPP;

	ret = __get_vf_tc_pdev(kobj, &pdev, &vf_id, &tc);
	if (ret)
		return ret;

	ret = vfd_ops->get_vf_qos_tc_share(pdev, vf_id, tc, &share);
	if (ret)
		return ret;

	ret = scnprintf(buff, PAGE_SIZE, "%d\n", share);
	return ret;
}

/**
 * vf_qos_tc_share_store - handler for VF bandwidth share per TC store
 * @kobj:	kobject being called
 * @attr:	struct kobj_attribute
 * @buff:	buffer with input data
 * @count:	size of buff
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vf_qos_tc_share_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buff, size_t count)
{
	struct pci_dev *pdev;
	int tc, vf_id, ret;
	u8 share;

	if (!vfd_ops->set_vf_qos_tc_share || !vfd_ops->get_vf_qos_tc_share)
		return -EOPNOTSUPP;

	ret = __get_vf_tc_pdev(kobj, &pdev, &vf_id, &tc);
	if (ret)
		return ret;

	ret = kstrtou8(buff, 10, &share);
	if (ret) {
		dev_err(&pdev->dev, "Invalid input\n");
		return ret;
	}

	if (share > 100) {
		dev_err(&pdev->dev, "Share must be in range 0-100.\n");
		return -EINVAL;
	}

	ret = vfd_ops->set_vf_qos_tc_share(pdev, vf_id, tc, share);
	if (ret)
		return ret;

	return count;
}

static struct kobj_attribute trunk_attribute =
	__ATTR(trunk, 0644, vfd_trunk_show, vfd_trunk_store);
static struct kobj_attribute vlan_mirror_attribute =
	__ATTR(vlan_mirror, 0644, vfd_vlan_mirror_show, vfd_vlan_mirror_store);
static struct kobj_attribute egress_mirror_attribute =
	__ATTR(egress_mirror, 0644,
	       vfd_egress_mirror_show, vfd_egress_mirror_store);
static struct kobj_attribute ingress_mirror_attribute =
	__ATTR(ingress_mirror, 0644,
	       vfd_ingress_mirror_show, vfd_ingress_mirror_store);
static struct kobj_attribute mac_anti_spoof_attribute =
	__ATTR(mac_anti_spoof, 0644,
	       vfd_mac_anti_spoof_show, vfd_mac_anti_spoof_store);
static struct kobj_attribute vlan_anti_spoof_attribute =
	__ATTR(vlan_anti_spoof, 0644,
	       vfd_vlan_anti_spoof_show, vfd_vlan_anti_spoof_store);
static struct kobj_attribute allow_untagged_attribute =
	__ATTR(allow_untagged, 0644,
	       vfd_allow_untagged_show, vfd_allow_untagged_store);
static struct kobj_attribute loopback_attribute =
	__ATTR(loopback, 0644, vfd_loopback_show, vfd_loopback_store);
static struct kobj_attribute mac_attribute =
	__ATTR(mac, 0644, vfd_mac_show, vfd_mac_store);
static struct kobj_attribute mac_list_attribute =
	__ATTR(mac_list, 0644, vfd_mac_list_show, vfd_mac_list_store);
static struct kobj_attribute promisc_attribute =
	__ATTR(promisc, 0644, vfd_promisc_show, vfd_promisc_store);
static struct kobj_attribute vlan_strip_attribute =
	__ATTR(vlan_strip, 0644, vfd_vlan_strip_show, vfd_vlan_strip_store);
static struct kobj_attribute link_state_attribute =
	__ATTR(link_state, 0644, vfd_link_state_show, vfd_link_state_store);
static struct kobj_attribute max_tx_rate_attribute =
	__ATTR(max_tx_rate, 0644, vfd_max_tx_rate_show, vfd_max_tx_rate_store);
static struct kobj_attribute min_tx_rate_attribute =
	__ATTR(min_tx_rate, 0644, vfd_min_tx_rate_show, vfd_min_tx_rate_store);
static struct kobj_attribute trust_attribute =
	__ATTR(trust, 0644, vfd_trust_show, vfd_trust_store);
static struct kobj_attribute reset_stats_attribute =
	__ATTR(reset_stats, 0200, NULL, vfd_reset_stats_store);
static struct kobj_attribute enable_attribute =
	__ATTR(enable, 0644, vfd_enable_show, vfd_enable_store);
static struct kobj_attribute num_queues_attribute =
	__ATTR(num_queues, 0644, vfd_num_queues_show, vfd_num_queues_store);
static struct kobj_attribute queue_type_attribute =
	__ATTR(queue_type, 0644, vfd_queue_type_show, vfd_queue_type_store);
static struct kobj_attribute allow_bcast_attribute =
	__ATTR(allow_bcast, 0644, vfd_allow_bcast_show, vfd_allow_bcast_store);

static struct attribute *s_attrs[] = {
	&trunk_attribute.attr,
	&vlan_mirror_attribute.attr,
	&egress_mirror_attribute.attr,
	&ingress_mirror_attribute.attr,
	&mac_anti_spoof_attribute.attr,
	&vlan_anti_spoof_attribute.attr,
	&allow_untagged_attribute.attr,
	&loopback_attribute.attr,
	&mac_attribute.attr,
	&mac_list_attribute.attr,
	&promisc_attribute.attr,
	&vlan_strip_attribute.attr,
	&link_state_attribute.attr,
	&max_tx_rate_attribute.attr,
	&min_tx_rate_attribute.attr,
	&trust_attribute.attr,
	&reset_stats_attribute.attr,
	&enable_attribute.attr,
	&num_queues_attribute.attr,
	&queue_type_attribute.attr,
	&allow_bcast_attribute.attr,
	NULL,
};

static struct attribute_group vfd_group = {
	.attrs = s_attrs,
};

static struct kobj_attribute rx_bytes_attribute =
	__ATTR(rx_bytes, 0444, vfd_rx_bytes_show, NULL);
static struct kobj_attribute rx_dropped_attribute =
	__ATTR(rx_dropped, 0444, vfd_rx_dropped_show, NULL);
static struct kobj_attribute rx_packets_attribute =
	__ATTR(rx_packets, 0444, vfd_rx_packets_show, NULL);
static struct kobj_attribute tx_bytes_attribute =
	__ATTR(tx_bytes, 0444, vfd_tx_bytes_show, NULL);
static struct kobj_attribute tx_dropped_attribute =
	__ATTR(tx_dropped, 0444, vfd_tx_dropped_show, NULL);
static struct kobj_attribute tx_packets_attribute =
	__ATTR(tx_packets, 0444, vfd_tx_packets_show, NULL);
static struct kobj_attribute tx_spoofed_attribute =
	__ATTR(tx_spoofed, 0444, vfd_tx_spoofed_show, NULL);
static struct kobj_attribute tx_errors_attribute =
	__ATTR(tx_errors, 0444, vfd_tx_errors_show, NULL);

static struct attribute *stats_attrs[] = {
	&rx_bytes_attribute.attr,
	&rx_dropped_attribute.attr,
	&rx_packets_attribute.attr,
	&tx_bytes_attribute.attr,
	&tx_dropped_attribute.attr,
	&tx_packets_attribute.attr,
	&tx_spoofed_attribute.attr,
	&tx_errors_attribute.attr,
	NULL,
};

static struct attribute_group stats_group = {
	.name = "stats",
	.attrs = stats_attrs,
};

static struct kobj_attribute share_attribute =
	__ATTR(share, 0644, qos_share_show, qos_share_store);

static struct attribute *qos_attrs[] = {
	&share_attribute.attr,
	NULL,
};

static struct attribute_group qos_group = {
	.attrs = qos_attrs,
};

static struct kobj_attribute apply_attribute =
	__ATTR(apply, 0200, NULL, pf_qos_apply_store);

static struct attribute *pf_qos_attrs[] = {
	&apply_attribute.attr,
	NULL,
};

static struct attribute_group pf_qos_group = {
	.attrs = pf_qos_attrs,
};

static struct kobj_attribute pf_ingress_mirror_attribute =
	__ATTR(ingress_mirror, 0644, pf_ingress_mirror_show, pf_ingress_mirror_store);
static struct kobj_attribute pf_egress_mirror_attribute =
	__ATTR(egress_mirror, 0644, pf_egress_mirror_show, pf_egress_mirror_store);
static struct kobj_attribute pf_tpid_attribute =
	__ATTR(tpid, 0644, pf_tpid_show, pf_tpid_store);

static struct attribute *pf_attrs[] = {
	&pf_ingress_mirror_attribute.attr,
	&pf_egress_mirror_attribute.attr,
	&pf_tpid_attribute.attr,
	NULL,
};

static struct attribute_group pf_attr_group = {
	.attrs = pf_attrs,
};

static struct kobj_attribute vf_qos_tc_max_tc_tx_rate_attribute =
	__ATTR(max_tc_tx_rate, 0644, vf_max_tc_tx_rate_show,
	       vf_max_tc_tx_rate_store);
static struct kobj_attribute vf_qos_tc_share_attribute =
	__ATTR(share, 0644, vf_qos_tc_share_show,
	       vf_qos_tc_share_store);

static struct attribute *vf_qos_tc_attrs[] = {
	&vf_qos_tc_max_tc_tx_rate_attribute.attr,
	&vf_qos_tc_share_attribute.attr,
	NULL,
};

static struct attribute_group vf_qos_tc_group = {
	.attrs = vf_qos_tc_attrs,
};

static struct kobj_attribute pf_qos_tc_priority_attribute =
	__ATTR(priority, 0644, pf_qos_tc_priority_show,
	       pf_qos_tc_priority_store);
static struct kobj_attribute pf_qos_tc_lsp_attribute =
	__ATTR(lsp, 0644, pf_qos_tc_lsp_show, pf_qos_tc_lsp_store);
static struct kobj_attribute pf_qos_tc_max_bw_attribute =
	__ATTR(max_bw, 0644, pf_qos_tc_max_bw_show, pf_qos_tc_max_bw_store);

static struct attribute *pf_qos_tc_attrs[] = {
	&pf_qos_tc_priority_attribute.attr,
	&pf_qos_tc_lsp_attribute.attr,
	&pf_qos_tc_max_bw_attribute.attr,
	NULL,
};

static struct attribute_group pf_qos_tc_group = {
	.attrs = pf_qos_tc_attrs,
};

/**
 * create_qos_tc_sysfs - create sysfs hierarchy for PF QOS traffic classes.
 * @pdev:       PCI device information struct
 * @tc:		Pointer to preallocated array of 8 kobjects.
 * @parent:     QOS parent
 * @attr_group:	attribute group to assign to tc kobject
 *
 * Creates a kobject for PF QOS traffic classes and assigns attributes to it.
 * Assumes mem is preallocated
 **/
static int create_qos_tc_sysfs(struct pci_dev *pdev, struct kobject **tc,
			       struct kobject *parent,
			       struct attribute_group *attr_group)
{
	struct kobject *pf_qos_tc;
	char kname[2];
	int ret, i;

	for (i = 0; i < VFD_NUM_TC; i++) {
		int length = snprintf(kname, sizeof(kname), "%d", i);

		if (length >= sizeof(kname)) {
			dev_err(&pdev->dev,
				"cannot request %d tcs, try again with smaller number of vfs\n",
				i);
			--i;
			ret = -EINVAL;
			goto err_qos_tc_sysfs;
		}
		pf_qos_tc = kobject_create_and_add(kname, parent);

		if (!pf_qos_tc) {
			dev_err(&pdev->dev,
				"failed to create VF kobj: %s\n", kname);
			i--;
			ret = -ENOMEM;
			goto err_qos_tc_sysfs;
		}
		dev_info(&pdev->dev, "created VF %s sysfs", parent->name);
		tc[i] = pf_qos_tc;

		/* create VF sys attr */
		ret = sysfs_create_group(tc[i], attr_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create PF QOS TC attributes: %d",
				i);
			goto err_qos_tc_sysfs;
		}
	}

	return 0;
err_qos_tc_sysfs:
	for (; i >= 0; i--)
		kobject_put(tc[i]);
	return ret;
}

/**
 * create_vfs_sysfs - create sysfs hierarchy for VF
 * @pdev:	PCI device information struct
 * @vfd_obj:	VF-d kobjects information struct
 *
 * Creates a kobject for Virtual Function and assigns attributes to it.
 **/
static int create_vfs_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj)
{
	struct kobject *vf_kobj;
	struct vfd_vf_obj *vfs;
	char kname[4];
	int ret, i;

	for (i = 0; i < vfd_obj->num_vfs; i++) {
		int length = snprintf(kname, sizeof(kname), "%d", i);

		if (length >= sizeof(kname)) {
			dev_err(&pdev->dev,
				"cannot request %d vfs, try again with smaller number of vfs\n",
				i);
			--i;
			ret = -EINVAL;
			goto err_vfs_sysfs;
		}

		vfs = &vfd_obj->vfs[i];

		vf_kobj = kobject_create_and_add(kname, vfd_obj->sriov_kobj);
		if (!vf_kobj) {
			dev_err(&pdev->dev,
				"failed to create VF kobj: %s\n", kname);
			i--;
			ret = -ENOMEM;
			goto err_vfs_sysfs;
		}
		dev_info(&pdev->dev, "created VF %s sysfs", vf_kobj->name);
		vfs->vf_kobj = vf_kobj;

		vfs->vf_qos_kobj = kobject_create_and_add("qos", vfs->vf_kobj);
		create_qos_tc_sysfs(pdev, vfs->vf_tc_kobjs, vfs->vf_qos_kobj,
				    &vf_qos_tc_group);

		/* create VF sys attr */
		ret = sysfs_create_group(vfs->vf_kobj, &vfd_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF sys attribute: %d",
				i);
			goto err_vfs_sysfs;
		}
		/* create VF stats sys attr */
		ret = sysfs_create_group(vfs->vf_kobj, &stats_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF stats attribute: %d",
				i);
			goto err_vfs_sysfs;
		}

		/* create VF qos sys attr */
		ret = sysfs_create_group(vfs->vf_qos_kobj, &qos_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF qos attribute: %d",
				i);
			goto err_vfs_sysfs;
		}
	}

	return 0;

err_vfs_sysfs:
	for (; i >= 0; i--)
		kobject_put(vfd_obj->vfs[i].vf_kobj);
	return ret;
}

/**
 * create_vfd_sysfs - create sysfs hierarchy used by VF-d
 * @pdev:		PCI device information struct
 * @num_alloc_vfs:	number of VFs to allocate
 *
 * If the kobjects were not able to be created, NULL will be returned.
 **/
struct vfd_objects *create_vfd_sysfs(struct pci_dev *pdev, int num_alloc_vfs)
{
	struct vfd_qos_objects *qos_objs;
	struct vfd_objects *vfd_obj;
	int ret;

	vfd_obj = kzalloc(sizeof(*vfd_obj), GFP_KERNEL);
	if (!vfd_obj)
		return NULL;

	qos_objs = kzalloc(sizeof(*qos_objs), GFP_KERNEL);
	if (!qos_objs)
		goto err_qos;

	vfd_obj->vfs = kcalloc(num_alloc_vfs, sizeof(*vfd_obj->vfs),
			       GFP_KERNEL);
	if (!vfd_obj->vfs)
		goto err_vfs;

	vfd_obj->qos = qos_objs;
	vfd_obj->num_vfs = num_alloc_vfs;
	vfd_obj->sriov_kobj = kobject_create_and_add("sriov", &pdev->dev.kobj);
	if (!vfd_obj->sriov_kobj)
		goto err_sysfs;
	dev_info(&pdev->dev, "created %s sysfs", vfd_obj->sriov_kobj->name);

	qos_objs->qos_kobj = kobject_create_and_add("qos",
						    vfd_obj->sriov_kobj);
	if (!qos_objs->qos_kobj) {
		dev_err(&pdev->dev, "failed to create VF qos pf kobject");
		goto err_pf_qos;
	}

	ret = create_vfs_sysfs(pdev, vfd_obj);
	if (ret)
		goto err_pf_qos;

	create_qos_tc_sysfs(pdev, qos_objs->pf_qos_kobjs, qos_objs->qos_kobj,
			    &pf_qos_tc_group);
	/* create PF qos sys attr */
	ret = sysfs_create_group(qos_objs->qos_kobj, &pf_qos_group);
	if (ret) {
		dev_err(&pdev->dev, "failed to create PF qos sys attribute");
		goto err_pf_qos;
	}

	/* create PF attrs */
	ret = sysfs_create_group(vfd_obj->sriov_kobj, &pf_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "failed to create PF attr sys attribute");
		goto err_pf_qos;
	}

	return vfd_obj;

err_pf_qos:
	kobject_put(vfd_obj->sriov_kobj);
err_sysfs:
	kfree(vfd_obj->vfs);
err_vfs:
	kfree(qos_objs);
err_qos:
	kfree(vfd_obj);
	return NULL;
}

static void free_vfd_vf(struct pci_dev *pdev, struct vfd_vf_obj *vf)
{
	int i;

	for (i = 0; i < VFD_NUM_TC; i++) {
		dev_dbg(&pdev->dev, "deleting VF %s tc",
			vf->vf_tc_kobjs[i]->name);
		kobject_put(vf->vf_tc_kobjs[i]);
	}

	dev_info(&pdev->dev, "deleting VF %s sysfs", vf->vf_qos_kobj->name);
	kobject_put(vf->vf_qos_kobj);
	dev_info(&pdev->dev, "deleting VF %s sysfs", vf->vf_kobj->name);
	kobject_put(vf->vf_kobj);
}

/**
 * destroy_vfd_sysfs - destroy sysfs hierarchy used by VF-d
 * @pdev:	PCI device information struct
 * @vfd_obj:	VF-d kobjects information struct
 **/
void destroy_vfd_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj)
{
	int i;

	for (i = 0; i < vfd_obj->num_vfs; i++)
		free_vfd_vf(pdev, &vfd_obj->vfs[i]);

	for (i = 0; i < VFD_NUM_TC; i++) {
		dev_info(&pdev->dev, "deleting sriov qos %s sysfs",
			 vfd_obj->qos->pf_qos_kobjs[i]->name);
		kobject_put(vfd_obj->qos->pf_qos_kobjs[i]);
	}

	dev_info(&pdev->dev, "deleting %s sysfs",
		 vfd_obj->qos->qos_kobj->name);
	kobject_put(vfd_obj->qos->qos_kobj);

	dev_info(&pdev->dev, "deleting %s sysfs", vfd_obj->sriov_kobj->name);
	kobject_put(vfd_obj->sriov_kobj);
	kfree(vfd_obj->qos);
	kfree(vfd_obj->vfs);
	kfree(vfd_obj);
}
