// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2013 - 2020 Intel Corporation. */

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

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
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

	ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
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

	ret = __get_pf_pdev(kobj, &pdev);
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
	.name = "qos",
	.attrs = qos_attrs,
};

static struct kobj_attribute apply_attribute =
	__ATTR(apply, 0200, NULL, pf_qos_apply_store);

static struct attribute *pf_qos_attrs[] = {
	&apply_attribute.attr,
	NULL,
};

static struct attribute_group pf_qos_group = {
	.name = "qos",
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

/**
 * create_vfs_sysfs - create sysfs hierarchy for VF
 * @pdev: 	PCI device information struct
 * @vfd_obj: 	VF-d kobjects information struct
 *
 * Creates a kobject for Virtual Function and assigns attributes to it.
 **/
static int create_vfs_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj)
{
	struct kobject *vf_kobj;
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

		vf_kobj = kobject_create_and_add(kname, vfd_obj->sriov_kobj);
		if (!vf_kobj) {
			dev_err(&pdev->dev,
				"failed to create VF kobj: %s\n", kname);
			i--;
			ret = -ENOMEM;
			goto err_vfs_sysfs;
		}
		dev_info(&pdev->dev, "created VF %s sysfs", vf_kobj->name);
		vfd_obj->vf_kobj[i] = vf_kobj;

		/* create VF sys attr */
		ret = sysfs_create_group(vfd_obj->vf_kobj[i], &vfd_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF sys attribute: %d", i);
			goto err_vfs_sysfs;
		}

		/* create VF stats sys attr */
		ret = sysfs_create_group(vfd_obj->vf_kobj[i], &stats_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF stats attribute: %d", i);
			goto err_vfs_sysfs;
		}

		/* create VF qos sys attr */
		ret = sysfs_create_group(vfd_obj->vf_kobj[i], &qos_group);
		if (ret) {
			dev_err(&pdev->dev, "failed to create VF qos attribute: %d", i);
			goto err_vfs_sysfs;
		}
	}

	return 0;

err_vfs_sysfs:
	for (; i >= 0; i--)
		kobject_put(vfd_obj->vf_kobj[i]);
	return ret;
}

/**
 * create_vfd_sysfs - create sysfs hierarchy used by VF-d
 * @pdev: 		PCI device information struct
 * @num_alloc_vfs: 	number of VFs to allocate
 *
 * If the kobjects were not able to be created, NULL will be returned.
 **/
struct vfd_objects *create_vfd_sysfs(struct pci_dev *pdev, int num_alloc_vfs)
{
	struct vfd_objects *vfd_obj;
	int ret;

	vfd_obj = kzalloc(sizeof(*vfd_obj) +
			  sizeof(struct kobject *)*num_alloc_vfs, GFP_KERNEL);
	if (!vfd_obj)
		return NULL;

	vfd_obj->num_vfs = num_alloc_vfs;

	vfd_obj->sriov_kobj = kobject_create_and_add("sriov", &pdev->dev.kobj);
	if (!vfd_obj->sriov_kobj)
		goto err_sysfs;

	dev_info(&pdev->dev, "created %s sysfs", vfd_obj->sriov_kobj->name);

	ret = create_vfs_sysfs(pdev, vfd_obj);
	if (ret)
		goto err_sysfs;

	/* create PF qos sys attr */
	ret = sysfs_create_group(vfd_obj->sriov_kobj, &pf_qos_group);
	if (ret) {
		dev_err(&pdev->dev, "failed to create PF qos sys attribute");
		goto err_sysfs;
	}

	/* create PF attrs */
	ret = sysfs_create_group(vfd_obj->sriov_kobj, &pf_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "failed to create PF attr sys attribute");
		goto err_sysfs;
	}
	return vfd_obj;

err_sysfs:
	kobject_put(vfd_obj->sriov_kobj);
	kfree(vfd_obj);
	return NULL;
}

/**
 * destroy_vfd_sysfs - destroy sysfs hierarchy used by VF-d
 * @pdev:	PCI device information struct
 * @vfd_obj: 	VF-d kobjects information struct
 **/
void destroy_vfd_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj)
{
	int i;

	for (i = 0; i < vfd_obj->num_vfs; i++) {
		dev_info(&pdev->dev, "deleting VF %s sysfs",
			 vfd_obj->vf_kobj[i]->name);
		kobject_put(vfd_obj->vf_kobj[i]);
	}

	dev_info(&pdev->dev, "deleting %s sysfs", vfd_obj->sriov_kobj->name);
	kobject_put(vfd_obj->sriov_kobj);
	kfree(vfd_obj);
}
