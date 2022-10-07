/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _KCOMPAT_VFD_H_
#define _KCOMPAT_VFD_H_

#define VFD_PROMISC_OFF		0x00
#define VFD_PROMISC_UNICAST	0x01
#define VFD_PROMISC_MULTICAST	0x02

#define VFD_LINKSTATE_OFF	0x00
#define VFD_LINKSTATE_ON	0x01
#define VFD_LINKSTATE_AUTO	0x02

#define VFD_EGRESS_MIRROR_OFF	-1
#define VFD_INGRESS_MIRROR_OFF	-1

#define VFD_QUEUE_TYPE_RSS	0x00
#define VFD_QUEUE_TYPE_QOS	0x01

#define VFD_NUM_TC		0x8

/**
 * struct vfd_objects - VF-d kobjects information struct
 * @num_vfs:	number of VFs allocated
 * @sriov_kobj:	pointer to the top sriov kobject
 * @vf_kobj:	array of pointer to each VF's kobjects
 */
struct vfd_objects {
	int num_vfs;
	struct kobject *sriov_kobj;
	struct vfd_vf_obj *vfs;
	struct vfd_qos_objects *qos;
};

/**
 * struct vfd_vf_obj - VF-d VF kobjects information struct
 * @vf_kobj:		pointer to VF qos kobject
 * @vf_qos_kobj:	pointer to VF kobject
 * @vf_tc_kobj:		pointer to VF TC kobjects
 */
struct vfd_vf_obj {
	struct kobject *vf_qos_kobj;
	struct kobject *vf_kobj;
	struct kobject *vf_tc_kobjs[VFD_NUM_TC];
};

/**
 * struct vfd_qos_objects - VF-d qos kobjects information struct
 * @qos_kobj:		pointer to PF qos kobject
 * @pf_qos_kobj:	pointer to PF TC kobjects
 */
struct vfd_qos_objects {
	struct kobject *qos_kobj;
	struct kobject *pf_qos_kobjs[VFD_NUM_TC];
};

struct vfd_macaddr {
	u8 mac[ETH_ALEN];
	struct list_head list;
};

#define VFD_LINK_SPEED_2_5GB_SHIFT		0x0
#define VFD_LINK_SPEED_100MB_SHIFT		0x1
#define VFD_LINK_SPEED_1GB_SHIFT		0x2
#define VFD_LINK_SPEED_10GB_SHIFT		0x3
#define VFD_LINK_SPEED_40GB_SHIFT		0x4
#define VFD_LINK_SPEED_20GB_SHIFT		0x5
#define VFD_LINK_SPEED_25GB_SHIFT		0x6
#define VFD_LINK_SPEED_5GB_SHIFT		0x7


enum vfd_link_speed {
	VFD_LINK_SPEED_UNKNOWN	= 0,
	VFD_LINK_SPEED_100MB	= BIT(VFD_LINK_SPEED_100MB_SHIFT),
	VFD_LINK_SPEED_1GB	= BIT(VFD_LINK_SPEED_1GB_SHIFT),
	VFD_LINK_SPEED_2_5GB	= BIT(VFD_LINK_SPEED_2_5GB_SHIFT),
	VFD_LINK_SPEED_5GB	= BIT(VFD_LINK_SPEED_5GB_SHIFT),
	VFD_LINK_SPEED_10GB	= BIT(VFD_LINK_SPEED_10GB_SHIFT),
	VFD_LINK_SPEED_40GB	= BIT(VFD_LINK_SPEED_40GB_SHIFT),
	VFD_LINK_SPEED_20GB	= BIT(VFD_LINK_SPEED_20GB_SHIFT),
	VFD_LINK_SPEED_25GB	= BIT(VFD_LINK_SPEED_25GB_SHIFT),
};

struct vfd_ops {
	int (*get_trunk)(struct pci_dev *pdev, int vf_id, unsigned long *buff);
	int (*set_trunk)(struct pci_dev *pdev, int vf_id,
			 const unsigned long *buff);
	int (*get_vlan_mirror)(struct pci_dev *pdev, int vf_id,
			       unsigned long *buff);
	int (*set_vlan_mirror)(struct pci_dev *pdev, int vf_id,
			       const unsigned long *buff);
	int (*get_egress_mirror)(struct pci_dev *pdev, int vf_id, int *data);
	int (*set_egress_mirror)(struct pci_dev *pdev, int vf_id,
				 const int data);
	int (*get_ingress_mirror)(struct pci_dev *pdev, int vf_id, int *data);
	int (*set_ingress_mirror)(struct pci_dev *pdev, int vf_id,
				  const int data);
	int (*get_mac_anti_spoof)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_mac_anti_spoof)(struct pci_dev *pdev, int vf_id,
				  const bool data);
	int (*get_vlan_anti_spoof)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_vlan_anti_spoof)(struct pci_dev *pdev, int vf_id,
				   const bool data);
	int (*get_allow_untagged)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_allow_untagged)(struct pci_dev *pdev, int vf_id,
				  const bool data);
	int (*get_loopback)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_loopback)(struct pci_dev *pdev, int vf_id, const bool data);
	int (*get_mac)(struct pci_dev *pdev, int vf_id, u8 *macaddr);
	int (*set_mac)(struct pci_dev *pdev, int vf_id, const u8 *macaddr);
	int (*get_mac_list)(struct pci_dev *pdev, int vf_id,
			    struct list_head *mac_list);
	int (*add_macs_to_list)(struct pci_dev *pdev, int vf_id,
				struct list_head *mac_list);
	int (*rem_macs_from_list)(struct pci_dev *pdev, int vf_id,
				  struct list_head *mac_list);
	int (*get_promisc)(struct pci_dev *pdev, int vf_id, u8 *data);
	int (*set_promisc)(struct pci_dev *pdev, int vf_id, const u8 data);
	int (*get_vlan_strip)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_vlan_strip)(struct pci_dev *pdev, int vf_id, const bool data);
	int (*get_link_state)(struct pci_dev *pdev, int vf_id, bool *enabled,
			      enum vfd_link_speed *link_speed);
	int (*set_link_state)(struct pci_dev *pdev, int vf_id, const u8 data);
	int (*get_max_tx_rate)(struct pci_dev *pdev, int vf_id,
			       unsigned int *max_tx_rate);
	int (*set_max_tx_rate)(struct pci_dev *pdev, int vf_id,
			       unsigned int *max_tx_rate);
	int (*get_min_tx_rate)(struct kobject *,
			       struct kobj_attribute *, char *);
	int (*set_min_tx_rate)(struct kobject *, struct kobj_attribute *,
			       const char *, size_t);
	int (*get_spoofcheck)(struct kobject *,
			      struct kobj_attribute *, char *);
	int (*set_spoofcheck)(struct kobject *, struct kobj_attribute *,
			      const char *, size_t);
	int (*get_trust)(struct kobject *,
			 struct kobj_attribute *, char *);
	int (*set_trust)(struct kobject *, struct kobj_attribute *,
			 const char *, size_t);
	int (*get_vf_enable)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_vf_enable)(struct pci_dev *pdev, int vf_id, const bool data);
	int (*get_rx_bytes)  (struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_rx_dropped)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_rx_packets)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_tx_bytes)  (struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_tx_dropped)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_tx_packets)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_tx_spoofed)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*get_tx_errors)(struct pci_dev *pdev, int vf_id, u64 *data);
	int (*reset_stats)(struct pci_dev *pdev, int vf_id);
	int (*set_vf_bw_share)(struct pci_dev *pdev, int vf_id, u8 bw_share);
	int (*get_vf_bw_share)(struct pci_dev *pdev, int vf_id, u8 *bw_share);
	int (*set_pf_qos_apply)(struct pci_dev *pdev);
	int (*get_pf_ingress_mirror)(struct pci_dev *pdev, int *data);
	int (*set_pf_ingress_mirror)(struct pci_dev *pdev, const int data);
	int (*get_pf_egress_mirror)(struct pci_dev *pdev, int *data);
	int (*set_pf_egress_mirror)(struct pci_dev *pdev, const int data);
	int (*get_pf_tpid)(struct pci_dev *pdev, u16 *data);
	int (*set_pf_tpid)(struct pci_dev *pdev, const u16 data);
	int (*get_num_queues)(struct pci_dev *pdev, int vf_id, int *num_queues);
	int (*set_num_queues)(struct pci_dev *pdev, int vf_id, const int num_queues);
	int (*get_trust_state)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_trust_state)(struct pci_dev *pdev, int vf_id, bool data);
	int (*get_queue_type)(struct pci_dev *pdev, int vf_id, u8 *data);
	int (*set_queue_type)(struct pci_dev *pdev, int vf_id, const u8 data);
	int (*get_allow_bcast)(struct pci_dev *pdev, int vf_id, bool *data);
	int (*set_allow_bcast)(struct pci_dev *pdev, int vf_id, const bool data);
	int (*get_pf_qos_tc_max_bw)(struct pci_dev *pdev, int tc, u16 *req_bw);
	int (*set_pf_qos_tc_max_bw)(struct pci_dev *pdev, int tc, u16 req_bw);
	int (*get_pf_qos_tc_lsp)(struct pci_dev *pdev, int tc, bool *on);
	int (*set_pf_qos_tc_lsp)(struct pci_dev *pdev, int tc, bool on);
	int (*get_pf_qos_tc_priority)(struct pci_dev *pdev, int tc,
				      char *tc_bitmap);
	int (*set_pf_qos_tc_priority)(struct pci_dev *pdev, int tc,
				      char tc_bitmap);
	int (*get_vf_qos_tc_share)(struct pci_dev *pdev, int vf_id, int tc,
				   u8 *share);
	int (*set_vf_qos_tc_share)(struct pci_dev *pdev, int vf_id, int tc,
				   u8 share);
	int (*get_vf_max_tc_tx_rate)(struct pci_dev *pdev, int vf_id, int tc,
				     int *rate);
	int (*set_vf_max_tc_tx_rate)(struct pci_dev *pdev, int vf_id, int tc,
				     int rate);
};

extern const struct vfd_ops *vfd_ops;

#endif /* _KCOMPAT_VFD_H_ */
