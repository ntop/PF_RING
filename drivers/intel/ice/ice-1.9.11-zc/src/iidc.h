/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _IIDC_H_
#define _IIDC_H_

#include <linux/dcbnl.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/auxiliary_bus.h>

/* This major and minor version represent IDC API version information.
 *
 * The concept of passing an API version should be incorporated into the
 * auxiliary drivers' probe handlers to check if they can communicate with the
 * core PCI driver. During auxiliary driver probe, auxiliary driver should
 * check major and minor version information (via iidc_core_dev_info:ver). If
 * the version check fails, the auxiliary driver should fail the probe and log
 * an appropriate message.
 */
#define IIDC_MAJOR_VER		10
#define IIDC_MINOR_VER		2

enum iidc_event_type {
	IIDC_EVENT_BEFORE_MTU_CHANGE,
	IIDC_EVENT_AFTER_MTU_CHANGE,
	IIDC_EVENT_BEFORE_TC_CHANGE,
	IIDC_EVENT_AFTER_TC_CHANGE,
	IIDC_EVENT_VF_RESET,
	IIDC_EVENT_LINK_CHNG,
	IIDC_EVENT_CRIT_ERR,
	IIDC_EVENT_FAILOVER_START,
	IIDC_EVENT_FAILOVER_FINISH,
	IIDC_EVENT_NBITS		/* must be last */
};

enum iidc_reset_type {
	IIDC_PFR,
	IIDC_CORER,
	IIDC_GLOBR,
};

enum iidc_rdma_protocol {
	IIDC_RDMA_PROTOCOL_IWARP = BIT(0),
	IIDC_RDMA_PROTOCOL_ROCEV2 = BIT(1),
};

enum iidc_rdma_gen {
	IIDC_RDMA_GEN_1,
	IIDC_RDMA_GEN_2,
	IIDC_RDMA_GEN_3,
	IIDC_RDMA_GEN_4,
};

struct iidc_rdma_caps {
	u8 gen; /* Hardware generation */
	u8 protocols; /* bitmap of supported protocols */
};
/* This information is needed to handle auxiliary driver probe */
struct iidc_ver_info {
	u16 major;
	u16 minor;
	u64 support;
};

/* Struct to hold per DCB APP info */
struct iidc_dcb_app_info {
	u8  priority;
	u8  selector;
	u16 prot_id;
};

struct iidc_core_dev_info;

#define IIDC_MAX_USER_PRIORITY		8
#define IIDC_MAX_APPS			64
#define IIDC_MAX_DSCP_MAPPING		64
#define IIDC_VLAN_PFC_MODE		0x0
#define IIDC_DSCP_PFC_MODE		0x1

/* Struct to hold per RDMA Qset info */
struct iidc_rdma_qset_params {
	u32 teid;	/* qset TEID */
	u16 qs_handle; /* RDMA driver provides this */
	u16 vport_id; /* VSI index */
	u8 tc; /* TC branch the QSet should belong to */
};

struct iidc_qos_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

/* Struct to hold QoS info */
struct iidc_qos_params {
	struct iidc_qos_info tc_info[IEEE_8021QAZ_MAX_TCS];
	u8 up2tc[IIDC_MAX_USER_PRIORITY];
	u8 vport_relative_bw;
	u8 vport_priority_type;
	u32 num_apps;
	u8 pfc_mode;
	struct iidc_dcb_app_info apps[IIDC_MAX_APPS];
	u8 dscp_map[IIDC_MAX_DSCP_MAPPING];
	u8 num_tc;
};

union iidc_event_info {
	/* IIDC_EVENT_AFTER_TC_CHANGE */
	struct iidc_qos_params port_qos;
	/* IIDC_EVENT_LINK_CHNG */
	bool link_up;
	/* IIDC_EVENT_VF_RESET */
	u32 vf_id;
	/* IIDC_EVENT_CRIT_ERR */
	u32 reg;
};

struct iidc_event {
	DECLARE_BITMAP(type, IIDC_EVENT_NBITS);
	union iidc_event_info info;
};

/* RDMA queue vector map info */
struct iidc_qv_info {
	u32 v_idx;
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct iidc_qvlist_info {
	u32 num_vectors;
	struct iidc_qv_info qv_info[1];
};

struct iidc_vf_port_info {
	u16 vf_id;
	u16 vport_id;
	u16 port_vlan_id;
	u16 port_vlan_tpid;
};

/* Following APIs are implemented by core PCI driver */
struct iidc_core_ops {
	/* APIs to allocate resources such as VEB, VSI, Doorbell queues,
	 * completion queues, Tx/Rx queues, etc...
	 */
	int (*alloc_res)(struct iidc_core_dev_info *cdev_info,
			 struct iidc_rdma_qset_params *qset);
	int (*free_res)(struct iidc_core_dev_info *cdev_info,
			struct iidc_rdma_qset_params *qset);

	int (*request_reset)(struct iidc_core_dev_info *cdev_info,
			     enum iidc_reset_type reset_type);

	int (*update_vport_filter)(struct iidc_core_dev_info *cdev_info,
				   u16 vport_id, bool enable);
	int (*get_vf_info)(struct iidc_core_dev_info *cdev_info, u16 vf_id,
			   struct iidc_vf_port_info *vf_port_info);
	int (*vc_send)(struct iidc_core_dev_info *cdev_info, u32 vf_id, u8 *msg,
		       u16 len);
	int (*vc_send_sync)(struct iidc_core_dev_info *cdev_info, u8 *msg,
			    u16 len, u8 *recv_msg, u16 *recv_len);
	int (*vc_queue_vec_map_unmap)(struct iidc_core_dev_info *cdev_info,
				      struct iidc_qvlist_info *qvl_info,
				      bool map);
	int (*ieps_entry)(struct iidc_core_dev_info *obj, void *arg);
};

#define IIDC_RDMA_ROCE_NAME	"roce"
#define IIDC_RDMA_IWARP_NAME	"iwarp"
#define IIDC_RDMA_ID	0x00000010
#define IIDC_IEPS_NAME  "ieps"
#define IIDC_IEPS_ID	0x00000015
#define IIDC_MAX_NUM_AUX	5

/* The const struct that instantiates cdev_info_id needs to be initialized
 * in the .c with the macro ASSIGN_IIDC_INFO.
 * For example:
 * static const struct cdev_info_id cdev_info_ids[] = ASSIGN_IIDC_INFO;
 */
struct cdev_info_id {
	char *name;
	int id;
};

#define IIDC_RDMA_INFO   { .name = IIDC_RDMA_ROCE_NAME, .id = IIDC_RDMA_ID },
#define IIDC_IEPS_INFO   { .name = IIDC_IEPS_NAME,  .id = IIDC_IEPS_ID },

#define ASSIGN_IIDC_INFO	\
{				\
	IIDC_IEPS_INFO		\
	IIDC_RDMA_INFO		\
}

enum iidc_function_type {
	IIDC_FUNCTION_TYPE_PF,
	IIDC_FUNCTION_TYPE_VF,
};

/* Structure representing auxiliary driver tailored information about the core
 * PCI dev, each auxiliary driver using the IIDC interface will have an
 * instance of this struct dedicated to it.
 */
struct iidc_core_dev_info {
	struct pci_dev *pdev; /* PCI device of corresponding to main function */
	struct auxiliary_device *adev;
	/* KVA / Linear address corresponding to BAR0 of underlying
	 * pci_device.
	 */
	u8 __iomem *hw_addr;
	int cdev_info_id;
	struct iidc_ver_info ver;

	/* Opaque pointer for aux driver specific data tracking. This memory
	 * will be alloc'd and freed by the auxiliary driver and used for
	 * private data accessible only to the specific auxiliary driver.
	 * It is stored here so that when this struct is passed to the
	 * auxiliary driver via an IIDC call, the data can be accessed
	 * at that time.
	 */
	void *auxiliary_priv;

	enum iidc_function_type ftype;
	u16 vport_id;
	/* Current active RDMA protocol */
	enum iidc_rdma_protocol rdma_protocol;

	struct iidc_qos_params qos_info;
	struct net_device *netdev;

	struct msix_entry *msix_entries;
	u16 msix_count; /* How many vectors are reserved for this device */
	struct iidc_rdma_caps rdma_caps;
	/* Following struct contains function pointers to be initialized
	 * by core PCI driver and called by auxiliary driver
	 */
	const struct iidc_core_ops *ops;
	u8 pf_id;
	u8 main_pf_port;
	u8 rdma_active_port;
};

struct iidc_auxiliary_dev {
	struct auxiliary_device adev;
	struct iidc_core_dev_info *cdev_info;
};

/* structure representing the auxiliary driver. This struct is to be
 * allocated and populated by the auxiliary driver's owner. The core PCI
 * driver will access these ops by performing a container_of on the
 * auxiliary_device->dev.driver.
 */
struct iidc_auxiliary_drv {
	struct auxiliary_driver adrv;
	/* This event_handler is meant to be a blocking call.  For instance,
	 * when a BEFORE_MTU_CHANGE event comes in, the event_handler will not
	 * return until the auxiliary driver is ready for the MTU change to
	 * happen.
	 */
	void (*event_handler)(struct iidc_core_dev_info *cdev_info,
			      struct iidc_event *event);
	int (*vc_receive)(struct iidc_core_dev_info *cdev_info, u32 vf_id,
			  u8 *msg, u16 len);
};

#endif /* _IIDC_H_*/
