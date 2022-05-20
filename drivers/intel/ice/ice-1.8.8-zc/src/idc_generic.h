/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _IDC_GENERIC_H_
#define _IDC_GENERIC_H_

/* Terminology
 * mfd: multi function device/driver that maintains and shares the data for the
 * mfd cell
 * mfd cell: Device/driver that depends on mfd for its hw data
 */

#include <linux/mfd/core.h>

/* Unique names used to match and load mfd cells */
#define IDC_MFD_CELL_NAME_RDMA		"rdma"

/* Unique ids used to match and load mfd cells */
#define IDC_MFD_CELL_ID_RDMA_PF	0x1
#define IDC_MFD_CELL_ID_RDMA_VF	0x2
#define IDC_MFD_CELL_ID_MAX	0x3

/* TODO: Revisit and move to virtchnl method of versioning */
/* Version info used to check for compatibility between mfd and mfd cell */
#define IDC_MAJOR_VER		1
#define IDC_MINOR_VER		1

#define IDC_QOS_MAX_USER_PRIORITY	8
#define IDC_QOS_MAX_TC	8

/* Forward declarations */
struct idc_mfd_data;

/* Reset types */
enum idc_reset_type {
	IDC_FUN_RESET = 0,
};

enum idc_close_reason {
	IDC_INTERFACE_DOWN,
	IDC_HW_RESET_PENDING,
};

enum idc_event {
	IDC_BEFORE_MTU_CHANGE,
	IDC_AFTER_MTU_CHANGE,
	IDC_BEFORE_TC_CHANGE,
	IDC_AFTER_TC_CHANGE,
	IDC_BEFORE_INTR_CHANGE,
	IDC_AFTER_INTR_CHANGE,
};

/* Version info used to check for compatibility between mfd and mfd cells */
struct idc_ver_info {
	u16 major;
	u16 minor;
};

/* QoS info */
struct idc_qos_params {
	u8 rel_bw[IDC_QOS_MAX_TC];
	u8 up2tc[IDC_QOS_MAX_USER_PRIORITY];
	u32 num_apps;
	u8 num_tc;
	u8 prio_type[IDC_QOS_MAX_TC];
	u64 tc_ctx[IDC_QOS_MAX_TC];
	u8 vport_relative_bw;
	u8 vport_priority_type;
};

/* RDMA queue vector map info */
struct idc_qv_info {
	u32 v_idx;
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct idc_qvlist_info {
	u32 num_vectors;
	struct idc_qv_info qv_info[1];
};

/* Following APIs are implemented by mfd and invoked by mfd cells */
struct idc_mfd_ops {
	/* Called by mfd cell to indicate probe finished */
	int (*probe_finished)(struct idc_mfd_data *mfd_data);
	/* Called by mfd cell to indicate remove started */
	void (*remove_started)(struct idc_mfd_data *mfd_data);
	/* Called by mfd cell to indicate remove finished */
	void (*remove_finished)(struct idc_mfd_data *mfd_data);
	/* Used by mfd cell to request a reset on mfd */
	int (*request_reset)(struct idc_mfd_data *mfd_data,
			     enum idc_reset_type reset_type);
	/* Used by mfd cell to send mailbox messages */
	int (*vc_send)(struct idc_mfd_data *mfd_data, u32 f_id, u8 *msg,
		       u16 len);
	/* used by mfd cell to send map unmap vector mailbox message. This
	 * message uses a different vc opcode and so different callback other
	 * than vc_send
	 */
	int (*vc_queue_vec_map_unmap)(struct idc_mfd_data *mfd_data,
				      struct idc_qvlist_info *qvl_info,
				      bool map);
};

/* Following APIs are implemented by mfd cells and invoked by mfd */
struct idc_mfd_cell_ops {
	/* Why we have 'open' and when it is expected to be called:
	 * 1. symmetric set of API w.r.t close
	 * 2. To be invoked form driver initialization path, should be probe
	 * 3. To be invoked upon RESET complete
	 */
	int (*open)(struct idc_mfd_data *mfd_data);

	/* close function is to be called when the mfd cell needs to be
	 * quiesced. This can be for a variety of reasons (enumerated in the
	 * idc_close_reason enum struct). A call to close will only be
	 * followed by a call to either remove or open. No IDC calls from the
	 * mfd cell should be accepted until it is re-opened.
	 *
	 * The *reason* parameter is the reason for the call to close. This
	 * can be for any reason enumerated in the idc_close_reason struct.
	 * It's primary reason is for the mfd drivers bookkeeping and in
	 * case the mfd cell wants to perform any different tasks
	 * dictated by the reason.
	 */
	int (*close)(struct idc_mfd_data *mfd_data,
		      enum idc_close_reason reason);
	/* Used by mfd to pass received mailbox messages to mfd cell */
	int (*vc_receive)(struct idc_mfd_data *mfd_data, u32 f_id, u8 *msg,
			  u16 len);
	/* used by mfd to inform various software events */
	int (*event)(struct idc_mfd_data *mfd_data, enum idc_event event);
};

/* Structure representing idc multi function device data  Initial steps for
 * sharing info is listed below
 * 1.mfd registers shared data with OS
 * 2.mfd cell registers platform_drv with OS
 * 3.mfd cell probe is called by OS
 *      Match of id_entry of mfd and id_table of mfd cell determines
 *      which probe has to be called
 * 4 probe_finished func of mfd will be called by mfd cell probe
 * 5.open function of mfd cell is called by mfd
 *.6 close function of mfd cell is called by mfd when mfd goes down
 */
struct idc_mfd_data {
	/* Below fields are initialized by mfd. Done before calling
	 * mfd_add_devices OS API
	 */
	/* PCI device corresponding to main function  Used by mfd cell
	 * for dma memory allocations and BAR4 access
	 */
	struct pci_dev *pdev;
	/* Linear address corresponding to BAR0 of underlying
	 * pci_device. Used by mfd cell for register space access
	 */
	u8 __iomem *hw_addr;

	/* Vector info to be used by mfd cell */
	struct msix_entry *msix_entries;
	/* Number of vectors reserved for the mfd cell */
	u16 msix_count;
	/* Used by mfd cell for version checks */
	struct idc_ver_info mfd_ver;
	/* mfd function type pf or vf */
	int func_type;
	/* net device interface owned by mfd */
	struct net_device *netdev;
	/* TC info */
	struct idc_qos_params qos_info;
	/* Function pointers to be initialized by mfd and called by mfd cell
	 */
	struct idc_mfd_ops mfd_ops;

	/* Below fields are initialized by mfd cell. Done before calling
	 * probe_finished function of mfd
	 */
	/* used by mfd for version checks */
	struct idc_ver_info mfd_cell_ver;
	/* Function pointers to be initialized by mfd cell and called by mfd
	 */
	struct idc_mfd_cell_ops mfd_cell_ops;
};

/* Structure representing the multi function device data to be shared */
struct __idc_mfd_data {
	struct idc_mfd_data *mfd_data;
};
#endif /* _IDC_GENERIC_H_*/
