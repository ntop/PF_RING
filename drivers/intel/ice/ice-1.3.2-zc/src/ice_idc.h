/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_IDC_H_
#define _ICE_IDC_H_

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/dcbnl.h>

#include <linux/ptp_clock_kernel.h>

/* This major and minor version represent IDC API version information.
 * During peer driver registration, peer driver specifies major and minor
 * version information (via. peer_driver:ver_info). It gets checked against
 * following defines and if mismatch, then peer driver registration
 * fails and appropriate message gets logged.
 */
#define ICE_PEER_MAJOR_VER		7
#define ICE_PEER_MINOR_VER		1

enum ice_peer_features {
	ICE_PEER_FEATURE_ADK_SUPPORT,
	ICE_PEER_FEATURE_PTP_SUPPORT,
	ICE_PEER_FEATURE_SRIOV_SUPPORT,
	ICE_PEER_FEATURE_PCIIOV_SUPPORT,
	ICE_PEER_FEATURE_NBITS
};

#define ICE_ADK_SUP		0

#define ICE_PTP_SUP		BIT(ICE_PEER_FEATURE_PTP_SUPPORT)

#define ICE_SRIOV_SUP		BIT(ICE_PEER_FEATURE_SRIOV_SUPPORT)

#ifdef CONFIG_PCI_IOV
#define ICE_PCIIOV_SUP		BIT(ICE_PEER_FEATURE_PCIIOV_SUPPORT)
#else
#define ICE_PCIIOV_SUP		0
#endif /* CONFIG_PCI_IOV */

#define ICE_IDC_FEATURES (ICE_ADK_SUP | ICE_PTP_SUP | ICE_SRIOV_SUP |\
			  ICE_PCIIOV_SUP)

enum ice_event_type {
	ICE_EVENT_LINK_CHANGE = 0x0,
	ICE_EVENT_MTU_CHANGE,
	ICE_EVENT_TC_CHANGE,
	ICE_EVENT_API_CHANGE,
	ICE_EVENT_MBX_CHANGE,
	ICE_EVENT_CRIT_ERR,
	ICE_EVENT_NBITS		/* must be last */
};

enum ice_res_type {
	ICE_INVAL_RES = 0x0,
	ICE_VSI,
	ICE_VEB,
	ICE_EVENT_Q,
	ICE_EGRESS_CMPL_Q,
	ICE_CMPL_EVENT_Q,
	ICE_ASYNC_EVENT_Q,
	ICE_DOORBELL_Q,
	ICE_RDMA_QSETS_TXSCHED,
};

enum ice_peer_reset_type {
	ICE_PEER_PFR = 0,
	ICE_PEER_CORER,
	ICE_PEER_CORER_SW_CORE,
	ICE_PEER_CORER_SW_FULL,
	ICE_PEER_GLOBR,
};

/* reason notified to peer driver as part of event handling */
enum ice_close_reason {
	ICE_REASON_INVAL = 0x0,
	ICE_REASON_HW_UNRESPONSIVE,
	ICE_REASON_INTERFACE_DOWN, /* Administrative down */
	ICE_REASON_PEER_DRV_UNREG, /* peer driver getting unregistered */
	ICE_REASON_PEER_DEV_UNINIT,
	ICE_REASON_GLOBR_REQ,
	ICE_REASON_CORER_REQ,
	ICE_REASON_EMPR_REQ,
	ICE_REASON_PFR_REQ,
	ICE_REASON_HW_RESET_PENDING,
	ICE_REASON_RECOVERY_MODE,
	ICE_REASON_PARAM_CHANGE,
};

enum ice_rdma_filter {
	ICE_RDMA_FILTER_INVAL = 0x0,
	ICE_RDMA_FILTER_IWARP,
	ICE_RDMA_FILTER_ROCEV2,
	ICE_RDMA_FILTER_BOTH,
};

/* This information is needed to handle peer driver registration,
 * instead of adding more params to peer_drv_registration function,
 * let's get it thru' peer_drv object.
 */
struct ice_ver_info {
	u16 major;
	u16 minor;
	u64 support;
};

/* Struct to hold per DCB APP info */
struct ice_dcb_app_info {
	u8  priority;
	u8  selector;
	u16 prot_id;
};

struct ice_peer_dev;
struct ice_peer_dev_int;

#define ICE_IDC_MAX_USER_PRIORITY        8
#define ICE_IDC_MAX_APPS        8

/* TIME_REF clock rate specification */
enum ice_time_ref_freq {
	ICE_TIME_REF_FREQ_25_000,
	ICE_TIME_REF_FREQ_122_880,
	ICE_TIME_REF_FREQ_125_000,
	ICE_TIME_REF_FREQ_153_600,
	ICE_TIME_REF_FREQ_156_250,
	ICE_TIME_REF_FREQ_245_760,

	NUM_ICE_TIME_REF_FREQ
};

/* Master timer mode */
enum ice_mstr_tmr_mode {
	ICE_MSTR_TMR_MODE_NANOSECONDS,
	ICE_MSTR_TMR_MODE_LOCKED,

	NUM_ICE_MSTR_TMR_MODE
};



/* Struct to hold per RDMA Qset info */
struct ice_rdma_qset_params {
	u32 teid;	/* qset TEID */
	u16 qs_handle; /* RDMA driver provides this */
	u16 vsi_id; /* VSI index */
	u8 tc; /* TC branch the QSet should belong to */
	u8 reserved[3];
};

struct ice_res_base {
	/* Union for future provision e.g. other res_type */
	union {
		struct ice_rdma_qset_params qsets;
	} res;
};

struct ice_res {
	/* Type of resource. Filled by peer driver */
	enum ice_res_type res_type;
	/* Count requested by peer driver */
	u16 cnt_req;


	/* Number of resources allocated. Filled in by callee.
	 * Based on this value, caller to fill up "resources"
	 */
	u16 res_allocated;

	/* Unique handle to resources allocated. Zero if call fails.
	 * Allocated by callee and for now used by caller for internal
	 * tracking purpose.
	 */
	u32 res_handle;

	/* Peer driver has to allocate sufficient memory, to accommodate
	 * cnt_requested before calling this function.
	 * Memory has to be zero initialized. It is input/output param.
	 * As a result of alloc_res API, this structures will be populated.
	 */
	struct ice_res_base res[1];
};

struct ice_qos_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

/* Struct to hold QoS info */
struct ice_qos_params {
	struct ice_qos_info tc_info[IEEE_8021QAZ_MAX_TCS];
	u8 up2tc[ICE_IDC_MAX_USER_PRIORITY];
	u8 vsi_relative_bw;
	u8 vsi_priority_type;
	u32 num_apps;
	struct ice_dcb_app_info apps[ICE_IDC_MAX_APPS];
	u8 num_tc;
};

union ice_event_info {
	/* ICE_EVENT_LINK_CHANGE */
	struct {
		struct net_device *lwr_nd;
		u16 vsi_num; /* HW index of VSI corresponding to lwr ndev */
		u8 new_link_state;
		u8 lport;
	} link_info;
	/* ICE_EVENT_MTU_CHANGE */
	u16 mtu;
	/* ICE_EVENT_TC_CHANGE */
	struct ice_qos_params port_qos;
	/* ICE_EVENT_API_CHANGE */
	u8 api_rdy;
	/* ICE_EVENT_MBX_CHANGE */
	u8 mbx_rdy;
	/* ICE_EVENT_CRIT_ERR */
	u32 reg;
};

/* ice_event elements are to be passed back and forth between the ice driver
 * and the peer drivers. They are to be used to both register/unregister
 * for event reporting and to report an event (events can be either ice
 * generated or peer generated).
 *
 * For (un)registering for events, the structure needs to be populated with:
 *   reporter - pointer to the ice_peer_dev struct of the peer (un)registering
 *   type - bitmap with bits set for event types to (un)register for
 *
 * For reporting events, the structure needs to be populated with:
 *   reporter - pointer to peer that generated the event (NULL for ice)
 *   type - bitmap with single bit set for this event type
 *   info - union containing data relevant to this event type
 */
struct ice_event {
	struct ice_peer_dev *reporter;
	DECLARE_BITMAP(type, ICE_EVENT_NBITS);
	union ice_event_info info;
};

/* Following APIs are implemented by ICE driver and invoked by peer drivers */
struct ice_ops {
	/* APIs to allocate resources such as VEB, VSI, Doorbell queues,
	 * completion queues, Tx/Rx queues, etc...
	 */
	int (*alloc_res)(struct ice_peer_dev *peer_dev,
			 struct ice_res *res,
			 int partial_acceptable);
	int (*free_res)(struct ice_peer_dev *peer_dev,
			struct ice_res *res);

	int (*is_vsi_ready)(struct ice_peer_dev *peer_dev);
	int (*peer_register)(struct ice_peer_dev *peer_dev);
	int (*peer_unregister)(struct ice_peer_dev *peer_dev);
	int (*request_reset)(struct ice_peer_dev *dev,
			     enum ice_peer_reset_type reset_type);

	void (*notify_state_change)(struct ice_peer_dev *dev,
				    struct ice_event *event);

	/* Notification APIs */
	void (*reg_for_notification)(struct ice_peer_dev *dev,
				     struct ice_event *event);
	void (*unreg_for_notification)(struct ice_peer_dev *dev,
				       struct ice_event *event);
	int (*update_vsi_filter)(struct ice_peer_dev *peer_dev,
				 enum ice_rdma_filter filter, bool enable);
	int (*vc_send)(struct ice_peer_dev *peer_dev, u32 vf_id, u8 *msg,
		       u16 len);
};

/* Following APIs are implemented by peer drivers and invoked by ICE driver */
struct ice_peer_ops {
	void (*event_handler)(struct ice_peer_dev *peer_dev,
			      struct ice_event *event);

	/* Why we have 'open' and when it is expected to be called:
	 * 1. symmetric set of API w.r.t close
	 * 2. To be invoked form driver initialization path
	 *     - call peer_driver:open once ice driver is fully initialized
	 * 3. To be invoked upon RESET complete
	 *
	 * Calls to open are performed from ice_finish_init_peer_device
	 * which is invoked from the service task. This helps keep devices
	 * from having their open called until the ice driver is ready and
	 * has scheduled its service task.
	 */
	int (*open)(struct ice_peer_dev *peer_dev);

	/* Peer's close function is to be called when the peer needs to be
	 * quiesced. This can be for a variety of reasons (enumerated in the
	 * ice_close_reason enum struct). A call to close will only be
	 * followed by a call to either remove or open. No IDC calls from the
	 * peer should be accepted until it is re-opened.
	 *
	 * The *reason* parameter is the reason for the call to close. This
	 * can be for any reason enumerated in the ice_close_reason struct.
	 * It's primary reason is for the peer's bookkeeping and in case the
	 * peer want to perform any different tasks dictated by the reason.
	 */
	void (*close)(struct ice_peer_dev *peer_dev,
		      enum ice_close_reason reason);

	int (*vc_receive)(struct ice_peer_dev *peer_dev, u32 vf_id, u8 *msg,
			  u16 len);
	/* tell RDMA peer to prepare for TC change in a blocking call
	 * that will directly precede the change event
	 */
	void (*prep_tc_change)(struct ice_peer_dev *peer_dev);
};

#define ICE_PEER_RDMA_NAME	"ice_rdma"
#define ICE_PEER_RDMA_ID	0x00000010
#define ICE_MAX_NUM_PEERS	4

/* The const struct that instantiates peer_dev_id needs to be initialized
 * in the .c with the macro ASSIGN_PEER_INFO.
 * For example:
 * static const struct peer_dev_id peer_dev_ids[] = ASSIGN_PEER_INFO;
 */
struct peer_dev_id {
	char *name;
	int id;
};

#define IDC_RDMA_INFO   { .name = ICE_PEER_RDMA_NAME,  .id = ICE_PEER_RDMA_ID },
#define IDC_AE_INFO
#define IDC_IPSEC_INFO
#define IDC_SWITCH_INFO
#define IDC_ADK_INFO
/* this is a list of all possible peers, some are unused but left for clarity */
#define ASSIGN_PEER_INFO	\
{				\
	IDC_RDMA_INFO		\
	IDC_AE_INFO		\
	IDC_IPSEC_INFO		\
	IDC_SWITCH_INFO		\
	IDC_ADK_INFO		\
}

#define ice_peer_priv(x) ((x)->peer_priv)

/* structure representing peer device */
struct ice_peer_dev {
	struct ice_ver_info ver;
	struct pci_dev *pdev; /* PCI device of corresponding to main function */
	/* KVA / Linear address corresponding to BAR0 of underlying
	 * pci_device.
	 */
	u8 __iomem *hw_addr;
	int peer_dev_id;

	int index;

	/* Opaque pointer for peer specific data tracking.  This memory will
	 * be alloc'd and freed by the peer driver and used for private data
	 * accessible only to the specific peer.  It is stored here so that
	 * when this struct is passed to the peer via an IDC call, the data
	 * can be accessed by the peer at that time.
	 * The peers should only retrieve the pointer by the macro:
	 *    ice_peer_priv(struct ice_peer_dev *)
	 */
	void *peer_priv;


	u8 ftype;	/* PF(false) or VF (true) */

	/* Data VSI created by driver */
	u16 pf_vsi_num;

	u8 lan_addr[ETH_ALEN]; /* default MAC address of main netdev */
	u16 initial_mtu; /* Initial MTU of main netdev */
	struct ice_qos_params initial_qos_info;
	struct net_device *netdev;
	/* PCI info */
	u8 ari_ena;
	u16 bus_num;
	u16 dev_num;
	u16 fn_num;

	/* Based on peer driver type, this shall point to corresponding MSIx
	 * entries in pf->msix_entries (which were allocated as part of driver
	 * initialization) e.g. for RDMA driver, msix_entries reserved will be
	 * num_online_cpus + 1.
	 */
	u16 msix_count; /* How many vectors are reserved for this device */
	struct msix_entry *msix_entries;

	/* Following struct contains function pointers to be initialized
	 * by ICE driver and called by peer driver
	 */
	const struct ice_ops *ops;

	/* Following struct contains function pointers to be initialized
	 * by peer driver and called by ICE driver
	 */
	const struct ice_peer_ops *peer_ops;

	/* Pointer to peer_drv struct to be populated by peer driver */
	struct ice_peer_drv *peer_drv;
};

struct ice_peer_dev_platform_data {
	struct ice_peer_dev *peer_dev;
};

/* structure representing peer driver
 * Peer driver to initialize those function ptrs and
 * it will be invoked by ICE as part of driver_registration
 * via bus infrastructure
 */
struct ice_peer_drv {
	u16 driver_id;
#define ICE_PEER_LAN_DRIVER		0
#define ICE_PEER_RDMA_DRIVER		4
#define ICE_PEER_ADK_DRIVER		5

	struct ice_ver_info ver;
	const char *name;

};

#endif /* _ICE_IDC_H_*/
