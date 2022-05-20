/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_IOCTL_USER_H_
#define _ICE_IOCTL_USER_H_

#define ICE_SWX_IOC_MAGIC 'a'

enum ice_qos_rl_type {
	ICE_QOS_MIN_BW = 1,	/* for CIR profile */
	ICE_QOS_MAX_BW,		/* for EIR profile */
};

/* struct that defines fields of bandwidth properties */
struct ice_qos_bw {
	enum ice_qos_rl_type rl_type;
	__u32 bw;
	__u8 bw_alloc;
};

/* struct that defines fields for QoS configuration per TC */
struct ice_qos_tc_cfg {
	struct ice_qos_bw bw_cfg;
	__u8 port;
	__u8 tc;
};

/* struct that defines fields for QoS configuration per VF */
struct ice_qos_vf_cfg {
	struct ice_qos_bw bw_cfg;
	__u16 vf_num;
	__u8 tc;
};

/* struct that defines fields for QoS configuration per queue */
struct ice_qos_q_cfg {
	struct ice_qos_bw bw_cfg;
	__u16 vf_num;
	__u16 q_num;
	__u8 tc;
};

enum ice_ioctl_command {
	ICE_QOS_CMD_CFG_TC_BW_LMT,
	ICE_QOS_CMD_CFG_TC_DFLT_LMT,
	ICE_QOS_CMD_CFG_TC_BW_ALLOC,
	ICE_QOS_CMD_CFG_VF_BW_LMT,
	ICE_QOS_CMD_CFG_VF_DFLT_LMT,
	ICE_QOS_CMD_CFG_VF_BW_ALLOC,
	ICE_QOS_CMD_CFG_Q_BW_LMT,
	ICE_QOS_CMD_CFG_Q_DFLT_LMT,

	NUM_ICE_QOS_CMD,
};

#define ICE_SWX_IOC_CFG_TC_BW_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_TC_BW_LMT,		\
		 struct ice_qos_tc_cfg)

#define ICE_SWX_IOC_CFG_TC_DFL_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_TC_DFLT_LMT,		\
		 struct ice_qos_tc_cfg)

#define ICE_SWX_IOC_CFG_TC_BW_ALLOC			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_TC_BW_ALLOC,		\
		 struct ice_qos_tc_cfg)

#define ICE_SWX_IOC_CFG_VF_BW_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_VF_BW_LMT,		\
		 struct ice_qos_vf_cfg)

#define ICE_SWX_IOC_CFG_VF_DFL_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_VF_DFLT_LMT,		\
		 struct ice_qos_vf_cfg)

#define ICE_SWX_IOC_CFG_VF_BW_ALLOC			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_VF_BW_ALLOC,		\
		 struct ice_qos_vf_cfg)

#define ICE_SWX_IOC_CFG_Q_BW_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_Q_BW_LMT,		\
		 struct ice_qos_q_cfg)

#define ICE_SWX_IOC_CFG_Q_DFL_LMT			\
	_IOW(ICE_SWX_IOC_MAGIC,				\
		 ICE_QOS_CMD_CFG_Q_DFLT_LMT,		\
		 struct ice_qos_q_cfg)

#endif /* _ICE_IOCTL_USER_H_ */
