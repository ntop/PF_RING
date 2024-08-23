/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2023 Intel Corporation */
#ifndef IRDMA_VIRTCHNL_H
#define IRDMA_VIRTCHNL_H

#include "hmc.h"
#include "irdma.h"

/* IRDMA_VCHNL_CHNL_VER_V0 is for legacy hw, no longer supported. */
#define IRDMA_VCHNL_CHNL_VER_V1 1
#define IRDMA_VCHNL_CHNL_VER_V2 2
#define IRDMA_VCHNL_CHNL_VER_MIN IRDMA_VCHNL_CHNL_VER_V1
#define IRDMA_VCHNL_CHNL_VER_MAX IRDMA_VCHNL_CHNL_VER_V2

#define IRDMA_VCHNL_OP_GET_VER_V0 0
#define IRDMA_VCHNL_OP_GET_VER_V1 1
#define IRDMA_VCHNL_OP_GET_VER_V2 2

#define IRDMA_VCHNL_OP_GET_HMC_FCN_V0 0
#define IRDMA_VCHNL_OP_GET_HMC_FCN_V1 1
#define IRDMA_VCHNL_OP_GET_HMC_FCN_V2 2
#define IRDMA_VCHNL_OP_PUT_HMC_FCN_V0 0
#define IRDMA_VCHNL_OP_MANAGE_PUSH_PAGE_V0 0
#define IRDMA_VCHNL_OP_GET_REG_LAYOUT_V0 0
#define IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP_V0 0
#define IRDMA_VCHNL_OP_QUEUE_VECTOR_UNMAP_V0 0
#define IRDMA_VCHNL_OP_GET_RDMA_CAPS_V0 0
#define IRDMA_VCHNL_OP_GET_RDMA_CAPS_MIN_SIZE 1
#define IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE_V0 0
#define IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE_V0 0
#define IRDMA_VCHNL_OP_MANAGE_WS_NODE_V0 0
#define IRDMA_VCHNL_OP_VLAN_PARSING_V0 0

#define IRDMA_VCHNL_INVALID_VF_IDX 0xFFFF

#define IRDMA_VCHNL_REG_ID_CQPTAIL 0
#define IRDMA_VCHNL_REG_ID_CQPDB 1
#define IRDMA_VCHNL_REG_ID_CCQPSTATUS 2
#define IRDMA_VCHNL_REG_ID_CCQPHIGH 3
#define IRDMA_VCHNL_REG_ID_CCQPLOW 4
#define IRDMA_VCHNL_REG_ID_CQARM 5
#define IRDMA_VCHNL_REG_ID_CQACK 6
#define IRDMA_VCHNL_REG_ID_AEQALLOC 7
#define IRDMA_VCHNL_REG_ID_CQPERRCODES 8
#define IRDMA_VCHNL_REG_ID_WQEALLOC 9
#define IRDMA_VCHNL_REG_ID_IPCONFIG0 10
#define IRDMA_VCHNL_REG_ID_DB_ADDR_OFFSET 11
#define IRDMA_VCHNL_REG_ID_DYN_CTL 12
#define IRDMA_VCHNL_REG_ID_AEQITRMASK 13
#define IRDMA_VCHNL_REG_ID_CEQITRMASK 14
#define IRDMA_VCHNL_REG_INV_ID 0xFFFF
#define IRDMA_VCHNL_REG_PAGE_REL 0x8000

#define IRDMA_VCHNL_REGFLD_ID_CCQPSTATUS_CQP_OP_ERR 2
#define IRDMA_VCHNL_REGFLD_ID_CCQPSTATUS_CCQP_DONE 5
#define IRDMA_VCHNL_REGFLD_ID_CQPSQ_STAG_PDID 6
#define IRDMA_VCHNL_REGFLD_ID_CQPSQ_CQ_CEQID 7
#define IRDMA_VCHNL_REGFLD_ID_CQPSQ_CQ_CQID 8
#define IRDMA_VCHNL_REGFLD_ID_COMMIT_FPM_CQCNT 9
#define IRDMA_VCHNL_REGFLD_ID_UPESD_HMCN_ID 10
#define IRDMA_VCHNL_REGFLD_INV_ID 0xFFFF

#define IRDMA_VCHNL_RESP_MIN_SIZE (sizeof(struct irdma_vchnl_resp_buf))

enum irdma_vchnl_ops {
	IRDMA_VCHNL_OP_GET_VER = 0,
	IRDMA_VCHNL_OP_GET_HMC_FCN = 1,
	IRDMA_VCHNL_OP_PUT_HMC_FCN = 2,
	IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE = 3,
	IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE = 4,
/* Unused OPs. Do not delete as OP numbers are ABI */
	IRDMA_VCHNL_OP_MANAGE_STATS_INST = 6,
	IRDMA_VCHNL_OP_MCG = 7,
	IRDMA_VCHNL_OP_UP_MAP = 8,
	IRDMA_VCHNL_OP_MANAGE_WS_NODE = 9,
	IRDMA_VCHNL_OP_MANAGE_PUSH_PAGE = 10,
	IRDMA_VCHNL_OP_GET_REG_LAYOUT = 11,
	IRDMA_VCHNL_OP_VLAN_PARSING = 12,
	IRDMA_VCHNL_OP_GET_RDMA_CAPS = 13,
	IRDMA_VCHNL_OP_QUEUE_VECTOR_MAP = 14,
	IRDMA_VCHNL_OP_QUEUE_VECTOR_UNMAP = 15,
};

#pragma pack(push, 1)
struct irdma_vchnl_req_hmc_info {
	u8 protocol_used;
	u8 disable_qos;
};

struct irdma_vchnl_resp_hmc_info {
	u16 hmc_func;
	u16 qs_handle[IRDMA_MAX_USER_PRIORITY];
};

struct irdma_vchnl_qv_info {
	u32 v_idx;
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct irdma_vchnl_qvlist_info {
	u32 num_vectors;
	struct irdma_vchnl_qv_info qv_info[];
};
struct irdma_vchnl_op_buf {
	u16 op_code;
	u16 op_ver;
	u16 buf_len;
	u16 rsvd;
	u64 op_ctx;
	/* Member alignment MUST be maintained above this location */
	u8 buf[];
};

struct irdma_vchnl_resp_buf {
	u64 op_ctx;
	u16 buf_len;
	s16 op_ret;
	/* Member alignment MUST be maintained above this location */
	u16 rsvd[2];
	u8 buf[];
};

struct irdma_vchnl_hmc_obj_range {
	u16 obj_type;
	u16 rsvd;
	u32 start_index;
	u32 obj_count;
};

struct irdma_vchnl_manage_ws_node {
	u8 add;
	u8 user_pri;
};

struct irdma_vchnl_rdma_caps {
	u8 hw_rev;
	u16 cqp_timeout_s;
	u16 cqp_def_timeout_s;
	u16 max_hw_push_len;
};

struct irdma_vchnl_init_info {
	struct workqueue_struct *vchnl_wq;
	struct irdma_vchnl_if *vchnl_if;
	enum irdma_vers hw_rev;
	bool privileged;
	bool is_pf;
};

struct irdma_vchnl_manage_push_page {
	u8 page_type;
	u8 add;
	u32 pg_idx;
	u32 qs_handle;
};

struct irdma_vchnl_reg_info {
	u32 reg_offset;
	u16 field_cnt;
	u16 reg_id; /* High bit of reg_id: bar or page relative */
};

struct irdma_vchnl_reg_field_info {
	u8 fld_shift;
	u8 fld_bits;
	u16 fld_id;
};

struct irdma_vchnl_req {
	struct irdma_vchnl_op_buf *vchnl_msg;
	void *parm;
	u32 vf_id;
	u16 parm_len;
	u16 resp_len;
};

struct irdma_vchnl_req_init_info {
	void *req_parm;
	void *resp_parm;
	u16 req_parm_len;
	u16 resp_parm_len;
	u16 op_code;
	u16 op_ver;
};

#pragma pack(pop)

int irdma_sc_vchnl_init(struct irdma_sc_dev *dev,
			struct irdma_vchnl_init_info *info);
int irdma_vchnl_req_add_hmc_objs(struct irdma_sc_dev *dev,
				 enum irdma_hmc_rsrc_type rsrc_type,
				 u32 start_index, u32 rsrc_count);
int irdma_vchnl_req_del_hmc_obj(struct irdma_sc_dev *dev,
			        enum irdma_hmc_rsrc_type rsrc_type,
			        u32 start_index, u32 rsrc_count);
int irdma_vchnl_req_manage_ws_node(struct irdma_sc_dev *dev, bool add,
				   u8 user_pri, u16 *qs_handle);
int irdma_vchnl_req_get_vlan_parsing_cfg(struct irdma_sc_dev *dev,
					 u8 *vlan_parse_en);
int irdma_vchnl_send_sync(struct irdma_sc_dev *dev, u8 *msg, u16 len,
			  u8 *recv_msg, u16 *recv_len);
int irdma_vchnl_req_recv(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
int irdma_vchnl_req_get_ver(struct irdma_sc_dev *dev, u16 ver_req, u32 *ver_res);
int irdma_vchnl_req_get_hmc_fcn(struct irdma_sc_dev *dev);
int irdma_vchnl_req_put_hmc_fcn(struct irdma_sc_dev *dev);
int irdma_vchnl_req_get_caps(struct irdma_sc_dev *dev);
int irdma_vchnl_req_get_resp(struct irdma_sc_dev *dev,
			     struct irdma_vchnl_req *vc_req);
int irdma_vchnl_req_manage_push_pg(struct irdma_sc_dev *dev, bool add,
				   u32 qs_handle, u32 *pg_idx);
int irdma_vchnl_req_get_reg_layout(struct irdma_sc_dev *dev);
int irdma_vchnl_req_aeq_vec_map(struct irdma_sc_dev *dev, u32 v_idx);
int irdma_vchnl_req_ceq_vec_map(struct irdma_sc_dev *dev, u16 ceq_id,
				u32 v_idx);
int irdma_vchnl_send_pf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
int irdma_vchnl_recv_pf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
struct irdma_vchnl_dev *irdma_find_vc_dev(struct irdma_sc_dev *dev, u16 vf_id);
void irdma_put_vfdev(struct irdma_sc_dev *dev, struct irdma_vchnl_dev *vc_dev);
void irdma_remove_vc_dev(struct irdma_sc_dev *dev, struct irdma_vchnl_dev *vc_dev);
void irdma_pf_put_vf_hmc_fcn(struct irdma_sc_dev *dev,
			     struct irdma_vchnl_dev *vc_dev);
#endif /* IRDMA_VIRTCHNL_H */
