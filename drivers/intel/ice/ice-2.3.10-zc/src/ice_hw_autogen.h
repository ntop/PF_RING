/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* Machine generated file. Do not edit. */

#ifndef _ICE_HW_AUTOGEN_H_
#define _ICE_HW_AUTOGEN_H_

#define GL_HIDA(_i)			(0x00082000 + ((_i) * 4))
#define GL_HIBA(_i)			(0x00081000 + ((_i) * 4))
#define GL_HICR				0x00082040
#define GL_HICR_EN			0x00082044
#define GLGEN_CSR_DEBUG_C		0x00075750
#define GLNVM_GENS			0x000B6100
#define GLNVM_FLA			0x000B6108
#define GL_HIDA_MAX_INDEX		15
#define GL_HIBA_MAX_INDEX		1023
#define GL_MNG_FWSM_FW_LOADING_M	BIT(30)
#define GLGEN_SWITCH_MODE_CONFIG_SELECT_25X4_ON_SINGLE_QUAD_M	BIT(2)
#define GLGEN_SWITCH_MODE_CONFIG	0x000B81E0 /* Reset Source: POR */
#define GL_MNG_FWSM_FW_MODES_M		E800_GL_MNG_FWSM_FW_MODES_M
#define GL_RDPU_CNTRL				0x00052054 /* Reset Source: CORER */
#define PF0INT_DYN_CTL(_i)			(0x03000000 + ((_i) * 4096)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QRX_TAIL_PAGE(_QRX)			(0x03800000 + ((_QRX) * 4096)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QTX_COMM_DBELL_PAGE(_DBQM)		(0x04000000 + ((_DBQM) * 4096)) /* _i=0...16383 */ /* Reset Source: CORER */
#define VSI_MBX_ARQBAH(_VSI)			(0x02000018 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ARQBAL(_VSI)			(0x02000014 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ARQH(_VSI)			(0x02000020 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ARQLEN(_VSI)			(0x0200001C + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: PFR */
#define VSI_MBX_ARQT(_VSI)			(0x02000024 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ATQBAH(_VSI)			(0x02000004 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ATQBAL(_VSI)			(0x02000000 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ATQH(_VSI)			(0x0200000C + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSI_MBX_ATQLEN(_VSI)			(0x02000008 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: PFR */
#define VSI_MBX_ATQT(_VSI)			(0x02000010 + ((_VSI) * 4096)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLCOMM_QTX_CNTX_CTL			0x002D2DC8 /* Reset Source: CORER */
#define GLCOMM_QTX_CNTX_CTL_QUEUE_ID_M		ICE_M(0x3FFF, 0)
#define GLCOMM_QTX_CNTX_CTL_CMD_EXEC_M		BIT(19)
#define GLCOMM_QTX_CNTX_DATA(_i)		(0x002D2D40 + ((_i) * 4)) /* _i=0...9 */ /* Reset Source: CORER */
#define GLCOMM_QUANTA_PROF(_i)			(0x002D2D68 + ((_i) * 4)) /* _i=0...15 */ /* Reset Source: CORER */
#define GLCOMM_QUANTA_PROF_MAX_INDEX		15
#define GLCOMM_QUANTA_PROF_QUANTA_SIZE_S	0
#define GLCOMM_QUANTA_PROF_QUANTA_SIZE_M	ICE_M(0x3FFF, 0)
#define GLCOMM_QUANTA_PROF_MAX_CMD_S		16
#define GLCOMM_QUANTA_PROF_MAX_CMD_M		ICE_M(0xFF, 16)
#define GLCOMM_QUANTA_PROF_MAX_DESC_S		24
#define GLCOMM_QUANTA_PROF_MAX_DESC_M		ICE_M(0x3F, 24)
#define GLTCLAN_CQ_CNTX0(_CQ)			(0x000F0800 + ((_CQ) * 4)) /* _i=0...511 */ /* Reset Source: CORER */
#define GLTCLAN_CQ_CNTX0_MAX_INDEX		511
#define QTX_COMM_DBELL(_DBQM)			(0x002C0000 + ((_DBQM) * 4)) /* _i=0...16383 */ /* Reset Source: CORER */
#define QTX_COMM_DBLQ_CNTX(_i, _DBLQ)		(0x002D0000 + ((_i) * 1024 + (_DBLQ) * 4)) /* _i=0...4, _DBLQ=0...255 */ /* Reset Source: CORER */
#define QTX_COMM_DBLQ_DBELL_MAX_INDEX		255
#define QTX_COMM_HEAD(_DBQM)			(0x000E0000 + ((_DBQM) * 4)) /* _i=0...16383 */ /* Reset Source: CORER */
#define QTX_COMM_HEAD_MAX_INDEX			16383
#define QTX_COMM_HEAD_HEAD_M			ICE_M(0x1FFF, 0)
#define GL_MBX_PASID				0x00231EC0 /* Reset Source: CORER */
#define GL_MBX_PASID_PASID_MODE_M		BIT(0)
#define PF_FW_ARQBAH				0x00080180 /* Reset Source: EMPR */
#define PF_FW_ARQBAH_ARQBAH_S			0
#define PF_FW_ARQBAH_ARQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_FW_ARQBAL				0x00080080 /* Reset Source: EMPR */
#define PF_FW_ARQBAL_ARQBAL_LSB_S		0
#define PF_FW_ARQBAL_ARQBAL_LSB_M		ICE_M(0x3F, 0)
#define PF_FW_ARQBAL_ARQBAL_S			6
#define PF_FW_ARQBAL_ARQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_FW_ARQH				0x00080380 /* Reset Source: EMPR */
#define PF_FW_ARQH_ARQH_S			0
#define PF_FW_ARQH_ARQH_M			ICE_M(0x3FF, 0)
#define PF_FW_ARQLEN				0x00080280 /* Reset Source: EMPR */
#define PF_FW_ARQLEN_ARQLEN_S			0
#define PF_FW_ARQLEN_ARQLEN_M			ICE_M(0x3FF, 0)
#define PF_FW_ARQLEN_ARQVFE_S			28
#define PF_FW_ARQLEN_ARQVFE_M			BIT(28)
#define PF_FW_ARQLEN_ARQOVFL_S			29
#define PF_FW_ARQLEN_ARQOVFL_M			BIT(29)
#define PF_FW_ARQLEN_ARQCRIT_S			30
#define PF_FW_ARQLEN_ARQCRIT_M			BIT(30)
#define PF_FW_ARQLEN_ARQENABLE_S		31
#define PF_FW_ARQLEN_ARQENABLE_M		BIT(31)
#define PF_FW_ARQT				0x00080480 /* Reset Source: EMPR */
#define PF_FW_ARQT_ARQT_S			0
#define PF_FW_ARQT_ARQT_M			ICE_M(0x3FF, 0)
#define PF_FW_ATQBAH				0x00080100 /* Reset Source: EMPR */
#define PF_FW_ATQBAH_ATQBAH_S			0
#define PF_FW_ATQBAH_ATQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_FW_ATQBAL				0x00080000 /* Reset Source: EMPR */
#define PF_FW_ATQBAL_ATQBAL_LSB_S		0
#define PF_FW_ATQBAL_ATQBAL_LSB_M		ICE_M(0x3F, 0)
#define PF_FW_ATQBAL_ATQBAL_S			6
#define PF_FW_ATQBAL_ATQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_FW_ATQH				0x00080300 /* Reset Source: EMPR */
#define PF_FW_ATQH_ATQH_S			0
#define PF_FW_ATQH_ATQH_M			ICE_M(0x3FF, 0)
#define PF_FW_ATQLEN				0x00080200 /* Reset Source: EMPR */
#define PF_FW_ATQLEN_ATQLEN_S			0
#define PF_FW_ATQLEN_ATQLEN_M			ICE_M(0x3FF, 0)
#define PF_FW_ATQLEN_ATQVFE_S			28
#define PF_FW_ATQLEN_ATQVFE_M			BIT(28)
#define PF_FW_ATQLEN_ATQOVFL_S			29
#define PF_FW_ATQLEN_ATQOVFL_M			BIT(29)
#define PF_FW_ATQLEN_ATQCRIT_S			30
#define PF_FW_ATQLEN_ATQCRIT_M			BIT(30)
#define PF_FW_ATQLEN_ATQENABLE_S		31
#define PF_FW_ATQLEN_ATQENABLE_M		BIT(31)
#define PF_FW_ATQT				0x00080400 /* Reset Source: EMPR */
#define PF_FW_ATQT_ATQT_S			0
#define PF_FW_ATQT_ATQT_M			ICE_M(0x3FF, 0)
#define PF_MBX_ARQBAH				0x0022E400 /* Reset Source: CORER */
#define PF_MBX_ARQBAH_ARQBAH_S			0
#define PF_MBX_ARQBAH_ARQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_MBX_ARQBAL				0x0022E380 /* Reset Source: CORER */
#define PF_MBX_ARQBAL_ARQBAL_LSB_S		0
#define PF_MBX_ARQBAL_ARQBAL_LSB_M		ICE_M(0x3F, 0)
#define PF_MBX_ARQBAL_ARQBAL_S			6
#define PF_MBX_ARQBAL_ARQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_MBX_ARQH				0x0022E500 /* Reset Source: CORER */
#define PF_MBX_ARQH_ARQH_S			0
#define PF_MBX_ARQH_ARQH_M			ICE_M(0x3FF, 0)
#define PF_MBX_ARQLEN				0x0022E480 /* Reset Source: PFR */
#define PF_MBX_ARQLEN_ARQLEN_S			0
#define PF_MBX_ARQLEN_ARQLEN_M			ICE_M(0x3FF, 0)
#define PF_MBX_ARQLEN_ARQVFE_S			28
#define PF_MBX_ARQLEN_ARQVFE_M			BIT(28)
#define PF_MBX_ARQLEN_ARQOVFL_S			29
#define PF_MBX_ARQLEN_ARQOVFL_M			BIT(29)
#define PF_MBX_ARQLEN_ARQCRIT_S			30
#define PF_MBX_ARQLEN_ARQCRIT_M			BIT(30)
#define PF_MBX_ARQLEN_ARQENABLE_S		31
#define PF_MBX_ARQLEN_ARQENABLE_M		BIT(31)
#define PF_MBX_ARQT				0x0022E580 /* Reset Source: CORER */
#define PF_MBX_ARQT_ARQT_S			0
#define PF_MBX_ARQT_ARQT_M			ICE_M(0x3FF, 0)
#define PF_MBX_ATQBAH				0x0022E180 /* Reset Source: CORER */
#define PF_MBX_ATQBAH_ATQBAH_S			0
#define PF_MBX_ATQBAH_ATQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_MBX_ATQBAL				0x0022E100 /* Reset Source: CORER */
#define PF_MBX_ATQBAL_ATQBAL_S			6
#define PF_MBX_ATQBAL_ATQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_MBX_ATQH				0x0022E280 /* Reset Source: CORER */
#define PF_MBX_ATQH_ATQH_S			0
#define PF_MBX_ATQH_ATQH_M			ICE_M(0x3FF, 0)
#define PF_MBX_ATQLEN				0x0022E200 /* Reset Source: PFR */
#define PF_MBX_ATQLEN_ATQLEN_S			0
#define PF_MBX_ATQLEN_ATQLEN_M			ICE_M(0x3FF, 0)
#define PF_MBX_ATQLEN_ATQVFE_S			28
#define PF_MBX_ATQLEN_ATQVFE_M			BIT(28)
#define PF_MBX_ATQLEN_ATQOVFL_S			29
#define PF_MBX_ATQLEN_ATQOVFL_M			BIT(29)
#define PF_MBX_ATQLEN_ATQCRIT_S			30
#define PF_MBX_ATQLEN_ATQCRIT_M			BIT(30)
#define PF_MBX_ATQLEN_ATQENABLE_S		31
#define PF_MBX_ATQLEN_ATQENABLE_M		BIT(31)
#define PF_MBX_ATQT				0x0022E300 /* Reset Source: CORER */
#define PF_MBX_ATQT_ATQT_S			0
#define PF_MBX_ATQT_ATQT_M			ICE_M(0x3FF, 0)
#define PF_SB_ARQBAH				0x0022FF00 /* Reset Source: CORER */
#define PF_SB_ARQBAH_ARQBAH_S			0
#define PF_SB_ARQBAH_ARQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_SB_ARQBAL				0x0022FE80 /* Reset Source: CORER */
#define PF_SB_ARQBAL_ARQBAL_LSB_S		0
#define PF_SB_ARQBAL_ARQBAL_LSB_M		ICE_M(0x3F, 0)
#define PF_SB_ARQBAL_ARQBAL_S			6
#define PF_SB_ARQBAL_ARQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_SB_ARQH				0x00230000 /* Reset Source: CORER */
#define PF_SB_ARQH_ARQH_S			0
#define PF_SB_ARQH_ARQH_M			ICE_M(0x3FF, 0)
#define PF_SB_ARQLEN				0x0022FF80 /* Reset Source: PFR */
#define PF_SB_ARQLEN_ARQLEN_S			0
#define PF_SB_ARQLEN_ARQLEN_M			ICE_M(0x3FF, 0)
#define PF_SB_ARQLEN_ARQVFE_S			28
#define PF_SB_ARQLEN_ARQVFE_M			BIT(28)
#define PF_SB_ARQLEN_ARQOVFL_S			29
#define PF_SB_ARQLEN_ARQOVFL_M			BIT(29)
#define PF_SB_ARQLEN_ARQCRIT_S			30
#define PF_SB_ARQLEN_ARQCRIT_M			BIT(30)
#define PF_SB_ARQLEN_ARQENABLE_S		31
#define PF_SB_ARQLEN_ARQENABLE_M		BIT(31)
#define PF_SB_ARQT				0x00230080 /* Reset Source: CORER */
#define PF_SB_ARQT_ARQT_S			0
#define PF_SB_ARQT_ARQT_M			ICE_M(0x3FF, 0)
#define PF_SB_ATQBAH				0x0022FC80 /* Reset Source: CORER */
#define PF_SB_ATQBAH_ATQBAH_S			0
#define PF_SB_ATQBAH_ATQBAH_M			ICE_M(0xFFFFFFFF, 0)
#define PF_SB_ATQBAL				0x0022FC00 /* Reset Source: CORER */
#define PF_SB_ATQBAL_ATQBAL_S			6
#define PF_SB_ATQBAL_ATQBAL_M			ICE_M(0x3FFFFFF, 6)
#define PF_SB_ATQH				0x0022FD80 /* Reset Source: CORER */
#define PF_SB_ATQH_ATQH_S			0
#define PF_SB_ATQH_ATQH_M			ICE_M(0x3FF, 0)
#define PF_SB_ATQLEN				0x0022FD00 /* Reset Source: PFR */
#define PF_SB_ATQLEN_ATQLEN_S			0
#define PF_SB_ATQLEN_ATQLEN_M			ICE_M(0x3FF, 0)
#define PF_SB_ATQLEN_ATQVFE_S			28
#define PF_SB_ATQLEN_ATQVFE_M			BIT(28)
#define PF_SB_ATQLEN_ATQOVFL_S			29
#define PF_SB_ATQLEN_ATQOVFL_M			BIT(29)
#define PF_SB_ATQLEN_ATQCRIT_S			30
#define PF_SB_ATQLEN_ATQCRIT_M			BIT(30)
#define PF_SB_ATQLEN_ATQENABLE_S		31
#define PF_SB_ATQLEN_ATQENABLE_M		BIT(31)
#define PF_SB_ATQT				0x0022FE00 /* Reset Source: CORER */
#define PF_SB_ATQT_ATQT_S			0
#define PF_SB_ATQT_ATQT_M			ICE_M(0x3FF, 0)
#define PF_SB_REM_DEV_CTL			0x002300F0 /* Reset Source: CORER */
#define VF_MBX_ARQLEN(_VF)			(0x0022BC00 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: PFR */
#define VF_MBX_ATQLEN(_VF)			(0x0022A800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: PFR */
#define PRTDCB_GENC				0x00083000 /* Reset Source: CORER */
#define PRTDCB_GENC_PFCLDA_M			ICE_M(0xFFFF, 16)
#define PRTDCB_GENS				0x00083020 /* Reset Source: CORER */
#define PRTDCB_GENS_DCBX_STATUS_M		ICE_M(0x7, 0)
#define PRTDCB_TDPUC				0x00040940 /* Reset Source: CORER */
#define PRTDCB_TDPUC_MAX_TXFRAME_M		ICE_M(0xFFFF, 0)
#define PRTDCB_TUP2TC				0x001D26C0 /* Reset Source: CORER */
#define GL_PREEXT_L2_PMASK0(_i)			(0x0020F0FC + ((_i) * 4)) /* _i=0...2 */ /* Reset Source: CORER */
#define GL_PREEXT_L2_PMASK1(_i)			(0x0020F108 + ((_i) * 4)) /* _i=0...2 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLAGS(_i, _j)		(0x0045D000 + ((_i) * 4 + (_j) * 256)) /* _i=0...63, _j=0...4 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLAGS_FLEXIFLAG_4N_S	0
#define GLFLXP_RXDID_FLAGS_FLEXIFLAG_4N_M	ICE_M(0x3F, 0)
#define GLFLXP_RXDID_FLX_WRD_0(_i)		(0x0045C800 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_0_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_0_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_0_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_0_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_0_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_0_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_0_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define GLFLXP_RXDID_FLX_WRD_1(_i)		(0x0045C900 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_1_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_1_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_1_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_1_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_1_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_1_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_1_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define GLFLXP_RXDID_FLX_WRD_2(_i)		(0x0045CA00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_2_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_2_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_2_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_2_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_2_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_2_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_2_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define GLFLXP_RXDID_FLX_WRD_3(_i)		(0x0045CB00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_3_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_3_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_3_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_3_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_3_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_3_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_3_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define GLFLXP_RXDID_FLX_WRD_4(_i)		(0x0045CC00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_4_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_4_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_4_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_4_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_4_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_4_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_4_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define GLFLXP_RXDID_FLX_WRD_5(_i)		(0x0045CD00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define GLFLXP_RXDID_FLX_WRD_5_MAX_INDEX	63
#define GLFLXP_RXDID_FLX_WRD_5_PROT_MDID_S	0
#define GLFLXP_RXDID_FLX_WRD_5_PROT_MDID_M	ICE_M(0xFF, 0)
#define GLFLXP_RXDID_FLX_WRD_5_EXTRACTION_OFFSET_S 8
#define GLFLXP_RXDID_FLX_WRD_5_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define GLFLXP_RXDID_FLX_WRD_5_RXDID_OPCODE_S	30
#define GLFLXP_RXDID_FLX_WRD_5_RXDID_OPCODE_M	ICE_M(0x3, 30)
#define QRXFLXP_CNTXT(_QRX)			(0x00480000 + ((_QRX) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QRXFLXP_CNTXT_RXDID_IDX_M		ICE_M(0x3F, 0)
#define QRXFLXP_CNTXT_RXDID_PRIO_M		ICE_M(0x7, 8)
#define QRXFLXP_CNTXT_TS_M			BIT(11)
#define GL_FWSTS				0x00083048 /* Reset Source: POR */
#define GLGEN_CLKSTAT_SRC			0x000B826C /* Reset Source: POR */
#define GLGEN_CLKSTAT_SRC_PSM_CLK_SRC_M		ICE_M(0x3, 4)
#define GLGEN_GPIO_CTL(_i)			(0x000880C8 + ((_i) * 4)) /* _i=0...6 */ /* Reset Source: POR */
#define GLGEN_GPIO_CTL_MAX_INDEX		6
#define GLGEN_GPIO_CTL_PIN_DIR_M		BIT(4)
#define GLGEN_GPIO_CTL_TRI_CTL_M		BIT(5)
#define GLGEN_GPIO_CTL_PIN_FUNC_M		ICE_M(0xF, 8)
#define GLGEN_RSTAT				0x000B8188 /* Reset Source: POR */
#define GLGEN_RSTAT_DEVSTATE_M			ICE_M(0x3, 0)
#define GLGEN_RSTAT_RESET_TYPE_M		ICE_M(0x3, 2)
#define GLGEN_RSTCTL				0x000B8180 /* Reset Source: POR */
#define GLGEN_RSTCTL_GRSTDEL_M			ICE_M(0x3F, 0)
#define GLGEN_RTRIG				0x000B8190 /* Reset Source: CORER */
#define GLGEN_RTRIG_CORER_M			BIT(0)
#define GLGEN_RTRIG_GLOBR_M			BIT(1)
#define GLGEN_STAT				0x000B612C /* Reset Source: POR */
#define GLGEN_VFLRSTAT(_i)			(0x00093A04 + ((_i) * 4)) /* _i=0...7 */ /* Reset Source: CORER */
#define PFGEN_CTRL				0x00091000 /* Reset Source: CORER */
#define PFGEN_CTRL_PFSWR_M			BIT(0)
#define PFGEN_STATE				0x00088000 /* Reset Source: CORER */
#define PRTGEN_STATUS				0x000B8100 /* Reset Source: POR */
#define VFGEN_RSTAT(_VF)			(0x00074000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: VFR */
#define VPGEN_VFRSTAT(_VF)			(0x00090800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPGEN_VFRSTAT_VFRD_M			BIT(0)
#define VPGEN_VFRTRIG(_VF)			(0x00090000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPGEN_VFRTRIG_VFSWR_M			BIT(0)
#define VSIGEN_RSTAT(_VSI)			(0x00092800 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSIGEN_RSTAT_VMRD_M			BIT(0)
#define VSIGEN_RTRIG(_VSI)			(0x00091800 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSIGEN_RTRIG_VMSWR_M			BIT(0)
#define GLINT_CEQCTL(_INT)			(0x0015C000 + ((_INT) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define GLINT_CEQCTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define GLINT_CEQCTL_ITR_INDX_M			ICE_M(0x3, 11)
#define GLINT_CEQCTL_CAUSE_ENA_M		BIT(30)
#define GLINT_CTL				0x0016CC54 /* Reset Source: CORER */
#define GLINT_CTL_DIS_AUTOMASK_M		BIT(0)
#define GLINT_CTL_ITR_GRAN_200_M		ICE_M(0xF, 16)
#define GLINT_CTL_ITR_GRAN_100_M		ICE_M(0xF, 20)
#define GLINT_CTL_ITR_GRAN_50_M			ICE_M(0xF, 24)
#define GLINT_CTL_ITR_GRAN_25_M			ICE_M(0xF, 28)
#define GLINT_DYN_CTL(_INT)			(0x00160000 + ((_INT) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define GLINT_DYN_CTL_INTENA_M			BIT(0)
#define GLINT_DYN_CTL_CLEARPBA_M		BIT(1)
#define GLINT_DYN_CTL_SWINT_TRIG_M		BIT(2)
#define GLINT_DYN_CTL_ITR_INDX_S		3
#define GLINT_DYN_CTL_ITR_INDX_M		ICE_M(0x3, 3)
#define GLINT_DYN_CTL_INTERVAL_S		5
#define GLINT_DYN_CTL_INTERVAL_M		ICE_M(0xFFF, 5)
#define GLINT_DYN_CTL_SW_ITR_INDX_ENA_M		BIT(24)
#define GLINT_DYN_CTL_SW_ITR_INDX_S		25
#define GLINT_DYN_CTL_SW_ITR_INDX_M		ICE_M(0x3, 25)
#define GLINT_DYN_CTL_WB_ON_ITR_M		BIT(30)
#define GLINT_DYN_CTL_INTENA_MSK_M		BIT(31)
#define GLINT_ITR(_i, _INT)			(0x00154000 + ((_i) * 8192 + (_INT) * 4)) /* _i=0...2, _INT=0...2047 */ /* Reset Source: CORER */
#define GLINT_RATE(_INT)			(0x0015A000 + ((_INT) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define GLINT_RATE_INTRL_ENA_M			BIT(6)
#define GLINT_VECT2FUNC(_INT)			(0x00162000 + ((_INT) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define GLINT_VECT2FUNC_VF_NUM_M		ICE_M(0xFF, 0)
#define GLINT_VECT2FUNC_PF_NUM_M		ICE_M(0x7, 12)
#define GLINT_VECT2FUNC_IS_PF_M			BIT(16)
#define PFINT_AEQCTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define PFINT_ALLOC				0x001D2600 /* Reset Source: CORER */
#define PFINT_ALLOC_FIRST_M			ICE_M(0x7FF, 0)
#define PFINT_FW_CTL				0x0016C800 /* Reset Source: CORER */
#define PFINT_FW_CTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define PFINT_FW_CTL_CAUSE_ENA_M		BIT(30)
#define PFINT_MBX_CTL				0x0016B280 /* Reset Source: CORER */
#define PFINT_MBX_CTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define PFINT_MBX_CTL_CAUSE_ENA_M		BIT(30)
#define PFINT_OICR				0x0016CA00 /* Reset Source: CORER */
#define PFINT_OICR_TSYN_TX_M			BIT(11)
#define PFINT_OICR_TSYN_EVNT_M			BIT(12)
#define PFINT_OICR_ECC_ERR_M			BIT(16)
#define PFINT_OICR_MAL_DETECT_M			BIT(19)
#define PFINT_OICR_GRST_M			BIT(20)
#define PFINT_OICR_PCI_EXCEPTION_M		BIT(21)
#define PFINT_OICR_LINK_STAT_CHANGE_M		BIT(25)
#define PFINT_OICR_HMC_ERR_M			BIT(26)
#define PFINT_OICR_PE_PUSH_M			BIT(27)
#define PFINT_OICR_PE_CRITERR_M			BIT(28)
#define PFINT_OICR_VFLR_M			BIT(29)
#define PFINT_OICR_SWINT_M			BIT(31)
#define PFINT_OICR_CTL				0x0016CA80 /* Reset Source: CORER */
#define PFINT_OICR_CTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define PFINT_OICR_CTL_CAUSE_ENA_M		BIT(30)
#define PFINT_OICR_ENA				0x0016C900 /* Reset Source: CORER */
#define PFINT_SB_CTL				0x0016B600 /* Reset Source: CORER */
#define PFINT_SB_CTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define PFINT_SB_CTL_CAUSE_ENA_M		BIT(30)
#define PFINT_TSYN_MSK				0x0016C980 /* Reset Source: CORER */
#define QINT_RQCTL(_QRX)			(0x00150000 + ((_QRX) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QINT_RQCTL_MSIX_INDX_M			ICE_M(0x7FF, 0)
#define QINT_RQCTL_ITR_INDX_M			ICE_M(0x3, 11)
#define QINT_RQCTL_CAUSE_ENA_M			BIT(30)
#define QINT_TQCTL(_DBQM)			(0x00140000 + ((_DBQM) * 4)) /* _i=0...16383 */ /* Reset Source: CORER */
#define QINT_TQCTL_MSIX_INDX_M			ICE_M(0x7FF, 0)
#define QINT_TQCTL_ITR_INDX_M			ICE_M(0x3, 11)
#define QINT_TQCTL_CAUSE_ENA_M			BIT(30)
#define VPINT_AEQCTL(_VF)			(0x0016B800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPINT_AEQCTL_ITR_INDX_M			ICE_M(0x3, 11)
#define VPINT_AEQCTL_CAUSE_ENA_M		BIT(30)
#define VPINT_ALLOC(_VF)			(0x001D1000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPINT_ALLOC_FIRST_M			ICE_M(0x7FF, 0)
#define VPINT_ALLOC_LAST_M			ICE_M(0x7FF, 12)
#define VPINT_ALLOC_VALID_M			BIT(31)
#define VPINT_ALLOC_PCI(_VF)			(0x0009D000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: PCIR */
#define VPINT_ALLOC_PCI_FIRST_M			ICE_M(0x7FF, 0)
#define VPINT_ALLOC_PCI_LAST_M			ICE_M(0x7FF, 12)
#define VPINT_ALLOC_PCI_VALID_M			BIT(31)
#define VPINT_MBX_CTL(_VSI)			(0x0016A000 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define VPINT_MBX_CTL_MSIX_INDX_M		ICE_M(0x7FF, 0)
#define VPINT_MBX_CTL_CAUSE_ENA_M		BIT(30)
#define PFLAN_RX_QALLOC				0x001D2500 /* Reset Source: CORER */
#define PFLAN_RX_QALLOC_FIRSTQ_M		ICE_M(0x7FF, 0)
#define PFLAN_RX_QALLOC_VALID_M			BIT(31)
#define PFLAN_TX_QALLOC				0x001D2580 /* Reset Source: CORER */
#define PFLAN_TX_QALLOC_FIRSTQ_M		ICE_M(0x3FFF, 0)
#define QRX_CONTEXT(_i, _QRX)			(0x00280000 + ((_i) * 8192 + (_QRX) * 4)) /* _i=0...7, _QRX=0...2047 */ /* Reset Source: CORER */
#define QRX_CTRL(_QRX)				(0x00120000 + ((_QRX) * 4)) /* _i=0...2047 */ /* Reset Source: PFR */
#define QRX_CTRL_MAX_INDEX			2047
#define QRX_CTRL_QENA_REQ_M			BIT(0)
#define QRX_CTRL_QENA_STAT_M			BIT(2)
#define QRX_ITR(_QRX)				(0x00292000 + ((_QRX) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QRX_TAIL(_QRX)				(0x00290000 + ((_QRX) * 4)) /* _i=0...2047 */ /* Reset Source: CORER */
#define QRX_TAIL_TAIL_M				ICE_M(0x1FFF, 0)
#define VPLAN_RX_QBASE(_VF)			(0x00072000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPLAN_RX_QBASE_VFFIRSTQ_M		ICE_M(0x7FF, 0)
#define VPLAN_RX_QBASE_VFNUMQ_M			ICE_M(0xFF, 16)
#define VPLAN_RXQ_MAPENA(_VF)			(0x00073000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPLAN_RXQ_MAPENA_RX_ENA_M		BIT(0)
#define VPLAN_TX_QBASE(_VF)			(0x001D1800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPLAN_TX_QBASE_VFFIRSTQ_M		ICE_M(0x3FFF, 0)
#define VPLAN_TX_QBASE_VFNUMQ_M			ICE_M(0xFF, 16)
#define VPLAN_TXQ_MAPENA(_VF)			(0x00073800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VPLAN_TXQ_MAPENA_TX_ENA_M		BIT(0)
#define E800_PRTMAC_HSEC_CTL_TX_PAUSE_QUANTA(_i) (0x001E36E0 + ((_i) * 32)) /* _i=0...8 */ /* Reset Source: GLOBR */
#define E800_PRTMAC_HSEC_CTL_TX_PAUSE_QUANTA_MAX_INDEX 8
#define E800_PRTMAC_HSEC_CTL_TX_PAUSE_QUANTA_HSEC_CTL_TX_PAUSE_QUANTA_M ICE_M(0xFFFF, 0)
#define E800_PRTMAC_HSEC_CTL_TX_PAUSE_REFRESH_TIMER(_i) (0x001E3800 + ((_i) * 32)) /* _i=0...8 */ /* Reset Source: GLOBR */
#define E800_PRTMAC_HSEC_CTL_TX_PAUSE_REFRESH_TIMER_M ICE_M(0xFFFF, 0)
#define GL_MDCK_TX_TDPU				0x00049348 /* Reset Source: CORER */
#define GL_MDCK_TX_TDPU_RCU_ANTISPOOF_ITR_DIS_M	BIT(1)
#define GL_MDET_RX				0x00294C00 /* Reset Source: CORER */
#define GL_MDET_RX_QNUM_M			ICE_M(0x7FFF, 0)
#define GL_MDET_RX_VF_NUM_M			ICE_M(0xFF, 15)
#define GL_MDET_RX_PF_NUM_M			ICE_M(0x7, 23)
#define GL_MDET_RX_MAL_TYPE_M			ICE_M(0x1F, 26)
#define GL_MDET_RX_VALID_M			BIT(31)
#define GL_MDET_TX_PQM				0x002D2E00 /* Reset Source: CORER */
#define GL_MDET_TX_PQM_PF_NUM_M			ICE_M(0x7, 0)
#define GL_MDET_TX_PQM_VF_NUM_M			ICE_M(0xFF, 4)
#define GL_MDET_TX_PQM_QNUM_M			ICE_M(0x3FFF, 12)
#define GL_MDET_TX_PQM_MAL_TYPE_M		ICE_M(0x1F, 26)
#define GL_MDET_TX_PQM_VALID_M			BIT(31)
#define GL_MDET_TX_TCLAN			0x000FC068 /* Reset Source: CORER */
#define GL_MDET_TX_TCLAN_QNUM_M			ICE_M(0x7FFF, 0)
#define GL_MDET_TX_TCLAN_VF_NUM_M		ICE_M(0xFF, 15)
#define GL_MDET_TX_TCLAN_PF_NUM_M		ICE_M(0x7, 23)
#define GL_MDET_TX_TCLAN_MAL_TYPE_M		ICE_M(0x1F, 26)
#define GL_MDET_TX_TCLAN_VALID_M		BIT(31)
#define PF_MDET_RX				0x00294280 /* Reset Source: CORER */
#define PF_MDET_RX_VALID_M			BIT(0)
#define PF_MDET_TX_PQM				0x002D2C80 /* Reset Source: CORER */
#define PF_MDET_TX_PQM_VALID_M			BIT(0)
#define PF_MDET_TX_TCLAN			0x000FC000 /* Reset Source: CORER */
#define PF_MDET_TX_TCLAN_VALID_M		BIT(0)
#define VP_MDET_RX(_VF)				(0x00294400 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VP_MDET_RX_VALID_M			BIT(0)
#define VP_MDET_TX_PQM(_VF)			(0x002D2000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VP_MDET_TX_PQM_VALID_M			BIT(0)
#define VP_MDET_TX_TCLAN(_VF)			(0x000FB800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VP_MDET_TX_TCLAN_VALID_M		BIT(0)
#define VP_MDET_TX_TDPU(_VF)			(0x00040000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define VP_MDET_TX_TDPU_VALID_M			BIT(0)
#define GL_MNG_FWSM				0x000B6134 /* Reset Source: POR */
#define E800_GL_MNG_FWSM_FW_MODES_M		ICE_M(0x7, 0)
#define E830_GL_MNG_FWSM_FW_MODES_M		ICE_M(0x3, 0)
#define GLNVM_FLA				0x000B6108 /* Reset Source: POR */
#define GLNVM_FLA_LOCKED_M			BIT(6)
#define GLNVM_GENS				0x000B6100 /* Reset Source: POR */
#define GLNVM_GENS_SR_SIZE_M			ICE_M(0x7, 5)
#define GLNVM_ULD				0x000B6008 /* Reset Source: POR */
#define GLNVM_ULD_PCIER_DONE_M			BIT(0)
#define GLNVM_ULD_PCIER_DONE_1_M		BIT(1)
#define GLNVM_ULD_CORER_DONE_M			BIT(3)
#define GLNVM_ULD_GLOBR_DONE_M			BIT(4)
#define GLNVM_ULD_POR_DONE_M			BIT(5)
#define GLNVM_ULD_POR_DONE_1_M			BIT(8)
#define GLNVM_ULD_PCIER_DONE_2_M		BIT(9)
#define GLNVM_ULD_PE_DONE_M			BIT(10)
#define GLPCI_CNF2				0x000BE004 /* Reset Source: PCIR */
#define GLPCI_CNF2_CACHELINE_SIZE_M		BIT(1)
#define GLPCI_LBARCTRL				0x0009DE74 /* Reset Source: POR */
#define PF_FUNC_RID				0x0009E880 /* Reset Source: PCIR */
#define PF_FUNC_RID_FUNC_NUM_M			ICE_M(0x7, 0)
#define PF_PCI_CIAA				0x0009E580 /* Reset Source: FLR */
#define PF_PCI_CIAA_VF_NUM_S			12
#define PF_PCI_CIAD				0x0009E500 /* Reset Source: FLR */
#define PFPCI_VMINDEX				0x0009E600 /* Reset Source: PCIR */
#define PFPCI_VMPEND				0x0009E800 /* Reset Source: PCIR */
#define GL_PWR_MODE_CTL				0x000B820C /* Reset Source: POR */
#define GL_PWR_MODE_CTL_CAR_MAX_BW_M		ICE_M(0x3, 30)
#define GLQF_FD_CNT				0x00460018 /* Reset Source: CORER */
#define GLQF_FD_CNT_FD_GCNT_S			0
#define GLQF_FD_CNT_FD_GCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_GLQF_FD_CNT_FD_GCNT_M : E800_GLQF_FD_CNT_FD_GCNT_M)
#define E800_GLQF_FD_CNT_FD_GCNT_M		ICE_M(0x7FFF, 0)
#define E830_GLQF_FD_CNT_FD_GCNT_M		ICE_M(0xFFFF, 0)
#define GLQF_FD_CNT_FD_BCNT_S			16
#define GLQF_FD_CNT_FD_BCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_GLQF_FD_CNT_FD_BCNT_M : E800_GLQF_FD_CNT_FD_BCNT_M)
#define E800_GLQF_FD_CNT_FD_BCNT_M		ICE_M(0x7FFF, 16)
#define E830_GLQF_FD_CNT_FD_BCNT_M		ICE_M(0xFFFF, 16)
#define GLQF_FD_SIZE				0x00460010 /* Reset Source: CORER */
#define GLQF_FD_SIZE_FD_GSIZE_S			0
#define GLQF_FD_SIZE_FD_GSIZE_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_GLQF_FD_SIZE_FD_GSIZE_M : E800_GLQF_FD_SIZE_FD_GSIZE_M)
#define E800_GLQF_FD_SIZE_FD_GSIZE_M		ICE_M(0x7FFF, 0)
#define E830_GLQF_FD_SIZE_FD_GSIZE_M		ICE_M(0xFFFF, 0)
#define GLQF_FD_SIZE_FD_BSIZE_S			16
#define GLQF_FD_SIZE_FD_BSIZE_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_GLQF_FD_SIZE_FD_BSIZE_M : E800_GLQF_FD_SIZE_FD_BSIZE_M)
#define E800_GLQF_FD_SIZE_FD_BSIZE_M		ICE_M(0x7FFF, 16)
#define E830_GLQF_FD_SIZE_FD_BSIZE_M		ICE_M(0xFFFF, 16)
#define GLQF_FDINSET(_i, _j)			(0x00412000 + ((_i) * 4 + (_j) * 512)) /* _i=0...127, _j=0...5 */ /* Reset Source: CORER */
#define GLQF_FDMASK(_i)				(0x00410800 + ((_i) * 4)) /* _i=0...31 */ /* Reset Source: CORER */
#define GLQF_FDMASK_MSK_INDEX_M			ICE_M(0x1F, 0)
#define GLQF_FDMASK_MASK_M			ICE_M(0xFFFF, 16)
#define GLQF_FDMASK_SEL(_i)			(0x00410400 + ((_i) * 4)) /* _i=0...127 */ /* Reset Source: CORER */
#define GLQF_FDSWAP(_i, _j)			(0x00413000 + ((_i) * 4 + (_j) * 512)) /* _i=0...127, _j=0...5 */ /* Reset Source: CORER */
#define GLQF_HINSET(_i, _j)			(0x0040E000 + ((_i) * 4 + (_j) * 512)) /* _i=0...127, _j=0...5 */ /* Reset Source: CORER */
#define GLQF_HMASK(_i)				(0x0040FC00 + ((_i) * 4)) /* _i=0...31 */ /* Reset Source: CORER */
#define GLQF_HMASK_MSK_INDEX_M			ICE_M(0x1F, 0)
#define GLQF_HMASK_MASK_M			ICE_M(0xFFFF, 16)
#define GLQF_HMASK_SEL(_i)			(0x00410000 + ((_i) * 4)) /* _i=0...127 */ /* Reset Source: CORER */
#define GLQF_HSYMM(_i, _j)			(0x0040F000 + ((_i) * 4 + (_j) * 512)) /* _i=0...127, _j=0...5 */ /* Reset Source: CORER */
#define PFQF_FD_CNT				0x00460180 /* Reset Source: CORER */
#define PFQF_FD_CNT_FD_GCNT_S			0
#define PFQF_FD_CNT_FD_GCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_PFQF_FD_CNT_FD_GCNT_M : E800_PFQF_FD_CNT_FD_GCNT_M)
#define E800_PFQF_FD_CNT_FD_GCNT_M		ICE_M(0x7FFF, 0)
#define E830_PFQF_FD_CNT_FD_GCNT_M		ICE_M(0xFFFF, 0)
#define PFQF_FD_CNT_FD_BCNT_S			16
#define PFQF_FD_CNT_FD_BCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_PFQF_FD_CNT_FD_BCNT_M : E800_PFQF_FD_CNT_FD_BCNT_M)
#define E800_PFQF_FD_CNT_FD_BCNT_M		ICE_M(0x7FFF, 16)
#define E830_PFQF_FD_CNT_FD_BCNT_M		ICE_M(0xFFFF, 16)
#define PFQF_FD_ENA				0x0043A000 /* Reset Source: CORER */
#define PFQF_FD_ENA_FD_ENA_M			BIT(0)
#define PFQF_FD_SIZE				0x00460100 /* Reset Source: CORER */
#define GLDCB_RTCTQ(_i)				(0x001222C0 + ((_i) * 4)) /* _i=0...31 */ /* Reset Source: CORER */
#define GLDCB_RTCTQ_RXQNUM_M			ICE_M(0x7FF, 0)
#define GLPRT_BPRCL(_i)				(0x00381380 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_BPTCL(_i)				(0x00381240 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_CRCERRS(_i)			(0x00380100 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_GORCL(_i)				(0x00380000 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_GOTCL(_i)				(0x00380B40 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_ILLERRC(_i)			(0x003801C0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_LXOFFRXC(_i)			(0x003802C0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_LXOFFTXC(_i)			(0x00381180 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_LXONRXC(_i)			(0x00380280 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_LXONTXC(_i)			(0x00381140 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_MLFC(_i)				(0x00380040 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_MPRCL(_i)				(0x00381340 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_MPTCL(_i)				(0x00381200 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_MRFC(_i)				(0x00380080 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC1023L(_i)			(0x00380A00 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC127L(_i)			(0x00380940 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC1522L(_i)			(0x00380A40 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC255L(_i)			(0x00380980 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC511L(_i)			(0x003809C0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC64L(_i)			(0x00380900 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PRC9522L(_i)			(0x00380A80 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC1023L(_i)			(0x00380C80 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC127L(_i)			(0x00380BC0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC1522L(_i)			(0x00380CC0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC255L(_i)			(0x00380C00 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC511L(_i)			(0x00380C40 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC64L(_i)			(0x00380B80 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PTC9522L(_i)			(0x00380D00 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_PXOFFRXC(_i, _j)			(0x00380500 + ((_i) * 8 + (_j) * 64)) /* _i=0...7, _j=0...7 */ /* Reset Source: CORER */
#define GLPRT_PXOFFTXC(_i, _j)			(0x00380F40 + ((_i) * 8 + (_j) * 64)) /* _i=0...7, _j=0...7 */ /* Reset Source: CORER */
#define GLPRT_PXONRXC(_i, _j)			(0x00380300 + ((_i) * 8 + (_j) * 64)) /* _i=0...7, _j=0...7 */ /* Reset Source: CORER */
#define GLPRT_PXONTXC(_i, _j)			(0x00380D40 + ((_i) * 8 + (_j) * 64)) /* _i=0...7, _j=0...7 */ /* Reset Source: CORER */
#define GLPRT_RFC(_i)				(0x00380AC0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_RJC(_i)				(0x00380B00 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_RLEC(_i)				(0x00380140 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_ROC(_i)				(0x00380240 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_RUC(_i)				(0x00380200 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_RXON2OFFCNT(_i, _j)		(0x00380700 + ((_i) * 8 + (_j) * 64)) /* _i=0...7, _j=0...7 */ /* Reset Source: CORER */
#define GLPRT_TDOLD(_i)				(0x00381280 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_UPRCL(_i)				(0x00381300 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLPRT_UPTCL(_i)				(0x003811C0 + ((_i) * 8)) /* _i=0...7 */ /* Reset Source: CORER */
#define GLSTAT_FD_CNT0H(_i)			(0x003A0004 + ((_i) * 8)) /* _i=0...4095 */ /* Reset Source: CORER */
#define GLSTAT_FD_CNT0L(_i)			(0x003A0000 + ((_i) * 8)) /* _i=0...4095 */ /* Reset Source: CORER */
#define GLV_BPRCL(_i)				(0x003B6000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_BPTCL(_i)				(0x0030E000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_GORCL(_i)				(0x003B0000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_GOTCL(_i)				(0x00300000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_MPRCL(_i)				(0x003B4000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_MPTCL(_i)				(0x0030C000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_RDPC(_i)				(0x00294C04 + ((_i) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_TEPC(_VSI)				(0x00312000 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_UPRCL(_i)				(0x003B2000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define GLV_UPTCL(_i)				(0x0030A000 + ((_i) * 8)) /* _i=0...767 */ /* Reset Source: CORER */
#define PRTRPB_RDPC				0x000AC260 /* Reset Source: CORER */
#define GLHH_ART_CTL				0x000A41D4 /* Reset Source: POR */
#define GLHH_ART_CTL_ACTIVE_M			BIT(0)
#define GLHH_ART_CTL_TIME_OUT1_M		BIT(1)
#define GLHH_ART_CTL_TIME_OUT2_M		BIT(2)
#define GLHH_ART_TIME_H				0x000A41D8 /* Reset Source: POR */
#define GLHH_ART_TIME_L				0x000A41DC /* Reset Source: POR */
#define GLTSYN_AUX_IN_0(_i)			(0x000889D8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_AUX_IN_0_INT_ENA_M		BIT(4)
#define GLTSYN_AUX_OUT_0(_i)			(0x00088998 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_AUX_OUT_0_OUT_ENA_M		BIT(0)
#define GLTSYN_AUX_OUT_0_OUTMOD_M		ICE_M(0x3, 1)
#define GLTSYN_CLKO_0(_i)			(0x000889B8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_CMD				0x00088810 /* Reset Source: CORER */
#define GLTSYN_CMD_SYNC				0x00088814 /* Reset Source: CORER */
#define GLTSYN_ENA(_i)				(0x00088808 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_ENA_TSYN_ENA_M			BIT(0)
#define GLTSYN_EVNT_H_0(_i)			(0x00088970 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_EVNT_L_0(_i)			(0x00088968 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_HHTIME_H(_i)			(0x00088900 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_HHTIME_L(_i)			(0x000888F8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_INCVAL_H(_i)			(0x00088920 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_INCVAL_L(_i)			(0x00088918 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_SHADJ_H(_i)			(0x00088910 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_SHADJ_L(_i)			(0x00088908 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_SHTIME_0(_i)			(0x000888E0 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_SHTIME_H(_i)			(0x000888F0 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_SHTIME_L(_i)			(0x000888E8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_STAT(_i)				(0x000888C0 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_STAT_EVENT0_M			BIT(0)
#define GLTSYN_STAT_EVENT1_M			BIT(1)
#define GLTSYN_STAT_EVENT2_M			BIT(2)
#define GLTSYN_SYNC_DLAY			0x00088818 /* Reset Source: CORER */
#define GLTSYN_TGT_H_0(_i)			(0x00088930 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_TGT_L_0(_i)			(0x00088928 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_TIME_0(_i)			(0x000888C8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_TIME_H(_i)			(0x000888D8 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define GLTSYN_TIME_L(_i)			(0x000888D0 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define PFHH_SEM				0x000A4200 /* Reset Source: PFR */
#define PFHH_SEM_BUSY_M				BIT(0)
#define PFTSYN_SEM				0x00088880 /* Reset Source: PFR */
#define PFTSYN_SEM_BUSY_M			BIT(0)
#define VSIQF_FD_CNT(_VSI)			(0x00464000 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: PFR */
#define VSIQF_FD_CNT_FD_GCNT_S			0
#define VSIQF_FD_CNT_FD_GCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_VSIQF_FD_CNT_FD_GCNT_M : E800_VSIQF_FD_CNT_FD_GCNT_M)
#define E800_VSIQF_FD_CNT_FD_GCNT_M		ICE_M(0x3FFF, 0)
#define E830_VSIQF_FD_CNT_FD_GCNT_M		ICE_M(0xFFFF, 0)
#define VSIQF_FD_CNT_FD_BCNT_S			16
#define VSIQF_FD_CNT_FD_BCNT_M_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? E830_VSIQF_FD_CNT_FD_BCNT_M : E800_VSIQF_FD_CNT_FD_BCNT_M)
#define E800_VSIQF_FD_CNT_FD_BCNT_M		ICE_M(0x3FFF, 16)
#define E830_VSIQF_FD_CNT_FD_BCNT_M		ICE_M(0xFFFF, 16)
#define VSIQF_FD_SIZE(_VSI)			(0x00462000 + ((_VSI) * 4)) /* _i=0...767 */ /* Reset Source: CORER */
#define VSIQF_HKEY_MAX_INDEX			12
#define PFPM_APM				0x000B8080 /* Reset Source: POR */
#define PFPM_APM_APME_M				BIT(0)
#define PFPM_WUFC				0x0009DC00 /* Reset Source: POR */
#define PFPM_WUFC_MAG_M				BIT(1)
#define PFPM_WUS				0x0009DB80 /* Reset Source: POR */
#define PFPM_WUS_LNKC_M				BIT(0)
#define PFPM_WUS_MAG_M				BIT(1)
#define PFPM_WUS_MNG_M				BIT(3)
#define PFPM_WUS_FW_RST_WK_M			BIT(31)
#define VF_MBX_ARQBAH1				0x00006000 /* Reset Source: CORER */
#define VF_MBX_ARQBAL1				0x00006C00 /* Reset Source: CORER */
#define VF_MBX_ARQH1				0x00007400 /* Reset Source: CORER */
#define VF_MBX_ARQLEN1				0x00008000 /* Reset Source: PFR */
#define VF_MBX_ARQT1				0x00007000 /* Reset Source: CORER */
#define VF_MBX_ATQBAH1				0x00007800 /* Reset Source: CORER */
#define VF_MBX_ATQBAL1				0x00007C00 /* Reset Source: CORER */
#define VF_MBX_ATQH1				0x00006400 /* Reset Source: CORER */
#define VF_MBX_ATQLEN1				0x00006800 /* Reset Source: PFR */
#define VF_MBX_ATQT1				0x00008400 /* Reset Source: CORER */
#define VFGEN_RSTAT1				0x00008800 /* Reset Source: VFR */
#define VFINT_DYN_CTL0				0x00005C00 /* Reset Source: CORER */
#define VFINT_DYN_CTLN(_i)			(0x00003800 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define VFINT_ITR0(_i)				(0x00004C00 + ((_i) * 4)) /* _i=0...2 */ /* Reset Source: CORER */
#define QRX_TAIL1(_QRX)				(0x00002000 + ((_QRX) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define QTX_TAIL(_DBQM)				(0x00000000 + ((_DBQM) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define E830_GLQTX_TXTIME_DBELL_LSB(_DBQM)	(0x002E0000 + ((_DBQM) * 8)) /* _i=0...16383 */ /* Reset Source: CORER */
#define E830_GLTXTIME_FETCH_PROFILE(_i, _j)	(0x002D3500 + ((_i) * 4 + (_j) * 64)) /* _i=0...15, _j=0...15 */ /* Reset Source: CORER */
#define E830_GLTXTIME_FETCH_PROFILE_FETCH_TS_DESC_M ICE_M(0x1FF, 0)
#define E830_MBX_PF_IN_FLIGHT_VF_MSGS_THRESH	0x00234000 /* Reset Source: CORER */
#define E830_MBX_VF_DEC_TRIG(_VF)		(0x00233800 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define E830_MBX_VF_IN_FLIGHT_MSGS_AT_PF_CNT(_VF) (0x00233000 + ((_VF) * 4)) /* _i=0...255 */ /* Reset Source: CORER */
#define E830_PRTTSYN_TXTIME_H(_i)		(0x001E5800 + ((_i) * 32)) /* _i=0...63 */ /* Reset Source: GLOBR */
#define E830_PRTTSYN_TXTIME_L(_i)		(0x001E5000 + ((_i) * 32)) /* _i=0...63 */ /* Reset Source: GLOBR */
#define E830_GL_MDET_TX_TCLAN_FIFO		0x000FCFD0 /* Reset Source: CORER */
#define E830_GL_MDET_TX_TCLAN_FIFO_FUNC_NUM_S	0
#define E830_GL_MDET_TX_TCLAN_FIFO_FUNC_NUM_M	ICE_M(0x3FF, 0)
#define E830_GL_MDET_TX_TCLAN_FIFO_PF_NUM_S	10
#define E830_GL_MDET_TX_TCLAN_FIFO_PF_NUM_M	ICE_M(0x7, 10)
#define E830_GL_MDET_TX_TCLAN_FIFO_FUNC_TYPE_S	13
#define E830_GL_MDET_TX_TCLAN_FIFO_FUNC_TYPE_M	ICE_M(0x3, 13)
#define E830_GL_MDET_TX_TCLAN_FIFO_MAL_TYPE_S	15
#define E830_GL_MDET_TX_TCLAN_FIFO_MAL_TYPE_M	ICE_M(0x1F, 15)
#define E830_GL_MDET_TX_TCLAN_FIFO_FIFO_FULL_S	20
#define E830_GL_MDET_TX_TCLAN_FIFO_FIFO_FULL_M	BIT(20)
#define E830_GL_MDET_TX_TCLAN_FIFO_VALID_S	21
#define E830_GL_MDET_TX_TCLAN_FIFO_VALID_M	BIT(21)
#define E830_GL_MDET_TX_TCLAN_FIFO_EVENT_CNT_S	24
#define E830_GL_MDET_TX_TCLAN_FIFO_EVENT_CNT_M	ICE_M(0xFF, 24)
#define E830_GL_MDET_TX_TCLAN_PF_CNT(_i)	(0x000FCF90 + ((_i) * 4)) /* _i=0...7 */ /* Reset Source: CORER */
#define E830_GL_MDET_TX_TCLAN_PF_CNT_MAX_INDEX	7
#define E830_GL_MDET_TX_TCLAN_PF_CNT_CNT_S	0
#define E830_GL_MDET_TX_TCLAN_PF_CNT_CNT_M	ICE_M(0xFFFFFFFF, 0)
#define E830_GL_MDET_TX_TCLAN_VF(_i)		(0x000FCFB0 + ((_i) * 4)) /* _i=0...7 */ /* Reset Source: CORER */
#define E830_GL_MDET_TX_TCLAN_VF_MAX_INDEX	7
#define E830_GL_MDET_TX_TCLAN_VF_VF_MAL_EVENT_S	0
#define E830_GL_MDET_TX_TCLAN_VF_VF_MAL_EVENT_M	ICE_M(0xFFFFFFFF, 0)
#define E830_GL_HICR_EN				0x00082044 /* Reset Source: EMPR */
#define E830_GLFLXP_RXDID_FLX_WRD_0_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_0_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_1_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_1_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_2_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_2_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_3_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_3_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_4_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_4_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_5_SPARE_S	18
#define E830_GLFLXP_RXDID_FLX_WRD_5_SPARE_M	ICE_M(0xF, 18)
#define E830_GLFLXP_RXDID_FLX_WRD_6(_i)		(0x0045CE00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define E830_GLFLXP_RXDID_FLX_WRD_6_MAX_INDEX	63
#define E830_GLFLXP_RXDID_FLX_WRD_6_PROT_MDID_S	0
#define E830_GLFLXP_RXDID_FLX_WRD_6_PROT_MDID_M	ICE_M(0xFF, 0)
#define E830_GLFLXP_RXDID_FLX_WRD_6_EXTRACTION_OFFSET_S 8
#define E830_GLFLXP_RXDID_FLX_WRD_6_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define E830_GLFLXP_RXDID_FLX_WRD_6_L2TAG_OVRD_EN_S 18
#define E830_GLFLXP_RXDID_FLX_WRD_6_L2TAG_OVRD_EN_M BIT(18)
#define E830_GLFLXP_RXDID_FLX_WRD_6_SPARE_S	19
#define E830_GLFLXP_RXDID_FLX_WRD_6_SPARE_M	ICE_M(0x7, 19)
#define E830_GLFLXP_RXDID_FLX_WRD_6_RXDID_OPCODE_S 30
#define E830_GLFLXP_RXDID_FLX_WRD_6_RXDID_OPCODE_M ICE_M(0x3, 30)
#define E830_GLFLXP_RXDID_FLX_WRD_7(_i)		(0x0045CF00 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define E830_GLFLXP_RXDID_FLX_WRD_7_MAX_INDEX	63
#define E830_GLFLXP_RXDID_FLX_WRD_7_PROT_MDID_S	0
#define E830_GLFLXP_RXDID_FLX_WRD_7_PROT_MDID_M	ICE_M(0xFF, 0)
#define E830_GLFLXP_RXDID_FLX_WRD_7_EXTRACTION_OFFSET_S 8
#define E830_GLFLXP_RXDID_FLX_WRD_7_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define E830_GLFLXP_RXDID_FLX_WRD_7_L2TAG_OVRD_EN_S 18
#define E830_GLFLXP_RXDID_FLX_WRD_7_L2TAG_OVRD_EN_M BIT(18)
#define E830_GLFLXP_RXDID_FLX_WRD_7_SPARE_S	19
#define E830_GLFLXP_RXDID_FLX_WRD_7_SPARE_M	ICE_M(0x7, 19)
#define E830_GLFLXP_RXDID_FLX_WRD_7_RXDID_OPCODE_S 30
#define E830_GLFLXP_RXDID_FLX_WRD_7_RXDID_OPCODE_M ICE_M(0x3, 30)
#define E830_GLFLXP_RXDID_FLX_WRD_8(_i)		(0x0045D500 + ((_i) * 4)) /* _i=0...63 */ /* Reset Source: CORER */
#define E830_GLFLXP_RXDID_FLX_WRD_8_MAX_INDEX	63
#define E830_GLFLXP_RXDID_FLX_WRD_8_PROT_MDID_S	0
#define E830_GLFLXP_RXDID_FLX_WRD_8_PROT_MDID_M	ICE_M(0xFF, 0)
#define E830_GLFLXP_RXDID_FLX_WRD_8_EXTRACTION_OFFSET_S 8
#define E830_GLFLXP_RXDID_FLX_WRD_8_EXTRACTION_OFFSET_M ICE_M(0x3FF, 8)
#define E830_GLFLXP_RXDID_FLX_WRD_8_L2TAG_OVRD_EN_S 18
#define E830_GLFLXP_RXDID_FLX_WRD_8_L2TAG_OVRD_EN_M BIT(18)
#define E830_GLFLXP_RXDID_FLX_WRD_8_SPARE_S	19
#define E830_GLFLXP_RXDID_FLX_WRD_8_SPARE_M	ICE_M(0x7, 19)
#define E830_GLFLXP_RXDID_FLX_WRD_8_RXDID_OPCODE_S 30
#define E830_GLFLXP_RXDID_FLX_WRD_8_RXDID_OPCODE_M ICE_M(0x3, 30)
#define E830_PRTMAC_CL01_PAUSE_QUANTA		0x001E32A0 /* Reset Source: GLOBR */
#define E830_PRTMAC_CL01_PAUSE_QUANTA_CL0_PAUSE_QUANTA_M ICE_M(0xFFFF, 0)
#define E830_PRTMAC_CL01_QUANTA_THRESH		0x001E3320 /* Reset Source: GLOBR */
#define E830_PRTMAC_CL01_QUANTA_THRESH_CL0_QUANTA_THRESH_M ICE_M(0xFFFF, 0)
#define E830_PRTMAC_TS_TX_MEM_VALID_H		0x001E2020 /* Reset Source: GLOBR */
#define E830_PRTMAC_TS_TX_MEM_VALID_L		0x001E2000 /* Reset Source: GLOBR */
#define E830_GLPTM_ART_CTL			0x00088B50 /* Reset Source: POR */
#define E830_GLPTM_ART_CTL_ACTIVE_M		BIT(0)
#define E830_GLPTM_ART_CTL_TIME_OUT_M		BIT(1)
#define E830_GLPTM_ART_TIME_H			0x00088B54 /* Reset Source: POR */
#define E830_GLPTM_ART_TIME_L			0x00088B58 /* Reset Source: POR */
#define E830_GLTSYN_PTMTIME_H(_i)		(0x00088B48 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define E830_GLTSYN_PTMTIME_L(_i)		(0x00088B40 + ((_i) * 4)) /* _i=0...1 */ /* Reset Source: CORER */
#define E830_PFPTM_SEM				0x00088B00 /* Reset Source: PFR */
#define E830_PFPTM_SEM_BUSY_M			BIT(0)
#endif /* !_ICE_HW_AUTOGEN_H_ */

