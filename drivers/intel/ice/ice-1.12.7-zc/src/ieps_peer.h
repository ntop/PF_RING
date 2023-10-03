/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

/* Intel(R) Ethernet Connection E800 Series Linux Driver IEPS extensions */

#ifndef _IEPS_PEER_H_
#define _IEPS_PEER_H_

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/bitops.h>

#define IEPS_VERSION_PEER_MAJOR    1
#define IEPS_VERSION_PEER_MINOR    1

struct ieps_peer_api_version {
	__u8  major;
	__u8  minor;
};

struct ieps_peer_i2c {
	__u8  bus;
	__u16 dev_addr;
	__u16 reg_addr;
	bool  en_10b_addr;
	__u8  *data;
	__u8  data_len;
};

enum ieps_peer_mdio_clause {
	IEPS_PEER_MDIO_CLAUSE_22,
	IEPS_PEER_MDIO_CLAUSE_45,

	/* Must be last */
	NUM_IEPS_PEER_MDIO_CLAUSE
};

struct ieps_peer_mdio {
	enum  ieps_peer_mdio_clause clause;
	__u8  bus;
	__u8  phy_addr;
	__u8  dev_type;
	__u16 reg_addr;
	__u16 *data;
	__u8  data_len;
};

struct ieps_peer_gpio {
	__u8 pin_num;
	bool is_input;
	bool pin_val;
};

/* INTPHY */
enum ieps_peer_phy_type {
	IEPS_PEER_PHY_TYPE_100BASE_TX         =  0,
	IEPS_PEER_PHY_TYPE_100M_SGMII         =  1,
	IEPS_PEER_PHY_TYPE_1000BASE_T         =  2,
	IEPS_PEER_PHY_TYPE_1000BASE_SX        =  3,
	IEPS_PEER_PHY_TYPE_1000BASE_LX        =  4,
	IEPS_PEER_PHY_TYPE_1000BASE_KX        =  5,
	IEPS_PEER_PHY_TYPE_1G_SGMII           =  6,
	IEPS_PEER_PHY_TYPE_2500BASE_T         =  7,
	IEPS_PEER_PHY_TYPE_2500BASE_X         =  8,
	IEPS_PEER_PHY_TYPE_2500BASE_KX        =  9,
	IEPS_PEER_PHY_TYPE_5GBASE_T           = 10,
	IEPS_PEER_PHY_TYPE_5GBASE_KR          = 11,
	IEPS_PEER_PHY_TYPE_10GBASE_T          = 12,
	IEPS_PEER_PHY_TYPE_10G_SFI_DA         = 13,
	IEPS_PEER_PHY_TYPE_10GBASE_SR         = 14,
	IEPS_PEER_PHY_TYPE_10GBASE_LR         = 15,
	IEPS_PEER_PHY_TYPE_10GBASE_KR_CR1     = 16,
	IEPS_PEER_PHY_TYPE_10G_SFI_AOC_ACC    = 17,
	IEPS_PEER_PHY_TYPE_10G_SFI_C2C        = 18,
	IEPS_PEER_PHY_TYPE_25GBASE_T          = 19,
	IEPS_PEER_PHY_TYPE_25GBASE_CR         = 20,
	IEPS_PEER_PHY_TYPE_25GBASE_CR_S       = 21,
	IEPS_PEER_PHY_TYPE_25GBASE_CR1        = 22,
	IEPS_PEER_PHY_TYPE_25GBASE_SR         = 23,
	IEPS_PEER_PHY_TYPE_25GBASE_LR         = 24,
	IEPS_PEER_PHY_TYPE_25GBASE_KR         = 25,
	IEPS_PEER_PHY_TYPE_25GBASE_KR_S       = 26,
	IEPS_PEER_PHY_TYPE_25GBASE_KR1        = 27,
	IEPS_PEER_PHY_TYPE_25G_AUI_AOC_ACC    = 28,
	IEPS_PEER_PHY_TYPE_25G_AUI_C2C        = 29,
	IEPS_PEER_PHY_TYPE_40GBASE_CR4        = 30,
	IEPS_PEER_PHY_TYPE_40GBASE_SR4        = 31,
	IEPS_PEER_PHY_TYPE_40GBASE_LR4        = 32,
	IEPS_PEER_PHY_TYPE_40GBASE_KR4        = 33,
	IEPS_PEER_PHY_TYPE_40G_XLAUI_AOC_ACC  = 34,
	IEPS_PEER_PHY_TYPE_40G_XLAUI          = 35,
	IEPS_PEER_PHY_TYPE_50GBASE_CR2        = 36,
	IEPS_PEER_PHY_TYPE_50GBASE_SR2        = 37,
	IEPS_PEER_PHY_TYPE_50GBASE_LR2        = 38,
	IEPS_PEER_PHY_TYPE_50GBASE_KR2        = 39,
	IEPS_PEER_PHY_TYPE_50G_LAUI2_AOC_ACC  = 40,
	IEPS_PEER_PHY_TYPE_50G_LAUI2          = 41,
	IEPS_PEER_PHY_TYPE_50G_AUI2_AOC_ACC   = 42,
	IEPS_PEER_PHY_TYPE_50G_AUI2           = 43,
	IEPS_PEER_PHY_TYPE_50GBASE_CP         = 44,
	IEPS_PEER_PHY_TYPE_50GBASE_SR         = 45,
	IEPS_PEER_PHY_TYPE_50GBASE_FR         = 46,
	IEPS_PEER_PHY_TYPE_50GBASE_LR         = 47,
	IEPS_PEER_PHY_TYPE_50GBASE_KR_PAM4    = 48,
	IEPS_PEER_PHY_TYPE_50G_AUI1_AOC_ACC   = 49,
	IEPS_PEER_PHY_TYPE_50G_AUI1           = 50,
	IEPS_PEER_PHY_TYPE_100GBASE_CR4       = 51,
	IEPS_PEER_PHY_TYPE_100GBASE_SR4       = 52,
	IEPS_PEER_PHY_TYPE_100GBASE_LR4       = 53,
	IEPS_PEER_PHY_TYPE_100GBASE_KR4       = 54,
	IEPS_PEER_PHY_TYPE_100G_CAUI4_AOC_ACC = 55,
	IEPS_PEER_PHY_TYPE_100G_CAUI4         = 56,
	IEPS_PEER_PHY_TYPE_100G_AUI4_AOC_ACC  = 57,
	IEPS_PEER_PHY_TYPE_100G_AUI4          = 58,
	IEPS_PEER_PHY_TYPE_100GBASE_CR_PAM4   = 59,
	IEPS_PEER_PHY_TYPE_100GBASE_KR_PAM4   = 60,
	IEPS_PEER_PHY_TYPE_100GBASE_CP2       = 61,
	IEPS_PEER_PHY_TYPE_100GBASE_SR2       = 62,
	IEPS_PEER_PHY_TYPE_100GBASE_DR        = 63,
	IEPS_PEER_PHY_TYPE_100GBASE_KR2_PAM4  = 64,
	IEPS_PEER_PHY_TYPE_100G_CAUI2_AOC_ACC = 65,
	IEPS_PEER_PHY_TYPE_100G_CAUI2         = 66,
	IEPS_PEER_PHY_TYPE_100G_AUI2_AOC_ACC  = 67,
	IEPS_PEER_PHY_TYPE_100G_AUI2          = 68,

	NUM_IEPS_PEER_PHY_TYPE,
};

struct ieps_peer_phy_caps {
	__u64 phy_type_low;
	__u64 phy_type_high;

	bool en_tx_pause;
	bool en_rx_pause;
	bool low_power_mode;
	bool en_link;
	bool an_mode;
	bool en_lesm;
	bool en_auto_fec;

	__u32 an_options_bm;
	__u32 fec_options_bm;
	__u8 phy_fw_ver[8];
};

enum ieps_peer_phy_fec_type {
	IEPS_PEER_FEC_10G_40G_KR_EN  = BIT(0),
	IEPS_PEER_FEC_10G_40G_KR_REQ = BIT(1),
	IEPS_PEER_FEC_25G_RS_528_REQ = BIT(2),
	IEPS_PEER_FEC_25G_KR_REQ     = BIT(3),
	IEPS_PEER_FEC_25G_RS_544_REQ = BIT(4),
	IEPS_PEER_FEC_25G_RS_CL91_EN = BIT(6),
	IEPS_PEER_FEC_25G_KR_CL74_EN = BIT(7),

	MASK_IEPS_PEER_FEC           = 0xDF,
};

enum ieps_peer_phy_an_clause {
	IEPS_PEER_AN_D3COLD = BIT(0),
	IEPS_PEER_AN_CL28   = BIT(1),
	IEPS_PEER_AN_CL73   = BIT(2),
	IEPS_PEER_AN_CL37   = BIT(3),

	MASK_IEPS_PEER_AN        = 0xF,
};

enum ieps_peer_port_mode {
	IEPS_PEER_PORT_MODE_DOWN,
	IEPS_PEER_PORT_MODE_UP,

	NUM_IEPS_PEER_PORT_MODE,
};

struct ieps_peer_phy_link_status {
	__u8 link_cfg_err;
	bool link_up;
	bool link_fault_tx;
	bool link_fault_rx;
	bool link_fault_remote;
	bool link_up_ext_port;
	bool media_available; /* Not applicable for BASE_T or BACKPLANE */
	bool los;
	bool an_complete;
	bool an_capable; /* Valid if AN enabled */
	bool fec_enabled;
	bool in_low_power_state;
	bool is_tx_pause_en;
	bool is_rx_pause_en;
	bool exessive_link_err;
	bool tx_suspended;
	bool lb_mac_on;
	bool lb_phy_local_on;
	bool lb_phy_remote_on;
	bool lse_on;
	enum ieps_peer_phy_fec_type fec_type;
	enum ieps_peer_phy_type phy_type;
	__le64 phy_type_low;
	__le64 phy_type_high;
};

enum ieps_peer_port_attr {
	IEPS_PEER_PA_PHY_TYPE,
	IEPS_PEER_PA_PHY_AN,
	IEPS_PEER_PA_PHY_FEC,
	IEPS_PEER_PA_PHY_LOOPBACK_LOCAL,
	IEPS_PEER_PA_PHY_LOOPBACK_REMOTE,

	NUM_IEPS_PEER_PA_PHY,
};

union ieps_peer_port_attr_cfg {
	enum ieps_peer_phy_type phy_type;
	bool an_cl37_enable;
	__u32 fec_options_bm;
	bool en_phy_local_lb;
	bool en_phy_remote_lb;
};

struct ieps_peer_port_attr_data {
	enum ieps_peer_port_attr attr;
	union ieps_peer_port_attr_cfg cfg;
};

struct ieps_peer_intphy_reg_rw {
	__u64 reg;
	__u32 data;
	bool is_write;
};

enum ieps_peer_cmd {
	IEPS_PEER_CMD_VERSION_CHECK,
	IEPS_PEER_CMD_I2C_READ,
	IEPS_PEER_CMD_I2C_WRITE,
	IEPS_PEER_CMD_MDIO_READ,
	IEPS_PEER_CMD_MDIO_WRITE,
	IEPS_PEER_CMD_GPIO_GET,
	IEPS_PEER_CMD_GPIO_SET,

	/* INTPHY */
	IEPS_PEER_CMD_GET_NVM_PHY_CAPS,
	IEPS_PEER_CMD_GET_LINK_STATUS,
	IEPS_PEER_CMD_PORT_SET_MODE,
	IEPS_PEER_CMD_PORT_GET_MODE,
	IEPS_PEER_CMD_PORT_SET_ATTR,
	IEPS_PEER_CMD_PORT_GET_ATTR,

	/* DFX */
	IEPS_PEER_CMD_INTPHY_REG_RW,

	IEPS_PEER_CMD_SET_LM_CONFIG,

	/* Must be last */
	NUM_IEPS_PEER_CMD
};

enum ieps_peer_status {
	IEPS_PEER_SUCCESS,
	IEPS_PEER_FW_ERROR,
	IEPS_PEER_NO_MEMORY,
	IEPS_PEER_INVALID_CMD,
	IEPS_PEER_INVALID_ARG,
	IEPS_PEER_INVALID_PEER_DEV,
	IEPS_PEER_VER_INCOMPATIBLE,

	IEPS_PEER_INVALID_PORT_MODE,
	IEPS_PEER_INVALID_PORT_ATTR,
	IEPS_PEER_PORT_INV_PHY_TYPE,
	IEPS_PEER_INVALID_AN_OPT,
	IEPS_PEER_INVALID_FEC_OPT,
	IEPS_PEER_MULTIPLE_PHY_TYPE,
	IEPS_PEER_PHY_TYPE_NOTSUP,
	IEPS_PEER_FEC_OPT_NOTSUP,
};

struct ieps_peer_arg {
	enum ieps_peer_cmd	cmd;
	unsigned int		port;
	void			*data;
	enum ieps_peer_status	status;
};

#endif /* _IEPS_PEER_H_ */
