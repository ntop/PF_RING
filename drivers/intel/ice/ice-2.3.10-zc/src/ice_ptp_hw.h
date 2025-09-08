/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_PTP_HW_H_
#define _ICE_PTP_HW_H_
#if defined(CONFIG_DPLL)
#include <linux/dpll.h>
#endif /* CONFIG_DPLL */

enum ice_ptp_tmr_cmd {
	ICE_PTP_INIT_TIME,
	ICE_PTP_INIT_INCVAL,
	ICE_PTP_ADJ_TIME,
	ICE_PTP_ADJ_TIME_AT_TIME,
	ICE_PTP_READ_TIME,
	ICE_PTP_NOP,
};

enum ice_ptp_serdes {
	ICE_PTP_SERDES_1G,
	ICE_PTP_SERDES_10G,
	ICE_PTP_SERDES_25G,
	ICE_PTP_SERDES_40G,
	ICE_PTP_SERDES_50G,
	ICE_PTP_SERDES_100G
};

enum ice_ptp_link_spd {
	ICE_PTP_LNK_SPD_1G,
	ICE_PTP_LNK_SPD_10G,
	ICE_PTP_LNK_SPD_25G,
	ICE_PTP_LNK_SPD_25G_RS,
	ICE_PTP_LNK_SPD_40G,
	ICE_PTP_LNK_SPD_50G,
	ICE_PTP_LNK_SPD_50G_RS,
	ICE_PTP_LNK_SPD_100G_RS,
	NUM_ICE_PTP_LNK_SPD /* Must be last */
};

enum ice_ptp_fec_mode {
	ICE_PTP_FEC_MODE_NONE,
	ICE_PTP_FEC_MODE_CLAUSE74,
	ICE_PTP_FEC_MODE_RS_FEC
};

#if !defined(CONFIG_DPLL)

/* Copied from include/uapi/linux/dpll.h to have common dpll status enums
 * between sysfs and dpll subsystem based solutions.
 */
enum dpll_lock_status {
	DPLL_LOCK_STATUS_UNLOCKED = 1,
	DPLL_LOCK_STATUS_LOCKED,
	DPLL_LOCK_STATUS_LOCKED_HO_ACQ,
	DPLL_LOCK_STATUS_HOLDOVER,
};
#endif /* !CONFIG_DPLL */

enum eth56g_res_type {
	ETH56G_PHY_REG_PTP,
	ETH56G_PHY_MEM_PTP,
	ETH56G_PHY_REG_XPCS,
	ETH56G_PHY_REG_MAC,
	ETH56G_PHY_REG_GPCS,
	NUM_ETH56G_PHY_RES
};

#define ETH56G_MAX_QUAD	1

/**
 * struct ice_phy_reg_info_eth56g
 * @base: base address for each PHY block
 * @step: step between PHY lanes
 *
 * Characteristic information for the various PHY register parameters in the
 * ETH56G devices
 */
struct ice_phy_reg_info_eth56g {
	u32 base[ETH56G_MAX_QUAD];
	u32 step;
};

/**
 * struct ice_tspll_info_e82x
 * @pll_freq: Frequency of PLL that drives timer ticks in Hz
 * @nominal_incval: increment to generate nanoseconds in GLTSYN_TIME_L
 *
 * Characteristic information for the various TIME_REF sources possible in the
 * E82X devices
 */
struct ice_tspll_info_e82x {
	u64 pll_freq;
	u64 nominal_incval;
};

/**
 * struct ice_vernier_info_e82x
 * @tx_par_clk: Frequency used to calculate P_REG_PAR_TX_TUS
 * @rx_par_clk: Frequency used to calculate P_REG_PAR_RX_TUS
 * @tx_pcs_clk: Frequency used to calculate P_REG_PCS_TX_TUS
 * @rx_pcs_clk: Frequency used to calculate P_REG_PCS_RX_TUS
 * @tx_desk_rsgb_par: Frequency used to calculate P_REG_DESK_PAR_TX_TUS
 * @rx_desk_rsgb_par: Frequency used to calculate P_REG_DESK_PAR_RX_TUS
 * @tx_desk_rsgb_pcs: Frequency used to calculate P_REG_DESK_PCS_TX_TUS
 * @rx_desk_rsgb_pcs: Frequency used to calculate P_REG_DESK_PCS_RX_TUS
 * @tx_fixed_delay: Fixed Tx latency measured in 1/100th nanoseconds
 * @pmd_adj_divisor: Divisor used to calculate PDM alignment adjustment
 * @rx_fixed_delay: Fixed Rx latency measured in 1/100th nanoseconds
 *
 * Table of constants used during as part of the Vernier calibration of the Tx
 * and Rx timestamps. This includes frequency values used to compute TUs per
 * PAR/PCS clock cycle, and static delay values measured during hardware
 * design.
 *
 * Note that some values are not used for all link speeds, and the
 * P_REG_DESK_PAR* registers may represent different clock markers at
 * different link speeds, either the deskew marker for multi-lane link speeds
 * or the Reed Solomon gearbox marker for RS-FEC.
 */
struct ice_vernier_info_e82x {
	u32 tx_par_clk;
	u32 rx_par_clk;
	u32 tx_pcs_clk;
	u32 rx_pcs_clk;
	u32 tx_desk_rsgb_par;
	u32 rx_desk_rsgb_par;
	u32 tx_desk_rsgb_pcs;
	u32 rx_desk_rsgb_pcs;
	u32 tx_fixed_delay;
	u32 pmd_adj_divisor;
	u32 rx_fixed_delay;
};

#define ICE_ETH56G_MAC_CFG_RX_OFFSET_INT	GENMASK(19, 9)
#define ICE_ETH56G_MAC_CFG_RX_OFFSET_FRAC	GENMASK(8, 0)
#define ICE_ETH56G_MAC_CFG_FRAC_W		9
/**
 * struct ice_eth56g_mac_reg_cfg
 * @tx_mode: Tx timestamp compensation mode
 * @tx_mk_dly: Tx timestamp marker start strobe delay
 * @tx_cw_dly: Tx timestamp codeword start strobe delay
 * @rx_mode: Rx timestamp compensation mode
 * @rx_mk_dly: Rx timestamp marker start strobe delay
 * @rx_cw_dly: Rx timestamp codeword start strobe delay
 * @blks_per_clk: number of blocks transferred per clock cycle
 * @blktime: block time, fixed point
 * @mktime: marker time, fixed point
 * @tx_offset: total Tx offset, fixed point
 * @rx_offset: total Rx offset, contains value for bitslip/deskew, fixed point
 *
 * MAC config values for specific PTP registers.
 * All fixed point registers except Rx offset are 23 bit unsigned integers with
 * a 9 bit fractional.
 * Rx offset is 11 bit signed integer with a 9 bit fractional.
 */
struct ice_eth56g_mac_reg_cfg {
	struct {
		u8 def;
		u8 rs;
	} tx_mode;
	u8 tx_mk_dly;
	struct {
		u8 def;
		u8 onestep;
	} tx_cw_dly;
	struct {
		u8 def;
		u8 rs;
	} rx_mode;
	struct {
		u8 def;
		u8 rs;
	} rx_mk_dly;
	struct {
		u8 def;
		u8 rs;
	} rx_cw_dly;
	u8 blks_per_clk;
	u16 blktime;
	u16 mktime;
	struct {
		u32 serdes;
		u32 no_fec;
		u32 fc;
		u32 rs;
		u32 sfd;
		u32 onestep;
	} tx_offset;
	struct {
		u32 serdes;
		u32 no_fec;
		u32 fc;
		u32 rs;
		u32 sfd;
		u32 bs_ds;
	} rx_offset;
};

extern
const struct ice_eth56g_mac_reg_cfg eth56g_mac_cfg[NUM_ICE_ETH56G_LNK_SPD];

enum ice_phy_rclk_pins {
	ICE_RCLKA_PIN = 0,		/* SCL pin */
	ICE_RCLKB_PIN,			/* SDA pin */
};

#define ICE_E810_RCLK_PINS_NUM		(ICE_RCLKB_PIN + 1)
#define ICE_E822_RCLK_PINS_NUM		(ICE_RCLKA_PIN + 1)
#define E810T_CGU_INPUT_C827(_phy, _pin) ((_phy) * ICE_E810_RCLK_PINS_NUM + \
					  (_pin) + ZL_REF1P)

enum ice_zl_cgu_in_pins {
	ZL_REF0P = 0,
	ZL_REF0N,
	ZL_REF1P,
	ZL_REF1N,
	ZL_REF2P,
	ZL_REF2N,
	ZL_REF3P,
	ZL_REF3N,
	ZL_REF4P,
	ZL_REF4N,
	NUM_ZL_CGU_PINS
};

enum ice_zl_cgu_out_pins {
	ZL_OUT0 = 0,
	ZL_OUT1,
	ZL_OUT2,
	ZL_OUT3,
	ZL_OUT4,
	ZL_OUT5,
	ZL_OUT6,
	NUM_ZL_CGU_OUTPUT_PINS
};

enum ice_si_cgu_in_pins {
	SI_REF0P = 0,
	SI_REF0N,
	SI_REF1P,
	SI_REF1N,
	SI_REF2P,
	SI_REF2N,
	SI_REF3,
	SI_REF4,
	NUM_SI_CGU_PINS
};

enum ice_si_cgu_out_pins {
	SI_OUT0 = 0,
	SI_OUT1,
	SI_OUT2,
	SI_OUT3,
	SI_OUT4,
	NUM_SI_CGU_OUTPUT_PINS
};

struct ice_cgu_pin_desc {
	char *name;
	u8 index;
#if defined(CONFIG_DPLL)
	enum dpll_pin_type type;
	u32 freq_supp_num;
	struct dpll_pin_frequency *freq_supp;
#endif /* CONFIG_DPLL */
};

enum ice_e825c_ref_clk {
	ICE_REF_CLK_ENET,
	ICE_REF_CLK_SYNCE,
	ICE_REF_CLK_EREF0,
	ICE_REF_CLK_MAX,
};

enum ice_e810t_cgu_dpll {
	ICE_CGU_DPLL_SYNCE,
	ICE_CGU_DPLL_PTP,
	ICE_CGU_DPLL_MAX
};

#define MAX_CGU_STATE_NAME_LEN 14
struct ice_cgu_state_desc {
	char name[MAX_CGU_STATE_NAME_LEN];
	enum dpll_lock_status state;
};

/* Table of constants related to possible ETH56G PHY resources */
extern const struct ice_phy_reg_info_eth56g eth56g_phy_res[NUM_ETH56G_PHY_RES];

/* Table of constants related to possible TIME_REF sources */
extern const struct ice_tspll_info_e82x e82x_tspll[NUM_ICE_TSPLL_FREQ];

/* Table of constants for Vernier calibration on E82X */
extern const struct ice_vernier_info_e82x e82x_vernier[NUM_ICE_PTP_LNK_SPD];

/* Increment value to generate nanoseconds in the GLTSYN_TIME_L register for
 * the E810 devices. Based off of a PLL with an 812.5 MHz frequency.
 */

#define ICE_PTP_NOMINAL_INCVAL_E810	0x13b13b13bULL
#define ICE_E810_E830_SYNC_DELAY	0
#define ICE_E825C_SYNC_DELAY		6

/* Device agnostic functions */
u8 ice_get_ptp_src_clock_index(struct ice_hw *hw);
bool ice_ptp_lock(struct ice_hw *hw);
void ice_ptp_unlock(struct ice_hw *hw);
void ice_ptp_src_cmd(struct ice_hw *hw, enum ice_ptp_tmr_cmd cmd);
int ice_ptp_init_time(struct ice_hw *hw, u64 time);
int ice_ptp_write_incval(struct ice_hw *hw, u64 incval);
int ice_ptp_write_incval_locked(struct ice_hw *hw, u64 incval);
int ice_ptp_adj_clock(struct ice_hw *hw, s32 adj);
int ice_ptp_clear_phy_offset_ready_e82x(struct ice_hw *hw);
int ice_read_phy_tstamp(struct ice_hw *hw, u8 block, u8 idx, u64 *tstamp);
int ice_clear_phy_tstamp(struct ice_hw *hw, u8 block, u8 idx);
void ice_ptp_reset_ts_memory(struct ice_hw *hw);
int ice_ptp_init_phc(struct ice_hw *hw);
bool refsync_pin_id_valid(struct ice_hw *hw, u8 id);
int ice_get_phy_tx_tstamp_ready(struct ice_hw *hw, u8 block, u64 *tstamp_ready);
int ice_ptp_one_port_cmd(struct ice_hw *hw, u8 configured_port,
			 enum ice_ptp_tmr_cmd configured_cmd);
int ice_ptp_config_sfd(struct ice_hw *hw, bool sfd_ena);

/* E82X family functions */
#define LOCKED_INCVAL_E82X 0x100000000ULL

int ice_read_phy_reg_e82x(struct ice_hw *hw, u8 port, u16 offset, u32 *val);
int ice_read_quad_reg_e82x(struct ice_hw *hw, u8 quad, u16 offset, u32 *val);
int ice_write_quad_reg_e82x(struct ice_hw *hw, u8 quad, u16 offset, u32 val);
void ice_ptp_reset_ts_memory_quad_e82x(struct ice_hw *hw, u8 quad);

/* E82X Vernier calibration functions */
int ice_stop_phy_timer_e82x(struct ice_hw *hw, u8 port, bool soft_reset);
int ice_start_phy_timer_e82x(struct ice_hw *hw, u8 port);
int ice_phy_cfg_tx_offset_e82x(struct ice_hw *hw, u8 port);
int ice_phy_cfg_rx_offset_e82x(struct ice_hw *hw, u8 port);
int ice_phy_cfg_intr_e82x(struct ice_hw *hw, u8 quad, bool ena, u8 threshold);

int ice_write_pca9575_reg(struct ice_hw *hw, u8 offset, u8 data);
bool ice_is_pca9575_present(struct ice_hw *hw);
int ice_ptp_read_sdp_ac(struct ice_hw *hw, __le16 *entries, uint *num_entries);
int ice_ena_dis_clk_ref(struct ice_hw *hw, int phy,
			enum ice_e825c_ref_clk clk, bool enable);
int ice_cgu_get_pin_num(struct ice_hw *hw, bool input);
bool ice_is_cgu_in_netlist(struct ice_hw *hw);
const char *ice_cgu_state_to_name(enum dpll_lock_status state);
const char *ice_cgu_get_pin_name(const struct ice_hw *hw, u8 pin, bool input);
#if defined(CONFIG_DPLL)
enum dpll_pin_type
ice_cgu_get_pin_type(const struct ice_hw *hw, u8 pin, bool input);
struct dpll_pin_frequency *
ice_cgu_get_pin_freq_supp(const struct ice_hw *hw, u8 pin, bool input, u8 *num);
#endif /* DPLL_SUPPORT && CONFIG_DPLL */
int ice_get_cgu_state(struct ice_hw *hw, u8 dpll_idx,
		      enum dpll_lock_status last_dpll_state, u8 *pin,
		      u8 *ref_state, u8 *eec_mode, s64 *phase_offset,
		      enum dpll_lock_status *dpll_state);
#if defined(CONFIG_DPLL)
int ice_get_cgu_rclk_pin_info(struct ice_hw *hw, u8 *base_idx, u8 *pin_num);
int ice_cgu_get_output_pin_state_caps(struct ice_hw *hw, u8 pin_id,
				      unsigned long *caps);
#endif /* DPLL_SUPPORT && CONFIG_DPLL */
int ice_get_dpll_ref_sw_status(struct ice_hw *hw, u8 dpll_num, u8 *los,
			       u8 *scm, u8 *cfm, u8 *gst, u8 *pfm, u8 *esync);
int
ice_set_dpll_ref_sw_status(struct ice_hw *hw, u8 dpll_num, u8 monitor,
			   u8 enable);
/* ETH56G family functions */
int ice_write_phy_eth56g(struct ice_hw *hw, u8 port, u32 addr, u32 val);
int ice_read_phy_eth56g(struct ice_hw *hw, u8 port, u32 addr, u32 *val);
int ice_cgu_set_pps_out(struct ice_hw *hw, bool ena, u8 amp);
int ice_ptp_read_tx_hwtstamp_status_eth56g(struct ice_hw *hw, u32 *ts_status);
int ice_stop_phy_timer_eth56g(struct ice_hw *hw, u8 port, bool soft_reset);
int ice_start_phy_timer_eth56g(struct ice_hw *hw, u8 port);
int ice_phy_cfg_tx_offset_eth56g(struct ice_hw *hw, u8 port);
int ice_phy_cfg_rx_offset_eth56g(struct ice_hw *hw, u8 port);
int ice_phy_cfg_intr_eth56g(struct ice_hw *hw, u8 port, bool ena, u8 threshold);
int ice_phy_cfg_ptp_1step_eth56g(struct ice_hw *hw, u8 port);

#define ICE_ETH56G_NOMINAL_INCVAL	0x140000000ULL
#define ICE_ETH56G_NOMINAL_PCS_REF_TUS	0x100000000ULL
#define ICE_ETH56G_NOMINAL_PCS_REF_INC	0x300000000ULL
#define ICE_ETH56G_NOMINAL_THRESH4	0x7777
#define ICE_ETH56G_NOMINAL_TX_THRESH	0x6

void ice_ptp_init_hw(struct ice_hw *hw);

#define ICE_E825_PLL_FREQ	800000000

static inline u64 ice_e82x_pll_freq(enum ice_tspll_freq time_ref)
{
	return e82x_tspll[time_ref].pll_freq;
}

static inline u64 ice_ptp_get_pll_freq(const struct ice_hw *hw)
{
	switch (hw->mac_type) {
	case ICE_MAC_GENERIC:
		return ice_e82x_pll_freq(hw->ptp.tspll_freq);
	case ICE_MAC_GENERIC_3K_E825:
		return ICE_E825_PLL_FREQ;
	default:
		return 0;
	}
}

static inline u64 ice_e82x_nominal_incval(enum ice_tspll_freq time_ref)
{
	return e82x_tspll[time_ref].nominal_incval;
}

static inline u64 ice_get_base_incval(const struct ice_hw *hw,
				      enum ice_src_tmr_mode src_tmr_mode)
{
	switch (hw->mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_E830:
		return ICE_PTP_NOMINAL_INCVAL_E810;
	case ICE_MAC_GENERIC:
		if (src_tmr_mode == ICE_SRC_TMR_MODE_NANOSECONDS &&
		    hw->ptp.tspll_freq < NUM_ICE_TSPLL_FREQ)
			return ice_e82x_nominal_incval(hw->ptp.tspll_freq);
		else
			return LOCKED_INCVAL_E82X;

		break;
	case ICE_MAC_GENERIC_3K_E825:
		return ICE_ETH56G_NOMINAL_INCVAL;
	default:
		return 0;
	}
}
/* PHY timer commands */
#define SEL_CPK_SRC	8
#define SEL_PHY_SRC	3

/* Time Sync command Definitions */
#define GLTSYN_CMD_INIT_TIME		BIT(0)
#define GLTSYN_CMD_INIT_INCVAL		BIT(1)
#define GLTSYN_CMD_INIT_TIME_INCVAL	(BIT(0) | BIT(1))
#define GLTSYN_CMD_ADJ_TIME		BIT(2)
#define GLTSYN_CMD_ADJ_INIT_TIME	(BIT(2) | BIT(3))
#define GLTSYN_CMD_READ_TIME		BIT(7)

/* PHY port Time Sync command definitions */
#define PHY_CMD_INIT_TIME		BIT(0)
#define PHY_CMD_INIT_INCVAL		BIT(1)
#define PHY_CMD_ADJ_TIME		(BIT(0) | BIT(1))
#define PHY_CMD_ADJ_TIME_AT_TIME	(BIT(0) | BIT(2))
#define PHY_CMD_READ_TIME		(BIT(0) | BIT(1) | BIT(2))

#define TS_CMD_MASK_E810		0xFF
#define TS_CMD_MASK			0xF
#define SYNC_EXEC_CMD			0x3
#define TS_CMD_RX_TYPE			ICE_M(0x18, 4)

/* Macros to derive port low and high addresses on both quads */
#define P_Q0_L(a, p) ((((a) + (0x2000 * (p)))) & 0xFFFF)
#define P_Q0_H(a, p) ((((a) + (0x2000 * (p)))) >> 16)
#define P_Q1_L(a, p) ((((a) - (0x2000 * ((p) - ICE_PORTS_PER_QUAD)))) & 0xFFFF)
#define P_Q1_H(a, p) ((((a) - (0x2000 * ((p) - ICE_PORTS_PER_QUAD)))) >> 16)

/* PHY QUAD register base addresses */
#define Q_0_BASE			0x94000
#define Q_1_BASE			0x114000

/* Timestamp memory reset registers */
#define Q_REG_TS_CTRL			0x618
#define Q_REG_TS_CTRL_M			BIT(0)

/* Timestamp availability status registers */
#define Q_REG_TX_MEMORY_STATUS_L	0xCF0
#define Q_REG_TX_MEMORY_STATUS_U	0xCF4

/* Tx FIFO status registers */
#define Q_REG_FIFO23_STATUS		0xCF8
#define Q_REG_FIFO01_STATUS		0xCFC
#define Q_REG_FIFO02_M			ICE_M(0x3FF, 0)
#define Q_REG_FIFO13_M			ICE_M(0x3FF, 10)

/* Interrupt control Config registers */
#define Q_REG_TX_MEM_GBL_CFG		0xC08
#define Q_REG_TX_MEM_GBL_CFG_LANE_TYPE_M	BIT(0)
#define Q_REG_TX_MEM_GBL_CFG_TX_TYPE_M	ICE_M(0xFF, 1)
#define Q_REG_TX_MEM_GBL_CFG_INTR_THR_M ICE_M(0x3F, 9)
#define Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M	BIT(15)

/* Tx Timestamp data registers */
#define Q_REG_TX_MEMORY_BANK_START	0xA00

/* PHY port register base addresses */
#define P_0_BASE			0x80000
#define P_4_BASE			0x106000

/* Timestamp init registers */
#define P_REG_RX_TIMER_INC_PRE_L	0x46C
#define P_REG_RX_TIMER_INC_PRE_U	0x470
#define P_REG_TX_TIMER_INC_PRE_L	0x44C
#define P_REG_TX_TIMER_INC_PRE_U	0x450

/* Timestamp match and adjust target registers */
#define P_REG_RX_TIMER_CNT_ADJ_L	0x474
#define P_REG_RX_TIMER_CNT_ADJ_U	0x478
#define P_REG_TX_TIMER_CNT_ADJ_L	0x454
#define P_REG_TX_TIMER_CNT_ADJ_U	0x458

/* Timestamp capture registers */
#define P_REG_RX_CAPTURE_L		0x4D8
#define P_REG_RX_CAPTURE_U		0x4DC
#define P_REG_TX_CAPTURE_L		0x4B4
#define P_REG_TX_CAPTURE_U		0x4B8

/* Timestamp PHY incval registers */
#define P_REG_TIMETUS_L			0x410
#define P_REG_TIMETUS_U			0x414

/* PHY window length registers */
#define P_REG_WL			0x40C
#define P_REG_WL_VERNIER		0x111ED

/* PHY start registers */
#define P_REG_PS			0x408
#define P_REG_PS_START_M		BIT(0)
#define P_REG_PS_BYPASS_MODE_M		BIT(1)
#define P_REG_PS_ENA_CLK_M		BIT(2)
#define P_REG_PS_LOAD_OFFSET_M		BIT(3)
#define P_REG_PS_SFT_RESET_M		BIT(11)

/* PHY offset valid registers */
#define P_REG_TX_OV_STATUS		0x4D4
#define P_REG_RX_OV_STATUS		0x4F8
#define P_REG_OV_STATUS_M		BIT(0)

/* PHY offset ready registers */
#define P_REG_TX_OR			0x45C
#define P_REG_RX_OR			0x47C

/* PHY total offset registers */
#define P_REG_TOTAL_RX_OFFSET_L		0x460
#define P_REG_TOTAL_RX_OFFSET_U		0x464
#define P_REG_TOTAL_TX_OFFSET_L		0x440
#define P_REG_TOTAL_TX_OFFSET_U		0x444

/* Timestamp PAR/PCS registers */
#define P_REG_UIX66_10G_40G_L		0x480
#define P_REG_UIX66_10G_40G_U		0x484
#define P_REG_UIX66_25G_100G_L		0x488
#define P_REG_UIX66_25G_100G_U		0x48C
#define P_REG_DESK_PAR_RX_TUS_L		0x490
#define P_REG_DESK_PAR_RX_TUS_U		0x494
#define P_REG_DESK_PAR_TX_TUS_L		0x498
#define P_REG_DESK_PAR_TX_TUS_U		0x49C
#define P_REG_DESK_PCS_RX_TUS_L		0x4A0
#define P_REG_DESK_PCS_RX_TUS_U		0x4A4
#define P_REG_DESK_PCS_TX_TUS_L		0x4A8
#define P_REG_DESK_PCS_TX_TUS_U		0x4AC
#define P_REG_PAR_RX_TUS_L		0x420
#define P_REG_PAR_RX_TUS_U		0x424
#define P_REG_PAR_TX_TUS_L		0x428
#define P_REG_PAR_TX_TUS_U		0x42C
#define P_REG_PCS_RX_TUS_L		0x430
#define P_REG_PCS_RX_TUS_U		0x434
#define P_REG_PCS_TX_TUS_L		0x438
#define P_REG_PCS_TX_TUS_U		0x43C
#define P_REG_PAR_RX_TIME_L		0x4F0
#define P_REG_PAR_RX_TIME_U		0x4F4
#define P_REG_PAR_TX_TIME_L		0x4CC
#define P_REG_PAR_TX_TIME_U		0x4D0
#define P_REG_PAR_PCS_RX_OFFSET_L	0x4E8
#define P_REG_PAR_PCS_RX_OFFSET_U	0x4EC
#define P_REG_PAR_PCS_TX_OFFSET_L	0x4C4
#define P_REG_PAR_PCS_TX_OFFSET_U	0x4C8
#define P_REG_LINK_SPEED		0x4FC
#define P_REG_LINK_SPEED_SERDES_M	ICE_M(0x7, 0)
#define P_REG_LINK_SPEED_FEC_MODE_M	ICE_M(0x3, 3)

/* PHY timestamp related registers */
#define P_REG_PMD_ALIGNMENT		0x0FC
#define P_REG_RX_80_TO_160_CNT		0x6FC
#define P_REG_RX_80_TO_160_CNT_RXCYC_M	BIT(0)
#define P_REG_RX_40_TO_160_CNT		0x8FC
#define P_REG_RX_40_TO_160_CNT_RXCYC_M	ICE_M(0x3, 0)

/* Rx FIFO status registers */
#define P_REG_RX_OV_FS			0x4F8
#define P_REG_RX_OV_FS_FIFO_STATUS_M	ICE_M(0x3FF, 2)

/* Timestamp command registers */
#define P_REG_TX_TMR_CMD		0x448
#define P_REG_RX_TMR_CMD		0x468

/* E810 timesync enable register */
#define ETH_GLTSYN_ENA(_i)		(0x03000348 + ((_i) * 4))

/* E810 shadow init time registers */
#define ETH_GLTSYN_SHTIME_0(i)		(0x03000368 + ((i) * 32))
#define ETH_GLTSYN_SHTIME_L(i)		(0x0300036C + ((i) * 32))

/* E810 shadow time adjust registers */
#define ETH_GLTSYN_SHADJ_L(_i)		(0x03000378 + ((_i) * 32))
#define ETH_GLTSYN_SHADJ_H(_i)		(0x0300037C + ((_i) * 32))

/* E810 timer command register */
#define E810_ETH_GLTSYN_CMD		0x03000344

/* E830 timer command register */
#define E830_ETH_GLTSYN_CMD		0x00088814

/* E810 PHC time register */
#define E830_GLTSYN_TIME_L(_tmr_idx)	(0x0008A000 + 0x1000 * (_tmr_idx))

/* Source timer incval macros */
#define INCVAL_HIGH_M			0xFF

/* PHY 40b registers macros */
#define PHY_EXT_40B_LOW_M		GENMASK(31, 0)
#define PHY_EXT_40B_HIGH_M		GENMASK_ULL(39, 32)
#define PHY_40B_LOW_M			GENMASK(7, 0)
#define PHY_40B_HIGH_M			GENMASK_ULL(39, 8)
#define TS_VALID			BIT(0)

#define BYTES_PER_IDX_ADDR_L_U		8
#define BYTES_PER_IDX_ADDR_L		4

/* Tx timestamp low latency read definitions */
#define ATQBAL_LL_TIMEOUT_US		2000
#define ATQBAL_LL_PHY_TMR_CMD_M		GENMASK(7, 6)
#define ATQBAL_LL_PHY_TMR_CMD_ADJ	0x1
#define ATQBAL_LL_PHY_TMR_CMD_FREQ	0x2
#define ATQBAL_LL_TS_HIGH		GENMASK(23, 16)
#define ATQBAL_LL_PHY_TMR_IDX_M		BIT(24)
#define ATQBAL_LL_TS_IDX		GENMASK(29, 24)
#define ATQBAL_LL_TS_INTR_ENA		BIT(30)
#define ATQBAL_LL_EXEC			BIT(31)

/* Internal PHY timestamp address */
#define TS_L(a, idx) ((a) + ((idx) * BYTES_PER_IDX_ADDR_L_U))
#define TS_H(a, idx) ((a) + ((idx) * BYTES_PER_IDX_ADDR_L_U +		\
			     BYTES_PER_IDX_ADDR_L))

/* External PHY timestamp address */
#define TS_EXT(a, port, idx) ((a) + (0x1000 * (port)) +			\
				 ((idx) * BYTES_PER_IDX_ADDR_L_U))

#define LOW_TX_MEMORY_BANK_START	0x03090000
#define HIGH_TX_MEMORY_BANK_START	0x03090004


/* PCA9575 IO controller registers */
#define ICE_PCA9575_P0_IN	0x0
#define ICE_PCA9575_P1_IN	0x1
#define ICE_PCA9575_P0_CFG	0x8
#define ICE_PCA9575_P1_CFG	0x9
#define ICE_PCA9575_P0_OUT	0xA
#define ICE_PCA9575_P1_OUT	0xB

/* PCA9575 IO controller pin control */
#define ICE_P0_GNSS_PRSNT_N	BIT(4)

/* ETH56G PHY register addresses */
/* Timestamp PHY incval registers */
#define PHY_REG_TIMETUS_L		0x8
#define PHY_REG_TIMETUS_U		0xC

/* Timestamp PCS registers */
#define PHY_PCS_REF_TUS_L		0x18
#define PHY_PCS_REF_TUS_U		0x1C

/* Timestamp PCS ref incval registers */
#define PHY_PCS_REF_INC_L		0x20
#define PHY_PCS_REF_INC_U		0x24

/* Timestamp init registers */
#define PHY_REG_RX_TIMER_INC_PRE_L	0x64
#define PHY_REG_RX_TIMER_INC_PRE_U	0x68
#define PHY_REG_TX_TIMER_INC_PRE_L	0x44
#define PHY_REG_TX_TIMER_INC_PRE_U	0x48

/* Timestamp match and adjust target registers */
#define PHY_REG_RX_TIMER_CNT_ADJ_L	0x6C
#define PHY_REG_RX_TIMER_CNT_ADJ_U	0x70
#define PHY_REG_TX_TIMER_CNT_ADJ_L	0x4C
#define PHY_REG_TX_TIMER_CNT_ADJ_U	0x50

/* Timestamp command registers */
#define PHY_REG_TX_TMR_CMD		0x40
#define PHY_REG_RX_TMR_CMD		0x60

/* Phy offset ready registers */
#define PHY_REG_TX_OFFSET_READY		0x54
#define PHY_REG_RX_OFFSET_READY		0x74

/* Phy total offset registers */
#define PHY_REG_TOTAL_TX_OFFSET_L	0x38
#define PHY_REG_TOTAL_TX_OFFSET_U	0x3C
#define PHY_REG_TOTAL_RX_OFFSET_L	0x58
#define PHY_REG_TOTAL_RX_OFFSET_U	0x5C

/* Timestamp capture registers */
#define PHY_REG_TX_CAPTURE_L		0x78
#define PHY_REG_TX_CAPTURE_U		0x7C
#define PHY_REG_RX_CAPTURE_L		0x8C
#define PHY_REG_RX_CAPTURE_U		0x90

/* Memory status registers */
#define PHY_REG_TX_MEMORY_STATUS_L	0x80
#define PHY_REG_TX_MEMORY_STATUS_U	0x84

/* Interrupt config register */
#define PHY_REG_TS_INT_CONFIG		0x88

/* XIF mode config register */
#define PHY_MAC_XIF_MODE		0x24
#define PHY_MAC_XIF_1STEP_ENA_M		ICE_M(0x1, 5)
#define PHY_MAC_XIF_TS_BIN_MODE_M	ICE_M(0x1, 11)
#define PHY_MAC_XIF_TS_SFD_ENA_M	ICE_M(0x1, 20)
#define PHY_MAC_XIF_GMII_TS_SEL_M	ICE_M(0x1, 21)

#define PHY_TS_INT_CONFIG_THRESHOLD_M	ICE_M(0x3F, 0)
#define PHY_TS_INT_CONFIG_ENA_M		BIT(6)

/* Macros to derive offsets for TimeStampLow and TimeStampHigh */
#define PHY_TSTAMP_L(x) (((x) * 8) + 0)
#define PHY_TSTAMP_U(x) (((x) * 8) + 4)

#define PHY_REG_DESKEW_0		0x94
#define PHY_REG_DESKEW_0_RLEVEL		GENMASK(6, 0)
#define PHY_REG_DESKEW_0_RLEVEL_FRAC	GENMASK(9, 7)
#define PHY_REG_DESKEW_0_RLEVEL_FRAC_W	3
#define PHY_REG_DESKEW_0_VALID		GENMASK(10, 10)

#define PHY_VENDOR_TXLANE_THRESH	0x2000C

#define PHY_MAC_TSU_CONFIG		0x40
#define PHY_MAC_TSU_CFG_RX_MODE_M	ICE_M(0x7, 0)
#define PHY_MAC_TSU_CFG_RX_MII_CW_DLY_M	ICE_M(0x7, 4)
#define PHY_MAC_TSU_CFG_RX_MII_MK_DLY_M	ICE_M(0x7, 8)
#define PHY_MAC_TSU_CFG_TX_MODE_M	ICE_M(0x7, 12)
#define PHY_MAC_TSU_CFG_TX_MII_CW_DLY_M	ICE_M(0x1F, 16)
#define PHY_MAC_TSU_CFG_TX_MII_MK_DLY_M	ICE_M(0x1F, 21)
#define PHY_MAC_TSU_CFG_BLKS_PER_CLK_M	ICE_M(0x1, 28)
#define PHY_MAC_RX_MODULO		0x44
#define PHY_MAC_RX_OFFSET		0x48
#define PHY_MAC_RX_OFFSET_M		ICE_M(0xFFFFFF, 0)
#define PHY_MAC_TX_MODULO		0x4C
#define PHY_MAC_BLOCKTIME		0x50
#define PHY_MAC_MARKERTIME		0x54
#define PHY_MAC_TX_OFFSET		0x58
#define PHY_GPCS_BITSLIP		0x5C

#define PHY_PTP_INT_STATUS		0x7FD140

/* ETH56G registers shared per quad */
/* GPCS config register */
#define PHY_GPCS_CONFIG_REG0		0x268
#define PHY_GPCS_CONFIG_REG0_TX_THR_M	ICE_M(0xF, 24)
/* 1-step PTP config */
#define PHY_PTP_1STEP_CONFIG		0x270
#define PHY_PTP_1STEP_T1S_UP64_M	ICE_M(0xF, 4)
#define PHY_PTP_1STEP_T1S_DELTA_M	ICE_M(0xF, 8)
#define PHY_PTP_1STEP_PEER_DELAY(_quad_lane)	(0x274 + 4 * (_quad_lane))
#define PHY_PTP_1STEP_PD_ADD_PD_M	ICE_M(0x1, 0)
#define PHY_PTP_1STEP_PD_DELAY_M	ICE_M(0x3fffffff, 1)
#define PHY_PTP_1STEP_PD_DLY_V_M	ICE_M(0x1, 31)
#define PHY_REG_SD_BIT_SLIP(_quad_lane)	(0x29C + 4 * (_quad_lane))

#endif /* _ICE_PTP_HW_H_ */
