/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_PTP_H_
#define _ICE_PTP_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>

enum tmr_cmd {
	INIT_TIME,
	INIT_INCVAL,
	ADJ_TIME,
	ADJ_TIME_AT_TIME,
	READ_TIME
};

enum port_type {
	RX,
	TX
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

enum ice_ptp_fec_algo {
	ICE_PTP_FEC_ALGO_NO_FEC,
	ICE_PTP_FEC_ALGO_CLAUSE74,
	ICE_PTP_FEC_ALGO_RS_FEC
};


#define MAC_RX_LINK_COUNTER(_port)	(0x600090 + 0x1000 * (_port))
#define PFTSYN_SEM_BYTES		4
#define PTP_SHARED_CLK_IDX_VALID	BIT(31)
#define PHY_TIMER_SELECT_VALID_BIT	0
#define PHY_TIMER_SELECT_BIT		1
#define PHY_TIMER_SELECT_MASK		0xFFFFFFFC
#define TS_LOW_MASK			0xFFFFFFFF
#define TS_HIGH_MASK			0xFF
#define TS_PHY_LOW_MASK			0xFF
#define TS_PHY_HIGH_MASK		0xFFFFFFFF
#define TS_CMD_MASK_EXT			0xFF
#define TS_CMD_MASK			0xF
#define SYNC_EXEC_CMD			0x3
#define ICE_PTP_TS_VALID		BIT(0)
#define FIFO_EMPTY			BIT(2)
#define FIFO_OK				0xFF
#define ICE_PTP_FIFO_NUM_CHECKS		5
/* PHY, quad and port definitions */
#define INDEX_PER_QUAD			64
#define INDEX_PER_PORT			(INDEX_PER_QUAD / ICE_PORTS_PER_QUAD)
#define INDEX_PER_PORT_EXT		64
#define TX_INTR_QUAD_MASK		0x03
/* Per-channel register definitions */
#define GLTSYN_AUX_OUT(_chan, _idx)	(GLTSYN_AUX_OUT_0(_idx) + ((_chan) * 8))
#define GLTSYN_CLKO(_chan, _idx)	(GLTSYN_CLKO_0(_idx) + ((_chan) * 8))
#define GLTSYN_TGT_L(_chan, _idx)	(GLTSYN_TGT_L_0(_idx) + ((_chan) * 16))
#define GLTSYN_TGT_H(_chan, _idx)	(GLTSYN_TGT_H_0(_idx) + ((_chan) * 16))
/* Pin definitions for PTP PPS out */
#define PPS_CLK_GEN_CHAN		3
#define PPS_PIN_INDEX			5
/* Macros to derive the low and high addresses for PHY */
#define LOWER_ADDR_SIZE			16
/* Macros to derive offsets for TimeStampLow and TimeStampHigh */
#define BYTES_PER_IDX_ADDR_L_U		8
#define BYTES_PER_IDX_ADDR_L		4
#define TS_L(_a, _idx) ((_a) + ((_idx) * BYTES_PER_IDX_ADDR_L_U))
#define TS_H(_a, _idx) ((_a) + ((_idx) * BYTES_PER_IDX_ADDR_L_U +              \
				BYTES_PER_IDX_ADDR_L))
#define TS_EXT(_a, _port, _idx) ((_a) + (0x1000 * (_port)) +                   \
				 ((_idx) * BYTES_PER_IDX_ADDR_L_U))
/* Macros to derive port low and high addresses on both quads */
#define P_Q0_L(_a, _p) ICE_LO_WORD(((_a) + (0x2000 * (_p))))
#define P_Q0_H(_a, _p) ICE_HI_WORD(((_a) + (0x2000 * (_p))))
#define P_Q1_L(_a, _p) ICE_LO_WORD(((_a) - (0x2000 * ((_p) -                   \
						      ICE_PORTS_PER_QUAD))))
#define P_Q1_H(_a, _p) ICE_HI_WORD(((_a) - (0x2000 * ((_p) -                   \
						      ICE_PORTS_PER_QUAD))))
/* PHY QUAD register base addresses */
#define Q_0_BASE			0x94000
#define Q_1_BASE			0x114000
/* Timestamp memory reset registers */
#define Q_REG_TS_CTRL			0x618
#define Q_REG_TS_CTRL_S			0
#define Q_REG_TS_CTRL_M			BIT(0)
/* Timestamp availability status registers */
#define Q_REG_TX_MEMORY_STATUS_L	0xCF0
#define Q_REG_TX_MEMORY_STATUS_U	0xCF4
/* Tx FIFO status registers */
#define Q_REG_FIFO23_STATUS		0xCF8
#define Q_REG_FIFO01_STATUS		0xCFC
#define Q_REG_FIFO02_S			0
#define Q_REG_FIFO02_M			ICE_M(0x3FF, 0)
#define Q_REG_FIFO13_S			10
#define Q_REG_FIFO13_M			ICE_M(0x3FF, 10)
/* Interrupt control Config registers */
#define Q_REG_TX_MEM_GBL_CFG		0xC08
#define Q_REG_TX_MEM_GBL_CFG_LANE_TYPE_S	0
#define Q_REG_TX_MEM_GBL_CFG_LANE_TYPE_M	BIT(0)
#define Q_REG_TX_MEM_GBL_CFG_TX_TYPE_S	1
#define Q_REG_TX_MEM_GBL_CFG_TX_TYPE_M	ICE_M(0xFF, 1)
#define Q_REG_TX_MEM_GBL_CFG_INTR_THR_S	9
#define Q_REG_TX_MEM_GBL_CFG_INTR_THR_M ICE_M(0x3F, 9)
#define Q_REG_TX_MEM_GBL_CFG_INTR_ENA_S	15
#define Q_REG_TX_MEM_GBL_CFG_INTR_ENA_M	BIT(15)
/* Tx Timestamp data registers */
#define Q_REG_TX_MEMORY_BANK_START	0xA00
/* PHY port register base addresses */
#define P_0_BASE			0x80000
#define P_4_BASE			0x106000
/* Timestamp command registers */
#define P_REG_TX_TMR_CMD		0x448
#define P_REG_RX_TMR_CMD		0x468
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
/* Phy window length registers */
#define P_REG_WL			0x40C
/* Phy start registers */
#define P_REG_PS			0x408
#define P_REG_PS_START_S		0
#define P_REG_PS_START_M		BIT(0)
#define P_REG_PS_BYPASS_MODE_S		1
#define P_REG_PS_BYPASS_MODE_M		BIT(1)
#define P_REG_PS_ENA_CLK_S		2
#define P_REG_PS_ENA_CLK_M		BIT(2)
#define P_REG_PS_LOAD_OFFSET_S		3
#define P_REG_PS_LOAD_OFFSET_M		BIT(3)
#define P_REG_PS_SFT_RESET_S		11
#define P_REG_PS_SFT_RESET_M		BIT(11)
/* Phy offset valid registers */
#define P_REG_TX_OV_STATUS		0x4D4
#define P_REG_TX_OV_STATUS_OV_S		0
#define P_REG_TX_OV_STATUS_OV_M		BIT(0)
#define P_REG_RX_OV_STATUS		0x4F8
#define P_REG_RX_OV_STATUS_OV_S		0
#define P_REG_RX_OV_STATUS_OV_M		BIT(0)
/* Phy offset ready registers */
#define P_REG_TX_OR			0x45C
#define P_REG_RX_OR			0x47C
/* Phy total offset registers */
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
#define P_REG_LINK_SPEED_SERDES_S	0
#define P_REG_LINK_SPEED_SERDES_M	ICE_M(0x7, 0)
#define P_REG_LINK_SPEED_FEC_ALGO_S	3
#define P_REG_LINK_SPEED_FEC_ALGO_M	ICE_M(0x3, 3)
/* PHY timestamp related registers */
#define P_REG_PMD_ALIGNMENT		0x0FC
#define P_REG_RX_80_TO_160_CNT		0x6FC
#define P_REG_RX_80_TO_160_CNT_RXCYC_S	0
#define P_REG_RX_80_TO_160_CNT_RXCYC_M	BIT(0)
#define P_REG_RX_40_TO_160_CNT		0x8FC
#define P_REG_RX_40_TO_160_CNT_RXCYC_S	0
#define P_REG_RX_40_TO_160_CNT_RXCYC_M	ICE_M(0x3, 0)
/* Rx FIFO status registers */
#define P_REG_RX_OV_FS			0x4F8
#define P_REG_RX_OV_FS_FIFO_STATUS_S	2
#define P_REG_RX_OV_FS_FIFO_STATUS_M	ICE_M(0x3FF, 2)
#define ETH_GLTSYN_SHTIME_0(_i)		(0x03000368 + ((_i) * 32))
#define ETH_GLTSYN_SHTIME_L(_i)		(0x0300036C + ((_i) * 32))
#define ETH_GLTSYN_CMD			0x03000344
#define ETH_GLTSYN_SHADJ_L(_i)		(0x03000378 + ((_i) * 32))
#define ETH_GLTSYN_SHADJ_H(_i)		(0x0300037C + ((_i) * 32))
#define ETH_GLTSYN_INCVAL_L(_i)		(0x03000370 + ((_i) * 32))
#define ETH_GLTSYN_INCVAL_H(_i)		(0x03000374 + ((_i) * 32))

#define PORT_TIMER_ASSOC(_i)		(0x0300102C + ((_i) * 256))
#define ETH_GLTSYN_ENA(_i)		(0x03000348 + ((_i) * 4))
#define LOW_TX_MEMORY_BANK_START	0x03090000
#define HIGH_TX_MEMORY_BANK_START	0x03090004

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
struct ice_pf;
int ice_ptp_set_ts_config(struct ice_pf *pf, struct ifreq *ifr);
int ice_ptp_get_ts_config(struct ice_pf *pf, struct ifreq *ifr);
int ice_ptp_get_ts_idx(struct ice_vsi *vsi);
int ice_get_ptp_clock_index(struct ice_pf *pf);

void ice_clean_ptp_subtask(struct ice_pf *pf);
void ice_ptp_set_timestamp_offsets(struct ice_pf *pf);
u64 ice_ptp_read_master_clk_reg(struct ice_pf *pf);
void
ice_ptp_rx_hwtstamp(struct ice_ring *rx_ring,
		    union ice_32b_rx_flex_desc *rx_desc, struct sk_buff *skb);
void ice_ptp_init(struct ice_pf *pf);
void ice_ptp_release(struct ice_pf *pf);
enum ice_status ice_ptp_link_change(struct ice_pf *pf, u8 port, bool linkup);
enum ice_status ice_ptp_check_rx_fifo(struct ice_pf *pf, int port);
enum ice_status ptp_ts_enable(struct ice_pf *pf, int port, bool enable);
int
ice_ptp_cfg_periodic_clkout(struct ice_pf *pf, bool ena, unsigned int chan,
			    u32 gpio_pin, u64 period, u64 start_time);
enum ice_status
ice_ptp_update_incval(struct ice_pf *pf, enum ice_time_ref_freq time_ref_freq,
		      enum ice_mstr_tmr_mode mstr_tmr_mode);
enum ice_status
ice_ptp_get_incval(struct ice_pf *pf, enum ice_time_ref_freq *time_ref_freq,
		   enum ice_mstr_tmr_mode *mstr_tmr_mode);
#else /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
static inline int
ice_ptp_set_ts_config(struct ice_pf __always_unused *pf,
		      struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline int
ice_ptp_get_ts_config(struct ice_pf __always_unused *pf,
		      struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline enum ice_status
ice_ptp_check_rx_fifo(struct ice_pf __always_unused *pf,
		      int __always_unused port)
{
	return 0;
}

static inline int ice_ptp_get_ts_idx(struct ice_vsi __always_unused *vsi)
{
	return 0;
}

static inline int ice_get_ptp_clock_index(struct ice_pf __always_unused *pf)
{
	return 0;
}
#define ice_clean_ptp_subtask(pf)			do {} while (0)
#define ice_ptp_set_timestamp_offsets(pf)		do {} while (0)
#define ice_ptp_rx_hwtstamp(r, d, s)			do {} while (0)
#define ice_ptp_init(pf)				do {} while (0)
#define ice_ptp_release(pf)				do {} while (0)
#define ice_ptp_link_change(pf, port, linkup)		do {} while (0)
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
#endif /* _ICE_PTP_H_ */
