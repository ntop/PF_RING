/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _E1000_PHY_H_
#define _E1000_PHY_H_

void e1000_init_phy_ops_generic(struct e1000_hw *hw);
s32  e1000_null_read_reg(struct e1000_hw *hw, u32 offset, u16 *data);
void e1000_null_phy_generic(struct e1000_hw *hw);
s32  e1000_null_lplu_state(struct e1000_hw *hw, bool active);
s32  e1000_null_write_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_null_set_page(struct e1000_hw *hw, u16 data);
s32  e1000_check_downshift_generic(struct e1000_hw *hw);
s32  e1000_check_polarity_m88(struct e1000_hw *hw);
s32  e1000_check_polarity_igp(struct e1000_hw *hw);
s32  e1000_check_polarity_ife(struct e1000_hw *hw);
s32  e1000_check_reset_block_generic(struct e1000_hw *hw);
s32  e1000_phy_setup_autoneg(struct e1000_hw *hw);
s32  e1000_copper_link_autoneg(struct e1000_hw *hw);
s32  e1000_copper_link_setup_igp(struct e1000_hw *hw);
s32  e1000_copper_link_setup_m88(struct e1000_hw *hw);
s32  e1000_phy_force_speed_duplex_igp(struct e1000_hw *hw);
s32  e1000_phy_force_speed_duplex_m88(struct e1000_hw *hw);
s32  e1000_phy_force_speed_duplex_ife(struct e1000_hw *hw);
s32  e1000_get_cable_length_m88(struct e1000_hw *hw);
s32  e1000_get_cable_length_igp_2(struct e1000_hw *hw);
s32  e1000_get_cfg_done_generic(struct e1000_hw *hw);
s32  e1000_get_phy_id(struct e1000_hw *hw);
s32  e1000_get_phy_info_igp(struct e1000_hw *hw);
s32  e1000_get_phy_info_m88(struct e1000_hw *hw);
s32  e1000_get_phy_info_ife(struct e1000_hw *hw);
s32  e1000_phy_sw_reset_generic(struct e1000_hw *hw);
void e1000_phy_force_speed_duplex_setup(struct e1000_hw *hw, u16 *phy_ctrl);
s32  e1000_phy_hw_reset_generic(struct e1000_hw *hw);
s32  e1000_phy_reset_dsp_generic(struct e1000_hw *hw);
s32  e1000_read_kmrn_reg_generic(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_read_kmrn_reg_locked(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_set_page_igp(struct e1000_hw *hw, u16 page);
s32  e1000_read_phy_reg_igp(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_read_phy_reg_igp_locked(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_read_phy_reg_m88(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_set_d3_lplu_state_generic(struct e1000_hw *hw, bool active);
s32  e1000_setup_copper_link_generic(struct e1000_hw *hw);
s32  e1000_wait_autoneg_generic(struct e1000_hw *hw);
s32  e1000_write_kmrn_reg_generic(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_kmrn_reg_locked(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_phy_reg_igp(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_phy_reg_igp_locked(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_phy_reg_m88(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_phy_reset_dsp(struct e1000_hw *hw);
s32  e1000_phy_has_link_generic(struct e1000_hw *hw, u32 iterations,
                                u32 usec_interval, bool *success);
s32  e1000_phy_init_script_igp3(struct e1000_hw *hw);
enum e1000_phy_type e1000_get_phy_type_from_id(u32 phy_id);
s32  e1000_determine_phy_address(struct e1000_hw *hw);
s32  e1000_enable_phy_wakeup_reg_access_bm(struct e1000_hw *hw, u16 *phy_reg);
s32  e1000_disable_phy_wakeup_reg_access_bm(struct e1000_hw *hw, u16 *phy_reg);
void e1000_power_up_phy_copper(struct e1000_hw *hw);
void e1000_power_down_phy_copper(struct e1000_hw *hw);
s32  e1000_read_phy_reg_mdic(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_write_phy_reg_mdic(struct e1000_hw *hw, u32 offset, u16 data);

#define E1000_MAX_PHY_ADDR                8

/* IGP01E1000 Specific Registers */
#define IGP01E1000_PHY_PORT_CONFIG        0x10 /* Port Config */
#define IGP01E1000_PHY_PORT_STATUS        0x11 /* Status */
#define IGP01E1000_PHY_PORT_CTRL          0x12 /* Control */
#define IGP01E1000_PHY_LINK_HEALTH        0x13 /* PHY Link Health */
#define IGP01E1000_GMII_FIFO              0x14 /* GMII FIFO */
#define IGP01E1000_PHY_CHANNEL_QUALITY    0x15 /* PHY Channel Quality */
#define IGP02E1000_PHY_POWER_MGMT         0x19 /* Power Management */
#define IGP01E1000_PHY_PAGE_SELECT        0x1F /* Page Select */
#define BM_PHY_PAGE_SELECT                22   /* Page Select for BM */
#define IGP_PAGE_SHIFT                    5
#define PHY_REG_MASK                      0x1F

#define IGP01E1000_PHY_PCS_INIT_REG       0x00B4
#define IGP01E1000_PHY_POLARITY_MASK      0x0078

#define IGP01E1000_PSCR_AUTO_MDIX         0x1000
#define IGP01E1000_PSCR_FORCE_MDI_MDIX    0x2000 /* 0=MDI, 1=MDIX */

#define IGP01E1000_PSCFR_SMART_SPEED      0x0080

/* Enable flexible speed on link-up */
#define IGP01E1000_GMII_FLEX_SPD          0x0010
#define IGP01E1000_GMII_SPD               0x0020 /* Enable SPD */

#define IGP02E1000_PM_SPD                 0x0001 /* Smart Power Down */
#define IGP02E1000_PM_D0_LPLU             0x0002 /* For D0a states */
#define IGP02E1000_PM_D3_LPLU             0x0004 /* For all other states */

#define IGP01E1000_PLHR_SS_DOWNGRADE      0x8000

#define IGP01E1000_PSSR_POLARITY_REVERSED 0x0002
#define IGP01E1000_PSSR_MDIX              0x0800
#define IGP01E1000_PSSR_SPEED_MASK        0xC000
#define IGP01E1000_PSSR_SPEED_1000MBPS    0xC000

#define IGP02E1000_PHY_CHANNEL_NUM        4
#define IGP02E1000_PHY_AGC_A              0x11B1
#define IGP02E1000_PHY_AGC_B              0x12B1
#define IGP02E1000_PHY_AGC_C              0x14B1
#define IGP02E1000_PHY_AGC_D              0x18B1

#define IGP02E1000_AGC_LENGTH_SHIFT       9   /* Course - 15:13, Fine - 12:9 */
#define IGP02E1000_AGC_LENGTH_MASK        0x7F
#define IGP02E1000_AGC_RANGE              15

#define IGP03E1000_PHY_MISC_CTRL          0x1B
#define IGP03E1000_PHY_MISC_DUPLEX_MANUAL_SET  0x1000 /* Manually Set Duplex */

#define E1000_CABLE_LENGTH_UNDEFINED      0xFF

#define E1000_KMRNCTRLSTA_OFFSET          0x001F0000
#define E1000_KMRNCTRLSTA_OFFSET_SHIFT    16
#define E1000_KMRNCTRLSTA_REN             0x00200000
#define E1000_KMRNCTRLSTA_DIAG_OFFSET     0x3    /* Kumeran Diagnostic */
#define E1000_KMRNCTRLSTA_TIMEOUTS        0x4    /* Kumeran Timeouts */
#define E1000_KMRNCTRLSTA_INBAND_PARAM    0x9    /* Kumeran InBand Parameters */
#define E1000_KMRNCTRLSTA_IBIST_DISABLE   0x0200 /* Kumeran IBIST Disable */
#define E1000_KMRNCTRLSTA_DIAG_NELPBK     0x1000 /* Nearend Loopback mode */

#define IFE_PHY_EXTENDED_STATUS_CONTROL 0x10
#define IFE_PHY_SPECIAL_CONTROL     0x11 /* 100BaseTx PHY Special Control */
#define IFE_PHY_SPECIAL_CONTROL_LED 0x1B /* PHY Special and LED Control */
#define IFE_PHY_MDIX_CONTROL        0x1C /* MDI/MDI-X Control */

/* IFE PHY Extended Status Control */
#define IFE_PESC_POLARITY_REVERSED    0x0100

/* IFE PHY Special Control */
#define IFE_PSC_AUTO_POLARITY_DISABLE      0x0010
#define IFE_PSC_FORCE_POLARITY             0x0020
#define IFE_PSC_DISABLE_DYNAMIC_POWER_DOWN 0x0100

/* IFE PHY Special Control and LED Control */
#define IFE_PSCL_PROBE_MODE            0x0020
#define IFE_PSCL_PROBE_LEDS_OFF        0x0006 /* Force LEDs 0 and 2 off */
#define IFE_PSCL_PROBE_LEDS_ON         0x0007 /* Force LEDs 0 and 2 on */

/* IFE PHY MDIX Control */
#define IFE_PMC_MDIX_STATUS      0x0020 /* 1=MDI-X, 0=MDI */
#define IFE_PMC_FORCE_MDIX       0x0040 /* 1=force MDI-X, 0=force MDI */
#define IFE_PMC_AUTO_MDIX        0x0080 /* 1=enable auto MDI/MDI-X, 0=disable */

/* SFP modules ID memory locations */
#define E1000_SFF_IDENTIFIER_OFFSET 0x00
#define E1000_SFF_IDENTIFIER_SFF    0x02
#define E1000_SFF_IDENTIFIER_SFP    0x03

#define E1000_SFF_ETH_FLAGS_OFFSET  0x06
/* Flags for SFP modules compatible with ETH up to 1Gb */
struct sfp_e1000_flags {
	u8 e1000_base_sx:1;
	u8 e1000_base_lx:1;
	u8 e1000_base_cx:1;
	u8 e1000_base_t:1;
	u8 e100_base_lx:1;
	u8 e100_base_fx:1;
	u8 e10_base_bx10:1;
	u8 e10_base_px:1;
};

/* Vendor OUIs: format of OUI is 0x[byte0][byte1][byte2][00] */
#define E1000_SFF_VENDOR_OUI_TYCO     0x00407600
#define E1000_SFF_VENDOR_OUI_FTL      0x00906500
#define E1000_SFF_VENDOR_OUI_AVAGO    0x00176A00
#define E1000_SFF_VENDOR_OUI_INTEL    0x001B2100

#endif
