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

#ifndef _E1000_82541_H_
#define _E1000_82541_H_

#define NVM_WORD_SIZE_BASE_SHIFT_82541 (NVM_WORD_SIZE_BASE_SHIFT + 1)

#define IGP01E1000_PHY_CHANNEL_NUM                    4

#define IGP01E1000_PHY_AGC_A                     0x1172
#define IGP01E1000_PHY_AGC_B                     0x1272
#define IGP01E1000_PHY_AGC_C                     0x1472
#define IGP01E1000_PHY_AGC_D                     0x1872

#define IGP01E1000_PHY_AGC_PARAM_A               0x1171
#define IGP01E1000_PHY_AGC_PARAM_B               0x1271
#define IGP01E1000_PHY_AGC_PARAM_C               0x1471
#define IGP01E1000_PHY_AGC_PARAM_D               0x1871

#define IGP01E1000_PHY_EDAC_MU_INDEX             0xC000
#define IGP01E1000_PHY_EDAC_SIGN_EXT_9_BITS      0x8000

#define IGP01E1000_PHY_DSP_RESET                 0x1F33

#define IGP01E1000_PHY_DSP_FFE                   0x1F35
#define IGP01E1000_PHY_DSP_FFE_CM_CP             0x0069
#define IGP01E1000_PHY_DSP_FFE_DEFAULT           0x002A

#define IGP01E1000_IEEE_FORCE_GIG                0x0140
#define IGP01E1000_IEEE_RESTART_AUTONEG          0x3300

#define IGP01E1000_AGC_LENGTH_SHIFT                   7
#define IGP01E1000_AGC_RANGE                         10

#define FFE_IDLE_ERR_COUNT_TIMEOUT_20                20
#define FFE_IDLE_ERR_COUNT_TIMEOUT_100              100

#define IGP01E1000_ANALOG_FUSE_STATUS            0x20D0
#define IGP01E1000_ANALOG_SPARE_FUSE_STATUS      0x20D1
#define IGP01E1000_ANALOG_FUSE_CONTROL           0x20DC
#define IGP01E1000_ANALOG_FUSE_BYPASS            0x20DE

#define IGP01E1000_ANALOG_SPARE_FUSE_ENABLED     0x0100
#define IGP01E1000_ANALOG_FUSE_FINE_MASK         0x0F80
#define IGP01E1000_ANALOG_FUSE_COARSE_MASK       0x0070
#define IGP01E1000_ANALOG_FUSE_COARSE_THRESH     0x0040
#define IGP01E1000_ANALOG_FUSE_COARSE_10         0x0010
#define IGP01E1000_ANALOG_FUSE_FINE_1            0x0080
#define IGP01E1000_ANALOG_FUSE_FINE_10           0x0500
#define IGP01E1000_ANALOG_FUSE_POLY_MASK         0xF000
#define IGP01E1000_ANALOG_FUSE_ENABLE_SW_CONTROL 0x0002

#define IGP01E1000_MSE_CHANNEL_D                 0x000F
#define IGP01E1000_MSE_CHANNEL_C                 0x00F0
#define IGP01E1000_MSE_CHANNEL_B                 0x0F00
#define IGP01E1000_MSE_CHANNEL_A                 0xF000


void e1000_init_script_state_82541(struct e1000_hw *hw, bool state);
#endif
