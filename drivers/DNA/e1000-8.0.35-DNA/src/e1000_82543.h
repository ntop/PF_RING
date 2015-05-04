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

#ifndef _E1000_82543_H_
#define _E1000_82543_H_

#define PHY_PREAMBLE      0xFFFFFFFF
#define PHY_PREAMBLE_SIZE 32
#define PHY_SOF           0x1
#define PHY_OP_READ       0x2
#define PHY_OP_WRITE      0x1
#define PHY_TURNAROUND    0x2

#define TBI_COMPAT_ENABLED 0x1 /* Global "knob" for the workaround */
/* If TBI_COMPAT_ENABLED, then this is the current state (on/off) */
#define TBI_SBP_ENABLED    0x2 
                                
void e1000_tbi_adjust_stats_82543(struct e1000_hw *hw,
                                  struct e1000_hw_stats *stats,
                                  u32 frame_len, u8 *mac_addr,
                                  u32 max_frame_size);
void e1000_set_tbi_compatibility_82543(struct e1000_hw *hw,
                                       bool state);
bool e1000_tbi_sbp_enabled_82543(struct e1000_hw *hw);

#endif
