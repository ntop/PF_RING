/*******************************************************************************

  Intel(R) 10GbE PCI Express Linux Network Driver
  Copyright(c) 1999 - 2017 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBE_CNA_H_
#define _IXGBE_CNA_H_

int ixgbe_cna_enable(struct ixgbe_adapter *adapter);
void ixgbe_cna_disable(struct ixgbe_adapter *adapter);

#endif /* _IXGBE_CNA_H_ */
