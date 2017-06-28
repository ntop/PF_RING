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


#ifndef _IXGBE_SRIOV_H_
#define _IXGBE_SRIOV_H_

/* ixgbe driver limit the max number of VFs could be enabled to
 * 63 (IXGBE_MAX_VF_FUNCTIONS - 1)
 */
#define IXGBE_MAX_VFS_DRV_LIMIT  (IXGBE_MAX_VF_FUNCTIONS - 1)
#define IXGBE_MAX_VFS_1TC	 IXGBE_MAX_VFS_DRV_LIMIT
#define IXGBE_MAX_VFS_4TC	 31
#define IXGBE_MAX_VFS_8TC	 15

void ixgbe_restore_vf_multicasts(struct ixgbe_adapter *adapter);
int ixgbe_set_vf_vlan(struct ixgbe_adapter *adapter, int add, int vid, u32 vf);
void ixgbe_set_vmolr(struct ixgbe_hw *hw, u32 vf, bool aupe);
void ixgbe_msg_task(struct ixgbe_adapter *adapter);
int ixgbe_set_vf_mac(struct ixgbe_adapter *adapter,
		     int vf, unsigned char *mac_addr);
void ixgbe_disable_tx_rx(struct ixgbe_adapter *adapter);
void ixgbe_ping_all_vfs(struct ixgbe_adapter *adapter);
#ifdef IFLA_VF_MAX
int ixgbe_ndo_set_vf_mac(struct net_device *netdev, int queue, u8 *mac);
#ifdef IFLA_VF_VLAN_INFO_MAX
int ixgbe_ndo_set_vf_vlan(struct net_device *netdev, int queue, u16 vlan,
			  u8 qos, __be16 vlan_proto);
#else
int ixgbe_ndo_set_vf_vlan(struct net_device *netdev, int queue, u16 vlan,
			  u8 qos);
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
int ixgbe_ndo_set_vf_bw(struct net_device *netdev, int vf, int min_tx_rate,
			int max_tx_rate);
#else
int ixgbe_ndo_set_vf_bw(struct net_device *netdev, int vf, int tx_rate);
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */
#ifdef HAVE_NDO_SET_VF_RSS_QUERY_EN
int ixgbe_ndo_set_vf_rss_query_en(struct net_device *netdev, int vf,
				  bool setting);
#endif
#ifdef HAVE_NDO_SET_VF_TRUST
int ixgbe_ndo_set_vf_trust(struct net_device *netdev, int vf, bool setting);
#endif
int ixgbe_ndo_get_vf_config(struct net_device *netdev,
			    int vf, struct ifla_vf_info *ivi);
#endif /* IFLA_VF_MAX */
int ixgbe_disable_sriov(struct ixgbe_adapter *adapter);
#ifdef CONFIG_PCI_IOV
int ixgbe_vf_configuration(struct pci_dev *pdev, unsigned int event_mask);
void ixgbe_enable_sriov(struct ixgbe_adapter *adapter);
int ixgbe_ndo_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting);
#endif
int ixgbe_pci_sriov_configure(struct pci_dev *dev, int num_vfs);
#ifdef IFLA_VF_MAX
void ixgbe_check_vf_rate_limit(struct ixgbe_adapter *adapter);
#endif /* IFLA_VF_MAX */
void ixgbe_dump_registers(struct ixgbe_adapter *adapter);

/*
 * These are defined in ixgbe_type.h on behalf of the VF driver
 * but we need them here unwrapped for the PF driver.
 */
#define IXGBE_DEV_ID_82599_VF			0x10ED
#define IXGBE_DEV_ID_X540_VF			0x1515
#define IXGBE_DEV_ID_X550_VF			0x1565
#define IXGBE_DEV_ID_X550EM_X_VF		0x15A8
#define IXGBE_DEV_ID_X550EM_A_VF		0x15C5
#endif /* _IXGBE_SRIOV_H_ */

