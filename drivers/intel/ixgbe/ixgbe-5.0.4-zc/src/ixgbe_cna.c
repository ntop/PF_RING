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


#include "ixgbe.h"
#include "ixgbe_cna.h"
#include "ixgbe_vmdq.h"

static int ixgbe_cna_open(struct net_device *cnadev)
{
	struct ixgbe_adapter *adapter = netdev_priv(cnadev);
	strcpy(cnadev->name, adapter->netdev->name);
	DPRINTK(PROBE, INFO, "CNA pseudo device opened %s\n", cnadev->name);
	return 0;
}

static int ixgbe_cna_close(struct net_device *cnadev)
{
	struct ixgbe_adapter *adapter = netdev_priv(cnadev);

	DPRINTK(PROBE, INFO, "CNA pseudo device closed %s\n", cnadev->name);
	return 0;
}

static int ixgbe_cna_change_mtu(struct net_device *cnadev, int new_mtu)
{
	struct ixgbe_adapter *adapter = netdev_priv(cnadev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	/* MTU < 68 is an error and causes problems on some kernels */
	if ((new_mtu < 68) || (max_frame > IXGBE_MAX_JUMBO_FRAME_SIZE))
		return -EINVAL;

	DPRINTK(PROBE, INFO, "changing MTU from %d to %d\n",
		cnadev->mtu, new_mtu);
	/* must set new MTU before calling down or up */
	cnadev->mtu = new_mtu;

	return 0;
}

int ixgbe_cna_enable(struct ixgbe_adapter *adapter)
{
	struct net_device *cnadev;
	struct net_device *netdev;
	int err;
	u64 wwpn;
	u64 wwnn;

	netdev = adapter->netdev;
	/*
	 * Oppositely to regular net device, CNA device doesn't have
	 * a private allocated region as we don't want to duplicate
	 * ixgbe_adapter information. Though, the CNA device still need
	 * to access the ixgbe_adapter while allocating queues or such. Thereby,
	 * cnadev->priv needs to point to netdev->priv.
	 */
	cnadev = alloc_etherdev_mq(0, MAX_TX_QUEUES);
	if (!cnadev) {
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}
	adapter->cnadev = cnadev;
	SET_MODULE_OWNER(cnadev);

	cnadev->priv = adapter;

	cnadev->open		= &ixgbe_cna_open;
	cnadev->stop		= &ixgbe_cna_close;
	cnadev->change_mtu	= &ixgbe_cna_change_mtu;
	cnadev->do_ioctl	= netdev->do_ioctl;
	cnadev->hard_start_xmit	= netdev->hard_start_xmit;
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	cnadev->vlan_rx_register = netdev->vlan_rx_register;
	cnadev->vlan_rx_add_vid  = netdev->vlan_rx_add_vid;
	cnadev->vlan_rx_kill_vid = netdev->vlan_rx_kill_vid;
#endif
	ixgbe_set_ethtool_ops(cnadev);

#if IS_ENABLED(CONFIG_DCB)
	cnadev->dcbnl_ops = netdev->dcbnl_ops;
#endif /* CONFIG_DCB */

	cnadev->mtu = netdev->mtu;
	cnadev->pdev = netdev->pdev;
	cnadev->gso_max_size = GSO_MAX_SIZE;
	cnadev->features = netdev->features | NETIF_F_CNA | NETIF_F_HW_VLAN_FILTER;

	/* set the MAC address to SAN mac address */
	if (ixgbe_validate_mac_addr(adapter->hw.mac.san_addr) == 0)
		memcpy(cnadev->dev_addr,
		       adapter->hw.mac.san_addr,
		       cnadev->addr_len);

	cnadev->features |= NETIF_F_FCOE_CRC |
			    NETIF_F_FCOE_MTU |
			    NETIF_F_FSO;

	cnadev->ndo_fcoe_ddp_setup = &ixgbe_fcoe_ddp_get;
	cnadev->ndo_fcoe_ddp_done = &ixgbe_fcoe_ddp_put;
	cnadev->fcoe_ddp_xid = IXGBE_FCOE_DDP_MAX - 1;

	netif_carrier_off(cnadev);
	netif_tx_stop_all_queues(cnadev);

	VMKNETDDI_REGISTER_QUEUEOPS(cnadev, ixgbe_netqueue_ops);

	err = register_netdev(cnadev);
	if (err)
		goto err_register;

	DPRINTK(PROBE, INFO, "CNA pseudo device registered %s\n", netdev->name);

	return err;

err_register:
	DPRINTK(PROBE, INFO, "CNA pseudo device cannot be registered %s\n",
		netdev->name);
	free_netdev(cnadev);
err_alloc_etherdev:
	DPRINTK(PROBE, INFO, "CNA cannot be enabled on %s\n", netdev->name);
	adapter->flags2 &= ~IXGBE_FLAG2_CNA_ENABLED;
	adapter->flags &= ~IXGBE_FLAG_FCOE_ENABLED;
	adapter->ring_feature[RING_F_FCOE].indices = 0;
	return err;
}

void ixgbe_cna_disable(struct ixgbe_adapter *adapter)
{
	if (!(adapter->flags2 & IXGBE_FLAG2_CNA_ENABLED))
		return;

	adapter->flags2 &= ~IXGBE_FLAG2_CNA_ENABLED;
	adapter->flags &= ~IXGBE_FLAG_FCOE_ENABLED;
	adapter->ring_feature[RING_F_FCOE].indices = 0;

	if (adapter->cnadev) {
		unregister_netdev(adapter->cnadev);
		DPRINTK(PROBE, INFO, "CNA pseudo device unregistered %s\n",
			adapter->cnadev->name);

		free_netdev(adapter->cnadev);
 		adapter->cnadev = NULL;
 	}
}

/* ixgbe_cna.c */
