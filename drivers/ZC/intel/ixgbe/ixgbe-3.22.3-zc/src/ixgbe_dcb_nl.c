/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright (c) 1999 - 2014 Intel Corporation.

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

#ifdef CONFIG_DCB
#include <linux/dcbnl.h>
#include "ixgbe_dcb_82598.h"
#include "ixgbe_dcb_82599.h"

/* Callbacks for DCB netlink in the kernel */
#define BIT_DCB_MODE	0x01
#define BIT_PFC		0x02
#define BIT_PG_RX	0x04
#define BIT_PG_TX	0x08
#define BIT_APP_UPCHG	0x10
#define BIT_RESETLINK	0x40
#define BIT_LINKSPEED	0x80

/* Responses for the DCB_C_SET_ALL command */
#define DCB_HW_CHG_RST	0  /* DCB configuration changed with reset */
#define DCB_NO_HW_CHG	1  /* DCB configuration did not change */
#define DCB_HW_CHG	2  /* DCB configuration changed, no reset */

int ixgbe_copy_dcb_cfg(struct ixgbe_adapter *adapter, int tc_max)
{
	struct ixgbe_dcb_config *scfg = &adapter->temp_dcb_cfg;
	struct ixgbe_dcb_config *dcfg = &adapter->dcb_cfg;
	struct ixgbe_dcb_tc_config *src = NULL;
	struct ixgbe_dcb_tc_config *dst = NULL;
	int i, j;
	int tx = IXGBE_DCB_TX_CONFIG;
	int rx = IXGBE_DCB_RX_CONFIG;
	int changes = 0;

#ifdef IXGBE_FCOE
	if (adapter->fcoe.up_set != adapter->fcoe.up)
		changes |= BIT_APP_UPCHG;

#endif /* IXGBE_FCOE */
	for (i = DCB_PG_ATTR_TC_0; i < tc_max + DCB_PG_ATTR_TC_0; i++) {
		src = &scfg->tc_config[i - DCB_PG_ATTR_TC_0];
		dst = &dcfg->tc_config[i - DCB_PG_ATTR_TC_0];

		if (dst->path[tx].tsa != src->path[tx].tsa) {
			dst->path[tx].tsa = src->path[tx].tsa;
			changes |= BIT_PG_TX;
		}

		if (dst->path[tx].bwg_id != src->path[tx].bwg_id) {
			dst->path[tx].bwg_id = src->path[tx].bwg_id;
			changes |= BIT_PG_TX;
		}

		if (dst->path[tx].bwg_percent != src->path[tx].bwg_percent) {
			dst->path[tx].bwg_percent = src->path[tx].bwg_percent;
			changes |= BIT_PG_TX;
		}

		if (dst->path[tx].up_to_tc_bitmap !=
		    src->path[tx].up_to_tc_bitmap) {
			dst->path[tx].up_to_tc_bitmap =
				src->path[tx].up_to_tc_bitmap;
			changes |= (BIT_PG_TX | BIT_PFC | BIT_APP_UPCHG);
		}

		if (dst->path[rx].tsa != src->path[rx].tsa) {
			dst->path[rx].tsa = src->path[rx].tsa;
			changes |= BIT_PG_RX;
		}

		if (dst->path[rx].bwg_id != src->path[rx].bwg_id) {
			dst->path[rx].bwg_id = src->path[rx].bwg_id;
			changes |= BIT_PG_RX;
		}

		if (dst->path[rx].bwg_percent != src->path[rx].bwg_percent) {
			dst->path[rx].bwg_percent = src->path[rx].bwg_percent;
			changes |= BIT_PG_RX;
		}

		if (dst->path[rx].up_to_tc_bitmap !=
		    src->path[rx].up_to_tc_bitmap) {
			dst->path[rx].up_to_tc_bitmap =
				src->path[rx].up_to_tc_bitmap;
			changes |= (BIT_PG_RX | BIT_PFC | BIT_APP_UPCHG);
		}
	}

	for (i = DCB_PG_ATTR_BW_ID_0; i < DCB_PG_ATTR_BW_ID_MAX; i++) {
		j = i - DCB_PG_ATTR_BW_ID_0;

		if (dcfg->bw_percentage[tx][j] != scfg->bw_percentage[tx][j]) {
			dcfg->bw_percentage[tx][j] = scfg->bw_percentage[tx][j];
			changes |= BIT_PG_TX;
		}
		if (dcfg->bw_percentage[rx][j] != scfg->bw_percentage[rx][j]) {
			dcfg->bw_percentage[rx][j] = scfg->bw_percentage[rx][j];
			changes |= BIT_PG_RX;
		}
	}

	for (i = DCB_PFC_UP_ATTR_0; i < DCB_PFC_UP_ATTR_MAX; i++) {
		j = i - DCB_PFC_UP_ATTR_0;
		if (dcfg->tc_config[j].pfc != scfg->tc_config[j].pfc) {
			dcfg->tc_config[j].pfc = scfg->tc_config[j].pfc;
			changes |= BIT_PFC;
		}
	}

	if (dcfg->pfc_mode_enable != scfg->pfc_mode_enable) {
		dcfg->pfc_mode_enable = scfg->pfc_mode_enable;
		changes |= BIT_PFC;
	}

	return changes;
}

static u8 ixgbe_dcbnl_get_state(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	return !!(adapter->flags & IXGBE_FLAG_DCB_ENABLED);
}

static u8 ixgbe_dcbnl_set_state(struct net_device *netdev, u8 state)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int err = 0;

	/* Fail command if not in CEE mode */
	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return 1;

	/* verify there is something to do, if not then exit */
	if (!state == !(adapter->flags & IXGBE_FLAG_DCB_ENABLED))
		goto out;

	err = ixgbe_setup_tc(netdev,
			     state ? adapter->dcb_cfg.num_tcs.pg_tcs : 0);
out:
	return !!err;
}

static void ixgbe_dcbnl_get_perm_hw_addr(struct net_device *netdev,
					 u8 *perm_addr)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int i, j;

	memset(perm_addr, 0xff, MAX_ADDR_LEN);

	for (i = 0; i < netdev->addr_len; i++)
		perm_addr[i] = adapter->hw.mac.perm_addr[i];

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		for (j = 0; j < netdev->addr_len; j++, i++)
			perm_addr[i] = adapter->hw.mac.san_addr[j];
		break;
	default:
		break;
	}
}

static void ixgbe_dcbnl_set_pg_tc_cfg_tx(struct net_device *netdev, int tc,
					 u8 prio, u8 bwg_id, u8 bw_pct,
					 u8 up_map)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	if (prio != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[0].tsa = prio;
	if (bwg_id != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[0].bwg_id = bwg_id;
	if (bw_pct != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[0].bwg_percent =
			bw_pct;
	if (up_map != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[0].up_to_tc_bitmap =
			up_map;
}

static void ixgbe_dcbnl_set_pg_bwg_cfg_tx(struct net_device *netdev, int bwg_id,
					  u8 bw_pct)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	adapter->temp_dcb_cfg.bw_percentage[0][bwg_id] = bw_pct;
}

static void ixgbe_dcbnl_set_pg_tc_cfg_rx(struct net_device *netdev, int tc,
					 u8 prio, u8 bwg_id, u8 bw_pct,
					 u8 up_map)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	if (prio != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[1].tsa = prio;
	if (bwg_id != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[1].bwg_id = bwg_id;
	if (bw_pct != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[1].bwg_percent =
			bw_pct;
	if (up_map != DCB_ATTR_VALUE_UNDEFINED)
		adapter->temp_dcb_cfg.tc_config[tc].path[1].up_to_tc_bitmap =
			up_map;
}

static void ixgbe_dcbnl_set_pg_bwg_cfg_rx(struct net_device *netdev, int bwg_id,
					  u8 bw_pct)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	adapter->temp_dcb_cfg.bw_percentage[1][bwg_id] = bw_pct;
}

static void ixgbe_dcbnl_get_pg_tc_cfg_tx(struct net_device *netdev, int tc,
					 u8 *prio, u8 *bwg_id, u8 *bw_pct,
					 u8 *up_map)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	*prio = adapter->dcb_cfg.tc_config[tc].path[0].tsa;
	*bwg_id = adapter->dcb_cfg.tc_config[tc].path[0].bwg_id;
	*bw_pct = adapter->dcb_cfg.tc_config[tc].path[0].bwg_percent;
	*up_map = adapter->dcb_cfg.tc_config[tc].path[0].up_to_tc_bitmap;
}

static void ixgbe_dcbnl_get_pg_bwg_cfg_tx(struct net_device *netdev, int bwg_id,
					  u8 *bw_pct)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	*bw_pct = adapter->dcb_cfg.bw_percentage[0][bwg_id];
}

static void ixgbe_dcbnl_get_pg_tc_cfg_rx(struct net_device *netdev, int tc,
					 u8 *prio, u8 *bwg_id, u8 *bw_pct,
					 u8 *up_map)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	*prio = adapter->dcb_cfg.tc_config[tc].path[1].tsa;
	*bwg_id = adapter->dcb_cfg.tc_config[tc].path[1].bwg_id;
	*bw_pct = adapter->dcb_cfg.tc_config[tc].path[1].bwg_percent;
	*up_map = adapter->dcb_cfg.tc_config[tc].path[1].up_to_tc_bitmap;
}

static void ixgbe_dcbnl_get_pg_bwg_cfg_rx(struct net_device *netdev, int bwg_id,
					  u8 *bw_pct)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	*bw_pct = adapter->dcb_cfg.bw_percentage[1][bwg_id];
}

static void ixgbe_dcbnl_set_pfc_cfg(struct net_device *netdev, int up, u8 pfc)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	u8 tc = ixgbe_dcb_get_tc_from_up(&adapter->temp_dcb_cfg, 0, up);

	adapter->temp_dcb_cfg.tc_config[tc].pfc = pfc;
	if (adapter->temp_dcb_cfg.tc_config[tc].pfc !=
	    adapter->dcb_cfg.tc_config[tc].pfc)
		adapter->temp_dcb_cfg.pfc_mode_enable = true;
}

static void ixgbe_dcbnl_get_pfc_cfg(struct net_device *netdev, int up, u8 *pfc)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	u8 tc = ixgbe_dcb_get_tc_from_up(&adapter->dcb_cfg, 0, up);
	*pfc = adapter->dcb_cfg.tc_config[tc].pfc;
}

static void ixgbe_dcbnl_devreset(struct net_device *dev)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);

	while (test_and_set_bit(__IXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(dev))
#ifdef HAVE_NET_DEVICE_OPS
		dev->netdev_ops->ndo_stop(dev);
#else
		dev->stop(dev);
#endif

	ixgbe_clear_interrupt_scheme(adapter);
	ixgbe_init_interrupt_scheme(adapter);

	if (netif_running(dev))
#ifdef HAVE_NET_DEVICE_OPS
		dev->netdev_ops->ndo_open(dev);
#else
		dev->open(dev);
#endif

	clear_bit(__IXGBE_RESETTING, &adapter->state);
}

static u8 ixgbe_dcbnl_set_all(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_dcb_config *dcb_cfg = &adapter->dcb_cfg;
	struct ixgbe_hw *hw = &adapter->hw;
	int ret = DCB_NO_HW_CHG;
	u8 prio_tc[IXGBE_DCB_MAX_USER_PRIORITY] = { 0 };

	/* Fail command if not in CEE mode */
	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return ret;

	adapter->dcb_set_bitmap |= ixgbe_copy_dcb_cfg(adapter,
						      IXGBE_DCB_MAX_TRAFFIC_CLASS);
	if (!adapter->dcb_set_bitmap)
		return ret;

	ixgbe_dcb_unpack_map_cee(dcb_cfg, IXGBE_DCB_TX_CONFIG, prio_tc);

	if (adapter->dcb_set_bitmap & (BIT_PG_TX | BIT_PG_RX)) {
		/* Priority to TC mapping in CEE case default to 1:1 */
		int max_frame = adapter->netdev->mtu + ETH_HLEN + ETH_FCS_LEN;
#ifdef HAVE_MQPRIO
		int i;
#endif

#ifdef IXGBE_FCOE
		if (adapter->netdev->features & NETIF_F_FCOE_MTU)
			max_frame = max(max_frame, IXGBE_FCOE_JUMBO_FRAME_SIZE);
#endif

		ixgbe_dcb_calculate_tc_credits_cee(hw, dcb_cfg, max_frame,
						   IXGBE_DCB_TX_CONFIG);

		ixgbe_dcb_calculate_tc_credits_cee(hw, dcb_cfg, max_frame,
						   IXGBE_DCB_RX_CONFIG);

		ixgbe_dcb_hw_config_cee(hw, dcb_cfg);

#ifdef HAVE_MQPRIO
		for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
			netdev_set_prio_tc_map(netdev, i, prio_tc[i]);
#endif /* HAVE_MQPRIO */
		ret = DCB_HW_CHG_RST;
	}

	if (adapter->dcb_set_bitmap & BIT_PFC) {
		if (dcb_cfg->pfc_mode_enable) {
			u8 pfc_en;
			ixgbe_dcb_unpack_pfc_cee(dcb_cfg, prio_tc, &pfc_en);
			ixgbe_dcb_config_pfc(hw, pfc_en, prio_tc);
		} else {
			hw->mac.ops.fc_enable(hw);
		}
		ixgbe_set_rx_drop_en(adapter);
		if (ret != DCB_HW_CHG_RST)
			ret = DCB_HW_CHG;
	}

#ifdef IXGBE_FCOE
	/* Reprogam FCoE hardware offloads when the traffic class
	 * FCoE is using changes. This happens if the APP info
	 * changes or the up2tc mapping is updated.
	 */
	if (adapter->dcb_set_bitmap & BIT_APP_UPCHG) {
		adapter->fcoe.up_set = adapter->fcoe.up;
		ixgbe_dcbnl_devreset(netdev);
		ret = DCB_HW_CHG_RST;
	}

#endif /* IXGBE_FCOE */
	adapter->dcb_set_bitmap = 0x00;
	return ret;
}

static u8 ixgbe_dcbnl_getcap(struct net_device *netdev, int capid, u8 *cap)
{
#ifdef HAVE_DCBNL_IEEE
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
#endif

	switch (capid) {
	case DCB_CAP_ATTR_PG:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PFC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_UP2TC:
		*cap = false;
		break;
	case DCB_CAP_ATTR_PG_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_GSP:
		*cap = true;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
#ifdef HAVE_DCBNL_IEEE
	case DCB_CAP_ATTR_DCBX:
		*cap = adapter->dcbx_cap;
		break;
#endif
	default:
		*cap = false;
		break;
	}

	return 0;
}

#ifdef NUMTCS_RETURNS_U8
static u8 ixgbe_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
#else
static int ixgbe_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	u8 rval = 0;

	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) {
		switch (tcid) {
		case DCB_NUMTCS_ATTR_PG:
			*num = adapter->dcb_cfg.num_tcs.pg_tcs;
			break;
		case DCB_NUMTCS_ATTR_PFC:
			*num = adapter->dcb_cfg.num_tcs.pfc_tcs;
			break;
		default:
			rval = -EINVAL;
			break;
		}
	} else {
		rval = -EINVAL;
	}

	return rval;
}

#ifdef NUMTCS_RETURNS_U8
static u8 ixgbe_dcbnl_setnumtcs(struct net_device *netdev, int tcid, u8 num)
#else
static int ixgbe_dcbnl_setnumtcs(struct net_device *netdev, int tcid, u8 num)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	u8 rval = 0;

	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED) {
		switch (tcid) {
		case DCB_NUMTCS_ATTR_PG:
			adapter->dcb_cfg.num_tcs.pg_tcs = num;
			break;
		case DCB_NUMTCS_ATTR_PFC:
			adapter->dcb_cfg.num_tcs.pfc_tcs = num;
			break;
		default:
			rval = -EINVAL;
			break;
		}
	} else {
		rval = -EINVAL;
	}

	return rval;
}

static u8 ixgbe_dcbnl_getpfcstate(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	return adapter->dcb_cfg.pfc_mode_enable;
}

static void ixgbe_dcbnl_setpfcstate(struct net_device *netdev, u8 state)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	adapter->temp_dcb_cfg.pfc_mode_enable = state;
	return;
}

#ifdef HAVE_DCBNL_OPS_GETAPP
/**
 * ixgbe_dcbnl_getapp - retrieve the DCBX application user priority
 * @netdev : the corresponding netdev
 * @idtype : identifies the id as ether type or TCP/UDP port number
 * @id: id is either ether type or TCP/UDP port number
 *
 * Returns : on success, returns a non-zero 802.1p user priority bitmap
 * otherwise returns 0 as the invalid user priority bitmap to indicate an
 * error.
 */
#ifdef HAVE_DCBNL_OPS_SETAPP_RETURN_INT
static int ixgbe_dcbnl_getapp(struct net_device *netdev, u8 idtype, u16 id)
#else
static u8 ixgbe_dcbnl_getapp(struct net_device *netdev, u8 idtype, u16 id)
#endif
{
	u8 rval = 0;
#ifdef HAVE_DCBNL_IEEE
	struct dcb_app app = {
		.selector = idtype,
		.protocol = id,
	};

	rval = dcb_getapp(netdev, &app);
#endif

	switch (idtype) {
	case DCB_APP_IDTYPE_ETHTYPE:
#ifdef IXGBE_FCOE
		if (id == ETH_P_FCOE)
			rval = ixgbe_fcoe_getapp(netdev);
#endif
		break;
	case DCB_APP_IDTYPE_PORTNUM:
		break;
	default:
		break;
	}

	return rval;
}

/**
 * ixgbe_dcbnl_setapp - set the DCBX application user priority
 * @netdev : the corresponding netdev
 * @idtype : identifies the id as ether type or TCP/UDP port number
 * @id: id is either ether type or TCP/UDP port number
 * @up: the 802.1p user priority bitmap
 *
 * Returns : 0 on success or 1 on error
 */
#ifdef HAVE_DCBNL_OPS_SETAPP_RETURN_INT
static int ixgbe_dcbnl_setapp(struct net_device *netdev,
#else
static u8 ixgbe_dcbnl_setapp(struct net_device *netdev,
#endif
			     u8 idtype, u16 id, u8 up)
{
	int err = 0;
#ifdef HAVE_DCBNL_IEEE
	struct dcb_app app;

	app.selector = idtype;
	app.protocol = id;
	app.priority = up;
	err = dcb_setapp(netdev, &app);
#endif

	switch (idtype) {
	case DCB_APP_IDTYPE_ETHTYPE:
#ifdef IXGBE_FCOE
		if (id == ETH_P_FCOE) {
			struct ixgbe_adapter *adapter = netdev_priv(netdev);

			adapter->fcoe.up = up ? ffs(up) - 1 : IXGBE_FCOE_DEFUP;
		}
#endif
		break;
	case DCB_APP_IDTYPE_PORTNUM:
		break;
	default:
		break;
	}

	return err;
}
#endif /* HAVE_DCBNL_OPS_GETAPP */

#ifdef HAVE_DCBNL_IEEE
static int ixgbe_dcbnl_ieee_getets(struct net_device *dev,
				   struct ieee_ets *ets)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ieee_ets *my_ets = adapter->ixgbe_ieee_ets;

	/* No IEEE PFC settings available */
	if (!my_ets)
		return -EINVAL;

	ets->ets_cap = adapter->dcb_cfg.num_tcs.pg_tcs;
	ets->cbs = my_ets->cbs;
	memcpy(ets->tc_tx_bw, my_ets->tc_tx_bw, sizeof(ets->tc_tx_bw));
	memcpy(ets->tc_rx_bw, my_ets->tc_rx_bw, sizeof(ets->tc_rx_bw));
	memcpy(ets->tc_tsa, my_ets->tc_tsa, sizeof(ets->tc_tsa));
	memcpy(ets->prio_tc, my_ets->prio_tc, sizeof(ets->prio_tc));
	return 0;
}

static int ixgbe_dcbnl_ieee_setets(struct net_device *dev,
				   struct ieee_ets *ets)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	int max_frame = dev->mtu + ETH_HLEN + ETH_FCS_LEN;
	int i, err = 0;
	__u8 max_tc = 0;
	__u8 map_chg = 0;

	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	if (!adapter->ixgbe_ieee_ets) {
		adapter->ixgbe_ieee_ets = kmalloc(sizeof(struct ieee_ets),
						  GFP_KERNEL);
		if (!adapter->ixgbe_ieee_ets)
			return -ENOMEM;
		/* initialize UP2TC mappings to invalid value */
		for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
			adapter->ixgbe_ieee_ets->prio_tc[i] =
				IEEE_8021QAZ_MAX_TCS;
		/* if possible update UP2TC mappings from HW */
		if (adapter->hw.mac.ops.get_rtrup2tc)
			adapter->hw.mac.ops.get_rtrup2tc(&adapter->hw,
					adapter->ixgbe_ieee_ets->prio_tc);
	}

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (ets->prio_tc[i] > max_tc)
			max_tc = ets->prio_tc[i];
		if (ets->prio_tc[i] != adapter->ixgbe_ieee_ets->prio_tc[i])
			map_chg = 1;
	}

	memcpy(adapter->ixgbe_ieee_ets, ets, sizeof(*adapter->ixgbe_ieee_ets));

	if (max_tc)
		max_tc++;

	if (max_tc > adapter->dcb_cfg.num_tcs.pg_tcs)
		return -EINVAL;

	if (max_tc != netdev_get_num_tc(dev))
		err = ixgbe_setup_tc(dev, max_tc);
	else if (map_chg)
		ixgbe_dcbnl_devreset(dev);

	if (err)
		goto err_out;

	err = ixgbe_dcb_hw_ets(&adapter->hw, ets, max_frame);
err_out:
	return err;
}

static int ixgbe_dcbnl_ieee_getpfc(struct net_device *dev,
				   struct ieee_pfc *pfc)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ieee_pfc *my_pfc = adapter->ixgbe_ieee_pfc;
	int i;

	/* No IEEE PFC settings available */
	if (!my_pfc)
		return -EINVAL;

	pfc->pfc_cap = adapter->dcb_cfg.num_tcs.pfc_tcs;
	pfc->pfc_en = my_pfc->pfc_en;
	pfc->mbc = my_pfc->mbc;
	pfc->delay = my_pfc->delay;

	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		pfc->requests[i] = adapter->stats.pxoffrxc[i];
		pfc->indications[i] = adapter->stats.pxofftxc[i];
	}

	return 0;
}

static int ixgbe_dcbnl_ieee_setpfc(struct net_device *dev,
				   struct ieee_pfc *pfc)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_hw *hw = &adapter->hw;
	u8 *prio_tc;
	int err;

	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	if (!adapter->ixgbe_ieee_pfc) {
		adapter->ixgbe_ieee_pfc = kmalloc(sizeof(struct ieee_pfc),
						  GFP_KERNEL);
		if (!adapter->ixgbe_ieee_pfc)
			return -ENOMEM;
	}

	prio_tc = adapter->ixgbe_ieee_ets->prio_tc;
	memcpy(adapter->ixgbe_ieee_pfc, pfc, sizeof(*adapter->ixgbe_ieee_pfc));


	/* Enable link flow control parameters if PFC is disabled */
	if (pfc->pfc_en)
		err = ixgbe_dcb_config_pfc(hw, pfc->pfc_en, prio_tc);
	else
		err = hw->mac.ops.fc_enable(hw);

	ixgbe_set_rx_drop_en(adapter);

	return err;
}

static int ixgbe_dcbnl_ieee_setapp(struct net_device *dev,
				   struct dcb_app *app)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	int err = -EINVAL;

	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return err;

	err = dcb_ieee_setapp(dev, app);

#ifdef IXGBE_FCOE
	if (!err && app->selector == IEEE_8021QAZ_APP_SEL_ETHERTYPE &&
	    app->protocol == ETH_P_FCOE) {
		u8 app_mask = dcb_ieee_getapp_mask(dev, app);

		if (app_mask & (1 << adapter->fcoe.up))
			return err;

		adapter->fcoe.up = app->priority;
		adapter->fcoe.up_set = adapter->fcoe.up;
		ixgbe_dcbnl_devreset(dev);
	}
#endif
	return 0;
}

#ifdef HAVE_DCBNL_IEEE_DELAPP
static int ixgbe_dcbnl_ieee_delapp(struct net_device *dev,
				   struct dcb_app *app)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	int err;

	if (!(adapter->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	err = dcb_ieee_delapp(dev, app);

#ifdef IXGBE_FCOE
	if (!err && app->selector == IEEE_8021QAZ_APP_SEL_ETHERTYPE &&
	    app->protocol == ETH_P_FCOE) {
		u8 app_mask = dcb_ieee_getapp_mask(dev, app);

		if (app_mask & (1 << adapter->fcoe.up))
			return err;

		adapter->fcoe.up = app_mask ?
				   ffs(app_mask) - 1 : IXGBE_FCOE_DEFUP;
		ixgbe_dcbnl_devreset(dev);
	}
#endif
	return err;
}
#endif /* HAVE_DCBNL_IEEE_DELAPP */

static u8 ixgbe_dcbnl_getdcbx(struct net_device *dev)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	return adapter->dcbx_cap;
}

static u8 ixgbe_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ieee_ets ets = { .ets_cap = 0 };
	struct ieee_pfc pfc = { .pfc_en = 0 };

	/* no support for LLD_MANAGED modes or CEE+IEEE */
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    ((mode & DCB_CAP_DCBX_VER_IEEE) && (mode & DCB_CAP_DCBX_VER_CEE)) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return 1;

	if (mode == adapter->dcbx_cap)
		return 0;

	adapter->dcbx_cap = mode;

	/* ETS and PFC defaults */
	ets.ets_cap = 8;
	pfc.pfc_cap = 8;

	if (mode & DCB_CAP_DCBX_VER_IEEE) {
		ixgbe_dcbnl_ieee_setets(dev, &ets);
		ixgbe_dcbnl_ieee_setpfc(dev, &pfc);
	} else if (mode & DCB_CAP_DCBX_VER_CEE) {
		u8 mask = (BIT_PFC | BIT_PG_TX | BIT_PG_RX | BIT_APP_UPCHG);

		adapter->dcb_set_bitmap |= mask;
		ixgbe_dcbnl_set_all(dev);
	} else {
		/* Drop into single TC mode strict priority as this
		 * indicates CEE and IEEE versions are disabled
		 */
		ixgbe_dcbnl_ieee_setets(dev, &ets);
		ixgbe_dcbnl_ieee_setpfc(dev, &pfc);
		ixgbe_setup_tc(dev, 0);
	}

	return 0;
}

#endif

struct dcbnl_rtnl_ops dcbnl_ops = {
#ifdef HAVE_DCBNL_IEEE
	.ieee_getets	= ixgbe_dcbnl_ieee_getets,
	.ieee_setets	= ixgbe_dcbnl_ieee_setets,
	.ieee_getpfc	= ixgbe_dcbnl_ieee_getpfc,
	.ieee_setpfc	= ixgbe_dcbnl_ieee_setpfc,
	.ieee_setapp	= ixgbe_dcbnl_ieee_setapp,
#ifdef HAVE_DCBNL_IEEE_DELAPP
	.ieee_delapp	= ixgbe_dcbnl_ieee_delapp,
#endif
#endif
	.getstate	= ixgbe_dcbnl_get_state,
	.setstate	= ixgbe_dcbnl_set_state,
	.getpermhwaddr	= ixgbe_dcbnl_get_perm_hw_addr,
	.setpgtccfgtx	= ixgbe_dcbnl_set_pg_tc_cfg_tx,
	.setpgbwgcfgtx	= ixgbe_dcbnl_set_pg_bwg_cfg_tx,
	.setpgtccfgrx	= ixgbe_dcbnl_set_pg_tc_cfg_rx,
	.setpgbwgcfgrx	= ixgbe_dcbnl_set_pg_bwg_cfg_rx,
	.getpgtccfgtx	= ixgbe_dcbnl_get_pg_tc_cfg_tx,
	.getpgbwgcfgtx	= ixgbe_dcbnl_get_pg_bwg_cfg_tx,
	.getpgtccfgrx	= ixgbe_dcbnl_get_pg_tc_cfg_rx,
	.getpgbwgcfgrx	= ixgbe_dcbnl_get_pg_bwg_cfg_rx,
	.setpfccfg	= ixgbe_dcbnl_set_pfc_cfg,
	.getpfccfg	= ixgbe_dcbnl_get_pfc_cfg,
	.setall		= ixgbe_dcbnl_set_all,
	.getcap		= ixgbe_dcbnl_getcap,
	.getnumtcs	= ixgbe_dcbnl_getnumtcs,
	.setnumtcs	= ixgbe_dcbnl_setnumtcs,
	.getpfcstate	= ixgbe_dcbnl_getpfcstate,
	.setpfcstate	= ixgbe_dcbnl_setpfcstate,
#ifdef HAVE_DCBNL_OPS_GETAPP
	.getapp		= ixgbe_dcbnl_getapp,
	.setapp		= ixgbe_dcbnl_setapp,
#endif
#ifdef HAVE_DCBNL_IEEE
	.getdcbx	= ixgbe_dcbnl_getdcbx,
	.setdcbx	= ixgbe_dcbnl_setdcbx,
#endif
};

#endif
