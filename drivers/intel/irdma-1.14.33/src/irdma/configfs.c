// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2023 Intel Corporation */
#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include "main.h"
#ifdef __OFED_4_8__
#include <target/configfs_macros.h>
#include <target/target_core_base.h>
#endif

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
enum irdma_configfs_attr_type {
	IRDMA_ATTR_IW_DCTCP,
	IRDMA_ATTR_IW_TIMELY,
	IRDMA_ATTR_IW_ECN,
	IRDMA_ATTR_ROCE_TIMELY,
	IRDMA_ATTR_ROCE_DCQCN,
	IRDMA_ATTR_ROCE_DCTCP,
	IRDMA_ATTR_ROCE_ENABLE,
	IRDMA_ATTR_IW_OOO,
	IRDMA_ATTR_ROCE_NO_ICRC,
	IRDMA_ATTR_ENABLE_UP_MAP,
};

struct irdma_vsi_grp {
	struct config_group group;
	struct irdma_device *iwdev;
};

/**
 * irdma_find_device_by_name - find a vsi device given a name
 * @name: name of iwdev
 */
static struct irdma_device *irdma_find_device_by_name(const char *name)
{
	struct irdma_handler *hdl;
	struct irdma_device *iwdev;
	unsigned long flags;

	spin_lock_irqsave(&irdma_handler_lock, flags);
	list_for_each_entry(hdl, &irdma_handlers, list) {
		iwdev = hdl->iwdev;
		if (!strcmp(name, iwdev->ibdev.name)) {
			spin_unlock_irqrestore(&irdma_handler_lock, flags);
			return iwdev;
		}
	}
	spin_unlock_irqrestore(&irdma_handler_lock, flags);

	return NULL;
}

#ifdef __OFED_4_8__
static int irdma_configfs_set_vsi_attr(struct irdma_vsi_grp *grp,
				       const char *buf,
				       enum irdma_configfs_attr_type attr_type)
{
#else
/*
 * irdma_configfs_set_vsi_attr - set vsi configfs attribute
 * @item_name: config item name
 * @buf: buffer
 * @irdma_configfs_type_attr: vsi attribute type to set
 */
static int irdma_configfs_set_vsi_attr(struct config_item *item,
				       const char *buf,
				       enum irdma_configfs_attr_type attr_type)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	struct irdma_up_info up_map_info = {};
	bool enable;
	int ret = 0;

	if (kstrtobool(buf, &enable)) {
		ret = -EINVAL;
		goto done;
	}

	switch (attr_type) {
	case IRDMA_ATTR_IW_DCTCP:
		iwdev->iwarp_dctcp_en = enable;
		iwdev->iwarp_ecn_en = !enable;
		break;
	case IRDMA_ATTR_IW_TIMELY:
		iwdev->iwarp_timely_en = enable;
		break;
	case IRDMA_ATTR_IW_ECN:
		iwdev->iwarp_ecn_en = enable;
		break;
	case IRDMA_ATTR_ENABLE_UP_MAP:
		iwdev->up_map_en = enable;
		if (enable) {
			*((u64 *)up_map_info.map) = iwdev->up_up_map;
			up_map_info.use_cnp_up_override = true;
			up_map_info.cnp_up_override = iwdev->cnp_up_override;
		} else {
			*((u64 *)up_map_info.map) = IRDMA_DEFAULT_UP_UP_MAP;
			up_map_info.use_cnp_up_override = false;
		}
		up_map_info.hmc_fcn_idx = iwdev->rf->sc_dev.hmc_fn_id;
		irdma_cqp_up_map_cmd(&iwdev->rf->sc_dev, IRDMA_OP_SET_UP_MAP,
				     &up_map_info);
		break;
	case IRDMA_ATTR_ROCE_NO_ICRC:
		iwdev->roce_no_icrc_en = enable;
		break;
	case IRDMA_ATTR_ROCE_TIMELY:
		iwdev->roce_timely_en = enable;
		break;
	case IRDMA_ATTR_ROCE_DCQCN:
		iwdev->roce_dcqcn_en = enable;
		break;
	case IRDMA_ATTR_ROCE_DCTCP:
		iwdev->roce_dctcp_en = enable;
		break;
	case IRDMA_ATTR_ROCE_ENABLE:
		//rf->roce_en = enable; FIXME: Add when roce/iwarp in configFS
		break;
	case IRDMA_ATTR_IW_OOO:
		iwdev->iw_ooo = enable;
		iwdev->override_ooo = true;
		break;
	default:
		ret = -EINVAL;
	}

done:
	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_push_mode(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * push_mode_show - Show the value of push_mode for device
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t push_mode_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->push_mode);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_push_mode(struct irdma_vsi_grp *grp,
					  const char *buf,
					  size_t count)
{
#else
/**
 * push_mode_store - Store value for push_mode
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t push_mode_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	bool enable;

	if (kstrtobool(buf, &enable))
		return -EINVAL;

	iwdev->push_mode = enable;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_cwnd(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_cwnd_show - Show the value of RoCE cwnd
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_cwnd_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_cwnd);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_cwnd(struct irdma_vsi_grp *grp,
					  const char *buf,
					  size_t count)
{
#else
/**
 * roce_cwnd_store - Store value for roce_cwnd
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_cwnd_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u32 rsrc_cwnd;

	if (kstrtou32(buf, 0, &rsrc_cwnd))
		return -EINVAL;

	if (!rsrc_cwnd || rsrc_cwnd > 0x400)
		return -EINVAL;

	iwdev->roce_cwnd = rsrc_cwnd;
	iwdev->override_cwnd = true;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_rd_fence_rate(struct irdma_vsi_grp *grp, char *buf)
{
#else
/*
 * roce_rd_fence_rate_show - Show RoCE read fence rate
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_rd_fence_rate_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->rd_fence_rate);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_rd_fence_rate(struct irdma_vsi_grp *grp,
						   const char *buf, size_t count)
{
#else
/**
 * roce_rd_fence_rate_store - Store RoCE read fence rate
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_rd_fence_rate_store(struct config_item *item,
					const char *buf, size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u32 rd_fence_rate;

	if (kstrtou32(buf, 0, &rd_fence_rate))
		return -EINVAL;

	if (rd_fence_rate > 256)
		return -EINVAL;

	iwdev->rd_fence_rate = rd_fence_rate;
	iwdev->override_rd_fence_rate = true;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_ackcreds(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_ackcreds_show - Show the value of RoCE ack_creds
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_ackcreds_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_ackcreds);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_ackcreds(struct irdma_vsi_grp *grp,
					      const char *buf,
					      size_t count)
{
#else
/**
 * roce_ackcreds_store - Store value for roce_ackcreds
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_ackcreds_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u32 rsrc_ackcreds;

	if (kstrtou32(buf, 0, &rsrc_ackcreds))
		return -EINVAL;

	if (!rsrc_ackcreds || rsrc_ackcreds > 0x1E)
		return -EINVAL;

	iwdev->roce_ackcreds = rsrc_ackcreds;
	iwdev->override_ackcreds = true;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_cnp_up_override(struct irdma_vsi_grp *grp,
						const char *buf,
						size_t count)
{
#else
/**
 * cnp_up_override_store - Store value for CNP override
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t cnp_up_override_store(struct config_item *item,
				     const char *buf,
				     size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u8 cnp_override;

	if (kstrtou8(buf, 0, &cnp_override))
		return -EINVAL;

	if (cnp_override > 0x3F)
		return -EINVAL;

	iwdev->cnp_up_override = cnp_override;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_cnp_up_override(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * cnp_up_override_show - Show value of CNP UP override
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t cnp_up_override_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->cnp_up_override);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_ceq_itr(struct irdma_vsi_grp *grp,
					const char *buf,
					size_t count)
{
#else
/**
 * ceq_itr_store - Set interrupt Throttling(ITR) value
 * @item: config item
 * @buf: buffer to read from
 * @count: size of buffer
 */
static ssize_t ceq_itr_store(struct config_item *item,
			     const char *buf,
			     size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u32 itr;

	if (kstrtou32(buf, 0, &itr))
		return -EINVAL;

#define IRDMA_MAX_ITR 8160
	if (itr > 8160) {
		return -EINVAL;
	}

	iwdev->rf->sc_dev.ceq_itr = itr;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_ceq_itr(struct irdma_vsi_grp *grp,
				       char *buf)
{
#else
/**
 * ceq_itr_show - Show interrupt Throttling(ITR) value
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t ceq_itr_show(struct config_item *item,
			    char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->rf->sc_dev.ceq_itr);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_ceq_intrl(struct irdma_vsi_grp *grp,
					  const char *buf,
					  size_t count)
{
#else
/**
 * ceq_intrl_store - Set the interrupt rate limit value
 * @item: config item
 * @buf: buffer to read from
 * @count: size of buffer
 */
static ssize_t ceq_intrl_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	struct irdma_msix_vector *msix_vec;
	u32 intrl, interval = 0;
	int i;

	if (kstrtou32(buf, 0, &intrl))
		return -EINVAL;

#define IRDMA_MIN_INT_RATE_LIMIT	4237
#define IRDMA_MAX_INT_RATE_LIMIT	250000
#define IRDMA_USECS_PER_SEC		1000000
#define IRDMA_USECS_PER_UNIT		4
#define IRDMA_MAX_SUPPORTED_INT_RATE_INTERVAL 59	/* 59 * 4 = 236 us */

	if (intrl && intrl < IRDMA_MIN_INT_RATE_LIMIT)
		intrl = IRDMA_MIN_INT_RATE_LIMIT;
	if (intrl > IRDMA_MAX_INT_RATE_LIMIT)
		intrl = IRDMA_MAX_INT_RATE_LIMIT;

	iwdev->ceq_intrl = intrl;
	if (intrl) {
		interval = (IRDMA_USECS_PER_SEC / intrl) / IRDMA_USECS_PER_UNIT;

		ibdev_info(&iwdev->ibdev, "CEQ Interrupt rate Limit enabled with interval = %d\n", interval);
	} else {
		ibdev_info(&iwdev->ibdev, "CEQ Interrupt rate Limit disabled\n");
	}

	if (iwdev->rf->msix_shared)
		msix_vec = &iwdev->rf->iw_msixtbl[1];
	else
		msix_vec = &iwdev->rf->iw_msixtbl[2];
	for (i = 1; i < iwdev->rf->ceqs_count; i++, msix_vec++)
		irdma_set_irq_rate_limit(&iwdev->rf->sc_dev, msix_vec->idx, interval);

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_ceq_intrl(struct irdma_vsi_grp *grp,
					 char *buf)
{
#else
/**
 * ceq_intrl_show - Show the interrupt rate limit value
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t ceq_intrl_show(struct config_item *item,
			      char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->ceq_intrl);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_up_up_map(struct irdma_vsi_grp *grp,
					  const char *buf,
					  size_t count)
{
#else
/**
 * up_up_map_store - Store value for UP-UP map
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t up_up_map_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u64 up_map;

	if (kstrtou64(buf, 0, &up_map))
		return -EINVAL;

	iwdev->up_up_map = up_map;
	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_up_up_map(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * up_up_map_show - Show value of IP-UP map
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t up_up_map_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "0x%llx\n", iwdev->up_up_map);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_rcv_wnd(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * rcv_wnd_show - Show the value of TCP receive window
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t rcv_wnd_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->rcv_wnd);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_rcv_wnd(struct irdma_vsi_grp *grp,
					const char *buf,
					size_t count)
{
#else
/**
 * rcv_wnd_store - Store value for rcv_wnd
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t rcv_wnd_store(struct config_item *item,
			     const char *buf,
			     size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u32 rsrc_rcv_wnd;

	if (kstrtou32(buf, 0, &rsrc_rcv_wnd))
		return -EINVAL;

	if (rsrc_rcv_wnd < 65536)
		return -EINVAL;

	iwdev->rcv_wnd = rsrc_rcv_wnd;
	iwdev->override_rcv_wnd = true;
	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_rcv_wscale(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * rcv_wscale_show - Show value of TCP receive window scale
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t rcv_wscale_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->rcv_wscale);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_rcv_wscale(struct irdma_vsi_grp *grp,
					   const char *buf,
					   size_t count)
{
#else
/**
 * rcv_wscale_store - Store value for recv_wscale
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t rcv_wscale_store(struct config_item *item,
				const char *buf,
				size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u8 rsrc_rcv_wscale;

	if (kstrtou8(buf, 0, &rsrc_rcv_wscale))
		return -EINVAL;

	if (rsrc_rcv_wscale > 16)
		return -EINVAL;

	iwdev->rcv_wscale = rsrc_rcv_wscale;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_iw_dctcp_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * iw_dctcp_enable_show - Show the value of dctcp_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t iw_dctcp_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->iwarp_dctcp_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_iw_dctcp_enable(struct irdma_vsi_grp *grp,
						const char *buf,
						size_t count)
#else
/**
 * iw_dctcp_enable_store - Store value of dctcp_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t iw_dctcp_enable_store(struct config_item *item,
				     const char *buf,
				     size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_IW_DCTCP);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_IW_DCTCP);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_iw_ecn_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * iw_ecn_enable_show - Show the value of ecn_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t iw_ecn_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->iwarp_ecn_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_iw_ecn_enable(struct irdma_vsi_grp *grp,
					      const char *buf,
					      size_t count)
#else
/**
 * iw_ecn_enable_store - Store value of ecn_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t iw_ecn_enable_store(struct config_item *item,
				   const char *buf,
				   size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_IW_ECN);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_IW_ECN);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_iw_timely_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * iw_timely_enable_show - Show value of iwarp_timely_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t iw_timely_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->iwarp_timely_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_iw_timely_enable(struct irdma_vsi_grp *grp,
						 const char *buf,
						 size_t count)
#else
/**
 * iw_timely_enable_store - Store value of iwarp_timely_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t iw_timely_enable_store(struct config_item *item,
				      const char *buf,
				      size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_IW_TIMELY);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_IW_TIMELY);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_iw_rtomin(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * iw_rtomin_show - Show the value of rtomin for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t iw_rtomin_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->iwarp_rtomin);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_iw_rtomin(struct irdma_vsi_grp *grp,
					  const char *buf,
					  size_t count)
{
#else
/**
 * iw_rtomin_store - Store value of iwarp_rtomin for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t iw_rtomin_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u8 rtomin;

	if (kstrtou8(buf, 0, &rtomin))
		return -EINVAL;

	iwdev->iwarp_rtomin = rtomin;
	iwdev->override_rtomin = true;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_rtomin(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_rtomin_show - Show the value of roce_rtomin for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_rtomin_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_rtomin);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_rtomin(struct irdma_vsi_grp *grp,
					    const char *buf,
					    size_t count)
{
#else
/**
 * roce_rtomin_store - Store value of roce_rtomin for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_rtomin_store(struct config_item *item,
				 const char *buf,
				 size_t count)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	u8 rtomin;

	if (kstrtou8(buf, 0, &rtomin))
		return -EINVAL;

	iwdev->roce_rtomin = rtomin;
	iwdev->override_rtomin = true;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_timely_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_timely_enable_show - Show value of roce_timely_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_timely_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_timely_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_timely_enable(struct irdma_vsi_grp *grp,
						   const char *buf,
						   size_t count)
#else
/**
 * roce_timely_enable_store - Store value of roce_timely_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_timely_enable_store(struct config_item *item,
					const char *buf,
					size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_ROCE_TIMELY);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_ROCE_TIMELY);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_no_icrc_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_no_icrc_enable_show - Show value of no_icrc for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_no_icrc_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_no_icrc_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_no_icrc_enable(struct irdma_vsi_grp *grp,
						    const char *buf,
						    size_t count)
#else
/**
 * roce_no_icrc_enable_store - Store value of roce_no_icrc for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_no_icrc_enable_store(struct config_item *item,
					 const char *buf,
					 size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_ROCE_NO_ICRC);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_ROCE_NO_ICRC);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_up_map_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * up_map_enable_show - Show value of up_map_enable for PF
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t up_map_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->up_map_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_up_map_enable(struct irdma_vsi_grp *grp,
					      const char *buf,
					      size_t count)
#else
/**
 * up_map_enable_store - Store value of up_map_enable for PF
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t up_map_enable_store(struct config_item *item,
				   const char *buf,
				   size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_ENABLE_UP_MAP);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_ENABLE_UP_MAP);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_iw_ooo_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * iw_ooo_enable_show - Show the value of iw_ooo_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t iw_ooo_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->iw_ooo);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_iw_ooo_enable(struct irdma_vsi_grp *grp,
					      const char *buf,
					      size_t count)
#else
/**
 * iw_ooo_enable_store - Store value of iw_ooo_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t iw_ooo_enable_store(struct config_item *item,
				   const char *buf,
				   size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_IW_OOO);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_IW_OOO);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_dcqcn_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/**
 * roce_dcqcn_enable_show - Show the value of roce_dcqcn_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_dcqcn_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_dcqcn_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_dcqcn_enable(struct irdma_vsi_grp *grp,
						  const char *buf,
						  size_t count)
#else
/**
 * roce_dcqcn_enable_store - Store value of roce_dcqcn_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_dcqcn_enable_store(struct config_item *item,
				       const char *buf,
				       size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_ROCE_DCQCN);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_ROCE_DCQCN);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
static ssize_t irdma_show_attr_roce_dctcp_enable(struct irdma_vsi_grp *grp, char *buf)
{
#else
/* roce_dctcp_enable_show - Show the value of roce_dctcp_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_dctcp_enable_show(struct config_item *item, char *buf)
{
	struct irdma_vsi_grp *grp = container_of(to_config_group(item),
						 struct irdma_vsi_grp,
						 group);
#endif
	struct irdma_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_dctcp_en);

	return ret;
}

#ifdef __OFED_4_8__
static ssize_t irdma_store_attr_roce_dctcp_enable(struct irdma_vsi_grp *grp,
						  const char *buf,
						  size_t count)
#else
/**
 * roce_dctcp_enable_store - Store value of roce_dctcp_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_dctcp_enable_store(struct config_item *item,
				       const char *buf,
				       size_t count)
#endif
{
	int ret;

#ifdef __OFED_4_8__
	ret = irdma_configfs_set_vsi_attr(grp, buf, IRDMA_ATTR_ROCE_DCTCP);
#else
	ret = irdma_configfs_set_vsi_attr(item, buf, IRDMA_ATTR_ROCE_DCTCP);
#endif

	if (ret)
		return ret;

	return count;
}

#ifdef __OFED_4_8__
CONFIGFS_EATTR_STRUCT(irdma, irdma_vsi_grp);
#define CFG_CONFIG_DESC_ITEM_ATTR(name) \
	static struct irdma_attribute name = \
		__CONFIGFS_EATTR(name, 0644, \
				irdma_show_attr_##name,      \
				irdma_store_attr_##name)

CFG_CONFIG_DESC_ITEM_ATTR(iw_dctcp_enable);
CFG_CONFIG_DESC_ITEM_ATTR(push_mode);
CFG_CONFIG_DESC_ITEM_ATTR(iw_timely_enable);
CFG_CONFIG_DESC_ITEM_ATTR(iw_ecn_enable);
CFG_CONFIG_DESC_ITEM_ATTR(iw_rtomin);
CFG_CONFIG_DESC_ITEM_ATTR(rcv_wnd);
CFG_CONFIG_DESC_ITEM_ATTR(rcv_wscale);
CFG_CONFIG_DESC_ITEM_ATTR(iw_ooo_enable);
CFG_CONFIG_DESC_ITEM_ATTR(cnp_up_override);
CFG_CONFIG_DESC_ITEM_ATTR(up_map_enable);
CFG_CONFIG_DESC_ITEM_ATTR(up_up_map);
CFG_CONFIG_DESC_ITEM_ATTR(ceq_itr);
CFG_CONFIG_DESC_ITEM_ATTR(ceq_intrl);
CFG_CONFIG_DESC_ITEM_ATTR(roce_cwnd);
CFG_CONFIG_DESC_ITEM_ATTR(roce_rd_fence_rate);
CFG_CONFIG_DESC_ITEM_ATTR(roce_ackcreds);
CFG_CONFIG_DESC_ITEM_ATTR(roce_timely_enable);
CFG_CONFIG_DESC_ITEM_ATTR(roce_no_icrc_enable);
CFG_CONFIG_DESC_ITEM_ATTR(roce_dcqcn_enable);
CFG_CONFIG_DESC_ITEM_ATTR(roce_dctcp_enable);
CFG_CONFIG_DESC_ITEM_ATTR(roce_rtomin);

CONFIGFS_EATTR_OPS(irdma, irdma_vsi_grp, group);

static struct configfs_attribute *irdma_gen1_iw_vsi_attrs[] = {
	&rcv_wnd.attr,
	&rcv_wscale.attr,
	NULL,
};

static struct configfs_attribute *irdma_iw_vsi_attrs[] = {
	&push_mode.attr,
	&iw_dctcp_enable.attr,
	&iw_timely_enable.attr,
	&iw_ecn_enable.attr,
	&iw_rtomin.attr,
	&rcv_wnd.attr,
	&rcv_wscale.attr,
	&iw_ooo_enable.attr,
	&cnp_up_override.attr,
	&up_map_enable.attr,
	&up_up_map.attr,
	&ceq_itr.attr,
	&ceq_intrl.attr,
	NULL,
};

static struct configfs_attribute *irdma_roce_vsi_attrs[] = {
	&push_mode.attr,
	&roce_cwnd.attr,
	&roce_rd_fence_rate.attr,
	&roce_ackcreds.attr,
	&roce_timely_enable.attr,
	&roce_no_icrc_enable.attr,
	&roce_dcqcn_enable.attr,
	&roce_dctcp_enable.attr,
	&roce_rtomin.attr,
	&cnp_up_override.attr,
	&up_map_enable.attr,
	&up_up_map.attr,
	&ceq_itr.attr,
	&ceq_intrl.attr,
	NULL,
};
#else /* OFED_4_8 */
CONFIGFS_ATTR(, push_mode);
CONFIGFS_ATTR(, iw_dctcp_enable);
CONFIGFS_ATTR(, iw_timely_enable);
CONFIGFS_ATTR(, iw_ecn_enable);
CONFIGFS_ATTR(, iw_rtomin);
CONFIGFS_ATTR(, rcv_wnd);
CONFIGFS_ATTR(, rcv_wscale);
CONFIGFS_ATTR(, iw_ooo_enable);
CONFIGFS_ATTR(, up_map_enable);
CONFIGFS_ATTR(, cnp_up_override);
CONFIGFS_ATTR(, up_up_map);
CONFIGFS_ATTR(, ceq_itr);
CONFIGFS_ATTR(, ceq_intrl);
CONFIGFS_ATTR(, roce_timely_enable);
CONFIGFS_ATTR(, roce_no_icrc_enable);
CONFIGFS_ATTR(, roce_dcqcn_enable);
CONFIGFS_ATTR(, roce_dctcp_enable);
CONFIGFS_ATTR(, roce_cwnd);
CONFIGFS_ATTR(, roce_rd_fence_rate);
CONFIGFS_ATTR(, roce_ackcreds);
CONFIGFS_ATTR(, roce_rtomin);

static struct configfs_attribute *irdma_gen1_iw_vsi_attrs[] = {
	&attr_rcv_wnd,
	&attr_rcv_wscale,
	NULL,
};

static struct configfs_attribute *irdma_iw_vsi_attrs[] = {
	&attr_push_mode,
	&attr_iw_dctcp_enable,
	&attr_iw_timely_enable,
	&attr_iw_ecn_enable,
	&attr_iw_rtomin,
	&attr_rcv_wnd,
	&attr_rcv_wscale,
	&attr_iw_ooo_enable,
	&attr_cnp_up_override,
	&attr_up_map_enable,
	&attr_up_up_map,
	&attr_ceq_itr,
	&attr_ceq_intrl,
	NULL,
};

static struct configfs_attribute *irdma_roce_vsi_attrs[] = {
	&attr_push_mode,
	&attr_roce_cwnd,
	&attr_roce_rd_fence_rate,
	&attr_roce_ackcreds,
	&attr_roce_timely_enable,
	&attr_roce_no_icrc_enable,
	&attr_roce_dcqcn_enable,
	&attr_roce_dctcp_enable,
	&attr_roce_rtomin,
	&attr_cnp_up_override,
	&attr_up_map_enable,
	&attr_up_up_map,
	&attr_ceq_itr,
	&attr_ceq_intrl,
	NULL,
};
#endif /* OFED_4_8 */

static void irdma_release_vsi_grp(struct config_item *item)
{
	struct config_group *group = container_of(item, struct config_group,
						  cg_item);
	struct irdma_vsi_grp *vsi_grp = container_of(group,
						     struct irdma_vsi_grp,
						     group);

	kfree(vsi_grp);
}

static struct configfs_item_operations irdma_vsi_ops = {
#ifdef __OFED_4_8__
	.show_attribute = irdma_attr_show,
	.store_attribute = irdma_attr_store,
#endif
	.release = irdma_release_vsi_grp
};

static struct config_item_type irdma_iw_vsi_type = {
	.ct_attrs = irdma_iw_vsi_attrs,
	.ct_item_ops = &irdma_vsi_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type irdma_roce_vsi_type = {
	.ct_attrs = irdma_roce_vsi_attrs,
	.ct_item_ops = &irdma_vsi_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type irdma_gen1_iw_vsi_type = {
	.ct_attrs = irdma_gen1_iw_vsi_attrs,
	.ct_item_ops = &irdma_vsi_ops,
	.ct_owner = THIS_MODULE,
};

/**
 * irdma_vsi_make_group - Creation of subsystem groups
 * @group: config group
 * @name: name of the group
 */
static struct config_group *irdma_vsi_make_group(struct config_group *group,
						 const char *name)
{
	struct irdma_vsi_grp *vsi_grp;
	struct irdma_device *iwdev;
	u8 hw_ver;

	iwdev = irdma_find_device_by_name(name);
	if (!iwdev)
		return ERR_PTR(-ENODEV);

	hw_ver = iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev;

	vsi_grp = kzalloc(sizeof(*vsi_grp), GFP_KERNEL);
	if (!vsi_grp)
		return ERR_PTR(-ENOMEM);

	vsi_grp->iwdev = iwdev;

	config_group_init(&vsi_grp->group);

	if (hw_ver == IRDMA_GEN_1) {
		config_group_init_type_name(&vsi_grp->group, name,
					    &irdma_gen1_iw_vsi_type);
	} else {
		if (iwdev->rf->protocol_used == IRDMA_IWARP_PROTOCOL_ONLY)
			config_group_init_type_name(&vsi_grp->group, name, &irdma_iw_vsi_type);
		else
			config_group_init_type_name(&vsi_grp->group, name, &irdma_roce_vsi_type);
	}

	return &vsi_grp->group;
}

static struct configfs_group_operations irdma_vsi_group_ops = {
	.make_group = irdma_vsi_make_group,
};

static struct config_item_type irdma_subsys_type = {
	.ct_group_ops = &irdma_vsi_group_ops,
	.ct_owner = THIS_MODULE,
};

static struct configfs_subsystem cfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "irdma",
			.ci_type = &irdma_subsys_type,
		},
	},
};

int irdma_configfs_init(void)
{
	config_group_init(&cfs_subsys.su_group);
	mutex_init(&cfs_subsys.su_mutex);
	return configfs_register_subsystem(&cfs_subsys);
}

void irdma_configfs_exit(void)
{
	configfs_unregister_subsystem(&cfs_subsys);
}
#endif /* CONFIG_CONFIGFS_FS */
