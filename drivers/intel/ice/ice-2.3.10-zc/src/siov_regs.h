/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/*
 * Copyright (C) 2023 Intel Corporation
 *
 * For licensing information, see the file 'LICENSE' in the root folder
 */

#ifndef _SIOV_REGS_H_
#define _SIOV_REGS_H_
#define VDEV_MBX_START			0x20000 /* Begin at 128KB */
#define VDEV_GET_RSTAT			0x21000 /* 132KB for RSTAT */

/* Begin at offset after 1MB (after 256 4k pages) */
#define VDEV_QRX_TAIL_START		0x100000
#define VDEV_QRX_TAIL(_i)		(VDEV_QRX_TAIL_START + ((_i) * 0x1000)) /* 2k Rx queues */

#define VDEV_QRX_BUFQ_TAIL_START	0x900000 /* Begin at offset of 9MB for  Rx buffer queue tail register pages */
#define VDEV_QRX_BUFQ_TAIL(_i)		(VDEV_QRX_BUFQ_TAIL_START + ((_i) * 0x1000)) /* 2k Rx buffer queues */

#define VDEV_QTX_TAIL_START		0x1100000 /* Begin at offset of 17MB for 2k Tx queues */
#define VDEV_QTX_TAIL(_i)		(VDEV_QTX_TAIL_START + ((_i) * 0x1000)) /* 2k Tx queues */

#define VDEV_QTX_COMPL_TAIL_START	0x1900000 /* Begin at offset of 25MB for 2k Tx completion queues */
#define VDEV_QTX_COMPL_TAIL(_i)		(VDEV_QTX_COMPL_TAIL_START + ((_i) * 0x1000)) /* 2k Tx completion queues */

#define VDEV_INT_DYN_CTL01		0x2100000 /* Begin at offset 33MB */

#define VDEV_INT_DYN_START		(VDEV_INT_DYN_CTL01 + 0x1000) /* Begin at offset of 33MB + 4k to accomdate CTL01 register */
#define VDEV_INT_DYN_CTL(_i)		(VDEV_INT_DYN_START + ((_i) * 0x1000))
#define VDEV_INT_ITR_0(_i)		(VDEV_INT_DYN_START + ((_i) * 0x1000) + 0x04)
#define VDEV_INT_ITR_1(_i)		(VDEV_INT_DYN_START + ((_i) * 0x1000) + 0x08)
#define VDEV_INT_ITR_2(_i)		(VDEV_INT_DYN_START + ((_i) * 0x1000) + 0x0C)

#define SIOV_REG_BAR_SIZE			0x2A00000
/* Next offset to begin at 42MB + 4K (0x2A00000 + 0x1000) */
#endif /* _SIOV_REGS_H_ */
