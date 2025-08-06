/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_CONTROLQ_H_
#define _ICE_CONTROLQ_H_

#include "ice_adminq_cmd.h"

/* Maximum buffer lengths for all control queue types */
#define ICE_AQ_MAX_BUF_LEN 4096
#define ICE_MBXQ_MAX_BUF_LEN 4096
#define ICE_SBQ_MAX_BUF_LEN 512

#define ICE_CTL_Q_DESC(R, i) \
	(&(((struct ice_aq_desc *)((R).desc_buf.va))[i]))

#define ICE_CTL_Q_DESC_UNUSED(R) \
	((u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	       (R)->next_to_clean - (R)->next_to_use - 1))

/* Defines that help manage the driver vs FW API checks.
 * Take a look at ice_aq_ver_check in ice_controlq.c for actual usage.
 */
#define EXP_FW_API_VER_BRANCH_E810		0x00
#define EXP_FW_API_VER_MAJOR_E810		0x01
#define EXP_FW_API_VER_MINOR_E810		0x05

#define EXP_FW_API_VER_BRANCH_E830		0x00
#define EXP_FW_API_VER_MAJOR_E830		0x01
#define EXP_FW_API_VER_MINOR_E830		0x07

#define EXP_FW_API_VER_BRANCH_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? \
					  EXP_FW_API_VER_BRANCH_E830 : \
					  EXP_FW_API_VER_BRANCH_E810)
#define EXP_FW_API_VER_MAJOR_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? \
					 EXP_FW_API_VER_MAJOR_E830 : \
					 EXP_FW_API_VER_MAJOR_E810)
#define EXP_FW_API_VER_MINOR_BY_MAC(hw) ((hw)->mac_type == ICE_MAC_E830 ? \
					 EXP_FW_API_VER_MINOR_E830 : \
					 EXP_FW_API_VER_MINOR_E810)

/* Different control queue types: These are mainly for SW consumption. */
enum ice_ctl_q {
	ICE_CTL_Q_UNKNOWN = 0,
	ICE_CTL_Q_ADMIN,
	ICE_CTL_Q_MAILBOX,
	ICE_CTL_Q_SB,
};

/* Control Queue timeout settings - max delay 1s */
#define ICE_CTL_Q_SQ_CMD_TIMEOUT	USEC_PER_SEC
#define ICE_CTL_Q_SQ_CMD_TIMEOUT_SPIN	100
#define ICE_CTL_Q_ADMIN_INIT_TIMEOUT	10    /* Count 10 times */
#define ICE_CTL_Q_ADMIN_INIT_MSEC	100   /* Check every 100msec */

struct ice_ctl_q_ring {
	void *dma_head;			/* Virtual address to DMA head */
	struct ice_dma_mem desc_buf;	/* descriptor ring memory */

	union {
		struct ice_dma_mem *sq_bi;
		struct ice_dma_mem *rq_bi;
	} r;

	u16 count;		/* Number of descriptors */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	/* used for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
	u32 len_mask;
	u32 len_ena_mask;
	u32 len_crit_mask;
	u32 head_mask;
};

/* sq transaction details */
struct ice_sq_cd {
	u8 postpone : 1;
	struct ice_aq_desc *wb_desc;
};

/* rq event information */
struct ice_rq_event_info {
	struct ice_aq_desc desc;
	u16 msg_len;
	u16 buf_len;
	u8 *msg_buf;
};

struct ice_var_lock {
	bool sleepable : 1;
	union {
		struct mutex mlock; /* Sleepable lock. */
		struct {
			spinlock_t slock; /* Non-sleepable lock. */
			unsigned long flags;
		};
	};
};

/**
 * ice_vlock_init - Initialize ice_var_lock
 * @vlock: pointer to the ice_var_lock structure
 */
static inline void ice_vlock_init(struct ice_var_lock *vlock, bool sleepable)
{
	vlock->sleepable = sleepable;
	if (sleepable)
		mutex_init(&vlock->mlock);
	else
		spin_lock_init(&vlock->slock);
}

/**
 * ice_vlock_destroy - Destroy ice_var_lock
 * @vlock: pointer to the ice_var_lock structure
 */
static inline void ice_vlock_destroy(struct ice_var_lock *vlock)
{
	if (vlock->sleepable)
		mutex_destroy(&vlock->mlock);
}

/**
 * ice_vlock_fsleep - Sleep using ice_var_lock
 * @vlock: pointer to the ice_var_lock structure
 * @msec_sleepable: time to sleep in milliseconds for sleepable
 * @usec_nonsleepable: time to delay in microseconds for nonsleepable
 */
static inline void ice_vlock_fsleep(struct ice_var_lock *vlock,
				    unsigned int msec_sleepable,
				    unsigned int usec_nonsleepable)
{
	if (vlock->sleepable)
		msleep(msec_sleepable);
	else
		udelay(usec_nonsleepable);
}

/**
 * ice_vlock - Acquire ice_var_lock
 * @vlock: pointer to the ice_var_lock structure
 */
static inline void ice_vlock(struct ice_var_lock *vlock)
{
	if (vlock->sleepable)
		mutex_lock(&vlock->mlock);
	else
		spin_lock_irqsave(&vlock->slock, vlock->flags);
}

/**
 * ice_vunlock - Release ice_var_lock
 * @vlock: pointer to the ice_var_lock structure
 */
static inline void ice_vunlock(struct ice_var_lock *vlock)
{
	if (vlock->sleepable)
		mutex_unlock(&vlock->mlock);
	else
		spin_unlock_irqrestore(&vlock->slock, vlock->flags);
}

DEFINE_GUARD(ice_var_lock, struct ice_var_lock *, ice_vlock(_T),
	     ice_vunlock(_T))

/* Control Queue information */
struct ice_ctl_q_info {
	enum ice_ctl_q qtype;
	struct ice_ctl_q_ring rq;	/* receive queue */
	struct ice_ctl_q_ring sq;	/* send queue */
	u16 num_rq_entries;		/* receive queue depth */
	u16 num_sq_entries;		/* send queue depth */
	u16 rq_buf_size;		/* receive queue buffer size */
	u16 sq_buf_size;		/* send queue buffer size */
	enum ice_aq_err sq_last_status;	/* last status on send queue */
	struct ice_var_lock sq_lock;	/* Send queue lock */
	struct mutex rq_lock;		/* Receive queue lock */
};

#endif /* _ICE_CONTROLQ_H_ */
