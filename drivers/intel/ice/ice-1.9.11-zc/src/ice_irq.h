/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_IRQ_H_
#define _ICE_IRQ_H_

int ice_init_interrupt_scheme(struct ice_pf *pf);
void ice_clear_interrupt_scheme(struct ice_pf *pf);

int ice_get_irq_num(struct ice_pf *pf, int idx);

#endif
