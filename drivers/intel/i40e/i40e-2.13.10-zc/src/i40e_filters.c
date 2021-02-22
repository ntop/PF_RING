// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2013 - 2020 Intel Corporation. */

#include "i40e_filters.h"

/**
 * __i40e_del_filter - Remove a specific filter from the VSI
 * @vsi: VSI to remove from
 * @f: the filter to remove from the list
 *
 * This function should be called instead of i40e_del_filter only if you know
 * the exact filter you will remove already, such as via i40e_find_filter or
 * i40e_find_mac.
 *
 * NOTE: This function is expected to be called with mac_filter_hash_lock
 * being held.
 * ANOTHER NOTE: This function MUST be called from within the context of
 * the "safe" variants of any list iterators, e.g. list_for_each_entry_safe()
 * instead of list_for_each_entry().
 **/
void __i40e_del_filter(struct i40e_vsi *vsi, struct i40e_mac_filter *f)
{
	if (!f)
		return;

	/* If the filter was never added to firmware then we can just delete it
	 * directly and we don't want to set the status to remove or else an
	 * admin queue command will unnecessarily fire.
	 */
	if (f->state == I40E_FILTER_FAILED || f->state == I40E_FILTER_NEW) {
		hash_del(&f->hlist);
		kfree(f);
	} else {
		f->state = I40E_FILTER_REMOVE;
	}

	vsi->flags |= I40E_VSI_FLAG_FILTER_CHANGED;
	set_bit(__I40E_MACVLAN_SYNC_PENDING, vsi->back->state);
}

