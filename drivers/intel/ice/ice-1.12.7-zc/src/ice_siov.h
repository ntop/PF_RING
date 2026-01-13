/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_SIOV_H_
#define _ICE_SIOV_H_

#define ICE_DFLT_QS_PER_SIOV_VF		4

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT) && defined(HAVE_IOMMU_DEV_FEAT_AUX)
bool ice_is_siov_capable(struct ice_pf *pf);
void ice_initialize_siov_res(struct ice_pf *pf);
void ice_deinit_siov_res(struct ice_pf *pf);
void ice_restore_pasid_config(struct ice_pf *pf, enum ice_reset_req reset_type);
#else
static inline bool ice_is_siov_capable(struct ice_pf *pf)
{
	return false;
}
static inline void ice_initialize_siov_res(struct ice_pf *pf) { }
static inline void ice_deinit_siov_res(struct ice_pf *pf) { }
static inline void ice_restore_pasid_config(struct ice_pf *pf,
					    enum ice_reset_req reset_type) { }
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT && HAVE_IOMMU_DEV_FEAT_AUX */

#endif /* _ICE_SIOV_H_ */
