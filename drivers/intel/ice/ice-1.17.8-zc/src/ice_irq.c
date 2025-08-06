/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_irq.h"

#ifdef HAVE_PF_RING
extern int RSS[ICE_MAX_NIC];
#endif

#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
/**
 * ice_init_irq_tracker - initialize interrupt tracker
 * @pf: board private structure
 * @max_vectors: maximum number of vectors that tracker can hold
 * @num_static: number of preallocated interrupts
 */
static void
ice_init_irq_tracker(struct ice_pf *pf, unsigned int max_vectors,
		     unsigned int num_static)
{
	pf->irq_tracker.num_entries = max_vectors;
	pf->irq_tracker.num_static = num_static;
	xa_init_flags(&pf->irq_tracker.entries, XA_FLAGS_ALLOC);
}

/**
 * ice_deinit_irq_tracker - free xarray tracker
 * @pf: board private structure
 */
static void ice_deinit_irq_tracker(struct ice_pf *pf)
{
	xa_destroy(&pf->irq_tracker.entries);
}

/**
 * ice_free_irq_res - free a block of resources
 * @pf: board private structure
 * @index: starting index previously returned by ice_get_res
 */
static void ice_free_irq_res(struct ice_pf *pf, u16 index)
{
	struct ice_irq_entry *entry;

	entry = xa_erase(&pf->irq_tracker.entries, index);
	kfree(entry);
}

/**
 * ice_get_irq_res - get an interrupt resource
 * @pf: board private structure
 * @dyn_only: force entry to be dynamically allocated
 *
 * Allocate new irq entry in the free slot of the tracker. Since xarray
 * is used, always allocate new entry at the lowest possible index. Set
 * proper allocation limit for maximum tracker entries.
 *
 * Returns allocated irq entry or NULL on failure.
 */
static struct ice_irq_entry *ice_get_irq_res(struct ice_pf *pf, bool dyn_only)
{
	struct xa_limit limit = { .max = pf->irq_tracker.num_entries,
				  .min = 0 };
	unsigned int num_static = pf->irq_tracker.num_static;
	struct ice_irq_entry *entry;
	unsigned int index;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	/* skip preallocated entries if the caller says so */
	if (dyn_only)
		limit.min = num_static;

	ret = xa_alloc(&pf->irq_tracker.entries, &index, entry, limit,
		       GFP_KERNEL);

	if (ret) {
		kfree(entry);
		entry = NULL;
	} else {
		entry->index = index;
		entry->dynamic = index >= num_static;
	}

	return entry;
}
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */

#ifdef HAVE_PCI_ALLOC_IRQ
static int ice_alloc_and_fill_msix_entries(struct ice_pf *pf, int nvec)
{
	int i;

	pf->msix_entries = kcalloc(nvec, sizeof(*pf->msix_entries),
				   GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		pf->msix_entries[i].entry = i;
		pf->msix_entries[i].vector = ice_get_irq_num(pf, i);
	}

	return 0;
}
#endif /* HAVE_PCI_ALLOC_IRQ */

#ifndef HAVE_PCI_ALLOC_IRQ
static int ice_alloc_msix_entries(struct ice_pf *pf, u16 num_entries)
{
	u16 i;

	pf->msix_entries = devm_kcalloc(ice_pf_to_dev(pf), num_entries,
					sizeof(*pf->msix_entries), GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		pf->msix_entries[i].entry = i;

	return 0;
}

static void ice_free_msix_entries(struct ice_pf *pf)
{
	devm_kfree(ice_pf_to_dev(pf), pf->msix_entries);
	pf->msix_entries = NULL;
}
#endif /* HAVE_PCI_ALLOC_IRQ */

static void ice_dis_msix(struct ice_pf *pf)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	pci_free_irq_vectors(pf->pdev);
#else
	ice_free_msix_entries(pf);
	pci_disable_msix(pf->pdev);
#endif /* HAVE_PCI_ALLOC_IRQ */
}

static int ice_ena_msix(struct ice_pf *pf, int nvec)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	return pci_alloc_irq_vectors(pf->pdev, ICE_MIN_MSIX, nvec,
				     PCI_IRQ_MSIX);
#else
	int vectors;
	int err;

	err = ice_alloc_msix_entries(pf, nvec);
	if (err)
		return err;

	vectors = pci_enable_msix_range(pf->pdev, pf->msix_entries,
					ICE_MIN_MSIX, nvec);
	if (vectors < 0)
		ice_free_msix_entries(pf);

	return vectors;
#endif /* HAVE_PCI_ALLOC_IRQ */
}

static void ice_adj_vec_clear(int *src, int size)
{
	int i;

	for (i = 0; i < size; i++)
		src[i] = 0;
}

static void ice_adj_vec_sum(int *dst, int *src, int size)
{
	int i;

	for (i = 0; i < size; i++)
		dst[i] += src[i];
}

/*
 * Allow 256 queue pairs for ADQ only if the PF has at least
 * 1024 msix vectors (1 or 2 port NIC).
 * Ensure at least 8 queue pairs for ADQ if the available local
 * node CPU threads are 8 or less for the PF.
 * Otherwise, allocate queue pairs based on the number of online
 * CPUs, but not exceeding ICE_ADQ_MAX_QPS.
 */
static int ice_adq_max_qps(struct ice_pf *pf)
{
	if (pf->hw.func_caps.common_cap.num_msix_vectors >= 1024)
		return ICE_ADQ_MAX_QPS;

	return min_t(int, ICE_ADQ_MAX_QPS,
		max_t(int, num_online_cpus(), MIN_DEFAULT_VECTORS));
}

/**
 * ice_ena_msix_range - request a range of MSI-X vectors from the OS
 * @pf: board private structure
 *
 * The driver tries to enable best-case scenario MSI-X vectors. If that doesn't
 * succeed than adjust to irqs number returned by kernel.
 *
 * The fall-back logic is described below with each [#] represented needed irqs
 * number for the step. If any of the steps is lower than received number, then
 * return the number of MSI-X. If any of the steps is greater, then check next
 * one. If received value is lower than irqs value in last step return error.
 * Please note that for the below steps the value range of num_online_cpus() is
 * normalized to a certain range.
 *
 * Step [0]: Enable the best-case scenario MSI-X vectors.
 *
 * Step [1]: Enable MSI-X vectors with eswitch support disabled
 *
 * Step [2]: Enable MSI-X vectors with the number of vectors reserved for
 * MACVLAN and Scalable IOV support reduced by a factor of 2.
 *
 * Step [3]: Enable MSI-X vectors with the number of vectors reserved for
 * MACVLAN and Scalable IOV support reduced by a factor of 4.
 *
 * Step [4]: Enable MSI-X vectors with MACVLAN and Scalable IOV support
 * disabled.
 *
 * Step [5]: Enable MSI-X vectors with the number of pf->num_lan_msix reduced
 * by a factor of 2 from the previous step (i.e. num_online_cpus() / 2).
 * Also, with the number of pf->num_rdma_msix reduced by a factor of ~2 from the
 * previous step (i.e. num_online_cpus() / 2 + ICE_RDMA_NUM_AEQ_MSIX).
 *
 * Step [6]: Same as step [3], except reduce both by a factor of 4.
 *
 * Step [7]: Enable the bare-minimum MSI-X vectors.
 *
 * Each feature has separate table with needed irqs in each step. Sum of these
 * tables is tracked in adj_vec to show needed irqs in each step. Separate
 * tables are later use to set correct number of irqs for each feature based on
 * choosed step.
 */
static int ice_ena_msix_range(struct ice_pf *pf)
{
#define ICE_ADJ_VEC_STEPS 8
#define ICE_ADJ_VEC_WORST_CASE 0
#define ICE_ADJ_VEC_BEST_CASE (ICE_ADJ_VEC_STEPS - 1)
	struct device *dev = ice_pf_to_dev(pf);
#ifdef HAVE_PF_RING
	int num_local_cpus = (RSS[pf->instance] != 0) ? RSS[pf->instance] :  ice_get_num_local_cpus(dev);
#else
	int num_local_cpus = ice_get_num_local_cpus(dev);
#endif
	int default_rdma_ceq = ice_normalize_cpu_count(num_local_cpus);
	int rdma_adj_vec[ICE_ADJ_VEC_STEPS] = {
		ICE_MIN_RDMA_MSIX,
		default_rdma_ceq / 4 > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq / 4 + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq / 2 > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq / 2 + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
		default_rdma_ceq > ICE_MIN_RDMA_MSIX ?
			default_rdma_ceq + ICE_RDMA_NUM_AEQ_MSIX :
			ICE_MIN_RDMA_MSIX,
	};
	int default_lan_qp = ice_normalize_cpu_count(num_local_cpus);
	int lan_adj_vec[ICE_ADJ_VEC_STEPS] = {
		ICE_MIN_LAN_MSIX,
		max_t(int, default_lan_qp / 4, ICE_MIN_LAN_MSIX),
		max_t(int, default_lan_qp / 2, ICE_MIN_LAN_MSIX),
		max_t(int, default_lan_qp, ICE_MIN_LAN_MSIX),
		max_t(int, default_lan_qp, ICE_MIN_LAN_MSIX),
		max_t(int, default_lan_qp, ICE_MIN_LAN_MSIX),
		max_t(int, default_lan_qp, ICE_MIN_LAN_MSIX),
#if defined(HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT)
		max_t(int, default_lan_qp, ICE_MIN_LAN_MSIX),
#else
		max_t(int, ice_adq_max_qps(pf), ICE_MIN_LAN_MSIX),
#endif /* DEVLINK_SUPPORT && HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
	};
	int fdir_adj_vec[ICE_ADJ_VEC_STEPS] = {
		ICE_FDIR_MSIX, ICE_FDIR_MSIX, ICE_FDIR_MSIX,
		ICE_FDIR_MSIX, ICE_FDIR_MSIX, ICE_FDIR_MSIX,
		ICE_FDIR_MSIX, ICE_FDIR_MSIX,
	};
	int adj_vec[ICE_ADJ_VEC_STEPS] = {
		ICE_OICR_MSIX, ICE_OICR_MSIX, ICE_OICR_MSIX,
		ICE_OICR_MSIX, ICE_OICR_MSIX, ICE_OICR_MSIX,
		ICE_OICR_MSIX, ICE_OICR_MSIX,
	};
#ifdef HAVE_NDO_DFWD_OPS
	int macvlan_adj_vec[ICE_ADJ_VEC_STEPS] = {
		0, 0, 0, 0,
		(ICE_MAX_MACVLANS * ICE_DFLT_VEC_VMDQ_VSI) / 4,
		(ICE_MAX_MACVLANS * ICE_DFLT_VEC_VMDQ_VSI) / 2,
		ICE_MAX_MACVLANS * ICE_DFLT_VEC_VMDQ_VSI,
		ICE_MAX_MACVLANS * ICE_DFLT_VEC_VMDQ_VSI,
	};
#endif /* OFFLOAD_MACVLAN_SUPPORT */
	int eswitch_adj_vec[ICE_ADJ_VEC_STEPS] = {
		0, 0, 0, 0, 0, 0, 0,
		ICE_ESWITCH_MSIX,
	};
	int scalable_adj_vec[ICE_ADJ_VEC_STEPS] = {
		0, 0, 0, 0,
		(ICE_MAX_SCALABLE * ICE_NUM_VF_MSIX_SMALL) / 4,
		(ICE_MAX_SCALABLE * ICE_NUM_VF_MSIX_SMALL) / 2,
		ICE_MAX_SCALABLE * ICE_NUM_VF_MSIX_SMALL,
		ICE_MAX_SCALABLE * ICE_NUM_VF_MSIX_SMALL,
	};
	int adj_step = ICE_ADJ_VEC_BEST_CASE;
	int total_msix = 0;
	int err = -ENOSPC;
	int v_actual, i;
	int needed = 0;

	needed += ICE_OICR_MSIX;

	needed += lan_adj_vec[ICE_ADJ_VEC_BEST_CASE];
	ice_adj_vec_sum(adj_vec, lan_adj_vec, ICE_ADJ_VEC_STEPS);

	if (test_bit(ICE_FLAG_ESWITCH_CAPABLE, pf->flags)) {
		needed += eswitch_adj_vec[ICE_ADJ_VEC_BEST_CASE];
		ice_adj_vec_sum(adj_vec, eswitch_adj_vec, ICE_ADJ_VEC_STEPS);
	} else {
		ice_adj_vec_clear(eswitch_adj_vec, ICE_ADJ_VEC_STEPS);
	}
#ifdef HAVE_NDO_DFWD_OPS

	if (test_bit(ICE_FLAG_VMDQ_ENA, pf->flags)) {
		needed += macvlan_adj_vec[ICE_ADJ_VEC_BEST_CASE];
		ice_adj_vec_sum(adj_vec, macvlan_adj_vec, ICE_ADJ_VEC_STEPS);
	} else {
		ice_adj_vec_clear(macvlan_adj_vec, ICE_ADJ_VEC_STEPS);
	}
#endif /* OFFLOAD_MACVLAN_SUPPORT */

	if (ice_is_aux_ena(pf) && ice_is_rdma_ena(pf)) {
		needed += rdma_adj_vec[ICE_ADJ_VEC_BEST_CASE];
		ice_adj_vec_sum(adj_vec, rdma_adj_vec, ICE_ADJ_VEC_STEPS);
	} else {
		ice_adj_vec_clear(rdma_adj_vec, ICE_ADJ_VEC_STEPS);
	}

	if (test_bit(ICE_FLAG_FD_ENA, pf->flags)) {
		needed += fdir_adj_vec[ICE_ADJ_VEC_BEST_CASE];
		ice_adj_vec_sum(adj_vec, fdir_adj_vec, ICE_ADJ_VEC_STEPS);
	} else {
		ice_adj_vec_clear(fdir_adj_vec, ICE_ADJ_VEC_STEPS);
	}

	if (test_bit(ICE_FLAG_SIOV_CAPABLE, pf->flags)) {
		needed += scalable_adj_vec[ICE_ADJ_VEC_BEST_CASE];
		ice_adj_vec_sum(adj_vec, scalable_adj_vec, ICE_ADJ_VEC_STEPS);
	} else {
		ice_adj_vec_clear(scalable_adj_vec, ICE_ADJ_VEC_STEPS);
	}

	v_actual = ice_ena_msix(pf, needed);
	if (v_actual < 0) {
		err = v_actual;
		goto err;
	} else if (v_actual < adj_vec[ICE_ADJ_VEC_WORST_CASE]) {
		ice_dis_msix(pf);
		goto err;
	}

	for (i = ICE_ADJ_VEC_WORST_CASE + 1; i < ICE_ADJ_VEC_STEPS; i++) {
		if (v_actual < adj_vec[i]) {
			adj_step = i - 1;
			break;
		}
	}
	pf->msix.misc = ICE_OICR_MSIX;
	pf->msix.eth = lan_adj_vec[adj_step];
	total_msix += pf->msix.eth;
	pf->msix.rdma = rdma_adj_vec[adj_step];
	total_msix += pf->msix.rdma;
	if (test_bit(ICE_FLAG_ESWITCH_CAPABLE, pf->flags) &&
	    !eswitch_adj_vec[adj_step]) {
		dev_warn(dev, "Not enough MSI-X for eswitch support, disabling feature\n");
		clear_bit(ICE_FLAG_ESWITCH_CAPABLE, pf->flags);
	}
	pf->msix.misc += eswitch_adj_vec[adj_step];
#ifdef HAVE_NDO_DFWD_OPS
	if (test_bit(ICE_FLAG_VMDQ_ENA, pf->flags) &&
	    !macvlan_adj_vec[adj_step]) {
		dev_warn(dev, "Not enough MSI-X for hardware MACVLAN support, disabling feature\n");
		clear_bit(ICE_FLAG_VMDQ_ENA, pf->flags);
	}
	pf->msix.misc += macvlan_adj_vec[adj_step];
#endif /* HAVE_NDO_DFWD_OPS */
#if defined(HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT)
	pf->max_adq_qps = !ice_is_safe_mode(pf) ? ice_adq_max_qps(pf) : 1;
#else
	pf->max_adq_qps = !ice_is_safe_mode(pf) ? lan_adj_vec[adj_step] : 1;
#endif /* DEVLINK_SUPPORT && HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
	pf->msix.misc += fdir_adj_vec[ICE_ADJ_VEC_BEST_CASE];
	if (test_bit(ICE_FLAG_SIOV_CAPABLE, pf->flags) &&
	    !scalable_adj_vec[adj_step]) {
		dev_warn(dev, "Not enough MSI-X for Scalable IOV support, disabling feature\n");
		clear_bit(ICE_FLAG_SIOV_CAPABLE, pf->flags);
	}
	pf->msix.siov += scalable_adj_vec[adj_step];
	total_msix += pf->msix.siov;
	total_msix += pf->msix.misc;

	return total_msix;

err:
	dev_err(dev, "Failed to enable MSI-X vectors\n");
	return  err;
}

static int ice_ena_msix_req(struct ice_pf *pf)
{
	int vectors = ice_ena_msix(pf, pf->req_msix.all_host);

	if (vectors != pf->req_msix.all_host)
		return -EOPNOTSUPP;

	pf->msix = pf->req_msix;
	return vectors;
}

/**
 * ice_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
int ice_init_interrupt_scheme(struct ice_pf *pf)
{
	int total_vectors = pf->hw.func_caps.common_cap.num_msix_vectors;
	int vectors, max_vectors;

	if (pf->req_msix.all_host)
		vectors = ice_ena_msix_req(pf);
	else
		vectors = ice_ena_msix_range(pf);

	if (vectors < 0)
		return -ENOMEM;

	/* pf->msix_entries is used in idc and needs to be filled on kernel
	 * with new irq alloc API
	 */
#ifdef HAVE_PCI_ALLOC_IRQ
	if (ice_alloc_and_fill_msix_entries(pf, vectors)) {
		ice_dis_msix(pf);
		return -ENOMEM;
	}
#endif /* HAVE_PCI_ALLOC_IRQ */
	/* set up vector assignment tracking */
	if (pci_msix_can_alloc_dyn(pf->pdev))
		max_vectors = total_vectors;
	else
		max_vectors = vectors;

#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	ice_init_irq_tracker(pf, max_vectors, vectors);
#else
	pf->irq_tracker = ice_alloc_res_tracker(max_vectors);
	if (!pf->irq_tracker) {
		ice_dis_msix(pf);
		return -ENOMEM;
	}
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */

	/* populate SW interrupts pool with number of OS granted IRQs. */
	if (!pf->msix.all_host) {
		pf->msix.all_host = (u16)vectors;
		pf->msix.vf = pf->hw.func_caps.common_cap.num_msix_vectors -
			pf->msix.all_host;
		pf->req_msix = pf->msix;
	}

	return 0;
}

/**
 * ice_clear_interrupt_scheme - Undo things done by ice_init_interrupt_scheme
 * @pf: board private structure
 */
void ice_clear_interrupt_scheme(struct ice_pf *pf)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	kfree(pf->msix_entries);
	pf->msix_entries = NULL;

#endif /* PEER_SUPPORT */
	ice_dis_msix(pf);

#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	ice_deinit_irq_tracker(pf);
#else
	kfree(pf->irq_tracker);
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */
}

/**
 * ice_get_irq_num - get system irq number based on index from driver
 * @pf: board private structure
 * @idx: driver irq index
 */
int ice_get_irq_num(struct ice_pf *pf, int idx)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	return pci_irq_vector(pf->pdev, idx);
#else
	if (!pf->msix_entries)
		return -EINVAL;

	return pf->msix_entries[idx].vector;
#endif /* HAVE_PCI_ALLOC_IRQ */
}

/**
 * ice_alloc_irq - Allocate new interrupt vector
 * @pf: board private structure
 * @dyn_only: force dynamic allocation of the interrupt
 *
 * Allocate new interrupt vector for a given owner id.
 * return struct msi_map with interrupt details and track
 * allocated interrupt appropriately.
 *
 * This function reserves new irq entry from the irq_tracker.
 * if according to the tracker information all interrupts that
 * were allocated with ice_pci_alloc_irq_vectors are already used
 * and dynamically allocated interrupts are supported then new
 * interrupt will be allocated with pci_msix_alloc_irq_at.
 *
 * Some callers may only support dynamically allocated interrupts.
 * This is indicated with dyn_only flag.
 *
 * On failure, return map with negative .index. The caller
 * is expected to check returned map index.
 *
 */
struct msi_map ice_alloc_irq(struct ice_pf *pf, bool dyn_only)
{
	struct msi_map map = { .index = -ENOENT };
#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_irq_entry *entry;

	entry = ice_get_irq_res(pf, dyn_only);
	if (!entry)
		return map;

	/* fail if we're about to violate SRIOV vectors space */
	if (pf->sriov_base_vector && entry->index >= pf->sriov_base_vector)
		goto exit_free_res;

	if (pci_msix_can_alloc_dyn(pf->pdev) && entry->dynamic) {
		map = pci_msix_alloc_irq_at(pf->pdev, entry->index, NULL);
		if (map.index < 0)
			goto exit_free_res;
		dev_dbg(dev, "allocated new irq at index %d\n", map.index);
	} else {
		map.index = entry->index;
		map.virq = ice_get_irq_num(pf, map.index);
	}

	return map;

exit_free_res:
	dev_err(dev, "Could not allocate irq at idx %d\n", entry->index);
	ice_free_irq_res(pf, entry->index);
	return map;
#else
	int entry;

	entry = ice_get_res(pf, pf->irq_tracker, 1, 0);
	if (entry < 0)
		return map;

	map.index = entry;
	map.virq = ice_get_irq_num(pf, map.index);

	return map;
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */
}

/**
 * ice_free_irq - Free interrupt vector
 * @pf: board private structure
 * @map: map with interrupt details
 *
 * Remove allocated interrupt from the interrupt tracker. If interrupt was
 * allocated dynamically, free respective interrupt vector.
 */
void ice_free_irq(struct ice_pf *pf, struct msi_map map)
{
#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	struct ice_irq_entry *entry;

	entry = xa_load(&pf->irq_tracker.entries, map.index);

	if (!entry) {
		dev_err(ice_pf_to_dev(pf), "Failed to get MSIX interrupt entry at index %d",
			map.index);
		return;
	}

	dev_dbg(ice_pf_to_dev(pf), "Free irq at index %d\n", map.index);

	if (entry->dynamic)
		pci_msix_free_irq(pf->pdev, map);

	ice_free_irq_res(pf, map.index);
#else
	if (map.index < pf->irq_tracker->end)
		pf->irq_tracker->list[map.index] = 0;
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */
}

/**
 * ice_get_max_used_msix_vector - Get the max used interrupt vector
 * @pf: board private structure
 *
 * Return index of maximum used interrupt vectors with respect to the
 * beginning of the MSIX table. Take into account that some interrupts
 * may have been dynamically allocated after MSIX was initially enabled.
 */
int ice_get_max_used_msix_vector(struct ice_pf *pf)
{
#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	unsigned long start, index, max_idx;
	void *entry;

	/* Treat all preallocated interrupts as used */
	start = pf->irq_tracker.num_static;
	max_idx = start - 1;

	xa_for_each_start(&pf->irq_tracker.entries, index, entry, start) {
		if (index > max_idx)
			max_idx = index;
	}

	return max_idx;
#else
	return pf->irq_tracker->num_entries;
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */
}

/**
 * ice_alloc_aux_vectors - Allocate vector resources for AUX/peer driver
 * @pf: board private structure to initialize
 * @count: number of interrupts to allocate for the aux device
 */
struct msix_entry *
ice_alloc_aux_vectors(struct ice_pf *pf, int count)
{
	struct msix_entry *msix_entries;
	int i;

	msix_entries = kcalloc(count, sizeof(struct msix_entry), GFP_KERNEL);
	if (!msix_entries)
		return NULL;

	for (i = 0; i < count; i++) {
		struct msix_entry *entry = &msix_entries[i];
		struct msi_map map;

		map = ice_alloc_irq(pf, false);
		if (map.index < 0)
			break;

		entry->entry = map.index;
		entry->vector = map.virq;
	}

	return msix_entries;
}

/**
 * ice_free_aux_vectors - Free vector resources for AUX/peer driver
 * @pf: board private structure to initialize
 * @count: number of interrupts to allocate for the aux device
 * @msix_entries: msix_entries array
 */
void
ice_free_aux_vectors(struct ice_pf *pf, struct msix_entry *msix_entries,
		     int count)
{
	int i;

	if (!msix_entries)
		return;

	for (i = 0; i < count; i++) {
		struct msi_map map;

		map.index = msix_entries[i].entry;
		map.virq = msix_entries[i].vector;
		ice_free_irq(pf, map);
	}

	kfree(msix_entries);
}
