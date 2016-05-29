/* Intel(R) Ethernet Switch Host Interface Driver
 * Copyright(c) 2013 - 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 */

#include "fm10k.h"

static inline struct fm10k_intfc *to_fm10k_intfc(struct uio_info *uio)
{
	return container_of(uio, struct fm10k_intfc, uio);
}

static irqreturn_t fm10k_msix_uio(int __always_unused irq, void *data)
{
	struct uio_info *uio = (struct uio_info *)data;

	/* clear the interrupt notification */
	fm10k_write_reg(&to_fm10k_intfc(uio)->hw, FM10K_EICR,
			FM10K_EICR_SWITCHINTERRUPT);

	uio_event_notify(uio);

	return IRQ_HANDLED;
}

/**
 *  fm10k_uio_set_irq - enable or disable uio irq
 **/
static void fm10k_uio_set_irq(struct fm10k_intfc *interface, bool on)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	struct fm10k_hw *hw = &interface->hw;
	u32 itr = FM10K_ITR_AUTOMASK;

	itr |= on ? FM10K_ITR_MASK_CLEAR : FM10K_ITR_MASK_SET;

	fm10k_write_reg(hw, FM10K_ITR(entry->entry), itr);
}

/**
 *  fm10k_uio_irq_task - manages the UIO irq out of band
 *  @work: pointer to work_struct containing data
 *
 *  This work item is called by the uio_irqcontrol, to enable the interrupt
 *  request. We do it out of band so that we can re-arm ourselves until the
 *  device isn't resetting. This ensures that reset (which clears our
 *  interrupt and re-enables us) doesn't race with us.
 **/
static void fm10k_uio_irq_task(struct work_struct *work)
{
	struct fm10k_intfc *interface;

	interface = container_of(work, struct fm10k_intfc, uio_task);

	/* if the interface is resetting, just re-queue */
	if (test_bit(__FM10K_RESETTING, &interface->state)) {
		queue_work(fm10k_workqueue, &interface->uio_task);
		return;
	}

	/* we aren't resetting, so we can arm the interrupt */
	fm10k_uio_set_irq(interface, interface->uio_int_enable);
}

static int fm10k_uio_irqcontrol(struct uio_info *uio, s32 irq_on)
{
	struct fm10k_intfc *interface = to_fm10k_intfc(uio);

	/* save the interrupt state for later */
	interface->uio_int_enable = irq_on ? true : false;

	/* queue our task to enable the interrupt */
	queue_work(fm10k_workqueue, &interface->uio_task);

	return 0;
}

int fm10k_uio_request_irq(struct fm10k_intfc *interface)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	int err;

	if (!(interface->flags & FM10K_UIO_REGISTERED))
		return 0;

	/* request the IRQ */
	err = request_irq(entry->vector, fm10k_msix_uio, 0, uio->name, uio);
	if (err)
		return err;

	/* restore the interrupt state */
	fm10k_uio_set_irq(interface, interface->uio_int_enable);

	/* enable interrupt with no moderation */
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_IMMEDIATE | entry->entry);

	/* Enable bits in EIMR register */
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_ENABLE(SWITCHINTERRUPT));

	return 0;
}

void fm10k_uio_free_irq(struct fm10k_intfc *interface)
{
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	struct msix_entry *entry;

	if (!(interface->flags & FM10K_UIO_REGISTERED))
		return;

	/* no uio IRQ to free if MSI-X is not enabled */
	if (!interface->msix_entries)
		return;

	entry = &interface->msix_entries[FM10K_UIO_VECTOR];

	/* Disable bits in EIMR register */
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_DISABLE(SWITCHINTERRUPT));

	/* disable the interrupt */
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_DISABLE);

	/* mask interrupt to prevent any remaining events */
	fm10k_write_reg(hw, FM10K_ITR(entry->entry), FM10K_ITR_MASK_SET);

	/* flush disables to guarantee no further interrupts */
	fm10k_write_flush(hw);

	/* free the IRQ */
	free_irq(entry->vector, uio);
}

int fm10k_uio_probe(struct fm10k_intfc *interface)
{
	struct msix_entry *entry = &interface->msix_entries[FM10K_UIO_VECTOR];
	struct uio_info *uio = &interface->uio;
	struct fm10k_hw *hw = &interface->hw;
	int err;

	/* Verify if BAR4 access is allowed, if not do nothing */
	if (!interface->sw_addr)
		return 0;

	/* initialize uio task */
	INIT_WORK(&interface->uio_task, fm10k_uio_irq_task);

	/* set driver name and version */
	uio->name = fm10k_driver_name;
	uio->version = fm10k_driver_version;

	/* We handle the IRQs so set the irq type to custom */
	uio->irq = UIO_IRQ_CUSTOM;

	/* add basic controls for mapping memory and controlling interrupts */
	uio->irqcontrol = fm10k_uio_irqcontrol;

	/* Add BAR4 as a region to be memory mapped */
	uio->mem[0].addr = pci_resource_start(interface->pdev, 4);
	uio->mem[0].size = pci_resource_len(interface->pdev, 4);
	uio->mem[0].internal_addr = interface->sw_addr;
	uio->mem[0].memtype = UIO_MEM_PHYS;

	/* register UIO device */
	err = uio_register_device(&interface->pdev->dev, uio);
	if (err)
		return err;

	/* add MSI-X interrupt configuration */
	err = request_irq(interface->msix_entries[FM10K_UIO_VECTOR].vector,
			  fm10k_msix_uio, 0, uio->name, uio);
	if (err) {
		uio_unregister_device(uio);
		return err;
	}

	/* start interrupt with vector masked */
	interface->uio_int_enable = false;
	fm10k_uio_set_irq(interface, interface->uio_int_enable);

	/* enable interrupt with no moderation */
	fm10k_write_reg(hw, FM10K_INT_MAP(fm10k_int_switch_event),
			FM10K_INT_MAP_IMMEDIATE | entry->entry);

	/* Enable bits in EIMR register */
	fm10k_write_reg(hw, FM10K_EIMR, FM10K_EIMR_ENABLE(SWITCHINTERRUPT));

	interface->flags |= FM10K_UIO_REGISTERED;

	return 0;
}

void fm10k_uio_remove(struct fm10k_intfc *interface)
{
	struct uio_info *uio = &interface->uio;

	if (!(interface->flags & FM10K_UIO_REGISTERED))
		return;

	fm10k_uio_free_irq(interface);
	uio_unregister_device(uio);

	cancel_work_sync(&interface->uio_task);
}
