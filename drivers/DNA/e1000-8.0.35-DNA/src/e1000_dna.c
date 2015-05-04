/*
 *
 * (C) 2008-12 - Luca Deri <deri@ntop.org>
 * (C) 2011-12 - Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define MAX_NUM_ADAPTERS       16

#define DEBUG

static char *adapters_to_enable[MAX_NUM_ADAPTERS] = { 0 };
module_param_array(adapters_to_enable, charp, NULL, 0444);
MODULE_PARM_DESC(adapters_to_enable,
		 "Comma separated list of adapters (MAC address) where DNA "
		 "will be enabled");

static unsigned int enable_debug = 0;
module_param(enable_debug, uint, 0644);
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable DNA debug tracing into the syslog");

/* Forward */
static void e1000_irq_enable(struct e1000_adapter *adapter);
static void e1000_irq_disable(struct e1000_adapter *adapter);

/* ****************************** */

void dna_check_enable_adapter(struct e1000_adapter *adapter) {
  //  struct pfring_hooks *hook = (struct pfring_hooks*)adapter->netdev->pfring_ptr;

  adapter->dna.dna_enabled = 0; /* Default */

  /*  if(hook && (hook->magic == PF_RING)) */ {
    if(adapters_to_enable[0] == NULL) {
      /* We enable all the adapters */
      adapter->dna.dna_enabled = 1;
    } else {
      int i = 0;

      while((i < MAX_NUM_ADAPTERS) && (adapters_to_enable[i] != NULL)) {
	u8 addr[ETH_ALEN];

	if(sscanf(adapters_to_enable[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		  &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]) == 6
	   && !memcmp(addr, adapter->hw.mac.addr, sizeof(addr))) {
	  adapter->dna.dna_enabled = 1;
	  break;
	}

	i++;
      } /* while */
    }
  }
}

/* ****************************** */

void reserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

/* ****************************** */

void unreserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

/* ********************************** */

static unsigned long alloc_contiguous_memory(u_int *tot_mem_len,
					     u_int *mem_order) {
  unsigned long mem;

  if(unlikely(enable_debug)) printk("[DNA] alloc_contiguous_memory(%d)\n", *tot_mem_len);

  *mem_order = get_order(*tot_mem_len);
  *tot_mem_len = PAGE_SIZE << *mem_order;

  mem = __get_free_pages(GFP_ATOMIC, *mem_order);

  if(mem) {
    if(unlikely(enable_debug))
      printk("[DNA] alloc_contiguous_memory: success (%d,%lu,%d)\n",
	     *tot_mem_len, mem, *mem_order);
    reserve_memory(mem, *tot_mem_len);
  } else {
    if(unlikely(enable_debug))
      printk("[DNA] alloc_contiguous_memory: failure (len=%d,order=%d)\n",
	     *tot_mem_len, *mem_order);
  }

  return(mem);
}

/* ********************************** */

static void free_contiguous_memory(unsigned long mem,
				   u_int tot_mem_len,
				   u_int mem_order) {
  if(unlikely(enable_debug))
    printk("[DNA] free_contiguous_memory(%lu,%d,%d)\n",
	   mem, tot_mem_len, mem_order);

  if(mem != 0) {
    unreserve_memory(mem, tot_mem_len);
    free_pages(mem, mem_order);
  }
}

/* ********************************** */

void init_dna(struct e1000_adapter *adapter) {
  init_waitqueue_head(&adapter->dna.packet_waitqueue);
}

/* ********************************** */

void notify_function_ptr(void *rx_data, void *tx_data, u_int8_t device_in_use) {
  /* struct e1000_adapter *adapter = (struct e1000_adapter*)data; */ /* Just in case */

  if(device_in_use)
    try_module_get(THIS_MODULE); /* ++ */
  else
    module_put(THIS_MODULE);     /* -- */
}

/* ********************************** */

int wait_packet_function_ptr(void *data, int mode) {
  struct e1000_adapter *adapter = (struct e1000_adapter*)data;

  // if(unlikely(enable_debug)) printk("[wait_packet_function_ptr] called [mode=%d]\n", mode);

  if(mode == 1) {
    struct e1000_rx_ring *rx_ring = adapter->rx_ring;
    struct e1000_rx_desc *rx_desc, *next_rx_desc;
    int ret;

    u16 i = E1000_READ_REG(&adapter->hw, E1000_RDT(0));
    
    /* Very important: update the value from the register set from userland.
     * Here i is the last I've read (zero-copy implementation) */
    if(++i == rx_ring->count) i = 0;
    /* Here i is the next I have to read */
    
    rx_ring->next_to_clean = i;

    rx_desc = E1000_RX_DESC(*rx_ring, rx_ring->next_to_clean);
    ret = rx_desc->status & E1000_RXD_STAT_DD;

    /* trick for appplications calling poll/select directly (indexes not in sync of one position at most) */
    if (!ret) {
      u16 next_i = i;
      if(++next_i == rx_ring->count) next_i = 0;
      next_rx_desc = E1000_RX_DESC(*rx_ring, next_i);
      ret = next_rx_desc->status & E1000_RXD_STAT_DD;
    }

    if(unlikely(enable_debug))
      printk("[wait_packet_function_ptr] Check if a packet is arrived [slotId=%u][status=%u][ret=%u]\n",
	     rx_ring->next_to_clean, rx_desc->status, ret);

    if(rx_desc->status & E1000_RXD_STAT_DD) {
      adapter->dna.interrupt_received = 0;

#if 0
      if(!adapter->dna.interrupt_enabled) {
	e1000_irq_enable(adapter), adapter->dna.interrupt_enabled = 1;
	if(unlikely(enable_debug)) printk("[wait_packet_function_ptr] Packet not arrived yet: enabling interrupts\n");
      }
#endif
    } else {
      /* Uncommenting the line below cause the cpu to raise up */
      // adapter->dna.interrupt_received = 1;
    }

    return(ret);
  } else {
    if(adapter->dna.interrupt_enabled) {
      e1000_irq_disable(adapter);
      adapter->dna.interrupt_enabled = 0;
      if(unlikely(enable_debug)) printk("[wait_packet_function_ptr] Disabled interrupts\n");
    }

    return(0);
  }
}

/* ***************************************************************** */

static bool dna_e1000_clean_rx_irq(struct e1000_adapter *adapter,
				   struct e1000_rx_ring *rx_ring,
				   int *work_done) {
  bool ret;
  int i, debug = 0;
  struct e1000_rx_desc *rx_desc;
  struct e1000_rx_buffer *buffer_info;
  struct e1000_hw *hw = &adapter->hw;

  /* The register contains the last packet that we have read */
  i = E1000_READ_REG(hw, E1000_RDT(0));
  if(++i == rx_ring->count)
    i = 0;

  rx_ring->next_to_clean = i;

  rx_desc = E1000_RX_DESC(*rx_ring, i);
  buffer_info = &rx_ring->buffer_info[i];

  if(debug)
    printk(KERN_INFO
	   "DNA: dna_e1000_clean_rx_irq(%s)[id=%d][status=%d][rx_reg=%u][buffer_addr=%lu]\n",
	   adapter->netdev->name, i, rx_desc->status,
	   E1000_READ_REG(&adapter->hw, E1000_RDT(0)),
	   (long unsigned int)rx_desc->buffer_addr);

  if(rx_desc->status & E1000_RXD_STAT_DD) {
    if(!adapter->dna.interrupt_received) {
      if(waitqueue_active(&adapter->dna.packet_waitqueue)) {
	wake_up_interruptible(&adapter->dna.packet_waitqueue);
	adapter->dna.interrupt_received = 1;

	if(debug)
	  printk(KERN_WARNING "DNA: dna_e1000_clean_rx_irq(%s): "
		 "woken up [slot=%d] XXXX\n", adapter->netdev->name, i);

      }
    }

    if(debug)
      printk(KERN_WARNING "DNA: dna_e1000_clean_rx_irq(%s): "
	     "woken up [slot=%d][interrupt_received=%d]\n",
	     adapter->netdev->name, i, adapter->dna.interrupt_received);

    ret = FALSE;
  } else
    ret = TRUE;

  return(ret);
}

/* ***************************************************************** */

void alloc_dna_memory(struct e1000_adapter *adapter) {
  struct net_device *netdev = adapter->netdev;
  struct pci_dev *pdev = adapter->pdev;
  struct e1000_rx_ring *rx_ring = adapter->rx_ring;
  struct e1000_tx_ring *tx_ring = adapter->tx_ring;
  struct e1000_tx_desc *tx_desc, *shadow_tx_desc;
  struct pfring_hooks *hook = (struct pfring_hooks*)netdev->pfring_ptr;
  struct e1000_rx_desc *rx_desc, *shadow_rx_desc;
  struct e1000_rx_buffer *buffer_rx_info;
  struct e1000_buffer    *buffer_tx_info;
  u16 cache_line_size;
  struct sk_buff *skb;
  unsigned int i;
  int cleaned_count = rx_ring->count; /* Allocate all slots in one shot */
  unsigned int bufsz = adapter->rx_buffer_len;
  mem_ring_info         rx_info = {0};
  mem_ring_info         tx_info = {0};
  int                   num_slots_per_page;

  /* Buffers are allocated all in one shot so we'll pass here once */
#if 0
  printk("[DNA] e1000_alloc_rx_buffers(cleaned_count=%d)[%s][slot len=%u/%u]\n",
	 cleaned_count, adapter->netdev->name,
	 bufsz, adapter->max_hw_frame_size);
#endif

  if(hook && (hook->magic == PF_RING)) {
    if(adapter->dna.rx_packet_memory[0] == 0) {
      pci_read_config_word(adapter->pdev,
			   0x0C /* Conf. Space Cache Line Size offset */,
			   &cache_line_size);
      cache_line_size *= 2; /* word (2-byte) to bytes */

      if(cache_line_size == 0) cache_line_size = 64;

      if (0)
	printk("[DNA] Cache line size is %u bytes\n", cache_line_size);

      adapter->dna.packet_slot_len  = ALIGN(bufsz, cache_line_size);
      adapter->dna.packet_num_slots = cleaned_count;

      adapter->dna.tot_packet_memory = PAGE_SIZE << DNA_MAX_CHUNK_ORDER;

      num_slots_per_page = adapter->dna.tot_packet_memory / adapter->dna.packet_slot_len;

      adapter->dna.num_memory_pages = (adapter->dna.packet_num_slots + num_slots_per_page-1) / num_slots_per_page;

      if(0)
	printk("[DNA] Allocating memory [%u slots][%u memory pages][tot_packet_memory %u bytes]\n",
	       adapter->dna.packet_num_slots, adapter->dna.num_memory_pages, adapter->dna.tot_packet_memory);

      for(i=0; i<adapter->dna.num_memory_pages; i++) {
	adapter->dna.rx_packet_memory[i] =
	  alloc_contiguous_memory(&adapter->dna.tot_packet_memory, &adapter->dna.mem_order);

	if(adapter->dna.rx_packet_memory[i] != 0) {
	  if(0)
	    printk("[DNA]  Successfully allocated %lu bytes at "
		   "0x%08lx [slot_len=%d]\n",
		   (unsigned long) adapter->dna.tot_packet_memory,
		   (unsigned long) adapter->dna.rx_packet_memory[i],
		   adapter->dna.packet_slot_len);
	} else {
	  printk("[DNA]  ERROR: not enough memory for DMA ring\n");
	  return;
	}
      }

      for(i=0; i<cleaned_count; i++) {
	u_int page_index, offset;

	page_index = i / num_slots_per_page;
	offset = (i % num_slots_per_page) * adapter->dna.packet_slot_len;
	skb = (struct sk_buff *)(adapter->dna.rx_packet_memory[page_index] + offset);

#ifdef DEBUG
	if(0)
	  printk("[DNA] Allocating slot %d of %d [addr=%p][page_index=%u][offset=%u]\n",
		 i, adapter->dna.packet_num_slots, skb, page_index, offset);
#endif

	buffer_rx_info = &rx_ring->buffer_info[i];
	buffer_rx_info->skb = skb;
	buffer_rx_info->page = NULL;
	buffer_rx_info->dma = dma_map_single(pci_dev_to_dev(adapter->pdev),
					     skb,
					     adapter->rx_buffer_len,
					     DMA_FROM_DEVICE);

#ifdef DEBUG
	if(0)
	  printk("[DNA] Mapping buffer %d [ptr=%llu][len=%d]\n",
		 i, buffer_rx_info->dma, adapter->dna.packet_slot_len);
#endif

	rx_desc = E1000_RX_DESC(*rx_ring, i);
	rx_desc->buffer_addr = cpu_to_le64(buffer_rx_info->dma);
	rx_desc->status = 0;
	rx_desc->errors = 0;

	shadow_rx_desc = E1000_RX_DESC(*rx_ring, i + rx_ring->count);
	memcpy(shadow_rx_desc, rx_desc, sizeof(struct e1000_rx_desc));
      }

      wmb();

      // writel(rx_ring->count-1, adapter->hw.hw_addr + rx_ring->rdt);
      // E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), rx_ring->next_to_clean);

      /* The statement below syncs the value of tail (next to read) to 
       * count-1 instead of 0 for zero-copy (one slot back) */
      E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), rx_ring->count-1);

      e1000_irq_disable(adapter);
      //e1000_irq_enable(adapter);

      /* TX */
      if(adapter->dna.tx_packet_memory[0] == 0) {
	for(i=0; i<adapter->dna.num_memory_pages; i++) {
	  adapter->dna.tx_packet_memory[i] =
	    alloc_contiguous_memory(&adapter->dna.tot_packet_memory, &adapter->dna.mem_order);

	  if(adapter->dna.tx_packet_memory[i] != 0) {
	    if(0)
	      printk("[DNA] [TX] Successfully allocated %lu bytes at "
		     "0x%08lx [slot_len=%d]\n",
		     (unsigned long) adapter->dna.tot_packet_memory,
		     (unsigned long) adapter->dna.rx_packet_memory[i],
		     adapter->dna.packet_slot_len);
	  } else {
	    printk("[DNA]  ERROR: not enough memory for DMA ring\n");
	    return;
	  }
	}

	for(i=0; i<cleaned_count; i++) {
	  u_int page_index, offset;

	  page_index = i / num_slots_per_page;
	  offset = (i % num_slots_per_page) * adapter->dna.packet_slot_len;
	  skb = (struct sk_buff *)(adapter->dna.tx_packet_memory[page_index] + offset);

	  if(0)
	    printk("[DNA] [TX] Allocating slot %d of %d [addr=%p][page_index=%u][offset=%u]\n",
		   i, adapter->dna.packet_num_slots, skb, page_index, offset);

	  buffer_tx_info = &tx_ring->buffer_info[i];
	  buffer_tx_info->skb = skb;
	  buffer_tx_info->length = adapter->rx_buffer_len;
	  buffer_tx_info->dma = dma_map_single(pci_dev_to_dev(adapter->pdev), skb,
					       buffer_tx_info->length,
					       DMA_TO_DEVICE);

#if 0
	  printk("[DNA] Mapping buffer %d [ptr=%p][len=%d]\n",
		 i, (void*)buffer_tx_info->dma, adapter->dna.packet_slot_len);
#endif

	  tx_desc = E1000_TX_DESC(*tx_ring, i);
	  tx_desc->buffer_addr = cpu_to_le64(buffer_tx_info->dma);

	  /* Note that shadows are useless for e1000e with standard DNA, but used by libzero */
	  shadow_tx_desc = E1000_TX_DESC(*tx_ring, i + tx_ring->count); 
	  memcpy(shadow_tx_desc, tx_desc, sizeof(struct e1000_tx_desc));
	}
      }

      rx_info.packet_memory_num_chunks    = adapter->dna.num_memory_pages;
      rx_info.packet_memory_chunk_len     = adapter->dna.tot_packet_memory;
      rx_info.packet_memory_num_slots     = adapter->dna.packet_num_slots;
      rx_info.packet_memory_slot_len      = adapter->dna.packet_slot_len;
      rx_info.descr_packet_memory_tot_len = 2 * rx_ring->size;

      tx_info.packet_memory_num_chunks    = adapter->dna.num_memory_pages;
      tx_info.packet_memory_chunk_len     = adapter->dna.tot_packet_memory;
      tx_info.packet_memory_num_slots     = adapter->dna.packet_num_slots;
      tx_info.packet_memory_slot_len      = adapter->dna.packet_slot_len;
      tx_info.descr_packet_memory_tot_len = 2 * tx_ring->size;

      /* Register with PF_RING */
      hook->zc_dev_handler(add_device_mapping,
				    dna_driver,
  				    &rx_info,
				    &tx_info,
				    adapter->dna.rx_packet_memory,
				    rx_ring->desc,
				    adapter->dna.tx_packet_memory,
				    tx_ring->desc, /* Packet descriptors */
				    (void*)pci_resource_start(adapter->pdev, BAR_0),
				    pci_resource_len(adapter->pdev, BAR_0),
				    0, /* Channel Id */
				    netdev,
				    &pdev->dev,
				    intel_e1000,
				    adapter->netdev->dev_addr,
				    &adapter->dna.packet_waitqueue,
				    &adapter->dna.interrupt_received,
				    (void*)adapter, NULL,
				    wait_packet_function_ptr,
				    notify_function_ptr);

      if(0) {
	printk("[DNA] Enabled DNA on %s (rx len=%u, tx len=%u)\n",
	       adapter->netdev->name, rx_ring->size, tx_ring->size);
      }
    } else {
      printk("WARNING e1000_alloc_rx_buffers(cleaned_count=%d)"
	     "[%s] already allocated\n",
	     cleaned_count, adapter->netdev->name);

    }
  }
}

