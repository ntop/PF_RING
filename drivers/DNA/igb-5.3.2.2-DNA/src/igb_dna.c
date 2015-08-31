/*
 *
 * (C) 2008-11 - Luca Deri <deri@ntop.org>
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

char *adapters_to_enable[MAX_NUM_ADAPTERS] = { 0 };
module_param_array(adapters_to_enable, charp, NULL, 0444);
MODULE_PARM_DESC(adapters_to_enable,
		 "Comma separated list of adapters (MAC address) where DNA "
		 "will be enabled");

static unsigned int enable_debug = 0;
module_param(enable_debug, uint, 0644);
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable DNA debug tracing into the syslog");

static unsigned int mtu = 1500;
module_param(mtu, uint, 0644);
MODULE_PARM_DESC(mtu, "Change the default Maximum Transmission Unit");

static unsigned int num_rx_slots = DNA_IGB_DEFAULT_RXD;
module_param(num_rx_slots, uint, 0644);
MODULE_PARM_DESC(num_rx_slots, "Specify the number of RX slots. Default: 2048");

static unsigned int num_tx_slots = DNA_IGB_DEFAULT_TXD;
module_param(num_tx_slots, uint, 0644);
MODULE_PARM_DESC(num_tx_slots, "Specify the number of TX slots. Default: 2048");

/* Forward */
static void igb_irq_enable(struct igb_adapter *adapter);
static void igb_irq_disable(struct igb_adapter *adapter);

/* ****************************** */

void dna_check_enable_adapter(struct igb_adapter *adapter) {
  adapter->dna.dna_enabled = 0; /* Default */
  
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

/* ****************************** */

void igb_irq_enable_queues(struct igb_adapter *adapter, u32 queue_id) {
  /* TODO - handle queue_id */
  // void igb_ring_irq_enable(struct igb_q_vector *q_vector)
  igb_irq_enable(adapter);
}

/* ****************************** */

void igb_irq_disable_queues(struct igb_adapter *adapter, u32 queue_id) {
  /* TODO */
  igb_irq_disable(adapter);
}

/* ****************************** */

void reserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  // if(unlikely(enable_debug)) printk("[DNA] reserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

/* ****************************** */

void unreserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  // if(unlikely(enable_debug)) printk("[DNA] unreserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

/* ********************************** */

static unsigned long alloc_contiguous_memory(u_int *tot_mem_len, u_int *mem_order) {
  unsigned long mem;

  if(unlikely(enable_debug)) printk("[DNA] alloc_contiguous_memory(%d)\n", *tot_mem_len);

  *mem_order = get_order(*tot_mem_len);
  *tot_mem_len = PAGE_SIZE << *mem_order;

  mem = __get_free_pages(GFP_ATOMIC, *mem_order);

  if(mem) {
    if(unlikely(enable_debug))
      printk("[DNA] alloc_contiguous_memory: success (%d,0x%08lx,%d)\n",
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
				   u_int tot_mem_len, u_int mem_order) {
  if(unlikely(enable_debug))
    printk("[DNA] free_contiguous_memory(0x%08lx,%u,%d)\n",
	   mem, tot_mem_len, mem_order);

  if(mem != 0) {
    unreserve_memory(mem, tot_mem_len);
    free_pages(mem, mem_order);
  }
}

/* ********************************** */

static void print_adv_rx_descr(union e1000_adv_rx_desc	*descr) {
  if(likely(!enable_debug)) return;

  return; // FIX

  printk("[hdr_addr 0x%llx][pkt_addr 0x%llx]\n",
	 le64_to_cpu(descr->read.hdr_addr),
	 le64_to_cpu(descr->read.pkt_addr));
  printk("  stat_err 0x%x\n", le32_to_cpu(descr->wb.upper.status_error));
  printk("  length   %d\n", le16_to_cpu(descr->wb.upper.length));
  printk("  vlan     %d\n", le16_to_cpu(descr->wb.upper.vlan));
  printk("  pkt_info 0x%x\n",
	 le16_to_cpu(descr->wb.lower.lo_dword.hs_rss.pkt_info));
  printk("  hdr_info 0x%x\n",
	 le16_to_cpu(descr->wb.lower.lo_dword.hs_rss.hdr_info));
  printk("  ip_id    0x%x\n",
	 le16_to_cpu(descr->wb.lower.hi_dword.csum_ip.ip_id));
  printk("  csum     0x%x\n",
	 le16_to_cpu(descr->wb.lower.hi_dword.csum_ip.csum));
}

/* ********************************** */

zc_dev_model dna_model(struct e1000_hw *hw){
  switch (hw->mac.type) {
    case e1000_82580:
    case e1000_i350:
      return intel_igb_82580;
    default:
      return intel_igb;
  }
}

/* ********************************** */

#if 0 /* Currently ring cleanup happens in userspace */

void dna_cleanup_rx_ring(struct igb_ring *rx_ring) {
  struct igb_adapter	  *adapter = netdev_priv(rx_ring->netdev);
  struct e1000_hw	  *hw = &adapter->hw;
  union e1000_adv_rx_desc *rx_desc, *shadow_rx_desc;
  u32 head = E1000_READ_REG(hw, E1000_RDH(rx_ring->reg_idx));
  u32 tail;
  
  /*
  tail = E1000_READ_REG(hw, E1000_RDT(rx_ring->reg_idx))
  u32 count = rx_ring->count;
  
  if(unlikely(enable_debug))
    printk("[DNA] dna_cleanup_rx_ring(%d): [head=%u][tail=%u]\n", rx_ring->queue_index, head, tail);

  // We now point to the next slot where packets will be received
  if(++tail == rx_ring->count) tail = 0;

  while(count > 0) {
    if(tail == head) break; // Do not go beyond head

    rx_desc = IGB_RX_DESC(rx_ring, tail);
    shadow_rx_desc = IGB_RX_DESC(rx_ring, tail + rx_ring->count);
    
    if(rx_desc->wb.upper.status_error != 0) {
      print_adv_rx_descr(rx_desc);
      break;
    }

    // Writeback
    rx_desc->wb.upper.status_error = 0;
    rx_desc->read.hdr_addr = shadow_rx_desc->read.hdr_addr, rx_desc->read.pkt_addr = shadow_rx_desc->read.pkt_addr;
    E1000_WRITE_REG(hw, E1000_RDT(rx_ring->reg_idx), tail);

    if(unlikely(enable_debug))
      printk("[DNA] dna_cleanup_rx_ring(%d): idx=%d\n", rx_ring->queue_index, tail);

    if(++tail == rx_ring->count) tail = 0;
    count--;
  }
  */


  /* resetting all */

  for (i=0; i<rx_ring->count; i++) {
    rx_desc = IGB_RX_DESC(rx_ring, i);
    shadow_rx_desc = IGB_RX_DESC(rx_ring, i + rx_ring->count);

    rx_desc->wb.upper.status_error = 0;
    rx_desc->read.hdr_addr = shadow_rx_desc->read.hdr_addr;
    rx_desc->read.pkt_addr = shadow_rx_desc->read.pkt_addr;
  }

  if (head == 0) tail = rx_ring->count - 1;
  else tail = head - 1;

  E1000_WRITE_REG(hw, E1000_RDT(rx_ring->reg_idx), tail);
}

/* ********************************** */

void dna_cleanup_tx_ring(struct ixgbe_ring *tx_ring) {
  struct igb_adapter	  *adapter = netdev_priv(tx_ring->netdev);
  struct e1000_hw	  *hw = &adapter->hw;
  union e1000_adv_tx_desc *tx_desc, *shadow_tx_desc;
  u32 tail;
  u32 head = E1000_READ_REG(hw, E1000_TDH(tx_ring->reg_idx));
  u32 i;

  /* resetting all */
  for (i=0; i<tx_ring->count; i++) {
    tx_desc = IGB_TX_DESC(tx_ring, i);
    shadow_tx_desc = IGB_TX_DESC(tx_ring, i + tx_ring->count);

    tx_desc->read.olinfo_status = 0;
    tx_desc->read.buffer_addr = shadow_tx_desc->read.buffer_addr;
  }

  tail = head; //(head + 1) % tx_ring->count;

  E1000_WRITE_REG(hw, E1000_TDT(tx_ring->reg_idx), tail);
}

#endif

/* ********************************** */

void notify_function_ptr(void *rx_data, void *tx_data, u_int8_t device_in_use) {
  struct igb_ring	*rx_ring = (struct igb_ring *) rx_data;
  struct igb_ring	*tx_ring = (struct igb_ring *) tx_data;
  struct igb_ring	*xx_ring = (rx_ring != NULL) ? rx_ring : tx_ring;
  struct igb_adapter	*adapter = netdev_priv(xx_ring->netdev);

  if(likely(device_in_use)) { /* We start using this device */

    try_module_get(THIS_MODULE); /* ++ */

    if (rx_ring != NULL)
      igb_irq_disable_queues(adapter, ((u64)1 << rx_ring->queue_index));

  } else { /* We're done using this device */
    
    if (rx_ring != NULL)
      /* I need interrupts for purging buckets when queues are not in use */
      igb_irq_enable_queues(adapter, rx_ring->queue_index);

    module_put(THIS_MODULE);  /* -- */
  }

  if (rx_ring != NULL) rx_ring->dna.queue_in_use = device_in_use;
  if (tx_ring != NULL) tx_ring->dna.queue_in_use = device_in_use;

  if(unlikely(enable_debug))
    printk("[DNA] %s(): %s@%d is %sIN use\n", __FUNCTION__,
	   xx_ring->netdev->name, xx_ring->queue_index, device_in_use ? "" : "NOT ");
}

/* ********************************** */

int wait_packet_function_ptr(void *data, int mode)
{
  struct igb_ring        *rx_ring = (struct igb_ring*)data;
  struct igb_adapter	 *adapter = netdev_priv(rx_ring->netdev);
  struct e1000_hw	      *hw = &adapter->hw;

  if(unlikely(enable_debug))
    printk("%s(): enter [mode=%d/%s][queueId=%d][next_to_clean=%u][next_to_use=%d]\n",
	   __FUNCTION__, mode, mode == 1 ? "enable int" : "disable int",
	   rx_ring->queue_index, rx_ring->next_to_clean, rx_ring->next_to_use);

  if(!rx_ring->dna.memory_allocated) return(0);

  if(mode == 1 /* Enable interrupt */) {
    union e1000_adv_rx_desc *rx_desc, *next_rx_desc;
    u32	staterr;
    u8	reg_idx = rx_ring->reg_idx;
    u16	i = E1000_READ_REG(hw, E1000_RDT(reg_idx));

    /* Very important: update the value from the register set from userland
     * Here i is the last I've read (zero-copy implementation) */
    if(++i == rx_ring->count) i = 0;
    /* Here i is the next I have to read */

    rx_ring->next_to_clean = i;

    rx_desc = IGB_RX_DESC(rx_ring, i);
    prefetch(rx_desc);
    staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

    /* trick for appplications calling poll/select directly (indexes not in sync of one position at most) */
    if (!(staterr & E1000_RXD_STAT_DD)) {
      u16 next_i = i;
      if(++next_i == rx_ring->count) next_i = 0;
      next_rx_desc = IGB_RX_DESC(rx_ring, next_i);
      staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    }

    if(unlikely(enable_debug)) {
      printk("%s(): Check if a packet is arrived [idx=%d][staterr=%d][len=%d]\n",
	     __FUNCTION__, i, staterr, rx_desc->wb.upper.length);

      print_adv_rx_descr(rx_desc);
    }

    if(!(staterr & E1000_RXD_STAT_DD)) {
      rx_ring->dna.rx_tx.rx.interrupt_received = 0;

      if(!rx_ring->dna.rx_tx.rx.interrupt_enabled) {
	igb_irq_enable_queues(adapter, rx_ring->queue_index);

	if(unlikely(enable_debug))
	  printk("%s(): Enabled interrupts, queue = %d\n", __FUNCTION__, rx_ring->queue_index);

	rx_ring->dna.rx_tx.rx.interrupt_enabled = 1;

	if(unlikely(enable_debug))
	  printk("%s(): Packet not arrived yet: enabling "
		 "interrupts, queue=%d, i=%d\n",
		 __FUNCTION__,rx_ring->queue_index, i);
      }

      /* Refresh the value */
      staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
      if (!(staterr & E1000_RXD_STAT_DD)) staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    } else {
      rx_ring->dna.rx_tx.rx.interrupt_received = 1; 
    }

    if(unlikely(enable_debug))
      printk("%s(): Packet received: %d\n", __FUNCTION__, staterr & E1000_RXD_STAT_DD);

    return(staterr & E1000_RXD_STAT_DD);
  } else {
    /* Disable interrupts */

    igb_irq_disable_queues(adapter, ((u64)1 << rx_ring->queue_index));

    rx_ring->dna.rx_tx.rx.interrupt_enabled = 0;

    if(unlikely(enable_debug))
      printk("%s(): Disabled interrupts, queue = %d\n", __FUNCTION__, rx_ring->queue_index);

    return(0);
  }
}

/* ********************************** */

#define IGB_PCI_DEVICE_CACHE_LINE_SIZE	0x0C
#define PCI_DEVICE_CACHE_LINE_SIZE_BYTES	8

void dna_igb_alloc_tx_buffers(struct igb_ring *tx_ring, struct pfring_hooks *hook) {
  union e1000_adv_tx_desc *tx_desc, *shadow_tx_desc;
  struct igb_tx_buffer *bi;
  u16 i;
  int num_slots_per_page = tx_ring->dna.tot_packet_memory / tx_ring->dna.packet_slot_len;

  /* Check if the memory has been already allocated */
  if(tx_ring->dna.memory_allocated) return;

  /* nothing to do or no valid netdev defined */
  if (!netdev_ring(tx_ring))
    return;

  /* We suppose that RX and TX are in sync */

  if(unlikely(enable_debug))
    printk("%s(): tx_ring->dna.rx_tx.tx.tot_packet_memory=%d dna.num_memory_pages=%d\n",
	   __FUNCTION__, tx_ring->dna.tot_packet_memory, tx_ring->dna.num_memory_pages);

  for(i=0; i<tx_ring->dna.num_memory_pages; i++) {
    tx_ring->dna.rx_tx.tx.packet_memory[i] =
      alloc_contiguous_memory(&tx_ring->dna.tot_packet_memory,
			      &tx_ring->dna.mem_order);
    
    if (tx_ring->dna.rx_tx.tx.packet_memory[i] == 0) {
      printk("\n\n%s() ERROR: not enough memory for TX DMA ring!!\n\n\n",
	     __FUNCTION__);
      return;
    }

    if(unlikely(enable_debug))
      printk("[DNA] %s(): Successfully allocated TX %u@%u bytes at "
	     "0x%08lx [slot_len=%d]\n",__FUNCTION__,
	     tx_ring->dna.tot_packet_memory, i,
	     tx_ring->dna.rx_tx.tx.packet_memory[i],
	     tx_ring->dna.packet_slot_len);    
  }

  for(i=0; i < tx_ring->count; i++) {
    u_int offset, page_index;
    char *pkt;

    page_index = i / num_slots_per_page;
    offset = (i % num_slots_per_page) * tx_ring->dna.packet_slot_len;
    pkt = (char *)(tx_ring->dna.rx_tx.tx.packet_memory[page_index] + offset);

    bi      = &tx_ring->tx_buffer_info[i];
    bi->skb = NULL;
    tx_desc = IGB_TX_DESC(tx_ring, i);

    if(unlikely(enable_debug))
      printk("%s(): [%s@%d] Mapping TX slot %d of %d [pktaddr=%p][tx_desc=%p][offset=%u]\n",
	     __FUNCTION__, 
	     tx_ring->netdev->name, tx_ring->queue_index,
	     i, tx_ring->dna.packet_num_slots,
	     pkt, tx_desc, offset);

    bi->dma = pci_map_single(to_pci_dev(tx_ring->dev), pkt,
			     tx_ring->dna.packet_slot_len,
			     PCI_DMA_TODEVICE);

    tx_desc->read.buffer_addr = cpu_to_le64(bi->dma);
    shadow_tx_desc = IGB_TX_DESC(tx_ring, i + tx_ring->count);
    memcpy(shadow_tx_desc, tx_desc, sizeof(union e1000_adv_tx_desc));
  } /* for */

  tx_ring->dna.memory_allocated = 1;
}

/* ********************************** */

static inline void igb_release_rx_desc(struct igb_ring *rx_ring, u32 val)
{
  rx_ring->next_to_use = val;
  wmb();
  writel(val, rx_ring->tail);
}

/* ********************************** */

void dna_reset_rx_ring(struct igb_ring *rx_ring) {
  igb_release_rx_desc(rx_ring, rx_ring->count-1);

  rx_ring->next_to_clean = 0;
}

/* ********************************** */

u16 igb_read_pci_cfg_word(struct e1000_hw *hw, u32 reg)
{
  u16 value;
  struct igb_adapter *adapter = hw->back;
  
  pci_read_config_word(adapter->pdev, reg, &value);
  return value;
}

/* ********************************** */

#define CACHE_LINE_SIZE 64

int gcd(int a, int b) {
  int c;
  while (a != 0) {
    c = a; 
    a = b % a;
    b = c;
  }
  return b;
}

u32 compute_buffer_padding(u32 size, u32 channels, u32 ranks) {
  u32 padded_size = (size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;
  while (gcd(padded_size, channels * ranks) != 1 || gcd(channels, padded_size) != 1)
    padded_size++;
  padded_size *= CACHE_LINE_SIZE;
  return padded_size;
}

/* ********************************** */

void dna_igb_alloc_rx_buffers(struct igb_ring *rx_ring, struct pfring_hooks *hook) {
  union e1000_adv_rx_desc *rx_desc, *shadow_rx_desc;
  struct igb_rx_buffer *bi;
  u16 i;
  struct igb_adapter 	*adapter = netdev_priv(rx_ring->netdev);
  struct e1000_hw	*hw = &adapter->hw;
  struct igb_ring	*tx_ring = adapter->tx_ring[rx_ring->queue_index];
  mem_ring_info         rx_info = {0};
  mem_ring_info         tx_info = {0};
  int                   num_slots_per_page;
#if 0
  u16			cache_line_size;

  cache_line_size = cpu_to_le16(igb_read_pci_cfg_word(hw, IGB_PCI_DEVICE_CACHE_LINE_SIZE));
  cache_line_size &= 0x00FF;
  cache_line_size *= PCI_DEVICE_CACHE_LINE_SIZE_BYTES;
  if(cache_line_size == 0) cache_line_size = 64;

  if(unlikely(enable_debug))
    printk("%s(): pci cache line size %d\n",__FUNCTION__, cache_line_size);

  rx_ring->dna.packet_slot_len  = ALIGN(rx_ring->rx_buffer_len, cache_line_size);
#endif

  /* Check if the memory has been already allocated */
  if(rx_ring->dna.memory_allocated) return;

  /* nothing to do or no valid netdev defined */
  if (!netdev_ring(rx_ring))
    return;

  if (!hook) {
    printk("[DNA] WARNING The PF_RING module is NOT loaded.\n");
    printk("[DNA] WARNING Please load it, before loading this module\n");
    return;
  }

  init_waitqueue_head(&rx_ring->dna.rx_tx.rx.packet_waitqueue);

  /* Optimising slot len for most common systems adding padding at the end. Please note 
   * that some Intel chipset has three channels, in this case no padding is required. */
  rx_ring->dna.packet_slot_len  = compute_buffer_padding(rx_ring->rx_buffer_len, 4, 4);
  rx_ring->dna.packet_num_slots = rx_ring->count;

  rx_ring->dna.tot_packet_memory = PAGE_SIZE << DNA_MAX_CHUNK_ORDER;

  num_slots_per_page = rx_ring->dna.tot_packet_memory / rx_ring->dna.packet_slot_len;

  rx_ring->dna.num_memory_pages = (rx_ring->dna.packet_num_slots + num_slots_per_page-1) / num_slots_per_page;

  for(i=0; i<rx_ring->dna.num_memory_pages; i++) {
    rx_ring->dna.rx_tx.rx.packet_memory[i] =
      alloc_contiguous_memory(&rx_ring->dna.tot_packet_memory, &rx_ring->dna.mem_order);
  
    if (rx_ring->dna.rx_tx.rx.packet_memory[i] == 0) {
      printk("\n\n%s() ERROR: not enough memory for RX DMA ring!!\n\n\n",
	     __FUNCTION__);
      return;
    }

    /*
    if(unlikely(enable_debug))
      printk("[DNA] %s(): Successfully allocated RX %u@%u bytes at 0x%08lx [slot_len=%d]\n",
	     __FUNCTION__, rx_ring->dna.tot_packet_memory, i,
	     rx_ring->dna.rx_tx.rx.packet_memory[i], rx_ring->dna.packet_slot_len);
    */
  }

  for(i=0; i < rx_ring->count; i++) {
    u_int offset, page_index;
    char *pkt;
    
    page_index = i / num_slots_per_page;
    offset = (i % num_slots_per_page) * rx_ring->dna.packet_slot_len;
    pkt = (char *)(rx_ring->dna.rx_tx.rx.packet_memory[page_index] + offset);

    if(unlikely(enable_debug))
      printk("[DNA] %s(): Successfully allocated RX %u@%u bytes at 0x%08lx [slot_len=%d][page_index=%u][offset=%u]\n",
	     __FUNCTION__, rx_ring->dna.tot_packet_memory, i,
	     rx_ring->dna.rx_tx.rx.packet_memory[i],
	     rx_ring->dna.packet_slot_len, page_index, offset);

    bi      = &rx_ring->rx_buffer_info[i];
    bi->skb = NULL;
    rx_desc = IGB_RX_DESC(rx_ring, i);

    /*
    if(unlikely(enable_debug))
      printk("%s(): [%s@%d] Mapping RX slot %d of %d [pktaddr=%p][rx_desc=%p][offset=%u]\n",
	     __FUNCTION__, 
	     rx_ring->netdev->name, rx_ring->queue_index,
	     i, rx_ring->dna.packet_num_slots,
	     pkt, rx_desc, offset);
    */

    bi->dma = pci_map_single(to_pci_dev(rx_ring->dev), pkt,
			     rx_ring->dna.packet_slot_len,
			     PCI_DMA_FROMDEVICE);

    /* Standard MTU */
    rx_desc->read.hdr_addr = 0;
    rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
    rx_desc->wb.upper.status_error = 0;

    shadow_rx_desc = IGB_RX_DESC(rx_ring, i + rx_ring->count);
    memcpy(shadow_rx_desc, rx_desc, sizeof(union e1000_adv_rx_desc));

    if(unlikely(enable_debug)) {
      print_adv_rx_descr(rx_desc);
      print_adv_rx_descr(shadow_rx_desc);
    }

    igb_release_rx_desc(rx_ring, i);
  } /* for */

    /* Shadow */
  rx_desc = IGB_RX_DESC(rx_ring, 0);

  dna_reset_rx_ring(rx_ring);

  if(unlikely(enable_debug))
  printk("[DNA] next_to_clean=%u/next_to_use=%u [register=%d]\n",
	 rx_ring->next_to_clean, rx_ring->next_to_use, 
	 E1000_READ_REG(hw, E1000_RDT(rx_ring->reg_idx)));

  /* Allocate TX memory */
  
  tx_ring->dna.tot_packet_memory = rx_ring->dna.tot_packet_memory;
  tx_ring->dna.packet_slot_len   = rx_ring->dna.packet_slot_len;
  tx_ring->dna.packet_num_slots  = tx_ring->count;
  tx_ring->dna.mem_order         = rx_ring->dna.mem_order;
  tx_ring->dna.num_memory_pages  = (tx_ring->dna.packet_num_slots + num_slots_per_page-1) / num_slots_per_page;

  dna_igb_alloc_tx_buffers(tx_ring, hook);

  rx_info.packet_memory_num_chunks    = rx_ring->dna.num_memory_pages;
  rx_info.packet_memory_chunk_len     = rx_ring->dna.tot_packet_memory;
  rx_info.packet_memory_num_slots     = rx_ring->dna.packet_num_slots;
  rx_info.packet_memory_slot_len      = rx_ring->dna.packet_slot_len;
  rx_info.descr_packet_memory_tot_len = 2 * rx_ring->size;
  
  tx_info.packet_memory_num_chunks    = tx_ring->dna.num_memory_pages;
  tx_info.packet_memory_chunk_len     = tx_ring->dna.tot_packet_memory;
  tx_info.packet_memory_num_slots     = tx_ring->dna.packet_num_slots;
  tx_info.packet_memory_slot_len      = tx_ring->dna.packet_slot_len;
  tx_info.descr_packet_memory_tot_len = 2 * tx_ring->size;

  /* Register with PF_RING */

  hook->zc_dev_handler(add_device_mapping,
				dna_driver,
  				&rx_info,
				&tx_info,
				rx_ring->dna.rx_tx.rx.packet_memory,
				rx_ring->desc, /* Packet descriptors */
				tx_ring->dna.rx_tx.tx.packet_memory,
				tx_ring->desc, /* Packet descriptors */
				(void*)rx_ring->netdev->mem_start,
				rx_ring->netdev->mem_end - rx_ring->netdev->mem_start,
				rx_ring->queue_index, /* Channel Id */
				rx_ring->netdev,
				rx_ring->dev,
				dna_model(hw),
				rx_ring->netdev->dev_addr,
				&rx_ring->dna.rx_tx.rx.packet_waitqueue,
				&rx_ring->dna.rx_tx.rx.interrupt_received,
				(void*)rx_ring, (void*)tx_ring,
				wait_packet_function_ptr,
				notify_function_ptr);

  if(unlikely(enable_debug))
    printk("[DNA] igb: %s: Enabled DNA on queue %d [RX][size=%u][count=%d] [TX][size=%u][count=%d]\n",
	   rx_ring->netdev->name, rx_ring->queue_index, rx_ring->size, rx_ring->count, tx_ring->size, tx_ring->count);

  rx_ring->dna.memory_allocated = 1;
}

#undef IGB_PCI_DEVICE_CACHE_LINE_SIZE
#undef PCI_DEVICE_CACHE_LINE_SIZE_BYTES

/* ********************************** */

static int dna_igb_clean_rx_irq(struct igb_q_vector *q_vector,
				  struct igb_ring *rx_ring, int budget) {
  union e1000_adv_rx_desc	*rx_desc, *next_rx_desc;
  u32				staterr;
  u16				i;
  struct igb_adapter	        *adapter = q_vector->adapter;
  struct e1000_hw		*hw = &adapter->hw;

  i = E1000_READ_REG(hw, E1000_RDT(rx_ring->reg_idx));
  if(++i == rx_ring->count)
    i = 0;

  rx_ring->next_to_clean = i;

  //i = E1000_READ_REG(hw, E1000_RDT(rx_ring->reg_idx));
  rx_desc = IGB_RX_DESC(rx_ring, i);
  staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

  if(rx_ring->dna.queue_in_use) {
    /*
      A userland application is using the queue so it's not time to
      mess up with indexes but just to wakeup apps (if waiting)
    */

    /* trick for appplications calling poll/select directly (indexes not in sync of one position at most) */
    if (!(staterr & E1000_RXD_STAT_DD)) {
      u16 next_i = i;
      if(++next_i == rx_ring->count) next_i = 0;
      next_rx_desc = IGB_RX_DESC(rx_ring, next_i);
      staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    }

    if(staterr & E1000_RXD_STAT_DD) {
      if(unlikely(enable_debug))
	printk(KERN_INFO "DNA: got a packet [index=%d]!\n", i);

      if(waitqueue_active(&rx_ring->dna.rx_tx.rx.packet_waitqueue)) {
	wake_up_interruptible(&rx_ring->dna.rx_tx.rx.packet_waitqueue);
	rx_ring->dna.rx_tx.rx.interrupt_received = 1;

	if(unlikely(enable_debug))
	  printk("%s(%s): woken up ring=%d, [slot=%d] XXX\n",
		 __FUNCTION__, rx_ring->netdev->name,
		 rx_ring->reg_idx, i);
      }
    }

    // goto dump_stats;
  }

  return(budget);
}

