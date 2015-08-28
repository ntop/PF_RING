/*******************************************************************************

   Copyright(c) 2008 - 2011 - Luca Deri <deri@ntop.org>
   Copyright(c) 2011 - Silicom Ltd

   This program is free software; you can redistribute it and/or modify it
   under the terms and conditions of the GNU General Public License,
   version 2, as published by the Free Software Foundation.

   This program is distributed in the hope it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

   The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

#define MAX_NUM_ADAPTERS       16 /* Note: IXGBE_MAX_NIC is 32 */

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

static unsigned int num_rx_slots = DNA_IXGBE_DEFAULT_RXD;
module_param(num_rx_slots, uint, 0644);
MODULE_PARM_DESC(num_rx_slots, "Specify the number of RX slots. Default: 8192");

static unsigned int num_tx_slots = DNA_IXGBE_DEFAULT_TXD;
module_param(num_tx_slots, uint, 0644);
MODULE_PARM_DESC(num_tx_slots, "Specify the number of TX slots. Default: 8192");

/* Note: currently numa cpu affinity is per-adapter, but this can be easily 
 * changed to per-queue (MAX_NUM_ADAPTERS * MAX_RX_QUEUES items) */
static int numa_cpu_affinity[MAX_NUM_ADAPTERS] = 
  { [0 ... (MAX_NUM_ADAPTERS - 1)] = -1 };
module_param_array(numa_cpu_affinity, int, NULL, 0444);
MODULE_PARM_DESC(numa_cpu_affinity,
                 "Comma separated list of core ids where per-adapter memory will be allocated");

/* Forward */
static inline void ixgbe_irq_disable(struct ixgbe_adapter *adapter);
static void ixgbe_irq_enable_queues(struct ixgbe_adapter *adapter, u64 qmask);
static void ixgbe_irq_disable_queues(struct ixgbe_adapter *adapter, u64 qmask);
static inline void ixgbe_release_rx_desc(struct ixgbe_ring *rx_ring, u32 val);

/* ****************************** */

void dna_check_enable_adapter(struct ixgbe_adapter *adapter) {
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

void reserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  if(unlikely(enable_debug)) printk("[DNA] reserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

/* ****************************** */

void unreserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  if(unlikely(enable_debug)) printk("[DNA] unreserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

/* ********************************** */

static unsigned long __get_free_pages_node(int nid, gfp_t gfp_mask, unsigned int order) {
  struct page *page;

#if 0  
  VM_BUG_ON((gfp_mask & __GFP_HIGHMEM) != 0);
#endif

  page = alloc_pages_node(nid, gfp_mask, order);
  
  if (!page)
    return 0;

  return (unsigned long) page_address(page);
}

/* ********************************** */

static unsigned long alloc_contiguous_memory(u_int *tot_mem_len, u_int *mem_order, int node) {
  unsigned long mem = 0;

  if(unlikely(enable_debug)) printk("[DNA] %s(%d)\n", __FUNCTION__, *tot_mem_len);

  *mem_order = get_order(*tot_mem_len);
  *tot_mem_len = PAGE_SIZE << *mem_order;

  if (node >= 0) {
    mem = __get_free_pages_node(node, GFP_ATOMIC, *mem_order);
    if (!mem) {
      printk("[DNA] Warning: memory allocation on node %d failed, using another node", node);
      node = -1;
    }
  }

  if (!mem)
    mem = __get_free_pages(GFP_ATOMIC, *mem_order);

  if(mem) {
    if(unlikely(enable_debug))
      printk("[DNA] %s() success [tot_mem_len=%d,mem=%lu,mem_order=%d,node=%d]\n",
	     __FUNCTION__, *tot_mem_len, mem, *mem_order, node);
    reserve_memory(mem, *tot_mem_len);
  } else {
    if(unlikely(enable_debug))
      printk("[DNA] %s() failure (len=%d,order=%d)\n",
	     __FUNCTION__, *tot_mem_len, *mem_order);
  }

  return(mem);
}

/* ********************************** */

static void free_contiguous_memory(unsigned long mem,
				   u_int tot_mem_len, u_int mem_order) {
  if(unlikely(enable_debug))
    printk("[DNA] free_contiguous_memory(%lu,%d,%d)\n",
	   mem, tot_mem_len, mem_order);

  if(mem != 0) {
    unreserve_memory(mem, tot_mem_len);
    free_pages(mem, mem_order);
  }
}

/* ********************************** */

static void print_adv_rx_descr(union ixgbe_adv_rx_desc	*descr) {
  if(likely(!enable_debug)) return;

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

zc_dev_model dna_model(struct ixgbe_hw *hw){
  switch (hw->mac.type) {
    case ixgbe_mac_82598EB:
      return intel_ixgbe_82598;
    case ixgbe_mac_82599EB:      
      return(hw->silicom.has_hw_ts_card ? intel_ixgbe_82599_ts : intel_ixgbe_82599);
    default:
      return intel_ixgbe;
  }
}

/* ********************************** */

void notify_function_ptr(void *rx_data, void *tx_data, u_int8_t device_in_use) {
  struct ixgbe_ring    *rx_ring = (struct ixgbe_ring *) rx_data;
  struct ixgbe_ring    *tx_ring = (struct ixgbe_ring *) tx_data;
  struct ixgbe_ring    *xx_ring = (rx_ring != NULL) ? rx_ring : tx_ring;
  struct ixgbe_adapter *adapter = netdev_priv(xx_ring->netdev);

  if(likely(device_in_use)) { /* We start using this device */

    try_module_get(THIS_MODULE); /* ++ */

    if (rx_ring != NULL) {
      if(adapter->hw.mac.type != ixgbe_mac_82598EB)
        ixgbe_irq_disable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
    }

  } else { /* We're done using this device */

    if (rx_ring != NULL) {
      if(adapter->hw.mac.type != ixgbe_mac_82598EB)
        /* TODO Check this*/
        //ixgbe_irq_enable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
        ixgbe_irq_disable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
    }

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
  struct ixgbe_ring		*rx_ring = (struct ixgbe_ring*)data;
  struct ixgbe_adapter	*adapter = netdev_priv(rx_ring->netdev);
  struct ixgbe_hw		*hw = &adapter->hw;
  struct ixgbe_q_vector	*q_vector = rx_ring->q_vector;

  if(unlikely(enable_debug))
    printk("%s(): enter [mode=%d/%s][queueId=%d][next_to_clean=%u][next_to_use=%d]\n",
	   __FUNCTION__, mode, mode == 1 ? "enable int" : "disable int",
	   rx_ring->queue_index, rx_ring->next_to_clean, rx_ring->next_to_use);

  if(!rx_ring->dna.memory_allocated) return(0);

  if(mode == 1 /* Enable interrupt */) {
    union ixgbe_adv_rx_desc *rx_desc, *next_rx_desc = NULL;
    u32	staterr;
    u8	reg_idx = rx_ring->reg_idx;
    u16	i = IXGBE_READ_REG(hw, IXGBE_RDT(reg_idx));

    /* Very important: update the value from the register set from userland
     * Here i is the last I've read (zero-copy implementation) */
    if(++i == rx_ring->count) i = 0;
    /* Here i is the next I have to read */

    rx_ring->next_to_clean = i;

    rx_desc = IXGBE_RX_DESC(rx_ring, i);
    prefetch(rx_desc);
    staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

    /* trick for appplications calling poll/select directly (indexes not in sync of one position at most) */
    if (!(staterr & IXGBE_RXD_STAT_DD)) {
      u16 next_i = i;
      if(++next_i == rx_ring->count) next_i = 0;
      next_rx_desc = IXGBE_RX_DESC(rx_ring, next_i);
      staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    }

    if(unlikely(enable_debug)) {
      printk("%s(): Check if a packet is arrived [idx=%d][staterr=%d][len=%d]\n",
	     __FUNCTION__, i, staterr, rx_desc->wb.upper.length);

      print_adv_rx_descr(rx_desc);
    }

    if(!(staterr & IXGBE_RXD_STAT_DD)) {
      rx_ring->dna.rx_tx.rx.interrupt_received = 0;

      if(unlikely(enable_debug))
        printk("%s(): Packet not arrived yet [slot=%d][queue=%d]\n",
		__FUNCTION__, i, q_vector->v_idx);

      if(!rx_ring->dna.rx_tx.rx.interrupt_enabled) {
	if(adapter->hw.mac.type != ixgbe_mac_82598EB)
	  ixgbe_irq_enable_queues(adapter, ((u64)1 << q_vector->v_idx));

	rx_ring->dna.rx_tx.rx.interrupt_enabled = 1;

	if(unlikely(enable_debug))
	  printk("%s(): enabling interrupts [queue=%d]\n",
		 __FUNCTION__, q_vector->v_idx);
      }

      /* Refresh the value */
      staterr  = le32_to_cpu(rx_desc->wb.upper.status_error);
      if (!(staterr & IXGBE_RXD_STAT_DD)) staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    } else {
      if(unlikely(enable_debug))
        printk("%s(): New packet arrived\n", __FUNCTION__);

      rx_ring->dna.rx_tx.rx.interrupt_received = 1;
    }

    if(unlikely(enable_debug))
      printk("%s(): Packet received: %d\n", __FUNCTION__, staterr & IXGBE_RXD_STAT_DD);

    return(staterr & IXGBE_RXD_STAT_DD);
  } else {
    /* Disable interrupts */

    if(adapter->hw.mac.type != ixgbe_mac_82598EB)
      ixgbe_irq_disable_queues(adapter, ((u64)1 << q_vector->v_idx));

    rx_ring->dna.rx_tx.rx.interrupt_enabled = 0;

    if(unlikely(enable_debug))
      printk("%s(): Disabled interrupts, queue = %d\n", __FUNCTION__, q_vector->v_idx);

    return(0);
  }
}

/* ********************************** */

void dna_ixgbe_alloc_tx_buffers(struct ixgbe_ring *tx_ring, struct pfring_hooks *hook) {
  union ixgbe_adv_tx_desc *tx_desc, *shadow_tx_desc;
  struct ixgbe_tx_buffer *bi;
  u16 i;
  int num_slots_per_page = tx_ring->dna.tot_packet_memory / tx_ring->dna.packet_slot_len;
  // struct ixgbe_adapter 	*adapter = netdev_priv(tx_ring->netdev);

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
			      &tx_ring->dna.mem_order,
			      tx_ring->q_vector->numa_node);

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

  if(unlikely(enable_debug))
    printk("[DNA] %s(): %s@%d ptr=%p memory allocated on node %d\n", __FUNCTION__, 
      tx_ring->netdev->name, tx_ring->queue_index, tx_ring, tx_ring->q_vector->numa_node);

  for(i=0; i < tx_ring->count; i++) {
    u_int offset, page_index;
    char *pkt;

    page_index = i / num_slots_per_page;
    offset = (i % num_slots_per_page) * tx_ring->dna.packet_slot_len;
    pkt = (char *)(tx_ring->dna.rx_tx.tx.packet_memory[page_index] + offset);

    bi      = &tx_ring->tx_buffer_info[i];
    bi->skb = NULL;
    tx_desc = IXGBE_TX_DESC(tx_ring, i);

    if(unlikely(enable_debug))
      printk("%s(): Mapping TX slot %d of %d [pktaddr=%p][tx_desc=%p][offset=%u]\n",
	     __FUNCTION__, i, tx_ring->dna.packet_num_slots,
	     pkt, tx_desc, offset);

    bi->dma = pci_map_single(to_pci_dev(tx_ring->dev), pkt,
			     tx_ring->dna.packet_slot_len,
			     PCI_DMA_BIDIRECTIONAL /* PCI_DMA_TODEVICE */ );

    tx_desc->read.buffer_addr = cpu_to_le64(bi->dma);
    shadow_tx_desc = IXGBE_TX_DESC(tx_ring, i + tx_ring->count);
    memcpy(shadow_tx_desc, tx_desc, sizeof(union ixgbe_adv_tx_desc));
  } /* for */

  tx_ring->dna.memory_allocated = 1;
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

void dna_ixgbe_alloc_rx_buffers(struct ixgbe_ring *rx_ring) {
  union ixgbe_adv_rx_desc *rx_desc, *shadow_rx_desc;
  struct ixgbe_rx_buffer *bi;
  u16 i;
  struct ixgbe_adapter 	*adapter = netdev_priv(rx_ring->netdev);
  struct ixgbe_hw       *hw = &adapter->hw;
  struct ixgbe_ring     *tx_ring = adapter->tx_ring[rx_ring->queue_index];
  struct pfring_hooks   *hook = (struct pfring_hooks*)rx_ring->netdev->pfring_ptr;
  mem_ring_info         rx_info = {0};
  mem_ring_info         tx_info = {0};
  int                   num_slots_per_page;
#if 0
#define IXGBE_PCI_DEVICE_CACHE_LINE_SIZE	0x0C
#define PCI_DEVICE_CACHE_LINE_SIZE_BYTES	8
  u16	                cache_line_size;

  cache_line_size = cpu_to_le16(IXGBE_READ_PCIE_WORD(hw, IXGBE_PCI_DEVICE_CACHE_LINE_SIZE));
  cache_line_size &= 0x00FF;
  cache_line_size *= PCI_DEVICE_CACHE_LINE_SIZE_BYTES;
  if(cache_line_size == 0) cache_line_size = 64;

  if(unlikely(enable_debug))
    printk("%s(): pci cache line size %d\n",__FUNCTION__, cache_line_size);

#undef IXGBE_PCI_DEVICE_CACHE_LINE_SIZE
#undef PCI_DEVICE_CACHE_LINE_SIZE_BYTES
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
  rx_ring->dna.packet_slot_len  = compute_buffer_padding(rx_ring->rx_buf_len, 4, 4);

  rx_ring->dna.packet_num_slots = rx_ring->count;

  rx_ring->dna.tot_packet_memory = PAGE_SIZE << DNA_MAX_CHUNK_ORDER;

  num_slots_per_page = rx_ring->dna.tot_packet_memory / rx_ring->dna.packet_slot_len;

  rx_ring->dna.num_memory_pages = (rx_ring->dna.packet_num_slots + num_slots_per_page-1) / num_slots_per_page;

  /* Packet Split disabled in DNA mode */
  //if (ring_is_ps_enabled(rx_ring)) {
    /* data will be put in this buffer */
    /* Original fuction allocate PAGE_SIZE/2 for this buffer*/
  //  rx_ring->dna.packet_slot_len  += PAGE_SIZE/2;
  //}

  if(unlikely(enable_debug))
    printk("%s(): RX dna.packet_slot_len=%d tot_packet_memory=%d num_memory_pages=%u num_slots_per_page=%d\n",
	   __FUNCTION__, 
	   rx_ring->dna.packet_slot_len,
	   rx_ring->dna.tot_packet_memory,
	   rx_ring->dna.num_memory_pages,
	   num_slots_per_page);

  for(i=0; i<rx_ring->dna.num_memory_pages; i++) {
    rx_ring->dna.rx_tx.rx.packet_memory[i] =
      alloc_contiguous_memory(&rx_ring->dna.tot_packet_memory, 
      			      &rx_ring->dna.mem_order, 
      			      rx_ring->q_vector->numa_node);

    if (rx_ring->dna.rx_tx.rx.packet_memory[i] == 0) {
      printk("\n\n%s() ERROR: not enough memory for RX DMA ring!!\n\n\n",
	     __FUNCTION__);
      return;
    }

    if(unlikely(enable_debug))
      printk("[DNA] %s(): Successfully allocated RX %u@%u bytes at 0x%08lx [slot_len=%d]\n",
	     __FUNCTION__, rx_ring->dna.tot_packet_memory, i,
	     rx_ring->dna.rx_tx.rx.packet_memory[i], rx_ring->dna.packet_slot_len);
  }

  if(unlikely(enable_debug))
    printk("[DNA] %s(): %s@%d ptr=%p memory allocated on node %d\n", __FUNCTION__, 
      rx_ring->netdev->name, rx_ring->queue_index, rx_ring, rx_ring->q_vector->numa_node);

  for(i=0; i < rx_ring->count; i++) {
    u_int offset, page_index;
    char *pkt;

    page_index = i / num_slots_per_page;
    offset = (i % num_slots_per_page) * rx_ring->dna.packet_slot_len;
    pkt = (char *)(rx_ring->dna.rx_tx.rx.packet_memory[page_index] + offset);

    /*
    if(unlikely(enable_debug))
      printk("[DNA] %s(): Successfully remapped RX %u@%u bytes at 0x%08lx [slot_len=%d][page_index=%u][offset=%u]\n",
	     __FUNCTION__, rx_ring->dna.tot_packet_memory, i,
	     rx_ring->dna.rx_tx.rx.packet_memory[i],
	     rx_ring->dna.packet_slot_len, page_index, offset);
    */

    bi      = &rx_ring->rx_buffer_info[i];
    bi->skb = NULL;
    rx_desc = IXGBE_RX_DESC(rx_ring, i);

    if(unlikely(enable_debug))
      printk("%s(): Mapping RX slot %d of %d [pktaddr=%p][rx_desc=%p][offset=%u]\n",
	     __FUNCTION__, i, rx_ring->dna.packet_num_slots,
	     pkt, rx_desc, offset);

    bi->dma = pci_map_single(to_pci_dev(rx_ring->dev), pkt,
			     rx_ring->dna.packet_slot_len,
			     PCI_DMA_BIDIRECTIONAL /* PCI_DMA_FROMDEVICE */ );

    /* Packet Split disabled in DNA mode */
    //if (!ring_is_ps_enabled(rx_ring)) {
      rx_desc->read.hdr_addr = 0;
      rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
    //} else {
    //  rx_desc->read.hdr_addr = cpu_to_le64(bi->dma);
    //  rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + rx_ring->dna.packet_slot_len);
    //}

    rx_desc->wb.upper.status_error = 0;

    shadow_rx_desc = IXGBE_RX_DESC(rx_ring, i + rx_ring->count);
    memcpy(shadow_rx_desc, rx_desc, sizeof(union ixgbe_adv_rx_desc));

    if(unlikely(enable_debug)) {
      print_adv_rx_descr(rx_desc);
      print_adv_rx_descr(shadow_rx_desc);
    }

    ixgbe_release_rx_desc(rx_ring, i);
  } /* for */

  /* Shadow */
  rx_desc = IXGBE_RX_DESC(rx_ring, 0);

  /* Resetting index
     rx_ring->next_to_use   = the last slot where the next incoming packets can be copied (tail) */
  ixgbe_release_rx_desc(rx_ring, rx_ring->count-1);
  /* rx_ring->next_to_clean = the slot where the next incoming packet will be read (head) */
  rx_ring->next_to_clean = 0;

  /* Register with PF_RING */

  if(unlikely(enable_debug))
    printk("[DNA] next_to_clean=%u/next_to_use=%u [register=%d]\n",
	   rx_ring->next_to_clean, rx_ring->next_to_use, IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx)));

  /* Allocate TX memory */
  tx_ring->dna.tot_packet_memory = rx_ring->dna.tot_packet_memory;
  tx_ring->dna.packet_slot_len   = rx_ring->dna.packet_slot_len;
  tx_ring->dna.packet_num_slots  = tx_ring->count;
  tx_ring->dna.mem_order         = rx_ring->dna.mem_order;
  tx_ring->dna.num_memory_pages  = (tx_ring->dna.packet_num_slots + num_slots_per_page-1) / num_slots_per_page;

  dna_ixgbe_alloc_tx_buffers(tx_ring, hook);

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
				rx_ring->dev, /* for DMA mapping */
				dna_model(hw),
				rx_ring->netdev->dev_addr,
				&rx_ring->dna.rx_tx.rx.packet_waitqueue,
				&rx_ring->dna.rx_tx.rx.interrupt_received,
				(void*)rx_ring, (void*)tx_ring,
				wait_packet_function_ptr,
				notify_function_ptr);

  rx_ring->dna.memory_allocated = 1;

  if(unlikely(enable_debug))
    printk("[DNA] ixgbe: %s: Enabled DNA on queue %d [RX][size=%u][count=%d] [TX][size=%u][count=%d]\n",
	   rx_ring->netdev->name, rx_ring->queue_index, rx_ring->size, rx_ring->count, tx_ring->size, tx_ring->count);
#if 0
  if(adapter->hw.mac.type != ixgbe_mac_82598EB)
    ixgbe_irq_disable_queues(rx_ring->q_vector->adapter, ((u64)1 << rx_ring->queue_index));
#endif
}

/* ********************************** */

static int dna_ixgbe_rx_dump(struct ixgbe_ring *rx_ring) {
  int j, found=0;

  for(j=0; j<rx_ring->count; j++) {
    union ixgbe_adv_rx_desc *rx_desc = IXGBE_RX_DESC(rx_ring, j);

    if(rx_desc->wb.upper.status_error) {
      printk("[%d][status=%u]\n", j, rx_desc->wb.upper.status_error);
      // for(i=0; i<16; i++) printf("%02X ", ptr[i+offset] & 0xFF);
      found++;
    }
  }

  return(found);
}

/* ********************************** */

static bool dna_ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
				  struct ixgbe_ring *rx_ring, int budget) {
  union ixgbe_adv_rx_desc	*rx_desc, *shadow_rx_desc, *next_rx_desc;
  u32				staterr;
  u16				i, num_laps = 0, last_cleaned_idx;
  struct ixgbe_adapter	        *adapter = q_vector->adapter;
  struct ixgbe_hw		*hw = &adapter->hw;
  unsigned int total_rx_packets = 0;

  last_cleaned_idx  = i = IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx));
  if(++i == rx_ring->count)
    i = 0;

  rx_ring->next_to_clean = i;

  //i = IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx));
  rx_desc = IXGBE_RX_DESC(rx_ring, i);
  staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

  if(rx_ring->dna.queue_in_use) {
    /*
      A userland application is using the queue so it's not time to
      mess up with indexes but just to wakeup apps (if waiting)
    */

    /* trick for appplications calling poll/select directly (indexes not in sync of one position at most) */
    if (!(staterr & IXGBE_RXD_STAT_DD)) {
      u16 next_i = i;
      if(++next_i == rx_ring->count) next_i = 0;
      next_rx_desc = IXGBE_RX_DESC(rx_ring, next_i);
      staterr = le32_to_cpu(next_rx_desc->wb.upper.status_error);
    }

    if(staterr & IXGBE_RXD_STAT_DD) {
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
    return(!!budget);
  }

  /* Only 82598 needs kernel housekeeping (82599 does not need that thanks
     to the drop bit), as the drop flag does not seem to work
  */
  if(adapter->hw.mac.type != ixgbe_mac_82598EB)
    return(!!budget);

  if( /* staterr || */ enable_debug) {
    printk("[DNA] %s(): %s@%d [used=%d][idx=%d][next_to_use=%u][#unused=%d][staterr=%d][full=%d][pkt_ptr=%llu]\n", __FUNCTION__,
	   rx_ring->netdev->name, rx_ring->queue_index,
	   rx_ring->dna.queue_in_use, i, rx_ring->next_to_use,
	   ixgbe_desc_unused(rx_ring), staterr, dna_ixgbe_rx_dump(rx_ring), rx_desc->read.pkt_addr);
  }

  /*
    This RX queue is not in use

    IMPORTANT
    We need to poll queues not in use as otherwise they will stop the operations
    also on queues where there is an application running that consumes the packets
  */
  while(staterr & IXGBE_RXD_STAT_DD) {
    shadow_rx_desc = IXGBE_RX_DESC(rx_ring, i+rx_ring->count);
    rx_desc->wb.upper.status_error = 0, last_cleaned_idx = i;
    rx_desc->read.hdr_addr = shadow_rx_desc->read.hdr_addr, rx_desc->read.pkt_addr = shadow_rx_desc->read.pkt_addr;

    rmb();

    // REMOVE BELOW
    // ixgbe_release_rx_desc(rx_ring, i); /* Not needed */

    i++, num_laps++, budget--;
    if(i == rx_ring->count)
      i = 0;

    rx_desc = IXGBE_RX_DESC(rx_ring, i);
    prefetch(rx_desc);
    staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

    if(budget == 0) break;
  }

  rx_ring->stats.packets += total_rx_packets;
  // rx_ring->stats.bytes += total_rx_bytes;
  q_vector->rx.total_packets += total_rx_packets;
  // q_vector->rx.total_bytes += total_rx_bytes;

  /* Update register */
  rx_ring->next_to_clean = i, IXGBE_WRITE_REG(&adapter->hw, IXGBE_RDT(rx_ring->reg_idx), last_cleaned_idx);

  if(unlikely(enable_debug)) {
    int j=0, full = 0, other = 0, null_dma = 0;
    struct ixgbe_rx_buffer *bi;

    for(j=0; j<rx_ring->count; j++) {
      rx_desc = IXGBE_RX_DESC(rx_ring, j);
      prefetch(rx_desc);
      staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

      bi = &rx_ring->rx_buffer_info[i];

      if(staterr & IXGBE_RXD_STAT_DD)
	full++;
      else if(staterr)
	other++;

      if(bi->dma == 0) null_dma++;
    }

    printk("[DNA] %s(): %s@%d [laps=%d][budget=%d][full=%d/other=%d][next_to_clean=%u][next_to_use=%d][#unused=%d][null_dma=%d]\n",
	   __FUNCTION__,
	   rx_ring->netdev->name, rx_ring->queue_index,
	   num_laps, budget, full, other,
	   rx_ring->next_to_clean, rx_ring->next_to_use,
	   ixgbe_desc_unused(rx_ring), null_dma);
  }

  return(!!budget);
}

