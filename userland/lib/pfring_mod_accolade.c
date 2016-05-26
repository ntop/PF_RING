/*
 *
 * (C) 2015    - ntop.org
 * (C) 2014-15 - Accolade Technology Inc.
 *
 */

#include "pfring_mod_accolade.h"
#include "pfring_mod.h" /* to print stats under /proc */

//#define DEBUG

void *anic_hugepageGet(anic_handle_t anic_handle, int count, int *shmidP);
int anic_hugepageDmaMap(anic_handle_t anic_handle, void *virtualP, int hugepageCount, struct anic_dma_info *dmacbP);

/* **************************************************** */

static void accolade_release_resources(pfring *ring) {
  pfring_anic *accolade = (pfring_anic *) ring->priv_data;

  if (accolade) {
    anic_close(accolade->anic_handle);
    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

int pfring_anic_open(pfring *ring) {
  pfring_anic *accolade;
  u_int32_t page, blk;
  u_int8_t *buf_p;
  int i;

  ring->close              = pfring_anic_close;
  ring->stats              = pfring_anic_stats;
  ring->recv               = pfring_anic_recv;
  ring->poll               = pfring_anic_poll;
  ring->set_direction      = pfring_anic_set_direction;
  ring->enable_ring        = pfring_anic_enable_ring;
  ring->get_bound_device_ifindex = pfring_anic_get_bound_device_ifindex;
  ring->get_interface_speed = pfring_anic_get_interface_speed;

  /* Inherited from pfring_mod.c */
  ring->set_socket_mode          = pfring_mod_set_socket_mode;
  ring->set_bound_dev_name       = pfring_mod_set_bound_dev_name;
  ring->set_application_name     = pfring_mod_set_application_name;
  ring->set_application_stats    = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;

  ring->priv_data = NULL;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL)); /* opening PF_RING socket to priaccolade stats under /proc */
  if(ring->fd < 0) return(-1);

  ring->priv_data = calloc(1, sizeof(pfring_anic));

  if(ring->priv_data == NULL)
    goto free_private;

  accolade = (pfring_anic *) ring->priv_data;

  /*
   * Device name:
   * 1. anic:D@R
   * 2. anic:D:P
   * 3. anic:P
   * Where D = device, P = port, R = ring (defined with anic_rx_block_mfl, using --mode=2 for RSS or --mode=port for ring-to-port binding)
   * Note: in 2. and 3. it is not possible to run multiple application instances
   */

#ifdef MFL_SUPPORT
  if (strchr(ring->device_name, '@')) {
    sscanf(ring->device_name, "%u@%u", &accolade->device_id, &accolade->ring_id);
    accolade->mfl_mode = 1;
  } else {
#endif
    if (sscanf(ring->device_name, "%u:%u", &accolade->device_id, &accolade->ring_id) != 2) {
      accolade->device_id = 0;
      sscanf(ring->device_name, "%u", &accolade->ring_id);
    }
#ifdef MFL_SUPPORT
    accolade->mfl_mode = 0;
  }
#endif

#ifdef DEBUG
  printf("[ANIC] Opening anic device=%u, %s=%u\n", accolade->device_id, 
#ifdef MFL_SUPPORT
    accolade->mfl_mode ? "ring" : 
#endif
    "port", accolade->ring_id);
#endif

  accolade->anic_handle = anic_open("/dev/anic", accolade->device_id);

  if (anic_error_code(accolade->anic_handle) != ANIC_ERR_NONE) {
    goto free_private;
  }

#ifdef DEBUG
  printf("[ANIC] Open device /dev/anic\n");
#endif

  accolade->blocksize = ACCOLADE_HUGEPAGE_SIZE;

#ifdef MFL_SUPPORT
  if (!accolade->mfl_mode) {
#endif

  if (accolade->anic_handle->is40k3) {
    if (anic_k325t_aurora_train(accolade->anic_handle))
      goto free_private;
  }

  /* Reset the NIC */
  anic_reset_and_restart_pipeline(accolade->anic_handle);
  sleep(2);

  if (accolade->anic_handle->product_info.product_id == ANIC_PRODUCT_ID_40K3_QUAD10G_PACKET_CAPTURE_NIC) {
    accolade->portCount = 4;
  } else if (accolade->anic_handle->product_info.product_id == ANIC_PRODUCT_ID_200K_DUAL100G_PACKET_CAPTURE_NIC) {    
    accolade->portCount = 2;   
  } else {
    fprintf(stderr, "Unsupportd product_id:0x%02x\n", accolade->anic_handle->product_info.product_id);
    goto free_private; 
  }

  if ((accolade->anic_handle->product_info.major_version & 0xf0) != 0x40) {
    fprintf(stderr, "Unsupported firmware revision\n");
    goto free_private;
  }

  //if (accolade->anic_handle->is40k3)
  //  anic_40k3_10ge(accolade->anic_handle, accolade->ring_id); /* set port speed */

  anic_pduproc_steer(accolade->anic_handle, ANIC_STEER0123);
  anic_pduproc_dma_pktseq(accolade->anic_handle, 1);


  if (accolade->anic_handle->product_info.product_id == ANIC_PRODUCT_ID_200K_DUAL100G_PACKET_CAPTURE_NIC) {    
    uint32_t pktif_csr = anic_read_u32(accolade->anic_handle->iom_base, 0x10000);
    anic_write_u32(accolade->anic_handle->iom_base, 0x10000, pktif_csr | 0xc0000); // set [19:18]     
  }

  //if (slice)
  //  anic_pduproc_slice(accolade->anic_handle, slice);

  accolade->blocksize_e = ANIC_BLOCK_2MB;
  anic_block_set_blocksize(accolade->anic_handle, accolade->blocksize_e);

  accolade->pages = ACCOLADE_BUFFER_COUNT;
  accolade->pageblocks = 1;

  for (page = 0, blk = 0; page < accolade->pages; page++) {
    void *vP;
    struct anic_dma_info dmaInfo;

    if ((vP = anic_hugepageGet(accolade->anic_handle, 1, NULL)) == NULL) {
      fprintf(stderr, "anic_hugepageGet() failed errno:%u %s\n", errno, strerror(errno));
      goto free_private;
    }

    if (anic_hugepageDmaMap(accolade->anic_handle, vP, 1, &dmaInfo)) {
      fprintf(stderr, "anic_hugepageDmaMap()\n");
      goto free_private;
    }

    buf_p = (uint8_t *) dmaInfo.userVirtualAddress;

    for (i = 0; i < accolade->pageblocks; i++) {
      accolade->l_blkA[blk].buf_p = buf_p + i * accolade->blocksize;
      accolade->l_blkA[blk].dma_address = dmaInfo.dmaPhysicalAddress + i*accolade->blocksize;
      anic_block_add(accolade->anic_handle, 0, blk, 0, accolade->l_blkA[blk].dma_address);
      blk++;
    }
  }

#ifdef MFL_SUPPORT
  } else { /* (accolade->mfl_mode) */
    struct anic_dma_info dmaInfo;

    memset(accolade->l_blkA, 0, sizeof(accolade->l_blkA));

    for (page = 0; page < ACCOLADE_BLOCKS_PER_RING; page++) {
      if ((buf_p = anic_hugepageGet(accolade->anic_handle, 1, NULL)) == NULL) {
        fprintf(stderr, "anic_hugepageGet() failed errno:%u %s\n", errno, strerror(errno));
        goto free_private;
      }
	
      if (anic_hugepageDmaMap(accolade->anic_handle, buf_p, 1, &dmaInfo)) {
        fprintf(stderr, "anic_hugepageDmaMap()\n");
        goto free_private;
      }
	
      blk = anic_block_add(accolade->anic_handle, accolade->ring_id, 0, accolade->ring_id, dmaInfo.dmaPhysicalAddress);
	
      if (blk < 0) {
        fprintf(stderr, "anic_block_add(ring:%u buf:%u) failed, oversubscribed?\n", accolade->ring_id, page);
        goto free_private;
      }

      if (accolade->l_blkA[blk].buf_p != NULL) {
        fprintf(stderr, "blk already in use blk:%u buf:%u\n", blk, page);
        goto free_private;
      }

      accolade->l_blkA[blk].buf_p = buf_p;
      accolade->l_blkA[blk].dma_address = dmaInfo.dmaPhysicalAddress;

#ifdef DEBUG
      printf("[ANIC] Init block %u va=%llu dma=%llu\n", blk, buf_p, accolade->l_blkA[blk].dma_address);
#endif
    }
  }
#endif

  ring->poll_duration = DEFAULT_POLL_DURATION;

  return 0;

 free_private:
  accolade_release_resources(ring);

  return(-1);
}

/* **************************************************** */

void pfring_anic_close(pfring *ring) {
  accolade_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_anic_stats(pfring *ring, pfring_stat *stats) {
  pfring_anic *accolade = (pfring_anic *) ring->priv_data;
  struct anic_port_pkt_counts_type tCounts;
  u_int64_t drops = 0;

  stats->recv = accolade->rstats.packets;

#ifdef MFL_SUPPORT
  if (!accolade->mfl_mode) {
#endif

    anic_port_get_cnts(accolade->anic_handle, accolade->ring_id, ANIC_STID_PORT_PKT_COUNTS_TYPE, &tCounts);

    //packets = tCounts.enet_rx_count;
    //bytes   = tCounts.enet_rx_bytes;
    //malfs   = tCounts.enet_rx_malf_count;
    //rsrcs   = tCounts.enet_rx_rsrc_count;

    //accolade->rstats.bytes;
    //accolade->rstats.packet_errors;
    //accolade->rstats.timestamp_errors;

    stats->drop = tCounts.enet_rx_drop_count;

#ifdef MFL_SUPPORT
  } else { /* (accolade->mfl_mode) i*/
    
    drops = anic_block_get_ring_dropcount(accolade->anic_handle, accolade->ring_id);

    if (drops < accolade->rstats.last_drops_counter) {
      accolade->rstats.cumulative_drops += accolade->rstats.last_drops_counter;
      accolade->rstats.last_drops_counter = drops;
    }

    stats->drop = accolade->rstats.cumulative_drops + drops;
  }
#endif

  return 0;
}

/* **************************************************** */

int pfring_anic_set_direction(pfring *ring, packet_direction direction) {
  if (direction == rx_only_direction || direction == rx_and_tx_direction) {
    return (setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction)));
  }

  return -1;
}

/* **************************************************** */

int pfring_anic_get_bound_device_ifindex(pfring *ring, int *if_index) {
  //pfring_anic *accolade = (pfring_anic *) ring->priv_data;

  *if_index = UNKNOWN_INTERFACE; /* TODO */
  return 0;
}

/* **************************************************** */

u_int32_t pfring_anic_get_interface_speed(pfring *ring) {
  //pfring_anic *accolade = (pfring_anic *) ring->priv_data;

  /* TODO */

  return 0;
}

/* **************************************************** */

int pfring_anic_enable_ring(pfring *ring) {
  pfring_anic *accolade = (pfring_anic *) ring->priv_data;
  struct rx_rmon_counts_s rmonTmp;

  /* Enable ring */

  anic_block_set_ring_nodetag(accolade->anic_handle, accolade->ring_id,
#ifdef MFL_SUPPORT
    accolade->mfl_mode ? accolade->ring_id : 
#endif
    0
  );
  anic_block_ena_ring(accolade->anic_handle, accolade->ring_id, 1);

#ifdef MFL_SUPPORT
  if (!accolade->mfl_mode) {
#endif

  anic_get_rx_rmon_counts(accolade->anic_handle, accolade->ring_id, 1, &rmonTmp);
  anic_port_get_counts(accolade->anic_handle, accolade->ring_id, 1, NULL);

  /* Set 1 msec block timeouts */
  anic_block_set_timeouts(accolade->anic_handle, 1000, 1000);

  /* turn on XGE port */
  anic_port_ena_disa(accolade->anic_handle, accolade->ring_id, 1);

#ifdef MFL_SUPPORT
  }
#endif

  return 0;
}

/* **************************************************** */

/* External functions (anic_hugepage_support.c) */

#define HUGEPAGE_SIZE (1 << ANIC_2M_PAGE)
#define MAX_ATTEMPTS (16)

// At the moment, the ANIC only supports up to 2**35 (32 Gbyte) physical memory. This corresponds to at most 16K 2Mbyte segments.
# define MAX_SEGMENTS 16384

// file scoped globals
static jmp_buf l_jumpEnv;
static void (*l_savedHandler)(int);

/* **************************************************** */

static void l_sigbusHandler(int signum) {
  // restore saved signal handler and force error handling
  signal(signum, l_savedHandler);
  longjmp(l_jumpEnv, 1);
}

/* **************************************************** */

/*
  This function returns a virtual address to a congiguous set of allocated huge pages that don't cross a 1GB boundary.
  It optionally returns the identifier of the shared memory segment in case these pages need to shared
  with another process or additional attatches are needed to the segment (say for ring buffer wrapping).
  On failure, this function return NULL and sets errno to an appropriate value.

  IMPORTANT NOTES:   <-----------------------------------------------------------------
  1) No NUMA policy is attempted by this routine.
  The calling function is strongly recommended to do so prior to calling this function.
  2) All memory allocated is private to the process calling this function (IPC_PRIVATE).
  Even though is is allocated as shared memory, it cannot be shared with another process.
  This function could be extended to also return a shared memory handle for the allocated memory if
  if interprocess sharing of the allocated memory was required.
  3) Memory allocation is via a "greedy" grabbing process that may temporarily allocate far more hugepage
  memory than what was requested.
  4) If multiple processes are contending for hugepage memory allocations it is likely that system calls
  to shmget() fail temporarily. There is retry logic to reattempt.
  5) When NUMA policy is set for restrictive node binding and we completely deplete the hugepage pool for that node,
  I've noticed that invalid physical memory addresses are obtained (for memory segments that don't exist).
  This results in a SIGBUS exception. I've added graceful exception handling for this case to return a
  errno=ENOMEM (as it is reflective of an out of memory condition) to the caller rather than just faulting.
  6) If the shmidP argument is non-null we will return the shared memory segment id of the hugepages.
  The confilicts with setting the allocated pages for automatic cleanup. Caution is needed when using this
  capablity to avoid hugepage leaking.
*/

/* **************************************************** */

void *anic_hugepageGetAt(anic_handle_t anic_handle, int count, void *atP, int *shmidP) {
  void *virtAddress[MAX_SEGMENTS];
  unsigned long physAddress[MAX_SEGMENTS];
  int i, k;
  int j = 0;
  void *vP;
  unsigned long pa;
  void *tP;
  struct anic_dma_info iocb;
  int shmid;
  int cnt;
  void *rtn = NULL;
  int tryCount;

  // Start grabbing free hugepages until we get a large enough contiguous group
  for (i = 0; i < MAX_SEGMENTS; i++) {
    tryCount = 0;
    do {
      // see note #4 above
      shmid = shmget(IPC_PRIVATE, HUGEPAGE_SIZE, SHM_HUGETLB|IPC_CREAT|SHM_R|SHM_W);
      if (shmid == -1) {
        fprintf(stderr, "try\n");
        if (errno != ENOMEM || ++tryCount > (MAX_ATTEMPTS - 1)) {
          fprintf(stderr, "anic_hugepageGetAt() shmget() failed errno:%u %s\n", errno, strerror(errno));
          goto cleanup;  // errno set by shmget()
        }
        sleep(1);
      }
    } while (shmid == -1);
    vP = shmat(shmid, NULL, SHM_RND);
    if (vP == (void *)-1) {
      fprintf(stderr, "anic_hugepageGetAt() shmat() failed errno:%d %s\n", errno, strerror(errno));
      goto cleanup;  // errno set by shmat()
    }
    shmctl(shmid, IPC_RMID, NULL);   // when the process exits, cleanup

    // setup context target for signal handler
    if (setjmp(l_jumpEnv)) {
      fprintf(stderr, "anic_hugepageGetAt() SIGBUS handled\n");
      errno = ENOMEM;
      goto cleanup;
    }

    // force creation of PTE for hugepage
    l_savedHandler = signal(SIGBUS, l_sigbusHandler);   // see note #5 above
    memset(vP, 0xff, 256);
    signal(SIGBUS, l_savedHandler);

    // determine physical address
    iocb.userVirtualAddress = vP;
    iocb.length = 0;
    if (anic_get_physical_address(anic_handle, &iocb))
      abort();
    pa = iocb.cpuPhysicalAddress;
    //  printf("allocated: 0x%016lx / 0x%016lx\n", (long)vP, (long)pa);

    // find where to insert in the list of segments based on physical address
    // (the performance of this could be vastly improved for large lists as a tree or even a binary search)
    for (j = 0; j < i; j++) {
      if (pa < physAddress[j])
        break;
    }
    for (k = i; k > j; k--) {
      virtAddress[k] = virtAddress[k-1];
      physAddress[k] = physAddress[k-1];
    }
    virtAddress[j] = vP;
    physAddress[j] = pa;

    // Do we now have a large enough contiguous group that doesn't cross a 1GB boundary?
    j = 0;
    cnt = 0;
    while (j <= i) {
      pa = physAddress[j] + (count * HUGEPAGE_SIZE) - 1;
#if defined(METADATA_MODE_ENA)
      // For Metadata mode firmware, an internal adder limitation requires that buffers not cross 1GB boundaries.
      if ((physAddress[j] ^ pa) & 0x40000000) {
#else
	// In stardard firmwares regardless of DMA48 support, buffers cannot cross 32GB boundaries.
	if ((physAddress[j] ^ pa) & 0x800000000) {
#endif
	  j++;
	  continue;
	}
	cnt = 1;
	pa = physAddress[j];
	for (k = j+1; k <= i; k++) {
	  pa = pa + HUGEPAGE_SIZE;
	  if (physAddress[k] == pa)
	    cnt++;
	  else
	    break;
	}
	if (cnt < count)
	  j = k;
	else
	  break;
      }
      if (cnt < count) {
	continue;   // neet to get another segment and reanalyze
      }
      else {
	i++;   // "i" is always the number of slots used (even if it maxes out)
	break;
      }
    }

    // If we hit here we have enough contiguous segments at slot[j] and we should be able fetch them with both
    // contiguous virtual and physical addresses.
    // Free them in reverse order (kernel free lists are maintained as LIFO).
    k = j+count;
    while (j <= --k) {
      if (shmdt(virtAddress[k]) == -1) {
	// If this detach failed, something is seriously wrong, we probabably wouldn't be able to gracefully cleanup.
	// abort() is approprite here, as the process death cleanup is the only chance to avoid leaking hugepages.
	fprintf(stderr, "anic_hugepageGetAt() shmdt() failed--aborting\n");
	fflush(stderr);
	abort();
      }
      virtAddress[k] = NULL;
    }

    // Attempt to reallocate as a continguous virtual address.
    tryCount = 0;
    do {
      // see note #4 above
      shmid = shmget(IPC_PRIVATE, HUGEPAGE_SIZE * count, SHM_HUGETLB|IPC_CREAT|SHM_R|SHM_W);
      if (shmid == -1) {
	if (errno != ENOMEM || ++tryCount > (MAX_ATTEMPTS - 1)) {
	  fprintf(stderr, "anic_hugepageGetAt() shmget() failed errno:%u %s\n", errno, strerror(errno));
	  goto cleanup;  // errno set by shmget()
	}
	fprintf(stderr, "anic_hugepageGetAt() retry\n");
	sleep(1);
      }
    } while (shmid == -1);
    vP = shmat(shmid, atP, (atP==NULL)?SHM_RND:SHM_REMAP);
    if (vP == (void *)-1) {
      fprintf(stderr, "anic_hugepageGetAt(line:%u) shmat(0x%lx) failed errno:%d %s\n", __LINE__, (long)atP, errno, strerror(errno));
      goto cleanup;   // errno set by shmat()
    }

    // Create the PTEs for the hugepages and verify the physical addresses are still contiguous.
    // IMPORTANT NOTE <-------------------------------------------------
    // Under hugepage allocation contention from other processes, it is possible for this to fail.
    // If that is the case, we'll set an errno value to indicate that retrying from the caller is appropriate.
    for (j = 0; j < count; j++) {
      tP = (char *)vP + (j * HUGEPAGE_SIZE);
      l_savedHandler = signal(SIGBUS, l_sigbusHandler);   // see note #5 above
      memset(tP, 0xff, 256);
      signal(SIGBUS, l_savedHandler);
      iocb.userVirtualAddress = tP;
      iocb.length = 0;
      anic_get_physical_address(anic_handle, &iocb);
      if (j == 0) {
	pa = iocb.cpuPhysicalAddress;
      } else {
	if ((pa + (j * HUGEPAGE_SIZE)) != iocb.cpuPhysicalAddress) {
	  //      fprintf(stderr, "anic_hugepageGetAt() unexpected physical adddress:0x%016lx instead of:0x%016lx\n", (long)iocb.cpuPhysicalAddress, pa+(j*HUGEPAGE_SIZE));
	  shmctl(shmid, IPC_RMID, NULL);   // when the process exits, cleanup
	  if (shmdt(vP) == -1) {
	    // If this detach failed, something is seriously wrong, we probabably wouldn't be able to gracefully cleanup.
	    // abort() is approprite here, as the process death cleanup is the only chance to avoid leaking hugepages.
	    fprintf(stderr, "anic_hugepageGetAt() shmdt() failed--aborting\n");
	    fflush(stderr);
	    abort();
	  }
	  errno = EAGAIN;
	  goto cleanup;
	}
      }
    }

    // Success
    if (shmidP != NULL)
      *shmidP = shmid;
    else
      shmctl(shmid, IPC_RMID, NULL);   // when the process exits, cleanup
    rtn = vP;

  cleanup:
    // Return the unused memory segments (that weren't contiguous and were part of the greedy grab).
    while (--i >= 0) {
      if (virtAddress[i] != NULL) {
	//    printf("returned:  0x%016lx / 0x%016lx\n", (long)virtAddress[i], (long)physAddress[i]);
	if (shmdt(virtAddress[i]) == -1) {
	  // If this detach failed, something is seriously wrong, we probabably wouldn't be able to gracefully cleanup.
	  // abort() is approprite here, as the process death cleanup is the only chance to avoid leaking hugepages.
	  fprintf(stderr, "anic_hugepageGetAt() shmdt() failed--aborting\n");
	  fflush(stderr);
	  shmctl(shmid, IPC_RMID, NULL);
	  abort();
	}
      }
    }
    return rtn;
}

/* **************************************************** */

void *anic_hugepageGet(anic_handle_t anic_handle, int count, int *shmidP) {
  return anic_hugepageGetAt(anic_handle, count, NULL, shmidP);
}

/* **************************************************** */

/*
 * This function creates a DMA mapping for a set of contiguous 2MB hugepages and returns an ANIC DMA descriptor with
 * the DMA address to be used by the ANIC as well as state information needed for the kernel to unmap DMA.
 */
int anic_hugepageDmaMap(anic_handle_t anic_handle, void *virtualP, int hugepageCount, struct anic_dma_info *dmacbP) {
  struct anic_dma_info iocb;
  int rtn;

  iocb.userVirtualAddress = virtualP;
  iocb.length = hugepageCount * HUGEPAGE_SIZE;
  iocb.pageShift = ANIC_2M_PAGE;
  rtn = anic_map_dma(anic_handle, &iocb);
  *dmacbP = iocb;
  return rtn;
}

/* **************************************************** */

static inline void l_createHeader(pfring_anic *accolade, unsigned blocksize, struct anic_blkstatus_s *status_p) {
  uint8_t *buf_p = status_p->buf_p;
  struct block_header_s *header_p = (struct block_header_s *) buf_p;
  struct anic_descriptor_rx_packet_data *desc_p;

  header_p->block_size = blocksize;
  header_p->packet_count = status_p->pktcnt;

#ifdef MFL_SUPPORT
  if (accolade->mfl_mode) {
    header_p->first_offset = status_p->firstpkt_offset;
    header_p->last_offset = status_p->lastpkt_offset;
  }
#endif

  desc_p = (struct anic_descriptor_rx_packet_data *) &buf_p[status_p->firstpkt_offset];
  header_p->first_timestamp = desc_p->timestamp;

  desc_p = (struct anic_descriptor_rx_packet_data *) &buf_p[status_p->lastpkt_offset];
  header_p->last_timestamp = desc_p->timestamp;

  header_p->byte_count = status_p->lastpkt_offset + desc_p->length;
}

/* **************************************************** */

static int __pfring_anic_ready(pfring *ring) {
  pfring_anic *accolade = (pfring_anic *) ring->priv_data;
  int blk, i, blocks_ready;
  struct anic_blkstatus_s blkstatus;
  struct block_status *blkstatusP;

  if (accolade->currentblock.processing) 
    return 1;

#ifdef MFL_SUPPORT
  if (!accolade->mfl_mode) {
#endif

prepare_anic_block:
  if (accolade->wq.tail != accolade->wq.head) {
    /* Block ready to be processed in the queue */

    accolade->currentblock.blk = accolade->wq.entryA[accolade->wq.tail];

    if (++accolade->wq.tail > ACCOLADE_BUFFER_COUNT)
      accolade->wq.tail = 0;

    accolade->currentblock.blkstatus_p = &accolade->l_blkStatusA[accolade->currentblock.blk].blkStatus;
    accolade->currentblock.buf_p = &accolade->currentblock.blkstatus_p->buf_p[accolade->currentblock.blkstatus_p->firstpkt_offset];

    accolade->currentblock.processing = 1;
    return 1;
  }

  /* Work queue is empty, service anic rings */
  blocks_ready = 0;
  for (i = 0; i < 3; i++) { /* pull up to 4 blocks off for each ring */
    if (anic_block_get(accolade->anic_handle, 0 /* threadId */, accolade->ring_id, &blkstatus) > 0) {
      blocks_ready = 1;
      blk = blkstatus.blkid;
      blkstatus.buf_p = accolade->l_blkA[blk].buf_p; /* virtual address of the block */
      l_createHeader(accolade, accolade->blocksize, &blkstatus);
      blkstatusP = &accolade->l_blkStatusA[blk];

      if (blkstatusP->refcount != 0) {
        printf("refcount:%u not zero blk:%u\n", blkstatusP->refcount, blk);
        return -1;
      }
      blkstatusP->refcount = 1;

      blkstatusP->blkStatus = blkstatus;
      accolade->wq.entryA[accolade->wq.head] = blk;
      if (++accolade->wq.head > ACCOLADE_BUFFER_COUNT)
        accolade->wq.head = 0;
    } else break;
  }

  if (blocks_ready)
    goto prepare_anic_block;

#ifdef MFL_SUPPORT
  } else { /* (accolade->mfl_mode) */
    struct block_header_s /* bufheader_s */ *header_p;
    uint8_t *buf_p;
	
    if (anic_block_get(accolade->anic_handle, accolade->ring_id, accolade->ring_id, &blkstatus) > 0) {
      blk = blkstatus.blkid;
      buf_p = accolade->l_blkA[blk].buf_p;
      if (buf_p == NULL) {
        fprintf(stderr, "anic_block_get(ring:%u) blk:%u never added\n", accolade->ring_id, blk);
        exit(-1);
      }
      blkstatus.buf_p = buf_p;
      header_p = (struct block_header_s /* bufheader_s */ *) buf_p;
      l_createHeader(accolade, accolade->blocksize, &blkstatus);
    	
      accolade->currentblock.blk = blk;

      accolade->currentblock.last_buf_p = &buf_p[header_p->last_offset];

      accolade->currentblock.buf_p = &buf_p[header_p->first_offset]; 

#ifdef DEBUG
      printf("[ANIC] Processing block %u va=%llu va-first=%llu va-last=%llu\n", blk, buf_p, accolade->currentblock.buf_p, accolade->currentblock.last_buf_p);
#endif

      accolade->currentblock.processing = 1;
      return 1;    
    }
	
  }
#endif

  return 0;
}

/* **************************************************** */

void __pfring_anic_recv_pkt(pfring *ring, u_char **buffer, u_int buffer_len, struct pfring_pkthdr *hdr) {
  pfring_anic *accolade = (pfring_anic *) ring->priv_data;
  struct anic_descriptor_rx_packet_data *desc_p = (struct anic_descriptor_rx_packet_data *) accolade->currentblock.buf_p;
  struct block_status *blkstatusP = &accolade->l_blkStatusA[accolade->currentblock.blk];

  hdr->len = hdr->caplen = desc_p->length - 16;

#ifdef DEBUG
  if (desc_p->length < 76) {
    printf("Wrong packet len=%u\n", desc_p->length);
    exit(-1);
  }
#endif

  if (likely(buffer_len == 0)) {
    *buffer = (uint8_t *) &desc_p[1];
  } else {
    if (buffer_len < hdr->caplen) 
      hdr->caplen = buffer_len;
    memcpy(*buffer, (uint8_t *) &desc_p[1], hdr->caplen);
    memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
    pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
  }

#ifdef DEBUG
  //printf("[ANIC] Packet %u bytes [%llu]\n", desc_p->length, accolade->currentblock.buf_p);
#endif

  hdr->caplen = min_val(hdr->caplen, ring->caplen);
  hdr->extended_hdr.pkt_hash = 0; //TODO available?
  hdr->extended_hdr.if_index = UNKNOWN_INTERFACE; //TODO
  hdr->extended_hdr.rx_direction = 1;

  //if (unlikely((buffer_len && !ring->disable_timestamp) || ring->force_timestamp)) {
    hdr->ts.tv_sec  = (desc_p->timestamp >> 32);
    hdr->ts.tv_usec = (desc_p->timestamp & 0xffffffff) / 1000;
  //} else { /* do not set the timestamp for consistency */
  //  hdr->ts.tv_sec = 0, hdr->ts.tv_usec = 0;
  //}
  hdr->extended_hdr.timestamp_ns = ((desc_p->timestamp >> 32) * 1000000000) + (desc_p->timestamp & 0xffffffff);

  accolade->rstats.packets++;
  accolade->rstats.bytes += hdr->len;
  if (desc_p->anyerr)
    accolade->rstats.packet_errors++;
  if (desc_p->timestamp < accolade->lastTs)
    accolade->rstats.timestamp_errors++;
  accolade->lastTs = desc_p->timestamp;

  accolade->currentblock.buf_p += (desc_p->length + 7) & ~7;

#ifdef MFL_SUPPORT
  if (!accolade->mfl_mode) {
#endif
  if (accolade->currentblock.buf_p > &accolade->currentblock.blkstatus_p->buf_p[accolade->currentblock.blkstatus_p->lastpkt_offset]) { 
    accolade->currentblock.processing = 0;
    blkstatusP->refcount = 0;
    anic_block_add(accolade->anic_handle, 0 /* threadId */, accolade->currentblock.blk, 0, 
      accolade->l_blkA[accolade->currentblock.blk].dma_address);
  }
#ifdef MFL_SUPPORT
  } else { /* (accolade->mfl_mode) */
    if  (accolade->currentblock.buf_p > accolade->currentblock.last_buf_p) {
      int newblk, blk = accolade->currentblock.blk;
	
#ifdef DEBUG
      printf("[ANIC] Done block %u\n", blk);
#endif

      accolade->currentblock.processing = 0;
      newblk = anic_block_add(accolade->anic_handle, accolade->ring_id, 0, accolade->ring_id, accolade->l_blkA[blk].dma_address);

      if (newblk < 0) {
        fprintf(stderr, "anic_block_add(ring:%u) failed, oversubscribed?\n", accolade->ring_id);
        return;
      }

      if (newblk != blk) {
        if (accolade->l_blkA[newblk].buf_p != NULL) {
          fprintf(stderr, "blk already in use newblk:%u\n", blk);
          exit(-1);
        }
#ifdef DEBUG
        printf("[ANIC] New block %u dma=%llu\n", newblk, accolade->l_blkA[blk].dma_address);
#endif
        accolade->l_blkA[newblk].buf_p = accolade->l_blkA[blk].buf_p;
        accolade->l_blkA[newblk].dma_address = accolade->l_blkA[blk].dma_address;
        memset(&accolade->l_blkA[blk], 0, sizeof(accolade->l_blkA[blk]));
      }
    }
  }	
#endif
}

/* **************************************************** */

int pfring_anic_recv(pfring *ring, u_char **buffer,
		     u_int buffer_len,
		     struct pfring_pkthdr *hdr,
		     u_int8_t wait_for_incoming_packet) {

check_pfring_anic_ready:
  if (__pfring_anic_ready(ring) > 0) {
    __pfring_anic_recv_pkt(ring, buffer, buffer_len, hdr);
    return 1;
  }

  if (wait_for_incoming_packet) {
    if (unlikely(ring->break_recv_loop)) {
      ring->break_recv_loop = 0;
      return -1;
    }

    usleep(1000);
    goto check_pfring_anic_ready;
  }

  return 0;
}

/* **************************************************** */

int pfring_anic_poll(pfring *ring, u_int wait_duration) {
  u_int64_t elapsed = 0, wait_duration_usec = wait_duration > 0 ? (wait_duration * 1000) : 0;

  if (wait_duration == 0)
    return __pfring_anic_ready(ring);

  while (likely(!ring->break_recv_loop && (wait_duration < 0 || elapsed++ < wait_duration_usec))) {
    if (__pfring_anic_ready(ring))
      return 1;
    usleep(1);
  }

  return 0;
}

/* **************************************************** */

