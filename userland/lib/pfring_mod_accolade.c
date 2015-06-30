/*
 *
 * (C) 2015    - ntop.org
 * (C) 2014-15 - Accolade Technology Inc.
 *
 */

#include "pfring_mod_accolade.h"
#include "pfring_mod.h" /* to print stats under /proc */

void *anic_hugepageGet(anic_handle_t anic_handle, int count, int *shmidP);
int anic_hugepageDmaMap(anic_handle_t anic_handle, void *virtualP, int hugepageCount, struct anic_dma_info *dmacbP);

/* **************************************************** */

static void accolade_release_resources(pfring *ring) {
  pfring_accolade *accolade = (pfring_accolade *)ring->priv_data;

  if(accolade) {
    anic_close(accolade->anic_handle);
    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

int pfring_accolade_open(pfring *ring) {
  pfring_accolade *accolade;
  int i;
  u_int32_t page, block;

  ring->close              = pfring_accolade_close;
  ring->stats              = pfring_accolade_stats;
  ring->recv               = pfring_accolade_recv;
  ring->poll               = pfring_accolade_poll;
  ring->set_direction      = pfring_accolade_set_direction;
  ring->enable_ring        = pfring_accolade_enable_ring;
  ring->get_bound_device_ifindex = pfring_accolade_get_bound_device_ifindex;

  /* Inherited from pfring_mod.c */
  ring->set_socket_mode          = pfring_mod_set_socket_mode;
  ring->set_bound_dev_name       = pfring_mod_set_bound_dev_name;
  ring->set_application_name     = pfring_mod_set_application_name;
  ring->set_application_stats    = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;

  ring->priv_data = NULL;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL)); /* opening PF_RING socket to priaccolade stats under /proc */
  if(ring->fd < 0) return(-1);

  ring->priv_data = calloc(1, sizeof(pfring_accolade));

  if(ring->priv_data == NULL)
    goto free_private;

  accolade = (pfring_accolade*)ring->priv_data;

  /*
    Device name accoladeX@Y where

    X   deviceId
    Y   ringId
  */

  sscanf(&ring->device_name[8], "%u@%u",
	 &accolade->device_id, &accolade->ring_id);

  accolade->anic_handle = anic_open("/dev/anic", accolade->device_id);
  if(anic_error_code(accolade->anic_handle) != ANIC_ERR_NONE) {
    goto free_private;
  }

  if(accolade->anic_handle->is40k3) {
    if(anic_k325t_aurora_train(accolade->anic_handle)) {
      goto free_private;
    }
  }

  /* Reset the NIC */
  anic_reset_and_restart_pipeline(accolade->anic_handle);
  sleep(2);

  anic_pduproc_steer(accolade->anic_handle, ANIC_STEERLB);
  anic_pduproc_dma_pktseq(accolade->anic_handle, 1);

  if(anic_setup_rings_largelut(accolade->anic_handle, accolade->ring_id, 0, NULL)) {
    // if large LUT is not supported, fall back to normal LUT
    if(anic_setup_rings(accolade->anic_handle, accolade->ring_id, 0, NULL)) {
      fprintf(stderr, "ERROR: unsupported firmware revision\n");
      abort();
    }
  }

  anic_block_set_blocksize(accolade->anic_handle, accolade->blocksize_e);
  switch(accolade->blocksize_e) {
  case ANIC_BLOCK_4MB:
    accolade->blocksize = 2 * ACCOLADE_HUGEPAGE_SIZE;
    accolade->pages = ACCOLADE_BUFFER_COUNT;
    accolade->pageblocks = 1;
    break;
  case ANIC_BLOCK_2MB:
    accolade->blocksize = ACCOLADE_HUGEPAGE_SIZE;
    accolade->pages = ACCOLADE_BUFFER_COUNT;
    accolade->pageblocks = 1;
    break;
  case ANIC_BLOCK_1MB:
    accolade->blocksize = ACCOLADE_HUGEPAGE_SIZE / 2;
    accolade->pages = ACCOLADE_BUFFER_COUNT / 2;
    accolade->pageblocks = 2;
    break;
  default:
    goto free_private;
  }

  for(page = 0, block = 0; page < accolade->pages; page++) {
    void *vP;
    u_int8_t *buf_p;
    struct anic_dma_info dmaInfo;
    u_int8_t count = (accolade->blocksize_e == ANIC_BLOCK_4MB) ? 2 : 1;

    if((vP = anic_hugepageGet(accolade->anic_handle, count, NULL)) == NULL) {
      fprintf(stderr, "anic_hugepageGet() failed errno:%u %s\n", errno, strerror(errno));
      goto free_private;
    }

    if(anic_hugepageDmaMap(accolade->anic_handle, vP, count, &dmaInfo)) {
      fprintf(stderr, "anic_hugepageDmaMap()\n");
      goto free_private;
    }

    buf_p = (uint8_t *)dmaInfo.userVirtualAddress;

    for(i=0; i<accolade->pageblocks; i++) {
      accolade->l_blkA[block].buf_p = buf_p + i*accolade->blocksize;
      accolade->l_blkA[block].dma_address = dmaInfo.dmaPhysicalAddress + i*accolade->blocksize;
      anic_block_add(accolade->anic_handle, 0, block, 0, accolade->l_blkA[block].dma_address);
      block++;
    }
  }

  ring->poll_duration = DEFAULT_POLL_DURATION;

  return 0;

 free_private:
  accolade_release_resources(ring);

  return(-1);
}

/* **************************************************** */

void pfring_accolade_close(pfring *ring) {
  accolade_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_accolade_stats(pfring *ring, pfring_stat *stats) {
  //pfring_accolade *accolade = (pfring_accolade *) ring->priv_data;

  //stats->recv = accolade->ring.stats.total_packets, stats->drop = 0; /* TODO */
  return(0);
}

/* **************************************************** */

int pfring_accolade_set_direction(pfring *ring, packet_direction direction) {
  if(direction == rx_only_direction || direction == rx_and_tx_direction) {
    return(setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction)));
  }

  return(-1);
}

/* **************************************************** */

int pfring_accolade_enable_ring(pfring *ring) {
  pfring_accolade *accolade = (pfring_accolade *) ring->priv_data;

  /* Enable ring */
  anic_block_set_ring_nodetag(accolade->anic_handle, accolade->ring_id, 0);
  anic_block_ena_ring(accolade->anic_handle, accolade->ring_id, 1);

  /* Set 1 msec block timeouts */
  anic_block_set_timeouts(accolade->anic_handle, 1000, 1000);

  return(0);
}

/* **************************************************** */

int pfring_accolade_poll(pfring *ring, u_int wait_duration) {
  /* TODO */
  return 1;
}

/* ******************************* */

int pfring_accolade_get_bound_device_ifindex(pfring *ring, int *if_index) {
  //pfring_accolade *accolade = (pfring_accolade *) ring->priv_data;

  *if_index = 0; /* FIX */
  return 0;
}

/* ******************************* */
/* ******************************* */

/* External functions (anic_hugepage_support.c) */

#define HUGEPAGE_SIZE (1 << ANIC_2M_PAGE)
#define MAX_ATTEMPTS (16)

// At the moment, the ANIC only supports up to 2**35 (32 Gbyte) physical memory. This corresponds to at most 16K 2Mbyte segments.
# define MAX_SEGMENTS 16384



// file scoped globals
static jmp_buf l_jumpEnv;
static void (*l_savedHandler)(int);



static void l_sigbusHandler(int signum)
{
  // restore saved signal handler and force error handling
  signal(signum, l_savedHandler);
  longjmp(l_jumpEnv, 1);
}



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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
void *anic_hugepageGetAt(anic_handle_t anic_handle, int count, void *atP, int *shmidP)
{
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

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  void *anic_hugepageGet(anic_handle_t anic_handle, int count, int *shmidP)
  {
    return anic_hugepageGetAt(anic_handle, count, NULL, shmidP);
  }



  /*
    This function creates a DMA mapping for a set of contiguous 2MB hugepages and returns an ANIC DMA descriptor with
    the DMA address to be used by the ANIC as well as state information needed for the kernel to unmap DMA.
  */

  int anic_hugepageDmaMap(anic_handle_t anic_handle, void *virtualP, int hugepageCount, struct anic_dma_info *dmacbP)
  {
    struct anic_dma_info iocb;
    int rtn;

    iocb.userVirtualAddress = virtualP;
    iocb.length = hugepageCount * HUGEPAGE_SIZE;
    iocb.pageShift = ANIC_2M_PAGE;
    rtn = anic_map_dma(anic_handle, &iocb);
    *dmacbP = iocb;
    return rtn;
  }



  /*
    This function removes a DMA mapping for a set of contiguous hugepages previously mapped with anic_hugepageDmaMap().
  */

  int anic_hugepageDmaUnmap(anic_handle_t anic_handle, struct anic_dma_info *dmacbP)
  {
    return anic_unmap_dma(anic_handle, dmacbP);
  }

  // ------------------------------------------------------------------------------

  static inline void l_createHeader(unsigned blocksize, struct anic_blkstatus_s *status_p)
  {
    uint8_t *buf_p = status_p->buf_p;
    struct blkheader_s *header_p = (struct blkheader_s *)buf_p;
    struct anic_descriptor_rx_packet_data *desc_p;

    header_p->block_size = blocksize;
    header_p->packet_count = status_p->pktcnt;
    desc_p = (struct anic_descriptor_rx_packet_data *)&buf_p[status_p->firstpkt_offset];
    header_p->first_timestamp = desc_p->timestamp;
    desc_p = (struct anic_descriptor_rx_packet_data *)&buf_p[status_p->lastpkt_offset];
    header_p->last_timestamp = desc_p->timestamp;
    header_p->byte_count = status_p->lastpkt_offset + desc_p->length;
  }

  /* **************************************************** */

  uint64_t l_validateBlk(int blk, uint64_t ts) {
    printf("%s\n", __FUNCTION__);

    return(0); // TODO
  }

  /* **************************************************** */
  int pfring_accolade_recv(pfring *ring, u_char **buffer,
			   u_int buffer_len,
			   struct pfring_pkthdr *hdr,
			   u_int8_t wait_for_incoming_packet) {
    pfring_accolade *accolade = (pfring_accolade *)ring->priv_data;
    int blk, i, we_have_something_to_do;
    struct anic_blkstatus_s blkstatus;
    struct blkstatus *blkstatusP;

    printf("%s\n", __FUNCTION__);

  do_pfring_accolade_recv:
    if(accolade->wq.tail != accolade->wq.head) {
      /* Looks like there is something to do */
      int ring_id;

      blk = accolade->wq.entryA[accolade->wq.tail];

      if(accolade->wq.tail < ACCOLADE_BUFFER_COUNT)
	accolade->wq.tail++;
      else
	accolade->wq.tail = 0;

      blkstatusP = &accolade->l_blkStatusA[blk];
      ring_id = blkstatusP->blkStatus.ringid;
      accolade->lastTs[ring_id] = l_validateBlk(blk, accolade->lastTs[ring_id]);
      blkstatusP->refcount = 0;
      anic_block_add(accolade->anic_handle, 0 /* threadId */, blk,
		     0, accolade->l_blkA[blk].dma_address);
      return(1);
    }

    // work queue is empty, service anic rings
    we_have_something_to_do = 0;
    for(i = 0; i < 3; i++) {   // pull up to 4 blocks off for each ring
      int blkcnt = anic_block_get(accolade->anic_handle, 0 /* threadId */,
				  accolade->ring_id, &blkstatus);

      if(blkcnt > 0) {
	we_have_something_to_do = 1;
	blk = blkstatus.blkid;
	// patch in the virtual address of the block base
	blkstatus.buf_p = accolade->l_blkA[blk].buf_p;
	// create the block header
	l_createHeader(accolade->blocksize, &blkstatus);
	blkstatusP = &accolade->l_blkStatusA[blk];
	if(blkstatusP->refcount != 0) {
	  printf("refcount:%u not zero blk:%u\n", blkstatusP->refcount, blk);
	  return(-1);
	}
	blkstatusP->refcount = 1;
	blkstatusP->blkStatus = blkstatus;
	accolade->wq.entryA[accolade->wq.head] = blk;
	if(accolade->wq.head < ACCOLADE_BUFFER_COUNT)
	  accolade->wq.head++;
	else
	  accolade->wq.head = 0;
      }
      else
	break;  // next ring
    }

    if(we_have_something_to_do)
      goto do_pfring_accolade_recv;

    if(wait_for_incoming_packet) {
      usleep(1000);
      goto do_pfring_accolade_recv;
    }

    return(0);
  }
