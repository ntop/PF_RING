/*
 *
 * (C) 2005-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_utils.h"
#include "pfring_hw_filtering.h"
#include "pfring_mod_dna.h"

//#define RING_DEBUG

/* ******************************* */

static int pfring_map_dna_device(pfring *ring,
				 zc_dev_operation operation,
				 char *device_name) {
  zc_dev_mapping mapping;

  if(ring->dna.last_dna_operation == operation) {
    fprintf(stderr, "%s(): operation (%s) already performed\n",
	    __FUNCTION__, operation == remove_device_mapping ?
	    "remove_device_mapping" : "add_device_mapping");
    return (-1);
  } else
    ring->dna.last_dna_operation = operation;

  memset(&mapping, 0, sizeof(mapping));
  mapping.operation = operation;
  snprintf(mapping.device_name, sizeof(mapping.device_name),
	   "%s", device_name);
  mapping.channel_id = ring->dna.dna_dev.channel_id;

  return(ring ? setsockopt(ring->fd, 0, SO_MAP_DNA_DEVICE,
			   &mapping, sizeof(mapping)): -1);
}

/* **************************************************** */

void pfring_dna_close(pfring *ring) {
  int i, rc = 0;

  if(ring->dna_term)
    ring->dna_term(ring);

  for(i=0; i<ring->dna.dna_dev.mem_info.rx.packet_memory_num_chunks; i++) {
    if(ring->dna.dna_dev.rx_packet_memory[i] != 0) {
      if(munmap((void *) ring->dna.dna_dev.rx_packet_memory[i],
	         ring->dna.dna_dev.mem_info.rx.packet_memory_chunk_len) == -1)
        rc = -1;      
    }
  }
  
  if(rc == -1) {
    fprintf(stderr, "Warning: unable to unmap rx packet memory [address=%p][size=%u]\n",
  	    (void *) ring->dna.dna_dev.rx_packet_memory, 
	    ring->dna.dna_dev.mem_info.rx.packet_memory_chunk_len *
	    ring->dna.dna_dev.mem_info.rx.packet_memory_num_chunks);
  }

  if(ring->dna.dna_dev.rx_descr_packet_memory != NULL) {
    rc = munmap(ring->dna.dna_dev.rx_descr_packet_memory, 
	        ring->dna.dna_dev.mem_info.rx.descr_packet_memory_tot_len);
    if(rc == -1) {
      fprintf(stderr, "Warning: unable to unmap rx description memory [address=%p][size=%u]\n",
	      ring->dna.dna_dev.rx_descr_packet_memory,
	      ring->dna.dna_dev.mem_info.rx.descr_packet_memory_tot_len);
    }
  }
  
  rc = 0;
  for(i=0; i<ring->dna.dna_dev.mem_info.tx.packet_memory_num_chunks; i++) {
    if(ring->dna.dna_dev.tx_packet_memory[i] != 0) {
      if(munmap((void *) ring->dna.dna_dev.tx_packet_memory[i],
	        ring->dna.dna_dev.mem_info.tx.packet_memory_chunk_len) == -1)
        rc = -1;
    }
  }

  if(rc == -1) {
    fprintf(stderr, "Warning: unable to unmap tx packet memory [address=%p][size=%u]\n",
            (void*)ring->dna.dna_dev.tx_packet_memory,
            ring->dna.dna_dev.mem_info.tx.packet_memory_chunk_len *
            ring->dna.dna_dev.mem_info.tx.packet_memory_num_chunks);
  }

  if(ring->dna.dna_dev.tx_descr_packet_memory != NULL) {
    rc = munmap(ring->dna.dna_dev.tx_descr_packet_memory, 
	        ring->dna.dna_dev.mem_info.tx.descr_packet_memory_tot_len);
    if(rc == -1) {
      fprintf(stderr, "Warning: unable to unmap xmit description memory [address=%p][size=%u]\n",
              ring->dna.dna_dev.tx_descr_packet_memory,
              ring->dna.dna_dev.mem_info.tx.descr_packet_memory_tot_len);
    }
  }

  if(ring->dna.dna_dev.phys_card_memory != NULL) {
    rc = munmap(ring->dna.dna_dev.phys_card_memory,
                ring->dna.dna_dev.mem_info.phys_card_memory_len);
    if(rc == -1) {
      fprintf(stderr, "Warning: unable to unmap physical card memory [address=%p][size=%u]\n",
  	      ring->dna.dna_dev.phys_card_memory, ring->dna.dna_dev.mem_info.phys_card_memory_len);
    }
  }

  pfring_map_dna_device(ring, remove_device_mapping, "");

  if(ring->clear_promisc)
    pfring_set_if_promisc(ring->device_name, 0);

  close(ring->fd);
}

/* **************************************************** */

int pfring_dna_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  /* nothing to do here, just returning success */
  return 0;
}

/* **************************************************** */

int pfring_dna_stats(pfring *ring, pfring_stat *stats) {
  stats->recv = ring->dna.tot_dna_read_pkts;
  stats->drop = ring->dna.tot_dna_lost_pkts;
  return(0);
}

/* **************************************************** */

int pfring_dna_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		    struct pfring_pkthdr *hdr,
		    u_int8_t wait_for_incoming_packet) {
  u_char *pkt = NULL;
  int8_t status = 0;

  if(unlikely(ring->reentrant)) pthread_rwlock_wrlock(&ring->rx_lock);

 redo_pfring_recv:
  if(ring->is_shutting_down || ring->break_recv_loop) {
    if(unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
    return(-1);
  }

  pkt = ring->dna_next_packet(ring, buffer, buffer_len, hdr);

  if(pkt && (hdr->len > 0)) {
    if(unlikely(ring->sampling_rate > 1)) {
      if (likely(ring->sampling_counter > 0)) {
        ring->sampling_counter--;
	goto redo_pfring_recv;
      } else {
        ring->sampling_counter = ring->sampling_rate-1;
      }
    }

    hdr->caplen = min_val(hdr->caplen, ring->caplen);
    if(unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
    return(1);
  }

  if(wait_for_incoming_packet) {
    status = ring->dna_check_packet_to_read(ring, wait_for_incoming_packet);

    if(status > 0)
      goto redo_pfring_recv;
  }

  if(unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
  return(0);
}

/* **************************************************** */

static int pfring_get_mapped_dna_device(pfring *ring, zc_dev_info *dev) {
  socklen_t len = sizeof(zc_dev_info);

  if(dev == NULL)
    return(-1);
  else
    return(getsockopt(ring->fd, 0, SO_GET_MAPPED_DNA_DEVICE,
		      &dev->mem_info, &len));
}

/* **************************************************** */

#ifdef DEBUG

static void pfring_dump_dna_stats(pfring* ring) {
  dna_dump_stats(ring);
}

#endif

/* **************************************************** */

int pfring_dna_get_card_settings(pfring *ring, pfring_card_settings *settings) {
  settings->max_packet_size = ring->dna.dna_dev.mem_info.rx.packet_memory_slot_len;
  settings->rx_ring_slots = ring->dna.dna_dev.mem_info.rx.packet_memory_num_slots;
  settings->tx_ring_slots = ring->dna.dna_dev.mem_info.tx.packet_memory_num_slots;
  return 0;
}

/* **************************************************** */

int pfring_dna_open(pfring *ring) {
  int   channel_id = 0;
  int   rc;
  int   i;
  char *at;

  ring->direction = rx_only_direction;

  ring->close = pfring_dna_close;
  ring->set_sampling_rate = pfring_dna_set_sampling_rate;
  ring->stats = pfring_dna_stats;
  ring->recv  = pfring_dna_recv;
  ring->enable_ring = pfring_dna_enable_ring;
  ring->set_direction = pfring_dna_set_direction;
  ring->poll = pfring_dna_poll;
  ring->set_tx_watermark = pfring_dna_set_tx_watermark;
  ring->set_poll_watermark = pfring_dna_set_poll_watermark;
  ring->get_card_settings = pfring_dna_get_card_settings;

  ring->set_poll_duration = pfring_mod_set_poll_duration;
  ring->set_channel_id = pfring_mod_set_channel_id;
  ring->set_application_name = pfring_mod_set_application_name;
  ring->set_application_stats = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;
  ring->bind = pfring_mod_bind;
  ring->get_num_rx_channels = pfring_mod_get_num_rx_channels;
  ring->get_selectable_fd = pfring_mod_get_selectable_fd;
  ring->set_socket_mode = pfring_mod_set_socket_mode;
  ring->get_ring_id = pfring_mod_get_ring_id;
  ring->version = pfring_mod_version;
  ring->get_bound_device_address = pfring_mod_get_bound_device_address;
  ring->get_bound_device_ifindex = pfring_mod_get_bound_device_ifindex;
  ring->get_device_ifindex = pfring_mod_get_device_ifindex;
  ring->get_slot_header_len = pfring_mod_get_slot_header_len;
  ring->set_virtual_device = pfring_mod_set_virtual_device;
  ring->add_hw_rule = pfring_hw_ft_add_hw_rule;
  ring->remove_hw_rule = pfring_hw_ft_remove_hw_rule;
  ring->loopback_test = pfring_mod_loopback_test;
  ring->disable_ring = pfring_mod_disable_ring;
  ring->handle_hash_filtering_rule = pfring_mod_handle_hash_filtering_rule;
  ring->add_filtering_rule = pfring_mod_add_filtering_rule;
  ring->remove_filtering_rule = pfring_mod_remove_filtering_rule;
  ring->toggle_filtering_policy = pfring_mod_toggle_filtering_policy;
  ring->shutdown = pfring_mod_shutdown;
  /* These functions are set by the dna library: (when supported by the device)
   * ring->send
   * ring->send_get_time
   * ring->next_pkt_time
   * ring->next_pkt_raw_timestamp
   * ring->set_device_clock
   * ring->get_device_clock
   */

  ring->poll_duration = DEFAULT_POLL_DURATION;
  ring->dna.last_dna_operation = remove_device_mapping;
  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

#ifdef DEBUG
  printf("Open RING [fd=%d]\n", ring->fd);
#endif

  if(ring->fd < 0)
    return -1;

  at = strchr(ring->device_name, '@');
  if(at != NULL) {
    at[0] = '\0';

    /* 
       Syntax
       ethX@1      channel 1
    */
    
    channel_id = atoi(&at[1]);
  }

  ring->dna.dna_dev.channel_id = channel_id;

  rc = pfring_map_dna_device(ring, add_device_mapping, ring->device_name);

  if(rc < 0) {
#if 0
    printf("pfring_map_dna_device() failed [rc=%d]: device already in use, channel not existing or non-DNA driver?\n", rc);
    printf("Make sure that you load the DNA-driver *after* you loaded the PF_RING kernel module\n");
#endif
    return -1;
  }

  rc = pfring_get_mapped_dna_device(ring, &ring->dna.dna_dev);

  if(rc < 0) {
    printf("pfring_get_mapped_dna_device() failed [rc=%d]\n", rc);
    pfring_map_dna_device(ring, remove_device_mapping, ring->device_name);
    close(ring->fd);
    return -1;
  }

#ifdef DEBUG
  printf("[num_slots=%d][slot_len=%d][tot_mem_len=%d]\n",
	 ring->dna.dna_dev.packet_memory_num_slots,
	 ring->dna.dna_dev.packet_memory_slot_len,
	 ring->dna.dna_dev.packet_memory_tot_len);
  printf("[memory_num_slots=%d][memory_slot_len=%d]"
	 "[memory_tot_len=%d]\n",
	 ring->dna.dna_dev.descr_packet_memory_num_slots,
	 ring->dna.dna_dev.descr_packet_memory_slot_len,
	 ring->dna.dna_dev.descr_packet_memory_tot_len);
#endif

  ring->zc_device = 1;

  /* ***************************************** */

  for(i=0; i<ring->dna.dna_dev.mem_info.rx.packet_memory_num_chunks; i++) {
    ring->dna.dna_dev.rx_packet_memory[i] =
      (unsigned long)mmap(NULL, ring->dna.dna_dev.mem_info.rx.packet_memory_chunk_len,
			  PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 
			  (100+i)*getpagesize());
      
    if(ring->dna.dna_dev.rx_packet_memory[i] == (unsigned long)MAP_FAILED) {
      printf("mmap(100/%d) failed", i);
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  for(i=0; i<ring->dna.dna_dev.mem_info.tx.packet_memory_num_chunks; i++) {
    ring->dna.dna_dev.tx_packet_memory[i] =
      (unsigned long)mmap(NULL, ring->dna.dna_dev.mem_info.tx.packet_memory_chunk_len,
			  PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 
			  (100+ring->dna.dna_dev.mem_info.rx.packet_memory_num_chunks+i)*getpagesize());
      
    if(ring->dna.dna_dev.tx_packet_memory[i] == (unsigned long)MAP_FAILED) {
      printf("mmap(100/%d) failed", i);
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if(ring->dna.dna_dev.mem_info.rx.descr_packet_memory_tot_len > 0) {
    ring->dna.dna_dev.rx_descr_packet_memory =
      (void*)mmap(NULL, ring->dna.dna_dev.mem_info.rx.descr_packet_memory_tot_len,
		  PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 1*getpagesize());

    if(ring->dna.dna_dev.rx_descr_packet_memory == MAP_FAILED) {
      printf("mmap(1) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if(ring->dna.dna_dev.mem_info.tx.descr_packet_memory_tot_len > 0) {
    ring->dna.dna_dev.tx_descr_packet_memory =
      (void*)mmap(NULL, ring->dna.dna_dev.mem_info.tx.descr_packet_memory_tot_len,
		  PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 3*getpagesize());

    if(ring->dna.dna_dev.tx_descr_packet_memory == MAP_FAILED) {
      printf("mmap(3) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if(ring->dna.dna_dev.mem_info.phys_card_memory_len > 0) {
    /* some DNA drivers do not use this memory */
    ring->dna.dna_dev.phys_card_memory =
      (void*)mmap(NULL, ring->dna.dna_dev.mem_info.phys_card_memory_len,
		  PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 2*getpagesize());

    if(ring->dna.dna_dev.phys_card_memory == MAP_FAILED) {
      printf("mmap(2) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if(ring->promisc) {
    if(pfring_set_if_promisc(ring->device_name, 1) == 0)
      ring->clear_promisc = 1;
  }

  /* ***************************************** */

  pfring_set_filtering_mode(ring, hardware_only);

  /* ***************************************** */

  rc = dna_init(ring, sizeof(pfring));

  if(rc < 0) {
    printf("dna_init() failed\n");
    close(ring->fd);
    return rc;
  }

  pfring_enable_hw_timestamp(ring, ring->device_name, ring->hw_ts.enable_hw_timestamp ? 1 : 0, 0 /* TX timestamp disabled by default */);

#ifdef DEBUG
  pfring_dump_dna_stats(ring);
#endif

  pfring_hw_ft_init(ring);

  return 0;
}

/* **************************************************** */

int pfring_dna_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  ring->dna.dna_rx_sync_watermark = watermark; 
  return pfring_mod_set_poll_watermark(ring, watermark);
}

/* ******************************* */

int pfring_dna_set_tx_watermark(pfring *ring, u_int16_t watermark) {
  ring->dna.dna_tx_sync_watermark = watermark;
  return 0;
}

/* ******************************* */

int pfring_dna_set_direction(pfring *ring, packet_direction direction) {
  if (direction != rx_only_direction)
    return -1;

  return pfring_mod_set_direction(ring, direction);
}

/* *********************************** */

int pfring_dna_enable_ring(pfring *ring) {
  int rc = pfring_mod_enable_ring(ring);

  if(rc < 0)
    return rc;

  rc = ring->dna_enable(ring);

  return rc;
}

/* *********************************** */

int pfring_dna_poll(pfring *ring, u_int wait_duration) {
  pfring_sync_indexes_with_kernel(ring);
  return pfring_mod_poll(ring, wait_duration);
}

/* *********************************** */

