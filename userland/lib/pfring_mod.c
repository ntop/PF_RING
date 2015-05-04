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

#ifdef ENABLE_BPF
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <linux/types.h>
#include <linux/filter.h>
#endif

#include "pfring.h"
#include "pfring_utils.h"
#include "pfring_hw_filtering.h"
#include "pfring_mod.h"

// #define RING_DEBUG

#define MAX_NUM_LOOPS         1000
#define YIELD_MULTIPLIER        10

#define USE_MB

#define gcc_mb() __asm__ __volatile__("": : :"memory")

#if defined(__i386__) || defined(__x86_64__)
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")
#else /* other architectures (e.g. ARM) */
#define rmb() gcc_mb()
#define wmb() gcc_mb()
#endif

#define ALIGN(a,b) (((a) + ((b)-1) ) & ~((b)-1))

#if 0
unsigned long long rdtsc() {
  unsigned long long a;
  asm volatile("rdtsc":"=A" (a));
  return(a);
}
#endif

/* **************************************************** */

inline int pfring_there_is_pkt_available(pfring *ring) {
#if 1
  return(ring->slots_info->tot_insert != ring->slots_info->tot_read);
#else
  /* stronger check: */
  return ((ring->slots_info->remove_off != ring->slots_info->insert_off && 
          (ring->slots_info->tot_insert != ring->slots_info->tot_read)) || 
         ((ring->slots_info->remove_off == ring->slots_info->insert_off) && 
	 ((ring->slots_info->tot_insert - ring->slots_info->tot_read) >= ring->slots_info->min_num_slots)));
#endif
}

/* **************************************************** */

int pfring_mod_open_setup(pfring *ring) {
  int rc;
  u_int memSlotsLen;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

  if(ring->fd < 0)
    return -1;

#ifdef RING_DEBUG
  printf("[PF_RING] Open RING [fd=%d]\n", ring->fd);
#endif

  if(ring->caplen > MAX_CAPLEN) ring->caplen = MAX_CAPLEN;
  rc = setsockopt(ring->fd, 0, SO_RING_BUCKET_LEN, &ring->caplen, sizeof(ring->caplen));

  if(rc < 0) {
    close(ring->fd);
    return -1;
  }

  if(!ring->long_header) {
    rc = setsockopt(ring->fd, 0, SO_USE_SHORT_PKT_HEADER, &ring->long_header, sizeof(ring->long_header));
    
    if(rc < 0) {
      close(ring->fd);
      return -1;
    }
  }

  if(!strcmp(ring->device_name, "none")) {
    /* No binding yet */
    rc = 0;
  } else /* "any" or "<interface name>" */
    rc = pfring_bind(ring, ring->device_name);

  if(rc < 0) {
    close(ring->fd);
    return -1;
  }

  ring->kernel_packet_consumer = 0;

  ring->buffer = (char *)mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
			      MAP_SHARED, ring->fd, 0);

  if(ring->buffer == MAP_FAILED) {
    fprintf(stderr, "[PF_RING] mmap() failed: try with a smaller snaplen\n");
    close(ring->fd);
    return -1;
  }

  ring->slots_info = (FlowSlotInfo *)ring->buffer;
  if(ring->slots_info->version != RING_FLOWSLOT_VERSION) {
    fprintf(stderr, "[PF_RING] Wrong RING version: "
	   "kernel is %i, libpfring was compiled with %i\n",
	   ring->slots_info->version, RING_FLOWSLOT_VERSION);
    close(ring->fd);
    return -1;
  }
  memSlotsLen = ring->slots_info->tot_mem;
  
  if(munmap(ring->buffer, PAGE_SIZE) == -1) {
    fprintf(stderr, "[PF_RING] Warning: unable to unmap ring buffer memory [address=%p][size=%u]\n",
            ring->buffer, PAGE_SIZE);
  }

  ring->buffer = (char *)mmap(NULL, memSlotsLen,
			      PROT_READ|PROT_WRITE,
			      MAP_SHARED, ring->fd, 0);

  if(ring->buffer == MAP_FAILED) {
    fprintf(stderr, "[PF_RING] mmap() failed");
    close(ring->fd);
    return -1;
   }

   ring->slots_info = (FlowSlotInfo *)ring->buffer;
   ring->slots = (char *)(ring->buffer+sizeof(FlowSlotInfo));

#ifdef RING_DEBUG
  printf("RING (%s): tot_mem=%u/max_slot_len=%u/"
	 "insert_off=%llu/remove_off=%llu/dropped=%lu\n",
	 ring->device_name, ring->slots_info->tot_mem,
	 ring->slots_info->slot_len,   ring->slots_info->insert_off,
	 ring->slots_info->remove_off, ring->slots_info->tot_lost);
#endif

  if(ring->promisc) {
    if(pfring_set_if_promisc(ring->device_name, 1) == 0)
      ring->clear_promisc = 1;
  }

  ring->slot_header_len = pfring_get_slot_header_len(ring);
  if(ring->slot_header_len == (u_int16_t)-1) {
    fprintf(stderr, "[PF_RING] ring failure (pfring_get_slot_header_len)\n");
    close(ring->fd);
    return -1;
  }

  pfring_hw_ft_init(ring);

  if(ring->tx.enabled_rx_packet_send) {
    int dummy = 0;
    if(setsockopt(ring->fd, 0, SO_ENABLE_RX_PACKET_BOUNCE, &dummy, sizeof(dummy)) < 0) {
      fprintf(stderr, "[PF_RING] failure enabling rx packet bounce support\n");
      close(ring->fd);
      return -1;
    }
  }

  return(0);
}

/* **************************************************** */

int pfring_mod_open(pfring *ring) {
  /* Setting pointers, we need these functions soon */
  ring->close = pfring_mod_close;
  ring->stats = pfring_mod_stats;
  ring->recv  = pfring_mod_recv;
  ring->set_poll_watermark = pfring_mod_set_poll_watermark;
  ring->set_poll_duration = pfring_mod_set_poll_duration;
  ring->set_channel_id = pfring_mod_set_channel_id;
  ring->set_channel_mask = pfring_mod_set_channel_mask;
  ring->set_application_name  = pfring_mod_set_application_name;
  ring->set_application_stats = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;
  ring->bind = pfring_mod_bind;
  ring->send = pfring_mod_send;
  ring->get_num_rx_channels = pfring_mod_get_num_rx_channels;
  ring->set_sampling_rate = pfring_mod_set_sampling_rate;
  ring->get_selectable_fd = pfring_mod_get_selectable_fd;
  ring->set_direction = pfring_mod_set_direction;
  ring->set_socket_mode = pfring_mod_set_socket_mode;
  ring->set_cluster = pfring_mod_set_cluster;
  ring->remove_from_cluster = pfring_mod_remove_from_cluster;
  ring->set_master_id = pfring_mod_set_master_id;
  ring->set_master = pfring_mod_set_master;
  ring->get_ring_id = pfring_mod_get_ring_id;
  ring->get_num_queued_pkts = pfring_mod_get_num_queued_pkts;
  ring->get_packet_consumer_mode = pfring_mod_get_packet_consumer_mode;
  ring->set_packet_consumer_mode = pfring_mod_set_packet_consumer_mode;
  ring->get_hash_filtering_rule_stats = pfring_mod_get_hash_filtering_rule_stats;
  ring->handle_hash_filtering_rule = pfring_mod_handle_hash_filtering_rule;
  ring->purge_idle_hash_rules = pfring_mod_purge_idle_hash_rules;
  ring->add_filtering_rule = pfring_mod_add_filtering_rule;
  ring->remove_filtering_rule = pfring_mod_remove_filtering_rule;
  ring->purge_idle_rules = pfring_mod_purge_idle_rules;
  ring->get_filtering_rule_stats = pfring_mod_get_filtering_rule_stats;
  ring->toggle_filtering_policy = pfring_mod_toggle_filtering_policy;
  ring->enable_rss_rehash = pfring_mod_enable_rss_rehash;
  ring->poll = pfring_mod_poll;
  ring->version = pfring_mod_version;
  ring->get_bound_device_address = pfring_mod_get_bound_device_address;
  ring->get_bound_device_ifindex = pfring_mod_get_bound_device_ifindex;
  ring->get_device_ifindex = pfring_mod_get_device_ifindex;
  ring->get_slot_header_len = pfring_mod_get_slot_header_len;
  ring->set_virtual_device = pfring_mod_set_virtual_device;
  ring->add_hw_rule = pfring_hw_ft_add_hw_rule;
  ring->remove_hw_rule = pfring_hw_ft_remove_hw_rule;
  ring->loopback_test = pfring_mod_loopback_test;
  ring->enable_ring = pfring_mod_enable_ring;
  ring->disable_ring = pfring_mod_disable_ring;
  ring->is_pkt_available = pfring_mod_is_pkt_available;
  ring->set_bpf_filter = pfring_mod_set_bpf_filter;
  ring->remove_bpf_filter = pfring_mod_remove_bpf_filter;
  ring->shutdown = pfring_mod_shutdown;
  ring->send_last_rx_packet = pfring_mod_send_last_rx_packet;
  ring->set_bound_dev_name = pfring_mod_set_bound_dev_name;

  ring->poll_duration = DEFAULT_POLL_DURATION;

  return(pfring_mod_open_setup(ring));
}

/* ******************************* */

int pfring_mod_set_channel_mask(pfring *ring, u_int64_t channel_mask64) {
  return(setsockopt(ring->fd, 0, SO_SET_CHANNEL_ID, &channel_mask64, sizeof(channel_mask64)));
}

/* ******************************* */

int pfring_mod_set_channel_id(pfring *ring, u_int32_t channel_id) {
  return pfring_set_channel_mask(ring, 1 << channel_id);
}

/* ******************************* */

int pfring_mod_set_application_name(pfring *ring, char *name) {
#if !defined(SO_SET_APPL_NAME)
  return(-1);
#else
  return(setsockopt(ring->fd, 0, SO_SET_APPL_NAME, name, strlen(name)));
#endif
}

/* ******************************* */

int pfring_mod_set_application_stats(pfring *ring, char *stats) {
#if !defined(SO_SET_APPL_STATS)
  return(-1);
#else
  return(setsockopt(ring->fd, 0, SO_SET_APPL_STATS, stats, strlen(stats)));
#endif
}

/* **************************************************** */

char* pfring_mod_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len) {
  socklen_t len = (socklen_t)path_len;
  int rc = getsockopt(ring->fd, 0, SO_GET_APPL_STATS_FILE_NAME, path, &len);

  return((rc == 0) ? path : NULL);
}

/* **************************************************** */

int pfring_mod_bind(pfring *ring, char *device_name) {
  struct sockaddr sa;
  char *at, *elem, *pos, name_copy[256];
  u_int64_t channel_mask = RING_ANY_CHANNEL;
  int rc = 0;

  if((device_name == NULL) || (strcmp(device_name, "none") == 0))
    return(-1);

  /* FIX: in case of multiple interfaces the channel ID must be the same */
  at = strchr(device_name, '@');
  if(at != NULL) {
    char *tok;

    at[0] = '\0';

    /* Syntax
       ethX@1,5       channel 1 and 5
       ethX@1-5       channel 1,2...5
       ethX@1-3,5-7   channel 1,2,3,5,6,7
    */

    pos = NULL;
    tok = strtok_r(&at[1], ",", &pos);
    channel_mask = 0;

    while(tok != NULL) {
      char *dash = strchr(tok, '-');
      int32_t min_val, max_val, i;

      if(dash) {
	dash[0] = '\0';
	min_val = atoi(tok);
	max_val = atoi(&dash[1]);

      } else
	min_val = max_val = atoi(tok);

      for(i = min_val; i <= max_val; i++)
	channel_mask |= 1 << i;

      tok = strtok_r(NULL, ",", &pos);
    }
  }

  /* Setup TX */
  ring->sock_tx.sll_family = PF_PACKET;
  ring->sock_tx.sll_protocol = htons(ETH_P_ALL);

  snprintf(name_copy, sizeof(name_copy), "%s", device_name);

  pos = NULL;
  elem = strtok_r(name_copy, ";,", &pos);

  while(elem != NULL) {
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = PF_RING;
    snprintf(sa.sa_data, sizeof(sa.sa_data), "%s", elem);

    rc = bind(ring->fd, (struct sockaddr *)&sa, sizeof(sa));
    
    if(rc == 0) {
      /* if(channel_mask != RING_ANY_CHANNEL) */ {
	rc = pfring_set_channel_mask(ring, channel_mask);
	
	//if(rc != 0)
	//  printf("pfring_set_channel_id() failed: %d\n", rc);
      }
    }

    pfring_enable_hw_timestamp(ring, elem, ring->hw_ts.enable_hw_timestamp ? 1 : 0, 0 /* TX timestamp disabled by default */);

    elem = strtok_r(NULL, ";,", &pos);
  }

  return(rc);
}

/* **************************************************** */

void pfring_mod_close(pfring *ring) {
  if(ring->buffer != NULL) {
    if(munmap(ring->buffer, ring->slots_info->tot_mem) == -1) {
      fprintf(stderr, "[PF_RING] Warning: unable to unmap ring buffer memory [address=%p][size=%u]\n",
     	      ring->buffer, (unsigned int)ring->slots_info->tot_mem);
    }
  }

  if(ring->clear_promisc)
    pfring_set_if_promisc(ring->device_name, 0);

  close(ring->fd);
}

/* **************************************************** */

int  pfring_mod_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  return(sendto(ring->fd, pkt, pkt_len, 0, (struct sockaddr *)&ring->sock_tx, sizeof(ring->sock_tx)));
}

/* **************************************************** */

int pfring_mod_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  return(setsockopt(ring->fd, 0, SO_SET_POLL_WATERMARK, &watermark, sizeof(watermark)));
}

/* **************************************************** */

int pfring_mod_set_poll_duration(pfring *ring, u_int duration) {
  ring->poll_duration = duration;

  return 0;
}

/* **************************************************** */

u_int8_t pfring_mod_get_num_rx_channels(pfring *ring) {
  socklen_t len = sizeof(u_int32_t);
  u_int8_t num_rx_channels;
  int rc = getsockopt(ring->fd, 0, SO_GET_NUM_RX_CHANNELS, &num_rx_channels, &len);

  return((rc == 0) ? num_rx_channels : 1);
}

/* **************************************************** */

int pfring_mod_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  return(setsockopt(ring->fd, 0, SO_SET_SAMPLING_RATE, &rate, sizeof(rate)));
}

/* ******************************* */

int pfring_mod_stats(pfring *ring, pfring_stat *stats) {

  if((ring->slots_info != NULL) && (stats != NULL)) {
    rmb();
    stats->recv = ring->slots_info->tot_read;
    stats->drop = ring->slots_info->tot_lost;
    return(0);
  }

  return(-1);
}

/* **************************************************** */

int pfring_mod_is_pkt_available(pfring *ring) {
  return(pfring_there_is_pkt_available(ring));
}

/* **************************************************** */

int pfring_mod_next_pkt_time(pfring *ring, struct timespec *ts) {
  struct pfring_pkthdr *header = (struct pfring_pkthdr*) &ring->slots[ring->slots_info->remove_off];

  if(!pfring_there_is_pkt_available(ring))
    return PF_RING_ERROR_NO_PKT_AVAILABLE;

  if(!header->ts.tv_sec)
    return PF_RING_ERROR_WRONG_CONFIGURATION;

  ts->tv_sec = header->ts.tv_sec;
  ts->tv_nsec = header->ts.tv_usec * 1000;

  /* TODO In order to use ns from hw ts we should make sure that
   * hw ts is in sync with sys time. */
  //if(header->extended_hdr.timestamp_ns)
  //  ts->tv_nsec = header->extended_hdr.timestamp_ns % 1000000000;

  return 0;
}

/* **************************************************** */

int pfring_mod_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		    struct pfring_pkthdr *hdr,
		    u_int8_t wait_for_incoming_packet) {
  int rc = 0;

  if(ring->is_shutting_down || (ring->buffer == NULL))
    return(-1);

  ring->break_recv_loop = 0;

  do_pfring_recv:
    if(ring->break_recv_loop)
      return(0);

    if(unlikely(ring->reentrant))
      pthread_rwlock_wrlock(&ring->rx_lock);

    //rmb();

    if(pfring_there_is_pkt_available(ring)) {
      char *bucket = &ring->slots[ring->slots_info->remove_off];
      u_int64_t next_off;
      u_int32_t real_slot_len, bktLen;

      /* Keep it for packet sending */
      ring->tx.last_received_hdr = (struct pfring_pkthdr*)bucket;

      memcpy(hdr, bucket, ring->slot_header_len);

#if 0
      if((hdr->caplen > 1518) || (hdr->len > 1518)) 
        fprintf(stderr, "%s:%d-----> Invalid packet length [caplen: %u][len: %u]"
                        "[hdr len: %u][slot len: %u][real slot len: %u]"
                        "[insert_off: %u][remove_off: %u][tot_insert: %lu][tot_read: %lu]\n", 
                __FUNCTION__, __LINE__, hdr->caplen, hdr->len, ring->slot_header_len, 
                ring->slots_info->slot_len, ring->slot_header_len+hdr->caplen, 
                ring->slots_info->insert_off, ring->slots_info->remove_off, 
                ring->slots_info->tot_insert, ring->slots_info->tot_read);
#endif

      bktLen = hdr->caplen;

      if(ring->slot_header_len == sizeof(struct pfring_pkthdr)) /* using long pkt header, parsed_header_len is available */
        bktLen += hdr->extended_hdr.parsed_header_len;

      real_slot_len = ring->slot_header_len + bktLen;

      /* padding at the end of the packet (it should contain the magic number) */
      real_slot_len += sizeof(u_int16_t);
      real_slot_len = ALIGN(real_slot_len, sizeof(u_int64_t));

#if 0
      printf("Real slot len adjusted to %u (MAGIC=%02X)\n", real_slot_len, bucket[ring->slot_header_len + bktLen]);
#endif

      if(bktLen > buffer_len) bktLen = buffer_len;

      if(buffer_len == 0)
	*buffer = (u_char*)&bucket[ring->slot_header_len];
      else
	memcpy(*buffer, &bucket[ring->slot_header_len], bktLen);

      next_off = ring->slots_info->remove_off + real_slot_len;
      if((next_off + ring->slots_info->slot_len) > (ring->slots_info->tot_mem - sizeof(FlowSlotInfo)))
        next_off = 0;
      
#ifdef USE_MB
      /* This prevents the compiler from reordering instructions.
       * http://en.wikipedia.org/wiki/Memory_ordering#Compiler_memory_barrier */
      gcc_mb();
#endif

      ring->slots_info->tot_read++, ring->slots_info->remove_off = next_off;

#if 0 /* this safety check is not so safe as could fail due to concurrent update */
      if(unlikely((ring->slots_info->tot_insert == ring->slots_info->tot_read)
	 && (ring->slots_info->remove_off > ring->slots_info->insert_off 
	 && ring->slots_info->insert_off != 0))) {
        fprintf(stderr, " *** corrupted ring buffer indexes (recovered) ***\n",
	ring->slots_info->remove_off = ring->slots_info->insert_off;
	ring->slots_info->tot_read = ring->slots_info->tot_insert;
      }
#endif

      if(unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
      return(1);
    }

    /* Nothing to do: we need to wait */
    if(unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);

    if(wait_for_incoming_packet) {
      rc = pfring_poll(ring, ring->poll_duration);

      if((rc == -1) && (errno != EINTR))
	return(-1);
      else
	goto do_pfring_recv;
    }

  return(0); /* non-blocking, no packet */
}

/* ******************************* */

int pfring_mod_get_selectable_fd(pfring *ring) {
  return(ring->fd);
}

/* ******************************* */

int pfring_mod_set_direction(pfring *ring, packet_direction direction) {
  return(setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction)));
}

/* ******************************* */

int pfring_mod_set_socket_mode(pfring *ring, socket_mode mode) {
  return(setsockopt(ring->fd, 0, SO_SET_SOCKET_MODE, &mode, sizeof(mode)));
}

/* ******************************* */

int pfring_mod_set_master_id(pfring *ring, u_int32_t master_id) {
  return(setsockopt(ring->fd, 0, SO_SET_MASTER_RING, &master_id, sizeof(master_id)));
}

/* ******************************* */

int pfring_mod_set_master(pfring *ring, pfring *master) {
  int id = pfring_get_ring_id(master);

  if(id != -1)
    return(pfring_set_master_id(ring, id));
  else
    return(id);
}

/* ******************************* */

int pfring_mod_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type) {
  struct add_to_cluster cluster;
  cluster.clusterId = clusterId, cluster.the_type = the_type;

  return(setsockopt(ring->fd, 0, SO_ADD_TO_CLUSTER, &cluster, sizeof(cluster)));
}


/* ******************************* */

int pfring_mod_remove_from_cluster(pfring *ring) {
  return(setsockopt(ring->fd, 0, SO_REMOVE_FROM_CLUSTER, NULL, 0));
}

/* ******************************* */

int pfring_mod_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec) {
  return(setsockopt(ring->fd, 0, SO_PURGE_IDLE_HASH_RULES, &inactivity_sec, sizeof(inactivity_sec)));
}

/* ******************************* */

int pfring_mod_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec) {
  return(setsockopt(ring->fd, 0, SO_PURGE_IDLE_RULES, &inactivity_sec, sizeof(inactivity_sec)));
}

/* **************************************************** */

int pfring_mod_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy) {

  int rc = setsockopt(ring->fd, 0, SO_TOGGLE_FILTER_POLICY,
		      &rules_default_accept_policy,
		      sizeof(rules_default_accept_policy));

  if(rc == 0)
    ring->socket_default_accept_policy = rules_default_accept_policy;

  if(rc < 0)
    return rc;

  if(ring->ft_mode != software_only)
    rc = pfring_hw_ft_set_traffic_policy(ring, rules_default_accept_policy);

  return rc;
}

/* **************************************************** */

int pfring_mod_enable_rss_rehash(pfring *ring) {
  char dummy;

  return(setsockopt(ring->fd, 0, SO_REHASH_RSS_PACKET, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_mod_poll(pfring *ring, u_int wait_duration) {
  if(wait_duration == 0)
    return(ring->is_pkt_available(ring));
  else {
    struct pollfd pfd;
    int rc;

    /* Sleep when nothing is happening */
    pfd.fd      = ring->fd;
    pfd.events  = POLLIN /* | POLLERR */;
    pfd.revents = 0;
    errno       = 0;

    rc = poll(&pfd, 1, wait_duration);
    ring->num_poll_calls++;

    return(rc);
  }
}

/* **************************************************** */

int pfring_mod_version(pfring *ring, u_int32_t *version) {
  socklen_t len = sizeof(u_int32_t);
  return(getsockopt(ring->fd, 0, SO_GET_RING_VERSION, version, &len));
}

/* **************************************************** */

u_int32_t pfring_mod_get_num_queued_pkts(pfring *ring) {
  socklen_t len = sizeof(u_int32_t);
  u_int32_t num_queued_pkts;

  int rc = getsockopt(ring->fd, 0, SO_GET_NUM_QUEUED_PKTS, &num_queued_pkts, &len);

  return((rc == 0) ? num_queued_pkts : 0);
}

/* **************************************************** */

u_int16_t pfring_mod_get_ring_id(pfring *ring) {
  u_int32_t id;
  socklen_t len = sizeof(id);

  int rc = getsockopt(ring->fd, 0, SO_GET_RING_ID, &id, &len);

  return((rc == 0) ? id : -1);
}

/* **************************************************** */

int pfring_mod_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				        char* stats, u_int *stats_len) {
  if(*stats_len < sizeof(u_int16_t))
    return(-1);

  memcpy(stats, &rule_id, sizeof(u_int16_t));
  return(getsockopt(ring->fd, 0,
		    SO_GET_FILTERING_RULE_STATS,
		    stats, stats_len));
}

/* **************************************************** */

int pfring_mod_get_hash_filtering_rule_stats(pfring *ring,
					     hash_filtering_rule* rule,
					     char* stats, u_int *stats_len) {
  char buffer[2048];
  int rc;
  u_int len;

  memcpy(buffer, rule, sizeof(hash_filtering_rule));
  len = sizeof(buffer);
  rc = getsockopt(ring->fd, 0,
		  SO_GET_HASH_FILTERING_RULE_STATS,
		  buffer, &len);
  if(rc < 0)
    return(rc);

  *stats_len = min_val(*stats_len, rc);
  memcpy(stats, buffer, *stats_len);
  return(0);
}

/* **************************************************** */

int pfring_mod_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  int rc = -1;

  if(!rule_to_add)
    return -1;

  /* Sanitize entry (add IPv6 check) */
  rule_to_add->core_fields.shost.v4 &= rule_to_add->core_fields.shost_mask.v4;
  rule_to_add->core_fields.dhost.v4 &= rule_to_add->core_fields.dhost_mask.v4;

  if(rule_to_add->balance_id > rule_to_add->balance_pool)
    rule_to_add->balance_id = 0;

  if(ring->ft_mode != hardware_only) {
    rc = setsockopt(ring->fd, 0, SO_ADD_FILTERING_RULE,
		    rule_to_add, sizeof(filtering_rule));
   
    if(rc < 0)
      return rc;
  }
  
  if(ring->ft_mode != software_only)
    rc = pfring_hw_ft_add_filtering_rule(ring, rule_to_add);

  return rc;
}

/* **************************************************** */

int pfring_mod_enable_ring(pfring *ring) {
  char dummy = 0;

  return(setsockopt(ring->fd, 0, SO_ACTIVATE_RING, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_mod_disable_ring(pfring *ring) {
  char dummy;

  return(setsockopt(ring->fd, 0, SO_DEACTIVATE_RING, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_mod_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  int rc = -1;

  if(ring->ft_mode != hardware_only) {
    rc = setsockopt(ring->fd, 0, SO_REMOVE_FILTERING_RULE,
		    &rule_id, sizeof(rule_id));

    if(rc < 0)
      return rc;
  }

  if(ring->ft_mode != software_only)
    rc = pfring_hw_ft_remove_filtering_rule(ring, rule_id);

  return rc;
}

/* **************************************************** */

int pfring_mod_handle_hash_filtering_rule(pfring *ring,
				 	  hash_filtering_rule* rule_to_add,
					  u_char add_rule) {
  int rc = -1;

  if(!rule_to_add)
    return -1;

  if(ring->ft_mode != hardware_only) {
    rc = setsockopt(ring->fd, 0, add_rule ? SO_ADD_FILTERING_RULE : SO_REMOVE_FILTERING_RULE,
		    rule_to_add, sizeof(hash_filtering_rule));
    
    if(rc < 0)
      return rc;
  }
  
  if(ring->ft_mode != software_only)
    rc = pfring_hw_ft_handle_hash_filtering_rule(ring, rule_to_add, add_rule);

  return rc;
}

/* ******************************* */

u_int8_t pfring_mod_get_packet_consumer_mode(pfring *ring) {
  u_int8_t id;
  socklen_t len = sizeof(id);
  int rc = getsockopt(ring->fd, 0, SO_GET_PACKET_CONSUMER_MODE, &id, &len);

  return((rc == 0) ? id : -1);
}

/* **************************************************** */

int pfring_mod_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				  	char *plugin_data, u_int plugin_data_len) {
  char buffer[4096];

  if(plugin_data_len > (sizeof(buffer)-1)) return(-2);

  memcpy(buffer, &plugin_id, 1);

  if(plugin_data_len > 0)
    memcpy(&buffer[1], plugin_data, plugin_data_len);

  return(setsockopt(ring->fd, 0, SO_SET_PACKET_CONSUMER_MODE,
		    buffer, plugin_data_len+1));
}

/* **************************************************** */

int pfring_mod_set_virtual_device(pfring *ring, virtual_filtering_device_info *info) {
  return(setsockopt(ring->fd, 0, SO_SET_VIRTUAL_FILTERING_DEVICE,
		    (char*)info, sizeof(virtual_filtering_device_info)));
}

/* **************************************************** */

int pfring_mod_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len) {
  socklen_t len;

  if(test_len > buffer_len) test_len = buffer_len;
  len = test_len;

  return(getsockopt(ring->fd, 0, SO_GET_LOOPBACK_TEST, (char*)buffer, &len));
}

/* **************************************************** */

int pfring_mod_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  socklen_t len = 6;

  return(getsockopt(ring->fd, 0, SO_GET_BOUND_DEVICE_ADDRESS, mac_address, &len));
}

/* **************************************************** */

int pfring_mod_get_bound_device_ifindex(pfring *ring, int *if_index) {
  socklen_t len = sizeof(int);

  return(getsockopt(ring->fd, 0, SO_GET_BOUND_DEVICE_IFINDEX, if_index, &len));
}

/* **************************************************** */

int pfring_mod_get_device_ifindex(pfring *ring, char *device_name, int *if_index) {
  char buffer[32];
  socklen_t len = sizeof(buffer);
  int rc;

  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, device_name, sizeof(buffer) - 1);
  
  rc = getsockopt(ring->fd, 0, SO_GET_DEVICE_IFINDEX, buffer, &len);

  if (rc < 0)
    return rc;

  memcpy(if_index, buffer, sizeof(*if_index));
  return 0;
}

/* **************************************************** */

int pfring_mod_get_link_status(pfring *ring) {
  int link_up = 1;
  socklen_t len = sizeof(link_up);
  getsockopt(ring->fd, 0, SO_GET_LINK_STATUS, &link_up, &len);
  return link_up;
}

/* **************************************************** */

u_int16_t pfring_mod_get_slot_header_len(pfring *ring) {
  u_int16_t hlen;
  socklen_t len = sizeof(hlen);
  int rc = getsockopt(ring->fd, 0, SO_GET_PKT_HEADER_LEN, &hlen, &len);

  return((rc == 0) ? hlen : -1);
}

/* **************************************************** */

int pfring_mod_set_bpf_filter(pfring *ring, char *filter_buffer) {
  int                rc = -1;
#ifdef ENABLE_BPF
  struct bpf_program filter;
  struct sock_fprog  fcode;

  if(!filter_buffer)
    return -1;

  if(unlikely(ring->reentrant))
    pthread_rwlock_wrlock(&ring->rx_lock);

  if(pcap_compile_nopcap(ring->caplen,  /* snaplen_arg */
                         DLT_EN10MB,    /* linktype_arg */
                         &filter,       /* program */
                         filter_buffer, /* const char *buf */
                         0,             /* optimize */
                         0              /* mask */
                         ) == -1) {
    rc = -1;
    goto pfring_mod_set_bpf_filter_exit;
  }

  if(filter.bf_insns == NULL) {
    rc = -1;
    goto pfring_mod_set_bpf_filter_exit;
  }

  fcode.len    = filter.bf_len;
  fcode.filter = (struct sock_filter *) filter.bf_insns;

  rc = setsockopt(ring->fd, 0, SO_ATTACH_FILTER, &fcode, sizeof(fcode));

  pcap_freecode(&filter);

  if(rc == -1)
    pfring_mod_remove_bpf_filter(ring);

 pfring_mod_set_bpf_filter_exit:
  if(unlikely(ring->reentrant))
    pthread_rwlock_unlock(&ring->rx_lock);

#endif

  return rc;
}

/* **************************************************** */

int pfring_mod_remove_bpf_filter(pfring *ring) {
  int rc = -1;
#ifdef ENABLE_BPF 
  int dummy = 0;

  if(unlikely(ring->reentrant))
    pthread_rwlock_wrlock(&ring->rx_lock);

  rc = setsockopt(ring->fd, 0, SO_DETACH_FILTER, &dummy, sizeof(dummy));

  if(rc == -1)
    rc = setsockopt(ring->fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(dummy));

  if(unlikely(ring->reentrant))
    pthread_rwlock_unlock(&ring->rx_lock);
#endif

  return rc;
}

/* **************************************************** */

int pfring_mod_send_last_rx_packet(pfring *ring, int tx_interface_id) {
  if(!ring->tx.enabled_rx_packet_send)
    return(PF_RING_ERROR_WRONG_CONFIGURATION);

  if(ring->tx.last_received_hdr == NULL)
    return(PF_RING_ERROR_NO_PKT_AVAILABLE); /* We have not yet read a single packet */
  
  ring->tx.last_received_hdr->extended_hdr.tx.bounce_interface = tx_interface_id;
  return(0);
}

/* **************************************************** */

void pfring_mod_shutdown(pfring *ring) {
  int dummy = 0;

  setsockopt(ring->fd, 0, SO_SHUTDOWN_RING, &dummy, sizeof(dummy));
}

/* **************************************************** */

int pfring_mod_set_bound_dev_name(pfring *ring, char *custom_dev_name) {
   return(setsockopt(ring->fd, 0, SO_SET_CUSTOM_BOUND_DEV_NAME, 
		     custom_dev_name, strlen(custom_dev_name)));
}

