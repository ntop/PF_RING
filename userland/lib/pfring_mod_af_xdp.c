/*
 *
 * (C) 2020-22 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifdef HAVE_PF_RING_ZC

#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>

#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>

#include "pfring_priv.h"

#include <bpf/xsk.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define _BPF_H_ /* Fix redefinition of struct bpf_insn from libpcap */

#include "pfring.h"
#include "pfring_utils.h"
#include "pfring_hw_filtering.h"
#include "pfring_mod.h"
#include "pfring_zc.h"
#include "pfring_mod_af_xdp.h"

#define AF_XDP_DEV_MAX_QUEUES      16
#define AF_XDP_DEV_NUM_BUFFERS     4096
#define AF_XDP_DEV_NUM_DESC        XSK_RING_CONS__DEFAULT_NUM_DESCS
#define AF_XDP_DEV_FRAME_SIZE      2048 /* XSK_UMEM__DEFAULT_FRAME_SIZE */
#define AF_XDP_DEV_DATA_HEADROOM   0
#define AF_XDP_DEV_RX_BATCH_SIZE   32

struct pf_xdp_xsk_umem_info {
  struct xsk_umem *umem;
  void *buffer;
};

struct pf_xdp_rx_stats {
  u_int64_t rx_pkts;
  u_int64_t rx_bytes;
};

struct pf_xdp_tx_stats {
  u_int64_t tx_pkts;
  u_int64_t tx_bytes;
  u_int64_t errors;
};

struct pf_xdp_rx_queue {
  struct xsk_ring_cons rx;
  struct xsk_socket *xsk;

  pfring_zc_pkt_buff *buffers_in_use[AF_XDP_DEV_RX_BATCH_SIZE];
  u_int32_t num_buffers_in_use;

  struct pf_xdp_rx_stats stats;

  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;

  struct pollfd fds[1];
};

struct pf_xdp_tx_queue {
  struct xsk_ring_prod tx;
  struct pf_xdp_tx_stats stats;
};

struct pf_xdp_handle {
  int if_index;
  u_int16_t queue_idx;
  struct ether_addr eth_addr;
  struct pf_xdp_xsk_umem_info umem;

  struct pf_xdp_rx_queue rx_queue;
  struct pf_xdp_tx_queue tx_queue;

  pfring_zc_cluster *zc;
};

/* **************************************************** */

static inline int pfring_mod_af_xdp_refill_queue(struct pf_xdp_handle *handle, pfring_zc_pkt_buff **fq_bufs, u_int16_t reserve_size) {
  struct pf_xdp_xsk_umem_info *umem = &handle->umem;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  struct xsk_ring_prod *fq = &rxq->fq;
  u_int32_t i, idx;

  if (unlikely(!xsk_ring_prod__reserve(fq, reserve_size, &idx))) {
    for (i = 0; i < reserve_size; i++)
      pfring_zc_release_packet_handle(handle->zc, fq_bufs[i]);
    return -1;
  }

  for (i = 0; i < reserve_size; i++) {
    u_char *pkt_data = pfring_zc_pkt_buff_data_from_cluster(fq_bufs[i], handle->zc);
    __u64 *fq_addr;
    u_int64_t rel_addr;

    fq_addr = xsk_ring_prod__fill_addr(fq, idx++);
    rel_addr = (uint64_t) pkt_data - (uint64_t) umem->buffer;
    *fq_addr = (u_int64_t) rel_addr;
  }

  xsk_ring_prod__submit(fq, reserve_size);

  return 0;
}

/* **************************************************** */

int pfring_mod_af_xdp_is_pkt_available(pfring *ring) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct xsk_ring_cons *rx = &handle->rx_queue.rx;

  return xsk_cons_nb_avail(rx, 1);
}

/* **************************************************** */

int pfring_mod_af_xdp_get_selectable_fd(pfring *ring) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;

  return xsk_socket__fd(handle->rx_queue.xsk);
}

/* **************************************************** */

int pfring_mod_af_xdp_poll(pfring *ring, u_int wait_duration) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  int ret;

  ret = poll(&rxq->fds[0], 1, wait_duration);

  return ret;
}

/* **************************************************** */

static u_int16_t pfring_mod_af_xdp_recv_burst_zc(struct pf_xdp_handle *handle, pfring_zc_pkt_buff **pkts, u_int16_t num_packets, int wait) {
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  struct xsk_ring_cons *rx = &rxq->rx;
  struct xsk_ring_prod *fq = &rxq->fq;
  struct pf_xdp_xsk_umem_info *umem = &handle->umem;
  pfring_zc_pkt_buff *fq_bufs[AF_XDP_DEV_RX_BATCH_SIZE];
  const struct xdp_desc *desc;
  u_char *pkt_data;
  uint64_t addr;
  uint32_t len;
  uint64_t offset;
  u_int32_t idx_rx = 0;
  u_int64_t rx_bytes = 0;
  int i;

  num_packets = min(num_packets, AF_XDP_DEV_RX_BATCH_SIZE);

  num_packets = xsk_ring_cons__peek(rx, num_packets, &idx_rx);

  if (num_packets == 0) {
    if (xsk_ring_prod__needs_wakeup(fq))
      poll(&rxq->fds[0], 1, 1000);

    return 0;
  }

  /* Allocating buffers to refill the queue */
  for (i = 0; i < num_packets; i++) {
    fq_bufs[i] = pfring_zc_get_packet_handle(handle->zc);

    if (fq_bufs[i] == NULL) {
      if (i == 0) {
        printf("Failure allocating enough buffers\n");
        /* Put back cached_cons, increased by xsk_ring_cons__peek */
        rx->cached_cons -= num_packets;
        return 0;
      } else {
        rx->cached_cons -= num_packets - i;
        num_packets = i;
      }
    }
  }

  /* Receive buffers */
  for (i = 0; i < num_packets; i++) {
    desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
    addr = desc->addr;
    len = desc->len;

    offset = xsk_umem__extract_offset(addr);
    addr = xsk_umem__extract_addr(addr);

    pkt_data = xsk_umem__get_data(umem->buffer, addr);
    pkts[i] = (pfring_zc_pkt_buff *) pfring_zc_pkt_data_buff(pkt_data, handle->zc);
    pkts[i]->len = len + offset;

    pfring_zc_pkt_buff_pull_only(pkts[i], offset);

    rx_bytes += len;
  }

  xsk_ring_cons__release(rx, num_packets);
  pfring_mod_af_xdp_refill_queue(handle, fq_bufs, num_packets);

  rxq->stats.rx_pkts += num_packets;
  rxq->stats.rx_bytes += rx_bytes;

  return num_packets;
}

/* **************************************************** */

int pfring_mod_af_xdp_recv_burst(pfring *ring, pfring_packet_info *packets, u_int8_t num_packets, u_int8_t wait_for_packets) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  u_char *pkt_data;
  u_int32_t duration = 1;
  u_int32_t i, j = 0;

  num_packets = min(num_packets, AF_XDP_DEV_RX_BATCH_SIZE);

  if (unlikely(ring->reentrant)) pthread_rwlock_wrlock(&ring->rx_lock);

 redo_recv:

  for (i = 0; i < rxq->num_buffers_in_use; i++)
    pfring_zc_release_packet_handle(handle->zc, rxq->buffers_in_use[i]);

  rxq->num_buffers_in_use = pfring_mod_af_xdp_recv_burst_zc(handle, rxq->buffers_in_use, num_packets, wait_for_packets);

  if (likely(rxq->num_buffers_in_use) > 0) {
    for (i = 0; i < rxq->num_buffers_in_use; i++) {

      if (unlikely(ring->sampling_rate > 1)) {
        if (likely(ring->sampling_counter > 0)) {
          ring->sampling_counter--;
          continue;
        } else {
          ring->sampling_counter = ring->sampling_rate-1;
        }
      }

      pkt_data = pfring_zc_pkt_buff_data_from_cluster(rxq->buffers_in_use[i], handle->zc);
      packets[j].data = pkt_data;

      packets[j].len = packets[j].caplen = rxq->buffers_in_use[i]->len;
      packets[j].hash = 0;
      packets[j].flags = 0;

      if (unlikely(ring->force_timestamp)) {
        gettimeofday(&packets[j].ts, NULL);
      } else {
        /* as speed is required, we are not setting the sw time */
        packets[j].ts.tv_sec = 0;
        packets[j].ts.tv_usec = 0;
      }

      j++;
    }

    if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
    
    return j;
  }

  if (wait_for_packets) {

    if (unlikely(ring->break_recv_loop)) {
      if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
      errno = EINTR;
      return 0;
    }
      
    if (unlikely(pfring_mod_af_xdp_poll(ring, duration) == -1 && errno != EINTR)) {
      if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
      return -1;
    }

    if (duration < ring->poll_duration) {
      duration += 10;
      if (unlikely(duration > ring->poll_duration)) 
        duration = ring->poll_duration;
    }

    goto redo_recv;
  }

  if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);

  return 0;
}

/* **************************************************** */

int pfring_mod_af_xdp_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  u_char *pkt_data;
  u_int32_t duration = 1;

  if (unlikely(ring->reentrant)) pthread_rwlock_wrlock(&ring->rx_lock);

 redo_recv:

  if (rxq->num_buffers_in_use > 0)
    pfring_zc_release_packet_handle(handle->zc, rxq->buffers_in_use[0]);

  if (likely(pfring_mod_af_xdp_recv_burst_zc(handle, rxq->buffers_in_use, 1, wait_for_incoming_packet) > 0)) {

    rxq->num_buffers_in_use = 1;

    if (unlikely(ring->sampling_rate > 1)) {
      if (likely(ring->sampling_counter > 0)) {
        ring->sampling_counter--;
        goto redo_recv;
      } else {
        ring->sampling_counter = ring->sampling_rate-1;
      }
    }

    hdr->len = hdr->caplen = rxq->buffers_in_use[0]->len;
    hdr->extended_hdr.pkt_hash = 0;
    hdr->extended_hdr.rx_direction = 1;
    hdr->extended_hdr.timestamp_ns = 0;

    if (unlikely(buffer_len || ring->force_timestamp)) {
      gettimeofday(&hdr->ts, NULL);
    } else {
      /* as speed is required, we are not setting the sw time */
      hdr->ts.tv_sec = 0;
      hdr->ts.tv_usec = 0;
    }

    pkt_data = pfring_zc_pkt_buff_data_from_cluster(rxq->buffers_in_use[0], handle->zc);

    if (likely(buffer_len == 0)) {
      *buffer = pkt_data;
    } else {
      if (buffer_len < rxq->buffers_in_use[0]->len)
        hdr->caplen = buffer_len;

      memcpy(*buffer, pkt_data, hdr->caplen);
      memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
      pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
    }

    hdr->caplen = min_val(hdr->caplen, ring->caplen);

    if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
    
    return 1;
  }

  if (wait_for_incoming_packet) {

    if (unlikely(ring->break_recv_loop)) {
      if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
      errno = EINTR;
      return 0;
    }
      
    if (unlikely(pfring_mod_af_xdp_poll(ring, duration) == -1 && errno != EINTR)) {
      if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
      return -1;
    }

    if (duration < ring->poll_duration) {
      duration += 10;
      if (unlikely(duration > ring->poll_duration)) 
        duration = ring->poll_duration;
    }

    goto redo_recv;
  }

  if (unlikely(ring->reentrant)) pthread_rwlock_unlock(&ring->rx_lock);
  return 0;
}

/* **************************************************** */

static void pfring_mod_af_xdp_cleanup_tx_cq(struct pf_xdp_handle *handle, int size, struct xsk_ring_cons *cq) {
  struct pf_xdp_xsk_umem_info *umem = &handle->umem;
  size_t i, n;
  uint32_t idx_cq = 0;

  n = xsk_ring_cons__peek(cq, size, &idx_cq);

  for (i = 0; i < n; i++) {
    uint64_t addr;
    pfring_zc_pkt_buff *pkt;
    u_char *pkt_data;

    addr = *xsk_ring_cons__comp_addr(cq, idx_cq++);
    addr = xsk_umem__extract_addr(addr);
 
    pkt_data = (u_char *) xsk_umem__get_data(umem->buffer, addr);
    pkt = pfring_zc_pkt_data_buff(pkt_data, handle->zc);

    if (pkt) /* safety check */
      pfring_zc_release_packet_handle(handle->zc, pkt);
    else
      fprintf(stderr, "Unable to find packet handle to release\n");
  }

  xsk_ring_cons__release(cq, n);
}

/* **************************************************** */

static void pfring_mod_af_flush_tx_q(struct pf_xdp_handle *handle, struct xsk_ring_cons *cq) {
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;

  pfring_mod_af_xdp_cleanup_tx_cq(handle, XSK_RING_CONS__DEFAULT_NUM_DESCS, cq);

  while (send(xsk_socket__fd(rxq->xsk), NULL, 0, MSG_DONTWAIT) < 0) {
    if (errno != EBUSY && errno != EAGAIN && errno != EINTR)
      break;

    /* Cleanup completion queue */
    if (errno == EAGAIN)
      pfring_mod_af_xdp_cleanup_tx_cq(handle, XSK_RING_CONS__DEFAULT_NUM_DESCS, cq);
  }
}

/* **************************************************** */

static u_int16_t pfring_mod_af_xdp_send_burst(struct pf_xdp_handle *handle, pfring_zc_pkt_buff **pkts, u_int16_t num_packets) {
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  struct pf_xdp_tx_queue *txq = &handle->tx_queue;
  struct pf_xdp_xsk_umem_info *umem = &handle->umem;
  pfring_zc_pkt_buff *pkt;
  unsigned long tx_bytes = 0;
  int i;
  uint32_t idx_tx;
  uint16_t count = 0;
  struct xdp_desc *desc;
  uint64_t addr, offset;
  struct xsk_ring_cons *cq = &rxq->cq;
  uint32_t free_thresh = cq->size >> 1;
  u_char *pkt_data;

  if (xsk_cons_nb_avail(cq, free_thresh) >= free_thresh)
    pfring_mod_af_xdp_cleanup_tx_cq(handle, XSK_RING_CONS__DEFAULT_NUM_DESCS, cq);

  for (i = 0; i < num_packets; i++) {
    pkt = pkts[i];
    
    pkt_data = pfring_zc_pkt_buff_data_from_cluster(pkt, handle->zc);

    if (!xsk_ring_prod__reserve(&txq->tx, 1, &idx_tx)) {
      pfring_mod_af_flush_tx_q(handle, cq);
      if (!xsk_ring_prod__reserve(&txq->tx, 1, &idx_tx))
        goto out;
    }

    desc = xsk_ring_prod__tx_desc(&txq->tx, idx_tx);
    desc->len = pkt->len;

    addr = (uint64_t) pkt_data - PF_RING_ZC_BUFFER_HEAD_ROOM - (uint64_t) umem->buffer;

    offset = PF_RING_ZC_BUFFER_HEAD_ROOM;
    offset = offset << XSK_UNALIGNED_BUF_OFFSET_SHIFT;

    desc->addr = addr | offset;

    tx_bytes += pkt->len;

    count++;
  }

  pfring_mod_af_flush_tx_q(handle, cq);

out:
  xsk_ring_prod__submit(&txq->tx, count);

  txq->stats.tx_pkts += count;
  txq->stats.tx_bytes += tx_bytes;
  txq->stats.errors += num_packets - count;

  return count;
}

/* **************************************************** */

int pfring_mod_af_xdp_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  pfring_zc_pkt_buff *p[1];
  u_char *pkt_data;

  p[0] = pfring_zc_get_packet_handle(handle->zc);

  if (!p[0]) {
    return -1;
  }

  pkt_data = pfring_zc_pkt_buff_data_from_cluster(p[0], handle->zc);
  memcpy(pkt_data, pkt, pkt_len);
  p[0]->len = pkt_len;

  if (pfring_mod_af_xdp_send_burst(handle, p, 1) > 0) 
    return pkt_len;

  return -1;
}

/* **************************************************** */

int pfring_mod_af_xdp_stats(pfring *ring, pfring_stat *stats) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct xdp_statistics xdp_stats;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  socklen_t optlen = sizeof(struct xdp_statistics);
  int ret;

  memset(stats, 0, sizeof(*stats));

  stats->recv += handle->rx_queue.stats.rx_pkts;
  stats->drop = 0;

  ret = getsockopt(xsk_socket__fd(rxq->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen);

  if (ret == 0)
    stats->drop += xdp_stats.rx_dropped;

  /* Other available stats: 
  handle->rx_queue.stats.rx_bytes;
  handle->tx_queue.stats.tx_pkts;
  handle->tx_queue.stats.tx_bytes;
  handle->tx_queue.stats.errors;
  */

  return 0;
}

/* **************************************************** */

static void pfring_mod_af_xdp_remove_xdp_program(struct pf_xdp_handle *handle) {
  u_int32_t curr_prog_id = 0;

  if (bpf_get_link_xdp_id(handle->if_index, &curr_prog_id, XDP_FLAGS_UPDATE_IF_NOEXIST)) {
    fprintf(stderr, "Failure in bpf_get_link_xdp_id\n");
    return;
  }

  bpf_set_link_xdp_fd(handle->if_index, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
}

/* **************************************************** */

static int pfring_mod_af_xdp_umem_configure(struct pf_xdp_handle *handle) {
  struct pf_xdp_xsk_umem_info *umem = &handle->umem;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  pfring_zc_cluster_mem_info mem_info;
  struct xsk_umem_config usr_config = {
    .fill_size = AF_XDP_DEV_NUM_DESC * 2,
    .comp_size = AF_XDP_DEV_NUM_DESC,
    .frame_size = AF_XDP_DEV_FRAME_SIZE,
    .frame_headroom = AF_XDP_DEV_DATA_HEADROOM,
    .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG
  };
  int ret;

  pfring_zc_get_memory_info(handle->zc, &mem_info);

  ret = xsk_umem__create(&umem->umem, mem_info.base_addr, mem_info.size, &rxq->fq, &rxq->cq, &usr_config);

  if (ret) {
    fprintf(stderr, "Failure creating umem");
    goto err;
  }

  umem->buffer = mem_info.base_addr;

  return 0;

err:
  return -1;
}

/* **************************************************** */

static int pfring_mod_af_xdp_xsk_configure(pfring *ring) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;
  struct pf_xdp_rx_queue *rxq = &handle->rx_queue;
  struct pf_xdp_tx_queue *txq = &handle->tx_queue;
  struct xsk_socket_config cfg;
  int ring_size = AF_XDP_DEV_NUM_BUFFERS;
  int reserve_size = AF_XDP_DEV_NUM_DESC;
  pfring_zc_pkt_buff *fq_bufs[reserve_size];
  int i, ret = 0;

  ret = pfring_mod_af_xdp_umem_configure(handle);

  if (ret != 0)
    return -ENOMEM;

  cfg.rx_size = ring_size;
  cfg.tx_size = ring_size;
  cfg.libbpf_flags = 0;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.bind_flags = 0;
#ifdef XDP_USE_NEED_WAKEUP
  cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
#endif

  //fprintf(stderr, "Creating xsk socket on dev %s queue %u\n", 
  //  ring->device_name, handle->queue_idx);

  ret = xsk_socket__create(&rxq->xsk, ring->device_name, 
    handle->queue_idx, handle->umem.umem,
    &rxq->rx, &txq->tx, &cfg);

  if (ret) {
    fprintf(stderr, "Failed to create xsk socket on dev %s queue %u: %s (%d)\n", 
      ring->device_name, handle->queue_idx, strerror(errno), ret);
    goto err;
  }

  for (i = 0; i < reserve_size; i++) {
    fq_bufs[i] = pfring_zc_get_packet_handle(handle->zc);
    
    if (fq_bufs[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      goto err;
    }
  }

  ret = pfring_mod_af_xdp_refill_queue(handle, fq_bufs, reserve_size);

  if (ret) {
    xsk_socket__delete(rxq->xsk);
    fprintf(stderr, "Failed to refill queue\n");
    goto err;
  }

  rxq->fds[0].fd = xsk_socket__fd(rxq->xsk);
  rxq->fds[0].events = POLLIN;

  return 0;

err:
  return ret;
}

/* **************************************************** */

static void pfring_mod_af_xdp_dev_change_flags(char *if_name, u_int32_t flags, u_int32_t mask) {
  struct ifreq ifr;
  int s;

  s = socket(PF_INET, SOCK_DGRAM, 0);

  if (s < 0)
    return;

  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

  if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    return;

  ifr.ifr_flags &= mask;
  ifr.ifr_flags |= flags;

  ioctl(s, SIOCSIFFLAGS, &ifr);

  close(s);
}

/* **************************************************** */

static void pfring_mod_af_xdp_dev_promiscuous_enable(char *if_name) {
  pfring_mod_af_xdp_dev_change_flags(if_name, IFF_PROMISC, ~0);
}

/* **************************************************** */

static void pfring_mod_af_xdp_dev_promiscuous_disable(char *if_name) {
  pfring_mod_af_xdp_dev_change_flags(if_name, 0, ~IFF_PROMISC);
}

/* **************************************************** */

int pfring_mod_af_xdp_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;

  memcpy(mac_address, &handle->eth_addr, ETHER_ADDR_LEN);

  return 0;
}

/* **************************************************** */

int pfring_mod_af_xdp_get_bound_device_ifindex(pfring *ring, int *if_index) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;

  *if_index = handle->if_index;

  return 0;
}

/* **************************************************** */

u_int8_t pfring_mod_af_xdp_get_num_rx_channels(pfring *ring) {
  char path[256];
  FILE *proc_net_pfr;
  u_int8_t n = 1;

  snprintf(path, sizeof(path), "/proc/net/pf_ring/dev/%s/info", ring->device_name);
  proc_net_pfr = fopen(path, "r");
  if (proc_net_pfr != NULL) {
    while(fgets(path, sizeof(path), proc_net_pfr) != NULL) {
      char *p = &path[0];
      const char *str_rx_queues = "RX Queues:";
      if (!strncmp(p, str_rx_queues, strlen(str_rx_queues))) {
        p += strlen(str_rx_queues);
        while (*p == ' ' && *p != '0') p++;
        n = atoi(p);
        break;
      }
    }
    fclose(proc_net_pfr);
  }

  return n;
}

/* **************************************************** */

int pfring_mod_af_xdp_set_direction(pfring *ring, packet_direction direction) {
  if (direction != rx_only_direction)
    return -1;

  return pfring_mod_set_direction(ring, direction);
}

/* **************************************************** */

int pfring_mod_af_xdp_enable_ring(pfring *ring) {
  int rc = -1;

  rc = pfring_mod_enable_ring(ring);

  if (rc < 0)
    goto error;

  if (ring->mode != send_only_mode) {
    // RX initialization
  }

  if (ring->mode != recv_only_mode) {
    // TX initialization
  }

  return 0;

 error:
  return rc;
}

/* **************************************************** */

void pfring_mod_af_xdp_close(pfring *ring) {
  struct pf_xdp_handle *handle = (struct pf_xdp_handle *) ring->priv_data;

  if (ring->promisc)
    pfring_mod_af_xdp_dev_promiscuous_disable(ring->device_name);

  if (handle) {
    struct pf_xdp_xsk_umem_info *umem = &handle->umem;

    xsk_socket__delete(handle->rx_queue.xsk);

    (void)xsk_umem__delete(umem->umem);

    pfring_mod_af_xdp_remove_xdp_program(handle);

    pfring_zc_destroy_cluster(handle->zc);

    free(handle);
    ring->priv_data = NULL;
  }

  close(ring->fd);
}

/* **************************************************** */

int pfring_mod_af_xdp_open(pfring *ring) {
  struct pf_xdp_handle *handle;
  int channel_id = 0;
  struct ifreq ifr;
  int sock, rc;
  char *at;

  ring->enable_ring = pfring_mod_af_xdp_enable_ring;
  ring->close = pfring_mod_af_xdp_close;
  ring->stats = pfring_mod_af_xdp_stats;
  ring->recv  = pfring_mod_af_xdp_recv;
  ring->recv_burst = pfring_mod_af_xdp_recv_burst;
  ring->poll = pfring_mod_af_xdp_poll;
  ring->is_pkt_available = pfring_mod_af_xdp_is_pkt_available;
  ring->send  = pfring_mod_af_xdp_send;
  ring->set_direction = pfring_mod_af_xdp_set_direction;
  ring->get_bound_device_address = pfring_mod_af_xdp_get_bound_device_address;
  ring->get_bound_device_ifindex = pfring_mod_af_xdp_get_bound_device_ifindex;
  ring->get_selectable_fd = pfring_mod_af_xdp_get_selectable_fd;
  ring->get_num_rx_channels = pfring_mod_af_xdp_get_num_rx_channels;

  ring->set_socket_mode = pfring_mod_set_socket_mode;
  ring->get_interface_speed = pfring_mod_get_interface_speed;
  ring->set_poll_duration = pfring_mod_set_poll_duration;
  ring->set_application_name = pfring_mod_set_application_name;
  ring->set_application_stats = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;
  ring->get_ring_id = pfring_mod_get_ring_id;
  ring->version = pfring_mod_version;
  ring->get_device_ifindex = pfring_mod_get_device_ifindex;
  ring->set_virtual_device = pfring_mod_set_virtual_device;
  ring->add_hw_rule = pfring_hw_ft_add_hw_rule;
  ring->remove_hw_rule = pfring_hw_ft_remove_hw_rule;
  ring->loopback_test = pfring_mod_loopback_test;
  ring->disable_ring = pfring_mod_disable_ring;
  ring->shutdown = pfring_mod_shutdown;

  ring->direction = rx_only_direction;
  ring->poll_duration = DEFAULT_POLL_DURATION;

  /* ***************************************** */

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

  if (ring->fd < 0) {
    rc = ring->fd;
    goto error;
  }

  /* Syntax: ethX@1 */
  at = strchr(ring->device_name, '@');
  if (at != NULL) {
    at[0] = '\0';
    channel_id = atoi(&at[1]);
    if (channel_id >= AF_XDP_DEV_MAX_QUEUES) {
      rc = -1;
      goto close_fd;
    }
  }

  if ((handle = calloc(1, sizeof(struct pf_xdp_handle))) == NULL) {
    rc = -1;
    goto close_fd;
  }

  ring->priv_data = handle;

  handle->queue_idx = channel_id;

  /* Read interafce index */

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

  if (sock < 0) {
    fprintf(stderr, "Failed to get interface info\n");
    rc = -1;
    goto close_fd;
  }

  strncpy(ifr.ifr_name, ring->device_name, IFNAMSIZ);

  if (ioctl(sock, SIOCGIFINDEX, &ifr)) {
    fprintf(stderr, "Failed to get interface ifindex\n");
    rc = -1;
    close(sock);
    goto close_fd;
  }

  handle->if_index = ifr.ifr_ifindex;

  /* Read MAC address */

  if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
    fprintf(stderr, "Failed to get interface address\n");
    rc = -1;
    close(sock);
    goto close_fd;
  }

  memcpy(&handle->eth_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  close(sock);

  /* Create ZC cluster */

  handle->zc = pfring_zc_create_cluster(
    (1 << 10) + (handle->if_index << 6) + handle->queue_idx, /* Encoded Cluster ID */
    AF_XDP_DEV_FRAME_SIZE,
    0, 
    (4 * AF_XDP_DEV_NUM_BUFFERS) + AF_XDP_DEV_RX_BATCH_SIZE + 1,
    pfring_zc_numa_get_cpu_node(0 /* CPU core */),
    NULL /* auto hugetlb mountpoint */,
    0 
  );

  if (handle->zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s]\n", strerror(errno));
    rc = -1;
    goto close_fd;
  }

  /* Setup queues */

#if 0
  /* Cleanup XDP in case we didn't shutdown gracefully.. 
   * Note: doing this for the first queue only (this assumes
   * that the application is opening queues in order) */
  if (handle->queue_idx == 0)
    pfring_mod_af_xdp_remove_xdp_program(handle);
#endif

  if (pfring_mod_af_xdp_xsk_configure(ring)) {
    fprintf(stderr, "Failed to configure xdp socket\n");
    goto free_handle;
  }

  /* Handle offloads */

  pfring_enable_hw_timestamp(ring, ring->device_name, ring->hw_ts.enable_hw_timestamp ? 1 : 0, 0);

  pfring_set_filtering_mode(ring, hardware_only);
  pfring_hw_ft_init(ring);

  /* Enable promisc */

  if (ring->promisc)
    pfring_mod_af_xdp_dev_promiscuous_enable(ring->device_name);  

  errno = 0;

  return 0;

 free_handle:
  free(handle);
  ring->priv_data = NULL;

 close_fd:
  close(ring->fd);

 error:
  return rc;
}

/* **************************************************** */

#endif /* HAVE_PF_RING_ZC */
