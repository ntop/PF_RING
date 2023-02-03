/*
 *
 * (C) 2014-23 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_mod_pcap.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* **************************************************** */

int pfring_mod_pcap_open(pfring *ring) {
  pfring_pcap *pcap = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];

  ring->close                    = pfring_mod_pcap_close;
  ring->recv                     = pfring_mod_pcap_recv;
  ring->poll                     = pfring_mod_pcap_poll;
  ring->enable_ring              = pfring_mod_pcap_enable_ring;
  ring->set_socket_mode          = pfring_mod_pcap_set_socket_mode;
  ring->set_poll_watermark       = pfring_mod_pcap_set_poll_watermark;
  ring->set_bpf_filter           = pfring_mod_pcap_set_bpf_filter;

  ring->priv_data = malloc(sizeof(pfring_pcap));

  if(ring->priv_data == NULL)
    goto pcap_ret_error;

  memset(ring->priv_data, 0, sizeof(pfring_pcap));
  pcap = (pfring_pcap*)ring->priv_data;

  if(ring->caplen > MAX_CAPLEN) ring->caplen = MAX_CAPLEN;
  ring->poll_duration = DEFAULT_POLL_DURATION;
  
  /* 1) Try with a pcap file first */
  pcap->pd = pcap_open_offline(ring->device_name, errbuf);
  if(pcap->pd != NULL) {
    pcap->fd = pcap_get_selectable_fd(pcap->pd);
    pcap->is_pcap_file = 1;
    return(0);
  }

  /* 2) Last resort use a real network device */
  pcap->pd = pcap_open_live(ring->device_name,
			    ring->caplen,
			    1 /* promiscuous mode */,
			    1000 /* ms */,
			    errbuf);
  
  if(pcap->pd != NULL) {
    pcap->fd = pcap_get_selectable_fd(pcap->pd);
    pcap->is_pcap_file = 0;
    return(0);
  }
  
 pcap_ret_error:
  return(-1);
}

/* **************************************************** */

void pfring_mod_pcap_close(pfring *ring) {
  pfring_pcap *pcap;

  if(ring->priv_data == NULL)
    return;

  pcap = (pfring_pcap *)ring->priv_data;

  if(pcap->pd)
    pcap_close(pcap->pd);

  free(ring->priv_data);
  ring->priv_data = NULL;
}

/* **************************************************** */

int pfring_mod_pcap_recv(pfring *ring, u_char** buffer, u_int buffer_len,
			 struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet) {
  pfring_pcap *pcap;
  int rc = 0;

  if(ring->priv_data == NULL)
    return(-1);

  pcap = (pfring_pcap *)ring->priv_data;

  if(pcap->pd == NULL)
    return(-2);

  if(ring->reentrant)
    pfring_rwlock_wrlock(&ring->rx_lock);

  if(ring->break_recv_loop) {
    errno = EINTR;
    goto exit; /* retval = 0 */
  }

  if(!pcap->is_pcap_file) {
    while(wait_for_incoming_packet) {
      rc = pfring_mod_pcap_poll(ring, 1 /* sec */);

      if(rc > 0) {
	break;
      } else if((rc == 0) || ring->break_recv_loop) {
        if (ring->break_recv_loop)
          errno = EINTR;
	return(0);
      } else {
	return(-1);
      }
    }
  }

  memset(hdr, 0, sizeof(struct pfring_pkthdr));

  if(buffer_len > 0) {
    /* one copy */
    const u_char *pkt = pcap_next(pcap->pd, (struct pcap_pkthdr *)hdr);

    if(pkt) {
      u_int len = hdr->caplen;

      if(len > ring->caplen) len = ring->caplen;
      if(len > buffer_len)   len = buffer_len;

      memcpy(*buffer, pkt, len);
      rc = 0;
    }
  } else {
    /* zero copy */
    struct pcap_pkthdr *h;

    rc = pcap_next_ex(pcap->pd,
		      (struct pcap_pkthdr **)&h,
		      (const u_char **)buffer);
    if(rc)
      memcpy(hdr, h, sizeof(struct pcap_pkthdr));
  }
  
 exit:
  if(ring->reentrant)
    pfring_rwlock_unlock(&ring->rx_lock);

  return(rc);
}

/* **************************************************** */

int pfring_mod_pcap_enable_ring(pfring *ring) {
  return(0);
}

/* ******************************* */

int pfring_mod_pcap_set_socket_mode(pfring *ring, socket_mode mode) {
  return((mode == recv_only_mode) ? 0 : -1);
}

/* ******************************* */

int pfring_mod_pcap_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  return(0);
}
/* **************************************************** */

int pfring_mod_pcap_poll(pfring *ring, u_int wait_duration) {
  pfring_pcap *pcap;
  fd_set mask;
  struct timeval wait_time;
  int rc;

  if(ring->priv_data == NULL)
    return(-1);
  else
    pcap = (pfring_pcap *)ring->priv_data;

  if(pcap->pd == NULL)
    return(-1);

  if(pcap->is_pcap_file)
    return(1);

  FD_ZERO(&mask);
  FD_SET(pcap->fd, &mask);
  wait_time.tv_sec = wait_duration, wait_time.tv_usec = 0;

  rc = select(pcap->fd+1, &mask, 0, 0, &wait_time);

  if(rc == 1)
    return(1);
  else if((rc == 0) || ring->break_recv_loop)
    return(0);
  else
    return(-1);
}

/* ******************************* */

int pfring_mod_pcap_stats(pfring *ring, pfring_stat *stats) {
  pfring_pcap *pcap = NULL;
  struct pcap_stat ps;

  if(ring->priv_data == NULL)
    return(-1);
  else
    pcap = (pfring_pcap*)ring->priv_data;

  if(pcap->pd == NULL)
    return(-1);

  if(pcap_stats(pcap->pd, &ps) == 0) {
    stats->recv = ps.ps_recv, stats->drop = ps.ps_drop;
    return(0);
  } else
    return(-1);
}

/* **************************************************** */

int pfring_mod_pcap_set_bpf_filter(pfring *ring, char *bpfFilter) {
  pfring_pcap *pcap;
  struct bpf_program fcode;
  int rc;

  if(ring->priv_data == NULL)
    return(-1);

  pcap = (pfring_pcap *)ring->priv_data;

  if(pcap->pd == NULL)
    return(-1);

  if(pcap_compile(pcap->pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
    return(-1);
  } else {
    rc = pcap_setfilter(pcap->pd, &fcode);

    pcap_freecode(&fcode);

    if (rc < 0)
      return(-1);
  }

  return(0);
}
