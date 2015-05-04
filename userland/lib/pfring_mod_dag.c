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

#include "pfring_mod_dag.h"


//#define DAG_DEBUG

int pfring_dag_open(pfring *ring) {
  int i = 0;
  pfring_dag *d = NULL;
  uint32_t mindata;
  struct timeval maxwait;
  struct timeval poll;
  daginf_t* info;
  uint8_t stream_erf_types[MAX_CARD_ERF_TYPES];
  uint8_t supported = 0;

#ifdef DAG_DEBUG
  printf("[PF_RING] DAG open\n");
#endif

  ring->close              = pfring_dag_close;
  ring->stats              = pfring_dag_stats;
  ring->recv               = pfring_dag_recv;
  ring->set_poll_watermark = pfring_dag_set_poll_watermark;
  ring->set_poll_duration  = pfring_dag_set_poll_duration;
  ring->poll               = pfring_dag_poll;
  ring->set_direction      = pfring_dag_set_direction;
  ring->set_socket_mode    = pfring_dag_set_socket_mode;
  ring->enable_ring        = pfring_dag_enable_ring;

  ring->priv_data = malloc(sizeof(pfring_dag)); 

  if(ring->priv_data == NULL)
    goto ret_error; 
  
  memset(ring->priv_data, 0, sizeof(pfring_dag));
  d = ring->priv_data;

  if(ring->caplen > MAX_CAPLEN) 
    ring->caplen = MAX_CAPLEN;

  d->device_name = (char *) malloc(DAGNAME_BUFSIZE);

  if (d->device_name == NULL) {
    goto free_private;
  }

  if (dag_parse_name(ring->device_name, d->device_name, DAGNAME_BUFSIZE, &d->stream_num) < 0) {
    fprintf(stderr,"Error: device name not recognized\n");
    goto free_device_name;
  }

  if (d->stream_num % 2) {
    fprintf(stderr,"Error: odd-numbered streams are TX streams\n");
    goto free_device_name;
  }

  if((d->fd = dag_open((char *) d->device_name)) < 0) {
    fprintf(stderr, "Error opening %s\n", d->device_name);
    goto free_device_name;
  }

  if (dag_attach_stream(d->fd, d->stream_num, 0, 0) < 0) {
    fprintf(stderr, "Error attaching to stream %d: is it already attached to another application?\n", d->stream_num);
    goto dag_close;
  }

  if (dag_get_stream_poll(d->fd, d->stream_num, &mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error getting poll info\n");
    goto dag_detach;
  }
	
  ring->poll_duration = DEFAULT_POLL_DURATION;

  mindata = DEFAULT_MIN_PKT_QUEUED * AVG_PACKET_SIZE; //min_pkt=128, avg=512 -> min_bytes=65536

  maxwait.tv_sec  =  ring->poll_duration / 1000;
  maxwait.tv_usec = (ring->poll_duration % 1000) * 1000;

  if (dag_set_stream_poll(d->fd, d->stream_num, mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error setting poll info\n");
    goto dag_detach;
  }

  if(dag_start_stream(d->fd, d->stream_num) < 0) {
    fprintf(stderr, "Error starting stream\n");
    goto dag_detach;
  }

  d->bottom = NULL;
  d->top    = NULL;

  d->strip_crc = 1;

  info = dag_info(d->fd);
  if (info->device_code == 0x4200 || info->device_code == 0x4230) //these cards already strip the CRC
    d->strip_crc = 0;

  memset(stream_erf_types, 0, MAX_CARD_ERF_TYPES);

  if (dag_get_stream_erf_types(d->fd, d->stream_num, stream_erf_types, MAX_CARD_ERF_TYPES) < 0) {
    fprintf(stderr, "Error getting stream type\n");
    goto dag_stop;
  }

  while (stream_erf_types[i] && i<MAX_CARD_ERF_TYPES)
    switch(stream_erf_types[i++] & 0x7f) {
    case TYPE_ETH:
    case TYPE_COLOR_ETH:
    case TYPE_DSM_COLOR_ETH:
    case TYPE_COLOR_HASH_ETH:
      supported = 1;
      break;
    default:
      break;
    }
  
  if (!supported){
    fprintf(stderr, "Error: stream type not supported\n");
    goto dag_stop;
  }

  return 0;

 dag_stop:
  dag_stop_stream(d->fd, d->stream_num);
	
 dag_detach:
  dag_detach_stream(d->fd, d->stream_num);

 dag_close:
  dag_close(ring->fd);

 free_device_name:
  free(d->device_name);

 free_private:
  free(ring->priv_data);

 ret_error:
  return -1;
}

/* **************************************************** */

void pfring_dag_close(pfring *ring) {
  pfring_dag *d;
 
  if(ring->priv_data == NULL) 
    return;

  d = (pfring_dag *) ring->priv_data;

  dag_stop_stream(d->fd, d->stream_num);
  dag_detach_stream(d->fd, d->stream_num);
  dag_close(d->fd);

  free(d->device_name);
  free(ring->priv_data);
}

/* **************************************************** */

int pfring_dag_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet) {
  int caplen = 0;
  int skip;
  dag_record_t *erf_hdr;
  uint16_t rlen;
  u_char *payload;
  uint8_t *ext_hdr_type;
  uint32_t ext_hdr_num;
  uint32_t len;
  unsigned long long ts;
  int retval = 0;
  pfring_dag *d;

#ifdef DAG_DEBUG
  printf("[PF_RING] DAG recv\n");
#endif

  if(ring->priv_data == NULL) 
    return -1;

  d = (pfring_dag *) ring->priv_data;

  if(ring->reentrant)
    pthread_rwlock_wrlock(&ring->rx_lock);

 check_and_poll:

  if (ring->break_recv_loop)
    goto exit; /* retval = 0 */

  if ((d->top - d->bottom) < dag_record_size) {

    if ( (d->top = dag_advance_stream(d->fd, d->stream_num, (void * /* but it is void** */) &d->bottom)) == NULL) {
      retval = -1;
      goto exit;
    }

    if ( (d->top - d->bottom) < dag_record_size && !wait_for_incoming_packet )
      goto exit; /* retval = 0 */
		
    goto check_and_poll;
  }

  erf_hdr = (dag_record_t *) d->bottom;

  rlen = ntohs(erf_hdr->rlen);

  if (rlen < dag_record_size) {
    fprintf(stderr, "Error: wrong record size\n");
    retval = -1;
    goto exit;
  }

  d->bottom += rlen;

  skip = 0;    
  switch((erf_hdr->type & 0x7f)) {
  case TYPE_PAD:
    skip = 1;
  case TYPE_ETH:
    /* stats update */
    if (erf_hdr->lctr) {
      if (d->stats_drop > (UINT_MAX - ntohs(erf_hdr->lctr))) 
	d->stats_drop = UINT_MAX;
      else
	d->stats_drop += ntohs(erf_hdr->lctr);
    }
    break;
    /* Note: 
     * In TYPE_COLOR_HASH_ETH, TYPE_DSM_COLOR_ETH, TYPE_COLOR_ETH 
     * the color value overwrites the lctr */
  default:
    break;
  }
		
  if (skip)
    goto check_and_poll;

  payload = (u_char *) erf_hdr;
  payload += dag_record_size;

  /* computing extension headers size */
  ext_hdr_type = &erf_hdr->type;
  ext_hdr_num  = 0;
  while ( (*ext_hdr_type & 0x80) && (rlen > (16 + ext_hdr_num * 8)) ) {
    ext_hdr_type += 8;
    ext_hdr_num++;
  }
  payload += 8 * ext_hdr_num;
  
  switch((erf_hdr->type & 0x7f)) {
  case TYPE_COLOR_HASH_ETH:
  case TYPE_DSM_COLOR_ETH:
  case TYPE_COLOR_ETH:
    /*
     * Note:
     * In TYPE_COLOR_HASH_ETH, TYPE_DSM_COLOR_ETH, TYPE_COLOR_ETH 
     * the color value overwrites the lctr
     */
    hdr->extended_hdr.pkt_hash /* 32bit */ =  erf_hdr->lctr /* 16bit */;

  case TYPE_ETH:

    len = ntohs(erf_hdr->wlen);
    if (d->strip_crc)
      len -= 4;

    caplen  = rlen;
    caplen -= dag_record_size;
    caplen -= (8 * ext_hdr_num);
    caplen -= 2;

    if (caplen > ring->caplen)
      caplen = ring->caplen;

    if (caplen > len) 
      caplen = len;
     
    if((buffer_len > 0) && (caplen > buffer_len))
      caplen = buffer_len;

    payload += 2;

    break;
  default:
#ifdef DAG_DEBUG
    printf("Warning: unhandled ERF type\n");
#endif
    goto check_and_poll;
  }

  if (buffer_len > 0){
    if(*buffer != NULL && caplen > 0)
      memcpy(*buffer, payload, caplen);
  }
  else
    *buffer = payload;

  hdr->caplen = caplen;
  hdr->len = len;

  /* computing timestamp as from DAG docs */
  ts = erf_hdr->ts;
  hdr->ts.tv_sec = ts >> 32;
  ts = (ts & 0xffffffffULL) * 1000000;
  ts += 0x80000000;
  hdr->ts.tv_usec = ts >> 32;		
  if (hdr->ts.tv_usec >= 1000000) {
    hdr->ts.tv_usec -= 1000000;
    hdr->ts.tv_sec++;
  }

  /* compute pf_ring timestamp_ns from ERF time stamp */
  ts = erf_hdr->ts;
  ts = (ts & 0xffffffffULL) * 1000000000;
  ts += 0x80000000;
  ts >>= 32;
  ts += ((erf_hdr->ts >> 32) * 1000000000);
  hdr->extended_hdr.timestamp_ns = ts;

#ifdef PFRING_DAG_PARSE_PKT
  pfring_parse_pkt(*buffer, hdr, 4, 0, 1);
#else
  hdr->extended_hdr.parsed_header_len = 0;
#endif

  d->stats_recv++;
	
  retval = 1;
           
 exit:

  if(ring->reentrant) 
    pthread_rwlock_unlock(&ring->rx_lock);

  return retval;
}

/* **************************************************** */

int pfring_dag_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  uint32_t mindata;
  struct timeval maxwait;
  struct timeval poll;
  pfring_dag *d;

  if(ring->priv_data == NULL) 
    return -1;

  d = (pfring_dag *) ring->priv_data;

  if (dag_get_stream_poll(d->fd, d->stream_num, &mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error getting poll info\n");
    return -1;
  }

  mindata = watermark * AVG_PACKET_SIZE;

  if (dag_set_stream_poll(d->fd, d->stream_num, mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error setting poll watermark\n");
    return -1;
  }

  return 0;
}

/* **************************************************** */

int pfring_dag_set_poll_duration(pfring *ring, u_int duration) {
  uint32_t mindata;
  struct timeval maxwait;
  struct timeval poll;
  pfring_dag *d;

  if(ring->priv_data == NULL) 
    return -1;

  d = (pfring_dag *) ring->priv_data;

  if (dag_get_stream_poll(d->fd, d->stream_num, &mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error getting poll info\n");
    return -1;
  }

  ring->poll_duration = duration;

  maxwait.tv_sec  =  ring->poll_duration / 1000;
  maxwait.tv_usec = (ring->poll_duration % 1000) * 1000;

  if (dag_set_stream_poll(d->fd, d->stream_num, mindata, &maxwait, &poll) < 0) {
    fprintf(stderr, "Error setting poll duration\n");
    return -1;
  }
  
  return 0;
}

/* **************************************************** */

int pfring_dag_stats(pfring *ring, pfring_stat *stats) {
  pfring_dag *d;

  if(ring->priv_data == NULL) 
    return -1;

  d = (pfring_dag *) ring->priv_data;

  stats->recv = d->stats_recv;
  stats->drop = d->stats_drop;
  return 0;
}

/* **************************************************** */

int pfring_dag_set_direction(pfring *ring, packet_direction direction) {

  if (direction == rx_only_direction || direction == rx_and_tx_direction)
    return 0;

  return -1;
}

/* **************************************************** */

int pfring_dag_set_socket_mode(pfring *ring, socket_mode mode) {
  if (mode == recv_only_mode)
    return 0;

  /* TODO send mode */

  return -1;
}

/* **************************************************** */

int pfring_dag_enable_ring(pfring *ring) {
  /* nothing to do */
  return 0;
}

/* **************************************************** */

int pfring_dag_poll(pfring *ring, u_int wait_duration) {
  pfring_dag *d;

  if(ring->priv_data == NULL)
    return -1;

  d = (pfring_dag *) ring->priv_data;
  
  if ((d->top - d->bottom) >= dag_record_size)
    return 1;

  if ( (d->top = dag_advance_stream(d->fd, d->stream_num, (void * /* but it is void** */) &d->bottom)) == NULL)
    return -1;

  if ( (d->top - d->bottom) < dag_record_size )
    return 0;
  
  return 1;
}

