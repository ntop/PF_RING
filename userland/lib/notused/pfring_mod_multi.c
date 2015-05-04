/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *               Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 */

#include "pfring.h"
#include "pfring_utils.h"
#include "pfring_mod.h"
#include "pfring_mod_multi.h"

// #define MULTI_RING_DEBUG

struct ring_list_element {
  pfring *ring;
  struct ring_list_element *next;
};

int pfring_mod_multi_open(pfring *ring) {
  int rc;
  char *device_list = ring->device_name;
  
  /* Opening master ring */
  ring->device_name = "none";
  rc = pfring_mod_open(ring);
  ring->device_name = device_list;

  if (rc < 0)
    return rc;
  
  ring->close = pfring_mod_multi_close;
  ring->add_hw_rule = pfring_mod_multi_add_hw_rule;
  ring->remove_hw_rule = pfring_mod_multi_remove_hw_rule;
  ring->bind = pfring_mod_multi_bind;
  ring->set_sampling_rate = pfring_mod_multi_set_sampling_rate;
  ring->set_direction = pfring_mod_multi_set_direction;
  ring->enable_rss_rehash = pfring_mod_multi_enable_rss_rehash;

  //TODO
  //? ring->set_virtual_device   
  //? ring->set_channel_id       
  //? ring->set_application_name 
  //? ring->get_num_rx_channels  

  ring->send                = NULL;
  ring->set_cluster         = NULL;
  ring->remove_from_cluster = NULL;
  ring->set_master_id       = NULL;
  ring->set_master          = NULL;

  ring->priv_data = NULL;

  rc = pfring_bind(ring, device_list);

  if (rc < 0) {
    pfring_mod_multi_close(ring);
    return rc;
  }

  return 0;
}

/* ******************************* */

void pfring_mod_multi_close(pfring *ring) {
  pfring_mod_close(ring);
  struct ring_list_element *tmp_elem;
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  ring->priv_data = NULL;

  while(elem != NULL) {
    pfring_close(elem->ring);

    tmp_elem = elem;
    elem = elem->next;
    free(tmp_elem);
  }
}

/* ******************************* */

int pfring_mod_multi_bind(pfring *ring, char *device_name) {
  char *tok, *pos = NULL;
  char dev_name[16];
  int rc;

  tok = strtok_r(device_name, ";", &pos);
    while(tok != NULL){
      pfring *new_ring = NULL;
      struct ring_list_element *elem;

      snprintf(dev_name, sizeof(dev_name), "default:%s", tok);

      new_ring = pfring_open(dev_name, ring->promisc, ring->caplen, 0 /* set in master only */);
      if (new_ring == NULL)
        return -1;

      rc = pfring_set_master(new_ring /* slave */, ring /* master */);
      if (rc < 0)
        return rc;

      elem = malloc(sizeof(struct ring_list_element));
      if (elem == NULL) {
        pfring_close(new_ring);
        return -1;
      }

      elem->ring = new_ring;
      elem->next = (struct ring_list_element *) ring->priv_data;
      ring->priv_data = (void *) elem;

      tok = strtok_r(NULL, ";", &pos);
  }
	  
  return 0;
}

/* ******************************* */

int pfring_mod_multi_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  while(elem != NULL) {
    if (pfring_add_hw_rule(elem->ring, rule) < 0) {
      pfring_remove_hw_rule(ring, rule->rule_id);
      return -1;
    }
    elem = elem->next;
  }
  return 0;
}

/* ******************************* */

int pfring_mod_multi_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  while(elem != NULL) {
    pfring_remove_hw_rule(elem->ring, rule_id);
    elem = elem->next;
  }
  return 0;
}

/* ******************************* */

int pfring_mod_multi_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  while(elem != NULL) {
    if(pfring_set_sampling_rate(elem->ring, rate)<0)
      return -1;
    elem = elem->next;
  }
  return 0;
}

/* ******************************* */

int pfring_mod_multi_set_direction(pfring *ring, packet_direction direction) {
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  while(elem != NULL) {
    if(pfring_set_direction(elem->ring, direction)<0)
      return -1;
    elem = elem->next;
  }
  return 0;
}

/* ******************************* */

int pfring_mod_multi_enable_rss_rehash(pfring *ring) {
  struct ring_list_element *elem = (struct ring_list_element *) ring->priv_data;
  while(elem != NULL) {
    if(pfring_enable_rss_rehash(elem->ring)<0)
      return -1;
    elem = elem->next;
  }
  return 0;
}

