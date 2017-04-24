#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/ip.h>

#define gcc_mb() __asm__ __volatile__("": : :"memory")

#define VALUE_TYPE  u_int32_t
#define NULL_VALUE 0
#define DROP       1
#define PASS       2

//#define DEBUG
#ifdef DEBUG
u_int32_t lookup_max_iterations = 0;
u_int32_t insert_max_iterations = 0;
u_int32_t remove_max_iterations = 0;
#endif

/* *************************************** */

typedef struct {
  u_int32_t ip_version;
  union {
    struct in_addr  v4;
    struct in6_addr v6;
  } ip_address;
} inplace_key_t;

typedef struct {
  /* Note: an entry is valid when value != NULL_VALUE and expiration > now */
  VALUE_TYPE value;
  u_int32_t expiration; /* epoch (sec) */
  inplace_key_t key;
} inplace_item_t;

typedef struct {
  u_int32_t size;
  u_int32_t mask;
  inplace_item_t table[];
} inplace_hash_table_t;

/* *************************************** */

u_int32_t pow2(u_int32_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

/* *************************************** */

int extract_keys(u_char *data, inplace_key_t *src_key, inplace_key_t *dst_key) {
  struct ethhdr *eh = (struct ethhdr*) data;
  u_int16_t l3_offset = sizeof(struct ethhdr);
  u_int16_t eth_type = ntohs(eh->h_proto);

  if (eth_type == 0x8100 /* 802.1q (VLAN) */) {
    struct eth_vlan_hdr *vh = (struct eth_vlan_hdr *) &data[l3_offset];
    eth_type = ntohs(vh->h_proto);
    l3_offset += sizeof(struct eth_vlan_hdr);
  }

  if (eth_type == 0x0800 /* IPv4 */) {
    struct iphdr *ip = (struct iphdr *) &data[l3_offset];
    src_key->ip_version = dst_key->ip_version = 4;
    dst_key->ip_address.v4.s_addr = ip->daddr;
    src_key->ip_address.v4.s_addr = ip->saddr;
    return 1;
  } else if (eth_type == 0x86DD /* IPv6 */) {
    struct kcompact_ipv6_hdr *ipv6 = (struct kcompact_ipv6_hdr *) &data[l3_offset];
    src_key->ip_version = dst_key->ip_version = 6;
    memcpy(&dst_key->ip_address.v6, &ipv6->daddr, sizeof(ipv6->daddr));
    memcpy(&src_key->ip_address.v6, &ipv6->saddr, sizeof(ipv6->saddr));
    return 1;
  }

  return 0;
}

/* *************************************** */

int match_key(inplace_key_t *key1, inplace_key_t *key2) {
  if (key1->ip_version != key2->ip_version) {
    return 0;
  } else if (key1->ip_version == 4) {
    return (key1->ip_address.v4.s_addr ==  key2->ip_address.v4.s_addr);
  } else if (key1->ip_version == 6) {
    return (memcmp(&key1->ip_address.v6, &key2->ip_address.v6, sizeof(key1->ip_address.v6)) == 0);
  } else {
    return 0;
  }
}

/* *************************************** */

u_int32_t compute_hash(inplace_key_t *key) {
  if (key->ip_version == 6) {
    u_int32_t *addr32 = (u_int32_t *) key->ip_address.v6.s6_addr;
    return (addr32[0] + addr32[1] + addr32[2] + addr32[3]);
  } else {
    return ((key->ip_address.v4.s_addr & 0xFFFF) + (key->ip_address.v4.s_addr >> 16)) << 1;
  }
}

/* *************************************** */

void remove_range(inplace_hash_table_t *ht, u_int32_t first_index, u_int32_t last_index) {
  u_int32_t i = 0;

  while (i++ < ht->size) {
    ht->table[first_index].value = NULL_VALUE;
    if (first_index == last_index) break;
    first_index = (first_index + 1) & ht->mask;
  }
}

/* *************************************** */

inplace_hash_table_t *inplace_alloc(u_int32_t size) {
  inplace_hash_table_t *ht;
  size = pow2(size);
  ht = (inplace_hash_table_t *) calloc(1, sizeof(inplace_hash_table_t) + size * sizeof(inplace_item_t));
  ht->size = size;
  ht->mask = size - 1;
  return ht;
}

/* *************************************** */

void inplace_free(inplace_hash_table_t *ht) {
  free(ht);
}

/* *************************************** */

int inplace_insert(inplace_hash_table_t *ht, inplace_key_t *key, u_int32_t expiration, VALUE_TYPE value) {
  u_int32_t hash = compute_hash(key) & ht->mask;
  u_int32_t i = 0, index = hash, last_index;
  int32_t insert_index = -1, first_expired = -1;

  //printf("#%d is %s\n", hash, ht->table[index].value != NULL_VALUE ? "USED" : "EMPTY");

  /* scan all the items until an empty bucket is found */
  while (ht->table[index].value != NULL_VALUE && i++ < ht->size) {
    if (match_key(key, &ht->table[index].key)) {
      if (insert_index == -1)
        insert_index = index; /* replace value */
      else
        ht->table[insert_index].expiration = 0; /* found another slot to replace before, set as expired */
    }

    if (ht->table[index].expiration <= epoch) {
      if (insert_index == -1)
        insert_index = index; /* reuse expired */
      if (first_expired == -1 && insert_index != index)
        first_expired = index;
    } else {
      first_expired = -1;
    }

    last_index = index;
    index = (index + 1) & ht->mask;
  }

#ifdef DEBUG
  if (i > insert_max_iterations)
    insert_max_iterations = i;
#endif

  if (i >= ht->size && insert_index == -1)
    return -1; /* no space or items to replace */

  if (first_expired != -1)
    remove_range(ht, first_expired, last_index);/* clean expired items */
  
  if (insert_index == -1)
    insert_index = index; /* no items to replace: insert new item */ 

  ht->table[insert_index].expiration = expiration;
  memcpy(&ht->table[insert_index].key, key, sizeof(inplace_key_t));
  gcc_mb();
  ht->table[insert_index].value = value; 

  return 0;
}

/* *************************************** */

void inplace_remove(inplace_hash_table_t *ht, inplace_key_t *key) {
   u_int32_t hash = compute_hash(key) & ht->mask;
  u_int32_t i = 0, index = hash, last_index;
  int32_t remove_index = -1, first_expired = -1;

  /* scan all the items until an empty bucket is found */
  while (ht->table[index].value != NULL_VALUE && i++ < ht->size) {
    if (remove_index == -1 && match_key(key, &ht->table[index].key)) {
      remove_index = index;
      ht->table[remove_index].expiration = 0; /* set as expired */
      /* do not break here to check for expired */
    }

    if (ht->table[index].expiration <= epoch) {
      if (first_expired == -1)
        first_expired = index;
    } else {
      first_expired = -1;
    }

    last_index = index;
    index = (index + 1) & ht->mask;
  }

#ifdef DEBUG
  if (i > remove_max_iterations)
    remove_max_iterations = i;
#endif

  if (first_expired != -1) /* clean expired from tail */
    remove_range(ht, first_expired, last_index);

  /* what about also moving back items (here and during insert) to reduce fragmentation? */
}

/* *************************************** */

VALUE_TYPE inplace_lookup(inplace_hash_table_t *ht, inplace_key_t *key) {
  u_int32_t hash = compute_hash(key) & ht->mask;
  u_int32_t i = 0, index = hash;
  VALUE_TYPE value = NULL_VALUE;

  while (ht->table[index].value != NULL_VALUE && i++ < ht->size) {
    if (match_key(key, &ht->table[index].key)) {
      if (ht->table[index].expiration > epoch) 
        value = ht->table[index].value; 
      break; 
    }
    index = (index + 1) & ht->mask;    
  }

#ifdef DEBUG
  if (i > lookup_max_iterations)
    lookup_max_iterations = i;
#endif

  return value;
}

/* *************************************** */

typedef void (*inplace_iterator_handler) (inplace_hash_table_t *ht, inplace_item_t *item);

void inplace_iterate(inplace_hash_table_t *ht, inplace_iterator_handler callback) {
  inplace_item_t tmp;
  u_int32_t i = 0;

  while (i < ht->size) {
    if (ht->table[i].value != NULL_VALUE && ht->table[i].expiration > epoch) {
      memcpy(&tmp, &ht->table[i], sizeof(inplace_item_t));
      callback(ht, &tmp);
    }
    i++;
  }
}

/* *************************************** */

