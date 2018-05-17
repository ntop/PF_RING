/*
 *  Copyright (C) 2017-2018 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "utils.h"
#include "common.h"
#include "rules_hash.h"

/* *********************************************************** */

static u_int32_t calculate_hash(void *key, size_t keysize) {
  size_t iterations = keysize / 4;
  int i, left_over = keysize % 4;
  u_int32_t sum = 0;

  for (i=0; i<iterations; i++)
    sum += ((u_int32_t *)key)[i];

  for (i=0; i<left_over; i++)
    sum += ((u_char *)key)[keysize - i - 1];

#ifdef DEBUG_HASH
  printf("hashing @%p~%ld -- iterations=%ld left_over=%d -> %d\n",
        key, keysize, iterations, left_over, sum);
#endif

  return sum;
}

/* *********************************************************** */

static int get_hash_bucket(ruleshash_key *key) { return calculate_hash(key, sizeof(ruleshash_key)) % HASH_BUCKETS; }

/* *********************************************************** */

/* Search an item by key.
 *
 * If the item is found, [out] points to the bucket holding the item
 * If the item is not found, [out] points NULL
 * The [prev] pointer points to previous item, which can be NULL for buckets head
 *
 */
static void hash_find_bucket(ruleshash_bucket_t *head, ruleshash_key *key,
        ruleshash_bucket_t **prev, ruleshash_bucket_t **out) {
  *prev = NULL;

  while ((head != NULL) && memcmp(key, &head->key, sizeof(ruleshash_key)) != 0) {
    *prev = head;
    head = head->next;
  }

  *out = head;
}

/* *********************************************************** */

static void find_by_rule_id(ruleshash_t *hash, u_int32_t rule_id, ruleshash_bucket_t **prev, ruleshash_bucket_t **bucket, int *i) {
  for (*i=0; *i<HASH_BUCKETS; (*i)++) {
    *prev = NULL;
    *bucket = hash->buckets[*i];

    while (*bucket != NULL) {
      if ((*bucket)->data.rule_id == rule_id) {
        /* Found */
        traceEvent(TRACE_NORMAL, "Found rule by id: id=%d\n", rule_id);
        return;
      }

      *prev = *bucket;
      *bucket = (*bucket)->next;
    }
  }

  /* Not found */
  *prev = *bucket = NULL;
}

/* *********************************************************** */

/* Returns 1 if the rule data was changed, 0 otherwise */
static int bucket_update_data(ruleshash_bucket_t * bucket, ruleshash_key *key, u_int32_t rule_id, u_int8_t policy, u_int8_t redirectionPort) {
  int rv = 0;

  if ((memcmp(&bucket->key, key, sizeof(ruleshash_key)) != 0)
      || (bucket->data.policy != policy)
      || ((policy == RRC_POLICY_STEER) && (bucket->data.redirectionPort != redirectionPort))) {
    memcpy(&bucket->key, key, sizeof(ruleshash_key));
    bucket->data.policy = policy;
    bucket->data.redirectionPort = redirectionPort;
    rv = 1;
  }

  bucket->data.rule_id = rule_id;
  bucket->data.last_update = time(0);
  return rv;
}

/* *********************************************************** */

static ruleshash_callback_rc rule_match_id_callback(const ruleshash_key *key, ruleshash_data *data, void *user_data) {
  u_int32_t rule_id = *(u_int32_t *) user_data;
  
  if (data->rule_id == rule_id) {
    *(u_int32_t *) user_data = 0;
    return RULESHASH_ITER_STOP;
  }

  return RULESHASH_ITER_CONTINUE;
}

/* *********************************************************** */

static u_int32_t gen_new_rule_id(ruleshash_t *hash) {
  u_int32_t start_id, cur_id, search_id;
  int first = 1;

  start_id = cur_id = hash->rule_id_ctr + 1;

  while((cur_id != start_id) || first) { /* avoid infinite loop */
    first = 0;
    search_id = cur_id;
    rules_hash_walk(hash, rule_match_id_callback, &search_id);

    if (search_id == cur_id) {
      hash->rule_id_ctr = cur_id;
      return cur_id;
    }

    cur_id++;
  }

  traceEvent(TRACE_ERROR, "No rule ids available - some rule will be overwritten\n");
  hash->rule_id_ctr = cur_id;
  return cur_id;
}

/* *********************************************************** */

int rules_hash_set(ruleshash_t *hash, ruleshash_key *key, u_int32_t *rule_id, u_int8_t policy, u_int8_t redirectionPort) {
  int id_bucket = -1; /* the bucket holding the match by id */
  int key_bucket;     /* the bucekt holding the match by key */
  int new_alloc = 0;
  ruleshash_bucket_t *bucket, *id_prev, *key_prev;

  key_bucket = get_hash_bucket(key);

  if (*rule_id) {
    find_by_rule_id(hash, *rule_id, &id_prev, &bucket, &id_bucket);

    key_prev = hash->buckets[key_bucket];

    while (key_prev && key_prev->next)
      key_prev = key_prev->next;
  } else {
    hash_find_bucket(hash->buckets[key_bucket], key, &key_prev, &bucket);

    if (bucket)
      *rule_id = bucket->data.rule_id;
  }

  /* note: id_bucket, key_prev, key_bucket are always valid here */

  if (bucket == NULL) {
    /* New item */
    bucket = (ruleshash_bucket_t *) calloc(1, sizeof(ruleshash_bucket_t));
    if (bucket == NULL)
      return -errno;

    /* Auto rule id */
    if (! *rule_id)
      *rule_id = gen_new_rule_id(hash);

    traceEvent(TRACE_NORMAL, "Adding new rule #%d\n", *rule_id);

    if (key_prev == NULL)
      hash->buckets[key_bucket] = bucket;
    else
      key_prev->next = bucket;

    new_alloc = 1;
    hash->num_rules++;
  } else if ((id_bucket >= 0) && (id_bucket != key_bucket)) {
    /* A rule id was specified, but a bucket move is needed */
    traceEvent(TRACE_NORMAL, "Moving item from bucket %d to %d\n", id_bucket, key_bucket);

    /* Unlink */
    if (id_prev)
      id_prev->next = bucket->next;
    else
      hash->buckets[id_bucket] = NULL;

    bucket->next = NULL;

    /* Append to new bucket */
    if (key_prev == NULL)
      hash->buckets[key_bucket] = bucket;
    else
      key_prev->next = bucket;
  }

  if (bucket_update_data(bucket, key, *rule_id, policy, redirectionPort)) {
    if (new_alloc)
      /* new rule */
      return 1;
    else
      /* rule changed */
      return 2;
  }

  /* rule unchanged */
  return 0;
}

/* *********************************************************** */

int rules_hash_is_set(ruleshash_t *hash, ruleshash_key *key, u_int32_t rule_id) {
  int b;
  ruleshash_bucket_t *bucket, *prev;

  if (rule_id) {
    find_by_rule_id(hash, rule_id, &prev, &bucket, &b);
  } else {
    b = get_hash_bucket(key);
    hash_find_bucket(hash->buckets[b], key, &prev, &bucket);
  }

  return (bucket != NULL);
}

/* *********************************************************** */

int64_t rules_hash_delete(ruleshash_t *hash, ruleshash_key *key, u_int32_t rule_id) {
  int b;
  ruleshash_bucket_t *bucket, *prev;

  if (rule_id) {
    find_by_rule_id(hash, rule_id, &prev, &bucket, &b);
  } else {
    b = get_hash_bucket(key);
    hash_find_bucket(hash->buckets[b], key, &prev, &bucket);
  }

  if (bucket == NULL)
    /* Not found */
    return 0;

  if (prev)
    prev->next = bucket->next;
  else
    hash->buckets[b] = bucket->next;

  rule_id = bucket->data.rule_id;
  free(bucket);
  hash->num_rules--;

  return rule_id;
}

/* *********************************************************** */

void rules_hash_walk(ruleshash_t *hash, ruleshash_item_callback *callback, void *user_data) {
  ruleshash_bucket_t *bucket, *next, *prev;
  ruleshash_callback_rc rc = RULESHASH_ITER_CONTINUE;
  int i;

  for (i = 0; i < HASH_BUCKETS; i++) {
    bucket = hash->buckets[i];
    prev = NULL;

    while ((bucket != NULL) && (rc != RULESHASH_ITER_STOP) && (rc != RULESHASH_ITER_DELETE_STOP)) {
      next = bucket->next;

      rc = callback(&bucket->key, &bucket->data, user_data);

      if (rc == RULESHASH_ITER_DELETE_CONTINUE || rc == RULESHASH_ITER_DELETE_STOP) {
        /* Delete the item */
        free(bucket);
        hash->num_rules--;

        if (prev)
          prev->next = next;
        else
          hash->buckets[i] = next;
      }

      bucket = next;
    }
  }
}

/* *********************************************************** */

static ruleshash_callback_rc reset_rules_callback(const ruleshash_key *key, ruleshash_data *data, void *user_data) {
  return RULESHASH_ITER_DELETE_CONTINUE;
}

/* *********************************************************** */

u_int32_t rules_hash_clear(ruleshash_t *hash) {
  u_int32_t deleted_rules = hash->num_rules;

  rules_hash_walk(hash, reset_rules_callback, NULL);
  hash->rule_id_ctr = 0;

  return deleted_rules;
}

/* *********************************************************** */

