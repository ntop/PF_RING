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

#ifndef RULES_HASH
#define RULES_HASH

#ifndef HASH_BUCKETS
#define HASH_BUCKETS 300
#endif

typedef rrc_match_t ruleshash_key;
struct ruleshash_bucket;

typedef struct {
  time_t last_update;
  u_int32_t rule_id;
  u_int8_t policy;
  u_int8_t redirectionPort;
} ruleshash_data;

typedef struct ruleshash_bucket {
  ruleshash_key key;
  ruleshash_data data;
  struct ruleshash_bucket *next;
} ruleshash_bucket_t;

typedef struct {
  ruleshash_bucket_t *buckets[HASH_BUCKETS];
  u_int32_t rule_id_ctr;
  u_int32_t num_rules;
} ruleshash_t;

typedef enum {
  RULESHASH_ITER_CONTINUE,              /* continue the iteration */
  RULESHASH_ITER_STOP,                  /* stop the iteration */
  RULESHASH_ITER_DELETE_CONTINUE,       /* delete the current item and continue */
  RULESHASH_ITER_DELETE_STOP,           /* delete the current item and stop */
} ruleshash_callback_rc;

/*
 * A callback to be called during the hash table iteration.
 *
 */
typedef ruleshash_callback_rc (ruleshash_item_callback)(const ruleshash_key *key, ruleshash_data *data, void *user_data);

/*
 * Set an item in the hash with a policy.
 *
 * If rule_id is 0, then the first item matching the key is updated, otherwise
 * the item with the specified rule_id is updated.
 * 
 * Note: rule_id is both a parameter and a return value:
 *  - as parameter, can be 0 for automatic rule id or contains a valid rule id
 *  - as return value, contains the rule id of the target rule
 *
 * 0 is returned if the rule did already exist and is unchanged
 * 1 is returned if a new rule was added
 * 2 is returned if a rule was modified
 * On error, -errno is returned.
 */
int rules_hash_set(ruleshash_t *hash, ruleshash_key *key, u_int32_t *rule_id, u_int8_t policy, u_int8_t redirectionPort);

/*
 * Checks if an item matches the key or the rule_id into the hash.
 *
 * If rule_id is 0, it looks for the first item matching the key.
 *
 * Return 1 if the element does exist, 0 otherwise.
 */
int rules_hash_is_set(ruleshash_t *hash, ruleshash_key *key, u_int32_t rule_id);

/*
 * Delete the first item which matches the key or the rule_id into the hash.
 *
 * If rule_id is 0, then the first item matching the key is deleted, otherwise
 * the item with the specified rule_id is updated.
 *
 * Return 0 if the element does not exist.
 * Return a positive integer on success with the matched rule id on success.
 * On error, -errno is returned.
 */
int64_t rules_hash_delete(ruleshash_t *hash, ruleshash_key *key, u_int32_t rule_id);

/*
 * Walks the hash table.
 * The callback is called on every hash item and user_data is passed.
 */
void rules_hash_walk(ruleshash_t *hash, ruleshash_item_callback *callback, void *user_data);

/*
 * Removes all the elements into the hash.
 * Returns the number of deleted rules.
 */
u_int32_t rules_hash_clear(ruleshash_t *hash);

#endif /* RULES_HASH */
