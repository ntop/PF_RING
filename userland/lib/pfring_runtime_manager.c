/*
 *
 * (C) 2023 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

/*

  Example:

  redis-cli RPUSH pfring.filter.host.queue "+10.0.0.1" "+10.0.0.2" "+10.0.0.3"
  redis-cli RPUSH pfring.filter.host.queue "-10.0.0.2"

  PF_RING_RUNTIME_MANAGER="pfring.filter.host.queue" ./pfcount -i mlx:mlx5_0 -v 1

 */

#ifdef HAVE_DL_REDIS

#include "pfring.h"

/* ********************************* */

#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>

#include <hiredis/hiredis.h>

#include "third_party/uthash.h"

//#define REDIS_DEBUG
//#define RUNTIME_DEBUG

/* ********************************* */

static struct thirdparty_func redis_function_ptr[] = {  
  { "redisConnectUnixWithTimeout", NULL },
  { "redisConnectWithTimeout", NULL },
  { "redisCommand", NULL },
  { "freeReplyObject", NULL },
  { "redisFree", NULL },
  { NULL, NULL }
};

#define redisConnectUnixWithTimeout (* (redisContext *(*)(const char *path, const struct timeval tv)) redis_function_ptr[0].ptr)
#define redisConnectWithTimeout (* (redisContext *(*)(const char *ip, int port, const struct timeval tv)) redis_function_ptr[1].ptr)
#define redisCommand (* (void *(*)(redisContext *c, const char *format, ...)) redis_function_ptr[2].ptr)
#define freeReplyObject (* (void (*)(void *reply)) redis_function_ptr[3].ptr)
#define redisFree (* (void (*)(redisContext *c)) redis_function_ptr[4].ptr)

static int init_redis_lib() {
  static int redis_initialized_ok = 0;
  int i, all_right = 1;

  if (redis_initialized_ok != 0)
    return redis_initialized_ok;

  pfring_thirdparty_lib_init("/usr/lib/x86_64-linux-gnu/libhiredis.so", redis_function_ptr);

  for (i = 0; redis_function_ptr[i].name != NULL; i++) {
    if (redis_function_ptr[i].ptr == NULL) {
#ifdef REDIS_DEBUG
      printf("[REDIS] Unable to locate function %s\n", redis_function_ptr[i].name);
#endif
      all_right = -2;
      break;
#ifdef REDIS_DEBUG
    } else {
      printf("[REDIS] Loaded function %s\n", redis_function_ptr[i].name);
#endif
    }
  }
  
  redis_initialized_ok = all_right;
  return redis_initialized_ok;

}

/* ********************************* */

typedef struct {
  union {
    u_int32_t v4;
    struct in6_addr v6;
  } ip;
  u_int8_t ip_version;
} host_hash_key_t;

typedef struct {
  u_int16_t rule_id_s;
  u_int16_t rule_id_d;
} host_hash_value_t;

typedef struct {
  host_hash_key_t key;
  host_hash_value_t value;
  UT_hash_handle hh;
} host_hash_item_t;

typedef struct {
  host_hash_item_t *host_hash;
  u_int32_t num_hosts;
} hash_filter_t;

/* ********************************* */

static int hash_filter_add_host(hash_filter_t *hf, host_hash_key_t *k, host_hash_value_t *value) {
  host_hash_item_t *hp = NULL;
  
  hp = (host_hash_item_t *) calloc(1, sizeof(host_hash_item_t));

  memcpy(&hp->key,   k,     sizeof(host_hash_key_t));
  memcpy(&hp->value, value, sizeof(host_hash_value_t));

  HASH_ADD(hh, hf->host_hash, key, sizeof(host_hash_key_t), hp);
  hf->num_hosts++;

  return 0;
}

/* ********************************* */

static int hash_filter_has_host(hash_filter_t *hf, host_hash_key_t *k, host_hash_value_t **value) {
  host_hash_item_t *hp = NULL;
  host_hash_item_t hk = { 0 };
  
  memcpy(&hk.key, k, sizeof(host_hash_key_t));

  HASH_FIND(hh, hf->host_hash, &hk.key, sizeof(host_hash_key_t), hp);

  if (hp != NULL)
    *value = &hp->value;
  else
    *value = NULL;

  return (hp != NULL);
}

/* ********************************* */

static void hash_filter_delete_host(hash_filter_t *hf, host_hash_key_t *k) {
  host_hash_item_t *hp = NULL;
  host_hash_item_t hk = { 0 };

  memcpy(&hk.key, k, sizeof(host_hash_key_t));

  HASH_FIND(hh, hf->host_hash, &hk.key, sizeof(host_hash_key_t), hp);

  if (hp != NULL) {
    HASH_DEL(hf->host_hash, hp);
    hf->num_hosts--;
    free(hp);
  }
}

/* ********************************* */

static void hash_filter_destroy(hash_filter_t *hf) {
  host_hash_item_t *hp = NULL, *htmp = NULL;

  HASH_ITER(hh, hf->host_hash, hp, htmp) {
    HASH_DEL(hf->host_hash, hp);
    free(hp);
  }
}

/* ********************************* */
/* ********************************* */

static int add_ip_pass_rule(pfring *ring, host_hash_key_t *k, int direction) {
  hw_filtering_rule r = { 0 };
  int rc = -1;

  r.priority = 0; /* Rule priority (0..2) */
  r.rule_id = FILTERING_RULE_AUTO_RULE_ID; /* auto generate rule ID */
  r.rule_family_type = generic_flow_tuple_rule;
  r.rule_family.flow_tuple_rule.action = flow_pass_rule;

  if (k->ip_version == 4) {
    r.rule_family.flow_tuple_rule.ip_version = 4;
    if (direction == 0)
      r.rule_family.flow_tuple_rule.src_ip.v4 = k->ip.v4;
    else
      r.rule_family.flow_tuple_rule.dst_ip.v4 = k->ip.v4;
  } else {
    r.rule_family.flow_tuple_rule.ip_version = 6;
    if (direction == 0)
      memcpy(&r.rule_family.flow_tuple_rule.src_ip.v6, &k->ip.v6, sizeof(r.rule_family.flow_tuple_rule.src_ip.v6));
    else
      memcpy(&r.rule_family.flow_tuple_rule.dst_ip.v6, &k->ip.v6, sizeof(r.rule_family.flow_tuple_rule.dst_ip.v6));
  }

  rc = pfring_add_hw_rule(ring, &r);
  
  if (rc < 0)
    return rc;

  return r.rule_id;
}

/* ********************************* */

static void remove_ip_pass_rule(pfring *ring, u_int16_t rule_id) {
  pfring_remove_hw_rule(ring, rule_id);
}

/* ********************************* */
/* ********************************* */

static redisContext* connect_to_redis(const char *host, u_int16_t port, const char *password, u_int8_t db_id) {
  redisContext *ctx;
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds

  if (init_redis_lib() < 0) return NULL;

  if (host == NULL) return NULL;

  if (host[0] == '/')
    ctx = redisConnectUnixWithTimeout(host, timeout);
  else
    ctx = redisConnectWithTimeout(host, port, timeout);

  if (ctx->err) {
    printf("[REDIS] Connection error: %s", ctx->errstr);
    return NULL;
  }

  if (password && strlen(password) > 0) {
    redisReply *reply = (redisReply *) redisCommand(ctx, "AUTH %s", password);
    if (reply) {
      if (reply->type == REDIS_REPLY_ERROR)
        fprintf(stderr, "* Redis authentication failed: %s\n", reply->str ? reply->str : "?");
      freeReplyObject(reply);
    }
  }

  if (db_id) {
    redisReply *reply = (redisReply *)redisCommand(ctx, "SELECT %u", db_id);
    if (reply) {
      if (reply->type == REDIS_REPLY_ERROR)
        fprintf(stderr, "* %s\n", reply->str ? reply->str : "?");
      freeReplyObject(reply);
    }
  }

  return ctx;
}

/* ********************************* */

static void close_redis(redisContext *context) {
  redisFree(context);
}

/* ********************************* */

static int is_number(const char *s) {
  int i, s_len = strlen(s);

  if (s_len == 0)
    return 0;

  for (i = 0; i < s_len; i++)
    if (!isdigit(s[i])) 
      return 0;

  return 1;
}

/* ********************************* */

static void parse_redis_connection_settings(char *parameters, 
    char *host, int host_len, u_int16_t *port, 
    char *password, int password_len, u_int8_t *db_id) {
  char buf[128] = {'\0'};
  char *r;

  /*
    Supported formats (same as ntopng):
    host:port
    host@redis_instance
    host:port@redis_instance
    host:port:password@redis_instance
  */

  snprintf(buf, sizeof(buf), "%s", optarg);
  r = strrchr(buf, '@');
  if (r) {
    char *idptr = &r[1];
    if (is_number(idptr)) {
      int id = atoi((const char *)idptr);
      if (id < 0 || id > 0xff) {
        fprintf(stderr, "* Redis DB ID provided with --redis|-r cannot be bigger than %u\n", 0xff);
      } else {
        *db_id = id;
      }
      (*r) = '\0';
    }
  }

  if (strchr(buf, ':')) {
    char *w, *c;

    c = strtok_r(buf, ":", &w);

    snprintf(host, host_len, "%s", c);

    c = strtok_r(NULL, ":", &w);
    if (c) *port = atoi(c);

    c = strtok_r(NULL, "\0", &w);
    if (c) snprintf(password, password_len, "%s", c);
  } else if (strlen(buf) > 0) {
    /* only the host */
    snprintf(host, host_len, "%s", buf);
  }
}

/* ********************************* */
/* ********************************* */

static void *dequeue_loop(void *__data) {
  pfring *ring = (pfring *) __data;
  redisContext *redis_context = NULL;
  char *queue_key;
  char *connection_parameters;
  char redis_host[128];
  char redis_password[64];
  u_int16_t redis_port;
  u_int8_t redis_db_id;
  hash_filter_t ht = { 0 };

  queue_key = getenv("PF_RING_RUNTIME_MANAGER");
  if (queue_key == NULL)
    return NULL;

  /* Default connection settings */
  snprintf(redis_host, sizeof(redis_host), "127.0.0.1");
  redis_port = 6379;
  redis_password[0] = '\0';
  redis_db_id = 0;

  connection_parameters = getenv("PF_RING_REDIS_SETTINGS");
  if (connection_parameters != NULL)
    parse_redis_connection_settings(connection_parameters, redis_host, sizeof(redis_host), &redis_port,
      redis_password, sizeof(redis_password), &redis_db_id);

#ifdef RUNTIME_DEBUG
  printf("[Runtime] Starting dequeue loop on %s\n", queue_key);
#endif

  /* Loop - dequeue rules from redis */
  while (!ring->is_shutting_down) {
    int check_for_more_data = 0;

    if (redis_context == NULL)
      redis_context = connect_to_redis(redis_host, redis_port, redis_password, redis_db_id);

    if (redis_context) {
      redisReply *reply = redisCommand(redis_context, "LPOP %s", queue_key);

      if (reply && (redis_context->err == REDIS_OK)) {
        if(reply->str && strlen(reply->str) > 1) {
          char op = reply->str[0];
          char *ip = &reply->str[1];
          host_hash_key_t k = { 0 };
          
          if (strchr(ip, '.') != NULL) {
            k.ip.v4 = ntohl(inet_addr(ip));
            if (k.ip.v4)
              k.ip_version = 4;
          } else {
            if (inet_pton(AF_INET6, ip, &k.ip.v6) <= 0)
              printf("[Runtime] Failure parsing IP '%s'\n", ip);
            else
              k.ip_version = 6;
          }

#ifdef RUNTIME_DEBUG
          printf("[Runtime] > %s\n", reply->str);
#endif

          if (k.ip_version) {
            host_hash_value_t *info;
            int found;

            found = hash_filter_has_host(&ht, &k, &info);

            /* Add */
            if (op == '+') {

              if (!found) {
                int rc_s, rc_d;

                /* Add to the device */
                rc_s = add_ip_pass_rule(ring, &k, 0);
                if (rc_s < 0) {
                  fprintf(stderr, "[Runtime] Failure adding rule '%s src PASS': %d\n", ip, rc_s);
                } else {
                  rc_d = add_ip_pass_rule(ring, &k, 1);
                  if (rc_d < 0) {
                    remove_ip_pass_rule(ring, rc_s);
                    fprintf(stderr, "[Runtime] Failure adding rule '%s dst PASS': %d\n", ip, rc_d);
                  } else {

                    host_hash_value_t value;
                    value.rule_id_s = rc_s;
                    value.rule_id_d = rc_d;
                    /* Add to the hashtable */
                    hash_filter_add_host(&ht, &k, &value);
#ifdef RUNTIME_DEBUG
                    printf("[Runtime] Rule '%s PASS' added successfully\n", ip);
#endif
                  }
                }
              }

            /* Remove */
            } else if (op == '-') {

              if (found) {
                /* Remove from the device by rule id */
                remove_ip_pass_rule(ring, info->rule_id_s);
                remove_ip_pass_rule(ring, info->rule_id_d);
                /* Remove from the hashtable */
                hash_filter_delete_host(&ht, &k);
#ifdef RUNTIME_DEBUG
                  printf("[Runtime] Rule '%s PASS' removed\n", ip);
#endif
              }

            }
          }

          check_for_more_data = 1;
        }

        freeReplyObject(reply);
      } else {
        close_redis(redis_context);
        redis_context = NULL; 
      }
    }

    if (!check_for_more_data)
      sleep(1);
  }

  if (redis_context)
    close_redis(redis_context);

  hash_filter_destroy(&ht);

#ifdef RUNTIME_DEBUG
  printf("[Runtime] Terminate dequeue loop on %s\n", queue_key);
#endif

  return NULL;
}

void pfring_run_runtime_manager(pfring *ring) {

  pfring_set_default_hw_action(ring, default_drop);

  pthread_create(&ring->runtime_manager_thread, NULL, dequeue_loop, (void *) ring);
}

void pfring_stop_runtime_manager(pfring *ring) {
  pthread_join(ring->runtime_manager_thread, NULL);
}

#endif /* HAVE_DL_REDIS */
