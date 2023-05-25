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

#ifdef HAVE_DL_REDIS

#include "pfring.h"

/* ********************************* */

#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <hiredis/hiredis.h>

//#define REDIS_DEBUG
#define RUNTIME_DEBUG

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

static redisContext* connect_to_redis(const char *host, u_int16_t port) {
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

  return ctx;
}

static void close_redis(redisContext *context) {
  redisFree(context);
}

static void add_ip_pass_rule(pfring *ring, char *ip) {
  hw_filtering_rule r = { 0 };
  u_int32_t addr = ntohl(inet_addr(ip));
  int rc = -1;

  if (!addr) goto print_rc;

  r.priority = 0; /* Rule priority (0..2) */
  r.rule_id = FILTERING_RULE_AUTO_RULE_ID; /* auto generate rule ID */
  r.rule_family_type = generic_flow_tuple_rule;
  r.rule_family.flow_tuple_rule.action = flow_pass_rule;
  r.rule_family.flow_tuple_rule.ip_version = 4;
  r.rule_family.flow_tuple_rule.src_ip.v4 = addr;
  //r.rule_family.flow_tuple_rule.protocol = IPPROTO_UDP;

  rc = pfring_add_hw_rule(ring, &r);

 print_rc:
  if (rc < 0)
    fprintf(stderr, "Failure adding rule '%s PASS': %d\n", ip, rc);
  else
    printf("Rule '%s PASS' added successfully\n", ip);
}

static void *dequeue_loop(void *__data) {
  pfring *ring = (pfring *) __data;
  redisContext *redis_context = NULL;
  char buf[1024];
  char *queue_key;

  /* Hardcoded configuration (TODO expose via env vars) */
  char *redis_host = "127.0.0.1";
  u_int16_t redis_port = 6379;

  queue_key = getenv("PF_RING_RUNTIME_MANAGER");

  if (queue_key == NULL)
    return NULL;

#ifdef RUNTIME_DEBUG
  printf("[Runtime] Starting dequeue loop on %s\n", queue_key);
#endif

  /* Loop - dequeue rules from redis */
  while (!ring->is_shutting_down) {
    int check_for_more_data = 0;

    if (redis_context == NULL)
      redis_context = connect_to_redis(redis_host, redis_port);

    if (redis_context) {
      redisReply *reply = redisCommand(redis_context, "LPOP %s", queue_key);

      if (reply && (redis_context->err == REDIS_OK)) {
        if(reply->str) {
          buf[0] = '\0';
          snprintf(buf, sizeof(buf), "%s", reply->str);

          //printf("> %s\n", buf);
          add_ip_pass_rule(ring, buf);

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
