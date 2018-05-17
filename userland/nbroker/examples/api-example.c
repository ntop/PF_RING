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
#include <arpa/inet.h>
#include <unistd.h>

#include "nbroker_api.h"

nbroker_t *bkr;
nbroker_rc_t rc = NBROKER_RC_OK;
rrc_match_t match;
char *target_port = NULL;
char *steering_port = NULL;
u_int32_t rule_id;

/* *************************************** */

int test0() {
  /* list filtering rules */
  u_int32_t num_rules;
  nbroker_rule_t *rules;

  /* add a filtering rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  memset(&match, 0, sizeof(match));
  match.dport.low = htons(80);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);

  /* remove a filtering rule */
  if ((rc = nbroker_remove_rule_by_match(bkr, target_port, &match, NBROKER_TYPE_FILTERING)) != NBROKER_RC_OK) {
    printf("nbroker_remove_rule_by_match failed with code %d\n", rc);
    return 1;
  }

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.dport.low != htons(80)) || (rules[0].u.policy != NBROKER_POLICY_DROP)) {
    printf("%d) Rule list assertion error\n", __LINE__);
    return 1;
  }
  
  free(rules);

  return 0;
}

/* *************************************** */

int rule_with_ids() {
  u_int32_t num_rules;
  nbroker_rule_t *rules;

  memset(&match, 0, sizeof(match));
  match.sport.low = htons(25);
  rule_id = 5;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_PASS)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule #1 failed with code %d\n", rc);
    return 1;
  }

  /* Test the rule has been set correctly */
  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.sport.low != htons(25)) || (rules[0].u.policy != NBROKER_POLICY_PASS)) {
    puts("Rule list assertion error");
    return 1;
  }

  free(rules);

  /* Overwrite the previous rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(443);

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule #2 failed with code %d\n", rc);
    return 1;
  }

  /* Verify the rule has been overwritten */
  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.dport.low != htons(443)) || (rules[0].u.policy != NBROKER_POLICY_DROP) || (rules[0].rule_id != rule_id)) {
    puts("Rule list assertion error");
    return 1;
  }

  free(rules);
  rule_id = NBROKER_AUTO_RULE_ID;

  /* Now add a new rule, it should not be addeded again since the match already exists */
  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("%d) nbroker_set_filtering_rule #3 failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("%d) nbroker_list_rules failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.dport.low != htons(443)) || (rules[0].u.policy != NBROKER_POLICY_DROP)) {
    printf("%d) Rule list assertion error\n", __LINE__);
    return 1;
  }

  free(rules);

  /* Add a completely new rule instead, it should take a new id*/
  memset(&match, 0, sizeof(match));
  match.vlan_id = htons(1);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_PASS)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule #3 failed with code %d\n", rc);
    return 1;
  }

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("%d) nbroker_list_rules failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if (num_rules != 2) {
    printf("%d) Rule list assertion error\n", __LINE__);
    return 1;
  }

  return 0;
}

/* *************************************** */

int pass_all_drop_http() {
  printf("%d) Setting default policy to pass...\n", __LINE__);

  if ((rc = nbroker_set_default_policy(bkr, target_port, NBROKER_POLICY_PASS)) != NBROKER_RC_OK) {
    printf("nbroker_set_default_policy failed with code %d\n", rc);
    return 1;
  }

  printf("%d) Dropping dport 80...\n", __LINE__);
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(80);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  printf("%d) Dropping dport 443...\n", __LINE__);
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(443);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  return 0;
}

/* *************************************** */

int drop_all_pass_7() {
  if ((rc = nbroker_set_default_policy(bkr, target_port, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_default_policy failed with code %d\n", rc);
    return 1;
  }

  memset(&match, 0, sizeof(match));
  match.shost.ip_version = 4;
  match.shost.mask.v4 = 0xFFFFFFFF;
  match.shost.host.v4 = htonl(167772167);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_PASS)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  return 0;
}

/* *************************************** */

int garbage_collect() {
  /* Set a rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  sleep(5);

  /* Set another rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(80);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  /* Collect the old rule, not the new one */
  if ((rc = nbroker_purge_idle_rules(bkr, 4)) != NBROKER_RC_OK) {
    printf("nbroker_purge_idle_rules failed with code %d\n", rc);
    return 1;
  }
 
  u_int32_t num_rules;
  nbroker_rule_t *rules;

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.dport.low != htons(80)) || (rules[0].u.policy != NBROKER_POLICY_DROP)) {
    printf("%d) Rule list assertion error\n", __LINE__);
    return 1;
  }

  free(rules);

  return 0;
}

/* *************************************** */

int port_conversion() {
  u_int8_t int_port, ext_port;

  if ((rc = nbroker_ifname_to_internal_port(bkr, target_port, &int_port)) != NBROKER_RC_OK) {
    printf("%d) nbroker_ifname_to_internal_port error\n", __LINE__);
    return 1;
  }

  if ((rc = nbroker_ifname_to_external_port(bkr, target_port, &ext_port)) != NBROKER_RC_OK) {
    printf("%d) nbroker_ifname_to_external_port error\n", __LINE__);
    return 1;
  }

  if (int_port != 4) {
    printf("Internal port assertion failed: port is %d\n", int_port);
    return 1;
  }

  if (ext_port != 2) {
    printf("External port assertion failed: port is %d\n", ext_port);
    return 1;
  }

  return 0;
}

/* *************************************** */

int returned_rule_id() {
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("%d) nbroker_set_filtering_rule failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if (rule_id != 1) {
    printf("%d) rule_id assert failed: rule_id is %d\n", __LINE__, rule_id);
    return 1;
  }

  rule_id = NBROKER_AUTO_RULE_ID;
  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("%d) nbroker_set_filtering_rule failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if (rule_id != 1) {
    printf("%d) rule_id assert failed: rule_id is %d\n", __LINE__, rule_id);
    return 1;
  }

  match.dport.low = htons(30);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("%d) nbroker_set_filtering_rule failed with code %d\n", __LINE__, rc);
    return 1;
  }

  if (rule_id != 2) {
    printf("%d) rule_id assert failed: rule_id is %d\n", __LINE__, rule_id);
    return 1;
  }

  if (steering_port == NULL) {
    printf("%d) nbroker_set_filtering_rule test requires -s\n", __LINE__);
  } else {
    rule_id = NBROKER_AUTO_RULE_ID;
    if ((rc = nbroker_set_steering_rule(bkr, target_port, &rule_id, &match, steering_port)) != NBROKER_RC_OK) {
      printf("%d) nbroker_set_filtering_rule failed with code %d\n", __LINE__, rc);
      return 1;
    }

    if (rule_id != 1) {
      printf("%d) rule_id assert failed: rule_id is %d\n", __LINE__, rule_id);
      return 1;
    }
  }

  return 0;
}

/* *************************************** */

int rule_string() {
  rrc_match_t *res_match;
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  match.sport.low = htons(80);

  if ((res_match = nbroker_parse_rule("dport 25 sport 80")) == NULL) {
    printf("%d) nbroker_parse_rule failed\n", __LINE__);
    return 1;
  }

  if (memcmp(res_match, &match, sizeof(match)) != 0) {
    printf("%d) nbroker_parse_rule assertion failed\n", __LINE__);
    return 1;
  }

  free(res_match);

  return 0;
}

/* *************************************** */

int auto_rule_purge () {
  /* Set a rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  /* Enable auto purge */
  if ((rc = nbroker_set_auto_purge(bkr, 1)) != NBROKER_RC_OK) {
    printf("nbroker_set_auto_purge failed with code %d\n", rc);
    return 1;
  }

  sleep(3);

  /* Verify it has been purged */
  u_int32_t num_rules;
  nbroker_rule_t *rules;

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if (num_rules != 0) {
    printf("%d) Rule list assertion error: %d\n", __LINE__, num_rules);
    return 1;
  }

  /* Disable auto purge */
  if ((rc = nbroker_set_auto_purge(bkr, 0)) != NBROKER_RC_OK) {
    printf("nbroker_set_auto_purge failed with code %d\n", rc);
    return 1;
  }

  /* Set a rule */
  memset(&match, 0, sizeof(match));
  match.dport.low = htons(25);
  rule_id = NBROKER_AUTO_RULE_ID;

  if ((rc = nbroker_set_filtering_rule(bkr, target_port, &rule_id, &match, NBROKER_POLICY_DROP)) != NBROKER_RC_OK) {
    printf("nbroker_set_filtering_rule failed with code %d\n", rc);
    return 1;
  }

  sleep(3);

  /* Verify it is still there */

  if ((rc = nbroker_list_rules(bkr, target_port, NBROKER_TYPE_FILTERING, &num_rules, &rules)) != NBROKER_RC_OK) {
    printf("nbroker_list_rules failed with code %d\n", rc);
    return 1;
  }

  if ((num_rules != 1) || (rules[0].match.dport.low != htons(25)) || (rules[0].u.policy != NBROKER_POLICY_DROP)) {
    printf("%d) Rule list assertion error\n", __LINE__);
    return 1;
  }

  free(rules);

  return 0;
}

/* *************************************** */

typedef int (test_fn)();

typedef struct {
  test_fn *fn;
  char *description;
} a_test;

a_test tests[] = {
  { test0,              "Simple rule add remove test" },
  { rule_with_ids,      "Test rule id add / delete" },
  { pass_all_drop_http, "Pass all drop http/https traffic" },
  { drop_all_pass_7,    "Drop all but 10.0.0.7 traffic" },
  { garbage_collect,    "Garbage collect with rules" },
  { port_conversion,    "Internal/external ports conversion - expected success on the second port only" },
  { returned_rule_id,   "Check the rule ID returned by nbroker_set_steering_rule/nbroker_set_filtering_rule" },
  { rule_string,        "Conversion from a textual BPF rule into the binary form" },
  { auto_rule_purge,    "Automatic rule purge" }
};

int num_tests = sizeof(tests) / sizeof(tests[0]);

/* *************************************** */

void help() {
  int i;

  printf("api-example - (C) 2017-18 ntop.org\n");
  printf("A sample client for testing binary commands.\n\n");
  printf("-i <port>       Port\n");
  printf("-o <port>       Destination port\n");
  printf("-t <num>        Test number\n");
  printf("-h              Print this help\n");
  printf("\nUsage: sample_client -i <target_port> -o <steering_port> -t <test_number>\n");
  printf("\n%d tests available:\n", num_tests);

  for(i=0; i<num_tests; i++)
    printf("\t%d) %s\n", i, tests[i].description);

  exit(0);
}

/* *************************************** */

int main(int argc, char *argv[]) {
  u_char c;
  int rc;
  int testno = 0;

  while ((c = getopt(argc,argv, "hi:o:t:")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
      case 'i':
        target_port = strdup(optarg);
      break;
      case 'o':
        steering_port = strdup(optarg);
      break;
      case 't':
        testno = atoi(optarg);
      break;
      case 'h':
      default:
        help();
      break;
    }
  }

  if (target_port == NULL) 
    help();

  if (nbroker_init(&bkr, 0) != NBROKER_RC_OK) {
    puts("Broken initialization failed");
    return 1;
  }

  /* reset all the rules */
  if ((rc = nbroker_reset_rules(bkr, target_port, NBROKER_TYPE_FILTERING)) != NBROKER_RC_OK) {
    printf("nbroker_reset_rules failed with code %d\n", rc);
    return 1;
  }

  if ((rc = nbroker_reset_rules(bkr, target_port, NBROKER_TYPE_STEERING)) != NBROKER_RC_OK) {
    printf("nbroker_reset_rules failed with code %d\n", rc);
    return 1;
  }

  if (testno < 0 || testno >= num_tests) {
    puts("Bad test number");
    return 1;
  }

  printf("Running test %d (%s), target_port=%s steering_port=%s\n", 
         testno, tests[testno].description, target_port, steering_port ? steering_port : "none");
  rc = tests[testno].fn();

  if (nbroker_term(bkr) != NBROKER_RC_OK) {
    puts("Broken destroy failed");
    return 1;
  }

  if (rc != 0) {
    puts("Test failed");
    return 1;
  } else {
    puts("Success");
    return 0;
  }
  
  return 0;
}

/* *************************************** */

