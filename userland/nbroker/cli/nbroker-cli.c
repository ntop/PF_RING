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
#include <regex.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <zmq.h>

#include "nbroker_api.h"

#include "linenoise.h"
#include "linenoise.c"

#define HISTORY_FILENAME ".nbroker-cli-history"

static const char *zmq_server_address = "tcp://127.0.0.1:5555";
static void *zmq_context = NULL, *zmq_requester = NULL;

static int debug = 0;

static const char *user_pwd = "admin:admin";

/* **************************************************************** */

int send_command(char *cmd) {
  nbroker_command_header_t header;
  char msg[512] = { '\0' };
  int64_t more;
  size_t more_size = sizeof(more);
  int rc = -1;

  //TODO keep alive and handle disconnections

  zmq_context = zmq_ctx_new();
  zmq_requester = zmq_socket(zmq_context, ZMQ_REQ);
  
  if (!zmq_requester) {
    printf("Unable to initalize ZMQ\n");
    return -1;
  }
  
  zmq_connect(zmq_requester, zmq_server_address);

  memset(&header, 0, sizeof(header));
  zmq_send(zmq_requester, (char *) &header, sizeof(header), ZMQ_SNDMORE);
  zmq_send(zmq_requester, (char *) cmd, strlen(cmd) + 1, 0);

  do {
    if (zmq_recv(zmq_requester, (char *) msg, sizeof(msg), 0) > 0) {
      printf("%s\n", msg);
      rc = 0;
    }
    zmq_getsockopt(zmq_requester, ZMQ_RCVMORE, &more, &more_size);
  } while (more);

  zmq_close(zmq_requester);
  zmq_ctx_destroy(zmq_context);

  return rc;
}

/* **************************************************************** */

const char *supported_commands[] = {
  "default port %s pass",
  "default port %s drop",
  "set port %s match %s pass",
  "set port %s match %s drop",
  "set port %s match %s steer-to %s",
  "delete port %s filtering match %s",
  "delete port %s steering match %s",
  "delete port %s filtering rule %s",
  "delete port %s steering rule %s",
  "clear port %s filtering",
  "clear port %s steering",
  "rules port %s filtering",
  "rules port %s steering",
  "gc idle-for %s",
  NULL
};

/* **************************************************************** */

void print_filter_primitives() {
  printf("\nFILTER is a space-separated list of:\n");
  printf("vlan NUM\n");
  printf("smac|dmac MAC\n");
  printf("shost|dhost IP\n");
  printf("shost|dhost IP/NUM\n");
  printf("shost|dhost IP netmask MASK\n");
  printf("sport|dport NUM\n");
  printf("proto udp|tcp\n");
  printf("proto NUM\n");
  printf("\nExample:\nset port eth1 match shost 8.8.8.8 proto udp sport 53 drop\n\n");
}

/* **************************************************************** */

void print_commands() {
  printf("\nCommands:\n");
  printf("default port PORT pass|drop\n");
  printf("set port PORT match FILTER pass|drop|steer-to [PORT]\n");
  printf("delete port PORT filtering|steering match FILTER\n");
  printf("delete port PORT filtering|steering rule ID\n");
  printf("clear port PORT filtering|steering\n");
  printf("rules port PORT filtering|steering\n");
  printf("gc idle-for SECONDS\n");
  printf("help\n");
  printf("quit\n");

  print_filter_primitives();
}

/* **************************************************************** */

char *head_trim(char *str) {
  while (str[0] == ' ') str++;
  return str;
}

/* **************************************************************** */

void tail_trim(char *str) {
  char *end;
  if (strlen(str) == 0) return;
  end = &str[strlen(str)-1];
  while (end >= str && *end == ' ') { *end = '\0'; end--; }
}

/* **************************************************************** */

void remove_multi_space(char *str) {
  char *dest = str;

  while (*str != '\0') {
    while (*str == ' ' && *(str + 1) == ' ') str++;
    *dest++ = *str++;
  }

  *dest = '\0';
}

/* **************************************************************** */

int handle_command(char *line) {
  int rc = 0;

  line = head_trim(line);
  tail_trim(line);
  remove_multi_space(line);
 
  if (!strcmp(line, "help") || !strcmp(line, "h") || !strcmp(line, "ls")) {
    print_commands();
  } else {
    rc = send_command(line);
  }
  
  return rc;
}

/* **************************************************************** */

void completion(const char *buf, linenoiseCompletions *lc) {
  char field[1024];
  char val1[32], val2[32];
  char *tok; 
  int i;

  if (strncmp("quit", buf, strlen(buf)) == 0)
    linenoiseAddCompletion(lc, "quit");

  if (strncmp("help", buf, strlen(buf)) == 0)
    linenoiseAddCompletion(lc, "help");

  /* global config fields */

  i = -1;
  while (supported_commands[++i] != NULL) {
    val1[0] = 0, val2[0] = 0;
    
    /* substring search */
    if (strncmp(supported_commands[i], buf, strlen(buf)) == 0) {
      strcpy(field, supported_commands[i]);
      tok = strchr(field, '%');
      if (tok != NULL) tok[0] = '\0';
      linenoiseAddCompletion(lc, field);

    /* string with params search (TODO use regexp) */
    } else {
      if (sscanf(buf, supported_commands[i], val1, val2) > 0) {
      sprintf(field, supported_commands[i], val1, val2);
      if (strncmp(field, buf, strlen(buf)) == 0)
        linenoiseAddCompletion(lc, field);
      }
    }
  }
}

/* **************************************************************** */

void help() {
  printf("nbroker-cli [-h] [-c <address>]\n");
  exit(0);
}

/* **************************************************************** */

int main(int argc, char **argv) {
  char prompt[256], *line, *arg_command = NULL;
  int c, rc;
  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  char history_path[256];

  snprintf(history_path, sizeof(history_path), "%s/" HISTORY_FILENAME, homedir);

  while ((c = getopt(argc,argv,"a:dc:C:h")) != '?') {
    if ((c == 255) || (c == -1)) break;
    switch(c) {
      case 'a':
        user_pwd = optarg;
      break;
      case 'c':
        zmq_server_address = strdup(optarg);
      break;
      case 'd':
        debug = 1;
      break;
      case 'C':
        arg_command = optarg;
      break;
      case 'h':
        help();
      break;
    }
  }

  if (arg_command != NULL) {
    rc = handle_command(arg_command);
    return rc;
  }

  linenoiseSetCompletionCallback(completion);

  linenoiseHistoryLoad(history_path);

  snprintf(prompt, sizeof(prompt), "%s> ", zmq_server_address);

  while((line = linenoise(prompt)) != NULL || errno == EAGAIN) {

    if (line == NULL /* && errno == EAGAIN */) continue;

    if (!strcmp(line, "quit") || !strcmp(line, "q") || !strcmp(line, "exit")) {
      free(line);
      break;
    }

    if (line[0] != '\0') {
      rc = handle_command(line);

      if (rc == 0)
        linenoiseHistoryAdd(line);
      else if (rc == -2)
        printf("Unrecognized command: %s\n", line);
      else
        printf("Command failed: %s\n", line);
    }

    free(line);

    snprintf(prompt, sizeof(prompt), "%s> ", zmq_server_address);
  }

  linenoiseHistorySave(history_path);

  return 0;
}
