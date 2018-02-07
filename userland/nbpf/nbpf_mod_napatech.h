/*
 *  Copyright (C) 2016-2018 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

extern void bpf_init_napatech_rules(u_int8_t stream_id, void *opt,
				    int (execCmd)(void *opt, char *cmd));

extern int bpf_rule_to_napatech(u_int8_t stream_id, u_int8_t port_id,
				void *opt, char *cmd, u_int cmd_len,
				nbpf_rule_core_fields_t *c,
				int (execCmd)(void *opt, char *cmd));

