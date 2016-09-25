/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

/* *********************************************************** */

extern void rule_to_napatech(u_int8_t stream_id, u_int8_t port_id,
			     char *cmd, u_int cmd_len,
			     fast_bpf_rule_core_fields_t *c);
