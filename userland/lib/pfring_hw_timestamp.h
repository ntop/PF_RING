/*
 *
 * (C) 2011-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#define IXIA_TS_LEN            19

struct ixia_hw_ts {
  u_int8_t type;
  u_int8_t timestamp_len;
  u_int32_t sec;
  u_int32_t nsec;
  u_int8_t trailer_len;
  u_int16_t signature;
  u_int16_t fcs;
} __attribute__((__packed__));

/* *********************************************** */

#define VSS_APCON_TS_LEN       sizeof(struct vss_apcon_hw_ts)

struct vss_apcon_hw_ts {
  u_int32_t sec;
  u_int32_t nsec;
  u_int32_t crc;
} __attribute__((__packed__));

