/*
 * (C) 2003-2019 - ntop 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <pthread.h>

#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>

#ifndef HAVE_DPDK
#include "pfring.h"
#include "../lib/config.h"
#endif

#include "../examples/pfutils.c"

#define CACHE_LINE_LEN 64

/* ******************************** */

u_int32_t days_left(time_t to) {
  return (to - time(NULL)) / 86400;
}

/* *************************************** */

char *ctime_nonl(time_t time) {
  char *s = ctime(&time);
  s[strlen(s) - 1] = '\0';
  return s;
}

/* *************************************** */

