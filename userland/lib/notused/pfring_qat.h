/*
 *
 * (C) 2013 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Part of this code has been taken from Intel QAT PM examples
 *
 * Many thanks to Intel and in particular
 * - Joseph Gasparakis <joseph.gasparakis@intel.com>
 * - James Chapman <james.p.chapman@intel.com>
 *
 *
 */

#ifndef _PFRING_QAT_H_
#define _PFRING_QAT_H_

#include <cpa_types.h>
#include "cpa_pm.h"
#include "cpa_pm_compile.h"

typedef struct {
  Cpa16U nInstances;
  CpaInstanceHandle * pHandles;
  CpaInstanceHandle instanceHandle;
  size_t len;
  Cpa32U sessionCtxSize;
  CpaPmSessionProperty sessionProperty;
  CpaPmSessionCtx sessionCtx;
  u_int num_loops;
  Cpa32U patternId;
  Cpa32U compileOptions;
  CpaPmPdbPatternSetHandle patternSetHandle;
  CpaPmPdbHandle pdbHandle;
  u_int32_t num_matches;
  char *pBuffer;
  int *pMatchArray;
  CpaFlatBuffer   flatBuffer;
  CpaBufferList   bufferList;
  CpaPmMatchResult matchResults[50];
  CpaPmMatchCtx   matchCtxList;
  CpaPmMatchCtx *pMatchCtxError;
  u_int8_t searchInitialized;
  u_int64_t num_filtered;
} QAThandle;


#endif /* _PFRING_QAT_H_ */
