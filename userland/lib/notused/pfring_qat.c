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

#include "pfring_qat.h"

/* *********************************************************** */

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static u_int32_t g_nAppMatches = 0, g_nAppCallbacks = 0;

/* *********************************************************** */

void AppMatchCallback(const CpaInstanceHandle instanceHandle,
		      CpaPmMatchCtx *pMatchCtx) {  
  size_t n;

  g_nAppCallbacks++;
  for(n=0; n<pMatchCtx->numMatchResults; n++) {
    CpaPmMatchResult *pResult = &pMatchCtx->pMatchResult[n];

      if(pResult->matchLength > 0) {
	int *pNumMatches = (int *)pMatchCtx->userData;
	
	if(pNumMatches != NULL) {
	  g_nAppMatches += pNumMatches[pResult->patternId];
	} else
	  g_nAppMatches++;
      }
  }
}

/* *********************************************************** */

void initQAThandle(QAThandle *handle) {
  CpaPmSessionProperty sessionProperty = { CPA_TRUE, 1, { 1 } };
  CpaBufferList   bufferList = {1, &handle->flatBuffer, NULL, NULL};
  CpaPmMatchCtx   matchCtxList = {
    NULL,
    &handle->bufferList,
    NULL,
    CPA_PM_MATCH_OPTION_RESET_SESSION | CPA_PM_MATCH_OPTION_END_OF_SESSION,
    AppMatchCallback,
    NULL,
    DIM(handle->matchResults),
    handle->matchResults
  };

  memset(handle, 0, sizeof(QAThandle));
  memcpy(&handle->sessionProperty, &sessionProperty, sizeof(sessionProperty));
  memcpy(&handle->bufferList, &bufferList, sizeof(bufferList));
  memcpy(&handle->matchCtxList, &matchCtxList, sizeof(matchCtxList));
  handle->patternId = 1;
  handle->compileOptions = CPA_PM_COMPILE_OPTION_NONE;


  /* Get an instance */
  cpaPmGetNumInstances(&handle->nInstances);
  handle->pHandles = (CpaInstanceHandle *)calloc(handle->nInstances, sizeof(CpaInstanceHandle));
  cpaPmGetInstances(handle->nInstances, handle->pHandles);
  handle->instanceHandle = handle->pHandles[0];

  /* Start the instance */
  cpaPmStartInstance(handle->instanceHandle);
  free(handle->pHandles);

  /* Generate and activate a PDB */
  cpaPmPdbCreatePatternSet(handle->instanceHandle, 0, &handle->patternSetHandle);
}

/* *********************************************************** */

int addStringToSearch(QAThandle *handle, char *str) {

  if(handle->searchInitialized) return(-1);

  if(str == NULL) return(-1);

  cpaPmPdbAddPattern(handle->instanceHandle,
		     handle->patternSetHandle,
		     handle->patternId++,
		     CPA_PM_PDB_OPTIONS_CASELESS,
		     strlen(str),
		     (const Cpa8U*)str,
		     (const Cpa16U)1 /* patternGroupId */);
  return(0);
}

/* *********************************************************** */

u_int checkMatch(QAThandle *handle, char *data_to_search, u_int data_to_search_len) {
  int debug = 0;

  if(!handle->searchInitialized) {
    // Compile the patterns and activate the PDB
    cpaPmPdbCompile(handle->instanceHandle, handle->patternSetHandle, handle->compileOptions, NULL, &handle->pdbHandle);
    
    // Activate the pdb
    cpaPmActivatePdb(handle->instanceHandle, handle->pdbHandle, NULL);
    
    /* Setup Session Context and Match Context */
    cpaPmSessionCtxGetSize(handle->instanceHandle, &handle->sessionProperty, &handle->sessionCtxSize);
    cpaPmCreateSessionCtx(handle->instanceHandle, &handle->sessionProperty, (Cpa8U *)malloc(handle->sessionCtxSize), &handle->sessionCtx);    
    handle->matchCtxList.sessionCtx = handle->sessionCtx, handle->matchCtxList.userData = handle->pMatchArray;
    handle->searchInitialized = 1;
  }

  handle->matchCtxList.pBufferList[0].pBuffers->dataLenInBytes = data_to_search_len;
  handle->matchCtxList.pBufferList[0].pBuffers->pData = (u_char*)data_to_search;
  
  g_nAppMatches = 0, g_nAppCallbacks = 0;
  if(debug) printf("Input data: '%s'\n", data_to_search);
  cpaPmSearchExec(handle->instanceHandle, &handle->matchCtxList, &handle->pMatchCtxError);

  if(debug) {
    printf("App matches   = %u\n", g_nAppMatches);
    printf("App callbacks = %u\n", g_nAppCallbacks);
  }

  return(g_nAppMatches);
}

/* *********************************************************** */

void freeHandle(QAThandle *handle) {
  if(handle->pdbHandle) cpaPmPdbRelease(handle->instanceHandle, handle->pdbHandle);
  cpaPmStopInstance(handle->instanceHandle);
}

