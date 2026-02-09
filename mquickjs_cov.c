/*
 * mquickjs_cov.c — Coverage map globals for mqjs_fuzz
 *
 * This file provides the coverage map and previous location variable
 * used by the instrumented engine and the fuzzer.
 */
#include "mqjs_cov.h"

#ifdef MQJS_COVERAGE
uint8_t __mqjs_cov_map[COV_MAP_SIZE];
uint32_t __mqjs_prev_loc;
#endif
