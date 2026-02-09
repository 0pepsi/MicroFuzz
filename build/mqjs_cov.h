/*
 * mQuickJS Semantic Coverage Instrumentation
 *
 * This header provides coverage macros to be injected into the engine source.
 * Coverage IDs are stable across builds (derived from compile-time constants).
 *
 * Usage: Add -DMQJS_COVERAGE to CFLAGS and #include "mqjs_cov.h" in mquickjs.c
 */
#ifndef MQJS_COV_H
#define MQJS_COV_H

#include <stdint.h>
#include <string.h>

#define COV_MAP_SIZE  (1 << 16)  /* 64KB */
#define COV_MAP_MASK  (COV_MAP_SIZE - 1)

#ifdef MQJS_COVERAGE

/* The shared coverage map — mmap'd by the fuzzer */
extern uint8_t __mqjs_cov_map[COV_MAP_SIZE];

/* Previous location for edge-style coverage */
extern uint32_t __mqjs_prev_loc;

/* Edge-style coverage: XOR current with previous location */
#define COV_EDGE(cur_id) do { \
    uint32_t _id = (cur_id); \
    __mqjs_cov_map[(_id ^ __mqjs_prev_loc) & COV_MAP_MASK]++; \
    __mqjs_prev_loc = _id >> 1; \
} while(0)

/* Direct hit coverage (no edge XOR) for infrequent events */
#define COV_HIT(id) __mqjs_cov_map[(id) & COV_MAP_MASK]++

/*
 * Coverage injection macros with stable IDs
 *
 * ID space allocation:
 *   0x0000-0x00FF: Opcode execution (256 opcodes max)
 *   0x0100-0x01FF: Opcode pairs (prev_op ^ cur_op)
 *   0x1000-0x10FF: Type coercion paths
 *   0x2000-0x20FF: Object class dispatch
 *   0x3000-0x30FF: Parser grammar productions
 *   0x4000-0x40FF: GC phases
 *   0x5000-0x50FF: Exception paths
 *   0x6000-0x60FF: Regex VM opcodes
 *   0x7000-0x7FFF: Call type dispatch
 */

/* A. Opcode execution — called in interpreter dispatch */
#define OPCODE_COV(opcode) COV_EDGE(0x0000 + (opcode))

/* B. Type-specialized path — (site_id, value_tag) */
#define TYPE_COV(site_id, tag) COV_HIT(0x1000 + ((site_id) << 4) + ((tag) & 0xF))

/* C. Object class dispatch — (site_id, class_id) */
#define CLASS_COV(site_id, class_id) COV_HIT(0x2000 + ((site_id) << 5) + ((class_id) & 0x1F))

/* D. Parser grammar production — called in js_parse_call */
#define PARSE_COV(func_idx) COV_HIT(0x3000 + (func_idx))

/* E. GC phase — called at GC transitions */
#define GC_COV(phase) COV_HIT(0x4000 + (phase))

/* F. Exception path — called at exception handling */
#define EXC_COV(site_id) COV_HIT(0x5000 + (site_id))

/* G. Regex VM opcode */
#define REOP_COV(opcode) COV_HIT(0x6000 + (opcode))

/* H. Call dispatch type */
#define CALL_COV(type_id) COV_HIT(0x7000 + (type_id))

/* GC phase IDs */
#define GC_PHASE_START         0
#define GC_PHASE_MARK_STACK    1
#define GC_PHASE_MARK_CTX      2
#define GC_PHASE_MARK_PARSE    3
#define GC_PHASE_COMPACT       4
#define GC_PHASE_DONE          5

/* Call type IDs */
#define CALL_TYPE_C_GENERIC      0
#define CALL_TYPE_C_MAGIC        1
#define CALL_TYPE_C_PARAMS       2
#define CALL_TYPE_C_F_F          3
#define CALL_TYPE_CLOSURE        4
#define CALL_TYPE_SHORT_FUNC     5
#define CALL_TYPE_NOT_FUNCTION   6
#define CALL_TYPE_CONSTRUCTOR    7
#define CALL_TYPE_TAIL_CALL      8

/* Exception site IDs */
#define EXC_INTERP_CATCH         0
#define EXC_INTERP_UNWIND        1
#define EXC_PARSE_SYNTAX         2
#define EXC_PARSE_OOM            3
#define EXC_RUNTIME_TYPE         4
#define EXC_RUNTIME_REF          5
#define EXC_RUNTIME_RANGE        6
#define EXC_OOM                  7
#define EXC_STACK_OVERFLOW       8
#define EXC_UNCATCHABLE          9

#else /* !MQJS_COVERAGE */

#define OPCODE_COV(opcode)         ((void)0)
#define TYPE_COV(site_id, tag)     ((void)0)
#define CLASS_COV(site_id, class_id) ((void)0)
#define PARSE_COV(func_idx)        ((void)0)
#define GC_COV(phase)              ((void)0)
#define EXC_COV(site_id)           ((void)0)
#define REOP_COV(opcode)           ((void)0)
#define CALL_COV(type_id)          ((void)0)

#endif /* MQJS_COVERAGE */

#endif /* MQJS_COV_H */
