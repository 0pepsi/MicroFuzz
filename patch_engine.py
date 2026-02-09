#!/usr/bin/env python3
"""
patch_engine.py — Instrument mquickjs.c with semantic coverage macros.

Usage:
    python3 patch_engine.py /path/to/mquickjs.c > mquickjs_instrumented.c
"""

import sys
import re

def patch_source(source):
    lines = source.split('\n')
    output = []
    in_js_call = False
    added_include = False

    for i, line in enumerate(lines):
        lineno = i + 1  # 1-based
        if not added_include and line.startswith('#include "mquickjs_priv.h"'):
            output.append(line)
            output.append('#ifdef MQJS_COVERAGE')
            output.append('#include "mqjs_cov.h"')
            output.append('#endif')
            added_include = True
            continue

        # A. OPCODE COVERAGE
        # two sites -> main interpreter (line ~5117, next line has DUMP_EXEC)
        #            regex VM (line ~17082, next line has DUMP_REEXEC)
        if 'opcode = *pc++;' in line and i + 1 < len(lines):
            next_line = lines[i + 1]
            if '#ifdef DUMP_EXEC' in next_line and 'DUMP_REEXEC' not in next_line:
                # main interpreter dispatch use OPCODE_COV
                output.append(line)
                output.append('#ifdef MQJS_COVERAGE')
                output.append('        OPCODE_COV(opcode);')
                output.append('#endif')
                continue
            elif 'DUMP_REEXEC' in next_line:
                # regex VM dispatch use REOP_COV
                output.append(line)
                output.append('#ifdef MQJS_COVERAGE')
                output.append('        REOP_COV(opcode);')
                output.append('#endif')
                continue

        # B. TYPE COVERAGE in JS_ToNumber
        # After "case JS_MTAG_STRING:" in JS_ToNumber
        if 'case JS_MTAG_STRING:' in line:
            output.append(line)
            # check if this is inside JS_ToNumber context (look for "atod" nearby)
            context = '\n'.join(lines[max(0,i-5):i+5])
            if 'atod' in context or 'pres' in context:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('            TYPE_COV(0x00, JS_MTAG_STRING);')
                output.append('#endif')
            continue

        if 'case JS_MTAG_FLOAT64:' in line:
            output.append(line)
            context = '\n'.join(lines[max(0,i-5):i+5])
            if 'pres' in context or 'dval' in context:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('            TYPE_COV(0x00, JS_MTAG_FLOAT64);')
                output.append('#endif')
            continue

        if 'case JS_MTAG_OBJECT:' in line:
            output.append(line)
            context = '\n'.join(lines[max(0,i-5):i+5])
            if 'ToPrimitive' in context:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('            TYPE_COV(0x00, JS_MTAG_OBJECT);')
                output.append('#endif')
            continue

        # C. CALL TYPE DISPATCH
        # instrument the interpreter call dispatch (inside JS_Call).
        # the C_FUNCTION site at ~5377 is preceded by "goto not_a_function;"
        # the CLOSURE site at ~5473 is preceded by "goto return_call;"
        if "p->class_id == JS_CLASS_C_FUNCTION" in line:
            # context: must be preceded by "goto not_a_function;" within 3 lines
            context_before = '\n'.join(lines[max(0, i-3):i])
            if 'goto not_a_function;' in context_before:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('                    CALL_COV(CALL_TYPE_C_GENERIC);')
                output.append('#endif')
            output.append(line)
            continue

        if "p->class_id == JS_CLASS_CLOSURE" in line:
            # context: must be preceded by "goto return_call;" within 5 lines
            context_before = '\n'.join(lines[max(0, i-5):i])
            if 'goto return_call;' in context_before:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('                    CALL_COV(CALL_TYPE_CLOSURE);')
                output.append('#endif')
            output.append(line)
            continue

        # D. PARSER COVERAGE
        # js_parse_call -> instrument at the dispatch point
        # actual dispatch -> "ret = parse_func_table[func_idx]"
        if 'ret = parse_func_table[func_idx]' in line:
            output.append('#ifdef MQJS_COVERAGE')
            output.append('        PARSE_COV(func_idx);')
            output.append('#endif')
            output.append(line)
            continue

        # E. GC COVERAGE
        # JS_GC2
        if 'gc_mark_all(ctx, keep_atoms);' in line and 'JS_GC2' in '\n'.join(lines[max(0,i-30):i]):
            output.append('#ifdef MQJS_COVERAGE')
            output.append('    GC_COV(GC_PHASE_START);')
            output.append('#endif')
            output.append(line)
            continue

        if 'gc_compact_heap(ctx);' in line:
            output.append('#ifdef MQJS_COVERAGE')
            output.append('    GC_COV(GC_PHASE_COMPACT);')
            output.append('#endif')
            output.append(line)
            continue

        # F. EXCEPTION COVERAGE
        # "exception:" label in interpreter
        if line.strip() == 'exception:' or line.strip() == 'goto exception;':
            output.append(line)
            if 'exception:' in line:
                output.append('#ifdef MQJS_COVERAGE')
                output.append('            EXC_COV(EXC_INTERP_CATCH);')
                output.append('#endif')
            continue

        # G. NOT A FUNCTION
        if 'not_a_function:' in line:
            output.append(line)
            output.append('#ifdef MQJS_COVERAGE')
            output.append('                    CALL_COV(CALL_TYPE_NOT_FUNCTION);')
            output.append('#endif')
            continue

        #  default pass through
        output.append(line)

    return '\n'.join(output)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mquickjs.c>", file=sys.stderr)
        print("Outputs instrumented source to stdout.", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        source = f.read()

    patched = patch_source(source)
    print(patched)


if __name__ == '__main__':
    main()
