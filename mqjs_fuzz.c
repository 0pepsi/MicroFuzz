/*
 * mqjs_fuzz.c — Custom coverage-guided fuzzer for mQuickJS
 *
 * Build:
 *   1. Patch mquickjs.c with coverage instrumentation (see patch_engine.py)
 *   2. gcc -O2 -DMQJS_COVERAGE -o mqjs_fuzz mqjs_fuzz.c mquickjs_cov.c \
 *          mquickjs.c dtoa.c libm.c cutils.c -lm
 *
 * Or use the provided build script.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include "mqjs_cov.h"

/* We include the header rather than linking against it to keep this self-contained */
#include "../../mquickjs.h"
#include "../../mquickjs_priv.h"
#ifdef USE_ASAN
/* ASAN death callback -> called just before ASAN aborts on a detected error */
void __asan_on_error(void);
/* Recover from ASAN errors instead of aborting */
const char *__asan_default_options(void) {
    return "detect_leaks=0:abort_on_error=0:halt_on_error=0"
           ":allocator_may_return_null=1:symbolize=1"
           ":print_stacktrace=1";
}
#endif

#ifdef USE_UBSAN
const char *__ubsan_default_options(void) {
    return "halt_on_error=0:print_stacktrace=1:silence_unsigned_overflow=1";
}
#endif
uint8_t __mqjs_cov_map[COV_MAP_SIZE];
uint32_t __mqjs_prev_loc;

/* Configuration */
#define MEM_SIZE       (512 * 1024)   /* 512KB engine memory */
#define MAX_INPUT_SIZE (16 * 1024)    /* 16KB max input */
#define MAX_CORPUS     4096
#define CRASH_DIR      "crashes"
#define CORPUS_DIR     "corpus"
#define TIMEOUT_OPS    500000         /* max opcode count before interrupt */

static const uint8_t count_class_lookup[256] = {
    [0]           = 0,
    [1]           = 1,
    [2]           = 2,
    [3]           = 4,
    [4 ... 7]     = 8,
    [8 ... 15]    = 16,
    [16 ... 31]   = 32,
    [32 ... 127]  = 64,
    [128 ... 255] = 128,
};

/* Corpus entry */
typedef struct {
    uint8_t *data;
    uint32_t len;
    uint64_t cov_hash;
    uint32_t exec_us;    /* execution time in microseconds */
} CorpusEntry;

/* Fuzzer state */
static struct {
    CorpusEntry corpus[MAX_CORPUS];
    int corpus_count;

    uint8_t virgin_bits[COV_MAP_SIZE];  /* tracks coverage never seen */
    uint64_t cov_hashes[MAX_CORPUS];
    int cov_hash_count;

    uint64_t total_execs;
    uint64_t total_crashes;
    uint64_t unique_crashes;
    uint64_t last_new_cov_exec;
    int max_coverage_bits;

    uint8_t *mem_buf;       /* engine memory buffer */
    uint8_t *cur_input;
    uint32_t cur_input_len;

    int timeout_triggered;
    volatile int in_target;

    struct timeval start_time;
    struct timeval last_ui_time;

    /* for longjmp on crash */
    sigjmp_buf crash_jmp;
    int crash_signal;
} fuzz;

/* Utility: FNV-1a hash */
static uint64_t fnv1a_hash(const uint8_t *data, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* bucket the coverage map */
static void classify_counts(uint8_t *map)
{
    for (int i = 0; i < COV_MAP_SIZE; i++) {
        map[i] = count_class_lookup[map[i]];
    }
}

static int has_new_coverage(void)
{
    int new_bits = 0;
    for (int i = 0; i < COV_MAP_SIZE; i++) {
        uint8_t cur = __mqjs_cov_map[i];
        if (cur && (fuzz.virgin_bits[i] & cur)) {
            fuzz.virgin_bits[i] &= ~cur;
            new_bits = 1;
        }
    }
    return new_bits;
}

static int count_coverage_bits(void)
{
    int count = 0;
    for (int i = 0; i < COV_MAP_SIZE; i++) {
        if (fuzz.virgin_bits[i] != 0xFF)
            count++;
    }
    return count;
}

static void crash_handler(int sig)
{
    if (fuzz.in_target) {
        fuzz.crash_signal = sig;
        siglongjmp(fuzz.crash_jmp, 1);
    }
    /* If not in target, re-raise */
    signal(sig, SIG_DFL);
    raise(sig);
}

static int interrupt_handler(JSContext *ctx, void *opaque)
{
    (void)opaque;
    fuzz.timeout_triggered = 1;
    return 1; /* interrupt execution */
}

static void null_write_func(void *opaque, const void *buf, size_t buf_len)
{
    (void)opaque;
    (void)buf;
    (void)buf_len;
}

static void save_crash(const uint8_t *data, uint32_t len, int sig)
{
    char path[256];
    uint64_t hash = fnv1a_hash(data, len);
    snprintf(path, sizeof(path), "%s/crash_%016llx_sig%d",
             CRASH_DIR, (unsigned long long)hash, sig);

    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        fuzz.unique_crashes++;
    }
}

static void save_corpus(const uint8_t *data, uint32_t len, int idx)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/id_%06d", CORPUS_DIR, idx);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

static int execute_input_direct(const uint8_t *input, uint32_t input_len, int save_on_crash)
{
    JSContext *ctx;
    JSValue val;
    int crashed = 0;
    memset(__mqjs_cov_map, 0, COV_MAP_SIZE);
    __mqjs_prev_loc = 0;

    memset(fuzz.mem_buf, 0, MEM_SIZE);

    uint8_t *input_copy = malloc(input_len + 1);
    if (!input_copy) return -1;
    memcpy(input_copy, input, input_len);
    input_copy[input_len] = '\0';

    fuzz.timeout_triggered = 0;
    fuzz.in_target = 1;

    if (sigsetjmp(fuzz.crash_jmp, 1) == 0) {
        ctx = JS_NewContext(fuzz.mem_buf, MEM_SIZE, NULL);
        if (!ctx) {
            fuzz.in_target = 0;
            free(input_copy);
            return -1;
        }
        JS_SetInterruptHandler(ctx, interrupt_handler);
        JS_SetLogFunc(ctx, null_write_func);
        JS_SetRandomSeed(ctx, 0); /* deterministic */

        val = JS_Eval(ctx, (const char *)input_copy, input_len,
                       "<fuzz>", JS_EVAL_RETVAL);

        JS_FreeContext(ctx);
    } else {
        crashed = 1;
        fuzz.total_crashes++;
        if (save_on_crash) {
            save_crash(input, input_len, fuzz.crash_signal);
        }
    }

    fuzz.in_target = 0;
    free(input_copy);
    classify_counts(__mqjs_cov_map);

    return crashed;
}

#if defined(USE_ASAN) || defined(USE_UBSAN)
#include <sys/wait.h>
#include <sys/mman.h>

/*
 * With ASAN/UBSAN, we use fork-based isolation.
 *
 * ASAN intercepts signals and corrupts its shadow memory state
 * on memory errors. siglongjmp after an ASAN-detected error leads to
 * undefined behavior. we fork a child for each execution.
 * The child inherits the coverage map (mmap'd MAP_SHARED) and the parent
 * detects crashes via waitpid().
 *
 * This is slower than in-process but necessary for correctnesssssssss with sanitizers.
 */

static uint8_t *shared_cov_map = NULL;

static void init_shared_cov(void)
{
    shared_cov_map = mmap(NULL, COV_MAP_SIZE, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared_cov_map == MAP_FAILED) {
        perror("mmap shared cov");
        exit(1);
    }
}

static int execute_input_fork(const uint8_t *input, uint32_t input_len, int save_on_crash)
{
    int crashed = 0;

    memset(shared_cov_map, 0, COV_MAP_SIZE);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        JSContext *ctx;
        JSValue val;

        memcpy(__mqjs_cov_map, shared_cov_map, 0); /* noop, just ensure symbol is used */

        memset(__mqjs_cov_map, 0, COV_MAP_SIZE);
        __mqjs_prev_loc = 0;

        uint8_t *mem = malloc(MEM_SIZE);
        if (!mem) _exit(2);
        memset(mem, 0, MEM_SIZE);

        uint8_t *input_copy = malloc(input_len + 1);
        if (!input_copy) _exit(2);
        memcpy(input_copy, input, input_len);
        input_copy[input_len] = '\0';

        ctx = JS_NewContext(mem, MEM_SIZE, NULL);
        if (!ctx) _exit(2);

        JS_SetInterruptHandler(ctx, interrupt_handler);
        JS_SetLogFunc(ctx, null_write_func);
        JS_SetRandomSeed(ctx, 0);

        val = JS_Eval(ctx, (const char *)input_copy, input_len,
                       "<fuzz>", JS_EVAL_RETVAL);

        JS_FreeContext(ctx);
        free(input_copy);
        free(mem);

        memcpy(shared_cov_map, __mqjs_cov_map, COV_MAP_SIZE);

        _exit(0);
    }

    /* ---- Parent process ---- */
    int status;
    waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        crashed = 1;
        fuzz.total_crashes++;
        if (save_on_crash) {
            save_crash(input, input_len, sig);
        }
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 2) {
        crashed = 1;
        fuzz.total_crashes++;
        if (save_on_crash) {
            save_crash(input, input_len, 0);
        }
    }

    memcpy(__mqjs_cov_map, shared_cov_map, COV_MAP_SIZE);

    classify_counts(__mqjs_cov_map);

    return crashed;
}
#endif /* USE_ASAN || USE_UBSAN */

static int execute_input(const uint8_t *input, uint32_t input_len, int save_on_crash)
{
#if defined(USE_ASAN) || defined(USE_UBSAN)
    return execute_input_fork(input, input_len, save_on_crash);
#else
    return execute_input_direct(input, input_len, save_on_crash);
#endif
}

static uint64_t rng_state = 0xdeadbeefcafe1337ULL;

static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static uint32_t rng_range(uint32_t max)
{
    if (max == 0) return 0;
    return rng_next() % max;
}

/* ---- Seed templates ---- */
static const char *seed_templates[] = {
    "1 + 2",
    "1.5 * 2.5",
    "10 / 3",
    "7 % 3",
    "2 ** 10",
    "-1",
    "~0",
    "1 << 3",
    "8 >> 1",
    "8 >>> 1",

    "1 < 2",
    "1 <= 1",
    "2 > 1",
    "1 == 1",
    "1 === 1",
    "1 != 2",
    "1 !== '1'",

    "'hello' + ' world'",
    "'abc'.length",
    "'hello'.slice(1, 3)",
    "'hello'.indexOf('l')",
    "'HELLO'.toLowerCase()",
    "'hello'.toUpperCase()",
    "'a,b,c'.split(',')",
    "'hello'.charAt(0)",
    "'abc'.charCodeAt(0)",
    "String.fromCharCode(65)",
    "'hello'.substring(1,3)",
    "'  hello  '.trim()",
    "'abc'.repeat(3)",
    "'hello world'.replace('world', 'js')",
    "'hello world'.search('world')",

    "var x = 1; x",
    "var x = 1; x = 2; x",
    "var x = 1, y = 2; x + y",

    "var o = {}; o",
    "var o = {a: 1, b: 2}; o.a",
    "var o = {a: 1}; o.b = 2; o.b",
    "var o = {a: 1}; delete o.a; o.a",
    "'a' in {a: 1}",
    "var o = {a: 1}; o.hasOwnProperty('a')",
    "Object.keys({a:1, b:2})",
    "Object.create({x: 1}).x",

    "var a = [1, 2, 3]; a[0]",
    "var a = []; a.push(1); a.push(2); a",
    "var a = [1,2,3]; a.pop()",
    "var a = [1,2,3]; a.shift()",
    "var a = [1,2,3]; a.unshift(0); a",
    "[1,2,3].join('-')",
    "[3,1,2].sort()",
    "[1,2,3].reverse()",
    "[1,2].concat([3,4])",
    "[1,2,3].slice(1)",
    "[1,2,3,4].splice(1, 2)",
    "[1,2,3].indexOf(2)",
    "[1,2,3].every(function(x){return x>0})",
    "[1,2,3].some(function(x){return x>2})",
    "[1,2,3].forEach(function(x){})",
    "[1,2,3].map(function(x){return x*2})",
    "[1,2,3].filter(function(x){return x>1})",
    "[1,2,3].reduce(function(a,b){return a+b}, 0)",
    "Array.isArray([1])",

    "if (true) 1; else 2",
    "var x = 0; for (var i = 0; i < 5; i++) x += i; x",
    "var x = 0; var i = 0; while (i < 5) { x += i; i++ } x",
    "var x = 0; do { x++ } while (x < 3); x",
    "switch(1) { case 0: 'a'; break; case 1: 'b'; break; default: 'c' }",
    "var x = 0; for (var k in {a:1,b:2}) x++; x",

    "function f(x) { return x + 1 } f(1)",
    "var f = function(x) { return x * 2 }; f(3)",
    "(function(a, b) { return a + b })(1, 2)",
    "function f() { return arguments.length } f(1,2,3)",
    "function f(a,b,c) {} f.length",

    "function f() { var x = 10; return function() { return x } } f()()",
    "var a=[]; for(var i=0;i<3;i++) { (function(j){ a.push(function(){return j}) })(i) } a[0]()",
    "function f(x) { return function(y) { return x + y } } f(1)(2)",

    "function F(x) { this.x = x } var o = new F(1); o.x",
    "function F() {} F.prototype.m = function(){return 1}; new F().m()",

    "try { throw 42 } catch(e) { e }",
    "try { undefined.x } catch(e) { typeof e }",
    "try { null() } catch(e) { typeof e }",
    "try { try { throw 1 } finally { 2 } } catch(e) { e }",

    "1 + '2'",
    "'3' * 2",
    "null + 1",
    "undefined + 1",
    "true + true",
    "+''",
    "+' '",
    "+null",
    "+'0x10'",
    "Number('123')",
    "String(123)",
    "Boolean(0)",
    "Boolean('')",
    "Boolean(null)",

    "(123).toString()",
    "(1.5).toFixed(2)",
    "(123456).toExponential(2)",
    "(1.2345).toPrecision(3)",
    "parseInt('0xff', 16)",
    "parseFloat('3.14')",
    "isNaN(NaN)",
    "isFinite(1/0)",

    "Math.abs(-5)",
    "Math.floor(1.9)",
    "Math.ceil(1.1)",
    "Math.round(1.5)",
    "Math.max(1,2,3)",
    "Math.min(1,2,3)",
    "Math.pow(2, 10)",
    "Math.sqrt(4)",
    "Math.random()",

    "/abc/.test('xabcy')",
    "'hello'.match(/l+/)",
    "'aaa'.replace(/a/g, 'b')",
    "/^(a|b)+$/.test('aab')",
    "/(\\d+)/.exec('abc123')[1]",
    "'a1b2c3'.split(/\\d/)",

    "var b = new ArrayBuffer(8); new Uint8Array(b)[0] = 42",
    "var b = new ArrayBuffer(16); var f = new Float64Array(b); f[0] = 1.5; f[0]",
    "var u = new Uint8Array(4); u.set([1,2,3,4]); u[2]",
    "new Int32Array(4).length",

    "JSON.parse('{\"a\":1,\"b\":[2,3]}')",
    "JSON.stringify({a:1,b:'hello',c:null})",
    "JSON.parse('\"hello\"')",
    "JSON.parse('[1,2,3]')",

    "var a = {}; var b = Object.create(a); a.x = 1; b.x",
    "Object.getPrototypeOf({}) === Object.prototype",
    "var o={}; Object.defineProperty(o,'x',{value:1,writable:false}); o.x",

    "var s=0; var a=[10,20,30]; for(var v of a) s+=v; s",

    "eval('1+2')",

    "typeof new Date()",
    "new Date(0).toString()",

    "try{eval('{')}catch(e){e instanceof SyntaxError}",
    "try{undeclared}catch(e){e instanceof ReferenceError}",
    "try{null.x}catch(e){e instanceof TypeError}",

    "function f(x){return this.a+x} f.call({a:1},2)",
    "function f(x){return this.a+x} f.apply({a:1},[2])",
    "function f(x,y){return x+y} var g=f.bind(null,1); g(2)",

    "typeof undefined",
    "typeof null",
    "typeof 1",
    "typeof 'a'",
    "typeof true",
    "typeof function(){}",
    "typeof {}",
    "void 0",
    "0/0",
    "1/0",
    "-1/0",
    "0 === -0",
};

#define N_SEEDS (sizeof(seed_templates) / sizeof(seed_templates[0]))

static void mutate_bitflip(uint8_t *buf, uint32_t len)
{
    if (len == 0) return;
    uint32_t pos = rng_range(len);
    buf[pos] ^= (1 << rng_range(8));
}

static void mutate_byte(uint8_t *buf, uint32_t len)
{
    if (len == 0) return;
    uint32_t pos = rng_range(len);
    buf[pos] = rng_range(256);
}

static uint32_t mutate_insert(uint8_t *buf, uint32_t len, uint32_t max_len)
{
    if (len >= max_len - 4) return len;
    uint32_t pos = rng_range(len + 1);
    uint32_t insert_len = 1 + rng_range(4);
    if (len + insert_len > max_len) insert_len = max_len - len;
    memmove(buf + pos + insert_len, buf + pos, len - pos);
    for (uint32_t i = 0; i < insert_len; i++) {
        buf[pos + i] = rng_range(256);
    }
    return len + insert_len;
}

static uint32_t mutate_delete(uint8_t *buf, uint32_t len)
{
    if (len <= 1) return len;
    uint32_t pos = rng_range(len);
    uint32_t del_len = 1 + rng_range(4);
    if (pos + del_len > len) del_len = len - pos;
    memmove(buf + pos, buf + pos + del_len, len - pos - del_len);
    return len - del_len;
}

static uint32_t mutate_splice(uint8_t *buf, uint32_t len, uint32_t max_len)
{
    if (fuzz.corpus_count < 2) return len;
    int other_idx = rng_range(fuzz.corpus_count);
    CorpusEntry *other = &fuzz.corpus[other_idx];
    if (other->len == 0) return len;

    uint32_t split_a = rng_range(len);
    uint32_t split_b = rng_range(other->len);
    uint32_t tail_len = other->len - split_b;
    if (split_a + tail_len > max_len) tail_len = max_len - split_a;

    memcpy(buf + split_a, other->data + split_b, tail_len);
    return split_a + tail_len;
}

static const char *js_tokens[] = {
    "var ", "function ", "return ", "if(", "else{", "for(", "while(",
    "try{", "}catch(e){", "}finally{", "new ", "delete ", "typeof ",
    "void ", "throw ", "switch(", "case ", "break;", "continue;",
    "this", "null", "undefined", "true", "false", "NaN", "Infinity",
    "[]", "{}", "()", "arguments", ".length", ".toString()", ".valueOf()",
    ".prototype", ".constructor", ".push(", ".pop()", ".slice(",
    "Object.create(", "Object.keys(", "Object.defineProperty(",
    "Array.isArray(", "JSON.parse(", "JSON.stringify(",
    "parseInt(", "parseFloat(", "isNaN(", "eval(",
    "new ArrayBuffer(", "new Uint8Array(", "new Float64Array(",
    "Math.floor(", "Math.random()",
    ";", ",", ".", "=", "==", "===", "!=", "!==", "<", ">", "<=", ">=",
    "+", "-", "*", "/", "%", "**", "&", "|", "^", "~", "<<", ">>", ">>>",
    "&&", "||", "!", "++", "--",
    " instanceof ", " in ",
    "0", "1", "-1", "0.5", "1e10", "0xff", "''", "'a'", "'abc'",
};
#define N_JS_TOKENS (sizeof(js_tokens) / sizeof(js_tokens[0]))

static uint32_t mutate_insert_token(uint8_t *buf, uint32_t len, uint32_t max_len)
{
    const char *tok = js_tokens[rng_range(N_JS_TOKENS)];
    uint32_t tok_len = strlen(tok);
    if (len + tok_len >= max_len) return len;

    uint32_t pos = rng_range(len + 1);
    for (int tries = 0; tries < 10; tries++) {
        uint32_t p = rng_range(len);
        if (buf[p] == ';' || buf[p] == ' ' || buf[p] == '{' || buf[p] == '}') {
            pos = p + 1;
            break;
        }
    }
    if (pos > len) pos = len;

    memmove(buf + pos + tok_len, buf + pos, len - pos);
    memcpy(buf + pos, tok, tok_len);
    return len + tok_len;
}

static uint32_t mutate_replace_number(uint8_t *buf, uint32_t len, uint32_t max_len)
{
    for (int tries = 0; tries < 20; tries++) {
        uint32_t pos = rng_range(len);
        if (pos < len && buf[pos] >= '0' && buf[pos] <= '9') {
            uint32_t start = pos;
            while (start > 0 && ((buf[start-1] >= '0' && buf[start-1] <= '9') || buf[start-1] == '.'))
                start--;
            uint32_t end = pos + 1;
            while (end < len && ((buf[end] >= '0' && buf[end] <= '9') || buf[end] == '.'))
                end++;

            char repl[32];
            int repl_len;
            switch (rng_range(6)) {
            case 0: repl_len = snprintf(repl, sizeof(repl), "%d", (int)(rng_next() % 1000)); break;
            case 1: repl_len = snprintf(repl, sizeof(repl), "0"); break;
            case 2: repl_len = snprintf(repl, sizeof(repl), "-1"); break;
            case 3: repl_len = snprintf(repl, sizeof(repl), "0.5"); break;
            case 4: repl_len = snprintf(repl, sizeof(repl), "1e%d", (int)(rng_next() % 20)); break;
            default: repl_len = snprintf(repl, sizeof(repl), "0x%x", (unsigned)(rng_next() % 256)); break;
            }

            uint32_t old_len = end - start;
            if (len - old_len + repl_len >= max_len) return len;
            memmove(buf + start + repl_len, buf + end, len - end);
            memcpy(buf + start, repl, repl_len);
            return len - old_len + repl_len;
        }
    }
    return len;
}

static uint32_t mutate(uint8_t *buf, uint32_t len, uint32_t max_len)
{
    int n_mutations = 1 + rng_range(4); /* 1-4 stacked mutations */

    for (int i = 0; i < n_mutations; i++) {
        switch (rng_range(8)) {
        case 0:
            mutate_bitflip(buf, len);
            break;
        case 1:
            mutate_byte(buf, len);
            break;
        case 2:
            len = mutate_insert(buf, len, max_len);
            break;
        case 3:
            len = mutate_delete(buf, len);
            break;
        case 4:
            len = mutate_splice(buf, len, max_len);
            break;
        case 5:
            len = mutate_insert_token(buf, len, max_len);
            break;
        case 6:
            len = mutate_replace_number(buf, len, max_len);
            break;
        case 7:
            /* Cross with seed template */
            if (rng_range(4) == 0) {
                const char *seed = seed_templates[rng_range(N_SEEDS)];
                uint32_t slen = strlen(seed);
                if (slen < max_len) {
                    memcpy(buf, seed, slen);
                    len = slen;
                }
            } else {
                mutate_byte(buf, len);
            }
            break;
        }
    }

    if (len == 0) {
        buf[0] = '0';
        len = 1;
    }
    return len;
}

static int add_to_corpus(const uint8_t *data, uint32_t len)
{
    if (fuzz.corpus_count >= MAX_CORPUS)
        return 0;

    uint64_t cov_hash = fnv1a_hash(__mqjs_cov_map, COV_MAP_SIZE);

    for (int i = 0; i < fuzz.cov_hash_count; i++) {
        if (fuzz.cov_hashes[i] == cov_hash)
            return 0;
    }

    int idx = fuzz.corpus_count;
    fuzz.corpus[idx].data = malloc(len);
    if (!fuzz.corpus[idx].data) return 0;
    memcpy(fuzz.corpus[idx].data, data, len);
    fuzz.corpus[idx].len = len;
    fuzz.corpus[idx].cov_hash = cov_hash;
    fuzz.corpus_count++;

    if (fuzz.cov_hash_count < MAX_CORPUS)
        fuzz.cov_hashes[fuzz.cov_hash_count++] = cov_hash;

    save_corpus(data, len, idx);
    return 1;
}

static double elapsed_seconds(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec - fuzz.start_time.tv_sec) +
           (now.tv_usec - fuzz.start_time.tv_usec) / 1e6;
}

static void print_status(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    double dt = (now.tv_sec - fuzz.last_ui_time.tv_sec) +
                (now.tv_usec - fuzz.last_ui_time.tv_usec) / 1e6;
    if (dt < 0.5 && fuzz.total_execs > 1)
        return;
    fuzz.last_ui_time = now;

    double elapsed = elapsed_seconds();
    double exec_per_sec = (elapsed > 0) ? fuzz.total_execs / elapsed : 0;
    int cov_bits = count_coverage_bits();

    printf("\033[2J\033[H"); /* clear screen */
    printf("\033[1;37m");
    printf("┌─────────────────────────────────────────────────────┐\n");
    printf("│          \033[1;36mmqjs-fuzz\033[1;37m — mQuickJS Custom Fuzzer          │\n");
    printf("├─────────────────────────┬───────────────────────────┤\n");
    printf("│  run time : \033[1;33m%8.1fs\033[1;37m   │  exec/sec : \033[1;33m%13.1f\033[1;37m │\n",
           elapsed, exec_per_sec);
    printf("│  execs    : \033[1;33m%8llu\033[1;37m    │  corpus   : \033[1;33m%13d\033[1;37m │\n",
           (unsigned long long)fuzz.total_execs, fuzz.corpus_count);
    printf("├─────────────────────────┼───────────────────────────┤\n");
    printf("│  cov bits : \033[1;32m%8d\033[1;37m    │  new cov@ : \033[1;32m%13llu\033[1;37m │\n",
           cov_bits, (unsigned long long)fuzz.last_new_cov_exec);
    printf("│  crashes  : \033[1;31m%8llu\033[1;37m    │  unique   : \033[1;31m%13llu\033[1;37m │\n",
           (unsigned long long)fuzz.total_crashes,
           (unsigned long long)fuzz.unique_crashes);
    printf("└─────────────────────────┴───────────────────────────┘\n");
    printf("\033[0m");
    fflush(stdout);
}

static void init_seeds(void)
{
    printf("[*] Generating initial seeds...\n");
    int added = 0;

    for (int i = 0; i < (int)N_SEEDS; i++) {
        const uint8_t *seed = (const uint8_t *)seed_templates[i];
        uint32_t len = strlen(seed_templates[i]);

        execute_input(seed, len, 0);

        if (has_new_coverage()) {
            add_to_corpus(seed, len);
            added++;
        }
    }
    printf("[+] Added %d/%d seeds to corpus (coverage-unique)\n", added, (int)N_SEEDS);

    if (fuzz.corpus_count < 10) {
        for (int i = 0; i < (int)N_SEEDS && fuzz.corpus_count < 50; i++) {
            const uint8_t *seed = (const uint8_t *)seed_templates[i];
            uint32_t len = strlen(seed_templates[i]);
            int already = 0;
            for (int j = 0; j < fuzz.corpus_count; j++) {
                if (fuzz.corpus[j].len == len && memcmp(fuzz.corpus[j].data, seed, len) == 0) {
                    already = 1;
                    break;
                }
            }
            if (!already) {
                fuzz.corpus[fuzz.corpus_count].data = malloc(len);
                memcpy(fuzz.corpus[fuzz.corpus_count].data, seed, len);
                fuzz.corpus[fuzz.corpus_count].len = len;
                fuzz.corpus_count++;
            }
        }
    }
}

static void load_corpus_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    int loaded = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        FILE *f = fopen(path, "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long flen = ftell(f);
        if (flen <= 0 || flen > MAX_INPUT_SIZE) { fclose(f); continue; }
        fseek(f, 0, SEEK_SET);

        uint8_t *buf = malloc(flen);
        fread(buf, 1, flen, f);
        fclose(f);

        execute_input(buf, flen, 0);
        if (has_new_coverage()) {
            add_to_corpus(buf, flen);
            loaded++;
        }
        free(buf);
    }
    closedir(d);

    if (loaded > 0)
        printf("[+] Loaded %d inputs from %s\n", loaded, dir);
}

int main(int argc, char **argv)
{
    const char *corpus_in = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            corpus_in = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-i corpus_dir]\n", argv[0]);
            return 0;
        }
    }

    memset(&fuzz, 0, sizeof(fuzz));
    memset(fuzz.virgin_bits, 0xFF, COV_MAP_SIZE);
    gettimeofday(&fuzz.start_time, NULL);
    fuzz.last_ui_time = fuzz.start_time;

    rng_state = fuzz.start_time.tv_sec ^ fuzz.start_time.tv_usec;
    if (rng_state == 0) rng_state = 1;

    fuzz.mem_buf = malloc(MEM_SIZE);
    if (!fuzz.mem_buf) {
        fprintf(stderr, "[-] Failed to allocate engine memory\n");
        return 1;
    }

#if defined(USE_ASAN) || defined(USE_UBSAN)
    /* Initialize shared memory for fork-based sanitizer execution */
    init_shared_cov();
    printf("[*] Sanitizer mode: using fork-based execution\n");
#else
    printf("[*] Direct mode: in-process execution\n");
#endif

    /* create output directories */
    mkdir(CRASH_DIR, 0755);
    mkdir(CORPUS_DIR, 0755);

    /* register signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sa.sa_flags = SA_NODEFER; /* allow re-entry for nested signals */
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    init_seeds();

    if (corpus_in) {
        load_corpus_dir(corpus_in);
    }

    printf("[*] Starting fuzzing with %d corpus entries\n", fuzz.corpus_count);

    uint8_t mut_buf[MAX_INPUT_SIZE];
    uint32_t mut_len;

    for (;;) {
        int pick = rng_range(fuzz.corpus_count);
        CorpusEntry *entry = &fuzz.corpus[pick];

        mut_len = entry->len;
        if (mut_len > MAX_INPUT_SIZE - 64) mut_len = MAX_INPUT_SIZE - 64;
        memcpy(mut_buf, entry->data, mut_len);
        mut_len = mutate(mut_buf, mut_len, MAX_INPUT_SIZE);

        execute_input(mut_buf, mut_len, 1);
        fuzz.total_execs++;

        if (has_new_coverage()) {
            add_to_corpus(mut_buf, mut_len);
            fuzz.last_new_cov_exec = fuzz.total_execs;
        }

        print_status();
    }

    free(fuzz.mem_buf);
    return 0;
}
