/*
 * afalg_bench.c — Layer 0 standalone harness.
 *
 * Drives the AF_ALG crypto core (alg_core) over the copy path (sendmsg) or the
 * zero-copy path (splice), across sizes, alignment and thread counts, and emits
 * throughput + latency as a CSV row (or a human summary).
 *
 * The key move (plan, "Архитектура"): `afalg_bench --method splice` run on two
 * kernels — one pre-fix (real zero-copy) and one post-fix (splice copies
 * internally) — isolates the cost of the fix, because the userspace code is
 * byte-for-byte identical on both.
 *
 * Linux only.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "alg_core.h"
#include "bench_common.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

struct config {
    const char *type;      /* skcipher | hash | aead */
    const char *alg;       /* cbc(aes) | sha256 | gcm(aes) */
    alg_method_t method;
    alg_dir_t    dir;
    size_t  size;
    long    iters;
    long    warmup;
    int     threads;
    int     aligned;
    size_t  misalign;
    int     keybits;
    size_t  taglen;
    size_t  assoclen;
    const char *variant;
    int     csv;
};

/* Per-thread worker state. */
struct worker {
    const struct config *cfg;
    int               id;
    struct lat_stats  lat;
    int               ok;     /* 0 on success, nonzero on error */
    uint64_t          busy_ns;/* total time spent in timed ops   */
};

static size_t digest_len_for(const char *name) {
    if (strstr(name, "sha512")) return 64;
    if (strstr(name, "sha384")) return 48;
    if (strstr(name, "sha256")) return 32;
    if (strstr(name, "sha224")) return 28;
    if (strstr(name, "sha1"))   return 20;
    if (strstr(name, "md5"))    return 16;
    return 32;
}

static size_t iv_len_for(const char *type, const char *name) {
    if (strcmp(type, "hash") == 0) return 0;
    if (strstr(name, "gcm")) return 12;   /* GCM nonce */
    return 16;                            /* AES block IV for cbc/ctr/xts-ish */
}

static void *worker_main(void *arg) {
    struct worker *w = arg;
    const struct config *cfg = w->cfg;
    w->ok = 1;

    size_t keylen = (size_t)cfg->keybits / 8;
    unsigned char key[64];
    for (size_t i = 0; i < keylen && i < sizeof key; i++) key[i] = (unsigned char)(i + 1);

    struct alg_ctx c;
    if (alg_setup(&c, cfg->type, cfg->alg, key, keylen, cfg->method) != 0) {
        w->ok = 0;
        return NULL;
    }
    c.digestlen = digest_len_for(cfg->alg);

    size_t ivlen = iv_len_for(cfg->type, cfg->alg);
    if (ivlen) {
        unsigned char iv[ALG_MAX_IV];
        for (size_t i = 0; i < ivlen; i++) iv[i] = (unsigned char)(0xA0 + i);
        alg_set_iv(&c, iv, ivlen);
    }
    if (c.kind == ALG_KIND_AEAD)
        alg_set_aead(&c, cfg->assoclen, cfg->taglen);

    /* Output buffer: large enough for ciphertext+tag or a digest. */
    size_t outcap = cfg->size + cfg->taglen + ALG_MAX_DIGEST + 64;
    void *raw_in = NULL, *raw_out = NULL;
    void *in  = alloc_payload(cfg->size, cfg->aligned, cfg->misalign, &raw_in);
    void *out = alloc_payload(outcap, 1, 0, &raw_out);
    if (!in || !out) {
        fprintf(stderr, "worker %d: out of memory\n", w->id);
        w->ok = 0;
        alg_teardown(&c);
        free(raw_in); free(raw_out);
        return NULL;
    }
    for (size_t i = 0; i < cfg->size; i++) ((unsigned char *)in)[i] = (unsigned char)i;

    lat_init(&w->lat, (size_t)cfg->iters);

    for (long it = 0; it < cfg->warmup + cfg->iters; it++) {
        uint64_t t0 = now_ns();
        ssize_t r;
        if (cfg->method == ALG_METHOD_SPLICE)
            r = op_splice(&c, cfg->dir, in, out, cfg->size);
        else
            r = op_sendmsg(&c, cfg->dir, in, out, cfg->size);
        uint64_t t1 = now_ns();

        if (r < 0) {
            fprintf(stderr, "worker %d: op failed at iter %ld: %s\n",
                    w->id, it, strerror(errno));
            w->ok = 0;
            break;
        }
        if (it >= cfg->warmup) {
            double us = (double)(t1 - t0) / 1000.0;
            lat_add(&w->lat, us);
            w->busy_ns += (t1 - t0);
        }
    }

    alg_teardown(&c);
    free(raw_in);
    free(raw_out);
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --type   skcipher|hash|aead   (default skcipher)\n"
        "  --alg    NAME                 (default cbc(aes))\n"
        "  --method sendmsg|splice       (default sendmsg)\n"
        "  --op     enc|dec              (default enc; ignored for hash)\n"
        "  --size   BYTES[K|M]           (default 4096)\n"
        "  --iters  N                    (default 10000)\n"
        "  --warmup N                    (default 1000)\n"
        "  --threads N                   (default 1)\n"
        "  --aligned | --unaligned       (default aligned)\n"
        "  --misalign N                  (default 1)\n"
        "  --keybits 128|192|256         (default 128)\n"
        "  --taglen N                    (AEAD, default 16)\n"
        "  --assoclen N                  (AEAD, default 0)\n"
        "  --variant LABEL               (default derived from type/method)\n"
        "  --csv                         (emit one CSV data row)\n"
        "  --header                      (print CSV header and exit)\n",
        prog);
}

static size_t parse_size(const char *s) {
    char *end = NULL;
    double v = strtod(s, &end);
    if (end && (*end == 'k' || *end == 'K')) v *= 1024.0;
    else if (end && (*end == 'm' || *end == 'M')) v *= 1024.0 * 1024.0;
    else if (end && (*end == 'g' || *end == 'G')) v *= 1024.0 * 1024.0 * 1024.0;
    return (size_t)v;
}

int main(int argc, char **argv) {
    struct config cfg = {
        .type = "skcipher", .alg = "cbc(aes)",
        .method = ALG_METHOD_SENDMSG, .dir = ALG_DIR_ENCRYPT,
        .size = 4096, .iters = 10000, .warmup = 1000, .threads = 1,
        .aligned = 1, .misalign = 1, .keybits = 128,
        .taglen = 16, .assoclen = 0, .variant = NULL, .csv = 0,
    };

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(argv[0]), exit(2), ""))
        if      (!strcmp(a, "--type"))     cfg.type = NEXT();
        else if (!strcmp(a, "--alg"))      cfg.alg = NEXT();
        else if (!strcmp(a, "--method")) {
            const char *m = NEXT();
            cfg.method = !strcmp(m, "splice") ? ALG_METHOD_SPLICE : ALG_METHOD_SENDMSG;
        }
        else if (!strcmp(a, "--op")) {
            const char *o = NEXT();
            cfg.dir = !strcmp(o, "dec") ? ALG_DIR_DECRYPT : ALG_DIR_ENCRYPT;
        }
        else if (!strcmp(a, "--size"))     cfg.size = parse_size(NEXT());
        else if (!strcmp(a, "--iters"))    cfg.iters = atol(NEXT());
        else if (!strcmp(a, "--warmup"))   cfg.warmup = atol(NEXT());
        else if (!strcmp(a, "--threads"))  cfg.threads = atoi(NEXT());
        else if (!strcmp(a, "--aligned"))  cfg.aligned = 1;
        else if (!strcmp(a, "--unaligned"))cfg.aligned = 0;
        else if (!strcmp(a, "--misalign")) cfg.misalign = parse_size(NEXT());
        else if (!strcmp(a, "--keybits"))  cfg.keybits = atoi(NEXT());
        else if (!strcmp(a, "--taglen"))   cfg.taglen = parse_size(NEXT());
        else if (!strcmp(a, "--assoclen")) cfg.assoclen = parse_size(NEXT());
        else if (!strcmp(a, "--variant"))  cfg.variant = NEXT();
        else if (!strcmp(a, "--csv"))      cfg.csv = 1;
        else if (!strcmp(a, "--header"))   { printf("%s\n", RUN_CSV_HEADER); return 0; }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 2; }
        #undef NEXT
    }

    if (cfg.threads < 1) cfg.threads = 1;
    int is_hash = !strcmp(cfg.type, "hash");

    if (!cfg.variant)
        cfg.variant = (cfg.method == ALG_METHOD_SPLICE) ? "afalg-zc" : "afalg-copy";

    struct worker *ws = calloc((size_t)cfg.threads, sizeof(*ws));
    pthread_t *tids = calloc((size_t)cfg.threads, sizeof(*tids));
    if (!ws || !tids) { fprintf(stderr, "out of memory\n"); return 1; }

    uint64_t wall0 = now_ns();
    for (int t = 0; t < cfg.threads; t++) {
        ws[t].cfg = &cfg;
        ws[t].id = t;
        if (pthread_create(&tids[t], NULL, worker_main, &ws[t]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    for (int t = 0; t < cfg.threads; t++) pthread_join(tids[t], NULL);
    uint64_t wall1 = now_ns();

    /* Aggregate. */
    int all_ok = 1;
    struct lat_stats merged;
    lat_init(&merged, (size_t)cfg.iters * (size_t)cfg.threads);
    for (int t = 0; t < cfg.threads; t++) {
        if (!ws[t].ok) all_ok = 0;
        for (size_t i = 0; i < ws[t].lat.n; i++) lat_add(&merged, ws[t].lat.samples[i]);
        lat_free(&ws[t].lat);
    }
    if (!all_ok) {
        fprintf(stderr, "afalg_bench: one or more workers failed; no result emitted\n");
        lat_free(&merged);
        free(ws); free(tids);
        return 1;
    }

    double mn, p50, p99, mx;
    lat_summary(&merged, &mn, &p50, &p99, &mx);

    double wall_s = (double)(wall1 - wall0) / 1e9;
    double total_bytes = (double)cfg.size * (double)cfg.iters * (double)cfg.threads;
    double mbps = (wall_s > 0.0) ? (total_bytes / (1024.0 * 1024.0)) / wall_s : 0.0;

    struct utsname un;
    uname(&un);

    const char *op_str = is_hash ? "hash" : (cfg.dir == ALG_DIR_ENCRYPT ? "enc" : "dec");
    const char *method_str = (cfg.method == ALG_METHOD_SPLICE) ? "splice" : "sendmsg";
    const char *align_str = cfg.aligned ? "aligned" : "unaligned";

    struct run_row row = {
        .variant = cfg.variant, .alg = cfg.alg, .type = cfg.type,
        .method = method_str, .op = op_str, .bytes = cfg.size,
        .alignment = align_str, .threads = cfg.threads,
        .iters = cfg.iters, .warmup = cfg.warmup,
        .throughput_MBps = mbps,
        .lat_min_us = mn, .lat_p50_us = p50, .lat_p99_us = p99, .lat_max_us = mx,
        .kernel = un.release,
    };

    if (cfg.csv) {
        print_csv_row(&row);
    } else {
        printf("AF_ALG bench  %s / %s / %s  op=%s  size=%zu  align=%s  threads=%d\n",
               cfg.variant, cfg.alg, method_str, op_str, cfg.size, align_str, cfg.threads);
        printf("  throughput : %.2f MB/s   (%.0f iters/thread, %d threads, %.3fs wall)\n",
               mbps, (double)cfg.iters, cfg.threads, wall_s);
        printf("  latency us : min=%.2f  p50=%.2f  p99=%.2f  max=%.2f\n", mn, p50, p99, mx);
        printf("  kernel     : %s\n", un.release);
    }

    lat_free(&merged);
    free(ws); free(tids);
    return 0;
}
