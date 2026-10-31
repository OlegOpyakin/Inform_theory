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
#include "ref_crypto.h"

#include <fcntl.h>
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
    int     file_backed; /* 1 = splice from temp file */
    int     verify;      /* 1 = check output against OpenSSL before timing */
};

/* Per-thread worker state. */
struct worker {
    const struct config  *cfg;
    struct bench_barrier *start;  /* released once every worker has warmed up */
    int               id;
    struct lat_stats  lat;
    int               ok;         /* 1 on success, 0 on error                */
    uint64_t          t_start;    /* timed phase: leaving the start barrier   */
    uint64_t          t_end;      /* timed phase: last op done                */
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

/* Payload start inside the data file: misaligned like `in` for --unaligned. */
static off64_t file_start(const struct config *cfg) {
    return cfg->aligned ? 0 : (off64_t)cfg->misalign;
}

/* One operation over the configured path; `inlen` bytes of input. */
static ssize_t run_op(const struct config *cfg, struct alg_ctx *c, int data_fd,
                      void *in, size_t inlen, void *out) {
    if (cfg->file_backed) {
        off64_t foff = file_start(cfg);
        return op_splice_file(c, cfg->dir, data_fd, &foff, out, inlen);
    }
    if (cfg->method == ALG_METHOD_SPLICE)
        return op_splice(c, cfg->dir, in, out, inlen);
    return op_sendmsg(c, cfg->dir, in, out, inlen);
}

/* Temp file holding the plaintext pattern at file_start(), page-cache hot. */
static int make_data_file(const struct config *cfg, int id) {
    char tmpl[] = "/tmp/afalg_data_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        fprintf(stderr, "worker %d: mkstemp: %s\n", id, strerror(errno));
        return -1;
    }
    unlink(tmpl);
    size_t pad = (size_t)file_start(cfg);
    unsigned char *seed = calloc(1, pad + cfg->size);
    if (!seed) {
        fprintf(stderr, "worker %d: oom\n", id);
        close(fd);
        return -1;
    }
    for (size_t i = 0; i < cfg->size; i++) seed[pad + i] = (unsigned char)i;
    ssize_t wr = write(fd, seed, pad + cfg->size);
    free(seed);
    if (wr != (ssize_t)(pad + cfg->size)) {
        fprintf(stderr, "worker %d: write tmpfile: %s\n", id, strerror(errno));
        close(fd);
        return -1;
    }
    posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED);
    fsync(fd);
    return fd;
}

static void *worker_main(void *arg) {
    struct worker *w = arg;
    const struct config *cfg = w->cfg;
    int arrived = 0;              /* reached the start barrier */
    int data_fd = -1;
    void *raw_in = NULL, *raw_out = NULL;
    w->ok = 0;

    size_t keylen = (size_t)cfg->keybits / 8;
    unsigned char key[64];
    for (size_t i = 0; i < keylen && i < sizeof key; i++) key[i] = (unsigned char)(i + 1);

    /* Unkeyed hashes reject ALG_SET_KEY, so only ciphers and hmac() get a key. */
    int keyed = strcmp(cfg->type, "hash") != 0 || !strncmp(cfg->alg, "hmac(", 5);
    if (!keyed) keylen = 0;

    struct alg_ctx c;
    if (alg_setup(&c, cfg->type, cfg->alg, keyed ? key : NULL, keylen, cfg->method) != 0)
        goto out_noctx;
    c.digestlen = digest_len_for(cfg->alg);

    size_t ivlen = iv_len_for(cfg->type, cfg->alg);
    unsigned char iv[ALG_MAX_IV];
    if (ivlen) {
        for (size_t i = 0; i < ivlen; i++) iv[i] = (unsigned char)(0xA0 + i);
        alg_set_iv(&c, iv, ivlen);
    }
    if (c.kind == ALG_KIND_AEAD && alg_set_aead(&c, cfg->assoclen, cfg->taglen) != 0)
        goto done;

    if (cfg->file_backed && (data_fd = make_data_file(cfg, w->id)) < 0)
        goto done;

    /* AEAD decrypt consumes ciphertext || tag and authenticates it, so feed it
     * a real ciphertext of `size` bytes (+ tag) — the plaintext pattern with a
     * garbage tag would fail with EBADMSG on every op. */
    int aead_dec = (c.kind == ALG_KIND_AEAD && cfg->dir == ALG_DIR_DECRYPT);
    size_t inlen = cfg->size + (aead_dec ? cfg->taglen : 0);

    /* Output buffer: large enough for ciphertext+tag or a digest. */
    size_t outcap = inlen + cfg->taglen + ALG_MAX_DIGEST + 64;
    void *in  = alloc_payload(inlen, cfg->aligned, cfg->misalign, &raw_in);
    void *out = alloc_payload(outcap, 1, 0, &raw_out);
    if (!in || !out) {
        fprintf(stderr, "worker %d: out of memory\n", w->id);
        goto done;
    }
    for (size_t i = 0; i < cfg->size; i++) ((unsigned char *)in)[i] = (unsigned char)i;

    if (aead_dec) {
        if (op_sendmsg(&c, ALG_DIR_ENCRYPT, in, out, cfg->size) != (ssize_t)inlen) {
            fprintf(stderr, "worker %d: AEAD pre-encrypt failed: %s\n", w->id, strerror(errno));
            goto done;
        }
        memcpy(in, out, inlen);
    }

    /* Run the timed path once and compare with an independent OpenSSL result
     * (same key / IV / input). Outside the timed loop. */
    if (cfg->verify) {
        ssize_t got = run_op(cfg, &c, data_fd, in, inlen, out);
        unsigned char *want = malloc(outcap);
        long wl = want ? ref_transform(cfg->type, cfg->alg, cfg->keybits,
                                       cfg->dir == ALG_DIR_ENCRYPT, key, iv,
                                       in, inlen, cfg->assoclen, cfg->taglen, want)
                       : -1;
        char who[32];
        snprintf(who, sizeof who, "afalg_bench[%d]", w->id);
        int good = 1;
        if (got < 0) {
            fprintf(stderr, "%s: verify: op failed: %s\n", who, strerror(errno));
            good = 0;
        } else if (wl == 0) {
            if (w->id == 0) fprintf(stderr, "%s: verify skipped (%s %s not checkable)\n",
                                    who, cfg->type, cfg->alg);
        } else if (wl < 0 || !ref_compare(who, out, (size_t)got, want, (size_t)wl)) {
            good = 0;
        } else if (w->id == 0) {
            fprintf(stderr, "%s: verify OK (%zd bytes match OpenSSL)\n", who, got);
        }
        free(want);
        if (!good) goto done;
    }

    lat_init(&w->lat, (size_t)cfg->iters);

    for (long it = 0; it < cfg->warmup; it++) {
        if (run_op(cfg, &c, data_fd, in, inlen, out) < 0) {
            fprintf(stderr, "worker %d: op failed at warmup iter %ld: %s\n",
                    w->id, it, strerror(errno));
            goto done;
        }
    }

    /* All workers start the timed phase together, so its wall time is a real
     * aggregate measurement for threads > 1. */
    bench_barrier_wait(w->start);
    arrived = 1;
    w->t_start = now_ns();

    for (long it = 0; it < cfg->iters; it++) {
        uint64_t t0 = now_ns();
        ssize_t r = run_op(cfg, &c, data_fd, in, inlen, out);
        uint64_t t1 = now_ns();

        if (r < 0) {
            fprintf(stderr, "worker %d: op failed at iter %ld: %s\n",
                    w->id, it, strerror(errno));
            goto done;
        }
        lat_add(&w->lat, (double)(t1 - t0) / 1000.0);
    }
    w->t_end = now_ns();
    w->ok = 1;

done:
    alg_teardown(&c);
out_noctx:
    if (!arrived) bench_barrier_abandon(w->start);
    if (data_fd >= 0) close(data_fd);
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
        "  --file-backed                 (splice from a temp file: true zero-copy)\n"
        "  --verify                      (check output against OpenSSL before timing)\n"
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
        .taglen = 16, .assoclen = 0, .variant = NULL, .csv = 0, .file_backed = 0,
        .verify = 0,
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
        else if (!strcmp(a, "--file-backed")) cfg.file_backed = 1;
        else if (!strcmp(a, "--verify"))   cfg.verify = 1;
        else if (!strcmp(a, "--header"))   { printf("%s\n", RUN_CSV_HEADER); return 0; }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 2; }
        #undef NEXT
    }

    if (cfg.threads < 1) cfg.threads = 1;
    int is_hash = !strcmp(cfg.type, "hash");
    if (!is_hash && cfg.keybits != 128 && cfg.keybits != 192 && cfg.keybits != 256) {
        fprintf(stderr, "afalg_bench: --keybits must be 128, 192 or 256\n");
        return 2;
    }
    if (cfg.size == 0 || cfg.iters < 1 || cfg.warmup < 0) {
        fprintf(stderr, "afalg_bench: need --size > 0, --iters >= 1, --warmup >= 0\n");
        return 2;
    }

    if (!cfg.variant) {
        if (cfg.file_backed)                cfg.variant = "afalg-zc-file";
        else if (cfg.method == ALG_METHOD_SPLICE) cfg.variant = "afalg-zc";
        else                                cfg.variant = "afalg-copy";
    }
    if (cfg.file_backed) cfg.method = ALG_METHOD_SPLICE;

    struct worker *ws = calloc((size_t)cfg.threads, sizeof(*ws));
    pthread_t *tids = calloc((size_t)cfg.threads, sizeof(*tids));
    struct bench_barrier *start = bench_barrier_new(cfg.threads);
    if (!ws || !tids || !start) { fprintf(stderr, "out of memory\n"); return 1; }

    uint64_t wall0 = now_ns();
    for (int t = 0; t < cfg.threads; t++) {
        ws[t].cfg = &cfg;
        ws[t].start = start;
        ws[t].id = t;
        if (pthread_create(&tids[t], NULL, worker_main, &ws[t]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    for (int t = 0; t < cfg.threads; t++) pthread_join(tids[t], NULL);
    uint64_t wall1 = now_ns();
    bench_barrier_free(start);

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
    /* Timed phase only (wall_s also covers setup and warmup). */
    uint64_t t_start = ws[0].t_start, t_end = ws[0].t_end;
    for (int t = 1; t < cfg.threads; t++) {
        if (ws[t].t_start < t_start) t_start = ws[t].t_start;
        if (ws[t].t_end   > t_end)   t_end   = ws[t].t_end;
    }
    double mbps = throughput_mbps(cfg.size, cfg.iters, cfg.threads, t_end - t_start);

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
        .keybits = is_hash && strncmp(cfg.alg, "hmac(", 5) ? 0 : cfg.keybits,
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
