/*
 * openssl_bench.c — Layer 1 reference baseline.
 *
 * The "optimized userspace crypto" side of the thesis: OpenSSL EVP, which uses
 * AES-NI (or ARMv8 crypto extensions) when the CPU has it. Same CSV schema,
 * same size/thread sweep as afalg_bench, so rows line up cell-for-cell against
 * the AF_ALG variants (plan RQ3, H3/H4).
 *
 * Toggle hardware acceleration out-of-band with OPENSSL_ia32cap (x86) to answer
 * RQ2 — see scripts/run_matrix.sh.
 *
 * Portable: no AF_ALG, builds anywhere OpenSSL is available.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "bench_common.h"
#include "ref_crypto.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <openssl/evp.h>
#include <openssl/err.h>

enum kind { K_SKCIPHER, K_HASH, K_AEAD };

struct config {
    const char *alg;       /* cbc(aes) | gcm(aes) | sha256 */
    const char *type;      /* skcipher | aead | hash       */
    enum kind   kind;
    int         encrypt;
    size_t      size;
    long        iters, warmup;
    int         threads;
    int         aligned;
    size_t      misalign;
    int         keybits;
    size_t      taglen, assoclen;
    const char *variant;
    int         csv;
    int         verify;    /* 1 = check output against one-shot EVP before timing */
};

struct worker {
    const struct config  *cfg;
    struct bench_barrier *start;  /* released once every worker has warmed up */
    int id, ok;
    struct lat_stats lat;
    uint64_t t_start, t_end;      /* timed phase wall clock                   */
};

/*
 * Resolve the AF_ALG-style name + key size to an OpenSSL cipher. Exact names
 * only: anything else returns NULL rather than silently benchmarking CBC under
 * another label.
 */
static const EVP_CIPHER *resolve_cipher(const struct config *cfg) {
    const char *mode = NULL;
    if      (!strcmp(cfg->alg, "cbc(aes)")) mode = "cbc";
    else if (!strcmp(cfg->alg, "ctr(aes)")) mode = "ctr";
    else if (!strcmp(cfg->alg, "ecb(aes)")) mode = "ecb";
    else if (!strcmp(cfg->alg, "gcm(aes)")) mode = "gcm";
    if (!mode) return NULL;
    char name[32];
    snprintf(name, sizeof name, "aes-%d-%s", cfg->keybits, mode);
    return EVP_get_cipherbyname(name);
}

/* Unkeyed digests only (no hmac); NULL for anything else. */
static const EVP_MD *resolve_md(const char *alg) {
    if (!strcmp(alg, "sha512")) return EVP_sha512();
    if (!strcmp(alg, "sha384")) return EVP_sha384();
    if (!strcmp(alg, "sha256")) return EVP_sha256();
    if (!strcmp(alg, "sha224")) return EVP_sha224();
    if (!strcmp(alg, "sha1"))   return EVP_sha1();
    if (!strcmp(alg, "md5"))    return EVP_md5();
    return NULL;
}

static int do_cipher_op(EVP_CIPHER_CTX *ctx, const struct config *cfg,
                        const EVP_CIPHER *ciph,
                        const unsigned char *key, const unsigned char *iv,
                        const unsigned char *in, unsigned char *out, int inlen,
                        unsigned char *aad, int aadlen, unsigned char *tag) {
    int len = 0, outlen = 0;
    if (!EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, cfg->encrypt)) return -1;
    if (cfg->kind == K_AEAD) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) return -1;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, cfg->encrypt)) return -1;
    if (cfg->kind != K_AEAD)
        EVP_CIPHER_CTX_set_padding(ctx, 0); /* buffer is block-aligned; keep it simple */

    if (cfg->kind == K_AEAD && aadlen > 0) {
        if (!EVP_CipherUpdate(ctx, NULL, &len, aad, aadlen)) return -1;
    }
    if (!EVP_CipherUpdate(ctx, out, &len, in, inlen)) return -1;
    outlen = len;
    if (cfg->kind == K_AEAD && !cfg->encrypt) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)cfg->taglen, tag)) return -1;
    }
    if (!EVP_CipherFinal_ex(ctx, out + len, &len)) return -1;
    outlen += len;
    if (cfg->kind == K_AEAD && cfg->encrypt) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)cfg->taglen, tag)) return -1;
    }
    return outlen;
}

/* One timed operation: digest (written to `out`) or cipher. Returns out bytes. */
static int run_op(const struct config *cfg, EVP_MD_CTX *mctx, const EVP_MD *md,
                  EVP_CIPHER_CTX *cctx, const EVP_CIPHER *ciph,
                  const unsigned char *key, const unsigned char *iv,
                  const unsigned char *in, unsigned char *out,
                  unsigned char *aad, size_t aadlen, unsigned char *tag) {
    if (cfg->kind == K_HASH) {
        unsigned int dlen = 0;
        return EVP_DigestInit_ex(mctx, md, NULL)
            && EVP_DigestUpdate(mctx, in, cfg->size)
            && EVP_DigestFinal_ex(mctx, out, &dlen) ? (int)dlen : -1;
    }
    return do_cipher_op(cctx, cfg, ciph, key, iv, in, out, (int)cfg->size,
                        aad, (int)aadlen, tag);
}

static void *worker_main(void *arg) {
    struct worker *w = arg;
    const struct config *cfg = w->cfg;
    int arrived = 0;              /* reached the start barrier */
    w->ok = 0;

    size_t keylen = (size_t)cfg->keybits / 8;
    unsigned char key[32], iv[16], tag[16], aad[256];
    for (size_t i = 0; i < keylen; i++) key[i] = (unsigned char)(i + 1);
    for (size_t i = 0; i < sizeof iv; i++) iv[i] = (unsigned char)(0xA0 + i);
    memset(aad, 0x5A, sizeof aad);
    memset(tag, 0, sizeof tag);

    const EVP_CIPHER *ciph = NULL;
    const EVP_MD *md = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    EVP_MD_CTX *mctx = NULL;

    void *raw_in = NULL, *raw_out = NULL;
    size_t outcap = cfg->size + EVP_MAX_MD_SIZE + 64;
    unsigned char *in  = alloc_payload(cfg->size, cfg->aligned, cfg->misalign, &raw_in);
    unsigned char *out = alloc_payload(outcap, 1, 0, &raw_out);
    if (!in || !out) goto done;
    for (size_t i = 0; i < cfg->size; i++) in[i] = (unsigned char)i;

    if (cfg->kind == K_HASH) {
        md = resolve_md(cfg->alg);
        mctx = EVP_MD_CTX_new();
        if (!md || !mctx) goto done;
    } else {
        ciph = resolve_cipher(cfg);
        cctx = EVP_CIPHER_CTX_new();
        if (!ciph || !cctx) goto done;
    }

    size_t aadlen = (cfg->kind == K_AEAD) ? cfg->assoclen : 0;
    if (aadlen > sizeof aad) aadlen = sizeof aad;

    /* AEAD decrypt authenticates its input, so give it a real ciphertext and
     * tag; the plaintext pattern with a zero tag fails on every op. */
    int aead_dec = (cfg->kind == K_AEAD && !cfg->encrypt);
    if (aead_dec) {
        struct config enc = *cfg;
        enc.encrypt = 1;
        if (do_cipher_op(cctx, &enc, ciph, key, iv, in, out, (int)cfg->size,
                         aad, (int)aadlen, tag) != (int)cfg->size) {
            fprintf(stderr, "worker %d: AEAD pre-encrypt failed\n", w->id);
            ERR_print_errors_fp(stderr);
            goto done;
        }
        memcpy(in, out, cfg->size);
    }

    /* Run the timed path once and compare with a fresh one-shot EVP result,
     * which catches context-reuse / length bugs in the hot loop. Untimed. */
    if (cfg->verify) {
        int got = run_op(cfg, mctx, md, cctx, ciph, key, iv, in, out, aad, aadlen, tag);
        if (got >= 0 && cfg->kind == K_AEAD && cfg->encrypt) {
            memcpy(out + got, tag, cfg->taglen);   /* compare as ct || tag */
            got += (int)cfg->taglen;
        }
        /* The reference takes AEAD decrypt input as ciphertext || tag. */
        size_t reflen = cfg->size + (aead_dec ? cfg->taglen : 0);
        unsigned char *refin = malloc(reflen);
        unsigned char *want = malloc(outcap);
        long wl = -1;
        if (refin && want) {
            memcpy(refin, in, cfg->size);
            if (aead_dec) memcpy(refin + cfg->size, tag, cfg->taglen);
            wl = ref_transform(cfg->type, cfg->alg, cfg->keybits, cfg->encrypt,
                               key, iv, refin, reflen, cfg->assoclen, cfg->taglen, want);
        }
        char who[32];
        snprintf(who, sizeof who, "openssl_bench[%d]", w->id);
        int good = 1;
        if (got < 0) {
            fprintf(stderr, "%s: verify: EVP op failed\n", who);
            ERR_print_errors_fp(stderr);
            good = 0;
        } else if (wl == 0) {
            if (w->id == 0) fprintf(stderr, "%s: verify skipped (%s %s not checkable)\n",
                                    who, cfg->type, cfg->alg);
        } else if (wl < 0 || !ref_compare(who, out, (size_t)got, want, (size_t)wl)) {
            good = 0;
        } else if (w->id == 0) {
            fprintf(stderr, "%s: verify OK (%d bytes match one-shot EVP)\n", who, got);
        }
        free(refin);
        free(want);
        if (!good) goto done;
    }

    lat_init(&w->lat, (size_t)cfg->iters);

    for (long it = 0; it < cfg->warmup; it++) {
        if (run_op(cfg, mctx, md, cctx, ciph, key, iv, in, out, aad, aadlen, tag) < 0) {
            fprintf(stderr, "worker %d: EVP op failed at warmup iter %ld\n", w->id, it);
            ERR_print_errors_fp(stderr);
            goto done;
        }
    }

    /* All workers start the timed phase together (see afalg_bench). */
    bench_barrier_wait(w->start);
    arrived = 1;
    w->t_start = now_ns();

    for (long it = 0; it < cfg->iters; it++) {
        uint64_t t0 = now_ns();
        int rc = run_op(cfg, mctx, md, cctx, ciph, key, iv, in, out, aad, aadlen, tag);
        uint64_t t1 = now_ns();
        if (rc < 0) {
            fprintf(stderr, "worker %d: EVP op failed at iter %ld\n", w->id, it);
            ERR_print_errors_fp(stderr);
            goto done;
        }
        lat_add(&w->lat, (double)(t1 - t0) / 1000.0);
    }
    w->t_end = now_ns();
    w->ok = 1;

done:
    if (!arrived) bench_barrier_abandon(w->start);
    if (cctx) EVP_CIPHER_CTX_free(cctx);
    if (mctx) EVP_MD_CTX_free(mctx);
    free(raw_in);
    free(raw_out);
    return NULL;
}

static size_t parse_size(const char *s) {
    char *end = NULL;
    double v = strtod(s, &end);
    if (end && (*end == 'k' || *end == 'K')) v *= 1024.0;
    else if (end && (*end == 'm' || *end == 'M')) v *= 1024.0 * 1024.0;
    else if (end && (*end == 'g' || *end == 'G')) v *= 1024.0 * 1024.0 * 1024.0;
    return (size_t)v;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]   (userspace OpenSSL baseline)\n"
        "  --alg NAME  --type skcipher|hash|aead  --op enc|dec\n"
        "  --size BYTES[K|M]  --iters N  --warmup N  --threads N\n"
        "  --aligned|--unaligned  --misalign N  --keybits 128|192|256\n"
        "  --taglen N  --assoclen N  --variant LABEL  --csv  --header\n"
        "  --verify    (check output against one-shot EVP before timing)\n",
        prog);
}

int main(int argc, char **argv) {
    struct config cfg = {
        .alg = "cbc(aes)", .type = "skcipher", .kind = K_SKCIPHER, .encrypt = 1,
        .size = 4096, .iters = 10000, .warmup = 1000, .threads = 1,
        .aligned = 1, .misalign = 1, .keybits = 128,
        .taglen = 16, .assoclen = 0, .variant = "userspace-aesni", .csv = 0,
        .verify = 0,
    };

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(argv[0]), exit(2), ""))
        if      (!strcmp(a, "--alg"))      cfg.alg = NEXT();
        else if (!strcmp(a, "--type"))     cfg.type = NEXT();
        else if (!strcmp(a, "--op"))       cfg.encrypt = strcmp(NEXT(), "dec") != 0;
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
        else if (!strcmp(a, "--verify"))   cfg.verify = 1;
        else if (!strcmp(a, "--header"))   { printf("%s\n", RUN_CSV_HEADER); return 0; }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 2; }
        #undef NEXT
    }

    if (!strcmp(cfg.type, "hash")) cfg.kind = K_HASH;
    else if (!strcmp(cfg.type, "aead")) cfg.kind = K_AEAD;
    else cfg.kind = K_SKCIPHER;
    if (cfg.threads < 1) cfg.threads = 1;

    if (cfg.kind != K_HASH && cfg.keybits != 128 && cfg.keybits != 192 && cfg.keybits != 256) {
        fprintf(stderr, "openssl_bench: --keybits must be 128, 192 or 256\n");
        return 2;
    }
    if (cfg.size == 0 || cfg.iters < 1 || cfg.warmup < 0) {
        fprintf(stderr, "openssl_bench: need --size > 0, --iters >= 1, --warmup >= 0\n");
        return 2;
    }
    if (cfg.kind == K_HASH ? !resolve_md(cfg.alg) : !resolve_cipher(&cfg)) {
        fprintf(stderr, "openssl_bench: unsupported %s algorithm '%s' "
                "(ciphers: cbc/ctr/ecb/gcm(aes); hashes: sha1/224/256/384/512, md5)\n",
                cfg.type, cfg.alg);
        return 2;
    }

    struct worker *ws = calloc((size_t)cfg.threads, sizeof(*ws));
    pthread_t *tids = calloc((size_t)cfg.threads, sizeof(*tids));
    struct bench_barrier *start = bench_barrier_new(cfg.threads);
    if (!ws || !tids || !start) { fprintf(stderr, "out of memory\n"); return 1; }

    uint64_t wall0 = now_ns();
    for (int t = 0; t < cfg.threads; t++) {
        ws[t].cfg = &cfg; ws[t].start = start; ws[t].id = t;
        if (pthread_create(&tids[t], NULL, worker_main, &ws[t]) != 0) {
            fprintf(stderr, "pthread_create failed\n"); return 1;
        }
    }
    for (int t = 0; t < cfg.threads; t++) pthread_join(tids[t], NULL);
    uint64_t wall1 = now_ns();
    bench_barrier_free(start);

    int all_ok = 1;
    struct lat_stats merged;
    lat_init(&merged, (size_t)cfg.iters * (size_t)cfg.threads);
    for (int t = 0; t < cfg.threads; t++) {
        if (!ws[t].ok) all_ok = 0;
        for (size_t i = 0; i < ws[t].lat.n; i++) lat_add(&merged, ws[t].lat.samples[i]);
        lat_free(&ws[t].lat);
    }
    if (!all_ok) {
        fprintf(stderr, "openssl_bench: worker failure; no result emitted\n");
        lat_free(&merged); free(ws); free(tids);
        return 1;
    }

    double mn, p50, p99, mx;
    lat_summary(&merged, &mn, &p50, &p99, &mx);
    double wall_s = (double)(wall1 - wall0) / 1e9;
    /* Timed phase only (wall_s also covers setup and warmup), as afalg_bench. */
    uint64_t t_start = ws[0].t_start, t_end = ws[0].t_end;
    for (int t = 1; t < cfg.threads; t++) {
        if (ws[t].t_start < t_start) t_start = ws[t].t_start;
        if (ws[t].t_end   > t_end)   t_end   = ws[t].t_end;
    }
    double mbps = throughput_mbps(cfg.size, cfg.iters, cfg.threads, t_end - t_start);

    struct utsname un; uname(&un);
    const char *op_str = (cfg.kind == K_HASH) ? "hash" : (cfg.encrypt ? "enc" : "dec");

    struct run_row row = {
        .variant = cfg.variant, .alg = cfg.alg, .type = cfg.type,
        .method = "evp", .op = op_str, .bytes = cfg.size,
        .alignment = cfg.aligned ? "aligned" : "unaligned",
        .threads = cfg.threads, .iters = cfg.iters, .warmup = cfg.warmup,
        .throughput_MBps = mbps,
        .lat_min_us = mn, .lat_p50_us = p50, .lat_p99_us = p99, .lat_max_us = mx,
        .kernel = un.release,
        .keybits = (cfg.kind == K_HASH) ? 0 : cfg.keybits,
    };

    if (cfg.csv) {
        print_csv_row(&row);
    } else {
        printf("OpenSSL bench  %s / %s  op=%s  size=%zu  threads=%d\n",
               cfg.variant, cfg.alg, op_str, cfg.size, cfg.threads);
        printf("  throughput : %.2f MB/s   (%.3fs wall)\n", mbps, wall_s);
        printf("  latency us : min=%.2f  p50=%.2f  p99=%.2f  max=%.2f\n", mn, p50, p99, mx);
        printf("  kernel     : %s\n", un.release);
    }

    lat_free(&merged); free(ws); free(tids);
    return 0;
}
