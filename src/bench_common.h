/*
 * bench_common.h — timing, latency stats, buffers and CSV output shared by
 * afalg_bench (Layer 0) and openssl_bench (Layer 1).
 *
 * Portable C (no AF_ALG), so this compiles and runs anywhere with a C toolchain.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* --- monotonic clock, nanoseconds --- */
uint64_t now_ns(void);

/* --- latency sample collection --- */
struct lat_stats {
    double *samples;  /* microseconds, one per timed iteration */
    size_t  n;
    size_t  cap;
};
void   lat_init(struct lat_stats *s, size_t cap);
void   lat_add(struct lat_stats *s, double us);
void   lat_free(struct lat_stats *s);
/* Fills min/p50/p99/max (microseconds). Sorts the sample array in place. */
void   lat_summary(struct lat_stats *s,
                   double *mn, double *p50, double *p99, double *mx);

/*
 * Allocate a payload buffer of `len` bytes.
 *  - aligned != 0: page-aligned base (posix_memalign), suitable for zero-copy.
 *  - aligned == 0: deliberately offset from a page boundary by `misalign`
 *                  bytes so the zero-copy path cannot engage (tests H1).
 * `*raw_out` receives the pointer to free(); the returned pointer is the
 * (possibly offset) usable buffer. Returns NULL on failure.
 */
void *alloc_payload(size_t len, int aligned, size_t misalign, void **raw_out);

/*
 * Fixed CSV schema emitted by every bench with --csv (no header; the header is
 * written by scripts/run_matrix.sh). One row per run.
 */
struct run_row {
    const char *variant;      /* afalg-copy | afalg-zc | userspace-aesni | ... */
    const char *alg;          /* cbc(aes) | gcm(aes) | sha256                  */
    const char *type;         /* skcipher | hash | aead                        */
    const char *method;       /* sendmsg | splice | evp                        */
    const char *op;           /* enc | dec | hash                              */
    size_t      bytes;        /* payload size per op                           */
    const char *alignment;    /* aligned | unaligned                           */
    int         threads;
    long        iters;        /* timed iterations per thread                   */
    long        warmup;
    double      throughput_MBps;
    double      lat_min_us, lat_p50_us, lat_p99_us, lat_max_us;
    const char *kernel;       /* uname -r                                      */
};

/* The header matching run_row, used by run_matrix.sh when creating a CSV. */
extern const char *RUN_CSV_HEADER;

/* Print one CSV data row to stdout. */
void print_csv_row(const struct run_row *r);

#endif /* BENCH_COMMON_H */
