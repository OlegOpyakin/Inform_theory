/*
 * bench_common.c — see bench_common.h.
 */
#include "bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void lat_init(struct lat_stats *s, size_t cap) {
    s->samples = cap ? malloc(cap * sizeof(double)) : NULL;
    s->n = 0;
    s->cap = s->samples ? cap : 0;
}

void lat_add(struct lat_stats *s, double us) {
    if (s->n < s->cap) s->samples[s->n++] = us;
}

void lat_free(struct lat_stats *s) {
    free(s->samples);
    s->samples = NULL;
    s->n = s->cap = 0;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Nearest-rank percentile on a sorted array. q in [0,1]. */
static double percentile(const double *sorted, size_t n, double q) {
    if (n == 0) return 0.0;
    size_t idx = (size_t)(q * (double)(n - 1) + 0.5);
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

void lat_summary(struct lat_stats *s,
                 double *mn, double *p50, double *p99, double *mx) {
    if (s->n == 0) { *mn = *p50 = *p99 = *mx = 0.0; return; }
    qsort(s->samples, s->n, sizeof(double), cmp_double);
    *mn  = s->samples[0];
    *mx  = s->samples[s->n - 1];
    *p50 = percentile(s->samples, s->n, 0.50);
    *p99 = percentile(s->samples, s->n, 0.99);
}

void *alloc_payload(size_t len, int aligned, size_t misalign, void **raw_out) {
    long ps = 4096;
#ifdef _SC_PAGESIZE
    long q = sysconf(_SC_PAGESIZE);
    if (q > 0) ps = q;
#endif
    void *raw = NULL;
    if (aligned) {
        if (posix_memalign(&raw, (size_t)ps, len) != 0) return NULL;
        *raw_out = raw;
        return raw;
    }
    /* Over-allocate a page, hand back a pointer `misalign` bytes into it. */
    if (misalign == 0) misalign = 1;
    if (posix_memalign(&raw, (size_t)ps, len + ps) != 0) return NULL;
    *raw_out = raw;
    return (char *)raw + misalign;
}

const char *RUN_CSV_HEADER =
    "variant,alg,type,method,op,bytes,alignment,threads,iters,warmup,"
    "throughput_MBps,lat_min_us,lat_p50_us,lat_p99_us,lat_max_us,kernel";

void print_csv_row(const struct run_row *r) {
    printf("%s,%s,%s,%s,%s,%zu,%s,%d,%ld,%ld,%.3f,%.3f,%.3f,%.3f,%.3f,%s\n",
           r->variant, r->alg, r->type, r->method, r->op,
           r->bytes, r->alignment, r->threads, r->iters, r->warmup,
           r->throughput_MBps,
           r->lat_min_us, r->lat_p50_us, r->lat_p99_us, r->lat_max_us,
           r->kernel);
}
