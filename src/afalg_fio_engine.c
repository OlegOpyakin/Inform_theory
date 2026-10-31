/*
 * afalg_fio_engine.c — Layer 2 fio external ioengine for AF_ALG (synchronous).
 *
 * Wraps the Layer 0 crypto core (alg_core) so fio can drive it with real I/O
 * machinery: numjobs (threads), iodepth, think time, and latency percentiles
 * "for free" (plan RQ4). Each fio job clone gets its own alg_ctx, so socket
 * state never crosses threads.
 *
 * This is a SKELETON, by design (plan, "Ограничения"): fio's internal ABI
 * (struct ioengine_ops, FIO_IOOPS_VERSION, struct io_u) changes between
 * releases. Build it against the fio source tree you intend to run — see the
 * `fio-engine` target in the Makefile and README. Cross-check field names and
 * the queue() return enum against engines/skeleton_external.c in THAT tree.
 *
 * Build: make fio-engine FIO_SRC=/path/to/fio   (-> bin/afalg.so)
 * Use:
 *   fio --ioengine=external:./afalg.so --name=enc --rw=write \
 *       --afalg_alg='cbc(aes)' --afalg_method=sendmsg \
 *       --bs=64k --size=256m --numjobs=4 --iodepth=1
 *
 * Synchronous (FIO_SYNCIO): each io_u completes inside ->queue(), so fio
 * never has more than one I/O in flight per job and --iodepth has no effect.
 * For a real queue depth use the separate async engine, afalg_async.so
 * (afalg_fio_async.c). Options and context setup are shared via
 * afalg_fio_common.{c,h}.
 *
 * Linux only.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afalg_fio_common.h"

/* Per-job runtime state, hung off td->io_ops_data. */
struct afalg_data {
    struct alg_ctx ctx;
    alg_method_t   method;
    unsigned char *outbuf;  /* scratch for crypto output         */
    size_t         outcap;
    int            ready;
};

static int fio_afalg_init(struct thread_data *td) {
    struct afalg_data *d = calloc(1, sizeof(*d));
    if (!d) return 1;
    td->io_ops_data = d;
    return 0;
}

/* Open == set up the AF_ALG socket for this job. */
static int fio_afalg_open(struct thread_data *td, struct fio_file *f) {
    struct afalg_options *o = td->eo;
    struct afalg_data *d = td->io_ops_data;
    (void)f;

    d->method = afalg_fio_method(o);
    if (afalg_fio_ctx_setup(&d->ctx, o, d->method) != 0) {
        td_verror(td, errno ? errno : EINVAL, "alg_setup");
        return 1;
    }
    d->ready = 1;
    return 0;
}

static int fio_afalg_close(struct thread_data *td, struct fio_file *f) {
    struct afalg_data *d = td->io_ops_data;
    (void)f;
    if (d && d->ready) {
        alg_teardown(&d->ctx);
        d->ready = 0;
    }
    return 0;
}

static enum fio_q_status fio_afalg_queue(struct thread_data *td,
                                         struct io_u *io_u) {
    struct afalg_data *d = td->io_ops_data;

    fio_ro_check(td, io_u);

    io_u->error = afalg_fio_do_io(&d->ctx, d->method, io_u, &d->outbuf, &d->outcap);
    return FIO_Q_COMPLETED;
}

static void fio_afalg_cleanup(struct thread_data *td) {
    struct afalg_data *d = td->io_ops_data;
    if (!d) return;
    if (d->ready) alg_teardown(&d->ctx);
    free(d->outbuf);
    free(d);
    td->io_ops_data = NULL;
}

struct ioengine_ops ioengine = {
    .name               = "afalg",
    .version            = FIO_IOOPS_VERSION,
    .init               = fio_afalg_init,
    .queue              = fio_afalg_queue,
    .cleanup            = fio_afalg_cleanup,
    .open_file          = fio_afalg_open,
    .close_file         = fio_afalg_close,
    .flags              = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    .options            = afalg_fio_options,
    .option_struct_size = sizeof(struct afalg_options),
};
