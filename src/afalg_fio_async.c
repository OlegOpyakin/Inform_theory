/*
 * afalg_fio_async.c — Layer 2 fio external ioengine for AF_ALG (asynchronous).
 *
 * The sync engine (afalg_fio_engine.c, FIO_SYNCIO) completes every io_u inside
 * ->queue(), so --iodepth is effectively 1 and "qd8" measures the same thing
 * as "qd1". This engine gives --iodepth a real meaning: each fio job owns a
 * pool of `iodepth` worker threads, each with its OWN AF_ALG op socket (and
 * pipe for splice). ->queue() hands the io_u to the pool and returns
 * FIO_Q_QUEUED; ->getevents()/->event() reap completions. Up to iodepth crypto
 * ops per job are therefore in flight concurrently, and fio's completion
 * latency includes the queueing delay — like a real async block device.
 *
 * Why threads and not kernel AIO on the op socket: AF_ALG AIO shares one IV
 * and one TX queue per socket, so in-flight ops would clobber each other, and
 * with synchronous tfms (AES-NI) the cipher runs in the submitter's context
 * anyway. One socket per slot keeps every op independent and identical to the
 * sync engine's op, so sync qd1 and async qdN rows are directly comparable.
 *
 * Kept separate from the sync engine on purpose: select it by loading
 * bin/afalg_async.so instead of bin/afalg.so. Same afalg_* options.
 *
 *   fio --ioengine=external:./bin/afalg_async.so --name=enc --rw=write \
 *       --afalg_alg='cbc(aes)' --afalg_method=sendmsg \
 *       --bs=64k --size=256m --numjobs=1 --iodepth=8
 *
 * Linux only. Build: make fio-engine FIO_SRC=/path/to/fio
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "afalg_fio_common.h"

struct afalg_async;

/* One in-flight slot: a worker thread with its own AF_ALG context. */
struct afalg_slot {
    struct afalg_async *a;
    pthread_t           tid;
    struct alg_ctx      ctx;
    unsigned char      *outbuf;
    size_t              outcap;
    int                 ctx_ready;
    int                 thread_ready;
};

/* Fixed-capacity FIFO of io_u pointers. */
struct ioq {
    struct io_u **v;
    unsigned      cap, head, n;
};

/* Per-job runtime state, hung off td->io_ops_data. */
struct afalg_async {
    alg_method_t      method;
    unsigned          depth;

    pthread_mutex_t   lock;
    pthread_cond_t    work_cv;   /* submitted work available / stop */
    pthread_cond_t    done_cv;   /* a completion was posted         */
    struct ioq        subq;      /* queued, not yet picked up       */
    struct ioq        doneq;     /* completed, not yet reaped       */
    struct io_u     **events;    /* last getevents() batch          */
    int               stop;

    struct afalg_slot *slots;
    int               running;
};

static int ioq_init(struct ioq *q, unsigned cap) {
    q->v = calloc(cap, sizeof(*q->v));
    q->cap = cap; q->head = 0; q->n = 0;
    return q->v ? 0 : -1;
}

static void ioq_push(struct ioq *q, struct io_u *io_u) {
    q->v[(q->head + q->n) % q->cap] = io_u;
    q->n++;
}

static struct io_u *ioq_pop(struct ioq *q) {
    struct io_u *io_u = q->v[q->head];
    q->head = (q->head + 1) % q->cap;
    q->n--;
    return io_u;
}

static void *slot_main(void *arg) {
    struct afalg_slot *s = arg;
    struct afalg_async *a = s->a;

    for (;;) {
        pthread_mutex_lock(&a->lock);
        while (!a->stop && a->subq.n == 0)
            pthread_cond_wait(&a->work_cv, &a->lock);
        if (a->subq.n == 0) {           /* stop requested and nothing left */
            pthread_mutex_unlock(&a->lock);
            break;
        }
        struct io_u *io_u = ioq_pop(&a->subq);
        pthread_mutex_unlock(&a->lock);

        io_u->error = afalg_fio_do_io(&s->ctx, a->method, io_u, &s->outbuf, &s->outcap);

        pthread_mutex_lock(&a->lock);
        ioq_push(&a->doneq, io_u);
        pthread_cond_signal(&a->done_cv);
        pthread_mutex_unlock(&a->lock);
    }
    return NULL;
}

/* Stop and join the workers, close their sockets. Idempotent. */
static void pool_stop(struct afalg_async *a) {
    if (!a->slots) return;
    pthread_mutex_lock(&a->lock);
    a->stop = 1;
    pthread_cond_broadcast(&a->work_cv);
    pthread_mutex_unlock(&a->lock);

    for (unsigned i = 0; i < a->depth; i++) {
        struct afalg_slot *s = &a->slots[i];
        if (s->thread_ready) pthread_join(s->tid, NULL);
        if (s->ctx_ready) alg_teardown(&s->ctx);
        free(s->outbuf);
    }
    free(a->slots);
    a->slots = NULL;
    a->running = 0;
}

static int fio_afalg_async_init(struct thread_data *td) {
    struct afalg_async *a = calloc(1, sizeof(*a));
    if (!a) return 1;
    a->depth = td->o.iodepth ? td->o.iodepth : 1;
    if (ioq_init(&a->subq, a->depth) || ioq_init(&a->doneq, a->depth) ||
        !(a->events = calloc(a->depth, sizeof(*a->events)))) {
        free(a->subq.v); free(a->doneq.v); free(a->events); free(a);
        return 1;
    }
    pthread_mutex_init(&a->lock, NULL);
    pthread_cond_init(&a->work_cv, NULL);
    pthread_cond_init(&a->done_cv, NULL);
    td->io_ops_data = a;
    return 0;
}

/* Open == set up `iodepth` AF_ALG sockets and start their workers. */
static int fio_afalg_async_open(struct thread_data *td, struct fio_file *f) {
    struct afalg_options *o = td->eo;
    struct afalg_async *a = td->io_ops_data;
    (void)f;

    if (a->running) return 0;
    a->method = afalg_fio_method(o);
    a->stop = 0;
    a->slots = calloc(a->depth, sizeof(*a->slots));
    if (!a->slots) { td_verror(td, ENOMEM, "calloc"); return 1; }

    for (unsigned i = 0; i < a->depth; i++) {
        struct afalg_slot *s = &a->slots[i];
        s->a = a;
        if (afalg_fio_ctx_setup(&s->ctx, o, a->method) != 0) {
            td_verror(td, errno ? errno : EINVAL, "alg_setup");
            pool_stop(a);
            return 1;
        }
        s->ctx_ready = 1;
        int rc = pthread_create(&s->tid, NULL, slot_main, s);
        if (rc != 0) {
            td_verror(td, rc, "pthread_create");
            pool_stop(a);
            return 1;
        }
        s->thread_ready = 1;
    }
    a->running = 1;
    return 0;
}

static int fio_afalg_async_close(struct thread_data *td, struct fio_file *f) {
    (void)f;
    pool_stop(td->io_ops_data);
    return 0;
}

static enum fio_q_status fio_afalg_async_queue(struct thread_data *td,
                                               struct io_u *io_u) {
    struct afalg_async *a = td->io_ops_data;

    fio_ro_check(td, io_u);

    pthread_mutex_lock(&a->lock);
    if (a->subq.n == a->subq.cap) {
        pthread_mutex_unlock(&a->lock);
        return FIO_Q_BUSY;
    }
    ioq_push(&a->subq, io_u);
    pthread_cond_signal(&a->work_cv);
    pthread_mutex_unlock(&a->lock);
    return FIO_Q_QUEUED;
}

/* Work is dispatched as soon as it is queued; nothing to batch. */
static int fio_afalg_async_commit(struct thread_data *td) {
    (void)td;
    return 0;
}

static int fio_afalg_async_getevents(struct thread_data *td, unsigned int min,
                                     unsigned int max, const struct timespec *t) {
    struct afalg_async *a = td->io_ops_data;
    struct timespec deadline;

    if (t) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec  += t->tv_sec;
        deadline.tv_nsec += t->tv_nsec;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }

    pthread_mutex_lock(&a->lock);
    while (a->doneq.n < min) {
        if (t) {
            if (pthread_cond_timedwait(&a->done_cv, &a->lock, &deadline) == ETIMEDOUT)
                break;
        } else {
            pthread_cond_wait(&a->done_cv, &a->lock);
        }
    }
    unsigned n = 0;
    while (a->doneq.n > 0 && n < max && n < a->depth)
        a->events[n++] = ioq_pop(&a->doneq);
    pthread_mutex_unlock(&a->lock);
    return (int)n;
}

static struct io_u *fio_afalg_async_event(struct thread_data *td, int event) {
    struct afalg_async *a = td->io_ops_data;
    return a->events[event];
}

static void fio_afalg_async_cleanup(struct thread_data *td) {
    struct afalg_async *a = td->io_ops_data;
    if (!a) return;
    pool_stop(a);
    pthread_cond_destroy(&a->done_cv);
    pthread_cond_destroy(&a->work_cv);
    pthread_mutex_destroy(&a->lock);
    free(a->subq.v);
    free(a->doneq.v);
    free(a->events);
    free(a);
    td->io_ops_data = NULL;
}

struct ioengine_ops ioengine = {
    .name               = "afalg_async",
    .version            = FIO_IOOPS_VERSION,
    .init               = fio_afalg_async_init,
    .queue              = fio_afalg_async_queue,
    .commit             = fio_afalg_async_commit,
    .getevents          = fio_afalg_async_getevents,
    .event              = fio_afalg_async_event,
    .cleanup            = fio_afalg_async_cleanup,
    .open_file          = fio_afalg_async_open,
    .close_file         = fio_afalg_async_close,
    .flags              = FIO_DISKLESSIO | FIO_NODISKUTIL,
    .options            = afalg_fio_options,
    .option_struct_size = sizeof(struct afalg_options),
};
