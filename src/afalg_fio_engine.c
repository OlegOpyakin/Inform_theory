/*
 * afalg_fio_engine.c — Layer 2 fio external ioengine for AF_ALG.
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
 * Build (out of fio tree):
 *   gcc -Wall -O2 -shared -rdynamic -fPIC \
 *       -o afalg.so afalg_fio_engine.c alg_core.c -I/path/to/fio
 * Use:
 *   fio --ioengine=external:./afalg.so --name=enc --rw=write \
 *       --afalg_alg='cbc(aes)' --afalg_method=sendmsg \
 *       --bs=64k --size=256m --numjobs=4 --iodepth=1
 *
 * Linux only.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../fio.h"
#include "../optgroup.h"

#include "alg_core.h"

/* Per-job engine options. fio requires the first member to be padding. */
struct afalg_options {
    void        *pad;
    char        *alg;       /* cbc(aes) | sha256 | gcm(aes)      */
    char        *type;      /* skcipher | hash | aead            */
    char        *method;    /* sendmsg | splice                  */
    unsigned int keybits;   /* 128 | 192 | 256                   */
};

/* Per-job runtime state, hung off td->io_ops_data. */
struct afalg_data {
    struct alg_ctx ctx;
    alg_method_t   method;
    unsigned char *outbuf;  /* scratch for crypto output         */
    size_t         outcap;
    int            ready;
};

static struct fio_option options[] = {
    {
        .name     = "afalg_alg",
        .lname    = "AF_ALG algorithm",
        .type     = FIO_OPT_STR_STORE,
        .off1     = offsetof(struct afalg_options, alg),
        .def      = "cbc(aes)",
        .help     = "Kernel crypto algorithm name, e.g. cbc(aes), sha256, gcm(aes)",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_INVALID,
    },
    {
        .name     = "afalg_type",
        .lname    = "AF_ALG type",
        .type     = FIO_OPT_STR_STORE,
        .off1     = offsetof(struct afalg_options, type),
        .def      = "skcipher",
        .help     = "AF_ALG socket type: skcipher, hash, or aead",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_INVALID,
    },
    {
        .name     = "afalg_method",
        .lname    = "AF_ALG transfer method",
        .type     = FIO_OPT_STR_STORE,
        .off1     = offsetof(struct afalg_options, method),
        .def      = "sendmsg",
        .help     = "Payload path: sendmsg (copy) or splice (zero-copy, pre-fix)",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_INVALID,
    },
    {
        .name     = "afalg_keybits",
        .lname    = "AF_ALG key bits",
        .type     = FIO_OPT_INT,
        .off1     = offsetof(struct afalg_options, keybits),
        .def      = "128",
        .help     = "Cipher key size in bits (128/192/256)",
        .category = FIO_OPT_C_ENGINE,
        .group    = FIO_OPT_G_INVALID,
    },
    { .name = NULL },
};

static size_t digest_len_for(const char *name) {
    if (strstr(name, "sha512")) return 64;
    if (strstr(name, "sha256")) return 32;
    if (strstr(name, "sha1"))   return 20;
    return 32;
}
static size_t iv_len_for(const char *type, const char *name) {
    if (!strcmp(type, "hash")) return 0;
    if (strstr(name, "gcm")) return 12;
    return 16;
}

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

    d->method = (o->method && !strcmp(o->method, "splice"))
                ? ALG_METHOD_SPLICE : ALG_METHOD_SENDMSG;

    size_t keylen = (size_t)(o->keybits ? o->keybits : 128) / 8;
    unsigned char key[32];
    for (size_t i = 0; i < keylen && i < sizeof key; i++) key[i] = (unsigned char)(i + 1);

    if (alg_setup(&d->ctx, o->type, o->alg, key, keylen, d->method) != 0) {
        td_verror(td, errno ? errno : EINVAL, "alg_setup");
        return 1;
    }
    d->ctx.digestlen = digest_len_for(o->alg);

    size_t ivlen = iv_len_for(o->type, o->alg);
    if (ivlen) {
        unsigned char iv[ALG_MAX_IV];
        for (size_t i = 0; i < ivlen; i++) iv[i] = (unsigned char)(0xA0 + i);
        alg_set_iv(&d->ctx, iv, ivlen);
    }
    if (d->ctx.kind == ALG_KIND_AEAD)
        alg_set_aead(&d->ctx, 0, 16);

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
    size_t len = io_u->xfer_buflen;

    fio_ro_check(td, io_u);

    /* Grow the scratch output buffer if needed (ciphertext/tag/digest). */
    size_t need = len + d->ctx.taglen + ALG_MAX_DIGEST + 64;
    if (need > d->outcap) {
        unsigned char *nb = realloc(d->outbuf, need);
        if (!nb) { io_u->error = ENOMEM; return FIO_Q_COMPLETED; }
        d->outbuf = nb;
        d->outcap = need;
    }

    /* fio DDIR_READ/WRITE map onto decrypt/encrypt; hashes ignore direction. */
    alg_dir_t dir = (io_u->ddir == DDIR_READ) ? ALG_DIR_DECRYPT : ALG_DIR_ENCRYPT;

    ssize_t r;
    if (d->method == ALG_METHOD_SPLICE)
        r = op_splice(&d->ctx, dir, io_u->xfer_buf, d->outbuf, len);
    else
        r = op_sendmsg(&d->ctx, dir, io_u->xfer_buf, d->outbuf, len);

    if (r < 0)
        io_u->error = errno ? errno : EIO;

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
    .flags              = FIO_SYNCIO | FIO_NODISKUTIL,
    .options            = options,
    .option_struct_size = sizeof(struct afalg_options),
};
