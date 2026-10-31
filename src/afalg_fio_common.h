/*
 * afalg_fio_common.h — pieces shared by the two AF_ALG fio engines:
 *
 *   afalg_fio_engine.c  -> bin/afalg.so        sync  (FIO_SYNCIO, iodepth = 1)
 *   afalg_fio_async.c   -> bin/afalg_async.so  async (real iodepth > 1)
 *
 * Both take the same afalg_* options and set up the AF_ALG context the same
 * way; only how io_us are executed and completed differs. Linux only; built
 * against a fio source tree (see Makefile `fio-engine`).
 */
#ifndef AFALG_FIO_COMMON_H
#define AFALG_FIO_COMMON_H

#include "fio.h"
#include "optgroup.h"

#include "alg_core.h"

/* Per-job engine options. fio requires the first member to be padding. */
struct afalg_options {
    void        *pad;
    char        *alg;       /* cbc(aes) | sha256 | gcm(aes)      */
    char        *type;      /* skcipher | hash | aead            */
    char        *method;    /* sendmsg | splice                  */
    unsigned int keybits;   /* 128 | 192 | 256                   */
};

/* The afalg_* option table (shared by both engines). */
extern struct fio_option afalg_fio_options[];

/* sendmsg or splice, from the afalg_method option. */
alg_method_t afalg_fio_method(const struct afalg_options *o);

/*
 * Bind + key + IV (+ AEAD params) one AF_ALG context from the job options.
 * Unkeyed hashes get no key. Returns 0, or -1 with errno set.
 */
int afalg_fio_ctx_setup(struct alg_ctx *c, const struct afalg_options *o,
                        alg_method_t method);

/*
 * Run one io_u's buffer through `c`. fio DDIR_READ/WRITE map onto
 * decrypt/encrypt; hashes ignore direction. `*out`/`*outcap` is a scratch
 * buffer grown as needed. Returns 0, or an errno value.
 */
int afalg_fio_do_io(struct alg_ctx *c, alg_method_t method, struct io_u *io_u,
                    unsigned char **out, size_t *outcap);

#endif /* AFALG_FIO_COMMON_H */
