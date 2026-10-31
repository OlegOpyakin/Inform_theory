/*
 * afalg_fio_common.c — see afalg_fio_common.h.
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "afalg_fio_common.h"

struct fio_option afalg_fio_options[] = {
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
    if (strstr(name, "sha384")) return 48;
    if (strstr(name, "sha256")) return 32;
    if (strstr(name, "sha224")) return 28;
    if (strstr(name, "sha1"))   return 20;
    if (strstr(name, "md5"))    return 16;
    return 32;
}

static size_t iv_len_for(const char *type, const char *name) {
    if (!strcmp(type, "hash")) return 0;
    if (strstr(name, "gcm")) return 12;
    return 16;
}

alg_method_t afalg_fio_method(const struct afalg_options *o) {
    return (o->method && !strcmp(o->method, "splice"))
           ? ALG_METHOD_SPLICE : ALG_METHOD_SENDMSG;
}

int afalg_fio_ctx_setup(struct alg_ctx *c, const struct afalg_options *o,
                        alg_method_t method) {
    size_t keylen = (size_t)(o->keybits ? o->keybits : 128) / 8;
    unsigned char key[32];
    for (size_t i = 0; i < keylen && i < sizeof key; i++) key[i] = (unsigned char)(i + 1);

    /* Unkeyed hashes reject ALG_SET_KEY, so only ciphers and hmac() get a key. */
    int keyed = strcmp(o->type, "hash") != 0 || !strncmp(o->alg, "hmac(", 5);

    if (alg_setup(c, o->type, o->alg, keyed ? key : NULL, keyed ? keylen : 0, method) != 0)
        return -1;
    c->digestlen = digest_len_for(o->alg);

    size_t ivlen = iv_len_for(o->type, o->alg);
    if (ivlen) {
        unsigned char iv[ALG_MAX_IV];
        for (size_t i = 0; i < ivlen; i++) iv[i] = (unsigned char)(0xA0 + i);
        alg_set_iv(c, iv, ivlen);
    }
    if (c->kind == ALG_KIND_AEAD && alg_set_aead(c, 0, 16) != 0) {
        alg_teardown(c);
        return -1;
    }
    return 0;
}

int afalg_fio_do_io(struct alg_ctx *c, alg_method_t method, struct io_u *io_u,
                    unsigned char **out, size_t *outcap) {
    size_t len = io_u->xfer_buflen;

    /* Grow the scratch output buffer if needed (ciphertext/tag/digest). */
    size_t need = len + c->taglen + ALG_MAX_DIGEST + 64;
    if (need > *outcap) {
        unsigned char *nb = realloc(*out, need);
        if (!nb) return ENOMEM;
        *out = nb;
        *outcap = need;
    }

    alg_dir_t dir = (io_u->ddir == DDIR_READ) ? ALG_DIR_DECRYPT : ALG_DIR_ENCRYPT;

    ssize_t r;
    errno = 0;
    if (method == ALG_METHOD_SPLICE)
        r = op_splice(c, dir, io_u->xfer_buf, *out, len);
    else
        r = op_sendmsg(c, dir, io_u->xfer_buf, *out, len);

    return (r < 0) ? (errno ? errno : EIO) : 0;
}
