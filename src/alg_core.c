/*
 * alg_core.c — AF_ALG crypto core (Layer 0) implementation.
 *
 * Linux only. See alg_core.h for the public contract.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "alg_core.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_alg.h>

/* Older headers may miss some of these; define defensively. */
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

static void perr(const char *what) {
    fprintf(stderr, "alg_core: %s: %s\n", what, strerror(errno));
}

/*
 * Build the AF_ALG control message (cmsg) for one skcipher/aead op: the
 * ALG_SET_OP direction, the IV, and (AEAD only) the associated-data length.
 * `cbuf` must be large enough for all three; caller sizes it with the
 * CMSG_SPACE() helpers below.
 */
static void build_control(struct alg_ctx *c, alg_dir_t dir,
                          struct msghdr *msg, char *cbuf, size_t cbuf_len) {
    memset(cbuf, 0, cbuf_len);
    msg->msg_control = cbuf;
    msg->msg_controllen = cbuf_len;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    /* ALG_SET_OP: encrypt or decrypt */
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) =
        (dir == ALG_DIR_ENCRYPT) ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    /* ALG_SET_IV */
    cmsg = CMSG_NXTHDR(msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + c->ivlen);
    struct af_alg_iv *ivmsg = (struct af_alg_iv *)CMSG_DATA(cmsg);
    ivmsg->ivlen = (uint32_t)c->ivlen;
    memcpy(ivmsg->iv, c->iv, c->ivlen);

    /* ALG_SET_AEAD_ASSOCLEN (AEAD only) */
    if (c->kind == ALG_KIND_AEAD) {
        cmsg = CMSG_NXTHDR(msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
        *(uint32_t *)CMSG_DATA(cmsg) = (uint32_t)c->assoclen;
    }

    /* Trim controllen to what we actually wrote. */
    msg->msg_controllen = cmsg->cmsg_len + ((char *)cmsg - cbuf);
}

/* Control buffer size: op + iv (+ assoclen for AEAD). */
static size_t control_bufsz(const struct alg_ctx *c) {
    size_t sz = CMSG_SPACE(sizeof(uint32_t)) +                        /* op  */
                CMSG_SPACE(sizeof(struct af_alg_iv) + c->ivlen);      /* iv  */
    if (c->kind == ALG_KIND_AEAD)
        sz += CMSG_SPACE(sizeof(uint32_t));                           /* alen */
    return sz;
}

int alg_setup(struct alg_ctx *c,
              const char *type, const char *name,
              const unsigned char *key, size_t keylen,
              alg_method_t method) {
    memset(c, 0, sizeof(*c));
    c->tfmfd = c->opfd = -1;
    c->pipefd[0] = c->pipefd[1] = -1;
    c->page_size = sysconf(_SC_PAGESIZE);
    if (c->page_size <= 0) c->page_size = 4096;
    c->splice_max = (size_t)c->page_size * 16; /* zero-copy ceiling: 16 pages */

    snprintf(c->type, sizeof(c->type), "%s", type);
    snprintf(c->name, sizeof(c->name), "%s", name);
    if (strcmp(type, "hash") == 0)          c->kind = ALG_KIND_HASH;
    else if (strcmp(type, "aead") == 0)     c->kind = ALG_KIND_AEAD;
    else                                    c->kind = ALG_KIND_SKCIPHER;

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "%s", type);
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s", name);

    c->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (c->tfmfd < 0) { perr("socket(AF_ALG)"); goto fail; }

    if (bind(c->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perr("bind");
        fprintf(stderr, "  (is the '%s' algorithm loaded? check /proc/crypto)\n", name);
        goto fail;
    }

    if (key && keylen) {
        if (setsockopt(c->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) < 0) {
            perr("setsockopt(ALG_SET_KEY)");
            goto fail;
        }
    }

    c->opfd = accept(c->tfmfd, NULL, 0);
    if (c->opfd < 0) { perr("accept"); goto fail; }

    if (method == ALG_METHOD_SPLICE) {
        if (pipe(c->pipefd) < 0) { perr("pipe"); goto fail; }
    }
    return 0;

fail:
    alg_teardown(c);
    return -1;
}

int alg_set_iv(struct alg_ctx *c, const unsigned char *iv, size_t len) {
    if (len > ALG_MAX_IV) { errno = EINVAL; return -1; }
    c->ivlen = len;
    memcpy(c->iv, iv, len);
    return 0;
}

int alg_set_aead(struct alg_ctx *c, size_t assoclen, size_t taglen) {
    c->assoclen = assoclen;
    c->taglen = taglen;
    if (setsockopt(c->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, taglen) < 0) {
        perr("setsockopt(ALG_SET_AEAD_AUTHSIZE)");
        return -1;
    }
    return 0;
}

/* Read exactly `len` bytes from opfd into out, looping over short reads. */
static ssize_t read_full(int fd, void *out, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, (char *)out + done, len - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break; /* short digest etc. */
        done += (size_t)r;
    }
    return (ssize_t)done;
}

ssize_t op_sendmsg(struct alg_ctx *c, alg_dir_t dir,
                   const void *in, void *out, size_t len) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    char cbuf[256]; /* holds op+iv(+alen); 256 covers any supported cipher */
    if (c->kind != ALG_KIND_HASH) {
        if (control_bufsz(c) > sizeof(cbuf)) { errno = EINVAL; return -1; }
        build_control(c, dir, &msg, cbuf, control_bufsz(c));
    }

    struct iovec iov;
    iov.iov_base = (void *)in;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(c->opfd, &msg, 0) < 0) { perr("sendmsg"); return -1; }

    size_t want;
    if (c->kind == ALG_KIND_HASH)
        want = c->digestlen;
    else if (c->kind == ALG_KIND_AEAD && dir == ALG_DIR_ENCRYPT)
        want = len + c->taglen;
    else if (c->kind == ALG_KIND_AEAD) /* decrypt strips tag */
        want = (len > c->taglen) ? len - c->taglen : 0;
    else
        want = len;

    ssize_t got = read_full(c->opfd, out, want);
    if (got < 0) perr("read");
    return got;
}

ssize_t op_splice(struct alg_ctx *c, alg_dir_t dir,
                  void *in, void *out, size_t len) {
    if (c->kind == ALG_KIND_AEAD) { errno = ENOTSUP; return -1; }
    if (c->pipefd[1] < 0) { errno = EINVAL; return -1; }

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > c->splice_max) chunk = c->splice_max;

        /* Control first, with MSG_MORE so the kernel waits for the spliced data. */
        if (c->kind != ALG_KIND_HASH) {
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            char cbuf[256];
            build_control(c, dir, &msg, cbuf, control_bufsz(c));
            if (sendmsg(c->opfd, &msg, MSG_MORE) < 0) { perr("sendmsg(MSG_MORE)"); return -1; }
        }

        struct iovec iov;
        iov.iov_base = (char *)in + off;
        iov.iov_len = chunk;
        ssize_t sp = vmsplice(c->pipefd[1], &iov, 1, SPLICE_F_GIFT);
        if (sp < 0) { perr("vmsplice"); return -1; }

        ssize_t mv = splice(c->pipefd[0], NULL, c->opfd, NULL, (size_t)sp, 0);
        if (mv < 0) { perr("splice"); return -1; }

        size_t want = (c->kind == ALG_KIND_HASH) ? c->digestlen : (size_t)mv;
        ssize_t got = read_full(c->opfd, (char *)out + off, want);
        if (got < 0) { perr("read"); return -1; }

        off += chunk;
        if (c->kind == ALG_KIND_HASH) break; /* single digest, whole input */
    }
    return (ssize_t)(c->kind == ALG_KIND_HASH ? c->digestlen : len);
}

void alg_teardown(struct alg_ctx *c) {
    if (!c) return;
    if (c->opfd >= 0) { close(c->opfd); c->opfd = -1; }
    if (c->tfmfd >= 0) { close(c->tfmfd); c->tfmfd = -1; }
    if (c->pipefd[0] >= 0) { close(c->pipefd[0]); c->pipefd[0] = -1; }
    if (c->pipefd[1] >= 0) { close(c->pipefd[1]); c->pipefd[1] = -1; }
}
