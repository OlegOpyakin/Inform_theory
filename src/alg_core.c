/*
 * alg_core.c — AF_ALG crypto core (Layer 0) implementation.
 *
 * Linux only. See alg_core.h for the public contract.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
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
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 4
#endif

/* Send/receive buffer asked for on each op socket (covers 16 MiB payloads). */
#define ALG_SOCKBUF_WANT (32 * 1024 * 1024)

/* Print "alg_core: what: strerror(errno)", leaving errno intact for callers. */
static void perr(const char *what) {
    int e = errno;
    fprintf(stderr, "alg_core: %s: %s\n", what, strerror(e));
    if (e == ENOMEM) {
        static int hinted;
        if (!hinted++)
            fprintf(stderr, "alg_core: hint: AF_ALG scatterlists are charged to "
                    "net.core.optmem_max (per network namespace); large payloads "
                    "need e.g. sysctl -w net.core.optmem_max=1048576\n");
    }
    errno = e;
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

/*
 * Ask for a socket buffer of ALG_SOCKBUF_WANT; the kernel silently caps it at
 * net.core.{w,r}mem_max, so check what we got and warn once per buffer kind.
 */
static int size_sockbuf(int fd, int opt, const char *name, const char *sysctl,
                        const char *symptom, int *warned) {
    int want = ALG_SOCKBUF_WANT, got = 0;
    socklen_t gl = sizeof(got);
    if (setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want)) < 0)
        perr(name);
    if (getsockopt(fd, SOL_SOCKET, opt, &got, &gl) < 0) return 0;
    if (got < want && !(*warned)++)
        fprintf(stderr, "alg_core: warning: %s capped at %d bytes (wanted %d); "
                "payloads above ~%d KiB %s. Raise it: sysctl -w %s=67108864\n",
                name, got, want, got / 2048, symptom, sysctl);
    return got;
}

/*
 * accept() the operation socket and size its buffers:
 *  - SO_SNDBUF: a sendmsg/splice larger than it deadlocks in
 *    af_alg_wait_for_wmem, because the reader runs only after sendmsg returns.
 *  - SO_RCVBUF: the kernel builds at most this much output per internal
 *    pass of recvmsg. skcipher copes (IV chained across passes), but AEAD
 *    silently becomes several separate operations inside ONE read() — full
 *    length, wrong ciphertext — so op_sendmsg refuses AEAD messages that do
 *    not fit (see c->rcvbuf).
 */
static int open_opfd(struct alg_ctx *c) {
    static int warned_snd, warned_rcv;
    c->opfd = accept(c->tfmfd, NULL, 0);
    if (c->opfd < 0) { perr("accept"); return -1; }
    size_sockbuf(c->opfd, SO_SNDBUF, "SO_SNDBUF", "net.core.wmem_max",
                 "may hang", &warned_snd);
    c->rcvbuf = size_sockbuf(c->opfd, SO_RCVBUF, "SO_RCVBUF", "net.core.rmem_max",
                             "fail for AEAD", &warned_rcv);
    return 0;
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

    if (open_opfd(c) < 0) goto fail;

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
    /* The kernel only accepts AUTHSIZE while the transform has no operation
     * socket (EBUSY otherwise), so drop the one alg_setup() opened, set the
     * tag size, and accept a fresh one. */
    if (c->opfd >= 0) { close(c->opfd); c->opfd = -1; }
    if (setsockopt(c->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, taglen) < 0) {
        perr("setsockopt(ALG_SET_AEAD_AUTHSIZE)");
        return -1;
    }
    return open_opfd(c);
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

    /* An AEAD message larger than the receive buffer is silently processed by
     * the kernel as several independent operations within one read() (full
     * length returned, wrong ciphertext/tag). Undetectable afterwards, so
     * refuse up front; one page of slack for the kernel's accounting. */
    if (c->kind == ALG_KIND_AEAD && c->rcvbuf > 0 &&
        len + c->taglen + (size_t)c->page_size > (size_t)c->rcvbuf) {
        fprintf(stderr, "alg_core: AEAD message of %zu bytes exceeds SO_RCVBUF (%d); "
                "raise net.core.rmem_max\n", len, c->rcvbuf);
        errno = EMSGSIZE;
        return -1;
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

/* Cipher block size for chunking: non-final chunks must be whole blocks. */
#define ALG_CHUNK_ALIGN 16

/*
 * Where the splice path takes its payload from: a user buffer (vmsplice'd
 * into the pipe) or a file (spliced from its page cache into the pipe).
 */
struct splice_src {
    char    *buf;       /* user buffer, or NULL for a file source  */
    int      fd;        /* file source                             */
    off64_t *off;       /* in/out file offset                      */
};

/*
 * Bytes for the next chunk starting at `pos`. The pipe holds 16 page buffers
 * (splice_max), and a buffer that does not start on a page boundary spans one
 * extra page — so cap the chunk at the pages left from its starting offset,
 * otherwise vmsplice comes back short and the op fails (unaligned >= 64 KiB).
 * Non-final skcipher chunks are rounded down to whole blocks so the kernel can
 * process them while MSG_MORE is still set.
 */
static size_t next_chunk(const struct alg_ctx *c, const struct splice_src *s,
                         size_t pos, size_t len) {
    size_t pgoff = s->buf ? (size_t)((uintptr_t)(s->buf + pos) % (uintptr_t)c->page_size)
                          : (size_t)(*s->off % c->page_size);
    size_t chunk = c->splice_max - pgoff;
    if (chunk >= len - pos) return len - pos;
    if (c->kind != ALG_KIND_HASH) chunk -= chunk % ALG_CHUNK_ALIGN;
    return chunk;
}

/* Put exactly `chunk` bytes of the source into the pipe. */
static int fill_pipe(struct alg_ctx *c, const struct splice_src *s,
                     size_t pos, size_t chunk) {
    size_t done = 0;
    while (done < chunk) {
        ssize_t sp;
        if (s->buf) {
            struct iovec iov = { .iov_base = s->buf + pos + done,
                                 .iov_len  = chunk - done };
            sp = vmsplice(c->pipefd[1], &iov, 1, SPLICE_F_GIFT);
            if (sp < 0) { perr("vmsplice"); return -1; }
        } else {
            sp = splice(s->fd, s->off, c->pipefd[1], NULL, chunk - done, 0);
            if (sp < 0) { perr("splice(file->pipe)"); return -1; }
        }
        if (sp == 0) { errno = EIO; perr("splice: short source"); return -1; }
        done += (size_t)sp;
    }
    return 0;
}

/*
 * One logical operation streamed over the splice path: a single control
 * message (op + IV) with MSG_MORE, then each chunk spliced pipe -> opfd with
 * SPLICE_F_MORE on all but the last. The kernel keeps the IV chained across
 * chunks (ctx->iv), so the output is one valid ciphertext / one digest of the
 * whole input, while every chunk still goes through the zero-copy splice.
 */
static ssize_t splice_stream(struct alg_ctx *c, alg_dir_t dir,
                             const struct splice_src *s, void *out, size_t len) {
    if (c->kind == ALG_KIND_AEAD) { errno = ENOTSUP; return -1; }
    if (c->pipefd[1] < 0) { errno = EINVAL; return -1; }

    if (c->kind != ALG_KIND_HASH) {
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        char cbuf[256];
        build_control(c, dir, &msg, cbuf, control_bufsz(c));
        if (sendmsg(c->opfd, &msg, MSG_MORE) < 0) { perr("sendmsg(MSG_MORE)"); return -1; }
    }

    size_t pos = 0;
    while (pos < len) {
        size_t chunk = next_chunk(c, s, pos, len);
        int last = (pos + chunk == len);

        if (fill_pipe(c, s, pos, chunk) < 0) return -1;

        /* pipe -> opfd: zero-copy on pre-fix kernels, copied on post-fix. */
        size_t moved = 0;
        while (moved < chunk) {
            unsigned int fl = last ? 0 : SPLICE_F_MORE;
            ssize_t mv = splice(c->pipefd[0], NULL, c->opfd, NULL, chunk - moved, fl);
            if (mv < 0) { perr("splice(pipe->opfd)"); return -1; }
            if (mv == 0) { errno = EIO; perr("splice(pipe->opfd): no progress"); return -1; }
            moved += (size_t)mv;
        }

        if (c->kind != ALG_KIND_HASH) {
            ssize_t got = read_full(c->opfd, (char *)out + pos, chunk);
            if (got < 0) { perr("read"); return -1; }
            if ((size_t)got != chunk) { errno = EIO; perr("read: short ciphertext"); return -1; }
        }
        pos += chunk;
    }

    if (c->kind == ALG_KIND_HASH) {
        ssize_t got = read_full(c->opfd, out, c->digestlen);
        if (got < 0) { perr("read"); return -1; }
        return got;
    }
    return (ssize_t)len;
}

ssize_t op_splice(struct alg_ctx *c, alg_dir_t dir,
                  void *in, void *out, size_t len) {
    struct splice_src s = { .buf = in, .fd = -1, .off = NULL };
    return splice_stream(c, dir, &s, out, len);
}

/*
 * op_splice_file — true zero-copy: splice directly from a file's page cache
 * into the AF_ALG op socket. This is the path targeted by the zero-copy
 * removal (ffdd2bc3, May 2026): on pre-fix kernels pages are pinned into the
 * crypto scatterlist without memcpy; on post-fix they are copied internally.
 *
 * `file_off` is in/out: starting offset on entry, advanced by bytes consumed.
 * Reset to 0 before each iteration to re-encrypt the same file content.
 */
ssize_t op_splice_file(struct alg_ctx *c, alg_dir_t dir,
                       int file_fd, off64_t *file_off,
                       void *out, size_t len) {
    struct splice_src s = { .buf = NULL, .fd = file_fd, .off = file_off };
    return splice_stream(c, dir, &s, out, len);
}

void alg_teardown(struct alg_ctx *c) {
    if (!c) return;
    if (c->opfd >= 0) { close(c->opfd); c->opfd = -1; }
    if (c->tfmfd >= 0) { close(c->tfmfd); c->tfmfd = -1; }
    if (c->pipefd[0] >= 0) { close(c->pipefd[0]); c->pipefd[0] = -1; }
    if (c->pipefd[1] >= 0) { close(c->pipefd[1]); c->pipefd[1] = -1; }
}
