/*
 * alg_core.h — AF_ALG crypto core (Layer 0).
 *
 * Shared between the standalone harness (afalg_bench) and the fio external
 * ioengine (afalg_fio_engine), so the kernel-facing logic is written once.
 * See afalg-always-slower-plan.md, section "Архитектура и структура кода".
 *
 * Linux only: AF_ALG lives in the kernel crypto subsystem and is not available
 * on other platforms. Build with gcc/clang on a Linux host.
 */
#ifndef ALG_CORE_H
#define ALG_CORE_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Which kind of transform the socket is bound to. */
typedef enum {
    ALG_KIND_SKCIPHER = 0, /* e.g. cbc(aes)            */
    ALG_KIND_HASH,         /* e.g. sha256              */
    ALG_KIND_AEAD          /* e.g. gcm(aes) — experimental */
} alg_kind_t;

/* How userspace hands the payload to the kernel. */
typedef enum {
    ALG_METHOD_SENDMSG = 0, /* copy path: sendmsg()/read()                    */
    ALG_METHOD_SPLICE       /* zero-copy path: vmsplice()+splice() (pre-fix)  */
} alg_method_t;

/* Operation direction (ignored for hashes). */
typedef enum {
    ALG_DIR_ENCRYPT = 0,
    ALG_DIR_DECRYPT
} alg_dir_t;

#define ALG_MAX_IV   64   /* generous upper bound for any supported cipher IV  */
#define ALG_MAX_DIGEST 64 /* sha512 digest size, upper bound for hashes        */

/*
 * One bound-and-accepted AF_ALG context. Create with alg_setup(), drive with
 * op_sendmsg()/op_splice(), destroy with alg_teardown(). Not thread-safe: give
 * each thread its own ctx (each with its own opfd and pipe).
 */
struct alg_ctx {
    int        tfmfd;      /* transform (bind) socket                          */
    int        opfd;       /* operation socket from accept()                   */
    int        pipefd[2];  /* pipe used by the splice path; {-1,-1} otherwise  */
    alg_kind_t kind;
    char       type[16];   /* "skcipher" / "hash" / "aead"                     */
    char       name[64];   /* "cbc(aes)" / "sha256" / "gcm(aes)"               */

    size_t        ivlen;               /* cipher/AEAD IV length (0 for hash)    */
    unsigned char iv[ALG_MAX_IV];      /* IV template, reused each op           */

    size_t assoclen;   /* AEAD associated-data length (0 otherwise)            */
    size_t taglen;     /* AEAD auth tag length (0 otherwise)                   */

    size_t digestlen;  /* hash output size (0 for ciphers)                     */

    long   page_size;      /* cached sysconf(_SC_PAGESIZE)                     */
    size_t splice_max;     /* max bytes per zero-copy op (16 pages, ~64 KiB)  */
};

/*
 * Bind an AF_ALG socket to (type, name), optionally set a key, and accept an
 * operation fd. For ALG_METHOD_SPLICE a pipe is created as well.
 *
 * key may be NULL (hashes take no key). For AEAD, set aead_taglen before/after
 * via alg_set_aead(); call it before the first op.
 *
 * Returns 0 on success, -1 on failure (errno set, human message on stderr).
 */
int alg_setup(struct alg_ctx *c,
              const char *type, const char *name,
              const unsigned char *key, size_t keylen,
              alg_method_t method);

/* Set the IV template reused by every subsequent op. len must be <= ALG_MAX_IV. */
int alg_set_iv(struct alg_ctx *c, const unsigned char *iv, size_t len);

/* Configure AEAD parameters (assoclen may be 0). Must be called before op_*. */
int alg_set_aead(struct alg_ctx *c, size_t assoclen, size_t taglen);

/*
 * Run one operation over the copy path (sendmsg + read).
 *
 *  - skcipher/aead: encrypt/decrypt `len` bytes of `in` into `out`.
 *  - hash:          absorb `len` bytes of `in`, write digest to `out`
 *                   (out must hold at least c->digestlen bytes); `dir` ignored.
 *
 * For AEAD encrypt, `out` must have room for len + taglen bytes.
 * Returns bytes read back on success, -1 on error.
 */
ssize_t op_sendmsg(struct alg_ctx *c, alg_dir_t dir,
                   const void *in, void *out, size_t len);

/*
 * Run one operation over the zero-copy path (vmsplice + splice). Payloads
 * larger than c->splice_max are processed in page-sized chunks as independent
 * operations — correct for throughput timing, NOT a single valid ciphertext
 * under CBC chaining (see plan, "Ограничения").
 *
 * `in` is non-const because SPLICE_F_GIFT donates the pages to the kernel; the
 * caller must not touch the buffer until the op returns. Not supported for AEAD.
 * Returns total bytes read back on success, -1 on error.
 */
ssize_t op_splice(struct alg_ctx *c, alg_dir_t dir,
                  void *in, void *out, size_t len);

/* Close all fds. Safe to call on a zeroed/partially-initialised ctx. */
void alg_teardown(struct alg_ctx *c);

#ifdef __cplusplus
}
#endif

#endif /* ALG_CORE_H */
