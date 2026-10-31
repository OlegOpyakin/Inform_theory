/*
 * ref_crypto.h — one-shot OpenSSL reference transform for --verify.
 *
 * Both benches time a transform in a hot loop but never looked at its output.
 * With --verify, each worker runs its timed path once before the loop and
 * compares the result against this independent, one-shot EVP implementation
 * (same key / IV / plaintext patterns in both benches). Outside the timed
 * region, so it does not perturb measurements.
 *
 * Portable (OpenSSL only).
 */
#ifndef REF_CRYPTO_H
#define REF_CRYPTO_H

#include <stddef.h>

/*
 * Compute the expected output of (type, alg) over `in[0..len)` into `out`.
 *  - skcipher: AES-{cbc,ctr,ecb}, no padding; out = len bytes.
 *  - hash:     sha1/224/256/384/512, md5; out = digest.
 *  - aead:     gcm(aes) with no AAD. Encrypt: out = ciphertext || tag.
 *              Decrypt: `in` is ciphertext || tag (len includes the tag),
 *              out = plaintext; -1 if the tag does not authenticate.
 * Returns the output length, 0 if this combination cannot be checked (caller
 * reports "skipped"), or -1 on an OpenSSL error.
 */
long ref_transform(const char *type, const char *alg, int keybits, int encrypt,
                   const unsigned char *key, const unsigned char *iv,
                   const unsigned char *in, size_t len,
                   size_t assoclen, size_t taglen, unsigned char *out);

/*
 * Compare `got` against `want`; on mismatch print the first differing offset
 * to stderr, prefixed by `who`. Returns 1 if equal, 0 otherwise.
 */
int ref_compare(const char *who, const unsigned char *got, size_t gotlen,
                const unsigned char *want, size_t wantlen);

#endif /* REF_CRYPTO_H */
