/*
 * ref_crypto.c — see ref_crypto.h.
 */
#include "ref_crypto.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

/* "cbc(aes)" + 128 -> "aes-128-cbc"; NULL if not an AES mode we can check. */
static const EVP_CIPHER *cipher_for(const char *alg, int keybits) {
    const char *mode = NULL;
    if      (!strcmp(alg, "cbc(aes)")) mode = "cbc";
    else if (!strcmp(alg, "ctr(aes)")) mode = "ctr";
    else if (!strcmp(alg, "ecb(aes)")) mode = "ecb";
    else if (!strcmp(alg, "gcm(aes)")) mode = "gcm";
    if (!mode) return NULL;
    char name[32];
    snprintf(name, sizeof name, "aes-%d-%s", keybits, mode);
    return EVP_get_cipherbyname(name);
}

static const EVP_MD *md_for(const char *alg) {
    if (!strcmp(alg, "sha1"))   return EVP_sha1();
    if (!strcmp(alg, "sha224")) return EVP_sha224();
    if (!strcmp(alg, "sha256")) return EVP_sha256();
    if (!strcmp(alg, "sha384")) return EVP_sha384();
    if (!strcmp(alg, "sha512")) return EVP_sha512();
    if (!strcmp(alg, "md5"))    return EVP_md5();
    return NULL;
}

long ref_transform(const char *type, const char *alg, int keybits, int encrypt,
                   const unsigned char *key, const unsigned char *iv,
                   const unsigned char *in, size_t len,
                   size_t assoclen, size_t taglen, unsigned char *out) {
    if (!strcmp(type, "hash")) {
        const EVP_MD *md = md_for(alg);
        if (!md) return 0;
        unsigned int dlen = 0;
        if (!EVP_Digest(in, len, out, &dlen, md, NULL)) return -1;
        return (long)dlen;
    }

    int is_aead = !strcmp(type, "aead");
    /* AF_ALG's AAD layout in the output is not modelled here. */
    if (is_aead && assoclen != 0) return 0;
    if (is_aead && !encrypt) {
        if (len < taglen) return -1;
        len -= taglen;                  /* trailing tag is not ciphertext */
    }

    const EVP_CIPHER *ciph = cipher_for(alg, keybits);
    if (!ciph) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    long ret = -1;
    int n = 0, total = 0;
    if (!EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, encrypt)) goto out;
    if (is_aead && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto out;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt)) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!EVP_CipherUpdate(ctx, out, &n, in, (int)len)) goto out;
    total = n;
    if (is_aead && !encrypt &&
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, (void *)(in + len)))
        goto out;
    if (!EVP_CipherFinal_ex(ctx, out + total, &n)) goto out;
    total += n;
    if (is_aead && encrypt) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen, out + total)) goto out;
        total += (int)taglen;
    }
    ret = total;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int ref_compare(const char *who, const unsigned char *got, size_t gotlen,
                const unsigned char *want, size_t wantlen) {
    if (gotlen != wantlen) {
        fprintf(stderr, "%s: verify FAILED: output length %zu, expected %zu\n",
                who, gotlen, wantlen);
        return 0;
    }
    for (size_t i = 0; i < gotlen; i++) {
        if (got[i] != want[i]) {
            fprintf(stderr, "%s: verify FAILED: first mismatch at byte %zu of %zu "
                    "(got %02x, expected %02x)\n", who, i, gotlen, got[i], want[i]);
            return 0;
        }
    }
    return 1;
}
