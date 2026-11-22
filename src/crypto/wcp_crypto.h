#ifndef P0916_WCP_CRYPTO_H
#define P0916_WCP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define WCP_SHA1_LEN 20u
#define WCP_SHA512_LEN 64u
#define WCP_KEY_LEN 32u
#define WCP_TAG_LEN 16u
#define WCP_NONCE8_LEN 8u
#define WCP_X25519_LEN 32u
#define WCP_ED25519_PK_LEN 32u
#define WCP_ED25519_SK_LEN 32u
#define WCP_ED25519_SIG_LEN 64u
#define WCP_SRP_PRIME_LEN 384u
#define WCP_SRP_SALT_LEN 16u
#define WCP_SRP_PROOF_LEN 64u

void wcp_zero_mem(volatile void *ptr, size_t len);
int wcp_ct_equal(const void *a, const void *b, size_t len);
void wcp_u64_to_dec(uint64_t value, char *buf, size_t capacity);

/* Cryptographic hashing & KDF */
void wcp_sha1(const uint8_t *data, size_t len, uint8_t out[WCP_SHA1_LEN]);
void wcp_sha512(const uint8_t *data, size_t len, uint8_t out[WCP_SHA512_LEN]);
void wcp_sha512_v(const uint8_t *const *parts, const size_t *lens, size_t count,
                  uint8_t out[WCP_SHA512_LEN]);
void wcp_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[WCP_SHA512_LEN]);
int wcp_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len);

/* RFC 7539 / RFC 8439 ChaCha20-Poly1305 with 12-byte nonce = {0,0,0,0} || nonce8[0..7] */
void wcp_chacha20_poly1305_encrypt_nonce8(const uint8_t key[WCP_KEY_LEN],
                                          const uint8_t nonce8[WCP_NONCE8_LEN],
                                          const void *aad, size_t aad_len,
                                          const void *plain, size_t len,
                                          void *cipher, uint8_t tag[WCP_TAG_LEN]);
int wcp_chacha20_poly1305_decrypt_nonce8(const uint8_t key[WCP_KEY_LEN],
                                         const uint8_t nonce8[WCP_NONCE8_LEN],
                                         const void *aad, size_t aad_len,
                                         const void *cipher, size_t len,
                                         const uint8_t tag[WCP_TAG_LEN],
                                         void *plain);

/* Curve25519 (RFC 7748 X25519) */
void wcp_x25519(uint8_t out[WCP_X25519_LEN],
                const uint8_t scalar[WCP_X25519_LEN],
                const uint8_t point[WCP_X25519_LEN]);
void wcp_x25519_base(uint8_t out[WCP_X25519_LEN],
                     const uint8_t scalar[WCP_X25519_LEN]);

/* Ed25519 (RFC 8032 pure Ed25519 / TweetNaCl compatible 32-byte seed sk -> 32-byte pk) */
void wcp_ed25519_publickey(uint8_t pk[WCP_ED25519_PK_LEN],
                           const uint8_t sk[WCP_ED25519_SK_LEN]);
void wcp_ed25519_sign(uint8_t sig[WCP_ED25519_SIG_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sk[WCP_ED25519_SK_LEN],
                      const uint8_t pk[WCP_ED25519_PK_LEN]);
int wcp_ed25519_verify(const uint8_t sig[WCP_ED25519_SIG_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t pk[WCP_ED25519_PK_LEN]);

/* Apple HAP SRP-6a 3072-bit / SHA-512 matching HomeKitADK HAPMbedTLS.c */
void wcp_srp_server_start(const uint8_t salt[WCP_SRP_SALT_LEN],
                          const uint8_t priv_b[32],
                          const uint8_t *user, size_t user_len,
                          const uint8_t *pass, size_t pass_len,
                          uint8_t verifier_out[WCP_SRP_PRIME_LEN],
                          uint8_t pub_b_out[WCP_SRP_PRIME_LEN]);

int wcp_srp_server_finish(const uint8_t salt[WCP_SRP_SALT_LEN],
                          const uint8_t *user, size_t user_len,
                          const uint8_t priv_b[32],
                          const uint8_t verifier[WCP_SRP_PRIME_LEN],
                          const uint8_t pub_a[WCP_SRP_PRIME_LEN],
                          const uint8_t pub_b[WCP_SRP_PRIME_LEN],
                          const uint8_t client_m1[WCP_SRP_PROOF_LEN],
                          uint8_t session_key_out[WCP_SRP_PROOF_LEN],
                          uint8_t server_m2_out[WCP_SRP_PROOF_LEN]);

#endif /* P0916_WCP_CRYPTO_H */
