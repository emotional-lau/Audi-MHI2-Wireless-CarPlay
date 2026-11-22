#include "wcp_crypto.h"
#include "qnx65_abi.h"

/* ---------------- Helpers (alignment-safe, zero 64-bit div) ---------------- */

void wcp_zero_mem(volatile void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; ++i)
        p[i] = 0u;
}

int wcp_ct_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0u;
    for (size_t i = 0; i < len; ++i)
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    return diff == 0u;
}

void wcp_u64_to_dec(uint64_t value, char *buf, size_t capacity)
{
    if (!buf || capacity == 0)
        return;
    if (value == 0) {
        if (capacity >= 2u) {
            buf[0] = '0';
            buf[1] = '\0';
        } else {
            buf[0] = '\0';
        }
        return;
    }
    char rev[24];
    size_t n = 0;
    while (value != 0 && n < sizeof(rev)) {
        /* Exact divmod by 10 without __aeabi_uldivmod (shift-and-subtract) */
        uint64_t q = 0u;
        uint32_t rem = 0u;
        for (int bit = 63; bit >= 0; --bit) {
            rem = (rem << 1) | (uint32_t)((value >> bit) & 1u);
            if (rem >= 10u) {
                rem -= 10u;
                q |= (UINT64_C(1) << bit);
            }
        }
        rev[n++] = (char)('0' + rem);
        value = q;
    }
    size_t out_n = n < capacity - 1u ? n : capacity - 1u;
    for (size_t i = 0; i < out_n; ++i)
        buf[i] = rev[n - 1u - i];
    buf[out_n] = '\0';
}

static inline uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

static inline uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64u - n));
}

static inline uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static inline uint64_t load_be64(const uint8_t *p)
{
    return ((uint64_t)load_be32(p) << 32) | (uint64_t)load_be32(p + 4);
}

static inline void store_be64(uint8_t *p, uint64_t v)
{
    store_be32(p, (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)(v & 0xffffffffu));
}

static inline void store_le64(uint8_t *p, uint64_t v)
{
    store_le32(p, (uint32_t)(v & 0xffffffffu));
    store_le32(p + 4, (uint32_t)(v >> 32));
}

/* ---------------- SHA-1 ---------------- */

struct wcp_sha1_ctx {
    uint32_t state[5];
    uint64_t total;
    uint8_t buf[64];
    size_t used;
};

static void sha1_block(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = load_be32(block + (size_t)i * 4u);
    for (int i = 16; i < 80; ++i)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1u);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t t = rotl32(a, 5u) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30u);
        b = a;
        a = t;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    wcp_zero_mem(w, sizeof(w));
}

void wcp_sha1(const uint8_t *data, size_t len, uint8_t out[WCP_SHA1_LEN])
{
    struct wcp_sha1_ctx ctx;
    ctx.state[0] = 0x67452301u;
    ctx.state[1] = 0xefcdab89u;
    ctx.state[2] = 0x98badcfeu;
    ctx.state[3] = 0x10325476u;
    ctx.state[4] = 0xc3d2e1f0u;
    ctx.total = (uint64_t)len;
    ctx.used = 0u;

    size_t off = 0u;
    while (off + 64u <= len) {
        sha1_block(ctx.state, data + off);
        off += 64u;
    }
    size_t rem = len - off;
    if (rem > 0u)
        memcpy(ctx.buf, data + off, rem);
    ctx.buf[rem++] = 0x80u;
    if (rem > 56u) {
        memset(ctx.buf + rem, 0, 64u - rem);
        sha1_block(ctx.state, ctx.buf);
        rem = 0u;
    }
    memset(ctx.buf + rem, 0, 56u - rem);
    store_be64(ctx.buf + 56u, ctx.total * 8u);
    sha1_block(ctx.state, ctx.buf);
    for (int i = 0; i < 5; ++i)
        store_be32(out + (size_t)i * 4u, ctx.state[i]);
    wcp_zero_mem(&ctx, sizeof(ctx));
}

/* ---------------- SHA-512 ---------------- */

static const uint64_t K512[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

typedef struct {
    uint64_t state[8];
    uint64_t total;
    uint8_t buf[128];
    size_t used;
} wcp_sha512_ctx;

static void sha512_block(uint64_t state[8], const uint8_t block[128])
{
    uint64_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = load_be64(block + (size_t)i * 8u);
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1u) ^ rotr64(w[i - 15], 8u) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19u) ^ rotr64(w[i - 2], 61u) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    wcp_zero_mem(w, sizeof(w));
}

static void sha512_init(wcp_sha512_ctx *ctx)
{
    ctx->state[0] = UINT64_C(0x6a09e667f3bcc908);
    ctx->state[1] = UINT64_C(0xbb67ae8584caa73b);
    ctx->state[2] = UINT64_C(0x3c6ef372fe94f82b);
    ctx->state[3] = UINT64_C(0xa54ff53a5f1d36f1);
    ctx->state[4] = UINT64_C(0x510e527fade682d1);
    ctx->state[5] = UINT64_C(0x9b05688c2b3e6c1f);
    ctx->state[6] = UINT64_C(0x1f83d9abfb41bd6b);
    ctx->state[7] = UINT64_C(0x5be0cd19137e2179);
    ctx->total = 0u;
    ctx->used = 0u;
}

static void sha512_update(wcp_sha512_ctx *ctx, const uint8_t *data, size_t len)
{
    if (!len)
        return;
    ctx->total += (uint64_t)len;
    if (ctx->used > 0u) {
        size_t take = 128u - ctx->used;
        if (take > len)
            take = len;
        memcpy(ctx->buf + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;
        if (ctx->used == 128u) {
            sha512_block(ctx->state, ctx->buf);
            ctx->used = 0u;
        }
    }
    while (len >= 128u) {
        sha512_block(ctx->state, data);
        data += 128u;
        len -= 128u;
    }
    if (len > 0u) {
        memcpy(ctx->buf, data, len);
        ctx->used = len;
    }
}

static void sha512_final(wcp_sha512_ctx *ctx, uint8_t out[WCP_SHA512_LEN])
{
    size_t rem = ctx->used;
    ctx->buf[rem++] = 0x80u;
    if (rem > 112u) {
        memset(ctx->buf + rem, 0, 128u - rem);
        sha512_block(ctx->state, ctx->buf);
        rem = 0u;
    }
    memset(ctx->buf + rem, 0, 112u - rem);
    store_be64(ctx->buf + 112u, ctx->total >> 61);
    store_be64(ctx->buf + 120u, ctx->total << 3);
    sha512_block(ctx->state, ctx->buf);
    for (int i = 0; i < 8; ++i)
        store_be64(out + (size_t)i * 8u, ctx->state[i]);
    wcp_zero_mem(ctx, sizeof(*ctx));
}

void wcp_sha512(const uint8_t *data, size_t len, uint8_t out[WCP_SHA512_LEN])
{
    wcp_sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, out);
}

void wcp_sha512_v(const uint8_t *const *parts, const size_t *lens, size_t count,
                  uint8_t out[WCP_SHA512_LEN])
{
    wcp_sha512_ctx ctx;
    sha512_init(&ctx);
    for (size_t i = 0; i < count; ++i) {
        if (parts[i] && lens[i])
            sha512_update(&ctx, parts[i], lens[i]);
    }
    sha512_final(&ctx, out);
}

void wcp_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[WCP_SHA512_LEN])
{
    uint8_t kbuf[128];
    uint8_t pad[128];
    uint8_t inner[WCP_SHA512_LEN];
    wcp_sha512_ctx ctx;

    memset(kbuf, 0, sizeof(kbuf));
    if (key_len > 128u) {
        wcp_sha512(key, key_len, kbuf);
    } else if (key_len > 0u) {
        memcpy(kbuf, key, key_len);
    }

    for (size_t i = 0; i < 128u; ++i)
        pad[i] = (uint8_t)(kbuf[i] ^ 0x36u);
    sha512_init(&ctx);
    sha512_update(&ctx, pad, 128u);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, inner);

    for (size_t i = 0; i < 128u; ++i)
        pad[i] = (uint8_t)(kbuf[i] ^ 0x5cu);
    sha512_init(&ctx);
    sha512_update(&ctx, pad, 128u);
    sha512_update(&ctx, inner, sizeof(inner));
    sha512_final(&ctx, out);

    wcp_zero_mem(kbuf, sizeof(kbuf));
    wcp_zero_mem(pad, sizeof(pad));
    wcp_zero_mem(inner, sizeof(inner));
}

int wcp_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len)
{
    static const uint8_t zero_salt[64] = {0};
    if (!okm || okm_len == 0u || okm_len > 255u * WCP_SHA512_LEN)
        return WCP_kParamErr;
    const uint8_t *use_salt = (salt && salt_len) ? salt : zero_salt;
    size_t use_salt_len = (salt && salt_len) ? salt_len : 64u;

    uint8_t prk[WCP_SHA512_LEN];
    wcp_hmac_sha512(use_salt, use_salt_len, ikm, ikm_len, prk);

    uint8_t t[WCP_SHA512_LEN];
    uint8_t ipad[128], opad[128];
    uint8_t kbuf[128];
    memset(kbuf, 0, sizeof(kbuf));
    memcpy(kbuf, prk, sizeof(prk));
    for (size_t i = 0; i < 128u; ++i) {
        ipad[i] = (uint8_t)(kbuf[i] ^ 0x36u);
        opad[i] = (uint8_t)(kbuf[i] ^ 0x5cu);
    }

    size_t pos = 0u;
    size_t t_len = 0u;
    uint8_t counter = 1u;
    while (pos < okm_len) {
        uint8_t inner[WCP_SHA512_LEN];
        wcp_sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, ipad, 128u);
        if (t_len)
            sha512_update(&ctx, t, t_len);
        if (info && info_len)
            sha512_update(&ctx, info, info_len);
        sha512_update(&ctx, &counter, 1u);
        sha512_final(&ctx, inner);

        sha512_init(&ctx);
        sha512_update(&ctx, opad, 128u);
        sha512_update(&ctx, inner, sizeof(inner));
        sha512_final(&ctx, t);
        wcp_zero_mem(inner, sizeof(inner));

        size_t take = okm_len - pos;
        if (take > WCP_SHA512_LEN)
            take = WCP_SHA512_LEN;
        memcpy(okm + pos, t, take);
        pos += take;
        t_len = WCP_SHA512_LEN;
        ++counter;
    }

    wcp_zero_mem(prk, sizeof(prk));
    wcp_zero_mem(t, sizeof(t));
    wcp_zero_mem(kbuf, sizeof(kbuf));
    wcp_zero_mem(ipad, sizeof(ipad));
    wcp_zero_mem(opad, sizeof(opad));
    return 0;
}

/* ---------------- ChaCha20-Poly1305 (RFC 7539 / RFC 8439) ---------------- */

#define CHACHA_QR(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16u); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12u); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8u); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7u); \
} while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i)
        s[4 + i] = load_le32(key + (size_t)i * 4u);
    s[12] = counter;
    s[13] = load_le32(nonce);
    s[14] = load_le32(nonce + 4);
    s[15] = load_le32(nonce + 8);
    memcpy(x, s, sizeof(x));

    for (int i = 0; i < 10; ++i) {
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i)
        store_le32(out + (size_t)i * 4u, x[i] + s[i]);
    wcp_zero_mem(s, sizeof(s));
    wcp_zero_mem(x, sizeof(x));
}

static void chacha20_xor(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t block[64];
    size_t off = 0u;
    while (off < len) {
        chacha20_block(key, counter++, nonce, block);
        size_t take = len - off;
        if (take > 64u)
            take = 64u;
        for (size_t i = 0; i < take; ++i)
            out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
        off += take;
    }
    wcp_zero_mem(block, sizeof(block));
}

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *st, const uint8_t key[32])
{
    uint32_t t0 = load_le32(key + 0u) & 0x0fffffffu;
    uint32_t t1 = load_le32(key + 4u) & 0x0ffffffcu;
    uint32_t t2 = load_le32(key + 8u) & 0x0ffffffcu;
    uint32_t t3 = load_le32(key + 12u) & 0x0ffffffcu;
    st->r[0] = t0 & 0x03ffffffu;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffffu;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffffu;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffffu;
    st->r[4] = (t3 >> 8) & 0x000fffffu;
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0u;
    st->pad[0] = load_le32(key + 16u);
    st->pad[1] = load_le32(key + 20u);
    st->pad[2] = load_le32(key + 24u);
    st->pad[3] = load_le32(key + 28u);
}

static void poly1305_block16(poly1305_ctx *st, const uint8_t *m, size_t len)
{
    uint8_t tmp[16];
    const uint8_t *src = m;
    uint32_t hibit = (len == 16u) ? (1u << 24) : 0u;
    if (len < 16u) {
        memset(tmp, 0, 16u);
        if (len > 0u)
            memcpy(tmp, m, len);
        tmp[len] = 1u;
        src = tmp;
    }
    uint32_t m0 = load_le32(src + 0u);
    uint32_t m1 = load_le32(src + 4u);
    uint32_t m2 = load_le32(src + 8u);
    uint32_t m3 = load_le32(src + 12u);

    uint32_t h0 = st->h[0] + (m0 & 0x03ffffffu);
    uint32_t h1 = st->h[1] + (((m0 >> 26) | (m1 << 6)) & 0x03ffffffu);
    uint32_t h2 = st->h[2] + (((m1 >> 20) | (m2 << 12)) & 0x03ffffffu);
    uint32_t h3 = st->h[3] + (((m2 >> 14) | (m3 << 18)) & 0x03ffffffu);
    uint32_t h4 = st->h[4] + (m3 >> 8) + hibit;

    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;

    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffffu; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffffu; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffffu; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffffu; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x03ffffffu; h1 += c;

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update_padded(poly1305_ctx *st, const uint8_t *data, size_t len)
{
    size_t off = 0u;
    while (off + 16u <= len) {
        poly1305_block16(st, data + off, 16u);
        off += 16u;
    }
    if (off < len) {
        uint8_t tail[16];
        memset(tail, 0, sizeof(tail));
        memcpy(tail, data + off, len - off);
        poly1305_block16(st, tail, 16u);
    }
}

static void poly1305_finish(poly1305_ctx *st, uint8_t tag[16])
{
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x03ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x03ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x03ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x03ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x03ffffffu; h1 += c;

    uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x03ffffffu;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x03ffffffu;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x03ffffffu;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x03ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store_le32(tag + 0u, h0);
    store_le32(tag + 4u, h1);
    store_le32(tag + 8u, h2);
    store_le32(tag + 12u, h3);
    wcp_zero_mem(st, sizeof(*st));
}

static void aead_poly_tag(const uint8_t key[32], const uint8_t nonce[12],
                          const void *aad, size_t aad_len,
                          const uint8_t *cipher, size_t len, uint8_t tag[16])
{
    uint8_t otk[64];
    chacha20_block(key, 0u, nonce, otk);
    poly1305_ctx poly;
    poly1305_init(&poly, otk);
    if (aad && aad_len)
        poly1305_update_padded(&poly, (const uint8_t *)aad, aad_len);
    if (cipher && len)
        poly1305_update_padded(&poly, cipher, len);
    uint8_t lens[16];
    store_le64(lens, (uint64_t)aad_len);
    store_le64(lens + 8u, (uint64_t)len);
    poly1305_block16(&poly, lens, 16u);
    poly1305_finish(&poly, tag);
    wcp_zero_mem(otk, sizeof(otk));
}

void wcp_chacha20_poly1305_encrypt_nonce8(const uint8_t key[WCP_KEY_LEN],
                                          const uint8_t nonce8[WCP_NONCE8_LEN],
                                          const void *aad, size_t aad_len,
                                          const void *plain, size_t len,
                                          void *cipher, uint8_t tag[WCP_TAG_LEN])
{
    uint8_t nonce12[12];
    memset(nonce12, 0, 4u);
    memcpy(nonce12 + 4u, nonce8, 8u);
    if (len && plain && cipher)
        chacha20_xor(key, 1u, nonce12, (const uint8_t *)plain, (uint8_t *)cipher, len);
    aead_poly_tag(key, nonce12, aad, aad_len, (const uint8_t *)cipher, len, tag);
    wcp_zero_mem(nonce12, sizeof(nonce12));
}

int wcp_chacha20_poly1305_decrypt_nonce8(const uint8_t key[WCP_KEY_LEN],
                                         const uint8_t nonce8[WCP_NONCE8_LEN],
                                         const void *aad, size_t aad_len,
                                         const void *cipher, size_t len,
                                         const uint8_t tag[WCP_TAG_LEN],
                                         void *plain)
{
    uint8_t nonce12[12];
    uint8_t computed[16];
    memset(nonce12, 0, 4u);
    memcpy(nonce12 + 4u, nonce8, 8u);
    aead_poly_tag(key, nonce12, aad, aad_len, (const uint8_t *)cipher, len, computed);
    if (!wcp_ct_equal(computed, tag, 16u)) {
        wcp_zero_mem(computed, sizeof(computed));
        wcp_zero_mem(nonce12, sizeof(nonce12));
        if (plain && len)
            wcp_zero_mem(plain, len);
        return WCP_kAuthenticationErr;
    }
    if (len && cipher && plain)
        chacha20_xor(key, 1u, nonce12, (const uint8_t *)cipher, (uint8_t *)plain, len);
    wcp_zero_mem(computed, sizeof(computed));
    wcp_zero_mem(nonce12, sizeof(nonce12));
    return 0;
}

/* ---------------- GF(2^255 - 19) for X25519 & Ed25519 (TweetNaCl) ---------------- */

typedef int64_t gf[16];

static const gf GF_D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const gf GF_D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const gf GF_X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const gf GF_Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const gf GF_I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};
static const gf GF_121665 = { 0xdb41, 1 };

static void set25519(gf r, const gf a)
{
    for (int i = 0; i < 16; ++i)
        r[i] = a[i];
}

static void car25519(gf o)
{
    for (int i = 0; i < 16; ++i) {
        o[i] += 1LL << 16;
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t c = ~(int64_t)(b - 1);
    for (int i = 0; i < 16; ++i) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    gf m, t;
    for (int i = 0; i < 16; ++i)
        t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; ++i)
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A25519(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] + b[i];
}

static void Z25519(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] - b[i];
}

static void M25519(gf o, const gf a, const gf b)
{
    int64_t t[31];
    for (int i = 0; i < 31; ++i)
        t[i] = 0;
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S25519(gf o, const gf a)
{
    M25519(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    for (int a = 0; a < 16; ++a)
        c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S25519(c, c);
        if (a != 2 && a != 4)
            M25519(c, c, i);
    }
    for (int a = 0; a < 16; ++a)
        o[a] = c[a];
}

static void pow2523(gf o, const gf i)
{
    gf c;
    for (int a = 0; a < 16; ++a)
        c[a] = i[a];
    for (int a = 250; a >= 0; --a) {
        S25519(c, c);
        if (a != 1)
            M25519(c, c, i);
    }
    for (int a = 0; a < 16; ++a)
        o[a] = c[a];
}

static int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return !wcp_ct_equal(c, d, 32u);
}

static uint8_t par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return (uint8_t)(d[0] & 1u);
}

/* ---------------- X25519 ---------------- */

void wcp_x25519(uint8_t out[WCP_X25519_LEN],
                const uint8_t scalar[WCP_X25519_LEN],
                const uint8_t point[WCP_X25519_LEN])
{
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    memcpy(z, scalar, 32u);
    z[31] = (uint8_t)((z[31] & 127u) | 64u);
    z[0] &= 248u;
    unpack25519(x, point);
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    memset(c, 0, sizeof(c));
    memset(d, 0, sizeof(d));
    for (int i = 0; i < 16; ++i) {
        b[i] = x[i];
        a[i] = 0;
        c[i] = 0;
        d[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A25519(e, a, c);
        Z25519(a, a, c);
        A25519(c, b, d);
        Z25519(b, b, d);
        S25519(d, e);
        S25519(f, a);
        M25519(a, c, a);
        M25519(c, b, e);
        A25519(e, a, c);
        Z25519(a, a, c);
        S25519(b, a);
        Z25519(c, d, f);
        M25519(a, c, GF_121665);
        A25519(a, a, d);
        M25519(c, c, a);
        M25519(a, d, f);
        M25519(d, b, x);
        S25519(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M25519(a, a, c);
    pack25519(out, a);
    wcp_zero_mem(z, sizeof(z));
}

void wcp_x25519_base(uint8_t out[WCP_X25519_LEN],
                     const uint8_t scalar[WCP_X25519_LEN])
{
    uint8_t bp[32];
    memset(bp, 0, sizeof(bp));
    bp[0] = 9u;
    wcp_x25519(out, scalar, bp);
}

/* ---------------- Ed25519 ---------------- */

static void ed_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    Z25519(a, p[1], p[0]);
    Z25519(t, q[1], q[0]);
    M25519(a, a, t);
    A25519(b, p[0], p[1]);
    A25519(t, q[0], q[1]);
    M25519(b, b, t);
    M25519(c, p[3], q[3]);
    M25519(c, c, GF_D2);
    M25519(d, p[2], q[2]);
    A25519(d, d, d);
    Z25519(e, b, a);
    Z25519(f, d, c);
    A25519(g, d, c);
    A25519(h, b, a);

    M25519(p[0], e, f);
    M25519(p[1], h, g);
    M25519(p[2], g, f);
    M25519(p[3], e, h);
}

static void ed_cswap(gf p[4], gf q[4], uint8_t b)
{
    for (int i = 0; i < 4; ++i)
        sel25519(p[i], q[i], (int)b);
}

static void ed_pack(uint8_t r[32], gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M25519(tx, p[0], zi);
    M25519(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

static void ed_scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    gf zero = {0};
    gf one = {1};
    set25519(p[0], zero);
    set25519(p[1], one);
    set25519(p[2], one);
    set25519(p[3], zero);
    for (int i = 255; i >= 0; --i) {
        uint8_t b = (uint8_t)((s[i / 8] >> (i & 7)) & 1u);
        ed_cswap(p, q, b);
        ed_add(q, p);
        ed_add(p, p);
        ed_cswap(p, q, b);
    }
}

static void ed_scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    gf one = {1};
    set25519(q[0], GF_X);
    set25519(q[1], GF_Y);
    set25519(q[2], one);
    M25519(q[3], GF_X, GF_Y);
    ed_scalarmult(p, q, s);
}

static int ed_unpackneg(gf r[4], const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    gf one = {1};
    set25519(r[2], one);
    unpack25519(r[1], p);
    S25519(num, r[1]);
    M25519(den, num, GF_D);
    Z25519(num, num, r[2]);
    A25519(den, r[2], den);

    S25519(den2, den);
    S25519(den4, den2);
    M25519(den6, den4, den2);
    M25519(t, den6, num);
    M25519(t, t, den);

    pow2523(t, t);
    M25519(t, t, num);
    M25519(t, t, den);
    M25519(t, t, den);
    M25519(r[0], t, den);

    S25519(chk, r[0]);
    M25519(chk, chk, den);
    if (neq25519(chk, num))
        M25519(r[0], r[0], GF_I);

    S25519(chk, r[0]);
    M25519(chk, chk, den);
    if (neq25519(chk, num))
        return -1;

    if (par25519(r[0]) == (p[31] >> 7))
        Z25519(r[0], (gf){0}, r[0]);

    M25519(r[3], r[0], r[1]);
    return 0;
}

static const uint64_t ED_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

static void ed_modL(uint8_t *r, int64_t x[64])
{
    for (int i = 63; i >= 32; --i) {
        int64_t carry = 0;
        int j;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * (int64_t)ED_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * (int64_t)ED_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; ++j)
        x[j] -= carry * (int64_t)ED_L[j];
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void ed_reduce(uint8_t *r)
{
    int64_t x[64];
    for (int i = 0; i < 64; ++i)
        x[i] = (uint64_t)r[i];
    memset(r, 0, 64u);
    ed_modL(r, x);
    wcp_zero_mem(x, sizeof(x));
}

void wcp_ed25519_publickey(uint8_t pk[WCP_ED25519_PK_LEN],
                           const uint8_t sk[WCP_ED25519_SK_LEN])
{
    uint8_t d[64];
    gf p[4];
    wcp_sha512(sk, 32u, d);
    d[0] &= 248u;
    d[31] &= 127u;
    d[31] |= 64u;
    ed_scalarbase(p, d);
    ed_pack(pk, p);
    wcp_zero_mem(d, sizeof(d));
}

void wcp_ed25519_sign(uint8_t sig[WCP_ED25519_SIG_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sk[WCP_ED25519_SK_LEN],
                      const uint8_t pk[WCP_ED25519_PK_LEN])
{
    uint8_t d[64], h[64], r[64];
    int64_t x[64];
    gf p[4];

    wcp_sha512(sk, 32u, d);
    d[0] &= 248u;
    d[31] &= 127u;
    d[31] |= 64u;

    const uint8_t *p1[2] = { d + 32u, msg };
    const size_t l1[2] = { 32u, msg_len };
    wcp_sha512_v(p1, l1, 2u, r);
    ed_reduce(r);
    ed_scalarbase(p, r);
    ed_pack(sig, p);

    const uint8_t *p2[3] = { sig, pk, msg };
    const size_t l2[3] = { 32u, 32u, msg_len };
    wcp_sha512_v(p2, l2, 3u, h);
    ed_reduce(h);

    for (int i = 0; i < 64; ++i)
        x[i] = 0;
    for (int i = 0; i < 32; ++i)
        x[i] = (int64_t)r[i];
    for (int i = 0; i < 32; ++i)
        for (int j = 0; j < 32; ++j)
            x[i + j] += (int64_t)h[i] * (int64_t)d[j];
    ed_modL(sig + 32u, x);

    wcp_zero_mem(d, sizeof(d));
    wcp_zero_mem(h, sizeof(h));
    wcp_zero_mem(r, sizeof(r));
    wcp_zero_mem(x, sizeof(x));
}

int wcp_ed25519_verify(const uint8_t sig[WCP_ED25519_SIG_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t pk[WCP_ED25519_PK_LEN])
{
    uint8_t t[32], h[64];
    gf p[4], q[4];
    /* Enforce canonical S < L against signature malleability */
    int cmp_lt = 0;
    for (int i = 31; i >= 0; --i) {
        if (sig[32 + i] < (uint8_t)ED_L[i]) {
            cmp_lt = 1;
            break;
        }
        if (sig[32 + i] > (uint8_t)ED_L[i])
            return -1;
    }
    if (!cmp_lt)
        return -1;

    if (ed_unpackneg(q, pk) != 0)
        return -1;

    const uint8_t *parts[3] = { sig, pk, msg };
    const size_t lens[3] = { 32u, 32u, msg_len };
    wcp_sha512_v(parts, lens, 3u, h);
    ed_reduce(h);

    ed_scalarmult(p, q, h);
    ed_scalarbase(q, sig + 32u);
    ed_add(p, q);
    ed_pack(t, p);
    return wcp_ct_equal(sig, t, 32u) ? 0 : -1;
}

/* ---------------- SRP-6a 3072-bit / SHA-512 (RFC 5054 Group 15) ---------------- */

static const uint8_t SRP_N_3072[WCP_SRP_PRIME_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
    0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
    0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
    0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb,
    0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
    0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f,
    0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9, 0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7c, 0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
    0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d, 0x04, 0x50, 0x7a, 0x33,
    0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64, 0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a,
    0x8a, 0xea, 0x71, 0x57, 0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
    0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0, 0x4a, 0x25, 0x61, 0x9d,
    0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b, 0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64,
    0xd8, 0x76, 0x02, 0x73, 0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
    0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0, 0xba, 0xd9, 0x46, 0xe2,
    0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31, 0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e,
    0x4b, 0x82, 0xd1, 0x20, 0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

#define BN_LIMBS 96u /* 96 * 32 = 3072 bits */
typedef struct {
    uint32_t w[BN_LIMBS];
} bn3072;

static void bn_from_be(bn3072 *out, const uint8_t *be, size_t len)
{
    memset(out, 0, sizeof(*out));
    if (len > WCP_SRP_PRIME_LEN)
        len = WCP_SRP_PRIME_LEN;
    for (size_t i = 0; i < len; ++i) {
        size_t pos = len - 1u - i;
        out->w[i >> 2] |= (uint32_t)be[pos] << ((i & 3u) * 8u);
    }
}

static void bn_to_be384(const bn3072 *in, uint8_t out[WCP_SRP_PRIME_LEN])
{
    for (size_t i = 0; i < WCP_SRP_PRIME_LEN; ++i) {
        size_t pos = WCP_SRP_PRIME_LEN - 1u - i;
        out[pos] = (uint8_t)((in->w[i >> 2] >> ((i & 3u) * 8u)) & 0xffu);
    }
}

static int bn_is_zero(const bn3072 *a)
{
    uint32_t acc = 0u;
    for (size_t i = 0; i < BN_LIMBS; ++i)
        acc |= a->w[i];
    return acc == 0u;
}

static int bn_cmp(const bn3072 *a, const bn3072 *b)
{
    for (size_t i = BN_LIMBS; i-- > 0;) {
        if (a->w[i] != b->w[i])
            return a->w[i] > b->w[i] ? 1 : -1;
    }
    return 0;
}

static uint32_t bn_sub(bn3072 *r, const bn3072 *a, const bn3072 *b)
{
    uint64_t borrow = 0u;
    for (size_t i = 0; i < BN_LIMBS; ++i) {
        uint64_t diff = (uint64_t)a->w[i] - (uint64_t)b->w[i] - borrow;
        r->w[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

static void bn_add_mod(bn3072 *r, const bn3072 *a, const bn3072 *b, const bn3072 *mod)
{
    uint64_t carry = 0u;
    for (size_t i = 0; i < BN_LIMBS; ++i) {
        uint64_t sum = (uint64_t)a->w[i] + b->w[i] + carry;
        r->w[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry || bn_cmp(r, mod) >= 0)
        (void)bn_sub(r, r, mod);
}

/* Precompute Montgomery constant n0' = -mod[0]^(-1) mod 2^32. For N_3072, w[0] = 0xffffffff so n0' = 1! */
static uint32_t bn_mont_inv32(uint32_t n0)
{
    uint32_t x = 1u;
    for (int i = 0; i < 5; ++i)
        x *= (2u - n0 * x);
    return (uint32_t)(0u - x);
}

/* Compute R^2 mod N once or by squaring R mod N (note R mod N = 2^3072 - N for N_3072 since top bit is 1!) */
static void bn_mont_mul(bn3072 *r, const bn3072 *a, const bn3072 *b,
                        const bn3072 *mod, uint32_t n0_inv)
{
    uint32_t t[BN_LIMBS + 2u];
    memset(t, 0, sizeof(t));
    for (size_t i = 0; i < BN_LIMBS; ++i) {
        uint64_t carry = 0u;
        uint32_t ai = a->w[i];
        for (size_t j = 0; j < BN_LIMBS; ++j) {
            uint64_t sum = (uint64_t)t[j] + (uint64_t)ai * b->w[j] + carry;
            t[j] = (uint32_t)sum;
            carry = sum >> 32;
        }
        uint64_t sum = (uint64_t)t[BN_LIMBS] + carry;
        t[BN_LIMBS] = (uint32_t)sum;
        t[BN_LIMBS + 1u] = (uint32_t)(sum >> 32);

        uint32_t m = t[0] * n0_inv;
        carry = ((uint64_t)t[0] + (uint64_t)m * mod->w[0]) >> 32;
        for (size_t j = 1; j < BN_LIMBS; ++j) {
            sum = (uint64_t)t[j] + (uint64_t)m * mod->w[j] + carry;
            t[j - 1u] = (uint32_t)sum;
            carry = sum >> 32;
        }
        sum = (uint64_t)t[BN_LIMBS] + carry;
        t[BN_LIMBS - 1u] = (uint32_t)sum;
        t[BN_LIMBS] = t[BN_LIMBS + 1u] + (uint32_t)(sum >> 32);
        t[BN_LIMBS + 1u] = 0u;
    }
    memcpy(r->w, t, BN_LIMBS * sizeof(uint32_t));
    if (t[BN_LIMBS] || bn_cmp(r, mod) >= 0)
        (void)bn_sub(r, r, mod);
    wcp_zero_mem(t, sizeof(t));
}

typedef struct {
    bn3072 n;
    bn3072 r_mod_n;
    bn3072 r2_mod_n;
    uint32_t n0_inv;
} srp_mont_ctx;

static void srp_mont_init(srp_mont_ctx *ctx)
{
    bn_from_be(&ctx->n, SRP_N_3072, sizeof(SRP_N_3072));
    ctx->n0_inv = bn_mont_inv32(ctx->n.w[0]);
    /* R = 2^3072; since N > 2^3071, R mod N = 2^3072 - N = (-N) mod 2^3072 */
    bn3072 zero;
    memset(&zero, 0, sizeof(zero));
    (void)bn_sub(&ctx->r_mod_n, &zero, &ctx->n);
    /* Square r_mod_n to get R^2 mod N: mont_mul((R), (R)) = R^2 * R^-1 = R; wait!
     * Start from r_mod_n = R mod N, repeated doubling mod N 3072 times gives R^2 mod N! */
    ctx->r2_mod_n = ctx->r_mod_n;
    for (unsigned i = 0; i < 3072u; ++i)
        bn_add_mod(&ctx->r2_mod_n, &ctx->r2_mod_n, &ctx->r2_mod_n, &ctx->n);
}

static void bn_mod_reduce(bn3072 *x, const bn3072 *mod)
{
    while (bn_cmp(x, mod) >= 0)
        (void)bn_sub(x, x, mod);
}

static void bn_mod_mul(const srp_mont_ctx *ctx, bn3072 *r, const bn3072 *a, const bn3072 *b)
{
    bn3072 ma, mb;
    ma = *a; bn_mod_reduce(&ma, &ctx->n);
    mb = *b; bn_mod_reduce(&mb, &ctx->n);
    bn_mont_mul(&ma, &ma, &ctx->r2_mod_n, &ctx->n, ctx->n0_inv);
    bn_mont_mul(&mb, &mb, &ctx->r2_mod_n, &ctx->n, ctx->n0_inv);
    bn_mont_mul(r, &ma, &mb, &ctx->n, ctx->n0_inv);
    bn3072 one;
    memset(&one, 0, sizeof(one));
    one.w[0] = 1u;
    bn_mont_mul(r, r, &one, &ctx->n, ctx->n0_inv);
}

/* Square-and-multiply in Montgomery domain using big-endian exponent bytes[exp_len] */
static void bn_mod_exp_be(const srp_mont_ctx *ctx, bn3072 *r,
                          const bn3072 *base, const uint8_t *exp, size_t exp_len)
{
    bn3072 b = *base;
    bn_mod_reduce(&b, &ctx->n);
    bn3072 mbase, acc;
    bn_mont_mul(&mbase, &b, &ctx->r2_mod_n, &ctx->n, ctx->n0_inv);
    acc = ctx->r_mod_n;

    for (size_t byte_i = 0; byte_i < exp_len; ++byte_i) {
        uint8_t byte = exp[byte_i];
        for (int bit = 7; bit >= 0; --bit) {
            bn_mont_mul(&acc, &acc, &acc, &ctx->n, ctx->n0_inv);
            if ((byte >> bit) & 1u)
                bn_mont_mul(&acc, &acc, &mbase, &ctx->n, ctx->n0_inv);
        }
    }
    bn3072 one;
    memset(&one, 0, sizeof(one));
    one.w[0] = 1u;
    bn_mont_mul(r, &acc, &one, &ctx->n, ctx->n0_inv);
    wcp_zero_mem(&mbase, sizeof(mbase));
    wcp_zero_mem(&acc, sizeof(acc));
}

static size_t strip_zero_offset(const uint8_t *buf, size_t len)
{
    size_t i = 0u;
    while (i < len && buf[i] == 0u)
        ++i;
    return i;
}

static void srp_calc_k(const srp_mont_ctx *ctx, bn3072 *k_out)
{
    uint8_t g_pad[WCP_SRP_PRIME_LEN];
    memset(g_pad, 0, sizeof(g_pad));
    g_pad[sizeof(g_pad) - 1u] = 5u;
    uint8_t kh[WCP_SHA512_LEN];
    const uint8_t *parts[2] = { SRP_N_3072, g_pad };
    const size_t lens[2] = { sizeof(SRP_N_3072), sizeof(g_pad) };
    wcp_sha512_v(parts, lens, 2u, kh);
    bn_from_be(k_out, kh, sizeof(kh));
    bn_mod_reduce(k_out, &ctx->n);
    wcp_zero_mem(kh, sizeof(kh));
}

void wcp_srp_server_start(const uint8_t salt[WCP_SRP_SALT_LEN],
                          const uint8_t priv_b[32],
                          const uint8_t *user, size_t user_len,
                          const uint8_t *pass, size_t pass_len,
                          uint8_t verifier_out[WCP_SRP_PRIME_LEN],
                          uint8_t pub_b_out[WCP_SRP_PRIME_LEN])
{
    static const uint8_t colon = (uint8_t)':';
    uint8_t inner[WCP_SHA512_LEN], x_bytes[WCP_SHA512_LEN];
    const uint8_t *p1[3] = { user, &colon, pass };
    const size_t l1[3] = { user_len, 1u, pass_len };
    wcp_sha512_v(p1, l1, 3u, inner);

    const uint8_t *p2[2] = { salt, inner };
    const size_t l2[2] = { WCP_SRP_SALT_LEN, sizeof(inner) };
    wcp_sha512_v(p2, l2, 2u, x_bytes);

    srp_mont_ctx ctx;
    srp_mont_init(&ctx);

    bn3072 g, v, gb, k, kv, b_pub;
    memset(&g, 0, sizeof(g));
    g.w[0] = 5u;
    bn_mod_exp_be(&ctx, &v, &g, x_bytes, sizeof(x_bytes));
    bn_to_be384(&v, verifier_out);

    bn_mod_exp_be(&ctx, &gb, &g, priv_b, 32u);
    srp_calc_k(&ctx, &k);
    bn_mod_mul(&ctx, &kv, &v, &k);
    bn_add_mod(&b_pub, &gb, &kv, &ctx.n);
    bn_to_be384(&b_pub, pub_b_out);

    wcp_zero_mem(inner, sizeof(inner));
    wcp_zero_mem(x_bytes, sizeof(x_bytes));
    wcp_zero_mem(&ctx, sizeof(ctx));
    wcp_zero_mem(&v, sizeof(v));
    wcp_zero_mem(&gb, sizeof(gb));
    wcp_zero_mem(&kv, sizeof(kv));
}

int wcp_srp_server_finish(const uint8_t salt[WCP_SRP_SALT_LEN],
                          const uint8_t *user, size_t user_len,
                          const uint8_t priv_b[32],
                          const uint8_t verifier[WCP_SRP_PRIME_LEN],
                          const uint8_t pub_a[WCP_SRP_PRIME_LEN],
                          const uint8_t pub_b[WCP_SRP_PRIME_LEN],
                          const uint8_t client_m1[WCP_SRP_PROOF_LEN],
                          uint8_t session_key_out[WCP_SRP_PROOF_LEN],
                          uint8_t server_m2_out[WCP_SRP_PROOF_LEN])
{
    srp_mont_ctx ctx;
    srp_mont_init(&ctx);

    bn3072 a_bn, v_bn, vu_bn, base_bn, s_bn;
    bn_from_be(&a_bn, pub_a, WCP_SRP_PRIME_LEN);
    bn_mod_reduce(&a_bn, &ctx.n);
    if (bn_is_zero(&a_bn)) {
        wcp_zero_mem(&ctx, sizeof(ctx));
        return WCP_kAuthenticationErr;
    }

    uint8_t u_bytes[WCP_SHA512_LEN];
    const uint8_t *up[2] = { pub_a, pub_b };
    const size_t ul[2] = { WCP_SRP_PRIME_LEN, WCP_SRP_PRIME_LEN };
    wcp_sha512_v(up, ul, 2u, u_bytes);

    bn_from_be(&v_bn, verifier, WCP_SRP_PRIME_LEN);
    bn_mod_exp_be(&ctx, &vu_bn, &v_bn, u_bytes, sizeof(u_bytes));
    bn_mod_mul(&ctx, &base_bn, &a_bn, &vu_bn);
    bn_mod_exp_be(&ctx, &s_bn, &base_bn, priv_b, 32u);

    uint8_t s_bytes[WCP_SRP_PRIME_LEN];
    bn_to_be384(&s_bn, s_bytes);
    size_t sz = strip_zero_offset(s_bytes, sizeof(s_bytes));
    wcp_sha512(s_bytes + sz, sizeof(s_bytes) - sz, session_key_out);

    /* Compute expected M1 = H(H(N)^H(g) | H(I) | s | A_stripped | B_stripped | K) */
    static const uint8_t g_byte = 5u;
    uint8_t h_n[WCP_SHA512_LEN], h_g[WCP_SHA512_LEN], h_ng[WCP_SHA512_LEN], h_u[WCP_SHA512_LEN];
    wcp_sha512(SRP_N_3072, sizeof(SRP_N_3072), h_n);
    wcp_sha512(&g_byte, 1u, h_g);
    for (size_t i = 0; i < WCP_SHA512_LEN; ++i)
        h_ng[i] = (uint8_t)(h_n[i] ^ h_g[i]);
    wcp_sha512(user, user_len, h_u);

    size_t az = strip_zero_offset(pub_a, WCP_SRP_PRIME_LEN);
    size_t bz = strip_zero_offset(pub_b, WCP_SRP_PRIME_LEN);
    uint8_t expected_m1[WCP_SHA512_LEN];
    const uint8_t *mp[6] = {
        h_ng, h_u, salt,
        pub_a + az, pub_b + bz, session_key_out
    };
    const size_t ml[6] = {
        sizeof(h_ng), sizeof(h_u), WCP_SRP_SALT_LEN,
        WCP_SRP_PRIME_LEN - az, WCP_SRP_PRIME_LEN - bz, WCP_SHA512_LEN
    };
    wcp_sha512_v(mp, ml, 6u, expected_m1);

    int match = wcp_ct_equal(expected_m1, client_m1, WCP_SRP_PROOF_LEN);
    if (match) {
        const uint8_t *m2p[3] = { pub_a, client_m1, session_key_out };
        const size_t m2l[3] = { WCP_SRP_PRIME_LEN, WCP_SRP_PROOF_LEN, WCP_SHA512_LEN };
        wcp_sha512_v(m2p, m2l, 3u, server_m2_out);
    } else {
        wcp_zero_mem(session_key_out, WCP_SRP_PROOF_LEN);
    }

    wcp_zero_mem(u_bytes, sizeof(u_bytes));
    wcp_zero_mem(s_bytes, sizeof(s_bytes));
    wcp_zero_mem(expected_m1, sizeof(expected_m1));
    wcp_zero_mem(&ctx, sizeof(ctx));
    wcp_zero_mem(&v_bn, sizeof(v_bn));
    wcp_zero_mem(&vu_bn, sizeof(vu_bn));
    wcp_zero_mem(&base_bn, sizeof(base_bn));
    wcp_zero_mem(&s_bn, sizeof(s_bn));
    return match ? 0 : WCP_kAuthenticationErr;
}
