/*!
 * blake2b.c - blake2b for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 *
 * Parts of this software are based on BLAKE2/BLAKE2:
 *   CC0 1.0 Universal
 *   https://github.com/BLAKE2/BLAKE2
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 *   https://tools.ietf.org/html/rfc7693
 *   https://github.com/BLAKE2/BLAKE2/blob/master/ref/blake2b-ref.c
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "blake2b.h"
#include "internal.h"
#include "util.h"

/*
 * Helpers
 */

static URKEL_INLINE uint64_t
urkel_rotr64(uint64_t w, unsigned int c) {
  return (w >> c) | (w << (64 - c));
}

/*
 * BLAKE2b
 */

static const uint64_t urkel_blake2b_iv[8] = {
  UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const uint8_t urkel_blake2b_sigma[12][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

void
urkel_blake2b_init(urkel_blake2b_t *ctx,
                   size_t outlen,
                   const unsigned char *key,
                   size_t keylen) {
  size_t i;

  CHECK(outlen >= 1 && outlen <= 64);
  CHECK(keylen <= 64);

  memset(ctx, 0, sizeof(urkel_blake2b_t));

  ctx->outlen = outlen;

  for (i = 0; i < 8; i++)
    ctx->h[i] = urkel_blake2b_iv[i];

  ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

  if (keylen > 0) {
    unsigned char block[128];

    memset(block, 0x00, 128);
    memcpy(block, key, keylen);

    urkel_blake2b_update(ctx, block, 128);
  }
}

static void
urkel_blake2b_increment(urkel_blake2b_t *ctx, const uint64_t inc) {
  ctx->t[0] += inc;
  ctx->t[1] += (ctx->t[0] < inc);
}

static void
urkel_blake2b_compress(urkel_blake2b_t *ctx,
                       const unsigned char *chunk,
                       uint64_t f0) {
  uint64_t m[16];
  uint64_t v[16];
  size_t i;

  for (i = 0; i < 16; i++)
    m[i] = urkel_read64(chunk + i * 8);

  for (i = 0; i < 8; i++)
    v[i] = ctx->h[i];

  v[ 8] = urkel_blake2b_iv[0];
  v[ 9] = urkel_blake2b_iv[1];
  v[10] = urkel_blake2b_iv[2];
  v[11] = urkel_blake2b_iv[3];
  v[12] = urkel_blake2b_iv[4] ^ ctx->t[0];
  v[13] = urkel_blake2b_iv[5] ^ ctx->t[1];
  v[14] = urkel_blake2b_iv[6] ^ f0;
  v[15] = urkel_blake2b_iv[7];

#define G(r, i, a, b, c, d) do {                    \
  a = a + b + m[urkel_blake2b_sigma[r][2 * i + 0]]; \
  d = urkel_rotr64(d ^ a, 32);                      \
  c = c + d;                                        \
  b = urkel_rotr64(b ^ c, 24);                      \
  a = a + b + m[urkel_blake2b_sigma[r][2 * i + 1]]; \
  d = urkel_rotr64(d ^ a, 16);                      \
  c = c + d;                                        \
  b = urkel_rotr64(b ^ c, 63);                      \
} while (0)

#define ROUND(r) do {                  \
  G(r, 0, v[ 0], v[ 4], v[ 8], v[12]); \
  G(r, 1, v[ 1], v[ 5], v[ 9], v[13]); \
  G(r, 2, v[ 2], v[ 6], v[10], v[14]); \
  G(r, 3, v[ 3], v[ 7], v[11], v[15]); \
  G(r, 4, v[ 0], v[ 5], v[10], v[15]); \
  G(r, 5, v[ 1], v[ 6], v[11], v[12]); \
  G(r, 6, v[ 2], v[ 7], v[ 8], v[13]); \
  G(r, 7, v[ 3], v[ 4], v[ 9], v[14]); \
} while (0)

  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i + 8];
#undef G
#undef ROUND
}

void
urkel_blake2b_update(urkel_blake2b_t *ctx, const void *data, size_t len) {
  const unsigned char *in = (const unsigned char *)data;

  if (len > 0) {
    size_t left = ctx->buflen;
    size_t fill = 128 - left;

    if (len > fill) {
      ctx->buflen = 0;

      memcpy(ctx->buf + left, in, fill);

      urkel_blake2b_increment(ctx, 128);
      urkel_blake2b_compress(ctx, ctx->buf, 0);

      in += fill;
      len -= fill;

      while (len > 128) {
        urkel_blake2b_increment(ctx, 128);
        urkel_blake2b_compress(ctx, in, 0);
        in += 128;
        len -= 128;
      }
    }

    memcpy(ctx->buf + ctx->buflen, in, len);
    ctx->buflen += len;
  }
}

void
urkel_blake2b_final(urkel_blake2b_t *ctx, unsigned char *out) {
  unsigned char buffer[64];
  size_t i;

  urkel_blake2b_increment(ctx, ctx->buflen);

  memset(ctx->buf + ctx->buflen, 0x00, 128 - ctx->buflen);

  urkel_blake2b_compress(ctx, ctx->buf, (uint64_t)-1);

  for (i = 0; i < 8; i++)
    urkel_write64(buffer + i * 8, ctx->h[i]);

  memcpy(out, buffer, ctx->outlen);
}
