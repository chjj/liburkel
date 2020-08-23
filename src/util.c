/*!
 * util.c - utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bits.h"
#include "blake2b.h"
#include "internal.h"
#include "io.h"
#include "util.h"

/*
 * Constants
 */

static const unsigned char SKIP_PREFIX[1] = {0x02};
static const unsigned char INTERNAL_PREFIX[1] = {0x01};
static const unsigned char LEAF_PREFIX[1] = {0x00};

/*
 * Hashing
 */

void
urkel_hash_internal(unsigned char *out,
                    const urkel_bits_t *prefix,
                    const unsigned char *left,
                    const unsigned char *right) {
  size_t bytes = (prefix->size + 7) / 8;
  unsigned char size[2];
  urkel_blake2b_t ctx;

  urkel_blake2b_init(&ctx, URKEL_HASH_SIZE, NULL, 0);

  if (prefix->size == 0) {
    urkel_blake2b_update(&ctx, INTERNAL_PREFIX, 1);
  } else {
    urkel_write16(size, prefix->size);
    urkel_blake2b_update(&ctx, SKIP_PREFIX, 1);
    urkel_blake2b_update(&ctx, size, 2);
    urkel_blake2b_update(&ctx, prefix->data, bytes);
  }

  urkel_blake2b_update(&ctx, left, URKEL_HASH_SIZE);
  urkel_blake2b_update(&ctx, right, URKEL_HASH_SIZE);
  urkel_blake2b_final(&ctx, out);
}

void
urkel_hash_leaf(unsigned char *out,
                const unsigned char *key,
                const unsigned char *vhash) {
  urkel_blake2b_t ctx;
  urkel_blake2b_init(&ctx, URKEL_HASH_SIZE, NULL, 0);
  urkel_blake2b_update(&ctx, LEAF_PREFIX, 1);
  urkel_blake2b_update(&ctx, key, URKEL_KEY_SIZE);
  urkel_blake2b_update(&ctx, vhash, URKEL_HASH_SIZE);
  urkel_blake2b_final(&ctx, out);
}

void
urkel_hash_value(unsigned char *out,
                 const unsigned char *key,
                 const unsigned char *value,
                 size_t size) {
  unsigned char vhash[URKEL_HASH_SIZE];
  urkel_blake2b_t ctx;

  urkel_blake2b_init(&ctx, URKEL_HASH_SIZE, NULL, 0);
  urkel_blake2b_update(&ctx, value, size);
  urkel_blake2b_final(&ctx, vhash);

  urkel_hash_leaf(out, key, vhash);
}

void
urkel_hash_key(unsigned char *out, const void *key, size_t size) {
  urkel_blake2b_t ctx;
  urkel_blake2b_init(&ctx, URKEL_KEY_SIZE, NULL, 0);
  urkel_blake2b_update(&ctx, key, size);
  urkel_blake2b_final(&ctx, out);
}

/*
 * String Functions
 */

int
urkel_parse_u32(uint32_t *out, const char *str) {
  uint64_t num = 0;
  size_t i;
  int ch;

  if (out)
    *out = 0;

  for (i = 0; i < 10; i++) {
    ch = (int)str[i];

    if (ch == '\0')
      return 0;

    if (ch < '0' || ch > '9')
      return 0;

    num *= 10;
    num += ch - '0';

    if (num > UINT32_MAX)
      return 0;
  }

  if (str[i] != '\0')
    return 0;

  if (out)
    *out = (uint32_t)num;

  return 1;
}

void
urkel_serialize_u32(char *out, uint32_t num) {
  size_t i = 10;

  out[i] = '\0';

  while (i--) {
    out[i] = '0' + (num % 10);
    num /= 10;
  }
}

/*
 * Helpers
 */

void
urkel_random_key(unsigned char *key) {
  /* Does not need to be cryptographically
     strong, just needs to be _different_
     from everyone else to make an attack
     not worth trying. Predicting one user's
     key does nothing to help an attacker. */
  if (!urkel_sys_random(key, 32)) {
    urkel_timespec_t ts;

    memset(&ts, 0, sizeof(ts));

    urkel_time_get(&ts);
    urkel_hash_key(key, &ts, sizeof(ts));
  }
}

unsigned char *
urkel_checksum(unsigned char *out,
               const unsigned char *data,
               size_t len,
               const unsigned char *key) {
  urkel_blake2b_t ctx;
  urkel_blake2b_init(&ctx, 20, key, 32);
  urkel_blake2b_update(&ctx, data, len);
  urkel_blake2b_final(&ctx, out);
  return out + 20;
}

uint32_t
urkel_murmur3(const unsigned char *data, size_t len, uint32_t seed) {
  uint32_t h1 = seed;
  uint32_t c1 = UINT32_C(0xcc9e2d51);
  uint32_t c2 = UINT32_C(0x1b873593);
  uint32_t k1 = 0;
  size_t left = len;

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

  while (left >= 4) {
    k1 = urkel_read32(data);

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + UINT32_C(0xe6546b64);

    data += 4;
    left -= 4;
  }

  k1 = 0;

  switch (left) {
    case 3:
      k1 ^= (uint32_t)data[2] << 16;
    case 2:
      k1 ^= (uint32_t)data[1] << 8;
    case 1:
      k1 ^= (uint32_t)data[0] << 0;
      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
  }

#undef ROTL32

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= UINT32_C(0x85ebca6b);
  h1 ^= h1 >> 13;
  h1 *= UINT32_C(0xc2b2ae35);
  h1 ^= h1 >> 16;

  return h1;
}
