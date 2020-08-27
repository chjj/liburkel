/*!
 * util.h - utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_UTIL_H
#define _URKEL_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "bits.h"
#include "internal.h"

/*
 * Hashing
 */

void
urkel_hash_internal(unsigned char *out,
                    const urkel_bits_t *prefix,
                    const unsigned char *left,
                    const unsigned char *right);

void
urkel_hash_leaf(unsigned char *out,
                const unsigned char *key,
                const unsigned char *vhash);

void
urkel_hash_value(unsigned char *out,
                 const unsigned char *key,
                 const unsigned char *value,
                 size_t size);

void
urkel_hash_key(unsigned char *out, const void *key, size_t size);

void
urkel_hash_raw(unsigned char *out, const void *key, size_t size);

/*
 * String Functions
 */

int
urkel_parse_u32(uint32_t *out, const char *str);

void
urkel_serialize_u32(char *out, uint32_t num);

/*
 * Helpers
 */

void
urkel_random_bytes(void *dst, size_t len);

unsigned char *
urkel_checksum(unsigned char *out,
               const unsigned char *data,
               size_t len,
               const unsigned char *key);

uint32_t
urkel_murmur3(const unsigned char *data, size_t len, uint32_t seed);

/*
 * Buffer I/O
 */

static URKEL_INLINE uint8_t *
urkel_write8(uint8_t *dst, uint8_t word) {
  dst[0] = word;
  return dst + 1;
}

static URKEL_INLINE uint8_t *
urkel_write16(uint8_t *dst, uint16_t word) {
  dst[0] = word >> 0;
  dst[1] = word >> 8;
  return dst + 2;
}

static URKEL_INLINE uint8_t *
urkel_write32(uint8_t *dst, uint32_t word) {
  dst[0] = word >>  0;
  dst[1] = word >>  8;
  dst[2] = word >> 16;
  dst[3] = word >> 24;
  return dst + 4;
}

static URKEL_INLINE uint8_t *
urkel_write64(uint8_t *dst, uint64_t word) {
  dst[0] = word >>  0;
  dst[1] = word >>  8;
  dst[2] = word >> 16;
  dst[3] = word >> 24;
  dst[4] = word >> 32;
  dst[5] = word >> 40;
  dst[6] = word >> 48;
  dst[7] = word >> 56;
  return dst + 8;
}

static URKEL_INLINE unsigned char *
urkel_write(unsigned char *dst, const unsigned char *src, size_t size) {
  if (size > 0)
    memcpy(dst, src, size);

  return dst + size;
}

static URKEL_INLINE uint8_t
urkel_read8(const uint8_t *src) {
  return src[0];
}

static URKEL_INLINE uint16_t
urkel_read16(const uint8_t *src) {
  return ((uint16_t)src[1] << 8)
       | ((uint16_t)src[0] << 0);
}

static URKEL_INLINE uint32_t
urkel_read32(const uint8_t *src) {
  return ((uint32_t)src[3] << 24)
       | ((uint32_t)src[2] << 16)
       | ((uint32_t)src[1] << 8)
       | ((uint32_t)src[0] << 0);
}

static URKEL_INLINE uint64_t
urkel_read64(const uint8_t *src) {
  return ((uint64_t)src[7] << 56)
       | ((uint64_t)src[6] << 48)
       | ((uint64_t)src[5] << 40)
       | ((uint64_t)src[4] << 32)
       | ((uint64_t)src[3] << 24)
       | ((uint64_t)src[2] << 16)
       | ((uint64_t)src[1] <<  8)
       | ((uint64_t)src[0] <<  0);
}

static URKEL_INLINE void
urkel_read(unsigned char *dst, const unsigned char *src, size_t size) {
  if (size > 0)
    memcpy(dst, src, size);
}

#endif /* _URKEL_UTIL_H */
