/*!
 * bits.h - bits management for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_BITS_H
#define _URKEL_BITS_H

#include <stddef.h>
#include "internal.h"

/*
 * Structs
 */

typedef struct urkel_bits_s {
  size_t size;
  unsigned char data[32];
} urkel_bits_t;

/*
 * Bits
 */

void
urkel_bits_init(urkel_bits_t *bits, size_t size);

size_t
urkel_bits_count(const urkel_bits_t *bits,
                  const unsigned char *key,
                  unsigned int depth);

int
urkel_bits_has(const urkel_bits_t *bits,
               const unsigned char *key,
               unsigned int depth);

void
urkel_bits_slice(urkel_bits_t *out,
                 const urkel_bits_t *bits,
                 size_t start,
                 size_t end);

void
urkel_bits_split(urkel_bits_t *left,
                 urkel_bits_t *right,
                 const urkel_bits_t *bits,
                 size_t index);

void
urkel_bits_collide(urkel_bits_t *out,
                   const urkel_bits_t *bits,
                   const unsigned char *key,
                   unsigned int depth);

void
urkel_bits_join(urkel_bits_t *out,
                const urkel_bits_t *left,
                const urkel_bits_t *right,
                unsigned int bit);

size_t
urkel_bits_size(const urkel_bits_t *bits);

unsigned char *
urkel_bits_write(const urkel_bits_t *bits, unsigned char *data);

int
urkel_bits_read(urkel_bits_t *bits, const unsigned char *data, size_t len);

static URKEL_INLINE unsigned int
urkel_get_bit(const unsigned char *key, size_t index) {
  return (key[index >> 3] >> (7 - (index & 7))) & 1;
}

static URKEL_INLINE void
urkel_set_bit(unsigned char *key, size_t index, unsigned int bit) {
  key[index >> 3] |= (bit & 1) << (7 - (index & 7));
}

static URKEL_INLINE unsigned int
urkel_bits_get(const urkel_bits_t *bits, size_t index) {
  return urkel_get_bit(bits->data, index);
}

static URKEL_INLINE void
urkel_bits_set(urkel_bits_t *bits, size_t index, unsigned int bit) {
  urkel_set_bit(bits->data, index, bit);
}

#endif /* _URKEL_BITS_H */
