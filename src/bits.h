#ifndef URKEL_BITS_H_
#define URKEL_BITS_H_

#include <stddef.h>
#include "util.h"

typedef struct urkel_bits_s {
  size_t size;
  unsigned char data[32];
} urkel_bits_t;

static URKEL_INLINE unsigned int
urkel_bits_get(const urkel_bits_t *bits, size_t index) {
  return urkel_get_bit(bits->data, index);
}

static URKEL_INLINE void
urkel_bits_set(urkel_bits_t *bits, size_t index, unsigned int bit) {
  return urkel_set_bit(bits->data, index, bit);
}

void
urkel_bits_init(urkel_bits_t *bits, size_t size);

size_t
urkel_bits_count(const urkel_bits_t *bits,
                  const unsigned char *key,
                  size_t depth);

int
urkel_bits_has(const urkel_bits_t *bits,
               const unsigned char *key,
               size_t depth);

void
urkel_bits_slice(const urkel_bits_t *bits,
                 urkel_bits_t *out,
                 size_t start,
                 size_t end);

void
urkel_bits_split(const urkel_bits_t *bits,
                 urkel_bits_t *left,
                 urkel_bits_t *right,
                 size_t index);

void
urkel_bits_collide(const urkel_bits_t *bits,
                   urkel_bits_t *out,
                   const unsigned char *key,
                   size_t depth);

void
urkel_bits_join(const urkel_bits_t *bits,
                urkel_bits_t *out,
                const urkel_bits_t *other,
                unsigned char bit);

size_t
urkel_bits_size(const urkel_bits_t *bits);

size_t
urkel_bits_write(const urkel_bits_t *bits, unsigned char *data, size_t off);

int
urkel_bits_read(urkel_bits_t *bits, const unsigned char **data, size_t *len);

#endif /* URKEL_BITS_H_ */
