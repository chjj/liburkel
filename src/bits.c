#include <stdlib.h>
#include <string.h>
#include "bits.h"

void
urkel_bits_init(urkel_bits_t *bits, size_t size) {
  bits->size = size;
  memset(bits->data, 0, sizeof(bits->data));
}

static size_t
urkel_bits__count(const urkel_bits_t *bits,
                  size_t index,
                  const unsigned char *key,
                  size_t depth) {
  size_t x = bits->size - index;
  size_t y = URKEL_KEY_BITS - depth;
  size_t len = x < y ? x : y;
  size_t count = 0;
  size_t i;

  for (i = 0; i < len; i++) {
    if (urkel_bits_get(bits, index) != urkel_get_bit(key, depth))
      break;

    index += 1;
    depth += 1;
    count += 1;
  }

  return count;
}

size_t
urkel_bits_count(const urkel_bits_t *bits,
                  const unsigned char *key,
                  size_t depth) {
  return urkel_bits__count(bits, 0, key, depth);
}

int
urkel_bits_has(const urkel_bits_t *bits,
               const unsigned char *key,
               size_t depth) {
  return urkel_bits_count(bits, key, depth) == bits->size;
}

void
urkel_bits_slice(urkel_bits_t *out,
                 const urkel_bits_t *bits,
                 size_t start,
                 size_t end) {
  size_t size = end - start;
  size_t i, j;

  urkel_bits_init(out, size);

  for (i = 0, j = start; j < end; i++, j++)
    urkel_bits_set(out, i, urkel_bits_get(bits, j));
}

void
urkel_bits_split(urkel_bits_t *left,
                 urkel_bits_t *right,
                 const urkel_bits_t *bits,
                 size_t index) {
  urkel_bits_slice(left, bits, 0, index);
  urkel_bits_slice(right, bits, index + 1, bits->size);
}

void
urkel_bits_collide(urkel_bits_t *out,
                   const urkel_bits_t *bits,
                   const unsigned char *key,
                   size_t depth) {
  size_t size = urkel_bits__count(bits, depth, key, depth);

  urkel_bits_slice(out, bits, depth, depth + size);
}

void
urkel_bits_join(urkel_bits_t *out,
                const urkel_bits_t *left,
                const urkel_bits_t *right,
                unsigned char bit) {
  size_t size = left->size + right->size + 1;
  size_t bytes = (left->size + 7) / 8;
  size_t i, j;

  urkel_bits_init(out, size);

  memcpy(out->data, left->data, bytes);

  urkel_bits_set(out, left->size, bit);

  for (i = left->size + 1, j = 0; j < right->size; i++, j++)
    urkel_bits_set(out, i, urkel_bits_get(right, j));
}

size_t
urkel_bits_size(const urkel_bits_t *bits) {
  size_t size = 0;

  if (bits->size >= 0x80)
    size += 1;

  size += 1;
  size += (bits->size + 7) / 8;

  return size;
}

unsigned char *
urkel_bits_write(const urkel_bits_t *bits, unsigned char *data) {
  size_t bytes = (bits->size + 7) / 8;

  if (bits->size >= 0x80)
    *data++ = 0x80 | (bits->size >> 8);

  *data++ = bits->size;

  memcpy(data, bits->data, bytes);
  data += bytes;

  return data;
}

int
urkel_bits_read(urkel_bits_t *bits, const unsigned char *data, size_t len) {
  size_t size, bytes;

  urkel_bits_init(bits, 0);

  if (len < 1)
    return 0;

  size = *data;
  data += 1;
  len -= 1;

  if (size & 0x80) {
    if (len < 1)
      return 0;

    size &= ~0x80;
    size <<= 8;
    size |= *data;

    if (size < 0x80)
      return 0;

    data += 1;
    len -= 1;
  }

  bytes = (size + 7) / 8;

  if (len < bytes)
    return 0;

  memcpy(bits->data, data, bytes);

  return 1;
}
