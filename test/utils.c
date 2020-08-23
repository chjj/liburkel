/*!
 * utils.c - test utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urkel.h>
#include "utils.h"

void
__urkel_test_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

static int
urkel_kv_compare(const void *x, const void *y) {
  const unsigned char *a = ((const urkel_kv_t *)x)->key;
  const unsigned char *b = ((const urkel_kv_t *)y)->key;
  return memcmp(a, b, 32);
}

urkel_kv_t *
urkel_kv_generate(size_t len) {
  urkel_kv_t *kvs = malloc(len * sizeof(urkel_kv_t));
  unsigned char seed[4];
  size_t i;

  ASSERT(kvs != NULL);

  for (i = 0; i < len; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;

    seed[0] = (i >>  0) & 0xff;
    seed[1] = (i >>  8) & 0xff;
    seed[2] = (i >> 16) & 0xff;
    seed[3] = (i >> 24) & 0xff;

    urkel_hash(key, seed, 4);

    urkel_hash(value +  0, key, 32);
    urkel_hash(value + 32, value, 32);
  }

  return kvs;
}

void
urkel_kv_free(urkel_kv_t *kvs) {
  free(kvs);
}

urkel_kv_t *
urkel_kv_dup(urkel_kv_t *kvs, size_t len) {
  urkel_kv_t *out = malloc(len * sizeof(urkel_kv_t));

  ASSERT(out != NULL);

  memcpy(out, kvs, len * sizeof(urkel_kv_t));

  return out;
}

void
urkel_kv_sort(urkel_kv_t *kvs, size_t len) {
  qsort(kvs, len, sizeof(urkel_kv_t), urkel_kv_compare);
}
