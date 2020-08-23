/*!
 * utils.h - test utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_UTILS_H
#define _URKEL_UTILS_H

#include <stddef.h>

#undef ASSERT

#define ASSERT(expr) do {                                \
  if (!(expr))                                           \
    __urkel_test_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifdef __wasi__
#  define URKEL_PATH "/urkel_db_test"
#else
#  define URKEL_PATH "./urkel_db_test"
#endif

typedef struct urkel_kv_s {
  unsigned char key[32];
  unsigned char value[64];
} urkel_kv_t;

void
__urkel_test_assert_fail(const char *file, int line, const char *expr);

urkel_kv_t *
urkel_kv_generate(size_t len);

void
urkel_kv_free(urkel_kv_t *kvs);

urkel_kv_t *
urkel_kv_dup(urkel_kv_t *kvs, size_t len);

void
urkel_kv_sort(urkel_kv_t *kvs, size_t len);

#endif /* _URKEL_UTILS_H */
