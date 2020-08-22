/*!
 * utils.h - test utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_UTILS_H
#define _URKEL_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef ASSERT

#define ASSERT(expr) do {                                \
  if (!(expr))                                           \
    __urkel_test_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

static void
__urkel_test_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#endif /* _URKEL_UTILS_H */
