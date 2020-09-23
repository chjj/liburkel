/*!
 * internal.h - internal utils for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_INTERNAL_H
#define _URKEL_INTERNAL_H

#include <stdlib.h>

/*
 * Clang Compat
 */

#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

/*
 * GNUC Compat
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#  define URKEL_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define URKEL_GNUC_PREREQ(maj, min) 0
#endif

/*
 * Builtins
 */

#undef LIKELY
#undef UNLIKELY

#if URKEL_GNUC_PREREQ(3, 0) || __has_builtin(__builtin_expect)
#  define LIKELY(x) __builtin_expect(!!(x), 1)
#  define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#endif

/*
 * Sanity Checks
 */

#undef CHECK_ALWAYS
#undef CHECK

#define CHECK_ALWAYS(expr) do { \
  if (UNLIKELY(!(expr)))        \
    __urkel_abort();          \
} while (0)

#if !defined(URKEL_COVERAGE)
#  define CHECK(expr) CHECK_ALWAYS(expr)
#else
#  define CHECK(expr) do { (void)(expr); } while (0)
#endif

/*
 * Assertions
 */

#undef ASSERT_ALWAYS
#undef ASSERT

#define ASSERT_ALWAYS(expr) do {                      \
  if (UNLIKELY(!(expr)))                              \
    __urkel_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#if defined(URKEL_DEBUG) && !defined(URKEL_COVERAGE)
#  define ASSERT(expr) ASSERT_ALWAYS(expr)
#else
#  define ASSERT(expr) do { (void)(expr); } while (0)
#endif

/*
 * Keywords/Attributes
 */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#  define URKEL_INLINE inline
#elif URKEL_GNUC_PREREQ(2, 7)
#  define URKEL_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define URKEL_INLINE __inline
#else
#  define URKEL_INLINE
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define URKEL_NORETURN _Noreturn
#elif URKEL_GNUC_PREREQ(2, 7)
#  undef noreturn
#  define URKEL_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  undef noreturn
#  define URKEL_NORETURN __declspec(noreturn)
#else
#  define URKEL_NORETURN
#endif

#if URKEL_GNUC_PREREQ(2, 7)
#  define URKEL_UNUSED __attribute__((unused))
#else
#  define URKEL_UNUSED
#endif

#define kh_inline URKEL_INLINE
#define kh_unused URKEL_UNUSED

/*
 * Helpers
 */

#define urkel_abort __urkel_abort

#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER)
/* Avoid a GCC bug: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189 */
#  define urkel_memcmp __urkel_memcmp
#else
#  include <string.h>
#  define urkel_memcmp memcmp
#endif

URKEL_NORETURN void
__urkel_assert_fail(const char *file, int line, const char *expr);

URKEL_NORETURN void
__urkel_abort(void);

int
__urkel_memcmp(const void *s1, const void *s2, size_t n);

static URKEL_INLINE void *
checked_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    urkel_abort();

  return ptr;
}

static URKEL_INLINE void *
checked_realloc(void *ptr, size_t size) {
  ptr = realloc(ptr, size);

  if (ptr == NULL)
    urkel_abort();

  return ptr;
}

/*
 * Constants
 */

#define URKEL_HASH_SIZE 32
#define URKEL_KEY_SIZE 32
#define URKEL_KEY_BITS 256
#define URKEL_VALUE_SIZE 1024

/* 17958 */
#define URKEL_PROOF_SIZE (0        \
  + 2                              \
  + 2                              \
  + URKEL_KEY_SIZE                 \
  + URKEL_KEY_BITS * (2 + 32 + 32) \
  + 2                              \
  + URKEL_VALUE_SIZE               \
)

#endif /* _URKEL_INTERNAL_H */
