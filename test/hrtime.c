/*!
 * hrtime.c - high-resolution time for liburkel tests
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
/* For clock_gettime(2). */
#  define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include "hrtime.h"

#undef HAVE_GETTIMEOFDAY

#if defined(_WIN32)
#  include <windows.h> /* QueryPerformance{Counter,Frequency} */
#  pragma comment(lib, "kernel32.lib")
#else /* !_WIN32 */
#  include <time.h> /* clock_gettime, time */
#  ifndef CLOCK_MONOTONIC
#    if defined(__unix) || defined(__unix__)     \
     || (defined(__APPLE__) && defined(__MACH__))
#      include <sys/time.h> /* gettimeofday */
#      define HAVE_GETTIMEOFDAY
#    endif
#  endif
#endif /* !_WIN32 */

uint64_t
urkel_hrtime(void) {
#if defined(_WIN32)
  static unsigned int scale = 1000000000;
  LARGE_INTEGER freq, ctr;
  double scaled, result;

  if (!QueryPerformanceFrequency(&freq))
    abort();

  if (!QueryPerformanceCounter(&ctr))
    abort();

  if (freq.QuadPart == 0)
    abort();

  /* We have no idea of the magnitude of `freq`,
   * so we must resort to double arithmetic[1].
   * Furthermore, we use some wacky arithmetic
   * to avoid a bug in Visual Studio 2019[2][3].
   *
   * [1] https://github.com/libuv/libuv/blob/7967448/src/win/util.c#L503
   * [2] https://github.com/libuv/libuv/issues/1633
   * [3] https://github.com/libuv/libuv/pull/2866
   */
  scaled = (double)freq.QuadPart / scale;
  result = (double)ctr.QuadPart / scaled;

  return (uint64_t)result;
#elif defined(CLOCK_MONOTONIC)
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    abort();

  return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
#elif defined(HAVE_GETTIMEOFDAY)
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
#else
  return (uint64_t)time(NULL) * 1000000000;
#endif
}
