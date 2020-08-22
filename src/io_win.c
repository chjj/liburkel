/*!
 * io_win.c - windows io for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io.h"

/*
 * Functions
 */

#define RtlGenRandom SystemFunction036

BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

#pragma comment(lib, "advapi32.lib")

/*
 * Structs
 */

typedef struct urkel_mutex_s {
  CRITICAL_SECTION handle;
} urkel__mutex_t;

typedef struct urkel_rwlock_s {
  unsigned int readers;
  CRITICAL_SECTION readers_lock;
  HANDLE write_semaphore;
} urkel__rwlock_t;

int
urkel_fs_open(const char *name, int flags, uint32_t mode) {
}

int
urkel_fs_stat(const char *name, urkel_stat_t *out) {
}

int
urkel_fs_lstat(const char *name, urkel_stat_t *out) {
}

int
urkel_fs_chmod(const char *name, uint32_t mode) {
}

int
urkel_fs_truncate(const char *name, int64_t size) {
}

int
urkel_fs_rename(const char *oldpath, const char *newpath) {
}

int
urkel_fs_unlink(const char *name) {
}

int
urkel_fs_mkdir(const char *name, uint32_t mode) {
}

int
urkel_fs_rmdir(const char *name) {
}

int
urkel_fs_scandir(const char *name, urkel_dirent_t ***out, size_t *count) {
}

int
urkel_fs_fstat(int fd, urkel_stat_t *out) {
}

int64_t
urkel_fs_seek(int fd, int64_t pos, int whence) {
}

int64_t
urkel_fs_tell(int fd) {
}

int
urkel_fs_read(int fd, void *dst, size_t len) {
}

int
urkel_fs_write(int fd, const void *src, size_t len) {
}

int
urkel_fs_pread(int fd, void *dst, size_t len, int64_t pos) {
}

int
urkel_fs_pwrite(int fd, const void *src, size_t len, int64_t pos) {
}

int
urkel_fs_ftruncate(int fd, int64_t size) {
}

int
urkel_fs_fsync(int fd) {
}

int
urkel_fs_fdatasync(int fd) {
}

int
urkel_fs_flock(int fd, int operation) {
}

int
urkel_fs_close(int fd) {
}

/*
 * Process
 */

int
urkel_ps_cwd(char *buf, size_t size) {
}

/*
 * Path
 */

char *
urkel_path_resolve(const char *path) {
}

/*
 * System
 */

int
urkel_sys_random(void *dst, size_t size) {
  return RtlGenRandom((PVOID)dst, (ULONG)size) == TRUE;
}

/*
 * Mutex
 */

urkel__mutex_t *
urkel_mutex_create(void) {
  urkel__mutex_t *mtx = malloc(sizeof(urkel__mutex_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

  InitializeCriticalSection(mtx->handle);

  return mtx;
}

void
urkel_mutex_destroy(urkel__mutex_t *mtx) {
  DeleteCriticalSection(mtx->handle);
  free(mtx);
}

void
urkel_mutex_lock(urkel__mutex_t *mtx) {
  EnterCriticalSection(mtx->handle);
}

void
urkel_mutex_unlock(urkel__mutex_t *mtx) {
  LeaveCriticalSection(mtx->handle);
}

/*
 * Read-Write Lock
 */

urkel__rwlock_t *
urkel_rwlock_create(void) {
  urkel__rwlock_t *mtx = malloc(sizeof(urkel__rwlock_t));
  HANDLE handle;

  if (mtx == NULL) {
    abort();
    return NULL;
  }

  handle = CreateSemaphoreW(NULL, 1, 1, NULL);

  if (handle == NULL)
    abort();

  mtx->write_semaphore = handle;

  InitializeCriticalSection(&mtx->readers_lock);

  mtx->readers = 0;

  return mtx;
}

void
urkel_rwlock_destroy(urkel__rwlock_t *mtx) {
  DeleteCriticalSection(&mtx->readers_lock);
  CloseHandle(mtx->write_semaphore);
}

void
urkel_rwlock_rdlock(urkel__rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (++mtx->readers == 1) {
    DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

    if (r != WAIT_OBJECT_0)
      abort();
  }

  LeaveCriticalSection(&mtx->readers_lock);
}

void
urkel_rwlock_wrlock(urkel__rwlock_t *mtx) {
  DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

  if (r != WAIT_OBJECT_0)
    abort();
}

void
urkel_rwlock_rdunlock(urkel__rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (--mtx->readers == 0) {
    if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
      abort();
  }

  LeaveCriticalSection(&mtx->readers_lock);
}

void
urkel_rwlock_wrunlock(urkel__rwlock_t *mtx) {
  if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
    abort();
}

/*
 * Time
 */

void
urkel_time_get(urkel_timespec_t *ts) {
  /* We borrow some more code from libuv[1] in order
   * to convert NT time to unix time. Note that the
   * libuv code was originally based on postgres[2].
   *
   * NT's epoch[3] begins on January 1st, 1601: 369
   * years earlier than the unix epoch.
   *
   * [1] https://github.com/libuv/libuv/blob/7967448/src/win/util.c#L1942
   * [2] https://doxygen.postgresql.org/gettimeofday_8c_source.html
   * [3] https://en.wikipedia.org/wiki/Epoch_(computing)
   */
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;
  FILETIME ft;
  uint64_t ns;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  ns = (uint64_t)(ul.QuadPart - epoch) * 100;

  ts->tv_sec = ns / UINT64_C(1000000000);
  ts->tv_nsec = ns % UINT64_C(1000000000);
}
