/*!
 * io_win.c - windows io for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 *
 * Parts of this software are based on libuv/libuv:
 *   Copyright (c) 2015-2020, libuv project contributors (MIT License).
 *   https://github.com/libuv/libuv
 */

#undef WIN32_LEAN_AND_MEAN
#undef _WIN32_WINNT

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <io.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io.h"

#pragma comment(lib, "advapi32.lib") /* SystemFunction036 */
#pragma comment(lib, "kernel32.lib")

#define RtlGenRandom SystemFunction036

BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

/*
 * Helpers
 */

#define FILETIME_TO_UINT(filetime)                            \
  (*((uint64_t *)&(filetime)) - UINT64_C(116444736000000000))

#define FILETIME_TO_TIME_T(filetime)                \
  (FILETIME_TO_UINT(filetime) / UINT64_C(10000000))

#define FILETIME_TO_TIME_NS(filetime, secs)                          \
  ((FILETIME_TO_UINT(filetime) - (secs * UINT64_C(10000000))) * 100)

#define FILETIME_TO_TIMESPEC(ts, filetime) do {              \
  (ts).tv_sec = FILETIME_TO_TIME_T(filetime);                \
  (ts).tv_nsec = FILETIME_TO_TIME_NS(filetime, (ts).tv_sec); \
} while(0)

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

/*
 * Filesystem
 */

static int
urkel_fs__flags_api_to_os(int flags) {
  int out = 0;

#ifdef _O_RDONLY
  if (flags & URKEL_O_RDONLY)
    out |= _O_RDONLY;
#endif

#ifdef _O_WRONLY
  if (flags & URKEL_O_WRONLY)
    out |= _O_WRONLY;
#endif

#ifdef _O_RDWR
  if (flags & URKEL_O_RDWR)
    out |= _O_RDWR;
#endif

#ifdef _O_APPEND
  if (flags & URKEL_O_APPEND)
    out |= _O_APPEND;
#endif

#ifdef _O_CREAT
  if (flags & URKEL_O_CREAT)
    out |= _O_CREAT;
#endif

#ifdef _O_EXCL
  if (flags & URKEL_O_EXCL)
    out |= _O_EXCL;
#endif

#ifdef _O_TRUNC
  if (flags & URKEL_O_TRUNC)
    out |= _O_TRUNC;
#endif

#ifdef _O_SEQUENTIAL
  if (flags & URKEL_O_SEQUENTIAL)
    out |= _O_SEQUENTIAL;
#endif

#ifdef _O_RANDOM
  if (flags & URKEL_O_RANDOM)
    out |= _O_RANDOM;
#endif

#ifdef _O_NOINHERIT
  out |= _O_NOINHERIT; /* O_CLOEXEC */
#endif

  return out;
}

static uint32_t
urkel_fs__mode_api_to_os(uint32_t mode) {
  uint32_t out = 0;

#ifdef _S_IFBLK
  if (mode & URKEL_S_IFBLK)
    out |= _S_IFBLK;
#endif

#ifdef _S_IFCHR
  if (mode & URKEL_S_IFCHR)
    out |= _S_IFCHR;
#endif

#ifdef _S_IFIFO
  if (mode & URKEL_S_IFIFO)
    out |= _S_IFIFO;
#endif

#ifdef _S_IFREG
  if (mode & URKEL_S_IFREG)
    out |= _S_IFREG;
#endif

#ifdef _S_IFDIR
  if (mode & URKEL_S_IFDIR)
    out |= _S_IFDIR;
#endif

#ifdef _S_IREAD
  if (mode & URKEL_S_IRUSR)
    out |= _S_IREAD;
#endif

#ifdef _S_IWRITE
  if (mode & URKEL_S_IWUSR)
    out |= _S_IWRITE;
#endif

#ifdef _S_IEXEC
  if (mode & URKEL_S_IXUSR)
    out |= _S_IEXEC;
#endif

  return out;
}

int
urkel_fs_open(const char *name, int flags, uint32_t mode) {
  int wflags = urkel_fs__flags_api_to_os(flags);
  DWORD access;
  DWORD share;
  DWORD disposition;
  DWORD attributes;
  HANDLE handle;
  int fd;

  switch (flags & (URKEL_O_RDONLY | URKEL_O_WRONLY | URKEL_O_RDWR)) {
    case URKEL_O_RDONLY:
      access = FILE_GENERIC_READ;
      break;
    case URKEL_O_WRONLY:
      access = FILE_GENERIC_WRITE;
      break;
    case URKEL_O_RDWR:
      access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
      break;
    default:
      return -1;
  }

  if (flags & URKEL_O_APPEND) {
    access &= ~FILE_WRITE_DATA;
    access |= FILE_APPEND_DATA;
  }

  if (!(flags & URKEL_O_EXLOCK))
    share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  else
    share = 0;

  switch (flags & (URKEL_O_CREAT | URKEL_O_EXCL | URKEL_O_TRUNC)) {
    case 0:
    case URKEL_O_EXCL:
      disposition = OPEN_EXISTING;
      break;
    case URKEL_O_CREAT:
      disposition = OPEN_ALWAYS;
      break;
    case URKEL_O_CREAT | URKEL_O_EXCL:
    case URKEL_O_CREAT | URKEL_O_TRUNC | URKEL_O_EXCL:
      disposition = CREATE_NEW;
      break;
    case URKEL_O_TRUNC:
    case URKEL_O_TRUNC | URKEL_O_EXCL:
      disposition = TRUNCATE_EXISTING;
      break;
    case URKEL_O_CREAT | URKEL_O_TRUNC:
      disposition = CREATE_ALWAYS;
      break;
    default:
      return -1;
  }

  attributes = FILE_ATTRIBUTE_NORMAL;

  if (flags & URKEL_O_CREAT) {
    if (!(mode & URKEL_S_IWUSR))
      attributes |= FILE_ATTRIBUTE_READONLY;
  }

  switch (flags & (URKEL_O_SEQUENTIAL | URKEL_O_RANDOM)) {
    case 0:
      break;
    case URKEL_O_SEQUENTIAL:
      attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
      break;
    case URKEL_O_RANDOM:
      attributes |= FILE_FLAG_RANDOM_ACCESS;
      break;
    default:
      return -1;
  }

  switch (flags & (URKEL_O_DSYNC | URKEL_O_SYNC)) {
    case 0:
      break;
    case URKEL_O_DSYNC:
    case URKEL_O_SYNC:
      attributes |= FILE_FLAG_WRITE_THROUGH;
      break;
    default:
      return -1;
  }

  attributes |= FILE_FLAG_BACKUP_SEMANTICS;

  handle = CreateFileA(name, access, share, NULL,
                       disposition, attributes, NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  fd = _open_osfhandle((intptr_t)handle, wflags);

  if (fd < 0) {
    CloseHandle(handle);
    return -1;
  }

  return fd;
}

static int
urkel_fs__stat_handle(HANDLE handle, urkel_stat_t *st) {
  BY_HANDLE_FILE_INFORMATION info;
  ULARGE_INTEGER ul;

  if (!GetFileInformationByHandle(handle, &info))
    return 0;

  st->st_dev = info.dwVolumeSerialNumber;
  ul.LowPart = info.nFileIndexLow;
  ul.HighPart = info.nFileIndexHigh;
  st->st_ino = ul.QuadPart;
  st->st_mode = 0;
  st->st_nlink = info.nNumberOfLinks;
  st->st_uid = 0;
  st->st_gid = 0;
  st->st_rdev = 0;
  ul.LowPart = info.nFileSizeLow;
  ul.HighPart = info.nFileSizeHigh;
  st->st_size = ul.QuadPart;

  FILETIME_TO_TIMESPEC(st->st_atim, info.ftLastAccessTime);
  FILETIME_TO_TIMESPEC(st->st_ctim, info.ftCreationTime);
  FILETIME_TO_TIMESPEC(st->st_mtim, info.ftLastWriteTime);
  FILETIME_TO_TIMESPEC(st->st_birthtim, info.ftCreationTime);

  st->st_blksize = 4096;
  st->st_blocks = (st->st_size + 4095) / 4096;

  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    st->st_mode |= URKEL_S_IFDIR;
    st->st_size = 0;
  } else {
    st->st_mode |= URKEL_S_IFREG;
  }

  if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
    st->st_mode |= URKEL_S_IRUSR;
  else
    st->st_mode |= URKEL_S_IRUSR | URKEL_S_IWUSR;

  return 1;
}

static int
urkel_fs__stat_path(const char *name, urkel_stat_t *st, int soft) {
  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  HANDLE handle;
  int ret = 0;

  if (soft)
    flags |= FILE_FLAG_OPEN_REPARSE_POINT;

  handle = CreateFileA(name,
                       FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL,
                       OPEN_EXISTING,
                       flags,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    goto fail;

  if (!urkel_fs__stat_handle(handle, st))
    goto fail;

  ret = 1;
fail:
  CloseHandle(handle);
  return ret;
}

static int
urkel_fs__stat_impl(const char *name, urkel_stat_t *st, int soft) {
  if (urkel_fs__stat_path(name, st, soft))
    return 1;

  if (soft) {
    if (error == ERROR_SYMLINK_NOT_SUPPORTED
        || error == ERROR_NOT_A_REPARSE_POINT) {
      return urkel_fs__stat_path(name, st, 0);
    }
  }

  return 0;
}

int
urkel_fs_stat(const char *name, urkel_stat_t *out) {
  return urkel_fs__stat_impl(name, out, 0);
}

int
urkel_fs_lstat(const char *name, urkel_stat_t *out) {
  return urkel_fs__stat_impl(name, out, 1);
}


int
urkel_fs_chmod(const char *name, uint32_t mode) {
  return _chmod(name, urkel_fs__mode_api_to_os(mode)) != -1;
}

int
urkel_fs_truncate(const char *name, int64_t size) {
  int fd = urkel_fs_open(name, URKEL_O_WRONLY, 0);
  int ret;

  if (fd == -1)
    return 0;

  ret = urkel_fs_ftruncate(fd, size);

  urkel_fs_close(fd);

  return ret;
}

int
urkel_fs_rename(const char *oldpath, const char *newpath) {
  return MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING);
}

int
urkel_fs_unlink(const char *name) {
  return DeleteFileA(name);
}

int
urkel_fs_mkdir(const char *name, uint32_t mode) {
  (void)mode;
  return CreateDirectoryA(name, NULL);
}

int
urkel_fs_rmdir(const char *name) {
  return RemoveDirectoryA(name);
}

static int
urkel__dirent_compare(const void *x, const void *y) {
  const urkel_dirent_t *a = *((const urkel_dirent_t **)x);
  const urkel_dirent_t *b = *((const urkel_dirent_t **)y);

  return strcmp(a->d_name, b->d_name);
}

int
urkel_fs_scandir(const char *name, urkel_dirent_t ***out, size_t *count) {
  HANDLE handle = INVALID_HANDLE_VALUE;
  const char buf[URKEL_PATH_MAX + 1];
  size_t len = strlen(name);
  urkel_dirent_t **list = NULL;
  urkel_dirent_t *item = NULL;
  WIN32_FIND_DATAA fdata;
  const char *fmt;
  size_t size = 8;
  size_t i = 0;
  size_t j;

  if (len + 3 > URKEL_PATH_MAX)
    goto fail;

  list = malloc(size * sizeof(urkel_dirent_t *));

  if (list == NULL)
    goto fail;

  memcpy(buf, name, len);

  if (len == 0) {
    buf[len++] = '.';
    buf[len++] = '/';
    buf[len++] = '*';
    buf[len++] = '\0';
  } else if (name[len - 1] == '\\' || name[len - 1] == '/') {
    buf[len++] = '*';
    buf[len++] = '\0';
  } else {
    buf[len++] = '\\';
    buf[len++] = '*';
    buf[len++] = '\0';
  }

  handle = FindFirstFileA(buf, &fdata);

  if (handle == INVALID_HANDLE_VALUE)
    goto fail;

  do {
    if (strcmp(fdata.cFileName, ".") == 0
        || strcmp(fdata.cFileName, "..") == 0) {
      continue;
    }

    item = malloc(sizeof(urkel_dirent_t));

    if (item == NULL)
      goto fail;

    len = strlen(fdata.cFileName);

    if (len + 1 > sizeof(item->d_name))
      goto fail;

    if (i == size - 1) {
      size = (size * 3) / 2;
      list = realloc(list, size * sizeof(urkel_dirent_t *));

      if (list == NULL)
        goto fail;
    }

    item->d_ino = 0;

    memcpy(item->d_name, fdata.cFileName, len + 1);

    list[i++] = item;
    item = NULL;
  } while (FindNextFileA(handle, &fdata));

  if (GetLastError() != ERROR_NO_MORE_FILES)
    goto fail;

  list[i] = NULL;

  FindClose(handle);

  qsort(list, i, sizeof(urkel_dirent_t *), urkel__dirent_compare);

  *out = list;
  *count = i;

  return 1;
fail:
  for (j = 0; j < i; j++)
    free(list[j]);

  if (list != NULL)
    free(list);

  if (item != NULL)
    free(item);

  if (handle != INVALID_HANDLE_VALUE)
    FindClose(handle);

  *out = NULL;
  *count = 0;

  return 0;
}

int
urkel_fs_fstat(int fd, urkel_stat_t *out) {
  HANDLE handle = _get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  return urkel_fs__stat_handle(handle, out);
}

int64_t
urkel_fs_seek(int fd, int64_t pos, int whence) {
  HANDLE handle = _get_osfhandle(fd);
  LARGE_INTEGER ptr;
  DWORD method = 0;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  switch (whence) {
    case URKEL_SEEK_SET:
      method = FILE_BEGIN;
      break;
    case URKEL_SEEK_CUR:
      method = FILE_CURRENT;
      break;
    case URKEL_SEEK_END:
      method = FILE_END;
      break;
    default:
      abort();
      break;
  }

  if (!SetFilePointerEx(handle, pos, &ptr, method))
    return -1;

  return ptr.QuadPart;
}

int64_t
urkel_fs_tell(int fd) {
  return urkel_fs_seek(fd, 0, URKEL_SEEK_CUR);
}

int
urkel_fs_read(int fd, void *dst, size_t len) {
  HANDLE handle = _get_osfhandle(fd);
  unsigned char *raw = dst;
  DWORD nread;
  int result;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  while (len > 0) {
    result = ReadFile(handle, raw, len, &nread, NULL);

    if (!result)
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
  }

  return len == 0;
}

int
urkel_fs_write(int fd, const void *src, size_t len) {
  HANDLE handle = _get_osfhandle(fd);
  unsigned char *raw = src;
  DWORD nread;
  int result;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  while (len > 0) {
    result = WriteFile(handle, raw, len, &nread, NULL);

    if (!result)
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
  }

  return len == 0;
}

int
urkel_fs_pread(int fd, void *dst, size_t len, int64_t pos) {
  HANDLE handle = _get_osfhandle(fd);
  LARGE_INTEGER zero, old, pos_;
  unsigned char *raw = dst;
  OVERLAPPED overlap;
  int restore = 0;
  DWORD nread;
  int result;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  zero.QuadPart = 0;

  memset(&overlap, 0, sizeof(overlap));

  if (SetFilePointerEx(handle, zero, &old, FILE_CURRENT))
    restore = 1;

  while (len > 0) {
    pos_.QuadPart = pos;
    overlap.Offset = pos_.LowPart;
    overlap.OffsetHigh = pos_.HighPart;

    result = ReadFile(handle, raw, len, &nread, &overlap);

    if (!result)
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
    pos += nread;
  }

  if (restore)
    SetFilePointerEx(handle, old, NULL, FILE_BEGIN);

  return len == 0;
}

int
urkel_fs_pwrite(int fd, const void *src, size_t len, int64_t pos) {
  HANDLE handle = _get_osfhandle(fd);
  LARGE_INTEGER zero, old, pos_;
  unsigned char *raw = src;
  OVERLAPPED overlap;
  int restore = 0;
  DWORD nread;
  int result;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  zero.QuadPart = 0;

  memset(&overlap, 0, sizeof(overlap));

  if (SetFilePointerEx(handle, zero, &old, FILE_CURRENT))
    restore = 1;

  while (len > 0) {
    pos_.QuadPart = pos;
    overlap.Offset = pos_.LowPart;
    overlap.OffsetHigh = pos_.HighPart;

    result = WriteFile(handle, raw, len, &nread, &overlap);

    if (!result)
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
    pos += nread;
  }

  if (restore)
    SetFilePointerEx(handle, old, NULL, FILE_BEGIN);

  return len == 0;
}

int
urkel_fs_ftruncate(int fd, int64_t size) {
  HANDLE handle = _get_osfhandle(fd);
  LARGE_INTEGER pos;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  pos.QuadPart = size;

  if (!SetFilePointerEx(handle, pos, NULL, FILE_BEGIN))
    return 0;

  if (!SetEndOfFile(handle))
    return 0;

  return 1;
}

int
urkel_fs_fsync(int fd) {
  HANDLE handle = _get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  return FlushFileBuffers(handle);
}

int
urkel_fs_fdatasync(int fd) {
  return urkel_fs_fsync(fd);
}

int
urkel_fs_flock(int fd, int operation) {
  (void)fd;
  (void)operation;
  return 0;
}

int
urkel_fs_close(int fd) {
  return _close(fd) != -1;
}

int
urkel_fs_open_lock(const char *name, uint32_t mode) {
  int flags = URKEL_O_RDWR | URKEL_O_CREAT | URKEL_O_TRUNC | URKEL_O_EXLOCK;
  return urkel_fs_open(name, flags, mode);
}

void
urkel_fs_close_lock(int fd) {
  urkel_fs_close(fd);
}

/*
 * Process
 */

int
urkel_ps_cwd(char *buf, size_t size) {
  DWORD len;

  if (size < 2)
    return 0;

  len = GetCurrentDirectoryA(size, buf);

  return len >= 1 && len <= size - 1;
}

/*
 * Path
 */

char *
urkel_path_resolve(const char *path) {
  char buf[MAX_PATH + 1];
  DWORD len = GetFullPathNameA(path, buf, sizeof(buf), NULL);
  char *out;

  if (len < 1 || len > MAX_PATH)
    return 0;

  out = malloc(len + 1);

  if (out == NULL)
    return 0;

  memcpy(out, buf, len + 1);

  return out;
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

  handle = CreateSemaphoreA(NULL, 1, 1, NULL);

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
  free(mtx);
}

void
urkel_rwlock_wrlock(urkel__rwlock_t *mtx) {
  DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

  if (r != WAIT_OBJECT_0)
    abort();
}

void
urkel_rwlock_wrunlock(urkel__rwlock_t *mtx) {
  if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
    abort();
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
urkel_rwlock_rdunlock(urkel__rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (--mtx->readers == 0) {
    if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
      abort();
  }

  LeaveCriticalSection(&mtx->readers_lock);
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
