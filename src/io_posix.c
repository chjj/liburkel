/*!
 * io_posix.c - posix io for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#undef HAVE_FLOCK

#if defined(__ANDROID__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__APPLE__)
#  undef _DARWIN_UNLIMITED_SELECT
#  undef _DARWIN_USE_64_BIT_INODE
#  define _DARWIN_UNLIMITED_SELECT 1
#  define _DARWIN_USE_64_BIT_INODE 1
#elif defined(__CYGWIN__) || defined(__MINGW32__)
#  undef _GNU_SOURCE
#  define _GNU_SOURCE
#elif defined(__HAIKU__)
#  undef _BSD_SOURCE
#  define _BSD_SOURCE
#elif defined(__linux__)
#  undef _GNU_SOURCE
#  undef _POSIX_C_SOURCE
#  define _GNU_SOURCE
#  define _POSIX_C_SOURCE 200112
#  define HAVE_FLOCK
#elif defined(_AIX) || defined(__OS400__)
#  undef _ALL_SOURCE
#  undef _LINUX_SOURCE_COMPAT
#  undef _THREAD_SAFE
#  undef _XOPEN_SOURCE
#  define _ALL_SOURCE
#  define _LINUX_SOURCE_COMPAT
#  define _THREAD_SAFE
#  define _XOPEN_SOURCE 500
#elif defined(__sun)
#  undef __EXTENSIONS__
#  undef _XOPEN_SOURCE
#  define __EXTENSIONS__
#  define _XOPEN_SOURCE 500
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#ifdef HAVE_FLOCK
#include <sys/file.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
#include <pthread.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io.h"

/*
 * Filesystem
 */

static int
urkel_fs__flags_api_to_os(int flags) {
  int out = 0;

#ifdef O_RDONLY
  if (flags & URKEL_O_RDONLY)
    out |= O_RDONLY;
#endif

#ifdef O_WRONLY
  if (flags & URKEL_O_WRONLY)
    out |= O_WRONLY;
#endif

#ifdef O_RDWR
  if (flags & URKEL_O_RDWR)
    out |= O_RDWR;
#endif

#ifdef O_APPEND
  if (flags & URKEL_O_APPEND)
    out |= O_APPEND;
#endif

#ifdef O_CREAT
  if (flags & URKEL_O_CREAT)
    out |= O_CREAT;
#endif

#ifdef O_DSYNC
  if (flags & URKEL_O_DSYNC)
    out |= O_DSYNC;
#endif

#ifdef O_EXCL
  if (flags & URKEL_O_EXCL)
    out |= O_EXCL;
#endif

#ifdef O_NOCTTY
  if (flags & URKEL_O_NOCTTY)
    out |= O_NOCTTY;
#endif

#ifdef O_NONBLOCK
  if (flags & URKEL_O_NONBLOCK)
    out |= O_NONBLOCK;
#endif

#ifdef O_RSYNC
  if (flags & URKEL_O_RSYNC)
    out |= O_RSYNC;
#endif

#ifdef O_SYNC
  if (flags & URKEL_O_SYNC)
    out |= O_SYNC;
#endif

#ifdef O_TRUNC
  if (flags & URKEL_O_TRUNC)
    out |= O_TRUNC;
#endif

  return out;
}

static uint32_t
urkel_fs__mode_api_to_os(uint32_t mode) {
  uint32_t out = 0;

#ifdef S_IFBLK
  if (mode & URKEL_S_IFBLK)
    out |= S_IFBLK;
#endif

#ifdef S_IFCHR
  if (mode & URKEL_S_IFCHR)
    out |= S_IFCHR;
#endif

#ifdef S_IFIFO
  if (mode & URKEL_S_IFIFO)
    out |= S_IFIFO;
#endif

#ifdef S_IFREG
  if (mode & URKEL_S_IFREG)
    out |= S_IFREG;
#endif

#ifdef S_IFDIR
  if (mode & URKEL_S_IFDIR)
    out |= S_IFDIR;
#endif

#ifdef S_IFLNK
  if (mode & URKEL_S_IFLNK)
    out |= S_IFLNK;
#endif

#ifdef S_IFSOCK
  if (mode & URKEL_S_IFSOCK)
    out |= S_IFSOCK;
#endif

#ifdef S_IRUSR
  if (mode & URKEL_S_IRUSR)
    out |= S_IRUSR;
#endif

#ifdef S_IWUSR
  if (mode & URKEL_S_IWUSR)
    out |= S_IWUSR;
#endif

#ifdef S_IXUSR
  if (mode & URKEL_S_IXUSR)
    out |= S_IXUSR;
#endif

#ifdef S_IRGRP
  if (mode & URKEL_S_IRGRP)
    out |= S_IRGRP;
#endif

#ifdef S_IWGRP
  if (mode & URKEL_S_IWGRP)
    out |= S_IWGRP;
#endif

#ifdef S_IXGRP
  if (mode & URKEL_S_IXGRP)
    out |= S_IXGRP;
#endif

#ifdef S_IROTH
  if (mode & URKEL_S_IROTH)
    out |= S_IROTH;
#endif

#ifdef S_IWOTH
  if (mode & URKEL_S_IWOTH)
    out |= S_IWOTH;
#endif

#ifdef S_IXOTH
  if (mode & URKEL_S_IXOTH)
    out |= S_IXOTH;
#endif

#ifdef S_ISUID
  if (mode & URKEL_S_ISUID)
    out |= S_ISUID;
#endif

#ifdef S_ISGID
  if (mode & URKEL_S_ISGID)
    out |= S_ISGID;
#endif

#ifdef S_ISVTX
  if (mode & URKEL_S_ISVTX)
    out |= S_ISVTX;
#endif

  return out;
}

static uint32_t
urkel_fs__mode_os_to_api(uint32_t mode) {
  uint32_t out = 0;

#ifdef S_IFBLK
  if (mode & S_IFBLK)
    out |= URKEL_S_IFBLK;
#endif

#ifdef S_IFCHR
  if (mode & S_IFCHR)
    out |= URKEL_S_IFCHR;
#endif

#ifdef S_IFIFO
  if (mode & S_IFIFO)
    out |= URKEL_S_IFIFO;
#endif

#ifdef S_IFREG
  if (mode & S_IFREG)
    out |= URKEL_S_IFREG;
#endif

#ifdef S_IFDIR
  if (mode & S_IFDIR)
    out |= URKEL_S_IFDIR;
#endif

#ifdef S_IFLNK
  if (mode & S_IFLNK)
    out |= URKEL_S_IFLNK;
#endif

#ifdef S_IFSOCK
  if (mode & S_IFSOCK)
    out |= URKEL_S_IFSOCK;
#endif

#ifdef S_IRUSR
  if (mode & S_IRUSR)
    out |= URKEL_S_IRUSR;
#endif

#ifdef S_IWUSR
  if (mode & S_IWUSR)
    out |= URKEL_S_IWUSR;
#endif

#ifdef S_IXUSR
  if (mode & S_IXUSR)
    out |= URKEL_S_IXUSR;
#endif

#ifdef S_IRGRP
  if (mode & S_IRGRP)
    out |= URKEL_S_IRGRP;
#endif

#ifdef S_IWGRP
  if (mode & S_IWGRP)
    out |= URKEL_S_IWGRP;
#endif

#ifdef S_IXGRP
  if (mode & S_IXGRP)
    out |= URKEL_S_IXGRP;
#endif

#ifdef S_IROTH
  if (mode & S_IROTH)
    out |= URKEL_S_IROTH;
#endif

#ifdef S_IWOTH
  if (mode & S_IWOTH)
    out |= URKEL_S_IWOTH;
#endif

#ifdef S_IXOTH
  if (mode & S_IXOTH)
    out |= URKEL_S_IXOTH;
#endif

#ifdef S_ISUID
  if (mode & S_ISUID)
    out |= URKEL_S_ISUID;
#endif

#ifdef S_ISGID
  if (mode & S_ISGID)
    out |= URKEL_S_ISGID;
#endif

#ifdef S_ISVTX
  if (mode & S_ISVTX)
    out |= URKEL_S_ISVTX;
#endif

  return out;
}

static void
urkel_fs__convert_stat(urkel_stat_t *dst, const struct stat *src) {
  dst->st_dev = src->st_dev;
  dst->st_ino = src->st_ino;
  dst->st_mode = urkel_fs__mode_os_to_api(src->st_mode);
  dst->st_nlink = src->st_nlink;
  dst->st_uid = src->st_uid;
  dst->st_gid = src->st_gid;
  dst->st_rdev = src->st_rdev;
  dst->st_size = src->st_size;
  /* From libuv. */
#if defined(__APPLE__)
  dst->st_atim.tv_sec = src->st_atimespec.tv_sec;
  dst->st_atim.tv_nsec = src->st_atimespec.tv_nsec;
  dst->st_mtim.tv_sec = src->st_mtimespec.tv_sec;
  dst->st_mtim.tv_nsec = src->st_mtimespec.tv_nsec;
  dst->st_ctim.tv_sec = src->st_ctimespec.tv_sec;
  dst->st_ctim.tv_nsec = src->st_ctimespec.tv_nsec;
#elif defined(__ANDROID__)
  dst->st_atim.tv_sec = src->st_atime;
  dst->st_atim.tv_nsec = src->st_atimensec;
  dst->st_mtim.tv_sec = src->st_mtime;
  dst->st_mtim.tv_nsec = src->st_mtimensec;
  dst->st_ctim.tv_sec = src->st_ctime;
  dst->st_ctim.tv_nsec = src->st_ctimensec;
#elif !defined(_AIX) && (defined(__DragonFly__)    \
                      || defined(__FreeBSD__)      \
                      || defined(__OpenBSD__)      \
                      || defined(__NetBSD__)       \
                      || defined(_GNU_SOURCE)      \
                      || defined(_BSD_SOURCE)      \
                      || defined(_SVID_SOURCE)     \
                      || defined(_XOPEN_SOURCE)    \
                      || defined(_DEFAULT_SOURCE))
  dst->st_atim.tv_sec = src->st_atim.tv_sec;
  dst->st_atim.tv_nsec = src->st_atim.tv_nsec;
  dst->st_mtim.tv_sec = src->st_mtim.tv_sec;
  dst->st_mtim.tv_nsec = src->st_mtim.tv_nsec;
  dst->st_ctim.tv_sec = src->st_ctim.tv_sec;
  dst->st_ctim.tv_nsec = src->st_ctim.tv_nsec;
#else
  dst->st_atim.tv_sec = src->st_atime;
  dst->st_atim.tv_nsec = 0;
  dst->st_mtim.tv_sec = src->st_mtime;
  dst->st_mtim.tv_nsec = 0;
  dst->st_ctim.tv_sec = src->st_ctime;
  dst->st_ctim.tv_nsec = 0;
#endif
  dst->st_blksize = src->st_blksize;
  dst->st_blocks = src->st_blocks;
}

static int
urkel_fs__open(const char *name, int flags_, uint32_t mode_) {
  int flags = urkel_fs__flags_api_to_os(flags_);
  uint32_t mode = urkel_fs__mode_api_to_os(mode_);
  int fd, r;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
  if (fd == -1)
    return fd;

  do {
    r = fcntl(fd, F_GETFD);
  } while (r == -1 && errno == EINTR);

  if (r == -1)
    return fd;

  flags = r | FD_CLOEXEC;

  do {
    r = fcntl(fd, F_SETFD, flags);
  } while (r == -1 && errno == EINTR);
#else
  (void)r;
#endif

  return fd;
}

int
urkel_fs_open(const char *name, int flags, uint32_t mode) {
  int fd;

  do {
    fd = urkel_fs__open(name, flags, mode);
  } while (fd == -1 && errno == EINTR);

  return fd;
}

int
urkel_fs_stat(const char *name, urkel_stat_t *out) {
  struct stat st;

  memset(out, 0, sizeof(*out));

  if (stat(name, &st) == 0) {
    urkel_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int
urkel_fs_lstat(const char *name, urkel_stat_t *out) {
  struct stat st;

  memset(out, 0, sizeof(*out));

  if (lstat(name, &st) == 0) {
    urkel_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int
urkel_fs_chmod(const char *name, uint32_t mode) {
  return chmod(name, urkel_fs__mode_api_to_os(mode)) == 0;
}

int
urkel_fs_truncate(const char *name, int64_t size) {
  return truncate(name, size) == 0;
}

int
urkel_fs_rename(const char *oldpath, const char *newpath) {
  return rename(oldpath, newpath) == 0;
}

int
urkel_fs_unlink(const char *name) {
  return unlink(name) == 0;
}

int
urkel_fs_mkdir(const char *name, uint32_t mode) {
  return mkdir(name, urkel_fs__mode_api_to_os(mode)) == 0;
}

int
urkel_fs_rmdir(const char *name) {
  return rmdir(name) == 0;
}

static int
urkel__dirent_compare(const void *x, const void *y) {
  const urkel_dirent_t *a = x;
  const urkel_dirent_t *b = y;

  return strcmp(a->d_name, b->d_name);
}

int
urkel_fs_scandir(const char *name, urkel_dirent_t ***out, size_t *count) {
  urkel_dirent_t **list = NULL;
  urkel_dirent_t *item = NULL;
  struct dirent *entry;
  size_t size = 8;
  DIR *dir = NULL;
  size_t i = 0;
  size_t len;
  size_t j;

  list = malloc(size * sizeof(urkel_dirent_t *));

  if (list == NULL)
    goto fail;

  dir = opendir(name);

  if (dir == NULL)
    goto fail;

  for (;;) {
    entry = readdir(dir);

    if (entry == NULL)
      break;

    if (strcmp(entry->d_name, ".") == 0
        || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    item = malloc(sizeof(urkel_dirent_t));

    if (item == NULL)
      goto fail;

    len = strlen(entry->d_name);

    if (len + 1 > sizeof(item->d_name))
      goto fail;

    if (i == size - 1) {
      size = (size * 3) / 2;
      list = realloc(list, size * sizeof(urkel_dirent_t *));

      if (list == NULL)
        goto fail;
    }

    item->d_ino = entry->d_ino;

    memcpy(item->d_name, entry->d_name, len + 1);

    list[i++] = item;
    item = NULL;
  }

  list[i] = NULL;

  closedir(dir);

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

  if (dir != NULL)
    closedir(dir);

  *out = NULL;
  *count = 0;

  return 0;
}

int
urkel_fs_fstat(int fd, urkel_stat_t *out) {
  struct stat st;

  memset(out, 0, sizeof(*out));

  if (fstat(fd, &st) == 0) {
    urkel_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int64_t
urkel_fs_seek(int fd, int64_t pos, int whence) {
  int w = 0;

  switch (whence) {
    case URKEL_SEEK_SET:
      w = SEEK_SET;
      break;
    case URKEL_SEEK_CUR:
      w = SEEK_CUR;
      break;
    case URKEL_SEEK_END:
      w = SEEK_END;
      break;
    default:
      abort();
      break;
  }

  return lseek(fd, pos, w);
}

int64_t
urkel_fs_tell(int fd) {
  return lseek(fd, 0, SEEK_CUR);
}

int
urkel_fs_read(int fd, void *dst, size_t len) {
  unsigned char *buf = dst;
  ssize_t nread;

  while (len > 0) {
    do {
      nread = read(fd, buf, len);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > len)
      abort();

    buf += nread;
    len -= nread;
  }

  return len == 0;
}

int
urkel_fs_write(int fd, const void *src, size_t len) {
  const unsigned char *buf = src;
  ssize_t nwrite;

  while (len > 0) {
    do {
      nwrite = write(fd, buf, len);
    } while (nwrite < 0 && (errno == EINTR || errno == EAGAIN));

    if (nwrite <= 0)
      break;

    if ((size_t)nwrite > len)
      abort();

    buf += nwrite;
    len -= nwrite;
  }

  return len == 0;
}

int
urkel_fs_pread(int fd, void *dst, size_t len, int64_t pos) {
  unsigned char *buf = dst;
  ssize_t nread;

  while (len > 0) {
    do {
      nread = pread(fd, buf, len, pos);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > len)
      abort();

    buf += nread;
    len -= nread;
    pos += nread;
  }

  return len == 0;
}

int
urkel_fs_pwrite(int fd, const void *src, size_t len, int64_t pos) {
  const unsigned char *buf = src;
  ssize_t nwrite;

#ifdef __APPLE__
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  if (pthread_mutex_lock(&lock) != 0)
    abort();
#endif

  while (len > 0) {
    do {
      nwrite = pwrite(fd, buf, len, pos);
    } while (nwrite < 0 && (errno == EINTR || errno == EAGAIN));

    if (nwrite <= 0)
      break;

    if ((size_t)nwrite > len)
      abort();

    buf += nwrite;
    len -= nwrite;
    pos += nwrite;
  }

#ifdef __APPLE__
  if (pthread_mutex_unlock(&lock) != 0)
    abort();
#endif

  return len == 0;
}

int
urkel_fs_ftruncate(int fd, int64_t size) {
  return ftruncate(fd, size) == 0;
}

int
urkel_fs_fsync(int fd) {
  /* From libuv. */
#if defined(__APPLE__)
  int r;

  r = fcntl(fd, F_FULLFSYNC);

  if (r != 0)
    r = fcntl(fd, 85 /* F_BARRIERFSYNC */);

  if (r != 0)
    r = fsync(fd);

  return r == 0;
#else
  return fsync(fd) == 0;
#endif
}

int
urkel_fs_fdatasync(int fd) {
  /* From libuv. */
#if defined(__linux__) || defined(__sun) || defined(__NetBSD__)
  return fdatasync(fd) == 0;
#elif defined(__APPLE__)
  return urkel_fs_fsync(fd);
#else
  return fsync(fd) == 0;
#endif
}

int
urkel_fs_flock(int fd, int operation) {
#if defined(HAVE_FLOCK)
  int op;

  switch (operation) {
    case URKEL_LOCK_SH:
      op = LOCK_SH;
      break;
    case URKEL_LOCK_EX:
      op = LOCK_EX;
      break;
    case URKEL_LOCK_UN:
      op = LOCK_UN;
      break;
    default:
      return 0;
  }

  return flock(fd, op) == 0;
#elif defined(F_SETLK)
  struct flock fl;
  int type;

  switch (operation) {
    case URKEL_LOCK_SH:
      type = F_RDLCK;
      break;
    case URKEL_LOCK_EX:
      type = F_WRLCK;
      break;
    case URKEL_LOCK_UN:
      type = F_UNLCK;
      break;
    default:
      return 0;
  }

  memset(&fl, 0, sizeof(fl));

  fl.l_type = type;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;
  fl.l_pid = 0;

  return fcntl(fd, F_SETLK, &fl) == 0;
#else
  return 1;
#endif
}

int
urkel_fs_close(int fd) {
  return close(fd) == 0;
}

/*
 * Process
 */

int
urkel_ps_cwd(char *buf, size_t size) {
  if (size < 2)
    return 0;

#if defined(__wasi__)
  buf[0] = '/';
  buf[1] = '\0';
#else
  if (getcwd(buf, size) == NULL)
    return 0;

  buf[size - 1] = '\0';
#endif

  return 1;
}

/*
 * Path
 */

char *
urkel_path_resolve(const char *path) {
  size_t plen = path != NULL ? strlen(path) : 0;
  size_t clen;
  char *out;

  while (plen > 1 && path[plen - 1] == '/')
    plen -= 1;

  if (plen > 0 && path[0] == '/') {
    out = malloc(plen + 1);

    if (out == NULL)
      return NULL;

    memcpy(out, path, plen + 1);
  } else {
    out = malloc(URKEL_PATH_MAX + 1);

    if (out == NULL)
      return NULL;

    if (!urkel_ps_cwd(out, URKEL_PATH_MAX + 1)) {
      free(out);
      return NULL;
    }

    if (plen == 0)
      return out;

    if (plen == 1 && path[0] == '.')
      return out;

    clen = strlen(out);

    if (clen + 1 + plen > URKEL_PATH_MAX) {
      free(out);
      return NULL;
    }

    out[clen] = '/';

    memcpy(out + clen + 1, path, plen + 1);
  }

  return out;
}

/*
 * Mutex
 */

#if defined(__EMSCRIPTEN__) || defined(__wasi__)
struct urkel_mutex_s {
  void *unused;
};

struct urkel_mutex_s *
urkel_mutex_create(void) {
  struct urkel_mutex_s *mtx = malloc(sizeof(struct urkel_mutex_s));

  if (mtx == NULL)
    abort();

  return mtx;
}

void
urkel_mutex_destroy(struct urkel_mutex_s *mtx) {
  free(mtx);
}

void
urkel_mutex_lock(struct urkel_mutex_s *mtx) {
  return;
}

void
urkel_mutex_unlock(struct urkel_mutex_s *mtx) {
  return;
}
#else
struct urkel_mutex_s {
  pthread_mutex_t handle;
};

struct urkel_mutex_s *
urkel_mutex_create(void) {
  struct urkel_mutex_s *mtx = malloc(sizeof(struct urkel_mutex_s));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort();

  return mtx;
}

void
urkel_mutex_destroy(struct urkel_mutex_s *mtx) {
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort();

  free(mtx);
}

void
urkel_mutex_lock(struct urkel_mutex_s *mtx) {
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort();
}

void
urkel_mutex_unlock(struct urkel_mutex_s *mtx) {
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort();
}
#endif

/*
 * Read-Write Lock
 */

#if defined(__EMSCRIPTEN__) || defined(__wasi__)
struct urkel_rwlock_s {
  void *unused;
};

struct urkel_rwlock_s *
urkel_rwlock_create(void) {
  struct urkel_rwlock_s *mtx = malloc(sizeof(struct urkel_rwlock_s));

  if (mtx == NULL)
    abort();

  return mtx;
}

void
urkel_rwlock_destroy(struct urkel_rwlock_s *mtx) {
  free(mtx);
}

void
urkel_rwlock_wrlock(struct urkel_rwlock_s *mtx) {
  return;
}

void
urkel_rwlock_rdlock(struct urkel_rwlock_s *mtx) {
  return;
}

void
urkel_rwlock_unlock(struct urkel_rwlock_s *mtx) {
  return;
}
#else
struct urkel_rwlock_s {
  pthread_rwlock_t handle;
};

struct urkel_rwlock_s *
urkel_rwlock_create(void) {
  struct urkel_rwlock_s *mtx = malloc(sizeof(struct urkel_rwlock_s));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

  if (pthread_rwlock_init(&mtx->handle, NULL) != 0)
    abort();

  return mtx;
}

void
urkel_rwlock_destroy(struct urkel_rwlock_s *mtx) {
  if (pthread_rwlock_destroy(&mtx->handle) != 0)
    abort();

  free(mtx);
}

void
urkel_rwlock_wrlock(struct urkel_rwlock_s *mtx) {
  if (pthread_rwlock_wrlock(&mtx->handle) != 0)
    abort();
}

void
urkel_rwlock_rdlock(struct urkel_rwlock_s *mtx) {
  if (pthread_rwlock_rdlock(&mtx->handle) != 0)
    abort();
}

void
urkel_rwlock_unlock(struct urkel_rwlock_s *mtx) {
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
}
#endif

/*
 * Time
 */

void
urkel_time_get(urkel_timespec_t *ts) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = (uint32_t)tv.tv_usec * 1000;
}
