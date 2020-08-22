/*!
 * io.h - io for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef URKEL_IO_H_
#define URKEL_IO_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Defines
 */

#define URKEL_O_RDONLY   (1 <<  0)
#define URKEL_O_WRONLY   (1 <<  1)
#define URKEL_O_RDWR     (1 <<  2)
#define URKEL_O_APPEND   (1 <<  3)
#define URKEL_O_CREAT    (1 <<  4)
#define URKEL_O_DSYNC    (1 <<  5)
#define URKEL_O_EXCL     (1 <<  6)
#define URKEL_O_NOCTTY   (1 <<  7)
#define URKEL_O_NONBLOCK (1 <<  8)
#define URKEL_O_RSYNC    (1 <<  9)
#define URKEL_O_SYNC     (1 << 10)
#define URKEL_O_TRUNC    (1 << 11)

#define URKEL_S_IFMT   00170000
#define URKEL_S_IFBLK  0060000
#define URKEL_S_IFCHR  0020000
#define URKEL_S_IFIFO  0010000
#define URKEL_S_IFREG  0100000
#define URKEL_S_IFDIR  0040000
#define URKEL_S_IFLNK  0120000
#define URKEL_S_IFSOCK 0140000

#define URKEL_S_IRWXU  00700
#define URKEL_S_IRUSR  00400
#define URKEL_S_IWUSR  00200
#define URKEL_S_IXUSR  00100

#define URKEL_S_IRWXG  00070
#define URKEL_S_IRGRP  00040
#define URKEL_S_IWGRP  00020
#define URKEL_S_IXGRP  00010

#define URKEL_S_IRWXO  00007
#define URKEL_S_IROTH  00004
#define URKEL_S_IWOTH  00002
#define URKEL_S_IXOTH  00001

#define URKEL_S_ISUID  0004000
#define URKEL_S_ISGID  0002000
#define URKEL_S_ISVTX  0001000

#define URKEL_S_ISLNK(m)  (((m) & URKEL_S_IFMT) == URKEL_S_IFLNK)
#define URKEL_S_ISREG(m)  (((m) & URKEL_S_IFMT) == URKEL_S_IFREG)
#define URKEL_S_ISDIR(m)  (((m) & URKEL_S_IFMT) == URKEL_S_IFDIR)
#define URKEL_S_ISCHR(m)  (((m) & URKEL_S_IFMT) == URKEL_S_IFCHR)
#define URKEL_S_ISBLK(m)  (((m) & URKEL_S_IFMT) == URKEL_S_IFBLK)
#define URKEL_S_ISFIFO(m) (((m) & URKEL_S_IFMT) == URKEL_S_IFIFO)
#define URKEL_S_ISSOCK(m) (((m) & URKEL_S_IFMT) == URKEL_S_IFSOCK)

#define URKEL_SEEK_SET 0
#define URKEL_SEEK_CUR 1
#define URKEL_SEEK_END 2

#define URKEL_LOCK_SH 0
#define URKEL_LOCK_EX 1
#define URKEL_LOCK_UN 2

#define URKEL_NSEC(ts) \
  ((uint64_t)(ts)->tv_sec * 1000000000 + (uint64_t)(ts)->tv_nsec)

#define URKEL_PATH_LEN 1024
#define URKEL_PATH_SIZE (URKEL_PATH_LEN + 1)

#if defined(_WIN32)
#  define URKEL_PATH_SEP '\\'
#  define URKEL_IS_SEP(c) ((c) == '\\' || (c) == '/')
#else
#  define URKEL_PATH_SEP '/'
#  define URKEL_IS_SEP(c) ((c) == '/')
#endif

/*
 * Structs
 */

typedef struct urkel_iovec_s {
  void *iov_base;
  size_t iov_len;
} urkel_iovec_t;

typedef struct urkel_timespec_s {
  int64_t /* time_t */ tv_sec;
  uint32_t /* long */ tv_nsec;
} urkel_timespec_t;

typedef struct urkel_stat_s {
  uint64_t /* dev_t */ st_dev;
  uint64_t /* ino_t */ st_ino;
  uint32_t /* mode_t */ st_mode;
  uint64_t /* nlink_t */ st_nlink;
  uint32_t /* uid_t */ st_uid;
  uint32_t /* gid_t */ st_gid;
  uint64_t /* dev_t */ st_rdev;
  int64_t /* off_t */ st_size;
  urkel_timespec_t /* time_t */ st_atim;
  urkel_timespec_t /* time_t */ st_mtim;
  urkel_timespec_t /* time_t */ st_ctim;
  int64_t /* blksize_t */ st_blksize;
  int64_t /* blkcnt_t */ st_blocks;
} urkel_stat_t;

typedef struct urkel_dirent_s {
  uint64_t d_ino;
  char d_name[256];
} urkel_dirent_t;

struct urkel_mutex_s;
struct urkel_rwlock_s;

typedef struct urkel_mutex_s urkel_mutex_t;
typedef struct urkel_rwlock_s urkel_rwlock_t;

/*
 * Filesystem
 */

int
urkel_fs_open(const char *name, int flags, uint32_t mode);

int
urkel_fs_stat(const char *name, urkel_stat_t *out);

int
urkel_fs_lstat(const char *name, urkel_stat_t *out);

int
urkel_fs_chmod(const char *name, uint32_t mode);

int
urkel_fs_truncate(const char *name, int64_t size);

int
urkel_fs_rename(const char *oldpath, const char *newpath);

int
urkel_fs_unlink(const char *name);

int
urkel_fs_mkdir(const char *name, uint32_t mode);

int
urkel_fs_rmdir(const char *name);

int
urkel_fs_scandir(const char *name, urkel_dirent_t ***out, size_t *count);

int
urkel_fs_fstat(int fd, urkel_stat_t *out);

int64_t
urkel_fs_seek(int fd, int64_t pos, int whence);

int64_t
urkel_fs_tell(int fd);

int
urkel_fs_read(int fd, void *dst, size_t len);

int
urkel_fs_write(int fd, const void *src, size_t len);

int
urkel_fs_pread(int fd, void *dst, size_t len, int64_t pos);

int
urkel_fs_pwrite(int fd, const void *src, size_t len, int64_t pos);

int
urkel_fs_ftruncate(int fd, int64_t size);

int
urkel_fs_fsync(int fd);

int
urkel_fs_fdatasync(int fd);

int
urkel_fs_flock(int fd, int operation);

int
urkel_fs_close(int fd);

/*
 * Mutex
 */

urkel_mutex_t *
urkel_mutex_create(void);

void
urkel_mutex_destroy(urkel_mutex_t *mtx);

void
urkel_mutex_lock(urkel_mutex_t *mtx);

void
urkel_mutex_unlock(urkel_mutex_t *mtx);

/*
 * Read-Write Lock
 */

urkel_rwlock_t *
urkel_rwlock_create(void);

void
urkel_rwlock_destroy(urkel_rwlock_t *mtx);

void
urkel_rwlock_wrlock(urkel_rwlock_t *mtx);

void
urkel_rwlock_rdlock(urkel_rwlock_t *mtx);

void
urkel_rwlock_unlock(urkel_rwlock_t *mtx);

/*
 * Time
 */

void
urkel_time_get(urkel_timespec_t *ts);

/*
 * High-level Calls
 */

int
urkel_fs_read_file(const char *name, void *dst, size_t len);

int
urkel_fs_write_file(const char *name,
                    uint32_t mode,
                    const void *dst,
                    size_t len);

int
urkel_fs_open_lock(const char *name, uint32_t mode);

void
urkel_fs_close_lock(int fd);

int
urkel_fs_exists(const char *name);

#endif /* URKEL_IO_H_ */
