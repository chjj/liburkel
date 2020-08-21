#ifndef URKEL_IO_H_
#define URKEL_IO_H_

#include <stdint.h>

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
#  define URKEL_IS_ABS(s) 1
#else
#  define URKEL_PATH_SEP '/'
#  define URKEL_IS_SEP(c) ((c) == '/')
#  define URKEL_IS_ABS(s) ((s)[0] == '/')
#endif

typedef struct urkel_iovec_s {
  void *iov_base;
  size_t iov_len;
} urkel_iovec_t;

typedef struct urkel_timespec_s {
  int64_t /* time_t */ tv_sec;
  uint32_t /* long */ tv_nsec;
  uint32_t __reserved;
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

typedef struct urkel_mutex_s urkel_mutex_t;

struct urkel_rwlock_s;

typedef struct urkel_rwlock_s urkel_rwlock_t;

#endif /* URKEL_IO_H_ */
