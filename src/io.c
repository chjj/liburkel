/*!
 * io.c - io for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#if defined(_WIN32)
#  include "io_win.c"
#else
#  include "io_posix.c"
#endif

/*
 * High-level Calls
 */

int
urkel_fs_read_file(const char *name, void *dst, size_t len) {
  int fd = urkel_fs_open(name, URKEL_O_RDONLY | URKEL_O_SEQUENTIAL, 0);
  int ret = 0;

  if (fd == -1)
    return 0;

  if (!urkel_fs_read(fd, dst, len))
    goto fail;

  ret = 1;
fail:
  urkel_fs_close(fd);
  return ret;
}

int
urkel_fs_write_file(const char *name,
                    uint32_t mode,
                    const void *dst,
                    size_t len) {
  int flags = URKEL_O_WRONLY | URKEL_O_CREAT | URKEL_O_TRUNC;
  int fd = urkel_fs_open(name, flags, mode);
  int ret = 0;

  if (fd == -1)
    return 0;

  if (!urkel_fs_write(fd, dst, len))
    goto fail;

  ret = 1;
fail:
  urkel_fs_close(fd);
  return ret;
}

int
urkel_fs_open_lock(const char *name, uint32_t mode) {
  int flags = URKEL_O_RDWR | URKEL_O_CREAT | URKEL_O_TRUNC;
  int fd = urkel_fs_open(name, flags, mode);

  if (fd == -1)
    return -1;

  if (!urkel_fs_flock(fd, URKEL_LOCK_EX)) {
    urkel_fs_close(fd);
    return -1;
  }

  return fd;
}

void
urkel_fs_close_lock(int fd) {
  urkel_fs_flock(fd, URKEL_LOCK_UN);
  urkel_fs_close(fd);
}
