/*!
 * blake2b.c - blake2b for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_BLAKE2B_H
#define _URKEL_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

/*
 * Structs
 */

typedef struct urkel_blake2b_s {
  uint64_t h[8];
  uint64_t t[2];
  unsigned char buf[128];
  size_t buflen;
  size_t outlen;
} urkel_blake2b_t;

/*
 * BLAKE2b
 */

void
urkel_blake2b_init(urkel_blake2b_t *ctx,
                   size_t outlen,
                   const unsigned char *key,
                   size_t keylen);
void
urkel_blake2b_update(urkel_blake2b_t *ctx, const void *data, size_t len);

void
urkel_blake2b_final(urkel_blake2b_t *ctx, unsigned char *out);

#endif /* _URKEL_BLAKE2B_H */
