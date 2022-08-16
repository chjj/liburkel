/*!
 * urkel.h - urkel tree database
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_H
#define _URKEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Visibility
 */

#ifdef URKEL_BUILD
#  if defined(__EMSCRIPTEN__)
#    include <emscripten.h>
#    define URKEL_EXTERN EMSCRIPTEN_KEEPALIVE
#  elif defined(__wasm__)
#    define URKEL_EXTERN __attribute__((visibility("default")))
#  elif defined(_MSC_VER) || defined(__BORLANDC__)
#    define URKEL_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define URKEL_EXTERN __attribute__((visibility("default")))
#  elif defined(__SUNPRO_C) && __SUNPRO_C >= 0x550
#    define URKEL_EXTERN __global
#  endif
#endif

#ifndef URKEL_EXTERN
#  define URKEL_EXTERN
#endif

/*
 * Structs
 */

struct urkel_s;
struct urkel_tx_s;
struct urkel_iter_s;

typedef struct urkel_s urkel_t;
typedef struct urkel_tx_s urkel_tx_t;
typedef struct urkel_iter_s urkel_iter_t;

/*
 * Error Number
 */

URKEL_EXTERN int *
__urkel_get_errno(void);

#define urkel_errno (*__urkel_get_errno())

#define URKEL_EHASHMISMATCH 1
#define URKEL_ESAMEKEY 2
#define URKEL_ESAMEPATH 3
#define URKEL_ENEGDEPTH 4
#define URKEL_EPATHMISMATCH 5
#define URKEL_ETOODEEP 6
#define URKEL_EINVAL 7
#define URKEL_ENOTFOUND 8
#define URKEL_ECORRUPTION 9
#define URKEL_ENOUPDATE 10
#define URKEL_EBADWRITE 11
#define URKEL_EBADOPEN 12
#define URKEL_EITEREND 13

/*
 * Database
 */

URKEL_EXTERN urkel_t *
urkel_open(const char *prefix);

URKEL_EXTERN void
urkel_close(urkel_t *tree);

URKEL_EXTERN int
urkel_destroy(const char *prefix);

URKEL_EXTERN int
urkel__corrupt(const char *prefix);

URKEL_EXTERN void
urkel_hash(unsigned char *hash, const void *data, size_t size);

URKEL_EXTERN void
urkel_root(urkel_t *tree, unsigned char *hash);

URKEL_EXTERN int
urkel_inject(urkel_t *tree, const unsigned char *hash);

URKEL_EXTERN int
urkel_get(urkel_t *tree,
          unsigned char *value,
          size_t *size,
          const unsigned char *key,
          const unsigned char *root);

URKEL_EXTERN int
urkel_has(urkel_t *tree,
          const unsigned char *key,
          const unsigned char *root);

URKEL_EXTERN int
urkel_insert(urkel_t *tree,
             const unsigned char *key,
             const unsigned char *value,
             size_t size);

URKEL_EXTERN int
urkel_remove(urkel_t *tree, const unsigned char *key);

URKEL_EXTERN int
urkel_compact(const char *dst_prefix,
              const char *src_prefix,
              const unsigned char *hash);

URKEL_EXTERN int
urkel_prove(urkel_t *tree,
            unsigned char **proof_raw,
            size_t *proof_len,
            const unsigned char *key,
            const unsigned char *root);

URKEL_EXTERN int
urkel_verify(int *exists,
             unsigned char *value,
             size_t *value_len,
             const unsigned char *proof_raw,
             size_t proof_len,
             const unsigned char *key,
             const unsigned char *root);

URKEL_EXTERN urkel_iter_t *
urkel_iterate(urkel_t *tree, const unsigned char *root);

/*
 * Transaction
 */

URKEL_EXTERN urkel_tx_t *
urkel_tx_create(urkel_t *tree, const unsigned char *hash);

URKEL_EXTERN void
urkel_tx_destroy(urkel_tx_t *tx);

URKEL_EXTERN void
urkel_tx_clear(urkel_tx_t *tx);

URKEL_EXTERN void
urkel_tx_root(urkel_tx_t *tx, unsigned char *hash);

URKEL_EXTERN int
urkel_tx_inject(urkel_tx_t *tx, const unsigned char *hash);

URKEL_EXTERN int
urkel_tx_get(urkel_tx_t *tx,
             unsigned char *value,
             size_t *size,
             const unsigned char *key);

URKEL_EXTERN int
urkel_tx_has(urkel_tx_t *tx, const unsigned char *key);

URKEL_EXTERN int
urkel_tx_insert(urkel_tx_t *tx,
                const unsigned char *key,
                const unsigned char *value,
                size_t size);

URKEL_EXTERN int
urkel_tx_remove(urkel_tx_t *tx, const unsigned char *key);

URKEL_EXTERN int
urkel_tx_prove(urkel_tx_t *tx,
               unsigned char **proof_raw,
               size_t *proof_len,
               const unsigned char *key);

URKEL_EXTERN int
urkel_tx_commit(urkel_tx_t *tx);

/*
 * Iterator
 */

URKEL_EXTERN urkel_iter_t *
urkel_iter_create(urkel_tx_t *tx);

URKEL_EXTERN void
urkel_iter_destroy(urkel_iter_t *iter);

URKEL_EXTERN int
urkel_iter_next(urkel_iter_t *iter,
                unsigned char *key,
                unsigned char *value,
                size_t *size);

/*
 * Helpers
 */

URKEL_EXTERN void
urkel_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* _URKEL_H */
