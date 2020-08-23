/*!
 * test.c - tests for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urkel.h>
#include "utils.h"

#ifdef __wasi__
#  define DB_PATH "/urkel_db_test"
#else
#  define DB_PATH "./urkel_db_test"
#endif

#define NUM_VALUES 1000

typedef struct urkel_kv_s {
  unsigned char key[32];
  unsigned char value[64];
} urkel_kv_t;

static int
urkel_kv_compare(const void *x, const void *y) {
  const unsigned char *a = ((const urkel_kv_t *)x)->key;
  const unsigned char *b = ((const urkel_kv_t *)y)->key;
  return memcmp(a, b, 32);
}

int
main(void) {
  urkel_kv_t *kvs;
  urkel_tx_t *tx;
  urkel_t *db;
  size_t i;

  urkel_destroy(DB_PATH);

  db = urkel_open(DB_PATH);
  kvs = malloc(NUM_VALUES * sizeof(urkel_kv_t));

  ASSERT(db != NULL);
  ASSERT(kvs != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;

    urkel_hash(key, &i, sizeof(i));
    urkel_hash(value + 0, key, 32);
    urkel_hash(value + 32, value, 32);
  }

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[64];
    size_t result_len;

    ASSERT(!urkel_tx_has(tx, key));
    ASSERT(!urkel_tx_get(tx, result, &result_len, key));
    ASSERT(urkel_tx_insert(tx, key, value, 64));
    ASSERT(urkel_tx_has(tx, key));
    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 64);
    ASSERT(memcmp(result, value, 64) == 0);

    if ((i & 15) == 0)
      ASSERT(urkel_tx_commit(tx));
  }

  ASSERT(urkel_tx_commit(tx));

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[64];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));
    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 64);
    ASSERT(memcmp(result, value, 64) == 0);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  db = urkel_open(DB_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[64];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));
    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 64);
    ASSERT(memcmp(result, value, 64) == 0);
  }

  {
    urkel_iter_t *iter = urkel_iter_create(tx);
    unsigned char key[32];
    unsigned char value[64];
    size_t len;

    ASSERT(iter != NULL);

    qsort(kvs, NUM_VALUES, sizeof(urkel_kv_t), urkel_kv_compare);

    i = 0;

    while (urkel_iter_next(iter, key, value, &len)) {
      ASSERT(len == 64);
      ASSERT(memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(memcmp(value, kvs[i].value, 64) == 0);
      i += 1;
    }

    ASSERT(i == NUM_VALUES);

    urkel_iter_destroy(iter);
  }

  {
    unsigned char root[32];
    unsigned char *key = kvs[0].key;
    unsigned char *proof_raw;
    size_t proof_len;
    unsigned char *value;
    size_t value_len;

    urkel_tx_root(tx, root);

    ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));
    ASSERT(urkel_verify(&value, &value_len, proof_raw, proof_len, root, key));

    ASSERT(value_len == 64);
    ASSERT(memcmp(value, kvs[0].value, 64) == 0);

    free(proof_raw);
    free(value);
  }

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;

    if (i & 1) {
      ASSERT(urkel_tx_has(tx, key));
      ASSERT(urkel_tx_remove(tx, key));
      ASSERT(!urkel_tx_has(tx, key));
    }

    if (i == NUM_VALUES / 2)
      ASSERT(urkel_tx_commit(tx));
  }

  {
    urkel_iter_t *iter = urkel_iter_create(tx);
    unsigned char key[32];
    unsigned char value[64];
    size_t len;

    ASSERT(iter != NULL);

    i = 0;

    while (urkel_iter_next(iter, key, value, &len)) {
      ASSERT(len == 64);
      ASSERT(memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(memcmp(value, kvs[i].value, 64) == 0);
      i += 2;
    }

    ASSERT(i == NUM_VALUES);

    urkel_iter_destroy(iter);
  }

  {
    unsigned char root[32];
    unsigned char *key = kvs[0].key;
    unsigned char *proof_raw;
    size_t proof_len;
    unsigned char *value;
    size_t value_len;

    urkel_tx_root(tx, root);

    ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));
    ASSERT(urkel_verify(&value, &value_len, proof_raw, proof_len, root, key));

    ASSERT(value_len == 64);
    ASSERT(memcmp(value, kvs[0].value, 64) == 0);

    free(proof_raw);
    free(value);
  }

  ASSERT(urkel_tx_commit(tx));

  {
    urkel_iter_t *iter = urkel_iter_create(tx);
    unsigned char key[32];
    unsigned char value[64];
    size_t len;

    ASSERT(iter != NULL);

    i = 0;

    while (urkel_iter_next(iter, key, value, &len)) {
      ASSERT(len == 64);
      ASSERT(memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(memcmp(value, kvs[i].value, 64) == 0);
      i += 2;
    }

    ASSERT(i == NUM_VALUES);

    urkel_iter_destroy(iter);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(DB_PATH));

  free(kvs);

  printf("Success.\n");

  return 0;
}
