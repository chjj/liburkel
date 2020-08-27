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

#define URKEL_ITERATIONS 1000

int
main(void) {
  urkel_kv_t *kvs = urkel_kv_generate(URKEL_ITERATIONS);
  unsigned char old_root[32];
  unsigned char old_root2[32];
  urkel_tx_t *tx;
  urkel_t *db;
  size_t i;

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < URKEL_ITERATIONS; i++) {
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

  for (i = 0; i < URKEL_ITERATIONS; i++) {
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

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < URKEL_ITERATIONS; i++) {
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

    urkel_kv_sort(kvs, URKEL_ITERATIONS);

    i = 0;

    while (urkel_iter_next(iter, key, value, &len)) {
      ASSERT(len == 64);
      ASSERT(memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(memcmp(value, kvs[i].value, 64) == 0);
      i += 1;
    }

    ASSERT(i == URKEL_ITERATIONS);

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

  urkel_root(db, old_root);

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;

    if (i & 1) {
      ASSERT(urkel_tx_has(tx, key));
      ASSERT(urkel_tx_remove(tx, key));
      ASSERT(!urkel_tx_has(tx, key));
    }

    if (i == URKEL_ITERATIONS / 2) {
      ASSERT(urkel_tx_commit(tx));
      urkel_tx_root(tx, old_root2);
    }
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

    ASSERT(i == URKEL_ITERATIONS);

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

    ASSERT(i == URKEL_ITERATIONS);

    urkel_iter_destroy(iter);
  }

  urkel_tx_destroy(tx);

  tx = urkel_tx_create(db, old_root);

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
      i += 1;
    }

    ASSERT(i == URKEL_ITERATIONS);

    urkel_iter_destroy(iter);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  {
    unsigned char new_root[32];

    ASSERT(urkel__corrupt(URKEL_PATH));

    db = urkel_open(URKEL_PATH);

    ASSERT(db != NULL);

    urkel_root(db, new_root);

    urkel_close(db);

    ASSERT(memcmp(new_root, old_root2, 32) == 0);
  }

  ASSERT(urkel_destroy(URKEL_PATH));

  urkel_kv_free(kvs);

  return 0;
}
