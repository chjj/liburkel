/*!
 * test.c - tests for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

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
  unsigned char value[50];
} urkel_kv_t;

static int
urkel_kv_compare(const void *x, const void *y) {
  unsigned char *a = ((urkel_kv_t *)x)->key;
  unsigned char *b = ((urkel_kv_t *)y)->key;
  return memcmp(a, b, 32);
}

int
main(void) {
  urkel_kv_t *kvs;
  urkel_tx_t *tx;
  urkel_t *db;
  size_t i, j;

  urkel_destroy(DB_PATH);

  db = urkel_open(DB_PATH);
  kvs = malloc(NUM_VALUES * sizeof(urkel_kv_t));

  ASSERT(db != NULL);
  ASSERT(kvs != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;

    for (j = 0; j < 32; j++)
      key[j] = rand();

    for (j = 0; j < 50; j++)
      value[j] = rand();
  }

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[50];
    size_t result_len;

    ASSERT(!urkel_tx_has(tx, key));

    ASSERT(!urkel_tx_get(tx, result, &result_len, key));

    ASSERT(urkel_tx_insert(tx, key, value, 50));

    ASSERT(urkel_tx_has(tx, key));

    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 50);
    ASSERT(memcmp(result, value, 50) == 0);
  }

  ASSERT(urkel_tx_commit(tx));

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[50];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));

    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 50);
    ASSERT(memcmp(result, value, 50) == 0);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  db = urkel_open(DB_PATH);
  tx = urkel_tx_create(db, NULL);

  ASSERT(db != NULL);
  ASSERT(tx != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[50];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));

    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 50);
    ASSERT(memcmp(result, value, 50) == 0);
  }

  {
    urkel_iter_t *iter = urkel_iter_create(tx);
    unsigned char key[32];
    unsigned char value[50];
    size_t len;

    ASSERT(iter != NULL);

    qsort(kvs, NUM_VALUES, sizeof(urkel_kv_t), urkel_kv_compare);

    i = 0;

    while (urkel_iter_next(iter, key, value, &len)) {
      ASSERT(len == 50);
      ASSERT(memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(memcmp(value, kvs[i].value, 50) == 0);
      i += 1;
    }

    ASSERT(i == NUM_VALUES);

    urkel_iter_destroy(iter);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(DB_PATH));

  free(kvs);

  return 0;
}
