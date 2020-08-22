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

int
main(void) {
  unsigned char *keys, *values;
  urkel_tx_t *tx;
  urkel_t *db;
  size_t i, j;

  urkel_destroy(DB_PATH);

  db = urkel_open(DB_PATH);
  keys = malloc(NUM_VALUES * 32);
  values = malloc(NUM_VALUES * 50);

  ASSERT(db != NULL);
  ASSERT(keys != NULL);
  ASSERT(values != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = &keys[i * 32];
    unsigned char *value = &values[i * 50];

    for (j = 0; j < 32; j++)
      key[j] = rand();

    for (j = 0; j < 50; j++)
      value[j] = rand();
  }

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  for (i = 0; i < NUM_VALUES; i++) {
    unsigned char *key = &keys[i * 32];
    unsigned char *value = &values[i * 50];
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
    unsigned char *key = &keys[i * 32];
    unsigned char *value = &values[i * 50];
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
    unsigned char *key = &keys[i * 32];
    unsigned char *value = &values[i * 50];
    unsigned char result[50];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));

    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 50);
    ASSERT(memcmp(result, value, 50) == 0);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(DB_PATH));

  free(keys);
  free(values);

  return 0;
}
