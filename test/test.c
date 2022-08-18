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

static void
test_memcmp(void) {
  static const unsigned char a[4] = {0, 1, 2, 3};
  static const unsigned char b[4] = {0, 1, 2, 3};
  static const unsigned char c[4] = {3, 2, 1, 0};
  static const unsigned char d[4] = {3, 2, 1, 0};

  ASSERT(urkel_memcmp(a, b, 4) == 0);
  ASSERT(urkel_memcmp(c, d, 4) == 0);
  ASSERT(urkel_memcmp(a, b, 4) >= 0);
  ASSERT(urkel_memcmp(c, d, 4) >= 0);
  ASSERT(urkel_memcmp(a, b, 4) <= 0);
  ASSERT(urkel_memcmp(c, d, 4) <= 0);
  ASSERT(urkel_memcmp(a, c, 4) != 0);
  ASSERT(urkel_memcmp(c, a, 4) != 0);
  ASSERT(urkel_memcmp(a, c, 4) < 0);
  ASSERT(urkel_memcmp(c, a, 4) > 0);
}

static void
test_urkel_sanity(void) {
  urkel_kv_t *kvs = urkel_kv_generate(URKEL_ITERATIONS);
  urkel_tree_stat_t old_tst = {0};
  unsigned char old_root[32];
  unsigned char old_root2[32];
  urkel_tx_t *tx;
  urkel_t *db;
  size_t i;

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(tst.files == 1);
    ASSERT(tst.size == 0);
    old_tst = tst;
  }

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
    ASSERT(urkel_memcmp(result, value, 64) == 0);

    if ((i & 15) == 0) {
      urkel_tree_stat_t before_tst = {0};
      urkel_tree_stat_t after_tst = {0};
      urkel_stat(URKEL_PATH, &before_tst);
      ASSERT(old_tst.files == before_tst.files);
      ASSERT(old_tst.size == before_tst.size);

      ASSERT(urkel_tx_commit(tx));

      urkel_stat(URKEL_PATH, &after_tst);
      ASSERT(old_tst.files == after_tst.files);
      ASSERT(old_tst.size < after_tst.size);
      old_tst = after_tst;
    }
  }

  ASSERT(urkel_tx_commit(tx));

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files <= tst.files);
    ASSERT(old_tst.size < tst.size);
    old_tst = tst;
  }

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;
    unsigned char result[64];
    size_t result_len;

    ASSERT(urkel_tx_has(tx, key));
    ASSERT(urkel_tx_get(tx, result, &result_len, key));

    ASSERT(result_len == 64);
    ASSERT(urkel_memcmp(result, value, 64) == 0);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files == tst.files);
    ASSERT(old_tst.size == tst.size);
    old_tst = tst;
  }
  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files == tst.files);
    ASSERT(old_tst.size == tst.size);
    old_tst = tst;
  }

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
    ASSERT(urkel_memcmp(result, value, 64) == 0);
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
      ASSERT(urkel_memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);
      i += 1;
    }

    ASSERT(i == URKEL_ITERATIONS);

    urkel_iter_destroy(iter);
  }

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files == tst.files);
    ASSERT(old_tst.size == tst.size);
    old_tst = tst;
  }

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char root[32];
    unsigned char *key = kvs[i].key;
    unsigned char *proof_raw;
    size_t proof_len;
    int exists;
    unsigned char value[1024];
    size_t value_len;

    urkel_tx_root(tx, root);

    ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));
    ASSERT(urkel_verify(&exists, value, &value_len,
                        proof_raw, proof_len, key, root));

    ASSERT(exists == 1);
    ASSERT(value_len == 64);
    ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);

    urkel_free(proof_raw);
  }

  urkel_root(db, old_root);

  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files == tst.files);
    ASSERT(old_tst.size == tst.size);
    old_tst = tst;
  }

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;

    if (i & 1) {
      ASSERT(urkel_tx_has(tx, key));
      ASSERT(urkel_tx_remove(tx, key));
      ASSERT(!urkel_tx_has(tx, key));
    }

    if (i == URKEL_ITERATIONS / 2) {
      urkel_tree_stat_t before_tst = {0};
      urkel_tree_stat_t after_tst = {0};
      urkel_stat(URKEL_PATH, &before_tst);
      ASSERT(old_tst.files == before_tst.files);
      ASSERT(old_tst.size == before_tst.size);

      ASSERT(urkel_tx_commit(tx));
      urkel_tx_root(tx, old_root2);

      urkel_stat(URKEL_PATH, &after_tst);
      ASSERT(old_tst.files == after_tst.files);
      ASSERT(old_tst.size < after_tst.size);
      old_tst = after_tst;
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
      ASSERT(urkel_memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);
      i += 2;
    }

    ASSERT(i == URKEL_ITERATIONS);

    urkel_iter_destroy(iter);
  }

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char root[32];
    unsigned char *key = kvs[i].key;
    unsigned char *proof_raw;
    size_t proof_len;
    int exists;
    unsigned char value[1024];
    size_t value_len;

    urkel_tx_root(tx, root);

    ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));
    ASSERT(urkel_verify(&exists, value, &value_len,
                        proof_raw, proof_len, key, root));

    if (i & 1) {
      ASSERT(exists == 0);
    } else {
      ASSERT(exists == 1);
      ASSERT(value_len == 64);
      ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);
    }

    urkel_free(proof_raw);
  }

  ASSERT(urkel_tx_commit(tx));
  {
    urkel_tree_stat_t tst = {0};
    urkel_stat(URKEL_PATH, &tst);
    ASSERT(old_tst.files == tst.files);
    ASSERT(old_tst.size < tst.size);
    old_tst = tst;
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
      ASSERT(urkel_memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);
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
      ASSERT(urkel_memcmp(key, kvs[i].key, 32) == 0);
      ASSERT(urkel_memcmp(value, kvs[i].value, 64) == 0);
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

    ASSERT(urkel_memcmp(new_root, old_root2, 32) == 0);
  }

  ASSERT(urkel_destroy(URKEL_PATH));

  urkel_kv_free(kvs);
}

static void
test_urkel_node_replacement(void) {
  /* See: https://github.com/chjj/liburkel/issues/6 */
  urkel_kv_t *kvs = urkel_kv_generate(2);
  urkel_tx_t *tx;
  urkel_t *db;

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);
  ASSERT(urkel_tx_insert(tx, kvs[0].key, kvs[0].value, 64));
  ASSERT(urkel_tx_commit(tx));

  ASSERT(!urkel_tx_remove(tx, kvs[1].key));

  ASSERT(urkel_tx_insert(tx, kvs[1].key, kvs[1].value, 64));
  ASSERT(urkel_tx_commit(tx));

  ASSERT(urkel_tx_insert(tx, kvs[0].key, kvs[0].value, 64));
  ASSERT(urkel_tx_insert(tx, kvs[1].key, kvs[1].value, 64));
  ASSERT(urkel_tx_insert(tx, kvs[0].key, kvs[1].value, 64));
  ASSERT(urkel_tx_commit(tx));

  ASSERT(urkel_tx_remove(tx, kvs[1].key));
  ASSERT(urkel_tx_commit(tx));

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(URKEL_PATH));

  urkel_kv_free(kvs);
}

static void
test_urkel_leaky_inject(void) {
  /* Valgrind should error out if the bug is present. */
  /* See: https://github.com/chjj/liburkel/issues/7 */
  urkel_kv_t *kvs = urkel_kv_generate(2);
  unsigned char root[32];
  unsigned char tmp[32];
  urkel_tx_t *tx;
  urkel_t *db;

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  ASSERT(urkel_tx_insert(tx, kvs[0].key, kvs[0].value, 64));
  ASSERT(urkel_tx_commit(tx));

  urkel_tx_root(tx, root);

  ASSERT(urkel_tx_insert(tx, kvs[1].key, kvs[1].value, 64));
  ASSERT(urkel_tx_commit(tx));

  urkel_tx_root(tx, tmp);

  ASSERT(urkel_memcmp(tmp, root, 32) != 0);

  ASSERT(urkel_tx_inject(tx, root));

  urkel_tx_root(tx, tmp);

  ASSERT(urkel_memcmp(tmp, root, 32) == 0);

  urkel_tx_clear(tx);

  urkel_tx_root(tx, tmp);

  ASSERT(urkel_memcmp(tmp, root, 32) != 0);

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(URKEL_PATH));

  urkel_kv_free(kvs);
}

static void
test_urkel_max_value_size(void) {
  unsigned char key[32];
  unsigned char val[1023 + 1];
  urkel_t *db;

  memset(key, 0xaa, sizeof(key));
  memset(val, 0x11, sizeof(val));

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  urkel_errno = 0;

  ASSERT(!urkel_insert(db, key, val, sizeof(val)));
  ASSERT(urkel_errno == URKEL_EINVAL);

  ASSERT(urkel_insert(db, key, val, sizeof(val) - 1));

  urkel_close(db);

  ASSERT(urkel_destroy(URKEL_PATH));
}

int
main(void) {
  test_memcmp();
  test_urkel_sanity();
  test_urkel_node_replacement();
  test_urkel_leaky_inject();
  test_urkel_max_value_size();
  return 0;
}
