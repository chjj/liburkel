/*!
 * bench.c - benchmarks for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <urkel.h>

#include "hrtime.h"
#include "utils.h"

#define URKEL_ITERATIONS 100000

/*
 * Benchmarks
 */

typedef uint64_t bench_t;

static void
bench_start(bench_t *start, const char *name) {
  printf("Benchmarking %s...\n", name);
  *start = urkel_hrtime();
}

static void
bench_end(bench_t *start, uint64_t ops) {
  bench_t nsec = urkel_hrtime() - *start;
  double sec = (double)nsec / 1000000000.0;

  printf("  Operations:  %" PRIu64 "\n", ops);
  printf("  Nanoseconds: %" PRIu64 "\n", nsec);
  printf("  Seconds:     %f\n", sec);
  printf("  Ops/Sec:     %f\n", (double)ops / sec);
  printf("  Sec/Op:      %f\n", sec / (double)ops);
}

static void
bench_urkel(void) {
  urkel_kv_t *kvs = urkel_kv_generate(URKEL_ITERATIONS);
  urkel_tx_t *tx;
  urkel_t *db;
  bench_t tv;
  size_t i;

  urkel_destroy(URKEL_PATH);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  bench_start(&tv, "insert");

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char *value = kvs[i].value;

    ASSERT(urkel_tx_insert(tx, key, value, 64));
  }

  bench_end(&tv, i);

  bench_start(&tv, "get (cached)");

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char value[64];
    size_t size;

    ASSERT(urkel_tx_get(tx, value, &size, key));
  }

  bench_end(&tv, i);

  bench_start(&tv, "commit");

  ASSERT(urkel_tx_commit(tx));

  bench_end(&tv, 1);

  urkel_tx_destroy(tx);
  urkel_close(db);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  bench_start(&tv, "get (uncached)");

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;
    unsigned char value[64];
    size_t size;

    ASSERT(urkel_tx_get(tx, value, &size, key));
  }

  bench_end(&tv, i);

  bench_start(&tv, "remove");

  for (i = 0; i < URKEL_ITERATIONS; i++) {
    unsigned char *key = kvs[i].key;

    if (i & 1)
      ASSERT(urkel_tx_remove(tx, key));
  }

  bench_end(&tv, i);

  bench_start(&tv, "commit");

  ASSERT(urkel_tx_commit(tx));

  bench_end(&tv, 1);

  bench_start(&tv, "commit (nothing)");

  ASSERT(urkel_tx_commit(tx));

  bench_end(&tv, 1);

  urkel_tx_destroy(tx);
  urkel_close(db);

  db = urkel_open(URKEL_PATH);

  ASSERT(db != NULL);

  tx = urkel_tx_create(db, NULL);

  ASSERT(tx != NULL);

  {
    unsigned char root[32];
    unsigned char *key = kvs[0].key;
    unsigned char *proof_raw;
    size_t proof_len;
    unsigned char *value;
    size_t value_len;

    urkel_tx_root(tx, root);

    bench_start(&tv, "prove");

    for (i = 0; i < URKEL_ITERATIONS; i++) {
      ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));

      free(proof_raw);
    }

    bench_end(&tv, i);

    ASSERT(urkel_tx_prove(tx, &proof_raw, &proof_len, key));

    bench_start(&tv, "verify");

    for (i = 0; i < URKEL_ITERATIONS; i++) {
      ASSERT(urkel_verify(&value, &value_len, proof_raw, proof_len, root, key));
      ASSERT(value_len == 64);
      ASSERT(memcmp(value, kvs[0].value, 64) == 0);

      free(value);
    }

    bench_end(&tv, i);

    free(proof_raw);
  }

  urkel_tx_destroy(tx);
  urkel_close(db);

  ASSERT(urkel_destroy(URKEL_PATH));

  urkel_kv_free(kvs);
}

int
main(void) {
  bench_urkel();
  return 0;
}
