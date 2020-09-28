# Urkel

![cmake](https://github.com/chjj/liburkel/workflows/cmake/badge.svg)

An optimized and cryptographically provable key-value store. Written in C.

## Design

The urkel tree is implemented as a [base-2 merkelized radix tree][1]. It builds
on earlier research done by [Bram Cohen][2] and [Amaury Séchet][3] in order to
create an alternative to [Ethereum's base-16 trie][4].

Nodes are stored in a series of append-only files for snapshotting and crash
consistency capabilities. Due to these presence of these features, Urkel has
the ability to expose a fully transactional database.

Urkel is its _own_ database. This is in contrast to earlier authenticated data
structures which were typically implemented on top of an existing data store
like LevelDB.

The urkel tree is currently used in production for the [Handshake protocol][5].

## Features

- Transactions - Fully atomic and [transactional API][6].
- Snapshots - Transactions can also behave as snapshots, pointing to a
  historical root hash.
- Iteration - Full tree iteration¹.
- Compact Proofs - Small proof size, with proof nodes averaging ~34 bytes in
  size.
- History Independence - Deterministic root hash calculation regardless of
  insertion/removal order.
- Crash Consistency - `kill -9`'able.
- Cross Platform - Runs on Windows XP and up, as well as any POSIX.1-2001
  compatible OS.
- WASM Support - Builds with both Emscripten as well as the WASI SDK.

---

1. Note that range iteration is not particularly useful for our use case.

## Example Usage

``` c
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <urkel.h>

int main(void) {
  unsigned char key[32];
  unsigned char val[4] = {0xde, 0xad, 0xbe, 0xef};
  unsigned char key_out[32];
  unsigned char val_out[1023]; /* Max size (currently). */
  size_t val_len;
  urkel_t *db;
  urkel_tx_t *tx;

  /* Open database. */
  db = urkel_open("/path/to/db");

  assert(db != NULL);

  /* Create transaction. */
  tx = urkel_tx_create(db, NULL);

  assert(tx != NULL);

  /* Hash key. */
  urkel_hash(key, "my key", 6);

  /* Insert record. */
  assert(urkel_tx_insert(tx, key, val, sizeof(val)));

  /* Retrieve record. */
  assert(urkel_tx_get(tx, val_out, &val_len, key));
  assert(val_len == sizeof(val));
  assert(memcmp(val_out, val, val_len) == 0);

  /* Commit transaction. */
  assert(urkel_tx_commit(tx));

  {
    unsigned char root[32];
    unsigned char *proof_raw;
    size_t proof_len;
    int exists;

    /* Compute root. */
    urkel_tx_root(tx, root);

    /* Create proof. */
    assert(urkel_tx_prove(tx, &proof_raw, &proof_len, key));

    /* Verify proof. */
    assert(urkel_verify(&exists, val_out, &val_len,
                        proof_raw, proof_len, key, root));

    /* Returns our value. */
    assert(exists == 1);
    assert(val_len == sizeof(val));
    assert(memcmp(val_out, val, val_len) == 0);

    urkel_free(proof_raw);
  }

  {
    /* Create an iterator. */
    urkel_iter_t *iter = urkel_iter_create(tx);
    size_t i = 0;

    assert(iter != NULL);

    /* Iterate over our single record. */
    while (urkel_iter_next(iter, key_out, val_out, &val_len)) {
      assert(memcmp(key_out, key, 32) == 0);
      assert(val_len == sizeof(val));
      assert(memcmp(val_out, val, val_len) == 0);
      i += 1;
    }

    assert(urkel_errno == URKEL_EITEREND);
    assert(i == 1);

    urkel_iter_destroy(iter);
  }

  /* Cleanup. */
  urkel_tx_destroy(tx);
  urkel_close(db);

  return 0;
}
```

Compile with:

``` sh
$ cc -o example example.c -lurkel
```

## CLI Usage

The default build will provide you with an `urkel` executable. This allows
very simple manipulation of an urkel database from the command line.

### Example

Data manipulation:

``` sh
$ urkel create
$ urkel root
0000000000000000000000000000000000000000000000000000000000000000
$ urkel insert foo 'deadbeef' -H
$ urkel root
1da2776eaa254ef65aeeee1f37f61c06bac2e82e221d37da21190191218f6631
$ urkel insert bar '01020304' -H
$ urkel root
497b751637ff244ab969a965f8d9dc7623f18d649d012276dfb317b0e38b9bec
$ urkel get bar -H
01020304
$ urkel remove bar -H
$ urkel root
1da2776eaa254ef65aeeee1f37f61c06bac2e82e221d37da21190191218f6631
$ urkel remove foo -H
$ urkel root
0000000000000000000000000000000000000000000000000000000000000000
```

Creating and verifying a proof:

``` sh
$ urkel root
497b751637ff244ab969a965f8d9dc7623f18d649d012276dfb317b0e38b9bec
$ urkel prove foo -H
03c00100800280a6386fa1781a92e3905f718d4e0ea0d757abe962eefdd52a23d2ad6e1409fd8a0400deadbeef
$ urkel verify foo -H \
  '03c00100800280a6386fa1781a92e3905f718d4e0ea0d757abe962eefdd52a23d2ad6e1409fd8a0400deadbeef' \
  --root '497b751637ff244ab969a965f8d9dc7623f18d649d012276dfb317b0e38b9bec'
deadbeef
```

### Usage

```
  Usage: urkel [options] [action] [args]

  Actions:

    create                create a new database
    destroy               destroy database
    info                  print database information
    root                  print root hash
    get <key>             retrieve value
    insert <key> <value>  insert value
    remove <key>          remove value
    list                  list all keys
    prove <key>           create proof
    verify <key> <proof>  verify proof (requires --root)

  Options:

    -p, --path <path>     path to database (default: $URKEL_PATH)
    -r, --root <hash>     root hash to use for snapshots
    -H, --hash            hash key with BLAKE2b-256
    -h, --help            output usage information

  Environment Variables:

    URKEL_PATH            path to database (default: ./)
```

## Benchmarks

Benchmarks were run on a high-end but consumer-grade laptop, containing a Intel
Core i7-8550U 1.80GHz and an NVMe PCIe SSD.

```
Benchmarking insert...
  Operations:  100000
  Nanoseconds: 176354477
  Seconds:     0.176354
  Ops/Sec:     567039.758225
  Sec/Op:      0.000002
Benchmarking get (cached)...
  Operations:  100000
  Nanoseconds: 91769518
  Seconds:     0.091770
  Ops/Sec:     1089686.446866
  Sec/Op:      0.000001
Benchmarking commit...
  Operations:  1
  Nanoseconds: 121798848
  Seconds:     0.121799
  Ops/Sec:     8.210258
  Sec/Op:      0.121799
Benchmarking get (uncached)...
  Operations:  100000
  Nanoseconds: 300755918
  Seconds:     0.300756
  Ops/Sec:     332495.535466
  Sec/Op:      0.000003
Benchmarking remove...
  Operations:  100000
  Nanoseconds: 88950509
  Seconds:     0.088951
  Ops/Sec:     1124220.660727
  Sec/Op:      0.000001
Benchmarking commit...
  Operations:  1
  Nanoseconds: 30168275
  Seconds:     0.030168
  Ops/Sec:     33.147404
  Sec/Op:      0.030168
Benchmarking commit (nothing)...
  Operations:  1
  Nanoseconds: 24088
  Seconds:     0.000024
  Ops/Sec:     41514.447028
  Sec/Op:      0.000024
Benchmarking prove...
  Operations:  100000
  Nanoseconds: 327144781
  Seconds:     0.327145
  Ops/Sec:     305675.058286
  Sec/Op:      0.000003
Benchmarking verify...
  Operations:  100000
  Nanoseconds: 330230736
  Seconds:     0.330231
  Ops/Sec:     302818.572285
  Sec/Op:      0.000003
```

Platforms without memory-mapped file support will suffer in performance (this
includes Emscripten and WASI).

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2020, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[1]: https://github.com/chjj/liburkel/blob/master/doc/tree.md
[2]: https://github.com/bramcohen/MerkleSet
[3]: https://www.deadalnix.me/2016/09/24/introducing-merklix-tree-as-an-unordered-merkle-tree-on-steroid/
[4]: https://eth.wiki/en/fundamentals/patricia-tree
[5]: https://handshake.org
[6]: https://github.com/chjj/liburkel/blob/master/doc/api.md
