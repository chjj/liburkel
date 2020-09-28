# API

See [include/urkel.h][1] if you prefer to read the raw header file.

## Globals

``` c
extern int urkel_errno;
```

Set with one of the below constants if any call fails.

## Constants

### Error Codes

- `URKEL_EHASHMISMATCH` - Computed hash did not match expected hash (proof
  verification failure).
- `URKEL_ESAMEKEY` - Expected different key (proof verification failure).
- `URKEL_ESAMEPATH` - Expected different prefix bits (proof verification
  failure).
- `URKEL_ENEGDEPTH` - Depth went negative (proof verification failure).
- `URKEL_EPATHMISMATCH` - Prefix bits do not match key (proof verification
  failure).
- `URKEL_ETOODEEP` - Depth is not satisfied by proof nodes (proof verification
  failure).
- `URKEL_EINVAL` - Invalid arguments.
- `URKEL_ENOTFOUND` - Entry not found.
- `URKEL_ECORRUPTION` - Corruption detected.
- `URKEL_EBADWRITE` - Write failed.
- `URKEL_EBADOPEN` - Open/Destroy failed.
- `URKEL_EITEREND` - Iterator was ended.

## Database

``` c
urkel_t *
urkel_open(const char *prefix);
```

Open/create database at `prefix`. Returns `NULL` and sets `urkel_errno` on
failure.

---

``` c
void
urkel_close(urkel_t *tree);
```

Close database.

---

``` c
int
urkel_destroy(const char *prefix);
```

Destroy database at `prefix`. Returns `1` on success. Returns `0` and sets
`urkel_errno` on failure.

---

``` c
void
urkel_hash(unsigned char *hash, const void *data, size_t size);
```

Hash `data` of `size` bytes with blake2b-256 and write the output to `hash` (32
bytes).

---

``` c
void
urkel_root(urkel_t *tree, unsigned char *hash);
```

Compute current tree root of tree `tree` and write output to `hash` (32 bytes).

---

``` c
int
urkel_inject(urkel_t *tree, const unsigned char *hash);
```

Revert tree `tree` to a historical root of `hash`. Returns `1` on success.
Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_get(urkel_t *tree,
          unsigned char *value,
          size_t *size,
          const unsigned char *key,
          const unsigned char *root);
```

Retrieve record at `key` from tree `tree` and write output to `value` and
`size`. Note that the current maximum value size is 1023 bytes. Returns `1` on
success. Returns `0` and sets `urkel_errno` on failure.

Missing records can be differentiated from other errors with the
`URKEL_ENOTFOUND` error code.

---

``` c
int
urkel_has(urkel_t *tree,
          const unsigned char *key,
          const unsigned char *root);
```

Check for existence of record at `key` from tree `tree`. Returns `1` on
success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_insert(urkel_t *tree,
             const unsigned char *key,
             const unsigned char *value,
             size_t size);
```

Insert record at `key` with `value` of `size` bytes into tree `tree`. Returns
`1` on success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_remove(urkel_t *tree, const unsigned char *key);
```

Remove record at `key` from tree `tree`. Returns `1` on success. Returns `0`
and sets `urkel_errno` on failure.

---

``` c
int
urkel_prove(urkel_t *tree,
            unsigned char **proof_raw,
            size_t *proof_len,
            const unsigned char *key,
            const unsigned char *root);
```

Create proof at `key` from tree `tree`. `*proof_raw` is allocated and written
with `*proof_len` bytes. Returns `1` on success. Returns `0` and sets
`urkel_errno` on failure.

---

``` c
int
urkel_verify(int *exists,
             unsigned char *value,
             size_t *value_len,
             const unsigned char *proof_raw,
             size_t proof_len,
             const unsigned char *key,
             const unsigned char *root);
```

Verify proof for `key` from byte array `proof_raw` of `proof_len` bytes at root
`root`. If the record exists, `exists` will be set to `1`, with `value_len`
bytes of data written to `value`. If the record does not exist, `exists` will
be set to `0` with `value_len` also set to `0`.

Returns `1` on success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
urkel_iter_t *
urkel_iterate(urkel_t *tree, const unsigned char *root);
```

Create iterator from `tree` at historical root of `root` (may be `NULL` for the
most current state). Returns `1` on success. Returns `0` and sets `urkel_errno`
on failure.

## Transaction

``` c
urkel_tx_t *
urkel_tx_create(urkel_t *tree, const unsigned char *hash);
```

Create transaction, optionally as a snapshot of root `hash`. Returns `NULL` and
sets `urkel_errno` on failure.

---

``` c
void
urkel_tx_destroy(urkel_tx_t *tx);
```

Destroy transaction `tx`.

---

``` c
void
urkel_tx_clear(urkel_tx_t *tx);
```

Reset transaction `tx` to the most current state. This behaves as if
`urkel_tx_create(tree, NULL)` was called in-place.

---

``` c
void
urkel_tx_root(urkel_tx_t *tx, unsigned char *hash);
```

Compute current tree root of transaction `tx` and write output to `hash` (32
bytes).

---

``` c
int
urkel_tx_inject(urkel_tx_t *tx, const unsigned char *hash);
```

Set snapshot view of transaction `tx` to historical root `hash`. This behaves
as if `urkel_tx_create(tree, hash)` was called in-place. Returns `1` on
success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_tx_get(urkel_tx_t *tx,
             unsigned char *value,
             size_t *size,
             const unsigned char *key);
```

Retrieve record at `key` from transaction `tx` and write output to `value` and
`size`. Note that the current maximum value size is 1023 bytes. Returns `1` on
success. Returns `0` and sets `urkel_errno` on failure.

Missing records can be differentiated from other errors with the
`URKEL_ENOTFOUND` error code.

---

``` c
int
urkel_tx_has(urkel_tx_t *tx, const unsigned char *key);
```

Check for existence of record at `key` from transaction `tx`. Returns `1` on
success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_tx_insert(urkel_tx_t *tx,
                const unsigned char *key,
                const unsigned char *value,
                size_t size);
```

Insert record at `key` with `value` of `size` bytes into transaction `tx`.
Returns `1` on success. Returns `0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_tx_remove(urkel_tx_t *tx, const unsigned char *key);
```

Remove record at `key` from transaction `tx`. Returns `1` on success. Returns
`0` and sets `urkel_errno` on failure.

---

``` c
int
urkel_tx_prove(urkel_tx_t *tx,
               unsigned char **proof_raw,
               size_t *proof_len,
               const unsigned char *key);
```

Create proof at `key` from transaction `tx`. `*proof_raw` is allocated and
written with `*proof_len` bytes. Returns `1` on success. Returns `0` and sets
`urkel_errno` on failure.

---

``` c
int
urkel_tx_commit(urkel_tx_t *tx);
```

Commit transaction. Returns `1` on success. Returns `0` and sets `urkel_errno`
on failure.

## Iterator

``` c
urkel_iter_t *
urkel_iter_create(urkel_tx_t *tx);
```

Create iterator from transaction `tx`. Returns `NULL` and sets `urkel_errno` on
failure.

---

``` c
void
urkel_iter_destroy(urkel_iter_t *iter);
```

Destroy iterator `iter`. __Must__ be called once iteration is complete.

---

``` c
int
urkel_iter_next(urkel_iter_t *iter,
                unsigned char *key,
                unsigned char *value,
                size_t *size);
```

Retrieve next record from iterator `iter` and write output to `key`, `value`,
and `size`. Note that the current maximum value size is 1023 bytes. Returns `1`
on success. Returns `0` and sets `urkel_errno` on failure.

Note that this function will return `0` when there are no more leaves to
iterate over. To differentiate this from other error conditions, use the
`URKEL_EITEREND` error code.

## Helpers

``` c
void
urkel_free(void *ptr);
```

Free a pointer which was previously allocated by urkel. This currently only
applies to proof data. `ptr` must not be `NULL`.

---

[1]: https://github.com/chjj/liburkel/blob/master/include/urkel.h
