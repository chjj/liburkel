# Tree Operations

The examples below illustrate a base-2 radix tree with 4 bit keys. Internal
nodes are marked as integers surrounded by parentheses, while leaf nodes
(key/value pairs) are letters. A map of key->value will be listed before each
illustration, showing the state of the leaves. Internal nodes' prefix bits are
also listed.

For our proof illustrations, the target node is surrounded by curly braces
(`{}`), while selected nodes are surrounded by square brackets (`[]`).

Skip this initial section if you are familiar with base-2 radix trees.

Note that an earlier iteration of the urkel tree was described in the Handshake
[whitepaper][1].

## Insertion

We start with a simple insertion of value `a` with a key of `0000`. It becomes
the root of the tree.

```
Leaves:
  0000 = a

Tree:
       a
```

We insert value `b` with a key of `1100`. The tree grows down and is now 1
level deep. Note that we only traversed right once despite the 3 extra bits in
the key.

```
Leaves:
  0000 = a
  1100 = b

Internal:
       = (0)

Tree:
      (0)
      / \
     /   \
    a     b
```

The following step is important as to how our urkel tree handles key
collisions. We insert value `c` with a key of `1101`. It has a three bit
collision with leaf `b` which has a key of `1100`. In order to maintain a
proper key path within the tree, we grow the subtree down and store two
colliding bits `10` on an internal node.

```
Leaves:
  0000 = a
  1100 = b
  1101 = c

Internal:
       = (0)
   10  = (1)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       b     c
```

We add value `d` with a key of `1000`. Note how this restructures the internal
nodes, including their prefix bits.

```
Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       d    (2)
            / \
           /   \
          b     c
```

Adding value `e` with a key of `1001` results in further growing.

```
Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d
  1001 = e

Internal:
       = (0)
       = (1)
    0  = (2)
    0  = (3)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       /     \
      /       \
    (3)       (2)
    / \       / \
   /   \     /   \
  d     e   b     c
```

## Removal

Removal may seem non-intuitive when several bit prefixes are present in the
subtree. Previously split prefixes must be rejoined.

```
Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       d    (2)
            / \
           /   \
          b     c
```

If we were to remove leaf `d` from the above tree, we must remove another
internal node and re-join the original prefix.

Removing leaf `d`:

```
Leaves:
       = R
  0000 = a
  1100 = b
  1101 = c

Internal:
       = (0)
   10  = (1)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       b     c
```

Removing leaf `c`:

```
Leaves:
  0000 = a
  1100 = b

Internal:
       = (0)

Tree:
      (0)
      / \
     /   \
    a     b
```

Removing leaf `b` (`a` becomes the root):

```
Leaves:
  0000 = a

Tree:
       a
```

With our final removal, we are back in the initial state.

## Proofs

Our urkel proof is similar to a standard merkle tree proof with some extra
caveats.

Leaf node hashes are computed as:

```
HASH(0x00 || 256-bit-key || HASH(value))
```

Whereas internal node hashes are computed as:


```
HASH(0x02 || num-bits || prefix-bits || left-hash || right-hash)
```

Where `||` denotes concatenation.

It is important to have the full key as part of the leaf preimage. If a
non-existence proof is necessary, the full preimage must be sent to prove that
the node is a leaf which contains a different key with a colliding path. If the
key path is cut short by a non-colliding bit prefix, no preimage is necessary.

If we were asked to prove the existence or non-existence of key `1110`, with
our original tree of:

```
Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
    a    (1)
         / \
        /   \
       d    (2)
            / \
           /   \
          b     c
```

Key `1110` does not exist in this case, so we must provide the hashes of nodes
`a`, `d`, and the parent node of `b` and `c` (including the prefix bits). The
verifier must ensure that the target key does not collide with said prefix bits
at the given depth.

```
Proving non-existence for: 1110

Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
   [a]   (1)
         / \
        /   \
      [d]   {2}
            / \
           /   \
          b     c
```

Proving non-existence for key `0100` is different, but roughly the same
complexity. Node `a` has a key of `0000`. In this case, we must provide the
parent node's hash for `d`, as well as `a` and its original key `0000`.

Ordinarily, this would make the non-existence proof larger because we have to
provide the full preimage, thus proving that node `a` is indeed a leaf, but
that it has a different key than the one requested.

However, due to our hashing of values before computing the leaf hash, the full
preimage is a constant size of 64 bytes, rather than it being the size of the
key in addition to the full value size.

```
Proving non-existence for: 0100

Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
   {a}   [1]
         / \
        /   \
       d    (2)
            / \
           /   \
          b     c
```

We need only send the preimage for `a` (the value hash of `a` itself and its
key `0000`). Sending its hash would be a redundant 32 bytes.

An existence proof is rather straight-forward. Proving leaf `c` (`1101`), we
would send the leaf hashes of `a`, `d`, and `b`.  The leaf hash of `c` is not
transmitted, only its value (`c`). The full preimage is known on the other
side, allowing us to compute `HASH(0x00 || 1101 || HASH("c"))` to re-create the
leaf hash.

Any leaf node included in the proof must also provide the parent internal
node's prefix bits. This allows the verifier to determine the depth of the
proof properly. Note that these parent bits are part of the internal node's
hash.

In our case, the prefix bits for internal node `2` would need to be included,
associated with leaf `b`.

```
Proving existence for: 1101 (c)

Leaves:
  0000 = a
  1100 = b
  1101 = c
  1000 = d

Internal:
       = (0)
       = (1)
    0  = (2)

Tree:
      (0)
      / \
     /   \
   [a]   (1)
         / \
        /   \
      [d]   (2)
            / \
           /   \
         [b]   {c}
```

[1]: https://handshake.org/files/handshake.txt
