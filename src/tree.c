/*!
 * tree.c - urkel tree database
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdlib.h>
#include <string.h>
#include <urkel.h>
#include "bits.h"
#include "internal.h"
#include "io.h"
#include "nodes.h"
#include "proof.h"
#include "store.h"
#include "util.h"

/*
 * Structs
 */

typedef struct urkel_s {
  urkel_store_t *store;
  urkel_rwlock_t *lock;
  unsigned char hash[URKEL_HASH_SIZE];
  int revert;
} tree_db_t;

typedef struct urkel_tx_s {
  tree_db_t *tree;
  urkel_node_t *root;
  urkel_rwlock_t *lock;
} tree_tx_t;

typedef struct urkel_state_s {
  urkel_node_t *node;
  unsigned int depth;
  int resolved;
  int child;
} urkel_state_t;

typedef struct urkel_iter_s {
  tree_db_t *tree;
  tree_tx_t *tx;
  urkel_mutex_t *lock;
  urkel_node_t *root;
  urkel_node_t *node;
  urkel_state_t stack[URKEL_KEY_BITS];
  size_t stack_len;
  int done;
  int transient;
} tree_iter_t;

/*
 * Error Number
 */

#if defined(URKEL_TLS)
static URKEL_TLS int __urkel_errno;

int *
__urkel_get_errno(void) {
  return &__urkel_errno;
}
#else
#include <errno.h>

int *
__urkel_get_errno(void) {
  return &errno;
}
#endif

/*
 * Tree Operations
 */

static int
urkel_tree_get(tree_db_t *tree,
               unsigned char *value,
               size_t *size,
               urkel_node_t *node,
               const unsigned char *key,
               unsigned int depth) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      /* Empty (sub)tree. */
      urkel_errno = URKEL_ENOTFOUND;
      return 0;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      unsigned int bit;

      if (!urkel_bits_has(prefix, key, depth)) {
        urkel_errno = URKEL_ENOTFOUND;
        return 0;
      }

      depth += prefix->size;

      bit = urkel_get_bit(key, depth);
      node = urkel_node_get(node, bit);

      return urkel_tree_get(tree, value, size, node, key, depth + 1);
    }

    case URKEL_NODE_LEAF: {
      /* Prefix collision. */
      if (!urkel_node_key_equals(node, key)) {
        urkel_errno = URKEL_ENOTFOUND;
        return 0;
      }

      if (value != NULL && size != NULL) {
        if (!urkel_store_retrieve(tree->store, node, value, size)) {
          urkel_errno = URKEL_ECORRUPTION;
          return 0;
        }
      }

      return 1;
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(tree->store, node);
      int ret;

      if (rn == NULL) {
        urkel_errno = URKEL_ECORRUPTION;
        return 0;
      }

      ret = urkel_tree_get(tree, value, size, rn, key, depth);

      urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort(); /* LCOV_EXCL_LINE */
      return 0;
    }
  }
}

static urkel_node_t *
urkel_tree_insert(tree_db_t *tree,
                  urkel_node_t *node,
                  const unsigned char *key,
                  const unsigned char *value,
                  size_t size,
                  unsigned int depth) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      urkel_node_destroy(node, 0);

      /* Replace the empty node. */
      return urkel_node_create_leaf(key, value, size);
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      urkel_node_t *x, *y, *z, *out;
      unsigned int bit;
      size_t bits;

      bits = urkel_bits_count(prefix, key, depth);

      depth += bits;

      bit = urkel_get_bit(key, depth);

      if (bits != prefix->size) {
        urkel_node_t *leaf = urkel_node_create_leaf(key, value, size);
        urkel_bits_t front, back;
        urkel_node_t *child;

        urkel_bits_split(&front, &back, prefix, bits);

        child = urkel_node_create_internal(&back,
                                           internal->left,
                                           internal->right,
                                           0);

        out = urkel_node_create_internal(&front, leaf, child, bit);

        urkel_node_destroy(node, 0);

        return out;
      }

      x = urkel_node_get(node, bit ^ 0);
      y = urkel_node_get(node, bit ^ 1);
      z = urkel_tree_insert(tree, x, key, value, size, depth + 1);

      if (z == NULL)
        return NULL;

      out = urkel_node_create_internal(prefix, z, y, bit);

      urkel_node_destroy(node, 0);

      return out;
    }

    case URKEL_NODE_LEAF: {
      urkel_bits_t bits;
      urkel_bits_t prefix;
      urkel_node_t *leaf;
      unsigned int bit;

      /* Current key. */
      if (urkel_node_key_equals(node, key)) {
        /* Exact leaf already exists. */
        if (urkel_node_value_equals(node, value, size)) {
          urkel_errno = URKEL_ENOUPDATE;
          return NULL;
        }

        /* The branch doesn't grow. Replace current node. */
        leaf = urkel_node_create_leaf(key, value, size);

        urkel_node_destroy(node, 0);

        return leaf;
      }

      urkel_node_key_bits(node, &bits);
      urkel_bits_collide(&prefix, &bits, key, depth);

      depth += prefix.size;

      leaf = urkel_node_create_leaf(key, value, size);
      bit = urkel_get_bit(key, depth);

      return urkel_node_create_internal(&prefix, leaf, node, bit);
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(tree->store, node);
      urkel_node_t *ret;

      if (rn == NULL) {
        urkel_errno = URKEL_ECORRUPTION;
        return NULL;
      }

      ret = urkel_tree_insert(tree, rn, key, value, size, depth);

      if (ret != NULL)
        urkel_node_destroy(node, 0);
      else
        urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort(); /* LCOV_EXCL_LINE */
      return NULL;
    }
  }
}

static urkel_node_t *
urkel_tree_remove(tree_db_t *tree,
                  urkel_node_t *node,
                  const unsigned char *key,
                  unsigned int depth,
                  unsigned int *flag) {
  *flag = 0;

  switch (node->type) {
    case URKEL_NODE_NULL: {
      /* Empty (sub)tree. */
      urkel_errno = URKEL_ENOTFOUND;
      return NULL;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      urkel_node_t *x, *y, *z, *out;
      unsigned int bit, found;

      if (!urkel_bits_has(prefix, key, depth)) {
        urkel_errno = URKEL_ENOTFOUND;
        return NULL;
      }

      depth += prefix->size;

      bit = urkel_get_bit(key, depth);
      x = urkel_node_get(node, bit ^ 0);
      y = urkel_node_get(node, bit ^ 1);
      z = urkel_tree_remove(tree, x, key, depth + 1, &found);

      if (z == NULL)
        return NULL;

      if (found) {
        urkel_node_t *side = y;
        int resolved = 0;

        if (side->type == URKEL_NODE_HASH) {
          side = urkel_store_resolve(tree->store, side);

          if (side == NULL) {
            urkel_errno = URKEL_ECORRUPTION;
            return NULL;
          }

          resolved = 1;
        }

        if (side->type == URKEL_NODE_INTERNAL) {
          urkel_internal_t *si = &side->u.internal;
          urkel_bits_t pre;

          urkel_bits_join(&pre, prefix, &si->prefix, bit ^ 1);

          out = urkel_node_create_internal(&pre, si->left, si->right, 0);

          urkel_node_destroy(side, 0);
        } else {
          out = side;
        }

        urkel_node_destroy(node, 0);

        if (resolved)
          urkel_node_destroy(y, 0);

        urkel_node_destroy(z, 0);

        return out;
      }

      out = urkel_node_create_internal(prefix, z, y, bit);

      urkel_node_destroy(node, 0);

      return out;
    }

    case URKEL_NODE_LEAF: {
      /* Not our key. */
      if (!urkel_node_key_equals(node, key)) {
        urkel_errno = URKEL_ENOTFOUND;
        return NULL;
      }

      *flag = 1;

      urkel_node_destroy(node, 0);

      return urkel_node_create_null();
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(tree->store, node);
      urkel_node_t *ret;

      if (rn == NULL) {
        urkel_errno = URKEL_ECORRUPTION;
        return NULL;
      }

      ret = urkel_tree_remove(tree, rn, key, depth, flag);

      if (ret != NULL)
        urkel_node_destroy(node, 0);
      else
        urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort(); /* LCOV_EXCL_LINE */
      return NULL;
    }
  }
}

static int
urkel_tree_prove(tree_db_t *tree,
                 urkel_proof_t *proof,
                 urkel_node_t *node,
                 const unsigned char *key,
                 unsigned int depth) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      proof->type = URKEL_TYPE_DEADEND;
      proof->depth = depth;
      return 1;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      urkel_node_t *x, *y;
      unsigned int bit;

      if (!urkel_bits_has(prefix, key, depth)) {
        const unsigned char *left = urkel_node_hash(internal->left);
        const unsigned char *right = urkel_node_hash(internal->right);

        proof->type = URKEL_TYPE_SHORT;
        proof->depth = depth;
        proof->prefix = *prefix;

        memcpy(proof->left, left, URKEL_HASH_SIZE);
        memcpy(proof->right, right, URKEL_HASH_SIZE);

        return 1;
      }

      depth += prefix->size;

      bit = urkel_get_bit(key, depth);
      x = urkel_node_get(node, bit ^ 0);
      y = urkel_node_get(node, bit ^ 1);

      urkel_proof_push(proof, prefix, urkel_node_hash(y));

      return urkel_tree_prove(tree, proof, x, key, depth + 1);
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;
      unsigned char value[URKEL_VALUE_SIZE];
      size_t size;

      if (!urkel_store_retrieve(tree->store, node, value, &size)) {
        urkel_errno = URKEL_ECORRUPTION;
        return 0;
      }

      if (urkel_node_key_equals(node, key)) {
        proof->type = URKEL_TYPE_EXISTS;
        proof->depth = depth;
        proof->size = size;

        if (size > 0)
          memcpy(proof->value, value, size);
      } else {
        proof->type = URKEL_TYPE_COLLISION;
        proof->depth = depth;

        memcpy(proof->key, leaf->key, URKEL_KEY_SIZE);

        urkel_hash_raw(proof->hash, value, size);
      }

      return 1;
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(tree->store, node);
      int ret;

      if (rn == NULL) {
        urkel_errno = URKEL_ECORRUPTION;
        return 0;
      }

      ret = urkel_tree_prove(tree, proof, rn, key, depth);

      urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort(); /* LCOV_EXCL_LINE */
      return 0;
    }
  }
}

static urkel_node_t *
urkel_tree_write(tree_db_t *tree, urkel_node_t *node) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      return node;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_node_t *left, *right, *out;

      left = urkel_tree_write(tree, internal->left);

      if (left == NULL)
        return NULL;

      internal->left = left;

      right = urkel_tree_write(tree, internal->right);

      if (right == NULL)
        return NULL;

      internal->right = right;

      if (!(node->flags & URKEL_FLAG_WRITTEN)) {
        urkel_store_write_node(tree->store, node);

        if (urkel_store_needs_flush(tree->store)) {
          if (!urkel_store_flush(tree->store))
            return NULL;
        }
      }

      out = checked_malloc(sizeof(urkel_node_t));

      urkel_node_hash(node);
      urkel_node_to_hash(node, out);
      urkel_node_destroy(node, 1);

      return out;
    }

    case URKEL_NODE_LEAF: {
      urkel_node_t *out;

      if (!(node->flags & URKEL_FLAG_WRITTEN)) {
        urkel_store_write_value(tree->store, node);
        urkel_store_write_node(tree->store, node);

        if (urkel_store_needs_flush(tree->store)) {
          if (!urkel_store_flush(tree->store))
            return NULL;
        }
      }

      out = checked_malloc(sizeof(urkel_node_t));

      urkel_node_hash(node);
      urkel_node_to_hash(node, out);
      urkel_node_destroy(node, 1);

      return out;
    }

    case URKEL_NODE_HASH: {
      CHECK(node->flags & URKEL_FLAG_WRITTEN);
      return node;
    }

    default: {
      urkel_abort(); /* LCOV_EXCL_LINE */
      return NULL;
    }
  }
}

static urkel_node_t *
urkel_tree_commit(tree_db_t *tree, urkel_node_t *node) {
  urkel_node_t *root = urkel_tree_write(tree, node);

  if (root == NULL) {
    urkel_node_destroy(node, 1);
    urkel_errno = URKEL_EBADWRITE;
    return NULL;
  }

  if (!urkel_store_commit(tree->store, root)) {
    urkel_node_destroy(root, 0);
    urkel_errno = URKEL_EBADWRITE;
    return NULL;
  }

  memcpy(tree->hash, root->hash, URKEL_HASH_SIZE);

  return root;
}

/*
 * Database
 */

tree_db_t *
urkel_open(const char *prefix) {
  tree_db_t *tree = checked_malloc(sizeof(tree_db_t));
  const unsigned char *root;

  tree->store = urkel_store_open(prefix);

  if (tree->store == NULL) {
    urkel_errno = URKEL_EBADOPEN;
    return NULL;
  }

  tree->lock = urkel_rwlock_create();

  root = urkel_store_root_hash(tree->store);

  memcpy(tree->hash, root, URKEL_HASH_SIZE);

  tree->revert = 0;

  return tree;
}

void
urkel_close(tree_db_t *tree) {
  urkel_rwlock_wrlock(tree->lock);
  urkel_store_close(tree->store);
  urkel_rwlock_wrunlock(tree->lock);
  urkel_rwlock_destroy(tree->lock);

  free(tree);
}

int
urkel_destroy(const char *prefix) {
  if (!urkel_store_destroy(prefix)) {
    urkel_errno = URKEL_EBADOPEN;
    return 0;
  }
  return 1;
}

int
urkel__corrupt(const char *prefix) {
  if (!urkel_store__corrupt(prefix)) {
    urkel_errno = URKEL_EBADOPEN;
    return 0;
  }
  return 1;
}

void
urkel_hash(unsigned char *hash, const void *data, size_t size) {
  urkel_hash_key(hash, data, size);
}

void
urkel_root(tree_db_t *tree, unsigned char *hash) {
  urkel_rwlock_rdlock(tree->lock);

  memcpy(hash, tree->hash, URKEL_HASH_SIZE);

  urkel_rwlock_rdunlock(tree->lock);
}

int
urkel_inject(tree_db_t *tree, const unsigned char *hash) {
  int ret = 0;

  urkel_rwlock_wrlock(tree->lock);

  if (!urkel_store_has_history(tree->store, hash)) {
    urkel_errno = URKEL_ENOTFOUND;
    goto fail;
  }

  memcpy(tree->hash, hash, URKEL_HASH_SIZE);

  tree->revert = 1;

  ret = 1;
fail:
  urkel_rwlock_wrunlock(tree->lock);
  return ret;
}

int
urkel_get(tree_db_t *tree,
          unsigned char *value,
          size_t *size,
          const unsigned char *key,
          const unsigned char *root) {
  tree_tx_t *tx = urkel_tx_create(tree, root);
  int ret;

  if (tx == NULL) {
    *size = 0;
    return 0;
  }

  ret = urkel_tx_get(tx, value, size, key);

  urkel_tx_destroy(tx);

  return ret;
}

int
urkel_has(tree_db_t *tree,
          const unsigned char *key,
          const unsigned char *root) {
  tree_tx_t *tx = urkel_tx_create(tree, root);
  int ret;

  if (tx == NULL)
    return 0;

  ret = urkel_tx_has(tx, key);

  urkel_tx_destroy(tx);

  return ret;
}

int
urkel_insert(tree_db_t *tree,
             const unsigned char *key,
             const unsigned char *value,
             size_t size) {
  tree_tx_t *tx = urkel_tx_create(tree, NULL);
  int ret = 0;

  if (tx == NULL)
    return 0;

  if (!urkel_tx_insert(tx, key, value, size))
    goto fail;

  if (!urkel_tx_commit(tx))
    goto fail;

  ret = 1;
fail:
  urkel_tx_destroy(tx);
  return ret;
}

int
urkel_remove(tree_db_t *tree, const unsigned char *key) {
  tree_tx_t *tx = urkel_tx_create(tree, NULL);
  int ret = 0;

  if (tx == NULL)
    return 0;

  if (!urkel_tx_remove(tx, key))
    goto fail;

  if (!urkel_tx_commit(tx))
    goto fail;

  ret = 1;
fail:
  urkel_tx_destroy(tx);
  return ret;
}

int
urkel_prove(tree_db_t *tree,
            unsigned char **proof_raw,
            size_t *proof_len,
            const unsigned char *key,
            const unsigned char *root) {
  tree_tx_t *tx = urkel_tx_create(tree, root);
  int ret;

  if (tx == NULL) {
    *proof_raw = NULL;
    *proof_len = 0;
    return 0;
  }

  ret = urkel_tx_prove(tx, proof_raw, proof_len, key);

  urkel_tx_destroy(tx);

  return ret;
}

int
urkel_verify(int *exists,
             unsigned char *value,
             size_t *value_len,
             const unsigned char *proof_raw,
             size_t proof_len,
             const unsigned char *key,
             const unsigned char *root) {
  urkel_proof_t proof;
  int ret;

  *exists = 0;
  *value_len = 0;

  if (root == NULL) {
    urkel_errno = URKEL_EINVAL;
    return 0;
  }

  if (!urkel_proof_read(&proof, proof_raw, proof_len)) {
    urkel_errno = URKEL_EINVAL;
    return 0;
  }

  ret = urkel_proof_verify(&proof, key, root);

  if (ret == 0 && proof.type == URKEL_TYPE_EXISTS) {
    *exists = 1;

    if (proof.size > 0)
      memcpy(value, proof.value, proof.size);

    *value_len = proof.size;
  }

  urkel_proof_clear(&proof);

  urkel_errno = ret;

  return ret == 0;
}

tree_iter_t *
urkel_iterate(tree_db_t *tree, const unsigned char *root) {
  tree_tx_t *tx = urkel_tx_create(tree, root);
  tree_iter_t *iter;

  if (tx == NULL)
    return 0;

  iter = urkel_iter_create(tx);

  iter->transient = 1;

  return iter;
}

/*
 * Transaction
 */

tree_tx_t *
urkel_tx_create(tree_db_t *tree, const unsigned char *hash) {
  tree_tx_t *tx = checked_malloc(sizeof(tree_tx_t));
  int write_lock;

  urkel_rwlock_rdlock(tree->lock);

  write_lock = (hash != NULL || tree->revert);

  /* Hold the write lock in case we
     end up writing to the root cache. */
  if (write_lock) {
    urkel_rwlock_rdunlock(tree->lock);
    urkel_rwlock_wrlock(tree->lock);
  }

  tx->tree = tree;

  if (hash != NULL)
    tx->root = urkel_store_get_history(tree->store, hash);
  else if (tree->revert)
    tx->root = urkel_store_get_history(tree->store, tree->hash);
  else
    tx->root = urkel_store_get_root(tree->store);

  tx->lock = urkel_rwlock_create();

  if (tx->root == NULL) {
    urkel_errno = URKEL_ENOTFOUND;
    urkel_rwlock_destroy(tx->lock);
    free(tx);
    tx = NULL;
  }

  if (write_lock)
    urkel_rwlock_wrunlock(tree->lock);
  else
    urkel_rwlock_rdunlock(tree->lock);

  return tx;
}

void
urkel_tx_destroy(tree_tx_t *tx) {
  urkel_rwlock_wrlock(tx->lock);
  urkel_node_destroy(tx->root, 1);
  urkel_rwlock_wrunlock(tx->lock);
  urkel_rwlock_destroy(tx->lock);

  free(tx);
}

void
urkel_tx_clear(tree_tx_t *tx) {
  urkel_rwlock_wrlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  tx->root = urkel_store_get_root(tx->tree->store);

  urkel_rwlock_rdunlock(tx->tree->lock);
  urkel_rwlock_wrunlock(tx->lock);
}

void
urkel_tx_root(tree_tx_t *tx, unsigned char *hash) {
  int write_lock;

  urkel_rwlock_rdlock(tx->lock);

  write_lock = !(tx->root->flags & URKEL_FLAG_HASHED);

  /* Hold the write lock when we
     need to update the root node. */
  if (write_lock) {
    urkel_rwlock_rdunlock(tx->lock);
    urkel_rwlock_wrlock(tx->lock);
  }

  memcpy(hash, urkel_node_hash(tx->root), URKEL_HASH_SIZE);

  if (write_lock)
    urkel_rwlock_wrunlock(tx->lock);
  else
    urkel_rwlock_rdunlock(tx->lock);
}

int
urkel_tx_inject(tree_tx_t *tx, const unsigned char *hash) {
  urkel_node_t *root;

  urkel_rwlock_wrlock(tx->lock);
  urkel_rwlock_wrlock(tx->tree->lock);

  root = urkel_store_get_history(tx->tree->store, hash);

  if (root != NULL) {
    urkel_node_destroy(tx->root, 1);

    tx->root = root;
  } else {
    urkel_errno = URKEL_ENOTFOUND;
  }

  urkel_rwlock_wrunlock(tx->tree->lock);
  urkel_rwlock_wrunlock(tx->lock);

  return root != NULL;
}

int
urkel_tx_get(tree_tx_t *tx,
             unsigned char *value,
             size_t *size,
             const unsigned char *key) {
  int ret;

  urkel_rwlock_rdlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  ret = urkel_tree_get(tx->tree, value, size, tx->root, key, 0);

  if (!ret)
    *size = 0;

  urkel_rwlock_rdunlock(tx->tree->lock);
  urkel_rwlock_rdunlock(tx->lock);

  return ret;
}

int
urkel_tx_has(tree_tx_t *tx, const unsigned char *key) {
  int ret;

  urkel_rwlock_rdlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  ret = urkel_tree_get(tx->tree, NULL, NULL, tx->root, key, 0);

  urkel_rwlock_rdunlock(tx->tree->lock);
  urkel_rwlock_rdunlock(tx->lock);

  return ret;
}

int
urkel_tx_insert(tree_tx_t *tx,
                const unsigned char *key,
                const unsigned char *value,
                size_t size) {
  urkel_node_t *root;

  if (size > URKEL_VALUE_SIZE) {
    urkel_errno = URKEL_EINVAL;
    return 0;
  }

  urkel_rwlock_wrlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  root = urkel_tree_insert(tx->tree, tx->root, key, value, size, 0);

  if (root != NULL)
    tx->root = root;

  urkel_rwlock_rdunlock(tx->tree->lock);
  urkel_rwlock_wrunlock(tx->lock);

  return root != NULL || urkel_errno == URKEL_ENOUPDATE;
}

int
urkel_tx_remove(tree_tx_t *tx, const unsigned char *key) {
  urkel_node_t *root;
  unsigned int flag;

  urkel_rwlock_wrlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  root = urkel_tree_remove(tx->tree, tx->root, key, 0, &flag);

  if (root != NULL)
    tx->root = root;

  urkel_rwlock_rdunlock(tx->tree->lock);
  urkel_rwlock_wrunlock(tx->lock);

  return root != NULL;
}

int
urkel_tx_prove(tree_tx_t *tx,
               unsigned char **proof_raw,
               size_t *proof_len,
               const unsigned char *key) {
  urkel_proof_t proof;
  int write_lock, ret;

  urkel_rwlock_rdlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  write_lock = (tx->root->type != URKEL_NODE_NULL
             && tx->root->type != URKEL_NODE_HASH);

  /* Node hashes may need to be computed. */
  if (write_lock) {
    urkel_rwlock_rdunlock(tx->lock);
    urkel_rwlock_wrlock(tx->lock);
  }

  urkel_proof_init(&proof);

  ret = urkel_tree_prove(tx->tree, &proof, tx->root, key, 0);

  if (ret) {
    *proof_len = urkel_proof_size(&proof);
    *proof_raw = checked_malloc(*proof_len);

    urkel_proof_write(&proof, *proof_raw);
  } else {
    *proof_len = 0;
    *proof_raw = NULL;
  }

  urkel_proof_clear(&proof);

  urkel_rwlock_rdunlock(tx->tree->lock);

  if (write_lock)
    urkel_rwlock_wrunlock(tx->lock);
  else
    urkel_rwlock_rdunlock(tx->lock);

  return ret;
}

int
urkel_tx_commit(tree_tx_t *tx) {
  urkel_node_t *root;

  urkel_rwlock_wrlock(tx->lock);
  urkel_rwlock_wrlock(tx->tree->lock);

  root = urkel_tree_commit(tx->tree, tx->root);

  if (root != NULL)
    tx->root = root;

  urkel_rwlock_wrunlock(tx->tree->lock);
  urkel_rwlock_wrunlock(tx->lock);

  return root != NULL;
}

/*
 * Iterator
 */

tree_iter_t *
urkel_iter_create(tree_tx_t *tx) {
  tree_iter_t *iter = checked_malloc(sizeof(tree_iter_t));

  urkel_rwlock_rdlock(tx->lock);
  urkel_rwlock_rdlock(tx->tree->lock);

  iter->tree = tx->tree;
  iter->tx = tx;
  iter->lock = urkel_mutex_create();
  iter->root = tx->root;
  iter->node = NULL;
  iter->stack_len = 0;
  iter->done = 0;
  iter->transient = 0;

  return iter;
}

void
urkel_iter_destroy(tree_iter_t *iter) {
  size_t i;

  urkel_mutex_lock(iter->lock);

  for (i = 0; i < iter->stack_len; i++) {
    urkel_state_t *state = &iter->stack[i];

    if (state->resolved)
      urkel_node_destroy(state->node, 1);
  }

  urkel_rwlock_rdunlock(iter->tree->lock);
  urkel_rwlock_rdunlock(iter->tx->lock);

  if (iter->transient)
    urkel_tx_destroy(iter->tx);

  urkel_mutex_unlock(iter->lock);
  urkel_mutex_destroy(iter->lock);

  free(iter);
}

static void
urkel_iter_push(tree_iter_t *iter,
                urkel_node_t *node,
                unsigned int depth,
                int resolved) {
  urkel_state_t *state;

  CHECK(iter->stack_len < URKEL_KEY_BITS);

  state = &iter->stack[iter->stack_len++];

  state->node = node;
  state->depth = depth;
  state->resolved = resolved;
  state->child = -1;
}

static urkel_state_t *
urkel_iter_pop(tree_iter_t *iter) {
  CHECK(iter->stack_len > 0);
  return &iter->stack[--iter->stack_len];
}

static urkel_state_t *
urkel_iter_top(tree_iter_t *iter) {
  CHECK(iter->stack_len > 0);
  return &iter->stack[iter->stack_len - 1];
}

static int
urkel_iter_seek(tree_iter_t *iter) {
  tree_db_t *tree = iter->tree;

  iter->node = NULL;

  if (iter->done)
    return 0;

  if (iter->stack_len == 0) {
    urkel_iter_push(iter, iter->root, 0, 0);
  } else {
    urkel_state_t *state = urkel_iter_pop(iter);

    if (state->resolved)
      urkel_node_destroy(state->node, 1);

    if (iter->stack_len == 0) {
      iter->done = 1;
      return 0;
    }
  }

  for (;;) {
    urkel_state_t *parent = urkel_iter_top(iter);
    urkel_node_t *node = parent->node;
    unsigned int depth = parent->depth;

    switch (node->type) {
      case URKEL_NODE_NULL: {
        iter->node = node;
        return 1;
      }

      case URKEL_NODE_INTERNAL: {
        urkel_internal_t *ni = &node->u.internal;

        if (parent->child >= 1)
          return 1;

        parent->child += 1;

        if (parent->child)
          urkel_iter_push(iter, ni->right, depth + ni->prefix.size + 1, 0);
        else
          urkel_iter_push(iter, ni->left, depth + ni->prefix.size + 1, 0);

        break;
      }

      case URKEL_NODE_LEAF: {
        iter->node = node;
        return 1;
      }

      case URKEL_NODE_HASH: {
        urkel_node_t *rn;

        if (parent->child >= 0)
          return 1;

        parent->child += 1;

        rn = urkel_store_resolve(tree->store, node);

        if (rn == NULL) {
          urkel_errno = URKEL_ECORRUPTION;
          return 0;
        }

        urkel_iter_push(iter, rn, depth, 1);

        break;
      }

      default: {
        urkel_abort(); /* LCOV_EXCL_LINE */
        break;
      }
    }
  }
}

int
urkel_iter_next(tree_iter_t *iter,
                unsigned char *key,
                unsigned char *value,
                size_t *size) {
  tree_db_t *tree = iter->tree;
  urkel_leaf_t *leaf;
  int ret = 0;

  urkel_mutex_lock(iter->lock);

  while (urkel_iter_seek(iter)) {
    if (iter->node == NULL || iter->node->type != URKEL_NODE_LEAF)
      continue;

    leaf = &iter->node->u.leaf;

    memcpy(key, leaf->key, URKEL_KEY_SIZE);

    if (value != NULL && size != NULL) {
      if (!urkel_store_retrieve(tree->store, iter->node, value, size)) {
        urkel_errno = URKEL_ECORRUPTION;
        goto fail;
      }
    }

    goto succeed;
  }

  if (iter->done)
    urkel_errno = URKEL_EITEREND;

  goto fail;
succeed:
  ret = 1;
fail:
  urkel_mutex_unlock(iter->lock);
  return ret;
}

/*
 * Helpers
 */

void
urkel_free(void *ptr) {
  CHECK(ptr != NULL);

  free(ptr);
}
