static int
urkel_tree_get(struct urkel_s *tree,
               const urkel_node_t *node,
               const unsigned char *key,
               unsigned int depth,
               unsigned char *value,
               size_t *size) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      /* Empty (sub)tree. */
      return 0;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      unsigned int bit;

      CHECK(depth != URKEL_KEY_BITS);

      if (!urkel_bits_has(prefix, key, depth))
        return 0;

      depth += prefix->size;

      bit = urkel_get_bit(key, depth);
      node = urkel_node_get(node, bit);

      return urkel_tree_get(tree, node, key, depth + 1, value, size);
    }

    case URKEL_NODE_LEAF: {
      /* Prefix collision. */
      if (!urkel_node_key_equals(node, key))
        return 0;

      return urkel_store_retrieve(&tree->store, node, value, size);
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(&tree->store, node);
      int ret;

      CHECK(rn != NULL);

      ret = urkel_tree_get(tree, rn, key, depth, value, size);

      urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort();
      return 0;
    }
  }
}

static urkel_node_t *
urkel_tree_insert(struct urkel_s *tree,
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

      CHECK(depth != URKEL_KEY_BITS);

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

      if (!z)
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
        if (urkel_node_value_equals(node, value, size))
          return NULL;

        /* The branch doesn't grow. Replace current node. */
        leaf = urkel_node_create_leaf(key, value, size);

        urkel_node_destroy(node, 0);

        return leaf;
      }

      CHECK(depth != URKEL_KEY_BITS);

      urkel_node_key_bits(node, &bits);
      urkel_bits_collide(&prefix, &bits, key, depth);

      depth += prefix.size;

      leaf = urkel_node_create_leaf(key, value, size);
      bit = urkel_get_bit(key, depth);

      return urkel_node_create_internal(&prefix, leaf, node, bit);
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(&tree->store, node);

      CHECK(rn != NULL);

      return urkel_tree_insert(tree, rn, key, value, size, depth);
    }

    default: {
      urkel_abort();
      return NULL;
    }
  }
}

static urkel_node_t *
urkel_tree_remove(struct urkel_s *tree,
                  urkel_node_t *node,
                  const unsigned char *key,
                  unsigned int depth,
                  unsigned int *flag) {
  *flag = 0;

  switch (node->type) {
    case URKEL_NODE_NULL: {
      /* Empty (sub)tree. */
      return NULL;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      urkel_node_t *x, *y, *z;
      unsigned int bit, found;

      CHECK(depth != URKEL_KEY_BITS);

      if (!urkel_bits_has(prefix, key, depth))
        return NULL;

      depth += prefix->size;

      bit = urkel_get_bit(key, depth);
      x = urkel_node_get(node, bit ^ 0);
      y = urkel_node_get(node, bit ^ 1);
      z = urkel_tree_remove(tree, x, key, depth + 1, &found);

      if (!z)
        return NULL;

      if (found) {
        urkel_node_t *side = urkel_store_resolve(&tree->store, y);
        urkel_node_t *out;

        if (side->type == URKEL_NODE_INTERNAL) {
          urkel_internal_t *internal = &side->u.internal;
          urkel_bits_t pre;

          urkel_bits_join(&pre, prefix, &internal->prefix, bit ^ 1);

          out = urkel_node_create_internal(&pre, internal->left,
                                                 internal->right, 0);

          urkel_node_destroy(side, 0);
        } else {
          out = side;
        }

        urkel_node_destroy(node, 0);

        if (side != y)
          urkel_node_destroy(y, 0);

        urkel_node_destroy(z, 0);

        return out;
      }

      urkel_node_destroy(node, 0);

      return urkel_node_create_internal(prefix, z, y, bit);
    }

    case URKEL_NODE_LEAF: {
      /* Not our key. */
      if (urkel_node_key_equals(node, key))
        return NULL;

      *flag = 1;

      urkel_node_destroy(node, 0);

      return urkel_node_create_null();
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(&tree->store, node);

      CHECK(rn != NULL);

      return urkel_tree_remove(tree, rn, key, depth, flag);
    }

    default: {
      urkel_abort();
      return NULL;
    }
  }
}

static int
urkel_tree_prove(struct urkel_s *tree,
                 urkel_node_t *node,
                 const unsigned char *key,
                 unsigned int depth,
                 urkel_proof_t *proof) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      proof->type = URKEL_TYPE_DEADEND;
      proof->depth = depth;
      return 1;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      unsigned int bit;

      if (depth == URKEL_KEY_BITS)
        return 0;

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

      return urkel_tree_prove(tree, x, key, depth + 1, proof);
    }

    case URKEL_NODE_LEAF: {
      unsigned char value[URKEL_VALUE_SIZE];
      size_t size;

      if (!urkel_store_retrieve(&tree->store, node, value, &size))
        return 0;

      if (urkel_node_key_equals(node, key)) {
        proof->type = URKEL_TYPE_EXISTS;
        proof->depth = depth;
        proof->size = size;

        if (size > 0)
          memcpy(proof->value, value, size);
      } else {
        proof->type = URKEL_TYPE_COLLISION;
        proof->depth = depth;

        memcpy(proof->key, key, URKEL_KEY_SIZE);

        urkel_hash_key(proof->hash, value, size);
      }

      return 1;
    }

    case URKEL_NODE_HASH: {
      urkel_node_t *rn = urkel_store_resolve(&tree->store, node);
      int ret;

      if (rn == NULL)
        return 0;

      ret = urkel_tree_prove(tree, rn, key, depth, proof);

      urkel_node_destroy(rn, 1);

      return ret;
    }

    default: {
      urkel_abort();
      return 0;
    }
  }
}

static void
urkel_tree_write(struct urkel_s *tree, urkel_node_t *node) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      return node;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_node_t *out = checked_malloc(sizeof(urkel_node_t));

      internal->left = urkel_tree_write(tree, internal->left);
      internal->right = urkel_tree_write(tree, internal->right);

      if (!(node->flags & URKEL_FLAG_WRITTEN)) {
        urkel_store_write_node(&tree->store, node);

        if (urkel_store_needs_flush(store))
          CHECK(urkel_store_flush(store));
      }

      urkel_node_to_hash(node, out);
      urkel_node_destroy(node, 1);

      return out;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;
      urkel_node_t *out = checked_malloc(sizeof(urkel_node_t));

      if (!(node->flags & URKEL_FLAG_WRITTEN)) {
        urkel_store_write_value(&tree->store, node);
        urkel_store_write_node(&tree->store, node);

        if (urkel_store_needs_flush(store))
          CHECK(urkel_store_flush(store));
      }

      urkel_node_to_hash(node, out);
      urkel_node_destroy(node, 1);

      return out;
    }

    case URKEL_NODE_HASH: {
      CHECK(node->flags & URKEL_FLAG_WRITTEN);
      return node;
    }

    default: {
      urkel_abort();
      break;
    }
  }
}

static urkel_node_t *
urkel_tree_commit(struct urkel_s *tree, urkel_node_t *node) {
  urkel_node_t *root = urkel_tree_write(tree, node);
  int ret = urkel_store_commit(root);

  if (!ret) {
    urkel_node_destroy(root, 0);
    return NULL;
  }

  tree->writes += 1;

  return root;
}

struct urkel_s {
  urkel_store_t store;
  urkel_rwlock_t *lock;
  unsigned int writes;
};

struct urkel_tx_s {
  struct urkel_s *tree;
  urkel_node_t *root;
  int snapshot;
  unsigned int writes;
};

struct urkel_s *
urkel_open(const unsigned char *prefix) {
  struct urkel_s *tree = checked_malloc(sizeof(struct urkel_s));

  if (!urkel_store_open(&tree->store, prefix))
    return NULL;

  tree->lock = urkel_rwlock_create();
  tree->writes = 0;

  return tree;
}

void
urkel_close(struct urkel_s *tree) {
  urkel_rwlock_wrlock(tree->lock);
  urkel_store_close(&tree->store);
  urkel_rwlock_unlock(tree->lock);
  urkel_rwlock_destroy(tree->lock);

  free(tree);
}

struct urkel_tx_s *tx
urkel_tx_create(struct urkel_s *tree, const unsigned char *hash) {
  struct urkel_tx_s *tx = checked_malloc(sizeof(struct urkel_tx_s));
  unsigned char *root_hash;

  urkel_rwlock_rdlock(tree->lock);

  tx->tree = tree;

  if (hash) {
    root_hash = tree->store.state.root_node.hash;
    tx->root = urkel_store_get_history(&tree->store, hash);
    tx->snapshot = memcmp(hash, root_hash) != 0;
  } else {
    tx->root = urkel_store_get_root(&tree->store);
    tx->snapshot = 0;
  }

  tx->writes = tree->writes;

  if (tx->root == NULL) {
    free(tx);
    tx = NULL;
  }

  urkel_rwlock_unlock(tree->lock);

  return tx;
}

void
urkel_tx_destroy(struct urkel_tx_s *tx) {
  struct urkel_s *tree = tx->tree;

  urkel_rwlock_wrlock(tree->lock);

  if (tx->root) {
    urkel_node_destroy(tx->root, 1);
    tx->root = NULL;
  }

  free(tx);

  urkel_rwlock_unlock(tree->lock);
}

void
urkel_tx_clear(struct urkel_tx_s *tx) {
  urkel_rwlock_rdlock(tree->lock);

  tx->root = urkel_store_get_root(&tree->store);
  tx->snapshot = 0;
  tx->writes = tree->writes;

  urkel_rwlock_unlock(tree->lock);
}

int
urkel_tx_get(struct urkel_tx_s *tx,
             const unsigned char *key,
             unsigned char *value,
             size_t *size) {
  int ret = 0;

  urkel_rwlock_rdlock(tx->tree->lock);

  if (tx->root == NULL)
    goto fail;

  ret = urkel_tree_get(tx->tree, tx->root, key, value, size);
fail:
  urkel_rwlock_unlock(tx->tree->lock);
  return ret;
}

int
urkel_tx_insert(struct urkel_tx_s *tx,
                const unsigned char *key,
                const unsigned char *value,
                size_t size) {
  urkel_node_t *root = NULL;

  urkel_rwlock_wrlock(tx->tree->lock);

  if (tx->root == NULL)
    goto fail;

  root = urkel_tree_insert(tx->tree, tx->root, key, value, size, 0);

  if (root)
    tx->root = root;
fail:
  urkel_rwlock_unlock(tx->tree->lock);
  return root != NULL;
}

int
urkel_tx_remove(struct urkel_tx_s *tx, const unsigned char *key) {
  urkel_node_t *root = NULL;
  unsigned int flag;

  urkel_rwlock_wrlock(tx->tree->lock);

  if (tx->root == NULL)
    goto fail;

  root = urkel_tree_remove(tx->tree, tx->root, key, 0, &flag);

  if (root)
    tx->root = root;
fail:
  urkel_rwlock_unlock(tx->tree->lock);
  return root != NULL;
}

int
urkel_tx_prove(struct urkel_tx_s *tx,
               unsigned char *raw,
               size_t *raw_len,
               const unsigned char *key) {
  urkel_proof_t proof;
  int ret = 0;

  urkel_proof_init(&proof);

  if (tx->root->type == URKEL_NODE_NULL
      || tx->root->type == URKEL_NODE_HASH) {
    urkel_rwlock_rdlock(tx->tree->lock);
  } else {
    urkel_rwlock_wrlock(tx->tree->lock);
  }

  if (tx->root == NULL)
    goto fail;

  ret = urkel_tree_prove(tx->tree, tx->root, key, 0, &proof);

  if (ret)
    *raw_len = urkel_proof_write(proof, raw) - raw;
fail:
  urkel_rwlock_unlock(tx->tree->lock);
  return ret;
}

int
urkel_tx_commit(struct urkel_tx_s *tx) {
  urkel_node_t *root = NULL;

  urkel_rwlock_wrlock(tx->tree->lock);

  if (tx->root == NULL)
    goto fail;

  if (tx->snapshot)
    goto fail;

  if (tx->writes != tx->tree->writes)
    goto fail;

  root = urkel_tree_commit(tx->tree, tx->root);

  if (root) {
    tx->root = root;
    tx->writes += 1;
  }
fail:
  urkel_rwlock_unlock(tx->tree->lock);
  return root != NULL;
}

typedef urkel_state_s {
  urkel_node_t *node;
  unsigned int depth;
  int resolved;
  int child;
} urkel_state_t;

struct urkel_iter_s {
  struct urkel_s *tree;
  urkel_node_t *root;
  urkel_node_t *node;
  urkel_state_t stack[URKEL_KEY_BITS];
  size_t stack_len;
  int done;
};

struct urkel_iter_s *
urkel_iter_create(struct urkel_tx_s *tx) {
  struct urkel_iter_s *iter = checked_malloc(sizeof(urkel_iter_s));

  urkel_rwlock_rdlock(tx->tree->lock);

  iter->tree = tx->tree;
  iter->root = tx->root;
  iter->node = NULL;
  iter->stack_len = 0;
  iter->done = 0;

  return iter;
}

void
urkel_iter_destroy(struct urkel_iter_s *iter) {
  struct urkel_s *tree = iter->tree;
  size_t i;

  for (i = 0; i < iter->stack_len; i++) {
    urkel_state_t *state = &iter->stack[i];

    if (state->resolved)
      urkel_node_destroy(state->node, 1);
  }

  free(iter);

  urkel_rwlock_unlock(tree->lock);
}

static void
urkel_iter_push(struct urkel_iter_s *iter,
                urkel_node_t *node,
                unsigned int depth,
                int resolved) {
  urkel_state_t *state = &iter->stack[iter->stack_len++];

  CHECK(iter->stack_len <= URKEL_KEY_BITS);

  state->node = node;
  state->depth = depth;
  state->resolved = resolved;
  state->child = -1;
}

static urkel_state_t *
urkel_iter_pop(struct urkel_iter_s *iter) {
  CHECK(iter->stack_len > 0);
  return &node->stack[--iter->stack_len];
}

static urkel_state_t *
urkel_iter_top(struct urkel_iter_s *iter) {
  CHECK(iter->stack_len > 0);
  return &node->stack[iter->stack_len - 1];
}

static int
urkel_iter_seek(struct urkel_iter_s *iter) {
  struct urkel_s *tree = iter->tree;

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
          urkel_iter_push(ni->right, depth + ni->prefix.size + 1, 0);
        else
          urkel_iter_push(ni->left, depth + ni->prefix.size + 1, 0);

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

        rn = urkel_store_resolve(&tree->store, node);

        CHECK(rn != NULL);

        urkel_iter_push(rn, depth, 1);

        break;
      }

      default: {
        urkel_abort();
        break;
      }
    }
  }
}

int
urkel_iter_next(struct urkel_iter_s *iter,
                unsigned char *key,
                unsigned char *value,
                size_t *size) {
  struct urkel_s *tree = iter->tree;
  urkel_leaf_t *leaf;

  while (urkel_iter_seek(iter)) {
    if (iter->node == NULL || iter->node->type != URKEL_NODE_LEAF)
      continue;

    leaf = &iter->node.u.leaf;

    memcpy(key, leaf->key, URKEL_KEY_SIZE);

    if (value && size)
      CHECK(urkel_store_retrieve(&tree->store, iter->node, value, size));

    return 1;
  }

  return 0;
}
