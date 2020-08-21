
static int
urkel_tree_get(struct urkel_s *tree,
               const urkel_node_t *node,
               const unsigned char *key,
               unsigned char *value,
               size_t *size) {
  unsigned int depth = 0;

  *size = 0;

  for (;;) {
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
        depth += 1;

        break;
      }

      case URKEL_NODE_LEAF: {
        /* Prefix collision. */
        if (!urkel_node_key_equals(node, key))
          return 0;

        return urkel_store_retrieve(&tree->store, node, value, size);
      }

      case URKEL_NODE_HASH: {
        node = urkel_store_resolve(&tree->store, node);

        if (!node)
          return 0;

        break;
      }

      default: {
        urkel_abort();
        return 0;
      }
    }
  }
}


