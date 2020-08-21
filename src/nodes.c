#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bits.h"
#include "bio.h"
#include "nodes.h"

static urkel_node_t urkel_node_null = {
  URKEL_NODE_NULL,
  URKEL_FLAG_HASHED | URKEL_FLAG_WRITTEN,
  {0},
  {0, 0, 0}
};

void
urkel_pointer_init(urkel_pointer_t *ptr) {
  ptr->index = 0;
  ptr->pos = 0;
  ptr->size = 0;
}

unsigned char *
urkel_pointer_write(const urkel_pointer_t *ptr, unsigned char *data) {
  size_t size = ptr->size;
  size_t bits = size >> 8;
  size_t hi = bits >> 1;
  size_t lo = bits & 1;

  data = urkel_write16(data, (ptr->index << 1) | hi);
  data = urkel_write32(data, (ptr->pos << 1) | lo);
  data = urkel_write8(data, size);

  return data;
}

void
urkel_pointer_read(urkel_pointer_t *ptr, const unsigned char *data) {
  size_t index = urkel_read16(data);
  size_t pos = urkel_read32(data + 2);
  size_t size = urkel_read8(data + 6);
  size_t hi = index & 1;
  size_t lo = pos & 1;

  ptr->index = index >> 1;
  ptr->pos = pos >> 1;
  ptr->size = (hi << 9) | (lo << 8) | size;
}

void
urkel_node_init(urkel_node_t *node, unsigned int type) {
  node->type = type;
  node->flags = 0;

  memset(node->hash, 0, sizeof(node->hash));

  urkel_pointer_init(&node->ptr);

  switch (type) {
    case URKEL_NODE_NULL: {
      node->flags = URKEL_FLAG_HASHED | URKEL_FLAG_WRITTEN;
      break;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;

      urkel_bits_init(&internal->prefix, 0);

      internal->left = &urkel_node_null;
      internal->right = &urkel_node_null;

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      memset(leaf->key, 0, sizeof(leaf->key));

      leaf->value = NULL;
      leaf->size = 0;

      urkel_pointer_init(&leaf->vptr);

      break;
    }

    case URKEL_NODE_HASH: {
      node->flags = URKEL_FLAG_HASHED;
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }
}

void
urkel_node_uninit(urkel_node_t *node) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      break;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;

      urkel_node_destroy(internal->left, 1);
      urkel_node_destroy(internal->right, 1);

      internal->left = &urkel_node_null;
      internal->right = &urkel_node_null;

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      if (leaf->value) {
        free(leaf->value);

        leaf->value = NULL;
        leaf->size = 0;

        node->flags &= ~URKEL_FLAG_VALUE;
      }

      break;
    }

    case URKEL_NODE_HASH: {
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }
}

void
urkel_node_hashed(urkel_node_t *node, const unsigned char *hash) {
  CHECK(node->type != URKEL_NODE_NULL);

  memcpy(node->hash, hash, URKEL_HASH_SIZE);

  node->flags |= URKEL_FLAG_HASHED;
}

void
urkel_node_mark(urkel_node_t *node,
                uint16_t index,
                uint32_t pos,
                uint8_t size) {
  CHECK(node->type != URKEL_NODE_NULL);

  node->ptr.index = index;
  node->ptr.pos = pos;
  node->ptr.size = size;
  node->flags |= URKEL_FLAG_WRITTEN;
}

void
urkel_node_store(urkel_node_t *node,
                 const unsigned char *data,
                 size_t size) {
  urkel_leaf_t *leaf = &node->u.leaf;
  unsigned char *value = checked_malloc(size + 1);

  CHECK(node->type == URKEL_NODE_LEAF);
  CHECK(!(node->flags & URKEL_FLAG_VALUE));

  if (size > 0)
    memcpy(value, data, size);

  leaf->value = value;
  leaf->size = size;

  node->flags |= URKEL_FLAG_VALUE;
}

void
urkel_node_save(urkel_node_t *node,
                uint16_t index,
                uint32_t pos,
                uint8_t size) {
  urkel_leaf_t *leaf = &node->u.leaf;

  CHECK(node->type == URKEL_NODE_LEAF);

  leaf->vptr.index = index;
  leaf->vptr.pos = pos;
  leaf->vptr.size = size;

  node->flags |= URKEL_FLAG_SAVED;
}

void
urkel_node_to_hash(urkel_node_t *node, urkel_node_t *out) {
  urkel_node_hash(node);

  CHECK(node->flags & URKEL_FLAG_HASHED);
  CHECK(node->flags & URKEL_FLAG_WRITTEN);

  if (node->type == URKEL_NODE_NULL) {
    *out = *node;
    return;
  }

  urkel_node_init(out, URKEL_NODE_HASH);
  urkel_node_hashed(out, node->hash);
  urkel_node_mark(out, node->ptr.index,
                       node->ptr.pos,
                       node->ptr.size);
}

urkel_node_t *
urkel_node_get(const urkel_node_t *node, unsigned int bit) {
  const urkel_internal_t *internal = &node->u.internal;

  CHECK(node->type == URKEL_NODE_INTERNAL);

  switch (bit) {
    case 0:
      return internal->left;
    case 1:
      return internal->right;
    default:
      urkel_abort();
      break;
  }
}

void
urkel_node_set(urkel_node_t *node, unsigned int bit, urkel_node_t *child) {
  urkel_internal_t *internal = &node->u.internal;

  CHECK(node->type == URKEL_NODE_INTERNAL);

  switch (bit) {
    case 0:
      internal->left = child;
      break;
    case 1:
      internal->right = child;
      break;
    default:
      urkel_abort();
      break;
  }
}

urkel_node_t *
urkel_node_create(unsigned int type) {
  urkel_node_t *node = checked_malloc(sizeof(urkel_node_t));

  urkel_node_init(node, type);

  return node;
}

urkel_node_t *
urkel_node_create_null(void) {
  return urkel_node_create(URKEL_NODE_NULL);
}

urkel_node_t *
urkel_node_create_internal(const urkel_bits_t *prefix,
                           urkel_node_t *x,
                           urkel_node_t *y,
                           unsigned int bit) {
  urkel_node_t *node = urkel_node_create(URKEL_NODE_INTERNAL);
  urkel_internal_t *internal = &node->u.internal;

  memcpy(internal->prefix, prefix, sizeof(*prefix));

  urkel_node_set(node, bit ^ 0, x);
  urkel_node_set(node, bit ^ 1, y);

  return node;
}

urkel_node_t *
urkel_node_create_leaf(const unsigned char *data, size_t size) {
  urkel_node_t *node = urkel_node_create(URKEL_NODE_LEAF);
  urkel_leaf_t *leaf = &node->u.leaf;

  urkel_node_store(node, data, size);
  urkel_node_hash(node);

  return node;
}

urkel_node_t *
urkel_node_create_hash(const unsigned char *hash) {
  urkel_node_t *node = urkel_node_create(URKEL_NODE_HASH);

  memcpy(node->hash, hash, URKEL_HASH_SIZE);

  return node;
}

void
urkel_node_destroy(urkel_node_t *node, int recurse) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      CHECK(node != &urkel_node_null);
      free(node);
      break;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;

      if (recurse) {
        urkel_node_destroy(internal->left, 1);
        urkel_node_destroy(internal->right, 1);
      }

      free(node);

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      if (leaf->value)
        free(leaf->value);

      free(node);

      break;
    }

    case URKEL_NODE_HASH: {
      free(node);
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }
}

const unsigned char *
urkel_node_hash(urkel_node_t *node) {
  if (node->flags & URKEL_FLAG_HASHED)
    return node->hash;

  switch (node->type) {
    case URKEL_NODE_NULL: {
      CHECK(node != &urkel_node_null);
      break;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      const unsigned char *left = urkel_node_hash(internal->left);
      const unsigned char *right = urkel_node_hash(internal->right);

      urkel_hash_internal(node->hash, prefix, left, right);

      node->flags |= URKEL_FLAG_HASHED;

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      CHECK(node->flags & URKEL_FLAG_VALUE);

      urkel_hash_value(node->hash, leaf->key,
                                   leaf->value,
                                   leaf->size);

      node->flags |= URKEL_FLAG_HASHED;

      break;
    }

    case URKEL_NODE_HASH: {
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }

  return node->hash;
}

void
urkel_node_key_bits(const urkel_node_t *node, urkel_bits_t *bits) {
  const urkel_leaf_t *leaf = &node->u.leaf;

  CHECK(node->type == URKEL_NODE_LEAF);

  urkel_bits_init(bits, URKEL_KEY_BITS);

  memcpy(bits->data, leaf->key, URKEL_KEY_SIZE);
}

int
urkel_node_key_equals(const urkel_node_t *node, const unsigned char *key) {
  const urkel_leaf_t *leaf = &node->u.leaf;

  CHECK(node->type == URKEL_NODE_LEAF);

  return memcmp(leaf->key, key, URKEL_KEY_SIZE) == 0;
}

int
urkel_node_value_equals(const urkel_node_t *node,
                        const unsigned char *value,
                        size_t size) {
  const urkel_leaf_t *leaf = &node->u.leaf;

  CHECK(node->type == URKEL_NODE_LEAF);

  if (!(node->flags & URKEL_FLAG_VALUE))
    return 0;

  if (leaf->size != size)
    return 0;

  if (leaf->size == 0)
    return 1;

  return memcmp(leaf->value, value, size) == 0;
}

unsigned int
urkel_node_flags(const urkel_node_t *node) {
  const urkel_internal_t *internal = &node->u.internal;
  const urkel_bits_t *prefix = &internal->prefix;
  unsigned int flags = 0;

  CHECK(node->type == URKEL_NODE_INTERNAL);

  if (prefix->size > 0)
    flags |= 1;

  if (prefix->size > 255)
    flags |= 2;

  return flags;
}

size_t
urkel_node_size(const urkel_node_t *node) {
  size_t size = 0;

  switch (node->type) {
    case URKEL_NODE_NULL: {
      urkel_abort();
      break;
    }

    case URKEL_NODE_INTERNAL: {
      const urkel_internal_t *internal = &node->u.internal;
      const urkel_bits_t *prefix = &internal->prefix;
      size_t bytes = (prefix->size + 7) / 8;

      size += 1;

      if (prefix->size > 255) {
        size += 2;
        size += bytes;
      } else if (prefix->size > 0) {
        size += 1;
        size += bytes;
      }

      size += URKEL_PTR_SIZE;
      size += URKEL_HASH_SIZE;

      size += URKEL_PTR_SIZE;
      size += URKEL_HASH_SIZE;

      break;
    }

    case URKEL_NODE_LEAF: {
      size += 1;
      size += URKEL_PTR_SIZE
      size += URKEL_KEY_SIZE;
      break;
    }

    case URKEL_NODE_HASH: {
      urkel_abort();
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }

  return size;
}

unsigned char *
urkel_node_write(urkel_node_t *node, unsigned char *data) {
  switch (node->type) {
    case URKEL_NODE_NULL: {
      urkel_abort();
      break;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      urkel_node_t *left = internal->left;
      urkel_node_t *right = internal->right;
      unsigned int type = (urkel_node_flags(node) << 4) | URKEL_NODE_INTERNAL;
      size_t bytes = (prefix->size + 7) / 8;

      data = urkel_write8(data, type);

      if (prefix->size > 255) {
        data = urkel_write16(data, prefix->size);
        data = urkel_write(data, prefix->data, bytes);
      } else if (prefix->size > 0) {
        data = urkel_write8(data, prefix->size);
        data = urkel_write(data, prefix->data, bytes);
      }

      CHECK(left->flags & URKEL_FLAG_WRITTEN);
      CHECK(right->flags & URKEL_FLAG_WRITTEN);

      urkel_node_hash(left);
      urkel_node_hash(right);

      data = urkel_pointer_write(&left->ptr, data);
      data = urkel_write(data, left->hash, URKEL_HASH_SIZE);

      data = urkel_pointer_write(&right->ptr, data);
      data = urkel_write(data, right->hash, URKEL_HASH_SIZE);

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      CHECK(node->flags & URKEL_FLAG_SAVED);

      data = urkel_write8(data, URKEL_NODE_LEAF);
      data = urkel_pointer_write(&leaf->vptr, data);
      data = urkel_write(data, leaf->key, URKEL_KEY_SIZE);

      break;
    }

    case URKEL_NODE_HASH: {
      urkel_abort();
      break;
    }

    default: {
      urkel_abort();
      break;
    }
  }

  return data;
}

int
urkel_node_read(urkel_node_t *node, const unsigned char *data, size_t len) {
  unsigned int type;

  if (len < 1)
    return 0;

  type = urkel_read8(data);
  data += 1;
  len -= 1;

  switch (type & 15) {
    case URKEL_NODE_NULL: {
      return 0;
    }

    case URKEL_NODE_INTERNAL: {
      urkel_internal_t *internal = &node->u.internal;
      urkel_bits_t *prefix = &internal->prefix;
      unsigned int flags = type >> 4;
      urkel_node_t *left, *right;

      urkel_node_init(node, URKEL_NODE_INTERNAL);

      if (flags & 1) {
        size_t size = 0;
        size_t bytes;

        if (len < 2)
          return 0;

        if (flags & 2) {
          size = urkel_read16(data);

          if (size < 0x100)
            return 0;

          data += 2;
          len -= 2;
        } else {
          size = urkel_read8(data);

          if (size == 0)
            return 0;

          data += 1;
          len -= 1;
        }

        bytes = (size + 7) / 8;

        if (len < bytes)
          return 0;

        urkel_bits_init(prefix, size);

        urkel_read(prefix->data, data, bytes);

        data += bytes;
        len -= bytes;
      }

      if (len < 2 * (URKEL_PTR_SIZE + URKEL_HASH_SIZE))
        return 0;

      left = urkel_node_create(URKEL_NODE_HASH);
      right = urkel_node_create(URKEL_NODE_HASH);

      urkel_pointer_read(&left->ptr, data);
      data += URKEL_PTR_SIZE;

      urkel_read(left->hash, data, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      urkel_pointer_read(&right->ptr, data);
      data += URKEL_PTR_SIZE;

      urkel_read(right->hash, data, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      internal->left = left;
      internal->right = right;

      break;
    }

    case URKEL_NODE_LEAF: {
      urkel_leaf_t *leaf = &node->u.leaf;

      urkel_node_init(node, URKEL_NODE_LEAF);

      if (len < URKEL_PTR_SIZE + URKEL_KEY_SIZE)
        return 0;

      urkel_pointer_read(&leaf->vptr, data);
      data += URKEL_PTR_SIZE;

      urkel_read(leaf->key, data, URKEL_KEY_SIZE);
      data += URKEL_KEY_SIZE;

      node->flags |= URKEL_FLAG_SAVED;

      break;
    }

    case URKEL_NODE_HASH: {
      return 0;
    }

    default: {
      return 0;
    }
  }

  return 1;
}
