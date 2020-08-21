#ifndef _URKEL_NODES_H
#define _URKEL_NODES_H

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

#define URKEL_NODE_NULL 0
#define URKEL_NODE_INTERNAL 1
#define URKEL_NODE_LEAF 2
#define URKEL_NODE_HASH 3

#define URKEL_FLAG_HASHED 1
#define URKEL_FLAG_WRITTEN 2
#define URKEL_FLAG_SAVED 4
#define URKEL_FLAG_VALUE 8

#define URKEL_PTR_SIZE 7

/* 113 */
#define URKEL_MAX_NODE_SIZE (0             \
  + 1                                      \
  + 2 + URKEL_KEY_SIZE                     \
  + 2 * (URKEL_PTR_SIZE + URKEL_HASH_SIZE) \
)

struct urkel_node_s;

typedef struct urkel_pointer_s {
  uint32_t index;
  uint64_t pos;
  size_t size;
} urkel_pointer_t;

typedef struct urkel_internal_s {
  urkel_bits_t prefix;
  struct urkel_node_s *left;
  struct urkel_node_s *right;
} urkel_internal_t;

typedef struct urkel_leaf_s {
  unsigned char key[URKEL_KEY_SIZE];
  unsigned char *value;
  size_t size;
  urkel_pointer_t vptr;
} urkel_leaf_t;

typedef struct urkel_node_s {
  unsigned int type;
  unsigned int flags;
  unsigned char hash[URKEL_HASH_SIZE];
  urkel_pointer_t ptr;
  union {
    urkel_internal_t internal;
    urkel_leaf_t leaf;
  } u;
} urkel_node_t;

void
urkel_pointer_init(urkel_pointer_t *ptr);

unsigned char *
urkel_pointer_write(const urkel_pointer_t *ptr, unsigned char *data);

void
urkel_pointer_read(urkel_pointer_t *ptr, const unsigned char *data);

void
urkel_node_init(urkel_node_t *node, unsigned int type);

void
urkel_node_uninit(urkel_node_t *node);

void
urkel_node_hashed(urkel_node_t *node, const unsigned char *hash);

void
urkel_node_mark(urkel_node_t *node,
                uint16_t index,
                uint32_t pos,
                uint8_t size);

void
urkel_node_store(urkel_node_t *node,
                 const unsigned char *data,
                 size_t size);

void
urkel_node_save(urkel_node_t *node,
                uint16_t index,
                uint32_t pos,
                uint8_t size);

void
urkel_node_to_hash(urkel_node_t *node, urkel_node_t *out);

urkel_node_t *
urkel_node_get(const urkel_node_t *node, unsigned int bit);

void
urkel_node_set(urkel_node_t *node, unsigned int bit, urkel_node_t *child);

urkel_node_t *
urkel_node_create(unsigned int type);

urkel_node_t *
urkel_node_create_null(void);

urkel_node_t *
urkel_node_create_internal(const urkel_bits_t *prefix,
                           urkel_node_t *x,
                           urkel_node_t *y,
                           unsigned int bit);

urkel_node_t *
urkel_node_create_leaf(const unsigned char *data, size_t size);

urkel_node_t *
urkel_node_create_hash(const unsigned char *hash);

void
urkel_node_destroy(urkel_node_t *node, int recurse);

const unsigned char *
urkel_node_hash(urkel_node_t *node);

void
urkel_node_key_bits(const urkel_node_t *node, urkel_bits_t *bits);

int
urkel_node_key_equals(const urkel_node_t *node, const unsigned char *key);

int
urkel_node_value_equals(const urkel_node_t *node,
                        const unsigned char *value,
                        size_t size);

size_t
urkel_node_size(const urkel_node_t *node);

unsigned char *
urkel_node_write(urkel_node_t *node, unsigned char *data);

int
urkel_node_read(urkel_node_t *node, const unsigned char *data, size_t len);

#endif /* _URKEL_NODES_H */
