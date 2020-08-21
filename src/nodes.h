
#define URKEL_NODE_NULL 0
#define URKEL_NODE_INTERNAL 1
#define URKEL_NODE_LEAF 2
#define URKEL_NODE_HASH 3

#define URKEL_FLAG_HASHED 1
#define URKEL_FLAG_WRITTEN 2
#define URKEL_FLAG_SAVED 4
#define URKEL_FLAG_VALUE 8

#define URKEL_PTR_SIZE 7
#define URKEL_HASH_SIZE 32
#define URKEL_KEY_SIZE 32
#define URKEL_VALUE_SIZE 1024

#define URKEL_MAX_NODE_SIZE (0             \
  + 1                                      \
  + 2 + URKEL_KEY_SIZE                     \
  + 2 * (URKEL_PTR_SIZE + URKEL_HASH_SIZE) \
)

typedef struct urkel_pointer_s {
  uint16_t index;
  uint32_t pos;
  uint8_t size;
} urkel_pointer_t;

typedef struct urkel_internal_s {
  urkel_bits_t prefix;
  urkel_node_t *left;
  urkel_node_t *right;
} urkel_internal_t;

typedef struct urkel_leaf_s {
  unsigned char key[32];
  unsigned char *value;
  size_t size;
  urkel_pointer_t vptr;
} urkel_leaf_t;

typedef struct urkel_node_s {
  unsigned int type;
  unsigned int flags;
  unsigned char hash[32];
  urkel_pointer_t ptr;
  union {
    urkel_internal_t internal;
    urkel_leaf_t leaf;
  } u;
} urkel_node_t;
