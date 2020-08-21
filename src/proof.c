#define URKEL_TYPE_DEADEND 0
#define URKEL_TYPE_SHORT 1
#define URKEL_TYPE_COLLISION 2
#define URKEL_TYPE_EXISTS 3
#define URKEL_TYPE_UNKNOWN 4

#define URKEL_PROOF_OK 0
#define URKEL_PROOF_HASH_MISMATCH 1
#define URKEL_PROOF_SAME_KEY 2
#define URKEL_PROOF_SAME_PATH 3
#define URKEL_PROOF_NEG_DEPTH 4
#define URKEL_PROOF_PATH_MISMATCH 5
#define URKEL_PROOF_TOO_DEEP 6
#define URKEL_PROOF_UNKNOWN_ERROR 7

typedef struct urkel_proof_node_s {
  urkel_bits_t prefix;
  unsigned char hash[32];
} urkel_proof_node_t;

typedef struct urkel_proof_s {
  unsigned int type;
  unsigned int depth;
  urkel_proof_node_t *nodes[URKEL_KEY_BITS];
  size_t nodes_len;
  urkel_bits_t prefix;
  unsigned char left[URKEL_HASH_SIZE];
  unsigned char right[URKEL_HASH_SIZE];
  unsigned char key[URKEL_KEY_SIZE];
  unsigned char hash[URKEL_HASH_SIZE];
  unsigned char value[URKEL_VALUE_SIZE];
  size_t size;
} urkel_proof_t;

void
urkel_proof_init(urkel_proof_t *proof) {
  memset(proof, 0, sizeof(*proof));
}

void
urkel_proof_uninit(urkel_proof_t *proof) {
  size_t i;

  for (i = 0; i < proof->nodes_len; i++)
    free(proof->nodes[i]);

  proof->nodes_len = 0;
}

void
urkel_proof_push(urkel_proof_t *proof,
                 const urkel_bits_t *prefix,
                 const unsigned char *hash) {
  urkel_proof_node_t *node = checked_malloc(sizeof(urkel_proof_node_t));

  CHECK(proof->nodes_len < URKEL_KEY_BITS);

  node->prefix = *prefix;

  memcpy(node->hash, hash, URKEL_HASH_SIZE);

  proof->nodes[proof->nodes_len++] = node;
}

size_t
urkel_proof_size(const urkel_proof_t *proof) {
  size_t size = 0;

  size += 2;
  size += 2;
  size += (proof->nodes_len + 7) / 8;

  for (i = 0; i < proof->nodes_len; i++) {
    const urkel_proof_node_t *node = proof->nodes[i];

    if (node->prefix.size != 0)
      size += urkel_bits_size(&node->prefix);

    size += URKEL_HASH_SIZE;
  }

  switch (proof->type) {
    case URKEL_TYPE_DEADEND:
      break;
    case URKEL_TYPE_SHORT:
      size += urkel_bits_size(&proof->prefix);
      size += URKEL_HASH_SIZE;
      size += URKEL_HASH_SIZE;
      break;
    case URKEL_TYPE_COLLISION:
      size += URKEL_KEY_SIZE;
      size += URKEL_HASH_SIZE;
      break;
    case URKEL_TYPE_EXISTS:
      size += 2;
      size += proof->size;
      break;
  }

  return size;
}

unsigned char *
urkel_proof_write(const urkel_proof_t *proof, unsigned char *data) {
  size_t count = proof->nodes_len;
  size_t bsize = (count + 7) / 8;
  uint16_t field = (proof->type << 14) | proof->depth;
  unsigned char *bits = data + 4;
  size_t i;

  data = urkel_write16(data, field);
  data = urkel_write16(data, count);

  memset(data, 0, bsize);
  data += bsize;

  for (i = 0; i < proof->nodes_len; i++) {
    const urkel_proof_node_t *node = proof->nodes[i];

    if (node->prefix.size != 0) {
      urkel_set_bit(bits, i, 1);
      data = urkel_bits_write(&node->prefix, data);
    }

    memcmpy(data, node->hash, URKEL_HASH_SIZE);
    data += URKEL_HASH_SIZE;
  }

  switch (proof->type) {
    case URKEL_TYPE_DEADEND: {
      break;
    }

    case URKEL_TYPE_SHORT: {
      data = urkel_bits_write(&proof->prefix, data);

      memcpy(data, proof->left, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      memcpy(data, proof->right, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      break;
    }

    case URKEL_TYPE_COLLISION: {
      memcpy(data, proof->key, URKEL_KEY_SIZE);
      data += URKEL_KEY_SIZE;

      memcpy(data, proof->hash, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      break;
    }

    case URKEL_TYPE_EXISTS: {
      data = urkel_write16(data, proof->size);

      if (proof->size > 0)
        memcpy(data, proof->value, proof->size);

      data += proof->size;

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
urkel_proof_read(urkel_proof_t *proof, const unsigned char *data, size_t size) {
  size_t i, count, bsize, size;
  const unsigned char *bits;
  unsigned char hash[32];
  urkel_bits_t prefix;
  uint16_t field;

  urkel_proof_init(proof);

  if (len < 4)
    return 0;

  field = urkel_read16(data + 0);
  count = urkel_read16(data + 2);
  bits = data + 4;
  bsize = (count + 7) / 8;
  data += 4;
  len -= 4;

  proof->type = field >> 14;
  proof->depth = field & ~(3 << 14);

  if (proof->depth > URKEL_KEY_BITS)
    return 0;

  if (count > URKEL_KEY_BITS)
    return 0;

  if (len < bsize)
    return 0;

  data += bsize;
  len -= bsize;

  for (i = 0; i < count; i++) {
    urkel_bits_init(&prefix);

    if (urkel_get_bit(bits, i)) {
      if (!urkel_bits_read(&prefix, data, len))
        return 0;

      if (prefix.size == 0 || prefix.size > URKEL_KEY_BITS)
        return 0;

      data += urkel_bits_size(&prefix);
    }

    if (len < URKEL_HASH_SIZE)
      return 0;

    memcpy(hash, data, URKEL_HASH_SIZE);
    data += URKEL_HASH_SIZE;

    urkel_proof_push(proof, &prefix, hash);
  }

  switch (proof->type) {
    case URKEL_TYPE_DEADEND: {
      break;
    }

    case URKEL_TYPE_SHORT: {
      if (!urkel_bits_read(&proof->prefix, data, len))
        return 0;

      if (proof->prefix.size === 0 || proof->prefix.size > URKEL_KEY_BITS)
        return 0;

      data += urkel_bits_size(&proof->prefix);

      if (len < URKEL_HASH_SIZE * 2)
        return 0;

      memcpy(proof->left, data, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      memcpy(proof->right, data, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      break;
    }

    case URKEL_TYPE_COLLISION: {
      if (len < URKEL_KEY_SIZE + URKEL_HASH_SIZE)
        return 0;

      memcpy(proof->key, data, URKEL_KEY_SIZE);
      data += URKEL_KEY_SIZE;

      memcpy(proof->hash, data, URKEL_HASH_SIZE);
      data += URKEL_HASH_SIZE;

      break;
    }

    case URKEL_TYPE_EXISTS: {
      if (len < 2)
        return 0;

      size = urkel_read16(data);
      data += 2;

      if (len < size)
        return 0;

      if (size > 0)
        memcpy(proof->value, data, size);

      proof->size = size;

      break;
    }

    default: {
      return 0;
    }
  }

  return 1;
}

static int
urkel_proof_is_sane(const urkel_proof_t *proof) {
  size_t i;

  if (proof->depth > URKEL_KEY_BITS)
    return 0;

  if (proof->nodes_len > URKEL_KEY_BITS)
    return 0;

  for (i = 0; i < proof->nodes_len; i++) {
    const urkel_proof_node_t *node = proof->nodes[i];

    if (node->prefix.size > URKEL_KEY_BITS)
      return 0;
  }

  switch (proof->type) {
    case URKEL_TYPE_DEADEND: {
      if (proof->prefix.size > 0)
        return 0;

      if (proof->size > 0)
        return 0;

      break;
    }

    case URKEL_TYPE_SHORT: {
      if (proof->prefix.size === 0)
        return 0;

      if (proof->prefix.size > bits)
        return 0;

      if (proof->size > 0)
        return 0;

      break;
    }

    case URKEL_TYPE_COLLISION: {
      if (proof->prefix.size > 0)
        return 0;

      if (proof->size > 0)
        return 0;

      break;
    }

    case URKEL_TYPE_EXISTS: {
      if (proof->prefix.size > 0)
        return 0;

      if (proof->size > 0xffff)
        return 0;

      break;
    }

    default: {
      return 0;
    }
  }

  return 1;
}

int
urkel_proof_verify(const urkel_proof_t *proof,
                   const unsigned char *root,
                   const unsigned char *key) {
  unsigned char next[URKEL_HASH_SIZE];
  unsigned int depth = proof->depth;
  size_t i = proof->nodes_len;

  if (!urkel_proof_is_sane(proof))
    return URKEL_PROOF_UNKNOWN_ERROR;

  /* Re-create the leaf. */
  switch (proof->type) {
    case URKEL_TYPE_DEADEND: {
      memset(next, 0, URKEL_HASH_SIZE);
      break;
    }

    case URKEL_TYPE_SHORT: {
      if (urkel_bits_has(&proof->prefix, key, proof->depth))
        return URKEL_PROOF_SAME_PATH;

      urkel_hash_internal(next, &proof->prefix, proof->left, proof->right);

      break;
    }

    case URKEL_TYPE_COLLISION: {
      if (memcmp(proof->key, key, URKEL_KEY_SIZE) == 0)
        return URKEL_PROOF_SAME_KEY;

      urkel_hash_leaf(next, proof->key, proof->hash);

      break;
    }

    case URKEL_TYPE_EXISTS: {
      urkel_hash_value(next, key, proof->value);
      break;
    }

    default: {
      return URKEL_PROOF_UNKNOWN_ERROR;
    }
  }

  /* Traverse bits right to left. */
  while (i--) {
    const urkel_proof_node_t *node = proof->nodes[i];

    if (depth < node->prefix.size + 1)
      return URKEL_PROOF_NEG_DEPTH;

    depth -= 1;

    if (urkel_get_bit(key, depth))
      urkel_hash_internal(next, &node->prefix, node->hash, next);
    else
      urkel_hash_internal(next, &node->prefix, next, node->hash);

    depth -= node->prefix.size;

    if (!urkel_bits_has(&node->prefix, key, depth))
      return URKEL_PROOF_PATH_MISMATCH;
  }

  if (depth != 0)
    return URKEL_PROOF_TOO_DEEP;

  if (memcmp(next, root, URKEL_HASH_SIZE) != 0)
    return URKEL_PROOF_HASH_MISMATCH;

  return URKEL_PROOF_OK;
}
