#ifndef _URKEL_PROOF_H
#define _URKEL_PROOF_H

#include <stddef.h>
#include "bits.h"
#include "internal.h"

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
  unsigned char hash[URKEL_HASH_SIZE];
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
urkel_proof_init(urkel_proof_t *proof);

void
urkel_proof_uninit(urkel_proof_t *proof);

void
urkel_proof_push(urkel_proof_t *proof,
                 const urkel_bits_t *prefix,
                 const unsigned char *hash);

size_t
urkel_proof_size(const urkel_proof_t *proof);

unsigned char *
urkel_proof_write(const urkel_proof_t *proof, unsigned char *data);

int
urkel_proof_read(urkel_proof_t *proof, const unsigned char *data, size_t len);

int
urkel_proof_verify(const urkel_proof_t *proof,
                   const unsigned char *root,
                   const unsigned char *key);

#endif /* _URKEL_PROOF_H */
