/*!
 * store.h - data store for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#ifndef _URKEL_STORE_H
#define _URKEL_STORE_H

#include <stddef.h>
#include "internal.h"

/*
 * Structs
 */

struct urkel_store_s;

typedef struct urkel_store_s urkel_store_t;

/*
 * Data Store
 */

urkel_store_t *
urkel_store_open(const char *prefix);

void
urkel_store_close(urkel_store_t *store);

urkel_node_t *
urkel_store_get_root(urkel_store_t *store);

const unsigned char *
urkel_store_root_hash(urkel_store_t *store);

int
urkel_store_retrieve(urkel_store_t *store,
                     const urkel_node_t *node,
                     unsigned char *out,
                     size_t *size);

urkel_node_t *
urkel_store_resolve(urkel_store_t *store, urkel_node_t *node);

uint64_t
urkel_store_write_node(urkel_store_t *store, urkel_node_t *node);

uint64_t
urkel_store_write_value(urkel_store_t *store, urkel_node_t *node);

int
urkel_store_needs_flush(const urkel_store_t *store);

int
urkel_store_flush(urkel_store_t *store);

int
urkel_store_commit(urkel_store_t *store, urkel_node_t *root);

int
urkel_store_has_history(urkel_store_t *store, const unsigned char *root_hash);

urkel_node_t *
urkel_store_get_history(urkel_store_t *store, const unsigned char *root_hash);

#endif /* _URKEL_STORE_H */
