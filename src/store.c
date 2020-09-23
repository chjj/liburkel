/*!
 * store.c - data store for liburkel
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bits.h"
#include "internal.h"
#include "khash.h"
#include "io.h"
#include "nodes.h"
#include "store.h"
#include "util.h"

/*
 * Defines
 */

/* Max read size on linux, and lower than off_t max. */
#define MAX_FILE_SIZE 0x7ffff000 /* File max = 2 GB */
#define MAX_FILES 0x7fff /* DB max = 64 TB. */
#define MAX_OPEN_FILES 32
#define META_SIZE (4 + (URKEL_PTR_SIZE * 2) + 20)
#define META_MAGIC 0x6d726b6c
#define WRITE_BUFFER (64 << 20)
#define READ_BUFFER (1 << 20)
#define SLAB_SIZE (READ_BUFFER - (READ_BUFFER % META_SIZE))
#define WRITE_FLAGS (URKEL_O_RDWR | URKEL_O_CREAT | URKEL_O_APPEND \
                   | URKEL_O_RANDOM | URKEL_O_MMAP)
#define READ_FLAGS (URKEL_O_RDONLY | URKEL_O_RANDOM | URKEL_O_MMAP)
#define CACHE_HASH(k) urkel_murmur3(k, URKEL_HASH_SIZE, 0)
#define CHACHE_EQUAL(a, b) (memcmp(a, b, URKEL_HASH_SIZE) == 0)

/*
 * Structs
 */

typedef struct urkel_meta_s {
  urkel_pointer_t meta_ptr;
  urkel_pointer_t root_ptr;
  urkel_node_t root_node;
} urkel_meta_t;

typedef struct urkel_slab_s {
  unsigned char *data; /* Preallocated slab. */
  size_t data_size; /* Total bytes allocated. */
  size_t data_len; /* Total bytes written. */
  size_t data_off; /* Bytes written since last file rollover. */
  size_t *offsets; /* Past offsets (one for each rollover). */
  size_t offsets_len; /* Allocated length of offsets array. */
  size_t steps; /* Number of elements in `offsets`. */
  size_t start; /* Index at which urkel_store_flush left off. */
  uint64_t file_pos; /* Current file position. */
  uint32_t file_index; /* Current file index. */
} urkel_slab_t;

typedef struct urkel_filemap_s {
  urkel_file_t **items;
  size_t size;
  size_t len;
  urkel_rwlock_t *lock;
} urkel_filemap_t;

KHASH_INIT(nodes, const unsigned char *,
           urkel_node_t *, 1, CACHE_HASH, CHACHE_EQUAL)

typedef struct urkel_cache_s {
  khash_t(nodes) *map;
} urkel_cache_t;

typedef struct urkel_rng_s {
  uint32_t state[(URKEL_HASH_SIZE + 3) / 4];
  size_t pos;
} urkel_rng_t;

typedef struct urkel_store_s {
  char prefix[URKEL_PATH_MAX + 1];
  size_t prefix_len;
  unsigned char key[URKEL_HASH_SIZE];
  urkel_slab_t slab;
  urkel_filemap_t files;
  urkel_cache_t cache;
  urkel_rng_t rng;
  urkel_meta_t state;
  urkel_meta_t last_meta;
  int lock_fd;
  uint32_t index;
  urkel_file_t *current;
} data_store_t;

/*
 * Constants
 */

static urkel_file_t urkel_null_file = {-1, 0, 0, NULL, 0, {0}};

/*
 * Meta Root
 */

static void
urkel_meta_init(urkel_meta_t *meta) {
  urkel_pointer_init(&meta->meta_ptr);
  urkel_pointer_init(&meta->root_ptr);
  urkel_node_init(&meta->root_node, URKEL_NODE_NULL);
}

static unsigned char *
urkel_meta_write(const urkel_meta_t *meta,
                 unsigned char *data,
                 const unsigned char *key) {
  unsigned char *start = data;

  data = urkel_write32(data, META_MAGIC);
  data = urkel_pointer_write(&meta->meta_ptr, data);
  data = urkel_pointer_write(&meta->root_ptr, data);
  data = urkel_checksum(data, start, data - start, key);

  return data;
}

static int
urkel_meta_read(urkel_meta_t *meta,
                const unsigned char *data,
                const unsigned char *key) {
  const unsigned char *start = data;
  uint32_t magic = urkel_read32(data);
  unsigned char expect[20];

  data += 4;

  if (magic != META_MAGIC)
    return 0;

  urkel_pointer_read(&meta->meta_ptr, data);
  data += URKEL_PTR_SIZE;

  urkel_pointer_read(&meta->root_ptr, data);
  data += URKEL_PTR_SIZE;

  urkel_checksum(expect, start, data - start, key);

  return memcmp(data, expect, 20) == 0;
}

/*
 * Write Buffer
 */

static void
urkel_slab_init(urkel_slab_t *slab) {
  memset(slab, 0, sizeof(*slab));
}

static void
urkel_slab_clear(urkel_slab_t *slab) {
  if (slab->data != NULL)
    free(slab->data);

  if (slab->offsets != NULL)
    free(slab->offsets);

  urkel_slab_init(slab);
}

static void
urkel_slab_write(urkel_slab_t *slab, const unsigned char *data, size_t len) {
  size_t needs = slab->data_len + len;

  CHECK(len <= MAX_FILE_SIZE);

  if (slab->offsets_len == 0) {
    slab->offsets = checked_malloc(2 * sizeof(size_t));
    slab->offsets_len = 1;
  }

  if (slab->file_pos + len > MAX_FILE_SIZE) {
    if (slab->steps == slab->offsets_len) {
      size_t new_size = (slab->offsets_len + 2) * sizeof(size_t);

      slab->offsets = checked_realloc(slab->offsets, new_size);
      slab->offsets_len += 1;
    }

    slab->offsets[slab->steps++] = slab->data_off;

    slab->data_off = 0;
    slab->file_pos = 0;
    slab->file_index += 1;
  }

  if (slab->data_size < needs) {
    slab->data_size = (slab->data_size * 3) / 2;

    if (slab->data_size < needs)
      slab->data_size = (needs * 3) / 2;

    slab->data = checked_realloc(slab->data, slab->data_size);
  }

  if (len > 0)
    memcpy(slab->data + slab->data_len, data, len);

  slab->data_len += len;
  slab->data_off += len;
  slab->file_pos += len;
}

/*
 * File Map
 */

static void
urkel_filemap_init(urkel_filemap_t *fm) {
  fm->items = NULL;
  fm->size = 0;
  fm->len = 0;
  fm->lock = urkel_rwlock_create();
}

static void
urkel_filemap_clear(urkel_filemap_t *fm) {
  urkel_rwlock_wrlock(fm->lock);

  if (fm->items != NULL) {
    size_t i;

    for (i = 0; i < fm->len; i++) {
      urkel_file_t *file = fm->items[i];

      if (file != NULL)
        urkel_file_close(file);
    }

    free(fm->items);
  }

  urkel_rwlock_wrunlock(fm->lock);
  urkel_rwlock_destroy(fm->lock);
}

static urkel_file_t *
urkel_filemap_lookup(urkel_filemap_t *fm, size_t index) {
  urkel_file_t *file = NULL;

  urkel_rwlock_rdlock(fm->lock);

  if (index >= fm->len)
    goto fail;

  file = fm->items[index];

fail:
  urkel_rwlock_rdunlock(fm->lock);
  return file;
}

static void
urkel_filemap_insert(urkel_filemap_t *fm, urkel_file_t *file) {
  urkel_rwlock_wrlock(fm->lock);

  if (file->index >= fm->len) {
    size_t new_size = (file->index + 1) * sizeof(urkel_file_t *);

    CHECK(file->index < MAX_FILES);

    fm->items = checked_realloc(fm->items, new_size);

    while (fm->len < file->index + 1)
      fm->items[fm->len++] = NULL;
  }

  CHECK(!fm->items[file->index]);

  fm->items[file->index] = file;
  fm->size += 1;

  urkel_rwlock_wrunlock(fm->lock);
}

static urkel_file_t *
urkel_filemap_remove(urkel_filemap_t *fm, size_t index) {
  urkel_file_t *file = NULL;

  urkel_rwlock_wrlock(fm->lock);

  if (index >= fm->len)
    goto fail;

  file = fm->items[index];

  if (file != NULL) {
    fm->items[index] = NULL;
    fm->size -= 1;
  }

fail:
  urkel_rwlock_wrunlock(fm->lock);
  return file;
}

/*
 * Node Cache
 */

static void
urkel_cache_init(urkel_cache_t *cache) {
  cache->map = kh_init(nodes);

  CHECK(cache->map != NULL);
}

static void
urkel_cache_clear(urkel_cache_t *cache) {
  khiter_t iter = kh_begin(cache->map);
  urkel_node_t *node;

  for (; iter != kh_end(cache->map); iter++) {
    if (kh_exist(cache->map, iter)) {
      node = kh_value(cache->map, iter);

      if (node != NULL)
        free(node);

      kh_value(cache->map, iter) = NULL;
    }
  }

  kh_destroy(nodes, cache->map);
}

static int
urkel_cache_lookup(urkel_cache_t *cache,
                   urkel_node_t *out,
                   const unsigned char *hash) {
  khiter_t iter = kh_get(nodes, cache->map, hash);
  urkel_node_t *node;

  if (iter == kh_end(cache->map))
    return 0;

  node = kh_value(cache->map, iter);

  if (node == NULL)
    return 0;

  *out = *node;

  return 1;
}

static int
urkel_cache_insert(urkel_cache_t *cache, const urkel_node_t *node) {
  urkel_node_t *val = checked_malloc(sizeof(urkel_node_t));
  khiter_t iter;
  int ret = -1;

  *val = *node;
  iter = kh_put(nodes, cache->map, val->hash, &ret);

  if (ret == -1) {
    urkel_abort();
    return 0;
  }

  if (ret) {
    kh_value(cache->map, iter) = val;
    return 1;
  }

  free(val);

  return 0;
}

/*
 * RNG
 */

static void
urkel_rng_init(urkel_rng_t *rng) {
  urkel_random_bytes(rng->state, URKEL_HASH_SIZE);
  rng->pos = 0;
}

static void
urkel_rng_clear(urkel_rng_t *rng) {
  (void)rng;
}

static uint32_t
urkel_rng_rand(urkel_rng_t *rng) {
  if ((rng->pos % (URKEL_HASH_SIZE / 4)) == 0) {
    urkel_hash_raw((unsigned char *)rng->state,
                   rng->state, URKEL_HASH_SIZE);
    rng->pos = 0;
  }

  return rng->state[rng->pos++];
}

/*
 * Data Store
 */

static void
urkel_store_path(const data_store_t *store, char *path, const char *name) {
  memcpy(path, store->prefix, store->prefix_len);

  path += store->prefix_len;

  *path++ = URKEL_PATH_SEP;

  while (*name)
    *path++ = *name++;

  *path++ = '\0';
}

static void
urkel_store_path_index(const data_store_t *store, char *path, uint32_t index) {
  char name[11];

  urkel_serialize_u32(name, index);
  urkel_store_path(store, path, name);
}

static void
urkel_store_close_file(data_store_t *, uint32_t);

static void
urkel_store_evict(data_store_t *store) {
  /* Write lock is held. */
  while (store->files.size > MAX_OPEN_FILES) {
    size_t num = urkel_rng_rand(&store->rng);
    size_t tries = num % (store->files.size - 1);
    size_t i;

    for (i = 1; i < store->files.len; i++) {
      if (store->files.items[i] == NULL)
        continue;

      if (i == store->index)
        continue;

      if (tries == 0) {
        urkel_store_close_file(store, i);
        break;
      }

      tries -= 1;
    }
  }
}

static urkel_file_t *
urkel_store_open_file(data_store_t *store, uint32_t index, int flags) {
  char path[URKEL_PATH_MAX + 1];
  urkel_file_t *file;

  if (index == 0 || index > store->index + 1)
    return NULL;

  file = urkel_filemap_lookup(&store->files, index);

  if (file != NULL)
    return file;

  urkel_store_path_index(store, path, index);

  file = urkel_file_open(path, flags, 0640);

  if (file == NULL)
    return NULL;

  file->index = index;

  if (flags == WRITE_FLAGS) {
    /* Only evict if the write lock is held. */
    urkel_store_evict(store);
  }

  urkel_filemap_insert(&store->files, file);

  return file;
}

static void
urkel_store_close_file(data_store_t *store, uint32_t index) {
  /* Write lock is held. */
  urkel_file_t *file = urkel_filemap_remove(&store->files, index);

  if (file != NULL) {
    if (file == store->current) {
      store->current = &urkel_null_file;
      store->index = 0;
    }

    urkel_file_close(file);
  }
}

static int
urkel_store_read(data_store_t *store,
                 unsigned char *out,
                 size_t size,
                 uint32_t index,
                 uint64_t pos) {
  urkel_file_t *file = urkel_store_open_file(store, index, READ_FLAGS);

  if (file == NULL)
    return 0;

  return urkel_file_pread(file, out, size, pos);
}

static int
urkel_store_sync(data_store_t *store) {
  /* Write lock is held. */
  return urkel_file_datasync(store->current);
}

static int
urkel_store_write(data_store_t *store,
                  const unsigned char *data,
                  size_t size) {
  /* Write lock is held. */
  urkel_file_t *file;

  if (store->current->size + size > MAX_FILE_SIZE) {
    file = urkel_store_open_file(store, store->index + 1, WRITE_FLAGS);

    if (file == NULL)
      return 0;

    if (!urkel_store_sync(store))
      return 0;

    urkel_store_close_file(store, store->index);

    store->current = file;
    store->index = file->index;
  }

  return urkel_file_write(store->current, data, size);
}

static int
urkel_store_read_node(data_store_t *store,
                      urkel_node_t *out,
                      const urkel_pointer_t *ptr) {
  unsigned char data[URKEL_NODE_SIZE];

  if (ptr->size == 0 || ptr->size > URKEL_NODE_SIZE)
    return 0;

  if (!urkel_store_read(store, data, ptr->size, ptr->index, ptr->pos))
    return 0;

  if (!urkel_node_read(out, data, ptr->size))
    return 0;

  out->ptr = *ptr;
  out->flags |= URKEL_FLAG_WRITTEN;

  return 1;
}

static int
urkel_store_read_root(data_store_t *store,
                      urkel_node_t *out,
                      const urkel_pointer_t *ptr) {
  urkel_node_t node;

  if (ptr->index == 0) {
    urkel_node_init(out, URKEL_NODE_NULL);
    return 1;
  }

  if (!urkel_store_read_node(store, &node, ptr))
    return 0;

  /* Edge case when our root is a leaf. */
  /* We need to recalculate the hash. */
  if (node.type == URKEL_NODE_LEAF) {
    unsigned char value[URKEL_VALUE_SIZE];
    size_t size;

    if (!urkel_store_retrieve(store, &node, value, &size))
      return 0;

    urkel_node_store(&node, value, size);
  }

  urkel_node_hash(&node);
  urkel_node_to_hash(&node, out);
  urkel_node_clear(&node);

  urkel_cache_insert(&store->cache, out);

  return 1;
}

urkel_node_t *
urkel_store_get_root(data_store_t *store) {
  urkel_node_t *node = checked_malloc(sizeof(urkel_node_t));

  *node = store->state.root_node;

  return node;
}

const unsigned char *
urkel_store_root_hash(data_store_t *store) {
  return store->state.root_node.hash;
}

int
urkel_store_retrieve(data_store_t *store,
                     const urkel_node_t *node,
                     unsigned char *out,
                     size_t *size) {
  const urkel_leaf_t *leaf = &node->u.leaf;
  const urkel_pointer_t *ptr = &leaf->vptr;

  CHECK(node->type == URKEL_NODE_LEAF);

  if (node->flags & URKEL_FLAG_VALUE) {
    CHECK(leaf->size <= URKEL_VALUE_SIZE);

    if (leaf->size > 0)
      memcpy(out, leaf->value, leaf->size);

    *size = leaf->size;

    return 1;
  }

  CHECK(node->flags & URKEL_FLAG_SAVED);

  if (ptr->size > URKEL_VALUE_SIZE)
    return 0;

  if (!urkel_store_read(store, out, ptr->size, ptr->index, ptr->pos))
    return 0;

  *size = ptr->size;

  return 1;
}

urkel_node_t *
urkel_store_resolve(data_store_t *store, const urkel_node_t *node) {
  urkel_node_t *out = checked_malloc(sizeof(urkel_node_t));

  CHECK(node->type == URKEL_NODE_HASH);

  if (!urkel_store_read_node(store, out, &node->ptr)) {
    free(out);
    return NULL;
  }

  urkel_node_hashed(out, node->hash);

  return out;
}

void
urkel_store_write_node(data_store_t *store, urkel_node_t *node) {
  /* Write lock is held. */
  urkel_slab_t *slab = &store->slab;
  unsigned char raw[URKEL_NODE_SIZE];
  size_t size = urkel_node_write(node, raw) - raw;

  CHECK(node->type == URKEL_NODE_INTERNAL
     || node->type == URKEL_NODE_LEAF);

  CHECK(!(node->flags & URKEL_FLAG_WRITTEN));

  urkel_slab_write(slab, raw, size);

  urkel_node_mark(node, slab->file_index,
                  slab->file_pos - size,
                  size);
}

void
urkel_store_write_value(data_store_t *store, urkel_node_t *node) {
  /* Write lock is held. */
  urkel_slab_t *slab = &store->slab;
  urkel_leaf_t *leaf = &node->u.leaf;

  CHECK(node->type == URKEL_NODE_LEAF);
  CHECK(!(node->flags & URKEL_FLAG_SAVED));
  CHECK(node->flags & URKEL_FLAG_VALUE);

  urkel_slab_write(slab, leaf->value, leaf->size);

  urkel_node_save(node, slab->file_index,
                  slab->file_pos - leaf->size,
                  leaf->size);
}

int
urkel_store_needs_flush(const data_store_t *store) {
  /* Write lock is held. */
  return store->slab.data_len >= WRITE_BUFFER;
}

int
urkel_store_flush(data_store_t *store) {
  /* Write lock is held. */
  urkel_slab_t *slab = &store->slab;
  unsigned char *data = slab->data;
  size_t i = 0;

  slab->offsets[slab->steps++] = slab->data_off;

  for (; i < slab->start; i++)
    data += slab->offsets[i];

  for (; i < slab->steps; i++) {
    size_t len = slab->offsets[i];

    if (!urkel_store_write(store, data, len)) {
      slab->steps -= 1;
      slab->start = i;
      return 0;
    }

    data += len;
  }

  slab->data_len = 0;
  slab->data_off = 0;
  slab->steps = 0;
  slab->start = 0;

  return 1;
}

static void
urkel_store_write_meta(data_store_t *store,
                       urkel_meta_t *state,
                       urkel_node_t *root) {
  /* Write lock is held. */
  static const unsigned char padding[META_SIZE] = {0};
  urkel_slab_t *slab = &store->slab;
  unsigned char raw[META_SIZE];

  CHECK(root->flags & URKEL_FLAG_WRITTEN);

  *state = store->state;

  state->root_ptr = root->ptr;

  urkel_node_to_hash(root, &state->root_node);

  if (slab->file_pos % META_SIZE) {
    size_t size = META_SIZE - (slab->file_pos % META_SIZE);

    urkel_slab_write(slab, padding, size);
  }

  urkel_meta_write(state, raw, store->key);
  urkel_slab_write(slab, raw, META_SIZE);

  state->meta_ptr.index = slab->file_index;
  state->meta_ptr.pos = slab->file_pos - META_SIZE;
}

int
urkel_store_commit(data_store_t *store, urkel_node_t *root) {
  /* Write lock is held. */
  urkel_meta_t state;

  urkel_store_write_meta(store, &state, root);

  if (!urkel_store_flush(store))
    return 0;

#ifdef URKEL_FSYNC
  if (!urkel_store_sync(store))
    return 0;
#endif

  store->state = state;

  if (state.root_node.type != URKEL_NODE_NULL)
    urkel_cache_insert(&store->cache, &state.root_node);

  urkel_store_evict(store);

  return 1;
}

static int
urkel_store_read_meta(data_store_t *store,
                      urkel_meta_t *meta,
                      const urkel_pointer_t *ptr) {
  unsigned char data[META_SIZE];

  if (!urkel_store_read(store, data, META_SIZE, ptr->index, ptr->pos))
    return 0;

  return urkel_meta_read(meta, data, store->key);
}

int
urkel_store_read_history(data_store_t *store,
                         urkel_node_t *root,
                         const unsigned char *root_hash) {
  static const unsigned char zero_hash[URKEL_HASH_SIZE] = {0};
  urkel_node_t *root_node = &store->state.root_node;
  urkel_pointer_t *meta_ptr;
  urkel_pointer_t *root_ptr;
  urkel_meta_t meta;
  urkel_node_t node;

  /* Use custom memcmp to avoid a GCC bug. */
  if (urkel_memcmp(root_hash, zero_hash, URKEL_HASH_SIZE) == 0) {
    urkel_node_init(root, URKEL_NODE_NULL);
    return 1;
  }

  if (memcmp(root_hash, root_node->hash, URKEL_HASH_SIZE) == 0) {
    *root = *root_node;
    return 1;
  }

  if (urkel_cache_lookup(&store->cache, root, root_hash))
    return 1;

  for (;;) {
    meta_ptr = &store->last_meta.meta_ptr;

    if (meta_ptr->index == 0)
      return 0;

    if (!urkel_store_read_meta(store, &meta, meta_ptr))
      return 0;

    root_ptr = &meta.root_ptr;

    if (!urkel_store_read_root(store, &node, root_ptr))
      return 0;

    store->last_meta = meta;

    if (memcmp(node.hash, root_hash, URKEL_HASH_SIZE) == 0) {
      *root = node;
      break;
    }
  }

  return 1;
}

int
urkel_store_has_history(data_store_t *store, const unsigned char *root_hash) {
  urkel_node_t root;
  int ret;

  ret = urkel_store_read_history(store, &root, root_hash);

  urkel_node_clear(&root);

  return ret;
}

urkel_node_t *
urkel_store_get_history(data_store_t *store, const unsigned char *root_hash) {
  urkel_node_t *root = checked_malloc(sizeof(urkel_node_t));

  if (!urkel_store_read_history(store, root, root_hash)) {
    free(root);
    return NULL;
  }

  return root;
}

/*
 * Initialization
 */

static int
urkel_store_init_prefix(data_store_t *store, const char *prefix) {
  char *path = urkel_path_resolve(prefix);
  size_t len;

  if (path == NULL)
    return 0;

  len = strlen(path);

  if (len + 10 > URKEL_PATH_MAX) {
    free(path);
    return 0;
  }

  memcpy(store->prefix, path, len + 1);

  store->prefix_len = len;

  free(path);

  if (urkel_fs_exists(store->prefix))
    return 1;

  return urkel_fs_mkdir(store->prefix, 0750);
}

static int
urkel_store_init_meta(data_store_t *store) {
  char path[URKEL_PATH_MAX + 1];

  urkel_store_path(store, path, "meta");

  if (urkel_fs_exists(path))
    return urkel_fs_read_file(path, store->key, URKEL_HASH_SIZE);

  urkel_random_bytes(store->key, URKEL_HASH_SIZE);

  return urkel_fs_write_file(path, 0640, store->key, URKEL_HASH_SIZE);
}

static int
urkel_store_find_index(data_store_t *store, uint32_t *index) {
  urkel_dirent_t **list;
  size_t i, count;
  int ret = 1;

  *index = 0;

  if (!urkel_fs_scandir(store->prefix, &list, &count))
    return 0;

  for (i = 0; i < count; i++) {
    uint32_t num;

    if (urkel_parse_u32(&num, list[i]->d_name)) {
      if (num != *index + 1)
        ret = 0;

      *index = num;
    }

    free(list[i]);
  }

  free(list);

  return ret;
}

static int
urkel_store_init_lock(data_store_t *store) {
  char path[URKEL_PATH_MAX + 1];
  int fd;

  urkel_store_path(store, path, "lock");

  fd = urkel_fs_open_lock(path, 0640);

  if (fd == -1)
    return 0;

  store->lock_fd = fd;

  return 1;
}

static int
urkel_store_find_meta(const data_store_t *store,
                      urkel_meta_t *meta,
                      uint64_t *off,
                      const char *path,
                      unsigned char *slab) {
  urkel_stat_t st;
  int ret = 0;
  int fd;

  fd = urkel_fs_open(path, URKEL_O_RDWR | URKEL_O_RANDOM, 0);

  if (fd == -1)
    return 0;

  if (!urkel_fs_fstat(fd, &st))
    goto done;

  *off = st.st_size - (st.st_size % META_SIZE);

  while (*off >= META_SIZE) {
    uint64_t pos = 0;
    uint64_t size = *off;

    if (*off >= SLAB_SIZE) {
      pos = *off - SLAB_SIZE;
      size = SLAB_SIZE;
    }

    if (!urkel_fs_pread(fd, slab, size, pos))
      goto done;

    while (size >= META_SIZE) {
      size -= META_SIZE;
      *off -= META_SIZE;

      if (urkel_meta_read(meta, slab + size, store->key)) {
        urkel_fs_ftruncate(fd, *off + META_SIZE);
        ret = 1;
        goto done;
      }
    }
  }

done:
  urkel_fs_close(fd);
  return ret;
}

static int
urkel_store_recover_state(const data_store_t *store,
                          urkel_meta_t *state,
                          urkel_meta_t *meta,
                          uint32_t *index) {
  unsigned char *slab = checked_malloc(SLAB_SIZE);
  char path[URKEL_PATH_MAX + 1];
  uint64_t off;
  int ret = 0;

  urkel_meta_init(state);
  urkel_meta_init(meta);

  while (*index >= 1) {
    urkel_store_path_index(store, path, *index);

    if (urkel_store_find_meta(store, meta, &off, path, slab)) {
      *state = *meta;
      state->meta_ptr.index = *index;
      state->meta_ptr.pos = off;
      goto succeed;
    }

    if (!urkel_fs_unlink(path))
      goto fail;

    *index -= 1;
  }

  *index = 1;

succeed:
  ret = 1;
fail:
  free(slab);
  return ret;
}

static void
urkel_store_clear(data_store_t *store);

static int
urkel_store_init(data_store_t *store, const char *prefix) {
  uint32_t index;

  if (!urkel_store_init_prefix(store, prefix))
    return 0;

  if (!urkel_store_init_meta(store))
    return 0;

  if (!urkel_store_find_index(store, &index))
    return 0;

  if (!urkel_store_init_lock(store))
    return 0;

  if (!urkel_store_recover_state(store,
                                 &store->state,
                                 &store->last_meta,
                                 &index)) {
    urkel_fs_close_lock(store->lock_fd);
    return 0;
  }

  urkel_slab_init(&store->slab);
  urkel_filemap_init(&store->files);
  urkel_cache_init(&store->cache);
  urkel_rng_init(&store->rng);

  store->index = index;
  store->current = urkel_store_open_file(store, index, WRITE_FLAGS);

  if (store->current == NULL) {
    urkel_store_clear(store);
    return 0;
  }

  store->slab.file_pos = store->current->size;
  store->slab.file_index = store->current->index;

  if (!urkel_store_read_root(store, &store->state.root_node,
                                    &store->state.root_ptr)) {
    urkel_store_clear(store);
    return 0;
  }

  return 1;
}

static void
urkel_store_clear(data_store_t *store) {
  char path[URKEL_PATH_MAX + 1];

  urkel_store_path(store, path, "lock");

  urkel_slab_clear(&store->slab);
  urkel_filemap_clear(&store->files);
  urkel_cache_clear(&store->cache);
  urkel_rng_clear(&store->rng);
  urkel_fs_close_lock(store->lock_fd);
  urkel_fs_unlink(path);

  memset(store, 0, sizeof(*store));
}

data_store_t *
urkel_store_open(const char *prefix) {
  data_store_t *store = checked_malloc(sizeof(data_store_t));

  if (!urkel_store_init(store, prefix)) {
    free(store);
    return NULL;
  }

  return store;
}

void
urkel_store_close(data_store_t *store) {
  urkel_store_clear(store);
  free(store);
}

int
urkel_store_destroy(const char *prefix) {
  char *prefix_ = urkel_path_resolve(prefix);
  char path[URKEL_PATH_MAX + 1];
  size_t path_len;
  urkel_dirent_t **list;
  size_t i, count;
  int ret = 0;
  int fd = -1;

  if (prefix_ == NULL)
    return 0;

  path_len = strlen(prefix_);

  if (path_len + 10 > URKEL_PATH_MAX)
    goto fail;

  memcpy(path, prefix_, path_len + 1);

  path[path_len++] = URKEL_PATH_SEP;

  memcpy(path + path_len, "lock", 5);

  fd = urkel_fs_open_lock(path, 0640);

  if (fd == -1)
    goto fail;

  if (!urkel_fs_scandir(prefix_, &list, &count))
    goto fail;

  for (i = 0; i < count; i++) {
    const char *name = list[i]->d_name;

    if (urkel_parse_u32(NULL, name) || strcmp(name, "meta") == 0) {
      memcpy(path + path_len, name, strlen(name) + 1);
      urkel_fs_unlink(path);
    }

    free(list[i]);
  }

  free(list);

  ret = 1;
fail:
  if (fd != -1) {
    memcpy(path + path_len, "lock", 5);

    urkel_fs_close_lock(fd);
    urkel_fs_unlink(path);
  }

  if (ret)
    ret = urkel_fs_rmdir(prefix_);

  free(prefix_);

  return ret;
}

int
urkel_store__corrupt(const char *prefix) {
  char *prefix_ = urkel_path_resolve(prefix);
  char path[URKEL_PATH_MAX + 1];
  size_t path_len;
  urkel_dirent_t **list;
  urkel_stat_t st;
  size_t i, count;
  int found = 0;
  int ret = 0;

  if (prefix_ == NULL)
    return 0;

  path_len = strlen(prefix_);

  if (path_len + 10 > URKEL_PATH_MAX)
    goto fail;

  memcpy(path, prefix_, path_len + 1);

  path[path_len++] = URKEL_PATH_SEP;

  if (!urkel_fs_scandir(prefix_, &list, &count))
    goto fail;

  for (i = 0; i < count; i++) {
    const char *name = list[i]->d_name;

    if (urkel_parse_u32(NULL, name)) {
      memcpy(path + path_len, name, strlen(name) + 1);
      found = 1;
    }

    free(list[i]);
  }

  free(list);

  if (!found)
    goto fail;

  if (!urkel_fs_stat(path, &st))
    goto fail;

  if (st.st_size == 0)
    goto fail;

  if (!urkel_fs_truncate(path, st.st_size - 1))
    goto fail;

  ret = 1;
fail:
  free(prefix_);
  return ret;
}
