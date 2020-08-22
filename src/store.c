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
#define MAX_WRITE (1024 + 0xffff + 1024 + META_SIZE)
#define META_MAGIC 0x6d726b6c
#define WRITE_BUFFER (64 << 20)
#define READ_BUFFER (1 << 20)
#define SLAB_SIZE (READ_BUFFER - (READ_BUFFER % META_SIZE))
#define KEY_SIZE 32
#define WRITE_FLAGS (URKEL_O_RDWR | URKEL_O_CREAT | URKEL_O_APPEND)
#define READ_FLAGS URKEL_O_RDONLY
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
  uint64_t offset; /* Start position in file. */
  uint32_t index; /* Current file index. */
  size_t start; /* Where the current file starts in memory. */
  size_t written; /* Current buffer position. */
  unsigned char *data;
  size_t size;
  urkel_iovec_t *chunks;
  size_t chunks_size;
  size_t chunks_len;
} urkel_slab_t;

typedef struct urkel_file_s {
  int fd;
  uint32_t index;
  uint64_t size;
} urkel_file_t;

typedef struct urkel_filemap_s {
  urkel_file_t **items;
  size_t size;
  size_t len;
} urkel_filemap_t;

KHASH_INIT(nodes, const unsigned char *,
           urkel_node_t *, 1, CACHE_HASH, CHACHE_EQUAL)

typedef struct urkel_cache_s {
  khash_t(nodes) *map;
} urkel_cache_t;

typedef struct urkel_store_s {
  char prefix[URKEL_PATH_SIZE];
  size_t prefix_len;
  unsigned char key[KEY_SIZE];
  urkel_slab_t slab;
  urkel_filemap_t files;
  urkel_cache_t cache;
  urkel_meta_t state;
  urkel_meta_t last_meta;
  int lock_fd;
  uint32_t index;
  urkel_file_t *current;
} data_store_t;

static urkel_file_t urkel_null_file = {-1, 0, 0};

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
urkel_slab_uninit(urkel_slab_t *slab) {
  if (slab->data)
    free(slab->data);

  if (slab->chunks)
    free(slab->chunks);

  urkel_slab_init(slab);
}

static void
urkel_slab_reset(urkel_slab_t *slab) {
  slab->offset = 0;
  slab->index = 0;
  slab->start = 0;
  slab->written = 0;
  slab->chunks_len = 0;
}

static uint64_t
urkel_slab_position(const urkel_slab_t *slab, size_t written) {
  return slab->offset + (written - slab->start);
}

static uint64_t
urkel_slab_pos(const urkel_slab_t *slab) {
  return urkel_slab_position(slab, slab->written);
}

static void
urkel_slab_render(const urkel_slab_t *slab, urkel_iovec_t *out) {
  out->iov_base = &slab->data[slab->start];
  out->iov_len = slab->written - slab->start;
}

static void
urkel_slab_expand(urkel_slab_t *slab, size_t size) {
  if (slab->size == 0) {
    slab->size = 8192;
    slab->data = checked_malloc(slab->size);
  }

  if (slab->chunks_size == 0) {
    slab->chunks_size = 1;
    slab->chunks = checked_malloc(sizeof(urkel_iovec_t));
  }

  if ((uint64_t)slab->written + size > slab->size) {
    slab->size = (slab->size * 3) / 2;
    slab->data = checked_realloc(slab->data, slab->size);
  }

  if (urkel_slab_pos(slab) + size > MAX_FILE_SIZE) {
    if (slab->chunks_len == slab->chunks_size - 1) {
      size_t new_size = (slab->chunks_size + 1) * sizeof(urkel_iovec_t);

      slab->chunks = checked_realloc(slab->chunks, new_size);
      slab->chunks_size += 1;
    }

    urkel_slab_render(slab, &slab->chunks[slab->chunks_len++]);

    slab->start = slab->written;
    slab->offset = 0;
    slab->index += 1;
  }
}

static uint64_t
urkel_slab_write(urkel_slab_t *slab, const unsigned char *data, size_t len) {
  size_t written = slab->written;

  if (len > 0) {
    urkel_slab_expand(slab, len);

    memcpy(slab->data + slab->written, data, len);

    slab->written += len;
  }

  return urkel_slab_position(slab, written);
}

static void
urkel_slab_pad(urkel_slab_t *slab, size_t size) {
  memset(slab->data + slab->written, 0, size);
  slab->written += size;
}

static void
urkel_slab_flush(urkel_slab_t *slab, urkel_iovec_t **chunks, size_t *count) {
  if (slab->written > slab->start)
    urkel_slab_render(slab, &slab->chunks[slab->chunks_len++]);

  *chunks = slab->chunks;
  *count = slab->chunks_len;

  urkel_slab_reset(slab);
}

/*
 * File Map
 */

static void
urkel_filemap_init(urkel_filemap_t *fm) {
  memset(fm, 0, sizeof(*fm));
}

static void
urkel_filemap_uninit(urkel_filemap_t *fm) {
  if (fm->items) {
    size_t i;

    for (i = 0; i < fm->len; i++) {
      urkel_file_t *file = fm->items[i];

      if (file) {
        urkel_fs_close(file->fd);
        free(file);
      }
    }

    free(fm->items);
  }

  urkel_filemap_init(fm);
}

static urkel_file_t *
urkel_filemap_lookup(urkel_filemap_t *fm, size_t index) {
  if (index >= fm->len)
    return NULL;

  return fm->items[index];
}

static void
urkel_filemap_insert(urkel_filemap_t *fm, urkel_file_t *file) {
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
}

static urkel_file_t *
urkel_filemap_remove(urkel_filemap_t *fm, size_t index) {
  urkel_file_t *file;

  if (index >= fm->len)
    return NULL;

  file = fm->items[index];

  if (file) {
    fm->items[index] = NULL;
    fm->size -= 1;
  }

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
urkel_cache_uninit(urkel_cache_t *cache) {
  khiter_t iter = kh_begin(cache->map);
  urkel_node_t *node;

  for (; iter != kh_end(cache->map); iter++) {
    if (kh_exist(cache->map, iter)) {
      node = kh_value(cache->map, iter);

      if (node)
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

  if (!node)
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
  size_t i, tries;

  CHECK(store->files.size > 1);

  tries = (size_t)rand() % (store->files.size - 1);

  for (i = 0; i < store->files.len; i++) {
    if (store->files.items[i] == NULL)
      continue;

    if (i == store->index)
      continue;

    if (tries == 0) {
      urkel_store_close_file(store, i);
      return;
    }

    tries -= 1;
  }

  urkel_abort();
}

static urkel_file_t *
urkel_store_open_file(data_store_t *store, uint32_t index, int flags) {
  char path[URKEL_PATH_SIZE];
  urkel_file_t *file;
  urkel_stat_t st;
  int fd;

  if (index == 0 || index > store->index + 1)
    return NULL;

  file = urkel_filemap_lookup(&store->files, index);

  if (file)
    return file;

  urkel_store_path_index(store, path, index);

  fd = urkel_fs_open(path, flags, 0640);

  if (fd == -1)
    return NULL;

  if (!urkel_fs_fstat(fd, &st)) {
    urkel_fs_close(fd);
    return NULL;
  }

  file = checked_malloc(sizeof(urkel_file_t));
  file->fd = fd;
  file->index = index;
  file->size = st.st_size;

  if (store->files.size >= MAX_OPEN_FILES)
    urkel_store_evict(store);

  urkel_filemap_insert(&store->files, file);

  return file;
}

static void
urkel_store_close_file(data_store_t *store, uint32_t index) {
  urkel_file_t *file = urkel_filemap_remove(&store->files, index);

  if (file) {
    if (file == store->current) {
      store->current = &urkel_null_file;
      store->index = 0;
    }

    urkel_fs_close(file->fd);

    free(file);
  }
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

  fd = urkel_fs_open(path, URKEL_O_RDONLY, 0);

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
  char path[URKEL_PATH_SIZE];
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
urkel_store_start(data_store_t *store) {
  CHECK(store->slab.written == 0);
  CHECK(store->slab.start == 0);

  store->slab.offset = store->current->size;
  store->slab.index = store->current->index;
}

static int
urkel_store_read(data_store_t *store,
                 unsigned char *out,
                 size_t size,
                 uint32_t index,
                 uint64_t pos) {
  urkel_file_t *file = urkel_store_open_file(store, index, READ_FLAGS);

  if (!file)
    return 0;

  return urkel_fs_pread(file->fd, out, size, pos);
}

static int
urkel_store_write(data_store_t *store,
                  const unsigned char *data,
                  size_t size) {
  urkel_file_t *file;

  if ((uint64_t)store->current->size + size > MAX_FILE_SIZE) {
    file = urkel_store_open_file(store, store->index + 1, WRITE_FLAGS);

    if (!file)
      return 0;

    if (!urkel_fs_fdatasync(store->current->fd))
      return 0;

    urkel_store_close_file(store, store->index);

    store->current = file;
    store->index = file->index;
  }

  if (!urkel_fs_write(store->current->fd, data, size))
    return 0;

  store->current->size += size;

  return 1;
}

static int
urkel_store_sync(data_store_t *store) {
  return urkel_fs_fdatasync(store->current->fd);
}

static int
urkel_store_read_node(data_store_t *store,
                      urkel_node_t *out,
                      const urkel_pointer_t *ptr) {
  unsigned char data[URKEL_MAX_NODE_SIZE];

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
  urkel_node_uninit(&node);

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
  CHECK(ptr->size <= URKEL_VALUE_SIZE);

  if (!urkel_store_read(store, out, ptr->size, ptr->index, ptr->pos))
    return 0;

  *size = ptr->size;

  return 1;
}

urkel_node_t *
urkel_store_resolve(data_store_t *store, urkel_node_t *node) {
  urkel_node_t *out;

  if (node->type != URKEL_NODE_HASH)
    return node;

  out = checked_malloc(sizeof(urkel_node_t));

  if (!urkel_store_read_node(store, out, &node->ptr)) {
    free(out);
    return NULL;
  }

  urkel_node_hashed(out, node->hash);

  return out;
}

uint64_t
urkel_store_write_node(data_store_t *store, urkel_node_t *node) {
  size_t size = urkel_node_size(node);
  size_t written = store->slab.written;
  uint32_t index;
  uint64_t pos;

  CHECK(node->type == URKEL_NODE_INTERNAL
     || node->type == URKEL_NODE_LEAF);

  CHECK(!(node->flags & URKEL_FLAG_WRITTEN));

  urkel_slab_expand(&store->slab, size);
  urkel_node_write(node, store->slab.data + store->slab.written);
  store->slab.written += size;

  index = store->slab.index;
  pos = urkel_slab_position(&store->slab, written);

  urkel_node_mark(node, index, pos, size);

  return pos;
}

uint64_t
urkel_store_write_value(data_store_t *store, urkel_node_t *node) {
  urkel_leaf_t *leaf = &node->u.leaf;
  uint32_t index;
  uint64_t pos;
  size_t size;

  CHECK(node->type == URKEL_NODE_LEAF);
  CHECK(!(node->flags & URKEL_FLAG_SAVED));
  CHECK(node->flags & URKEL_FLAG_VALUE);

  size = leaf->size;
  pos = urkel_slab_write(&store->slab, leaf->value, leaf->size);
  index = store->slab.index;

  urkel_node_save(node, index, pos, size);

  return pos;
}

int
urkel_store_needs_flush(const data_store_t *store) {
  return store->slab.written >= WRITE_BUFFER - MAX_WRITE;
}

int
urkel_store_flush(data_store_t *store) {
  urkel_iovec_t *chunks;
  size_t i, count;

  urkel_slab_flush(&store->slab, &chunks, &count);

  for (i = 0; i < count; i++) {
    if (!urkel_store_write(store, chunks[i].iov_base, chunks[i].iov_len))
      return 0;
  }

  urkel_store_start(store);

  return 1;
}

static void
urkel_store_write_meta(data_store_t *store,
                       urkel_meta_t *state,
                       urkel_node_t *root) {
  size_t padding;

  CHECK(root->flags & URKEL_FLAG_WRITTEN);

  *state = store->state;
  state->root_ptr = root->ptr;
  urkel_node_to_hash(root, &state->root_node);

  padding = META_SIZE - (urkel_slab_pos(&store->slab) % META_SIZE);

  urkel_slab_expand(&store->slab, padding + META_SIZE);
  urkel_slab_pad(&store->slab, padding);

  urkel_meta_write(state, store->slab.data + store->slab.written, store->key);
  store->slab.written += META_SIZE;

  state->meta_ptr.index = store->slab.index;
  state->meta_ptr.pos = urkel_slab_pos(&store->slab) - META_SIZE;
}

int
urkel_store_commit(data_store_t *store, urkel_node_t *root) {
  urkel_meta_t state;

  urkel_store_write_meta(store, &state, root);

  if (!urkel_store_flush(store))
    return 0;

  if (!urkel_store_sync(store))
    return 0;

  store->state = state;

  if (state.root_node.type != URKEL_NODE_NULL)
    urkel_cache_insert(&store->cache, &state.root_node);

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

  if (memcmp(root_hash, zero_hash, URKEL_HASH_SIZE) == 0) {
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

  urkel_node_uninit(&root);

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

static int
urkel_store_init(data_store_t *store, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  char path[URKEL_PATH_SIZE];
  urkel_dirent_t **list;
  uint32_t index = 0;
  size_t i, count;
  int failed = 0;
  int fd;

  while (prefix_len > 1 && URKEL_IS_SEP(prefix[prefix_len - 1]))
    prefix_len -= 1;

  if (prefix_len == 0 || prefix_len > URKEL_PATH_LEN - 11)
    return 0;

  memcpy(store->prefix, prefix, prefix_len);

  store->prefix[prefix_len] = '\0';
  store->prefix_len = prefix_len;

  if (!urkel_fs_exists(store->prefix)) {
    if (!urkel_fs_mkdir(store->prefix, 0750))
      return 0;
  }

  urkel_store_path(store, path, "meta");

  if (urkel_fs_exists(path)) {
    if (!urkel_fs_read_file(path, store->key, KEY_SIZE))
      return 0;
  } else {
    urkel_random_bytes(store->key, KEY_SIZE);

    if (!urkel_fs_write_file(path, 0640, store->key, KEY_SIZE))
      return 0;
  }

  if (!urkel_fs_scandir(store->prefix, &list, &count))
    return 0;

  for (i = 0; i < count; i++) {
    uint32_t num;

    if (urkel_parse_u32(&num, list[i]->d_name)) {
      if (num > 0 && num != index + 1)
        failed = 1;

      index = num;
    }

    free(list[i]);
  }

  free(list);

  if (failed)
    return 0;

  urkel_store_path(store, path, "lock");

  fd = urkel_fs_open_lock(path, 0640);

  if (fd == -1)
    return 0;

  if (!urkel_store_recover_state(store,
                                 &store->state,
                                 &store->last_meta,
                                 &index)) {
    urkel_fs_close_lock(fd);
    return 0;
  }

  urkel_slab_init(&store->slab);
  urkel_filemap_init(&store->files);
  urkel_cache_init(&store->cache);

  store->lock_fd = fd;
  store->index = index;
  store->current = urkel_store_open_file(store, index, WRITE_FLAGS);

  if (!store->current) {
    urkel_fs_close_lock(fd);
    return 0;
  }

  urkel_store_start(store);

  if (!urkel_store_read_root(store, &store->state.root_node,
                                    &store->state.root_ptr)) {
    urkel_store_close(store);
    return 0;
  }

  return 1;
}

static void
urkel_store_uninit(data_store_t *store) {
  urkel_slab_uninit(&store->slab);
  urkel_filemap_uninit(&store->files);
  urkel_cache_uninit(&store->cache);
  urkel_fs_close_lock(store->lock_fd);

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
  urkel_store_uninit(store);
  free(store);
}

int
urkel_store_destroy(const char *prefix) {
  size_t prefix_len = strlen(prefix);
  char path[URKEL_PATH_SIZE];
  urkel_dirent_t **list;
  size_t i, count;

  if (prefix_len > URKEL_PATH_LEN - 11)
    return 0;

  if (!urkel_fs_scandir(prefix, &list, &count))
    return 0;

  memcpy(path, prefix, prefix_len);

  for (i = 0; i < count; i++) {
    const char *name = list[i]->d_name;

    int match = urkel_parse_u32(NULL, name)
             || strcmp(name, "meta") == 0
             || strcmp(name, "lock") == 0;

    if (match) {
      size_t len = strlen(name);
      size_t off = prefix_len;

      path[off++] = URKEL_PATH_SEP;

      memcpy(path + off, name, len);

      off += len;

      path[off++] = '\0';

      urkel_fs_unlink(path);
    }

    free(list[i]);
  }

  free(list);

  return urkel_fs_rmdir(prefix);
}
