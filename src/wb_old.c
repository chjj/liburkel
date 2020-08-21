
typedef struct urkel_wb_s {
  int64_t offset; /* Start position in file. */
  uint32_t index; /* Current file index. */
  size_t start; /* Where the current file starts in memory. */
  size_t written; /* Current buffer position. */
  unsigned char *data;
  size_t data_len;
  urkel_iovec_t *chunks;
  size_t chunks_size;
  size_t chunks_len;
} urkel_wb_t;

static void
urkel_wb_init(urkel_wb_t *wb) {
  memset(wb, 0, sizeof(*wb));
}

static int64_t
urkel_wb_position(const urkel_wb_t *wb, size_t written) {
  return wb->offset + (written - wb->start);
}

static int64_t
urkel_wb_pos(const urkel_wb_t *wb) {
  return urkel_wb_position(wb, wb->written);
}

static void
urkel_wb_render(const urkel_wb_t *wb, urkel_iovec_t *out) {
  out->iov_base = &wb->data[wb->start];
  out->iov_len = wb->written - wb->start;
}

static void
urkel_wb_expand(urkel_wb_t *wb, size_t size) {
  if (wb->data_len == 0) {
    wb->data_len = 8192;
    wb->data = malloc(wb->data_len);

    CHECK(wb->data != NULL);
  }

  if (wb->written + size > wb->data_len) {
    wb->data_len = (wb->data_len * 3) / 2;
    wb->data = realloc(wb->data, wb->data_len);

    CHECK(wb->data != NULL);
  }

  if (urkel_wb_pos(wb) + size > MAX_FILE_SIZE) {
    urkel_iovec_t *chunk;

    if (wb->chunks_len == wb->chunks_size) {
      wb->chunks_size += 1;
      wb->chunks = realloc(wb->chunks, wb->chunks_size * sizeof(urkel_iovec_t));

      CHECK(wb->chunks != NULL);
    }

    chunk = &wb->chunks[wb->chunks_len++];
    chunk->iov_base = &wb->data[wb->start];
    chunk->iov_len = wb->written - wb->start;

    wb->start = wb->written;
    wb->offset = 0;
    wb->index += 1;
  }
}

static int64_t
urkel_wb_write(urkel_wb_t *wb, const unsigned char *data, size_t len) {
  size_t written;

  if (len == 0)
    return;

  urkel_wb_expand(wb, len);

  written = wb->written;

  memcpy(wb->data + wb->written, data, len);

  wb->written += len;

  return urkel_wb_position(written);
}

static void
urkel_wb_pad(urkel_wb_t *wb, size_t size) {
  memset(wb->data + wb->written, 0, size);
  wb->written += size;
}
