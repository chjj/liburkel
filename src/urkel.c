/*!
 * urkel.c - urkel tree cli
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/liburkel
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urkel.h>

/*
 * Helpers
 */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Base16
 */

static const char *urkel_base16_charset = "0123456789abcdef";

static const int8_t urkel_base16_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static void
urkel_base16_encode(char *dst, const uint8_t *src, size_t srclen) {
  size_t i, j;

  for (i = 0, j = 0; i < srclen; i++) {
    dst[j++] = urkel_base16_charset[src[i] >> 4];
    dst[j++] = urkel_base16_charset[src[i] & 15];
  }

  dst[j] = '\0';
}

static int
urkel_base16_decode(uint8_t *dst, size_t *dstlen, const char *src) {
  size_t srclen = strlen(src);
  uint8_t z = 0;
  size_t i, j;

  if (srclen & 1)
    return 0;

  if (srclen / 2 > *dstlen)
    return 0;

  for (i = 0, j = 0; i < srclen / 2; i++) {
    uint8_t hi = urkel_base16_table[(uint8_t)src[j++]];
    uint8_t lo = urkel_base16_table[(uint8_t)src[j++]];

    z |= hi | lo;

    dst[i] = (hi << 4) | lo;
  }

  if (z & 0x80)
    return 0;

  *dstlen = i;

  return 1;
}

static int
urkel_base16_decode32(uint8_t *dst, const char *src) {
  size_t dstlen = 32;

  if (!urkel_base16_decode(dst, &dstlen, src))
    return 0;

  return dstlen == 32;
}

static void
urkel_base16_print(const uint8_t *src, size_t srclen) {
  char tmp[1024 + 1];
  char *dst = tmp;

  if (srclen > 512) {
    dst = malloc(srclen * 2 + 1);

    if (dst == NULL) {
      abort();
      return;
    }
  }

  urkel_base16_encode(dst, src, srclen);

  printf("%s\n", dst);

  if (dst != tmp)
    free(dst);
}

/*
 * Constants
 */

#define URKEL_KEY_RAW 0
#define URKEL_KEY_BLAKE2B 1

#define URKEL_ACTION_CREATE 0
#define URKEL_ACTION_DESTROY 1
#define URKEL_ACTION_INFO 2
#define URKEL_ACTION_ROOT 3
#define URKEL_ACTION_GET 4
#define URKEL_ACTION_INSERT 5
#define URKEL_ACTION_REMOVE 6
#define URKEL_ACTION_LIST 7
#define URKEL_ACTION_PROVE 8
#define URKEL_ACTION_VERIFY 9

static const struct {
  const char *name;
  int value;
} urkel_actions[] = {
  { "create", URKEL_ACTION_CREATE },
  { "destroy", URKEL_ACTION_DESTROY },
  { "info", URKEL_ACTION_INFO },
  { "root", URKEL_ACTION_ROOT },
  { "get", URKEL_ACTION_GET },
  { "insert", URKEL_ACTION_INSERT },
  { "remove", URKEL_ACTION_REMOVE },
  { "list", URKEL_ACTION_LIST },
  { "prove", URKEL_ACTION_PROVE },
  { "verify", URKEL_ACTION_VERIFY }
};

/*
 * Usage
 */

static void
urkel_usage(void) {
  printf("%s",
    "\n"
    "  Usage: urkel [options] [action] [args]\n"
    "\n"
    "  Actions:\n"
    "\n"
    "    create                create a new database\n"
    "    destroy               destroy database\n"
    "    info                  print database information\n"
    "    root                  print root hash\n"
    "    get <key>             retrieve value\n"
    "    insert <key> <value>  insert value\n"
    "    remove <key>          remove value\n"
    "    list                  list all keys\n"
    "    prove <key>           create proof\n"
    "    verify <key> <proof>  verify proof (requires --root)\n"
    "\n"
    "  Options:\n"
    "\n"
    "    -p, --path <path>     path to database (default: $URKEL_PATH)\n"
    "    -r, --root <hash>     root hash to use for snapshots\n"
    "    -H, --hash            hash key with BLAKE2b-256\n"
    "    -h, --help            output usage information\n"
    "\n"
    "  Environment Variables:\n"
    "\n"
    "    URKEL_PATH            path to database (default: ./)\n"
    "\n"
    "  Example:\n"
    "\n"
    "    $ urkel create -p db\n"
    "    $ cd db\n"
    "    $ urkel insert foo 'deadbeef' -H\n"
    "    $ urkel get foo -H\n"
    "    $ urkel prove foo -H\n"
    "    $ urkel verify foo $(urkel prove foo -H) -r $(urkel root) -H\n"
    "    $ urkel destroy\n"
    "\n"
  );
}

/*
 * Options
 */

typedef struct urkel_options_s {
  const char *path;
  unsigned char root_data[32];
  unsigned char *root;
  int key_type;
  int help;
  int action;
  unsigned char key[32];
  unsigned char value[1024];
  size_t value_len;
  unsigned char *proof;
  size_t proof_len;
} urkel_options_t;

static int
urkel_options_init(urkel_options_t *opt, char **argv, size_t argc) {
  const char *args[32];
  size_t args_len = 0;
  size_t i;

  opt->path = NULL;
  opt->root = NULL;
  opt->key_type = URKEL_KEY_RAW;
  opt->help = 0;
  opt->action = -1;
  opt->value_len = 0;
  opt->proof = NULL;
  opt->proof_len = 0;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--path") == 0 || strcmp(argv[i], "-p") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Invalid argument: %s\n", argv[i]);
        return 0;
      }

      opt->path = argv[++i];

      continue;
    }

    if (strcmp(argv[i], "--root") == 0 || strcmp(argv[i], "-r") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Invalid argument: %s\n", argv[i]);
        return 0;
      }

      opt->root = opt->root_data;

      if (!urkel_base16_decode32(opt->root, argv[++i])) {
        fprintf(stderr, "Invalid hex string for root.\n");
        return 0;
      }

      continue;
    }

    if (strcmp(argv[i], "--hash") == 0 || strcmp(argv[i], "-H") == 0) {
      opt->key_type = URKEL_KEY_BLAKE2B;
      continue;
    }

    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      opt->help = 1;
      return 1;
    }

    if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 0;
    }

    if (args_len == ARRAY_SIZE(args)) {
      fprintf(stderr, "Too many arguments.\n");
      return 0;
    }

    args[args_len++] = argv[i];
  }

  if (opt->path == NULL) {
    opt->path = getenv("URKEL_PATH");

    if (opt->path == NULL)
      opt->path = ".";
  }

  if (args_len < 1) {
    urkel_usage();
    return 0;
  }

  for (i = 0; i < ARRAY_SIZE(urkel_actions); i++) {
    if (strcmp(args[0], urkel_actions[i].name) == 0) {
      opt->action = urkel_actions[i].value;
      break;
    }
  }

  if (opt->action == -1) {
    fprintf(stderr, "Invalid action.\n");
    return 0;
  }

  switch (opt->action) {
    case URKEL_ACTION_GET:
    case URKEL_ACTION_INSERT:
    case URKEL_ACTION_REMOVE:
    case URKEL_ACTION_PROVE:
    case URKEL_ACTION_VERIFY: {
      if (args_len < 2) {
        fprintf(stderr, "Must provide a key.\n");
        return 0;
      }

      switch (opt->key_type) {
        case URKEL_KEY_RAW: {
          if (!urkel_base16_decode32(opt->key, args[1])) {
            fprintf(stderr, "Invalid hex string for key.\n");
            return 0;
          }

          break;
        }

        case URKEL_KEY_BLAKE2B: {
          urkel_hash(opt->key, args[1], strlen(args[1]));
          break;
        }

        default: {
          return 0;
        }
      }

      break;
    }
  }

  switch (opt->action) {
    case URKEL_ACTION_INSERT: {
      if (args_len < 3) {
        fprintf(stderr, "Must provide a value.\n");
        return 0;
      }

      opt->value_len = sizeof(opt->value);

      if (!urkel_base16_decode(opt->value, &opt->value_len, args[2])) {
        fprintf(stderr, "Invalid hex string for value.\n");
        return 0;
      }

      break;
    }

    case URKEL_ACTION_VERIFY: {
      if (args_len < 3) {
        fprintf(stderr, "Must provide proof data.\n");
        return 0;
      }

      opt->proof_len = strlen(args[2]) / 2;
      opt->proof = malloc(opt->proof_len + 1);

      if (opt->proof == NULL) {
        fprintf(stderr, "Allocation failed.\n");
        return 0;
      }

      if (!urkel_base16_decode(opt->proof, &opt->proof_len, args[2])) {
        fprintf(stderr, "Invalid hex string for proof data.\n");
        return 0;
      }

      break;
    }
  }

  return 1;
}

static void
urkel_options_clear(urkel_options_t *opt) {
  if (opt->proof != NULL) {
    free(opt->proof);
    opt->proof = NULL;
  }
}

/*
 * Main
 */

static int
urkel_main(const urkel_options_t *opt) {
  urkel_t *db = NULL;
  urkel_iter_t *iter = NULL;
  int ret = 0;

  switch (opt->action) {
    case URKEL_ACTION_INFO:
    case URKEL_ACTION_ROOT:
    case URKEL_ACTION_GET:
    case URKEL_ACTION_INSERT:
    case URKEL_ACTION_REMOVE:
    case URKEL_ACTION_LIST:
    case URKEL_ACTION_PROVE: {
      db = urkel_open(opt->path);

      if (db == NULL) {
        fprintf(stderr, "Could not open database.\n");
        goto fail;
      }

      break;
    }
  }

  switch (opt->action) {
    case URKEL_ACTION_CREATE: {
      db = urkel_open(opt->path);

      if (db == NULL) {
        fprintf(stderr, "Could not create database.\n");
        goto fail;
      }

      break;
    }

    case URKEL_ACTION_DESTROY: {
      if (!urkel_destroy(opt->path)) {
        fprintf(stderr, "Could not destroy database.\n");
        goto fail;
      }

      break;
    }

    case URKEL_ACTION_INFO: {
      unsigned char root[32];
      unsigned char key[32];
      unsigned char value[1024];
      size_t value_len;
      size_t items = 0;
      size_t size = 0;

      urkel_root(db, root);

      iter = urkel_iterate(db, opt->root);

      if (iter == NULL) {
        fprintf(stderr, "Could not create iterator.\n");
        goto fail;
      }

      while (urkel_iter_next(iter, key, value, &value_len)) {
        items += 1;
        size += 32;
        size += value_len;
      }

      if (urkel_errno != URKEL_EITEREND) {
        fprintf(stderr, "Iteration failed.\n");
        goto fail;
      }

      printf("Items: %lu\n", (unsigned long)items);
      printf("Size:  %lu\n", (unsigned long)size);
      printf("Root:  ");

      urkel_base16_print(root, 32);

      break;
    }

    case URKEL_ACTION_ROOT: {
      unsigned char root[32];

      urkel_root(db, root);
      urkel_base16_print(root, 32);

      break;
    }

    case URKEL_ACTION_GET: {
      unsigned char value[1024];
      size_t value_len;

      if (!urkel_get(db, value, &value_len, opt->key, opt->root)) {
        fprintf(stderr, "Value not found.\n");
        goto fail;
      }

      urkel_base16_print(value, value_len);

      break;
    }

    case URKEL_ACTION_INSERT: {
      if (!urkel_insert(db, opt->key, opt->value, opt->value_len)) {
        fprintf(stderr, "Could not write value.\n");
        goto fail;
      }

      break;
    }

    case URKEL_ACTION_REMOVE: {
      if (!urkel_remove(db, opt->key)) {
        fprintf(stderr, "Could not remove value.\n");
        goto fail;
      }

      break;
    }

    case URKEL_ACTION_LIST: {
      unsigned char key[32];

      iter = urkel_iterate(db, opt->root);

      if (iter == NULL) {
        fprintf(stderr, "Could not create iterator.\n");
        goto fail;
      }

      while (urkel_iter_next(iter, key, NULL, NULL))
        urkel_base16_print(key, 32);

      if (urkel_errno != URKEL_EITEREND) {
        fprintf(stderr, "Iteration failed.\n");
        goto fail;
      }

      break;
    }

    case URKEL_ACTION_PROVE: {
      unsigned char *proof;
      size_t proof_len;

      if (!urkel_prove(db, &proof, &proof_len, opt->key, opt->root)) {
        fprintf(stderr, "Could not write value.\n");
        goto fail;
      }

      urkel_base16_print(proof, proof_len);

      free(proof);

      break;
    }

    case URKEL_ACTION_VERIFY: {
      unsigned char value[1024];
      size_t value_len;
      int exists;

      if (opt->root == NULL) {
        fprintf(stderr, "Must provide a root.\n");
        goto fail;
      }

      if (!urkel_verify(&exists, value, &value_len,
                        opt->proof, opt->proof_len,
                        opt->key, opt->root)) {
        fprintf(stderr, "Invalid proof.\n");
        goto fail;
      }

      if (exists)
        urkel_base16_print(value, value_len);

      break;
    }
  }

  ret = 1;
fail:
  if (iter != NULL)
    urkel_iter_destroy(iter);

  if (db != NULL)
    urkel_close(db);

  return ret;
}

/*
 * Entry
 */

int
main(int argc, char **argv) {
  urkel_options_t opt;
  int ret = 1;

  if (!urkel_options_init(&opt, argv, argc))
    goto fail;

  if (opt.help) {
    urkel_usage();
    goto succeed;
  }

  if (!urkel_main(&opt))
    goto fail;

succeed:
  ret = 0;
fail:
  urkel_options_clear(&opt);
  return ret;
}
