#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urkel.h>

int
main(void) {
  char cwd[1024];
  char path[1024];
  char *ret;
  urkel_t *db;

  ret = getcwd(cwd, sizeof(path));
  assert(ret != NULL);

  cwd[sizeof(cwd) - 1] = '\0';

  assert(strlen(cwd) <= 1000);

  sprintf(path, "%s/urkel_test_db", cwd);

  db = urkel_open(path);

  assert(db != NULL);

  urkel_close(db);

  return 0;
}
