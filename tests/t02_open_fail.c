#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
  return openat(AT_FDCWD, "unknown", 0);
}