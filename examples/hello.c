#include <unistd.h>

int main(void) {
  write(1, "hello\n", 5);
  return 0;
}