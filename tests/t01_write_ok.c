#include <unistd.h>

int main(void) {
  return write(1, "hello\n", 6);
} 