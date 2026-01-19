#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    char *argv[] = { "/usr/bin/echo", "hello", NULL };
    execve(argv[0], &argv[0], NULL);
    perror("execve");
    return 0;
  }

  return 0;
}