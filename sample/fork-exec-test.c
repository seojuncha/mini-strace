#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  pid_t parent, child;

  child = fork();
  if (child == 0) {
    char *argv[] = {"/usr/bin/echo", "hello-from-exec", NULL};
    execv(argv[0], argv);
    perror("execv");
    return 1;
  } else {
    waitpid(child, NULL, 0);
    printf("child done\n");
  }
  return 0;
}