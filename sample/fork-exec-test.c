#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  pid_t parent, child;

  child = fork();
  if (child == 0) {
    if (argc < 2) {
      fprintf(stderr, "not enougth arguments\n");
      return 2;
    }
    execve(argv[1], &argv[1], NULL);
    perror("execv");
    return 1;
  } else {
    waitpid(child, NULL, 0);
    printf("child done\n");
  }
  return 0;
}