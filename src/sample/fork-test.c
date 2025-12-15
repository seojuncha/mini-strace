#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
 
int main(void) {
  pid_t parent, child;

  child = fork();

  if (child == -1) {
    perror("fork");
    return 1;
  }

  if (child == 0) {
    printf("[pid: %d], sleeping child...\n", getpid());
    sleep(3);
    return 1;
  } else {
    pid_t ret;
    int wstatus;

    parent = getpid();

    printf("[pid: %d], waiting child...\n", parent);
    ret = waitpid(child, &wstatus, 0);
    if (ret == -1) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(wstatus)) {
      printf("[pid: %d], child %d has terminated.\n", parent, ret);
    }
  }

  return 0;
}