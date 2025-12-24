#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
 
#include <stdio.h>
#include <string.h>  /* strstr() */
#include <stdlib.h>  /* malloc() */
 
struct stack_area {
  char *top;   /* end of stack buffer */
  char *base;  /* start of stack buffer */
  size_t size;
};
 
static int show_maps(pid_t pid, const char *find) {
  FILE *f;
  char fmt[] = "/proc/%ld/maps";
  char path[64];
  char buf[256];
 
  sprintf(path, fmt, pid);
  printf("maps path: %s\n", path);
 
  f = fopen(path, "r");
  if (!f) {
    perror("fopen");
    return -1;
  }
 
  while (fgets(buf, sizeof(buf), f)) {
    if (!strcmp(find, "all")) {
      fputs(buf, stdout);
    } else {
      if (strstr(buf, find) != NULL) {
        printf("%s\n", buf);
        break;
      }
    }
  }
  return 0;
}
 
static int child_func(void *arg) {
  char *str = arg;
  pid_t pid = getpid();
  int i = 19;
 
  sleep(3);
 
  printf("[pid:%d] print in child: %s\n", pid, str);
  printf("[pid:%d] str pointer: %p\n", pid, str);
  printf("[pid:%d] i pointer: %p\n", pid, &i);
 
  return 0;
}
 
static int alloc_stack(struct stack_area *stack, size_t size) {
  char *buf = malloc(size);
  if (!buf) {
    perror("malloc");
    return -1;
  }
 
  stack->base = buf;
  stack->top = buf + size;
  stack->size = size;
 
  printf("<< allocated stack >>\n");
  printf("  base: %p\n", stack->base);
  printf("  top: %p\n\n", stack->top);
 
  return 0;
}
 
#define STACK_SIZE (1024*1024)
 
int main(void) {
  pid_t child;
  struct stack_area child_stack;
 
  if (alloc_stack(&child_stack, STACK_SIZE)) {
    fprintf(stderr, "alloc stack fail\n");
    return 1;
  }
 
  /* SIGCHLD is necessary to use waitpid() in calling process */
  child = clone(child_func, child_stack.top, SIGCHLD, (void *)"hello");
 
  /*
  printf("<< child maps >>\n");
  if (show_maps(child, "all") == -1) {
    fprintf(stderr, "cannot find [stack] maps\n");
  }
 
  printf("<< parent maps >>\n");
  if (show_maps(getpid(), "all") == -1) {
    fprintf(stderr, "cannot find [heap] maps\n");
  }
  */
 
  if (waitpid(child, NULL, 0) == -1) {
    perror("waitpid");
    return 1;
  }
  printf("child has terminated\n");
 
  return 0;
}