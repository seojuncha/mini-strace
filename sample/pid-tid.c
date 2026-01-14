#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

static pid_t gettid_linux(void) {
  return (pid_t)syscall(SYS_gettid);
}

void* worker_thread(void* arg) {
  long idx = (long)arg;

  pid_t pid = getpid();        // TGID
  pid_t tid = gettid_linux();  // TID

  printf("[worker %ld] pid=%d tid=%d\n", idx, pid, tid);

  for (int i = 0; i < 3; i++) {
      write(1, ".", 1);
      usleep(100 * 1000); // 100ms
  }
  write(1, "\n", 1);

  return NULL;
}

int main(void) {
  pid_t pid = getpid();
  pid_t tid = gettid_linux();

  printf("[main] pid=%d tid=%d\n", pid, tid);

  const int NUM_THREADS = 3;
  pthread_t threads[NUM_THREADS];

  for (long i = 0; i < NUM_THREADS; i++) {
      pthread_create(&threads[i], NULL, worker_thread, (void*)i);
  }

  for (int i = 0; i < NUM_THREADS; i++) {
      pthread_join(threads[i], NULL);
  }

  printf("[main] done\n");
  return 0;
}
