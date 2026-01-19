#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

void* worker_thread(void* arg) {
  long idx = (long)arg;

  for (int i = 0; i < idx; i++) {
      write(1, ".", 1);
  }
  write(1, "\n", 1);

  return NULL;
}

int main(void) {
  const int NUM_THREADS = 5;
  pthread_t threads[NUM_THREADS];

  for (long i = 0; i < NUM_THREADS; i++) {
      pthread_create(&threads[i], NULL, worker_thread, (void*)i);
  }

  for (int i = 0; i < NUM_THREADS; i++) {
      pthread_join(threads[i], NULL);
  }
}