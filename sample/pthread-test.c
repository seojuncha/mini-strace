#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

static void* worker(void* arg) {
    write(1, "thread alive\n", 13);
    sleep(1);
    write(1, "thread exit\n", 12);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    write(1, "main alive\n", 11);
    pthread_join(t, NULL);
    write(1, "main exit\n", 10);
    return 0;
}
