CC = gcc
CFLAGS = -Wall -g

mini-strace: mini-strace.o
	$(CC) $(CFLAGS) -o mini-strace mini-strace.o

mini-strace.o : mini-strace.c
	$(CC) $(CFLAGS) -c mini-strace.c

.PHONY: clean

clean:
	rm -rf *.o mini-strace

run:
	./mini-strace ./examples/hello