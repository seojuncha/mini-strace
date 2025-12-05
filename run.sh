#!/bin/bash
gcc -Wall -Werror -std=c90 src/syscalls_x64.c src/tracer.c src/main.c && ./a.out /usr/bin/echo "a"
