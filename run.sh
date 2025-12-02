#!/bin/bash
gcc -Wall -Werror -std=c90 syscalls_x64.c tracer.c main.c && ./a.out echo "a"
