# mini-strace

## Goal

## Setup 

Host OS: Debian Linux 11

Configure Host OS
```shell
# Download and install ARM toolchain
$ arm-none-linux-gnueabihf-gcc --version
$ sudo apt install bc
```

QEMU 
```shell
$ sudo apt install qemu-system-arm
$ qemu-system-arm --version
QEMU emulator version 9.2.2 (v9.2.2)
Copyright (c) 2003-2024 Fabrice Bellard and the QEMU Project developers
```

Choose a model
```shell
# List of supported boards
$ qemu-system-arm -machine help
```
I'll choose a `virt` with `cortex-a7` CPU

```shell
$ qemu-system-arm -M virt -cpu cortex-a7 ...
```

Build a Linux Kernel
```shell
# Requirement
$ sudo apt install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev bc
# Download linux kernel
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
# Move downloaded directory
$ cd linux
# Configure
$ make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- vexpress_defconfig
# Build 
$ make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- -j$(nproc)
# Output directory
$ ls arch/arm/boot
# Check zImage
$ file arch/arm/boot/zImage
```

BusyBox
```shell
# Downlaod busybox 1.36.1
$ wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
# Decompress
$ tar xvjf busybox-1.36.1.tar.bz2
# Move
$ cd busybox-1.36.1
# configure
$ make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- defconfig
# make
$ make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- -j$(nproc)
# make install
$ make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- install
```

> NOTE: busybox-1.37.0 has an error

`_install` directory includes output files.


Then, create the `init` file
```bash
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
exec /bin/sh
```

```shell
$ chmod +x init
$ find . | cpio -o --format=newc > ../initramfs.cpio
$ ls ../ | grep initramfs
initramfs.cpio
```

```shell
$ file initramfs.cpio
initramfs.cpio: ASCII cpio archive (SVR4 with no CRC)
```

Run QEMU
```shell
$ qemu-system-arm -M virt -m 256M -cpu cortex-a7 -kernel zImage -initrd initramfs.cpio -append "console=ttyAMA0 rdinit=/init" -nographic
```

Test program: Simple hello world.
```c
#include <stdio.h>
int main(void) { 
  printf("hello world\n");
}
```
```shell
$ arm-none-linux-gnueabihf-gcc -static -o main main.c
$ cp main busy-box/_install/bin
```
Then, create `initramfs.cpio` again.

Run QEMU with new rootfs.



## System Calls Manual
```shell
# introduction to system calls
$ man 2 intro
# 
$ man 2 syscalls
```

## `ptrace` system call


## Technical Notes
### What is `zImage`?
### Relation `busybox` with `rootfs`
### What is `syscall`?
### About `ptrace`