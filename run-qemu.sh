#!/bin/bash

qemu-system-arm -M virt -m 256M -cpu cortex-a7 -kernel zImage -initrd initramfs.cpio -append "console=ttyAMA0 rdinit=/init" -nographic
