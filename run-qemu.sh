#!/bin/bash

qemu_cpu=cortex-a7
qemu_memory=256M
qemu_append_options="console=ttyAMA0 rdinit=/init"

busybox_dir=$HOME/9/busybox-1.36.1/_install
kernel_dir=$HOME/9/linux/arch/arm/boot

zimage_path=$kernel_dir/zImage
initramfs_path=$busybox_dir/../initramfs.cpio

# Compile process
echo "Compile"
arm-linux-gnueabihf-gcc -static -o mini-strace mini-strace.c || exit

if [ ! -d $buxybox_dir ]; then
  echo "Directory not found: $busybox_dir"
  exit
fi

cp mini-strace $busybox_dir/bin

echo "Entering busybox directory: $busybox_dir"
cd $busybox_dir

echo "Creating initramfs.cpio.."
find . | cpio -o --format=newc > $initramfs_path
if [ ! -f $initramfs_path ]; then
  echo "Fail: [$initramfs_path]"
fi

qemu-system-arm -M virt \
  -m $qemu_memory \
  -cpu $qemu_cpu \
  -kernel $zimage_path \
  -initrd $initramfs_path \
  -append "$qemu_append_options" \
  -nographic
