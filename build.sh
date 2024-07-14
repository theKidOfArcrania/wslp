#!/bin/bash

set -e

make -C busybox
make -j -C containerd

rm -rf disk.img disk
mkdir disk
dd if=/dev/zero of=disk.img bs=1M count=100
mkfs.ext4 disk.img

sudo mount disk.img disk/
trap "sudo umount disk" exit
sudo cp -a busybox/build/_install/* disk/
sudo mkdir disk/dev
sudo mkdir disk/proc
sudo mkdir disk/tmp
sudo chown -R root:root disk/*
