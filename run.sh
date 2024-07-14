#!/bin/sh -e

if [ ! -f /flag ]; then
  echo "pbctf{fake_flag}" > /flag
fi
chown 0:1000 /flag
chmod 440 /flag
unshare -pfm bash -c "mount -t proc none /proc; mount -o ro disk.img disk; containerd/containerd disk/"
