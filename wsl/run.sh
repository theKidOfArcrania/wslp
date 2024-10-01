#!/bin/sh -e

echo "pbctf{fake_flag}" > /flag
chown 0:1000 /flag
chmod 440 /flag
unshare -muipCf --kill-child bash -c "timeout 300; mount -t proc none /proc; mount -o ro disk.img disk; containerd/containerd disk/"
