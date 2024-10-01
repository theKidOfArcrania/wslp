#!/bin/bash -e

echo "$1" > /flag
chown 0:1000 /flag
chmod 440 /flag

while true; do
  read IP PORT
  exec 5<> "/dev/tcp/$IP/$PORT"
  unshare -muipCf --kill-child bash -c "exec 2>&5 >&5 <&5 5>&-; timeout 300; mount -t proc none /proc; mount -o ro disk.img disk; containerd/containerd disk/" &
  disown
  exec 5>&-
done
