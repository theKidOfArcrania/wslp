#!/bin/bash -e
IP=10.69.0.1
PORT=31337

echo "$1" > /flag
chown 0:1000 /flag
chmod 440 /flag

exec 4<> "/dev/tcp/$IP/$PORT"
echo -e "$2" >&4

while true; do
  read INPUT <&4
  exec 5<> "/dev/tcp/$IP/$PORT"
  echo -e "$INPUT" >&5
  unshare -muipCf --kill-child bash -c "exec 2>&5 >&5 <&5 5>&- 4>&-; timeout 300; mount -t proc none /proc; mount -o ro disk.img disk; containerd/containerd disk/" &
  disown
  exec 5>&-
done
