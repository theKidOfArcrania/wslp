#!/bin/bash

useradd -M ctf
mkdir -p /home/ctf/disk

mv /mnt/c/OEM/flag1.txt /flag1.txt
chown 0:1000 /flag1.txt
chmod 440 /flag1.txt

mv /mnt/c/OEM/flag2.1.txt /flag2.1.txt
chown 0:0 /flag2.1.txt
chmod 400 /flag2.1.txt

cp -r /mnt/c/OEM/{containerd,disk.img,runner} /home/ctf

chmod a+x /home/ctf/runner
chmod u+s /home/ctf/runner
