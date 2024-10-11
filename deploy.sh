#!/bin/bash

FILES="""
wsl/containerd/Makefile
wsl/containerd/containerd
wsl/containerd/main.c
wsl/runner/Makefile
wsl/runner/runner
wsl/runner/runner.c
wsl/disk.img
wsl/README.md
sku/efi/README.txt
sku/efi/EFI/Boot/bootx64.efi
sku/efi/EFI/Rufus/ntfs_x64.efi
sku/install_user.ps1
sku/install_specialize.ps1
sku/install.sh
sku/setup.ps1
sku/unattend.xml
sku/README.md
serverlite/Cargo.lock
serverlite/Cargo.toml
serverlite/src/main.rs
serverlite/src/sess.rs
serverlite/src/utils.rs
serverlite/README.md
"""

DEPLOY=wslp
rm -rf "$DEPLOY"
for FILE in $FILES; do
  mkdir -p "$DEPLOY/$(dirname $FILE)"
  cp "$FILE" "$DEPLOY/$FILE"
done
echo "bwctf{flag1}" > "$DEPLOY/flag1.txt"
echo "bwctf{flag2_part1" > "$DEPLOY/flag2.1.txt"
echo "_part2}" > "$DEPLOY/flag2.2.txt"
tar -acvf handout.tar.gz "$DEPLOY"

cp flag1.txt flag2.1.txt flag2.2.txt "$DEPLOY/"
tar -acvf handout_prod.tar.gz "$DEPLOY"

rm -rf "$DEPLOY"
