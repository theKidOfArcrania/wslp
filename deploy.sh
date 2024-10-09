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
server/README.md
server/Cargo.toml
server/Cargo.lock
server/src/wmi_ext.rs
server/src/main.rs
server/src/instances.rs
server/src/sess.rs
server/src/vmm.rs
server/src/vmm_async.rs
server/src/utils.rs
server/crates/powershell-script/src/error.rs
server/crates/powershell-script/src/builder.rs
server/crates/powershell-script/src/target/unix.rs
server/crates/powershell-script/src/target/windows.rs
server/crates/powershell-script/src/output.rs
server/crates/powershell-script/src/target.rs
server/crates/powershell-script/src/psscript.rs
server/crates/powershell-script/src/lib.rs
"""

DEPLOY=wslp
rm -rf "$DEPLOY"
for FILE in $FILES; do
  mkdir -p "$DEPLOY/$(dirname $FILE)"
  cp "$FILE" "$DEPLOY/$FILE"
done
echo "pbctf{flag1}" > "$DEPLOY/flag1.txt"
echo "pbctf{flag2_part1" > "$DEPLOY/flag2.1.txt"
echo "_part2}" > "$DEPLOY/flag2.2.txt"
tar -acvf handout.tar.gz "$DEPLOY"
rm -rf "$DEPLOY"
