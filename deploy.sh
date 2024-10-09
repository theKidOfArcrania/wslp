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
sku/setup.ps1
sku/unattend.xml
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
tar -acvf handout.tar.gz "$DEPLOY"
rm -rf "$DEPLOY"
