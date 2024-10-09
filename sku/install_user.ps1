icacls C:\OEM\flag2.2.txt /setowner SYSTEM
icacls C:\OEM\flag2.2.txt /inheritance:r
wsl --install Debian -n
debian install --root
debian run /mnt/c/OEM/install.sh
debian config --default-user ctf
