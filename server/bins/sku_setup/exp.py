from pwn import *

p = remote('172.18.176.1', 20000)

p.recvuntil('./kctf-pow solve ')

pow = p.recvline().strip()
result = check_output(['./kctf-pow', 'solve', pow])

p.recvuntil

