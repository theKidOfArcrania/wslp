from pwn import *

p = remote('172.18.176.1', 20000)

p.recvuntil(b'./kctf-pow solve ')

pow = str(p.recvline().strip(), 'utf8')
result = check_output(['./kctf-pow', 'solve', pow])
p.sendline(result)

p.recvuntil(b'Flag from part 1:')
p.sendline(open('flag1.txt', 'b').read())

p.intreactive()
