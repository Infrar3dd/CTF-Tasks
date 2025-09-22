from pwn import *
import re

context.arch = 'i386'

HOST = "178.216.122.15"
PORT = 43464

elf = ELF('./func')
log.info(f"puts@got: {hex(elf.got['puts'])}")
log.info(f"give_flag: {hex(elf.symbols['give_flag'])}")