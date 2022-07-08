#!/usr/bin/env python3
from pwn import *

conn = remote('140.113.207.240',8831)
conn.recvline()
#0xDEADBEAF = -559038801
conn.sendline('-559038801')
conn.recvline()
conn.sendline('YOUSHALLNOTPASS')
conn.recvline()
print (conn.recv())
conn.close()