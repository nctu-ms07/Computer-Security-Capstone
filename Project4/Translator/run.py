#!/usr/bin/env python3
from pwn import *

origin = 'A'.encode('ASCII')[0]

def translate(s : string):
  translation = bytearray(s, 'ASCII')
  for i in range(len(translation)):
    translation[i] = origin - (translation[i] - origin)
  return translation

conn = remote('140.113.207.240',8833)
conn.recvuntil('Give me some input: ')
conn.sendline(translate("flag"))
conn.recvuntil("Anything else to translate?(y/n)")
conn.sendline("n")
conn.recvuntil("Tell me what are you looking for in my language: ")
conn.sendline(translate("flag"))
print(conn.recv())
conn.close()