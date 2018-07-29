#!/bin/python

from pwn import *


def main():
    key = "fl4g_i5_h3r3"
    key += chr(33)

    xor_bytes = [
        0x7D, 0x4D, 0x23, 0x44,
        0x36, 2, 0x76, 3,
        0x6F, 0x5B, 0x2F, 0x46,
        0x76, 0x18, 0x39
    ]

    for b in xor_bytes:
        key_byte = 0

        for c in key:
            key_byte ^= ord(c)

        key += chr(key_byte^b)

    p = process("./cool")
    p.recvuntil("Give me your key: ")
    p.sendline(key)
    data = p.recvrepeat(0.2)

    log.info("Key: {}".format(key))
    log.success(data)

if __name__ == "__main__":
    main()
