# XOR

Category: `crypto`

File: [xor.py](files/xor.py)

Points: `100`

### What It Does

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flag import flag,key

assert len(key) == 10

if len(flag) % len(key) != 0:
    n = len(key) - len(flag) % len(key)
    for i in range(n):
        flag += " "
m = []
for a in range(len(key)):
    i = a
    for b in range(len(flag)/len(key)):
        if b % 2 != 0:
            m.append(ord(flag[i]) ^ ord(key[a]))
        else:
            m.append(ord(flag[i+len(key)-(a+1+a)])^ ord(key[a]))
        i += len(key)
enc_flag = ""
for j in range(len(m)):
    enc_flag += "%02x" % m[j]

print enc_flag

#enc_flag = 1d14273b1c27274b1f10273b05380c295f5f0b03015e301b1b5a293d063c62333e383a20213439162e0037243a72731c22311c2d261727172d5c050b131c433113706b6047556b6b6b6b5f72045c371727173c2b1602503c3c0d3702241f6a78247b253d7a393f143e3224321b1d14090c03185e437a7a607b52566c6c5b6c034047

```

`flag` is padded with a whitespace such that each character in `key` xor with some characters from `flag` to get a block of `enc_flag`.

### How to Solve

Reverse the source code to get a character of `flag` if the character of `key` is known and vice-versa. `flag` starts with `ISITDTU{` for this CTF. We can use it to get the `key` and `flag`.

Here is the [partial solution](files/xor_soln_partial.py):

```python
#!/bin/python

def main():
    flag_pre = "ISITDTU{"
    flag_padding = " "
    len_key = 10
    enc_flag = "1d14273b1c27274b1f10273b05380c295f5f0b03015e301b1b5a293d063c62333e383a20213439162e0037243a72731c22311c2d261727172d5c050b131c433113706b6047556b6b6b6b5f72045c371727173c2b1602503c3c0d3702241f6a78247b253d7a393f143e3224321b1d14090c03185e437a7a607b52566c6c5b6c034047"
    key = [None] * len_key
    m = []

    for i in xrange(0, len(enc_flag), 2):
        m.append(int(enc_flag[i:i+2], 16))

    flag = [None] * len(m)

    for idx, i in enumerate(flag_pre):
        flag[idx] = i

    updated = True

    while updated and None in flag:
        updated = False
        m_idx = 0

        for a in range(len_key):
            i = a

            for b in range(len(m)/len_key):
                if b % 2 != 0:
                    if not flag[i] and key[a]:
                        flag[i] = chr(m[m_idx] ^ ord(key[a]))
                        updated = True
                    elif not key[a] and flag[i]:
                        key[a] = chr(m[m_idx] ^ ord(flag[i]))
                        updated = True
                else:
                    flag_idx = i + len_key - (a+1+a)

                    if not key[a] and flag[flag_idx]:
                        key[a] = chr(m[m_idx] ^ ord(flag[flag_idx]))
                        updated = True
                    elif not flag[flag_idx] and key[a]:
                        flag[flag_idx] = chr(m[m_idx] ^ ord(key[a]))
                        updated = True

                i += len_key
                m_idx += 1

    print "flag: {}".format("".join(c if c else "?" for c in flag))
    print "key: {}".format("".join(c if c else "?" for c in key))


if __name__ == "__main__":
    main()

```

Here is the output:

```shellsession
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/crypto$ python xor_soln_partial.py
flag: ISITDTU{????ome_to_ISITDTUCT????ntest!_Hav3_a_g0????ay._Hope_y0u_w1l????j0y_and_hav3_a_h????rank_1n_0ur_F1rs????f_C0nt3st._Thank??
key: ??RCr4cKm3
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/crypto$ 
```

We need to guess some of the characters. The solution is updated to allow the user to guess some characters.

Here is part of the [solution](files/xor_soln.py):

```python
#!/bin/python

def user_guess(flag, key):
    choice = raw_input("Update flag or key? ").lower()

    if choice not in ["flag", "key"]:
        print "Error: Invalid choice"
        return False

    idx = int(raw_input("Update at which index? ")) 
    value = raw_input("What will be the new value? ")

    try:
        locals()[choice][idx] = value
    except IndexError as e:
        print "Error: {}".format(e)
        return False

    return True

def main():
    flag_pre = "ISITDTU{"
    flag_padding = " "
    len_key = 10
    enc_flag = "1d14273b1c27274b1f10273b05380c295f5f0b03015e301b1b5a293d063c62333e383a20213439162e0037243a72731c22311c2d261727172d5c050b131c433113706b6047556b6b6b6b5f72045c371727173c2b1602503c3c0d3702241f6a78247b253d7a393f143e3224321b1d14090c03185e437a7a607b52566c6c5b6c034047"
    key = [None] * len_key
    m = []

    for i in xrange(0, len(enc_flag), 2):
        m.append(int(enc_flag[i:i+2], 16))

    flag = [None] * len(m)

    for idx, i in enumerate(flag_pre):
        flag[idx] = i

    updated = True

    while updated and None in flag:
        updated = True

        while updated and None in flag:
            updated = False
            m_idx = 0

            for a in range(len_key):
                i = a

                for b in range(len(m)/len_key):
                    if b % 2 != 0:
                        if not flag[i] and key[a]:
                            flag[i] = chr(m[m_idx] ^ ord(key[a]))
                            updated = True
                        elif not key[a] and flag[i]:
                            key[a] = chr(m[m_idx] ^ ord(flag[i]))
                            updated = True
                    else:
                        flag_idx = i + len_key - (a+1+a)

                        if not key[a] and flag[flag_idx]:
                            key[a] = chr(m[m_idx] ^ ord(flag[flag_idx]))
                            updated = True
                        elif not flag[flag_idx] and key[a]:
                            flag[flag_idx] = chr(m[m_idx] ^ ord(key[a]))
                            updated = True

                    i += len_key
                    m_idx += 1

        print "flag: {}".format("".join(c if c else "?" for c in flag))
        print "key: {}".format("".join(c if c else "?" for c in key))

        if not updated:
            if user_guess(flag, key):
                updated = True
            else:
                print "Aborted"


if __name__ == "__main__":
    main()

```

By guessing the last character of `flag` as the padding ` `, `flag` contains non-ASCII characters. Hence, there is no padding in `flag`.

```shellsession
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/cryto$ python xor_soln.py 
flag: ISITDTU{????ome_to_ISITDTUCT????ntest!_Hav3_a_g0????ay._Hope_y0u_w1l????j0y_and_hav3_a_h????rank_1n_0ur_F1rs????f_C0nt3st._Thank??
key: ??RCr4cKm3
Update flag or key? flag
Update at which index? -1
What will be the new value?  
flag: ISITDTU{?81?ome_to_ISITDTUCT??ntest!_Hav3_a_g0?9?ay._Hope_y0u_w1l?n?j0y_and_hav3_a_h?:5?rank_1n_0ur_F1rs??f_C0nt3st._Thank? 
key: %?RCr4cKm3
Update flag or key? ^CTraceback (most recent call last):
  File "xor_soln.py", line 85, in <module>
    main()
  File "xor_soln.py", line 78, in main
    if user_guess(flag, key):
  File "xor_soln.py", line 4, in user_guess
    choice = raw_input("Update flag or key? ").lower()
KeyboardInterrupt
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/crypto$ 
```

The last character of `flag` should be `}`, which is the suffix of most CTF flags. By guessing the second character of `key` as `o` based on the title of the challenge, we get the flag.

```shellsession
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/crypto$ python xor_soln.py 
flag: ISITDTU{????ome_to_ISITDTUCT????ntest!_Hav3_a_g0????ay._Hope_y0u_w1l????j0y_and_hav3_a_h????rank_1n_0ur_F1rs????f_C0nt3st._Thank??
key: ??RCr4cKm3
Update flag or key? flag
Update at which index? -1
What will be the new value? }
flag: ISITDTU{?el?ome_to_ISITDTUCT?_C?ntest!_Hav3_a_g0?d_?ay._Hope_y0u_w1l?_3?j0y_and_hav3_a_h?gh?rank_1n_0ur_F1rs?_C?f_C0nt3st._Thank?}
key: x?RCr4cKm3
Update flag or key? key
Update at which index? 1
What will be the new value? o
flag: ISITDTU{Welcome_to_ISITDTUCTF_C0ntest!_Hav3_a_g00d_day._Hope_y0u_w1ll_3nj0y_and_hav3_a_h1gh_rank_1n_0ur_F1rst_Ctf_C0nt3st._Thank5}
key: xoRCr4cKm3
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/crypto$ 
```

**Flag: `ISITDTU{Welcome_to_ISITDTUCTF_C0ntest!_Hav3_a_g00d_day._Hope_y0u_w1ll_3nj0y_and_hav3_a_h1gh_rank_1n_0ur_F1rst_Ctf_C0nt3st._Thank5}`**

**Files**
- [xor.py](files/xor.py)
- [xor_soln.py](files/xor_soln.py)
- [xor_soln_partial.py](files/xor_soln_partial.py)