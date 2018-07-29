#!/bin/python

from pwn import *
from StringIO import StringIO
from types import CodeType

import ast
import dis
import marshal
import py_compile
import string
import sys
import time


import uncompyle6


MAX_TRIES = 5
PYC_FILENAME = "xoxopwn_{}.pyc"


def get_remote_data(input, retry=True):
    data = None
    tries = 0

    while not data and (tries == 0 or retry and tries < MAX_TRIES):
        p = remote("178.128.12.234", 10002)
        p.recvuntil("This is function x()>>> ")
        p.sendline(input)
        data = p.recvrepeat(0.2)
        p.close()

        tries += 1
        sleep(2)

    return data


def get_remote_argcount(func):
    for i in xrange(5):
        if get_remote_data("{}({})".format(func, ", ".join(["\"a\""]*i)), retry=False):
            return i

    return 0


def get_dis_output(codestring):
    stdout = sys.stdout
    f = StringIO()
    sys.stdout = f

    dis.dis(codestring)

    sys.stdout = stdout

    output = f.getvalue()
    output = filter(None, output.split("\n"))
    output = [line.split() for line in output]

    return output


def get_var_count(dis_output):
    store_fast_idxes = []

    for line in dis_output:
        op_code_idx = 2 if line[0] == ">>" else 1

        if line[op_code_idx] in ["LOAD_FAST", "STORE_FAST"]:
            store_fast_idxes.append(int(line[op_code_idx+1]))

    var_count = max(store_fast_idxes) + 1

    return var_count


def get_varnames(count):
    return tuple(string.ascii_lowercase[:count])


def get_firstlineno(dis_output):
    return int(dis_output[0][0])


def get_code_obj(func):
    # Remote
    argcount = get_remote_argcount(func)
    nlocals = int(get_remote_data("{}.__code__.co_nlocals".format(func)))
    flags = int(get_remote_data("{}.__code__.co_flags".format(func)))
    codestring = get_remote_data("{}.__code__.co_code".format(func))
    constants = ast.literal_eval(get_remote_data("{}.__code__.co_consts".format(func)))
    names = ast.literal_eval(get_remote_data("{}.__code__.co_names".format(func)))
    filename = get_remote_data("__file__")
    lnotab = get_remote_data("{}.__code__.co_lnotab".format(func))

    # Local
    # if func == "x":
    #     argcount = 1
    #     nlocals = 2
    #     flags = 67
    #     codestring = (
    #         "d\x01\x00}\x01\x00t\x00\x00|\x00\x00\x83\x01\x00d\x02\x00k\x04\x00r\x1c\x00d"
    #         "\x03\x00St\x01\x00|\x00\x00\x83\x01\x00S"
    #     )
    #     constants = (
    #         None,
    #         "finding secret in o()",
    #         21,
    #         "Big size ~"
    #     )
    #     names = (
    #         "len",
    #         "eval"
    #     )
    #     filename = "/home/xoxopwn/xoxopwn.py"
    #     lnotab = "\x00\x01\x06\x01\x12\x01\x04\x02"
    # elif func == "o":
    #     argcount = 1
    #     nlocals = 5
    #     flags = 67
    #     codestring = (
    #         "d\x01\x00}\x01\x00|\x01\x00j\x00\x00d\x02\x00\x83\x01\x00}\x01\x00d\x03\x00}"
    #         "\x02\x00d\x04\x00}\x03\x00xL\x00t\x01\x00t\x02\x00|\x00\x00\x83\x01\x00\x83"
    #         "\x01\x00D]8\x00}\x04\x00|\x03\x00t\x03\x00t\x04\x00|\x00\x00|\x04\x00\x19\x83"
    #         "\x01\x00t\x04\x00|\x02\x00|\x04\x00t\x02\x00|\x00\x00\x83\x01\x00\x16\x19\x83"
    #         "\x01\x00A\x83\x01\x007}\x03\x00q4\x00W|\x03\x00|\x01\x00k\x02\x00r\x84\x00d"
    #         "\x05\x00GHn\x05\x00d\x06\x00GHd\x00\x00S"
    #     )
    #     constants = (
    #         None,
    #         "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09",
    #         "hex",
    #         "pythonwillhelpyouopenthedoor",
    #         "",
    #         "Open the door",
    #         "Close the door"
    #     )
    #     names = (
    #         "decode",
    #         "xrange",
    #         "len",
    #         "chr",
    #         "ord"
    #     )
    #     filename = "/home/xoxopwn/xoxopwn.py"
    #     lnotab = "\x00\x01\x06\x01\x0f\x01\x06\x01\x06\x01\x19\x016\x01\x0c\x01\x08\x02"

    stacksize = 1
    name = func
    dis_output = get_dis_output(codestring)
    varnames = get_varnames(get_var_count(dis_output))
    firstlineno = get_firstlineno(dis_output)

    code = CodeType(
        argcount,
        nlocals,
        stacksize,
        flags,
        codestring,
        constants,
        names,
        varnames,
        filename,
        name,
        firstlineno,
        lnotab
    )

    return code


def create_pyc_file(func, code):
    with open(PYC_FILENAME.format(func), "wb") as f:
        f.write("\0\0\0\0")
        py_compile.wr_long(f, long(time.time()))
        marshal.dump(code, f)
        f.flush()
        f.seek(0, 0)
        f.write(py_compile.MAGIC)


def print_code(func, code):
    f = StringIO()
    uncompyle6.uncompyle_file(PYC_FILENAME.format(func), outstream=f)

    log.info("def {}({}):\n{}".format(
        func,
        ", ".join(get_varnames(code.co_argcount)) if code.co_argcount else "",
        f.getvalue())
    )


def flag():
    # Error in line 221
    # Line 221: d += chr(ord(a[e]) ^ ord(c[e % len(c)]))
    # # uncompyle6 version 3.2.3
    # # Python bytecode 2.7 (62211)
    # # Decompiled from: Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
    # # [GCC 5.4.0 20160609]
    # # Embedded file name: /home/xoxopwn/xoxopwn.py
    # # Compiled at: 2018-07-29 07:35:22
    # b = '392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09'
    # b = b.decode('hex')
    # c = 'pythonwillhelpyouopenthedoor'
    # d = ''
    # for e in xrange(len(a)):
    #     d += chr(ord(a[e]) ^ ord(c[e % len(a)]))

    # if d == b:
    #     print 'Open the door'
    # else:
    #     print 'Close the door'

    b = "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09"
    b = b.decode("hex")
    c = "pythonwillhelpyouopenthedoor"
    d = ""

    for e in xrange(len(b)):
        d += chr(ord(b[e]) ^ ord(c[e % len(c)]))

    return d


def main():
    x_code = get_code_obj("x")
    o_code = get_code_obj("o")
    create_pyc_file("x", x_code)
    create_pyc_file("o", o_code)
    print_code("x", x_code)
    print_code("o", o_code)

    log.success("Flag: {}".format(flag()))


if __name__ == "__main__":
    main()
