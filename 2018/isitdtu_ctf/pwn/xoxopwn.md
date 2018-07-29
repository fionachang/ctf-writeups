# xoxopwn

Category: `pwn`

Services: `nc 178.128.12.234 10002` or `nc 178.128.12.234 10003`

Points: `601`

### What It Does

The maximum length of the user input is 21 characters.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> A
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ python -c 'print "A" * 22' | nc 178.128.12.234 10002
This is function x()>>> Big size ~ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

The process is written in python and the function is evaluating the user input. If there are any exceptions, nothing will be printed.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> 1
1ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> "A"
Aubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> 1+1
2ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> x
<function x at 0x7f88b0d2e050>ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

The function definition of `x()` can be viewed in the [xoxopwn_soln.out](files/xoxopwn_soln.out)

### How to Solve

Using builtin python functions, we know more about the process and that the flag is in function `o()`.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> globals()
{'server_thread': <Thread(Thread-1, started daemon 140225032603392)>, 'ThreadedTCPRequestHandler': <class __main__.ThreadedTCPRequestHandler at 0x7f88b0d32530>, 'ThreadedTCPServer': <class __main__.ThreadedTCPServer at 0x7f88b0d324c8>, 'socket': <module 'socket' from '/usr/lib/python2.7/socket.pyc'>, 'SocketServer': <module 'SocketServer' from '/usr/lib/python2.7/SocketServer.pyc'>, '__builtins__': <module '__builtin__' (built-in)>, '__file__': '/home/xoxopwn/xoxopwn.py', 'o': <function o at 0x7f88b0d21c80>, '__package__': None, 'port': 9999, 'threading': <module 'threading' from '/usr/lib/python2.7/threading.pyc'>, 'host': '0.0.0.0', 'x': <function x at 0x7f88b0d2e050>, '__name__': '__main__', '__doc__': None, 'serverthuong123': <__main__.ThreadedTCPServer instance at 0x7f88b0d19e18>}ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> locals()
{'a': 'locals()', 'xxx': 'finding secret in o()'}ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> dir(x)  
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

The `__code__` and `func_code` attribute of a python function is the code object of the function. It contains the bytecode and other information of the function. Using the code object, we can create the `.pyc` python compiled code file. With the `.pyc` file, we can decompile it to obtain the source code.

To create the code object, we need a few parameters.

```shell
In [1]: from types import CodeType

In [2]: CodeType?
Type:        type
String form: <type 'code'>
Docstring:
code(argcount, nlocals, stacksize, flags, codestring, constants, names,
      varnames, filename, name, firstlineno, lnotab[, freevars[, cellvars]])

Create a code object.  Not for the faint of heart.

In [3]: 
```

We can get the parameters by inspecting the attributes of code object.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> dir(o.__code__)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

However, we can only get some of the parameters due to the length restriction on the user input.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_nlocals
5ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_flags
67ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_code
d}|jd�}d}d}xLtt|��D]8}|tt||�t||t|��A�7}q4W||kr�dGHndGHdSubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_consts
(None, '392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09', 'hex', 'pythonwillhelpyouopenthedoor', '', 'Open the door', 'Close the door')ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_names
('decode', 'xrange', 'len', 'chr', 'ord')ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> __file__
/home/xoxopwn/xoxopwn.pyubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o.__code__.co_lnotab
6
            ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

To get `argcount`, we can test whether the function outputs anything. `o()` has 1 `argcount`.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o()
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o("A")
Noneubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ nc 178.128.12.234 10002
This is function x()>>> o("A", "B")
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

To get `varnames` and `firstlineno`, we can use the disassembly of the bytecode.

```shell
In [3]: import dis

In [4]: codestring = "d\x01\x00}\x01\x00|\x01\x00j\x00\x00d\x02\x00\x83\x01\x00}\x01\x00d\x03\x00}\x02\x00d\x04\x00}\x03\x00xL\x00t\x01\x00t\x02\x00|\x00\x00\x83\x01\x00\x83\x01\x00D]8\x00}\x04\x00|\x03\x00t\x03\x00t\x04\x00|\x00\x00|\x04\x00\x19\x83\x01\x00t\x04\x00|\x02\x00|\x04\x00t\x02\x00|\x00\x00\x83\x01\x00\x16\x19\x83\x01\x00A\x83\x01\x007}\x03\x00q4\x00W|\x03\x00|\x01\x00k\x02\x00r\x84\x00d\x05\x00GHn\x05\x00d\x06\x00GHd\x00\x00S"

In [5]: dis.dis(bytecode)
          0 LOAD_CONST          1 (1)
          3 STORE_FAST          1 (1)
          6 LOAD_FAST           1 (1)
          9 LOAD_ATTR           0 (0)
         12 LOAD_CONST          2 (2)
         15 CALL_FUNCTION       1
         18 STORE_FAST          1 (1)
         21 LOAD_CONST          3 (3)
         24 STORE_FAST          2 (2)
         27 LOAD_CONST          4 (4)
         30 STORE_FAST          3 (3)
         33 SETUP_LOOP         76 (to 112)
         36 LOAD_GLOBAL         1 (1)
         39 LOAD_GLOBAL         2 (2)
         42 LOAD_FAST           0 (0)
         45 CALL_FUNCTION       1
         48 CALL_FUNCTION       1
         51 GET_ITER       
    >>   52 FOR_ITER           56 (to 111)
         55 STORE_FAST          4 (4)
         58 LOAD_FAST           3 (3)
         61 LOAD_GLOBAL         3 (3)
         64 LOAD_GLOBAL         4 (4)
         67 LOAD_FAST           0 (0)
         70 LOAD_FAST           4 (4)
         73 BINARY_SUBSCR  
         74 CALL_FUNCTION       1
         77 LOAD_GLOBAL         4 (4)
         80 LOAD_FAST           2 (2)
         83 LOAD_FAST           4 (4)
         86 LOAD_GLOBAL         2 (2)
         89 LOAD_FAST           0 (0)
         92 CALL_FUNCTION       1
         95 BINARY_MODULO  
         96 BINARY_SUBSCR  
         97 CALL_FUNCTION       1
        100 BINARY_XOR     
        101 CALL_FUNCTION       1
        104 INPLACE_ADD    
        105 STORE_FAST          3 (3)
        108 JUMP_ABSOLUTE      52
    >>  111 POP_BLOCK      
    >>  112 LOAD_FAST           3 (3)
        115 LOAD_FAST           1 (1)
        118 COMPARE_OP          2 (==)
        121 POP_JUMP_IF_FALSE   132
        124 LOAD_CONST          5 (5)
        127 PRINT_ITEM     
        128 PRINT_NEWLINE  
        129 JUMP_FORWARD        5 (to 137)
    >>  132 LOAD_CONST          6 (6)
        135 PRINT_ITEM     
        136 PRINT_NEWLINE  
    >>  137 LOAD_CONST          0 (0)
        140 RETURN_VALUE   

In [6]: 
```

We can obtain the variable count by getting the maximum index of "LOAD_FAST" and "STORE_FAST" in the third column of the `dis.dis()` output. Then, make a tuple of random variable names with the size of variable count. Hence, the variable count is 5 and `varnames` will be `("a", "b", "c", "d", "e")`.

`firstlineno` is `0` based on the first column of the first line of the `dis.dis()` output.

`stacksize` is `1` by getting the `stacksize` of a dummy function.

```shell
In [6]: def func():
   .....:     pass
   .....: 

In [7]: func.__code__.co_stacksize
Out[7]: 1

In [8]: 
```

`name` is `o`.

With all the required parameters, we can create the code object.

```shell
In [8]: argcount = 1

In [9]: nlocals = 5

In [10]: stacksize = 1

In [11]: flags = 67

In [12]: codestring = 'd\x01\x00}\x01\x00|\x01\x00j\x00\x00d\x02\x00\x83\x01\x00}\x01\x00d\x03\x00}\x02\x00d\x04\x00}\x03\x00xL\x00t\x01\x00t\x02\x00|\x00\x00\x83\x01\x00\x83\x01\x00D]8\x00}\x04\x00|\x03\x00t\x03\x00t\x04\x00|\x00\x00|\x04\x00\x19\x83\x01\x00t\x04\x00|\x02\x00|\x04\x00t\x02\x00|\x00\x00\x83\x01\x00\x16\x19\x83\x01\x00A\x83\x01\x007}\x03\x00q4\x00W|\x03\x00|\x01\x00k\x02\x00r\x84\x00d\x05\x00GHn\x05\x00d\x06\x00GHd\x00\x00S'

In [13]: constants = (None, '392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09', 'hex', 'pythonwillhelpyouopenthedoor', '', 'Open the door', 'Close the door')

In [14]: names = ('decode', 'xrange', 'len', 'chr', 'ord')

In [15]: varnames = ('a', 'b', 'c', 'd', 'e')

In [16]: filename = '/home/xoxopwn/xoxopwn.py'

In [17]: name = 'o'

In [18]: firstlineno = 0

In [19]: lnotab = '\x00\x01\x06\x01\x0f\x01\x06\x01\x06\x01\x19\x016\x01\x0c\x01\x08\x02'

In [20]: code = CodeType(argcount, nlocals, stacksize, flags, codestring, constants, names, varnames, filename, name, firstlineno, lnotab)

In [21]: 
```

Create the `.pyc` file using the code object.

```shell
In [21]: with open("xoxopwn_o.pyc", "wb") as f:
   ....:     f.write("\0\0\0\0")
   ....:     py_compile.wr_long(f, long(time.time()))
   ....:     marshal.dump(code, f)
   ....:     f.flush()
   ....:     f.seek(0, 0)
   ....:     f.write(py_compile.MAGIC)
   ....:     

In [22]: 
```

Decompile the `.pyc` file to get the source code. `a` is the user input.

```shell
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ uncompyle6 xoxopwn_o.pyc 
# uncompyle6 version 3.2.3
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
# [GCC 5.4.0 20160609]
# Embedded file name: /home/xoxopwn/xoxopwn.py
# Compiled at: 2018-07-29 18:26:27
b = '392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09'
b = b.decode('hex')
c = 'pythonwillhelpyouopenthedoor'
d = ''
for e in xrange(len(a)):
    d += chr(ord(a[e]) ^ ord(c[e % len(a)]))

if d == b:
    print 'Open the door'
else:
    print 'Close the door'
# okay decompiling xoxopwn_o.pyc
ubuntu@ubuntu-xenial:/ctf/2018/isitdtu_ctf/pwn$ 
```

There seems to be an error in the `for` loop. The correct code should be:

```python
for e in xrange(len(a)):
    d += chr(ord(a[e]) ^ ord(c[e % len(c)]))
```

Reverse the code to get the flag.

```python
b = "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09"
b = b.decode("hex")
c = "pythonwillhelpyouopenthedoor"
d = ""

for e in xrange(len(b)):
    d += chr(ord(b[e]) ^ ord(c[e % len(c)]))

print d
```

**Flag: `ISITDTU{1412_secret_in_my_door}`**

Files:
- [xoxopwn_soln.py](files/xoxopwn_soln.py)
- [xoxopwn_soln.out](files/xoxopwn_soln.out)
- [xoxopwn_x.pyc](files/xoxopwn_x.pyc)
- [xoxopwn_o.pyc](files/xoxopwn_o.pyc)