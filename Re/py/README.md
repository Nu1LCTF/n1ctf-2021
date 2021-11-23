ELF is packaged and encrypted by `pyinstaller`.Use `pyinstxtractor` to unpack and then use `uncompyle6` to decompile `0a5n.pyc`, from which we know that flag is a hexadecimal string with a length of 28, and the `L` and `var` modules are imported.
Decrypt `PYZ-00.pyz`.

```python
from pyimod02_archive import ZlibArchiveReader
import zlib

module = ZlibArchiveReader("./PYZ-00.pyz")
PYZ_TYPE_MODULE = 0
PYZ_TYPE_PKG = 1
PYZ_TYPE_DATA = 2
PYZ_TYPE_NSPKG = 3

def extract(module, name):
        (typ, pos, length) = module.toc.get(name, (0, None, 0))
        if pos is None:
            return None
        with module.lib:
            module.lib.seek(module.start + pos)
            obj = module.lib.read(length)
        try:
            if module.cipher:
                obj = module.cipher.decrypt(obj)
            obj = zlib.decompress(obj)
            if typ in (PYZ_TYPE_MODULE, PYZ_TYPE_PKG, PYZ_TYPE_NSPKG):
                with open("PYC/%s.pyc"%name, "wb") as f:
                    f.write(b"\x16\x0D\x0D\x0A\x00\x00\x00\x00\x5a\x01\x00\x00")
                    f.write(obj)
                    print("%s OK!"%name)
        except EOFError as e:
            pass

for k, v in module.toc.items():
    extract(module, k)
```

Then decompile `var.pyc` to get the variable.

![image-20211121171733796](https://github.com/Nu1LCTF/n1ctf-2021/blob/main/Re/py/images/image-20211121171733796.png)

Check `opcode.pyc` and found that the opcode of some operators has been modified (`^` -> `+`, `+` ->` %` ... )

Modify the opcode map of `pycdc` and try to decompile `L.pyc`, but it fails. Disassemble `L.pyc` with `pycdas`.

![image-2021](https://github.com/Nu1LCTF/n1ctf-2021/blob/main/Re/py/images/image-20211122104824479.png)

Get the code from these bytecode.

```python
z = [105, 103, 123, 34, 63, 34, 50, 8, 110, 107, 96, 97, 34, 63, 34, 97, 118, 123, 114, 
...
111, 103, 111, 97, 114, 123, 8, 105, 103, 123, 34, 41, 63, 34, 51]
z=''.join([chr(i^2) for i in z])
exec(z)

z = [112, 101, 102, 104, 97, 57, 95, 38, 98, 53, 38, 40, 36, 38, 98, 54, 38, 40, 36, 38, 
...
98, 107, 118, 36, 109, 36, 109, 106, 36, 103, 107, 96, 97, 119, 62, 97, 124, 97, 103, 44, 109, 45]
z=''.join([chr(i^4) for i in z])
exec(z)
```

exec will execute the following code.

```python
key = 0
libc = ctypes.CDLL("libc.so.6")
_ptrace = libc.ptrace
key=_ptrace(0, 0, 1, 0)
_memcpy = libc.memcpy
key += 1

table=["f1", "f2", "c2.__add__", "c1.s1", "c2.__mul__", "f3"]
x="""address=id(%s.__code__.co_code)+bytes.__basicsize__-1
codes=list(%s.__code__.co_code)
for i in range(len(codes)):codes[i]^=key
codes=bytearray(codes)
buff=(ctypes.c_byte*len(codes)).from_buffer(codes)
_memcpy(ctypes.c_char_p(address),ctypes.cast(buff,ctypes.POINTER(ctypes.c_char)),ctypes.c_int(len(codes)))
key+=1"""
codes = [x%(i,i) for i in table]
for i in codes:exec(i)
```

Read the code to know that the bytecode will be decrypted when importing module `L`.

We can directly decrypt the bytecode in the `L.pyc`, or dump the decrypted bytecode from the process.

Here we directly decrypt the bytecode in the pyc file.

```python
# mylib.py
import marshal

f = open('./L.pyc', 'rb')

f.read(12)
code = marshal.load(f)

def decrypt(code_object, key):
    code=list(code_object)
    for i in range(len(code)):
        code[i]^=key
    return bytearray(code)

def decrypt_code():
    code.co_consts[2].co_code = decrypt(code.co_consts[2].co_code, 1) # f1
    code.co_consts[4].co_code = decrypt(code.co_consts[4].co_code, 2) # f2
    code.co_consts[8].co_consts[6].co_code = decrypt(code.co_consts[8].co_consts[6].co_code, 3) # c2.__add__
    code.co_consts[6].co_consts[3].co_code = decrypt(code.co_consts[6].co_consts[3].co_code, 4) # c1.s1
    code.co_consts[8].co_consts[8].co_code = decrypt(code.co_consts[8].co_consts[8].co_code, 5) # c2.__mul__
    code.co_consts[10].co_code = decrypt(code.co_consts[10].co_code, 6) # f3

decrypt_code()

ff = open('dumpss.pyc', 'wb')
ff.write(b"\x16\x0D\x0D\x0A\x00\x00\x00\x00\x5a\x01\x00\x00")
marshal.dump(code, ff)
```

Call the api in libpython to run the python script.

```c
#include <stdio.h>
#include <dlfcn.h>

typedef void (func_void)();
typedef void (func_str)(char *);

int main(int argc, char *argv[]) {
    void * handle = NULL;
    dlopen("./libcrypto.so.1.0.0", RTLD_LOCAL | RTLD_NOW);
    dlopen("./libssl.so.1.0.0", RTLD_LOCAL | RTLD_NOW);
    handle = dlopen("./libpython3.5m.so", RTLD_LOCAL | RTLD_NOW );

    func_void *Py_Initialize = (func_void *)dlsym(handle, "Py_Initialize");
    func_str *PyRun_SimpleString = (func_str *)dlsym(handle, "PyRun_SimpleString");
    func_void *Py_Finalize = (func_void *)dlsym(handle, "Py_Finalize");

    Py_Initialize();
    
    PyRun_SimpleString("import mylib");

    Py_Finalize();

    return 0;
}
```

After decrypting the bytecode, it can be decompiled, but it is found that varname is some invisible characters. Modify varname to make it readable.

```python
tot = 0
def generate_names(size):
    names = []
    global tot
    for i in range(size):
        names.append("var_%d"%tot)
        tot += 1
    return names

def modify_varname(code_object):
    for i in range(len(code_object.co_consts)):
        if str(type(code_object.co_consts[i])) == "<class 'code'>":
            if len(code_object.co_consts[i].co_varnames) > 1:
                if code_object.co_consts[i].co_varnames[0] == "self":
                    names = generate_names(len(code_object.co_consts[i].co_varnames) - 1)
                    names = ["self"] + names
                    code_object.co_consts[i].co_varnames = tuple(names)
                else:
                    names = generate_names(len(code_object.co_consts[i].co_varnames))
                    code_object.co_consts[i].co_varnames = tuple(names)
            modify_varname(code_object.co_consts[i])

modify_varname(code)
```

Then decompile `dumpss.pyc` to get the source code.

![image-20211122093925885](https://github.com/Nu1LCTF/n1ctf-2021/blob/main/Re/py/images/image-20211122093925885.png)

From the code we know that this is a Python library for elliptic curve crypto.

Simplify the program, we get the following sage code.

```python
p = 1461501637330902918203684832716283019651637554291
a = 1461501637330902918203684832716283019651637554289
b = 33
Gx = 1409958218732090440323571427282941405264992526638
Gy = 1003170987214086410878112234291438209997203387689

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)

flag = 'xxxxxxxxxxxxx'
k = int('0x' + flag[::-1], 16)

K = k * G
_x, _y = K.xy()
assert _x == 418314664634765473100948993230460851448740309937
assert _y == 1014751162621960915383962534690487909615594365554
```

Use Pohlig-Hellman attack to get k.

```python
p = 1461501637330902918203684832716283019651637554291
a = 1461501637330902918203684832716283019651637554289
b = 33

Gx = 1409958218732090440323571427282941405264992526638
Gy = 1003170987214086410878112234291438209997203387689

_x = 418314664634765473100948993230460851448740309937
_y = 1014751162621960915383962534690487909615594365554

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
n = E.order()
h = E(_x, _y)

factors = list(factor(n))
m = 1
moduli = []
remainders = []

print(factors)

for i, j in factors:
    Qi = i**j
    g2 = G*(n//Qi)
    q2 = h*(n//Qi)
    ri = discrete_log(q2, g2, operation='+')
    remainders.append(ri)
    moduli.append(Qi)
    m *= Qi

k = hex(crt(remainders, moduli))[2:]
k = k[::-1]
print("n1ctf{" + k + "}")
# n1ctf{304e6e4f3155756f493169304c6c}
```

