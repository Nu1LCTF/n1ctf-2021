import pwn
import itertools
from pwn import asm
import functools
import struct

alphanum_pool = b"UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789"
pwn.context.arch = "amd64"

xor_table = [0] * 0x80
for i in itertools.product(alphanum_pool, repeat=2):
    n = i[0] ^ i[1]
    xor_table[n] = i
xor_table = xor_table


def num_size(num: int):
    assert num >= 0
    if num <= 0xff:
        return 1
    elif num <= 0xffff:
        return 2
    elif num <= 0xffffffff:
        return 4
    elif num <= 0xffffffffffffffff:
        return 8
    else:
        raise Exception("size out of range")


def is_alphanumeric(num: int, size: int):
    for i in range(size):
        if num & 0xff not in alphanum_pool:
            return False
        num = num >> 8
    return num == 0


def mul_iter():
    # 1. try one byte * one byte
    for i in itertools.combinations_with_replacement(alphanum_pool, 2):
        yield i

    numbers = map(lambda x: (x[0] << 8) + x[1], itertools.product(alphanum_pool, repeat=2))
    # 2. try two byte * one byte
    for i in itertools.product(numbers, alphanum_pool):
        yield i

    # 3. try two byte * two byte
    for i in itertools.combinations_with_replacement(numbers, 2):
        yield i


def pack(data: int, fmt):
    return struct.pack(fmt, data)


def unpack(data: bytes, fmt):
    return struct.unpack(fmt, data)[0]


p8 = functools.partial(pack, fmt="<B")
p16 = functools.partial(pack, fmt="<H")
p32 = functools.partial(pack, fmt="<I")
p64 = functools.partial(pack, fmt="<Q")

u8 = functools.partial(unpack, fmt="<B")
u16 = functools.partial(unpack, fmt="<H")
u32 = functools.partial(unpack, fmt="<I")
u64 = functools.partial(unpack, fmt="<Q")
