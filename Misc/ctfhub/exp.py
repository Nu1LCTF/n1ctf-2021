import itertools
import os
import random
from typing import Callable, Iterable
random.seed(23331337)

def genrandseq(l: int):
    src = [_ for _ in range(l)]
    random.shuffle(src)
    return src

sbox = [(genrandseq(16) + genrandseq(16) + genrandseq(16) + genrandseq(16)) for j in
        range(8)]  # 32 to 48(6*8) #6bit to 4bit
p_tbl = genrandseq(48)
p2_tbl = genrandseq(64)
#print(','.join(map(lambda x: str(x), p_tbl)))
#print(','.join(map(lambda x: str(x), p2_tbl)))
#print(','.join(map(lambda x: str(x), itertools.chain(*sbox))))


# extend 32 to 48
def e(x: list[int]):
    out = x.copy()
    for i in range(16):
        out.append(x[i * 2] ^ x[i * 2 + 1])
    return out


def p(x: list[int], tbl: list):
    assert (len(x) == len(tbl))
    final = x.copy()
    for i in range(len(x)):
        final[i] = x[tbl[i]]
    return final


def inv_p(x: list[int], tbl: list):
    assert (len(x) == len(tbl))
    out = x.copy()
    for i in range(len(x)):
        out[tbl[i]] = x[i]
    return out


def list2int(l):
    return int(''.join(map(lambda x: '1' if x == 1 else '0', l))[::-1], 2)
def list2bytes(l):
    return int.to_bytes(list2int(l),length=8,byteorder='little',signed=False)

def listxor(x, y):
    assert (len(x) == len(y))
    return list(map(lambda a, b: a ^ b, x, y))


def sbox_pass(x: list[int], k: list[int]) -> list[int]:
    out = listxor(x, k)
    out2 = []
    for i in range(8):
        sub = list2int(out[i * 6:i * 6 + 6])
        out2.append("{:0>4b}".format(sbox[i][sub])[::-1])
    return list(map(lambda _: 1 if _ == '1' else 0, ''.join(out2)))


def f(x: list[int], k: list[int]) -> list[int]:
    x = e(x)
    x = p(x, p_tbl)
    return sbox_pass(x, k)


def getk(k: list[int], rnd: int):
    for i in range(rnd):
        k = inv_p(k, p2_tbl)
    return k[:48]


def enc_blk(x: list[int], k: list[int]):
    x = p(x, p2_tbl)
    l, r = x[:32], x[32:]
    for i in range(3):
        l, r = r, listxor(f(r, getk(k, i)), l)
    return inv_p(l + r, p2_tbl)


def dec_blk(x: list[int], k: list[int]):
    x = p(x, p2_tbl)
    l, r = x[:32], x[32:]
    for i in range(3):
        l, r = listxor(f(l, getk(k, 2 - i)), r), l
    return inv_p(l + r, p2_tbl)


# assert (dec_blk(enc_blk([0] * 64, [1] * 64), [1] * 64) == [0] * 64)


def byte2list(x: bytes):
    return list(map(lambda _: int(_), list(("{0:0>" + str(len(x) * 8) + "b}").format(int.from_bytes(x, "little")))))[
           ::-1]


def attack_sbox(idx: int, inpstar: list[int], oneinp: list[int], outstar: list[int]) -> set[int]:
    def get_diff(box):
        cf = {}
        for i in range(64):
            for j in range(0, i + 1):
                k = i ^ j
                d = box[i] ^ box[j]
                cf.setdefault((k, d), set())
                cf[(k, d)].add(i)
                cf[(k, d)].add(j)
        return cf

    diff = get_diff(sbox[idx])
    possible = diff[(list2int(inpstar), list2int(outstar))]
    hint = list2int(oneinp)
    res = set(map(lambda x: x ^ hint, possible))
    return res


def attack(decfun: Callable[[list[int]], list[int]]) -> dict[int, set[int]]:
    '''
    l0 r0
    enc:
    l1=r0 r1=l0^f(r0,k0)
    l2=r1 r2=l1^f(r1,k1)
    l3=r2 r3=l2^f(r2,k2)
    dec:
    l1=r0^f(l0,k2) r1=l0
    l2=r1^f(l1,k1) r2=l1
    l3=r2^f(l2,k0) r3=l2
    l0*=0 r0*=*
    l1*=* r1*=0
    l2*=? r2*=*
    l3*=*^f*(l2,k0)(known) r3*=l2*(known)
    '''
    l0, r0, r0d = tuple(map(lambda _: byte2list(os.urandom(4)), range(3)))

    def decpair(l, r):
        o1 = l + r
        o1 = inv_p(o1, p2_tbl)
        o1 = decfun(o1)
        o1 = p(o1, p2_tbl)
        return o1[:32], o1[32:]

    l3, r3 = decpair(l0, r0)
    star = listxor(r0, r0d)
    l3n, r3n = decpair(l0, r0d)
    l3s = listxor(listxor(l3, l3n), star)

    inpstar = listxor(p(e(r3), p_tbl), p(e(r3n), p_tbl))
    outstar = l3s
    possible = dict()
    for i in range(8):
        possible[i] = attack_sbox(i, inpstar[i * 6:i * 6 + 6], p(e(r3), p_tbl)[i * 6:i * 6 + 6],
                                  outstar[i * 4:i * 4 + 4])
    return possible


def attack3(decf: Callable[[list[int]], list[int]], check_enc: list[list[int]], check_plain: list[list[int]]):

    res = attack(decf)
    for _ in range(6):
        res1 = attack(decf)
        for i in range(8):
            res[i].intersection_update(res1[i])
    guesskey = []
    for i in range(8):
        assert (len(list(res[i])) == 1)
        subk = list(res[i])[0]
        guesskey += list(map(lambda _: int(_), list("{0:0>6b}".format(subk)[::-1])))
    print("guess",guesskey)

    ans = []
    for i in range(65536):
        nowkey = guesskey + list(map(lambda _: int(_), list("{0:0>16b}".format(i))))
        succflag = True
        for _ in range(len(check_enc)):
            if dec_blk(check_enc[_], nowkey) != check_plain[_]:
                succflag = False
                break
        if succflag:
            ans.append(nowkey)
    print(len(ans))
    for i in ans:
        print("possible key %d"%list2int(i))
    return ans

from n1misc import decrypt_blk
checks=[b'nt1drctf',os.urandom(8)]
def run():
    check_enc=[]
    check_plain=[]
    for i in checks:
        check_enc.append(byte2list(i))
        check_plain.append(byte2list(decrypt_blk(i)))
    attack3(lambda x:byte2list(decrypt_blk(list2bytes(x))),check_enc,check_plain)
run()
