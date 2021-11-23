# -*- coding: utf-8 -*-
import ctypes

def inv_mod(b, p): # f1
    if b < 0 or p <= b:
        b = b % p
    c, d = b, p
    uc, vc, ud, vd, temp = 1, 0, 0, 1, 0
    while c != 0:
        temp = c
        q, c, d = d // c, d % c, temp
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc

    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + p


def leftmost_bit(x): # f2 
    assert x > 0
    result = 1
    while result <= x:
        result = 2 * result
    return result // 2


class CurveFp(object): # c1

    def __init__(self, p, a, b):
        _t = p
        _t ^= 1<<160
        self.p = _t
        __t = a
        __t -=1
        __t //= 2
        self.a = __t
        ___t = b
        ___t //= 2
        ___t += 1
        self.b = ___t
    

    def contains_point(self, x, y):
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

class Point(object): # c2

    def __init__(self, curve, x, y, order=None):

        self.curve = curve
        self.x = x
        self.y = y
        self.order = order
        if self.curve:
            assert self.curve.contains_point(x, y)
        if order:
            assert self * order == INFINITY

    def __eq__(self, other):
        if self.curve == other.curve \
                and self.x == other.x \
                and self.y == other.y:
            return True
        else:
            return False

    def __add__(self, other):
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.curve == other.curve

        if self.x == other.x:
            if (self.y + other.y) % self.curve.p == 0:
                return INFINITY
            else:
                return self.double()

        p = self.curve.p
        l = ((other.y - self.y) * \
             inv_mod(other.x - self.x, p)) % p

        x3 = (l * l - self.x - other.x) % p
        y3 = (l * (self.x - x3) - self.y) % p

        return Point(self.curve, x3, y3)

    def __mul__(self, other):
        e = other
        if self.order:
            e = e % self.order
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY

        e3 = 3 * e
        negative_self = Point(self.curve, self.x, -self.y, self.order)
        i = leftmost_bit(e3) // 2
        result = self

        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            i = i // 2
        return result

    def __rmul__(self, other):
        return self * other

    def double(self): # s1
        if self == INFINITY:
            return INFINITY

        p = self.curve.p
        a = self.curve.a
        l = ((3 * self.x * self.x + a) * \
             inv_mod(2 * self.y, p)) % p

        x3 = (l * l - 2 * self.x) % p
        y3 = (l * (self.x - x3) - self.y) % p

        return Point(self.curve, x3, y3)

INFINITY = Point(None, None, None)

def f3(flag):
    t = 0
    for i in flag[::-1]:
        t = t << 4 | int(i, 16)
    return t


# key = 0
# libc = ctypes.CDLL("libc.so.6")
# _ptrace = libc.ptrace
# key=_ptrace(0, 0, 1, 0)
# _memcpy = libc.memcpy
# key += 1
z = [105, 103, 123, 34, 63, 34, 50, 8, 110, 107, 96, 97, 34, 63, 34, 97, 118, 123, 114, 103, 113, 44, 65, 70, 78, 78, 42, 32, 110, 107, 96, 97, 44, 113, 109, 44, 52, 32, 43, 8, 93, 114, 118, 112, 99, 97, 103, 34, 63, 34, 110, 107, 96, 97, 44, 114, 118, 112, 99, 97, 103, 8, 105, 103, 123, 63, 93, 114, 118, 112, 99, 97, 103, 42, 50, 46, 34, 50, 46, 34, 51, 46, 34, 50, 43, 8, 93, 111, 103, 111, 97, 114, 123, 34, 63, 34, 110, 107, 96, 97, 44, 111, 103, 111, 97, 114, 123, 8, 105, 103, 123, 34, 41, 63, 34, 51]
z=''.join([chr(i^2) for i in z])
exec(z)




# table=["f1", "f2", "c2.__add__", "c1.s1", "c2.__mul__", "f3"]
# x="""address=id(%s.__code__.co_code)+bytes.__basicsize__-1
# codes=list(%s.__code__.co_code)
# for i in range(len(codes)):codes[i]^=key
# codes=bytearray(codes)
# buff=(ctypes.c_byte*len(codes)).from_buffer(codes)
# _memcpy(ctypes.c_char_p(address),ctypes.cast(buff,ctypes.POINTER(ctypes.c_char)),ctypes.c_int(len(codes)))
# key+=1"""
# codes = [x%(i,i) for i in table]
# for i in codes:exec(i)
z = [112, 101, 102, 104, 97, 57, 95, 38, 98, 53, 38, 40, 36, 38, 98, 54, 38, 40, 36, 38, 103, 54, 42, 91, 91, 101, 96, 96, 91, 91, 38, 40, 36, 38, 103, 53, 42, 119, 53, 38, 40, 36, 38, 103, 54, 42, 91, 91, 105, 113, 104, 91, 91, 38, 40, 36, 38, 98, 55, 38, 89, 14, 124, 57, 95, 61, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 55, 40, 36, 53, 53, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 53, 53, 54, 40, 36, 50, 54, 40, 36, 53, 52, 50, 40, 36, 53, 52, 55, 40, 36, 48, 55, 40, 36, 55, 60, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 48, 54, 40, 36, 48, 52, 40, 36, 61, 51, 40, 36, 53, 54, 54, 40, 36, 53, 53, 61, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 61, 51, 40, 36, 61, 60, 40, 36, 53, 53, 54, 40, 36, 53, 52, 50, 40, 36, 61, 50, 40, 36, 53, 53, 54, 40, 36, 53, 52, 50, 40, 36, 53, 54, 53, 40, 36, 53, 52, 54, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 48, 50, 40, 36, 49, 52, 40, 36, 61, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 50, 54, 40, 36, 53, 53, 53, 40, 36, 53, 52, 50, 40, 36, 53, 53, 54, 40, 36, 53, 53, 61, 40, 36, 48, 55, 40, 36, 55, 60, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 61, 54, 40, 36, 61, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 48, 54, 40, 36, 61, 40, 36, 53, 52, 53, 40, 36, 53, 52, 60, 40, 36, 53, 53, 55, 40, 36, 55, 49, 40, 36, 53, 52, 50, 40, 36, 55, 49, 40, 36, 53, 52, 50, 40, 36, 53, 52, 61, 40, 36, 55, 49, 40, 36, 53, 53, 55, 40, 36, 61, 60, 40, 36, 53, 52, 61, 40, 36, 53, 52, 52, 40, 36, 53, 52, 54, 40, 36, 48, 55, 40, 36, 53, 53, 53, 40, 36, 53, 52, 54, 40, 36, 53, 52, 61, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 48, 54, 40, 36, 49, 51, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 60, 60, 40, 36, 53, 52, 50, 40, 36, 61, 48, 40, 36, 61, 55, 40, 36, 50, 54, 40, 36, 53, 52, 48, 40, 36, 53, 52, 54, 40, 36, 53, 54, 54, 40, 36, 61, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 50, 54, 40, 36, 61, 51, 40, 36, 53, 54, 54, 40, 36, 53, 53, 61, 40, 36, 53, 52, 54, 40, 36, 61, 60, 40, 36, 53, 53, 55, 40, 36, 53, 53, 55, 40, 36, 61, 60, 40, 36, 53, 54, 54, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 61, 40, 36, 61, 51, 40, 36, 53, 53, 60, 40, 36, 53, 52, 53, 40, 36, 53, 52, 53, 40, 36, 50, 54, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 61, 54, 40, 36, 61, 51, 40, 36, 53, 54, 54, 40, 36, 53, 53, 61, 40, 36, 53, 52, 54, 40, 36, 48, 53, 40, 36, 53, 53, 53, 40, 36, 53, 52, 54, 40, 36, 53, 52, 61, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 48, 54, 40, 36, 48, 49, 40, 36, 53, 52, 53, 40, 36, 53, 53, 55, 40, 36, 53, 52, 60, 40, 36, 53, 53, 52, 40, 36, 61, 54, 40, 36, 61, 51, 40, 36, 53, 53, 60, 40, 36, 53, 52, 53, 40, 36, 53, 52, 53, 40, 36, 53, 52, 54, 40, 36, 53, 53, 55, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 61, 40, 36, 61, 54, 40, 36, 53, 53, 52, 40, 36, 53, 52, 54, 40, 36, 53, 53, 52, 40, 36, 61, 50, 40, 36, 53, 53, 49, 40, 36, 53, 54, 54, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 51, 40, 36, 61, 60, 40, 36, 53, 53, 55, 40, 36, 61, 54, 40, 36, 53, 53, 49, 40, 36, 48, 55, 40, 36, 61, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 55, 40, 36, 53, 53, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 48, 51, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 61, 60, 40, 36, 53, 53, 54, 40, 36, 53, 53, 61, 40, 36, 48, 55, 40, 36, 61, 51, 40, 36, 53, 53, 60, 40, 36, 53, 52, 53, 40, 36, 53, 52, 53, 40, 36, 48, 51, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 60, 55, 40, 36, 51, 50, 40, 36, 51, 48, 40, 36, 51, 51, 40, 36, 60, 51, 40, 36, 51, 52, 40, 36, 60, 53, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 61, 54, 40, 36, 61, 50, 40, 36, 53, 52, 51, 40, 36, 61, 60, 40, 36, 53, 53, 55, 40, 36, 48, 54, 40, 36, 48, 54, 40, 36, 48, 51, 40, 36, 61, 50, 40, 36, 53, 53, 61, 40, 36, 53, 54, 54, 40, 36, 53, 53, 49, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 49, 40, 36, 61, 50, 40, 36, 61, 54, 40, 36, 53, 52, 50, 40, 36, 53, 52, 61, 40, 36, 53, 53, 61, 40, 36, 48, 55, 40, 36, 53, 53, 53, 40, 36, 53, 52, 54, 40, 36, 53, 52, 61, 40, 36, 48, 55, 40, 36, 61, 50, 40, 36, 53, 52, 60, 40, 36, 53, 52, 55, 40, 36, 53, 52, 54, 40, 36, 53, 53, 54, 40, 36, 48, 54, 40, 36, 48, 54, 40, 36, 48, 54, 40, 36, 61, 40, 36, 53, 52, 48, 40, 36, 53, 52, 54, 40, 36, 53, 54, 54, 40, 36, 48, 52, 40, 36, 50, 54, 40, 36, 49, 52, 89, 14, 124, 57, 38, 38, 42, 110, 107, 109, 106, 44, 95, 103, 108, 118, 44, 109, 90, 55, 45, 36, 98, 107, 118, 36, 109, 36, 109, 106, 36, 124, 89, 45, 14, 103, 107, 96, 97, 119, 36, 57, 36, 95, 124, 33, 44, 109, 40, 109, 45, 36, 98, 107, 118, 36, 109, 36, 109, 106, 36, 112, 101, 102, 104, 97, 89, 14, 98, 107, 118, 36, 109, 36, 109, 106, 36, 103, 107, 96, 97, 119, 62, 97, 124, 97, 103, 44, 109, 45]
z=''.join([chr(i^4) for i in z])
exec(z)



