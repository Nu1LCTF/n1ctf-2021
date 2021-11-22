from encoder import util
from functools import cached_property


class Shellcode(object):

    @cached_property
    def asm(self):
        return util.asm(str(self))

    def __len__(self):
        return len(self.asm)

    def code(self):
        raise Exception("do not call virtual class")

    def __str__(self):
        return self.code

    def __add__(self, other):
        return str(self) + str(other)

    def __radd__(self, other):
        return str(other) + str(self)


class Mov(Shellcode):
    stack_mov = """
push {src}
pop {dst}
"""

    stack_mov2 = """
push {src}
push rsp
pop rcx
xor [rcx], {dst}
xor {dst}, [rcx] 
"""
    stack_mov3 = """ 
push {src}
push rsp
pop {tmp}
xor {src}, [{tmp}+0x30]
xor [{tmp}+0x30], {src}
xor [{tmp}+0x30], {dst}
xor {dst}, [{tmp}+0x30]
"""

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    @cached_property
    def code(self):
        if self.dst in ("rax", "rcx", "rdx", "r8", "r9", "r10"):
            return self.stack_mov.format(src=self.src, dst=self.dst)
        elif self.dst in ("rdi", "rsi"):
            return self.stack_mov2.format(src=self.src, dst=self.dst)
        elif self.dst in ("rbx", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"):
            if self.src == "rcx":
                tmp = "rdx"
            else:
                tmp = "rcx"
            return self.stack_mov3.format(src=self.src, dst=self.dst, tmp=tmp)
        else:
            raise Exception(f"can't mov to reg {self.dst}")


class Zero(Shellcode):
    clean_rax = """
push 0x30
pop rax
xor al, 0x30
"""
    clean2 = """
push {reg}
push rsp
pop rcx
xor {reg}, [rcx]
"""

    def __init__(self, reg):
        self.clean_reg = reg

    @cached_property
    def code(self):
        if self.clean_reg == "rax":
            return self.clean_rax
        elif self.clean_reg in (
                "rcx", "rdx", "r8", "r9", "r10", "rbx", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"):
            return self.clean_rax + Mov(src="rax", dst=self.clean_reg)
        elif self.clean_reg in ("rdi", "rsi"):
            return self.clean2.format(reg=self.clean_reg)
        else:
            raise Exception(f"can't clean reg {self.clean_reg}")


class MulReg(Shellcode):
    mul_reg = '''
push {mul1:#x}
push rsp
pop {tmp}
imul {dst}, WORD PTR [{tmp}], {mul2:#x}
'''

    # imul will modify rdi/rsi, this not easy to set
    # so ask to select one
    def __init__(self, mul1: int, mul2: int, dst: str = "di", modify_reg: str = "rax"):
        # keep mul1 the small one
        assert dst in ("di", "si")
        if modify_reg not in ("rcx", "rax", "r8", "r9"):
            raise Exception("the src reg must in rcx, rax, r8, r9")
        self.dst = dst
        self.modify_reg = modify_reg
        self.mul1, self.mul2 = (mul1, mul2) if mul1 < mul2 else (mul2, mul1)

        mul2_size = util.num_size(self.mul2)
        mul1_size = util.num_size(self.mul1)
        assert mul1_size <= 2
        assert mul2_size <= 2
        assert util.is_alphanumeric(self.mul1, mul1_size)
        assert util.is_alphanumeric(self.mul2, mul2_size)

        self.mul1 = self.mul1 if mul1_size == 1 else self.mul1 | 0x30300000

    @cached_property
    def code(self):
        return self.mul_reg.format(mul1=self.mul1, mul2=self.mul2, dst=self.dst, tmp=self.modify_reg)

    @staticmethod
    def find_mul(data: int):
        assert util.num_size(data) <= 2
        for i in util.mul_iter():
            if i[0] * i[1] & 0xffff == data:
                return i
        return None


class XorReg(Shellcode):
    xor_reg = '''
push {xor1:#x}
pop rax
xor {reg}, {xor2:#x}
'''
    reg_map = {1: "al", 2: "ax", 4: "eax"}

    def __init__(self, xor1: int, xor2: int):
        xor1_size = util.num_size(xor1)
        xor2_size = util.num_size(xor2)
        assert xor1_size <= 4
        assert xor2_size <= 4
        assert util.is_alphanumeric(xor1, xor1_size)
        assert util.is_alphanumeric(xor2, xor2_size)
        if xor1_size == xor2_size == 2:
            xor1 = xor1 | 0x30300000
            xor2 = xor2 | 0x30300000
        elif xor1_size == 2:
            xor1, xor2 = xor2, xor1

        self.xor1 = xor1
        self.xor2 = xor2

    @cached_property
    def code(self):
        return self.xor_reg.format(xor1=self.xor1, xor2=self.xor2, reg=self.reg_map[util.num_size(self.xor2)])

    @staticmethod
    def find_xor(data: int):
        data_size = util.num_size(data)
        assert data_size <= 4

        if data_size == 1:
            return util.xor_table[data]

        if data_size == 2:
            data_array = util.p16(data)
            if data_array[1] in util.alphanum_pool:
                _, n = util.xor_table[data_array[0]]
                return data ^ n, n
            else:
                n = util.u16(bytes([util.xor_table[i][0] for i in data_array]))
                return n, n ^ data

        if data_size == 4:
            data_array = util.p32(data)
            if data_array[2] in util.alphanum_pool and data_array[3] in util.alphanum_pool:
                if data_array[1] in util.alphanum_pool:
                    _, n = util.xor_table[data_array[0]]
                    return data ^ n, n
                else:
                    n = util.u16(bytes([util.xor_table[i][0] for i in data_array[:2]]))
                    return data ^ n, n
            else:
                n = util.u32(bytes([util.xor_table[i][0] for i in data_array]))
                return n, n ^ data


class MulXorReg(Shellcode):
    mul_xor_reg = '''
xor {reg}, {xor:#x}
'''
    reg_map = {1: "al", 2: "ax"}

    def __init__(self, mul1: int, mul2: int, xor: int, modify_reg="di"):
        assert modify_reg in ("di", "si")
        self.mul1 = mul1
        self.mul2 = mul2

        xor_size = util.num_size(xor)
        assert xor_size <= 2
        assert util.is_alphanumeric(xor_size)

        self.xor = xor
        self.modify_reg = modify_reg

    @cached_property
    def code(self):
        code = ''
        code += MulReg(self.mul1, self.mul2, dst=self.modify_reg)
        code += Mov("r" + self.modify_reg, "rax")
        code += self.mul_xor_reg.format(reg=self.reg_map[util.num_size(self.xor)], xor=self.xor)
        return code

    @staticmethod
    def find_mul_xor(data: int):
        assert util.num_size(data) <= 2
        for i in util.mul_iter():
            if util.is_alphanumeric((i[0] * i[1] & 0xffff) ^ data, 2):
                return i[0], i[1], (i[0] * i[1] & 0xffff) ^ data
        return None


class CodeInit(Shellcode):
    @cached_property
    def code(self):
        code = ''

        code += Zero("rdi")
        code += Zero("rsi")

        mul1, mul2 = MulReg.find_mul(0x8080)
        code += MulReg(mul1=mul1, mul2=mul2)
        code += Mov(src="rdi", dst="r8")

        mul1, mul2 = MulReg.find_mul(0x8010)
        code += MulReg(mul1=mul1, mul2=mul2)
        code += Mov(src="rdi", dst="r9")

        mul1, mul2 = MulReg.find_mul(0x0080)
        code += MulReg(mul1=mul1, mul2=mul2)
        code += Mov(src="rdi", dst="r10")
        return code


class FastNumGen(Shellcode):
    reg_map = {1: "al", 2: "ax"}

    def __init__(self, data: int):
        assert util.num_size(data) <= 2
        self.data = data

    @cached_property
    def code(self):
        if self.data & 0x8080 == 0x8080:
            src_reg = "r8"
            src_num = 0x8080
        elif self.data & 0x8000 == 0x8000:
            src_reg = "r9"
            src_num = 0x8010
        elif self.data & 0x0080 == 0x0080:
            src_reg = "r10"
            src_num = 0x0080
        else:
            xor1, xor2 = XorReg.find_xor(self.data)
            return str(XorReg(xor1=xor1, xor2=xor2))

        code = ''
        code += Mov(src=src_reg, dst="rax")

        xor_num = self.data ^ src_num
        if xor_num == 0:
            pass
        elif xor_num < 0x80 and util.is_alphanumeric(xor_num, 1):
            code += f"xor al, {xor_num}\n"
        elif util.is_alphanumeric(xor_num, 2):
            code += f"xor ax, {xor_num}\n"
        else:
            xor1, xor2 = XorReg.find_xor(xor_num)
            code += f"xor {self.reg_map[util.num_size(xor1)]}, {xor1}\n"
            code += f"xor {self.reg_map[util.num_size(xor2)]}, {xor2}\n"
        return code


class NumGen(Shellcode):
    def __init__(self, data: int):
        self.data = data

    @cached_property
    def code(self):
        data_words = []
        data = self.data
        for i in range(4):
            data_words.append((data & 0xffff, i))
            data = data >> 16
        data_words.sort()
        shellcode = ''
        # set rcx == rsp
        shellcode += '''
push rsp
pop rcx
'''
        shellcode += Zero("rax")

        shellcode += '''    
xor rax, [rcx+0x30]
xor [rcx+0x30], rax
'''

        # TODO: this can be optimize
        prev_number = None
        for i in data_words:
            if i[0] != 0:
                if prev_number != i[0]:
                    shellcode += AutoNumGen(data=i[0])
                prev_number = i[0]
                shellcode += 'xor [rcx+0x%x], ax\n' % (i[1] * 2 + 0x30)

        shellcode += "xor [rcx+0x30], rax\n"
        shellcode += "xor rax, [rcx+0x30]\n"

        return shellcode


# set 64bit data to rax with shortest length
class AutoNumGen(Shellcode):
    neg_init = False

    def __init__(self, data: int):
        assert -0x7fffffffffffffff <= data < 0x10000000000000000
        self.number = data

    @cached_property
    def code(self):
        shellcode = ''
        if self.number == 0:
            shellcode += Zero("rax")
        elif 0 < self.number < 0x80:
            if self.number in util.alphanum_pool:
                shellcode += """
push {num:#x}
pop rax
""".format(num=self.number)
            else:
                xor1, xor2 = XorReg.find_xor(self.number)
                shellcode += XorReg(xor1=xor1, xor2=xor2)
        elif 0x80 <= self.number <= 0xffff:
            shellcode += FastNumGen(self.number)
        elif self.number >= 0x10000:
            shellcode += NumGen(self.number)
        elif self.number < 0:
            if not AutoNumGen.neg_init:
                shellcode += NumGen(0xffffffffffffffff)
                shellcode += Mov(src="rax", dst="r15")
                AutoNumGen.neg_init = True
            num = 0xffffffffffffffff ^ (0x10000000000000000 + self.number)
            if self.number <= 0xffff:
                shellcode += FastNumGen(num)
            else:
                shellcode += NumGen(num)

            shellcode += '''
push rsp
pop rcx
push r15
pop rdx
'''
            shellcode += '''
xor rdx, [rcx+0x30]
xor [rcx+0x30], rdx
xor rax, [rcx+0x30]
'''
        return shellcode


class Padding(Shellcode):
    padding = '''
push rax
pop rax
'''

    def __init__(self, size):
        self.size = size

    @cached_property
    def code(self):
        shellcode = ''
        shellcode += self.padding * (self.size // 2)
        if self.size % 2 == 1:
            shellcode += "push rax\n"
        return shellcode


class ShellCodeXor(Shellcode):
    def __init__(self, code_length):
        self.code_length = code_length

    @cached_property
    def code(self):
        xor_encoder_template = ''

        xor_encoder_template += str(AutoNumGen(self.code_length))
        xor_encoder_template += '''
    push rax
    pop rcx
    '''

        xor_encoder_template += '''
    / save rsp t0 r9
    push rsp
    pop r9
    
    push 0x30
    pop rax
    xor al, 0x30
    xor rax, [r9+0x30]
    xor [r9+0x30], rax
    lea rsp, [rip + data + 8]
    xor [r9+0x30], rsp  # we save rsp addr to [r9+0x30]
    
xor_loop:
    pop rax
    imul rax, rax, 16
    
    / clean rsi
    push rsi
    push rsp
    pop rdx
    xor rsi, [rdx]
    pop r8
    
    / mov rsi, rax
    push rax
    xor rsi, [rdx]
    pop r8
    
    / mov rsp, rdx
    push rsp
    pop rdx
    
    xor rsi, [rdx]
    pop rax
    
    / xarg rsp, [r9+0x30]
    xor rsp, [r9+0x30]
    xor [r9+0x30], rsp
    xor rsp, [r9+0x30]
    
    / save data to [r9+0x30] 
    push rsi
    pop rax
    pop rax
    
    / xarg rsp, [r9+0x30]
    xor rsp, [r9+0x30]
    xor [r9+0x30], rsp
    xor rsp, [r9+0x30]
    
    loop xor_loop
    
data:
'''
        return xor_encoder_template

    @staticmethod
    def shellcode_xor(shellcode: bytes):
        enc_code = b"a" * 8
        shellcode = util.asm("mov rsp, r9") + shellcode + b"\x90" * 8
        for i in range(len(shellcode) // 8):
            data = shellcode[:8]
            shellcode = shellcode[8:]
            c1, c2 = ShellCodeXor.shift_xor(data)
            enc_code += c1 + c2
        return enc_code

    @staticmethod
    def shift_xor(data: bytes):
        assert len(data) == 8

        def get_code(low_8bit):
            return next(filter(lambda x: x & 0xf == low_8bit, util.alphanum_pool))

        code_array1 = []
        code_array2 = []
        init_num = 0
        for i in range(8):
            b = (data[i] ^ init_num) & 0xf
            code = get_code(b)
            code_array1.append(code)
            b2 = (data[i] ^ code) >> 4
            code2 = get_code(b2)
            code_array2.append(code2)
            init_num = code2 >> 4

        return bytes(code_array2), bytes(code_array1)
