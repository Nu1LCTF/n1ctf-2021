from encoder import util
from .shellcode_template import CodeInit, AutoNumGen, Mov, MulReg, Padding, ShellCodeXor
import typing

import pwn

IdxList = typing.List[int]
EncBlock = typing.Tuple[int, IdxList]
log_process = None


class Encoder(object):
    def __init__(self, shellcode, base_reg: str, offset: int = 0):
        self.base_reg = base_reg
        self.offset = offset
        self.shellcode = shellcode
        self.origin_shellcode = shellcode

    def encode(self):
        shift_offset = 0
        shellcode_list = self.block_encode_gen()
        while True:
            all_shellcode = ''
            all_shellcode += Mov(self.base_reg, "rbx")
            all_shellcode += CodeInit()
            for idx, shellcode in shellcode_list:
                enc_offset = idx + self.offset + shift_offset
                re = None
                if enc_offset > 0 and util.num_size(enc_offset) <= 2:
                    re = MulReg.find_mul(enc_offset)
                if re is None:
                    all_shellcode += AutoNumGen(enc_offset)
                    all_shellcode += Mov(src="rax", dst="rsi")
                    all_shellcode += shellcode
                else:
                    mul1, mul2 = re
                    all_shellcode += MulReg(mul1=mul1, mul2=mul2, dst="si")
                    all_shellcode += shellcode
            asm_code = util.asm(all_shellcode)
            # print(f"we try offset: {shift_offset}")
            # print(f"the shellcode length: {len(asm_code)}")
            if len(asm_code) < shift_offset:
                break

            global log_process
            if log_process is not None:
                process_num = round((shift_offset / len(asm_code)) * 100)
                log_process.status(f" ({process_num}%)")

            inc_count = (len(asm_code) - shift_offset) // 5
            if inc_count == 0:
                inc_count = 1
            shift_offset += inc_count
        padding_size = shift_offset - len(asm_code)
        asm_code += util.asm(str(Padding(padding_size)))
        return asm_code + self.shellcode

    def block_encode_gen(self):
        enc_blocks = self.split_enc_idx()
        shellcode_list = []
        for enc_block in enc_blocks:
            shellcode = ''
            while len(enc_block[1]) != 0:
                enc_shellcode, re_enc_block, part_shellcode, score = self.byte_xor_strategy(enc_block)
                re = self.word_xor_strategy(enc_block)
                if re is not None and re[3] < score:
                    self.shellcode = re[0]
                    enc_block = re[1]
                    shellcode += re[2]
                else:
                    self.shellcode = enc_shellcode
                    enc_block = re_enc_block
                    shellcode += part_shellcode
            shellcode_list.append((enc_block[0], shellcode))
        return shellcode_list

    # def dword_xor_strategy(self, enc_block: EncBlock) -> typing.Tuple[bytes, EncBlock, str, float]:
    #     enc_shellcode = bytearray(self.shellcode)
    #     off = enc_block[0]
    #     idx_list = enc_block[1]
    #     xor_map = {}
    #     for idx in idx_list:
    #         xor_data = 0
    #         for i in range(4):
    #             self.shellcode

    def word_xor_strategy(self, enc_block: EncBlock) -> typing.Tuple[bytes, EncBlock, str, float]:
        enc_shellcode = bytearray(self.shellcode)
        off = enc_block[0]
        idx_list = enc_block[1]
        enc_bytes = [self.shellcode[off + i] for i in idx_list]
        xor_map = self.find_max_match(enc_bytes)

        # data_list = [(idx, xor_map[self.shellcode[off + idx]]) for idx in idx_list]
        i = 0
        word_data_list: typing.List[typing.Tuple[int, int]] = []
        idx_length = len(idx_list)
        while i < idx_length - 1:
            if idx_list[i + 1] - idx_list[i] == 1:
                idx = idx_list[i]
                word_data_list.append((idx, (xor_map[self.shellcode[off + idx]]) + xor_map[
                    self.shellcode[off + idx + 1]] << 8))
            i += 1

        if len(word_data_list) == 0:
            return None

        idx_map = {}
        for i in word_data_list:
            if i[1] in idx_map:
                idx_map[i[1]].append(i[0])
            else:
                idx_map[i[1]] = [i[0]]

        xor_list = [(key, value) for key, value in idx_map.items()]
        xor_list.sort(key=lambda x: len(x[1]), reverse=True)
        xor_data = xor_list[0][0]
        xor_idx = xor_list[0][1]

        i = 0
        while i < len(xor_idx) - 1:  # avoid some case like "\x00\x00\x00\x00"
            if xor_idx[i + 1] - xor_idx[i] == 1:
                xor_idx.pop(i + 1)
            i += 1

        encode_byte_count = 0

        shellcode = ''
        shellcode += AutoNumGen(xor_data)
        for idx in xor_idx:
            shellcode += "xor [rbx+rsi+{idx:#x}], ax\n".format(idx=idx)
            idx_list.remove(idx)
            idx_list.remove(idx + 1)
            enc_shellcode[off + idx] ^= xor_data & 0xff
            enc_shellcode[off + idx + 1] ^= xor_data >> 8
            encode_byte_count += 2

        i = 0
        while i < len(idx_list):
            idx = idx_list[i]
            enc_data = xor_map[self.shellcode[off + idx]]
            if enc_data == xor_data & 0xff:
                shellcode += "xor [rbx+rsi+{idx:#x}], al\n".format(idx=idx)
                idx_list.pop(i)
                enc_shellcode[off + idx] ^= xor_data & 0xff
                encode_byte_count += 1
            elif enc_data == xor_data >> 8:
                shellcode += "xor [rbx+rsi+{idx:#x}], ah\n".format(idx=idx)
                idx_list.pop(i)
                enc_shellcode[off + idx] ^= xor_data >> 8
                encode_byte_count += 1
            else:
                i += 1

        shellcode_length = len(util.asm(shellcode))

        return bytes(enc_shellcode), (off, idx_list), shellcode, shellcode_length / encode_byte_count

    def byte_xor_strategy(self, enc_block: EncBlock) -> typing.Tuple[bytes, EncBlock, str, float]:
        enc_shellcode = bytearray(self.shellcode)
        off = enc_block[0]
        idx_list = enc_block[1]
        enc_bytes = [self.shellcode[off + i] for i in idx_list]
        xor_map = self.find_max_match(enc_bytes)

        idx_map: typing.Dict[int, typing.List[int]] = {}

        for i in idx_list:
            xor_data = xor_map[self.shellcode[off + i]]
            if xor_data in idx_map:
                idx_map[xor_data].append(i)
            else:
                idx_map[xor_data] = [i]

        xor_list = [(key, value) for key, value in idx_map.items()]
        xor_list.sort(key=lambda x: len(x[1]), reverse=True)

        # select the max two
        low_data = xor_list[0][0]
        low_enc_idx = xor_list[0][1]
        if len(xor_list) > 1:
            high_data = xor_list[1][0]
            high_enc_idx = xor_list[1][1]
        else:
            high_data = 0
            high_enc_idx = []

        enc_bytes_count = len(low_enc_idx) + len(high_enc_idx)

        # first gen data
        data = low_data + (high_data << 8)
        shellcode = ''
        shellcode += AutoNumGen(data=data)
        for idx in low_enc_idx:
            shellcode += "xor [rbx+rsi+{idx:#x}], al\n".format(idx=idx)
            idx_list.remove(idx)
            enc_shellcode[off + idx] ^= low_data
        for idx in high_enc_idx:
            shellcode += "xor [rbx+rsi+{idx:#x}], ah\n".format(idx=idx)
            idx_list.remove(idx)
            enc_shellcode[off + idx] ^= high_data

        shellcode_length = len(util.asm(shellcode))
        score = shellcode_length / enc_bytes_count
        return bytes(enc_shellcode), (off, idx_list), shellcode, score

    def data_scan(self):
        need_enc = []
        shellcode = bytearray(self.shellcode)
        i = 0
        shellcode_length = len(shellcode)
        while i < shellcode_length:
            if shellcode[i] not in util.alphanum_pool:
                need_enc.append(i)
            i += 1
        return need_enc

    def split_enc_idx(self) -> typing.List[typing.Tuple[int, IdxList]]:
        need_enc = self.data_scan()
        enc_blocks = []

        while len(need_enc) != 0:
            max_size = 0
            max_offset = 0
            first_idx = need_enc[0]
            base_offset = first_idx - 0x7a
            while base_offset <= first_idx - 0x30:
                point = 0
                for idx in need_enc:
                    off = idx - base_offset
                    if 0x30 <= off <= 0x39 or 0x41 <= off <= 0x5a or 0x61 <= off <= 0x7a:
                        point += 1

                if point > max_size:
                    max_size = point
                    max_offset = base_offset
                base_offset += 1

            i = 0
            enc_block = []
            while i < len(need_enc):
                off = need_enc[i] - max_offset
                if 0x30 <= off <= 0x39 or 0x41 <= off <= 0x5a or 0x61 <= off <= 0xff:
                    enc_block.append(off)
                    need_enc.pop(i)
                else:
                    i += 1

            enc_blocks.append((max_offset, enc_block))
        return enc_blocks

    @staticmethod
    def find_max_match(data: typing.List[int]) -> dict:
        xor_data_map = {}

        while len(data) != 0:
            max_point = 0
            max_data = 0

            # we prefer alphanum
            l = [i for i in range(0x100)]
            l.sort(key=lambda x: x in util.alphanum_pool, reverse=True)
            for i in l:
                point = 0
                for d in data:
                    if d ^ i in util.alphanum_pool:
                        point += 1

                if point > max_point:
                    max_point = point
                    max_data = i

            i = 0
            while i < len(data):
                if data[i] ^ max_data in util.alphanum_pool:
                    xor_data_map[data[i]] = max_data
                    data.pop(i)
                else:
                    i += 1
        return xor_data_map


def encoder_with_xor_compress(shellcode: bytes, base_reg, offset=0):
    shellcode_xor = ShellCodeXor((len(shellcode) // 8) + 1)
    e = Encoder(shellcode=util.asm(str(shellcode_xor)), base_reg=base_reg, offset=offset)
    enc_shellcode = e.encode()
    enc_shellcode += ShellCodeXor.shellcode_xor(shellcode)
    return enc_shellcode


def encoder_direct(shellcode: bytes, base_reg, offset=0):
    e = Encoder(shellcode=shellcode, base_reg=base_reg, offset=offset)
    enc_shellcode = e.encode()
    return enc_shellcode


def encode(shellcode: bytes, base_reg, offset=0):
    global log_process
    log_process = pwn.log.progress("shellcode is generating step(1/2), plz wait")
    shellcode1 = encoder_direct(shellcode, base_reg, offset)
    log_process.success()
    log_process = pwn.log.progress("shellcode is generating step(2/2), plz wait")
    shellcode2 = encoder_with_xor_compress(shellcode, base_reg, offset)
    log_process.success()
    return shellcode1 if len(shellcode1) < len(shellcode2) else shellcode2
