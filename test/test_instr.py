import unittest

import capstone
from instr import *

class InstraTestCase(unittest.TestCase):
    def setUp(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        self.md.detail = True
        self.data = b'U\x8b\xec\x83\xec\x0e\xc7F\xfc\x00\x00\xc7F\xfa\x00\x00\x8bF\x06\x89F\xf8\x8bF\x08\x89F\xf6\xc7F\xf4\x00\x00\xc7F\xf2\x00\x00\x8bV\x04\xb8\x00=\xcd!re\x89F\xfe\x8b\xd83\xc93\xd2\xb8\x02B\xcd!rU\x89F\xfc\x89V\xfa\x8bN\xfaAQ\x8bN\xf2\x8bV\xf4\xb8\x00B\xcd!\x1e\x8b^\xfe\xb9\xff\xff\x8bV\xf8\x8bF\xf6\x8e\xd8\xb4?\xcd!\x1fYr(=\xff\xffu#Q\x1e\x8b^\xfe\xb9\x01\x00\x8bV\xf8\x83\xc2\xff\x8bF\xf6\x8e\xd8\xb4?\xcd!\x1fY\x81F\xf6\x00\x10\xffF\xf2\xe2\xb5\x8b^\xfe\xb4>\xcd!\x8bV\xfa3\xc0\x03F\xfc\x83\xd2\x00\x8b\xe5]\xc3'

    def test_push_bp(self):
        data = b'\x55'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        self.assertEqual(InstrPush(Reg.BP), instr)

    def test_mov_sp_bp(self):
        data = b'\x8b\xec'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        self.assertEqual(InstrMov(Reg.BP, Reg.SP), instr)

    def test_mov_bp_ptr_0(self):
        data = b'\xC7\x46\xFC\x00\x00'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        self.assertEqual(InstrMov(Mem(None, Reg.BP, -4), Imm(0)), instr)

    def test_mov_ax_bp_ptr(self):
        data = b'\x8B\x46\x06'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        self.assertEqual(InstrMov(Reg(Reg.AX), Mem(None, Reg.BP, 6)), instr)

    def test_int_21(self):
        data = b'\xCD\x21'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        self.assertEqual(InstrInt(Imm(0x21)), instr)

    def test_jb(self):
        data = b'\x72\x65'
        instructions = self.md.disasm(data, 0x1234)
        instruction = next(instructions)
        instr = build_instr(instruction)
        dest = 0x1234 + len(data) + 0x65
        self.assertEqual(InstrJb(Imm(dest)), instr)
