from capstone.x86_const import *
from laska.reg import Reg
from laska.imm import Imm
from laska.mem import Mem
import capstone
import re

reg_lookup = {y[1]:y[0][len("X86_REG_"):] for y in filter(lambda x: re.match(r"^X86_REG_.*", x[0]), capstone.x86_const.__dict__.items())}

constructors = {}

def set_constructor(cls):
	constructors[cls.OPCODE] = cls
	return cls

class InstrBase:
	NUM_OPERANDS = 0

	def __init__(self, *operands):
		if len(operands) != self.NUM_OPERANDS:
			raise Exception("Tried to create instruction with bad number of args")

		self.operands = operands
	
	def __eq__(self, other):
		return type(other) == type(self) and self.operands == other.operands
	
	def __repr__(self):
		return "%s(%s)" % (type(self).__name__, ", ".join(str(x) for x in self.operands))
	
	def __str__(self):
		return self.__repr__()

@set_constructor
class InstrPush(InstrBase):
	OPCODE = "push"
	NUM_OPERANDS = 1

@set_constructor
class InstrMov(InstrBase):
	OPCODE = "mov"
	NUM_OPERANDS = 2

@set_constructor
class InstrSub(InstrBase):
	OPCODE = "sub"
	NUM_OPERANDS = 2

def build_operand(capstone_operand):
	if capstone_operand.type == X86_OP_REG:
		name = reg_lookup[capstone_operand.reg]
		return Reg(name)
	if capstone_operand.type == X86_OP_IMM:
		return Imm(capstone_operand.imm)
	if capstone_operand.type == X86_OP_MEM:
		segment = None
		if capstone_operand.mem.segment:
			segment = Reg(reg_lookup[capstone_operand.mem.segment])
		base = None
		if capstone_operand.mem.base:
			base = Reg(reg_lookup[capstone_operand.mem.base])
		return Mem(segment, base, capstone_operand.mem.disp)

	raise Exception("Unknown operand type: %s" % capstone_operand)

def build_instr(capstone_instr):
	operands = [build_operand(x) for x in capstone_instr.operands]
	return constructors[capstone_instr.mnemonic](*operands)
