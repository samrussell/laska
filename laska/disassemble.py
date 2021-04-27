import capstone
from instr import build_instr

with open("input/KEEN1UP.EXE", "rb") as file:
	data = file.read()

code = data[0x5D18:0x5DC3]

print(code)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
md.detail = True

for instr in md.disasm(code, 0x15CB8):
	#import pdb
	#pdb.set_trace()
	print("0x%x: %s %s" %(instr.address, instr.mnemonic, instr.op_str))
	print(build_instr(instr))
