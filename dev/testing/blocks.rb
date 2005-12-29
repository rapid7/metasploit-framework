#!/usr/bin/ruby
#  shikata ga nai implementation using poly block generation

require 'rex'
require 'rex/poly'

raw_length = 8
raw_buf    = "\xcc\xcc\xcc\xcc"
raw_buf    = "\xdd\xdd\xdd\xdd"

def fpu_instructions
	fpus = []

	0xe8.upto(0xee) { |x| fpus << "\xd9" + x.chr }
	0xc0.upto(0xcf) { |x| fpus << "\xd9" + x.chr }
	0xc0.upto(0xdf) { |x| fpus << "\xda" + x.chr }
	0xc0.upto(0xdf) { |x| fpus << "\xdb" + x.chr }
	0xc0.upto(0xc7) { |x| fpus << "\xdd" + x.chr }

	fpus << "\xd9\xd0"
	fpus << "\xd9\xe1"
	fpus << "\xdb\xe1"
	fpus << "\xd9\xf6"
	fpus << "\xd9\xf7"
	fpus << "\xd9\xe5"

	fpus
end

# Declare logical registers
count_reg = Rex::Poly::LogicalRegister::X86.new('count', 'ecx')
addr_reg  = Rex::Poly::LogicalRegister::X86.new('addr')
key_reg   = Rex::Poly::LogicalRegister::X86.new('key')

# Declare individual blocks
endb     = Rex::Poly::SymbolicBlock::End.new

fpu     = Rex::Poly::LogicalBlock.new('fpu',
	*fpu_instructions)
fnstenv = Rex::Poly::LogicalBlock.new('fnstenv',
	"\xd9\x74\x24\xf4")

popeip  = Rex::Poly::LogicalBlock.new('popeip',
	Proc.new { |b| (0x58 + b.regnum_of(addr_reg)).chr })

clear_register = Rex::Poly::LogicalBlock.new('clear_register',
	"\x31\xc9",
	"\x29\xc9",
	"\x33\xc9",
	"\x2b\xc9")

init_counter = Rex::Poly::LogicalBlock.new('init_counter')
if (raw_length <= 255)
	init_counter.add_perm("\xb1" + [ raw_length ].pack('C'))
else
	init_counter.add_perm("\x66\xb9" + [ raw_length ].pack('v'))
end

init_key = Rex::Poly::LogicalBlock.new('init_key',
	Proc.new { |b| (0xb8 + b.regnum_of(key_reg)).chr + 'XORK'})

loop_block = Rex::Poly::LogicalBlock.new('loop_block')

xor  = Proc.new { |b| "\x31" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
xor1 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4) ].pack('c') }
xor2 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 8) ].pack('c') }
add  = Proc.new { |b| "\x03" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
add1 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4) ].pack('c') }
add2 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 8) ].pack('c') }
sub4 = Proc.new { |b| "\x83" + (0xe8 + b.regnum_of(addr_reg)).chr + "\xfc" }
add4 = Proc.new { |b| "\x83" + (0xc0 + b.regnum_of(addr_reg)).chr + "\x04" }


#xor  = Proc.new { |b| "\x31" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
#xor1 = Proc.new { |b| xor.call(b) + (b.offset_of(endb) - b.offset_of(fpu) - 4).chr }
#xor2 = Proc.new { |b| xor.call(b) + (b.offset_of(endb) - b.offset_of(fpu) - 8).chr }
#add  = Proc.new { |b| "\x03" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
#add1 = Proc.new { |b| add.call(b) + (b.offset_of(endb) - b.offset_of(fpu) - 4).chr }
#add2 = Proc.new { |b| add.call(b) + (b.offset_of(endb) - b.offset_of(fpu) - 8).chr }
#sub4 = Proc.new { |b| "\x83" + (0xe8 + b.regnum_of(addr_reg)).chr + "\xfc" }
#add4 = Proc.new { |b| "\x83" + (0xc0 + b.regnum_of(addr_reg)).chr + "\x04" }

loop_block.add_perm(
	Proc.new { |b| xor1.call(b) + add1.call(b) + sub4.call(b) },
	Proc.new { |b| xor1.call(b) + sub4.call(b) + add2.call(b) },
	Proc.new { |b| sub4.call(b) + xor2.call(b) + add2.call(b) },
	Proc.new { |b| xor1.call(b) + add1.call(b) + add4.call(b) },
	Proc.new { |b| xor1.call(b) + add4.call(b) + add2.call(b) },
	Proc.new { |b| add4.call(b) + xor2.call(b) + add2.call(b) })
	
loop_inst = Rex::Poly::LogicalBlock.new('loop_inst', 
	"\xe2\xf5")

# Define block dependencies
fnstenv.depends_on(fpu)
popeip.depends_on(fnstenv)
init_counter.depends_on(clear_register)
loop_block.depends_on(popeip, init_counter, init_key)
loop_inst.depends_on(loop_block)

# Generate a permutation
puts loop_inst.generate([
	Rex::Arch::X86::ESP,
	Rex::Arch::X86::ECX ])
