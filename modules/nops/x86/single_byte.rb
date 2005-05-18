require 'Msf'

module Msf
module Nops
module IA32

###
#
# SingleByte
# ----------
#
# This class implements single-byte NOP generation for IA32.  It takes from
# ADMmutate and from spoonfu.
#
###
class SingleByte < Msf::Nop

SINGLE_BYTE_SLED = 
	{
		# opcode  affected registers
		# ------  ------------------
		"\x90" => nil             , # nop
		"\x97" => [ 'eax', 'edi' ], # xchg eax, edi
		"\x96" => [ 'eax', 'esi' ], # xchg eax,esi
		"\x95" => [ 'eax', 'ebp' ], # xchg eax,ebp
		"\x93" => [ 'eax', 'ebx' ], # xchg eax,ebx
		"\x92" => [ 'eax', 'edx' ], # xchg eax,edx
		"\x91" => [ 'eax', 'ecx' ], # xchg eax,ecx
		"\x99" => [ 'edx'        ], # cdq
		"\x4d" => [ 'ebp'        ], # dec ebp
		"\x48" => [ 'eax'        ], # dec eax
		"\x47" => [ 'edi'        ], # inc edi
		"\x4f" => [ 'edi'        ], # dec edi
		"\x40" => [ 'eax'        ], # inc eax
		"\x41" => [ 'ecx'        ], # inc ecx
		"\x37" => [ 'eax'        ], # aaa
		"\x3f" => [ 'eax'        ], # aas
		"\x27" => [ 'eax'        ], # daa
		"\x2f" => [ 'eax'        ], # das
		"\x46" => [ 'esi'        ], # inc esi
		"\x4e" => [ 'esi'        ], # dec esi
		"\xfc" => nil             , # cld
		"\xfd" => nil             , # std
		"\xf8" => nil             , # clc
		"\xf9" => nil             , # stc
		"\xf5" => nil             , # cmc
		"\x98" => [ 'eax'        ], # cwde
		"\x9f" => [ 'eax'        ], # lahf
		"\x4a" => [ 'edx'        ], # dec edx
		"\x44" => [ 'esp'        ], # inc esp
		"\x42" => [ 'edx'        ], # inc edx
		"\x43" => [ 'ebx'        ], # inc ebx
		"\x49" => [ 'ecx'        ], # dec ecx
		"\x4b" => [ 'ebx'        ], # dec ebx
		"\x45" => [ 'ebp'        ], # inc ebp
		"\x4c" => [ 'esp'        ], # dec esp
		"\x9b" => nil             , # wait
		"\x60" => [ 'esp'        ], # pusha
		"\x0e" => [ 'esp'        ], # push cs
		"\x1e" => [ 'esp'        ], # push ds
		"\x50" => [ 'esp'        ], # push eax
		"\x55" => [ 'esp'        ], # push ebp
		"\x53" => [ 'esp'        ], # push ebx
		"\x51" => [ 'esp'        ], # push ecx
		"\x57" => [ 'esp'        ], # push edi
		"\x52" => [ 'esp'        ], # push edx
		"\x06" => [ 'esp'        ], # push es
		"\x56" => [ 'esp'        ], # push esi
		"\x54" => [ 'esp'        ], # push esp
		"\x16" => [ 'esp'        ], # push ss
		"\x58" => [ 'esp', 'eax' ], # pop eax
		"\x5d" => [ 'esp', 'ebp' ], # pop ebp
		"\x5b" => [ 'esp', 'ebx' ], # pop ebx
		"\x59" => [ 'esp', 'ecx' ], # pop ecx
		"\x5f" => [ 'esp', 'edi' ], # pop edi
		"\x5a" => [ 'esp', 'edx' ], # pop edx
		"\x5e" => [ 'esp', 'esi' ], # pop esi
		"\xd6" => [ 'eax'        ], # salc
	}

	def initialize
		super(
			'Name'        => 'Single Byte',
			'Version'     => '$Revision$',
			'Description' => 'Single-byte NOP generator',
			'Author'      => 'spoonm',
			'Arch'        => ARCH_IA32)
	end

	# Generate a single-byte NOP sled for IA32
	def generate_sled(length, opts)
		sled_hash    = SINGLE_BYTE_SLED
		sled_max_idx = sled_hash.length
		sled_cur_idx = 0
		out_sled     = ''

		random   = opts['Random']        || false
		badchars = opts['Badchars']      || ''
		badregs  = opts['SaveRegisters'] || []

		# Generate the whole sled...
		1.upto(length) { |current|

			cur_char  = nil
			threshold = 0

			# Keep snagging characters until we find one that satisfies both the
			# bad character and bad register requirements
			begin
				sled_cur_idx  = rand(sled_max_idx) if (random)
				cur_char      = sled_hash.keys[sled_cur_idx]
				sled_cur_idx += 1 if (!random)

				# Make sure that we haven't gone over the sled repeat threshold
				if ((threshold += 1) > self.nop_repeat_threshold)
					return nil
				end

			end while ((badchars.include?(cur_char)) or
			           ((sled_hash[cur_char]) and
			            ((sled_hash[cur_char] & badregs)).length > 0))

			# Add the character to the sled now that it's passed our checks
			out_sled += cur_char
		}

		# If the sled fails to entirely generate itself, then that's bogus,
		# man...
		if (out_sled.length != length)
			return nil
		end

		return out_sled
	end

end

end end end
