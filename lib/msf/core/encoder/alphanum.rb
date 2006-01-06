require 'msf/core'

module Msf

###
#
# This class provides common options for certain alphanumeric encoders.
#
###
class Encoder::Alphanum < Msf::Encoder

	def initialize(info)
		super(info)

		# Defaults based on architecture.
		reg = 'EAX' if (arch?(ARCH_X86))
		off = 0

		register_options(
			[
				OptString.new('BufferRegister', [ true, "The register that pointers to the encoded payload", reg ]),
				OptInt.new('BufferOffset', [ true, "The offset to the buffer from the start of the register", off ])
			], Msf::Encoder::Alphanum)
	end
	
end

end
