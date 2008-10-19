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

		off = 0

		register_options(
			[
				OptString.new('BufferRegister', [ false, "The register that pointers to the encoded payload" ]),
				OptInt.new('BufferOffset', [ false, "The offset to the buffer from the start of the register", off ])
			], Msf::Encoder::Alphanum)
	end
	
end

end