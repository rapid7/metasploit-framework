module Rex
module Encoding
module Xor

	#
	# autoload the Xor encodings
	#
	autoload :Generic, 'rex/encoding/xor/generic'
	autoload :Byte,    'rex/encoding/xor/byte'
	autoload :Word,    'rex/encoding/xor/word'
	autoload :Dword,   'rex/encoding/xor/dword'
	autoload :DwordAdditive, 'rex/encoding/xor/dword_additive'
	autoload :Qword,   'rex/encoding/xor/qword'

	autoload :Exception, 'rex/encoding/xor/exceptions'

end 
end
end
