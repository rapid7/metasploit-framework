module Msf::Simple
	# Buffer management
	autoload :Buffer,     'msf/base/simple/buffer'
	autoload :Statistics, 'msf/base/simple/statistics'

	# Simplified module interfaces
	autoload :Module,    'msf/base/simple/module'
	autoload :Encoder,   'msf/base/simple/encoder'
	autoload :Exploit,   'msf/base/simple/exploit'
	autoload :Nop,       'msf/base/simple/nop'
	autoload :Payload,   'msf/base/simple/payload'
	autoload :Auxiliary, 'msf/base/simple/auxiliary'
	autoload :Post,      'msf/base/simple/post'

	# Simplified framework interface
	autoload :Framework, 'msf/base/simple/framework'
end
